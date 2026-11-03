// Selftest for the canopy dashboard (web/canopy-observe.mjs + web/dashboard-server.mjs).
//
// Two MOCK Elders speak the real /health, /directory, /incidents and /telemetry/aggregate shapes,
// each signing with its own key, over gateways whose onions are derived from real ed25519 keys (so
// verifyDirectory's onion<->pubkey binding holds). The test then pins:
//   - both Elders verified under their OWN pins, nodes merged and attributed per Elder;
//   - a down Elder is visible (reachable false, error kind, no rows from it);
//   - adversarial: a tampered directory, a directory signed by the OTHER Elder's key, a stale and a
//     future-dated directory, a bad caps signature, a tampered incident feed, a tampered relay
//     aggregate, garbage JSON, and a non-object all show as unverified and contribute no node row;
//   - privacy: no full onion, no operator address, no region on any node row, no incident
//     instance, in /api/canopy or /api/history;
//   - the server: page + assets served with the site CSP, 503 before the first observation, query
//     strings rejected, history ring bounded.
//
//   node web/dashboard.selftest.mjs
//
// Exit 0 = every check held; nonzero = a check failed.

import http from "node:http";
import { generateKeyPairSync } from "node:crypto";
import { signDirectory, signCaps, pubkeyToOnion } from "../packages/node/lib/directory.mjs";
import { signIncidents } from "../packages/node/bootnode/incidents.mjs";
import {
  checkDirectory,
  errorKind,
  observeCanopy,
  parseEldersSpec,
  plainGetJson,
  reduceCanopy,
  scrubOnions,
  makeElderFetch,
  eldersFromRecord,
} from "./canopy-observe.mjs";
import { makeDashboard, makeDashboardServer, resolveTargets, sampleOf } from "./dashboard-server.mjs";

let failures = 0;
const ok = (cond, msg) => { if (cond) console.log(`  ok   ${msg}`); else { console.log(`  FAIL ${msg}`); failures++; } };

function mintEd25519() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  return {
    pub: publicKey.export({ format: "der", type: "spki" }).subarray(-32).toString("hex"),
    priv: privateKey.export({ format: "der", type: "pkcs8" }).subarray(-32).toString("hex"),
  };
}

// A gateway entry with a real onion and an onion-signed caps block (so the caps signature check in
// verifyDirectory runs on every entry, not only on the bare ones).
function mintGateway({ caps = {}, ...extra } = {}) {
  const k = mintEd25519();
  const onion = pubkeyToOnion(k.pub);
  const fullCaps = { proto: { min: 4, max: 4 }, admits: ["staked"], ...caps };
  return { onion, entry: { onion, pubkey: k.pub, weight: 100, health: "up", caps: fullCaps, capsSig: signCaps(onion, fullCaps, k.priv), ...extra } };
}

const nowSec = () => Math.floor(Date.now() / 1000);
const OPS = ["0x1111111111111111111111111111111111111111", "0x2222222222222222222222222222222222222222", "0x3333333333333333333333333333333333333333"];

function relayAggregate(signer) {
  // A valid suppressed aggregate, signed like packages/node/lib/relay-telemetry.mjs does it.
  return import("../packages/node/lib/relay-telemetry.mjs").then(async (m) => {
    const { ed25519Sign } = await import("../packages/node/lib/directory.mjs");
    const gen = new Date(Math.floor(Date.now() / 3_600_000) * 3_600_000);
    const end = new Date(gen.getTime() - 6 * 3_600_000);
    const win = (h) => ({ status: "suppressed", windowHours: h, windowStart: new Date(end.getTime() - h * 3_600_000).toISOString(), windowEnd: end.toISOString(), reportingNodes: 0, suppressionReason: "unavailable" });
    const agg = { schema: m.RELAY_AGGREGATE_SCHEMA, generatedAt: gen.toISOString(), definition: "payload-bytes-relayed", unit: "bytes", delayHours: 6, minimumCohort: 5, rounding: { method: "ceiling", bucketBytes: "1073741824" }, windows: { sixHour: win(6), twentyFourHour: win(24) }, signer: signer.pub };
    agg.signature = ed25519Sign(Buffer.from(JSON.stringify(m.relayAggregateSigningPayload(agg)), "utf8"), signer.priv);
    return agg;
  });
}

// A mock Elder. `routes` maps a path to a body (object) or a function returning one; a missing
// route is 404. `raw` bodies are sent as-is (garbage JSON).
function mockElder(routes) {
  const server = http.createServer((req, res) => {
    const r = routes[req.url];
    if (r === undefined) { res.writeHead(404, { "content-type": "application/json" }); return res.end('{"ok":false}'); }
    const v = typeof r === "function" ? r() : r;
    const body = typeof v === "string" ? v : JSON.stringify(v);
    res.writeHead(200, { "content-type": "application/json", "content-length": Buffer.byteLength(body) });
    res.end(body);
  });
  return new Promise((resolve) => server.listen(0, "127.0.0.1", () => resolve({ server, url: `http://127.0.0.1:${server.address().port}` })));
}
const close = (s) => new Promise((r) => (s ? s.close(r) : r()));

async function main() {
  const sigA = mintEd25519();
  const sigB = mintEd25519();
  const COMMIT = "a".repeat(40);
  const OTHER_COMMIT = "b".repeat(40);

  // Canopy: g1+g2 on both Elders, g3 only on A (draining), g4 only on B (down, region singleton).
  const g1 = mintGateway({ operator: OPS[0], staked: true, caps: { region: "eu" } });
  const g2 = mintGateway({ operator: OPS[1], staked: true, caps: { region: "eu", admits: ["invited", "staked"] } });
  const g3 = mintGateway({ operator: OPS[0], staked: true, caps: { region: "na", draining: true } });
  const g4 = mintGateway({ operator: OPS[2], staked: false, health: "down", caps: { region: "oc" } });
  const fullOnions = [g1, g2, g3, g4].map((g) => g.onion);
  const dirA = () => signDirectory({ version: 1, issued: nowSec(), gateways: [g1.entry, g2.entry, g3.entry], signer: sigA.pub }, sigA.priv);
  const dirB = () => signDirectory({ version: 1, issued: nowSec(), gateways: [g1.entry, g2.entry, g4.entry], signer: sigB.pub }, sigB.priv);
  const incA = signIncidents({ issued: nowSec(), incidents: [{ id: "elder-b", component: "elder", instance: "host-7.example", severity: "warning", summary: `elder b down, see ${g4.onion}`, since: nowSec() - 60, until: null }] }, sigA.priv);
  const relA = await relayAggregate(sigA);

  const elderA = await mockElder({ "/health": { ok: true, count: 3, admission: "stake", signer: sigA.pub, commit: COMMIT }, "/directory": dirA, "/incidents": incA, "/telemetry/aggregate": relA });
  const elderB = await mockElder({ "/health": { ok: true, count: 3, admission: "stake", signer: sigB.pub, commit: OTHER_COMMIT }, "/directory": dirB });
  const fetchJson = makeElderFetch();
  const servers = [elderA.server, elderB.server];
  let dashServer = null;

  try {
    // ===== healthy two-Elder canopy ==========================================================
    console.log("two healthy Elders:");
    const elders = [{ label: "elder-a", url: elderA.url, signer: sigA.pub }, { label: "elder-b", url: elderB.url, signer: sigB.pub }];
    const obs = await observeCanopy({ network: "test", elders, fetchJson, pinnedCommit: COMMIT });
    ok(obs.summary.eldersVerified === 2 && obs.summary.eldersReachable === 2, "both Elders reachable and verified");
    ok(obs.canopy.size === 4, `merged canopy has 4 distinct nodes (got ${obs.canopy.size})`);
    ok(obs.canopy.listedByAll === 2, "2 nodes listed by both Elders");
    ok(obs.nodes.filter((n) => n.listedBy.length === 1).length === 2, "2 nodes listed by one Elder only");
    ok(obs.canopy.draining === 1 && obs.nodes.some((n) => n.draining), "draining node counted and flagged");
    ok(obs.canopy.down === 1, "down node counted");
    ok(obs.canopy.operators === 3, "3 distinct operators counted");
    ok(obs.canopy.staked === 3 && obs.canopy.unstaked === 1, "staked / unstaked tally");
    ok(obs.elders[0].commitMatchesPin === true && obs.elders[1].commitMatchesPin === false, "Elder commit compared against the record pin");
    ok(obs.elders[0].incidents?.verified === true && obs.elders[0].incidents.active === 1, "signed incident feed verified, 1 active");
    ok(obs.elders[0].relay?.verified === true && obs.elders[0].relay.windows[1].status === "suppressed", "signed relay aggregate verified (suppressed)");
    ok(obs.elders[1].incidents === null && obs.elders[1].relay === null, "absent feeds are null, not errors");
    ok(obs.canopy.regions.shown.length === 1 && obs.canopy.regions.shown[0].label === "eu" && obs.canopy.regions.folded === 2, "regions folded at k=2: eu named, na+oc folded");
    ok(obs.canopy.coverage.some((c) => c.label === "all Elders" && c.count === 2), "coverage aggregate counts nodes listed by every Elder");

    console.log("\nprivacy scrub:");
    const json = JSON.stringify(obs);
    ok(!fullOnions.some((o) => json.includes(o)), "no full node onion anywhere in the observation");
    ok(!fullOnions.some((o) => json.includes(o.slice(0, 17))), "no onion prefix longer than 16 characters");
    ok(!OPS.some((a) => json.toLowerCase().includes(a)), "no operator address anywhere");
    ok(!json.includes("host-7.example"), "incident instance (host label) dropped");
    ok(obs.nodes.every((n) => !("region" in n) && !("operator" in n) && !("pubkey" in n)), "no node row carries region, operator or pubkey");
    ok(obs.nodes.every((n) => n.onionShort.length === 16), "every onionShort is exactly 16 characters");
    ok(obs.elders[0].incidents.items[0].summary.includes("<onion>"), "onion inside incident prose is scrubbed");

    // ===== one Elder down ======================================================================
    console.log("\none Elder down:");
    const dead = [{ label: "elder-a", url: elderA.url, signer: sigA.pub }, { label: "dead", url: "http://127.0.0.1:1", signer: sigB.pub }];
    const obsDown = await observeCanopy({ elders: dead, fetchJson });
    ok(obsDown.elders[1].reachable === false && obsDown.elders[1].error === "connection refused", "down Elder: reachable false, short error kind");
    ok(obsDown.summary.eldersVerified === 1 && obsDown.canopy.size === 3, "canopy built from the live Elder only");
    ok(obsDown.nodes.every((n) => n.listedBy.length === 1 && n.listedBy[0] === 0), "no row attributed to the down Elder");

    // ===== adversarial directories ===============================================================
    console.log("\nadversarial: each bad directory is unverified and lists nothing:");
    const tampered = dirA(); tampered.gateways[0].weight = 1000;
    const crossSigned = signDirectory({ version: 1, issued: nowSec(), gateways: [g1.entry], signer: sigA.pub }, sigA.priv);
    const stale = signDirectory({ version: 1, issued: nowSec() - 3600, gateways: [g1.entry], signer: sigB.pub }, sigB.priv);
    const future = signDirectory({ version: 1, issued: nowSec() + 3600, gateways: [g1.entry], signer: sigB.pub }, sigB.priv);
    const badCapsEntry = { ...g2.entry, caps: { ...g2.entry.caps, admits: ["invited"] } };
    const badCaps = signDirectory({ version: 1, issued: nowSec(), gateways: [badCapsEntry], signer: sigB.pub }, sigB.priv);
    const injected = dirB(); injected.gateways.push(mintGateway().entry);
    const cases = [
      ["tampered weight after signing", tampered, sigA.pub],
      ["directory signed by the OTHER Elder's key", crossSigned, sigB.pub],
      ["stale directory (issued 1 h ago)", stale, sigB.pub],
      ["future-dated directory", future, sigB.pub],
      ["caps changed after the onion signed them", badCaps, sigB.pub],
      ["extra entry injected after signing", injected, sigB.pub],
      ["unsigned directory", { version: 1, issued: nowSec(), gateways: [g1.entry] }, sigB.pub],
      ["non-object directory", ["nope"], sigB.pub],
      ["signer field not a string", { ...dirB(), signer: 7 }, sigB.pub],
    ];
    for (const [name, doc, pin] of cases) {
      const evil = await mockElder({ "/health": { ok: true, count: 1, signer: pin }, "/directory": doc });
      servers.push(evil.server);
      const o = await observeCanopy({ elders: [{ label: "evil", url: evil.url, signer: pin }], fetchJson });
      const d = o.elders[0].directory;
      ok(o.elders[0].reachable === true && (!d.verified || !d.fresh) && o.canopy.size === 0 && o.nodes.length === 0, `${name}: unverified (${d.reason}), 0 nodes`);
    }
    ok(checkDirectory(null, sigA.pub).reason === "no-directory", "checkDirectory(null) fails closed, no throw");
    ok(checkDirectory({ gateways: "x", signature: "zz" }, sigA.pub).verified === false, "checkDirectory on junk fields fails closed, no throw");

    console.log("\nadversarial: garbage over the wire:");
    const junk = await mockElder({ "/health": "{not json", "/directory": "{not json" });
    servers.push(junk.server);
    const oJunk = await observeCanopy({ elders: [{ label: "junk", url: junk.url, signer: sigA.pub }], fetchJson });
    ok(oJunk.elders[0].reachable === false && oJunk.elders[0].error === "bad json" && oJunk.canopy.size === 0, "garbage /health: unreachable, bad json, 0 nodes");
    const big = await mockElder({ "/health": { ok: true }, "/directory": "x".repeat(600 * 1024) });
    servers.push(big.server);
    const oBig = await observeCanopy({ elders: [{ label: "big", url: big.url, signer: sigA.pub }], fetchJson });
    ok(oBig.elders[0].directory.reason === "fetch: response too large" && oBig.canopy.size === 0, "oversized /directory refused by the bounded read");

    console.log("\nadversarial: tampered feeds:");
    const badInc = { ...incA, incidents: [{ ...incA.incidents[0], severity: "info" }] };
    const badRel = { ...relA, minimumCohort: 6 };
    const feeds = await mockElder({ "/health": { ok: true, count: 3, signer: sigA.pub }, "/directory": dirA, "/incidents": badInc, "/telemetry/aggregate": badRel });
    servers.push(feeds.server);
    const oFeeds = await observeCanopy({ elders: [{ label: "feeds", url: feeds.url, signer: sigA.pub }], fetchJson });
    ok(oFeeds.elders[0].incidents.verified === false && oFeeds.elders[0].incidents.items.length === 0, "tampered incident feed: unverified, contents dropped");
    ok(oFeeds.elders[0].relay.verified === false && oFeeds.elders[0].relay.windows.length === 0, "tampered relay aggregate: unverified, contents dropped");
    const wrongPinInc = await mockElder({ "/health": { ok: true }, "/directory": dirB, "/incidents": incA });
    servers.push(wrongPinInc.server);
    const oWrong = await observeCanopy({ elders: [{ label: "x", url: wrongPinInc.url, signer: sigB.pub }], fetchJson });
    ok(oWrong.elders[0].incidents.verified === false, "incident feed signed by another Elder: unverified");

    // ===== node dial probe =====================================================================
    console.log("\noptional node dial:");
    const dialed = await observeCanopy({ elders, fetchJson, dialNode: async (onion) => { if (onion === g4.onion) throw new Error("x"); return 1234; } });
    ok(dialed.summary.nodeDialProbe === true && dialed.nodes.filter((n) => n.dialFailed === true).length === 1 && dialed.nodes.filter((n) => n.dialMs === 1234).length === 3, "dial results attached per node, failure flagged");
    ok(!JSON.stringify(dialed).includes(g4.onion), "dial results do not leak the onion");

    // ===== config parsing ======================================================================
    console.log("\nconfig:");
    ok(parseEldersSpec("") === null, "empty SHADE_TREE_DASH_ELDERS => use the record");
    ok(parseEldersSpec(`http://127.0.0.1:8877=${sigA.pub}`)[0].url === "http://127.0.0.1:8877", "url=signer parsed");
    let threw = 0;
    for (const bad of ["nope", `ftp://x=${sigA.pub}`, "http://x=zz", `bad.onion=${sigA.pub}`]) { try { parseEldersSpec(bad); } catch { threw++; } }
    ok(threw === 4, "malformed SHADE_TREE_DASH_ELDERS entries throw (fail closed)");
    const rec = resolveTargets({ network: "sepolia", eldersSpec: "" });
    ok(rec.elders.length >= 1 && rec.elders.every((e) => /^[a-z2-7]{56}\.onion$/.test(e.onion) && e.label.length === 8), "sepolia record resolves to labelled onion Elders");
    ok(eldersFromRecord({ elders: [{ onion: null, canopySigner: "x" }] }).length === 0, "record Elder with no onion is skipped");
    ok(errorKind(new Error("Socks5 proxy rejected connection - HostUnreachable")) === "tor: onion unreachable" && errorKind("weird") === "transport error", "error kinds are a fixed vocabulary");
    ok(scrubOnions(`x ${g1.onion} y`) === "x <onion> y", "scrubOnions removes full onions");
    ok(reduceCanopy([], { elderCount: 2 }).canopy.size === 0, "reduceCanopy over nothing is an empty canopy");
    await plainGetJson("http://127.0.0.1:1/x").then(() => ok(false, "plainGetJson to a closed port rejects"), () => ok(true, "plainGetJson to a closed port rejects"));

    // ===== server ==============================================================================
    console.log("\nserver:");
    const dash = makeDashboard({ targets: { network: "test", elders, pinnedCommit: COMMIT }, fetchJson, historyCap: 5 });
    dashServer = makeDashboardServer(dash, { network: "test" });
    await new Promise((r) => dashServer.listen(0, "127.0.0.1", r));
    const base = `http://127.0.0.1:${dashServer.address().port}`;
    const pending = await fetch(`${base}/api/canopy`);
    ok(pending.status === 503, "503 before the first observation (never a fake empty canopy)");
    for (let i = 0; i < 8; i++) await dash.tick();
    const api = await (await fetch(`${base}/api/canopy`)).json();
    ok(api.schema === "shade-tree-dashboard-v1" && api.canopy.size === 4, "GET /api/canopy serves the last observation");
    const hist = await (await fetch(`${base}/api/history`)).json();
    ok(hist.count === 5 && hist.cap === 5, "history ring bounded at its cap");
    ok(hist.samples.every((s) => Object.keys(s).sort().join() === "at,down,draining,elders,size"), "history samples are counts + booleans only");
    const page = await fetch(`${base}/`);
    const html = await page.text();
    ok(page.status === 200 && /Canopy<br><span>Dashboard<\/span>/.test(html), "GET / serves the page");
    ok(/script-src 'self'/.test(page.headers.get("content-security-policy") || "") && page.headers.get("x-frame-options") === "DENY", "page carries the site CSP + frame denial");
    ok(!/<script>/.test(html) && !/\son[a-z]+="/.test(html), "page has no inline script or handlers (CSP-clean)");
    for (const a of ["/dashboard.css", "/dashboard.js", "/site.css", "/favicon.svg"]) ok((await fetch(base + a)).status === 200, `asset ${a} served`);
    ok((await fetch(`${base}/api/canopy?x=1`)).status === 400, "query strings rejected");
    ok((await fetch(`${base}/nope`)).status === 404, "unknown route 404");
    ok((await fetch(`${base}/api/canopy`, { method: "POST" })).status === 405, "non-GET 405");
    ok((await fetch(`${base}/../package.json`)).status === 404, "no path traversal to repo files");
    const servedJson = JSON.stringify(api) + JSON.stringify(hist);
    ok(!fullOnions.some((o) => servedJson.includes(o)) && !OPS.some((a) => servedJson.toLowerCase().includes(a)), "served JSON leaks no full onion and no operator");
    ok(Object.keys(sampleOf(api)).length === 5, "sampleOf shape");
  } finally {
    await close(dashServer);
    for (const s of servers) await close(s);
  }

  console.log(`\n${failures === 0 ? "PASS" : "FAIL"}: web dashboard selftest (${failures} failure${failures === 1 ? "" : "s"})`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => { console.error(e); process.exit(1); });
