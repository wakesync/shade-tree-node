// Canopy observer for the operator dashboard (web/dashboard-server.mjs).
//
// The status page (web/status-server.mjs) reads ONE bootnode. A v4 network record lists every
// Elder Tree (network/<name>/deployment.json `elders[]`), each with its own Canopy signer, and a
// client fails over between them. So an Elder can be down for days while the canopy still works
// and the one-Elder status page, the hosted uptime probe (which reads elders[0] only) and the public
// Grove all stay green. This module observes EVERY Elder of the record independently, verifies
// each Elder's directory against THAT Elder's pinned signer, and reduces the result to a
// privacy-scrubbed view.
//
// Trust model, the same as the status page: this is a cache viewer, not a trust root.
//   - A directory counts only if it verifies under the Elder's own pinned signer (verifyDirectory)
//     AND its `issued` time is inside the freshness window. A directory signed by the OTHER Elder's
//     key is rejected for this Elder: per-Elder pins, never a union of pins.
//   - Only verified, fresh directories feed the merged canopy. An unverified Elder is shown with its
//     reason and contributes no node rows, so a lying Elder shows up as "unverified", never as a
//     forged fleet.
//   - The incident feed and the relay aggregate are verified under the same Elder signer; a
//     tampered feed is reported unverified and its contents are dropped.
//
// Privacy, the same line as the status page, applied to more fields:
//   - a node onion is truncated to its first 16 characters before it leaves this module; the full
//     address is only ever a Map key inside reduce();
//   - operator addresses are dropped; a node carries a staked boolean and the canopy carries one
//     aggregate count of distinct operators;
//   - the self-declared caps.region is NEVER put on a node row (that would map a node to a region);
//     regions appear only as aggregate buckets folded at k (web/fleet-map.mjs bucketBy), so a named
//     region always stands for at least k nodes;
//   - incident `instance` labels are dropped (they name hosts, and the canopy deliberately does not
//     map hosts to onions);
//   - error strings are scrubbed of every full onion.
// Elder onions are public (they are in the committed network record), so Elders are labelled by an
// 8-character prefix of their onion.

import http from "node:http";
import { verifyDirectory, canonicalCaps, isDraining } from "../packages/node/lib/directory.mjs";
import { verifyIncidents } from "../packages/node/bootnode/incidents.mjs";
import { verifyRelayAggregate } from "../packages/node/lib/relay-telemetry.mjs";
import { eldersOf } from "../packages/node/lib/network-record.mjs";
import { bucketBy } from "./fleet-map.mjs";

export const DASHBOARD_SCHEMA = "shade-tree-dashboard-v1";

// Same 16-character prefix the status page uses: enough to tell two rows apart, far short of the
// 56 characters that would make the canopy enumerable.
export const ONION_PREFIX = 16;
export const ELDER_LABEL_PREFIX = 8;

// Directory freshness, matching scripts/uptime-probe.mjs (DIR_MAX_AGE_SEC / DIR_FUTURE_SEC).
export const DIR_MAX_AGE_SEC = 300;
export const DIR_FUTURE_SEC = 300;

// Responses are tiny (a 13-node directory is ~12 KB). Cap them well below fetch.mjs's 2 MB so a
// hostile Elder gets a bounded read. 512 KiB still holds a directory of several hundred nodes.
export const MAX_RESPONSE_BYTES = 512 * 1024;

// k for the region fold. Matches web/fleet-map.mjs DEFAULT_K; raise it, never lower it below 2.
export const REGION_K = 2;

const ONION_RE = /[a-z2-7]{56}\.onion/gi;
export const scrubOnions = (s) => String(s == null ? "" : s).replace(ONION_RE, "<onion>");

const isHex64 = (s) => typeof s === "string" && /^[0-9a-f]{64}$/i.test(s);
const isCommit = (s) => typeof s === "string" && /^[0-9a-f]{40}$/.test(s);

// ---- configuration --------------------------------------------------------------------------

// Elders from a loaded network record: [{ label, onion, signer }]. A record signer may be a list
// (rotation); keep it as a list, verifyDirectory accepts both.
export function eldersFromRecord(deployment) {
  return eldersOf(deployment)
    .filter((e) => typeof e.onion === "string" && e.onion.endsWith(".onion"))
    .map((e) => ({ label: e.onion.slice(0, ELDER_LABEL_PREFIX), onion: e.onion, signer: e.canopySigner }));
}

// Dev / test override: SHADE_TREE_DASH_ELDERS="http://127.0.0.1:8877=<signerhex>,<onion>=<signerhex>".
// Each entry is <url-or-onion>=<signer>. Returns null when unset; throws on a malformed entry so a
// typo fails closed instead of silently watching nothing.
export function parseEldersSpec(spec) {
  if (!spec) return null;
  return spec.split(",").map((raw) => raw.trim()).filter(Boolean).map((entry, i) => {
    const at = entry.lastIndexOf("=");
    if (at <= 0) throw new Error(`SHADE_TREE_DASH_ELDERS entry ${i + 1}: expected <url-or-onion>=<signer>`);
    const target = entry.slice(0, at).trim();
    const signer = entry.slice(at + 1).trim().toLowerCase().replace(/^0x/, "");
    if (!isHex64(signer)) throw new Error(`SHADE_TREE_DASH_ELDERS entry ${i + 1}: signer must be 64 hex`);
    if (/^https?:\/\//.test(target)) return { label: `elder-${i + 1}`, url: target.replace(/\/$/, ""), signer };
    if (/^[a-z2-7]{56}\.onion$/.test(target)) return { label: target.slice(0, ELDER_LABEL_PREFIX), onion: target, signer };
    throw new Error(`SHADE_TREE_DASH_ELDERS entry ${i + 1}: target must be an http(s) URL or a v3 .onion`);
  });
}

// ---- transport --------------------------------------------------------------------------------

// Plain-http GET with a bounded read and a timeout. Dev/local Elders and the selftests only; real
// Elders are onions and go through packages/node/bootnode/fetch.mjs.
export function plainGetJson(url, { maxBytes = MAX_RESPONSE_BYTES, timeoutMs = 10_000 } = {}) {
  return new Promise((resolve, reject) => {
    const req = http.get(url, { headers: { Accept: "application/json" } }, (res) => {
      const chunks = [];
      let total = 0;
      res.on("data", (c) => {
        total += c.length;
        if (total > maxBytes) { req.destroy(); reject(new Error(`response exceeded ${maxBytes} bytes`)); return; }
        chunks.push(c);
      });
      res.on("end", () => {
        const body = Buffer.concat(chunks).toString("utf8");
        if (res.statusCode !== 200) return reject(new Error(`HTTP ${res.statusCode}`));
        try { resolve(JSON.parse(body)); } catch { reject(new Error("bad-json")); }
      });
      res.on("error", reject);
    });
    req.on("error", reject);
    req.setTimeout(timeoutMs, () => req.destroy(new Error("timeout")));
  });
}

// The default per-Elder GET: plain http for a url Elder, Tor for an onion Elder. `socks` is only
// loaded on the onion path, so the selftests never need it.
export function makeElderFetch({ torHost = "127.0.0.1", torPort = 9250, timeoutMs = 20_000, attempts = 2 } = {}) {
  return async (elder, path) => {
    if (elder.url) return plainGetJson(elder.url + path, { timeoutMs });
    const { fetchOverTor } = await import("../packages/node/bootnode/fetch.mjs");
    return fetchOverTor(elder.onion, path, { torHost, torPort, timeoutMs, attempts, maxBytes: MAX_RESPONSE_BYTES });
  };
}

// Optional active dial of each node: a bare SOCKS connect to <onion>:80, the same check the
// Elder's own prober makes (packages/node/bootnode/server.mjs defaultProbe). It sends no request
// and no proof. Off by default (SHADE_TREE_DASH_PROBE_NODES=1): it adds Tor load on every node.
export function makeNodeDialer({ torHost = "127.0.0.1", torPort = 9250, timeoutMs = 45_000 } = {}) {
  return async (onion) => {
    const { SocksClient } = await import("socks");
    const started = Date.now();
    const { socket } = await SocksClient.createConnection({
      proxy: { host: torHost, port: torPort, type: 5 },
      command: "connect",
      destination: { host: onion, port: 80 },
      timeout: timeoutMs,
    });
    socket.destroy();
    return Date.now() - started;
  };
}

// ---- per-Elder observation ----------------------------------------------------------------

// A short, fixed vocabulary for why an Elder did not answer. The raw transport error is long
// and can carry an onion; the page shows the kind, the raw text stays in the server log.
export function errorKind(err) {
  const m = String(err?.message || err || "");
  if (/HostUnreachable|host unreachable/i.test(m)) return "tor: onion unreachable";
  if (/TTL ?expired|TtlExpired/i.test(m)) return "tor: circuit ttl expired";
  if (/timeout|timed out/i.test(m)) return "timeout";
  if (/ECONNREFUSED/.test(m)) return "connection refused";
  if (/exceeded \d+ bytes/.test(m)) return "response too large";
  if (/HTTP \d{3}/.test(m)) return "http " + m.match(/HTTP (\d{3})/)[1];
  if (/json/i.test(m)) return "bad json";
  return "transport error";
}

async function timed(fn) {
  const started = Date.now();
  try { return { ok: true, value: await fn(), ms: Date.now() - started }; }
  catch (e) { return { ok: false, error: e, ms: Date.now() - started }; }
}

// Verify one Elder's directory: signature under THIS Elder's pin, then freshness. Pure; never throws.
export function checkDirectory(dir, signer, { nowSec = Math.floor(Date.now() / 1000) } = {}) {
  if (!dir || typeof dir !== "object" || Array.isArray(dir)) return { verified: false, fresh: false, reason: "no-directory" };
  let v;
  try { v = verifyDirectory(dir, signer); } catch { v = { ok: false, reason: "verify-threw" }; }
  // Some verifier reasons append a short onion prefix (bad-caps-sig:<12 chars>..). Keep the kind only:
  // the page names which Elder failed, not which node inside its directory.
  if (!v.ok) return { verified: false, fresh: false, reason: scrubOnions(String(v.reason || "unverified").split(":")[0]).slice(0, 48) };
  const issued = dir.issued;
  if (!Number.isInteger(issued)) return { verified: true, fresh: false, reason: "no-issued-time" };
  const ageSec = nowSec - issued;
  if (ageSec > DIR_MAX_AGE_SEC) return { verified: true, fresh: false, issued, ageSec, reason: "stale" };
  if (-ageSec > DIR_FUTURE_SEC) return { verified: true, fresh: false, issued, ageSec, reason: "future-dated" };
  return { verified: true, fresh: true, issued, ageSec, reason: null };
}

function checkIncidents(doc, signer) {
  if (!doc) return null;
  let v;
  try { v = verifyIncidents(doc, Array.isArray(signer) ? signer[0] : signer); } catch { v = { ok: false, reason: "verify-threw" }; }
  if (!v.ok) return { verified: false, reason: v.reason, active: 0, items: [] };
  const nowSec = Math.floor(Date.now() / 1000);
  // `instance` is a host label: dropped here. Summary is operator prose, clipped and onion-scrubbed.
  const items = doc.incidents
    .filter((i) => i && (i.until == null || i.until > nowSec))
    .slice(0, 16)
    .map((i) => ({
      component: String(i.component || "other").slice(0, 16),
      severity: String(i.severity || "warning").slice(0, 16),
      summary: scrubOnions(i.summary).slice(0, 160),
      since: Number.isInteger(i.since) ? i.since : null,
    }));
  return { verified: true, reason: null, active: items.length, items };
}

function checkRelay(aggregate, signer) {
  if (!aggregate) return null;
  const pins = Array.isArray(signer) ? signer : [signer];
  let ok = false;
  try { ok = pins.some((p) => verifyRelayAggregate(aggregate, String(p).toLowerCase())); } catch { ok = false; }
  if (!ok) return { verified: false, windows: [] };
  return {
    verified: true,
    minimumCohort: aggregate.minimumCohort,
    windows: ["sixHour", "twentyFourHour"].map((key) => {
      const w = aggregate.windows[key];
      return { hours: w.windowHours, status: w.status, reportingNodes: w.reportingNodes, ...(w.status === "available" ? { roundedBytes: w.roundedBytes } : { suppressionReason: w.suppressionReason }) };
    }),
  };
}

// Observe one Elder. Returns the scrubbed public view plus `_dir` (the verified directory, kept
// in-process for reduce() and deleted before anything is served).
export async function observeElder(elder, { fetchJson, pinnedCommit = null, nowSec } = {}) {
  const view = {
    label: elder.label,
    reachable: false,
    latencyMs: null,
    health: null,
    commit: null,
    commitMatchesPin: null,
    directory: { verified: false, fresh: false, reason: "not-fetched", issued: null, ageSec: null, size: 0, latencyMs: null },
    incidents: null,
    relay: null,
    error: null,
  };
  const h = await timed(() => fetchJson(elder, "/health"));
  if (!h.ok) {
    view.error = errorKind(h.error);
    view.directory.reason = "elder-unreachable";
    return { view, dir: null };
  }
  view.reachable = true;
  view.latencyMs = h.ms;
  const health = h.value && typeof h.value === "object" ? h.value : {};
  view.health = {
    ok: health.ok === true,
    count: Number.isInteger(health.count) ? health.count : null,
    admission: typeof health.admission === "string" ? health.admission.slice(0, 16) : null,
  };
  if (isCommit(health.commit)) {
    view.commit = health.commit;
    if (isCommit(pinnedCommit)) view.commitMatchesPin = health.commit === pinnedCommit;
  }

  const [d, inc, rel] = await Promise.all([
    timed(() => fetchJson(elder, "/directory")),
    timed(() => fetchJson(elder, "/incidents")),
    timed(() => fetchJson(elder, "/telemetry/aggregate")),
  ]);
  let dir = null;
  if (!d.ok) {
    view.directory = { ...view.directory, reason: "fetch: " + errorKind(d.error) };
  } else {
    const c = checkDirectory(d.value, elder.signer, { nowSec });
    view.directory = {
      verified: c.verified,
      fresh: c.fresh,
      reason: c.reason,
      issued: c.issued ?? null,
      ageSec: c.ageSec ?? null,
      size: c.verified && Array.isArray(d.value.gateways) ? d.value.gateways.length : 0,
      latencyMs: d.ms,
    };
    if (c.verified && c.fresh) dir = d.value;
  }
  view.incidents = inc.ok ? checkIncidents(inc.value, elder.signer) : null;
  // A 404 telemetry-disabled is normal; only a served, verifiable aggregate is shown.
  view.relay = rel.ok ? checkRelay(rel.value, elder.signer) : null;
  return { view, dir };
}

// ---- merge ------------------------------------------------------------------------------------

function protoLabel(caps) {
  const p = caps.proto;
  if (!p) return "unspecified";
  return p.min === p.max ? `v${p.min}` : `v${p.min}-v${p.max}`;
}

// Merge the verified, fresh directories into one canopy view. The full onion is a Map key here
// and is never copied into the output.
export function reduceCanopy(verified, { elderCount, dials = new Map(), k = REGION_K } = {}) {
  const byOnion = new Map();
  for (const { index, dir } of verified) {
    for (const g of dir.gateways || []) {
      if (!g || typeof g.onion !== "string") continue;
      let row = byOnion.get(g.onion);
      if (!row) {
        const caps = canonicalCaps(g.caps);
        row = {
          entry: g,
          caps,
          listedBy: new Set(),
          health: new Set(),
        };
        byOnion.set(g.onion, row);
      }
      row.listedBy.add(index);
      row.health.add(g.health === "down" ? "down" : g.health === "up" ? "up" : "unknown");
    }
  }

  const nodes = [];
  const operators = new Set();
  const forRegions = [];
  const tally = { up: 0, down: 0, mixed: 0, draining: 0, staked: 0, unstaked: 0, listedByAll: 0, weight: 0 };
  const protos = new Map();
  const admits = new Map();
  const coverage = new Map();
  for (const [onion, row] of byOnion) {
    const g = row.entry;
    const health = row.health.size === 1 ? [...row.health][0] : "mixed";
    const draining = isDraining({ caps: row.caps });
    const staked = Object.prototype.hasOwnProperty.call(g, "operator") ? g.staked === true : null;
    const weight = Number.isFinite(Number(g.weight)) ? Math.max(0, Math.min(1000, Number(g.weight))) : 0;
    if (typeof g.operator === "string") operators.add(g.operator.toLowerCase());
    forRegions.push({ region: row.caps.region || null, weight });
    if (health === "up") tally.up += 1; else if (health === "down") tally.down += 1; else tally.mixed += 1;
    if (draining) tally.draining += 1;
    if (staked === true) tally.staked += 1; else if (staked === false) tally.unstaked += 1;
    if (row.listedBy.size === elderCount) tally.listedByAll += 1;
    tally.weight += weight;
    const pl = protoLabel(row.caps);
    protos.set(pl, (protos.get(pl) || 0) + 1);
    for (const a of row.caps.admits || []) admits.set(a, (admits.get(a) || 0) + 1);
    // How many Elders list this node: "all Elders" or "1 of 2 Elders".
    const cov = row.listedBy.size === elderCount ? "all Elders" : `${row.listedBy.size} of ${elderCount} Elders`;
    coverage.set(cov, (coverage.get(cov) || 0) + 1);
    const dial = dials.get(onion);
    nodes.push({
      onionShort: onion.slice(0, ONION_PREFIX),
      listedBy: [...row.listedBy].sort((a, b) => a - b),
      health,
      weight,
      draining,
      proto: pl,
      admits: row.caps.admits || [],
      staked,
      dialMs: dial && dial.ok ? dial.ms : null,
      dialFailed: dial ? !dial.ok : null,
    });
  }
  nodes.sort((a, b) => (a.onionShort < b.onionShort ? -1 : a.onionShort > b.onionShort ? 1 : 0));
  const sortCounts = (m) => [...m].map(([label, count]) => ({ label, count })).sort((a, b) => b.count - a.count || (a.label < b.label ? -1 : 1));

  // Regions: aggregate only, folded at k. bucketBy reads `region` and `weight` and nothing else.
  const regions = bucketBy(forRegions, "region", Math.max(2, k));
  return {
    canopy: {
      size: byOnion.size,
      listedByAll: tally.listedByAll,
      up: tally.up,
      down: tally.down,
      mixed: tally.mixed,
      draining: tally.draining,
      staked: tally.staked,
      unstaked: tally.unstaked,
      weight: tally.weight,
      operators: operators.size,
      protocols: sortCounts(protos),
      admits: sortCounts(admits),
      coverage: sortCounts(coverage),
      regions: {
        k: regions.k,
        shown: regions.shown.map(({ label, count }) => ({ label, count })),
        folded: regions.folded ? regions.folded.count : 0,
      },
    },
    nodes,
  };
}

// ---- one full observation -------------------------------------------------------------------

// Observe every Elder in parallel, verify, merge. `dialNodes` (optional) dials each merged node
// with bounded concurrency. Never throws: every failure is a field on the result.
export async function observeCanopy({
  network = null,
  elders,
  fetchJson,
  pinnedCommit = null,
  dialNode = null,
  dialConcurrency = 4,
  now = Date.now(),
} = {}) {
  const nowSec = Math.floor(now / 1000);
  const results = await Promise.all(elders.map((e) => observeElder(e, { fetchJson, pinnedCommit, nowSec })));
  const verified = results.map((r, index) => ({ index, dir: r.dir })).filter((r) => r.dir);

  const dials = new Map();
  if (dialNode && verified.length) {
    const onions = [...new Set(verified.flatMap((v) => (v.dir.gateways || []).map((g) => g && g.onion).filter((o) => typeof o === "string")))];
    let next = 0;
    const worker = async () => {
      while (next < onions.length) {
        const onion = onions[next++];
        try { dials.set(onion, { ok: true, ms: await dialNode(onion) }); }
        catch { dials.set(onion, { ok: false }); }
      }
    };
    await Promise.all(Array.from({ length: Math.max(1, Math.min(dialConcurrency, onions.length)) }, worker));
  }

  const { canopy, nodes } = reduceCanopy(verified, { elderCount: elders.length, dials });
  const elderViews = results.map((r) => r.view);
  const reachable = elderViews.filter((e) => e.reachable).length;
  const verifiedCount = elderViews.filter((e) => e.directory.verified && e.directory.fresh).length;
  const freshest = elderViews.map((e) => e.directory.ageSec).filter((a) => Number.isInteger(a));
  return {
    schema: DASHBOARD_SCHEMA,
    network,
    observedAt: new Date(now).toISOString(),
    pinnedCommit: isCommit(pinnedCommit) ? pinnedCommit : null,
    summary: {
      elders: elders.length,
      eldersReachable: reachable,
      eldersVerified: verifiedCount,
      directoryAgeSec: freshest.length ? Math.min(...freshest) : null,
      nodeDialProbe: Boolean(dialNode),
    },
    elders: elderViews,
    canopy,
    nodes,
  };
}
