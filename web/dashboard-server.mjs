// Canopy dashboard: an operator view of every Elder Tree and every node it lists.
//
// web/status-server.mjs shows one bootnode. This server reads every Elder of a network record
// (web/canopy-observe.mjs), verifies each directory against that Elder's own pinned signer, merges
// the verified ones, and serves a privacy-scrubbed view plus a bounded in-memory trend. It answers
// the questions the one-Elder page cannot: is every Elder up, do they agree, how fresh is each
// directory, which nodes are down, draining or listed by only one Elder.
//
// Like the status page it is a cache viewer, not a trust root, and it binds loopback with no auth.
// It is an operator tool, not a public page: node rows come from the discovery plane, which
// specs/data-api.md says must not be mirrored onto the public site. See web/DASHBOARD.md.
//
// Observation runs on a timer, not per request: an onion round trip takes seconds and an Elder that
// is down takes the full timeout, so a page view must never wait on Tor. Every request reads the
// last completed observation.
//
// Config (all optional):
//   SHADE_TREE_NETWORK              network record to read Elders from          (default sepolia)
//   SHADE_TREE_DASH_ELDERS          override: "<url-or-onion>=<signer>,..."   (dev/test)
//   SHADE_TREE_DASH_PORT            loopback port                               (default 8091)
//   SHADE_TREE_DASH_INTERVAL_SEC    seconds between observations                (default 60, min 15)
//   SHADE_TREE_DASH_PROBE_NODES     1 => also dial each node's onion (SOCKS connect only)
//   SHADE_TREE_TOR_HOST / _TOR_PORT local Tor SOCKS                             (127.0.0.1:9250)
//
// Run: node web/dashboard-server.mjs

import http from "node:http";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { loadNetworkRecords } from "../packages/node/lib/network-record.mjs";
import {
  eldersFromRecord,
  makeElderFetch,
  makeNodeDialer,
  observeCanopy,
  parseEldersSpec,
} from "./canopy-observe.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const SITE = join(HERE, "..", "docs", "post");

// The page shares the public site's stylesheet, so it draws with the same tokens, type and nav.
// Read once at start: these are static files and the server never writes them.
const ASSETS = new Map([
  ["/", { file: join(HERE, "dashboard.html"), type: "text/html; charset=utf-8" }],
  ["/dashboard.css", { file: join(HERE, "dashboard.css"), type: "text/css; charset=utf-8" }],
  ["/dashboard.js", { file: join(HERE, "dashboard.js"), type: "text/javascript; charset=utf-8" }],
  ["/site.css", { file: join(SITE, "site.css"), type: "text/css; charset=utf-8" }],
  ["/favicon.svg", { file: join(SITE, "favicon.svg"), type: "image/svg+xml" }],
]);

// The same policy the public site sends (docs/post/vercel.json), so a page that works here works
// under it: no inline script, same-origin fetch only.
const PAGE_HEADERS = Object.freeze({
  "content-security-policy": "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; font-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
  "referrer-policy": "no-referrer",
  "x-content-type-options": "nosniff",
  "x-frame-options": "DENY",
  "cache-control": "no-store",
});

// 1440 samples = 24 h at the 60 s default. Counts and booleans only (see sampleOf).
export const HISTORY_CAP = 1440;

export function configFromEnv(env = process.env) {
  const interval = Math.max(15, Number(env.SHADE_TREE_DASH_INTERVAL_SEC || 60) || 60);
  return {
    network: env.SHADE_TREE_NETWORK || "sepolia",
    eldersSpec: env.SHADE_TREE_DASH_ELDERS || "",
    port: Number(env.SHADE_TREE_DASH_PORT || 8091),
    intervalMs: interval * 1000,
    probeNodes: /^(1|true|yes|on)$/i.test(env.SHADE_TREE_DASH_PROBE_NODES || ""),
    torHost: env.SHADE_TREE_TOR_HOST || "127.0.0.1",
    torPort: Number(env.SHADE_TREE_TOR_PORT || 9250),
  };
}

// Resolve Elders + the pinned Elder commit. An explicit SHADE_TREE_DASH_ELDERS wins over the record.
export function resolveTargets(cfg) {
  const override = parseEldersSpec(cfg.eldersSpec);
  if (override) return { network: cfg.network, elders: override, pinnedCommit: null };
  const { deployment } = loadNetworkRecords(cfg.network);
  if (!deployment) throw new Error(`network/${cfg.network}/deployment.json not found`);
  const elders = eldersFromRecord(deployment);
  if (!elders.length) throw new Error(`network/${cfg.network}/deployment.json lists no Elder onion`);
  return { network: cfg.network, elders, pinnedCommit: deployment?.services?.elder?.commit || null };
}

// One trend sample: per-Elder booleans + counts. No node, onion prefix, or operator enters it.
export function sampleOf(obs) {
  return {
    at: obs.observedAt,
    size: obs.canopy.size,
    down: obs.canopy.down + obs.canopy.mixed,
    draining: obs.canopy.draining,
    elders: obs.elders.map((e) => ({ reachable: e.reachable, verified: e.directory.verified && e.directory.fresh, size: e.directory.size })),
  };
}

export function makeRing(cap = HISTORY_CAP) {
  const buf = [];
  return {
    cap,
    push(s) { buf.push(s); if (buf.length > cap) buf.splice(0, buf.length - cap); },
    samples() { return buf.slice(); },
  };
}

// The observer loop. `observe` is injectable so the selftest can drive it without a timer.
export function makeDashboard({ targets, fetchJson, dialNode = null, historyCap = HISTORY_CAP, now = () => Date.now() }) {
  const history = makeRing(historyCap);
  let last = null;
  let running = null;
  async function tick() {
    if (running) return running; // never overlap two observations
    running = (async () => {
      const obs = await observeCanopy({ ...targets, fetchJson, dialNode, now: now() });
      last = obs;
      history.push(sampleOf(obs));
      return obs;
    })().finally(() => { running = null; });
    return running;
  }
  return { tick, latest: () => last, history };
}

function sendJson(res, status, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(status, { "content-type": "application/json; charset=utf-8", "content-length": Buffer.byteLength(body), ...PAGE_HEADERS });
  res.end(body);
}

export function makeDashboardServer(dashboard, { network = null } = {}) {
  const files = new Map([...ASSETS].map(([route, a]) => [route, { ...a, body: readFileSync(a.file) }]));
  return http.createServer((req, res) => {
    try {
      const url = new URL(req.url, "http://dashboard");
      if (req.method !== "GET" && req.method !== "HEAD") return sendJson(res, 405, { error: "method" });
      // No query parameters on any route: one view, no caller-controlled variants.
      if (url.search) return sendJson(res, 400, { error: "unsupported_query" });
      const path = url.pathname === "/index.html" ? "/" : url.pathname;
      const asset = files.get(path);
      if (asset) {
        res.writeHead(200, { "content-type": asset.type, "content-length": asset.body.length, ...PAGE_HEADERS });
        return res.end(req.method === "HEAD" ? undefined : asset.body);
      }
      if (path === "/api/canopy") {
        const obs = dashboard.latest();
        if (!obs) return sendJson(res, 503, { error: "first_observation_pending", network });
        return sendJson(res, 200, obs);
      }
      if (path === "/api/history") {
        const samples = dashboard.history.samples();
        return sendJson(res, 200, { cap: dashboard.history.cap, count: samples.length, samples });
      }
      return sendJson(res, 404, { error: "no-route" });
    } catch {
      return sendJson(res, 500, { error: "internal" });
    }
  });
}

async function main() {
  const cfg = configFromEnv();
  let targets;
  try { targets = resolveTargets(cfg); }
  catch (e) { console.error(`dashboard: ${e.message}`); process.exit(1); }
  const fetchJson = makeElderFetch({ torHost: cfg.torHost, torPort: cfg.torPort });
  const dialNode = cfg.probeNodes ? makeNodeDialer({ torHost: cfg.torHost, torPort: cfg.torPort }) : null;
  const dashboard = makeDashboard({ targets, fetchJson, dialNode });
  const server = makeDashboardServer(dashboard, { network: targets.network });
  server.listen(cfg.port, "127.0.0.1", () => {
    console.log(`canopy dashboard on http://127.0.0.1:${cfg.port}  (network=${targets.network}, elders=${targets.elders.length}, every ${cfg.intervalMs / 1000}s${dialNode ? ", node dial on" : ""})`);
  });
  const loop = async () => {
    try {
      const obs = await dashboard.tick();
      const s = obs.summary;
      console.log(`${obs.observedAt} elders ${s.eldersVerified}/${s.elders} verified, canopy ${obs.canopy.size}`);
    } catch (e) { console.error("observation failed:", String(e?.message || e).replace(/[a-z2-7]{56}\.onion/gi, "<onion>")); }
    setTimeout(loop, cfg.intervalMs).unref?.();
  };
  loop();
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch((e) => { console.error(e); process.exit(1); });
}
