// Selftest for the egress benchmark's sites-file parser and report generator:
// bench/egress/lib/{sites,report}.mjs.
//
//   node bench/egress/parse.selftest.mjs
//
// The sites file decides what gets measured, so it fails closed: a malformed line is an error
// with a line number, never a silently dropped site, and an api marker that would also match a
// block is refused. The report decides what a reader concludes, so it must keep the harness's
// own failures out of every denominator, and must never print an IP, hostname, kernel build
// string or local path from the meta rows. No network, no files.

import assert from "node:assert/strict";
import { parseSites, selectSites, isLoopbackHost, allLoopback, TIERS, GENERIC_API_ERRORS } from "./lib/sites.mjs";
import { parseJsonl, fmtCell, fmtShare, quantile, buildReport, validateCohorts, isMeasured } from "./lib/report.mjs";
import { classify, NOT_MEASURED } from "./lib/classify.mjs";

let n = 0;
const t = (name, fn) => { fn(); n++; console.log(`  ok   ${name}`); };

// ---- sites -------------------------------------------------------------------------------

t("a good line with and without min= and marker", () => {
  const r = parseSites("# c\n\nweb a none https://a.example/ min=50 <title>a b\nsearch b own http://b.example/x?q=1\n");
  assert.ok(r.ok);
  assert.deepEqual(r.sites.map((s) => [s.site, s.minBytes, s.okMarker, s.line]), [["a", 50, "<title>a b", 3], ["b", null, "", 4]]);
  assert.deepEqual(TIERS, ["search", "web", "api"]);
});

t("every malformed line is reported with its line number and nothing is returned", () => {
  const bad = [
    ["web a none", /expected/],
    ["blog a none https://a.example/", /unknown tier/],
    ["web A! none https://a.example/", /bad name/],
    ["web a WALL https://a.example/", /bad wall/],
    ["web a none not-a-url", /bad url/],
    ["web a none ftp://a.example/", /http\(s\)/],
    ["web a none file:///etc/passwd", /http\(s\)/],
    ["web a none https://u:p@a.example/", /credentials/],
    ["web a none https://a.example/ (unclosed", /not a valid regex/],
    ["web a none https://a.example/ (a+)+$", /nested quantifier/],
    ["web a none https://a.example/ (.*)*", /nested quantifier/],
    ["web a none https://a.example/ " + "x".repeat(301), /longer than/],
  ];
  for (const [line, re] of bad) {
    const r = parseSites(`# header\n${line}\n`);
    assert.equal(r.ok, false, line);
    assert.equal(r.sites.length, 0);
    assert.match(r.errors[0], /^line 2: /);
    assert.match(r.errors[0], re, line);
  }
  const dup = parseSites("web a none https://a.example/\nweb a none https://b.example/\n");
  assert.match(dup.errors[0], /line 2: duplicate/);
  assert.deepEqual(parseSites("# only comments\n").errors, ["no sites"]);
  assert.equal(parseSites(null).ok, false);
});

t("item 3a: an api marker that matches a generic error body is refused", () => {
  // The two api markers from the #402 sites file each ended in a bare "error" alternative.
  for (const m of ['invalid_api_key|missing bearer|you didn\'t provide an api key|"error"', 'authentication_error|x-api-key|"error"', "error", "forbidden", '"type"']) {
    const r = parseSites(`api a cloudflare https://api.a.example/v1/models ${m}\n`);
    assert.equal(r.ok, false, m);
    assert.match(r.errors[0], /^line 1: api marker matches a generic error body/, m);
  }
  // markers that name the unauthenticated error are fine
  for (const m of ["invalid_api_key|missing bearer|you didn't provide an api key", "authentication_error|x-api-key"]) {
    const r = parseSites(`api a cloudflare https://api.a.example/v1/models ${m}\n`);
    assert.ok(r.ok, `${m}: ${r.errors.join("; ")}`);
  }
  // the rule is for the api tier only; a web marker may say "error"
  assert.ok(parseSites("web a none https://a.example/ error-page-ok\n").ok);
  assert.ok(GENERIC_API_ERRORS.length >= 3);
});

t("item 3a end to end: a marker the parser accepts cannot label an api 403 as ok", () => {
  const [site] = parseSites("api a cloudflare https://api.a.example/v1/models invalid_api_key|missing bearer\n").sites;
  const regionBlock = '{"error":{"code":"unsupported_country_region_territory","message":"Country, region, or territory not supported","type":"request_forbidden"}}';
  assert.equal(classify({ site, code: 403, body: regionBlock }).outcome, "blocked-403");
  assert.equal(classify({ site, code: 401, body: '{"error":{"message":"Missing bearer authentication in header"}}' }).outcome, "ok");
  for (const body of GENERIC_API_ERRORS) assert.notEqual(classify({ site, code: 401, body }).outcome, "ok", body);
});

t("--only keeps file order and rejects unknown names", () => {
  const { sites } = parseSites("web a none https://a.example/\nweb b none https://b.example/\nweb c none https://c.example/\n");
  assert.deepEqual(selectSites(sites, "c,a").sites.map((s) => s.site), ["a", "c"]);
  assert.equal(selectSites(sites, "").sites.length, 3);
  const r = selectSites(sites, "a,zz");
  assert.equal(r.ok, false);
  assert.match(r.error, /zz/);
});

t("loopback detection is exact (a lookalike host is not loopback)", () => {
  for (const h of ["127.0.0.1", "127.1.2.3", "localhost", "LOCALHOST", "::1", "[::1]"]) assert.ok(isLoopbackHost(h), h);
  for (const h of ["127.0.0.1.example.com", "localhost.example", "10.0.0.1", "0.0.0.0", "", null, "::ffff:8.8.8.8"]) assert.equal(isLoopbackHost(h), false, String(h));
  assert.equal(allLoopback([{ url: "not a url" }]), false);
  assert.equal(allLoopback([{ url: "http://127.0.0.1:8/" }, { url: "https://a.example/" }]), false);
  assert.equal(allLoopback([{ url: "http://127.0.0.1:8/" }, { url: "http://[::1]:9/" }]), true);
});

// ---- report ------------------------------------------------------------------------------

const row = (exit, client, site, outcome, extra = {}) => ({ exit, client, site, outcome, tier: "web", wall: "w-" + site, pass: 1, code: 200, t: 1, ts: "2026-01-01T00:00:00Z", ...extra });

t("parseJsonl separates meta, dial and cell rows and counts malformed lines", () => {
  const text = [JSON.stringify({ type: "meta", run: "r" }), JSON.stringify(row("a", "curl", "s", "ok")), "", "not json", "[1]", "null",
    JSON.stringify({ exit: "a", client: "curl", site: "s", outcome: "made-up" }), JSON.stringify({ type: "dial", exit: "a", phase: "cold" }),
    JSON.stringify(row("a", "curl", "s2", "proxy-refused"))].join("\n");
  const p = parseJsonl(text);
  assert.equal(p.metas.length, 1);
  assert.equal(p.rows.length, 2, "the not-measured outcomes are valid rows");
  assert.equal(p.dials.length, 1);
  assert.equal(p.bad, 4);
  assert.deepEqual(parseJsonl(undefined), { rows: [], dials: [], metas: [], bad: 0 });
});

t("fmtCell prints ok/n with the measured non-ok labels by count", () => {
  assert.equal(fmtCell([]), ".");
  assert.equal(fmtCell(["ok", "ok", "ok"]), "3/3");
  assert.equal(fmtCell(["ok", "blocked-challenge", "blocked-challenge"]), "1/3 chl:2");
  assert.equal(fmtCell(["captcha", "error", "error", "blocked-429"]), "0/4 err:2,429,cap");
  assert.equal(fmtCell(["weird"]), "0/1 weird");
  assert.equal(fmtCell(["blocked-403", "blocked-403"]), "0/2 403:2", "a count must not glue onto a numeric label");
});

t("item 4a: fmtCell keeps proxy refusals, harness errors and cancellations out of n", () => {
  assert.deepEqual([...NOT_MEASURED].map(isMeasured), [false, false, false]);
  assert.equal(isMeasured("error"), true);
  assert.equal(isMeasured("timeout"), true);
  assert.equal(fmtCell(["ok", "proxy-refused", "proxy-refused"]), "1/1 +prx:2");
  assert.equal(fmtCell(["ok", "blocked-403", "harness-error", "cancelled"]), "1/2 403 +can,+hrn");
  assert.equal(fmtCell(["proxy-refused"]), "-/0 +prx");
});

t("item 4a: fmtShare is ok over measured cells, with the not-measured count beside it", () => {
  assert.equal(fmtShare([]), ".");
  assert.equal(fmtShare(["ok", "error"]), "1/2 (50%)");
  assert.equal(fmtShare(["ok", "error", "proxy-refused", "proxy-refused"]), "1/2 (50%) +2 not measured");
  assert.equal(fmtShare(["proxy-refused"]), "-/0 +1 not measured");
});

t("quantile is nearest-rank and ignores non-numbers", () => {
  assert.equal(quantile([], 0.5), null);
  assert.equal(quantile([3, 1, 2], 0.5), 2);
  assert.equal(quantile([1, 2, 3, 4], 0.9), 4);
  assert.equal(quantile([NaN, 5, "x"], 0.5), 5);
});

t("buildReport: summary, per-wall, per-site and timing tables in the requested order", () => {
  const rows = [row("dc", "curl", "a", "ok"), row("dc", "curl", "a", "captcha", { pass: 2 }), row("tor", "curl", "a", "blocked-403"),
    row("dc", "headed", "b", "ok", { t: 4 }), row("tor", "headed", "b", "ok", { t: 8 }), row("tor", "headed", "z", "ok", { tier: "api", t: 8 })];
  const md = buildReport({ rows }, { exitOrder: ["tor", "dc"], clientOrder: ["headed", "curl"], title: "T | x" });
  assert.match(md, /^# T \\\| x/);
  assert.match(md, /\| client \| tor \| dc \|/);
  assert.match(md, /\| curl \| 0\/1 \(0%\) \| 1\/2 \(50%\) \|/);
  assert.match(md, /\| w-a \| curl \| 0\/1 403 \| 1\/2 cap \|/);
  assert.doesNotMatch(md, /\| w-a \| headed \|/, "a wall x client pair with no cells is not printed");
  assert.ok(md.indexOf("client = headed") < md.indexOf("client = curl"));
  // api tier rows sort after web rows
  const perSite = md.slice(md.indexOf("client = headed"));
  assert.ok(perSite.indexOf("| web | b |") < perSite.indexOf("| api | z |"));
  assert.match(md, /2 pass\(es\)/);
  assert.match(md, /\| headed \| 8\.0 \/ 8\.0 \| 4\.0 \/ 4\.0 \|/);
  assert.match(md, /6 measured, 0 not measured/);
  assert.doesNotMatch(md, /WARNING: \d+ of \d+ cells were not measured/);
});

t("item 4a: buildReport leaves not-measured cells out of every share, cell and timing", () => {
  // 4 cells for one exit/client: 1 ok, 1 site block, 2 refused by the local proxy (with a fake
  // long time). Charging the refusals would print 1/4 (25%) and a p90 of 99.0.
  const rows = [row("sn", "curl", "a", "ok", { t: 2 }), row("sn", "curl", "b", "blocked-403", { t: 2 }),
    row("sn", "curl", "c", "proxy-refused", { code: null, t: 99 }), row("sn", "curl", "d", "proxy-refused", { code: 403, t: 99 }),
    row("sn", "headed", "a", "harness-error", { code: null, t: 0 }), row("sn", "headed", "b", "cancelled", { t: 50, code: 200 })];
  const md = buildReport({ rows });
  assert.match(md, /\| curl \| 1\/2 \(50%\) \+2 not measured \|/);
  assert.match(md, /\| headed \| -\/0 \+2 not measured \|/);
  assert.match(md, /\| web \| c \| w-c \| -\/0 \+prx \|/);
  assert.match(md, /\| curl \| 2\.0 \/ 2\.0 \|/, "a refused cell's time must not enter the timing");
  assert.match(md, /\| headed \| \. \|/, "a cancelled cell with a status must not enter the timing");
  assert.match(md, /2 measured, 4 not measured/);
  assert.match(md, /WARNING: 4 of 6 cells were not measured/);
  assert.match(md, /\+prx = the local proxy refused/);
});

t("buildReport labels cell time as wall-clock including any browser settle wait", () => {
  const md = buildReport({ rows: [row("a", "headed", "s", "ok")] });
  assert.match(md, /## Cell time, seconds/);
  assert.match(md, /includes any fixed settle wait/);
  assert.doesNotMatch(md, /Page time/);
});

t("item 8: the report prints no IP, hostname, kernel string, local path or exit spec from meta rows", () => {
  const metas = [{ type: "meta", run: "r1", exit: "dc", exitKind: "datacenter", exitSpec: "http://198.51.100.7:3128",
    exitInfo: { ip: "203.0.113.9", org: "AS64500 Example", country: "ZZ" },
    clients: ["curl"], passes: 1, startedAt: "S", git: { commit: "0123456789abcdef", dirty: true },
    versions: { node: "v24", curl: "curl 8.5.0 (x86_64-pc-linux-gnu) libcurl/8.5.0 OpenSSL/3.0.13" },
    sites: { path: "/srv/operator/private/sites.txt", sha256: "a".repeat(64), count: 1 }, args: ["--out", "/srv/operator/runs/x.jsonl"],
    host: { cpus: 2, cpu: "cpu-model", os: "linux 5.15.0-1-fixture", hostname: "box-17.internal" } }];
  const dials = [{ type: "dial", exit: "sn", phase: "cold", tTunnelMs: 13700, tTotalMs: 14000 }, { type: "dial", exit: "sn", phase: "warm", tTunnelMs: 1400, tTotalMs: 1700 },
    { type: "dial", exit: "sn", phase: "warm", error: "timeout" }];
  for (const opts of [{}, { showIps: true }]) {
    const md = buildReport({ rows: [row("dc", "curl", "a", "ok")], metas, dials }, opts);
    assert.doesNotMatch(md, /203\.0\.113\.9/, "exit IP");
    assert.doesNotMatch(md, /198\.51\.100\.7/, "exit spec host");
    assert.doesNotMatch(md, /5\.15\.0|fixture/, "kernel release");
    assert.doesNotMatch(md, /\/srv\/|private\/|sites\.txt|x\.jsonl/, "local path");
    assert.doesNotMatch(md, /box-17/, "hostname");
    assert.doesNotMatch(md, /x86_64-pc-linux-gnu|OpenSSL/, "curl build line");
    assert.match(md, /AS64500 Example, ZZ/);
    assert.match(md, /0123456789ab\+dirty/);
    assert.match(md, /host 2 x cpu-model, linux\./);
    assert.match(md, /, curl 8\.5\.0\./);
    assert.match(md, /\| sn \| cold \| 1 \| 0 \| 13\.7 \|/);
    assert.match(md, /\| sn \| warm \| 2 \| 1 \| 1\.4 \|/);
  }
  assert.match(buildReport({ rows: [], metas: [{ type: "meta" }] }), /exit not looked up/);
  assert.match(buildReport({ rows: [], metas: [{ type: "meta", host: { os: "../../etc" } }] }), /host \? x \?, \?\./);
  assert.match(buildReport(), /^# Egress benchmark report/);
});

t("validateCohorts refuses duplicate and mixed cells and warns on incomplete or unverified runs", () => {
  const cell = { run: "r", exit: "e", client: "node", tier: "web", site: "s", url: "http://127.0.0.1/", pass: 1 };
  assert.throws(() => validateCohorts([cell, cell], []), /duplicate/);
  assert.throws(() => validateCohorts([cell, { ...cell, run: "r2" }], []), /mixed/);
  assert.throws(() => validateCohorts([cell, { ...cell, pass: 2, tier: "api" }], []), /ambiguous/);
  assert.throws(() => validateCohorts([cell, { ...cell, pass: 2, url: "http://127.0.0.1/x" }], []), /changed site URL/);
  assert.match(validateCohorts([cell], []).join(), /Unverified metadata for e/);
  const meta = { run: "r", exit: "e", passes: 2, clients: ["node"], sites: { count: 1 } };
  assert.match(validateCohorts([cell], [meta]).join(), /Incomplete e: observed 1, expected 2/);
  assert.match(validateCohorts([cell], [meta]).join(), /Unverified site manifest/);
  assert.throws(() => validateCohorts([cell], [meta, meta]), /duplicate run metadata/);
  assert.throws(() => validateCohorts([{ ...cell, client: "curl" }], [meta]), /outside planned cohort/);
  assert.throws(() => validateCohorts([{ ...cell, url_sha256: "x" }], [{ ...meta, plannedSites: [{ tier: "web", site: "s", urlHash: "y" }] }]), /outside planned cohort/);
  assert.match(validateCohorts([], [{ sites: { sha256: "a" } }, { sites: { sha256: "b" } }]).join(), /descriptive results only/);
});

console.log(`PASS parse (${n} cases)`);
