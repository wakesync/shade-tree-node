// Aggregate egress benchmark JSONL into markdown tables. Pure: rows in, string out.
//
// Cell format: `ok/n` plus the other measured labels by count, e.g. `1/3 chl:2` (the colon keeps
// "403 twice" from reading as "4032"). n counts only MEASURED cells for that (exit, client,
// site), and is printed so a reader never mistakes 1/1 for 3/3.
//
// Measured vs not measured: a cell whose outcome is in NOT_MEASURED (lib/classify.mjs: the local
// proxy refused the request, the harness could not run the cell, or the operator cancelled it)
// says nothing about the exit or the site. It is left out of every denominator, every share and
// every timing, and printed after the cell as `+prx`, `+hrn` or `+can` (with a count), so the
// loss stays visible without being charged to the exit or the site.
//
// The report has no single "percent blocked per exit" headline on purpose: an exit can do better
// on some sites and worse on others, and a per-exit average hides that. The summary is there,
// but the per-wall and per-site tables come right after it.
//
// The report prints no IP address, hostname, kernel build string or local path, whatever the
// meta rows carry: the provenance line names only the platform and the hardware class.

import { ABBR, OUTCOMES, NOT_MEASURED } from "./classify.mjs";

const TIER_ORDER = { search: 0, web: 1, api: 2 };

export function isMeasured(outcome) { return !NOT_MEASURED.includes(outcome); }

// Parse JSONL text; skip blank lines; collect (not throw on) malformed lines.
export function parseJsonl(text) {
  const rows = [];
  const metas = [];
  let bad = 0;
  for (const line of String(text || "").split(/\r?\n/)) {
    const s = line.trim();
    if (!s) continue;
    let r;
    try { r = JSON.parse(s); } catch { bad++; continue; }
    if (!r || typeof r !== "object" || Array.isArray(r)) { bad++; continue; }
    if (r.type === "meta") { metas.push(r); continue; }
    if (r.type === "dial") { rows.push(r); continue; }
    if (typeof r.exit !== "string" || typeof r.client !== "string" || typeof r.site !== "string" || !OUTCOMES.includes(r.outcome)) { bad++; continue; }
    rows.push(r);
  }
  return { rows: rows.filter((r) => r.type !== "dial"), dials: rows.filter((r) => r.type === "dial"), metas, bad };
}

function countLabels(outs) {
  const m = new Map();
  for (const o of outs) m.set(o, (m.get(o) || 0) + 1);
  return [...m.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    .map(([k, v]) => (ABBR[k] || k) + (v > 1 ? `:${v}` : ""));
}

// `ok/n other-labels +not-measured`. n is the measured count only. A cell with no measured
// outcome prints `-/0` followed by what happened instead.
export function fmtCell(outs) {
  if (!outs || !outs.length) return ".";
  const measured = outs.filter(isMeasured);
  const skipped = outs.filter((o) => !isMeasured(o));
  const ok = measured.filter((o) => o === "ok").length;
  const tail = countLabels(measured.filter((o) => o !== "ok")).join(",");
  const head = measured.length ? `${ok}/${measured.length}` : "-/0";
  return head + (tail ? " " + tail : "") + (skipped.length ? " +" + countLabels(skipped).join(",+") : "");
}

// ok share over measured cells, with the not-measured count beside it.
export function fmtShare(outs) {
  if (!outs || !outs.length) return ".";
  const measured = outs.filter(isMeasured);
  const skipped = outs.length - measured.length;
  const ok = measured.filter((o) => o === "ok").length;
  const share = measured.length ? `${ok}/${measured.length} (${Math.floor((100 * ok) / measured.length)}%)` : "-/0";
  return share + (skipped ? ` +${skipped} not measured` : "");
}

export function quantile(xs, q) {
  const a = xs.filter((x) => Number.isFinite(x)).sort((p, r) => p - r);
  if (!a.length) return null;
  return a[Math.min(a.length - 1, Math.max(0, Math.ceil(q * a.length) - 1))];
}

const r1 = (x) => (x == null ? "-" : (Math.round(x * 10) / 10).toFixed(1));
const esc = (s) => String(s ?? "").replace(/\|/g, "\\|").replace(/[\r\n]+/g, " ");

function uniq(xs) { return [...new Set(xs)]; }

// Platform only: older meta rows carried "<platform> <kernel release>"; the release is dropped.
function platformOf(host) {
  const os = host && typeof host.os === "string" ? host.os.trim().split(/\s+/)[0] : "";
  return /^[a-z0-9]{1,20}$/i.test(os) ? os : "?";
}
function hostClassText(host) {
  const h = host && typeof host === "object" ? host : {};
  const cpus = Number.isInteger(h.cpus) ? h.cpus : "?";
  const cpu = typeof h.cpu === "string" ? h.cpu.slice(0, 80) : "?";
  return `${cpus} x ${cpu}, ${platformOf(h)}`;
}

// "curl 8.5.0" only: the full `curl --version` line also names the build triple and every
// linked library.
function curlShort(s) {
  const m = /^curl \d+(?:\.\d+){0,3}/.exec(typeof s === "string" ? s : "");
  return m ? m[0] : "curl ?";
}

export function buildReport({ rows = [], dials = [], metas = [] } = {}, { exitOrder = null, clientOrder = null, title = "Egress benchmark report" } = {}) {
  const warnings = validateCohorts(rows, metas);
  const out = [];
  const p = (s = "") => out.push(s);
  const exits = exitOrder ? exitOrder.filter((e) => rows.some((r) => r.exit === e)) : uniq(rows.map((r) => r.exit));
  const clients = clientOrder ? clientOrder.filter((c) => rows.some((r) => r.client === c)) : uniq(rows.map((r) => r.client));
  const siteKeys = uniq(rows.map((r) => `${r.tier}\u0000${r.site}`)).map((k) => { const [tier, site] = k.split("\u0000"); return { tier, site }; })
    .sort((a, b) => (TIER_ORDER[a.tier] ?? 9) - (TIER_ORDER[b.tier] ?? 9) || a.site.localeCompare(b.site));
  const wallOf = new Map(rows.map((r) => [r.site, r.wall || ""]));
  const cell = new Map();
  for (const r of rows) {
    const k = `${r.exit}\u0000${r.client}\u0000${r.site}`;
    if (!cell.has(k)) cell.set(k, []);
    cell.get(k).push(r.outcome);
  }
  const get = (e, c, s) => cell.get(`${e}\u0000${c}\u0000${s}`) || [];
  const measuredRows = rows.filter((r) => isMeasured(r.outcome));
  const notMeasured = rows.length - measuredRows.length;

  p(`# ${esc(title)}`);
  for (const warning of warnings) p(`WARNING: ${warning}`);
  p();
  const passes = uniq(rows.map((r) => r.pass)).length;
  const ts = rows.map((r) => r.ts).filter(Boolean).sort();
  p(`${rows.length} cells: ${exits.length} exit(s) x ${clients.length} client(s) x ${siteKeys.length} site(s), ${passes} pass(es)` +
    (ts.length ? `, ${ts[0]} to ${ts[ts.length - 1]}` : "") + `. ${measuredRows.length} measured, ${notMeasured} not measured.`);
  p("Cells are ok/n over measured cells. chl = blocked-challenge, cap = captcha, 403 = blocked-403, 429 = blocked-429, to = timeout, err = error, unv = unverified; ':2' is a count.");
  p("Not measured, outside every denominator and timing: +prx = the local proxy refused or failed the request, +hrn = the harness could not run the cell, +can = cancelled by the operator.");
  if (notMeasured) p(`WARNING: ${notMeasured} of ${rows.length} cells were not measured. The shares below cover the measured cells only; this is not a complete run.`);
  p();

  if (rows.length) {
    p("## Summary: share of measured cells ok");
    p();
    p(`| client | ${exits.map(esc).join(" | ")} |`);
    p(`|---|${exits.map(() => "---|").join("")}`);
    for (const c of clients) {
      const vals = exits.map((e) => fmtShare(rows.filter((r) => r.exit === e && r.client === c).map((r) => r.outcome)));
      p(`| ${esc(c)} | ${vals.join(" | ")} |`);
    }
    p();

    const walls = uniq(siteKeys.map((s) => wallOf.get(s.site))).sort();
    p("## By wall (anti-bot vendor in front of the site)");
    p();
    p(`| wall | client | ${exits.map(esc).join(" | ")} |`);
    p(`|---|---|${exits.map(() => "---|").join("")}`);
    for (const w of walls) {
      for (const c of clients) {
        const vals = exits.map((e) => fmtCell(rows.filter((r) => r.exit === e && r.client === c && (r.wall || "") === w).map((r) => r.outcome)));
        if (vals.every((v) => v === ".")) continue;
        p(`| ${esc(w || "-")} | ${esc(c)} | ${vals.join(" | ")} |`);
      }
    }
    p();

    for (const c of clients) {
      p(`## Per site, client = ${esc(c)}`);
      p();
      p(`| tier | site | wall | ${exits.map(esc).join(" | ")} |`);
      p(`|---|---|---|${exits.map(() => "---|").join("")}`);
      for (const s of siteKeys) p(`| ${esc(s.tier)} | ${esc(s.site)} | ${esc(wallOf.get(s.site) || "-")} | ${exits.map((e) => fmtCell(get(e, c, s.site))).join(" | ")} |`);
      p();
    }

    p("## Cell time, seconds (p50 / p90, measured cells that returned a status)");
    p();
    p("Wall-clock time of the whole cell as the client recorded it. For browser clients this includes any fixed settle wait the runner adds after the page loads, so it is not a page-load time and is not comparable across clients.");
    p();
    p(`| client | ${exits.map(esc).join(" | ")} |`);
    p(`|---|${exits.map(() => "---|").join("")}`);
    for (const c of clients) {
      const vals = exits.map((e) => {
        const ts2 = measuredRows.filter((r) => r.exit === e && r.client === c && r.code != null).map((r) => Number(r.t));
        return ts2.length ? `${r1(quantile(ts2, 0.5))} / ${r1(quantile(ts2, 0.9))}` : ".";
      });
      p(`| ${esc(c)} | ${vals.join(" | ")} |`);
    }
    p();
  }

  if (dials.length) {
    p("## Dial time through the exit, seconds (tunnel open = CONNECT 200 or SOCKS ready, then TLS)");
    p();
    p("| exit | phase | n | failed | tunnel p50 | tunnel max | total p50 | total max |");
    p("|---|---|---|---|---|---|---|---|");
    const keys = uniq(dials.map((d) => `${d.exit}\u0000${d.phase}`));
    for (const k of keys) {
      const [e, ph] = k.split("\u0000");
      const ds = dials.filter((d) => d.exit === e && d.phase === ph);
      const good = ds.filter((d) => !d.error);
      const tun = good.map((d) => d.tTunnelMs / 1000);
      const tot = good.map((d) => d.tTotalMs / 1000);
      p(`| ${esc(e)} | ${esc(ph)} | ${ds.length} | ${ds.length - good.length} | ${r1(quantile(tun, 0.5))} | ${r1(quantile(tun, 1))} | ${r1(quantile(tot, 0.5))} | ${r1(quantile(tot, 1))} |`);
    }
    p();
  }

  if (metas.length) {
    p("## Provenance");
    p();
    for (const m of metas) {
      const x = m.exitInfo || {};
      const where = [x.org, x.country].filter(Boolean).join(", ") || "exit not looked up";
      const git = m.git && m.git.commit ? `${String(m.git.commit).slice(0, 12)}${m.git.dirty ? "+dirty" : ""}` : "unknown";
      const v = m.versions || {};
      p(`- \`${esc(m.run)}\`: exit \`${esc(m.exit)}\` (${esc(m.exitKind)}): sampled lookup ${esc(where)} (not stream attribution). ` +
        `clients ${esc((m.clients || []).join(","))}, passes ${esc(m.passes)}, started ${esc(m.startedAt)}. ` +
        `harness ${esc(git)}, node ${esc(v.node)}, chromium ${esc(v.chromium || "-")}, ${esc(curlShort(v.curl))}. ` +
        `host ${esc(hostClassText(m.host))}.`);
    }
    p();
  }
  return out.join("\n");
}

// Missing legacy metadata is explicitly unverified, never a certified comparison.
export function validateCohorts(rows, metas) {
  const warnings = [];
  const seen = new Set();
  const labels = new Map();
  const urls = new Map();
  const tiers = new Map();
  for (const r of rows) {
    const key = JSON.stringify([r.run, r.exit, r.client, r.tier, r.site, r.pass]);
    if (seen.has(key)) throw new Error("duplicate benchmark cell");
    seen.add(key);
    if (labels.has(r.exit) && labels.get(r.exit) !== r.run) throw new Error("mixed runs under one exit label");
    labels.set(r.exit, r.run);
    if (tiers.has(r.site) && tiers.get(r.site) !== r.tier) throw new Error("ambiguous site name across tiers");
    tiers.set(r.site, r.tier);
    const sk = JSON.stringify([r.tier, r.site]);
    if (urls.has(sk) && urls.get(sk) !== r.url) throw new Error("changed site URL in cohort");
    urls.set(sk, r.url);
  }
  for (const [label, run] of labels) {
    const ms = metas.filter(m => m.run === run && m.exit === label);
    if (ms.length > 1) throw new Error("duplicate run metadata");
    if (!run || ms.length !== 1) { warnings.push(`Unverified metadata for ${label}`); continue; }
    const m = ms[0];
    const expected = m.passes * m.clients?.length * m.sites?.count;
    const actual = rows.filter(r => r.run === run && r.exit === label);
    if (actual.some(r => !m.clients.includes(r.client) || !Number.isInteger(r.pass) || r.pass < 1 || r.pass > m.passes)) throw new Error("cell outside planned cohort");
    if (m.plannedSites?.length) {
      const planned = new Set(m.plannedSites.map(s => JSON.stringify([s.tier, s.site, s.urlHash])));
      if (actual.some(r => !planned.has(JSON.stringify([r.tier, r.site, r.url_sha256])))) throw new Error("cell site or URL outside planned cohort");
    } else warnings.push(`Unverified site manifest for ${label}`);
    if (expected !== actual.length) warnings.push(`Incomplete ${label}: observed ${actual.length}, expected ${expected}`);
  }
  if (new Set(metas.map(m => JSON.stringify([m.sites?.sha256, m.versions, m.args?.filter(x => !String(x).includes("redacted"))]))).size > 1) warnings.push("Cohort metadata/policies differ; descriptive results only, not a controlled comparison");
  return warnings;
}
