/* global document, fetch, window */

// Canopy dashboard client. It only reads /api/canopy and /api/history from the server that served
// it. Every value is written with textContent: the Elder is semi-trusted and an incident summary is
// operator prose, so nothing from the API is ever parsed as markup.

const POLL_MS = 15_000;
const $ = (selector) => document.querySelector(selector);

function el(tag, attrs = {}, children = []) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs)) {
    if (value === null || value === undefined || value === false) continue;
    if (key === "class") node.className = value;
    else if (key === "text") node.textContent = value;
    else node.setAttribute(key, value === true ? "" : String(value));
  }
  for (const child of [].concat(children)) if (child) node.append(child);
  return node;
}

export function ageText(sec) {
  if (!Number.isFinite(sec)) return "n/a";
  const s = Math.max(0, Math.round(sec));
  if (s < 5) return "now";
  if (s < 60) return `${s}s`;
  if (s < 3600) return `${Math.floor(s / 60)}m ${s % 60}s`;
  if (s < 172800) return `${Math.floor(s / 3600)}h`;
  return `${Math.floor(s / 86400)}d`;
}

export function msText(ms) {
  if (!Number.isFinite(ms)) return "n/a";
  return `${(ms / 1000).toFixed(1)} s`;
}

// When an Elder last verified, from the in-memory trend. null = not once since the server started.
export function lastVerified(samples, index) {
  for (let i = samples.length - 1; i >= 0; i--) if (samples[i].elders?.[index]?.verified) return samples[i].at;
  return null;
}

let lastHistory = { samples: [] };

// One Elder's verdict. Unreachable or unverified is bad; reachable but stale, or running a commit
// other than the record pin, is a warning.
export function elderVerdict(e) {
  if (!e.reachable) return { tone: "bad", text: "unreachable" };
  if (!e.directory.verified) return { tone: "bad", text: "unverified" };
  if (!e.directory.fresh) return { tone: "warn", text: e.directory.reason || "stale" };
  if (e.commitMatchesPin === false) return { tone: "warn", text: "verified, off pin" };
  return { tone: "ok", text: "verified" };
}

function row(label, value, tone = null) {
  return el("div", {}, [el("dt", { text: label }), el("dd", { class: tone ? `is-${tone}` : null, text: value })]);
}

function renderElders(obs) {
  const host = $("[data-elders]");
  host.replaceChildren(...obs.elders.map((e, index) => {
    const v = elderVerdict(e);
    const d = e.directory;
    // Both states draw the same rows in the same order, so a down Elder reads as the same card
    // with its values missing rather than as a different, shorter thing.
    const samples = lastHistory.samples || [];
    const seenCount = samples.filter((s) => s.elders?.[index]?.verified).length;
    const seen = lastVerified(samples, index);
    const rows = [];
    if (!e.reachable) {
      rows.push(row("Status", e.error || "no answer", "bad"));
      rows.push(row("Directory", "not fetched", "bad"));
      rows.push(row("Issued", "n/a"));
      rows.push(row("Health / directory", "n/a"));
      rows.push(row("Commit", "n/a"));
    } else {
      rows.push(row("Status", e.health?.ok ? `ok, ${e.health.count ?? "?"} live` : "health not ok", e.health?.ok ? null : "bad"));
      rows.push(row("Directory", d.verified ? `${d.size} nodes, signature ok` : (d.reason || "unverified"), d.verified ? null : "bad"));
      rows.push(row("Issued", Number.isInteger(d.ageSec) ? (ageText(Math.max(0, d.ageSec)) === "now" ? "just now" : `${ageText(Math.max(0, d.ageSec))} ago`) : "n/a", d.fresh ? null : "warn"));
      rows.push(row("Health / directory", `${msText(e.latencyMs)} / ${msText(d.latencyMs)}`));
      rows.push(row("Commit", e.commit ? `${e.commit.slice(0, 12)}${e.commitMatchesPin === false ? ", pin " + (obs.pinnedCommit || "").slice(0, 8) : ""}` : "not reported", e.commitMatchesPin === false ? "warn" : null));
    }
    rows.push(row("Verified", samples.length ? `${seenCount} of ${samples.length} observations` : "n/a", samples.length && seenCount < samples.length ? (seenCount ? "warn" : "bad") : null));
    rows.push(row("Last verified", seen ? (seen === samples.at(-1)?.at ? "this observation" : seen.replace("T", " ").replace(/:\d\d\.\d+Z$/, " UTC")) : "not since dashboard start", seen ? null : "bad"));
    const inc = e.incidents;
    rows.push(row("Incidents", !inc ? "n/a" : inc.verified ? (inc.active ? `${inc.active} active` : "none") : "feed unverified", inc && !inc.verified ? "bad" : inc?.active ? "warn" : null));
    const rel = e.relay;
    const w24 = rel?.verified ? rel.windows.find((x) => x.hours === 24) : null;
    rows.push(row("Relay telemetry", !rel ? "n/a" : !rel.verified ? "aggregate unverified" : w24?.status === "available" ? "published" : `suppressed, ${w24?.reportingNodes ?? 0} reporting`, rel && !rel.verified ? "bad" : null));
    return el("article", { class: `elder-card is-${v.tone}`, "aria-label": `Elder ${e.label}` }, [
      el("div", { class: "elder-top" }, [
        el("span", { class: "elder-name" }, [el("span", { class: `dot is-${v.tone}`, "aria-hidden": "true" }), `${e.label}…`, el("small", { text: index === 0 ? "primary" : `elder ${index + 1}` })]),
        el("span", { class: "elder-verdict", text: v.text }),
      ]),
      el("dl", {}, rows),
    ]);
  }));
}

function setSum(key, value, tone = null) {
  const dd = $(`[data-sum="${key}"]`);
  dd.className = tone ? `is-${tone}` : "";
  dd.replaceChildren(...[].concat(value));
}

function renderSummary(obs) {
  const s = obs.summary;
  const c = obs.canopy;
  const elderTone = s.eldersVerified === s.elders ? null : s.eldersVerified === 0 ? "bad" : "warn";
  setSum("elders", [`${s.eldersVerified}`, el("small", { text: ` / ${s.elders}` })], elderTone);
  setSum("size", String(c.size), c.size === 0 ? "bad" : null);
  setSum("up", String(c.up));
  const degraded = c.down + c.mixed + c.draining;
  setSum("degraded", String(degraded), degraded ? "warn" : null);
  setSum("operators", String(c.operators));
  // 300 s is the freshness window the observer enforces (DIR_MAX_AGE_SEC).
  setSum("age", s.directoryAgeSec === null ? "n/a" : ageText(Math.max(0, s.directoryAgeSec)), s.directoryAgeSec === null ? "bad" : s.directoryAgeSec > 300 ? "warn" : null);

  const dot = $("[data-state-dot]");
  const state = $("[data-state]");
  if (s.eldersVerified === 0) { dot.className = "state-dot is-bad"; state.textContent = "No Elder verified"; }
  else if (s.eldersVerified < s.elders) { dot.className = "state-dot is-warn"; state.textContent = `Degraded: ${s.elders - s.eldersVerified} of ${s.elders} Elders not verified`; }
  else { dot.className = "state-dot is-ok"; state.textContent = "All Elders verified"; }
  $("[data-observed]").textContent = `observed ${obs.observedAt.replace("T", " ").replace(/\.\d+Z$/, " UTC")}`;
  if (obs.network) $("[data-network]").textContent = `network/${obs.network}`;
}

function renderNodes(obs) {
  const body = $("[data-nodes]");
  const dialOn = obs.summary.nodeDialProbe;
  $("[data-dial-col]").hidden = !dialOn;
  if (!obs.nodes.length) {
    body.replaceChildren(el("tr", {}, el("td", { class: "empty", colspan: dialOn ? 8 : 7, text: "No verified directory, so no nodes are shown." })));
    return;
  }
  const elderCount = obs.elders.length;
  body.replaceChildren(...obs.nodes.map((n) => {
    const healthTone = n.draining ? "warn" : n.health === "up" ? "ok" : n.health === "down" ? "bad" : "warn";
    const healthText = n.draining ? "draining" : n.health;
    const listed = el("span", { class: "listed", "aria-hidden": "true" },
      Array.from({ length: elderCount }, (_, i) => el("i", { class: n.listedBy.includes(i) ? "on" : null })));
    const cells = [
      el("td", { class: "onion", text: `${n.onionShort}…` }),
      el("td", {}, [listed, el("span", { class: "quiet", text: ` ${n.listedBy.length}/${elderCount}` })]),
      el("td", {}, el("span", { class: `health is-${healthTone}` }, [el("span", { class: `dot is-${healthTone}`, "aria-hidden": "true" }), healthText])),
      el("td", { text: String(n.weight) }),
      el("td", { text: n.proto }),
      el("td", { text: n.admits.length ? n.admits.join(", ") : "none" }),
      el("td", {}, el("span", { class: n.staked === true ? "is-ok" : "quiet", text: n.staked === true ? "staked" : n.staked === false ? "unstaked" : "n/a" })),
    ];
    if (dialOn) cells.push(el("td", {}, el("span", { class: n.dialFailed ? "is-bad" : null, text: n.dialFailed ? "failed" : msText(n.dialMs) })));
    return el("tr", {}, cells);
  }));
}

function bars(host, items, total, folded = 0) {
  const list = [...items];
  if (folded) list.push({ label: "other", count: folded, folded: true });
  if (!list.length) { host.replaceChildren(el("li", {}, el("span", { class: "empty", text: "Nothing declared." }))); return; }
  host.replaceChildren(...list.map((b) => {
    const pct = total ? Math.round((b.count / total) * 100) : 0;
    const fill = el("i");
    fill.style.width = `${pct}%`;
    return el("li", { class: b.folded ? "is-folded" : null }, [el("span", { text: b.label }), el("b", { "aria-hidden": "true" }, fill), el("em", { text: String(b.count) })]);
  }));
}

function renderMix(obs) {
  const c = obs.canopy;
  $("[data-k]").textContent = String(c.regions.k);
  bars($('[data-mix="regions"]'), c.regions.shown, c.size, c.regions.folded);
  bars($('[data-mix="admits"]'), c.admits, c.size);
  bars($('[data-mix="coverage"]'), c.coverage || [], c.size);
}

// The y axis runs from 0 to a quarter above the peak, so a steady canopy draws as a line inside
// the frame rather than along its top edge.
export function sparkPath(values, width = 600, height = 72, pad = 4) {
  if (!values.length) return { line: "", area: "", max: 0 };
  const max = Math.max(1, Math.ceil(Math.max(...values) * 1.25));
  const n = values.length;
  const x = (i) => (n === 1 ? width / 2 : pad + (i * (width - 2 * pad)) / (n - 1));
  const y = (v) => height - pad - (v / max) * (height - 2 * pad);
  const pts = values.map((v, i) => `${x(i).toFixed(1)},${y(v).toFixed(1)}`);
  const line = `M${pts.join(" L")}`;
  return { line, area: `${line} L${x(n - 1).toFixed(1)},${height - pad} L${x(0).toFixed(1)},${height - pad} Z`, max };
}

function renderTrend(history, obs) {
  const samples = history.samples || [];
  const spark = $("[data-spark]");
  const sizes = samples.map((s) => s.size);
  const { line, area } = sparkPath(sizes);
  spark.querySelector(".spark-line").setAttribute("d", line);
  spark.querySelector(".spark-area").setAttribute("d", area);
  $("[data-trend-now]").textContent = samples.length ? String(samples.at(-1).size) : "n/a";
  spark.classList.toggle("is-collecting", samples.length < 2);
  $("[data-trend-range]").textContent = sizes.length ? `low ${Math.min(...sizes)}, high ${Math.max(...sizes)}` : "";
  $("[data-trend-from]").textContent = samples.length ? samples[0].at.slice(11, 16) + " UTC" : "";
  $("[data-trend-to]").textContent = samples.length ? samples.at(-1).at.slice(11, 16) + " UTC" : "";
  const span = samples.length > 1 ? (Date.parse(samples.at(-1).at) - Date.parse(samples[0].at)) / 1000 : 0;
  $("[data-trend-meta]").textContent = `${samples.length} observation${samples.length === 1 ? "" : "s"} over ${ageText(span)}. Kept in memory only: counts and booleans, no node identities.`;
  const recent = samples.slice(-90);
  const strips = (obs?.elders || []).map((e, i) => el("div", { class: "strip-row" }, [
    el("span", { text: `${e.label}… verified` }),
    el("div", { class: "strip", role: "img", "aria-label": `${e.label} verified in ${recent.filter((s) => s.elders[i]?.verified).length} of the last ${recent.length} observations` },
      recent.map((s) => el("i", { class: s.elders[i]?.verified ? "is-ok" : s.elders[i]?.reachable ? "is-warn" : "is-bad" }))),
  ]));
  $("[data-strips]").replaceChildren(...strips);
}

async function poll() {
  try {
    const [canopyRes, historyRes] = await Promise.all([
      fetch("/api/canopy", { cache: "no-store" }),
      fetch("/api/history", { cache: "no-store" }),
    ]);
    if (canopyRes.status === 503) { $("[data-state]").textContent = "Waiting for the first observation over Tor"; return; }
    if (!canopyRes.ok) throw new Error(`HTTP ${canopyRes.status}`);
    const obs = await canopyRes.json();
    if (historyRes.ok) lastHistory = await historyRes.json();
    renderSummary(obs);
    renderElders(obs);
    renderNodes(obs);
    renderMix(obs);
    renderTrend(lastHistory, obs);
  } catch (error) {
    $("[data-state-dot]").className = "state-dot is-bad";
    $("[data-state]").textContent = `Dashboard server unreachable (${error.message})`;
  }
}

if (typeof window !== "undefined" && typeof document !== "undefined" && document.querySelector("[data-elders]")) {
  poll();
  window.setInterval(poll, POLL_MS);
}
