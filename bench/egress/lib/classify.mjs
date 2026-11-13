// Outcome classifier for one egress benchmark cell: (exit, client, site) -> one label.
//
// The point of the benchmark is to tell a real page apart from every way a site can refuse an
// automated client, and to keep the refusals apart from each other: a 429 is rate limiting (a
// property of the request volume), a challenge or CAPTCHA is reputation or fingerprint scoring
// (a property of the IP and the client), a 403 is a flat deny. Folding them together hides the
// thing the egress design is about (docs/exit-blocking-benchmark.md). It must also keep the
// harness's own failures apart from both: a refusal by the local proxy is not a site's answer.
//
// Labels, exactly one per cell:
//   ok                 2xx and the site's positive marker matched, with no challenge header and
//                      no interstitial title; or, for the api tier, a 401 carrying the marker
//   blocked-429        HTTP 429 or a rate-limit page ("unusual traffic", "too many requests")
//   blocked-challenge  a JS / managed interstitial the client may pass by running code
//   captcha            an interactive human test
//   blocked-403        403/451 or a deny page with no challenge offered
//   timeout            transport timeout
//   error              transport error after the tunnel opened, no status, or 5xx
//   unverified         a status with neither a positive nor a block marker (needs a human look)
//   proxy-refused      the local proxy refused or failed the request itself: no request reached
//                      the site through the exit (a non-200 CONNECT reply, the proxy unreachable,
//                      or the proxy's own answer to a browser's plain-http forward request)
//   harness-error      the harness could not run the cell (client missing, temp dir, a guard)
//   cancelled          operator interruption
//
// The last three are NOT_MEASURED: lib/report.mjs keeps them out of every denominator and
// prints them beside the cell instead, so the harness's own failures are never charged to the
// exit or the site.
//
// Precedence, and why:
//   1. Transport and proxy failures first: there is no site response to look at.
//   2. Hard block signals in status and headers (429, cf-mitigated: challenge, AWS WAF action,
//      x-px-blocked, the CloudFront empty 202) before the positive marker. An interstitial often
//      names the site it guards, so a weak marker ("hacker news", "github") matches it; the
//      header is the stronger evidence.
//   3. The positive marker, vetoed when the document title is an interstitial title ("Just a
//      moment", "Access denied", ...), for the same reason when the header is missing.
//   4. Body block markers last. A real page can embed a captcha widget or mention "captcha" in
//      its text, so a page whose marker matched is ok even when a body block regex also matches.
//
// Pure: no I/O. Every input may be hostile (it is whatever a remote server sent), so the
// function never throws and does bounded work: block regexes run on a capped prefix, and the
// positive marker (supplied by the operator's sites file, not the server) runs on a larger cap,
// because on a big rendered page the element it looks for can sit far into the document.

export const OUTCOMES = Object.freeze([
  "ok", "blocked-429", "blocked-challenge", "captcha", "blocked-403", "timeout", "error", "unverified",
  "proxy-refused", "harness-error", "cancelled",
]);

// Outcomes that are failures of the measuring setup, not answers from the exit's path to a site.
export const NOT_MEASURED = Object.freeze(["proxy-refused", "harness-error", "cancelled"]);

// Short forms for report cells.
export const ABBR = Object.freeze({
  ok: "ok", "blocked-challenge": "chl", captcha: "cap", "blocked-403": "403", "blocked-429": "429",
  timeout: "to", error: "err", unverified: "unv", "proxy-refused": "prx", "harness-error": "hrn", cancelled: "can",
});

// Clients that send a plain http:// request through an HTTP proxy as a forward request
// (absolute-form GET) instead of a CONNECT tunnel. Chromium does; curl is run with
// --proxytunnel and the Node client always tunnels, so for those two the answer comes from the
// far end of the tunnel.
export const FORWARD_HTTP_CLIENTS = Object.freeze(["headless", "headed"]);

// Block markers are matched on at most this many characters of the lowercased body; the cap
// bounds regex work on a hostile 50 MB body.
export const BLOCK_SCAN_CHARS = 400_000;
// The positive marker scan is capped too, far above any real page, for the same reason.
export const MARKER_SCAN_CHARS = 8_000_000;

// [name, regex]. Order inside a table is the order of evidence; the first hit names the marker.
export const CAPTCHA = Object.freeze([
  ["recaptcha", /class="g-recaptcha|google\.com\/recaptcha|\/sorry\/index/],
  ["hcaptcha", /class="h-captcha|hcaptcha\.com\/1\/api/],
  ["perimeterx", /px-captcha|press (?:&amp;|&) hold|access to this page has been denied/],
  ["datadome", /captcha-delivery\.com/],
  ["ddg-ducks", /bots use duckduckgo too|select all squares containing a duck/],
  ["yandex-smartcaptcha", /are you not a robot|smart-captcha|showcaptcha/],
  ["title-captcha", /<title>\s*captcha/],
  ["robot-check", /are you a robot|suspect you.re a robot|verify you are human by completing/],
]);
export const CHALLENGE = Object.freeze([
  ["cf-just-a-moment", /<title>just a moment/],
  ["cf-chl", /cf-chl-|\/cdn-cgi\/challenge-platform\/h\/[gb]\/orchestrate/],
  ["cf-turnstile-interstitial", /verifying you are human|checking your browser|checking if the site connection is secure/],
  ["security-check-title", /<title>security check/],
  ["google-enablejs", /\/httpservice\/retry\/enablejs/],
  ["enable-js-cookies", /enable javascript and cookies to continue|please enable js and disable any ad blocker/],
  ["pow-challenge", /"challenge":\{"issuedat"|"rules":\{"algorithm"/],
  ["akamai-sec-cpt", /sec-if-cpt|_sec\/cp_challenge|behavioral-content/],
  ["amazon-continue-shopping", /click the button below to continue shopping/],
  ["reddit-js-pow", /nameditem\("solution"\)/],
  ["aws-waf-js", /awswafcookiedomainlist|token\.awswaf\.com/],
]);
export const DENY = Object.freeze([
  ["access-denied-title", /<title>access denied/],
  ["cf-you-have-been-blocked", /you have been blocked/],
  ["reddit-network-security", /blocked by network security/],
  ["forbidden-title", /<title>(?:403 )?forbidden/],
  ["attention-required-title", /<title>attention required/],
]);
export const RATE_LIMIT = Object.freeze([
  ["unusual-traffic", /unusual traffic from your computer/],
  ["too-many-requests", /too many requests/],
]);

// A document title that only an interstitial or a deny page carries. It vetoes the positive
// marker (step 3 above). Every title here is also matched by an entry in CAPTCHA, CHALLENGE or
// DENY, so a vetoed page always gets a block label rather than `unverified`.
// Anchored and short on purpose: a real page titled "Forbidden Planet" or "Captcha solving,
// explained" is not vetoed.
export const INTERSTITIAL_TITLE = /^\s*(?:just a moment(?:\.{3}|\u2026)?|security check|captcha|access denied|(?:403 )?forbidden|attention required!(?: \| cloudflare)?)\s*$/;

// Size guard: a 2xx that matched the positive marker but is far too small to be the real page,
// e.g. a small interstitial that carries the site's own title. Keyed by the site's `min=<bytes>`
// field in the sites file (lib/sites.mjs).
export function sizeGuardFails(site, bytes) {
  const min = Number(site && site.minBytes);
  return Number.isFinite(min) && min > 0 && bytes < min;
}

function str(v) {
  if (typeof v === "string") return v;
  if (v == null || typeof v === "object" || typeof v === "function") return "";
  try { return String(v); } catch { return ""; }
}

// Lowercased header map from a plain object, a Map, a Headers instance, or garbage.
export function lowerHeaders(h) {
  const out = {};
  if (!h || typeof h !== "object") return out;
  let entries = [];
  try {
    entries = typeof h.entries === "function" && !(h.constructor === Object) ? [...h.entries()] : Object.entries(h);
  } catch { return out; }
  for (const [k, v] of entries) {
    if (typeof k !== "string") continue;
    out[k.toLowerCase()] = Array.isArray(v) ? v.map(str).join(", ") : str(v);
  }
  return out;
}

function firstHit(table, hay) {
  for (const [name, re] of table) if (re.test(hay)) return name;
  return null;
}

// Best-effort anti-bot vendor from response headers (and two body tells). Evidence only, it
// never changes the label: a Cloudflare header on an ok page is normal.
export function vendorOf(headers, body = "") {
  const h = lowerHeaders(headers);
  const b = str(body).slice(0, BLOCK_SCAN_CHARS).toLowerCase();
  const server = (h.server || "").toLowerCase();
  const keys = Object.keys(h);
  const v = [];
  if ("cf-ray" in h || server.includes("cloudflare") || "cf-mitigated" in h) v.push("cloudflare");
  if (server.includes("akamai") || keys.some((k) => k.startsWith("akamai")) || "x-akamai-transformed" in h) v.push("akamai");
  if (keys.some((k) => k.startsWith("x-datadome")) || server.includes("datadome") || b.includes("captcha-delivery")) v.push("datadome");
  if (keys.some((k) => k.startsWith("x-px")) || b.includes("px-captcha") || b.includes("perimeterx")) v.push("perimeterx");
  if ("x-amz-cf-id" in h || server === "cloudfront") v.push("cloudfront");
  if ("x-amzn-waf-action" in h) v.push("aws-waf");
  if (server.includes("snooserv")) v.push("reddit");
  if ((h["x-served-by"] || "").includes("cache-")) v.push("fastly");
  return v;
}

export function titleOf(body) {
  const m = /<title[^>]*>([^<]{0,200})/i.exec(str(body).slice(0, BLOCK_SCAN_CHARS));
  return m ? m[1].replace(/\s+/g, " ").trim().slice(0, 120) : "";
}

// Compile a sites-file marker. Returns null for an absent or invalid one (the sites parser
// rejects invalid markers up front; this is the belt to that brace).
export function compileMarker(src) {
  if (src instanceof RegExp) return src;
  if (typeof src !== "string" || !src) return null;
  try { return new RegExp(src, "i"); } catch { return null; }
}

// Transport strings a client reports when no site answered. This is the contract the runners
// must follow (they are not part of this module):
//   "timeout"                         transport timeout
//   "error:cancelled"                 operator interruption
//   "error:client-unavailable[...]"   the client could not run (no browser, no display, ...)
//   "error:tmpdir", "error:non-loopback"   harness setup or a local-only guard
//   "error:proxy-*", "error:connect-refused-<status>", "error:bad-proxy-reply"
//                                     the HTTP proxy was unreachable, refused the CONNECT, or
//                                     answered it with something that is not HTTP
//   "error:curl-proxy-*"              curl could not reach or handshake with the proxy
//   "error:curl-<reason>-connect<status>"  curl's CONNECT got <status>; non-200 is the proxy's
//   "...net::ERR_TUNNEL_CONNECTION_FAILED" / "ERR_PROXY_CONNECTION_FAILED"   Chromium's names
//                                     for the same two proxy failures
// Anything else that starts "error:" is a transport error after the tunnel opened, or one the
// harness cannot attribute, and stays `error`.
const HARNESS_TRANSPORT = /^error:(?:client-unavailable|tmpdir$|non-loopback$)/;
const PROXY_TRANSPORT = /^error:(?:proxy-|connect-refused-\d{3}$|bad-proxy-reply$|curl-proxy-)|net::err_(?:tunnel_connection_failed|proxy_connection_failed)\b/;

export function transportOutcome(transport) {
  const t = str(transport);
  if (t === "error:cancelled") return { outcome: "cancelled", marker: "error:cancelled" };
  if (t === "timeout") return { outcome: "timeout", marker: null };
  const marker = t.slice(0, 160);
  if (HARNESS_TRANSPORT.test(t)) return { outcome: "harness-error", marker };
  if (PROXY_TRANSPORT.test(t.toLowerCase())) return { outcome: "proxy-refused", marker };
  const curl = /^error:curl-[a-z0-9]+(?:-[a-z0-9]+)*-connect(\d{3})$/.exec(t);
  if (curl && curl[1] !== "200") return { outcome: "proxy-refused", marker };
  return { outcome: "error", marker };
}

function schemeOf(url) {
  try { return new URL(str(url)).protocol; } catch { return null; }
}

// classify({site, code, headers, body, title, finalUrl, transport, connectCode, exitType, client})
//   -> {outcome, marker}
//   site:        {tier, okMarker (string|RegExp), minBytes?, url?}
//   code:        HTTP status of the main document, or null
//   transport:   null on a completed response, "timeout", or an error string (see above)
//   connectCode: the HTTP proxy's reply to CONNECT, when the client saw one
//   exitType:    "direct" | "http" | "socks5": how the client reached the exit, used for the
//                forward rule
//   client:      the client name, used for the forward rule
export function classify(input) {
  const r = classifyResponse(input);
  const { site, finalUrl = "", exitType = null, client = null } = input && typeof input === "object" ? input : {};
  // A browser's plain-http request through an HTTP proxy is a forward request (absolute-form
  // GET), not a tunnel, so the status line may be the proxy's own. A CONNECT-only proxy refuses
  // it with a 403 that carries no site evidence at all. On that path a status with no evidence
  // behind it (a bare 403/451, a 5xx, no status, or a generic "Forbidden" / "Access denied"
  // page that any proxy can serve) is charged to the proxy, not the site. A page whose marker
  // matched, a 429, or a vendor's own challenge, captcha or block page or header is still the
  // site's.
  if ((r.outcome === "blocked-403" || r.outcome === "error") && FORWARD_UNATTRIBUTABLE.test(String(r.marker)) &&
      exitType === "http" && FORWARD_HTTP_CLIENTS.includes(client)) {
    const scheme = schemeOf(finalUrl) || schemeOf(site && site.url);
    if (scheme === "http:") return { outcome: "proxy-refused", marker: `proxy-forward-${r.marker}` };
  }
  return r;
}

// Markers that carry no evidence of who answered: a bare status, or a generic deny title.
const FORWARD_UNATTRIBUTABLE = /^(?:http-\d{3}|no-status|forbidden-title|access-denied-title)$/;

function classifyResponse(input) {
  const { site: rawSite, code: rawCode = null, headers = {}, body: rawBody = "", title: rawTitle = "",
    finalUrl = "", transport = null, connectCode = null } = input && typeof input === "object" ? input : {};
  const site = rawSite && typeof rawSite === "object" ? rawSite : {};
  if (transport) return transportOutcome(transport);
  if (Number.isInteger(connectCode) && connectCode !== 200) return { outcome: "proxy-refused", marker: `connect-${connectCode}` };

  const code = Number.isInteger(rawCode) ? rawCode : (/^\d{3}$/.test(str(rawCode)) ? Number(rawCode) : null);
  const body = str(rawBody);
  const title = str(rawTitle) || titleOf(body);
  const h = lowerHeaders(headers);
  const low = body.slice(0, BLOCK_SCAN_CHARS).toLowerCase();
  const hay = `${low} ${str(finalUrl).slice(0, 2000).toLowerCase()} <title>${title.toLowerCase()}`;
  const is2xx = code !== null && code >= 200 && code < 300;
  const ok = compileMarker(site.okMarker);
  const markerHit = () => ok !== null && ok.test(`${body.slice(0, MARKER_SCAN_CHARS)} <title>${title}`);

  // 407 is always a proxy's answer (Proxy Authentication Required), never a site's.
  if (code === 407) return { outcome: "proxy-refused", marker: "http-407" };

  // Step 2: hard signals in status and headers.
  if (code === 429) return { outcome: "blocked-429", marker: "http-429" };
  if ((h["cf-mitigated"] || "").toLowerCase().includes("challenge")) return { outcome: "blocked-challenge", marker: "hdr-cf-mitigated" };
  const waf = (h["x-amzn-waf-action"] || "").toLowerCase();
  if (waf === "captcha") return { outcome: "captcha", marker: "hdr-aws-waf-captcha" };
  if (waf === "challenge") return { outcome: "blocked-challenge", marker: "hdr-aws-waf-challenge" };
  if (h["x-px-blocked"]) return { outcome: "captcha", marker: "hdr-x-px-blocked" };
  // CloudFront answers a bot-scored client with an empty 202 (AWS WAF silent challenge).
  if (code === 202 && body.length < 5000 && ("x-amz-cf-id" in h || (h.server || "").toLowerCase() === "cloudfront")) {
    return { outcome: "blocked-challenge", marker: "cloudfront-202-stub" };
  }

  // Step 3: positive evidence.
  // api tier: an unauthenticated 401 with the API's own error proves the path works. A 403 does
  // not: an API also answers 403 to a region or policy block, in the same JSON error envelope.
  if (site.tier === "api" && code === 401 && ok && ok.test(low)) {
    return { outcome: "ok", marker: "api-401" };
  }
  if (is2xx && !INTERSTITIAL_TITLE.test(title.toLowerCase()) && markerHit()) {
    if (sizeGuardFails(site, body.length)) return { outcome: "blocked-challenge", marker: `small-page-${body.length}b` };
    return { outcome: "ok", marker: "ok-marker" };
  }

  // Step 4: body evidence. Rate-limit text is body evidence like the rest: a real page can
  // contain the words "too many requests".
  const rl = firstHit(RATE_LIMIT, low);
  if (rl) return { outcome: "blocked-429", marker: rl };
  const cap = firstHit(CAPTCHA, hay);
  if (cap) return { outcome: "captcha", marker: cap };
  const chl = firstHit(CHALLENGE, hay);
  if (chl) return { outcome: "blocked-challenge", marker: chl };
  // A named deny page is checked before the bare status, so the marker records the evidence.
  const deny = firstHit(DENY, hay);
  if (deny) return { outcome: "blocked-403", marker: deny };
  if (code === 403 || code === 451) return { outcome: "blocked-403", marker: `http-${code}` };

  if (code === null) return { outcome: "error", marker: "no-status" };
  if (code >= 500 && code < 600) return { outcome: "error", marker: `http-${code}` };
  if (is2xx && body.length < 200) return { outcome: "unverified", marker: `empty-${code}` };
  return { outcome: "unverified", marker: `http-${code}-no-marker` };
}
