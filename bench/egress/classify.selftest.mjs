// Selftest for the egress benchmark classifier (bench/egress/lib/classify.mjs).
//
//   node bench/egress/classify.selftest.mjs
//
// The classifier reads untrusted bytes (whatever a site or proxy sent), and its label IS the
// measurement, so a wrong label is a wrong result. Each assertion is meant to fail on a specific
// defect: a flipped precedence, a lost size guard, a marker scan window that is too short, a
// regex that throws, a header lookup that is case sensitive, a block counted as ok, or a failure
// of the harness's own proxy charged to the site. No network, no files.

import assert from "node:assert/strict";
import { classify, transportOutcome, vendorOf, titleOf, lowerHeaders, compileMarker, sizeGuardFails, OUTCOMES, NOT_MEASURED, ABBR,
  BLOCK_SCAN_CHARS, INTERSTITIAL_TITLE } from "./lib/classify.mjs";

let n = 0;
const t = (name, fn) => { fn(); n++; console.log(`  ok   ${name}`); };
const web = (okMarker, extra = {}) => ({ tier: "web", okMarker, ...extra });
const c = (o) => classify(o);

t("every outcome has a distinct abbreviation and OUTCOMES is closed", () => {
  for (const o of OUTCOMES) assert.ok(ABBR[o], o);
  assert.equal(Object.keys(ABBR).length, OUTCOMES.length);
  assert.equal(new Set(Object.values(ABBR)).size, OUTCOMES.length);
  for (const o of NOT_MEASURED) assert.ok(OUTCOMES.includes(o), o);
  assert.deepEqual([...NOT_MEASURED].sort(), ["cancelled", "harness-error", "proxy-refused"]);
});

t("plain ok needs a positive marker", () => {
  assert.deepEqual(c({ site: web("id=\"main\""), code: 200, body: '<div id="main">' }), { outcome: "ok", marker: "ok-marker" });
  assert.equal(c({ site: web(""), code: 200, body: "<html>" + "a".repeat(500) }).outcome, "unverified");
  assert.equal(c({ site: web("id=\"main\""), code: 200, body: "<html>" + "a".repeat(500) }).marker, "http-200-no-marker");
});

t("marker matches the title even when the body does not carry it", () => {
  assert.equal(c({ site: web("<title>hacker news"), code: 200, body: "x".repeat(300), title: "Hacker News" }).outcome, "ok");
});

t("a captcha widget inside a real page is ok when the marker matched", () => {
  const body = '<title>Stories</title><div class="g-recaptcha"></div> human stories ' + "z".repeat(1000);
  assert.equal(c({ site: web("human stories"), code: 200, body }).outcome, "ok");
  // and without the marker the same widget is a captcha, so the precedence really matters
  assert.equal(c({ site: web("never-there"), code: 200, body }).outcome, "captcha");
  // the same holds for rate-limit wording inside a real page
  assert.equal(c({ site: web("human stories"), code: 200, body: body + " too many requests" }).outcome, "ok");
});

t("marker past the 400 KB block-scan window still counts", () => {
  const body = "<title>weather today - Search</title>" + "q".repeat(BLOCK_SCAN_CHARS + 50_000) + '<ol id="b_results">';
  assert.equal(c({ site: web('id="b_results"'), code: 200, body }).outcome, "ok");
});

t("block markers past the scan window are ignored (bounded work on hostile bodies)", () => {
  const body = "<title>x</title>" + "q".repeat(BLOCK_SCAN_CHARS + 10) + "<title>just a moment";
  assert.equal(c({ site: web("never"), code: 200, body }).outcome, "unverified");
});

t("size guard: a small interstitial wearing the real title is a challenge, the real page is ok", () => {
  const site = web('id="nav-logo', { minBytes: 10000 });
  const stub = '<title>Shop</title><div id="nav-logo"></div>Click the button below to continue shopping';
  assert.equal(c({ site, code: 200, body: stub }).outcome, "blocked-challenge");
  assert.match(c({ site, code: 200, body: stub }).marker, /^small-page-/);
  assert.equal(c({ site, code: 200, body: stub + "w".repeat(10000) }).outcome, "ok");
  // boundary: exactly minBytes is not "under"
  const exact = '<div id="nav-logo">'.padEnd(10000, "w");
  assert.equal(exact.length, 10000);
  assert.equal(c({ site, code: 200, body: exact }).outcome, "ok");
  assert.equal(c({ site, code: 200, body: exact.slice(0, 9999) }).outcome, "blocked-challenge");
});

t("size guard ignores junk minBytes", () => {
  for (const v of [null, undefined, "abc", -5, 0, NaN]) assert.equal(sizeGuardFails({ minBytes: v }, 1), false, String(v));
  assert.equal(sizeGuardFails(null, 1), false);
});

t("a JS proof-of-work page is a challenge even with a 200", () => {
  const body = '<title>Forum</title><script>document.forms.namedItem("solution")</script>';
  assert.deepEqual(c({ site: web("heart of the internet", { minBytes: 60000 }), code: 200, body }), { outcome: "blocked-challenge", marker: "reddit-js-pow" });
});

t("CloudFront 202 empty stub is a challenge; a 202 with a big body is not", () => {
  assert.equal(c({ site: web("x"), code: 202, headers: { Server: "CloudFront" }, body: "" }).outcome, "blocked-challenge");
  assert.equal(c({ site: web("x"), code: 202, headers: { "X-Amz-Cf-Id": "a" }, body: "" }).marker, "cloudfront-202-stub");
  assert.notEqual(c({ site: web("x"), code: 202, headers: { server: "cloudfront" }, body: "b".repeat(6000) }).marker, "cloudfront-202-stub");
});

t("429 beats every reputation marker (rate limit is kept apart)", () => {
  assert.equal(c({ site: web("x"), code: 429, body: "<title>just a moment" }).outcome, "blocked-429");
  assert.equal(c({ site: web("x"), code: 200, body: "Our systems have detected unusual traffic from your computer network" }).outcome, "blocked-429");
  // a 429 page that names the site is still a 429
  assert.equal(c({ site: web("hacker news"), code: 429, body: "<title>Hacker News</title> slow down" }).outcome, "blocked-429");
});

t("header signals are case-insensitive and typed correctly", () => {
  assert.deepEqual(c({ site: web("x"), code: 403, headers: { "CF-Mitigated": "challenge" } }), { outcome: "blocked-challenge", marker: "hdr-cf-mitigated" });
  assert.equal(c({ site: web("x"), code: 405, headers: { "X-Amzn-Waf-Action": "CAPTCHA" } }).outcome, "captcha");
  assert.equal(c({ site: web("x"), code: 202, headers: { "x-amzn-waf-action": "challenge" } }).outcome, "blocked-challenge");
  assert.equal(c({ site: web("x"), code: 200, headers: { "x-px-blocked": "1" }, body: "z".repeat(300) }).outcome, "captcha");
  assert.equal(c({ site: web("x"), code: 200, headers: new Map([["CF-MITIGATED", "challenge"]]) }).outcome, "blocked-challenge");
});

// ---- item 3: blocks counted as ok ---------------------------------------------------------

// A Cloudflare managed-challenge page as served with a 200: it names the host it guards, and the
// text says "<site> needs to review the security of your connection".
const cfInterstitial = (host, name) => `<!DOCTYPE html><html lang="en-US"><head><title>Just a moment...</title></head><body>` +
  `<h1>${host}</h1><p>${name} needs to review the security of your connection before proceeding.</p>` +
  `<script src="/cdn-cgi/challenge-platform/h/g/orchestrate/chl_page/v1"></script></body></html>`;
const WEAK = [["hn", "hacker news", "news.ycombinator.com", "Hacker News"], ["wiby", "wiby", "wiby.me", "wiby.me"], ["github", "<title>github", "github.com", "GitHub"]];

t("item 3b: a 200 with cf-mitigated: challenge that names the site is a challenge, not ok (weak markers)", () => {
  for (const [name, marker, host, label] of WEAK) {
    const hdr = { "cf-mitigated": "challenge", server: "cloudflare" };
    // the real interstitial
    assert.deepEqual(c({ site: web(marker), code: 200, headers: hdr, body: cfInterstitial(host, label) }),
      { outcome: "blocked-challenge", marker: "hdr-cf-mitigated" }, name);
    // the header alone decides: a page that carries the site's own title and no body block
    // marker is still a challenge when the edge says it served one
    assert.deepEqual(c({ site: web(marker), code: 200, headers: hdr, body: `<title>${label}</title> ${label} ` + "p".repeat(300) }),
      { outcome: "blocked-challenge", marker: "hdr-cf-mitigated" }, `${name} (title is the site's)`);
  }
  // the other block headers win over the marker the same way
  assert.equal(c({ site: web("hacker news"), code: 200, headers: { "x-amzn-waf-action": "challenge" }, body: "<title>Hacker News</title>" }).outcome, "blocked-challenge");
  assert.equal(c({ site: web("hacker news"), code: 200, headers: { "x-px-blocked": "1" }, body: "<title>Hacker News</title>" }).outcome, "captcha");
});

t("item 3b: the same interstitial without the header is vetoed by its title, not counted ok", () => {
  for (const [name, marker, host, label] of WEAK) {
    const body = cfInterstitial(host, label) + `<!-- ${label} -->`;
    const r = c({ site: web(marker), code: 200, body });
    assert.equal(r.outcome, "blocked-challenge", `${name}: ${JSON.stringify(r)}`);
    assert.equal(r.marker, "cf-just-a-moment", name);
  }
  // other interstitial titles are vetoed too, and land on a block label, never unverified
  for (const [title, outcome] of [["Security Check", "blocked-challenge"], ["Captcha", "captcha"], ["Access Denied", "blocked-403"], ["403 Forbidden", "blocked-403"], ["Attention Required! | Cloudflare", "blocked-403"]]) {
    const r = c({ site: web("hacker news"), code: 200, body: `<title>${title}</title> Hacker News` });
    assert.equal(r.outcome, outcome, `${title}: ${JSON.stringify(r)}`);
  }
});

t("item 3b: the title veto is anchored, so real pages with similar titles stay ok", () => {
  for (const title of ["Forbidden Planet - Books", "Captcha solving, explained", "Security Checklist", "Just a Moment of Calm"]) {
    assert.equal(INTERSTITIAL_TITLE.test(title.toLowerCase()), false, title);
    assert.equal(c({ site: web("real-page"), code: 200, body: `<title>${title}</title> real-page ` + "p".repeat(300) }).outcome, "ok", title);
  }
});

t("item 3a: an api-tier 403 is never ok, even with a JSON error body that matches the marker", () => {
  // The shape of a region block from an API: a 403 in the API's own JSON error envelope.
  const regionBlock = '{"error":{"code":"unsupported_country_region_territory","message":"Country, region, or territory not supported","param":null,"type":"request_forbidden"}}';
  const loose = { tier: "api", okMarker: "invalid_api_key|missing bearer|you didn't provide an api key|\"error\"" };
  assert.deepEqual(c({ site: loose, code: 403, body: regionBlock }), { outcome: "blocked-403", marker: "http-403" });
  // even a marker that names the auth error does not turn a 403 into ok
  const strict = { tier: "api", okMarker: "invalid_api_key" };
  assert.equal(c({ site: strict, code: 403, body: '{"error":{"code":"invalid_api_key"}}' }).outcome, "blocked-403");
  // the unauthenticated 401 is still the proof of reach
  assert.deepEqual(c({ site: strict, code: 401, body: '{"error":{"code":"invalid_api_key"}}' }), { outcome: "ok", marker: "api-401" });
  assert.equal(c({ site: strict, code: 403, body: "<title>Access Denied</title>" }).outcome, "blocked-403");
  // the api exception does not leak into the web tier
  assert.equal(c({ site: { tier: "web", okMarker: "\"error\"" }, code: 401, body: '{"error":1}' }).outcome, "unverified");
});

// ---- item 4: the harness's own failures --------------------------------------------------

t("item 4a: proxy refusals are proxy-refused (not measured), not a site error", () => {
  const cases = [
    "error:connect-refused-502", // the member Proxy answered CONNECT with 502 (budget, no node, dial failed)
    "error:connect-refused-407",
    "error:proxy-ECONNREFUSED", // nothing listening on the proxy port
    "error:proxy-closed",
    "error:bad-proxy-reply",
    "error:curl-proxy-connect",
    "error:curl-recv-connect502", // curl: CONNECT got 502
    "error:curl-proxy-handshake-connect403",
    "error:page.goto: net::ERR_TUNNEL_CONNECTION_FAILED at https://www.example.com/",
    "error:page.goto: net::ERR_PROXY_CONNECTION_FAILED at https://www.example.com/",
  ];
  for (const tr of cases) {
    assert.equal(c({ site: web("x"), transport: tr }).outcome, "proxy-refused", tr);
    assert.ok(NOT_MEASURED.includes(transportOutcome(tr).outcome), tr);
  }
  // a CONNECT code the client saw but that did not end in a transport error
  assert.deepEqual(c({ site: web("x"), code: null, connectCode: 502 }), { outcome: "proxy-refused", marker: "connect-502" });
  assert.equal(c({ site: web("x"), code: 200, body: "x", connectCode: 200 }).outcome, "ok");
  // a 407 status line can only come from a proxy
  assert.deepEqual(c({ site: web("x"), code: 407, body: "" }), { outcome: "proxy-refused", marker: "http-407" });
});

t("item 4a: failures past the tunnel, and the site's own refusals, stay measured", () => {
  for (const tr of ["error:ECONNREFUSED", "error:ECONNRESET", "error:curl-tls", "error:curl-recv-connect200", "error:curl-connect", "error:socks-host-unreachable",
    "error:bad-encoding", "error:page.goto: net::ERR_CONNECTION_RESET at https://www.example.com/", "error:body-limit"]) {
    assert.equal(c({ site: web("x"), transport: tr }).outcome, "error", tr);
  }
  assert.equal(c({ site: web("x"), transport: "timeout" }).outcome, "timeout");
});

t("harness failures are harness-error and cancellations are cancelled (both not measured)", () => {
  for (const tr of ["error:client-unavailable", "error:client-unavailable:no-display (run under xvfb-run)", "error:client-unavailable:launch-failed: x", "error:tmpdir", "error:non-loopback"]) {
    assert.equal(c({ site: web("x"), transport: tr }).outcome, "harness-error", tr);
  }
  assert.deepEqual(c({ site: web("x"), code: 200, body: "x", transport: "error:cancelled" }), { outcome: "cancelled", marker: "error:cancelled" });
  // prefix lookalikes are not swallowed
  assert.equal(c({ site: web("x"), transport: "error:tmpdirx" }).outcome, "error");
  assert.equal(c({ site: web("x"), transport: "error:connect-refused-50" }).outcome, "error");
});

t("item 4b: a proxy's own 403 to a browser http:// fetch is proxy-refused, not blocked-403", () => {
  const site = { tier: "web", okMarker: "hacker news", url: "http://news.example/" };
  // The ShadeNet Proxy answers any non-CONNECT request with this.
  const own = { code: 403, headers: { "content-type": "text/plain; charset=utf-8" }, body: "ShadeNet accepts HTTPS CONNECT tunnels only.\n" };
  for (const client of ["headless", "headed"]) {
    assert.deepEqual(c({ site, ...own, finalUrl: "http://news.example/", exitType: "http", client }), { outcome: "proxy-refused", marker: "proxy-forward-http-403" }, client);
    assert.equal(c({ site, code: 403, body: "<title>403 Forbidden</title>", finalUrl: "http://news.example/", exitType: "http", client }).outcome, "proxy-refused", client);
    assert.equal(c({ site, code: 502, body: "", finalUrl: "http://news.example/", exitType: "http", client }).outcome, "proxy-refused", client);
  }
  // falls back to the site URL when the client reports no final URL
  assert.equal(c({ site, ...own, exitType: "http", client: "headed" }).outcome, "proxy-refused");
});

t("item 4b: the forward rule is narrow (only browser + http proxy + http:// + no site evidence)", () => {
  const site = { tier: "web", okMarker: "hacker news", url: "http://news.example/" };
  const own = { code: 403, body: "ShadeNet accepts HTTPS CONNECT tunnels only.\n", finalUrl: "http://news.example/" };
  // curl and node tunnel even plain http, so a 403 there came from the far end
  for (const client of ["curl", "node"]) assert.equal(c({ site, ...own, exitType: "http", client }).outcome, "blocked-403", client);
  // SOCKS and direct have no forward path
  for (const exitType of ["socks5", "direct", null]) assert.equal(c({ site, ...own, exitType, client: "headed" }).outcome, "blocked-403", String(exitType));
  // https:// pages went through CONNECT, so the 403 is the site's
  assert.equal(c({ site: { ...site, url: "https://news.example/" }, ...own, finalUrl: "https://news.example/", exitType: "http", client: "headed" }).outcome, "blocked-403");
  // a real page or a vendor's block through the forward path is still the site's answer
  assert.equal(c({ site, code: 200, body: "<title>Hacker News</title>" + "h".repeat(300), finalUrl: "http://news.example/", exitType: "http", client: "headed" }).outcome, "ok");
  assert.equal(c({ site, code: 403, headers: { "cf-mitigated": "challenge" }, body: "", finalUrl: "http://news.example/", exitType: "http", client: "headed" }).outcome, "blocked-challenge");
  assert.equal(c({ site, code: 403, body: "Sorry, you have been blocked", finalUrl: "http://news.example/", exitType: "http", client: "headed" }).outcome, "blocked-403");
  assert.equal(c({ site, code: 429, body: "", finalUrl: "http://news.example/", exitType: "http", client: "headed" }).outcome, "blocked-429");
  assert.equal(c({ site, code: 200, body: "<html>" + "a".repeat(500), finalUrl: "http://news.example/", exitType: "http", client: "headed" }).outcome, "unverified");
});

// ---- unchanged behavior ------------------------------------------------------------------

t("captcha vendors are told apart from challenges and denies", () => {
  const cases = [
    ['<script src="https://geo.captcha-delivery.com/c.js">', "captcha", "datadome"],
    ["Press &amp; Hold to confirm you are a human", "captcha", "perimeterx"],
    ["<title>Captcha</title>", "captcha", "title-captcha"],
    ["Bots use DuckDuckGo too. Select all squares containing a duck", "captcha", "ddg-ducks"],
    ["<title>Just a moment...</title>", "blocked-challenge", "cf-just-a-moment"],
    ["/httpservice/retry/enablejs?sei=", "blocked-challenge", "google-enablejs"],
    ["<title>Access Denied</title>", "blocked-403", "access-denied-title"],
    ["Sorry, you have been blocked", "blocked-403", "cf-you-have-been-blocked"],
    ["You've been blocked by network security.", "blocked-403", "reddit-network-security"],
  ];
  for (const [body, outcome, marker] of cases) assert.deepEqual(c({ site: web("never"), code: 200, body }), { outcome, marker }, body);
});

t("captcha precedence over challenge, challenge over plain 403", () => {
  assert.equal(c({ site: web("never"), code: 403, body: '<title>just a moment</title><div class="h-captcha">' }).outcome, "captcha");
  assert.equal(c({ site: web("never"), code: 403, body: "<title>just a moment</title>" }).outcome, "blocked-challenge");
  assert.deepEqual(c({ site: web("never"), code: 403, body: "nope" }), { outcome: "blocked-403", marker: "http-403" });
  assert.deepEqual(c({ site: web("never"), code: 451, body: "" }), { outcome: "blocked-403", marker: "http-451" });
});

t("a final URL on Google's /sorry/ page is a captcha even when the body is empty", () => {
  assert.equal(c({ site: web("never"), code: 200, body: "", finalUrl: "https://www.google.com/sorry/index?continue=x" }).outcome, "captcha");
});

t("transport outcomes: timeout and error never look at the body", () => {
  assert.deepEqual(c({ site: web("x"), code: 200, body: "x", transport: "timeout" }), { outcome: "timeout", marker: null });
  assert.equal(c({ site: web("x"), transport: "error:curl-connect" }).outcome, "error");
  assert.equal(c({ site: web("x"), transport: "e".repeat(1000) }).marker.length, 160);
});

t("5xx is error, no status is error, tiny 2xx is unverified", () => {
  assert.deepEqual(c({ site: web("x"), code: 503, body: "down" }), { outcome: "error", marker: "http-503" });
  assert.deepEqual(c({ site: web("x"), code: null }), { outcome: "error", marker: "no-status" });
  assert.deepEqual(c({ site: web("x"), code: 200, body: "<html></html>" }), { outcome: "unverified", marker: "empty-200" });
  assert.deepEqual(c({ site: web("x"), code: 302, body: "" }), { outcome: "unverified", marker: "http-302-no-marker" });
});

t("string status codes are accepted, junk ones are not", () => {
  assert.equal(c({ site: web("yes"), code: "200", body: "yes" }).outcome, "ok");
  assert.equal(c({ site: web("yes"), code: "2OO", body: "yes" }).outcome, "error");
  assert.equal(c({ site: web("yes"), code: 200.5, body: "yes" }).outcome, "error");
});

t("hostile and garbage input never throws", () => {
  const weird = [undefined, null, 42, "str", [], { site: null }, { site: { okMarker: "(" }, code: 200, body: "(" },
    { site: { okMarker: 5 }, code: 200, body: {} }, { headers: "nope", body: Symbol.iterator.toString() },
    { headers: { toString: null, a: [1, 2] }, code: 200, body: { toString() { throw new Error("x"); } } },
    { site: web("x"), code: 200, body: "\u0000".repeat(1000), title: { length: 9 } },
    { site: { url: {} }, code: 403, finalUrl: { href: 1 }, exitType: "http", client: "headed" },
    { site: web("x"), transport: { toString() { throw new Error("t"); } } }, { site: web("x"), transport: 7 }, { connectCode: "502" }];
  for (const w of weird) {
    const r = classify(w);
    assert.ok(OUTCOMES.includes(r.outcome), JSON.stringify(r));
  }
});

t("a 2 MB body classifies in bounded time", () => {
  const body = ("<div class=\"g-rec" + "a".repeat(100)).repeat(20000);
  const t0 = Date.now();
  classify({ site: web("never-matches"), code: 200, body });
  assert.ok(Date.now() - t0 < 2000, `took ${Date.now() - t0}ms`);
});

t("an invalid marker regex is treated as no marker, not a crash", () => {
  assert.equal(compileMarker("(unclosed"), null);
  assert.equal(compileMarker(""), null);
  assert.equal(compileMarker(7), null);
  const re = /x/;
  assert.equal(compileMarker(re), re);
  assert.equal(c({ site: web("(unclosed"), code: 200, body: "(unclosed" + "a".repeat(300) }).outcome, "unverified");
});

t("vendorOf names the vendor from headers and two body tells", () => {
  assert.deepEqual(vendorOf({ "CF-RAY": "1" }), ["cloudflare"]);
  assert.deepEqual(vendorOf({ server: "AkamaiGHost" }), ["akamai"]);
  assert.deepEqual(vendorOf({ "x-akamai-transformed": "9" }), ["akamai"]);
  assert.deepEqual(vendorOf({}, "geo.captcha-delivery.com"), ["datadome"]);
  assert.deepEqual(vendorOf({ "x-px-foo": "1" }), ["perimeterx"]);
  assert.deepEqual(vendorOf({ server: "CloudFront", "x-amzn-waf-action": "challenge" }), ["cloudfront", "aws-waf"]);
  assert.deepEqual(vendorOf({ server: "snooserv" }), ["reddit"]);
  assert.deepEqual(vendorOf({ "x-served-by": "cache-fra1" }), ["fastly"]);
  assert.deepEqual(vendorOf(null, null), []);
});

t("titleOf and lowerHeaders are bounded and tolerant", () => {
  assert.equal(titleOf("<title>  A \n B </title>"), "A B");
  assert.equal(titleOf("<TITLE lang=en>" + "t".repeat(500)).length, 120);
  assert.equal(titleOf(null), "");
  assert.deepEqual(lowerHeaders({ A: "1", B: ["x", "y"] }), { a: "1", b: "x, y" });
  assert.deepEqual(lowerHeaders("x"), {});
  const bad = { get entries() { throw new Error("no"); } };
  Object.setPrototypeOf(bad, { constructor: Map });
  assert.deepEqual(lowerHeaders(bad), {});
});

console.log(`PASS classify (${n} cases)`);
