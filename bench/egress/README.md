# Egress benchmark: classifier, sites parser, report

The pure parts of an egress benchmark: label one request's outcome, parse the operator's site
list, and turn result rows into markdown tables. There is no runner here yet. Nothing in this
directory opens a socket, spawns a process or reads a file, and there is no CLI and no sample
data. The selftests run in the normal node suite:

```bash
node bench/egress/classify.selftest.mjs
node bench/egress/parse.selftest.mjs
```

Bench code is not in the coverage gate (`.c8rc.json` does not include `bench/`).

## Outcomes (`lib/classify.mjs`)

One per cell. `lib/classify.mjs` explains the precedence; in short, a block signal in the status
or headers wins over the site's positive marker, an interstitial title vetoes the marker, and a
real page that matched its marker wins over block words in its body.

| Outcome | Meaning | In the denominator |
|---|---|---|
| `ok` | 2xx, the positive marker matched, no challenge header, no interstitial title. For the `api` tier: an unauthenticated 401 carrying the marker. A 403 is never ok | yes |
| `blocked-429` | 429 or a rate-limit page | yes |
| `blocked-challenge` | a JS or managed interstitial (`cf-mitigated: challenge`, "Just a moment", AWS WAF, a CloudFront empty 202, proof-of-work pages, a size-guard hit) | yes |
| `captcha` | an interactive test | yes |
| `blocked-403` | 403/451 or a deny page with no challenge offered | yes |
| `timeout` | transport timeout | yes |
| `error` | transport error after the tunnel opened, no status, or 5xx | yes |
| `unverified` | a status with neither a positive nor a block marker; look at it by hand | yes |
| `proxy-refused` | the local proxy refused or failed the request itself: a non-200 CONNECT reply, the proxy unreachable, a 407, or the proxy's own answer to a browser's plain `http://` forward request | no |
| `harness-error` | the harness could not run the cell (client unavailable, temp dir, a local-only guard) | no |
| `cancelled` | operator interruption | no |

The last three say nothing about the exit or the site. The report leaves them out of every
share, cell count and timing, and prints them next to the cell (`+prx`, `+hrn`, `+can`) with a
warning that the run is incomplete.

The transport strings a runner must report for each case are listed above `transportOutcome`
in `lib/classify.mjs`.

## Sites file (`lib/sites.mjs`)

One site per line, `#` starts a comment:

```
tier  name  wall  url  [min=<bytes>]  [ok-marker regex, rest of line, case-insensitive]
```

- `tier`: `search`, `web` or `api`.
- `wall`: the anti-bot vendor or policy in front of the site, as recorded by whoever added it.
  The report groups by it.
- `ok-marker`: positive evidence the real page rendered. Without one, a 2xx is `unverified`.
  For `api` it must name the API's own unauthenticated error; a marker that also matches a
  generic error body (for example a bare `"error"`) is refused, because it would match a region
  or policy block too.
- `min=N`: a marker match under N bytes is an interstitial wearing the site's title, so it is a
  challenge.

The parser fails closed with a line number on any malformed line, a bad regex, or a marker with
an obvious nested quantifier. That check is a heuristic, not a bound on hostile regexes: use
markers you trust.

## Report (`lib/report.mjs`)

`buildReport({rows, dials, metas})` returns markdown: a summary of the ok share over measured
cells, a table per wall, a table per client and site, cell time (wall-clock for the whole cell,
which for a browser includes any fixed settle wait the runner adds, so it is not page-load time),
dial times, and one provenance line per run. The provenance line prints the exit label and kind,
the sampled ASN and country if one was looked up, the harness commit, versions, and the hardware
class with the platform only. It never prints an IP address, a hostname, a kernel build string,
a proxy host or a local path, whatever the meta rows carry.

`validateCohorts` refuses duplicate cells, mixed runs under one exit label, and cells outside the
planned cohort, and warns when a run is incomplete or its metadata cannot be checked.
