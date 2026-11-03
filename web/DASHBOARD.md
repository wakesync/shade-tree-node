# Canopy dashboard

An operator view of every Elder Tree in a network record and every node they list. It is
read-only and binds loopback. It sits next to the [status page](README.md), which reads one
bootnode.

```bash
# Elders come from network/sepolia/deployment.json; needs a local Tor SOCKS port
SHADE_TREE_TOR_PORT=9050 node web/dashboard-server.mjs
# -> http://127.0.0.1:8091
```

## Why it exists

A v4 record lists more than one Elder (`deployment.json` `elders[]`), each with its own Canopy
signer, and clients fail over between them. That means one Elder can be down for days while
the canopy keeps working, and none of the existing views show it:

| View | Reads | Shows a down second Elder? |
| --- | --- | --- |
| `web/status.html` | one bootnode | no, it only knows one |
| `uptime-probe.yml` + public Grove | `SHADE_TREE_BOOTNODE_ONION` (one Elder) | no, stays green |
| `monitoring/grafana-dashboard.json` | loopback metrics on hosts you run | only for Elders you run |
| this dashboard | every Elder in the record, over Tor | yes, per Elder, with history |

It also shows things the public Grove is not allowed to publish: per-node health, draining,
which Elder lists which node, the Elder's running commit against the record pin, and the signed
incident feed.

## What it shows

- **Summary.** Elders verified out of listed, distinct nodes, up, down or draining, distinct
  operators (a count only), and how old the newest verified directory is.
- **Elder Trees.** One card per Elder: reachable, directory verified under *that* Elder's pinned
  signer, freshness, round-trip times, running commit against `services.elder.commit`, signed
  incidents, signed relay-telemetry state, and how many observations since start verified.
- **Trend.** Canopy size and a per-Elder verified strip, held in memory for the server's life
  (1440 samples, 24 h at the default 60 s interval). It is not persisted.
- **Nodes.** The merged canopy, one row per node: which Elders list it, health (`up`, `down`, or
  `mixed` when Elders disagree), draining, weight, protocol, admission paths, staked. With
  `SHADE_TREE_DASH_PROBE_NODES=1` it also shows a SOCKS dial time per node.
- **Canopy mix.** Declared region, admission paths, and Elder coverage as aggregate bars.

## Trust

Like the status page, it is a cache viewer and not a trust root.

- A directory counts only if `verifyDirectory` accepts it under that Elder's own pinned signer
  and its `issued` time is within 300 s, the same window `scripts/uptime-probe.mjs` uses. Pins are
  per Elder: a directory signed by another Elder's key does not verify, even though both keys
  are in the record.
- An Elder whose directory fails is shown as **unverified**, with a short reason, and none of
  its rows enter the node table. A lying or tampered cache makes its Elder look bad. It cannot
  add, remove or edit a row.
- The incident feed (`verifyIncidents`) and relay aggregate (`verifyRelayAggregate`) are checked
  under the same Elder signer. A feed that fails is labelled unverified and its contents are
  dropped.
- Responses are read with a 512 KiB cap. Errors are reduced to a fixed vocabulary
  (`tor: onion unreachable`, `timeout`, ...), so the page never echoes Elder-supplied text. The
  page writes every value with `textContent` and is served with the site's CSP.

## Privacy

The node rows come from the discovery plane. `specs/data-api.md` says that plane must not be
mirrored onto the public site, so this is an operator tool. The page still uses the status
page's privacy rules and adds a few more:

- Node onions are cut to 16 characters. The full address is only ever a map key in memory.
- Operator addresses are dropped. A node has a `staked` flag, and the canopy has one count of
  distinct operators.
- `caps.region` never appears on a row, because that would map a node to a region. Regions are
  only aggregate bars, folded at k = 2 with `web/fleet-map.mjs` `bucketBy`, so a named region
  always means at least two nodes.
- Incident `instance` labels are dropped. They name hosts, and the canopy deliberately does not
  map hosts to onions. Onions inside incident text are replaced with `<onion>`.
- History samples are counts and per-Elder booleans only.
- Elder onions are public (they are in the committed record), so Elders are labelled with an
  8-character prefix.

Do not put this server on a public address. If it has to be shared, front it with auth or serve
it as its own onion.

## Config

| Var | Meaning | Default |
| --- | --- | --- |
| `SHADE_TREE_NETWORK` | record under `network/` to read Elders from | `sepolia` |
| `SHADE_TREE_DASH_ELDERS` | override, `<url-or-onion>=<signer>,...` (dev, local Elders) | none |
| `SHADE_TREE_DASH_PORT` | loopback port | `8091` |
| `SHADE_TREE_DASH_INTERVAL_SEC` | seconds between observations (minimum 15) | `60` |
| `SHADE_TREE_DASH_PROBE_NODES` | `1` to also dial every node's onion (SOCKS connect, no request, no proof) | off |
| `SHADE_TREE_TOR_HOST` / `SHADE_TREE_TOR_PORT` | local Tor SOCKS | `127.0.0.1:9250` |

Observation runs on a timer, never per request: an onion round trip takes seconds and a dead
Elder takes the full timeout, so a page view must not wait on Tor. The node dial adds one Tor
circuit per node per interval. Leave it off unless you are looking at reachability.

## API

- `GET /api/canopy` returns the last observation as `shade-tree-dashboard-v1`, or `503
  {"error":"first_observation_pending"}` before the first one completes. It never returns a
  synthetic empty canopy.
- `GET /api/history` returns `{ cap, count, samples: [{ at, size, down, draining, elders: [{
  reachable, verified, size }] }] }`.

Any query string gets a 400. The schema is internal to this tool and is not a public Data API.

## What it does not do (yet)

- **Public page.** A public version on shadenet.xyz needs a signed aggregate, not this view.
  The Vercel function cannot dial Tor, so the hosted observer would have to publish per-Elder
  aggregates (reachable, verified, directory age, count) through the `network-state` path, signed
  like `grove-v2.json`. That is a Data API change. See `specs/data-api.md` "Aggregate publisher
  plane".
- **Member-side stats.** Proof time, ticket reuse, and first-byte latency through a node need a
  staked member identity and spend rate-limit slots. The node dial is the most that can be
  measured without one.
- **Persistence.** History resets on restart.

## Test

```bash
node web/dashboard.selftest.mjs                                    # observer + server, incl. adversarial
npx playwright test --config=playwright.config.mjs test/site-browser/dashboard.spec.mjs   # browser + axe
```
