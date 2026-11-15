# research/measurements

Aggregates from a scheduled shadenet measurement battery (one run every 6 h, script only).
This branch holds only `measurements/YYYY-MM-DD.jsonl`, one JSON line per run. It is not code and
is never merged into main.

Each line has:
- `m`: headline metrics. `e1_*`/`e2_*` = the two Elders: /health and /directory over Tor, 3 rounds each,
  fresh circuit per request (median seconds, ok counts, up flag). `node2_*` = one 100-byte HTTPS fetch
  through a member proxy pinned to one private gateway (total seconds, tunnel setup seconds from the
  proxy's own log, ok flag).
- `e1_directory` / `e2_directory`: directory size and operator shares (gateway count, staked count,
  operators, weight shares, effective operators = inverse Simpson, health and region counts).
  New `canopy_v: 2` rows use stable opaque full-identity hashes for both `operator_shares` and
  `operator_counts`; older rows used address prefixes (do not join these keys across versions).
  `eff_regions` is count-based inverse Simpson, including missing region as one category.
  `asn_mapped`, `asn_unmapped`, `asns_known` and `eff_asns_known` describe coverage from our
  local fleet table only, with no external lookup. `eff_asns` is null unless every listed gateway
  is mapped, so partial fleet coverage is never presented as network-wide ASN diversity.
  Missing fields in older rows mean unmeasured, not zero. Directory claims are self-declared.
- `transfer_1mib`: 1 MiB from an owned endpoint, plain Tor vs shadenet, or `skipped` if the endpoint is down.
- `onion_trial` (2026-11-13 to 2026-11-15): one restart trial and one control on a throwaway onion that is
  never announced, to measure day-to-day swing in warm-client recovery. `outage_warm_s` is seconds from
  just before the restart command to the first successful fetch by an already-connected client.
- `confounders`, `gateway_restarts_during_run`, `load1`: things that could have disturbed the run.
- `regressions`: metrics more than 2x the trailing median of the last 12 runs (and above an absolute floor).

No IPs, no credentials, no onion addresses.
