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
  operators, weight share per operator address prefix, effective operators = inverse Simpson, health
  and region counts). Only what the public directory shows.
- `transfer_1mib`: 1 MiB from an owned endpoint, plain Tor vs shadenet, or `skipped` if the endpoint is down.
- `onion_trial` (2026-11-13 to 2026-11-15): one restart trial and one control on a throwaway onion that is
  never announced, to measure day-to-day swing in warm-client recovery. `outage_warm_s` is seconds from
  just before the restart command to the first successful fetch by an already-connected client.
- `confounders`, `gateway_restarts_during_run`, `load1`: things that could have disturbed the run.
- `regressions`: metrics more than 2x the trailing median of the last 12 runs (and above an absolute floor).

No IPs, no credentials, no onion addresses.
