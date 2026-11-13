# Benchmarks

Reproducible measurements of what ShadeNet costs. Each benchmark is a small Node CLI with a
`*.selftest.mjs` (picked up by `npm test` automatically) and a section in this README: what it
measures, what it does not, how to run it. Benchmark code is not product code and stays out of
the c8 coverage `include`.

`experiments/` holds historical measurements of older protocol versions and is not
maintained.

## RLN proof and verify timing

`bench/rln/prove-verify.mjs` builds an in-memory RLN group of ephemeral members (as
`test/timing.selftest.mjs` does), then times `proveForSlot` and `verifyEnvelope` from
`packages/node/lib/rln.mjs` with the circuit artifacts in `circuits/rln/`. No network is in
the path. Every envelope it times must verify, or the run fails.

```bash
node bench/rln/prove-verify.mjs --label laptop --prove 20 --verify 200 --out laptop.json
node bench/rln/prove-verify.mjs --markdown laptop.json other-box.json
```

- **Cold and warm.** The first prover call is in a fresh process and is reported as `prove.coldMs`.
  The verifier's `coldMs` is its first call *after proving in the same process*, not a
  fresh-process verifier cold start; the markdown column says so. Every later call is warm and
  goes into the p50/p95.
- **Provenance.** The result records the commit (and whether `packages/node/lib`, `circuits` or
  `bench/rln` were dirty), the artifact id the client proved with, K, Node, the exact command,
  and the hardware class (CPU model, core count, memory, platform, arch). It does not record the
  hostname, the kernel build string or a local path: `--label` defaults to `unlabelled`, and
  `--out` is recorded as a file name only.
- **What it does not measure.** This is one piece of
  [#63](https://github.com/dmarzzz/shade-tree-node/issues/63): the JS proof and verify rows.
  Still open there: the Rust prover (`crates/shadenet-rln`), paired direct-Tor vs ShadeNet
  request latency to one target, gateway saturation under a controlled ramp, and the published
  table. Crypto timing on one box is not throughput and not Tor latency. No results are
  committed here.
