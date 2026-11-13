#!/usr/bin/env node
// RLN v4 proof generation and verification timing, JS path (refs #63).
//
//   node bench/rln/prove-verify.mjs                       one JSON object on stdout
//   node bench/rln/prove-verify.mjs --label laptop --prove 20 --verify 100 --out bench/rln/runs/laptop.json
//   node bench/rln/prove-verify.mjs --markdown runs/*.json one table row per file
//
// What it measures, with no network in the path:
//   prove   packages/node/lib/rln.mjs proveForSlot: the member's cost, once per RLN slot
//           (direct-proof/session-init spends slots; session redemption differs)
//   verify  verifyEnvelope: the node's cost, on every tunnel, after its cheap checks
// The first prover call is a fresh-process cold call. The verifier first call runs AFTER
// proving in the same process, so its legacy coldMs field is not a fresh-worker cold start.
//
// It uses the same in-memory group construction as test/timing.selftest.mjs: N ephemeral
// identities at the default tier, one fixed target. Proof cost depends on the circuit and tree
// depth, not on which member proves, so ephemeral identities give the real number without any
// member secret on the benchmark box.
//
// The result names the hardware class (CPU model, core count, memory, platform, arch) because a
// timing means nothing without it, and nothing that identifies the machine or its operator: no
// hostname (the label defaults to "unlabelled", not os.hostname()), no kernel build string, and
// no local path (the recorded command keeps only the file name of --out).
//
// What it does NOT measure (the rest of #63, still open): the Rust prover
// (crates/shadenet-rln), added round-trip over plain Tor, and gateway saturation. Crypto timing
// is not throughput and not Tor latency.

import os from "node:os";
import { execFileSync } from "node:child_process";
import { realpathSync } from "node:fs";
import { readFile, writeFile, mkdir } from "node:fs/promises";
import { basename, dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, "../..");

export const DEFAULT_LABEL = "unlabelled";

export function stats(xs) {
  const a = xs.filter(Number.isFinite).sort((p, q) => p - q);
  const n = a.length;
  if (!n) return { n: 0 };
  const q = (p) => a[Math.min(n - 1, Math.max(0, Math.ceil(p * n) - 1))];
  const r2 = (x) => Math.round(x * 100) / 100;
  const mean = a.reduce((s, x) => s + x, 0) / n;
  return { n, min: r2(a[0]), p50: r2(q(0.5)), p95: r2(q(0.95)), max: r2(a[n - 1]), mean: r2(mean) };
}

const fmt = (x) => (x == null ? "-" : `${Math.round(x)} ms`);
export function markdownRows(results) {
  const out = ["| label | host | prove cold | prove p50 | prove p95 | verify first after proving | verify p50 | verify p95 | n prove / verify | commit | artifact |",
    "|---|---|---|---|---|---|---|---|---|---|---|"];
  for (const r of results) {
    const h = r.host || {};
    out.push(`| ${r.label} | ${h.cpus} x ${h.cpu}, ${h.memGb} GB | ${fmt(r.prove?.coldMs)} | ${fmt(r.prove?.warm?.p50)} | ${fmt(r.prove?.warm?.p95)} | ` +
      `${fmt(r.verify?.coldMs)} | ${fmt(r.verify?.warm?.p50)} | ${fmt(r.verify?.warm?.p95)} | ${r.prove?.warm?.n ?? 0} / ${r.verify?.warm?.n ?? 0} | ` +
      `${String(r.git?.commit || "?").slice(0, 12)}${r.git?.dirty ? "+dirty" : ""} | ${String(r.artifact || "?").slice(0, 16)} |`);
  }
  return out.join("\n");
}

// The command as recorded in the result. --out is reduced to its file name: the full path is a
// local directory layout (often a home directory), which says who ran it and adds nothing to
// reproducing the timing.
export function commandLine(argv) {
  const out = [];
  for (let i = 0; i < argv.length; i++) {
    const v = String(argv[i]);
    if (v === "--out" && i + 1 < argv.length) { out.push(v, basename(String(argv[++i]))); continue; }
    if (v.startsWith("--out=")) { out.push(`--out=${basename(v.slice(6))}`); continue; }
    out.push(v);
  }
  return `node bench/rln/prove-verify.mjs ${out.join(" ")}`.trim();
}

// Hardware class only. os.hostname() and os.release() are left out on purpose (see the header).
export function hostClass() {
  const cpus = os.cpus() || [];
  return { os: os.platform(), arch: os.arch(), cpu: cpus[0]?.model.trim() || null, cpus: cpus.length, memGb: Math.round(os.totalmem() / 2 ** 30) };
}

// The timed loops. `rln` is packages/node/lib/rln.mjs in a real run; the selftest passes a stub
// with a virtual clock (`now`) so it can check exactly which call lands in which bucket.
// Call 0 of each loop is the "cold" call and is kept out of the warm statistics.
export async function measure({ members, nProve, nVerify }, rln, now) {
  const { currentEpoch, requestSignal, proveForSlot, verifyEnvelope, identityFor, groupFromIdentities, toField, K_SLOTS } = rln;
  const secrets = Array.from({ length: members }, (_, i) => toField("0x" + (i + 17).toString(16).padStart(2, "0").repeat(32)));
  const group = groupFromIdentities(secrets.map((s) => identityFor(s)));
  const roots = new Set([group.root.toString()]);
  const epoch = currentEpoch();
  const target = "example.com:443";

  const proveTimes = []; const envelopes = []; let proveCold = null;
  for (let i = 0; i <= nProve; i++) {
    const nonce = `bench-${i}`;
    const t0 = now();
    const p = await proveForSlot(secrets[i % members], epoch, i % K_SLOTS, requestSignal(target, nonce), { group });
    const dt = now() - t0;
    if (i === 0) proveCold = dt; else proveTimes.push(dt);
    envelopes.push({ v: 4, target, nonce, proof: p.proof, nullifier: p.nullifier, externalNullifier: p.externalNullifier, share: p.share, artifact: p.artifact });
  }
  const verifyTimes = []; let verifyCold = null;
  for (let i = 0; i <= nVerify; i++) {
    const env = envelopes[i % envelopes.length];
    const t0 = now();
    const r = await verifyEnvelope(env, roots);
    const dt = now() - t0;
    // A timing of a rejected proof is not a verify timing (a rejection can return before the
    // SNARK check), so one rejection fails the whole run.
    if (r?.ok !== true) throw new Error(`verify rejected a valid envelope: ${r?.reason}`);
    if (i === 0) verifyCold = dt; else verifyTimes.push(dt);
  }
  return {
    artifact: envelopes[0].artifact || null, kSlots: K_SLOTS,
    prove: { coldMs: Math.round(proveCold * 100) / 100, warm: stats(proveTimes) },
    verify: { coldMs: Math.round(verifyCold * 100) / 100, warm: stats(verifyTimes) },
  };
}

async function main() {
  const { values: a, positionals } = parseArgs({ allowPositionals: true, options: {
    label: { type: "string", default: DEFAULT_LABEL }, members: { type: "string", default: "4" },
    prove: { type: "string", default: "10" }, verify: { type: "string", default: "50" }, out: { type: "string" },
    markdown: { type: "boolean", default: false },
  } });
  if (a.markdown) {
    const rs = await Promise.all(positionals.map(async (f) => JSON.parse(await readFile(f, "utf8"))));
    console.log(markdownRows(rs));
    return;
  }
  const int = (k, lo, hi) => { const v = Number(a[k]); if (!Number.isInteger(v) || v < lo || v > hi) { console.error(`--${k} must be an integer in [${lo}, ${hi}]`); process.exit(2); } return v; };
  const members = int("members", 1, 64); const nProve = int("prove", 1, 1000); const nVerify = int("verify", 1, 100000);

  const rln = await import("../../packages/node/lib/rln.mjs");
  try {
    const m = await measure({ members, nProve, nVerify }, rln, () => Number(process.hrtime.bigint()) / 1e6);
    const git = (() => {
      try {
        return { commit: execFileSync("git", ["rev-parse", "HEAD"], { cwd: ROOT, encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim(),
          dirty: execFileSync("git", ["status", "--porcelain", "--", "packages/node/lib", "circuits", "bench/rln"], { cwd: ROOT, encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim().length > 0 };
      } catch { return { commit: null, dirty: null }; }
    })();
    const result = {
      bench: "rln/prove-verify", label: a.label, ts: new Date().toISOString(),
      command: commandLine(process.argv.slice(2)),
      git, artifact: m.artifact || rln.clientArtifactIds()[0], kSlots: m.kSlots, members,
      host: hostClass(),
      node: process.version,
      prove: m.prove,
      verify: m.verify,
      notes: "prove cold = first call in a fresh process. verify coldMs is the first verifier call AFTER proving in that same process, not a fresh-process verifier cold start. JS path only; see bench/README.md for what this does not measure.",
    };
    const json = JSON.stringify(result, null, 2);
    if (a.out) { await mkdir(dirname(resolve(a.out)), { recursive: true }); await writeFile(a.out, json + "\n"); }
    console.log(json);
  } finally {
    rln.cleanUp();
  }
}

// import.meta.url is the real path; argv[1] is the path as typed. Compare real paths, or a run
// through a symlinked checkout would skip main() and exit 0 having measured nothing.
export function isEntry(argv1, selfUrl = import.meta.url) {
  if (!argv1) return false;
  const real = (p) => { try { return realpathSync(p); } catch { return resolve(p); } };
  return real(argv1) === real(fileURLToPath(selfUrl));
}

if (isEntry(process.argv[1])) {
  main().then(() => process.exit(0), (e) => { console.error(e); process.exit(1); });
}
