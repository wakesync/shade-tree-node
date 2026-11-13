// Selftest for bench/rln/prove-verify.mjs (the RLN v4 timing benchmark, refs #63).
//
//   node bench/rln/prove-verify.selftest.mjs
//
// Two halves.
//
// 1. measure() against a stub rln module and a virtual clock. Each stub call advances the clock by
//    a scripted amount, so the test knows exactly what the cold and warm numbers must be: call 0
//    of each loop is cold and is kept out of the warm statistics, every proof is verified (and
//    only proofs this run made), a rejection fails the run, and --members spreads the proofs over
//    that many identities. Wall-clock timings cannot check any of this, which is why it is a stub.
//
// 2. The real CLI once with tiny counts: real Groth16 proofs through proveForSlot and
//    verifyEnvelope. The result must be well formed, carry the commit and the artifact id the
//    client actually proves with, and name the hardware class without the hostname, the kernel
//    build or a local path. Timings are only checked to be positive: CI hardware varies, and
//    test/timing.selftest.mjs already owns the "verify is member-independent" property.
//
// Listed in scripts/test-all.mjs SLOW_SUITES because it makes real Groth16 proofs. No Linux
// assumption: paths come from os.tmpdir() and path.join, and git is optional (if this tree is
// not a git checkout the commit must then be null, not invented).

import assert from "node:assert/strict";
import { execFileSync, spawn } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, symlinkSync } from "node:fs";
import os from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { stats, markdownRows, measure, commandLine, hostClass, isEntry, DEFAULT_LABEL } from "./prove-verify.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, "../..");
const run = (args, script = join(HERE, "prove-verify.mjs")) => new Promise((done) => {
  const c = spawn(process.execPath, [script, ...args]);
  let stdout = ""; let stderr = "";
  c.stdout.on("data", (d) => { stdout += d; });
  c.stderr.on("data", (d) => { stderr += d; });
  c.on("close", (status) => done({ status, stdout, stderr }));
});

assert.deepEqual(stats([]), { n: 0 });
assert.deepEqual(stats([3, 1, 2, NaN]), { n: 3, min: 1, p50: 2, p95: 3, max: 3, mean: 2 });
assert.equal(stats(Array.from({ length: 100 }, (_, i) => i + 1)).p95, 95);
console.log("  ok   stats: nearest-rank percentiles, NaN dropped");

const md = markdownRows([{ label: "box", host: { cpus: 2, cpu: "cpu", memGb: 4 }, prove: { coldMs: 900.4, warm: { n: 5, p50: 400, p95: 450 } },
  verify: { coldMs: 30, warm: { n: 50, p50: 12, p95: 14 } }, git: { commit: "0123456789abcdef", dirty: false }, artifact: "rln-ae43614cd02ebe95" }, {}]);
assert.match(md, /\| box \| 2 x cpu, 4 GB \| 900 ms \| 400 ms \| 450 ms \| 30 ms \| 12 ms \| 14 ms \| 5 \/ 50 \| 0123456789ab \| rln-ae43614cd02e \|/);
assert.match(md.split("\n")[3], /\| - \| - \|/, "a result with missing fields renders dashes, not a crash");
console.log("  ok   markdownRows: one row per result, tolerant of missing fields");

// ---- 1. measure() with a stub rln and a virtual clock ----------------------------------------

// Scripted durations: call 0 is deliberately far slower, so any mixing of cold into warm (or warm
// into cold) changes a number this test pins.
const PROVE_MS = [1000, 10, 30, 20];        // cold, then 3 warm
const VERIFY_MS = [500, 4, 1, 3, 2, 5];     // cold, then 5 warm
function stubRln({ reject = false } = {}) {
  let t = 0; let pi = 0; let vi = 0;
  const made = new Set(); const verified = []; const provers = []; const slots = [];
  const rln = {
    K_SLOTS: 3,
    currentEpoch: () => 7,
    toField: (h) => BigInt(h),
    identityFor: (s) => ({ s }),
    groupFromIdentities: (ids) => ({ root: 99n, ids }),
    requestSignal: (target, nonce) => `${target}|${nonce}`,
    proveForSlot: async (secret, epoch, slot, signal, { group }) => {
      assert.equal(group.root, 99n, "proves against the group it built");
      provers.push(secret); slots.push(slot);
      t += PROVE_MS[pi++];
      const proof = `proof-${pi}`; made.add(proof);
      return { proof, nullifier: "n", externalNullifier: "e", share: { x: "1", y: "2" }, artifact: "rln-stub0123" };
    },
    verifyEnvelope: async (env, roots) => {
      assert.ok(roots.has("99"), "verifies against the group's root");
      verified.push(env.proof);
      t += VERIFY_MS[vi++];
      return reject && vi === 3 ? { ok: false, reason: "stub-reject" } : { ok: true };
    },
  };
  return { rln, now: () => t, made, verified, provers, slots };
}

{
  const s = stubRln();
  const m = await measure({ members: 2, nProve: 3, nVerify: 5 }, s.rln, s.now);
  assert.equal(m.prove.coldMs, 1000, "prove cold is call 0");
  assert.deepEqual(m.prove.warm, { n: 3, min: 10, p50: 20, p95: 30, max: 30, mean: 20 }, "prove warm is calls 1..n, cold excluded");
  assert.equal(m.verify.coldMs, 500, "verify first-after-proving is verify call 0");
  assert.deepEqual(m.verify.warm, { n: 5, min: 1, p50: 3, p95: 5, max: 5, mean: 3 }, "verify warm is calls 1..n, first excluded");
  assert.equal(s.verified.length, 6, "every timed verify called verifyEnvelope");
  assert.ok(s.verified.every((p) => s.made.has(p)), "only this run's own proofs are verified");
  assert.equal(new Set(s.verified).size, 4, "every proof made is verified at least once");
  assert.equal(new Set(s.provers.map((p) => String(p))).size, 2, "--members 2 proves with 2 distinct identities");
  assert.deepEqual(s.slots, [0, 1, 2, 0], "slots cycle through K_SLOTS");
  assert.equal(m.artifact, "rln-stub0123", "artifact id is the one the prover reported");
  assert.equal(m.kSlots, 3);
  console.log("  ok   measure: cold call kept out of warm stats, every proof verified, members spread, artifact from the prover");
}
{
  const s = stubRln({ reject: true });
  await assert.rejects(measure({ members: 1, nProve: 1, nVerify: 4 }, s.rln, s.now), /verify rejected a valid envelope: stub-reject/);
  console.log("  ok   measure: one rejected verify fails the run instead of being timed");
}

// ---- recorded command and host class: no local path, no hostname -----------------------------

const sep = os.platform() === "win32" ? "\\" : "/";
const deep = ["", "someone", "private", "runs", "r.json"].join(sep);
assert.equal(commandLine(["--prove", "2", "--out", deep]), "node bench/rln/prove-verify.mjs --prove 2 --out r.json");
assert.equal(commandLine([`--out=${deep}`, "--verify", "3"]), "node bench/rln/prove-verify.mjs --out=r.json --verify 3");
assert.equal(commandLine([]), "node bench/rln/prove-verify.mjs");
const hc = hostClass();
assert.deepEqual(Object.keys(hc).sort(), ["arch", "cpu", "cpus", "memGb", "os"]);
assert.equal(hc.os, os.platform(), "os is the platform only, no kernel build string");
console.log("  ok   provenance: --out kept as a file name, host is hardware class only");

// ---- 2. the real CLI -----------------------------------------------------------------------

const bad = await run(["--prove", "0"]);
assert.equal(bad.status, 2);
assert.match(bad.stderr, /--prove/);
console.log("  ok   bad counts are refused");

// Entry detection: run through a symlink, the CLI must still run main() (here: refuse the bad
// count with status 2) instead of exiting 0 having done nothing. Where the OS refuses to make a
// symlink (Windows without the privilege), only the pure check runs.
const self = join(HERE, "prove-verify.mjs");
assert.equal(isEntry(self, pathToFileURL(self).href), true);
assert.equal(isEntry(join(HERE, "prove-verify.selftest.mjs"), pathToFileURL(self).href), false);
assert.equal(isEntry(undefined), false);
{
  const ldir = mkdtempSync(join(os.tmpdir(), "rln-bench-link-"));
  try {
    let linked = null;
    try { symlinkSync(HERE, join(ldir, "rln"), "dir"); linked = join(ldir, "rln", "prove-verify.mjs"); } catch { /* no symlink privilege */ }
    if (linked) {
      assert.equal(isEntry(linked, pathToFileURL(self).href), true);
      const viaLink = await run(["--prove", "0"], linked);
      assert.equal(viaLink.status, 2, "through a symlink the CLI still parses its arguments");
    }
    console.log(`  ok   entry detection compares real paths${linked ? " (symlinked run checked)" : " (symlink not available, pure check only)"}`);
  } finally { rmSync(ldir, { recursive: true, force: true }); }
}

const expectCommit = (() => {
  try { return execFileSync("git", ["rev-parse", "HEAD"], { cwd: ROOT, encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim(); } catch { return null; }
})();
const rln = await import("../../packages/node/lib/rln.mjs");
const expectArtifact = rln.clientArtifactIds()[0];
rln.cleanUp();

const dir = mkdtempSync(join(os.tmpdir(), "rln-bench-"));
try {
  const out = join(dir, "runs", "r.json"); // a directory that does not exist yet: --out creates it
  const r = await run(["--members", "2", "--prove", "2", "--verify", "3", "--out", out]);
  assert.equal(r.status, 0, r.stderr);
  const raw = readFileSync(out, "utf8");
  const j = JSON.parse(raw);
  assert.deepEqual(JSON.parse(r.stdout), j, "stdout and --out carry the same result");
  assert.equal(j.bench, "rln/prove-verify");
  assert.equal(j.members, 2);
  assert.equal(j.prove.warm.n, 2);
  assert.equal(j.verify.warm.n, 3);
  assert.ok(j.prove.coldMs > 0 && j.prove.warm.p50 > 0 && j.verify.coldMs > 0 && j.verify.warm.p50 > 0);
  assert.equal(j.artifact, expectArtifact, "artifact is the id the client proves with");
  assert.match(j.artifact, /^rln-[0-9a-f]+$/);
  assert.equal(j.git.commit, expectCommit, "commit is this checkout's HEAD (null only when git is unavailable)");
  assert.equal(j.kSlots, rln.K_SLOTS);
  assert.equal(j.command, "node bench/rln/prove-verify.mjs --members 2 --prove 2 --verify 3 --out r.json");
  assert.equal(j.label, DEFAULT_LABEL, "an unlabelled run is not named after the machine");
  assert.deepEqual(j.host, hostClass());
  assert.ok(!raw.includes(dir), "no local path in the result");
  // No hostname anywhere: label, command and host are pinned exactly above, and the result has
  // no other machine-supplied field. (A substring scan for os.hostname() is not used: a host
  // named "node" or "linux" would false-fail it.)
  assert.deepEqual(Object.keys(j).sort(), ["artifact", "bench", "command", "git", "host", "kSlots", "label", "members", "node", "notes", "prove", "ts", "verify"]);
  const m = await run(["--markdown", out]);
  assert.equal(m.status, 0, m.stderr);
  assert.match(m.stdout, new RegExp(`\\| ${DEFAULT_LABEL} \\|`));
  console.log("  ok   real run: proofs made and verified, commit and artifact stamped, no host identity, markdown renders");
} finally { rmSync(dir, { recursive: true, force: true }); }

console.log("PASS prove-verify");
