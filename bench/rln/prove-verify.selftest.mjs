// Selftest for bench/rln/prove-verify.mjs (the RLN v4 timing benchmark, refs #63).
//
//   node bench/rln/prove-verify.selftest.mjs
//
// Three parts.
//
// 1. measure() against a stub rln module and a virtual clock. Each stub call advances the clock by
//    a scripted amount, so the test knows exactly what the cold and warm numbers must be: call 0
//    of each loop is cold and is kept out of the warm statistics, every proof is verified (and
//    only proofs this run made), a rejection anywhere, including the last proof, fails the run,
//    a --verify smaller than --prove is refused, and --members spreads the proofs over that many
//    identities. Wall-clock timings cannot check any of this, which is why it is a stub.
//
// 2. The pure pieces of the CLI: argument parsing (counts, label, stray positionals), the
//    recorded command, the hardware class, and git provenance against a throwaway repository
//    (clean, then dirty).
//
// 3. The real CLI twice with tiny counts: real Groth16 proofs through proveForSlot and
//    verifyEnvelope. Every field of the result is pinned: counts and label as given, the commit
//    and the artifact id the client actually proves with, the hardware class, and fixed notes,
//    with no local path. Timings are only checked to be positive: CI hardware varies, and
//    test/timing.selftest.mjs already owns the "verify is member-independent" property.
//
// Listed in scripts/test-all.mjs SLOW_SUITES because it makes real Groth16 proofs. No Linux
// assumption: paths come from os.tmpdir() and path.join, and git is optional (without git the
// provenance must be null, not invented).

import assert from "node:assert/strict";
import { execFileSync, spawn } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import os from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { stats, markdownRows, measure, commandLine, hostClass, isEntry, parseCli, gitProvenance, countsError, UsageError, DEFAULT_LABEL } from "./prove-verify.mjs";

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
  verify: { coldMs: 30, warm: { n: 50, p50: 12, p95: 14 } }, git: { commit: "0123456789abcdef", dirty: false }, artifact: "rln-ae43614cd02ebe95" },
{ label: "edited", host: { cpus: 1, cpu: "c", memGb: 1 }, git: { commit: "fedcba9876543210", dirty: true } }, {}]);
const mdLines = md.split("\n");
assert.equal(mdLines[0], "| label | host | prove cold | prove p50 | prove p95 | verify first after proving | verify p50 | verify p95 | n prove / verify | commit | artifact |",
  "the header says the verifier number is its first call after proving, not a cold start");
assert.match(mdLines[2], /^\| box \| 2 x cpu, 4 GB \| 900 ms \| 400 ms \| 450 ms \| 30 ms \| 12 ms \| 14 ms \| 5 \/ 50 \| 0123456789ab \| rln-ae43614cd02e \|$/);
assert.match(mdLines[3], /\| fedcba987654\+dirty \|/, "a dirty tree is marked in the commit column");
assert.match(mdLines[4], /\| - \| - \|/, "a result with missing fields renders dashes, not a crash");
console.log("  ok   markdownRows: header wording pinned, one row per result, dirty marked, tolerant of missing fields");

// ---- 1. measure() with a stub rln and a virtual clock ----------------------------------------

// Scripted durations: call 0 is deliberately far slower, so any mixing of cold into warm (or warm
// into cold) changes a number this test pins.
const PROVE_MS = [1000, 10, 30, 20];        // cold, then 3 warm
const VERIFY_MS = [500, 4, 1, 3, 2, 5];     // cold, then 5 warm
// reject: the 3rd verifier call fails. rejectProof: any verify of that proof (1-based) fails.
function stubRln({ reject = false, rejectProof = null } = {}) {
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
      t += PROVE_MS[pi++] ?? 10;
      const proof = `proof-${pi}`; made.add(proof);
      return { proof, nullifier: "n", externalNullifier: "e", share: { x: "1", y: "2" }, artifact: "rln-stub0123" };
    },
    verifyEnvelope: async (env, roots) => {
      assert.ok(roots.has("99"), "verifies against the group's root");
      verified.push(env.proof);
      t += VERIFY_MS[vi++] ?? 1;
      if (rejectProof != null && env.proof === `proof-${rejectProof}`) return { ok: false, reason: "stub-reject-tail" };
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
{
  // The proof tail. nProve 3 makes 4 proofs. With nVerify 1 only 2 verifier calls would run, so
  // proofs 3 and 4 would never be checked: that count is refused before anything is proved.
  const s = stubRln({ rejectProof: 3 });
  await assert.rejects(measure({ members: 2, nProve: 3, nVerify: 1 }, s.rln, s.now), /--verify \(1\) must be at least --prove \(3\)/);
  assert.equal(s.provers.length, 0, "a refused count proves nothing");
  // At the boundary (nVerify == nProve) the last proof is the last one verified: a bad last proof
  // must fail the run.
  const t = stubRln({ rejectProof: 4 });
  await assert.rejects(measure({ members: 2, nProve: 3, nVerify: 3 }, t.rln, t.now), /verify rejected a valid envelope: stub-reject-tail/);
  assert.deepEqual(t.verified, ["proof-1", "proof-2", "proof-3", "proof-4"], "verifier walks the proofs in order up to the last one");
  assert.equal(countsError({ nProve: 3, nVerify: 3 }), null);
  assert.equal(countsError({ nProve: 1, nVerify: 100 }), null);
  assert.match(countsError({ nProve: 4, nVerify: 3 }), /must be at least/);
  console.log("  ok   measure: --verify < --prove refused, a rejecting last proof fails the run");
}

// ---- 2. CLI parsing, recorded command, host class, git provenance ---------------------------

assert.deepEqual(parseCli(["--members", "5", "--prove", "3", "--verify", "7", "--label", "bench-box-7", "--out", "x.json"]),
  { markdown: false, label: "bench-box-7", members: 5, nProve: 3, nVerify: 7, out: "x.json" }, "every option is passed through as given");
assert.deepEqual(parseCli([]), { markdown: false, label: DEFAULT_LABEL, members: 4, nProve: 10, nVerify: 50, out: undefined },
  "defaults: unlabelled, not the machine's name");
assert.deepEqual(parseCli(["--markdown", "a.json", "b.json"]), { markdown: true, files: ["a.json", "b.json"] });
assert.throws(() => parseCli(["--prove", "1", "--verify", "1", "stray-positional"]), (e) => e instanceof UsageError && /unexpected positional argument/.test(e.message),
  "outside --markdown a positional argument is refused, not copied into the result");
assert.throws(() => parseCli(["--prove", "3", "--verify", "1"]), (e) => e instanceof UsageError && /--verify \(1\) must be at least --prove \(3\)/.test(e.message));
assert.throws(() => parseCli(["--prove", "0"]), (e) => e instanceof UsageError && /--prove/.test(e.message));
assert.throws(() => parseCli(["--members", "65"]), (e) => e instanceof UsageError && /--members/.test(e.message));
assert.throws(() => parseCli(["--no-such-flag"]), (e) => e.code === "ERR_PARSE_ARGS_UNKNOWN_OPTION");
console.log("  ok   parseCli: counts and label passed through, stray positionals and undersized --verify refused");

const sep = os.platform() === "win32" ? "\\" : "/";
const deep = ["", "someone", "private", "runs", "r.json"].join(sep);
assert.equal(commandLine(["--prove", "2", "--out", deep]), "node bench/rln/prove-verify.mjs --prove 2 --out r.json");
assert.equal(commandLine([`--out=${deep}`, "--verify", "3"]), "node bench/rln/prove-verify.mjs --out=r.json --verify 3");
assert.equal(commandLine([]), "node bench/rln/prove-verify.mjs");
const hc = hostClass();
assert.deepEqual(Object.keys(hc).sort(), ["arch", "cpu", "cpus", "memGb", "os"]);
assert.equal(hc.os, os.platform(), "os is the platform only, no kernel build string");
console.log("  ok   provenance: --out kept as a file name, host is hardware class only");

const hasGit = (() => { try { execFileSync("git", ["--version"], { stdio: "ignore" }); return true; } catch { return false; } })();
{
  const g = mkdtempSync(join(os.tmpdir(), "rln-bench-git-"));
  try {
    assert.deepEqual(gitProvenance(join(g, "missing")), { commit: null, dirty: null }, "no checkout: null, not invented");
    if (hasGit) {
      const git = (...args) => execFileSync("git", ["-c", "user.name=bench", "-c", "user.email=bench@example.invalid", "-c", "commit.gpgsign=false",
        "-c", "core.hooksPath=.no-hooks", ...args], { cwd: g, encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim();
      git("init", "-q");
      mkdirSync(join(g, "bench", "rln"), { recursive: true });
      writeFileSync(join(g, "bench", "rln", "a.mjs"), "1\n");
      writeFileSync(join(g, "other.txt"), "1\n");
      git("add", "-A");
      git("commit", "-q", "-m", "fixture");
      const head = git("rev-parse", "HEAD");
      assert.deepEqual(gitProvenance(g), { commit: head, dirty: false }, "clean tree: commit, not dirty");
      writeFileSync(join(g, "other.txt"), "2\n");
      assert.deepEqual(gitProvenance(g), { commit: head, dirty: false }, "an edit outside the measured paths is not dirty");
      writeFileSync(join(g, "bench", "rln", "a.mjs"), "2\n");
      assert.deepEqual(gitProvenance(g), { commit: head, dirty: true }, "an edit in bench/rln is dirty");
    }
    console.log(`  ok   gitProvenance: ${hasGit ? "clean, unrelated edit and dirty tree reported correctly" : "git not available, null checked only"}`);
  } finally { rmSync(g, { recursive: true, force: true }); }
}

// ---- 3. the real CLI -----------------------------------------------------------------------

const bad = await run(["--prove", "0"]);
assert.equal(bad.status, 2);
assert.match(bad.stderr, /--prove/);
const stray = await run(["--prove", "1", "--verify", "1", "stray-positional"]);
assert.equal(stray.status, 2, "a stray positional is a usage error");
assert.match(stray.stderr, /unexpected positional argument/);
assert.equal(stray.stdout, "", "no result is written when the command line is refused");
const tail = await run(["--prove", "3", "--verify", "1"]);
assert.equal(tail.status, 2, "--verify below --prove is a usage error");
assert.match(tail.stderr, /--verify \(1\) must be at least --prove \(3\)/);
assert.equal(tail.stdout, "");
console.log("  ok   CLI refuses bad counts, an undersized --verify and stray positionals with status 2");

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

const rln = await import("../../packages/node/lib/rln.mjs");
const expectArtifact = rln.clientArtifactIds()[0];
rln.cleanUp();
const NOTES = "prove cold = first call in a fresh process. verify coldMs is the first verifier call AFTER proving in that same process, not a fresh-process verifier cold start. JS path only; see bench/README.md for what this does not measure.";
const KEYS = ["artifact", "bench", "command", "git", "host", "kSlots", "label", "members", "node", "notes", "prove", "ts", "verify"];

// Every field of a real result, pinned. Nothing machine-supplied is left unchecked: the key set is
// fixed, each string field is compared exactly (so a hostname cannot hide inside one), and the
// numbers are checked for shape and count.
function checkResult(j, { label, members, nProve, nVerify, command }) {
  assert.deepEqual(Object.keys(j).sort(), KEYS);
  assert.equal(j.bench, "rln/prove-verify");
  assert.equal(j.label, label, `label is the one given (${label})`);
  assert.equal(j.members, members);
  assert.equal(j.command, command);
  assert.equal(j.prove.warm.n, nProve);
  assert.equal(j.verify.warm.n, nVerify);
  assert.ok(j.prove.coldMs > 0 && j.prove.warm.p50 > 0 && j.verify.coldMs > 0 && j.verify.warm.p50 > 0);
  assert.equal(j.artifact, expectArtifact, "artifact is the id the client proves with");
  assert.match(j.artifact, /^rln-[0-9a-f]+$/);
  assert.deepEqual(j.git, gitProvenance(ROOT), "commit and dirty flag are this checkout's");
  if (hasGit) assert.match(String(j.git.commit), /^[0-9a-f]{40}$/);
  assert.equal(j.kSlots, rln.K_SLOTS);
  assert.deepEqual(j.host, hostClass());
  assert.equal(j.node, process.version);
  assert.match(j.ts, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/);
  assert.equal(j.notes, NOTES, "notes are fixed text");
}

const dir = mkdtempSync(join(os.tmpdir(), "rln-bench-"));
try {
  const out = join(dir, "runs", "r.json"); // a directory that does not exist yet: --out creates it
  const r = await run(["--members", "2", "--prove", "2", "--verify", "3", "--out", out]);
  assert.equal(r.status, 0, r.stderr);
  const raw = readFileSync(out, "utf8");
  const j = JSON.parse(raw);
  assert.deepEqual(JSON.parse(r.stdout), j, "stdout and --out carry the same result");
  checkResult(j, { label: DEFAULT_LABEL, members: 2, nProve: 2, nVerify: 3, command: "node bench/rln/prove-verify.mjs --members 2 --prove 2 --verify 3 --out r.json" });
  assert.ok(!raw.includes(dir), "no local path in the result");

  // Different counts and an explicit label, so a CLI that ignored any of them would show here.
  const out2 = join(dir, "s.json");
  const r2 = await run(["--label", "bench-box-7", "--members", "3", "--prove", "3", "--verify", "4", `--out=${out2}`]);
  assert.equal(r2.status, 0, r2.stderr);
  const raw2 = readFileSync(out2, "utf8");
  checkResult(JSON.parse(raw2), { label: "bench-box-7", members: 3, nProve: 3, nVerify: 4,
    command: "node bench/rln/prove-verify.mjs --label bench-box-7 --members 3 --prove 3 --verify 4 --out=s.json" });
  assert.ok(!raw2.includes(dir), "no local path in the result");

  const m = await run(["--markdown", out, out2]);
  assert.equal(m.status, 0, m.stderr);
  const rows = m.stdout.trim().split("\n");
  assert.equal(rows.length, 4, "header, separator and one row per file");
  assert.match(rows[2], new RegExp(`^\\| ${DEFAULT_LABEL} \\|.*\\| 2 / 3 \\|`));
  assert.match(rows[3], /^\| bench-box-7 \|.*\| 3 \/ 4 \|/);
  console.log("  ok   real runs: counts and label as given, every field pinned, no host identity or path, markdown renders");
} finally { rmSync(dir, { recursive: true, force: true }); }

console.log("PASS prove-verify");
