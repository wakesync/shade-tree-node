// Session init after a slow dial (ADR 0011): the JS client proves a session init BEFORE it dials,
// and a dial through Tor retries can take minutes (4 attempts x 120 s plus 3 s pauses). The node
// accepts the proof's external nullifier only for its current or previous epoch
// (verifySessionEnvelope), so an init that arrives two epochs late is refused
// `stale-external-nullifier` and the request fails. The client now checks the proof's epoch after
// the dial and before the write, and proves again (new slot, new nonce, same SOCKS credential)
// when it would be stale.
//
// No Tor, no sockets, no Groth16. A fake wall clock drives the client (`now`), the slot pool and a
// fake node. A fake SOCKS dialer advances that clock by a scripted dial time, and the fake node
// applies the exact epoch rule of verifySessionEnvelope at the moment the envelope arrives.
//
//   node packages/node/client/session-init-stale.selftest.mjs
//
// Exit 0 = every case held; nonzero = a check failed (prints which).

import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

// The live network's epoch. Set before the client reads it.
process.env.SHADE_TREE_EPOCH_SECONDS = "60";
const EPOCH_MS = 60_000;

const {
  ShadeTreeClient,
  ShadeTreeSessionInitStaleError,
  SESSION_INIT_TRANSIT_MARGIN_MS,
  SESSION_INIT_MAX_REPROVES,
  sessionInitFresh,
  sessionInitArrivalEpoch,
} = await import("./shade-tree-client.mjs");
const { currentEpoch } = await import("../lib/rln.mjs");
const { policyEcho, SESSION_SIGNAL_PREFIX } = await import("../lib/session-tickets.mjs");

let failures = 0;
async function test(name, fn) {
  try { await fn(); console.log("  PASS  " + name); }
  catch (error) { failures += 1; console.log("  FAIL  " + name + " :: " + (error?.stack || error)); }
}

const work = mkdtempSync(join(tmpdir(), "shade-tree-session-stale-"));
let stateId = 0;
const ONION = "a".repeat(56);
// An epoch boundary far from 0 so epoch arithmetic is not trivially small.
const E0 = 29_000_000n;
const epochStart = (e) => Number(e) * EPOCH_MS;

// One scenario: `proveMs` per proof (array, last value repeats), `dials` a list of SOCKS attempts
// in order ({ ms, fail }), `transitMs` how long the envelope takes to reach the node after write.
function harness({ startMs, proveMs = [31_000], dials, transitMs = 0, dialAttempts = 1, limit = 8 }) {
  let clock = startMs;
  const now = () => clock;
  const proofs = [];      // { epoch, slot, signal, at }
  const dialLog = [];     // { at, userId, ok }
  const written = [];     // { kind, env, at, arrival }
  const events = [];
  const sockets = [];
  let dialIndex = 0;

  const prove = async (_secret, epoch, slot, signal, opts = {}) => {
    const session = String(signal).startsWith(SESSION_SIGNAL_PREFIX);
    if (session) {
      // The background warm proof of the slot pool costs no fake time and is not counted.
      clock += proveMs[Math.min(proofs.length, proveMs.length - 1)];
      proofs.push({ epoch: BigInt(epoch), slot, signal, at: clock });
    }
    return {
      proof: { epoch: String(epoch), rlnIdentifier: "1", snarkProof: { publicSignals: { x: signal, externalNullifier: `ext-${epoch}` }, proof: {} } },
      nullifier: `null-${epoch}-${slot}`,
      externalNullifier: `ext-${epoch}`,
      share: { x: signal, y: "1" },
      artifact: opts.artifact,
    };
  };

  class NodeSocket extends EventEmitter {
    constructor() { super(); this.destroyed = false; this.closed = false; this.readableEnded = false; this.wrote = false; }
    setNoDelay() {}
    write(data, cb) {
      this.wrote = true;
      const env = JSON.parse(String(data));
      const arrival = clock + transitMs;
      const kind = env.ticket ? "ticket" : env.session ? "init" : "v4";
      written.push({ kind, env, at: clock, arrival });
      queueMicrotask(() => {
        cb?.();
        let ack;
        if (kind === "init") {
          // verifySessionEnvelope check 1: current or previous epoch, at the node's clock.
          const nodeNow = currentEpoch(arrival);
          const fresh = [nodeNow, nodeNow - 1n].some((e) => `ext-${e}` === env.externalNullifier);
          ack = fresh
            ? { ok: true, session: { ticketBookDigest: env.session.ticketBookDigest, policy: policyEcho(env.session.class) } }
            : { ok: false, err: "stale-external-nullifier" };
        } else {
          ack = { ok: true };
        }
        this.emit("data", Buffer.from(JSON.stringify(ack) + "\n"));
      });
      return true;
    }
    end(cb) { cb?.(); }
    destroy() { if (!this.destroyed) { this.destroyed = true; this.closed = true; queueMicrotask(() => this.emit("close")); } return this; }
  }

  const socksClient = {
    async createConnection({ proxy, destination }) {
      assert.equal(destination.host, ONION + ".onion");
      // Ticket spends after the book opens are fast: script only the init dials.
      const step = dials[dialIndex] ?? { ms: 500 };
      dialIndex += 1;
      clock += step.ms;
      dialLog.push({ at: clock, userId: proxy.userId || null, ok: !step.fail });
      if (step.fail) throw new Error("Socks5 proxy rejected connection - TTLExpired");
      const socket = new NodeSocket();
      sockets.push(socket);
      return { socket };
    },
  };

  const client = new ShadeTreeClient({
    secret: "test-secret",
    onion: ONION,
    sessionTickets: true,
    socksClient,
    dialAttempts,
    limit,
    artifacts: ["test-artifact"],
    gatewayArtifacts: ["test-artifact"],
    loadGroupFn: async () => ({ group: {}, source: "members.json" }),
    prove,
    now,
    slotStatePath: join(work, `slots-${stateId++}.json`),
  });
  return {
    client, proofs, dialLog, written, events, sockets, now,
    connect: () => client.connect("example.com:443", { onEvent: (e) => events.push(e) }),
  };
}

const inits = (h) => h.written.filter((w) => w.kind === "init");
const stale = (h) => h.events.filter((e) => e.phase === "session" && e.status === "stale");

console.log("session init freshness after a slow dial:");

await test("control: a 31 s proof and a 3.5 s dial open the book with one proof and no stale check firing", async () => {
  const h = harness({ startMs: epochStart(E0), dials: [{ ms: 3_500 }] });
  const t = await h.connect();
  assert.equal(h.proofs.length, 1);
  assert.equal(stale(h).length, 0);
  assert.equal(inits(h).length, 1);
  assert.equal(inits(h)[0].env.externalNullifier, `ext-${E0}`);
  assert.ok(h.events.some((e) => e.phase === "session" && e.status === "opened"));
  assert.equal(t.shadeTree.ticket, 0);
  t.destroy();
});

await test("first SOCKS attempt times out at 120 s: the stale proof is never sent, one re-proof opens the book", async () => {
  // Illustrative simulation (fake clock): a 31 s proof, then a SOCKS attempt that runs out its
  // 120 s timeout, the 3 s pause, and a second attempt that connects. Without the check the init
  // reaches the node 2 epochs late.
  const h = harness({ startMs: epochStart(E0), dialAttempts: 4, dials: [{ ms: 120_000 + 3_000, fail: true }, { ms: 3_000 }, { ms: 3_000 }] });
  const t = await h.connect();
  assert.equal(h.proofs.length, 2, "one re-proof");
  assert.equal(h.proofs[0].epoch, E0);
  assert.equal(h.proofs[1].epoch, E0 + 2n, "the re-proof takes a slot in the epoch it is made in");
  const s = stale(h);
  assert.equal(s.length, 1);
  assert.equal(s[0].proofEpoch, String(E0));
  assert.equal(s[0].reproves, 0);
  // The stale envelope never left the client: the node saw exactly one init, from the second proof.
  assert.equal(inits(h).length, 1);
  assert.equal(inits(h)[0].env.externalNullifier, `ext-${E0 + 2n}`);
  assert.notEqual(inits(h)[0].env.session.nonce, undefined);
  assert.ok(h.sockets[0].destroyed && !h.sockets[0].wrote, "the socket of the stale attempt is closed unwritten");
  // Same SOCKS credential for every dial of the book (warm circuit for the re-dial).
  assert.equal(new Set(h.dialLog.map((d) => d.userId)).size, 1);
  assert.ok(h.events.some((e) => e.phase === "session" && e.status === "opened"));
  assert.equal(t.shadeTree.slot, h.proofs[1].slot);
  assert.equal(t.shadeTree.nullifier, `null-${E0 + 2n}-${h.proofs[1].slot}`);
  t.destroy();
});

await test("no SOCKS failure, just a slow dial: a 33.3 s proof started 30 s into an epoch and a 57.2 s dial re-prove", async () => {
  // Illustrative simulation, not a replay of a measurement. It is loosely modelled on one natural
  // refusal we recorded: a prove:start to prove:done span of 33.3 s that began 32.0 s into its
  // epoch, a single SOCKS dial of 56.6 s, and 57.2 s from session start to the refusal, which
  // came 2 epochs after the epoch at prove:start. Here the fake dialer charges the whole 57.2 s
  // to the dial and the proof starts at +30 s.
  const h = harness({ startMs: epochStart(E0) + 30_000, proveMs: [33_300, 2_000], dials: [{ ms: 57_200 }, { ms: 3_000 }] });
  const t = await h.connect();
  assert.equal(h.proofs.length, 2);
  assert.equal(stale(h).length, 1);
  assert.equal(inits(h).length, 1);
  assert.equal(inits(h)[0].env.externalNullifier, `ext-${E0 + 2n}`);
  t.destroy();
});

await test("transit margin: a proof that would cross into its third epoch on the way to the node is replaced", async () => {
  // Written 5 s before the end of the previous-epoch window; the envelope needs 10 s to arrive.
  const h = harness({ startMs: epochStart(E0) + 50_000, proveMs: [30_000, 1_000], dials: [{ ms: 35_000 }, { ms: 2_000 }], transitMs: 10_000 });
  const t = await h.connect();
  // The fixture really needs the margin: the first proof (E0) would have been written 115 s into
  // E0, still E0+1 on the client clock, and reached the node 125 s in, in E0+2.
  assert.equal(sessionInitFresh(E0, epochStart(E0) + 115_000, { marginMs: 0 }), true);
  assert.equal(currentEpoch(epochStart(E0) + 125_000), E0 + 2n);
  assert.equal(stale(h).length, 1);
  assert.equal(inits(h).length, 1);
  assert.ok(h.events.some((e) => e.phase === "session" && e.status === "opened"));
  t.destroy();
});

await test("no needless re-proof: a proof one epoch old with room to spare is sent as is", async () => {
  // Proof made 59 s into E0, written 40 s into E0+1: the node accepts it (previous epoch).
  const h = harness({ startMs: epochStart(E0) + 59_000, proveMs: [500], dials: [{ ms: 40_500 }] });
  const t = await h.connect();
  assert.equal(h.proofs.length, 1);
  assert.equal(stale(h).length, 0);
  assert.equal(inits(h)[0].env.externalNullifier, `ext-${E0}`);
  assert.ok(h.events.some((e) => e.phase === "session" && e.status === "opened"));
  t.destroy();
});

await test("still stale after the re-proof: fails locally with a typed error and sends nothing", async () => {
  const h = harness({ startMs: epochStart(E0), dials: [{ ms: 200_000 }, { ms: 200_000 }, { ms: 200_000 }] });
  await assert.rejects(h.connect(), (e) => {
    assert.ok(e instanceof ShadeTreeSessionInitStaleError);
    assert.equal(e.code, "SHADE_TREE_SESSION_INIT_STALE");
    assert.equal(e.retryable, true);
    assert.equal(e.reproves, SESSION_INIT_MAX_REPROVES);
    return true;
  });
  assert.equal(h.proofs.length, 1 + SESSION_INIT_MAX_REPROVES, "bounded: no proof loop");
  assert.equal(h.written.length, 0, "no envelope reached the node");
  assert.ok(h.sockets.every((s) => s.destroyed && !s.wrote));
  assert.equal(h.client.sessionBooks().length, 0);
  assert.ok(h.events.some((e) => e.phase === "session" && e.status === "error" && e.code === "SHADE_TREE_SESSION_INIT_STALE"));
});

await test("a re-proof never reuses an (epoch, slot) pair and never reuses the session nonce", async () => {
  // h: proof done 15 s into E0, a 50 s dial, written 65 s in (E0+1, previous-epoch rule): no re-proof.
  // h2: the same with a 110 s dial, written 125 s in (E0+2): stale, one re-proof.
  const h = harness({ startMs: epochStart(E0) + 10_000, proveMs: [5_000], dials: [{ ms: 50_000 }, { ms: 1_000 }] });
  const h2 = harness({ startMs: epochStart(E0) + 10_000, proveMs: [5_000], dials: [{ ms: 110_000 }, { ms: 1_000 }] });
  const t1 = await h.connect(); t1.destroy();
  const t2 = await h2.connect(); t2.destroy();
  assert.equal(h.proofs.length, 1);
  assert.equal(h2.proofs.length, 2);
  const pairs = h2.proofs.map((p) => `${p.epoch}:${p.slot}`);
  assert.equal(new Set(pairs).size, pairs.length);
  const signals = h2.proofs.map((p) => p.signal);
  assert.notEqual(signals[0], signals[1], "a fresh nonce and ticket book: a different signal");
});

await test("the re-proof takes its slot from the epoch it is made in: a tier-1 member still opens the book", async () => {
  // The first proof spent E0's only slot. The re-proof is made in E0+1, where slot 0 is free.
  // The slot cursor is the shared durable one, so this is the same budget the v4 path draws on.
  const h = harness({ startMs: epochStart(E0) + 50_000, proveMs: [30_000, 1_000], dials: [{ ms: 35_000 }, { ms: 2_000 }], transitMs: 10_000, limit: 1 });
  const t = await h.connect();
  assert.deepEqual(h.proofs.map((p) => p.epoch), [E0, E0 + 1n]);
  assert.deepEqual(h.proofs.map((p) => p.slot), [0, 0]);
  t.destroy();
});

console.log("\nsessionInitFresh / sessionInitArrivalEpoch (pure, adversarial inputs):");

await test("matches the node rule: current and previous epoch pass, two back and one ahead fail", () => {
  const t = epochStart(E0) + 1_000; // early in E0, margin keeps arrival in E0
  assert.equal(sessionInitFresh(E0, t), true);
  assert.equal(sessionInitFresh(E0 - 1n, t), true);
  assert.equal(sessionInitFresh(E0 - 2n, t), false, "a flipped >= would accept this");
  assert.equal(sessionInitFresh(E0 + 1n, t), false, "a proof from the future is refused by the node too");
  assert.equal(sessionInitFresh(String(E0), t), true, "decimal strings are epochs too");
});

await test("the transit margin moves the boundary by exactly SESSION_INIT_TRANSIT_MARGIN_MS", () => {
  const edge = epochStart(E0 + 2n) - SESSION_INIT_TRANSIT_MARGIN_MS;
  assert.equal(sessionInitFresh(E0, edge - 1), true);
  assert.equal(sessionInitFresh(E0, edge), false);
  assert.equal(sessionInitFresh(E0, edge - 1, { marginMs: 0 }), true);
  assert.equal(sessionInitFresh(E0, epochStart(E0 + 2n) - 1, { marginMs: 0 }), true);
  assert.equal(sessionInitArrivalEpoch(edge), E0 + 2n);
});

await test("the margin is capped at a quarter epoch, so a current-epoch proof is never called stale", () => {
  // 4 s epochs: a 15 s margin would push every write two epochs ahead; the cap keeps it at 1 s.
  const eps = 4;
  const at = 1_000_000 * eps * 1000; // start of an epoch
  const ep = BigInt(1_000_000);
  assert.equal(sessionInitFresh(ep, at, { epochSeconds: eps }), true);
  assert.equal(sessionInitFresh(ep, at + eps * 1000 - 1, { epochSeconds: eps }), true);
  assert.equal(sessionInitFresh(ep, at, { epochSeconds: eps, marginMs: 10 * 60_000 }), true);
});

await test("garbage never throws and fails closed (stale => prove again, never send a doubtful proof)", () => {
  const t = epochStart(E0);
  for (const bad of [undefined, null, "", "x", "1.5", {}, [], NaN, Infinity, 1.5, Symbol("e")]) {
    let r;
    assert.doesNotThrow(() => { r = sessionInitFresh(bad, t); }, `epoch ${String(bad)}`);
    // "" and [] coerce to 0n via BigInt: epoch 0 is two epochs back from E0, so still stale.
    assert.equal(r, false, `epoch ${String(bad)}`);
  }
  for (const nowMs of [NaN, Infinity, -Infinity, undefined, "soon"]) {
    assert.equal(sessionInitFresh(E0, nowMs), false);
    assert.equal(sessionInitArrivalEpoch(nowMs), null);
  }
  for (const epochSeconds of [0, -60, NaN, "abc", null]) {
    assert.equal(sessionInitFresh(E0, t, { epochSeconds }), false);
  }
  for (const marginMs of [-5_000, NaN, "abc", undefined]) {
    assert.equal(sessionInitFresh(E0, t, { marginMs }), true, "a bad margin falls back to no margin, never to a wider window");
  }
});

await test("option values that cannot be converted never throw: Symbol epoch length and margin, null options", () => {
  const t = epochStart(E0) + 1_000;
  let r;
  assert.doesNotThrow(() => { r = sessionInitFresh(E0, t, { epochSeconds: Symbol("e") }); });
  assert.equal(r, false, "an unreadable epoch length fails closed");
  assert.doesNotThrow(() => { r = sessionInitArrivalEpoch(t, { epochSeconds: Symbol("e") }); });
  assert.equal(r, null);
  const throwing = { valueOf() { throw new Error("no"); } };
  assert.equal(sessionInitFresh(E0, t, { epochSeconds: throwing }), false);
  // A margin that cannot be read is no margin: same answer as marginMs 0, never a wider window.
  for (const marginMs of [Symbol("m"), throwing]) {
    assert.doesNotThrow(() => { r = sessionInitFresh(E0, t, { marginMs }); });
    assert.equal(r, true);
    assert.equal(sessionInitArrivalEpoch(epochStart(E0 + 1n) - 1, { marginMs }), E0, "no margin at all");
  }
  // null options means defaults, like no options.
  assert.doesNotThrow(() => { r = sessionInitFresh(E0, t, null); });
  assert.equal(r, sessionInitFresh(E0, t));
  assert.equal(sessionInitArrivalEpoch(t, null), sessionInitArrivalEpoch(t));
  const edge = epochStart(E0 + 2n) - SESSION_INIT_TRANSIT_MARGIN_MS;
  assert.equal(sessionInitFresh(E0, edge, null), false, "null options still apply the default margin");
  const getterThrows = { get epochSeconds() { throw new Error("no"); } };
  assert.doesNotThrow(() => { r = sessionInitFresh(E0, t, getterThrows); });
  assert.equal(r, false);
});

await test("a finite clock with a tiny positive epoch length (quotient overflow) fails closed instead of throwing", () => {
  let r;
  assert.doesNotThrow(() => { r = sessionInitArrivalEpoch(Number.MAX_VALUE, { epochSeconds: Number.MIN_VALUE }); });
  assert.equal(r, null, "Infinity quotient");
  assert.doesNotThrow(() => { r = sessionInitFresh(E0, Number.MAX_VALUE, { epochSeconds: Number.MIN_VALUE }); });
  assert.equal(r, false);
  // Finite but beyond the safe-integer range: the epoch would be imprecise, so it is not used.
  assert.equal(sessionInitArrivalEpoch(1e300, { epochSeconds: 60 }), null);
  assert.equal(sessionInitFresh(E0, 1e300, { epochSeconds: 60 }), false);
});

await test("a +Infinity margin is no margin at an epoch boundary, not a capped quarter-epoch margin", () => {
  // 60 s epochs. 170 s is 10 s before the start of epoch 3: with no margin the arrival epoch is 2,
  // so a proof from epoch 1 is fresh. A capped 15 s margin would push arrival into epoch 3.
  const at = 170_000;
  assert.equal(sessionInitFresh(1n, at, { epochSeconds: 60, marginMs: 0 }), true);
  assert.equal(sessionInitFresh(1n, at, { epochSeconds: 60, marginMs: Infinity }), true);
  assert.equal(sessionInitArrivalEpoch(at, { epochSeconds: 60, marginMs: Infinity }), 2n);
  assert.equal(sessionInitArrivalEpoch(at, { epochSeconds: 60, marginMs: -Infinity }), 2n);
  // The valid default margin still moves the boundary there.
  assert.equal(sessionInitFresh(1n, at, { epochSeconds: 60 }), false);
});

rmSync(work, { recursive: true, force: true });
console.log(failures ? `\nSELFTEST FAILED: ${failures} case(s)` : "\nSELFTEST PASSED: all cases green");
process.exit(failures ? 1 : 0);
