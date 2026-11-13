// Offline check that a direct-SDK ShadeTreeClient reads the network record's session-ticket switch
// the same way on its FIRST construction as on any later one (#250, the JavaScript side). No Tor,
// no network, no proofs: the constructor only resolves configuration.
//
// The constructor applies the named record to process.env (applyClientNetworkEnv). It used to read
// SHADE_TREE_SESSION_TICKETS before that, so in a fresh process the first
// `new ShadeTreeClient({ onion, network })` had sessionTickets false while a second identical client
// had it true. Each case below starts from an environment with no SHADE_TREE_* variable.
//
//   node packages/node/client/pinned-network-record.selftest.mjs
//
// Exit 0 = all cases green; nonzero = a case failed (prints which).

import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ShadeTreeClient } from "./shade-tree-client.mjs";
import { networkEnvDefaults } from "../lib/network-record.mjs";

let failures = 0;
async function test(name, fn) {
  try { await fn(); console.log("  PASS  " + name); }
  catch (e) { failures++; console.log("  FAIL  " + name + "  ::  " + ((e && e.message) || e)); }
}

function freshEnv() {
  for (const k of Object.keys(process.env)) if (k.startsWith("SHADE_TREE_") || k.startsWith("SHADENET_")) delete process.env[k];
}

const PIN = "d".repeat(56) + ".onion";
const slotStateDir = mkdtempSync(join(tmpdir(), "shade-tree-pinned-record-"));
const loadGroupFn = async () => ({ group: null, root: 0n, count: 0, source: "members.json" });
const make = (opts) => new ShadeTreeClient({ secret: "0x01", slotStateDir, loadGroupFn, ...opts });

// What the committed record says, so the test follows the record rather than hard-coding it.
const recordTickets = networkEnvDefaults("sepolia").SHADE_TREE_SESSION_TICKETS === "1";

console.log("pinned client + network record (direct SDK, fresh environment per case):");

try {
  await test("the committed sepolia record turns session tickets on (precondition for the cases below)", () => {
    assert.equal(recordTickets, true, "network/sepolia sessionTickets");
  });

  await test("first pinned client with { network } takes the record's session-ticket switch", () => {
    freshEnv();
    const c = make({ onion: PIN, network: "sepolia" });
    assert.equal(process.env.SHADE_TREE_SESSION_TICKETS, "1", "record applied to the env");
    assert.equal(c.sessionTickets, recordTickets, "instance matches the record on first construction");
    assert.equal(c.ratePolicy?.epochSeconds, Number(networkEnvDefaults("sepolia").SHADE_TREE_EPOCH_SECONDS), "same construction also took the record epoch");
  });

  await test("construction order does not matter: two identical clients agree", () => {
    freshEnv();
    const a = make({ onion: PIN, network: "sepolia" });
    const b = make({ onion: PIN, network: "sepolia" });
    assert.equal(a.sessionTickets, b.sessionTickets);
    assert.equal(a.sessionTickets, recordTickets);
  });

  await test("explicit { sessionTickets: false } beats the record", () => {
    freshEnv();
    const c = make({ onion: PIN, network: "sepolia", sessionTickets: false });
    assert.equal(c.sessionTickets, false);
  });

  await test("explicit SHADE_TREE_SESSION_TICKETS=0 beats the record", () => {
    freshEnv();
    process.env.SHADE_TREE_SESSION_TICKETS = "0";
    const c = make({ onion: PIN, network: "sepolia" });
    assert.equal(process.env.SHADE_TREE_SESSION_TICKETS, "0", "record did not overwrite the explicit value");
    assert.equal(c.sessionTickets, false);
  });

  await test("explicit { sessionTickets: true } with a pin and no network stays on", () => {
    freshEnv();
    const c = make({ onion: PIN, sessionTickets: true });
    assert.equal(c.sessionTickets, true);
  });

  await test("a pin without a network takes nothing from the record: tickets stay off", () => {
    freshEnv();
    const c = make({ onion: PIN });
    assert.equal(process.env.SHADE_TREE_SESSION_TICKETS, undefined);
    assert.equal(c.sessionTickets, false);
    assert.equal(c.ratePolicy, null, "no record rate policy behind a bare pin");
  });

  await test("zero-config client (bundled record, no pin) also takes the switch on first construction", () => {
    freshEnv();
    const a = make({});
    const b = make({});
    assert.equal(a.sessionTickets, recordTickets, "first zero-config client");
    assert.equal(b.sessionTickets, a.sessionTickets, "second zero-config client agrees");
  });

  await test("pinned client with a record still keeps auto leaf discovery and the default tier path", () => {
    freshEnv();
    const c = make({ onion: PIN, network: "sepolia" });
    assert.equal(c.leafSourcePin, "auto");
    assert.equal(process.env.SHADE_TREE_LIMIT, undefined, "record default tier not imposed behind a pin");
  });
} finally {
  rmSync(slotStateDir, { recursive: true, force: true });
}

console.log("");
if (failures) {
  console.log(`SELFTEST FAILED: ${failures} failing case(s)`);
  process.exit(1);
}
console.log("SELFTEST PASSED: all cases green");
process.exit(0);
