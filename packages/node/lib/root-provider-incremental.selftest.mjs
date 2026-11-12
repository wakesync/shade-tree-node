// NodeRootProvider keeps the replayed RLN tree across root polls and applies only the fresh
// finalized log suffix (applyFreshSuffix), instead of rebuilding the depth-20 tree from the whole
// history on every 12 s poll. This suite pins:
//   1. incremental == full rebuild: any split of a register/remove history into poll-sized suffixes,
//      applied to a kept state, gives the same root, live map, slot count and live count as
//      reconstructGroup over the same logs (removals and re-registrations included);
//   2. adversarial suffixes (out-of-order inside the window is fine; a reorged, duplicated,
//      out-of-window, index-gapped, re-registered or counter-mismatching suffix, or unparseable
//      bytes) are REJECTED before the kept tree is touched;
//   3. the provider end to end over a fake RPC: steady polls never re-scan, a rejected suffix falls
//      back to a full counter-checked rebuild from the start block, and the root always equals the
//      oracle; a finalized block at the SAME height with a different hash (an RPC view change that
//      carries a removal) is not served from the kept tree; a hashless head falls back to the
//      contract counters; a head-read RPC error or an undecodable head drops the kept tree;
//   4. the gateway applies the snapshot its poll already read (one provider refresh per change).
//
//   node packages/node/lib/root-provider-incremental.selftest.mjs

import http from "node:http";
import { reconstructGroup, NodeRootProvider, _internals } from "./root-provider.mjs";

const { TOPIC, newReplayState, applyFreshSuffix, sortLogs, applyMemberLog } = _internals;

let failures = 0;
const ok = (cond, msg) => { if (cond) console.log(`  ok   ${msg}`); else { console.log(`  FAIL ${msg}`); failures++; } };

const word = (n) => "0x" + BigInt(n).toString(16).padStart(64, "0");
const hex = (n) => "0x" + BigInt(n).toString(16);
const CONTRACT = "0x" + "cd".repeat(20);
// StakedReputationSet register: MemberRegistered(uint256 indexed commitment, uint64 indexed index, uint256 limit)
const reg = (c, index, block, logIndex = 0) => ({ address: CONTRACT, topics: [TOPIC.registeredV4, word(c), word(index)], data: word(8), blockNumber: hex(block), logIndex: hex(logIndex) });
// PaidAccessSet insert: Inserted(uint256 indexed commitment, uint256 limit, uint256 index, uint256 root)
const ins = (c, index, block, logIndex = 0) => ({ address: CONTRACT, topics: [TOPIC.inserted, word(c)], data: "0x" + word(8).slice(2) + word(index).slice(2) + word(1).slice(2), blockNumber: hex(block), logIndex: hex(logIndex) });
const rm = (topic, c, block, logIndex = 0) => ({ address: CONTRACT, topics: [topic, word(c)], data: "0x", blockNumber: hex(block), logIndex: hex(logIndex) });

const summary = (s) => ({ root: s.active === 0 ? null : s.group.root.toString(), active: s.active, slots: s.group.members.length, live: [...s.liveIndex.entries()].sort().join(";") });
const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);
const countersOf = (logs) => { const r = reconstructGroup(logs); return { nextIndex: r.group.members.length, activeCount: r.active }; };
const stateFrom = (logs) => { const r = reconstructGroup(logs); return { group: r.group, liveIndex: r.liveIndex, active: r.active }; };

// A deterministic history: registers (staked + paid shapes), exits, withdraws, slashes, and a
// re-registration after removal. Several events share a block (logIndex order matters).
function makeHistory(seed, n) {
  let x = seed;
  const rand = () => { x = (x * 1103515245 + 12345) % 2147483648; return x / 2147483648; };
  const logs = [];
  const live = [];
  const removedEver = [];
  let next = 0;
  let block = 100;
  let c = 5000 + seed * 1000;
  for (let i = 0; i < n; i++) {
    if (rand() < 0.6) block++;
    const li = logs.filter((l) => Number(BigInt(l.blockNumber)) === block).length;
    const r = rand();
    if (live.length > 0 && r < 0.3) {
      const k = Math.floor(rand() * live.length);
      const who = live.splice(k, 1)[0];
      removedEver.push(who);
      const topic = [TOPIC.exiting, TOPIC.withdrawn, TOPIC.slashedV4, TOPIC.paidSlashed][Math.floor(rand() * 4)];
      logs.push(rm(topic, who, block, li));
    } else if (removedEver.length > 0 && r < 0.4) {
      const who = removedEver.shift(); // re-register a removed commitment: a fresh index
      live.push(who);
      logs.push(reg(who, next++, block, li));
    } else {
      const who = c++;
      live.push(who);
      logs.push(rand() < 0.5 ? reg(who, next++, block, li) : ins(who, next++, block, li));
    }
  }
  return logs;
}

function equivalence() {
  console.log("incremental suffix == full rebuild:");
  for (const seed of [1, 2, 3]) {
    const logs = makeHistory(seed, 36);
    const full = reconstructGroup(logs);
    const blocks = [...new Set(logs.map((l) => Number(BigInt(l.blockNumber))))].sort((a, b) => a - b);
    // split points: every 1..4 distinct blocks, deterministic per seed
    const state = newReplayState();
    let after = 99;
    let polls = 0;
    let removalsSeen = 0;
    let allTransitionsMatch = true;
    let allPollsMatch = true;
    for (let i = 0; i < blocks.length; ) {
      const step = 1 + ((i + seed) % 4);
      const upTo = blocks[Math.min(blocks.length - 1, i + step - 1)];
      const suffix = logs.filter((l) => { const b = Number(BigInt(l.blockNumber)); return b > after && b <= upTo; });
      const prefix = logs.filter((l) => Number(BigInt(l.blockNumber)) <= upTo);
      removalsSeen += suffix.filter((l) => l.topics[0] !== TOPIC.registeredV4 && l.topics[0] !== TOPIC.inserted).length;
      // shuffle the page: an RPC may return a window in any order
      const page = suffix.slice().reverse();
      const prevCount = logs.filter((l) => Number(BigInt(l.blockNumber)) <= after).length;
      const res = applyFreshSuffix(state, page, { after, upTo, counters: countersOf(prefix) });
      if (res.reject) { ok(false, `seed ${seed}: honest suffix rejected (${res.reject})`); return; }
      // transitions are exactly what a full replay reports for the same suffix
      const expectT = reconstructGroup(prefix, { trackFrom: prevCount }).transitions;
      if (!same(res.transitions, expectT)) allTransitionsMatch = false;
      // after EVERY poll: root, live map, slot count and live count equal the full rebuild
      if (!same(summary(state), summary(stateFrom(prefix)))) allPollsMatch = false;
      after = upTo;
      polls++;
      i += step;
    }
    ok(allPollsMatch, `seed ${seed}: after each of ${polls} polls, root, live map, slot count and live count equal reconstructGroup over the same prefix`);
    ok(same(summary(state), summary(full)), `seed ${seed}: ${logs.length} logs in ${polls} polls -> root, live map, ${full.group.members.length} slots, ${full.active} live all equal the full rebuild (${removalsSeen} removals)`);
    ok(allTransitionsMatch, `seed ${seed}: per-poll transitions equal reconstructGroup(trackFrom) on the same prefix`);
  }
  // an empty suffix is a no-op with no transitions
  {
    const logs = makeHistory(4, 10);
    const s = stateFrom(logs);
    const before = summary(s);
    const res = applyFreshSuffix(s, [], { after: 10_000, upTo: 10_005, counters: countersOf(logs) });
    ok(!res.reject && res.transitions.length === 0 && same(summary(s), before), "an empty suffix (head moved, no member events) is a no-op");
  }
  // removing everyone -> null root, like the full rebuild
  {
    const logs = [reg(1, 0, 1), reg(2, 1, 1, 1)];
    const s = stateFrom(logs);
    const suffix = [rm(TOPIC.exiting, 1, 2), rm(TOPIC.withdrawn, 2, 3)];
    const res = applyFreshSuffix(s, suffix, { after: 1, upTo: 3, counters: countersOf(logs.concat(suffix)) });
    ok(!res.reject && summary(s).root === null && res.transitions.at(-1) === null && reconstructGroup(logs.concat(suffix)).root === null, "a suffix that removes every member leaves no root (null), as the full rebuild");
  }
}

function adversarial() {
  console.log("\nadversarial suffixes are rejected before the kept tree changes:");
  const base = [reg(11, 0, 10), reg(22, 1, 11), ins(33, 2, 12)];
  const counters = (extra) => countersOf(base.concat(extra));
  const check = (name, suffix, opts = {}) => {
    const s = stateFrom(base);
    const before = summary(s);
    let res;
    try { res = applyFreshSuffix(s, suffix, { after: 12, upTo: 20, counters: opts.counters === undefined ? counters(opts.honest || []) : opts.counters }); } catch (e) { res = { threw: e.message }; }
    const rejected = !!(res.reject || res.threw);
    ok(rejected && same(summary(s), before), `${name} -> ${res.reject || (res.threw ? "throws (provider treats as reject)" : "ACCEPTED")}, tree unchanged`);
  };
  // honest out-of-order (inside the window) is accepted and equals the full rebuild
  {
    const suffix = [reg(55, 4, 15), reg(44, 3, 14), rm(TOPIC.exiting, 22, 14, 1)];
    const s = stateFrom(base);
    const res = applyFreshSuffix(s, suffix, { after: 12, upTo: 20, counters: counters(suffix) });
    ok(!res.reject && same(summary(s), summary(reconstructGroup(base.concat(suffix)))), "out-of-order logs inside the window are sorted and accepted (== full rebuild)");
  }
  check("a duplicated log (same block + logIndex twice)", [reg(44, 3, 14), reg(44, 3, 14)], { honest: [reg(44, 3, 14)] });
  check("a duplicate of an already-applied register (reorg echo)", [reg(22, 3, 14)], { counters: null });
  check("a log at or before the last applied block (stale page)", [reg(44, 3, 12, 5)], { counters: null });
  check("a log past the finalized head (RPC ignored the range)", [reg(44, 3, 21)], { counters: null });
  check("a log flagged removed:true (reorged out)", [{ ...reg(44, 3, 14), removed: true }], { counters: null });
  check("a gap: the register claims index 4, the next slot is 3", [reg(55, 4, 15)], { counters: null });
  check("a gap in the paid shape (index in data)", [ins(55, 7, 15)], { counters: null });
  check("a dropped log: counters say 5 slots, the suffix has 4", [reg(44, 3, 14)], { counters: { nextIndex: 5, activeCount: 5 } });
  check("a dropped removal: counters say 2 live, the suffix leaves 3", [], { counters: { nextIndex: 3, activeCount: 2 } });
  check("garbage topics[1] (not hex)", [{ ...reg(44, 3, 14), topics: [TOPIC.registeredV4, "zz", word(3)] }], { counters: null });
  check("garbage blockNumber", [{ ...reg(44, 3, 14), blockNumber: "nope" }], { counters: null });
  // a valid-but-later register (claims index 3 while a register of index 3 is missing before it)
  check("a register reordered ahead of the one it follows (index 4 at an earlier block than index 3)", [reg(55, 4, 13), reg(44, 3, 14)], { counters: null });
  // the apply step uses the shared fold: one log at a time, same as reconstructGroup
  {
    const s = newReplayState();
    for (const l of sortLogs(base)) applyMemberLog(s, l);
    ok(same(summary(s), summary(reconstructGroup(base))), "applyMemberLog over sorted logs == reconstructGroup (one shared fold)");
  }
}

// A fake JSON-RPC with a finalized head, eth_getLogs over a log list, and the StakedReputationSet
// counters (nextIndex / activeCount) computed from the logs up to the asked block. `lie` lets a
// test drop or add logs in what eth_getLogs returns for a given window.
function fakeRpc({ logs, head }) {
  // `fork` names the RPC's current view of the chain: the block hash is a function of (fork,
  // height), so bumping it changes the hash of an already-seen height. `failHead` makes the head
  // read error out, `badHead` returns an undecodable block number, `noHash` omits the hash.
  const state = { head, getLogs: [], methods: [], lie: null, failLogs: false, fork: 0, failHead: false, badHead: false, noHash: false };
  const upTo = (n) => logs.filter((l) => Number(BigInt(l.blockNumber)) <= n);
  const srv = http.createServer((req, res) => {
    let body = "";
    req.on("data", (d) => { body += d; });
    req.on("end", () => {
      const j = JSON.parse(body);
      state.methods.push(j.method);
      const reply = (result, error) => { res.setHeader("content-type", "application/json"); res.end(JSON.stringify(error ? { jsonrpc: "2.0", id: j.id, error } : { jsonrpc: "2.0", id: j.id, result })); };
      if (j.method === "eth_getBlockByNumber") {
        if (state.failHead) return reply(null, { code: -32000, message: "head unavailable" });
        if (state.badHead) return reply({ number: "not-a-number", hash: word(1), stateRoot: word(0) });
        const tag = j.params[0];
        const n = tag === "latest" || tag === "finalized" ? state.head : Number(BigInt(tag));
        const blk = { number: hex(n), stateRoot: word(0) };
        if (!state.noHash) blk.hash = word(BigInt(state.fork) * 1_000_000_000n + BigInt(n));
        return reply(blk);
      }
      if (j.method === "eth_getLogs") {
        const f = j.params[0];
        const from = Number(BigInt(f.fromBlock));
        const to = Number(BigInt(f.toBlock));
        state.getLogs.push([from, to]);
        if (state.failLogs) return reply(null, { code: -32000, message: "backend unavailable" });
        let hit = logs.filter((l) => { const b = Number(BigInt(l.blockNumber)); return b >= from && b <= to; });
        if (state.lie) hit = state.lie(from, to, hit);
        return reply(hit);
      }
      if (j.method === "eth_call") {
        const r = reconstructGroup(upTo(Number(BigInt(j.params[1]))));
        const sel = j.params[0].data;
        return reply(word(sel === "0xfc7e9c6f" ? r.group.members.length : r.active));
      }
      reply(null);
    });
  });
  return new Promise((resolve) => srv.listen(0, "127.0.0.1", () => resolve({ url: `http://127.0.0.1:${srv.address().port}`, close: () => srv.close(), state })));
}

async function provider() {
  console.log("\nNodeRootProvider keeps the tree across polls:");
  const saved = { SHADE_TREE_FROM_BLOCK: process.env.SHADE_TREE_FROM_BLOCK, SHADE_TREE_FROM_BLOCKS: process.env.SHADE_TREE_FROM_BLOCKS, SHADE_TREE_CONFIRMATIONS: process.env.SHADE_TREE_CONFIRMATIONS, SHADE_TREE_LOGS_CHUNK: process.env.SHADE_TREE_LOGS_CHUNK };
  process.env.SHADE_TREE_FROM_BLOCK = "0x0"; process.env.SHADE_TREE_LOGS_CHUNK = "10000"; delete process.env.SHADE_TREE_FROM_BLOCKS; delete process.env.SHADE_TREE_CONFIRMATIONS;
  const all = makeHistory(7, 40);
  const lastBlock = Number(BigInt(all.at(-1).blockNumber));
  const mid = Number(BigInt(all[20].blockNumber));
  const visible = all.filter((l) => Number(BigInt(l.blockNumber)) <= mid);
  const rpc = await fakeRpc({ logs: visible, head: mid });
  const oracle = () => reconstructGroup(visible.filter((l) => Number(BigInt(l.blockNumber)) <= rpc.state.head)).root;
  const fullScans = () => rpc.state.getLogs.filter(([from]) => from === 0).length;
  try {
    const p = NodeRootProvider({ rpcUrl: rpc.url, contract: CONTRACT, freshnessMs: 3_600_000 });
    const r1 = await p.currentRoots();
    ok(r1.roots[0] === oracle() && fullScans() === 1 && p.stats().fullRebuilds === 1, "first poll: one full scan + rebuild, the oracle root");

    // advance the head a few blocks at a time, appending the real history (registers + removals)
    let steps = 0;
    let allMatch = true;
    for (let b = mid + 1; b <= lastBlock; b += 3) {
      for (const l of all) { const n = Number(BigInt(l.blockNumber)); if (n > rpc.state.head && n <= b) visible.push(l); }
      rpc.state.head = b;
      const r = await p.currentRoots();
      if (r.roots[0] !== oracle() && !(r.roots.length === 0 && oracle() === null)) allMatch = false;
      steps++;
    }
    ok(allMatch && fullScans() === 1 && p.stats().fullRebuilds === 1 && p.stats().suffixApplies === steps, `${steps} more polls over registers + removals: root == full rebuild every time, ${p.stats().suffixApplies} suffix applies, still ONE tree rebuild`);
    const windows = rpc.state.getLogs.slice(1);
    ok(windows.every(([from, to], i) => i === 0 || from === windows[i - 1][1] + 1), "each poll fetched only (last finalized, head]");

    const callsBefore = rpc.state.methods.length;
    const rSame = await p.currentRoots();
    const sameCalls = rpc.state.methods.slice(callsBefore);
    ok(rSame.roots[0] === oracle() && sameCalls.join() === "eth_getBlockByNumber", `unchanged finalized head: only the head read, no eth_getLogs and no counter calls (${sameCalls.join(",")})`);

    // a suffix that drops a log -> counter mismatch -> full rebuild (correct root, fresh ring)
    visible.push(reg(424242, reconstructGroup(visible).group.members.length, lastBlock + 2));
    rpc.state.head = lastBlock + 2;
    rpc.state.lie = (from, to, hit) => (from > 0 ? [] : hit); // the narrow page comes back empty
    const rDrop = await p.currentRoots();
    ok(rDrop.roots[0] === oracle() && fullScans() === 2 && p.stats().fullRebuilds === 2 && /contract reports/.test(p.stats().lastRejection) && rDrop.roots.length === 1, `fresh page drops a log -> refused (${p.stats().lastRejection}) -> full rebuild, oracle root, ring reset`);

    // a reorged (removed:true) log in the fresh page -> full rebuild
    visible.push(reg(434343, reconstructGroup(visible).group.members.length, lastBlock + 4));
    rpc.state.head = lastBlock + 4;
    rpc.state.lie = (from, to, hit) => (from > 0 ? hit.concat([{ ...reg(1, 999, to), removed: true }]) : hit);
    const rReorg = await p.currentRoots();
    ok(rReorg.roots[0] === oracle() && fullScans() === 3 && /reorged/.test(p.stats().lastRejection), "fresh page carries a removed:true log -> refused -> full rebuild, oracle root");

    // a page that repeats an already-applied block -> rejected -> full rebuild
    visible.push(rm(TOPIC.exiting, 434343, lastBlock + 6));
    rpc.state.head = lastBlock + 6;
    rpc.state.lie = (from, to, hit) => (from > 0 ? visible.filter((l) => Number(BigInt(l.blockNumber)) >= from - 2 && Number(BigInt(l.blockNumber)) <= to) : hit);
    const rOld = await p.currentRoots();
    ok(rOld.roots[0] === oracle() && fullScans() === 4 && /outside the fresh window/.test(p.stats().lastRejection), "fresh page includes logs from before the window -> refused -> full rebuild, oracle root (the removal applied)");

    // an RPC error while fetching the suffix drops the kept tree: the next success is a full rebuild
    rpc.state.lie = null;
    visible.push(reg(454545, reconstructGroup(visible).group.members.length, lastBlock + 8));
    rpc.state.head = lastBlock + 8;
    rpc.state.failLogs = true;
    const rErr = await p.currentRoots(); // withCache serves the last-known-good inside the window
    rpc.state.failLogs = false;
    const rAfter = await p.currentRoots();
    ok(rErr.stale === true && rAfter.roots[0] === oracle() && fullScans() === 5, "an eth_getLogs error mid-suffix serves last-known-good, drops the kept tree, and the next read is a full rebuild");

    // SAME height, DIFFERENT finalized block hash, and that block now carries a removal (an RPC
    // pool switching to a backend with another view). The kept tree must not be served.
    {
      const victim = [...reconstructGroup(visible).liveIndex.keys()][0];
      const keptRoot = (await p.currentRoots()).roots[0];
      const scansBefore = fullScans();
      visible.push(rm(TOPIC.exiting, BigInt(victim), rpc.state.head, 7));
      rpc.state.fork = 1;
      const rFork = await p.currentRoots();
      ok(rFork.roots[0] === oracle() && rFork.roots[0] !== keptRoot && fullScans() === scansBefore + 1 && /changed hash/.test(p.stats().lastRejection) && rFork.roots.length === 1,
        `same height, changed finalized hash, a removal at that height -> refused (${p.stats().lastRejection}) -> full rebuild, oracle root, ring reset`);
      const m0 = rpc.state.methods.length;
      const rFork2 = await p.currentRoots();
      ok(rFork2.roots[0] === oracle() && rpc.state.methods.slice(m0).join() === "eth_getBlockByNumber", "the new block at that height is then kept: the next unchanged poll is the head read only");
    }

    // A head without a hash (some RPCs/proxies drop it): the same-height path falls back to the
    // contract counters instead of trusting the kept tree blindly.
    {
      rpc.state.noHash = true;
      const m0 = rpc.state.methods.length;
      const scansBefore = fullScans();
      const rNoHash = await p.currentRoots();
      ok(rNoHash.roots[0] === oracle() && rpc.state.methods.slice(m0).join() === "eth_getBlockByNumber,eth_call,eth_call" && fullScans() === scansBefore,
        "hashless head at the same height, counters agree -> kept tree, head read + 2 counter calls, no rescan");
      const victim = [...reconstructGroup(visible).liveIndex.keys()][0];
      visible.push(rm(TOPIC.withdrawn, BigInt(victim), rpc.state.head, 8));
      const rNoHash2 = await p.currentRoots();
      ok(rNoHash2.roots[0] === oracle() && fullScans() === scansBefore + 1 && /disagrees with the contract counters/.test(p.stats().lastRejection),
        "hashless head at the same height, a removal the kept tree lacks -> counters disagree -> full rebuild, oracle root");
      rpc.state.noHash = false;
      await p.currentRoots(); // re-learn the hash (changed from null: counter path again, agrees)
    }

    // A head-read RPC error: that refresh serves last-known-good, the kept tree is dropped, and
    // the next successful refresh at the SAME height is a full rebuild (not a head read only).
    {
      rpc.state.failHead = true;
      const rHeadErr = await p.currentRoots();
      rpc.state.failHead = false;
      const scansBefore = fullScans();
      const rHeadAfter = await p.currentRoots();
      ok(rHeadErr.stale === true && rHeadAfter.roots[0] === oracle() && fullScans() === scansBefore + 1,
        "a head-read RPC error serves last-known-good now, drops the kept tree, and the next successful refresh at the same height is a full rebuild");
    }

    // An undecodable head (block number not hex) is treated the same way.
    {
      rpc.state.badHead = true;
      const rBad = await p.currentRoots();
      rpc.state.badHead = false;
      const scansBefore = fullScans();
      const rBadAfter = await p.currentRoots();
      ok(rBad.stale === true && rBadAfter.roots[0] === oracle() && fullScans() === scansBefore + 1,
        "an undecodable head block serves last-known-good, drops the kept tree, and the next refresh is a full rebuild");
    }
  } finally {
    for (const [k, v] of Object.entries(saved)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
    rpc.close();
  }
}

async function gatewaySingleRead() {
  console.log("\ngateway poll applies the snapshot it already read:");
  const { initRoots, _getRecentRoots, _setRecentRoots } = await import("../gateway/gateway.mjs");
  // (a) pollOnChange hands the snapshot it read to the callback.
  {
    const snap = { roots: ["7"], observedAtBlock: 3, finalized: true, leafCount: 1 };
    let got = null;
    const stop = _internals.pollOnChange(async () => snap)((roots, error, snapshot) => { got = { roots, error, snapshot }; stop(); }, 1);
    for (let i = 0; i < 100 && !got; i++) await new Promise((s) => setTimeout(s, 2));
    ok(got && got.snapshot === snap && got.roots[0] === "7" && got.error === null, "pollOnChange passes (roots, null, snapshot) to the callback");
  }
  // (b) the gateway's callback applies that snapshot without reading the provider again.
  let reads = 0;
  let poll = null;
  const p = {
    contract: "0xA",
    currentRoots: async () => { reads++; return { roots: ["100"], observedAtBlock: reads, finalized: true, leafCount: 1 }; },
    onChange: (fn) => { poll = fn; return () => {}; },
    describe: () => ({ provider: "node", contract: "0xA" }),
  };
  _setRecentRoots([]);
  await initRoots({ contracts: [{ address: "0xA", kind: "staked" }], want: { static: false, onchain: true }, makeProvider: () => p, watchFile: () => {}, quiet: true, rpcUrl: "http://127.0.0.1:1" });
  ok(reads === 1 && _getRecentRoots().has("100"), "startup: one provider read");
  await poll(["200"], null, { roots: ["200"], observedAtBlock: 9, finalized: true, leafCount: 2 });
  ok(reads === 1 && _getRecentRoots().has("200") && !_getRecentRoots().has("100"), `a detected change is applied from the poll's snapshot (provider reads: ${reads}, was 2 before this change)`);
  // (c) a callback without a snapshot (an older provider) still refreshes by reading once.
  await poll(["100"], null);
  ok(reads === 2 && _getRecentRoots().has("100"), "no snapshot -> the callback reads the provider once, as before");
  _setRecentRoots([]);
}

equivalence();
adversarial();
await provider();
await gatewaySingleRead();
console.log(`\n${failures === 0 ? "PASS" : "FAIL"}: root-provider incremental selftest (${failures} failure${failures === 1 ? "" : "s"})`);
process.exit(failures === 0 ? 0 : 1);
