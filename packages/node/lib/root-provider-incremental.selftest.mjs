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
//      contract counters, and with no counters either (empty word, reverted call, a PaidAccessSet
//      without activeCount) it replays the full history instead of trusting the kept tree; a
//      head-read RPC error or an undecodable head drops the kept tree;
//   4. the kept tree's RAW root is checked against the contract's currentRoot() after every
//      non-empty suffix and every full rebuild: a swapped-commitment register (which the counters
//      cannot see) is rejected and rebuilt; an RPC that swaps it on every page never gets its root
//      served (last-known-good, then fail closed); an empty set (leafCount 0) does not trip;
//      a missing getter skips the check; garbage answers never parse as a root;
//   5. the gateway applies the snapshot its poll already read (one provider refresh per change).
//
//   node packages/node/lib/root-provider-incremental.selftest.mjs

import http from "node:http";
import { reconstructGroup, NodeRootProvider, contractCurrentRoot, _internals } from "./root-provider.mjs";
import { newGroup } from "./rln.mjs";

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
  // `counters` shapes the eth_call answers: "ok" (both counters), "empty" (an empty word, as for
  // a contract without the function), "revert" (both calls revert), or "paid" (a PaidAccessSet:
  // nextIndex answers, activeCount reverts).
  // `root` shapes the currentRoot() answer: "ok" (the raw root over the true logs), "empty",
  // "revert" (a contract without the getter) or "fail" (a transport-style RPC error);
  // `rootCalls` counts the currentRoot() calls.
  const state = { head, getLogs: [], methods: [], lie: null, failLogs: false, fork: 0, failHead: false, badHead: false, noHash: false, counters: "ok", root: "ok", rootCalls: 0 };
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
        const reverted = { code: -32000, message: "execution reverted" };
        // currentRoot(): the contract's raw root over the TRUE logs (both set contracts have it).
        if (sel === "0xfdab463d") {
          state.rootCalls++;
          if (state.root === "empty") return reply("0x");
          if (state.root === "revert") return reply(null, reverted);
          if (state.root === "fail") return reply(null, { code: -32000, message: "backend unavailable" });
          return reply(word(r.group.root));
        }
        if (state.counters === "empty") return reply("0x");
        if (state.counters === "revert") return reply(null, reverted);
        if (state.counters === "paid" && sel !== "0xfc7e9c6f") return reply(null, reverted);
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

    // A hashless head at the same height where the counters are unavailable too: an empty word,
    // a reverted call, or a PaidAccessSet (nextIndex answers, activeCount does not). Nothing then
    // checks the kept tree, so the poll replays the full history. Before this check, such a poll
    // kept serving a root whose member had been removed at that height, with no stale flag.
    {
      for (const mode of ["empty", "revert", "paid"]) {
        // A normal hashed poll that adds a member first, so the ring holds two roots and a
        // needless ring reset on the unchanged poll below would show.
        rpc.state.noHash = false;
        rpc.state.counters = "ok";
        visible.push(reg(464646 + rpc.state.head, reconstructGroup(visible).group.members.length, rpc.state.head + 1));
        rpc.state.head += 1;
        const before = await p.currentRoots();
        rpc.state.noHash = true;
        rpc.state.counters = mode;
        const scansBefore = fullScans();
        const rNoChange = await p.currentRoots();
        ok(rNoChange.roots[0] === oracle() && fullScans() === scansBefore + 1 && before.roots.length >= 2 && JSON.stringify(rNoChange.roots) === JSON.stringify(before.roots) && !rNoChange.stale,
          `hashless head, counters unavailable (${mode}), nothing changed -> full replay (${p.stats().lastRejection}), same root, ring of ${rNoChange.roots.length} kept`);
        const keptRoot = rNoChange.roots[0];
        const victim = [...reconstructGroup(visible).liveIndex.keys()][0];
        visible.push(rm(TOPIC.exiting, BigInt(victim), rpc.state.head, 20 + ["empty", "revert", "paid"].indexOf(mode)));
        const rRemoved = await p.currentRoots();
        ok(rRemoved.roots[0] === oracle() && rRemoved.roots[0] !== keptRoot && !rRemoved.roots.includes(keptRoot) && rRemoved.leafCount === reconstructGroup(visible).active && fullScans() === scansBefore + 2 && !rRemoved.stale,
          `hashless head, counters unavailable (${mode}), a removal at that height -> full replay, oracle root, the removed member's root is no longer served (ring reset)`);
      }
      rpc.state.counters = "ok";
      rpc.state.noHash = false;
      await p.currentRoots(); // re-learn the hash
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

// The kept tree's RAW root is checked against the contract's currentRoot() after every non-empty
// suffix and after every full rebuild. Fixtures: a register with a swapped commitment (the counters
// cannot see it), an RPC that swaps it on EVERY page (the rebuild reads the same lie), an empty set
// (leafCount 0: the raw empty-tree root must match, not trip), a contract without the getter, and a
// transport error on the call.
// (bit 40 so the swapped value never collides with another small fixture commitment)
const swapCommitment = (l) => ({ ...l, topics: [l.topics[0], word(BigInt(l.topics[1]) ^ (1n << 40n)), ...l.topics.slice(2)] });
const isRegister = (l) => l.topics[0] === TOPIC.registeredV4 || l.topics[0] === TOPIC.inserted;
const swapRegisters = (hit) => hit.map((l) => (isRegister(l) ? swapCommitment(l) : l));

async function rootCheck() {
  console.log("\nthe kept tree's raw root is checked against the contract currentRoot():");
  const saved = { SHADE_TREE_FROM_BLOCK: process.env.SHADE_TREE_FROM_BLOCK, SHADE_TREE_FROM_BLOCKS: process.env.SHADE_TREE_FROM_BLOCKS, SHADE_TREE_CONFIRMATIONS: process.env.SHADE_TREE_CONFIRMATIONS, SHADE_TREE_LOGS_CHUNK: process.env.SHADE_TREE_LOGS_CHUNK, SHADE_TREE_RPC_RETRIES: process.env.SHADE_TREE_RPC_RETRIES };
  process.env.SHADE_TREE_FROM_BLOCK = "0x0"; process.env.SHADE_TREE_LOGS_CHUNK = "10000"; process.env.SHADE_TREE_RPC_RETRIES = "0";
  delete process.env.SHADE_TREE_FROM_BLOCKS; delete process.env.SHADE_TREE_CONFIRMATIONS;
  const rpcs = [];
  try {
    // contractCurrentRoot parse surface: only one 32-byte word is a root; revert/empty/garbage is
    // "no getter" (null); any other RPC error propagates.
    {
      const rpc = await fakeRpc({ logs: [reg(5, 0, 1)], head: 1 });
      rpcs.push(rpc);
      const truth = reconstructGroup([reg(5, 0, 1)]).group.root;
      ok((await contractCurrentRoot(CONTRACT, "0x1", rpc.url)) === truth, "contractCurrentRoot reads the raw 32-byte word as a bigint");
      for (const mode of ["empty", "revert"]) {
        rpc.state.root = mode;
        ok((await contractCurrentRoot(CONTRACT, "0x1", rpc.url)) === null, `contractCurrentRoot: ${mode} answer -> null (no getter, the check is skipped)`);
      }
      rpc.state.root = "fail";
      let threw = null;
      try { await contractCurrentRoot(CONTRACT, "0x1", rpc.url); } catch (e) { threw = e.message; }
      ok(threw != null && /backend unavailable/.test(threw), "contractCurrentRoot: a non-revert RPC error propagates");
      rpc.state.root = "ok";
    }
    for (const [name, answer] of [["short word", "0x12"], ["65 hex digits", "0x" + "1".repeat(65)], ["non-hex", "0x" + "z".repeat(64)], ["a number", 7], ["null", null], ["an object", { root: 1 }]]) {
      const srv = http.createServer((req, res) => { let b = ""; req.on("data", (d) => { b += d; }); req.on("end", () => { const j = JSON.parse(b); res.setHeader("content-type", "application/json"); res.end(JSON.stringify({ jsonrpc: "2.0", id: j.id, result: answer })); }); });
      await new Promise((r) => srv.listen(0, "127.0.0.1", r));
      let got;
      try { got = await contractCurrentRoot(CONTRACT, "0x1", `http://127.0.0.1:${srv.address().port}`); } catch (e) { got = `threw ${e.message}`; }
      srv.close();
      ok(got === null, `contractCurrentRoot: garbage answer (${name}) -> null, never a root`);
    }

    // A register whose commitment is swapped in the fresh page only. Index, counts and window all
    // check out, so applyFreshSuffix accepts it; the root check rejects it and the full rebuild
    // (honest pages) serves the oracle root.
    {
      const logs = [reg(101, 0, 1), reg(102, 1, 2), reg(103, 2, 3)];
      const visible = logs.slice(0, 2);
      const rpc = await fakeRpc({ logs: visible, head: 2 });
      rpcs.push(rpc);
      const oracle = () => reconstructGroup(visible.filter((l) => Number(BigInt(l.blockNumber)) <= rpc.state.head)).root;
      const p = NodeRootProvider({ rpcUrl: rpc.url, contract: CONTRACT, freshnessMs: 3_600_000 });
      const r0 = await p.currentRoots();
      ok(r0.roots[0] === oracle() && p.stats().rootChecks === 1 && p.stats().rootMismatches === 0 && rpc.state.rootCalls === 1, "first full rebuild: one currentRoot() call, it matches");

      // An empty suffix (head moved, no member event) and an unchanged head make no root call.
      rpc.state.head = 3;
      await p.currentRoots();
      await p.currentRoots();
      ok(rpc.state.rootCalls === 1, `an empty suffix and an unchanged head make no currentRoot() call (calls: ${rpc.state.rootCalls})`);

      // Control: the counter-only check (applyFreshSuffix) accepts the swapped suffix.
      {
        const kept = stateFrom(visible);
        const res = applyFreshSuffix(kept, [swapCommitment(reg(103, 2, 4))], { after: 3, upTo: 4, counters: countersOf(visible.concat([reg(103, 2, 4)])) });
        ok(!res.reject && kept.group.root !== reconstructGroup(visible.concat([reg(103, 2, 4)])).group.root, "control: the counter check alone ACCEPTS a swapped-commitment register (wrong root)");
      }

      visible.push({ ...logs[2], blockNumber: hex(4) });
      rpc.state.head = 4;
      rpc.state.lie = (from, to, hit) => (from > 0 ? swapRegisters(hit) : hit);
      const scansBefore = rpc.state.getLogs.filter(([from]) => from === 0).length;
      const r1 = await p.currentRoots();
      const st = p.stats();
      ok(r1.roots[0] === oracle() && !r1.stale && r1.roots.length === 1 && st.rootMismatches === 1 && st.fullRebuilds === 2 && /currentRoot\(\)/.test(st.lastRejection) && rpc.state.getLogs.filter(([from]) => from === 0).length === scansBefore + 1,
        `swapped commitment in the fresh page -> refused (${st.lastRejection}) -> full rebuild, oracle root, ring reset`);
      ok(rpc.state.rootCalls === 3, `that poll made two currentRoot() calls: the suffix check and the rebuild check (total ${rpc.state.rootCalls})`);
      rpc.state.lie = null;

      // One honest register: exactly one root call for the non-empty suffix, applied incrementally.
      visible.push(reg(104, 3, 5));
      rpc.state.head = 5;
      const applies = p.stats().suffixApplies;
      const r2 = await p.currentRoots();
      ok(r2.roots[0] === oracle() && p.stats().suffixApplies === applies + 1 && rpc.state.rootCalls === 4 && p.stats().rootMismatches === 1, "an honest non-empty suffix: exactly one currentRoot() call, it matches, kept tree extended");

      // A contract without the getter (empty word, reverted call): the check is skipped, not tripped.
      for (const mode of ["empty", "revert"]) {
        rpc.state.root = mode;
        visible.push(reg(105 + rpc.state.head, reconstructGroup(visible).group.members.length, rpc.state.head + 1));
        rpc.state.head += 1;
        const skips = p.stats().rootCheckSkips;
        const a = p.stats().suffixApplies;
        const r = await p.currentRoots();
        ok(r.roots[0] === oracle() && !r.stale && p.stats().rootCheckSkips === skips + 1 && p.stats().suffixApplies === a + 1 && p.stats().rootMismatches === 1, `currentRoot() ${mode} -> check skipped (no getter), suffix applied, oracle root`);
      }

      // A transport-style error on the root call propagates like any RPC error: last-known-good
      // now (stale), and the next successful refresh is a full rebuild.
      rpc.state.root = "fail";
      visible.push(reg(999, reconstructGroup(visible).group.members.length, rpc.state.head + 1));
      const lkg = oracle();
      rpc.state.head += 1;
      const rFail = await p.currentRoots();
      rpc.state.root = "ok";
      const fb = p.stats().fullRebuilds;
      const rBack = await p.currentRoots();
      ok(rFail.stale === true && rFail.roots[0] === lkg && rBack.roots[0] === oracle() && !rBack.stale && p.stats().fullRebuilds === fb + 1, "a transport error on currentRoot() serves last-known-good now and the next refresh is a full rebuild");
    }

    // An RPC that swaps the commitment on EVERY page, the full-history pages included. The rebuild
    // reads the same lie and the counters still agree, so without the rebuild check the provider
    // would serve the wrong root. With it: never the wrong root; last-known-good (the previous
    // verified current root, stale) for at most F, then no roots at all (fail closed).
    {
      const visible = [reg(201, 0, 1), reg(202, 1, 2)];
      const rpc = await fakeRpc({ logs: visible, head: 2 });
      rpcs.push(rpc);
      let clock = 1_000_000;
      const p = NodeRootProvider({ rpcUrl: rpc.url, contract: CONTRACT, freshnessMs: 60_000, now: () => clock });
      const verified = (await p.currentRoots()).roots[0];
      visible.push(reg(203, 2, 3));
      rpc.state.head = 3;
      rpc.state.lie = (from, to, hit) => swapRegisters(hit);
      // Any served root other than the last verified one and the true current one is a wrong root.
      const trueRoot = reconstructGroup(visible).root;
      const servedWrong = [];
      let staleServes = 0;
      for (let i = 0; i < 5; i++) {
        clock += 12_000;
        let r;
        try { r = await p.currentRoots(); } catch { r = { roots: [] }; }
        if (r.roots.some((x) => x !== verified && x !== trueRoot)) servedWrong.push(i);
        if (r.stale === true && r.roots.length === 1 && r.roots[0] === verified) staleServes++;
      }
      ok(servedWrong.length === 0 && staleServes === 5 && /full replay root disagrees/.test(p.stats().lastRejection),
        `every page lies: ${servedWrong.length}/5 polls served the wrong root, ${staleServes}/5 served last-known-good (${p.stats().lastRejection})`);
      clock += 12_001; // 60 001 ms after the last verified read: past F
      let failedClosed = null;
      try { const r = await p.currentRoots(); failedClosed = `served ${JSON.stringify(r.roots)}`; } catch (e) { failedClosed = e.message; }
      ok(/full replay root disagrees/.test(failedClosed), "every page lies, past F: the refresh throws (no roots served, fail closed)");
      // The same lie with no last-known-good at all (a fresh provider): fails closed at once.
      const p2 = NodeRootProvider({ rpcUrl: rpc.url, contract: CONTRACT, freshnessMs: 60_000 });
      let first = null;
      try { await p2.currentRoots(); first = "served"; } catch (e) { first = e.message; }
      ok(/full replay root disagrees/.test(first), "every page lies, no last-known-good: the first refresh throws");
      rpc.state.lie = null;
      clock += 12_000;
      const rOk = await p.currentRoots();
      ok(rOk.roots[0] === reconstructGroup(visible).root && !rOk.stale, "the RPC stops lying -> the next refresh serves the oracle root");
    }

    // Empty set (leafCount 0): every member left. The raw tree root is the depth-20 empty-tree
    // root, which is what the contract holds; the check must pass on the suffix that empties the
    // set and on a full rebuild of an empty set. roots[0] at that point is the superseded root
    // (still inside F), which is why the check never compares roots[0] or the null-mapped root.
    {
      const visible = [reg(301, 0, 1), reg(302, 1, 2)];
      const rpc = await fakeRpc({ logs: visible, head: 2 });
      rpcs.push(rpc);
      const p = NodeRootProvider({ rpcUrl: rpc.url, contract: CONTRACT, freshnessMs: 3_600_000 });
      const before = await p.currentRoots();
      visible.push(rm(TOPIC.exiting, 301, 3), rm(TOPIC.withdrawn, 302, 4));
      rpc.state.head = 4;
      let r;
      try { r = await p.currentRoots(); } catch (e) { r = { roots: [], error: e.message }; }
      const chainEmpty = await contractCurrentRoot(CONTRACT, "0x4", rpc.url);
      ok(r.leafCount === 0 && p.stats().rootMismatches === 0 && p.stats().suffixApplies === 1 && p.stats().fullRebuilds === 1 && !r.stale,
        "the suffix that empties the set (leafCount 0) passes the raw root check: no trip, no rebuild");
      ok(chainEmpty === newGroup().root && r.roots.length >= 1 && r.roots.includes(before.roots[0]) && r.roots.every((x) => BigInt(x) !== chainEmpty),
        "at leafCount 0 roots[0] is the superseded root and differs from currentRoot() (the trap a roots[0] compare falls into)");
      const p2 = NodeRootProvider({ rpcUrl: rpc.url, contract: CONTRACT, freshnessMs: 3_600_000 });
      let r2;
      try { r2 = await p2.currentRoots(); } catch (e) { r2 = { error: e.message }; }
      ok(r2.leafCount === 0 && r2.roots.length === 0 && p2.stats().rootChecks === 1 && p2.stats().rootMismatches === 0, "a full rebuild of an empty set passes the raw root check (no throw, no roots)");
    }
  } finally {
    for (const [k, v] of Object.entries(saved)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
    for (const rpc of rpcs) rpc.close();
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
await rootCheck();
await gatewaySingleRead();
console.log(`\n${failures === 0 ? "PASS" : "FAIL"}: root-provider incremental selftest (${failures} failure${failures === 1 ? "" : "s"})`);
process.exit(failures === 0 ? 0 : 1);
