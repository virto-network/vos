# Slice 2 progress

Results for each step of `slice-2-one-node.md`.

## Step 2.1: wire types and host-call surface

**Done:**

- **`vos-wire`** (`agent/wire`, `no_std`), SCALE-coded with `pvm/codec`:
  - ids, the batch and its inputs (requests, messages, admin commands);
  - the work result: the version read, the batch time and seed, and its
    steps. A step either ran (the input it answers, `Done` or `Failed`, the
    gas per instance, writes, outgoing messages and attests) or was
    refused (an input out of order or in an expired session), which
    consumes nothing and cannot carry effects;
  - principals: clients, agents, and the calling instance of a nested
    call, so a callee never acts with its caller's caller's roles;
  - the actor ABI (`abi`): operation ids `0x500..`, the register
    convention of each, the table of operations per invocation kind,
    prices, per-step caps, result, failure and refusal codes. A nested
    call returns the callee's own error, with its writes discarded, or a
    role refusal; any other callee failure fails the step;
  - the agent's key layout (`keys`): system keys under `0x00`, instance
    state under `0x01 ∥ be32(instance)`;
  - the Gray Paper structures (`jam`): refine's arguments and accumulate's
    inputs (operands and deferred transfers);
  - the owner's defaults (W = 64, one-hour expiry, 10M handler gas, 1G
    refine gas).
- **Refine host** (`vos_pvm::refine_host`): `state_read` (`0x481`) serves
  the node's applied state through a `StateReader` and costs 1 gas per
  byte copied; `gas` (0) and `log` (100) are served; `try_run_jam` runs as a
  JAM node would, answering `WHAT` to every call it does not serve,
  `instantiate` and `state_read` included. The refine allow-list is the
  served set.
- **Accumulate host** (`vos_pvm::accumulate_host`): the accumulate entry
  (instruction counter 5) with `E(t, s, |inputs|)`, serving `fetch` (kinds
  14 and 15), `read`, `write`, `gas` and `log`; everything else answers
  `WHAT`. `read` of another service answers `NONE`.
- The Gray Paper ids (0, 2–8, 100) and the VOS extensions (`0x480`,
  `0x481`) are pinned by test.

**Captured from PolkaJam.** The SJ echo service, rerun on the PolkaJam
0.1.29 testnet (Gray Paper 0.8.0), stored three accumulate inputs: its
endowment transfer, an operand for an item that refined to
`vos:hello-jam`, and an operand for an item refined with 50 gas. They are
fixture tests in `agent/wire/tests/wire.rs`. They show that:

- an accumulate input starts with its kind: 0 for an operand, 1 for a
  deferred transfer;
- an operand is `p ∥ e ∥ a ∥ y ∥ g ∥ O(result) ∥ ↕trace`, with the gas
  limit as a natural, as the Gray Paper text has it;
- out of gas is error tag 1, with nothing after it;
- a transfer is `E4(source) ∥ E4(destination) ∥ E8(amount) ∥ memo[128] ∥
  E8(gas)`.

The PolkaJam in `~/bin/polkajam` is 0.1.27 (Gray Paper 0.7.2); captures
need the 0.1.29 nightly.

**Toolchain.** fjall 3.1 (step 2.2) needs rustc 1.90. The workspace moved
from `nightly-2025-05-09` to `nightly-2025-07-14` (1.90.0-nightly), the
newest nightly on which the pinned stwo still builds: later nightlies
dropped `array_chunks_mut`. The guests keep their own toolchain; the root
toolchain gains `rust-src` for the settlement verifier's standard-library
build. fjall is pinned exactly, since a 1.90 pre-release satisfies its
`rust-version` only by Cargo ignoring the suffix. The newer clippy's lints
(`manual_is_multiple_of`, `cloned_ref_to_slice_refs` and a few
machine-fixable ones) are fixed across the workspace.

**Compiler bugs the new toolchain exposed.** Built with the new rustc, the
settlement verifier panicked on the PVM after 4.6M instructions, while the
same ELF accepts under `qemu-riscv64`. Comparing the two runs' pc traces,
mapped through the linker's address map, found the first divergence at a
`beq zero, zero` that LLVM 21 emits. A differential property test
(`pvm/compiler/src/linker_differential.rs`) then compared random RV64IM
programs, with x0 weighted in, against a reference interpreter through
the production link path, and found the rest:

- a branch between two x0 operands, and OP and OP-32 forms with x0
  sources, read PVM register 0, which holds the return address, not zero;
  division and remainder by x0 were also folded wrongly;
- a `lui` before a direct branch target was emitted at the target, so
  every branch to it ran the `lui`: direct branch and jump targets now
  stop fusion as symbols do;
- peephole passes removed an instruction by clearing its bitmask, which
  folds its bytes into the previous instruction and changes that
  instruction's immediate length. The dead-`load_imm` pass is removed and
  the memory fusion now writes the fused instruction in the `load_imm`'s
  place.

The settlement verifier accepts again, in 10,683,638 instructions (qemu:
10,675,993 RISC-V instructions).

The pin is held between two constraints that will diverge: fjall wants a
newer rustc, the pinned stwo an older one. Moving stwo, which the privacy
work needs anyway for zero-knowledge masking, unblocks the toolchain.

## Step 2.2: storage

**Done:**

- **`vos-node`** (`node/host`) starts with its store: fjall behind a `Store`
  trait, one keyspace with four partitions:
  - `state`: instance rows, keyed by the agent (big-endian) and the
    agent-relative key;
  - `system`: system keys (first byte `0x00`), and after a `0xff` byte no
    agent key uses, the node's applied index per agent;
  - `log`: work results by (agent, index), with their term;
  - `programs`: program blobs by hash.
- **Two write operations,** `append` (log entries) and `apply` (a work
  result's writes and the applied index), grouped in one `Batch` that the
  storage thread commits for several agents at once, buffered or synced.
- **Reads** through snapshots: point reads and ordered prefix scans with a
  cursor, which never leave their agent or partition.
- **A crash test** (`node/host/tests/crash.rs`) runs a writer in a child
  process, kills it at random moments over 12 rounds, and checks each time
  that the applied index, the log and the state recover as one prefix of
  the work results applied, and that every commit reported before the kill
  survived. Its last six rounds also tear the journal's tail, truncating it
  or zeroing its last bytes as a power loss could, and recovery loses at
  most the batch the tear reached.
- **Store tests** also pin that a snapshot sees the applied index (in
  `system`) and the rows (in `state`) as of one commit while another
  thread commits, and that a later write to a key wins within a batch.

**Recovery findings:**

- fjall discards an incomplete last batch, but a complete batch whose
  checksum fails, as after a flipped bit, makes it refuse to open: a loud
  failure, not an inconsistent store, but one a node cannot recover from
  by itself. A store test pins the refusal. Whether the node log needs a journal format the node controls
  is open question 3's to settle in slice 3.
- fjall's journal decoder `debug_assert`s on a torn item header that its
  release build recovers from as an incomplete tail. The workspace builds
  fjall without debug assertions so tests recover as the node does; the
  assertion on data read from disk is worth reporting upstream.

**Notes for later steps:**

- An agent writes any system key in its own namespace, so a custom agent
  can forge its own outbox rows and session replies. That stays inside its
  trust boundary, but the node must never take another agent's effects
  from this partition on the strength of the key alone.
- The store's error type is fjall's, and the trait has no range delete or
  prefix export yet; slice 3's Raft snapshot install needs both.

**Benchmark** (`store-bench`, 64-byte values under one agent's table,
1,000 reads per snapshot, µs per row):

| | 1M rows | 10M rows | 10M, last-level filters kept |
|---|---|---|---|
| Bulk load | 1.68 | 3.09 | 3.12 |
| Read, hit, compacted | 1.56 | 2.54 | 3.43 |
| Read, hit, after 620k updates | 3.48 | 5.16 (4.98 in a second run) | 6.04 |
| Read, miss | 1.43 | 2.44 | 0.73 |
| Update, 1-row batch | 1.60 | 2.22 | 2.69 |
| Update, 1,000-row batch | 2.02 | 2.64 | 2.67 |
| Update, 1,000-row batch, synced | 2.39 | 2.86 | 2.84 |
| Scan | 0.38 | 0.28 | 0.29 |

- The **read gate passes** (≤ 5 µs warm): 2.5 µs at 10M rows, against S4's
  5.2–5.6 µs. The gain is skipping the filters of the last level, where
  most rows live, for the `state` partition: reads of actor state mostly
  hit, and a filter there only adds a lookup. Misses cost more (2.4 µs
  against 0.7), so the `system` partition, where sessions and replies are
  often absent, keeps its filters.
- **Behind fresh writes** reads meet the gate only just: 5.0–5.2 µs while
  620k updated rows sit in the memtable and level 0. Steady-state read cost
  under continuous writes depends on compaction, which slice 3's
  replicated apply path measures.
- A 2 GiB cache gave nothing (the data is 679 MiB); an in-block hash index
  and pinned filter and index blocks gave nothing measurable.
