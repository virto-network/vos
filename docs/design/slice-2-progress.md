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

## Step 2.3: the actor SDK

**Done:**

- **`vos-sdk`** (`agent/sdk`, `no_std`):
  - the ABI client, one function per operation, following `vos_wire::abi`'s
    register conventions: `ecalli` on the guest target, a native host
    function elsewhere;
  - contexts: `Query` reads, `Command` adds writes, `send` and `attest`;
    nested `call` is `async` and ready when polled, since the agent runs
    the callee while the caller waits at its `ecalli`; a query may call
    only queries, which the types enforce;
  - `Table<K, V>` with an order-preserving `TableKey` encoding and scans
    that fetch rows a buffer at a time;
  - state load and save (the struct at `0x00`, written back only if its
    encoding changed);
  - the guest runtime: a bump allocator, panic as a trap, and the
    `actor_program!` and `attestable_program!` entry points.
- **`vos-sdk-macros`:** `#[actor]` gives each table field a tag from its
  name or `#[table(name = "…")]`; `#[messages]` generates a module per
  actor with a message type per handler, the dispatcher, and the schema
  bytes. Ids derive from names with BLAKE2b; 0 and collisions are compile
  errors.
- **Schema** (`vos_wire::schema`): `"VOSS" ∥ E4(len) ∥ SCALE(schema)`,
  first in the program's read-only data (the guest linker script keeps
  `.vos_schema` first), read and validated at install.
- **`vos-testkit`** (`agent/testkit`): the reference host. It runs actor
  programs on the interpreter and serves the ABI against in-memory state
  with a step overlay and one overlay per nested call, kind enforcement,
  prices, caps, roles with the calling instance as principal, cycle and
  depth limits, and attestable programs run with no host calls. It
  records instances in the order they first ran, each with the gas its
  own code used.
- **Test actors** (`agent/test-actors`, built with the guest toolchain by
  `just build-test-actors`): a counter, a ledger (a table, a role-gated
  mint, a failing transfer, scans, an attestable checksum), an actor that
  calls the ledger, and the checksum's program. Nine testkit tests run
  them: state, failure without effects, batch time and randomness, roles,
  tables and scans, attestation, install checks, nested calls with their
  principal, and a cycle.
- **Compile-fail tests** (`trybuild`): a query calling a command, a query
  handler with a command context, an attestable method with `self`, a
  handler without a receiver, and a missing `new()`.
- The codec gained signed integers, `u128`/`i128`, `()`, `String` and
  triples; its `thiserror` no longer pulls in `std` on the guest.

**Review fixes** (the testkit is 2.4's oracle):

- A nested callee that fails or is refused leaves no effects: its writes,
  sends, attests and share of the write cap are discarded; random draws
  keep counting. `vos_wire::abi` states it, with the price of an unserved
  id (an operation's, then `WHAT`) and exact role matching.
- The testkit serves precompiles as the node's machines do, and runs an
  attestable program on a bare machine that serves precompiles and
  refuses every other host call.
- `cap::SCAN` holds a row at the key and value caps, and the SDK's rows
  grow their reused buffer only up to it; a nested call's reply lands in
  one static buffer on the guest, so calls do not exhaust the 2 MiB heap,
  which allocates without freeing within an invocation.
- An undecodable table row or caller traps rather than vanishing.
- `#[messages(module = "…")]` names the generated module; the default
  keeps acronyms together (`HTTPServer` → `http_server`).

The heap size is fixed at 2 MiB for now; making it a program's choice
waits for an actor that needs more.

## Step 2.4: the default agent

**Done:**

- **`vos-agent`** (`agent/default`, a standard program built with the
  guest toolchain by `just build-agent`):
  - **refine** decodes `E(c, i, s, ↕payload, H(p))` and its `Work`: a
    batch, run input by input, or a query, which returns its outcome
    alone. Requests and messages are checked against their session or
    pair marks, as advanced earlier in the batch, and expiry; out of order
    or expired, they are refused. Admin inputs install packages (the agent
    reads the schema from the program's machine and checks every
    attestable method and role is bound; an install's record is under the
    step write cap) and set roles. Install runs unmetered: only the
    operator submits it. A step dispatches only while the refine's gas
    left (`gas`) covers its handler's limit and the agent's reserves
    (`defaults::STEP_RESERVE`, `INSTALL_RESERVE`, `FINISH_RESERVE`), and
    joins the result only if the result stays within its cap; otherwise
    it and every later input wait for the next batch. The result is
    written a step at a time (`ResultWriter`), so its size is known as it
    grows and finishing re-encodes nothing; every step fits an empty
    result (`cap::STEP_RESULT`), so a batch always makes progress;
  - each step runs its actor in an inner machine from the pool
    (`instantiate`), or on a JAM node from the loader (`historical_lookup`,
    then `machine`, `pages` and `poke`), and serves the actor ABI against a
    step overlay with one overlay per nested call, above the batch's
    committed writes and applied state (`state_read`, and `state_scan`
    for scans). A scan walks those sources in key order and stops when
    the actor's buffer is full; a cursor below the prefix starts at the
    prefix, as the node's applied rows do;
  - a refine whose host serves no applied state (`WHAT`, a JAM node until
    witnesses) traps rather than compute on empty state. A stored value
    the agent cannot read fails only the step that reads it (`TRAPPED`),
    and a session or pair mark it cannot read refuses the input with
    `UNREADABLE`, which no resend can fix, so one bad row cannot stop the
    agent;
  - attestable programs see their arguments read-only, as the testkit
    and the prover do;
  - **accumulate** fetches each input, applies each step's writes, the
    session mark and reply window, the pair mark and the outbox with pair
    sequences, and the state version, and skips a result built on another
    version.
- **`state_scan`** (`0x482`), a refine extension: applied rows under a
  prefix after a cursor, in the actor ABI's row format; `WHAT` on JAM.
- Stored values carry a format byte (`records::STORED`), since Gray Paper
  storage deletes a key written empty.
- **One heap for every program:** the SDK's size-class allocator, sized
  per program by `program_runtime!`; actors and attestable programs get
  512 KiB, since the pool prices a machine by its mapped pages, and the
  agent 64 MiB.
- The codec encodes and decodes byte sequences, and byte arrays, in one
  copy rather than byte by byte: storing 300 KB had cost an actor
  millions of instructions.
- Every program compares bytes a word at a time (`vos_sdk::mem`, exported
  as `memcmp` and `bcmp` by `program_runtime!`): compiler_builtins' byte
  loop cost about 50 gas a byte under the Gray Paper's pipeline gas
  model, and the agent compares keys on every lookup.
- A step holds at most 16 attests (`cap::ATTESTS`), as it holds 16
  messages: uncapped, one step's attests could outgrow a work result.
- A schema's duplicate ids are found by sorting, not by comparing every
  pair: installing a program with a 64 KiB schema cost the agent 38.7M
  gas, now 6.3M. Its first read costs 3.2M; the reserves are set from
  these (`the_step_reserve_covers_the_largest_install`).

**Tests** (`agent/testkit/tests/agent.rs`, on the node's refine and
accumulate hosts):

- a failed step consumes its input and discards its effects, and a later
  step sees an earlier one's writes;
- sessions refuse gaps, duplicates and expired sessions, and keep a reply
  window;
- a query that writes traps, an unserved id answers `WHAT`, and a query
  cannot run a command;
- the write and message caps fail their steps, and messages reach the
  outbox with their pair sequences;
- roles, nested calls with the calling instance's gas and principal,
  cycles, attests, and a failed callee's discarded send;
- a call that cannot get a machine (a chain of 70 instances) fails with
  `DEPTH`, as in the testkit;
- without a pool, the loader builds the machines from preimages, across
  batches;
- a refine on a host that serves no state traps, batch after batch;
- a corrupt row fails the get or scan that reads it, a corrupt session
  mark refuses its request as unreadable, and other rows still read;
- a scan sees the step's own writes from any cursor: below, at, inside
  and above the prefix, as the testkit does;
- an attestable program that writes its arguments traps on both hosts;
- swept from below a handler's limit upward, every refine's gas yields a
  valid prefix of the batch, longer as the gas grows;
- a batch of large replies stops before its result outgrows the cap, and
  the rest run in the next batch;
- **a differential test** of random multi-batch workloads against the
  testkit: every step's outcome, writes, messages, attests, per-instance
  gas and gas used, and the final state, agree (24 cases in `ci`; 150
  passed once).

**Prices.** The cost test (`every_operation_pays_for_its_serving`)
measures what serving each operation costs the agent, at a handler's
limit and after the writes that make the overlays largest (a step's own,
and eight steps' worth committed before it in the batch) or through 61
call frames. It fails unless every charge leaves a fifth spare. The measured costs are recorded beside
the prices in `abi.rs`.

| Operation | Agent's cost (gas) | Price |
|---|---|---|
| unserved id, register operations | 1,170–1,530 | 2,000 |
| `random` (32 bytes) | 4,400 | 6,000 + bytes |
| `caller` | 5,050 | 6,000 + bytes |
| `log` | 2,740 | 4,000 + bytes |
| `send` | 3,070 | 4,000 |
| `get` | 7,500–14,300 | 20,000 |
| `scan` | 40,000–44,100 | 60,000 |
| `put`, `delete` | 12,000–44,450 | 64,000 |
| `call`, `attest` (a machine from the pool) | 27,500–39,400 | 60,000 |
| per byte copied | about 18 | 24 |

Measuring at the cap found what measuring on near-empty overlays had
hidden:

- a scan merged every overlay row in its range before emitting any:
  after 2,000 writes one scan cost the agent 44.7M gas against its 16,000
  charge, enough for one handler to exhaust a refine. It now costs what
  it returns;
- `memcmp` as a byte loop made a 1 KiB key cost 72 gas a byte;
- a handler declaring 100M gas ran with 203,256: the translator dropped
  the constant a `min` compared against and then read (fixed and pinned
  in the compiler's differential test).

Earlier, measuring found three costs the agent did not need: zero-filling
a 66 KiB buffer per applied-state scan, decoding an instance's installed
record on every nested call, and a 2 MiB actor heap that the pool priced
at 62,000 gas per machine. The generic map and vector work of the
overlays still dominates `put`; making them cheaper is open work, as is
the heap's large-block list, which neither splits nor coalesces.

Also open:

- a method's schema entry is found by a linear search, three times a
  step: about 150,000 gas for a program of a thousand methods, within the
  step reserve but unpriced;
- the agent decodes each applied page whole before merging it; at 4 KiB
  pages that is cheap, and a larger page should decode lazily;
- an unreadable pair mark wedges that pair, since its sender cannot open
  a new one: the node's admin surface needs a way to reset a pair's mark
  (`Admin::ResetPair`).

At these prices the default handler gas (10M) buys about 150 writes or
500 reads, and a transfer (two gets, two puts) about 170,000 gas in
charges: about 60 transfers per default handler, before the actor's own
code.

## Step 2.5: the node host

**Done:**

- **`vos_node::Node`** (`node/host/src/node.rs`) runs every agent on one
  process: each agent's leader loop on one async thread (smol), PVM work
  on a fixed pool of executor threads (`executor.rs`), and commits on one
  storage thread (`storage.rs`), which writes everything queued in one
  batch and syncs once.
- **A batch, per agent, in order:** the leader takes queued inputs (256,
  or 1 MiB of arguments, lingering 2 ms only when it found the queue
  empty); refine and accumulate run on executors against one snapshot
  (`pvm.rs`), accumulate reading back its own writes; one commit appends
  the work result as log entry `applied + 1` and applies the writes; only
  then does the leader answer requests, requeue what the result did not
  cover, deliver the outbox and acknowledge applied messages.
- **Acknowledgements are agent inputs**, `Input::Ack { to, sequence }`,
  so only accumulate writes agent state: unsequenced, never refused, and
  applied monotonically, clamped to what was sent and to `ACK_LIMIT`
  entries a step; the node acks again while the mark trails.
- **Exactly once:** a message at or below its pair mark is a duplicate,
  dropped and acknowledged with the mark, before batching or when refine
  refuses it; above the mark a refusal is a gap, dropped unacknowledged.
  On start, each agent's outbox is delivered above its ack mark, and the
  node checks each agent's applied index against its state version.
- **A failing batch** commits nothing. If the agent program failed it, the
  batch returns to the queue at half its length until it passes or one
  input fails alone: a request answers `Failed` (not consumed: the client
  resends the same sequence), a message or ack is reported and dropped.
  If the node failed it (a read, a backend, an executor's panic, which the
  executor catches), the batch returns whole and the leader backs off. A
  failed commit stops the node, since fjall then refuses every commit; an
  accumulate that skips the result (the agent's version is not its
  leader's) stops that agent; a leader that panics stops its agent only.
  A stopped agent drops its queue, whose callers see `Stopped`.
- **Admission:** 1,024 queued client requests per agent, then busy;
  messages and acks are not capped.
- **Queries** run on an executor with the pool and a fresh snapshot, with
  the last applied batch's time and seed, and never enter the log.
- **Programs** are committed to `programs` and pooled before an install
  is queued; the pool is refilled from `programs` on start, and refine's
  `historical_lookup` reads them.
- The store gained the node's agent registry (under an id no agent gets)
  and a listing of programs.
- Test hooks (`vos_node::Hooks`): hold commits, fail a commit, stop a
  leader between its commit and its sends, fail a refine or panic in its
  executor job.

**Tests** (`node/host/tests/node.rs`, on the default agent and the
counter actor):

- calls apply and survive a restart; a query sees applied state and
  leaves the log unchanged; an unknown agent is refused;
- no reply while its commit is held; a full queue answers busy;
- a failing refine isolates its input, which fails alone while the rest
  apply (the dropped request leaves its session a gap);
- a panic on an executor retries the batch whole, as one batch, and drops
  nothing;
- a failed commit stops the node: every call answers `Stopped`, nothing of
  the batch applies, and a restart goes on;
- two agents exchange messages, and acks clear the sender's outbox;
- exactly once, each across a stop and a restart: a stop before delivery
  (recovery delivers), a stop before the target's ack (redelivery is a
  duplicate, acknowledged, applied once), redelivery interleaved with new
  sends (each applied once, in order), and a gap (refused, unacknowledged,
  applied once filled).

The suite passed 10 sequential runs and 16 runs at 8-way concurrency.

**Open:**

- a target unknown or stopped when a sender recovers is skipped until the
  sender next sends to it or the node restarts; slice 3's resend timer
  closes this;
- a message that fails the agent program alone is dropped, so every later
  message on its pair is a gap: like an unreadable mark, it needs an
  operator's `Admin::ResetPair`;
- messages are not capped at their target: each sender's outbox bounds
  what it sends, not what a target receives (slice 3's per-pair window).
