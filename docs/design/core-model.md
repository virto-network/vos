# VOS core model

Draft 3 (2026-10-08). Draft 2 was reviewed by the project owner and by a
second-opinion architecture review. The run 3 spikes then measured every
performance budget; results are in `spikes.md`, cited here by spike name
(S1–S6, SJ). Tags:

- **[decided]**: confirmed by the project owner, or settled by a spike the
  owner delegated the choice to;
- **[proposed]**: recommendation awaiting review;
- **[open]**: left for a later run.

This is the model for a new core built on branch `vos-core` (from master
`d2378274`). The v2 service layer on master, the saga's agent layer and
everything specific to JAR are not ported; section 17 lists what is reused.

## Changes from draft 2

- **Measured, not estimated.** Every budget in section 14 now carries its
  spike result. All pass with the runtime work listed in section 16; most
  fail on today's code.
- **Gray Paper 0.8.0 is the only PVM version** (SJ). JAR is dropped
  entirely, including its leftovers in the compiler and prover
  (section 12).
- **Machines come from a node-side pool and cost what they touch** (S1,
  S2). Setup sized to the 4 GiB address space is removed (section 6.5).
- **No node-side fast path for actor calls** (S2): the agent path is about
  10× within budget (section 6.4).
- **One LSM storage engine** (fjall) replaces redb (S4), with one log writer
  per node and no fsync per applied entry (section 9.5).
- **A path-compressed root format** replaces the fixed-depth one (S4).
  cipher-clerk changes with it (section 9.3).
- **The vos-raft driver is rewritten** around group commit and
  replicate-on-propose; its protocol core stays (S3, section 10).
- **merkle-crdt apply becomes incremental** (S6, section 9.4).
- **Precompiles are JAM host calls** with VOS-owned ids and a software
  fallback, served in place by nodes and the prover (S5b, section 11).
- **Attestable size guideline:** whole settlement windows in chained
  segments of at most 2^16 steps (S5, section 11).

## 1. Goals

1. An **agent** is a JAM service: one PVM program with *refine* (stateless
   compute) and *accumulate* (cheap persistence). The same program runs on a
   VOS node and on JAM.
2. Writing an agent is easy: `#[agent]` on a main function, and a default
   agent for the common case.
3. **Actors** are independently compiled, distributed and licensed skills
   that agents install and invoke.
4. Proofs are opt-in: only `#[attestable]` code is proven, never the
   platform.
5. Consistency is chosen per field: ordered by the agent's log, or CRDT
   (merkle-crdt).
6. Large tables (millions of rows) are first class.
7. Performance and flexibility across very different workloads: sustained
   transaction throughput, heavy computation and storage, real-time
   collaboration. The agent is the unit of isolation and scaling.
8. Early JAM integration: agents deploy on JAM, and on-chain agents verify
   proofs from spaces (value transfer, governance, subscriptions).
9. Simplicity and performance are the deciding criteria.

## 2. Non-goals for v1

- Byzantine faults inside a space.
- Re-verifying local storage, or results produced by other nodes of the same
  space.
- Proving anything not marked `#[attestable]`.
- Replay-based durable execution.
- Encrypted private agents with key rotation.
- JAR compatibility.
- A node-side fast path for actor calls.
- Operations tooling beyond the basics until the core meets its performance
  budgets.

## 3. Principles

- **Verify only where trust changes:** client ingress, other spaces, JAM.
- **Cost follows the data touched.** No hot path costs more than the data
  it touches, and none grows with history or with the 4 GiB address space.
- **Apply, then send.** Nothing leaves an agent (replies, acknowledgements,
  messages) before the work result that produced it has been applied.
- **One mechanism per concern:** snapshots for suspension, sequence numbers
  and idempotency keys for exactly-once, one replication path per lane.
- **JAM first.** Every VOS extension degrades to something a JAM node does:
  an equivalent JAM call, or an unknown-call answer (`WHAT`) the guest
  handles with identical results.
- **Batch before anything else.** An fsync costs 0.35–0.5 ms (S3), and a
  proof has a fixed cost of about 2 s (S5). Logs, storage and proofs are
  batched.
- **Measure.** Every slice ships with performance tests against section 14.

## 4. Concepts

| Term | Meaning |
|---|---|
| Space | A trust domain: nodes run by one operator (or mutually trusting operators), plus member devices. |
| Node | A VOS process: storage, networking, ingress, PVM execution, logs, CRDT sync, optional prover. |
| Agent | Unit of deployment, state, ordering, replication and placement: an agent program, its state and its installed instances. |
| Agent program | The agent's PVM code (refine and accumulate): the default agent or a custom `#[agent]`. |
| Package | Content-addressed, vendor-signed bundle: actor and workflow programs, schema, attestable programs, metadata, license terms. |
| Actor instance | An installed stateful actor inside an agent. Its handlers run to completion within one refine. |
| Workflow | A durable orchestration without shared state. The only code that suspends. |
| Invocation | One run of a handler or workflow, in its own inner machine. |
| Step | An actor handler with its synchronous call tree, or the part of a workflow between two suspension points. Atomic. |
| Snapshot | The persisted execution state of a suspended workflow. |
| Work result | Refine's output for a batch of inputs; what the agent's log orders. |
| Lane | A field's state class: Linear (agent log) or Merge (CRDT). |
| Machine pool | The node's reusable machines, keyed by program hash and reset between uses. |
| Precompile | A pure memory transform (hash, curve operation) a guest invokes with `ecalli`; served natively by VOS nodes and proven by a dedicated chip. |

## 5. Trust model [decided]

- Nodes in a space trust each other and may crash. Raft is sufficient.
- Local disk is trusted; no integrity re-checks beyond the storage engine's
  own.
- The PVM protects nodes from agent code, and agents from actor code:
  memory isolation, gas, mediated host calls.
- Member devices are clients. They may replicate Merge lanes they are
  authorized for, never Linear state.
- Ingress authenticates clients into principals; the node hands the
  authenticated origin to the agent. No signed evidence inside guests.
- Proofs exist for parties outside the space.

## 6. Agents

### 6.1 Agent program [decided shape, proposed details]

A Gray Paper 0.8.0 standard program with two entries: refine (IC 0) and
accumulate (IC 5).

- **Refine** uses JAM's refine host calls (gas, fetch, historical_lookup,
  export, machine, peek, poke, pages, invoke, expunge, log) plus VOS
  extensions, each with a JAM fallback:
  - `state_read`: the agent's state at the refine base. On JAM, served from
    a witness carried in the work package.
  - `instantiate(code_hash)`: a machine from the node's pool (section 6.5).
    On JAM, the agent's loader builds it with `machine`, then `pages` and
    `poke`.
  - snapshot page access and dirty-page capture. On JAM: imports, exports,
    and peek-and-hash.
  - precompiles (section 11.2). On JAM, the unknown id returns `WHAT` and
    the guest computes in software.
- **Accumulate** uses JAM's accumulate host calls (read, write, transfer,
  provide, solicit, checkpoint, log) plus VOS extensions for page storage,
  Merge emission, external replies and timers.
- The node implements every host call natively. Inner machines run on the
  same interpreter or JIT as the agent.

### 6.2 The agent loop [proposed]

```rust
#[vos::agent]
async fn main(agent: &mut Agent) {
    while let Some(input) = agent.next().await {
        agent.dispatch(input).await; // default routing to the target instance
    }
}
```

- `main` runs once per refine over one batch of inputs; `next()` returns
  `None` when the batch is exhausted. Agent state between refines lives in
  storage, as on JAM.
- `.await` interleaves machines inside the refine (for example a `join` over
  several dispatches).
- Accumulate has a default (section 7.4). A custom agent may wrap it, for
  example with cheap invariant checks or commutative updates for hot keys.
- A custom agent can change scheduling and priorities, admission and rate
  limits, routing (such as an instance per key), gas allocation, the extra
  operations it offers its actors ("tools"), and accumulate policy.
- The default agent is written with the same framework and is its reference
  implementation.

### 6.3 Packages [decided: separately compiled; proposed details]

- A package holds actor and workflow program hashes, schema (methods, state
  fields and their lanes), attestable program hashes, vendor id, signature
  and license terms. Packages are content-addressed and move between spaces.
- Installing creates an actor instance with an id, the package hash and a
  state namespace.
- Upgrade drain rule: new invocations use the new program immediately.
  Running workflows finish on the program they started with, or fail at
  their deadline; the old program is released when the last one ends.
  Actor handlers never span refines, so actors need no draining.
- Licensing hook: installing may require a license, either a grant signed by
  the vendor's space or a proof from it. Per-instance gas metering comes for
  free, since every machine reports its gas. Details [open].
- Bytecode is visible to the space that runs it; the PVM does not encrypt
  programs. [open: confirm this is acceptable]

### 6.4 The actor ABI [decided: served by the agent program; operation list proposed]

Actors and workflows run as inner machines. Their host calls exit to the
agent program, which serves them; precompiles are the one exception
(section 11.2). The default ABI:

| Operation | Actor handler | Workflow |
|---|---|---|
| input, reply, log | yes | yes |
| state get/put/delete/scan on its own Linear state; CRDT operations on its own Merge fields | yes | no (no shared state) |
| `call` an instance in the same agent (runs nested, synchronous) | yes | yes |
| `send` a message to any agent (fire-and-forget) | yes | yes |
| `start` a workflow | yes | yes |
| await another agent, a timer, `checkpoint` | no | yes |
| `now`, `random` (fixed per work result) | yes | yes |
| `attest` (section 11) | yes | yes |

An actor cannot touch another instance's state; everything else is a call
or a message. Custom agents can add operations.

**No node-side fast path** [decided by S2]:

- Serving actor calls through the agent costs 2.4–3.6 µs more per transfer
  than the node serving them directly. That is about 20 agent host calls
  at about 0.12 µs each, about 7% of one core for an agent at 25k
  transfers per second.
- A fast path would duplicate the ABI in the node, with no JAM counterpart.
- Fewer, larger memory copies per call (one peek for key and value, one for
  the reply) recover part of the cost first.
- Revisit only if real workloads spend more than about 20% of refine CPU in
  the agent's serving layer.

### 6.5 Machines [decided by S1 and S2]

- **Pool.** The node keeps reusable machines keyed by program hash, for
  actors and for agent programs alike.
  - A pooled machine is reused across requests and refines. Its writable
    memory is reset to the program image between uses, through dirty pages.
  - Resetting a small actor's whole writable image costs about 1.4 µs (S2).
- **Prepared programs** (decoded, and JIT-compiled) are cached by hash.
  Preparing one costs 64–140 µs per KB (S2), so it happens at install or
  first use, never per invocation.
- **Memory structures follow mapped pages**, never the 4 GiB address space:
  - the interpreter's page table and permissions grow with mapped pages;
  - the JIT syncs permissions only for ranges that changed.

  Today's address-space-sized structures cost 0.1–1 ms per machine (S2).
- **Dirty pages are tracked natively** on both backends: about 16 µs per
  capture, against about 1 ms to scan an 8 MiB heap (S1).
- **Interpreter or JIT, per program:** for short handlers the JIT is only
  about 1.6× faster, because host calls dominate. For computation it is
  about 11× faster (S1, S2). The choice is a node policy [open].

## 7. Execution [decided]

### 7.1 Inputs

Client requests (through ingress, each with an idempotency key), messages
from other agents (with per-pair sequence numbers, section 8.4), replies to
waiting workflows, and timer firings. The node leading the agent's log
batches inputs, by count, bytes or about 1–5 ms, into one work package.
Admission control limits queued inputs per agent; excess requests are
refused with "busy" and retried by the client.

### 7.2 Refine

Runs on the leader in v1. Later any replica may refine, with read sets
validated at accumulate. The node supplies:

- the batch of inputs;
- a base: the applied state plus an overlay of the leader's own pending
  work results, so refines can pipeline;
- a timestamp and a random seed for the batch.

The agent loop dispatches inputs. Actor handlers run to completion;
workflows run until they finish, suspend or fail.

### 7.3 The work result (default agent)

- the state version it read (section 7.5), time, seed;
- the inputs consumed (idempotency keys, per-pair sequence numbers);
- per step: instances touched, Linear writes, Merge operations, outgoing
  messages, reply when done, status (done, suspended, failed), changed
  snapshot pages, gas used.

### 7.4 Accumulate (default agent)

Runs on every replica, in log order, as one storage transaction per log
entry, without fsync (section 9.5). It does the following:

- applies writes;
- stores snapshot pages and updates the workflow table;
- appends outgoing messages to the outbox with their sequence numbers;
- records consumed inputs and replies (dedup);
- schedules timers;
- applies Merge operations emitted by Linear steps (section 9.4).

Accumulate never re-executes actor code and never re-verifies history.

### 7.5 Leader changes and pipeline hygiene

- A new leader commits a no-op and applies everything before it, then
  refines from there.
- Each work result names the state version it read: the number of work
  results applied before it, counting the leader's pending ones. Entries
  that do not change refine-visible state (no-ops, acknowledgements,
  membership) do not advance the version. Accumulate applies a result only
  if that version is still current; otherwise it skips the result and its
  inputs are retried.
- Replies, acknowledgements and outbox sends happen only after the local
  accumulate applied the result, never merely because the entry committed.
- A skipped result or a term change aborts the leader's pipeline and
  flushes its overlay and its cached machines.
- Dedup is recorded when the log consumes an input, so a retry arriving
  while the original is pending is recognized.
- A client's reply comes from the applied dedup table of a replica, so it
  never depends on the leader that produced it surviving.

### 7.6 Queries

`&self` handlers run on any replica against applied state, outside the log,
and report the version they read. `#[msg(linearizable)]` first obtains
Raft's read index.

## 8. Handlers, workflows and snapshots

### 8.1 Actor handlers [decided]

```rust
#[messages]
impl Ledger {
    #[msg]
    fn transfer(&mut self, req: TransferReq) -> Result<Receipt, Error> {
        // reads and writes own state; may `call` idle instances of this
        // agent and `send` messages; never waits on anything else
    }
}
```

- A mutating handler runs to completion within the refine that starts it.
  It is a plain function: no `.await`.
- It may call instances of the same agent synchronously; the callee runs
  nested. The whole call tree commits or aborts as one step: if any part
  traps, nothing commits. A call cycle (A calls B calls A) fails.
- It may send messages to other agents and start workflows, but may not
  wait for them.
- Exceeding its gas share fails the invocation. Long work belongs in
  workflows.

Why:

- hot actors never block on remote latency, never produce snapshots and
  cannot deadlock across agents;
- one invocation per instance at a time holds without mailboxes;
- upgrades apply at the next invocation.

### 8.2 Workflows [decided]

```rust
#[workflow]
async fn transfer(wf: &mut Workflow, req: TransferReq) -> Result<Receipt, Error> {
    let verdict = wf.call_agent(RISK, Check(req.clone())).await?; // step ends, snapshot
    if !verdict.ok {
        return Err(Error::Rejected);
    }
    wf.call(LEDGER, Transfer(req)).await // same agent: runs nested in this step
}
```

- A workflow holds no shared state: only its own memory, which its
  snapshots preserve.
- A step ends at an await on another agent, a timer or a `checkpoint()`, or
  at completion. Its synchronous calls' effects, its outgoing messages and
  its snapshot commit together. If a step traps, nothing from it commits
  and the workflow fails. Earlier steps stay committed; multi-step atomicity
  uses reservation (saga) patterns.
- Every await on another agent has a deadline (default per agent,
  overridable). An expired deadline returns an error to the awaiting code,
  so stuck workflows cannot pin pages and programs forever.
- A workflow is started by a message with an idempotency key; its result is
  sent to whoever started it.
- Long computations run as workflows, preferably in their own agent so their
  gas does not delay a latency-sensitive agent's batches.

### 8.3 Snapshots [decided: the only continuation mechanism]

- A snapshot is: program hash, program counter, registers, gas, and the page
  table (page index → page). Pages are 4 KiB. Zero pages and pages
  unchanged from the program image are not stored.
- On VOS, a snapshot is taken when a workflow step ends. Gas preemption does
  not snapshot: the machine stays live on the leader and continues in the
  next refine. After failover, the step re-runs from the last snapshot; its
  effects were never committed. On JAM, machines do not survive a refine,
  so every work package ends with a snapshot (the CoreVM model).
- Changed pages ship in full in the work result, compressed with LZ4. They
  are never referenced by hash alone, because garbage collection could
  remove a matching page first. Later: XOR deltas against the previous
  version.
- Measured cost (S1):
  - a typical suspension changes 3 pages, under 1 KiB after LZ4;
  - capture with dirty tracking takes about 16 µs;
  - restoring from a pooled image takes about 0.1 ms on the JIT;
  - a long computation's checkpoints ship 136 KiB each.
- A Merkle root over the page table is computed only for JAM and for
  attestable runs.
- The leader caches live machines keyed by (workflow, last committed
  snapshot). Section 7.5's flush rules apply.
- Pages are reference-counted by snapshots; completion releases them.
- Interpreter and JIT are kept equivalent by the conformance vectors. Exact
  parity with the prover's tracer matters only for attestable programs and
  JAM.

### 8.4 Messages and exactly-once [decided]

- **Clients:** an idempotency key per request; the dedup table keeps it for
  a retention window. A duplicate gets the stored reply or joins the
  pending request.
- **Between agents:** each (sender agent, receiver agent) pair has its own
  sequence.
  - The sender's accumulate assigns numbers, and its outbox resends until
    acknowledged.
  - The receiver processes each sender's messages in order, keeps one
    high-water mark per sender permanently, and rejects gaps so the sender
    resends.
  - The receiver caches replies until the sender's acknowledgement
    watermark passes them.

  Effects are never duplicated or reordered within a pair, however long a
  sender was offline.
- Acknowledgements are batched into later log entries.

### 8.5 Time, randomness and gas

The leader assigns a timestamp and seed per work result, and code reads them
through the ABI, so attestable runs stay deterministic. On JAM, values the
builder supplies are checked against the slot. Each refine has a gas budget
split across invocations; gas per instance is recorded for metering.

## 9. State

### 9.1 Lanes per field [decided]

```rust
#[actor]
struct Channel {
    topic: String,                     // Linear
    members: Table<PrincipalId, Role>, // Linear, storage-backed
    posts: crdt::List<Post>,           // Merge
}
```

The Local (replica-only) lane is deferred until a use case needs it.

### 9.2 Handler modes [proposed]

| Handler | Runs on | May write | May read |
|---|---|---|---|
| `#[msg] fn f(&mut self)` | leader, through the log | Linear; Merge operations applied after commit | Linear; Merge as of the step |
| `#[msg] fn f(&self)` | any replica (`linearizable` flag: after a read index) | nothing | applied state |
| `#[msg(merge)]` | any replica or device, no log | Merge | Merge |
| `#[workflow]` | leader, through the log | nothing directly (calls and messages) | its own memory |

The macros generate a view per mode, so forbidden access fails to compile.

### 9.3 Tables and committed maps [decided]

- `Table<K, V>` (with map, set and vector variants) stores rows in the
  agent's keyspace: point reads and writes, ordered scans with cursors.
  Memory use follows touched rows, not table size. Point operations at 10M
  rows cost about 1.5 µs to write and about 5 µs to read (S4).
- `CommittedMap<K, V>` also yields a Merkle root and multiproofs
  (`BatchProof`) for attestable functions and JAM witnesses.
  - Only branching nodes are stored: about log₂(n) rows per key path.
  - Roots and node rows are updated only at attest or settlement
    boundaries, as sorted batches. A batch of 10,000 rewrites 7–10 node
    rows per update, against 20–24 for single updates (S4).
- **Compressed root format** [decided]:
  - a leaf hash commits the full key and the value;
  - a branch hash commits its split level and both children;
  - spines through empty levels are never hashed.

  An update costs 8–25 hashes (3–8 µs at 1M–10M keys), against 100–280
  for the fixed-depth format it replaces (S4). The format change moves
  together through `CommittedMap`, `BatchProof`, the witness math, the
  attestable kernels and cipher-clerk (`merkle.rs`, `state_root.rs`,
  `succinct.rs`, `snapshot.rs`), which the owner cleared to change.
- Hashing inside the PVM uses the hash precompile (section 11.2).
- No global state root on VOS. Agents deployed on JAM keep one.

### 9.4 Merge lane

- One merkle-crdt DAG per agent. A DAG node is a batch of CRDT operations
  with stable operation ids, its parents and its author.
- **Incremental apply** [decided by S6]. merkle-crdt's DAG and sync format
  are reused; its apply path is rewritten:
  - validate and apply only newly fetched nodes, in causal order, onto the
    current state;
  - derive which heads are subsumed from the fetched nodes;
  - apply local operations in place, with no state clone.

  Full validation and rebuild remain only for recovery and audits. Today's
  library takes 8.7 s to sync one operation onto a 1M-operation history; a
  40-line incremental prototype takes about 1.9 µs, 1.5–1.8× its cost at
  1k (S6).
- CRDT types are storage-backed. The v2 `List` rebuilds its whole order on
  every call and never drops tombstones, so it is replaced.
- **Linear-emitted chain.** Linear handlers may emit Merge operations, for
  materialized views, membership epochs and checkpoints that let devices
  bootstrap without full history.
  - Every replica applies them in accumulate, each chained to the previous
    Linear-emitted node, so all replicas build identical nodes.
  - The chain head is signed once per commit. Devices accept such nodes
    only as ancestors of a signed head.
- **Authorization rule** (starting design, to be property-tested):
  1. A membership change is a Linear step that emits an epoch node E_n.
     E_n cites the Merge heads the leader had applied at that point.
  2. Removing member A records cutoff_A: A's latest node among those heads,
     identified by A's sequence number and its CID.
  3. Every device node is signed, carries its author's sequence number (the
     previous node's plus one, linked to it) and has an epoch node in its
     causal past.
  4. A replica accepts A's node only if A was a member at that epoch, and
     the node is at or before the cutoff of every later epoch that removed
     A. Re-admission at epoch r requires E_r in the node's causal past.
  5. When an epoch arrives that invalidates operations a replica already
     applied, those operations are masked. Only the removed author's
     in-flight operations are affected.

  The decision depends only on the log and the DAG, so every replica
  agrees. It costs O(1) per operation with per-member epoch intervals.

### 9.5 Storage engine [decided: LSM; layout proposed]

One embedded LSM key-value store per node (fjall first). It holds Linear
state, Merge state and DAG, the page store, system tables (dedup and
high-water marks, outbox, workflows, timers) and the node log.

- **Why an LSM** (S4):
  - at 10M rows, random updates cost about 1.5 µs per row on fjall against
    18 µs on redb;
  - durable log appends were 1.5–2× faster;
  - redb reclaims space only after durable commits: a 0.7 GB table loaded
    without them grew to 24.6 GiB.

  Reads cost about 5 µs at 10M rows with a 1 GiB cache, against 1.6 µs on
  redb; compaction and cache tuning belong to the first storage slice.
- **Layout** [proposed]: agents share one LSM tree per data class under
  agent key prefixes. A tree per agent would multiply memtables and
  background work. A Raft snapshot exports an agent's prefix as a range and
  installs by range delete and ingestion.
- **One log writer per node** [proposed]. Every agent's Raft log goes to one
  node-level log, keyed by (agent, index).
  - The writer drains the pending writes of all agents, commits them with
    one fsync, then acknowledges each.
  - Storage I/O never runs on executor threads.
  - Writes that only move the commit index are not fsynced.

  In S3, separate stores per agent lost leaders from 64 active agents up.
- **Applied state is not fsynced per entry** [proposed]. The log is
  durable, so accumulate commits without fsync, and the node makes state
  durable periodically, recording the applied index. After a crash it
  re-applies the log from that index. Accumulate is deterministic, so
  replies sent after a non-durable apply stay correct.

## 10. Replication and placement [decided: one log per agent]

- The catalog chooses each agent's replica set. An agent with Linear state
  and more than one replica has its own Raft group (vos-raft, `no_std`).
- The log carries work results, not inputs; followers only accumulate.
- Raft snapshots of agent state bound log size. Installing one costs
  O(state), never O(history).
- Agents with only Merge state have no log.
- **New vos-raft driver** [decided by S3]. The protocol core stays, and the
  driver changes:
  - queued proposals are appended in one batch (group commit);
  - new entries go to followers at once, with one append in flight per
    peer;
  - every group runs on one shared executor; the thread-per-group `Worker`
    is dropped;
  - followers answer heartbeats without waiting for the store, and
    heartbeats are combined per node pair.

  A 165-line prototype of the first two changes passed all of vos-raft's
  tests. It reached about 25k commits/s at p99 8 ms, peaking at 44k/s,
  where the current driver managed 1.2k/s at p99 58 ms. openraft managed
  2.5k/s on the same store.
- **The heartbeat sets failure detection only.** Commits no longer wait for
  it, so idle groups heartbeat slowly or quiesce. 1,000 idle groups at a
  500 ms heartbeat cost about 1.6% of a core per node, 5 threads and about
  8 KiB per replica (S3).
- Rebalancing uses membership changes (joint consensus exists in vos-raft).

## 11. `#[attestable]` [decided intent and direction; sizes proposed]

### 11.1 Mechanism

```rust
#[attestable]
fn apply_batch(w: Witness<LedgerSlice>, batch: Batch) -> Transition { /* ... */ }
```

- Compiled into its own small program and shipped in the package. Inputs
  are private (the witness); the return value is public.
- A live call runs that same program as an inner machine, so what runs is
  what gets proven. The call records the program hash, an input commitment
  and the output.
- The witness and the record are stored with the agent's replicated state,
  so losing the producing node cannot make a settlement window unprovable.
- Proving is asynchronous (prover service). Proofs are content-addressed and
  attached to messages for other spaces or JAM.
- State binding uses app-named roots: the witness carries rows and a
  `BatchProof` against `CommittedMap` roots, and the output includes the
  roots before and after.
- Verification is a host call on VOS nodes. On JAM, an on-chain agent's
  refine runs the PVM settlement verifier (about 10M cycles), and its
  accumulate applies the public output.

### 11.2 Precompiles [decided direction; prototyped in S5b]

- A precompile is an `ecalli` host call with a VOS-owned id in
  `0x400..=0x4ff`, outside every id JAM assigns (the Gray Paper calls, and
  JIP-1 `log` at 100). BLAKE2b compression is `0x400`.
- VOS nodes serve precompiles in place, inside the machine slice, for agent
  programs and inner machines alike. It is the one call that bypasses the
  agent: a pure memory transform with no state.
- The prover attaches each call to its chip (BLAKE2b, Ristretto) inside the
  same slice. The STARK alone rejects a tampered call (S5b).
- A JAM node answers the unknown id with `WHAT`. The guest then computes in
  software with identical results; only gas differs.
- A precompile leaves every register unchanged, so `WHAT` in φ[7] can only
  come from a host that does not know the id.
- Cost per BLAKE2b compression (S5b): 66 steps plus about 35 ms and 50 MiB
  of proving, against about 4,760 steps, 0.4 s and 800 MiB when hashing in
  the PVM.

### 11.3 Cost and size guideline [proposed]

- **Prover:** about 2 s plus 80 µs per step, and 4.6 GiB plus about
  170 KiB per step (S5).
  - A slice beyond about 2^16 steps is split into chained segments, cut by
    steps and by chip calls (one 24 GiB slice holds about 400 BLAKE2b
    compressions).
  - Proofs are about 0.6–0.9 MiB.
- **Hashing dominates attestable cost.** A transfer touches two leaves:
  about 45–100 compressions under the compressed root format. That is
  about 2–4 s of proving with the precompile, and 0.2–0.5M steps without
  it.
- **Guideline:**
  - prove a whole settlement window at once, never one proof per item;
  - keep segments at most 2^16 steps;
  - target about 1M steps per window, which the precompile makes
    reachable.
- **The BLAKE2b chip's memory,** about 50 MiB per compression, is the next
  prover cost to reduce.

## 12. JAM integration [decided: early]

- Agent programs are valid JAM services from the first slice. CI runs them
  under a JAM host-call harness.
- **One PVM version for everything: Gray Paper 0.8.0** [decided by SJ]:
  - it covers the runtime, compiler, prover and agents;
  - the saga's 0.8.0 PVM layer is the base, and its interpreter and JIT
    both charge the exact 0.8.0 block gas model;
  - in SJ, a Rust service linked with our toolchain ran unchanged on a
    PolkaJam 0.1.29 testnet: refine on the guarantors, accumulate on all
    seven validators.
- **JAR is gone** [decided]. Its capability-manifest encoding, the `ecall`
  opcode paths, JAR lifecycle stubs and capability calls in the prover's
  allow-list, and JAR blob tests are removed.
- JAM mode differs from VOS mode:
  - Continuity is (root before, root after) plus witnesses, checked in
    accumulate; the version counter has no meaning there. All system
    tables (dedup, outbox, workflows) sit under the committed root.
  - Refine output is capped, so state data goes to data availability (DA)
    and accumulate only swaps roots.
  - Every work package ends with workflow snapshots exported as segments.
    DA retention is finite, so long-waiting workflows re-export their pages
    or move them to preimages.
  - Messages map to transfers, whose memos are small; payloads go through
    preimages. Each hop takes several blocks.
  - Time and randomness supplied by the builder are checked against the
    slot.
  - Precompiles fall back to software (section 11.2).
- Refine witnesses are built by simulating refine off-chain, as CoreVM's
  builder does. Actor and workflow programs are preimages.
- Deployment tooling waits until the code preimage is available at the
  package's lookup anchor; a submission made earlier refines to `BAD` (SJ).
- **First milestone:** the default agent and one actor deployed on a JAM
  node, with a workflow suspended in one work package and resumed in a
  later one. It needs the agent framework's loader:
  - it builds inner machines from standard programs (`machine` with bare
    code, then `pages` and `poke`);
  - it carries snapshot pages through export and import segments.
- **Next:** an on-chain verifier agent that accepts proofs from a space
  (Clerk settlement).

## 13. Portability [decided direction]

- **`no_std + alloc` core crates:** wire types, the agent and actor SDK, the
  PVM interpreter and inner machines, vos-raft, merkle-crdt, storage traits
  and the proof verifier.
- **`std` adapters at the edges:** the LSM engine, libp2p, the JIT and
  ingress.
- A future bare-metal light client runs Merge replicas and proof
  verification on the interpreter.
- The shared-executor Raft driver keeps vos-raft's core free of threads.

## 14. Performance budgets [decided; measured in run 3]

| Path | Budget | Measured |
|---|---|---|
| Actor invocation, refine and accumulate, one node | ≤ 50 µs | 3.3–5.3 µs per transfer with warm machines (S2) |
| Replicated agent on 3 LAN nodes, simple mutations | ≥ 20k per second per agent; p99 commit ≤ 10 ms at half load | about 25k/s at p99 8 ms with the new driver (S3) |
| Workflow snapshot capture plus restore, up to 50 KB | ≤ 1 ms | about 0.1–0.2 ms with dirty tracking and pooled images (S1) |
| Table point read or write at 10M rows (host cost) | ≤ 5 µs | write 1.5 µs, read about 5 µs on the LSM (S4) |
| Query on a follower | ≤ 100 µs | 1.5–2.3 µs of execution plus one or two reads (S2, S4) |
| Merge apply, cost per operation at 1M operations | ≤ 2× the cost at 1k | 1.5–1.8× with incremental apply (S6) |
| 1,000 mostly idle Raft groups per node | no thread per group; idle CPU ≤ 5% of one core | about 1.6% at a 500 ms heartbeat (S3) |

- Every budget passes with the work in section 16. On today's code, most
  fail: invocation (fresh machines), replication (the current driver),
  tables (redb writes), merge apply, and snapshots on the interpreter.
- The measurements ran on one laptop (Core Ultra 7 155H, consumer NVMe),
  with all three replicas sharing one disk; multi-agent runs varied up to
  4×.
- No hot path may grow with history length.

## 15. Worked examples

### 15.1 Neobank transfer

Agent `bank` (default agent) is replicated on nodes N1–N3. It holds a
`ledger` actor instance (a Clerk ledger package) and runs `transfer`
workflows for requests that need a risk check. `risk` is another agent.

Plain transfer:

1. The client calls N2, a follower. Ingress authenticates it, attaches the
   idempotency key K, and forwards to the leader N1.
2. N1 batches the request with others and runs refine. The default agent
   dispatches it to `ledger`, a warm machine from the pool, whose handler
   reads rows a and b, writes them and returns a receipt within the refine.
3. The work result (state version, K consumed, writes, reply) goes to N1's
   node log writer with other agents' entries and is committed by quorum.
   Accumulate on N1–N3 applies the writes and records K → reply.
4. N2 answers the client from its own applied dedup table. A retry with K
   returns the stored reply.

With a risk check:

1. The request starts a `transfer` workflow.
2. Its first step calls `risk` and ends: the message (sequence number s on
   the bank→risk pair) and a snapshot of a few pages commit together.
3. After apply, N1 sends the message. `risk` applies its answer, then
   replies on the risk→bank pair.
4. The second step resumes, usually from the live machine, and calls
   `ledger.transfer` nested; the ledger write, the workflow's completion
   and the client's reply commit in one work result.
5. If N1 fails between steps 2 and 4, N2 holds the snapshot pages (they
   were in the log). `risk` resends its reply to N2, which resumes the
   workflow from the snapshot.

Settlement proof:

1. For each settlement window, `ledger` calls `attest(apply_batch, witness)`.
   The attestable program runs live, hashing through the precompile, and
   the witness and record are replicated with the agent.
2. The prover service proves the window asynchronously, in chained
   segments, and publishes the proof.
3. A bridge instance sends the claim and proof to bank B's space, whose
   agent verifies it and credits the account.
4. On JAM, a verifier agent checks both banks' window claims in refine and
   records net positions in accumulate.

### 15.2 Community channel

Agent `community` is replicated on N1–N3. Member devices replicate the
Merge lane of channels they belong to.

1. A device posts. `post("hi")` is `#[msg(merge)]`: it runs on the device,
   or on the nearest node for thin clients. It produces a list-insert
   operation in a DAG node the device signs and chains to its previous one.
   Nodes and other devices receive it and apply only that node. No log, no
   leader.
2. A moderator removes a user. `remove(user)` is a Linear handler: it
   commits through the log, updates `members`, and emits an epoch node
   recording the user's cutoff, plus an operation hiding their posts. All
   replicas build the identical signed chain node.
3. The removed user's posts made before the cutoff stay; posts past the
   cutoff are rejected, or masked where already applied. Every replica
   reaches the same result.
4. Feed reads use local Merge state on the device or any node.

## 16. Work the spikes require

Each item is required for the budget or decision it names; prototypes exist
where noted.

**PVM runtime**

1. Memory structures proportional to mapped pages, on the interpreter and
   in the JIT's permission sync (S1, S2).
2. Native dirty-page tracking on both backends (S1).
3. The machine pool and the prepared-program cache, keyed by program hash
   (S2).
4. Precompiles on the refine path (S5b; prototype on branch
   `exp/gp-precompiles`):
   - port the BLAKE2b change;
   - move Ristretto and the scalar operations (ids 110–114) into the VOS
     range;
   - add the `WHAT` fallback to the guest crypto wrappers;
   - price precompiles in VOS gas.
5. Remove every JAR leftover (section 12).

**Prover**

6. Chained segments on the refine path, cut by steps and by chip calls
   (S5).
7. Reduce the BLAKE2b chip's memory per compression (S5b).

**Storage**

8. The LSM engine (S4):
   - data classes under agent prefixes;
   - the node log writer;
   - non-durable apply with periodic durable checkpoints;
   - Raft snapshot export and ingestion.
9. The compressed root format across `CommittedMap`, `BatchProof`, the
   witness math and cipher-clerk (S4).

**Replication and merge**

10. The vos-raft driver (S3; prototype in `spikes/s3-raft/vos-raft-eager`):
    - group commit and replicate-on-propose;
    - one shared executor;
    - heartbeats that never wait on log I/O, combined per node pair, with
      quiescence for idle groups.
11. Incremental merkle-crdt apply, with local operations in place and
    storage-backed CRDT types (S6).
12. LZ4-compressed snapshot pages (S1).

**Build order** [proposed]:

1. PVM base: items 1–5.
2. One node: the agent framework, the default agent and the actor ABI on
   the LSM engine.
3. Replication: items 8 and 10.
4. Workflows and snapshots (item 12), then the first JAM milestone.
5. Attestable programs and Clerk: items 6, 7 and 9.
6. The Merge lane: item 11.

## 17. Reused from earlier code

- **PVM:** the saga's Gray Paper 0.8.0 layer (runtime, compiler,
  conformance vectors, standard inner machines, refine host). It brings the
  precompile change from `exp/gp-precompiles` and the work in section 16.
  Master's JAR runtime is not ported.
- **Prover:** `pvm/proof` (prover, chain segments, verifier, settlement
  verifier, BLAKE2b and Ristretto chips), on the refine path, without its
  JAR paths.
- **`support/vos-raft`:** the consensus core. Its `std` driver is replaced
  (section 10).
- **`support/merkle-crdt`:** the DAG and sync format; the apply path is
  rewritten (section 9.4).
- **State:** the storage handles and `CommittedMap` / `BatchProof` API
  (`vos::storage`, `vos::zk::state`), on the compressed root format.
- The v2 CRDT field types' API, reimplemented storage-backed.
- From the macros: schema and typed-argument code.
- Clerk actors and cipher-clerk as the flagship application, moved to the
  compressed root format.
- libp2p networking, HTTP and SSH ingress, vosx, native extensions, the
  Substrate light client.

## 18. Open questions

1. Masking in CRDT types for operations invalidated by a removal; property
   tests for the authorization rule.
2. Storage-backed CRDT type design.
3. Raft snapshot format. Large log entries: in S3, 64 KiB entries managed
   only 613 commits/s, and the cause is not yet known. A raw segment log
   for witnesses and snapshot pages may be needed.
4. LSM tuning: compaction under sustained writes, cache sizing per node,
   and cold reads (about 0.1 ms on NVMe when data is not cached).
5. Precompile gas on VOS; whether gas differences between VOS and the JAM
   fallback matter for any agent.
6. Interpreter or JIT per program: a static choice, or tiering by observed
   cost.
7. Refining on any replica with read-set validation: when it becomes
   necessary.
8. Licensing model, metering, bytecode visibility.
9. Agent placement and rebalancing.
10. Upgrades: state migration for actors.
11. JAM witness format; DA retention for long-waiting workflows.
12. Devices running merge handlers locally (local-first) versus thin
    clients.
13. Workflow deadline defaults and timer precision.
14. Whether workflows need external signals beyond replies and timers.
