# VOS core model

Draft 2, planning run 2 (2026-10-08), updated with the run 3 spikes done so
far (SJ, S1, S3, S2; results in `spikes.md`). Draft 1 was reviewed by the
project owner and by a second-opinion architecture review; the adopted
changes are listed below. Tags: **[decided]** confirmed by the project
owner, or settled by a spike the owner delegated the choice to;
**[proposed]** recommendation awaiting review; **[open]** left for a later
run.

This is the model for a new core built on branch `vos-core` (from master
`d2378274`). The v2 service layer on master and the saga's agent layer are
not ported; section 17 lists what is reused.

## Changes from draft 1

- Stateful actor handlers run to completion within one refine. Waiting on
  other agents, timers or long work moves to **workflows**, which hold no
  shared state and are the only code that suspends (section 8).
- Mailboxes are gone: an actor handler never suspends, so an instance is
  never busy across refines.
- Failover hygiene: replies and acknowledgements go out only after local
  accumulate applied the result; a skip or a term change flushes pending
  results and cached machines; dedup is recorded when the log consumes an
  input (section 7.5).
- Messages between agents carry per-pair sequence numbers: FIFO delivery
  and permanent dedup (section 8.4).
- Gas preemption keeps a workflow live on VOS instead of snapshotting it.
  Snapshot pages are always shipped in full. Cross-agent awaits have
  deadlines (section 8.3).
- `CommittedMap` costs one hash per key bit per write, not O(log n); roots
  are computed at attest or settlement boundaries (section 9.3).
- The reused merkle-crdt library rebuilds state from the whole history on
  every sync; its apply path is rewritten to process only new nodes, and a
  concrete authorization rule replaces the open question (section 9.4).
- Many Raft groups per node become an explicit requirement (section 10).
- Attestable witnesses are replicated with the agent (section 11).
- JAM-mode differences are spelled out, and one PVM version and gas model
  must be chosen (section 12).
- Handler modes trimmed to mutating, query, merge and workflow. The Local
  lane is deferred until something needs it.
- Machines are created from a pool of prepared program images. A node-side
  fast path for simple actor calls waits for spike S2's numbers.

## Changes from the run 3 spikes

- **PVM version (SJ):** Gray Paper 0.8.0 for the runtime, compiler, prover
  and agents. A Rust service built with our toolchain ran unchanged on a
  PolkaJam testnet. Master's JAR profile and its block gas model are
  dropped (section 12).
- **Snapshot runtime work (S1):** the snapshot gate passes, but only with
  native dirty-page tracking, a copy-on-write image pool, no full-span
  permission sync, and LZ4 for shipped pages (section 8.3).
- **Raft driver (S3):** vos-raft's protocol core is kept; openraft is not
  faster. Its driver is rewritten:
  - group commit;
  - replicate on propose;
  - no fsync for commit-index-only writes;
  - a shared executor;
  - liveness that never waits on log I/O.

  Commit latency no longer depends on the heartbeat (section 10).
- **Storage (S3):** one log writer per node commits every agent's pending
  log writes with one fsync. Applied state is not fsynced per log entry
  (section 9.5).
- **Machines (S2):** warm machines meet the invocation budget about 10×
  over. A machine per invocation misses it, because setup is sized to the
  4 GiB address space. Required:
  - memory structures proportional to mapped pages;
  - a node-side machine pool, keyed by program hash and reset between
    uses, for actors and for agent programs;
  - prepared programs cached by hash.

  No node-side fast path in v1 (sections 6.1 and 6.4).

## 1. Goals

1. An **agent** is a JAM service: one PVM program with *refine* (stateless
   compute) and *accumulate* (cheap persistence). The same program runs on a
   VOS node and on JAM.
2. Writing an agent is easy: `#[agent]` on a main function, and a default
   agent for the common case.
3. **Actors** are independently compiled, distributed and licensed skills
   that agents install and invoke.
4. Proofs are opt-in: only `#[attestable]` code is proven, never the platform.
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
- Operations tooling beyond the basics until the core meets its performance
  budgets.

## 3. Principles

- **Verify only where trust changes:** client ingress, other spaces, JAM.
  No hot path costs more than the data it touches, and none grows with
  history.
- **Apply, then send.** Nothing leaves an agent (replies, acknowledgements,
  messages) before the work result that produced it has been applied.
- **One mechanism per concern:** snapshots for suspension, sequence numbers
  and idempotency keys for exactly-once, one replication path per lane.
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

## 5. Trust model [decided]

- Nodes in a space trust each other and may crash. Raft is sufficient.
- Local disk is trusted; no integrity re-checks beyond the storage engine's
  own.
- The PVM protects nodes from agent code, and agents from actor code: memory
  isolation, gas, mediated host calls.
- Member devices are clients. They may replicate Merge lanes they are
  authorized for, never Linear state.
- Ingress authenticates clients into principals; the node hands the
  authenticated origin to the agent. No signed evidence inside guests.
- Proofs exist for parties outside the space.

## 6. Agents

### 6.1 Agent program [decided shape, proposed details]

A Gray Paper standard program with two entries: refine (IC 0) and accumulate
(IC 5).

- **Refine** uses JAM's refine host calls (gas, fetch, historical_lookup,
  export, machine, peek, poke, pages, invoke, expunge, log) plus VOS
  extensions, each with a JAM fallback:
  - `state_read`: the agent's state at the refine base. On JAM it is served
    from a witness carried in the work package.
  - `instantiate(code_hash)`: a machine from the node's pool, keyed by
    program hash. A pooled machine is reused across requests and refines,
    and its writable memory is reset to the program image (dirty pages)
    between uses. The node pools agent programs' machines the same way.
    Prepared programs (decoded and JIT-compiled) are cached by hash;
    preparing one costs 64–140 µs per KB (S2). On JAM, the agent's loader
    uses `machine`, then `pages` and `poke`.
  - Machine memory structures are proportional to mapped pages, never to
    the 4 GiB address space. In S2, address-space-sized page tables and
    permission syncs cost 0.1–1 ms per machine, while a transfer took
    3–5 µs.
  - snapshot page access and dirty-page capture. On JAM: imports, exports,
    and peek-and-hash.
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
agent program, which serves them. The default ABI:

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

An actor cannot touch another instance's state; everything else is a call or
a message. Custom agents can add operations.

**No node-side fast path in v1** [decided by S2]. Serving actor calls
through the agent program costs about 2.4–3.6 µs more per transfer than the
node serving them directly. That is about 20 agent host calls at about
0.12 µs each, and the nested path stays about 10× within the invocation
budget.

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
entry. It applies writes; stores snapshot pages and updates the workflow
table; appends outgoing messages to the outbox with their sequence numbers;
records consumed inputs and replies (dedup); schedules timers; and applies
Merge operations emitted by Linear steps (section 9.4).

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
- It may send messages to other agents and start workflows, but may not wait
  for them.
- Exceeding its gas share fails the invocation. Long work belongs in
  workflows.

Why: hot actors never block on remote latency, never produce snapshots and
cannot deadlock across agents; one invocation per instance at a time holds
without mailboxes; upgrades apply at the next invocation.

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
  its snapshot commit together. If a step traps, nothing from it commits and
  the workflow fails. Earlier steps stay committed; multi-step atomicity uses
  reservation (saga) patterns.
- Every await on another agent has a deadline (default per agent,
  overridable). An expired deadline returns an error to the awaiting code,
  so stuck workflows cannot pin pages and programs forever.
- A workflow is started by a message with an idempotency key; its result is
  sent to whoever started it.
- Long computations run as workflows, preferably in their own agent so their
  gas does not delay a latency-sensitive agent's batches.

### 8.3 Snapshots [decided: the only continuation mechanism]

- A snapshot is: program hash, program counter, registers, gas, and the page
  table (page index → page). Pages are 4 KiB. Zero pages and pages unchanged
  from the program image are not stored.
- On VOS, a snapshot is taken when a workflow step ends. Gas preemption does
  not snapshot: the machine stays live on the leader and continues in the
  next refine. After failover, the step re-runs from the last snapshot; its
  effects were never committed. On JAM, machines do not survive a refine, so
  every work package ends with a snapshot (the CoreVM model).
- Changed pages are always shipped in full in the work result, compressed
  with LZ4. They are never referenced by hash alone, because garbage
  collection could remove a matching page first. Later: XOR deltas against
  the previous version.
- Runtime requirements measured in S1:
  - native dirty-page tracking on the interpreter and the JIT: about
    16 µs per capture, versus about 1 ms to scan an 8 MiB heap;
  - machines restored from a copy-on-write image pool: a JIT restore takes
    about 0.1 ms, but the interpreter clones fixed tables for 2.3 ms;
  - no full-span permission sync, which costs about 0.5 ms on a fresh JIT
    machine's first resume.

  A typical suspension changes 3 pages, which compress to under 1 KiB.
- A Merkle root over the page table is computed only for JAM and for
  attestable runs.
- The leader caches live machines keyed by (workflow, last committed
  snapshot). Section 7.5's flush rules apply.
- Pages are reference-counted by snapshots; completion releases them.
- Interpreter and JIT are kept equivalent by the conformance vectors.
  Exact parity with the prover's tracer matters only for attestable programs
  and JAM.

### 8.4 Messages and exactly-once [decided]

- **Clients:** an idempotency key per request; the dedup table keeps it for
  a retention window. A duplicate gets the stored reply or joins the
  pending request.
- **Between agents:** each (sender agent, receiver agent) pair has its own
  sequence. The sender's accumulate assigns numbers; its outbox resends
  until acknowledged. The receiver processes each sender's messages in order,
  keeps one high-water mark per sender permanently, and rejects gaps so the
  sender resends. It caches replies until the sender's acknowledgement
  watermark passes them. Effects are never duplicated or reordered within a
  pair, regardless of how long a sender was offline.
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
  Memory use follows touched rows, not table size.
- `CommittedMap<K, V>` also yields a sparse Merkle root and multiproofs
  (`BatchProof`) for attestable functions and JAM witnesses. The current
  format hashes once per key bit on every write (128–256 hashes), so roots
  are computed only at attest or settlement boundaries, as sorted batch
  updates, and in-PVM hashing goes through a native hash host call. Whether
  to adopt a path-compressed format, which breaks Clerk root compatibility,
  is decided after spike S4.
- No global state root on VOS. Agents deployed on JAM keep one.

### 9.4 Merge lane

- One merkle-crdt DAG per agent. A DAG node is a batch of CRDT operations
  with stable operation ids, its parents and its author.
- **Incremental apply.** merkle-crdt's DAG and sync format are reused, but
  its apply path is rewritten:
  - apply only newly fetched nodes, in causal order, onto the current state;
  - validate only new nodes;
  - derive which heads are subsumed from the fetch frontier.
  
  No whole-DAG rebuild at runtime. Gate: cost per operation at 1M
  operations within 2× of the cost at 1k.
- CRDT types are storage-backed. The v2 `List` rebuilds its whole order on
  every call and never drops tombstones, so it is replaced.
- **Linear-emitted chain.** Linear handlers may emit Merge operations, for
  materialized views, membership epochs and checkpoints that let devices
  bootstrap without full history. Every replica applies them in accumulate,
  each chained to the previous Linear-emitted node, so all replicas build
  identical nodes. The chain head is signed once per commit; devices accept
  such nodes only as ancestors of a signed head.
- **Authorization rule** (starting design, to be property-tested):
  1. A membership change is a Linear step that emits an epoch node E_n. E_n
     cites the Merge heads the leader had applied at that point.
  2. Removing member A records cutoff_A: A's latest node among those heads,
     identified by A's sequence number and its CID.
  3. Every device node is signed, carries its author's sequence number (the
     previous node's plus one, linked to it) and has an epoch node in its
     causal past.
  4. A replica accepts A's node only if A was a member at that epoch, and
     the node is at or before the cutoff of every later epoch that removed A.
     Re-admission at epoch r requires E_r in the node's causal past.
  5. When an epoch arrives that invalidates operations a replica already
     applied, those operations are masked. Only the removed author's
     in-flight operations are affected.
  
  The decision depends only on the log and the DAG, so every replica agrees.
  It costs O(1) per operation with per-member epoch intervals.

### 9.5 Storage engine [proposed]

One embedded key-value store per node (redb first), with per-agent keyspaces:
Linear state; Merge state and DAG; the page store; and system tables (dedup
and high-water marks, outbox, workflows, timers).

An fsync costs 0.35–0.5 ms on a consumer NVMe, so batching outweighs every
other storage cost (S3).

- **One log writer per node.** Every agent's Raft log goes to one node-level
  log. Its writer drains the pending writes of all agents, commits them in
  one transaction with one fsync, then acknowledges each.
  - The log is one table keyed by (agent, index).
  - Storage I/O never runs on executor threads.
  - Writes that only move the commit index are not fsynced.

  In S3, separate stores per agent lost leaders from 64 active agents up,
  and one shared store committed from each task serialized its writers.
- **Applied state is not fsynced per entry.** The log is durable, so
  accumulate commits without fsync and makes the state durable
  periodically, recording the applied index. After a crash, the node
  re-applies the log from that index. Accumulate is deterministic, so
  replies sent after a non-durable apply stay correct. Otherwise every
  applied entry would pay a full fsync.
- redb is within 2× of a raw append for batched and large writes. A raw
  append-only segment log replaces it for the log if large entries make
  that difference matter; witnesses and snapshot pages are the likely
  cases.

## 10. Replication and placement [decided: one log per agent]

- The catalog chooses each agent's replica set. An agent with Linear state
  and more than one replica has its own Raft group (vos-raft, `no_std`).
- The log carries work results, not inputs; followers only accumulate.
- Raft snapshots of agent state bound log size. Installing one costs
  O(state), never O(history).
- Agents with only Merge state have no log.
- **The vos-raft driver is rewritten; the protocol core stays.** In S3, the
  existing driver committed only on the next heartbeat and fsynced once per
  proposal and again per commit advance: about 1.2k commits/s at p99
  58 ms. A 165-line prototype passed all of vos-raft's tests and met the
  budget: about 25k/s at p99 8 ms, peaking at 44k/s. openraft managed
  2.5k/s on the same store. The new driver:
  - appends all queued proposals in one batch (group commit);
  - sends new entries to followers at once, with one append in flight per
    peer;
  - runs every group on one shared executor; the thread-per-group `Worker`
    is dropped;
  - keeps liveness independent of log I/O. Followers answer heartbeats
    without waiting for the store, and heartbeats are combined per node
    pair. In S3, waiting on the store lost leaders at 1,000 active agents.
- **The heartbeat sets failure detection only.** Commits no longer wait for
  it, so idle groups heartbeat slowly or quiesce. In S3, 1,000 idle groups
  at a 500 ms heartbeat cost about 1.6% of a core per node, 5 threads and
  about 8 KiB per replica.
- Rebalancing uses membership changes (joint consensus exists in vos-raft).

## 11. `#[attestable]` [decided intent, proposed mechanism]

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
- Long attestable computations are proven as chained segments, which the
  zkPVM chain prover already supports.
- Verification is a host call on VOS nodes. On JAM, an on-chain agent's
  refine runs the PVM settlement verifier (about 10M cycles), and its
  accumulate applies the public output.
- Cost: a 32k-step window proves in about 4 s on the reference machine.
  Kernels should prove a whole settlement window at once; per-transfer
  proofs do not scale (10k transfers at 100k steps each would take about
  35 prover-hours).

## 12. JAM integration [decided: early]

- Agent programs are valid JAM services from the first slice. CI runs them
  under a JAM host-call harness.
- JAM mode differs from VOS mode:
  - Continuity is (root before, root after) plus witnesses, checked in
    accumulate; the version counter has no meaning there. All system tables
    (dedup, outbox, workflows) sit under the committed root.
  - Refine output is capped, so state data goes to data availability (DA)
    and accumulate only swaps roots.
  - Every work package ends with workflow snapshots exported as segments.
    DA retention is finite, so long-waiting workflows re-export their pages
    or move them to preimages.
  - Messages map to transfers, whose memos are small; payloads go through
    preimages. Each hop takes several blocks.
  - Time and randomness supplied by the builder are checked against the
    slot.
- Refine witnesses are built by simulating refine off-chain, as CoreVM's
  builder does. Actor and workflow programs are preimages.
- **One PVM version for everything: Gray Paper 0.8.0** [decided by SJ]. It
  covers the runtime, compiler, prover and agents, and the saga's 0.8.0
  PVM layer is the base. Master's JAR capability-kernel profile and its
  block gas model are dropped. The saga's interpreter and JIT both charge
  the exact 0.8.0 block gas model in conformance mode.
  In SJ, a Rust service linked with our toolchain ran unchanged on a
  PolkaJam 0.1.29 testnet: refine on the guarantors and accumulate on all
  seven validators.
- Deployment tooling waits until the code preimage is available at the
  package's lookup anchor. A submission made earlier refines to `BAD`.
- First milestone: the default agent and one actor deployed on a JAM node,
  with a workflow suspended in one work package and resumed in a later one.
  It needs the agent framework's loader, which builds inner machines from
  standard programs (`machine` with bare code, then `pages` and `poke`) and
  carries snapshot pages through export and import segments.
- Next: an on-chain verifier agent that accepts proofs from a space (Clerk
  settlement).

## 13. Portability [decided direction]

Core crates are `no_std + alloc`: wire types, the agent and actor SDK, the
PVM interpreter and inner machines, vos-raft, merkle-crdt, storage traits and
the proof verifier. `std` adapters sit at the edges: redb, libp2p, the JIT,
ingress. A future bare-metal light client runs Merge replicas and proof
verification on the interpreter. The shared-executor Raft driver keeps
vos-raft's core free of threads.

## 14. Performance budgets [decided; numbers validated in run 3]

| Path | Budget | Run 3 |
|---|---|---|
| Actor invocation, refine and accumulate, one node | ≤ 50 µs | S2: passes with warm machines (3–5 µs per transfer); a machine per invocation takes 130–420 µs |
| Replicated agent on 3 LAN nodes, simple mutations | ≥ 20k per second per agent; p99 commit ≤ 10 ms at half load | S3: passes with the new driver (about 25k/s at p99 8 ms); fails with the current one |
| Workflow snapshot capture plus restore, up to 50 KB | ≤ 1 ms | S1: passes with dirty tracking and pooled images |
| Table point read or write at 10M rows (host cost) | ≤ 5 µs | S4 |
| Query on a follower | ≤ 100 µs | S2: 1.5–2.3 µs of execution with warm machines; storage reads in S4 |
| Merge apply, cost per operation at 1M operations | ≤ 2× the cost at 1k | S6 |
| 1,000 mostly idle Raft groups per node | no thread per group; idle CPU ≤ 5% of one core | S3: passes on a shared executor at a 500 ms heartbeat (about 1.6%) |

No hot path may grow with history length.

## 15. Worked examples

### 15.1 Neobank transfer

Agent `bank` (default agent) is replicated on nodes N1–N3. It holds a
`ledger` actor instance (a Clerk ledger package) and runs `transfer`
workflows for requests that need a risk check. `risk` is another agent.

Plain transfer:

1. The client calls N2, a follower. Ingress authenticates it, attaches the
   idempotency key K, and forwards to the leader N1.
2. N1 batches the request with others and runs refine. The default agent
   dispatches it to `ledger`, whose handler reads rows a and b, writes them
   and returns a receipt within the refine.
3. The work result (state version, K consumed, writes, reply) is appended
   to the log and committed by quorum. Accumulate on N1–N3 applies the
   writes and records K → reply.
4. N2 answers the client from its own applied dedup table. A retry with K
   returns the stored reply.

With a risk check:

1. The request starts a `transfer` workflow.
2. Its first step calls `risk` and ends: the message (sequence number s on
   the bank→risk pair) and a snapshot of a few pages commit together.
3. After apply, N1 sends the message. `risk` applies its answer, then
   replies on the risk→bank pair.
4. The second step resumes, usually from the live machine, and calls
   `ledger.transfer` nested; the ledger write, the workflow's completion and
   the client's reply commit in one work result.
5. If N1 fails between steps 2 and 4, N2 holds the snapshot pages (they were
   in the log). `risk` resends its reply to N2, which resumes the workflow
   from the snapshot.

Settlement proof:

1. For each settlement window, `ledger` calls `attest(apply_batch, witness)`.
   The attestable program runs live, and the witness and record are
   replicated with the agent.
2. The prover service proves the window asynchronously and publishes the
   proof.
3. A bridge instance sends the claim and proof to bank B's space, whose agent
   verifies it and credits the account.
4. On JAM, a verifier agent checks both banks' window claims in refine and
   records net positions in accumulate.

### 15.2 Community channel

Agent `community` is replicated on N1–N3. Member devices replicate the Merge
lane of channels they belong to.

1. A device posts. `post("hi")` is `#[msg(merge)]`: it runs on the device, or
   on the nearest node for thin clients, and produces a list-insert operation
   in a DAG node the device signs and chains to its previous one. Nodes and
   other devices receive it and apply only that node. No log, no leader.
2. A moderator removes a user. `remove(user)` is a Linear handler: it
   commits through the log, updates `members`, and emits an epoch node
   recording the user's cutoff, plus an operation hiding their posts. All
   replicas build the identical signed chain node.
3. The removed user's posts made before the cutoff stay; posts past the
   cutoff are rejected, or masked where already applied. Every replica
   reaches the same result.
4. Feed reads use local Merge state on the device or any node.

## 16. Spikes (run 3)

SJ, S1, S3 and S2 are done; results are in `spikes.md`. SJ part b, a
workflow suspended across work packages, moved to the first JAM milestone.
Next: S4, then S6 and S5.

| Spike | Measures | Gate |
|---|---|---|
| SJ JAM | Choose the JAM node, Gray Paper version and gas model. Build an agent with our toolchain and run it on that node, suspending and resuming a workflow across work packages | the version decision; blob and ABI compatibility confirmed |
| S1 Snapshots | Dirty pages per suspension for three workflows (transfer with a risk check, a multi-await saga, a long computation with checkpoints); capture and restore time on interpreter and JIT; resume from the live cache | typical suspension ≤ 50 KB and ≤ 1 ms |
| S3 Logs | Batched work-result throughput and latency on 3 nodes with redb (openraft as a reference); 1,000 mostly idle groups per node on a shared executor with combined heartbeats | the replicated and idle-group budgets in section 14 |
| S2 Nesting | Machine creation from the image pool; actor → agent → node host-call overhead | invocation budget; decides the node-side fast path |
| S4 Tables | Point operations at 1M and 10M rows; `CommittedMap` batch root updates; native vs in-PVM hashing | table budget; decides the tree format |
| S5 Attestable | Prove a transfer kernel: steps per transfer, cost of a settlement window, witness size | sets the attestable size guideline |
| S6 Merge apply | Incremental apply in merkle-crdt; cost per operation at 1k vs 1M operations | Merge budget in section 14 |

## 17. Reused from earlier code

- `pvm/runtime` and `pvm/compiler`, plus the saga's PVM-layer work (Gray
  Paper v0.8.0 conformance vectors, standard inner machines, refine host),
  which is self-contained. Inner-machine creation must move to a pool of
  prepared images: the saga's version copies the program and allocates a
  2^32-byte address space and a million-entry permission table per machine.
  The JIT also syncs permissions across the whole span on first resume
  (S1, S2).
- `pvm/proof`: prover, chain segments, verifier, settlement verifier.
- `support/merkle-crdt`: DAG and sync format; the apply path is rewritten.
- `support/vos-raft`: the consensus core. Its `std` driver is replaced
  (section 10); `spikes/s3-raft/vos-raft-eager` is the prototype.
- Storage handles, `CommittedMap` and `BatchProof` (`vos::storage`,
  `vos::zk::state`), with batched root computation.
- The v2 CRDT field types' API, reimplemented storage-backed.
- From the macros: schema and typed-argument code.
- Clerk actors and cipher-clerk as the flagship application.
- libp2p networking, HTTP and SSH ingress, vosx, native extensions, the
  Substrate light client.

## 18. Open questions

1. Masking in CRDT types for operations invalidated by a removal; property
   tests for the authorization rule.
2. Storage-backed CRDT type design.
3. Raft snapshot format. Whether large entries need a raw segment log
   instead of redb: in S3, 64 KiB entries managed only 613 commits/s, and
   the cause is not yet known.
4. Refining on any replica with read-set validation: when it becomes
   necessary.
5. Licensing model, metering, bytecode visibility.
6. Agent placement and rebalancing.
7. Upgrades: state migration for actors.
8. JAM witness format; DA retention for long-waiting workflows.
9. Devices running merge handlers locally (local-first) versus thin clients.
10. Workflow deadline defaults and timer precision.
11. Whether workflows need external signals beyond replies and timers.
