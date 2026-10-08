# VOS core model

Draft 4 (2026-10-08). Draft 3 was reviewed by a second-opinion architecture
review, and the owner decided the questions it raised. Measurements come
from the run 3 spikes in `spikes.md`, cited by name: S1–S6, S5b and SJ.
Tags:

- **[decided]**: confirmed by the project owner, or settled by a spike the
  owner delegated the choice to;
- **[proposed]**: recommendation awaiting review;
- **[open]**: left for a later run.

This is the model for a new core built on branch `vos-core` (from master
`d2378274`). The v2 service layer on master, the saga's agent layer and
everything specific to JAR are not ported; section 17 lists what is reused.

## Changes from draft 3

- **Correctness gaps closed** (review):
  - a workflow preempted by gas commits as an implicit checkpoint; handlers
    are never preempted (section 8.3);
  - an input whose handler fails is still consumed, with an error reply
    (section 8.1);
  - non-durable apply has explicit invariants, and the periodic checkpoint
    is gone (section 9.5);
  - pooled machines reset to exactly a fresh machine (section 6.6).
- **`.await` stays in the API** [decided]. v1 runs one dispatch at a time;
  interleaving later needs no change to actor code (section 6.3).
- **The actor framework keeps its shape** [decided]: an `#[actor]` struct
  and an impl block of methods taking `self` and a context (section 6.2).
- **Privacy is the top priority** [decided]:
  - attestable arguments and actor state are private inputs, and return
    values are public;
  - today's prover is not hiding, so zero-knowledge proving becomes a
    requirement (section 11.4).
- **The JIT is the default backend** [decided]. Its small lead on short
  handlers is treated as optimization headroom, not a reason to defer it
  (section 6.6).
- **One sync scope per Merge DAG** instead of one DAG per agent; the
  authorization rule names authors precisely (section 9.4).
- **Client sessions** replace unbounded idempotency-key retention
  (section 8.4).
- **New budgets** for many active agents per node and for fixed cost per
  refine (section 14).
- **Evidence restated where draft 3 over-claimed:**
  - table reads at 10M rows miss their budget;
  - invocation cost includes storage;
  - snapshot restore from pooled images is not yet measured.

## 1. Goals

1. An **agent** is a JAM service: one PVM program with *refine* (stateless
   compute) and *accumulate* (cheap persistence). The same program runs on a
   VOS node and on JAM.
2. Writing an agent is easy: `#[agent]` on a main function, and a default
   agent for the common case.
3. **Actors** are independently compiled, distributed and licensed skills
   that agents install and invoke.
4. **Privacy first.** An actor's state is private. Only `#[attestable]`
   methods produce proofs: their arguments and the state they read stay
   private, and only their return values are public.
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
- Concurrent execution of dispatches inside one refine.
- The Merge lane on JAM.
- Operations tooling beyond the basics until the core meets its performance
  budgets.

## 3. Principles

- **Verify only where trust changes:** client ingress, other spaces, JAM.
- **Cost follows the data touched.** No hot path costs more than the data
  it touches, and none grows with history or with the 4 GiB address space.
- **Apply, then send.** Nothing leaves an agent (replies, acknowledgements,
  messages) before the work result that produced it has been applied.
- **One mechanism per concern:** snapshots for suspension, and sequence
  numbers for exactly-once, for clients and agents alike. There is one
  replication path per lane, with one exception: Linear steps may emit
  Merge operations through the log (section 9.4).
- **JAM first.** Every VOS extension degrades to something a JAM node does:
  an equivalent JAM call, or an unknown-call answer (`WHAT`) the guest
  handles with identical results for runs that complete.
- **Batch before anything else.** An fsync costs 0.35–0.5 ms (S3), and a
  proof has a fixed cost of about 2 s (S5). Logs, storage and proofs are
  batched.
- **Untrusted code is checked at run time.** Actors are separately compiled
  vendor code. Macros make correct use easy, but the agent enforces every
  rule when serving calls.
- **Measure.** Every slice ships with performance tests against section 14.

## 4. Concepts

| Term | Meaning |
|---|---|
| Space | A trust domain: nodes run by one operator (or mutually trusting operators), plus member devices. |
| Node | A VOS process: storage, networking, ingress, PVM execution, logs, CRDT sync, optional prover. |
| Agent | Unit of deployment, state, ordering, replication and placement: an agent program, its state and its installed instances. |
| Agent program | The agent's PVM code (refine and accumulate): the default agent or a custom `#[agent]`. |
| Package | Content-addressed, vendor-signed bundle: actor and workflow programs, schema, attestable programs, metadata, license terms. |
| Actor | An `#[actor]` struct with private state, and its impl block of methods. |
| Actor instance | An installed actor inside an agent. Its handlers run to completion within one refine. |
| Workflow | A durable orchestration without shared state. The only code that suspends across refines. |
| Invocation | One run of a handler or workflow step, in its own inner machine. |
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
- Member devices are clients. They may replicate Merge scopes they are
  authorized for, never Linear state.
- Ingress authenticates clients into principals; the node hands the
  authenticated origin to the agent. No signed evidence inside guests.
- Proofs exist for parties outside the space. They reveal only the
  attestable method's return value (section 11.4).

## 6. Agents and actors

### 6.1 Agent program [decided shape, proposed details]

A Gray Paper 0.8.0 standard program with two entries: refine (IC 0) and
accumulate (IC 5).

- **Refine** uses JAM's refine host calls (gas, fetch, historical_lookup,
  export, machine, peek, poke, pages, invoke, expunge, log) plus VOS
  extensions, each with a JAM fallback:
  - `state_read`: the agent's state at the refine base. On JAM, served from
    a witness carried in the work package.
  - `instantiate(code_hash)`: a machine from the node's pool (section 6.6).
    On JAM, the agent's loader builds it with `machine`, then `pages` and
    `poke`, into the same layout.
  - snapshot page access and dirty-page capture. On JAM: imports, exports,
    and peek-and-hash.
  - precompiles (section 11.2). On JAM, the unknown id returns `WHAT` and
    the guest computes in software.
  - proof verification (section 11.1). On JAM, the agent runs the verifier
    program itself.
- **Accumulate** uses JAM's accumulate host calls (read, write, transfer,
  provide, solicit, checkpoint, log) plus VOS extensions for page storage,
  Merge emission, external replies and timers.
- The node implements every host call natively.

### 6.2 The actor framework [decided shape; API proposed]

An actor is a struct holding its private state and an impl block of
methods. Each method takes `self` and a context:

```rust
#[actor(role = LedgerRole)]
pub struct Ledger {
    owner: PrincipalId,                           // Linear
    accounts: CommittedMap<AccountId, Account>,   // Linear, committed: attestable reads
    notes: crdt::List<Note>,                      // Merge
}

#[messages]
impl Ledger {
    fn new() -> Self { /* ... */ }

    /// Query: any replica, applied state, outside the log.
    #[msg]
    async fn balance(&self, id: AccountId, ctx: &Context<Self>) -> u64 { /* ... */ }

    /// Command: through the agent's log, atomic, within one refine.
    #[msg(role = LedgerRole::Member)]
    async fn transfer(&mut self, req: Transfer, ctx: &mut Context<Self>) -> Result<Receipt, Error> {
        let fee = ctx.call(FEES, Quote(req.amount)).await?; // same agent: nested, completes here
        /* ... */
    }

    /// Proven: arguments and state read are private, the return value public.
    #[attestable]
    async fn settle(&mut self, window: Window, ctx: &mut Context<Self>) -> Settlement { /* ... */ }

    /// Merge: any replica or device, no log.
    #[msg(merge)]
    async fn note(&mut self, text: String, ctx: &mut MergeContext<Self>) { /* ... */ }

    /// Workflow: suspends across refines; no access to `self`.
    #[workflow]
    async fn checked_transfer(wf: &mut Workflow, req: Transfer) -> Result<Receipt, Error> { /* ... */ }
}
```

- This is the shape on master today (`#[actor]`, `#[messages]`, `async fn`
  handlers with a `Context`). Roles stay as on master.
- **The context is the actor's whole ABI:** calls, sends, workflow starts,
  `now`, `random`, `attest`, the caller's identity and logging (section
  6.5). The context type differs by handler kind, so a query cannot reach
  a mutating operation.
- The full API is designed in the next planning run [open].

### 6.3 Execution order and `.await` [decided]

- `.await` marks a point where a handler or workflow yields. The API keeps
  it everywhere, so a later scheduler can run dispatches concurrently
  without changing actor code.
- **v1 runs one dispatch at a time,** in batch order. A same-agent call
  completes before the awaiting code continues, within the same refine.
  The dispatch order is the order of steps in the work result.
- A handler may not await another agent. Only workflows do, and that ends
  the step (section 8.2).
- Running dispatches concurrently later requires:
  - exclusion per instance: one invocation per instance at a time;
  - an overlay per step, with conflicts detected before commit;
  - cycle detection across call trees.

### 6.4 Packages [decided: separately compiled; proposed details]

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

### 6.5 The actor ABI [decided: served by the agent program; operation list proposed]

Actors and workflows run as inner machines. Their host calls exit to the
agent program, which serves them. Precompiles are the one exception
(section 11.2). The default ABI:

| Operation | Command | Query | Merge | Workflow |
|---|---|---|---|---|
| input, reply, log, caller | yes | yes | yes | yes |
| read own Linear state | yes | yes | no | no |
| write own Linear state | yes | no | no | no |
| read and write own Merge fields | yes (applied after commit) | read | yes | no |
| `call` an instance in the same agent (nested, synchronous) | yes | queries only | no | yes |
| `send` to any agent; `start` a workflow | yes | no | no | yes |
| await another agent, a timer, `checkpoint` | no | no | no | yes |
| `now`, `random` (fixed per work result) | yes | yes | yes | yes |
| `attest` (section 11) | yes | no | no | yes |

- **The agent enforces this table per invocation at run time.** A raw host
  call outside the invocation's kind fails the invocation.
- **Unknown ids:** the agent answers any id it does not serve with `WHAT`,
  as a JAM node does. That includes a precompile id an inner machine
  raises on JAM.
- An actor cannot touch another instance's state; everything else is a call
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

### 6.6 Machines [decided by S1, S2 and the owner]

- **Pool.** The node keeps reusable machines keyed by program hash, for
  actors and for agent programs alike. A pooled machine is reused across
  requests and refines.
- **Reset** [decided]. Before reuse, a machine is made observationally equal
  to a fresh `instantiate`:
  - same page map and permissions;
  - same contents;
  - same registers and gas.

  Every write marks its page dirty, whether by the guest or by the host
  (precompile output, `poke`, `fetch`, `state_read`). Reset restores the
  dirty pages and undoes any `pages` changes. The pool is node-wide, so a
  missed page would leak data between tenants.
  - A differential test (pooled against fresh, adversarial sequences)
    gates the pool.
  - `instantiate` produces the same layout as the JAM loader, bit for bit.
  - S2 measured a full reset of a small actor's writable image at
    about 1.4 µs. A dirty-page reset should cost less but is not yet
    measured.
- **Prepared programs** (decoded, and JIT-compiled) are cached by hash.
  Preparing one costs 64–140 µs per KB (S2), so it happens at install or
  first use, never per invocation.
- **Memory structures follow mapped pages**, never the 4 GiB address space:
  - the interpreter's page table and permissions grow with mapped pages;
  - the JIT syncs permissions only for ranges that changed.

  Today's address-space-sized structures cost 0.1–1 ms per machine (S2).
- **Dirty pages are tracked natively** on both backends. S1 estimated
  capture at about 16 µs by copying and hashing a known delta; the tracking
  itself is not yet measured.
- **The JIT (the recompiler to native code) is the default backend**
  [decided] for agents, actors and workflows. The interpreter serves
  tracing for proofs and platforms without the JIT.
  - On short handlers the JIT is only about 1.6× faster today, because
    host-call exits dominate. That is headroom to optimize, not a reason to
    defer it.
  - On computation it is about 11× faster (S1).

## 7. Execution [decided]

### 7.1 Inputs

- **Input kinds:** client requests (through ingress, in client sessions,
  section 8.4); messages from other agents (with per-pair sequence numbers);
  replies to waiting workflows; timer firings.
- The node leading the agent's log batches inputs, by count, bytes or about
  1–5 ms, into one work package.
- Admission control limits queued inputs per agent. Excess requests are
  refused with "busy" and retried by the client.

### 7.2 Refine

Runs on the leader in v1. Later any replica may refine, with read sets
validated at accumulate. The node supplies:

- the batch of inputs;
- a base: the applied state plus an overlay of the leader's own pending
  work results, so refines can pipeline;
- a timestamp and a random seed for the batch.

The agent loop dispatches inputs one at a time (section 6.3). Actor
handlers run to completion; workflows run until they finish, suspend or
fail.

### 7.3 The work result (default agent)

- the state version it read (section 7.5), time, seed;
- the inputs consumed (client session sequence numbers, per-pair sequence
  numbers);
- per step: instances touched, Linear writes, Merge operations, Merge heads
  read, outgoing messages, the reply or error, status (done, suspended,
  failed), changed snapshot pages, gas used.

### 7.4 Accumulate (default agent)

Runs on every replica, in log order, on committed entries only. Each entry
is applied as one atomic storage batch, which also records the applied
index (section 9.5). It does the following:

- applies writes;
- stores snapshot pages and updates the workflow table;
- appends outgoing messages to the outbox with their sequence numbers;
- advances session and pair high-water marks and records replies;
- schedules timers, at times taken from the work result, never from a
  local clock;
- applies Merge operations emitted by Linear steps (section 9.4).

Accumulate never re-executes actor code and never re-verifies history. On
JAM, the default agent's accumulate also maintains the committed root over
all state (section 12), so it has two paths: VOS and JAM.

### 7.5 Leader changes and pipeline hygiene

- A new leader commits a no-op and applies everything before it, then
  refines from there. Its timestamps never go below the last committed
  one.
- **Version check.** Each work result names the state version it read: the
  number of applied, non-skipped work results before it, counting the
  leader's pending ones. Entries that do not change refine-visible state
  (no-ops, acknowledgements, membership) do not advance the version.
  Accumulate applies a result only if that version is still current;
  otherwise it skips the result and its inputs are retried.
- Replies, acknowledgements and outbox sends happen only after the local
  accumulate applied the result, never merely because the entry committed.
- A skipped result or a term change aborts the leader's pipeline and
  flushes its overlay and its cached machines.
- An input is recorded as consumed when its result is applied. A retry that
  arrives while the original is pending in the leader's pipeline is joined
  to it.
- A client's reply comes from the applied state of a replica, so it never
  depends on the leader that produced it surviving.
- **The leader sends commit-index updates eagerly,** combined per node
  pair, so followers apply and reply within one network hop rather than at
  the next heartbeat.

### 7.6 Queries

- `&self` handlers run on any replica against applied state, outside the
  log, and report the version they read.
- `#[msg(linearizable)]` first obtains Raft's read index.
- A client may ask for a read at or after a version it has seen, which
  gives read-your-writes through followers.

## 8. Handlers, workflows and snapshots

### 8.1 Actor handlers [decided]

- A command runs to completion within the refine that starts it. Handlers
  are never preempted.
- It may call instances of the same agent; the callee runs nested and
  completes before the caller continues. The whole call tree commits or
  aborts as one step: if any part traps, nothing commits. A call cycle (A
  calls B calls A) fails.
- It may send messages to other agents and start workflows, but may not
  wait for them.
- Each invocation has a gas limit, fixed per call and independent of how
  the batch was packed. Exceeding it fails the invocation.
- **A failed step still consumes its input** [decided]:
  - its effects are discarded;
  - the session or pair high-water mark advances;
  - an error reply goes to the caller.

  A message that always fails therefore cannot stall its sender pair, and a
  client request that always fails is not retried forever. The same holds
  for a late reply to a workflow whose deadline expired: it is consumed and
  dropped.

Why handlers run to completion:

- hot actors never block on remote latency, never produce snapshots and
  cannot deadlock across agents;
- one invocation per instance at a time holds without mailboxes;
- upgrades apply at the next invocation.

### 8.2 Workflows [decided]

- A workflow holds no shared state: only its own memory, which its
  snapshots preserve.
- A step ends at an await on another agent, a timer or a `checkpoint()`, or
  at completion. Its synchronous calls' effects, its outgoing messages and
  its snapshot commit together. If a step traps, nothing from it commits
  and the workflow fails. Earlier steps stay committed; multi-step
  atomicity uses reservation (saga) patterns.
- Every await on another agent has a deadline (default per agent,
  overridable). An expired deadline returns an error to the awaiting code,
  so stuck workflows cannot pin pages and programs forever.
- A workflow is started by a message in a session or pair sequence. Its
  result is sent to whoever started it.
- Long computations run as workflows, preferably in their own agent so their
  gas does not delay a latency-sensitive agent's batches.

### 8.3 Snapshots and preemption [decided: snapshots are the only continuation mechanism]

- A snapshot is: program hash, program counter, registers, gas, and the page
  table (page index → page). Pages are 4 KiB. Zero pages and pages
  unchanged from the program image are not stored.
- On VOS, a snapshot is taken when a workflow step ends.
- **Preemption** [decided]:
  - A workflow that exhausts its refine's gas share ends its step there as
    an implicit checkpoint: effects so far and a snapshot commit together,
    and it continues in a later refine.
  - Preemption never happens inside a nested call. A nested call runs to
    completion under its own fixed gas limit, so no uncommitted writes are
    ever held across refines.
- After failover, a workflow resumes from its last committed snapshot.
- On JAM, machines do not survive a refine, so every work package ends with
  a snapshot (the CoreVM model).
- Changed pages ship in full in the work result, compressed with LZ4. They
  are never referenced by hash alone unless the large-entry path pins them
  (open question 3). Later: XOR deltas against the previous version.
- Measured cost (S1):
  - a typical suspension changes 3 pages, under 1 KiB after LZ4;
  - a long computation's first checkpoint ships 2 MiB, and later ones about
    136 KiB, because random data does not compress.
  - Restore was measured on fresh machines: about 0.1 ms to instantiate on
    the JIT, plus about 0.5 ms on the first resume until the full-span
    permission sync is removed. On the interpreter it takes 2.3 ms today.
    Restore from pooled images is not yet measured.
- A Merkle root over the page table is computed only for JAM and for
  attestable runs.
- The leader caches live machines keyed by (workflow, last committed
  snapshot). Section 7.5's flush rules apply.
- Pages are reference-counted by snapshots; completion releases them.
- Interpreter and JIT are kept equivalent by the conformance vectors. Exact
  parity with the prover's tracer matters only for attestable programs and
  JAM.

### 8.4 Sessions, messages and exactly-once [decided mechanism; retention proposed]

- **One mechanism for clients and agents: sequence numbers.**
  - Each client session and each (sender agent, receiver agent) pair has
    its own sequence.
  - The receiver processes each sequence in order and keeps its high-water
    mark. A duplicate at or below the mark is dropped; a gap is rejected so
    the sender resends.
  - For a client session, the receiver also keeps the last reply, to answer
    a retry.
- **Client sessions.** Ingress opens a session per client connection or
  device. Its state is the high-water mark and the last reply, kept until
  the session expires after inactivity. State is O(active clients), not
  O(requests), so a busy agent never holds billions of keys.
- **Between agents:**
  - The sender's accumulate assigns sequence numbers, and its outbox resends
    until acknowledged.
  - Pair marks are kept permanently.
  - A reply is itself a sequenced message on the reverse pair, already in
    the sender's outbox, so the receiver keeps no separate reply cache.
  - Effects are never duplicated or reordered within a pair, however long
    a sender was offline.
- Acknowledgements are batched into later log entries.

### 8.5 Time, randomness and gas

- **Time.** The leader assigns a timestamp per work result, monotonic
  across leader changes.
- **Randomness.** The leader also assigns a seed. Code reads time and seed
  through the ABI, so attestable runs stay deterministic. The leader can
  bias the seed, so attestable outputs that outside parties rely on must
  not depend on it; where they need randomness, it comes from the chronos
  VRF.
- **On JAM,** values the builder supplies are checked against the slot.
- **Gas.** Each refine has a gas budget split across invocations, and gas
  per instance is recorded for metering. Gas outcomes may differ between
  VOS and JAM (section 11.2).

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
| `#[msg] fn f(&mut self)` (command) | leader, through the log | Linear; Merge operations applied after commit | Linear; Merge as of the heads recorded in the work result |
| `#[msg] fn f(&self)` (query) | any replica (`linearizable`: after a read index) | nothing | applied Linear and Merge state |
| `#[msg(merge)]` | any replica or device, no log | Merge | Merge |
| `#[workflow]` | leader, through the log | nothing directly (calls and messages) | its own memory |
| `#[attestable]` | inside a command or workflow step | as a command | as a command, through witnesses |

- The macros generate a view per mode, so misuse fails to compile.
- The agent also enforces the modes at run time (section 6.5).
- A command does not see its own Merge operations until after commit.

### 9.3 Tables and committed maps [decided]

- `Table<K, V>` (with map, set and vector variants) stores rows in the
  agent's keyspace: point reads and writes, ordered scans with cursors.
  Memory use follows touched rows, not table size. At 10M rows (S4, warm
  cache), writes cost about 1.5 µs and reads 5.2–5.6 µs, slightly over the
  5 µs budget.
- `CommittedMap<K, V>` also yields a Merkle root and multiproofs
  (`BatchProof`) for attestable methods and JAM witnesses. Only branching
  nodes are stored: about log₂(n) rows per key path.
- **Compressed root format** [decided]:
  - a leaf hash commits a domain tag, the fixed-width key and H(value);
  - a branch hash commits a different domain tag, its split level and both
    children;
  - spines through empty levels are never hashed;
  - variable-length keys are hashed to a fixed width first;
  - the empty map has a defined root;
  - verifiers check that split levels strictly increase along a path and
    fit the key width.

  Non-inclusion of a key k is shown by the leaf for a different key k′
  that k's path reaches. An update costs 8–25 hashes (3–8 µs at 1M–10M
  keys), against 100–280 for the fixed-depth format it replaces (S4). The
  change moves together through `CommittedMap`, `BatchProof`, the witness
  math, the attestable kernels and cipher-clerk (`merkle.rs`,
  `state_root.rs`, `succinct.rs`, `snapshot.rs`), which the owner cleared
  to change.
- **Root maintenance** [proposed]: replicas maintain node rows
  incrementally in accumulate, as each entry's committed writes apply. That
  is 8–25 hashes per committed write, within the invocation budget. A
  settlement boundary then needs no batch recomputation that would stall
  accumulate (a 10,000-update batch took about 64 ms in S4, including the
  tree walk).
- Hashing inside the PVM uses the hash precompile (section 11.2).
- No global state root on VOS. Agents deployed on JAM keep one.

### 9.4 Merge lane

- **One DAG per sync scope** [proposed]. A scope is one instance's Merge
  fields, or a declared group of them. Each scope has its own merkle-crdt
  DAG and epoch chain, so a device fetches only the scopes it belongs to.
  A DAG node is a batch of CRDT operations with stable operation ids, its
  parents and its author.
- **Incremental apply** [decided by S6]. merkle-crdt's DAG and sync format
  are reused; its apply path is rewritten:
  - validate and apply only newly fetched nodes, in causal order, onto the
    current state;
  - derive which heads are subsumed from the fetched nodes;
  - apply local operations in place, with no state clone.

  Full validation and rebuild remain only for recovery and audits. Today's
  library takes 8.7 s to sync one operation onto a 1M-operation history; a
  40-line incremental prototype takes about 1.9 µs, 1.5–1.8× its cost at
  1k (S6, an LWW map on an in-memory store without signature checks).
- CRDT types are storage-backed. The v2 `List` rebuilds its whole order on
  every call and never drops tombstones, so it is replaced.
- **Linear-emitted chain.** Linear handlers may emit Merge operations, for
  materialized views, membership epochs and checkpoints that let devices
  bootstrap without full history.
  - Every replica applies them in accumulate, each chained to the previous
    Linear-emitted node, so all replicas build identical nodes.
  - Their cited parents may arrive later.
  - The chain head is signed once per commit. Devices accept such nodes
    only as ancestors of a signed head.
- **Authors.** An author is a device key or a node key, never a principal.
  The scope's membership maps principals to their authors. A thin client's
  `#[msg(merge)]` operation is authored by the node that ran it, on the
  principal's behalf.
- **Authorization rule** (starting design, to be property-tested):
  1. A membership change is a Linear step that emits an epoch node E_n.
     E_n cites the Merge heads the leader had applied at that point.
  2. Removing an author A records cutoff_A: A's latest node among those
     heads, identified by its CID.
  3. Every author node is signed, carries the author's sequence number (the
     previous node's plus one, linked to it) and has an epoch node in its
     causal past.
  4. A replica accepts A's node only if A was a member at that epoch, and
     the node is an ancestor of or equal to cutoff_A for every later epoch
     that removed A. Re-admission at epoch r requires E_r in the node's
     causal past.
  5. Two nodes by one author with the same sequence number are an
     equivocation. Both are rejected, and the author is removed.
  6. Operations invalidated by a later epoch are filtered when read, by
     (author, position relative to the cutoff), not unapplied. Lists and
     sets need nothing else; LWW maps keep their top two values per key.

  The decision depends only on the log and the DAG, so every replica
  agrees. It costs O(1) per operation with per-author epoch intervals.
- **Merge-only agents** have no log only if they have no Linear state, no
  workflows and no outbox. `#[msg(merge)]` handlers cannot send messages or
  start workflows.

### 9.5 Storage engine [decided: LSM; layout and durability proposed]

One embedded LSM key-value store per node (fjall first), as one keyspace
with one journal and a partition per data class. It holds:

- Linear state, Merge state and DAGs, and the page store;
- system tables: session and pair high-water marks, outbox, workflows and
  timers;
- the node log.

**Why an LSM** (S4):

- at 10M rows, random updates cost about 1.5 µs per row on fjall against
  18 µs on redb;
- durable log appends were 1.5–2× faster;
- redb reclaims space only after durable commits: a 0.7 GB table loaded
  without them grew to 24.6 GiB.

Reads cost 5.2–5.6 µs at 10M rows with a 1 GiB warm cache (redb: 1.6 µs),
and about 0.1 ms cold. Bringing reads within budget is part of the first
storage slice: key layout per data class, filters and cache sizing.

**Layout** [proposed]: agents share each partition under agent key
prefixes; a tree per agent would multiply memtables and background work. A
Raft snapshot exports an agent's prefix as a range and installs by range
delete and ingestion.

**One log writer per node** [proposed]. Every agent's Raft log goes to one
node-level log, keyed by (agent, index):

- the writer drains the pending writes of all agents, commits them with one
  fsync, then acknowledges each;
- a flush is capped in bytes, so one large entry cannot hold back every
  agent (open question 3);
- storage I/O never runs on executor threads;
- writes that only move the commit index are not fsynced.

**Applied state without fsync** [proposed]. Accumulate writes each entry as
one atomic batch without fsync. This is safe under six invariants:

1. The batch includes the new applied index.
2. State and log share the one journal, so after a crash the store
   recovers a consistent prefix: an apply batch is never durable without
   the log write before it.
3. Only entries committed by quorum are applied, never the leader's
   pending overlay.
4. Log truncation and Raft snapshots stay at or below the durable applied
   index.
5. Accumulate reads no local clock or other node-local input.
6. Snapshot ingestion is fsynced before the applied index that depends on
   it is recorded.

Every node-log fsync then also makes all earlier apply batches durable, so
no separate checkpoint mechanism exists. After a crash, the node re-applies
the log from the recovered applied index. Re-applying regenerates the same
outbox sequence numbers, which receivers deduplicate.

## 10. Replication and placement [decided: one log per agent]

- The catalog chooses each agent's replica set. An agent with Linear state,
  workflows or an outbox, and more than one replica, has its own Raft group
  (vos-raft, `no_std`).
- The log carries work results, not inputs; followers only accumulate.
- Raft snapshots of agent state bound log size. Installing one costs
  O(state), never O(history).
- **New vos-raft driver** [decided by S3]. The protocol core stays, and the
  driver changes:
  - queued proposals are appended in one batch (group commit);
  - new entries go to followers at once, with one append in flight per
    peer;
  - commit-index updates go out eagerly, combined per node pair (section
    7.5);
  - every group runs on one shared executor; the thread-per-group `Worker`
    is dropped;
  - followers answer heartbeats without waiting for the store, and
    heartbeats are combined per node pair.

  A 165-line prototype of the first two changes passed all of vos-raft's
  tests. It reached about 25k commits/s at p99 8 ms, peaking at 44k/s,
  where the current driver managed 1.2k/s at p99 58 ms; openraft managed
  2.5k/s on the same store. Those runs were on redb, in one process, with
  three replicas on one disk, under closed-loop load, measuring leader-side
  latency only (S3).
- **The heartbeat sets failure detection only.** Commits no longer wait for
  it, so idle groups heartbeat slowly or quiesce. 1,000 idle groups at a
  500 ms heartbeat cost about 1.6% of a core per node, 5 threads and about
  8 KiB per replica (S3).
- **Many active agents per node** are not yet within budget. With S3's
  prototype node writer, p99 was 16–56 ms at 16 active agents and up to
  191 ms at 64, and leaders were lost at 1,000 (section 14).
- Rebalancing uses membership changes (joint consensus exists in vos-raft).

## 11. `#[attestable]` [decided intent and direction; sizes proposed]

### 11.1 Mechanism

- An `#[attestable]` method is compiled into its own small program and
  shipped in the package.
  - Its private inputs are its arguments and the actor state it reads,
    delivered as witnesses: rows plus a `BatchProof` against
    `CommittedMap` roots.
  - Its return value is public, together with the roots before and after
    and the program hash.
- A live call runs that same program as an inner machine, so what runs is
  what gets proven. The call records the program hash, a hiding commitment
  to its inputs, and the output.
- The witness and the record are stored with the agent's replicated state,
  so losing the producing node cannot make a settlement window unprovable.
- Proving is asynchronous (prover service). Proofs are content-addressed and
  attached to messages for other spaces or JAM.
- **Verification**:
  - On VOS, a VOS extension call served by the node.
  - On JAM, an on-chain agent's refine runs the verifier program itself,
    and its accumulate applies the public output. Earlier work measured the
    settlement verifier at about 10.7M PVM cycles for one segment; a whole
    window needs aggregation (section 11.4).

### 11.2 Precompiles [decided direction; prototyped in S5b]

- A precompile is an `ecalli` host call with a VOS-owned id in
  `0x400..=0x4ff`, outside every id JAM assigns (the Gray Paper calls, and
  JIP-1 `log` at 100). BLAKE2b compression is `0x400`. The range should be
  reserved through a JIP, because a future Gray Paper id in it would
  silently break the fallback.
- VOS nodes serve precompiles in place, inside the machine slice, for agent
  programs and inner machines alike. It is the one call that bypasses the
  agent: a pure memory transform with no state.
- Every precompile takes a pointer in φ[7] and leaves every register
  unchanged. `WHAT` in φ[7] can therefore only come from a host that does
  not know the id.
- The prover attaches each call to its chip (BLAKE2b, Ristretto) inside the
  same slice. The STARK alone rejects a tampered call input (S5b).
- **On JAM,** the unknown id returns `WHAT` and the guest computes in
  software, with identical results for runs that complete.
- **Gas** [proposed]:
  - Results are promised identical only for runs that complete. Whether a
    run exhausts its gas depends on the environment: a hash costs about 66
    steps on VOS and about 4,760 on the JAM fallback, and the `gas` call is
    observable.
  - JAM tooling budgets gas at fallback cost, from per-call counts recorded
    on VOS.
  - VOS prices each precompile, and the prover binds that price wherever a
    proof binds final gas.
- **Cost per BLAKE2b compression** (S5b): 66 steps plus about 35 ms and
  50 MiB of proving. Hashing in the PVM costs about 4,760 steps, 0.4 s and
  800 MiB per hash. The marginal cost rises near a slice's memory cap:
  about 20 ms per compression up to 100 calls, 46 ms between 200 and 400.

### 11.3 Cost and size guideline [proposed]

- **Prover memory per segment** ≈ 4.6 GiB + 170 KiB × steps + 50 MiB ×
  compressions (S5, S5b). Segments are sized to the prover's memory, not to
  steps alone. On a 24 GiB prover that means about 2^16 steps with about
  200 compressions; a 2^16-step segment of hash-heavy code (about 1,000
  compressions) would need about 50 GiB.
- **Proving time** ≈ 2 s plus 80 µs per step per segment. Proofs are about
  0.6–0.9 MiB per segment.
- **Hashing dominates.** A transfer touches two leaves, about 45–100
  compressions under the compressed root format. That suggests about 2–4 s
  of proving per transfer with the precompile, derived from per-call costs
  rather than from a proved kernel.
- **Guideline:**
  - prove a whole settlement window at once, never one proof per item;
  - size segments to the prover's memory as above;
  - target about 1M steps per window. This target assumes the precompile
    and is checked once a transfer kernel is proved.

### 11.4 Privacy [decided: top priority; requirements]

The owner's model: an actor's state is private; an `#[attestable]` method's
arguments and the state it reads are private inputs to the circuit; its
return value is the public output that on-chain agents act on.

Status today (checked in the code, not only by the review):

- **Not hiding.** The pinned Stwo revision has no zero-knowledge masking
  (no randomized trace or blinding). STARK openings can leak information
  about the trace, and so about private inputs.
- **Witness-free verification is incomplete.** A STARK-only verifier exists
  (`verify_refine_bundle_authenticated`), but it reports "replay required":
  host-call boundaries and machine states are not proven inside the proof.
  Full soundness today needs a replay with the private arguments. S5's
  verify figures are replay verification.
- **The arguments are exposed by commitment.** The bundle carries a plain
  hash of the arguments, which is not hiding.

Requirements before any proof leaves a space:

1. **Zero-knowledge proving:** hiding trace commitments and openings in the
   prover and its chips.
2. **Witness-free verification of attestable programs:** everything an
   attestable run depends on is proven in the AIR. Its precompile calls are
   already in-AIR (S5b), and it has no other host-call boundaries.
3. **A hiding commitment, or none:** no plain hash of private arguments in
   anything published.
4. **Public outputs only:** the return value, the roots and the program
   hash.
5. **Window aggregation** for on-chain verification. A window is many
   segments, and it must fit a JAM work package and the on-chain verifier's
   gas.

These form a prover track that runs alongside the core slices (section 16).

## 12. JAM integration [decided: early]

- Agent programs are valid JAM services from the first slice. A JAM
  host-call CI harness runs them from slice 2.
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
    accumulate; the version counter has no meaning there.
  - All system tables (sessions, outbox, workflows) sit under the committed
    root, so the default agent maintains that root on JAM only.
  - Root continuity serializes an agent's work packages. The builder
    chains them with prerequisites.
  - Refine output is capped, so state data goes to data availability (DA)
    and accumulate only swaps roots.
  - Every work package ends with workflow snapshots exported as segments.
    DA retention is finite, so long-waiting workflows re-export their pages
    or move them to preimages.
  - Messages map to transfers, whose memos are small; payloads go through
    preimages. Each hop takes several blocks.
  - Time and randomness supplied by the builder are checked against the
    slot.
  - Precompiles fall back to software (section 11.2). Witnessed state reads
    therefore cost about 25 × 4,760 gas per row in hashing.
  - The Merge lane is VOS-only in v1.
- Refine witnesses are built by simulating refine off-chain, as CoreVM's
  builder does. Actor and workflow programs are preimages.
- Deployment tooling waits until the code preimage is available at the
  package's lookup anchor; a submission made earlier refines to `BAD` (SJ).
- **First milestone:** the default agent and one actor deployed on a JAM
  node, with a workflow suspended in one work package and resumed in a
  later one. It needs:
  - the agent framework's loader, which builds inner machines from standard
    programs (`machine` with bare code, then `pages` and `poke`);
  - snapshot pages carried through export and import segments;
  - witnessed state reads on the compressed root format.
- **Next:** an on-chain verifier agent that accepts proofs from a space
  (Clerk settlement), once the privacy track's aggregation exists.

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

| Path | Budget | Measured | Status |
|---|---|---|---|
| Actor invocation, refine and accumulate, one node | ≤ 50 µs | 3.6–5.0 µs marginal on an in-memory store (S2); about 15–20 µs with storage and pool reset | passes with section 16 work |
| Fixed cost per refine [proposed] | ≤ 50 µs; pooled acquire and reset ≤ 5 µs; a new machine ≤ 50 µs | 0.8–1.6 ms today (S2) | needs the pool |
| Replicated agent on 3 LAN nodes, simple mutations | ≥ 20k per second per agent; p99 commit ≤ 10 ms at half load | about 25k/s at p99 8 ms with the prototype driver, on redb, one process, one disk (S3) | passes with section 16 work; repeat on fjall and a network |
| Many active agents per node [proposed] | 64 active agents: ≥ 40k commits per second in total, p99 ≤ 20 ms | 6.3–26k/s at p99 31–191 ms (S3) | fails |
| Workflow snapshot capture plus restore, up to 50 KB | ≤ 1 ms | about 16 µs estimated capture (S1); restore 0.1 ms fresh JIT, plus about 0.5 ms first resume today | passes with section 16 work; pooled restore not yet measured |
| Table point read or write at 10M rows (host cost) | ≤ 5 µs | write 1.5 µs; read 5.2–5.6 µs warm, about 0.1 ms cold (S4) | writes pass; reads fail narrowly |
| Query on a follower | ≤ 100 µs | 1.5–2.3 µs of execution plus reads (S2, S4) | passes warm |
| Merge apply, cost per operation at 1M operations | ≤ 2× the cost at 1k | 1.5–1.8× with incremental apply on LWW maps, in memory (S6) | passes with section 16 work |
| 1,000 mostly idle Raft groups per node | no thread per group; idle CPU ≤ 5% of one core | about 1.6% at a 500 ms heartbeat (S3) | passes |

- All measurements ran on one laptop (Core Ultra 7 155H, consumer NVMe),
  with all three replicas sharing one disk and a warm page cache. Runs
  with many active agents varied up to 4×.
- No hot path may grow with history length.

## 15. Worked examples

### 15.1 Neobank transfer

Agent `bank` (default agent) is replicated on nodes N1–N3. It holds a
`ledger` actor instance (a Clerk ledger package) and runs `checked_transfer`
workflows for requests that need a risk check. `risk` is another agent.

Plain transfer:

1. The client's session on N2, a follower, carries the request with
   sequence number q. Ingress authenticates it and forwards it to the
   leader N1.
2. N1 batches the request with others and runs refine. The default agent
   dispatches it to `ledger`, a warm machine from the pool, whose
   `transfer` command reads rows a and b, writes them and returns a receipt
   within the refine.
3. The work result (state version, session mark q, writes, reply) goes to
   N1's node log writer with other agents' entries and is committed by
   quorum. N1 sends the new commit index to N2 and N3 at once. Accumulate
   on each replica applies the writes and records q and the reply.
4. N2 answers the client from its applied session state. A retry with q
   returns the stored reply.

With a risk check:

1. The request starts a `checked_transfer` workflow.
2. Its first step calls `risk` and ends: the message (sequence number s on
   the bank→risk pair) and a snapshot of a few pages commit together.
3. After apply, N1 sends the message. `risk` applies its answer, which goes
   back as a sequenced message on the risk→bank pair.
4. The second step resumes, usually from the live machine, and calls
   `ledger.transfer` nested. The ledger write, the workflow's completion
   and the client's reply commit in one work result.
5. If N1 fails between steps 2 and 4, N2 holds the snapshot pages (they
   were in the log). `risk`'s outbox resends its reply to N2, which resumes
   the workflow from the snapshot.

Settlement proof:

1. For each settlement window, a command calls `ledger.settle(window)`, an
   `#[attestable]` method. Its program runs live, hashing through the
   precompile. The witness and a record with a hiding commitment to the
   inputs are replicated with the agent.
2. The prover service proves the window asynchronously, in segments sized
   to its memory, aggregates them and publishes the proof. Only the
   `Settlement` return value, the roots and the program hash are public.
3. A bridge instance sends the claim and proof to bank B's space, whose
   agent verifies it and credits the account.
4. On JAM, a verifier agent checks both banks' window claims in refine and
   records net positions in accumulate.

### 15.2 Community channel

Agent `community` is replicated on N1–N3. Each channel is an instance whose
Merge fields form one sync scope; member devices replicate the scopes of
channels they belong to.

1. A device posts. `post("hi")` is `#[msg(merge)]`. It runs on the device,
   or on the nearest node for thin clients, where that node is the author.
   It produces a list-insert operation in a DAG node the author signs and
   chains to its previous one. Nodes and other devices receive it and apply
   only that node. No log, no leader.
2. A moderator removes a user. `remove(user)` is a command: it commits
   through the log, updates `members`, and emits an epoch node recording
   each of the user's authors' cutoffs, plus an operation hiding their
   posts. All replicas build the identical signed chain node.
3. The removed user's posts at or before a cutoff stay. Later ones are
   rejected, or filtered when read where already applied. Every replica
   reaches the same result.
4. Feed reads use local Merge state on the device or any node.

## 16. Work the spikes and review require

Each item is required for the budget, decision or finding it names;
prototypes exist where noted.

**PVM runtime**

1. Memory structures proportional to mapped pages: the interpreter's page
   table and the JIT's permission sync (S1, S2).
2. Native dirty-page tracking on both backends, including host writes (S1,
   section 6.6).
3. The machine pool and the prepared-program cache, keyed by program hash,
   gated by the pooled-against-fresh differential test (S2).
4. Precompiles on the refine path, BLAKE2b first (S5b; prototype on branch
   `exp/gp-precompiles`). Precompile gas (section 11.2) is decided before
   this lands.
5. Remove every JAR leftover (section 12).
6. JIT host-call exit cost, the main lever on short handlers (section
   6.6).

**Prover and privacy track** (alongside the core slices)

7. Chained segments on the refine path, sized by prover memory (S5, S5b).
8. Reduce the BLAKE2b chip's memory per compression (S5b).
9. Zero-knowledge proving (section 11.4, requirement 1).
10. Witness-free verification of attestable programs, and a hiding input
    commitment (section 11.4, requirements 2 and 3).
11. Window aggregation for on-chain verification (section 11.4,
    requirement 5).
12. Move Ristretto and the scalar operations (ids 110–114) into the VOS
    range, with the `WHAT` fallback in the guest crypto wrappers.

**Storage**

13. The LSM engine: one keyspace, partitions per data class, agent prefixes,
    and reads within budget (S4).
14. The node log writer with capped flushes, non-durable apply under
    section 9.5's invariants, and Raft snapshot export and ingestion
    (S3, S4).
15. The compressed root format across `CommittedMap`, `BatchProof`, the
    witness math and cipher-clerk, with incremental root maintenance (S4).
16. A path for large entries (open question 3), settled before item 14.

**Replication and merge**

17. The vos-raft driver (S3; prototype in `spikes/s3-raft/vos-raft-eager`):
    - group commit and replicate-on-propose;
    - eager commit notification;
    - one shared executor;
    - heartbeats that never wait on log I/O, combined per node pair, with
      quiescence for idle groups.
18. Incremental merkle-crdt apply per sync scope, with local operations in
    place, storage-backed CRDT types and read-time filtering (S6).
19. LZ4-compressed snapshot pages (S1).

**Build order** [proposed]:

1. PVM base: items 1–6, BLAKE2b precompile only.
2. One node: the actor framework, the default agent, the actor ABI with
   run-time enforcement, the LSM engine (item 13), client sessions, and the
   JAM host-call CI harness.
3. Large entries (item 16), then replication: items 14 and 17.
4. The compressed root format and witnessed state reads (item 15),
   workflows and snapshots (item 19), then the first JAM milestone.
5. Attestable methods and Clerk on the prover track's results (items 7–12).
6. The Merge lane (item 18).

The prover and privacy track (items 7–12) starts with step 1, because zero
knowledge and aggregation are the longest work and gate goal 8.

## 17. Reused from earlier code

- **PVM:** the saga's Gray Paper 0.8.0 layer (runtime, JIT, compiler,
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
- From the macros: the `#[actor]` / `#[messages]` shape, roles, schema and
  typed-argument code.
- Clerk actors and cipher-clerk as the flagship application, moved to the
  compressed root format.
- libp2p networking, HTTP and SSH ingress, vosx, native extensions, the
  Substrate light client.

## 18. Open questions

1. Masking and read-time filtering in each CRDT type; property tests for
   the authorization rule.
2. Storage-backed CRDT type design.
3. **Large log entries** (to settle before build step 3):
   - in S3, 64 KiB entries managed only 613 commits/s, cause unknown;
   - snapshot pages (2 MiB on a first compute checkpoint) and witnesses
     ride the log;
   - candidate: content-addressed blobs pinned at propose and replicated
     with the entry that references them.
4. LSM tuning: compaction under sustained writes, cache sizing per node,
   cold reads.
5. The context API of the actor framework (section 6.2).
6. Zero-knowledge proving: the approach in the prover and its chips, and
   its cost.
7. Window aggregation: recursion or another scheme, and its on-chain gas.
8. Refining on any replica with read-set validation: when it becomes
   necessary.
9. Licensing model, metering, bytecode visibility.
10. Agent placement and rebalancing.
11. Upgrades: state migration for actors.
12. JAM witness format; DA retention for long-waiting workflows.
13. Devices running merge handlers locally (local-first) versus thin
    clients.
14. Workflow deadline defaults and timer precision; session expiry
    defaults.
15. Whether workflows need external signals beyond replies and timers.
