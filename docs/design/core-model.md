# VOS core model

Draft 5 (2026-10-08). Drafts 3 and 4 were each reviewed by a second-opinion
architecture review, and the owner decided the questions they raised.
Measurements come from the run 3 spikes in `spikes.md`, cited by name:
S1–S6, S5b and SJ. Tags:

- **[decided]**: confirmed by the project owner, or settled by a spike the
  owner delegated the choice to;
- **[proposed]**: recommendation awaiting review;
- **[open]**: left for a later run.

This is the model for a new core built on branch `vos-core` (from master
`d2378274`). The v2 service layer on master, the saga's agent layer and
everything specific to JAR are not ported; section 17 lists what is reused.

## Changes from draft 4

- **Agents on JAM are public** [decided]. They hold global data that spaces
  agree on, such as one agent per space holding the space's aggregate
  balance, or a collective in which each space's agent votes. They verify
  proofs but produce none. Privacy lives inside VOS spaces (sections 1, 12).
- **Attestable methods are restricted, and the macro enforces it**
  [decided]. They read only their arguments and committed fields, use no
  context, and return their writes privately to the enclosing command
  (section 11.1).
- **Gas is nested** [proposed]. A callee draws from its caller's
  remaining gas, and a step is dispatched only if the refine can cover its
  limit, so outcomes never depend on batch packing (section 8.1).
- **Preemption keeps steps atomic** [proposed]. An effect-free workflow
  step stays live across refines. Once a step has effects, it runs under a
  fixed limit to the end of the step (section 8.3).
- **Sessions keep a window of replies,** use server-assigned ids that are
  never reused, and refuse expired sessions (section 8.4).
- **Committed roots are built in the background** from dirty keys, off the
  apply path (section 9.3).
- **Leaves are salted,** and published proofs carry nothing beyond the
  public output and a fixed shape class (sections 9.3, 11.4).
- **Proofs are verified at ingress,** before a claim enters the log
  (section 11.1).
- **Merge authors are chains per (key, principal),** with fresh keys after
  a crash or restore (section 9.4).

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
8. Early JAM integration. Agents on JAM hold public, global data that
   spaces agree on, and verify proofs from spaces. For example:
   - one agent per space holds the space's aggregate balance, so value
     moves between spaces while accounts inside each space stay private;
   - a collective in which each space's agent votes;
   - subscriptions.
9. Simplicity and performance are the deciding criteria.

## 2. Non-goals for v1

- Byzantine faults inside a space.
- Re-verifying local storage, or results produced by other nodes of the same
  space.
- Proving anything not marked `#[attestable]`.
- Replay-based durable execution.
- Encrypted private agents with key rotation.
- JAR compatibility.
- Privacy for agents on JAM: their state is public by design.
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
- Agents on JAM are public. Spaces trust their state as far as JAM's
  consensus goes, and never put private data there.

## 6. Agents and actors

### 6.1 Agent program [decided shape, proposed details]

A Gray Paper 0.8.0 standard program with two entries: refine (IC 0) and
accumulate (IC 5).

- **Refine** uses JAM's refine host calls (gas, fetch, historical_lookup,
  export, machine, peek, poke, pages, invoke, expunge, log) plus VOS
  extensions, each with a JAM fallback:
  - `state_read`: the agent's state at the refine base. On JAM, served from
    a witness carried in the work package.
  - `instantiate(code_hash)` (id `0x480`): a machine from the node's pool
    (section 6.6), laid out as the standard layout with no arguments. It
    costs what laying the machine out costs in `machine`, `pages` and
    `poke` calls. On JAM, the unknown id returns `WHAT`, and the agent's
    loader builds the machine with those calls into the same layout.
  - snapshot page access and dirty-page capture. On JAM: imports, exports,
    and peek-and-hash.
  - precompiles (section 11.2). On JAM, the unknown id returns `WHAT` and
    the guest computes in software.
- Proofs from other spaces are verified at ingress on VOS, before refine
  sees them. On JAM, the agent runs the verifier program in refine (section
  11.1).
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

    /// Proven: reads its arguments and committed fields only, no context.
    /// Arguments and state stay private; the return value is public.
    #[attestable]
    fn settle(&mut self, window: Window) -> Settlement { /* ... */ }

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
  `now`, `random`, the caller's identity and logging (section 6.5). The
  context type differs by handler kind, so a query cannot reach a mutating
  operation.
- **Attestable methods take no context.** The macro rejects any use of
  fields that are not committed maps, and any call outside the method
  (section 11.1).
- The v1 API is decided in `slice-2-one-node.md` ("Contexts").

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
| call an `#[attestable]` method (section 11.1) | yes | no | no | yes |

- **The agent enforces this table per invocation at run time.** A raw host
  call outside the invocation's kind fails the invocation.
- **Unknown ids:** the agent answers any id it does not serve with `WHAT`,
  as a JAM node does. That includes a precompile id an inner machine
  raises on JAM.
- **Inside an attestable method,** the agent serves no ABI at all. Only
  precompiles run (section 11.1).
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
    about 1.4 µs. Slice 1's pool resets only the pages written since the
    last reset: acquire plus reset after a use costs 2.4 µs on the
    interpreter and 3.5 µs on the JIT for S2's actor.
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
  aborts as one step: if any part traps, runs out of gas or forms a cycle
  (A calls B calls A), nothing commits. Two outcomes return to the caller
  instead: a callee's own error (`fail`), whose writes are discarded while
  the caller's survive, and a refusal because the caller lacks the
  callee's role, in which the callee never runs. A nested callee sees the
  calling instance as its caller, not the original client, so an instance
  is never a confused deputy; an instance holds roles only where granted.
- It may send messages to other agents and start workflows, but may not
  wait for them.
- **Gas is nested** [proposed]:
  - Each step has a fixed gas limit, declared per handler with an agent
    default.
  - A nested call draws its gas from its caller's remaining gas, so a
    step's total never exceeds its limit.
  - The agent dispatches a step only if the refine's remaining gas covers
    the step's limit; otherwise the step waits for the next refine.

  Exceeding the limit fails the step, the same way however the batch was
  packed.
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
  gas does not delay a latency-sensitive agent's batches. They call
  `checkpoint()` explicitly around their effects (section 8.3).

### 8.3 Snapshots and preemption [decided: snapshots are the only continuation mechanism]

- A snapshot is: program hash, program counter, registers, gas, and the page
  table (page index → page). Pages are 4 KiB. Zero pages and pages
  unchanged from the program image are not stored.
- On VOS, a snapshot is taken when a workflow step ends.
- **Preemption** [proposed]. A step's atomicity never depends on gas:
  - **Effect-free:** a step has no effects until its first call, send or
    workflow start. Until then it may be preempted when its refine's gas
    share runs out. The machine stays live, no snapshot is taken, and the
    step continues in the next refine. After failover it re-runs from the
    last snapshot, which is safe because nothing escaped.
  - **Effectful:** before the first effect, the agent checks that the
    refine's remaining gas covers the step's fixed limit for that phase;
    otherwise it preempts the still effect-free step there. From the first
    effect on, the step runs to its end within that limit and is never
    preempted. Exceeding the limit fails the step.
  - No uncommitted writes are ever held across refines. A long computation
    that must make effects calls `checkpoint()` before and after them.
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
  - For a client session, the receiver also keeps the replies of the last
    W sequence numbers, so a client that pipelines requests can recover
    any lost reply. A request more than W ahead of the oldest kept reply is
    refused until the client catches up.
- **Client sessions:**
  - **Ids:** a client names its session: its key, a random 128-bit name
    and a creation time t0, in every signed request (slice 3, owner's
    decision). The triple is the session's identity. The agent creates a session only if t0 is within a skew of
    the batch time, and collects one only once it has expired and the
    batch time is past t0 plus the skew, so a collected session is never
    created again. Caps on live sessions refuse new ones and never evict.
    This relies on batch time never going backwards: the agent keeps a
    replicated high-water mark that refine never goes below.
  - **Sequences** are kept per (session, receiver agent), so requests to
    different agents never leave gaps in each other's sequence.
  - **State:** the high-water mark and the window of replies, kept until
    the session expires after inactivity. Expiry is computed from
    work-result time, never a local clock. State is O(active clients), not
    O(requests).
  - **Expiry:** a request in an expired session, or naming an absent one
    whose t0 is stale, is refused with "session expired" and never
    executed. The client starts a new session and decides itself whether
    to resend.
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
| `#[attestable]` | inside a command or workflow step | committed fields only, returned privately and applied by the caller | its arguments and committed fields, through witnesses |

- The macros generate a view per mode, so misuse fails to compile.
- The agent also enforces the modes at run time (section 6.5).
- A command does not see its own Merge operations until after commit.

### 9.3 Tables and committed maps [decided]

- `Table<K, V>` (with map, set and vector variants) stores rows in the
  agent's keyspace: point reads and writes, ordered scans with cursors.
  Memory use follows touched rows, not table size. At 10M rows (slice 2,
  warm cache), writes cost 2.2–2.9 µs and compacted reads 2.5 µs, within
  the 5 µs budget; reads behind fresh writes in the memtable and level 0
  cost 5.0–5.2 µs.
- `CommittedMap<K, V>` also yields a Merkle root and multiproofs
  (`BatchProof`) for attestable methods and JAM witnesses. Only branching
  nodes are stored: about log₂(n) rows per key path.
- **Compressed root format** [decided]:
  - a leaf hash commits a domain tag, the fixed-width key, the leaf's salt
    and H(value);
  - a branch hash commits a different domain tag, its split level and both
    children;
  - spines through empty levels are never hashed;
  - variable-length keys are hashed to a fixed width first;
  - the empty map has a defined root;
  - verifiers check that split levels strictly increase along a path and
    fit the key width;
  - **salted leaves** [proposed]: each row stores a salt of 16 bytes, so a
    root or a path never lets anyone guess low-entropy values. The salt
    is deterministic for every replica: it comes from the work result, or
    from a keyed function of a space secret and the key. A local random
    source would give each replica a different root (section 9.5,
    invariant 5).
    Keys and the tree's shape remain visible in any path that is shared,
    so paths stay private witnesses.

  Non-inclusion of a key k is shown by the leaf for a different key k′
  that k's path reaches. An update costs 8–25 hashes (3–8 µs at 1M–10M
  keys), against 100–280 for the fixed-depth format it replaces (S4). The
  change moves together through `CommittedMap`, `BatchProof`, the witness
  math, the attestable kernels and cipher-clerk (`merkle.rs`,
  `state_root.rs`, `succinct.rs`, `snapshot.rs`), which the owner cleared
  to change.
- **Root maintenance** [proposed]:
  - Accumulate only records each committed write's key as dirty, one row
    each, so the apply path stays at table cost.
  - A deterministic background task builds node rows in sorted batches
    from a storage snapshot at an exact applied index, off the apply
    thread. Batches of 10,000 rewrite 7–10 node rows per update; single
    updates rewrite 20–24 (S4).
  - An attest waits for the root at its window's applied index.

  Maintaining node rows inside accumulate would cost about 35–45 µs per
  committed write (8–25 hashes plus 20–24 row writes at about 1.5 µs).
  That would cap a ledger at about 12k transfers per second per agent,
  below the replication budget.
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
- **Authors** [proposed]:
  - An author is a chain of signed nodes under one key for one principal:
    (device key, principal) or (node key, principal). A thin client's
    `#[msg(merge)]` operation goes on the chain of the node that ran it,
    for that principal. Removing a user never cuts off other users of the
    same node.
  - A node takes a fresh author key on every start, and a device on every
    install or restore. A crash or a backup therefore never reuses a
    sequence number under an old key.
  - The scope's membership maps principals to their author chains.
- **Authorization rule** (starting design, to be property-tested):
  1. A membership change is a Linear step that emits an epoch node E_n.
     E_n cites the Merge heads the leader had applied at that point.
  2. Removing a principal records, for each of its author chains A,
     cutoff_A: A's latest node among those heads, identified by its CID.
     Removals are Linear steps issued by a member whose role allows it.
  3. Every author node is signed, carries the author's sequence number (the
     previous node's plus one, linked to it) and has an epoch node in its
     causal past.
  4. A replica accepts A's node only if A was a member at that epoch, and
     the node is an ancestor of or equal to cutoff_A for every later epoch
     that removed A. Re-admission at epoch r requires E_r in the node's
     causal past.
  5. Two nodes on one author chain with the same sequence number are an
     equivocation. Both stay in the DAG, because other authors' nodes may
     cite them, but their operations are filtered when read, and the
     chain's key is removed.
  6. Operations invalidated by a later epoch are filtered when read, by
     (author chain, position relative to the cutoff), not unapplied. Lists
     and sets need nothing else. An LWW map keeps the latest write per
     (key, author chain), and a read takes the latest among unfiltered
     chains.

  The decision depends only on the log and the DAG, so every replica
  agrees. It costs O(1) per operation with per-author epoch intervals.
- **Merge-only agents** have no log only if they have no Linear state, no
  workflows, no outbox and no membership. Any scope with members needs a
  log, because epochs and removals are Linear steps. `#[msg(merge)]`
  handlers cannot send messages or start workflows.

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

S4 measured reads at 5.2–5.6 µs at 10M rows with a 1 GiB warm cache (redb:
1.6 µs), and about 0.1 ms cold. Slice 2 brought compacted reads to 2.5 µs
by skipping last-level filters where reads mostly hit (step 2.2); reads
behind fresh writes stay at 5.0–5.2 µs, and steady-state read cost under
continuous writes is slice 3's measurement.

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
one atomic batch without fsync. This is safe under seven invariants:

1. The batch includes the new applied index.
2. State and log share the one journal, so after a crash the store
   recovers a consistent prefix: an apply batch is never durable without
   the log write before it.
3. Only entries committed by quorum are applied, never the leader's
   pending overlay.
4. Local log truncation stays at or below the durable applied index. An
   exported Raft snapshot may come from any consistent applied index.
5. Accumulate reads no local clock or other node-local input.
6. Snapshot ingestion is fsynced before the applied index that depends on
   it is recorded.
7. A blob that an entry references (large work results, programs,
   snapshot pages, witnesses) is durable on a replica, verified against
   its hash, before that replica counts the entry durable, the leader
   included.

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
  191 ms at 64, and leaders were lost at 1,000 (section 14; work item 16).
- Rebalancing uses membership changes (joint consensus exists in vos-raft).

## 11. `#[attestable]` [decided intent and direction; sizes proposed]

### 11.1 Mechanism [decided: restricted methods; details proposed]

- An `#[attestable]` method is compiled into its own small program and
  shipped in the package. It is pure: it uses no context and makes no calls,
  sends, `now` or `random`; only precompiles run inside it. The macro
  enforces this.
- **Inputs** (private): its arguments, plus the committed fields it reads,
  delivered as witnesses (rows plus a `BatchProof` against `CommittedMap`
  roots). Plain fields and tables have no root, so the macro rejects any
  use of them.
- **Outputs:**
  - **public:** the return value, the roots before and after, and the
    program hash;
  - **private:** its writes to committed fields, bound by the root after.
    The enclosing command applies them as ordinary writes.
- A live call runs that same program as an inner machine, so what runs is
  what gets proven. The agent records the program hash, the witness and the
  output with the agent's replicated state. The record is internal to the
  space, so losing the producing node cannot make a settlement window
  unprovable.
- Proving is asynchronous, by a prover inside the space's trust domain
  (section 11.4). Proofs are content-addressed and attached to messages
  for other spaces or JAM.
- **Verification** [proposed]:
  - On VOS, the receiving node verifies a proof at ingress, where trust
    changes, before the message enters the log. Refine sees only verified
    claims, and a batch never stalls on a verification that takes seconds.
  - On JAM, an on-chain agent's refine runs the verifier program itself,
    and its accumulate applies the public output. The settlement verifier
    takes 10.68M instructions and about 29M gas under Gray Paper 0.8.0 for
    one segment (slice 1). A whole window needs aggregation (section 11.4).

### 11.2 Precompiles [decided direction; prototyped in S5b]

- A precompile is an `ecalli` host call with a VOS-owned id in
  `0x400..=0x47f`, outside every id JAM assigns (the Gray Paper calls, and
  JIP-1 `log` at 100). BLAKE2b compression is `0x400`. VOS extension calls
  take `0x480..=0x4ff` (`instantiate` is `0x480`). The whole block
  `0x400..=0x4ff` should be reserved through a JIP, because a future Gray
  Paper id in it would silently break the fallback.
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
- **Gas** [decided; delegated by the owner]:
  - Results are promised identical only for runs that complete. Whether a
    run exhausts its gas depends on the environment: a hash costs about 66
    steps on VOS and about 4,760 on the JAM fallback, and the `gas` call is
    observable.
  - JAM tooling budgets gas at fallback cost, from per-call counts recorded
    on VOS.
  - VOS prices each precompile, and the prover binds that price wherever a
    proof binds final gas. A BLAKE2b compression costs 600 gas, from its
    native serving cost (slice 1).
- **Cost per BLAKE2b compression** (S5b): 66 steps plus about 35 ms and
  50 MiB of proving. Hashing in the PVM costs about 4,760 steps, 0.4 s and
  800 MiB per hash. The marginal cost rises near a slice's memory cap:
  about 20 ms per compression up to 100 calls, 46 ms between 200 and 400.

### 11.3 Cost and size guideline [proposed]

- **Prover memory per segment** ≈ 4.6 GiB + 170 KiB × steps + 39 MiB ×
  compressions (S5, S5b). Steps include the 66 a compression takes, so a
  compression costs about 50 MiB in all. Segments are sized to the prover's memory, not to
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
  - Kernels hash tree nodes with the compress-level call (one block for a
    76-byte node). The streaming `blake2b_hash` in the shim costs about 325
    steps per hash (slice 1, S5b rerun), five times the target's 66, which
    would put a 1,000-transfer window at 15–33M steps.

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
   attestable run depends on is proven in the AIR. Attestable methods are
   pure (section 11.1), so their only host calls are precompiles, which
   are already in-AIR (S5b).
3. **No plain hash of private inputs** in anything published.
4. **A minimal published format.** A published proof carries only:
   - the public output: the return value, the roots and the program hash;
   - a fixed shape class.

   Today's bundle also carries the gas limit, host boundaries and
   per-slice machine states, which must stay out.
5. **Fixed shape classes:** segment counts and trace sizes are padded to a
   few canonical shapes (the existing canonical-shape work), so a proof
   does not reveal how busy a window was.
6. **Window aggregation** for on-chain verification. A window is many
   segments, and it must fit a JAM work package and the on-chain verifier's
   gas.

Around the proof:

- **The prover runs inside the space's trust domain.** It sees every
  witness, so proving is never outsourced to a party outside the space.
- **Leaves are salted** (section 9.3), so published roots do not let anyone
  guess low-entropy values.
- **Agents on JAM are public by design** (section 12). Private data stays in
  VOS spaces; only proofs and their public outputs reach JAM.

These form a prover track that runs alongside the core slices (section 16).

## 12. JAM integration [decided: early]

- **What runs on JAM** [decided]: public agents holding global data that
  spaces agree on. They verify proofs from spaces and never produce any.
  For example:
  - **Cross-space value transfer:** one agent per space holds the space's
    aggregate balance. A space proves a settlement window, and its agent
    moves the net amounts between space agents. Inside each space,
    accounts stay private, so the space works like a mixer to the outside.
  - **Collectives:** each space joins through an on-chain agent that
    represents it and votes.
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
- **Next:** the per-space aggregate-balance agent that accepts settlement
  proofs (Clerk settlement), once the privacy track's aggregation exists.

## 13. Portability [decided direction]

- **`no_std + alloc` core crates:** wire types, the agent and actor SDK, the
  PVM interpreter and inner machines, vos-raft, merkle-crdt, storage traits
  and the proof verifier.
- **`std` adapters at the edges:** the LSM engine, libp2p, the JIT and
  ingress.
- **Nodes may require Linux ≥ 6.7** [decided], for userfaultfd-based
  dirty-page tracking, if slice 1's measurement picks it.
- A future bare-metal light client runs Merge replicas and proof
  verification on the interpreter.
- The shared-executor Raft driver keeps vos-raft's core free of threads.

## 14. Performance budgets [decided; measured in run 3 and slices 1 to 3]

| Path | Budget | Measured | Status |
|---|---|---|---|
| Actor invocation, refine and accumulate, one node | ≤ 50 µs | the default agent on one node with fjall storage, counter increments under load: 21–24 µs per request on the JIT, 85 µs on the interpreter, plus a 0.9 ms synced commit per batch of 165–210 requests (slice 2) | passes on the JIT; the interpreter, kept for tracing and platforms without the JIT, misses |
| Committed-map write on the apply path [proposed] | ≤ 5 µs; background root building keeps up with apply | not yet measured; node rows in accumulate would cost 35–45 µs (S4) | needs background roots |
| Fixed cost per refine [proposed] | ≤ 50 µs; pooled acquire and reset ≤ 5 µs; a new machine ≤ 50 µs | an empty refine on a kept agent machine 13 µs (JIT) and 10 µs (interpreter); pooled acquire, use and reset 1.6 and 1.1 µs; a new machine 7–10 and about 32 µs (slices 1 and 2) | passes |
| Replicated agent on 3 LAN nodes, simple mutations | ≥ 20k per second per agent; p99 commit ≤ 10 ms at half load | three node processes over QUIC, signed calls over HTTP (slice 3). The most, closed loop at 256 sessions: 18.6–19.5k/s on the reference pinning, 19.7–20.1k/s with the leader on cores of its own. The half-load p99, open loop: 6.7–14.2 ms in five runs (one of four over HTTP within 10 ms, 8.2 ms over HTTPS), and 7.0–10.9 ms in four with cores of its own (three within 10 ms). The prototype driver's 25k/s at p99 8 ms (S3) was one process, unsigned | at the edge on the laptop: capacity just short or just met; the half-load p99 not met reliably; awaiting a machine of its own |
| Many active agents per node [proposed] | 64 active agents: ≥ 40k commits per second in total, p99 ≤ 20 ms | three node processes, reference pinning (slice 3): 33.9k/s most at 16 sessions each (p99 45 ms); open loop p99 6.8 ms at 20k/s and 106 ms at 25k/s, so the knee lies between; closed, the nodes 4.6–5.3 of their 6 logical CPUs busy, hyperthreads included | misses on the laptop; awaiting a machine of its own and the owner's contract levers |
| Workflow snapshot capture plus restore, up to 50 KB | ≤ 1 ms | 3-page suspensions: capture 0.2–0.6 µs (interpreter) and 8–12 µs (JIT, quiet machine; 6–19 µs under load), copying and hashing the pages 10–15 µs, writing them into a pooled machine 0.3 µs (excluding its reset on return, 2.4–3.5 µs, and loading registers, gas and counter); a 2 MiB suspension takes 150–190 µs and about 400 µs to write (slice 1, S1) | passes |
| Table point read or write at 10M rows (host cost) | ≤ 5 µs | write 2.5–3.3 µs; read 2.5–3.2 µs compacted, 5.0–5.2 µs with 620k fresh updates in the memtable and level 0, about 0.1 ms cold (slice 2); read under the 64-agent run's writes at 31–32k inputs/s, over a whole memtable cycle, at the store: mean 2.68–2.72 µs, p99 3.70–3.81 µs, against 2.29–2.34 and 3.54–3.68 alone (slice 3, two runs) | passes compacted and under continuous writes; at the edge behind a bulk of fresh writes to the table itself |
| Query on a follower | ≤ 100 µs | through a node's query path (executor round trip, snapshot, refine in query mode, one actor): median 49 µs and p99 115–175 µs on the JIT, median 87 µs on the interpreter (slice 2); a follower of three processes (two runs over HTTP, one over HTTPS): p50 0.12–0.23 ms, p99 0.22–0.34 ms client to answer, 86–92 µs of the follower's CPU a query; linearizable, p50 0.36–0.41 ms and 244 µs (slice 3) | open: met at the median, missed at p99; the percentile is the owner's call |
| Request latency on a quiet node [proposed] | ≤ 5 ms at p99 | one request at a time on one node: about 3 ms in process, the batch's 2 ms linger plus a 0.9 ms synced commit; its execution, 260–340 µs, is idle-core cost (slice 2); three processes over HTTP, one call at a time: p50 2.7 ms, p99 3.3 ms (slice 3) | passes |
| Merge apply, cost per operation at 1M operations | ≤ 2× the cost at 1k | 1.5–1.8× with incremental apply on LWW maps, in memory (S6) | passes with section 16 work |
| 1,000 mostly idle Raft groups per node | no thread per group; idle CPU ≤ 5% of one core | about 1.6% at a 500 ms heartbeat (S3); three node processes with 1,000–1,065 groups each: 1.0–1.4% of one core, 16–17 threads (slice 3) | passes |

- All measurements ran on one laptop (Core Ultra 7 155H, consumer NVMe),
  with all three replicas sharing one disk and a warm page cache. Runs
  with many active agents varied up to 4×.
- Slice 3's rows ran three release node processes, their stores on
  tmpfs, a driver signing every call before its window, and two
  pinnings:
  - **the reference:** each node on two hyperthread pairs of P-cores
    and two E-cores;
  - **cores of its own:** the leader on two P-cores whose siblings stay
    idle, and two E-cores.

  Refine an input costs about 40 µs on the reference pinning against
  17–20 µs in one process, so a machine of its own may move the
  replicated rows. The slice 3 progress log has every run.
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
   `#[attestable]` method. Its program runs live on witnessed committed
   rows, hashing through the precompile, and returns the `Settlement` plus
   its private writes, which the command applies. The witness and record
   are replicated with the agent.
2. The space's prover proves the window asynchronously, in segments sized
   to its memory, aggregates them and publishes the proof. Only the
   `Settlement` return value, the roots and the program hash are public,
   in a fixed shape class.
3. A bridge instance sends the claim and proof to bank B's space. B's
   ingress verifies it before it enters B's log, and B's agent credits the
   account.
4. On JAM, each bank's space has an agent holding the space's aggregate
   balance. It verifies the window proof in refine and moves the net
   amounts between space agents in accumulate. Individual accounts never
   appear on JAM.

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

## 16. Work the spikes and reviews require

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
   `exp/gp-precompiles`), priced in VOS gas (section 11.2).
5. Remove every JAR leftover (section 12).
6. JIT host-call exit cost, the main lever on short handlers (section
   6.6). Tuned once a real agent exists to profile (build step 2).

**Prover and privacy track** (alongside the core slices)

7. Chained segments on the refine path, sized by prover memory (S5, S5b).
8. Reduce the BLAKE2b chip's memory per compression (S5b).
9. Zero-knowledge proving (section 11.4, requirement 1). It needs a newer
   Stwo, and moving Stwo also frees the workspace toolchain: the pinned
   revision builds only on nightlies up to mid-2025.
10. Witness-free verification of attestable programs, with no plain hash of
    private inputs (requirements 2 and 3).
11. The minimal published proof format and fixed shape classes
    (requirements 4 and 5).
12. Window aggregation for on-chain verification (requirement 6).
13. Move Ristretto and the scalar operations (ids 110–114) into the VOS
    range, with the `WHAT` fallback in the guest crypto wrappers.

**Storage**

14. The LSM engine: one keyspace, partitions per data class, agent prefixes,
    and reads within budget (S4).
15. The node log writer with capped flushes, non-durable apply under
    section 9.5's invariants, and Raft snapshot export and ingestion
    (S3, S4).
16. Many active agents per node within budget: writer batching, liveness
    and executor scheduling under load, with a test of 64 or more active
    agents (S3, section 14).
17. The compressed root format with salted leaves, across `CommittedMap`,
    `BatchProof`, the witness math and cipher-clerk; dirty-key recording
    in accumulate and background root building (S4, section 9.3).
18. A path for large entries (open question 3), settled before item 15.

**Replication and merge**

19. The vos-raft driver (S3; prototype in `spikes/s3-raft/vos-raft-eager`):
    - group commit and replicate-on-propose;
    - eager commit notification;
    - one shared executor;
    - heartbeats that never wait on log I/O, combined per node pair, with
      quiescence for idle groups.
20. Incremental merkle-crdt apply per sync scope, with author chains, local
    operations in place, storage-backed CRDT types and read-time filtering
    (S6, section 9.4).
21. LZ4-compressed snapshot pages (S1).

**Build order** [proposed]:

1. **PVM base:** items 1–5, BLAKE2b precompile only.
2. **One node:** the actor framework with restricted attestable methods,
   the default agent, the actor ABI with run-time enforcement and nested
   gas, the LSM engine (item 14), client sessions, and the JAM host-call
   CI harness. Then item 6, profiled on this agent.
3. **Replication:** large entries (item 18) first, then items 15, 16 and
   19.
4. **JAM:** the compressed root format and witnessed state reads (item
   17), workflows and snapshots (item 21), then the first JAM milestone.
5. **Attestable methods and Clerk,** on the prover track's results (items
   7–13).
6. **The Merge lane** (item 20).

The prover and privacy track (items 7–13) starts with step 1, because zero
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
5. ~~The context API of the actor framework (section 6.2).~~ Decided for
   v1 in `slice-2-one-node.md`.
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
14. Workflow deadline defaults and timer precision; session expiry and the
    reply window W.
15. Whether workflows need external signals beyond replies and timers.
16. Default gas limits per handler kind, and how an agent declares them.
17. The JAM agents' designs: the per-space aggregate-balance agent (how a
    space's net positions settle, and what a mixer-like space reveals by
    its flows), and collectives that vote.
18. **The node host and native extensions:** designed for one node in
    `slice-2-one-node.md`; what remains open is the extension host itself
    and its multi-node form:
    - the node process and its scheduler across agents;
    - storage and networking ownership;
    - ingress;
    - how native extensions attach: the HTTP and SSH transports, the
      prover, the Substrate light client. On master they are small
      capability adapters behind an extension host.
