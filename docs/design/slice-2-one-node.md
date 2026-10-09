# Slice 2: One node

Plan v2 for build step 2 of `core-model.md` (section 16), on the slice 1
PVM base. v1 was reviewed by the second-opinion reviewer; v2 folds in its
findings, and the owner decided the items it left open (listed at the
end). Tags as in the core model. This planning run also designs the
two items the core model left to it: the node host and native extensions
(open question 18), and the actor framework's context API (open question
5).

## Goal

One VOS node runs agents end to end, on one machine:

1. A client opens a session over HTTP and calls a method on an actor
   instance.
2. The node batches the agent's inputs and runs the default agent
   program's refine.
3. The agent hosts each actor instance as a pooled inner machine, serves
   its calls through the actor ABI, enforces the ABI per invocation and
   nests gas.
4. Accumulate applies the work result to the node's LSM store.
5. The reply leaves only after the result is applied.

The slice delivers:

1. **The actor SDK:** `#[actor]` and `#[messages]` with the master shape,
   the context API, storage-backed `Table<K, V>`, and the compile-time
   restrictions on `#[attestable]` methods (their proving is step 5).
2. **The default agent program:** refine (loader, dispatcher, ABI server,
   run-time enforcement, nested gas, step overlay, work result) and
   accumulate (apply, sessions, replies, outbox).
3. **The node host:** the process, its scheduler across agents, storage
   and its ownership, refine and accumulate host calls, queries, and how
   native extensions attach.
4. **The LSM engine** on fjall (item 14), with reads within budget.
5. **Client sessions and HTTP ingress** (section 8.4).
6. **The JAM host-call CI harness** (section 12).
7. **A minimal CLI:** run a node, create an agent, install a package, call
   a method.
8. **Then item 6:** the JIT's host-call exit cost, profiled on this agent.

Out of scope:

- replication: Raft, the node log writer, many active agents, large
  entries (slice 3);
- workflows, snapshots, timers, `CommittedMap` and the compressed root
  format, witnessed state reads (step 4);
- proving attestable methods, and `instantiate` under proof tracing
  (step 5);
- the Merge lane and `#[msg(merge)]` (step 6);
- SSH ingress, the prover extension and the Substrate light client, which
  attach through the extension host after this slice;
- package signatures and licensing (section 6.4 [open]).

## Crates [proposed]

| Crate | Path | Kind | Contents |
|---|---|---|---|
| `vos-wire` | `agent/wire` | `no_std` | SCALE-coded types shared by the node, the agent and the SDK: ids, inputs, the work result, ABI operation numbers, errors |
| `vos-sdk` | `agent/sdk` | `no_std`, guest | contexts, `Table`, the actor side of the ABI, entry points |
| `vos-sdk-macros` | `agent/sdk-macros` | proc macro | `#[actor]`, `#[messages]`, `#[msg]`, `#[attestable]` |
| `vos-agent` | `agent/default` | guest program | the default agent program |
| `vos-node` | `node/host` | `std` | the node host |
| `vos` | `node/cli` | binary | the minimal CLI |

Wire types use the workspace's SCALE codec (`pvm/codec`), the encoding JAM
uses, rather than master's rkyv: the agent's work result and accumulate
operands are also what a JAM node carries [owner decision 7].

## Host calls

### Agent program and node [proposed]

The agent uses Gray Paper calls wherever JAM has one, and VOS extensions
(in `0x480..=0x4ff`, section 11.2) only where it does not:

| Call | Entry | Id | On VOS | On JAM |
|---|---|---|---|---|
| `fetch` | accumulate | 2 | accumulate's inputs: operands and transfers | the same |
| `gas`, `log` | both | Gray Paper; `log` is 100 | served | served |
| `machine` … `expunge` | refine | 9–14 | served | served |
| `instantiate` | refine | `0x480` | from the node's pool | `WHAT`: the agent's loader builds the machine |
| `state_read` | refine | `0x481` | the agent's applied state, by key | `WHAT` until step 4's witnesses |
| `state_scan` | refine | `0x482` | the agent's applied rows under a prefix, in key order, for the actor ABI's `scan` | `WHAT` until step 4's witnesses |
| `historical_lookup` | refine | 7 | program blobs by hash, for the loader when `instantiate` has no pool | the service's preimages |
| `read`, `write` | accumulate | Gray Paper; `write` is 5 | the agent's state in the LSM store, including its system keys | service storage |

- Precompiles keep `0x400..=0x47f`.
- Ids marked "Gray Paper" are pinned in step 2.1 against the 0.8.0
  specification, with a test as for 9–14; SJ confirmed `fetch` (2),
  `write` (5) and `log` (100) on PolkaJam.
- Refine reads the batch from its arguments, `E(c, i, s, ↕payload, H(p))`
  with the batch as the work item's payload (SJ), so it needs no `fetch`.
  Refine returns the encoded work result. Accumulate receives it through
  `fetch`, as JAM delivers work results to accumulate.
- **Accumulate is pure Gray Paper calls** [owner decision 2]. Replies and
  outgoing messages are `write`s to well-known system keys: the session's
  reply window, and the outbox with its pair sequences. After the applied
  batch is durable, the node sends what it contains. That gives "apply,
  then send" by construction, identical code on JAM (where step 4 maps the
  outbox to `transfer`), and no extension surface in accumulate.
- On VOS, accumulate's `write` calls for one work result form one atomic
  batch, together with the session and pair marks and the applied index
  (section 9.5).
- Every value the agent stores starts with a format byte
  (`vos_wire::records::STORED`): Gray Paper storage deletes a key written
  with an empty value, and the byte keeps empty values, which the actor
  ABI allows, present. Work results carry the values themselves.
- A refine's payload is a `Work`: a batch, or a query, for which refine
  returns the outcome alone and writes nothing.

### Actor ABI: actor and agent [proposed]

Actor and workflow host calls exit to the agent program, which serves
them. They use the agent's own block, `0x500..=0x5ff`, so they never meet
a JAM id, a node extension or a precompile id. The agent answers any id it
does not serve with `WHAT`.

| Operation | Id | Command | Query | Attestable |
|---|---|---|---|---|
| `input(out, offset, cap) -> len` | `0x500` | yes | yes | no |
| `reply(buf, len)`, `fail(buf, len)` | `0x501`, `0x502` | yes | yes | no |
| `log(level, buf, len)` | `0x503` | yes | yes | no |
| `caller(out, cap) -> len` | `0x504` | yes | yes | no |
| `now() -> u64`, `random(buf)` | `0x505`, `0x506` | yes | yes | no |
| `get(key, out, offset, cap) -> len \| NONE` | `0x510` | yes | yes | no |
| `put(key, value)`, `delete(key)` | `0x511`, `0x512` | yes | no | no |
| `scan(prefix, cursor, out, cap) -> len` | `0x513` | yes | yes | no |
| `call(instance, method, args, out, cap) -> len` | `0x520` | yes | queries only | no |
| `send(agent, instance, method, args)` | `0x521` | yes | no | no |
| `attest(method, args, out, cap) -> len` | `0x522` | yes | no | no |
| `self_id() -> (instance, agent)` | `0x523` | yes | yes | no |

- **Registers:** `vos_wire::abi` fixes which register holds each
  argument and result, so the SDK and the agent cannot drift. Outputs
  copy at most the capacity and return the whole length, as the Gray
  Paper's `read`.
- **Requests reach the actor through `input`:** the agent copies the
  request into the actor's own buffer. No request page is mapped per call,
  which closes slice 1's JIT pooled-cycle miss.
- **Run-time enforcement:** the agent keeps the invocation's kind and
  checks every call against this table. A call outside it fails the
  invocation, and with it the step.
- **Attestable methods** get no ABI at all. Only precompiles run (section
  11.1). `attest` runs one as its own inner machine, unproven in this slice
  and with its arguments only, until step 4's committed maps and step 5's
  proofs [owner decision 3]. The call is recorded in the work result for
  step 5.
- **Every operation is priced** in the actor's gas, charged from its frame
  before it is served, as precompiles are: a fixed price per operation
  plus a price per byte copied. A step's gas limit then bounds the agent's
  work too, not only the actor's. Prices are set from the measured serving
  cost in 2.4 [proposed: 500 gas per operation, 1 gas per byte, until
  measured].
- **Per-step caps** [owner decision 5; proposed numbers]: request and
  reply 64 KiB each; one value 64 KiB; a step's writes 256 KiB; one scan
  64 KiB; 16 outgoing messages of 64 KiB each; a work result 4 MiB. They
  are declared in `vos-wire`; an operation that would exceed one fails
  the invocation.
- **Raw ids:** an actor raising a JAM id (2, 9–14) or a node extension id
  (`0x480`, `0x481`) gets `WHAT` from the agent, like any id it does not
  serve, so the table is complete for raw calls.
- **Call depth** is bounded by the 63 inner machines: a `call` that cannot
  get a machine (`FULL`) fails.

## The actor SDK [proposed]

### Shape

The master shape stays: `#[actor]` on the struct, `#[messages]` on the
impl block, `async fn` handlers taking `&self` (query) or `&mut self`
(command), roles as on master. The macro code is rewritten, since master's
generated code targets the v2 service guest.

### State

- **Linear only** in this slice. An instance's struct is its state, stored
  encoded under one key and loaded per invocation. A command writes it
  back if it changed.
- **`Table<K, V>`** keeps rows under the instance's prefix and a tag
  derived from the field's name, which survives reordering fields: point
  reads and writes, ordered scans with cursors. Memory follows the touched
  rows. A `Table` field is a handle, not data: the macro skips it when
  encoding the struct. Large collections belong in tables, not in the
  struct, whose whole encoding is read on every invocation.
- `CommittedMap` waits for step 4's compressed root format.

### Contexts: the API [proposed; the owner decides]

The context type differs by handler kind, so a query cannot reach a
mutating operation:

```rust
impl Query<A> {        // &self handlers
    fn caller(&self) -> Option<Principal>;
    fn me(&self) -> (AgentId, InstanceId);
    fn now(&self) -> u64;
    fn random(&self) -> [u8; 32];
    fn log(&self, level: Level, message: &str);
    async fn call<M: QueryMethod>(&self, to: Ref<M::Actor>, msg: M) -> Result<M::Reply, CallError<M::Error>>;
}

impl Command<A> {      // &mut self handlers; everything a query has, plus:
    async fn call<M: Method>(&mut self, to: Ref<M::Actor>, msg: M) -> Result<M::Reply, CallError<M::Error>>;
    fn send<M: Method>(&mut self, agent: AgentId, to: Ref<M::Actor>, msg: M);
    async fn attest<M: AttestableMethod<Actor = A>>(&mut self, args: M) -> Result<M::Output, CallError<Never>>;
}

enum CallError<E> { Failed(E), Forbidden, Undecodable }
```

- `call` reaches an instance of the same agent, nested and synchronous
  (section 8.1). `send` queues a message for any agent, delivered after
  the step commits. A callee's own error and a role refusal return to the
  caller; any other callee failure fails the whole step, so the caller
  never sees it.
- `#[messages]` generates a module named after the actor holding a type
  per handler, its arguments as fields: `ledger::Transfer { from, to,
  amount }`, sent to a `Ref<Ledger>`.
- Tables are fields, used directly: `self.accounts.get(&id)`,
  `self.accounts.insert(id, account)`. The agent serves them through
  `get`, `put` and `scan`.
- Workflows (`Workflow`) and Merge handlers (`MergeContext`) arrive with
  their steps.
- **Queries see the latest applied work result's time and seed,** so a
  query's `now` and `random` are deterministic for the state version it
  reads.

### Restrictions checked by the macros

- An `#[attestable]` method takes no context, and touches only fields
  whose type is a committed map. Until step 4 brings `CommittedMap`, an
  attestable method may touch only its arguments, and it compiles as its
  own program, which `attest` runs.
- A query handler (`&self`) cannot name a `Command`.

### Roles [owner decision 6]

`#[msg(role = …)]` needs the caller's role before dispatch. In this slice a
per-agent membership table in the `system` partition maps principals to
roles, set by the CLI. The agent reads it with `state_read` and checks the
handler's role before invoking. The space catalog of step 2 or 3 replaces
the CLI as its writer. A role is a byte in the wire format; a package's
schema names its roles, and `#[msg(role)]` refers to one by name. In a
nested call the caller is the calling instance, which holds only the roles
granted to it, none by default.

## The default agent [proposed]

**Refine,** per batch:

1. Read the batch from refine's arguments. Inputs are client requests, in their
   sessions, and messages from other agents, in their pair sequences.
2. Dispatch inputs one at a time, in order (section 6.3). Each is one step.
3. **Load the instance:** `instantiate(program hash)`, or on `WHAT` the
   loader (`machine`, then `pages` and `poke`). Read its struct through
   the read chain below.
4. **Invoke** with the step's gas limit. Serve its ABI calls against two
   overlays:
   - the **step overlay**, the current step's writes, discarded if the
     step fails;
   - the **batch overlay**, the writes of the steps already committed in
     this refine, in order.

   Reads go step overlay, then batch overlay, then `state_read`. Writes go
   to the step overlay. Without the batch overlay, two transfers on one
   account in one batch would both read the base balance.
5. **Nested calls:** a `call` invokes the callee as its own inner machine,
   with gas drawn from the caller's remaining gas, and with the calling
   instance as its caller (`Principal::Instance`). The callee's own error
   (`fail`) returns to the caller and discards the callee's writes, so each
   call level keeps its own overlay above the step's; so does a refusal
   for a role the calling instance lacks. A trap, running out of gas, a
   cycle (an instance already on the call stack) or a missing machine
   fails the whole step (core model section 8.1).
6. **Finish the step:** on success the step overlay folds into the batch
   overlay, and its writes, outgoing messages and reply join the work
   result as that step's lists, in step order. On any trap the step's
   effects are discarded and an error reply is recorded. The input is
   consumed either way (section 8.1).
   **Refusals** are the exception: a request out of its session's order
   or in an expired session, or a message out of its pair's order, is
   recorded as `Refused` and not consumed, so no mark moves past a gap.
   The leader batches only in-order inputs of live sessions; refine
   checks again, since on JAM the builder is not trusted.
7. A step is dispatched only if the refine's remaining gas covers its
   limit; otherwise it waits for the next batch.

**Accumulate,** per work result: `write` each step's writes in step order,
advance the session and pair marks, and write the replies into the session
windows and the outgoing messages into the outbox.

**The version check** (section 7.5) never fails on one node, since a result
is applied before the next refine starts. The work result still carries
the version it read from 2.1 on, so slice 3's check has a field to test.
Pipelining refines needs the leader's overlay and arrives with slice 3.

## The node host [proposed]

This answers open question 18 for one node.

- **One process.** An async runtime (smol, as master's scheduler) for
  ingress and timers; a fixed pool of executor threads for PVM work; one
  storage thread that owns all writes and fsyncs. Storage I/O never runs
  on executor threads (section 9.5).
- **Per agent, a leader loop:**
  1. collect inputs: client requests from sessions, messages from the
     node's inbox;
  2. close a batch by count, bytes or 1–5 ms;
  3. refine on an executor thread, with the node's machine pool;
  4. hand the agent's log entry and accumulate's apply batch to the
     storage thread;
  5. after the storage thread reports it durable, send the replies and
     deliver the outbox's messages from the applied batch.

  The storage thread groups batches from all agents into one fsync.
- **The store API has two operations from the start:** `append(log
  entries)` and `apply(batch with applied index)`. One node commits them
  together; slice 3 commits the log entry by quorum before applying, and
  applies without fsync (section 9.5). The `log` partition is keyed by
  (agent, index) with a term field.
- **Inter-agent messages** always go through the sender's outbox, with
  pair sequences and acknowledgements, even on one node, so slice 3 only
  changes the transport.
- **Admission control** (section 7.1): a cap on queued inputs per agent,
  with "busy" beyond it, and a gas budget per refine.
- **Fairness:** an agent holds at most one executor at a time, and its
  refine's gas budget bounds how long. A long computation therefore delays
  only its own agent.
- **Reads** (`state_read`, queries) run on executor threads against fjall
  snapshots, which are thread-safe. The storage thread owns writes and
  fsyncs only.
- **Storage** (item 14): one fjall keyspace; partitions `state` (Linear
  rows under agent prefixes), `system` (sessions, pair marks, outbox),
  `log` (agent, index → work result), `programs` (package blobs by hash).
- **Queries** run the agent's refine entry in query mode against applied
  state: no writes, the reply only, never through the log.
- **Native extensions** attach as node-side services that agents reach by
  message: an extension has an agent id, receives `send`s in its pair
  sequences and answers with messages. That keeps one mechanism for
  everything that crosses an agent's boundary. The HTTP ingress is a
  built-in node component in this slice. The extension host itself,
  loading SSH, the prover and the Substrate light client, follows after
  this slice.

## Sessions and ingress [proposed]

- `POST /sessions` opens a session; the server assigns its id.
- `POST /agents/{agent}/calls` carries `{session, sequence, instance,
  method, arguments}` and returns the reply once applied.
- Sequences are per (session, agent). Duplicates at or below the mark are
  answered from the reply window; gaps are refused; a request more than W
  ahead of the oldest kept reply waits. Expiry follows work-result time.
- A `Failed` reply means the agent program failed on that request alone:
  it was not consumed and its session's mark did not move, so the client
  resends the same sequence or opens a new session. The reply window
  never holds a `Failed`.
- Bodies are SCALE bytes in this slice. JSON, through the package schema,
  is for the CLI and later clients [open].
- **Defaults** [owner decision 4; proposed]: a reply window W of 64 per
  (session, agent); sessions expire after one hour of work-result time
  without a request; a handler's gas limit is 10M by default, declared per
  handler in the schema; a refine's budget is 1G gas.

## Packages [proposed, minimal]

A package is an actor program blob and its schema (methods, argument and
reply types, handler kinds, gas limits, roles), named by content hash.
Creating an agent and installing a package into it are node commands in
this slice. Signatures, licensing and upgrades come later.

## Steps

### 2.1 Wire types and host-call surface

- `vos-wire`: ids, inputs, the work result, accumulate operands, ABI
  numbers, errors, all SCALE-coded, with round-trip property tests.
- The refine host call `state_read`, with its JAM fallback, in `vos_pvm`'s
  refine host; the Gray Paper ids pinned by test.
- An accumulate host (`vos_pvm::accumulate_host`) with `fetch`, `read`,
  `write`, `gas` and `log`.
- **The JAM-only host:** the same refine and accumulate hosts with every
  VOS extension answering `WHAT`. The default agent runs against it from
  2.4 on.
- The work result's fields, including the version read, per-step lists and
  the `attest` record; the per-step caps; the ABI prices.

### 2.2 Storage (item 14)

- fjall behind a `Store` trait: partitions, agent prefixes, atomic
  batches, ordered scans, snapshots for queries.
- **Reads within budget:** S4 measured 5.2–5.6 µs at 10M rows; the slice
  tunes key layout, filters and cache size to reach ≤ 5 µs warm.
- Benchmarks at 1M and 10M rows; a crash test that the applied index and
  state recover as one prefix.

### 2.3 The actor SDK

- Macros, contexts, `Table`, the ABI client, entry points.
- A test actor set: a counter, the S2 ledger actor rebuilt on the SDK, an
  actor that calls another, and an attestable method.
- Compile-fail tests for the restrictions.

**Implementation decisions** [reviewed]:

1. **Handlers are `async fn`,** with `.await` on `call` (core model
   section 6.3), so a later concurrent scheduler needs no change to actor
   code. In this slice `call` returns an already-ready future, since the
   agent runs the callee while the caller's machine waits at its
   `ecalli`, and the entry point drives a handler with a no-op waker.
2. **The program entry.** An actor program is a standard program. The
   agent invokes it at instruction 0 with φ7 the method id, φ8 the kind (0
   command, 1 query, 2 attestable) and φ9 the arguments' length; arguments
   come through `input`, the outcome through `reply` or `fail`, and the
   program halts. φ8 is a hint: the agent enforces the kind regardless.
3. **Method ids and table tags** are the first four bytes, big-endian, of
   BLAKE2b-256 over a domain and a name (`vos/method/<name>`,
   `vos/table/<name>`): stable when items are reordered, and the same in
   any language. A table's name defaults to its field's and can be set
   with `#[table(name = "…")]`, so renaming a field need not orphan its
   rows. The macros reject an id of 0 (reserved) or a collision within an
   actor; the fix is an explicit name.
4. **The schema is static data in the program:** a `.vos_schema` section,
   which the linker script places first in read-only data, holds `"VOSS" ∥
   E4(len) ∥ SCALE(schema)`: methods with their id, kind, role name and
   requested gas limit. The agent reads it with `peek` after loading the
   program, the same on VOS and JAM, and the node and the CLI parse it
   from the blob without running anything. Installing validates it:
   unique ids, valid kinds, sizes under the caps. Gas limits are requests,
   capped by the agent's policy. Role names come from the schema; the
   operator maps them to role bytes at install (`Admin::Install`), since
   role bytes belong to the agent and two packages in it must agree on
   them.
5. **State.** The struct lives at the instance-relative key `0x00`; a
   command loads it (or `new()` when absent), runs, and writes it back if
   its encoding changed; a query only loads it. Table rows live at `0x01 ∥
   tag ∥ key`, so every key is non-empty by construction. Table keys use an
   order-preserving `TableKey` encoding (big-endian integers, raw fixed
   arrays, a raw byte string only as the last component), so scans run in
   key order; values are SCALE.
6. **Crates.** `vos-sdk` (`no_std`): the ABI client (inline `ecalli` on
   the guest target; elsewhere a native host function, `vos_sdk::host::Host`,
   installed with `set_host`), contexts, `Table`, and the guest runtime
   (allocator, panic as trap). `vos-sdk-macros`: `#[actor]`, `#[messages]`,
   `#[msg]`, `#[attestable]`. An actor is a library, which other actors
   use for its message types, and a program crate of one line,
   `actor_program!(ledger::ledger)`, which places the schema and defines
   the entry point; an attestable method's program is likewise
   `attestable_program!(ledger::Ledger::__vos_attest_checksum)`. The
   library carries no entry, so a program links only its own.
7. **A native test host** (`agent/testkit`, `std`) runs actor programs in
   `vos_pvm` and serves the actor ABI against an in-memory state with the
   step and per-call overlays. 2.3's tests run the test actors on it, and
   2.4's differential test uses it as the reference model. It implements
   the semantics from this plan and the core model and shares no overlay,
   dispatch or enforcement code with the default agent; the two crates do
   not depend on each other.
8. **`attest` names an attestable method, not a program.** A package is an
   actor program, its attestable programs and the schema (core model
   section 6.4); installing binds each attestable method id to its
   program's hash, and refuses a package whose attestable programs are
   missing. `ATTEST` takes the method id, and the agent resolves it
   through the instance's package, so neither an actor nor a client can
   substitute another program. An attestable program is a standard program
   with no host calls at all, precompiles aside: its arguments arrive in
   the standard argument window, and it returns its output by the halt
   convention (address and length in φ7 and φ8).

### 2.4 The default agent

- Refine and accumulate as above, as a standard program built with the
  slice 1 toolchain.
- **Tests:**
  - a failed step consumes its input and discards its effects;
  - a later step in a batch sees an earlier step's writes;
  - a nested call draws its caller's gas, and every ABI operation is
    charged;
  - a cycle fails, and so does a call that cannot get a machine;
  - an ABI call outside the invocation's kind fails it, and an unknown id
    answers `WHAT`;
  - each per-step cap fails the invocation when exceeded;
  - a handler whose role the caller lacks is refused before invocation.
- **A differential test** against a reference model of the agent's
  semantics over random batches: replies, state and consumed inputs
  agree. The model encodes the two-level overlay, the one property it most
  needs to check.
- **On the JAM-only host,** the same tests run through the loader and with
  no `state_read`, for the batches that need no prior state.

### 2.5 The node host

- Leader loops, executors, the storage thread, queries.
- One node, many agents: messages between them through the inbox, with
  pair sequences and acknowledgements.
- **Tests:** apply-then-send (no reply before durability); crash and
  restart recover the applied index and resend nothing twice; "busy"
  beyond the queued-input cap.

#### Design [reviewed]

**Threads.** One async thread (smol) runs every agent's leader loop and
message delivery. A fixed pool of executor threads runs PVM work (refine,
accumulate, queries); each job reads a fresh store snapshot. One storage
thread owns commits: it takes every commit queued, writes them in one
fjall batch, syncs once, and reports each commit durable.

**A batch, per agent, strictly in order:**

1. The leader takes queued inputs, up to 256 inputs or 1 MiB of
   arguments. Inputs queue while a batch is in flight, so the next batch
   starts as soon as the previous commit is durable; only when the queue
   was empty does the leader linger, up to 2 ms after the first input.
2. Refine on an executor: `Work::Batch { version, time, seed, inputs }`,
   with the node's machine pool and a `StateReader` over the snapshot.
   `time` is wall-clock milliseconds, never below the agent's last; `seed`
   comes from the operating system. Both are in the work result, so the
   log replays deterministically.
3. Accumulate on an executor, over the snapshot with the writes it makes
   recorded in order and read back by its later reads (the pair and
   version counters it updates): these are the apply batch.
4. The storage thread appends the work result as log entry `applied + 1`
   (term 0, so slice 3's entries have the same shape) and applies the
   writes, in one commit. The node's applied index and the agent's
   `version` advance in that commit; recovery checks they agree. A leader
   waits on its commit, which is the node's backpressure, alongside the
   queue cap.
5. Only once that commit is durable: each request's step answers its
   caller; inputs past the last step return to the front of the queue;
   the agent's new outbox entries are delivered; each applied message is
   acknowledged to its sender.

A batch that fails commits nothing, and who failed decides what follows.
When the agent program fails it (a trap, out of gas, an output that does
not decode), the batch returns to the queue at half its length, and so
on until one passes, which isolates the input that breaks it: a request
alone answers `Failed`; a message or ack alone is dropped and reported,
which leaves its pair for an operator. When the node fails it (a read, a
backend, a panic on an executor), no input is to blame: the batch
returns to the queue whole and the leader waits, from 50 ms doubling to
5 s, before trying again. A failed commit is not retried: fjall then
refuses every later commit, so the node stops every agent and needs a
restart. An accumulate that skips the result means the agent's state is
not at its leader's version; that agent stops. A panic in a leader stops
that agent only.

**Shutdown** lets each leader finish its batch in flight. Queued inputs
are dropped and their callers see `Stopped`; storage loses nothing, since
only durable batches were ever answered.

The node's refine gas covers `REFINE_GAS`, and checks at start that the
largest handler limit with the agent's reserves fits it, so every input
can be dispatched.

**Acknowledgements are agent inputs.** Only an agent's accumulate writes
its state, so the outbox is cleared by a new input, `Input::Ack { to,
sequence }`: agent `to` has applied this agent's messages through
`sequence`. It is unsequenced and never refused; refine passes it through
as a step that runs no actor. Accumulate applies it monotonically: it
clears the outbox from the `acked(to)` mark through `sequence`, stopping
at what was sent and after `ACK_LIMIT` entries, and advances the mark; a
stale ack does nothing. The node sends an ack when a target applies a
message, when it drops a duplicate, and again while the mark trails what
it acknowledged.

**Delivery and recovery.** A message reaches its target's queue unless
its sequence is at or below the target's pair mark; then it is a
duplicate, dropped and acknowledged with the mark. A message refine
refuses with `SEQUENCE` is a duplicate if its sequence is at or below the
mark, acknowledged so; above the mark it is a gap, dropped without an ack
for the sender's next delivery. In-process queues are reliable, so a
message is delivered once per process and redelivered only from the
outbox at start: there is no resend timer. Slice 3 adds resend timers and
a per-pair window of messages in flight. On start, the node
reads its agent registry (`system`, node keys), restores each agent's
version and applied index from storage, and delivers every agent's
outbox entries above its `acked` mark. One node commits the log entry and
the apply together, so there is nothing to replay. A crash after a commit
loses that batch's replies, which the reply window serves in 2.6, and its
deliveries and acks, which recovery redoes. Duplicates are dropped by
the pair marks, so no message applies twice.

**Admission.** Client requests are capped per agent (1,024 queued by
default); beyond the cap a call answers busy at once. Messages and acks
are not capped, to drop none: each sender's outbox bounds what it sends,
but not what a target receives from many senders [open: slice 3's
per-pair window].

**Queries** run on an executor with the machine pool and a fresh snapshot,
and never enter the leader's queue or the log.

**Programs.** Installing commits the blobs to `programs` and installs
them in the machine pool, then queues the install. On start, the node
installs every stored program in the pool. Refine also answers
`historical_lookup` from `programs`. A crash before the install's own
commit loses only the queued install, which the client sends again.

**API (`vos_node::Node`).** `open(path, config)`; `create_agent`;
`install(agent, instance, blob, attestables, roles)`; `set_role`;
`call(agent, request)`, answering the step or busy; `query(agent,
query)`; `shutdown`. The agent program is a configured blob, the default
agent linked as a standard program. Tests inject faults through a hook:
hold a commit, stop a leader after a commit and before it sends, make a
refine fail, or deliver a message out of order.

**Tests** (`node/host/tests/node.rs`): calls and state across a restart; no
reply while a commit is held; busy at the cap; two agents exchanging
messages, outboxes cleared by acks; queries see applied state and leave
the log unchanged; a failing refine isolates its input and requeues the
rest. Exactly once, each case followed by a restart:

- a stop after the sender's commit, before delivery: recovery delivers;
- a stop after the target's commit, before its ack: recovery redelivers,
  the target drops the duplicate and acks;
- redelivery while the sender sends more: the target applies each once,
  in order;
- a gap (3 before 2): refused, not acked; then 2 and 3 apply.

### 2.6 Sessions, ingress and the CLI

- HTTP ingress, sessions, the reply window, expiry.
- The CLI: `vos node`, `vos agent create`, `vos install`, `vos call`.
- **Tests:** duplicate and gapped sequences, expired sessions, pipelined
  requests that lose their replies.

### 2.7 The JAM host-call CI harness

The JAM-only host exists from 2.1 and the agent's tests run on it from
2.4. This step adds:

- a static check that the agent and actor programs call only JAM calls and
  VOS extensions with a documented fallback. The VOS refine allow-list
  omits `fetch`, `historical_lookup` and `export`, which a JAM refine may
  use; the check decides whether the node answers them (`NONE`) rather
  than refuse such a package;
- the dynamic comparison of work results between VOS and the JAM-only host
  in `ci`. Stateful refines follow with step 4's witnesses.

### 2.8 JIT host-call exit cost (item 6)

Profile a real batch on this agent, then cut the cost of an inner
machine's host-call exit and re-entry.

### 2.9 Acceptance

Measure against section 14, on one node with storage:

| Budget | Threshold |
|---|---|
| Actor invocation, refine and accumulate | ≤ 50 µs |
| Fixed cost per refine | ≤ 50 µs |
| Pooled actor acquire, use and reset (slice 1's carried gate) | ≤ 5 µs, JIT included |
| Table point read or write at 10M rows | ≤ 5 µs |
| Query | ≤ 100 µs |
| Per-step caps, admission ("busy"), reply window and expiry | each enforced, in tests |

## Gates

| Gate | Threshold |
|---|---|
| Slice 1 | `just ci-full` stays green |
| ABI enforcement | every operation outside an invocation's kind fails it, in tests |
| Agent semantics | the differential test against the reference model passes |
| Apply, then send | no reply or message leaves before its result is durable |
| JAM harness | passes in `ci` |
| Budgets | as in 2.9 |

## Risks

- **The context API** is the surface every actor is written against.
  Getting it wrong is expensive later; hence the owner's review of the
  proposal above.
- **Struct state loaded per invocation** costs in proportion to its
  encoding. The guideline (collections in tables) keeps it small; a
  lazily loaded struct is the fallback.
- **fjall reads** were slightly over budget in S4. If tuning does not reach
  5 µs, a read cache in the node is next.
- **Run-time enforcement and nested gas** sit in the agent program, which
  is guest code: a bug there is a bug in every agent. The differential
  test and the enforcement tests are the guard.
- **ABI prices** are placeholders until 2.4 measures the serving cost; set
  too low, a step's limit stops bounding the agent's work.

## Carried in from slice 1

- Request delivery that keeps the JIT's pooled cycle within 5 µs: `input`
  copies requests, so no page is mapped per call.
- `state_read` writes join the pool's property test.

## Decisions [decided by the owner]

1. **The context API** as in "Contexts".
2. **Replies and messages in accumulate** are `write`s to system keys;
   accumulate uses Gray Paper calls only.
3. **`attest` is in this slice,** unproven and with arguments only.
4. **Defaults:** reply window 64, session expiry one hour, handler gas 10M,
   refine budget 1G (open questions 14 and 16), as constants that are
   cheap to change.
5. **Per-step caps:** the numbers under "Actor ABI".
6. **Roles:** a per-agent membership table in `system`, set by the CLI,
   until the space catalog.
7. **SCALE** (the JAM encoding) for wire types, instead of master's rkyv.

Technical choices the review accepted as they are: the private ABI id
block, `input` copying requests, Gray Paper calls wherever JAM has them,
the thread model, extensions as message-addressed services, the fjall
partitions, queries in query mode, and the crate split.
