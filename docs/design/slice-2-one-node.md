# Slice 2: One node

Plan v1 for build step 2 of `core-model.md` (section 16), on the slice 1
PVM base. Tags as in the core model. This planning run also designs the
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
operands are also what a JAM node carries.

## Host calls

### Agent program and node [proposed]

The agent uses Gray Paper calls wherever JAM has one, and VOS extensions
(in `0x480..=0x4ff`, section 11.2) only where it does not:

| Call | Entry | Id | On VOS | On JAM |
|---|---|---|---|---|
| `fetch` | refine, accumulate | 2 | the batch of inputs, as the work item's payload; accumulate's operands | the same |
| `gas`, `log` | both | Gray Paper; `log` is 100 | served | served |
| `machine` … `expunge` | refine | 9–14 | served | served |
| `instantiate` | refine | `0x480` | from the node's pool | `WHAT`: the agent's loader builds the machine |
| `state_read` | refine | `0x481` | the agent's applied state, by key | `WHAT` until step 4's witnesses |
| `read`, `write` | accumulate | Gray Paper; `write` is 5 | the agent's state in the LSM store | service storage |
| `reply` | accumulate | `0x482` | queued for the client session, sent after the batch is durable | `WHAT`; a JAM client reads results from state |
| `emit` | accumulate | `0x483` | a message into the receiver's inbox, with its pair sequence | `WHAT` until step 4 maps messages to transfers |

- Precompiles keep `0x400..=0x47f`.
- Ids marked "Gray Paper" are pinned in step 2.1 against the 0.8.0
  specification, with a test as for 9–14; SJ confirmed `fetch` (2),
  `write` (5) and `log` (100) on PolkaJam.
- Refine returns the encoded work result. Accumulate receives it through
  `fetch`, as JAM delivers work results to accumulate.
- On VOS, accumulate's `write` calls for one work result form one atomic
  batch, together with the result itself, the session and pair marks, and
  the applied index (section 9.5).

### Actor ABI: actor and agent [proposed]

Actor and workflow host calls exit to the agent program, which serves
them. They use the agent's own block, `0x500..=0x5ff`, so they never meet
a JAM id, a node extension or a precompile id. The agent answers any id it
does not serve with `WHAT`.

| Operation | Id | Command | Query | Attestable |
|---|---|---|---|---|
| `input(buf, cap) -> len` | `0x500` | yes | yes | no |
| `reply(buf, len)`, `fail(code, buf, len)` | `0x501`, `0x502` | yes | yes | no |
| `log(level, buf, len)` | `0x503` | yes | yes | no |
| `caller(buf) -> len` | `0x504` | yes | yes | no |
| `now() -> u64`, `random(buf)` | `0x505`, `0x506` | yes | yes | no |
| `get(key, out, cap) -> len \| NONE` | `0x510` | yes | yes | no |
| `put(key, value)`, `delete(key)` | `0x511`, `0x512` | yes | no | no |
| `scan(prefix, cursor, out, cap) -> len` | `0x513` | yes | yes | no |
| `call(instance, method, args, out, cap) -> len` | `0x520` | yes | queries only | no |
| `send(agent, instance, method, args)` | `0x521` | yes | no | no |

- **Requests reach the actor through `input`:** the agent copies the
  request into the actor's own buffer. No request page is mapped per call,
  which closes slice 1's JIT pooled-cycle miss.
- **Run-time enforcement:** the agent keeps the invocation's kind and
  checks every call against this table. A call outside it fails the
  invocation, and with it the step.
- **Attestable methods** get no ABI at all. Only precompiles run (section
  11.1).

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
- **`Table<K, V>`** keeps rows under the instance's prefix and a table
  tag: point reads and writes, ordered scans with cursors. Memory follows
  the touched rows. Large collections belong in tables, not in the struct,
  whose whole encoding is read on every invocation.
- `CommittedMap` waits for step 4's compressed root format.

### Contexts: the API [proposed; the owner decides]

The context type differs by handler kind, so a query cannot reach a
mutating operation:

```rust
impl Query<A> {        // &self handlers
    fn caller(&self) -> &Principal;
    fn now(&self) -> Timestamp;
    fn random(&self) -> [u8; 32];
    async fn call<R: ActorRef>(&self, to: R, msg: R::Query) -> Result<R::Reply, CallError>;
}

impl Command<A> {      // &mut self handlers; everything a query has, plus:
    async fn call<R: ActorRef>(&mut self, to: R, msg: R::Message) -> Result<R::Reply, CallError>;
    fn send<R: ActorRef>(&mut self, agent: AgentId, to: R, msg: R::Message);
}
```

- `call` reaches an instance of the same agent, nested and synchronous
  (section 8.1). `send` queues a message for any agent, delivered after
  the step commits.
- Typed references (`LedgerRef`) are generated from the schema, as on
  master.
- Tables are fields, used directly: `self.accounts.get(&id)`,
  `self.accounts.insert(id, account)`. The agent serves them through
  `get`, `put` and `scan`.
- Workflows (`Workflow`) and Merge handlers (`MergeContext`) arrive with
  their steps.

### Restrictions checked by the macros

- An `#[attestable]` method takes no context, and touches only fields
  whose type is a committed map. Until step 4 brings `CommittedMap`, an
  attestable method may touch only its arguments.
- A query handler (`&self`) cannot name a `Command`.

## The default agent [proposed]

**Refine,** per batch:

1. Read the batch with `fetch`. Inputs are client requests, in their
   sessions, and messages from other agents, in their pair sequences.
2. Dispatch inputs one at a time, in order (section 6.3). Each is one step.
3. **Load the instance:** `instantiate(program hash)`, or on `WHAT` the
   loader (`machine`, then `pages` and `poke`). Read its struct with
   `state_read`.
4. **Invoke** with the step's gas limit. Serve its ABI calls against the
   step's overlay: reads check the overlay, then `state_read`; writes go
   to the overlay.
5. **Nested calls:** a `call` invokes the callee as its own inner machine,
   with gas drawn from the caller's remaining gas. An instance already on
   the call stack fails the call (cycle).
6. **Finish the step:** on success the overlay, outgoing messages and
   reply join the work result; on any trap the step's effects are
   discarded and an error reply is recorded. The input is consumed either
   way (section 8.1).
7. A step is dispatched only if the refine's remaining gas covers its
   limit; otherwise it waits for the next batch.

**Accumulate,** per work result: `write` each step's writes, advance the
session and pair marks, record the replies in the session windows, and
`emit` outgoing messages.

**The version check** (section 7.5) is trivial on one node: a result is
applied before the next refine starts. Pipelining refines needs the
leader's overlay and arrives with slice 3.

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
  4. hand the work result and accumulate's writes to the storage thread
     as one batch, with the agent's log entry;
  5. after the storage thread reports it durable, send the replies and
     deliver emitted messages.

  The storage thread groups batches from all agents into one fsync.
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
- Bodies are SCALE bytes in this slice. JSON, through the package schema,
  is for the CLI and later clients [open].

## Packages [proposed, minimal]

A package is an actor program blob and its schema (methods, argument and
reply types, handler kinds, gas limits, roles), named by content hash.
Creating an agent and installing a package into it are node commands in
this slice. Signatures, licensing and upgrades come later.

## Steps

### 2.1 Wire types and host-call surface

- `vos-wire`: ids, inputs, the work result, accumulate operands, ABI
  numbers, errors, all SCALE-coded, with round-trip property tests.
- The refine host calls `state_read` and the accumulate calls `reply` and
  `emit` in `vos_pvm`'s refine host, with their JAM fallbacks.
- An accumulate host (`vos_pvm::accumulate_host`) with `fetch`, `read`,
  `write`, `gas`, `log`, `reply`, `emit`.

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

### 2.4 The default agent

- Refine and accumulate as above, as a standard program built with the
  slice 1 toolchain.
- **Tests:** a failed step consumes its input and discards its effects; a
  nested call draws its caller's gas; a cycle fails; an ABI call outside
  the invocation's kind fails it; an unknown id answers `WHAT`.
- **A differential test** against a reference model of the agent's
  semantics over random batches: reply, state and consumed inputs agree.

### 2.5 The node host

- Leader loops, executors, the storage thread, queries.
- One node, many agents: messages between them through the inbox, with
  pair sequences and acknowledgements.
- **Tests:** apply-then-send (no reply before durability); crash and
  restart recover the applied index and resend nothing twice.

### 2.6 Sessions, ingress and the CLI

- HTTP ingress, sessions, the reply window, expiry.
- The CLI: `vos node`, `vos agent create`, `vos install`, `vos call`.
- **Tests:** duplicate and gapped sequences, expired sessions, pipelined
  requests that lose their replies.

### 2.7 The JAM host-call CI harness

- A JAM-only host: Gray Paper refine and accumulate calls; every VOS
  extension answers `WHAT`.
- **Checks:**
  - the agent and actor programs call only JAM calls and VOS extensions
    with a documented fallback (static);
  - a batch that needs no prior state gives the same work result on the
    JAM-only host as on VOS, through the loader and software precompiles
    (dynamic);
  - stateful refines follow with step 4's witnesses.
- Runs in `ci`.

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

## Carried in from slice 1

- Request delivery that keeps the JIT's pooled cycle within 5 µs: `input`
  copies requests, so no page is mapped per call.
- `state_read` writes join the pool's property test.
