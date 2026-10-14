# Slice 4: Workflows, committed state and JAM

Plan v3 for build step 4 of `core-model.md` (section 16):
- the compressed root format and witnessed state reads (item 17);
- workflows and their snapshots (sections 8.2 and 8.3, item 21);
- the first JAM milestone (section 12).

It also takes the items slice 3 carried to it. It builds on slice 3's
replicated node (`slice-3-replication.md`) and on S1 and SJ
(`spikes.md`). v1 was reviewed for soundness (Fable) and against the
code (Opus), and v2 folded both. v3 folds the review of the owner's
two changes: scans on JAM, and preemption at the awaits. Tags as in the
core model.

## Goal

1. **A workflow runs end to end on a replicated agent:**
   - a client starts it;
   - it calls an actor of its own agent, then asks another agent and
     awaits the reply;
   - meanwhile its leader is killed. The new leader resumes it from its
     snapshot;
   - it completes, and the client reads its result.
   - Every effect happens exactly once.
2. **An agent's committed map yields a root and proofs:**
   - accumulate records only which keys changed;
   - each replica builds the same root in the background.
3. **On a JAM testnet,** the default agent and one actor run as a
   service. A workflow suspends in one work package and resumes in a
   later one, and every state read is witnessed against the root on
   chain.

The slice delivers:

1. **Requests and replies between agents.** Today a message is sent and
   forgotten.
2. **The compressed tree:** the format, proofs and updates, in a
   `no_std` crate.
3. **`CommittedMap<K, V>`:** in the SDK, its rows, dirty keys recorded
   in accumulate, and the node's background root builder.
4. **Workflows:** the SDK's `#[workflow]`, the default agent's workflow
   table, snapshots captured and restored with Gray Paper calls alone,
   and deadlines and timers. Under them: the work result's blob path,
   `instantiate` at a counter, and the agent's tracked writes.
5. **JAM mode in the default agent:** witnessed reads, the root before
   and after, and snapshot pages through export and import segments.
6. **A builder,** which prepares and submits the agent's work packages
   to a JAM node.
7. **The carried items:**
   - a message that fails in refine;
   - fast retransmit;
   - fan-in, measured;
   - `#[msg(linearizable)]`;
   - the agent serving its machines' precompiles.

Out of scope:

- **Proving.** Attestable methods reading committed fields, and
  cipher-clerk's move to the new format, go to slice 5 with the prover
  track [owner decision 1].
- **Messages between agents on JAM** (transfers and their memos), and
  re-exporting pages before DA retention ends.
- The Merge lane (step 6), the catalog, pipelined refines.

## What earlier slices leave

- **The loader** (`agent/default/src/machines.rs`):
  - it acquires a pooled machine with `instantiate`;
  - where that is not served, it builds the machine with `machine`,
    `pages` and `poke` from `historical_lookup`, as a JAM node would.
- **Inner machines** (`pvm/runtime/src/inner.rs`) follow Gray Paper
  0.8.0:
  - `pages` allocates, frees, and sets read-only or read-write;
  - a read from an unmapped page exits `Fault(address)`, and the machine
    resumes once the page is allocated (tested on both backends). A
    write to a read-only page repaired by `SetReadWrite`, the loop this
    plan uses, looks supported on both backends but is untested;
  - `poke` into a read-only page fails, as Gray Paper requires;
  - `expunge` returns the program counter;
  - `instantiate` always starts a pooled machine at counter 0, where
    `machine` takes a counter.
- **Dirty-page tracking** exists in the runtime on both backends
  (`take_dirty_pages`), but nothing exposes it to an agent program.
- **The JAM-only host** (`RefineContext::try_run_jam`) and the CI
  surface check (`agent/testkit/tests/agent/hosts.rs`):
  - VOS and JAM refines agree, byte for byte, on batches that read no
    state;
  - `state_read` and `state_scan` are `NoResult` on JAM, so a refine
    that reads state traps;
  - in refine, `fetch`, `export` and imports are served nowhere
    (accumulate serves `fetch`);
  - an inner machine's precompile writes its output in place, and the
    agent answers `WHAT` on JAM.
- **Messages between agents:**
  - `Command::send` is fire-and-forget;
  - pair sequences, the outbox, acknowledgements and resend windows
    exist (`leader.rs`: 256 entries or 1 MiB a window, a round of 1 s
    doubling to 16 s);
  - no reply exists.
- **The sweep:** the node puts `Input::Sweep` first in a batch when the
  first expiry row is due. This is the one place where time alone
  starts a batch. It is the node's as much as the agent's: the leader
  decodes the expiry keys to time it (`leader.rs`), and refine scans
  the expiry index.
- **Blobs carry only programs.** A work result always travels inline in
  its log entry, whatever its size; the consensus frames are sized for
  a 4 MiB result. Step 3.1 found an inline 4 MiB entry beside small ones
  costs the small ones' p99 (263 ms against 15 ms), so large snapshots
  need the result's blob path, which this slice builds.
- **Programs beside an actor's** come from a crate of their own: an
  attestable is compiled by `attestable_program!` in a separate crate,
  and installed as `(MethodId, ProgramHash)` beside the actor.
- **Prototypes:**
  - S1's workflows (`pvm/bench/guests/workflows`, the `snapshots` bench
    binary) with LZ4;
  - S4's two radix trees (`spikes/s4-tables`);
  - SJ's echo service and its metadata tool (`spikes/sj-jam`);
  - PolkaJam binaries in `~/bin/polkajam/`, but 0.1.27 on Gray Paper
    0.7.2: SJ's 0.8.0 nightly is gone, so 4.0 fetches a current one.
- **On `master`, the committed map to port:**
  - `vos/src/actors/storage/committed.rs` (value rows, node rows at
    branching points, a root row);
  - `vos/src/zk/state.rs` (`BatchProof`);
  - both on the fixed-depth format this slice replaces.
- **Open from slice 2 (step 2.7):** an inner machine's precompiles reach
  the agent, which answers `WHAT` on JAM, so the actor's software
  fallback spends different gas there. Batches that run actors cannot be
  compared across hosts until the agent serves the precompiles itself.

## Design

### Messages between agents: requests and replies [proposed]

A workflow awaits other agents, so a message needs a reply. Section 8.4
fixes the mechanism: a reply is a sequenced message on the reverse pair,
already in the sender's outbox, so the receiver keeps no reply cache.

- **Wire:** a `Message` carries a body:
  - `Call { instance, method, arguments, awaiting: Option<Await> }`;
  - `Reply { awaiting: Await, outcome }`.
  - `Await` names the awaiting workflow and its await counter.
- **The receiver** runs a `Call` like today's message. When the call
  carries `awaiting`, its step adds a `Reply` with the handler's outcome
  to the sender's outbox, whether the handler succeeded or failed. A
  refusal (no such method, the caller lacks the role) replies too.
- **The sender** consumes a `Reply` in its pair sequence like any
  message:
  - it resumes the awaiting workflow;
  - if the await is gone (its deadline passed, or the workflow failed),
    the reply is consumed and dropped (section 8.1).
- `Command::send` keeps its form and never awaits. Only a workflow
  requests.
- **A request to a workflow** answers twice:
  - at once, with `Reply::Started(id)` to the request's await;
  - on completion, with its result, to a second await the starter
    names when it waits for the result.
  - A starter's deadline then bounds each wait, never the callee's
    whole run.

**A message that fails in refine** (carried):
- Today the leader bisects a failing batch until one input fails alone,
  answers a client request, and drops a message without acknowledging
  it. The sender then resends that message every round, forever.
- Instead, the leader proposes it as `Input::Failed { from, sequence,
  awaiting }`, never the body, which is never run. Refine does not run
  it. It records a consuming step, as section 8.1 requires
  of a failed step:
  `Step::Ran(Run { outcome: Failed { code: FAILED }, writes: [], .. })`,
  with an error `Reply` among its messages when the message awaited one.
  `Step::Refused` would not do: accumulate applies nothing for it, so
  the pair mark would stay. Through that `Run`:
  - accumulate advances the pair mark;
  - the leader acknowledges it, as any `Ran` step;
  - an awaiting sender gets the error reply.
- Deterministic, because the batch itself says the input failed.
- **Once in the log, the message is consumed for good,** so the leader
  asserts it only when the message fails alone twice, each on a fresh
  storage snapshot. A transient failure then never consumes a message.
- **A client request that fails alone stays as it is:** answered
  `Failed` and not consumed, so the client decides whether to retry.

**Fast retransmit** (carried):
- A receiver that refuses a gap answers the sender with `Behind`.
- **A message dropped past a full queue gets no `Behind` while the queue
  stays full,** so the rounds' backoff holds when the receiver is
  overloaded.
- **Once the queue drains of other agents' messages,** the receiver sends
  a `Behind` to the senders it dropped, in arrival order:
  - as many at a time as their windows fit (4 by default);
  - the next ones at the 100 ms pace while it stays idle.
  - The fan-in bench (4.7) showed that dropped senders otherwise sit out
    their backoff, up to 16 s, while the receiver idles.
- **`Behind` is a trigger, not a cursor:**
  - the sender rewinds its window to the acknowledgement at once, as a
    due round does (`Window::rewind`), instead of waiting for the round;
  - it never moves to a sequence the frame names. A stale `Behind`
    therefore only resends what the receiver drops at its mark;
  - it is accepted only from a replica of the receiving agent, as
    `Deliver` and `Acknowledge` are;
  - one rewind per window per 100 ms at most, so a receiver that keeps
    refusing cannot make the sender resend a whole window per message.
    A `Behind` that comes sooner is deferred to that moment, not
    ignored, so a drain's `Behind` is never lost to the pace.
- Rounds stay as the fallback when `Behind` itself is lost.

**Fan-in and batching across agents** (carried): measured first.
- A bench: N agents on two nodes send to one agent on a third, and to
  each other in pairs.
- Combining the deliveries of several agent pairs to one node into one
  frame is built only if the bench shows frames, not refine, bound it.
  It did not (4.7): the receiver's refine bounds fan-in, at 97–98%
  busy, with about 1.1 frames a message when nothing drops. So it is
  not built.

### The compressed tree [decided format; proposed details]

A crate `agent/tree` (`vos-tree`, `no_std + alloc`). Its users:
- the node's root builder;
- the default agent on JAM;
- the builder;
- in slice 5, the attestable kernels and cipher-clerk.

**Hashing:** BLAKE2b-256, through a `Hasher` trait:
- natively on the node;
- through the precompile shim in PVM programs, which falls back to
  software on JAM.

**Format** (section 9.3):
- **One tree format over prefix-free key strings.** A row's key in the
  tree is `key' = prefix ‖ transform(key)`, and each table chooses its
  transform, as a Substrate map chooses its hasher [owner decision 8,
  hashed by default]:
  - **hashed,** the default: `H128(key) ‖ escape(key)`, as Substrate's
    `Blake2_128Concat`. Depth stays near log₂ n whatever keys clients
    choose. The table iterates, whole or from a cursor, in hash order,
    and the raw key stays in the row key for the scan to return;
  - **ordered,** `Table<K, V, Ordered>`: `escape(key)`, as Substrate's
    `Identity`. The table scans in key order, with ranges. Its keys are
    capped at 64 bytes, so a path through it is at most about 1,040
    levels deep: about 5M gas for a witnessed read on JAM at worst;
  - **private,** in slice 5: `H(key)` alone, for maps whose proofs leave
    the space. A shared path then hides its neighbours' keys, and the
    map does not iterate.
- **Why per table:** an ordered key lets whoever chooses keys make paths
  deep (a chain k, k‖0, k‖00, … grows a level per insert). With 1 KiB
  keys one witnessed read on JAM could cost about 78M gas, a dozen of
  them a package's whole budget. So only a table that needs key order
  takes it, with short keys.
- **The same order on both hosts:** a table's value rows on VOS are
  keyed by the same `key'`, so a scan returns rows in the same order on
  VOS and JAM, and the refines agree byte for byte.
- **Every row key is prefix-free,** which JAM's whole-keyspace tree
  needs: every table's rows move from `prefix ‖ raw key` to
  `prefix ‖ transform(key)` in 4.3, not only committed maps', and every
  system row's key under its prefix is fixed-width or escaped.
- **Refine computes `key'`,** through the precompile on VOS and in
  software on JAM, so accumulate writes rows by the keys the work result
  names and never hashes.
- **`escape`** is prefix-free and keeps byte order: each `0x00` becomes
  `0x00 0xFF`, then `0x00 0x00` ends the key.
  - `0x00 0x00` never occurs inside an escaped body, and no body ends
    in a lone `0x00`, so no encoded key prefixes another.
  - At the first differing byte, nonzero bytes compare as they did, and
    `0x00 0xFF` sorts below any nonzero byte.
  - A key that prefixes another continues with `0x00 0x00`, which sorts
    below both continuations of the longer key.
- **Ordered scans** on VOS read the value rows, in the tree's order. The
  tree serves roots and proofs.
- **A leaf:** `H(TAG_LEAF ‖ len(key') ‖ key' ‖ vh)`, with the value
  committed as `vh = H(TAG_VALUE ‖ salt ‖ value)`. It does not depend on
  its depth. The salt sits inside `vh`, so a proof that opens a
  neighbour's leaf (every absence and range proof does) shows `vh`,
  never a hash of the bare value that a low-entropy guess could match.
- **A branch:** `H(TAG_BRANCH ‖ level ‖ left ‖ right)`. `level` is the
  first bit where its two subtrees' keys differ, a big-endian `u16`.
  Empty levels are never hashed.
- **The empty tree's root:** `H(TAG_EMPTY)`.
- **Deleting a leaf** replaces its parent branch with the sibling. A
  leaf's hash does not depend on its depth, and a branch's commits its
  own level, so the sibling's hash does not change.

**Proofs:**
- `BatchProof` is a multiproof for a set of keys. Each key is proven:
  - present (its leaf);
  - or absent, by the leaf for another key that its path reaches. A tree
    of branching nodes has no empty child, so only the empty tree proves
    absence by `H(TAG_EMPTY)`.
- The proof holds the sibling hashes the paths need, each once, in a
  canonical order.
- `verify(root, proof, claims)` checks the claims. Along each path the
  verifier checks:
  - that levels increase strictly and stay within the key's bits;
  - that at each branch, the key's bit at that branch's level selects
    the child taken.
- **Range proofs:** `RangeProof` shows that the leaves it holds are
  every key in `[from, to)`. Its boundaries are leaves, never a cursor's
  path: a cursor between keys has no leaf, and below the branch its
  path reaches, a sibling given as a hash cannot show which side of the
  cursor it lies on.
  - **Boundaries:** the predecessor of `from` (the largest key below
    it) and the first key at or past `to`, as leaves, or the tree's edge
    on either side.
  - **The proof:** the two boundary paths with their outside siblings
    as hashes, and every subtree between them in full, down to its
    leaves.
  - **The verifier checks** predecessor < `from` ≤ the first leaf
    included, the last leaf included < `to` ≤ successor, and the
    leaves in order. It then rebuilds the root, so a leaf left out
    changes it.
  - **An empty range:** the two boundary leaves are adjacent, with
    nothing between their paths, and they bracket the range. In an
    empty tree, the root `H(TAG_EMPTY)`.
  - **A bounded scan,** from a cursor, of at most `limit` rows, is the
    range from the cursor to just past the last row returned. When
    fewer than `limit` came back, it runs to the end of the scanned
    prefix: the successor of the encoded prefix in byte order (the last
    byte below `0xFF` incremented, the rest dropped), or the tree's right
    edge when there is none.
  - **`update` works over a range proof,** whose subtrees are complete,
    so refine writes inside a range it scanned.
- `update(proof, writes) -> root` computes the root after inserting,
  changing and deleting the proven keys. It needs nothing beyond the
  proof: an insert's path ends at the leaf (or the empty root) that
  proved the key absent. This is the witness math that JAM refine and
  attestable runs both use.

**Salts** [owner decision 2]:
- `salt` = the first 16 bytes of `H(TAG_SALT ‖ seed ‖ key')`, from the
  work result's seed: 16 bytes, as section 9.3 has it.
- One function, computed where the leaf is built: by the root builder on
  VOS, from the seed of the version that wrote the row; in refine on
  JAM, where `update` needs it and the batch carries the seed.
- The builder stores the salt in the key's leaf row, so a later proof
  needs no old seed.
- Every replica derives the same salt, and so does a re-apply.
- The salt changes on every write, so equal values in different rows or
  versions never share a leaf hash.
- No space secret is needed. The work result carries the seed and stays
  inside the space, so salts hide values exactly as far as the seed is
  kept: inside the space. A leader can bias the seed (section 8.5); a
  biased salt is still a salt, and nothing rests on its entropy beyond
  the space.

**Tests:**
- property tests over random sequences of inserts, changes and deletes;
- every root checked against a from-scratch build of the same set;
- every proof verified, and every tampered proof refused;
- `update` from proofs agreeing with direct updates;
- the in-PVM build (precompile, and the software fallback) agreeing
  with the native one.

### `CommittedMap<K, V>` [decided type; proposed rows]

- **In the SDK:** a field type like `Table<K, V>`, with the same point
  reads, writes and scans, and the same choice of key transform. A
  handler never sees a root: on VOS the root is built after commit.
- **The ABI marks its writes as committed,** so the step's `Run` carries
  them apart and accumulate knows which rows to mark dirty.
- **No hashing on the apply path.** The accumulate host serves no
  precompile, so a software hash per write would break the budget.
  Refine computes `key'` (the transform), the work result names rows by
  it, accumulate writes rows only, and the native builder computes the
  salts and the tree.
- **Rows** in the agent's keyspace:
  - **value rows:** `c/<map>/<key'>` → `(version, value)`, the version
    that wrote it, in the tree's order;
  - **dirty rows:** `d/<version>/<map>/<key'>`, written in accumulate
    beside each committed write, under the state version the write
    makes, version first so a build seeks straight past the rows
    earlier builds deleted. One row each, so the apply path stays at table cost (section
    9.3). The version keeps a later write's row apart from an earlier
    one's, so consuming the rows through one version never deletes a
    newer row;
  - **seed rows:** `s/<version>` → the work result's seed, one per
    version that wrote a committed row, kept until the builder has
    consumed that version;
  - **the builder's rows,** which accumulate never writes:
    - node rows `n/<map>/<level><prefix>` at branching points;
    - leaf rows `l/<map>/<key'>` → `(salt, vh)`: what a proof needs
      once the seed row is gone;
    - a root row `r/<map>` → the tree's current top, and its last
      complete root with the version it is complete through;
    - one watermark row: the version every map is built through, so one
      build covers every version past it;
- **The root builder** runs on every replica:
  - it takes a storage snapshot at the agent's state version V;
  - it reads the dirty rows past the watermark through V, in batches of
    10,000 keys, deduplicated and sorted by key, and holds no more than
    a batch: each batch deletes the dirty rows it read, and the seeds of
    the versions it has read whole, so a build's memory and its commits
    never grow with a backlog;
  - it computes each dirty key's salt from the seed row of the version
    that wrote it;
  - **one invariant carries correctness:** every leaf and node row
    whose subtree holds no dirty key matches the value rows;
  - each batch recomputes the whole path of each of its dirty keys,
    from the key's value row at V and the stored hashes of the
    subtrees beside the path, which hold no dirty key or are
    recomputed in a later batch for V;
  - every row on a recomputed path is overwritten, or deleted where an
    insert or delete moved the branching point, and a deleted key's leaf
    row goes with it, so no row is left off the tree for a proof to walk
    into;
  - each batch is one commit through the node's writer. The root row
    for V, and the deletion of exactly the dirty and seed rows through
    V, go with the last batch for V. Apply never touches node rows, so
    the commits race nothing.
  - **Each commit carries the epoch it read,** and the writer refuses it
    once the agent's epoch has moved (a snapshot switch or a
    retirement). So node rows built on an old epoch never land in a new
    one.
  - It is deterministic: the state at V is the same on every replica,
    so the root is too.
  - **After a crash** it catches up at some V' ≥ V. A key stays dirty
    until the last batch for its version commits, so the keys an
    interrupted build touched are still dirty through V', the invariant
    still holds, and the catch-up rewrites every row that build may
    have left.
  - It runs on the executor, off the apply path.
  - A Raft snapshot carries the builder's, dirty and seed rows with the
    rest of the keyspace. The builder restarts on a new epoch.
- **Proofs on VOS:** `Node::prove(agent, map, keys)` answers a
  `BatchProof` against the latest root and its version. Slice 5's attests
  wait for the root at their window's index (section 9.3).
- **Budget** (section 14): a committed write costs at most 5 µs on the
  apply path, its value row and its dirty row included (two rows at
  about 1.5 µs each, so the margin is thin), and the builder keeps up
  with apply at the replicated row's rate.

### Workflows [decided semantics (8.2, 8.3); proposed shape]

**In the SDK:**

```rust
#[workflows]
impl Shop {
    #[workflow]
    async fn checkout(ctx: &mut Workflow<Self>, order: Order) -> Result<Receipt, Error> {
        let held = ctx.call(stock, stock::Hold { items: order.items }).await?;
        let paid = ctx
            .request(bank_agent, bank_ref, bank::Charge { amount: held.total })
            .within(Duration::from_secs(30))
            .await?;
        Ok(Receipt { paid })
    }
}
```

- **A workflow takes no `self`:** it holds no shared state, only its
  own memory (section 8.2).
- **Its own program,** built as attestables are: the macro emits the
  workflow's entry, a crate of its own builds it (`workflow_program!`,
  as `attestable_program!`), and the install carries it in the list of
  programs beside the actor, `(MethodId, ProgramHash)`, with a workflow
  kind. It is pinned with the install's other programs.
- **`Workflow<A>`:**
  - `call`: a same-agent instance, nested and synchronous, as in a
    command;
  - `send`;
  - `request(..).within(d)`: another agent. It ends the step and awaits
    the reply until the deadline;
  - `start(..)` and `result(id).within(d)`: a workflow of another agent,
    started, then its result awaited;
  - `sleep_until(t)`;
  - `now`, `random`, `log`.
- **Every `.await` is a point where the workflow may pause** and return
  control to its agent [owner decision 5]. There is no `checkpoint()`:
  - an await on another agent, or on a timer, always pauses;
  - an await on a same-agent `call` pauses only when the workflow's
    share of the refine's gas is spent; otherwise the step goes on;
  - so the code between two awaits runs atomically, as async Rust
    already suggests, and a pause commits the effects made before it
    with the snapshot.
- **The guest needs no executor.** A pausing call is a host call that
  does not return until the agent resumes the machine, possibly in
  another process after a restore, so `block_on`'s single poll
  completes.
- **Starting** [owner decision 3, for clients and agents alike]:
  - a client request or an agent's `Call` naming a workflow starts one;
  - the start answers `Started(id)` at once: a client's reply, or an
    agent's first `Reply` (section "Requests and replies");
  - its result is read by id, with an optional wait: by the client that
    started it (its session's key is the workflow's owner), or by the
    starting workflow, which awaits the result as a second await;
  - a command's `send` that starts a workflow gets no reply.

**In the default agent:**
- **The workflow table** (system rows):
  - `w/<id>` → `Workflow { program, owner, state, snapshot }`:
    - `state`: running, awaiting an await with its deadline, sleeping
      until a time, done with its result, or failed;
    - `snapshot`: program counter, registers, gas, and the pages it
      holds, each with its hash;
  - `p/<id>/<page>` → the page, LZ4-compressed.
- **A live workflow pins its program,** one pin per workflow, counted
  with the install's pins and released at completion or failure. A
  snapshot's counter and registers mean nothing on other code, so a
  workflow resumes on the program it started on, whatever an upgrade
  or uninstall does meanwhile.
- **One due index for all timed rows:** session expiry, await
  deadlines, timers, under one key format the leader and the agent
  share. An expired deadline or a due timer starts a batch the way an
  expired session does today.
- **The node lists the due rows in the batch,** and refine reads each
  by its key instead of scanning the index:
  - the leader already reads the index natively to time the sweep, so
    it puts up to `SWEEP_LIMIT` due rows into `Input::Sweep`;
  - refine checks each named row exists and is due at the batch's time,
    and ignores any that is not;
  - so refine never scans, which JAM needs: a tree over hashed keys
    proves single keys, never that a range holds nothing else.
- **Due rows become steps, not sweep work:**
  - session rows are collected as today (`Step::Swept`);
  - a workflow's row becomes `InputRef::Due { workflow }`, a dispatched
    step, which restores the machine and runs with the step's own gas
    limit and instances, within the refine's gas, and waits for the next
    batch like any step when the gas is not there;
  - a `Due` step that traps fails its workflow, which removes its due
    row, so no workflow row sticks at the head of the index and holds
    the deadlines behind it.
- **A step:**
  - **Resuming input:** a start, a `Reply` for its await, or `Due` for
    its deadline or timer. An await records the agent it awaits, and a
    `Reply` from any other agent is consumed and dropped, so no agent
    answers another's await.
  - **Machine:** the agent restores the workflow's machine and passes
    the input in.
  - **Run:** it runs until it pauses at an await, is preempted,
    completes, traps or passes the step's gas limit (decision 5).
  - **Commit:** the step's synchronous calls' effects, its messages and
    its snapshot commit together as one `Run`.
  - **On a trap or the gas limit:** the step's effects are discarded,
    and the step still consumes its input, as section 8.1 has it: the
    workflow is marked failed, its pin and due row go, and its owner
    learns of it. Earlier steps stay.
- **Gas:** each step has a fixed limit, declared per workflow, with the
  agent's default. A step is dispatched only if the refine's remaining
  gas covers it, as handlers are (section 8.1). Preemption lets
  effect-free code between awaits span refines (decision 5).

**Snapshots with Gray Paper calls alone,** the same calls on VOS and
JAM, so a step's `gas_used` is the same on both hosts:
- **Written pages, by faults:**
  - a restored machine maps its writable pages read-only;
  - its first write to a page exits `Fault(address)`;
  - the agent marks the page written, sets it read-write and resumes.
  - So the agent knows a step's written pages exactly, with no host
    extension, and JAM charges the same calls.
  - **The agent's own writes into the machine are tracked too.** It
    pokes inputs, replies, reads and `random` into the workflow's
    memory, and `poke` into a read-only page fails, so each such write
    marks its pages written and sets them read-write first.
  - **An inner precompile writes its output in place,** which a
    read-only page refuses (the machine panics). So a workflow's
    precompiles are served by the agent (the carried item, needed from
    4.5 on): the inner machine exits, the agent computes and writes the
    output through its tracked write.
  - **The writable ranges** to arm come from the program's layout,
    which the loader parses already.
  - **Cost:**
    - arming: the read-only mapping at restore, paid every step, in
      proportion to the writable pages (4.0 measures it);
    - one exit and one `pages` call per page written in a step: three
      for a typical suspension (S1), 514 for a long computation's first
      pause.
- **The program counter:** from `expunge`, at the step's end, on both
  hosts. A machine is never kept past its step (decision 4), so nothing
  is lost, and no VOS-only call changes the gas between hosts. If the
  live-machine cache is ever built, the call that reads the counter
  without ending the machine is priced as `expunge`.
- **The snapshot:** the program counter, registers and gas, and for
  each written page its index and hash, in a `pages` field of the step's
  `Run`, apart from its writes.
- **A page is stored when it differs from its base:** the program image
  for image pages, zeros otherwise. A page written back to its base
  deletes its row, so a restore gives the base again.
- **The page bytes travel beside the work result,** not in it:
  - on VOS, in the result's page section, LZ4-compressed per page;
  - **a work result of 64 KiB or more travels as a blob,** its log
    entry carrying the hash, as programs do since step 3.1. This
    slice builds that path (4.4), on the program blobs' fetch and the
    entry reports, so a 2 MiB snapshot never rides inline beside
    small entries;
  - on JAM, as exported segments, one raw page each (see JAM mode).
  - So the work result proper is the same on both hosts, and the pages
    compare by their hashes.
- **Caps:**
  - 8 MiB raw of pages a step; past it the step fails;
  - 16 MiB a result's page section; a step that would pass it waits for
    the next batch, as the other caps do.
  - Pages count apart from `STEP_WRITES` (256 KiB) and `WORK_RESULT`
    (4 MiB), which stay as they are. S1's long computation ships 2 MiB
    on its first pause, which neither would hold.
- **Accumulate** overwrites the page rows in place. A workflow owns its
  pages, and only its latest snapshot is kept, so pages need no
  reference counts until XOR deltas share them (section 8.3, later).
  Completion deletes them.
- **Restore:**
  - acquire a machine for the program from the pool, at the snapshot's
    counter: `instantiate` gains the counter that `machine` already
    takes. A machine entered mid-block is charged that block's gas
    again, the same on both of our backends; 4.0 checks PolkaJam does
    the same;
  - write the page rows into it with `pages` and `poke`, checking each
    against its hash;
  - set the counter, registers and gas.
- **The leader's cache of live machines** (section 8.3) is built only
  if restoring misses the budget: capture plus restore of 50 KB within
  1 ms (section 14) [owner decision 4]. S1 measured restore at 0.11 ms
  on the JIT; slice 1's pool makes acquiring a machine a few
  microseconds.

**Failover:**
- A new leader resumes every workflow from its committed snapshot, on
  the program the workflow pins.
- Replies arrive in pair sequences, so a reply is never applied twice.
- An await's deadline is batch time, never a local clock.

### JAM mode [decided direction (section 12); proposed details]

- **Work on JAM:** the work item's payload is `Work::Package { batch,
  witness, root }`, with:
  - `root`: the agent's root before;
  - `witness`: a `BatchProof` over every key the refine reads or writes,
    with their values.
- **Refine serves its own state reads from the witness.** The witness is
  verified once against `root`, and a key it does not cover traps.
- **Refine also applies the work result,** as accumulate does on VOS:
  the same `apply` code, run over the witness, writing session marks,
  replies, the outbox, pair marks, due rows, workflow rows and page
  rows. The root after covers every row it writes, so the witness
  covers every key `apply` reads or writes, beside the handlers' keys.
- **The whole keyspace is one tree:** system rows, actor tables,
  committed maps, workflows and their pages (section 12). Every row
  written on JAM is a salted leaf.
- **Scans on JAM are witnessed** [owner decision 8]:
  - the builder's simulation records each scan's range, in the table's
    order, and the witness proves it complete with a `RangeProof`;
  - refine serves `state_scan` from the witness, and a scan past what
    the witness covers traps;
  - the sweep stays scan-free (the batch names its due rows), so the
    common path pays no range proof.
- **Refine's output** is capped on JAM, so it holds only:
  - `root`, and the root after (`update` over every write, salts
    computed in refine from the batch's seed);
  - the batch's time and seed;
  - the work result's hash.
  The work result itself is exported to DA with the pages, and the
  builder keeps it.
- **Accumulate on JAM:**
  - checks `root` against the root it stores, and refuses the result on
    a mismatch;
  - checks the time against the slot, within the session skew;
  - stores the root after;
  - stores nothing else, so state data lives in DA and with the
    builder.
  - It verifies nothing else about the work result: the builder is
    trusted for its content. That is section 12's model, in which JAM
    agents verify proofs from spaces and produce none. A space's own
    agent on JAM is as trustworthy as its builder until slice 5's
    proofs.
- **Root continuity serializes an agent's packages.** The builder chains
  them with prerequisites.
- **Snapshot pages:**
  - each written page is exported as one segment (4,104 bytes: the
    page, then 8 zero bytes);
  - the page's row holds its hash, as on VOS. Refine cannot know the
    segment root of its own exports, which the guarantor computes; it
    reaches accumulate and the builder in the work report. So the
    builder keeps, off-chain, where each page was exported: the
    package's segment root and the export's index. An import names the
    segment root, which works as long as DA holds it; a package hash
    works only for 8 blocks of history (4.0);
  - the package that resumes the workflow imports those segments, and
    refine checks each page against its hash. A segment exported as
    zeros by a failed package fails that check;
  - a package holds at most 3,072 imports and 3,072 exports (12 MiB),
    so the builder schedules workflows' pages within them, and a
    workflow whose pages do not fit waits for the next package.
- **The default agent detects the mode from its work.** A
  `Work::Package` brings its own witness, so no host flag exists.
- **The JAM-only host in CI** learns `fetch` (payload, parameters and
  imports), `export` with its offset, and import segments supplied by
  the test. Its prices become PolkaJam's where they differ (4.0): `gas`
  48, `log` 1,000 and answering `WHAT`, an unserved call 1,000.
- **A work result never depends on the outer machine's gas readings:**
  the agent dispatches by its own accounting of step limits against the
  batch's budget. Host-call prices differ between hosts (the loader's
  `instantiate` attempt costs 1,000 on JAM and nothing on VOS), and
  must not change which steps run.
- **The dynamic comparison grows** to batches that read state, batches
  that run actors and workflows suspended across packages. The work
  result must match the VOS run byte for byte. Only the JAM output's
  roots and exports are extra.
- **Time and the seed:** the builder supplies them in the batch, and
  refine passes them to accumulate in its output.
- **Privacy on JAM:** a path through an ordered or hashed table shows
  its neighbours' raw keys, since both transforms keep the key. On JAM
  the witness is public, so a table whose keys must stay private uses
  the private transform (slice 5) or stays off JAM.
- **Every input costs leaf updates on JAM:** a session mark, a pair mark
  or an outbox row is a row of the tree, so the root after costs grow
  with a batch's inputs, not only with its handlers' writes.
- **The CI surface check pins PolkaJam's prices** for the calls 4.0
  measured, so a change in either host shows.

**The builder** (`node/jam`, a library and `vos jam` commands):
- it holds the agent's full state in a node store, with one root over
  the whole keyspace;
- it assembles a batch from its own queue;
- it simulates refine on the JAM-only host, recording every key read
  or written, then builds the witness and the package (imports of the
  pages it resumes);
- it submits the package and waits for its accumulation;
- it applies the work result to its store, whose root must equal the
  root after.
- **Deployment** waits until the code preimage is available at the
  package's lookup anchor, checked by the builder itself: `jamt`'s
  wait did not prevent SJ's race in 4.0, where a package declaring
  exports failed with an export-count error and left zero segments.
- **Imports name segment roots,** never package hashes, which expire
  after 8 blocks of history.
- **The service blob's metadata prefix** moves from SJ's tool into the
  compiler's linker.

### The carried smaller items [proposed]

- **The agent serves its inner machines' precompiles:**
  - itself, at the fixed price on every host;
  - natively through the outer host's precompile on VOS;
  - in software inside the agent on JAM.
  - Then actor-running batches compare across hosts, and a workflow's
    precompiles write through the agent's tracked writes (4.4).
- **`#[msg(linearizable)]`:** the handler always reads after a read
  index, whatever the client asked.
- **`historical_lookup` answers only programs the agent pins**
  [owner decision 6]: as JAM scopes a lookup to the service's
  preimages, and as `instantiate` already does.

## Steps

### 4.0 JAM probe [done]

Recorded in `slice-4-progress.md`: all three behaviours hold on
PolkaJam and on both of our backends, with identical gas for every
inner-machine call.

The plan rests on Gray Paper behaviours that PolkaJam and our runtime
must both show. A probe service on the testnet (from SJ's guest) and the
same checks on our two backends:
- **fault tracking:** a write to a read-only page exits
  `Fault(address)`; after `SetReadWrite` the machine resumes and the
  write lands; `poke` into a read-only page fails;
- **the counter:** `expunge` at a host-call exit returns the counter
  after the call, and a machine created there (`machine(code, pc)`)
  resumes correctly, charged the same gas for entering mid-block;
- **segments:** two pages exported by one package, imported by a later
  one and read back with `fetch`.

It also records:
- each call's gas on PolkaJam against our JAM-only host, including the
  arming: `pages` setting a whole writable region (2,048 pages for an
  8 MiB arena) read-only;
- PolkaJam's refine gas budget per work item;
- how imports are named when a package is submitted;
- the PolkaJam build in use, and how the testnet starts here;
- the fault loop on both PolkaVM backends: the interpreter, and the
  recompiler, which needs `vm.unprivileged_userfaultfd=1`. That setting
  is 0 here, and the kernel is the owner's, so the recompiler run waits
  for the owner's word. The milestone runs on the backend the probe
  proves.

### 4.1 The wire, and requests and replies between agents

- **Wire changes land with the step that uses them;** nothing is
  frozen before `vos/1`. This step brings `Message`'s body,
  `Input::Failed` and `Behind`, and the owner's three wire-format items
  (decision 7).
- **The receiver's side of a request:** a `Call` that awaits gets its
  `Reply` in the sender's outbox, its outcome whatever it was.
- **The failed message** as `Input::Failed`, asserted after two lone
  failures.
- **`Behind`** for fast retransmit.
- **Tests:**
  - a failing message acknowledged once, never resent;
  - a gap recovered within one round trip;
  - a stale `Behind` changing nothing;
  - a `Call` with an await answered by a `Reply` in the outbox, after a
    leader kill too.
  - Consuming replies waits for 4.5, which has something that awaits.

### 4.2 The compressed tree

`agent/tree`, with the property tests, and S4's update costs reproduced
on it.

### 4.3 `CommittedMap` and the root builder

- The SDK type, the rows, accumulate's dirty and seed rows, the builder
  in the node with the epoch-checked commit, and `Node::prove`.
- **A crash test:** the builder killed mid-build resumes to the same
  root, with no node or leaf row left off the tree.
- The section 14 row: the committed write on the apply path (value and
  dirty rows), and the builder at the replicated rate.
- It shares nothing with 4.4 to 4.6, so it can run beside them.

### 4.4 What workflows need underneath

- **The result's blob path:** a work result of 64 KiB or more as a
  blob, with its page section.
- **`instantiate` with a counter.**
- **The agent's tracked writes into a machine.**
- **The agent serving its machines' precompiles,** at the fixed price
  on every host, with each call's bounce counted. Actor-running batches
  then compare across hosts.
- **Programs beside an actor:** the workflow kind in installs, and
  `workflow_program!`.

### 4.5 Workflows in the agent

- `#[workflow]`, `Workflow<A>` and the ABI operations.
- The workflow table and pins, the shared due index with the node
  listing due rows, and `Due` steps.
- Fault-tracked snapshots and restore, deadlines and timers, failure,
  results by id.
- A failure code of its own for a callee program that cannot be loaded,
  a node's fault, which `Unknown` (no such method) covers today, so a
  workflow tells them apart.
- **The testkit's reference model and tests on one node:**
  - S1's three workflows (transfer, saga, compute);
  - replies consumed, and late ones dropped;
  - the interpreter and the JIT agree on every step's `gas_used` and
    snapshot.

### 4.6 Workflows in the replicated node

- Ingress: `Started(id)`, and a workflow's status and result by id for
  its owner, with an optional wait.
- **The checker's workflows:**
  - started, killed mid-await, and resumed from their snapshots;
  - their effects counted exactly once;
  - requests between agents with replies.
- A fault-suite case across processes.
- The snapshot row of section 14 measured through the agent, and the
  live-machine cache built only if that row misses.

### 4.7 The carried smaller items

- `#[msg(linearizable)]`;
- `historical_lookup` scoped to the agent's programs;
- the fan-in bench, and batching across agents only if the bench shows
  frames, not refine, bound it.

### 4.8 JAM mode

- `Work::Package`, witnessed reads, roots before and after, salts in
  refine, pages through segments, `state_scan` trapping.
- The JAM-only host's `fetch`, `export` and imports, with DA emulated
  in process.
- **The recording simulation and the witness build,** which the
  builder reuses in 4.9, so `ci` can chain packages without a JAM node.
- **The dynamic comparison:** stateful batches, actor batches and
  workflows suspended across packages, the work result equal byte for
  byte and the pages equal by hash.

### 4.9 The builder and the milestone

- `node/jam` and `vos jam`: the store with one root over the whole
  keyspace, submission, waiting for code availability, the service's
  metadata in the compiler's linker.
- **On a local PolkaJam testnet:**
  - the default agent and one actor deployed;
  - a workflow suspended in one package and resumed in a later one,
    every read witnessed.
- A recipe, `just jam-milestone`. It is outside `ci`, because it needs
  the PolkaJam binaries.

### 4.9b One actor, one ELF [owner decisions 10–12; reviewed by Fable]

**For the developer:**
- One crate per actor, built once with plain `cargo build`. The SDK
  ships the toolchain file, the cargo configuration, the target spec and
  the linker script as a template.
- That gives one ELF, published as it is (`vos publish actor.elf`). No
  program per workflow, no crate per attestable, no linking by hand,
  nothing declared beyond the macros.

**What the ELF carries:**
- the actor's entry, which routes by method to a command, a query or a
  workflow, as handlers are routed today;
- one entry symbol per attestable method (`__vos_attest_<method>`);
- the actor's schema (methods, kinds, roles, gas limits), which the
  macros generate into a section of its own, so the ELF describes
  itself.

**What the platform derives from it, once, at install:**
- **The actor's program:** the ELF linked from the actor's entry and
  transpiled to PVM. Its workflows are in it: a workflow's machine
  starts at the program's entry with an input naming the workflow
  method, and the entry routes there.
- **One kernel per attestable method:**
  - the ELF linked from that method's entry symbol alone, following
    every call and data reference its relocations name, so only the
    code it can reach is in it;
  - a static check that the reachable code makes no host call but the
    precompiles, refusing the install otherwise;
  - one kernel per method, so a method's proof pins a hash that changes
    only when its own code does.
- **Reachability follows relocations only:**
  - the target builds position-independent code with `--emit-relocs`;
    an ELF without relocations is refused;
  - calls, tail calls, address-taken functions, vtables, function
    pointers in data, switch tables and the builtins all reach their
    targets through relocations under this toolchain, and safe Rust
    cannot compute a code address;
  - the linker's heuristic scan for code-like values in data, kept for
    stripped ELFs, may add targets but never justifies pruning one;
  - a code pointer whose target was pruned is rewritten to an address
    outside the kernel's jump table, so jumping to it panics.
  - So a missed target can only trap, never run something else, and
    the data the kernel reaches comes with it through the same
    relocations.
  - Over-approximation is harmless: an unreachable branch of a shared
    helper still pulls its callee in. If that callee makes a host call
    other than a precompile, the install is refused, and the error names
    the chain of symbols from the entry to the call.
- **The install record:** the actor program's hash, each kernel's hash
  by method, the schema, the transpiler's version, and the ELF's hash
  for provenance.
- **Bit-reproducible:** the same ELF and transpiler version give the same
  bytes on any machine, because the VOS installing node and the JAM
  builder must agree whenever a space's proof is verified on chain. The
  output's order comes from sorted sections and symbols, never from a
  map's iteration. A test derives the test actors twice, on different
  machines, and compares them.

**Identity:**
- The PVM program's hash is the identity everywhere: pins, workflows'
  snapshots, proofs, JAM preimages.
- An installed program is never transpiled again: a newer transpiler
  would change bytes that running workflows and proofs refer to. A
  re-publish is an upgrade, and running workflows keep the program they
  pin. On JAM, the builder keeps a program's preimage solicited while
  any live workflow names it.
- **A kernel's hash on chain is pinned per transpiler version:** a
  transpiler upgrade means re-pinning the verifiers. That is the simpler
  of the two choices; the other is to pin the ELF's hash and a version
  and derive at verification. Slice 5 may revisit it.

**Where the derivation runs:**
- **On VOS,** the node that takes the install derives the programs
  before proposing it. The log carries their hashes, and the replicas
  fetch the programs as blobs, as installs do today. The space's nodes
  trust each other, so no two node versions need agree on a
  transpilation.
- **On JAM,** validators run PVM only, so the builder derives the same
  programs with the same transpiler and provides them as preimages.
- `vos publish` prints the hashes either way, so a developer sees when
  a kernel's hash moved. rustc can change a kernel's machine code when
  unrelated code changes, through inlining, so its hash is far more
  stable than the whole program's but not fixed.

**The node now parses uploaded ELFs:**
- fuzzed;
- bounded in size (the install body's cap), sections, symbols and
  relocations;
- run off the node's runtime thread;
- a panic in parsing or linking fails the install and never halts the
  node. The operator is trusted, but the toolchain that made the ELF is
  not part of that trust.
- `#[inline(never)]` on each generated `__vos_attest_<method>` entry,
  and `codegen-units = 1` in the SDK's cargo configuration, make a
  kernel's code move less with unrelated changes.

**`ctx.read(|actor: &Self| ..)` and `ctx.update(|actor: &mut Self| ..)`**
[owner decision 11]:
- **Synchronous sections** on the starting instance's state, tables
  included:
  - the SDK opens a section with a host call naming the instance;
  - the agent serves that instance's state operations to the workflow's
    machine until the section closes;
  - the closure runs, and the section closes.
- **Atomic, holding nothing across a pause:** a closure is not `async`
  and holds no context, so it can neither await nor call. State is read
  afresh after every await.
- **Runs as the instance itself,** with no role check, as the actor's
  own code.
- **Counts as an effect** for preemption, commits with the step, and on
  JAM its rows are witnessed like any. A `read` counts too: a value
  read and then updated within one unit stays atomic across a
  preemption.
  - A workflow that reads, computes long, then updates cannot keep that
    atomicity: it must pause between, re-reading after. The doc shows
    the pattern: a short computation goes inside one `update`.
- **Enforced at run time, not only by types:** inside an open section
  the agent serves only that instance's `GET`, `PUT`, `DELETE` and
  `SCAN`, plus `NOW` and `LOG`. A `CALL`, `SEND`, `REQUEST`, `RESULT`,
  `SLEEP`, or a second open, traps the step, since `host::send` is a
  public function.

**What goes away:**
- `workflow_program!`, `attestable_program!`;
- the per-workflow and per-attestable crates in the test actors;
- `--workflow` and `--attestable` at install.
- Snapshots stay as small: a page unchanged from the program's image is
  never stored.
- The workflow's writable runs are the actor program's, heap included,
  so arming (200 gas a page, every step) follows the heap the actor
  configures.
- **An actor's heap is paid by every invocation of any kind,** not only
  by its workflows' steps: a handler's machine maps the whole heap too,
  on JAM through the loader's calls (about 372,000 gas a call for a
  12 MiB heap, against about 15,000 at the SDK's default) and on VOS in
  the price the pool gives a machine by its pages. So an actor keeps its
  heap as small as its largest workflow needs, and the test actors keep
  small heaps but where a test needs one: the shop's 4 MiB, and its `big`
  and `huge` builds for the steps and caps that need more.
  - **Carried to a later slice:** a bump allocator over the header's heap
    region, so the agent maps a small heap for a handler and a larger
    one for a workflow's step.

### 4.10 Acceptance

- The section 14 rows: committed writes and the builder keeping up,
  snapshot capture and restore, the cross-node messaging bench.
- **New rows measured:**
  - a workflow's resume latency: a reply in, the workflow resumed, on
    three processes;
  - a witnessed JAM read's gas.
- Then:
  - `just ci-full`;
  - the checker loop with workflows;
  - the end review (Fable);
  - the code-quality review (Opus);
  - each carried item closed or carried to a named slice.

**Size:** about 16,000–23,000 lines of code and tests (the code check's
estimate): the tree 2,000, workflows in the agent 3,000, JAM mode 2,500,
the builder 3,000, the rest 1,000 each or less.

## Gates

| Gate | Threshold |
|---|---|
| Slices 1 to 3 | `just ci-full` stays green |
| The tree | the property tests: roots equal a from-scratch build; proofs verify and tampered ones fail; `update` agrees with direct updates; PVM and native agree |
| Roots | every replica's root at a version is the same; a crash mid-build resumes to it, with no node or leaf row left off the tree |
| Workflows | the exactly-once checker with workflows across leader kills; the interpreter and the JIT agree on every step's snapshot and `gas_used` |
| JAM | VOS and JAM refines agree on every comparable batch in `ci`; the milestone on a PolkaJam testnet |
| Budgets | as in 4.10 |

## Risks

- **PolkaJam may differ from our runtime** on faults, `expunge`, mid-block
  entry gas or segments, and our own runtime has never run the
  read-only write loop. Step 4.0 finds out on both before anything
  builds on them.
- **PolkaJam is a nightly.** The milestone pins one build and records
  how to start it.
- **The witness covers every key a refine touches.** A JAM refine that
  reads a key the builder's simulation did not see traps. So the
  builder's simulation and the refine must run the same code on the
  same host interface; the dynamic comparison guards that.
- **Fault tracking costs an exit per written page.** A long computation's
  first pause pays 514 of them, and every step pays the arming;
  measured in 4.5 against the snapshot row.
- **The slice is the widest so far:** messages, storage, the SDK, the
  agent, the node and JAM. Each step stands alone and is checked
  alone, in the order above.

## Decisions [decided by the owner, except 5]

1. **Proving stays in slice 5:** attestable methods reading committed
   fields, and cipher-clerk on the new format, move there with the
   prover track. This slice builds the tree, the map, the roots and
   JAM's witnessed reads.
2. **Salts from the work result:** the first 16 bytes of
   `H(tag ‖ seed ‖ key')`, not from a space secret, which needs key
   management no slice has yet.
3. **A started workflow answers `Started(id)` at once,** to a client or
   to a starting workflow, and its result is read by id, with an
   optional wait.
4. **The leader's live-machine cache only if the budget needs it,**
   restoring from rows otherwise.
5. **Preemption, at the awaits and between them,** as below: every
   `.await` may pause, and no `checkpoint()` exists.
6. **`historical_lookup` scoped to the agent's pinned programs,** as on
   JAM.
7. **The wire-format items now,** in 4.1:
   - the refusal and failure codes as enums;
   - the `PeerMessage` index gap;
   - the directory acknowledgement's order tuple.
8. **Scans on JAM in this slice,** as Substrate's iterable maps lead
   users to expect:
   - one tree format over prefix-free keys, with range proofs;
   - each table chooses its key transform, as a Substrate map chooses
     its hasher: hashed (`H128(key) ‖ key`, iterating in hash
     order, balanced) by default, and ordered (`Table<K, V, Ordered>`,
     key order and ranges, keys of at most 64 bytes) by choice;
   - so an actor that scans its tables runs on JAM too.
9. **A finished workflow's result is kept an hour** for its owner to
   read, then collected, and it reads `Unknown` like a stranger's id.
10. **One actor, one ELF:** the developer builds one ELF and publishes
    it. The platform derives at install the actor's program (its
    workflows in it, routed by method) and one kernel per attestable
    method by reachability, transpiled once and pinned (4.9b).
11. **A workflow reaches its actor's state** through `ctx.read` and
    `ctx.update`, synchronous and atomic, never across an await (4.9b).
12. **The ELF is the upload format:** VOS's installing node, or JAM's
    builder, links and transpiles it; the developer runs only the Rust
    compiler.

**Decision 5: preemption.** Section 8.3's effect-free preemption,
built on this slice's snapshots instead of on live machines, with the
awaits as the pause points:
- **A unit** is the code between two awaits. It runs atomically: its
  effects (calls, sends, table writes through calls) commit together or
  not at all.
- **A step** is one or more units, from a resume to a pause. At every
  await the agent may end the step: it must for another agent or a
  timer, and does at a same-agent `call` when the workflow's share of
  the refine's gas is spent. The step's effects and its snapshot commit
  together.
- **Between awaits, a unit with no effect yet may be preempted:**
  - it runs on the workflow's share. If the share runs out there, the
    machine exits out of gas at the start of a block, having done
    nothing of it;
  - the agent ends the step there: the effects of the step's earlier
    units commit with the snapshot. That is safe, because an await
    separates them from this unit, which has done nothing;
  - the workflow is due at once, so the next batch continues it.
- **At a unit's first effect,** the workflow exits to the agent for it.
  Before serving it, the agent checks that the refine's remaining gas
  covers the step's limit. If not, it ends the step there, snapshotted
  at that call, still effect-free in this unit. The resumed step serves
  the pending call first.
- **After its first effect, a unit runs to its next await** within the
  step's limit, and is never preempted. Past the limit the step fails.
- **The share is the step's own limit,** the gas its workflow declares,
  never the batch's remainder and never the `gas` host call:
  - dispatch keeps the reserve, that limit and the finish from the
    batch's budget (`Batch.budget`), by the agent's own accounting;
  - the agent sets the machine's gas itself at every invoke;
  - so the same batch preempts at the same block on every host, and on
    JAM. A long computation takes one limit a step, not every batch's
    budget ahead of the inputs behind the sweep.
  - Each effectful unit gets a fresh limit once the batch covers it.
- **Fairness: due steps leave a batch's inputs a floor.** When a batch
  holds inputs beside its sweep:
  - the head due row's step runs whenever the batch can keep its
    reserve, restore, limit and finish, so the due index always moves;
  - from the head's step on, half of what the head leaves stays for
    the inputs, and the head's pages and every later due step's keep
    and pages must stay above it;
  - a due step that cannot waits for the next sweep, with the rows after
    it;
  - with only the sweep in a batch, or for a start's first step or a
    reply's step, which are inputs' own work, there is no floor.
  - A step fails `Cap` only when even an empty batch could not hold it
    with two pages of room.
- **A progress floor:** a step is preempted only after it has moved
  since its resume. Otherwise it fails out of gas, or, at a page the
  batch cannot pay, waits or fails as an overrun, so a workflow is never
  pinned at one counter, committing a snapshot every batch.
  - At an out-of-gas exit or a call, moving means gas used.
  - At an unpaid page it means a page paid or a call served. A machine
    resumed at a page fault re-enters mid-block and pays that block
    again, so gas used there proves nothing.
- **The snapshot records how the step exited:** a pending host call
  (its id, beside the counter and registers), or out of gas, which
  needs nothing. The block an out-of-gas exit stopped at is charged
  once on resume, as a block entered at its start is (4.0 and 4.5's
  probe).
- **No gas is stored:** every step starts its unit at the workflow's
  limit, which the agent sets.
- **A preempted step still consumes its input:** the `Reply`'s pair
  mark, the `Due` row or the start's session mark moves in that `Run`,
  so the input is never redelivered to a workflow that already holds it
  in its snapshot.
- **What stays as it was:**
  - failover resumes from the committed snapshot, and the due row
    brings the next step on any leader;
  - no reply can target a preempted workflow, which is running, not
    awaiting, and a duplicate drops at the pair mark;
  - `now` and `random` are drawn per step from the batch and written
    into tracked memory.
- **Probe:** resuming after an out-of-gas exit at a block start, on
  PolkaJam (the interpreter now, the recompiler once the owner enables
  it) and on both of our backends, before 4.5 builds on it.

**Core-model edits these decisions make,** amended with the plan:
- §6.4: a package is the ELF. The install record holds the derived
  program and kernel hashes, the schema and the transpiler's version.
  Packages are content-addressed by the ELF, and derived hashes are per
  transpiler version, so two spaces agree on a kernel's hash only when
  they derive with the same version (decisions 10, 12).
- §6.5: workflows read and write their actor's Linear state, through
  sections only (decision 11).
- §11.1: an attestable method is "derived from the actor's ELF by
  reachability from its entry", no longer "compiled into its own small
  program" (decision 10).
- §8.2 "Its result is sent to whoever started it" becomes: answered
  `Started(id)`, the result read by id (decision 3).
- §8.3 "The leader caches live machines" becomes conditional on the
  budget (decision 4); "Pages are reference-counted by snapshots"
  waits for XOR deltas, since a workflow owns its pages.
- §8.2 and §8.3: no `checkpoint()`. Every `.await` may pause, the code
  between two awaits is atomic, and effect-free code between awaits is
  preempted when its gas share runs out (decision 5).
- §9.3: the salt source is the work result's seed (decision 2); keys
  enter the tree through each table's transform, hashed by default or
  ordered, and "variable-length keys are hashed to a fixed width"
  becomes the hashed transform (decision 8).
- §12: JAM's whole-keyspace tree is over each table's transformed keys,
  and scans are witnessed by
  range proofs (decision 8).

**Defaults** (engineering, recorded rather than asked):

| Setting | Value |
|---|---|
| Await deadline | 60 s by default, set per call with `within` |
| Workflow step gas | the handler default, 10M |
| Snapshot per step | 8 MiB raw at most; 16 MiB of pages a result |
| `Behind` | one rewind per window per 100 ms |
| Live workflows | 65,536 per agent, refusing new ones past it |
| Root builder batch | 10,000 dirty keys |
| Tree hash | BLAKE2b-256, keys hashed to 32 bytes, 16-byte salts |
