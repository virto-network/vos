# VOS runtime v2 contract

> Implementation status: the versioned contracts, guest service state tree,
> canonical `vos-service.pvm` Refine/Accumulate entries, package tooling, actor
> APIs, and CRDT primitives described here are present. The local v2 harness
> executes both phases through that PVM and commits only an accepted guest
> result; it has no native transition-apply shortcut. The production node still
> runs the legacy runtime while durable v2 scheduling and backend integration
> are completed. Legacy node behavior is not evidence of v2 conformance.

The local conformance scheduler can admit one guest-committed durable inbox
row, derive the callee invocation, origin, authorization and causal parent from
that row, enforce its deadline, and consume it atomically with the callee's
first accepted slice. Its logical timeslot is an explicit harness input;
production integration must bind that value to the consensus JAM timeslot
rather than accept a caller-selected value. Actor-side cross-root CALL now
emits a durable outbox row and captures the exact pending protocol boundary.
For linear services the guest-owned workflow row reconstructs every later
slice after restart without a process-local copy of the original request.

The local linear-service transport is also guest-owned end to end. An accepted
actor slice stores a recoverable publication row whose receipt commits the
complete canonical outbox. After restart, transport selects a message from
that publication and destination Accumulate verifies receipt finality,
producer ownership, full-outbox membership, deadline and the exact current
destination base before atomically inserting the inbox. A stable delivery
identity excludes that changing base, so a retry after inbox execution is
still an idempotent duplicate. Guest delivery records retain the admission
timeslot and consumed bit; the local scheduler scans them after restart and
drains runnable inbox rows through Refine plus Accumulate at an explicit later
logical timeslot. Publication removal is a separate guest Accumulate
acknowledgement performed only after the external consumer is durably
committed.

The local linear conformance path also routes a committed callee reply back to
the caller service. It recovers the exact caller invocation from the
guest-owned outbox, reconstructs the saved machine after restart, and submits
the physical Refine result to guest Accumulate. A permanent reply-admission
record binds the `CallId`, accumulated reply, work input and work hash, so a
lost transport acknowledgement remains an idempotent duplicate after another
restart or a later workflow slice. The callee publication is acknowledged only
after the caller commit succeeds.

The local host serializes the complete committed service image as canonical
`LocalJamStoreSnapshotV2` bytes. Restore checks the current store header and
recomputes every blob and program identity before exposing the image; in-flight
transactions and process-local receipt policy are excluded. `DurableJamStoreV2`
persists each candidate image through a `CommittedImageStoreV2` backend before
swapping it into live state or returning published effects. A backend failure
leaves the prior in-process image visible and permits an exact retry. The
filesystem backend flushes a sibling candidate, atomically renames it over the
committed image, then syncs the parent directory.

The local transport accepts either the in-memory host or this durable host
without changing scheduling or service semantics. Its physical cross-root
gate reopens both roots exclusively from committed backend bytes throughout
delivery, inbox draining, reply resume, and publication acknowledgement.
Injected destination and caller commit failures expose neither an admitted
inbox nor resumed reply effects; the exact envelopes remain retryable from the
previous durable images.

CRDT anti-entropy also enters through physical Accumulate. A
`CrdtSyncEnvelopeV2` carries advertised heads, canonical causal nodes, the
content-addressed blobs they reference, and each node's finalized admission
receipt. The guest verifies receipt/service identity, node CID, change-ID
deduplication, exact causal height, complete ancestry, workflow rules, and blob
hashes before staging anything. It preserves concurrent heads, reconstructs
continuation/inbox/outbox/workflow rows from the DAG, and commits nodes,
receipts, blobs, materialized rows, and the header atomically. The read-only
local scheduler only packages these authenticated bytes.

Guest Install is fail-closed on an exact-genesis authorization capability. It
binds service/deployment identity, consistency mode, the complete actor tree,
programs, initial states, method policies, and the supplied authorization
evidence before consulting program or blob availability and before staging any
service row. Before either physical entry runs, the platform dispatcher binds
the declared service `ProgramId` to the canonical PVM selected for execution;
the package validator pins that same protocol program. The local conformance
host uses an explicit process-local allowlist which is excluded from durable
service snapshots; reopening an empty store therefore requires authority to be
established again.

This is still a conformance orchestrator, not production network routing.
Automatic node discovery and outbox/reply routing, plus CRDT delivery/reply
consumption, remain staged. Acknowledging a publication containing several
effects is the transport host's responsibility only after every required
consumer has accepted it.

Guest Accumulate can admit a receipt-bound reply for an existing pending-call
continuation. It reloads the committed continuation and outbox row, binds the
call, caller invocation, await ordinal and producer, rejects replies admitted
at or after the call deadline, asks the host to verify the exact external
receipt and its service's ownership of that producer, and consumes the outbox
only in the accepted resumed transition. The local harness uses an explicit
receipt-and-producer allowlist for conformance. Refine injects an admitted
reply into the exact saved protocol-call result buffer, so execution continues
after the await rather than replaying the handler. The inline injection
envelope is bounded by `CHECKPOINT_TOKEN_CAPACITY`; larger application results
must use a content-addressed blob reference once the transport API exposes
that result form. This path is currently linear-only: CRDT services reject an
awaited reply until consumption of the pending outbox row is represented by
the built-in workflow CRDT. The local scheduler reports this boundary as
`CrdtAwaitUnsupported` when it encounters a CRDT continuation with a pending
call, instead of preparing work which guest Accumulate must reject. The
actor-side resume branch already rebinds and resets the restored CRDT
operation allocator, so enabling that future consumption path cannot reuse
the pre-await change namespace.

Before that production cutover, the Install authorization capability must be
backed by consensus-authoritative deployment state rather than the local
conformance allowlist. That authority must bind the executing JAM service
account and its current code identity to the exact genesis, not trust the
genesis's self-declared identity. `PROGRAM_LOOKUP` availability must be pinned
to or imported from consensus-visible state rather than a node-local cache.
`RECEIPT_VERIFY` must likewise use consensus-authoritative receipt finality
rather than its local conformance allowlist, and delivery timeslots must come
from the JAM slot.
Production routing must recover and retry guest publication, delivery and
reply-admission rows rather than maintain a second native message ledger. A
bounded reclamation or checkpoint plan for unreachable SMT and CRDT DAG nodes,
plus completed delivery/deduplication/reply-admission bookkeeping, is also
required before the engine stores production state; pruning must not weaken
retry safety.

The CRDT checkpoint is a consensus feature, not a local cache optimization.
Before cutover it must:

- bind a complete, CID-verified causal frontier and every actor
  materialization needed to resume from it;
- verify full ancestry once while ingesting untrusted DAG blocks, then let
  activation walk only the bounded suffix after the latest retained
  checkpoint;
- retain every head referenced by a suspended continuation or in-flight work
  envelope, even when a newer checkpoint exists;
- prune DAG nodes, completeness metadata, and stale SMT interior nodes only
  after the checkpoint and all referenced blobs are durably available under
  the selected Local, Raft, or CRDT availability rule; and
- detect a missing or malicious parent before marking a checkpoint complete.

Until that lands, CRDT activation deliberately revalidates complete ancestry.
This is sound but O(history), so the current CRDT engine remains a conformance
path rather than a production-state path.

VOS v2 assigns one logical JAM service to a root actor and its owned child
tree. The protocol-pinned `vos-service.pvm` is one generic program with the
Gray Paper two-slot entry prologue: Refine begins at instruction counter 0 and
Accumulate at instruction counter 5. Registers `φ[7]`/`φ[8]` remain the
standard argument pointer/length window; they are never VOS phase selectors.
Actor packages contain application PVMs, not application-written Refine or
Accumulate functions.

Refine is pure. A `WorkEnvelopeV2` imports the exact deployment, program,
state, continuation pages, authorization evidence, causal base and referenced
blobs needed to run a slice. Refine may only return a `TransitionV2`; it cannot
write service storage or expose a reply. Identical bytes and execution
semantics produce an identical transition.

Accumulate validates service and ABI identity, the canonical actor
`ProgramId`, authorization, base revision or causal dependencies, blob and
proof availability, and invocation deduplication. It commits state or CRDT
operations, continuations, inbox/outbox rows and the receipt atomically.
Replies, outbound calls and proof packages become visible only after that
commit. A stale linear transition is rejected intact for rescheduling.

## Continuations

An await checkpoint stores the exact nested kernel: each VM's program hash,
PC, registers, heap bounds, gas and lifecycle, mutable capabilities, dirty
page hashes, active/runnable scheduler state, nested call stack and the pending
protocol boundary. Resume consumes the checkpoint, injects one result into its
declared registers and continues at `resume_pc`. It never restarts the handler
at PC 0. Suspended actors are non-reentrant; later messages remain queued.

Raft orders canonical `AccumulateRequestV2` bytes, including every referenced
continuation/blob byte required by that request. It does not replicate an
`EffectLog` or a leader-produced post-state image. `ReplicatedJamServiceV2`
waits for the request's log position to commit, then applies it through the
physical service-PVM Accumulate entry before advancing the replica's applied
cursor. Followers and a newly elected leader use the same catch-up path;
replaying after a cursor-write failure is safe because guest deduplication sees
the already committed workflow input.

`RaftAccumulateLogV2` is the redb/`vos-raft` implementation of that boundary.
In multi-replica mode it accepts writes only from the elected leader, waits for
the worker's quorum-commit notification, then re-reads and verifies the exact
committed request bytes. Its `last_applied` cursor advances separately and only
after the local service image commits. A replica behind the compacted Raft
prefix currently fails with an explicit service-snapshot-install requirement;
binding Raft `InstallSnapshot` payloads to `LocalJamStoreSnapshotV2` is still a
production cutover task.

Every await is a durable slice boundary. Effects before it may commit even if a
later slice fails, so multi-await handlers have saga semantics. Same-tree calls
may execute inline. Cross-root calls always use durable outbox/inbox rows and a
`CallId` derived from `(InvocationId, await ordinal)`. A compact copy of the
authenticated parent call is bound into the workflow identity and every exact
continuation. It retains caller/callee, deadline and parent linkage after the
step-0 inbox row is consumed, so later awaits preserve cycle and inherited
deadline checks without resurrecting that row. Await ordinals live in the
captured actor machine and therefore advance across successive restarts.

## Packages and identity

`.vos` v2 packages bind the service ABI, execution-semantics ID, canonical
actor PVM and its `ProgramId`, interfaces, role policies and schemas. Optional
ELF/source-map data is diagnostic only. `DeploymentId` excludes diagnostics
and signatures but includes the authoritative manifest and PVM bytes.
Registries store these bytes and never retranspile an ELF. JIT products,
proving keys and traces are caches keyed by `ProgramId`.

The infrastructure PVM is committed at
`services/vos-service/vos-service.pvm`; its identity is
`VOS_SERVICE_PROGRAM_ID`. To reproduce it, build and validate the guest:

```sh
cd services/vos-service
cargo +nightly actor
cd ../..
cargo run -p vosx -- service-pvm \
  services/vos-service/target/riscv64em-javm/release/vos_service.elf \
  --out target/vos-service.pvm
```

The guest build remaps its checkout directory and pins Rust crate metadata so
path-derived symbol hashes cannot perturb the linked program. The v2 service
integration gate transpiles a fresh ELF and requires byte identity with the
committed PVM, in addition to checking its pinned `ProgramId` and GP entry
layout.

This is a clean storage and wire break. A v1 store or package must be reset and
reinstalled; there is no v1 decoder or migration in a v2 service.

## CRDT boundary

Only `#[actor(crdt)]` packages may select CRDT consistency. Their replicated
fields use explicit `vos::crdt` merge rules (`Value`, `Map`, `Set`, `List`,
`Text`, `Counter`). Stable logical operation IDs and causal metadata replace
wall clocks. The Merkle-DAG supplies causal transport and persistence, not
convergence for arbitrary commands.

Workflow operations are a built-in CRDT payload alongside application fields.
Every actor slice records its complete `WorkEnvelopeV2`; synchronized peers can
therefore reconstruct the exact workflow step without a process-local request
cache. Concurrent identical messages are add-wins and deduplicated by stable
`CallId`; divergent continuations, replies, or executions of the same workflow
step are rejected instead of selecting an arbitrary branch.

Concurrent scalar assignments retain alternatives through `conflicts()` while
choosing the same visible value; counter increments, list and text operations
merge without dropping a DAG branch. Constraints such as uniqueness,
overdraft prevention or irreversible global ordering require Raft or a
purpose-built conflict-free construction.

One workflow slice derives one CRDT `ChangeId` from its stable service, actor,
`InvocationId`, and workflow step—not from its observed heads. The change also
commits the complete `WorkEnvelopeV2` hash. An exact retry therefore reuses the
original envelope bytes, including its causal base; changing that base is new
work and must not masquerade as a retry of the old input.

Within a change, the scheduler assigns every actor execution a unique dispatch
ordinal. Field operations are canonical in `(ActorId, dispatch ordinal,
operation ordinal)` emission order; their hashed `OperationId` is a dedup key,
not an ordering key. A continuation resume carries the new dispatch namespace
in its checkpoint token and resets the restored actor-local allocator before
post-await guest code executes. This prevents both stale pre-await change IDs
and repeated ordinal-zero allocation when an actor is dispatched again.
