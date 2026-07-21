# VOS runtime v2 contract

> Implementation status: the versioned contracts, conformance service, package
> tooling, canonical `vos-service.pvm`, exact JAR restoration, durable local
> scheduler, local cross-root delivery/resume, and guest-owned CRDT
> synchronization described here are present in the v2 conformance runtime.
> The production node still contains legacy paths awaiting cutover; legacy host
> behavior is not evidence of v2 conformance.

VOS v2 assigns one logical JAM service to a root actor and its owned child
tree. The protocol-pinned `vos-service.pvm` is one generic program with the
Gray Paper two-slot entry prologue: Refine begins at instruction counter 0 and
Accumulate at instruction counter 5. Registers `φ[7]`/`φ[8]` remain the
standard argument pointer/length window; they are never VOS phase selectors.
Actor packages contain application PVMs, not application-written Refine or
Accumulate functions.

The generic service deliberately declares an 8 MiB standard slot-0 argument
capability and an 8 MiB infrastructure-only allocator. Complete continuation
and Accumulate wires can be much larger than an application message. Ordinary
actor PVMs retain JAR's one-page argument capability and VOS's compact actor
heap; enlarging the infrastructure guest does not silently change application
manifests. A service PVM with the old undersized argument capability is rejected
at installation rather than failing partway through guest Accumulate.

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

Publishable effects also live in a guest-owned `PublicationRecordV2` keyed by
the consumed workflow input. A process restart drains these committed records;
an exact retry returns no duplicate effects but cannot erase the pending row.
After the external consumer accepts the reply, outbox batch, or proof package,
the host submits a commitment-bound acknowledgement through physical
Accumulate. That acknowledgement deletes the record atomically and is itself
idempotent.

Cross-root transport is also guest-owned. The source receipt commits to the
complete canonical outbox published by its accepted transition. A destination
submits that finalized receipt and outbox through the physical Accumulate
entry; the destination service guest verifies membership and finality,
deduplicates by `CallId`, and atomically creates the inbox row. Local and Raft
deliveries require the exact current revision. CRDT deliveries append a
workflow-only causal change and preserve concurrent heads.

Delivery retries compare a stable source identity containing the destination
service, logical timeslot, message, complete source outbox, and finalized source
receipt. The destination base/frontier remains part of the first accepted
delivery commitment but is excluded from retry identity: executing the inbox
legitimately advances that base before an ACK retry arrives. A changed source
record is still a divergent duplicate. The guest's physical delivery record
also retains the admitted logical timeslot and whether actor execution consumed
the inbox row. A restarted local host drains every unconsumed admission from
those records; the consuming actor slice marks the record and removes the inbox
atomically, while retaining delivery identity for duplicate acknowledgements.

CRDT anti-entropy also enters through physical Accumulate. A
`CrdtSyncEnvelopeV2` carries advertised heads, canonical causal nodes, the
content-addressed blobs they reference, and each node's finalized admission
receipt. The guest verifies receipt/service identity, node CID, change-ID
deduplication, exact causal height, complete ancestry, workflow rules, and blob
hashes before staging anything. It unions heads without dropping concurrent
branches, reconstructs continuation/inbox/outbox/workflow rows from the DAG,
and commits nodes, receipts, blobs, materialized rows, and the new header in
one transaction. A synced replica retains admission receipts so it can safely
forward the same DAG; the read-only local scheduler merely packages those
bytes and never applies them.

## Continuations

An await checkpoint stores the exact nested kernel: each VM's program hash,
PC, registers, heap bounds, gas and lifecycle, mutable capabilities, dirty
page hashes, active/runnable scheduler state, nested call stack and the pending
protocol boundary. Resume consumes the checkpoint, injects one result into its
declared registers and continues at `resume_pc`. It never restarts the handler
at PC 0. Suspended actors are non-reentrant; later messages remain queued.

The local conformance host persists the complete committed service image as a
canonical `LocalJamStoreSnapshotV2` wire. Restore verifies every blob and
program against its content identity and validates the current v2 store header
before exposing any rows; in-flight transactions and host verifier policy are
deliberately excluded. `DurableJamStoreV2` sends that candidate image through a
`CommittedImageStoreV2` boundary before making it visible or returning effects.
The filesystem backend flushes a sibling file, atomically renames it, and syncs
the parent directory. A backend rejection leaves the previous in-process image
visible and the same work may be retried exactly.

`LocalRootTreeServiceV2` is the reusable local ownership boundary used by
hosts. It validates the package/service/deployment tuple, installs an empty
backing image through physical Accumulate, and on restart rejects any stored
service, root actor, program, policy, initial-state, or external-binding
mismatch. Its ordinary invocation path schedules exclusively from committed
guest state. Non-empty replies, outbox records, blobs, and proofs remain in the
guest-owned publication table until the host submits their exact commitment to
physical Accumulate for acknowledgement.

`VosNode::register_v2_root_at_id` attaches that owner to the existing node
transport without converting its `ActorId` into a route identifier. Direct v2
calls use `RootTreeInvocationV2`, which carries the stable `InvocationId`,
logical timeslot, exact actor, method, arguments, and proof mode. The service
thread derives typed origin and authorization from the authenticated transport,
checks them against the signed method policy, and rejects a retry whose durable
workflow identity differs. A reply-only publication is acknowledged only after
the consumer channel accepts it. For locally routed roots, a committed outbox
publication is sent as `RootTreeTransportV2`, admitted through destination
physical Accumulate, executed from the guest inbox, returned only after the
callee's Refine/Accumulate commit, and injected at the caller's exact JAR
snapshot boundary. The source outbox and callee reply publications are removed
only after commitment-bound acknowledgements; retries recover their original
logical timeslot from guest workflow state. After a host restart, a pending
callee reply also reconstructs its caller actor and invocation from the
authenticated workflow origin and causal parent rather than a process-local
return table. A retried direct invocation is classified from the durable
workflow row and the invocation embedded in the current continuation snapshot:
it reattaches its caller channel to a suspended machine without replaying slice
zero, or publishes the pending effect from the latest completed slice using
that slice's committed timeslot. The retry timeslot is not part of stable
ingress identity; actor, method, arguments, origin, authorization, causal
binding, application blob references, and proof mode are. A completed workflow
whose publication was already externally accepted is refused rather than
executed again. Continuation blob references may coexist with an outbox record
because those pages are already committed in the source content store and
never become destination state. Cross-node actor-route discovery and proof/blob
publication drivers remain to be attached. Attested ingress currently fails
closed unless a proof producer is configured.

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
after the local service image commits. Each cursor advance also records the
canonical `LocalJamStoreSnapshotV2` image for that exact log index. Automatic
compaction cannot cross this durable application cursor and freezes the matching
image—not a newer mutable state row—into a `CommittedServiceSnapshotV2`.
A lagging follower receives that envelope through Raft `InstallSnapshot`,
checks that its bound index matches the installed snapshot metadata, durably
replaces its physical service image, and only then advances `last_applied` and
replays any surviving log tail.

Every await is a durable slice boundary. Effects before it may commit even if a
later slice fails, so multi-await handlers have saga semantics. Same-tree calls
may execute inline. Cross-root calls always use durable outbox/inbox rows and a
`CallId` derived from `(InvocationId, await ordinal)`.

## Packages and identity

`.vos` v2 packages bind the service ABI, execution-semantics ID, canonical
actor PVM and its `ProgramId`, interfaces, role policies and schemas. Optional
ELF/source-map data is diagnostic only. `DeploymentId` excludes diagnostics
and signatures but includes the authoritative manifest and PVM bytes.
Registries store these bytes and never retranspile an ELF. JIT products,
proving keys and traces are caches keyed by `ProgramId`.

Build the infrastructure artifact once with the pinned workspace and JAR
revision, then give those exact bytes to every application package build:

```sh
cd services/vos-service && cargo +nightly actor
cd ../..
cargo run -p vosx -- service-pvm \
  services/vos-service/target/riscv64em-javm/release/vos_service.elf \
  --out dist/vos-service.pvm
cargo run -p vosx -- build examples/v2/counter \
  --service-pvm dist/vos-service.pvm
cargo run -p vosx -- run dist/Counter.vos \
  --service-pvm dist/vos-service.pvm \
  --method value
```

`service-pvm` rejects an ELF without the physical JAM Refine/Accumulate entry
shape. `build` derives the service `ProgramId` from the validated PVM bytes; it
never accepts a hand-entered service hash. `run` validates that same identity,
installs the root tree through physical Accumulate, schedules Refine from
guest-committed state, and publishes the reply only after physical Accumulate
accepts the transition. Raw ELF/PVM inputs still use the explicitly legacy
single-actor runner while the production daemon is being cut over.

`space up --service-pvm <exact-vos-service.pvm>` recognizes signed `.vos`
catalog artifacts and opens each Local deployment as one durable root-tree
service. It validates the package signature and exact pinned service
`ProgramId`; it never extracts the actor PVM into `VosNode`'s legacy runtime or
retranspiles an ELF. Normal actors installed as CRDT are refused. V2 Raft and
CRDT rows also remain fail-closed until their request-log and anti-entropy
drivers are attached to the daemon; legacy ELF/PVM rows continue on the old
host only during this staged cutover.

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
cache. Concurrent identical messages are add-wins/deduplicated by stable
`CallId`; divergent continuations, replies, or executions of the same workflow
step are rejected instead of selecting an arbitrary branch.

Concurrent scalar assignments retain alternatives through `conflicts()` while
choosing the same visible value; counter increments, list and text operations
merge without dropping a DAG branch. Constraints such as uniqueness,
overdraft prevention or irreversible global ordering require Raft or a
purpose-built conflict-free construction.
