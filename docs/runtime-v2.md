# VOS runtime v2 contract

> Implementation status: the versioned contracts, conformance service, package
> tooling, canonical `vos-service.pvm`, exact JAR restoration, durable local
> scheduler, local cross-root delivery/resume, and guest-owned CRDT
> synchronization described here are present in the v2 conformance runtime.
> The production node now opens signed `.vos` rows through the same root-tree
> services. Package publication, recipe reconciliation, one-shot execution,
> and production catalog-row startup reject raw artifacts. Existing raw registry
> rows fail with an actionable rebuild/reset error; regression actors remain
> test fixtures.

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
operations, direct-ingress admissions, continuations, inbox/outbox rows and the
receipt atomically.
Replies, outbound calls and proof packages become visible only after that
commit. A stale linear transition is rejected intact for rescheduling.

Publishable effects also live in a guest-owned `PublicationRecordV2` keyed by
the consumed workflow input. A process restart drains these committed records;
an exact retry returns no duplicate effects but cannot erase the pending row.
After the external consumer accepts the reply, outbox batch, or proof package,
the host submits a commitment-bound acknowledgement through physical
Accumulate. That acknowledgement deletes the pending record atomically and is
itself idempotent. Proof-bearing publications move in the same transaction to
a guest-owned physical archive outside the actor state root. This avoids a
receipt/root commitment cycle while allowing an exact direct-invocation retry
to return the identical statement, receipt, trace commitment, and proof bytes
without replaying or reproving the actor.

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
protocol boundary. Its VOS envelope also records the canonical
actor/`DeploymentId`/`ProgramId` layout used to create every dormant handle.
Resume consumes the checkpoint, reconstructs that exact layout, injects one
result into its declared registers and continues at `resume_pc`. Actors spawned
after the checkpoint remain in the complete current work import but do not
rewrite the older JAR invocation-layout commitment. Resume never restarts the
handler at PC 0. Suspended actors are non-reentrant; later messages remain
queued.

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
physical Accumulate for acknowledgement. `open_raft` composes the same owner
with `ReplicatedJamServiceV2`: genesis, direct ingress, delivery, actor apply,
and publication acknowledgement enter the canonical Raft request log before
IC-5 mutates the local service image. Followers catch up the exact request log
and committed service snapshot; they never apply native actor commands.

`VosNode::register_v2_root_at_id` attaches that owner to the existing node
transport without converting its `ActorId` into a route identifier. Direct v2
calls use `RootTreeInvocationV2`, which carries the stable `InvocationId`,
logical timeslot, exact actor, method, arguments, and proof mode. The service
thread derives typed origin and authorization from the authenticated transport,
checks them against the signed method policy, and rejects a retry whose durable
workflow identity differs. For Local/Raft roots, every fresh direct call first
enters physical Accumulate as an `IngressEnvelopeV2` containing
`DirectIngressV2` and any newly supplied content-addressed input bytes. The
guest validates its typed origin, authorization, actor, signed method policy,
and every supplied blob before atomically importing those bytes and storing the
queue record. An attested role credential is carried as a private witness blob;
the durable ingress and later attestation statement expose only its reference
and commitment. The credential wire and commitment include the exact
`SpaceId`; Refine and guest Accumulate reject evidence issued for a sibling
space before exposing its role to actor code. Refine runs only from that stored
input. If the actor is suspended, the record survives restart and is consumed atomically with its
eventual first slice; retry timeslots do not replace the originally admitted
scheduling timeslot. A reply-only publication is acknowledged only after the
consumer channel accepts it. For locally routed roots, a committed outbox publication is
sent as `RootTreeTransportV2`, admitted through destination
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
binding, application blob references, and proof mode are. After its publication
is acknowledged, a completed workflow returns the canonical reply retained in
guest workflow state without executing the actor again. Continuation blob
references may coexist with an outbox record
because those pages are already committed in the source content store and
never become destination state. An authenticated operator/runtime may bind a
canonical `ActorId` to an immutable physical `ServiceId` with
`VosNode::bind_v2_actor_route`; the same guest-owned delivery, reply, and
acknowledgement protocol then runs across connected libp2p nodes. Registry-backed
package resolution now derives exact external actor identities from signed
`.vos` rows. Cross-node physical route discovery and proof/blob publication
discovery still requires an authenticated route binding. Proof-bearing replies
already use the same committed root transport locally and across bound network
routes: canonical decoding binds the complete package to the source
publication, and destination guest Accumulate rechecks the pending call,
receipt, proof expectation, and signed external-actor identity. Attested
ingress fails closed unless a proof producer is configured. Before a producer
is called, the service deterministically replays the submitted work with JAR's
canonical interpreter observer, follows every nested CALL/REPLY VM switch, and
commits instruction state, protocol-call requests/results, checkpoint
artifacts, transition bytes, and gas. The replayed transition and artifacts
must exactly match the Refine envelope. The producer receives the exact target
actor PVM separately from the complete canonical import set, plus the live
instruction/protocol/switch counts and observed code hashes; its trace must
equal that live commitment before proof availability or Apply is attempted. The
Local, CRDT, and Raft node registration APIs each have an explicit
`*_with_producer` form; the ordinary forms deliberately install no fallback
producer. CRDT proof generation precedes its causal Apply, and Raft proof
generation precedes proposal of the exact Apply request to the accumulation
log.

An attested Refine result containing a continuation, durable outbox, or no
final reply is returned as `AttestationError::CannotSuspend` before the proof
producer or physical Accumulate runs. Deterministic same-tree calls that finish
inline leave none of those artifacts and remain part of the single traced
slice. Guest Accumulate repeats the shape check so a host cannot bypass it.

The remaining production gap is a proof backend that consumes or reproduces the
full witness behind this commitment; it is not a second attestation-only actor
binary.

Raft orders canonical `AccumulateRequestV2` bytes, including private ingress
witnesses and every referenced continuation/blob byte required by that request.
It does not replicate an `EffectLog` or a leader-produced post-state image.
`ReplicatedJamServiceV2`
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

## Actor upgrades

`UpgradeActor` is a guest-owned Accumulate operation, not a native descriptor
rewrite. The canonical request binds the service and actor, expected and
replacement actor `DeploymentId` and `ProgramId`, replacement producer and
generated method policies, an exact consistency base, and an authenticated
system capability. The host
must authorize those exact physical request bytes and already possess canonical
replacement PVM bytes matching the requested `ProgramId`.

For Ephemeral, Local, and Raft services, guest Accumulate requires the exact
current revision and state root. It rejects an actor as `ActorBusy` while any
durable continuation in the root tree still binds that actor's package/program
in its dormant JAR layout. It replaces only that actor's
package/program/producer/policy rows, and preserves instance identity,
ownership, consistency kind, and application state. A
physical upgrade record makes an exact retry read-only. The old program remains
in the content-addressed program store; activation cannot occur until its
continuation references drain, and conservative cache retention keeps the old
bytes available afterward. Queued ingress may use the new program only after
the upgrade commits.

For CRDT services, an upgrade is a standalone workflow-DAG operation whose
change ID binds the exact request and causal heads. Each replica validates the
expected package against the descriptor visible at those heads, checks every
continuation visible there for the old package, and activates the node only
after its complete ancestry and canonical replacement PVM are available.
Sync receipts bind the exact upgrade hash and causal node; PVM imports, DAG
rows, receipts, deduplication records, and descriptor materialization share one
Accumulate transaction. Concurrent upgrades remain as separate DAG branches.
The visible package is selected deterministically by `DeploymentId` (then CID),
while a later upgrade observing all heads causally supersedes those alternatives.
This winner applies only to the package register; no CRDT branch is discarded.

The local root-tree controller exposes the deployment sequence explicitly:
`prepare_actor_upgrade` derives one exact request from committed guest state,
`stage_actor_upgrade` validates the replacement `.vos`, imports its canonical
PVM, and authorizes only that request, and `commit_actor_upgrade` submits it to
physical Accumulate. Keep the prepared request for retries. For Raft, stage the
same signed package and request on every replica before the leader commits its
log entry; followers then apply the canonical request during catch-up. Reopen
validation accepts only the descriptor fields that `UpgradeActor` may change
and continues to require stable actor identity, ownership, state kind, and
initial-state reference. Both old and replacement PVM bytes survive restart.

## Packages and identity

`.vos` v2 packages bind the service ABI, execution-semantics ID, canonical
actor PVM and its `ProgramId`, interfaces, role policies and schemas. Optional
ELF/source-map data is diagnostic only. `DeploymentId` excludes diagnostics
and signatures but includes the authoritative manifest and PVM bytes.
Registries store these bytes and never retranspile an ELF. JIT products,
proving keys and traces are caches keyed by `ProgramId`.

The service identity retains the root package `DeploymentId` selected when
the root tree is installed; it is the stable service/routing identity. Every
actor descriptor separately retains the exact current package `DeploymentId`.
Refine work, continuations, transitions, external dependency bindings, and
attestation statements bind that actor deployment together with its
`ProgramId`. Guest-owned upgrades change the actor package identity without
rewriting the service identity, including policy/schema-only upgrades whose
canonical PVM bytes are unchanged.

Cross-root dependencies are declared by install-time actor name in the signed
manifest. `vosx build --external-actor <name>` is repeatable; names are sorted
and become part of the `DeploymentId` and deployment signature. At `space up`,
the daemon resolves every name to an exact signed `.vos` registry row in the
same space and derives its `ServiceIdentityV2`, root `ActorId`, producer, and
actor `ProgramId`. A missing row defers the consumer, and a missing package
blob is fetched before retry. Legacy artifacts, invalid signatures, mixed
service PVMs, and invalid consistency modes fail closed. Bindings do not float
to a later dependency deployment: upgrade the consumer package when changing
an external actor deployment.

Build the infrastructure artifact once with the pinned workspace and JAR
revision, then give those exact bytes to every application package build:

```sh
cd services/vos-service && cargo +nightly actor
cd ../..
cargo run -p vosx -- service-pvm \
  services/vos-service/target/riscv64em-javm/release/vos_service.elf \
  --out dist/vos-service.pvm
cargo run -p vosx -- build examples/actors/counter \
  --service-pvm dist/vos-service.pvm
cargo run -p vosx -- build examples/actors/age-gate \
  --service-pvm dist/vos-service.pvm \
  --external-actor private-age
cargo run -p vosx -- run dist/Counter.vos \
  --service-pvm dist/vos-service.pvm \
  --method value
```

`service-pvm` rejects an ELF without the physical JAM Refine/Accumulate entry
shape. `build` derives the service `ProgramId` from the validated PVM bytes; it
never accepts a hand-entered service hash. `run` validates that same identity,
installs the root tree through physical Accumulate, schedules Refine from
guest-committed state, and publishes the reply only after physical Accumulate
accepts the transition. `run` rejects raw ELF/PVM inputs; ELF is transpiled
only by `build`, and registries or runners consume the resulting exact package.
Application actors are never baked into `vosx` as raw ELF publication shortcuts;
`space publish` requires an explicit signed `.vos` source.

`space up --service-pvm <exact-vos-service.pvm>` recognizes signed `.vos`
catalog artifacts and opens each Local, Raft, or CRDT deployment as one durable
root-tree service. It validates the package signature and exact pinned service
`ProgramId`; it never extracts the actor PVM into `VosNode`'s legacy runtime or
retranspiles an ELF. Normal actors installed as CRDT are refused. V2 Raft rows
use the existing voter discovery, join, election, and RPC-handler path,
but their log payload is the canonical `AccumulateRequestV2`, not an
`EffectLog`. V2 CRDT rows serve point-fetched guest-exported causal packets;
the receiver assembles complete ancestry and submits it to physical
`SyncCrdt` Accumulate on the owning root thread. Native sync never writes or
materializes v2 actor state. Raw ELF/PVM catalog rows are never started by the
production daemon.

`space install` records only the signed deployment identity, root-tree
replication settings, and immutable external bindings. It does not accept
constructor arguments or execute actor code. Any application initialization is
an explicit typed invocation after installation, so authorization,
deduplication, state changes, and replies cross the same durable
Refine/Accumulate boundary as every later message. The v2 registry `install`
wire and `AgentRow` contain no constructor-argument or cold-start-payload
fields.

This is a clean storage and wire break. A v1 store or package must be reset and
reinstalled; there is no v1 decoder or migration in a v2 service.

CRDT direct ingress is itself a guest-authenticated workflow DAG node. Its
exact causal base, stable invocation identity, authorization input, and
accumulation receipt replicate before actor Refine runs; synchronized replicas
rematerialize the same queued/consumed ingress record through physical IC-5.
Store schema 14 and continuation snapshot version 5 are therefore a clean
break from earlier experimental v2 images. They add exact actor-package
identity to descriptors, work, checkpoints, transitions, upgrades, and
cross-root proof bindings, the immutable install descriptor used to replay
causal package metadata, the immutable role-authority binding, plus the complete
dormant actor-program layout in each continuation.

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
