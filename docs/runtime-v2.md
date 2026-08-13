# VOS runtime v2 contract

> Implementation status: the versioned contracts, guest service state tree,
> canonical `vos-service.pvm` Refine/Accumulate entries, package tooling, actor
> APIs, and CRDT primitives described here are present. The local v2 harness
> executes both phases through that PVM and commits only an accepted guest
> result; it has no native transition-apply shortcut. `VosNode` can attach an
> explicitly opened Local, Raft, or CRDT v2 root and route ordinary public
> calls, durable cross-root outbox delivery, inbox execution, exact
> reply/timeout resume, and
> restart retries through Local and Raft roots. Enrolled nodes automatically
> exchange complete authenticated CRDT frontiers and redrive them after restart.
> A direct space-role-only call to a Local, Raft, or CRDT
> root obtains an invocation-scoped accumulated assertion from that space's
> installed Raft `space-authority`; caller-supplied legacy role bytes are ignored. Signed v2
> catalog rows use this root service when the daemon is started with the exact
> service PVM. Actor-local or mixed-role external calls, role-bearing durable
> calls, CRDT cross-root calls, and attested network
> transport remain fail-closed. Legacy node behavior is
> not evidence of v2 conformance.

The local conformance scheduler can admit one guest-committed durable inbox
row, derive the callee invocation, origin, authorization and causal parent from
that row, enforce its deadline, and consume it atomically with the callee's
first accepted slice. Its logical timeslot is an explicit harness input;
production integration must bind that value to the consensus JAM timeslot
rather than accept a caller-selected value. Actor-side cross-root CALL now
emits a durable outbox row and captures the exact pending protocol boundary.
Fresh Local/Raft root invocations likewise enter physical Accumulate as a
guest-authenticated direct-ingress row before Refine executes. The guest binds
the typed origin, authorization, actor, signed method policy, imported blobs,
and original logical timeslot. A busy actor leaves that row queued across
restart, and the eventual first accepted slice consumes it atomically.
For linear services the guest-owned workflow row reconstructs every later
slice after restart without a process-local copy of the original request.
It can also rediscover a suspended outbound call, submit one canonical
`ExpireCall` request when the consensus logical timeslot reaches its recorded
deadline, and reconstruct the exact timed-out resume after another restart.
Deadline-bearing calls are indexed in guest-owned physical rows when their
outbox entry commits and removed with reply admission or expiration, so this
scan requires no process-local `InvocationId`. IC-5 independently reads an
ambient Accumulate-only timeslot capability and rejects expiration when that
trusted observation is absent or still before the deadline; the scheduler's
due-time filter is only an orchestration convenience.
Expiration outcomes have a separate durable index. The node enumerates that
index on every transport poll and after restart, then filters it against the
current continuation before resuming, so a crash after deadline removal cannot
strand the suspended workflow. Linear expirations are prepared and committed
one at a time against the freshly advanced service revision.
The committed outcome uses the deadline itself as `expired_at`, so hosts which
first observe the due call in different later slots still derive identical
bytes.

Cross-root transport is guest-owned end to end. An accepted
actor slice stores a recoverable publication row whose receipt commits the
complete canonical outbox. After restart, transport selects a message from
that publication. Each message commits the exact source and installed
destination service identities as well as both ActorIds; destination
Accumulate rejects a different root which merely reuses either ActorId. It
also verifies receipt finality,
producer ownership, full-outbox membership, deadline and the exact current
destination base before atomically inserting the inbox. External directories
reject duplicate ActorIds, so application resolution cannot collapse two
service bindings onto one route. A stable delivery
identity excludes that changing base, so a retry after inbox execution is
still an idempotent duplicate. Guest delivery records retain the admission
timeslot and consumed bit; the local scheduler scans them after restart and
drains runnable inbox rows through Refine plus Accumulate at an explicit later
logical timeslot. Publication removal is a separate guest Accumulate
acknowledgement performed only after the external consumer is durably
committed. The exception is an undelivered call which expires at its source:
expiration atomically retires its publication and deadline index, and a later
reply is classified terminally from the permanent expiration row.

For a CRDT destination, `Deliver` derives its own causal workflow node after
verifying the finalized source receipt. The node retains the complete source
outbox and destination observation, and materialization reconstructs both the
inbox and permanent delivery record on every replica. Concurrent retries may
observe different destination heads or trusted slots; they retain distinct
physical CIDs but collapse by stable message/outbox identity before any
descendant workflow is evaluated. A replica also reconstructs pending source
publications from synchronized workflow nodes. Its permanent acknowledgement
marker suppresses publications whose logical reply/outbox was already accepted
without treating branch-local continuation blobs as new external effects.
The logical delivery and ordinary-reply identities retain the producer service
and finality domain but exclude branch-local fields of the physical CRDT
receipt, so equivalent finalized branches converge. Every submitted physical
receipt is still authenticated before admission or duplicate classification.
A causal expiration is also a terminal publication disposition and suppresses
reconstruction without requiring an external acknowledgement row. Proof and
attestation packages are not encoded in causal workflow nodes; synchronization
therefore preserves a producer's complete local publication but never
synthesizes or validates a stripped proofless form on another replica.

The transport also routes a committed callee reply back to
the caller service. It recovers the exact caller invocation from the
guest-owned outbox, reconstructs the saved machine after restart, and submits
the physical Refine result to guest Accumulate. A permanent reply-admission
record binds the `CallId`, accumulated reply, work input and work hash, so a
lost transport acknowledgement remains an idempotent duplicate after another
restart or a later workflow slice. The callee publication is acknowledged only
after the caller commit succeeds.
Node envelopes retain the authenticated source peer separately from the exact
destination peer selected by the external directory. An explicit destination
is routed before the lossy 16-bit local-prefix test, so a prefix collision can
neither redirect remote traffic locally nor change who authenticated inbound
delivery, reply, or acknowledgement bytes.
When the original message requests an attestation, the drain path performs
read-only preparation, proof production and proved guest Accumulate rather
than submitting an ordinary Apply. The recoverable publication retains the
guest-derived producer name, `ProducerId`, statement and proof commitment;
reply routing carries those exact fields and the content-addressed proof bytes
into the restored caller.

The local host serializes the complete committed service image as canonical
`LocalJamStoreSnapshotV2` bytes. Restore checks the current store header and
recomputes every blob and program identity before exposing the image; in-flight
transactions and process-local receipt policy are excluded. `DurableJamStoreV2`
persists each candidate image through a `CommittedImageStoreV2` backend before
swapping it into live state or returning published effects. A backend failure
leaves the prior in-process image visible and permits an exact retry. The
filesystem backend flushes a sibling candidate, atomically renames it over the
committed image, then syncs the parent directory.

`LocalRootTreeServiceV2` is the reusable single-writer ownership boundary for
one root actor tree. Before opening storage it cryptographically verifies the
package deployment signature and validates the actor capability layout, exact
service/deployment/program/ABI/semantics tuple, consistency choice, gas
schedule, root descriptor, external bindings, and complete canonical genesis
wire. A fresh image imports the canonical actor PVM and initial state, then
installs only through physical Accumulate. A reopened image must carry the
same service identity, consistency, installed root descriptor, actor program,
and external directory; dynamically spawned children may already have grown
the guest-owned actor directory. Ordinary calls are scheduled exclusively
from committed guest state and run through physical Refine followed by
physical Accumulate. Before scheduling, a repeated direct invocation is
matched against its guest-owned workflow checkpoint and input-deduplication
record. An exact retry reattaches the committed receipt and any pending
publication without executing the actor; divergent reuse of the invocation is
rejected. Replies and outbox effects remain in the durable publication table
until their exact commitment is acknowledged through physical Accumulate.
The direct constructor rejects `Raft` consistency rather than claiming
replication without a driver. `open_raft` composes the same owner with
`ReplicatedJamServiceV2`: genesis, actor Apply, and publication
acknowledgement enter the canonical Raft request log before IC-5 mutates the
local service image. Followers catch up those exact requests and installed
service snapshots; they never apply native actor commands. Attested work
remains rejected until a proof producer is explicitly connected by a later
host surface.
Every native `std` host verifies the deployment's frozen libp2p-Ed25519 wire
through its existing native crypto provider. Bare single-node hosts therefore
retain the same authority check without requiring network transport or adding
a host-only dependency to canonical riscv64 service and actor guests.

`VosNode::register_v2_root_at_id` attaches that boundary without extracting
the actor PVM into the legacy runtime. Its strict `RootTreeInvocationV2` keeps
the full `ActorId`, `InvocationId`, method, arguments, and proof mode intact
until the service builds work from guest-owned state. Logical time is not an
external field: the node stamps a trusted, monotone admission slot at the
scheduler boundary. The invocation is then guest-admitted before actor Refine;
exact retries reattach through the ingress, workflow, and dedup records, which
retain the original admitted slot. The
guest-owned store header advances a durable admission-timeslot high-water in
the same transaction as each newly accepted slice, delivery, or timeout.
Registration restores the node-wide allocator strictly above every opened
root's high-water before publishing its route, so a process restart or
backward wall-clock adjustment cannot issue a slot below committed local
work. A Raft follower may register before genesis has committed; it has no
header yet, and defers restoration until catch-up installs one. Every later
catch-up restores the allocator again before the next ingress, covering a
newer replicated high-water learned after registration. Exact duplicates do
not advance or rewrite that committed floor. The default host bound handle
resolves `ActorId` directly rather than truncating it to a `ServiceId`. This
first node cutover admits only ordinary methods whose
signed installed policy is public and non-attested; protected or attested
methods fail closed instead of inheriting the legacy trusted-System role
bypass. Space startup installs the immutable-root-signed canonical
`space-authority` package as its own Raft root. Root-signed role mutations,
delegated invite redemption, and grow-only invite cancellation execute in
that actor. For invite redemption the serving immutable-root host first waits
for physical Accumulate to publish `Bool(true)`, then signs that exact
redemption and records the attestation with the registry CRDT operation; a
rejected authority transition can never create an effective registry grant.
The joiner deletes its pending bearer only after both commits succeed. The
admin signature binds the authority's replication incarnation, so a lagging
registry replica cannot turn absence of its catalog row into legacy completion;
markerless invitation minting and redemption are disabled. Activation first
runs a read-only guest preflight: exactly one node must remain enrolled, with
no effective non-root grant,
dormant revivable grant, or live actor-local ACL. The separately root-signed
seal is unconditional and monotone, so CRDT replay can never erase it merely
because a concurrent legacy row materializes in a different order. The
one-node condition is the conservative operator admission point for this CRDT
cutover; any previously unseen legacy row that materializes afterward has no
authority witness and therefore fails closed. Migration is an explicit
revoke/remove-before-cutover and re-grant-after-cutover operation; rows already
dominated by their holder's own revoke high-water do not block it. Registry and
authority use the same total grant order (rootness, epoch, grantor, role), and
post-cutover registry grants carry one fixed-size, point-addressed guest-owned
witness per peer in a private storage map which catalog metadata cannot address.
An invitation witness additionally carries the immutable
root host's signature emitted only after the exact authority commit; a bare
caller-supplied authority ID is never sufficient. A direct reply is
acknowledged only after its waiting channel accepts the bytes. Ordinary outbox
and suspended-workflow publications are retried by the node transport until
the destination guest has committed them. Local, Raft, and CRDT roots share
that guest-owned publication state machine. For a Raft destination, the
authenticated source-receipt decision is quorum-ordered beside `Deliver` or
the resumed `Apply`, so a follower never depends on the leader's process-local
receipt cache. Proof and attestation publications stay durable but are not
admitted by this ordinary node route. The host-generated logical timeslot is still a local admission
ordinal, not a consensus JAM slot.

`RootTreeTransportV2` is the canonical node wire for an ordinary publication,
reply, or exact publication acknowledgement. It carries no observation slot:
the receiving root first completes its admission barrier, restores the durable
node-wide high-water, and allocates the slot locally. The sender and receiver
both check the full `ServiceIdentityV2` committed in the message; a node route
is usable only when its ActorId and service identity match a trusted directory
binding. Across network links, the envelope source prefix must also belong to
the authenticated peer, so peer-selected payload bytes cannot impersonate a
different local route. Raft actor routes retain the exact replication ID and
only a bootstrap replica: every delivery, reply, and acknowledgement resolves
the current leader through group status plus the canonical voter row's full
Noise `PeerId`. A locally attached current leader is selected before network
discovery, including the supported networkless single-voter configuration.
Remote discovery never blocks the global envelope router: it has one bounded
worker per destination root, coalesces repeated durable redrives, briefly
caches a verified leader, and backs off after failure. Only the source leader
redrives durable publications. After failover it reconstructs process-local
multi-consumer progress by replaying the publication and collecting the
destinations' permanent duplicate acknowledgements; an acknowledgement
received by a follower is never retained as authoritative progress. The
transport wire names both its destination and source actor/service identities,
so this resolution is unambiguous even when roots reuse a local route suffix on
different nodes. The router is trusted for eventual delivery, not for safety:
dropping an acknowledgement can delay reclamation, while guest-owned delivery,
input, and reply-admission records prevent double execution.

The local transport accepts either the in-memory host or this durable host
without changing scheduling or service semantics. Its physical cross-root
gate reopens both roots exclusively from committed backend bytes throughout
delivery, inbox draining, reply resume, and publication acknowledgement.
Injected destination and caller commit failures expose neither an admitted
inbox nor resumed reply effects; the exact envelopes remain retryable from the
previous durable images.

Attested linear slices use a read-only physical Accumulate preparation before
proof production. The guest derives the predicted accumulation receipt and
statement from committed service state, the exact work and transition, the
installed method policy, and the installed actor's producer identity; the host
does not reconstruct or relabel those public inputs.
The proof producer receives that preparation together with the canonical
service PVM and Refine imports. Before invoking it, the service replays the
exact work through the canonical interpreter observer, including nested
`CALL`/`REPLY` execution, protocol requests and injected results, checkpoints,
the transition, artifacts, and gas. The replayed transition and artifacts
must equal the proposed envelope, and the producer must return the resulting
nonzero trace commitment. The final Apply carries the proof bytes as a
content-addressed verifier/CAS input. Proof bytes do not enter the
recoverable service image or its retained Raft snapshots. A durable host
writes them to a separate content-addressed proof store before proved
Accumulate can publish their commitment, so reply routing can refetch the
exact bytes after the producer restarts; the committed publication stores
only their content reference. Guest Accumulate re-derives
the statement, invokes `PROOF_VERIFY`, and commits or publishes the proof
package only when that exact request is valid and available. Raft orders only
the final proved Apply: preparation remains read-only, while followers hydrate
the verifier from the carried proof bytes and execute the same guest gate
before advancing their apply cursor. An exact retry recovers the existing
proof publication during preparation and does not propose another Apply.

The application package is a portable typed `Attestation<T, M>`, not a bare
claim. Its generated method marker binds the method and exact actor reply wire;
the preview remains explicitly unverified. Portable decoding authenticates the
supplied claim bytes before deserializing them and requires their canonical
re-encoding to match, while generated `Option<T>` replies use an explicit
None/Some tag so zero-sized values remain injective. The verifier-only path
resolves the named producer and method from an authenticated registry and pins
the complete current service identity, actor, canonical actor program, schema,
authorization policy and typed `ProducerId`.
It independently verifies both accumulation-receipt finality and the actor
proof against the statement commitment and the package's exact trace
commitment. It also reconstructs the exact reply commitment from the
statement's call ID, actor and authenticated claim wire, before admitting the
`(space, deployment, actor, invocation)` replay key. Proof validity alone is
insufficient because proof production precedes Accumulate; a transition that
never committed must never become `Verified<T>`. The replay admission must be
durable and atomic with any state change the verified claim authorizes.

The statement's input commitment includes the full authorization scope, which
cryptographically binds the typed origin without necessarily revealing a
private member. A generic portable attestation is nevertheless not a bearer
identity credential: a relying application that needs to associate the claim
with a particular subject must include a suitable subject or unlinkable
pseudonym in the typed claim, or verify an application-defined opening of that
input commitment.

The local proof producer and proof-verification allowlist are conformance
seams, not a production proof system. A production host must replace them with
the pinned prover/verifier implementation. Portable verification already
passes the exact serialized trace as a proof public input; a production prover
must additionally derive that trace from the observed canonical Refine
execution rather than relying on the producer interface contract alone. There
is still no attestation-only
actor binary: proof production always receives the live actor program through
the canonical Refine imports.

CRDT anti-entropy also enters through physical Accumulate. A
`CrdtSyncEnvelopeV2` carries advertised heads, canonical causal nodes, the
content-addressed blobs they reference, and each node's finalized admission
receipt. The guest verifies receipt/service identity, node CID, change-ID
deduplication, exact causal height, complete ancestry, workflow rules, and blob
hashes before staging anything. It preserves concurrent heads, reconstructs
continuation/inbox/outbox/workflow rows from the DAG, and commits nodes,
receipts, blobs, materialized rows, and the header atomically. The read-only
local scheduler only packages these authenticated bytes.

`VosNode` exports complete history locally, then splits it into causally
ordered deltas below the network frame limit. Each delta commits through guest
Accumulate before the receiver acknowledges it; the source advances that
peer's cursor only after the acknowledgement. Each peer finishes an immutable
transfer even while local writes advance the latest frontier; the next
transfer offered to that peer then uses the newest frontier, while topology,
pagination, and other peers' chunk cursors remain intact. Old chunk vectors
are released when their last peer advances. A completed registry scan evicts
removed peers, exact authorization precedes transfer assignment, and a peer
whose outstanding chunk remains unacknowledged for thirty seconds releases
its snapshot and restarts from the newest transfer. Time spent waiting for its
next bounded round-robin turn after an acknowledgement never counts as a
stall. Lost process-local progress
restarts at the first chunk and is safe because the guest classifies already
committed causal nodes idempotently. Node-roster pagination also retains its
opaque cursor and fans out each completed page, so registries larger than one
scan budget continue to make progress. A full-peer-identity round-robin cursor
also advances before each authentication attempt. Each drive attempts at most
four retry-eligible peers, so failed or stalled authorization cannot bypass the
work bound or let an early group of offline replicas starve later roster
members.

Both outbound selection and inbound admission bind the complete Noise
`PeerId` to an exact voter/observer registry row and apply the actor's existing
sync floor. Enrollment satisfies `Member`, but a `Private` root additionally
requires a space or actor-local read grant; enrollment alone never discloses
private state or authorizes imported history. If the actor catalog row or its
sync floor cannot be resolved exactly, synchronization fails closed rather
than assuming the `Member` floor. The transport carries no
verifier allowlist. After checking the destination service identity, the root
thread derives the complete ordered
`ReceiptVerificationRequestV2` sidecar locally before entering IC-5. Missing,
extra, or substituted verifier entries are rejected at the service boundary.
This is the same non-Byzantine authorized-replica trust boundary used by the
current cluster drivers: an admitted replica is trusted to advertise only
finalized CRDT receipts. A Byzantine-capable deployment must replace that
decision with independently verifiable receipt certificates; a peer-supplied
envelope alone is never authority.

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

Installation commits the canonical actor directory and each actor's
parent-scoped name in guest-owned service state. Every Refine invocation imports
the exact code, state frontier and continuation status of all directory members;
guest Accumulate rejects a partial or differently named tree. The infrastructure
PVM instantiates at most four application actors: the pinned JAR kernel has one
shared five-entry code-capability table and the generic service consumes one
entry. It grants only idle peers a directory-indexed JAR `CALLABLE`.

The shared CALL IPC contains only the generated target identity, await ordinal
and message. The canonical actor directory, actor state and authenticated
caller fields arrive through a scheduler-supplied private capability bound to
the currently active JAR VM; nested `Origin::Actor` is derived from the live
call stack. The complete move-only IPC page is zeroed before and after every
hop, so a shorter call cannot observe a prior sibling's tail bytes. Each actor
exports its own canonical effects through a second scheduler capability; a
parent sees only the child reply and checkpoint control flow, while the generic
service guest canonicalizes the opaque effect batch into `TransitionV2`.
These buffers are invocation-local Refine state, never native persistent
service state. This preserves role-gated sibling-state isolation without
changing JAR CALL/REPLY semantics or making the host the transition authority.

An ordinary same-tree call executes through JAR `CALLABLE` and returns inline.
For CRDT trees, the private scheduler channel also carries a host-owned
per-actor dispatch ordinal and refreshes only that actor's private
materialization after it returns. The service guest independently requires
contiguous dispatch ordinals, aggregates operations in
`(ActorId, dispatch ordinal, operation ordinal)` order, and content-addresses
the final materialization of every actor reached by the slice. Repeated calls
therefore cannot reuse an operation namespace, and no sibling state enters the
caller-visible IPC page. A nested CRDT call must currently finish inline;
suspending a nested CRDT stack remains fail-closed until causal-branch
continuation rebinding lands.

The scheduler derives the active actor set from JAR's live call stack through
the private channel, so application IPC cannot clear it; attempting to re-enter
any active caller returns `InvokeError::Cycle`. Await ordinals are allocated
across the complete inline actor tree and flow back through the minimal call
result, preventing nested actors from deriving the same `CallId`. The
checkpoint also records the exact active actor VM which issued an awaited call;
the service and guest Accumulate both bind the durable outbox sender to that
host-derived identity. On resume the host removes every snapshot-frozen
`CALLABLE` and rebuilds routes from the current committed continuation set:
actors owned by this continuation remain available after they unwind, while an
actor locked by a different workflow cannot be entered through stale
capability state. Completed child checkpoint tokens and already-committed
effect queues are cleared before a parent can suspend again.

Actor metadata is also the source of installed method policy. `#[msg]`
annotations produce one canonical schema and role-policy artifact; package
validation derives the same artifact again and installation takes method rows
only from those signed bytes. The artifact records both space-wide and
actor-local role requirements, and a method requiring both enforces their
conjunction. Public methods use one distinguished public predicate; a method
with either role annotation is never installed as public. The v2 actor dispatch
also treats the work arguments only as application bytes. It cannot reinterpret
a caller-provided legacy dispatch prefix and replace the origin or authenticated
roles established by Refine. Application dispatch accepts only the canonical
dynamic message frame; the former typed-enum fallback used a trusted-byte
decoder and was remotely reachable, so it is not part of the v2 ABI.

This v2 cutover changes two application reply wires. `Option<T>` uses
`Value::Bytes([0])` for `None` and `Value::Bytes([1] ++ rkyv(T))` for `Some`,
including ordinary non-attested methods; generic HTTP clients therefore see
the tagged bytes rather than the legacy empty/bare-rkyv representation. Void
handlers now commit encoded `Value::Unit` rather than an empty result. The
latter changes receipt reply commitments and is consensus-visible, so stores
or receipts created under the earlier service `ProgramId` are not compatible
with the repinned v2 service artifact.

The conformance credential carrier binds its holder, invocation-scoped
authorization scope, space and actor roles, authenticator, generated policy and
exact byte commitment. The scope commits to the service and deployment
identity, invocation, actor and program, method and arguments, origin, causal
identity, and proof mode. A credential copied from one call therefore cannot
authorize another invocation. Ordinary calls disclose those bytes and guest
Accumulate additionally asks the host authority to verify the exact scoped
credential before accepting them. Attested calls carry only their content
reference and commitment in the work wire; the witness bytes live in a
process-private host store and are supplied only to Refine/proving. They are
not work imports, service-state blobs, durable service snapshots, or CRDT sync
payloads. Before entering the actor PVM, Refine checks the holder, scope and
complete role threshold and injects the authenticated roles into `Context`.
Private credentials cannot use the disclosed-credential
`ROLE_CREDENTIAL_VERIFY` hostcall because guest Accumulate intentionally
cannot read their witness bytes. Their issuer/authenticator check is therefore
part of Refine. The exact canonical Refine replay and private-policy execution
are now bound to the proof producer's trace commitment, but the check is not
consensus-authoritative until the production proof backend proves and verifies
that complete witness.
The local credential-verification allowlist is only a conformance stand-in.
Production admission therefore remains gated on a consensus-authoritative
issuer/verifier authenticating the exact scoped credential bytes and on a
proof backend that consumes the bound canonical Refine witness.

When service genesis pins a `RoleAuthorityBindingV2`, disclosed space-role
credentials instead carry an `AccumulatedRoleAssertionV2`. Guest Accumulate
requires a finalized reply from that exact authority service and producer,
binding the space, holder, role, audience service, invocation, complete
authorization scope, target actor, method, and generated policy. A copied
assertion cannot authorize another invocation or survive a package-only target
upgrade. An assertion authenticates only its space role: assertion-backed
credentials carrying an actor-local role are rejected before Refine and again
by guest Accumulate, so mixed policies require a separately authenticated
actor role. Receipt unavailability rejects the complete ingress or transition
without staging writes. Guest Accumulate also persists a transition-bound
eligibility record only for the single-slice authority reply shape. That record
survives publication acknowledgement and is required for recovery, so a reply
with a continuation, outbox, exported artifact, proof, attestation, spawn, or
other external effect cannot later become an assertion after its publication
row disappears. Private space-role credentials remain fail-closed on
authority-backed roots until the proof public inputs expose the authority
assertion independently of the private witness bytes.

For direct network ingress, the node derives that claim from the target's
guest-owned scheduler projection, asks the exact locally attached Raft
authority to finalize `authorize_role`, and admits the target only after the
returned assertion matches the installed authority and complete claim. A
denial is acknowledged as an authority publication but surfaces as
`Forbidden`; it never creates target ingress. Restart and lost-result retries
recover the original credential from the target's guest-owned direct-ingress
row, recover the same authority decision from its durable eligibility/receipt
rows, and never reinterpret the target's current package policy. This cutover
supports Local, Raft, and CRDT targets. Local and CRDT roots expose the exact
verifier decision only to the admission IC-5 call. CRDT admission retains the
scoped credential in its causal ingress node; every syncing replica verifies
the finalized receipt which commits that complete node before materializing
it. Raft roots encode that same
`ReceiptVerificationRequestV2` beside `AdmitIngress` in the committed entry;
every replica hydrates it before IC-5 and leaves its applied cursor unchanged
if hydration fails. Once admission commits, the guest-owned ingress row is the
durable authorization anchor. Later Apply and resume slices authenticate the
same scoped credential against that row rather than process-local verifier
state, including after snapshot recovery. This ordering is narrowly scoped to
direct authority ingress; it does not make arbitrary receipt-bearing transport
consensus-authoritative. Actor-local and mixed policies still require the
separate bound-handle authority path.

Authority redirects never trust the 16-bit routing prefix as identity. The
target retains the authority's exact Raft replication ID, requires the leader
hint to name a live member of that group, resolves that slot through the
canonical node roster, and sends to the row's complete PeerId. The resulting
receipt must itself declare Raft consistency. Assertion reply extraction is
selected by a host-private marker carried only on this local protocol and its
voter-authenticated redirect; an application method merely named
`authorize_role` retains its ordinary declared reply.
Authority decisions and invite redemptions use a no-auto-redirect network
send: every leadership change is surfaced to the caller and reauthenticated
against a fresh exact-group status plus the complete roster PeerId. The
generic prefix-map redirect helper is never on either authorization path.

The current legacy `vosx space publish` path does not activate this v2 Install
entry. Production v2 installation must resolve a signature-verified `.vos`
package, derive the exact `ActorGenesisV2` (including its canonical role-policy
artifact) from those package bytes, and authorize that exact genesis. Passing
an independently constructed genesis directly to guest Install is only a
conformance seam.

The reusable local transport remains a conformance orchestrator. `VosNode`
connects ordinary Local, Raft, and CRDT calls plus same-service CRDT
anti-entropy to authenticated node envelopes, but
automatic service discovery remains staged: external actor routes must come
from a trusted registry or consensus directory, never from a received
envelope. Durable CRDT cross-root calls therefore remain a conformance path
until receipt finality and logical time come from their consensus domains.
Raft delivery and reply
transport instead quorum-order their exact verifier sidecars as described
below.
Acknowledging a publication containing several
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
also applies to CRDT workflows: the scheduler selects the checkpoint node's
causal branch rather than the service's later merged heads, the resumed slice
records an explicit workflow-CRDT outbox consumption, and post-await
operations receive a fresh change/dispatch identity. The suspended heap
continues against the materialization it originally observed; concurrent
branches merge only after that resumed change commits.
Independently scheduled retries remain as distinct physical DAG nodes, but a
deterministic winner represents each logical workflow step during
materialization. A descendant refined before synchronization may physically
name a discarded retry node and its continuation blob; those identities are
treated as aliases of the selected step, so later checkpoints do not lose
their causal predecessor. Every reply-consuming node separately retains the
finalized reply omitted from the normalized workflow checkpoint. Sync can
therefore rebuild and canonicalize the permanent reply-admission and dedup
rows for every historical step, not only the latest visible checkpoint.

A durable timeout follows the same boundary without fabricating a reply. Guest
Accumulate verifies the exact outbox row, workflow checkpoint, pending actor,
await ordinal and deadline before atomically removing the outbox and storing a
receipt-bound `AccumulatedTimeoutV2`. Linear mode advances the revision; CRDT
mode emits a workflow-only expiration node whose ID and receipt bind the exact
caller actor and causal frontier. A CRDT timeout resume selects that expiration
node as its base rather than the earlier checkpoint which still contained the
outbox. Refine restores the captured kernel and
injects a typed `CallError::Timeout` at the original call boundary. The resumed
slice consumes that outcome independently of whether it completes, yields, or
immediately checkpoints at a later await.
The inline reply envelope is bounded by `CHECKPOINT_TOKEN_CAPACITY`; larger
application results must use a content-addressed blob reference once the
transport API exposes that result form. The optional rebound work envelope in
that token is heap-backed, so exact resume does not combine its complete wire
shape with the fixed 4 KiB protocol buffer on the compact actor stack. A
resumed CRDT slice may complete,
checkpoint at another await, or explicitly yield. In every case it records
consumption of the admitted reply independently of the outgoing checkpoint
shape, and binds any replacement continuation to the selected causal branch.
The actor-side resume branch rebinds and resets the restored CRDT operation
allocator, so post-await operations cannot reuse the pre-await change
namespace.

Before that production cutover, the Install authorization capability must be
backed by consensus-authoritative deployment state rather than the local
conformance allowlist. That authority must bind the executing JAM service
account and its current code identity to the exact signature-verified package
and derived genesis, not trust the genesis's self-declared identity.
`ROLE_CREDENTIAL_VERIFY` must use the consensus-authoritative role issuer
rather than its local conformance allowlist. Installed `PROGRAM_LOOKUP`
availability is already part of the recoverable service image: Install and
Upgrade order the exact content-addressed program/genesis bytes and stage them
atomically with IC-5, while snapshots carry the resulting catalog.
`RECEIPT_VERIFY` must likewise use consensus-authoritative receipt finality
rather than its local conformance allowlist for general delivery and reply
paths. The automatic CRDT driver currently derives that verifier decision only
after authenticating and sync-floor-authorizing an enrolled node's complete
Noise identity; deployments which do not trust every authorized replica must
carry an independently verifiable finality certificate instead. Direct
role-authorized Raft ingress
already quorum-orders its exact authority verifier input beside admission and
persists the accepted ingress in guest state. Every delivery, deadline, and
expiration observation must come from the JAM slot. `PROOF_VERIFY`
must use the workspace-pinned verifier and execution-semantics identity rather
than the local proof allowlist. Its proof backend must consume or reproduce
the canonical Refine trace committed by the proof request before attested
execution becomes a production path.
Replicated service identity binds the exact Refine and Accumulate gas schedule.
`OutOfGas` is therefore a deterministic cross-replica result only for replicas
with that declared schedule; a mismatched host stops before advancing its
applied cursor rather than recording a local no-op.
CRDT routing retains the Local/Raft path's rule of recovering and retrying
guest publication, delivery and reply-admission rows rather than maintaining a
second native message ledger. Production use still requires the consensus
finality and time bindings above. A
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

## Owned child creation

`Context::spawn::<R>(name, &initial_state)` is the only application-facing
operation that creates an owned child. In this v2 slice it creates a
same-package child: the typed initial state and reference must name the
calling actor type, while guest Accumulate derives the child's program,
deployment, producer and signed method policies from the authenticated parent
descriptor. Actor source cannot choose or substitute any of those identities.
The child `ActorId` is deterministically derived from the parent identity and
UTF-8 name.

Refine buffers the request and content-addresses the initial state. Accumulate
then installs the child descriptor, method-policy rows, state row and sorted
actor-directory membership in the same atomic transaction as the enclosing
linear slice. Missing state, a duplicate parent-scoped name, an identity
collision or the four-actor JAR ceiling rejects the complete transition. An
exact retry resolves through the original input-deduplication receipt even
though the accepted transition changed the directory.

The returned handle identifies the future child but cannot execute it in the
creating slice. Only a fresh Refine after the spawn commit can install its VM
and CALLABLE. A continuation captured before the commit keeps its exact frozen
program layout: the new directory member is authenticated work input on
resume, but is not retrofitted into that older kernel. CRDT tree-membership
operations and cross-package child creation remain staged and fail closed.

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
handler at PC 0. One continuation reference locks every actor in the captured
nested stack; guest Accumulate rejects a partial lock or unlock. Suspended
actors are non-reentrant, including children whose caller remains suspended,
and later messages remain queued.

Raft orders canonical `AccumulateRequestV2` bytes together with a canonical
availability sidecar and the consensus-observed JAM slot for a time-dependent
`ExpireCall`. The slot is part of the committed entry, so leader execution,
follower catch-up, restart, and failover inject the identical IC-5 ambient
input; a slotless replicated expiration is rejected before proposal. An
`Apply` request carries the `AccumulationEnvelopeV2::provided_blobs` needed by
that transition. `Install` and `UpgradeActor` additionally carry exactly the
program and genesis-blob bytes named by their content identities. Those bytes
are inserted only into the request's cloned Accumulate transaction: rejection
leaves no availability trace, acceptance makes them part of the durable
service image, and a follower with an empty node-local cache can replay the log
tail. Snapshot catch-up carries the same installed program/blob catalog.
Replicated direct role-authorized ingress must carry exactly one canonical
authority receipt-verification request; an empty sidecar is rejected even if the
leader's process-local verifier already knows that receipt. No other request
shape accepts a verification sidecar. The replicated payload uses the
clean-break `VRQ4` wire; retired
payloads fail loud rather than being interpreted without their availability or
receipt-verification sidecars. Raft
does not replicate an `EffectLog` or a leader-produced post-state image.
`ReplicatedJamServiceV2` waits for the
request's log position to commit, then applies it through the physical
service-PVM Accumulate entry before advancing the replica's applied cursor.
For a proved Apply, durable proof-CAS hydration is a retryable local
precondition: failure returns before guest execution and leaves that cursor on
the committed entry for exact replay.
Followers and a newly elected leader use the same catch-up path; replaying
after a cursor-write failure is safe because guest deduplication sees the
already committed workflow input.

`RaftAccumulateLogV2` is the redb/`vos-raft` implementation of that boundary.
In multi-replica mode it accepts writes only from the elected leader, waits for
the worker's quorum-commit notification, then re-reads and verifies the exact
committed request and time-provenance bytes. Its `last_applied` cursor advances separately and only
after the local service image commits. Each cursor advance records the canonical
`LocalJamStoreSnapshotV2` image for that exact log index while retaining a
bounded recent window. Automatic compaction cannot cross this durable
application cursor and freezes the matching image—not a newer mutable state
row—into a `CommittedServiceSnapshotV2`. A lagging follower receives that
envelope through Raft `InstallSnapshot`, checks that its bound index matches the
installed snapshot metadata, and durably hydrates the snapshot's separate
content-addressed proof-artifact bundle for pending publications before
replacing its physical service image. Completed reply admissions are permanent
deduplication markers but do not retain proof bytes: their retry path resolves
before proof lookup. Only after hydration does the follower advance
`last_applied` and replay any surviving log tail. A proof-CAS or service-image
failure leaves the old image and cursor eligible for retry.

Every await is a durable slice boundary. Effects before it may commit even if a
later slice fails, so multi-await handlers have saga semantics. Same-tree calls
may execute inline. Cross-root calls always use durable outbox/inbox rows and a
`CallId` derived from `(InvocationId, await ordinal)`. A compact copy of the
authenticated parent call is bound into the workflow identity and every exact
continuation. It retains caller/callee, deadline and parent linkage after the
step-0 inbox row is consumed, so later awaits preserve cycle and inherited
deadline checks without resurrecting that row. Await ordinals live in the
captured actor machine, are shared by inline descendants, and therefore advance
across successive restarts. Accumulate accepts a durable outbox row only beside
the exact replacement checkpoint that names its `CallId` and host-derived
sending actor. A nested sender may form the first causal edge below the root's
authenticated inbound call; every older edge retains the ordinary
parent-recipient equals child-sender rule.

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

CRDT actor upgrades currently fail closed with `InvalidConsistency`. Program
metadata needs an explicit causal operation and complete-ancestry activation;
the runtime does not pretend that a linear descriptor rewrite is a CRDT merge.

## Packages and identity

`.vos` v2 packages bind the service ABI, execution-semantics ID, canonical
actor PVM and its `ProgramId`, interfaces, role policies and schemas. Optional
ELF/source-map data is diagnostic only. `DeploymentId` excludes diagnostics
and signatures but includes the authoritative manifest and PVM bytes.
Registries store these bytes and never retranspile an ELF. JIT products,
proving keys and traces are caches keyed by `ProgramId`.

`space up --service-pvm <exact-vos-service.pvm>` recognizes signed `.vos`
catalog artifacts and opens each ordinary Local or Raft deployment as one
durable root-tree service. Raft rows resolve membership only after their exact
package and root configuration pass validation, then order genesis and every
mutation as canonical IC-5 request bytes. It verifies the package signature,
capability layout, and protocol-pinned service `ProgramId`; it never extracts
the actor PVM into the
legacy runtime or retranspiles an ELF. Missing or invalid service artifacts
skip only the affected row, so an installed package cannot prevent the rest of
a space from starting. Package classification precedes every legacy Raft seed,
probe, or join action, so a refused v2 row cannot change quorum membership.
The daemon derives the guest root-service identity and image path from the
registry installation incarnation `(SpaceId, instance name, replication_id)`.
Restarting the same installation reopens its exact image; uninstalling and
reinstalling under the required fresh replication id creates a fresh actor and
deduplication domain. Its Raft database is keyed by that root-service identity
too, so a reinstall cannot inherit terms, logs, cursors, or voters from the
retired incarnation. On the next boot, images, proof side-CAS directories, and
Raft databases whose incarnation is no longer present move to recoverable
trash.

A joining v2 Raft root starts its worker, registers the inbound Raft handler,
opens its durable service, and validates its still-unpublished route before it
asks the leader for voter promotion. Promotion is node-owned background state,
not work performed by the router or reconciliation callback. A definite
pre-request refusal returns the row to deferred reconciliation; once a request
has an ambiguous outcome, the prepared worker stays available and retries
idempotently until final non-joint membership is visible. Shutdown cancels and
joins that worker, and the route becomes public only after successful final
membership. Calls that reach a follower receive a transport-level leader
redirect which both the raw node API and generated typed actor handles follow.
Remote peers reconnect to the leader directly and therefore retain their
Noise-authenticated member identity. For local `System` and actor calls, the
follower carries the exact typed origin in a node-internal delegation envelope;
the leader accepts that envelope only from a current voter of the target's
exact replication group. This is the same non-Byzantine trust boundary as Raft
state replication, and keeps `Context::origin()` and exact-retry identity stable
across leader changes. Typed forwarding requests the full invoke envelope, so
`Forbidden`, `NotFound`, panic and out-of-gas statuses remain identical to a
direct leader call.

V2 CRDT roots admit anti-entropy only from a full Noise identity present in the
canonical node roster and authorized by the root's `Public`/`Member`/`Private`
sync floor. Peer-supplied chunks never carry their own allowlist; the receiving
root derives an exact ordered verifier sidecar after authentication and guest
Accumulate independently checks each causal delta.
For Local, Raft, and CRDT roots, ordinary public cross-root calls are emitted as
guest-owned publications, routed over canonical node envelopes, admitted
through destination IC-5, and resumed from the caller's exact saved machine
after the committed reply returns. A Raft `Deliver` or reply-consuming `Apply`
carries exactly one canonical `ReceiptVerificationRequestV2` in its log entry. Missing,
extra, or mismatched verifier input is rejected before proposal and again on
follower replay; non-receipt-bearing requests require the sidecar to be empty.
The node periodically redrives pending publications, inboxes, and ingresses
after restart; for Raft roots this redrive begins only after a current-term
leader barrier, and every hop independently resolves the destination group's
leader. Slow or partitioned discovery is bounded off-router and coalesced per
root, so it cannot stall unrelated services or grow one lookup per 250 ms
retry. Permanent guest deduplication makes a lost acknowledgement safe.
Direct space-role-only calls to Local, Raft, and CRDT roots use the installed
canonical authority path described above. Attested calls, actor-local or
mixed-role calls, and role-bearing durable messages remain unavailable on this
node route; they never fall back to an unproved, caller-declared role or
synthetic-System invocation. Legacy ELF/PVM rows
continue on the old host during this staged cutover.

Registry-level `space upgrade` is rejected whenever either side is a signed v2
package. A catalog pointer rewrite cannot update guest-owned descriptors or
prove that a suspended actor is idle; v2 upgrades must enter through the
guest-owned `UpgradeActor` protocol described above.

The service identity retains the root package `DeploymentId` selected when
the root tree is installed; it is the stable service/routing identity. Every
actor descriptor separately retains the exact current package `DeploymentId`.
Refine work, continuations, transitions, external dependency bindings, and
attestation statements bind that actor deployment together with its
`ProgramId`. Guest-owned upgrades change the actor package identity without
rewriting the service identity, including policy/schema-only upgrades whose
canonical PVM bytes are unchanged.

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

CRDT direct ingress is itself a guest-authenticated workflow DAG node. Its
exact causal base, stable invocation identity, authorization input, and
accumulation receipt replicate before actor Refine runs; synchronized replicas
rematerialize the same queued/consumed ingress record through physical IC-5.
Store schema 27, continuation snapshot version 6, and platform ABI version 6
are therefore a clean
break from earlier experimental v2 images. They add exact actor-package
identity to descriptors, work, checkpoints, transitions, upgrades, and
cross-root proof bindings, bind durable messages and retained causal context to
their exact source/destination services, retain the complete dormant
actor-program layout in each continuation, retain the immutable role-authority
binding, bind the executing Refine and Accumulate gas limits into service
identity, and support guest-owned atomic same-package child creation. Actor and
service guests must be rebuilt together; an earlier-ABI artifact is rejected
rather than interpreted as this wire.
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
