# Agent saga: current status

This is the single live plan. The approved first-customer release scope below
supersedes the previous all-capabilities release mandate. A review checkpoint
is not a release. Full-saga ambitions remain a deferred backlog, not permission
to expand these batches.

## Customer release scope and implementation order

Supported target: Linux, a fixed authenticated three-node deployment with
replicated system Authority/Catalog and ordinary Shared Agents, plus production
Local Agents. One hot Shared Clerk ledger provides accounts, transfers, reads,
authorization and idempotent retries. Preserve its existing kernel, signatures
and committed roots; do not create a second ledger implementation. Customer
backend credentials use normal VOS roles, without foreclosing later direct
self-custodial clients. Both Local and Shared require durable recovery and
backup. Human-friendly create/install/invoke commands must preserve exact
protocol requests and resumability.

Three release-work batches remain. The bounded-state vertical slice is a
separate intermediate review checkpoint on `saga/agents`, not completion of
batch 1; subsequent integration stays on `wip/ch08-runtime-directory`:

1. **Authenticated storage + customer workflow (in progress).** First qualify
   the bounded external-state vertical slice below, then port Clerk's
   ledger core to the Agent interface; establish common authenticated static
   three-node genesis (not three singleton spaces); expose ordinary Shared
   Create/Install through durable reservation/publication/application/finalize/
   retirement; add schema-aware CLI invocation. Qualify with actual release
   binaries, not fixture-only issuer handoffs. Check Clerk growth feasibility
   before investing in the rest of this integration.
2. **Measured performance.** Attribute credential/Authority, queue, VM, quorum,
   persistence and retirement costs using the real backend credential pattern.
   Fix measured redundant work first. At most two tuning passes; an ABI/state
   redesign beyond the approved storage workstream requires an explicit scope
   decision. Do not manufacture throughput
   by multiplying credentials, weakening checks or merely enlarging queues.
   Replicas do not parallelize one ordered ledger's writes.
3. **Recoverability and release.** Maintenance-window backup drains admissions
   and captures consistent Local/Shared and lifecycle/retry state. Use validated
   opaque Local exports and authenticated Shared exports, not private runtime
   decoding or raw directory-copy guarantees. Restore with matching node
   identities and binary/artifact version; keys stay separate and replaced
   destinations are preserved. Qualify leader loss, catch-up, partitions,
   interrupted lifecycle, whole restart and restore using release binaries.
   Finish artifact reproduction, full outer-PVM mixed recovery, workspace/CLI
   regressions, formatting and targeted lint before the final reviewed merge.
   Customer deployment/data cutover still needs operator approval.

Immediate integration seam: the experimental external-state package, physical
Create, sealed Local genesis, file journal, pinned Invoke/ACK owner, and
authenticated actor inspection exist. The owner retains its locked slot,
catalog-bound executor and validated materialization across mutations; staged
successors cannot become serving cursors before publication. Targeted actor
lookup uses one exclusive-cursor page, but still transports full runtime
metadata. Startup and request costs are unmeasured.

The internal external Local Create coordinator now uses the existing signed
CMI4/CIS2 lifecycle: retained package and authorization anchor, exact-intent
file slot, physical checkpoint publication, issuer ACK, Authority actor
finalization and retirement. Finalized exact retry reopens and checks the
original authenticated generation even after the receipt window. Its denial
branch shares the image path's durable signed retirement and verifies physical
absence before releasing pending admission. `just test-agent-state-local-create`
builds opt-in Authority and standard-runtime guests and exercises the complete
internal Create/retry flow, including a failure after actor finality but before
local retirement. The released bundled Authority correctly rejects
the experimental ABI; its artifact is not replaced or implicitly upgraded.
The coordinator now accepts an operator-selected, filesystem-descriptor-pinned
external directory owner rather than a request-controlled slot-opening
callback; replacing that directory pathname cannot redirect a retained owner.
Retries after saved authorization or retirement reopen an existing stable lock
only; a missing lock fails without minting a replacement.
The pinned directory can now discover bounded lock-only and exposed slot
candidates, rejecting malformed names, orphan generations and limit overflow.
The startup recovery model matches those candidates against independently
verified lifecycle stores. Discovery is not authority: controller integration
must still replay every matched generation before route attachment.
The external owner can build route identities from its authenticated read-only
directory, reusing the same bounded paging and identity checks as image Local.
It can also reconstruct an installed Actor's exact signed package, program,
schema, policy and constructor layout from pinned catalog blobs; missing or
altered artifacts fail closed. No external route worker or public attachment
exists yet. A successful external journal publication now returns its exact
guest SDK invocation outcome only after the head commit succeeds. An
`AlreadyCommitted` retry still lacks an authenticated response handoff,
including after restart; do not attach a route that can execute without it.

No released startup, lifecycle queue or route adapter selects this owner yet;
the caller must choose Space/Node storage roots independently and attach a
route only after authenticated finalization. Unretired Create now checks its
saved authorization anchor against the pinned system journal before physical
recovery; startup must restore its pending/retirement admission first. Keep
the image Local path active until external selection, file-backed restart and
near-3-MiB ACK recovery qualify. The external replay adapter covers signed
Create, Install, Invoke and ACK without decoding private runtime state.
The current released-binary path is `vosx` clean startup -> image-based
`LocalAgentHost` -> `LocalLifecycleController` -> Local route backend. The
older `host::LocalGenesisIntent` file opener accepts r19 only. Next, select and
recover the external owner through the existing lifecycle controller, then
route only after authenticated Create publication. Shared common finality and
Clerk follow within batch 1. Candidate signed packages are not live admission;
the large ACK's 5-billion-gas success is not a release-latency guarantee.

External Local cutover TODOs, in order: (1) pass the Space/Node-pinned external
directory into the lifecycle controller and select format per Agent,
then recover mixed image/external intents under one startup admission before
publishing either kind of route; (2) attach an external per-Agent route owner
with Install, Invoke, Resume and ACK using the existing signed journal
semantics, not an image-host fallback; (3) qualify file-backed restart,
near-ceiling ACK, candidate artifact identities and released-binary behavior.
`LocalLifecycleController::with_recovery` currently assumes every discovered
Agent is present in `LocalAgentHost`; merely accepting an external Create
submission would strand it on restart. Keep that ingress disabled until these
gates pass.

Provisional acceptance envelope (customer confirmation required before sign-off):

- Three separate 8-vCPU/16-GiB/SSD nodes, inter-node RTT at most 5 ms.
- 300 continuously active clients, 80% reads / 20% signed mutations against one
  Shared Clerk, with unrelated Local/Shared activity. End-to-end p95 at most
  1 second and p99 at most 2 seconds, including queues/retries.
- 1,000 accounts and 100,000 retained transfers, growing during a 30-minute load
  run and 24-hour lower-rate retention soak. Measure write-only bursts separately.
- No acknowledged loss, duplicate effects, unauthorized access or false
  completion. Stable retry identities across restart/failover; minority cannot
  commit. Provisional failover recovery at most 30 seconds.
- Backup preserves roots, Local state, identities and retry semantics. Resource
  use remains bounded under overload (memory, descriptors, queues and results).

No throughput or release ETA is established. These numbers are targets, not
measurements. Existing broad Clippy debt is recorded below, not hidden by
suppression or unrelated cleanup.

### Early capacity gate: storage workstream approved

The proposed retained dataset cannot fit the current lane format:

- `ActorLaneImage::encoded_parts_len` in `vos/src/agent/actor_storage.rs`
  rejects more than 16,384 rows, independently of its 4-MiB image limit.
- Clerk retains each accepted transfer in `LedgerView::put_transfer`.
  `CommittedMap` stores one value per key, one branch per branching point
  (N - 1), and one root: 100,000 transfers alone require 200,000 rows.
  Accounts, external IDs, root anchors and other state are additional.
- A codec regression fills all 16,384 slots with tiny records below the byte
  limit, verifies growth fails atomically, and verifies existing rows remain
  writable. This is a format-capacity check, not a Clerk/PVM/load benchmark.

The user approved bounded external-state work, retaining the original customer
dataset target. Do not simply raise limits, discard history/idempotency data or
shard the ledger. Keep the reviewed branch and released ABI/artifacts unchanged
until the new storage path qualifies. The current codec remains active meanwhile.

### Storage TODOs and acceptance gates

Design: small authenticated lane roots, immutable content-addressed tree blocks,
bounded runtime-controlled fetches and incremental writes. Keep actor storage
APIs, Clerk kernel/signatures/roots and per-Agent ordering. A content hash verifies
bytes, not membership in an authoritative state: traversal must start at the
correct pinned root. Missing blocks mean unavailable state, never absent keys.

- [x] Add an experimental portable block-authentication/read-budget primitive,
  isolated behind SDK feature `experimental-state-blocks` (also unit-tested in
  the SDK test build). It does not change r19 or activate a new production path.
- [x] Prototype canonical fixed-key compressed radix nodes, authenticated path
  lookup/absence and staged immutable insert/replace/delete. Validate path
  placement, strict codec shape, read/write budgets and deterministic roots.
  Old roots remain readable; only changed paths emit new blocks. This is an
  experimental library primitive, not admitted persistent runtime storage.
- [x] Add canonical chunked values: inline through 65,495 bytes, otherwise
  authenticated 64-KiB chunks under a bounded descriptor (candidate per-value
  ceiling 1 MiB). Test boundaries, missing/corrupt chunks, no-op replacement,
  old-root retention, malformed descriptors and read/write budget exhaustion.
  This ceiling does not replace signed actor row limits.
- [x] Add a strict revision-bound root descriptor and exact commitment check.
  It binds space/Agent/storage generation/lane, runtime-binding commitment,
  revision commitment and root hash/length (including empty roots). It is NOT
  finality evidence; expected values must come from an independent trusted head.
- [x] Add actor-row key/value adapter with full actor/incarnation/key records.
  Replacements/deletes validate the existing identity in one tree traversal;
  injected identity collisions fail closed. 64-KiB keys and values use chunks.
- [x] Derive expected contexts from journal metadata: cycle-free Create intent
  plus authority sequence define storage generation, with node isolation for
  Local state. Initial cursors normalize to the pre-admission Create context;
  subsequent root-producing revisions bind final genesis and their lane cursor.
  Later projections may retain that exact root without changing its provenance.
  Runtime upgrades change the runtime-binding commitment, not storage scope.
  Final genesis admission can commit post-Create state: never derive initial
  block scope/root identity from that post-state-dependent admission ID.
  Control metadata remains outside this actor-state contract.
- [ ] Wire those descriptors to authoritative journal/finality heads and enforce
  generation retirement. Context derivation validates shape/scope, not signatures,
  freshness, cursor existence or finality; callers must use independently
  authenticated replay/checkpoint metadata, not candidate-supplied fields.
- [ ] Integrate row reads/deltas without materializing all rows. Keep signed actor
  namespace/lane permissions and exact incarnation checks. Account for total
  durable rows/bytes incrementally with authenticated counters.
  Read-side prerequisite: the existing inner actor runner now accepts a common
  runtime-owned row view. The legacy image reader keeps borrowed values; the
  experimental external reader uses authenticated tree paths and owned bounded
  row values. Both use the same namespace/method/delta permission checks and
  unchanged `STORAGE_R`/row-export ABI. External reads charge a shared block
  budget; missing lane declarations, missing/corrupt blocks and budget exhaustion
  return unavailable execution, never key absence or a durable actor rejection.
  Root selection, schema/installation authentication and caller admission remain
  the enclosing runtime's responsibility; constructing this reader grants none
  of them. Production dispatch still selects the legacy reader.
  Candidate-write prerequisite: canonical multi-row batches now use a private
  copy-on-write overlay over the same provider, with one shared read/write budget.
  Intermediate emissions consume quota even if later superseded; finishing walks
  only candidate blocks and prunes unreachable intermediate nodes before the
  existing `StateChange` reachability check. Failure returns no candidate and
  never writes the backing provider or changes the reader's current root.
  `prepare_delta` admits namespaces/lanes first and checks final logical row
  count/key+value bytes against a lane-wide counter read from the selected root
  and explicit package-shaped limits. Counter and rows share one candidate root;
  only an empty tree has implicit zero usage. Nonempty unaccounted trees fail
  closed, with no silent migration. At-capacity
  insert/delete exchanges do not fail merely because insertion sorts first.
  The counter covers all actor/incarnation namespaces in that lane. It excludes
  inline/runtime metadata, immutable history and physical
  storage overhead; those still need their own accounting and reclamation bounds.
  The existing signed `RuntimeResourceLimits.max_runtime_state_bytes` bounds
  the encoded runtime image, not separately retained external rows. Experimental
  runtime manifests now require an explicit signed `ExternalStateResourceLimits`
  extension: row count and logical key/value bytes per data lane, aggregated over
  actors/incarnations. Independent lane allowances avoid replica-local usage
  changing admission of common Linear/Merge writes. There is no implicit default;
  the test issuer's one-million-row/1-GiB limits are fixture policy only.
  Manifest tag 2 includes both ceilings in signing bytes and deployment identity;
  zero/missing limits are refused. Tag 1's released r19 byte/signature layout is
  unchanged and rejects the extension. Feature-disabled decoders refuse tag 2.
  Earlier limit-free experimental packages are deliberately not admitted; this
  adds no migration path. The production runtime must still select authenticated
  roots, bind the passed limits to its admitted package/policy, prohibit raw
  unaccounted writes into accounted lanes, and define operator admission caps.
  Quota qualification: SDK package tests passed 18 with the feature and 18
  without it, including legacy-layout equality and disabled-tag refusal. Host
  admission's real Ed25519 test refuses either ceiling changed without re-signing;
  a valid re-sign changes the admitted package/deployment identity. The full
  rebuilt-guest prototype passed (`task-tmp/state-quota-prototype.log`), with the
  newly added feature-off package group also run separately
  (`task-tmp/state-quota-package-disabled.log`). `cargo check -p vosx --tests`
  passed offline/locked (`task-tmp/state-quota-vosx-check.log`, 5 CLI-test warnings).
  Released runtime constructors explicitly select no extension; bundled artifact
  bytes were not regenerated. This does not qualify counter enforcement or storage capacity.
  Still required: runtime-selected root/installation binding, atomic external
  row deltas with production inline state and retained outcomes, and
  continuation-safe persistence of block-work budgets.
  Do not activate the reader as a partial write backend or reset quotas on resume.
  Verification: 13 actor-storage tests and 22 execution tests passed (7 existing
  artifact-dependent execution tests ignored); feature-off groups passed 11 and
  21 respectively (the same 7 ignored). The new assembler inner actor reads a
  row from a 1,024-row authenticated tree through unchanged `STORAGE_R`, and
  missing/corrupt blocks or exhausted budgets fail without a successful reply.
  Reader tests verify permission denial before IO, actor/incarnation isolation,
  absent keys versus absent lane roots, and two row lookups using fewer than 64
  block reads. SDK batch tests additionally cover late failure with consumed
  budgets, duplicate-key refusal before IO, at-capacity exchanges, maximum-size
  chunked rows, no-op emission and final candidate reachability. The runtime
  adapter regression rejects quota overflow without changing provider bytes or
  the current view, then verifies the successful candidate against its base.
  These original checks are native candidate and inner-reader tests; production
  lifecycle and real Clerk execution remain unqualified.
  All 67 replay tests also passed. Full rebuilt-guest prototype evidence:
  `task-tmp/state-row-batch-prototype.log`.
  Native accounting qualification: `task-tmp/state-accounted-prototype.log`
  passed the complete rebuilt-guest recipe: SDK 240 passed/1 ignored, feature-off
  contract/package 6/18, admission 7, actor-storage 13, execution 22/7 ignored,
  replay 67, physical PVM 10, journal-store 105, ABI-pair checks on/off, and
  feature-off actor-storage/execution 11/21 (7 execution tests ignored).
  The 11 SDK row tests include cross-actor lane quota, immutable predecessor
  roots, zero counter after deleting all rows, no-op with zero write budget,
  late counter-write failure, missing accounting, malformed counters, unavailable
  blocks, exhausted reads and limits below existing usage. Host candidate checks
  verify final reachability with the counter included.
  Physical accounting follow-up: the test guest's execution protocol now uses
  accounted Create, two-row Invoke and ACK batches. Its legacy raw tree probe
  remains separate. The quota now comes from the exact admitted package through
  explicit execution framing rather than a compiled-in guest constant. Recovery fixtures check
  exact persisted lane counters and both rows after restart/checkpoint/collection,
  including untouched-lane usage and existing interruption/retry coverage.
  Qualification: the complete rebuilt-guest recipe passed with unchanged group
  counts above (`task-tmp/state-accounted-physical-final.log`), including 67 replay,
  10 physical PVM and 105 journal-store tests and the feature-disabled checks.
  Initial run `task-tmp/state-accounted-physical.log` exposed one stale unaccounted
  file-store seed, which the guest correctly refused. That seed and its independent
  expected transition now use accounted batches; reopening additionally checks
  the three-row usage and mirror value while retaining the original chunked row
  at the predecessor root. Formatting and diff checks passed. No released artifact
  bytes or production dispatch changed; `saga/agents` remains at `7bae9269`.
  Next scoped step: bind the production runtime's root/installation/schema and
  inline state/results before connecting the external actor execution path.
  Standard-runtime resolver follow-up: `resolve_clean_external_storage_reader`
  now reuses the installed schema/method/namespace checks, binds work to the
  current space/Agent/runtime deployment, and rejects trees for another space
  or Agent before provider IO. Its returned lifetime borrows the runtime to
  prevent lifecycle mutation while the access scope is live. It refuses existing
  image rows for that actor/incarnation instead of silently hiding them during
  an unsupported backend switch. This still requires independently selected
  authoritative roots and caller-policy admission; a resolver is not an
  authorization token or a new dispatch path. Native fixture coverage includes
  stale identities, malformed schema, wrong method and scope, namespace denial,
  successful authenticated lookup, and mixed-backend refusal.
  Runtime validation passed: 111 wire tests/5 ignored with the feature and
  110/5 without it. The full expanded prototype recipe passed
  (`task-tmp/state-runtime-prototype.log`), including SDK 241/1 ignored, replay 67,
  physical PVM 10, journal-store 105 and the existing compatibility groups.
  Both wire groups are now in the recipe. A no-default-features library check
  exposed a missing `alloc::boxed::Box` import in experimental replay; the
  explicit import fixes it. The rerun passed (279 warnings,
  `task-tmp/state-runtime-nostd-final.log`), and that check is now in the recipe
  too; it ran separately because the recipe was already in flight when added.
  This is native no-default-features compilation, not a cross-compiled standard
  runtime qualification. Formatting and diff checks passed; the reviewer branch
  is still unchanged at `7bae9269`.
  Remaining integration: retain the existing bounded runtime metadata/results
  while publishing their successor atomically with external row roots; do not
  put row data back into the legacy whole-image format or expose partial writes.
  Metadata candidate implementation: the experimental `state_metadata` helper
  stores an opaque lane component under domain-separated tree keys (strict header
  plus bounded 512-KiB parts, at most the existing 4-MiB runtime-state ceiling).
  Accounted row batches can stage it in the same private tree overlay as rows
  and counters, pruning superseded blocks into one final candidate. Only an
  empty tree has uninitialized metadata; existing metadata-free trees are not
  silently upgraded. Metadata bytes are separate from logical row quotas.
  The runtime must enforce its aggregate signed metadata/inline/result limit;
  the existing candidate-envelope limit still applies, including tree overhead,
  so a raw maximum-size metadata component is not a promise it fits publication.
  `prepare_clean_external_row_batch` matches base metadata against the current
  standard runtime, runs the existing authorization/result commit in a clone,
  validates signed state resources and rejects changes to other lanes/control,
  then returns a combined metadata/row candidate without mutating the source.
  It remains an unselected preparation path, not a journal publication API.
  Validation passed: SDK 244/1 ignored, no-default-features library compilation,
  runtime wire 112/5 ignored, replay 67, physical PVM 10, journal-store 105 and
  all existing feature-on/off groups (`task-tmp/state-metadata-prototype.log`).
  SDK metadata boundary, malformed/missing-data, no-op, shrinking and late-failure
  tests are also recorded in `task-tmp/state-metadata-sdk.log`. The final focused
  runtime rerun (`task-tmp/state-metadata-binding.log`, 2 passed) adds refusal of
  a valid tree whose opaque metadata does not match the current runtime before
  commit logic runs. The positive test reconstructs the standard runtime and
  recovers its exact result from the metadata in the same verified candidate as
  the row/counter update. These are native preparation tests; the existing physical
  probe does not yet exercise metadata or the standard-runtime candidate path.
  Formatting/diff checks passed at this earlier prototype stage.
  Remaining before activation: physical standard-runtime metadata load/execute/
  publish/recovery, independently admitted read roots for every readable lane,
  metadata-only query/ACK/management transitions, and continuation-safe aggregate
  work budgets. Preserve the existing bounded
  control/directory model; do not claim metadata cost tracks individual rows.
  Candidate storage/work-budget failures currently return unavailable execution,
  not a retained rejection; distinguish quota saturation from retryable
  availability/budget exhaustion before exposing production error semantics.
  Standard-guest bootstrap follow-up: `services/agent-runtime` now has an opt-in
  `experimental-state-blocks` build accepting XSW2, initially Create and read-only
  management inspection (Install follow-up below). It
  executes the existing standard Create implementation (including signed
  Authority validation), checks the aggregate signed state limit, then initializes
  each declared lane's metadata and zero row accounting under one candidate root.
  SDK initialization requires an empty tree and no artificial actor identity.
  Undeclared lanes can only omit canonical empty metadata; unsupported operations
  trap instead of falling back to whole-image row execution. The default guest
  entry and committed released artifacts remain unchanged.
  The new guest cross-compiled with the pinned toolchain and ran through the
  physical admitted Create adapter (`task-tmp/state-standard-create-physical.log`).
  Its metadata reconstructs the native standard Create state, and tampering with
  the fixture issuer's real signature is refused. Staging publishes no genesis
  or heads. This is actual standard guest execution but not installed Authority,
  node startup, ordinary Shared lifecycle or deployed release qualification.
  `just build-agent-standard-state-guest` builds a separate candidate directory;
  the full prototype recipe now builds both guests. Full validation passed:
  `task-tmp/state-standard-create-prototype.log`, including SDK 244/1 ignored,
  native no-default-features compilation, wire 112/5 ignored, replay 67,
  physical PVM 11, journal-store 105 and all feature-disabled compatibility
  groups (wire 110/5 ignored). The invalid signature specifically produces a
  guest Panic exit, rather than merely any host-side refusal. Formatting/diff
  checks passed. No production dispatcher or released artifact changed.
  Metadata loading/inspection follow-up: the standard guest traverses each
  declared root, validates lane usage against admitted quotas and reconstructs
  bounded opaque metadata under one aggregate read budget. It validates complete
  runtime identity, declared capabilities and signed metadata size, then reuses
  that one restored runtime for existing InspectActors/InspectResources/
  InspectManagementHistory logic. No second restore or host decode fallback is
  used. Undeclared nonempty components and missing metadata are refused.
  The typed multi-lane inspection adapter verifies package/deployment/limits,
  scopes and request/reply kind; SDK output validation requires unchanged roots
  and state. The caller still owes authoritative, revision-consistent root
  selection and freshness; this is not a new production route or publication
  capability. Inspection still loads whole bounded runtime metadata, not rows,
  and is not a constant-cost directory projection or throughput qualification.
  The rebuilt physical standard guest passed all three inspection types against
  native standard semantics, with actual fetches, zero candidate blocks and no
  heads. Empty backing storage and exhausted read budget fail; altered quota
  input is rejected before execution (`task-tmp/state-standard-inspection-physical.log`).
  Full validation passed: `task-tmp/state-standard-inspection-prototype.log`,
  including SDK 244/1 ignored, wire 112/5 ignored, replay 67, physical PVM 11,
  journal-store 105, native no-default-features and feature-disabled groups.
  Installation follow-up: the experimental standard guest now also accepts
  Install using the restored runtime's existing signature, authority ordering,
  exact-retry and resource checks. Install updates the bounded control/directory
  component only and preserves every lane root and row counter. The guest
  explicitly refuses unexpected lane mutations or embedded image-backed rows;
  there is no implicit legacy-row migration. Constructor execution belongs to
  first invocation and is not implemented by this new entry yet. The typed host
  management adapter admits only Install and the three inspections, checks the
  public reply kind, and still neither decodes metadata nor publishes state.
  The physical regression covers install, reconstruction against native state,
  exact retry, post-install directory inspection and an invalid signature.
  Full validation passed: `task-tmp/state-standard-install-prototype.log`,
  including SDK 244/1 ignored, native no-default-features compilation, wire
  112/5 ignored, replay 67, physical PVM 11, journal-store 105 and all
  feature-disabled compatibility groups. The first focused test exposed a
  fixture reusing Create's logical slot; Install now uses the next slot without
  weakening the production ordering guard. Formatting/diff checks passed.
  No released artifacts changed; `saga/agents` remains clean at `7bae9269`.
  Retirement follow-up: ACK now uses the same restored-runtime retirement
  implementation as r19, without a second runtime restore or host metadata
  interpretation. The external loader and bounded metadata publisher preserve
  actor rows and accounting while staging the result removal and positive
  retirement fact under the owning lane's successor root. Unchanged retries
  retain their original roots and emit no candidate blocks. The typed control
  adapter matches the full public acknowledgement binding to its request.
  SDK coverage includes preserved rows/counters/old roots, no-op updates, write
  exhaustion, over-quota refusal and refusal of unaccounted or empty roots
  (`task-tmp/state-standard-ack-sdk.log`, passed). The physical ACK fixture seeds
  a retained result using native standard semantics: it is not evidence of
  external guest invocation, authenticated genesis or durable restart recovery.
  Physical validation passed (`task-tmp/state-standard-ack-physical-final.log`):
  exact native result, one changed Linear metadata root, unchanged row/counter,
  idempotent retry, invalid-signature refusal, malformed-message frame refusal
  and exhausted-read-budget failure. No heads or genesis are published. Full
  validation passed: `task-tmp/state-standard-ack-prototype.log`, including SDK
  245/1 ignored, native no-default-features compilation, wire 112/5 ignored,
  replay 67, physical PVM 12, journal-store 105 and feature-disabled compatibility
  groups. Formatting/diff checks passed; bundled artifacts and `saga/agents`
  were unchanged at that earlier stage. This was not release qualification.
  Before activation, qualify retirement at maximum admitted metadata occupancy
  against the provisional aggregate read/write and candidate-output budgets;
  this small fixture does not establish that every near-capacity state retires.
  Invocation follow-up: the standard Invoke state
  machine now has a private storage adapter boundary. Both image and external
  adapters reuse the same authorization, installed-schema/constructor admission,
  exact retry, durable failure and result-capacity logic. The external adapter
  resolves touched rows through authenticated trees and prepares row/counter/
  inline/result metadata atomically; publication checks that the final runtime
  metadata exactly matches this candidate before returning any blocks. Its
  metadata loader, execution reads and writes share one operation budget.
  The typed multi-lane adapter checks admitted package/policy and public reply
  identity without decoding standard-runtime metadata. Neither adapter publishes
  journal heads. Production dispatch and bundled artifacts remain unchanged.
  Important incomplete semantics: yielded external executions are refused
  without publishing state until continuation budgets are persisted; Resume is
  unsupported. Merge-capable actors are also refused: the existing image
  Merge frontier hashes embedded rows, so using it for external rows would
  report an incorrect observation. Define external Merge frontier/replay
  semantics before enabling those actors; do not silently reuse the image hash.
  The physical fixture exercises a non-Merge actor's row read/export, retained
  result, exact retry and invalid authorization against native semantics. Its
  installation is a synthetic seed, not a Create/Install/constructor end-to-end
  or durable restart qualification. Physical Create/Install, ACK and Invoke
  tests passed (`task-tmp/state-standard-invoke-physical.log`, 3 passed). A
  subsequent real yielding-actor regression also passed in the full recipe:
  the image backend yields, while external execution returns unavailable with
  byte-identical original state, no row candidate and no continuation. This is
  a fail-closed restriction, not Resume support. Full validation passed:
  `task-tmp/state-standard-invoke-prototype.log`, including SDK 245/1 ignored,
  native no-default-features compilation, wire 112/5 ignored, replay 67,
  physical PVM 14, journal-store 105 and all feature-disabled compatibility
  groups. Formatting/diff checks passed. `saga/agents` remains clean at
  `7bae9269`; no bundled artifacts were replaced.
  Fresh lifecycle/constructor follow-up: the new `agent-state-actor` fixture
  uses the actual actor macros, emitted AAS2 constructor schema and Public
  authorization metadata, a required named seed, Linear inline state and a
  StorageMap. It builds separately with the pinned offline/locked toolchain.
  The physical test starts with guest Create, installs through guest Install,
  obtains the incarnation through guest InspectActors and then invokes the real
  compiled actor. Seed 41 returns 42 then 43; a subsequent LinearizableQuery
  reads 43 from the external row. Exact retries preserve the result/state, and
  each result is acknowledged before the next fresh call. No private native
  runtime state is synthesized to install or initialize this actor.
  Initial physical validation passed (`task-tmp/state-standard-lifecycle-physical.log`).
  The final regression additionally submits a freshly signed invocation with
  substituted constructor data and requires refusal with unchanged state.
  Full validation passed: `task-tmp/state-standard-lifecycle-prototype.log`,
  including the substituted-constructor refusal, SDK 245/1 ignored, native
  no-default-features compilation, wire 112/5 ignored, replay 67, physical PVM
  15, journal-store 105 and all feature-disabled compatibility groups.
  Formatting/diff checks passed. `saga/agents` remains clean at `7bae9269` and
  bundled artifacts are unchanged; this is not a release checkpoint.
  Recipe coverage now includes the lifecycle test submodule, not only the
  earlier physical-test module. The harness still uses a test Authority issuer,
  fixture actor-package reference and in-memory root staging: signed actor
  package admission, live reservation/finality and durable restart remain
  separate gates. Its debug-host single-operation timings are diagnostic only,
  not release latency or throughput evidence.
  Read-lane journal integration: a journal step still owns only
  one writable Ordered/Local lane, but declares every pinned external base for
  reads. Capture/publication require the exact complete declaration set and
  forbid secondary-lane successor contexts or candidates. Fresh replay derives
  those declarations from its own materialization; a scoped, read-only block
  interface shares the existing aggregate budget and does not expose store
  mutation. Read-only lanes retain their root-producing cursor even after
  no-op entries advance their journal heads. The signed probe now reads the
  secondary lanes during both forward execution and fresh recovery. Regressions
  reject omitted/substituted read roots, advancing read-only cursors and missing
  secondary blocks (the physical guest must actually attempt that fetch).
  Full validation passed: `task-tmp/state-read-lanes-prototype.log`, including
  SDK 245/1 ignored, no-default-features compilation, replay 68, physical PVM 15,
  journal-store 105 and all feature-disabled compatibility groups. Formatting
  and diff checks passed. This qualifies the probe's all-lane reads through
  crash recovery/checkpoint/GC, not the standard runtime's durable lifecycle.
  Bundled artifacts were unchanged.
  Durable standard Create follow-up: the existing authenticated genesis test
  now runs both the probe and the actual standard guest. Standard Create passed
  memory publication and file-store crash/reopen qualification at ObjectDurable,
  HeadsStaged and HeadsDurable (`task-tmp/state-standard-genesis-durable.log`).
  The same test retains wrong-signature/expired-receipt, wrong replica, budget,
  wrong seal and missing-block refusal checks. This reuses the ordinary initial
  checkpoint/exposure path; it does not invent a second persistence engine.
  The final regression executes public directory inspection from the reopened
  standard store and requires an empty directory, unchanged roots/state, no
  candidate blocks and no filesystem/head writes. All 69 replay tests passed
  (`task-tmp/state-standard-genesis-replay.log`), including both guests' genesis
  cases and the probe's mutation/restart/checkpoint/GC tests. Journal-store
  regression passed 105 tests (`task-tmp/state-standard-genesis-store.log`);
  formatting/diff checks passed. No production dispatcher or bundled artifact
  changed, and `saga/agents` remains clean at `7bae9269`.
  Probe mutation markers are explicitly excluded from the standard guest test:
  a real Install must precede its invocation lifecycle. Shared per-replica roots
  still refuse conversion to a common quorum proposal.
  Install handoff follow-up: physical capture now represents Control-only
  Install with no owning data lane. Canonical journal work requires a fenced
  Ordered position and unchanged successor contexts for all read lanes. The
  exact Installed entry must match the request; other management operations
  remain unsupported here. Capture refuses any data-component mutation or block
  candidate, and exposes the exact decoded management result through an
  input/transition-bound accessor for the existing replay evidence hook.
  The real compiled-actor lifecycle test now uses read-only data declarations
  for Install and checks successful capture, unfenced refusal, substituted reply
  refusal and read-lane advance refusal. Focused physical validation passed
  (`task-tmp/state-install-handoff-physical.log`). Full validation passed:
  `task-tmp/state-install-handoff-prototype.log`, including SDK 245/1 ignored,
  no-default-features compilation, replay 69, physical PVM 15, journal-store
  105 and all feature-disabled compatibility groups. Formatting/diff checks
  passed; `saga/agents` remains clean at `7bae9269`, with no bundled changes.
  Fenced publication follow-up: the pinned owner now admits metadata-only
  Install over the unchanged initial Merge projection, authenticates the existing
  fence, retains all data roots and uses the ordinary sealed publication path.
  Storage validates the fence's external manifest only under the existing pinned
  checkpoint availability proof; no whole-tree request-path audit or root-blind
  fallback was added. External Merge execution and non-Install fences remain
  unsupported. Scope checks bind the retained fence to its genesis/runtime.
  A real standard-guest test installs the macro-generated actor from actual
  schema/policy/constructor artifacts, publishes Control metadata, checks exact
  retry without re-execution, discards captures and requires fresh physical replay
  to reproduce the installed state and management evidence. Focused validation
  passed (`task-tmp/state-install-publication-physical.log`). The final regression
  also checks wrong-predecessor fence refusal before execution, public directory
  visibility after recovery and checkpoint preservation. Full validation passed:
  `task-tmp/state-install-publication-prototype.log`, including SDK 245/1 ignored,
  no-default-features compilation, replay 69, physical PVM 15, journal-store 105
  and feature-disabled compatibility. Formatting/diff checks passed.
  File-backed Install follow-up: the same standard lifecycle test now runs on
  the production Local-slot file journal, interrupting publication at
  ObjectDurable, HeadsStaged and HeadsDurable. Each fault must actually trigger;
  the poisoned owner refuses reuse. Captures are discarded before reopening.
  Reopen with exhausted availability budget refuses without filesystem changes;
  successful reopen preserves the durable head and all files, rather than
  promoting or repairing a staged Install. Retry either freshly executes from
  the unchanged predecessor or recovers the committed entry. Public directory
  inspection, exact retry without re-execution, checkpointing and another file
  reopen must preserve the installation and management evidence. Focused
  validation passed (`task-tmp/state-install-file-physical.log`). Full validation
  also passed with the explicit fault assertions (`task-tmp/state-install-file-prototype.log`):
  SDK 245/1 ignored, no-default-features compilation, replay 69, physical PVM 15,
  journal-store 105 and feature-disabled compatibility. Formatting/diff checks
  passed. Bundled artifacts were unchanged.
  Actor-package and Authority issuance remain fixture-scoped, not production admission.
  Durable Invoke/ACK follow-up: the standard lifecycle now continues from the
  installed, checkpointed actor on memory and file journals. The real compiled
  actor advances seed 41 to 42, survives reopening and an exact runtime retry
  under a new journal entry, acknowledges the retained result, and survives
  another reopen and exact ACK retry. Retired invocation replay must return
  DivergentInvocation with unchanged actor/runtime state. After checkpoint and
  reopen, a new invocation returns 43, demonstrating neither lost nor duplicated
  effects. Every journal entry also checks the no-execution committed retry.
  Captures are cleared before reopening; fresh physical replay is required.
  Fixture invocation receipts now receive host-side signature/binding checks as
  well as guest validation. Focused validation passed
  (`task-tmp/state-durable-invoke-physical.log`). Full regression passed:
  `task-tmp/state-durable-invoke-prototype.log`, including SDK 245/1 ignored,
  no-default-features compilation, replay 69, physical PVM 15, journal-store 105
  and feature-disabled compatibility. Formatting/diff checks passed. The test
  qualifies small-workload durability, not throughput or large-state capacity.
  Bundled artifacts were unchanged.
  Publication-fault follow-up: the same file-backed lifecycle now interrupts
  each real Invoke and ACK at ObjectDurable, HeadsStaged and HeadsDurable, in
  addition to Install. The fault must be reached for both operations. A poisoned
  owner cannot be reused; reopening never silently promotes or repairs the
  store. Recovery either finds the exact committed entry without re-execution
  or freshly executes and publishes that same entry from its predecessor.
  Each result survives a second reopen and the existing later-position retry,
  retirement, checkpoint and next-invocation checks. Focused physical regression
  passed (1 test, 89.89 seconds); the full gate passed at
  `task-tmp/state-durable-actor-fault-prototype.log` (SDK 245/1 ignored,
  replay 69, physical PVM 15, journal-store 105 and feature-disabled groups).
  This is fixture-issued Authority on the experimental file journal; it does
  not establish live finality, production dispatch or bounded release latency.
  The compiled macro-actor fixture now builds a signed VOS3 actor package from
  its actual PVM, generated schema, method policy, introspection and empty task
  closure. Host package admission verifies that exact envelope; Install binds
  its deployment, program, producer, package and requirements to the admitted
  values, and the file journal stages the exact package bytes in its catalog.
  The physical lifecycle test passed
  (`task-tmp/state-signed-actor-lifecycle.log`), as did file-backed crash/reopen
  (`task-tmp/state-signed-actor-durable.log`). The complete gate passed again at
  `task-tmp/state-signed-actor-prototype.log` (SDK 245/1 ignored, replay 69,
  physical PVM 15, journal-store 105 and feature-disabled groups). This removes
  the synthetic package reference from the test, but does not install a live
  registry reservation, production package admission or finality.
  Metadata-capacity follow-up: an SDK regression reaches the former 4-MiB
  runtime-metadata ceiling through individually bounded publications, then
  shows that a valid one-byte leading deletion cannot publish its shifted
  successor inside the 4-MiB change envelope. A 3-MiB shift fits both the
  provisional operation write budget and the change envelope. The experimental
  contract now defaults to a signed 3-MiB aggregate runtime-state limit, and
  host admission rejects a correctly signed external-runtime package above it;
  the released r19 limit remains 4 MiB. The rebuilt guest also passes physical
  ACK, unchanged rows, exact retry and result retirement with its signed state
  limit set exactly to the fixture's larger pre/post-transition size
  (`task-tmp/state-metadata-cap-physical.log`). The full prototype gate passed
  at `task-tmp/state-metadata-cap-prototype.log` (SDK 247/1 ignored, replay 69,
  physical PVM 16, journal-store 105 and feature-disabled groups). This is a
  conservative admission policy backed by a worst-case opaque-metadata rewrite
  and a small physical ACK. After the `b2457ddf` checkpoint, a further physical
  regression fills a valid standard-runtime retained-result predecessor to
  within 48 KiB of the signed 3-MiB ceiling using historical Linear images,
  then executes ACK, stages its rewritten metadata, verifies unchanged rows
  and exact retry under the current 5-billion management-gas budget. The
  earlier 1-billion fixture allowance ran out of gas; that allowance is not
  the production management default. The larger case still uses in-memory
  staging, not file-backed restart, and does not exercise large row-tree
  overhead or establish release latency. Before activation, qualify its
  file-backed publication/restart and retry within the admitted budgets.
  The complete prototype gate passed after adding this case at
  `task-tmp/state-near-cap-prototype.log` (SDK 247/1 ignored, replay 69,
  physical PVM 17, journal-store 105 and feature-disabled groups). The focused
  final-tree ACK variants passed at `task-tmp/state-near-cap-ack-final.log`;
  the new predecessor encoded to 3,129,456 bytes and its physical debug ACK
  took 1,994 ms in that run. This timing is diagnostic, not a release benchmark.
  Owner-lifetime follow-up after `8488c133`: `PinnedExternalJournal` now holds
  either a borrowed store or an owned `Box<FileAgentJournalStore>` while
  retaining its authenticated materialization between mutations. A focused
  file-backed regression reopens an exposed generation into the owned cursor,
  proves a competing stable-slot opener is excluded until that cursor drops,
  then reopens the same unchanged generation. The owned in-memory cursor also
  publishes a checkpoint. These are internal lifecycle contracts, not a
  production Local route or evidence that the live issuer selects this ABI.
  The file opener previously validated the durable/staged external head and
  `PinnedExternalJournal::open` materialized the durable head again. The owned
  cursor path now reuses that authenticated durable materialization while
  preserving staged-head validation. Measure startup cost before accepting it.
  The focused owned-file regression passed at
  `task-tmp/state-owned-file-cursor-focused.log`;
  the complete prototype gate passed at `task-tmp/state-owned-cursor-prototype.log`
  (SDK 247/1 ignored, replay 69, physical PVM 17, journal-store 105 and
  feature-disabled groups).
  The external replay adapter independently materializes the complete physical
  Install, two Invoke and ACK histories after file-backed publication faults.
  A forged Install signature and missing catalog artifact fail before execution.
  The focused compiled file test passed at `task-tmp/external-local-physical-test.log`.
  The complete prototype gate passed after the missing-artifact check at
  `task-tmp/external-local-prototype.log` (SDK 247/1 ignored, replay 69,
  physical PVM 17, journal-store 105 and feature-disabled groups).
  This was a replay seam, not active production routing; the fixture's
  credentials are not released-binary admission.
  File-owner follow-up: the owner now admits its exact signed runtime package
  through a resolver minted from the already-locked file store, validates both
  durable and staged heads, and keeps the executor with the cursor and lock.
  A restart fixture independently re-executes Create from the saved request
  inputs before opening it and verifies lock exclusion until owner drop.
  Live Ordered/Local preparation now passes replay-selected lane roots and the
  aggregate budget to physical execution; the earlier opaque hook could replay
  history but could not publish a first Install through this adapter. A fresh
  physical Install is now exercised on a cloned in-memory journal. The active
  `vosx` lifecycle has not selected this owner, and its retained Create seal
  still carries candidate output; reconstruct/compact that evidence from exact
  durable intent and measure startup memory/latency before release. The file
  owner now takes the opener's store-bound validated durable materialization;
  this removes the additional durable replay without selecting a staged head.
  The full prototype gate passed on this owner/live-execution tree at
  `task-tmp/external-live-prototype-final.log` (SDK 247/1 ignored, replay 69,
  physical PVM 17, journal-store 105 and feature-disabled groups). The focused
  standard lifecycle and synthetic block probe passed separately at
  `task-tmp/external-live-focused2.log` and
  `task-tmp/external-live-probe-focused.log`. The probe now charges guest reads
  and changed-link verification to one live budget and refuses later-position
  ACK with zero fetch allowance; exact committed retry still costs no guest
  execution.
  Locked-open replay follow-up: the file opener now passes its authenticated
  durable materialization directly into the retained cursor. The cursor checks
  both the stable store ID and a per-open epoch, so a token from a prior lock
  lifetime cannot bypass replay on a later reopen. A staged head is still
  validated but never selected for serving. The final physical standard-runtime
  crash/reopen test passed at `task-tmp/validated-cursor-final.log`; the
  feature-off check passed at `task-tmp/validated-cursor-feature-off.log`.
  The complete prototype gate passed at
  `task-tmp/validated-cursor-prototype.log` (SDK 247/1 ignored, replay 69,
  physical PVM 17, journal-store 105 and feature-disabled groups).
  Read-only serving follow-up: the locked owner now runs physical actor
  inspection from the pinned authenticated roots and checks that the guest
  changes neither state nor files. A named ActorId uses one exclusive-cursor
  page, with boundary arithmetic tested independently; the recovered standard
  Install test exercises that cursor and the materialization's current roots.
  The focused file-backed test passed at `task-tmp/external-targeted-physical.log`,
  the cursor unit test at `task-tmp/external-targeted-unit.log`, and the
  feature-off check at `task-tmp/external-targeted-feature-off.log`. The full
  prototype gate has not been rerun after this read-only follow-up. No route
  currently selects this owner, and per-execution full-metadata transport
  remains a measured-performance TODO.
  Initial Create-observation follow-up: the external owner derives a positive
  result, receipt and stable reopened-head commitment only from the locked,
  replay-validated initial head. Both Local formats now use the same issuer
  acknowledgement path; a focused issuer retry test passed at
  `task-tmp/external-observation-issuer-exact.log`, and the file-backed physical
  Create observation passed at `task-tmp/external-observation-physical.log`.
  The released image path's 26 Local lifecycle recovery tests passed at
  `task-tmp/external-observation-local-lifecycle.log`; the feature-off build
  passed at `task-tmp/external-observation-feature-off.log`.
  This is not yet a production Create path. Its initial-head restriction is
  appropriate before finalization; a later finalized Create retry must instead
  verify the same generation and original application without requiring the
  current head to remain at revision one. This remains a correctness TODO for
  lifecycle cutover.
  Production actor-package issuance and authoritative heads remain separate.
  Local Create-preparation follow-up: the new external preparer consumes a
  bounded immutable supplied catalog, rejects a missing package, verifies the
  exact admitted experimental binding and signed Create receipt, and uses a
  zero-read physical guest execution before minting the root-bearing Local
  seal. The focused standard lifecycle regression compares that seal and
  physical output with the independently prepared fixture, and rejects a bad
  receipt and foreign node (`task-tmp/state-production-external-preparer.log`).
  The full gate passed at
  `task-tmp/state-production-external-preparer-prototype.log` (SDK 247/1
  ignored, replay 69, physical PVM 16, journal-store 105 and feature-disabled
  groups). This is not a production Local route: no external intent persistence,
  owner-held file slot, exposed route or live Authority/finality is wired yet.
  Install changes bounded Control metadata and no data
  roots; its external frame must keep every data lane read-only. Do not route
  it through the unfenced invocation path or synthesize installed private state
  in the host. Signed actor-package admission and live Authority/finality remain
  separate gates. Continuation-safe budgets/Resume and other mutating management
  operations remain required, preserving row/metadata/result atomicity. Failed
  bootstrap currently traps; structured bootstrap error transport also needs
  definition before activation. This external-state candidate is reviewable as
  a scoped architecture checkpoint, not a deployable runtime.
  Package-policy transport follow-up: experimental ABI 003/s03 uses `XSW2`,
  requiring positive per-lane row/byte limits in each work envelope and its
  response commitment. Create derives these from its admitted package; typed
  Invoke/ACK checks exact equality before execution or provider access. Journal
  execution supplies the admitted limits and recovery retains that exact frame.
  Synthetic convenience defaults exist only in test helpers. Guest accounting
  consumes the frame limits; signed one-row or insufficient-byte packages must
  refuse a two-row mutation, while a sufficient signed package can execute it.
  Stricter operator policy is not an unauthenticated per-call override: it still
  needs an admitted lifecycle policy and replay-stable representation.
  Prior experimental 001/002 packages and frames are refused; released r19 is
  unchanged. Full rebuilt-guest validation passed
  (`task-tmp/state-policy-prototype.log`): SDK 241 passed/1 ignored, all prior
  host/replay/storage/physical and feature-off groups passed with unchanged counts.
  SDK tests bind responses to both exact ceilings and refuse legacy quota-free
  frames; physical tests reject mismatched limits before provider IO and enforce
  signed one-row/insufficient-byte limits against the same two-row operation that
  succeeds with sufficient signed limits. Non-test library compilation passed
  (`task-tmp/state-policy-production-check.log`, 306 existing/dead-path warnings),
  confirming synthetic policy helpers are not required by production builds.
  Formatting and diff checks passed; no released artifacts were regenerated.
- [x] Add a Refine embedder-call runner that resumes the same outer/inner
  machines. Default runner still rejects unknown calls; built-in Refine calls
  cannot be intercepted. Tests verify retained inner execution, no prefix
  reexecution and exact refusal counters. This is not yet a block-fetch ABI.
- [x] Add feature-gated physical host fetch prototype and four assembler-guest
  tests: verified reads, missing/corrupt bytes, invalid pointers/capacity/call,
  and gas/fetch-budget exhaustion. Default runner still rejects this call.
- [x] Add guest fetch transport with exact status/length validation; the tree
  independently verifies returned hashes. RV64E cross-check and native refusal
  tests pass. No native fallback silently substitutes for the PVM transport.
- [x] Qualify compiled Rust tree/row lookup and absence at 1,024 unrelated rows,
  including guest rejection of a substituted commitment and stale bytes from
  a deliberately dishonest host. Fixture is not a released AgentRuntime.
- [x] Add bounded candidate-change wire binding the old descriptor commitment
  and next context to sorted/deduplicated scoped blocks. Codec rejects malformed,
  reordered, duplicate, oversized or corrupt transport. It is NOT a publication
  certificate or proof of complete block availability.
- [x] Qualify compiled row replacement/deletion against native SDK candidates,
  including exact changed blocks, unchanged old snapshots and no provider writes
  on bounded-output failure. This uses the in-memory fixture, not durable heads.
- [x] Define authenticated public block-link inspection and bounded-memory full
  tree audit for recovery/import. Validate branch placement and every reachable
  chunk without interpreting actor values. Missing/corrupt unrelated data fails
  the audit; repeated chunk references consume read budget on each visit.
  This is not durable availability or permission to publish a root.
- [x] Align experimental block identities with journal blob addressing: the
  exact `VSB2` envelope contains scope and payload length, and its ordinary VOS
  blob hash is the block hash. Payload hashing streams header and bytes without
  allocating an envelope in the guest. This replaces the prototype's separate
  hash domain, not a released ABI; old experimental block hashes are incompatible.
- [x] Qualify journal-backed immutable block staging/reopen. The feature-gated
  adapter uses existing blob writes and
  read verification; no separate filesystem engine or hash index. Each physical
  envelope adds 105 bytes to the payload work reported by SDK probes. A native
  read can check two inodes (canonical and recovery alias), separately bounded.
  Staging alone cannot advance heads, seal replay, pin roots or promise quorum
  durability. Until reachability integration, these blocks are unpublished GC
  candidates; publication owners must serialize staging/commit against GC.
  Do not open released stores with the experimental build: its extra namespace
  is deliberately rejected by builds without the feature. No migration promised.
- [x] Add/test explicit external-root lane manifests and maintenance marking.
  The feature-gated manifest extension names the descriptor publicly and binds
  its exact blob; opaque manifests keep their old bytes/IDs. Extension tag 2
  explicitly retains the root-producing runtime binding and cursor separately
  from the current projection. It replaces unpublished prototype tag 1; no
  production format or migration changes. GC traversal checks
  the provenance-derived context and all reachable blocks, marking unique blobs
  while charging repeated chunk reads. It must reject missing data, bad binding
  or budget exhaustion before a collection intent is created. The ordinary
  publication validator still rejects these manifests until incremental
  replay-sealed availability exists; do not enable them by running a full audit
  on every publication. Codec/marker tests are not an end-to-end GC/restart gate.
- [x] Add bounded candidate reachability checks: changed nodes are supplied,
  reused subtrees require membership paths under the prior root, and changed
  chunked values supply all chunks. Reject unused candidate blocks, unrelated
  stored nodes, malformed placement, corrupt/missing proof paths and exhausted
  budgets. The base's complete availability is an explicit precondition, not
  re-established by scanning reused descendants. Fixed-work tests at 16/256/4,096
  rows bound provider reads below 512 blocks / 64,000 payload bytes per change.
  These are native structural tests, not production latency measurements.
- [x] Add an exclusive journal staging session: audit the base on entry, then
  advance data availability incrementally after complete immutable staging.
  Its mutable store borrow prevents GC interleaving; dropping it releases that
  guarantee. A descriptor alone does not retain availability. Data availability
  does not authorize execution or advance journal heads. Older candidates are
  rejected as stale; exact operation retries remain the journal's responsibility.
  Staging can now consume the private execution handoff directly, matching its
  selected base to the session and using its captured successor context. A
  stale execution fails before staging; a no-change output preserves the root
  with zero storage-read budget. Raw block staging remains only a lower-level
  primitive, not a way to attach caller-selected candidates to replay evidence.
  A recovery/import entry can now audit an exact persisted lane manifest:
  verify its store genesis, explicit declaration, root-origin context and exact
  stored descriptor bytes before traversing blocks under a read budget. It
  retains the exclusive store borrow through subsequent incremental staging.
  This is availability only: the caller still must authenticate manifest
  selection, origin ancestry and replica placement. Do not call this full audit
  on every request, or treat its result as a replay/publication capability.
  Recovery also has a read-only captured-transition verifier: validate incremental
  reuse under the audited base, then require every emitted block to exist and
  match its scoped hash and guest payload before advancing availability. Charge
  before allocation/I/O, share the recovery read budget, and preserve the old
  cursor on failure. Do not use staging to repair missing durable blocks during
  replay. No-change captures require no reads. This verifier is exercised with
  the compiled guest and now connected to the opt-in Ordered/Local suffix path.
- [x] Qualify compiled guest writes against the file-backed journal session:
  seed/reopen a chunked row plus an unrelated row, execute the guest, compare
  its complete candidate with native SDK execution, persist, reopen and read
  both old/new snapshots. Gas/output-size/staging-budget failures leave files
  and available root unchanged. The staging phase installs no heads. A separate
  final reopen check initializes only the sealed opaque genesis, persists an
  unpublished external manifest, audits it and stages a captured no-op without
  changing files or heads. It does not publish an external root or qualify an
  upgrade/recovery selecting that root. The fixture uses a test-only file opener
  because it has no installed Authority foundation.
- [x] Add explicit experimental execution framing (`XSW2`/`XST1`, not r19):
  bind responses to exact work, independently selected root contexts, outcome
  kind and returned root descriptors. Reject undeclared lane changes, inspection
  mutations, noncanonical lanes and aggregate candidate bytes above 4 MiB.
  The physical adapter decodes the actual guest response against its request;
  the compiled file-backed regression exercises this frame using journal Invoke
  work and contexts derived from test-admitted genesis and explicit provenance.
  This is structural binding, not production runtime admission or a replay seal.
- [x] Add an explicit signed experimental execution-contract identity and
  separate host package admission type. The opt-in SDK can decode that contract;
  ordinary host admission still requires r19, even in a feature-enabled build.
  Experimental admission verifies the existing signature and exact artifact
  closure and permits only Refine calls plus the state-fetch call. The released
  envelope/signature layout and r19 contract remain unchanged. This is not the
  final production ABI: gas/resources and lifecycle integration are still open.
  Compiled in-memory and file-backed fixtures pass this admission with a test
  signer. The journal fixture's predecessor root and runtime-selection history
  remain synthetic; signing a package does not admit a lifecycle upgrade.
  The physical entry now consumes that admitted type, executes its exact stored
  program, checks the work's runtime deployment and signed lane capabilities,
  and enforces signed state-byte limits both before execution and on the actual
  response. Unsupported management/Resume work is refused until its lifecycle
  and retained-owner bindings are integrated. Raw-program/framing hooks and the
  synthetic r19-shaped journal bridge are test-only; non-test callers cannot
  select them instead of signed package admission. Root authority, actor
  authorization, candidate availability and journal sealing remain separate
  required checks, not claims made by this physical entry.
- [ ] Finish production runtime dispatch and ordinary replay-sealed publication.
  Experimental Invoke/ACK handoffs, ordinary Local/Ordered preparation seals and
  genesis seals retain exact root changes;
  ordinary publication still rejects them without a pinned availability owner.
  The experimental Local journal session now stages candidates and uses the real
  memory/file publication engines; production dispatch remains unconnected.
  A decoded standalone `StateChange` must not be
  attached to a seal as caller-supplied execution evidence. Use an explicit
  versioned runtime contract, not payload-magic guessing or an r19 backdoor.
  Ordinary runtime authorization, reply identity and lifecycle validation remain
  mandatory. Journal Invoke/ACK currently admits one scoped lane; Create now
  routes all declared lanes under one shared budget. Attested reads and general
  multi-lane lifecycle execution remain unsupported. The fixture's
  obsolete Resume-with-Ready guest fixture was removed when the file-backed test
  moved to journal Invoke; real continuation recovery remains unqualified.
  Implemented prerequisite: one canonical CleanManage/Invoke/Resume/ACK mapping
  is now shared by the normal journal executor and replay work binding, including
  the existing Attested binding path. The experimental journal request adapter
  requires explicitly declared root manifests, exact genesis/runtime/base bytes
  and journal-derived contexts; it does not infer storage format from bytes.
  Bootstrap and conditional runtime-upgrade bindings remain unsupported there.
  Cursor ancestry/authentication remains replay's responsibility; constructing
  an experimental request grants neither execution authority nor a seal.
  Added the experimental physical journal invocation adapter: construct work
  from explicit manifests, require its single owning lane's successor cursor
  to match the Ordered/Local execution position, execute once, and convert the
  exact response through the common clean outcome and replay lane/transition
  checks. The normal executor and Attested binder now share the same public
  invocation/yield/ACK identity checks. Rejected ACKs still require unchanged
  state. The bridge now returns a private-field `ReplayExternalExecution` handoff
  binding input ID, prior-state commitment, position, accepted transition and
  exact guest output. Replay consumes it through the executor hook and checks
  those bindings before ownership mutation, retaining it on `ReplayStep`.
  The admitted journal adapter derives the complete runtime binding from the
  verified package and compares deployment/program/producer/package/ABI/semantics
  before loading or fetching. Experimental journal decoding requires the exact
  experimental ABI/semantics pair; mixed pairs fail, and feature-off builds
  still accept only r19. File-backed replacement/no-op execution now uses this
  adapter and retains the predecessor root's original runtime provenance.
  Opaque genesis preparation and cross-format upgrades explicitly remain closed
  until their root/availability conversion closures are integrated.
  It is not authority to publish; no released driver selects it. Lifecycle
  activation, general management/upgrade and Merge successor-frontier binding
  remain open; multi-lane Create framing/execution is described below.
  Initial Create framing is now derived separately from the exact admitted
  experimental package and canonical Create input. It binds package identity,
  declared contract/capabilities and the complete selected replica, then supplies
  empty roots for every declared data lane (Linear/Merge/Local), with Local scope
  tied to that node. Contexts use the existing Create-intent/authority-sequence
  seed, avoiding a cycle through the eventual post-Create genesis commitment.
  Framing does not verify receipt authority or relax the external-genesis refusal.
  Bounded multi-lane physical dispatch now selects declared scopes using fetch
  register r11 (guest a4), with one aggregate fetch/byte budget and the existing
  scoped-hash validation. Experimental ABI/semantics are now 003/s03, including
  quota-policy framing; 001/002 artifacts are rejected, while r19 is unchanged.
  A distinct admitted Create executor runs that initial frame and enforces signed
  input/output state limits. Its output remains an uncommitted candidate until
  the dedicated genesis seal and initializer stage and validate all declared
  roots. That initial-only memory/file path is implemented; general
  management/Resume and production runtime selection remain closed.
- [ ] Connect the staging session to replay-sealed publication while keeping
  availability pinned across commit. Do not re-audit once per ordinary request
  or execute against an uncommitted availability cursor. The existing manifest
  publication gate remains in place until this integration is complete.
  Local/Ordered step-based sealing now retains the exact execution capture after
  checking input, predecessor state/root, runtime, position, disposition and
  declared lane. A changed external state without its capture is rejected;
  unchanged non-executing retained-result/ACK paths do not fabricate one.
  Ordinary prepared publication and both storage publishers refuse captured
  mutation seals unless the exact pinned mutation capability is supplied;
  checkpoint availability alone is insufficient. An experimental
  `PinnedExternalJournal` now owns the exclusive store borrow from seal-bound
  recovery through successive commits. Recovery audits all declared roots once;
  each mutation verifies/stages changed paths against that retained availability,
  without a full-tree request-path audit. Its borrowed validation context binds
  the store, exact seal, predecessor/successor and unchanged checkpoint lanes.
  Mutation permission is enabled only after staging succeeds. State advances
  only after successful CAS; a publication error poisons the owner until recovery
  because the commit may already be durable. Abandoned staging can leave orphan
  blocks, never an executable uncommitted cursor. Unchanged Merge roots may be
  carried through an Ordered/Local step; changing an unrelated lane or executing
  a Merge/fence remains forbidden.
  The advanced filesystem opener now reuses locked-slot admission and common
  replay to validate both durable and staged heads under one aggregate budget.
  It accepts later checkpoints only under the same admitted genesis/runtime,
  retaining the exact initial Merge root and unchanged frontier; Merge/fence
  execution and runtime upgrades remain closed. Bootstrap keeps its separate
  initial-only opener. It returns a locked store,
  not a route or executable cursor, and does not clean/promote stages. A pinned
  execution session still recovers its own cursor before serving work.
  Compiled-probe publication/reopen coverage now exercises both Linear and Local
  lanes, changed ACK roots, exact ACK publication retry and an executed no-change
  ACK at a later position. Clean-runtime result retention remains the runtime's
  responsibility: later-position ACKs must not be silently converted to legacy
  host-index no-ops. The probe writes only an ACK marker, not a production result
  store. The pinned session now publishes maintenance checkpoints, updates its
  selected availability set, and can continue mutations before another checkpoint.
  Root audits are charged only at recovery/maintenance, not to ordinary mutations.
  File GC has a genesis-qualified entry point for those checkpoints, preserving
  the existing fresh-head, staged-head, marking and bounded-unlink guards.
  Actual-genesis checkpoint fault qualification now covers both lanes at all
  three file publication boundaries and a lost memory-store commit response.
  Recovery now reruns the signed probe against persisted blocks with an empty
  capture list. Its read-only executor hook runs after authentication, retains
  the store's exclusive lifetime, and shares the aggregate recovery read budget.
  Remaining: the production runtime's bounded state/result model and dispatch,
  released-binary/process restart qualification. GC still requires an exact fresh
  checkpoint and cannot collect a pending mutation suffix. Do not silently drop
  captures, treat caller-supplied roots as pins, or add full-tree audits per request.
  Ordinary checkpoint/fence/Shared-projection loading rejects explicit external
  declarations; only the bounded opt-in recovery paths described below accept
  them without erasing provenance. The original regression caught checkpoint
  recovery erasing that distinction: the same descriptor bytes remain valid as
  explicitly opaque state, but an external declaration requires explicit
  availability validation rather than descriptor decoding alone.
  The refusal regression failed before this loader check was added. Maintenance
  traversal and canonical record decoding remain available independently.
  Released r19 executors default to no capture. Replay now requires a matching
  capture for physical execution under the experimental ABI, before ownership
  mutation. Authenticated retained-result recovery and synthetic non-applied
  ACKs remain non-executing paths and must not manufacture a capture. No
  descriptor-magic inference selects an execution contract.
  Record-level prerequisite implemented: root provenance is separate from
  projection position, so later projections preserve descriptor/state bytes.
  Codec checks reject future or same-height conflicting Ordered/Local origins;
  these shape checks do NOT prove ancestor membership (especially Merge).
  Execution framing now allows a no-change response to retain its original
  descriptor even when work selects a newer successor context. A changed
  descriptor still requires a matching candidate; the new SDK regression checks
  both cases. This is not yet end-to-end retry/no-op publication qualification.
  The compiled fixture now also repeats an identical row value at a later
  journal position, returns no candidate, and retains exact state/descriptor
  bytes and unchanged files. This is an executed data no-op, not proof of
  retained-result deduplication or authoritative journal recovery.
  An accepted `ReplayStep` can now derive an Ordered/Local successor lane
  manifest from its authenticated predecessor: changed roots take the captured
  successor context/runtime/position, while unchanged roots retain exact origin
  and descriptor bytes. Missing captures cannot authorize changed descriptors;
  stale projections, foreign genesis and cross-replica Local positions fail.
  Materialization now has a private explicit lane-root provenance map, retained
  by successor/checkpoint copies. Local and Shared compaction use one projection
  helper: retain the original root/runtime/cursor, require exact descriptor bytes
  and independently derive its expected context. Projection regression coverage
  includes later cursors/current-runtime changes, wrong bytes/origin/Local owner,
  and identical bytes remaining opaque without a declaration. This is record
  derivation, not publication qualification: normal loaders still reject external
  declarations, so their maps remain empty. Ordered (including Shared) and Local
  preparation now derive successor maps from accepted steps: changed roots need
  matching captures and previously declared lanes; no-ops retain exact origin.
  Wrong base bytes, missing capture and undeclared lanes fail. The opaque path
  does not fetch genesis again. This runs under the existing store-bound prepare
  lifetime and before returning a prepared publication; it does not create a
  second commit mechanism. Shared preparation loads origin context before the
  index borrow so its successor claim names the declared Linear manifest, not
  an opaque manifest over identical descriptor bytes. Exact retries derive the
  same declaration-aware projection. The ordinary opaque path adds no read.
  Ordered snapshot caches now retain explicit Linear provenance through live
  preparation and checkpoint copies. Cache validation rejects inconsistent
  bytes, future/foreign origins and same-base replacement with an opaque entry;
  materialization authentication also checks current-cache/root-map agreement.
  Resolver-provided snapshots must preserve declarations, but no external-root
  recovery resolver is enabled. These are metadata-consistency checks, not root
  availability or ancestry proofs. An explicit experimental recovery entry now
  loads Linear/Local declarations selected by a durable checkpoint, requires the
  matching experimental runtime contract, audits exact persisted roots under one
  caller-supplied aggregate block budget, and retains origins in the returned map
  and ordered snapshot. Origin runtime packages must remain in the authenticated
  artifact closure. The exclusive store borrow spans recovery; returned metadata
  is not a portable availability pin. Ordinary/reverified recovery still refuses
  external declarations. The opt-in path now advances Ordered/Local suffix roots
  using accepted execution captures and verifies emitted blocks already exist.
  Its checkpoint audit and suffix checks share one budget. Invocation indexes
  expose only a read borrow of their backing store, retaining exclusive ownership
  through replay. Unchanged roots retain origin; changed roots acquire the exact
  accepted cursor/runtime, and snapshots retain the new declaration. Cross-lane
  mutations, undeclared captures and absent persisted blocks fail. External Merge
  roots, Merge replay and fence dependencies remain unsupported.
  Fixture-selected checkpoints do not qualify lifecycle admission, Shared
  certificates or released recovery. The same simulated-execution regression now
  covers both Ordered and Local suffixes, including unrelated-lane preservation
  and refusal of a Local checkpoint under a foreign replica identity. Physical
  end-to-end suffix qualification and integration of Shared recovery,
  preserving Merge dependencies, matching storage-side publication derivation to
  declared claims, and sealing availability remain open. Publication gates have
  not been removed.
  The actual Local checkpoint preparation path now has regression coverage for
  both lane kinds: reject a pre-suffix materialization, retain exact declaration,
  cursor, descriptor hash and successor root map, stage descriptor bytes, and
  leave durable heads unchanged when the prepared object is dropped. Manifests
  remain inside the sealed checkpoint until storage publication. The lightweight
  test-store CAS is deliberately not used as publication evidence.
  A non-Clone audited checkpoint owner now consumes the prepared publication and
  retains its exclusive store borrow, exact seal and audited lane-manifest IDs.
  It checks freshness/contract/checkpoint shape, origin contexts, descriptor bytes
  and complete external block availability under one caller-supplied budget.
  Failure or abandonment leaves heads unchanged. This is maintenance-only full
  auditing, not an ordinary-write fast path. Memory and Linux file stores consume the
  owner's exact availability set under that same borrow through checkpoint CAS.
  Ordinary publication still rejects external roots. Separate sets cover successor
  manifests and external manifests selected by the predecessor checkpoint.
  Both audits share the caller's budget; an identical manifest is not traversed
  twice under the same exclusive borrow. Changed successor roots do not prove
  availability of retired predecessor branches. No store-level permission flags or
  clonable availability tickets were added.
  Audited publication joins this sealed checkpoint to storage's checkpoint
  publication/closure validation with a private, borrowed context bound to the
  exact store instance, predecessor/successor heads, checkpoints and lane IDs.
  Regression coverage uses the real memory publication engine and opt-in
  rematerialization, but starts from a synthetic runtime/checkpoint boundary.
  It does not establish authenticated lifecycle selection or disk durability.
  The ordinary-generation filesystem slot now has an explicit budgeted reopen
  entry point. It retains the same admission, exposed-generation and stable-lock
  checks; audits external Linear/Local checkpoint roots under an aggregate budget;
  then runs the existing head-closure validation using call-scoped availability.
  Durable and staged heads are both checked, without promoting `heads.next` or
  returning a reusable availability ticket. Normal opens remain unchanged.
  No production driver selects this entry point yet, and availability alone is
  not authenticated origin ancestry: replay remains required before exposure.
  File publication now threads that same call-scoped context through checkpoint
  dependency validation and head CAS, including exact retry, while preserving
  the existing immutable staging, history overlay and sync/rename protocol.
  Only checkpoint branches receive this context; ordinary execution publication
  has not been opened. The file regression now covers object-durable,
  heads-staged and heads-durable failure boundaries for both Linear and Local
  roots, then read-only admitted reopen and exact sealed retry. Its starting
  checkpoint and seal are synthetic, and roots are retained rather than changed.
  The replay regression now also transfers its synthetic checkpoint/suffix into
  an admitted file journal, then uses real preparation, audit ownership and
  publication for the changed root. It covers abandoned preparation, failure
  after head staging, admitted reopen, fresh preparation/re-audit and final
  rematerialization. The execution handoff and initial runtime selection remain
  synthetic. An explicit Linux file-store maintenance collector now retains
  head-bound availability through marking and sweeping. Ordinary GC remains
  closed for external roots. The availability audit uses its supplied read
  budget; marking, namespace scans and unlink batches retain separate GC limits.
  Stale heads and pending `heads.next` stages are refused before audit/sweep.
  The compiled Linear probe now supplies a signed-package physical execution
  handoff to that same replay/publication/reopen/GC fixture; its changed blocks
  are checked against an independent native row update. Production lifecycle
  selection and released-runtime end-to-end execution remain gates.
  Do not enable durable external heads before they can be safely reopened. Do not
  replace the current external-root refusal with blob-existence checks or an
  unbounded audit on ordinary writes. Availability evidence must survive until
  the same-store, exact-predecessor CAS; an abandoned prepared object must
  not carry an availability promise across intervening GC. Qualify stale heads,
  wrong store, missing candidate blocks and abandoned preparation/GC before
  opening that path.
  Replay must carry authenticated provenance across exact retries/terminal
  no-ops and prove each changed origin before sealing. Preserve terminal-state
  equality and cover retry/no-op/checkpoint/reopen before opening the gate.
- [ ] Qualify growing data and arena/resource use for writes, then wire
  the same guest reader into normal runtime execution.
- [ ] Integrate authenticated, resumable outer-PVM block fetch. Bound gas,
  fetches, fetched/written bytes, allocations and
  resident cache memory; cached reads also consume deterministic work budgets.
- [ ] Qualify a custom runtime against the same public contract. No host decode
  of private standard-runtime layouts and no native-only qualification shortcut.
- [ ] Persist blocks before atomic publication of roots/results/retry records;
  test crashes at each boundary and repeated exact operations for Local/Shared.
- [ ] Bind Shared commits to required data availability and durability under
  existing quorum rules; test missing blocks, minority failure and catch-up.
- [ ] Implement root-pinned export/restore and safe reclamation. Keep references
  held by authoritative heads, pending work, retry/recovery and backups. Never
  advertise durable success for a root whose required blocks are unavailable.
  Use public block-link/closure traversal for these host tasks; do not make
  hosts decode private actor values or standard-runtime control layouts. Full
  audits belong at import/recovery boundaries, not on each request/publication.
  Incremental publication must establish availability of changed links against
  previously durable subtrees, without rescanning all retained state.
- [x] Run the compiled outer-PVM fixture's fixed lookup/replacement/deletion
  against 16, 256, 4,096 and 100,000 retained rows. Enforce bounded fetched/output
  bytes and blocks, compare exact candidates with native execution, and measure
  actual gas, program-load/run time and incremental-reuse verification separately.
  This uses an in-memory provider and native setup, not Clerk or journal commits.
- [ ] Qualify cumulative guest allocation and actual Clerk at 1,000 accounts /
  100,000 transfers, including its multi-row operations, filesystem publication
  and quorum. The fixed one-row fixture does not establish this acceptance gate.
- [ ] Version the admitted ABI, regenerate/reproduce artifacts and qualify
  production Local/Shared paths before removing the experimental feature gate.

Known shortcomings: no journal/finality source for descriptor admission,
durable root publication or production caller. `StateTree::from_root` binds a
caller-supplied root but does not admit it. Path validation is not a full audit
of imported roots; unvisited subtrees must be audited before importing a root
as authoritative. `StateTree::audit` supplies graph validation, not authority,
durability or a durable availability index. Its row/byte totals describe encoded
tree values, not signed actor quotas or unique physical storage consumption.
Scope covers state lanes, not control metadata. The tree uses
32-byte digests, while the new row adapter retains and verifies full actor,
incarnation and arbitrary key bytes. Runtime method/lane/schema namespace
admission is still required before constructing that adapter; it is not an
authorization API. Accounted batches now carry lane-wide logical counters in the
same candidate tree as rows; production policy binding and coupling to real
runtime inline state/results remain pending. Physical/journal fixture evidence
is recorded above and does not qualify a production runtime.
Incremental reuse currently proves each boundary subtree via its own bounded
membership path, so shared prefixes can be reread (up to quadratic work in tree
depth, not retained row count). Share/cache these paths only if measured work
warrants it. Changed chunked leaves resend their full bounded value; partial
chunk reuse remains unimplemented; canonical row batches now share a private overlay.
Hashed row keys do not provide ordered prefix scans. Preserve collection-owned
indexes for ordered operations, and choose per-actor subtree ownership (or an
equivalent bounded index) before implementing actor removal/reclamation; do not
introduce a whole-Agent scan to find one actor's rows.
The provisional block size is 64 KiB; chunked values now cover the 64-KiB actor
row boundary. Values are still materialized individually (at most 1 MiB), not
streamed; replacement/deletion currently reads the old value's chunks. That
cost must be measured with the row adapter, not hidden by the small-value probe.
The reader receives an exact pre-budgeted buffer; production I/O still needs
its own memory/gas controls. Staged writes are budgeted but neither durable nor
automatically published. Failed/missing/cached fetch attempts are charged;
failed admission does not partially spend budget. Root publication, replica
durability, reclamation and backup remain unimplemented release gates.
Candidate changes cap one operation's wire at 4 MiB / 4,096 unique blocks,
not the retained dataset. Publication must additionally validate the complete
reachable data set, execute/admit the exact operation and atomically bind its
result/retry record to the new head. Neither decoding a candidate nor calling
`validate_context` supplies that authority. Batch row deltas and repeated-path
caching remain unqualified; one-row probes do not represent Clerk's workload.
The experimental `vos/experimental-state-blocks` host handler validates bounded
guest pointers/capacity, charges fetch/gas budgets, verifies scoped bytes and
refuses missing/corrupt blocks without output. It is not selected by production
drivers. The SDK guest adapter and `state-tree-probe` fixture now exercise
the same host ABI. The first compiled run failed closed with
`UnsupportedCall(0)`: the compiler's static host-ID extraction recognized only
an immediate `li t0, N`, not the original multi-instruction large identifier.
The experimental ABI now uses `0x180` and explicitly emits that load in asm.
General compiler validation/rejection of unrecognized host-ID construction is
a recorded follow-up, not silently claimed fixed by this ABI adjustment.
Its gas tariff is provisional; freeze/version it with the eventual admitted ABI.
The portable runtime guest currently uses a one-shot allocator (deallocation
does not reuse arena space). Physical qualification must therefore bound
cumulative allocation as well as live buffers; native allocation behavior is
not evidence that the guest fits its arena.
The observed/proof
runner does not support external handlers; proof production stays deferred,
and future proof support must bind external reads rather than omit them.

Tree choice: a deterministic compressed binary radix tree avoids page split/
rebalance policy in this first slice. Typical fixture paths grow with tree
depth; adversarial fixed-width keys can require 257 nodes. That bound is tested
iteratively, without recursive guest-stack growth. It is not a production
throughput claim. The test store retains historical blocks without reclamation.

Keep existing bounded control/directory metadata initially; measure its cost
and document its remaining caps rather than claiming every runtime component
scales with touched data. Clerk's committed-map tree remains separate from the
physical block tree; measure the extra hashing instead of merging the formats.
No release ETA or 300-client throughput claim follows from these primitives.

Deferred storage extensions: online/mixed-ABI migration, dynamic membership,
automatic ledger sharding, a new query language, concurrent online GC,
Private/Attested production, and full generic runtime-state consolidation.
Maintenance-window reclamation is acceptable initially, but safe bounded disk
retention is still a release gate. These exclusions do not waive recovery,
backup or long-running retention tests.

## Branch boundary

- Reviewer: `saga/agents` is at bounded-state checkpoint `6bcff6fe`;
  see [the review guide](agent-saga-review.md). This is
  prototype qualification, not production release evidence.
- Implementation continues on `wip/ch08-runtime-directory` from that checkpoint.
  The next work is external Local startup selection/recovery and route attachment,
  then remaining batch 1. This signed Create seam is internal, not deployed.
- Current WIP checks: candidate Authority/standard-guest signed Local Create,
  interrupted retirement and expired-window retry pass; existing physical
  external-genesis publication/crash-recovery passes after the ACK clock fix.
  Feature-disabled `vos` and default Authority builds still check. None of
  these is released-binary or full-workspace qualification.
- Master is unchanged; nothing is pushed. Review read-only and apply findings
  on the implementation branch to avoid conflicting fixes.
- Exact formatted-tree checkpoint gate passed at
  `task-tmp/state-review-checkpoint-prototype.log`: SDK 247/1 ignored,
  replay 69, physical PVM 16, journal-store 105 and feature-disabled groups.
  `cargo fmt --all -- --check`, `git diff --check`, and offline/locked
  `cargo check -p vosx --tests` passed. This is not the release/workspace gate.
- Detailed integration chronology: `42928ddc:docs/agent-saga-status.md`.
  Its pending-run statements are historical, not additional live tasks.

## Reviewed baseline and qualification

At `7bae9269`, the mixed retired/unfinished Shared recovery P1 is resolved.
Unfinished generations complete normal publication/ACK/application/finalization/
retirement before fresh Authority reads for retired generations. Temporary
physical opening never exposes serving routes. Reservation and freshness guards
remain unchanged. Independent review found no new findings: Shared recovery
7 passed / 1 ignored, including both Agent-ID orderings and actor Invoke/ACK;
staging finality, lease retention and route nonexposure also passed.

Review evidence: `target/agent-review-7bae9269.cfAj31/REVIEW.md`.
Full historical commands, logs and qualification boundaries are preserved at
`7bae9269:docs/agent-saga-status.md`; [review guide](agent-saga-review.md)
describes the reviewed boundary, not the new release plan.

Earlier `2b1e7f56` qualification included 2,406 workspace tests passing
(6 ignored), 278 CLI tests passing (20 ignored), and a full outer-PVM lifecycle
passing in 1,938.39 seconds. These are source-specific historical results, not
qualification of new implementation work or a request-latency benchmark.
The mixed-recovery follow-up did not rerun the full outer PVM.

The existing fixture still uses an immutable genesis issuer checkpoint for
subsequent management. It does not qualify released Shared Create/Install,
multi-node replication, backup or throughput. Whole-state execution and Shared
host-wide locking remain. Historical optimized Local Create/Install timings
(about 15.6/19.7 seconds) are not current throughput data.

## Current implementation verification

The actor-storage test group passed: 11 passed, 0 failed, 0 ignored (0.11 seconds
after compilation), including the new row-capacity regression. Command:

```sh
cargo +nightly-2025-05-09 test --offline --locked -p vos --lib \
  --features 'agent-runtime storage network http-ingress' \
  agent::actor_storage::tests -- --nocapture
```

No released Clerk/PVM benchmark has run. This proves the current codec boundary,
not an exact supported ledger size or throughput. Clerk port, three-node workflow,
CLI, performance and backup implementation remain pending.
Feature-enabled SDK suite after explicit experimental contract admission: 232
passed, 0 failed, 1 ignored. Coverage includes maximum audit frontier (256
pending siblings plus 16 value chunks), unreachable historical blocks, opaque
chunks that resemble nodes, missing/corrupt unrelated values, scoped inspection,
invalid branch placement and budgets enforced before provider access. Five
execution-frame tests cover exact request/root binding, undeclared lane and
inspection mutations, malformed/truncated frames and aggregate multi-lane limits;
a sixth covers retaining an unchanged root at a later execution position.
SDK library Clippy passes with `-D warnings`.
The current prototype gate also passes all 6 contract tests without the
experimental feature, 7 package-admission tests, 8 physical tests (including
typed signed-package execution and 100,000-row growth), and 104 journal-store
tests. Signature substitution, cross-contract admission, undeclared host calls
and malformed PVMs are rejected. The nonexperimental VOS library check passes
with 264 existing warnings. Logs: disk-backed target
`task-tmp/state-contract-prototype.log` and `task-tmp/state-contract-production.log`.
The typed-entry follow-up is recorded in `task-tmp/state-admitted-entry-gate.log`;
it checks deployment/lane/input-limit refusal before execution and returned-state
limit refusal without staging, using the actual compiled guest.
The experimental non-test library check also passes after raw execution hooks
became test-only (`task-tmp/state-admitted-entry-check.log`, 277 warnings,
including unused experimental integration code; no warning suppression added).
The admitted package now selects the experimental journal execution adapter;
new runtime-binding pairs are feature-gated and captures are mandatory for its
physical replay. Production driver selection and lifecycle admission remain
closed. Opt-in recovery now preserves explicit root provenance through Ordered
and Local suffixes; audited memory-store checkpoint publication is implemented.
Audited disk-backed checkpoint publication and budgeted reopen are implemented;
production recovery integration, Shared publication and physical end-to-end
lifecycle qualification remain pending.

Current replay gate: 67 tests passed (13.40 seconds;
`task-tmp/state-fresh-replay-boxed.log`). In addition to capture/refusal and
initial-genesis coverage, the compiled fixture now opens a pinned session on an
actual initialized external genesis and commits two guest mutations followed by
ACK and repeated-ACK transitions, separately for Linear and Local lanes, through
real memory and file publishers. It verifies budget-exhaustion leaves
heads/cursor unchanged, each commit spends exactly the changed-link verifier's
read budget (no repeated base audit), exact retry skips execution, and a cloned
seal cannot reuse a borrowed publication capability. File fault points cover
ObjectDurable, HeadsStaged and HeadsDurable. A publication error poisons the
session; recovery selects durable heads, retries an unfinished mutation or
recognizes an already committed one. Removing a changed suffix block makes
recovery fail without repairing it from captured guest output or changing heads.
The follow-up now drops the file store and reacquires its stable slot lock after
each injected boundary and after retry, using the advanced opener. Successful
and failed reopen preserve the complete journal filesystem snapshot; staged
heads are never promoted. Zero budget, one fetch less than the measured complete
recovery requirement, and missing changed-state blocks fail closed. The exact
aggregate fetch budget succeeds, including when durable and staged heads both
need validation. These remain in-process fault injection and handle-reopen
tests, not process-kill or production qualification. The actual-genesis recovery
executor now freshly executes the signed compiled probe for each suffix step,
reading the recovery store through a scoped read-only interface. The first reopen
and materialization run with the captured-transition list empty. A rejected
authentication produces no guest execution and leaves heads unchanged. Guest
fetches and persisted-successor verification share the aggregate read budget;
returned candidate bytes cannot repair missing storage. Other synthetic fixtures
still use captured transitions, and the live-mutation test adapter uses captures
from its immediately preceding physical execution. This is not a released runtime
or a process restart. Create uses the authenticated fixture receipt;
invocation authority and runtime result
retention are still probe fixtures. No production lifecycle, ACK semantics,
Shared quorum, serving throughput or release qualification follows from this.
The ACK probe binds the original work/authorization commitments, and its repeated
execution returns no new blocks/root. Exact journal retry skips execution; a
later-position ACK executes the runtime and publishes the captured no-change
result with zero block-staging reads. This distinction corrected an invalid test
assumption about legacy host-owned retirement; production behavior was not
changed to satisfy it (`task-tmp/state-local-ack-replay.log` preserves that failure).
The same fixture now checkpoints after ACK, executes another no-change ACK,
checkpoints again, and reopens the selected successor. Both lanes preserve exact
state while the original Merge declaration remains unchanged. Altering that root,
its frontier or the runtime is refused; generic checkpoint validation without
the genesis binding still refuses Merge roots. File collection rejects stale
heads, an uncheckpointed/staged mutation suffix and exhausted audit budgets
without changing files. One-unlink passes resume to completion, remove an
explicitly unreachable block, preserve heads and permit read-only reopen after
GC. The actual-genesis fixture now also interrupts checkpoint publication at
ObjectDurable, HeadsStaged and HeadsDurable for both lanes, plus a memory commit
whose response is lost. The old session remains poisoned; read-only reopen
preserves the durable heads without promoting staged heads. Recovery retries an
unfinished checkpoint to the exact candidate ID or recognizes the durable
checkpoint without publishing a replacement. Another ACK, checkpoint and GC
still succeed afterward. Generic checkpoint crash tests remain covered separately.
The execution-hook refactor initially exceeded the default test stack in an
existing native Merge recovery regression. The final implementation keeps ordinary
execution direct and heap-owns the large private recovery Create envelope, rather
than carrying it by value through every recovery frame. All 67 replay tests pass
with the default stack; no stack-limit override or journal-format change was used.
Failure evidence is retained in `task-tmp/state-fresh-replay{,-inline,-direct}.log`.
The first run exposed an obsolete blanket rejection of retained Merge roots;
the fix preserves unchanged roots but still rejects unrelated-lane mutations
and Merge/fence execution (`task-tmp/state-pinned-mutation.log` retains failure
evidence; the first passing end-to-end run is `state-pinned-mutation-retry.log`).
The full storage gate passed 105 tests
(16.10 seconds; `task-tmp/state-fresh-replay-store.log`). The physical PVM group
passed 10 tests, including the 100,000-row probe (12.42 seconds;
`task-tmp/state-fresh-replay-physical.log`). The feature-disabled replay group
passed all 58 tests (3.65 seconds; `task-tmp/state-fresh-replay-disabled.log`).
The feature-enabled replay build reported 303 library warnings; the previous
feature-off library check reported 266 warnings
(`task-tmp/state-genesis-checkpoint-faults-disabled.log`).
These include unused experimental integration members; this is not a warning-free build.
The last complete rebuilt-guest prototype recipe passed: SDK 237 passed/1 ignored,
feature-off contract 6 passed, admission 7 passed, physical execution 10 passed,
and the runtime-binding pair test passed with and without the feature, alongside
67 replay and 105 storage tests. The expanded recipe also passed actor storage
13/11 (feature on/off) and inner execution 22/21 (7 artifact-dependent tests
ignored in each configuration). Log: `task-tmp/state-quota-prototype.log`.
The additional feature-off package group passed 18 tests separately in
`task-tmp/state-quota-package-disabled.log` and is now part of the recipe.
Formatting (host and pinned guest toolchains) and diff checks pass. Released r19
artifact pins are unchanged; only the test probe was rebuilt.
The Create-framing follow-up is recorded in `task-tmp/state-create-framing-replay.log`
and `task-tmp/state-create-framing-disabled.log`. It checks all declared initial
lane roots, empty input state, package/placement/non-Create refusal and continued
external-genesis refusal; no lifecycle activation is inferred from these tests.
Multi-lane follow-up adds explicit scope selection with one shared host budget.
Its assembly regression reads Linear/Merge/Local blocks in one run, rejects
cross-lane and undeclared selectors, and fails when the aggregate fetch or byte
budget is exhausted. The compiled Create probe initializes all three declared
lanes; each returned candidate is independently staged from its exact empty
base, while journal heads and genesis remain absent. The physical group passed
10 tests (9.53 seconds), including exhausted gas and signed output-state limits.
Empty Create input consumes zero state bytes; small positive state limits reject
the produced state, not input framing overhead. The initial stricter test had
that expectation reversed; enforcement was not changed to make it pass.
The current experimental contract is ABI 003/semantics s03 (quota framing).
001/002 experimental packages/guests must be regenerated; no production migration or
change to released r19 artifacts is implied.
Create now returns a private-construction `ExternalCreateExecution` handoff,
retaining the exact input ID, replica, initial lane work and physical output.
It rejects a structurally valid `Created` reply for a different Agent identity;
request and replica mismatches cannot reuse the capture. This is not receipt
authentication or availability evidence. Authenticated preparation now invokes
the external executor only after the common genesis input/placement/receipt
checks, validates the exact capture and common genesis transition semantics,
and retains the complete capture in `ReplayPreparedExternalGenesis`. The wrapper
has no conversion to an opaque genesis seal. Local sealing now retains its
physical capture and emits explicit root-bearing lane manifests, validating
initial root contexts against the final genesis without changing their
cycle-free origins. This separate seal cannot use ordinary storage
initialization, which has no external-block availability contract. A dedicated
in-memory initializer now stages all declared roots under one shared budget
and exclusive store borrow. It persists the metadata into a private candidate,
then runs the existing complete head-closure validator with store/head/checkpoint/
lane-bound availability before replacing the live store. Missing artifacts,
scope conflicts and budget exhaustion leave the original store unchanged.
The admitted filesystem slot now accepts the seal's metadata while ordinary
open/initialize/expose paths explicitly refuse its genesis checkpoint. Dedicated
initialization stages the roots and complete metadata before installing heads;
dedicated reopen audits persisted roots without promotion or reconstruction.
Exposure requires another persisted-closure check before the stable-lock marker
is committed. Existing admission, pinned-parent, lock and exposure checks are
shared, not replaced by a parallel storage engine. Materialization now accepts
this real genesis boundary through a distinct seal-bound entry point. Its
initial checkpoint retains the exact public Create management evidence; replay
loads persisted lane bytes, audits roots and retains their provenance. Initial
Merge roots are accepted only for the checkpoint selected by that authenticated
genesis seal; general Merge/fence execution remains refused. The pinned session
now connects this genesis boundary to incremental mutation staging, real
memory/file publication and suffix recovery. The compiled probe covers Linear
mutations and ACK markers on both Linear and Local lanes, including advanced
filesystem slot reopen, subsequent checkpoints with publication fault injection,
and bounded file GC. Recovery now freshly executes this signed probe against
persisted blocks. Production runtime/result integration and released-process
restart qualification remain next;
marker fixtures do not qualify runtime retention.
The seal derives an initial checkpoint referencing all four lane manifests and
the artifact closure, and initial heads referencing that checkpoint. The
canonical revision-zero head is retained as history; the first usable head is
its revision-one successor, because revision-zero heads forbid checkpoints.
Initialization must persist that predecessor and the complete closure before
exposing the successor, not expose a rootless intermediate head. Bare
genesis heads do not select those manifests and are not sufficient to keep the
initial block graph discoverable. These reuse existing record formats; the
memory and file initializers can publish them. Initial-only reopen validates
all roots, including Merge, against the exact admitted seal. General checkpoint
recovery/GC still requires integration: the older opt-in checkpoint recovery
only accepts external Linear/Local roots. Ordinary external
genesis remains closed; no production driver
is activated. Shared proposal generation also remains closed: its quorum
commitment must be independent of each replica's node-bound Local roots. Define
and verify that common-state projection before Shared finality integration;
do not share private block scopes merely to make replica proposals equal.
Verification: all 10 physical-host tests passed after the capture change
(`task-tmp/state-create-capture-final.log`); formatting and diff checks passed.
The negative binding test caught that canonical runtime work alone omits some
journal runtime-selection fields. Capture construction now rederives the full
initial work from the admitted package and exact replica rather than comparing
only the inner runtime work. Preparation verification is recorded in
`task-tmp/state-genesis-preparation-final.log`: invalid/expired receipts prevent
physical execution; foreign placement, exhausted gas and substituted capture
fail; successful preparation retains all three declared roots without writing
genesis/heads. Two physically executed Shared replicas have identical public
components and different Local roots; both refuse common proposal generation.
The first run exposed r19's empty-lane encoding check rejecting root descriptors.
That rule remains unchanged on r19; external preparation instead consumes the
physical capture's exact declared-lane validation. No generic lifecycle lane
permission was broadened. Full prototype/release gates were not rerun for these
preparation changes, and this remains a probe runtime, not production lifecycle
qualification.
Local seal follow-up: `task-tmp/state-genesis-seal-anchor-final.log` checks exact
root origins and lane-manifest codecs, replica mismatch refusal, all four
checkpoint lane references and the canonical predecessor/successor relationship.
The ordinary Local seal constructor explicitly rejects external prepared state;
the distinct root-bearing seal cannot enter ordinary initialization. These are
sealed record-construction checks; the later file qualification below adds
initialization/reopen evidence.
Memory initialization follow-up: `task-tmp/state-genesis-memory-init.log` covers
physical authenticated Create through sealed initialization, missing-package and
wrong-node refusal, aggregate fetch/byte exhaustion (including failure after
earlier lanes staged), unchanged live store on failure, exact checkpoint/history
publication and idempotent retry. Each persisted data root is independently
audited afterward, including Merge. This is not filesystem durability, released
lifecycle, or general external Merge recovery qualification.
File follow-up: `task-tmp/state-genesis-file-init-retry.log` covers actual admitted
initialization, faults after object durability/head staging/head durability,
unchanged read-only reopen, exact retry, budget refusal, successful exposure and
exposed reopen. Removing a persisted block causes refusal without reconstruction
from the Create capture. The first run found an initialization recovery assumption
limited to revision-zero heads; only the dedicated admitted path now accepts its
exact sealed revision-one initial stage. Ordinary recovery rules are unchanged.
This qualifies the synthetic probe's initial file closure, not a released runtime,
post-invocation recovery, Shared finality or power-loss testing.
Materialization follow-up checks exact restored state and all three root origins,
retained Create evidence, refusal without the seal or audit budget, and rejection
of another authenticated genesis. File replay after exposure preserves the file
snapshot. An initial common-path validation change overflowed the existing
Attested regression's debug stack; moving large seal temporaries to the dedicated
entry point restored default-stack test execution (no stack-size override).
Initial experimental checkpoints now include management evidence; old prototype
fixture stores must be regenerated, not silently reinterpreted as this boundary.
The shared Ordered/Local fixture covers:

- missing persisted execution blocks and missing predecessor branches;
- shared audit budgets, exact root origin, unchanged unrelated lanes and replica isolation;
- stale materialization, abandoned preparation and ordinary-path refusal;
- real memory checkpoint CAS and opt-in rematerialization;
- wrong-store/checkpoint binding, missing audited lane sets and swapped
  predecessor/successor lane-set refusal without head changes.

These tests use a simulated execution handoff and synthetic starting runtime/
checkpoint boundary. The fixture explicitly persists that boundary's historical
head because the real publication engine validates predecessor history; no
production validation was relaxed. They do not qualify authenticated runtime
upgrade, disk durability or released-binary recovery. Earlier preparation/audit/
suffix runs are superseded by this gate; their logs remain in `task-tmp/`.
The filesystem reopen regression uses a real admitted/exposed Local slot with
a synthetic external checkpoint boundary. Both Linear and Local roots are tested
as durable heads and interrupted `heads.next` stages. Ordinary open, exhausted
audit budget and missing/corrupt blocks refuse reopening; successful and failed
budgeted opens preserve the complete journal file snapshot, including stages.
This qualifies closure validation at reopen, not external checkpoint publication,
runtime upgrade, replay provenance or production route exposure. The follow-up
file-CAS test uses the real sealed publisher with test-only audited endpoint
binding. For both lane types it injects failure after immutable-object persistence,
head staging and durable-head replacement. Reopen preserves the crash snapshot;
exact retry advances only an unpublished head and removes a completed stage.
Ordinary publication still refuses these roots. The synthetic fixture must retain
its predecessor history just like real preparation; the initial `MissingObject`
failure exposed absent fixture history, not a reason to relax storage validation.
Focused test: 1 passed (1.35 seconds), `task-tmp/state-external-file-cas-retry.log`.
Changed-root follow-up: the existing Ordered/Local replay fixtures now seed an
admitted filesystem journal and publish through real `prepare_checkpoint`, the
non-Clone audited owner and the file publisher. Abandoning the audited owner
leaves heads unchanged. An injected `HeadsStaged` failure leaves the predecessor
selected; budgeted reopen retains the stage, and fresh preparation/audit commits
the same staged head. A second reopen rematerializes the exact changed state and
root-origin map. Only the starting checkpoint/runtime selection and execution
handoff remain synthetic; no production import API or synthetic successor seal
was added for this path. The fixture bridge is test-only.
GC follow-up extends both replay fixtures: abandon an audited preparation,
collect one obsolete file, reopen with the collection intent still pending, then
resume the bounded sweep. The old root block is removed; reopening and
rematerializing the published root still yields identical state and provenance,
and fresh preparation/audit/publication succeeds afterward. Zero-budget,
ordinary-GC, stale-head and staged-head refusals preserve the journal snapshot;
checkpoint preparation is blocked while collection is pending. This is a
maintenance GC/reopen regression, not power-loss or production load qualification.
Compiled probe follow-up: the ignored
`compiled_external_checkpoint_publication_reopen_and_gc` test passed (1.56
seconds, `task-tmp/state-physical-replay.log`). It executes the compiled PVM
through `execute_admitted_journal` with the exact signed package binding, checks
its candidate blocks against the native ActorRows update, then exercises suffix
replay, missing-block refusal, audited memory/file publication, interrupted head
staging, exact resume, rematerialization and bounded GC/reopen. The initial
runtime selection remains synthetic; the probe neither authenticates actor work
nor implements lifecycle/result retention. This is not released-binary or
production-executor qualification. The prototype recipe now includes ignored
replay tests after building the probe so this path cannot silently be skipped.
Remaining: released-runtime physical execution and production driver/lifecycle
integration, plus the existing Shared/release gates. Memory-store external GC
and portable external checkpoint backup/import remain closed.
The stricter error-code assertion initially expected `Corrupt` for a damaged
block. The existing reader intentionally maps backend integrity failures through
`TreeError::Storage` to `Unavailable`; the assertion now checks that mapping
without changing production behavior. Missing blocks remain `MissingObject`,
and exhausted audit budgets remain `LimitExceeded`.
The final focused regression passed (1.04 seconds):
`task-tmp/state-external-reopen-final-retry.log`. Formatting and diff checks pass.
The initial suffix integration exposed a default-test-stack overflow in the
attested-Merge regression; boxing the optional recovery genesis fixed it without
increasing stack limits (`state-suffix-replay.log`,
`state-suffix-replay-retry.log`).
Prior snapshot/Shared-claim metadata preservation: replay group 63 passed
(3.45 seconds), including the explicit-versus-opaque snapshot regression and
distinct Shared manifest identities over identical descriptor bytes. Logs:
`task-tmp/state-shared-root-claim.log` and `task-tmp/state-ordered-snapshot.log`.
Feature-off library check passed with the existing 264 warnings
(`task-tmp/state-snapshot-disabled.log`); changed-file formatting and diff checks
passed. These do not qualify external Shared publication or recovery.
Prior captured root-map advancement: replay group 62 passed (3.63 seconds),
including refusal of a missing capture under the external contract,
changed/retained Ordered roots and Local replica isolation. The ABI/semantics
pair codec regression passes both with and without the experimental feature
(the latter refuses the new pair). Logs:
`task-tmp/state-journal-contract.log`, `task-tmp/state-journal-contract-replay.log`
and `task-tmp/state-journal-contract-{codec,disabled}.log`. The compiled file-backed
regression rejects substitution of all six runtime identity fields before I/O.
These tests do not publish external-state heads or qualify lifecycle selection
of the experimental runtime.
Read-only persisted-execution verification: compiled guest regression passed
(1.14 seconds), then all 104 journal-store tests passed (15.54 seconds).
Missing candidate blocks are rejected without writes or cursor advancement;
after staging, verification advances to the exact candidate with unchanged files.
Zero-budget failure retains the base, and a no-change capture succeeds with no
reads. Logs: `task-tmp/state-persisted-replay.log` and
`task-tmp/state-persisted-replay-store.log`. Formatting and diff checks pass.
That run qualified the availability session method; suffix integration follows below.
Prior persisted-manifest availability audit: all 104 journal-store tests pass
(16.30 seconds), including the compiled file-backed guest and final manifest
reopen/no-op check. Negative cases cover zero block budget, opaque declarations,
foreign genesis, altered origin, missing descriptor bytes and missing descendants.
Logs: `task-tmp/state-manifest-audit.log` and
`task-tmp/state-manifest-audit-store-retry.log`. The first full run had 103 passes
and a fixture-opener failure (`task-tmp/state-manifest-audit-store.log`): the
production opener correctly refused the fixture's absent Authority foundation.
The corrected test-only opener preserves exact admitted Agent/replica identity;
no production admission check was relaxed. Formatting and diff checks pass.
Current root-map evidence: `task-tmp/state-root-advance.log`; all 104 journal-store
tests pass (15.54 seconds), including the compiled signed execution/staging
fixture (`task-tmp/state-root-advance-store.log`). The nonexperimental library
check passes with the existing 264 warnings (`task-tmp/state-root-advance-disabled.log`).
Captured changed roots, undeclared/stale bases, stripped captures and no-op
origin retention are exercised. Existing opaque checkpoint
reopen/retirement tests pass; ordinary external checkpoint recovery still refuses.
The opt-in path supports budgeted checkpoint plus Ordered/Local suffix recovery;
publication, Merge/fence and Shared/reverified recovery remain gated.
After shared outcome checks, Local journal-driver group 33 passed
(37.32 seconds), including
the physical current-ABI custom-runtime create/manage/restart/retry test.
New regressions preserve exact Direct/Attested invocation bytes, retained Resume
identity/continuation and ACK authorization, and reject mismatched or undeclared
external-root manifests. The nonexperimental VOS library check passed again;
existing unrelated warnings remain. These are mapping/integration prerequisites,
not qualification of external-root replay publication.
The journal request regression also executes an assembler guest response
through the raw physical frame adapter, constructs a semantic handoff, and feeds
it to a real replay step using a test executor. Its embedded response makes a
self-consistent declared program hash circular, so the full journal adapter
correctly rejects this assembler fixture; only the compiled guest qualifies
that program-bound path. The capture is consumed once; substituted input ID,
prior-state commitment, journal position and accepted transition are rejected.
The step fails the side-product publication gate until availability is integrated.
Wrong next position is refused before loading the guest; a frame-valid Control mutation
on a Linear request is refused by replay. Retained continuation sequence and
program substitutions and ACK work/authorization substitutions are rejected.
This is not yet the compiled row guest through authoritative replay publication.
Journal-backed staging test passed: wrong operation binding leaves the directory
unchanged; exact retry creates no blocks; reopening preserves chunked values;
foreign scope and on-disk corruption fail closed; no head is published. The
initial run caught a missing experimental directory allowlist entry on reopen;
both directory-validation paths now share the same child-name list. Full journal
store suite including the compiled file-backed test: 104 passed,
0 failed, 0 ignored (16.13 seconds), including exact compiled program binding,
substitution refusal, capture-bound staging, stale-base
refusal and the compiled same-value no-op. Journal codec/identity suite: 41 passed
at the preceding manifest change.
Two new context tests cover pre-admission/initial-cursor equality, changed final
admission IDs, distinct authority sequences, Local replica isolation, malformed
cursors and runtime-upgrade binding with stable storage scope. These exercise
canonical fixture inputs, not signature verification or live finality.
The manifest/marker regression verifies exact reachable blocks, unmarked obsolete
blocks, missing-child refusal, root-producing cursor binding, mark limits, explicit
descriptor declaration versus opaque bytes, codec roundtrip/trailing refusal,
and the continued publication gate. No test publishes an external-state head;
publication-time availability and end-to-end GC/recovery remain open.
Provenance tests retain identical descriptor bytes through later Ordered/Local
projection positions and a changed current runtime binding. They reject future
origins, same-height conflicting heads and foreign runtime identity. Maintenance
marking accepts a retained root at a later projection and rejects a substituted
origin. This proves codec/binding behavior, not replay ancestry or published-head
retry/no-op recovery; those gates remain open.
The exclusive staging regression advances 32 data roots after one base audit,
checks stale-candidate rejection and retained read access, and requires a new
audit after relinquishing the store borrow. It does not publish journal heads.
The compiled journal write/reopen regression now runs a canonical journal Invoke
through signed package admission, the admitted physical journal adapter and
ordinary replay transition validation before immutable staging and reopened
row reads. It uses a synthetic post-upgrade projection over a test-admitted
genesis; the selected runtime is package-authenticated, but its lifecycle
selection and Agent creation are not executed by this fixture. Native and compiled
candidate blocks/roots agree exactly. A separate physical boundary regression passed:
wrong-work response rejection and wrong-scope refusal before program loading or
storage access. The latest full prototype gate includes that boundary test.
This is process reopen and tamper coverage, not power-loss/quorum qualification.
Nonexperimental VOS check (`agent-runtime storage network http-ingress`) passed;
changed-file formatting and diff checks passed. Existing unrelated warnings
remain; the SDK library's targeted Clippy gate is warning-free.
Refine host group: 11 passed. Full PVM runtime library:
263 passed, 0 failed, 2 ignored (0.47 seconds). Tree tests cover mixed
operations against a reference map, canonical roots, historical roots, empty
values, missing/corrupt/foreign/misplaced blocks, codec refusals, no-op updates,
budget exhaustion and a 257-node adversarial path. Feature-enabled SDK library
Clippy passed with `-D warnings`. Tests use the pinned toolchain and disk-backed
target/scratch directories described below.
PVM `--no-default-features` library check passed with four existing dead-code
warnings outside the changed Refine host module; these were not suppressed.
Physical host group including typed admitted execution and the compiled
100,000-row growth regression: 8 passed, 0 failed, 0 ignored (8.15 seconds
including native fixture setup).
Compiled replacement/deletion candidates match native SDK roots and blocks.
The existing snapshot, missing/corrupt data, scope, exact-response, gas and
output-budget checks also pass, including guest rejection of stale bytes when
host verification is deliberately bypassed. A 64-KiB row uses 14 fetches /
66,945 bytes; the growth test below deliberately holds values to four bytes.

Fixed replacement results (in-memory provider, debug host, compiled guest):

| Retained rows | Guest read / emitted blocks | Read / emitted bytes | Reuse-verification blocks / bytes |
| ---: | ---: | ---: | ---: |
| 16 | 3 / 3 | 342 / 342 | 5 / 555 |
| 256 | 9 / 9 | 1,008 / 1,008 | 44 / 4,921 |
| 4,096 | 13 / 13 | 1,452 / 1,452 | 90 / 9,990 |
| 100,000 | 18 / 18 | 2,007 / 2,007 | 170 / 18,933 |

Lookup and deletion pass at all four sizes too. Guest gas for replacement grows
from 13,201,582 to 15,933,736, including initialization and provisional fetch gas.
Diagnostic phase timings separate roughly 22–26 ms program loading from roughly
1–6 ms execution in this run. This identifies preparation/initialization as the
largest measured phase of this fixture; it does not distinguish parsing, table
preparation and memory initialization within loading. Incremental verification
still rereads shared prefixes (170 fetches at 100,000 rows); it does not scan the
retained dataset. No caching change is justified solely by these debug timings.
Log: disk-backed target `task-tmp/state-physical-growth.log`.

These checks establish path-sized fixed-row work, not Clerk multi-row cost,
guest allocation high-water, filesystem durability, quorum or serving capacity.
Native setup and ELF linking are excluded from operation timings; PVM loading is
included and reported separately. Reproduce the complete prototype gate with:

```sh
just test-agent-state-prototype
```

This recipe rebuilds the guest and runs the feature-enabled SDK, feature-off
contract/package tests, actor-storage and non-ignored inner-execution tests with/without
the experimental feature, package admission, replay, ABI-pair codec checks with/without the
feature, physical host group, and journal-store group
including its ignored-by-default compiled file-backed test. It does
not replace released Local/Shared recovery, quorum or production load gates.

Changed Rust formatting and `git diff --check` passed. The separately selected
100,000-row release-mode probe passed again after chunking in 3.25 seconds (whole fixture build plus
checks, not per-operation latency). Run it with:

```sh
cargo +nightly-2025-05-09 test --offline --locked --release -p vos-agent-sdk \
  hundred_thousand_row_growth_probe -- --ignored --nocapture
```

Fixed four-byte-value lookup/update probe (native SDK, not PVM/Clerk):

| Retained rows | Read blocks / bytes | New blocks / bytes |
| --- | --- | --- |
| 16 | 4 / 378 | 4 / 381 |
| 256 | 9 / 933 | 9 / 936 |
| 4,096 | 14 / 1,488 | 14 / 1,491 |
| 100,000 | 18 / 1,932 | 18 / 1,935 |

These are deterministic data-work counts for one selected key. They do not
include Clerk's own Merkle operations, authentication, quorum or durability.
Runtime limits, bundled artifacts and production behavior are unchanged. The
experimental SDK block primitive now reaches prototype journal staging,
checkpoint publication/recovery and authenticated in-memory genesis initialization.
The prototype also covers admitted filesystem initial-genesis crash/retry and
reopen. A pinned session now connects actual genesis to Linear/Local mutation
and ACK-marker publication, suffix replay and subsequent checkpoints on memory/file
stores, plus bounded file GC. Advanced slot reopening validates actual/staged
suffixes and checkpoint successors read-only. None of this activates production
runtime dispatch or qualifies production retained-result semantics.

## Artifact and test boundaries

`support/production-artifacts.toml` and `vosx/build.rs` own the exact pins.
Runtime source `2ccfacb82089f804dbdbfea7ebfcabf377e7dde3`, ABI r19;
template source `c5e751e7bc7992782bf7403f73b254c64e5c26c6`;
builder `3c5e44c769d4cc16c1c13a9949c60a154f378a57`.
No artifact changes are part of this capacity investigation.

Use `cargo +nightly-2025-05-09`, offline/locked, with disk-backed
`CARGO_TARGET_DIR=.worktrees/ch08-c2-native/target` and its `task-tmp`
directory for `TMPDIR` (absolute paths when running inside a worktree).
Do not use RAM-backed `/tmp`. Rebuild the custom guest with
`just build-agent-recovery-fixture` before physical custom-runtime tests.
Socket-restricted failures are not passing network evidence.
Full physical gates use `just test-shared-agent-publication`; native-outer
tests do not substitute for it. Broad Clippy at `ac1b2860` had 358 diagnostics,
including 279 unused items; keep unrelated cleanup out of this release.

## Deferred backlog and housekeeping

Deferred: Private/Attested production, proof production, bridge/federation/
settlement, dynamic membership, old-store migration, generic runtime unification
and generic redesign beyond the bounded storage workstream above. Keep existing
regression coverage without claiming production support.

No automatic expansion to every profile, every fault matrix or thousands-active-
user qualification. Local/Shared correctness, customer capacity and backup remain
mandatory. Update this document as the single live plan; other handoffs are
checkpoint evidence/navigation. Prior full chronology is in Git at `efd0f5ca`,
`42928ddc` and `7bae9269`. Preserve failure evidence and remove obsolete code
only after checking callers, feature gates and replacement coverage.
