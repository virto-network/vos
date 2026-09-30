# Agent saga: v1 release checklist

This is the single live plan. [Review instructions and checkpoint evidence](agent-saga-review.md)
are the sole reviewer entry point. History is in Git, not a parallel set of plans.
A passing internal checkpoint is not a release. No completion percentage or
release date is established.

## Finish line and current position

The approved target is a usable **Linux x86-64, fixed authenticated three-node
Shared deployment**, production **image-based Local Agents**, and one Shared
Clerk with **100,000 retained transfers**. Keep Clerk's kernel, signatures,
committed roots and exact retry semantics. Do not replace this with a singleton,
smaller dataset or an experimental-only release without a new user decision.

The review-fix checkpoint is `6c1bab2a..saga/agents`. It addresses repeated-input
evidence/retry admission and expired unadmitted registration, including a
catch-up barrier race exposed by qualification. `wip/ch08-runtime-directory` and
`saga/agents` share this checkpoint; verify the heads before review. This is
**one scoped review-fix batch**, not production startup or service qualification.
Preceding signed read delegation is `6d2a9b38`; Shared journal/applied availability
is `7c1a1b7c`; backend follow-up `4ea0271c`, pruning
`48df3995`, and admission baseline `62ffbc20` retain their
historical evidence. Findings continue on the implementation branch before a
qualified fast-forward. `master` is unchanged; do not push or change it automatically.

Status vocabulary: **implemented** means source and focused tests exist;
**integrated** means the supported workflow selects it; **qualified** means its
specified acceptance test passes on the actual release. These are not synonyms.

Current evidence, without promoting production startup or changing the finish line:

- Independent review reproduced a recompiler gas-parity bug when re-invoking
  a terminal inner machine. The reviewed fix preserves reference funding;
  276 PVM tests and 20 vectors pass, plus the no-default-features check.
- The normal custom-linear guest now has 36 exact-input backend comparisons
  across Local/Shared lifecycle, retained results, retries and scheduling.
  This closes the missing custom-layout test coverage, not service qualification.
- Shared external integration uses the existing signed Linear-only runtime
  capabilities. Physical Create/Clerk Install produce identical state on three
  replica identities without normalizing node-local roots or changing the ABI.
  The internal journal now passes Create/Install/Invoke, lost-response reopen,
  ACK/reopen and missing-block refusal across three independent file owners.
  This uses committed-slot fixtures, not three released daemons or Clerk transfers.
- Transport result delivery now requires exact applied availability on a voter
  majority, with an independent bounded request pool. External blocks are durable
  before head publication; detected missing data invalidates the serving pin.
  The external driver and transport are not yet joined through public startup.
- Review-driven fixes align physical preview with committed replay, retain exact
  declared Merge-root fencing, cover legal suffix recovery budgets, and preserve
  singleton-image snapshot retries. These are correctness fixes, not throughput
  evidence. Direct external operations currently execute preview plus application.
- The user-approved scoped, expiring signed read delegation (2026-09-29) binds
  the query to its generation, committee and original preflight slot; unseen
  admission independently checks the current trusted clock. Candidate physical
  tests now complete a pre-Invoke read with its original attesting Network shut
  down, preserve both reopen orderings, and refuse invalid delegation/generic
  ingress bypasses. Legacy reads remain committed-only and byte-compatible.
  This is an opt-in candidate path, not automatic production read delegation.
- Expired, unseen pending reads stay fail-closed. The `6d2a9b38` survivor fixture
  receives the frozen query from its harness; the current custody batch adds
  replicated discovery after registration is applied. Origin loss before that
  admission and safe terminal resolution remain limitations. Production stays gated.
- Common snapshot votes bind the same shared Ordered state, committee, epoch
  and exact semantic ancestry. Each node separately signs its own physical
  checkpoint binding. Existing AGS3/AGP1 formats keep their meaning; no foreign
  node/store claim is treated as a local publication capability.
- Candidate catch-up derives destination-local state from admitted genesis,
  preserves higher Raft term/full NodeId vote, rejects changed or speculative
  cached membership and rollback, and refuses any unknown log suffix beyond its
  target. The healthy fixed-three physical workflow and three source/destination
  crash-boundary fixtures pass: pruned-prefix catch-up, exact boundary Query
  retry/ACK, reopen and continued common ordering with mixed checkpoint cadence.
  These are candidate fixtures, not released-daemon qualification.
  Physical compaction/catch-up entrypoints remain
  test-only: a local "no pending work" check cannot protect an offline origin's
  unresolved after-ACK PAP2. Boundary-only Query recovery is not evidence of
  arbitrary historical reply retention. Production pruning stays disabled until
  all pending scopes have qualified recovery evidence, not only delegated reads.

Custody retains at most one recovery slot per physical owner in the
fixed-three committee, not per query attestor. Registration retains
the exact signed request and original work/preflight in the existing Raft log
before claiming recoverable admission. Physically verified terminal Invoke and
positive ACK evidence enrich the slot; common checkpoints bind and carry it.
Forwarding followers also need a delivery obligation because their original
response can otherwise disappear after the leader's local cleanup. An owner
may replace only its own completed slot, using a signed monotonic sequence after
its prior PAP2 is durably clear. Keep the last completed slot until replacement,
avoiding a separate release round on every read while retaining a fixed bound.
This adds one registration round for Authority reads, not ordinary actor calls.
The local PAP2 write is a registration intent, not recoverable admission: an
origin lost before quorum registration can still leave a request undiscoverable
to survivors. This slice conservatively admits one distinct unfinished delegated
read per system Agent; separate owner holds for that exact read share its result.
Recovery may finish an admitted read directly from shared custody while retaining
a different, unadmitted local intent unchanged. Neither path relaxes execution
authorization or treats a registration signature as proof of its result.
This batch adds no guest ABI or private-state decoding. Delegation expiry is never
permission to drop evidence; expired-unseen cancellation and unsupported
management/legacy obligations remain explicit pruning gates until qualified.

Final-source optimized evidence: 278 focused tests pass with four existing
ignored, plus 11 physical cases (two new review regressions, eight delegation/
compatibility cases and follower delivery across checkpoints/reopen). Seven
other checkpoint/custody cases passed immediately before the final barrier-race
correction; they are earlier-source evidence, not a full final-source 18-case
rerun. CLI 300 active tests, two daemon smoke tests and supported feature checks
also pass. A late first custody slot is refused after an exact legacy Invoke or
positive ACK. A racing signed intent remains unchanged
while exact legacy recovery finishes, and clears only after proven positive ACK.
These fixtures use the native clean-runtime test adapter around physical Authority
execution; full outer-PVM and released-daemon qualification remain separate gates.

The follow-up preserves the first terminal Invoke and first positive ACK while
checking physical replay by exact Ordered position, not the latest input cache.
Later valid repeated inputs cannot replace canonical custody or its response;
negative ACK rows do not release it. Same-key reservation and already-reserved
submission both recheck the committed/applied prefix. A fresh post-drain worker
sample distinguishes legitimate catch-up from a contradictory stable cursor;
changed samples return retryable unavailability without releasing the reservation.
New registration requires fresh delegation or exact retained execution evidence
before append/reservation
mutation; retrying an existing admitted registration remains idempotent.
No guest format, artifact or execution-authority change is included.

This prevents a second immutable Ordered entry from being proposed behind an
unresolved append. It does not repair old raw logs already containing the same
immutable entry at two Raft positions: those violate the existing physical
publication binding and must still fail closed. Valid repeated inputs use new
Ordered entries. Keep this distinction explicit in reviewer evidence.

Next scoped step: qualify reconciliation when a registration append times out
and is later overwritten before commitment. The coordinator conservatively retains its exact
volatile projection exclusion; without an owner retry, reattachment may be needed
to release that exclusion. This is a liveness limitation of an unadmitted intent,
not evidence that an admitted request or result was lost. The current policy unit
tests establish retained exclusion, not a physical append-overwrite recovery test.

No finish-line change follows from these results. The remaining work stays in
the three batches below; do not add a parallel plan or treat these as a release.

| Area | Current checkpoint evidence | Remaining release boundary |
| --- | --- | --- |
| Admission and recovery | Baseline `62ffbc20` binds complete imported-plan certification and rejects unsupported rosters before writes; mixed-generation recovery P1 resolved | Review checkpoint findings; remaining three-node crash boundaries |
| Fixed three-node bootstrap | Baseline common certified genesis, physical startup/reopen and post-Invoke leader-loss fixtures pass | Production startup remains gated; actual three-process daemon/HTTP qualification is pending |
| Local execution | Image path retained; final default/reference Local suites and actual default-selected image daemon pass; public external Local removed | Exact-release performance, recovery and backup qualification |
| External actor storage | Internal fixed-three-voter Linear-only Shared executor/finality and three-file Clerk query/recovery slice pass; prior Local Clerk transfer fixture passes on both backends | Public Shared owner/startup/route integration, network availability/catch-up, retained growth, reclamation and export |
| VM backend | Outer/inner recompiler integrated; Linux x86-64 Agent default and explicit interpreter pass focused differential/physical checks; bounded preparation caches and post-cache phase measurements recorded; custom-runtime differential and terminal-reuse fix pass | Exact-release resource/cold-warm qualification and service capacity |
| Customer workflow | Ordinary Shared production finality and public management are unavailable | Released Shared Create/Install/Invoke, Shared Clerk and usable CLI orchestration |
| Operations | Historical source-specific tests exist; current backup is registry-only | Load, overload, failover, Agent backup/restore, soak and reproducible release artifacts |

## Batch 1 — Simplify and qualify the recompiler

Checkpoint `48df3995` implements pruning and outer/inner recompiler integration, with
focused differential, physical lifecycle, Clerk and feature-build evidence.
Agent execution now selects the recompiler by default on Linux x86-64, with an
explicit interpreter override. Final focused default/reference, CLI and actual
image-daemon checks pass; this is scoped checkpoint evidence, not a release.
Initial optimized phase measurements show real but bounded gains; exact-release
and cold/warm customer-workflow qualification remain open. See the [candidate evidence](agent-saga-review.md).

- [x] Establish the tested `62ffbc20` review-fix baseline on `saga/agents` before
  promoting later changes. Retain this commit as the recovery reference for pruning.
- [x] Consolidate the live plan and reviewer entry; remove redundant navigation
  documents and historical chronology. Preserve the [recovery contract](agent-recovery-contract.md).
- [x] Remove saga-added Private host/storage/synchronization implementations and
  Agent Attested proof-production adapters, including exclusive configuration,
  routing and tests. Unsupported profiles must fail before durable writes.
  Preserve canonical wire types/commitments, Shared enrollment cryptography,
  runtime-independent validation and the existing PVM/prover. Do not remove
  legacy service paths still used by the registry or extensions.
- [x] Retain experimental external-Local machinery only where it qualifies
  storage needed by Shared; remove unsupported user-facing experimental entrypoints.
  Production Local stays image-based; no mixed-format or in-place migration.
- [x] Record the removed capabilities and recovery commit, separating production
  source, tests and documentation reductions. Do not infer complexity reduction
  from aggregate line counts that include large inline test modules.
- [ ] Measure optimized cold/warm Authority Query/ACK, actor invocation and Clerk
  transfer. Separate preparation, outer VM, inner VM, persistence, queue and quorum
  costs. Synthetic instruction loops and whole-fixture times are not this evidence.
  Bundled lifecycle and post-cache Authority/Clerk method measurements pass on
  both backends, including full Clerk recovery. Shared queue/quorum attribution
  remains open; fixture times are not service qualification.
- [x] Thread the existing `PvmBackend` through Refine, outer execution first and
  then inner execution. Reuse the existing recompiler; do not introduce a new VM.
  Bound immutable compiled preparation; key caches by program and execution
  semantics; allocate fresh invocation memory.
- [x] Run focused PVM/SDK and interpreter/native parity checks, image Local
  lifecycle, opaque custom-runtime recovery, and physical external-state Clerk
  with rebuilt candidate guests. These qualify the tested slices, not the release.
- [x] Select the recompiler by default for Linux x86-64 Agent execution,
  retaining explicit interpreter and tracing/reference execution. Keep gas,
  authorization, signed artifact identities and persistence semantics unchanged.
  Compilation failure is explicit; never silently retry an execution fault with
  another backend.
  Default/reference host suites and default-selected CLI/daemon checks pass;
  exact-release resource and service qualification remain mandatory.
- [x] Differentially compare outputs, gas, PC/registers, exits/faults, memory
  permissions, host-call suspension/resume and commitments, including standard
  and genuinely different custom-runtime layouts. Run physical lifecycle/recovery
  tests and supported feature builds after pruning and backend changes.
  Exact standard-runtime comparisons and both custom-runtime physical suites pass.
  The continuation adds 36 exact custom-runtime comparisons; core feature checks,
  CLI build and focused integrated host reruns pass. The final released-artifact
  matrix remains a batch 3 gate.

Exit: a scoped, tested checkpoint with actual phase timings. Recompiler speedups
do not by themselves qualify Shared capacity or eliminate whole-runtime work.

## Batch 2 — Complete the customer workflow

- [ ] Complete fixed-roster common authenticated genesis and production Shared
  finality. Never represent three singleton lineages as one replicated Space.
  Keep unsupported production paths gated until their admission/recovery is proved.
- [ ] Qualify leader loss before Invoke commit and the remaining ACK/metadata-clear
  crash matrix. Preserve exact retry, fresh authorization, reservation ownership
  and unpublished recovery. The current candidate custody/checkpoint/delegation
  follow-up passes 11 final-source optimized fixtures, including both new review
  regressions, follower delivery and all eight delegation/compatibility cases.
  Seven additional checkpoint/custody cases are explicitly earlier-source
  evidence. This does not qualify all pending scopes, full outer-PVM execution
  or production startup.
  Signed delegation is an explicit candidate-only opt-in: legacy authenticators
  still emit ordinary reads. Delegated SSH attestors must be current voters with
  authenticated committee keys. Applied custody now retains delegated signed
  requests for offline-origin discovery. Finish expired-unseen terminal resolution
  and qualify every pending scope before production; neither local absence nor
  a timeout releases PAP2.
- [ ] Collect quorum-certified snapshots/checkpoints and qualify restart/catch-up
  before replay capacity is exhausted. Optional checkpoint skipping is temporary;
  mandatory capacity/certificate guards must continue to fail closed.
  Use a common-state QC plus a separately signed physical node/store binding;
  collecting signatures over different local claims is not a quorum certificate.
  Preserve semantic ancestry independently of physical checkpoint cadence.
  The candidate image path now passes pruned-prefix catch-up, exact boundary
  lost-response retry, reopen, continued ordering and source/destination marker,
  journal and ledger interruption tests. Mutation remains test-only
  until **all** pending recovery scopes survive retirement, including an offline
  origin's after-ACK PAP2. Do not replace that gate with a local absence check or
  weaken exact retry. External block-root closure/export remains a separate
  integration gate; image catch-up does not qualify the 100,000-transfer workload.
- [ ] Integrate the existing external-state executor and block store into Shared
  Clerk through a narrow internal executor selection, not a new driver framework.
  The internal driver now supports signed Linear-only Shared Create/Install,
  completed Direct Linear/LinearizableQuery and ACK. Public filesystem-owner
  startup, lifecycle and route selection still use the image path; this is not
  a CLI-only cutover. Control Query, Resume, yield, timers and Attested execution
  remain unsupported on this external Shared slice, not on the generic SDK.
- [ ] Prove durable, available blocks before acknowledging their roots/results
  under Shared quorum rules, including missing blocks, minority failure and
  catch-up. Preserve provenance, exact predecessor checks and retry atomicity.
  Missing data is unavailable state, never an absent row or successful execution.
  Local file-owner and authenticated transport checks pass independently; the
  integrated external network/minority/catch-up workflow is still required.
- [ ] Bound reclamation and root-pinned export. Retain authoritative, pending,
  checkpoint, retry/recovery and backup roots. Maintenance-window reclamation is
  acceptable; unbounded historical retention is not. Use public block closure
  traversal, not host decoding of private runtime/actor state. Full import/recovery
  audits must not become ordinary-request whole-state scans.
- [ ] Expose public Shared Create/Install/Invoke with resumable, schema-aware CLI
  commands using existing management/request mechanisms. Preserve signed terminal
  failure finality and exact request identities.
- [ ] Verify first-use Space UX: bundled packages prepared automatically,
  authenticated HTTP/SSH defaults, system actors installed before readiness.
  User-created arbitrary Agents are not automatically provisioned.
- [ ] Promote a coherent reproducible artifact set with an explicit signed
  external-state contract and fresh external roots. Do not reinterpret image
  Local roots or silently enable an experimental ABI.
- [ ] Qualify actual three-process released-binary lifecycle and Shared Clerk:
  create/install/invoke, growing retained data, lost responses, restart and failover.
  No test signers, hand-edited journals or environment-only candidate artifacts.

Exit: one integrated customer workflow, not another collection of isolated
storage tests. The image format's 16,384-row ceiling cannot contain the approved
dataset: Clerk's retained transfers alone need approximately 200,000 rows.
Do not hide that requirement by discarding history, raising one codec limit or
sharding the customer's ledger without approval.

## Batch 3 — Measure, recover and release

User decision (2026-09-29): prepare reproducible deployment/load-test tooling;
the three external test nodes will be provided later. Continue local three-process
integration checks meanwhile. Tooling preparation and local results do not close
the hardware, load or soak gates below; no remote deployment is authorized by
this choice. Scoped signed-read recovery delegation was approved separately;
its implementation and qualification remain in batch 2.

- [ ] Prepare inventory/artifact preflight, a signed Clerk corpus/reference
  generator and a bounded public-API load runner using existing release packaging
  and lifecycle evidence collection. Do not revive the retired acceptance API.
  Execution must remain explicitly blocked until public Shared startup/lifecycle,
  external ownership and retention prerequisites pass. The native 100k-row probe
  is not a corpus of 100k signed Clerk transfers or a service load result.
- [ ] Run the exact release under the acceptance envelope below. Permit **at most
  two measured tuning passes after backend integration**. After two failed passes,
  stop for an evidence-backed scope/architecture decision; do not silently lower
  targets or start another workstream. Stop tuning when the agreed gates pass.
- [ ] Implement maintenance-window Agent backup/restore: drain admissions, capture
  authenticated Shared state, validated opaque Local exports and lifecycle/retry
  state. Keep keys separate; restore matching identities and binary/artifact
  versions; retain replaced destinations. Raw directory copies are not a guarantee.
- [ ] Qualify overload, partitions/minority refusal, leader loss, catch-up,
  interrupted lifecycle, full restart and restore with release binaries.
- [ ] Reproduce final artifacts; run full outer-PVM, supported feature/CLI tests,
  formatting and targeted lint. Update operator instructions to match supported
  behavior. Do not mix unrelated repository-wide lint cleanup into this batch.
- [ ] Review the final checkpoint with no release-blocking correctness findings
  and recorded evidence for every mandatory gate. Prepare the merge to `master`;
  production deployment/data cutover still requires operator approval.

## Mandatory acceptance envelope

These are approved targets, not measured capacity or an availability promise.

- Three separate Linux x86-64 **8-vCPU / 16-GiB / SSD** nodes; inter-node RTT
  at most **5 ms**.
- **300 continuously active clients**, **80% reads / 20% signed mutations**
  against one Shared Clerk, with unrelated Local/Shared activity. End-to-end
  **p95 <= 1 s, p99 <= 2 s**, including queues and retries.
- **1,000 accounts and 100,000 retained transfers**, growing through a
  **30-minute load run** and **24-hour lower-rate retention soak**. Measure
  write-only bursts separately.
- **Failover <= 30 s**; no acknowledged loss, duplicate effects, unauthorized
  access or false completion. Stable retries across restart/failover; minority
  cannot commit.
- Bounded memory, descriptors, queues, retained results and disk retention under
  overload. Use realistic backend credentials; multiplying credentials or queues
  must not manufacture apparent throughput.
- Backup/restore preserves committed roots, identities, Local state and exact
  retry behavior. Interpreter/recompiler differential gates from batch 1 remain
  mandatory through artifact promotion.

## Shortcomings to track without expanding scope

- Exploratory `vos --no-default-features --features 'std storage'` currently
  fails because Shared-host route-audit methods refer to network-gated adapter
  types/functions. The affected code is unchanged from `7c850160`; this is a
  pre-existing embedding-feature defect, not a regression from pending custody.
  The approved v1 host/CLI includes networking. Keep this extra combination
  explicitly unqualified and repair its feature boundary separately.
- Incremental actor rows do not eliminate whole-runtime control-state transport,
  directory reconstruction/publication or Shared ordering/locking. Measure their
  actual cost; the release does not promise every operation scales with touched data.
- External Shared preview uses the same physical response validator and read/reuse
  budget as application, preventing deterministic invalid-output admission.
  It currently repeats execution for Install/Invoke/ACK; measure that cost before
  optimizing. Recovery budgets cover the legal bounded suffix, not a qualified
  recovery-time target. Historical roots remain pinned until certified snapshots,
  reclamation and export are implemented; this cannot qualify unbounded retention.
- Qualify sustained minority load: unused requests to a silent voter retain
  availability permits until transport completion/timeout even after another
  voter establishes quorum. Idle-loopback progress is not load qualification.
- Pending-read custody has a fixed three-owner bound, but includes complete
  signed work/artifacts and public evidence (declared manifest ceiling about
  14.8 MiB). Canonical decoding, signature checks and evidence validation are
  still real control-path costs. Candidate debug-test timings are not release
  latency evidence; measure the exact optimized workflow before claiming capacity.
  Qualification exposed two concrete costs: manifest preparation holding the
  database writer needed by Raft heartbeats, and repeated proof construction
  consuming the availability deadline before peer confirmation. The scoped fixes
  prepare manifests before the writer with exact atomic predecessor checks,
  reuse one freshly audited view within each proof call, and skip locking for
  empty Merge advertisements. Validation after peer I/O stays fresh; nonempty import,
  durability, authorization and deadline guards remain unchanged.
  Focused corruption/interleaving tests and all four new exact-release custody
  fixtures pass after call-local proof reuse and a startup-auto-cleanup fixture
  correction. The legacy after-Invoke compatibility regression and racing signed
  intents are covered by the final eight passing delegation fixtures. Measurements
  and reproduction live in the review guide; these candidate recovery tests do not
  qualify service capacity or the remaining production recovery scopes.
- Expiry after custody admission remains unresolved; a remote owner's unfinished
  registration also retains the leader's projection reservation until positive
  ACK. Expiry never authorizes execution of unseen work or discarding custody.
  Legacy/mixed-version stale intents can outlive all owner replacements and
  pruning; retained-history legacy checks alone cannot prevent such an old read
  from registering again. Keep this with the legacy pending-scope pruning gate.
  A registration reply can time out while its append later applies; exact retry
  reconciles it. None of these limits is closed by refusing expired new admission.
- Native full-memory snapshots and cloning still scale with the guest address
  span, not touched pages, and can materialize a large flat image. Sparse snapshot
  behavior must not be assumed for the native mapping. Instruction attribution
  explicitly selects interpreter plus sparse memory; qualify native memory before
  claiming production concurrency.
- Inner preparation now retains one immutable exact program per worker, with a
  2-MiB input-program admission ceiling and explicit backend identity. Larger or
  unresolved-default programs bypass caching; invocation state is never retained.
  Native code/tables add memory beyond those input bytes. Post-cache native
  observations distinguish first/second-query preparation; old overlapped-build
  totals must not be compared as a controlled cache-effect measurement.
- Bound guest cumulative allocation as well as live memory: the portable guest's
  one-shot allocator does not reuse freed arena space. Fixed one-row/100,000-row
  tree probes do not establish real Clerk multi-row or quorum capacity.
- External state uses bounded values/blocks and hashed row keys, not ordered
  prefix scans. Keep collection-owned indexes. Partial chunk reuse, shared-path
  optimization and actor-removal indexing require measured need or separate scope;
  never substitute an unbounded Agent scan. Keep initial control/directory caps explicit.
- Freeze external-fetch gas/resource tariffs with the admitted ABI. The compiler's
  handling of unrecognized host-ID construction remains a follow-up; the current
  experimental ABI's explicit immediate host ID is not a general compiler fix.
- General Private/Attested production, proof production for external reads,
  bridge/federation/settlement, dynamic-membership orchestration, old-store migration,
  public external Local, automatic sharding, online GC, broad runtime unification,
  ARM64 production and thousands-active-client qualification are deferred.
  Deferred does not mean silently supported, nor permission to remove shared
  protocol validation or the existing prover.

## Evidence and working rules

The [review guide](agent-saga-review.md) records the tested `62ffbc20` fixes,
candidate fixture limitations and reproducible commands. Artifact identities
come from `support/production-artifacts.toml` and `vosx/build.rs`, not this plan.
Released image ABI remains r19; SAC6 Authority is a candidate, not a repinned release.

Use offline/locked `cargo +nightly-2025-05-09`. Put builds, test stores and logs in
the disk-backed `.worktrees/ch08-c2-native/target`, using absolute paths inside
worktrees and its existing `task-tmp` directory for `TMPDIR`/`JUST_TEMPDIR`.
Never use RAM-backed `/tmp`. Preserve frozen clients, failure evidence and stores;
do not mix generations or treat socket-restricted/ignored/zero-selected tests as passes.

The full pre-consolidation chronology and removed handoffs are recoverable with
`git show 62ffbc20:docs/agent-saga-status.md` (or the original document path).
Historical source-specific timings/test counts are not qualification of today's
release. Record new checkpoint evidence in the review guide and update this
checklist; do not grow a second chronological plan.
