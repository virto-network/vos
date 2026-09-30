# Agent saga: v1 release checklist

This is the single live plan. [The review guide](agent-saga-review.md) is the
sole reviewer entry point. Historical evidence lives in Git, not parallel plans.
A passing internal checkpoint is not a release; no completion percentage or
release date is established.

## Approved finish line and current position

A usable **Linux x86-64, fixed authenticated three-node Shared deployment**,
production **image-based Local Agents**, and one Shared Clerk with **100,000
retained transfers**. Preserve Clerk's kernel, signatures, committed roots and
exact retry semantics. A singleton, smaller dataset or experimental-only release
requires a new user decision.

The user requested completing this plan before the next whole-branch review.
This batch follows the qualified checkpoint `64a687dc`; its source
boundary is that checkpoint plus the implementation in the commit containing
this document. The active worktree is `.worktrees/ch08-runtime-directory`.
Verify actual branch heads and cleanliness before using the checkpoint; do not
infer promotion from these docs. `master` remains `d2378274`; no automatic push,
mainline change, artifact promotion or deployment is included.

**Implemented** means source and focused tests exist; **integrated** means the
supported workflow selects it; **qualified** means its specified acceptance test
passes on the actual release. These are separate milestones.

## This batch: paired checkpoints and retained replies

The preceding checkpoint's expiry, overwrite and signed Clerk evidence is in
`git show 64a687dc:docs/agent-saga-review.md`; those counts are not inherited here.
Two connected candidate changes are implemented:

- External Shared checkpoint publication and reopen use the existing common QC,
  separately signed local store binding and journal-first recovery marker.
  Predecessor and target closures are audited before publication or staged-head
  recovery. A raw genesis opener cannot admit a later certified checkpoint.
  Missing blocks or physical profile metadata revoke the serving pin; restoring
  bytes does not revive it without a fresh owner audit. Portable export, automatic
  pruning, public startup and external Local remain gated.
- Ordinary signed Direct Linear/LinearizableQuery Invoke/ACK retries can inspect
  the exact retained terminal under the authenticated current root. An opaque
  proof binds owner epoch, head, request kind, retirement, authorization, trusted
  inspection clock, current claim and outcome. It never invents an old input ID.
  A distinct strict-current availability message reuses the bounded quorum pool;
  historical availability semantics remain unchanged. Final validation after peer
  I/O rejects root/owner changes and clock regression as retryable unavailability.
  Completed results still require a real ACK; an acknowledged Invoke cannot rerun.
  No historical index, guest ABI change, peer VM or new driver framework is added.

All seven external Shared physical fixtures pass on the final default optimized
build: healthy checkpoint/reopen, exact marker/journal/ledger interruptions,
retained replies through two checkpoints after authorization expiry, and both
existing file/network lifecycle cases. They include signed Clerk/reference-root
checks, missing data and substitution refusal. The final healthy case also proves
that a failed physical head read revokes the pin after exact byte restoration;
stale caller/plan mismatches do not revoke healthy pins. All eight selected
image/checkpoint/custody recovery regressions also pass, along with 143 distinct
focused checks and the physical bounded-pool regression. Guest and external CLI
feature checks pass; ordinary CLI tests pass (300, with 45 explicitly ignored).
This is not service capacity, public cutover or complete release qualification.

The fixtures collect a genuine authenticated network quorum, then isolate and
retire all Raft workers before filesystem publication. Exact crash assertions
check the signed marker's predecessor/target heads. This qualifies offline
publication/recovery, not live coordinated checkpoint/catch-up. Keeping the other
two voters active during source publication correctly refused a certificate after
a new election advanced its physical foundation; neither deadlines nor certificate
checks were relaxed. Preserve those failure logs.

Next, complete bounded external checkpoint export/import and detached reclamation
using existing certificates, public block traversal and recovery markers. Stream
both canonical typed objects and scoped block records, not a larger whole-memory
AJB1 image. Its separate 65,536-object and 65,536-blob limits cannot represent the
approved retained dataset and cumulative invocation history. Qualify actual
capacity, exact retry and interrupted import before public cutover.

Public three-node startup/finality, external owner selection, public Shared
management and pruning remain gated. No current result establishes production
cutover, customer capacity or the complete customer workflow.

## Recovery requirements

Custody retains at most one signed slot per physical owner in the fixed-three
committee. Registration commits the exact request, work and original preflight
before recoverable admission. PAP2 alone is an intent: origin loss before quorum
registration can leave a request undiscoverable. Admit one distinct unfinished
delegated read per system Agent; separate holders of that exact read share its
result. This adds a registration round for Authority reads, not ordinary calls.

Preserve the first physically verified terminal Invoke and first positive ACK.
Later valid repeated inputs cannot replace their evidence/response; negative
ACKs do not retire custody. Verify the exact Ordered position rather than the
latest outcome for an input. Reservation and submission require fresh committed/
applied barriers. Movement during validation is retryable unavailability; a
contradictory stable cursor is corruption. Old logs assigning one immutable
Ordered entry to multiple Raft positions remain invalid.

New registration requires fresh delegation or exact retained execution evidence.
An already-applied registration can retry after expiry without authorizing unseen
execution. Recovery may finish an admitted dependency while retaining a different
unadmitted local intent unchanged. Owner-only monotonic replacement requires the
previous PAP2 to be durably clear.

The user approved explicit expiry finality on 2026-09-30. A quorum-certified
terminal proves **no committed Invoke or published effect**, not that a VM preview
never ran. It retains the exact request/proof and is distinct from Invoke/ACK.
Signers bind the manifest, committee, trusted time and semantic/physical prefix.
Existing Invoke evidence and ambiguous suffixes refuse expiry. Clock expiry
alone never permits execution, evidence deletion or durable cleanup. Historical
no-expiry bytes remain unchanged; new host recovery envelopes are versioned
without a guest ABI change.

The certified floor fences stale admission after holder replacement or clock
regression. It is not an indefinite archive of the original terminal and cannot
clear an unadmitted WAL by itself. Candidate `ProjectionExpired` now maps to the
existing nonretryable route rejection instead of transport unavailability. Its
focused optimized regression passes; public integration remains unqualified. No
new public API variant is needed. Production authenticators presently create
legacy reads without this delegation.

## Batch 1 — Simplify and qualify the recompiler

Linux x86-64 Agents select the recompiler by default with an explicit interpreter
override. Backend/lifecycle checkpoint evidence is historical; exact-release
customer-workflow phase measurements remain open.

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
  Standard/custom-runtime checkpoint evidence exists; the final released-artifact
  matrix remains a batch 3 gate.

Exit: a scoped, tested checkpoint with actual phase timings. Recompiler speedups
do not by themselves qualify Shared capacity or eliminate whole-runtime work.

## Batch 2 — Complete the customer workflow

- [ ] Complete fixed-roster common authenticated genesis and production Shared
  finality. Never represent three singleton lineages as one replicated Space.
  Keep unsupported production paths gated until their admission/recovery is proved.
- [ ] Qualify leader loss before Invoke commit and the remaining ACK/metadata-clear
  crash matrix. Preserve exact retry, fresh authorization, reservation ownership
  and unpublished recovery. Historical custody/checkpoint/delegation fixtures do
  not qualify all pending scopes, full outer-PVM execution or production startup.
  Signed delegation is an explicit candidate-only opt-in: legacy authenticators
  still emit ordinary reads. Delegated SSH attestors must be current voters with
  authenticated committee keys. Applied custody now retains delegated signed
  requests for offline-origin discovery. Expired-unseen terminal resolution passes
  the candidate offline/quorum/import fixture; qualify every pending scope before
  production. Neither local absence nor a timeout releases PAP2.
- [ ] Collect quorum-certified snapshots/checkpoints and qualify restart/catch-up
  before replay capacity is exhausted. Optional checkpoint skipping is temporary;
  mandatory capacity/certificate guards must continue to fail closed.
  Use a common-state QC plus a separately signed physical node/store binding;
  collecting signatures over different local claims is not a quorum certificate.
  Preserve semantic ancestry independently of physical checkpoint cadence.
  Image candidate fixtures cover pruned-prefix catch-up, exact boundary retry,
  reopen, ordering and marker/journal/ledger interruptions. Mutation remains test-only
  until **all** pending recovery scopes survive retirement, including an offline
  origin's after-ACK PAP2. Do not replace that gate with a local absence check or
  weaken exact retry. Ordinary retained replies now have a candidate current-root
  proof; optimized physical qualification passes, public qualification remains
  pending. External block-root
  closure/export remains a separate integration
  gate; image catch-up does not qualify the 100,000-transfer workload.
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
  The full-outer signed network and three-file lifecycle slices pass on this
  batch's optimized source. Integrated external minority behavior and catch-up
  remain unqualified.
- [ ] Bound reclamation and root-pinned export. Retain authoritative, pending,
  checkpoint, retry/recovery and backup roots. Maintenance-window reclamation is
  acceptable; unbounded historical retention is not. Use public block closure
  traversal, not host decoding of private runtime/actor state. Full import/recovery
  audits must not become ordinary-request whole-state scans. The current portable
  bundle's 65,536-blob ceiling cannot hold approximately 200,000 rows (roughly
  400,000 Patricia structural blocks before chunks). Cumulative acknowledged
  invocation history can also exceed its separate 65,536-object ceiling.
  Stream both kinds with explicit per-record/count/byte limits; qualify archive
  sizing and peak memory without lowering the approved workload.
- [ ] Expose public Shared Create/Install/Invoke with resumable, schema-aware CLI
  commands using existing management/request mechanisms. Preserve signed terminal
  failure finality and exact request identities; qualify the implemented terminal
  expiry rejection mapping before promotion.
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
  Historical candidate recovery evidence is not service capacity or complete
  production recovery qualification. Current debug timing and optimized checks
  are tracked above; retain fresh validation after peer I/O.
- Certified expiry after custody admission passes the optimized offline-origin,
  follower-RPC and common-import fixture above; complete public integration and
  pending-scope qualification remain open. A remote owner's
  unfinished registration retains the leader's projection reservation until
  positive ACK or an applied, verified expiry terminal. Clock expiry alone never
  authorizes execution of unseen work or discarding custody.
  Legacy/mixed-version stale intents can outlive all owner replacements and
  pruning; retained-history legacy checks alone cannot prevent such an old read
  from registering again. Keep this with the legacy pending-scope pruning gate.
  A registration reply can time out while its append later applies; exact retry
  reconciles it. Unadmitted WAL cleanup after loss of the retained exact terminal
  remains gated; the floor alone cannot clear it. None of these limits is closed
  by refusing expired new admission.
- Current-root retained inspection is implemented and passes the optimized
  physical two-checkpoint fixture; public qualification remains pending. It
  binds exact old work/auth/outcome and fresh majority availability, not merely
  a newer certificate. Fresh eligible external calls currently perform an extra
  read-only inspection before preview/execution; measure this integrated cost.
- A fresh supervisor Invoke currently performs at least four outer runs:
  directory inspection, retained-result inspection, terminal preview and leader
  application; followers also apply independently. Both outer and inner machines
  use the recompiler, but prepared code does not reuse invocation memory. Existing
  single-call network samples remain around 0.8 s (transfer 854,255 us; post-reopen
  state-root 812,063 us on this optimized source), not a capacity result. The
  isolated external fixture needs explicit tracing initialization before its
  existing VM phase counters are observable. Queue waits and journal/application
  persistence are not fully attributed; do not infer the actor or VM dominates.
- Certified reopen currently repeats complete block-closure/replay audits across
  the slot opener and driver. Recovery/maintenance time is unmeasured at the
  approved dataset. Existing GC bounds unlinks, but each pass still audits the
  reachable tree and scans/stats/sorts the namespace. Keep it detached and measure
  peak metadata memory and repeated-pass latency; do not put it on request paths.
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

The [review guide](agent-saga-review.md) records current source-specific evidence,
candidate fixture limitations and reproducible commands. Reviewed baseline
evidence is recoverable with `git show 6d3a4926:docs/agent-saga-review.md`.
Artifact identities
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
