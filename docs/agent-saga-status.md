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

The current code checkpoint is `4ea0271c` on `wip/ch08-runtime-directory`:
terminal gas-parity repair and exact custom-runtime qualification. Review
`bd378ae9..4ea0271c` as **one batch**, together with this docs-only handoff.
The preceding pruning/backend checkpoint is `48df3995`; the tested
admission/recovery baseline remains `62ffbc20`.
The reviewer checks `saga/agents`: verify that it contains the code checkpoint
before starting. Fixes continue on the implementation branch before a qualified
fast-forward. `master` is unchanged; do not push or change it automatically.

Status vocabulary: **implemented** means source and focused tests exist;
**integrated** means the supported workflow selects it; **qualified** means its
specified acceptance test passes on the actual release. These are not synonyms.

Completed backend follow-up at `4ea0271c`, with subsequent Shared work still
unpromoted in the implementation worktree:

- Independent review reproduced a recompiler gas-parity bug when re-invoking
  a terminal inner machine. The reviewed fix preserves reference funding;
  276 PVM tests and 20 vectors pass, plus the no-default-features check.
- The normal custom-linear guest now has 36 exact-input backend comparisons
  across Local/Shared lifecycle, retained results, retries and scheduling.
  This closes the missing custom-layout test coverage, not service qualification.
- Shared external integration uses the existing signed Linear-only runtime
  capabilities. Physical Create/Clerk Install produce identical state on three
  replica identities without normalizing node-local roots or changing the ABI.
  Journal integration and majority durable-availability checks are in progress.
- A real three-node pre-Invoke leader-loss test reproduces an unresolved pending
  read: committed-only recovery correctly refuses an unseen request. Do not
  relax that admission guard. Recovery delegation versus original-attestor
  readmission needs an explicit authorization decision; production remains gated.
- Both post-Invoke replay orderings and post-ACK/pre-metadata-clear reopen now
  pass physical three-node tests. These do not close the pre-Invoke gate.

No finish-line change follows from these results. The remaining work stays in
the three batches below; do not add a parallel plan or treat these as a release.

| Area | Current checkpoint evidence | Remaining release boundary |
| --- | --- | --- |
| Admission and recovery | Baseline `62ffbc20` binds complete imported-plan certification and rejects unsupported rosters before writes; mixed-generation recovery P1 resolved | Review checkpoint findings; remaining three-node crash boundaries |
| Fixed three-node bootstrap | Baseline common certified genesis, physical startup/reopen and post-Invoke leader-loss fixtures pass | Production startup remains gated; actual three-process daemon/HTTP qualification is pending |
| Local execution | Image path retained; final default/reference Local suites and actual default-selected image daemon pass; public external Local removed | Exact-release performance, recovery and backup qualification |
| External actor storage | Experimental authenticated incremental storage, durable publication/recovery and real Clerk fixture pass on both backends with rebuilt guests | Shared executor/finality integration, block availability, retained growth, safe reclamation and export |
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
- [ ] Differentially compare outputs, gas, PC/registers, exits/faults, memory
  permissions, host-call suspension/resume and commitments, including standard
  and genuinely different custom-runtime layouts. Run physical lifecycle/recovery
  tests and supported feature builds after pruning and backend changes.
  Exact standard-runtime comparisons and both custom-runtime physical suites pass.
  The continuation adds 36 exact custom-runtime comparisons; final integrated
  host/feature reruns remain pending before promoting that work.

Exit: a scoped, tested checkpoint with actual phase timings. Recompiler speedups
do not by themselves qualify Shared capacity or eliminate whole-runtime work.

## Batch 2 — Complete the customer workflow

- [ ] Complete fixed-roster common authenticated genesis and production Shared
  finality. Never represent three singleton lineages as one replicated Space.
  Keep unsupported production paths gated until their admission/recovery is proved.
- [ ] Qualify leader loss before Invoke commit and the remaining ACK/metadata-clear
  crash matrix. Preserve exact retry, fresh authorization, reservation ownership
  and unpublished recovery. The post-Invoke/pre-ACK fixture already passes, but
  does not qualify these other boundaries.
- [ ] Collect quorum-certified snapshots/checkpoints and qualify restart/catch-up
  before replay capacity is exhausted. Optional checkpoint skipping is temporary;
  mandatory capacity/certificate guards must continue to fail closed.
- [ ] Integrate the existing external-state executor and block store into Shared
  Clerk through a narrow internal executor selection, not a new driver framework.
  Current Shared replay selects the image executor and the external executor
  admits Local descriptors; neither is a CLI-only cutover.
- [ ] Prove durable, available blocks before acknowledging their roots/results
  under Shared quorum rules, including missing blocks, minority failure and
  catch-up. Preserve provenance, exact predecessor checks and retry atomicity.
  Missing data is unavailable state, never an absent row or successful execution.
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

- Incremental actor rows do not eliminate whole-runtime control-state transport,
  directory reconstruction/publication or Shared ordering/locking. Measure their
  actual cost; the release does not promise every operation scales with touched data.
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
