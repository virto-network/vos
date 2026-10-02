# Agent saga: review entry point

This is the sole reviewer handoff. [The live checklist](agent-saga-status.md)
owns scope, dependency order, forecasts, open gates and acceptance targets.
Review read-only and return findings for the implementation branch, not competing
fixes on the review branch.
Start with [R37 replacement](#active-priority-r37-observation-replacement); older evidence is
explicitly frozen and cannot qualify later source.

## Boundary and release claim

Starting checkpoint is `e6f2bb45` on `saga/agents` and
`wip/ch08-runtime-directory`; inspect the latter's active diff.
Verify actual heads and cleanliness before assuming fast-forward promotion.
`master` remains `d2378274`. No released fixed-three workflow or service capacity
is qualified by this diff yet.

The live checklist defines three usable exits: **M1 packaged recovery test
pilot**, **M2 full-data/backup pilot**, and **M3 qualified v1**. A pilot states its
demonstrated limits and does not waive any final workload, latency, recovery or
correctness gate. Review a frozen source/artifact boundary plus its acceptance
evidence and delta; internal passing suites are not a milestone exit.

Production Local remains image-based. Fixed-three prewrite gates and production
artifact pins remain closed pending coherent packaged workflow qualification.
Test signers, candidate guests and fixture resource policies are not release proof.
The replacement release requires fresh v1 System/control and Shared roots;
existing experimental spaces remain untouched and unsupported by the new binary.

## Active priority: R37 observation replacement

User approval on 2026-10-02 supersedes the proposed never-admitted read-expiry
extension. Scope is one replacement internal System Authority observation path;
no durable-read fallback or parallel supported design. The user additionally
approved **fresh v1 spaces**, including System/control and Shared roots.
Old experimental spaces remain untouched and unsupported by the new binary;
migration, reset and mixed-generation Local rebinding are not authorized.

O1/O2 and O3 removal are implemented; the current integration diff is not yet a
frozen qualified checkpoint. Explicit signed image opt-in, Observe tag 5,
non-retaining guest execution/no-effects policy, opaque host purity validation,
authenticated ReadIndex/apply-through and exact SAC7 System contract binding
exist. Complete consumer cutover and read-lifecycle deletion are present;
packaged artifacts/startup and integrated acceptance remain open.
O1–O3 are three review chunks within M1, not new release milestones.
The live plan owns acceptance, effort bands, go/no-go cap and unchanged targets.

Current O3 component evidence (logs under the native worktree's `target`):

- `release-observation-o3-fixed-three-physical-debug-r37a.log`: **1 passed,
  86.19s**, actual own leader/follower guest state, 40 distinct no-ACK reads,
  credential enrollment/revocation and exact old request, unchanged retained
  state, callback, cancellation, retirement, reopen and minority/return.
- `release-observation-o3-critical-unit-debug-r37b.log`: **241 passed,
  10 ignored, 29.86s**. Six earlier failures were invalid management test
  fixtures (first-owner, anchor and reused identity), corrected without changing
  production invariants.
- `release-observation-o3-cli-unit-debug-r37b.log`: **362 passed,
  52 ignored, 323.23s**, with allowed local loopback. This precedes the last
  packaged-role/prewrite source edits, so those edits still need fresh tests.
- Current SDK feature/default suites: **259 / 256 passed**, each 1 ignored.
  New System and external guests build/link; the actual paired signed-role and
  purity probe **passes 4.64s** (`release-observation-o3-runtime-role-probe-r37a.log`).
  Its explicit 1,000,000-row/1GiB ceilings are declarations, not capacity proof.
- `release-observation-o3-management-pruning-physical-debug-r37b.log`:
  **fails 156.67s**, `management_retention.rs:546`, offline authenticated common
  checkpoint restore returns `SnapshotReplay`. This is an open mandatory
  correctness gate; unit tests and observation success cannot waive it.

Earlier frozen O2 evidence is retained at `release-observation-o2-r37j-test-binary`
(BLAKE2b-256 `3fa8049f1587f1202d86d30a3c7995e1052739bab343f2ed197fdc76b78852c9`),
with 38 consumer/publication/archive-phase checks and a 76.43s physical slice.
It does not qualify later O3 source. SAC7 constructor/directory binding was a
necessary contract fix, not a relaxed matcher. An overbroad network deletion
was caught and exactly restored from the archived dirty source before the
current checks; generic execution was structurally audited.

No packaged workflow/SLA, blanket filesystem-write trace, hard wall-clock bound
under stalled locks/disk, live-root replacement or mid-guest term/config-change
qualification is claimed. No artifact pins, release gates or branches have been
promoted. The next boundary must bind exact packaged System/Authority closure
before writes: SAC7 alone cannot identify O3's management-only RMF4 lineage.

### Settled preliminary contract

- Internal reads are observations at a committed revision, not durable operation
  identities. Lost reply/restart obtains a fresh observation. Preserve public
  actor Invoke/ACK, signed Create/Install, exact mutation results and retention.
- Current System leader uses existing bounded ReadIndex. Internal receiving
  voters own authenticated local System journals; after fresh correlated barrier
  context they apply through its index and execute the admitted guest locally.
  No naked remote page/role/status assertion becomes execution or finality proof.
- Preserve the existing authenticated-CFT trust boundary (`shared_commit.rs:1`),
  not claim independent Byzantine freshness. A bounded typed leader barrier RPC
  is integration over the current worker, not a new quorum algorithm/certificate.
- Bind exact route/generation, runtime/artifacts, committee/configuration, term,
  authenticated request/reply and per-open state pin. Raft applied frontier
  **A >= R** may coexist with older actor-state publication **J < R** after
  no-ops; validate that linkage. Recheck lifecycle/fingerprint after I/O and do
  not hold host/proposal mutexes across barrier/peer waits.
- One explicit scoped guest observation operation is needed: normal Query still
  retains results. Require whole opaque state unchanged, no root/row/metadata
  mutation, retained reply, ACK, consumed authorization, effect, Yield or
  continuation. No host-private Standard/Authority decoding or raw actor bypass.
- Fresh credential/revocation/visibility checks and returned facts use the same
  immutable revision. Keep gas/output/read bounds. Exact head/credential-claim
  changes discard partial pagination; no durable snapshot session framework.
- Keep complete retained-member scope for cold Shared Install and all creation/
  publication/checkpoint certificates. GenesisDecision alone is not application/
  member readiness. A required consumer without verifiable local System state
  stops cutover; it cannot fall back to trusting a leader-supplied answer.
- Scoped admission uses signed `SYSTEM_OBSERVATION_ABI_ID`, image-only contract
  and explicit AWRK tag 5. Global runtime ABI, mutation tags 0–4, state/control
  schema and image Local wire remain unchanged. Default/old contracts, external
  frames and attested/public image execution cannot select Observe. Coherent
  fresh artifact/version cutover still requires integration qualification.

Reusable sources: `support/vos-raft/src/worker.rs:3390` (ReadIndex),
`vos/src/service/service.rs:1707` (apply-through precedent),
`vos/src/agent/shared_journal_driver.rs:4085` (non-publishing inspections),
`vos-agent-sdk/src/runtime.rs:779` (missing first-execution observation),
`actors/system-authority/src/lib.rs:1645` (pure Authority handlers),
`vos-agent-sdk/src/authority.rs:1294` (revision head),
`vos/src/network/shared_agent.rs:2736,5309` (I/O/lifecycle fencing).

### Required consumer cutover and removal inventory

| Boundary | Remove after all consumers switch | Must remain / implementation trap |
| --- | --- | --- |
| Inventory/credential client | `production_owner.rs:170–397` pending recovery/context/live continuation and `in_flight_query`; query-specific scheduling where unused | Signed query auth, exact head/claims, complete inventory assembly and route publication; no mixed pages/cache-on-error. |
| System bootstrap reads | `clean_bootstrap.rs:1579–2073,8908–10504` PAP2/PPR1, bootstrap pending read, read registration/dependency/expiry/Invoke/ACK | Bootstrap Authority/Catalog receipts, exact signed plan admission and management lifecycle/reopen. No unsigned legacy-record clearing. |
| Genesis decision | Ordinary delegated and management-anchored read variants, `invoke_genesis_recovery_read` and read-only child anchors | Guest validates permanent decision and exact provision; fresh complete descriptor/roster before application/readiness. |
| Member admission/cold Install | Custody-specific `ColdMemberProjectionScope`, read pair and combined read replay budgeting | Complete independently leased required set, scoped Root authorization, exact retained parent, fresh facts, generation recheck and staged publication; no blanket readiness exemption. |
| Genesis committee selection | `RetainedCommitteeQuery` GCW1/read reply, deterministic read invocation and ACK child | Authenticated committee observation; immutable selected roster/lease; exact certified candidate/signatures/archive; publication successor of original authorization. |
| Supervisor/network | Read recovery commands/accessors, `ProjectionRecoveryRequest`, read registration/disposition/expiry RPCs, read pair/dependency dispatch in `agent_protocol`, `agent_network`, `shared_agent` and `projection_recovery` | Authenticated routes, worker lifetime/bounds, Raft, ordinary availability, public exact invocation and bounded original-owner management forwarding. |
| Custody manifest | Read registration/request, read slots/sequence/watermark, expiry floor/claim/certificate/terminal, exclusive unfinished-read rule | Management slots/MRQ2 ownership, shared first Invoke/positive ACK evidence and Register/ReleaseManagementRecovery. Rename remaining helpers instead of deleting shared authentication. |
| Raft/checkpoint/replay | `RegisterRecovery`, `ExpireRecovery`, read-specific dispositions, folds/dependency pins and expiry checks | Accepted ordinary rows apply harmlessly; mutation/management replay, physical store binding, certified manifest commitment and pruning/reopen evidence. |
| SDK/Authority wire | Internal durable-read delegation producers/branches and obsolete tests once unused | Request signatures, SSH attestation, selectors/visibility/revocation, heads/limits and unrelated public actor query semantics. No silently overloaded Invoke or broad compatibility decoder. |
| Bootstrap/native formats | Old read-containing CSB2/PAP2/GCW1/RMF/ASR formats on the fresh-space path; old-code recovery fallback | Explicit prewrite old-space refusal and coherent new artifact/version admission. Preserve normal immutable closure and management state in the new format. |

Critical shared-store/code checks:

- `SharedRecoveryObservation` serves management root/successor evidence
  (`shared_recovery/management.rs:593–819`). `SharedRecoveryManifest` and
  snapshot/ASR commitments cannot vanish; remove the read portion coherently.
- `NativeSharedCreateRecovery.query` also owns selected replica material
  (`clean_genesis_recovery.rs:2548–2586`). Delete GCW1/read replies, not its
  immutable roster or lease.
- `prepare_genesis_publication` extends the retained committee-read predecessor
  (`clean_bootstrap.rs:6600`). After removing that child, publication must extend
  the original retained authorization while preserving owner/capacity/signature
  and durable terminal release.
- Existing image Local program/space bindings must not be silently rebound.
  Global ABI/version changes require coherent admitted artifacts and Local
  regression evidence, not an assumption of backward compatibility.

### Preliminary evidence and review acceptance

Independently rerun on unchanged `support/vos-raft` source at `e6f2bb45`:

```sh
cd /home/daniel/src/virto/vos/.worktrees/ch08-runtime-directory
env CARGO_TARGET_DIR=/home/daniel/src/virto/vos/.worktrees/ch08-c2-native/target \
  TMPDIR=/home/daniel/src/virto/vos/.worktrees/ch08-c2-native/target/task-tmp \
  JUST_TEMPDIR=/home/daniel/src/virto/vos/.worktrees/ch08-c2-native/target/task-tmp \
  RUST_MIN_STACK=16777216 \
  cargo +nightly-2025-05-09 test --offline --locked -j2 \
  -p vos-raft --test state_machine read_index -- --test-threads=1
```

**5 passed / 0 failed / 0 ignored, 0.55s**: fresh quorum confirmation, prior-term
tail on leadership transfer, isolated-leader step-down, bounded timeout/shutdown
and queue backpressure. This is existing primitive qualification, not an Agent
wrapper, PVM or replacement workflow pass.

Log (disk-backed target): `release-observation-preliminary-read-index-r37.log`,
SHA-256 `60c1d7268f2b21478b38a65adbcfb4d065a7e64f878862c873752875ee8ac721`.
Source audit independently confirms the receiver-owned authenticated-CFT design
and mixed read/management deletion boundary; no source edits were delegated.

For O1–O3, require each selector's physical purity/authentication/no-publication
negative tests; fresh leader/follower apply/retirement fencing; observation-loss/
restart without settlement; bounded revision-consistent pagination; genuine
public mutation-loss/exact retry; complete cold member/Install recovery and
pruning. Measure no read-specific writes **after required consensus catch-up**:
replication of preexisting committed writes and election no-ops is legitimate.
Tests cannot pass by zero selection, native Authority oracle, raised deadline,
manual finalization or merely checking an unchanged actor lane.

Close the removal inventory before declaring replacement: no live legacy
producer, read transport/apply/recovery branch, decoded read-format fallback or
runtime switch survives. Preserve all management/public exact semantics. Record
actual deleted paths, surviving shared helpers and source/ABI/artifact identities.
Do not infer code shrinkage, M1 readiness or service capacity from the audit.

Superseded live-plan/reviewer text is recoverable in
`release-observation-docs-before-replacement-r37.tar.gz`, SHA-256
`10ecf3d7b5b9c6aa094ba97d234e52051e8dcbc825fc4b4cbbc11132fb56af7a`.
The following R36 boundaries remain forensic source/evidence, not another active
plan or authority to keep their read design alongside observation.

## Current source-specific evidence

All paths below are relative to disk-backed `.worktrees/ch08-c2-native/target`.
Ignored/zero-selected fixtures and source review are not physical passes.
Later source cannot inherit a frozen boundary's timings or tests.

### Frozen foundations and packaging boundary

Earlier R36p–R36v corrections remain in the focused regression set: authenticated
snapshot binding, leased inert staging, checked retained serialization/budgeting,
inventory hint continuity and dominating validation. Their individual failed
timelines, complete source/binary identities and reproduction details are in
`release-observation-docs-before-replacement-r37.tar.gz` (identity above).
They are forensic evidence, not active tasks or qualification of R36y/replacement.

Frozen R36s root/child retention, two pruning cycles, archived exact retry,
returning owner and Local Install through final ACK/release **PASS485.11s**.
Its late peer vote **1.754s** is close to the unchanged **1.8s** bound. Log:
`release-integration-observation-serialization-root-child-physical-opt-r36s.log`.
It does not qualify later source, whole-cold Shared <=30s or service.

Role tooling remains unapplied:
`task-tmp/release-runtime-role-materialization-current.patch`, SHA-256
`5ecddde0fbb95245919f53f4c094215b06871ed9a40845fae2c4c0eede4479f1`.
No build, guest or reproduction pass exists for this draft. Observation changes
require renewed contract/artifact review before applying it.
Ordinary enrollment/common-genesis and Shared Create/admit/Install/call/exact-
resume seams already exist; no new CLI or signing framework is needed.
The packaged acceptance must lose the initial successful mutation response,
not merely an ACK reply, and demonstrate exact replay.

### Frozen legacy diagnostic boundary: R36y

R36y adds only an environment-gated diagnostic to the existing drained/audited
expiry-eligibility lookup. The identical full query/work/authorization find
reports public IDs/commitments, manifest identity/count and exact-slot/Invoke/
ACK/expiry presence. No new read, write, outcome, signature, payload log or
terminal cleanup is introduced. Current absence does not prove pruned-history
absence. Independent review reports no findings. Debug compilation **PASS39.77s**;
all 149 unchanged focused checks pass. The unchanged debug public diagnostic
**FAIL80.29s** before its targeted expiry: Create custody times out, then the
exact retry returns ScopeMismatch and the client rejects its reply. It cannot
classify R36x's expired member read or qualify optimized behavior. The existing
controlled expired-unadmitted fixture **PASS50.25s**, unchanged on frozen R36y.
The losing owner `5df09f4d` / invocation `3c18d576` / work `8ac4a321` /
authorization `d619f3d5` never acquired custody. Its drained/audited manifest
`ab7a4b65` contains two slots and no exact slot, Invoke, ACK or expiry proof;
the leader refuses the original window at trusted slot **142**, with accepted
slot **22** and exclusive expiry **142**. The fixture asserts unchanged leader
proposal/admission state, full manifest, in-memory pending record and durable
WAL bytes. A fresh voter read subsequently reaches acknowledged custody while
the losing owner still has no slot. This proves safe refusal and preservation,
not retirement or M1. It does not prove historical absence for the separate
R36x public read or pruned history. No new fixture or production capability is
added; R36y has no optimized qualification.

Current quorum expiry cannot settle this controlled never-admitted intent.
The proposed additional terminal variant is superseded by the approved R37
replacement, not an active task. Frozen legacy records must not be cleared or
re-signed; fresh-space format rejection replaces migration/fallback. No
fabricated Invoke/ACK, mutation delegation, management Busy change or deadline
increase is authorized. No commit, branch/artifact promotion or master change.

Frozen tracked source (excluding docs):
`release-integration-expiry-eligibility-tracked-source-r36y.patch`, SHA-256
`104d27edb950a48f357f6247b0f71b5ca709d4be3a5759659824f2c6001f5278`;
tracked Rust `release-integration-expiry-eligibility-tracked-rust-r36y.patch`,
`d8ae5b84df9fe191167d7fe387ad0cf9e471a38eb13befb5607b961127d1470c`;
untracked `release-integration-expiry-eligibility-untracked-source-r36y.tar.gz`,
`c7c6257e83678a2f4a0241a6d7b58187957428da17ce6451eb3c11a7b1596de7`.
Pinned debug `release-integration-pinned-debug-r36y.WeiiZ5/{core,cli}`:
core `de24109a0ef73a154b7094aa0418f0c5f4fc874a16a6576757643c4d8f02f8bc`,
CLI `74d2efb0185de7abd1f6035f44eb1ff3de217369c4d70fd792401878d970f7b6`.
Logs: `release-integration-expiry-eligibility-{build,selected-phase}-debug-r36y.log`,
`release-integration-expiry-eligibility-warm-public-physical-debug-r36y.log`,
`release-integration-expiry-eligibility-expired-unadmitted-physical-debug-r36y.log`
(exact controlled fixture:
`agent::clean_bootstrap::tests::physical::common_checkpoint::candidate_expired_unadmitted_intent_cannot_acquire_custody_after_election`,
`--exact --ignored --test-threads=1 --nocapture`).

### Qualified regression boundary: R36x

R36x applies a narrow correction to the demonstrated R36w public retry cycle.
Only the feature-enabled exact `/_vos/agents/shared/create` handler can reach
the existing bounded lifecycle queue while recovering. The shared recovery
atomic marks that queue item retained-only, independently of caller-controlled
bytes. The owner must use its native full signed request/call/descriptor/runtime/
committee lookup even if readiness returns before dispatch. Absent or altered
material cannot invoke the fresh factory, sign, allocate or publish. The existing
not-ready queued continuation, terminal verification and route readiness remain
unchanged; all other HTTP quarantine routes remain closed.

Two independent source reviews report no findings. Applied owner tests cover the
readiness race and refusal ordering; actual native signed regression checks six
retained stores, journal index and allocation count unchanged for exact/absent/
validly altered/unowned lookup. HTTP/queue negatives retain feature boundaries,
capacity and shutdown. These qualify lookup/ordering, not released fixed-three custody.
Initial debug compilation **PASS1m31s**. The newly selected old singleton fixture
also fails on frozen R36w (**2.40s**) because fixed-three custody cannot form in
one-voter scope. All added actual signed-tuple/no-write checks pass before that
assertion. The fixture now explicitly asserts its fail-closed `ScopeMismatch`;
it does not claim fixed-three custody qualification or change production guards.
Final debug compilation **PASS30.25s**, and **all 149 count-checked focused checks
pass** on final frozen debug binaries. Normal optimized compilation
**PASS14m18s**; **149 focused checks pass in each profile**. The full physical
same-leader duplicate/no-write/locked-reopen check **PASS35.57s**; the unchanged
public workflow **FAIL286.55s** at its original lost-successful-member-admission
phase bound (`member_handoff_tests.rs:299`). Leader-origin Create completes
**103.045s**; no `retained_only=true` dispatch is observed, so the original
Follower-origin cycle remains unqualified. d799's exact initial inventory
`14379b01` / work `6103e338` / authorization `de19425b` loses registration before
its window closes: accepted slot **1790914235**, expiry **1790914355**, first
explicit refusal trusted slot **1790914356**. Different read `ef58d205` completes
and 934 republishes routes; d799 remains quarantined. No exact Invoke/ACK/expiry
is logged, but these logs lack a complete custody view. R36y records that existing
checked view without treating absent evidence or a timeout as terminal. Cleanup
after the assertion is not causal. Install/reopen and packaged startup stay open.
No protocol/artifact change, Busy reply,
timeout/window extension, new scheduler or offline mutation delegation is added.

Frozen tracked source (excluding docs):
`release-integration-retained-create-tracked-source-r36x.patch`, SHA-256
`d26519148aaece9a54960032204470e48cb437cf20fecd64cd58cb26e90d1dcb`;
tracked Rust `release-integration-retained-create-tracked-rust-r36x.patch`,
`b5f69ac3020e0d334810bffc78fdcec8ac3204a49d8faf86bab739fab4b7c292`;
untracked `release-integration-retained-create-untracked-source-r36x.tar.gz`,
`c7c6257e83678a2f4a0241a6d7b58187957428da17ce6451eb3c11a7b1596de7`.
Pinned final debug `release-integration-pinned-debug-final-r36x.JvSamU/{core,cli}`:
core `34176e539182a7a25d6b20f161dab49f6a0b93de68ff62cfc54d61eeb0d8540f`,
CLI `5c8f365daa9e2411f171821654085ea2826c0856147af712c6427e1e0cca2943`.
Logs: `release-integration-retained-create-build-debug-final-r36x.log`,
`release-integration-retained-create-selected-phase-debug-final-r36x.log`.
Pinned optimized `release-integration-pinned-opt-r36x.stzHvF/{core,cli}`:
core `73805e981f5fed100cf6d0d8bae85b8ebaf1c420615b04863cea3208553ebb84`,
CLI `509ae05ed2d35eccfc31df35c1766d1a619bf533c8096568876fa569a8f0b273`.
Logs: `release-integration-retained-create-build-opt-r36x.log`,
`release-integration-retained-create-selected-phase-opt-r36x.log`.
Physical regression log:
`release-integration-retained-create-duplicate-read-physical-opt-r36x.log`.
Public log (closed FAIL286.55s):
`release-integration-retained-create-warm-public-physical-opt-r36x.log`.

### Archived diagnostic and correctness history

The full R36w finite pre-admission handoff, retained-only Create retry-cycle
evidence, all earlier frozen source/binary hashes, failed timelines and old
archive identities are preserved in
`release-observation-docs-before-replacement-r37.tar.gz` (identity above).
No legacy read scheduling/expiry task survives as a competing active plan.
Deletion still requires proving that a helper is read-only rather than shared
with signed management admission or public invocation.

Frozen R36k duplicate/reopen, expired-unadmitted/fresh-voter progress and
follower checkpoint/reopen fixtures passed **44.66s / 56.65s / 228.61s**.
Logs:
`release-integration-management-refusal-{duplicate-read,expired-unadmitted,follower-delivery}-physical-opt-r36k.log`.
They do not qualify later source, whole recovery or public lifecycle.

Management clock ordering and CSF1/NRT1 native terminal archives remain
implemented but not fully release-qualified. Preserve exact mutation clocks,
unfinished management work and old exact terminal retries; synthetic 257 pairs
do not prove genuine >256 public authorizations.

The two-Member public smoke remains unapplied/uncompiled/unqualified:
`task-tmp/member-clerk-nonroot-public-smoke-current.patch`, SHA-256
`92689a418790a432b2233a48f067d25882948bccb1f609c9c9b492fdc985ae25`.
It covers two Member mutations, denial non-effect, lost-result reopen and six
count/composite reads, not independent six-map parity, full loading or service.

### Offline signed corpus tooling

Three debug smoke checks pass (**0.57s**, build **2m23s**).
Normal optimized build passes (**4m11s**), SHA-256
`90c7e1a8cc6c7e954a49e345cb0caf3fbaf64af022f79c2d264c8f94ac12f4df`.
Full generation passes (**32.33s**): 1,000 accounts, 100,000 retained
transfers/external IDs, 101,000 verified signatures and six reference roots.
Independent BLAKE2b-256 file digests match the last-published manifest.
Logs: `release-integration-clerk-corpus-{debug,build-release,full-release,stream-digests}-r32a.log`.
Private parent/output 0700, files 0600; business keys/openings must not be exposed.
Peak memory is unmeasured. This closes offline corpus only, not public loading,
capacity, service or hardware. Public parity requires actual accepted batch seed
timestamps and execution order, not synthetic offline roots or client reply order.

### Unchanged guests and prior boundaries

Frozen R30e clock/retry/ACK/reopen and R32c selected expiry fixtures remain
historical correctness evidence, not later public or packaged qualification.
Starting foundation: `git show e6f2bb45:docs/agent-saga-review.md`.

| Unchanged output | SHA-256 |
| --- | --- |
| Authority ELF | `3272da2da7d7d2c76c4dcbbb3edcf802476d376f5db3b3b5ac7876416cf61124` |
| System-image ELF | `a3c17d033a4dcdf9d626e323729c340e454dd1fb62cfc4f0693105d58bcd695a` |
| System-image PVM | `f1bdab8272bf5aebeaf7a3b7a66cdbe9cb8fa81ac412e56ac9da110815f12264` |
| External runtime ELF | `2d92c4350093a9b37825db4f9e6fc7688f7410ac6d48a15e48750af638173d21` |

System-image program ID:
`41d4073836b785457df23bf8fce9803b7c1dd88df713a57bd332bd5454b7078e`.
No production pin or fixed-three gate is promoted.
Superseded chronology remains in target evidence/source archives, including
`release-integration-docs-pre-consolidation-r31.txt`; it is not another live plan.

## Reproduction and working rules

Use implementation worktree, offline/locked host nightly `2025-05-09` and
disk-backed paths:

```sh
export CARGO_TARGET_DIR=/home/daniel/src/virto/vos/.worktrees/ch08-c2-native/target
export TMPDIR="$CARGO_TARGET_DIR/task-tmp"
export JUST_TEMPDIR="$TMPDIR"
export CARGO_NET_OFFLINE=true CARGO_BUILD_JOBS=2 RUST_MIN_STACK=16777216
export AUTHORITY_CANDIDATE_ELF="$CARGO_TARGET_DIR/agent-state-authority/riscv64em-vos/release/system_authority.elf"
export VOS_AGENT_RUNTIME_COST_CANDIDATE="$CARGO_TARGET_DIR/agent-system-image-selector/system-image-runtime.pvm"
export GREY_PVM=recompiler VOS_AGENT_PROFILE_REFINE_MACHINES=1
export VOS_AGENT_DISABLE_REFINE_ATTRIBUTION=1
export CLERK_AGENT_PACKAGE="$CARGO_TARGET_DIR/clerk-agent-canonical/clerk-ledger.vos"
cargo +nightly-2025-05-09 test --release --offline --locked -p vos \
  --features 'agent-runtime storage network http-ingress experimental-state-blocks' \
  --lib agent::clean_bootstrap::tests::physical:: \
  -- --ignored --test-threads=1 --nocapture
```

Run physical tests separately from builds, with loopback socket permission.
Explicitly select fixtures; ignored/zero-selected/socket-refused runs are not passes.
For native outer-runtime adapter expiry tests unset the outer-profile variable;
full outer-PVM is a distinct boundary. Guest nightly is `2026-03-20`.
Normal release uses fat LTO/one codegen unit; override builds are diagnostic.

Diagnostic filters/phase logging can affect lock-held timing. Quiet optimized
runs are required before latency claims. Preserve source/log/hash boundaries:
mutable target paths can overwrite an older binary. Candidate results never
promote `support/production-artifacts.toml` or `vosx/build.rs` pins.

## Reviewer deliverable

Return severity, location, violated invariant, concrete scenario and regression.
Separate demonstrated defects from unqualified gates. The live checklist owns
all remaining capacity/service/recovery/operations work; hardware is supplied
later, not implicitly qualified by local tests.

Capacity remains 1,000 accounts / 100,000 signed retained transfers with distinct
external IDs: >502,000 logical actor rows before other indexes, over one million
outer Patricia blocks before chunks, not merely 200,000 primary values. Fixture one-million-row/1-GiB
ceilings are not production defaults or corpus evidence. No migration, dynamic
membership, external Local or broader redesign is included.
