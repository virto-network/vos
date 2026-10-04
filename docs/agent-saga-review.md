# Agent saga: review entry point

This is the sole reviewer handoff. [The live checklist](agent-saga-status.md)
owns scope, dependency order, forecasts, open gates and acceptance targets.
Review read-only and return findings for the implementation branch, not competing
fixes on the review branch.
Start with [the observation replacement](#active-priority-r37-observation-replacement)
and its current scoped R38 decoder correction. Older evidence is explicitly
frozen and cannot qualify later source.

## Boundary and release claim

The review branch remains `e6f2bb45` on `saga/agents`. Original replacement
source `8128e677` and its role bundle `7085c220` precede the corrected integration
source frozen at `2e19cd17` on `wip/ch08-runtime-directory`. Inspect the coherent
artifact repin and subsequent qualification delta as well. These checkpoints
are not a release promotion.
Verify actual heads and cleanliness before assuming fast-forward promotion.
`master` remains `d2378274`. No released fixed-three workflow or service capacity
is qualified by this diff yet.

The live checklist defines three usable exits: **M1 packaged recovery test
pilot**, **M2 full-data/backup pilot**, and **M3 qualified v1**. A pilot states its
demonstrated limits and does not waive any final workload, latency, recovery or
correctness gate. Review a frozen source/artifact boundary plus its acceptance
evidence and delta; internal passing suites are not a milestone exit.

Production Local remains image-based. Exact paired-role artifact pins are
staged; fixed-three startup stays closed pending packaged recovery qualification.
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

O1/O2 and O3 removal are implemented; corrected integration source is frozen,
with released workflow qualification still open. Explicit signed image opt-in, Observe tag 5,
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
- `release-observation-o3-single-audit-physical-debug-r37b.log`: **1 passed,
  67.75s**, the same physical observation slice plus an explicit exactly-one
  caught-up capacity audit assertion. The earlier `r37a` single-audit log ran
  zero tests due to a wrong filter and is not evidence.
- `release-observation-o3-critical-unit-debug-r37b.log`: **241 passed,
  10 ignored, 29.86s**. Six earlier failures were invalid management test
  fixtures (first-owner, anchor and reused identity), corrected without changing
  production invariants.
- `release-observation-o3-critical-unit-release-r37a.log`: the same **241 passed,
  10 ignored, 7.09s** in the portable optimized build.
- `release-observation-o3-local-image-regressions-r37a.log`: **2 passed, 2.58s**,
  canonical unchanged Local create/install/invoke/retry/locked reopen with
  candidate runtime overrides explicitly unset.
- `release-observation-o3-pinned-package-prewrite-r37d.log`: **40 passed,
  2 ignored, 8.47s**. Exact runtime/Authority/Catalog closure, old-format
  prewrite refusal, immutable retained startup target and typed exact CLI retry
  classification. This is component evidence, not daemon startup qualification.
- `release-observation-o3-cli-unit-debug-r37b.log`: **362 passed,
  52 ignored, 323.23s**, with allowed local loopback. This precedes the last
  packaged-role/prewrite source edits, so those edits still need fresh tests.
- Current SDK feature/default suites: **259 / 256 passed**, each 1 ignored.
  New System and external guests build/link; the actual paired signed-role and
  purity probe **passes 4.64s** (`release-observation-o3-runtime-role-probe-r37a.log`).
  Its explicit 1,000,000-row/1GiB ceilings are declarations, not capacity proof.
- `release-observation-o3-role-reproduction-r37a.log`: independent immutable
  `8128e677` builds match both runtime roles, Authority, Catalog and signed Clerk
  bytes; detailed evidence is in the active worktree's
  `target/agent-release-reproduction/run.OvqoaS`. Explicit limits remain unmeasured.
- `release-observation-o3-full-pinned-reproduction-r37a.log`: **passes**, using
  frozen builder `7085c220` and source `8128e677` for templates; unchanged Local
  runtime and strict six-file packaged closure match pins. Independent role
  rebuild evidence remains the separate two-pass reproduction above.
- `release-observation-o3-management-pruning-physical-release-r37a.log`:
  **fails 545.31s**. Restore, exact Create/Install and checkpoint votes pass;
  Install finalization takes **32.979s**, beyond unchanged 30s. Expensive repeated
  admission audits overlap heavy builds; isolate before changing execution.
  Earlier `SnapshotReplay` did not recur.
- `release-observation-o3-management-pruning-physical-release-r37b.log`:
  **passes 419.04s**, isolated with no concurrent builds/physical fixtures.
  Offline restore, exact Create/Install, checkpoint/pruning, ACK and custody
  release pass. Install finalization **21.588s** meets unchanged 30s. This closes
  that component regression, not the public Shared cold-start or M1 exit.

### Current integration delta and blocking result

Corrected source `2e19cd17` freezes these changes, which close demonstrated
M1 defects without changing authorization, wire bounds or deadlines:

- Ambiguous publication exact retry re-admits the original leased stores.
  `release-observation-o3-publication-exact-retry-physical-debug-r37b.log`
  **passes 36.44s**, including missing/substituted material refusal, preserved
  signed bytes/leases and no new rows on acknowledged retry. Finalization now
  keeps publication protection until exact terminal cleanup and checks fresh
  full GenesisDecision equality before normal management retirement.
- Caught-up observation reuses only one call's fresh audited cursor under the
  uninterrupted host guard and re-audits after application progress. The physical
  single-audit slice above passes; the complete packaged workflow must rerun.
- Readonly startup reuses the existing stage resolver, validates every canonical/
  staged signed candidate and fences the complete snapshot under the actual
  writer lease before reconciliation. Configured Space/local node/pins and exact
  packaged System/Authority/Catalog closure are bound before writes. Focused
  `release-observation-o3-staged-startup-{store,strict-client,semantic,core-factory}-r37a.log`
  pass **4 / 2 / 2 / 3 tests**. Strict clients and old-format refusal remain
  unchanged. Exact Pins-before-record requires the verified supplied plan and
  no Shared residue/lifecycle/history. Packaged interruption/cold-open and owner
  reopen now select normal admission, but are not qualified while both bails
  remain closed.

Exact Create finalization/recovery was the current component blocker.
`release-observation-o3-finalization-exact-retry-physical-debug-r37d.log`
**fails 92.09s** with GenesisDecision **Panicked** before retirement ACK.
Exact captured-input interpreter/recompiler replay
(`release-observation-o3-captured-backend-replay-r37a.log`, **3.49s**)
and ELF mapping reproduce nested genesis decoder stack overflow with gas
remaining. This is failure parity, not successful execution or performance
evidence.

The reviewed provisional R38 correction changes four provision component
decodes to the existing boxed, non-inlined helper in
`vos/src/agent/genesis.rs::AgentGenesisProvision::decode_body`; canonical wire,
signature/component validation and guest limits stay unchanged. Native genesis
checks **15 pass, 0.21s**
(`release-observation-o3-boxed-provision-genesis-tests-r38a.log`); Authority
guest build **passes 38.30s**
(`release-observation-o3-boxed-provision-authority-build-r38a.log`).
The expanded physical regression nevertheless **fails 99.03s**: post-handoff
exact retry takes **31.064s**, beyond unchanged **30s**
(`release-observation-o3-boxed-provision-finalization-physical-r38b.log`).
R38c scoped diagnostics establish repeated **Panicked** guest outcomes after
successful retirement handoff and before terminal cleanup (**98.79s**, post-handoff
bound failure **30.596s**, `release-observation-o3-boxed-provision-finalization-diagnostics-r38c.log`).
R38d fault-status diagnostics, without guest-memory collection, locate a stack
page fault in `ProofSystemSet::from_sorted` during nested Create-capability decode,
with gas remaining. Exact ELF/program mapping passes
(`release-observation-o3-boxed-provision-fault-map-r38d.log`). The four-call provision
correction is insufficient. Direct decode in the existing boxed helper removes
its extra by-value helper frame with identical byte bounds, decode errors and
successful allocation. Native genesis checks **15 pass, 0.19s**
(`release-observation-o3-direct-boxed-genesis-tests-r38e.log`); uninstrumented
Authority build **passes 31.96s**
(`release-observation-o3-direct-boxed-authority-build-r38e.log`). R38e execution
completes but refuses the fixture's unenrolled API observation credential.
R38g scoped phase diagnostics confirm authentication refusal after provision,
publication binding and certificate verification; no authentication check is removed.

The fixture now enrolls that credential through ordinary signed Admin Invoke/ACK,
asserts non-retaining refusal before enrollment and authenticated acceptance after
it. `release-observation-o3-enrolled-finalization-physical-r38h.log` **passes
81.37s**: pre-Invoke and post-handoff interruption, original leased stores,
fresh exact GenesisDecision, finalization/retirement ACKs and custody release.
Post-handoff retry **8.846s** meets unchanged **30s**. This is candidate Authority
plus prior System runtime component evidence. Isolated quiet confirmation
`release-observation-o3-enrolled-finalization-quiet-r38i.log` **passes 91.91s**.
Coherent signed-artifact reproduction precedes cutover. Packaged recovery and M1
remain open. Temporary guest/host probes and private-input capture helpers have
been removed; regression coverage and disk evidence remain.

`release-observation-o3-coherent-role-reproduction-r38j.log` passes two independent
builds from corrected `2e19cd17`: System/Shared runtime ELFs and programs, all four
signed templates and signed Clerk bytes match. Detailed evidence is
`target/agent-release-reproduction/run.1JsTwa` under the native worktree. The coherent
repin preserves Local's canonical image runtime. The artifact-bearing builder
checkpoint, strict six-file verification and packaged recovery still precede
normal startup admission; reproduction alone does not close M1.

The portable full CLI suite previously **passes 375 tests**, 52 ignored, 39.53s
(`release-observation-o3-cli-unit-release-r37a.log`); that boundary predates the
latest startup/decoder edits. Prior packaged failure timelines remain in
`release-observation-o3-packaged-public-{release-r37b,release-r37c,debug-r37d}.log`.
They do not qualify current workflow or release latency.

Earlier frozen O2 evidence is retained at `release-observation-o2-r37j-test-binary`
(BLAKE2b-256 `3fa8049f1587f1202d86d30a3c7995e1052739bab343f2ed197fdc76b78852c9`),
with 38 consumer/publication/archive-phase checks and a 76.43s physical slice.
It does not qualify later O3 source. SAC7 constructor/directory binding was a
necessary contract fix, not a relaxed matcher. An overbroad network deletion
was caught and exactly restored from the archived dirty source before the
current checks; generic execution was structurally audited.

No packaged workflow/SLA, blanket filesystem-write trace, hard wall-clock bound
under stalled locks/disk, live-root replacement or mid-guest term/config-change
qualification is claimed. Artifact repins are staged, not release-qualified;
no release gate or review branch has been promoted. Packaged startup binds exact
System/Authority/Catalog closure before writes: SAC7 alone cannot identify O3's
management-only RMF4 lineage. The full reproducer passes with artifact-bearing
builder `7085c220`. The direct CLI acceptance script is unrun.

### Implemented contract; integrated qualification remains open

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
- One explicit scoped guest observation operation exists: normal Query still
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

Current review seams: `vos-agent-sdk/src/runtime.rs` / `contract.rs` (Observe
and explicit signed opt-in), `vos/src/agent/wire.rs::apply_clean_observe`,
`local_journal_driver.rs::observe_system_authority` (physical opaque-state
validation), `network/shared_agent/authority_observation.rs` (ReadIndex,
apply-through and lifecycle fencing), `clean_bootstrap.rs::invoke_authority_observation`
(internal consumer), and `actors/system-authority/src/lib.rs` (SAC7 binding,
signed query authentication and pure handlers). Existing ReadIndex is in
`support/vos-raft/src/worker.rs`; the global ABI/mutation wire is unchanged.

### Completed deletion inventory to verify in the final diff

| Boundary | Removed internal-read path | Must remain / implementation trap |
| --- | --- | --- |
| Inventory/credential client | Pending recovery/context/live continuation and `in_flight_query` in `production_owner.rs`; unused query-specific scheduling | Signed query auth, exact head/claims, complete inventory assembly and route publication; no mixed pages/cache-on-error. |
| System bootstrap reads | PAP2/PPR1, bootstrap pending read, read registration/dependency/expiry/Invoke/ACK in `clean_bootstrap.rs` | Bootstrap Authority/Catalog receipts, exact signed plan admission and management lifecycle/reopen. No unsigned legacy-record clearing. |
| Genesis decision | Ordinary delegated and management-anchored read variants, `invoke_genesis_recovery_read` and read-only child anchors | Guest validates permanent decision and exact provision; fresh complete descriptor/roster before application/readiness. |
| Member admission/cold Install | Custody-specific `ColdMemberProjectionScope`, read pair and combined read replay budgeting | Complete independently leased required set, scoped Root authorization, exact retained parent, fresh facts, generation recheck and staged publication; no blanket readiness exemption. |
| Genesis committee selection | `RetainedCommitteeQuery` GCW1/read reply, deterministic read invocation and ACK child | Authenticated committee observation; immutable selected roster/lease; exact certified candidate/signatures/archive; publication successor of original authorization. |
| Supervisor/network | Read recovery commands/accessors, `ProjectionRecoveryRequest`, read registration/disposition/expiry RPCs, read pair/dependency dispatch in `agent_protocol`, `agent_network`, `shared_agent` and `projection_recovery` | Authenticated routes, worker lifetime/bounds, Raft, ordinary availability, public exact invocation and bounded original-owner management forwarding. |
| Custody manifest | Read registration/request, read slots/sequence/watermark, expiry floor/claim/certificate/terminal, exclusive unfinished-read rule | Management slots/MRQ2 ownership, shared first Invoke/positive ACK evidence and Register/ReleaseManagementRecovery. Rename remaining helpers instead of deleting shared authentication. |
| Raft/checkpoint/replay | `RegisterRecovery`, `ExpireRecovery`, read-specific dispositions, folds/dependency pins and expiry checks | Accepted ordinary rows apply harmlessly; mutation/management replay, physical store binding, certified manifest commitment and pruning/reopen evidence. |
| SDK/Authority wire | Internal durable-read delegation producers/branches and obsolete tests once unused | Request signatures, SSH attestation, selectors/visibility/revocation, heads/limits and unrelated public actor query semantics. No silently overloaded Invoke or broad compatibility decoder. |
| Bootstrap/native formats | Old read-containing CSB2/PAP2/GCW1/RMF/ASR formats on the fresh-space path; old-code recovery fallback | Explicit prewrite old-space refusal and coherent new artifact/version admission. Preserve normal immutable closure and management state in the new format. |

Critical shared-store/code checks:

- `SharedRecoveryObservation` still serves management root/successor evidence
  in `shared_recovery/management.rs`. Management-only RMF4 and snapshot/ASR
  commitments remain; ordinary public Query Invoke/ACK keeps exact semantics.
- `NativeSharedCreateRecovery.query` still owns immutable selected replica
  material and its lease; GCW1/read replies are gone, not that recovery authority.
- Genesis publication extends the original retained authorization after removal
  of the committee-read child. Verify full work/predecessor/owner binding,
  capacity/signatures and durable terminal release through live and cold retry.
- Existing image Local program/space bindings must not be silently rebound.
  Global ABI/version changes require coherent admitted artifacts and Local
  regression evidence, not an assumption of backward compatibility.

### Existing ReadIndex primitive evidence and review acceptance

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
The preliminary source audit confirmed the receiver-owned authenticated-CFT
design and mixed read/management deletion boundary. It predates implementation.

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

## Archived legacy evidence

R36 is forensic evidence, not an active task, supported fallback or qualification
of observation. Source and full prior reviewer chronology are recoverable at
`e6f2bb45:docs/agent-saga-review.md` and the disk-backed target archive
`release-observation-docs-before-replacement-r37.tar.gz`, SHA-256
`10ecf3d7b5b9c6aa094ba97d234e52051e8dcbc825fc4b4cbbc11132fb56af7a`.
Preserve these files; do not replay old formats as permission to reopen or clear
experimental spaces.

Frozen logs retain the legacy boundary without duplicating its chronology here:

- R36s root/child retention and pruning:
  `release-integration-observation-serialization-root-child-physical-opt-r36s.log`.
- R36x retained-only Create/duplicate/reopen and failed public workflow:
  `release-integration-retained-create-{duplicate-read,warm-public}-physical-opt-r36x.log`.
- R36y expiry-eligibility diagnostic, failed public attempt and controlled
  never-admitted refusal:
  `release-integration-expiry-eligibility-{selected-phase,warm-public-physical,expired-unadmitted-physical}-debug-r36y.log`.

Absence of current custody never proved historical absence or authorized
retirement. The additional never-admitted read-finality proposal is superseded
by the approved replacement. Management clocks, exact terminal evidence and
public retry remain authoritative. Old draft role patches and guest hashes are
not current packaged selection or artifact evidence.

## Offline signed corpus tooling

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
