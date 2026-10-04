# Agent saga: v1 release checklist

This is the single live plan. [The review guide](agent-saga-review.md) is the
sole reviewer entry point. Implementation, integration and qualification are
different milestones. Internal tests or a checkpoint do not constitute release.

## Approved scope and next integrated milestone

Ship Linux x86-64, a fixed authenticated three-node Shared deployment,
production image-based Local Agents, and one external-state Shared Clerk.
Fresh external roots are required; no migration or public external-Local cutover.
The workload, latency, recovery and correctness targets below are unchanged.

Approved next priority (2026-10-02): replace internal durable Authority reads
with scoped observations and remove the obsolete read lifecycle. Fresh v1
spaces are required, including System/control and Shared roots; existing
experimental spaces stay untouched and are unsupported by the new binary.
Local execution/format remains image-based. No migration or legacy-read fallback.

The next milestone is the **released three-process Shared Clerk workflow**:
public Create/Install/Invoke, lost response, restart/catch-up and leader loss,
recovering the exact result through real filesystem owners and public routing.
Acceptance uses packaged artifacts and ordinary authenticated identities, not
test signers, environment-only guests, fake quorum or hand-edited journals.
A small vertical slice proves integration only, not capacity or service targets.

Review branch: `e6f2bb45` on `saga/agents`. Original replacement source `8128e677`
and its role bundle `7085c220` precede the decoder/integration correction.
Corrected source is frozen at `2e19cd17` on `wip/ch08-runtime-directory`;
two independent builds match both runtime roles, Authority, Catalog and signed
Clerk bytes. The coherent pin update is frozen at `da86c686`, with verifier
provenance at `39f1f6bb`. These
checkpoints are not a release promotion.
Verify actual heads/cleanliness before assuming promotion.
`master` remains `d2378274`. No push, master change, artifact pin promotion or
deployment is automatic.

## Current position

| Mandatory gate | Implementation | Integration / qualification |
| --- | --- | --- |
| Internal Authority observations | O1/O2 and O3 removal are implemented: no read custody/transport/apply/expiry lifecycle. Management retention and public Invoke/ACK remain. | Current physical observation **passes 67.75s**, including exactly one caught-up audit and existing freshness/no-write/cancellation/reopen cases. Optimized management/replay/owner/supervisor/protocol/observation checks **241/241** pass (10 ignored, 7.09s). SDK **259 + 256 passed**, each 1 ignored. Paired signed-role/purity probes **pass 4.64s** with explicit, unmeasured limits. Packaged closure/startup/retry checks **40 passed**, 2 ignored. No released workflow or SLA pass. |
| External storage/restore | Incremental executor, immutable closure, ACX1 publication and exact marker retirement exist. | Historical optimized reopen/crash-cut slices pass; the released workflow must requalify. |
| System management recovery | Parent retention, immutable MRQ2 first-owner binding, exact mutation evidence, signed terminal release and recovery remain. | Isolated optimized offline-pruning test **passes 419.04s**: restore, exact Create/Install, checkpoint/pruning, ACK and custody release. Install finalization **21.588s** meets unchanged 30s. Earlier contended 32.979s failure remains recorded, not waived or tuned away. Returning/all-cold Shared pending-Install remain unqualified. |
| Member/public management | Packaged PublicWorkflow selects exact bundled roles and ordinary CLI Create. Ambiguous publication re-admits the original leased stores before exact retry. Finalization retains publication protection and verifies fresh decision state before exact terminal cleanup. Packaged reopen helpers explicitly use normal startup admission. Provision components use the existing boxed decoder, whose direct decode removes an extra by-value scratch frame without changing wire, validation or limits. | Native genesis checks **15 passed, 0.19s**. Expanded exact-finalization retry on independently reproduced coherent components **passes 96.21s** (`release-observation-o3-coherent-finalization-physical-r38n.log`), with unchanged 30s phase bounds. The fixture uses ordinary signed Admin Invoke/ACK to enroll its API observation credential and verifies refusal before enrollment. Source and six-file bundle reproduction pass. Install/lost-result/reopen, packaged cold recovery and actual three-process acceptance remain open. |
| Service/operations | Offline signed corpus generator, bounded public corpus loader and read-only hardware collector exist. Loader resumes exact private ATQ1 through existing CLI/ASR1 verification and independently replays accepted seeds/order for all six maps. | Loader tooling tests **7 passed, 0.10s**; it has not executed public data. M1 setup and pre-granted signed Clerk Operator/Member roles are prerequisites. Public retained loading, resources/recovery, backup/restore, overload, soak and hardware qualification remain open. |

R36y is the frozen, superseded legacy-read diagnostic boundary, not qualification
of this replacement. The review guide points to its archived evidence; there
is no legacy-read fallback or further expiry/finality extension. Do not add
management Busy, change signed mutation windows/deadlines, or clear old spaces.

Bundled role materialization and strict six-file release verification are
implemented. Independent builds from corrected `2e19cd17` match byte-for-byte for
both roles, Authority, Catalog and signed Clerk. Exact signed role pins are committed;
normal fixed-three startup was deliberately opened after coherent reproduction,
prewrite/refusal checks and isolated finalization. Packaged recovery qualification
remains open. Exact Catalog closure and retained-plan target selection are
implemented and their focused refusal tests pass. CLI defaults select existing
external-state components for Shared, without changing image Local. R38j
reproduction evidence is `release-observation-o3-coherent-role-reproduction-r38j.log`
and `target/agent-release-reproduction/run.1JsTwa` under the native worktree.
The artifact-bearing builder checkpoint is `da86c686`; strict six-file
verification passes (`release-observation-o3-coherent-full-pinned-reproduction-r38k.log`,
evidence `target/agent-release-reproduction/run.ykT3eh` under the native worktree).
The old `7085c220` full bundle check cannot qualify later source.
The existing enrollment/common-genesis and Shared Create/admit/Install/call/resume
CLI are reused; no new CLI/signing framework is needed. The direct three-process
CLI acceptance script's first run R38u is unresolved as recorded below; it does
not claim load, hardware, mutation-loss or non-root qualification.

The active diff closes demonstrated M1 defects, not new capabilities:

- Exact publication retry re-admits the original leased stores after an ambiguous
  write; its three-node component regression **passes 36.44s**. Publication
  protection now survives ambiguous finalization until exact terminal cleanup.
- Caught-up observations reuse a fresh cursor only under the same uninterrupted
  host guard, re-audit after application progress and retain all freshness fences.
  The actual observation slice passes; the packaged workflow must still rerun.
- Startup rejects orphaned Shared roots, binds configured Space/local node/pins,
  validates every canonical/staged signed candidate and compares the complete
  inspection under the actual writer lease before reconciliation. Focused checks
  pass: **4 store/fence**, **2 strict-client**, **2 semantic prewrite**, and
  **3 core factory**. Exact Pins-before-record initialization requires the verified
  supplied plan and no Shared residue or lifecycle/operation history. Strict
  client reading and old-format refusal are unchanged. Packaged interruption/
  cold-open and normal reopen helpers are prepared, not qualified.
- Current coherent source passes **3 startup inspection**, **2 exact package
  prewrite**, **87 store checks** (including both strict client readers), and
  **3 core factory** tests. The store suite's one loopback sandbox refusal passes
  its exact permitted rerun; it is not a waived failure. Logs:
  `release-observation-o3-coherent-{startup,package,store}-prewrite-r38l.log`,
  `release-observation-o3-coherent-store-loopback-r38m.log` and
  `release-observation-o3-coherent-core-factory-r38m.log`. The separate client
  filter selected zero tests and is not evidence. Isolated finalization on the
  coherent components **passes 96.21s** (`release-observation-o3-coherent-finalization-physical-r38n.log`).
  The two startup bails are deliberately removed: preflight returns the actual
  inspected snapshot, and its leased comparison remains before reconciliation.
  The staged-admission regression now asserts exact returned snapshot equality.
  Current debug CLI unit suite **passes 381 tests**, 52 ignored, **314.36s**
  (`release-observation-o3-open-startup-cli-unit-r38o.log`). Packaged recovery
  qualification follows this opening; the ignored fixtures are not passes.
- Packaged public debug run R38p **fails 143.94s** during ordinary CLI Shared
  Create: repeated HTTP 503 exhausts the existing 120s correctness retry cap;
  Install/lost-response/reopen are not reached. R38q diagnostics show ready
  dispatch and successful authorization/candidate/committee preparation, then
  forwarded custody timeouts while the leader later commits publication and
  finalization. Repeated guarded validation contributes measurable delay.
  This is debug-host evidence, not an established release performance defect.
  Portable current main and test harness R38r each build in about seven minutes
  with empty RUSTFLAGS. Optimized R38s completes Create but **fails 212.17s** at
  the first nonleader Install HTTP 503. It had not resumed the retained SIQ1.
  Optimized scoped diagnostics R38t **fail 53.18s** earlier: a delayed signed
  registration extension replaces the owner slot while an exact root retry is
  in flight, producing a permanent registration ScopeMismatch. This is a
  demonstrated retry race, not proof of guest failure or a solved timing gate.
  The narrow origin correction authenticates the current same-owner exact
  member, then returns Conflict before reading evidence if registration changed;
  the receiver still refuses the stale digest. A signed-manifest regression
  passes, including exact retained result and wrong owner/member/anchor refusals.
  The packaged Install fixture now resumes the normal CLI operation and asserts
  its unchanged retained root/SIQ1 within the existing 120s correctness cap.
  The corrected portable integrated workflow remains unqualified. Preserve
  forwarding/recovery bounds; no service-tuning pass is consumed.
- Portable R39a main and optimized harness build from clean `7d08ee95` in
  **7m04s / 7m07s**, with empty RUSTFLAGS and recorded binary provenance.
  Public R39b **fails 241.95s**: Create completes, but normal exact nonleader
  Install retries exhaust the unchanged 120s correctness cap. Scoped R39c
  **fails 255.73s** and establishes a recovery-admission deadlock before
  Authority management Invoke: original registration custody waits **2.058s**,
  the leader commits after **7.599s**, and the same origin quarantines on
  observation Unavailable. Protected admission prevents inventory refresh;
  HTTP quarantine refuses all subsequent Install retries before dispatch.
  No Install guest execution, application or terminal release is established.
  The correction carries retained-only admission through the queue,
  matches the original coordinator's exact signed intent and admitted package,
  then uses existing completion. Fresh custody remains forbidden while
  quarantined; normal leased sidecar reconciliation remains intact. This is
  correctness integration, not a service-tuning pass. Public qualification is
  still open; R39b/R39c finish without the earlier shutdown liveness error.
  Independent review finds no blocker. Native R39d signed-input, owner/queue
  and HTTP checks **61 pass, 1.53s** after a **1m45s** build; exact, changed,
  missing and member-only inputs and both readiness races are covered. These
  are admission checks, not physical Install/finality qualification.
- Portable R39e main and optimized harness build from clean `d3408382` in
  **7m00s / 8m18s**, with empty RUSTFLAGS and recorded provenance. Quiet public
  R39f **fails 133.10s** on a credential-discovery HTTP 503 whose typed cause
  was lost by its diagnostic wrapper. Scoped R39g **fails 312.19s** after
  verified nonleader Install, at a one-shot credential query for the next
  Clerk Operator role grant. Lost mutation response and reopen are not reached.
  The cumulative Install stage marker is not a standalone Install duration.
  The current narrow correction preserves typed HTTP/transport causes in
  credential/admin delivery and gives the fixture the existing 120s retry
  bound. Before a new durable admin claim it retries discovery/preparation;
  afterward it resumes only the exact signed role grant, fencing all retained
  evidence. Earlier completed claims cannot select resume. Independent review
  finds no blocker. Native R39h build **passes 40.48s**; three new regressions
  **pass 0.28s**, and related CLI checks **14 pass**, 1 ignored, **4.24s**
  (`release-observation-o3-cli-transport-{test-build,regressions,related}-r39h.log`).
  The correction is frozen at `d5459f66`; portable R39i main/harness **pass
  3m29s / 3m28s** with provenance recorded. Public R39j **fails 418.17s**:
  verified nonleader Install at cumulative **129470ms**, then the existing
  role-grant retry cap expires on `/__agents/admin` HTTP 503. Discovery and
  preparation advanced. Scoped R39k **fails 333.13s** earlier at the nonleader
  Install retry cap: Authority approval/receipt and local retained Install
  replay are verified, but finalization/release/SIR1 delivery are not.
  Neither run reaches lost mutation response/reopen. Observation errors alone
  cannot distinguish guest execution from freshness failure because their
  outcome diagnostics were test-only in the CLI-linked core dependency. The
  existing two scoped outcome blocks are temporarily enabled behind the same
  diagnostic flag; remove that temporary visibility after attribution. A
  possible pre-NAD2 admin retention seam is a source hypothesis, not yet the
  established R39j cause. No observation bypass, authorization change, deadline
  increase or service-tuning pass is introduced.
- Optimized harness R39l builds from clean `a1780e83` in **7m02s**, with empty
  RUSTFLAGS and recorded provenance. Scoped public R39m **fails 457.34s**:
  verified nonleader Install at cumulative **135506ms**, then the Clerk Operator
  role grant exceeds its unchanged 120s correctness bound. All **88** visible
  observation guests return `Done`; no guest refusal, non-completed outcome or
  host refusal is recorded. Of **23** outer Unavailable refusals, eight follow
  guest completion and fifteen have no adjacent completion. Associated guest
  calls take **0.186–0.371s**; total coordination/apply/guard time is not yet
  attributed. Custody timeout followed by later commit does not establish admin
  finalization or terminal release. Lost mutation response/reopen remain
  unreached. Temporary scoped guard diagnostics will distinguish the actual
  freshness refusal without changing guard order, ownership or the **1.8s**
  observation bound; remove them after attribution. Log:
  `release-observation-o3-packaged-public-outcomes-r39m.log`.
- Scoped guard harness R39n builds from clean `32b12b0b` **passes 7m06s**.
  Public R39o **fails 369.77s** at the same Operator role-grant 120s retry cap
  after verified nonleader Install at cumulative **133140ms**. All **70** visible
  guests return `Done`, with no guest/host refusal or non-completed outcome.
  Its **15** outer refusals are attributed: five post-guest deadline failures
  (**1.854–2.040s** total), four pre-guest deadline failures (**1.983–3.450s**),
  and six barrier-delivery timeouts (about **1.800s**). No term/configuration,
  ownership or stale-generation rejection appears. These are correct enforced
  freshness failures, not permission to relax the 1.8s bound. The role-grant
  recovery cause is still unproven: registration times out at its origin and
  commits later, followed by quarantine. Observation diagnostic visibility and
  guard labels are removed after attribution; only scoped admin phase/boolean
  diagnostics are now provisional. Logs/provenance:
  `release-observation-o3-observation-guards-cli-{build,provenance}-r39n.*`,
  `release-observation-o3-packaged-public-guards-r39o.log`.
  The attempted native admin regression builds **52.07s**, but both it (**2.64s**)
  and the unchanged baseline (**2.43s**) fail before the intended cut: their
  historical singleton fixture cannot pass authenticated fixed-three manifest
  inspection. Neither establishes the proposed admin defect. The new singleton
  test is removed; reuse the existing three-node fixture for the signed cut,
  without adding singleton support or test-policy bypass. R39p/R39p2 logs retain
  this precondition boundary; an earlier missing Duration namespace was corrected.
- The >256 fixture's final locked-owner reopen now measures from before all
  constructors through production attachment/readiness, retained handoff and
  exact archived native-result verification using one unchanged **30s** bound.
  Its two HTTP retries share that absolute deadline and late completion fails.
  Source review passes; execution remains pending. Running transports and one
  published supervisor do not prove whole-process/every-member readiness.
- First actual three-process CLI run R38u uses the provenance-recorded portable
  binary and exact six-file bundle. Readiness passes **9.744s**, then initial
  Local Create returns an ambiguous HTTP 503 after **10.776s**. The script exits
  without normal --resume, so this is not evidence of a persistent Local defect.
  All owned processes exited; one worker reports InvalidConfiguration during
  simultaneous shutdown, after peers begin stopping. Exact CLI resume and
  cleanup qualification remain open; private evidence is preserved.
- The script now fences the fresh operation and every retained client file
  before normal --resume; all attempts share its existing whole 180s command
  budget. Signed denials and invalid inputs fail. Shell/Python syntax checks
  pass; actual corrected-script delivery and cleanup remain unqualified.
- Normal-shutdown InvalidConfiguration is reproduced by holding inventory I/O,
  requesting explicit cancellation, then returning ProjectionNotReady. Unchanged
  production fails **0.05s**. A single Acquire shutdown recheck inside the final
  failed owner-liveness branch preserves all earlier fatal errors and checked
  retirement; **7 focused checks pass**, including fatal inventory/panic controls.
  Logs are `release-observation-o3-r38w-shutdown-regression-{before,after}.log`.
  Actual three-process cleanup still requires qualification. The interrupted
  R38w portable build is not evidence.
- A separate packaged Shared-leader-loss selector is prepared. It stops the
  actual Shared leader before public mutation dispatch and after commit/pre-ACK,
  verifies exact result recovery at the online original issuer, then normally
  reopens each stopped owner before the next cut. Both fault and returning-owner
  phases have whole 30s bounds, including stop/open and verified completion.
  Exactly one owner is offline during either fault. It does not claim an accepted
  in-flight precommit crash or System mutation failover. Independent review
  caught and corrected the retry fixture's premature Completed assertion;
  success still requires completion and every retry retains identical SIQ1.
  Current CLI debug harness compiles **4.08s** after the final correction
  (`release-observation-o3-leader-loss-cli-test-final-r38x.log`). Portable build
  and actual execution remain pending.
- `vos/examples/clerk_corpus_public.rs` prepares M2's public retained loader via
  existing invoke/submit CLI commands, with stable intents, exact result checks,
  durable verification identities and six-map accepted-context reference replay.
  Its host-only opt-in uses existing std/http-ingress features. Independent
  source review and seven focused tests pass (`release-observation-o3-public-corpus-tool-tests-r38v.log`);
  the interrupted cold debug build is not evidence. No corpus has been publicly
  loaded; signed resource, backup/recovery and full-data qualification remain open.
- Exact backend replay and ELF mapping identify nested genesis decoder stack use.
  Four boxed provision calls were insufficient; direct decode in the existing
  boxed helper removes the overlapping helper scratch frame. The uninstrumented
  guest then completes and refuses an unenrolled API observation credential.
  Scoped phase evidence confirms that refusal; the fixture now uses normal signed
  enrollment and verifies both refusal and acceptance. Expanded publication/
  finalization retry passes, including pre-Invoke and post-handoff interruption,
  fresh decision equality, exact parent ACKs, custody release and retained leases.
  Temporary guest/host diagnostic scaffolding and private-input capture helpers
  have been removed. Evidence remains on disk; no authorization, wire, gas,
  memory or deadline relaxation was needed. Coherent release qualification is open.

The portable full CLI suite previously passed **375 tests**, 52 ignored, 39.53s;
that boundary predates the latest startup/decode changes and cannot qualify them.
No new authorization, deadline, memory limit, fallback or release promotion is
approved. Corrected source is frozen; its released workflow is not qualified.

## Approved replacement: contract and acceptance

This is an approved architectural simplification on M1's critical path, not a
new profile, general query framework or relaxation of release targets.
Observations return authenticated values at a committed revision. A lost reply
or restarted observer may obtain a fresh observation; it does not retain an
obligation to recover the first inventory answer. Public actor Invoke/ACK,
Create/Install identities, exact mutation results and parent recovery stay
unchanged.

### Scoped consumers and execution contract

Replace every internal System Authority read used by credential/inventory
refresh, Agent/replica/actor projections, genesis signing-committee selection,
GenesisDecision verification, member admission and returning/all-cold pending
Install recovery. Cover ordinary and management-anchored read variants together.
No fallback to a retained read path, implicit special-case actor execution,
new public observation endpoint or arbitrary actor query redesign.

Reuse the installed Authority guest, existing signed credential/SSH
authentication, package/schema/policy checks, revision heads, exact System
route and complete retained-member restriction. The runtime owns its state.
One explicit scoped non-retaining execution operation must enforce unchanged
**whole opaque runtime state**, no external StateChange/root advance, no retained
result, ACK, consumed authorization, continuation, Yield/Await or outbound effect.
Existing normal Query is not sufficient: it still stores a runtime result.
Do not simulate purity by dropping a mutating transition or decoding Standard/
Authority-private layouts. Preserve existing gas/output/read bounds.

### Freshness and receiver-owned verification

Baseline is the existing authenticated crash-fault model, not a new Byzantine
guarantee or a trusted remote page:

1. The System leader calls existing bounded ReadIndex; role/status sampling or
   commit-equals-tail cannot replace fresh majority contact.
2. An internal follower obtains a fresh, correlated barrier over existing
   authenticated transport, bound to exact System route/generation, admitted
   committee/configuration, leader term and required index R. A small typed
   barrier request/reply is integration plumbing, not a new quorum protocol.
3. The consumer independently verifies its own committed System prefix and
   application frontier A >= R, then captures its admitted runtime/artifacts and
   actual state under an immutable per-open pin and executes the guest locally.
   The latest actor-state publication J may be below R after leader no-ops;
   authenticate that linkage rather than requiring J >= R.
4. Credentials/visibility and returned facts use the same pinned revision and
   trusted observation clock. Recheck attachment, configuration, lifecycle and
   per-open identity after peer I/O; a changed/retired generation refuses.
5. No host/proposal mutex crosses ReadIndex or network I/O. Reuse bounded
   cancellation/permits/lifecycle leases. Failed or timed-out observations release
   volatile resources and leave no read obligation.

The barrier is not a transferable certificate. Preserve all actual genesis,
publication, transfer and checkpoint certificates. Reject the design if a
mandatory consumer lacks a complete independently authenticated local System
state; do not silently substitute a leader-supplied answer. All mandatory
consumer paths must demonstrate this precondition before cutover.

Pagination initially reuses exact head/credential-claim consistency:
discard partial collections and restart with bounded attempts if either changes.
Do not publish mixed/partial routes or add durable snapshot sessions.
Continuous Authority mutation may cause repeated restarts; qualify liveness
under the unchanged release workload early, rather than assume it is harmless.
A concurrent later revocation can race a completed observation; an old
observation never authorizes a future mutation.

### Coherent cutover and removal boundary

Removal inventory is in the review guide. Delete read-specific producers,
PAP2/registration/expiry/dependency recovery, Invoke/ACK read dispatch, transport
and Raft dispositions, custody slots/expiry floor and read-only checkpoint pins
once all consumers use observation. Remove read-specific scheduling/combined
replay-budget work only where no management/public use remains. Rename shared
helpers by their remaining purpose; no runtime flag or catch-error legacy fallback.

Keep exact signed management intent, first Invoke/positive ACK evidence,
MRQ2 ownership/families, Register/ReleaseManagementRecovery and authenticated
checkpoint retention. SharedRecoveryObservation and manifest commitments also
serve management; they cannot be deleted wholesale. The native 'query' store
also owns selected replica material: preserve its immutable bytes/lease while
removing GCW1 and read-reply capsules. Genesis publication must remain a successor
of the original retained authorization, not lose its predecessor/owner guards
when the committee-query child is removed.

**Fresh-space cutover approved:** require fresh System/control as well as Shared
roots with a coherent new signed artifact set. Earlier approval covered only
external roots; the user explicitly approved fresh v1 spaces on 2026-10-02.
Existing experimental System formats must be rejected before durable writes,
never cleared/reset/
converted; old spaces remain untouched. Existing image Local execution/format
stays intact and cannot be silently rebound to a new Authority generation.
No global ABI bump or old-space reopen promise without evidence. The replacement
binary does not support existing experimental spaces; do not implement migration.
No legacy-read decoder/execution fallback is an acceptable shortcut.

### Acceptance of the replacement

- [ ] Receiver-owned leader/follower observations verify fresh ReadIndex,
  authenticated apply-through (including no-ops), exact runtime/artifacts, clock,
  state pin, signature/revocation, full IDs and route/configuration. Minority,
  stale reply/leader, incomplete state and lifecycle/reopen races refuse.
- [ ] Actual image-System PVM observation preserves opaque runtime and actor
  state; hostile/custom fixtures changing metadata, roots, rows or producing
  effects/yields/continuations refuse. No native Authority oracle substitutes.
- [ ] After required catch-up, each selector adds **no request WAL, read custody,
  retained result, ACK or read-specific log record**. Existing committed writes
  and election no-ops are not misreported as observation writes.
- [ ] Lost response, canceled request, expired attempt, restart and distinct
  concurrent observations require no read settlement and cannot strand routes.
  Bounded queues/cancellation remain joinable; no deadline/cap inflation.
- [ ] Revision/claim changes discard partial inventory; concurrent Authority
  writes still permit bounded progress at the approved workload.
- [ ] Complete member proofs, wrong roster/runtime/archive/target refusals and
  cold pending Install use observation without releasing or transferring the
  parent. Genesis decision alone remains insufficient for application/readiness.
- [ ] Public Create/admit/Install/Invoke, genuinely lost mutation response,
  exact retry, locked reopen, returning/all-cold Install, leader loss and
  checkpoint/pruning pass with management evidence unchanged.
- [ ] The removal inventory is closed: no live durable internal-read producer,
  recovery transport/apply branch or fallback survives. Old-format prewrite
  rejection, coherent artifact reproduction and image Local regressions pass.
  Relevant old tests are replaced by observation negatives, not blindly deleted.

## Critical path and forecast

M1 remains the next integrated release milestone; M2 and M3 remain unchanged.
The approved observation replacement now precedes the rest of M1. It can delay
M1, but must reduce the final supported design to one internal-read path.
An internal primitive/checkpoint is not a usable exit or a deployment claim.

| Milestone | Usable exit and acceptance | Claim / remaining limits |
| --- | --- | --- |
| **M1: recoverable packaged test pilot** | Fresh fixed-three startup through ordinary CLI/HTTP, system actors ready, image Local and external Shared Clerk; authenticated Create/Install/Invoke/read/denial; exact lost-result retry, locked reopen, returning/all-cold pending Install and leader-loss recovery; observation freshness/cancellation, mutation-expiry/forwarding negatives and >256 authorization/pruning checks. Reproducible signed role artifacts, setup/acceptance script and recorded tested workload. | A working test-environment release at its demonstrated small workload, not full-capacity or service-qualified v1. Candidate-only tests cannot close this exit. |
| **M2: full-data operational pilot** | Publicly load and retain 1,000 accounts/100,000 signed transfers and external IDs; independently verify all six maps against accepted execution contexts. Measure signed row/byte/resource bounds, qualify checkpoint/catch-up/reopen and <=30s recovery at that data size, and authenticate Agent backup/restore including image Local state and exact retries. Re-run M1 on the resulting exact artifacts. | Usable with the qualified retained dataset and recovery/backup procedure; the 300-client SLA remains open. |
| **M3: qualified v1** | Exact release on the three approved hardware nodes; 300 clients, 80/20 mix plus unrelated activity, p95<=1s/p99<=2s, 30-minute load and 24-hour soak; overload/partition/minority/crash/restore checks, <=30s failover, bounded resources, differential/reproducibility and final independent review. | Release/merge candidate only after every mandatory gate passes. Hardware unavailability stays explicit; operator authorizes deployment/cutover. |


Implementation is grouped into **three scoped review chunks**, not new release
milestones or many small checkpoint reviews:

| Chunk | Dependency / deliverable | Acceptance before progressing | Original source estimate, not remaining effort |
| --- | --- | --- | --- |
| O1: pure observation and fresh local state | Fix scoped runtime/transport contract; reuse ReadIndex and authenticated local apply/pin. No host-private Authority decoding or remote page trust. | Physical guest purity, wrong scope/artifact/state refusal; leader/follower freshness including no-op linkage, cancellation and retirement. | **6–12 hours**, medium-low confidence. |
| O2: complete internal consumer cutover | O1; inventory/credential, committee, ordinary/anchored genesis decision, complete member proofs and native recovery all use observation. | No read-specific durable publication for each selector; lost observation/restart needs no settlement; original management publication chain/roster intact. | **8–16 hours**, low confidence. |
| O3: delete old read lifecycle and qualify workflow | O2 plus approved fresh-space artifact/format cutover; remove all old live producers/transport/apply/custody/expiry paths and superseded tests. | Public Create/admit/Install/Invoke, lost mutation response/exact retry/reopen, pending-Install/cold/leader loss and pruning; old-format prewrite refusal and Local regressions. | **8–16 hours**, low confidence, plus artifact/physical qualification. |

The original replacement band is **22–44 source hours**, not a remaining-work
estimate, calendar ETA or M1 completion forecast. O1–O3 source exists; integrated
corrections and qualification remain. The unexpected startup stage/owner-fence
and nested decoder dependencies are recorded below, not another architecture
extension. If a chunk exceeds its upper band, explain variance and re-scope
before expanding it. This replaces continued read-expiry/priority/
micro-optimization iterations; it is not work added alongside them.
Use the existing **one focused engineering week go/no-go cap** to assess whether
the replacement is converging; do not quietly roll the cap forward.

Completed prerequisites: corrected source `2e19cd17`, independent role builds
R38j, coherent pins/builder `da86c686`, strict six-file verification R38k,
current prewrite/factory checks and isolated coherent finalization R38n.
Both startup bails were deliberately opened after these checks; actual inspected
snapshot return and leased comparison remain mandatory.

Remaining release work, in dependency order:

1. Attribute the admin recovery refusal after the enforced observation deadlines
   in R39o, using the supported three-node fixture, and fix only the
   demonstrated cause. Typed CLI transport causes and exact admin-claim retry
   selection pass focused checks; they do not resolve this later gate. Then
   qualify the packaged public lost-result/reopen workflow and returning/all-cold
   pending Install. Exercise Pins-before-record, first Intent stage, fresh
   initialization and locked reopen through normal startup, with unchanged whole
   **<=30s** recovery and no test-policy bypass.
2. Requalify original-owner forwarded Install refusals (complete wrong-shadow
   upload and absent System root), positive completion/exact retry and genuine
   cumulative >256 public authorizations with unchanged checkpoint/recovery.
   Preserve signed owner/parent evidence, package limits and whole **<=30s**
   recovery. Automatic startup must pass; manual recovery loops are not proof.
3. Freeze the startup correction, build the current portable main and run M1
   through ordinary packaged three-process CLI/HTTP: system actors ready,
   image Local and external Shared Clerk, genuinely lost initial mutation
   response, exact retry and restart/failover. Record demonstrated small workload
   and a public steady-state phase/queue/VM/persistence probe.
4. Progress through unchanged M2 retained-data/parity/resource/recovery/Agent
   backup gates, then locally possible M3 tooling and qualification. Hardware
   qualification remains explicitly open.
   Backup integration must use the existing certified System/AXJ1 checkpoint
   and ACX1 restore mechanisms under production ownership, plus authenticated
   opaque image Local capture and exact client retry state. Permanent freshness
   ledgers and lock nonces remain outside replaceable journal archives; raw
   filesystem copying does not qualify this gate. Existing-identity catch-up is
   in scope; replacement authority after loss of that permanent domain is not
   established by the existing mechanisms. Local preparation cannot qualify the
   actual three-node hardware workload, latency, load or soak targets.

Separate forecasts and unknowns:

- **Implementation:** O1/O2 and O3 removal exist; the current physical slice and
  241 selected regression tests pass. Role materialization, verification and
  caller selection exist; independent paired-role builds match. Exact packaged
  Catalog prewrite binding, certified-plan startup selection and typed retained
  transport-error fixes pass focused tests; normal startup is admitted, with
  packaged workflow qualification still pending.
  Exact SAC7 constructor/directory binding and the scoped nested-decoder fix are
  necessary correctness dependencies, not relaxed matching or larger limits.
  O1–O3's original source band remains above, not as a remaining-work estimate.
  The remaining uncertainty is
  integrated recovery/pruning and packaged selection, not another observation
  design. Component admission/purity, Raft-vs-state linkage and publication
  predecessor tests pass but do not establish the full released workflow.
- **Integration:** unchanged public phase bounds must survive complete consumer
  cutover. Cold pending Install, all receiver/local-System ownership, nonleader
  Create retry, pruning and concurrent Authority pagination may expose more work.
  If a required consumer lacks verifiable local System state or bounded pagination
  cannot meet the workload, stop for a focused decision rather than add a framework.
- **Unexpected mandatory restart work:** predecessor-bound startup inspection,
  signed semantic checks, owner fencing and exact Pins-before-record factory
  reuse are implemented, with focused passes. The original **3–6 source-hour**
  band, moderate confidence, excluded qualification. Additional signed-receipt,
  all-four-store and empty-initialization cases enlarged the test diff; this
  remained within O3's existing restart gate, not a format/migration project.
  Integrated packaged crash/restart evidence is still pending.
- **Qualification:** normal optimized rebuilds historically take **14–15 min**.
  Full physical runs are sequential; new guest/ABI artifacts require reproduction
  and new evidence. ReadIndex smoke is not System guest or released workflow
  qualification. No reliable aggregate qualification range exists yet.
- **Current diagnostic variance:** the four-call decoder correction left a
  deeper scratch-frame overlap; fixing it exposed a missing fixture credential,
  which was enrolled through the existing signed Admin path. The immediate
  diagnostic/fix/retest forecast was **2–6 engineering hours**, low confidence,
  excluding reproduction and packaged qualification. Coherent finalization
  and reproduction now pass, but public qualification exposed the delayed
  registration succession race and single-attempt fixture/script assumptions.
  The focused remaining correction/review band is **1–4 source hours**,
  medium-low confidence, plus **2–6 elapsed hours** of isolated M1 execution if
  no further defect appears. This is not a combined M1/M2/M3 forecast.
  R39b/R39c exposed a retained-Install quarantine admission gap; its narrow
  correction passes focused checks and R39g reaches verified nonleader Install.
  R39f/R39g next exposed lost typed transport causes and one-shot role-grant
  fixture handling; their correction passes focused checks. R39j/R39k still
  exceed existing public retry caps at admin/Install. R39m verifies nonleader
  Install and visible guest completion but still exceeds the role-grant bound;
  R39o attributes outer refusals to existing deadlines but not the later admin
  recovery gap. The component regression's singleton precondition must be
  replaced by the existing three-node harness, not a production exception.
  This adds fixture preparation within the same mandatory recovery gate;
  no admission correction is qualified yet. The **2–6 elapsed-hour**
  execution band remains conditional and is not a reliable remaining estimate
  while failure attribution is open. Scoped diagnostics must distinguish guest,
  freshness and terminal completion before further source work; current evidence
  does not establish a new guest execution defect or performance-only cause.
  Optimized R38r main and harness builds each take about seven minutes;
  R38s/R38t and first CLI failure establish the current variance. Cold recovery,
  actual leader-loss coverage, cumulative pruning and cleanup may expose more
  work. No service-tuning pass was consumed.
- **Packaging after correctness:** paired-role tooling/reproduction is
  implemented within the previous **4–8 source-hour** band. Corrected-source
  independent builds and strict frozen-builder bundle verification pass;
  packaged acceptance remains open. Signed resource ceilings are
  explicit but unmeasured; M2 must qualify them against retained data.
- **M1 overall:** no defensible combined ETA. M2 loading at 1,000 accounts/
  100,000 retained transfers, measured capacity/recovery, six-map parity and
  Agent backup/restore remain open. M3 additionally requires external hardware
  and prescribed 30-minute load/24-hour soak elapsed time.

Two audit reuse opportunities remain deferred unless measured qualification
requires them: reuse a call-local already verified manifest for retained-result
availability, and a single guarded audited view for new-member admission.
Existing retained-registration early return already works. Never cache permits
across host-lock release/peer I/O or remove fresh physical corruption checks.
The isolated recovery pass does not warrant implementing these optimizations.

No completion percentage, deployment date, release promotion or master change is
established. At most two measured service-tuning passes remain authorized; none
has been consumed. Architectural replacement and correctness diagnosis are not
service-tuning passes. Hardware is unavailable; prepare tooling locally and
leave hardware/load/soak qualification explicitly open.

## Recovery and authorization invariants

- Internal observations use fresh quorum coordination plus the consumer's own
  authenticated System state and guest execution. A sampled leader/index,
  remote page, archive, expired request or incomplete local state is not enough.
  Authentication and facts share one immutable revision; failed observations
  cannot leave persistent state, custody or partial routes.
- Public and management operations preserve the first verified terminal Invoke
  and first positive ACK. Repeated accepted inputs are ordinary rows, not
  replacement evidence. Negative ACKs do not retire their custody. Verify exact
  Ordered evidence rather than a latest cached outcome.
- Original signed mutation requests/work, nonce, caller, preflight/receipt and
  clocks remain immutable. Exact retained evidence precedes fresh execution;
  no re-signing, private-clock clamp, replacement authorization, widened window
  or non-durable preview refusal becomes terminal.
- Management families retain bounded exact signed members before dispatch.
  Native durable terminal and every required positive ACK precede signed release.
  Observations cannot release/extend parents or grant offline mutation authority.
  Their no-publication execution no longer spends management replay slots;
  management capacity/signature/owner checks remain authoritative.
- Cold member observations remain only the Root-authorized genesis decision
  and exact fresh complete descriptor/roster for the independently validated
  required physical set. No remote request expands that set, blanket Root/readiness
  exception, archive-only member, Local/Create-parent exception or ninth family
  member. A valid Install parent's caller authorization need not be Root.
- Forwarded Install remains the original online owner's exact operation.
  Authenticated sender plus retained registration/member/approval must match the
  current System. A reply is only a hint: exact replay, ordinary majority
  availability, issuer terminal/finalization and retention release remain mandatory.
  Discard-only transfer is not canonical Raft publication. Preserve valid Install
  packages at the existing 8-MiB reference cap; do not conflate decoder aggregate
  ceilings with supported package capacity.
- Fresh decision plus complete live descriptor/roster precedes member publication.
  Create Applied, durable OGAR or coordinator ACK is not readiness. Missing serving
  namespaces are never repaired from archives. Reopen uses exact present retained
  management intent/stage and independent leases.
- Restore authenticates complete immutable closure/destination before journal-first
  mutable publication. Exact inode sync and certified reopen precede marker
  retirement/serving. Scratch paths, process epochs and directory copies are not
  recovery authority.
- Fresh v1 System/control and Shared roots are required. Old experimental spaces
  reject before writes; no reset, legacy fallback, migration or mixed-generation
  Local rebinding. Image Local execution/format and public exact semantics remain.
- v1 keeps configured Root operators on participating daemons. No key-copy tool,
  implicit node API grant or replacement authorization. Enrollment uses existing
  signed upsert, not a roster-CAS framework.
- The obsolete internal-read machinery is removed, not silently settled.
  Legacy evidence remains forensic only; old generations reject before writes.
  Management evidence and public exact retry remain authoritative.

## Remaining mandatory release gates

### Integrated workflow and recovery

- [ ] Replace durable internal Authority reads end-to-end and remove the legacy
  lifecycle; satisfy the named observation acceptance checks above, including
  supported fresh-space prewrite rejection and coherent System runtime artifacts.
- [ ] Fixed-roster common authenticated genesis and supported Shared finality.
- [ ] Public Create/Install/Invoke with schema-aware resumable CLI, signed
  terminal failure/denial and usable first-use readiness.
- [ ] Cold/restarting/returning voters, mixed pending generations, fresh
  observation after observer loss and offline-origin management custody, leader
  loss before commit, after-ACK/metadata-clear crash cuts, exact retry and
  automatic bounded recovery.
- [ ] Common-state certified checkpoint/catch-up before replay exhaustion,
  separately signed physical store binding, complete pending scopes through pruning.
- [ ] External Shared block availability before quorum acknowledgment; missing
  blocks/minority cannot produce success; qualify catch-up and lost responses.
- [ ] Root-pinned closure/export and bounded detached reclamation. Protect
  authoritative, pending, checkpoint, retry/recovery and backup roots.
- [ ] Coherent signed external-state package contract and reproducible artifacts;
  production Local remains image-based. No default fixed-three prewrite gate or
  pin opens based on candidate guests/test signers alone.
- [ ] Bundled packages automatically prepared, authenticated HTTP/SSH defaults,
  system actors installed before Space readiness. Arbitrary user Agents remain
  explicit user operations.

### Capacity, service and operations

- [x] Real signed Clerk corpus/reference generator: 1,000 accounts and 100,000
  retained transfers, not a native tree probe or discarded history.
  Existing-dependency host example is independently reviewed, passes three debug
  smoke checks and full optimized generation (32.33s). Counts include 100,000
  retained external IDs and 101,000 verified signatures; independent file digests
  match the last-published manifest. Peak memory is unmeasured. Its roots bind
  explicit offline reference timestamps/order;
  public validation must replay actual accepted contexts rather than compare those
  synthetic roots directly. No Root/API/node credentials are generated.
- [ ] Account signed storage ceilings and streaming archive count/byte limits:
  >502,000 logical actor rows before other indexes/metadata: committed accounts,
  transfers and external IDs plus per-transfer root anchors. This implies over
  one million outer Patricia structural blocks before chunks. This is a structural
  lower bound, not a measured ceiling. The 65,536-object portable IMAGE/System
  archive is not the external checkpoint path; do not raise it globally. Existing
  bounded AXJ1 streaming export/ACX1 restore must be integrated through actual
  lifecycle ownership and qualified with measured external counts/bytes.
- [ ] Bounded public-API load tooling using existing ATQ1/AOC5/AOQ1/ASQ1 paths.
  Execution stays gated on supported startup/lifecycle/retention. Do not multiply
  Root credentials/queues or revive the retired acceptance API.
- [ ] Exact-release phase measurements: preparation, outer/inner VM, persistence,
  queue and quorum. Recompiler selection is implemented, not service qualification.
  At most two measured tuning passes; stop for direction after two failed passes.
- [ ] Maintenance-window Agent backup/restore: drain admission; capture authenticated
  Shared state, opaque validated Local exports and lifecycle/retry state; separate
  keys, matching identities/artifacts and recoverable replaced destinations.
  Current public backup is registry-only and rejects live Agent roots; external
  streaming export is test-only and restore remains internal. Integrate those
  existing authenticated mechanisms rather than wrapping registry backup or
  describing it as an Agent backup.
- [ ] Release-binary overload, partitions/minority refusal, catch-up, full restart,
  interrupted lifecycle and restore; unchanged load, failover and soak targets.
  `scripts/collect-agent-release-node.sh` prepares read-only per-node binary-hash,
  CPU/memory, disk, clock and literal-peer RTT evidence on later hardware. Shell
  syntax, four output/refusal checks and 13 numeric-address checks pass. Review
  found/fixed a hostname acceptance bug using standard-library numeric parsing;
  independent fix review finds no further findings. It never deploys or closes
  hardware/load qualification.
- [ ] Final interpreter/recompiler differential, full outer-PVM, supported
  feature/CLI tests, formatting/targeted lint and artifact reproduction.
- [ ] Final read-only review without release-blocking correctness findings.
  Prepare merge to master; production cutover still needs operator approval.

## Mandatory acceptance envelope

These are approved targets, not measured capacity or an availability promise.

- Three separate Linux x86-64 **8-vCPU / 16-GiB / SSD** nodes; RTT **<=5 ms**.
- **300 continuously active clients**, **80% reads / 20% signed mutations** on
  one Shared Clerk, plus unrelated Local/Shared activity.
  End-to-end **p95 <=1 s, p99 <=2 s**, including queues and retries.
- **1,000 accounts / 100,000 retained transfers**, **30-minute load** and
  **24-hour lower-rate retention soak**; measure write-only bursts separately.
- **Failover <=30 s**; no acknowledged loss, duplicate effects, unauthorized
  access or false completion. Exact retry survives restart/failover; minority
  cannot commit.
- Bounded memory, descriptors, queues, retained results and disk retention
  under overload, with realistic backend credentials.
- Backup/restore preserves roots, identities, Local state and exact retry.
  Interpreter/recompiler differential gates remain mandatory through promotion.

User supplied hardware later; prepare tooling and local three-process evidence.
Local tests do not close hardware/load/soak gates or authorize remote deployment.

## Shortcomings and deferred work

Measure these within existing gates, not another redesign:

- Whole-runtime/control-directory reconstruction and Shared ordering remain.
  Incremental actor rows alone do not imply touched-data cost.
- External preview repeats physical work; fresh invocation has directory/result
  inspection, preview and application plus follower apply. Outer VM, queue and
  persistence costs remain important beyond millisecond actor execution.
- Management-only RMF4 cost remains unmeasured; the removed combined format's
  declared 14.8-MiB ceiling is not current capacity evidence. Remeasure actual
  retained management state. Fresh predecessor checks and
  post-I/O validation remain mandatory; no corruption retry or cross-call proof cache.
- Common reopen repeats full closure/replay audits; detached GC still scans/sorts
  metadata. Qualify peak memory, recovery time and retained disk at the real corpus.
- Native snapshots scale with guest address span. Immutable preparation caches
  do not reuse invocation memory; bound code/table and one-shot guest allocation.
  Inner cache admits one exact <=2-MiB program per worker; larger/unresolved
  defaults bypass it, not artifact admission.
- Silent-voter availability permits can survive successful quorum until timeout;
  qualify sustained minority load. Management registration can time out then
  commit: exact mutation retry must reconcile it. Observation timeout instead
  releases volatile resources; it cannot create a durable read obligation.
- Old experimental read generations/pending WALs are not migrated or interpreted
  as settled by absence/expiry. Fresh-space format/admission rejects them before
  writes. Never-admitted read finality is superseded by replacement, not deferred
  work to implement alongside it.
- Experimental external Shared is Direct Linear/LinearizableQuery plus ACK.
  Control Query, Resume/yield/timers/Attested are not supported on that slice.
- Frozen ABI fetch tariffs, sparse-memory assumptions, partial chunk/path/index
  optimizations and unrecognized compiler host-ID handling remain follow-ups,
  not permission to change admitted semantics.
- Existing no-network `std storage` embedding combination fails in unchanged
  Shared adapter references; supported v1 includes networking. Qualify the
  supported feature matrix, not unrelated feature-boundary cleanup.
- Defer Private/Attested production, dynamic membership, bridge/settlement,
  old-store migration, public external Local, sharding, online GC, broad runtime
  unification, ARM64 and thousands-active-client qualification.
  The existing prover/protocol validation stays; deferred is not silently supported.

## Working and evidence rules

Every change closes a named mandatory gate or demonstrated blocking defect.
Use existing mechanisms; no new profile/framework/migration/broader compatibility.
Report user-visible behavior, source evidence, integration/qualification, blockers,
unexpected work and forecast separately. Do not stop at internal tests/commits.

Use offline/locked host nightly `2025-05-09`, guest nightly `2026-03-20`.
Build/test/log roots are disk-backed `.worktrees/ch08-c2-native/target`; set
`TMPDIR` and `JUST_TEMPDIR` to its `task-tmp`. Never use RAM-backed `/tmp`.
Sequence physical tests separately from builds; preserve failure evidence and
source boundaries. Ignored/socket-denied/zero-selected tests are not passes.

Production identities come from `support/production-artifacts.toml` and
`vosx/build.rs`; candidate results never promote pins. Baseline evidence is
recoverable at `e6f2bb45`, `6d3a4926` and `62ffbc20`.
Superseded uncommitted experiment text is frozen as target evidence
`release-integration-docs-pre-consolidation-r31.txt`, not a second live plan.
