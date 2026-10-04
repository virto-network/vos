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
committed; normal fixed-three startup is admitted after the prerequisite checks.
Packaged recovery qualification remains open.
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
  reopen now select normal admission; packaged qualification remains open.

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
checkpoint is `da86c686`, with verifier provenance at `39f1f6bb`.
`release-observation-o3-coherent-full-pinned-reproduction-r38k.log` passes strict
six-file verification; detailed evidence is `target/agent-release-reproduction/run.ykT3eh`
under the native worktree. Current source also passes **3 startup inspection**,
**2 package prewrite**, **87 store** and **3 core factory** checks. Store evidence
includes both strict client readers and the exact permitted rerun of one
loopback sandbox refusal; the separate client filter selected zero tests and
is not evidence. Logs are the R38l prewrite and R38m store-loopback/core-factory
files referenced by the live checklist. Isolated coherent-artifact finalization
R38n **passes 96.21s** on the coherent components. The two startup bails are now
deliberately removed after these checks. Preflight directly returns the actual
inspection; the full leased snapshot comparison still precedes reconciliation.
The staged-admission regression asserts exact returned snapshot equality.
Current debug CLI unit suite **passes 381 tests**, 52 ignored, **314.36s**
(`release-observation-o3-open-startup-cli-unit-r38o.log`). Packaged recovery
checks follow this opening; the ignored fixtures are not passes. M1 remains
open; reproduction and component passes do not close it.

The first opened-startup packaged public debug run
`release-observation-o3-packaged-public-open-startup-r38p.log` **fails 143.94s**
at ordinary CLI Shared Create: repeated HTTP 503 exhausts the existing 120s
correctness retry cap, before Install or the lost-response seam. R38q existing
diagnostics establish `retained_only=false`, successful authorization/candidate/
committee/receipt recovery, then origin custody timeouts and eventual leader
publication/finalization commits. Repeated guarded validation is a measured
contributor; no guest failure is established by these HTTP errors. This debug
host result is superseded by the following current portable evidence, without
waiving its failure.

R38r builds the portable main and optimized CLI harness from `63a2d2f0`, with
empty RUSTFLAGS; each takes about seven minutes. Main SHA-256 is
`e1cdb183c6ef3dd3f083335456806e59760eb3db4392d8b92b7023ad2d0fa4a6`.
Optimized public R38s **fails 212.17s**: Create completes, then the initial
nonleader Install returns HTTP 503; the fixture did not resume its retained
SIQ1. Scoped optimized R38t **fails 53.18s** during Create: a delayed signed
registration extension replaces the owner slot while the same root retry waits
on peer I/O. The stale registration digest produces ScopeMismatch despite
preserved exact member/result evidence. Review the narrow origin-only correction
in `network/shared_agent/management_recovery.rs`: current owner and exact member
are checked first, then a changed registration returns Conflict before reading
evidence. Receiver exact registration checks remain unchanged. The deterministic
signed-manifest regression and **14 Shared route unit checks** pass; integrated
portable retry remains unqualified. The Install fixture now uses normal resume
and asserts unchanged operation root/SIQ1 under the existing 120s cap.

Actual three-process CLI R38u passes readiness **9.744s**, then the initial
Local Create returns ambiguous HTTP 503 after **10.776s**. The script did not
resume; this does not prove a persistent Local Create defect. All owned processes
exited. One worker reports InvalidConfiguration during simultaneous cleanup
after peers begin stopping. Exact CLI resume and graceful cleanup remain open.
Logs are `release-observation-o3-portable-*-r38r.log`,
`release-observation-o3-packaged-public-portable{-diagnostics-r38t,-r38s}.log`,
`release-observation-o3-registration-*-r38v.log` and
`release-observation-o3-actual-three-process-cli-r38u.log` under the shared target.
All checks/deadlines remain; no service-tuning pass is consumed.

The corrected CLI script fences the fresh operation and immutable retained
client bytes before each normal --resume. Its attempts share the existing whole
180s command bound; shell/Python syntax checks pass, actual corrected delivery
and cleanup remain unqualified. The opt-in host example
`vos/examples/clerk_corpus_public.rs` prepares the M2 public loader using existing
CLI/retained ASR1 verification, stable intents and independently replayed accepted
business seeds/order for all six maps. Source review and **7 tooling tests,
0.10s** pass; no public corpus run, resource/recovery or backup qualification is
claimed. It requires passing M1 setup and existing signed Operator/Member roles.

Normal-shutdown correction adds one Acquire cancellation check inside the final
failed owner-liveness branch. A held-inventory regression reproduces unchanged
production InvalidConfiguration (**0.05s**); **7 final focused checks pass**,
including fatal inventory and panic propagation. Checked retirement remains
unconditional. R38w before/after logs preserve evidence; the interrupted portable
build is not qualification. Actual three-process cleanup remains open.

Review the separate test-only packaged Shared-leader-loss selector: actual Shared
leader loss before first dispatch and after committed/pre-ACK result, online
original issuer, exact request/result on survivors and normally reopened owners,
and three healthy owners restored before either cut. Fault and returning-owner
phases retain whole 30s bounds including stop/open and verification. Setup alone
uses the existing 120s correctness cap. It does not prove accepted in-flight
precommit crash or public System mutation failover. Independent review corrected
the retry fixture's premature Completed assertion; failed attempts can inspect
the canonical retained operation, while success requires completion. Same SIQ1
bytes remain mandatory. Final CLI debug harness compilation passes **4.08s**
(`release-observation-o3-leader-loss-cli-test-final-r38x.log`); portable build and
actual execution remain pending.

R39a portable main and optimized harness build from clean `7d08ee95`
**pass 7m04s / 7m07s** with empty RUSTFLAGS; exact binary provenance is recorded
in `release-observation-o3-portable-main-provenance-r39a.txt`. R39b public workflow
**fails 241.95s** despite completed Create and normal exact Install resumes.
R39c scoped diagnostics **fail 255.73s** and establish a pre-Invoke recovery
deadlock: original Install custody timeout **2.058s**, later leader registration
commit **7.599s**, same-origin observation Unavailable/quarantine, no route
republish, then HTTP rejection of every Install resume. Protected admission
prevents inventory refresh. No Install guest execution or terminal release is
established. Review the narrow correction: exact current coordinator
intent/call/package lookup, retained-only queue restriction through both
readiness races, then existing completion without fresh initialization or
preparation. Lookup uses existing leased sidecar loading/reconciliation; it
cannot create missing inputs or custody. Fresh Install remains blocked during
quarantine. R39 logs are under the shared target; public qualification remains
open and no service-tuning pass is consumed. Independent review finds no blocking
issue. Native R39d signed-input, owner/queue and HTTP checks **61 pass, 1.53s**
after a **1m45s** build (`release-observation-o3-retained-install-{core,regressions}-r39d.log`).
They cover exact/changed/missing/member-only inputs and both readiness races;
they do not qualify physical Install execution, finality or restart recovery.

Portable R39e main and optimized harness build from clean `d3408382`
**pass 7m00s / 8m18s** with empty RUSTFLAGS; binary provenance is recorded in
`release-observation-o3-portable-main-provenance-r39e.txt`. Quiet R39f public
workflow **fails 133.10s** when credential-discovery HTTP 503 loses its typed
transport cause. Scoped R39g **fails 312.19s**, but completes verified nonleader
Install before a one-shot credential query for the next Clerk Operator role
grant fails HTTP 503. Lost mutation response and reopen are not reached; the
cumulative stage marker is not a standalone Install duration or SLA result.
Review the current CLI-only correction: unchanged diagnostic text preserves the
typed cause in credential/admin delivery. The fixture uses the existing 120s
retry bound, retries discovery before a new durable admin claim, then resumes
only the complete matching signed operation and fences retained nonce/draft/
preparation/submission/terminal bytes. An earlier completed claim cannot select
resume. Independent review finds no blocker. Native R39h build **passes 40.48s**;
three new regressions **pass 0.28s**, and related CLI checks **14 pass**, 1 ignored,
**4.24s** (`release-observation-o3-cli-transport-{test-build,regressions,related}-r39h.log`).
Correction is frozen at `d5459f66`; portable R39i main/harness **pass
3m29s / 3m28s**, with exact main provenance recorded. Public R39j **fails
418.17s** after verified nonleader Install at cumulative **129470ms**, at the
existing role-grant retry cap on `/__agents/admin` HTTP 503; discovery and
preparation advanced. Scoped R39k **fails 333.13s** earlier at the nonleader
Install retry cap. It verifies Authority approval/receipt and local retained
Install replay, but not terminal finalization/release/SIR1 delivery. Neither
reaches lost mutation response/reopen. Observation Unavailable alone cannot
attribute guest versus freshness failure: existing inner outcome diagnostics
were test-only in the CLI-linked dependency. Review the temporary visibility of
those two existing diagnostic blocks under the same flag, then remove it after
attribution. A pre-NAD2 admin retention seam remains a source hypothesis. No
observation admission bypass, authorization, deadline or service-tuning change
is introduced.

Optimized harness R39l builds from clean `a1780e83` **pass 7m02s**, with empty
RUSTFLAGS and recorded provenance. Scoped R39m **fails 457.34s**: verified
nonleader Install at cumulative **135506ms**, then the Clerk Operator role grant
exceeds the unchanged 120s correctness bound. All **88** visible observation
guests return `Done`; no guest refusal, non-completed outcome or host refusal
appears. Of **23** outer Unavailable refusals, eight follow guest completion and
fifteen have no adjacent completion. Associated guest calls take
**0.186–0.371s**, but total coordination/apply/guard time remains unattributed.
Custody timeout followed by later commit does not establish admin finalization
or terminal release. Lost mutation response/reopen are not reached. Review the
temporary scoped guard labels and remove them after attribution; guard order,
ownership and the **1.8s** observation bound remain unchanged. Evidence:
`release-observation-o3-observation-outcome-cli-{build,provenance}-r39l.*` and
`release-observation-o3-packaged-public-outcomes-r39m.log` under the shared target.

R39n guard harness builds from clean `32b12b0b` **pass 7m06s**. Public R39o
**fails 369.77s** at the unchanged Operator role-grant 120s retry cap after
verified nonleader Install at cumulative **133140ms**. All **70** visible guests
return `Done`; no guest/host refusal or non-completed outcome appears. Its
**15** outer refusals are five post-guest deadline failures (**1.854–2.040s**
total), four pre-guest deadline failures (**1.983–3.450s**), and six barrier
delivery timeouts (about **1.800s**). No term/configuration, ownership or stale
rejection is recorded. Preserve the enforced 1.8s bound; this is not proof of
a performance-only cause or of admin finalization. Registration times out and
later commits before quarantine, but admin-specific attribution remains open.
The temporary observation visibility/guard labels are removed; scoped admin
phase/boolean diagnostics remain provisional. Evidence is
`release-observation-o3-observation-guards-cli-{build,provenance}-r39n.*` and
`release-observation-o3-packaged-public-guards-r39o.log`.
The new native regression builds **52.07s**, but it (**2.64s**) and the unchanged
baseline (**2.43s**) fail authenticated manifest inspection before the intended
cut: their historical fixture has one voter. These R39p2 precondition failures
do not establish an admin recovery defect. The new singleton test is removed;
reuse the existing signed three-node fixture, with no singleton exception or
test-policy bypass. No production admission correction is qualified.

Scoped admin harness R39q builds from clean `594c5ff8` **pass 6m35s** with
portable flags and recorded provenance. Public R39r **fails 375.26s** after
verified nonleader Install at cumulative **105115ms**. Exactly one ready admin
submit has no NAD2/current pending member and capture returns Unavailable
before its journal callback. Private exact metadata/work correlation ties that
admin registration's origin timeout (**1.897s**) to its later leader commit
(**7.909s**); this leader trace does not prove original-owner application.
Then **733** unready submissions fail retained admission with NAD2 absent.
Lost mutation response/reopen remain unreached. Review the narrow same-open
attempt correction against this demonstrated gap, preserving cold
missing-journal refusal and complete original-owner family restrictions.
R39s supported fixed-three regressions compile **1m05s**; both fail at the
intended normal-owner exact submission with ScopeMismatch: registration
timeout/later exact commit (**25.64s**) and journal-prewrite interruption
(**23.91s**). Their earlier signed custody, no Invoke/ACK, absent NAD2,
unchanged actor state and input-negative assertions pass. These are before-fix
component reproductions, not completion or released qualification. Evidence:
`release-observation-o3-admin-stage-cli-{build,provenance}-r39q.*`,
`release-observation-o3-packaged-public-admin-stages-r39r.log`, and
`release-observation-o3-fixed-three-admin-{registration,prewrite}-before-r39s.log`.
Temporary admin diagnostics must be removed after attribution.

The same-open correction is applied after independent source review. Review its
one validated signed submission plus entire original work before metadata I/O,
pure complete-family validation under the existing guards before restoration,
unmatched-attempt preservation, cold initialization without proof, and matching
NAD2 confirmation in both owner and controller. Temporary admin diagnostics
are removed. Core R39t build **passes 1m16s**; prewrite recovery **passes 28.00s**
(whole recovery **5.799s**), and diagnostic timeout recovery R39u **passes
30.42s** (whole recovery **7.897s**). Both reach real guest Invoke/ACK, signed
release and identical terminal retry. First quiet timeout **fails 51.92s**
waiting for exact registration commit, before corrected retry admission; its
quiet log does not establish the cause. Reconnection of both shorter-log peers
permits loss of an uncommitted proposal, so preserve the intended cut with the
original-plus-one-peer reconnect until exact commit, then restore the third
under the same 30s bound and checked cleanup. Actual cold-owner and complete
family negatives remain open. Logs are the R39t core build/provenance,
`release-observation-o3-admin-{registration,prewrite}-after-r39t.log`, and
`release-observation-o3-admin-registration-after-diagnostics-r39u.log`.
No packaged workflow, M1 or service qualification pass is claimed.

Final component R39v build **passes 1m29s**, with recorded source/binary
provenance; related management recovery/protocol checks **9 pass, 0.66s**.
Live timeout/prewrite cases pass with authenticated family negatives and exact
terminal retry: **30.70s / 28.98s overall**, **8.352s / 6.488s whole recovery**.
Actual cold same-store reopen **passes 29.97s**, whole recovery **7.695s**:
the freshly constructed normal recovery owner refuses the original signed
submission, with absent NAD2, unchanged actor state and original unreleased
custody without Invoke/ACK. Review the real dropped owner/transport, no copied
marker, signed admitted shadow/extended-family refusals, same-ID whole-envelope
substitutions, failed validation before map restoration and genuine released
slot refusal. Detached exclusion/candidate checks are explicitly not additional
live fault qualification. The pair-reconnect guard preserves the intended
late-commit cut and restores all peers on failure; every recovery phase keeps
the original whole 30s bound, excluding bootstrap setup. R39v logs/provenance
are referenced by the live checklist. These passes close this component defect,
not the current portable public workflow or M1 exit.

R39w portable main builds from clean `290e2563` **pass 6m32s**, empty RUSTFLAGS
with recorded SHA/source provenance. Actual ordinary three-process CLI checks
the exact six-file bundle and reaches readiness **9.333s**. Image Local Create
recovers its ambiguous first error through normal exact resume (**24.292s**
total). Local Install exhausts its unchanged 180s command budget with **163**
exact attempts at `/__agents/local/install`: first server error
`Lifecycle(Unavailable)`, then `InvalidConfiguration`. The unready production
guard explains the later source path; info logs do not attribute the first
interruption to guest/freshness/application/terminal. All matching owned PIDs
exit and graceful cleanup **passes 0.317s**. Shared workflow/reopen remain
unreached; no actual CLI acceptance pass is claimed. Private evidence and
R39w logs/provenance are referenced by the live checklist.

The packaged public fixture previously timed reopen after construction and
reset correctness retries. Review its test-only whole 30s correction: original
pre-constructor start covers every locked constructor, attachment/readiness,
retained Create/member handoff, exact Install/invocation result, normal positive
ACK/durable progress and all three Shared actor routes. It uses normal admission
and rejects late completion; initial 120s setup is unchanged. Existing transports
stay live, so its scope is locked-owner reopen. The later fresh serving query is
separate. Current optimized R39x harness from clean `74de3df4` **passes 7m29s**,
empty RUSTFLAGS with exact provenance. Quiet public R39x **fails 310.50s**
after verified nonleader Install (cumulative **120692ms**) and completed ordinary
Operator role grant. One-shot bootstrap authorization credential discovery
returns HTTP 503 before AOC5 preparation/signing or AOQ publication. Review its
test-only existing 120s exact retry with immutable ATQ/invocation nonce and full
ATQ/AOQ fences plus signed issuance verification. Normal CLI and later loss/ACK/
reopen checks are unchanged; corrected compilation/execution remain open.
The live checklist references R39x logs/provenance.

Separate R39y normal same-root diagnostics keep the preserved R39w main,
artifacts, identities, configuration and original retained request. All three
attachments return while actual HTTP remains recovery 503 (**10.223s**).
Exact Local Install resume is refused **503, 0.658s** before its handler/queue;
no authorization material/capture/Invoke or guest phase appears. Client/config
fences stay exact and every owned process stops normally (**0.301s**). This is
the current cold closed-admission boundary, not first-failure attribution or
whole recovery qualification. Private evidence is preserved; the safe summary
and original evidence pointer are referenced by the live checklist.
The source-reviewed Local Install regression retains the same controller,
physical System/Local images and owned non-clone memory lifecycle stores through
real registration timeout/late commit, bare intent/absent map and strict
substitutions before normal owner completion. Its whole 30s starts before the
cut. Run it against the unchanged guard first; no cut or completion pass is
claimed before execution. Memory lifecycle wrappers do not qualify filesystem
durability or cold recovery. No speculative missing-envelope restore is applied.
Core R39z from clean `e9d9832f` **passes 38.12s**; real Local cut **fails
42.66s** at the intended normal InvalidConfiguration guard after committed
original registration/bare intent/absent map (**6.756s**) and strict no-Invoke
substitutions (**7.142s**). The live checklist references build/source provenance
and before-fix execution. Review the applied conservative admission separately:
image-only already-held stores, exact signed intent/package and complete local
first-owner family, queue restriction across readiness, normal finality and
route completion unchanged. Closed owners and bare absent-map requests remain
refused; compilation and complete recovery are pending. It alone cannot complete
the reproduced missing-map case and must not be reported as qualification.
Conservative R40a builds **1m26s**, queue/HTTP checks **2 pass, 0.30s**, but the
same cut **fails 43.06s** at ProjectionNotReady (late registration **6.776s**,
no-Invoke negatives **7.210s**). The live plan references its logs/provenance.
Review the applied same-open correction: physically validated original whole
work before metadata, fresh signed image handoff eligibility only, complete
original-owner single-root validation under existing guards before restoration,
original pair pledge before new material and matching-confirmed CMI clear.
Ready pre-append retries recapture the same envelope; quarantined and cold
requests cannot create proof. Memento-backed callbacks require whole-envelope
equality before pledge. A prewrite regression reuses the unchanged whole 30s.
Compilation, A/B/cold/family and public/main qualification remain open. Compound
handoff-store-write ambiguity is a separate open cut, not waived by this patch;
the first original CLI interruption remains unattributed.

The final >256 locked-owner reopen now includes all constructors/attachments,
readiness and exact archived native-result verification under one unchanged
30s deadline, including both HTTP retries and post-call elapsed checks. Source
review passes; actual execution remains pending. Running transports and one
published supervisor do not qualify whole-process/every-member readiness.

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
qualification is claimed. Artifact repins are committed and the two startup
bails deliberately removed after the prerequisite checks; packaged pilot and
service qualification remain open. The review branch is unchanged. Startup binds exact
System/Authority/Catalog closure before writes: SAC7 alone cannot identify O3's
management-only RMF4 lineage. The full reproducer passes with artifact-bearing
builder `da86c686`. The direct CLI acceptance script has run once with the
unresolved result above; no three-process acceptance pass is claimed.

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
