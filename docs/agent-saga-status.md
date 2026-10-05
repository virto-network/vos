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

### Completed R49 bounded admission-cost investigation

The user-authorized investigation is **complete, without a recovery pass or
performance benefit**. Frozen clean source is
`40a7e553396e68f6e3eebbea0ed3dc9e2afe0fa2`, including the `64c7f528` ownership
repair. Independently reviewed temporary diagnostics export only fixed phases,
durations, bounded counts and source-success booleans. No validation, audit,
guard, deadline, artifact, guest or protocol was changed. This is investigation,
not a fourth tuning candidate or an engineering-week cap extension.

Portable main/harness **pass 448.359s / 510.131s**; strict six-file verification
**passes 0.101s**. Empty RUSTFLAGS, unset overrides, exact frozen clean source,
binaries/artifact inputs and exhausted owned groups are checked. Guest bytes
and pins are unchanged. Provenance:
`task-tmp/r49-cli-build-40a7e553/provenance.json`, SHA-256
`fb49f727f640cdb72b6d9a0e686f50273f99649f2cc21eabea1f08bc364be083`.

Quiet selector **fails 340.264s**, one executed test, at Shared recovery before
routes with Unavailable (`clean_startup_tests.rs:1981`). Its finite projection
does not establish the inner cause or receipt-cut occurrence. Safe artifact:
`task-tmp/r49-pending-all-cold-40a7e553/quiet-safe-summary.json`, SHA-256
`900b73eadef1f8a263a15220d77d1543fa2a4f0666efced59469c5c555798c73`.
The 5.67-minute attempt exceeds the preceding 3–5-minute failed-run band;
variance was reported before the scoped run, without changing any deadline.

Scoped selector **fails 135.554s**, one executed test, during **ordinary packaged
Shared Create before the pending Install receipt cut**. The affirmative public
phase label and assertion at `member_handoff_tests.rs:492` establish exhaustion
of the existing retry bound in its retryable transport/status branch. Private
error detail and exact HTTP status remain unclassified. Missing cold frames did
not establish this stage; the source-bound label did. This run cannot attribute
or qualify the quiet recovery failure. Separately, the fixed observation guard
records one deadline refusal at **2.068986s** against unchanged **1.8s**, without
exact-request association or a quiet-run cause. Finalization markers record
extension refusals, extension completion and Invoke Unavailable; no full guest
outcome or saved-result marker is admitted.

The reviewed finite cost reader admits **1,041 records / 14 phase groups / zero
unknown**. The original reader refused three rows because an existing
`durable_terminal_verification` tracing span added two prefix fields. V2
normalizes only that exact source-declared bounded prefix; all other extra
fields, malformed scalars or unknown phases still refuse. Original readers,
refusal/schema explanations and private inputs remain preserved. Original
source/provenance/artifact/binary/test/owned-process and before/after input
fences remain. No raw memory or private diagnostic inputs were exported; both
loopback executions passed normal automatic approval.

Selected completed-call measurements from scoped preparation:

| Phase | Calls | Per-call elapsed range |
| --- | ---: | ---: |
| Signed request verification | 3 | 2.430–16.815ms |
| Request succession | 12 | 2.299–27.819ms |
| Fresh request preflight | 12 | 17.741–448.095ms |
| Fresh absence ledger audit | 7 | 64.172–792.327ms |
| Retention budget | 6 | 59.418–351.570ms |
| Custody budget | 4 | 143.619–1,028.118ms |
| Singleton budget | 3 | 142.816–947.506ms |
| Manifest evidence verification | 965 | 8.333–192.864ms |
| Clock preview | 6 | 302.640–738.536ms |
| Preparation preview | 3 | 475.641–779.760ms |

These are call durations, not cumulative phase clocks. Calls nest, repeat and
interleave across owners; their totals are not CPU time, one request's latency
or whole recovery. No exact request/node correlation is available. All observed
success fields are true, but budgets include Ok(None), previews report the
original terminal predicate, and early errors can omit records. Missing markers
remain unknown. Diagnostic timing supplies no quiet/default performance,
cold guest-outcome, whole30, SLA or M1 claim.

The manifest timer measures physical/cross-store observation and positioned
result evidence, not initial decoding/signature validation, guest execution or
the full ledger fold (`shared_journal_driver.rs:5356–5445`). One item means one
management slot, which can contain eight members and evolving evidence. Equal
counts do not permit reuse across guard release, progress, checkpoint or reopen.

Evidence under `task-tmp/r49-pending-all-cold-scoped-40a7e553`:

- `management-admission-cost-v2-safe.json`, SHA-256
  `7ae634ad1663ef02edf658d576264438f72d0376cbbd9aef70493aea4f56c37a`;
  reader `task-tmp/r49-management-admission-cost-reader-v2.py`, SHA-256
  `3c7bc79ac9f43601a672f8fb46d74dcb1b81d5c8175b974246ac3cc5e3103671`.
- `all-cold-public-retry-stage-safe.json`, SHA-256
  `f9e1e83d214482457911b98d503b4de6d4300e4d5c6dc71445c8073d30e03a9c`;
  reader `task-tmp/r49-all-cold-public-retry-stage-reader.py`, SHA-256
  `29de7bc69b5d729359727bec5b18c83c0c2d6aa5bb272aa6008e0cf89bf8a750`.
- `management-finalization-fixed-order-safe.json`, SHA-256
  `00301ef13a4acebec93b0ef29c7506785069d2b4f6a7fcabdf4965f2c8bb585d`;
  `observation-guard-fixed-order-safe.json`, SHA-256
  `a8b05abab36bd535598f80c33cd680e300cb577c064e975bb44f9df46f58819e`.

Source review permits one narrowly dominated immutable validation removal in
`SharedRecoveryManifest::apply_management_registration`: the unchanged clone
immediately repeats the outer call's exact request/old-slot validation. Its own
cost is **not separately measured**; it does not directly target the 965 measured
manifest-evidence calls or replace any fresh audit, incoming signature, final
candidate validation, owner/family restriction or terminal preview. Independent
interpretation is **no-go for treating this micro-change as the demonstrated
recovery fix**. No safe correction to the blocking deadline is established.
Another tuning candidate requires explicit go/no-go direction; the cap is not
renewed. Temporary diagnostics remain available for unresolved attribution and
must be removed when it no longer needs them.

The preceding user-authorized bounded R48 candidate is **measured and failed** on clean
source `89b40ba6e34b87d94a323b3fe54a08fea614afa5`. This is the **third measured
candidate**, explicitly authorized after the original two failed passes; it
supplies no recovery, performance benefit or M1 exit. The engineering-week
go/no-go cap has not been extended. Another tuning change requires direction.

A subsequent seven-line preservation repair restores the original post-worker-
snapshot live lease/Agent check before selecting any retained custody capsule.
Two independent source reviews pass. It uses the existing verified-manifest
selector, without another audit, changed admission rule or cross-guard cache.
The repair is frozen at `64c7f528d7463ede73fc5e013e49d28327b610a5`:
fresh core build **passes 24.827s** and both existing ownership regressions
**pass 0.101s each**, with clean exact source/binary/artifact fences and exhausted
owned groups. These tests cover root replacement/quarantine and pinned root
identity, not combined custody timing. Core provenance:
`task-tmp/r48-lease-core-build-64c7f528/provenance.json`, SHA-256
`fd4b570054410d6139cb7cfb466ffb133f448d5639190ebbba65402c5ae8121f`;
`task-tmp/r48-lease-units-64c7f528/safe-summary.json`, SHA-256
`c3aecf87da381a86dc61a13df88298f1a2e7dc82e68269c998eff998df186a2d`.
Measured R48 portable binaries precede the repair. R49's portable binaries
include it, but recovery qualification still fails. This is a correctness
preservation repair, not another service-tuning candidate.

R48 reads the completed R47 logs without rerunning a fixture. Its independently
reviewed finite reader reports **689 events / eight temporal intervals / zero
unknown**. Archived source admission proves that clean `fa601999` differs from
measured `e168c39d` only in the two live documents; original binaries, artifacts,
source, test counts and owned-process fences remain exact. The first cold
extension's origin custody wait times out while leader registration validation
continues: leader checks reach clock-preview completion at **4.724s**, and its
commit/local confirmation completes at **8.768s**. Later Invoke origin custody
confirmation times out while leader admission still continues. The subsequent
ordered-result waiter timeout occurs after origin startup failure and may be
affected by teardown; it is not an independently established result-loss defect.
Abbreviated Debug IDs do not prove cross-node/exact-request association. These
are temporal phase facts, not a global performance-only or guest-outcome verdict.

Reader: `task-tmp/r48-cold-finalization-fixed-reader-v2.py`, SHA-256
`5d970407bb7e3dcd39802d8b4bbb9b54cd46c8822c9cf2fd908c28aad622628a`.
Safe artifact: `task-tmp/r47-pending-all-cold-scoped-e168c39d/cold-finalization-attribution-safe.json`,
SHA-256 `576832be538e3bdd59da19d929afa62ad68b734cbeb101fbb94aa8bb1e2a7923`.
V1 remains unexecuted: independent review corrected overlapping-window pairing
before V2 extraction. No raw memory or private diagnostic inputs are exported.

The candidate targets the named M1 cold management-admission blocker by removing
demonstrably repeated immutable validation. Register uses the existing Release
precedent: request-only checks follow the same call's full physical preflight.
Registration/budget/clock selectors borrow the existing verified manifest only
under uninterrupted host/proposal guards. Capacity returns its already-decoded
manifest through the existing driver evidence verifier. Fresh ledger preflights,
each unseen member's settled-prefix/absence proof, signatures, first-owner and
complete-family checks, actual successful-terminal guest preview, full capacity
audit, corruption/availability and worker barriers all remain. No manifest crosses
application progress, host-guard release, publication or peer I/O.

On `89b40ba6`, the core build **passes 76.885s** and six existing preservation
units pass. The first unit runner's wrong module executes zero tests and is
rejected; only the independently reviewed corrected exact selectors count.
Portable main/harness **pass 410.140s / 476.407s**, strict six-file verification
**passes 0.101s**. Provenance:
`task-tmp/r48-cli-build-89b40ba6/provenance.json`, SHA-256
`116ab1c0ec90e453c010d26b80e00b728c302fe11397456eb826f1dfefdabed5`.
Empty RUSTFLAGS, unset overrides, exact frozen source/binaries/guest inputs and
exhausted owned groups are checked; guest bytes and pins are unchanged.

Quiet all-cold **fails 266.697s**, one executed test, with Shared startup
Unavailable before public routes at `clean_startup_tests.rs:1981`. Safe artifact:
`task-tmp/r48-pending-all-cold-89b40ba6/quiet-safe-summary.json`, SHA-256
`85a50ba47bd6b0b4d8c4a0fd0d9d48279df7dbba55dab28b7715a5c487650812`.
Its independently reviewed finite reader checks the exact exit/result/count
tuple; the unexecuted predecessor remains preserved.

The same-candidate scoped run **fails 266.397s**, one executed test and owned
group gone. Preparation succeeds once, so preparation retry is not exercised.
Cold durable and issuer observations complete; extension refuses twice, then
completes, and finalization Invoke returns Unavailable. The admitted timeline
contains **705 fixed events / eight temporal intervals / zero unknown**:
origin registration confirmation times out at **1.840002s**, while temporally
overlapping leader validation reaches clock preview at **3.612922s** and
commit/local confirmation at **6.607590s**. Later origin Invoke confirmation
times out during leader admission. A leader ordered-result waiter completes
after origin startup has failed; its outcome category is not exported, and the
subsequent availability refusal may be affected by teardown. No exact-request
or node association, full cold guest verdict, result-loss defect or controlled
speedup is established by these timestamps. Observation guard labels separately
record six whole-observation post-execution refusals at **1.886070–1.993513s**
against unchanged **1.8s**; they do not establish finalization causality.
Scoped evidence: `task-tmp/r48-pending-all-cold-scoped-89b40ba6`.
Timeline reader V3 SHA-256:
`82659ae547bb3eca116b64d2a154749d643a4295d857244473f381019a4b9e06`;
`cold-finalization-attribution-safe.json` SHA-256:
`cb7aa873e539fa54fc3a2342d73c4356f8658afd8b5723a680f4c511c010a901`.
Original source/artifact/binary/count/owned-process fences remain exact.
No raw memory or private input collection was used; both loopback executions
passed normal automatic approval. The previously errored standalone regression
and decoder agent remain untouched.

Source review also confirms that startup **already** retries only Unavailable,
using the same held controller, System owner, signer, leases and original
signed request/package. `recover_shared_before_publication` in
`vos/src/agent/local_lifecycle/shared_recovery_retry.rs` limits scheduling
between attempts to the existing 30s window; a blocking recovery attempt may
consume that window. The packaged whole-recovery bound remains authoritative.
A missing caller retry is not demonstrated; adding another loop, Busy protocol
or reset deadline would not close this gate.

**Implementation:** replacement/removal and reviewed preservation repair exist;
remaining integrated recovery defects are unresolved. No defensible remaining
source-hour range is established. **Integration:** measured portable build
attempts take **14–16 minutes**; R49's failed quiet/scoped selector attempts take
**2.3–5.7 minutes**, high confidence as attempt costs only. The scoped attempt
fails before the cut, so this is not a cold-recovery effort range.
**Qualification:** M1 is still open; remaining
packaged gates, M2 and local M3 have no defensible aggregate effort range.
External hardware qualification remains open. No completion percentage, date,
performance credit or cap rollover follows these internal passes.

### Frozen preceding diagnostic boundary


The one user-authorized bounded diagnostic continuation is **completed, not
qualified** on clean source `e168c39d7db42997f159b17ff0b691bb2d37b596`.
Independent source reviews preserve the same held lifecycle, original signed
Install/call/package, native Unavailable-only setup retry and unchanged 120s
pre/post deadline. Fixed observation refusal diagnostics add no guard, state,
cache, deadline or payload change. Portable main/harness **pass 428.434s /
506.520s**; strict six-file verification **passes 0.101s**. Main is `d83eec90`,
harness `ead0723c`; provenance is `task-tmp/r47-cli-build-e168c39d/provenance.json`,
SHA-256 `6b7f9dfd75e7195af75549dc071096e9fef8daf97a656575dd9c405ea0cf83b9`.
Clean source, empty RUSTFLAGS/unset overrides, exact frozen binaries/artifact
inputs and exhausted owned groups are checked. Guest bytes/pins are unchanged.

The single scoped all-cold run **fails 294.324s**, with one executed test and
owned group gone. Preparation succeeds on attempt **one**: this does not
reproduce the prior pre-cut refusal or exercise retry. Receipt-stage assertions
are followed by the three cold constructors (seven total startup records).
Cold durable Install and issuer observations complete. The first recorded
cold finalization failure is `extend_management_pending -> Unavailable`, before
Invoke; the next extension also refuses, then a later extension completes and
finalization Invoke returns Unavailable before an outcome is recorded. This
locates call boundaries, not their inner causes, node association, a cold guest
outcome or the earlier quiet failure. Recovery, routes, fresh Query and whole30
remain unqualified. Existing finalization/transfer readers report **28 / 84
fixed events**, each **zero unknown**, with all evidence fences preserved.

The supplemental reader reports **nine events / zero unknown**: one ready
preparation and eight **post-execution deadline** refusals at **1.830756–2.076408s**
against unchanged **1.8s**. Elapsed time covers the whole observation, not only
guest execution. Those labels attribute only their own refusals;
interleaved aggregate events cannot establish cold finalization causality or a
performance-only cause. The v1 supplemental reader refused its own erroneous
boolean expectation for r43's exact test-count dictionary. Its independently
reviewed v2 corrects only that schema comparison, preserving the original file,
all fences and private finite exports. No fixture rerun follows that correction.
Evidence is `task-tmp/r47-pending-all-cold-scoped-e168c39d`; safe summary,
finalization, transfer and guard artifact SHA-256s are respectively
`83186539b2c70aa93039961f849f9e8ca39fd0efc60c9b6a1da63a308c69c21a`,
`b6d47e935af6b75a726048af36fa3ed5c09e79f418ec9b6c5ceb9926386c8d0a`,
`b311a442e7fb4109c859f7129542720fbae33c28209df7cad1c5eb7cbd29bd7d`,
`0d9704a4a28b27064bc14a172ff895de821844f4f92ff6ff9956fe88330f5286`.
No raw memory or new private-input collection was used; normal approval review
accepted this continuation. Debug timing is attribution only. This is not a
third tuning pass, cap extension, benefit credit or M1 exit. Further tuning
still requires go/no-go direction after the two failed measured passes.

Previous completed portable source is frozen at
`76b3f7232e423a666f1240a4611f54a2fd732fef`, including the Local correction and
guarded custody Invoke/ACK manifest reuse. Portable main/harness **pass
389.506s / 459.188s**; strict six-file verification **passes 0.101s**.
Main is `bc2eeab8`; harness is `2b3471aa`. Empty RUSTFLAGS, unset
encoded/target overrides, exact copied hashes, clean source before/after,
unchanged artifact inputs and exhausted owned groups are recorded in
`task-tmp/r46-cli-build-76b3f723/provenance.json`. Authority, Catalog, both
runtime roles and coherent guest pins remain unchanged. Earlier portable
boundaries remain frozen evidence, not current workflow qualification.

The **second/final measured tuning pass fails**: quiet all-cold **223.845s**,
one executed failing test, owned group gone and source/artifact/binary fences
passing. Replica 0 `restart=true` fails Shared recovery before public routes at
`clean_startup_tests.rs:1981` with Unavailable. No recovery, fresh Query,
whole30 or inner guest outcome is established. Evidence:
`task-tmp/r46-pending-all-cold-76b3f723/quiet-safe-summary.json`, SHA-256
`8d0432aec6f78dfdec4fdc09c07665dc50cd7bffc63bb285e8d7ab2224f8364f`.

The same-candidate scoped rerun **fails 170.388s**, one executed test and
closed owned group, at `member_cold_install_tests.rs:165`:
`prepare_shared_install` returns Unavailable while retaining the original
actual signed Install, **before fault creation or the receipt cut**.
It does not attribute the quiet run's cold failure. The fixed finalization
reader reports **10 events / zero unknown** and transfer reader **50 / zero
unknown**; these are setup events, with no all-owner cold cluster or recovery
pass. Aggregated guest Done/finalization/retirement events cannot bind episodes
or establish quiet-run causality. Scoped evidence:
`task-tmp/r46-pending-all-cold-scoped-76b3f723`; safe artifact hashes
`9f37e94c02f2a9156c3406da5e584b5a0aa56c81a46640eb5abf6f32a586701c`
and `e54c375ce9f9f1f11e32ad03b5751486f7cb53b52a691aa692c3a3c48e543dbd`.
Debug timing supplies attribution only, not quiet qualification.

**Both measured tuning passes are consumed and failed to qualify recovery.**
No benefit, performance-only cause, global guest-stack resolution or M1 exit is
claimed. At that preceding boundary, the two-pass gate required renewed
direction: a third change had not yet been authorized. R48's later explicit
renewal is recorded in the current position; deadlines and cap remain unchanged.
Current ordinary CLI, remaining packaged gates, full native NRT1 retry/reopen,
Local whole30/remaining negatives, M2 and M3 remain open.

The first measured ACK tuning candidate remains **UNQUALIFIED**. Its
quiet/scoped all-cold runs **fail 239.765s / 242.958s**, one executed test each,
owned groups gone and source/artifact fences passing. Cold durable and issuer
observations complete. Extension twice returns Unavailable, then succeeds;
the subsequent forwarded finalization Invoke times out waiting for local
custody after **1.903902s** under the unchanged **1.8s** bound. Leader custody
validation occurs after origin failure; later ordered-result availability also
returns Unavailable. No cold guest outcome, issuer save, handoff, recovery,
fresh Query or whole30 pass follows. The cold episode never reaches the ACK
branch being optimized. No tuning benefit or performance-only/guest-failure
verdict is established. This was **tuning pass one**; the result above consumes
the final pass. A same-candidate diagnostic rerun is not another tuning change.
Evidence: `task-tmp/r45-pending-all-cold{,-scoped}-3b2d9b74`. The fixed
forward/custody artifact has **114 records / zero unknown**, SHA-256
`383ad432ae68d43d2bae6020af118e487b6291f92dc30890c938b98ce8b3f637`.

Fresh owned Local diagnostic **fails 206.129s** before Query or Shared, with
127 Install attempts and 123 two-member/root-only-CMI refusals. All source,
artifact and process fences pass; three recorded launches, zero survivors.
Full private correlation now **proves** that every refused child carries the
original journal-verified signed ACK and the earlier proposed envelope, with
all signature/request/message/whole-work/clock/parent/anchor/canonical checks
true: **248 fixed events / zero unknown**. Only validation/equality booleans
are exported. Evidence is `task-tmp/r45-local-child-correlation-3b2d9b74`;
safe artifact SHA-256
`a9c77026debe47eec3c9611e68b73fcacf5fb3134e691350b5fcb86bdff670ee`.
That correlation does not establish physical-image equality; the current
component test below exercises the production physical observer.

The reviewed exact Local recovery correction is **CORE BUILT,
UNQUALIFIED** on `4ce0f46b` (36.439s). Only the same-held production image Local controller may prove
this exact original-owner two-member, authorization-present/finalization-absent
family. All original child bindings are checked before normal issuer recovery
and physical observation; complete canonical ACK bytes and physical receipt,
application, whole state and applied clock must match. A fresh authenticated
generation/committee/complete-slot comparison follows before admission.
Default/bare/cold restrictions remain strict, with no signer, new custody,
restoration or cached proof. Normal issuer open/physical observation can
reconcile staged records/catalog state; this is real new recovery-path I/O,
not a pure-read claim. Patch SHA-256
`940585cdcfdfa6c939d5f08f74b2811899dbf0a93b7a2d0b60ebaa19de6395d9`.
The component run below exercises admission and three callback refusals, but
whole30, additional typed/fresh-family negatives, current portable builds and
ordinary CLI/M1 qualification remain prerequisites.

Existing strict Local cold-adoption refusal **passes 54.460s**. Existing
registration-timeout exact retry **fails 65.472s** at
`local_install_recovery.rs:1062`: completed issuer ACK, ready actor route and
released family assertions passed, then a terminal retry returns before the
unchanged **whole30** deadline assertion fails. Its exact ACK equality and
later no-change assertions are unreached. Neither pass/failure qualifies the
new child callback or ordinary CLI. Both execute one test, owned groups are gone
and source/artifact fences pass. Evidence is
`task-tmp/r46-local-{cold,registration}-compat-4ce0f46b`.
The initial shortened-selector wrapper refusal launched no test and is not
execution evidence.

The genuine Local child-before-pledge regression is **BUILT AND EXECUTED,
UNQUALIFIED** on `70ce586a`: **fails 65.873s**, one executed test, exhausted
owned group and source/artifact fences passing. After actual child registration
and an exact CMI finalization-prewrite refusal, the fixed marker at **14.744s**
confirms strict default refusal, held-controller admission and three negatives:
missing observed ACK, a different validly signed issuer ACK against the unchanged
child, and actual physical-image corruption. The normal original retry then
matches the ACK and original child envelope/anchor and releases the complete
Invoke/ACK family. The second terminal retry call returns, but whole30 fails at
`local_install_recovery.rs:185` before its result is accepted. Its success,
final ACK equality, signer-count and owner-extraction assertions are unvalidated.
This proves component admission/refusal and the first retry/release, not the
complete test, whole30, ordinary CLI or M1. Non-clone memory lifecycle leases
and physical images do not qualify filesystem lifecycle custody/public HTTP.
Outer System/transport shutdown is outside the helper's whole30; lease release
and owner extraction are inside. Typed observation-field mismatch and fresh
family progression between callback and recheck remain open. Evidence:
`task-tmp/r46-local-child-callback-70ce586a/summary.json`. Reviewed patch SHA-256
`fefec4149bd87f8dbeccd66ca6ec804efe8285d9fc54338234898f347dda0ac2`.

Combined core build on `324f7e6c` **fails 24.031s** before execution:
the new fixture's `load_actor` needs a mutable slot binding (`E0596`). Only
that first binding is corrected; independent source review passes. The failed
build/owned-group completion remain at `task-tmp/r46-core-build-324f7e6c`.
This is a test compile correction, with no runtime or tuning credit.
Corrected clean `70ce586a` debug core **passes 43.049s**, with exact binary,
source/artifact fences and exhausted owned group recorded in
`task-tmp/r46-core-build-70ce586a/provenance.json`. This compiles the Local
correction, genuine child regression and Invoke candidate together; it is not
a portable build or integrated qualification.

Eight existing preservation units on that core **pass**, each exactly once:
clock ordering/finalization, exact capsule/whole envelope, aggregate retention
and ACK exclusion, committed/uncommitted recovery tails, settled committee
barrier, archived whole-live-view/capsule and fresh corruption/common baseline.
Timings are **0.101 / 0.101 / 0.101 / 0.101 / 0.301 / 0.201 / 0.101 / 4.205s**.
All owned groups are gone and source/artifact/binary fences pass. Evidence:
`task-tmp/r46-invoke-preservation-units-v2-70ce586a/summary.json`.
The original wrapper refused an incorrect inferred module alias at listing,
before any unit execution; V2 corrects only `evidence_ledger` to the compiled
`application_ledger_v2` path. The failed listing is preserved separately.
These existing units do not qualify the new borrowed Invoke path, Local
callback, physical recovery bounds or M1; they consume no tuning measurement.

The **second/final tuning candidate is PORTABLE BUILT AND MEASURED, UNQUALIFIED**.
Direct persisted ManagementCustody Invoke now may borrow only its own
post-drain/capacity/barrier-verified manifest under uninterrupted admission
guards, alongside the existing Current ACK path. Only immutable applied
selectors are reused: aggregate/pending/singleton budgets and persisted
preparation. Original PublicPreflight/clock ordering, successful unseen-member
preview, exact anchored-input agreement, every fresh absence/raw settled-prefix
check, physical/common closure and availability remain. Defaults stay fresh;
explicit disposal precedes publication, drain, unlock or peer I/O.
No full audited view, result, absence or availability proof is cached.
Independent source review, core/portable compilation and strict verification
pass; failed packaged recovery supplies no runtime benefit or M1 qualification.
Reviewed patch SHA-256
`73550005e9d5ec39d3b5962fd83927164ef70bfaf425aa1d81b70d9ac2e197c3`.
The second measured pass is consumed by the quiet failure above.
Three focused exact-retention units on preceding `f4a3dc90` each execute one test and **pass
0.101s / 0.101s / 0.601s** (credential query, reservation and exact Install),
with owned groups gone. These and the earlier typed retained-client regressions
are component evidence, not integrated recovery or M1 qualification.

Latest completed quiet/scoped public runs on `5750f0c2` **fail
412.139s / 366.996s** at the unchanged
**120s** bootstrap issuance correctness cap on **`/__agents/authorize` HTTP 503**,
after verified nonleader Install **105.444s / 109.102s** respectively. Each
executes one failing test and leaves its owned group gone; later gates were not
run at that public-failure boundary. The initial diagnostic run on this source
**fails 429.670s** at
**`/__agents/credential`**, before any native-operation phase; preserve that
unattributed failure. Previous `3b72eab6` authorize failures remain frozen
evidence, not current qualification.

The scoped extractor accepts **216 fixed native records / 0 unknown**. It reports
four dispatch Unavailable errors, two actor-ACK-pair errors, six authorization
**CompletedDone** outcomes and two AOI1 **CompletedDone** outcomes. Aggregate
counts alone cannot match interleaved episodes. The single serial bootstrap
source and privately reviewed trace order establish that authorization attempt
seven completes the actor ACK pair and NRT1 `retirement_save`, then its forwarded
`ReleaseManagementRecovery` reaches **local_custody_timeout at 1.873882s** under the unchanged **1.8s local
confirmation bound**, separate from the outer 120s correctness cap.
The fixed-order safe artifact records this sequence; the quiet run has no native
phase records. This establishes the scoped failure boundary after the saved
retirement witness, without identifying the release-ambiguity cause, resolving
every earlier failure or supporting a guest-failure/performance-only verdict.

The next action is exact terminal-release ambiguity/recovery attribution using
the existing NRT1, retained family and publication mechanisms. **No native terminal-release source
correction is established yet.** Preserve original work/clock/anchor,
journal-backed authorization, complete original-owner retention, exact release
and unchanged bounds. Source review of last-completed-row compaction protection
and unreleased-root fences preserves the latest hot NRT1 exact-retry path; no
archive-removal defect is demonstrated. This is source evidence only: **full
supported fixed-three native NRT1 exact retry/reopen remains open**.
The diagnostics are now compiled and exercised under the
existing flag with unchanged fixture backend/profile/stack settings. They affect
timing, provide attribution only, and must be removed after the cause is
established; they are not quiet, ordinary-default or SLA qualification.

The fixture fences exact ATQ1 and retained AOQ1 on retries; ordinary client code
publishes AOQ1 before authorize and reuses it without discovery, preparation or
replacement signing. These are source-path retention witnesses.
Packaged-fixture `Scratch::drop` removes its runtime tree on unwind, so ATQ/AOC/AOQ/AOR and
native retirement states are **not archived** beside the preserved logs.
No surviving-state or client-decoded bootstrap Issued claim follows. Neither
Clerk mutation/lost response, Clerk positive ACK nor whole locked-owner reopen
is reached. The remaining four packaged gates, current ordinary three-process
CLI acceptance and M1/M2/M3 remain open.

Latest completed ordinary three-process CLI, frozen at clean `fcac175a`,
**fails 208.524s**
before Local Query or Shared. First-ready **passes 9.338s**; Local Create
**passes 26.178s**, with an initial HTTP 503 and successful second exact retained
attempt. Local Install makes **125 attempts**, spanning **169.760s** before the
unchanged **180s** command budget has less than its existing ten-second
termination grace remaining. All attempts return HTTP 503; the production
Install warnings classify the first **three Lifecycle(Unavailable)** and next
**122 Lifecycle(ScopeMismatch)**. The ScopeMismatch substage and underlying
cause remain unattributed: these statuses establish neither a source defect,
stack failure nor performance-only cause. Graceful cleanup **passes 0.318s**,
three recorded launches/zero matching survivors, owned group gone and all
source/artifact fences passing. Original private inputs/evidence are preserved.

The corrected Query predicate is in the launched script but **was not reached**;
this run does not qualify it. The earlier `5750f0c2` **101.711s** assertion
failure remains frozen evidence of successful Local Query **46.307s**, issued/
delivery-retired/Done/direct `"0x"`, before the old wrong shape assertion.
The one-line `.result.value == "0x"` change preserves those checks; no Query
retry/endpoint proposal is applied. Neither run reaches Shared or reopen.
Ordinary CLI integration needs a current frozen-provenance rerun of the Local
correction above. This older ordinary failure did not establish its inner cause.
Stage timings are not whole-recovery/SLA or complete workflow qualification.

Earlier quiet returning/all-cold pending-Install runs on clean `f4a3dc90`
**fail 186.302s / 244.666s**, each one executed failing test, owned group gone
and frozen source/provenance/artifact fences passing. Both report **complete
Shared recovery before routes: Unavailable**. Returning fails at
`member_cold_install_tests.rs:46` in `open_origin`; that helper has both pre-cut
and timed-recovery callers, so **receipt-cut occurrence is unestablished** from
this quiet evidence. All-cold fails at `clean_startup_tests.rs:1981`, **replica 0
restart=true**. Its source ordering proves the intended signed receipt cut and
entry into all-owner reopen, but supplies **no successful recovery or fresh
Query**. Neither failure identifies the inner guest, observation, storage or
release cause, or supports a performance-only verdict. Existing whole **30s**
recovery remains mandatory; no recovery or Query pass is credited.

Before the transport correction, scoped all-cold on clean `5c45f4a8` **fails 194.815s**,
one executed failing test, owned group gone and source/artifact/provenance
fences passing. Seven constructor material records partition initial setup,
pre-cut open and the cold cluster. All **seven Shared Install origin_forwarded**
attempts occur in that cold cluster: **six leader-selection Unavailable**,
then **one apply-barrier Unavailable**, before any package Progress send.
There are no Progress/peer/Finish/local-evidence events. The aggregate host
reports **56 observation guest Done**, **four freshness Unavailable**, **three
matching finalized GenesisDecision**, and one completed terminal handoff pair.
Aggregate outcomes do not identify every episode or prove all guest paths.

Source review establishes a missing transport attachment step: exact fresh
genesis proofs reopen the deferred Shared namespaces, but member-only recovery
never refreshes their Raft workers. The fixture joins every constructor before
starting production; only the retained issuer's later authorization refresh
attaches its Shared worker. That dependency cycle explains the demonstrated
leader-selection boundary. Ordinary CLI uses the same constructor but starts
each completed daemon independently; **no ordinary CLI deadlock is claimed**.
The individual worker role/leader-hint clause was not logged.

The narrow correction is **BUILT and EXECUTED, UNQUALIFIED** on `941b3d3c`:
existing network `refresh()` after `generations_recovered = true` and the borrowed
entry drop, before handoff/Install recovery. Partial attachment retries refresh
without reopening the cleared deferred set. Existing lease/role/fingerprint/
worker checks attach only independently verified namespaces; public projection
export stays closed while recovery is pending. No election, authorization,
observation, protocol, resource or deadline change.

Earlier quiet/scoped all-cold runs on clean `19e8d051` **fail 243.961s /
201.317s**, each one executed failing test, owned group gone and frozen
source/artifact/provenance fences passing. Both fail constructor Shared recovery
before routes with Unavailable. The scoped cold episode reaches exact retained
Install evidence after a Progress/Finish timeout and peer row validation. Durable
and issuer observations complete. Finalization extension twice returns
Unavailable, then succeeds; the first Invoke returns Unavailable, and exact
retry returns **CompletedDone**. Issuer finalization saves and the cold handoff
completes, before **submit_ack Unavailable** refuses retirement. This proves
that episode's guest finalization and handoff, not terminal release, fresh Query,
whole **30s** recovery or global guest-stack resolution.

The cold ACK forwards and waits for local confirmation; the peer reaches capacity
audit, custody validation and preparation start. Origin confirmation times out
at approximately **1.887s** under the unchanged **1.8s** bound; peer preparation
starts approximately 140ms before that timeout. No peer completion, late commit
or exact failed-member identity is established. CMR2 save/root release are later
phases and were not reached. The existing 30s retry window cannot schedule another
retry after this returned failure; it does not bound nested execution. The scoped
cold constructor interval is at least **57.868s**. These are failure boundaries,
not a performance-only diagnosis or recovery pass.

The new phase/outcome visibility is **BUILT and EXECUTED, UNQUALIFIED**. Original
calls, error mappings, lock/fault order and bounds remain, with no extra I/O or
audits. Patch SHA-256
`340e33fe648a3026457cd9b392c6ddac70a3e7612c5c291de310ad95575fa8a8`.
Remove temporary diagnostics when attribution no longer needs them.

Current quiet evidence: `task-tmp/r44-pending-all-cold-19e8d051`,
safe-summary SHA-256
`fe3dc356cb4e2533af38e8e1cfe5ca82a369d2c483d4ff2cbf034f70a0da8765`.
Scoped evidence: `task-tmp/r44-pending-all-cold-scoped-19e8d051`.
Finalization order reports **31 fixed events / zero unknown**, SHA-256
`6ce9ec648b03bf4af04871a694647fb0888123da9b12827ab07a989850db7ba7`.
Host order reports **132 fixed events / zero unknown**, SHA-256
`250b03fdf135278fc584468cf260080a3bae58ee4d136b7b20acc40f21da2106`.
Transfer V2 reports **86 fixed events / zero unknown**, SHA-256
`b38b6175c3c664d333f79a6554b8d043382147854f641f501f875502ac2961f8`.
Completed inputs/tools/provenance/strict verification are hash-fenced. Serial
retained-issuer source plus reviewed order binds the cold episode; counts alone
do not. Earlier `5c45f4a8` pre-Progress and `941b3d3c` retained-row evidence
remain frozen under `task-tmp/r43-pending-all-cold-transfer-5c45f4a8`,
`task-tmp/r43-pending-all-cold-941b3d3c` and
`task-tmp/r43-pending-all-cold-scoped-941b3d3c`. Preserve their safe artifacts
and earlier `be0844c3`/`f4a3dc90` failure boundaries.

The fresh target-only Local diagnostic on `19e8d051` **fails 208.124s**.
It reports **123 root_family ScopeMismatch** checks: two members versus expected
one, root-only CMI, matching original owner, parentless root, anchor and full root
work; three checks report complete-family admission. There are 126 guard starts
and zero unknowns. Three recorded daemons/zero matching survivors, owned group
gone and source/artifact fences pass. The ordinary script is unchanged; no
ordinary-default/recovery/SLA credit follows.

Serial command/order evidence places **extension_start → extension_error
Unavailable** inside Local Install. Registration forwards, waits, and confirmation
times out at **1.837893s** under the unchanged **1.8s** bound. The extension error
follows, without a pledge refusal or later Invoke. The next exact retry refuses
the two-member/root-only family. Initial generic finalization events belong to
Local Create, not this Install.

This demonstrates registration confirmation failure before the CMI pledge,
followed by the family admission gap. The actual child's complete original
envelope/parent/anchor/clock and signed issuer-message binding remain unproved.
Keep complete-family restrictions and cold bare-intent refusal; prove that exact
child before permitting the existing original-envelope/CMI-callback retry.
No admission correction is applied yet. Physical observation performs disk,
guest and catalog work; issuer opening can reconcile staged records. Neither
may be added as supposedly pure diagnostics.

Evidence: `task-tmp/r44-local-finalization-attribution-19e8d051`.
Family summary SHA-256
`c023faf74745febf7c2bbc6634000dd8aa5fd6e03f62a89a043dab1cfa825494`;
finalization order: **10 fixed events / zero unknown**, SHA-256
`2d1ff7e0f49711ff86098a585254a1ba020b9b036677f9b938d4c8f3342898df`;
command order: **405 fixed events / zero unknown**, SHA-256
`0f87d21f5d0f3581fdfd9ed7940fa0e1d9de921a7ff7ec47c0060b656a1a089b`.
Completed inputs/tools/provenance/strict verification are hash-fenced. Preserve
the earlier `941b3d3c` count-only run; neither fresh run retrospectively
attributes `fcac175a`. The large copied-state proposal stays held/unqualified
and opened no original stores.

Next qualify the proved Local child-admission correction and investigate the
current forwarded finalization Invoke custody delay. Any second tuning
candidate must reuse only the same-guard immutable manifest while preserving
the Invoke-specific original-clock, anchored-input and fresh absence checks. Preserve every
fresh settled-prefix, physical availability/corruption and post-peer check.
Fix only demonstrated causes, freeze current host provenance, then rerun quiet
cold/returning and ordinary CLI under unchanged bounds. Native NRT1 terminal
release remains separate and open.

The approved measured ACK audit-reuse delta is **CORE BUILT, UNQUALIFIED**:
only a Current forwarded ManagementCustody ACK borrows its freshly verified
manifest within the uninterrupted post-drain host/proposal guards. Aggregate
budget outer/inner selectors, pending-family exclusion and early preparation
reuse that immutable value; up to four repeated source validations disappear.
All fresh settled-prefix/absence, physical availability/common closure,
capacity, worker barrier and exact custody predicates remain. The value is
dropped before guard release, peer availability or publication; ordinary,
Invoke, persisted and local-owner retirement paths retain fresh behavior.
Reviewed patch SHA-256
`6d94a2f1dd66f588a2162f3e30ed8e4b821ea60c0fb4b4f29a128fa89d856866`.
Current portable CLI compilation passes. Timing/recovery benefit remains open:
first measured quiet/scoped qualification fails as recorded above before the
cold ACK branch; **service-tuning pass one** is consumed without benefit credit.
First core build on `7aa46a57` **fails 16.617s** before execution: the new
network match omitted the existing fully qualified replay-request enum path.
That one reference is corrected; the failed build and exhausted owned group
are preserved. This is a build correction, not qualification or tuning evidence.
Corrected clean `09c18fd7` core builds **79.285s**. Three existing exact
preservation tests **pass 0.101s / 0.101s / 4.505s**: early ACK/no-publication,
archived whole-live-view/capsule and fresh-corruption/common-baseline checks.
Each executes one test; source/artifact/binary fences and owned groups pass.
The existing supported returning-owner retention regression **fails 171.383s**
at `management_retention.rs:1495`: after finalization returns Unavailable,
CMI has no saved child, so the intended before-Invoke cut is not established.
The inner cause remains unattributed; no custody/recovery or tuning benefit
is credited. Evidence: `task-tmp/r45-core-build-09c18fd7`,
`task-tmp/r45-ack-preservation-units-09c18fd7` and
`task-tmp/r45-management-retention-09c18fd7`. Original failed build remains at
`task-tmp/r45-core-build-7aa46a57`. No owned build/test remains from this batch.

The fixture-only preparation correction is **BUILT and EXECUTED, UNQUALIFIED**.
Normal credential/descriptor discovery retries the exact persisted credential
query while the original reservation/nonce remain held; SIQ1 signing/publication
still occurs once. The existing **120s** setup deadline starts before preparation
and is reused through the receipt cut, rejecting late results. Only the premature
raw-lifecycle pre-cut follower wait was removed: normal authorization refreshes
authenticated transport before receipt signing, and real returning-follower
checks remain after normal production attachment. Exact SIQ1/no-response/
staged-receipt/unchanged ordinary-journal assertions and whole **30s** recovery
remain. No API/visibility, forced election/readiness or public admission is added.

Earlier `fcac175a` failures **148.160s / 290.903s** remain frozen setup evidence:
returning credential HTTP 503 before SIQ1 publication, and all-cold pre-cut
follower wait before receipt-fault construction. They do not qualify recovery;
the current all-cold cut/reopen boundary must not be reduced to those earlier
setup failures. The current quiet evidence and safe summaries are
`task-tmp/r42-pending-install-f4a3dc90` and
`task-tmp/r42-pending-all-cold-f4a3dc90`; summaries export fixed status/boolean
boundaries only. Attribute the inner normal-startup Unavailable before changing
source, then rerun both with unchanged bounds. This does not resolve ordinary
Local ScopeMismatch or native NRT1 terminal-release causes.

Their source-based independence still allows focused recovery qualification,
but a fresh Query after timed recovery remains a distinct native-issuance probe
outside whole30. Native NRT1 release/retry/reopen, remaining packaged gates,
ordinary CLI and M1/M2/M3 remain open. Older R39w stays source-frozen history.

A supported signed THREE-node regression now **proves the missing-NOD1
recovery-admission defect on this supported cut**. Before correction, clean `61530b52` debug core
builds **45.045s** after one preserved **20.727s** test-only mutable host-guard
compile failure (no execution evidence). The exact physical BEFORE run **fails
28.831s** at the intended normal production ScopeMismatch guard: genuine
registration timeout is followed by the exact signed committed original-owner
Root, whole physical work and anchor at **2.809s**, with both NOD1 and the
origin's pending map absent; normal unready guard is reached at **3.057s**.
There is no bound failure or fabricated pending state. The separate normal
same-store cold reopen **passes 33.136s total / 7.452s whole recovery**, refusing
exact preparation without journal-independent adoption, Invoke or ACK.

The reviewed correction keeps one same-open signed preparation, original whole
physical envelope/clock and anchor, minted under the existing final barrier and
lifecycle/proposal/host guards immediately before fresh metadata I/O. It refuses
cold adoption and validates the complete original-owner, unreleased, one-member
parentless Root before reservation restoration or NOD1 retention, including an
already-held map. Authorization remains journal-backed. Exact NOD1 replay takes
precedence over an unrelated live attempt, and proof clears only after matching
retention is confirmed. No authorization, wire, limit or deadline changes.

Component qualification on `b20faacd` uses a debug core build of **55.558s**. The first extended timeout
run **fails 70.579s** during the existing **60s leader-bootstrap** setup with
HostUnavailable, before any operation cut phase. Preserve this unattributed
setup failure; it neither tests the correction nor qualifies service behavior.
The identical isolated rerun **passes 29.132s total / 4.076s whole recovery**,
proving exact original NOD1/context/work/anchor retry after late registration,
map-absent guarded substitutions and signed detached complete-family refusals.

The real journal prewrite cut **passes 28.032s total / 2.527s whole recovery**:
journal retain attempt count is one, NOD1 is absent, the exact original map/proof remains,
and normal recovery preserves the whole input. The actual fsync write-then-error
cut **passes 27.430s total / 2.028s whole recovery**; a bytes-present native retry
confirms exact retained NOD1 and clears only its matching proof at **1.625s**.
Both journal cuts exercise strict map-present gas/clock/anchor refusal. Extended
normal same-store cold reopening **passes 32.735s total / 7.392s whole recovery**,
with the new owner's proof absent, exact preparation refused and no replicated
custody adoption, Invoke or ACK. All four successful cuts finish with one executed
test and owned groups gone, under the unchanged **30s** whole-recovery bound.

The demonstrated preparation recovery defect is **component-qualified** across
late metadata commit, journal prewrite/ambiguous write and normal cold refusal.
These use genuine physical System images and non-clone fsync operation test
stores, **not hardened CSF1 filesystem lifecycle lease qualification**. Signed
shadow/extended-family candidates are authenticated detached copies; no live
retirement or application permission is inferred from them. The cuts prepare
only: no operation guest policy, receipt/issuance or operation-evidence signing,
follower-forwarding timing, public workflow or SLA claim. The preserved setup
failure remains unexplained. No deadline increase or service-tuning pass was
consumed. Existing Admin registration-timeout compatibility on production
`f9c61863` also **passes 30.933s total / 8.385s whole30** through exact terminal
retry/release, qualifying preserved default Admin component semantics.
Current portable packaging passes; public authorization/issuance and later M1
gates remain open.

Current component evidence under the native worktree's target is
`task-tmp/r41-operation-prepare-journal-build-b20faacd` and
`task-tmp/r41-operation-{family-timeout-b20faacd,family-timeout-b20faacd-rerun,journal-prewrite-b20faacd,journal-write-error-b20faacd,family-cold-b20faacd}`
(build provenance or `summary.json`, private stdout/stderr and exact result
records). Original BEFORE/initial correction evidence remains
`task-tmp/r41-operation-prepare-{before-build-61530b52,before-61530b52,cold-before-61530b52,after-build-f9c61863,after-f9c61863,cold-after-f9c61863}`.
Admin compatibility evidence is
`task-tmp/r41-admin-registration-related-f9c61863/{physical.result.json,physical.stdout,physical.stderr}`.
Current portable evidence is `task-tmp/r44-cli-build-19e8d051/provenance.json`;
focused exact-retention units are under
`task-tmp/r42-pending-install-retention-units-f4a3dc90`. Earlier portable builds
remain `task-tmp/r42-cli-build-be0844c3/provenance.json`,
`task-tmp/r42-cli-build-f4a3dc90/provenance.json`,
`task-tmp/r42-cli-build-fcac175a/provenance.json` and
`task-tmp/r41-cli-build-5750f0c2/provenance.json`.
Latest completed public evidence is
`task-tmp/r41-public-stage-outcomes-5750f0c2{,-rerun}/{public.stdout,public.stderr,public.result.json,safe-summary.json}`
and `task-tmp/r42-public-quiet-5750f0c2/{public.stdout,public.stderr,public.result.json,safe-summary.json}`.
Latest completed ordinary CLI evidence is `task-tmp/r42-current-actual-cli-fcac175a`,
with `ordinary-cli.result.json`, `before.json`, `after.json`, `run/timings.tsv`
and `safe-summary.json` (SHA-256
`84b89f0ef599d5a79275e0c3e831936e8475875ea51fb00eb1edb3aafee67673`),
with private attempt/daemon logs. The preceding Local Query slice stays frozen
under `task-tmp/r42-current-actual-cli-5750f0c2`; identities/request stores and
raw logs remain private. Current quiet pending-Install evidence is
`task-tmp/r42-pending-install-f4a3dc90/returning.{stdout,stderr,result.json}`
and `task-tmp/r42-pending-all-cold-f4a3dc90/all-cold.{stdout,stderr,result.json}`;
source/provenance/artifact fences and selector evidence are retained alongside.
Their `safe-summary.json` SHA-256 values are respectively
`cfc474ec8cc6cdb0b61d8df2103e34de230464fcb9c12874f64fcd9ad597631c` and
`8ecfd9393dd0a9bcdd3f58da735af419177900e00b7ede329d72241645b86020`.
Earlier pre-cut setup failures remain under
`task-tmp/r42-pending-install-fcac175a` and
`task-tmp/r42-pending-all-cold-fcac175a`.
The scoped `task-tmp/r41-public-stage-outcomes-5750f0c2-rerun/native-phase-order-safe.json`
(SHA-256 `1101184e6260c8b05978247e6a58672ff4aa145057cfdc68ac26721e2b46c6ac`)
exports fixed-enum order only. The v2 summary exports allowlisted
phase/outcome/method counts and existing safe timing/status fields; raw logs
remain private, and order/count artifacts are not archived native/client state.
Previous quiet/scoped authorize failures remain
`task-tmp/r41-packaged-five-3b72eab6/public.{stdout,stderr,result.json}` and
`task-tmp/r41-public-scoped-3b72eab6/{public.stdout,public.stderr,public.result.json,safe-summary.json}`,
with their portable provenance under `task-tmp/r41-cli-build-3b72eab6`.
Preparation-blocked evidence stays under `task-tmp/r40-*-5c2bf99c`.
Typed-client component logs remain
`release-observation-o3-{preparation,authorization,invocation}-typed-error-{before,final}-r40f.log`;
unrelated zero-selection filters are not evidence.

| Mandatory gate | Implementation | Integration / qualification |
| --- | --- | --- |
| Internal Authority observations | O1/O2 and O3 removal are implemented: no read custody/transport/apply/expiry lifecycle. Management retention and public Invoke/ACK remain. | Current physical observation **passes 67.75s**, including exactly one caught-up audit and existing freshness/no-write/cancellation/reopen cases. Optimized management/replay/owner/supervisor/protocol/observation checks **241/241** pass (10 ignored, 7.09s). SDK **259 + 256 passed**, each 1 ignored. Paired signed-role/purity probes **pass 4.64s** with explicit, unmeasured limits. Packaged closure/startup/retry checks **40 passed**, 2 ignored. No released workflow or SLA pass. |
| External storage/restore | Incremental executor, immutable closure, ACX1 publication and exact marker retirement exist. | Historical optimized reopen/crash-cut slices pass; the released workflow must requalify. |
| System management recovery | Parent retention, immutable MRQ2 first-owner binding, exact mutation evidence, signed terminal release and recovery remain. | Isolated optimized offline-pruning test **passes 419.04s**: restore, exact Create/Install, checkpoint/pruning, ACK and custody release. Install finalization **21.588s** meets unchanged 30s. Earlier contended 32.979s failure remains recorded, not waived or tuned away. Same-open native operation preparation, complete-family refusals, journal prewrite/ambiguous-write exact retention and normal cold refusal are component-qualified under whole30 on `b20faacd`; preparation-only fsync test-store limits apply. Latest scoped public authorization reaches saved NRT1 then times out during forwarded terminal release; this is attribution, not quiet qualification. Current returning fails normal startup with cut occurrence unestablished; all-cold proves the receipt cut and all-owner reopen entry before replica 0 startup fails Unavailable. Neither qualifies pending-Install recovery or fresh Query. |
| Member/public management | Packaged PublicWorkflow selects exact bundled roles and ordinary CLI Create. Ambiguous publication re-admits the original leased stores before exact retry. Finalization retains publication protection and verifies fresh decision state before exact terminal cleanup. Packaged reopen helpers explicitly use normal startup admission. Provision components use the existing boxed decoder, whose direct decode removes an extra by-value scratch frame without changing wire, validation or limits. | Native genesis checks **15 passed, 0.19s**. Expanded exact-finalization retry on independently reproduced coherent components **passes 96.21s** (`release-observation-o3-coherent-finalization-physical-r38n.log`), with unchanged 30s phase bounds. The fixture uses ordinary signed Admin Invoke/ACK to enroll its API observation credential and verifies refusal before enrollment. Source and six-file bundle reproduction pass. Latest scoped public reaches verified nonleader Install, actor ACK and retirement retention, then fails before client-decoded Issued. Current CLI completes exact Local Create resume, then repeatedly receives Local Install 503 with unattributed production ScopeMismatch. The corrected Query check is unreached; preceding `5750f0c2` Local Query/ACK remains frozen evidence. Shared is not reached. Lost-result/reopen, packaged cold recovery and complete three-process acceptance remain open. |
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
  unreached. Temporary scoped guard diagnostics were added to distinguish the
  freshness refusal without changing guard order, ownership or the **1.8s**
  observation bound; their later removal is recorded below. Log:
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
- Scoped admin harness R39q builds from clean `594c5ff8` in **6m35s** with
  portable flags and recorded provenance. Public R39r **fails 375.26s** after
  verified nonleader Install at cumulative **105115ms**. Its one ready admin
  submission finds no NAD2 or volatile pending member; capture returns
  Unavailable before its journal callback. Exact private trace correlation
  identifies that admin registration's origin timeout (**1.897s**) and later
  leader commit (**7.909s**). Then **733** unready submissions find no NAD2
  and fail retained admission. Original-owner application is not established
  by the leader trace. This is an admin-specific recovery-admission gap, not a
  new guest failure or permission to relax freshness. Lost mutation response
  and reopen remain unreached. Evidence:
  `release-observation-o3-admin-stage-cli-{build,provenance}-r39q.*` and
  `release-observation-o3-packaged-public-admin-stages-r39r.log`.
  The supported fixed-three component regressions compile **1m05s** and both
  reproduce the intended normal-owner ScopeMismatch: late registration after
  timeout (**25.64s**) and journal-prewrite interruption (**23.91s**). Before
  either failure, signed original-owner custody, absent NAD2, unchanged actor
  state and strict input refusals are verified. R39s build/provenance and
  `release-observation-o3-fixed-three-admin-{registration,prewrite}-before-r39s.log`
  preserve this boundary. The narrow same-open exact-attempt correction is
  under review; cold missing-journal admission remains closed. No correction
  or complete public workflow pass is claimed.
- The narrow same-open admin correction is applied after independent source
  review. One fully validated signed submission and complete original work are
  kept in memory before metadata I/O; only matching original-owner, single-root
  applied custody can restore exclusion, after full validation under the same
  guards. Confirmed exact NAD2 retention clears it, including bytes-present
  controller retries. Cold opens initialize no proof; unmatched attempts cannot
  replace it. Temporary admin diagnostics are removed. Core R39t builds
  **1m16s**. Journal-prewrite recovery **passes 28.00s**, with whole recovery
  **5.799s**; diagnostic registration-timeout recovery R39u **passes 30.42s**,
  with whole recovery **7.897s**, including actual guest Invoke/ACK, signed
  terminal release and identical terminal retry. The first quiet timeout run
  **fails 51.92s** before retry admission, waiting for exact registration commit
  under the unchanged whole 30s bound. Its cause is not established by that
  quiet log. Reconnecting both shorter-log peers can legitimately lose an
  uncommitted proposal; the fixture was corrected to reconnect the original plus
  one peer until exact commit, then restore the third, with checked cleanup and no bound
  change. Cold missing-journal and complete-family negatives remain pending.
  These are component passes, not M1 or released-workflow qualification. Logs:
  `release-observation-o3-admin-live-attempt-core-{build,provenance}-r39t.*`,
  `release-observation-o3-admin-{registration,prewrite}-after-r39t.log`, and
  `release-observation-o3-admin-registration-after-diagnostics-r39u.log`.
- Final corrected component source R39v builds **1m29s**; nine related
  management recovery/protocol checks **pass 0.66s**. Both live three-node cuts
  pass with authenticated family negatives and exact terminal retry: timeout
  **30.70s overall / 8.352s whole recovery**, prewrite **28.98s / 6.488s**.
  The real cold same-store reopen **passes 29.97s / 7.695s**, reaching a normal
  recovery owner whose exact original signed submission is refused while NAD2
  remains absent, actor state unchanged and custody unreleased without Invoke
  or ACK. It inherits no live marker. Valid signed shadow/extended families,
  original-owner and same-ID gas/anchor substitutions, exclusion conflicts,
  failed validation before actual map restoration and genuine released slots
  are covered. Detached candidate/exclusion checks do not claim extra live
  fault coverage. The reconnect guard restores every peer on failure and the
  third immediately after original-plus-one-peer commit. All recovery phases
  retain the whole **30s** bound; bootstrap setup is outside and unclaimed.
  Logs are `release-observation-o3-admin-family-core-{build,provenance}-r39v.*`,
  `release-observation-o3-admin-related-core-r39v.log`,
  `release-observation-o3-admin-{registration,prewrite}-family-after-r39v.log`
  and `release-observation-o3-admin-cold-missing-journal-r39v.log`.
  The current portable public workflow and M1 remain unqualified.
- Portable main R39w builds from clean `290e2563` **passes 6m32s**, with empty
  RUSTFLAGS and recorded SHA/source provenance. Actual ordinary three-process
  CLI acceptance verifies the exact six-file bundle and reaches readiness
  **9.333s**. Image Local Create initially fails ambiguously (**10.442s**),
  then normal exact resume succeeds (**13.510s**, **24.292s** total), preserving
  the script's retained-file fences. Local Install then exhausts its existing
  **180s** command budget after **163** exact attempts at the actual
  `/__agents/local/install` endpoint. The first server error is
  `Lifecycle(Unavailable)`; later attempts return `InvalidConfiguration`.
  Info-level evidence cannot distinguish the first interruption's guest,
  observation, image application or terminal stage. The unconditional unready
  Local Install guard is the source seam for later rejections, not proof of that
  first cause. All three matching owned PIDs exit; graceful cleanup **passes
  0.317s**. Shared workflow and all-owner reopen are unreached. Preserve private
  evidence through `target/task-tmp/r39w-cli-acceptance-path` under the native
  worktree and `release-observation-o3-actual-three-process-cli-r39w.log`.
  No actual CLI acceptance pass or Local runtime defect is claimed.
  Source review also found the packaged public fixture's reopen timer excluded
  constructors/handoff. Its test-only correction now shares one **30s** window
  from before all locked constructors through attachment/readiness, retained
  handoff, exact Install/invocation result and positive ACK, and all three Shared
  actor routes. Normal admission and initial 120s setup remain unchanged; fresh
  serving query is separate. This is locked-owner reopen with live transports,
  not process-outage coverage. Current optimized harness R39x compiles from
  clean `74de3df4` **passes 7m29s**, with empty RUSTFLAGS and exact provenance.
- Quiet public R39x **fails 310.50s**, after verified nonleader Install at
  cumulative **120692ms** and completed ordinary Operator role grant. The next
  one-shot bootstrap authorization fails credential discovery with HTTP 503,
  before its AOC5 preparation/signing or AOQ request. Stable ATQ1 and invocation
  nonce are already retained. The test-only correction uses the existing 120s
  exact retry, fences complete ATQ/AOQ bytes and verifies signed issuance;
  normal CLI, clocks and recovery bounds remain unchanged. Source review passes;
  corrected compilation and public execution remain open. Lost mutation response
  and whole locked-owner reopen are unreached. Logs/provenance:
  `release-observation-o3-whole-reopen-cli-{build,provenance}-r39x.*` and
  `release-observation-o3-packaged-public-admin-corrected-whole-reopen-r39x.log`.
- Separate same-root R39y diagnostics use the preserved R39w main, artifacts,
  identities, configuration and original retained Local Install request.
  All three normal attachments return but actual HTTP status remains recovery
  **503** (**10.223s**); exact CLI resume is refused **503, 0.658s** before the
  excluded Local Install handler/queue/guest path. Existing scoped logs record
  no authorization material/capture/Invoke phase. Client/configuration fences
  remain exact; every owned process stops normally (**0.301s**). This establishes
  the current cold closed-admission boundary, not the first R39w interruption
  or a whole recovery pass. Private diagnostic evidence is beside the original
  run; safe summary is `release-observation-o3-normal-local-install-reopen-diagnostic-r39y.log`.
  The supported fixed-three Local Install regression is source-reviewed and
  applied for a before-fix run: real registration timeout/late exact commit,
  bare intent, absent pending map, strict substitutions, then normal owner
  completion under whole 30s. System/Local images are physical; lifecycle
  intent/issuer use owned non-clone memory store wrappers. It does not qualify
  filesystem lifecycle durability or cold recovery. Compilation and intended
  cut reproduction remain open; no speculative original-work restore is applied.
  Core R39z compiles from clean `e9d9832f` **passes 38.12s**. The real cut
  **fails 42.66s** at the intended normal owner InvalidConfiguration guard,
  after locally committed original registration/bare intent/absent map
  (**6.756s**) and strict no-Invoke substitutions (**7.142s**). Logs:
  `release-observation-o3-local-install-before-core-{build,provenance}-r39z.*`
  and `release-observation-o3-local-install-registration-before-r39z.log`.
  Exact retained image-only admission is now applied after independent review:
  already-held stores, signed current intent, identical package and complete
  original-owner family; a captured queue bit preserves the restriction across
  readiness changes. Closed owners and missing-map bare intents remain refused.
  Compilation and whole recovery remain open; this conservative correction
  alone cannot complete the reproduced missing-map case.
  Conservative core R40a **passes 1m26s**; queue/readiness and HTTP quarantine
  checks **2 pass, 0.30s**. The same real cut **fails 43.06s** at normal
  ProjectionNotReady after late registration (**6.776s**) and no-Invoke negatives
  (**7.210s**), demonstrating the remaining missing-map seam. Evidence is
  `release-observation-o3-local-install-admission-core-{build,provenance}-r40a.*`,
  `release-observation-o3-local-install-admission-unit-r40a.log` and
  `release-observation-o3-local-install-registration-admission-only-r40a.log`.
  The independently reviewed same-open correction is applied: mint original
  full work only after validated fresh image Install handoff, before metadata;
  restore only the exact complete local single-root family under existing
  guards; pledge the original pair before fresh material; clear only confirmed
  matching CMI retention. Generic/cold helpers cannot mint proof. Ready retries
  before append recapture the same whole work; quarantine stays closed without
  applied custody. A separate pre-authorization-write regression shares the
  fixture and original whole 30s. Current debug core R40b builds **85.62s** from
  `e8bc5e45`. Quiet B verifies original work, native finality, exact issuer ACK,
  released two-member custody and the Local route, but **fails 65.61s** at the
  unchanged 30s bound immediately after terminal retry; subsequent no-write
  assertions are not established. Quiet A R40c **passes 63.72s**, whole recovery
  **28.316s**. Scoped diagnostic B R40c **passes 67.95s**, whole recovery
  **29.747s**, including unchanged journal/state/client/CMI bytes on terminal
  retry and cached exact publication reuse. The quiet failure is preserved;
  no performance-only cause or robust timing qualification is claimed. Evidence:
  `release-observation-o3-local-install-live-attempt-core-{build,provenance}-r40b.*`,
  `release-observation-o3-local-install-registration-live-attempt-after-r40b.log`,
  `release-observation-o3-local-install-prewrite-r40c.log` and
  `release-observation-o3-local-install-registration-diagnostic-r40c.log`.
  Independently reviewed test-only cold/family and compound handoff-write cuts
  are applied. Cold refusal drops the actual original owner and normally reopens
  the same roots without adopting missing work; signed family substitutions
  preserve the original whole envelope and live state. Compound handoff proves
  a real canonical signed write-then-error before the late registration cut,
  under the same whole 30s. Portable optimized core R40d from `dc5292d3`
  **builds 785.31s**, with empty RUSTFLAGS and unchanged clean source. Quiet
  B **passes 52.72s / 26.851s whole30**; A **passes 52.11s / 25.011s whole30**;
  normal cold refusal **passes 42.13s / 15.088s whole30**. All positive cuts
  verify exact terminal no-write retry; five existing owner/queue/HTTP checks
  **pass 0.27s**. Compound **fails 34.58s** at normal ProjectionNotReady after
  real signed handoff commit-then-error (**0.616s**), original late registration
  (**6.456s**) and strict no-Invoke negatives (**6.706s**). The same-open
  eligibility assignment follows the ambiguous handoff write and is skipped
  on exact retry; no full-work proof is minted. This is a demonstrated admission
  defect, not a timing-only failure. The independently reviewed correction is applied:
  preserve exact eligibility before that write only after signed retired
  predecessor, issuer ACK and physical image validation; eligibility alone
  grants no recovery, and full work still requires existing physical validation
  and complete original-owner guarded family admission. The same bounded
  memento now carries optional full work; cold constructors remain empty and
  exact pledge confirmation alone clears it. An unconditional exact-intent
  Conflict fence precedes intent/issuer loads and native writes, including another Agent's
  already-bare intent. Signed compound negatives preserve eligibility with no
  whole work or mutation, then require the original full work after capture.
  Different-Agent reachability is source-reviewed, not a new physical claim.
  Corrected portable core R40e from clean `eeec1d49` **builds 781.50s**, empty
  RUSTFLAGS and encoded/target overrides unset. All quiet cuts pass: B
  **52.96s / 26.955s whole30**, A **51.89s / 23.621s**, normal cold refusal
  **41.95s / 14.656s**, and compound **54.04s / 26.365s**. Compound proves
  eligibility-only refusal/no-write/no-clear after the real handoff error, then
  exact original full work, signed family negatives, issuer finality, complete
  two-member ACK/release, Local route and terminal no-write retry. Five current
  owner/queue/HTTP checks **pass 0.27s**. This qualifies the demonstrated
  same-open Local correction at the stated component/test-profile boundary;
  actual CLI and filesystem server lifecycle durability remain open.
  Logs/provenance:
  `release-observation-o3-local-install-qualified-cuts-core-{build,provenance}-r40d.*`,
  `release-observation-o3-local-install-{registration,prewrite,cold-refusal,compound-handoff}-optimized-r40d.log`,
  `release-observation-o3-local-install-optimized-{cuts-summary,related}-r40d.*`.
  Corrected evidence is the corresponding
  `release-observation-o3-local-install-handoff-eligibility-core-{build,provenance}-r40e.*`
  and `release-observation-o3-local-install-{registration,prewrite,cold-refusal,compound-handoff}-optimized-r40e.log`;
  `release-observation-o3-local-install-optimized-{cuts-summary,related}-r40e.*`.
  The exact before-fix binary is preserved at
  `release-observation-o3-local-install-before-handoff-test-binary-r40d`.
  Current portable packaging passes at the boundary above; public workflow
  integration remains unqualified.
  Lifecycle stores in these cuts are memory-backed; this is not filesystem
  lifecycle durability or all-cold cluster evidence. Original R39w first
  interruption remains unattributed. No service-tuning pass is consumed.
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

1. Obtain explicit go/no-go direction before another tuning candidate. The
   bounded R49 cost investigation is complete on frozen `40a7e553`; portable
   binaries include the ownership repair, but the quiet selector fails Shared
   startup recovery and the scoped run fails public Create before the cut.
   The eligible immutable duplicate-validation helper is unmeasured and does
   not directly target repeated physical manifest-evidence verification.
   No demonstrated recovery correction or performance benefit is established.
   R49 does not authorize a fourth tuning change or automatic week-cap extension.
   Source review rules out a missing caller retry: existing same-held recovery
   already retries Unavailable within the original scheduling window. Preserve
   exact retained continuation, fresh absence/settled-prefix, physical
   availability/corruption, worker/post-peer checks and original deadlines.
   Preserve separate attribution of fresh-prefix audits, evidence verification,
   immutable validation and preview. Phase success for budgets includes Ok(None), and
   missing success-only markers are unknown. The temporal timeline does not
   prove exact-request causality or a promised fix. A pass still requires
   cold recovery, routes, fresh Query and whole30;
   build/unit/component passes do not close this gate. Any resumed source change
   must rebuild portable main/harness with exact provenance. Measured R49 inputs
   remain bound to clean `40a7e553`; later documentation is not execution evidence.
2. Qualify Local callback recovery under unchanged whole30 and current ordinary
   three-process CLI/HTTP. The genuine child test proves admission, three
   refusals and original retry/release, then exceeds whole30 at a second
   terminal retry; its result/equality/signer assertions and typed/fresh-family
   negatives remain open. `3b2d9b74` correlation proves its original child/issuer
   binding, not ordinary acceptance or retrospective attribution of `fcac175a`.
   Preserve complete-family/cold-adoption restrictions and original requests.
   Attribute the separate public NRT1 terminal-release ambiguity using existing
   retained-family/publication mechanisms. `5750f0c2` reaches saved NRT1/actor ACK,
   then release confirmation times out under 1.8s; quiet public exhausts its
   unchanged 120s issuance cap. No native release correction or archive-removal
   defect is established. Hot-row/root-fence protection is not full fixed-three
   NRT1 retry/reopen proof. Remove diagnostics after attribution no longer needs them.
3. Complete public lost-result/exact retry/whole locked-owner reopen,
   returning/all-cold pending Install, leader loss and actual ordinary CLI
   acceptance on current provenance. Fresh Query after recovery separately probes
   native issuance. Pins-before-record, first Intent and startup/reopen retain
   actual inspected-snapshot return and writer-lease comparison before writes;
   routes remain closed during recovery and no test-policy bypass is allowed.
   Requalify complete wrong-shadow/absent-origin forwarding refusals,
   observation freshness/cancellation, mutation negatives and cumulative >256
   public authorizations/pruning. Preserve original work/clock/anchor,
   journal-backed authorization, complete retained families, exact AOQ1/NRT1
   retry/release, package limits and whole **<=30s** recovery.
   Component/fixture passes and manual loops do not qualify automatic startup
   or M1. Guest bytes/pins remain unchanged; a guest change requires renewed
   independent reproduction and coherent pins.
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
- **Current diagnostic variance:** nested decoding, delayed registration
  succession, exact retained-operation admission and typed client-error loss
  exposed additional mandatory recovery work within M1. Their reviewed fixes
  and component evidence are recorded above and in the frozen review evidence;
  none authorizes new authority, a fallback, larger limits or longer deadlines.
  The earlier **1–4 source-hour** and **2–6 elapsed-hour** bands were conditional
  on no further defect and remain unreliable as remaining forecasts. They never
  covered combined M1/M2/M3 delivery.
  Supported THREE-node preparation BEFORE evidence proved normal admission
  refusal after late exact registration with no NOD1/pending map. Its same-open
  correction now passes late-registration, journal prewrite/ambiguous-write,
  complete-family and normal cold-refusal component cuts under whole30. The
  preserved first extended leader-bootstrap setup failure reached no cut;
  its identical isolated rerun passed without changing limits. Its cause remains
  unattributed. These are preparation-only fsync test-store results, not native
  policy/issuance or follower-forwarding qualification.
  Earlier `19e8d051` portable main/harness take **391.198s / 449.955s**; both
  include temporary diagnostics and provisional transport refresh. This is
  **14.0 minutes** combined; preceding `941b3d3c` took **14.2 minutes**, while
  the preceding fixture-only build took **7.4 minutes**. Cache/source build
  variance does not expand scope.
  Focused exact-retention units on `f4a3dc90` pass **0.101s / 0.101s /
  0.601s**, without qualifying integrated recovery.
  Recorded durations are high-confidence measurements at their source/toolchain
  boundaries. The prior predictive **3–8 minutes per portable main/harness binary**
  band had moderate confidence and was exceeded by R47's **8.44-minute** harness;
  main took **7.14 minutes**, combined **15.58 minutes**. Build variance is
  measured, but its specific cause is not isolated. These figures do not extend
  engineering scope/caps or provide an aggregate milestone estimate. Latest
  completed quiet/scoped public runs still fail.
  Scoped fixed-order evidence identifies forwarded terminal release timing out
  after actor ACK and saved NRT1; earlier dispatch/ACK and initial credential-stage
  failures remain preserved. Exact release ambiguity/recovery needs attribution,
  and full fixed-three native NRT1 retry/reopen remains unqualified. Static latest-row/
  root-fence protection does not justify an archive fix or prove execution.
  The latest ordinary CLI run demonstrates exact Local Create resume but repeats
  Local Install HTTP 503. Separate `3b2d9b74` diagnostics prove full signed
  issuer/child envelope binding after the registration-before-pledge gap.
  The reviewed Local correction is core built; its genuine callback test proves
  admission/three refusals and original retry/release, then exceeds whole30 at
  a second terminal retry. That partial result does not qualify current CLI.
  The corrected Query assertion is unreached, while the prior successful
  Local Query slice remains frozen. Existing native terminal-release and ordinary
  Local integration causes both need attribution. Earlier quiet pending-Install
  runs fail **186.302s / 244.666s** at normal-startup Unavailable: returning cut
  occurrence is unestablished; all-cold proves the receipt cut and all-owner
  reopen entry, without a recovery or Query pass. These durations are measured
  failed gate costs, not a successful recovery range or aggregate forecast. The
  first-pass quiet/scoped all-cold fails **239.765s / 242.958s**. Forwarded finalization
  Invoke confirmation fails before any cold guest outcome, so the first ACK
  tuning pass has no measured benefit. Earlier `19e8d051` finalization/handoff
  and count-only Local evidence remain frozen, without retrospective attribution.
  These failed-gate costs are not recovery or remaining engineering ranges. No whole
  recovery, global guest-stack or performance-only verdict is established.
  Cold/returning qualification remains; fresh Query separately probes issuance.
  No Query retry proposal was used.
  Counts alone do not bind episodes, and packaged-fixture client/native states
  were removed on unwind. No guest-failure/performance-only conclusion, engineering
  ETA or reliable aggregate qualification range is established. Remaining cold
  recovery, leader loss, cumulative pruning and ordinary CLI delivery may expose
  more work.
  Both original measured tuning passes are consumed and failed to qualify recovery.
  The explicitly renewed third candidate also fails, as recorded at Current
  position. No benefit or automatic cap extension is credited; another tuning
  change requires direction.
- **Packaging after correctness:** paired-role tooling/reproduction is
  implemented within the previous **4–8 source-hour** band. Corrected-source
  independent builds and strict frozen-builder bundle verification pass;
  packaged acceptance remains open. Signed resource ceilings are
  explicit but unmeasured; M2 must qualify them against retained data.
- **M1 overall:** no defensible combined ETA. M2 loading at 1,000 accounts/
  100,000 retained transfers, measured capacity/recovery, six-map parity and
  Agent backup/restore remain open. M3 additionally requires external hardware
  and prescribed 30-minute load/24-hour soak elapsed time.

The narrow ACK immutable-manifest reuse delta above is compiled; its first
measured cold runs fail before the optimized ACK branch. That first-pass evidence
identifies forwarded finalization Invoke custody confirmation delay; that
first-pass quiet run's inner cold failure remains unknown.
The original second candidate was reviewed, portable built and measured; quiet
all-cold recovery failed and its preceding scoped rerun failed before the receipt cut.
Every Invoke preparation, fresh absence and physical availability check remains
mandatory. The
separate retained-result availability seam and full audited-view reuse remain
deferred: raw Raft movement requires the fresh settled-prefix/absence checks.
Existing retained-registration early return already works. Never cache permits
across host-lock release/peer I/O or remove fresh physical corruption checks.

No completion percentage, deployment date, release promotion or master change is
established. Both original measured service-tuning passes are consumed without
qualification or benefit credit. The renewed bounded R48 candidate has also
failed; another tuning change requires direction. Do not extend the engineering-
week go/no-go cap automatically.
Architectural replacement and correctness diagnosis are not service-tuning passes.
Hardware is unavailable; prepare tooling locally and
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
  Root credentials/queues or revive the retired acceptance API. Source audit
  finds the M2 loader's final fresh per-member Ordered Queries cannot succeed
  at a stable follower through the current HTTP supervisor path; ordinary
  follower submission returns Unavailable, while forwarding is management-only.
  Close exact retained delivery to a serving leader and separately authenticate
  all-owner application/parity. A cached ASR1 or repeated leader response does
  not prove each owner's six maps, local freshness or catch-up. No public corpus
  or full-data parity pass is claimed.
- [ ] Exact-release phase measurements: preparation, outer/inner VM, persistence,
  queue and quorum. Recompiler selection is implemented, not service qualification.
  At most two measured tuning passes; stop for direction after two failed passes.
- [ ] Maintenance-window Agent backup/restore: drain admission; capture authenticated
  Shared state, opaque validated Local exports and lifecycle/retry state; separate
  keys, matching identities/artifacts and recoverable replaced destinations.
  Current public backup is registry-only and rejects live Agent roots; external
  streaming export is test-only and restore remains internal. Integrate those
  existing authenticated mechanisms rather than wrapping registry backup or
  describing it as an Agent backup. Production-owner maintenance orchestration
  for certified System state, detached Shared AXJ1/ACX1, opaque image Local
  closure and exact lifecycle/client retries remains absent. Existing detached
  catch-up applies to an already finalized same-identity replica; it does not
  authorize replacing permanent freshness/lock domains after their loss.
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
