# Agent saga: single live v1 plan

This is the single live plan. [agent-saga-review.md](agent-saga-review.md) is the sole reviewer entry point.
Detailed preceding R66/R67 evidence is frozen at **56bb1a9f849165f4581ba2f4df5d247180acdceb:docs/agent-saga-status.md** and the corresponding reviewer document; R37–R64 histories are frozen at **1bf30df26128eb59d4bb4e5837660b38d360fe35:docs/agent-saga-status.md**.
Use those immutable Git objects for exact old selectors/logs/hashes and earlier failed experiments; they are evidence, not another live plan.
This consolidation does not change the measured source, authorize a behavior candidate or close a release gate.

## Approved scope and milestones

Supported v1 is Linux x86-64, a fixed authenticated **three-node System/Shared deployment**, ordinary image-based Local Agents and one external-state Shared Clerk.
Use fresh entire v1 spaces, including System/control and Shared roots. Existing experimental spaces remain untouched, unsupported and rejected before writes.
No migration, legacy-read fallback, singleton System, public external-Local cutover, new profiles/frameworks, quorum redesign, offline mutation delegation or management Busy expansion.
No push, master change, deployment or automatic reviewer-branch promotion. Broader architecture simplification requires a separate decision after demonstrated lower-level causes.

| Milestone | Mandatory usable exit | Current claim |
| --- | --- | --- |
| **M1: recoverable packaged test pilot** | Fresh ordinary three-process CLI/HTTP startup; ready system actors; image Local and external Shared Clerk; authenticated Create/admit/Install/Invoke/read/denial; genuinely lost initial mutation response, exact retry, locked reopen; returning/all-cold pending Install and leader loss; observation freshness/cancellation, mutation/forwarding negatives, cumulative >256 authorization/pruning; reproducible artifacts, acceptance tooling and recorded workload. | **OPEN.** Demonstrated small-workload pilot only; internal/component passes cannot close it. |
| **M2: full-data operational pilot** | Publicly load 1,000 accounts and 100,000 retained signed transfers/external IDs; verify all six maps against actual accepted contexts; measure signed storage/resource bounds; full-data checkpoint, catch-up, reopen and recovery <=30s; authenticated Agent backup/restore including image Local and exact retries; rerun M1 on those exact artifacts. | **OPEN.** Offline corpus tooling is not public parity or operational qualification. |
| **M3: qualified v1** | Three actual 8-vCPU/16-GiB/SSD Linux x86-64 nodes, RTT <=5ms; 300 continuously active clients, 80% reads/20% signed mutations plus unrelated activity; end-to-end p95 <=1s/p99 <=2s including queues/retries; 30-minute load, 24-hour lower-rate retention soak, with write-only bursts measured separately; overload, faults, partitions/minority, backup/restore and failover <=30s; bounded resources, backend differential, full outer-PVM, reproducibility and final independent review. | **OPEN.** Hardware unavailable; preparation is authorized, hardware qualification and operator cutover remain external gates. |

All gates also require no acknowledged loss, duplicate effects, unauthorized access or false completion; exact retry survives restart/failover and minority cannot commit.
Measure bounded memory, descriptors, queues, retained results and disk under realistic backend credentials. Local three-process evidence does not qualify hardware, load or soak.

## Current position and evidence boundary

**Next integrated milestone: M1.** Implementation exists; integration still fails; service/operations qualification remains open.
Latest native/component source is **c138b89d33982279bd54428dbf7a094837e78b28** (S10), clean throughout admitted execution. Receiver-only diagnostic core67.470s passes; exact scoped forwarding130.245s/101 fails. Count-only SAFE18 locates prepared management denials and smaller owner-proof/package refusals, with source/error/caller limits below. S9 signed controls/publication remain passed historical components; returning retention still blocks separate quiet/scoped gates. The selected category-only diagnostic is applied, awaiting a successor checkpoint/build/reader/fixture; latest admitted evidence remains S10. No behavior remedy, public outcome or performance benefit follows.
Latest independently reproduced guest source remains **6f7ed8404871b956e9e7060081a296d0855d8d05** (S4/R70). Both ordered reuse remedies have preservation evidence; eleven native controls and two independent coherent guest builds pass, with all ten artifact pairs byte-equal to R69. Latest admitted artifact/builder checkpoints remain **c377d5082f051f70ed7acfd818e017eb4004ec1d** / **71a3ec15dd2be19ca05cde0474a2d0256cd7500e** (A/Q1), branch wip/ch08-runtime-directory.
Latest admitted portable/public-workflow source remains Q1. Ordinary completes Local Create/Install then fails Query; quiet/scoped cold recovery fail whole30. Q1 committee samples complete and scoped constructors/terminal/release succeed late. Those older artifacts/binaries do not qualify S9; R68 at56bb1a9f remains a separate frozen baseline.
Preceding S7/S8 fixture outcomes, signed count2/expected1 baseline, failed compile and correction proposals are frozen at **7b7f7a13cfe478351720428f6b0c460f5701c642:docs/agent-saga-status.md** and its reviewer document; earlier S4–S6 details remain at dd2de303:docs. Current S9 outcomes below replace their pending-execution claims. These immutable records are evidence, not another live plan; no deadline, limit, cap or authority change follows.
Repository/worktree: /home/daniel/src/virto/vos/.worktrees/ch08-runtime-directory.
Master remains d2378274c0503d9737edce9bcb189d24c3d4e247; reviewer saga/agents remains e6f2bb4551274064e3d080c64763e95faa8c5ebb.
This document update follows completed S10 component reader/admission fences and does not change its measured source. The ordered-fix approval below authorizes only the named remedies; the completed R68 diagnostic approval did not authorize a runtime remedy.

## Approved ordered fixes after R68

The user subsequently approved proceeding in order: implement decoded Observe validation reuse first, preserve the fully checked constructed entry, test it and measure its effect before deciding whether verified-observation reuse in the fresh audit is needed.
This authorizes the named first remedy and necessary source review, preservation/differential tests, independent coherent artifact reproduction and exact-artifact integration/measurement. It does not restart design, renew the engineering-week cap, raise limits/deadlines or authorize unrelated tuning. Current first-fix/coherent-artifact evidence has selected the second narrow candidate: omit only the repeated validation of the same immutable VerifiedSharedRecoveryObservation at manifest.observe. Transaction redesign and broader architecture remain deferred.
Current implementation work begins from56bb1a9f with the two R68 closeout document edits preserved. R68 source/artifacts/SAFE remain immutable baseline evidence; candidate/component results will remain distinct from coherent released-bundle qualification. M1/M2/M3 remain open.
The first source patch and real signed Observe regression have passed independent source review and native/physical execution. Only the decoded Observe arm can mint the existing borrowed work-validation proof; constructed Observe retains its checked entry, and only the later duplicate full-work predicate is omitted. All other predicate/restore/execution/purity ordering is preserved. The test-only accessor returns owned fixture state/slot after live-lease validation and grants no admission proof. Component measurements, coherent release/current portable build and public/cold outcomes are recorded below. Current committee samples complete; isolated savings, controlled deadline benefit and public acceptance remain unqualified.
Initial candidate44ab6d89dd9a45789fdb79755acf830ccbea2b1e native compile failed23.627s/101 with E0596 in the test-only accessor: the existing lease validator requires a mutable receiver. A one-line mutable-receiver correction preserves the original lease check/errors/copy order; no native test or guest outcome follows from that failed compile. Failed evidence remains at task-tmp/r69-core-preservation-44ab6d89.

## R69 first remedy: components and coherent repin

**Implementation:** b5aca82d contains the decoded Observe proof reuse and the test-only mutable-receiver correction. The full constructed entry remains checked. Real signed credential and committee work compare decoded/constructed complete transitions and unchanged four-part opaque state; target/origin/install/clock, program/schema substitution, bad signatures, malformed control ABI and corrupt/truncated/trailing canonical input are refused. No proof, authorization, ProgramId, freshness, purity, limit or deadline check is relaxed.
Core debug build47.848s passes with experimental-state-blocks,http-ingress,agent-runtime. Six preservation tests pass (total recorded2.408s): decoded Invoke fresh/retry/ACK/retired differential and corruption/receipt authentication; native/physical whole-opaque terminal observations; both raw-worker prefix/proposal barriers. Evidence: task-tmp/r69b-core-preservation-b5aca82d and r69b-native-preservation-six-b5aca82d.
System guest30.337s, portable debug linker164.677s and ordinary ABI probe1.502s pass. This linker is component tooling, not the portable public acceptance binary.

**Component integration:** the exact physical selector agent::clean_bootstrap::tests::physical::common_checkpoint::authority_observation::candidate_authority_observation_uses_fresh_quorum_local_guest_without_custody_and_reopens passes with both old released System runtime75.979s and corrected runtime72.577s, holding the current frozen core and reproduced Authority fixed. Both one-test runs end normally/exhausted with unchanged recompiler/scoped environment and bounds.
The fixture retains40 no-ACK observations, durable/whole-state comparisons, real reopen, revocation, minority/fresh-quorum, generation/cancellation and permit-return controls. Its native signed committee differential passes; this does not supply an outer-runtime committee timing declaration.
Finite SAFE reports each admit2899 records/38 explicit edges/zero unknowns,82 completed_done/82 purity-ok/82 own-work Refine records. Identical negative controls include two unavailable ReadIndex records, one unavailable local barrier and one stale refusal;81 receiver-complete records are separately established.

| Explicitly projection-declared work counters | Released baseline | Corrected System |
| --- | --- | --- |
| Outer execution,32 Refine records bound to three work aliases | 141.538–168.248ms | 108.550–128.070ms |
| Outer slices | 29 each | 29 each |

These are source-controlled component observations, not32 unique requests/attempts, isolated full-work-validation cost, matched signed-input benchmarking, quiet/public/SLA benefit or R68 committee deadline success. Fifty other Refine records have unknown query kind; no committee declaration exists in these runs. Nested wall counters are not summed or subtracted.
Baseline SAFE task-tmp/r69b-observe-baseline-b5aca82d/observation-runtime-safe.json SHA a1adeb00114c6de6740835fe6d5f8bdd4f8033f058641fc71eacf7e5ed353a2d; corrected r69b-observe-candidate-b5aca82d/observation-runtime-safe.json SHA57807cd52b2a07a86ed49687a74a08d8f22dab4cda1e37eab92e26eaaac0658f.
Reader r69-observation-runtime-safe-reader.py SHA a47af6d261bbf39cb8be41ec43d44844c4744fe5f9f096a88fc7c542dd07841e; pure source/grammar checks pass15 accepted/23 refused; independent source/privacy/evidence review passes.

Immediate prepatch56bb1a9f System guest was independently rebuilt29.931s and linked1.502s using the same frozen b5 linker. Both ELF and PVM directly match the old released controls byte-for-byte;1136 immutable exported source files remain unchanged. This closes the baseline guest-source gap without another physical arm.
Evidence task-tmp/r69b-prepatch-system-equality-56bb1a9f/prepatch-system-provenance.json SHA1d6992d014c9a8c2abd2158cabcdc16c569e2df4c70462999a7a107255fb9a57. Initial pure harness0dc26488 refused an ambiguous source mutation needle appearing twice; no baseline build followed that failed check. New harness1f551878 targets the unique precheck and passes; unchanged owner8b53c300 then executes the qualified build above. Preserve the failed harness; this was tooling failure, not runtime evidence.

**Artifact integration:** two independent full role/Authority/Catalog/signed-Clerk builds from immutable b5aca82d pass548.479s. Ten artifact pairs are equal; Authority/Catalog/Clerk lockfiles remain byte-equal to their immutable source. Embedded actor commands are offline with unchanged-lock evidence; direct runtime/host commands explicitly use --locked. The trusted fixture signer metadata stays unchanged and its temporary copy is removed by the existing owned script.
Root target/agent-release-reproduction/run.J08TTq; admitted provenance task-tmp/r69b-coherent-role-reproduction-b5aca82d/role-reproduction-provenance.json SHA8fed3d7241f9fa395c3cc019bf43767751d266783a1d53dc5a7f66f634a839b3; runtime-role-inputs.toml SHA2a8d344233ff66d87c01f798a707bff71e68046b49ebfee326bc1a287fa0b83c.
Both independently reproduced System ELF/PVM exactly match the measured corrected component. Catalog and signed Clerk bytes remain identical; Authority/System/Shared signed packages change coherently. Local canonical source/blob/program/ELF/PVM, public template signer and signed external ceilings remain unchanged.
Artifact A=c377d5082f051f70ed7acfd818e017eb4004ec1d and builder Q=71a3ec15dd2be19ca05cde0474a2d0256cd7500e are admitted. Canonical all-mode reproduction293.903s/0 passes normal/exhausted/noninterrupted with Q clean before/after: task-tmp/r69b-all-mode-release-71a3ec15/all-mode-provenance.json SHA5698fb98680eff7ff406e4b3d87c23c28a1fb112ee7079f5d3eb877425cb6d26, exact six-file release target/agent-release-reproduction/run.HpoXXT/release.

### Current coherent-artifact workflows

Fresh portable main415.924s/harness461.082s/strict verify0.101s pass (877.107s/14.62min build cost). Evidence task-tmp/r69-cli-build-71a3ec15/provenance.json SHAc2e3dc73e9ffca29c893401aaf56a6dd75a0a5b7776d1f95176e6ca149b69818; frozen main1e1c551e716c54d3a7ecbca7bf898f82c19bee49adbb7e58e08c969391e24f31, harness87bc3189f516e86d5454b602aec0e230a0b005940df041bc69e81eb539b9b618; strict-verification result40b28874487518637c78418cc165dfb1117e0e97e33b190d4f177943a224b19c. Mutable Cargo target main differs and is not admitted. Original source/toolchain/features/portable flags/six roles+Clerk/private/group/exhaustion/noninterruption/cleanup and pre-post fences pass.

| R69 run at frozen Q71a3ec15 | Admitted outcome and limits |
| --- | --- |
| Ordinary, task-tmp/r69-current-actual-cli-71a3ec15 | **FAIL92.701s/script1.** Ready9.548s; Local Create21.673s/2 attempts and Install47.239s/5 attempts complete; Query8.712s/1. Shared/handoff/reopen unreached; inner Query cause unknown. Cleanup2.802s/0, three launches/zero survivors. |
| Fresh quiet all-cold, task-tmp/r69-pending-all-cold-quiet-71a3ec15 | **FAIL223.646s/101**, one failed/exhausted/noninterrupted. Closed whole_pending_install_30s at member_cold_install_tests.rs:277:9; no quiet inner-cause inference from scoped evidence. |
| Eligible scoped all-cold, task-tmp/r69-pending-all-cold-scoped-71a3ec15 | **FAIL246.870s/101.** SAFE20191 records/580 explicit edges/315 phase groups/54 thread aliases/zero unknowns. Current committee completes; cold constructor/issuer/terminal/release success is late, not whole30 or public Applied/routes/Query qualification. |

Run-local SAFEs: ordinary r69-ordinary-cli-metadata-safe.json SHA6dc5db945cf9b41b904e70f5648514b4aef603113f779e3eb4b96b54a59871ff; quiet r69-quiet-stage-safe-summary.json SHAe9aa610b6650c15d72d74505a216514f454ffd2f95225b6703760ec65d78fca3; scoped r69-refine-execution-safe-v3.json SHA6d87ebcb4073af39cc02325ba123cd31e0a64d87f47d9d673eb83bb00acf3051.
Explicit Create root30/original31→committee request39/work41 has eight Done/purity/callback/receiver Complete records and no request39 deadline refusal. Execution116.604–174.083ms, callback129.754–194.891ms, whole completion256.333–1445.083ms and Refine outer99.065–155.964ms remain distinct clocks. R68/current source/artifact/sample contrast is uncontrolled, not a same-input speedup or isolated validation saving.
Cold Install root172/original171/work173/auth174→final199/work200/auth201/registration202/sequence5 reaches issuer18773; full-input Invoke207/ACK208/ACK209 anchors on all three nodes and buffered Ready; terminal19343/release19834. Final Invoke's directly bound fresh audit bodies913533/931646/966486us contain46 rows/five registrations/one release/11 Ordered. Registered419201–433020us and Ordered172482–189114us folds are nested and not removable cost.
All three constructors return Ok: id2/replica1/thread33=20.944182s, id1/replica2/thread34=23.565861s, id3/replica0/thread32=65.182786s. Slow id3's own borrowed recovery helper47.437681s has four Unavailable returns then a fifth Ok call20.562442s. Its own startup cumulative checkpoints are system_owner17.279s/shared_lifecycle_recovery64.719s; do not subtract independent clocks or pair local ordinals to family calls. Existing retry budget limits scheduling after Unavailable, not a running call. Nested owner/open clocks lack node/thread/call declarations; generations_recovered stays across retries, and no removable fresh recovery proof is demonstrated.
Release211 explicitly binds original171/work173/registration202/genesis10/admission11, with own host wait2.799917s/custody completion4.342162s. Positive confirmation precedes the original deadline refusal check; late success is not timely1.8s, a hidden-holder proof or whole30 qualification.
Initial strict reader refusal2 published no SAFE. Closed postfenced probes report only unknown_or_malformed_source_record2/public reason036 (legacy capture prefix). Readerf9d3f0b82ea3f397686153a8cba452a9793b8e4c5afaeacae20d6b99a700ac9e now ignores only unselected captured messages with unmatched legacy headers, guarding both MARKERS and management_finalization_phase=; all selected/new-family/context checks/eight validators/fences remain. Pure result6249fc3af0c1d4b310e073d25aff0171f728af9ab94018cd1fe7d630869c3360 preserves36 accepted/185 refused/six source-fence negatives/12 validated-unselected cases plus selection/fallback/new-family regressions. Old refusals are tooling evidence, not product failures or partial causal admission.

**Qualification:** M1/M2/M3 remain OPEN. Ordinary Local Create, exact Shared Create committee/GenesisDecision deadlines, actual cold/returning Install confirmation, loss/retry/locked reopen, leader loss, Query/forwarding/denial and >256/pruning remain integrated gates. The ordered second audit candidate passes native preservation/coherent guest reproduction; current frozen portable/public execution, isolated cost and sufficiency remain unknown. No redesign or unrelated tuning is selected.

### R70 second remedy: preservation and current blockers

**Implementation:** only repeated `VerifiedSharedRecoveryObservation::validate` at manifest.observe is omitted. Canonical owned constructors still fully validate binding, signatures, exact positions/claim/input; fresh authenticated physical reads/corruption checks, complete changed-candidate/member validation, global positions and assignment-last remain. No cross-guard cache or permission is minted.
Frozen S4 core build22.624s passes; eleven exact native controls pass12.022s total, including checked-manifest differential, complete signed extended families, first capsules/ACK/release/no-op/refusal bytes, malformed predecessor prewrite refusal, physical reopen/current corruption and raw-worker barriers. Provenance task-tmp/r70c-core-preservation-6f7ed840/provenance.json SHA1f26ddfe13c657f077cdca99a907e3d10e82c3f60ce04977a812577695185e8d; eleven-summary task-tmp/r70c-native-preservation-eleven-6f7ed840/summary.json SHA475670aab443c1d94e893f973365d895339f172cd0f9283793781c7bae94e0e0. Independent admission passes.
Two independent full guest/package builds from S4 pass500.336s; all ten pairs match each other and both R69 passes byte-for-byte, including the measured System runtime, Authority/Catalog and signed Clerk. All18 actor locks match immutable S4 before/after/export. Provenance task-tmp/r70c-coherent-role-reproduction-6f7ed840/role-reproduction-provenance.json SHAcaf3129c0656299e3452277196ec1de641b4d139329536f70d2442d00073de81; artifacts target/agent-release-reproduction/run.UPsnyb. Recorded guest equality preserves digest values; it does not permit stale source/materializer/builder provenance or close public qualification.

### S9 exact-shadow correction and component blockers

**Implementation:** S9 applies reviewed correction task-tmp/r70f-exact-shadow-headroom-correction.patch SHA413048af5e54e12f03a6b58ecb0a5f02ea0fabdfc1332fe5c27faa1130d3ad11. Only exact duplicate pending `(anchor,envelope)` pairs are skipped; every per-holder future reserve, incoming signed request/full-family/fresh validation and unequal-pair collision refusal remains. The unchanged S8 signed baseline demonstrated count2/expected1 before this correction; its failed compile and all preceding fixture history remain frozen at7b7f7a13:docs. The earlier physical joint-budget inner leaf was not established.
S9 core54.458s/0 passes (task-tmp/r70i-core-exact-shadow-correction-7b7f7a13/provenance.json SHA8b16b0489dae87767347c62f1dc5cc9bad95ff1e6abff87ddd1bbc4decc53971); four exact native headroom/shadow/conflict/ACK/owner-scope controls pass0.504s total (r70i-signed-headroom-correction-four-7b7f7a13/summary.json SHAc22b7f034a89065285d7485bbac279a9f445016787b63a20f2d8694bcc842085). This closes the demonstrated native selection defect, not the complete forwarding/retention or public gates.
The genuine two-survivor LeaderNoop checkpoint fixture and exact publisher/completer composition are now executed under their original30s bounds. Neither adopts the offline owner, ACKs its retained original family, submits the constructed checkpoint Query, manufactures progress nor relaxes replay/authentication.

| Isolated S9 component execution | Admitted result and boundary |
| --- | --- |
| Exact publication retry, r70i-exact-publication-retry-7b7f7a13 | **PASS77.486s/0**, summary53e2513ed168817e3a4d8b4a6e77ab4a02245fb79330e5c5f10ff0dad9dde355. |
| Quiet forwarding, r70i-forwarding-negatives-7b7f7a13 | **FAIL136.746s/101**, summary59da35508408dcb20f68d4b2bfbfcd8803d072d7a3fa4d80e19fd282bea1439d. Original Install helper exceeded unchanged30s at34.385798337s; operation returned, but its Result was not inspected before the cumulative assertion. |
| Quiet returning retention, r70i-retention-returning-follower-7b7f7a13 | **FAIL360.590s/101**, summary3162ec7ac724af4819f162caebb3c216341a3f3fd01d4b23f70cc3696b6ce319. Scheduled Local Install hook6 was not consumed within30s while calls returnedUnavailable (management_retention.rs:2022); its earlier leaf remains unknown. |
| Scoped forwarding, r70i-forwarding-original-install-scoped-7b7f7a13 | **FAIL142.251s/101**, summary52155759f181730939ddf4cb23cc97d624b349edf9da87f9e51d784e38af7072. Six retained-owner successes82.074–88.424ms and six management-submission errors3.573251–3.628500s; no recorded later Shared durable observation/finalization. |
| Scoped returning retention, r70j-retention-authorization-scoped-7b7f7a13 | **FAIL431.963s/101**, summaryc163f827030a292ae7b24fa00658b112f6f10b770dad0c9e4b99b30fe8d5b0be. Exact source-location SAFE reports management_retention.rs:544:9, unchanged30s composite certified-checkpoint wait. Source control flow places this at the second prune call2100 after hook6 was consumed; cycle/composite QC inner leaf remains unknown. This differs from the quiet hook6 boundary. |

All original source/binary/component/input/environment/private ownership/owned-process/exhaustion/noninterruption pre-post fences pass. Exact-one component executions and deadline-sensitive runs are isolated; no matched speedup or public qualification follows.
Quiet original-install-bound SAFEfcac38fa8e145d0c496c74b2c2e5e5d263bdf68ebb74eb5fabccf3a883482d61 exports only that cumulative bound/unknown Result. Scoped forwarding r70i-original-install-phase-safe.json SHA01b985b2820eba0ffcd170f9a811bfb4cc42c00f2eb853971bd4ad34385be6fb records one prior Create finalization Done/issuer save separately from the missing Shared Install completion records.
Same-stream transfer SAFE r70i-install-transfer-phase-safe.json SHAf29fcd4c16da413369568e684749487fb1cea4eafb43c77a65ef6d0bb8f2a806 has six progress_complete/finish_sent and six local_timeout/Unavailable records; peer-refusal counts are separate and not request-paired. Missing markers do not establish nonexecution, absence of commit or a particular holder.
Same-stream count-only boundary SAFE r70i-forwarding-boundary-safe.json SHAecaaa1340e6a4657230ad1589ff45a6635363e4fe852733a91ec375b80deef05 records six origin_forwarded, zero peer_validated_new_row and zero waiter-failure records. Thirteen buffered Ready records belong to the whole fixture and are not bound to this Install. Receiver preparation/proposal positives remain unproved; no capsule-absence, no-commit or pre-wait cause follows from zeros. Its pure checks pass221/644/28 with unchanged original fences.
Retention r70j-retention-authorization-safe.json SHA74d570a831870e193cfb341d87faf219db37c93da7bd0d20e982da656a0f3727 admits114 phase records in five source-declared original root/invocation alias groups, not five attempts. Report-local group5 has one invoke_complete, two invoke_error/Unavailable and two capture_error/Unavailable records; no approval-error/receipt-start record. Group order does not identify Local Install or its failing call. invoke_complete only reports returned RuntimeOutcome; hook6 follows decoded approval and precedes receipt_start, with no error trace when consumed, so absence alone cannot classify it. Independently reviewed source control flow permits at most three distinct authorization intent pairs before the first prune1399; five positive declared pairs plus the failing QC location require the second prune2100. Its prerequisites2022–2037 require hook6 consumption, separately from marker ordering. Cycle/composite QC leaf remains unknown. This scoped progression does not supply the quiet failure's cause.
Retention source-location SAFE r70j-retention-source-location-safe.json SHAed444a8e7ded0da08e8937fc70f93de7e5987bde1fb80f6ea2173e929f19b3ae selects only the exact test-thread public panic header, no body/keys/requests. Source/helper location is a reproduction boundary, not an inner cause. Reader pure checks pass150/208/21 for authorization and independently reviewed location grammar; these qualify tooling only.
Same-stream count-only checkpoint SAFE r70j-checkpoint-boundary-safe.json SHAb2956a71e72f8c4c70bde6c913b3aeda7c624621cf0f350eb6ce1b4b42539bbe admits84 records: quorum/install/reattach each have two Ok phases, all seven voter phases have ten records, and common_snapshot_signed/reply_ready are true ten times each. Eight collector Unavailable records positively report expired=true under the original1.8s gate; selected barrier/local/early-refusal records are zero. Source collector checks a verified certificate before its pending-empty/deadline refusal; voter signing/reply readiness does not prove timely delivery or matching collector acceptance. Counts alone identify no calls/cycles/claims/owners or quiet cause, and zeros do not exclude unlogged paths. Reader r70j-checkpoint-boundary-safe-reader.py SHAa0381b12ce99ffd8cc217b8389d565d93e1ffc8d93d0c8248ff9d32ce85435ff and pure dd99d18f9f3a7c14645db682b47442daac7f9619a4230e27e1297cdbe4eb20c3 preserve original fences; resultda5e6b582368833e62e7ce58b179754c54a3a0abcd8c348a9f4fcf5d28f593e1 passes1650 accepted/378 refused/22 source mutations with zero helpers/private inputs. Tooling checks are not component qualification.
Same-stream timing SAFE r70j-checkpoint-timing-safe.json SHA21cd10460afae61e74eb3255c98538732465586ec99c0ed683b0a23627e1eb91 preserves all84 count records exactly. Each range is cumulative from its own function entry, includes preceding work and grants no pairing:

| Source-owned cumulative phase | Admitted range / count |
| --- | --- |
| Voter handler: attachment_verified; common_snapshot_signed=true; reply_ready=true | 28.789–38.818ms; 0.951040–1.949052s; 0.951111–1.949129s; ten records each. |
| Composite checkpoint: quorum; install=Ok; reattach=Ok | 2.541856–3.315275s; 5.659547–8.940774s; 6.312069–9.742013s; two records each. |

Some handler signing/Ready cumulative markers exceed the numerical1.8s collector budget, but cannot be matched to its eight expirations. This is not isolated signing cost, a phase difference, transport/holder proof or quiet-run cause. Independent source control flow requires two successful first-prune cycles before the second prune, accounting for the two positive checkpoint phase sets; count ordering identifies neither expired calls nor the failing cycle. Reader386675ea1ab97c95809c63f7bedd09a7f45a1dd81f8da3918c494e7db01fb6a8/pured1689ed5d4d9dd49440c211f2df8ea89a702e13af6b85a69c51880177e7480fe preserve original fences; timing pure result6cd3ee166aece7b657fee8ae804ffa774806dbe36f157aa3449868b2f9161ac2 passes1677/403/26 with zero helpers/private inputs. No new runtime run or source change produced these projections.
**S10 receiver diagnostic — implemented; component execution completed:** reviewed task-tmp/r70j-shared-install-receiver-diagnostic-proposal.patch SHA1934ccbd09a9406b0fc8ad4411312379e561ad4e871ee0975f431113f5cf81f8 adds only closed phase/status/public error categories under the existing diagnostic flag. Receiver markers are Finish-only, ordinary submission uses its already-computed forwarded provenance, and driver markers expose only the existing approval mode; no identities, payloads or new clocks. Original reads/proofs/signatures/checks/error mapping/guard-drop/wait/cancel/cleanup order, APIs, authority, limits and deadlines remain unchanged. The three-file source projections are network/shared_agent f676d36bb852715549c49dd673494b90da6a2fc1f22d6d3f260d0c11bfda4c4c, network/forwarded_management 3f3224f38982d0f4f8358271312ced295db72b28df781105bc274b612f0b5377 and driver/forwarded_management 588db871126b32b8c37bdc951813af98572a829fb628c11ddabc4a7ef51f6985.
S10 core task-tmp/r70k-core-receiver-diagnostic-c138b89d/provenance.json SHAaf78532feb969017399aafb3e2c55817c8e36cf22db61184b43de28e3a934849 passes67.470s/0; frozen native binary0f79038aea9a8c917e45b272a60b55f314ac6039881eb31e4e2e36b48bc19c99. Scoped task-tmp/r70k-forwarding-receiver-scoped-c138b89d/summary.json SHA14c20bb54bd5f3c90480eee10a1c6d0b4d18720d09a17191aa377a6456c47131 fails130.245s/101, exactly one executed test, noninterrupted/exhausted with original source/tool/artifact/environment/private/owned-process pre-post fences independently admitted.
Receiver SAFE r70k-shared-install-receiver-safe.json SHA61f9b339b9c0eec338ee42d4a90171bf5511d0b9ea81b9813348c2373ea5a8f7 selects18 count-only records: ordinary_denied/receiver_denied Unavailable six each; owner_proof/management_submit InvalidProvision one each; package_load Unavailable one; owner_unreleased_slot_missing approval=false three. Nested records can describe the same failure; counts identify neither calls nor original fixture requests. Source's prepared-denial branch requires all four preview lanes unchanged and RuntimeOutcome::Management(Err(_)), then returns before a new waiter/proposal in that path. This is not a guest-stack error classification; its ManagementError and original caller remain unknown. No capsule/commit/holder absence follows from zero other labels. Reader00f6532f3e6ce05c642c72bfa3a891e712e0f3c804033b274dbfc168201cb841/purea44f2fa5d671f0458bcf9b76e5ebdb0a0aacf31b81c26cc5a875a3e961dc0c7d result1e670ceecb7e1675cc9d5c6d8b1f527f03cb722c3d1bad64f0a3ae37f5ab9d3b passes809/263/30 with zero helpers/private inputs/identity exports.
**Selected denial-category diagnostic — applied; integration pending:** task-tmp/r70l-shared-install-denial-category-diagnostic-proposal.patch SHA5334a07890502ec5428e4ef958e452d4c56a4687e66705978002e1815970394f has independent source/privacy preservation review and is applied in the successor source/docs bundle. One insertion borrows the already-cloned ManagementErr in ordinary_denied, exports only15 static SDK categories (Busy debt discarded) under the existing forwarded decision/diagnostic flag, then preserves the original return. No new product reads/hashes/clones/clocks/locks/proofs/API or checks/error/drop/callback/limit/deadline change. Reviewed network source5011adf34115faeb49f5231de86f65c5a94215991d149dc414d667a7bde7daea; latest admitted S10 network remainsf676. The successor checkpoint/core build/reader/scoped fixture and category evidence are pending; no future HEAD, runtime result, benefit or behavior remedy is claimed. Three semantic limits remain: unchanged four-lane ManagementErr preview is a prepared denial rather than RuntimeError/guest-stack classification; the fixed category discards Busy lifecycle debt and exposes no detailed policy explanation; nested category/refusal counts have no original request/caller/attempt binding and may project one failure.
**Next bounded evidence step:** preserve completed S9/S10 fences and qualify this named diagnostic before classifying the prepared ManagementError; existing markers expose only management_error, so no further same-stream reason projection is selected. Keep nested counts unpaired, quiet outcomes independent and package/registration/intent/lease/filesystem internals coarse. No behavior remedy, audit suppression, cap renewal or architecture choice is selected. Resolve the two component blockers before final-source reproduction/coherent A2/Q2/six-file/portable/public qualification; M1/M2/M3 remain OPEN.

| Area | Implementation | Integration / qualification |
| --- | --- | --- |
| Internal Authority reads | O1/O2 observation cutover and O3 legacy lifecycle removal exist; management retention and public Invoke/ACK remain. | Frozen purity/authentication/no-write/freshness components exist; all replacement acceptance below still require integrated released-artifact evidence. |
| Runtime/artifact/startup | Corrected decoder, separate signed System-image/Shared-external roles, coherent pins, strict six-file verification and normal fixed-three startup exist; Local canonical image is unchanged. | Coherent reproduction/prewrite/factory/finalization components passed before deliberately opening startup; no M1 claim follows. |
| Publication/recovery | Exact ambiguous publication re-admits original leased stores; pending protection survives finalization/retirement; fresh exact GenesisDecision precedes terminal cleanup. First-owner/full-family restrictions remain. | S9 native exact-pair correction and publication retry pass; S10 selects prepared management denials before its new proposal path, with category/caller unknown. Forwarding and retention authorization/QC controls still fail separately. Scoped samples establish distinct boundaries, not quiet causes. Current guest/artifact/portable/public provenance and whole30/recovered Applied/routes/fresh Query remain open. |
| Signed release | R57 derives scalar capacity from one fresh signed-release preflight under its existing guard/read transaction; final worker snapshot/barrier and prefix-checked proposal remain. | Nineteen signed preservation/component tests prove counter deltas and raw-worker/prefix restrictions. Packaged vosx links non-cfg(test) vos: those counters are not packaged execution proof. |
| Current ordinary CLI | Existing public CLI/HTTP and owned three-process script are used. | Current Q Local Create/Install complete, Query fails with inner cause unknown; Shared/handoff/reopen remain unreached. Historical Query/admission503 findings stay separate. |
| Current cold recovery | Existing source-bound phases/closed refusals and unchanged recovery/deadline rules. | Current Q quiet/scoped reach cold recovery but fail whole30; scoped constructors/terminal/release succeed late. R68 setup deadlines/R66 owner-confirmation failures remain separate. |
| Data/service/operations | Signed offline corpus, bounded public-loader preparation and read-only hardware collector exist. | Public full data, all-owner parity, resources, backup/restore, service, fault/soak/hardware and final review remain open. |

## Approved R68 diagnostic session

User approved **diagnosis and a fix proposal only**, with a four-hour wall-clock cap: start 2026-10-06 19:40:09 UTC, deadline 23:40:09 UTC, including review/builds/runs/evidence/cleanup. This does not renew the engineering-week cap or authorize a behavior remedy.
One reviewed host-only closed admission/error/timing bundle and finite reader extension; preserve original calls, masks, guards, callback/assignment order and checkpoint fallback. Bind the already-decoded original AOC5, not unique attempts; keep physical error categories payload-free and source-context restricted.
Existing core preservation tests may compile their debug harness before **one portable CLI main/harness build cycle**; core evidence is not portable CLI provenance. Then sequential ordinary CLI, fresh quiet all-cold, and scoped all-cold only after admitted quiet failure. At most one same-artifact replay for a named non-reproduction/unreached branch, with ordinary priority; no automatic second portable build. Preserve all original evidence fences, environments, deadlines and owned cleanup.
Delivered separate causal boundaries/direct durations with unknown intervals, focused proof/recovery/readiness review and ranked fix proposals below. One-hour checkpoint reported; the finite one-build/four-workflow cycle ended before the cap. CPU flamegraphs, guest symbol export, held Shared-admission probe, new frameworks and runtime behavior changes remained outside this session. M1/M2/M3 remain open.

## R68 diagnostics and admitted evidence

**Implementation:** frozen diagnostic source **56bb1a9f849165f4581ba2f4df5d247180acdceb** adds closed admission phases, source-bound physical/metadata refusal categories and original AOC5 preparation entry/reply markers. Original Results/masks/calls/guards/drops/signing/callback/assignment order, proof checks, deadlines and pins are unchanged. No runtime remedy or guest change.
Reviewed five-file proposal: task-tmp/r68-admission-diagnostic-source.patch, SHA 1a9feb44d2cd0f3b2812895d838f45f995c6c23ec63ddd9df9cea6fa7fbb234a.
Successful timing records require the scoped diagnostic environment; ordinary error WARNs use closed payload-free categories. Capture invocation is caller context, not an individual attempt or a historical row/work identity.

Core debug compile90.495s and two raw-worker preservation tests1.609s pass. Four isolated physical exact-retry cuts pass at30.034/28.731/29.231/38.239s: registration timeout, journal prewrite, write-then-error confirmation/proof cleanup and cold missing-journal refusal.
Original core features are experimental-state-blocks,http-ingress,agent-runtime. Exact request/window/anchor/full-family, no premature WAL, ambiguous retention and worker/prefix barriers remain covered; these are components, not public-workflow qualification.
Evidence: task-tmp/r68-core-preservation-56bb1a9f and the four r68-operation-* directories.

**Integration:** exactly one portable main/harness build cycle and four sequential permitted workflows; no second build or extra replay.
Original source/toolchain/commands/features/environment/frozen binaries/six-file bundle+Clerk/private ownership/group exhaustion/noninterruption fences independently pass for each run.
Build: task-tmp/r68-cli-build-56bb1a9f, main441.148s/harness840.133s/strict verification0.605s, all0; total1281.886s/21.36min is build cost, not application performance.
Provenance SHA 2d2e224355d11e88485e11b2d213244bd8cd0dec5a5dce8f2cf0170525fdca9c.
Frozen main SHA 24f0b97264f6e3fbc34230deb75cc1c03bf7121592c3ec56122cdafa35cb43ab; harness ade639a38f4920e45ad49e416c7a5a542d4ac0edea12a1e74e3116d656edf4fd.
Strict-verification result SHA 7a6b18627919a1581b47dc3c5574381d322e9ea387997b9d1846b5b501c548d8. Mutable Cargo target binaries are not the admission boundary.

| R68 run, all at frozen 56bb1a9f | Admitted outcome and limits |
| --- | --- |
| Ordinary, task-tmp/r68-current-actual-cli-56bb1a9f | **FAIL242.650s/script1.** Ready63.381s; Local Create170.150s/28 attempts, first27 exit1, final child124. Install/Query/Shared/handoff/reopen unreached. Cleanup0.373s/0, three launches/zero survivors. No inner Local Create cause classified. |
| Fresh quiet all-cold, task-tmp/r68-pending-all-cold-quiet-56bb1a9f | **FAIL166.276s/101**, one failed test. Closed ordinary_packaged_shared_create_retryable_timeout1 at member_handoff_tests.rs:504:17: initial ordinary Shared Create setup's120s retry bound. No cold cut or whole30 qualification; no inner cause attributed from another run. |
| Eligible scoped all-cold, task-tmp/r68-pending-all-cold-scoped-56bb1a9f | **FAIL187.939s/101**, one failed test. Reader admits5035 records/142 explicit edges/71 identity aliases/20 thread aliases/203 phase groups/zero unknowns. Initial Shared Create authorization and exact committee observation findings below; no accepted cold-cut/finalization/release proof. |
| One reserved ordinary replay, task-tmp/r68-current-actual-cli-replay-56bb1a9f | **FAIL242.849s/script1.** Ready63.807s;26 recorded Local Create attempts, all exit1; no aggregate Local Create row establishes the final branch/duration. Install/Query/Shared/handoff/reopen unreached. Cleanup0.481s/0, three launches/zero survivors. No fifth workflow permitted. |

Ordinary metadata SAFE SHA e987bbcbdf893697c9086003713dbb54ad5a9f098a3f01575767e66325c07869; replay e9c9952f5f6b506e84703a46025e2df148eee84dc7fa0ea1314048a0080afb99.
Quiet SAFE8ff595d2f111bc0acfc4b9b1a0a88160f55e7a7ed08c4ebe371c328f619cd362; scoped basicSAFEf68661c6d19475f1004e7110db6b57cb247e6593069bca519a0eb577c2226128.
Detailed scoped admission-critical-path-safe.json SHA **2d9b2a3c2f60093503a8eb159ca51a5d4fcadd1baf5dd8647c4cfc8221b84728**; reader r68-admission-critical-path-safe-reader-v2.py SHA62dd3bc3157c501ec2012a452c62ee2a8059ea59ceebd826cfe92ec3701b20df.
All groups ended normally/exhausted/noninterrupted; cleanup outcome and zero survivors are separate facts.

### Scoped initial Shared Create: demonstrated boundary

Report-local root57/original invocation58/work60/original authorization61 belongs to owner node1/System4; managed Shared59.
Initial management capture passes initial/capacity/publication prefix checks e2914/e2934/e2986. Direct registration_prepare2.867783s/e2983, metadata_commit1.188907s/e3061 and persist_callback88.264ms/e3070 are separate nested boundaries, not additive preparation latency.
Exact authorization input68 is prepared e3179/appended at34 e3182; its waiter times out at1.800082s/e3203.
The same full input is later durably anchored on nodes1/2/3 at e3210/e3231/e3233. Append/anchor alone is not delivered authorization.
Exact retained retries positively record invoke_complete and validated receipt_complete ten times (first e3402/e3404, last e4955/e4957).

Committee request69/observation70/work71 is explicitly bound to the same root and original authorization invocation (first e3415).
Ten enclosing observe_execute records return completed_done and ten purity records return ok; ten callbacks return ok, then ten receiver deadline refusals report **2.120670–2.222227s** cumulative observation time.
Source authority_observation.rs:260 uses the existing **1.8s** ORDERED_REPLY_WAIT for the whole observation; its post-callback check at480 rejects these completed observations.
This demonstrates a scoped observation deadline blocker after successful guest execution/purity. It does not establish a general guest/stack verdict, prefix instability, corrupt state or policy denial.

| Exact committee observation direct clocks, ten samples each | Recorded range |
| --- | --- |
| ReadIndex coordination | 4.672–7.074ms |
| Fresh barrier, including leader attachment checks | 174.472–185.573ms |
| Receiver host-lock wait | 0–0.544ms |
| Initial fresh audit | 658.595–735.457ms |
| VM run, halt status | 1.037649–1.099056s |
| Enclosing observation execution (observe_execute), completed_done | 1.051371–1.114491s |
| Callback, enclosing guest work | 1.161326–1.214998s |
| Receiver deadline refusal, whole observation clock | 2.120670–2.222227s |

These clocks are direct samples; nested intervals are not summed, subtracted or paired into unique attempts. Repeated aliases declare semantic identity, not individual calls.
Every exact committee observation audit records34 ledger rows/one registered/no released/five Ordered rows. Inner audit total658.363–735.254ms contains recovery fold287.189–347.416ms, registered fold157.728–201.006ms and Ordered fold129.455–146.406ms. These nested clocks do not establish removable validation, touched-account cost or full-data scaling.

Existing Refine counters were independently admitted from the same completed scoped input; no additional runtime run, trace framework or guest instrumentation was added.
Refine SAFE: task-tmp/r68-pending-all-cold-scoped-56bb1a9f/refine-execution-safe-v4.json, SHA **56cf75516e1c621e4e9c0a7ec951c8f5463816f848f8006fe906065846f313e5**;5224 records/142 edges/71 aliases/20 threads/204 phase groups/zero unknowns.
Ten own-work counters bind the committee observation through the same explicitly declared invocation-work domain. They are aggregate phase clocks, not CPU samples or per-function flamegraphs.

| Exact committee work: Refine counters, ten samples | Recorded range |
| --- | --- |
| Outer runtime execution | 973.000–1032.692ms |
| Inner create, including decode/preparation | 15.924–19.010ms |
| Inner invoke, including frame/refund handling | 29.252–34.753ms |
| Other host dispatch | 15.758–27.057ms |
| Outer slices | 39 each |

Source pvm/runtime/src/refine_host.rs:177–224 times outer resume and source-selected dispatch phases; context load/output decode are excluded. Drop emits counters even on error, so counters alone prove no successful outcome. Guest Done/purity evidence is separate.
This isolates most VM time in the outer runtime rather than inner Authority execution on this exact scoped work; it does not locate the outer leaf or measure proposed duplicate-validation savings. Program preparation caches already exist; no cache-miss/eviction claim or controlled speedup follows.
No admitted finalization_child, issuer save, terminal/release or cold-constructor proof follows for this family. The failed initial Create setup supplies no cold Install/whole30 result.
R68 ordinary Local Create failures remain separate lifecycle paths; the AOC5 Query-entry probes were unreached. Their missing records cannot classify Local Create or transfer the scoped cause into quiet/ordinary runs.

### Reader correction and privacy boundary

Initial reader317a refused two full-input waiter records lacking same-stream management prepared/appended declarations; it produced no partial SAFE.
A reviewed count-only locator9347 retained that refusal and exposed only the fixed ordered_waiter_full_input_declaration_missing category/count2.
Source proves ordinary invocation and clean-management submission also use OrderedReplyWaiters::wait without those management declaration markers.
Narrow reader62dd therefore admits only the waiter's own exact source/full32-byte ReplayInputId/five closed reasons/u128 duration, with no caller/route/family/attempt or successful-append inference. All seven other binding validators, parser/projection and original pre/post fences remain unchanged.
Pure4ca79a7f4a50ad332517731c0b4057ea2742db9c6cdf5a94855bf9a366217fec passes13 accepted/61 refused plus one actual source-fence mutation; privacy passes, zero helpers/private inputs. Root executed each reviewed actual reader once after owned groups ended; failed readers/evidence remain preserved.
Other pure tooling: metadata26/141, Query admission230/87 plus20 activation and three source refusals, scoped405/1528; these qualify readers, not v1.
Refine extension admits only the existing exact vos_pvm::refine_host five-u64 source schema and its own full work commitment. Generic runtime domain resolution remains based on explicit typed declarations; it adds no caller/node/root/proximity edge.
Source-valid no-own-work records are fully validated then unselected, including strict supported capture-stage checks. Unknown targets, malformed fields and unsupported/mixed contexts still refuse. All original parser/bindings/private source/tool/build/artifact/process pre/post fences remain.
Final Refine reader09ba277bddea87be22da542e8644e6990c0eac645174aa2486063b2f154937ff and pureb622e202170ae0760f956cf7e8b0181d2d41f55c47c1d5bb9fbbb12a882dd5b7 were independently reviewed before root's one execution of each. Pure36 accepted/185 refused/six source-fence mutations,12 valid unselected cases and absolute-path1 accepted/3 refused; zero helper/private reads.
Earlier immutable Refine versions retain their failures: first synthetic formatter-target gap, then28 no-work context refusals isolated by fixed source-site locator; relative-path v3 invocation failed before helper/input reads. No partial report was admitted, no runtime outcome inferred and no original fence was relaxed to obtain the v4 pass.
SAFE and conversation expose only reviewed finite aliases and scalar phase/status summaries; raw request payloads, error details and credentials are not exported. Private stdout/stderr remain preserved evidence. No new raw-memory collection or guest-symbol export was performed.

**Qualification:** M1 remains OPEN. No public Shared Install/lost-mutation/reopen, returning/all-cold pending Install, leader-loss, cumulative >256/pruning or service gate closes. M2/M3 remain OPEN.
Prior R66/R67 full evidence is frozen at **56bb1a9f:docs/agent-saga-status.md** and its reviewer document; earlier R37–R64 at1bf30df2. R67 Query503 and actual R66 cold custody-confirmation/late-application failures remain independent; current setup failures do not retrospectively explain them.
The creator-admission script correction c880 (admit b/c only, preserving all-three queries/Install/reopen/limits) remains built but unreached/unqualified.
No controlled replacement speedup, quiet inner-cause claim or new tuning authorization follows.

## Ranked fix proposal — separate implementation decision

The first demonstrated R68 blocker is fresh committee observation cost on exact Shared Create root57, after successful retained authorization and guest purity. This is a scoped result; quiet/ordinary failures, R67 Query503 and R66 cold Install remain distinct.
No behavior remedy was implemented or authorized in R68. The subsequent ordered-fix approval authorizes the first remedy and, after its evidence, the second same-object audit candidate; preservation execution and measurement remain required. Larger protocol redesign remains deferred.

1. **Decoded Observe: reuse existing validated-work capability.** R68 source premise at56bb1a9f: the canonical SDK decoder validates the complete immutable InvocationWork, including availability preimage hashes (vos-agent-sdk/src/wire.rs:3992; runtime.rs:95). Observe then reached another full work.validate in standard.rs:3101. General Invoke already distinguished canonical decoded input from fully checked constructed values using private ValidatedInvocationWork in wire.rs:2224.
   Implemented in R69 with the same internal distinction for Observe, removing only this proved duplicate full-work validation on canonical decoded input. Constructed-value APIs remain fully checked; descriptor/installed Authority target, distinct ProgramId digest, Query/anonymity/preflight/clock, signed query/guest authorization, state restore/schema/storage and whole opaque-state purity remain. Projection component outer walls are lower and current committee samples complete without deadline refusal; isolated removable cost and controlled speedup remain unmeasured.
   Required evidence: decoded-versus-constructed real signed Observe differential, malformed/corrupt/truncated/trailing preimages and all authorization/target/clock/purity negatives; existing physical unchanged-opaque and fresh term/prefix/cancellation/corruption-after-progress tests. Any guest change requires independent Authority/Catalog/both-runtime-role reproduction and coherent six-file pins before public acceptance.
2. **Fresh audit: same-object repeated validation only — native preservation and guest reproduction pass; public measurement pending.** Omit only the final validate of the already immutable VerifiedSharedRecoveryObservation at manifest.observe. Canonical decode/constructor validate_binding, fresh physical read/corruption checks, exact index/term/claim/full-input binding, full changed-candidate/member validation, global positions and atomic assignment remain. Earlier decoder reuse needs a separate private proof; neither candidate nor retained-slot validation is presumed redundant. Incoming validation cost is not isolated and full/Ordered folds are not removable. No cross-lock cache/stale manifest/native oracle/skipped fresh audit is authorized.
3. **Attachment view: prove one authenticated committee view in the same read transaction before reuse.** active_route, network_committee_state and local_role reconstruct committee information under one host guard but currently take separate DB snapshots. Reuse requires same-transaction dominance and preserved corrupt-later-read/error ordering. Retain both leader checks around ReadIndex and post-I/O receiver rechecks; one host guard alone proves no snapshot equivalence.
4. **Separate delivery and recovery investigation.** Initial exact authorization input68 times out before later three-node anchors and retained receipt success; classify its confirmation path separately if still blocking after the targeted observation remedy. Likewise preserve R66's actual pending Install owner-confirmation failure, and obtain evidence for ordinary Local Create before attributing its cause. Current AOC5 public Query probes were unreached.

The outer and inner exact-program preparation caches already exist; these measurements do not prove cache misses, eviction or a need for another cache. RuntimeState::validate is four length checks, not a measured heavy validator. The owned opaque-state move pattern used by Invoke is a lower-ranked Observe candidate with unmeasured clone cost.
Do not raise deadlines/limits, restore old read custody, use a native Authority oracle, drop certificate/signature/ProgramId validation or infer publication/release/readiness from Done/anchor/Ready.

## Replacement contract and simplification evidence

Internal Authority credential/inventory/projected Agent/replica/actor, committee/GenesisDecision, member admission and returning/all-cold Install reads now use one receiver-owned observation path.
Use existing authenticated-CFT ReadIndex, not a new quorum design or Byzantine freshness claim.
Bind exact route/generation/committee/configuration/term/correlation, fresh majority contact and barrier R; receiver independently authenticates its committed local System state and apply frontier A >= R.
Older actor publication J < R after no-ops is legal only with authenticated linkage.
Execute installed pinned Authority guest against receiver state; no native Authority oracle, host-private decoding or trusted remote answer.
Bind runtime/artifacts/clock/per-open state; credentials, revocation, visibility and facts use one immutable revision.
Recheck lifecycle/fingerprint after peer I/O. Hold no host/proposal mutex across ReadIndex/peer waits; preserve bounded permits and joinable cancellation.
Require unchanged **whole opaque runtime state**, no actor/root/row/meta mutation, effects, consumed auth, retained result, ACK, continuation, Yield/Await/suspension or durable request/custody.
Loss/restart starts a fresh observation. Exact head/credential changes discard partial pagination; no mixed pages or durable snapshot session.
Public actor Query remains ordinary Invoke/ACK with exact public retention semantics.

Scoped observation uses signed SYSTEM_OBSERVATION_ABI_ID, image-only contract and AWRK tag5. Global ABI, mutation tags0–4, Local image wire/control schema remain unchanged.
Default/old/external/attested/public image contracts cannot select Observe.
O3 removed live legacy producers, read registration/recovery/expiry/custody, transport/apply/checkpoint dependencies and decoded fallback; old experimental generations reject before writes.
Preserve management SharedRecoveryObservation, RMF4/MRQ2, Register/Release, NativeSharedCreateRecovery selected-roster material/lease and original publication authorization successor.

Source audit versus e6f2bb45 removes **13 read-specific production types, nine transport variants, two Raft commands and three live record formats**; read coordination is the barrier request/reply pair.
This simplifies durable protocol/recovery surface. Overall branch growth includes other implementation/integration/tests; combined 8128e677 cannot isolate replacement-only net lines.
A physical component verifies 40 distinct no-ACK observations leave retained state unchanged and caught-up observation uses one fresh audit rather than two.
No matched old/new latency/throughput benchmark exists; no end-to-end speedup or service benefit is claimed.
Cursor reuse is only within one uninterrupted guard; progress requires re-audit. No proof/permit cache across guard/read transaction/peer I/O.

Mandatory replacement acceptance remains **OPEN as an integrated gate**:
- [ ] Fresh leader/follower ReadIndex, exact signatures/revocation/clock/IDs/configuration/apply and no-op linkage; stale/minority/incomplete state and lifecycle/reopen races refuse.
- [ ] Actual image System PVM whole-state purity; hostile mutation/effect/continuation/suspension refusal without an oracle or bypass.
- [ ] No read-specific writes after required catch-up; existing committed replication and election no-ops are legitimate.
- [ ] Lost/cancelled/expired observations, restart and concurrency leave no settlement/stranded routes; queues/cancellation stay bounded.
- [ ] Revision-consistent full pagination and bounded progress under Authority writes; no mixed heads/cache-on-error.
- [ ] Complete physical member/roster/runtime/archive/target negatives and cold Install preserve original parent. GenesisDecision is not application/readiness.
- [ ] Public mutation loss/exact retry/reopen, cold/returning/leader-loss and pruning preserve management evidence; no manual finalization, raised limits/deadlines or zero-selection success.
- [ ] Final removal inventory, old-format prewrite refusal, coherent artifact reproduction and image Local regressions.

## Artifact and startup closure

Earlier replacement 8128e677 and bundle-role 7085c220 precede the decoder correction and cannot qualify later source.
Corrected source 2e19cd17 was independently reproduced for Authority, Catalog, both runtime roles and signed Clerk; role reproduction R38j and coherent pins/builder da86c686/verification39f1f6bb are frozen evidence.
Coherent finalization R38n and startup/prewrite/factory checks passed before both startup bails were deliberately opened.
Readonly preflight must return the **actual inspected snapshot**, validate canonical and staged predecessor-bound signed records, Space/local node/pins/full closure, then compare the complete snapshot under the actual writer lease before reconciliation.
Pins-before-record is permitted only through trusted exact-plan factory with no Shared residue/lifecycle/operation history. Strict client/old-format refusal and normal admission in reopen helpers remain mandatory.
Neither Create Applied, durable archive nor coordinator ACK proves member/serving readiness.

Strict release expects these **six files**, independently materialized/verified at Q71a3ec15. The preceding R38/R68 bundle table is frozen at56bb1a9f:docs/agent-saga-status.md.
| File | SHA-256 |
| --- | --- |
| manifest.json | 8a8c5bcba486e0e3d8939dfa09e48e351aff60183340175883669e95b4c649ae |
| standard-runtime.pvm | 6f1eda0e936f9e9796ecb3ba5c7cee0b073c488ac6117efc332a52e5f5d3c3d8 |
| system-image-runtime.vos | 942a6c782c44923d690da8326218091bcb0809c15c2fdacf7d1c8bfa5be4a733 |
| shared-external-runtime.vos | e0c8b250b64197b2d11a7035282854b63984538a027d375ab1103d857210646a |
| system-authority.vos | 8488d9e124f9b96940d1dba8a0399b984a805646b12b344f98a12fa42fb103ce |
| system-catalog.vos | daceab71bd313ed9e5ea57851f9c4594280f17b599d98c84c7546f61fc91175d |

R69 six-file bundle: target/agent-release-reproduction/run.HpoXXT/release; independent role inputs remain run.J08TTq/first/system-templates. Old run.ykT3eh/release is frozen baseline only.
R69 reproduced Clerk: target/agent-release-reproduction/run.J08TTq/first/clerk/clerk-ledger.vos, SHA dd33d2b3ddbc4d31e5d389ad340d8561bed4afb3ba004fb09d2c1b4da65a595b, identical to the old signed package.
Pins in support/production-artifacts.toml and vosx/build.rs move coherently only after reproduction/verification; candidate/test-signer evidence never promotes them.
Any guest change requires renewed independent reproduction/coherent pins. R69 reproduction/component/all-mode/portable-build gates pass; actual public/recovery acceptance stays OPEN. Any later candidate requires its own checkpoint/artifact/provenance fences.

## Recovery and authorization invariants

- Preserve first verified terminal Invoke and first positive ACK; negative ACK cannot retire custody. Repeated accepted rows are ordinary evidence, not replacement authority; verify exact Ordered evidence, not latest cache.
- Original signed request/work/nonce/caller/preflight/receipt/clock and signed windows remain immutable. Exact retained evidence precedes fresh execution; no re-signing/rebase/private-clock clamp/widening or preview refusal as terminal.
- Management retains bounded complete exact signed members before dispatch; original MRQ2 first-owner binding, whole manifest/positions/capsules/signatures and complete-family restrictions remain. Durable native terminal plus every required positive ACK precede exact signed release.
- Incoming registration/release signatures precede exact-retry decisions. Checked general APIs remain; same-call reuse requires proved dominance. Assignment only on success; refusal leaves retained state unchanged.
- Observation cannot extend/release parents or grant offline mutation authority. Cold Root scope is only exact fresh GenesisDecision/descriptor/roster for the independently leased required physical set; no blanket readiness, remote expansion, archive-only member, Local/Create exception or ninth member. Install caller need not be Root.
- Forward original online owner work with authenticated sender/current System/registration/member approval. Reply is a hint; exact replay, majority availability, issuer finalization and terminal release still required. Discard transfer is not Raft publication.
- Preserve 8-MiB Install reference-package cap and independent aggregate decoder bounds. Do not raise gas/output/package/count/byte limits or deadlines to pass.
- Fresh decision/live complete roster precedes publication; missing serving namespaces cannot be repaired from archives. Reopen exact retained intent/stage under independent leases.
- Restore authenticates complete immutable closure/destination before journal-first publication; exact inode sync/certified reopen before marker retirement/serving. Scratch paths/epochs/copies are not authority.
- Keep permanent freshness ledgers and lock nonces outside replaceable archives. Existing same-identity detached catch-up is not authority to replace lost permanent domains.
- Configured Root operators remain on participating daemons; no key-copy tool/implicit node API grant/replacement authorization. Existing signed enrollment upsert, no roster-CAS framework.
- Preserve authorization, genesis/checkpoint certificates, durable publication, clocks, output/gas/window bounds and image Local public exact semantics. Old spaces are not reset, migrated, silently settled or rebound.

## Remaining prerequisites in dependency order

1. Preserve the S8 native red baseline and completed S9 post-fix evidence. Four signed headroom controls and exact publication retry pass; forwarding original Install and retention controls still block their mandatory component gates.
   Preserve the admitted count-only forwarding boundary and preserve the admitted collector-expiry counts and own-phase timing ranges on the completed retention stream and S10's source-bound receiver denial/refusal counts. Qualify the prepared category-only diagnostic under a new frozen checkpoint/build/reader/fixture before classifying the ManagementError, attributing a caller or proposing a remedy. Identify a demonstrated leaf before a behavior correction. Keep quiet cumulative Install/hook6 failures separate from scoped submission/second-prune QC failures; no alias-order, missing-marker or refused-reader cause inference. Complete the remaining controls under unchanged bounds; no component pass closes M1.
2. At the final corrected coherent source, independently reproduce Authority/Catalog/both runtime roles twice, preserve Local and signed limits, advance truthful A2/Q2 source/artifact/builder pins, verify the exact six-file release, and build current frozen portable main/harness. S4 guest equality and Q1 portable success do not grant later source provenance.
   Run actual ordinary three-process CLI through Shared/reopen, then fresh quiet and eligible scoped packaged workflows on those exact artifacts. Separate ordinary Query, Shared Create/committee, and actual cold/returning Install confirmation; do not infer a remedy from old Q1 or scoped-only results. Isolated savings and sufficiency remain unknown.
3. Qualify automatic cold/returning/mixed pending-generation recovery and image Local callback recovery under unchanged whole30, full public genuine loss/exact retry/locked reopen, leader loss, original-owner/wrong-shadow/absent-origin forwarding, mutation-expiry/denial and observation freshness/cancellation. Prove recovered client Applied/routes/fresh Query separately from guest/GenesisDecision/ACK; qualify cumulative >256 authorizations/pruning and complete retained scopes.
   Preserve historical NRT1 terminal-release ambiguity independently: saved NRT1/actor ACK then1.8s release confirmation timeout and120s issuance exhaustion are not fixed by hot-row/root-fence protection. Full fixed-three NRT1 retry/reopen, Local second-terminal-retry whole30/result/signer checks and typed/fresh-family negatives remain open.
4. Close all M2 public retained corpus/parity/resource/checkpoint/catch-up/reopen/backup gates, rerun M1 exact resulting artifacts, and continue locally possible M3. Leave unavailable hardware qualification explicitly open.
Implementation authority is limited to the separately approved ordered fixes and named demonstrated defects/fixture release gates above. The held Shared-admission diagnostic is not a selected remedy. Stop for new authority/material scope or exhausted local resources; no automatic candidate, cap renewal, unrelated tuning, deadline change or wider redesign.

## Mandatory workflow and operations checklist

- [ ] Fixed-roster common authenticated genesis and supported Shared finality; schema-aware resumable public CLI, signed terminal failure/denial and usable first-use readiness.
- [ ] Cold/restarting/returning/mixed generations, offline original owner, leader loss before commit, after-ACK/metadata-clear cuts, observer loss, exact retries and automatic bounded recovery.
- [ ] Common-state certified checkpoint/catch-up before replay exhaustion; separate signed physical store binding; complete pending scopes survive pruning.
- [ ] External blocks available before quorum ACK; missing blocks/minority never succeed; catch-up and genuinely lost responses qualified.
- [ ] Root-pinned immutable closure/export and bounded detached reclamation protecting authoritative/pending/checkpoint/retry/backup roots.
- [ ] Coherent signed package contracts; image Local unchanged; bundled default packages/authenticated HTTP/SSH and system actors installed before Space readiness. Arbitrary user Agents remain explicit.
- [x] Offline signed corpus/reference generator: 1,000 accounts, 100,000 retained transfers/external IDs, 101,000 verified signatures; full 32.33s, independent digests. Peak memory unmeasured; offline timestamp/order roots are not public parity, and no credentials are generated.
- [ ] Public corpus uses actual accepted contexts/order and verifies all six maps on every owner. Current loader's stable-follower fresh Ordered Query cannot succeed through ordinary HTTP; exact retained delivery to serving leader plus independent all-owner application/freshness is needed. Cached ASR1/repeated leader answers are insufficient.
- [ ] Signed storage/streaming bounds and resources: >502,000 logical actor rows before other indexes, >1m outer Patricia structural blocks before chunks are lower bounds, not measured ceilings. 65,536 portable IMAGE/System archive cap is not external checkpoint capacity; do not raise it globally.
- [ ] Integrate existing bounded AXJ1 export/ACX1 restore under actual production ownership. Public backup is registry-only and rejects live Agent roots; test-only export/internal restore do not qualify maintenance-window Agent backup.
- [ ] Drain admission; authenticate certified System/detached Shared/opaque image Local/lifecycle/client retry backup, separate keys and replaced destinations; preserve permanent freshness/locks. Qualify restore/recovery and exact retries.
- [ ] Existing ATQ1/AOC5/AOQ1/ASQ1 bounded API load tooling, signed Operator/Member roles, exact preparation/outer-inner VM/persistence/queue/quorum measurements; no retired acceptance API or multiplied Root credentials/queues.
- [ ] Exact release overload/partitions/minority/crashes/catch-up/restart/interrupted lifecycle/restore, failover <=30s and unchanged service/load/soak targets.
- [ ] Hardware collector scripts/collect-agent-release-node.sh is read-only preparation (syntax/refusals/numeric-address checks passed), not deployment or qualification.
- [ ] Interpreter/recompiler differential, full outer-PVM, supported feature/CLI tests, targeted formatting/lint, artifact reproducibility and final independent review with no release blockers. Merge/cutover requires separate authorized action.

## Architecture context and deferred work

Fresh signed-ledger physical validation, settled absence, runtime/replay/common-baseline provenance, complete-family checks and final worker barriers are distinct proof obligations.
Raw Raft can progress outside host/proposal/ledger guards; two transactions under a host guard are not one snapshot. No as-is audit consolidation, freshness suppression or cross-lock permit cache is justified.
ACK already uses one capacity_and_recovery_manifest plus independent provenance; historical two full absence audits belonged to a different final Invoke. Do not optimize the wrong branch.
Whole opaque runtime/control-directory reconstruction, preview/application/follower work, outer VM/queues/persistence and reopen/GC scans remain potential cost centers; incremental actor rows alone do not guarantee touched-data cost.
Measure actual management-only RMF4 and corpus resource costs; removed combined-format 14.8-MiB ceiling and declared fixture million-row/1-GiB limits are not production capacity.
Inner immutable program cache is bounded to one exact <=2-MiB program per worker; larger/unresolved programs bypass cache, not artifact admission. Invocation memory is never reused.
Silent-voter permits/registration ambiguity need sustained minority/exact retry qualification; observation timeout leaves no durable read obligation.
External Shared supports Direct Linear/LinearizableQuery plus ACK; Control Query/Resume/yield/timers/Attested are not supported on this slice.
Deferred: Private/Attested production, dynamic membership, bridge/settlement, migration, external Local, sharding/online GC, broad runtime unification, ARM64/thousands clients and unrelated no-network feature repair. Existing prover/validation remains.
Broader simplifications can be revisited after lower-level causes; no architectural change is selected by this context.

## Effort, variance and go/no-go discipline

| Work type | Remaining forecast and confidence | Evidence / unknowns |
| --- | --- | --- |
| Implementation | Both ordered remedies have S4 native/coherent guest preservation. S9 exact-pair correction closes its signed native count defect; publication retry passes, forwarding/retention blockers remain. No defensible aggregate source-hour forecast; low confidence in total remaining effort. | Scoped forwarding locates submission/local-timeout boundaries; scoped retention fails the composite certified-checkpoint wait while quiet retention fails scheduled hook6. S10 prepared-denial records locate unchanged-state ManagementErr before its new proposal path; exact error/caller and measured benefit remain unknown; selected category-only diagnostic is applied, awaiting its new frozen build/reader/fixture evidence. Matching-response/collector-expiry leaves and current Query/recovery sufficiency remain unknown; source proves scoped second-prune progression past hook6 but no quiet cause. Fresh proofs, per-holder reserves and custody checks are not licensed for removal. |
| Integration | Recorded portable cycles **7.83–21.36min**, coherent reproduction **8.34–9.14min**, all-mode **4.90min** imply roughly **21–35min** for those build stages before workflow runs. High confidence in recorded costs; low confidence in remaining cycle count/aggregate effort. No future bound or ETA. | S9 core54.458s/native0.504s/publication77.486s pass; quiet forwarding136.746s/retention360.590s and scoped forwarding142.251s/retention431.963s fail independently. S10 core67.470s passes/scoped forwarding130.245s fails; diagnostic evidence gives no controlled benefit. Latest Q1 ordinary/quiet/scoped92.701/223.646/246.870s fail. Final-source reproduction/portable/public cycles remain pending; variance is uncontrolled and no isolated performance benefit follows. |
| Qualification | M1/M2/local M3 aggregate effort remains unknown; hardware M3 has a known external dependency. The prescribed30-minute load and24-hour soak are fixed execution requirements, not a delivery estimate. | M1 Shared/reopen/loss/returning/all-cold/leader-loss/negatives/pruning remains; M2 public data/parity/resources/Agent backup and M3 workload/faults remain. Hardware availability is unknown; local tooling cannot close external gates. |

Original O1 6–12/O2 8–16/O3 8–16 = **22–44 source hours plus qualification** is historical, not remaining effort or calendar delivery.
Retain the focused **one engineering-week go/no-go cap**; explain variance before expanding scope, never quietly roll it forward.
Both original measured service-tuning passes were consumed and failed. Later R48 (explicit third), R52/R54 and R57 coordination were separately authorized; none closes M1 or renews the cap.
R58–R68 diagnostics do not automatically authorize another behavior candidate. Another tuning change/material architecture decision requires explicit direction.
Historical conditional effort bands stay in the immutable record, not a new current forecast. No completion percentage, deployment date or readiness claim.

## Working and evidence rules

Each change must close a named mandatory release gate or demonstrated blocker; reuse existing mechanisms. Passing tests/checkpoints is not completion.
Use host nightly-2025-05-09 and guest nightly-2026-03-20, offline/locked builds generally -j2; core features experimental-state-blocks,http-ingress,agent-runtime.
Portable RELEASE explicitly RUSTFLAGS empty and encoded/target flags unset; use current frozen binary provenance, never a mutable Cargo path.
Target and TMPDIR/JUST_TEMPDIR are disk-backed /home/daniel/src/virto/vos/.worktrees/ch08-c2-native/target and its task-tmp; no RAM-backed /tmp.
Sequence deadline-sensitive physical tests separately from builds/other fixtures. Exact selectors, ignored qualification explicitly selected, normal startup admission; no cfg(test) bypass, zero-selection or sandbox refusal as pass.
Scoped logging can perturb timing; quiet runs remain independent. No quiet inner-cause inference from a different scoped run.
Use admitted finite SAFE aliases/scalars only in summaries; keep credentials, bodies/private diagnostics out of output. Aliases/threads/local ordinals are not unique attempts/calls/holders.
No adjacency/proximity joins, cross-domain index joins, sums/subtractions of nested or independently started clocks, or missing-marker=nonexecution claims.
Preserve user-owned dirty work/evidence. Apply narrow patches, avoid whole-file style churn. Remove temporary tracked scaffolding when no longer needed; retain useful regressions/evidence references.
Frozen older evidence:7b7f7a13:docs retains preceding R70 S7/S8 fixtures/native baseline/correction history;dd2de303:docs retains detailed S4–S6 history;56bb1a9f:docs retains R66/R67,1bf30df2:docs retains R37–R64; e6f2bb45/6d3a4926/62ffbc20 and target release-integration-docs-pre-consolidation-r31.txt remain immutable references.
