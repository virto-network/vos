# Agent saga: single live v1 plan

This is the single live plan. [agent-saga-review.md](agent-saga-review.md) is the sole reviewer entry point.
Detailed preceding evidence is frozen at **1bf30df26128eb59d4bb4e5837660b38d360fe35:docs/agent-saga-status.md** and the corresponding reviewer document.
Use that immutable Git object for R37–R64 histories, exact old selectors/logs/hashes and earlier failed experiments; they are evidence, not another live plan.
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
Latest admitted build/ordinary source is clean **1ce4ea7cbcb648c2af94de1c27f5c177208ee44b** (R67), branch wip/ch08-runtime-directory; script c880 and the compact documents are frozen there.
Latest cold-recovery evidence remains R66 at 1bf30df26128eb59d4bb4e5837660b38d360fe35; the script/docs-only delta leaves host binaries and six-file bundle/Clerk unchanged.
Repository/worktree: /home/daniel/src/virto/vos/.worktrees/ch08-runtime-directory.
Master remains d2378274c0503d9737edce9bcb189d24c3d4e247; reviewer saga/agents remains e6f2bb4551274064e3d080c64763e95faa8c5ebb.
The next checkpoint will not retrospectively become either measured source. The requested R67 recap is complete; current R68 diagnostic changes await review and a new frozen source/build boundary.

| Area | Implementation | Integration / qualification |
| --- | --- | --- |
| Internal Authority reads | O1/O2 observation cutover and O3 legacy lifecycle removal exist; management retention and public Invoke/ACK remain. | Frozen purity/authentication/no-write/freshness components exist; all replacement acceptance below still require integrated released-artifact evidence. |
| Runtime/artifact/startup | Corrected decoder, separate signed System-image/Shared-external roles, coherent pins, strict six-file verification and normal fixed-three startup exist; Local canonical image is unchanged. | Coherent reproduction/prewrite/factory/finalization components passed before deliberately opening startup; no M1 claim follows. |
| Publication/recovery | Exact ambiguous publication re-admits original leased stores; pending protection survives finalization/retirement; fresh exact GenesisDecision precedes terminal cleanup. First-owner/full-family restrictions remain. | Historical same-source cold outcomes vary: some accept finalization/ACK/terminal/release late; others refuse startup or availability. Whole30, recovered client Applied/routes/fresh Query remain open. |
| Signed release | R57 derives scalar capacity from one fresh signed-release preflight under its existing guard/read transaction; final worker snapshot/barrier and prefix-checked proposal remain. | Nineteen signed preservation/component tests prove counter deltas and raw-worker/prefix restrictions. Packaged vosx links non-cfg(test) vos: those counters are not packaged execution proof. |
| Current ordinary CLI | Existing public CLI/HTTP and owned three-process script are used. | R67 completes Local Create/Install then fails Query authorization preparation HTTP503 before actor Invoke; Shared Create/Install and corrected handoff/reopen are unreached. R66's Query success did not repeat. |
| Current cold recovery | R66 diagnostics add source-bound local preparation/capacity and guard/error context; unchanged recovery/deadline rules. | Latest cold evidence: quiet/scoped R66 fail Shared-before-routes, scoped owner constructor Err. R66 admit-a HTTP503 remains independent; no R67 cold rerun. |
| Data/service/operations | Signed offline corpus, bounded public-loader preparation and read-only hardware collector exist. | Public full data, all-owner parity, resources, backup/restore, service, fault/soak/hardware and final review remain open. |

## Approved R68 diagnostic session

User approved **diagnosis and a fix proposal only**, with a four-hour wall-clock cap: start 2026-10-06 19:40:09 UTC, deadline 23:40:09 UTC, including review/builds/runs/evidence/cleanup. This does not renew the engineering-week cap or authorize a behavior remedy.
One reviewed host-only closed admission/error/timing bundle and finite reader extension; preserve original calls, masks, guards, callback/assignment order and checkpoint fallback. Bind the already-decoded original AOC5, not unique attempts; keep physical error categories payload-free and source-context restricted.
Existing core preservation tests may compile their debug harness before **one portable CLI main/harness build cycle**; core evidence is not portable CLI provenance. Then sequential ordinary CLI, fresh quiet all-cold, and scoped all-cold only after admitted quiet failure. At most one same-artifact replay for a named non-reproduction/unreached branch, with ordinary priority; no automatic second portable build. Preserve all original evidence fences, environments, deadlines and owned cleanup.
Deliver separate causal timelines/direct durations with unknown intervals, focused proof/recovery/readiness review and ranked fix proposals. CPU flamegraphs, guest symbol export, held Shared-admission probe, new frameworks and runtime behavior changes are outside this session. Report at one hour and at completion/cap; M1/M2/M3 remain open.

## R66 diagnostics and current R67 evidence

**Implementation:** source-preserving diagnostics only; no behavior remedy, new authority, tuning authorization or cap/deadline extension.
Original reviewed proposals in disk-backed task-tmp:
- r64-host-guard-boundary-diagnostic-proposal-v2.patch — c633ac4091e24e0a6add84847459fda8a450afc3ce3249980cae3a01ca2d9434.
- r64-local-management-context-diagnostic-proposal.patch — f3ba54c177d406b75a72556b02ed77537ad21762319fb168db5802966b35f4aa.
- r64-native-operation-preparation-error-diagnostic-proposal.patch — 7f7184c1317f02fdd28566520d24d59724b8346f663bad58af83c390c081ca41.

Local capacity/manifest/singleton-budget/preparation gains exact caller context around existing calls.
Release wait/acquired/release-pending/released and applier guard phases use existing identities. Same-Arc/same-open source proof is required; markers do not identify every holder or create a global pairing token.
Guard-held intervals are distinct from total mutex wait; missing release markers after a successful early Present return are inconclusive.
Native error-only WARN phases are controller_validation, fresh_capture, retained_lookup, retained_capture, physical_material and fresh_admission.
Controller categories are wrong_authority/completion/issuer_open/coordinator_open/coordinate; original masking/error/drop/check order remains.
Network diagnostics are std/env gated; native error WARNs are ungated and error-only, preserving the ordinary script environment.
No new hash, read, clone, lock, product API, physical audit, deadline or limit; no request/error payload is emitted.

Frozen 1dab33473f82f412ab3c27edcfa4cb045292029e main build failed **15.616s/exit101**, E0308 at shared_agent.rs:1745:49: SDK Hash versus service Hash in diagnostic metadata.
No harness, verification or runtime evidence followed that failure.
Reviewed correction r66-host-guard-metadata-type-correction.patch, SHA 821bad6596dd73b217a89491e8f01a90c4a346052afa6dfc1dcee9a7875c3db5, changes only the optional metadata type to crate::service::Hash.
Correction was measured at 1bf30df2; R67's script/docs-only source is 1ce4ea7c. Failed evidence remains preserved.

| Current source file | SHA-256 |
| --- | --- |
| vos/src/network/shared_agent.rs | 59ca888e50adddadcbaf962f366d59dbd6bbefd0982d54ea5809bbbe693a13f5 |
| vos/src/agent/clean_operation_controller.rs | 8996cfb830d05214eb86a85b26005f4ab3dad8fd19f8277a148acee10a3273f5 |
| vos/src/agent/clean_operation_dispatch.rs | c414afb53ea44f198e4f2556af7c780040abb31dadc41195bb686f5e471fc458 |

**Integration:** R67 original portable owner/fences independently admit clean before/after/current 1ce4ea7c, exact toolchain/commands/features/environment, unchanged six-file bundle plus Clerk, owned exhausted noninterrupted groups and frozen binaries.
Main **205.313s**, harness **264.286s**, strict verification **0.101s**; combined build cost **469.700s/7.83min**, not application performance or remaining ETA. R66's earlier 897.061s is uncontrolled build variation.
Build directory: task-tmp/r67-cli-build-1ce4ea7c.
Provenance SHA f092dee83a03b7401dc339bb186d9b0b4569a82b3742103a9a4808852eb474a2.
Frozen main SHA 2ee75c2e815cb2a37ba8e271ff03de2200e43834b171f338187ee56e985252a9.
Frozen harness SHA ef58d3f94f58391df3f1e86dcbe340fd6d38b34b2515b0297535acd27d416a74.
R67 verification-result SHA 23884dc294365d625246d1e33f48f49f5b33ebfc86e1d4af2b5ac0c178f18718; main/harness hashes are identical to R66 (unchanged host code), not new service evidence.
Mutable Cargo target binaries are not the original admission boundary.

| Isolated run (source stated) | Admitted outcome | Exact limits |
| --- | --- | --- |
| **Latest ordinary R67**, task-tmp/r67-current-actual-cli-1ce4ea7c | **FAIL 99.208s/script1**, exhausted/noninterrupted. Ready10.063s; Local Create22.141s/one attempt and Install52.295s/five attempts complete (four exit1, fifth0); Query8.948s/exit1. | No Query value assertion; Shared Create/Install attempts0, handoff/reopen unreached. Cleanup3.009s/exit0, three launches/zero owned survivors passes. No controlled speedup or repeatable Query success. |
| Ordinary three-process CLI, task-tmp/r66-current-actual-cli-1bf30df2 | **FAIL 192.208s/script1**, exhausted/noninterrupted. Ready 9.530s; Local Create 14.145s/one attempt, Install 30.242s/one attempt and Query 47.686s/exit0 complete; Query value assertion verified by reaching Shared stage. Shared Create 81.369s/one attempt completes; admit-a 2.382s/exit1. | Shared Install attempts 0; admit-b/c, Shared queries and reopen unreached. Graceful stop 4.141s/exit0, three recorded launches and zero owned survivors: cleanup passed. No controlled speedup or retrospective cause for earlier Query failures. |
| Quiet all-cold, task-tmp/r66-pending-all-cold-quiet-1bf30df2 | **FAIL 246.768s/exit101**, one failed test, exhausted/noninterrupted. Shared-before-routes Unavailable count1; fixed public clean_startup_tests.rs:2013:29 count1; unknown0. | Constructor refusal, not whole30 assertion277. Bound/affirmative maps empty; no inner-cause, exact-family or scoped-cost attribution. |
| Scoped all-cold, task-tmp/r66-pending-all-cold-scoped-1bf30df2 | **FAIL 260.885s/exit101**, one failed test, exhausted/noninterrupted; strict reader admits 18,236 records/528 explicit edges/216 identity aliases/43 thread aliases/291 phase groups/zero unknowns. Shared-before-routes Unavailable1. | Owner constructor Err54.475594s; peers Ok24.764687s/24.656347s. Root-bound finalization/refusal limits below; no scoped exact public panic-row or whole30 assertion277 claim. |
| Ordinary admit-a finite error classification | Shared-member-admission **HTTP503**, no exported response body/detail; all native/preparation warning counts0/unmapped0. | Not the source-predicted Conflict409. Readiness/queue/controller/inner stage unknown; zero warnings do not prove those branches were absent. |

R67 metadata SAFE SHA 587fb1aa5e90b9dec32d8dce8136d1d8e3127651738db469aa7d7fdb7974b281; native-error SAFE b7b8e662aab24d4e674caf81fcf8eff52fd2ddfb8c9114c8791ebbada28f01d1.
R67 Query authorization preparation returns HTTP503/exact retained AOC5 suffix before actor Invoke. Daemon a records fresh_admission/unavailable then outer fresh_capture/unavailable on one file-local invocation alias; source permits propagation, not two independent causes/unique attempts or an explicit HTTP Query/System-root join. Deeper leaf remains unknown; old flat Unavailable1 and b/c zero records supply no such binding.
R67 metadata pure26 accepted/141 refused, result a1342c046b5bec068eaeabee617b98e5ce524936a04c9207720e860dc14ec1fa; native grammar pure109/15 plus20 activation refusals, unchanged grammar/fences, are tooling only.
Frozen R66 ordinary metadata SAFE SHA 8f5e844fda8ff831f0a75c2c847aff87628f927b52e70311e0f7b133098b4dc4.
Quiet SAFE SHA 9842c5ef98fa5caba68e927a4fdd71ab84f71ef4398e5432ddf36784fb99dc75.
Scoped local-guard-safe.json SHA d52521c265d0125a003551e98d8aa0b3ba82e84e547dbfc585f3086f0bfe01dd; basic safe-summary.json SHA 76409cd6077ae54920e13d98da069f4a7bff247218987647b3f6bf69b590fe62.
Ordinary ordinary-admit-errors-safe-v2.json SHA c3a3db572717a2ea48b76e7ca1d2a33182d6e9648ece69ba59ed6ac0cc395246.
Original quiet adapter changes only the pinned full HEAD; grammar/fences remain unchanged.
Any backtrace unsetting is an invocation fact, not a field certified by the finite environment metadata.

Scoped pure synthetic result r66a-local-guard-synthetic-result.json:
**364 accepted/1457 refused**, SHA 2c521cb8eec2c8277d12e3c1b9f8e25a8447441eb67ea1b09267312975431801; privacy/source/alias checks pass, zero helpers/private inputs.
Metadata draft pure 25/136 and native-error draft pure 109/15 are tooling evidence only.
The Query-failure reader was ineligible for successful R66 Query; it is eligible for current R67 failure with unchanged grammar/fences. R67 reader f7408399659ae130aa465ed1a4ac89ca28045076d820abb55567950d5978058b.

Scoped exact Install lineage is root181/original invocation180/work182/authorization183, owner node2/System4; final child208/work209/original authorization210. Prospective authorizations remain distinct.
Earlier Create root30 terminal restore/release is a different family; it supplies no Install181 completion proof.
Owner exact final key208/209/210 records forward-sent e17937 at cumulative1.048941s, then local-custody-timeout e18076 at cumulative2.859256s on its source clock.
Owner invoke_error e18078, helper Unavailable35.167235s/e18080 and constructor Err54.475594s/e18100 follow. Five source-local returned ordinals are not globally unique attempts or additive clocks.
Leader final-key audit bodies e18034/e18117/e18158 cost1.044866s/1.061743s/0.816599s in capacity_manifest/custody_budget/singleton_budget; each has46 rows/5 registered/1 released/11 Ordered. Nested folds, enclosing budgets and preview are not added and do not establish removable validation.
Final input216 is prepared e18174, locally appended at index47/e18177, anchored on leader node1/e18195, polled present/Ready e18196–97, then wait completes/e18199 and availability refuses/e18218.
These later records follow owner System ingress removal/e18091 and constructor Err; that later refusal cannot establish the earlier owner's failure cause. Buffered Ready is not ACK/availability/client delivery.
No root-bound accepted Install issuer-save, terminal-persistence or retention-release proof is recorded; missing markers are inconclusive about unlogged execution.
Original-work submission records report success=false3.425217s and later true11.455ms, durable observation48.042ms/issuer observation3.933ms; they do not bind final-child interiors or prove Applied.
No new local_capacity/local_manifest/local_singleton_budget/local_preparation context appears in the SAFE. Recorded noncustody exact keys declare forwarding; source follower return precedes local spans, so no local leaf cost is assigned.
Guard markers record182 acquired/180 pending+released phases (applier173 each; release_poll9 acquired/7 explicit drops); successful implicit drops remain blind. No post-cold release_poll record or holder proof follows.
Post-cold metadata_host_wait max2.672861s is register211/node1/poll2, not release. Exact shared keys alone do not pair guard holders/calls or attribute that wait.

**Qualification:** M1 remains open. Latest ordinary fails before Shared; corrected handoff is unexercised. Latest cold R66 still fails bounded readiness; M2/M3 remain open.
The new outcomes do not retrospectively explain earlier frozen refusals, prove a general guest/stack verdict, or authorize another behavior candidate.

### Current admission-tooling source defect — applied

The measured R66 script created Shared on a, then attempted admission on a/b/c. Native Create retains the creator's canonical issuer entry.
Native member locator validation requires disjoint issuer/member agents; admitting that same creator again is a source-predicted Conflict. The existing packaged handoff fixture admits only indices 1..3.
R66 admitted HTTP503 is different from that Conflict409; the source defect is not a demonstrated cause of that run or a proven HTTP503 remedy.
Reviewed r66-origin-member-handoff-script-correction-proposal.patch, SHA f1eacdf646a288913d2cc2ebe645e78d5769fdc9f8c1861f51b3089eeb5a5c99, changes only index=1 and personas b/c.
It preserves their original endpoints, exact archive/Root/authorization checks, all-three queries, later Shared Install, reopen, cleanup and every limit/deadline.
Applied current script SHA c880a1f5dde65ecca874da1fee31ec7a97d419da2cfefe16d45697a6289cfc8c; measured original SHA 6930e0aef12c89e6fc4e8bb18a6b7743627bdbdf70a98d342f47fa8cc6205b28.
Independent source review, bash syntax and dry-run patch checks pass; root applied the exact +4/-2 tooling correction only after all original 1bf30df2 admission fences closed.
**Applied/frozen at 1ce4ea7c; corrected Shared handoff unexercised/unqualified.** R67 built and ran the script but failed Local Query before Shared. No product behavior/invariant/limit change or promotion.

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

Strict release expects these **six files**, unchanged through current evidence:
| File | SHA-256 |
| --- | --- |
| manifest.json | ee9fa1b2452a4982e56974149b3b8b5f2961306d259403a8afc479ebd8a5c24f |
| standard-runtime.pvm | 6f1eda0e936f9e9796ecb3ba5c7cee0b073c488ac6117efc332a52e5f5d3c3d8 |
| system-image-runtime.vos | a0ccfbc58e667cda331cac2c5e8b7a7972db19e883e4bf2dfdb171b0815d5159 |
| shared-external-runtime.vos | c86c8d1541879d3305faa1af69f1a04944381a2cb5d5b99fbca590ef1fa1bdae |
| system-authority.vos | 3b08beca2462a45e9001a93206db055741861a0b51ebc70eb4db077d1e689afd |
| system-catalog.vos | daceab71bd313ed9e5ea57851f9c4594280f17b599d98c84c7546f61fc91175d |

Bundle: target/agent-release-reproduction/run.ykT3eh/release under the native worktree.
Clerk: target/agent-release-reproduction/run.1JsTwa/first/clerk/clerk-ledger.vos, SHA dd33d2b3ddbc4d31e5d389ad340d8561bed4afb3ba004fb09d2c1b4da65a595b.
Pins in support/production-artifacts.toml and vosx/build.rs move coherently only after reproduction/verification; candidate/test-signer evidence never promotes them.
Any guest change requires renewed independent reproduction/coherent pins. Current std-only diagnostics do not change guest bytes.

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

1. Execute the approved bounded R68 diagnostic session above: recorded fresh_admission/current Query failure and cold original-owner custody confirmation. No deeper leaf or behavior remedy is established. Creator-handoff correction is frozen/built but unreached; R66 admit-a503 remains independent.
   Distinguish original-owner local custody, guest completion, durable application, full ACK availability, terminal persistence, release and public readiness. Existing diagnostic markers are not attempt IDs.
   Resolve demonstrated System-open/local Persisted budget, retained submission/registration-confirmation interiors and post-proposal/availability gaps with bounded evidence; earlier release-holder questions remain separate. No local leaf timing or removable fresh work follows from this scoped run.
2. Qualify automatic cold/returning/mixed pending-generation recovery and image Local callback recovery under unchanged whole30, then full public exact loss/retry/locked reopen.
   Preserve historical NRT1 terminal-release ambiguity independently: saved NRT1/actor ACK then 1.8s release confirmation timeout and 120s issuance exhaustion are not fixed by hot-row/root-fence protection.
   Full supported fixed-three NRT1 retry/reopen, Local second-terminal-retry whole30/result/signer checks and typed/fresh-family negatives remain open.
3. Run current packaged public workflow, returning/all-cold Install, leader loss, original-owner/wrong-shadow/absent-origin forwarding, mutation-expiry/denial and observation freshness/cancellation.
   Prove recovered client Applied/routes/fresh Query separately from guest/GenesisDecision/ACK; qualify cumulative >256 authorizations/pruning and complete retained scopes.
   Run actual three-process script through Shared/reopen; genuine mutation-response loss remains a separate fixture requirement.
4. Close all M2 public retained corpus/parity/resource/checkpoint/catch-up/reopen/backup gates, rerun M1 exact resulting artifacts, and continue locally possible M3. Leave unavailable hardware qualification explicitly open.
The prepared Shared-admission error diagnostic remains target-only/unapplied/conditional; it is not a selected runtime remedy. No behavior remedy or broader redesign is selected. Stop for direction for new authority/material scope or after exhausted local resources; no automatic cap renewal or extra tuning pass.

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
| Implementation | No defensible aggregate remaining source-hour range; low confidence until demonstrated leaf causes/remedy scope are established. | O1/O2/O3, corrected decoder/roles/startup/recovery and approved validation/release changes exist. R66 diagnostics and R67 tooling compile; corrected handoff remains unreached. Current fresh_admission's deeper leaf/HTTP association, historical admission503, cold custody confirmation/leader availability and local/guard interiors remain. |
| Integration | Exact current attempt costs have high confidence; number of remaining correction/reproduction/acceptance cycles is unknown, so no aggregate range or ETA. | Current R67 build7.83min/ordinary failure1.65min; latest cold R66 quiet/scoped4.11/4.35min. Earlier build14.95min is uncontrolled variation. Older uncontrolled build/run variation is not application regression or speedup. Guest changes need coherent reproduction. |
| Qualification | M1/M2/local M3 aggregate effort is unbounded by admitted evidence; hardware M3 has a known external dependency. | M1 Shared/reopen/loss/recovery/negatives/pruning remains; M2 public data/parity/resources/Agent backup and M3 prescribed workload/soak/faults remain. Local tooling cannot close external gates. |

Original O1 6–12/O2 8–16/O3 8–16 = **22–44 source hours plus qualification** is historical, not remaining effort or calendar delivery.
Retain the focused **one engineering-week go/no-go cap**; explain variance before expanding scope, never quietly roll it forward.
Both original measured service-tuning passes were consumed and failed. Later R48 (explicit third), R52/R54 and R57 coordination were separately authorized; none closes M1 or renews the cap.
R58–R66 diagnostics do not automatically authorize another behavior candidate. Another tuning change/material architecture decision requires explicit direction.
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
Frozen older evidence: 1bf30df2:docs includes complete R histories; e6f2bb45/6d3a4926/62ffbc20 and target release-integration-docs-pre-consolidation-r31.txt remain immutable references.
