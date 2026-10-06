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
Latest admitted build and four-workflow source is clean **56bb1a9f849165f4581ba2f4df5d247180acdceb** (R68), branch wip/ch08-runtime-directory. Only host diagnostics changed; signed guest/runtime bundle and Clerk pins are unchanged.
R68 quiet/scoped fixtures failed initial Shared Create setup before the cold cut. Latest evidence that actually reached pending Install cold recovery remains R66 at 1bf30df26128eb59d4bb4e5837660b38d360fe35.
Repository/worktree: /home/daniel/src/virto/vos/.worktrees/ch08-runtime-directory.
Master remains d2378274c0503d9737edce9bcb189d24c3d4e247; reviewer saga/agents remains e6f2bb4551274064e3d080c64763e95faa8c5ebb.
This closeout document edit follows completed original admission fences and does not become the measured binary source. R68 diagnosis and ranked fix proposal are complete; no runtime remedy or further tuning pass is authorized by that diagnostic session.

## Approved ordered fixes after R68

The user subsequently approved proceeding in order: implement decoded Observe validation reuse first, preserve the fully checked constructed entry, test it and measure its effect before deciding whether verified-observation reuse in the fresh audit is needed.
This authorizes the named first remedy and necessary source review, preservation/differential tests, independent coherent artifact reproduction and exact-artifact integration/measurement. It does not restart design, renew the engineering-week cap, raise limits/deadlines or authorize unrelated tuning. The second narrow proposal remains conditional on first-fix evidence; transaction redesign and broader architecture remain deferred.
Current implementation work begins from56bb1a9f with the two R68 closeout document edits preserved. R68 source/artifacts/SAFE remain immutable baseline evidence; candidate/component results will remain distinct from coherent released-bundle qualification. M1/M2/M3 remain open.
The first source patch and real signed Observe regression have passed independent source review. Only the decoded Observe arm can mint the existing borrowed work-validation proof; constructed Observe retains its checked entry, and only the later duplicate full-work predicate is omitted. All other predicate/restore/execution/purity ordering is preserved. The test-only accessor returns owned fixture state/slot after live-lease validation and grants no admission proof. Native execution, guest builds, coherent reproduction and measured benefit remain pending.

| Area | Implementation | Integration / qualification |
| --- | --- | --- |
| Internal Authority reads | O1/O2 observation cutover and O3 legacy lifecycle removal exist; management retention and public Invoke/ACK remain. | Frozen purity/authentication/no-write/freshness components exist; all replacement acceptance below still require integrated released-artifact evidence. |
| Runtime/artifact/startup | Corrected decoder, separate signed System-image/Shared-external roles, coherent pins, strict six-file verification and normal fixed-three startup exist; Local canonical image is unchanged. | Coherent reproduction/prewrite/factory/finalization components passed before deliberately opening startup; no M1 claim follows. |
| Publication/recovery | Exact ambiguous publication re-admits original leased stores; pending protection survives finalization/retirement; fresh exact GenesisDecision precedes terminal cleanup. First-owner/full-family restrictions remain. | Historical same-source cold outcomes vary: some accept finalization/ACK/terminal/release late; others refuse startup or availability. Whole30, recovered client Applied/routes/fresh Query remain open. |
| Signed release | R57 derives scalar capacity from one fresh signed-release preflight under its existing guard/read transaction; final worker snapshot/barrier and prefix-checked proposal remain. | Nineteen signed preservation/component tests prove counter deltas and raw-worker/prefix restrictions. Packaged vosx links non-cfg(test) vos: those counters are not packaged execution proof. |
| Current ordinary CLI | Existing public CLI/HTTP and owned three-process script are used. | Both R68 ordinary runs stop during Local Create; Install/Query/Shared and corrected handoff/reopen are unreached. R67 Query503 remains an independent deeper-leaf question. |
| Current cold recovery | R68 adds source-bound admission phases and closed refusal categories; unchanged recovery/deadline rules. | R68 quiet/scoped fail earlier Shared Create setup; scoped committee guest completes purely but observations exceed1.8s. Actual R66 cold owner-confirmation failure remains unqualified. |
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
No behavior remedy was implemented or authorized in R68. The subsequent ordered-fix approval above now authorizes the first proposal's implementation and measurement; these proposals reuse existing mechanisms and larger protocol redesign remains deferred.

1. **Decoded Observe: reuse existing validated-work capability.** The canonical SDK decoder validates the complete immutable InvocationWork, including availability preimage hashes (vos-agent-sdk/src/wire.rs:3992; runtime.rs:95). Observe then reaches another full work.validate in standard.rs:3101. General Invoke already distinguishes canonical decoded input from fully checked constructed values using private ValidatedInvocationWork in wire.rs:2224.
   Propose the same internal distinction for Observe, removing only this proved duplicate full-work validation on canonical decoded input. Keep constructed-value APIs fully checked; preserve descriptor/installed Authority target, distinct ProgramId digest, Query/anonymity/preflight/clock, signed query/guest authorization, state restore/schema/storage and whole opaque-state purity. No isolated removable cost or deadline success has been measured.
   Required evidence: decoded-versus-constructed real signed Observe differential, malformed/corrupt/truncated/trailing preimages and all authorization/target/clock/purity negatives; existing physical unchanged-opaque and fresh term/prefix/cancellation/corruption-after-progress tests. Any guest change requires independent Authority/Catalog/both-runtime-role reproduction and coherent six-file pins before public acceptance.
2. **Fresh audit: same-object repeated validation only.** Canonical SharedRecoveryObservation decode, validate_binding and SharedRecoveryManifest::observe repeat validation of unchanged observation material. The narrow candidate reuses the existing immutable VerifiedSharedRecoveryObservation at manifest.observe, retaining canonical decode and constructor validate_binding, canonical physical read, exact index/term/claim/full-input binding, fresh corruption checks and complete changed-candidate validation. Any earlier decoder reuse would need a separate private decoded proof; neither candidate nor retained-slot validation is presumed redundant. The measured audit is substantial; its individually removable validation cost is unknown. No cross-lock cache, stale manifest or skipped fresh audit is proposed.
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
Any guest change requires renewed independent reproduction/coherent pins. R68 std-only diagnostics did not change guest bytes; the subsequently approved decoded Observe candidate changes the System guest path and remains unqualified until the reproduction/integration gates pass.

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

1. R68 diagnosis is complete and the first narrow remedy is now separately approved. Implement canonical decoded Observe's proved duplicate work validation reuse, preserving the fully checked constructed entry and all other proof/check ordering; measure its benefit on exact committee work before selecting another change. The diagnostic approval itself does not authorize a remedy or additional tuning pass.
   Component preservation and meaningful Observe differential/hostility tests precede a source freeze. Any guest change then requires independent Authority/Catalog/both-runtime-role reproduction, coherent six-file pins, strict portable verification and exact resulting-artifact integration. Host-only changes still require current frozen CLI provenance.
   Reproduce ordinary Local Create, Shared Create/committee observation and the historical Query authorization lane separately. Initial input68 delivery, R67 Query503, R66 admit-a503 and actual cold Install confirmation remain independent; no generic prefix retry, deadline change or wider redesign is selected.
2. Qualify automatic cold/returning/mixed pending-generation recovery and image Local callback recovery under unchanged whole30, then full public exact loss/retry/locked reopen. R68 initial Create failure did not reach this gate.
   Preserve historical NRT1 terminal-release ambiguity independently: saved NRT1/actor ACK then 1.8s release confirmation timeout and 120s issuance exhaustion are not fixed by hot-row/root-fence protection.
   Full supported fixed-three NRT1 retry/reopen, Local second-terminal-retry whole30/result/signer checks and typed/fresh-family negatives remain open.
3. Run current packaged public workflow, returning/all-cold Install, leader loss, original-owner/wrong-shadow/absent-origin forwarding, mutation-expiry/denial and observation freshness/cancellation.
   Prove recovered client Applied/routes/fresh Query separately from guest/GenesisDecision/ACK; qualify cumulative >256 authorizations/pruning and complete retained scopes.
   Run actual three-process script through Shared/reopen; genuine mutation-response loss remains a separate fixture requirement.
4. Close all M2 public retained corpus/parity/resource/checkpoint/catch-up/reopen/backup gates, rerun M1 exact resulting artifacts, and continue locally possible M3. Leave unavailable hardware qualification explicitly open.
The prepared Shared-admission error diagnostic remains target-only/unapplied/conditional; it is not a selected runtime remedy. Implementation authority is limited to the separately approved ordered fixes above. Stop for direction for new authority/material scope or after exhausted local resources; no automatic cap renewal or unrelated tuning pass.

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
| Implementation | No defensible aggregate remaining source-hour range; low confidence in total effort. Source confidence in the two narrow reuse candidates is high; removable cost and integration benefit remain unmeasured. | R68 host diagnostics and preservation checks compile/pass. Exact scoped observation's successful guest/purity and deadline refusal are established; outer execution and fresh audit are measured. Ordinary Local Create, historical Query/admission503, actual cold owner confirmation and additional release/readiness defects remain unknown. No runtime fix has been implemented. |
| Integration | Observed portable build-cycle cost **7.83–21.36min** (R67/R68); current R68 workflow attempts **2.77–4.05min**. High confidence in these recorded costs, low confidence in any aggregate remaining range: correction/reproduction/acceptance cycle count is unknown. | Current main441.148s/harness840.133s/verify0.605s; four workflows166.276–242.849s. These uncontrolled costs are neither benchmarks nor future upper bounds/speedup/ETA. A guest remedy adds mandatory coherent independent reproduction whose current cost is unmeasured. Failed setup supplies no cold30 result. |
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
Frozen older evidence:56bb1a9f:docs retains R66/R67,1bf30df2:docs retains R37–R64; e6f2bb45/6d3a4926/62ffbc20 and target release-integration-docs-pre-consolidation-r31.txt remain immutable references.
