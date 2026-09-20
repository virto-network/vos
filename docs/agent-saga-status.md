# Agent saga checkpoint — 2026-09-20

Review integration proposal: freeze at `e20cbb76` with the two exact ranges
and revalidated evidence in [the review guide](agent-saga-review.md).
Everything newer remains unfinished follow-up; no branch has moved. Approval
to advance `saga/agents` remains pending. Fresh bootstrap/ingress/Create/Install,
invocation, exact retry and state-after-restart smoke passes using a rebuilt
frozen-source client; see the review guide for exact evidence and failed
production latency gates. This is
a review milestone only, not a reduction of the complete saga objective.

The complete saga is **not finished**. This is a review/test-environment
checkpoint, not production or master sign-off. `saga/agents` remains at
`31b0cdbb`; nothing has merged or pushed.

Latest genesis integration step: the Shared host now exposes execution-derived
ordinary proposal preparation, including clean signed receipt/admitted-package
input construction, without signing, finality or generation writes.
Its compiled-runtime candidate test passes for both a single member and three
voters plus one observer, with identical proposals across replicas. Scope/finality
refusal coverage and20 selected Shared-host regressions pass (1 ignored).
The internal coordinator now connects retained Create approval/receipt issuance
to proposal preparation using only persisted observation and receipt clocks;
compilation and a negative policy-boundary regression pass. A positive source-runtime
coordinator test now reopens intent/issuer images and reproduces the exact proposal
without signing again or appending another journal entry. Full compiled end-to-end,
daemon-restart coverage and a native startup caller are still absent.
An internal per-signer genesis slot now pledges the exact committee-bound message
before signing and retains/reloads the verified signature. A bounded, leased
native signature backend now passes its focused recovery tests and56 selected
store regressions (1 ignored, HTTP case excluded). It is not yet composed with
the signer. Verified quorum assembly now produces an exact archive record, with
positive two-of-three, malformed-signature and archive-reopen tests; production
trusted committee selection and native coordinator composition remain open.
Authority now exposes a read-only genesis committee query using the exact helper
used for publication verification. The owner authenticates that response through
the installed system actor in source-runtime tests; root and transport committees
are not substituted for it. A fresh unsealed Authority guest passes the query with512
persisted nodes and all5 compiled Authority regressions on small fixtures.
Reproduced/pinned release packages and complete native startup composition remain open.
The owner now prepares and retains that query as a successor of the Create
reservation from authenticated physical material. Fresh-package preparation and
exact reopen after clock advance pass; the old bundle's missing query policy is
refused without persistence. Authenticated dispatch now retains the committee
reply and reuses the exact journal result on retry in the source-runtime test.
ACK now follows durable reply retention, and post-ACK retry replays the pinned
journal instead of trusting a reply file. Reservation release and native startup
reconstruction remain pending (see latest handoff); this is not compiled lifecycle qualification.
Native immutable query/reply files now share an exclusive lease and pass bounds,
reopen and staged-write recovery tests. Their startup-controller composition is
still pending; physical file tests do not qualify end-to-end crash recovery.
The source coordinator now passes full Create/query reservation reattachment
before execution and after ACK, reproducing the exact authorized candidate.
A recovery-only loader provides reservation data before candidate reproduction;
native discovery/admission assembly and process restart remain unqualified.
The native committee-store factory now supplies bounded, descriptor-pinned
same-space discovery and noncreating leased opens. It is not yet connected to
clean_startup or a complete Shared recovery/controller.
Leased Shared recovery now validates the signed Create/locator and query/reply
linkage, and can contribute pending work to bootstrap admission while borrowing
the stores. Its source-runtime reattachment test passes; native discovery-to-
controller composition and end-to-end restart remain open.
Shared preparation now retains the exact admitted runtime before authorization;
recovery re-admits and checks it against the descriptor, rejecting missing or
corrupt packages once authorization exists. Native runtime loads reestablish the
durability barrier after ambiguous publication. Focused and store tests pass.
Shared recovery also owns the issuer lease and verifies retained issuance against
the signed Create. Committee work without its issued receipt is refused rather
than recovered with a fresh issuer; focused tests pass.
Native discovery now joins lifecycle and committee stores into leased Shared
recovery entries, rejecting orphan committee records and invalid intents.
The owning controller and clean_startup call site are still not connected.
The owner can now resume pre-signing preparation through the leased recovery
entry itself, refreshing admission on success and invalidating it on failure.
Focused replay/reattachment and stale-admission refusal checks pass; full native
controller composition remains open.
The owner now issues durable genesis endorsements using the authenticated
committee from recovery. Source tests cover foreign-signer refusal and exact
retained-signature retry; native signer/file composition and publication/finality
are still pending.
Quorum archive selection now retains one exact valid QC across retries with
different signer subsets, including ambiguous insertion failures. Exact archive
retries reestablish durability; focused and archive regressions pass. This is
not live Authority publication or independent finality.
Exact bounded publication input can now be derived from the selected archive,
with candidate/QC binding and content-addressed provision bytes checked. Its
focused test passes; persisted publication work and the extra-blob dispatch
validation path are still pending.
Physical dispatch now validates one exact provision blob for publication on the
descriptor-pinned Authority route while preserving all installed artifacts.
Focused positive/refusal and existing physical-policy tests pass; publication
work persistence and live execution remain open.
Genesis QC integration, archive/startup wiring, Authority publication and independent trusted finality
remain open. These checks do not qualify a release; see the handoff for the
preserved guest artifact and exact test selections.

Replica committees now separate the enrolled logical owner from transport-key
identity while retaining exact descriptor and certified-roster binding. Genesis
tests pass15/0, selected Shared suites59/0 (2 ignored), and the preserved compiled
guest passes proposal preparation with a distinct owner across three voters and
one observer. no-default-features compilation passes. Full enrolled-owner
coordinator/restart/finality qualification remains open.
The signed-publication fixture no longer rewrites ownership to match transport:
native authorization/publication, compiled publication/refusal/expired retry and
native archive reopen/stage recovery pass with the actual distinct enrolled owner.
Its post-state claim is synthetic; this is not full runtime-to-finality qualification.

Broader source checks:56 replay tests pass. The Shared no-op change
retains full recovery auditing but avoids rebuilding unchanged committee
history. Its Shared regression selection passes54 tests/1 ignored, the new
missing-history refusal test passes, and the4095-entry capacity/recovery test
passes in219.03s. This remains slow and is not a controlled live latency result.
The localhost merge-convergence test passes when loopback networking is allowed;
its sandboxed run failed before listener creation. See the handoff for logs and
the review guide's new current boundary for the two consolidated review groups.

## Current node-table cutover

Authority generation20 now uses NodeTable in its production Linear state,
with certificates in the declared s/authority-nodes/ namespace. Bootstrap
stays inline/read-only until the first node mutation materializes it; stored
headers never recreate missing rows. Owner projections use the compact index;
certificate consumers check the exact row commitment. Full certificate/role/
signature auditing remains enabled: bounded validation and compiled maximum
capacity are still open, not bypassed by this conversion. Other Authority
collections remain inline.

The256-replica native fixture now encodes17918 Linear bytes, down from76494,
below the49152-byte inline ceiling. This is not a complete capacity or latency
gate. Current native Authority tests pass72/0 failures/2 fixture exporters ignored, including
reconstruction corruption and513-node capacity. The fresh boxed-seed guest
passes both schema/loader and signed publication/refusal/retry tests with two
persisted certificate rows. Boxing the pending seed resolves the exercised
stack fault without increasing limits; complete transitions match native state.
Compiled node enrollment/removal now also passes: full row images and replies
match native through restore, exact retries and forged-signature refusal;
enrollment/removal export4/3 changes, retries/refusals none. All3 compiled
Authority lifecycle/publication regressions and the new malformed-entrypoint
regression pass together (4 tests) against the latest entry-preflight candidate
in1.98s. Malformed calls to six entrypoints also pass with512 persisted nodes,
preserving all inline lanes and exporting no rows (1 compiled test,1.46s).
Management authorization and signed acknowledgements now check signatures
before the table audit; operation calls reject malformed/context mismatches
before the audit but keep state-dependent authentication after it.
The new full-capacity mutation fixture starts with512 nodes and enrolls the513th.
Native execution passes, but the compiled valid enrollment exhausts the shared
20-read quota. Admin call/context/signature preflight now runs before the full
state audit: the compiled forged-signature phase succeeds without row exports
at this capacity, while valid enrollment remains a failing gate. No validation
or resource ceiling was removed or raised by this preflight change. This does not qualify full-table
guest work, complete crash coverage or a release artifact.
The following follow-up history
includes pre-cutover measurements; see the latest handoff for current artifacts.

## Review boundary and unfinished follow-up

Use **`e20cbb76`** for review and disposable Local/Public-policy testing, not
the current dirty worktree. The clean local `saga/agents` tip is an ancestor of
that checkpoint, so a fast-forward is available; no branch movement is done.
Keep the two review groups below, with no additional micro-batches.

The work branch is at `7470d600` with uncommitted Shared-genesis publication
changes. It now covers signed Authority decision persistence/retry, invocation
reservation and publication/terminal byte reservations. Consolidated checks:
63 actor tests,11 genesis tests and no-default-features compilation pass. These
are host-source checks, **not a reproducibly repinned guest or native Shared
release**. Current Authority state version20 is not the bundled generation.
The updated Authority now also builds for real RISC-V and links/loads in the
inner machine (1044604 PVM bytes, below1280KiB). The full63-test Authority
suite passes after the blob-reference method cutover. Publication execution
with authenticated guest state and a reproducibly sealed package remains open.
The compiled publication test initially found64KiB stack exhaustion, followed
by the1024-compression native-work limit. Heap-backed proposal/provision
components and separate nested decoder frames, plus removal of duplicate
new-record verification (full candidate validation remains), now pass missing
blob, byte-identical native/guest publication state, and expired exact retry.
No stack, heap, gas or compression limit was raised. This small signed fixture
does not qualify maximum capacity, real root-backed finality or a release pin.

Large-provision transport now has a source-level fix: SDK, native pre-reservation
and executor admission share192KiB caller availability, sufficient for the
174921-byte conservative clean-Create provision bound. FETCH work is now460675
bytes and compression work2568 calls, including bounded blob verification;
unlike the earlier small-fixture fix, this change raises resource ceilings and
requires release requalification. Inline state remains48KiB. A fresh compiled
Rust guest passes192KiB blob success/missing/invalid-reference checks. Publication
uses invocation-local `provision_hash`/`provision_len`; no inline or ambient-store
fallback exists. Native issuance/authenticated finality, committee history and
distinct logical-owner/transport-principal handling remain unfinished.
The full signed256-replica regression now measures55586 provision bytes
(18596 proposal,35947 roster,754 evidence,237 decision plus framing), above
the former49152-byte caller window. It now passes exact call/approval/QC
verification, canonical roundtrip and invocation availability admission.
Before the node-table cutover, the256-node Authority enrollment
fixture encoded76494 Linear bytes, above49152 before publication.
The current cutover reduces that header, but complete Authority capacity
qualification remains open. At that checkpoint: executor21 pass/4
artifact-dependent ignored, clean wire36 pass, availability7 pass, SDK167 pass.
A subsequent fresh outer-runtime build now also executes signed192KiB payload
dispatch and exact retry with complete byte-identical native/guest transitions
(1 test passed). Canonical wire/restore coverage and one-byte-over-window
rejection bring the clean-dispatch suite to38 passes. This candidate is not
repinned or independently reproduced; actual Shared/Authority capacity remains
unqualified. See the handoff for artifact identity, gas and evidence boundaries.
Physical row tests subsequently found a large-state guest panic absent natively.
Removing duplicate encoded rollback state and streaming row images directly into
lane frames fixes the exercised case without increasing heap/gas limits. The
fresh outer runtime now matches native reads, write/failure rollback and retries,
including a64KiB write beside3.75MiB untouched rows.39 clean tests and10 codec
tests pass. This qualifies those physical fixtures, not every4MiB state shape,
Authority's table conversion, or a release artifact.
Extending the physical fixture through acknowledgement found and fixed the
same duplicate rollback-buffer issue in ACK. The fresh candidate now also
retires large-state results, repeats ACK exactly after restore and rejects
post-retirement invocation without changing actor rows. Full tested transitions
match native execution. A subsequent large-row yield/resume test exposed and
fixed the same duplicate rollback image in Resume. The current candidate passes
all3 physical regressions (maximum payload, row lifecycle, yielded row lifecycle)
and40 clean tests, with no further ceiling changes. Authority conversion,
uncovered capacity/crash/proof cases and full release qualification remain open.
The same large-row fixtures now cover actor/resource inspection after retirement.
They exposed a second full-state encoding retained during signed resource
validation. Reusing the measured length from the same immutable runtime fixes
the physical inspection panic while preserving all resource checks. Latest
candidate:3 physical regressions,40 clean-wire tests and51 standard-runtime
tests pass; no-default-features agent-runtime compilation also passes (warnings
remain). Reported resource bytes equal the actual encoded state, and inspection
leaves state unchanged. Evidence: `row-resource-runtime.5B1apX` in the handoff.
This is still an uncommitted, unpinned candidate, not a live latency result.
Clean row-storage work now has a private bounded lane-image codec separating
inline snapshots from row data, plus signed-prefix/method-lane access checks
(ten unit tests pass). Runtime schema validation now derives that scope from
the installed schema commitment and checks actor incarnation/deployment/program.
Caller authorization remains a separate required gate. The inner executor now
supports bounded STORAGE_R through an explicit runtime-owned row view; actual
PVM tests cover namespace/hidden-lane rejection,64KiB reads, probes/misses and
budget retention over two yield/restore cycles (executor20 pass,3 artifact-
dependent ignored). An atomic lane-image batch operation now validates all
changes and final byte/count capacity before replacing inline state and rows;
full images can exchange rows without transient overfill. Runtime lane entries
now persist separate rows in strict ALI1 images under a new SLR1 lane marker;
inline updates preserve rows, and Merge observations bind row content.51 runtime
tests pass. The wire suite has90 passes,10 bundled-runtime failures and1 ignored:
the frozen guest predates SLR1. **Current source and bundled runtime are not a
qualified pair.** No old-lane fallback or artifact repin was introduced.
Fresh/resumed clean dispatch now supplies a borrowed row view selected from the
installed actor/incarnation after schema checks and caller authorization.
The clean-dispatch suite36/0 failures includes an actual PVM reading a persisted
64KiB row, committing inline/result state while preserving rows, restoring and
recovering the exact result after expiry (only the authority clock advances).
A runtime commit wrapper stages row deltas and terminal/yield transitions in
one candidate, then validates complete state against signed limits. Clean
ACTOR_EFFECT_EXPORT now decodes one bounded canonical ARD1 delta per slice and
routes successful/yielded rows through that wrapper. Actual PVM tests create a
64KiB row and preserve it through restore/retry; failure statuses discard the
export. Executor21/0 failures (3 artifact-dependent ignored) also covers malformed,
unauthorized/duplicate exports, suspension after export and work-budget refusal.
Generated Rust storage now uses the PVM read backend and exports its successful/
yielded dispatch drain; failed slices discard it. Resume clears prior committed
overlay/cache state.14 storage tests pass. A fresh RISC-V StorageMap fixture
passes set/get and write-yield-resume-write execution, with row-image roundtrips
between slices. This inner-machine test is not package admission or daemon
restart evidence. Authority conversion, full guest capacity and the frozen-bundle
generation mismatch remain open.

Row-transaction savepoints now preserve refusal semantics when storage handles
share an overlay: failed/nested operations restore pending rows and clear cached
reads, and an open transaction cannot cross yield or dispatch boundaries.
All17 native storage tests pass. These savepoints do not roll back inline fields.
Authority's seven mutation entry points now wrap their existing byte/bool
acceptance conventions in row transactions, preserving all inline candidates
and validation.64 Authority native tests pass,0 fail,1 ignored, including
refusal rollback and nested acceptance. The native-only test dependency enables
thread-local storage; the RISC-V dependency remains no_std and its fresh locked
build passes. Authority's actual table conversion remains unfinished.
The fresh compiled Authority also passes missing-blob refusal, byte-identical
publication and expired exact retry (1 test,0 failures); this is not maximum
capacity or trusted-root finality evidence.
The subsequent node-access refactor separates owner projections from owned
certificate reads and centralizes enrollment/removal;65 native Authority tests
pass,0 fail,1 ignored. At that checkpoint this was the inline node table, with unchanged full
validation and state format. No guest artifact qualification covers this latest
refactor yet; the row backend and bootstrap/validation cutover remain open.
The subsequent node-storage component binds per-node certificate rows to a
compact node/owner/digest index and tests explicit bootstrap, commit/reopen,
substitution refusal and rollback.66 native Authority tests pass (1 ignored),
and no-default-features compilation passes with warnings. Authority now declares
the Linear `s/authority-nodes/` namespace in its version19 schema, but the
production node table was still inline at that checkpoint. Constructor-driven row seeding would
be unsafe on restore; a generated-loader regression checks that construction
and restore initialize the handle without creating or repairing certificates.
The component now has explicit lazy bootstrap and atomic header/row mutation.
Its full513-node/64-owner index stays below36KiB by interning owner IDs; a
96-byte-per-node index would exceed the inline ceiling.69 native Authority
tests pass (1 ignored), including restore/refusal/owner-slot-compaction cases;
no-default-features compilation passes with dead-code warnings. Production
integration and the complete-state/compiled-capacity gates remain open.
Latest generation19 checks:70 native Authority tests pass (1 ignored). The
fresh ELF's declared certificate namespace and inner loading, plus signed
publication/refusal/exact retry, pass both physical tests. This exposed and
fixed a PVM compiler bug: raw pointer discovery was reinterpreting a relocated
32-bit jump-table offset as an absolute64-bit pointer. Both discovery and
rewriting now respect overlapping relocation metadata; genuine raw interior
call targets remain rejected. Relocation intervals are merged and searched
with binary search, avoiding a new per-data-word linear scan. Compiler tests
pass66 unit/9 integration (1 unit test ignored). This requires release
requalification; no bundle was repinned.
The indexed compiler also passes all3 existing physical outer-runtime
regressions, including large-state retirement/resume/inspection, in36.38s.
A fresh compiled Rust guest also passes refused insertion/replacement with no
exported rows, subsequent unchanged reads, and the existing yield/resume checks
(1 test,0 failures). Evidence is in the handoff; no bundled artifact was repinned.

Additional physical-execution gap: `run_inner_actor` caps aggregate actor lanes
at48KiB, independently of the now-larger availability/work budgets. The4MiB
Authority archive/reservation tests run native actor handlers and do not prove
such states fit this inner guest boundary. Reconcile these limits and exercise
compiled guest capacity before treating the new reservations as production
completion guarantees. The inline-state limit has not been raised.
The uncommitted source now aligns inner messages with the SDK's16KiB ceiling
and budgets complete FETCH frames plus their sizing probes (67331 bytes).
PVM-enabled executor17 tests pass; this still needs coordinated runtime/guest
generation and artifact qualification. State preparation/lifecycle retain the
48KiB limit. The qualified bundle has not changed.
The real compiled Rust input probe now also passes: largest naturally encoded
message16377 bytes, decoded payload16327, unchanged canonical Local state;
next natural message and16385-byte input reject. This closes the compiled
input-decoder check, not guest capacity or release artifact qualification.
The subsequent lookup dispatcher shares persisted FETCH counters:20 calls and
165763 work bytes cover original frames/probes plus four keys and aggregate
48KiB blob hashing/copying. It charges before verification/copy, returns
HOST_NONE for absent data and HOST_FULL without partial copying for a short
buffer. Executor tests pass18/0 failed/1 explicitly artifact-dependent ignored.
The qualified bundle still has neither this dispatcher nor the revised budget.

The full goal also still requires performance, authenticated reclamation,
remaining crash/proof coverage, workspace lint and production release gates.
No controlled live latency improvement has been established. In the qualified
release, Invoke+ACK account for76.7% of measured Authority-query phase time;
six serial inventory queries account for16.3s after Install. This is not a
disk-write-dominated bottleneck or a production-ready result.

## Qualified release evidence

Latest qualified release source: `e20cbb76`, including the host startup-decode
fix. Locked/offline build7m05s, bundle creation/verification and fresh Local
lifecycle pass. SHA-256:
`d11e52eed2e917a53e025536972f375363d30355d602dee2e9e23a3f6950e2cc`.
Final-source CLI regression at93e63c5f passes255 tests,0 failed,19 ignored
in81.76s; that test revision has no implementation changes since the qualified
release source. Later Shared follow-up work is outside this qualification.
Fixture `current-latency.KD6UwR`: Create29s, Install38s, mutation21.95s,
read-after-restart21.88s (full retry tests23.79s/23.68s). Positive retirement,
exact retry, HTTP status and SSH keyscan pass; authenticated shell not tested.
Readiness16s/20s/26s still fails10s. Shutdown0s/0s/1s needs no forced cleanup;
daemon/listeners are gone. This remains disposable Local/Public-policy
qualification, not production. See the handoff for exact evidence and the
preserved initial fixture-prefix setup failure. Earlier release results below
retain their original source boundaries.

Runtime repin after9cdc1ff1: PublicPreflight Invoke matching now avoids one
duplicate work-commitment hash. SDK166 tests and full runtime-wire98/1 ignored
pass. A paired guest test preserves exact Invoke/ACK transition bytes and saves
1.43%/0.76% gas on its fixed4KiB-padding fixture. This is not a live speedup.
Bundled ProgramId `8071ad67661c6539ab504ccecc18c9e8d6d858803b52fca05389823f8109d3cc`
is independently reproduced from immutable ba7be457 in two isolated builds;
ELF/PVM bytes match the measured candidate. Candidate-enabled wire98/1 ignored
and the actual bundled-Authority fresh-query regression also pass. Manifest,
host ProgramId, build-time digest and embedded PVM are now updated together.
Post-pin artifact-release18/18 and bundled wire98/1 ignored pass; the full
current-source `just verify-agent-runtime-release` build/byte-comparison passes.
Release a732e079 now builds in7m14s and passes bundle creation/verification.
SHA-256: `4f7f48048679b0a0ecc2283e128c7996d62e5f34d87ab1a9e1817d3aa305cd94`.
Full post-pin CLI255/19 ignored passes in96.44s. Fresh fixture
`current-latency.bWPsi4` passes Create30s, Install37s, Counter mutation21.64s,
read-after-restart21.96s with value7, positive retirement and exact ACK retries.
HTTP status/SSH keyscan pass, not authenticated shell access. Readiness16s/20s/26s
still fails10s; shutdowns0s/0s/1s require no forced cleanup. Probe daemon/listeners
are gone. No controlled end-to-end speedup is established.
Build/bundle/CLI evidence: shared `target/task-tmp/single-preflight-release.pE0Yxy/`.
Subsequent host-only startup cleanup removes a duplicate NOD1 decode while
preserving canonical/scope checks. Physical native-operation tests10/1 ignored
pass, including added malformed/wrong-scope cases. It is not in the a732e079
executable and has no measured latency claim; reclamation remains incomplete.
Full host-feature run at c9990ed6 finishes1877 passed,1 failed,4 ignored. The
failure was an immediate cached-status read racing AppendEntries publication
in a Raft test. Its test-only fix passes all15 worker tests and50 isolated
repetitions. The full corrected-source rerun at45ff53e0 now passes1878 tests,
zero failed,4 ignored,0 filtered in1587.02s (session25218 exit0), logged to
`single-preflight-release.pE0Yxy/host-feature-suite-fixed.log` under shared
`target/task-tmp`. Both long inventory/system-attachment tests and the repaired
Raft test pass in this run. This does not close the remaining production gates.
Use the d4d38ebb release checkpoint below only with its original-pin fixtures;
do not boot those stores with the new pin.

Previous live-tested release checkpoint: `d4d38ebb`. Its locked/offline release build
passes in7m03s, and its `release bundle` / `release verify` commands pass.
Executable SHA-256:
`1ddcc3c99ea16c5982d7ac8f2e752cfdbf91ceb9145d34d087f1524110668a08`.
Fresh Local/Public-policy lifecycle qualification also passes on this executable:
Create29s, Install37s, Counter mutation21.55s, read-after-restart21.48s with value7,
positive retirement and exact ACK retries. Readiness16s/20s/26s still fails10s;
shutdowns0s/0s/1s at whole-second resolution pass without forced cleanup.
HTTP status and SSH keyscan pass, not authenticated shell access. Fresh fixture
`current-latency.VF0MXp` remains at its original path; no old store was reused.
The older detailed live results below belong to8f96fad8 and are historical.
The current-source full CLI suite also passes255 tests,0 failures,19 ignored
in80.29s with loopback access; explicit host-feature and full clean-break reruns
still retain their older source qualification boundaries.
Evidence and the preserved previous executable are in shared
`target/task-tmp/review-checkpoint-release.6a7GXF/`.

## Previous-pin qualification (historical)

The preceding release pinned decoded-input validation reuse from immutable
`330274bb139885b61e833bb63768a3024b5b9797`, ProgramId
`ebed0967a4d987e2f50f6e8908b294f713b0cf74583d1b5dc6648a8a542a049c`.
Two isolated ELF/PVM builds match each other and the measured candidate.
Paired exact-output tests use12.6% less fresh-Invoke gas and20.9% less ACK gas
than the preceding bundle. Post-pin release checks18/18 and bundled wire
checks97/1 ignored pass. The real candidate Authority-query test also passes.
Release implementation **`8f96fad8`** builds and verifies its bundled artifacts.
SHA-256: `ee49a636c477c1e3ef21d56f16e2c181307bd1e740ad20bee80b6da27e30e76d`.
Full CLI regression passes255 tests/19 ignored with loopback access. New spaces automatically
receive system packages and enabled HTTP/SSH configuration. The Local workflow
has live evidence for Create, Counter Install, increment, retirement/ACK retry,
and reading7 after restart. Latest release checks HTTP status and SSH listener
availability (not authenticated shell access). Earlier-generation probes cover
host-key persistence and conflict reporting. New-space probes verify fresh
Create (25s) and Counter Install (36s), with no retry/resume.
Fresh Counter increment takes20.04s and read-after-restart20.33s on this release;
value7, positive retirement and exact ACK retries pass. This is Public-policy
qualification, not the remaining Private/Attested proof matrix.
Readiness13s, then19s/26s after restarts, still fails the10s production gate.
All three clean shutdowns completed below1s at the probe's whole-second
resolution, with no forced cleanup. Fresh fixture: `current-latency.coTfCk`.
Older fixtures must stay with their original pins. The post-repin default-library
suite passes 1,434 tests, zero failures, one ignored in 195.71s. The post-repin
host-feature suite passes 1,876 tests, zero failures, three ignored in 1,403.60s.
Both full inventory rotation and system-attachment checkpoint tests pass.

Use disposable spaces only. Do not migrate valuable older-generation stores.
Preserve failed operations and exact request bytes; a timeout or unsigned HTTP
error does not prove failure. Retired historical Create replay after Install
returns409; retention is bounded, not indefinite server reply caching.

## Review organization

Keep two scoped batches, not one review per work-in-progress commit:

1. `31b0cdbb..f79f0e3d`: integrated clean-break architecture/lifecycle.
2. `f79f0e3d..45ff53e0`: recovery, performance, artifact, host/build fixes and qualification follow-ups
   (60 files, +6,484/-345 at this frozen source checkpoint).

The integrated diff remains large (240 files, +79,025/-59,066 at `a732e079`).
These are review groupings, not independently deployable slices. Subsequent
review-handoff documentation and disposable-fixture test updates belong with batch2. The old C1 boundary
is not independently merge-ready.
See [review guide](agent-saga-review.md) and [evidence handoff](agent-saga-handoff.md).

The qualified implementation is a review/disposable Local-space checkpoint,
not production/master sign-off.
The post-`36e63581` uncommitted Shared-finality experiment has been removed:
it depended on legacy embedded authority state absent from clean Create. Its
failed test and patch are preserved in the evidence directory; see the handoff.
The latest live-qualified Local release checkpoint is `a732e079`. Ordinary Shared finality needs clean
system-authority actor integration, not a switch to the legacy replay helper.
No merge or push is authorized by this checkpoint. Fresh Create/Install/invocation
have now been measured, but not as a controlled before/after comparison.
Preserve original fixture paths and failure evidence. When implementation
resumes, address authenticated inventory
with bounded equivalence/recovery checks and repeat release qualification.

## Remaining production work

| Requirement | Current evidence / gap |
| --- | --- |
| Startup and operation latency | Latest a732e079 fresh readiness16s, restarts20s/26s;10s gate fails. Fresh Create30s, Install37s, managed increment21.64s and read-after-restart21.96s. No controlled before/after speedup is established. |
| Recovery performance | With8-entry scheduling, second pass system owner8.02s, including14 runtime calls6.39s. Shorter history helps; not a same-history A/B. |
| Inventory performance | Two agents require six sequential authenticated queries. Latest fresh Create lifecycle9.54s is followed by route reconciliation16.52s (inventory16.24s); post-Install inventory16.16s. Inventory still materially delays operation completion. |
| Shutdown | Latest disposable probes report0s at whole-second resolution and no forced cleanup; general busy/crash matrix still incomplete. |
| Ordinary Shared genesis/finality | Native startup still installs `UnavailableAgentFinality`. A canonical ordinary archive codec, generic archived provider and leased per-locator native backend now exist and have focused tests, but are not composed into the native coordinator/startup. Signed issuance, live Authority publication and authenticated replay-backed finality integration remain missing, not just a verifier switch. System genesis is a separate path. |
| Authenticated reclamation | Issuer/coordinator bounded-record reclamation remains unfinished; invocation retirement is not proof of Authority application. |
| Recovery/proof qualification | Remaining mixed pending/crash/capacity cases, pre-expiry Abort/management expiry, cross-runtime portable positive ACK, and full Private/Attested cryptographic proof matrix. |
| Formatting | Pinned-host formatting passes, including after decoded-input validation reuse. No lint allowances added. |
| Workspace lint | Full `check-all` at cb01ae08 passes formatting and fails in vos Clippy with351 diagnostics. Host/journal/network/cache cleanup reduces this to336; driver34, Local50, journal-store97, network96 and updated journal-driver33 tests pass. No warning allowances added. Downstream workspace lint completion and the full `check-all` result remain unproven. |
| Cutover supporting gates | Full `just clean-break-check` passes at bf013ff1 with all nonzero test selections, nested actors, SDK intra-doc links and CLI/docs surface checks. Full `just test-examples` now also passes; see the qualification below. Atcda6c997, SDK165/165 tests and vos no-default-feature library check pass. The broader `just check-all` recipe and workspace lint remain unqualified. |
| Release integration | At8f96fad8: release build/bundle and fresh Local lifecycle pass; CLI255/19 ignored, release18/18 and wire97/1 ignored pass. Post-pin default library1,434/1 ignored and host-feature1,876/3 ignored pass with unchanged runtime source. Prior-pin actor-build4/task-build1 pass atcda6c997. Full cryptographic proof qualification and remaining sign-off stay open. |

The post-pin `scripts/check-agent-clean-break.sh` gate also passes: retained CLI,
removed compatibility surfaces/paths, and selected operator documentation.
The full `just clean-break-check` recipe now also passes at bf013ff1; workspace
lint and the broader `just check-all` recipe remain open.
Post-pin supporting gates also pass: system-authority 58/58, system-catalog
10/10, and SDK no-default-feature documentation with broken intra-doc links denied.
These do not qualify all examples/external links or host issuer reclamation.
At2c340623, `just test-pvm-proof-fast` passes120 library,1 arithmetic,15
control-flow and7 memory tests, with zero failures/ignored. This does not close
the full Private/Attested cryptographic proof matrix.
Atbe0b54f4, `just check-pvm-proof-no-std` and `just check-pvm-proof-wasm` also
pass. These are verifier portability builds, not WASM execution qualification.
The full `just test-examples` recipe now passes after correcting the custom
runtime test's target-directory lookup and removing moving-nightly overrides
from actor builds. All four actors build; guest entry, host examples and the
explicit compiled custom-runtime scheduling/rejection test pass. This does not
close the broader `check-all` recipe or production profile gaps.
At4817e479, `just test-pvm-vectors` passes20 tests and
`just verify-voucher-check-release` passes2 catalog checks. The latter verifies
the checked-in released artifact, not a new source reproduction or full proof.
At23f98d4b, full workspace library regression passes2,314 tests, zero failures,
5 ignored across22 library binaries. This covers current source integration,
not all explicit feature combinations, nested workspaces or binary/integration tests.
The probe fixture now builds with a pinned guest toolchain/locked dependencies,
and `just check-probe-fixture` passes its real commit-before-outbox test. The
missing-artifact negative check fails explicitly instead of silently passing.
That test is now ignored in ordinary library runs and executed by the release gate.
Full `just build-pvm` also passes after fixing current-runtime artifact lookup
to follow Cargo's target directory and locking/pinning the registry build.
The current-source runtime candidate exactly matches the bundled PVM; no
production artifacts or pins were replaced. The complete `check-all` gate still fails at lint.

Post-pin broad library regressions are complete; the production gaps above remain.
The subsequent host/journal/network/cache changes have targeted tests and the
current workspace library pass. They are now in the d4d38ebb release executable
with fresh Local lifecycle coverage; the explicit host-feature suite and full clean-break recipe precede
those changes and retain their recorded qualification boundaries.
Performance work must remain focused on the14–16s authenticated two-agent
inventory. Exact-binary profiling identified outer BLAKE2b cost, leading to
the now-released decoded-input validation reuse. Paired gas savings are proven;
the different live fixtures do not establish a controlled end-to-end speedup.
Create improved in this observation, but Install and managed operations remain
slow. Preserve complete-head authentication, recovery and positive ACKs;
do not lower safety/retention bounds or publish readiness before recovery.
Latest live phase attribution across21 complete queries places75.64% of56.284s
in Invoke+ACK,12.31% in reservation/checkpoint and3.00% in pending-record
persist+clear. These are disjoint wall-time spans, not guest-only CPU samples;
see the handoff. Optimizing record writes alone cannot solve the measured delay.
An additional mock-transport regression after50607708 verifies the two-agent
query pattern (6 initial, 1 unchanged, 6 after an Install-like head change,
1 unchanged) and requires the newly installed actor in the refreshed inventory.
All12 production-owner tests pass. This is cache correctness coverage, not a
latency improvement or new live-release qualification.
