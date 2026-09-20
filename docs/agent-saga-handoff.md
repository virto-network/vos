# Agent saga review handoff — 2026-09-15

## Checkpoint and decision

Review source checkpoint: `45ff53e0` (two batches; see review guide).
Build/bundle checkpoint: `e20cbb76`.
Live-qualified Local/Public-policy test release source: `e20cbb76`.
Use [current status](agent-saga-status.md) for remaining gates and
[the review guide](agent-saga-review.md) for the two current review ranges.
This log is reverse chronological: older statements about pending builds or
the then-current executable are historical, not additional current blockers.
The checkpoint is suitable for review/disposable Local testing only; the full
saga remains unfinished. No merge or push has been performed.

### 2026-09-20: public deferred-generation recovery entrypoint

Added recover_deferred_shared_generations on the system owner for the native
controller. It bounds and validates the complete archived locator set against
the host's deferred IDs, rejects duplicate/extra/missing records and mismatched
recovery targets before replay, independently reproduces each archived candidate
and authenticates its committee/publication, then completes reopening with the
opaque proof set. A non-staged/already-completed host is refused immediately.
Callers retain the six-store recovery owners and archive leases; the method
does not manufacture finality from supplied records or caller-selected replicas.

The root-only bootstrap test now uses this public entrypoint for its empty
ordinary set and verifies repeated completion refusal. Native clean_startup and
running controller still need discovery, archive loading and lifetime ownership
wiring. A positive root-plus-ordinary reopen/process restart test remains open.

### 2026-09-20: bootstrap admission selects root-first host opening

NativeAuthorityOperationStartupAdmission now offers an explicit
with_deferred_shared_genesis mode, defaulting off. Bootstrap selects the staged
host path only in that mode, acquiring the original outer lease and using its
independent root pins and system Agent identity. Existing admission preparation,
pending-work reattachment and system route recovery remain in place; ordinary
generations are deferred for the controller's replay-proof completion. Native
clean_startup does not select this mode yet, so it cannot silently announce
readiness without completing ordinary recovery.

The new root-owner test drops/reopens the actual physical system owner from
retained bootstrap stores (no fresh-plan fallback), preserves target/journal
identity and completes the empty ordinary phase exactly once: 1/0 in 3.01s
(deferred-bootstrap-owner.log under shared target/task-tmp/
committee-query-package.6w5tI7). This is actual root-generation reopening in one
process, not a root-plus-ordinary/process-restart proof. Full native controller
and startup integration, broader gates and reproducible release remain open.
The existing eager Shared coordinator selection also passes 3/0 in 43.89s
(deferred-bootstrap-eager-regression.log), including source publication/ACK/
recovery and finality attestation. git diff --check passes.

### 2026-09-20: exact proof-set completion of deferred host opening

Added owner-mediated completion of deferred Shared genesis recovery. It accepts
only opaque replay-produced proofs, bounds the set by host capacity, validates
Space/system Agent/Authority binding and current system genesis/admission,
rejects duplicate ordinary locators, and requires exact membership equality
with the host's deferred generations. The resulting verifier accepts only the
exact attested provision; missing provisions have no fallback. It then delegates
physical reopening to the host under the retained outer lease.

Staged completion is now explicitly one-shot. Eagerly opened hosts and already
completed staged hosts reject this operation, preventing it from replacing an
existing verifier after startup. Tests cover exact/mismatched/absent provision
lookup, duplicate/extraneous proof refusal and non-staged completion refusal;
the host staging test checks repeated completion refusal. Native startup still
needs to select staged opening and collect fresh proofs before completion.
Positive root-plus-ordinary process-restart qualification remains open.

Fresh-package coordinator selection passes 3/0 in 40.83s
(deferred-finality-proof-set.log); final staged-host one-shot test passes 1/0 in
0.57s (deferred-completion-once.log). Logs are under shared target/task-tmp/
committee-query-package.6w5tI7. git diff --check passes.

### 2026-09-20: host regression diagnosis and merge convergence wait

The original serial run completed: 22 pass, 1 fail, 1 ignored in 217.71s
(deferred-host-regressions-serial.log). The full 4095-entry system-attachment
capacity test passed. Its only failure was merge-pump waiting for a loopback
listener under network restrictions. Isolated loopback-enabled execution passes
1/0 in 1.30s (merge-pump-loopback.log); restricted isolation fails at the listen
wait (merge-pump-isolated.log).

A loopback-enabled serial run excluding the already-running capacity test passed
21, failed 1, ignored 1 in 30s (deferred-host-loopback-serial.log). That failure
was later: the event blob was present but target roots were still empty. The
test incorrectly used blob availability as its convergence barrier even though
authenticated blob staging precedes merge-head integration. Changed the existing
10-second predicate to check both exact event bytes and exact source roots under
one target-host lock; the final root equality assertion remains. This does not
increase timeouts or relax the convergence requirement. Initial parallel-suite
provisioning failures remain unexplained; serial success is not a parallel gate.
Logs are under shared target/task-tmp/committee-query-package.6w5tI7.

After the predicate fix, loopback-enabled serial selection passes 22/0 with one
compiled-runtime test ignored in 15.00s (deferred-host-loopback-fixed.log). It
excludes only the capacity test already passed by the original serial run.
Focused staged opening also passes 1/0 in 0.53s (deferred-host-rebuild.log).
No test process from this diagnosis remains running. git diff --check passes.

### 2026-09-20: staged root-first host opening

Added an internal open_system_first path using independently supplied root pins
and system Agent identity. It retains the outer host lease and opens only that
system generation through root/QC verification; all other discovered generations
remain deferred and absent from host listings/routes. Completion verifies all
deferred ordinary provisions through the supplied finality verifier and physical
recovery before adding any to the live map. Failure leaves them deferred;
retries rescan file-stage state under the same lease. Deferred generations count
toward capacity and cannot be overwritten through provision/portable restore.
The existing public open/reopen paths remain eager and unchanged in semantics.

This is not yet wired to the bootstrap owner or native startup. The new test
exercises deferral, lease retention, finality refusal and successful completion
using the existing ordinary fixture and controlled finality; it does not claim
end-to-end root-plus-ordinary reopening or cryptographic finality qualification.

Focused staging test passes 1/0 in 0.57s (deferred-generation-finality-final.log
under shared target/task-tmp/committee-query-package.6w5tI7). The broader parallel
Shared-host selection fails 6 tests, 17 pass, 1 ignored in 3.84s
(deferred-host-regressions.log): five Unavailable failures and the new test's
initial provision reports CorruptResidue before exercising deferral. A serial
rerun is underway (deferred-host-regressions-serial.log); the new test passes
there, but merge-pump has failed and system-attachment is still running. Do not
report the broader gate green or attribute these failures without further checks.
Initial compilation's borrow conflict was corrected by copying bounded deferred
IDs before mutating the host. git diff --check passes.

### 2026-09-20: owner-produced replay finality attestation

Added an opaque, non-wire-decodable ReplayVerifiedAgentGenesisFinality for one
exact provision. Only the root-pinned owner constructs it: reproduce the
authorized candidate and independently authenticated committee, load/validate
the exact retained publication, require its positive ACK, then independently
replay the pinned journal/ledger interval and validate the decision through the
existing physical-dispatch checks. An archive, signature set or saved reply
cannot construct this capability, and a missing/unacknowledged publication is
refused rather than dispatched by the attestation phase.

This is a finality building block, not startup completion. Native startup still
uses UnavailableAgentFinality. SharedAgentHost currently opens all generation
namespaces before returning the system owner; ordinary generations need their
verifier during that open. Integration must establish trusted root-system replay
before ordinary reopening, retain leases, and obtain fresh attestations on
restart without a circular callback/host lock. Do not replace the unavailable
verifier with archive-only validation.

Fresh-package source selection passes 3/0 initially in 40.60s
(publication-finality-attestation.log) and 3/0 in 41.21s with cross-provision
refusal (publication-finality-attestation-final.log), under shared target/task-tmp/
committee-query-package.6w5tI7. The tests refuse attestation before publication,
accept the exact provision after independent replay without journal growth, and
reject a structurally valid alternate-epoch provision. These remain source
fixture tests, not compiled full-system or process-restart qualification.
git diff --check passes.

### 2026-09-20: first-dispatch archive gate and startup integration audit

Added a failure case before the first publication dispatch: archive insertion
returns unavailable, the coordinator invalidates admission, neither archive nor
reply is written, and the journal remains at the post-query index with no
publication ACK. Publication work is already reserved in this fixture; the
assertion covers first execution ordering, not a whole fresh process.

Inspected clean_startup: Local lifecycle discovery precedes operation/admin
admission; Shared genesis admission must be included in that combined admission
before opening the system owner, with all leases transferred into the running
controller afterward. Ordinary-agent finality is still UnavailableAgentFinality.
The AgentGenesisFinalityVerifier contract requires independently authenticated
live system-Agent history and rechecking reopened generations. Archive integrity,
quorum signatures and retained ACK alone must not replace that boundary.
Startup wiring is not claimed complete, and the fail-closed verifier is unchanged.

Fresh-package source selection passes 3/0 in 36.17s
(publication-first-dispatch-archive-gate.log under shared target/task-tmp/
committee-query-package.6w5tI7). git diff --check passes.

### 2026-09-20: recovery-to-publication coordinator composition

Added publish_recovered_shared_genesis: it reproduces the replay-authorized
candidate, authenticates the installed Authority committee, selects and durably
retains the exact archive against collected signatures, then executes publication,
retains the decision and ACKs. It reloads exact work and restores all three
reservations to admission only after success. Any failed phase invalidates the
old admission snapshot; reopening retains all six store handles. The caller
must keep the archive's exclusive lease, and signatures are validated against
the authenticated committee, not trusted because the caller supplied them.
The returned archive is not finality and no lifecycle reservation is released.

Native controller/startup callsites, signature collection/selection policy,
independent finality, process restart qualification and release gates remain
open. This composes existing safety boundaries; it does not expose a new public
CLI/API or claim production readiness.

Fresh-package source selection passes 3/0 in 35.75s
(publication-coordinator-composition.log under shared target/task-tmp/
committee-query-package.6w5tI7). Tests cover archive write refusal without new
journal entries, invalidated admission, reopening all six stores, successful
composition, immutable archive retry with no new signatures and restored
three-reservation admission. The refusal is tested with publication execution
already pending from lower-level retention-failure tests; it is not a cold-start
proof that first dispatch never precedes archiving. git diff --check passes.

### 2026-09-20: six-store leased genesis recovery

Native recovery now owns the publication reply as its sixth store. Opening and
refreshing admission validate/resync reply bytes against exact publication work,
refuse orphan replies, and retain all three pending reservations. A failed
refresh keeps admission invalid. into_stores transfers all six handles. Native
discovery now passes the reply's shared lease into typed recovery instead of
unconditionally rejecting that phase. Local integrity still does not authenticate
publication or prove finality: execution/replay remains the owner's boundary.

Tests exercise post-ACK open/resume, retained three-work admission, orphan reply
refusal, corrupt-reply refusal on open, and invalidation after corruption during
refresh. The full native controller/startup wiring, process restart proof,
independent finality and release gates remain unfinished.

Fresh-package source selection passes 3/0 in 28.68s
(publication-reply-leased-recovery-final.log under shared target/task-tmp/
committee-query-package.6w5tI7). Initial compilation caught an owner generic-name
collision; corrected before this passing run. git diff --check passes.
Native store regression selection passes 62/0 in 0.43s, with the existing
ignored test and HTTP retry exclusion unchanged (native-six-store-recovery.log).

### 2026-09-20: native publication reply storage and recovery codec

Added immutable role 44, ordinary-agent.genesis-publication-reply, under the
shared query/reply/publication lease. The GPR1 bound is 68 bytes plus the maximum
canonical genesis decision and is enforced by both retention and file storage.
Tests cover replacement/oversize refusal, exact retries, reopening, lease held
by the last reply handle, interrupted first staging and conflicting successor
staging. Native store selection passes 62/0 in 0.53s, with one existing ignored
test and the HTTP retry exclusion unchanged (native-publication-reply-store.log
under shared target/task-tmp/committee-query-package.6w5tI7).

Added a bounded reply loader checking GPR1, exact work/authorization commitments,
canonical decision and equality with the provision in retained work, followed
by exact resync/readback. This returns data, not execution authority. Native
typed recovery still needs the sixth handle and loader integration; discovery
explicitly refuses a retained publication reply until then, rather than silently
omitting it. The full publication controller, finality and release gates remain
unfinished.

Fresh-package source selection passes 3/0 in 25.37s (publication-reply-load.log),
including exact decision decoding, mismatched work refusal, resync failures
before/after write and corrupt trailing bytes. git diff --check passes.

### 2026-09-20: publication ACK and authenticated replay

Publication execution now acknowledges only after exact decision retention.
The network ACK entrypoint accepts an owner-constructed opaque proof; the owner
checks all ACK identity fields plus work/authorization commitments and retained
positive acknowledgment. Already acknowledged invocations replay the pinned
Invoke/ACK interval instead of dispatching consumed work. Pending-capacity
recovery classifies canonical publication decisions against the exact provision
blob in freshly replayed work; stored reply bytes alone grant no authority.
No finality or lifecycle reservation release is inferred from ACK.

Fresh-package source selection passes 3/0 in 25.91s
(publication-ack-recovery.log under shared target/task-tmp/
committee-query-package.6w5tI7). Tests prove no ACK after either retention failure,
successful ACK after retention, retry without added journal entries, three-work
reattachment after ACK, reconstruction of missing reply bytes from history and
refusal of conflicting/corrupt saved bytes. This is still a same-host fixture,
not process-restart qualification. git diff --check passes.

Native reply-file storage/lease ownership and recovery validation still need
integration, followed by independently authenticated finality, native startup
wiring and process-restart/end-to-end/release qualification.

### 2026-09-20: publication execution and retained decision

The coordinator now executes the exact reserved publication using persisted
management dispatch and validates the returned invocation identity, completion
status and canonical decision against the selected archive. GPR1 retention
binds exact work and authorization commitments to that decision, refuses a
different existing image, and requires commit/readback before returning.
The method deliberately does not ACK yet: publication ACK capability, post-ACK
recovery classification, native reply storage/lease ownership and recovery
validation remain next. Retained decision bytes are not independent finality.

The fresh-package source selection passes 3/0 in 19.79s
(publication-execution-final.log under shared target/task-tmp/
committee-query-package.6w5tI7). It executes the source Authority actor through
the existing coordinator fixture, injects reply-store failures before and after
write, verifies no ACK in either case, then retains and retries the exact
decision without new journal entries. This is not compiled full-system/live
deployment qualification. Initial compilation caught a generic parameter name
collision with the owner; renamed before the passing run. git diff --check
passes. The full saga and production release gates remain unfinished.

### 2026-09-20: leased publication reservation in native recovery

NativeSharedGenesisRecovery now owns the publication store as its fifth store
and validates/includes the optional third pending reservation on open. It
refuses publication without a query or without authorization, and validates
publication via the reservation-only loader. Admission borrows the full owner;
into_stores transfers all five handles. Native discovery now hands the shared
publication lease into this owner instead of rejecting every publication phase.
Resume replays authorization/query as before and reloads/preserves publication
when refreshing admission, rather than reducing the snapshot to two works.

The fresh-package source selection passes 3/0 in 18.22s
(publication-leased-recovery.log under shared target/task-tmp/
committee-query-package.6w5tI7). Tests open the three-reservation recovery owner,
borrow startup admission, detach/reattach, reproduce candidate and committee,
and confirm refreshed admission still contains exact publication work with no
new journal entries. Missing-query and corrupt-publication recovery are refused.
This is same-host recovery, not a completed process-restart/native startup test.
The factory is still not wired into clean_startup, and publication execution,
reply/ACK, independent finality and release gates remain open.
Native store regression selection passes 62/0 in 0.44s, with the existing
ignored test and HTTP retry exclusion unchanged
(native-publication-recovery-suite.log). git diff --check passes.

### 2026-09-20: publication reservation recovery validation

GPW1 now has a bounded recovery loader which accepts reservation data only,
not execution authority or finality. It verifies the preceding query's exact
domain-derived ID and installed Authority route, publication's candidate claim
and authorization-derived invocation, provision bytes, journal lineage and
ordering, preflight, and unchanged base artifacts/origin/work fields. It resyncs
and reloads exact bytes before returning. Candidate reproduction and independent
committee authentication remain required before publication execution.

Initial source selection passes 3/0 in 16.27s (publication-recovery-load.log under
shared target/task-tmp/committee-query-package.6w5tI7), including mismatched
query invocation and runtime-lineage refusal. Native typed recovery still needs
to own the publication handle and retain its third reservation when refreshing
admission; the scanner's explicit refusal remains until that is implemented.
The extended selection passes 3/0 in 17.31s
(publication-recovery-reattach.log): failed durability resync returns no recovered
work, and detaching/reattaching all three reservations allows exact publication
preparation without adding journal entries. This retains the same host and is
not a process-restart/native-controller test. git diff --check passes.

### 2026-09-20: native publication file and shared lease

Added role 43, ordinary-agent.genesis-publication, under the existing dedicated
committee directory. Publication shares the query/reply lease, has its own GPW1
size bound used by both codec and file backend, and uses immutable commits and
stage reconciliation. Tests cover exact retries, replacement/oversize refusal,
lease retention after both query/reply handles drop, reopening, interrupted
first publication staging and conflicting successor staging.

Native store selection initially passes 62/0 with one existing ignored test
and the HTTP retry test explicitly skipped (native-publication-store.log under
shared target/task-tmp/committee-query-package.6w5tI7). Until typed recovery
owns and validates the third reservation, discovery explicitly refuses any
publication record; it cannot return an incomplete two-work snapshot. This is
an intermediate fail-closed boundary, not completed publication recovery.
The final selection, including an explicit discovery refusal test for retained
publication data, passes 62/0 with the same exclusions
(native-publication-store-final.log). git diff --check passes.

### 2026-09-20: retained publication preparation and failure boundaries

Publication preparation now retains the complete GPW1 work and journal anchor
as a successor to the exact committee query. Retries preserve the original
preflight and observed slot, validate the candidate/committee/archive binding,
and check the installed physical artifacts before returning reserved work.
This does not execute publication or prove finality.

The fresh-Authority-package source test selection passes 3/0 in 16.10s
(publication-retention.log). Added storage failure tests cover failures before
write and after write, refusal while durability confirmation keeps failing,
exact-byte recovery after reopening, immutable conflicts, and corrupt trailing
bytes without modifying the corrupt image. The selection passes 3/0 in 16.03s
(publication-retention-failures.log). Both logs are under shared target/task-tmp/
committee-query-package.6w5tI7. These are in-memory store failure tests, not
native-file/process-crash tests. git diff --check passes.

Next: add publication storage and its third pending reservation to leased native
recovery before wiring execution. The current recovery snapshot only contains
authorization and committee query; it must not be used to recover a publication
phase. Publication dispatch/reply/ACK, independently authenticated finality,
native startup/controller wiring and release gates remain open.

### 2026-09-20: publication provision availability validation

Physical dispatch validation now has a narrow provision-blob path for
publish_genesis on the exact Authority issuer actor/deployment/program/producer
selected by the descriptor. It requires one extra blob and still compares every
installed program/schema/policy/configuration byte. The extra provision must be
bounded, hash-valid and canonically decodable, match the work's Space/system
Agent, derive the exact invocation from the authorization ID, and reproduce the
complete canonical compact message. Missing provision or base artifacts,
unrelated extras, changed preimages and substituted invocation IDs are refused.
This validates transport data only; actor policy must still verify pending
authorization and QC. No receipt, finality or policy validation was removed.

Initial source selection passes3/0 in16.48s (publication-availability.log under
shared target/task-tmp/committee-query-package.6w5tI7). Final run includes the
narrow Authority-route and missing-artifact checks and passes3/0 in15.52s
(publication-availability-final.log). The existing physical policy/attestation/
availability regression passes1/0 (physical-dispatch-regression.log).
git diff --check passes.
Publication work/anchor persistence, actual live publication, finality and the
native controller remain open.

### 2026-09-20: exact compact genesis publication input

The genesis issuance module now builds the exact publication invocation,
dynamic publish_genesis message and content-addressed provision blob from the
selected record. It checks the proposal/roster/claim/catalog against the opaque
authorized candidate, verifies the QC against the independently authenticated
committee, and enforces both clean-provision and caller-availability bounds.
The message carries only authorization ID, provision hash and length; no inline
fallback or ambient blob lookup is added.

The source test derives this input after ambiguous archive selection, checks
exact invocation and canonical blob/message fields, and refuses substituted
system-genesis lineage. The focused coordinator test passes1/0 in3.36s
(genesis-publication-input-final.log under shared target/task-tmp/
committee-query-package.6w5tI7); git diff --check passes. This is data
preparation only: persisted publication work/anchor and authenticated dispatch
remain open. In particular physical_material_authorizes_work currently requires
exact installed-artifact availability, so publication's additional provision
blob needs an explicit validated route, not a bypass of that check.

### 2026-09-20: immutable quorum selection before publication

Genesis issuance now selects and retains one archive record. A previously
stored selection is checked against the replay-authorized candidate's exact
proposal, roster, claim and catalog, and its QC is verified against independently
authenticated committee data. A later different valid signer subset cannot
replace that selection. With no retained record, quorum assembly/verification
precedes immutable publication and read-back. This is storage publication only,
not a live Authority decision or finality.

The archive provider now exposes structurally validated record reads and
recommits exact publish retries through insert_if_absent before read-back. This
completes durability after an ambiguous previous write rather than treating mere
visibility as success. The coordinator source test injects failures before and
after the first archive insertion, then changes the quorum subset and verifies
that an existing selection and bytes remain unchanged. Focused test evidence:
genesis-archive-selection.log under shared target/task-tmp/
committee-query-package.6w5tI7 (1 pass in2.91s). The initial archive regression
selection had12 passes/1 failure because an old assertion forbade a second
storage call on exact retry. It now requires that durability call and checks
unchanged bytes plus no insertion on conflict. Final archive selection passes
13/0 in1.16s (genesis-archive-regressions-final.log); git diff --check passes.
Live publication, finality, and the native controller remain open.

### 2026-09-20: endorse against the authenticated committee

The owner now composes recovered preparation with durable genesis issuance.
Its endorsement entry point obtains the committee through the installed
Authority's authenticated query/replay path; it does not accept an Authority
committee from the caller. The caller supplies a scoped signature store and
signer, while the existing issuance protocol checks exact voter membership,
pledges the complete claim/committee message, verifies the signature and retains
it before returning. It returns one endorsement, not publication or finality.

The source coordinator test rejects a foreign signer without invoking it or
writing a pledge, issues with the configured credential key, retries from the
retained signature, and checks exact candidate/committee/signature, one signing
call and no new system journal entry. It also assembles the one-voter fixture's
QC into archive data. The native_shared_ selection passes3/0 in15.58s
(authenticated-genesis-endorsement.log under shared target/task-tmp/
committee-query-package.6w5tI7); git diff --check passes. Native signer
and signature-file controller ownership, multisigner collection, durable archive
selection/publication and independently verified finality remain open.

### 2026-09-20: resume preparation through the owning recovery entry

The owner now resumes Shared pre-signing preparation directly through
NativeSharedGenesisRecovery: it uses the retained admitted runtime, intent,
issuer and committee query/reply stores without opening another lease set.
It replays authorization, reproduces the candidate, obtains the authenticated
committee through query/ACK recovery, and refreshes the exact pending admission.
The independently supplied replica committee still must match the signed
descriptor. No QC signature, publication, finality or generation is produced.

Admission is invalidated before any potentially persistent phase extension.
On failure the old snapshot cannot be contributed to bootstrap; callers must
reopen the still-leased stores. On success it contains both retained work items.
Initial focused selection passes3/0 in11.23s (shared-recovery-resume.log under
shared target/task-tmp/committee-query-package.6w5tI7). The source test resumes
after reattachment/ACK and checks exact candidate/committee, one total receipt
signature and no new journal entry. Final selection including corrupt-reply
failure and stale-admission refusal passes3/0 in12.35s
(shared-recovery-resume-final.log); git diff --check passes.
The method remains internal: full signing/publication/controller ownership and
the native clean_startup call site are not yet integrated.

### 2026-09-20: compose native discovery with leased Shared recovery

The committee-store factory now discovers both the dedicated Shared lifecycle
directory and committee directory before opening records. It rejects committee
locators without a matching lifecycle, opens existing intent/issuer leases,
opens the matching committee pair, and constructs NativeSharedGenesisRecovery
for each entry against the independently selected valid Authority. A crash before
query preparation may leave no committee directory; only that known lifecycle's
empty pair is created. The returned collection owns all four leases per entry.
The existing LocalLifecycleStoreFactory is reused only as a physical backend;
Shared recovery, not Local policy, validates the signed intent and runtime.

The focused native test passes1/0 in0.04s (native-recovery-discovery.log under
shared target/task-tmp/committee-query-package.6w5tI7), covering empty discovery,
orphan query refusal, invalid intent refusal, lease release on failure and data
preservation. This is negative composition coverage, not a positive native-file
end-to-end test. Selected store suite passes61/0 (1 ignored) in0.42s with the
HTTP loopback case excluded (native-recovery-discovery-suite.log).
git diff --check passes. The clean_startup
call site and owning Shared controller remain open; dropping this collection
after attachment would be incorrect, so startup is not prematurely enabled.

### 2026-09-20: Shared recovery retains the issuance store

NativeSharedGenesisRecovery now owns the issuer lease as well as intent/query/
reply stores. It opens the issuer against the exact descriptor authority, space
and agent, verifies any issued receipt against the signed Create, and checks
eligibility for an unissued initial Create. A committee query requires an issued
receipt; losing its issuer file cannot silently become a fresh issuer. Orphan
issuance without authorization and unsupported already-observed application
phases are refused. into_stores transfers all four leases to the eventual
controller. None of these structural checks replaces anchored Authority replay.

The focused source test checks that the genuine retained issuance reopens and
that missing/corrupt issuer state is refused once committee work exists. The
native_shared_ selection passes3/0 in10.45s (shared-issuer-recovery-final.log
under shared target/task-tmp/committee-query-package.6w5tI7); git diff --check
passes. Native scanner/controller composition is
still open; this closes the recovery ownership boundary, not Shared deployment.

### 2026-09-20: retain the Shared runtime before authorization

Shared proposal preparation now verifies the signed Create, retains the exact
admitted descriptor-bound runtime package, and reloads it before dispatching
Authority authorization. Previously it depended on the caller supplying that
package again. The leased Shared recovery type now re-admits the stored package,
checks its complete descriptor binding and exposes it to the eventual controller.
A persisted authorization without its runtime is refused; pristine signed intent
may still await package retention. Corrupt packages are never accepted as recovery
inputs. This is a clean-break requirement, not a fallback to a bundled runtime.

Initial native_shared_ selection passes3/0 in9.71s (shared-runtime-retention.log
under shared target/task-tmp/committee-query-package.6w5tI7). Final coverage also
checks exact retained bytes and missing/corrupt package refusal.
Final selection passes3/0 in10.17s (shared-runtime-retention-final.log).
Native runtime-file load now exact-recommits visible bytes to finish a possibly
ambiguous prior publication's durability barrier before recovery uses them.
This also protects callers whose retention helper sees an existing package and
does not write it again. Native store regressions pass60/0 (1 ignored) in0.43s,
with the HTTP loopback case excluded (runtime-resync-store-suite.log).
git diff --check passes.
Native startup
controller composition, leased issuer state and replica selection still need
integration; retaining the runtime does not make ordinary Shared Create complete.

### 2026-09-20: leased Shared-genesis recovery and bootstrap admission

NativeSharedGenesisRecovery now owns the intent/query/reply stores, validates
the signed Shared Create against the independently selected Authority and exact
locator, and assembles the retained authorization/query reservation. It rejects
orphan reply/query images, different locators and unsupported finalized/retired
phases. Existing replies are checked for canonical exact-query binding, never
treated as approval, execution or finality. Pristine signed Creates produce no
pending journal work until authorization has been retained.

NativeAuthorityOperationStartupAdmission can be created from or extended with
this recovery type. Its lifetime borrows the owning recovery stores, and it
checks Authority scope, aggregate pending bounds and duplicate invocations
against pending/retiring work. Existing bootstrap therefore has a typed route
to attach the full reservation alongside other management work. The coordinator
test now constructs this admission and reattaches its data before reproducing
the candidate; a foreign locator is refused.

Host-feature compilation passes (shared-recovery-check.log under shared
target/task-tmp/committee-query-package.6w5tI7). Focused native_shared_ selection
passes3/0 in10.08s (shared-recovery-admission.log); git diff --check passes.
Native clean_startup still does not discover and construct the
Shared recovery collection: intent/issuer/runtime ownership and the complete
Shared lifecycle controller must be composed there. This is not daemon restart
or full lifecycle qualification; signed request validation is not execution
authority. No merge or push was performed.

### 2026-09-20: bounded native committee-store discovery

CleanAgentGenesisCommitteeStoreFactory pins a dedicated private parent and
space. It scans through the opened directory descriptor, checks parent identity
before/after, accepts only canonical same-space locator directory names, refuses
zero agents/non-directories/symlinks/residue, sorts the bounded result and checks
duplicates. Discovery does not open/reconcile images or acquire their leases.
open_existing checks scope and parent identity and opens the joint query/reply
lease without creating a missing locator directory.

Focused discovery and pair tests pass4/0 (native-committee-discovery.log under
shared target/task-tmp/committee-query-package.6w5tI7). They cover scanning while
leases are held, deterministic ordering/bounds, noncreating open, competing-writer
refusal, wrong-space records and symlink rejection. The existing backend tests
still cover immutable data and staged publication. This factory is not yet
called by clean_startup: a Shared recovery/controller must own its leased set
and validate the linked Create/runtime/issuer data before constructing startup
admission. No unsigned filesystem data is promoted to authority by discovery.
Selected store regressions pass60/0 (1 ignored) in0.43s, excluding the HTTP
loopback case (native-discovery-store-suite.log). git diff --check passes.

### 2026-09-20: recover the complete Create/query reservation

Added a recovery-only query loader that does not require an already reproduced
opaque candidate. It bounds and decodes GCW1, checks the retained Create
invocation/route, system anchor lineage, query identity domain, exact public
preflight and Query method. It returns reservation data only: callers must keep
the store lease, reattach against independently opened journal history, then
reproduce the authorized candidate and run normal candidate-bound validation
before execution. This avoids requiring candidate production before the pending
reservation can be restored. It does not confer committee trust or finality.

The source coordinator test now detaches and reattaches the full Create/query
pending set both before query execution and after ACK. It reproduces the exact
candidate after each attachment and recovers the exact committee after ACK.
Initial reattachment test passes1/0 in9.22s (query-reattach.log under shared
target/task-tmp/committee-query-package.6w5tI7). The final recovery-loader test
also refuses a different runtime anchor or predecessor invocation; final selection
passes3/0 in9.89s (query-recovery-load-final.log in the same directory).
git diff --check passes. These tests retain the host and use memory protocol stores;
they are not process restart or native-file controller qualification. Native
directory discovery, leased startup-admission assembly and Shared controller
composition remain open.

### 2026-09-20: native committee-query and reply files

CleanAgentGenesisCommitteeFile::open_pair now opens bounded immutable query and
reply slots in a locator-derived directory under one shared exclusive lease.
Dropping only one handle does not permit another writer. CSF1 roles41/42 have
distinct filenames and domains, fixed entry allowlisting, existing atomic
staging/reconciliation and exact-recommit durability. Both roles reject changed
payloads and staged replacement of an existing image. The provider/coordinator
still authenticates record contents; filesystem integrity is not committee trust.

GCW1/GCR1 maximum image sizes are now shared public constants so native readers
and protocol decoders use the same bounds. Focused lease/immutability/oversize/
reopen/staged-publication tests pass2/0 in0.01s (native-committee-stores.log under
shared target/task-tmp/committee-query-package.6w5tI7). The selected clean-store
suite passes58/0 (1 ignored) in0.44s with the HTTP loopback case excluded; see
native-committee-store-suite.log.
git diff --check passes. No files were written to /tmp. These are physical
backend tests with opaque payloads, not coordinator+native-file crash tests.
The pair is not yet opened by a native Shared startup controller; complete
pending-set reattachment, composition with signing/publication and reservation
release remain open.

### 2026-09-20: committee-query ACK and replay-authenticated retry

The owner now acknowledges the query only after retaining its validated reply.
An opaque owner-created capability gates the network ACK path; exact ACK
identity, work/authorization commitments and positive retained outcome are
checked before success. Query mode is permitted for pending-result ACK, not
generic lifecycle retirement. Pending-capacity recovery recognizes a canonical
committee-query result from replayed history without treating it as finality or
proof that a reply file was durable.

Post-ACK query retry independently replays the pinned journal's exact Invoke/ACK
interval, then revalidates and retains its reply. It does not trust a saved
committee as authority or redispatch consumed work. The existing historical
denial-replay helper is reused only for its generic exact interval/replay checks;
the query caller performs its own committee-result validation.

Initial native_shared_ selection passes3/0 in6.17s (query-ack.log under shared
target/task-tmp/committee-query-package.6w5tI7). Final recovery checks also cover
pending-capacity reconstruction, missing-reply reconstruction from history and
refusal to overwrite a corrupt reply image; final selection passes3/0 in7.66s
(query-ack-recovery.log in the same directory). git diff --check passes.
The existing admin retained-dispatch recovery regression also passes1/0 in14.71s
(admin-recovery-regression.log), exercising the shared pending-result path.
This is source-runtime/memory-store coverage, not daemon restart or compiled
end-to-end qualification. Native query/reply backends, startup reattachment of
the full pending set, final publication/finality and reservation release remain
open. Earlier sections describe the then-current pre-ACK stages.

### 2026-09-20: authenticated committee-query dispatch and reply retention

The owner now dispatches the exact retained Query through persisted-management
admission, authenticating its route, pinned system generation and journal
anchor. The network and journal dispatch guards accept Query as well as Linear;
all preflight, reservation, material and anchored-history checks remain. The
result is validated and durably retained before return. A pre-existing reply
file is never used as an independent trust source: retries reauthenticate the
retained journal result. No ACK is issued yet, so post-ACK recovery and
retirement integration remain open.

The fresh-package source-runtime coordinator test checks that the selected
committee uses the configured credential signing key (not the transport key),
reply retention succeeds, and retry after clock advance returns the exact
committee without appending a journal entry. Initial dispatch selection passes
3/0 in4.52s (committee-query-package.6w5tI7/dispatch-final.log under shared
target/task-tmp). Final selection including reply-store failures before and
after write passes3/0 in5.14s (dispatch-retention.log in the same directory).
The test confirms failed retention leaves no positive ACK, later retention
recovers the exact result without another journal entry, and clock-advanced
retry leaves the reply image unchanged. git diff --check passes.
This remains native source execution with memory stores,
not compiled end-to-end or native daemon restart qualification.

### 2026-09-20: native committee-query preparation joins the Create reservation

The owner now prepares the exact genesis committee query from authenticated
physical Authority material, persists it as a successor of the existing Create
reservation, and checks its reserved material on reload. It does not derive a
new observation/preflight on retry. Pending-envelope and journal-interval
validation now accept ordered Query as well as Linear; dispatch and retirement
guards have not yet been extended. No query execution or finality is claimed.

The frozen bundled Authority lacks this query: its installed policy correctly
refuses preparation without writing a query image. A separate ignored test uses
AUTHORITY_CANDIDATE_PACKAGE, re-signs the complete package for the fixture, and
checks positive preparation and exact memory-store reopen after clock advance.
The candidate package was generated from the existing fresh Authority ELF
6828d1bbf54dc05e87aebbf72e6900d2f031ccf60b9c364029f9088dc4eae0a0
using the existing debug vosx actor build, with isolated task-local XDG config.
Its PVM ProgramId is
5040d84f292247e56b32b732d0b7ea17f7e83c879b5c98e98a0aa73cfc575625.
This is a test input, not a reproduced or repinned release package.

Evidence: shared target/task-tmp/committee-query-package.6w5tI7/package/
SystemAuthority.vos and preparation-final.log. The native_shared_ selection
including the candidate-package test passes3/0 in3.81s. This harness executes
Authority source, not the candidate PVM, and retains a shape-only destination
runtime. Full compiled lifecycle, native file storage, startup reconstruction
of the extended reservation, authenticated query dispatch, reply-before-ACK and
retirement remain open. Earlier preparation/diagnostic logs record the stale
policy and Linear-only reservation failures that led to these changes.

Broader native_management_ selection:1 pass/2 failures in3.12s. Both failures
return Unavailable at Local Create using the bundled outer runtime, after
authorization succeeds (management-regressions.log). A control run restoring
the two original Linear-only guards reproduces the same failures at the same
call in3.04s (management-linear-only-control.log); this isolates them from the
Query reservation widening, not a complete root-cause diagnosis. The Query
guards were restored afterward. Do not report this selection as passing.

### 2026-09-20: retained complete committee query work

RetainedCommitteeQuery now serializes the complete RuntimeWork and journal
anchor in bounded GCW1 data, bound to the replay-authorized genesis claim and
approval invocation. Its query invocation has a dedicated domain and cannot
reuse the authorization invocation identity. Pledge and reload check the exact
system genesis/admission, candidate, target route, Query method, direct empty
input state, canonical work encoding and matching preflight observation.
Recovery requires a fresh opaque candidate and independently selected target;
the anchor still must be reauthenticated against the live system journal.

Exact pledge/reload completes the durability barrier after ambiguous writes.
Tests cover failures before/after persistence, reopen of complete work, refusal
to overwrite it with a refreshed preflight, a different candidate's refusal and
trailing-byte corruption. These checks extend the existing source coordinator
test and use memory-store failure injection. Native query file storage, fresh
physical-material preparation, authenticated dispatch, reply-before-ACK and
retirement integration are still open. The record itself is not query execution
or finality evidence.
The final retained-work coordinator test passed1/0 in2.97s, recorded in
ordinary-archive-integration.v21i1n/committee-work-retention-final.log.

### 2026-09-20: committee reply retention before ACK

The genesis issuance module now has retain_committee_reply/load_committee_reply
for the reply-before-ack persistence boundary. They check the independently
selected Authority target, exact Query method, work/preflight binding, reply
invocation/actor/incarnation/deployment/mode/status, bounded canonical committee
bytes and matching space/authority binding. GCR1 stores work and authorization
commitments with the exact committee. Ambiguous writes reload/recommit; different
query/authorization bytes cannot replace a retained result. Read-back makes
exact result data available after ACK without redispatching a consumed query.

This stores reply data only, not a trust proof. The coordinator must still
persist the complete query work/anchor, authenticate dispatch against the pinned
system generation, retain this result before ACK, then recover and retire the
query. That live integration and a dedicated native reply backend remain open.
Tests use a synthetic reply only to exercise persistence validation, never as
production committee authority: pre/post-write failure and reopen, exact retry,
wrong-actor refusal, changed-preflight conflict and trailing-byte corruption.
The extended coordinator source test passes1/0 in2.84s
(ordinary-archive-integration.v21i1n/committee-reply-retention-final.log under
shared target/task-tmp); git diff --check passes. No live query lifecycle or
file-backed reply recovery qualification is claimed.

### 2026-09-20: publication fixture uses the actual enrolled owner

Removed the signed-publication fixture's workaround that rewrote the bootstrap
owner and enrollment signature to match the transport principal. It now uses
the ordinary configured enrolled owner and asserts that it differs from the
transport principal. The real Authority authorizes that Shared Create and
publishes/reopens/retries its signed provision in the fixture exercise. Export
passes1/0 in0.59s (distinct-owner-publication.8ouIQ1/export.log under shared
target/task-tmp). The compiled publication test now explicitly rejects old
fixtures whose owner and transport principal match, so its coverage cannot
silently fall back to the former workaround.

The new exported fixture still signs a synthetic post-state and uses a one-byte
runtime catalog; it is publication evidence, not a deployable runtime package
or independent finality proof. The compiled run uses the preserved query-capable
Authority ELF documented below. Host-authenticated committee consumption still
needs a retained query/ack lifecycle; no direct unjournaled query shortcut was
added to the coordinator.
Compiled publication/refusal/expired-retry passes1/0 in1.47s (compiled.log in
the new fixture directory), matching complete native inline state and emitting
no certificate-row writes. The native archive/provider integration also passes
1/0 in0.02s (native-archive.log), including staged recovery and exact provision
reproduction with the distinct owner. git diff --check passes.

### 2026-09-20: compiled Authority committee-query candidate

Fresh dirty-source Authority ELF built offline/locked with nightly-2026-03-20
in27.13s under shared target/task-tmp/authority-committee-query.InkXOo/target.
SHA-256:6828d1bbf54dc05e87aebbf72e6900d2f031ccf60b9c364029f9088dc4eae0a0.
This is an unsealed candidate, not a reproduced or pinned release package.

compiled_authority_genesis_committee_query_preserves_state links that ELF,
reads its actual schema, dispatches the generated Query method with persisted
certificate rows, and compares the canonical reply to a committee independently
constructed from configuration fields. Two queries must preserve every inline
lane and emit no row changes. The first host compilation attempted a private
actor conversion helper; it was replaced by explicit SDK field construction.
The query is exercised against the existing512-node fixture, separately from
the still-failing full-capacity valid enrollment gate. It passes1/0 in1.07s
(compiled-query-final.log). All5 compiled Authority tests pass together on the
small node fixture in2.00s (compiled-suite-small.log): loader/schema, committee
query, malformed-entrypoint refusal, signed publication/retry, and node
enrollment/removal/retry. Logs share the candidate directory above. git diff
--check passes. Host-authenticated committee consumption remains unimplemented;
these tests prove guest behavior, not native trust selection or startup finality.

### 2026-09-20: Authority genesis committee query

The installed Authority now exposes genesis_signing_committee as a read-only
query. Its bytes come from the same initial_committee helper used by genesis
publication verification, not from caller input or a guessed root/data-plane
committee. This matters because native configuration uses the bootstrap
credential key and enrolled node, while a bootstrap root signer may be distinct
(the existing source fixture deliberately uses a different root key/node).

The query checks configuration validity and returns the canonical exact
committee; invalid configuration returns no bytes. A native helper test checks
space/binding/epoch/member, credential key versus transport key, exact repeat and
unchanged Linear state. Macro-generated handlers are not callable as ordinary
Rust methods, so the test exercises the query helper, not guest dispatch.
Host integration still must authenticate the exact installed actor/query and
system generation before trusting its output. This does not switch startup to
a caller-supplied committee or establish current committee-history rotation.
The new method also requires rebuilt actor/package artifacts before deployment.
Final native Authority suite passes73/0 with2 fixture exporters ignored in31.13s
(authority-committee-query-suite-final.log under shared
target/task-tmp/ordinary-archive-integration.v21i1n). The first full run failed
only the old12-method schema count; the final schema test checks all13 methods,
including explicit Query mode and public authorization for the new method.
git diff --check passes. No new compiled query-dispatch evidence yet.

### 2026-09-20: verified quorum assembly into exact archive data

genesis_issuance::assemble accepts only the opaque coordinator candidate,
independently selected Authority committee and bounded signature replies. It
canonicalizes reply order without deduplicating, verifies quorum/membership and
every signature, then constructs evidence, decision, provision and the exact
catalog-bearing archive record. It does not grant publication or finality.
The coordinator must retain this selected record before publication and reload
it on retry: different valid signature subsets must not replace its exact QC.

The positive coordinator test now covers a three-voter committee: two votes
succeed, response order does not alter the record, and insufficient votes,
duplicates, forged signatures, foreign signers and wrong-epoch signatures are
refused. It publishes/reopens the record through the generic archived provider
and checks exact reproduction. A separate refusing finality verifier still
blocks promotion of this fully signed provision. This remains source-runtime
and memory-store integration, not production committee selection, native file
composition, live Authority publication or independently replay-backed finality.
The extended test passes1/0 in3.03s (genesis-quorum-archive-final.log under shared
target/task-tmp/ordinary-archive-integration.v21i1n). The preceding assembly-only
run passed1/0 in2.88s (genesis-quorum-assembly.log). git diff --check passes.

### 2026-09-20: native leased genesis signature storage

CleanAgentGenesisSignatureFile implements the existing issuer-store contract
over ExactFileStore with a dedicated role40 and164-byte payload ceiling shared
with the signing protocol. Its directory is derived from validated space/agent
and signer identity, with a fixed file/stage whitelist and exclusive lease.
Pledge-to-signature replacement uses the existing predecessor-bound atomic
publication/recovery mechanism; exact recommits retain file and directory sync.
No new filesystem writer or ambient path input was introduced.

Focused tests cover exclusive reopen, independent signer slots, bounded writes,
signature-image reopen, initial-stage recovery, matching-predecessor replacement
recovery and refusal of a stale predecessor. Payloads here are opaque fixture
bytes: signature verification belongs to the issuance layer. The production
coordinator does not yet compose this backend with issuance/startup, and native
file-backed signing fault injection remains required.
The two focused tests pass in0.01s (native-signature-store.log). The selected
native store suite passes56/0 with1 ignored in0.68s
(native-signature-store-suite.log), excluding the HTTP loopback retry case.
Logs are under shared target/task-tmp/ordinary-archive-integration.v21i1n;
git diff --check passes.

### 2026-09-20: retained per-signer genesis signature

clean_genesis_issuance.rs adds a crate-internal per-candidate/per-signer slot.
It requires the opaque replay-authorized candidate and an independently selected
Authority committee; only a voter key in that committee may sign. The fixed100-byte
GSI1 pledge binds authorization invocation, signer key and full QC signing message
(committee epoch/commitment and genesis claim). It is durably committed and
reloaded before the signer callback. The verified signature extends the record
to164 bytes, committed/reloaded before return. Every attempt reloads and exact
retained signatures avoid signing again. Existing pledge/signature images are
recommitted before use to finish durability after a prior ambiguous write.

The coordinator's positive test exercises this slot with an explicit test
committee: failures before/after pledge and signature commits, store reopen,
identical-message resubmission only when signature retention failed, exact retry
without signing, authorization conflict, corrupt retained signature, invalid
signer output and an untrusted key. A returned signature forms a verifiable QC
with the test's one-voter committee. The slot itself returns only one signature,
not a QC, provision or finality; it is not restricted to one-voter committees.

This is generic store/source-runtime evidence. Native leased signature storage,
production committee-history selection, signer integration, quorum assembly,
archive/publication and finality wiring remain open. No filesystem crash or
production release qualification is implied.
The extended test passes1/0 in2.70s (genesis-signature-crash-final.log under shared
target/task-tmp/ordinary-archive-integration.v21i1n); git diff --check passes.

### 2026-09-20: opaque coordinator authorization for genesis issuance

The coordinator now returns AuthorizedSharedGenesisProposal, not a raw tuple.
Its private fields retain the execution-derived proposal/catalog, exact replica
committee, authorization invocation and AgentGenesisClaim. The claim's system
agent comes from independent owner pins; its genesis/admission come from the
retained authorization anchor already reauthenticated by the issuance path.
There is no public constructor or wire decoder. A future durable genesis signer
must require this capability and retain its exact claim before signing; decoding
an archive or a caller-selected proposal cannot mint the capability.

The positive retry test now also checks all lineage selectors, catalog/claim
consistency and a changed system genesis producing a different signing claim.
Durable genesis signing itself is still not implemented, nor publication or
finality. This type is an authorization boundary, not a finality proof.
The extended source-runtime test passes1/0 in2.75s
(ordinary-archive-integration.v21i1n/authorized-proposal-lineage.log under shared
target/task-tmp); git diff --check passes. No compiled end-to-end or crash-signing
qualification was added by this check.

### 2026-09-20: positive authenticated Shared proposal retry

native_shared_proposal_reuses_durable_authorization_and_receipt passes1/0
in2.56s (coordinator-positive-retry.log). The test uses the installed real
Authority source implementation through the native test executor, a retained
signed ordinary Shared Create, an enrolled logical owner distinct from its
transport key, and the new coordinator preparation method. After the first
approval/receipt/proposal, it drops and reopens both intent and issuer over
retained memory-store images and advances the logical clock. The repeated
proposal/catalog are identical; signing count stays1, the system journal does
not advance, both store images are unchanged, and no destination generation
is provisioned. This verifies coordinator replay and receipt reuse, not merely
the standalone host proposal builder.

This is source-runtime evidence with durable-image reload semantics, not a
compiled Authority/runtime end-to-end run, file crash test, full daemon restart,
genesis QC issuance, live publication or finality qualification. Those remain
open. The installed-policy refusal regression also passes1/0 in1.74s
(coordinator-policy-after-owner-fix.log); git diff --check passes.
Log location: shared target/task-tmp/ordinary-archive-integration.v21i1n.

### 2026-09-20: logical owner and transport identity separation

Inspection for positive coordinator coverage exposed a pre-existing contradiction:
Authority enrollment assigns replicas to the enrolled owner, while
AgentReplicaMember required that owner to be the transport key's principal.
The member now accepts a nonzero logical owner independently of that key.
Canonical peer/key agreement, peer-derived node identity, roster ordering,
duplicate transport/slot rejection, exact descriptor roster matching and the
authority-certified committee commitment remain required. Construction alone
does not authenticate an owner mapping; Authority approval and finality remain
separate mandatory boundaries.

The new genesis test roundtrips a distinct-owner committee and proves it changes
the committee ID and cannot reuse the original signed provision/claim. All15
genesis tests pass (replica-owner-genesis.log,0.09s). The multi-replica proposal
fixture now explicitly uses one logical owner distinct from all four transport
keys, for both native and compiled guest checks. The selected Shared suites
pass59/0 with2 ignored in4.07s (distinct-owner-shared.log), excluding the capacity
and loopback-convergence cases. The compiled runtime candidate passes1/0 in2.20s
(compiled-distinct-owner.log), using the preserved ELF identified below, not a
new runtime release. no-default-features compilation passes in4.68s
(distinct-owner-no-default.log); git diff --check passes.
No live coordinator/restart or full enrollment-to-finality
qualification is implied. Logs are in ordinary-archive-integration.v21i1n.

### 2026-09-20: authenticated coordinator proposal preparation

CleanSystemAgentBootstrapOwner::prepare_shared_from_management_intent connects
the retained clean Create to the existing authenticated management-issuance
path and then host proposal execution. Before issuing, it checks Shared profile,
space/agent, complete descriptor/committee roster, local membership and admitted
runtime binding. The existing issuance path still dispatches the installed
Authority, checks the exact durable reply, and retains the signed receipt.
Proposal observation is max(persisted authorization observation, receipt
valid_from), so retry does not sample a new clock. No extra persistence format
or finality shortcut was introduced.

This is a crate-internal coordinator step, not a completed public Shared-create
workflow. It has no native startup caller yet. Positive end-to-end Shared
authorization/restart coverage, genesis QC issuance, immutable archive
publication, live Authority publication and independently trusted finality
remain required. cargo check --offline --locked -p vos --features agent-runtime
passes with nightly-2025-05-09 (coordinator-proposal-check-final.log,11.38s).
The installed-policy boundary regression passes1/0 in1.66s
(coordinator-policy-boundary.log). It now also checks that this preparation
entrypoint rejects a non-Create retained intent without signing, changing the
issuer/intent images or advancing the system journal. It is negative coverage,
not the still-missing positive Shared coordinator lifecycle. git diff --check
passes.
Logs remain under shared target/task-tmp/ordinary-archive-integration.v21i1n.

### 2026-09-20: multi-replica proposal execution

The clean proposal fixture now supports a sorted roster with independently
matched signing keys. A new test executes preparation separately on three voters
and one observer, comparing every complete proposal and catalog to the same
source-executed Create fixture. Removing the selected node from the proposed
committee is refused; no host generation is written. The native test passes1/0
in0.11s (multi-replica-proposal.log). The existing ignored compiled candidate
test now also runs this four-member case without either native-runtime oracle,
as well as the original single-member case:1/0 in2.10s
(compiled-multi-replica-proposal.log). This uses the preserved runtime ELF named
below, not newly sealed release artifacts. The selected host suite passes20/0
with1 ignored in3.55s (multi-replica-shared-suite.log); capacity and live loopback
tests remain excluded from this selection. All logs are under shared
target/task-tmp/ordinary-archive-integration.v21i1n. git diff --check passes.

This closes the positive multi-replica preparation coverage gap noted below,
not live multi-node issuance, committee authorization, transport/principal
separation, startup finality or release qualification.

### 2026-09-20: clean SDK receipt-to-proposal preparation

SharedAgentHost::prepare_clean_genesis_proposal now constructs the exact replay
input/catalog from an admitted runtime, clean descriptor, signed management
receipt and retained observed slot, then executes the existing proposal path.
The shared input builder checks package identity/contract/capabilities, local
replica membership, clock bounds and the receipt. The system-root wrapper keeps
its separate single-local-voter restriction. This avoids using root bootstrap
as an ordinary multi-replica creation path.

The native test checks exact retry across clock advancement, future-slot
refusal, substituted package/descriptor and forged receipt refusal, no written
generation, and rejection of the multi-replica descriptor by system bootstrap.
The compiled candidate test also compares the clean API's complete proposal
and catalog with the raw replay path and source-derived fixture. Both positive
paths currently use a single-replica fixture; positive multi-replica execution
through this new convenience API still needs coverage. Final selected Shared
host tests pass19/0 with1 ignored in3.44s (clean-host-proposal-suite-final.log).
The compiled candidate passes1/0 in1.56s (compiled-clean-host-proposal.log), using
the same preserved ELF documented below, not a rebuilt release. Logs are in
ordinary-archive-integration.v21i1n under shared target/task-tmp. The first suite
run failed a test-only assumption that the fixture already had multiple replicas;
the corrected test constructs the additional replica explicitly. No signing
coordinator, durable retained
proposal slot, Authority publication or independent finality is implied.

### 2026-09-20: host proposal boundary and compiled preparation

SharedAgentHost::prepare_genesis_proposal now exposes runtime-derived ordinary
Shared proposal preparation to native coordinators. It validates the live host
lease before and after execution, checks committee space and local membership,
and uses the host's configured trust and merge identity. It writes no generation
and returns a proposal, not a seal or trusted finality. The issuer must still
independently authorize the proposed committee. Provisioning still verifies
finality before writing an intent; no startup verifier was replaced.

The preceding internal preparation test passed against the preserved runtime
ELF in row-resource-runtime.5B1apX (SHA-256
b5913b0b2a552f92edfe36dd2ef35db5e50147c03d35c029beee005cdcd66a8a):
compiled-proposal.log,1 passed in1.37s. It packages the linked guest and uses
CleanTrust without either native-runtime oracle, comparing the full proposal
to independently source-executed Create. This is preserved candidate evidence,
not a fresh build or a release qualification. The test now exercises the host
API instead; compiled-host-proposal.log passes1/0 in1.37s. The host regression
checks exact retry, foreign-space refusal, missing-catalog refusal and denied
finality with no generation written (host-proposal-checked.log,1/0 in0.05s).
The selected Shared-host suite passes18/0 with1 ignored in3.33s
(host-proposal-shared-suite.log), excluding the previously exercised4095-entry
capacity and live loopback-convergence tests. This is not a full Shared-suite
or release-gate run. git diff --check also passes.
Logs are under shared target/task-tmp/ordinary-archive-integration.v21i1n.

Coordinator signing, archive/startup composition, live Authority publication
and independent trusted finality remain unimplemented integration work.

### 2026-09-20: native pre-certification Shared preparation

LocalJournalAgentDriver::prepare_shared_genesis_candidate now executes the
ordinary Shared Create with the native replay executor before certification.
It checks the configured merge node, complete selected replica identity,
validated committee and exact descriptor roster, then runtime execution and
exact catalog preimages. Its return type is opaque ReplayPreparedGenesis, not
a journal seal. The existing finalized-provision path reuses this preparation
and still requires VerifiedAgentGenesisProvision for seal construction.

shared_genesis_candidate_derives_proposal_without_provisioning exercises the
new path, checks its proposal against the fixture, rejects substituted replica
principal and missing/corrupt catalog, and confirms the host has no provisioned
generation. This uses the source-runtime test executor; it is not new physical
guest or live Shared issuance qualification.
Final Shared regression selection passes56/0 with1 ignored in5.26s:
ordinary-archive-integration.v21i1n/native-candidate-shared-final.log. Selection
excludes the previously exercised4095-entry capacity and loopback convergence
tests; it is not a new full Shared-suite run. The earlier pre-new-test selection
passed55/0 with1 ignored (native-candidate-shared.log).

The production coordinator still needs to consume this candidate through an
authenticated approval, trusted committee signing, durable archive publication,
live Authority decision publication and independent finality. Startup remains
fail-closed for ordinary Shared genesis.

### 2026-09-20: replay-derived ordinary genesis proposal

ReplayPreparedGenesis::ordinary_proposal derives the complete ordinary proposal
from opaque prepared Create output: exact request, runtime identity, post-state
commitment, sequence and catalog. It accepts no caller-selected expectations.
Shared seal verification now compares that complete derived proposal with the
finality-verified provision, retaining the subsequent actual state/artifact and
committee checks. Shared replay fixtures use the same conversion rather than
manually assembling expectations. This is proposal construction only: it neither
signs, publishes, verifies finality nor grants root provenance.

New regression checks the exact request/locator/catalog and recomputes state/
artifact commitments, canonical roundtrip and repeat construction without another
execution. Full replay suite passes56/0 in2.51s; no-default-features Authority
compilation passes19.67s. Evidence: ordinary-archive-integration.v21i1n/
replayed-proposal-final.log and replayed-proposal-no-default.log. The initial
replayed-proposal.log records two stale expectations-only method references,
fixed before the final successful run.

Native signing remains gated on the authenticated runtime approval path:
issue_management_intent_with_admission checks persisted work/material identity
and exact completed reply before the crate-private approval-to-issuer boundary.
The ordinary-genesis coordinator still needs to prepare the runtime proposal,
bind it to that approval and trusted committee, and drive signing/archive/
Authority publication/finality; no signer shortcut was introduced.

### 2026-09-20: signed-fixture native archive/provider composition

The Authority publication exporter now writes runtime-catalog and asserts its
BlobRef equals the proposal's sole catalog reference. The new ignored CLI test
ordinary_genesis_provider_persists_signed_fixture_and_recovers_stage consumes
that fixture and composes ArchivedAgentGenesisProvider with the real leased
CleanAgentGenesisArchiveFile. It covers normal publication and initial staged
publication, drop/reopen, byte-exact provision reproduction, exact publish/create
retry, catalog lookup, malformed catalog refusal without record changes, and
a second reopen. This closes the prior opaque-payload-only integration gap.

Evidence: shared target/task-tmp/ordinary-archive-integration.v21i1n.
export-final.log:1 signed fixture export passed0.62s; integration.log:1 native
composition test passed0.02s. export.log records an initial test-only assertion
inserted in the wrong exporter, corrected before successful fixture creation.
Use AUTHORITY_PUBLICATION_FIXTURE pointing to this directory's fixture child
when rerunning the explicitly ignored integration test.

The fixture has real signatures but a synthetic post-state claim and a one-byte
runtime preimage. It is not runtime-package admission, independent live finality,
or a production Shared creation test. The archive/provider/backend are composed
in this test, not yet in native startup or the production issuance coordinator.

### 2026-09-20: leased native ordinary genesis archive backend

CleanAgentGenesisArchiveFile implements AgentGenesisArchiveStore using the
existing StoreRoot/ExactFileStore machinery. One validated locator derives one
private directory under an explicitly configured canonical parent; the backend
retains its exclusive writer lease. New role39 has its own fixed canonical/stage
names and per-record size bound. Loads refuse another locator and re-establish
file/directory durability before returning existing bytes. Insert-if-absent
keeps the first winner under the mutex/lease; provider reload determines exact
retry versus conflict. Initial staged publication can complete after reopen;
predecessor-bearing replacement stages are forbidden for this immutable role.

Focused native tests cover lease exclusion, exact bytes after reopen, immutable
conflicting insertion, wrong-locator rejection, initial-stage recovery,
replacement-stage refusal and concurrent insertions preserving one winner.
All3 pass in0.01s (authority-entry-preflight.Z6rTVF/native-genesis-archive.log).
The complete clean-store suite passes55/0 in the permitted-loopback rerun
(native-clean-store-loopback.log). The sandboxed run passed54 and failed only
credential_discovery_reuses_published_query_across_http_retries at listener
creation with PermissionDenied (native-clean-store-suite.log).

These tests use opaque backend payloads; the separate provider/codec tests
validate actual provisions. Native coordinator/provider composition with real
provisions, signing, live Authority publication and finality remain unwired.
This backend must not be described as enabling ordinary Shared creation yet.

### 2026-09-20: immutable ordinary genesis archive provider

agent/genesis_archive.rs adds AgentGenesisArchiveStore and
ArchivedAgentGenesisProvider. The store contract requires bounded loads,
atomic insert-if-absent, durable success, and no overwrites. The provider binds
one space, validates each loaded record against the requested locator, reloads
after insertion, distinguishes absence/corruption/conflict, and never caches
an ambiguous result. publish accepts a structurally valid externally issued
record; create reproduces only an already stored exact proposal/catalog and
returns NotConfigured when absent. This is archive access, not native issuance
or finality, and it is not wired into startup yet.

The generic regression uses a simulated atomic store: durable-then-error
publication, reconstruction with the same store, exact retry without another
write, exact catalog lookup, alternate evidence conflict under the same locator,
wrong-space refusal, substituted-locator and trailing-byte corruption. Current
genesis suite passes14/0 in0.09s (authority-entry-preflight.Z6rTVF/
genesis-archive-provider.log). Filesystem crash/durability, racing insertions,
native signer/coordinator integration and independent finality remain open.
Next integration step is a leased bounded native per-locator store implementing
this contract; no in-memory test result proves its disk durability.

### 2026-09-20: ordinary genesis archive persistence unit

AgentGenesisArchiveRecord in agent/genesis.rs adds a bounded canonical OGAR
record containing one complete ordinary provision and its exact runtime catalog
preimage. It checks provision/certificate shape and exact catalog count/reference/
bytes, with complete-record and nested-payload bounds before copying runtime
bytes. The bound is per locator, not a whole-registry allowance. The type has
no finality capability and cannot bypass VerifiedAgentGenesisProvision.

The regression covers exact encode/decode, missing/duplicate/substituted catalog,
wire/provision/reference/payload corruption, oversized declared length,
truncation/trailing bytes, and independent NotFinalized rejection after decode.
The initially selected AGAR tag collided with AgentAuthorityReceipt during
review; final source uses OGAR. Final genesis suite:13 passed,0 failed in0.13s
(authority-entry-preflight.Z6rTVF/genesis-archive-codec-final.log). Existing
management issuer suite:12 passed in2.63s (issuer-suite.log).

This is the archive codec, not a production provider. Still required: durable
per-locator storage under an exclusive owner, atomic exact/conflicting retry
handling and crash recovery, native signed issuance, publication through the
live Authority, independent replay-backed finality, and startup/provider wiring.
CleanSystemAgentGenesisArchive implements only SystemAgentGenesisProvider;
CleanManagementIssuer issues management receipts, not ordinary genesis.
UnavailableAgentFinality is unchanged. The prior fresh-target ELF reproduction
predates this unused archive API addition and is not a new current-source pin.

### 2026-09-20: Authority candidate fresh-target reproduction

Rebuilt current Authority source with nightly-2026-03-20, cargo actor
--offline --locked, CARGO_BUILD_JOBS=2, and a new independent target directory:
shared target/task-tmp/authority-reproduce.ukq1cN/target. build.log succeeds
in30.64s. The resulting target/riscv64em-vos/release/system_authority.elf is
byte-identical (cmp) to authority-entry-preflight.Z6rTVF's tested candidate;
SHA25675f2f8fd0783542924cfbe4b04c65dcbaf07cf4f4ae01ff892d139358190949d.
This is fresh-output reproducibility from the same dirty worktree/toolchain,
not an immutable-source export, independent-machine build, package provenance
seal or release repin. The candidate's existing compiled checks apply to the
identical ELF bytes; remaining capacity/finality/release gates are unchanged.

The Agent release reproduction script now passes --locked to its host-builder
and runtime-guest Cargo invocations, so lockfile drift cannot be silently
resolved during those stages. bash -n and git diff --check pass. The entire
immutable-source release reproduction recipe was not rerun by this check;
the system-template build subcommand retains its own dependency/build handling.

### 2026-09-20: Shared no-op history reconstruction

The original Shared campaign completed:55 passed,1 failed,1 ignored in252.31s.
The4095-entry system_attach_checkpoints_and_drains_raw_tail_before_publishing_route
test passed. The sole failure is the loopback-listener restriction already
isolated below; its permitted-network rerun passed. Session28810 is terminal.

Source inspection identifies repeated work in SharedJournalAgentDriver::apply_next:
every leader no-op called committee_history, which performs a full recovery
audit then scans the retained suffix again to reconstruct committee history.
The4095-entry fixture therefore repeatedly visits a growing suffix. This is a
separate source-level performance finding from the Authority certificate scan;
it is not a measured explanation of all live Create/Install latency.

For leader no-ops only, retain audit_recovery but omit the redundant history
reconstruction and executor replacement. transition_state rejects a pending
committee transition and returns unchanged committee state for a no-op.
Configuration and PrepareCommitteeChange paths still refresh full history.
No audit, signature validation, work limit or recovery guard is removed.
The full suffix audit remains potentially quadratic over a sequence of no-ops.

Added leader_noop_still_rejects_missing_earlier_physical_history at the host
boundary: apply two valid no-ops, remove the first physical Raft row, then append
and apply the third. The retained recovery audit must reject the missing earlier
evidence; logical journal position remains unchanged. Initial focused check
passes1/0 in0.37s (noop-corruption.log); the assertion is tightened to require
CorruptResidue specifically; that focused check also passes1/0 in0.43s
(noop-corruption-exact.log).
This does not assert physical-slot rollback: apply_foundation_slot precedes the
recovery audit, as it did before the optimization.

Current-source Shared regressions excluding the long capacity test and loopback
test:54 passed,0 failed,1 ignored in5.03s (shared-noop-regressions.log in the
same authority-entry-preflight.Z6rTVF evidence directory). The exact capacity
test now passes against the changed binary (session75079 exit0):1 passed,0 failed
in219.03s (shared-noop-capacity.log). This is still slow. The prior252.31s result
was a broader concurrent suite, and compilation overlapped this exact run;
these are not controlled before/after timings or a production speedup claim.

### 2026-09-20: broader replay and Shared verification

Current-source replay module:55 passed,0 failed,0 ignored in1.75s, including
the row-binding and checkpoint-provenance regressions. Authority
--no-default-features check passes2.50s. Logs are in shared target/task-tmp/
authority-entry-preflight.Z6rTVF/replay-suite.log and authority-no-default.log.

The57-test agent::shared_ campaign initially remained running (session28810;
now completed as recorded above); system_attach_checkpoints_and_drains_raw_tail_before_publishing_route
exercises4095 durable post-snapshot entries. Do not restart merely because it
exceeds60 seconds. shared-suite.log is not a completed green gate.
The merge convergence test reported failure in the restricted network sandbox.
An exact diagnostic rerun (merge-failure-detail.log) locates the failure at the
five-second localhost-listener assertion, before convergence. With loopback
networking permitted, the same built test passes1/0 in1.31s (merge-loopback.log).
No production code or timeout was changed for this environment-specific failure.

### 2026-09-20: Authority entrypoint rejection preflight

Extended the safe Admin ordering to management authorization, management
finalization, operation issuance ACK, and Private application/retirement ACK:
decode/context/target/signature checks precede full state auditing. All valid
requests still undergo the same audit before retry lookup or mutation.
Operation authorization moves only decode/context/target checks ahead of the
audit; state-dependent SSH attester authentication remains after it. Query and
publication paths are unchanged. No resource limits or validations were removed.

Added compiled_authority_malformed_entrypoints_preserve_rows. It exercises
authorize, authorize_operation, administer, finalize, acknowledge_issuance and
resolve_private_application with empty malformed payloads against actual schema
and persisted node rows. It requires Done/refusal, exact full inline state and
zero row exports. This tests malformed requests, not every signed ACK corruption
shape; native signed-protocol regressions remain part of the suite.

Evidence: shared target/task-tmp/authority-entry-preflight.Z6rTVF.
build.log: guest succeeds48.73s; target/riscv64em-vos/release/system_authority.elf
SHA25675f2f8fd0783542924cfbe4b04c65dcbaf07cf4f4ae01ff892d139358190949d.
native.log:72 passed,0 failed,2 exporters ignored in38.21s.
physical-before-fixed.log: previous mFUWVa artifact fails malformed authorize
with OutOfGas at512 nodes. physical-full-refusals-final.log: new artifact passes
all six refusals at512 nodes (1 test,1.46s). physical-small.log: all4 compiled
Authority tests pass1.98s, using node-capacity.ePpKOw/small and the unchanged
boxed-seed publication fixture. Earlier physical-before.log records a missing
test Encode import; physical-full-refusals.log records a fixture mismatch between
absent and explicit empty lanes, corrected by supplying explicit empty lanes
and retaining exact state equality. These are not remaining runtime failures.

Valid full-capacity enrollment still requires a bounded-validation solution;
this rejection-only improvement does not qualify production latency, release
pins, all capacities or trusted-root finality. Candidate remains unsealed.

### 2026-09-20: bounded-validation trust-boundary investigation

Follow-up: ReverifiedRootJournalStore supplies process-local root identity,
not identity reconstructed from disk. materialize_current_reverified rejects
its absence before executor setup and matches genesis/admission to heads.
LocalJournalAgentDriver's root create/open paths use it and validate route
ownership. This root-runtime path is not automatically proof for the clean
Authority actor: materialized_system_authority_view still extracts the runtime
system_authority projection; clean startup separately constructs its system
archive and still installs UnavailableAgentFinality for ordinary genesis.

Extended ordinary_local_checkpoint_cannot_acquire_root_authority_provenance
to publish a real Local checkpoint, refuse root materialization with zero
executor calls, and then successfully reopen unchanged through ordinary replay.
Focused test passes1/0 in0.03s: authority-preflight.mFUWVa/
checkpoint-provenance-local.log. The earlier checkpoint-provenance.log records
an abandoned test extension using the Shared root fixture with ordinary
prepare_checkpoint; its InvalidRecord is the correct profile rejection, not
a production defect. The original root-clone test is unchanged.

Do not treat Authority's state_integrity_commitment as an authentication token.
computed_state_integrity_commitment clones the header, zeros that field and
hashes its encoding with configuration/ABI: it binds content but has no secret
or signature. NodeTable::get additionally binds each retrieved certificate to
its header digest. Neither alone establishes who authorized a restored header.

The outer replay path provides distinct checks: replay_state_commitment hashes
all four complete lane byte strings with lane-specific domains;
load_checkpoint_base checks lane BlobRef contents against manifests;
validate_published_shared_checkpoint matches manifests to the snapshot claim.
SharedJournalDriver's snapshot installation separately calls certificate.verify
against the ledger-derived committee and exact expected claim.
SharedAgentSnapshotCertificate::verify enforces matching committee, voter
quorum and signatures. journal_audit invokes audit_recovery on reopening.
These are concrete call-path findings, not yet an end-to-end proof for every
Authority restore/invocation path, Local profile or trusted-root bootstrapping.

Added replay_state_commitment_binds_row_images_and_lane_identity: ALI1 inline,
row-key, row-value and deletion changes must alter each lane's commitment;
moving identical bytes between lanes must also alter the commitment. This
regression proves content binding, not authentication. Full Authority auditing
remains enabled. Focused test passes (1 passed,0 failed); log:
shared target/task-tmp/authority-preflight.mFUWVa/replay-row-binding.log.
Before replacing it, trace all entry/restore paths from trusted
genesis/checkpoint to exact guest state and add negative reconstruction tests
there; preserve enrollment verification and exact touched-row checks.

### 2026-09-20: full-capacity guest gate and Admin signature preflight

The node mutation exporter now accepts AUTHORITY_NODE_INITIAL_COUNT (default1)
and exports initial-rows alongside the inline state. The compiled lifecycle
test restores this initial image; old exports without initial-rows must be
regenerated. The new native capacity test starts with512 verified nodes,
enrolls the513th, removes it and checks exact retries and refusal images.

Evidence: shared target/task-tmp/authority-node-capacity.ePpKOw contains full
and small fixture exports. Full native export passes in14.99s; initial/enrolled
inline states are34558/36622 bytes. Against the previous boxed-seed ELF,
physical-full.log fails on the first forged-signature phase: the complete
certificate audit exhausts the20-read quota before signature refusal.

Admin now decodes and checks the call, invocation context, target and signature
before the full state audit. Valid calls still undergo that audit before retry
lookup or mutation. This is a rejection-path fix, not bounded valid-call
validation, and changes neither security checks nor resource ceilings.

Fresh evidence: shared target/task-tmp/authority-preflight.mFUWVa.
build.log: guest release build succeeds in45.60s. ELF at
target/riscv64em-vos/release/system_authority.elf has SHA256
35e0604184e0289eb49a3f0d30b33e4e2c87dc7f286a7a28b67f14059344ef55.
native.log:72 passed,0 failed,2 exporters ignored in37.46s.
physical-small.log: all3 compiled Authority regressions pass in1.76s;
linked program1081398 bytes. Uses the new small node fixture and the previous
boxed-seed publication-fixture (publication layout is unchanged).
physical-full.log: capacity test remains FAILED in0.98s. Phase0 now returns
Done with989142691 gas remaining and no row exports; phase1 valid enrollment
returns OutOfGas with no row exports, diagnostic total=20 amount=1 maximum=20.
Thus the inline-size reduction is proven, but valid full-table guest work is
not qualified. Do not increase quotas or bypass whole-state validation merely
to turn this test green: bounded validation needs an established authenticated
state boundary. This candidate is not sealed, repinned or release-qualified.

### 2026-09-20: compiled Authority enrollment/removal and exact row replay

The new signed native fixture starts with the pending bootstrap seed, refuses
a forged Admin signature without materializing rows, enrolls a second node,
restores the complete header/row state, repeats enrollment exactly, refuses the
forged call again, removes the second node and repeats removal after restore.
The bootstrap certificate remains available after removal. Native fixture
capture commits the mock overlay with each state checkpoint.

The compiled test decodes the candidate ELF's actual schema, runs administer
through the inner storage view, atomically applies each exported delta and
roundtrips its ALI1 image before the next phase. Every complete row image and
reply matches the native fixture. Enrollment must export rows; removal must
include a tombstone; retries/refusals must export no rows. This is real guest
node mutation, not only host handlers or read-only publication.

Evidence: shared target/task-tmp/authority-node-mutations.7sDMWE.
export.log:1 explicit fixture export passed. physical.log:1 six-phase physical
test passed in1.80s against the unchanged authority-boxed-seed.Iaq81H ELF
(SHA25611d26565078bbfeb64903172c3197d2e75885721e8ea0c6f54a1f1cf8bdb4237).
Rows exported by phase:0/4/0/0/3/0. Gas remaining:
983109123/946011142/955690113/965600401/939355623/962517166.
The initial compile.log records a fixture-reader closure lifetime error; an
explicit &str argument fixes it without changing runtime behavior.
Final native.log:71 passed,0 failed,2 explicit fixture exporters ignored,35.55s.
physical-all.log: all3 compiled Authority regressions pass in3.23s against the
same candidate: schema/loader, row-backed publication and node mutations.

These phases qualify the exercised two-node lifecycle, not full-table guest
work, all rejection/capacity shapes, trusted-root finality, daemon crash recovery,
or release artifact provenance. Full certificate audits still scan the table;
bounded validation and the remaining complete-saga requirements stay open.

### 2026-09-20: production Authority node-table cutover, generation20

AuthorityLinearState.nodes is now NodeTable, not Vec<NodeOwnerRow>. Enrollment
and removal update its compact header and declared certificate rows inside
the existing Authority refusal transaction. The bootstrap seed is materialized
only on a node-table mutation. Owner projections use header indices; certificate
consumers verify the exact stored row against its header digest. The enclosing
state integrity commitment now binds that header. Generation20 distinguishes
the new archived layout from the preceding generation19 schema-only candidate.

Full certificate, role, signature and state validation is deliberately retained,
streaming certificates rather than allocating another complete vector. This
does not yet meet bounded guest work for a full table. No signature check or
work ceiling was weakened. Other Authority collections remain inline.

Native corruption tests now tamper persisted certificate rows inside a refused
transaction and require full Authority validation to reject each alteration.
The alternate PAR1/PCA2 history fixture initially failed because it rewound only
inline state after another history removed a node. It now captures/commits the
row snapshot with that header and restores both for the alternate branch.
Fresh native actor fixtures reset their own thread-local mock storage; ordinary
generated restores do not reset or repair rows. Over-capacity reconstructed
headers remain explicitly rejected.

Evidence: shared target/task-tmp/authority-node-cutover.e9wq0k:
native.log:70 passed,0 failed,1 ignored,34.55s. The full256-replica enrollment
fixture now measures18206 Linear bytes versus the previous76494, below49152.
This is the exercised header shape, not every complete Authority capacity.
build.log: fresh locked offline RISC-V build succeeds in41.13s.
ELF target/riscv64em-vos/release/system_authority.elf SHA256:
a03d618ae0b16c7010e687b9b38b35e47f32365e51d5ad55aa213400e4f1b1ed.
export.log:1 signed publication fixture pass,0 failures. The fixture now
materializes two verified node certificates before publication and exports
their persisted row image. Physical execution must consume that image through
schema-derived storage access and must not rewrite certificates during publication.
Earlier compile and PAR1 fixture failures are retained under
authority-node-schema.U7uylW/node-cutover-*.log, not counted as final gates.

The initial physical.log passes schema/loader admission (1079899 PVM bytes)
and missing-blob refusal, but faults during publication with persisted rows.
diagnostic.log records Fault(0xfefcf000), not a policy refusal; native output
is green. Storage backend reads still reserved an8192-byte stack probe inside
the nested validation call chain. The source now allocates that same bounded
probe on the heap, with unchanged host calls, copy charges, row/stack/heap/gas
ceilings and complete validation. A separate fresh candidate is retained under
authority-row-probe.5MrIn6; the initial guest is not counted as an execution pass.
That probe-only candidate still faults at the identical address/register state;
physical.log is1 pass/1 failure and is not a fix qualification. Opt-in native
inner-machine diagnostics now expose the failing PC and can export the exact
observed program without overwriting an existing file. pc-diagnostic.log plus
pc-map.log verify byte-exact program identity and map PC273120 to RISC-V
0x94d140, a stack store in blake2b_simd::portable::compress1_loop. The failure
is accumulated stack depth, not a missing/corrupt certificate or relaxed gas gate.

NodeTable's pending seed is now Option<Box<NodeOwnerRow>>, retaining its exact
archived contents while avoiding a complete certificate embedded in every
cloned Authority stack value, including materialized tables with no seed.
The separate authority-boxed-seed.Iaq81H candidate builds in31.53s; ELF SHA256:
11d26565078bbfeb64903172c3197d2e75885721e8ea0c6f54a1f1cf8bdb4237.
Its newly exported matching fixture passes (export.log,1 test,0 failures).
The probe buffer remains bounded on the heap; that change alone did not fix
the observed fault. No stack, heap, host-work or gas ceiling was raised.

Final authority-boxed-seed.Iaq81H/native.log:70 pass,0 fail,1 ignored,33.27s;
the256-replica fixture's Linear image is now17918 bytes after boxing the seed.
physical.log: both compiled Authority tests pass in1.68s; PVM1081440 bytes,
below1280KiB. Publication reads the exported two-node persisted table via the
actual compiled schema, returns byte-identical native state/decision, preserves
certificate rows and survives expired exact retry. Gas remaining for missing
blob/success/retry is993992545/820748188/849795663. The earlier probe-only fault
is not a remaining failure for this exercised candidate.
Native storage suite17/0 failures also passes (authority-row-probe.5MrIn6/storage.log).
Full-table guest work, compiled node mutation, other table conversions, finality,
release reproduction and live performance gates remain open. No merge or repin.

### 2026-09-20: Authority certificate namespace in clean schema generation19

SystemAuthority now declares node_certificates as a Linear StorageMap with
the exact prefix s/authority-nodes/. State generation advances18→19; constructors
only create an empty handle, and generated loading initializes it. The native
loader regression exercises fresh construction, explicit seed insertion,
commit/reopen and a substituted certificate across another restore. Restore
does not seed or repair rows, and the certificate/index check rejects drift.
The compiled candidate loader check now decodes the actual ELF AAS2 section
and requires exactly that storage field, prefix and lane before linking/loading.

This wires the signed storage declaration, NOT the live node-policy table:
AuthorityLinearState still carries the old inline nodes. Replacing that field
with NodeTable and coordinating its mutation/validation and native dispatch
isolation remain next. No bootstrap mutation is implicitly added to queries.
There is no old-schema fallback, bundle repin, merge or production qualification.

Fresh locked offline guest build: shared target/task-tmp/authority-node-schema.U7uylW,
build.log,41.28s. ELF target/riscv64em-vos/release/system_authority.elf SHA256:
9f69f933eaef6bbdbcd70efc1d22526d4d28cbb5fa9fdbcb942fabd6e45dad39.
The initial native.log has69 passes/1 failure/1 ignored: the generation test
still expected18. It now requires19 for the new declared storage schema.
The generated-loader test separately passed in row-resource-runtime.5B1apX/node-schema.log.
native-final.log passes70 tests,0 failures,1 ignored in35.70s. export.log
exports the generation19 signed publication fixture (1 pass,0 failures).

Physical checks then found a compiler failure, not guest execution:
physical.log fails both links; link-diagnostic.log locates a spurious target
0x91ae58 inside the relocated call at0x91ae54. The ELF's rodata at0x10190
contains a four-byte ADD32/SUB32 relative jump-table entry: its actual target
is0x92afcc minus table base0x10174, numerically0x91ae58. The adjacent zero word
made the raw eight-byte pointer heuristic mistake it for an absolute code
pointer. Relocation metadata already defines that entry's interpretation.

The compiler now excludes every overlapping recognized data-relocation range
from both heuristic target discovery and raw pointer rewriting, including
non-code relocation targets. Genuine raw call-interior pointers remain refused.
The synthetic ELF regression covers the real ADD32/SUB32 shape and a relocation
covering only the high half of a heuristic candidate; scalar neighbors remain
unchanged. This is a compiler change requiring release requalification, not
an artifact or instruction-safety bypass. No original relocation or call-pair
safety check was removed.

Final compiler-final.log:65 unit tests pass (1 ignored),9 integration tests
pass,0 failures. physical-fixed.log: both compiled Authority checks pass in3.07s
using the same ELF and corrected compiler. Linked PVM size1055197 bytes is
below1280KiB. Publication missing-blob/refusal, success and expired retry all
return Done, with byte-identical native/guest publication state. Gas remaining
is994029417/829424427/854176058 respectively. These are the small signed fixture
and compiled schema/loader gates, not row-table execution, maximum Authority
capacity, trusted-root finality or an independently reproduced release.

The first overlap implementation linearly scanned all relocations for every
data word. The outer-runtime regression exposed excessive linking time; after
its maximum-availability case passed, that superseded test process was
explicitly interrupted (runtime-regression.log, session20626 exit130).
The final implementation sorts/merges relocation intervals once and uses a
binary search per candidate. A unit test compares indexed overlap against
direct byte-range checks, including adjacent, nested and duplicate intervals.
compiler-indexed.log passes66 unit tests (1 ignored) and9 integration tests.
The interrupted run is not completion evidence; fresh indexed-compiler
physical results are recorded separately below.
authority-indexed.log: both compiled Authority tests pass again in1.80s with
the indexed implementation, preserving the same published state and gas values.
runtime-indexed.log: all3 physical outer-runtime regressions pass in36.38s
against the preserved row-resource-runtime.5B1apX ELF with the indexed compiler:
maximum availability, row commit/refusal/retirement, and large-row yield/resume/
retirement/inspection. Complete physical/native transitions match. This is
regression coverage for the compiler fix, not a new outer-runtime release pin.

### 2026-09-20: atomic lazy node bootstrap and full-capacity compact header

NodeTable now carries a compact index plus an explicit pending bootstrap
certificate. Construction and pre-materialization queries perform no storage
access, so generated constructor replay cannot write or overwrite certificates.
The first node-table mutation materializes the seed in a nested row transaction
and publishes its cloned inline header only on acceptance. Stored headers never
recreate missing certificates. Enclosing Authority handlers must still publish
their complete inline candidate only after all later policy checks succeed.

The capacity fixture caught a design error before integration: the declared
MAX_AUTHORITY_NODES is513 (2*MAX_PRIVATE_NODES+1), not the256 nodes in the
earlier replica fixture.513 full node/owner/digest index entries alone exceed
48KiB. The header now interns at most64 owner IDs and stores a one-byte owner
slot per node. The513-node/64-owner header encodes below36KiB. Owner-slot
removal renumbers surviving references; tests retain exact certificate bindings.
This is a node-header bound, NOT proof that the complete Authority state fits.

Evidence under shared target/task-tmp/row-resource-runtime.5B1apX:
node-table.log records the initial256-versus513 capacity-test failure.
node-table-compact.log:2 focused tests pass after compacting the header.
node-table-suite.log: final69 native Authority tests pass,0 fail,1 ignored,
28.19s, including513 nodes/64 owners, overflow refusal, bootstrap conflict,
outer refusal rollback, encoded-header restore, missing-certificate refusal,
and owner-slot compaction. node-table-no-default.log: no-default-features
Authority compilation passes in1.64s, with7 dead-code warnings because the
component is not yet wired into production Authority state/schema. No new
guest artifact or live timing is qualified. The next step is that integration,
including native per-incarnation store isolation and bounded policy validation.

### 2026-09-20: Authority node-certificate storage component (not yet wired)

Added node_storage.rs with a compact node/owner/certificate-digest index and
StorageMap-backed certificate operations. Reads bind the exact stored row to
the index; insertion refuses existing keys, removal requires a matching row,
and explicit bootstrap refuses a nonempty table. Enrollment signature/role
verification and capacity admission remain required caller responsibilities.
The native storage mock now exposes commit_dispatch so actor-crate tests can
exercise a drained overlay and fresh handle without exposing the runtime's
internal drain API.

The generated clean loader calls the constructor before initializing storage
handles, including on restore (vos/vos-macros/src/lib.rs, __load_agent_state).
Therefore bootstrap row writes cannot simply be added to Authority::new.
Production Authority still uses inline nodes: this component is not the schema,
bootstrap or state-integrity cutover and does not yet reduce production state.
Next integration must bind the compact index into the Linear integrity image,
declare certificate storage in the signed schema, initialize rows exactly once
through an authorized Linear path, and retain bounded certificate validation.
Do not claim native row tests qualify that integration or compiled capacity.

Evidence under shared target/task-tmp/row-resource-runtime.5B1apX:
authority-node-storage.log:66 native Authority tests pass,0 fail,1 ignored,
30.85s, including bootstrap refusal, commit/reopen, owner/certificate substitution,
refusal rollback and missing-row removal. node-storage-no-default.log: locked
offline no-default-features Authority check passes in7.82s; the not-yet-wired
component produces dead-code warnings. Initial node-storage.log records a
compile failure from attempting to use the private drain API; the mock helper
fixes it. No current compiled Authority artifact covers this component yet.

### 2026-09-20: large-row inspection and shared resource-accounting fix

The large-row lifecycle fixtures now execute InspectActors and InspectResources
after result retirement, for both ordinary completion and yield/resume. They
compare complete physical/native transition bytes, require unchanged state and
check reported state bytes against the actual encoded image. The preceding
row-resume-runtime.wPkIcf candidate panicked on the first inspection despite
passing the preceding lifecycle (management-guest.log, exit101).

Signed resource validation retained an encoded state while resource accounting
encoded another complete snapshot. It now retains only the measured length and
passes that to a private accounting helper on the same immutable runtime. All
package, policy, artifact, debt and resource checks remain. No caller-provided
size, state-format change or further heap/gas/availability increase is involved.

Evidence: shared target/task-tmp/row-resource-runtime.5B1apX:

- build.log: fresh locked offline guest build succeeds in35.22s.
- target/riscv64em-vos/release/agent_runtime.elf SHA256:
  b5913b0b2a552f92edfe36dd2ef35db5e50147c03d35c029beee005cdcd66a8a.
- physical.log:3 passed,0 failed,33.69s; maximum availability, ordinary row
  lifecycle and yielded row lifecycle, including both large-state inspections.
- clean.log:40 passed,0 failed,4.43s.
- standard.log:51 passed,0 failed,12.00s.
- authority.log: current Authority native library suite65 passed,0 failed,
  1 artifact-dependent ignored,30.23s; not compiled maximum-capacity evidence.
- no-default.log: locked offline `cargo +nightly-2025-05-09 check -p vos
  --no-default-features --features agent-runtime` succeeds in8.90s, with268
  warnings; this is not a clean lint gate.

Large inspection inputs are4004476/4004473 bytes; gas is920851412/998709280
for actor/resource queries in both fixtures. No controlled live Create/Install
latency improvement is established. Authority collections remain inline, and
its complete-state integrity calculation still clones/serializes the image;
changing storage handles alone would not solve bounded validation. The next
Authority cutover must coordinate signed storage schema, bootstrap row creation,
row integrity/validation and native dispatch isolation, then qualify compiled
capacity. Current source remains uncommitted and incompatible with the frozen
pre-SLR1 bundle; no merge, push, repin or independent reproduction was done.

### 2026-09-20: large-row yield, restore and completion

The row fixture now has a genuine SUSPEND/capture path: finalization exports
the first64KiB row only after SUSPEND returns0; restored execution receives1,
changes the first value byte, exports the replacement and completes. It checks
the committed row and retained continuation before restore, replacement row and
removed continuation afterward, then exact Invoke retry, ACK, exact ACK retry
and rejected post-retirement replay, beside the same60 untouched64KiB rows.

Native execution passed, but the preceding row-retirement-runtime.NTm1B6 guest
panicked on Resume after successfully committing the yielded slice. Evidence:
yield-source.log (session58451 exit0,0.15s) and yield-guest.log (session85138
exit101). apply_clean_resume retained duplicate SDK/legacy rollback bytes. It
now moves those buffers into one owned image, matching Invoke/ACK; input-bearing
and stale continuations still reject, with the same rollback bytes and gates.
No heap/gas/state/availability ceiling or wire format changed for this fix.

Final evidence: shared target/task-tmp/row-resume-runtime.wPkIcf.
build.log: fresh locked build31.92s, session8733 exit0.
ELF: target/riscv64em-vos/release/agent_runtime.elf, SHA256
19bcb91d2d80fa56c50822d867ef7b1672ed8d27fed8190863de2b12913d7b6c.
clean.log:40 pass,0 fail,4.75s, session68351 exit0.
physical.log: all3 explicit compiled_runtime_ regressions pass against this
candidate, session40086 exit0: maximum availability, row commit/failure/retirement,
and large-state yield/resume/retirement. Full physical transitions equal native
output throughout. The large Resume input4145773 bytes uses1440141208 gas, below
the unchanged5-billion management allowance. This closes the exercised suspended
row lifecycle, not every capacity/crash/proof case or Authority's table conversion.
No merge, push, repin or independent artifact reproduction was performed.

### 2026-09-20: large-row acknowledgement and durable retirement

The row lifecycle fixture now continues from exact invocation retry through
acknowledgement, restored exact ACK retry, and rejected invocation replay after
retirement. It checks that results are removed, actor rows/inline state remain
unchanged, repeat ACK returns the identical transition, and retired invocation
returns DivergentInvocation without changing state. All physical output bytes
are compared with native transitions, for small read/write/failure cases and
the60-row (3.75MiB unrelated data) case.

This extension exposed another physical panic: the preceding row-stream-runtime
candidate passed large execution/retry but failed its first large acknowledgement
(row-stream-runtime.1NeXrB/retirement-guest.log, session66380 exit101). Native
extended lifecycle passed (retirement-source.log, session31924 exit0,0.12s).
apply_clean_acknowledge_inner still retained SDK and legacy copies of its
encoded rollback state. It now moves those buffers into one rollback image,
as Invoke does, preserving exact failure and repeat-ACK output. No validation,
state format, heap, gas or other resource ceiling changed.

Final evidence: shared target/task-tmp/row-retirement-runtime.NTm1B6.
build.log: locked fresh runtime build31.68s, session95105 exit0.
ELF: target/riscv64em-vos/release/agent_runtime.elf, SHA256
350554254b2e39eb900fe1a42da65debf77fd839b6a64a0382e81931c93ebe39.
clean.log:39 pass,0 fail,4.69s, session25836 exit0.
retirement-guest.log:1 explicit physical lifecycle test pass,0 fail,14.06s,
session99138 exit0. Large ACK input4072509 bytes uses1160516165 gas; exact ACK
retry4071372 bytes uses1062720299; retired Invoke4071380 uses1066762818. Each is
below the unchanged5-billion management allowance, preserves actor state and
matches native output exactly. This is not a latency or every-state-shape gate.
availability-guest.log: the same candidate also passes the192KiB physical
invocation/retry regression (1 pass,0 failures,2.26s, session59614 exit0).
Authority conversion, large suspended-state paths, reproducible release pins
and the remaining complete-saga requirements remain open. No merge or push.

### 2026-09-20: physical row persistence and large-state allocation fix

The clean row fixture now canonically decodes complete signed work, compares
physical outer-runtime transitions byte-for-byte against native execution, and
restores/retries the result. Cases cover persisted64KiB reads,64KiB exports,
Panicked/Forbidden/OOG rollback, and a successful export beside60 untouched64KiB
rows (3.75MiB of unrelated state). All unrelated rows and the exact result are
preserved. This is synthetic signed runtime work, not Authority table conversion.

The original availability-runtime.cVFFv6 candidate passed every small case but
panicked on the large state, while native execution passed. rows-guest.log and
rows-diagnostic.log retain that failure (sessions93671/34634 exit101). Removing
the duplicate SDK/legacy encoded rollback image from apply_clean_invoke_inner
alone was insufficient: row-memory-runtime.55KUQC also failed the large physical
case (rows-guest.log, session70272 exit101). It remains preserved, SHA256
f24eee992353213f427b62440ebc58fa7ff1d61e794c9b0654e11bb63dfe1f4c.

The completed fix also streams each ALI1 row image directly into its enclosing
lane frame, patching the same length prefix instead of allocating a complete
temporary image and copying it. The wire format, rollback bytes, admission and
validation are unchanged. No heap/gas/resource ceiling was raised for this fix.

Final evidence: shared target/task-tmp/row-stream-runtime.1NeXrB.
build.log: locked fresh runtime build31.74s, session43200 exit0.
ELF: target/riscv64em-vos/release/agent_runtime.elf, SHA256
19e9ec1d2088f7d518f0a456152f103dd971cddb69449cc627a2915b5a18757b.
rows-guest.log:1 explicit physical test passed,0 failures,6.41s, session1579
exit0, covering all cases and retries. Large fresh input4005623 bytes uses
1399879866 gas; retry4072517 bytes uses1175248138, below unchanged5-billion
management gas. Both full transitions equal native output. This is near-capacity
coverage, not proof of every4MiB boundary, all slice shapes, or measured peak RAM.
clean.log:39 pass,0 fail,4.61s, session83065 exit0. codec.log:10 pass,0 fail,0.06s.
availability-guest.log: the192KiB physical outer-runtime execution/retry also
passes against this same final candidate (1 pass,0 failures,2.23s, session79098
exit0); complete transitions still equal native output.
The first native large-row probe also passed before the allocation fix
(availability-runtime.cVFFv6/rows-source.log, session34731 exit0).
No release repin, merge or push. Authority conversion and the full saga gates
remain unfinished; retained frozen artifacts are unchanged.

### 2026-09-20: physical outer-runtime maximum-availability execution

A new signed clean fixture reads the full192KiB caller payload through an inner
PVM, returns its length and last eight bytes, and commits one inline byte. Its
complete RuntimeWork is canonically encoded/decoded before dispatch; resulting
state is decoded/restored before the same signed invocation is retried at slot99.
The native regression verifies positive output and exact retry outcome. A separate
signed one-byte-over-window fixture still fits the larger outer code/schema/policy
availability envelope but rejects with InvalidInput at caller admission.

A fresh current-source outer runtime was built without changing any bundle pin.
The explicit ignored test compiled_runtime_maximum_availability_matches_source_and_retry
uses AGENT_RUNTIME_CANDIDATE_ELF, validates its outer hostcall surface and executes
both phases in the physical runtime PVM. Complete output bytes match native
transitions, including SLR1 lane state. Fresh input399484 bytes uses367893979 gas;
retry input400862 uses269348848, under the unchanged5-billion management budget.
This is signed synthetic fixture/physical outer execution, not actual trusted-root
Shared finality, maximum Authority state, daemon restart, independent artifact
reproduction, a peak-memory benchmark, or production latency qualification.

Evidence: shared target/task-tmp/availability-runtime.cVFFv6.
build.log: locked runtime guest build26.59s, session9764 exit0.
ELF: target/riscv64em-vos/release/agent_runtime.elf, SHA256
55e98092952b98f6d3aab2c0b87d5afa3c70d5fe7ed435b705dbd8fa65977140.
source.log: native maximum fixture1 pass,0 fail,0.05s, session45452 exit0.
guest.log: physical test1 pass,0 fail,2.28s, session1811 exit0.
clean-suite.log:38 pass,0 fail,3.84s, session39568 exit0, including the new
over-window rejection. The physical test predates only the test-helper rename
and extra native negative case; runtime implementation/artifact are unchanged.
No merge, push or repin; the frozen bundle remains incompatible with current
source and the full suite has not been qualified against a new release.

### 2026-09-20: bounded large-provision transport

Caller availability now shares one192KiB SDK/executor ceiling, including native
pre-reservation shape checks (previously those also used the48KiB inline-state
cap per blob). Complete clean-Create provisions have a174921-byte conservative
wire bound. The signed256-replica fixture's55586 bytes now pass both that bound
and ActorInvocation admission/exact preimage lookup; its call/approval/QC and
roundtrip checks remain. Inline state is still48KiB and the256-node Authority
state still exceeds it. This does not qualify full Shared creation.

Resource changes are explicit: FETCH ceiling460675 bytes derives from complete
frames/probes plus key/hash/copy work for the caller window; BLAKE2b compression
ceiling2568 derives from the1024 baseline plus one bounded SDK blob verification
and framing allowance per blob.20 fetch calls,4096 total host calls, instruction
gas, stack/heap and inline-state ceilings are unchanged. Row and preimage budget
tests now derive exhaustion from these ceilings and retain actual yield/restore
coverage. Successful large-blob transport does not constitute32MiB outer-runtime
peak-memory, production latency, or release artifact qualification.

Fresh RISC-V fixture evidence: shared target/task-tmp/availability-guest.GVRrNo.
build.log: locked build29.74s, session96196 exit0. ELF at
target/riscv64em-vos/release/agent_yield_probe.elf, SHA256
4bb27075b9dd4b820cf863ef96fb4458ca8b62b5e56356d61b33c9e30bbf1f08.
execution-fixed.log:1 pass,0 failures,0.17s, session62127 exit0; maximum encoded
message plus192KiB invocation_blob success/missing/invalid length and unchanged
state. execution.log records an initial test-module path compile error, fixed
without changing production behavior. Earlier executor failure from a stale
36KiB expected counter remains in authority-single-check.7E8Tdq/availability-executor.log.

Final source checks in availability-guest.GVRrNo:
- executor-suite.log:21 pass,0 fail,4 artifact-dependent ignored,0.02s.
- clean-wire.log:36 pass,0 fail,4.19s, session35345 exit0.
- availability-tests.log:7 pass,0 fail,0.09s, session53277 exit0; includes native
  pre-reservation individual/aggregate rejection and signed maximum roster.
- sdk.log:167 pass,0 fail,0.08s, session92698 exit0.
- authority-publication.log:1 pass,0 fail,1 fixture-export ignored,0.56s,
  session53431 exit0; missing/oversized blob refusal and signed publication retry.

No bundle repin, merge or push. The ten frozen-runtime failures were last
measured before this resource change; the full wire suite was not rerun here.
Current source and the frozen bundle remain unqualified together.

### 2026-09-20: node owner/certificate access separation

Authority now separates enrolled_node_owner (a copied principal projection)
from enrolled_node (an owned certificate row). Replica reconstruction, replica
membership checks, managed-agent validation and authenticated owner checks use
the owner-only path; SSH attestation and Private identity verification retain
the complete certificate path. Enrollment insertion/removal are centralized
with capacity, duplicate and exact-owner checks, inside the existing Admin
candidate/transaction. Fast prechecks and full state/certificate validation
remain. The table is still an inline Vec: this prepares the backend cutover,
does not change the state format, and does not solve the48KiB capacity gap.

Locked native Authority suite passes65/0 failures,1 ignored,28.77s; evidence:
authority-single-check.7E8Tdq/authority-node-boundaries.log, session36590 exit0.
New coverage checks detached certificate ownership, duplicate enrollment refusal,
wrong-owner removal rollback, absence and exact reinsertion. The earlier
owner-lookup-only run passed64/0 failures in28.32s (authority-node-access.log,
session91959 exit0). No fresh guest artifact was built for this refactor.

Remaining cutover must coordinate signed storage schema, table initialization,
bounded validation and native dispatch/store isolation; simply replacing the
Vec with a handle would not satisfy these. In particular generated storage
prefix initialization occurs after actor construction, so bootstrap rows cannot
be inserted through an uninitialized constructor handle.

### 2026-09-20: Authority mutation acceptance boundaries

authorize_call, authorize_operation_call, administer_call, finalize_application,
acknowledge_operation_issuance, resolve_private_application and genesis publication
now enter authority_row_transaction before their unchanged staged handlers.
Empty byte replies and false acknowledgements roll back rows; successful replies
leave rows pending for the enclosing runtime commit. No inline candidate or
validation was removed, and no Authority table has been converted yet.

The nested actor's native-only dev dependency enables vos/std for thread-local
storage rather than sharing the single-thread guest overlay across test threads.
Cargo.lock includes that host test dependency graph; RISC-V still uses the
existing no_std dependency. Native suite:64 pass,0 fail,1 ignored,38.94s;
authority-single-check.7E8Tdq/authority-row-transactions.log, session88269 exit0.
The added test covers bool and byte refusal, preserved prior writes, inner
success discarded by outer refusal, and unchanged positive reply bytes.
Fresh locked RISC-V build passes in40.16s, session49798 exit0; evidence directory
shared target/task-tmp/authority-row-guest.bIor6Q, build.log.
ELF: target/riscv64em-vos/release/system_authority.elf, SHA256
86b03c49ec8ab78ec1460f79ed71a7c4f2dbab07463ad633e80c9d9fe4ea8d32.
This candidate is not a repinned release artifact.
The compiled signed publication regression passes missing-blob refusal,
byte-identical native/guest publication state and expired exact retry against
the retained explicit fixture (1 pass,0 failures,1.53s; host build53.76s;
publication.log, session8214 exit0). This remains a small inner-machine fixture,
not maximum capacity, actual trusted-root finality, or package qualification.

### 2026-09-20: row-transaction rollback prerequisite

Authority currently rejects operations by discarding an inline-state clone.
StorageMap clones share the dispatch overlay, so converting those collections
without a row savepoint would leak refused mutations into a successful reply.
The storage API now provides synchronous `with_transaction`: Err/unwind restores
the previous pending delta and clears reads; nested successful scopes remain
subject to outer rollback. It copies pending writes only, not persistent rows.
Dispatch draining and cooperative yield reject an open transaction. Ordinary
actor fields and external effects are not rolled back by this API; Authority
still needs its inline candidate and explicit acceptance boundary on conversion.
No Authority table has been converted yet.

All17 native storage tests pass, including replacement/insertion/index rollback,
nested scopes, unwind and rejected dispatch boundaries. Evidence:
shared target/task-tmp/authority-single-check.7E8Tdq/storage-savepoints.log.

Fresh RISC-V fixture execution also passes (1 test,0 failures,0.22s; host
build83s). Local row_rejected stages999 then returns Err from its transaction.
Both existing key7=41 and absent key9 retain their original state, export no
rows despite a Done reply, and remain unchanged on subsequent invocations.
The same test still passes set/get and write/yield/resume/write. This is real
inner-machine evidence, not Authority integration or signed package admission.
Evidence: shared target/task-tmp/storage-rollback-guest.uYKuDb/execution.log;
build.log records an initial fixture macro/borrow error, build-fixed.log succeeds.
ELF: target/riscv64em-vos/release/agent_yield_probe.elf, SHA256
fde0047965d95c85a960d482df7180187bcff1ff46e5984f540672b16e9ca084.
The earlier storage-rust-guest.cSZzlY artifact remains unchanged.

### 2026-09-20: compiled Rust StorageMap dispatch and resume

The no_std PVM storage backend now reads through peek/STORAGE_R without the
service feature. Clean run_refine drains storage only after inline lane checks,
exports one ARD1 packet for Done/Yielded and discards failed overlays. A restored
clean yield clears the prior slice's committed pending writes, tombstones and
read cache before user code resumes. Existing service dispatch retains its
own drain path.14 storage tests pass, including explicit drain-status behavior
and stale-overlay reset (storage-rust-backend.log, session52684 exit0 in the
authority-single-check.7E8Tdq evidence directory).

The agent-yield fixture now has Local StorageMap row_set/row_yield and LocalQuery
row_get under s/rows/. A fresh RISC-V build passes; the compiled inner-machine
test performs set(7,41), get(7), a row8 write/yield/read/replace sequence ending2,
then get(8). The row image is encoded/decoded between invocations and around
the real machine yield. All expected replies/deltas and one-yield completion
pass (1 test,0 failures,0.12s; session97891 exit0). This is explicit fixture
namespace scope and real guest IO, not signed package admission, installed
Authority execution, or a daemon/disk restart qualification.

Evidence directory: shared target/task-tmp/storage-rust-guest.cSZzlY.
ELF: target/riscv64em-vos/release/agent_yield_probe.elf
SHA256:3ebd8dca9429af413910bd9be20868f9df7b98070422fdd1209bc8aa2b81dab6.
Logs: build.log (missing alloc::vec import exposed by no_std+pvm),
build-fixed.log (fixture missing explicit StorageMap import),
build-import-fixed.log (success1.12s, session32287 exit0), execution.log and
no-std.log. Both compile errors were repaired without changing bounds. Earlier
partial build failures remain retained. The ordinary no-default-features check
also passes (session98206 exit0).

No old package/store was replaced. The frozen guest still predates the SLR1
format and its ten known wire failures remain open until generation sealing,
reproducible rebuild/repin and gate rerun. Next substantive work is Authority
collection conversion and physically bounded access/validation at required
capacity; full-provision transport, Shared finality and production gates remain
unfinished. The small compiled map fixture is not maximum-capacity proof.

### 2026-09-20: guest row export reaches atomic clean dispatch

Clean ACTOR_EFFECT_EXPORT accepts one ARD1 row delta per slice. The wire binds
the SDK ABI, strict unique key order, bounded count/key/value/input bytes, exact
option tags and full consumption. Producer preflight validates before building
the buffer, without decoding/cloning it again in the guest. Host dispatch
charges twice the input length before allocation (guest copy plus owned decoded
rows) against the existing persisted FETCH quota, then validates signed prefix/
write-lane ownership. No quota was increased. The4MiB codec ceiling is not an
invocation-throughput promise; the165763-byte native work budget is still lower.

Inner outcomes now carry exported rows only for Done or a valid captured Yield.
Panic/fault/forbidden/out-of-gas outcomes discard them. Duplicate export and
SUSPEND after export reject: a host-side pending delta may not disappear into
a continuation snapshot. Yield finalizers may export after capture and their
work remains charged to the continuation. Fresh and resumed clean dispatch
route nonempty deltas through the atomic row/result/continuation wrapper; empty
delta calls retain their existing commit path. Legacy dispatch receives no row
view and cannot use this export decoder.

Actual assembled-PVM clean-dispatch tests create a64KiB row, commit it with inline
state/result, restore and recover the exact reply. Reported Panicked, Forbidden
and OutOfGas outputs after export retain neither the row nor inline mutation.
The earlier real read test remains separate. Focused guest tests2/0 failures
pass0.21s after43.14s build (storage-guest-export.log, session8161 exit0).
Broader checks: executor21/0 failures with3 artifact-dependent ignored, codec/
storage10/0, clean-dispatch36/0 in3.92s (session57688 exit0). Executor rejection
coverage includes duplicate export, suspension after export, malformed magic,
undeclared namespace and an input exceeding the native work quota. Codec tests
include delete/empty distinction, duplicates, malformed ABI/count and trailing
bytes. No-default-features compilation passes (session25385 exit0).

Logs under shared target/task-tmp/authority-single-check.7E8Tdq:
storage-export-check.log, storage-guest-export.log, storage-export-executor.log,
storage-export-codec.log, storage-export-clean-suite.log, storage-export-no-std.log.
No tests were disabled to pass these checks. The ten known frozen-runtime wire
failures were not rerun or fixed: generation seal/rebuild/repin remains required.

Next: wire the generated Rust storage backend and end-dispatch drain, including
continuation overlay handling, then test a compiled Rust actor. The current
positive writer is an assembled PVM, not a StorageMap guest. Authority conversion,
maximum-capacity/physical guest qualification, Shared finality and production
gates remain open. No artifacts, old stores or branch pointers changed.

### 2026-09-20: atomic row/result/continuation commit boundary

StandardAgentRuntime::commit_clean_row_batch now authenticates the installed
schema/target, stages the canonical delta and inline bytes in one candidate,
runs the existing terminal/yield transition callback in that candidate, and
checks restored lane invariants plus complete encoded runtime resource usage
before replacing live state. The callback must retain the existing caller
authorization and result/continuation checks; this helper is not an alternate
authorization path. Its owned result is returned only after final admission.
Rows move out of the candidate entry into the image primitive without another
whole-image clone. A failure at any stage discards the candidate.

Native integration verifies64KiB row plus terminal result commit/restore,
namespace refusal before callback, late failure after result staging, complete
runtime resource refusal, rows committed with a portable yield, and terminal
consumption of that continuation together with a replacement row. A forced late
failure after consuming the continuation preserves the original yielded state
exactly. This uses native runtime transitions and a test continuation, not a
guest-generated row mutation or physical restart.

Focused test1/0 failures passes0.03s after21.86s build
(storage-row-result-yield-atomic.log, session17012 exit0). Broader clean suite
35/0 failures passes3.79s and no-default-features check passes1.69s
(storage-row-commit-clean-suite.log, storage-row-commit-no-std.log,
session4028 exit0). Logs remain under shared target/task-tmp/
authority-single-check.7E8Tdq. Initial storage-row-result-atomic.log failure is
retained: directly narrowing only the policy made an inconsistent fixture;
restore correctly rejected it. The fixed fixture derives config/initial policy
from its coherently constrained descriptor. No restore validation was relaxed.

Guest mutation export has not been connected to this wrapper yet. The clean
Rust collection backend therefore remains disabled; no silent write dropping
is allowed. Authority conversion, physical guest capacity, Shared finality,
the frozen-bundle format mismatch and the other release gates remain open.
No source commit, branch movement, repin or external deployment occurred.

### 2026-09-20: clean dispatch reads runtime-owned persisted rows

Fresh and resumed clean invocations now resolve their STORAGE_R view through
StandardAgentRuntime::resolve_clean_storage_reader, after existing caller
authorization. The installed schema/incarnation/deployment/program checks
derive the scope, and row maps come only from that actor's exact incarnation
in each physical lane. Namespace ownership is validated before use, including
hidden lanes. The reader owns its small access scope and borrows the persisted
maps; it does not clone row collections into another image or the inner heap.
Legacy dispatch remains without row access. Guest collection writes remain
disabled until their mutations can be exported and committed atomically.

New integration coverage starts with a canonical storage schema/policy and
signed Authority receipt, seeds a64KiB persisted row, serializes/restores the
runtime through actual clean dispatch, and reads it using an assembled PVM.
The inner inline snapshot remains one byte. The guest returns the complete
row length and copied payload prefix; its inline/result commit preserves rows.
Restore plus expired exact retry preserves all state except the existing
result-lane authority clock, which advances to the observed retry slot. This
is a real guest read, not a guest-created row or a disk/daemon restart claim.

Clean-dispatch suite34 passed,0 failed in3.82s after16.38s build
(storage-clean-dispatch-suite.log, session46814 exit0). Storage suite9/0 and
executor20/0 with3 artifact-dependent ignored also pass; no-default-features
check passes3.12s (session96980 exit0). Logs are in shared target/task-tmp/
authority-single-check.7E8Tdq: storage-borrowed-reader.log,
storage-dispatch-executor.log and storage-dispatch-no-std.log.
The initial storage-clean-dispatch.log failed only the final whole-state retry
comparison: it incorrectly disallowed the documented authority-clock advance.
The corrected assertion specifies that exact field change and compares the
complete decoded state; no production retry behavior was relaxed. The initial
failure log includes large state dumps and is retained, not printed again.

The prior ten bundled-runtime wire failures remain a generation/release gate;
this turn did not rebuild or repin the frozen guest. Next are guest mutation
export and batch/result/continuation commits, Authority conversion/capacity,
and coordinated artifact qualification. No branch pointers moved and no
existing stores or artifacts were modified.

### 2026-09-20: runtime row persistence and explicit lane-format cutover

StandardLaneEntry now separates its inline value from an ordered row map.
The outer lane encoder writes SLR1 after the runtime ABI, and each entry is an
ALI1 image. Decoding has no raw-inline fallback; wrong lane marker, image magic
or image ABI rejects. Rows remain outside prepare_execution_state/FETCH inline
snapshots. Runtime canonical admission uses complete image byte/key/value/count
bounds while retaining the48KiB aggregate inline limit. Empty inline plus rows
is canonical; an entirely empty entry still must be omitted. Existing inline
upserts preserve rows, including when inline becomes empty. Merge observations
now hash the complete encoded image so changing a row changes the frontier.
The historical checkpoint fixture was updated for the new row field, not for
different compaction semantics.

Focused persistence tests3/0 failures pass, including a row-only image above
the inline ceiling, restore/roundtrip, old framing rejection and oversized row
rejection. Production-feature Standard runtime suite51/0 failures passes12.18s,
including row preservation through inline updates and Merge observation/reopen
binding. Storage image suite9/0 failures passes; no-default-features check
passes1.91s. Logs under shared target/task-tmp/authority-single-check.7E8Tdq:
storage-persistence-wire-fixed.log (session50111 exit0),
storage-persistence-standard.log, storage-persistence-image-tests.log and
storage-persistence-no-std.log (session96870 exit0).
The initial storage-persistence-wire.log compile failure is retained: Encoder's
fixed method takes32 bytes; the four-byte marker now uses explicit byte append.

IMPORTANT: full production-feature wire suite is RED:90 passed,10 failed,
1 ignored in11.23s (storage-persistence-wire-suite.log; combined session44048
exit101). All ten failures exercise the frozen bundled runtime, which predates
SLR1; its decoder in immutable source ba7be457 reads a lane tag immediately
after the ABI and rejects the new marker. Tests observe Panic rather than Halt.
No tests were disabled or weakened and no backward decoder was added. Current
source and bundled guest are NOT deployable together. A coordinated clean
generation seal/reproducible rebuild/repin and rerun of these tests are required.
The frozen e20cbb76 Local/Public-policy checkpoint and old stores are unchanged.

Still open: supplying authenticated row views in production dispatch, guest
mutation export, applying batches in the same candidate as results and machine
continuations, whole-runtime reservation checks, Authority collection conversion
and maximum-capacity qualification. The new persistence test seeds rows directly
and does not claim an end-to-end guest write. Shared finality, production latency
and the other saga release gates remain open. No branch pointers or artifact
pins moved.

### 2026-09-20: atomic lane-image row batches

ActorStorageAccess::apply_batch validates the owned write lane, persisted
namespace ownership, inline ceiling, canonical strictly ordered unique keys,
per-row bounds, bounded delta input, and final encoded image byte/count limits
before any mutation. It then removes old touched rows before inserting new
ones and replaces inline bytes in the same operation. No whole-image clone is
needed for this primitive; outer runtime result/continuation atomicity remains
the responsibility of the enclosing commit path, which is not wired yet.

Nine default-feature storage tests pass (0 failures,0.09s; session38262 exit0),
including late-invalid changes preserving the full before image, query denial,
empty versus deleted rows, canonical roundtrip, exact delta replay, exact4MiB
and16384-row images exchanging rows whose new key sorts before the deleted key,
and final capacity overflow rejecting unchanged. The test constructs the
maximum-count fixture directly but checks image encoding and namespace admission
before applying updates. Log: shared target/task-tmp/
authority-single-check.7E8Tdq/storage-atomic-batch.log. No-default-features
compilation also passes (storage-atomic-no-std.log, session59667 exit0).

This is a native image primitive, not durable runtime integration or a guest
capacity qualification. StandardLaneState still stores raw inline bytes; its
codec/admission/lifecycle paths need a coordinated clean generation change
before consuming ALI1 images. Guest mutation export, binding image commits to
results/continuations, and whole-runtime byte reservations remain open. Neither
capacity blocker nor Shared finality/release gates is closed; no artifact pins,
branch pointers, or review ranges changed.

### 2026-09-20: bounded inner-machine row reads

The inner executor now has an explicit runtime-owned ActorStorageReader input.
It validates namespace ownership across supplied images, selects a row's lane
from the signed prefix (never from guest input), and denies hidden namespaces
even when no image/row exists. A reader requires a matching clean invocation
mode; ordinary calls without a reader still reject STORAGE_R. This does not
authenticate caller policy or bind an arbitrary image to an actor: production
integration must resolve images from the same installed actor/generation as
the previously authenticated access scope.

STORAGE_R bounds key and output lengths before allocation, charges key reads
including misses, returns HOST_NONE only for permitted absence, and implements
the existing full-length/prefix-copy probe semantics. Copies consume the same
persisted FETCH byte budget as other native reads. No limits were raised;
the existing20-call/165763-byte work budget is not a qualified bulk-storage
capacity promise. Actual assembled PVM tests exercise64KiB values, short/zero
probes, empty/absent rows, hidden/undeclared namespaces, malformed lengths,
missing reader/clean context, call/byte exhaustion and two real yield/restore
cycles. Two full reads fit; the third returns OutOfGas with the latest slice
state unchanged. Stored images remain byte-identical.

Current-source production-feature executor suite:20 passed,0 failed,3 explicit
artifact-dependent ignored,0.01s after19.84s build (session3872 exit0).
Storage suite:7 passed,0 failed,0.01s; no-default-features check3.72s
(session50912 exit0). Logs under shared target/task-tmp:
authority-single-check.7E8Tdq/storage-inner-executor.log,
storage-reader-unit.log and storage-reader-no-std.log. The initial
storage-inner-read.log failure is retained: the test compared absent input
lanes with the return frame's present-empty lanes; the fixture now consistently
uses present-empty lanes. No production behavior was relaxed to repair it.

Production dispatch still does not supply row views, and the clean Rust
collection backend remains disabled: its old service-effect write path must
not silently discard clean mutations. Next are runtime image persistence,
atomic writes/continuations and guest collection dispatch, followed by the
Authority conversion and real capacity qualification. No artifact pins or
branches moved; Shared finality and release gates remain open.

### 2026-09-20: installed-schema binding for clean row access

ActorStorageAccess now checks exact declared namespaces and the full six-mode,
three-lane read/write matrix; denied updates leave images unchanged. The
StandardAgentRuntime schema-validation boundary derives this scope only after
checking the installed schema reference/preimage, state-layout and lane set,
actor incarnation, deployment, program, and selected method/mode. Caller
authorization remains a separate mandatory gate, not something this scope
proves. Regression coverage uses an installed actor with an inline field plus
a storage field: authorized namespace read/write succeeds; foreign namespaces,
stale identities, wrong modes and a self-consistent replacement schema reject.

Production-feature focused tests pass: installed-schema regression1/0 failures
(0.02s after1m12s build), codec/access tests6/0 failures (0.01s). No-default-
features check passes3.77s. Evidence under the shared target task-tmp directory:
authority-single-check.7E8Tdq/storage-installed-scope.log,
storage-scope-runtime-feature.log and storage-scope-no-std.log.
The earlier default-feature access suite also passed6/0 failures in
storage-access.log. Existing compiler warnings remain; these are not lint or
whole-workspace release gates.

This is uncommitted source, not deployed storage: StandardLaneState still holds
raw inline bytes. Guest row IO, runtime image persistence, continuation/atomic
commit integration and Authority collection conversion remain next. Neither
the48KiB capacity gaps nor Shared finality are closed. No release pin, branch
pointer or review boundary changed.

### 2026-09-20: uncommitted Authority publication compile repair

Clean row-storage implementation started with the private ActorLaneImage
representation (actor_storage.rs). ALI1 separately encodes inline fields and
ordered row key/value pairs, binding the current ABI. Inline remains48KiB;
one image is bounded by the existing4MiB outer ceiling, including keys, values
and all framing; the complete runtime must still reserve its own overhead.
Rows use the existing64KiB value bound, a64KiB key bound and16384-row count
bound. These are candidate codec limits, not a newly advertised guest capability.
Updates reject overflow before mutation; empty values differ from absent rows;
decoding checks total bytes before allocation, count plausibility, per-item
bounds, strict key order/uniqueness and complete consumption. Four tests pass
0.01s after38.26s build (session14586 exit0;
authority-single-check.7E8Tdq/lane-image.log), including256 separate rows beside
a maximum inline snapshot and an exact4MiB image. This is only an internal
codec: StandardLaneState does NOT yet consume it, and no guest storage hostcall
or Authority table migration has been implemented. Next implement signed
field-prefix/lane access, bounded row IO and atomic runtime persistence before
converting Authority collections. Do not reinterpret existing lane bytes as
this image or claim capacity qualification from its unit tests.

Blob quota across real continuation boundaries is now covered by an assembled
PVM regression. The actor reads36KiB, suspends, resumes and reads36KiB again,
suspends again, then the third read exhausts the accumulated native-work quota.
Both captures retain exact FETCH calls/bytes and valid portable snapshots;
OutOfGas preserves the last yielded state. This is physical capture/restore,
not daemon/disk restart or only counter arithmetic. Production-feature executor
suite passes19/0 failures/3 explicit artifact-dependent ignored,1626 filtered,
0.01s (session60552 exit0; authority-single-check.7E8Tdq/executor-yield-budget.log).
All three explicit artifact tests also pass together3/0 failures/0 ignored,
1645 filtered,1.39s (session41608 exit0, executor-artifacts.log in that directory):
Rust input/blob decoder, Authority candidate loader (1046074 PVM bytes), and
native/guest publication-state equality with expired exact retry. Artifact
paths remain the independently retained input probe and single-check candidate;
this is not a fresh generation reproduction or maximum-capacity qualification.

Storage-contract audit: RuntimeResourceLimits authenticates outer runtime
state/catalog/proof ceilings; ActorPackageContract currently carries only its
ABI. Existing #[storage] handles use the service-runtime backend; a no_std
non-service backend explicitly panics, and clean run_agent rejects unsupported
effects. Therefore these handles cannot simply replace Authority's vectors to
solve capacity without implementing the clean storage execution path. No
storage redesign or new per-actor capacity contract has been introduced here.

FULL-ROSTER CAPACITY AUDIT: the complete signed256-replica provision is55586
bytes: proposal18596, roster35947, evidence754, decision237, framing52.
The regression reuses the full strict pending-Create signature/receipt/QC,
canonical roundtrip and publication-identity checks, not just a standalone
roster size. It is valid under MAX_CLEAN_CREATE_GENESIS_PROVISION_BYTES but
exceeds caller availability49152. All12 genesis tests pass0.09s
(session26111 exit0; authority-single-check.7E8Tdq/full-provision-capacity.log).
This passing audit proves the current incompatibility, not successful delivery.

Separately, the existing native full256-replica authorization fixture has76494
encoded Linear bytes after node enrollment and before adding its Create or
publication record. This exceeds the49152 inner actor lane ceiling already.
The full-replica principal-substitution/authorization test passes1/0 failures,
63 filtered,9.11s after7.93s build (session98914 exit0;
authority-single-check.7E8Tdq/enrollment-capacity.log). Its assertion explicitly
records the mismatch so it cannot be misrepresented as guest qualification.
The runtime package resource contract signs the outer state-image ceiling,
not a per-actor heap/lane allowance. No existing signed per-actor capacity
negotiation was found in ActorPackageContract. Thus transport-only expansion
cannot close maximum support: both transport and persistent Authority state
must be reconciled with a physically tested bounded execution policy/layout.

RESOLVED FOR THE SMALL FIXTURE: compiled Authority publication now passes all
three phases against the original exported native fixture: absent blob leaves
pending state unchanged, valid publication produces identical reply and Linear
bytes, and expired exact retry preserves the published state. Candidate:
shared target/task-tmp/authority-single-check.7E8Tdq;
normal locked/offline RISC-V build36.56s (session23053 exit0), ELF SHA256
`fc2240a55f2f875d063c20a9c8a731527bbc4fa17fef48c78fcbc2221244e643`.
Same production-feature harness which rejects the original candidate now
passes1/0 failures/0 ignored,1645 filtered,1.38s (session44474 exit0,
publication.log). Remaining gas by phase:994033525,829657706,854184255.
This is an explicit inner guest test, not real root-backed native finality,
maximum resource qualification, or sealed/reproduced release artifacts.

Stack investigation with -Zemit-stack-sizes: original provision decoder35648
bytes and dispatch13432. Separate nested decoding alone still overflowed;
boxing only the proposal's ReplayInput progressed further but still overflowed.
Final layout boxes the replay input and provision components and keeps nested
decoders out of the enclosing frame. Largest decoder scratch frame in the
measured final-layout build is12256 bytes. Private in-memory layout changes do
not change canonical wires; the unchanged exported fixture proves exact output
equivalence. All11 genesis tests pass (session39554 exit0). Failed intermediate
targets/logs remain at authority-stack.KUdG3H, authority-stack-fix.YcCHUU,
authority-boxed.keOq2l, authority-boxed-split.wiUvmj, authority-components.oWLXdT
under shared target/task-tmp.

Final-layout execution then exhausted exactly1024 hash-compression calls
(publication-quota.log, session93545 exit101). Removed the duplicate
record_is_valid before candidate insertion: authority_state_is_valid still
verifies every candidate publication before replacing live state. Publication
native regressions pass2/0 failures/1 explicit exporter ignored,0.52s
(session25818 exit0). No stack/heap/gas/hash-quota ceilings were raised.
The compiled publication regression now requires feature agent-runtime, which
provides the real hash precompile; pvm alone is not that execution surface.
Earlier failure paragraphs below are historical, not the current small-fixture
result. Broader capacity and production gates remain open.
Final-current-source production-feature rerun also passes1/0 failures/0 ignored,
1.37s after8.89s build (session50225 exit0,
authority-single-check.7E8Tdq/publication-current-source.log), with the same
three gas values. Full updated Authority binary passes63/0 failures/1 explicit
exporter ignored,27.95s (session25043 exit0, authority-full.log). Final
no-default-features check passes (session97910 exit0, no-std.log).

To reproduce the physical publication regression, build the current Authority
ELF from examples/actors with the locked guest toolchain as above, using disk
target/TMPDIR. Set AUTHORITY_CANDIDATE_ELF to it and
AUTHORITY_PUBLICATION_FIXTURE to a new directory under that disk scratch root.
From the worktree root, export then execute:

```sh
cargo +nightly-2025-05-09 test --locked --offline -p system-authority \
  tests::export_signed_genesis_publication_fixture -- --ignored --exact
cargo +nightly-2025-05-09 test --locked --offline -p vos --features agent-runtime --lib \
  agent::execution::tests::compiled_authority_publication_matches_native_state_and_retry \
  -- --ignored --exact --nocapture
```

The exporter refuses an existing output directory, and the execution test
fails on missing artifacts. Do not substitute the default pvm-only feature.

IMPORTANT: actual compiled Authority publication currently FAILS. Added explicit
signed fixture export (test export_signed_genesis_publication_fixture; env
AUTHORITY_PUBLICATION_FIXTURE must name a new directory) and PVM regression
compiled_authority_publication_matches_native_state_and_retry. Export passes
1/0 failures,63 filtered,0.30s (session66717 exit0), preserving configuration,
pending Linear5606 bytes, expected published Linear12102 bytes, canonical
provision3279 bytes, decision237 bytes, context and authorization. Fixture:
shared target/task-tmp/authority-blob-guest.GC8HWn/publication-fixture.
It retains the original synthetic post-state certificate fixture limitation;
this is not real root-backed finality evidence.

Guest phase0 missing blob returns Done with gas994035172 and unchanged pending
state. Phase1 valid publication faults with gas971347736 before comparison;
expired retry phase2 is NOT reached. First failure session78055 exit101,
publication-execution.log; opt-in test diagnostics reproduce (session64270
exit101, publication-fault.log): Fault(4277981184)=0xfefcd000,
SP4277984184=0xfefcdbb8. The canonical actor linker declares64KiB stack
(.rodata0x10000); standard layout maps it at0xfefd0000..0xfefe0000, so the
fault and SP are below its lower bound, consistent with stack exhaustion.
No guest panic diagnostic was emitted. Identify large stack frames next;
do not call native publication tests or successful loading proof of usability.
VOS_TEST_INNER_DIAGNOSTICS enables bounded guest debug/raw failure output only
in tests; production still discards it. All earlier bundle qualification is
unchanged, and no release pin or resource limit was raised to hide this failure.

Post-reference-consumer full Authority suite passes63/0 failures/0 ignored,
32.02s (session60168 exit0), including reservation/restart/capacity tests;
log shared target/task-tmp/agent-blob-guest.9PXZOd/authority-full.log.
The actual updated system-authority also builds locked/offline for RISC-V
with nightly-2026-03-20 and two jobs in37.46s (session3454 exit0). Isolated
disk target/evidence: shared target/task-tmp/authority-blob-guest.GC8HWn.
ELF target/riscv64em-vos/release/system_authority.elf SHA256:
`6c50fb115e2bfef25c340aee12aa32c8175c617476fa03e24ec5954fb4e190d6`.
No package or bundle replaced. This is guest build evidence, not successful
publication execution or independent reproduction of a sealed generation.
Explicit candidate-loader regression links that ELF to1044604 PVM bytes,
below the1280KiB program ceiling, and loads it in the real inner machine.
Pass1/0 failures/0 ignored,1644 filtered,0.74s after33.87s build
(session67971 exit0, authority-blob-guest.GC8HWn/loader.log). Reproduce with
AUTHORITY_CANDIDATE_ELF set to the ELF above and `cargo +nightly-2025-05-09
test --locked --offline -p vos --features pvm --lib
agent::execution::tests::compiled_authority_candidate_fits_inner_loader
-- --ignored --exact --nocapture`, using the disk-backed target/TMPDIR.
Missing artifact fails explicitly. Loading does not execute publication or
establish state-capacity feasibility.

Publication's public message now carries authorization, provision_hash and
provision_len instead of inline provision bytes. The boundary rejects malformed
IDs/context and above48KiB references before lookup; loads only invocation
availability; verifies exact length/hash; then calls the existing canonical
signed-Create/publication validator. No inline/ambient fallback is retained.
Native regression explicitly injects its loader and checks missing/corrupt data
leave pending state unchanged, oversized references do not invoke the loader,
valid publication succeeds, and an expired exact retry survives restart.
Both publication regressions pass2/0 failures/0 ignored,61 filtered,0.31s
(session9431 exit0; publication-reference-fixed.log under shared
target/task-tmp/agent-blob-guest.9PXZOd). Initial compilation caught the older
generated-message fixture field; corrected it and preserved the failed log.
The full public Authority guest/host route is not qualified by these handler
tests. Provisions above48KiB, archive/guest capacity, native issuance/finality,
and generation sealing/reproducibility remain unresolved.

Rust actors now have Context::invocation_blob(&clean BlobRef). It requires
clean invocation context, bounds allocation to48KiB before ECALL, distinguishes
absent data from errors, and verifies returned length/content. Native handlers
explicitly return UnsupportedHost rather than acquiring an ambient store.
Extended protected agent-yield fixture and compiled execution regression pass:
36KiB blob success, missing availability, wrong length and oversized reference,
all with unchanged Local state, alongside the existing maximum-message query.
Pass1/0 failed/0 ignored,1643 filtered,0.15s after57.16s host build
(session19791 exit0). Guest rebuild passes2.19s (session24300 exit0) after fixing
an overlong role-ID literal; original failure retained. Evidence in shared
target/task-tmp/agent-blob-guest.9PXZOd/{build.log,build-fixed.log,execution.log}.
Guest ELF SHA256:
`3933823bc829714af7c03f130f435569f79ddd8f44927a01a46249be376c4159`.
This closes the compiled Rust blob-consumer prerequisite, not publication
integration, capacity reconciliation, full native Shared or artifact repinning.

Inner PREIMAGE_LOOKUP is now implemented against only invocation availability.
Registers carry hash pointer/output pointer/capacity; success returns full byte
length, absent returns HOST_NONE, short capacity returns HOST_FULL with no copy.
Capacity is bounded48KiB. Key reading costs32 work bytes and one FETCH call;
selected content is charged twice its length before hash verification/copy.
FETCH counters already persist across continuations; their new ceilings20 calls
and165763 bytes cover five framed inputs/probes plus four caller keys and total
48KiB verification/copy. No guest-state, message or availability bound increased
in this step. Real assembled PVM tests verify36KiB copy, absent data, short
buffer, repeated-lookup OutOfGas and preserved failure state. Executor suite
passes18,0 failures,1 artifact-dependent ignored,1625 filtered,0.01s after40.30s
build (session81959 exit0). Log: shared target/task-tmp/
agent-input-guest.9TjFzK/preimage-execution.log. Actor convenience API, compiled
Rust blob-consumer test, publication integration, and generation/repro/repin
remain outstanding. This is not native Shared release qualification.

Compiled Rust input-boundary regression now passes:1 passed,0 failed,0 ignored,
1642 filtered,0.04s after21.85s build (session86294 exit0). The exact disposable
ELF below is linked by link_elf_spi and executes with a protected clean context.
Largest natural dynamic archive is16377 bytes (payload16327); the next payload
size crosses16KiB because of archive alignment. The guest returns the correct
length and preserves canonical Local state. Both the next natural message and
an explicit16385-byte message reject at invocation validation. This corrects
the earlier requirement for an exactly16384-byte archive, which this encoding
cannot represent. It does not qualify large Authority state, blob lookup,
native Shared finality, or a reproducibly repinned release. The explicit ignored
test fails on a missing AGENT_INPUT_PROBE_ELF; instructions are in the fixture
README. Prior fixture-build paragraphs below describe their then-pending state.

The updated agent-yield input probe now builds for the real RISC-V target with
nightly-2026-03-20, locked/offline cargo actor, two build jobs and disk TMPDIR.
Isolated target/evidence directory in the shared target:
`task-tmp/agent-input-guest.9TjFzK` (217MiB); build.log records27.13s and exit0
(session57768). ELF is `target/riscv64em-vos/release/agent_yield_probe.elf`
inside that directory, SHA256
`b42463f2ffdd0ad668249367309c9cc4127ced5f2343a026a11cdb707c023d82`.
No prior target/package was replaced. Next link this exact ELF with
vos_pvm_compiler::link_elf_spi and execute the full16KiB actor message under
the protected clean context. Build success alone does not close execution or
reproducibility; this is an unqualified disposable fixture, not a release pin.

Extended the existing non-system agent-yield fixture with a read-only
`input_len(Vec<u8>)` LocalQuery using the same explicit deployment actor role.
Its small length reply isolates large input decoding from reply capacity, and
the README requires sizing the complete actor message to16KiB, checking one
byte over and unchanged Local state. Locked/offline host type-check passes2.07s
(session41848 exit0, `agent-yield-input-probe-check.log`). No new fixture package
was introduced and no retained yield package replaced. Compilation to PVM and
physical execution remain outstanding; this is only fixture preparation.

Full clean resolver regression accepts a validated16KiB SDK message with its
execution artifacts and a36KiB caller blob. The resolved inner invocation keeps
the message and only the caller blob; program/schema/policy remain separate.
Invocation-local lookup returns those exact caller bytes. Missing program
rejects InvalidAvailability;16KiB+1 fails SDK validation and inner resolution.
Pass1/1,1641 filtered,0.00s after27.05s build (session2007 exit0,
`clean-resolver-message-availability.log`). This closes the resolver-specific
check, not policy authorization of that opaque message, guest blob API wiring,
compiled Rust actor execution or artifact qualification.

Follow-up source checks after message/FETCH alignment: vos no-default-features
check passes1.80s (session86151 exit0, `clean-message-fetch-no-std.log`). Existing
clean execution SDK schema/policy/hash-domain regression passes1/1,1640 filtered,
0.01s (`clean-message-artifact-boundary.log`, command exit0). This checks schema,
policy and authorization boundaries; it does not itself exercise full invocation
availability resolution or a16KiB compiled Rust actor call. Those and artifact
qualification remain open; no new release qualification is inferred.

Actual inner ECALL regression now fetches three lanes totaling48KiB, exact clean
control and a16KiB message using the guest's256-byte probe followed by an exact
retry for each larger frame. The assembled program completes with Done rather
than exhausting native FETCH work; unchanged over-limit lane assertions still
reject48KiB+1 and99200 bytes. Pass1/1,1640 filtered,0.01s after22.79s build
(session44676 exit0, `clean-inner-maximum-fetch.log`). This exercises real inner
machine FETCH dispatch, not only budget counters, but is not a compiled Rust
actor allocator test or reproducible runtime/actor bundle qualification.

Source cutover fix aligns MAX_EXECUTION_MESSAGE_BYTES with the existing clean
SDK16KiB message ceiling; the guest fetch path already uses this constant.
The shared256-byte probe constant now ties guest fetch_owned to host budget
accounting. FETCH budget67331 covers three lane tags,48KiB aggregate lanes,
512-byte control,16KiB message and five256-byte sizing probes. All17 PVM-enabled
executor tests pass (session96620 exit0, `clean-message-fetch-alignment.log`),
including exact message acceptance/one-byte-over rejection and all maximum
frames plus probes exhausting the budget exactly. Actor state/availability
remain48KiB and reply size remains8KiB. This changes runtime/guest semantics in
uncommitted source: coordinated generation sealing, compiled-guest tests,
reproduction and repin remain REQUIRED before qualification or deployment.
The frozen e20cbb76 artifacts are unchanged.

Clean-path follow-through confirms limits cannot be repaired at one dispatcher:
`StandardRuntime::resolve_clean_invocation` separates authenticated execution
artifacts from caller inputs, builds ActorInvocation, then calls its validator.
That applies the inner8KiB message/four-blob/48KiB availability limits even
though the SDK InvocationWork message ceiling is16KiB. Actor-state preparation
also checks the48KiB aggregate lane limit before run_inner_actor; lifecycle
state validation checks it separately. SDK caller availability intentionally
matches48KiB, and actor-storage documentation describes a256KiB guest heap.
Therefore this is a coordinated boundary/heap/contract reconciliation issue,
not evidence that changing one old constant safely enables4MiB actors. The
invocation-local preimage helper receives only caller availability after
execution-artifact role separation; no ambient store is needed for that path.

PVM-enabled executor regression now directly confirms the lane-boundary gap.
A valid assembled program runs with clean AIC1 context and exactly48KiB input
lane state; the same program/context rejects48KiB+1 and99200 bytes as InvalidInput,
although both fit the outer4MiB cap. Pass1/1,1638 filtered (session88518 exit0,
`clean-inner-state-boundary-pvm.log`, build1m23s). The first default-feature
command selected zero tests because the test is pvm-gated; its separate log is
preserved and is not qualification evidence. The test exercises the real inner
executor boundary with a tiny program, not the compiled Authority actor or its
allocator limits. No limit, host call or artifact was changed.

Physical-limit audit: `execution.rs` sets individual/aggregate actor lanes and
aggregate availability to48KiB, FETCH work to64KiB; `run_inner_actor` checks lane
size before running the guest even with a clean context. These are separate
from the4MiB outer runtime/Authority archive cap. Existing native-handler
reservation/capacity tests therefore do NOT prove compiled-guest capacity. The
99200-byte host fixture must not be described as guest-executable.
Reconciliation requires physical execution
qualification, not merely choosing a bigger archive ceiling. No limits changed.
Lookup tests now independently reject a single blob one byte over48KiB and two
individually valid blobs exceeding aggregate48KiB, while accepting the exact
single-blob boundary. Both lookup tests pass2/2,1440 filtered (session71824 exit0,
`invocation-preimage-byte-limits.log`). Future dispatch must charge work before
copy/hash and preserve continuation budget accounting; it is not wired yet.

Added the executor-side `ActorInvocation::available_preimage` primitive for the
large-provision transport path. It only reads this invocation's availability,
checks collection bounds/canonical order, matches the full requested hash/length
and verifies the selected bytes. Complete invocation authentication remains the
caller's prerequisite. A36KiB carried blob is readable despite the smaller
message limit; absent/cross-invocation lookup misses, while wrong length,
tampered bytes, duplicate hashes and excessive entry count reject. Targeted
test passes1/1,1440 filtered (session90799 exit0,
`invocation-preimage-boundary.log`). This primitive is not yet exposed through
the inner-machine dispatcher or guest Context API; no host call/ABI permission
or artifact was changed. Never treat this lookup as an authorization grant.

Consolidated formatted-source checks: full Authority actor63 passed,0 failed,
0 ignored in102.22s (session23618 exit0, `authority-publication-consolidated.log`);
all genesis11 passed,0 ignored in0.05s (session48759 exit0,
`genesis-consolidated.log`); vos no-default-features check passes4.58s
(session51948 exit0, `genesis-bound-no-std.log`). Formatting was restricted to
new/touched sections and the new publication module. These changes remain
uncommitted and are not a bundled guest or full native Shared qualification.
Next integration boundary: invocation-bound large-provision transport, then
native issuance/authenticated finality and owner/transport identity handling.

Blob-transport feasibility audit: `Context::blob_get` belongs to ExtensionCtx,
explicitly unavailable to PVM actors. Inner clean actor execution in
`vos/src/agent/execution.rs` supplies exactly five sequential FETCH frames
(Linear, Merge, Local, invocation context, message). Its host-call dispatcher
supports GAS/FETCH/GROW_HEAP/debug and the configured crypto precompile, with
all other calls rejected; the service `preimage_lookup` wrapper is not usable
here. Thus native publication cannot merely replace the inline provision with
a blob reference and reuse Context::blob_get. The next transport step must
provide deterministic access to invocation-bound availability at the inner
actor boundary (with corresponding guest/runtime qualification), or a bounded
authenticated chunk protocol. No ABI or host-call permission was changed in
this audit. Do not use ambient host/network lookup as replay evidence.

Transport-boundary regression confirms an integration gap: a valid256-member
Shared roster (one voter,255 observers) canonically round-trips at35947 bytes,
already exceeding the16384-byte InvocationWork message limit before enclosing
proposal/evidence or actor-message framing. The inline `publish_genesis`
prototype cannot cover the supported roster limit. Native publication must use
bounded blob availability/reference or a reviewed chunk protocol; do not raise
the invocation limit or count the one-replica storage fixture as full transport
coverage. Host regression passes1/1,1439 filtered,0.01s after1m11s build
(session81498 exit0, `genesis-roster-transport-bound.log`).

Real admission-budget regression now enrolls32 independent Admin credentials
and issues distinct Shared Creates through generated actor messages. It admits20
pending Creates, then denies the next atomically: archived state99200 bytes,
publication reservations3562720, terminal reservations380800. This is below
the4MiB combined limit but insufficient for another complete reservation; retry
and agent count limits are not exhausted. Save/reload preserves exact approvals
and the denial. A signed acknowledgement for one admitted Create succeeds and
the exact previously denied call then succeeds without changing its sequence.
Targeted test passes1/1,62 filtered,27.82s (session88716 exit0,
`authority-publication-capacity-admission.log`). This exercises actual admission
budget exhaustion, not a4MiB materialized archive or max-sized publications.

Two independently enrolled Admin credentials now exercise simultaneous Shared
Create reservations. Equal-shape signed requests reserve twice the publication
and terminal bytes; combined budget edge passes and one byte over fails.
Both exact approvals survive Linear restart. Acknowledging one releases only
its reservation while the other approval remains replayable; acknowledging the
second releases the remainder. Targeted test passes1/1,61 filtered,1.10s
(session75923 exit0, `authority-publication-multiple-reservations.log`). This
tests reservation accounting and signed acknowledgement handling, not two
replay-backed publications or an actually filled near-capacity actor archive.

Shared Create terminal byte reservation is now included in the common state
budget check. It covers the complete new live ManagedAgentRow (including replica
and proof-system vectors) and LatestManagementAckRow, exact retained call,
the16KiB canonical MAA2 ceiling and alignment. It conservatively takes no credit
for removed pending/previous-ACK rows. Publication leaves this reservation intact;
Create acknowledgement removes it with the pending record. The signed fixture
checks observed terminal growth is covered, retention after publication, release
after ACK and exact combined-budget edges. Full actor suite passes61/61,
0 ignored,68.63s (session65465 exit0,
`authority-publication-terminal-budget-full.log`). Maximum-roster and multiple
simultaneous pending/capacity integration still require coverage; this does not
reserve terminal bytes for unrelated lifecycle/Private operations.

Pending Shared Creates now reserve publication bytes through the common state
integrity/size check: bounded clean provision plus exact retained call/approval,
archived row size and alignment. Every state update must preserve the remaining
reservations, so unrelated operations cannot spend those bytes. Once the row is
published it is charged as actual state instead. Create approval uses a cloned
candidate and returns no approval if reservation cannot fit. The signed fixture
checks reservation covers observed growth, exact budget edge acceptance,
one-byte-over and usize overflow rejection, and release after publication/ACK.
Full actor suite passes61/61,0 ignored,68.65s (session4520 exit0,
`authority-publication-budget-full.log`). Terminal acknowledgement growth is
still NOT reserved; worst-case multi-pending/capacity integration remains open.

Introduced `MAX_CLEAN_CREATE_GENESIS_PROVISION_BYTES` from the canonical
AJI4/AWRK CleanManage/Create framing, bounded descriptor/receipt, empty runtime
lanes, fixed runtime binding and existing proposal/roster/evidence/decision
limits. The Authority publication boundary now uses this Create-specific bound
instead of the generic invocation-sized provision ceiling. Counting complete
descriptor/receipt limits where only their bodies are embedded is conservative.
The signed publication/restart/acknowledgement test still passes1/1,60 filtered,
0.87s (session44582 exit0, `authority-publication-create-bound.log`), asserting
the fixture fits and the new bound is below4MiB. This does not yet reserve total
archive/terminal bytes before approval or prove maximum-roster integration.

Sizing evidence from the signed one-replica fixture: archived pending state5600
bytes, published12096, finalized12184; publication adds6496 bytes and terminal
acknowledgement adds88. Provision3279, retained call1518, approval1564 bytes.
The generic provision wire ceiling is6343068 bytes, exceeding the4194304-byte
state budget. Reserving that generic ceiling cannot work; derive a tighter
Create-specific bound, including replica/QC limits, archive overhead and
terminal state, before introducing admission reservations. These small-fixture
numbers are not worst-case estimates. The test also reloads the acknowledged
state and verifies the retained decision remains readable. Pass1/1,60 filtered,
0.82s (session73778 exit0, `authority-publication-sizing.log`).

Full current actor regression now passes61 tests,0 failed,0 ignored,0 filtered
in68.63s (session51738 exit0, `authority-publication-full.log`), including both
publication tests and the reservation fix. This is host actor coverage, not a
new bundled guest qualification.

Capacity audit: Create admission already counts live plus pending agents
against256; no production managed-agent removal exists in this actor. Thus a
separate publication row-count reservation is not presently demonstrated to be
necessary for reachable states. Byte capacity is different: the4MiB SDK runtime
state cap is enforced by `computed_state_integrity_commitment`, while each new
publication retains full call, approval and provision bytes. There is no
pre-approval byte reservation. A sizing/admission solution must guarantee
publication and terminal acknowledgement capacity before Shared Create is
approved; publication-time atomic rejection alone does not close that gap.

Reservation audit found and fixed a missing publication-ID exclusion in
`private_application_invocation_is_unreserved`. The signed publication fixture
now checks retained-ID reservation after restart and Create acknowledgement:
Admin, either management/operation pair position, and Private application must
reject the publication ID; a fresh ID remains available. The focused test
failed specifically at the Private reservation assertion before the fix
(session4182 exit101, `authority-publication-reservation-repro.log`) and passes
afterwards (session70313 exit0,1 passed/60 filtered,0.76s,
`authority-publication-reservation-fixed.log`). Final state uniqueness already
included publication IDs; this fixes early admission, not an observed committed
duplicate. Its allocation estimate now also includes publication rows. The
initial test-edit compile failure is preserved separately in the `before` log.

Positive signed storage coverage now passes: a real credential-authorized Shared
Create and signed receipt/QC publish a decision, retain it across Linear
save/reload, and allow exact retry after expiry and after a signed application
acknowledgement removes the pending Create. The same valid provision rejects
wrong actor, wrong mode, wrong invocation and expired first publication without
changing state. Targeted test passes1/1,60 filtered in0.77s (session87853 exit0),
`authority-publication-positive-final.log` in the evidence directory below.
This signs a synthetic post-state claim, not a native replay proof. The fixture
aligns logical ownership with the transport-key principal; ordinary distinct
owner/transport identities still need end-to-end reconciliation because the
genesis roster binds principal to transport key while Authority enrollment
checks node ownership. The first fixture failure was an unenrolled node chosen
by the old owner-derived helper; its log is preserved. No production predicate
was weakened to admit the fixture.

Added a direct generated-message regression for malformed publication while a
Shared Create approval is pending: no context, normal context, wrong actor and
wrong mode all leave the state unchanged. Zero invocation is checked at the
publication function boundary because the public Context setter rejects it
before dispatch. Saving/reloading the Linear lane retains the exact pending
approval and no publication. Targeted test passes1/1,59 filtered in0.20s
(session70408 exit0), `authority-publication-rejection-fixed.log` in the evidence
directory below. The original failing harness log is preserved: it attempted to
inject a zero invocation through the validating setter. These malformed-input
cases do not independently prove each context check or successful publication.

The separate, uncommitted publication prototype now passes the locked/offline
host library check with nightly-2025-05-09. Fixed the SDK MethodMode import and
the mutable receiver required by the explicit Linear decision method. Its new
state field requires actor state version18; schema tests now cover the two new
Linear methods and that generation. The first actor regression run completed
57 passed/2 failed, both stale schema expectations; the corrected full rerun
passed59 tests,0 failed,0 ignored in67.77s (session73094 exit0). The result
is recorded in `authority-publication-regression-fixed.log` under the shared
target's `task-tmp/final-review-release.HbPbex` evidence directory.

This is NOT a qualified actor or a completed Shared path. Native publication
replay coverage, capacity admission, committee history and native
provider/authenticated finality integration remain outstanding. No artifact
repin, merge or push was performed. Keep this prototype out of the frozen
e20cbb76 review/test checkpoint; do not deploy the dirty working tree as that
release.

### 2026-09-20: exact genesis-publication invocation identity

`AgentGenesisProvision::publication_invocation` derives a distinct-domain ID
from the ABI, nonzero retained authorization invocation and complete canonical
provision. It validates structural consistency but does not verify signatures
or grant publication rights. The clean signed fixture checks exact decode/reopen
stability, separation from authorization/acknowledgement IDs, changed authorization
and provision separation, and zero-authorization rejection. Genesis10/10 pass
(session59232 exit0,0 ignored,1429 filtered,0.09s), with formatting/diff checks
passing. Log: shared
`target/task-tmp/final-review-release.HbPbex/genesis-publication-identity.log`.
The Authority still needs to retain and collision-check this ID as part of
durable publication; this derivation alone does not implement those operations.
Qualified release and artifact pins remain unchanged.

### 2026-09-20: pending clean Shared Create admission prerequisite

`AgentGenesisProvision::verify_pending_create_at` validates the full provision,
requires clean Shared Create, and binds its exact authorization plan, signer,
system-Agent identity and receipt selectors to an independently selected pending
call/approval. It verifies the credential signature, receipt signature at the
genesis observation slot, publication-time liveness, and QC against the trusted
committee using the caller's verifier. Publication before the recorded genesis
observation rejects. Existing durable exact publication retries must bypass
fresh admission only by reopening their exact retained record, not by weakening
expiry checks. This method itself neither retains a decision nor grants finality.

A clean-generation fixture with real Ed25519 credential/receipt/QC signatures
passes using distinct authorization73/issuer7 clocks. Wrong timing, forged call,
changed approval and wrong committee reject. All10 genesis tests pass
(session28079 exit0,0 ignored,1429 filtered,0.08s). No-default-features library
check passes (session37415 exit0,2.63s), and pinned formatting/diff checks pass.
Evidence: `pending-genesis-admission-check.log` and
`pending-genesis-admission-tests.log` under shared
`target/task-tmp/final-review-release.HbPbex/`.
This is a library admission prerequisite, not a wired publisher or a production
Shared creation success. Actor durable state/methods, provider issuance,
authenticated retrieval and replay-backed finality still require integration.
The qualified e20cbb76 executable/artifact pins remain unchanged.

### 2026-09-20: reusable pre-publication receipt/approval binding

The SDK's existing `receipt_matches_approval` comparison is now public for
pre-publication admission; its predicate and existing acknowledgement caller
are unchanged. Documentation explicitly separates this comparison from shape,
signature, validity-window and retained credential-call verification. A new
regression confirms that changing only the issuer decision sequence does not
change the comparison (it is not the actor authorization clock), while signature
verification still rejects that unsigned change. Agent/request substitutions
reject. Full SDK167/167 tests pass (session51078 exit0,0 ignored,0.07s); formatting
and diff checks pass. Log: shared
`target/task-tmp/final-review-release.HbPbex/receipt-approval-binding.log`.
No actor publisher is wired yet and no artifacts were repinned.

### 2026-09-20: Authority strict-backend QC regression passes

A test in the nested Authority actor uses its existing
`Ed25519CredentialVerifier` with `AuthorityQuorumCertificate::verify_with`.
A real signed AgentGenesis-domain claim verifies; altered signature and
substituted claim reject. Targeted test1 passed,0 ignored,58 filtered,0.02s
(session69539 exit0). Nested formatting/diff checks pass. Initial test compile
failed because an infallible claim constructor was incorrectly unwrapped;
the two test-only calls were corrected. Both logs remain under shared
`target/task-tmp/final-review-release.HbPbex/`:
`authority-genesis-backend.log` and `authority-genesis-backend-fixed.log`.
This is native actor-library coverage, not a compiled PVM execution or durable
publication test. Production actor methods/state, artifacts and qualified
release remain unchanged; no publication/finality completion is claimed.

### 2026-09-20: no-std caller-supplied certificate signature backend

The Authority guest does not enable vos `std` or `agent-runtime`, so the default
QC Ed25519 backend fails closed there. Enabling `agent-runtime` merely to obtain
cryptography would also select unrelated infrastructure runtime features.
`AuthorityQuorumCertificate::verify_with` now accepts the trusted caller's strict
signature backend while retaining committee/binding/epoch/quorum/signer/claim
checks in the shared implementation. Existing `verify` delegates to it with
the unchanged default backend. `AgentGenesisEvidence::verify_certificate_with`
adds the same exact-space validation as its default-backend counterpart.

Real-signature tests exercise positive backend dispatch, rejection by the
backend, and wrong-committee/space rejection before dispatch. Genesis9/9
(session57842 exit0) and committee14/14 pass, with no ignored tests; the
no-default-features library build passes (session22252 exit0). Logs under
shared `target/task-tmp/final-review-release.HbPbex/`:
`genesis-certificate-backend.log`, `committee-certificate-backend.log`,
`certificate-backend-no-std.log`. No guest execution is claimed by those host
tests/builds. The hook is not yet connected to an Authority publication method;
permanent publication and independent replay-backed finality remain required.
No artifact was repinned; the e20cbb76 qualified release is unchanged.

### 2026-09-20: scoped ordinary-genesis certificate verification prerequisite

`AgentGenesisEvidence::verify_certificate` now checks structural consistency,
exact claim-space equality with an independently supplied trusted committee,
and the existing QC verifier's binding/epoch/committee/claim/signature checks.
It returns no admission capability and is explicitly not publication or finality.
The target Agent replica roster must not be substituted for the system authority
committee. Real Ed25519 regression coverage accepts the correct committee,
rejects a different committee and substituted claim, and rejects cross-space
evidence even when the underlying QC signatures are valid for that committee.
All9 genesis tests pass (session23260 exit0,0 ignored,1429 filtered,0.03s),
including the existing independent-finality gate regression. Pinned-host fmt
and diff checks pass; no-default-features library check passes (session62732
exit0,2.46s). Logs: `genesis-certificate-admission.log` and
`genesis-certificate-no-std.log` under shared
`target/task-tmp/final-review-release.HbPbex/`.

This helper is not yet called by a production publisher. Durable exact-decision
publication, provider issuance and authenticated retrieval/finality remain
unimplemented. The qualified release remains frozen at e20cbb76 and does not
include this new helper. No guest artifact repin or branch integration occurred.
Authority actor baseline at d1b1cdc7 also passes58/58 in119.87s (session9460
exit0; `authority-baseline.log` in the same directory).

### 2026-09-20: ordinary genesis catalog rejection coverage

Extended the existing ordinary genesis catalog regression to reject an empty
catalog, duplicate runtime entries, and an internally valid replacement package
whose hash differs from the proposal's exact committed reference. Existing
corrupt-preimage coverage remains. All8 genesis tests pass (session62428 exit0,
0 ignored,1429 filtered,0.02s), including the independent-finality negative
test. Formatting and diff checks pass. Log: shared
`target/task-tmp/final-review-release.HbPbex/genesis-catalog-negatives.log`.
This is test-only coverage after the frozen review checkpoint; production
code and the qualified executable/artifact pins are unchanged. It does not
implement ordinary Shared issuance, permanent decision publication or finality.
Include it with batch2 if reviewing the later tip; full-suite evidence above
retains its original source boundary.

### 2026-09-20: explicit compiled external-transfer fixture passes

At `ab7fb7bb`, `just check-probe-fixture` completes successfully (session30453
exit0). The recipe builds the probe with its nested pinned actor toolchain and
`cargo actor --locked`, then explicitly selects the normally ignored
`node::tests::dispatch_routes_external_transfers_only_after_commit` test.
Result:1 passed,0 failed,0 ignored,1436 filtered in0.38s; host test build42.31s.
Offline dependencies, shared target and disk-backed TMPDIR were used. Log:
`target/task-tmp/final-review-release.HbPbex/probe-fixture.log` in the shared
target. This is nonzero artifact-dependent coverage, not a pass for the whole
`check-all` recipe. No implementation changes were made.

### 2026-09-20: final-release logs confirm the latency concentration

Read-only analysis of `current-latency.KD6UwR/{up,mutation-up,read-up}.log`
finds45 complete eight-phase Authority query sequences. Each sequence was
checked in prepare/reserve/identity/persist/reopen/invoke/acknowledge/complete
order. Timings are cumulative within two separate clocks: subtract the prior
phase, resetting at prepare and reopen. Summing raw elapsed fields is invalid.
Incremental totals in milliseconds: prepare3793, reserve13795, identity3270,
persist1827, reopen4073, invoke59665, acknowledge33811, complete1644;
total121878. Invoke+ACK is76.70%; persistence+clear is2.85%. These are host-plus-
guest phase spans, not pure CPU samples or a controlled before/after benchmark.
Post-Install inventory takes16275ms and route reconciliation16999ms. Its six
serial query durations total16272ms. An unchanged-head credential-only refresh
takes2986ms (route3252ms). The final host decode cleanup has not removed the
dominant repeated execution cost. Do not infer that weakening authentication,
retirement, or readiness checks is an acceptable optimization.

### 2026-09-20: final-source CLI regression passes

At frozen `93e63c5f` (documentation-only changes since release sourcee20cbb76),
the complete CLI binary suite passes255 tests,0 failed,19 ignored,0 filtered
in81.76s (session57739 exit0). Command:
`cargo +nightly-2025-05-09 test --locked --offline -p vosx --bin vosx -- --test-threads=1`.
Shared target, disk-backed TMPDIR, RUST_TEST_THREADS=1, RAYON_NUM_THREADS=2,
and localhost socket access were used. Log: shared
`target/task-tmp/final-review-release.HbPbex/cli-suite.log`.
Ignored live campaigns are not coverage from this command; the explicit fresh
Counter mutation/read campaigns below provide their own separate evidence.
This closes the final host-fix CLI regression gap, not the remaining production
gates or all workspace integration tests. No implementation changes were added.

### 2026-09-20: final review release passes fresh Local lifecycle

Release source `e20cbb76`, SHA-256
`d11e52eed2e917a53e025536972f375363d30355d602dee2e9e23a3f6950e2cc`,
passes the fresh `current-latency.KD6UwR` probe (session62056 exit0). Evidence
is under shared `target/task-tmp/current-latency.KD6UwR/`; stores remain there.
Create29s, Install38s, first readiness16s, restart readiness20s/26s. Counter
mutation and read-after-restart each pass, including positive retirement and
exact retry. Attempt timings are21.95s/21.88s; entire tests including retry
take23.79s/23.68s (each1 passed,273 filtered). HTTP status and SSH keyscan pass,
not authenticated shell access. Shutdowns0s/0s/1s at whole-second resolution
require no forced cleanup; subsequent listener/process checks find no daemon.

New-space system packages and HTTP/SSH defaults are automatic. Only isolated
test ports were changed to18099/2243. No old stores were copied or migrated.
The unchanged test client executable has SHA-256
`a9405e57d7aa03e9c068918c50edf37d651e2ef8369f9512ca58d93059ec88d9`.
This qualifies Local/Public-policy behavior, not the full Private/Attested
proof matrix. Readiness still fails10s; no controlled wall-time improvement
is established. Production blockers remain open, with no merge or push.

An initial fixture `final-review-live.vzPl9A` is preserved as failed evidence:
Create29s and Install37s passed, but the mutation test rejected its directory
prefix before executing (session8295 exit101). This was harness setup error;
the existing `current-latency.` safety guard was kept unchanged. Its daemon
and listeners were confirmed gone before creating the new fixture above.

### 2026-09-19: final review-source release builds and verifies

Frozen source `e20cbb76` builds with
`cargo +nightly-2025-05-09 build --release --locked --offline -p vosx`
in7m05s (session6875 exit0), using the shared target and disk-backed TMPDIR.
The resulting executable includes the host-only startup decode fix. SHA-256:
`d11e52eed2e917a53e025536972f375363d30355d602dee2e9e23a3f6950e2cc`.
Its `release bundle --out .../bundle` and `release verify .../bundle` both pass.
Evidence: shared `target/task-tmp/final-review-release.HbPbex/`, with `build.log`,
`bundle.log`, `verify.log` and materialized `bundle/`. The prior live-qualified
binary is preserved there as `vosx-before`; its verified SHA-256 remains
`4f7f48048679b0a0ecc2283e128c7996d62e5f34d87ab1a9e1817d3aa305cd94`.
No stores were copied, migrated or reopened. Fresh live qualification of this
new executable is still pending. Guest pins are unchanged; production gates
remain open. No merge or push has been performed.

### 2026-09-19: full host-feature run exposes and fixes a status-test race

The full host-feature suite at frozen c9990ed6 terminates with1877 passed,
1 failed,4 ignored,0 filtered in1601.17s (session45034 exit101). Both complete
inventory rotation and system-attachment checkpoint tests pass. Command:
`cargo +nightly-2025-05-09 test --locked --offline -p vos --features 'agent-transition-proof private-agent-store http-ingress ssh-ingress' --lib -- --test-threads=1`.
Dependencies were offline, RAYON_NUM_THREADS=2, loopback available and TMPDIR
disk-backed. No workload was shortened or restarted. The nested1-test child
summary is not the parent suite result and is not added to its count.

The sole failure, `raft::worker::tests::status_preserves_old_voters_during_joint_consensus`,
read the cached pre-append membership. Generic worker `handle_msg` sends the
AppendEntries response before the event loop calls `publish_status`; therefore
receipt of the response is not a cache-publication barrier. The test now waits
at most1s for `last_log_index == response.match_index`, then performs its original
new-members/joint-old/old-only-voter assertions unchanged. It waits for the append,
not for the membership answer under test. This matches neighboring cached-status
tests and changes no production consensus behavior or readiness deadline.

All15 Raft worker tests pass (session87856 exit0,2.34s). The corrected test also
passes50 separate-process repetitions (session37688 exit0). Formatting/diff
checks pass. Evidence in shared `target/task-tmp/single-preflight-release.pE0Yxy/`:
`host-feature-suite.log`, `raft-status-race-fix.log`, `raft-status-race-repeat.log`.
The original full-suite failure remains preserved. The unified rerun at45ff53e0
now terminates successfully:1878 passed,0 failed,4 ignored,0 filtered in1587.02s
(session25218 exit0), using the same command and environment. Its log is
`host-feature-suite-fixed.log` in the same evidence directory. Both complete
inventory rotation and system-attachment checkpoint tests, the startup-admission
regression and the repaired Raft status test pass in this full run. The nested
one-test child summary is not added to the parent count.

The four ignored cases are the explicit real64MiB capacity diagnostic, copied-DB
decode timing probe, large-ACK profiling probe, and compiled external-transfer
fixture test (separate `just check-probe-fixture` gate). Ignored cases are not
claimed as coverage here. Guest artifacts and the a732e079 live-qualified release
executable are unchanged. This closes the pending host-feature rerun only, not
ordinary Shared finality/issuance, reclamation, remaining proof/crash coverage,
production latency/lint gates or final-source release qualification.

### 2026-09-19: native operation startup reuses its checked decode

Following33489588, `load_evidence` no longer decodes each full NOD1 dispatch
twice. A shared private helper returns the decoded record only after checking
its Authority target, invocation/file key and exact canonical re-encoding.
`native_operation_record_matches` uses the same helper, preserving its public
boolean contract. All later admission, signature, predecessor and retirement
checks remain unchanged. No cached result crosses a store read or mutation.

The physical startup regression now supplies otherwise valid record bytes under
a wrong Authority/file key and supplies truncated/trailing bytes. Each fails
closed without journal writes or advancing the owner's ordered head. Valid
before/after-policy reopen still passes. The native-operation physical selection
passes10 tests,0 failures,1 ignored in86.36s (session56270 exit0); the ignored
case remains the explicit real64MiB journal-capacity diagnostic. Log: shared
`target/task-tmp/single-preflight-release.pE0Yxy/single-decode-native-operation.log`.
Pinned-host formatting/diff checks pass.

This removes a redundant host decode while the existing full dispatch records
remain required. It does not add compaction or establish a wall-time speedup.
Runtime guest/artifact pins and the a732e079 live-tested executable are unchanged;
that executable does not include this subsequent host-only source fix.
Independently recoverable compact terminal evidence and cross-store reclamation
remain the functional dependency, not a deletion based on NRT1 alone.

### 2026-09-19: capacity retry boundary and reclamation dependencies

After65ef39e0, the existing256-record coordinator-capacity test now retains the
first/last issued results and verifies exact retries of both at capacity, before
and after reopen. Receipts/AOI1 values stay identical; dispatcher calls,
signatures, both stored images and commit counts stay unchanged. A257th new
operation still fails before side effects. All26 coordinator tests pass
(session28518 exit0,34.09s); pinned-host formatting/diff checks pass. Log: shared
`target/task-tmp/single-preflight-release.pE0Yxy/coordinator-capacity-retry.log`.
This is memory-store/coordinator coverage, not sustained live operation beyond256.

The reclamation audit identifies the existing evidence boundary precisely:
NOC1 signs two NOD1 record commitments and NRT1 signs that completion after
positive runtime ACKs. `restore_completion` / `restore_retirement` still require
both exact full dispatch records; signature verification alone is not a
self-contained consumption proof. Coordinator reopen also requires one-to-one
issuer membership and binds consumed_issuance_ack to the retained issuer AOI1.
`retire_issued` loads both dispatches before considering retirement certificates.
Thus deleting issuer/coordinator/dispatch records independently breaks current
recovery, and the completion/retirement indexes themselves remain append-only
and bounded. Invocation retirement is not a general deletion authorization.

The next implementation dependency is independently verifiable compact terminal
evidence and authenticated replay/collision fences, followed by crash-safe
cross-store reclamation and sustained >256-operation qualification. Preserve
recoverability until that evidence is durable; no automatic deletion, eviction,
limit increase, production-code or release-pin change was made in this step.

### 2026-09-19: repinned release and fresh Local lifecycle qualified

Frozen source `a732e079f7792e953434f3dfe7f83a899c8ea057` builds locked/offline
with nightly-2025-05-09 in7m14s (session31541 exit0). Executable SHA-256:
`4f7f48048679b0a0ecc2283e128c7996d62e5f34d87ab1a9e1817d3aa305cd94`.
Its release bundle/verify commands pass. Evidence directory: shared
`target/task-tmp/single-preflight-release.pE0Yxy/`, including build/bundle/verify
logs, verified `bundle/`, and `vosx-before` preserving the d4d38ebb executable
(SHA-256 `1ddcc3c99ea16c5982d7ac8f2e752cfdbf91ceb9145d34d087f1524110668a08`).

Full CLI255 passed,0 failed,19 ignored in96.44s (session88849 exit0,
`cli-suite.log`), using the current post-pin test executable SHA-256
`a9405e57d7aa03e9c068918c50edf37d651e2ef8369f9512ca58d93059ec88d9`.
CLI and release compilation overlapped with sufficient available RAM; neither
their durations nor the following distinct-history fixtures are controlled A/B
performance evidence. Both jobs finished before the live probe began.

Fresh `current-latency.bWPsi4/probe.sh` passes (session69210 exit0) using isolated
XDG roots. `space new` automatically supplies system packages and HTTP8080/
SSH2222 configuration; only test ports changed to18099/2243. No old store was
copied or reopened; only immutable Counter package bytes were reused.

Readiness16s, Create30s, Install37s, restart20s, Counter mutation21.64s,
restart26s, read21.96s. Both explicit tests pass1 test with273 filtered and
require value7, positive retirement and exact ACK retry. HTTP status and SSH
keyscan pass, not authenticated shell or full Private/Attested proof coverage.
Shutdowns0s/0s/1s at whole-second resolution need no forced cleanup. Post-probe
checks confirm no matching daemon or test listeners. Logs/new/Create/Install/
mutation/read outputs stay at the original fixture path; TMPDIR is disk-backed.

Create lifecycle9.543s is followed by route reconciliation16.518s (inventory
16.244s); post-Install inventory16.155s/reconciliation16.896s. The unchanged-head
inventory refresh is3.011s. All readiness measurements still exceed10s. The
small paired gas saving does not establish usable production latency.

Two review ranges now freeze at a732e079: batch1 unchanged; batch2 is57 files,
+6,231/-331, integrated240 files,+79,025/-59,066. Later documentation belongs
with batch2. This completes the new pin's release/Local smoke handoff, not the
remaining full saga, host-feature/proof/crash/lint or performance gates.

### 2026-09-19: reproduced PublicPreflight runtime is pinned

Following9cdc1ff1, production manifest, `STANDARD_RUNTIME_PROGRAM_ID`, vosx
build-time PVM digest and embedded `agent_runtime.pvm` are updated together to
the independently reproduced ba7be457 runtime. ProgramId
`8071ad67661c6539ab504ccecc18c9e8d6d858803b52fca05389823f8109d3cc`,
PVM BLAKE2b256 `50927c9c8e0d4daf1bb30b7f6948d197da7f53ec5f3b0e8027469b5e2b3b3776`,
984,302bytes. Source/ELF digest are the immutable reproduction values below.
System templates, actor pins and execution ABI are unchanged.

Post-pin gates pass with no candidate overrides:

- Artifact-release18 tests,0 failed,0 ignored,1.52s (session43821).
- Full bundled runtime-wire98 tests,0 failed,1 ignored,30.54s (session26450).
- `just verify-agent-runtime-release` rebuilds current guest source with the
  pinned toolchain and locked/offline dependencies, converts actual shared
  Cargo output, then requires byte equality with the committed bundle
  (session90688 exit0). This complements the two immutable-source reproductions.
- Pinned-host formatting and diff checks pass.

Logs: shared `target/task-tmp/single-preflight-reproduction.rSz92N/`, named
`post-pin-release.log`, `post-pin-wire.log`, `post-pin-source-reproduction.log`.
The existing d4d38ebb release executable is untouched and still embeds its old
pin. It and `current-latency.VF0MXp` are previous-pin evidence now. Do not boot
that or any older fixture with the new runtime. Release rebuild, bundle check
and NEW disposable Local lifecycle remain due; no live speedup or production
sign-off is claimed. This is a coordinated source/artifact repin, not a merge.

### 2026-09-19: PublicPreflight candidate independently reproduced and checked

Immutable source `ba7be4575ca060990180e0c95d7b8223c3633f59` was exported twice
with git archive into separate source/target directories, built sequentially
with nightly-2026-03-20 `cargo actor --locked` and offline dependencies.
Both ELF files match byte-for-byte; both converted PVMs match each other and
the earlier measured candidate. Session11956 exits0; builds29.84s/32.49s.

- ProgramId: `8071ad67661c6539ab504ccecc18c9e8d6d858803b52fca05389823f8109d3cc`
- ELF BLAKE2b256: `4bfc4f3e3e1cc3bb58971dc1f0cf4851305231f105278d265cd9f60568702d68`
- PVM BLAKE2b256: `50927c9c8e0d4daf1bb30b7f6948d197da7f53ec5f3b0e8027469b5e2b3b3776`

The converter is the preserved d4d38ebb release, SHA-256 checked by the runner
as `1ddcc3c99ea16c5982d7ac8f2e752cfdbf91ceb9145d34d087f1524110668a08`.
Evidence: shared `target/task-tmp/single-preflight-reproduction.rSz92N/` contains
`reproduce.sh`, `reproduction.log`, both source exports, targets, PVMs, build logs
and identity logs. No source export, older fixture or failure evidence was removed;
all temporary files were disk-backed.

Full runtime-wire suite with ACK/FAILURE/TYPED_ERROR/EXPIRY candidate overrides
passes98 tests,0 failures,1 ignored in36.26s (session1918, `candidate-wire.log`).
Those explicit override paths execute the candidate for retained-invocation
rejection, malformed ACK frames, terminal failure, typed error and expiry
coverage; other tests retain their bundled/native selection. This is not98
candidate-only tests. The prior paired PublicPreflight cost test remains the
fixed-input bundled/candidate gas comparison.

The real bundled Authority fresh Credential query/retirement regression also
passes against `first.pvm` using its existing COST_CANDIDATE override with full
host features (session6591,1 passed,1881 filtered,3.74s; `authority-query.log`).
This executes the physical outer runtime and the actual Authority actor,
not the fixture's native runtime shortcut. It is not a full host-feature run
or an end-to-end latency benchmark.

Production pins and the live-tested d4d38ebb executable remain unchanged.
Reproduction and these targeted candidate gates pass; coordinated repin and
post-pin artifact/release checks remain due before this candidate is bundled.

### 2026-09-19: candidate removes duplicate PublicPreflight commitment hash

Following08139275, `InvocationAuthorization::matches_invoke` still performs its
initial full immutable `matches_work` check. Its PublicPreflight branch now only
checks the observation-slot lower bound rather than repeating matches_work and
hashing the same work again. Receipt matching, origin/role restrictions, blob
validation, signature verification and wire encodings are unchanged.

SDK166 tests pass, including100 predicate comparisons against the previous
implementation (five authorization variants, four work variants, five slots).
No-default-feature SDK check and pinned-host formatting pass. Full PVM-enabled
runtime-wire module passes98 tests,0 failures,1 ignored in30.04s (session5841).
This includes decoded-input/corruption checks. Initial commands without `pvm`
selected0 runtime tests; those logs are preserved and are not coverage.

Pinned guest build passes (session2031,23.92s). Existing released converter
produces candidate `single-preflight-candidate.pvm`, ProgramId
`8071ad67661c6539ab504ccecc18c9e8d6d858803b52fca05389823f8109d3cc`.
The new paired physical test runs bundled and candidate programs on identical
PublicPreflight Invoke and ACK bytes with4KiB inert actor padding, requiring
complete transition-byte equality and strictly reduced gas (session94424,
1 passed,0 failed,0 ignored,0.62s):

| Operation | Bundled gas | Candidate gas |
| --- | ---: | ---: |
| Invoke | 25,637,967 | 25,272,180 |
| ACK | 23,843,674 | 23,661,467 |

Savings1.43%/0.76% are modest and do not establish an end-to-end latency gain.
The full wire suite uses the existing bundle against native source expectations;
only the explicit paired cost test executes the candidate too. Logs are under
shared `target/task-tmp/review-checkpoint-release.6a7GXF/`, named
`single-preflight-{sdk,runtime,guest,cost,cost-pvm,no-std,wire}.log`.

Production manifest, embedded artifacts and release executable remain unchanged.
This source change intentionally creates a new candidate, not a qualified repin:
current-source bundle reproduction no longer matches until artifact release work
is completed. Independently reproduce from committed source, qualify remaining
candidate paths and evaluate whether the saving warrants release work before
replacing any pin. The d4d38ebb live-tested executable remains the review/test
deployment checkpoint. No old fixture was migrated and no merge/push occurred.

### 2026-09-19: current live query phase attribution

Read-only analysis of `current-latency.VF0MXp/up.log` finds21 complete projection
sequences and0 unmatched phase records. The trace clocks are cumulative: subtract
prepare/reserve/identity/persist predecessors, then start a separate execution
clock for reopen/invoke/acknowledge/complete. Do not sum raw elapsed_ms fields.
Across those sequences the disjoint totals in milliseconds are:

| Phase | Total ms |
| --- | ---: |
| Prepare | 1,732 |
| Reserve/checkpoint | 6,931 |
| Pending identity | 1,445 |
| Persist pending record | 925 |
| Reopen/recovery identity | 1,915 |
| Invoke | 26,988 |
| Acknowledge | 15,583 |
| Clear pending record | 765 |

Total56,284ms: Invoke+ACK75.64%, reservation12.31%, pending-record persist+clear
3.00%. These span host work plus runtime execution; they are not pure guest CPU
measurements. Reservation includes potential certified checkpoint work. The
sample includes bootstrap and unchanged-head queries as well as changed-head
inventory, not just one Create. Per-query mean is2.680s; Invoke+ACK alone2.027s.

This narrows the next performance action: pending-record write optimization
cannot address most measured latency. Preserve durability and positive ACKs;
concentrate on reducing repeated execution/hash work or authenticated bounded
projection aggregation. The latter needs protocol/actor/artifact qualification,
not merely parallelizing callers or reusing inventory across a changed head.
`crypto/blake2b.rs` deliberately excludes the actor ECALL100 path when
agent-runtime is enabled: the outer runtime only permits standard PVM machine
management calls. Re-enabling that host trap is not an equivalent optimization.
No runtime code, fixture state, artifact pin or performance gate changed here.

### 2026-09-19: full current-source CLI regression passes

The current-source CLI test executable built in session74483 (SHA-256
`91c89f24a051e28705d8fe555f3507737ce6b22a291a21e7db009e53125258c4`)
passes the complete ordinary suite:255 passed,0 failed,19 ignored,0 filtered
in80.29s (session73341 exit0). It was run directly with `--test-threads=1`,
loopback access, RAYON_NUM_THREADS=2 and disk-backed TMPDIR. Source remained
unchanged apart from handoff documentation since d4d38ebb. Log: shared
`target/task-tmp/review-checkpoint-release.6a7GXF/cli-suite.log`.

Ignored tests are not counted as passes; the two explicit fresh Counter live
tests have their separate qualification below. This closes the current-source
ordinary CLI rerun gap, not the explicit host-feature suite, full integration
matrix, lint, Shared finality, proof/crash or production-performance requirements.

### 2026-09-19: current checkpoint fresh Local lifecycle passes

Release d4d38ebb (SHA-256 `1ddcc3c99ea16c5982d7ac8f2e752cfdbf91ceb9145d34d087f1524110668a08`)
passes the guarded disposable `current-latency.VF0MXp/probe.sh` (session53847
exit0). `space new` generated HTTP8080/SSH2222 configuration; only ports were
changed to isolated18099/2243. System packages required no manual installation.
Only immutable Counter package bytes were copied; no older store was reused.

Readiness16s, Create29s, Install37s, restart20s, Counter mutation21.55s,
restart26s, read21.48s. Both invocation tests assert value7, positive retirement
and exact ACK retry; each passes1 test with273 filtered. HTTP status and SSH
keyscan pass, not authenticated SSH shell or Private/Attested proof coverage.
Shutdowns0s/0s/1s at whole-second resolution require no forced cleanup; a
post-probe process/listener check confirms no matching daemon or test listeners.

Current-source test client rebuilt locked/offline with nightly-2025-05-09
(session74483 exit0,38.07s), SHA-256
`91c89f24a051e28705d8fe555f3507737ce6b22a291a21e7db009e53125258c4`.
Build log: `review-checkpoint-release.6a7GXF/live-test-build.log`.
Probe/new/Create/Install/HTTP/SSH/mutation/read logs stay in the fresh fixture
under shared `target/task-tmp/`; all temporary files are disk-backed.

Performance remains failing: Create lifecycle9.373s followed by route
reconciliation16.180s (inventory15.917s); post-Install inventory16.098s and
reconciliation16.786s. An unchanged-head refresh still costs3.054s inventory.
All readiness observations exceed the unchanged10s gate. Different fixture
histories prevent a controlled before/after comparison. No speedup is claimed.
This closes the rebuilt executable's fresh Local smoke gap, not full CLI,
host-feature, busy/crash, proof, Shared-finality or production qualification.

### 2026-09-19: current review checkpoint release builds and verifies

Frozen source `d4d38ebb704e1e024f36bf4ce98974edb526d81b` builds with
`cargo +nightly-2025-05-09 build --release --locked --offline -p vosx` in7m03s
(session18262 exit0). Only review documentation changed during the build.
The resulting shared `target/release/vosx` SHA-256 is
`1ddcc3c99ea16c5982d7ac8f2e752cfdbf91ceb9145d34d087f1524110668a08`.
Its `release bundle --out <evidence>/bundle` and `release verify <evidence>/bundle`
both exit0. Guest artifacts and production pins are unchanged.

Evidence directory: shared `target/task-tmp/review-checkpoint-release.6a7GXF/`,
containing `build.log`, `bundle.log`, `verify.log`, verified `bundle/`, and
`vosx-before` preserving the8f96fad8 executable with SHA-256
`ee49a636c477c1e3ef21d56f16e2c181307bd1e740ad20bee80b6da27e30e76d`.
Temporary files were disk-backed; no fixture was migrated or removed.
The new binary includes the host/cache/network changes, but has not yet had
their fresh live lifecycle, full CLI or explicit host-feature release rerun.
Earlier live timings and lifecycle evidence remain tied to the preserved binary.
No performance improvement, full saga completion or master sign-off is claimed.

The two review ranges now end at d4d38ebb: batch1 unchanged; batch2 is57 files,
+5,802/-330; integrated240 files,+78,596/-59,065. Later handoff documentation
belongs with batch2. No merge or push occurred.

### 2026-09-19: two-agent inventory refresh regression

On top of `50607708`, a transport-level unit regression now checks the measured
two-agent query pattern: six queries on first load, one fresh Credential query
at the unchanged complete head, six after a simulated Install advances the
transport head, then one at the new unchanged head. The refreshed inventory must
contain the installed actor despite unchanged Agent descriptors. The test changes
the transport state rather than editing the client's cache. This is mock-transport
cache/invalidation coverage, not a live Install or latency benchmark.

All 12 production-owner tests pass (session48881 exit0, 0.15s test time), using
`cargo +nightly-2025-05-09 test --locked --offline -p vos --lib agent::production_owner::tests::`.
Log: shared `target/task-tmp/decoded-input-release.RIkx3j/inventory-refresh-regression.log`.
Pinned-host formatting passes. No production code, artifacts or release pins
changed. The unchanged-head shortcut already exists; skipping the full refresh
at a changed head is not justified by that shortcut. Inventory latency remains
open, and this test supplies a regression boundary for its eventual optimization.

### 2026-09-19: full build-pvm gate uses fresh Cargo output and passes

Following `4e4cf613`, the runtime-candidate recipe uses Cargo metadata to locate
the actual guest target directory, rather than building in CARGO_TARGET_DIR and
then reading a stale hard-coded service-local ELF. Guest build and converter use
locked dependencies. The metadata lookup is isolated in a Nushell `do` block so
the host converter still runs from the root workspace. An initial unscoped
attempt failed before conversion (session10438 exit101, `build-pvm-recipe.log`);
the corrected recipe passed (session13781 exit0, `build-pvm-recipe-fixed.log`).

The registry portion exposed its stale lockfile: the generated diff adds only
the current local vos-agent-sdk/vos-protocol packages and dependency edges,
without external package upgrades. Registry now pins nightly-2026-03-20 and the
generic actor recipe uses `cargo actor --locked`, honoring each actor workspace's
toolchain rather than overriding it with moving nightly. Other actor workspaces
retain their own existing pins; this does not claim all are pinned or qualified.

The final full `just build-pvm` rerun passes (session48823 exit0,
`build-pvm-recipe-pinned.log`). It builds current runtime source, converts the
actual shared-target ELF, requires byte equality with the bundled runtime,
builds all four actor examples/custom runtime and builds the registry. Candidate
and bundle BLAKE2b256 both equal
`dfcf70ef5a335125176eb350e6fe3d857e9efc593a55860dee9761e4f2ac112f`,
ProgramId `ebed0967a4d987e2f50f6e8908b294f713b0cf74583d1b5dc6648a8a542a049c`.
This current-source comparison complements, but does not replace, the earlier
two-isolated-build reproduction. No production artifact/pin was replaced.
Logs are in shared `target/task-tmp/decoded-input-release.RIkx3j/`; the candidate
is the recipe's normal `target/agent-runtime-candidate.pvm` build output.
RUSTUP_TOOLCHAIN was unset to honor workspace pins; dependencies were offline,
and temporary files disk-backed. Formatting/diff checks pass. The complete
`check-all` result remains blocked by lint, and production functionality/latency
requirements remain open.

### 2026-09-19: probe fixture build and real outbox invariant qualified

Following `48379340`, the retained probe fixture is pinned to guest
nightly-2026-03-20 and its recipe uses `cargo actor --locked`. The first locked
build failed because the fixture's tracked lockfile was stale; it was refreshed
offline (fixture lockfile only), then the pinned build passed (session73044
exit0). Logs: `probe-fixture-build.log` and `probe-fixture-build-fixed.log` under
shared `target/task-tmp/decoded-input-release.RIkx3j/`.

Its remaining consumer, `node::tests::dispatch_routes_external_transfers_only_after_commit`,
previously read a fixed package-local ELF and returned success without executing
when missing. It now honors CARGO_TARGET_DIR and fails on missing artifact. It is
explicitly ignored in ordinary library runs, with `just check-probe-fixture`
building the fixture then selecting that exact ignored test. `check-all` invokes
this stronger build-and-execute gate instead of only building the fixture.

The full `check-probe-fixture` recipe passes (session58804 exit0):1 test passed,
zero failed/ignored,0.24s; `probe-fixture-check.log`. It verifies no outbox delivery
after failed commit and exactly one delivery after successful retry. Running the
same binary against a verified nonexistent target directory fails as expected
with exit101 and an explicit missing-ELF error (`probe-missing-negative.log`),
not a silent pass. Earlier library success alone did not prove this artifact was
executed; this dedicated run does. Ordinary library ignored counts now increase
by one, while the explicit gate executes the case.

All temporary data remains disk-backed; old fixture bytes/logs were preserved.
Root formatting/diff checks pass. Production runtime code and bundled pins are
unchanged; this is fixture/test/gate maintenance, not full release sign-off.

### 2026-09-19: full workspace library regression passes

At frozen source `23f98d4b`, the complete command
`cargo +nightly-2025-05-09 test --locked --offline --workspace --lib` passes
(session28998 exit0). Log: shared
`target/task-tmp/decoded-input-release.RIkx3j/workspace-lib.log`.
Used disk-backed TMPDIR, loopback permission, `RUST_TEST_THREADS=1` and
`RAYON_NUM_THREADS=2`. No source/pin/lockfile changes during the run.

Final per-crate summaries total2,314 passed, zero failed and5 ignored across22
library binaries. Child-process subtest summaries are excluded from the total.
Nonempty suites: vos1,516/1 ignored (198.63s), SDK165, PVM260/2 ignored,
compiler65/1 ignored, proof120, codec44, macros23, protocol12, precompiles11,
program9, Raft27, merkle-crdt22, prover-extension19, substrate-extension20/1
ignored and clerk-witness1. Seven libraries have no unit tests; their successful
empty runs are not additional test coverage.

Ignored cases: public Kreivo/Kusama network smoke; fixed-history physical decode
diagnostic; flat-memory performance smoke; prepared-program load measurement;
and exact-PC symbol diagnostic. None is counted as a pass. This qualifies current
workspace library integration after the host/network/cache cleanups, not the
separate explicit host-feature matrix, CLI binary, integration tests or nested
workspaces. Their prior results retain their recorded source boundaries. This
completes the library-test step independently, not the failing `check-all` recipe
or the outstanding production functionality/performance requirements.

### 2026-09-19: bounded replay-result cache updates verified

Following `133d4307`, the ordered and management recent-result caches replace
existing values through one `get_mut` lookup instead of contains-key plus insert.
Capacity remains1,024 entries; replacement does not refresh FIFO position or
change durable journal state. The existing bounded-handoff regression now covers
replacement at capacity, unchanged ordering, one-shot response handoff and
eviction of the same oldest entry on the next insertion.

The complete `agent::local_journal_driver::tests` selection with `--features pvm`
passes33 tests, zero failed/ignored,36.44s (session12450 exit0). Formatting and
diff checks pass. Workspace Clippy with `check-all` flags reports336 remaining
diagnostics (session82803 exit101), down from338; both duplicate-lookup diagnostics
are gone. Logs in shared `target/task-tmp/decoded-input-release.RIkx3j/`:
`cache-update-tests.log` and `lint-after-cache-update.log`.
No wire/artifact changes or measured latency improvement are claimed. This is
targeted source qualification, not a rebuilt release or a passing `check-all`.

### 2026-09-19: PVM vectors and voucher release catalog gates pass

At `4817e479`, unchanged release recipes pass with nightly-2025-05-09,
offline dependencies, shared disk-backed target/TMPDIR and serial tests:

- `just test-pvm-vectors`:20 passed, zero failed/ignored/filtered,0.22s;
  session85189 exit0, `decoded-input-release.RIkx3j/pvm-vectors.log`.
  The integration test checks the reviewed173 v0.8 semantic cases and16 block-gas
  oracle cases, corpus/opcode completeness and interpreter/JIT parity on this
  Linux/x86-64 host. The historical v0.7.2 corpus is separately labelled.
- `just verify-voucher-check-release`:2 passed, zero failed/ignored,9 filtered,
  0.48s; session47641 exit0, `voucher-catalog-release.log` in the same directory.
  Tests validate the production catalog pin and re-measure the checked-in
  released voucher PVM's blob/profile/AIR commitment. This is not the filtered
  maintenance-only current-source reproduction test or full voucher proving.

Source, production artifacts and lockfiles are unchanged. These individual
gates do not make the still-failing workspace `check-all` recipe pass.

### 2026-09-19: complete examples recipe passes after artifact-path correction

Following `c3ce5261`, `test-examples` no longer overrides the actor workspaces'
nightly-2026-03-20 pin with the moving `+nightly` alias; its four actor builds
use `cargo actor --locked`, matching the maintained build recipe.

The first full run (session33615 exit101, `examples-recipe.log`) passed actor
tests/builds, the guest entry tests and custom-runtime host tests, but failed the
explicit compiled-runtime execution check with Panic rather than Halt. The test
read its hard-coded package-local ELF (505,800 bytes, dated September12), while
the build wrote the new ELF to CARGO_TARGET_DIR (504,720 bytes, September19).
Both original files and the failure log were preserved. No fixture was relabelled.

The test now honors CARGO_TARGET_DIR and has a pure path regression covering
default, absolute and package-relative target directories. The complete recipe
rerun passes (session36911 exit0, `examples-recipe-fixed.log`):6 actor unit tests
across four crates; all four actor guest builds;5 guest-entry tests;11 custom
runtime host tests; and the explicit compiled scheduling/attested-context rejection
test (1 passed,7.23s). The compiled test remains ignored in the ordinary host run
and is explicitly executed by the recipe; empty doctest sets are not test passes.

Logs are in shared `target/task-tmp/decoded-input-release.RIkx3j/`. The run unsets
RUSTUP_TOOLCHAIN so each workspace honors its checked-in toolchain file, uses
offline Cargo dependencies, the shared target, disk-backed TMPDIR and bounded
test/prover concurrency. Root and nested formatting/diff checks pass; lockfiles
and bundled production artifacts are unchanged. This closes `just test-examples`,
not the remaining full `check-all`, Shared finality or production latency gates.

### 2026-09-19: verifier portability build gates pass

At `be0b54f4`, both unchanged recipes complete with exit0 using
nightly-2025-05-09, offline Cargo dependencies and the shared disk-backed
target/TMPDIR:

- `just check-pvm-proof-no-std`: proof crate without default features and the
  standalone verifier build,1.23s/0.24s (session76266).
- `just check-pvm-proof-wasm`: the existing wasm32-unknown-unknown target is
  reported up to date, then the verifier cross-build passes in1.34s (session86619).

Logs: shared `target/task-tmp/decoded-input-release.RIkx3j/pvm-proof-no-std.log`
and `pvm-proof-wasm.log`. These prove the specified build configurations, not
WASM execution, target performance, or full Private/Attested proof coverage.
No runtime source or artifact pins changed; both processes are terminal.

### 2026-09-19: fast PVM proof recipe passes

At `2c340623`, `just test-pvm-proof-fast` completed unchanged with exit0
(session2436). It ran120 library tests (2.27s),1 add64 end-to-end test (2.06s),
15 control-flow tests (29.13s), and7 memory tests (21.98s), with zero failures,
ignored or filtered tests in each binary. This includes actual proof verification
and expected rejection cases; it is not the full Private/Attested proof matrix.
Log: shared `target/task-tmp/decoded-input-release.RIkx3j/pvm-proof-fast.log`.
Environment: nightly-2025-05-09, offline dependencies, shared disk-backed target
and TMPDIR, `RUST_TEST_THREADS=1`, `RAYON_NUM_THREADS=2` to limit memory pressure.
No source/artifact changes accompanied the run; existing warnings remain.

### 2026-09-19: Shared finality dependency audit

Read-only follow-up at `2c340623` rechecked the C2 requirements in the review
guide: ordinary provisioning requires authenticated live system-Agent decision
publication and independent replay verification on both admission and reopen.
The blocker is not a safe one-line replacement for UnavailableAgentFinality.

Concrete source boundaries:

- `agent::genesis` is public and not std-gated. Its decision records already
  have bounded canonical encoding/decoding and are available through the
  Authority actor's existing vos dependency. A duplicate SDK record is not
  necessary merely for parsing; publishing valid, correctly authorized facts
  and proving their permanence remains the missing integration.
- `genesis.rs::AgentGenesisDecision` binds exact system genesis/admission,
  proposal, replica committee, evidence and authority claim. Provider output is
  explicitly not proof of permanent publication.
- `shared_host.rs::verify_and_prepare` requires independent finality before
  preparing ordinary Shared genesis. The system bootstrap path separately checks
  root pins; it must not be reused to authorize ordinary agents.
- `system-authority::finalize_application` replaces `latest_management_acks` by
  credential when the request sequence advances. MAA2 is therefore not a
  permanent genesis-decision archive, even when its signature is valid.
- `ManagedAgentRow`/`AuthorityAgentProjection` describe current runtime, replicas
  and capabilities, not an immutable exact AgentGenesisDecision. Matching a
  current inventory row cannot substitute for that decision's finality.

Next implementation dependency is a bounded permanent exact-decision publication
path in the clean Authority, with authenticated retrieval/replay evidence that
survives later management, credential turnover and checkpoint/GC. Durable archive
creation/reproduction must remain separate from independent trust promotion.
Only then wire native issuance/provisioning and reopen verification, accounting
for root-first recovery and the non-reentrant system-owner lock. Required checks
include self-consistent-but-unpublished rejection, exact retry, conflicting
decision rejection, retention after later operations and restart, and native
ordinary Shared Create/Install/invoke/restart. No new implementation, artifact
repin or test pass is claimed by this audit; no auth/retention bypass was added.

### 2026-09-19: boxed network command payload verified

Following `a4f22004`, the network mailbox now owns each Agent outbound request
through a Box, unboxed at the same dispatch point. The test-only untracked frame
is boxed consistently. Requests still own their original admission permit and
reply sender; failed enqueue, queue drop and normal dispatch retain their prior
ownership semantics. No wire types, request encoding, route authentication,
capacity limits or artifact pins changed.

Clippy previously measured the production NetworkCmd enum at at least3,216
bytes because it embedded AgentOutboundRequest. A new layout/queue-drop test
measures NetworkCmd at280 bytes in the test build (AgentOutboundRequest3,216),
enforces a512-byte command bound and verifies queued-request drop releases both
the permit and reply sender. The payload itself remains allocated on the heap;
this adds an allocation per outbound request and is not a measured latency or
total-memory improvement.

`cargo +nightly-2025-05-09 test --locked --offline -p vos --lib network:: --
--test-threads=1 --nocapture` passes96 tests, zero failed/ignored,10.57s with
loopback permission (session35806 exit0). Log:
`decoded-input-release.RIkx3j/boxed-network-tests.log` in the shared target.
Formatting/diff checks pass. Workspace Clippy reports338 remaining diagnostics
(session77367 exit101, `lint-after-network-box.log`); the NetworkCmd size
diagnostic is gone. Qualified release binary remains8f96fad8; this is targeted
source qualification, not a rebuilt/requalified release.

### 2026-09-19: journal-store lint cleanup verified

Following `21fb4bab`, journal-store cleanup removes six further diagnostics:
zero-ID membership uses `contains`, two Copy manifests are dereferenced instead
of cloned, a private helper's explicit lifetime is elided, and two redundant
borrows are removed. Wire/storage formats, validation conditions/order, bounds,
error propagation and persistence ordering are unchanged. No lint allowances.

`cargo +nightly-2025-05-09 test --locked --offline -p vos --features pvm --lib
agent::journal_store::tests -- --test-threads=1` passes 97 tests, zero failures or
ignored, in21.10s (session56405 exit0). Log:
`decoded-input-release.RIkx3j/lint-journal-tests.log` in the shared target.
Formatting and `git diff --check` pass. Workspace Clippy with `check-all` flags
now reports339 diagnostics (session10601 exit101,
`lint-after-journal-cleanup.log`); the six targeted diagnostics are gone.
This remains targeted source qualification, not a new release build or full
regression run. The qualified executable and guest artifact pins are unchanged.

### 2026-09-19: check-all blocked by lint; six host-only diagnostics fixed

At `cb01ae08`, the full `just check-all` passes formatting and fails at workspace
Clippy with 351 diagnostics (session72212 exit101). Later recipe steps did not
run. Log: `decoded-input-release.RIkx3j/check-all.log` in the shared target.

A narrow host-only cleanup removes four redundant boolean comparisons in the
whole-image/local-journal installation paths, replaces one manual error-forwarding
match with `?`, and removes unnecessary mutability when observing a Local
management application. No validation, error mapping, persistence ordering,
public API, guest source, protocol, or artifact pin changes. No warning allowances
were added and unused integration code was not deleted to hide missing wiring.

Verification with nightly-2025-05-09, locked/offline dependencies and disk-backed
TMPDIR:

- `cargo fmt -- --check` and `git diff --check` pass.
- `cargo test -p vos --features pvm --lib agent::driver::tests -- --test-threads=1`:
  34 passed, zero failed/ignored, 1.25s; session76921 exit0, `lint-driver-tests.log`.
- Same test command with filter `agent::local_`: 50 passed, zero failed/ignored,
  51.52s; session66541 exit0, `lint-local-tests.log` (local socket permission).
- Workspace Clippy with the exact `check-all` lint flags now reports 345
  diagnostics; session4176 exit101, `lint-after-host-cleanup.log`. All six targeted
  diagnostics are gone; the lint gate still fails.

Logs share `decoded-input-release.RIkx3j/`. The release executable remains the
qualified `8f96fad8` build; this subsequent source cleanup has targeted coverage,
not a new release rebuild or broad-suite qualification. The full clean-break
and broad-suite results below belong to the preceding source checkpoint.

### 2026-09-19: complete clean-break recipe passes

At `bf013ff1`, the full `just clean-break-check` recipe was started unchanged,
with `RUSTUP_TOOLCHAIN=nightly-2025-05-09`, `CARGO_NET_OFFLINE=true`, the shared
`ch08-c2-native/target`, disk-backed TMPDIR, and local socket permission.
Exec session `74299` finished with exit0; log:
`target/task-tmp/decoded-input-release.RIkx3j/clean-break-recipe.log`.
Every test selection ran nonzero tests and passed:

| Selection | Passed | Ignored | Test time |
| --- | ---: | ---: | ---: |
| Clean bootstrap (`pvm`) | 75 | 1 | 805.26s |
| Production owner | 11 | 0 | 0.13s |
| Supervisor adapters | 27 | 0 | 0.03s |
| CLI clean-space modules | 94 | 0 | 51.22s |
| Private host | 63 | 0 | 81.91s |
| Private store | 40 | 0 | 3.31s |
| Private runtime | 21 | 0 | 0.02s |
| Portable recovery selection | 6 | 0 | 5.70s |
| System Authority actor | 58 | 0 | 102.52s |
| System Catalog actor | 10 | 0 | 24.77s |

SDK no-default-feature intra-doc-link checking and the final retained CLI/negative
surface script also pass. The ignored bootstrap case is the explicit 64MiB
initial-capture capacity diagnostic, not a pass. The full inventory-rotation
workload ran unchanged. Counts overlap other suites; do not add them as unique
coverage. Runtime source, lockfiles and artifacts are unchanged. Nested actor/docs
recipes used this worktree's disk-backed `target/task-tmp`, not `/tmp`.
Session74299 is terminal; there is no pending clean-break run to resume.
This closes `just clean-break-check`, not `just check-all`, workspace Clippy,
all examples, remaining proof/crash qualification, or production functionality
and latency gaps. The six portable tests do not independently close the missing
cross-runtime positive-ACK matrix.

### 2026-09-19: full post-pin host-feature regression passes

Session55057 finished with exit0: **1,876 passed, zero failed, three ignored**,
zero filtered, 1,403.60s. Full log:
`target/task-tmp/decoded-input-release.RIkx3j/host-feature-suite.log` in the shared
`ch08-c2-native` target. The run started at `ea13d293`; only documentation changed
during execution (HEAD at completion `45a22e3f`). Runtime source and pins remained
unchanged from the qualified `8f96fad8` implementation. Command:

```sh
cargo +nightly-2025-05-09 test --locked --offline -p vos --features 'agent-transition-proof private-agent-store http-ingress ssh-ingress' --lib -- --test-threads=1
```

Both `same_head_inventory_rotates_authenticated_suffix_past_1024_entries` and
`system_attach_checkpoints_and_drains_raw_tail_before_publishing_route` passed
in full, without shortened workloads or restarts. Three ignored diagnostics:

- `native_operation_initial_capture_requires_more_headroom_than_projection`:
  fills the real 64MiB journal boundary; capacity diagnostic not qualified here.
- `fixed_history_physical_decode_probe`: requires the explicit copied-DB fixture;
  timing diagnostic, not a release gate.
- `profile_bundled_runtime_large_acknowledgement`: fixed-work CPU profiling probe.

This closes the broad post-pin library reruns, not the full Private/Attested
cryptographic proof matrix, ordinary Shared integration, issuer reclamation,
workspace lint/recipes, remaining crash cases, or production latency gates.
Session55057 is terminal: do not poll or restart it as unfinished work.

### 2026-09-19: post-pin nested system-actor suites pass

With runtime source frozen at the current checkpoint, both nested actor suites
pass using nightly-2025-05-09, `--locked --offline --lib -- --test-threads=1`,
the shared target and disk-backed TMPDIR:

- `actors/system-authority/Cargo.toml`: 58 passed, zero failures/ignored,
  111.93s, session82369 exit0; `decoded-input-release.RIkx3j/system-authority-tests.log`.
- `actors/system-catalog/Cargo.toml`: 10 passed, zero failures/ignored,
  26.08s, session22543 exit0; `decoded-input-release.RIkx3j/system-catalog-tests.log`.

These nested workspaces are not covered by root workspace tests. The passing
Authority compaction tests do not close host issuer/coordinator reclamation.
Host-feature session55057 is still running the full authenticated-inventory
rotation workload; it has not been restarted, filtered, or shortened.

### 2026-09-19: post-pin SDK documentation gate passes

At `c22015ea`, with unchanged runtime source/pins, the SDK no-default-feature
documentation build passes with broken intra-doc links denied:

```sh
RUSTDOCFLAGS='-D rustdoc::broken_intra_doc_links' cargo +nightly-2025-05-09 doc --locked --offline -p vos-agent-sdk --no-default-features --no-deps
```

Exit0, 0.83s; log: shared
`target/task-tmp/decoded-input-release.RIkx3j/sdk-doc-check.log`. This checks SDK
intra-doc links only, not all examples or external links. Host-feature session
`55057` remains live, progressing through Local lifecycle recovery cases; poll
that same session before any rerun. No runtime source or artifact edits.

### 2026-09-19: post-pin default regression passes; host-feature run started

At source `ea13d293` (runtime/release implementation unchanged from `8f96fad8`),
the full default-library suite finished: 1,434 passed, zero failed, one ignored,
195.71s. Terminal test summary is in
`target/task-tmp/decoded-input-release.RIkx3j/default-suite.log`; process inspection
confirmed the previous Cargo/test processes were no longer running.

The broader host-feature suite was then started, with source frozen, using:

```sh
cargo +nightly-2025-05-09 test --locked --offline -p vos --features 'agent-transition-proof private-agent-store http-ingress ssh-ingress' --lib -- --test-threads=1
```

Live exec session: `55057`. Evidence log:
`target/task-tmp/decoded-input-release.RIkx3j/host-feature-suite.log` in the shared
`ch08-c2-native` target. Both runs use that shared target and its disk-backed
`task-tmp` as TMPDIR, with local socket permission. Poll the existing session or
inspect authoritative processes before starting another run. The host-feature
result is pending, not a pass; the previous run took about 25 minutes. No runtime
source or artifact changes accompany this qualification update.

The post-pin `bash scripts/check-agent-clean-break.sh` also passes (session13949,
exit0): locked offline CLI build, retained/retired help surfaces, rejection of
the removed dynamic dispatcher, retired-path absence, and the script's selected
operator-documentation checks. Log: `decoded-input-release.RIkx3j/clean-break-surface.log`.
This is only the surface gate, not the full `just clean-break-check` recipe or
the full documentation/examples sign-off. Build warnings remain; no lint
allowances or automatic fixes were applied. Host-feature session55057 remains
running and has passed the fresh bundled Authority query test.

Read-only inventory follow-up: `CleanAuthorityProjectionClient::load_inventory`
issues Credential + Agents + (AgentReplicas + Actors) per agent: six queries for
two agents with single-page results. Existing unchanged-complete-head reuse
already reduces a valid unchanged refresh to the fresh Credential query. The
projection route serializes execution through one worker and the system-owner
mutex (`supervisor_adapters.rs`), so caller-side parallel requests alone would
not parallelize guest execution. Aggregating authenticated bounded projections
would require protocol/actor changes and artifact requalification; this has not
been implemented or measured. Do not replace fresh credential checks with stale
inventory, assume parallel dispatch is safe, or infer an end-to-end speedup.

### 2026-09-19: decoded-input release and fresh Local lifecycle qualified

Release source `8f96fad8d46ab5f5421ddd3afb1fbe6011b09bea` builds locked/offline
with nightly-2025-05-09 in7m11s (session97380 exit0). SHA-256:
`ee49a636c477c1e3ef21d56f16e2c181307bd1e740ad20bee80b6da27e30e76d`.
`release bundle` and `release verify` pass with reproduced runtime ProgramId
`ebed0967a4d987e2f50f6e8908b294f713b0cf74583d1b5dc6648a8a542a049c`.
Evidence: shared `target/task-tmp/decoded-input-release.RIkx3j/`, including
`build.log`, verified `bundle/`, and preserved prior executable `vosx-before`
(SHA-256 `e76cf5428ebc443ec7cc6859c162ee7b9ec67e5fb03706b2ee9798051fa84106`).

Full CLI suite passes255 tests,0 failed,19 ignored in98.76s with loopback access
(session9925 exit0, `cli-suite-loopback.log`). The initial sandboxed run failed
15 socket-listener tests with `PermissionDenied`/`Operation not permitted`;
240 passed,19 ignored. Its `cli-suite.log` is preserved. No source fixes,
skipped failing tests or changed timeouts: the same binary/suite was rerun with
local socket permission. Its concurrent release build means suite wall time is
not a performance benchmark. Both jobs finished before the live probe started.

New disposable fixture `target/task-tmp/current-latency.coTfCk/` has isolated
XDG roots and name `current-latency-smoke`. SpaceId:
`2a6d0bf2c2eea7b123763caf399640fd1701b64899515f014ea5f54cea0eaab0`.
AgentId: `0b8915bf7b808aa62f68519a451f2de2b9dc794c3032a026b988fa7237f1c761`.
Generated config enabled HTTP8080 and SSH2222; only ports changed to18099/2243.
Only the immutable Counter package was copied, never a raw store. System
packages were installed automatically during startup. All prior fixtures remain
at original paths and were not opened with the new pin.

Guarded `probe.sh` passes (session59543 exit0):

- Initial readiness13s; HTTP status and SSH keyscan pass.
- Fresh Create25s and Install36s both return verified acknowledgements without
  retry/resume.
- Restart readiness19s; fresh managed increment20.04s (full test21.84s).
- Restart readiness26s; managed read20.33s (full test22.12s), value7 persists.
- Positive retirement, retired Invoke rejection and exact ACK retries pass.
  All shutdowns report0s at whole-second resolution; no forced cleanup.
  Post-probe process/listener checks find no test daemon or occupied test ports.

Mutation invocation `6c1869a1694bc23258f3a2fe5218d2e21e1831d1d9f0adde4660184da3b53b78`;
read invocation `590702442883dc4c3503182a808c3c8d498b6c8048c427b4adcedcc80918ee71`.
CLI test executable SHA-256:
`1eadc4862b50c9ec67a9b138f888d81316a8b13310045ed4bb06bd4768d5a3ad`.
Do not rerun the fresh mutation campaign or move/relabel the fixture stores.
The logs are `probe.log`, `up.log`, `mutation-up.log`, `read-up.log`,
`mutation-test.log`, `read-test.log`, plus exact Create/Install outputs.

Post-Create lifecycle8,058ms is followed by14,079ms route reconciliation,
including13,845ms inventory (six queries). Post-Install inventory15,681ms;
final route reconciliation16,353ms. Existing phase analysis parses all four
completed inventory loads; output is `decoded-input-release.RIkx3j/inventory-phases.json`.
Create/inventory are lower than the preceding fixture, but Install remains36s
and managed calls remain about20s. These differing generations/histories are
not controlled A/B evidence. All three readiness observations fail the10s gate.
SSH keyscan is not authenticated shell qualification; Counter Public-policy
success is not the full Private/Attested cryptographic matrix.

Review remains two groups, frozen at this implementation checkpoint:
`31b0cdbb..f79f0e3d` and `f79f0e3d..8f96fad8`. Batch2 is48 files,+4,946/-258;
integrated234 files,+77,744/-58,997. No merge/push. Full post-pin default/host
regressions and all remaining Shared, reclamation, proof and production gates
stay open. This closes release rebuild/fresh Local-test qualification only.

### 2026-09-19: independently reproduce and atomically pin decoded-input runtime

Exported immutable `330274bb139885b61e833bb63768a3024b5b9797` twice with
`git archive`, into separate source and target trees under shared disk-backed
`target/task-tmp/decoded-input-reproduction.ge5gNd/`. Both locked/offline
nightly-2026-03-20 builds pass in30.92s/30.88s. The preserved frozen converter
produces identical PVMs. Both ELF files, both PVMs, and the previously measured
candidate match byte-for-byte (session81910 exit0). Identities are exactly the
candidate IDs recorded below. Script, build logs, source trees, ELF/PVM bytes
and converter identity logs remain in that evidence directory.

Updated the runtime source/program/ELF/PVM provenance manifest, protocol
ProgramId, CLI build digest and committed PVM together. The PVM grows from
983,825 to984,164 bytes. System templates, public signing seed, outer ABI,
guest/host toolchains and other production artifacts remain unchanged.
No old space/store was opened or modified, and no release binary was rebuilt.

Focused post-pin verification (locked/offline nightly-2025-05-09, shared target
and disk-backed TMPDIR):

- CLI production-release checks:18 passed,0 failed in1.56s; session85573 exit0,
  `release-pin-tests.log`. Filtered integration binaries ran zero tests and
  are not counted as passes. Runtime byte/ProgramId pins, host-call surface,
  release-manifest semantics and self-contained bundle checks pass.
- Full wire module with the new bundled artifact and no candidate override:
  97 passed,0 failed,1 ignored in31.40s; session90601 exit0,
  `bundled-wire-tests.log`. The ignored test remains the fixed-work ACK CPU
  profiling diagnostic. Formatting, diff checks and bundled/independent PVM
  equality pass.

Next: rebuild the release from this pin, preserve the previous executable,
verify its bundle and use a NEW disposable space for Create/Install/Invoke,
restart, positive retirement/ACK and readiness/shutdown measurements. Previous
fixtures including `current-latency.VSCZEK` are now older-pin evidence: do not
boot them with the new executable. The old live-qualified release remains
`b16abf81`/SHA-256 `e76cf5428ebc443ec7cc6859c162ee7b9ec67e5fb03706b2ee9798051fa84106`.
New full CLI/default/host regression gates and all outstanding production work
remain open. A reproduced artifact and focused tests are not production sign-off.

### 2026-09-19: decoded-input validation reuse candidate reduces fresh Invoke/ACK gas

Implemented the next bounded optimization identified by the profile. The
guest now enters through `apply_standard_runtime_input`, which performs the
same complete SDK canonical decode before execution. Only its private Direct
Invoke/ACK continuations can mint the borrowed `ValidatedInvocationWork` token
for that exact immutable work. Standard recovery skips the redundant complete
availability validation, not scope/signature/slot checks, actor/ProgramId
resolution, exact retained-result matching, or public-I/O hashing. Public
constructed-work entry points still perform full validation. Guest Attested
Invoke/Resume retains the prior proof-host path and full validation; native
byte-input callers cannot select it. No ABI/domain/generation change.

Two new source regressions compare complete encoded transitions for fresh
Invoke, exact retry, ACK, ACK retry and retired Invoke. They also reject
corrupt preimages, truncation/trailing bytes, forged receipt signatures and
native Attested selection. Both pass with the four host features (session61937
exit0). The initial default-feature filtered probe selected zero tests and is
not qualification; the first compile exposed a WireError conversion, fixed
by mapping failed canonical decode to the existing fail-closed error.

Pinned guest build succeeds in14.30s (session13843 exit0). The isolated
candidate is NOT bundled or release-qualified. Candidate ProgramId:
`ebed0967a4d987e2f50f6e8908b294f713b0cf74583d1b5dc6648a8a542a049c`.
ELF BLAKE2b256:
`4a1930c4b8b6ba38daad3079ace97bb34903e446596346f3814d24eac11a505f`.
PVM BLAKE2b256:
`dfcf70ef5a335125176eb350e6fe3d857e9efc593a55860dee9761e4f2ac112f`.

Paired exact-input large-artifact tests compare complete output bytes:

| Work | Bundled gas | Candidate gas | Reduction |
| --- | ---: | ---: | ---: |
| Fresh Invoke | 463,462,521 | 405,201,877 | 12.6% |
| Retained Invoke retry | 404,577,747 | 346,317,879 | 14.4% |
| Fresh ACK | 278,766,249 | 220,499,368 | 20.9% |

The wire suite with both candidate environment selectors passes97 tests,
0 failed,1 ignored in29.71s (session25383 exit0). Tests without a candidate
selector retain their existing source/bundled coverage; do not describe this
as every case executing both PVMs. Formatting and diff checks pass.

The real bundled-Authority fresh credential query also passes on the candidate
outer PVM, including positive exact ACK and cleared pending projection
(session2212 exit0,15.01s with instruction observation). Observed candidate
Invoke gas555,039,116; ACK207,065,357. Its fixture runtime identity changes
with the candidate package, so this is successful real-workload qualification,
not identical-input/output A/B evidence or deployed wall-time speedup.
The test-only runtime fixture now accepts the explicit candidate selector only
when bundled-PVM profiling is requested; normal fixtures are unchanged.

Evidence is preserved in shared disk-backed
`target/task-tmp/decoded-input-candidate.81qO9E/`: `guest-build-fixed.log`,
`decoded-input-tests-fixed.log`, `wire-candidate.log`,
`authority-query-candidate.log`, `runtime.pvm`, and the guest target ELF.
Prior failed compile logs remain. Production artifact manifest, guest bundle,
runtime identity constants and release binary remain unchanged.

Before promotion: independently reproduce from the immutable candidate source
in two isolated source/target trees, require equality with the measured bytes,
atomically repin, rebuild the release and repeat fresh disposable lifecycle /
restart qualification plus the full regression gates. Do not boot preserved
older-pin stores with a candidate release or claim the production latency
gate is fixed. Ordinary Shared/finality and all other outstanding gates remain.

### 2026-09-19: exact-binary PC attribution identifies BLAKE2b as dominant cost

Extended the opt-in test observer with bounded-by-code-length outer instruction
counters, top PCs and4KiB regions. Count totals are asserted against all outer
instructions. Re-ran the successful bundled Authority query: session30885
exit0,19.29s; gas and instruction totals exactly match the preceding profile.
Instrumentation time is not release latency.

A compiler-test diagnostic maps observed PCs through the preserved ELF only
after `link_elf_spi(ELF)` matches the bundled PVM byte-for-byte. The diagnostic
also applies the final branch-target insertion offset map; the raw translation
map is NOT sufficient. The preliminary `authority-query-pc-map.log` omits that
relocation and must not be used for symbol attribution. Its corrected successor
is `authority-query-pc-map-relocated.log`; region mapping is in
`authority-query-region-map.log`. All corrected selected PCs map exactly, with
no nearest-address gap. The preserved ELF is
`role-length-reproduction.IeXBpW/target-a/riscv64em-vos/release/agent_runtime.elf`.

Five whole4KiB regions at PVM PCs `[16384,36864)` lie within ELF function
`blake2b_simd::portable::compress1_loop` (RISC-V symbols `0x3004cec` to
`0x300c5d4`). Together they account for:

- Invoke:144,017,192 of182,482,309 outer instructions, **at least78.9%**.
- ACK:82,520,526 of95,650,075 outer instructions, **at least86.3%**.

These are conservative lower bounds excluding partial boundary regions, not
percentages of wall time. `llvm-addr2line` may print local `.Lpcrel_hi17` labels;
the surrounding function range comes from `llvm-nm --numeric-sort --demangle`.
Other frequent PCs map to `vos_pvm_program::parse_compact_code_blob`,
`ActorMachine::load_at`, and compiler-builtins `memcpy`. Top individual-PC
counts alone would overemphasize those small loops and miss the large unrolled
hash function, which is why region aggregation was necessary.

Next bounded optimization target: redundant hashing of identical immutable
availability bytes across the canonical decoder and execution boundary.
The decoder already avoids duplicate nested-envelope and per-blob checks;
do not redo those optimizations. The canonical decode still validates Invoke
availability, while Standard recovery independently validates constructed work.
Any reuse must be unforgeably tied to the exact decoded value; public
constructed-value entry points must continue full validation. ProgramId and
BlobRef are separate digest domains, and public-I/O hashing is proof binding,
not removable overhead. No validation or hashing was removed in this step.

Compiler regression passes65 unit tests (1 opt-in diagnostic ignored) and
8 integration tests; the explicit exact-binary mapping diagnostic also passes.
New tests prove offset-map reporting preserves emitted code and handles both
inserted and unchanged boundaries. Production linker API/output is unchanged;
the optional relocation observer shares the existing implementation. Formatting
and diff checks pass. Evidence in shared `role-length-release.UnaSE1/`:
`authority-query-region-profile.log`, `authority-query-region-map.log`,
`compiler-profile-support-tests.log`. No guest repin, release rebuild or
deployment was performed; remaining production gates stay open.

### 2026-09-19: real bundled Authority query profile localizes cost to outer runtime

Added `native_bundled_authority_fresh_credential_query_retires_exact_pair`.
It uses the actual bundled Authority executable/schema/policies, re-signed only
for the existing fixture issuer. A valid enrolled SSH-node credential query
must return the exact query, active status and expected principal; no positive
ACK exists beforehand, and the exact retained positive ACK and cleared pending
projection are required afterward. This is a fresh successful query, not an
unknown-credential rejection or retained-result timing probe.

The normal test passes (session18710 exit0,3.62s). With
`VOS_AGENT_PROFILE_REFINE_MACHINES=1`, the existing fixture disables the native
outer-runtime shortcut and uses the bundled `agent_runtime.pvm`; the same test
passes (session74286 exit0,12.82s). Markers delimit just the measured query
after bootstrap. Both runs use locked/offline nightly-2025-05-09, the four host
features, shared target and disk-backed TMPDIR. No guest pin or executable
bytes changed. This is fixture-based attribution, not a deployed wall-time A/B.

| Fresh query transition | Input bytes | Gas | Outer instructions | Inner instructions |
| --- | ---: | ---: | ---: | ---: |
| Invoke | 772,026 | 611,555,466 | 182,482,309 | 5,442,329 |
| ACK | 774,351 | 263,780,712 | 95,650,075 | 0 |

Outer instructions account for97.1% of observed Invoke instructions and100%
of ACK instructions. Observer wall spans are3.804s outer/0.168s inner for
Invoke and2.024s outer for ACK; instrumentation adds overhead, so these are
not release latency numbers. Invoke has26 host calls; ACK has none. The outer
and inner observation intervals are separated at host calls by the observer.

This changes the next optimization target: first localize outer runtime
validation/encoding/hash work, rather than optimizing Authority actor policy
execution or its state. Do not infer the exact hot outer function from this
machine-level split alone. Retain this successful real-workload regression
alongside the synthetic large-artifact equivalence test for any candidate.
Logs: shared `target/task-tmp/role-length-release.UnaSE1/authority-query-native.log`
and `authority-query-pvm-profile.log`. Formatting and diff checks pass.
The full suites remain qualified at their earlier recorded source revisions;
this new test does not close the remaining production gates.

### 2026-09-19: current-pin inventory attribution narrows the performance target

Analyzed the retained current-release `current-latency.VSCZEK/up.log` without
opening, copying or mutating any store or starting another daemon. Unlike the
older phase table below, these measurements include the latest reproduced
runtime pin. The post-Create inventory (lines226–361) contains six authenticated
queries and takes16,677ms:

| Phase | Wall ms | Enclosed runtime ms | Runtime calls |
| --- | ---: | ---: | ---: |
| Prepare | 426 | 118.741 | 6 |
| Reserve/checkpoint | 2,208 | 44.256 | 2 |
| Identity | 400 | 126.324 | 6 |
| Persist pending | 224 | 0 | 0 |
| Reopen/check retained ACK | 504 | 121.696 | 6 |
| Invoke | 8,036 | 6,245.987 | 12 |
| Acknowledge | 4,679 | 2,905.777 | 12 |
| Complete pending | 195 | 0 | 0 |

The two cumulative timing families are differenced independently, resetting
at `reopen`. Phase totals are16,672ms;5ms remain between logged boundaries.
Runtime spans total9,562.781ms across44 calls. Of these,12 calls with encoded
inputs at least512KiB consume8,890.561ms; the other32 consume672.220ms.
In the inspected fresh-query trace, Invoke and ACK each contain one small
inspection and one large execution, not two large executions. Exact terminal
preflight reuse is logged. Do not count every runtime span as a repeated full
invocation, or remove replay based on that assumption.

The post-Install inventory (lines500–635) corroborates the concentration:
15,483ms total,44 runtime calls taking9,017.575ms, of which12 large-input calls
take8,372.321ms. Fresh unchanged-head credential-only refresh (lines405–429)
still costs2,450ms. Thus existing page reuse helps but does not make even one
authenticated query cheap. These are phase observations, not controlled A/B
or CPU instruction profiles; non-runtime residuals are not proven to be I/O.
Explicit pending persist/clear contributes only419ms after Create.

This rules out small inspection execution as the primary remaining target:
even eliminating all32 smaller runtime spans would recover only0.672s in the
measured16.677s inventory, before any associated host overhead. The next
bounded performance investigation should profile the actual bundled Authority
fresh Invoke/ACK workloads (not just the synthetic Counter) and separately
attribute reserve/checkpoint's2.164s and Invoke/ACK's3.563s outside runtime.
Preserve authenticated complete-head pagination, exact pending recovery and
positive ACK semantics. Do not introduce a new batch protocol or repin guests
without measured evidence and equivalence/recovery qualification.

Reproduction script and full output are in shared disk-backed
`target/task-tmp/role-length-release.UnaSE1/inventory-phases.py` and
`current-inventory-phases.json`. The parser asserts sequential complete phase
sequences, monotonic cumulative timing and at most5ms query boundary residual;
all four completed inventories in this log pass. No implementation, pin,
fixture or release binary changed. Full production gates remain open.

### 2026-09-19: reject legacy-state Shared finality experiment; keep review checkpoint clean

The uncommitted ordinary-finality experiment following `36e63581` was removed
after its live-reader test failed: it returned `Unavailable`, not the expected
`NotFinalized`. Evidence remains in shared disk-backed
`target/task-tmp/role-length-release.UnaSE1/finality-reader-test.log` and
`rejected-finality-experiment.patch`; no fixture or failure log was deleted.
The experiment's constructed-view unit test passed, but did not establish
compatibility with clean production replay.

This corrects the earlier ordinary Shared read/ownership audit below:
`materialized_system_authority_view` requires decoded Standard runtime
`system_authority` state. Clean descriptor conversion explicitly sets
`system_authority_genesis: None`; it does not initialize that legacy embedded
ledger. The failing clean replay fixture also uses opaque control bytes, so
its failure alone is not evidence about production decoding. Source inspection
establishes the separate embedded-ledger mismatch. Do not initialize legacy
authority state or weaken provenance checks to make this approach pass.

Ordinary Shared issuance/archive/finality must instead be integrated with the
clean system-authority actor's authenticated decision evidence and lifecycle.
The root-first reopen and non-reentrant ownership requirements from the prior
audit still apply. Native admission remains fail-closed. No production finality
implementation, guest artifact change, merge or push was made. The committed
`36e63581` implementation remains the review checkpoint; the reproduced release
binary is still the separately qualified `b16abf81` build.

After removing only the experiment's211 added Rust lines, all three source
files exactly match `36e63581`. Pinned-host formatting and `git diff --check`
pass. The restored provenance regression
`memory_clone_drops_root_provenance_while_original_remains_reverified` passes
(1 passed, 0 failed, 1,875 filtered out; session34702 exit0), using the same
four host features as the full host suite, offline/locked and disk-backed
TMPDIR. Log: `finality-experiment-removal-test.log` in the same evidence
directory. This verifies restoration, not completion of Shared finality.

### 2026-09-19: complete host-feature regression and mechanical formatting cleanup

Original host-feature session38510 completes successfully, exit0:1,873 passed,
0 failed,3 ignored in1,509.36s (25m09s). Started at `02dbc8c6`; runtime source
remained unchanged throughout, with only documentation commits added. Command:
offline/locked host nightly-2025-05-09 `cargo test -p vos --features
'agent-transition-proof private-agent-store http-ingress ssh-ingress' --lib --
--test-threads=1`. Loopback access and disk-backed TMPDIR were available.
Both the full inventory-rotation workload and system-attachment checkpoint/drain
passed. No workload reductions, source fixes, restarts or retries. Concurrent
supporting checks mean suite duration is not a controlled performance result.

The three ignored tests remain the explicit64MiB initial-capture diagnostic,
fixed-history copied-database timing probe and repeated large-ACK CPU profile.
Feature-enabled test success is not the remaining full cryptographic proof
qualification. Evidence: `target/task-tmp/role-length-release.UnaSE1/host-suite.log`.

Only after the suite terminated, applied pinned-host `cargo fmt --all`. Reviewed
all15 changed files: indentation, line wrapping and formatter-supplied trailing
commas only (117 insertions/80 deletions before documentation updates). The exact
recipe formatting check now exits0, as does `git diff --check`;
`format-fixed-check.log` is empty on success. No lint suppression, schema,
protocol, release artifact or source-provenance pin changed. The bundle continues
to reproduce from immutable `19d73390`; no claim is made that a rebuild of the
reformatted checkout has identical guest bytes. Full-suite evidence above is
explicitly pre-formatting. Workspace lint and functional production gaps remain.

Post-format focused verification passes: full wire module95 passed/1 ignored
in26.80s (session36530 exit0), including complete bundled/source transitions;
SDK165 passed/0 ignored in0.20s (session49262 exit0), including golden wire
commitments. Logs: `post-format-wire.log`, `post-format-sdk.log` in the same
evidence directory. These are not a rerun of all full-suite feature combinations.

### 2026-09-19: post-pin portable SDK and build-integration gates

At `cda6c997`, without changing the frozen runtime source:

- `cargo check -p vos --no-default-features --lib`:exit0 in2.04s;
  existing272 warnings remain, so this does not supersede the failed lint gate.
- `cargo test -p vos-agent-sdk --lib -- --test-threads=1`:165 passed,0 failed,
  none ignored in0.18s.
- `cargo test -p vosx --test build_actor_e2e --test build_task_e2e --
  --test-threads=1`:actor-build4 passed in29.27s, task-build1 passed in29.53s;
  session80400 exit0. This updates the older-generation build-integration
  evidence, not signed package reproduction or live deployment proof.

All commands use host nightly-2025-05-09, `--locked --offline`, shared target
and disk-backed TMPDIR; nested build integration also sets CARGO_NET_OFFLINE.
Logs under `target/task-tmp/role-length-release.UnaSE1/`: `no-std-check.log`,
`sdk-suite.log`, `build-integration.log`. The original host-feature run remains
active on its long inventory-rotation workload (session38510); do not restart it.
Source/release pins and fixture contents were not changed by this work.

### 2026-09-19: workspace Clippy release gate fails

At `7b45d2f0`, ran pinned-host offline/locked `cargo clippy --workspace` with
the exact `just check-all` lint flags: `-D warnings`, allowing only
`clippy::too_many_arguments`, `clippy::type_complexity`,
`clippy::result_unit_err`, `clippy::manual_async_fn`. Session48040 exits101:
vos library compilation reports351 prior errors. Counting diagnostic headers
(not individual methods/fields) gives258 unused/dead-code,1 unused-mut and92
other diagnostics. Large enum variants are among the latter. Do not assume
downstream workspace crates have passed: this run fails at vos.

Evidence: `target/task-tmp/role-length-release.UnaSE1/clippy-workspace.log`.
No source or lint configuration changed, and no autofix was applied. This is
another concrete release gate, separate from the passing targeted suites and
still-running host-feature session38510. Triage after the frozen suite: retire
only genuinely obsolete clean-break code; wire required production paths;
apply justified test/feature scoping and scoped lint fixes. Do not delete needed
Shared/authority integration or add a blanket dead-code allowance merely to
make this check green. The read-only check does not identify which diagnostics
predate this branch, and does not establish a new runtime correctness failure.

### 2026-09-19: post-pin nested actor, SDK documentation and static cutover gates

At `7bc52924`, with runtime source unchanged during the live host-feature run:

- `actors/system-authority` separate-workspace library suite:58 passed,0 failed,
  none ignored in129.70s; session24810 exit0.
- `actors/system-catalog` separate-workspace library suite:10 passed,0 failed,
  none ignored in32.46s; session97673 exit0.
- SDK no-default-feature/no-deps docs with
  `RUSTDOCFLAGS=-D rustdoc::broken_intra_doc_links`:exit0. This is an intra-doc
  gate, not a whole-book or external-link audit.
- `scripts/check-agent-clean-break.sh`:exit0, retained CLI and negative surface
  verified; session3434 exit0. Its debug vosx build took18.09s. This script alone
  is not the complete `just clean-break-check` recipe.

All cargo work used pinned host nightly-2025-05-09, locked/offline resolution
(the script via `CARGO_NET_OFFLINE=true`), shared target and disk-backed TMPDIR.
Evidence under `target/task-tmp/role-length-release.UnaSE1/`:
`system-authority-suite.log`, `system-catalog-suite.log`, `sdk-doc-check.log`,
`clean-break-static.log`. No release binary, source, guest artifact or fixture
changed. System-actor tests do not close host issuer/coordinator reclamation or
ordinary Shared issuance/finality. Host-feature session38510 still requires its
own terminal result; no restart occurred. Formatting remains a failed gate.

### 2026-09-19: pinned-toolchain formatting gate fails (read-only check)

At `b437af09`, both `cargo +nightly-2025-05-09 fmt --all -- --check` and the
`just check-all` recipe's exact formatting command, `cargo fmt -- --check`
with that same pinned toolchain, exit1. Their logs are byte-identical and show
40 diff locations across15 files. This is a real remaining release gate, not
a compiler/test failure or a missing formatter. No source files were changed.

Files: vos agent journal_store, production_owner, shared_host,
shared_journal_driver, standard and wire; vos ingress/server and node; SDK
authority_operation, catalog, proof, runtime and wire; CLI local_create and
local_operation_live_tests. Several differences are in tests, but guest-linked
files also appear. Apply the mechanical formatting as one scoped follow-up after
the running host-feature suite completes, check the resulting diff, and rerun
the gate. Do not assume rebuilt guest bytes are identical after source-location
changes; retain the immutable reproduced source pin unless a measured rebuild
and the required qualification justify another repin.

Evidence under shared `target/task-tmp/role-length-release.UnaSE1/`:
`format-check.log`, `format-recipe-check.log`. The host-feature suite remains a
separate live run, session38510, and must be polled rather than restarted.

### 2026-09-19: ordinary Shared finality read and ownership audit

Historical read-only audit while the post-pin host-feature suite ran. The
later experiment above invalidates this as a clean-production implementation
plan: these components require legacy embedded authority state. The proposed
permanent-fact read was:

1. `replay::materialized_system_authority_view` authenticates materialization,
   compares durable Heads with the materialized Heads/ID and reverified root
   identity, then constructs the opaque scope and authority view. Use this
   boundary; caller-supplied state/IDs do not substitute for replay.
2. `prove_decision(view.authority_state().decisions_root(), target, loader)`
   can follow `SystemAuthorityHistoryStore::load_system_authority_decision_node`.
   It verifies bounded canonical paths and exact node IDs against that root.
   A vacant proof is not finality. An occupied proof supplies the exact fact.
3. Load the content-addressed committee named by that fact, and call
   `verify_historical_provision(scope, provision, fact, committee)`. This checks
   root-generation scope, exact provision/fact closure and the original QC.
   That helper alone does NOT prove inclusion: it must follow step2 against
   the authenticated root, with no stale-head or alternate-store substitution.

There is also a startup/ownership dependency missing from the earlier bounded
plan. `SharedAgentHost::open_with_lease_and_root` scans a BTreeMap keyed by
AgentId, verifies each intent, then opens/inserts that generation. Thus an
ordinary generation can be verified before its system generation is opened.
`verify_and_prepare` calls the external finality verifier during construction
and synchronous `provision_intent`; the production bootstrap owner holds this
same host as `Arc<Mutex<SharedAgentHost>>`. A verifier that simply reacquires
that host is not a safe integration: construction has no completed host yet,
and provisioning while its mutex is held would deadlock on recursive locking.
This is an integration hazard inferred from the call graph, not an observed
deadlock in the current unavailable verifier.

Before wiring ordinary issuance, define a root-first authenticated reopen and
non-reentrant ownership path (or an equally strong independently pinned proof
source). Test both AgentId orderings, missing/corrupt root generation, changed
Heads/store identity, vacant/conflicting decisions, missing/wrong committee,
and repeated verification after restart. Keep admission fail-closed until the
root is ready; do not solve ordering with an accepting cache or root-bootstrap
QC standing in for ordinary finality. No runtime source changed in this audit.

### 2026-09-19: complete post-pin default-library regression

At `02dbc8c6d50acdbc06b984cff651cfa61c5fc136`, the offline/locked default
`cargo +nightly-2025-05-09 test -p vos --lib -- --test-threads=1` completes:
1,434 passed,0 failed,1 ignored in199.41s (session32510, exit0). Loopback
network access was available and TMPDIR remained in disk-backed shared target.
No fixes, retries or filters. Evidence:
`target/task-tmp/role-length-release.UnaSE1/default-suite.log`.
The full host-feature suite is the next gate; do not substitute this narrower
feature selection or earlier-generation host results for it. Production
latency, Shared integration, reclamation and remaining proof gates stay open.

### 2026-09-19: repinned release and fresh Local lifecycle qualified

Release `b16abf81948d64cc08ea34f683316f60c7f8759c` builds offline/locked with
host nightly-2025-05-09 in6m20s. Executable SHA-256:
`e76cf5428ebc443ec7cc6859c162ee7b9ec67e5fb03706b2ee9798051fa84106`.
Bundle creation and verification pass. The prior release is preserved as
`target/task-tmp/role-length-release.UnaSE1/vosx-before` (SHA-256 `a2e12ecd77cf393c3ddf8ecfabecb4d366fb3e55d0d0d14dcc4f221fca8ef08b`).
That directory also contains `build.log`, verified `bundle/` and `cli-suite.log`.
Full current-pin CLI suite passes255 tests/19 ignored in87.64s. Build and test
sessions47890/71145 both terminated successfully; no overlapping build ran
during the live latency probe.

Fresh fixture `target/task-tmp/current-latency.VSCZEK/` has isolated XDG roots;
space name `current-latency-smoke`, SpaceId
`85fcc4bcb030fafe9bb56f5acfffea0330132f2e160237d475b2c674bb71e01a`.
Generated config enables HTTP8080/SSH2222; only test ports changed to18099/2243.
System packages are automatic; only the immutable Counter package was copied.
Created AgentId: `59fe9c9ab2a9f9ac50893058e50333273ccbe490754597824964388345ce913b`.

Guarded `probe.sh` completed successfully (session77977, exit0): first readiness
15s; HTTP status/SSH keyscan pass; fresh Create30s and Install36s both return
verified acknowledgements without resume. Shutdown1s. Restart19s; managed fresh
increment20.71s (full test22.42s); shutdown1s. Restart24s; managed read19.90s
(full test21.51s), persisted value7, retirement/late-Invoke rejection and exact
ACK retry pass; shutdown1s. No forced cleanup; host process inspection after
completion found no vosx/cargo/rustc. SSH listener checks are not authenticated
shell qualification; these Public-policy probes do not prove non-Public policy.

Fresh Create lifecycle9,618ms is followed by route reconciliation16,930ms,
including16,677ms inventory. Install's final reconciliation16,108ms includes
15,483ms inventory. Readiness still fails10s and operation latency remains too
high. Older release timings are not a controlled same-history A/B.
CLI test executable SHA-256:
`7a5b078dbf5b911d87112b5766419a832e4a9a8b23507fe99f987370955336d4`.
Mutation invocation `60376c6faa3dcd95f2a813d15b2d9b2078abcffb0175fd23595f7be52f760273`;
read invocation `11b10d2bae585d9b3a807176fd08763af5217624f6da3e2596ad8bd8d6f65406`.
Do not rerun the fresh increment: retain its exact request/ACK files. Keep all
stores at original absolute paths. Full post-pin default/host library suites,
Shared integration, reclamation and remaining production gates stay open.

### 2026-09-19: independently reproduced artifact-role optimization repinned

Exported immutable source `19d733903930b1e8cf5ef861e5ce0440336cde6a` twice into
separate source and target directories. Offline locked guest builds with
nightly-2026-03-20 took25.53s/26.55s. Both ELF files match each other and the
saved measured candidate ELF; both converted PVMs likewise match the candidate.
ProgramId and hashes are those recorded in the candidate entry below.

Updated `support/production-artifacts.toml`, `STANDARD_RUNTIME_PROGRAM_ID`,
the vosx build-time digest and bundled PVM together. System templates and ABI
identity remain unchanged. Post-pin tests without candidate overrides pass:
release verifier18/18 (0.92s), bundled signing/admission4/4 (0.30s), clean outer
surface1/1 (0.11s), bundled runtime7 passed/1 ignored (5.97s). This is focused
qualification, not the full host-feature/CLI/default matrix or live release.

Evidence: shared `target/task-tmp/role-length-reproduction.IeXBpW/` contains
`reproduce.sh`, `reproduce.log`, independent source/target trees, build/identity
logs, both PVMs, `post-pin-release-tests.log`, `post-pin-runtime-tests.log`.
The existing release executable is still the prior `b131edc3` generation;
it has not been rebuilt or replaced. Next: preserve that executable, build and
verify the new release, create a fresh disposable space, and qualify
Create/Install/Invoke/ACK/restart before reporting new live latency. Do not boot
the previous runtime's fixtures with the new pin. Full production gates in the
status page remain open; no merge or push occurred.

### 2026-09-19: artifact-role length rejection candidate

`resolve_clean_invocation` now checks actual preimage length before computing
the domain-separated blob digest for schema/policy/constructor roles. If none
of those references has that length, the preimage cannot match any role.
Program identity is still computed independently from complete bytes. Possible
matches are still hashed; caller-supplied references are not trusted. Duplicate
and aliased-role rejection, application availability construction, signatures,
expiry, readiness and recovery are unchanged. This is not a validation cache.

New native regression checks same-length corruption of both schema and policy,
changed lengths with unchanged supplied references, and duplicates. Existing
role-alias regression also passes. Whole wire suite against the existing bundle:
95 passed/1 ignored in30.78s, including empty installation-data/resume coverage.
Repeated with COST/ACK/FAILURE/TYPED_ERROR/EXPIRY candidate overrides:95 passed/
1 ignored in30.18s (`wire-candidate.log`). Only tests consuming those overrides
execute the candidate PVM; the others remain native or bundled checks. This
covers candidate malformed ACK, retirement, terminal failures, durable typed
errors and expiry; it is not full Private/Attested proof qualification.

Candidate guest builds with pinned guest toolchain in16.99s. Paired benchmarks
against current bundle pass with identical complete output:

| Work | Bundled gas | Candidate gas | Reduction |
| --- | ---: | ---: | ---: |
| Fresh Invoke | 579,883,967 | 463,462,521 | 20.1% |
| Retained Invoke retry | 520,997,765 | 404,577,747 | 22.3% |
| Fresh ACK of retained result | 336,976,258 | 278,766,249 | 17.3% |

These are synthetic768KiB-program tests, not live inventory latency or a new
production release. Candidate ProgramId:
`e61dc1dacd564ac9371512eaaf9d35ad8f1e081f8e3b638ca9da9425e887e86b`.
ELF BLAKE2b-256: `c9c3e01f31e2b5939fe5e13f71cfdfecf9b68faeebf8e7192c94fdd34ed2c081`.
PVM BLAKE2b-256: `8f4dd034314963408c2f7650147aeb7311094a4528f936881155eb238eff9fd7`.
Evidence: shared `target/task-tmp/role-length-candidate.D59PGi/` contains saved
ELF/PVM and `cost.log`; adjacent `role-length-native-20260919.log`,
`role-length-guest-build-20260919.log`, `role-length-wire-regressions-20260919.log`.
No release pins changed. Independent reproduction, atomic repin and fresh
release qualification remain required. Preserve existing fixtures at their
original paths and do not boot them using a new-generation pin.

### 2026-09-19: fresh large-program Invoke baseline added without changing release pins

Added `bundled_runtime_large_fresh_invoke_validation_cost`: a valid tiny Public
actor has768KiB of inert read-only padding, starts without a retained invocation
result, returns Done and commits a lane change. The complete bundled guest
transition must equal native source output. An optional
`VOS_AGENT_RUNTIME_COST_CANDIDATE` must also preserve those bytes and use less
gas. This measures fresh execution rather than the existing retained-retry
benchmark, but is still synthetic, not Authority inventory throughput.

Current bundle baseline:792,481 input bytes,579,883,967 gas,1,400,409us in the
first passing run. Initial fixture development failed with InvalidActorOutput
because read-only padding relocates writable data; the helper now computes the
output address using zone-rounded read-only length. Zero-padding failure
fixtures retain their original address. No production code or artifact pin
changed. Host-feature `bundled_runtime_` filter passes7 tests/1 ignored in6.69s,
including the fresh baseline and existing failure/retirement/ACK cases.
Logs under shared `target/task-tmp`: `fresh-invoke-baseline-20260919.log` and
`fresh-invoke-bundled-regressions-20260919.log`.

The source trace finds full work/authorization verification in both
`recover_clean_invocation_error` and later `recover_clean_execution`, with
expiry and policy admission between them. Artifact resolution also occurs in
preflight and again before execution. These are optimization candidates, not
permission to drop checks: any reuse must be scoped to exact immutable work,
authorization, runtime identity and observed slot, preserve error precedence,
and not cross the interposed mutation/early-return paths unchecked. Production
latency remains unresolved; this test supplies the missing fresh-work baseline.

### 2026-09-19: current-pin inventory attribution for the review handoff

Read-only attribution at `97dac482`, using the already completed current-release
probe `target/task-tmp/current-latency.qEl4ba/read-up.log` in the shared
`ch08-c2-native` target. No daemon rerun, store mutation, or rebuild. This is the
initial inventory on the read-after-restart run, not fresh Create or Install.

The six query durations sum to17,909ms; the enclosing inventory log reports
17,912ms. They contain44 physical runtime calls, including12 inputs over700KB.
Runtime spans sum to11,471.194ms (64%);6,437.806ms lies outside those spans.
Summing successive cumulative phase deltas, resetting at each query and at the
execution family's `reopen`, gives:

| Phase | Total ms | Enclosed runtime ms | Outside runtime spans ms |
| --- | ---: | ---: | ---: |
| Prepare | 447 | 129.383 | 317.617 |
| Reserve/checkpoint | 1,778 | 42.320 | 1,735.680 |
| Identity | 377 | 126.858 | 250.142 |
| Persist pending | 218 | 0 | 218 |
| Reopen/check retained ACK | 466 | 125.869 | 340.131 |
| Invoke | 9,125 | 7,434.812 | 1,690.188 |
| Acknowledge | 5,302 | 3,611.952 | 1,690.048 |
| Complete pending | 194 | 0 | 194 |

Phase totals differ from summed query times by2ms due to boundaries/rounding.
This is wall-time attribution, not a CPU profile: the outside-runtime residual
must not be labelled disk I/O or a single validation function. Explicit pending
persist/complete phases total412ms and cannot explain the overall delay.
Invoke plus ACK account for14,427ms (81% of query time). The earlier18.3% gas
benchmark measures retained Invoke retries, not these fresh inventory Invokes.

Source audit confirms unchanged-head reuse is already implemented in
`CleanAuthorityProjectionClient::load_inventory`, with a fresh authenticated
active credential and exact claims; failed refreshes invalidate reuse. Parallel
dispatch is not a drop-in fix: the clean projection path persists one pending
query and rejects a different query while it is pending. Next bounded performance
work should measure fresh Invoke/ACK validation against this current pin, then
isolate reserve/checkpoint's host residual. Do not add another unchanged-head
cache, omit ACKs, or bypass authentication/readiness. Existing historical
measurements are not a controlled before/after comparison with this run.

### 2026-09-19: ordinary Shared finality gap traced to both production boundaries

Read-only audit at `00921e04`: native `clean_startup.rs` installs
`UnavailableAgentFinality` at line340; its verifier always returns Unavailable.
Repository-wide exact-word search for `AgentGenesisProvider` finds only its
trait and trust-boundary documentation in `vos/src/agent/genesis.rs`, no
implementation or caller. `CleanSystemAgentGenesisArchive` implements the
different `SystemAgentGenesisProvider` for root system bootstrap. The ordinary
gap therefore includes archive/issuance and lifecycle wiring, not merely
replacing a finality stub with an accepting implementation.

Reusable existing pieces: `AgentGenesisProvision` validates canonical links;
`SystemAuthorityDecisionFact` and `verify_provision_fact` exact-compare provision
content; `SystemAuthorityState::verify_historical_provision` checks trusted
scope, exact fact and historical committee/QC together. Their comments explicitly
say data validation alone is not an admission/sealing capability. The independent
`AgentGenesisFinalityVerifier` must source the permanent decision from authenticated
live system replay and must run again on generation reopen. Existing
`self_consistent_provision_never_bypasses_independent_finality` covers refusal
propagation/reverification sequencing using a fake verifier, not production proof.

Bounded implementation order within the existing goal: expose an authenticated
replay-backed exact genesis-fact read (scope, decision, committee/QC); connect
that read to an independent finality verifier; implement durable ordinary
proposal/catalog/provision issuance and reproduction; wire Shared provisioning
and reopen through both boundaries. Require negative tests for provider-only
self-consistency, wrong system generation, absent/unfinalized fact, altered
committee/evidence, and verifier unavailability after a prior successful open.
Do not grant acceptance from root bootstrap QC, provider response, or decoding
private Standard state outside authenticated replay. No source change or new
production readiness claim follows from this audit.

### 2026-09-19: complete post-pin host-feature regression

At `bf7ced06` (release implementation `b131edc3`), full host-feature library
suite passes1,871 tests, zero failures,3 ignored,1,450.60s (24m11s). Command:
`cargo +nightly-2025-05-09 test --locked --offline -p vos --features 'agent-transition-proof private-agent-store http-ingress ssh-ingress' --lib -- --test-threads=1`.
Shared target, disk-backed TMPDIR, serial socket-enabled run; session59361
terminal0. Evidence: `target/task-tmp/invoke-reproduction.OS8HAC/post-pin-host-suite.log`.
No source fixes, retries or workload reductions. The514-query inventory rotation,
system-attachment checkpoint/drain, new Invoke validation rejection/retirement
and large-retry benchmark all pass in this uninterrupted run.

Ignored: native-operation initial-capture64MiB headroom diagnostic, explicit
fixed-history physical decode timing probe, and repeated large-ACK CPU profiling
probe. They are not claimed as passes. This updates the earlier full host-feature
baseline for the new pin. It does not prove the missing ordinary Shared finality
bridge, authenticated reclamation, full Private/Attested cryptographic proofs,
the unimplemented/unqualified recovery cases, or acceptable production latency.
No merge, push or master/production sign-off follows from this regression result.

### 2026-09-19: complete post-pin default-library regression

At `e63db78b` (release implementation `b131edc3`), full default-feature library
suite passes1,434 tests, zero failures,1 ignored,198.17s. Command:
`cargo +nightly-2025-05-09 test --locked --offline -p vos --lib -- --test-threads=1`,
shared target and disk-backed TMPDIR. Session24727 terminal0; evidence
`target/task-tmp/invoke-reproduction.OS8HAC/post-pin-default-suite.log`.
No implementation changes needed. This supersedes the earlier default-feature
baseline for the repinned runtime, not the still-pending full post-pin host-feature
suite, cryptographic proof matrix or production gates.

### 2026-09-19: complete post-pin CLI regression

At `c1614b96` (release implementation `b131edc3`), full CLI unit/binary suite
passes255 tests, zero failures,19 ignored,68.54s. Command:
`cargo +nightly-2025-05-09 test --locked --offline -p vosx --bin vosx -- --test-threads=1`,
shared target, disk-backed TMPDIR and loopback socket access. Session40371
terminal0; evidence `target/task-tmp/invoke-reproduction.OS8HAC/post-pin-cli-suite.log`.
No source changes required. Ignored live campaigns are not counted as passes;
the completed new-generation Counter campaign is recorded below. Full post-pin
library and production gates remain outstanding.

### 2026-09-19: repinned release and fresh Local lifecycle qualification

Release source `b131edc3` built locked/offline nightly-2025-05-09 in6m05s,
session53025 terminal0. SHA-256:
`a2e12ecd77cf393c3ddf8ecfabecb4d366fb3e55d0d0d14dcc4f221fca8ef08b`.
Bundle creation/verification passes with the reproduced e815f4b0 runtime and
unchanged system template pins. Build, bundle and preserved previous executable
are under `target/task-tmp/invoke-release.HNhVWg/`. Previous executable checksum
remains69732438…; old fixtures were not reopened, relocated or reset.

Fresh fixture `target/task-tmp/current-latency.qEl4ba/` uses isolated XDG roots,
name `current-latency-smoke`, generated HTTP/SSH configuration with ports changed
only to18099/2243. Only the immutable Counter package was copied. Space ID:
`7852fc0a55f4d599fd461794ead6454321b96f0647b36f5347ffae51e470de7b`;
Local Agent `e690502f9954db2c631385fc35ce0c38cb23ad5f239107c955de18d020b2662c`.
First readiness17s; HTTP status/SSH keyscan pass; fresh Create35s and Install43s
both verify their signed acknowledgement without retry/resume. Shutdown<1s;
session19944 terminal0. Logs: probe.sh/probe.log/up.log, new.json, create.txt,
install.txt and HTTP/SSH evidence.

Next restart21s; fresh Counter increment managed23.48s/full test25.19s, pass;
shutdown<1s. Next restart29s; fresh read managed24.50s/full test26.29s, pass;
shutdown1s. Both test exact retirement, late-Invoke rejection, positive ACK retry
and managed resume; read verifies value7. Session52775 terminal0; host process
inspection finds no matching daemon. Logs: invoke-probe.sh/invoke-probe.log,
mutation-up.log/mutation-test.log, read-up.log/read-test.log. Counter is now7;
preserve original-path state and retained requests, do not fresh-increment again.

First-start system owner4,776ms, initial one-agent inventory11,283ms and route
reconciliation11,609ms. Create lifecycle11,198ms; publication31,359ms including
20,016ms reconciliation/19,772ms inventory. Final Install reconciliation18,570ms
includes17,942ms inventory. The large-retry deterministic gas improvement is
proven; these differing fixture/historical runs are not a controlled overall
speedup comparison. Startup still fails10s, and tens-of-seconds operations remain
unacceptable. Full post-pin suites and other production gates remain open.

### 2026-09-19: independently reproduced Invoke candidate and atomic repin

Exported immutable `24000c8add0a93ffbdf0a45f4ab3945d48583195` twice into
separate source directories with separate empty guest targets. Both locked/offline
nightly-2026-03-20 builds succeed, with identical ELF and PVM bytes. Reproduced
PVM also matches the earlier measured worktree candidate. Session45039 terminal0;
evidence `target/task-tmp/invoke-reproduction.OS8HAC/`, including `reproduce.sh`,
source-a/b, target-a/b, build/identity logs and runtime-a/b.pvm.

ProgramId `e815f4b010f7213290850189f5bc20fc54533068f0d73ea4982de9414b1135e9`;
ELF BLAKE2b256 `07c26a66d0fb477c116a158f296e8b72ba83de88bc937bcd54b70c7feea815ef`;
PVM BLAKE2b256 `cf0c0cb6799b2a808aa27300597110bd2df1e4225bc79fa268c5edf8dc907778`.
Updated provenance, host Standard ProgramId, CLI blob digest and embedded runtime
together. System templates and ABI generation unchanged.

Reproduced cost comparison again passes byte-identical output and
637,510,333→520,997,765 gas; explicit malformed/error ACK candidate test passes
(session30595 terminal0, cost.log/errors.log). Post-pin CLI compilation passes;
an initial incorrect test filter selected zero tests (pin-tests.log), not a pass
claim. Corrected selection passes18 release tests,4 bundled admission tests and
1 outer-surface test, session69863 terminal0; separate logs retained.
Post-pin physical bundled-runtime selection also passes6 tests/1 ignored in5.16s,
session48426 terminal0, `post-pin-runtime-tests.log`; no candidate override used.

The installed release executable is still the older `cca4c911` artifact. Rebuild,
fresh-space live qualification and broader post-pin regression remain required.
Do not reopen or relocate prior-generation fixtures under the new pin. The
earlier full-suite and live evidence applies to its recorded source/artifact,
not automatically to this repin. No end-to-end latency improvement claimed.

### 2026-09-19: same-call Invoke validation reuse candidate

`recover_clean_execution` and `recover_clean_invocation_error` now call a private
ACK-recovery continuation immediately after full work/authorization validation.
It retains acknowledgement matching and every exact retirement comparison.
Standalone ACK recovery still validates all availability preimages. No trust
cache, protocol change, signature bypass or unvalidated public entry point.
The initial full verifier and its NotCreated precedence are unchanged.

New native regression checks corrupted preimages, altered message and forged
signature through both recovering entry points before/after retirement, with
byte-identical state on rejection; valid retained reply and retired-Invoke
rejection pass. Session99870 terminal0 (build34.32s, test0.05s). Existing
acknowledgement selection31 passed/1 ignored in48.24s, session11541 terminal0.

Source candidate built locked/offline nightly-2026-03-20 in28.01s, session79735
terminal0. Frozen converter produces candidate ProgramId
`e815f4b010f7213290850189f5bc20fc54533068f0d73ea4982de9414b1135e9`.
Large Invoke retry input793,742 bytes: bundled637,510,333 gas versus candidate
520,997,765 (18.3% reduction), with byte-identical complete output. Timing in
that paired run1.707s/1.331s is diagnostic, not fresh-operation throughput.
Cost test session35567 terminal0. Bundled-runtime selection6 pass/1 ignored
in5.37s, session25630 terminal0; candidate override is consumed only by the
retired-Invoke and malformed-ACK cases in that selection, not every test.
The explicit `clean_acknowledgement_errors_are_byte_identical_and_fail_closed`
test also passes against the candidate (`candidate-errors.log`).

Evidence: shared `target/task-tmp/invoke-validation.5C7sn0/` with build, identity,
cost, acknowledgement and candidate logs. Native regression log remains in
`current-latency.p7U3OE/invoke-validation-regression.log`. Candidate uses current
worktree source; independent immutable-source reproduction, atomic provenance
repin, broader regression and release/live qualification remain required.
Committed runtime pins and the qualified release executable are unchanged.

### 2026-09-19: large Invoke retry validation baseline

Added `bundled_runtime_large_invoke_retry_validation_cost`, using a retained
receipt-bearing terminal result with768KiB availability. It isolates outer
validation/recovery, not fresh actor execution. The committed guest completes
with the exact expected reply: input793,742 bytes,637,510,333 gas,1,347,866us
in this run. With `VOS_AGENT_RUNTIME_COST_CANDIDATE`, the same test additionally
requires byte-identical whole output and strictly lower deterministic gas.
No production implementation or artifact changed.

The focused host-feature test passes1/1 in1.36s, session70838 terminal0;
evidence `target/task-tmp/current-latency.p7U3OE/large-invoke-retry-baseline.log`.
Source inspection locates a candidate duplicate: both `recover_clean_execution`
and `recover_clean_invocation_error` perform full work/authorization validation
then call `recover_clean_acknowledgement`, which validates the same immutable
work again. Any private continuation must retain signature/scope checks, error
precedence, exact retirement comparisons and malformed-preimage rejection.
This observation is not a measured candidate improvement or a release gate pass.

### 2026-09-19: no-std boundary and pinned maintained-example builds

`cargo +nightly-2025-05-09 check --locked --offline -p vos --no-default-features --lib`
passes5.04s (session4019 terminal0), with existing warnings. This is a library
compile boundary check, not embedded-target execution or a warning-free lint gate.
Evidence: `target/task-tmp/current-latency.p7U3OE/no-std-check.log`.

The actor example workspace used floating `nightly`, and `just build-examples`
overrode it explicitly. Pinned the actor workspace to `nightly-2026-03-20`,
matching the custom runtime workspace; removed the floating recipe override
and added `--locked` to all five builds. `CARGO_NET_OFFLINE=true just build-examples`
passes for Counter, Shared Board, Private Notes, Local Signer and the custom
Linear runtime. Session52550 terminal0; evidence
`target/task-tmp/current-latency.p7U3OE/build-examples.log`. Shared target and
disk-backed TMPDIR used throughout; no lockfile or production-pin changes.
`git diff --check` passes. These are source guest builds, not signed-package
reproduction, cross-profile deployment or full cryptographic proof qualification.

### 2026-09-19: ingress and extension qualification boundaries clarified

HTTP guide now reflects native operator API bootstrap and the live receipt-bearing
Public Counter mutation/restart campaign; it retains non-Public, yield/resume,
Private/Attested and crash-matrix gaps. Name-based adapter behavior is explicitly
separate from the qualified clean binary workflow. SSH guide and compact status
now distinguish listener/host-key smoke checks from unqualified authenticated
shell/route/proof behavior; an operator API credential is not evidence of SSH
credential enrollment. Extension guides no longer claim Local installation is
absent, but do not claim Counter evidence qualifies Substrate transactions.

Source boundaries checked: native startup bootstrap credential kind is Api;
SSH authenticates via `authenticate_ssh_public_key`; clean HTTP preparation
authenticates via `authenticate_clean_api`. No runtime changes or external
network transactions. Static clean-break gate and `git diff --check` pass;
evidence `target/task-tmp/current-latency.p7U3OE/ingress-docs-clean-break.log`.
Broader adapter/extension integration remains unqualified by this docs update.

### 2026-09-19: operator documentation aligned with qualified Local workflow

README, getting-started, operations, actor and example guides still advertised
the earlier absence of Local Create/Install/invocation. Updated them to the
implemented Linux commands, with Counter build/install instructions, canonical
ATQ1 invocation boundary, exact-resume guidance, bounded historical retention
and explicit disposable-test/Shared/proof limitations. Current release help
was checked for actor build, Local Install and managed invocation arguments;
package output naming was checked against the builder. The space-module header
was corrected; no executable production logic or artifact changed.

The static retired-command regex also falsely classified `install-local-actor`
as retired `install`. Added a complete-word boundary and executable matcher
regressions for retained Local verbs and retired whitespace/end-of-line/Markdown
forms. `bash scripts/check-agent-clean-break.sh` passes with offline Cargo,
shared target and disk-backed TMPDIR (build45.29s, session21222 terminal0).
Evidence: `target/task-tmp/current-latency.p7U3OE/docs-clean-break.log`.
`bash -n` and `git diff --check` pass. This is the static CLI/documentation gate,
not the entire `just clean-break-check` recipe or a full release documentation
audit. Remaining ingress/extension/example and proof/deployment gates stay open.

### 2026-09-19: complete current host-feature library regression

At `ba2d08ad`, the complete host-feature library suite passes1,869 tests,
zero failures,3 ignored,1,411.11s (23m31s); build13.02s. Command:
`cargo +nightly-2025-05-09 test --locked --offline -p vos --features 'agent-transition-proof private-agent-store http-ingress ssh-ingress' --lib -- --test-threads=1`.
Shared CARGO_TARGET_DIR and disk-backed TMPDIR; session14453 terminal0.
Evidence: `target/task-tmp/current-latency.p7U3OE/host-library-suite.log`.
One uninterrupted run, no source fixes, no narrowed workloads. The complete
514-query inventory rotation and system-attachment checkpoint/drain tests pass.
This supersedes the earlier full host-feature run with one outdated assertion
and its separate corrected rerun; current regression evidence is now all-green
for this precise suite, not for all production gates.

Ignored (not claimed as passing in this run): native-operation initial-capture
headroom diagnostic at the real64MiB journal boundary; fixed-history physical
decode timing probe requiring an explicit copied-db fixture; repeated large-ACK
CPU profiling probe. Their older evidence remains historical. Enabling
`agent-transition-proof` does not by itself establish the full Private/Attested
cryptographic proof matrix. Startup10s, ordinary Shared finality, authenticated
reclamation and remaining crash/proof/release requirements stay open.

### 2026-09-19: current-source default-feature library regression

At `7e096a31`, the complete default-feature library suite passes1,434 tests,
zero failures,1 ignored,200.90s. Command:
`cargo +nightly-2025-05-09 test --locked --offline -p vos --lib -- --test-threads=1`,
using the shared target and disk-backed TMPDIR. Session6085 terminal0;
evidence `target/task-tmp/current-latency.p7U3OE/default-library-suite.log`.
No source fixes or reduced workloads were needed. This updates the older
`206ea1e3` default-feature baseline, but does not substitute for a current full
host-feature suite, proof qualification or failing production readiness gate.

### 2026-09-19: current-source CLI regression and integration gates

Source `14b81955`, nightly-2025-05-09, locked/offline, shared CARGO_TARGET_DIR and
disk-backed TMPDIR. CLI binary/unit suite passes255 tests, zero failures,
19 ignored,73.34s (build0.27s). Command:
`cargo +nightly-2025-05-09 test --locked --offline -p vosx --bin vosx -- --test-threads=1`.
Session67943 terminal0. Ignored campaigns are not counted as passes; the two
explicit live Counter campaigns are recorded separately below.

Integration command:
`cargo +nightly-2025-05-09 test --locked --offline -p vosx --test build_actor_e2e --test build_task_e2e --test shutdown_smoke --no-fail-fast -- --test-threads=1`.
Actor-build4 pass25.48s; task-build1 passes28.19s; shutdown smoke fails11.68s
because no endpoint is published within the unchanged10s startup deadline.
It never reaches SIGTERM or the5s shutdown assertion. Build4.95s;
session9276 terminal101. No gates relaxed and no source changes required.

Evidence: `target/task-tmp/current-latency.p7U3OE/cli-suite.log` and
`cli-integration.log`. Failed smoke fixtures remain at their original paths:
`target/task-tmp/vosx-shutdown-450908-data-1789827038495611180` and
`target/task-tmp/vosx-shutdown-450908-config-1789827038495713962`.
The test child guard reaped its daemon; subsequent host process inspection found
no `vosx space up shutdown-smoke` process. Do not remove or relocate failure
evidence. Full library/proof and production gates are not closed by these runs.

### 2026-09-19: current-release fresh invocation and restart/read

Extended only the ignored live-test fixture whitelist for `current-latency-smoke`
with required `current-latency.` path prefix. It uses the same exact retained
Create request/ACK verification as `fresh-ack-smoke`; no success, retirement,
retry or value assertions were removed. No production runtime or artifact changed.
Locked/offline vosx test compilation passes26.03s (session69735 terminal0).

On the original `current-latency.p7U3OE` fixture, restart27s precedes a fresh
Counter increment: managed attempt25.33s, full test27.20s, pass. Shutdown2s;
next restart33s precedes a fresh read: managed attempt25.76s, full test27.56s,
pass. Both tests verify positive retirement, rejected post-retirement Invoke,
exact positive ACK retry and managed resume; read verifies persisted value7.
Both shutdowns complete within2s without forced cleanup. Probe session80905
terminal0; host process inspection finds no matching remaining daemon.
Both restarts still fail10s readiness. These Public-policy checks do not qualify
Private/Attested proofs or a general crash matrix. No controlled speedup claim.

Evidence under the same fixture root: `invoke-build.log`, `invoke-probe.sh`,
`invoke-probe.log`, `mutation-up.log`, `mutation-test.log`, `read-up.log`,
`read-test.log`. Release SHA-256 unchanged. Test executable SHA-256:
`ee6ab0da7f2063ef996ebfd8a17539028e4a4a489dc5f8ff00e201e7176a0116`.
Mutation ID `dea0f17e60e4b1b2ece77ab530f159c10f585edc8cdf8fc7a1bf22dc40751d8f`;
read ID `d74795a0cd4cd3d296bee5e8636fc38bf84ca8d708722a25477958b13bb484e6`.
Counter value is now7: preserve request stores; do not issue another fresh
increment when reproducing recovery. The probe guards against log overwrites.

### 2026-09-19: current-release fresh Create/Install measurement

No implementation or artifact changes. Verified release SHA-256 remains
`697324387cf98331f0c237e228dfc9e98947c8a97f9f1204dfa3d8eca985ce20`.
A new disposable `current-latency-smoke` space was generated with the release,
using isolated XDG roots under the shared target, not `/tmp`. Generated HTTP/SSH
configuration was enabled automatically; only ports changed to18099/2243.
Only the immutable Counter package was copied from the earlier fixture; no
host store was copied, moved or reset.

Results: first readiness18s (fails10s gate); HTTP status and SSH keyscan pass;
fresh Create38s and fresh Counter Install45s both exit0 with verified signed
acknowledgements and empty stderr, without retry/resume. SIGTERM completes in
less than1s; no forced cleanup. Probe session89278 terminal0; subsequent host
process inspection finds no matching qualification daemon. This is not a
controlled before/after comparison and does not remeasure fresh invocation.

The logs narrow the operation bottleneck: Create lifecycle takes13,029ms;
publication completes at33,901ms from lifecycle start, including20,705ms route
reconciliation (20,463ms inventory). Both Create and Install synchronously call
`self.reconcile()` before returning their successful result in
`vos/src/agent/production_owner.rs`. Install's final reconciliation takes19,570ms
(18,942ms inventory); do not attribute its entire45s wall time to this stage.
The initial one-agent inventory takes11,989ms across four queries; after Create,
two-agent inventory requires six queries. This explains why inventory work
matters beyond startup. Do not bypass authenticated publication to reduce it.

Evidence: shared `target/task-tmp/current-latency.p7U3OE/`, including `new.json`,
`probe.sh`, `probe.log`, `up.log`, HTTP/SSH output and `create.txt`/`install.txt`.
Space ID: `64877d8203099e9bb2ab739487853708087a7b380bb14507f2d8e7ac0847c6bf`.
Local Agent: `ba7d547d71e6e54f276abcd5bcc49486e103606b27393693eb63194646dc5fb2`.
Preserve this fixture at its original absolute path with its operation evidence.
The previous `fresh-ack-release.Of5a75` recovery fixture remains untouched.

### 2026-09-19: eight-entry release, two restart passes

Release `cca4c911` built locked/offline nightly-2025-05-09 in6m35s; SHA-256:
`697324387cf98331f0c237e228dfc9e98947c8a97f9f1204dfa3d8eca985ce20`.
Both bundle verifications pass with unchanged runtime/system pins. Two
successive probes used the original `fresh-ack-release.Of5a75` space without
relocation/reset or fresh mutation. Both pass HTTP, unchanged SSH identity,
live409 guidance, unchanged retained Create request, retained Counter read,
retirement and exact ACK retry. SIGTERM completes within1s in both, without
forced cleanup. Build/probe sessions86622/79561 terminal0; no remaining
vosx/cargo/rustc found after the run.

| Measurement | First pass | Second pass |
| --- | ---: | ---: |
| Readiness (10s gate) | 36s, fail | 29s, fail |
| System-owner cumulative | 14,447ms | 8,022ms |
| Runtime work before owner | 20 calls /12,307.4ms | 14 calls /6,385.3ms |
| Initial inventory | 20,422ms | 19,772ms |
| Initial full route reconciliation | 21,264ms | 20,562ms |
| Next periodic full reconciliation | 3,707ms | 3,567ms |

The first pass recovers existing history before the new policy can schedule
checkpoints. The second shows a shorter subsequent replay workload. These are
two observations, not a same-history A/B or a broad steady-state throughput
proof. Both complete one post-ready periodic refresh; more frequent checkpoint
work did not prevent these checks completing. Inventory now dominates this
fixture's remaining startup delay. No readiness gate is closed and no fresh
Create/Install/invocation latency improvement is inferred.

Evidence: shared `target/task-tmp/eight-entry-release.1zodLo/`: `build.log`,
`probe.sh`, `first-probe.log`, `second-probe.log`, and separate `first/`,
`second/` bundle/phase logs, HTTP/SSH output, conflict/request-integrity checks
and `read-test.log`. Prior release preserved as `vosx-before`. The release
and compact status now include8-entry scheduling; next investigate the roughly
20s authenticated initial inventory while preserving projection-head/credential
validation. Ordinary Shared finality, reclamation and proof/recovery gates also
remain part of the full objective.

### 2026-09-19: earlier idle checkpoint scheduling candidate

Existing owner-phase events now locate the expensive startup boundary:
`reproduce_genesis_archive`163ms → `open_shared_host`33,094ms; later provision,
drain and attachment finish the owner. This is32,931ms in the shared-host open
step, not evidence of two identical expensive owner opens. Runtime calls in
that interval need authenticated replay; do not skip them or trust an unsigned
materialized image.

Host scheduling now triggers idle system-projection checkpoints at8 retained
physical entries instead of32. This is not the protocol history/capacity limit,
issuer retention limit, or authorization policy. It uses the unchanged signed
snapshot/reattachment path and still skips reserved projections or management
work. Earlier scheduling trades more checkpoint work for a shorter future
cold-replay suffix; it cannot shorten the first reopen of an existing longer
suffix retroactively or guarantee10s startup (inventory remains expensive).

Tests:3 checkpoint threshold/exclusion/failure-recovery regressions pass11.19s;
full514-query rotation workload passes229.53s. It checks every ordered index,
authenticated monotonic snapshot and unchanged query result, now requiring at
most10 retained entries at each pre-dispatch sample (8 trigger plus completed
two-entry query). No workload or crash assertions removed. Evidence:
`target/task-tmp/eight-entry-checkpoint-tests.log`, session23585 terminal0;
build30.70s. These tests are not controlled production throughput measurements.

Release executable remains `3a990280` with32-entry scheduling. Candidate is
source-only until release rebuild and live qualification. Next measure a first
restart, a completed authenticated inventory cycle and a second restart on the
same original-path disposable fixture; record both replay and checkpoint/steady
state costs. Preserve all pending/crash evidence and unchanged readiness gates.

For a compact review/test-deployment summary, start with
[the current status](agent-saga-status.md). It does not replace this evidence
history or narrow the full saga objective.

### System-owner latency boundary confirmed

Existing `attachment-refresh-release.uESjEc/up.log` contains38 physical runtime
executions before `system_owner`, totaling30,946.6ms;30 inputs over700KB account
for30,588.7ms. System-owner cumulative time is34,937ms. These spans explain
most of that stage, but the logs do not label each runtime call as a particular
replay/management subtype. Avoid attributing all38 to one subtype without
further evidence. The source's opportunistic checkpoint trigger is32 retained
physical entries, not a10s replay-cost bound. Next inspect authenticated replay
and checkpoint scheduling; another administrative-status micro-optimization
cannot remove30s of guest execution. No new build or fixture mutation was
needed for this analysis.

### 2026-09-19: attachment-refresh release qualified

Release source `3a990280` built locked/offline with nightly-2025-05-09 in6m18s.
Executable SHA-256:
`15f23e7bd959356c7f7a5997efb5f4ddb245b8fa07de84f67a358d78329a7e5a`.
Bundle creation/verification pass with unchanged runtime/system pins. On the
original `fresh-ack-release.Of5a75` fixture, HTTP status and unchanged SSH key
pass, retired Create reports409 with inspect-evidence guidance, and request
bytes match their pre-probe SHA-256. Retained Counter read/retirement/exact ACK
retry passes2.54s (managed0.66s, NOT fresh invocation latency). SIGTERM exits
within1s without forced cleanup. Build/probe sessions90004/80115 terminal0;
post-run inspection found no vosx/cargo/rustc.

Startup58s still fails10s gate. Cumulative system-owner recovery34,937ms,
lifecycle controller35,391ms, production ready57,945ms. Initial inventory
loads in21,342ms and route reconciliation completes in22,328ms. Its six
queries now execute43 runtime calls: Credential8, each remaining page7.
The prior phase-logged release executed61 calls. This verifies removal of
repeated directory-query work, not a controlled end-to-end speedup: history,
checkpoint placement and host conditions differ, and owner recovery grew.

Across those six queries, phase totals (runtime contribution in parentheses):
prepare475ms (134.9), reserve/checkpoint1,976ms (21.5), identity403ms (136.5),
persist216ms (0), reopen593ms (132.6), Invoke11,428ms (9,419.7),
ACK6,029ms (4,025.2), complete214ms (0). Cumulative families were differenced
separately as documented below. Remaining reservation/Invoke/ACK host residuals
are roughly1.95/2.01/2.00s; physical runtime execution still dominates inventory.
System-owner recovery is now the largest observed startup stage and needs
its own bounded attribution before claiming readiness can meet10s.

Evidence: shared `target/task-tmp/attachment-refresh-release.uESjEc/`, including
`build.log`, `probe.sh`, `probe.log`, `bundle/`, `up.log`, `read-test.log`,
`conflict.stderr`, `request-before.sha256`, HTTP/SSH outputs and preserved
`vosx-before`. No old fixture was relocated or reset. No fresh Create/Install
or invocation latency was measured on this release. Full production gates
remain open; the existing two-batch review organization is unchanged.

### 2026-09-19: unchanged attachment refresh no longer queries actor lanes

`SharedAgentNetworkHost::refresh` previously called full host `list()`, which
builds administrative status and executes `engine_lanes()` through the runtime
actor-directory query. Refresh consumed only ownership/committee facts.
It now lists the existing authenticated attachment view and compares the same
generation, route, membership, committee-transition and role fingerprint.
An absent/stale/changed attachment still loads full status (including snapshot)
and follows the existing retire/rebuild path. Dispatch, capacity, Raft barrier,
admission and physical recovery checks remain in their existing owners.
No long-lived validation cache, guest change or new trust assertion is added.
Obsolete full-status fingerprint wrappers were removed.

The expanded attachment regression checks every narrow field against full
status, preserves the owner through three unchanged refreshes, then verifies
stale replacement, retired-handler rejection and restart recovery. Final-source
verification:8 network tests passed (0.60s), attachment regression passed
(3.37s),16 repeated system promotions passed (9.98s), native management
application/receipt recovery passed (42.19s). Session80564 terminal0; evidence
`target/task-tmp/attachment-refresh-final-tests.log`. Initial attachment check
also passed (`attachment-refresh-regression.log`, session5495).

The release executable remains `1c9ebdab` with SHA-256 `46c64811…`. This source
change is not yet release-built or live-performance-qualified. Next measure
the same preserved fixture and phase counters before attributing any startup
gain; the eliminated directory work is identified in source, not a measured
end-to-end improvement. All broader release gates remain open.

### Conflict-reporting release and phase qualification

Release source `1c9ebdab` (production change `12e45422`) built locked/offline
with nightly-2025-05-09 in6m49s. SHA-256:
`46c64811783cedc96c0b676f68edcdfca7c85fbea27bce2d23f00d3f53d767a2`.
Bundle creation/verification pass with unchanged guest/system pins. On the
original `fresh-ack-release.Of5a75` fixture, readiness took53s (fails10s gate),
HTTP passed and SSH identity matched. Original retired Create now reports409
with inspect-evidence guidance; SHA-256 confirms its request file unchanged.
Retained Counter read/retirement/exact ACK retry passed2.07s (managed0.54s;
this reuses the old read, not a fresh invocation latency measurement).
SIGTERM exited within1s without forced cleanup. Sessions53595/46572 terminal0;
post-run inspection found no vosx/cargo/rustc. No new functional speedup claimed.

Evidence under shared target `task-tmp/lifecycle-conflict-release.1bE9kx/`:
`build.log`, `probe.sh`, `probe.log`, `bundle/`, `up.log`, `status.json`,
`ssh-key.txt`, `conflict.stderr`, `request-before.sha256`, `read-test.log`.
Previous executable preserved as `vosx-before`. Fixture remains at its original
absolute path; this separate evidence directory does not contain relocated
host stores.

Enabled existing projection-phase logging. Summing deltas within each of the
two cumulative timing families for six initial inventory queries yields:

| Phase | Total ms | Enclosed runtime ms | Outside runtime spans ms |
| --- | ---: | ---: | ---: |
| Prepare | 1,733 | 272.6 | 1,460.4 |
| Reserve/checkpoint | 3,588 | 270.8 | 3,317.2 |
| Identity | 396 | 130.7 | 265.3 |
| Persist pending | 219 | 0 | 219 |
| Reopen/check retained ACK | 1,258 | 136.4 | 1,121.6 |
| Invoke | 13,451 | 9,504.8 | 3,946.2 |
| Acknowledge | 7,041 | 3,857.7 | 3,183.3 |
| Complete pending | 201 | 0 | 201 |

These are phase attribution on one run, not CPU profiling or controlled
before/after results. Preparation includes reattachment; reserve includes
opportunistic checkpoint and bounded reservation attempts. Runtime spans
include program load/run, not every surrounding validation. Logging/rounding
and boundary overhead remain. The explicit pending-record persist/clear
phases total420ms, so they cannot alone explain the multi-second residual.
Next bounded diagnosis should examine reserve/checkpoint's3.3s host residual
and repeated host validation around Invoke/ACK, retaining all binding, admission
and crash-recovery checks. Do not remove authenticated queries or infer that
all remaining cost is disk I/O. Full production release gates remain open.

### Inventory latency attribution from current release evidence

Analysis of existing `fresh-ack-release.Of5a75/framed-invoke-up.log` (no new
daemon/build) separates each completed startup inventory query from its
enclosed `physical Agent runtime execution` events. For two visible agents,
initial inventory required six sequential authenticated queries:

| Selector | Query ms | Runtime ms | Large calls (>700KB) | Outside runtime spans ms |
| --- | ---: | ---: | ---: | ---: |
| Credential | 4,466 | 2,351.5 | 2 | 2,114.5 |
| Agents | 4,579 | 2,330.1 | 2 | 2,248.9 |
| System-agent replicas | 4,708 | 2,275.3 | 2 | 2,432.7 |
| System-agent actors | 4,806 | 2,299.9 | 2 | 2,506.1 |
| Local-agent replicas | 4,824 | 2,218.4 | 2 | 2,605.6 |
| Local-agent actors | 5,191 | 2,269.5 | 2 | 2,921.5 |

Totals: queries28,574ms;61 runtime spans13,744.7ms;12 large calls12,687.8ms.
About14,829.3ms is outside those runtime spans. Rounding and outer query
boundaries apply; this residual is NOT attributed to one function, disk I/O,
or a replay category. Initial route reconciliation then totals29,554ms.
The later unchanged-head Credential refresh takes3,527ms, including2,336.8ms
in10 runtime spans, so the existing authenticated inventory reuse is active.

Source confirms each full refresh queries Credential, agent pages, then replica
and actor pages per agent; pagination can add queries. Each query still requires
authenticated dispatch and completion. Do not bypass these boundaries or use
stale unauthenticated inventory to satisfy readiness. Guest-only optimization
cannot remove the measured host-side residual.

Next bounded measurement: enable
`vos::agent::clean_bootstrap=debug` alongside current owner/driver logging in
the next release qualification. Existing `Authority projection phase complete`
events cover prepare/reserve/identity/persist, and execution events cover
reopen/invoke/acknowledge/complete. Each family reports cumulative elapsed time
from its own start; subtract consecutive values within a family, not across
families. These events were filtered out of the retained run, so their missing
attribution cannot be inferred. Combine this with the pending conflict-reporting
release rebuild rather than launching another independent optimization build.

### Lifecycle conflict reporting corrected (source, not rebuilt release)

Local Create/Install now map `Lifecycle(Conflict)` to HTTP409 with guidance to
inspect retained evidence. Other unavailable cases remain503; timeout remains
504. Create's existing scope/authorization403 mapping is unchanged. The CLI's
retained submission paths preserve requests and distinguish409 from transient
errors, explicitly warning that unsigned HTTP conflict is not a signed outcome
and does not prove the original operation failed. No lifecycle/issuer retention,
authentication, signed wire format, guest pin or completion state changed.

Tests: server conflict/unavailability mapping1 passed; client acknowledgement
and real-loopback409/request-preservation regression1 passed (2.58s); adjacent
Install tests7 passed/1 ignored (2.81s); noncanonical/unsigned ingress1 passed.
Logs under shared `target/task-tmp`: `lifecycle-conflict-server-test.log`,
`lifecycle-conflict-client-test.log`, `lifecycle-conflict-install-tests.log`,
`lifecycle-conflict-ingress-tests.log`. Sessions66512/4744/36573 terminal0.
The release binary remains `b7cfa17d`; this reporting fix needs its next release
rebuild and live qualification. It does not restore historical retired retries.

Evidence clarification: `submit-local-install` verifies and returns a retained
client ACK without contacting the server when one exists. The successful
Install retry commands below establish client exact-retry verification, NOT
server-side Install replay. Counter Invoke rejection and ACK retry tests do
contact the daemon, and fresh post-restart reads prove the value remains7.
Server-side Install replay remains unqualified by those CLI retry commands.

### Counter invocation and read-after-restart qualified

Unchanged release `b7cfa17d` passes the full Public Counter campaign on the
original `fresh-ack-release.Of5a75` fixture. Latest Install exact retry verified.
Increment-by7 completed in29.12s (full test31.03s), returned7 and completed
positive retirement. Two late Invoke replays rejected the consumed identity;
two ACK retries returned identical positive responses. After restart a fresh
value query returned7, completed in34.80s (full test36.71s), and passed the same
retirement/retry checks. Restarts54s/53s still fail the10s gate; both SIGTERM
shutdowns passed within2s without forced cleanup. Session11199 terminal0;
post-run inspection found no vosx/cargo/rustc. Not non-Public policy/proof
qualification; latency remains a production blocker.

Mutation: `79d4818fb02562f45c35a14e7285fe5ecc60ed624da2bb622f41076543fd23b6`.
Read: `f82147371d7a3ea729659a1362ef10cc8657344f295bd2f4616f92403247e02e`.
Do not issue another fresh increment to repeat this test; reuse retained intent.
Evidence under the same fixture: `framed-invoke-probe.sh`,
`framed-invoke-probe.log`, `framed-invoke-up.log`, `invoke-test-framed.log`,
`read-up.log`, `read-test.log`, `install-retry-framed.json`,
`framed-ack-test-build-fixed.log` (build3.03s).

Correction to prior diagnosis: the issuer deliberately retains only the latest
acknowledged decision plus bounded unacknowledged decisions. Its authorization
high-water rejects reuse of older acknowledged identifiers, and finalized
recovery consults only the latest acknowledged record. Moving lookup before
`pledge` would not recover old Create after Install. Extending historical server
retry requires an explicit retention/protocol decision, not bypassing checks.
The observed503 and its retry guidance remain limitations, not evidence of
failed creation. No production retry fix or expanded retention is claimed.

The test uses the existing framed stores at their original paths to load the
one retained Create request/ACK, verifies the signature against that exact
request, and checks SpaceID before deriving Counter coordinates. First loader
attempt treated framed bytes as raw wire and failed before mutation
(session70857 exit101, `invoke-test.log`; latest Install retry passed).
Corrected loader and full campaign pass above; failed logs and earlier503
evidence remain intact. Only test code changed, not the guest or release.

### Completed Create retry after Install: conflict found

The invocation qualification probe stopped before any mutation. Restart of the
same `fresh-ack-release.Of5a75` fixture reached readiness in60s, then
`space submit-local-create` with the original retained signed Create request
returned HTTP503. Server log: `Local Create did not complete:
Lifecycle(Conflict)`. No fresh Create or replacement nonce was submitted.
The probe exited1 (session54647); its cleanup stopped the exact daemon without
forced cleanup, and subsequent process inspection found no vosx/cargo/rustc.
Install retry, mutation and read-after-restart were NOT reached.

Source explanation: Local Install uses `CleanManagementIntentSlot::handoff_retired`
to replace the single retired per-Agent intent with its next signed request.
`CleanSystemAgentBootstrapOwner::create_local_agent` calls `slot.pledge` before
`recover_finalized_application`; `pledge` rejects a different current request.
Consequently an older completed Create cannot reach finalized issuer recovery
after that slot has advanced to Install. This is a retry-lifetime limitation,
not evidence that the previously acknowledged creation or installation failed.
Do not weaken slot authentication or relabel/reset the store to avoid it.
The correction above explains the bounded-retention contract: changing lookup
order is insufficient. Current retained retries and older retired replay must
not be conflated when qualifying the release.

Evidence: `invoke-probe.sh`, `invoke-probe.log`, `invoke-up.log`,
`create-retry.stderr` (503 error), and empty `create-retry.json` under the same
fixture. The original `create.json` acknowledgement text and all retained
requests/acknowledgements remain intact. The failed probe script is guarded
against reuse; use a new evidence path for further attempts.

The existing ignored Counter test now explicitly allows `fresh-ack-smoke`
only with the `fresh-ack-release.` fixture prefix and Counter-only checks.
It reuses the existing parent-directory guard and points to `counter.vos`.
The test binary builds successfully (4.97s; session62055 terminal0), but its
new campaign path has not executed because the prerequisite retry failed.
No production implementation or guest pin changed in this follow-up.

### Release `b7cfa17d`: restart and fresh Install

The same exact-path `fresh-ack-release.Of5a75` fixture restarted successfully
in54s. HTTP status passed and SSH host identity matched first startup.
This still fails the10s readiness gate. Cumulative phases: material34ms,
discovery48ms, admission51ms, system owner24,344ms, lifecycle controller24,605ms,
production ready53,913ms. Initial reconciliation took28,891ms. Retained-history
recovery and reconciliation dominate the observed restart stages; these logs
do not attribute every interval to an individual function or runtime call.

Fresh Counter Install into Agent `f7dd7306…` succeeded in65s, with a verified
installation acknowledgement and no timeout/resume. It used a copy of the
previously qualified `issuer-reuse-release.QR6Y4x/counter-dist/counter.vos`
package, name `counter`, no constructor bytes. Only the immutable package was
copied, not the old space stores or identity. Post-Install SIGTERM exited
successfully in under1s, with no forced cleanup. Session38226 is terminal0;
post-run inspection found no vosx/cargo/rustc. Binary checksum is unchanged.

Evidence in `fresh-ack-release.Of5a75`: `install-probe.sh`, `install-probe.log`,
`install-up.log`, `install-status.json`, `install-ssh-key.txt`, `install.txt`,
`install.stderr`, and `counter.vos`. Keep all fixture data at its original
absolute path. Create/Install now both succeed on the current release, but
their43s/65s timings are not acceptable production latency or a controlled
before/after comparison. Invocation, install retry/read-after-restart and the
broader release gates remain to be qualified. Do not repeat fresh Install
against this already installed actor to simulate a retry.

### Release `b7cfa17d`: fresh startup and Create

The locked/offline nightly-2025-05-09 release build passed in7m08s with the
unchanged production profile. Executable SHA-256:
`2b9b205e82d066b66683fe9e018ae353ba160b2cfa66fee4e1fd76606a770613`.
Its release bundle verifies and contains runtime `25bdad0f…`; authority/catalog
template identities are unchanged. This supersedes the older executable below.

A newly created isolated space automatically generated active HTTP/SSH config.
Only ports were changed to18098/2242 for isolation. First startup reached
readiness in21s; HTTP status was `ok` and SSH keyscan succeeded. The unchanged
10s startup gate therefore still fails. Cumulative startup phases were:
material36ms, discovery40ms, admission50ms, system owner5,359ms, lifecycle
controller5,361ms and production ready20,672ms. Initial route reconciliation
took15,180ms. These identify the remaining startup stages, not individual
hot functions.

Fresh `space create-local-agent fresh-ack-smoke` succeeded in43s without a
timeout/resume and returned a verified creation acknowledgement for Agent
`f7dd7306e364c65d7de953846f215675b031a0dba5af30e5f7f4415d1cf09a00`.
Immediate post-Create SIGTERM exited successfully within1s, without forced
cleanup. This is one shutdown observation, not universal busy-shutdown proof.
At this first probe, Install and fresh invocation had not been measured. Do not
compare these fresh-history timings directly with earlier retained-history
probes or infer that the14.74% fixed ACK gas saving explains the whole change.

Evidence and exact original-path fixture:
`target/task-tmp/fresh-ack-release.Of5a75/` in the shared target. Files include
`build.log`, `bundle/`, `new.json`, `probe.sh`, `probe.log`, `up.log`,
`status.json`, `ssh-key.txt`, `create.json` (CLI acknowledgement text, not JSON)
and `create.stderr`; the previous binary is preserved as `vosx-before`.
SpaceID: `0119ae586ab102b90dd606b390ef18d0d68a3c1422f2617f497d5bdf2cd971a1`.
Data/config/cache remain in this directory; never relocate raw stores for boot.
Build/probe sessions17725/70725 are terminal0; post-run process inspection
found no vosx/cargo/rustc. No existing fixture was modified.

The subsequent restart and Install are recorded above. Next measure invocation
and exact retained-request retry/read-after-restart, then update the review
handoff. Startup/Create/Install latency, ordinary Shared finality,
authenticated reclamation and full proof/recovery/release gates remain open.

### Fresh-ACK bundled artifact qualification

The fresh-ACK optimization is now in the checked-in guest. Two independent
immutable exports of source `4a208b19baa9dd36b216548681f5a3ab5add3401`, built
with nightly-2026-03-20 using separate targets, produced byte-identical ELFs
and PVMs. Conversion used the preserved, qualified builder from
`task-tmp/r17-release-candidate.fNbf43/builder/vosx`. Provenance, protocol
ProgramId, build-time digest and bundled bytes were updated together.

ProgramId: `25bdad0f9a1b0ca8450338d916adc41306d9d740f68bb5b2490ab8b8b9fb3da1`.
ELF BLAKE2b-256: `1698aff38de4b34eed9ca28c4718e2d1e7be60017d1f05d017dd1f4e8d011b72`.
PVM BLAKE2b-256: `a3cb1cfbc62cf5e5a9bb21edd892caccb41ce484da39e78577eedc9dc78f7a78`.
ABI remains `vos-agent-runtime-abi-260915-r17`; system templates are unchanged.

The fixed 793,734-byte ACK comparison has byte-identical complete output and
gas decreases from395,232,496 to336,976,182 (14.74%). All eight candidate
checks pass, covering malformed ACKs, retired retries, terminal failures,
typed errors, expiry and byte-identical fail-closed rejection. Post-pin release
checks pass18/18; ordinary physical runtime tests pass4/4 (4.08s). Both
explicit candidate tests also pass (3.20s), checking exact install lineage
after restart and Attested Invoke/Resume public-output binding. These are
execution/binding checks, not full cryptographic proof qualification.
Evidence lives in shared disk-backed
`target/task-tmp/fresh-ack-candidate.xCeHWs/`: `build-{a,b}.log`,
`identity-{a,b}.log`, `cost.log`, `candidate-tests.log`, `post-pin-tests.log`,
and `post-pin-explicit-tests.log`. Sessions10956/96781 are terminal0.

At the artifact-only checkpoint, the release executable still contained
implementation `206ea1e3` and the old runtime pin. The next step was to rebuild
the release, verify its bundle and test a fresh
isolated space before making any live latency claim. Preserve old-space
fixtures at their original paths; the new ProgramId is not permission to
rewrite existing deployment identities. Startup/Create/Install latency,
ordinary Shared finality wiring, authenticated issuer reclamation and the
remaining proof/recovery/release matrix are still open. No merge or push has
occurred. These changes belong to review batch2, not a new architecture batch.

### Source optimization qualification (before repinning)

Fresh-ACK source optimization now removes one redundant availability-validation
pass within a single immutable-work call chain. `recover_clean_acknowledgement`
already validates the work before returning no retained acknowledgement; its
sole private continuation previously called the full validator again. That
continuation now calls a private authorization helper after work validation,
retaining descriptor/scope checks, typed authorization matching and signature
verification. Other callers still use the full validator. The original
NotCreated-before-invalid-work error ordering is preserved. No public unchecked
entry point, cross-call authentication cache or durable result shortcut exists.

Acknowledgement-selected host-feature regressions pass:31 passed, zero failed,
one ignored,48.93s (build27.64s). New fresh-ACK negatives corrupt blob bytes
without changing their references, and corrupt the receipt signature; both
reject without state mutation before a valid fresh ACK and exact retry succeed.
Evidence: `task-tmp/fresh-ack-validation-reuse-tests.log`; session30763 terminal0.
The bundled-PVM tests in that selection still execute the old pinned artifact:
they are not candidate-gas qualification for this source change.

At this earlier source-only checkpoint, the change was not yet bundled or
performance-qualified. The planned next step was to build a candidate guest,
compare exact output/gas using the existing fixed large-ACK test and
`VOS_AGENT_RUNTIME_COST_CANDIDATE`, then independently reproduce and update pins
only after equivalence/hostile-frame checks pass. The release executable remains
`206ea1e3` and guest pin/source remain `79c7d1f0…` / `aad65049`. Do not claim a
live latency improvement or close any production gate from native tests alone.

### Outer-runtime instruction attribution

Instruction attribution now separates the outer AgentRuntime from nested
actors using the existing read-only Refine observer. The opt-in
`VOS_AGENT_PROFILE_REFINE_MACHINES=1` is test-only: it selects the bundled
outer runtime for the native system fixture, disables that fixture's native
clean-runtime shortcut, and profiles physical calls with inputs over700KB.
Ordinary test defaults and the production `RefineContext::run` path remain
unchanged. No guest memory or request bytes are recorded. Deliberately invalid
shape-only packages used by negative tests remain shape-only in profiling mode.

The existing `native_management_intent_executes_bundled_authority_and_recovers_receipt`
test passes with real-system-runtime profiling (149.94s, build29.89s), including
its lifecycle, exact receipt, negative-scope and recovery assertions. The same
test passes with normal defaults/profiling disabled (45.44s). Large nested calls
show274.6–276.9 million outer instructions versus11.2–19.5 million inner actor
instructions. Six large calls perform142.0–143.6 million outer instructions
with zero inner instructions and zero host calls. Thus the outer runtime is
the dominant instruction workload here; optimizing the nested Authority actor
alone cannot remove the measured cost. Machine identity and instruction count
do not identify a specific outer function: investigate outer work decoding,
validation and commitment computation rather than assuming any check is
redundant. Preserve exact authenticated bytes and gas semantics.

Observed slice times (roughly5.6–6.0s outer versus0.3–0.6s inner in nested
calls) include tracing overhead and are **not production latency measurements**.
This is a deterministic fixture with bundled code, not the preserved live-space
query. No new performance fix or release qualification is claimed.

Evidence under shared target `task-tmp`:
`prepared-runtime-real-machine-attribution-fixed.log` (session78827 exit0),
`prepared-runtime-machine-attribution-default.log` (session50103 exit0).
The initial `prepared-runtime-machine-attribution.log` run passed but emitted
no large profiles because its system fixture took the native shortcut.
`prepared-runtime-real-machine-attribution.log` records the first diagnostic
attempt's negative-fixture mismatch; the scoped fixture correction fixes it,
and the final complete run passes. Sessions48310/59846 are terminal0/101.
Reproduce via the host-feature library command with the exact test above,
`--nocapture --test-threads=1`, the opt-in variable and disk-backed TMPDIR.

### Fresh startup phase diagnosis

Targeted startup-smoke diagnosis used existing logging only; no source or
deadline change. With `RUST_LOG=info,vosx::commands::space::clean_startup=debug,
vos::agent::local_journal_driver=debug`, the isolated fresh-space test again
failed its10s endpoint deadline (test11.16s). Cumulative clean-startup phases:
bootstrap material89ms, lifecycle discovery93ms, operation admission107ms,
system owner7,254ms, admin recovery7,254ms, Local host7,256ms, lifecycle
controller7,257ms. `production_ready` was not reached. Source places the
remaining wait inside `node.start_clean_local_agent_production`; it is not a
delay in configuration generation or discovery. Two completed large runtime
calls before `system_owner` took1,503,768us and1,516,560us, with771,614/782,000
input bytes. Later logs show small calls and retry lookups before the deadline;
they do not report a completed large invocation in that final partial stage.
Do not attribute the unmeasured interval to one specific runtime subtype.

Evidence: `task-tmp/prepared-runtime-startup-phase-regression.log`; session72049
is terminal101. Failing directories remain at original paths under shared
task-tmp: `vosx-shutdown-427703-data-1789493555590592188` and
`vosx-shutdown-427703-config-1789493555590691458`. The diagnostic run preserved
the prior failure as well. Post-run inspection found no vosx or cargo process.
Next performance diagnosis should separate bundled system-owner bootstrap work
from initial production reconciliation, preserving authenticated completion
before readiness. Do not publish an endpoint early to bypass this gate.

### CLI qualification

Current CLI qualification on HEAD `04454ef0` (production implementation still
`206ea1e3`): unit/binary suite255 passed, zero failed,19 ignored,70.78s
(build50.41s). Separate integration targets: actor-build4 passed24.21s;
task-build1 passed24.76s; shutdown smoke failed11.24s because no endpoint was
published within the unchanged10s startup deadline. The SIGTERM/5s shutdown
phase was never reached, so this result is a startup failure, not a shutdown
failure. Combined CLI evidence:260 passed, one failed,19 ignored. No startup
gate extension or new production behavior was introduced.

Commands used locked/offline nightly-2025-05-09 and the shared target/disk
TMPDIR: `cargo test -p vosx --bin vosx -- --test-threads=1`, followed by
`cargo test -p vosx --test build_actor_e2e --test build_task_e2e --test
shutdown_smoke -- --test-threads=1`. Logs under shared `task-tmp`:
`prepared-runtime-cli-suite.log` and `prepared-runtime-cli-integration.log`.
Sessions64072 and22388 are terminal (exit0 and101). Failure cleanup kills and
joins only its own daemon; post-run process inspection found no vosx, cargo
or rustc. Failing data/config directories remain at their original paths:
`task-tmp/vosx-shutdown-426457-data-1789493399736676170` and
`task-tmp/vosx-shutdown-426457-config-1789493399736745123`. Daemon stderr was
empty; it does not identify the precise startup phase. Do not reset or move
this fixture as a substitute for diagnosing startup. The release executable
and pinned artifacts remain unchanged; current CLI qualification is not green.

### Host-feature qualification

The full host-feature library run on implementation `206ea1e3` is terminal
with **1,867 passed, one failed, three ignored**,1671.06s (build2m23s).
Command: `cargo +nightly-2025-05-09 test --locked --offline -p vos --features
'agent-transition-proof private-agent-store http-ingress ssh-ingress' --lib
-- --test-threads=1`. Evidence: shared target
`task-tmp/prepared-runtime-host-feature-library-suite.log`; session99230 exit101.
The sole failure is `same_head_inventory_rotates_authenticated_suffix_past_1024_entries`:
its line18475 expected the original certified snapshot at query513 (Raft10),
but opportunistic checkpointing had legitimately advanced it to Raft1033.
All descriptor/selector/nonce and preceding exact ordered-index checks passed.
The old assertion predates the idle32-entry checkpoint scheduling policy.

A test-only correction is now verified: sample every query's certified
snapshot and audited retained-entry count; require monotonic snapshot progress,
unchanged certificate at an unchanged index, repeated rotations, and at most34
retained entries (32-entry trigger plus a completed two-entry pair). Retain all
514 queries, exact selectors/nonces/descriptors,1,028-entry ordered progress,
final snapshot equality and no-pending-work/join checks. No production behavior
or gate was changed. Focused full-workload rerun passed:one test, zero failures,
279.07s (build38.69s); session37290 is terminal0. Log:
`task-tmp/prepared-runtime-inventory-rotation-regression.log`. The observation
helper has only this one test caller. The original failing log is preserved.
Evidence is a full suite with one outdated assertion plus its passing corrected
full-workload rerun, not a second all-green full-suite invocation. No known
host-feature regression remains from this run. Production latency, ordinary
Shared finality, authenticated reclamation and full proof/release gates remain
open; this test-only change does not require rebuilding the release executable.

### Default-feature qualification

Full default-feature `vos` library regression suite at source `206ea1e3`
(documentation-only HEAD `06008adf`) passes:1,434 passed, zero failed, one
ignored,219.66s. Command: `cargo +nightly-2025-05-09 test --locked --offline
-p vos --lib -- --test-threads=1`, with the shared target and disk-backed
TMPDIR. Evidence: `task-tmp/prepared-runtime-default-library-suite.log`;
session77273 is terminal0. This supersedes the older default-library baseline
for the current recovery and preparation-cache implementation. It does not
replace the host-feature matrix, CLI suite, cryptographic proof qualification,
or production release gates. No implementation change in this qualification.

Further analysis of the already-recorded `prepared-runtime-release.cJZtXj`
startup log (no new probe) isolates the pre-inventory phase:30 runtime calls
total23,634,791us, including20 large calls totaling23,203,656us. Registry
verification is logged at16:38:02.494, first inventory reconciliation starts
at16:38:30.493, and readiness at16:39:01.010. Thus roughly28s precedes the
30.516s initial inventory reconciliation. Both portions contain substantial
runtime execution; the59s startup is not explained solely by a readiness
timer or by the one periodic Credential query. These timing events lack
operation subtypes: do not label every pre-inventory call as replay or assume
it can be skipped without following its authenticated recovery requirements.

### Latest release probe

Release `206ea1e3` is now built and live-probed. Build passed6m48s with the
unchanged release profile (`cargo +nightly-2025-05-09 build --locked --offline
--release -p vosx`); bundle creation and verification pass with unchanged guest
pins. Executable SHA-256:
`8a7eda3426da2c74086881a0577516fa8e817c53672bc9df6f38118789b6e2ee`.

On the preserved space at its original absolute path, readiness took59s;
HTTP status and the original SSH identity passed. One complete periodic
Credential query took3,439ms and route reconciliation3,884ms. Its ten runtime
load/run spans totaled2,510,839us. Eight smaller executions took19.8–25.5ms;
the two large inputs still dominate:788,374bytes /1,535,769us /875,226,651gas
and790,499bytes /806,345us /385,264,799gas. They total2,342,114us, roughly93%
of measured runtime time. About928ms of the query is outside these spans.
The two earlier retry lookups took10,576/11,130us; four post-query route-audit
executions took23.8–24.3ms each. The earlier `8716f6a7` sample was4,780ms for
the query and5,602ms for reconciliation, with small calls77–98ms; retained
history and workload differ, so these are observations, not a controlled
end-to-end speedup or evidence that changed gas was charged for identical work.
The large calls remain about2.3s together: preparation reuse does not solve
their execution cost. No fresh Create or Install latency was measured.

Retained Counter read/positive retirement/exact retry passed (test2.04s,
managed attempt0.58s); no fresh actor mutation or replacement nonce. SIGTERM
sent during the next newly started Credential query passed the unchanged5s
deadline without forced cleanup. This is one busy-shutdown pass, not universal
qualification. Startup still fails the10s gate. Resident memory was225.4MiB
at readiness and232.1MiB after reconciliation; observed process high-water was
261.0MiB. There is no matching old-release memory baseline, so these values
do not isolate cache overhead or establish deployment-scale memory bounds.

Evidence: shared target `task-tmp/prepared-runtime-release.cJZtXj/` contains
`build.log`, `bundle/`, `probe.sh`, `probe.log`, `up.log`, `counter-test.log`,
HTTP/SSH evidence, and `memory-{ready,reconciled}.txt`. `vosx-before`,
`data-before` and `config-before` preserve pre-probe evidence, not a space to
boot at a new path. Build session16999 and probe session40044 are terminal0;
post-probe host process inspection found no vosx daemon. No merge or push.

Next bounded performance work should attribute the two large invocation
transitions and the startup work preceding readiness, not repeat immutable
preparation optimization. Keep exact authenticated work and gas semantics.
The full integrated release matrix, ordinary Shared finality wiring,
authenticated256-record reclamation, and proof qualification remain open.

### Preparation implementation checkpoint

Validated program-preparation reuse is now implemented after review checkpoint
`97c08c88`. `refine::PreparedProgram` owns executor-validated standard bytes and
private Conformance/standard-latency tables. Cold and prepared loads share the
fresh-state initializer; every invocation gets its own memory, permissions,
registers, arguments, gas, pending-call state and inner-machine dictionary.
The Agent replay executor retains one preparation keyed by exact program bytes,
bounded by the existing 1,280KiB program limit. Cache replacement/invalid-input
tests pass. Oversized programs and poisoned cache locks fall back to the cold
loader rather than introducing new execution admission rules. No authorization
or execution result is cached by this mechanism. Tables are cloned into each
interpreter; this avoids repeated derivation, not all allocation. Retained
tables add memory per executor; deployment-scale memory impact is unmeasured.

Release-mode load-only measurement on the bundled 983,442-byte runtime with a
790,499-byte input buffer, 20 alternating samples per path: first run cold mean
67,057us versus prepared 3,039us (one-time preparation74,970us). A repeat while
other checks were active measured87,139us versus3,492us (preparation99,356us).
The synthetic zero input is never executed; these are load measurements, not
valid management requests or end-to-end Create/Install improvements. The
ignored `refine::tests::prepared_program_load_measurement` test is reproducible
with `VOS_PVM_PREPARE_BENCH_PROGRAM` pointing to `vosx/blobs/agent_runtime.pvm`,
using `cargo +nightly-2025-05-09 test --locked --offline --release -p vos-pvm
--lib refine::tests::prepared_program_load_measurement -- --exact --ignored
--nocapture --test-threads=1` and the existing disk-backed target/TMPDIR.

Qualification: current `vos-pvm` library260 passed/zero failed/two ignored
(0.73s), including cold/prepared flat/sparse corpus equivalence, gas/exit/output/
register/permission/mapped-memory comparisons, invalid input, changed arguments,
fresh writable state, and repeated nested-machine execution. `vos-pvm
--no-default-features` check passes. Default-feature local-journal-driver module
32 passed/zero failed (42.43s), including cache admission/replacement and existing
exact-retry/authentication/preflight regressions. Focused host build1m44s.
Evidence in shared target `task-tmp/prepared-program-{runtime-tests,
local-driver-tests,load-measurement}.log`; sessions11202,10149,62749,94489,
85355,17719 are terminal. No probe daemon was started or fixture mutated.

Next: rebuild the host-feature release, verify its unchanged guest bundle,
repeat the preserved-space inventory timing and busy-shutdown probes, and
measure memory. The release executable is still source `8716f6a7`; this new
source is **not yet live-qualified**. Runtime guest pins and frozen two-batch
review ranges remain unchanged. No production latency gate is closed, and the
Shared finality, authenticated reclamation and final proof/matrix work remains.

### Previous profiling checkpoint

Existing per-runtime diagnostics captured one complete periodic Credential
cycle on unchanged release `8716f6a7`; no diagnostic code or rebuild was needed.
Readiness40s, Credential dispatch4,780ms, full route reconciliation5,602ms.
Ten physical runtime executions inside the query total2,950,015us. Two large
inputs dominate those spans:788,374bytes /1,480,849us /875,295,164gas and
790,499bytes /821,093us /385,264,799gas. Eight smaller calls take roughly77–98ms
each; four additional route-audit calls after the query take88–92ms each.
Two pre-dispatch retry lookups take about99ms each. Roughly1.83s of the query
lies outside the measured runtime load/run spans; do not attribute it all to
one host subsystem without further measurement.

Evidence: `task-tmp/runtime-timings.Ti3CYX/{probe.sh,probe.log,up.log}`. The probe
enabled existing `local_journal_driver` debug logs, waited for one complete
post-readiness reconciliation, then joined the daemon without forced cleanup.
Session95824 is terminal. No new actor mutation or client operation was submitted.
The larger gas allowance and executor source locate the large-input calls in
the invocation-transition path; there is no operation label in these timing
events, so don't claim each exact subtype solely from input size/order.

A specific next optimization candidate follows from source inspection:
`ConformanceState` gas simulation is used to precompute block costs in
`Interpreter::with_memory_and_mode`; `Machine::load_with` parses/validates and
rebuilds this immutable program preparation on every Refine load. Existing
`Interpreter::predecode` produces reusable tables for another backend path,
but Refine does not currently reuse them. Investigate an opaque, validated,
bounded prepared-program cache in the Agent executor/Refine path, with fresh
memory, registers, arguments, gas and inner-machine state for every call.
Do not expose caller-forgeable gas tables, reuse execution results, omit
availability bytes from exact acknowledgements, or alter charged gas. Require
cold/prepared differential tests for exits, gas, outputs and state isolation,
then measure the actual gain. This candidate is not implemented or qualified.

Bounded production inventory CPU profiling completed on the unchanged
`8716f6a7` release. An8s user-CPU-clock sample at99Hz captured492 samples with
zero lost samples (4.058MiB private `perf.data`). It started at a freshly logged
periodic Credential query after readiness64s. The logged query took4,441ms;
inventory/route reconciliation took5,226ms. Cleanup waited for a completed
reconciliation and joined the daemon without forced cleanup; this cleanup is
not a busy-shutdown gate. Probe session41052 is terminal.

Current symbol-level CPU sample shares: interpreter `run_inner`51.63%,
conformance gas `dispatch_one`9.55%, `tick`8.94%, `feed`1.42%, and BLAKE2
compression18.50%. Compact-code parsing and two SPI validation functions each
accounted for about1%. These are sample shares during this specific interval,
not wall-time percentages, per-invocation costs or a controlled comparison to
the older hashing-heavy campaign. The evidence now prioritizes runtime
execution/gas simulation over another blanket journal-hashing optimization.
Gas accounting, authorization and replay validation must not be disabled.

Evidence directory: `task-tmp/inventory-profile.BXFk2T/` contains `profile.sh`,
`probe.log`, `up.log`, `perf-record.log`, private `perf.data`, and `callers.txt`.
The installed profiler supports DWARF unwinding and the executable retains
unwind/symbol sections, but most recorded caller stacks were empty/incomplete;
the caller report cannot identify which individual runtime work dominates.
Next measure the individual runtime executions inside a projection or improve
stack capture before changing execution orchestration. No production source,
gas model, runtime pin or release executable changed in this profiling turn.

Safe-boundary cancellation is now live-tested on release `8716f6a7`, but the
five-second shutdown gate is **still not fully passing**. Both probes first
verified the retained Counter read/retirement/exact-retry path (no new mutation),
then waited for a newly logged Credential inventory query before signalling.
SIGINT passed within5s without forced cleanup (startup61s; session90632 exit0).
SIGTERM exceeded5s (startup37s; session82499 exit1); the daemon exited during
the following bounded cleanup after a further SIGINT, without SIGKILL. Do not
attribute the difference to signal type: both handlers set the same flag, and
per-call workload/timing differs. These are separate probe results, not a
controlled signal comparison or proof of a universal shutdown bound.

Logs/scripts under `task-tmp/issuer-reuse-release.QR6Y4x/`:
`counter-check.sh shutdown-read` / `shutdown-term-read`,
`counter-shutdown{,-term}-read-check.log`, and corresponding `-up.log` /
`-test.log` files. Each client test passed; retained managed attempt durations
were0.49/0.55s, not fresh invocation latency measurements. New logs preserve the
earlier forced-kill failures. Original state and requests remain unchanged in
identity. Host process inspection after the probes found no test/build/daemon
processes. Sessions30284 (build),90632 and82499 are terminal.

Release build passed6m34s and bundle/verification pass with unchanged guest pins.
Binary SHA-256: `4e7aa7dfa0b6e9680d33c4f46c5bf68e1553a439ad289e7703bbeb7919185d5a`.
`task-tmp/inventory-shutdown-release.DYH4h7/` contains build log, bundle,
previous executable and pre-probe forensic data/config copies. Remaining issue:
source cancellation cannot preempt one in-flight projection call; production
transport uses synchronous response waits. Profile that call and its durable
work before choosing further optimization/cancellation changes. `/usr/bin/perf`
is available; no new sampling has yet been run. Do not replace joins with
detached workers, shorten receive waits as a substitute for completion, or
extend the shutdown gate. Startup latency and other production gates remain open.

Inventory reconciliation now observes the node's shared shutdown signal between
durable projection calls. The node wires its existing signal into the owned
inventory source; the client checks before recovery/authenticated dispatch and
after each completed call, refusing further pages and discarding partial/cache
reuse. A `ShutdownRequested` result is a normal node stop only when that same
node signal is set; other errors remain fatal. No worker is detached and no
in-flight journal operation is interrupted or relabelled as complete.

All11 production-owner tests pass (0.17s), including a new transport-controlled
regression that stops before dispatch or after the Agents page, never starts
replica/actor pagination after the signal, and invalidates cached inventory.
All8 selected shutdown tests also pass (2.42s), including physical lifecycle
refusal after shutdown, owner/route join ordering and busy-outbox signal handling.
Logs: `task-tmp/inventory-shutdown-regressions.log` and
`task-tmp/inventory-shutdown-node-regressions.log`; sessions47472 and57808 terminal.
Configuration: locked/offline host features `agent-transition-proof
private-agent-store http-ingress ssh-ingress`.

This is safe-boundary cancellation, **not yet a passing five-second live gate**.
A single already-running projection call may itself be too slow. The new
release/probe results above still do not close the gate.

Current release (`668a86bb`) passes recovered-space restart/HTTP/stable SSH
identity with clean SIGINT shutdown in the idle-ingress probe: readiness30s,
HTTP status `ok`, SSH key equal to the original fixture, shutdown within5s.
Logs: `task-tmp/issuer-reuse-release.QR6Y4x/fixed-restart*`; session44307 terminal.

Counter functional qualification now passes against that same release:
mutation returned7 with positive retirement and exact-retry checks (39.55s test;
managed attempt38.01s), and a subsequent restart-read returned7 with the same
retirement/retry checks (32.42s test; managed attempt30.92s). The second check did
not repeat the mutation. The opt-in CLI test helper now explicitly allows this
disposable campaign, validates its XDG fixture root, and selects the actual
`counter` name / `counter-dist/counter.vos`; older fixtures retain their paths
and names. No production code or release executable changed for this adaptation.
CLI test binary build passed41.35s; log `pending-binding-release.QlSlXs/counter-campaign-build.log`.

**Shutdown remains a reproduced release failure after invocation.** Both phases
exceeded the unchanged5s SIGINT deadline; cleanup waited a further bounded5s
then killed and reaped only its own daemon. Overall probe sessions18429 and70435
exited1 despite their individual functional tests passing. Readiness was48s
before mutation and57s before the post-kill read. The original data and retained
requests remain in place. No data reset, repeated mutation or replacement nonce
was used; the second startup recovered after forced termination. Evidence:
`counter-check{.sh,.log}`, `counter-read-check.log`, `counter-{mutation,read}-{up,test}.log`
under the original fixture. The two managed preparation roots are
`agent-client/managed-counter-mutation` and `agent-client/managed-counter-read-after-restart`.

Logs show inventory reconciliation still progressing around shutdown. Code
inspection finds synchronous `drive_clean_agent_owner()` between shutdown checks
in `VosNode::run_forever_with`, with inventory queries dispatched synchronously.
This is the next shutdown investigation target, not yet a proven complete cause
or an implemented cancellation fix. Do not extend the5s gate or erase these
failures with the earlier idle-shutdown pass. Startup latency also remains above
the10s gate. Counter results do not qualify protected/non-Public policy or the
remaining production finality, retention and proof gates.

Live recovery and Counter Install now pass on release source `668a86bb` at the
original preserved-space path. Readiness took147s; the resumed Install reservation
then completed in92s with exit0 and a verified1,654-byte acknowledgement for
Agent `745ce15ee9860b2b50ddd80460add47e7fe518480cb5793af525ae26010e32ae`.
This was the first signed Install submission for the previously reserved nonce,
not recovery of an earlier sent Install. No new nonce, store reset, migration,
binding deletion or manual repair was used. The probe joined its own daemon
without forced cleanup; session `85175` is terminal and the subsequent host
process check found no remaining test/build/daemon processes.

Evidence: `task-tmp/issuer-reuse-release.QR6Y4x/recovery-install{,-probe,-up}`
JSON/logs/stderr, plus `create-probe.sh recovery-install`. Host startup passed
the former reconciliation failure and reached lifecycle-controller setup at
112,893ms; initial inventory/route reconciliation took31,945ms. Later Install
reconciliation took33,260ms, with individual inventory queries around4–6s.
These are observed phase timings, not a controlled before/after benchmark.
The147s startup still fails the10s release gate;92s Install is still too slow.
Subsequent restart/HTTP/SSH and Counter checks are recorded above, including
the post-invocation shutdown failures. Do not infer production qualification.

The configured release build passed in6m50s, and bundle creation/verification
pass with unchanged runtime/system pins. Executable SHA-256:
`51691210f3c98f46a40feae86bd06d79ee7d6233c98fc13b54b7f0af1cf994e8`.
Evidence directory: `task-tmp/pending-binding-release.QlSlXs/` holds `build.log`,
`bundle/`, `vosx-before`, and pre-recovery forensic `data-before` / `config-before`.
The same directory's `default-regression.log` records the four-case pending
binding regression passing under default features (3.34s; build1m40s).
Sessions `93556` (release) and `88296` (default test) are terminal.

Pre-publication pending-binding recovery is now implemented and regression-tested.
The physical test stages the actual replay-derived Shared projection/binding
before the head CAS, both with and without the immutable entry file, and with
empty and non-empty committed prefixes. Before the fix it failed reopening
with `CorruptResidue` (0.65s). After the fix all four cases reopen with the
applied cursor unchanged and reservation still pending, apply exactly once,
clear the reservation, and reopen again with identical completed status (2.86s).
Seven altered/missing reservation cases are rejected in every setup: no pending
record, different Ordered index/parent, physical index/term, payload commitment,
or entry ID. An initial test-helper compile error and a zero-ID error-variant
expectation were corrected; neither is counted as a production regression.

The ledger audit now projects Ordered index/parent from the authenticated
physical pending command. Reconciliation accepts a staged binding outside the
committed chain only for that exact next Ordered successor; all existing store,
route, payload, claim index/term/head and committee comparisons remain. This
does not mark the staged command applied or rewrite data: normal replay must
reconstruct and publish it before the ledger anchor advances. No wire, guest
pin, signed capacity or persisted-record format changes. The existing physical
snapshot/compaction/suffix-reopen regression also passes (2.12s).

Evidence under shared target `task-tmp/`: `pending-binding-regression-exact.log`
(reproduced failure), `pending-binding-fixed-exact.log` (initial passing cases),
`pending-binding-prefix-fixed.log` (four-case pass), and
`pending-binding-snapshot-regression.log`. Tests use locked/offline host features
`agent-transition-proof private-agent-store http-ingress ssh-ingress`.
Sessions `71810`, `90396`, `31487`, `65063`, `17284`, and `73433` are terminal.
The subsequent fixed release and live recovery/Install result are recorded above.

The detailed diagnostic now identifies the live failure: all 85 committed
Ordered anchors validate, but the retained pending command at Raft index113
has a binding for entry `4c26180c…` which is not in the committed Ordered chain.
Log: `task-tmp/reconciliation-release.B0uTZ2/reopen-debug.log`, failure at
2026-09-15T15:07:01Z. Reported ordered index85, snapshot base0, pending=true;
materialization completed at109,826ms. The process exited1 before readiness.
This is **not** the original-successor bug fixed below: its committed anchor
comparisons all passed. No store repair/reset or Install submission occurred.

Code inspection explains a legitimate crash boundary missing from reconciliation:
`journal_store::stage_sealed_dependencies` durably writes the Shared binding
before writing the Ordered anchor and before the head CAS. In contrast,
`validate_pending_binding` currently requires the pending entry in the committed
chain whenever a binding exists. A crash after dependency staging but before
head publication can therefore leave a recoverable reservation which open
rejects. Next add a physical regression at that boundary, then validate a
pre-CAS binding against the exact authenticated pending command and current
Ordered predecessor without treating it as applied. Recompute/replay the exact
reserved command before anchoring; do not drop the binding, skip mismatches, or
advance Raft merely because staged material exists. The binding may precede
even its immutable entry file, so tests must cover that earlier boundary too.

Diagnostic build at `66805f3e` passed in7m26s; executable SHA-256
`3ff273a7993621651afd911413a0538198cb0a382a33b883462bf35129ca617b`.
It predates the original-successor fix. Build log and pre-probe forensic copies
are in the same evidence directory. Sessions `64899` (build) and `47296`
(reopen) are terminal. The diagnostic-only suffix regression also passed1.99s;
log `task-tmp/reconciliation-diagnostic-test.log`, session `32539` terminal.

A deterministic Shared replay regression now reproduces an original-successor
bug: publish an Ordered entry, publish a Local entry, then retry the exact
Ordered entry. `AlreadyCommitted` previously constructed its publication
receipt with `current.id()`, so the receipt's successor differed from the
independently durable Ordered binding's successor. The regression failed on
that exact comparison (0.39s). Recovery now uses `stored_commit.successor()`;
the regression passes (0.52s), and all seven Shared replay tests pass (2.77s).
The retry does not re-execute the Ordered work or change current heads, and
the claim remains exact. No wire/guest pin or persisted record is changed.
This prevents new inconsistent recovery anchors; it does not repair an
already-inconsistent ledger. Whether the preserved fixture has this exact
mismatch was subsequently disproved by the detailed diagnostic above.
Evidence: `task-tmp/reconciliation-release.B0uTZ2/local-successor-regression.log`,
`local-successor-fixed.log`, and `shared-replay-fixed.log`. Test sessions
`53822`, `55289`, and `65621` are terminal. The diagnostic release build
session `64899` was started at `66805f3e` before this fix; it is not the fixed
release candidate. Its previous executable is preserved as `vosx-before`.

Diagnostic release at `2624cc0a` now localizes the preserved-space failure to
**journal/ledger reconciliation**: `published_checkpoint_validation` completed
successfully at 107,811ms, followed by `Shared journal open ledger reconciliation
failed error=CrossStoreMismatch` at 2026-09-15T14:53:17Z. Materialization completed
at 106,999ms. The process exited 1 before readiness or Install; no timeout,
repair or reset was used. The exact conflicting chain/anchor/binding remains
unknown, so this is localization, not a fix or proof the new policy caused it.
Next inspect reconciliation's ordered chain, ledger anchors, pending binding
and extra pre-snapshot bindings; do not weaken checkpoint authentication.

Build passed in 6m59s with the configured release profile. Binary SHA-256:
`5f7f2f2e879e0637a540462c36934dde81c3c7639a95e11499fe7c82d2434d9a`.
Evidence directory: `task-tmp/reopen-diagnostic-release.hiE5mF/`, containing
`build.log`, `reopen-debug.log`, `vosx-before`, and forensic `data-before` /
`config-before` copies taken before this run. Copies are evidence only, not
bootable replacements for the path-bound original. Sessions `64830` (build),
`99294` (test) and `16823` (reopen) are terminal.

The existing filesystem snapshot test now actually reopens after applying an
ordered suffix and before installing the second snapshot. It asserts exact
status preservation and no remaining command to apply. Previously its final
reopen tested only the second snapshot's empty suffix. The strengthened test
passes: 1 test, 2.35s, build31.52s, locked/offline host-feature configuration
`agent-transition-proof private-agent-store http-ingress ssh-ingress`.
Log: `suffix-reopen-test.log` in the same evidence directory. This rules out
a general suffix-reopen failure in that fixture, not the live failure above.
The test-only addition was made during the diagnostic release build; no
production source beyond `2624cc0a` was changed for that executable.

Follow-up diagnostic at the original fixture path reproduced the failure at
2026-09-15T14:37:19Z. Journal-driver materialization completed at 98,258ms
(executor setup completed at 320ms), and profile/ledger audit completed at
98,957ms. The failure is therefore after successful replay, in published
checkpoint validation or journal/ledger reconciliation, not in materialization
itself. It remains unproven which check fails or whether the checkpoint policy
caused the mismatch. Evidence: `task-tmp/cross-store-audit.bDsrWd/reopen-debug.log`.
That directory also holds forensic `data-before` and `config-before` copies,
taken before this diagnostic; they must not be booted at a different path.
No store repair or replacement was attempted. Narrow driver-open diagnostics
now distinguish those two validation stages while preserving their errors and
fail-closed behavior; the subsequent diagnostic release and result are above.
The three `projection_checkpoint` tests pass with those diagnostics (14.69s;
build 1m44s), using the locked/offline host-feature library configuration
`agent-transition-proof private-agent-store http-ingress ssh-ingress`.
This is focused regression coverage, not a reproduction or fix of the live
reopen failure.

Current preserved-space reopen is blocked: the checkpoint-policy release
exited during bootstrap at 2026-09-15T14:32:15Z with
`Shared journal operation failed error=CrossStoreMismatch`, surfaced as
`Host(CorruptResidue)`, before readiness or Install submission. Cause is not yet
localized; do not attribute it to the new policy or treat the fixture as
repairable without further evidence. The prior probe had stopped during
inventory startup, so interrupted-startup recovery is part of the investigation.
The original fixture path and all stores/request reservations remain untouched
after this failure. Log: `task-tmp/issuer-reuse-release.QR6Y4x/soft-install-up.log`;
probe session `6547` is terminal. No Install request was sent. Do not reset,
relabel, migrate or delete this failing fixture.

Release build at `53c98f7f` passes in 8m02s; `release bundle` and
`release verify` pass with the unchanged runtime pin. Build/bundle logs,
previous executable and SHA-256 evidence are in
`task-tmp/soft-checkpoint-release.CU2mct/`. Executable SHA-256:
`c6b4706944fcab89b13079d90257ccfdcd24e9139d0a19c40c795f55fa8b2d71`.
Build session `24832` is terminal; this build is not a passing live qualification.

Explicit native initial-capture headroom test now passes (320.79s; build30.99s).
The first policy-enabled run failed setup after192.07s because opportunistic
checkpoints prevented history reaching the hard boundary. The fixture now
reserves each exact projection pair before dispatch, using the real occupied
gate to suppress optional checkpoints during fill; no production knob or
synthetic capacity counter is used. Original budget, refusal-before-publication,
unchanged-state and authenticated management-repair assertions are unchanged.
Logs: `task-tmp/soft-checkpoint-headroom-exact.log` (failed setup) and
`task-tmp/soft-checkpoint-headroom-reserved.log` (pass). An earlier short-name
`--exact` command selected zero tests and is not counted. Test sessions `39390`
and `42310` are terminal. No task-owned test/build/daemon process remains live.

Opportunistic system-projection checkpoint policy is implemented with a
32-retained-Raft-entry soft threshold, derived from authenticated capacity
relative to the installed snapshot. It runs before fresh projection admission,
not during pending projection recovery. A physical command reservation skips
the attempt; the proposal mutex atomically refuses an occupied projection,
management-pending or management-retirement gate. Certificate, snapshot and
reattachment failures remain fail-closed. The existing hard-capacity checkpoint
path is unchanged; no wire, guest pin, signed capacity or issuer retention
limit changed. The threshold is a host scheduling candidate, not a proven
10-second startup bound.

Three focused tests pass (14.25s; build 1m23s): threshold/busy-gate boundaries,
physical snapshot preserving state and skipping a reserved pair, and existing
checkpoint failure/reattachment recovery. Three further physical lifecycle
tests pass (75.65s): Install handoff/retry/restart, accepted-finalization startup
recovery, and management-finalization clock-advance exact replay. Logs:
`task-tmp/opportunistic-checkpoint-tests.log` and
`task-tmp/opportunistic-checkpoint-lifecycle.log`. The release CLI was subsequently
rebuilt with this policy as recorded above; startup/Install latency remain unqualified.

The combined host-feature library suite at `f79f0e3d` is now complete:
1,862 passed, zero failed, three ignored, 2968.51s (49m28s), build 3m18s.
Enabled features: `agent-transition-proof private-agent-store http-ingress
ssh-ingress`, with defaults, locked/offline and serial socket-enabled tests.
Log: `task-tmp/current-host-feature-library-suite.log`; session `12062` is
terminal. The 514-query inventory rotation test and Shared-host attachment
checkpoint test passed. Ignored: native-operation initial-capture headroom,
fixed-history decode probe, and large-ACK profiling probe. The native headroom
case subsequently passed separately as recorded above; the others are
diagnostics. This suite predates both checkpoint changes above and does not
certify their full matrix, full cryptographic proof integration or release
readiness. No test/build processes from this checkpoint remain running.

Projection checkpoint admission now uses the existing authenticated ledger
capacity accessor instead of full host `show` status before and after snapshot
installation. Only remaining capacity was needed; deriving the actor-directory
status was unnecessary. The physical checkpoint failure/recovery regression
passes (10.22s; locked offline PVM-enabled build 32.83s), covering committee
mismatch, signing refusal, bad certificate installation and attachment/gate
recovery. Log: shared target `task-tmp/checkpoint-capacity-accessor.log`.
This is not an earlier-checkpoint policy or a measured startup improvement.
The release executable and ongoing full feature suite predate this small host
change; their evidence must remain tied to their recorded source revisions.

Counter packaging passes with the current CLI and isolated operator identity:
`actor build examples/actors/counter --name counter` completed its pinned guest
build in 27.18s. Package/PVM and build log are under
`task-tmp/issuer-reuse-release.QR6Y4x/counter-dist/` and `counter-build.log`;
ProgramId `0d2d77723e24432b0d2af5d1d94f5937fac528d2bbb3ce1391bd0905329fd402`.
The initial Install probe incorrectly supplied present-empty constructor data;
Counter requires absent data, so local validation rejected it before any signed
Install request was published or sent. Its reserved client nonce remains.
After correcting that input and selecting `--resume` to preserve the nonce,
the next probe exceeded its 180s daemon-readiness allowance before invoking
Install. Startup logs show serial inventory queries taking about 11s each.
No Install request file exists and no Install response-time result is claimed.
The isolated space, package and pending reservation are preserved. Evidence:
`install{,-probe,-up}` and `install-resume{,-probe,-up}` logs/JSON/stderr under
the same probe directory, plus `create-probe.sh install-resume`. Sessions
`5932` and `68538` are terminal and their daemons were joined without forced
cleanup. Do not allocate a replacement nonce or interpret this as an HTTP
Install failure: the corrected request was never submitted. The full feature
suite remains running in session `12062`; concurrent load limits timing claims.

Exact recovery of the timed-out Create now passes on the same release and
original fixture path. `create-local-agent --resume` returned a verified
1,520-byte acknowledgement for Agent
`745ce15ee9860b2b50ddd80460add47e7fe518480cb5793af525ae26010e32ae`
in 12s after readiness. The sole retained request compares byte-identically
to the saved pre-resume copy; the acknowledgement is durably present in that
same operation directory. No new Create request was generated. Startup on this
retained-history fixture took 129s, with the feature suite still concurrent;
this does not repair the initial 127s/HTTP-504 failure below. Evidence:
`task-tmp/issuer-reuse-release.QR6Y4x/create-resume{,-probe,-up}` JSON/logs,
`create-request-before-resume`, and `create-probe.sh resume`. Session `20128`
exited successfully and joined its daemon without forced cleanup. Install
latency is still unqualified. Feature-suite session `12062` remains live.

Initial Local Create was rechecked on the issuer-reuse release (`f79f0e3d`)
and is still not usable: one `create-local-agent` call returned HTTP 504 after
127 seconds, explicitly retaining the request with unknown outcome. The daemon
logged lifecycle completion at 66.976s and publication completion at 114.953s;
post-create inventory/reconciliation consumed 47.778s (inventory 46.551s).
These timings locate remaining work but are not controlled benchmarks: the
feature suite was running concurrently. The daemon reached readiness in 58s
on this third open of the disposable fixture. Evidence in shared target
`task-tmp/issuer-reuse-release.QR6Y4x/`: `create-probe.sh`, `create-probe.log`,
`create.stderr`, `create.json`, `create-up.log`. Session `56740` exited 1 and
its daemon was joined by cleanup without forced kill. All retained client and
space state is preserved in the original isolated directories. No retry or
Install was attempted. Publication in the daemon log is not proof the client
received its acknowledgement; use only exact retained recovery next, not a
fresh Create request. This result supersedes the earlier unmeasured-Create
qualification below; Install latency remains unqualified.

Release qualification at `f79f0e3d`: locked offline CLI release build passes
in 7m44s and now includes issuer validation reuse. Fresh `issuer-reuse-smoke`
creation generated HTTP and SSH ingress configuration without manual enabling;
only test ports changed to 18099/2241. First startup/restart passed in 30/44s,
with HTTP status `ok`, identical SSH host keys, and successful SIGINT shutdown
within the smoke's five-second allowance after both runs. The diagnostic smoke
permits 180s readiness; the unchanged 10s production startup gate still fails.
The concurrent feature suite makes these timings unsuitable for a controlled
performance comparison. Ordinary Create/Install latency is not requalified.
`release bundle` and `release verify` both pass with the unchanged `79c7d1f0…`
runtime pin. Evidence, rerunnable scripts, generated original config, preserved
previous executable, bundle, logs and executable SHA-256 are in shared target
`task-tmp/issuer-reuse-release.QR6Y4x/`. New executable SHA-256:
`317c92505ea7e1cf640b3e0da5a66851c0b595fc5b57d5f6efe94925dab7ae44`.
SpaceId: `1c041f9e9e00eaa4dbc719b45b3942851c7032cc508c6001ba7eb7574039a872`.
Build session `88238` and smoke session `14101` are terminal; no smoke daemon
is left running. The combined host-feature library suite remains active in
session `12062` (`task-tmp/current-host-feature-library-suite.log`); do not
count it as passed or launch a duplicate.

Full default-feature `vos` library suite at `0bf97332` passes: 1,429 passed,
zero failed, one ignored, 212.30s. Command: `cargo test --offline --locked
-p vos --lib -- --test-threads=1`, with approved local sockets and disk-backed
TMPDIR. The sole ignored test is
`agent::shared_raft::application_ledger_v2::fixed_history_physical_decode_probe`,
an opt-in timing probe requiring `VOS_AGENT_RAFT_BENCH_COPIED_DB`, not a release
gate. Evidence: shared target `task-tmp/current-default-library-suite.log`.
This includes the issuer validation optimization and default-feature test
guard correction. It does not qualify feature-gated PVM/Private/Attested
coverage, CLI startup/SIGTERM deadlines, live latency or the full release matrix.

Issuer validation reuse: candidate commits now reuse signature validation only
for byte-identical records at the same index under the exact same authority
in the live, already-validated issuer image. There is no persisted cache.
Changed/new records and all disk reopen paths still receive full verification;
image-wide envelope, ordering, invocation/sequence uniqueness, canonical bytes,
time and private-resolution relationships remain checked. All 22 issuer tests
pass with `--features agent-transition-proof` (28.94s; build 1m54s), including
new forged-signature, duplicate-record, high-water, authority, reopen and
precommit side-effect regressions. Log: `task-tmp/issuer-validation-reuse-pvm.log`.
The original two-test capacity baseline completed successfully in 1559.66s
(session `99095` is terminal). The candidate's same two selected capacity tests
pass in 52.04s (`task-tmp/operation-capacity-validation-reuse.log`, session
`99058` terminal). Feature sets and concurrent build load differ, so these
are indicative timings, not a controlled speedup or production latency result.
The 256-record ceiling and authenticated reclamation requirement remain.
No guest or ABI change; the previously qualified release CLI does not yet
include this host optimization.

The default-feature library test-build failure is now fixed: the two
`driver.rs` descriptor tests use a fixture that commits a PVM execution result,
so they now carry the same `pvm` guard as the fixture and execution method.
Default-feature library tests compile (1m06s), and both validation-reuse
regressions pass (0.35s). With `agent-transition-proof`, both descriptor tests
remain enabled and pass, together with the selected package descriptor test
(3/3, 0.01s; build 1m14s including Cargo lock wait). Logs:
`task-tmp/default-feature-test-gate.log` and `task-tmp/pvm-descriptor-test-gate.log`.
The original failure is preserved in `task-tmp/issuer-validation-reuse.log`.
This qualifies compilation and the selected tests, not the full library suite.

Current full CLI default suite at `1c787774`: 260 passed, 19 ignored, one
failure. Unit tests passed 255/255 selected (92.16s); actor-build integration
passed 4/4 (32.96s); task-build integration passed 1/1 (32.98s). Shutdown smoke
failed before SIGTERM at its unchanged 10-second endpoint-readiness deadline
(11.71s test duration). The exact test daemon was reaped; host process
inspection showed no remaining `vosx` process. This is a debug CLI suite,
not a release-mode latency benchmark, and it does not qualify the 19 ignored
tests. Evidence: shared target `task-tmp/review-head-cli-suite.log`.
The task-build test refreshed its stale `clerk-apply` fixture lockfile with
the SDK/protocol dependencies now required by `vos`; locked offline metadata
resolution passes with the corrected lock. No dependency version changed.
The separate coordinator capacity baseline remains live (session `99095`),
with over 21 minutes of CPU time observed; it is not counted as passed.

Review-head qualification at source `4f0b6ffb`: all 18 CLI
`production_release` tests pass (2.17s, locked offline build 24.38s).
The integration test binaries selected zero tests by this filter; this does
not rerun shutdown or the full CLI suite. Evidence: shared target
`task-tmp/review-head-release-pins.log`. The matching locked offline release
rebuild passed in 8m12s and includes the host pagination fix. Its process
(exec session `81791`) is terminal. Build log:
`task-tmp/review-head-release-build.log`. The resulting executable successfully
ran `release bundle` and `release verify`, retaining runtime pin `79c7d1f0…`.
Bundle, command logs and executable SHA-256 are preserved in
`task-tmp/review-head-bundle.LV6R83/`; executable SHA-256 is
`af3e2372489cd8461ce36c95e997a3f16cf21322c6158b283dd88a9328f1453c`.
This closes the stale release-executable gap, not live pagination qualification,
fresh-space smoke on this host revision, or ordinary Create/Install latency.
The review guide now identifies the current `79c7d1f0…` pin and separates
historical results; the old C1 boundary remains unsuitable for standalone
merge. No merge, push, runtime change or release-gate waiver was performed.

Issuer capacity safety regression: the full 256-record issuer test now
explicitly proves overflow preserves the exact image and commit count and
performs no receipt, acknowledgement, application or retirement signing. The
strengthened test passes (30.34s; locked offline build 34.35s), with evidence
in shared target `task-tmp/issuer-capacity-atomicity.log`. This does not reclaim
capacity or alter production behavior. A separate two-test baseline sequence
is still running its full-protocol coordinator capacity setup as of this
checkpoint (`task-tmp/operation-capacity-baseline.log`); do not count it as
passed or launch a replacement without checking its existing process handle.

System-actor and clean-break qualification at `c9c5ecce`: explicit locked
offline nested-workspace suites pass, with 58 Authority tests (139.27s) and
10 Catalog tests (27.36s), zero ignored. The Authority suite includes its
4,096-operation compaction regression; that does not close the distinct host
issuer's 256-record ceiling. `scripts/check-agent-clean-break.sh` also passes
with offline Cargo and isolated XDG directories: retired paths, CLI commands,
flags, unknown-command fallback and selected documentation references are
checked. Logs: shared target `task-tmp/system-actor-qualification.Rnl5Ia/`
`authority.log`, `catalog.log`, `clean-break.log`. The script rebuilt the debug
CLI, not the release executable. These are source actor tests and CLI-surface
checks, not full release or physical Shared-genesis qualification.

Portable documentation / wasm qualification at `ec779164`: the locked offline
SDK no-default-features documentation build passes with
`-D rustdoc::broken_intra_doc_links` (0.77s), and the standalone proof verifier
builds for `wasm32-unknown-unknown` (1m22s). These cover `agent-sdk-doc-check`
and `check-pvm-proof-wasm`; they do not verify external documentation links or
execute a cryptographic proof in a browser. Logs: shared target
`task-tmp/sdk-doc-current.log` and `task-tmp/verifier-wasm-current.log`.

Inventory pagination fix: the host now accepts non-final pages shortened by
the Authority's encoded-reply size bound. Previously it incorrectly required
every continuation page to fill the requested entry count and budgeted only
`ceil(entries / page_size)` calls, despite SDK-valid shorter pages. Agent,
replica and actor loops now permit at most the total-entry bound plus one page;
existing shape validation requires every non-final page to be nonempty and
advance its cursor. Exact query/head, total-entry, roster-count and descriptor
checks remain. All ten production-owner tests pass (0.16s), including a new
one-entry-per-page test spanning three agents with three replicas and actors
each, and the existing revocation/head/limit checks. Evidence: shared target
`task-tmp/inventory-short-pages.log`. This fixes host pagination correctness,
not the number of initial inventory calls. No guest ABI/artifact changed; the
previously built release CLI does not yet contain this host fix.

Ordinary-genesis promotion regression: all eight `agent::genesis::tests` pass
with a new test that rejects every independent-finality error even for a
self-consistent provision, checks repeated attempts consult the verifier,
rejects substituted contents before the trust call, and confirms a previous
successful promotion cannot bypass a later unavailable verifier. The test's
controlled verifier is deliberately synthetic; it proves call sequencing and
fail-closed promotion, not authenticated live-system publication or physical
Shared reopen. Production behavior remains unchanged. Final run log: shared
target `task-tmp/ordinary-genesis-finality-gate-final.log`. The production
issuance/publication/replay bridge identified below is still unimplemented.

No-std build qualification at `80362c21`: five explicit locked offline commands
pass: SDK check with no default features; `vos-raft` builds with no default
features for `thumbv7em-none-eabihf` and `riscv32imc-unknown-none-elf`;
`vos-pvm-proof` build with no default features; and `vos-pvm-proof-verifier`
build. These cover the commands in `just check-no-std` and
`just check-pvm-proof-no-std`, plus the SDK check. The two required embedded
targets were initially absent and were installed for nightly-2025-05-09 with
approved toolchain access; the skip-capable test wrapper was not counted as
qualification. Rerunnable evidence: shared target
`task-tmp/no-std-qualification.e0pLKx/check.sh` and `check.log` (one successful
command sequence, source revision recorded). This is build evidence, not
cryptographic proving, wasm qualification, or closure of the full release matrix.

Newest-pin release smoke at source `83737aee`: the locked offline CLI release
build passed in 6m49s. Fresh space `invoke-pin-smoke` was created with HTTP and
SSH enabled in its generated config; only test ports were changed to
127.0.0.1:18099/2241. First startup and restart passed in 27/37 seconds, with
HTTP status `ok`, identical SSH host key, and clean shutdown after both runs.
Evidence: shared target `task-tmp/invoke-pin-smoke.PqzkGQ/` contains `build.log`,
`new.json`, preserved `generated-local.toml`, `cli.sh`, `smoke.sh`, `smoke.log`,
both daemon logs/status/key files, and the prior CLI as `vosx-before`. The
current release CLI now contains the `79c7d1f0…` runtime pin and host preflight
reuse. This qualifies basic new-space/restart usability, not initial ordinary
Create/Install response times or the failing 10-second startup gate. Existing
older spaces were not migrated or relabelled; all original release gates remain.

The reproduced Invoke-authorization candidate (`79c7d1f0…`, frozen guest source
`aad65049`) is now pinned consistently in the production manifest, protocol
ProgramId, CLI build checksum and bundled PVM. Candidate Attested public-output
binding and restart-lineage checks passed before pinning (2.76s). After pinning,
all 18 CLI release-pin tests passed (1.28s), and all six feature-enabled physical
runtime integration tests passed with zero ignored. Logs are in shared target
`task-tmp/invoke-authorization-candidate.PGfgHq/post-pin-cli.log` and
`post-pin-physical.log`. The ABI and system templates are unchanged. A new
release CLI build and fresh-space smoke are still required: the existing
release executable and disposable spaces use the previous `db577aff…` pin.
Do not relabel those spaces to the new ProgramId. Full proof qualification,
production latency and the other original release gates remain open.

Invoke candidate reproduction at frozen source `aad6504974307698bd0484f65f29c5191832fe6a`:
two separate source/target/tmp guest builds passed in 29.88/30.46s, with
byte-identical ELF and PVM outputs. Frozen builder remains the previously
qualified `r17-release-candidate.fNbf43/builder/vosx`. Candidate ProgramId is
`79c7d1f0ed2feff40eaca198951656c705d687ab83bbd581a8895a13db0022a7`;
ELF BLAKE2b-256 `4d7f50c53208f69fea06a670895dd211dfcf08fda4c2f5d02b244a5bc7e5e90c`;
PVM BLAKE2b-256 `5e2a82c86cccb70b7320487b8e627d879b78924de2a6774670b4dd03ee96ff8b`.
Six candidate-selected tests passed (5.09s), covering physical terminal-failure
lifecycle, two typed-error retirements, unseen expiry, retired Invoke, and
fail-closed ACK errors. The baseline lifecycle also passed (2.46s). Both guest
versions match the entire source transition in the fixed lifecycle cases.
The first 6,049-byte Invoke consumed 40,164,903 gas on the current pin versus
36,041,920 on the candidate (10.3% less); corresponding ACK gas is unchanged.
This is a fixed-fixture gas result, not startup/Create/Install latency proof.
Evidence: shared target `task-tmp/invoke-authorization-candidate.PGfgHq/`
(`build.sh`, two build/identity logs, `physical-tests.log`,
`baseline-lifecycle.log`). Candidate remains unpinned pending remaining
artifact/integration qualification; the previously qualified CLI is unchanged.

Invoke authorization candidate: `apply_clean_invoke` no longer calls full
authorization verification immediately before `recover_clean_invocation_error`,
whose first operation is the identical full verification on unchanged arguments
and runtime state. The latter still checks blob preimages, scope and signature
before any mutation. Seven source-runtime regressions pass (0.54s): explicit
signature/scope/blob substitution preserves state, typed-error retirement,
unseen-expiry retirement, three expiry-fence cases, and unsupported-method
retirement. Locked offline build passed in 32.35s. Logs: shared target
`task-tmp/invoke-authorization-substitution.log` and
`task-tmp/invoke-authorization-regressions.log`. A preliminary legacy-execution
test also passed but does not qualify this clean Invoke change. The committed
guest pin and release CLI remain unchanged; independently reproduce and
physically compare this candidate before replacing any artifact. Source and
bundle qualification are not yet closed for this new optimization.

Preflight reuse regression follow-up: a small admitted scripted PVM produces
the same replay transition and exact RuntimeOutcome with and without reuse.
The same test proves a prepared computation cannot grant a missing replay
authentication capability and cannot bypass the runtime state-size limit.
The existing Attested provider test now injects an exact-match prepared tuple;
the proof provider remains authoritative. These three focused tests (including
the byte/gas/runtime mismatch and one-shot test) pass, with a locked offline
test build in 34.24s. Logs: shared target `task-tmp/terminal-preflight-equivalence.log`
and `task-tmp/terminal-preflight-equivalence-final.log`. Formatting followed the
build; no additional production behavior changed. This is physical scripted
runtime equivalence, not full bundled-system-workload qualification.

Release qualification of preflight reuse at `c1ab75a5`: locked offline release
build passed in 6m29s. The existing disposable space reopened, passed HTTP
status and the exact original SSH key check, and shut down cleanly. Each of
the four inventory queries emitted exactly one preflight-consumption event
and nine physical executions (previous probe: ten). Summed physical load/run
times per query were 3.029, 3.068, 3.036 and 3.000 seconds; inventory loading
took 23.834 seconds. Total readiness was 63 seconds, with more retained history
than the previous 55-second probe: do not report an end-to-end speedup or
production-latency closure. This confirms the production reuse path and smoke
behavior, not a controlled full-output equivalence benchmark. Evidence in
shared target `task-tmp/preflight-release.1ft0DF/`: `build.log`, `probe.sh`,
`up.log`, `status.json`, `ssh-key.txt`; the prior CLI is preserved as
`vosx-before`. The current shared-target release CLI now contains the reuse
change. Further substitution/invalidation coverage and final regression remain.

Terminal preflight reuse candidate: the host executor now retains at most one
completed Direct terminal-admission transition, matching full runtime program
bytes, canonical work bytes and gas before one-shot consumption by authenticated
replay. Mismatches consume the candidate and execute normally; other replay
operation kinds clear it. Restart starts empty. Attested execution still uses
the proof provider, and all existing transition/resource/publication checks
remain after reuse. Guest artifacts and checkpoint formats are unchanged.
The locked offline test build completed in 2m11s. Four focused tests passed
in 12.36s: exact-byte/gas/runtime substitution and single-use behavior, physical
pending projection Invoke/ACK recovery, checkpoint-failure gate recovery, and
existing Attested proof-binding consumption. Evidence in shared target
`task-tmp/terminal-preflight-build-test.log` and
`task-tmp/terminal-preflight-recovery-tests.log`. This is provisional: a fresh
release binary and physical reuse-count/output/latency comparison are still
required; the previously qualified CLI does not contain this host change.

Feature-enabled physical qualification at source `4b3a8c54`: all six
`agent_runtime_pvm` integration tests pass (6.19s, zero ignored), explicitly
including compiled-guest Attested Invoke/Resume and install-lineage restart.
The locked offline build used features
`pvm,private-agent-store,http-ingress,agent-transition-proof` and completed in
1m01s. `VOS_AGENT_RUNTIME_PVM` pointed to the pinned `vosx/blobs/agent_runtime.pvm`
(`db577aff…`); execution used a 12 GiB virtual-memory limit, disabled core dumps,
disk-backed TMPDIR, and a 180-second deadline. The isolated Attested test also
passed in 2.63s. Logs are in the shared target's `task-tmp/` directory:
`attested-db577-bounded-run.log` and `attested-db577-feature-physical.log`.
This verifies exact observed public-output binding and substitution rejection,
not generation/verification of a full cryptographic proof. That release gate
remains open; no production latency or full-suite claim follows from this run.

Current HEAD pins the independently reproduced authorization-reuse follow-up
(`db577aff…`), with 18 release-pin and five physical lifecycle/lineage checks
passing. Newest-pin fresh startup/restart now pass in 28/39 seconds with HTTP,
unchanged SSH key and clean shutdown; production latency remains failing.

Latest source qualification: the independently reproduced acknowledgement
optimization is now pinned, with 18 release-pin tests and five physical
lifecycle/lineage tests passing. Fresh-space startup/restart with HTTP/SSH now
pass; final release qualification and production latency remain open. The frozen
checkpoint below remains unchanged.

Implementation checkpoint: `f76dabe1` on `wip/ch08-runtime-directory`.
At that checkpoint, `saga/agents` is `31b0cdbb`: 258 commits ahead, zero behind,
221 changed files, 71,025 insertions and 58,780 deletions. These counts exclude
this documentation handoff. Both worktrees were clean when inspected.

The checkpoint is available for review and isolated, disposable Local-space
testing. It is **not master-ready or production-ready**. No merge, push,
history rewrite, or release-gate waiver is part of this handoff. Existing data
must not be relabelled across the intentional r16/r17 clean break.

## Three review areas, not three completed batches

Ordinary Shared finality wiring audit at `9d6d378d`: the CLI constructs
`UnavailableAgentFinality`, and `SharedAgentHost::verify_and_prepare` invokes
the independent verifier before accepting an AuthorityFinalized provision.
The repository has canonical decision/proof types and Standard-runtime
`FinalizeSystemAuthority` transitions/replay support; those are not absent.
However, no production implementation of the ordinary `AgentGenesisProvider`
or accepting `AgentGenesisFinalityVerifier` was found in `vos`, `vosx` or actors.
The configured `CleanSystemAgentGenesisArchive` implements the separate root
system-genesis provider, not ordinary-Agent issuance. The deployed clean
`actors/system-authority` application-finalization path does not by itself
establish an ordinary host-genesis decision proof.

Closing this gate therefore needs a clean production bridge spanning ordinary
provision issuance/archive, durable live-system decision publication, and
independent authenticated replay verification on initial admission and reopen.
Reuse the existing canonical invariants where appropriate, but do not revive
Standard-private-state decoding as the clean runtime-independent trust boundary,
substitute root bootstrap QC, or accept a provider's self-consistent response.
This audit changes no acceptance behavior and does not qualify Shared creation.

Standalone C1 audit (2026-09-15): do not treat the three-commit historical
boundary as a merge-ready recovery batch. Its `journal.rs` still encodes AJC3
checkpoints with the v3 identity domain. The later `fd7df8ec` recovery fix,
contained in the C2 range, introduces authenticated host-owned management
evidence and AJC4 checkpoints, deliberately rejecting AJC3. It also replaces
the Shared projection comparator's Standard-state decoding with that evidence.
Thus even a green historical C1 test run would not establish completion of the
required runtime-independent recovery / clean-break gate. `git diff --check`
passes for the historical C1 range; no historical build was run in this audit.
Review C1 as the portable-recovery foundation, then review its later recovery
follow-ups in C2 before deciding on integration. A separately mergeable complete
C1 batch requires dependency-aware extraction and fresh qualification; these
existing refs do not provide it. Preserve the integrated branch and its evidence.

Keep the agreed C1/C2/C3 grouping. Internal checkpoint commits are not additional
review endpoints. Two local review references now expose existing ancestry
boundaries, without rewriting or cherry-picking history. They are review
checkpoints, not declarations of completed batches or independently qualified
release branches. C3 remains pending.

| Review reference | Compare range | Size at frozen tip |
| --- | --- | --- |
| `review/agent-saga-ch08-c1-recovery` | `31b0cdbb..2eb94e4b` | 3 commits; 13 files; +3,278/-199 |
| `review/agent-saga-ch08-c2-native-integration` | `2eb94e4b..bb6c35b9` | 270 commits; 217 files; +68,596/-58,623 |
| C3 — final release | Not yet created | Depends on unfinished implementation and release gates |

The C1 tip is an ancestor of the C2 tip (integrated through merge `e72566ee`).
The two ranges cover the 273 commits ahead of `saga/agents` at `bb6c35b9`
without duplicating C1 commits. C2 includes later C1 recovery follow-ups and
provisional artifact/release work; it is not a pure native-lifecycle-only diff.
It remains a large review, not a small merge-ready patch. The old C1 boundary
was not rebuilt in this audit, so current integrated test results must not be
attributed to that historical tip. These refs are local and were not pushed;
`saga/agents` is unchanged.

Start review with:

```sh
git diff --stat saga/agents..review/agent-saga-ch08-c1-recovery
git diff saga/agents..review/agent-saga-ch08-c1-recovery -- vos/src/agent
git diff --stat review/agent-saga-ch08-c1-recovery..review/agent-saga-ch08-c2-native-integration
```

Use the per-area gates below to separate review comments from production
acceptance. Do not merge or declare C3 complete solely because the review refs
exist. Consolidating commits further, if desired, requires dependency-aware
preparation on separate branches, preserving this integrated evidence history.

| Area | Review focus | Still required |
| --- | --- | --- |
| C1 — recovery | Host-owned management evidence, physical checkpoint/GC/reopen, opaque-runtime Local lifecycle and portable recovery. | Remaining cross-runtime and positive-ack retirement coverage; preserve the distinction between scripted host-ABI tests and actual guest execution. |
| C2 — native lifecycle | Durable authorization/issuance/application/acknowledgement, native Local Create/Install, bundled system actors, first-up ingress, exact retry and restart. | Acceptable latency; authenticated reclamation beyond the 256 issued-record ceiling; ordinary Shared-agent finality; broader expiry/abort, mixed-pending and profile recovery. |
| C3 — release | Source/bundle identity, independent artifact reproduction, feature/no_std checks, docs/examples, physical and inventory qualification. | Final-source full regression and release matrix, required profile gates and fresh-space smoke after implementation closure; final scoped review ranges. |

The detailed requirements remain in [the current closeout plan](agent-saga-review.md#current-closeout-plan).
This handoff does not narrow them. Review C1/C2 implementation now; C3 cannot
certify release readiness while those implementation gates remain open.

## What has usable evidence

- Matching r17 runtime/system-template bundles were independently reproduced.
  Fresh bootstrap/restart and HTTP/SSH have passed.
- Local Create/Install exact recovery, Counter mutation, exact retries and
  restart reads have passed. Initial Create/Install HTTP 504s remain failures
  of first-response usability; successful recovery does not erase them.
- At `4e8aa893`, the broad optimized library run reported 1,813 passed,
  20 failed and three ignored. All 20 socket-dependent failures passed
  socket-enabled reruns. The ignored native-capacity test passed separately;
  the other two ignored tests were diagnostic probes. This is evidence across
  several commands, not a single green full-suite run.
- After the nested decoder changes at `d2aa1efe`, 74 focused tests passed in
  both debug and release. The full library suite was not rerun on that source.
- At `f76dabe1`, the CLI check and production-profile build passed. The release
  restart passed HTTP status, byte-identical SSH host key and clean shutdown.
  This reused a retained disposable fixture; it was not a new-space test.

## Performance: measured facts and remaining uncertainty

Newest-pin inventory phase probe (2026-09-15): the existing disposable fixture
reopened with the same release binary and additional debug filters, reached
HTTP readiness in 55 seconds, returned status `ok`, and shut down cleanly.
Evidence: shared target `task-tmp/authorization-pin-smoke.thZJrt/`
`inventory-probe.sh` and `inventory-probe.log`. Retained history advanced; this
is not a controlled comparison with the previous 28/39-second runs.

Inventory loading took 27.614 seconds across four sequential authenticated
queries (Credential, Agents, AgentReplicas, Actors): 6.696, 6.763, 6.990 and
7.163 seconds. Each query caused ten physical runtime executions; their summed
load/run times were 4.556, 4.530, 4.541 and 4.568 seconds respectively (about
66% of total inventory loading). Pending recovery rounded to zero milliseconds
in the earlier first-start log; it did not explain that log's 20.081-second load.

For the Credential query, the Invoke phase alone took 4.082 seconds after its
reopen marker; acknowledgement added 1.501 seconds. Two large physical runs
during Invoke each consumed exactly 919,907,960 gas on 783,846-byte inputs,
taking 1.616/1.624 seconds. Identical lengths and gas are not proof of identical
bytes or redundant authorization: trace their proposal/commit callers before
attempting reuse. The remaining eight executions include smaller runtime
inspection work and the large acknowledgement. The next optimization target
is the repeated Invoke execution path, not removing authenticated inventory
queries, skipping ACK, or relaxing readiness. No implementation change or
end-to-end speedup is claimed by this diagnostic run.

Source follow-up at `af132614` identifies the two execution sites:
`SharedRouteHandler::submit_clean_ordered_operation_with_admission` prepares
the reserved terminal-only query before Raft proposal. In
`SharedAgentJournalDriver::prepare_clean_ordered_operation_with_policy`,
`clean_invocation_is_terminal` executes the complete guest against current
materialized state to reject Yielded before consuming durable capacity.
`clean_invocation_terminal_outcome` returns only the outcome, discarding the
computed transition. After proposal, committed replay reaches
`StandardLocalReplayExecutor::execute_clean_invocation_transition` and executes
the guest again. This is terminal-admission preflight followed by replay, not
two inventory client dispatches or a five-second timer.

Do not remove the terminal check. A possible bounded optimization is a
single-use prepared transition consumed only after normal replay authentication
and exact equality of runtime program, canonical work (including every state
lane, authorization, availability bytes and observed slot), gas and execution
context. Mismatch, intervening state changes, restart, follower replay and
Attested contexts must retain normal execution/proof behavior. Returned outcome,
state/resource and publication checks must remain unchanged. This optimization
is not implemented or qualified; it needs substitution, one-shot consumption,
yield refusal, reopen and physical equivalence tests before performance claims.

Repeated authenticated history validation can rehash embedded artifact blobs.
A resolved library-test stack reached that work through capacity admission:
`reserve_projection_pair` → `audit_recovery_capacity` → physical-row validation
→ journal/runtime-work decoding → availability validation → BLAKE2.
This is a confirmed expensive path, not proof that it explains all daemon time.

Removing redundant nested validation preserves public constructed-value
validation, physical integrity checks and canonical encoding checks. On the
same copied 46-row, 33,750,544-byte history, the ABBA comparison measured median
decode time of **366.874 ms before versus 141.168 ms after** (about 62% lower).
There is no cross-observation validation cache and no bypass of authentication.

The latest `f76dabe1` release restart took **159 seconds**:

| Measured stage | Duration |
| --- | ---: |
| System-owner open/recovery | 95.515 s |
| Inventory reconciliation | 59.784 s |
| Of that reconciliation: inventory loading | 56.712 s |

The inventory figure includes authenticated queries, not just reading a local
table. Earlier release restarts took 99, 112 and 125 seconds, but retained
history changes between runs: these are not a controlled before/after series.
The decoder benchmark has **not** established acceptable startup or operation
latency. The internal split of system-owner recovery remains unmeasured.

Post-checkpoint diagnostic preparation adds debug-only cumulative owner-stage
timings for record/issuer validation, genesis preparation/archive reproduction,
Shared host open/provision, committed-entry draining, pending-projection recovery,
network attachment, and Authority/Catalog checks. Only static phase names and
elapsed milliseconds are logged; no payloads or identity material are added.
`cargo check --locked -p vosx` passed in 5.35 seconds with warnings. These new
markers were subsequently measured at `824b2c9c`, as below. Successive cumulative
timestamps must be subtracted to obtain each stage's duration.

### Owner-stage measurement at `824b2c9c`

The locked production-profile CLI build passed in 6m45s. A release restart of
the original disposable r17 fixture passed HTTP status, unchanged SSH identity
and clean shutdown, but readiness took **183 seconds** (09:57:13–10:00:16 UTC).
Within this run:

| Stage | Duration |
| --- | ---: |
| Owner record/issuer through genesis/archive preparation | 0.174 s |
| Shared host open, including committee binding before the marker | 119.009 s |
| System bootstrap provisioning | 0.784 s |
| Explicit post-open committed-entry drain and pending-projection check | about 0.001 s |
| Network attachment | 2.235 s |
| Authority/Catalog checks after attachment | 0.202 s |
| Inventory reconciliation | 56.682 s |

The dominant owner interval is `SharedAgentHost::open_with_root`, not genesis
preparation or the explicit post-open drain. Its internal replay/verification
split still needs measurement; this does not show that replay itself is cheap,
because reopening the host includes recovery. Retained history differs from
earlier runs, so 183 seconds is not an optimization comparison.

A preceding raw-copy probe failed with `Host(CorruptResidue)` before host open
completed; networking also reported sandbox `Operation not permitted`. Source
inspection found that the outer lease commits to the absolute host path and
the authority namespace is derived from that path. Relocating a directory copy
is not a supported reopen fixture. Neither copy nor original was repaired or
cleared. The successful probe instead used socket permission at the original
fixture path and therefore could advance that fixture's authenticated history.
The raw copy's Raft DB initially matched the original at SHA256
`ddef123679ad07d43c374f0340f14f36b4462a11642f2bd57bc7f750063a4a6a`;
matching bytes alone does not preserve the outer lease's path binding.

Next performance work should measure that owner stage internally on fixed
history, then address the measured repeated work while preserving recovery
proofs. Do not clear history, increase timeouts, skip checks, or infer that
retirement alone permits deleting issuer/coordinator records.

The next diagnostic source adds cumulative debug timings in
`SharedAgentHost::open_generation` for journal-store opening, Raft ledger,
artifact store, journal driver and exposure/restore. Nested driver timings
separate artifact audit, committee history, executor setup, materialization,
profile/ledger audit, reconciliation and final reverified-open bookkeeping.
Enable `vos::agent::shared_host=debug` and
`vos::agent::shared_journal_driver=debug` in addition to the prior modules.
These markers have only a CLI check pass (5.28 seconds, with warnings), not a
release timing result. Its log is `owner-startup-phases.5se4bH/shared-open-check.log`.
Source inspection shows `audit_recovery` is invoked by ledger opening,
committee-history loading and journal auditing. Their duration and safe scope
for reuse are not yet established; no audit was removed or cached.

### Replay attribution at `f2b17cb2`

The locked release CLI build passed in 6m35s. The original-path r17 restart
passed HTTP status, unchanged SSH identity and clean shutdown in **54 seconds**
(10:10:20–10:11:14 UTC). This was instrumentation-only source, not a performance
fix. The retained suffix started at **7 rows**, versus **85** in the preceding
183-second run. That prior log shows 92 rows at 09:59:55.374682, zero at
09:59:55.731954, and seven at shutdown. The shorter restart must not be
attributed to the new timing markers. The capacity-triggered certified
checkpoint path is present in `query_authority`; the row-count transition is
consistent with that path, not evidence of manual history deletion.

Measured generation-open durations on the seven-row suffix:

| Stage | Duration |
| --- | ---: |
| Journal-store opening | 44 ms |
| Raft ledger opening | 24 ms |
| Artifact-store opening | below 1 ms timer resolution |
| Journal driver total | 8,054 ms |
| Within driver: `materialize_current` replay | 7,898 ms |
| Within driver: committee history | 19 ms |
| Within driver: profile/ledger audit | 56 ms |
| Within driver: cross-store reconciliation | 80 ms |
| Exposure/restore after driver | 43 ms |
| Inventory reconciliation after owner startup | 41,798 ms |

In the earlier 119.009-second host-open interval, the three completed recovery
audits total only 847,082 microseconds (299,300 + 251,223 + 296,559). Auditing
therefore does not account for most of that interval. The new run directly
locates most driver-open time in replay; attributing the earlier interval to
replay is an inference from the call order and audit timestamps, not a direct
replay timing on the same 85-row history.

Next work should focus on replay execution and safe certified-checkpoint policy,
while separately addressing inventory-query execution. Do not remove audit
checks based on the earlier BLAKE2 sample: the sample and decoding benchmark
identify real work but do not explain most startup latency. Both builds and
the startup probe are terminal; no process remains to poll. Evidence is in
`shared-reopen-phases.LP4zS4/{build.log,run.log,up.log}`, with the probe script,
HTTP status and SSH-key evidence alongside them.

### Physical runtime attribution without another rebuild

The same `f2b17cb2` release executable, with the existing
`vos::agent::local_journal_driver=debug` timer enabled, passed original-path
startup/HTTP/SSH/shutdown in **75 seconds** (10:14:33–10:15:48 UTC). Its retained
suffix started at 20 rows, so this is again not a fixed-history comparison.

Between the driver `executor_setup` and `materialize_current` markers, replay
took **25,048 ms**. Eighteen `physical Agent runtime execution` records total
**24,304,768 microseconds**, approximately **97%** of replay time. The timer
includes `RefineContext::load` and `.run`, not just interpreted instructions;
it excludes the subsequent bounded output decode. Call inputs were roughly
789–793 KB, with alternating calls using about 933 million and 500 million gas.
This establishes physical runtime load/run as the dominant measured replay
cost, not repeated host-side ledger auditing. It does not yet separate loading,
outer-runtime execution, nested actor execution or specific guest functions.

Inventory reconciliation took **44,935 ms**, including **42,885 ms** loading
inventory. The next implementation investigation should target runtime-call
cost (and distinguish load from execution if needed), while preserving guest
semantics, exact outputs and gas accounting. More aggressive checkpointing
could limit replay length but would not by itself fix expensive live queries.
No cache, checkpoint-policy change, timeout change or new artifact pin was made.
Logs, script and HTTP/SSH evidence are in `runtime-replay-timings.J9kxo3/`.
The probe exited zero and its daemon is stopped.

### Source-only acknowledgement candidate

The wire acknowledgement path first called `recover_clean_acknowledgement`,
then called `acknowledge_clean_invocation`, which repeated the same recovery
validation before applying fresh work. That validation includes `work.validate`
on the large availability payload. The candidate introduces one combined
recovery/application method returning the acknowledgement and whether it was
newly applied. The wire layer preserves its original state for retained retries
and errors. Fresh application still performs all original authorization,
result-binding, capacity and retirement checks. The unchecked fresh helper is
private and only called immediately after successful recovery validation.

Three focused acknowledgement tests passed (0.86 s), including a new status,
exact-retry and substituted-request state-preservation test. Seven additional
terminal-failure/restart/exact-acknowledgement/Required-attestation tests passed
(0.23 s). The CLI check passed (5.55 s, warnings). Only whitespace formatting
changed between the focused test build and the final CLI check. Logs are
`runtime-replay-timings.J9kxo3/ack-status-{tests,recovery,check}.log`.

This is **not yet in the bundled PVM** and has no measured gas or production
latency improvement. Next: build a candidate runtime without changing the pin,
compare its fixed large-ACK output and gas against the bundle, run rejection
and retry coverage against the physical candidate, then independently reproduce
and repin only when the candidate is qualified. Preserve the frozen review
checkpoint for matching-source/bundle testing in the meantime.

### Acknowledgement candidate built and reproduced

Two independent exports of `e3e9cb85a23c6122743ef641f209c670d4d8b70f`, separate
guest targets and locked/offline `nightly-2026-03-20` builds completed in
27.62 s and 28.66 s. The existing frozen r17 builder converted both. ELF and
PVM comparisons are byte-identical. Candidate identities (BLAKE2b-256 for
files, ProgramId for the program):

- ELF: `192eb3707f5028c23bdb283b5ac27949d6c3b9a634265481bad7558eb1c19811`
- PVM: `039393a40e61e25096533dedd24354ad38fb2d2ec05182bc08d60d11ffeb2933`
- ProgramId: `891e74d48bed26dc93f744a48cc34a001fddf1f348d3e19570133be282117cb0`

The fixed 793,734-byte large-ACK test passes byte-identical complete output
against the bundled r17 runtime. Gas decreases from **515,760,196 to
457,383,570** (about **11.3%**). Single debug-host timings of 1.089 s and 1.048 s
are not a controlled production wall-time comparison. The candidate also
passes the physical terminal-failure lifecycle test (five cases with retries,
acknowledgement and repeated acknowledgement) and two physical typed-error
retirement tests, comparing complete guest output to source: three tests total,
2.56 s. Together with the gas comparison, four candidate physical tests passed.

Evidence is under `ack-recovery-candidate.dHhhcp/`: `build.sh`, `build.log`,
`runtime-build.log`, `identity.log`, `cost.log`, `physical-recovery.log`, and
the independent `second/` export/build/artifacts. Builds and tests are terminal.
The candidate is **not pinned**. Broader physical malformed/retry qualification,
atomic provenance/pin updates and final-source fresh-space checks remain before
promoting it; no production latency gate is closed by the gas result.

### Physical rejection qualification and native-test failure

`VOS_AGENT_RUNTIME_ACK_CANDIDATE` now selects the candidate in the physical
retired-invocation test and optionally adds physical output comparison to the
five forged/divergent acknowledgement rejection cases. A new physical test
requires truncated and trailing acknowledgement frames to produce `Panic`,
with a valid-frame `Halt` control. Five focused tests passed in 1.25 s, covering
those checks plus capacity and exact-retry status. The changes are test-only;
the previously reproduced candidate remains the same guest source.

The broader 31-test `acknowledgement` filter **aborted with stack overflow**;
it is not a passing qualification run. Isolated native Install/reopen before
acknowledgement passed in 12.00 s. The isolated startup-finalizes-saved-ACK
case still overflows at the normal stack limit. A debugger located the fault
in BTreeMap insertion during `StandardAgentRuntime::restore`, called from
`decode_standard_runtime_state` → `apply_clean_invoke` → native-test replay
inside Shared driver reopen. The sampled path does not reach acknowledgement
application, but there is no same-profile baseline comparison proving this is
pre-existing. Do not promote the candidate on the focused passes alone.

Evidence under `ack-recovery-candidate.dHhhcp/`: `ack-qualification.log`,
`ack-focused.log`, `native-ack-isolated.log`, `native-ack-remaining.log` and
`stack-diagnosis.log`. The debugger accidentally used the default temporary
directory; its exact failed fixture was moved from
`/tmp/vos-clean-system-bootstrap-bundled-authority-management-49266-1` to
`debugger-failed-fixture/` in this evidence directory, preserving it on disk
and removing that RAM-backed copy. The moved raw fixture is forensic evidence,
not a reopenable replacement for its path-bound original. Test/debugger
sessions are terminal. Next: resolve or establish the baseline for this native
stack failure without increasing stack limits or weakening assertions, then
finish pin qualification.

### Native stack failure resolved without changing the stack limit

The install fixture called its restart/recovery helper while retaining large
installation-setup frames. `check_install_startup` now runs that same recovery
helper on a normal-sized scoped worker, following the existing lifecycle-test
pattern. No assertions, production code, thread stack sizes or guest artifacts
changed. The previously overflowing exact native saved-ack startup test passes
in **16.80 s**. The original broader acknowledgement filter then passes:
**30 passed, zero failed, one ignored profiling probe**, **29.56 s**, with
`VOS_AGENT_RUNTIME_ACK_CANDIDATE` selecting the candidate where supported.
This resolves the observed stack failure; it does not establish when it first
appeared or replace final-source full-suite qualification.

Evidence: `ack-recovery-candidate.dHhhcp/native-stack-fixed.log` and
`ack-qualification-fixed.log`. `native-stack-build.log` records the 32.03-second
test build but selected zero tests due to a short filter combined with
`--exact`; it is build evidence only. The subsequent exact fully qualified
invocation and broader run above are the actual test evidence. Both are
terminal. Artifact pins remain unchanged pending promotion qualification.

### Reproduced acknowledgement runtime pinned

The runtime PVM, `support/production-artifacts.toml`, protocol ProgramId and
`vosx/build.rs` digest now use the independently reproduced `e3e9cb85` artifact
and identities listed above. The r17 ABI and system actor templates are
unchanged; the runtime ProgramId is new. Preserve old fixtures and do not
relabel their pinned identity. Use a new disposable space for the next smoke.

Post-pin verification without candidate overrides:

- CLI release-pin tests: **18 passed**, 0.88 s (34.71-second test build).
- Physical `agent_runtime_pvm` suite: **4 passed, one ignored**, 1.75 s.
- The ignored compiled directory-lineage/restart test was explicitly run with
  the new bundled PVM: **passed**. The Attested output-binding test is gated by
  `agent-transition-proof` and was not compiled/run in this feature selection.

The first integration run failed two stale assertions: a hardcoded r15 ABI
despite r17 source, and `AuthorityExpired` for an invocation already acknowledged
and retired. The latter is now asserted as `DivergentInvocation`, consistent
with the existing physical retired-invocation test and the runtime's retained
retirement check. State-preservation assertions remain. The final rerun above
uses corrected expectations, not changes to guest behavior.

Evidence under `ack-recovery-candidate.dHhhcp/`: `post-pin-cli.log`, initial
`post-pin-physical.log`, corrected `post-pin-physical-final.log`, and
`post-pin-lineage.log`. No full-suite or new-pin daemon latency pass is claimed.
Next: build the pinned CLI and run fresh-space bootstrap/restart/HTTP/SSH with
the matching runtime, then finish the remaining original release gates.

### Fresh-space smoke at `725f6240`

The pinned release CLI build passed in **6m32s**. A new isolated identity and
space were created successfully, with the generated `local.toml` enabling HTTP
on loopback 8080 and SSH on loopback 2222. The original default-port smoke
refused to start because a default port was already occupied; that service was
not touched. The generated config was preserved, then only this fixture's ports
were changed to loopback **18097/2239**.

First startup reached readiness in **32 s**, restart in **42 s**. Both passed
HTTP `status == ok`, SSH key acquisition and clean SIGINT shutdown. The final
raw `ssh-keyscan` file comparison failed because comment/banner lines arrived
in different order. A separate comparison established exactly one actual key
record in each file and byte-identical sorted non-comment records; no key data
was ignored. The script now compares key records rather than comment order.
Thus the original script exited one, while the explicit corrected identity
check passed; do not describe this as an unmodified one-command green run.

SpaceId: `b609a179190b8678f0b1223f0a25fec4e6dfb1390c3acda20add17cca978ba07`.
Genesis root: `60394853bfae8f28af589c52411a8de93181ddf6ee17c35bc44dfd38e061d072`.
Evidence: `ack-pin-fresh-smoke.31JLq5/` contains `build.log`, `new.json`,
`new.stderr`, `generated-local.toml`, initial `smoke.log`,
`isolated-smoke.log`, `first-up.log`, `restart-up.log`, HTTP responses,
SSH key records and the corrected `smoke.sh`. Both daemon runs and build are
terminal. Previous fixtures were untouched and all scratch is disk-backed.

This validates fresh bootstrap and restart with the new bundle, not new-pin
Create/Install latency, sustained capacity, ordinary Shared-agent finality or
the final production release matrix. Different histories make earlier timing
comparisons uncontrolled; the measured 11.3% gas reduction remains limited to
the fixed large acknowledgement test.

### Full CLI run: startup deadline remains failing

At `c441fabd`, the full socket-enabled `cargo test --locked -p vosx` run
reported **255 unit tests passed, 19 ignored**, four package-build integration
tests passed, and one build-task integration test passed. Shutdown smoke failed
to observe an endpoint within its unchanged **10-second startup deadline**.
Its preserved daemon log later reported `Address already in use`; the process
had exited when checked. The command is therefore **not green**: 260 passed,
19 ignored, one failed across its binaries. The SDK locked/offline
`--no-default-features` check also passed (0.20 s).

The shutdown test now uses loopback ephemeral ingress ports, detects early
child exit, and owns a guard that kills/reaps its exact child on panic paths.
Both startup (10 s) and SIGTERM-exit (5 s) deadlines and endpoint-removal
assertions are unchanged. The isolated rerun still failed startup readiness in
11.43 s overall; the child was subsequently confirmed absent. The guard fixes
test cleanup and port isolation, **not** the production latency gate. The
successful 32/42-second manual release smoke does not satisfy this test's
deadline or prove SIGTERM-after-readiness through this test. Earlier manual
smoke shutdown used SIGINT.

Logs: `ack-pin-fresh-smoke.31JLq5/full-cli.log`, `sdk-no-std.log` and
`shutdown-isolated.log`. The first failure's retained fixture is
`target/task-tmp/vosx-shutdown-69213-data-1789469988435677136` with its paired
config directory; all are disk-backed. The build-task test incidentally updated
its tracked fixture lockfile; only that generated change was reverted before
committing the shutdown-test patch. Tests and child processes are terminal.

### Source-only reuse of fresh acknowledgement authorization

Fresh acknowledgement already fully verified immutable work, authorization
and runtime identity before loading the retained result. It then called that
full verifier again with only a different observation slot. The follow-up keeps
the first full verification (blob validation, scope, issuer and signature) and
uses `matches_invoke` for the second slot-dependent check. PublicPreflight's
lower-bound slot condition and `InvalidAuthorization` error are retained. There
is no intervening mutation, no persistent validation cache and no weakening of
retained result/liveness/retirement checks.

A new test compares full verification with slot-only rechecking after admission
for signed receipts and PublicPreflight at zero, below/at/above the admission
slot and `u64::MAX`. The final acknowledgement run reports **31 passed, zero
failed, one ignored profiling probe**, **29.16 s**. Evidence:
`ack-recovery-candidate.dHhhcp/authorization-reuse-final.log` (the earlier pass
without the added equivalence test is `authorization-reuse-tests.log`).

This follow-up is not built into the bundled PVM and has no measured gas or
end-to-end speedup yet. Next: freeze and independently build a candidate,
compare exact output and gas against the current `891e74d4…` pin, and qualify
physical retry/rejection behavior before another pin change. The unchanged
10-second startup deadline remains failing.

### Authorization-reuse candidate reproduced and pinned

Independent exports of `126657f70b6e8523f57b6cfd3e476a75adaa048c` built with
locked/offline `nightly-2026-03-20` in **26.80 s** and **28.78 s**, using distinct
guest targets and the frozen r17 converter. ELF and PVM match byte-for-byte.
The PVM and matching provenance/build-time/protocol pins now use:

- ProgramId: `db577aff938689516493e01de59536218388e780dd7bf1f9f81ce056dbb764a9`
- ELF BLAKE2b-256: `ba471081c021bc0ada12d091941ed7b7099f44e7e72a75223b6066a28b1ef0fd`
- PVM BLAKE2b-256: `90774afca15a8911b9690f4621c838b4ef46b1aa1c1c11e739eff113ac49c8a7`

The fixed 793,734-byte acknowledgement output is identical to the preceding
`891e74d4…` pin, with gas **457,383,570 → 395,232,496** (13.6% lower). Relative
to the earlier 515,760,196 baseline, the two optimizations together reduce this
specific test's gas by about 23.4%. Single concurrent debug-host wall timings
are not evidence of production latency improvement.

Nine selected checks passed (4.69 s), including the gas comparison, candidate
physical malformed-frame/rejection/retry/retirement and terminal-failure/typed
error coverage, plus native acknowledgement capacity/status tests. Post-pin,
without candidate overrides, **18 CLI release checks** passed (0.72 s), **four
physical lifecycle tests** passed (1.68 s), and the separately enabled compiled
directory-lineage test passed. The Attested proof-feature gate and newest-pin
daemon smoke remain open, as does the original 10-second startup failure.

Evidence: `ack-authorization-candidate.rYKE8M/` contains `build.sh`, `build.log`,
the `first/` and `second/` source/build/artifact directories, `physical-tests.log`,
`post-pin-cli.log`, `post-pin-physical.log` and `post-pin-lineage.log`. No guest
ABI or system-template change was made; no existing fixture was relabelled.
All builds/tests from this checkpoint are terminal.

### Newest-pin release smoke

The locked release CLI build from `c5260e9f` completed in **6m26s**; its runtime
and production source match the `bb6c35b9` C2 review checkpoint (the intervening
commit only records review references). A new isolated space named
`authorization-pin-smoke` was created, generating the default HTTP/SSH config.
That generated config was retained, then only the test ports were changed to
loopback **18098/2240**. Prior fixtures and services were untouched.

The complete smoke script exited zero: **28 s first startup, 39 s restart**,
HTTP `status == ok` on both, exactly one SSH key record per run, identical
non-comment key records, and clean SIGINT shutdown after each run. No test
daemon remains. These are new-history observations, not controlled wall-time
speedup measurements. The 10-second startup test and Create/Install latency,
capacity, Shared finality and remaining release/profile gates are still open.

Evidence: `authorization-pin-smoke.thZJrt/` contains `build.log`, `new.json`,
`new.stderr`, `generated-local.toml`, `cli.sh`, `smoke.sh`, `smoke.log`,
`first-up.log`, `restart-up.log`, HTTP responses and SSH key records. All
scratch and fixture stores are disk-backed. Review refs remain frozen; neither
`saga/agents` nor master was advanced.

## Local evidence and resumption

Evidence is on disk under `.worktrees/ch08-c2-native/target/task-tmp/`, not `/tmp`:

- `decoder-fixed-history.Q5oYmW/`: `comparison.log`, paired baseline/candidate
  logs, `candidate-release-regressions.log`, `startup-phase-check.log`,
  `startup-phase-build.log`, `startup-phases-run.log`, `startup-phases-up.log`,
  status response and SSH-key comparison inputs.
- `r17-startup-smoke.ncMr4z/`: `final-source-release-library.log`,
  `final-source-network-sockets.log`, `final-source-merge-socket.log`,
  `final-source-node-socket.log`, and `final-source-native-capacity.log`.
- `owner-startup-phases.5se4bH/`: `build.log`, failed relocated-copy `run.log`
  and `up.log`, successful `original-run.log` and `original-up.log`, HTTP/SSH
  evidence and both probe scripts. The successful probe exited zero; neither
  probe remains running.

These are local evidence paths, not committed or portable release artifacts.
Preserve the fixture's config/locks authority stores as well as its data,
retained requests and logs. The latest smoke completed and stopped its daemon;
its session handle is no longer live. Do not restart it merely to poll status.

Before integration, inspect the complete diff and dependencies and establish
the three review boundaries without rewriting the existing implementation
branch. Before master, close every open requirement in the closeout plan and
qualify the final source, not just this checkpoint's focused tests.
