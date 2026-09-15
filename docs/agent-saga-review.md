# Reviewing the Agent architecture saga

## Review entry point: bundled checkpoint `b7cfa17d`

Use these two ranges for the current review; the older snapshot below remains
historical evidence. No merge or push is implied by this breakdown.

| Batch | Exact range | Scope and size |
| --- | --- | --- |
| 1 | `31b0cdbb..f79f0e3d` | Integrated clean-break architecture and lifecycle;225 files,+72,934/-58,875. |
| 2 | `f79f0e3d..b7cfa17d` | Recovery, checkpointing, shutdown, prepared-runtime reuse, ACK validation reuse, reproduced pin and qualification;23 files,+2,115/-88. |

Batch1 remains large and cannot be presented as an independently safe old C1
cut. Batch2 contains all subsequent fixes together, not one review per commit.
For batch2, review exact pending-binding recovery and original retry successor;
safe-boundary shutdown; cold/prepared output and gas equivalence with fresh
machine state; and the private fresh-ACK continuation's preceding immutable
work validation plus retained signature/scope checks. Match the new artifact
to immutable source and provenance. The following evidence distinguishes
passing regressions from still-failing production gates.

## Follow-up after the frozen review snapshot

Current release now passes Counter increment and fresh read-after-restart:
both return7; managed calls29.12s/34.80s. Retired Invoke replays reject and ACK
retries match exactly. Latest Install retry verified. Restarts54s/53s still
fail readiness; both shutdowns pass within2s. The test verifies the original
client Create request/ACK through framed stores. See the handoff for evidence.

Correction to the diagnosis below: the issuer deliberately keeps only the
latest acknowledged decision, so moving lookup before intent pledge cannot
restore older Create replies after Install. Such historical retry support
requires a retention/protocol decision. No production fix or expanded
retention is claimed; the503 reporting limitation remains documented.

Latest retry qualification found a limitation: replaying the original completed
Create after Install/restart returns503 `Lifecycle(Conflict)`. Install advances
the single retired lifecycle intent slot; Create pledges against that slot
before reaching finalized issuer recovery. The original requests and fixture
are preserved. Invocation/read-after-restart checks were not reached. Broad
exact-retry qualification remains open; see the handoff for evidence and the
required authenticated successor-handoff recovery boundary.

Release `b7cfa17d` is now built and its bundle verified. Fresh isolated startup
took21s (still fails10s gate), HTTP/SSH passed, fresh Create succeeded in43s
with a verified acknowledgement and no timeout, and post-Create SIGTERM exited
within1s. The same fixture subsequently restarted in54s with HTTP and unchanged
SSH identity, then completed fresh Counter Install in65s with a verified
acknowledgement and no timeout. Post-Install shutdown passed within1s.
Invocation and post-Install retry/read-after-restart are now qualified above. These are not
controlled comparisons with old retained-history probes. See the handoff for
binary checksum, exact fixture, logs and remaining release blockers.

The latest fresh-ACK optimization is now bundled: source `4a208b19`, runtime
ProgramId `25bdad0f9a1b0ca8450338d916adc41306d9d740f68bb5b2490ab8b8b9fb3da1`.
Two independent immutable-source builds produce identical ELF/PVM bytes.
It removes one duplicate validation of immutable work, retaining scope and
signature checks. The fixed large-ACK comparison preserves complete output
and reduces gas14.74%; eight candidate checks and18 post-pin release checks
pass. All six physical runtime checks pass, including the two explicit
candidate checks (install lineage and Attested public-output binding, not
full cryptographic proof qualification). These changes belong to batch2 below.
The release executable now includes this pin; initial live qualification is
above. No controlled end-to-end speedup or production sign-off is claimed.

Latest performance diagnosis uses test-only instruction attribution with the
real bundled outer runtime: large nested calls execute roughly275 million
outer instructions versus11–19 million actor instructions; other large calls
execute142–144 million outer instructions with no actor execution at all.
The lifecycle/recovery regression passes in both profiling and normal modes.
This points the next optimization toward outer-runtime work, not solely actor
execution. It is not a new production speedup; instrumented timings are not
production benchmarks. Exact evidence and opt-in instructions are in the handoff.

Current CLI result at `04454ef0`:255 unit tests and five actor/task-build
integration tests passed;19 tests ignored. Shutdown smoke still fails because
startup exceeds its10s endpoint deadline; it never reaches the SIGTERM phase.
The failing isolated fixture and logs are preserved in the handoff. This is
an unresolved production-latency gate, not a fully green CLI qualification.

The current full host-feature run completed with1,867 passed, one failed,
three ignored (27m51s). The failure is an inventory stress-test assertion that
expected the original snapshot to survive until the hard history boundary,
despite the newer32-entry opportunistic checkpoint policy. A test-only update
retains the complete514-query workload and checks bounded history and monotonic
certified snapshots throughout; its focused rerun **passed in279.07s**.
The original failure log is retained; see the newest handoff entry. This is
full-suite evidence plus a passing corrected regression, not a second all-green
full-suite invocation. No production behavior changed in this correction.

The full default-feature `vos` library suite now passes on implementation
`206ea1e3`:1,434 passed, zero failed, one ignored,219.66s. This replaces the
old default-library baseline for current source; the host-feature result and
corrected regression verification are above. See the handoff for the exact
command and retained log.

Latest release implementation: `206ea1e3`. Its release build and bundle
verification pass. The preserved-space probe passed HTTP, unchanged SSH
identity, retained Counter read/exact retry, and one busy SIGTERM shutdown
within5s. Startup took59s and remains a failed gate. Periodic Credential query
3.439s / route reconciliation3.884s; the two large runtime executions still
take2.342s together. These are not controlled before/after measurements or
fresh Create/Install timings. Resident memory after reconciliation232.1MiB,
observed high-water261.0MiB; no comparable old-release memory baseline.
The release is suitable for continued disposable testing, not production
sign-off. Exact logs and release checksum are in the newest handoff entry.

Program-preparation reuse has been implemented after `97c08c88`: opaque
validated Refine preparation plus a single-entry, exact-byte-keyed Agent
executor cache. This belongs in the performance portion of batch 2; the frozen
ranges below remain reproducible and do not include it. Runtime tests (260)
and default-feature local-driver tests (32) pass, as does the runtime no_std
check. Load-only measurement fell from67ms to3ms on the bundled program; this
does **not** establish an end-to-end speedup. Live qualification of `206ea1e3`
is summarized above; the final integrated matrix and release gates remain
open. See the newest handoff entry before using historical
statements below that describe this optimization as unimplemented.

## Current review checkpoint

Review snapshot: `2d88d540` on `wip/ch08-runtime-directory`;
latest production implementation and release executable: `8716f6a7`.
`saga/agents` remains at `31b0cdbb`. Nothing has been merged or pushed.
Review the integrated Chapter 8 changes together: the old C1 boundary depends
on clean-break corrections in C2 and is not independently merge-ready. The
frozen C2 review ref (`bb6c35b9`) does not include the subsequent fixes and
qualifications through this checkpoint. No C3 release sign-off is claimed.

Current runtime pin: `79c7d1f0ed2feff40eaca198951656c705d687ab83bbd581a8895a13db0022a7`,
reproduced from guest source `aad65049` and committed in `83737aee`.
Two independent builds match byte-for-byte; 18 post-pin release checks and
six physical integration tests pass. Fresh release startup/restart at
`83737aee` passed HTTP/SSH checks in 27/37 seconds. The release executable has
subsequently rebuilt at implementation source `668a86bb`, including issuer
validation reuse, pagination/checkpoint changes and two exact-recovery fixes;
its bundle creation and verification pass. The preserved test space now
recovers at its original path (147s), and Counter Install returns a verified
acknowledgement (92s). Recovery recognizes the exact reserved binding staged
before journal-head publication; it neither resets stores nor marks staged
work applied. A separate retry fix preserves the original publication successor.
Both have regression evidence in the handoff. At `668a86bb`, idle restart,
HTTP and stable SSH identity pass (30s startup), as do Counter mutation/exact
retry and read-after-restart. Post-invocation shutdown fails its unchanged5s
deadline in both earlier probes and requires forced cleanup. The follow-up
`8716f6a7` release (the current executable; bundle verification passes) stops
inventory pagination at shutdown-safe boundaries:
busy-inventory SIGINT passed within5s, but SIGTERM exceeded5s before exiting
during cleanup without SIGKILL. This does not establish a signal-type difference
or close the shutdown gate. Latency and shutdown remain release blockers;
the functional passes are not production sign-off.

### Two review batches, not 318 individual commit reviews

These immutable ranges define the review snapshot. They are sequential, not
independently deployable alternatives. No new review refs or merges were made.

| Batch | Exact diff range | Scope and size |
| --- | --- | --- |
| 1: Integrated architecture | `31b0cdbb..f79f0e3d` | Clean-break architecture, runtime/artifacts and native lifecycle; 225 files, +72,934/-58,875 lines. |
| 2: Recovery and qualification follow-up | `f79f0e3d..2d88d540` | Checkpoint admission, exact replay/publication recovery, safe-boundary shutdown, live tests and evidence; 12 files, +1,171/-39 lines. |

From this worktree, review without changing branches:

```sh
git diff --stat 31b0cdbb..f79f0e3d
git diff 31b0cdbb..f79f0e3d -- vos/src/agent
git diff --stat f79f0e3d..2d88d540
git diff f79f0e3d..2d88d540 -- vos/src vosx/src
```

The first batch remains large; two batches simplify review sequencing, not the
underlying change size. Batch 2's primary correctness questions are whether
recovery accepts only the exact authenticated pending reservation, exact replay
retains its original successor, and shutdown stops new pagination without
interrupting durable work or treating incomplete work as applied.

Test baselines: 1,429 default library tests passed at `0bf97332`; 1,862
host-feature library tests passed at `f79f0e3d`. Later recovery changes have
focused regression coverage; the shutdown implementation has 11 passing
production-owner tests and eight passing selected shutdown tests. These do not
constitute a passing final integrated matrix. Do not infer production readiness
from library tests or merge the old C1 boundary independently.

### Measured performance and the next bounded fix

On unchanged release `8716f6a7`, one periodic Credential query took 4.780s:
10 runtime load/run spans totaled 2.950s, with two roughly 790KB inputs taking
2.302s together. About 1.83s remains outside those measured spans. A separate
8s CPU sample attributed roughly 52% to interpreter execution, 20% to
conformance gas-cost simulation functions and 19% to BLAKE2. Sample shares are
not wall-time fractions or a controlled before/after benchmark.

Refine currently repeats immutable program parsing, validation, instruction
decoding and block-gas-cost preparation on each load. The next bounded candidate
is opaque, validated, bounded prepared-program reuse, with fresh memory,
registers, arguments, gas and inner-machine state per invocation. It is **not
implemented or qualified**. Require cold/prepared equivalence for output, exit,
gas and state isolation, then measure the gain before rebuilding the release.
Do not change charged gas, omit authenticated work bytes or reuse results to
achieve a latency target. The profiling evidence does not yet fully explain
the 92s Install or startup delays.

### Test deployment boundary and remaining release work

The checkpoint supports initial testing in a disposable environment, not a
production rollout or master release. Start with a fresh isolated space and
retain logs and exact client requests; do not migrate existing production
stores through this clean-break branch. Preserved fixtures must stay at their
original absolute paths because their host bindings include path identity.
Expect startup delays, possible request timeouts and a failing busy-shutdown
deadline. An HTTP timeout does not prove that a mutation failed: preserve and
resume the exact operation rather than issuing a fresh replacement mutation.

This is a review checkpoint, not production readiness.
Remaining blockers include production ordinary Shared-agent genesis/finality
wiring, authenticated reclamation of the host's 256-record operation journal,
startup/Create/Install latency and shutdown gates, and the final integrated
release matrix including full cryptographic proof qualification. See
[the handoff](agent-saga-handoff.md) for exact evidence and remaining work.

## Historical checkpoints

The entries below describe earlier pins and source revisions, not the current
release identity. Timings with different retained histories are not controlled
before/after comparisons.

Previous pin: the authorization-reuse follow-up from `126657f7` is independently
reproduced and bundled as ProgramId `db577aff…`. Nine candidate checks, 18
post-pin release checks and five physical lifecycle/lineage checks pass. Fixed
large-ACK gas is 13.6% lower than the preceding pin with identical output.
Newest-pin fresh startup/restart now pass in 28/39 seconds with HTTP, unchanged
SSH key and clean shutdown. This remains above the 10-second startup gate.

Previous pin update: the acknowledgement optimization from `e3e9cb85` was
bundled with matching provenance, ProgramId and build-time digest. Two independent
candidate builds matched; 18 release-pin tests and five physical lifecycle/lineage
tests pass after pinning. The r17 ABI and system templates are unchanged, but
the runtime ProgramId changed. Fresh-space release startup/restart now pass in
32/42 seconds with HTTP, SSH key identity and clean shutdown checks. Final release
qualification and production latency remain open. Historical r17 timings below
used the old pin; see the handoff for the new-pin smoke's exact qualifications.
The subsequent full CLI run is not green: 260 tests passed, 19 were ignored,
and shutdown smoke failed its unchanged 10-second startup-readiness deadline,
including after test ingress ports were isolated. Production latency remains
an explicit release-test failure; see the handoff for cleanup and exact logs.

For the frozen `f76dabe1` review checkpoint, current evidence limits, and the
three scoped review areas, start with [the review handoff](agent-saga-handoff.md).
The later sections of this document retain historical results; they are not
all measurements of the current source or the same retained history.

Current Ch08 WIP warning: `wip/ch08-runtime-directory` now has matching r17
source and independently reproduced runtime/system-template bundles. Fresh r17
bootstrap/restart and HTTP/SSH checks now pass (39 s first start, 58 s restart).
Recovered r17 Create/Install and Counter mutation/exact-retry/restart-read also
pass. Live unseen-expiry retirement and unchanged Counter state after restart
now pass too. Ordinary-agent finality,
cross-runtime actor lifecycle, production latency
and full release gates remain open. This is not a master-ready branch.
Capacity qualification: successful issued coordinator/issuer records still
accumulate to a 256-record ceiling. Passing overflow-rejection tests does not
prove sustained operation beyond that ceiling; authenticated reclamation and
exact-retry preservation remain required before production readiness.
Timing qualification: earlier live campaigns used the debug CLI. The configured
fat-LTO release build now passes, but its r17 recovery startup took 161 seconds
and the first Counter Install returned HTTP 504. This is also a release-mode
latency failure, not just debug overhead. A short CPU sample during installation
attributed 77.57% of core-cycle samples to BLAKE2 compression; the caller/root
cause remains unproven. Exact retained Install recovery now passes, as below.
The updated release executable at `2a4f17ea`, including both subsequent host
optimizations, passes startup/HTTP/SSH in 99 seconds. Startup remains too slow;
different retained histories prevent treating these runs as a controlled A/B.
The newer release executable at `ec8bdb70`, including the nested decoder
changes, passes the same startup/HTTP/SSH/shutdown check in 112 seconds.
The fixed-history decode improvement below has not established an end-to-end
startup improvement; production latency remains open.
The instrumented `f76dabe1` release restart completed in 159 seconds, with
HTTP status, unchanged SSH identity, and clean shutdown passing. System-owner
open/recovery took 95.515 seconds; inventory reconciliation took 59.784 seconds.
These phase measurements locate the delay but do not establish its complete
internal cause or a controlled end-to-end performance comparison.
The subsequent `824b2c9c` release restart passed HTTP/SSH/shutdown in 183 seconds.
Owner-stage timings attribute 119.009 seconds to Shared host opening (including
the committee-binding step before its marker); inventory reconciliation took
56.682 seconds. See the handoff for the failed raw-copy attempt, path-bound
lease constraint, and successful original-path run. This is still a latency
failure, not a fixed-history before/after result.
At `f2b17cb2`, the instrumented release restart passed in 54 seconds after the
previous run reduced the retained suffix from 92 rows to zero and ended at
seven rows. Direct driver timings now locate 7.898 seconds in journal replay;
inventory reconciliation still took 41.798 seconds. This is a different-history
measurement, not a speedup from instrumentation. The prior 119-second open
contained only 0.847 seconds of completed ledger recovery audits. See the
handoff's replay attribution before choosing another performance change.
See the current closeout plan below; later checkpoint sections retain historical
results, including failures that have since been fixed.
Earlier clock-test pass counts had a fixture-dispatch gap; see "Retained
lifecycle-store leases and corrected clock coverage" for the correction.

## Current closeout plan

Implementation is in `.worktrees/ch08-runtime-directory` on
`wip/ch08-runtime-directory`, not yet in the root `saga/agents` checkout.
The C2 r17 runtime and system templates are reproduced from source `5bbab66b`
with the matching frozen builder and bundled together. Post-pin physical expiry
and failure-retirement checks pass without candidate overrides; see the r17
checkpoint below for the current validation results. Fresh r17 bootstrap/restart
now passes, as do recovered r17 Create/Install and Counter mutation/exact-retry/
restart-read against the release daemon. Live unseen-expiry retirement and
post-expiry restart-read also pass; broader expiry/abort recovery remains open.
Do not reuse or relabel r16 fixture data.
The earlier r16 `.lU4S5Z` live campaign passes compiled protected Local yield/resume,
retirement, two restarts and final-state query, plus Panicked-result retirement
after restart with a released credential reservation. Its daemon is stopped.
Compiled typed-error retirement passes; live typed-error coverage,
expiry/abort/mixed-pending recovery, Shared finality,
Private/Attested and production latency/release gates remain open. These are
still C1/C2/C3 work, not new review batches or a master-readiness declaration.
Use only an isolated, disposable environment for bootstrap/ingress testing.
Fresh-space identity derivation now selects the actual canonical `set_root`
event instead of empty initialization, and creation commits a full-width
per-space bootstrap identity. Two spaces under one operator now have distinct
root-bound IDs, and corrected genesis passes native startup. Existing spaces
whose IDs came from the empty event are intentionally mismatched, not migrated;
preserve the earlier collision fixtures and do not relabel their IDs manually.
Fresh-space first start and restart with bundled system actors and HTTP/SSH
have passed. One recovered Local Create has returned a client-verified
acknowledgement after native route reconciliation. Exact repeated delivery now
passes after recovering a recorded HTTP timeout; first-response latency remains
high. The fresh signed-denial / valid-successor / exact-retry campaign also
passes at `8abbe363`, but requires two HTTP 504 retries for the valid Create.
Install delivery has passed exact recovery after restart. A Public Catalog
query on the installed Local actor now passes through clean HTTP preparation,
invocation, retained delivery and an exact HTTP retry. Exact HTTP invocation
after restart also passes. Native positive retirement and exact acknowledgement
retries now pass before and after restart. Public Counter mutation, late replay
rejection and a fresh read of seven after actual daemon restart now pass with
the repinned runtime. Protected Local mutation and yield/restart now pass as
detailed below; other profiles and broader failure categories remain open.
The latest LocalSigner campaign passes installation, a live deployment-scoped
role grant, protected Local execution, visible signature verification and
positive retirement. An exact retained client retry and a fresh protected
execution with a new invocation ID also pass after actual daemon restart.
Deployment-scoped role revocation now produces a verified signed denial with
no actor application; exact denial retry and fresh success after re-grant pass.
Two earlier malformed test inputs and their reservations remain preserved.
See the LocalSigner campaign checkpoints below. Latency remains unacceptable.
This is not yet a usable ordinary-agent production path.
The latest runtime pin includes single-pass AWRK availability decoding. Its
fixed 768KB-program ACK comparison uses about 25.3% less gas with byte-identical
successful output; that does not establish acceptable end-to-end latency.
The latest host-only interpreter inlining probe reduces median time for the
same fixed ACK by about 20% with identical gas; no live latency gate is closed
by that microbenchmark. See "Native interpreter helper inlining" below.
Managed authorization now has a live exact-recovery pass: the saved IgQS0r call
was authorized after recovery-only startup, followed by verified inventory,
receipt-bearing Catalog query, positive retirement and exact retries. The live
invocation test passed in 5.14s after readiness, and shutdown was clean. This is
a Public query with a receipt, not non-Public mutation or ordinary Shared finality.
A fresh successor invocation now also passes on its first managed attempt, with
the next credential operation sequence, positive retirement and exact retries.
It took 176.52s; the full live test took 178.76s. Historical clock/scheduler/startup
failures are preserved below. Protected mutation and latency gates remain open.
The next Counter installation exhausted four exact HTTP attempts with 504s,
then exact resume after restart returned a verified acknowledgement in about
14 seconds. The subsequent live mutation exposed a **duplicate-execution bug**:
the first increment returned seven and retired, but exact late Invoke returned
fourteen. Restart-read verification was not run. A source guard now rejects
Invoke against a retained acknowledgement. The runtime artifact is now rebuilt,
repinned and verified by a physical-PVM regression and a fresh isolated
end-to-end Counter mutation/restart campaign. Do not deploy the old bundled
runtime as fixed. The failing disposable state is
preserved, not reset. A short reconciliation CPU sample was dominated by BLAKE2
hashing; the complete caller/root cause remains unproven.
Native host-clock preparation retains AOC5 before HTTP and exact returned AOQ1
before authorization. Periodic reconciliation defers while admission is held;
startup now exposes only exact retained authorization recovery until inventory
is verified. Issuance alone leaves the credential pending; actor retirement
completes it. No saved AOQ1 was rebased or pending reservation cleared.
Recovery remained slow: about 217s to recovery ingress, 109s to authorization,
then 196.952s of initial inventory reconciliation. These are release blockers,
not acceptable production latency or grounds to waive timeouts.
The native Local Install application and startup-recovery phases now pass
physical tests from prepared authorization through retirement, including
pristine client-retry admission. Native Install controller handoff, retry and
restart now pass; the production-owner wrapper requires an exact active Local
route after reconciliation. Install now has signed-frame, bounded native queue
and HTTP server wiring, plus retained-request and fresh managed CLI commands.
Fresh Install discovery/preparation/credential allocation is wired; managed
resume and a fresh successor Install now pass live. A Public actor query now
passes live, but this does not prove protected/mutating invocation or the full
mutation/recovery workflow. Do not treat command availability as an end-to-end pass.
The first fresh Install campaign on saved disposable state failed all four
HTTP waits (604.30s total test time), then shut down cleanly after route
reconciliation finished. No client MAA2 was retained in that failed campaign.
Subsequent exact resume after restart now passes and retains verified MAA2.
A second fresh actor Install on the same Agent passes in 394.01s after two
HTTP 504 responses, followed by exact retained retry and clean shutdown;
first-response latency and protected/mutating invocation remain open. See the
live results below.
The native Local-controller wiring at `ee047d48` passed fresh-data startup and
restart using the rebuilt CLI (`target/native-local-smoke.DATNas`, details below).
This is bootstrap/ingress coverage, not ordinary-Agent creation/installation.
AJC3 checkpoints and AGIM/AGI2 images are deliberately rejected, with no in-place
migration provided; do not point this clean-break build at valuable old data.
Current host lifecycle images additionally use CMI4/CMR2 with pre-dispatch
journal anchors; earlier CMI3/CMR1 images are rejected, not migrated.
Canonical denial completion now uses a signed CND1 host record.
Startup now discovers lifecycle stores before system attachment, replays saved
initial-Create authorization when receipt issuance is incomplete, completes
Local Create from an exact issued receipt and retained runtime when necessary,
recovers acknowledgements from durable Local images, completes finalization
(including protected preparation of a missing envelope), and retires results
before normal routes. First-time application still requires a valid unexpired
receipt. A pristine intent without saved authorization remains available for
client retry rather than automatic dispatch. A same-credential successor can
now recover after its already-issued predecessor when that predecessor has a
saved finalization whose clock does not overtake any unissued authorization.
Startup physically checks and retires those predecessors before dispatching
successors. Missing predecessor finalization, incompatible saved clocks,
unsupported issuer histories, or missing required runtime artifacts still stop
startup, preserving their stores. Fresh live Local Create now reserves capture,
extends admission through finalization and positively acknowledges both runtime
results before returning success. Saved live requests require their exact
restored reservation; retirement-write retries release only the verified pair.
Canonical unissued denials now positively acknowledge their single runtime
result and persist signed retirement before releasing admission, including
signer/write retries and startup recovery. Signed denial is now wired through
the native queue and HTTP response; the managed Create CLI retains certificates
before marking reservations denied. A live signed denial and local denial resume
passed; the subsequent valid Create timed out, then returned matching verified
acknowledgements after restart with exact-head inventory reuse. A separate fresh
combined denial/successor campaign now passes with two timeout retries (details
below). Fresh latency remains high. Other blockers include
expiry/abort resolution after approval or issuance,
full capacity/crash-boundary verification, and coexistence with an unfinished
projection. This is not deployment-ready behavior. Do not delete those stores
to bypass the recovery check.

The integrated library run at `37d6a5720e7e45e4a19850a16a531e6cb316e299`
completed: **1,663 passed, zero failed, one filtered**, in 1,771.43 seconds.
It used `pvm,private-agent-store`, serial tests and socket access. Evidence:
`.worktrees/ch08-c2-native/target/task-tmp/r16-integrated-library.log` (path
relative to the main checkout). A newer optimized run at `4e8aa893` completed
in 3,696.62s, including the formerly filtered large inventory test: 1,813 passed,
20 socket-dependent failures (all passed unchanged with socket access), and
three ignored cases. The ignored native capacity gate also passed separately;
only two diagnostic probes remained unexecuted. Later decoder changes have
targeted passes, not a full-library rerun on their updated source. See the
cross-image and nested-decoder checkpoints below for exact scope and logs.

Keep the remaining work in three scoped Chapter 08 batches, without adding
review endpoints for individual fixes:

1. **C1 — recovery:** preserve the integrated portable-recovery fixes. Host-owned
   management evidence now survives checkpoint/GC/reopen and feeds the Shared
   projection comparator. Physical Shared certified snapshot/compaction and
   substituted-evidence reopen checks now pass, as do portable evidence
   preservation and the post-snapshot one-ack-lag projection checks described
   below. Production Local opaque-runtime management Create/reopen now uses
   public metadata and durable history. Scripted physical-PVM actor installation,
   invocation/resume/reopen and lane-transition checks now pass. Complete the
   remaining positive-ack retirement checks. Migrated invocation/reopen and
   expired upgrade retries now pass at the scripted physical host-ABI boundary.
   Target-runtime directory compatibility is now checked before Local cutover;
   the scripted host-ABI tests do not prove arbitrary guest execution semantics.
   Neither a private-state decoder nor a volatile cache is a runtime-independent
   proof.
2. **C2 — native lifecycle:** finish ordinary-Agent provisioning through the
   native entry point. Startup now retains both the system owner and the Local
   lifecycle controller. Signed Local Create has a bounded ingress queue and
   an HTTP submission endpoint and retained-request CLI submission. Fresh CLI
   preparation/discovery is now wired. Management dispatch clock drift is fixed
   in targeted tests. One live resume returned a verified acknowledgement after
   route reconciliation. The latest live test recovered a timeout and then
   returned two identical verified responses; initial latency remains high.
   Install ingress and retained CLI delivery are now wired, with live exact
   recovery passing. Public Counter mutation/restart and protected Local
   mutation/yield/restart have live passes; the latter campaigns predate r17.
   Live r17 unseen-expiry retirement and unchanged Counter state after restart
   also pass. Fresh completion latency and broader failure/profile coverage
   remain open. Complete
   authorization, durable issuance, physical application, acknowledgement and
   route publication as one restartable workflow. Replace the deliberately unavailable ordinary-Agent
   finality adapter with authenticated live system-Agent decision publication
   and independent replay verification, including reopen. A self-consistent
   provision or permissive verifier is not sufficient. Prove ordinary-agent
   creation, actor installation, invocation and restart from the actual native
   entry point, not a manually prepared library host.
   The owner now has tested Local Create/application and Authority-finalization
   adapters, including fresh journal replay before the issuer's finalization
   marker. These are now wired into native startup and the node Create API;
   first-response Create latency remains unacceptable, and they do not close
   ordinary Shared-Agent finality.
   Implement the Local native entry point first without pretending it replaces
   the Shared finality gate: image-backed `LocalAgentHost::open` does not use
   `AgentGenesisFinalityVerifier`. The journal-backed ordinary-Agent path does.
3. **C3 — release:** after those implementation changes, freeze source, rebuild
   and independently reproduce artifacts, run the final feature, physical,
   inventory, docs/examples and release checks, and repeat the fresh-space
   smoke. Fold internal checkpoints into the scoped review batches and only
   then advance the integration/review branches toward master.

The broad regression result closes the fourteen previously observed library
failures. It does not close either implementation gap or certify master
readiness. Avoid another full build/artifact repin before those changes are
ready, and keep temporary build data on disk under `target`, not RAM-backed
`/tmp`.

### Immediate C2 execution order

Keep these as work within C2, not new review batches:

1. **Done for the terminal Public query:** native invocation retirement/restart
   coverage for the newly added continuation client passes (live evidence
   below). Native yielded work still belongs to item 3.
2. **Implemented, with edge-case gates still open:**
   `DurableAuthorityOperationCoordinator` is connected to durable native stores and
   exact physical Authority dispatch. The CSF1 store pair and native owner
   execution boundary are implemented and tested below. The native coordinator
   adapter now passes disk-backed fixture checks; the production immutable
   journal backend also passes its CLI regression suite. Exact operation
   admission now passes native owner reopen before/after policy execution;
   the coordinator now captures native input automatically before a new pledge.
   A native-only controller now retains all three store handles across calls
   and reopens parsed state on each attempt, including after open failures.
   Daemon startup now adopts those stores and native node dispatch reaches the
   controller. Host-clock preparation, operation ingress/client wiring and
   terminal recovery now have the live and native passes recorded below.
   Mixed-pending, expiry/abort and capacity gates remain open. Preparation and an API
   credential do not issue an actor
   receipt. Retain the signed AOC5, exact authorization context and issuance
   slot before policy dispatch, and recover the exact issued preimages before
   re-authorizing. Physical admission must also survive restart/checkpoint/GC
   and coexist safely with pending management/projection work. Do not route a
   mutating operation through the read-only `pending_projection` record or
   replace actor policy with host-side signing.
   Real bundled-Authority approval, AOI1 consumption and exact issuance retry
   after owner reopen now pass for an installed executable query fixture.
   This does not prove protected application or terminal result retirement.
   Native acknowledgement of the successful result pair now passes while
   deliberately retaining admission. Signed completion continuation and owner
   reopen after either one or both acknowledgements now pass; production
   continuation storage now has a hardened, bounded file backend, owned by the
   production controller throughout daemon recovery and dispatch. Production
   operation dispatch now captures completion and acknowledges the result pair;
   signed terminal retirement and durable release now have a native owner
   boundary. Signed terminal startup classification now passes through the
   native owner. The production controller/daemon now own the hardened
   retirement index and use terminal retry/release. Native unissued-denial
   verification/acknowledgement and signed terminal denial release have native
   owner boundaries. Issuer-gated denial startup classification is implemented;
   the production controller/daemon now retain the hardened denial index and
   validate it during startup. Automatic terminal denial handling now has a typed
   native decision path. Canonical AOQ1 retry inputs now enter the existing
   bounded lifecycle queue. Request-bound AOR1 responses and immutable client
   request/response storage are implemented. HTTP and retained-submission CLI delivery
   are wired. Operation-domain discovery and deterministic prepared-work signing
   helpers and durable fresh-command orchestration are implemented. A fresh
   receipt-bearing Public successor now passes live; the protected mutation
   and broader terminal-resolution cases are not thereby complete.
3. **Protected Local scenario passed; broader terminal recovery remains open:**
   protected mutation, compiled yield/resume, positive retirement and actual
   restart now pass through native ingress and the managed client.
   The fresh Public Counter post-retirement/restart campaign now passes.
   The protected permission setup is now exercised: the real bundled
   Authority passes native signed space-role grant/revoke and rejects anonymous
   signed administration. Native retained admin dispatch now recovers across
   publication failures and owner restart before/after execution. Native
   success/denial terminal retirement and a valid successor now pass across
   result/retirement publication failures and restart. Hardened admin stores
   and the lease-owning controller are implemented and tested. Daemon startup
   now discovers/replays admin evidence before routes and retains those leases
   in the lifecycle owner. Signed host-clock preparation and submission now
   have native lifecycle APIs, bounded node-owned queue delivery and dedicated
   signed-body HTTP routes. Retained client preparation/submission commands now
   exist; deterministic signing, a separate admin reservation and fresh
   deployment-scoped role command/resume orchestration are implemented. The live
   protected LocalSigner execution, signature and retirement now pass before
   and after actual daemon restart, with a fresh post-restart invocation ID.
   Deployment-scoped role revoke, signed denial, exact denial retry and fresh
   success after re-grant now pass without consuming the denied operation's
   credential sequence. The compiled yield actor now retains two cooperative
   yields, resumes after an actual restart, completes with 111, retires, and
   returns 111 through a fresh query after another restart (`.lU4S5Z` evidence
   below). The broader terminal resolution/recovery cases remain open. Keep
   its credential sequence and generation CAS distinct from operation
   authorization; do not relax anonymous HTTP invocation or
   put this mutation in the read-only projection journal.
   A Public query or mutation alone does not close this item.
4. Close the already-required Shared finality, Private/Attested, terminal
   resolution and physical recovery/capacity gates above before C3. These are
   implementation blockers, not merely a final test run. Do not promote the
   branch or report the full saga complete while they remain open.

The nested system actor libraries also pass on `ae66a058`: Authority **58/58**
and Catalog **10/10**, with no ignored or filtered tests. Evidence beside the
library log: `r16-authority-actor-final.log` and `r16-catalog-actor-final.log`.
The commands used locked, offline dependencies and disk-backed scratch space.
The root workspace does not execute these nested workspaces' unit tests, so
`agent-system-actors-check` now explicitly includes both in `clean-break-check`.
The recipe expansion was checked; its two underlying test commands passed
individually. The full composite release recipe has not been rerun. SDK
`cargo check --no-default-features` also passes after the lint-only edits
(`r16-sdk-no-std-final.log`).

The completed Agent architecture chapters are integrated on `saga/agents`. They are reviewed
as a stack of larger, single-theme chapters; `master` receives only the
completed clean cutover after the release gate passes.

Every range below is base-exclusive and head-inclusive. Review the chapters
in number order, targeting each numbered review branch at the preceding
chapter. The SHA ranges remain canonical even when a local review branch has
not yet been published.

For one chapter:

```bash
git log --reverse --oneline <base>..<head>
git diff --stat <base>..<head>
git diff --check <base>..<head>
git diff <base>..<head>
```

Private modules are not enabled by default. Every Private gate below
therefore names `--features private-agent-store` explicitly. System actors
and custom runtime examples are nested workspaces and are addressed through
their manifests.

## Review chapters

| Chapter | Local review branch | Range | Scope |
| ---: | --- | --- | --- |
| 01 | `review/agent-saga-01-runtime-pvm-foundation` | `eb81aa37..f114edfe` | 30 commits; 382 files; `+41832/-4393`. Standard-PVM Agent runtime model, typed packages, lifecycle and actor execution, authority receipts, PVM v0.8/conformance, Raft redirect boundary, and source-derived production pins. |
| 02 | `review/agent-saga-02-durable-system-agent` | `f114edfe..1bd25329` | 42 commits; 107 files; `+113972/-3181`. Authenticated journals and lanes, continuation proofs, invocation history, system authority/catalog, exact replay/finality, restartable publication, clean host boundary, and corrected pin. |
| 03 | `review/agent-saga-03-sdk-private-physical-host` | `1bd25329..1cd01638` | 73 commits; 140 files; `+77931/-6120`. Portable SDK and VOS3 packages, scheduling/continuations and storage proofs, encrypted Private storage/sync/backup, Shared Raft apply, physical VOS3/Private hosts, ingress, identity stores, and Agent network protocol. |
| 04 | `review/agent-saga-04-authority-operation-recovery` | `1cd01638..5945ee1d` | 42 commits; 78 files; `+59157/-3135`. System authority/catalog actors, offline Private recovery, Agent-only authoring and custom-runtime kit, AOC/AOP/AOI issuance and application, PCA, enrollment, catalog compaction, and mandatory Private-sync authority evidence. |
| 05 | `review/agent-saga-05-release-private-closure` | `5945ee1d..b667bfdb` | 26 commits; 60 files; `+16527/-12532`. Host identity and backup confidentiality, release/docs/examples, all Private controls, fail-closed authority-state publication, system-Agent bootstrap, recovery-key/PRA1 binding, exact PSE2 evidence, and staged PVRP3 publication/restart. |
| 06 | `review/agent-saga-06-private-runtime-bridge` | `b667bfdb..2c98b8c1` | 41 commits; 45 files; `+33749/-5068`. r12/r13 management authorization and resource policy, terminal Private capabilities, canonical runtime evidence and lineage, physical lifecycle/storage/sync application, authenticated import provenance, and crash-safe replica establishment from encrypted archives. |

These six ranges cover all 254 source commits through `2c98b8c1` exactly once.
Chapter 01 is intentionally generated-heavy: review its source and pin recipe,
then verify the derived vectors/artifact by identity rather than line-reviewing
generated bytes. Chapter 02 remains separate because it is already the largest
source chapter; combining it would make the review materially harder. Chapters
03 through 06 each retain a coherent physical-host, authority, or hardening
model while reducing endpoint overhead.

## Chapter invariants and gates

### 01 — Runtime and PVM foundation

Typed packages are the only admission path, invocation replay is exact, lane
separation is enforced, and lifecycle authority precedes mutation. ISA, gas,
and control-flow semantics match the official vectors; leader handoff
preserves the exact invocation; generated identities are source-derived.

```bash
cargo test -p vos --lib agent -- --test-threads=1
cargo test -p vos-pvm --lib
cargo test -p vosx
just test-pvm-vectors
just test-pvm-proof-fast
just verify-agent-runtime-release
```

### 02 — Durable system Agent

Append precedes publication, replay is idempotent, authority retirement cannot
outrun durable evidence, and catalog publication resumes from retained intent.

```bash
cargo test -p vos --lib agent::journal -- --test-threads=1
cargo test -p vos --lib agent::catalog_finality -- --test-threads=1
cargo test -p vos --lib agent::system_authority -- --test-threads=1
cargo test -p clerk-ledger --lib
just verify-agent-runtime-release
```

### 03 — SDK, Private storage, and physical hosts

Wire/package identities are canonical; transitions and storage descriptors are
signed; Private state stays ciphertext-only; continuation proofs bind exact
inner state; obsolete package generations fail closed. No unauthenticated
restore can publish; feature-gated tests reach the real Private host;
management retries are exact; snapshot retirement follows durable storage;
Node identity and network routes use full bindings.

```bash
cargo test -p vos-agent-sdk -- --test-threads=1
cargo test -p vos --lib --features private-agent-store agent::private_host -- --test-threads=1
cargo test -p vos --lib --features private-agent-store agent::private -- --test-threads=1
cargo test -p vos --lib agent::shared -- --test-threads=1
cargo test -p vos --lib agent::clean -- --test-threads=1
cargo test -p vos --test agent_runtime_pvm -- --test-threads=1
just check-no-std
just test-pvm-proof-fast
just verify-agent-runtime-release
```

### 04 — Authority operations and recovery

The actor selects authority; both recovery halves are required; history and
key lineage are exact; acknowledgements use reserved invocations; transport
identities are full-ID bound. Authoring exposes no service-era route, weak
authority keys fail, and custom runtimes obey the same package, ABI, and
scheduling contract. Authorization, issuance, and application use distinct
Linear invocations; AOI proves issuance rather than application; PCA binds the
exact applied control; actors consume only retained sources; enrollment and
PSE values cannot alias.

```bash
cargo test -p vos-agent-sdk --lib authority_operation -- --test-threads=1
cargo test --manifest-path actors/system-authority/Cargo.toml -- --test-threads=1
cargo test --manifest-path actors/system-catalog/Cargo.toml -- --test-threads=1
cargo test -p vos --lib agent::authority_operation -- --test-threads=1
cargo test -p vos --lib --features private-agent-store agent::private_control_application_coordinator -- --test-threads=1
cargo test -p vos --lib --features private-agent-store agent::private_sync -- --test-threads=1
cargo test -p vos-raft --lib
cargo test -p vosx
cargo test --manifest-path examples/agent-runtimes/custom-linear/Cargo.toml
just test-examples
```

### 05 — Release and Private recovery closure

Fresh and joined identity material is protected and bounded; backups contain
no plaintext; retired Service surfaces cannot re-enter the release; old proof
wires fail closed. Unpublished or unapplied controls never advance authority
state; old state generations fail; recovery binding is immutable; PRA1, PCTL,
and authority head are transitively exact; two valid PRA1 values for one PCTL
cannot mix.

```bash
cargo test -p vosx
cargo test -p vos-agent-sdk -- --test-threads=1
cargo test -p vos-agent-sdk --lib authority_operation -- --test-threads=1
cargo test --manifest-path actors/system-authority/Cargo.toml -- --test-threads=1
cargo test -p vos --lib --features private-agent-store agent::private_control_application_coordinator -- --test-threads=1
cargo test -p vos --lib --features private-agent-store agent::private_sync -- --test-threads=1
cargo test -p vos --lib --features private-agent-store agent::private_store -- --test-threads=1
cargo test -p vos --lib --features private-agent-store agent::private_host -- --test-threads=1
just test-examples
just package-production-release
rg -n '\b(JAM|JAR|Gray Paper|service[-_ ]runtime|Service)\b' --glob '!pvm/**' --glob '!target/**'
git diff --check
```

Any result from the terminology search requires an explicit platform or
migration-history allowlist entry; an empty exit status alone is not the gate.

### 06 — Management policy and the Private runtime bridge

Management admission is authorized against compact, resource-bounded plans;
denied capabilities retire without mutation; Private controls are applied only
with exact authority and runtime evidence. Store, runtime, lineage, and sync
commitments remain transitively bound across restart and object growth. A new
replica is published only after an authenticated encrypted archive is replayed
through a crash-safe plan whose exact retry and completion receipt bind the
origin, final store, and final runtime lineage.

```bash
cargo test -p vos-agent-sdk -- --test-threads=1
cargo test --manifest-path actors/system-authority/Cargo.toml -- --test-threads=1
cargo test -p vos --lib --features private-agent-store agent::private_control_application_coordinator -- --test-threads=1
cargo test -p vos --lib --features private-agent-store agent::private_runtime -- --test-threads=1
cargo test -p vos --lib --features private-agent-store agent::private_store -- --test-threads=1
cargo test -p vos --lib --features private-agent-store agent::private_sync -- --test-threads=1
cargo test -p vos --lib --features private-agent-store agent::private_host -- --test-threads=1
cargo test -p vos --lib --features private-agent-store replica_establishment -- --test-threads=1
cargo test -p vos --test agent_runtime_pvm -- --test-threads=1
cargo check -p vos --features private-agent-store --all-targets
just test-examples
just verify-agent-runtime-release
just build-agent-runtime-release
cargo fmt --all -- --check
git diff --check
```

## History and future chapters

Keep security fixes, protocol-generation bumps, and source-to-artifact repins
as visible commits inside their chapter. Mechanical fixups may be folded only
when their parent change already carries the complete review intent. Never
hide `0195696a`, `fa7a474a`, `e507b298`, `98e4bbc7`, or `87329648`, and never
hide a generated repin in a source commit.

The remaining review endpoints are intentionally limited to two larger,
scoped chapters:

1. Chapter 07: proof material, scheduling and custom runtime, supervisor and
   system projection, and ingress closure.
2. Chapter 08: backup/recovery closure, legacy deletion, serial reproducible
   artifacts, final docs/examples, and the production release gate.

Later work should extend one of those chapters when it completes the same
invariant; it should not create another reviewer endpoint. Keep internal
security fixes, protocol-generation bumps, and repins bisectable. Advance a
review branch only after its base and head are immutable, all named tests run
with a nonzero count, `git diff --check` is clean, and generated artifacts are
absent or isolated in their own reproducibility-reviewed commit.

### Chapter 08 first-start acceptance

The new-space UX belongs to the native startup batch in Chapter 08. It does
not introduce another review endpoint. Before advancing `saga/agents`, verify:

1. `space new` prepares the root-signed bundled runtime and system actor
   artifacts and writes `local.toml` with HTTP and SSH ingress enabled.
   Default listeners are `127.0.0.1:8080` and `127.0.0.1:2222`; operators can
   edit the addresses for multiple spaces or remote access.
2. The first `space up` automatically finishes durable system Agent,
   Authority, and Catalog installation before reporting readiness and
   serving ingress. Cached packages alone do not satisfy this requirement.
3. A subsequent restart reopens the same installed system actors without
   duplicate installation or manual bootstrap commands. Verify this and
   actual HTTP/SSH listener availability on a host that permits sockets.

Creating an arbitrary application Agent is a later user action on the running
space, not a required action of `space new` or `space up`. This distinction
does not waive the saga's existing Agent lifecycle or finality release gates.

Current checkpoint (2026-09-11): configuration and bundled-package compatibility
tests pass. Bootstrap now supplies Authority program/schema/policy blobs in
addition to installation data. Its internal admission path samples the trusted
clock for a new invocation and recovers exact authorization from the journal
on retry. Both crash-before/after-every-phase tests pass with an advancing
clock and no duplicate slots. The bootstrap suite excluding inventory passes
12 tests. The 152 vosx tests, six gas/budget tests, and the physical Refine
proof/replay regression also pass. The large inventory/release gates have not
been rerun here.

The original real-artifact failure was `Replay(Executor(RuntimeExit { reason: OutOfGas,
pc: 440679 }))`, surfaced by the host as `CorruptResidue`, during Catalog
authorization with a 2-billion outer allowance. The bounded outer-runtime
allowance is now 5 billion plus the actor's unchanged maximum of 1 billion;
bootstrap explicitly selects the actor cap, not the outer allowance. Fresh
physical bootstrap reached durable `Complete`, with Authority and Catalog
installed and finalized. Measured authorization/finalization executions used
about 1.78–1.80 billion outer gas. A development build without interpreter
optimization timed out during production-route reconciliation, after system
bootstrap completed. Development/test profiles now optimize the interpreter
without disabling debug assertions or changing guest artifacts or gas accounting.
The optimized recovery attempt also exceeded the roughly 12-minute smoke
limit during production reconciliation. It continued executing authenticated
queries/replay but never reported `Space daemon ready`; the harness stopped
its disposable daemon and retained the data. HTTP/SSH probes and the subsequent
normal restart were therefore not reached. This is not deployment readiness.

The release batch must include the changed host/proof gas allowance in its
reproducibility and compatibility review. A separate custom-runtime host test
also failed in `supervisor_invocation_material` with `CorruptResidue`, before
the new admission check; its opaque-runtime material lookup needs triage.

Retained disposable evidence in the native worktree:

- `target/task-tmp/native-admission-restart.log`: underlying runtime failure.
- `target/native-admission-smoke`: interrupted space, config and blob cache.
- `target/task-tmp/bootstrap-focused-suite.log`: 12 passing bootstrap tests.
- `target/task-tmp/bootstrap-restart-clock-test.log`: advancing-clock crash tests.
- `target/task-tmp/native-ready-first.log`: completed real system bootstrap;
  unoptimized production reconciliation timed out.
- `target/task-tmp/native-ready-recovered.log`: optimized recovery also timed
  out during reconciliation; no listener-readiness claim.
- `target/task-tmp/physical-proof-budget-test.log`: passing physical proof test.

Follow-up profiling identified unoptimized host BLAKE2 SIMD hashing as the
dominant CPU cost (three-minute profile retained at
`target/task-tmp/native-reconcile.perf`). Development/test profiles now optimize
`blake2b_simd`, retaining debug assertions and every authenticated read/check.
Eight hash cross-check tests pass. Reconciliation now schedules its next run
from completion, preventing slow queries from making the next run immediately
overdue; all three production-owner tests pass, including that regression.

With hashing optimized, the retained smoke reached a concrete `InvalidProjection`
instead of timing out. Diagnostics confirmed equal descriptors but two physical
actors versus one projected actor. This is the protected Authority actor:
Authority intentionally excludes itself from managed inventory. The system
bootstrap owner now adds its exact root-certified Authority install before the
ordinary full physical audit. It never derives this exception from an inventory
response or from whatever bytes happen to be installed. Inventory attempts to
claim Authority are rejected; physical package/install mismatches remain fatal.
No actor schema, package template, guest artifact, or admission limit changed.
The new positive/hostile root-pinning test passes, and the bootstrap suite
excluding inventory now passes 13 tests. Diagnostic evidence is retained in
`target/task-tmp/native-ready-projection-recovered.log`.

A fresh `native-first-ready-smoke` space completed automatic system installation
and the full route audit. Its first listener bind failed because the existing
IPFS daemon owns HTTP port 8080. Only the disposable space's `local.toml` was
changed to HTTP `127.0.0.1:18080`; SSH remained `127.0.0.1:2222`, and the IPFS
daemon was left untouched. Reopening that space reached `Space daemon ready`,
returned HTTP 401 for an unauthenticated request, and completed an SSH host-key
handshake. Its clean shutdown succeeded. This is listener/authentication-boundary
evidence, not an authenticated arbitrary-Agent lifecycle test. Development
startup still takes minutes; release/performance gates remain outstanding.
Evidence: `target/task-tmp/native-ready-root-first.log` (port collision),
`target/task-tmp/native-ready-root-ports-recovered.log` and sibling HTTP/SSH
probe files (successful readiness). The same-space restart also reached readiness,
returned HTTP 401, completed SSH key exchange with the identical host key, and
shut down successfully. Its bootstrap phase remained `Complete`; the restart
reopened the installed actors through the normal authenticated bootstrap/audit
path. Evidence is in `target/task-tmp/native-ready-root-ports-restart.log` and
its sibling probe files. The bounded lifecycle script exited zero, and neither
test listener remained afterward. The successful reopen took about 3m45s and
the normal restart about 5m18s in the development build, so this is not a
performance sign-off. All 152 vosx tests also pass on this checkpoint.

Keep the ordinary-Agent finality adapter, custom-runtime material lookup,
portable recovery crash closure, reproducible artifacts, and final release gates
in the existing three Chapter 08 batches. These startup fixes alone do not make
the complete saga deploy-ready or authorize advancing `saga/agents`/`master`.

### Chapter 08 opaque-runtime directory correction (isolated r15 work)

The verified r14 native-startup checkpoint remains `f212f278` on
`saga/ch08-c2-native`. The follow-up source correction is isolated on
`wip/ch08-runtime-directory`; this is internal work in the existing startup
and artifact batches, not another review endpoint. Do not deploy this worktree
until its system templates and first-start/restart gates have also been updated.

The physical custom-runtime host regression reproduced `CorruptResidue` because
Shared invocation preparation decoded Standard-private state to recover install
lineage. Custom runtimes own an opaque state representation. ABI
`vos-agent-runtime-abi-260911-r15` therefore adds a required nonzero immutable
`install_request` commitment to `ActorDirectoryRecord`. Standard projects its
retained original install commitment (not the upgradeable entry), and the
custom Linear example returns its original install commitment. Shared preparation
now executes the canonical read-only directory query and admits the exact signed
package/artifact closure without decoding Standard-private state. Supervisor
checks require the directory and prepared material to agree on lineage.

The control-schema pin and ABI-dependent golden commitments were regenerated.
Directory tests independently check the field's byte position, reject missing
or zero lineage, and reject the previous ABI. Verification on this source:

- 160 SDK tests pass.
- 28 supervisor-adapter tests pass.
- The formerly failing physical opaque-runtime management/material/reopen test
  passes and checks the returned install commitment.
- Standard actor-upgrade coverage checks that the directory reports the new
  deployment but retains the original install lineage, without mutating state.
- The maintained custom Linear example passes 10 normal tests. Its r15 guest
  artifact has now been rebuilt, and the explicitly selected compiled
  scheduling/attestation test passes for Local and Shared profiles. Both native
  and physical directory checks assert the original immutable install lineage.
- A newly built Standard-runtime ELF passed the current CLI physical ABI probe;
  its PVM passed the explicit physical create/install/exact-retry/directory test.

The candidate is 935415 bytes, ProgramId
`6bcc6da44743202942746bfede64db263bbca704fc11c6d2e8f783bfa55c1df0`.
Its ELF reproduced byte-for-byte from an independent immutable export of
`78434a4f2d213badf1769f8ba4ec5d251d617a0d`; the runtime blob and digest pins
are now updated in this isolated worktree. All four active bundled-runtime
integration tests pass (one explicit candidate test remains ignored by default).
This is not yet a complete release-artifact reproduction gate. Evidence lives
under the native worktree's disk-backed
`target/task-tmp/r15-*.log`; the candidate is
`target/task-tmp/r15-agent-runtime-candidate.pvm`, and its ELF is under
`target/r15-guest/riscv64em-vos/release/agent_runtime.elf`.

The Authority and Catalog templates now also reproduce byte-for-byte (both
raw PVM and signed VOS3 envelope) across two independent source-export paths.
Their committed blobs and build-time digests are updated. Provenance, including
the immutable source and builder revisions, is in
`support/production-artifacts.toml`. The public template-signing seed is not an
operator credential: new spaces re-sign these templates with their own root.
The template builder never loads or creates an operator identity and rejects
existing output paths; all three focused safety tests pass.

To reproduce templates, build `vosx` from the pinned builder revision using
the pinned host toolchain, export the pinned template source revision into a
fresh disk-backed directory, and create an empty `.git` directory in that
export as the canonical source-root marker. Then run:

```sh
vosx release build-system-templates --source SOURCE_EXPORT --out FRESH_OUTPUT
```

The builder selects the dated guest toolchain; set `TMPDIR` to disk-backed
storage. Compare both output `.vos` files against the manifest digests. Current
two-export evidence is in `target/task-tmp/r15-system-templates-{first,second}`
and the corresponding logs under the native worktree. Host-tool independent
reproduction remains a separate outstanding gate; package reproduction alone
does not close it.

The release bundle now exports the actual Authority and Catalog VOS3 templates,
not the retired root-authority PVM and linked registry renamed as system actors.
Format `VOS-AGENT-RELEASE-2` binds full package bytes and enclosed program IDs;
verification admits the packages, checks canonical runtime compatibility, and
rejects the old format and legacy programs. The top-level release build recipes
now invoke the Agent-only reproduction script, which builds the pinned builder
from an immutable export and compares runtime and complete system-package
bytes against the committed pins. Full reproduction and production gates must
still pass before release.
The Agent-only script's full `all` run now passes, including an independently
rebuilt pinned host tool, exact Authority/Catalog package comparisons, the
runtime ELF digest, the physical runtime ABI conversion probe, runtime ProgramId,
and committed PVM comparison. Evidence is in the native worktree's
`target/task-tmp/r15-immutable-release-reproduction.log`; immutable exports are
retained in this worktree's `target/agent-release-reproduction/run.xi2Xa1`.
This closes the source/tool reproduction gate for these three artifacts, not
the other release, recovery, custom-runtime, or deployment gates.
Verification: all 156 active vosx tests pass (one explicit candidate test is
ignored by default), including 18 release tests. The rebuilt CLI successfully
bundled and verified `target/task-tmp/r15-release-v2-smoke` under the native
worktree. This proves the release-directory cutover, not deployment readiness.

Fresh r15 space `r15-startup` reached ready on its first startup at
2026-09-12 07:08:09 UTC (about 2m16s after network startup). Its automatically
created config enabled both ingress types; only the disposable HTTP port was
changed from occupied 8080 to 18080. HTTP returned 401 without credentials and
SSH returned its host key. The smoke script then cleanly stopped the daemon and
started the same space again. Restart reached ready at 07:12:15 UTC (about
4m03s), passed HTTP 401 and SSH handshake again, and retained the same SSH key.
The smoke script exited successfully and both test listeners were absent
afterward; the existing IPFS listeners were untouched. Evidence is under this
worktree's `target/r15-startup.oEbkfJ`. This is a development-build correctness
check, not a startup-performance sign-off or an ordinary-Agent creation test.

The static clean-break/retained CLI check also passes. Inspection caught a
separate gate omission: `agent::clean_bootstrap::tests::physical` requires the
`pvm` feature, so the default-feature inventory command selected zero tests.
The clean-break recipe now explicitly enables `pvm`; the corrected large
inventory rotation test must pass before that gate is considered closed.
With that feature enabled, all 13 other bootstrap tests pass, including
physical restart before and after every bootstrap phase and root-pinned
Authority auditing (`r15-bootstrap-physical-suite.log` under the native
worktree's disk-backed task logs). `cargo check -p vos-agent-sdk
--no-default-features` also passes (`r15-sdk-no-std.log`). The separate large
inventory test has now passed: one selected test, 514 authenticated queries,
and suffix rotation past 1,024 entries. Its log is
`r15-inventory-rotation-physical.log`; elapsed test time was 11334.20s (about
3h09m), not a performance sign-off. This run predates recovery integration,
so the final combined release gate still needs to run against its frozen head.

Next: finish the corrected inventory regression, then rerun physical,
proof, bootstrap, and real first-start/restart gates before integrating this
work into the native startup branch. The old r14 CLI correctly rejects the r15
candidate ABI; use the current CLI or its explicit
`compiled_runtime_candidate_uses_current_abi` candidate test with
`VOS_AGENT_RUNTIME_ELF` and `VOS_AGENT_RUNTIME_CANDIDATE_OUT`.
The integration test
`compiled_runtime_directory_reports_exact_install_lineage_after_restart` uses
`VOS_AGENT_RUNTIME_PVM` and must be run explicitly with `--ignored`.
The existing ordinary-Agent finality, recovery crash-closure, and release gates
remain open. The Standard-specific management-disposition lookup used only for
classifying projection lag also remains to be audited for opaque runtimes;
successful material lookup alone does not prove every custom-runtime lifecycle.

### Chapter 08 portable restore-marker verification

On the isolated `wip/ch08-c1-portable-recovery` worktree, the physical
`singleton_system_agent_portable_backup_is_authenticated_fresh_and_restartable`
test passes with `--features pvm`. It covers authenticated fresh-store restore,
occupied-destination rejection, restart, and process loss with either the
canonical restore marker or its staged `.next` file. Both marker forms must be
retired after recovery, and subsequent reopen preserves the fresh store identity
and journal position. Ten temporary portable-recovery diagnostic prints were
removed without changing error propagation or validation order.

Evidence: native worktree `target/task-tmp/c1-portable-marker-staged-verification.log`
(one explicitly selected test, passed). This does not establish every cross-store
crash boundary or the Private recovery gates, and this older recovery worktree
still needs integration with the r15 native/artifact work before final release.

The same physical test now also passes two cross-store interruption cases:
`heads.next` durably staged before promotion, and heads promoted while the
Raft ledger is still at genesis. The previously unused stop hook now reaches
the actual file-store publication boundary. Assertions prove staged heads
existed and differed from committed heads, reopen promotes exactly those bytes,
the stage disappears, and journal position/snapshot/store identity survive
another reopen. Evidence is `c1-portable-heads-stage-verification.log` in the
same disk-backed log directory. The broader Private host suite is separately
running with `pvm,private-agent-store`; it is not yet signed off.

Integration checkpoint: the recovery source is now combined with the r15
native/artifact work on the internal runtime-directory branch. The only merge
conflict was this additive handoff document; both evidence sections are retained.
All 63 Private host tests passed on the recovery checkpoint with
`--features pvm,private-agent-store` (`c1-private-host-store-suite.log`, 318s).
Combined-source verification is required before considering these results
release evidence for the integrated tree. No review endpoint or master advanced.
The recovery checkpoint additionally passes 40 Private store tests, 21 Private
runtime tests, and 6 tests selected by `portable`, all with the same explicit
features. Evidence logs are `c1-private-store-suite.log`,
`c1-private-runtime-suite.log`, and `c1-portable-suite.log`. The integrated
portable run is tracked separately in `integrated-portable-suite.log`.
That integrated run passes all 6 selected tests. The integrated Private host,
store, and runtime suites also pass 63, 40, and 21 tests respectively; evidence
is in `integrated-private-{host,store,runtime}-suite.log`. The serial release
gate now invokes `agent-recovery-check` with `pvm,private-agent-store` explicitly,
so disabled Private modules cannot silently bypass these suites.

Ordinary-genesis integration remains functional work, not just a release flag:
`clean_startup.rs` still installs `UnavailableAgentFinality`. The canonical
`system_authority.rs` decision/QC and historical-provision verification logic
exists, but `verify_historical_provision` currently has only test callers. A
production adapter must bind a provision to authenticated live-system replay,
including reopen and historical committee evidence; accepting a provision's
self-consistency or a standalone membership proof is not an adequate substitute.

Integrated Shared host verification: 15 of 16 tests passed in the sandbox;
the network convergence test failed waiting for a local listening address.
That exact test then passed with socket access (1.22s), without code changes.
Evidence: `integrated-shared-host-suite.log` and
`integrated-merge-pump-network.log`. The full final serial gate must run in a
socket-capable environment; the sandboxed suite's exit status was not green.

The broader integrated library run (socket-capable, `pvm,private-agent-store`,
serial, excluding only the separately verified inventory test) completed with
1649 passed and 14 failed in 1754.83s. Full evidence and failure details are in
`integrated-vos-library-suite.log`. This is a failed release gate. Failures span
issuer hostile-tag offsets, driver preflight, journal/shared-commit golden
identities, three Local SDK host physical tests, three wire tests, and two node
authorization tests. In particular, restore accepted mutated exact install
requirements and accepted-invocation provenance; do not dismiss these as golden
fixture churn or weaken the rejection assertions.

The issuer hostile-tag test was corrected to locate its operation byte after
the encoded managed target (instead of stale offset 96); its exact rerun passes
in `integrated-issuer-hostile-offset.log`. The other 13 failures remain open.
Workspace formatting validation passed before this test-only correction.

### Standard original-install validation correction (source ahead of bundle)

Do not deploy the current source worktree with its existing runtime blob. The
source now retains `CompactInstallActor` in Standard's `SCI2` private-state
installation table, replacing `SCAI`. Restore recomputes the original SDK
lineage commitment and requires exact contract/requirements plus stable
installation and reservation identities. This preserves original facts across
upgrades without retaining constructor bytes. The runtime must be rebuilt,
independently reproduced, repinned, and physically retested before release.

The exact install-state regression passes, including substitution of both
requirement copies without changing the signed lineage and rejection of the old
state marker. Upgrade/restart and historical-retry wire tests also pass. Fixture
builders which synthesize initial installations now update their original plan;
production rejection checks were not relaxed. The oversized nested-authority
test now encodes the current prefix and reaches the intended length bound.

The latest wire suite result is 65 passed, 1 failed in
`install-plan-wire-verified.log`: accepted-invocation provenance is still an open
failure. That remaining failure, the other full-library failures, finality, and
opaque-runtime projection recovery are not waived by the install-state fix.

### Integrated fixture corrections after the install-state checkpoint

The two node authorization failures were outdated registry stubs: enrollment
now requires a full authenticated peer roster row, not a prefix-only role byte.
The fixtures now answer the real `members` probe, reject unexpected probes, and
also assert that a different peer cannot borrow enrollment for sync or blobs.
Production authorization was not changed. All 120 node tests pass with socket
access (`integrated-node-roster-socket-suite.log`); the sandbox run passed 119
and failed only the listener-bind test (`integrated-node-roster-suite.log`).

The driver historical-receipt fixture now explicitly supplies the two empty
clean actor tables required for an initialized runtime. Its exact regression
passes (`integrated-driver-preflight-fixture.log`). These three corrections
leave eight of the original 14 full-library failures unaddressed: accepted
invocation provenance, three physical Local SDK host tests, and four journal /
shared-commit identity expectations. The full library gate has not been rerun.

The release path remains: fix the remaining runtime and ordinary-genesis /
opaque-runtime recovery blockers; rebuild and reproduce matching artifacts;
run fresh-space startup/restart and final release gates; then fold the work
into the three scoped review batches. The integrated WIP is not ready to land
on master or deploy with the currently bundled runtime. No branch was pushed
or merged to `saga/agents` or master by these fixture corrections.

### r16 accepted-invocation provenance correction (source only)

The remaining wire restore failure was a real binding gap: retained accepted
metadata contained availability references, but the signed work hash included
their preimages, so restore could not reconstruct and compare the signed work.
The SDK invocation commitment now encodes every invocation field and the exact
ordered BlobRefs, omitting only preimages. Admission still validates each blob's
bytes against its reference. Standard reconstructs that same commitment from
retained metadata before accepting either receipt or PublicPreflight bindings
for continuations and terminal results. It does not retain caller-sized blobs
or prohibit legitimate signed actor origins.

This changes the clean protocol to `vos-agent-runtime-abi-260912-r16`, with
control schema `0dd3107d1168fb23f2c1e6be24a57146b6d858908f4ffd57622716d2ff767c3e`.
All runtime/system packages and protocol golden expectations must be regenerated
and checked for this ABI; old bundles have not been repinned or rebuilt here.

The final wire suite passes all 66 tests in 20.83s (`r16-wire-final.log`),
including forged origin/message/gas/reference rejection, terminal-result origin
rejection, and a correctly signed actor origin surviving restore. The SDK adds
a regression showing reference binding and independent preimage validation.
SDK tests currently pass 153 and fail 8 ABI-dependent golden-hash tests
(`r16-sdk-final.log`); this remains a failed gate, not a waiver or a completed
golden refresh. SDK no-default-features and workspace formatting checks pass.
Seven of the original full-library failures remain unaddressed, in addition to
these r16 pin updates, ordinary-agent finality, opaque-runtime recovery, and
the final artifact/physical/release gates. No deployment readiness is claimed.

### r16 SDK golden refresh

All 161 SDK tests now pass (`r16-sdk-pins-final.log`). Fifteen expected digest
arrays were refreshed for the r16 wire generation across authority operations,
catalog, proof publication, runtime public I/O, and invocation context. The
canonical decoding, bounds, domain separation, and tampering assertions remain
unchanged. A separate Python hashlib calculation agrees with the r16 control
schema and runtime-public-I/O fixture digest. No bundle was rebuilt or repinned.

Current journal and shared-commit reruns reproduce the four earlier identity
expectation failures: journal 35 passed / 3 failed (`r16-journal-tests.log`),
shared commit 5 passed / 1 failed (`r16-shared-commit-tests.log`). Their observed
hashes match those from the earlier r15 run; they are not new r16 regressions.
They remain open pending accounting for their underlying encoding changes, as
do the three physical Local SDK host failures and architectural release gaps.

### Journal and Shared commit fixture closure

The four remaining identity-expectation failures are corrected without changing
production encoders. Their fixtures contain BlobRefs, whose hash domain changed
from `vos/blob/service` to `vos/blob` in `4e7d974d`; their old expected hashes
predate that change. Journal pins also predated later runtime binding changes.
Both current-domain and retired-domain comparison hashes were refreshed;
predecessor wire rejection and domain inequality assertions remain intact.

All 38 journal tests pass (`journal-pins-final.log`), and all 6 shared-commit
tests pass (`shared-commit-pins-final.log`), including signature and quorum
validation. Formatting and diff checks pass. The three physical Local SDK host
failures are now the only unaddressed failures from the original broad library
run, but that whole run has not been repeated. r16 artifact rebuild/reproduction,
ordinary-agent finality, opaque-runtime recovery, and all final release gates
remain required; passing these fixture suites is not deployment readiness.

### Initial r16 artifacts and exact-retry host correction

Runtime and system templates were built from immutable source
`42f3f3bf2362e5189f094a1e39c7288e7a26eea7`, with the builder from that same
revision and the pinned guest/host toolchains. Candidate evidence is under
`target/r16-release.ziYI98`; scratch data stayed on disk. The committed blob
candidates and production manifest now name r16. The runtime passed the physical
ABI probe with ProgramId
`1152a50e0117033569ddf9e7a71869adb8650184a63e3473a8ab88c72254cb00`.
This was one build, not independent reproduction or startup signoff. The normal
CLI binary was built before the new blobs were staged and must be rebuilt.

Host preflight incorrectly checked the current time for an exact retained
management retry, although the guest recovers that result before current-expiry
checks. Retained history now carries its recorded acceptance slot; only exact
retries authenticate against that slot. Other receipts still use the current
window, and signature/request/runtime checks remain unchanged. This host-only
change is newer than the guest artifact source. The exact preflight regression
passes (`r16-retry-preflight.log`).

With the r16 runtime candidate, Local SDK host tests pass 9 and fail 1
(`r16-local-host-tests.log`): both expired-retry failures are resolved, while
`physical_resume_boundary_replays_persisted_fifo_continuations` still returns
`Driver(InvalidRuntime)` at the first resume. This is the last unaddressed
failure from the earlier full-library run, not the last release requirement.
Artifact reproduction, current-source CLI rebuild/startup, finality, opaque
recovery, and the complete release gates remain open.

### Ordinary resume host validation corrected

The remaining Local host failure was in the host's Yielded-response validator:
ordinary `resume_sdk` supplies no optional original InvocationWork, but the
validator required it even though ResumeWork carries the exact availability
fields needed for this check. It now compares the yielded installation-data
marker and required references with the actual Invoke/Resume input. Identity,
mode, increasing ready sequence, guest validation, and Standard preflight /
persisted-continuation verification are retained. This is a host-only fix;
the r16 guest artifacts do not need another rebuild for it.

All 10 Local SDK host tests pass (`r16-local-host-resume-final.log`, 28.40s).
The resume regression now reopens the host between both yielded slices and
rejects tampered availability before continuing to the exact terminal reply.
All originally observed library failures have targeted passing reruns, but
the complete integrated library gate has not yet been rerun.

Independent artifact reproduction is running via
`scripts/build-agent-release-artifacts.sh all`; evidence log is
`r16-independent-reproduction.log`, with fresh exports under
`target/agent-release-reproduction/run.TYpSBz`. The active command session is
60130 at this checkpoint; poll it rather than launching another reproduction.
Its completion is not yet claimed. Finality, opaque-runtime recovery, CLI /
fresh-space checks, and final full release gates still prevent landing.

### Independent r16 reproduction passed

The above reproduction completed successfully: runtime ELF, runtime PVM /
ProgramId, and both signed system templates match their pins and staged bytes
from independent immutable exports. `r16-independent-reproduction.log` ends
with `verified Agent-generation all artifacts from immutable sources`; session
60130 is terminal and must not be resumed or restarted for this checkpoint.

The first current-source CLI test build exposed three stale digest arrays in
`vosx/build.rs`. These have been updated to the independently reproduced r16
hashes; the digest checks themselves are unchanged. CLI tests now pass 156,
with one opt-in physical candidate test ignored (`r16-vosx-pins-tests.log`).
Normal CLI rebuilding and that explicit physical candidate test are tracked
separately; no fresh-space startup result is claimed by this test suite.

The normal current-source CLI rebuild completed (`r16-current-cli-build.log`).
Its real `release bundle` and `release verify` commands passed against
`target/r16-release.ziYI98/release-bundle`. The opt-in compiled-runtime candidate
test also passed (`r16-cli-physical-candidate.log`), and its emitted candidate
is byte-identical to the bundled runtime. Thus the ignored test above has a
separate successful explicit run. These checks do not substitute for daemon
startup/restart or ordinary-agent finality integration.

### Fresh r16 first-start and restart ingress evidence

The rebuilt CLI created a fresh isolated `r16-startup` space under
`target/r16-startup.jQHfbi`. Creation prepared the bundled packages and generated
HTTP/SSH-enabled `local.toml`. Only the disposable HTTP port was changed from
8080 (already occupied) to 18080; SSH used 2222. Scratch files remained on disk.

First startup reached `Space daemon ready` at 2026-09-12 22:03:30 UTC (about
78 seconds); restart reached readiness at 22:05:30 UTC (about 120 seconds).
Both returned HTTP 401 to the unauthenticated probe and completed the SSH
host-key handshake. The startup path installs/audits the clean system Agent
before publishing readiness. The script stopped both daemons cleanly; a
socket-capable `ss -ltn` check confirmed neither test ingress port remained
listening, while the pre-existing listeners were untouched.

The original smoke command exited 1 at its final byte-for-byte key-file
comparison: ssh-keyscan banner comments were interleaved differently, while
the actual ed25519 host-key record was identical. The corrected check requires
an actual ed25519 record in each file, filters comments, sorts key records, and
compares them; this check passed on the captured outputs. The disposable script
was corrected for subsequent runs. This is a verified startup/restart and key
persistence result, not a claim that the original script exited successfully.

This checkpoint supports isolated system-bootstrap/ingress testing. It does
not establish ordinary-agent creation/finality, opaque-runtime recovery, full
library/regression closure on this head, or production performance readiness.

### SDK documentation release check

The retained-CLI/negative-surface clean-break script passes on the r16 tree.
There is no generic `doc-check` recipe in this branch; an attempted invocation
was not a successful documentation gate. The new `agent-sdk-doc-check` recipe
builds the public SDK docs with no default features and treats broken intra-doc
links as errors. Its explicit run passes (`r16-sdk-doc-gate.log`), and
`clean-break-check` now invokes it. Scratch files use the disk-backed target
directory. This does not claim whole-book or external-link validation.

The broad library rerun remains active as session 11706, against source
`37d6a5720e7e45e4a19850a16a531e6cb316e299`, with `pvm,private-agent-store`, serial
execution, and socket access. Only the separately tracked long inventory test
is filtered. Evidence is `r16-integrated-library.log`; poll the existing session
before scheduling another run. No final result has been recorded yet.

### Portable SDK lint follow-up

Strict SDK linting (`cargo clippy -p vos-agent-sdk --all-targets
--no-default-features -- -D warnings`) initially reported three manual-contains
and three large-enum-variant errors. The equivalent `contains` checks replace
the three zero-ID searches; all 161 SDK tests still pass
(`r16-sdk-contains-tests.log`). Strict lint remains failed on the three enum
layout warnings (`r16-sdk-clippy-remaining.log`): AuthorityOperationIntent,
InvocationAuthorization, and PrivateRuntimeMutation. No warning suppression or
public allocation/layout change was made. These source-only cleanup edits are
newer than the pinned artifact source and the running full-library checkpoint;
final frozen-source artifact/gate verification remains required.

The three SDK enum layout warnings now have scoped `expect` attributes with
explicit allocation/API rationale. Inline representation is intentionally
preserved: boxing public variants would change constructors and add guest
allocation paths solely for lint. Two regression tests guard inline growth
(authorization <= 1 KiB; intent and Private mutation <= 2 KiB); they are not
wire limits, heap bounds, or performance signoff. Strict all-target/no-default-
features SDK clippy passes (`r16-sdk-clippy-final.log`), and all 163 SDK tests
pass (`r16-sdk-layout-tests.log`). No runtime representation or canonical wire
change was made by the attributes/tests. The integrated library run has passed
the coordinator capacity test and advanced into issuer tests; it remains live
as session 11706, not a completed gate.

### Exact management result carried through replay publication

The full integrated library run described above subsequently completed with
1,663 passing tests; see the current closeout section for its exact source and
excluded test. No test process from that run remains active.

The opaque-runtime recovery work now preserves the exact decoded SDK management
result across the executor/replay boundary, rather than reducing it to a boolean
and discarding the reply. `ReplayExecutor::clean_management_transition_result`
defaults to no evidence; replay rejects missing results and mismatched
success/failure dispositions. Validated `ReplayStep` and publication execution
results retain the reply independently of runtime-private state. The Local
management path now reads its freshly published result from those execution
facts, while retaining the bounded cache for the existing retry/transport paths.

All 53 replay tests pass (`r16-replay-management-result-suite.log`), including
new missing-result/disposition-mismatch coverage and exact opaque-runtime upgrade
and retry publication results. An initial exact-name command selected zero
tests and is not verification evidence. These are host-side changes: no SDK
wire generation or guest artifact was changed.

The combined final rerun passes all **63 replay and Local SDK host tests**,
with no failures, ignored tests or selected tests filtered internally
(`r16-management-publication-final.log`, 14.36s; 1,602 unrelated library tests
were filtered). This includes physical lifecycle, exact retry and restart paths
using the publication-carried management reply. Formatting and diff checks pass.

This is the first part of C1's opaque-runtime closure, not completion: the exact
reply still needs request/receipt-bound host evidence in replay materialization,
canonical checkpoint authentication, pruning/reopen recovery, and consumption
by the Shared/Local projection audits. Do not replace those audits with the
volatile cache or treat publication result accessors as durable checkpoint proof.

### Host-owned management evidence in AJC4 checkpoints

`CleanManagementEvidence` now binds the latest state-changing portable management
input and its Ordered position to the signed receipt commitment, replay request
commitment, epoch/sequence, observed slot and exact decoded result. Replay
materialization carries it through both Local and Shared publication and
checkpoint construction. State/runtime-preserving retries keep the original
mutation evidence, so an older retry cannot replace it or change its clock.

The canonical checkpoint is now **AJC4**, with checkpoint identity domain
`vos/agent/journal/checkpoint/v4`; AJC3, AJC2 and AGJC are rejected. Clean-genesis
checkpoint reopen requires the evidence. Its fields and bounded canonical SDK
reply are included in the checkpoint identity (and therefore an authenticated
Shared checkpoint claim), not an unbound sidecar. The two checkpoint digest
fixtures were refreshed for the new format/domain, preserving predecessor
rejection and domain-separation checks. This is a host checkpoint generation
change, not an SDK ABI bump; committed guest blobs were not replaced.

Shared projection-lag recovery now obtains its disposition from authenticated
replay/checkpoint evidence without decoding Standard private state. The common
comparator still uses the legacy-named disposition value type; this change does
not claim that all Standard-state dependencies in the Local image host are gone.

Verification: **199 passed, zero failed** in
`r16-checkpoint-management-final.log` (40.05s; journal, journal store, replay,
Local SDK host, and physical custom-runtime Shared host selection). The initial
run failed only the expected checkpoint identity fixtures before their update.
A strengthened physical-state-independent regression separately passed in
`r16-checkpoint-management-pruned-source.log`: after another exact retry advances
the fence, GC actually removes the original mutation's Ordered entry, and a
fresh executor with an empty management-result cache reopens the same exact
evidence from the checkpoint. The Shared physical test also verifies the exact
installation receipt/request/result before and after reopen.
The affected CLI clean-space selection also passes **31/31**
(`r16-checkpoint-management-cli.log`); formatting and diff checks pass. These
test builds did not replace the preserved r14 normal CLI binary.

Still required: physical Shared checkpoint certificate/snapshot import and
tampering coverage for the new evidence, production Local opaque recovery,
ordinary-Agent finality, and final frozen-source release gates. Earlier startup
and artifact reproduction evidence is not a final AJC4 daemon smoke result.

### Physical Shared management-evidence snapshot verification

The custom-runtime physical host regression now creates and installs an actual
quorum-certified snapshot after actor installation, completes bounded physical
compaction, and closes the host. It resolves exactly the certified AJC4 file
and independently substitutes five validly encoded variants: receipt commitment,
request commitment, sequence, result, and removal of the evidence. Each changes
the checkpoint identity and prevents cold host reopen under the original
certificate. Restoring the original file restores normal cold reopen with the
exact management disposition and actor material; the subsequent runtime work
still succeeds.

For each variant the test also rewrites the certificate's checkpoint reference
to the substituted identity while retaining its signatures. The altered
certificate decodes canonically, but signature verification against its own
altered claim fails. This exercises content-address substitution and signature
binding separately; it is not a claim of cross-store portable import coverage.
The final selection passes **8/8 tests**, with no failures or ignored tests
(`r16-shared-management-certificate-final.log`, 5.44s): the physical opaque
snapshot regression, cross-store/node/generation certificate isolation, and
all six Shared commit tests. Formatting and diff checks pass. No guest blobs,
runtime ABI, or production source paths were changed by this test checkpoint.

The remaining Local issue is broader than only checkpoint metadata:
`LocalAgentHost` uses the image-backed `AgentDriver`, whose clean Create and
management paths require exact equality with a natively reconstructed Standard
transition. Descriptor and physical-material recovery also decode Standard
private state. The transitional Local journal's opaque-runtime tests do not
prove that production image-backed host supports an opaque runtime. Closing
that production boundary remains required; removing its guards without replacing
their authenticated public-state invariants is not a valid fix.

### Portable evidence and post-snapshot projection checks

The final focused run passes **3/3 tests**
(`r16-portable-management-and-projection.log`, 7.71s), covering:

- The physical singleton-system portable backup path preserves the exact
  management evidence in a different physical store, on subsequent reopen,
  and through all four existing interrupted-restore boundaries (canonical
  marker, staged marker, staged heads, and promoted heads before Raft recovery).
  This fixture uses the Standard-shaped system runtime and the existing
  root-authorized singleton backup protocol.
- The opaque-runtime journal test exports after the original mutation entry
  has actually been collected, initializes a distinct store with its required
  genesis runtime artifact, imports the portable closure, and restores the
  exact evidence and opaque state with an empty executor result cache. Its
  first new import attempt exposed a missing genesis artifact in the test
  setup; adding that required bootstrap artifact fixed the fixture, without
  weakening import checks.
- After certified snapshot/compaction and reopen, the physical custom-runtime
  Shared host's actual projection comparator recognizes the one-installation
  acknowledgement gap and rejects an authority head whose sequence predates
  the installation. It does so without interpreting Standard private state.

These are complementary boundary tests, not a newly supported portable backup
protocol for ordinary or multi-replica Shared Agents. That existing explicit
restriction remains unchanged. Formatting and diff checks pass; this checkpoint
adds tests and a test-only evidence accessor, not production behavior or guest
artifact changes. Production Local custom-runtime support and ordinary-Agent
finality remain implementation work, followed by the final release gates.

### Production Local public directory inspection

`AgentDriver::inspect_sdk_actor_directory` now reads bounded canonical SDK
directory pages from one immutable image through the physical runtime. It
checks the supplied descriptor against the image's public configuration and
runtime identity, fixes the observation slot for the whole scan, rejects
state changes in every lane, bounds page/cumulative counts and cursor progress,
and rejects non-directory outcomes. Local exact-projection actor counting and
one-ack-lag actor enumeration now use this interface instead of interpreting
the Standard actor table. Exact physical-material and management-disposition
checks remain in place.

**11/11 tests pass** (`r16-local-public-directory-final.log`, 8.22s): all ten
Local SDK host tests plus a physical scripted-PVM regression which accepts an
opaque state image and rejects changes to each of its four lanes and a
non-directory management result. The lifecycle/restart test compares the query
to the canonical management page and verifies the stored image is unchanged.
The scripted test deliberately constructs the post-admission driver directly;
it does not prove production custom-runtime Create/reopen. Formatting and diff
checks pass; guest artifacts and SDK ABI are unchanged.

The Local work is still incomplete: descriptor persistence/reopen, physical
actor-material loading, management history, and Standard transition-oracle
comparisons remain private-layout dependencies. The module overview now states
that limitation instead of incorrectly claiming this driver never decodes
runtime internals. Continue replacing those dependencies with authenticated
public metadata and runtime ABI checks; do not simply remove their validation.

### Local physical actor material from the public directory

The production image-backed driver's actor-material loader now resolves the
actor record, immutable install-plan commitment, installation ID and reservation
through the public directory query instead of constructing a native Standard
runtime to inspect its internal actor/installation tables. Runtime package
admission and program-byte identity, signed actor package admission, schema,
policy, installation-data references, runtime capability checks and suspended
actor refusal remain enforced. The producer comes from the verified signed
actor package and is still compared with authority projection during route
validation.

The existing material-recovery test now uses the bundled physical runtime
instead of a scripted stub that could not answer inspection queries. It is
explicitly PVM-gated and verifies immutable installation lineage, package
producer, exact reopen, missing artifacts and substituted process/runtime/policy
bytes. **36/36 driver and Local SDK host tests pass**
(`r16-local-public-material-final.log`, 8.95s); formatting and diff checks pass.

This removes the private actor-table lookup, not every private-state dependency:
the descriptor is still recovered from Standard state before material loading,
and image reopen, management history and transition-oracle comparisons still
need closure. Guest artifacts, ABI and deployment-readiness claims are unchanged.

### Local public descriptor persistence

The image-backed Local driver now persists the canonical SDK descriptor as
bounded public metadata, atomically with configuration and all runtime state
lanes. The new **AGI2** envelope validates the descriptor, its exact configuration
projection and runtime program identity without decoding guest-private state.
Local descriptor reads and physical material lookup use this metadata; public
directory inspection additionally requires the exact stored descriptor.
Management commits update the descriptor together with the state. Old AGIM
images are deliberately rejected; there is no in-place migration.

The storage regression round-trips opaque state through the image codec and
store, and rejects missing metadata, changed configuration, mismatched runtime
identity and the predecessor envelope. The driver/Local/wire run passed
**103/103** (`r16-local-descriptor-image-final.log`, 25.40s). After adding the
exact directory metadata binding, driver and Local host tests passed **37/37**
(`r16-local-descriptor-binding-final.log`, 10.04s); clean-space CLI tests passed
**31/31** (`r16-local-descriptor-cli.log`, 0.43s).
The final **37/37** rerun (`r16-local-descriptor-commit.log`, 9.04s) also
covers refusal of directory inspection without stored metadata. Descriptor-only
changes now trigger a commit as well. Formatting and diff checks pass.

This is storage-format closure, not production opaque-runtime lifecycle
support. Reopen deliberately retains the Standard-state descriptor consistency
check. Create, management history, acknowledgement/invocation validation and
transition-oracle comparisons still need runtime-independent replacements;
removing the existing checks alone would weaken admission. Ordinary-Agent
finality also remains open. The current CLI smoke predates AGI2 and AJC4 and
must be repeated on fresh disposable data after the implementation is complete.

### Local descriptor transitions from public management inputs

Local management now derives its next persisted descriptor from the authorized
SDK request and validated reply rather than decoding the returned Standard
state. Runtime upgrades replace only their selected runtime fields; replica
changes require the exact predecessor generation. Other supported operations
leave the descriptor unchanged. Denials and authenticated retained retries
preserve current metadata, including when a retained upgrade or roster-change
reply predates a newer deployment or roster. Immutable identity substitutions,
wrong reply shapes and invalid descriptors fail closed. The existing exact
Standard transition comparison remains enforced as a separate safety boundary.

All **38/38 driver and Local host tests pass**
(`r16-local-descriptor-transition-final.log`), including physical Local
lifecycle/restart tests and the new public-metadata transition regression.
The first run's new fixture was rejected because its replica list was unsorted;
the fixture now preserves canonical ordering, without weakening validation.
Formatting and diff checks pass. No guest artifact or wire-format change is
introduced in this checkpoint.

Next Local recovery work remains durable management history: exact retained
results, acknowledged-through and decision/epoch high-water marks, and original
observation slots must be host-owned and atomically persisted. A latest-receipt
cache alone cannot replace that history. Standard Create/reopen and runtime
transition checks must then be replaced with public authenticated invariants,
with an opaque runtime tested through the production host lifecycle. Neither
that implementation work nor ordinary-Agent finality is closed by these tests.

### Local management history component

`local_management` now defines a bounded host-owned history and strict LMH1
codec without any private runtime-state decoding. Its retained records include
the complete receipt and request commitments, epoch, decision sequence,
original observation slot and exact SDK result. The latest retained record
preserves the decision/epoch high-water marks; acknowledgement pruning never
leaves an empty history with a nonzero acknowledged frontier.

The transition operation explicitly requires prior independent authentication
and guest-result validation. It rejects changed state or a changed result on
an exact retry, preserves failed unconsumed admissions, refuses consumed
sequences that mutate state, and enforces bounded retention and canonical
clocks. Empty/opaque guest bytes are never interpreted. Codec checks reject
oversized counts before allocating record storage and bound individual results.

The two component regressions pass (`r16-local-management-history.log`, 0.20s):
codec round-trip, late retries, skipped/acknowledged sequences, invalid
acknowledgements, exact-result substitution, full-journal refusal and legitimate
acknowledgement headroom, duplicate commitments and noncanonical clocks.
The combined driver, Local host and history run passes **40/40**
(`r16-local-management-history-final.log`, 8.71s). Formatting and diff checks pass.

This component is not yet wired into `AgentImage` or `manage_sdk`; it does not
close production recovery. Next, persist it atomically with clean Local images,
derive it from verified Create/management transitions, preserve it through
state-only commits, and use it for retry classification and Local projection
comparison. Reopen must reject missing or inconsistent history. Then exercise
those paths through the physical host before removing any remaining Standard
validation boundary. No image format, guest artifact or deployment-readiness
claim changes in this checkpoint.

### Atomic Local management history integration

The **AGI3** image now stores descriptor, bounded LMH1 management history and
all runtime lanes atomically. Verified Create initializes the history;
management advances it from the independently checked request/transition,
including state-changing denials. Invocation/acknowledgement and other
state-only commits preserve it. Clean images without nonempty, canonical
history in the descriptor's authority epoch range are rejected. AGIM and AGI2
predecessors are rejected with no migration.

Production Local retry classification now uses persisted public history rather
than decoding Standard state. The Local one-ack-ahead projection comparator
likewise obtains its exact disposition from that history. Reopen retains an
explicit comparison of every retained record and acknowledgement/epoch/decision
frontier against Standard state until runtime-independent lifecycle validation
is complete; no permissive fallback or history reconstruction is used there.
The old private-state retry helper survives only as a test fixture adapter.

**107/107 history, driver, Local-host and wire tests pass**
(`r16-local-management-image-final.log`, 29.10s). A new physical Create/reopen
regression persists a canonically encoded substituted request commitment,
confirms cold reopen refuses it, restores the original history and confirms
reopen succeeds again. Opaque image codec tests reject missing/empty history
and both predecessor formats. Existing physical lifecycle, expired retries,
staged-create reconciliation and FIFO resume tests pass. Initial compilation
found three test-only module paths needing another `super`; these were fixed
before the passing run. Formatting and diff checks pass.
Clean-space CLI checks also pass **31/31**
(`r16-local-management-image-cli.log`, 0.21s).

This closes persistence and production consumption of Local management
history, not general custom-runtime Create/reopen. The remaining Local work is
replacing Standard admission/transition/reopen checks with authenticated public
invariants, then proving an opaque runtime's full production lifecycle.
Ordinary-Agent finality and final-source release/smoke gates remain open.

### Production Local opaque-runtime management lifecycle

Image-backed Local Create, management and reopen now distinguish the bundled
Standard runtime's additional native parity checks from the public validation
required for every admitted runtime. Custom-runtime state is no longer sent
through the Standard decoder/oracle at those boundaries. Signed receipt and
exact package admission, typed reply binding, persisted descriptor/history,
state bounds, exact retry consistency and management lane isolation remain
mandatory. As in the Local file-store model, the private host-owned image is
the durable metadata authority; its hashes alone are not an external finality
proof. Reopen re-admits the exact signed package/program and catalog closure.

Create now also runs bounded public actor-directory inspection **before**
writing the package or image and requires an empty, state-preserving directory.
That prevents a runtime from publishing preinstalled actors through the Create
reply. The same bounded scanner serves later physical directory queries.

A new physical scripted-PVM regression uses the real `LocalAgentHost` and file
store, not a manually constructed driver or the transitional journal host.
It rejects a forged Create receipt without publishing an Agent, creates an
opaque-state Agent, durably records a management denial, cold-reopens, and
recovers both expired management and original Create receipts without changing
the persisted revision/state/history. Native decoding of its stored state is
explicitly shown to fail. **42/42 driver, Local-host and history tests pass**
(`r16-local-opaque-lifecycle-final.log`, 10.28s); clean-space CLI tests pass
**31/31** (`r16-local-opaque-lifecycle-cli.log`, 0.17s). Formatting and diff
checks pass. Existing Standard parity and substituted-history refusal remain
covered. No guest artifact or wire format is changed by this checkpoint.

This proves production opaque management Create/reopen/retry, not the complete
custom actor lifecycle. Next prove signed actor installation, invocation and
continuation/acknowledgement recovery through this same host, and reconcile
management lane-transition rules with the public ABI for initialization and
migration. Ordinary-Agent finality and the final release gates remain open;
the branch is not yet master-ready.

### Local and journal management lane parity

The image-backed Local path previously rejected every non-Control management
change, including legitimate actor initialization and migration which journal
replay already permitted. Both paths now use one public lane-boundary helper:
successful installation/actor upgrade may change declared requirement lanes,
runtime upgrade may change declared capability lanes, and successful removal
may clear retired actor state. Signed request admission, runtime validation,
typed replies and exact-history checks remain separate mandatory gates; a lane
mask alone is not authorization. Denials may consume authority in Control but
cannot change actor lanes, and inspection preserves all four lanes exactly.

The new regression checks all eight lane masks against each actor lane for
installation, actor upgrade and runtime upgrade, plus denied transitions and
read-only Control mutation. **160/160 driver, Local host, replay and wire tests
pass** (`r16-management-lane-parity.log`, 33.02s), including opaque Local
Create/reopen, checkpoint/replay and the existing exact retry tests. Formatting
and diff checks pass. This removes a concrete Local initialization/migration
restriction; it does not replace the still-required signed custom actor
installation/invocation/continuation lifecycle test or the final release gates.
The physical Shared custom-runtime management/snapshot/reopen regression also
passes **1/1** (`r16-management-lane-shared-physical.log`, 1.27s), exercising
the other production consumer of the common lane rule.

### Opaque Local actor installation and continuation recovery

The production Local opaque-runtime fixture now installs a real signed actor
package and initializes its declared Linear lane. It resolves the actor through
the public directory and verifies recovered program bytes, installation ID,
reservation, incarnation and immutable install-plan lineage. It then yields an
invocation, cold-reopens the file-backed host, refuses a resume with missing
required preimages without changing the image, and completes the exact resume.
A second reopen recovers the actor material and retries the expired install,
original invocation and completed resume without changing the terminal image.

**42/42 driver, Local host and management-history tests pass**
(`r16-local-opaque-actor-resume.log`). The initial installation/invocation-only
version also passed independently (`r16-local-opaque-actor-final.log`, 0.21s).
Formatting and diff checks pass. This checkpoint changes tests, not production
behavior or guest artifacts.

This is a physical scripted-PVM **host ABI/persistence** regression: the actor
package and immutable closure are genuinely admitted, but the custom runtime's
responses are scripted, not proof that it executes the actor's program. It
does not cover positive acknowledgement retirement or target-runtime migration
execution. Those lifecycle edges and application-runtime execution evidence
remain to be closed, alongside ordinary-Agent finality and final release gates.

### Native lifecycle integration audit

After the Local actor recovery regression, the native startup path was traced
again rather than treating library coverage as deployment evidence:

- `vosx/src/commands/space/clean_startup.rs::start_clean_system_agent` creates
  the root bootstrap owner and calls `VosNode::start_clean_agent_production`.
  Its ordinary-Agent `UnavailableAgentFinality` still returns `Unavailable`.
- `vos/src/node.rs::start_clean_agent_production` constructs the system route
  attachment and production owner. It does not open/create a Local host or
  provision ordinary Agents. Separate Local/Shared attachment APIs exist, but
  no call from the examined `vosx` space startup path supplies an ordinary Local
  attachment.
- `RouteHostCommand` in `supervisor_adapters.rs` supports invocation, resume,
  acknowledgement, material preparation and authority projection/reconciliation;
  it has no lifecycle Create/Install command. An attachment for already-created
  physical Agents is not a provisioning workflow.
- `AgentGenesisFinalityVerifier` requires independently authenticated live
  system-Agent history. The older `verify_historical_provision` helper's only
  current call sites are tests, and its documentation explicitly denies that
  validation alone is a sealing capability. It cannot safely replace the
  unavailable verifier by itself.

The separate `CleanSystemAgentControl` is read-only, but it is **not** the
startup attachment used above; its existence is not evidence that all current
ingress dispatch is read-only. The actual supervisor routes already support
actor invocation.

This audit changes the next implementation priority: C2 must connect a durable,
authenticated ordinary lifecycle workflow to the native owner and finality
source. Its acceptance test must start from the same native entry point as
`space up`, create an ordinary Agent, install an admitted actor, invoke it,
restart, and repeat exact retries while preserving authority and physical
state. Keep the existing C1/C2/C3 review grouping. The remaining work is not
merely final tests or artifact repinning, and the branch is not master-ready.

### Local durable application observation for native coordination

`LocalAgentHost::observe_management_application` now provides the physical
observation needed before the existing durable issuer signs an application
acknowledgement. It rereads the private image, requires exact agreement with
the live descriptor/image, finds the exact retained receipt/request result,
reverifies the signed receipt at its original observation slot, and reopens
the admitted runtime/program and actor catalog. Reopen includes normal catalog
reconciliation. Missing artifacts or divergent durable state cannot be replaced
by an in-memory success value.

The host alone constructs `LocalManagementObservation`. It carries the exact
receipt/result, original application slot and a domain-separated commitment to
the complete AGI3 image. The issuer's crate-private Local entry point accepts
this observation and forwards successful results to its existing durable
acknowledgement pledge/sign/retirement machinery; denials are not signed as
successful applications. An observation is a Local storage fact, not system-
Agent finality or route-publication authority.

**21/21 Local host, management-history and clean-issuer tests pass**
(`r16-local-application-observation-final.log`, 13.48s). The physical opaque
fixture checks exact application result/receipt, forged-receipt refusal,
original slot preservation on a later retry, and a changed commitment after
subsequent invocation state. The substituted-history fixture now also verifies
that an already-open host refuses an out-of-band durable image change before
any observation escapes. Existing issuer pledge and recovery tests remain
green; the new Local issuer entry is not yet exercised by a complete native
authorization-to-finalization workflow. Formatting and diff checks pass.

Next connect that native workflow: persist the exact authorized intent, drive
physical application, obtain this observation once, durably pledge its MAA2,
finalize it through the authenticated system authority and publish/reconcile
routes. Retrying after a later image must recover the already-pledged
acknowledgement rather than silently sign a different state commitment. The
Local observation component does not itself complete native provisioning or
ordinary-Agent finality.

### Recover original application acknowledgements before observing newer state

The durable clean issuer now exposes a crate-private recovery operation for an
exact issued receipt. It returns no acknowledgement only when that receipt is
known but has no application pledge. Unknown/substituted receipts are refused.
A pending pledge is signed using its stored image commitment and application
slot; an already signed MAA2 is recovered without consulting the signer. Both
paths reuse the existing exact result/decision validation and crash-safe commit
machinery, rather than rebuilding evidence from today's Agent state.

The Local observation entry point attempts this recovery before pledging a new
observation. Thus a retry after subsequent invocation state cannot silently
replace the already-pledged image commitment. A changed application result is
still rejected, and authority-actor finalization remains mandatory before the
next management decision can be issued. No wire format or artifact changes.

The issuer regressions now exercise recovery before any pledge, rejection of an
unissued receipt, recovery after a failed signer, exact result substitution,
restart with an unavailable signer, and an ambiguous completed storage commit
without resigning. This supports the forthcoming native lifecycle coordinator;
it does not connect native Create/Install or provide ordinary-Agent finality by
itself.
**19/19 clean-issuer and Local-host tests pass**
(`r16-local-ack-recovery-final.log`, 14.54s); formatting and diff checks pass.

### Durable native management intent component

`clean_management_intent` now retains the complete canonical management request
and signed credential call before the future coordinator invokes authority
policy or allocates a receipt. CMI1 bounds both nested frames, binds the call's
authorization plan to the exact request, and checks complete Create target and
authority fields. Construction verifies the credential signature against
independently selected authority/managed routes. Recovery must explicitly
reverify those routes and signature; decoding stored bytes is not authorization.

The dedicated single-writer intent slot uses the existing atomic whole-image
storage contract, but must have a separate physical image from the issuer. An
identical retry is read-only; a different operation conflicts. Any commit error
poisons the instance because the write may already be durable, so recovery
requires reopening the actual store rather than trusting old process state.

**8/8 issuer and intent tests pass** (`r16-management-intent.log`, 3.83s).
The new regression covers canonical round-trip, wrong-route and forged-call
refusal, a write that becomes durable before returning an error, poisoned
in-process retry, exact recovery on reopen, and conflicting-intent refusal
without changing the stored image. Formatting and diff checks pass.

This is the coordinator's pending-input component, not native provisioning.
It intentionally does not claim policy approval, issue a receipt, clear a
completed workflow or publish routes. Next connect its persisted input to the
authenticated authority dispatcher and existing durable issuer/application
observation/finalization stages, including completion and restart handling.
No guest artifact or existing store format is changed by this checkpoint.

### Persisted intent to durable issuance

The intent slot now feeds its stored request and signed credential call into
the existing issuer, after rechecking independently selected routes and the
credential signature. Missing or poisoned intent, mismatched approval and
wrong managed routes are rejected before signing or changing the issuer image.
The caller must supply the configured authority actor's authenticated, durably
applied result; this crate-private adapter does not authenticate actor execution
merely because an approval decodes or matches the call.

The regression reopens both independent stores after signer failure, recovers
the exact receipt, then reopens again and retrieves that receipt without an
available signer. It also checks that an ambiguous intent write cannot issue
through the poisoned live slot. This remains component-level evidence, not a
native authority-dispatch or provisioning test.

**9/9 issuer and intent tests pass** (`r16-intent-issuance-final.log`, 3.59s),
using locked offline dependencies and disk-backed scratch space. Formatting
and diff checks pass. Existing compiler warnings remain; this is not a full
library or release-gate rerun.

The next integration milestone remains one real native ordinary-Agent Create:
durably retain its input, invoke the installed Authority actor, issue and apply
the receipt, reopen the physical result, finalize its acknowledgement through
that actor, and publish its route with independently verified finality. Only
after that path works should Install/invoke/restart acceptance and final release
gates be claimed. No new review batch, guest artifact or store format is added.

### Local target-runtime compatibility before cutover

`AgentDriver::manage_sdk` now physically executes the admitted target runtime's
bounded public directory query against the proposed migrated image before an
UpgradeRuntime commit. The query must preserve all four state lanes and return
exactly the existing actor installation records, including incarnation and
installation lineage. The old runtime's successful upgrade reply alone no
longer causes publication of a target that cannot interpret that image.
Probe errors roll back only newly staged artifacts; the prior image, runtime
selection, descriptor and receipt history remain unchanged. Ambiguous errors
from the subsequent atomic image commit still retain staged artifacts for
recovery, as before.

The existing physical opaque-runtime lifecycle fixture now upgrades through
the actual Local host after actor installation, invocation, yield/resume and
restart. A compatible target commits one revision and resolves the same actor
from its signed catalog after cold reopen. Seven incompatible targets mutate
one of the four lanes, omit the actor, substitute its incarnation, or reject
inspection. Every refusal checks the unchanged live and on-disk image, removal
of the newly staged target package/program, and successful reopen of the old
runtime and actor material.

**43/43 driver, Local-host and management-history tests pass**
(`r16-runtime-migration-regression-final.log`, 12.04s), with locked offline
dependencies and disk-backed scratch space. Formatting and diff checks pass.
An intermediate test-only compile failed on two incorrectly qualified legacy
types; both were corrected before this final run. This evidence covers target
directory compatibility, not execution of migrated actor code or exact receipt
retry through the new runtime. No guest artifact or store format changes.

The native authority-dispatch trace also confirms that its restartable path
must persist the exact prepared invocation and PublicPreflight (including the
original observation slot) before dispatch. Rebuilding that envelope from
current material on retry would change its authorization commitment. Existing
projection-query recovery is not a management authorization/finalization
adapter; native lifecycle integration and ordinary-Agent finality remain open.

### Native management authorization dispatch adapter

The pending intent now uses **CMI2**, retaining the exact prepared Authority
invocation and PublicPreflight as well as the request and credential call.
Decoding binds the envelope to that call's target, invocation, principal,
credential, message and Linear method mode, with no ambient role grants or
runtime state. All nested frames are bounded. CMI1 is rejected rather than
silently reconstructing missing invocation evidence. An identical input retry
preserves its prepared envelope; a different envelope, including a changed
observation slot, conflicts. An ambiguous envelope write poisons the live slot
until a real reopen.

`CleanSystemAgentBootstrapOwner::issue_management_intent` now connects those
stores to the native owner's installed Authority route. It independently
selects the pinned Authority target, verifies the signed input, loads the exact
physical actor/artifact closure, checks the installed public Linear policy,
persists the envelope before dispatch, and submits it through the authenticated
terminal invocation path. Only an exact completed approval reaches the durable
issuer. Recovery rechecks current physical identity/artifacts while reusing
the original persisted preflight. A pending projection conflicts explicitly.

The new tests cover invalid envelope substitutions, an ambiguous completed
write, poisoned retry, recovery without another write, changed-slot refusal,
and predecessor-format rejection. A native-owner test installs the existing
projection-only fixture and confirms that a signed management call cannot
bypass its missing `authorize` policy: no prepared envelope, invocation,
issuer write or signature is produced. The initial test compile missed a
local ServiceWire import; it was corrected before the passing runs.

**39/39 issuer, native-boundary and supervisor-adapter tests pass**
(`r16-native-intent-adapters-final.log`, 5.24s), using locked offline
dependencies and disk-backed scratch space. Formatting and diff checks pass.

This is an internal adapter, **not yet called by the running native lifecycle
entry point**. Positive dispatch with the bundled Authority actor still needs
an integration test. Result retirement, journal-capacity reservation across
authorization/application/finalization, denial handling, host attachment and
route publication remain to be connected before enabling it. The adapter
deliberately leaves the authorization result retained and does not claim
ordinary-Agent finality. No guest artifact was rebuilt in this checkpoint.

### Bundled Authority Create authorization and issuer-size fix

The positive native-owner dispatch test now executes the bundled Authority
PVM, retaining its executable/schema/policy bytes and re-signing only the
package for the fixture's issuer identity. It submits a signed ordinary Local
Agent Create call through `issue_management_intent`, obtains the real actor's
approval and a durable signed receipt, then reopens the separate intent and
issuer stores and retries after expiry. The exact original envelope and
receipt are recovered without another signature or ordered journal entry.

This test exposed a production issuer defect: its 1,024-byte internal decision
limit rejected a valid approved Create carrying both the complete creation
authority binding and the authenticated application context. The limit is now
1,536 bytes; a codec matrix exercises all optional evidence and lane-root
fields with and without the Create binding, round-trips those frames, and
rejects oversized input. The complete issuer image remains bounded at 512 KiB.
The field encoding and CIS2 magic are unchanged. A dev-only `system-authority`
dependency supplies the exact constructor configuration codec; the lockfile
change adds only that dependency edge.

Initial integration attempts also caught two fixture errors: the enrollment
signature must name the founding owner, and the ordinary replica roster must
name the enrolled node owner rather than copying the system bootstrap's
separate transport-principal pin. These were corrected without bypassing
Authority validation. Temporary diagnostics were removed.

**41/41 issuer, native dispatch and supervisor-adapter tests pass**
(`r16-bundled-authority-dispatch-regression-final.log`, 8.43s), including the
expired retry at slot 40 for a receipt expiring at slot 30. The final run uses
locked offline dependencies and disk-backed scratch space. Formatting and
diff checks pass.

Scope of evidence: the Authority actor itself executes as PVM, while this
native-owner fixture uses the existing test-only native Standard outer runtime
and seeds a completed bootstrap predecessor. The intent/issuer stores are
reopened, not the whole owner/transport. This does not prove fresh production
bootstrap, an all-PVM outer-runtime restart, physical application of the newly
authorized Create, finalization, route publication or native ingress wiring.
Those remain required, alongside the existing journal-capacity and lifecycle
completion work. No guest artifact was rebuilt or repinned here.

### Native Local Create and application acknowledgement

`CleanSystemAgentBootstrapOwner::create_local_from_management_intent` now
connects authorization/issuance to physical Local creation and durable
application acknowledgement. It rejects non-Create/non-Local input, checks
the host's Space/node and the sole replica, and verifies the admitted runtime
package against the requested descriptor before dispatch. After creation it
uses `observe_management_application`, which reloads the image and re-admits
its runtime/catalog, before asking the issuer to sign application evidence.
It does not finalize the Authority effect or publish a route; the enclosing
lifecycle coordinator must retain exclusive ownership through those phases.

The bundled-Authority regression now uses the actual bundled runtime PVM for
the ordinary Local Agent. It tests runtime-package mismatch refusal, successful
Create through the owner adapter, cold Local-host reopen, exact Created
observation and signed application acknowledgement, then reopens the intent,
issuer and Local host and retries at slot 40 after expiry at slot 30. The image
commitment, receipt and acknowledgement remain exact, with only two signatures
total (receipt and application ack) and no extra Authority journal entry.
The system fixture still uses its native Standard outer-runtime shortcut and
seeded bootstrap predecessor; this does not prove an all-PVM system restart.

**26/26 issuer, native creation and Local-host tests pass**
(`r16-native-local-create-coordinator-final.log`, 22.10s), using locked offline
dependencies and disk-backed scratch space. Formatting and diff checks pass.
An initial test compile used `program` instead of the runtime manifest's
`outer_program` field; it was corrected before the passing runs.

Next connect durable Authority finalization and receipt/result retirement,
journal-capacity reservation, native host attachment and route publication.
The CLI/ingress management entry point and independent ordinary-Agent finality
are still incomplete. No artifact or store format changed in this checkpoint.

### Native Authority finalization and exact recovery

The owner now finalizes the exact signed application acknowledgement retained
by the durable issuer. It checks the installed Authority identity and method
policy, dispatches the bundled actor, and requires an exact successful terminal
reply. Before marking the issuer finalized, a fresh replay executor materializes
the durable Shared journal, reconciles its ledger/checkpoint and compares its
heads, state and exact terminal result with the live host. This is independent
of the live executor's result cache, not a whole-process cold reopen or an
ordinary-Agent genesis-finality implementation. Missing/pruned results and
histories needing an unavailable attested replay provider fail closed.

Pending intents now use **CMI3**, rejecting CMI1/CMI2 without migration. They
retain separate authorization and finalization envelopes. Finalization needs
a current preflight slot for its first acceptance, even when the application
receipt is an expired exact retry. An initial test using the application slot
correctly failed with `AuthorityExpired`; the fix persists the current
finalization envelope before dispatch and reuses it on retries, without weakening
runtime clock checks. Prepared-but-not-accepted work still needs the lifecycle
reservation/recovery design; this change does not solve that boundary.

**13/13 issuer and native management tests pass** in 14.35s:
`r16-native-management-finalization-recovery.log` under the shared disk-backed
`target/task-tmp`. Coverage includes substituted signed-ack refusal before
dispatch, canonical envelope reopen, ambiguous completed intent writes with
poisoned-handle refusal, changed-slot retry conflict, and recovery with the
issuer's pre-finalization image after the actor has committed. The latter
advances the clock again and proves exact replay without another journal entry
or signature. Already-finalized issuer reopen is also a no-op. As before, the
system fixture uses the native Standard outer-runtime shortcut; the Authority
actor and ordinary Local runtime execute their bundled PVM programs.

Next: result/receipt retirement and safe intent completion, joint lifecycle
capacity reservation, native management entry-point/host attachment and route
publication, and independent ordinary-Agent finality. Then run final-source
release gates and fresh-data startup before advancing integration branches.
No artifact was rebuilt or repinned. This remains an internal C2 checkpoint,
not a fourth review batch or a deployment-readiness claim.

### Local migrated execution and expired upgrade recovery

The opaque-runtime Local regression now reopens after runtime cutover, invokes
the installed actor through the target PVM, observes its new Linear state and
one image revision, and reopens again at slot 100. Replaying the upgrade receipt
(expired at slot 71) returns the exact historical identity without reverting
the post-upgrade state, descriptor or image revision. Replaying the migrated
invocation also leaves the image byte-identical. The seven invalid target
directory/lane variants continue to reject cutover without changing disk state.

**13/13 Local-host tests pass** in 10.39s, using locked offline dependencies and
disk-backed scratch space (`r16-migrated-runtime-retry-final.log`). The initial
extension correctly trapped on upgrade retry because the scripted target had
no management-retry handler; adding that fixture handler resolved it without a
production-code change. These PVM scripts exercise host ABI, persistence and
retry validation, not general actor bytecode semantics inside an arbitrary
runtime. Positive acknowledgement retirement for opaque Local runtimes remains
open, as do the native lifecycle/finality/publication and release gates above.

Do not clear native lifecycle intents or retire their finalization evidence
merely because the issuer marker exists: independent ordinary-Agent finality
and publication still need durable evidence. That completion ordering must be
resolved in C2. This test-only checkpoint remains part of C1; no new review batch,
artifact repin or integration-branch move is introduced.

### Native wiring dependency audit after `8e73c140`

Current source distinguishes two completion paths; the unavailable ordinary
genesis verifier is not a reason to stall all native Local wiring:

- `LocalAgentHost::open` authenticates AGI3 images, runtime/catalog and scope.
  `LocalAgentRouteBackend` admits invocation against physical material, while
  `AgentProductionOwner::reconcile` authenticates the Authority descriptor and
  actor inventory before publication. This path does not consume
  `AgentGenesisProvision` or its verifier.
- Journal-backed ordinary admission requires `AgentGenesisProvision`: a full
  proposal, replica committee, claim-specific quorum certificate and immutable
  decision. The clean actor's `LatestManagementAckRow` is instead the newest
  credential acknowledgement; it does not certify that genesis claim and is
  replaced by later management work. `ManagedAgentRow` holds mutable current
  metadata, not a permanent genesis decision. Neither is a drop-in replacement
  for `UnavailableAgentFinality`. The older
  `SystemAuthorityState::verify_historical_provision` explicitly validates data,
  not a replay-derived sealing capability.
- `start_clean_agent_production` moves the system owner into its route worker.
  That worker has no lifecycle management command. Attaching an empty Local
  host earlier is not sufficient: `reconcile_slot` retires a pending attachment
  when both its authenticated projection and identities are empty. A separate
  lifecycle owner/command boundary must retain exclusive Local-host ownership
  through Create/application/finalization, then hand it to route publication.
  Later Install must coordinate that ownership with the already running worker;
  opening a second writer is not an acceptable shortcut.

Next implementation should establish that native lifecycle command/ownership
boundary and durable per-agent intent/issuer stores, then connect the tested
Create/finalize adapters and authenticated publication. Shared genesis claim
publication, independent verification and restart remain explicit required work,
not waived by a successful Local path. This audit did not modify production
code, rerun release gates, or establish deployment readiness.

### Native lifecycle file stores

`CleanManagementLifecycleFiles` now provides a dedicated per-agent directory
with independent `management.intent` and `management.issuer` images under one
shared exclusive writer lease. It reuses the existing exact-file persistence
implementation: private directories/files, no alias or hard-link acceptance,
role-bound integrity envelopes, predecessor-bound staging, atomic publication
and directory synchronization. New envelope roles 5/6 distinguish these files
from bootstrap roles 1–4. Separate directory allowlists reject bootstrap files
inside lifecycle storage and vice versa; existing bootstrap envelopes are
unchanged.

The intent storage limit is exported from the host library and reused by CMI3
and the physical store, without exposing the private intent codec or granting
issuance authority. The enclosing coordinator must still verify configured
Space/Agent bindings when opening signed intent and issuer images. File-envelope
integrity alone is not identity authorization.

**28/28 native file-store tests pass**, including both new lifecycle tests, in
0.38s (`r16-lifecycle-file-stores.log`, locked/offline `vosx` test binary, disk
scratch). Coverage includes independently preserved issuer bytes during staged
intent recovery, shared lock lifetime after dropping one handle, payload bounds,
cross-role swaps and incompatible directory namespaces. These tests use opaque
payload bytes; they do not yet exercise a native lifecycle command with CMI3/CIS2.
The stores are implemented but not wired to startup or management ingress. No
guest artifact was rebuilt, and the three review batches are unchanged.

### Public Local creation coordinator

`CleanSystemAgentBootstrapOwner::create_local_agent` now composes the existing
Create lifecycle behind a public native-call boundary. It accepts independent
intent/issuer stores, the signed credential call and descriptor, an admitted
runtime, an exclusively owned Local host and receipt signer. Before pledging
anything it checks host/replica/runtime scope and the signed call. It opens both
stores with the expected binding, pledges CMI3, executes authorization and
issuance, creates/reopens the physical Local image, signs the durable application
acknowledgement and finalizes through independently replayed Authority execution.
Errors preserve pending evidence; callers reopen the same stores to recover.

**14/14 issuer and native management tests pass** in 25.23s
(`r16-local-coordinator-final.log`, locked/offline `pvm,private-agent-store`,
disk scratch). The new complete-coordinator case rejects a forged call before
intent/issuer writes, journal changes or signing, then creates and finalizes a
valid Local Agent. Reopening the Local host and both stores after expiry returns
the exact result with no additional Authority entry and still two signatures.
It shares the existing actual bundled Authority/Local-runtime PVM fixture; the
system outer runtime remains the test-only native shortcut. Stores in this test
are in-memory durable-image fixtures, not the CLI file-store implementation.

This gives native callers an implemented coordinator instead of exposing private
intent/approval internals. It does not yet add a route-worker management command,
connect the CLI file stores, publish routes, retire evidence or implement joint
capacity reservation. Those steps, Install on a running Local host, Shared
genesis finality and final release gates remain required.

### Serialized Local lifecycle/route ownership

The Local route adapter can now share the lifecycle owner's existing
`Arc<Mutex<LocalAgentHost>>` through a crate-private attachment constructor.
There is still one physical host and one filesystem writer lease. Route
inventory, preparation, projection checks and invocation/resume/acknowledgement
all take the same mutex; invocation admission and execution stay in one critical
section. The existing public constructor keeps its move-owned behavior by
creating the shared holder internally. No public management permission or
wire command was added.

This resolves the empty-route retirement ownership issue identified above:
retiring a route worker drops its reference, while the lifecycle coordinator
can retain the host lease and later attach a worker again. Poisoned access is
unavailable rather than recovered implicitly. The lifecycle owner must release
the mutex before waiting for any Local route-worker operation or retirement;
otherwise it would deadlock with an in-flight route waiting for that mutex.

The physical Local-host regression checks serialized route inventory, lease
retention after worker retirement, reattachment, poisoned-lock refusal and
successful disk reopen only after the final owner is dropped. Native lifecycle
commands, system-owner access, file-store wiring and route publication are still
unconnected; this is the ownership prerequisite, not a completed native path.

**42/42 Local-host and supervisor-adapter tests pass** in 11.78s
(`r16-local-shared-owner-final.log`, locked/offline `pvm,private-agent-store`,
disk scratch). Formatting and diff checks pass. No guest artifact or persisted
format changed in this checkpoint.

### Shared system-owner access for native coordination

The system route backend now supports a crate-private shared attachment to the
existing `Arc<Mutex<CleanSystemAgentBootstrapOwner<...>>>`. Every worker operation
locks that owner, including Authority projection/recovery and physical invocation
preparation. The existing public move-owned attachment constructor remains
available and creates the holder internally. No second Shared network owner or
physical host is constructed.

The complete Local creation coordinator regression now runs while a system route
worker is attached to that same owner. A separate test checks serialization,
worker retirement followed by reattachment without losing the owner, and poisoned
owner refusal. **30/30 native coordinator/system-owner and supervisor-adapter
tests pass** in 10.13s (`r16-system-shared-owner-final.log`, locked/offline
`pvm,private-agent-store`, disk scratch). An initial compile needed a mutable
guard for projection audit; that was fixed before the passing run. Formatting
and diff checks pass.

Future lifecycle/route integration must release owner locks before waiting on
route-worker calls, and shutdown must join lifecycle work and drop its retained
references before expecting network and physical leases to disappear. Native
startup still uses the move-owned constructor; it does not yet retain or expose
the shared coordinator. The command interface, CLI file-store connection,
publication, completion/reservations and Shared finality remain required.

### Local lifecycle controller and native store factory

`LocalLifecycleController` now owns the shared system and Local hosts, the
receipt signer and a `LocalLifecycleStoreFactory`. It supplies route attachments
using the same physical owners, and its Create method locks system then Local,
checks scope/runtime and the signed intent before opening stores, then calls
the tested durable Create/application/finalization coordinator. The controller
retains the Local writer lease when an empty route worker is retired. It does
not wait on a route worker while holding either owner lock.

The `vosx` factory implements that interface with the existing lifecycle files.
It accepts a configured private parent and Space, pins the opened parent
directory, derives each child from the canonical hexadecimal Agent ID, rejects
wrong-Space/zero-Agent calls and rechecks the parent identity before and after
opening the child. The parent must already exist; startup directory creation and
controller retention are not yet wired. Signed image bindings, not the parent
path or integrity envelope, establish lifecycle authority.

**4/4 native coordinator/controller tests pass** in 25.56s
(`r16-local-lifecycle-controller.log`) and **29/29 CLI file-store tests pass** in
0.10s (`r16-local-lifecycle-factory.log`). The controller test runs with both
workers attached, refuses a forged call without opening stores, verifies issuer
finalization, retires/reattaches the Local worker and repeats Create after expiry.
The file factory test checks Space refusal before directory creation, derived
paths, exclusive locking and independent image recovery. Commands were locked,
offline and used disk-backed scratch. These remain separate controller and
file-store tests, not an end-to-end daemon/ingress acceptance test.

Next connect controller lifetime/shutdown to `VosNode`, construct it from native
startup with this file factory, expose bounded signed lifecycle commands, and
drive authenticated publication. Install/completion/capacity recovery, Shared
genesis finality and final release gates remain open. No artifact repin or
integration-branch move was performed.

### Node-owned lifecycle lifetime and creation API

`VosNode::start_clean_local_agent_production` now consumes the controller into
the production owner through a crate-private, Send-only lifecycle interface.
It rejects duplicate/shutdown admission before starting attachments. Production
construction checks the configured node, attaches both physical owners before
the initial authenticated reconciliation, and exposes the supervisor only after
that reconciliation succeeds. Existing system-only startup still delegates to
the same construction logic without a lifecycle controller.

`VosNode::create_clean_local_agent` now calls the retained controller, attaches
the Local worker again if empty-route reconciliation retired it, and performs
authenticated reconciliation after creation/finalization. A publication failure
is not an application rollback: the exact signed request and durable stores are
retained for retry. No host mutex is held while waiting on reconciliation.
Production shutdown joins pending and published workers before dropping the
retained lifecycle controller and its physical/network owners.

**33/33 controller, production-owner and supervisor-adapter tests pass** in
10.63s (`r16-node-local-lifecycle-final.log`, locked/offline
`pvm,private-agent-store`, disk scratch). The new native node test rejects
post-shutdown startup before authentication/store access, exposes no supervisor,
and verifies that the Local root can reopen after the consumed controller is
dropped. Positive lifecycle execution remains the attached-controller test;
successful node startup/Create with live authenticated inventory has not yet
been demonstrated by this suite.

At this checkpoint the CLI still called system-only startup; the native wiring
checkpoint below supersedes that limitation. Positive node Create/publication
with complete system-actor state and a bounded ingress command remain required. Remaining
Install, completion/reservations, Shared finality and release gates are unchanged.

### Native startup retains Local lifecycle coordination

`vosx space up` now creates or exactly reopens the dedicated `local-agent-host`
root, opens `local-agent-lifecycle` with the hardened store factory, and passes
the controller to node-owned Local production startup. Existing paths are opened,
not recreated or silently repaired; symlink/partial-root rejection stays with
the physical host. This provisions an empty Local host, not arbitrary Agents.
The system actors still complete their existing bootstrap before production
publication.

An explicitly owned Ed25519 operator signer is retained for future lifecycle
calls. It uses the existing signer validation and signing implementation, without
loading or serializing secret keys. The lifecycle factory can now create its
private parent with directory-relative filesystem operations and sync both new
directory and parent. **36/36 signer and file-store tests pass** in 0.32s
(`r16-native-local-startup.log`). The current-worktree CLI build passes
(`r16-native-local-cli-build.log`, 39.97s), preserving the older shared-cache
`target/debug/vosx`. No guest program/package was rebuilt or repinned.

A fresh disposable smoke space is under `target/native-local-smoke.DATNas`,
using HTTP 18081 and SSH 2223. First start reported ready at
2026-09-13 02:15:47 UTC (about 77 seconds), with HTTP 401 and an SSH host-key
handshake. This exercises current-source native startup and the Local controller
with the real bundled system runtime/actors; it does not exercise ordinary-Agent
Create or Install through ingress.

Restart also passed, reporting ready at 2026-09-13 02:17:47 UTC (about 118
seconds). The complete smoke script exited successfully: both starts returned
HTTP 401 and completed SSH handshakes, the canonical SSH host-key lines matched,
and both dedicated Local directories were present. Both daemon processes stopped
after their checks. This establishes current-source positive native startup and
restart with the retained controller, but not ordinary-Agent Create/publication
or management ingress. The compiled CLI remains an unpromoted test candidate;
the final reproducible-artifact and release gates are still open.

### Bounded ingress-to-node Local lifecycle queue

`IngressHandle::create_clean_local_agent` now accepts structurally bounded
descriptor/call data and an admitted runtime, then returns a separate result
receiver. The queue opens only after Local production startup succeeds, holds
at most four pending requests (plus one executing), and is closed during node
shutdown. The router loop processes at most one lifecycle request per pass
through the existing node Create API; it does not hold the queue lock during
authorization, physical application or authenticated reconciliation.

Queue acceptance is neither authorization nor success. The controller still
verifies the signed call before opening stores. Disconnect does not cancel an
accepted durable lifecycle operation, and a post-application failure still needs
the same signed retry. Shutdown refuses queued requests and prevents later
submission; a request already executing may have committed and must not be
reported as rolled back. Ingress handlers must await the result outside the node
router thread. HTTP/SSH request decoding and CLI command submission are not yet
connected to this API.

The queue regression uses the existing native lifecycle fixture to check closed
admission, capacity refusal, exact queued descriptor/call delivery, slot reuse
after dequeue, response routing, shutdown replies and refusal after close. It is
a transport-boundary test, not an ordinary-Agent creation test through HTTP/SSH.
The CLI smoke at `ee047d48` predates this queue change; no new CLI build or daemon
smoke has been claimed for the queue checkpoint.

**34/34 queue/controller/node-boundary, production-owner and supervisor-adapter
tests pass** in 11.94s (`r16-local-lifecycle-queue-final.log`, locked/offline
`pvm,private-agent-store`, disk scratch). Formatting and diff checks pass.

### Signed Local Create HTTP submission

The exact `POST /__agents/local` path now accepts `application/octet-stream`
LCQ1: magic followed by three u32-length-prefixed canonical values (AMRQ Create,
ACC3 credential call, exact VOS3 runtime package). The public
`LocalCreateSubmission` codec checks bounds, canonical decoding, the credential
signature, request/target binding and admitted runtime identity. This is request
validation, not authorization: the configured live Authority still approves the
operation before receipt issuance. HTTP rejects transport-node claims and uses
the signed body instead of the older bearer-authentication route. ACC3 does not
enforce an API credential-kind restriction. All other application paths retain
their existing bearer gate.

The endpoint keeps the 1 MiB body cap and bounded blocking worker pool. It
waits outside the node router for at most 120 seconds and returns a canonical
MAA2 acknowledgement with HTTP 201 only after node lifecycle success. Queue
pressure/unavailability returns 503; an unknown timeout/disconnect outcome
returns 504. A failure after application is not rollback: retain and retry the
identical signed submission. Request decoding neither installs an arbitrary
actor nor auto-creates an ordinary Agent during startup.

Coverage includes actual bundled-runtime signed-frame round trips, forged
signatures, runtime substitution, truncation/trailing bytes, HTTP method/query/
content-type/body rejection, and socket dispatch of the reserved endpoint while
adjacent paths remain bearer-protected. The first combined fixture run overflowed
the debug test stack; extracting the codec assertions into a separate helper
resolved it without raising the stack limit.

**48/48 focused lifecycle and ingress tests pass** in 12.36s with explicit
`pvm,private-agent-store,http-ingress`, locked/offline and disk-backed scratch
(`r16-local-create-http-final.log`). Formatting and diff checks pass. This is
not a final-source full-library or release-gate run.

No rebuilt CLI or successful HTTP Create/publication smoke is claimed here.
The existing CLI smoke still refers to `ee047d48`. Next: construct and retain an
exact signed submission from the native CLI, prove HTTP Create/publication plus
restart/retry, then wire Install and prove invocation. Durable retirement,
capacity/recovery boundaries, ordinary Shared-Agent finality and final release
gates remain open. This checkpoint belongs inside C2, not a fourth review batch.

### Native operator Local Create preparation

`vosx` now has an internal `local_create::prepare` boundary that constructs ACC3
from an explicit operator key, Authority target, Local descriptor, admitted
runtime, nonzero credential sequence and validity window. It derives the exact
invocation identity, signs the complete call, omits transport-node claims, and
passes the result through the host LCQ1 verifier. This founding-operator helper
requires the operator to own the new Agent; it is not a general delegated
credential/owner API. It reads no keys or clock and creates no nonce or files.

**8/8 Local Create preparation and identity tests pass** in 0.20s
(`r16-local-create-preparation-final.log`, locked/offline `vosx` binary tests,
disk scratch). With the actual bundled runtime, repeated exact inputs produce
identical HTTP-sized signed frames; changed sequences change invocation identity.
Wrong owner, Authority space, validity ordering and runtime package are rejected.
Formatting and diff checks pass.

### Shared native identity derivation for fresh Local Create

Native startup and `local_create::prepare_fresh` now share
`derive_system_authority_target`. The extraction preserves the existing
creation-nonce, Agent-ID and policy-binding domains and inputs. It requires the
admitted runtime and Authority package to be signed by the configured root and
checks their runtime compatibility. This is expected immutable identity
derivation, not evidence that a remote daemon currently uses those pins.

Fresh preparation constructs an operator-owned single-node Local descriptor
using the bundled runtime and only the node's public Ed25519 key. Its replica
principal is the enrolled owner, its Node ID uses the full authenticated-peer
derivation, and its transition producer binds that public key. Root/node key
reuse is rejected. Nonce, sequence and validity remain explicit inputs; the
helper does not load transport secrets, read live stores or allocate a sequence.

The SDK credential projection already exposes `management_request_high_water`,
but a clean HTTP query path and credential-wide local reservation are still
needed for fresh command wiring. The legacy bearer gate must not be treated as
a clean Authority projection. Follow that with the real native Create/restart
smoke; the previous startup smoke predates this source refactor.

**All `vosx` binary tests pass: 168 passed, zero failed, one ignored**, in 3.54s
(`r16-local-create-fresh-identity-final.log`, locked/offline, serial with socket
access and disk scratch). New checks cover deterministic fresh preparation,
the original identity hash formulas, owner/node/producer binding, wrong-root
packages, zero Space and root/node reuse. The ignored compiled-runtime candidate
test remains a release gate. Formatting and diff checks pass.

### Clean signed credential-query ingress

`POST /__agents/credential` now accepts a canonical binary Authority projection
query signed by an API credential. The native ingress boundary restricts the
selector to that credential's own projection and verifies the API signature
before worker dispatch. It does not use the older bearer-authentication route.
The configured system owner checks the Authority target and the live actor
checks credential enrollment/status; the returned projection must echo the
exact signed query. Revoked status remains data for the caller to reject before
preparing a mutation, not implicit authorization to create an Agent.

The system-worker query handle is exposed atomically with the clean supervisor
only after authenticated startup, and the shared exposure is cleared on
shutdown. Requests use the existing bounded HTTP worker pool and system-worker
queue, with a 120-second result wait. A timeout does not cancel a queued query.
Projection execution has durable host recovery state despite its query
semantics: after an ambiguous outcome, retry the identical signed query.

**50/50 focused ingress, production-owner and native shutdown-boundary tests
pass** in 2.67s (`r16-credential-query-ingress-final.log`, locked/offline
`pvm,private-agent-store,http-ingress`, serial with socket access, disk scratch).
New checks cover signed admission while unavailable, forged signatures,
broader-selector refusal and socket routing of the reserved path while adjacent
paths remain bearer-protected. An initial compile caught placement in the
connection task; it was corrected to the bounded request worker before this
passing run. Formatting and diff checks pass.

This is not yet a successful live credential-query smoke. CLI query transport,
exact query retention, response validation and credential-wide sequence
reservation remain to be wired before fresh Create. The projection response is
not an independent signed finality proof. No new native CLI build, artifact
reproduction or master-readiness claim is made here.

### Checked credential discovery client

`local_create::query_credential` accepts already chosen canonical query bytes,
verifies their API signature and Credential selector before network dispatch,
then uses the same bounded loopback-only binary HTTP transport as Local Create
submission. The caller is still responsible for durably retaining those bytes
before dispatch; the helper does not generate a new nonce on retry.

Response validation requires the exact echoed query and expected Principal,
active status and API kind, and checks `management_request_high_water + 1`
without overflow. Operation/admin high-water marks cannot influence the chosen
management sequence. API kind is a client preparation restriction, not a new
claim about ACC3's actor-side credential-kind rules. This result remains an
unsigned discovery hint, not a credential-wide reservation or finality proof.
The subsequent exact mutation must still be authorized by the live Authority.

**All `vosx` binary tests pass: 169 passed, zero failed, one ignored**, in 3.60s
(`r16-credential-query-client-final.log`, locked/offline, serial with socket
access and disk scratch). New response tests cover exact query/owner binding,
revocation, wrong kind, management-sequence exhaustion, truncation/trailing bytes
and forged queries rejected before dispatch. Existing signed Create socket tests
exercise the shared HTTP transport after its extraction. A successful credential
query against a real daemon has not yet been tested. The ignored compiled-runtime
candidate test remains a release gate. Formatting and diff checks pass.

Next: durable exact-query retention and credential-wide reservation, wire fresh
Create preparation and submission into the CLI, then prove live query/Create,
route publication and restart/retry. Install/invoke, lifecycle retirement,
ordinary Shared finality and full release gates remain within the original goal.

### Durable credential discovery queries

`CleanCredentialQueryFile` now retains one canonical signed Credential query in
its own private, exclusively leased store, using CSF1 role 8. Expected Authority
and Credential IDs are supplied independently at open and checked again against
the signed query on load/publication. Invalid signatures, other selectors and
scope mismatches are refused. Existing role numbers and store directory
allowlists are unchanged. Initial-stage recovery and file/directory syncing
reuse the hardened store machinery; replacement nonces and staged replacements
are refused without deleting evidence.

`discover_credential` loads the original query when present; only an empty store
causes it to sign a new query, which is durably published before HTTP dispatch.
The lease remains held while receiving and validating the response. This is a
per-query lease, not yet the credential-wide reservation needed to prevent two
separate local operation directories from selecting the same next sequence.

**All `vosx` binary tests pass: 172 passed, zero failed, one ignored**, in 4.88s
(`r16-credential-query-store-final.log`, locked/offline, serial with socket
access and disk scratch). New store tests cover exact nonce retention, exclusive
leases, forged queries, wrong-credential reopen, initial-stage recovery and
staged-replacement refusal. A positive simulated HTTP server observes two
identical query bodies, verifies the query was published and the lease remains
held at receipt, and returns a response accepted as next management sequence 2.
This tests the real client/store boundary but not the real Authority daemon.
Formatting and diff checks pass; the ignored compiled-runtime candidate still
requires its release inputs.

Next: credential-wide durable operation reservation and fresh Create command
wiring, then real-daemon discovery/Create/publication and restart/retry. No
master promotion, guest artifact rebuild or new native daemon smoke is claimed.

### Durable credential-wide operation reservation

`CleanCredentialReservation` now derives one control directory from the full
Space and Credential IDs under a configured private parent and holds an
exclusive writer lease. Its bounded CRS1 record (CSF1 role 9) retains an
operation nonce and pending/completed disposition. A pending nonce survives
restart and refuses replacement; `current()` exposes the validated retained
nonce for resumption. The caller must use the same configured parent and retain
this lease across discovery, preparation and sending. Other hosts or independently
configured clients remain serialized by the live Authority's sequence policy.

Completion requires a cryptographically verified MAA2 for the exact LCQ1 request,
the reserved creation nonce, Space and Credential. The completed record binds
the exact request hash and acknowledgement commitment. Repeating that completion
is safe; a different operation can be reserved only after completion. An old
acknowledgement cannot complete a newer pending nonce. No HTTP error, unsigned
projection or cancellation can mark a reservation complete, and query/request
files are not deleted by this control record.

**All `vosx` binary tests pass: 173 passed, zero failed, one ignored**, in 3.99s
(`r16-credential-reservation-final.log`, locked/offline, serial with socket
access and disk scratch). Checks cover exclusive acquisition, zero-nonce
rejection, unchanged pending state after conflicting reservations/bad completion,
pending lookup after reopen, exact signed completion/reopen/retry, and refusal of
stale completion after the next reservation. The positive completion assertions
reuse the existing signed acknowledgement fixture. Formatting and diff checks
pass; the ignored compiled-runtime candidate remains a release gate.

Fresh Create CLI orchestration must now hold this reservation while choosing or
resuming per-operation query/request stores and sending the retained request.
That orchestration and real-daemon testing are still open; this is not yet an
end-to-end usable fresh Create command. Explicit denial/abort recovery and
retirement remain separate outstanding lifecycle requirements, not implicit
permission to discard a pending reservation.

### Fresh Local Create CLI and failed live integration smoke

The CLI now exposes `vosx space create-local-agent SPACE [--http LOOPBACK:PORT]`
and `--resume`. It loads an existing operator identity (never generates a
replacement), resolves the indexed Space and daemon public peer identity, and
selects a unique configured plaintext loopback listener unless overridden.
Under `<space-data>/agent-client`, it holds the credential reservation through
query discovery, signed preparation, durable request publication, submission
and verified completion. A pending operation requires explicit `--resume`;
resume loads its retained nonce and request instead of re-signing with a new
sequence/window. A fresh request uses a one-hour validity window with 60 seconds
of start-time tolerance. An expired unaccepted request is not silently refreshed.

The private-directory creation helper was extracted from the existing lifecycle
factory without changing its validation/sync behavior. The command checks the
retained Space/operator/Authority/nonce/transition-producer scope before sending.
It does not install an arbitrary Actor automatically or expose Shared creation.

**Final-source `vosx` binary tests: 174 passed, zero failed, one ignored**, in
5.21s (`r16-create-local-command-final.log`, locked/offline, serial with socket
access, disk scratch). New guards reject a fresh command over pending work and
a resume using a different retained target without replacing its request.
The ignored compiled-runtime candidate remains a release gate. Formatting and
diff checks pass. Native CLI builds passed (32.47s initial, 13.38s diagnostic);
the shared r14 CLI build was not overwritten.

**The real integration smoke failed; ordinary creation is not usable yet.**
The existing disposable `target/native-local-smoke.DATNas` Space was started
with the rebuilt CLI on HTTP 18081/SSH 2223. It became ready at
`2026-09-13T03:31:52.008871Z`, after roughly 160 seconds. Live signed credential
discovery completed and a signed Create request was durably published. The
status endpoint stayed responsive, but Create returned HTTP 503 without a Local
Agent image or verified acknowledgement. Logs are `create-daemon.log`,
`create-client.log` and `create-result.json` under that smoke directory.

Diagnostic logging was added for management authorization/issuance and the
HTTP lifecycle failure category, without dumping request bodies or key material.
The same Space was restarted and only `--resume` was run. Startup became ready
at `03:44:35.273351Z`, after roughly 307 seconds; at `03:44:40.794677Z` the owner
reported `management authorization did not return a completed invocation`,
followed by `Local Create did not complete: Lifecycle(Unavailable)` and HTTP
503. This identifies the failed stage, not the exact runtime error variant.
See `create-resume-daemon.log` and `create-resume-client.log`. Both scripts ended
with exit 1 and both daemons were stopped; their endpoint files are absent.

The retained request envelope SHA-256 before and after restart/retry is
`daf809373a7734d8b92bafcd5e901f677512b78b5068cb17cac8c1b9fd3edc0f`.
Operation nonce: `a32443984fc1548ad3899af014b755f9ec7c25f8ca2918396bfe52589e2cd7b4`.
Pending reservation/query/request and management intent remain intact for
diagnosis; no new nonce, repaired state or permissive authorization was used.

Next: capture the precise runtime rejection and add a regression with a clock
advance between durable authorization-envelope pledge and dispatch. One concrete
suspect is that management uses `prepare_terminal_clean_ordered_operation`
(which samples a fresh observation slot), while the existing reserved projection
path retains the accepted preflight slot. This is a source-based hypothesis,
not a proven root cause. Fix the admission/recovery boundary without refreshing
already accepted identities, then rerun native Create/restart/publication.
Journal-capacity reservation, Install/invoke, retirement, Shared finality and
full release gates remain open. This failed smoke does not justify promotion.

Historical pre-CLI checkpoint (superseded by the fresh CLI wiring above):
the CLI subcommand was still absent. The required wiring had to persist the complete
submission durably before sending and resend those bytes on retry. Bootstrap
uses management credential sequence 1; Authority requires the next consecutive
sequence and refuses another pending application. Do not silently choose a fresh
sequence, nonce or window after an ambiguous response. Descriptor/Authority
discovery, safe sequence allocation, request-file publication and bounded HTTP
submission/ack verification were prerequisites for the native Create smoke.

### Management authorization clock-advance reproduction

The physical native fixture now deterministically advances the trusted clock by
one slot immediately after the authorization envelope's durable commit. The
management call returns `Unavailable`; exact dispatch returns
`RuntimeOutcome::Completed(Err(AuthorityExpired))`. Reopening the intent and
retrying preserves the original envelope and store bytes, signs no receipt,
and leaves the issuer store untouched. This is a **passing diagnostic test for
an unresolved bug**, not a successful Create regression.

The underlying mismatch is confirmed: management persists a PublicPreflight at
the material's observation slot, while normal terminal journal admission samples
the clock again. Standard runtime requires equal slots for unseen preflight work.
The live smoke's exact error still needs confirmation with the improved logging;
the deterministic reproduction does not establish that it was the only live
failure. Production logging now reports only the bounded invocation-error enum,
never request bodies, credentials, or reply contents.

The large fixture's phased lifecycle assertions were extracted into a separate
non-inlined helper to stay within the default test-thread stack; neither runtime
semantics nor a global stack-size setting was changed. The initial diagnostic
attempts hit the fixture stack limit before reaching the assertion.

Final-source targeted validation: all **9 native bootstrap/lifecycle tests pass**
with `pvm,private-agent-store`, serial execution, and the default stack size.
Evidence: `.worktrees/ch08-c2-native/target/task-tmp/r16-management-clock-final.log`
(relative to the main checkout). `cargo fmt --all -- --check` and
`git diff --check` also pass. No guest source or bundled artifact changed.

Next implementation remains the admission/recovery boundary: persist and replay
the exact admitted authorization with management capacity protected, distinguish
prepared-but-unaccepted work from accepted work, and never refresh an already
accepted identity. Do not reuse the query-only reserved projection API for Linear
management work without its corresponding admission protocol. Then rerun live
Create, route publication, restart, and exact retry. All other C1/C2/C3 release
requirements above remain open; no branch promotion is justified yet.

### Persisted management preflight dispatch

Authorization and finalization now use an internal dispatch path that carries
the observation slot from the durable CMI3 envelope into the ordered input.
It does not regenerate the envelope or change its work, invocation, authorization,
or credential sequence. The owner pins the system Authority target; the network
path requires Linear/PublicPreflight work and the same physical route checks;
the journal requires Direct invocation, an exact work/preflight binding, and no
future observation. Normal routed admission still samples the current clock.
Query-only reserved projection dispatch is unchanged, including its exclusion
gate, Raft proposal checks, and acknowledgement path.

The clock-advance diagnostic is now a positive regression: a one-slot advance
after persisting authorization succeeds, and reopening intent/issuer followed
by an expired-window retry returns the same receipt without a second signature
or ordered slot. A second test advances the clock after persisting finalization
and proves exact finalization replay. Wrong actor, Query mode, and future-dated
management dispatch are refused without appending an ordered slot.

Targeted evidence (logs under `.worktrees/ch08-c2-native/target/task-tmp`, relative
to the main checkout): **10 native lifecycle tests pass**, 55.39 seconds,
`r16-management-clock-fix.log`; the existing pending-projection invoke/ack/reopen
test passes, 4.20 seconds, `r16-management-clock-projection.log`. The native CLI
build passes in 28.49 seconds, `r16-management-clock-cli-build.log`. No guest
source, wire format, or bundled artifact changed.

This fixes dispatch clock drift, **not the complete lifecycle admission protocol**.
Joint capacity reservation, retirement/clear, and prepared-but-unaccepted
recovery remain open. In particular, an older journal that already recorded the
failed dispatch is not silently rewritten or given a replacement identity.
The live test uses new disposable data in `target/native-clock-smoke.GLMaE7`,
HTTP 18082/SSH 2224; the earlier failed `native-local-smoke.DATNas` is untouched.
The initial sandbox-denied network attempt was stopped before rerunning with
socket access; its log is preserved as `sandbox-daemon.log`.

Live progress: the new daemon became ready at `2026-09-13T04:12:32.763161Z`.
The request was saved at approximately `04:12:51Z`, but the HTTP wait ended with
504 (`create-client.log`). Unlike the earlier failure, the scope now contains
both `management.issuer` and an ordinary Local `image`, for Agent
`c73db0519443e8c5744763a8073ec17781aeda5017cfb8a131ec15e9efb6c866`.
The issuer file changed again at `04:16:21Z`. No verified client acknowledgement
has been returned, and route publication is not yet proven. The script requested
SIGINT after the timeout; at this checkpoint its daemon was still CPU-active
finishing the in-flight workflow/shutdown. Do not start another daemon on these
stores until that process has terminated. `resume-smoke.sh` is prepared to start
the same Space and submit only `--resume`, then compare a second exact retry.
The lifecycle request SHA-256 is
`173da629f2e649e485927ca92a2d02b9ab5aa629197645ff6bfbe124aef8862f`;
no new request or nonce was substituted after the timeout. Debug-build completion
latency and shutdown latency need assessment alongside the resume result.

### Lifecycle reconciliation scheduling

The first clock-fix smoke subsequently stopped with exit 1 and removed its
endpoint. Its retained-request resume script started the same Space at
`2026-09-13T04:22:10Z`; no new request/nonce was generated. That running binary
contains `470adcfb`, not the scheduling change below.

Source inspection found a second concrete latency problem: Create calls
`AgentProductionOwner::reconcile` directly, but only startup and periodic driving
previously advanced `reconcile_after`. A slow Create could therefore finish route
publication and immediately repeat the full inventory query in the same router
tick. The node also did not recheck shutdown between completing a queued lifecycle
request and beginning that periodic pass.

Every successful reconciliation now sets the next deadline after completion,
including lifecycle-triggered publication. The router finishes/replies to an
accepted lifecycle request, then checks shutdown before starting periodic work.
No in-flight application is canceled, and no projection or authorization check
is omitted. The new deadline regression failed on the old implementation
(`r16-lifecycle-reconcile-deadline-red.log`) and passes with the fix. Seven tests
matching `reconciliation` pass in 4.22 seconds, including the new shutdown guard
(`r16-lifecycle-reconcile-deadline.log`); all four production-owner tests pass in
0.12 seconds (`r16-lifecycle-reconcile-owner.log`). Logs are under
`.worktrees/ch08-c2-native/target/task-tmp`, relative to the main checkout.
This scheduling fix is not yet covered by a rebuilt native smoke and does not
prove that the original Create can finish within the HTTP deadline.

Final-source follow-up: all ten native bootstrap/lifecycle tests pass in 51.35
seconds (`r16-lifecycle-reconcile-native.log`), and the existing busy-outbox raw
shutdown test passes (`r16-lifecycle-reconcile-shutdown.log`). The live resume
daemon running the earlier `470adcfb` binary reached readiness at
`04:29:11.097691Z`, about 421 seconds after restart. Its retained Create again
returned HTTP 504 (`create-resume-client.log`), leaving
`create-resume-result.json` empty. The request SHA-256 is still
`173da629f2e649e485927ca92a2d02b9ab5aa629197645ff6bfbe124aef8862f`.
No native acknowledgement/publication success is claimed. The resume script
requested shutdown and is waiting on that same daemon; do not start an
overlapping process. Next: establish which work an already-applied Create retry
repeats, then verify bounded completion with the updated native binary. Do not
replace durable authorization or remove physical/Authority verification to make
the HTTP test pass.

### Finalized Create retry recovery

The issuer can now recover its latest already-finalized application for an
exact signed credential call. It reconstructs and compares the complete stored
decision, validates the canonical signed acknowledgement through the existing
finalization check, and returns no result for an incomplete barrier or a different
call. This path never issues a new receipt or advances a sequence.

The Local Create coordinator uses that result only when both persisted lifecycle
envelopes exist, the finalization message matches the exact acknowledgement,
and the observed slots are consistent. It then reopens the physical Local image
and verifies the applied result against the retained receipt/acknowledgement.
A missing Local image fails without recreating it, signing, or mutating the
intent/issuer. The production owner still performs route reconciliation; the
durable marker does not replace physical or publication evidence.

All **12 issuer tests pass** in 4.04 seconds (`r16-finalized-create-issuer.log`),
including exact signed-call recovery across issuer reopen, unfinished-barrier,
forged-call, wrong-target, different-call, and poisoned-store cases. All **10
native lifecycle tests pass** in 47.42 seconds (`r16-finalized-create-native.log`),
including a missing-image retry that preserves both stores and the system journal.
The updated CLI build passes in 21.69 seconds
(`r16-finalized-create-cli-build.log`). Logs are under
`.worktrees/ch08-c2-native/target/task-tmp`, relative to the main checkout.
Formatting and diff checks pass; no guest artifact or wire format changed.

The previous resume smoke stopped with exit 1 and removed its endpoint. The
updated CLI is now being tested by `target/native-clock-smoke.GLMaE7/fast-resume-smoke.sh`
against the same retained request. Its logs use the distinct `fast-resume-` prefix;
earlier evidence is preserved. A successful native acknowledgement is still
unproven at this checkpoint. Initial Create latency, journal capacity/retirement,
Install/invoke, ordinary Shared finality, and the full C1/C2/C3 release gates
remain open.

### First verified live Create acknowledgement and repeated-publication work

The `fast-resume` daemon reached readiness at `2026-09-13T04:43:32.969598Z`,
about 108 seconds after startup. Its first retained-request submission returned
a **client-verified MAA2** for Local Agent
`c73db0519443e8c5744763a8073ec17781aeda5017cfb8a131ec15e9efb6c866` at
approximately `04:45:27Z`, about 114 seconds later. This exercised durable
application recovery and production route reconciliation before HTTP 201.
The 3,138-byte JSON response is `fast-resume-result.json` under the smoke root.
However, the immediate second retry returned HTTP 504 and the script exited 1;
`fast-resume-retry-result.json` is empty. Both outcomes matter: one verified live
acknowledgement is now proven, but repeat completion within the HTTP deadline
is not. The daemon stopped and removed its endpoint. The request SHA-256 stayed
`173da629f2e649e485927ca92a2d02b9ab5aa629197645ff6bfbe124aef8862f`.

The production owner now remembers at most one successfully published Local
application response in memory. Every retry still passes through signed-call
validation and durable physical application recovery. Only an identical full
acknowledgement commitment, unchanged accepted head, and existing Local
attachment may reuse that previous completion without another inventory pass.
The record is cleared before each lifecycle attempt and every reconciliation
attempt, including failures; a successful exact delivery may restore it.
Reopening starts empty and must reconcile again. This is bounded response
delivery deduplication, not an authorization proof, durable publication marker,
or promise that a previously created Agent is currently healthy.

All five production-owner tests pass in 0.09 seconds
(`r16-published-create-owner.log` under the shared disk test target). They cover
matching response/head/attachment, missing and substituted matches, and clearing
the record on successful and failed reconciliation. A new native script,
`target/native-clock-smoke.GLMaE7/published-resume-smoke.sh`, preserves all earlier
logs and will compare two exact retained-request responses with the rebuilt CLI.
Full C1/C2/C3 completion and native latency remain open.

Follow-up validation: all ten native lifecycle tests pass in 55.47 seconds
(`r16-published-create-native.log`), and the CLI builds in 19.85 seconds
(`r16-published-create-cli-build.log`). The new live script is running against
that rebuilt source. If its first submission returns 504, it records that
failure and allows one more exact `--resume` while keeping the same daemon up,
then compares the next verified response byte-for-byte. It neither increases
the HTTP deadline nor substitutes a new request. This exercises bounded
recovery after a wait timeout; any initial timeout remains a latency failure.

That live script subsequently **passed with exit 0** on `d95b7afa`. Startup
became ready at `2026-09-13T05:01:13.745562Z`. The first submission timed out;
an exact retry on the same running daemon returned a verified response at
`05:04:08.307527Z`, and the next identical retry returned at
`05:04:08.811548Z` (about 0.50 seconds later). Both JSON files are 3,138 bytes
with SHA-256 `b45514dc37f30798a2fae95769fc75388ab7f2431805fd80a5fde8c2e0736cc0`:
`published-resume-recovered-result.json` and `published-resume-retry-result.json`
under `target/native-clock-smoke.GLMaE7`. The request hash remains
`173da629f2e649e485927ca92a2d02b9ab5aa629197645ff6bfbe124aef8862f`.
The daemon shut down and removed its endpoint. This proves verified Local
Create recovery and repeat delivery after restart, not a within-deadline
initial response or actor Install/invoke. No fresh nonce, permissive verifier,
cached client response, or fabricated acknowledgement was used.
The recovered response also compares byte-for-byte equal to the earlier
`fast-resume-result.json`, proving the acknowledgement itself stayed unchanged
across the intervening daemon restart.

### Finalized management-result retirement phase

The system owner now has a retirement phase for the retained authorization and
finalization runtime results. It requires the exact signed intent, the issuer's
durable finalized application acknowledgement, both saved Linear envelopes and
the current physical Authority route. It rejects an unfinished application or
substituted acknowledgement before submitting retirement work. Positive runtime
acknowledgements are checked against the exact work/authorization commitments
and committed journal evidence. Existing positive acknowledgements are reused;
the intent, receipt, application acknowledgement and signer count are preserved.

The initial targeted `native_` run passed **22 tests, zero failures**, in 13.08s:
`.worktrees/ch08-c2-native/target/task-tmp/r16-management-retirement.log`.
The lifecycle fixture verifies rejection before finalization and for a
substituted signed acknowledgement, exactly two retirement slots, and no new
slots on an exact repeat. These fixtures use bundled Authority policy with the
native outer system runtime; they are not an independent opaque-runtime proof.
The final-source native lifecycle run passed **10 tests, zero failures**, in
13.78s, including simulated interruption after the first positive retirement:
`.worktrees/ch08-c2-native/target/task-tmp/r16-management-retirement-partial.log`.
The resumed phase adds only the second acknowledgement, and another repeat adds
none. This is a retained-journal interruption check, not a daemon-restart smoke.

This phase is deliberately **not wired into the production lifecycle yet**.
Production does not clear or replace the retained intent. The completion/handoff
storage boundary is now implemented below, but joint journal-capacity/GC
protection across restart must be finished before enabling it;
the bounded retained acknowledgement suffix alone is not a permanent retirement
marker. Install remains unavailable through the native lifecycle. Next work
stays in C2: protected retirement/handoff, then signed Install and real actor
invocation/restart. C1 recovery and C3 final-source release gates remain open;
no additional review batch or branch promotion is introduced here.

The retirement phase now preflights the **combined** encoded acknowledgement
suffix cost and remaining physical Raft slots before retiring either result.
It counts two, one, or zero records using exact committed positive evidence,
and retains an extra physical slot when work remains for the reopen leader
no-op. Both inputs must be distinct, canonical Direct/Linear preflight envelopes;
an unretired input must have its exact successful invocation in the authenticated
suffix. Unlike Query recovery, this path does not speculatively re-execute a
Linear invocation at a checkpoint boundary when evidence is missing.

Final-source native lifecycle checks passed **10 tests, zero failures**, in
16.80s: `.worktrees/ch08-c2-native/target/task-tmp/r16-management-retirement-capacity-final.log`.
They cover two/one/zero remaining acknowledgements, duplicate invocation refusal,
Query refusal, and rejection of a substituted but internally consistent preflight
clock. That checkpoint did not prove exhausted-capacity or concurrent-writer
behavior: its precheck was not a reservation. The live reservation added below
supersedes that precheck-only implementation. Existing Query reservation semantics
remain unchanged.
The authenticated-boundary Query reopen regression also passed (one test,
1.92s): `.worktrees/ch08-c2-native/target/task-tmp/r16-management-retirement-projection.log`.

### Live management-retirement reservation

The retirement phase now reserves both exact acknowledgement keys under the
live proposer's admission mutex. Before publishing the reservation it waits for
the leader barrier, drains committed work, verifies the physical apply cursor,
and checks the combined suffix and physical-slot budgets. Ordinary Ordered,
Merge, Local and merge-import admission share the exclusion; projection and
checkpoint reservations conflict with it. Only exact reserved Acknowledge work
may pass, not a replacement Invoke or an unrelated acknowledgement.

The reservation remains held after both positive acknowledgements. Completion
rechecks committed evidence for both, calls the durable-handoff callback while
admission is excluded, and releases only on callback success. A premature,
failed or ambiguous completion leaves the reservation held. This does not yet
implement the durable intent handoff: production Create still does not invoke
retirement, and restoring this reservation on reopen before route publication
remains required. There is no durable-record format change or new guest bundle.

Final-source native lifecycle checks passed **10 tests, zero failures**, in
14.30s: `.worktrees/ch08-c2-native/target/task-tmp/r16-management-retirement-reservation-final.log`.
They exercise mutual exclusion with projection admission, idempotent exact
reservation, reversed-key conflict, ordinary/unrelated acknowledgement refusal,
premature callback refusal, retained exclusion after callback failure, partial
retirement recovery, and release after a successful test callback. A test
callback is not durable handoff evidence; these checks do not prove restart
restoration or the exhausted-capacity boundary.
The same source also passed all **six Shared-network unit tests** and the
**pending-projection Invoke/Ack/record-clear recovery test**. Logs:
`.worktrees/ch08-c2-native/target/task-tmp/r16-retirement-reservation-network.log`
and `.worktrees/ch08-c2-native/target/task-tmp/r16-retirement-reservation-projection.log`.

### Durable retirement marker and intent handoff

The lifecycle owner can now commit a host-owned **CMR1** retirement marker while
the reservation proves both positive journal acknowledgements, then release
admission. CMR1 retains the exact CMI3 body: signed request, authorization work,
and finalization work containing the signed application acknowledgement. It has
the same encoded length and storage bound; no guest ABI, bundle or CSF1 role
changes. Old active CMI3 records remain readable. The CMR1 decoder rejects
missing authorization/finalization envelopes; this marker is trusted private
host persistence, not an independently signed finality proof.

After an ambiguous successful marker write, reopening the store recognizes
completion and can release the matching volatile reservation without relying
on the bounded journal acknowledgement suffix. The lifecycle owner still
reverifies the exact signed intent and finalized issuer acknowledgement before
using that marker. A marker write error poisons the current slot instance.

An explicit `handoff_retired` operation atomically replaces only the exact
completed intent with a fresh signed request for the same Space/Agent. Ordinary
`pledge` still refuses replacement. Handoff grants no policy approval: later
dispatch must verify independently selected routes and run Authority policy.
Retries after an ambiguous replacement recognize the already-persisted next
request without resetting its envelopes. Active/unretired intents cannot be
replaced through this boundary.

Final-source native checks passed **10 tests, zero failures**, in 16.78s:
`.worktrees/ch08-c2-native/target/task-tmp/r16-management-retirement-handoff.log`.
The full lifecycle fixture covers successful completion and handoff, before-
and after-publication failures for both writes, poisoned-instance refusal,
exact reopened retry, unchanged acknowledgement/issuer evidence through
retirement, and no extra Ordered slots for marker/handoff recovery. The next
request in this test is persisted only; it is not dispatched or approved.
The intent-filter run also passed **three tests** (including two overlapping
native checks), covering rejection of a premature CMR1 marker and existing
ambiguous-pledge recovery:
`.worktrees/ch08-c2-native/target/task-tmp/r16-management-intent-handoff-codec.log`.

Production integration remains disabled. Next: restore pending retirement
protection before any startup/reattachment route publication, verify GC and
exhausted-capacity recovery, then wire native lifecycle completion/handoff and
signed Install/invoke. These store-reopen tests are not daemon-restart or
post-GC physical evidence, and do not complete C1/C2/C3 release gates.

### Retirement protection across network reattachment

The network owner now retains exact pending retirement envelopes independently
of its volatile route/worker generation. Refresh restores their admission gate
before activating a replacement route. A new recovery constructor also accepts
one independently verified pending retirement before attaching the system Agent.
Both paths drain recovered commits, enforce the one-voter leader barrier, check
capacity before and after promotion, and initialize the reserved keys before
route registration or merge pumping. They refuse missing Linear evidence or
insufficient capacity rather than checkpointing away the pending results.

Durable completion removes both the live reservation and its retained recovery
envelopes. A stale completion cannot remove a different pending retirement,
including while no route is attached. Projection and retirement recovery cannot
be selected together for the same attachment.

Final-source native checks passed **10 tests, zero failures**, in 17.82s:
`.worktrees/ch08-c2-native/target/task-tmp/r16-retirement-reattachment-final.log`.
They retire/recreate a real network owner with both acknowledgements pending,
replace a stale route after the first acknowledgement, verify a different
handler is installed with projection admission still excluded, and prove the
completed reservation does not reappear on another refresh. No replacement
Ordered work is introduced. The Shared runtime host is retained during these
tests; they are not a full filesystem-host or daemon restart.
The same source passed the projection checkpoint-failure/reattachment regression
(one test, 9.47s) and all six Shared-network unit tests (0.23s):
`.worktrees/ch08-c2-native/target/task-tmp/r16-retirement-reattachment-projection.log`
and `.worktrees/ch08-c2-native/target/task-tmp/r16-retirement-reattachment-network.log`.

Startup integration remains open: `clean_startup.rs` currently constructs the
system owner before opening `CleanManagementLifecycleStoreFactory`. At that
checkpoint its trait only opened a selected Agent's stores; the discovery
boundary added below is not yet invoked by startup. It cannot yet verify pending
retirements before the first system route is attached. Move that discovery
boundary ahead of owner attachment, handle the bounded pending set without an
unprotected publication gap, and prove full restart/GC/exhausted-capacity recovery
before enabling production retirement/handoff or native Install.

### Bounded lifecycle-store discovery

`LocalLifecycleStoreFactory` now requires explicit `discover` and `open_existing`
operations. Discovery returns sorted unique Agent candidates, fails rather than
truncating at the caller's bound, and does not read/reconcile images or acquire
their writer leases. The filesystem implementation scans the pinned directory
descriptor, revalidates the configured parent, and accepts only canonical nonzero
lowercase Agent names backed by exact private child directories. Unexpected
residue, files, symlinks and replaced parents fail closed. Callers must run this
before lifecycle writers start; candidate names are not authenticated requests,
issuer evidence or a transactional snapshot of concurrent directory changes.

Recovery-only opening retains the existing exclusive lease and staged-image
checks but never creates a missing Agent directory. If a candidate disappears
after discovery, recovery fails instead of silently treating it as fresh state.
The descriptor-pinned scan currently uses Linux `/proc/self/fd`; other platforms
explicitly return Unsupported and require a supported equivalent before this
startup path can be enabled there.

Final-source results: **nine lifecycle-storage tests passed** (0.01s), **all
42 clean-store tests passed** (0.45s with loopback socket access), and the native
scoped-store controller regression passed (6.74s). Evidence:
`.worktrees/ch08-c2-native/target/task-tmp/r16-lifecycle-discovery-final.log`,
`r16-lifecycle-discovery-clean-store-final.log`, and
`r16-lifecycle-discovery-controller.log` in the same directory. The initial
broader sandbox run passed 41 tests and could not bind the existing HTTP-retry
fixture's socket; the socket-enabled rerun passed all 42.

This boundary is not yet wired into `clean_startup.rs`. Next, load every bounded
candidate through `open_existing`, verify its intent and issuer against the
independently selected system Authority and Agent scope, then feed the pending
set into attachment before route publication. Keep incomplete and finalized
but unretired intents protected; do not mistake directory discovery for recovery.

### Verified lifecycle recovery candidates

`discover_local_lifecycle_recovery` now opens every bounded candidate through
existing-only stores and retains both store handles (and their backend leases)
in an opaque recovery container. It independently checks the candidate list's
bound, strict ordering, uniqueness and nonzero identities, then verifies each
signed intent against the caller's configured Authority, discovered Space/Agent,
and Local profile. Issuer images are opened against that same independent scope.

Incomplete intents remain pending rather than being skipped. Finalized entries
must reproduce the exact signed issuer acknowledgement and match both retained
envelopes, including the authorization clock. A completed CMR1 marker cannot be
accepted without that finalized issuer evidence. Missing intents alongside
nonempty issuers, missing issuers alongside finalization work, and finalized
records hiding an outstanding issuance fail closed. A new handoff intent may
legitimately coexist with the previous completed issuer record; it remains
pending and is not treated as approved. Empty directory candidates remain
distinct from authenticated work.

This loader performs no policy invocation, signing, retirement or route
publication. It verifies request/storage scope, not physical Local application
or independent Shared finality. `clean_startup.rs` does not yet call it or pass
the returned pending set into protected attachment.

The lifecycle fixtures exercise finalized-unretired, completed and next-pending
states, wrong Authority/Agent scope, duplicate/oversized/zero candidate lists,
missing intent/issuer evidence and empty stores. They also assert that scanning
does not change either stored image or use a create-capable factory open.

Verification includes an intermediate serial run with **10 passed** (59.00s,
`r16-lifecycle-recovery-scan-serial.log`). Final-source serial execution recorded
**nine passed and one failure** at bootstrap attachment (`Host(Unavailable)`,
before the failing fixture reached the new scan assertions), in 40.67s:
`r16-lifecycle-recovery-scan-final-source.log`. The exact failed test then passed
in isolation on the same source (**one passed**, 14.75s):
`r16-lifecycle-recovery-isolated.log`. An earlier parallel run also recorded an
attachment `Unavailable`. All logs are under
`.worktrees/ch08-c2-native/target/task-tmp/`. No deadline was increased and no
failure was filtered out. This intermittent attachment failure remains a release
investigation item; these results do not establish a green final-source suite.

Next: integrate the verified pending set before first route activation, including
incomplete lifecycle phases rather than only finalized retirement pairs, and
resolve the attachment failure before claiming restart/release readiness.

### Serialized attachment check at the promotion deadline

Investigation reproduced an attachment failure with the atomic worker role still
`Candidate` at the 1.8-second polling deadline. It did not capture the serialized
worker state from that failure, so the full intermittent failure cause remains
unproven. Subsequent diagnostic runs found no storage commit errors; repeated
reattachment also passed, including one observed 478 ms metadata commit. Those
observations alone do not establish a storage-latency cause.

Attachment now consults one worker-serialized snapshot even when atomic role
polling reaches its deadline. This lets an in-flight promotion finish before
the attachment decision. The snapshot must still report `Leader` with the
entire log committed, and the host must drain to that exact committed cursor
before proceeding. A non-leader, incomplete commit, stopped worker or cursor
mismatch still fails closed. The polling interval and 1.8-second hint deadline
are unchanged; the blocking snapshot query is not a hard wall-clock timeout.
Temporary diagnostic logging was removed.

A deterministic regression test failed with the old deadline behavior and now
passes, including the refusal cases. A new native stress test retires and
reattaches the system worker 16 times and checks that the Ordered journal index
does not change. Evidence logs use the `r16-promotion-barrier-` prefix under
`.worktrees/ch08-c2-native/target/task-tmp/` (disk scratch, not `/tmp`).

Final-source targeted checks: **7 network tests passed** (0.57s,
`r16-promotion-barrier-green.log`), and the serial `native_` filter reported
**23 passed, zero failed** (68.89s, `r16-promotion-barrier-native.log`), including
all 11 native bootstrap/lifecycle tests and the 16-reattachment stress test.
One unrelated extension test self-skipped because `echo-extension` was not
built, despite the harness counting it as passed; no extension coverage is
claimed from that test. Formatting and diff checks pass. These targeted results
do not replace a final full-library run or a rebuilt-CLI real-daemon smoke.

This change does not wire startup recovery, enable retirement/handoff in the
production controller, or establish native Install/invoke or Shared finality.
The next implementation step remains protected adoption of the verified pending
lifecycle set before the first system route is published, including incomplete
phases and without an unprotected gap between pending retirement pairs.

### Joint retirement-set capacity

The journal now accepts a bounded set of exact completed management envelopes
for one combined retirement admission calculation. The existing two-envelope
check delegates to it. Every remaining acknowledgement contributes its encoded
Ordered-entry bytes and entry count to one prospective chain before the shared
suffix headroom check. Independently checking pairs against the same starting
headroom is not sufficient for startup recovery with multiple pending intents.

Duplicate invocation identities are rejected across the entire set, including
already-acknowledged members. Sets larger than the replay suffix entry bound
are rejected before scanning. Exact retained positive acknowledgements consume
no new entries; missing or unsuccessful Linear invocation evidence still fails
closed, with no checkpoint-boundary re-execution fallback. This is a read-only
capacity calculation, not a live reservation, authorization decision or durable
retirement marker.

The native fixture checks empty/single/pair sets, reverse order, non-adjacent
duplicates and the size bound. Additional fresh signed calls exercise four
distinct unretired results combined with two already-acknowledged results;
the expected combined delta is four, not six. This is result-retirement
accounting, not proof that four additional Agents were approved or created.
The initial fixture that changed only old invocation IDs failed and was
corrected to use fresh signed calls; its failure log is retained as
`r16-retirement-set-final.log` in disk scratch. A second fixture run exposed
`AuthoritySlotRegressed` (`r16-retirement-set-signed.log`): fresh calls must use
the current physical admission slot, whereas retries keep their saved slot.
The fixture now prepares fresh signed calls with fresh admission preflights;
no persisted production request identity or clock was changed.

The corrected final-source management tests pass: **3 passed, zero failed**
in 32.28s (`r16-retirement-set-clock.log`). Formatting and diff checks pass.
The final serial native bootstrap/lifecycle suite also passes: **11 passed,
zero failed**, 68.29s (`r16-retirement-set-native.log`). These targeted checks
do not replace final full-library, exhausted-capacity or real-daemon gates.

Still required: seed a set-wide admission/GC exclusion before first route
activation, protect incomplete and prepared-but-unaccepted phases too, and
prove exhausted-capacity/restart behavior before enabling production handoff.
The startup loader and production retirement/handoff wiring remain incomplete.

### Live retirement sets survive partial completion and reattachment

Network admission now retains a bounded set of exact retirement pairs rather
than one pair. A set is jointly budgeted before reservation; its exact matching
acknowledgements are the only admitted submissions while it is reserved. Query
reservations and ordinary suffix-consuming submissions remain excluded.
Re-reserving an existing member is idempotent and cannot replace the broader
pending set. Empty, oversized and duplicate sets fail closed, as do sets that
conflict with an existing grouping.

The recovery attachment constructor seeds the entire supplied set before
worker route activation and uses the joint capacity calculation both before
and after leader promotion. The owning network host retains the set across
generation retirement. Completing one pair requires its two retained positive
acknowledgements and a successful completion callback under the proposal lock;
only that pair is removed. Failed callbacks retain the whole remaining set.
Reopened durable-marker release likewise removes only its matching pair and
cannot clear a different pending operation.

The bundled-Authority fixture exercises two pairs/four completed results,
member re-reservation, conflicting regrouping, network-owner recreation,
ordinary acknowledgement refusal, premature completion refusal, failed
completion callbacks, and refresh both before and after partial completion.
Query admission stays excluded until the final pair completes, and exactly
four new Ordered acknowledgements are recorded. This test's successful
callbacks simulate the network completion boundary; durable CMR1 publication
is covered by the existing single-intent fixtures, not by a multi-intent
filesystem restart in this test.

Verification: the management subset passed **3/3** (54.40s,
`r16-retirement-set-gate-native.log`); the broader native bootstrap/lifecycle
run passed **11/11** (108.61s, `r16-retirement-set-gate-final.log`); and the
projection checkpoint/reattachment failure test passed **1/1** (10.32s,
`r16-retirement-set-gate-projection.log`). After the final constructor size
guard, the network suite passed **7/7** (0.46s,
`r16-retirement-set-gate-network-final.log`). Logs are in the shared disk
scratch directory; formatting and diff checks pass.
The final-source native bootstrap/lifecycle rerun also passed **11/11**
(97.98s, `r16-retirement-set-gate-verified.log`).

This remains an internal completed-pair recovery mechanism. Production startup
still needs to adopt the independently verified store set before constructing
the system owner, cover incomplete/prepared-but-unaccepted phases and coexist
with a pending projection. No final-source exhausted-capacity proof or native
daemon restart of multiple lifecycle stores is claimed. Production
retirement/handoff remains disabled until those gates are implemented.

### Linear management cannot use the projection boundary fallback

Tracing incomplete recovery found that persisted Linear management preparation
also reached `retained_terminal_projection_boundary`. That fallback is meant
for read-only Query projections, but it previously accepted an exact matching
Linear invocation at the certified checkpoint boundary and executed the runtime
to reconstruct a terminal result. A physical bundled-Authority regression
reproduced this: the old source returned `Ok(Completed(Ok(...)))` for Linear work
after checkpointing its invocation (`r16-linear-boundary-red.log`, one expected
failure, 48.08s). This proves the unsupported fallback was reachable; it does
not prove the bundled runtime duplicated an external effect.

An exact non-Query boundary now returns a cross-store error before runtime
execution, instead of reporting a retained result or falling through to new
publication. Exact Linear results still present in the authenticated suffix
remain replayable without an additional Ordered slot. The fixture checks both
sides of that boundary and verifies that checkpoint/refusal do not append a
replacement invocation. The existing read-only Query boundary protocol remains
supported and has a separate physical checkpoint/reopen regression.

Final-source verification: **11 native bootstrap/lifecycle tests passed**
(100.67s, `r16-linear-boundary-green.log`), including the previously failing
Linear-boundary regression. The physical Query boundary/reopen test also
passed (**1/1**, 1.34s, `r16-linear-boundary-query.log`). Formatting and diff
checks pass. All evidence is under the shared disk scratch directory, not
`/tmp`; no rebuilt-CLI smoke or full release run is claimed.

This is not a complete incomplete-intent recovery protocol. Startup still needs
authenticated evidence distinguishing never-accepted work from pruned work,
protection before any checkpoint can discard needed evidence, and integration
of pending projections with the lifecycle recovery set. Rejecting this unsafe
fallback does not establish restart readiness for those cases.

### Anchored management journal lookup

The Shared host now exposes an internal read-only lookup for one exact Linear
management envelope after a supplied journal position. It independently matches
the anchor's genesis, genesis admission and runtime binding, and the envelope's
Space/Agent/runtime scope. The journal walk verifies every content-addressed
entry's index, parent chain, genesis and runtime back to the exact anchor before
returning a matching input ID. It does not stop early after finding the request.
The walk is bounded by the replay suffix limit and rejects anchors before the
authenticated replay boundary, future or substituted anchors, mismatched
preflight clocks, duplicate publication and later lifecycle steps for the same
invocation.

`None` means only **not observed in the applied Ordered interval after the
anchor**. It does not mean never accepted before the anchor, nor does it cover
unapplied Raft entries. The recovery coordinator must first exclude competing
admissions, drain a leader barrier, and verify that the anchor was durably
recorded before the first dispatch. This lookup does not invoke the runtime,
sign, retire evidence, publish routes or authorize a retry.

Native bundled-Authority fixtures check absence before dispatch, exact presence
after dispatch and after unrelated later calls, refusal of altered head/genesis,
future anchors, substituted clocks and foreign Agent scope. A late anchor gives
interval absence even though the call existed earlier, documenting that limit.
Acknowledgement and checkpointing make the old evidence lookup fail closed,
rather than changing missing evidence into permission to execute.

Verification: the intermediate management subset passed **3/3** (62.02s,
`r16-management-anchor.log`). The final-source serial native bootstrap/lifecycle
suite passed **11/11** (97.82s, `r16-management-anchor-final.log`). Formatting
and diff checks pass; logs remain in shared disk scratch. No full release or
real-daemon incomplete-recovery test is claimed.

The pre-dispatch position is not yet persisted in the intent image; no intent
wire format changed at this checkpoint. Durable anchor capture under admission
exclusion and startup adoption remain required before incomplete lifecycle
recovery can use this primitive.

### Durable pre-dispatch anchors in CMI4/CMR2

Both native authorization and finalization preparation now persist the exact
invocation envelope together with its pre-dispatch journal anchor. The network
coordinator holds proposal exclusion, requires a local leader with a fully
committed log, drains the committed suffix and verifies the exact apply cursor.
It then validates envelope scope and captures the journal position while
holding the host lock through the independent intent-store write. The callback
must not re-enter the host or coordinator. Existing projection/retirement
reservations reject anchor publication before the callback runs.

MJA1 records the genesis, genesis-admission ID, runtime commitment and exact
Ordered index/head. CMI4 requires an anchor for each retained envelope; CMR2
preserves the same complete anchored body on retirement. Anchors must be
well-shaped, and finalization cannot regress or substitute the authorization
anchor's genesis/admission/runtime scope. Re-pledging an envelope with a
different anchor conflicts. Ambiguous writes poison the in-memory slot; reopen
recovers the same envelope and anchor rather than sampling a new position.
The bounded host image allowance grew by 512 bytes for the two anchors.

This intentionally rejects CMI3/CMR1 images. No migration or empty-anchor
fallback exists, and no guest ABI or bundled PVM artifact changed. Use fresh
disposable lifecycle data when testing a rebuilt CLI from this source.

Final-source verification: **11 native bootstrap/lifecycle tests passed**
(107.02s, `r16-durable-anchor-native-final.log`), **12 issuer tests passed**
(3.85s, `r16-durable-anchor-issuer.log`) and **9 vosx filesystem lifecycle tests
passed** (0.11s, `r16-durable-anchor-stores.log`). Native fixtures verify exact
pre-dispatch indices and scope, retained anchors after reopen, rejection while
retirement admission is reserved, host-lock ownership during publication and
lock release after a callback error. Issuer fixtures cover malformed anchors,
changed-anchor retries, cross-phase scope substitution, ambiguous writes and
legacy-image rejection. Formatting and diff checks pass. Logs use disk scratch;
no fresh CLI build/smoke, migration, or full release validation is claimed.

The capture exclusion ends when the store callback returns. This is not yet
the full lifecycle reservation lasting through dispatch, retirement and restart.
Startup must still authenticate the retained anchors against the opened journal,
adopt and protect incomplete work before publishing routes, and reconcile it
with pending projections. No real-daemon incomplete recovery or release-ready
claim follows from persisting the anchors alone.

### Persisted anchors are checked inside management dispatch

The production authorization/finalization dispatch interface now requires the
anchor from its retained intent slot; there is no unanchored overload of that
internal management entry point. Under the proposal lock, dispatch obtains a
worker-serialized leader barrier, refuses an uncommitted tail, drains committed
work and checks that the host application cursor exactly equals the barrier.
It then authenticates the saved anchor's genesis/admission/runtime commitment
and walks the exact applied journal interval before preparing the invocation.
The same proposal exclusion remains held through Raft proposal and result wait.

Preparation must agree with the interval evidence: a retained response must
have the exact replay input ID found after the anchor, and an absent interval
must not be satisfied by a cached result predating a substituted late anchor.
Pruned, substituted or unreachable anchors fail closed without publishing a
replacement invocation. Both fresh dispatch and retained-result retry preserve
the saved preflight clock.

Native fixtures now pass the original saved anchors through retry and physical
checkpoint tests. Additional dispatch-level cases substitute genesis, runtime,
head and a later real journal position; every refusal leaves the Ordered index
unchanged. These are tests of the invocation admission boundary, not proof of
complete startup recovery or of an anchor's provenance in an untrusted store.

Final-source verification: **11 native bootstrap/lifecycle tests passed**
(114.06s, `r16-anchored-dispatch-final.log`) and **7 network tests passed**
(0.58s, `r16-anchored-dispatch-network.log`). An intermediate native run also
passed 11/11 (101.87s, `r16-anchored-dispatch.log`). Formatting and diff checks
pass. Logs remain in disk scratch; no rebuilt-CLI smoke or full release gate
is claimed by these targeted results.

Still required: retain incomplete-work protection across the gap between the
anchor-store callback and dispatch, and across process restart; adopt the entire
verified store set before route activation; handle pending projections and
exhausted capacity. Anchor persistence and dispatch checking do not close those
remaining lifecycle/release gates.

### Pending invocation and acknowledgement capacity

The Shared journal now calculates one combined suffix budget for a bounded set
of exact anchored terminal-management envelopes, without executing the runtime
or previewing policy. An invocation not observed after its verified pre-dispatch
anchor costs an Invoke plus an acknowledgement; an exact retained successful
terminal invocation costs only its acknowledgement. Prospective Ordered entries
are chained and their canonical encoded bytes counted together against the
authenticated suffix budget. This does not cover Yielded/Resume lifecycles.

The calculation rejects duplicate identities, invalid/pruned anchors, a retained
input before a substituted later anchor, non-successful retained outcomes and
retained positive acknowledgements being misclassified as unseen work. Retired
intents use their separate durable-completion protocol. Absence remains scoped
to the verified interval and does not establish an untrusted anchor's origin.

Production anchored dispatch now checks this requirement under its existing
proposal/leader barrier before preparing runtime work. It also requires a spare
physical slot for the next leader's mandatory no-op. This is a capacity check,
not a reservation lasting after dispatch returns: competing work can still
consume headroom before later acknowledgement unless the incomplete-lifecycle
reservation is implemented. Future finalization work that has not yet been
prepared is not included in this set's cost.

Native fixtures cover the two-entry fresh cost, one-entry retained cost, empty
sets, duplicate/oversized sets, late anchors, acknowledged work and a mixed
retained/unseen set costing three in either order. The synthetic unseen envelope
used for the mixed-set check is not executed or claimed to be authorized.
Exhausted-capacity and cross-process recovery remain release gates, as does the
continuous reservation across capture, dispatch, finalization and retirement.

Final-source verification: **11 native bootstrap/lifecycle tests passed**
(124.04s, `r16-pending-management-budget.log`) and **7 network tests passed**
(0.39s, `r16-pending-management-network.log`). Formatting and diff checks pass.
Evidence remains in disk scratch; no rebuilt-CLI smoke or full release run is
claimed from these targeted results.

### Pending management admission and atomic retirement handoff

The internal network recovery constructor now accepts a bounded, independently
verified set of prepared management envelopes and their saved journal anchors.
Before worker/route publication it validates the entire set's journal evidence
and combined Invoke/acknowledgement budget, including the leader-promotion no-op.
It rechecks capacity after promotion and never checkpoints away these anchors
to make recovery fit. Missing agents, malformed/duplicate envelopes, and
coexisting projection/retirement recovery are rejected.

While this set is pending, only an exact saved envelope with its exact anchor
can invoke. Ordinary traffic, projection reservations, acknowledgements and new
anchor publication remain excluded. Refresh reinstates the same full set before
publishing the replacement route. An explicit handoff requires every pending
identity, successful retained terminal results, a committed leader/application
barrier, and the joint acknowledgement budget. It replaces pending admission
with retirement admission under one proposal lock; failed or partial handoffs
leave the original protection intact. The lifecycle owner must independently
verify authorization/finalization pairing; network identity coverage alone is
not that proof.

Native physical fixtures now prepare four signed Authority calls before any is
submitted, attach with that pending set, reject premature handoff, execute each
call once, and refresh between submissions. Retained retries leave Ordered
unchanged. Checks reject wrong anchors, unknown work, ordinary dispatch, both
acknowledgement paths, new anchor publication and partial retirement handoff.
The full handoff feeds the existing two-pair retirement test, including failed
completion callbacks and refresh while another pair remains protected. These
are in-process physical-journal/network tests, not filesystem startup adoption
or independently verified lifecycle pairing.

Final-source verification: **11 native bootstrap/lifecycle tests passed**
(140.34s, `r16-pending-gate-final.log`) and **7 network tests passed**
(0.36s, `r16-pending-gate-network.log`). An earlier retained-only version passed
23 tests selected by `native_` (144.47s, `r16-pending-gate.log`); that broader
selection is not a final-source full-library run. Formatting and diff checks
pass. Logs remain under `.worktrees/ch08-c2-native/target/task-tmp` relative to
the main checkout. No guest artifacts changed and no new CLI smoke is claimed.

This constructor is **not wired into production startup yet**. Still required:
adopt all verified lifecycle-store leases before route activation; continuously
protect capture/store-error/dispatch/application/finalization transitions;
handle future unprepared finalization, pending projections, exhausted capacity,
and process restart. This scoped change does not enable production retirement,
ordinary Shared finality, actor install ingress, or master readiness.

### Retained lifecycle-store leases and corrected clock coverage

The native Local lifecycle controller now retains each intent/issuer store pair
instead of reacquiring its filesystem paths for every Create retry. Protocol
state is still reloaded and validated on every attempt using borrowed stores;
a failed commit can already be durable and must not reuse poisoned cached state.
Both handles remain owned through failure, retry, and route-worker retirement,
and are released with the controller. Rejected request authentication still
precedes creation of any new store directory.

`LocalLifecycleController::with_recovery` adopts the verified discovery result's
existing handles without reacquiring their leases. The recovery result now also
retains its independently supplied Authority target; adoption rejects a target
different from the system owner's pins. This is store ownership transfer, not
proof of journal admission or an automatic startup recovery implementation.
Production startup still needs the full pending set installed before routes,
plus continuous management phase extension/error handling before retirement can
be enabled.

Native fixtures cover fresh and recovered handles, an intent commit that writes
successfully then reports failure, retry with durable reload, unchanged factory
open count, exclusive-handle retention through route retirement and release on
shutdown. The lease counter fixture is not an OS-lock proof. A separate `vosx`
filesystem test stages replacements for both lifecycle images, reloads through
borrowed handles, verifies reconciliation, and verifies the actual writer lock
remains busy until both handles are dropped.

Coverage correction: the native fixture previously routed every mode >= 2 into
the generic controller case. Consequently the tests named for authorization
and finalization clock advance (modes 6/7) did not reach their intended branches.
Earlier pass counts are historical execution results, not evidence for those
two named scenarios. The dispatch now explicitly selects controller modes
2/3/8, allowing both clock cases to execute their dedicated assertions.

Verification: **12 native bootstrap/lifecycle tests passed**, including both
corrected clock branches (241.53s, `r16-lifecycle-leases-native.log`), and **10
`vosx` lifecycle-store tests passed** (0.09s, `r16-lifecycle-leases-files.log`).
Formatting and diff checks pass. Logs are in the shared disk-backed
`target/task-tmp` directory documented above. This is targeted source coverage,
not a rebuilt-CLI deployment smoke, full-library run or release approval.

### Startup discovery before attachment and finalized-result retirement

Native `vosx` startup now discovers and exclusively leases all Local lifecycle
store candidates before constructing the system owner. A bounded opaque
admission value is derived from the independently verified set and checked
against the durable bootstrap Authority target. Existing finalized work cannot
cause fresh bootstrap planning or attach against an incomplete bootstrap record.
Unretired finalized envelope pairs seed the complete network retirement set
before worker/route publication; that attachment never checkpoints away the
required Linear evidence. Durable CMR2-completed entries need no journal suffix.

The recovering controller first rechecks every finalized acknowledgement against
its actual Local image and durable application observation. It then acknowledges
and commits retirement markers under the restored admission restriction before
normal lifecycle and projection routes are started. All original store handles
transfer into the controller. Marker-complete entries are verified but not
released against another intent's pending reservation.

This is a production startup integration, but not complete crash recovery.
Prepared incomplete phases currently reject startup before system attachment;
they are not silently omitted, replayed without protection, or erased. A remaining
pending projection combined with management retirement also rejects attachment.
Continuous live protection, incomplete-phase recovery/extension, combined pending
projection recovery, exhausted-capacity recovery and subsequent install/invoke
still must be finished. A successful ordinary Create may now be retired on its
next startup; this does not yet enable continuous live retirement.

The native restart fixture uses the original genesis archive, physical Shared
and Local host stores, and the normal factory/controller startup APIs. It checks
pre-cleanup projection rejection, a first reopen that publishes CMR2, a second
reopen without pending retirement, and exact Create retry after each. Lifecycle
images in this fixture remain lease-tracked memory stores; real filesystem
discovery/lease tests are separate. No cross-process CLI smoke is implied.

Final verification: **13 native tests passed** (251.39s,
`r16-startup-retirement-native-final.log`), **2 bootstrap factory tests passed**
(2.25s, `r16-startup-retirement-factory.log`), and **10 filesystem lifecycle
tests passed** (0.12s, `r16-startup-retirement-files-verified.log`). Formatting
and diff checks pass. Logs remain in shared disk scratch. The dedicated restart
case also passed separately (18.94s, `r16-startup-retirement-isolated.log`).
Earlier fixture attempts failed with stack overflow and a mistakenly fresh
empty genesis archive. The corrected fixture retains its original archive and
runs restart on a separate default-sized thread stack, without raising stack
limits. The first cleanup adds exactly two Ordered acknowledgements; the second
adds none. No new bundled artifacts or rebuilt-CLI smoke is claimed here.

### Mixed incomplete-work and retirement admission

Shared journal recovery now calculates one prospective Ordered chain for both
anchored incomplete invocations and older completed calls awaiting retirement.
The combined entry/byte budget rejects duplicate identities across the two
classes and an oversized combined set. Checking classes independently could
allow each to fit while their sum did not. Existing pending-only and retirement-only
checks now delegate to the same combined calculation.

The network recovery constructor can seed both classes before route publication.
Only the exact saved anchored Invoke is admitted for pending work; only reserved
acknowledgements are admitted for retirement work. Ordinary work, new anchor
publication and projection reservations stay blocked. Refresh retains both
classes and rechecks the combined budget before and after leader promotion.
Completing an older retirement leaves pending-work exclusion in place. The
pending-to-retirement handoff includes every pending identity and preserves all
existing retirement pairs under the proposal lock, instead of replacing them.

Native fixtures exercise an already acknowledged older pair alongside four
prepared signed calls, a failed retirement completion callback followed by
refresh, and successful older-pair completion without releasing pending work.
After two fresh invocations, two unseen calls plus two retained retirement calls
require six prospective entries. The fixture reattaches in that mixed state,
rejects invoking a retirement-only member, executes remaining pending work,
and transfers it without losing the older pair. Cross-class duplicate identities
are rejected both by the journal budget and before network attachment.

This is the shared admission mechanism required by incomplete startup recovery;
it does **not** yet enable that recovery in `vosx`. The next integration remains
recovery of the durable application acknowledgement and saved finalization call,
then phase extension for authorization-only work. The startup classifier still
rejects incomplete phases, and pending projections and exhausted-capacity
recovery remain open. These fixtures do not prove filesystem cross-process
recovery or the final release gates.

Verification: **13 native tests passed** (250.47s,
`r16-mixed-management-native-final.log`) and **7 shared-network tests passed**
(0.43s, `r16-mixed-management-network.log`). The initial focused native mixed
recovery run also passed (104.74s, `r16-mixed-management-gate.log`), before the
last duplicate/retirement-only dispatch assertions were added. Formatting and
diff checks pass; logs remain in the shared disk-backed scratch directory.

### Saved-finalization recovery in production startup

The issuer can now independently recover an exact durable signed application
acknowledgement without claiming that the Authority finalization call completed.
It validates the signed credential call, request, managed target, reconstructed
decision, receipt and acknowledgement against the issuer image. This read-only
operation neither signs nor advances the finalization barrier. Existing finalized
recovery retains its stricter completed-barrier requirement.

Lifecycle discovery validates saved finalization work against that exact
acknowledgement and rejects hidden outstanding issuer work. Startup admission
classifies both saved anchored envelopes as pending when the issuer has not yet
recorded finalization. The system owner seeds the combined pending/retirement
set before attaching routes and does not checkpoint away its evidence.

The recovering controller rechecks every recorded application against the
physical Local image first, then replays only already-saved finalization calls
using their original preflight clocks and journal anchors. After every pending
finalization has a durable issuer marker, it atomically hands those pairs into
the existing retirement set and publishes CMR2 markers under admission exclusion.
Already-retired entries continue to use their durable marker rather than a
possibly pruned journal suffix.

Two native interruption cases now exercise the production startup APIs: failure
after finalization-envelope persistence but before dispatch, and failure after
successful durable invocation/replay but before issuer finalization persistence.
The clock advances before restart. The first case adds one Invoke and two Acks;
the second adds only two Acks. A second restart adds no Ordered entries, and
exact Create retry returns the same acknowledgement after both restarts. These
are injected between-action failures with physical host journals and Local
images plus lease-tracked in-memory lifecycle stores, not cross-process file
write fault injection or an end-to-end CLI deployment smoke.

Earlier authorization/application phases, creation of a not-yet-saved finalization
envelope, continuous live admission protection, pending projection coexistence,
exhausted/pruned evidence recovery, install/invoke and release gates remain open.
Saved-finalization recovery requires its authenticated anchors and retained
authorization evidence; it does not paper over evidence lost before startup.

Verification: **15 native tests passed** (288.16s,
`r16-saved-finalization-native-final.log`), **12 issuer tests passed** (4.04s,
`r16-saved-finalization-issuer.log`), and **10 filesystem tests passed** (0.09s,
`r16-saved-finalization-files.log`). The three focused startup cases also passed
(44.89s, `r16-saved-finalization-startup-isolated.log`). Formatting and diff checks
pass; evidence remains in shared disk scratch. An initial fixture run overflowed
its stack during bootstrap replay beneath the large multiphase caller, located
with a debugger (`r16-saved-finalization-stack.log`). Fixture bootstrap now runs
on its own default-sized thread stack; stack limits were not increased. No guest
artifact rebuild, full-library run or fresh CLI deployment smoke is claimed.

### Protected pending-phase extension prerequisite

The network attachment can now extend an existing verified management-pending
reservation before invoking the independent intent-store callback. It verifies
the exact reserved predecessor and both refresh/admission images, excludes
projection work and retirement identity collisions, then jointly budgets the
expanded pending set and existing retirement pairs under the serialized leader,
full-commit and journal-drain barrier. Insufficient capacity fails without
checkpointing or publishing a new image.

Both the proposal gate and its attachment-refresh image retain the candidate
before the callback runs. An ambiguous callback failure does not release it.
A retry may propose a later preflight clock, but receives the original exact
envelope and anchor; changed invocation contents are rejected. The caller must
authenticate the phase transition and persist the returned pair, not its newly
proposed envelope. This is an internal prerequisite, **not yet wired into
production lifecycle startup**. Earlier missing-finalization startup remains
fail-closed; no release gate is declared closed by this change.

Next integration remains within C2: admit an acknowledged application with only
its saved authorization envelope; use protected extension when preparing its
missing finalization; build retirement pairs from the resulting durable slots;
test interruption before preparation and ambiguous intent writes across restart.
Do not enable earlier authorization/application phases or continuous live
retirement merely because this lower-level operation exists.

Verification: the native bundled-Authority lifecycle regression passed (1 test,
108.70s, `r16-pending-extension-native.log`), now including mixed pending/retiring
extension, a failed callback, attachment refresh, original-clock retry and
substituted predecessor/next-work rejection. The 7 adjacent network tests passed
(0.36s, `r16-pending-extension-network.log`). Logs are in shared disk scratch.
Formatting and diff checks pass. This uses a test callback rather than actual
filesystem write-fault injection; no full-library rerun, rebuilt guest artifacts
or new CLI smoke is claimed.

### Startup prepares missing finalization after observed application

The pending-phase extension prerequisite above is now used by production
lifecycle startup. A verified durable application acknowledgement can enter
startup with only its saved anchored authorization envelope. The controller
rechecks every observed application against its physical Local image before
finalizing any member. It reserves a missing finalization envelope jointly with
the complete pending/retiring set before pledging its exact envelope and anchor.
Saved finalizations keep their saved clock; missing finalizations receive the
current recovery clock. Retirement handoff uses the resulting durable slots,
not the initial one-envelope admission image, and normal routes remain behind
controller recovery.

A new native test interrupts after application acknowledgement but before
finalization preparation. First restart requires one pending authorization,
adds one finalization Invoke and two positive Acks, and records CMR2. Its saved
finalization uses the advanced restart clock. A second restart adds no Ordered
entries and exact Create retry returns the same acknowledgement after both
restarts. This uses physical host journals/Local images and lease-tracked memory
lifecycle stores; it is not a cross-process filesystem fault campaign.

Earlier authorization/application recovery, continuous live protection,
unfinished-projection coexistence, capacity/pruned-evidence recovery and native
install/invoke remain open. No artifact rebuild, current CLI smoke or full
release-gate completion is implied.

Verification: the `native_` library filter reported **28 passed** (315.45s,
`r16-missing-finalization-native-final.log`), including all **16 native bootstrap/
lifecycle tests**. One unrelated extension test returned early because the
echo-extension fixture was not built; its green result is not extension
coverage. The filesystem lifecycle filter passed **10 tests** (0.04s,
`r16-missing-finalization-files.log`). The first focused startup run passed all
4 cases (69.57s, `r16-missing-finalization-startup.log`); final clock/CMR2 assertions
are covered by the later native run. Evidence is in shared disk scratch.
Formatting and diff checks pass.

### Startup observes an unacknowledged durable Local application

Issuer recovery now exposes a read-only lookup for the exact latest issued
application receipt. It binds the signed call, independent Authority target,
managed agent, request, and reconstructed authorized decision. Pending issuance
is not a receipt; forged calls and poisoned issuers reject. It does not sign,
observe application, or advance a watermark.

Lifecycle discovery can admit the saved authorization envelope for that receipt
even before an application acknowledgement exists. Before any missing
acknowledgement is signed, startup re-observes **all** recovered applications by
reopening their physical Local images and runtime/catalog artifacts. It then
recovers or signs the acknowledgement against the original durable application
state/slot and uses protected finalization/retirement before normal routes.
This handles an already-durable Create, not creation with an unavailable runtime
or missing Local image. A receipt without physical application still fails shut.

The new native test interrupts after physical Create observation but before
acknowledgement publication. It verifies the outstanding receipt and absent
acknowledgement, then restarts with an advanced clock. Recovery adds one
finalization Invoke and two Acks; the acknowledgement keeps the original
application slot and the finalization envelope uses the restart slot. A second
restart adds no Ordered work and exact retries return the same signed result.
Fixtures use physical Local images/host journals and lease-tracked in-memory
lifecycle stores, not a cross-process filesystem fault campaign.

Remaining C2 recovery work includes pending authorization/issuance, obtaining
the exact runtime and finishing Create when no durable Local image exists,
ambiguous filesystem writes across process restart, continuous live protection,
and unfinished-projection/capacity/GC cases. Native install/invoke and the other
release gates remain open; bundles and deployment smoke were not refreshed.

Verification: **5 startup tests passed** on the corrected final fixture (82.17s,
`r16-unacknowledged-local-startup-final.log`), **12 issuer tests passed** (4.36s,
`r16-unacknowledged-local-issuer.log`), and **10 filesystem tests passed** (0.11s,
`r16-unacknowledged-local-files.log`). The broader native run passed its 16
existing tests but failed the new test's initial hard-coded application-slot
assertion (357.94s, `r16-unacknowledged-local-native-final.log`). Diagnostic output
showed 22 versus 20: bootstrap had advanced the fixture clock twice before
Create. The assertion now captures the actual pre-Create clock; the final five
startup tests above include that correction. Production code did not change
between those runs. This is not a claim of a single all-green full native rerun.
Logs remain in shared disk scratch; formatting and diff checks pass.

### Retained Create runtime and recovery before Local image creation

Authenticated Create now retains its exact admitted runtime package after
pledging the intent but before authorization/issuance. The runtime has an
independent immutable whole-image store under the intent/issuer writer lease;
storage failures poison the live intent slot and retries reload without dropping
the lease. In vosx this is `management.runtime`/`management.runtime.next`, CSF1
role 11, bounded by `MAX_PACKAGE_ENCODED_BYTES`. Existing private-file validation,
role separation, predecessor-bound staged publication and directory syncing are
reused. CMI4/CMR2 remain unchanged. Older completed intents need no runtime sidecar
for physical re-observation, but an older missing-image intent without this
artifact cannot be reconstructed from a substitute/default runtime.

Startup with an issued receipt and no Local image loads and re-admits the saved
package, checks its complete descriptor binding, then applies Create. It checks
all existing images and needed package bindings before creating missing images;
all resulting physical applications are observed before signing any missing
acknowledgement. Protected finalization and retirement follow as before. An
already-recorded application acknowledgement cannot authorize recreating a
missing image. Expired first application still fails; this does not bypass
receipt expiry or implement reauthorization/cancellation.

The new positive native case interrupts after receipt issuance but before
physical Create, recovers using only retained stores, and verifies current-slot
application/finalization followed by a zero-Ordered-work second restart and exact
retry. Missing/corrupt runtime cases require no created agent, unchanged issuer
state, and released leases after rejection. The filesystem tests cover staged
runtime publication, borrowed reload, immutable retry, writer exclusion and
cross-role rejection; raw file payload tests are not package-admission proof.

Pending authorization/issuance, continuous protection throughout live creation,
cross-process filesystem fault campaigns, projection/capacity/GC cases and
expired-operation resolution remain open, along with native install/invoke and
the release gates. No bundle rebuild or fresh deployment smoke is claimed.

Verification: **20 native bootstrap/lifecycle tests passed** (347.78s,
`r16-retained-runtime-native-final.log`), and **12 filesystem lifecycle tests
passed** (0.09s, `r16-retained-runtime-files.log`). The focused positive recovery
also passed (13.83s, `r16-retained-runtime-startup-final.log`). Its initial fixture
attempt reused the post-expiry replay clock and was refused
(`r16-retained-runtime-startup.log`); first application is now tested at slot 23,
within the signed window, rather than slot 40. Receipt-expiry enforcement was
not weakened. Logs remain in shared disk scratch. Formatting and diff checks
pass; the full feature/release matrix remains pending.

### Startup replays saved authorization and unfinished receipt issuance

Initial Create recovery now accepts a saved anchored authorization envelope with
an empty issuer or an exact first-decision issuance pledge. The new read-only
issuer eligibility check binds the signed call, independent Authority/managed
scope, request and any pending decision, and excludes existing receipt histories.
Eligibility is not approval. Startup validates required runtime packages first,
then invokes the existing anchored Authority replay path and issues only its
actual accepted approval before physical Create, acknowledgement, finalization
and retirement. It never signs a receipt merely from the pending issuer image.

New native cases interrupt before authorization dispatch, after its accepted
reply but before issuance, and during receipt signing after the durable pledge.
They verify absent receipts, the exact pending/no-pending issuer state, read-only
eligibility, forged-call rejection and a mismatched signed call against an
existing pledge. First recovery adds two Invokes plus two Acks for an unaccepted
authorization, or one Invoke plus two Acks when authorization was already
accepted. Second restart adds no Ordered entries and exact retry preserves the
signed acknowledgement. First physical application remains inside receipt expiry.

The Authority permits only one outstanding application per credential and
requires exact request sequence. Startup therefore rejects a recovery set that
needs authorization while another unretired intent shares that credential,
before attachment/dispatch. This prevents agent-ID iteration order from recording
a terminal denial. The guard permits independent credentials and unchanged
already-issued recovery sets; it is not completion of dependent-set recovery.
Next, recovery needs partial pending-to-retirement handoff and per-credential
phase sequencing before that guard can be removed. Pristine intents with no
authorization envelope still await exact client retry. Continuous live admission,
capacity/GC/projection cases, denial/expiry resolution, cross-process filesystem
fault campaigns, install/invoke and release gates remain open.

Verification: **23 native bootstrap/lifecycle tests passed** (412.76s,
`r16-unissued-create-native-final.log`), **12 issuer tests passed** (4.74s,
`r16-unissued-create-issuer.log`), and **12 filesystem tests passed** (0.11s,
`r16-unissued-create-files.log`). After the final dependency guard was added,
its focused order/independence test passed (`r16-unissued-create-dependencies.log`)
and all **11 startup cases passed again** (142.19s,
`r16-unissued-create-startup-final.log`). The broader native run preceded that
last guard; it is not a final full-library or release-matrix run. Formatting and
diff checks pass; logs remain in shared disk scratch. No guest artifacts or CLI
deployment smoke were refreshed.

### Partial pending-to-retirement handoff prerequisite

The network owner can now move a strict subset of finished management pairs
into retirement while keeping the rest pending. Under the serialized leader,
full-commit and journal-drain barrier, it validates exact coverage of the old
reservation set: every member is either still pending with its original anchor
or belongs to a completed retiring pair. Existing retirement pair grouping is
preserved. Joint suffix/physical capacity includes the remaining pending work,
not just the pairs being retired. Both proposal admission and refresh images
retain the remaining set.

The native mixed-management fixture now uses the live partial handoff instead
of manually rebuilding the mixed attachment after its first pair completes.
It also acknowledges and completes one pair while a second remains pending,
including callback failure, refresh, successful completion, repeated no-op
release, another refresh, and eventual completion of the second pair. Query
admission remains excluded until the remaining pair is retired. Unaccepted work
and invalid pair identities still cannot be moved into retirement.

The same-credential startup guard remains in place. Next integration must order
pending intents by credential request sequence and complete each lifecycle's
retirement before authorizing the next dependent call, with a reversed-agent-ID
multi-intent native restart test. The current controller still batches its
phases; partial network handoff alone does not close dependent-set recovery or
continuous live admission protection. No release gate or deployment readiness
is claimed by this prerequisite.

Verification: the native bundled-Authority management regression passed (1 test,
104.02s, `r16-partial-retirement-native-final.log`) and 7 adjacent network tests
passed (0.47s, `r16-partial-retirement-network.log`). The initial native run failed
an old assertion expecting repeated release to conflict when another pair was
retiring. That pair is now pending, so release is a harmless no-op; the corrected
test instead verifies that query admission and refresh remain protected. No
production release behavior was weakened to satisfy the assertion. Formatting
and diff checks pass; logs remain in shared disk scratch. No broad native/full
library rerun, guest rebuild or CLI smoke is claimed for this prerequisite.

### Clock-compatible dependent startup recovery

Startup admission now validates signed credential sequence order independently
of Agent directory order. It rejects duplicate sequences, a known pristine
client-only predecessor, and a predecessor needing fresh finalization before
an unissued successor. Already-issued predecessors with saved finalization can
complete first using partial pending-to-retirement handoff. Their saved clocks
must not exceed the earliest unissued authorization clock; ties preserve
credential order. Physical Local images and required retained runtimes are
checked before advancing that prefix. Remaining independent requests retain
the existing all-authorizations-before-fresh-finalizations pipeline.

The native two-agent fixture deliberately makes Agent ID order the reverse of
signed request order. The compatible case starts with the predecessor's
authorization accepted and finalization saved, and the successor's authorization
saved but unaccepted. Recovery uses the real bundled Authority and Local runtime,
adds exactly seven Ordered entries (one authorization, two finalizations and four
positive ACKs), and leaves two physical Local images and durable retirement
markers. Exact retries return verified identical ACKs; a second restart adds no
Ordered entries. The stores in this fixture are memory-backed and do not claim
new filesystem crash/lease coverage.

Two negative native cases preserve issuer/intent images and journal position:
both requests lack finalization, or the successor was captured before its
predecessor's later finalization clock. These remain explicit startup blockers,
not terminal denials or rewritten envelopes.

The initial unrestricted sequential experiment failed on the second saved
authorization with `Completed(Err(AuthoritySlotRegressed))`: fresh predecessor
finalization advanced slot 22 to 23 while the successor retained slot 22.
Evidence is `r16-sequential-recovery-diagnostic-outcome.log` in shared disk
scratch. The final design preserves the runtime check and rejects that set
before dispatch. Merely sorting requests or retiring the predecessor is not a
general solution. Continuous live admission must prevent capturing overlapping
successors until their prerequisites are complete; denial/expiry resolution
and interrupted-set recovery beyond the supported prefix remain open.

Verification on the final source: **14 native startup tests passed**, zero
failed, in 175.30s (`r16-sequential-recovery-startup-final.log`); the pure ordering
and rejection test also passed (`r16-sequential-recovery-order-final.log`).
Formatting and diff checks pass. Logs are under
`.worktrees/ch08-c2-native/target/task-tmp`, relative to the main checkout.
The earlier 13-test run passed on the intermediate pipeline, not the final
independent-request-preserving implementation; it is not substituted for the
final run above.

No source freeze, guest rebuild, CLI smoke, broad library rerun or release
readiness is claimed here. Keep this checkpoint within C2, with C1/C2/C3 as the
three eventual review batches; root `saga/agents` and `master` are not promoted.

### Initial live management capture reservation

`SharedAgentNetworkHost::capture_management_pending` now captures an initial
envelope and journal anchor under the existing serialized Leader/full-commit,
drained-host and proposal-admission boundary. It validates current-phase
slot/byte admission, installs the pending key and root refresh image, and only
then invokes the independent intent-store callback. A callback failure retains
that exact reservation. A retry with the same invocation work receives its
original envelope, clock and anchor; a different request cannot append itself.
Failures before reservation remove the otherwise-empty root entry. Existing
protected phase extension shares this machinery with an explicit predecessor;
initial capture cannot bypass pending projection or retirement admission.

The native bundled-Authority regression now covers a failed capture callback,
unchanged Ordered position, generation refresh, exact retry despite a later
proposed clock, and rejection of an overlapping capture, unprotected anchor
write and projection reservation. It then runs the existing mixed-set extension
and partial-retirement checks. This is network admission evidence, not a
filesystem crash campaign or proof of fresh credential-policy sequencing.

Verification: the native regression passed (1 test, 105.60s,
`r16-initial-capture-native-final.log`), and 7 adjacent network tests passed
(0.58s, `r16-initial-capture-network.log`). An initial mistyped filter selected
zero tests (`r16-initial-capture-native.log`); it is not verification evidence.
Logs remain in shared disk scratch under
`.worktrees/ch08-c2-native/target/task-tmp` relative to the main checkout.

Production lifecycle callers have **not** switched to this operation yet.
The current-phase reservation does not prove capacity for the future
finalization envelope. Next, switch initial capture, protected finalization
extension, pending-to-retirement handoff and live retirement together; preserve
exact retry/reopen after each failed store publication, and prove whole-lifecycle
capacity before dispatch. Switching only capture would strand callers at their
unprotected finalization step. Continuous live protection, complete dependent
recovery and the previously listed C1/C2/C3 release gates remain open. This is
another internal C2 checkpoint, not a new review batch or deployment claim.

### Protected live Local Create through retirement

The native controller's public `create_local_agent` path now captures initial
authorization under persistent pending admission, uses protected finalization
extension, hands off the pair to retirement, positively acknowledges both
runtime results, and commits CMR2 before reporting success. Physical Local
application and independently reopened issuer evidence remain required. A saved
authorization can resume on this path only if its exact envelope/anchor is in
both the root refresh image and live coordinator reservation; possession of a
saved intent alone cannot dispatch it without protection.

Initial capture now budgets both remaining authorization/ACK records and two
future finalization/ACK records. The future byte allowance derives from the
actual authorization Ordered encodings plus the full SDK invocation-message
limit and possible parent-hash growth for each record. Finalization copies the
same work, replaces fixed-width identities, uses anonymous origin and a bounded
message, so this overestimates its size without manufacturing an acknowledgement
as application evidence. Physical generation headroom still requires one spare
slot. Protected extension later checks the exact final envelope. Boundary and
filesystem crash campaigns remain release gates; a passing normal-sized native
fixture is not proof of those campaigns.

Retirement handoff now accepts an exact already-retiring pair idempotently,
without duplicating it or changing other pending members. If retirement-store
publication persists CMR2 and then fails, a same-process retry revalidates the
durable marker and releases that exact reservation. Returning an ACK without
this release would strand the next request, so that case has a native regression.

The new live two-agent test interrupts authorization preparation, rejects the
successor before it captures an authorization, restarts and completes the first
request, then creates and retires the successor normally. Both signed ACKs are
verified and exact repeated delivery adds no Ordered entries. Historical
overlapping-store tests now construct their residues through low-level fixture
primitives: the public live path deliberately can no longer create those stores.
The pre-retirement startup test now interrupts the actual live handoff, rather
than relying on successful Create leaving retirement until restart.

Verification so far: 21 native Local regressions passed (266.05s,
`r16-live-admission-native.log`) before the final exact-membership and
post-commit-release adjustments. On the adjusted production source, both live
overlap/restart and committed-retirement retry tests passed (60.80s,
`r16-live-admission-live-verified.log`), 12 vosx lifecycle file tests passed
(0.13s, `r16-live-admission-files.log`), and 7 adjacent network tests passed
(0.43s, `r16-live-admission-network.log`). The native admission/extension/retirement
regression also passed (141.72s, `r16-live-admission-capacity.log`), including
current-phase cost of two records versus initial full-lifecycle cost of four.
The final same-process prepared-authorization retry also passed (1 test,
24.42s, `r16-live-admission-prepared-retry.log`): the successor remains blocked
until the exact saved request finishes, then both requests retire with exactly
eight total Ordered entries and no additional entries on repeated delivery.
These are targeted results, not a final full-library rerun. Logs remain under
`.worktrees/ch08-c2-native/target/task-tmp`, relative to the main checkout.

Two intermediate live-test runs overflowed the combined setup/runtime stack
(`r16-live-admission-retirement-retry.log` and
`r16-live-admission-live-final.log`). Moving the retirement retry sequence to its
own normal-sized execution thread fixed the fixture; stack limits were not
increased. The passing final live checks above include that correction.

Next: resolve denied/expired requests without abandoning admission or durable
evidence, complete physical fault/capacity gates, and continue native actor
installation/invocation and ordinary Shared finality. No rebuilt-CLI smoke,
source freeze, guest rebuild, release certification or branch promotion is
claimed by this C2 checkpoint.

### Independently replayed unissued-denial evidence

`verify_management_denial` now distinguishes an executed canonical Authority
denial from an approval awaiting issuance. It authenticates the retained signed
Create against independent bootstrap pins, requires an empty matching issuer
with no pending issuance, no finalization/retirement marker and no Local
application, and requires the exact live envelope/anchor reservation. It walks
the anchored journal to the retained invocation and uses a fresh replay executor
to recover its terminal result, reconciling replay state/heads with the physical
journal and ledger. Reply identity and Done status must match the exact work.
Only the byte-for-byte canonical encoding of an empty byte value qualifies;
transport/runtime failures, malformed responses and nonempty approvals do not.

The resulting evidence binds the credential-call commitment, immutable envelope,
anchor and journal input ID. Its fields cannot be constructed outside the pinned
owner module. It is deliberately ephemeral: it is not a durable denial marker
and does not authorize releasing admission or signing an application ACK.

Native regressions send a genuine signed out-of-sequence request through the
bundled Authority and compare it with a valid authorization interrupted before
receipt issuance. The denial alone yields evidence, including after attachment
refresh. Both cases retain one Ordered invocation, zero receipt/ACK signatures,
unchanged issuer/intent images and no Local Agent; the reservation remains held.
A substituted issuer scope is rejected. All 15 tests selected by `denial` passed
(11.15s, `r16-denial-evidence-verified.log`), including both native controls and
adjacent existing denial tests. The initial compile attempt failed on an absent
decode-trait import; exact canonical-byte comparison replaced decoding and is
what the verified run exercised. Logs remain in shared disk scratch.

This evidence helper is not yet invoked by automatic denial cleanup. Next, add
a durable denial disposition and single-authorization positive-ACK retirement,
including recovery when the host marker or ACK publication fails. The completed
disposition must remain independently verifiable after runtime result pruning;
an empty issuer, local error or discarded CMI4 file is not that proof. Client
credential retry bookkeeping and expiry/abort handling still need their own
verified completion semantics. No release readiness or branch promotion is
claimed by this C2 checkpoint.

### Signed server-side denial retirement

The preceding evidence-only checkpoint is now extended into live Create and
startup recovery. Only independently replayed canonical empty-byte denials of
the exact signed, anchored authorization qualify. The issuer must remain empty
and the Local Agent absent. An approval, malformed response, trap, or transport
failure cannot become a denial disposition.

A dedicated reserved route positively acknowledges the single authorization
result. The host then signs a domain-separated commitment to the full retained
intent and durably publishes CND1 in the existing intent store before releasing
only that pending member. This is neither a management approval nor an application
ACK, and does not manufacture a two-result retirement pair. Store errors preserve
admission even when publication may already have succeeded. A completed CND1
verifies against the independently pinned Authority key without retaining the
runtime result; it cannot be overwritten by a different request or reissued.

Recovery after the runtime ACK uses a separate bounded anchored walker accepting
exactly the original Invoke and its following exact ACK. Ordinary pending-Invoke
lookup stays strict. Admission grants zero additional journal slots only for an
exact positively acknowledged canonical denial; acknowledged approvals remain
rejected. Fresh replay still reconciles journal heads and state before signing.
Completed denials do not consume credential sequence and are omitted from startup
credential predecessor ordering. A subsequent valid request for a different Agent
at the original credential sequence succeeds in the native regression.

Targeted evidence in `.worktrees/ch08-c2-native/target/task-tmp`:

- `r16-denial-retirement-final.log`: 19 denial tests passed (67.15s), including
  automatic retirement, signer failure after ACK, ambiguous CND1 publication,
  restart after ACK, a second restart after signed completion, tampered-signature
  rejection, and subsequent valid creation without duplicate journal work.
- `r16-denial-retirement-approved-guard.log`: native management regression passed
  (1 test, 127.62s), including rejection of an acknowledged approval as pending
  denial recovery.
- `r16-denial-retirement-network.log`: 7 adjacent network tests passed (0.71s).
- `r16-denial-retirement-live-verified.log`: 3 live overlap/restart, prepared
  authorization retry, and committed-retirement retry tests passed (73.92s).
- `r16-denial-retirement-files.log`: 12 vosx lifecycle file tests passed (0.18s),
  compiling the production identity signer implementation.
- `r16-denial-retirement-startup.log`: 14 startup tests passed (175.77s) after
  initial CND1 integration but before the final post-ACK walker/retry changes;
  this is intermediate-source evidence, not a final-source startup-suite claim.

Initial compilation exposed the decoder's 32-byte fixed-field limit; the
64-byte signature now uses two such reads. An intermediate fault run passed 17
tests and failed two post-ACK retries (`r16-denial-retirement-faults.log`): strict
ordinary invocation lookup correctly rejected an invocation hidden behind its
ACK. The dedicated denial walker and fresh anchored replay fixed those failures;
the final 19-test result above includes both cases.
The initial live regression overflowed the combined setup/runtime stack
(`r16-denial-retirement-live.log`). Moving dependent lifecycle fixture execution
onto its own default-sized thread fixed all three live checks; stack limits were
not increased. Formatting and `git diff --check` also passed.

These native fixtures use real bundled Authority/runtime execution and Local
filesystem images with memory-backed intent/issuer fault stores. They do not
certify cross-process host-store crashes, checkpoint/GC pruning, or full capacity
boundaries. No guest or SDK artifact ABI changed; final artifact/source freeze
still remains. Client transport currently returns `ScopeMismatch`, not a signed
denial response, so client credential retry bookkeeping remains open. Expiry or
abort after approval/issuance and runtime failures retain their protected evidence.
No full-library rerun, rebuilt-CLI smoke, release certification, or branch
promotion is claimed. Fold this checkpoint into C2, not a separate review batch.

### Exact-request client denial verification

`LocalCreateSubmission::verify_denial` now verifies a bounded CND1 response
against the independently retained full Create and credential call, including
its Authority binding. Signature validation against a key supplied only by the
response is insufficient: both embedded inputs must exactly equal the retained
submission, whose credential signature and shape are checked again. The returned
`LocalCreateDenial` has private bytes and no unchecked constructor, and exposes
the exact verified certificate for durable retention. It is not an application
ACK, approval, route check, or credential-sequence advancement.

Native denial fixtures now exercise this client-facing verifier against actual
server certificates, including after recovery. They also reject truncation,
trailing bytes, oversized input, altered signatures, a positive-retirement tag,
and substitution for a different valid signed Create. Verification requires no
server journal/store access. Callers must still establish their retained request's
Space/operator/Authority from independent local pins, as the current Create CLI
already does for acknowledgement handling.

All 5 native denial tests passed (68.83s), including startup after a positive
runtime ACK and reopening signed completion. Evidence:
`.worktrees/ch08-c2-native/target/task-tmp/r16-denial-client-verification.log`.
Formatting and `git diff --check` passed. This is targeted verification, not a
full-library or CLI end-to-end release run.

This is verification infrastructure, not completed CLI denial handling. Next wire
the typed disposition through the lifecycle controller/queue and HTTP response,
persist the verified certificate in a distinct leased client store before marking
the reservation denied, and let a new operation discover the current credential
sequence. Preserve exact retry after every ambiguous HTTP or store outcome;
neither a generic HTTP error nor `ScopeMismatch` can release the credential lease.
Keep these changes in the existing C2 review batch.

### Typed native denial delivery

The native queue now carries `LocalCreateDisposition::{Created, Denied}` rather
than assuming every completed operation created an Agent. The production owner
still runs the existing authenticated Create path first. Only its scope-rejection
result may trigger certificate lookup; the concrete controller reads the already
leased retained intent, checks its Authority against the live system pins, and
verifies CND1 against the exact submitted request. Missing stores or an ordinary
pending intent yield no certificate. Other lifecycle implementations default to
no denial evidence. Generic failures, signer/storage errors, and timeouts remain
errors; no journal work or successful route publication is manufactured for denial.

The HTTP endpoint preserves 201 plus MAA2 for successful creation and now sends
403 plus `application/octet-stream` CND1 for a verified denial. A generic scope
rejection remains a textual 403, incomplete work remains 503, and unknown timeout
remains 504. Clients must verify the binary certificate; HTTP status is not proof.
The existing CLI still treats these 403 responses as errors and retains its
reservation until the following client-persistence change is implemented.

Native fixtures additionally reopen the completed request through a concrete
lifecycle controller, recover the exact certificate from its retained stores,
reject absent/unrelated entries, and confirm no extra Ordered records. The first
compile attempt exposed the node method's old tuple reply type; it now forwards
the typed disposition consistently with the queue and HTTP consumer.

Verification: all 5 native denial tests passed (90.33s,
`r16-denial-disposition-verified.log`); all 12 vosx lifecycle file tests passed
(0.17s, `r16-denial-disposition-files.log`), also compiling the HTTP-enabled
production path. Logs are in shared disk scratch under
`.worktrees/ch08-c2-native/target/task-tmp`. Formatting and `git diff --check`
passed. No socket-level signed-denial response or CLI completion test is claimed
by these controller/file results.

Next: bounded client receipt of binary 403, immutable leased denial-file retention
before a distinct denied reservation marker, exact-response retry after ambiguous
publication, and actual HTTP/CLI end-to-end tests. This checkpoint does not close
client denial UX, expiry/abort, installation/invocation, Shared finality, or release
gates. It belongs in C2 and does not promote the implementation branch.

### Durable client denial and credential release

The managed Create CLI now accepts a binary HTTP 403 only after exact-request
CND1 verification. It preserves separate response limits: MAA2 retains its
original bound, CND1 uses its own bound. Textual 403, malformed/substituted or
oversized certificates, transport errors and unknown statuses remain failures
with the exact request and pending credential reservation retained.

CSF1 role 12 stores immutable `local-create.denial` under the operation's
`denial/` directory with an exclusive lease, staged-publication recovery and no
replacement predecessor. A distinct CRS1 tag 2 records Denied, committing to the
retained request and a domain-separated certificate digest. The reservation API
accepts an open denial-file store, re-verifies and synchronizes its certificate
before committing that marker; raw response bytes or unsigned errors cannot
complete it. Positive completion cannot replace denial or vice versa.

If a certificate was published before a failed reservation write, `--resume`
re-verifies it and completes denial locally without requiring another HTTP
response. A denied marker with missing evidence fails closed on resume, and
simultaneous acknowledgement/denial files are rejected. The CLI reports the
verified denial and instructs the user to start a new Create without `--resume`;
that new nonce goes through fresh authenticated sequence discovery rather than
incrementing sequence for a denied request. Existing request/certificate files
remain retained. The lower-level submit-only command still reports a verified
denial as an error and leaves its exact request; it does not own a credential
reservation.

All 6 Local Create tests passed (3.12s,
`r16-denial-client-flow-verified.log`). Coverage includes loopback HTTP delivery
of host-signed valid/tampered certificates and physical leased denial-file
publication, reopen before reservation completion, idempotent completion, new
nonce admission, and refusal to complete a different reservation. An initial
run failed the existing ACK oversize assertion because the shared response bound
was widened; response-specific limits fixed it and the final six-test run includes
the original assertion. The signed fixture models the host certificate, not an
executed Authority denial; the prior native tests prove runtime prerequisites
separately. All 45 clean file-store regressions also passed (1.07s,
`r16-denial-client-stores.log`); formatting and `git diff --check` passed.
Logs remain in shared disk scratch. A fresh real-daemon Create/deny/
resume/new-Create campaign and physical crash injection are still required, as
are the broader native lifecycle, Shared finality and release gates. Fold into C2.

### Fresh daemon campaign and corrected sequence discovery

The opt-in vosx test `real_daemon_denial_resume_then_valid_create` exercises the
actual loopback daemon through the production client functions. It requires a
fresh disposable space named `native-denial-smoke` and refuses existing client
state. It prepares a deliberately skipped credential sequence, retries exact
bytes after uncertain HTTP outcomes, checks retained denial/local resume, then
requires valid successor creation and identical verified ACK delivery. It remains
ignored in ordinary test runs; isolated XDG homes must select the disposable space.

Initial run: current production source `50840aeb` was rebuilt in the implementation
worktree's own target (46.47s, shared scratch `r16-denial-daemon-build.log`). New
data is preserved at `target/native-denial-smoke.mmLNc8`, Space
`b9e1120cb41249347b9070ec9065e81c92b4593d2c384af3ca612b0b2b6fdf3d`, HTTP
18083 and SSH 2225. `space new` generated enabled ingress defaults and prepared
bundles; only its local ports were changed. The daemon became ready in about
81 seconds at `2026-09-13T12:07:12Z` (`daemon.log`).

The first test run failed (310.85s, `client-test.log`) because its fixture assumed
sequence 2 was invalid. Production bootstrap's signed catalog operation consumes
sequence 1, so sequence 2 was valid. After two 504 waits, the exact request returned
a verified MAA2 and durably retained client acknowledgement for Agent
`3d28987950edee5f9dc50c502d7a023a22b512a00c573984ceae095d17d7bb48`.
This is real Create/recovery evidence, **not a denial campaign pass**; the harness
correctly failed its expected-denial assertion and did not run the remaining
denial/successor checks. The original signed request was never rewritten.

The harness now obtains the authenticated current sequence under its credential
lease and deliberately skips that sequence rather than assuming an initial value.
It compiles, and all 6 regular CLI tests passed with 1 opt-in test ignored (5.06s,
shared scratch `r16-denial-daemon-harness-verified.log`). Corrected real-daemon
execution on fresh data remains required. The original daemon was sent SIGINT
after the test ended; confirm its process/session has terminated before reusing
its stores or ports. No production failure was fixed by changing the signed
request, and no release, arbitrary actor, or Shared-finality certification is
claimed from this failed campaign.

### Corrected live denial and successor publication deadline

The first campaign's daemon (`native-denial-smoke.mmLNc8`) subsequently exited
0 and removed its endpoint. A separate fresh directory,
`target/native-denial-smoke.WkFgbh`, reused only the released loopback ports
18083/2225, not the old lifecycle data. It became ready at
`2026-09-13T12:18:35Z`, about 83 seconds after launch. The production binary
still contains `50840aeb`; subsequent source changes before this run were only
the opt-in test and documentation.

The corrected real-daemon test performed authenticated sequence discovery and
then received a verified signed denial after one HTTP 504 and an exact retry.
It durably retained CND1, resumed the denied operation locally, confirmed CRS1
Denied, and admitted a new credential reservation with fresh sequence discovery.
The denied Agent was
`ae90a229062b899655ac4f584646971528fa1114c73ca4eb6942f37e1c2847c3`.
This closes real HTTP delivery and local client completion of the canonical
denial path, but **the complete campaign failed** (752.21s, `client-test.log`).

The valid successor, Agent
`63625d0441fe106acdd58d0365da4ba01ff68bdfad85a2e8b26cf107bb151a1c`,
created its Local image and published CMR2 by `12:29:34Z`. All four allowed
submission waits nevertheless returned 504, so no verified client ACK or exact
ACK-repeat result was obtained. A separately recorded, additional ordinary CLI
`--resume` also returned 504 (`followup-resume.log`; its JSON output is empty).
The bounded test was not changed to count that extra attempt as success. All
original requests, certificate and lifecycle files remain intact. Do not infer
successful route publication from the Local image or CMR2 alone.

A five-second CPU sample found 84.81% of 237 samples in
`blake2b_simd::avx2::compress1_loop` on the system-agent thread
(`daemon.perf.data`, `daemon-profile.txt`). A second short sample showed hashing
and interpreter work but could not reconstruct reliable callers
(`daemon-callers.perf.data`). The hash implementation is already optimized by
the dev/test package profile. These samples locate CPU cost, not its root cause;
no verification, replay, or hashing checks were removed. Kernel ptrace policy
prevented a function-only debugger attachment (`daemon-stacks.log`); no kernel
settings were changed.

Debug-level phase timing is now added for lifecycle completion, exact publication
reuse, inventory pending recovery/dispatch, inventory loading, and route
reconciliation. Next rebuild the CLI in this worktree's own target and resume
the preserved operation with
`RUST_LOG=info,vos::agent::production_owner=debug`, after confirming the current
daemon has terminated. The original daemon received SIGINT after the diagnostic
attempt; do not reuse its stores while it remains live. This timing change is
diagnostic, not a claimed latency fix. Production responsiveness, fresh restart
and successful ACK delivery remain open, alongside the existing install/invoke,
Shared finality and full release gates. Keep this evidence within C2.
All 5 production-owner regressions passed after the timing change (0.20s,
shared scratch `r16-publication-timing.log`); this is not a new daemon run.

### Timed inventory bottleneck and exact-head page reuse

The prior daemon exited 0 and removed its endpoint. The instrumented CLI rebuilt
in 17.59s (`r16-publication-timing-cli-build.log`) and reopened the same
`target/native-denial-smoke.WkFgbh` stores without changing either signed request.
`timing-daemon.log` locates the delay: initial reopening took about 356 seconds
before inventory began; the first complete two-Agent inventory took 203.215s,
while route reconciliation added only about 2.8s. Credential, Agent listing,
Local replica and Local actor queries took 36.531s, 38.120s, 38.186s and 59.542s
respectively. Every pending-recovery phase reported zero milliseconds. Readiness
was reached at `2026-09-13T12:50:59Z`, then full periodic inventory restarted five
seconds later. Subsequent complete reconciliations took 105.881s, 126.801s and
148.456s. The daemon was stopped gracefully and its endpoint was removed.

`CleanAuthorityProjectionClient` now retains at most one complete bounded
inventory together with its credential projection. Every refresh still performs
a fresh authenticated Credential query and validates shape, active status and
credential kind. Pages are reused only for an exact match of Authority target,
credential, complete Authority head and every credential claim (ignoring only
the replaced fresh query itself). `AuthorityProjectionHead` commits to the full
validated state and advances on every mutation; current inventory visibility is
derived solely from that state and credential claims. Equal head with conflicting
claims fails closed. Changed scope/head forces complete pagination, and any failed
refresh discards the cached inventory. Only a fully loaded, bounded, same-head
inventory enters the cache; it never supplies a fallback for a failed query.

Physical route authorization/reconciliation still runs on each refresh, and
completed-response delivery caching is not relaxed. Restart starts with no page
cache and still performs full reopening and inventory. This is not acceptance of
a volatile cache as independent Authority evidence: fresh live head/credential
evidence is required for every reuse, with existing host audits unchanged.

All 7 production-owner regressions passed (0.15s,
`r16-inventory-head-reuse.log`). New tests require a fresh Credential query for
every reuse (the one-Agent fixture goes from four queries to one), force full
refetch after scope/head changes, reject conflicting claims, and prove that
revocation, wrong kind and transport failure cannot return cached pages. The
physical protected-Authority projection regression also passed (1 test, 1.81s,
`r16-inventory-head-reuse-physical.log`), as did formatting and `git diff --check`.
The
change does not alter guest artifacts, authentication, retirement or hard capacity
limits. The following live check measures the effect; cold replay,
first-time inventory cost and checkpoint policy remain separate open concerns.

### Verified live retry with exact-head inventory reuse

The worktree-local CLI rebuilt from `8abbe363` in 18.34s
(`r16-inventory-head-reuse-cli-build.log`). It reopened the preserved
`target/native-denial-smoke.WkFgbh` data with isolated XDG directories, disabled
mDNS auto-dial and disk-backed temporary storage. No request, nonce or lifecycle store was
replaced. `head-reuse-run.log` records start at `2026-09-13T13:04:06Z`, readiness
at 13:09:59Z, a client-verified MAA2 at 13:10:32Z, and an identical exact-resume
response at 13:10:33Z. Both retained request hashes matched before and after.
SIGINT shutdown exited zero at 13:10:33Z and removed the endpoint.

`head-reuse-daemon.log` shows first inventory loading took 156.420s and initial
route reconciliation completed in 167.995s total. The resumed Create's lifecycle
took 200ms. Publication performed a fresh authenticated Credential query in
27.720s, reused pages at the unchanged complete head, physically reconciled
routes and completed in 32.249s total. The immediate exact retry completed in
196ms using the separately guarded completed-publication path. Neither CLI
submission needed a timeout retry in this run.

This proves retained-request delivery and matching retry after reopening the
previously timed-out operation. It does not turn the earlier fresh campaign's
failure into a pass: the successor had already persisted CMR2 before this run.
Cold readiness still took about 354 seconds, and fresh mutations invalidate page
reuse. Fresh workflow latency and the remaining native lifecycle/release gates
are not closed by this result.

Current-source SDK checks also passed: all 163 unit tests (0.16s; zero doc tests),
`--no-default-features` check (0.82s), and all-targets no-default-features Clippy
with `-D warnings` (5.33s). Logs in the shared disk-backed scratch directory are
`r16-current-sdk-tests.log`, `r16-current-sdk-no-std.log` and
`r16-current-sdk-clippy.log`. The complete current vosx binary suite also passed:
182 tests, zero failures, two opt-in tests ignored, in 8.63s
(`r16-head-reuse-vosx-tests.log`). The separate live campaign is not included in
that count. These are leaf checks, not final-source integrated
release certification. Keep this evidence within C2; root `saga/agents` and
master remain unmodified.

### Fresh denial, valid successor and exact retry: live pass

The rebuilt `8abbe363` CLI then created a separate disposable space in
`target/native-denial-head-reuse.XoaplU`, using fresh isolated XDG state and
the default bundled artifacts. Generated HTTP/SSH listeners remained enabled;
only their loopback ports changed to 18083/2225. mDNS auto-dial was disabled.
All scratch and logs stayed on disk, not `/tmp`.

The existing opt-in `real_daemon_denial_resume_then_valid_create` test passed
without changing its retry bounds: **1 passed, zero failures**, 441.46s,
183 unrelated tests filtered. It discovered the live credential sequence,
submitted the deliberately skipped sequence, received and retained a verified
signed denial on the first attempt, checked local denial resume and the durable
Denied reservation, then created a valid successor with fresh discovery. The
successor returned two HTTP 504 responses before exact-request resume obtained
the verified MAA2. One additional exact resume returned the same acknowledgement.
This is a fresh complete campaign pass, separate from the earlier preserved-data
recovery check and its historical failed campaign.

`run.log` records daemon start at `2026-09-13T13:16:38Z`, readiness at 13:18:14Z,
successful campaign completion at 13:25:35Z and clean zero-exit shutdown with
endpoint removal at 13:25:36Z. `client-test.log` contains the assertions and
timeout/retry outcome. `daemon.log` measures valid Create lifecycle at 139.169s,
changed-head full inventory at 136.478s, and lifecycle through publication at
278.863s. Subsequent exact publication reuse took 214ms, 208ms and 198ms.
The complete CLI regression suite ran during initial startup, so startup timing
is not an isolated performance benchmark.

This closes the bounded fresh denial/successor/repeated-ACK campaign, not the
latency gate: first Create still exceeds the HTTP response deadline. Next work
stays within C2: address lifecycle/publication latency without weakening replay
or acknowledgement requirements, and implement/prove signed native actor
installation plus real invocation/restart. Ordinary Shared finality, remaining
C1 recovery/crash/capacity checks, and C3 final-source release gates remain open.
No artifact repin, review-branch promotion or master-readiness claim is made.

### Native Local Install application and protected retirement phase

The native owner now has a crate-private `install_local_from_management_intent`
phase. It derives the managed target from the independently opened Local Agent,
checks the pinned Authority binding and signed intent, and validates the admitted
actor package against that descriptor before policy dispatch. It captures live
pending admission before issuing through the bundled Authority, applies through
the Local host, then reopens durable application evidence before asking the issuer
to sign MAA2. The caller still owns exact package retention, protected finalization,
result retirement and route publication; this method is not an ingress endpoint
or a completed client response.

The physical `native_local_install_reopens_application_before_acknowledgement`
regression passed (1 test, 23.85s; `r16-native-local-install-application.log`). It
creates an ordinary Local Agent using the bundled runtime PVM, hands the retired
Create intent to a signed Install, and installs the bundled Catalog actor with
its typed immutable configuration. Incorrect signed runtime scope and an
incorrect admitted package fail before any new Ordered entry or signature.
The valid Install obtains a verified application ACK, drops/reopens the Local
image and intent/issuer stores, and returns the identical ACK without additional
Ordered entries or signatures. It then performs protected Authority finalization,
positively acknowledges the runtime results and commits retirement.

Initial attempts exposed two fixture mistakes: omitted required constructor
configuration and reuse of Create's logical slot for new Install. These were
corrected without relaxing package validation or strict clock progression.
The test also caught missing live admission capture in the first implementation;
Install now uses protected dispatch and protected finalization, and retirement
passes. Temporary diagnostic prints have been removed. The added `system-catalog`
dependency is test-only and supplies its typed configuration encoder.

Adjacent regressions also passed: all three live Local Create admission/retry
tests (67.60s, `r16-native-install-create-regressions.log`) and all seven production
owner tests (0.10s, `r16-native-install-owner-regressions.log`). Formatting and
`git diff --check` passed. This is targeted verification, not a full-library or
final-source release rerun.

This is physical bundled-Authority / bundled-Local-runtime evidence, with the
existing native outer system fixture and memory-backed intent/issuer stores.
It does not prove cross-process Install crash recovery, arbitrary actor method
execution, HTTP/SSH Install submission or ordinary Shared finality. In particular,
startup lifecycle discovery still assumes retained Create runtimes; before wiring
Install into the controller, add durable exact actor-package storage and recover
pending Install/application/finalization from those leased stores. Do not repurpose
the immutable Create-runtime role or expose this phase directly as client success.
All work stays in C2, with C1 recovery and C3 final-source release gates unchanged.

### Durable active Install artifact under the lifecycle lease

`CleanManagementActorStore` now supplies a separate bounded active actor-package
image. The Linux lifecycle files use CSF1 role 13 (`management.actor` and
`management.actor.next`) under the existing intent/issuer lease, with the existing
package-size bound, role integrity and predecessor-bound staged publication.
Create's role-11 runtime remains immutable and separate. A later Install may
replace the previous operation's valid package only before its authorization
or finalization envelope exists; retired/denied current intents cannot replace it.

The intent slot checks the exact Install package reference, re-admits the saved
VOS3 package, and poisons itself after any failed publication. Reopen is mandatory
after an ambiguous write. Malformed saved package bytes are preserved and rejected,
not silently repaired. Once dispatch is prepared, a missing or different artifact
cannot be reconstructed from the retry's supplied package. The native Install
phase now requires this storage capability, durably retains and reloads the package
before authorization, and applies the re-admitted stored bytes.

All 47 hardened filesystem tests passed (2.14s, `r16-install-artifact-files.log`),
including staged initial publication/replacement, lease retention, cross-role
refusal, divergent-stage preservation and unchanged Create-runtime bytes. The
first restricted run failed only its existing loopback HTTP fixture; the rerun
with socket permission passed. File-store fixtures test physical persistence,
not actor-package authentication; the intent layer supplies the latter.

The final-source physical Install regression passed (1 test, 23.95s,
`r16-install-artifact-recovery-verified.log`). It additionally checks a mismatched
valid predecessor package, preservation of malformed persisted bytes, failures
before and after artifact commit, poisoned-slot refusal, explicit slot reopen,
and exact recovery without policy/signature activity before durable publication.
Injected artifact loss after application refuses ACK recovery without rewriting
the missing sidecar. The fixture restores its injected loss only to continue the
separate Local-image/store reopen and protected-retirement assertions. This is
not an automatic artifact-repair path or a whole-daemon crash campaign. Formatting
and diff checks passed; no guest artifact or ABI was changed or repinned.

Automatic startup lifecycle discovery still needs to recognize pending Install
intents and use this leased artifact role for application/finalization recovery.
Pristine pre-dispatch Install must remain retryable, while missing prepared-work
artifacts must fail closed. Controller/queue/HTTP/CLI wiring and real actor method
invocation/restart remain open. These changes stay inside C2; they do not close
C1 recovery, ordinary Shared finality or C3 release gates.

### Startup recovery for already-issued Local Install

`LocalLifecycleController::with_recovery` now recognizes Install receipts already
verified by lifecycle discovery. Before advancing required predecessors or
applying work, it loads every issued Install's leased role-13 package, re-admits
it, checks the exact request/package binding and derives the managed target from
the independently opened Local descriptor. Missing Agent, package or conflicting
Authority/runtime scope fails closed. The lifecycle factory contract now requires
both the immutable Create-runtime and active actor-package storage capabilities.

If an issued Install has no stored acknowledgement and the physical Local host
reports no matching application record, recovery may apply that exact retained
request/receipt/package. Other observation failures are not treated as missing
work. If an acknowledgement already exists, its application must already be
physically observable; startup does not recreate evidence behind an issuer ACK.
All required packages and existing observations are checked before applying the
pending installs, and every application is reopened before missing ACKs are signed.
Existing protected finalization, positive result acknowledgement and durable
retirement then complete before the controller is returned for route publication.

Four physical startup regressions passed in 120.31s
(`r16-install-startup-issued.log`): issued receipt without Local application,
physical application without issuer acknowledgement, saved acknowledgement without
finalization, and a missing-package refusal that preserves intent/issuer bytes.
Each successful case reopens the system journal, Local image and discovered
lifecycle stores, completes exactly one finalization and two result ACK entries,
then restarts again with no new Ordered entries or signatures and the same
verified application acknowledgement. The original genesis provider is retained;
recovery cannot create a replacement bootstrap plan. The physical system and
Local runtime use the existing native/bundled-PVM fixture; intent/issuer stores
are memory-backed, so these are not whole-process filesystem crash tests.

All 47 CLI hardened file-store tests also passed on the extended factory contract
(1.98s, `r16-install-startup-files.log`). This is targeted evidence, not a final
integrated release run. All 14 existing Local Create startup regressions passed
as well (189.67s, `r16-install-startup-create-regressions.log`), including prepared
and accepted authorization/finalization, pending receipt signature, missing or
corrupt runtime refusal, reverse-Agent-order recovery, dependent clock and
missing-finalization rejection, and retirement before publication. Formatting
and `git diff --check` passed. Pending Install before receipt issuance still requires
issuer eligibility and credential-ordered recovery; pristine Install retry and
denial/expiry handling remain open. Controller/queue/HTTP/CLI Install submission,
actual actor invocation/restart, ordinary Shared finality and C1/C3 gates remain
unfinished. Keep this extension in C2 without promoting the branch.

### Pre-issuance Install recovery and pristine retry admission

The issuer now exposes a read-only Install replay-eligibility check. It verifies
the signed request against the selected Authority/Agent scope and requires a
fully application-finalized predecessor, matching decision/acknowledgement high
waters, no retained unacknowledged decision and no pending application ACK.
A pending receipt must be the next sequence and reconstruct the exact retained
Install decision from the signed call; a different signed call cannot adopt it.
Eligibility is not policy approval: the anchored Authority invocation still has
to execute or replay and yield its authenticated approval before issuance.

Startup's former Create-only unissued flag now represents unissued authorization
for Create or Install. Install uses the existing per-credential ordering and
saved-clock constraints. Required actor packages and the independently opened
Local descriptor are checked before replay. After receipt issuance, the issued
Install application/finalization/retirement recovery added above completes the
workflow. Create denial handling remains Create-specific; Install denials are
not reclassified as completed Create denials.

A pristine Install without any dispatch envelope may leave startup available
for exact client retry when its predecessor issuer is fully finalized. It does
not dispatch during startup or reconstruct an absent actor package. An empty
issuer can represent pristine Create, not a pristine Install whose predecessor
evidence has disappeared. Credential ordering still prevents automatic work
from overtaking a known operation waiting for its client.

The first three new restart regressions passed (114.50s,
`r16-install-startup-unissued.log`): prepared authorization, accepted authorization
without issuance, and interrupted receipt signature. They exercise the bundled
Authority/runtime and preserve the original signed call and captured work.
All nine final-source Install regressions passed in 258.63s
(`r16-install-unissued-all-verified.log`), including pristine retry and predecessor
finalization-barrier checks. Pristine retry leaves intent/issuer bytes and the
absent package unchanged across two restarts, with no new Ordered entries or
signatures. Prepared authorization recovery adds its one missing invocation;
already accepted authorization is replayed without a duplicate invocation.
The existing application/finalization/retirement checks still pass, including
missing-artifact refusal and exact repeated recovery.

All 14 existing Create startup regressions passed on the same source (182.87s,
`r16-install-unissued-create-regressions.log`), as did all 12 issuer tests (4.43s,
`r16-install-unissued-issuer-regressions.log`). Formatting and diff checks passed.
These targeted runs do not replace final-source feature, full-library, artifact
reproduction or whole-daemon release checks.

These are native physical journal/Local-image tests with memory-backed lifecycle
stores, not a whole-daemon power-loss campaign. No ingress endpoint, artifact
repin, ordinary Shared finality or master readiness follows from this change.
Remaining C2 work includes Install denial/expiry resolution, controller and
queue/HTTP/CLI submission, actual actor invocation/restart, and mixed-operation
capacity/crash campaigns. C1 recovery and C3 release gates remain open.

### Native Install controller and publication guard

The Local controller now validates the signed Install against the independently
loaded Local descriptor and admitted package before opening lifecycle paths.
It opens existing stores only and retains their exclusive handles across
failures. A successor may hand off a retired slot only after verifying the
predecessor's finalized acknowledgement and physical application. Active-call
replacement and stale same-credential sequences are rejected. Exact finalized
retry physically rechecks the saved application and retirement without dispatch.

The production-owner wrapper reconciles Authority and physical routes, then
requires a running supervisor snapshot matching the exact Space/Agent/Actor,
runtime deployment, actor deployment/program and Local profile. Reconciliation
alone is insufficient because a route may remain deferred. Publication failure
preserves the durable lifecycle result for retry; no ingress success is claimed.

The controller regression passed in 35.75s
(`r16-install-controller-verified.log`): invalid signatures open no stores,
interrupted finalization retains the existing lease, replacement fails, exact
retry completes, stale calls fail, and two completed restarts add no Ordered
work. The first fixture run overflowed its stack; separating the large setup
and restart fixtures into normal-sized scoped threads fixed the test without
increasing stack limits. Eight production-owner tests pass in 0.19s
(`r16-install-controller-owner.log`), including missing/mismatched route identity
rejection. This is not a live end-to-end test of the production wrapper.
The final-code controller rerun also passes (one test, 41.05s,
`r16-install-controller-final.log`); formatting and diff checks pass. All scratch
and test logs remain on disk under the shared target, not the `/tmp` RAMFS.

Next C2 work remains native queue/HTTP/CLI Install submission and a real actor
install/invoke/restart campaign, followed by unresolved denial/expiry/abort and
crash/capacity cases. C1 recovery and C3 release gates remain open. These commits
are implementation checkpoints within the three review groups, not new review
batches; neither root `saga/agents` nor `master` has been promoted.

### Signed Install ingress and shared lifecycle queue

LIQ1 carries bounded canonical AMRQ Install, ACC3 credential call and the exact
admitted VOS3 actor package. Construction checks the Local profile, signed
request binding, package reference, deployment/program and producer. This is
request authentication, not policy approval: the controller still independently
loads and validates the Local descriptor, package requirements and Authority.

Create and Install share one four-entry queue and serial node-owner execution.
Closing the queue explicitly rejects pending operations; losing a client reply
does not cancel an accepted operation. Install dispatch reaches the production
wrapper and therefore requires exact active-route publication before success.

`POST /__agents/local/install` accepts only binary LIQ1 with no query parameters
or claimed authenticated transport node. Its exact path uses signed-body
authentication; adjacent application paths retain bearer authentication.
Success is HTTP 201 with canonical MAA2. Queue saturation/unavailability and
controller failures return 503; a 120-second wait timeout returns 504. Those
responses require identical signed retry and do not assert rollback. In
particular, an Install policy failure is not represented as a completed denial:
canonical Install denial/expiry/abort completion remains open.

The expanded native controller regression passes (one test, 39.67s,
`r16-install-ingress-controller.log`). In addition to physical recovery, it
checks LIQ1 exact round-trip and parts, truncated/trailing/wrong-tag/corrupted
package rejection, bad signature and package binding, closed/full queue,
pending reply completion, shutdown rejection and disconnected-client handling.
An initial compile caught the existing Create queue fixture's old struct
assumption; it now matches the explicit Create enum variant.
The existing Create queue regression passes (one test, 2.13s,
`r16-install-ingress-create-queue.log`). All three HTTP server tests pass in
0.26s with `pvm,private-agent-store,http-ingress`
(`r16-install-ingress-http-enabled.log`), covering malformed lifecycle frames,
exact endpoint routing versus adjacent bearer-protected paths, and status
responsiveness under saturated workers. The earlier HTTP command omitted
`http-ingress` and selected zero tests; `r16-install-ingress-http.log` is not
passing HTTP evidence. Formatting and diff checks pass. Scratch remains on disk
under the shared target, not `/tmp`.

No CLI Install command, live install/invoke campaign, complete denial handling
or release readiness is claimed by this server checkpoint. Next is durable
client preparation/submission with exact MAA2 verification, then the live
install/invoke/restart campaign. C1/C2/C3 remain the review groups.

### Retained Install client delivery

`vosx space submit-local-install /absolute/private/request-store --http 127.0.0.1:8080`
now submits an already retained LIQ1. It does not discover an Agent, allocate a
credential sequence, build an actor installation or sign a fresh request. The
new pure preparation helper accepts an explicitly selected descriptor/Authority,
Install/package and already allocated sequence/validity window; wiring those
inputs into the managed CLI remains the next step, not completed UX.

CSF1 roles 14/15 retain immutable `local-install.request` and
`local-install.acknowledgement` under one exclusive private-directory lease.
Request load revalidates signed LIQ1 and re-establishes durability; publication
cannot replace different bytes. MAA2 load/publication verifies the exact retained
call, both signatures, selected Authority, reconstructed approval and exact
Installed actor entry. An orphaned acknowledgement cannot authorize recreation
of its missing request. A different otherwise valid MAA2 cannot replace retained
completion. This authenticates the issuer's application claim, not independent
runtime replay or proof that a formerly published route is still live.

Submission retains that lease through HTTP delivery and verification, persists
MAA2 before returning success, and resumes a saved verified acknowledgement
without network access. The existing bounded loopback-only transport disables
proxies/redirects and accepts only HTTP 201 binary MAA2. Errors retain the exact
request and report an unknown/incomplete outcome; Install has no client-side
denial completion. Create and Install now share only the exact-call MAA2 verifier
and transport helper; their signed frames and persistent roles remain distinct.

The first new storage fixture was rejected with `InsecureParent`; its private
parent layout was corrected without relaxing store validation. The signed
Install fixture is synthetic client evidence, not a runtime execution. Its
constructor data is intentionally not used to invoke the PVM. The empty failed
fixture directory was removed; all scratch/logs use disk-backed target paths.
The final full `vosx` binary suite passes: 186 passed, zero failed, two ignored,
6.78s (`r16-install-client-final.log`, locked/offline with socket access).
The new tests include deterministic preparation, both signature checks,
re-signed actor-entry substitution, immutable request/response conflicts,
exclusive lease/reopen, orphan rejection, local completed resume and six real
socket response cases (201, 503, 403, redirect, wrong content type, truncated
MAA2), comparing every transmitted request byte. Earlier full and targeted logs
are `r16-install-client-all.log`, `r16-install-client-verified.log` and
`r16-install-client-create-regressions.log`; the ignored live-daemon campaign
and compiled-runtime candidate remain unexecuted release evidence at this head.
Formatting and diff checks pass.

Remaining C2 work is fresh managed Install command wiring with shared durable
credential reservation, followed by real install/invoke/restart testing and
the still-open denial/expiry/abort/crash/capacity cases. No master promotion or
ordinary-agent usability claim is made here.

### Shared credential reservation completion for Install

The existing Space/Credential reservation now has an Install completion path
that reads and re-syncs LIQ1 and verified MAA2 under the delivery store lease.
It checks the reserved nonce against the signed installation ID and checks the
Space/Credential before committing a domain-separated Install request commitment
and exact acknowledgement commitment. Missing delivery evidence, a different
reserved operation or conflicting terminal evidence cannot release a reservation.
Create and Install use the same reservation namespace and exclusive lease; this
does not introduce independent sequence allocation for each operation kind.

All `vosx` binary tests pass: 187 passed, zero failed, two ignored, 7.20s
(`r16-install-reservation-tests.log`, locked/offline, disk scratch). The added
case covers exclusive lease contention, refused successor while pending,
missing acknowledgement, exact completion/reopen, allowed successor after
completion, refused stale completion and a mismatched Space. Existing Create
reservation and delivery regressions remain in the passing full suite.

This is the shared completion primitive, not yet a fresh managed Install
command. That command must reserve the installation ID before preparation and
hold the credential lease through discovery, publication, delivery and this
completion. Fresh descriptor discovery is another concrete prerequisite: the
current HTTP query endpoint exposes only Credential, while the Authority SDK
provides paged Agents and AgentReplicas. Reconstructing a descriptor requires
response-bound pages at one exact Authority head; do not invent a descriptor
from a caller-provided Agent ID or substitute a stale inventory on query errors.
The full goal and C1/C2/C3 release blockers remain unchanged.

### Response-bound Agent discovery for fresh Install

`POST /__agents/inventory` now exposes only the existing bounded Agents and
AgentReplicas selectors, with canonical signed API queries, no URL query
parameters and binary content type. The live Authority still checks permission;
the node decodes the exact expected page type and verifies its echoed query
before returning bytes. Adjacent paths retain normal bearer authentication.
This is a discovery endpoint, not mutation approval or signed finality.

The Install client discovery helper signs each read query, requires every page
to match the independently supplied credential-discovery head, scans at most
4096 Agent entries, collects the target's bounded replica roster and reconstructs
the descriptor only after checking its count and generation. Missing targets,
changed heads, query substitutions and incomplete rosters fail rather than
returning a partially reconstructed or cached descriptor. Queries are read-only;
the managed command must retain its credential lease and retry discovery before
signing if the Authority head changes.

All three HTTP server tests pass in 0.26s (`r16-install-inventory-http.log`,
`pvm,private-agent-store,http-ingress`), including exact inventory endpoint versus
adjacent-path authentication. The full `vosx` binary suite passes: 188 passed,
zero failed, two ignored (`r16-install-discovery-client.log`). The new client
fixture verifies a complete descriptor and rejects Agent-head changes, echoed
query substitution, missing Agent, replica-head changes and missing roster.
These are endpoint-routing and client-validation tests, not a live multi-page
Authority discovery campaign. Formatting and diff checks pass.

Fresh managed Install command wiring remains next: reserve the installation ID,
discover credential and descriptor at one head, prepare and persist the actor
request, submit it and complete the shared reservation from saved MAA2. The
live install/invoke/restart campaign and full C1/C2/C3 release gates remain open.

### Package-derived client Install construction

The client now builds Install entries from an admitted actor package, selected
Agent/name/optional parent, explicitly supplied installation/reservation IDs and
optional constructor bytes. It derives actor identity, deployment/program,
package/schema/policy references, constructor ABI, state layout, lane set and
installation-data reference instead of accepting caller-provided artifact fields.
Constructor-data presence must match the package schema. Zero target or parent,
invalid names/IDs and invalid request shape are rejected. The builder does not
allocate IDs, prove a parent exists, validate guest constructor semantics or
authorize installation; those are separate workflow/runtime responsibilities.

The signed Install client fixtures now use this builder instead of the private
system-bootstrap fixture helper, which was removed. The first new negative case
found that generic request-shape validation alone did not reject a zero parent;
the client now checks it explicitly. Final full `vosx` tests: 189 passed, zero
failed, two ignored, 7.71s (`r16-install-builder-final.log`). Coverage includes
deterministic construction, package/target binding, top-level/child identity,
required constructor data, invalid name/parent, changed data references, and the
existing signed delivery/storage/reservation tests using the new construction.
The synthetic constructor bytes are not evidence of successful PVM execution.
Formatting and diff checks pass; all scratch remains disk-backed.

The fresh managed command still needs orchestration and user-input wiring.
This checkpoint does not expose fresh Install UX or close the live invocation
and full C1/C2/C3 release gates.

### Fresh managed Install command wiring

The CLI now exposes:

```sh
vosx space install-local-actor SPACE AGENT_HEX actor.vos \
  --name worker --constructor-data constructor.bin
```

`--http` overrides the configured loopback plaintext listener; `--resume`
selects the current credential operation. `--name` defaults to the package
manifest name. Constructor data is optional only when the schema permits its
absence; it is exact encoded input, not JSON conversion. This command initially
installs top-level actors. The package is bounded by the admitted-package limit,
constructor input by 64 KiB, and durable request publication by the HTTP-sized
request-store limit.

It selects the indexed Space, live daemon node identity and bundled root
Authority using the same resolver as Create. One shared Space/Credential lease
spans nonce reservation, credential query, exact-head Agent/replica discovery,
package-derived construction, signed LIQ1 publication, delivery and durable MAA2
completion. The nonce becomes the signed installation ID; the request's registry
correlation commitment is domain-separated over Space, Agent, nonce and package.
This is not a separate registry mutation or external reservation proof.

Retained LIQ1 takes precedence over reading package/name/constructor inputs and
over new discovery/signing. It must still match the selected Space, Agent,
operator, node and reserved installation ID. A completed marker with a missing
request is rejected. Pending work blocks a new operation; failures preserve the
reservation for the original command's resume. A retained verified MAA2 may
finish a pending reservation without repeating the server mutation. The selected
Space must still have a live daemon for the indexed managed command; the lower
level retained delivery helper can resume saved completion without a connection.

The managed-resume fixture uses the derived bundled Authority pins, rejects
wrong Agent/node, ignores changed or missing package/constructor inputs after
request retention, and completes/reopens the same reservation from saved MAA2.
This is not fresh daemon execution. Invalid guest constructor semantics and
post-approval failures still lack the complete denial/expiry/abort resolution
needed for release readiness.

The final full `vosx` binary suite passes: 191 passed, zero failed, two ignored,
8.81s (`r16-install-command-final.log`, locked/offline with socket access and
disk scratch). The actual clap parser accepts the new command/options and
rejects missing required inputs. Earlier runs are
`r16-install-command-precheck.log` and `r16-install-command-tests.log`.
Formatting and diff checks pass. No fresh CLI executable or live campaign is
claimed at this checkpoint.

Next is rebuilding the CLI and running a fresh disposable-space
install/invoke/restart campaign. Command parsing and isolated component tests
cannot establish that campaign's result. C1 recovery and C3 release gates, plus
remaining C2 failure/capacity cases, remain open; root branches are unpromoted.

### Live Install campaign (initial progress record)

The CLI was rebuilt from `f37625e3` (locked/offline, 52.00s,
`r16-install-live-build.log`). A guarded ignored test now supplies a valid typed
Catalog constructor, runs fresh managed Install against a previously verified
Local Agent, retries only the retained operation and verifies identical retained
resume. It requires explicit disposable-space environment variables and is not
enabled in ordinary test runs. The ordinary full suite with the harness compiled
passes: 191 passed, zero failed, three ignored, 11.44s
(`r16-install-live-harness-tests.log`).

The live campaign started at 2026-09-13T15:25:20Z on the existing disposable
`target/native-denial-head-reuse.XoaplU` space, using the rebuilt shared-target
CLI and `install-live-run.sh`. This is a fresh actor installation on saved test
state, not a fresh-space campaign. Logs are `install-run.log`,
`install-daemon.log` and, once ready, `install-client-test.log`. The harness owns
daemon shutdown and endpoint cleanup. At 15:28:47Z startup had reached Authority
inventory reconciliation; no Install result was available. Check the running
process/logs before attempting another run; do not interpret this entry as a pass.

Source inspection also identifies an invocation gate: ordinary HTTP routing
still calls `IngressHandle::resolve_actor` over `service_actor_routes`, then
uses registry `meta_for_instance` and a one-schema-actor assumption in
`ingress/routing.rs`. The typed clean supervisor route published by Install is
not by itself proof this bridge can invoke an ordinary clean Agent actor. A
live Install pass therefore cannot close install/invoke/restart or C2 release
readiness without verifying/updating that path.

### Live Install result: delivery timeout gate failed

The campaign above is terminal, not still running. The daemon became ready at
15:31:08Z after 348 seconds of saved-state reopen. Fresh client discovery
succeeded and published LIQ1; the server retained the actor package at
15:33:48Z and updated its protected intent. All four HTTP waits returned 504.
The ignored live test failed after 604.30s at 15:41:12Z
(`install-client-test.log`); this is not superseded by the passing ordinary
suite. No client `local-install.acknowledgement` exists.

Post-lifecycle reconciliation began at 15:39:05Z. Its changed-head inventory
took 193.298s, with complete route reconciliation at 15:42:23.962Z (198.957s).
The harness's shutdown request waited for this work; daemon exit and endpoint
removal completed at 15:42:24Z (`install-run.log`, `install-daemon.log`). The
live process handle is closed. No daemon was restarted or operation regenerated.
Successful reconciliation after clients timed out is not client-verified MAA2
or proof of actor method execution.

The exact request is retained under operation suffix
`6f9522e4a40e22033ea6197b93ffdc4861fc0cb310aedca6ceeacec7ed7a5813`.
Its complete CSF1 file SHA-256 remained
`6a828eccec0a481672d25e2186f0d59819308d2a1e9820a04c345bb851d14c3b`
before/after retries and clean shutdown. Server and client evidence, valid
constructor bytes and the campaign script remain in the same disposable tree.
A subsequent run must explicitly resume, not use the fresh script unchanged
(its constructor-file absence guard correctly prevents that).

A five-second CPU profile while the accepted operation was running recorded
253 samples, no lost samples, and 81.70% self samples in
`blake2b_simd::avx2::compress1_loop`; the daemon was at 100% CPU, not idle.
Disk-backed `r16-install-live.perf.data` and `.perf.txt` retain that evidence.
This identifies a hashing-dominated performance problem, not a proven complete
root cause. Next work must verify exact resume/reopen and address the latency
and clean invocation bridge; simply increasing the test retry count does not
make this UX or the full C1/C2/C3 release gates pass.

### Recovery profile and Standard scalar permission fast path

An explicit resume campaign started at 2026-09-13T15:45:03Z using the same
stopped disposable state and unchanged retained Install. The harness uses
`VOSX_INSTALL_SMOKE_RESUME=1` and separate `install-resume-*` logs, preserving
the fresh failure. The previous daemon binary reached readiness at 15:54:08Z;
the exact-resume client test is running as of this checkpoint. Inspect its
existing process/logs before starting another campaign. Reopen/readiness alone
is not client MAA2 or an invocation pass.

A separate five-second branch-stack profile during cold recovery (no raw stack
memory capture) identified Standard interpreter execution and per-byte memory
permission checks as a startup hotspot. This is a different execution phase
from the earlier hashing-dominated profile. Evidence is
`r16-install-resume-lbr.perf.data` and `.perf.txt` (255 core samples and one atom
sample, no lost samples); inclusive call percentages are not additive.

`standard_memory_exception` now checks scalar accesses wholly within one page
with one range-permission check. The original ordered byte walk remains for
page crossings and u32 wrapping, preserving first-fault and low-zone panic
precedence. It changes no gas, guest artifact, permission or memory contents.
A differential test compares the original algorithm against the fast path for
widths 1/2/4/8, reads/writes, all combinations of NONE/RO/RW on adjacent pages,
flat/sparse memories, bounds, low-zone boundaries and high-address wrapping.

Full PVM tests pass: 259 library tests (one ignored), 20 vector tests and four
SPI tests (`r16-standard-permission-all.log`; the vector runner also logs its
one-test subprocess). The no-default-features library check passes in 0.79s
(`r16-standard-permission-nostd.log`). The earlier targeted library result is
`r16-standard-permission-fast-path.log`. Formatting/diff checks pass.

The live resume daemon predates this optimization. No real-world speedup or
resolution of the hashing hotspot is claimed until a rebuilt daemon is measured.
Exact delivery recovery, clean invocation and all remaining release gates still
must be verified; the goal is not complete.

### Live Install exact recovery passed

The old-binary resume campaign is now terminal: readiness at 15:54:08Z, test
completion and clean daemon shutdown at 15:55:28Z, endpoint removed. The live
test passed once in 67.47s (`install-resume-client-test.log`), recovering the
original signed Install from the failed campaign, verifying/persisting its MAA2,
completing the shared credential reservation and matching a repeated retained
resume. The request's CSF1 SHA-256 remains exactly
`6a828eccec0a481672d25e2186f0d59819308d2a1e9820a04c345bb851d14c3b`.
Its `local-install.acknowledgement` now exists. Both live process handles are
closed; neither campaign has a running daemon.

This proves native restart recovery and client-verified Install delivery, not
fresh delivery within the original retry window, actor method execution, or a
post-delivery invocation/restart campaign. The previous four-timeout failure
remains release evidence. The newly committed permission optimization was not
in this daemon and still requires rebuilt-binary performance measurement.

### Rebuilt interpreter: startup measurement and successor Install

The CLI rebuilt from `2ce0c358` passed (`r16-permission-optimized-cli-build.log`,
8.94s). The optimized retained-resume campaign started at 15:57:59Z, reached
readiness at 15:59:19Z (about 80s), and completed with clean daemon shutdown and
endpoint removal at 15:59:23Z. The live test passed in 0.51s. Evidence under
`target/native-denial-head-reuse.XoaplU`: `install-permission-run.log`,
`install-permission-daemon.log`, and `install-permission-client-test.log`.

This is not a controlled comparison against the earlier 545s reopen: saved
state, journal and cache history differ. The client already had a persisted
MAA2, so 0.51s measures retained local completion/reservation validation, not a
fresh HTTP Install. Initial inventory took 62.115s and route reconciliation
66.684s; this does not resolve first-response latency.

The ignored live harness now accepts `VOSX_INSTALL_SMOKE_NAME` and derives a
valid Catalog constructor from either the preceding completed Create or
completed Install. This allows a different actor installation on the same
Agent without resetting credential history. Ordinary vosx regression remains
191 passed, zero failed, three ignored in 8.56s
(`r16-second-install-harness-tests.log`).

The successor campaign started at 16:00:59Z and reached readiness at 16:03:10Z.
It uses actor name `install-smoke-catalog-second`, constructor
`install-second-constructor.bin`, and separate `install-second-*` logs in the
same disposable directory. The campaign is now terminal: one live test passed
in 394.01s, after two HTTP 504 responses and identical retained retries. The
client verified and persisted MAA2, completed the credential reservation, and
confirmed an identical retained completion. Test completion and clean daemon
shutdown were both at 16:09:44Z; the endpoint was removed. No campaign daemon
remains running. The changed-head inventory took 116.521s and reconciliation
121.098s. This proves completed Install-to-Install handoff and fresh delivery
without restarting the daemon, not acceptable first-response latency or actor
method invocation. Formatting and diff checks pass.

The next functional gate is clean native actor invocation through ingress,
then exact retry/restart of that invocation. Existing ordinary HTTP routing
still resolves legacy `service_actor_routes` and dynamic messages; publication
in the clean supervisor is not proof that those HTTP calls reach the actor.
Use the existing typed preparation/dispatch boundary and authenticated origin
and authorization; do not add a caller-controlled principal/role shortcut.
After that, address lifecycle expiry/abort resolution and the remaining C1/C2
gates above before spending a full rebuild on the final C3 release matrix.

### Clean HTTP invocation transport

`POST /__agents/invoke` now forwards bounded canonical ASQ1 directly to the
active clean supervisor, selecting the full Space/Agent/Actor key and checking
the installed identity through `dispatch_encoded_invocation`. It retains exact
request bytes, including authorization and recovery intent, and only returns
canonical ASR1 after exact response-commitment verification. HTTP 200 is a
runtime outcome, not necessarily actor success. Transport failures remain
unknown outcomes; they do not authorize replacing the invocation identity.

The selected runtime still verifies Authority receipts and installed method
policy. Unsigned PublicPreflight calls must be completely anonymous; bearer
headers do not rewrite their claims. Transport-node claims are rejected.
Attested execution returns 501 before dispatch: the generic dispatcher cannot
provide the required verified attested delivery capability. No new legacy
fallback or permissive authorization adapter was added.

HTTP tests pass: four tests in 0.26s (`r16-clean-invoke-http-final.log`),
including malformed/trailing frames, wrong method/content type, query/body
limits, unsigned principal/credential/actor/node claims, unchanged behavior
with a bearer header, unavailable supervisor, pre-dispatch attested rejection,
exact endpoint versus adjacent bearer-protected paths, and socket saturation.
These are boundary tests, not successful native actor execution.

The first supervisor regression run found one failure (27 passed): its
cross-page mismatch fixture kept the already-cached authenticated head. The
fixture now advances that head and asserts that pagination was exercised,
preserving its mutation-free failure and ABA cleanup checks. Production
inventory reuse is unchanged. Initial evidence: `r16-clean-invoke-supervisor.log`.
The corrected full supervisor-adapter suite passes: 28 tests in 0.03s
(`r16-clean-invoke-supervisor-final.log`), including canonical frame rejection,
exact replay/restart, stale route identity, response substitution, and rejection
of generic attested-response admission. Formatting and diff checks pass.

Still required: client preparation against physical identity/policy, protected
receipt issuance for non-Public calls, retained invocation submission and
continuation/acknowledgement transport, friendly HTTP/SSH routing, and the
fresh installed actor invocation/exact retry/restart campaign. The typed
endpoint is one implementation step toward that workflow, not a replacement
for it or for any C1/C2/C3 release gate.

### Targeted physical preparation transport

Clients can now encode `AgentTargetedPreparationRequest` (ATQ1), containing
only the full route key and invocation intent. `prepare_targeted_invocation`
selects a current supervisor snapshot and uses the existing physical
preparation worker; caller-supplied incarnation, packages, availability and
policy are absent. ATP1 wraps the validated physical preparation with an exact
request commitment. `for_request` checks that commitment plus every intent and
target field, so echoing a different commitment cannot mask substituted work.
This response binding is not an independent host attestation or authorization.

`POST /__agents/prepare` requires binary ATQ1, bounded framing, no query
parameters, and a live bearer credential with `agent.invoke`. Preparation
returns package/installation material, so anonymous discovery is not exposed.
Intent identity/role claims remain untrusted until proper authorization;
preparation neither signs a receipt nor executes the requested method. Private
routes retain their existing no-plaintext-preparation rejection.

Checks pass: 28 supervisor-adapter tests in 0.03s
(`r16-targeted-preparation-supervisor.log`), including physical preparation,
canonical ATQ1/ATP1 round trips, trailing/cross-format rejection, response/intent
substitution and missing target refusal; four HTTP tests in 0.26s
(`r16-targeted-preparation-http.log`), including valid-frame authentication,
framing limits and exact versus adjacent paths. Formatting/diff checks pass.
These are host/transport checks, not a native HTTP method invocation pass.

Next required work remains the retained client preparation/invocation workflow,
protected non-Public receipt issuance and continuation/acknowledgement delivery,
then live installed-actor invocation/exact retry/restart. The full C1/C2/C3
scope remains open; neither this endpoint nor a Public-only smoke substitutes
for authenticated ordinary-agent use or release verification.

### Retained clean invocation delivery client

`vosx space submit-agent-invocation REQUEST_DIR --request call.asq1 --http
127.0.0.1:PORT` now imports a bounded canonical Direct invocation and publishes
it before HTTP submission. Retries omit `--request`; even when supplied, input
is ignored after retention. No signing, identity allocation or preparation
occurs in this command. Non-loopback/zero-port endpoints, attested delivery,
transport-node claims and identity-bearing unsigned public requests are refused.

CSF1 roles 16/17 hold immutable `invocation.request`/`invocation.response` under
one exclusive lease, using existing private-directory and durable replacement
rules. The lease spans network delivery and response persistence. A response
is canonical ASR1 and must match the exact request and outcome identity before
publication. Reopen revalidates/resyncs both records; an orphan response cannot
authorize reconstructing its missing request. Existing saved delivery is
returned without contacting the daemon. Output preserves the full response:
retained delivery may be an actor error or yield, not terminal actor success.
Direct response binding is not independent daemon authentication or finality.

Full vosx regression passes: 194 tests, zero failed, three ignored, 7.92s
(`r16-invocation-client-final.log`). New coverage includes actual CLI parsing,
initial input publication, retry after that input is removed, exclusive lease,
conflicting requests/replies, mismatched/truncated response refusal, orphan
refusal and offline reopen. Six socket cases verify identical request bytes
and a held store lease across 503, 302, wrong content type, substituted reply,
truncated reply, and successful bound delivery. The earlier run passed 193
tests (`r16-invocation-client.log`) before parser/input-path additions.

Fresh preparation/authorization, continuation/acknowledgement transport and
native installed-actor invocation/restart are still required. This closes the
retained submission seam, not that full workflow or any remaining release gate.

### Preparation client and guarded live invocation campaign

The local preparation client now sends exact ATQ1 over bounded, proxy-free,
non-redirecting loopback HTTP with a validated VOS bearer credential. It decodes
ATP1 and requires exact target/intent binding before exposing prepared work.
Assembly accepts an explicit Authority receipt or, only for an installed Public
method, the prepared public preflight. It never synthesizes authorization for a
non-Public method. Receipt issuance remains a separate protected workflow;
runtime signature/policy verification is not replaced by this client check.

The guarded ignored test `real_daemon_preparation_invocation_and_exact_retry`
uses the existing disposable second Catalog installation, queries an empty
namespace, retains ASQ1/ASR1 through the real client, and forces a second HTTP
request even if client delivery was already cached. It requires an explicitly
selected constructor configuration and checks its disposable data-directory
boundary. Operator credential material is used only in memory, not logged.

Correction to the earlier routing analysis: clean preparation itself selects
the method from `TAG_DYNAMIC` plus `Msg` (`invocation_method_name`). That payload
format is supported; the ordinary ingress gap is clean route selection and
authorization, not tagged message encoding. ASQ1 is the clean envelope around
that payload. No change of guest payload ABI is needed for this check.

The CLI rebuild passed in 35.13s (`r16-invocation-preparation-build.log`). Ordinary
vosx regression passes: 195 tests, zero failed, four ignored, 9.94s
(`r16-invocation-preparation-http-client-final.log`). Preparation socket tests
check exact credential/body forwarding, refusal of remote addresses/invalid
tokens, and rejection of 401, redirects, wrong content type and malformed ATP1.
Initial harness compilation exposed incorrect test API names and was corrected;
the initial log is not a passing test result.

The first live campaign started at 2026-09-13T16:36:44Z, reached readiness at
16:41:27Z, and failed immediately before HTTP: its Catalog query requested
eight entries while the protocol maximum is four. The daemon shut down cleanly
at 16:41:27Z and removed its endpoint. No ASQ1 was submitted or retained by this
failed fixture. The fixture now uses `MAX_CATALOG_PAGE_ENTRIES` directly.
Logs are preserved under
`target/native-denial-head-reuse.XoaplU/invocation-{run,daemon,client-test}.log`.
A corrected campaign is running with separate `invocation-page-bounded-*` logs;
inspect its existing live process before starting another campaign. The
ordinary client regression is not a substitute for this native result, and a
Public Catalog query does not close protected non-Public invocation, continuation,
attested delivery, or the remaining C1/C2/C3 gates.

### Live preparation failure: legacy authentication lookup

The page-bounded campaign is terminal: start 16:43:10Z, readiness 16:48:38Z,
test failure and clean shutdown 16:48:40Z, endpoint removed. The live test
failed at `/__agents/prepare` with HTTP 503 before invocation submission.
Its dedicated invocation store contains only `lock`, no ASQ1/ASR1. Preserve
the `invocation-page-bounded-*` logs; this is not an invocation pass.

Source diagnosis found `handle_clean_preparation` reused `authenticate`, which
calls `IngressHandle::authenticate_credential`. That function searches legacy
`service_actor_routes` for a role authority; native clean startup publishes its
Authority through `clean_agent_supervisor` instead. Readiness could therefore
not make this authentication path available.

Preparation now uses `authenticate_clean_api`: select the attached clean
Authority target, sign a fresh Credential projection query using the proven
API key, and require the exact echoed query through the existing bounded clean
projection API. The handler requires Active status and API kind, with no cache
or legacy fallback. Metadata access follows existing clean non-Private inventory
visibility, not a fabricated mapping from clean built-in roles to legacy
`agent.invoke` capabilities. Private physical preparation remains rejected;
actor invocation still requires its installed policy/receipt. Earlier references
to legacy capability gating for this new endpoint describe the failed version.

All 47 ingress tests pass in 0.29s (`r16-preparation-clean-auth.log`), and the
daemon rebuild passes in 18.76s (`r16-preparation-clean-auth-build.log`). A new
live run is in progress with `invocation-clean-auth-*` logs, leaving both prior
campaigns intact. The test result is still pending; inspect that existing run
before starting another. Formatting and diff checks pass.

The attached-owner test additionally exercises `authenticate_clean_api` through
the published node ingress handle: two distinct nonces reach the selected clean
Authority, their exact target/credential/selector and raw API signatures verify,
and shutdown makes authentication unavailable. It passes once in 0.03s
(`r16-clean-api-attached-authority.log`). This is trusted-adapter wiring
coverage, not a substitute for the running physical campaign.

### Live Public Catalog invocation passed

The clean-auth campaign is terminal and passed: start 16:53:24Z, readiness
16:59:22Z, client completion 16:59:56Z, clean shutdown 17:00:08Z and endpoint
removal. The live test passed once in 13.15s after 21.53s of harness compilation
(`invocation-clean-auth-client-test.log`). It authenticated physical preparation,
selected the installed `page` policy, retained ASQ1 before submission, decoded
a successful empty Catalog page with exact target/namespace, saved bound ASR1,
and matched a second real HTTP response. This is not just cached local delivery.

The two records are retained under
`target/native-denial-head-reuse.XoaplU/space/agent-client/invocation-smoke/`.
Their CSF1 file SHA-256 values before restart are
`fa487b4a948b65e55c23592d1ebf737125d0b4482d860529551a986c950b3980`
(request) and
`e7ef5f5048ae0a83dc70fc32642bf80cadf2bc7bae3accc5b610fb59ef27ff37`
(response).
A new campaign with separate `invocation-restart-*` logs is running against
the same stopped/reopened state and exact saved request. The harness forces
HTTP even when local ASR1 exists, so restart is not passed by an offline cache
check. That campaign remains pending; inspect its existing process first.

This closes a live Public Query delivery check only. It does not prove mutation,
protected Authority-operation issuance, continuation/acknowledgement delivery,
attested execution, ordinary Shared finality, or the remaining release matrix.
Startup still took about 358 seconds in this campaign and remains a UX issue.

### Public Query restart passed; continuation transport

The exact restart campaign is terminal and passed: start 17:01:27Z, readiness
17:03:29Z, client completion 17:03:30Z, clean shutdown 17:03:31Z with endpoint
removal. The live test passed once in 0.72s
(`invocation-restart-client-test.log`). It forced a real HTTP request against
the reopened actor and matched the previously retained ASR1 and decoded Catalog
page; it did not pass solely through local cached delivery. Both CSF1 hashes
recorded above are unchanged after restart. No campaign daemon remains running.
Reopen took about 122s; saved state/checkpoint history differs from the earlier
358s campaign, so this is not a controlled performance comparison.

HTTP now forwards exact ARQ3 to `/__agents/resume` and AAQ3 to
`/__agents/acknowledge` through the existing supervisor lifecycle dispatchers.
Each endpoint requires its own canonical frame and preserves the common body,
method, content-type, anonymous-Public/receipt and no-transport-node boundaries.
Attested lifecycle requests are rejected before execution. The selected route
and response commitment are checked as for Invoke; no ingress-built ResumeWork,
new availability, or acknowledgement-as-new-invocation fallback is introduced.

Checks pass: four HTTP tests in 0.26s
(`r16-invocation-continuation-http.log`), now covering valid and hostile
Resume/Acknowledge frames, wrong endpoint/frame domains, truncation, unsigned
identity claims and exact/adjacent socket paths; 28 supervisor-adapter tests
in 0.05s (`r16-invocation-continuation-supervisor.log`), including exact
lifecycle replay/reopen and response substitution. Formatting/diff checks pass.

This is transport wiring, not a native yielded-work/retirement pass. Durable
client continuation/acknowledgement, protected non-Public issuance/mutation,
ordinary Shared finality and all remaining release gates remain required.

### Durable continuation and retirement client

`vosx space continue-agent-invocation REQUEST_DIR --http 127.0.0.1:PORT` now
advances the saved Direct invocation through successive yields and terminal
delivery acknowledgement. It uses the original work and authorization plus
each exact saved yielded selector; no IDs, caller claims, availability or
continuation state are regenerated from current inputs.

CSF1 role 18 stores `invocation.progress`/`.next` in the same exclusively leased
directory as the initial ASQ1/ASR1. Its bounded canonical CIP1 JSON history
contains hex protocol frames, the original invocation commitment and at most
64 exchanges/64 MiB. Publication permits only appending a pending request or
filling that request's exact response. Every predecessor is revalidated against
the original request and each typed response commitment. Missing base delivery,
rewritten history, orphan progress, or response-before-request publication is
rejected. Ambiguity retains the exact pending request for reopen/retry. At the
history ceiling nothing is evicted to manufacture room.

The lease spans request publication, HTTP delivery and response persistence.
Resume replies must advance the yielded selector or terminate; terminal delivery
is acknowledged using original work/authorization. Saved successful retirement
returns offline; a negative acknowledgement remains retained and reports
failure. The success marker is delivery retirement, never actor success.

Initial regression passes: 197 vosx tests, zero failed, four ignored in 7.70s
(`r16-invocation-progress-tests.log`). New fixture tests cover two yields,
terminal acknowledgement, 503 then identical retry, the physical held lease,
pending request presence before network response, reopen, malformed/substituted
responses, canonical JSON, bounded step count, predecessor rollback and orphan
refusal. This is protocol/store coverage; its scripted terminal outcome does
not prove native guest mutation, yielding or retirement. The final regression
passes: 198 tests, zero failed, four ignored in 7.70s
(`r16-invocation-progress-final.log`), including actual CLI parsing and refusal
to publish a response without its preceding durable pending request.
Formatting and diff checks pass.

The native yielded-work/retirement campaign, protected non-Public issuance and
mutation, ordinary Shared finality, capacity/crash closure and final release
matrix remain required. The Public query/restart pass does not replace them.

### Native Public invocation retirement

The ignored, explicitly disposable
`real_daemon_invocation_retirement_and_exact_retry` test continues the retained
live Catalog query through positive acknowledgement, then forces two real
`/__agents/acknowledge` HTTP requests even when client progress is already
complete. Both canonical AAR3 replies must match the original work and
authorization, report `Acknowledged(Ok(_))`, and be byte-identical. The original
ASQ1/ASR1 are checked unchanged; reopening completed continuation must preserve
the exact progress image. This test never manufactures a new invocation or
counts offline client completion as native acknowledgement evidence.

The rebuilt CLI passed the first live campaign on the existing disposable
`target/native-denial-head-reuse.XoaplU` state: startup at 17:22:51Z, readiness
17:25:34Z, **one passed in 1.84s**, clean shutdown 17:25:37Z (2026-09-13).
Evidence is `invocation-retirement-{run,daemon,client-test}.log` beneath that
directory. The original request/response hashes remain those of the preceding
Public query campaign. The new CSF1 progress image SHA-256 is
`02bd4992091a3294dd23d5e6989fdd04db4391a1772703c45d62a12ed7bd93a5`.

The same-state restart also passes: startup 17:26:14Z, readiness 17:29:46Z,
**one passed in 1.18s**, clean shutdown 17:29:50Z. Evidence is
`invocation-retirement-restart-{run,daemon,client-test}.log`. The test forces
two actual HTTP acknowledgements against the reopened native route; it does
not merely read client progress. All three client image hashes remain exact.
The disposable query is now retired: preserve its evidence and use a separate
invocation/store for any fresh execution campaign. Both daemons are stopped
and their endpoint marker is absent. Startup latency remains high; these are
correctness results, not a startup-performance improvement.

The vosx regression suite passes **198 tests, zero failed, five ignored**, in
9.15s (`r16-native-retirement-regression.log` in the shared target's task-tmp).
Workspace formatting and diff checks pass.
The extra ignored test is the explicit live retirement campaign above. This
closes native terminal Public-query acknowledgement coverage, not protected
issuance, guest mutation/yielding, Shared finality or the release matrix.

### Native protected-operation file stores

`CleanAuthorityOperationFiles` supplies the existing
`AuthorityOperationCoordinatorStore` and `AuthorityOperationIssuerStore`
traits with hardened whole-image files in a dedicated private directory. CSF1
roles 19/20 bind `authority-operation.coordinator` (2 MiB maximum) and
`authority-operation.issuer` (4 MiB maximum), each with a fixed `.next` staging
file. Both handles retain one shared exclusive writer lease, even when the
other handle is dropped. Publication uses the existing synced, exact-
predecessor replacement protocol. The pair is per Authority, not per invocation;
the global issuance sequence must not be split across independently opened
issuers. No existing bootstrap or management namespace is widened.

Five focused tests pass in 0.19s
(`r16-native-operation-files-semantic.log`): exact/repeated publication,
independent reopen of both journal roles, initial and predecessor-bound stage
recovery, ambiguous-stage preservation across reopen, both lease lifetimes,
independent size ceilings, namespace and cross-role substitution refusal, and
real coordinator/issuer opening. The latter uses a dispatcher that panics if
called: startup of empty stores must not invoke policy, and CSF1-wrapped unsigned
contents must be rejected by the actual semantic decoders without deleting
evidence. These are storage/admission checks, not authenticated physical actor
execution. The first focused run had a fixture-only `usize::MAX` bound overflow
when directly inspecting a stored predecessor; changing it to the actual
role ceiling fixes that check (`r16-native-operation-files.log` retains the
failure; the four pre-semantic tests subsequently pass in
`r16-native-operation-files-final.log`).

The full vosx regression suite passes **203 tests, zero failed, five ignored**
in 8.97s (`r16-native-operation-files-regression.log`). Formatting and diff
checks pass. All logs are under the shared target's disk-backed `task-tmp`.

The store pair is deliberately not installed into native startup yet. The next
required change is a trusted physical operation dispatcher with durable exact
RuntimeWork and pre-dispatch journal admission, startup recovery and safe
exclusion/coexistence with pending management/projection work. Only then may
startup reopen these stores and expose protected issuance. Retained coordinator
context alone cannot reconstruct installed incarnation, availability and gas;
do not regenerate those from a later live route or mark an uncommitted result
`authenticated`/`durable`. The pending projection record remains read-only and
must not carry `authorize_operation`. No protected method, live mutation,
Private/Attested, Shared finality or release gate is claimed by this checkpoint.

### Native protected-operation physical execution boundary

The native owner now prepares an exact Authority operation envelope and executes
only an already-retained envelope with its pre-dispatch journal anchor.
`clean_operation_dispatch.rs` keeps this distinct from read-only projections.
Both signed method domains are validated: AOC5 for `authorize_operation`, AOI1
for `acknowledge_issuance`. Targets, context, signature, method argument name,
Direct mode, empty runtime state, pinned incarnation/installation material and
the exact Public preflight are checked. These self-authenticating Authority
methods do not bypass policy for the requested downstream actor operation.

Fresh preparation requires the selected observation clock. Execution preserves
the saved work and uses the existing physical journal-anchored Linear admission
path, including live installed-material checks. Only a durable completed native
result with matching invocation/actor/incarnation/deployment/mode is reported
as authenticated and durable to the operation coordinator. The result remains
retained; this boundary does not sign receipts or release admission.

The bundled-Authority physical test passes in **4.22s**
(`r16-native-operation-physical-binding.log`). It persists the complete envelope
and anchor in a synced test-only file under native admission, reads them back,
and proves that changed context, substituted anchor and changed gas with a
recomputed preflight cannot execute. A correctly signed but unenrolled credential
is evaluated and denied by the actual bundled guest. The resulting empty approval
is durable and an exact retry returns the same result with no second journal
transition. This is native policy-denial execution, not successful protected
issuance, AOI1 consumption or startup recovery. The earlier unextended test also
passed in 4.77s (`r16-native-operation-physical-final.log`); its initial compile
errors were confined to test fixture codec imports/API usage
(`r16-native-operation-physical.log`).

The signed-domain test passes in **0.07s** (`r16-native-operation-domain.log`),
covering valid AOC5/AOI1, swapped method domains, changed target/context,
trailing bytes and forged signatures. Its AOI1 is issued through the existing
scripted coordinator fixture, not physical policy. Formatting and diff checks
pass. All logs remain in the shared target's disk-backed `task-tmp`.

The existing native management issuance regression passes: **one passed in
124.90s** (`r16-native-operation-management-regression.log`). The broader
coordinator regression also completed: **19 passed, zero failed, in 1,254.24s**
(`r16-native-operation-dispatch.log`). That run started before the final native
test additions and clock-extension changes; it is not a final-source release
matrix. Both processes are terminal, not waiting or abandoned.

The next connection still requires a durable native dispatch record and its
startup recovery: the coordinator's context omits incarnation, availability,
gas and journal admission. Connect the validated native methods to the real
coordinator only with those exact retained records and admission recovery,
then verify approved issuance/AOI1 consumption and retirement. Do not expose
HTTP authorization or treat the denial test as a working protected mutation.

### Canonical retained native operation input

`RetainedAuthorityOperationDispatch` now encodes bounded canonical NOD1: the
method domain, complete signed AOC5/AOI1, entire RuntimeWork and pre-dispatch
journal anchor. It derives target/context from those retained inputs, checks
the exact message and preflight, and rejects invalid signatures, inner frames,
runtime state, anchor shape and cross-domain encodings. The ABI-tagged record
is not a self-authenticating journal proof; execution still uses independently
pinned owner material and authenticated native journal admission.

`capture_authority_operation_dispatch` reserves the first authorization input
and invokes a durable record callback under the existing exclusive native
admission. Only successful persistence returns the record to the caller.
An ambiguous callback failure retains admission, so an exact retry cannot
silently switch its clock, work or anchor. An already-saved record must be used
directly after material/clock advancement, not regenerated by fresh preparation.
Initial capture rejects the acknowledgement method: that requires a verified
phase extension from the exact authorization and issued evidence.

The physical test now uses NOD1 instead of its former test-only encoding. It
syncs the record, injects a callback error after publication, reads and validates
the file, and proves a second capture produces identical bytes without running
policy. Native denial/replay and substituted clock/gas/anchor checks remain.
The expanded record checks pass in **3.89s**
(`r16-native-operation-record-final.log`), covering roundtrip, truncation,
trailing data, wrong magic/ABI/method and an oversized declared request length.
The earlier record run also passed in 4.32s (`r16-native-operation-record.log`).
The final initial-authorization-only capture run passes in **3.85s**
(`r16-native-operation-capture-final.log`). Formatting and diff checks pass.

Startup dispatch-store wiring and recovery remain open. In particular, connect
AOI1 preparation/admission to its exact retained AOC5/AOP5 and signed issuance
slot; do not replace that slot with a later host clock or treat AOI1 as a fresh
unrelated initial invocation. Then connect the native record store, coordinator
and issuer and prove approved issuance, actor consumption and positive
retirement. This checkpoint does not expose protected HTTP issuance, complete
startup recovery or establish a working protected mutation.

### Native issuance-acknowledgement phase admission

`extend_authority_operation_dispatch` now admits AOI1 only after validating its
exact retained AOC5 predecessor, matching AOP5, both issuance signatures and
the signed observation slot. The native journal independently requires that
exact predecessor envelope and anchor to be present in the pending admission
set. A structurally valid NOD1 record cannot manufacture that admission.
The new AOI1 record is persisted under the same admission boundary; ambiguous
publication retains the exact pair for retry. This does not consume the actor's
pending approval or retire either native result by itself.

Fresh AOC5 preparation still requires the current observed clock. AOI1
preparation instead preserves its signed `issued_at`, which may precede the
current host clock but may not precede its authorization or lie in the future.
Current physical actor/installation material is still checked. Regenerating
AOI1 context from a later host clock would violate its signed protocol binding;
the native preparation path now supports that delayed phase without rewriting
the signed time or weakening initial authorization admission.

The extended physical test passes **one test in 5.18s**
(`r16-native-operation-extension-final.log`; the preceding pass was 5.25s in
`r16-native-operation-extension.log`). It advances the host clock after the
original authorization, rejects fresh-AOI1 capture, substituted predecessor
anchors and mismatched approval, then syncs an AOI1 NOD1 record and injects a
post-publication error. Exact extension retry preserves the record and signed
clock, with no policy execution during capture. The bundled guest rejects its
consumption and exact replay adds no second journal transition.

This is intentionally a negative security test: a test-only scripted
coordinator produces authority-signed issuance for the real guest-denied,
unenrolled request. The guest's `false` reply proves host signatures alone
cannot substitute for its own policy approval. It is not evidence for approved
native issuance or successful AOI1 consumption. Production code has no such
scripted signer/policy path. Formatting and diff checks pass; all test processes
are terminal. The next implementation remains the durable dispatch-store and
coordinator connection plus native startup admission recovery, followed by a
genuinely approved operation, successful consumption and positive retirement.

### Native dispatcher connected to the operation coordinator

`NativeAuthorityOperationDispatcher` now implements the coordinator's trusted
`AuthorityOperationActorDispatcher` boundary. Authorization requires an existing
canonical NOD1 matching the exact invocation, request, context and pinned
Authority; missing state never triggers fresh preparation. Every successful
reply comes from the native owner's authenticated journal execution/replay.
No unsigned approval-response cache substitutes for the guest.

AOI1 dispatch always reloads its exact authorization predecessor and re-observes
the native retained approval, including on retries. Its signed issuance must
match both AOC5 and that AOP5. Only then can a missing AOI1 record extend
admission, persist, and be read back exactly before physical execution. An
issuer-signed acknowledgement without native policy approval is rejected before
creating the acknowledgement record. Completed operation receipt recovery in
the portable coordinator still takes precedence over new dispatch.

The public `NativeAuthorityOperationJournalStore` boundary supplies immutable,
bounded per-invocation NOD1 load/retain under a writer lease. Backend success
must mean durable publication, exact retries must remain idempotent, and
different records cannot replace one another. The `vosx` hardened production
implementation and native startup wiring are still required; the new physical
tests use synced, disk-backed test-only image/journal backends in private
fixtures, not production CSF1 storage or a live CLI endpoint.

Both physical tests pass: **two passed in 10.02s**
(`r16-native-operation-coordinator-final.log`; preceding pass 8.99s in
`r16-native-operation-coordinator.log`). The real coordinator calls the bundled
Authority through the native dispatcher, returns `AuthorizationDenied`, and
never reaches either signer method. Reopening the actual coordinator/issuer
file backends and advancing the host clock returns the same denial with no
second native transition or issuer image. Missing/corrupt NOD1 is rejected and
preserved. The signed-but-scripted AOI1 negative case is additionally rejected
by the dispatcher before acknowledgement record creation because the actual
retained guest result is a denial. Lower-level phase/clock/substitution checks
remain passing. Formatting and diff checks pass; all processes are terminal.

This connects the coordinator to native execution but is still negative-path
and same-owner recovery evidence. Production journal storage, startup
restoration of exact pending admission, genuinely approved native issuance,
successful AOI1 consumption, denial/success retirement and protected mutation
remain open. Do not report protected issuance as available to users yet.

### Production native operation journal storage

`CleanNativeAuthorityOperationJournal` implements the NOD1 store boundary in
`vosx`, under one exclusive directory lease pinned to the configured Authority.
CSF1 role 21 uses nonzero lowercase invocation-derived names and immutable
initial-publication stages. Existing fixed-name store namespaces remain closed
to these names. Opening validates every discovered record, including staged
records, before returning a usable handle; key/Authority substitution is
rejected before stage publication. Exact retries re-establish file/directory
durability. Missing existing stores, replacement histories, unknown names,
symlink/hardlink aliases and replaced directories/locks fail closed.

The backend enforces the NOD1 byte bound and at most 512 distinct records
(two per coordinator capacity slot), without eviction. This is a safety bound,
not completed retention/compaction support. Record framing and pinned-target
validation do not establish native admission, policy approval or finality.

All **210 CLI tests pass, zero fail, five ignored**, in 9.43s, including seven
new journal tests. Evidence: `r16-native-operation-journal-regression.log` in
the shared disk-backed `target/task-tmp`. Tests cover staged recovery, immutable
retry/conflict, wrong key/Authority/role, exclusive leases, byte/count limits
and filesystem substitution while preserving rejected evidence. The initial
restricted precheck hit an existing socket permission failure; an intermediate
fixture compile failure was corrected. The final full run had socket access.
Formatting and diff checks pass. No guest artifacts changed.

This closes the backend gap identified in the preceding checkpoint, not native
startup recovery or endpoint integration. Next, restore retained NOD1 admission
before normal routes and connect the coordinator/store pair to the daemon;
then prove genuinely approved native issuance, successful AOI1 consumption,
denial/success retirement and protected mutation/restart. The branch remains
limited to isolated disposable testing, not master-ready deployment.

### Exact operation admission at native owner startup

`NativeAuthorityOperationStartupAdmission` loads the complete bounded NOD1
discovery set while borrowing the journal lease. Missing/duplicate/zero IDs,
wrong Authority/key, malformed records and issuance records without their exact
authorization predecessor are rejected. Issuance references must match the
saved call commitment and cannot predate its authorization slot. This is scope
validation, not evidence that the native guest approved issuance.

The production file backend exposes complete discovery plus admission loading
as one borrowed operation. The native owner's new
`open_or_bootstrap_with_operation_admission` entry point merges the saved
anchor/envelope pairs into the existing management recovery barrier before
route attachment. The physical host still authenticates anchors and checks
admission compatibility; stored bytes alone cannot authorize execution. Pending
projection coexistence remains fail-closed. Nonempty operation recovery against
an incomplete/missing bootstrap is rejected before invoking a fresh-plan
factory. Existing lifecycle-only callers retain their previous entry point.

The new physical test closes the owner and reopens the actual journal-backed
host before policy execution, then closes/reopens it again after the durable
denial, advancing the clock each time. Exact native dispatch returns the same
reply with only one transition total and unchanged NOD1 bytes. It passes in
**6.90s** (`r16-native-operation-startup-final.log`). The initial compile used
an unavailable Result helper; that compatibility error was corrected before
the passing run. The combined native operation regression also passes:
**three passed in 16.73s** (`r16-native-operation-startup-regression.log`),
covering owner reopen, coordinator denial and physical dispatch/issuance
binding. All **211 CLI tests pass, zero fail, five ignored**, in 10.38s
(`r16-native-operation-startup-cli.log`), including complete leased discovery,
duplicate/over-limit/wrong-target rejection and exact reopen. Logs remain under
the shared disk-backed `target/task-tmp`.
The existing native lifecycle startup retirement-before-route-publication
regression also passes: **one passed in 14.01s**
(`r16-native-operation-startup-lifecycle.log`). Formatting and diff checks pass.

This is native owner recovery evidence, not a live daemon operation endpoint.
Production startup/controller ownership of the journal and issuer/coordinator
pair still needs wiring. All discovered operation records currently describe
pending admission: terminal retirement classification, denial resolution and
capacity reclamation remain required before treating completed operations as
safe to release. No records may be deleted to bypass those gates. Genuinely
approved issuance, successful AOI1 consumption and protected mutation/restart
are still unproved. No guest artifacts changed; C1/C2/C3 review scope remains.

### Coordinator-owned pre-pledge native retention

The coordinator now calls the trusted dispatcher's `retain_authorization`
hook only after validating a new operation's signature, route, context, slots,
pending/capacity/collision constraints and signer, but before committing its
pledge. The native adapter loads an exact existing NOD1 or captures and durably
retains a new one under physical admission, then reads it back exactly. This
hook neither executes policy nor signs evidence. Existing coordinator pledges
skip preparation entirely: missing NOD1 still fails closed at native dispatch,
and cannot be reconstructed against a later physical head. Adapters without a
separate physical journal retain their previous behavior through a no-op hook.

This closes an ordering prerequisite for daemon/controller wiring: a caller no
longer has to reproduce capture-before-pledge ordering outside the coordinator.
The native coordinator test now begins with no NOD1 and no manual capture;
automatic retention precedes the bundled Authority's denial, with no signer
calls. Exact retry after clock advance preserves the original NOD1 and causes
no second transition.

Verification: the new retention-order/failure test passes in **0.06s**
(`r16-native-operation-retention-order.log`), including invalid-signer refusal
before preparation, failed retention with no coordinator/issuer writes or
execution, and an ambiguous successful pledge commit followed by recovery that
never calls preparation again. The three native operation tests pass in
**14.69s** (`r16-native-operation-automatic-retention.log`). The existing
completed retry/restart test passes in **0.08s** with no additional dispatch or
signing (`r16-native-operation-retention-retry.log`). Formatting/diff checks
pass; logs are in shared disk-backed `target/task-tmp`. No guest artifacts
changed. This is targeted evidence, not a new full regression/release run.

Daemon/controller store ownership, live operation ingress, terminal retirement
classification and genuinely approved protected mutation remain open. This
checkpoint does not change deployment readiness or the C1/C2/C3 review batches.

### Long-lived native operation controller ownership

`NativeAuthorityOperationController` owns the coordinator, issuer and NOD1
journal handles. Each call borrows those handles and reopens both parsed images
before constructing the native-only dispatcher. Failed opens and ambiguous
operation errors therefore leave the backing handles owned by the controller;
later attempts cannot accidentally reuse a poisoned parsed issuer. No caller
can supply an unsigned approval or a replacement dispatcher through this API.
Controller, request and native owner must select the same valid Authority.
Structured errors preserve the distinction between issuer/coordinator opening
and coordination failures, including native policy denial.

Construction merely adopts stores; it is not a readiness assertion. Startup
admission remains explicitly loaded from the complete discovery set, borrowing
the controller's journal. Exact contexts and issuance slots are still required
on calls and retries; they must not be regenerated from a later host clock.
`into_parts` transfers handles without reopening their paths. This follows the
existing lifecycle controller's long-lived-handle/per-call-parsing pattern.

The three native operation tests pass in **14.91s**
(`r16-native-operation-controller.log`). The coordinator fixture now uses one
controller across an injected coordinator-open failure and two native denial
attempts. The failed open creates no coordinator/issuer/NOD1 file, executes no
transition and never signs; recovery on the same controller then automatically
retains native input, and retry after clock advance preserves its bytes without
a second transition. These are native physical tests with synced test image
backends, not a live daemon endpoint.

All **212 CLI tests pass, zero fail, five ignored**, in 10.63s
(`r16-native-operation-controller-cli.log`). The new CSF1-backed ownership test
rejects missing recovery input while retaining both directory leases, recovers
the exact record on the same controller, and verifies that transferring/dropping
one image handle cannot release the other image's shared lease or the separate
journal lease. Formatting/diff checks pass. Logs remain in disk-backed
`target/task-tmp`.

The controller still needs adoption by daemon startup and lifecycle/operation
dispatch, with complete discovery and terminal retirement classification. This
does not close protected issuance, mutation, denial retirement, capacity or
release gates. No guest artifacts changed; review scope remains C1/C2/C3.

### Daemon adoption and native operation dispatch

Startup now opens dedicated `authority-operation` image and
`authority-operation-journal` namespaces, discovers every NOD1 candidate and
cross-checks coordinator/issuer images before loading admission. Every pledged
authorization and consumed issuance acknowledgement must have an exact retained
native dispatch record; a missing/substituted record stops startup. Signed but
unconsumed issuance may legitimately await first native acknowledgement capture.
The owner restores operation admission together with lifecycle recovery before
attachment; the lifecycle controller then adopts all three handles and an
explicitly owned signer pinned to the same Authority.

`VosNode::authorize_clean_agent_operation` dispatches through the retained
production/lifecycle owner, holding the system-owner lock while coordinating.
Shutdown/unavailable-owner checks fail closed. This is a native node API, not
an HTTP/CLI operation endpoint, and issuance is not actor application or result
retirement. The type-erased lifecycle boundary currently reports operation
errors as unavailable: it must not turn a denial into terminal completion or
release admission without the still-missing durable retirement evidence.

The three physical native operation tests pass in **33.95s**
(`r16-native-operation-daemon-native-final.log`). Coverage now includes an error
after a durable coordinator pledge, missing required NOD1 refusal without
execution, exact recovery after restoring the deliberately displaced test file,
and native denial replay through the actual type-erased lifecycle access.
The latter cannot open lifecycle stores or sign, and does not add a transition.
The earlier pass before the lifecycle-access assertion was **15.52s** in
`r16-native-operation-daemon-native.log`.
All **212 CLI tests pass, zero fail, five ignored**, in **10.12s**
(`r16-native-operation-daemon-cli-final.log`). The current daemon build passes
(`r16-native-operation-daemon-build.log`, 43.49s). These logs remain under the
shared disk-backed `target/task-tmp`; no guest artifacts changed.

The owned-signer check also passes with exact deterministic operation-issuance
signatures and the same configured public key
(`r16-native-operation-daemon-signer-final.log`, one passed). Its initial test
compile had ambiguous management/operation trait calls; those fixture calls
were qualified explicitly. The daemon binary used for the disposable smoke
predates only this test assertion and a documentation-only source edit.

Remaining C2 work includes retained operation ingress/client preparation,
genuinely approved native issuance and protected mutation, success/denial
retirement, restart/terminal classification and the existing capacity/finality
gates. Directory creation or a native API alone is not a completed user workflow.

The rebuilt daemon also passes the existing disposable-space smoke:
`operation-controller-startup` started **2026-09-13 19:02:42Z**, became ready at
**19:07:04Z**, passed native invocation retirement/two forced exact HTTP
acknowledgement retries (**one passed in 1.14s**), and shut down cleanly at
**19:07:06Z**, with no endpoint marker left. Evidence is under
`target/native-denial-head-reuse.XoaplU/operation-controller-startup-{run,daemon,client-test}.log`
in this implementation worktree. The new image/journal directories are private
and contain only their lock files: this proves empty-operation-store startup
compatibility, not live pending-operation recovery. The saved request, response
and progress hashes remain exactly those from the earlier retirement campaign.
Startup still takes roughly 4m22s; this does not close the latency gate or make
the branch master-ready.

### Genuine native approval and issuance recovery

`native_operation_approved_issuance_reopens_without_new_signatures` performs
the complete native bootstrap rather than seeding a completed bootstrap image.
The bundled Authority PVM authorizes and registers an installed query actor,
then evaluates a real enrolled-credential SSH-node-attested AOC5 for that actor.
The native coordinator retains authorization work, obtains the guest's AOP5,
issues the signed receipt/AOI1 and observes successful native AOI1 consumption.
Exactly two operation transitions and two signature calls occur.

The test closes the native owner, advances the host clock and reopens it with
both retained NOD1 records. The same operation returns byte-identical issuance
without further signatures or transitions. This is positive native policy and
issuance/recovery evidence, not a scripted approval and not a host signer
shortcut. It uses the native Standard host fixture and an executable public
query actor fixture, not a full CLI/HTTP protected mutation campaign. The
authorized query itself is not executed in this test; operation result
retirement remains pending and must not be bypassed to enable application.

The focused test passes in **12.67s**
(`r16-native-operation-approved-bootstrap.log`). The first runtime attempt
stopped with `GuestDenied` during bootstrap under the fixture's fixed logical
clock (`r16-native-operation-approved-native.log`, 2.01s). The passing fixture
advances the clock across bounded retries of the same durable bootstrap stores,
requiring strict phase progress on any such denial. No approval/finalization
state is fabricated. Two intermediate fixture compile errors (installed actor
lookup and memory-store accessor) were corrected; their logs are preserved as
`r16-native-operation-approved.log` and `r16-native-operation-approved-clock.log`.
Logs remain under shared disk-backed `target/task-tmp`.

The combined native operation regression also passes: **four passed, zero
failed**, in **29.51s** (`r16-native-operation-approved-regression.log`), covering
both approval and denial paths plus physical dispatch and reopen. Formatting
and diff checks pass.

Only test fixtures and coverage changed; no production code or guest artifacts
were modified. The next required work remains terminal operation retirement,
retained operation ingress/client wiring and a protected Local mutation with
restart, followed by the existing broader C2 and C3 gates.

### Native successful-result acknowledgement without release

The native owner can now verify an exact successful operation completion by
replaying its retained authorization and issuance dispatches. The signed AOI1
must match the exact AOC5 and actual native AOP5, and native acknowledgement
execution must return `true`. Receipt/issuance substitution and swapped phases
are rejected. `VerifiedNativeOperationCompletion` is an opaque, ephemeral value
with no decoder: unsigned disk bytes cannot manufacture this verification.

Given that value, `acknowledge_native_operation_completion` validates both
envelopes against current installed material, moves their exact pending pair
to retirement admission, positively acknowledges each runtime result and
independently observes the durable acknowledgements. Exact repetition adds no
transition. This method never calls retirement completion/release and is not
wired into the controller/ingress path. It must remain unwired until terminal
evidence can be durably stored and recovered after either result is gone.

The positive physical test passes in **20.17s**
(`r16-native-operation-result-retirement.log`). After real approval, issuance
and owner reopen, completion verification adds no transition; the two positive
result acknowledgements add exactly two, and retry adds none. Signer counts
and both NOD1 records remain unchanged. An unrelated projection reservation is
still rejected, proving this step did not prematurely release admission.

The combined native regression passes: **four passed, zero failed**, in
**33.54s** (`r16-native-operation-result-retirement-regression.log`). The
negative native case additionally refuses completion verification for signed
but scripted issuance whose real guest result is denial, with no additional
transition and the original pending admission still present. Formatting and
diff checks pass.

Next: durable, independently verifiable terminal evidence before destructive
result retirement; restart classification and exact release; then application
and ingress integration. This is not terminal recovery closure, protected
mutation coverage or permission to delete retained stores. No guest artifacts
changed. Evidence logs remain in shared disk-backed `target/task-tmp`.

### Signed completion continuation and retirement-class reopen

Native result acknowledgement now requires `RetainedNativeOperationCompletion`,
not the ephemeral completion-verification value alone. The native owner signs
canonical, ABI-bound NOC1 continuation evidence only from its verified success
pair and invokes the caller's durable retention callback before returning the
retained value. The configured Authority key signs a distinct completion domain
binding both invocation IDs and hashes of the complete immutable NOD1 inputs,
including their journal anchors. Exact signing/retention retries are idempotent.

Recovery verifies the configured key, both exact source-record commitments,
signed request domains, authorization/issuance linkage and canonical encoding.
Malformed, truncated, trailing, signature-substituted and phase-swapped evidence
is rejected. NOC1 attests successful native phase observation; it is neither an
application receipt, guest quorum/finality proof nor a claim that either result
has already been acknowledged. Native acknowledgement evidence is still checked
independently, and this record cannot release admission.

`NativeAuthorityOperationStartupAdmission::load_with_completions` validates
bounded signed continuation records against its discovered NOD1 set, rejects
duplicate/cross-pair identities, and classifies verified pairs as retiring rather
than pending. Owner startup merges that class with existing lifecycle retirement
admission before attachment. Retiring-only recovery also requires a completed
bootstrap and remains incompatible with unfinished projection work.

The focused physical test passes in **21.11s**
(`r16-native-operation-completion-reopen.log`). It persists NOC1 to a synced
test file, injects an error after publication, verifies no result acknowledgement
occurred, and retries with identical certificate bytes. Both results are then
acknowledged. Recovery reconstructs the continuation from disk, closes/reopens
the native owner with retirement-class admission, and retries acknowledgement
without any new transition. Unrelated projection admission remains blocked.
The preceding same-owner certificate test passed in **18.28s**
(`r16-native-operation-completion-certificate.log`).

The combined native operation regression passes: **four passed, zero failed**,
in **41.71s** (`r16-native-operation-completion-regression.log`). All **212 CLI
tests pass, zero fail, five ignored**, in **10.45s**
(`r16-native-operation-completion-cli.log`). Formatting and diff checks pass.

Production hardened completion storage/discovery and controller adoption are
still missing; this uses synced test-file retention. The crash case after only
one positive result acknowledgement, durable final retirement/release markers
and release retries remain required. Do not wire retirement into the daemon
until those are closed. No guest artifacts changed. Logs remain in shared
disk-backed `target/task-tmp`.

### Partial operation acknowledgement interruption and reopen

The native acknowledgement loop now has an internal progress-observation
boundary after each independently verified positive acknowledgement. An
observer error stops before the next result while retaining the exact retirement
reservation; normal callers use a no-op observer. The observer cannot substitute
for acknowledgement verification and must not re-enter the owner or release
admission.

`native_operation_partial_result_retirement_reopens_exactly` interrupts that
actual loop immediately after the first positive acknowledgement. It closes the
native owner, reloads signed NOC1 and both immutable NOD1 records, and reopens
retirement-class admission with an advanced clock. Completion acknowledges only
the remaining result; exact retry adds no transition. Receipt/issuance and
completion-signature counts do not increase, the certificate bytes are unchanged,
and unrelated projection admission remains blocked. The original both-results
reopen case is retained as a separate test using the same fixture helper.

The focused case passes in **23.42s**
(`r16-native-operation-partial-retirement.log`, shared disk-backed
`target/task-tmp`). This is native owner/journal reopen after an injected
interruption, not a live daemon process-kill campaign. Production completion
storage/discovery, durable final retirement/release and daemon adoption remain
required before enabling this phase in ingress. No guest artifacts changed.

The combined native regression passes: **five passed, zero failed**, in
**56.37s** (`r16-native-operation-partial-retirement-regression.log`). Formatting
and diff checks pass. This is targeted coverage, not a new full release run.

### Bounded native operation completion storage

Verification: the final CLI suite passed **216 tests, zero failures, five
ignored**, in **14.14s**, including four completion-index tests. Evidence:
`.worktrees/ch08-c2-native/target/task-tmp/r16-native-operation-completion-store-cli-final.log`
(relative to the main checkout). The initial three focused tests passed in
5.26s; the earlier CLI run passed 215 tests before adding malformed-stage
coverage. Formatting and whitespace checks pass. These are host storage/CLI
checks, not a fresh live deployment or full-library release run.

The native operation completion index now has a dedicated, exclusively leased
CSF1 role (22) and an NCI1 image pinned to the configured Authority scope.
It retains at most 256 signed NOC1 certificates, with bounded canonical framing,
signature validation, sorted authorization IDs and no overlapping invocation
IDs. Exact retries preserve bytes and synchronize storage; capacity exhaustion
fails without eviction. Recovery validates both canonical and staged images
before publication, permitting only exact retention or one-record append to an
existing image. Removal, replacement and malformed stages preserve evidence and
fail closed. Missing existing stores are not silently recreated.

This backend is not yet owned by the production operation controller or daemon.
Signature/index validation is not native execution proof: startup must still
bind each certificate to both exact NOD1 records. NOC1 permits continuation of
acknowledgement, not release of admission. Final signed retirement after both
positive acknowledgements, its restart handling, and denial retirement remain
required. No guest artifact or user-facing operation endpoint changed here.

The next scoped C2 step is controller/daemon ownership of the completion-store
lease and recovery admission from its fully validated certificates, followed by
durable terminal retirement before release. Do not treat this storage checkpoint
as completion of protected invocation or the release gates.

### Controller-owned completion recovery

Verification: **5 native operation tests passed, zero failures**, in **68.19s**
(`r16-completion-controller-native-final.log`); **216 CLI tests passed, zero
failures, five ignored**, in **14.83s**
(`r16-completion-controller-cli-final.log`). Logs are in the shared disk-backed
`.worktrees/ch08-c2-native/target/task-tmp` directory. Initial builds caught an
incorrect host-error import at the storage boundary and a moved-store cleanup
in the test fixture; both were corrected before these passing runs. Formatting
and whitespace checks pass. No fresh live daemon or full-library release
campaign was run for this checkpoint.

Following the storage checkpoint, the native operation controller now owns a
fourth store handle through `NativeAuthorityOperationCompletionStore`. Daemon
startup opens `authority-operation-completions`, transfers its lease to that
controller, and restores retirement admission from its saved certificates before
system-owner attachment. Local lifecycle adoption retains the complete
controller and therefore all four leases. Decomposition of a completion-bearing
controller returns all four stores; the original three-store constructor has no
completion durability and its empty backend refuses retention.

Validation checks bounded certificates against the configured signer and both
exact native dispatch records, not merely the completion index's framing. The
startup discovery list must include both records. Validation failures preserve
the stores and no policy execution, signing, or admission release occurs there.
The positive native fixtures now reopen through controller-owned completion
storage after one or both acknowledgements, reject a deliberately corrupted
certificate without changing it, and reject incomplete discovery before
recovering the exact retirement pair.

Automatic completion capture and acknowledgement in production dispatch are
still unwired. Final durable retirement/release and denial retirement remain
required; simply loading a valid NOC1 is not permission to release admission.
No operation HTTP endpoint, guest artifact, or master integration changed.

### Production operation completion and acknowledgement

Verification: final native operation regression **6 passed, zero failures** in
**85.09s** (`r16-automatic-completion-native-final.log`); CLI regression **216
passed, zero failures, five ignored** in **16.89s**
(`r16-automatic-completion-cli.log`). Both logs are in the shared disk-backed
`.worktrees/ch08-c2-native/target/task-tmp` directory. The first native run also
passed all six in 85.15s before strengthening the reopened-controller retry
assertions. Formatting and whitespace checks pass. No full-library or fresh
live-daemon release campaign was run for this host-only checkpoint.

The native fixture covers a completion file published before an injected write
error: zero acknowledgements occur on that failure, and exact retry adds just
the two acknowledgement transitions without another receipt or completion
signature. Another exact retry changes neither bytes nor execution history.
The existing full/partial acknowledgement restart fixtures now call the same
production controller entry point after reopening. Unrelated projection work
remains excluded, demonstrating that acknowledgement alone does not release
the reservation.

Native Local lifecycle operation dispatch now uses the controller's
`coordinate_and_acknowledge` path. It validates retained state, recovers or
issues the exact operation evidence, reads both native dispatch records, and
verifies the actual native policy results before signing new completion.
Completion retention must succeed before either result acknowledgement. A
saved certificate is fully restored against its source records and retained
again to establish durability, without another completion signature. The
configured owned operator signer now implements completion signing, and Local
lifecycle adoption checks both operation and completion signer keys.

An ambiguous completion write that publishes before reporting failure returns
unavailable without acknowledging either result. Exact retry uses that saved
certificate; successful result acknowledgement remains independently verified
by the native owner. Denials still return unavailable and retain their native
reservation, without signing completion. Admission is deliberately not released:
NOC1 is continuation evidence, not the required terminal retirement record.
This change does not apply the requested actor operation or add operation HTTP
ingress. Final durable release, denial retirement, and protected application
remain the next C2 work.

### Signed terminal operation retirement boundary

Verification: the native operation regression passed **6 tests, zero failures**
in **93.56s** (`r16-terminal-operation-retirement-native.log`); CLI regression
passed **216 tests, zero failures, five ignored** in **17.30s**
(`r16-terminal-operation-retirement-cli.log`). The final strengthened partial
acknowledgement test passed **1 test, zero failures** in **25.91s**
(`r16-terminal-operation-retirement-partial-final.log`), explicitly verifying no
retirement signature or publication after only one acknowledgement. Formatting
and whitespace checks pass. Logs are in the shared disk-backed
`.worktrees/ch08-c2-native/target/task-tmp` directory. These are targeted native
and CLI checks, not a full-library or fresh live deployment release campaign.

NRT1 is a bounded host-only terminal certificate containing the exact NOC1
continuation and a separately domain-separated Authority signature. Restoration
verifies canonical framing, the terminal signature, and the embedded completion
against both exact NOD1 source records. A completion certificate alone cannot be
used as retirement evidence. This certifies retirement of the policy-result
pair, not application of the authorized actor operation.

The native owner signs and persists NRT1 inside the existing network retirement
completion callback. That callback runs under proposal exclusion only after
the native host independently confirms both positive acknowledgements. Failure
before or during durable publication preserves exclusion. Recovery from an
ambiguous successful publication verifies and synchronizes the exact saved
certificate before idempotent release, without another signature. These are
owner-level APIs; production controller retirement storage, owned retirement
signer wiring, and startup classification of retired pairs are still required.
Production dispatch continues to retain admission after NOC1 acknowledgement
until that integration exists. No guest bundle or user-facing ingress changed.

The native fixtures test rejection without signing before acknowledgement,
rejection after only one positive acknowledgement, publication followed by a
reported failure with exclusion preserved, exact signed retry, and restoration
of published retirement followed by idempotent release. Corruption, truncation,
trailing bytes, and substitution of NOC1 for NRT1 fail verification. Successful
release permits the previously excluded projection reservation without adding
native execution transitions. Restart classification using NRT1 is not yet
covered and must not be inferred from same-owner certificate restoration.

### Native startup classification of retired operation pairs

Verification: native operation regression **6 passed, zero failures** in
**106.17s** (`r16-terminal-operation-reopen-native.log`); CLI regression **216
passed, zero failures, five ignored** in **16.54s**
(`r16-terminal-operation-reopen-cli.log`). The final test adding explicit
missing-bootstrap rejection passed **1 test, zero failures** in **27.63s**
(`r16-terminal-operation-reopen-final.log`). Logs are in the shared disk-backed
`.worktrees/ch08-c2-native/target/task-tmp` directory. Formatting and whitespace
checks pass. These are targeted host/native checks, not final release evidence.

Startup admission now accepts bounded NRT1 terminal evidence alongside the
complete NOD1 discovery set and NOC1 completion index. It verifies canonical
framing, both signatures, exact embedded completion membership, and linkage to
both source dispatch records before excluding a retired pair from pending or
retiring admission. Missing completion/source records, duplicate terminal
records, and substitution of a completion for a terminal certificate fail
closed. The terminal signature/framing helper is public for the upcoming file
backend, but does not replace native source-record verification.

An admission set containing only retired pairs has no active reservations but
still has history. Both bootstrap entry paths require completed existing
bootstrap state for that history, so retired evidence cannot turn a missing
bootstrap record into permission to initialize a new system. The native fixture
closes and reopens the owner after signed terminal publication, restores the
retired pair without execution or signing, retries release, and successfully
reserves unrelated projection work. The missing-bootstrap check rejects before
calling the fresh factory.

The production operation controller and daemon still do not own/discover a
terminal retirement store. They therefore continue to restore NOC1 pairs as
retiring, not released. The next C2 step is hardened retirement storage plus
controller/daemon adoption and exact terminal retry, using this classification
before attachment. Mixed unfinished-operation/projection coverage and the
remaining application/release gates are not closed by this single-pair test.

### Hardened terminal operation retirement index

Verification: **219 CLI tests passed, zero failures, five ignored**, in
**33.78s**, including three new retirement-index tests and the unchanged
completion-index regressions. Evidence:
`.worktrees/ch08-c2-native/target/task-tmp/r16-terminal-operation-store-cli-final.log`.
The first compile caught a static-lifetime requirement in the shared namespace
entry list, corrected before the passing run. Formatting and whitespace checks
pass. No native execution behavior changed and no fresh live daemon or
full-library release run was performed for this storage checkpoint.

`CleanNativeAuthorityOperationRetirements` implements the leased retirement
store boundary using the completion index's shared hardened storage logic.
Its namespace is separate: CSF1 role 23, `authority-operation.retirements` and
its `.next` stage, with NRI1 framing and a retirement-specific Authority scope
digest. The existing completion namespace and NCI1 wire image are unchanged.
The index retains at most 256 NRT1 certificates, each bounded to 1,024 bytes.
It validates both terminal and embedded completion signatures, rejects reused
invocation IDs, and permits only exact retry or one-record append to an existing
image. No record is evicted to make room.

Recovery verifies both images before publishing an append. Removal,
replacement, duplicates, malformed framing, and completion-only substitution
preserve source/staged evidence and fail closed. The storage fixtures cover
exclusive leases, wrong Authority scope, missing-existing behavior, exact byte
retention, nested-signature rejection, stage recovery, and capacity exhaustion.
They use synthetic signed source hashes, not native execution evidence; startup
must still match each certificate against its exact NOD1 pair and NOC1 index.

The backend is not yet adopted by the production controller/daemon. That wiring,
owned terminal signing, and exact retry after terminal publication remain the
immediate C2 integration work. No guest artifact or HTTP endpoint changed.

### Production terminal retirement and exact retry

Verification: final native operation regression **6 passed, zero failures** in
**104.97s** (`r16-terminal-operation-controller-native-final.log`), with the
normal test stack limit; CLI regression **219 passed, zero failures, five
ignored** in **34.11s** (`r16-terminal-operation-controller-cli-final.log`).
The normal daemon binary rebuilt in **11.59s**
(`r16-terminal-operation-controller-build-final.log`). These logs are in shared
disk-backed `.worktrees/ch08-c2-native/target/task-tmp`.

Two initial native runs aborted with a stack overflow. Removing redundant
nested coordination did not resolve it; a debugger backtrace located the
overflow in Standard-runtime replay during bootstrap reopen, before the new
terminal entry point. The expanded automatic-write fixture campaign was
extracted into a separate helper to keep its locals off that replay stack.
The final run passed without increasing the stack limit. Diagnostic evidence:
`r16-terminal-operation-controller-stack.log` in the same directory. This is
targeted recovery evidence, not a completed full-library release run.

Daemon startup now opens `authority-operation-retirements` and transfers its
exclusive store handle into the operation controller alongside coordinator,
issuer, NOD1 journal and NOC1 completion stores. Validation and startup admission
load the terminal index and fully cross-check its records before attachment.
Controller decomposition returns every adopted handle rather than silently
dropping the retirement lease. The owned operator signer implements terminal
signing, and Local lifecycle adoption verifies all three signer capabilities
against the configured Authority key.

Production native dispatch now calls `coordinate_and_retire`. It recovers or
issues exact evidence once, completes and acknowledges the pair through a
shared completion helper, and publishes signed terminal retirement under
exclusion before release. A retained NRT1 takes the terminal retry path instead:
verify exact source records, synchronize the saved certificate, then idempotently
release without re-acknowledging or re-signing. Publication followed by an error
preserves exclusion until exact retry establishes durability. Denials remain
unavailable and reserved; their terminal recovery still needs implementation.

Native fixtures cover terminal publication failure, exact same-owner retry,
retired owner/controller reopen, and unchanged execution/signature counts.
The production path does not apply the authorized actor operation and still has
no operation HTTP endpoint. Protected application, denial/expiry resolution,
mixed pending work, capacity/GC, and C3 release gates remain open.

The rebuilt daemon also passed the existing disposable-state ingress campaign
in `target/native-denial-head-reuse.XoaplU`. Start: **2026-09-13 20:42:32 UTC**;
ready: **20:47:37 UTC** (about **5m05s**); the ignored live retirement/exact HTTP
acknowledgement retry test passed **1 test in 1.18s**, with two forced exact
acknowledgement retries. Campaign exited zero at **20:47:42 UTC**, followed by
clean shutdown at **20:48:12 UTC** and removal of the endpoint marker. Evidence:
`terminal-controller-startup-{run,daemon,client-test}.log` under that disposable
root. The saved invocation request/response/progress hashes remain unchanged.
The new completion and retirement directories are mode 0700 with mode-0600
lock files. Their indexes are empty in this live campaign: it proves normal
daemon adoption/startup and existing Public-query ingress compatibility, not
live protected operation authorization. Positive operation retirement/reopen
evidence comes from the native tests above. Startup latency remains high.

### Native unissued operation denial proof and acknowledgement

Verification: **7 native operation tests passed, zero failures**, in **111.97s**
(`r16-native-operation-denial-proof-final.log`); **219 CLI tests passed, zero
failures, five ignored**, in **37.35s** (`r16-native-operation-denial-proof-cli.log`).
Logs are in shared disk-backed `.worktrees/ch08-c2-native/target/task-tmp`.
The initial compile required explicit SDK outcome/status imports, fixed before
the passing runs. Formatting and whitespace checks pass. No fresh live campaign
or full-library release run was performed for this native-owner checkpoint.

The operation denial boundary now inspects exact retained native policy
execution without dispatching new work. It validates the signed authorization
record and physical reservation, requires a matching non-poisoned issuer with
no retained issuance for that invocation, and independently replays the durable
input after its saved anchor. Only canonical empty approval bytes from a
matching completed reply produce a denial proof; absent execution, another
reply, or execution/storage errors cannot be substituted for denial.

The proof borrows the issuer mutably for its lifetime, preventing issuance or
replacement while it is used. The native owner acknowledges only that exact
reserved input, checks the complete acknowledgement identity/commitments, and
independently observes positive durable acknowledgement. Exact retries do not
add another transition. The reservation is deliberately retained: signed
terminal denial evidence and production controller/startup integration still
need implementation before release is safe.

The new native fixture checks no proof before policy execution, wrong issuer
scope rejection, genuine bundled-Authority denial, one positive acknowledgement,
exact acknowledgement retry, proof reconstruction after acknowledgement, no
issuer record/write, unchanged native source bytes, and continuing exclusion of
unrelated projection work. The approved-operation fixture additionally rejects
denial classification when issuance is retained. This does not yet prove denial
retirement or a usable successor operation after denial.

### Signed native operation denial retirement boundary

Verification: **8 native operation tests passed, zero failures**, in **120.28s**
(`r16-native-operation-denial-retirement.log`); **219 CLI tests passed, zero
failures, five ignored**, in **36.27s**
(`r16-native-operation-denial-retirement-cli.log`). Logs are in shared disk-backed
`.worktrees/ch08-c2-native/target/task-tmp`. Formatting and whitespace checks
pass. No full-library or fresh live deployment campaign was run for this
native-owner checkpoint.

NDR1 is now a bounded host-only terminal denial certificate, separately domain
signed over the invocation, exact NOD1 source-record commitment, signed call
commitment and durable replay input. Native verification retains the source
record and borrows the issuer until the proof/terminal token is dropped, keeping
the unissued invariant intact. Restoration validates canonical framing,
signature and source/call linkage, and rejects a mismatched, poisoned or
already-issued issuer. It does not reinterpret execution/storage errors as
policy denial.

The owner signs and persists NDR1 through the existing pending-denial completion
callback, under proposal/host exclusion and only after independently confirmed
positive acknowledgement. A failed write retains admission even if it already
published the certificate. Exact signed retry can finish that callback; an
already-published certificate can instead be verified and synchronized before
idempotent release without another signature. A denial store lease remains a
caller requirement, and production store/controller/startup integration is not
yet implemented.

The two native denial fixtures cover premature retirement rejection without
signing, publication followed by error with exclusion preserved, byte-identical
signed retry, restored-certificate release without re-signing, malformed and
substituted certificate rejection, unchanged issuer/source evidence, and no
additional native execution transitions. After durable release the previously
excluded projection reservation succeeds. This is same-owner recovery evidence;
NDR1 startup classification and a live valid-successor campaign remain open.

### Issuer-gated native denial restart classification

Verification: **8 native operation tests passed, zero failures**, in **116.78s**
(`r16-native-operation-denial-reopen.log`); **219 CLI tests passed, zero failures,
five ignored**, in **35.42s** (`r16-native-operation-denial-reopen-cli.log`).
Logs are in shared disk-backed `.worktrees/ch08-c2-native/target/task-tmp`.
Formatting and whitespace checks pass. No fresh live-daemon or full-library
release campaign was run for this native recovery checkpoint.

Native operation startup admission now accepts signed NDR1 evidence while
borrowing both the native journal and issuer stores through attachment. It
reopens and validates issuer state, verifies each signed denial against the
exact source record, and requires absence of retained issuance for that
invocation. Duplicate/missing denial sources, malformed signatures, issuance
acknowledgement records contradicting denial, and completion/denial overlap all
fail closed. A denied-only history has no active reservations but still requires
completed existing bootstrap state.

The denial fixtures close and reopen the owner after terminal publication,
restore the signed denial without another execution/signature, repeat release,
and successfully reserve unrelated projection work. Negative cases reject
missing source discovery, duplicate certificates, corrupted signatures and
native-record substitution. The approved fixture deliberately constructs a
correctly signed but contradictory denial storage record: issuer history
prevents it from being admitted, regardless of its signature. That synthetic
record is test-only and is not native policy-denial evidence.

The new public signature/framing helper supports the forthcoming durable denial
index; it is not sufficient without native-source and issuer-history checks.
Production daemon/controller discovery of denial storage, automatic terminal
denial handling, and live valid-successor testing remain open. No guest bundle,
HTTP endpoint or master integration changed in this checkpoint.

### Hardened native operation denial index

Verification: **222 CLI tests passed, zero failures, five ignored**, in
**37.14s**, including three new denial-index tests and the existing completion/
retirement regressions. Evidence:
`.worktrees/ch08-c2-native/target/task-tmp/r16-native-operation-denial-store-cli.log`.
Formatting and whitespace checks pass. No native execution behavior changed;
no full-library or fresh live deployment campaign was run for this storage
checkpoint.

`CleanNativeAuthorityOperationDenials` now implements the leased denial store
boundary. It uses a separate CSF1 role (24), `authority-operation.denials` and
its `.next` stage, NDI1 framing, and a denial-specific Authority scope digest.
It shares the hardened certificate-index engine with completion and successful
retirement through an explicit certificate-kind enum. Existing NCI1/NRI1 bytes
and namespaces are unchanged. Denials carry one invocation ID rather than a
pair, with uniqueness and canonical ordering checked before publication.

The index bounds retention to 256 NDR1 records of at most 512 bytes each.
Signature/framing checks reject completion/retirement substitution; native
source binding and issuer-history checks still belong to startup recovery.
Exact retries synchronize unchanged bytes. Recovery permits only retention or
one-record append to an existing image; deletion, replacement, duplicate IDs,
invalid ordering/signatures and trailing bytes preserve evidence and fail
closed. Capacity exhaustion does not evict records.

Storage fixtures cover exact retry, exclusive ownership, wrong Authority scope,
missing-existing behavior, cross-kind rejection, staged append recovery,
conflicting/malformed stage preservation, and the count limit. Their signed
source hashes are synthetic storage fixtures, not native denial proof. The
backend is not yet adopted by the production controller/daemon; that integration
and automatic terminal denial handling remain next within C2.

### Production operation denial-store recovery adoption

Verification: **8 targeted native tests passed, zero failures**, in **117.92s**;
**222 CLI tests passed, zero failures, five ignored**, in **46.82s**. Evidence
is in `.worktrees/ch08-c2-native/target/task-tmp/`:
`r16-denial-adoption-native-final.log` and
`r16-denial-adoption-cli-final.log`. Formatting and whitespace checks pass.
The initial CLI run had seven loopback permission failures; the permitted rerun
passed. The initial native compile found a moved journal handle in fixture
cleanup, corrected before the passing run. The full library/release matrix was
not rerun.

The production controller now owns the denial-index lease alongside its five
existing stores. Daemon startup opens `authority-operation-denials` and uses
issuer-gated denial admission before attaching the native owner. Validation
checks signed denial IDs against canonical native dispatches and freshly read
issuer history; missing discovery, contradictory issuance, duplicate evidence
and cross-kind substitution remain errors. A controller without a denial store
has an empty, fail-closed default that cannot acknowledge retention.

Both native terminal-denial fixture variants now reopen through this controller,
including rejection of an omitted source discovery set. The controller retains
all store handles during attachment, and its six-part decomposition explicitly
returns the denial handle rather than silently dropping it.

This checkpoint only integrates recovery. Production dispatch still does not
automatically sign/retire a new policy denial or return a retained denial on exact
retry. That distinction, the valid-successor campaign, operation HTTP/client
wiring and protected mutation remain open. No guest artifact or master branch
change is included; no new live-daemon campaign is claimed.

### Typed native operation decision and automatic denial retirement

Verification: **9 targeted native tests passed, zero failures**, in **137.01s**;
**222 CLI tests passed, zero failures, five ignored**, in **47.99s**. Evidence:
`.worktrees/ch08-c2-native/target/task-tmp/r16-denial-decision-native-final.log`
and `r16-denial-decision-cli-final.log` in the same directory. Formatting and
whitespace checks pass. No full-library, live-daemon, artifact reproduction or
performance campaign was run for this checkpoint.

The first native run failed two tests: it exposed re-pledging after acknowledged
denial/certificate-write failure, and an outdated fixture expectation that the
restored valid denial could never reach signing. The corrected path verifies
pledge absence before direct denial recovery. The fixture now injects signer
unavailability and verifies that the acknowledged result still returns an error,
not a terminal decision. Its corrupt-journal rejection checks remain intact.

The production operation API now returns an explicit issued authorization or a
signed terminal denial. Only the coordinator's exact `AuthorizationDenied`
result reaches native denial verification, positive acknowledgement and signed
retention. Transport, execution, signing and storage errors remain errors, never
policy denials. All signer identities are pinned during controller adoption.

An exact retained denial is checked against the original call/context, canonical
native source and freshly read absence of issuance. The controller synchronizes
the exact saved certificate before releasing admission or returning it; it does
not dispatch policy or create a new coordinator pledge on that terminal retry.
If acknowledgement succeeded but certificate retention did not, recovery also
requires that the unissued coordinator pledge has been durably removed before
reconstructing the native denial proof and retrying retention. A still-pledged
call remains on the coordinator path; native evidence is not used to bypass its
journal transition.
Successful authorization uses the existing completion/retirement boundary.
Neither outcome claims that the requested actor operation has been applied.

The added native campaign injects failure before denial publication and failure
after publication, checks reservation exclusion, and retries exact bytes without
new native execution. Positive retirement coverage also exercises the typed
decision path. The existing owner-reopen fixtures remain separate evidence;
this is not a live operation HTTP/client or valid-successor pass.

Scope remains C2. Operation ingress/client, protected application and restart,
the remaining runtime support and recovery gates, and C3 remain unfinished.
Create/Install latency is explicitly a production blocker: hashing-dominated
execution and expensive inventory refresh are measured, but their underlying
cause and acceptable fresh-response performance are not yet established.
Timeout extensions or repeated retries do not close that gate.

### Exact operation submission and bounded native queue

Verification: **2 focused frame/queue tests passed**, zero failures, in **0.04s**;
**222 CLI tests passed**, zero failures, five ignored, in **52.03s**. Logs under
`.worktrees/ch08-c2-native/target/task-tmp/` are
`r16-operation-submission-final.log` and `r16-operation-submission-cli.log`.
Formatting and whitespace checks pass. Initial compilation required correcting
the nested decoder's borrowed bytes and explicit wire-error conversion.

The broader coordinator run subsequently completed: **23 passed, zero failures**
in **1,593.99s**, including the full-capacity retention fixture. Evidence:
`r16-operation-submission-coordinator-final.log`. This run predates the response
and HTTP checkpoints and is not a current-source full-library release pass.
No native PVM execution or live HTTP campaign is claimed for this queue slice.

`AuthorityOperationSubmission` adds canonical AOQ1 framing for the exact signed
AOC5, authorization invocation context and selected issuance slot. Construction
and decoding check the original ingress signature, call/context binding, wire
bounds and slot range; malformed/trailing/truncated input is not a submission.
The frame is untrusted request data, not policy approval or an issued receipt.

Authorization now shares the existing bounded native lifecycle queue with
Create/Install. The node passes the exact retained inputs to its production
operation controller and replies with its typed decision. Full/closed queues
fail explicitly. Receiver disconnection does not cancel accepted work, while
shutdown rejects queued work as unavailable. Queue acceptance does not promise
durability; the client must retain the exact frame before submitting it.

This is the native request/queue boundary, not an HTTP endpoint or a completed
client. Durable client retention, bound response verification, HTTP handling,
fresh preparation and protected application still belong to the remaining C2
work. No guest artifacts or performance behavior are claimed changed.

### Request-bound operation responses and immutable client retention

Verification: **226 CLI tests passed**, zero failures, five ignored, in
**63.52s**; **9 native operation tests passed**, zero failures, in **208.99s**;
the focused issued-response verifier passed **1 test** in **0.27s**. Logs under
`.worktrees/ch08-c2-native/target/task-tmp/`:
`r16-operation-response-client-final.log`, `r16-operation-response-native-final.log`,
and `r16-operation-response-verifier-final.log`. Formatting and whitespace checks
pass. The first CLI fixture compile used a private decoder and the wrong ABI
length accessor; the fixture was corrected before these passing checks.
The earlier 23-test coordinator process subsequently passed in 1,593.99s and
predates this response checkpoint; it is not current-source release evidence. No full release
matrix, live HTTP or artifact rebuild is claimed here.

AOR1 carries either the signed AOI1 (including its receipt), or NDR1 plus its
committed NOD1 source. Response verification always uses the independently
retained AOQ1, never an authority key selected by the response. Issued evidence
must match the exact call, acknowledgement identity and retained issuance slot;
the verifier reconstructs the expected approval selector and checks both
authority signatures. Historical verification is not present-day receipt
liveness: application must still independently check expiry.

Denial verification checks the entire original dispatch against NDR1, including
the expected call and authorization context. A valid signature/InvocationId alone
is insufficient. The native decision now returns the original source alongside
the exact retained denial certificate; this adds no new signature or guest wire
format. Client verification does not replace native issuer-absence/replay checks.

`CleanOperationClientFile` retains immutable AOQ1/AOR1 under an exclusive private
directory, using distinct CSF1 roles 25/26 and `operation.request` /
`operation.response` files. Exact retries synchronize unchanged evidence. A
response requires its existing independently retained request, including during
staged recovery; new input cannot repair an orphan response. Both canonical and
staged payloads are validated before recovery publication, and either role rejects
replacement lineage. Malformed or substituting stages preserve both files. This backend is not
yet a CLI delivery command or HTTP endpoint.

Tests cover signed issued-response substitution and invalid receipt signatures,
signed denial/source/context binding, framing/truncation, exact file retry,
exclusive ownership, staged recovery and orphan rejection. CLI denial storage
fixtures use a synthetic journal anchor/input commitment, not native policy
execution evidence; native owner tests separately exercise actual denials.

### HTTP operation authorization and retained-submission CLI

Verification: **228 CLI tests passed**, zero failures, five ignored, in **62.21s**;
**4 ingress-server tests passed**, zero failures, in **0.27s**. Evidence under
`.worktrees/ch08-c2-native/target/task-tmp/`: `r16-operation-http-cli.log` and
`r16-operation-http-server-final.log`. The server tests include exact path versus
adjacent-path isolation and malformed frame rejection. The CLI campaign uses a
loopback mock server with correctly signed fixture responses; it is not a live
native authorization/application campaign.

The normal `vosx` binary also built successfully in about 65 seconds
(`r16-operation-http-build.log`), and its
`space submit-agent-authorization --help` output confirms the retained-input
command is available. Formatting and whitespace checks pass. All test/build
processes from this and the preceding coordinator campaign are terminal.

`POST /__agents/authorize` accepts signed canonical AOQ1 on the existing bounded
lifecycle queue. Exact path routing, POST/content-type/body checks and rejection
of caller-asserted transport nodes apply before enqueue. Both completed signed
policy decisions return HTTP 200 with AOR1; the verified payload distinguishes
issuance from denial. Queue/controller failures return 503, and the existing
120-second wait returns 504 without cancelling accepted work. No timeout was
increased and this does not resolve the production latency gate.

`vosx space submit-agent-authorization REQUEST_DIR --request INPUT --http ADDRESS`
persists the initial exact request before delivery, ignores new input once a
request exists, verifies the bound signed response and synchronizes it before
reporting completion. Retry can omit `--request`; a saved decision is verified
locally without another HTTP request. Delivery uses loopback only, no environment
proxy or redirects, bounded binary responses and the existing transport client.
Output distinguishes `issued` / `denied` and explicitly reports `applied: false`.

This is retained-input delivery, not a fresh preparation/signing command or
proof of protected actor application. The latter, its live restart/resume
campaign, the existing latency blocker and remaining C2/C3 gates remain open.

### Operation-domain discovery and deterministic prepared-work signing

Verification: **230 CLI tests passed**, zero failures, five ignored, in **52.09s**
(`.worktrees/ch08-c2-native/target/task-tmp/r16-operation-preparation-cli.log`).
Formatting and whitespace checks pass. This is client-side preparation coverage,
not native protected execution or a fresh end-to-end command campaign.

Credential discovery now explicitly selects the management or operation request
sequence domain while preserving exact retained query bytes. Operation requests
use `operation_request_high_water + 1`, not the Create/Install management counter.
Each domain fails independently on exhaustion; an exhausted management/admin
counter does not prevent signing an operation with available operation sequence.
Discovery remains a hint, not an exclusive reservation or policy approval.

The operation preparation helper checks the supplied Agent descriptor's Authority
binding, profile, runtime identity/package and prepared observation, then derives
the signed intent from the exact prepared invocation work. Its signing boundary
requires the selected operator's active API credential query/projection and
rejects a mismatched prepared caller before invoking the key. Authorization ID
is derived canonically; caller-selected authorization/issuance/validity slots are
fixed inputs, with no new clock or random ID read inside the signer.

Tests verify deterministic AOQ1, correct sequence-domain selection despite other
domain exhaustion, credential revocation/kind/scope/signature mismatches, invalid
timing and wrong prepared caller. The signing tests use shaped invocation intent;
they do not assert host preparation or Authority policy execution.

The helpers are not yet orchestrated by a fresh user-facing command. That command
must own the credential reservation, retain initial intent and physical
preparation, load any existing AOQ1 before fresh discovery/signing, and publish the
exact new AOQ1 before HTTP delivery. Protected application and restart remain
subsequent C2 work; no release or latency gate is waived.

### Durable targeted physical preparation

Verification: **231 CLI tests passed**, zero failures, five opt-in tests ignored,
in **53.26s** (`.worktrees/ch08-c2-native/target/task-tmp/r16-preparation-retained-cli.log`).
Formatting and whitespace checks pass. Earlier runs exposed fixture-only issues
(private parent admission and canonical schema/availability construction), fixed
before this pass. No current native or live-daemon campaign is claimed here.

The fresh-command foundation now has a separately leased immutable ATQ1/ATP1
pair (CSF1 roles 27/28), reusing the existing operation-client storage engine.
It retains the exact targeted intent before authenticated HTTP delivery, verifies
the response against that intent, and syncs the first bound preparation before
returning it. Retries use the saved intent even when supplied a different new
intent, and a saved response can be returned without contacting the daemon.
Both canonical and staged images are checked before recovery promotion; orphan
responses cannot be repaired with new input, and replacement lineage is rejected.
Tests cover authenticated exact-body retries after errors, redirects, wrong
content type, malformed and wrong-request ATP1; successful retention and offline
reuse; exclusive leasing, staged recovery, corrupt-stage preservation and orphan
rejection. The shaped response uses admitted Catalog artifacts and tests wire
binding, not native execution or usable Catalog installation configuration.

This is historical physical work, not Authority approval, host attestation or a
guarantee that its observed head remains live. The fresh command still needs
credential-wide reservation and orchestration through discovery, retained
preparation, signing, authorization and protected application. No timeout,
latency gate, bundled artifact or review-batch boundary changed.

### Operation denial and credential reservation

Verification: **232 CLI tests passed**, zero failures, five opt-in tests ignored,
in **48.56s** (`.worktrees/ch08-c2-native/target/task-tmp/r16-operation-reservation-cli.log`).
Formatting and whitespace checks pass; no new native/live-daemon result is claimed.

The credential-wide reservation now has a denial-only operation release helper.
It loads and syncs the exact retained AOQ1/AOR1 under the delivery lease, verifies
the signed denial/source binding, and checks Space, credential and the signed
actor invocation ID against the reservation nonce. The denied marker commits
both exact request and response hashes with operation-specific domains. Exact
repeat after reopen is idempotent; a different signed decision with the same
invocation nonce cannot replace a terminal marker. A successor reservation cannot
be released using the predecessor's denial.

Missing responses, malformed staged responses and wrong scope leave reservations
pending. Issued authorization is explicitly rejected by this release helper:
receipt issuance is not proof of protected application completion. This closes
a prerequisite for managed operation orchestration, not that command itself.
The fresh command and live protected application/restart gates remain open.
Tests use signed protocol fixtures, not native actor denial execution.

### Managed Local invocation authorization

Verification: **235 CLI tests passed**, zero failures, five opt-in tests ignored,
in **48.62s** (`.worktrees/ch08-c2-native/target/task-tmp/r16-managed-operation-cli.log`).
The normal CLI build also passes (**7.03s**, `r16-managed-operation-build.log`),
and `space authorize-local-invocation --help` advertises its authorization-only
and pending-reservation constraints. Formatting and whitespace checks pass.
No live fresh authorization or protected
application result is claimed.

`authorize-local-invocation SPACE --intent intent.atq1` now connects the existing
credential-wide reservation, retained ATQ1/ATP1 preparation, operation-domain
credential discovery, Local descriptor discovery, deterministic signing and
retained AOQ1/AOR1 delivery. `--resume` selects the current reservation and reads
no new input. Existing AOQ1 is checked before discovery/preparation/signing; a
missing retained intent permits retry only with the original explicit input.
The common request namespace rejects attempts to resume a Create/Install as an
operation. Scope checks require the selected operator, Space and Local node.

This is an advanced canonical-intent authorization interface, not a complete
invocation command. It does not generate actor messages or apply an issued
receipt. Errors and issuance keep the reservation pending; an exact retained
signed denial completes it with the distinct denied marker. Protected
application, terminal retirement/reservation completion, live fresh authorization
and restart remain required C2 work. Production latency is still blocking.

The managed-resume test uses signed shaped native records. It verifies exact
AOQ1 after HTTP 504, held credential lease during delivery, denied completion,
wrong-node rejection and cached retry without discovery/preparation files.
Fresh-intent tests verify caller rejection before client state, immutable ATQ1
and query retention before failed discovery, and pending-successor exclusion.
These tests do not prove a live fresh authorization/actor mutation campaign.

### Issued authorization to exact application envelope

Verification: **236 CLI tests passed**, zero failures, five opt-in tests ignored,
in **51.28s** (`.worktrees/ch08-c2-native/target/task-tmp/r16-operation-application-cli-final.log`).
The normal CLI build passes in **4.80s** (`r16-operation-application-build.log`).
Formatting and whitespace checks pass. No native protected invocation campaign
is claimed at this checkpoint.

The managed authorization command now retains receipt-bearing ASQ1 in the
operation's `application/` child before returning an issued decision. The handoff
holds the credential reservation, re-verifies/syncs retained AOQ1/AOR1 and
ATQ1/ATP1, requires the signed operation intent to match every prepared-work
commitment field, and uses the exact issued receipt. It never re-prepares missing
physical work or replaces a previously retained application envelope. Orphaned
response/progress histories remain rejected by the existing invocation store.

This is durable application preparation, not actor dispatch, successful mutation
or positive application retirement. The command still reports `applied: false`
and leaves issuance pending. A historical receipt signature check does not bypass
the runtime's live expiry/policy checks. Required next work is application delivery,
continuation/retirement and credential completion, followed by the live native
campaign. No production latency or release gate is waived.

The signed fixture checks exact retained issuance, missing/corrupt decisions,
missing or substituted preparation, stable ASQ1 on reopen, and preservation of a
conflicting public invocation. It also verifies that a valid issued decision
cannot use the denial-only reservation release. The fixture uses real Ed25519
signatures and admitted Catalog artifacts but shaped evidence, not native policy
execution or usable Catalog installation configuration.

### Managed Local application, retirement and credential completion

Verification: **237 CLI tests passed**, zero failures, five opt-in tests ignored,
in **52.83s** (`.worktrees/ch08-c2-native/target/task-tmp/r16-operation-retirement-cli.log`).
The normal CLI build passes in **5.04s** (`r16-operation-retirement-build.log`),
and `space invoke-local --help` succeeds from that binary.
Formatting and whitespace checks pass. No new native/live mutation result is claimed.

`invoke-local SPACE --intent intent.atq1` and `--resume` reuse the managed
authorization path while holding the same credential-wide reservation through
application delivery, continuation and positive acknowledgement. The
authorization-only command remains unchanged in purpose. Missing responses or
HTTP errors never release the reservation, and issuance alone remains pending.

Completion requires retained/synchronized AOQ1/AOR1, the exact receipt-bearing
ASQ1, its initial response and canonical continuation history. The signed intent
must match the complete work; Space, credential and invocation nonce must match
the reservation. History must end with an explicit positive acknowledgement
exchange, not an initial response, yield, completed actor reply or failed ACK.
The terminal reservation commits exact authorization and application/history
hashes. Exact replay is idempotent, while a successor cannot be completed with
its predecessor's retirement. `delivery_retired` deliberately does not claim
business success: the runtime can positively retire an actor error.

The loopback fixture starts from signed retained issuance and prepared work,
injects 504 at initial delivery and acknowledgement, verifies exact request bytes
and the held credential lease, then proves terminal completion and no-network
retry after reopen. Existing continuation fixtures also check that empty, pending
and failed-ACK histories do not count as retired. These are shaped signed protocol
records and HTTP responses, not native guest execution. Live fresh protected
authorization/application, mutation/restart, Shared finality, latency and full
release gates remain required. No bundled artifacts or timeouts changed.

### First native managed receipt-bearing invocation campaign

On the existing disposable `target/native-denial-head-reuse.XoaplU` space, the
normal binary at `831f6d57` started at **2026-09-14 16:33:21Z**, became ready at
**16:39:49Z** (about **6m28s**), and shut down cleanly at **16:41:10Z**, with its
endpoint removed. Startup inventory dispatch took **194.351s** and complete
reconciliation **197.298s**. Two short CPU profiles were taken during startup,
so this is diagnostic timing, not an uninstrumented release latency result.

The new opt-in `real_daemon_managed_receipt_invocation_and_exact_retry` attempted
a receipt-bearing `page` query on the already-installed Local Catalog actor.
It **failed after 80.36s at `/__agents/authorize` with HTTP 503**. ATQ1, ATP1 and
signed AOQ1 were retained for exact retry; no AOR1, application envelope or native
operation journal/coordinator/issuer image was published. The credential remains
pending. This is a concrete native authorization blocker, not a completed
invocation or mutation result. The Catalog method is Public; even a future pass
of this campaign will not by itself prove non-Public policy or mutation.

Evidence remains in `managed-receipt-first-daemon.log` and
`managed-receipt-first-client-test.log` under that disposable root. The operation
nonce is `fb1fa8b78381d4729409d93eb21d797f019da38018c7e816ee2d65d45b0a3eed`.
Never replace its signed request/timestamps or clear its reservation to retry.
The exact native failure stage was not logged by the tested binary. The strict
AuthorizeOperation observation-equals-physical-clock check is a candidate,
not a confirmed diagnosis. Added diagnostics now report controller error class
and rejected requested/physical clock slots, without relaxing those checks or
logging request bodies/credentials. Next: diagnose the exact retained retry and
fix the demonstrated native handoff, preserving recovery binding.

Five-second profiles, kept under shared disk-backed `target/task-tmp`, show
different phase costs: `r16-managed-startup.perf` sampled **72.75%** of core cycles
in the PVM interpreter; `r16-managed-inventory.perf` sampled **54.23%** in BLAKE2
and **19.79%** in the interpreter. Both crates already have opt-level 3 dev/test
overrides. These short samples do not identify the full caller/root cause.
An argument-free debugger attach was denied by the OS; permissions were not
changed. No `/tmp` scratch, timeout increase, validation bypass or latency waiver
was introduced.

Normal regression verification after adding the campaign/diagnostics:
**237 CLI tests passed**, zero failures, **six ignored**, in **50.51s**
(`r16-managed-live-cli.log`). The opt-in live test separately failed as described
above; the ordinary suite is not evidence that this live blocker is resolved.
The normal diagnostic binary builds in **15.02s**
(`r16-managed-live-diagnostic-build.log`); formatting and whitespace checks pass.

### Confirmed native clock mismatch and host-owned preparation

The diagnostic exact retry started at **2026-09-14 16:47:52Z**, became ready at
**16:50:07Z**, and shut down cleanly at **16:50:31Z**, with the endpoint removed.
It failed after **18.73s** with the same HTTP 503. The new native diagnostic
confirms rejection of requested slot **1789404055** versus physical slot
**1789404630**, before any native operation record was published. Logs are
`managed-receipt-diagnostic-{daemon,client-test}.log` in the disposable root.
The request/reservation remain untouched. This retry was not profiled; the
different startup duration is not evidence of a performance fix.

The native controller now has a host-owned signed-call preparation boundary.
It chooses the authorization context from the same physical material used to
build native work, captures that work under admission, and syncs NOD1 before
returning the context. It executes no policy and signs no receipt. Existing
records are revalidated/synchronized and returned exactly. The old submitted
context path keeps its strict clock check; it is not silently rebased.

If a journal callback fails while native admission retains the candidate, retry
uses the original reserved envelope's clock, not the newer observation. The
signed call and invocation work still must match exactly. A native positive
fixture injects that first-write failure, advances the clock, recovers the old
context, rejects a substituted signature, and then proves real policy execution,
issuance and reopen without extra signing. The focused check passes in **30.52s**
(`r16-operation-host-preparation-write-retry.log`).
The complete native operation regression passes: **nine passed**, zero failures,
in **123.87s** (`r16-operation-host-preparation-native-final.log`).
CLI regression: **237 passed**, zero failures, **six ignored**, in **51.52s**
(`r16-operation-host-preparation-cli.log`). Formatting and whitespace checks pass.
These tests cover the native preparation boundary, not yet its HTTP/client use.

Remaining handoff: expose this durable native preparation before final AOQ1
retention, and have the fresh client obtain the host context rather than select
it from its wall clock. Do not overwrite the old failed AOQ1/timestamps to make
the campaign pass. HTTP/client integration, a fresh native campaign, non-Public
mutation, expiry/abort handling and the other C2/C3 gates remain open.

### Retained HTTP/client host-clock handoff (C2)

The native preparation boundary is now connected through the existing four-entry
lifecycle queue and `POST /__agents/prepare-authorization`. Signed API AOC5 is
checked before admission; HTTP transport-node claims are rejected. The response
is exact call-bound AOQ1 using the durably captured host observation as issuance
slot. Queue acceptance alone remains non-durable; preparation does not approve,
issue or release anything. The 120-second wait and strict native clock check are
unchanged.

Managed fresh invocation now retains AOC5 in an exclusively leased immutable
`authorization-preparation/` pair (CSF1 roles 29/30) before HTTP. The returned AOQ1
must match the entire signed call, use the captured slot as issuance time, and
not precede retained actor preparation. It is synchronized before authorization
delivery. Retrying saved AOC5 skips discovery/signing; saved AOQ1 skips preparation
entirely. Orphan, invalid or replacing stages fail closed and remain intact.
The prior failed live AOQ1 and its credential reservation were not modified.

CLI regression: **239 passed**, zero failures, **six ignored**, in **75.85s**
(`r16-host-clock-client-final.log`). New loopback tests cover a lost response,
wrong-call response, earlier-than-actor observation, exact successful retry,
exclusive lease, reopen without HTTP, invalid signature and orphan/staged data.
HTTP framing tests: **four passed** in **0.26s**
(`r16-operation-preparation-http.log`). Mixed authorization/preparation queue
test: **one passed** in **0.02s** (`r16-host-clock-queue.log`), including capacity,
invalid signatures, dropped receivers and shutdown rejection.
Native operation recovery regression: **nine passed**, zero failures, in
**146.22s** (`r16-host-clock-native-final.log`). Normal vosx build passes in
**38.05s** (`r16-host-clock-build.log`). Formatting and whitespace checks pass.
All new logs use the shared disk-backed target's `task-tmp`; no `/tmp` scratch
or live daemon was started for this checkpoint. Guest artifacts/pins are unchanged.

This remains part of **C2**, not another review batch. Next is a corrected fresh
native campaign using isolated new state while preserving the old failed call;
do not rebase that old AOQ1 or clear its pending reservation. A live pass,
non-Public/mutating workflows, startup/Create/Install latency, Shared finality,
expiry/abort recovery and the remaining C2/C3 release gates are still open.
No performance improvement or master readiness is claimed.

### Fresh clock-handoff campaign at 224a0ba6 (C2)

A completely new Space/operator/node was created under shared disk-backed
`target/task-tmp/native-denial-head-reuse.IgQS0r`, with isolated XDG directories,
HTTP `127.0.0.1:18085` and SSH `127.0.0.1:2227`. The earlier XoaplU campaign,
failed AOQ1 and pending reservation were not copied, cleared or modified.
The campaign's `run.sh` retains exact Create retries and runs the existing
opt-in Install and managed invocation tests. It does not raise HTTP timeouts.

At **2026-09-14 17:23:21Z** the new daemon started; readiness was observed at
**17:24:16Z** (about **55 seconds**). Fresh Local Create completed at **17:27:23Z**
after one HTTP 504 and exact retry (about **187 seconds** from first attempt).
Install passed its native exact-resume test in **446.90 seconds**, after two
HTTP 504 responses, completing at **17:34:56Z**. These results reaffirm the
first-response latency blocker; successful recovery is not a latency waiver.

Managed receipt-bearing Catalog query then **failed after 224.59 seconds** at
`/__agents/authorize` with HTTP 503. Unlike the earlier client-clock failure,
both canonical AOC5 and returned host-prepared AOQ1 were retained, along with
the final authorization request and one native operation dispatch record.
No AOR1/application or native operation completion/retirement/denial was retained.
The invocation nonce is
`e0067faa1c43fce9a8b70044fac6b50bbe4bdc75e65560cbd3655a37491d0a04`;
the native authorization dispatch filename is
`c7f07b3db1061d2ee2efce04ac449410fa51860712727dc1ca853395d88339db`.
Preserve this request and reservation for exact recovery.

Logs show inventory reconciliation beginning at **17:38:31.979Z**, after native
preparation, then authorization reporting `Unavailable` at **17:38:41.406Z**.
Shutdown reports `ProjectionTransport` and `Agent host shutdown failed` rather
than clean retirement. The campaign process exited **101**, the daemon exited,
and `.endpoint` is absent. This is a terminal failed campaign, not a running
process or a clean-shutdown pass. Evidence is in `daemon.log`, `create-*.json`,
`create-*.log`, `install.log` and `invocation.log` in the new disposable root.

Source inspection identifies the next concrete interleaving to reproduce:
`drive_clean_agent_owner` runs `drive_if_due` immediately after replying to
preparation; reconciliation asks for an Authority projection while the native
operation still holds management admission. Projection reservation errors are
mapped to `ProjectionTransport`, and a reconciliation failure shuts down the
owner before the queued authorization can run. Native preparation tests did not
exercise this production scheduler interleaving. Add that regression and fix
admission-aware reconciliation without allowing stale authorization, bypassing
physical exclusion, or clearing retained operation state. Then retry the exact
fresh campaign state, accounting for restart/expiry rather than rebasing it.

The daemon also spends tens of seconds per inventory query, with one changed-head
reconciliation taking **139.379 seconds**. Root-cause performance work remains
open; no speed improvement, non-Public mutation, Shared finality or release
readiness is claimed by this campaign. This evidence remains within **C2**.

### Admission-aware periodic reconciliation (C2)

The production scheduler now queries native management admission before starting
an overdue periodic inventory refresh. Retained pending/retirement state and the
active coordinator exclusion are checked; absent attachment or lock failure is
an error, not permission to refresh. Held admission returns "no periodic work"
without moving the overdue deadline. After durable release, the next drive can
refresh immediately. This is scheduling only: it does not authorize work,
release admission, manufacture fresh inventory or suppress forced reconciliation.

Scheduler regressions model the multi-request preparation gap, repeated overdue
polls, admission-query failure and subsequent release. They verify no projection
query or deadline change while held. The native operation fixture now checks
that admission is held even after the first preparation journal-write failure,
remains held on retry, rejects an intervening projection reservation with
`Conflict`, and becomes free after exact durable retirement. These tests exercise
the exclusion behind the live failure without weakening it.

Verification (logs in shared disk-backed `target/task-tmp`):

- `r16-admission-scheduler.log`: **four passed**, zero failures, **0.51s**.
- `r16-admission-owner.log`: all **eight production-owner tests passed**, **0.20s**.
- `r16-admission-native.log`: **nine native operation tests passed**, **163.58s**.
- `r16-admission-cli.log`: **239 passed**, zero failures, **six ignored**, **81.23s**.
- `r16-admission-build.log`: normal vosx build passed, **49.70s**.

Formatting and whitespace checks pass. No live daemon was started for this
checkpoint; the IgQS0r and XoaplU evidence remains unchanged. Guest artifacts and
timeouts are unchanged. This remains within C2, not a new review batch.

Next required recovery check: constructor-time reconciliation is forced before
normal readiness, unlike the periodic drive. Source inspection shows prepared-only
operation admission can still conflict with that initial projection before a
client gets to resume. Do not simply skip verified startup inventory, advertise
ordinary readiness, rebase the saved AOQ1, or clear admission. Reproduce and handle
that recovery boundary, then run the exact saved live retry. The periodic fix is
not proof of restart recovery or end-to-end invocation. Latency, expiry/abort,
non-Public mutation, ordinary Shared finality and C3 release gates remain open.

### Prepared-only physical reopen versus production startup (C2)

The preserved IgQS0r Space was restarted using the normal **0754b9ad** binary,
without editing the request, reservation or native journal. `recovery-run.sh`
started at **2026-09-14 17:49:56Z**. Initial inventory reconciliation began at
**17:53:53.533Z**, then failed with `ProjectionTransport`; the log's final write
was at **17:54:03Z**. No readiness was reported, the script exited **1**, the daemon
exited, and `.endpoint` is absent. The exact invocation test was never reached.
Evidence is `recovery-daemon.log` and `recovery-run.sh` in the same disk-backed
`target/task-tmp/native-denial-head-reuse.IgQS0r` directory; earlier logs remain.

A native regression now reopens the owner immediately after durable preparation,
before any operation coordinator or issuer image exists. It reloads admission
from the exact journal, forbids fresh bootstrap, asserts the same ordered index,
held admission, original context and zero early signatures, then completes policy,
issuance and the existing later recovery/retirement checks. All **nine native
operation tests pass**, zero failures, in **134.57 seconds**
(`r16-prepared-recovery-native.log`). This isolates the live failure to production
startup coordination rather than an inability to restore the prepared journal.

The enlarged multi-reopen debug fixture initially overflowed the default test
stack, including after restore setup was split into a non-inlined helper. Its
three callers now use a bounded **8 MiB test-only thread stack**. Production
thread limits are unchanged. The two initial failures remain in
`r16-prepared-only-reopen.log` and `r16-prepared-only-reopen-final.log`; only the
subsequent full native run is a pass. Formatting and whitespace checks pass.
No production code or guest artifacts changed in this checkpoint.

Required next step: permit exact-request recovery before normal readiness, while
retaining admission and requiring verified inventory before ordinary routes are
published. `space up` currently constructs/reconciles the production owner before
registering HTTP ingress, so a client cannot resolve this prepared state. Do not
derive a fresh issuance input from journal-only state: the coordinator retains
native authorization before committing its record, and that intermediate NOD1
does not preserve a direct AOQ1 caller's separately chosen issuance time. Recovery
must preserve the actual request rather than guess or silently rebase it.
Periodic deferral remains verified; live invocation, startup recovery, expiry/
abort and all previously listed production/release gates remain open.

### Recovery-only startup and live retained invocation pass (C2)

Startup now defers initial inventory only while the native lifecycle reports held
management admission. It keeps normal supervisor/Authority ingress unpublished.
The recovery endpoint returns HTTP 503 for `/__status` and ordinary routes; only
the exact authorization/preparation paths are available. Their signed requests
must match an existing native journal call (and context for authorization).
Missing or altered calls cannot start new work. Normal policy/issuer validation
still runs, including exact coordinator issuance inputs on retry.

After native authorization retirement releases admission, the overdue inventory
refresh runs. Only successful authenticated reconciliation publishes ingress,
clears the recovery flag and reports verified readiness. Create/Install also
require readiness at the production-owner boundary. Lock/validation errors are
not treated as free admission. No timestamp inference, journal rewrite, timeout
increase or artifact change was introduced.

Verification:

- `r16-recovery-only-owner-final.log`: **eight passed**, **0.17s**.
- `r16-recovery-only-http.log`: **four passed**, **0.27s**, including recovery
  route restrictions, 503 status, exact path matching and return to normal status.
- `r16-recovery-only-native.log`: **nine passed**, **172.32s**, including rejection
  of missing calls, changed contexts and substituted signatures.
- `r16-recovery-only-cli.log`: **239 passed**, zero failures, **six ignored**, **80.18s**.
- `r16-recovery-only-build.log`: normal vosx build passed (about **68 seconds**).

The preserved IgQS0r campaign then passed with this implementation. Its new
`recovery-only-run.sh` began at **2026-09-14 18:09:25Z**; recovery ingress was
observed at **18:13:02Z**. Real HTTP probes confirmed 503 for readiness and actor
invocation. `authorize-local-invocation --resume` returned a verified retained
**issued** decision at **18:14:51Z**, with `applied: false` and its credential still
pending. There was no HTTP timeout during this exact authorization recovery.
Initial inventory reconciliation took **196.952 seconds**; verified readiness
was observed at **18:18:08Z**, and `/__status` then returned 200.

The existing live managed test subsequently passed: receipt-bearing Public Catalog
query, verified empty page, positive retirement, repeated real HTTP acknowledgement,
and cached managed resume. Its managed application attempt took **2.98 seconds**;
the full test passed in **5.14 seconds** (test build **13.13s**). The same daemon
shut down cleanly at **18:18:30Z**, script exit **0**, and `.endpoint` is absent.
Logs and JSON are `recovery-only-{daemon,authorization,invocation}.log`,
`recovery-only-authorization.json`, and the HTTP probe bodies in
`target/task-tmp/native-denial-head-reuse.IgQS0r`. The original nonce, signed call,
prepared frame and reservation were reused, not replaced. Earlier failed logs
and the separate XoaplU campaign remain intact.

This closes the demonstrated recovery-only startup/authorization interleaving,
not every recovery or release gate. Fresh first-attempt/successor invocation,
non-Public/mutating workflows, expiry/abort, ordinary Shared finality and C3 remain
open. The multi-minute startup/reconciliation and Create/Install results remain
production-blocking. All changes belong to the existing **C2** review batch.

### Fresh successor invocation after completed recovery (C2)

The opt-in `real_daemon_fresh_successor_invocation_and_exact_retry` campaign uses
a separate immutable `agent-client/managed-invocation-successor` intent. Before
creating it, the test requires the prior credential reservation to be Completed.
It verifies a distinct invocation ID, exactly the predecessor's operation sequence
plus one, and unchanged predecessor AOQ1 bytes. It then performs the same actual
receipt-bearing query, positive retirement, two real acknowledgement retries and
cached managed resume checks. It never clears or replaces pending work.

The existing IgQS0r space restarted normally with **cba908b2** production code:
start **2026-09-14 18:23:25Z**, ready **18:25:18Z** (about **113 seconds**), without
recovery-only mode. Fresh successor
`1d61ca50555b8286eca69513e0aa09570ea6b198392b94bd93224012af982246` passed on its
first managed attempt in **176.52 seconds**, without an HTTP timeout or caller
retry. The full native test passed in **178.76 seconds** (test build **0.24s**).
The daemon shut down cleanly at **18:30:13Z**, campaign exit **0**, and `.endpoint`
is absent. Shutdown waited for an in-flight inventory reconciliation, whose total
time was **120.456 seconds**. This remains a responsiveness/latency concern.

Evidence remains in `successor-run.sh`, `successor-daemon.log`, and
`successor-invocation.log` under shared disk-backed
`target/task-tmp/native-denial-head-reuse.IgQS0r`. The predecessor and older failed
campaigns remain intact. Ordinary CLI regression: **239 passed**, zero failures,
**seven ignored**, in **63.70s** (`r16-successor-cli-final.log`); formatting and
whitespace checks pass. Only the opt-in test/fixture and review record changed.

Next mutation coverage must use a legitimate Local mutable actor and protected
permission setup. The existing Counter example supplies Local mutable state, but
the Public Catalog query is not a mutation proof. Catalog's `mutate` method is a
signed Shared/Merge publication and must not be repurposed as evidence for Local
protected mutation. Non-Public policy, mutation/restart, expiry/abort, ordinary
Shared finality, performance and C3 release gates remain open. This stays in C2.

### Counter mutation fixture and installation checkpoint (C2)

The existing Local Counter example now has two opt-in managed invocation tests:
`real_daemon_counter_mutation_and_exact_retry` increments by seven and verifies
two actual duplicate HTTP deliveries return the identical retained response;
`real_daemon_counter_value_after_restart` reads seven after an externally
performed daemon restart. Both verify the admitted Counter program/deployment,
receipt-bearing application and positive retirement. They use separate retained
intents and do not clear pending credentials. These are Public policy tests,
not a substitute for the protected Local mutation gate. They have compiled but
have **not yet passed live**; installation must finish before running them.

The ordinary CLI suite passed: **239 passed**, zero failures, **nine ignored**,
**62.47 seconds**, in `target/task-tmp/r16-counter-cli.log`. Formatting and
whitespace checks also passed. The Counter package built with the pinned guest
toolchain; a second build produced byte-identical PVM and VOS files. This is a
same-worktree repeat, not the independent clean rebuild required by C3.
`Counter.vos` is **45,585 bytes**, SHA-256
`2a18452da6e8a33866f16896b5d587f0a86ecc8451d7ea219e44e6ff72687571`;
program `3605c485c5a39637265d4c6666fe79a3037ad0def7e1531f1f417f5a461c167b`,
deployment `d07f765553293c2c5f6e2e4007fab0028a7f26361ce026944671e0c1c3897023`.
Build evidence: `r16-counter-build.log` and `r16-counter-build-repeat.log`.

The existing IgQS0r disposable space began its Counter install campaign at
**2026-09-14 18:39:27Z**, reaching readiness at **18:44:04Z** (about **277s**).
Initial inventory reconciliation took **143.962s**. Later refreshes reused
inventory pages at the authenticated unchanged head but still took **53.945s**
and **32.387s**. Install has returned repeated HTTP 504 responses, retaining the
exact request for bounded retry. This is a failed first-response latency gate,
not evidence that the installation was rejected or that replay is safe to skip.
Evidence is `counter-install-run.sh`, `counter-install-daemon.log` and
`counter-install-{1,2,3,4}.{json,log}` under disk-backed
`target/task-tmp/native-denial-head-reuse.IgQS0r`.

All four attempts returned 504; the last began at **18:51:47Z**. A later full
inventory reconciliation completed in **188.052s**, immediately followed by
another credential refresh. The script requested graceful shutdown after the
fourth failed wait. No Counter mutation/read test was started and no client
completion is claimed.

The campaign script exited **1** after graceful shutdown; the final inventory
refresh finished at **18:54:40Z** in **56.027s**. The daemon process is absent
and `.endpoint` was removed. Retained client/native stores and all failed
attempt logs remain untouched for exact recovery.

A ten-second CPU sample of the same daemon, during the later inventory queries,
contained **502 core-cycle samples**, with **84.12%** in
`blake2b_simd::avx2::compress1_loop` on `vos-system-agen`. The two atom-cycle
samples were also in that function. Caller stacks were incomplete, so this
identifies a hotspot, not the high-level root cause or whole-campaign cost.
Evidence: disk-backed `target/task-tmp/r16-counter-install.perf.{data,txt}`.
Do not bypass hashing, skip route verification or increase HTTP waits based on
this sample.

Next work remains within C2: resolve the exact retained install outcome, then
run mutation/duplicate/restart verification. Protected permission setup should
reuse existing Authority administration calls and authorization machinery;
Counter's Public mutation does not close it. No new review batch, timeout
increase, production artifact repin or master integration is included here.

### Counter recovery and post-retirement duplicate-execution fix (C2)

Exact Counter install resume passed on the preserved IgQS0r space using the
unchanged normal binary: start **2026-09-14 18:56:40Z**, ready **18:57:57Z**,
verified install completion **18:58:11Z**, clean shutdown **18:58:12Z**, exit **0**.
Evidence: `counter-resume-{run.sh,daemon.log}`, `counter-resume.{json,log}` in the
same disk-backed campaign directory. No retained request or reservation was
replaced. Startup/inventory CPU samples (`r16-counter-resume*.perf.data`) again
showed both PVM interpretation and BLAKE2 hashing, but even deeper unwinding did
not produce reliable high-level callers; no latency fix is claimed.

The subsequent mutation campaign began at **18:58:59Z**, ready **19:01:11Z**.
Fresh invocation
`9dee2d6be9bcafe8b870cde9b66cebfcfa2a2b7012f256114fe56746b7e0abec`
completed its managed application/retirement in **192.06s**, returning seven.
The first real HTTP replay after retirement returned fourteen rather than the
retained response. The live test correctly failed in **192.52s**, and the
script did not start its read-after-restart phase. The daemon subsequently
exited and removed `.endpoint`; script exit **101**. Evidence is
`counter-mutation-{run.sh,daemon.log,test.log}`. This is a production-blocking
correctness failure, not just slow delivery. Preserve this now-double-mutated
actor as failure evidence; a passing exactly-once campaign needs fresh state.

Cause found in `StandardAgentRuntime::recover_clean_execution`: acknowledgement
removes the delivered reply but retains a durable retirement fact. Recovery
looked only for the reply, classified its absence as unseen work, and allowed
the same live receipt to execute again. The source fix checks the exact durable
acknowledgement before unseen-work admission. Late Invoke now returns the
existing non-mutating `DivergentInvocation` rejection for the consumed key;
exact Acknowledge retries remain positive. This changes no wire encoding or
stored-state layout, and does not resurrect a deleted reply or discard facts.

The live fixture's old demand for byte-identical Invoke replies *after* managed
retirement was also incorrect: after explicit result deletion, the host must
reject late Invoke. It now requires that rejection while retaining positive ACK
retry checks and a separate fresh Query after restart. Existing pre-retirement
exact-result retry coverage remains in the runtime test.

Regression coverage extends the full runtime Invoke/Acknowledge/reopen test and
the acknowledgement-capacity test: reject retired work with still-live receipts,
preserve all retirement facts across restore, keep unacknowledged replies
retryable, and leave state byte-identical on rejection. The initial pre-fix
regression (`r16-retired-reinvoke-red.log`) failed because an expired late Invoke
reached fresh authorization/expiry handling instead of the consumed-key check;
the stronger still-live assertions accompany the fix. Native test success is
not a bundled-PVM verification. Rebuild/repin the standard runtime and dependent
system packages, then use fresh disposable state for mutation/restart coverage.
This remains C2, with production artifact verification in the existing C3 gate.

Validation so far: acknowledgement/capacity tests **2 passed, 0.61s**
(`r16-retired-reinvoke-green.log`); full Invoke/Acknowledge/reopen regression
**1 passed, 0.05s** (`r16-retired-reinvoke-done.log`); CLI **239 passed**, zero
failures, **9 ignored**, **49.15s** (`r16-retired-reinvoke-cli.log`). Formatting
and whitespace checks pass. The native operation authorization/retirement and
physical reopen suite also passed: **9 passed, 120.50s**
(`r16-retired-reinvoke-native.log`). None of these results closes the fresh bundled-PVM
mutation/restart gate or the separate protected-permission gate.

### Reproducible runtime repin for retired-invocation rejection (C2/C3)

The standard runtime is now pinned to source commit
`15dd53eca7f698f931fc3ffd41c7c5dae2f55af4`. Two independent clean exports with
separate target directories built under `nightly-2026-03-20` in **22.21s** and
**22.17s**. The pinned builder from
`42f3f3bf2362e5189f094a1e39c7288e7a26eea7` transpiled and physically ABI-probed
both ELF files. Both ELF and PVM comparisons were byte-identical.

- Runtime ProgramId: `2b10cf4d99eab68eab90325e872052880de65bfae7fbd5fe264be5732a726b53`.
- ELF BLAKE2b-256: `0d08c766a2b1809d8c207843fd90ad7d4bc148cf1885a764e38e6600344124d6`.
- PVM BLAKE2b-256: `5d48a4a822c788d662d52d8ebd7f596797f511dd381918508c987ae78ee68804`.
- PVM size: **954,004 bytes** (previously 953,887).

Evidence is under shared disk-backed `target/task-tmp/runtime-repin.4Ximp6`
and `runtime-repeat.pWRj7W`: source exports, isolated build outputs, build logs,
and runtime-identity logs. `support/production-artifacts.toml`, the native
ProgramId constant, build-time digest check, and committed PVM agree. System
actor template bytes and their independent source/builder pins are unchanged;
the rebuilt release bundle validates them alongside the new runtime.

The new `bundled_runtime_rejects_retired_invocation_without_reexecution` test
executes the committed PVM in a new VM for every call. It verifies retained
delivery, positive acknowledgement, byte-identical state after rejected late
Invoke with both a live and expired receipt, and positive exact ACK retry.
It failed against the old bundled PVM (late Invoke reached `InvalidInput`
instead of consumed-key rejection; **0.35s**) and passes against the repin
(**0.54s**). Logs: `r16-retired-reinvoke-pvm-{red,green}.log`. The fixture uses
canonical host-constructed terminal state; it is not a substitute for a fresh
HTTP mutation and disk restart campaign.

CLI regression passed **239 tests**, zero failures, **9 ignored**, **51.69s**
(`r16-runtime-repin-cli.log`). The normal binary rebuilt and the clean-break
check passed (`r16-runtime-repin-clean-break-final.log`). That script now honors
`CARGO_TARGET_DIR` and requests a locked build, avoiding a separate target tree
or checking a stale default-path binary. Normal `release bundle` and `release
verify` passed for `runtime-repin.4Ximp6/release`. This is an artifact checkpoint,
not completion of C3's full feature/release matrix or production readiness.
With the repinned bytes, the native operation/recovery suite also passed:
**9 passed, 120.97s**, `r16-runtime-repin-native.log`. Formatting and whitespace
checks passed. No old disposable space was reopened with the new runtime, and
no failed state was reset to manufacture a passing mutation result.

### Fresh Counter campaign and genesis-identity collision (C2)

Fresh isolated XDG/config/data/cache roots are
`target/task-tmp/native-denial-head-reuse.N5274B`, with a newly generated operator
identity and node peer `12D3KooWSdVoYGXS3dgeAhrMhZ7vswcNk9EfF68Y5cZeHBDptM1J`.
The normal binary contains the **51dae8fb** repin. `space new` prepared the
bundles and enabled HTTP/SSH defaults; only the disposable loopback ports were
changed to **18086/2228**. No state from IgQS0r or XoaplU was copied. The only
reused input is the unchanged signed Counter package, exercising installation
of an independently published actor package.

The Counter fixture now reads the successful Create CLI JSON acknowledgement
via `VOSX_INVOKE_SMOKE_CONFIG`, rather than requiring an unrelated Local Catalog
installation/constructor. Catalog campaigns continue to use their original
constructor configuration. The fixture checks the Space/agent coordinates and
admitted Counter program/deployment before evaluating its result.

Timeline (**2026-09-14 UTC**, `run.sh` and phase-specific logs):

- Start **19:27:09**, ready **19:28:00** (about **51s**).
- Create started **19:28:00**, verified completion **19:30:56** (**176s**), after
  one HTTP 504 and exact retry; agent
  `46a48c769852a71dbbb8296285f32a4bfaaaf4b0eb52033dca7845b79616fc49`.
- Counter install started **19:30:56**, verified completion **19:37:55**
  (**419s**), after two HTTP 504 responses. A full post-install inventory pass
  took **130.879s**; subsequent exact retries still performed refreshes.
- Mutation `645561e2e23253ee993c413c5723e88884d99bb24b80b1d62feb6b85312bd637`
  passed: managed attempt **298.27s**, full test **300.14s**. It returned **7**,
  rejected both actual late HTTP Invoke replays, and retained positive exact
  acknowledgement retries. Completion was observed at **19:42:55**.
- Graceful shutdown completed **19:45:49**, waiting for an already-running
  inventory pass. Restart began immediately and was ready **19:47:13**.
- Fresh read `0784c40486bbb389b6cf9b6f9a3566742d62364a75dd194df234ab22e2fa2d79`
  returned **7** after restart. Managed application took **157.81s**, full test
  **159.70s**, passing at **19:49:53** with late Invoke rejection and positive
  exact acknowledgement retries. `mutation-test.log` and `read-test.log` each
  report one passing live test. This proves the isolated Public Counter
  mutation happened once across the tested duplicate requests and restart,
  not protected permission setup or ordinary Shared finality.
- Final graceful shutdown completed **19:51:40**, campaign exit **0**, endpoint
  removed. Its in-flight inventory pass took **110.562s**.

These timings remain production-blocking. No timeout was raised and no saved
request, reservation, or failed historical state was rewritten.

The new space unexpectedly has the same genesis hash and Space ID as IgQS0r:
genesis `2b14cd25c0705fa792db8feae161c31d5251a7c6daa159dcdc2cae52a1c1e524`,
Space `b9e1120cb41249347b9070ec9065e81c92b4593d2c384af3ca612b0b2b6fdf3d`.
The canonical operator key files differ (byte comparison only; no secret key
material was printed). A copied, stopped IgQS0r registry database was inspected
without opening or modifying its original. It contains:

- seq **0**: the above genesis CID, **empty message**;
- seq **1**: `set_root`, CID
  `c9852b4e56fd4027bdd6d1172a1b73b1818d91ee9552e02d9e7e78ce703c8110`;
- seq **2**: `set_space_id`;
- seq **3**: `add_node`.

Evidence: `target/task-tmp/inspect-genesis.rs`, its compiled diagnostic,
`igqs0r-genesis-diagnostic.redb` and `igqs0r-genesis-diagnostic.log`. Both `new.rs`
and `verify.rs` currently select seq zero, contrary to their claim that it is
the root-setting operation. Fix genesis selection/verification consistently,
including root binding, independent-space uniqueness and existing-data rejection
tests; do not merely change one scanner or relabel existing spaces. This is an
original bootstrap/isolation requirement, not a new feature. It remains open.
After N5274B stopped, a copied registry independently confirmed the same empty
seq-zero CID, but a different seq-one `set_root` CID:
`1ba51dcba34d14ef2ebc26baea8f17ac65f2b36d0da6943e6907cd5e2d1942f8`.
Evidence: `n5274b-genesis-diagnostic.{redb,log}` alongside the first diagnostic.
The originals remain intact. This directly distinguishes the two real root
anchors from the shared empty event mistakenly used as space genesis.
Final CLI regression: **239 passed**, zero failures, **9 ignored**, **52.88s**
(`r16-fresh-counter-cli.log`); formatting and whitespace checks pass. Only the
opt-in Counter fixture and review/checklist record changed in this checkpoint.
The genesis derivation fix is the next implementation step; it is not included
in these passing results.

### Root-bound, independently unique space genesis (C2)

Creation and verification now share `registry_genesis_cid`: it checks the
stored CID against the complete node bytes, uses the canonical registry replay
decoder, and accepts only the versioned/schema-compatible `set_root` request.
An empty initialization event is never an identity anchor. Creation requires
exactly one root candidate; verification still locates the candidate matching
the advertised identity rather than trusting CID sort order. The second
creation boot also uses the existing genesis-bound node validator before
anchoring the Space ID and enrolling the initial node.

Initial CRDT registration now derives its bootstrap identity from the new
per-space node's full PeerId under `vos/space-genesis-origin/v1`. It no longer
uses a fixed all-zero replication ID. The operator's persistent signing key
can therefore create separate spaces without depending on a collision-prone
16-bit node prefix. Normal replication still switches to the derived Space ID;
neither existing IDs nor stored DAG records are rewritten.

The persisted regression covers initialization exclusion, actual root binding,
different roots, corrupted/malformed CIDs and node framing, wrong schemas,
old empty-event identity rejection, ambiguous creation roots, and verifier
selection in the presence of multiple candidates. An initial test-only
`Vec<i32>` literal compile error was corrected to `Vec<u8>` before validation.
CLI regression: **240 passed**, zero failures, **9 ignored**, **51.06s**
(`r16-genesis-root-cli.log`); normal binary build passed
(`r16-genesis-root-build.log`), as did formatting and whitespace checks.

Real CLI evidence is `target/task-tmp/genesis-root-smoke.V8PTde`. Two successive
`space new` commands used the **same isolated operator/config directory**, and
both completed their cold registry replay with the root-bound validator:

- `genesis-one`: Space
  `a4d608a8d4b6063c58bb198034535d47cc329de28b4536c4984a1a65663fac6f`, root
  `c4d736580d6a9d1a2e28ac35f35dd084b6d0f55f56f56a772cd8932b2fc76f2e`.
- `genesis-two`: Space
  `b752b40b5aa153c8e55e77eb545ae451f966fce472bc16ebbf46d18d3c8fa13d`, root
  `34f7368075edbdf7e49315ca6042f27ed166f876e3894b174a49a56662ed1b03`.

The first space then started normally at **2026-09-14 20:01:47Z**, explicitly
verified the above signing-root CID, reached HTTP/SSH readiness at **20:02:39Z**,
returned HTTP 200 from `/__status`, and shut down cleanly in the same second
(script exit **0**). Logs/data: `one.{json,log}`, `two.{json,log}`, `up-run.sh`,
`up.log`, and `status.json`. No old collision dataset was booted or modified.
This closes the demonstrated genesis collision; it does not close latency,
protected permission setup, Shared finality, terminal/capacity recovery or the
full final-source release matrix. Guest artifacts did not change.

### Bounded exact Install publication reuse (C2)

The owner now retains one process-local completed Install publication, matching
the existing bounded Create delivery optimization. Every attempt still calls
the native lifecycle to authenticate and reopen physical application evidence.
Only the same acknowledgement commitment, accepted authority head, existing
Local attachment and exact active route identity (including incarnation) can
reuse the earlier verified publication. The expected route key, runtime,
actor deployment, program and Local profile are checked separately.

The marker is taken before processing Install, so errors cannot retain an old
success. Create and every reconciliation attempt invalidate it; restart never
restores it. First Install, changed identities, missing routes and changed heads
still require full reconciliation before ingress success. The optimization
does not cache authorization or bypass physical lifecycle recovery.

This addresses the repeated inventory passes observed on queued exact Install
retries in N5274B. It does **not** fix or waive the 130.879-second first
post-install inventory, establish a measured end-to-end speedup, or close the
production latency gate. No timeout, guest artifact, wire format or public API
changed. Review remains within C2, alongside C1 recovery and C3 release; this
checkpoint is not a fourth review batch.

Validation: all **9 production-owner tests passed** (0.14s), including the
new exact-ack/head/attachment/incarnation matrix and clearing the Install
marker on successful and failed reconciliation. All **9 native operation
regressions passed** (130.44s). The normal CLI build, formatting and whitespace
checks passed. Logs in the shared disk-backed `target/task-tmp` directory:
`r16-install-publication-owner-final.log`, `r16-install-publication-native.log`
and `r16-install-publication-build.log`. No live campaign was run for this
checkpoint; first-response latency and actual retry speedup remain unmeasured
on this source. Next latency work must measure the authenticated inventory
dispatch path; repeated-publication reuse alone is insufficient for release.

### Audited capacity without full status construction (C2)

The first live phase measurement on `genesis-root-smoke.V8PTde` used the
normal CLI built from `2161a174` plus phase-only debug instrumentation.
`projection-phases-run.sh` restarted the corrected-genesis `genesis-one` space
at **2026-09-14 20:15:39Z**, reached readiness at **20:17:00Z**, returned HTTP
200, and shut down cleanly in that same second. `projection-phases.log` and
`projection-phases-status.json` retain the evidence. No old collision fixture
was booted. Four inventory queries took **47.948s** in total; reconciliation
including publication took **52.263s**. Individual dispatches were roughly
11–13s. Phase elapsed values are cumulative within either the preparation or
execution function, not independent durations: most time was in Invoke and
ACK, with 2–3s more in preparation/reservation and roughly 70ms per bootstrap
record write. Pending-recovery checks were effectively zero.

Code inspection identified redundant work in capacity-only admission checks:
`SharedAgentHost::show` executes the runtime actor-directory ABI, and driver
capacity previously built the complete journal projection after an already
complete recovery audit. The new internal capacity path returns applied index,
remaining slots and reservation presence directly from that **same full
recovery audit and read transaction**, under the existing ledger write guard.
It still validates physical log rows, canonical commands, committee history,
snapshot boundary, application metadata and any pending reservation. It is not
a cache or a trusted-metadata shortcut. Full cross-store journal projection
remains in place for its existing consumers.

Projection and management admission now consume those capacity facts while
holding the host lock. Raft barrier comparisons, suffix-budget requirements,
the extra reopen slot and exact durable-anchor validation are unchanged.
Two identical status calls within persisted management preparation become one
capacity read; no intervening operation mutates the host. Generic user-facing
status and Raft status replies are unchanged. Phase timings remain debug-only
and contain no request/signature/package bodies. This is a host-only change:
no guest repin, wire change, timeout increase or new review batch.

Validation: **14 V2 ledger tests passed** (5.90s), including capacity equality
with the full projection after reservation/reopen/completion and certified
snapshot compaction, plus missing physical log and corrupt audit rejection.
All **9 native operation tests passed** (114.99s). The normal CLI build,
formatting and whitespace checks passed. Logs: `r16-capacity-audit-tests.log`,
`r16-capacity-audit-native.log`, `r16-capacity-audit-build.log` in the shared
disk-backed `target/task-tmp` directory.

The subsequent live run (`projection-phases-run.sh capacity-audit`) started at
**20:24:39Z**, reached readiness at **20:26:31Z**, returned HTTP 200 and shut
down cleanly at **20:26:31Z**, exit **0**. Evidence: `capacity-audit.log` and
`capacity-audit-status.json` alongside the baseline. Query times were
**12.873 / 13.484 / 13.653 / 14.272s**, totaling **54.284s**; complete inventory
reconciliation took **58.870s**. The first reservation phase dropped from
1.429s to 1.258s and the fourth from 2.093s to 1.613s, but this is sequential
testing with additional retained history, **not a controlled speedup claim**.
Overall latency is still unacceptable; this checkpoint does not close that
gate. The larger restart and dispatch times keep history-dependent physical
validation and Invoke/ACK execution as the next profiling targets. Do not
replace the full recovery audit with unauthenticated cached metadata.

### Reuse canonical command decoding within one physical read (C2)

V2 physical-row verification previously decoded and canonically checked the
command, discarded it, and returned only raw entry-kind bytes. Recovery then
decoded the same command again to replay committee disposition. Full journal
projection and committee-history projection also decoded it again.

The private `ValidatedPhysicalEntry` now carries that canonical command forward
with its entry kind. Consumers retain their route, disposition, authority and
entry-ID checks. Every storage observation still verifies the physical term,
raw-payload commitment and canonical outer framing, and every nonempty command
still undergoes bounded canonical decoding. Snapshot committee replay uses the
same shape validator after validating its evidence item. This is **not** a
cross-read cache: changed storage bytes cannot reuse earlier validation.

The new regression checks exact command preservation, wrong physical term,
wrong record kind, changed bytes after a successful read, and malformed command
bytes even when their new physical hash matches. All **31 Shared-Raft tests
passed** (6.17s), including V2 recovery, reservations, committee rotation and
snapshot cases (`r16-physical-decode-all-tests.log`). An initial unused-pattern
warning introduced during refactoring was removed before that final suite.
This host-only optimization remains in C2; no guest artifact or wire change.
It does not by itself establish acceptable startup or Create/Install latency.

All **9 native operation regressions passed** (115.90s;
`r16-physical-decode-native.log`), and the normal CLI build passed
(`r16-physical-decode-build.log`), along with formatting and whitespace checks.
No live latency campaign was run for this checkpoint. The native test duration
is not materially better than the preceding run and is not a speedup claim.
Next performance validation should compare equivalent retained histories, not
infer improvement from consecutive boots that each append more journal work.

### Fixed-history decoding probe and recovery-audit attribution (C2)

`fixed_history_physical_decode_probe` is an opt-in diagnostic, not a timing
assertion or release gate. It consumes `VOS_AGENT_RAFT_BENCH_COPIED_DB`, which
must name a **copy** of a stopped space's Raft database: redb open can update
metadata. It reads one fixed set of retained physical rows and alternates the
current canonical-command reuse path with the former consumer's extra decode.
Both paths retain the same physical-byte and canonical-encoding checks. Output
contains counts and elapsed times, not command bodies or credentials.

Evidence is `target/task-tmp/fixed-history-probe.NVoTam`: `raft.redb`,
`probe.log`, `build.log` and `tests.log`. The source was the stopped corrected-
genesis `genesis-one` fixture; an external file-user check found no opener.
After the probe, source and copy still had identical SHA-256
`fd90548eaadb787e197c0f0cf45f541532b22ea1b0f0f93afbc5ea42aea97f58`.
The probe processed **52 rows / 49 commands / 20,894,428 bytes** without
appending history. Excluding the first warm-up round, median physical-row pass
time was **531,526 us** with duplicate decoding and **296,368 us** with reuse
(about **44% lower for this path only**). This does not measure full recovery,
PVM execution, I/O, or end-to-end startup/Create/Install latency. The modeled
duplicate path runs in the current binary, not a separate historical build.

The complete Shared-Raft suite passed **31 tests**, with this diagnostic
ignored by default (6.16s); the explicit probe passed separately (3.71s).
Normal CLI build passed. A debug-only recovery-audit timer now reports retained
row count and elapsed microseconds so live query cost can be attributed to
actual full audits rather than inferred from microbenchmark improvements.

Two additional native runs completed on the same disposable space, each with
normal HTTP readiness and clean shutdown:

- `recovery-audit-profile.log`: **20:39:01Z–20:41:07Z**. Queries took
  13.069 / 13.277 / 13.866 / 14.135s. Each performed five full recovery audits,
  totaling 1.540 / 1.687 / 1.882 / 1.959s respectively. Audits are therefore
  not the main remaining query cost.
- `execution-profile.log`: **20:42:17Z–20:44:56Z**, ready at **20:44:55Z**.
  Additional debug timings cover ordered retry lookup and physical runtime
  load/run (not output decoding). Before the first inventory query, 48 runtime
  calls consumed **79.193s** and 14 full audits consumed **5.898s**. Fresh
  query timings below are disjoint measured call intervals; the unaccounted
  remainder includes other host work and output processing.

| Query | Total | Full audits (5) | Retry lookups (3) | Runtime calls (10) |
| --- | ---: | ---: | ---: | ---: |
| Credential | 14.833s | 2.053s | 0.823s | 7.643s |
| Agents | 15.199s | 2.172s | 0.798s | 7.716s |
| Replicas | 15.601s | 2.272s | 0.852s | 7.778s |
| Actors | 15.950s | 2.374s | 0.887s | 7.815s |

The two largest identical Invoke executions per query take approximately 2.5s
each (preflight plus committed execution); ACK takes approximately 1.9s.
These calls carry roughly 780KB inputs. Short management inspection calls are
about 0.1s each. This directs the next latency work to the guest/runtime path,
not more audit-only micro-optimizations. Source inspection also finds repeated
availability validation in invocation decoding, outer wire validation and
runtime admission. Its contribution is not yet separately measured; any
deduplication must retain byte integrity, shape and authorization rejection,
and requires the normal guest rebuild/reproducibility gates if guest code
changes. Do not omit preflight or committed execution checks speculatively.

The runtime timer was added to the existing debug execution event; the retry
timer logs only index and elapsed time. No work bytes, signatures or secrets
are logged. `summarize.awk` in the probe directory reproduces the per-query
totals; the earlier audit-only log has no lookup/runtime timings. The final
normal binary build (`execution-build.log`), formatting and whitespace checks
passed. The final instrumentation was exercised by the second live run.
These are diagnostic results, **not production latency passes**. No guest
artifact changed, and every live/test process from this checkpoint is stopped.

### Single-pass availability validation during AWRK decoding (C2)

Runtime work decoding previously authenticated availability bytes while
parsing each blob, again in Invoke/Resume validation, again in RuntimeWork body
validation, and again in the generic canonical frame decoder. The decoder now
parses bounded availability first and authenticates it exactly once in its
complete Invoke/Resume value. RuntimeWork's body validator reuses that nested
validation while still checking context, state and authorization binding; its
frame decoder still enforces size, magic, ABI and exhaustion without a second
whole-value validation. Constructed values and encoders still use full
validation, and runtime authorization/admission checks are unchanged.

The framing helper remains private; other canonical wire types retain their
existing final validation. The two availability-parser callers both validate
their complete value before returning. RuntimeWork body decoding itself still
rejects invalid nested values, so direct body-decoder users do not gain an
unchecked path. No canonical format or ABI identifier changes.

All **164 SDK tests passed** (0.05s), including a new 768KB availability matrix
for Invoke, Resume and Acknowledge: corrupt preimages, wrong lengths, zero
hashes, duplicate entries, missing installation references, truncated frames
and trailing bytes are rejected. Both constructed/encoded values and hostile
raw body/frame decoding are covered (`r16-single-validation-sdk-final.log`).
Guest artifact validation and repinning are required before treating this
source optimization as present in the distributed runtime.

The SDK no-default-features check also passed. A new physical-PVM regression
constructs a retained terminal result for a synthetic 768KB installed program
and requires positive ACK. The baseline committed runtime consumed
**690,622,135 gas**, **2.077s**, for the fixed **793,734-byte** input
(`r16-single-validation-baseline-final.log`). An optional candidate PVM path
must produce byte-identical output with strictly lower deterministic gas.
This isolates decoder/ACK cost; it does not execute the synthetic actor or
replace live Counter validation. The initial attempt modeled the large bytes
as an application attachment and correctly hit its independent smaller input
limit; the fixture was corrected to model the installed program instead.

### Reproduced single-pass runtime candidate (C2/C3)

Two separate archive exports and guest targets built immutable source
`b4b82473af82c107d2cd7ece248011f6191d0058` with locked dependencies and
`nightly-2026-03-20`. The existing pinned `42f3f3bf` host builder converted and
physically ABI-probed each ELF. Both ELFs and both PVMs are byte-identical.
Evidence: `target/task-tmp/runtime-single-pass.pOKisH/build.sh`, the `first/`
and `second/` build/identity logs, and `comparison.log`.

- Runtime ProgramId:
  `f24a8ea3dc8ccc7e8615dec557477363095f23c09ca2089f1298fab345d3fb93`.
- ELF BLAKE2b-256:
  `6bc864a5bcade826f4c48f0718eee659656aae6acd40b62b8ed196f7054249f8`.
- PVM BLAKE2b-256:
  `47aafb374f25fbd89af87321a48782e7bdbe7e3001a4ec3cd2d9ead37152042e`.
- PVM size: **956,476 bytes**. ABI remains `vos-agent-runtime-abi-260912-r16`.

The same 793,734-byte ACK input returned **byte-identical successful output**
from old and candidate physical runtimes. Deterministic gas fell from
**690,622,135 to 515,787,220** (about **25.3%**); the paired wall times were
**1.832s / 1.383s**. This is an isolated ACK/decoder result, not an end-to-end
startup or Install latency pass. Existing authorization, terminal replay
protection and output commitments remain required. The provenance manifest,
standard runtime ProgramId, bundled blob and build digest now select this
candidate. Existing system actor templates remain pinned to their original
immutable source and are still wire-compatible; they were not rebuilt.

Final validation against the repinned artifact: **240 CLI tests passed**, zero
failures, **9 ignored**, **54.85s** (`cli-final.log`); **9 native operation
tests passed**, **123.21s** (`native.log`); all **3 bundled-runtime tests
passed**, **3.03s**, including late retired-Invoke rejection (`bundled.log`).
The first CLI attempt had 11 socket-permission failures under the sandbox
(229 otherwise passed); the complete rerun with local sockets enabled passed.
Normal build plus clean-break surface checks passed (`clean-break.log`), as did
normal `release bundle` and `release verify` (`release-bundle.log`,
`release-verify.log`) and formatting/whitespace checks. Logs are under the
candidate evidence directory above. No daemon or test process remains live.
No new live Create/Install or protected-actor campaign was run for this repin;
those workflow and latency gates, plus the rest of the original release
matrix, remain open. No root-branch or master integration was performed.

### Native bundled Authority administration boundary (C2)

`native_admin_bundled_authority_grants_and_revokes_with_bound_identity` passes
against the bundled Authority executable through the native system owner
(1 test, 13.59s; `target/task-tmp/native-admin-test.log`). It reads the enrolled
SSH credential through a node-attested projection, signs administration using
the separate admin sequence and generation CAS, grants and revokes a space
role, acknowledges each terminal result, and verifies projected role membership
and counters. An otherwise valid signed grant with anonymous invocation origin
is denied without granting the role or consuming the administration sequence.

This is a test of the existing trusted native boundary, not a new production
admin endpoint. The fixture supplies host-bound identity directly and uses the
existing native system runtime fixture; it does not prove end-to-end physical
runtime latency, crash-safe admin orchestration, deployment-scoped actor grants,
or protected Local mutation. Those gates remain open. No production code,
artifact pins, authentication rules, or timeouts changed in this checkpoint.

### Retained native admin dispatch and restart (C2)

`clean_admin_dispatch.rs` adds the distinct signed NAD1 record, immutable journal
contract, persistence-before-dispatch boundary, and exact native execution.
Startup admission can include pending admin records while holding their journal
lease alongside operation leases. It checks discovery identity, duplicate IDs,
bounded canonical records and signed envelope binding; physical reopen separately
authenticates each journal anchor. Admin work stays pending, never reclassified
as an operation approval, read-only projection, or retired result.

Both native admin tests pass (`target/task-tmp/native-admin-retained-test.log`).
The nine existing native operation regressions also pass (115.15s;
`target/task-tmp/native-admin-operation-regressions.log`), as do the ordinary
CLI build (`target/task-tmp/native-admin-vosx-build.log`), formatting and diff checks.
The new regression injects failure before publication, advances the clock,
injects failure after publication, and recovers the identical signed record.
It reopens the native owner before and after real bundled-Authority execution:
exact retry returns generation two with only one committed admin invocation.
Changed signatures, anchors and gas are rejected, as are truncated/trailing
records and missing/duplicate startup records. In-process recovery after a
missing publication uses the exact retained native reservation, not a new clock.

This remains internal, with a test-only disk store. No ingress is enabled and
no successful admin reply is acknowledged or admission released by this API.
Next implement authenticated durable terminal result/denial recovery and
retirement, then the hardened production store/controller and host-clock
preparation/client delivery. The protected Local mutation gate remains open.
No SDK wire ABI or bundled executable changed; no artifact repin is needed.

### Native admin terminal result and retirement (C2)

NAT1 certificates separately sign the observed result and completed retirement,
binding the complete NAD1 record and phase. The result is persisted before
positive ACK; terminal retirement is signed and persisted under native pending
admission exclusion after ACK. Ambiguous publication retains admission, and an
exact retry reuses the saved certificate. Startup excludes only records with a
verified retired certificate, not merely a saved result. No admin ingress is
enabled yet; these are internal owner APIs with test-only stores/signers.

Three native admin tests pass (final rerun 46.89s;
`target/task-tmp/native-admin-terminal-final.log`). The nine native operation
regressions also pass (112.63s; `native-admin-terminal-operations-final.log`),
as do the ordinary CLI build (`native-admin-terminal-vosx-final.log`), formatting
and diff checks; all logs are under `target/task-tmp`. Success and denial each
exercise failure before/after result publication, failure before/after terminal
publication, five owner reopens, unchanged committed invocation/ACK counts,
signature/phase rejection, release, and a completed valid successor. Startup
re-synchronizes a recovered terminal certificate before excluding admission. In
particular, a denied admin request does not consume the admin sequence.

The success test initially exposed a recovery rule that allowed only empty
denials to remain pending after ACK (`native-admin-terminal-reopen.log`, reopen
3). The journal now additionally accepts an independently replayed successful
admin result only when its signature and complete signed call match the exact
anchored envelope. Arbitrary nonempty replies remain rejected. The shared
pending-result ACK/release machinery has neutral naming; existing operation
denial proofs remain distinct from retained admin-result proofs.

Next: hardened production admin stores/controller, host-clock preparation and
client delivery, then protected Local mutation/retirement/restart. Broader
capacity/GC and release gates remain open. No SDK ABI, artifact pin, ingress
policy or timeout changed.

### Hardened admin stores and owning controller (C2)

`NativeAuthorityAdminController` owns the dispatch/result/retirement leases and
rereads exact durable records on every attempt. Its startup adapter merges the
complete admin discovery set into existing operation admission. Completed
requests bypass fresh reservation only through verified terminal evidence.
Native success and denial fixtures now complete their valid successors through
this controller and retry both predecessor and successor with no additional
signatures or journal entries (3 native tests, 51.50s;
`target/task-tmp/native-admin-controller-tests.log`).

The CLI now has dedicated CSF1 roles and namespaces for immutable admin dispatch,
observed result and retirement. Reads validate staged and canonical records
before reconciliation; terminal files must match their original signed dispatch,
including its full native envelope commitment. All three roles reject replacement
predecessors. Discovery includes first-publication stages, stays bounded, and
retains exclusive leases through controller errors. Missing source records,
wrong scope/key/phase, role-exchanged envelopes, symlinks and conflicting stages
fail closed. The new store tests use synthetic signed storage fixtures, not
native finality proof; native execution evidence is separately listed above.

Verification: CLI suite 243 passed / 9 ignored (60.48s;
`target/task-tmp/native-admin-store-cli-final.log`); final focused store rerun
3 passed (1.86s; `native-admin-store-final-tests.log`) after independently checking
each terminal namespace lease. Ordinary CLI build, formatting and diff checks
also pass (`native-admin-controller-vosx-build.log`; logs under `target/task-tmp`).

These types are not wired into daemon startup or ingress yet. Next connect
their lifetime/discovery to daemon recovery, then implement host-clock preparation
and client delivery before the protected Local mutation campaign. No SDK ABI,
bundled artifact or timeout changed; this remains C2, not a new review batch.

### Daemon admin recovery ownership and fresh startup (C2)

Daemon startup now opens `authority-admin-dispatch`, `authority-admin-results`
and `authority-admin-retirements`, combines their full discovery set with
operation recovery admission, and resumes only retained signed calls before
publishing ordinary routes. `LocalLifecycleController::with_admins` checks the
Authority and signer binding and owns the controller for its lifetime. Typed
native `administer` dispatch is available; no HTTP/SSH admin endpoint or client
preparation is enabled yet.

Native tests now reopen with a pending successor, recover it through the owning
controller, adopt the controller into the lifecycle owner, and verify exact
retired retry without further commits. All 3 pass (61.37s;
`target/task-tmp/native-admin-startup-native.log`). CLI tests pass 243 / 9 ignored
(73.36s; `native-admin-startup-cli.log`), as do the owned-signer regression
(`native-admin-startup-signer.log`), normal build, formatting and diff checks.
Logs are under shared `target/task-tmp`.

Live evidence: `target/task-tmp/admin-startup-smoke.nHw46n/run.sh` and
`timing.log`, using isolated operator/node/config/data, HTTP 18088 and SSH 2230
on loopback with mDNS autodial disabled. Fresh Space
`e82c2863a174c3ba25f6aa08bb1f3e2d6f936389028c66a644ae5e98158a685a`
uses the current f24a8ea3 runtime pin. First startup reached HTTP 200 after
61s, then shut down cleanly; restart reached HTTP 200 after 66s and shut down
cleanly. Each admin namespace was present and independently locked during
restart (`flock -n -E 75`); all three locks were released after final shutdown.
This live check has empty admin history; populated-history recovery is covered
by the separate native fixtures, not by an unimplemented live admin command.
Concurrent test/build activity means these timings are not a controlled
performance comparison. The production latency gate remains open.

Next: host-clock preparation plus authenticated admin delivery/client wiring,
then the deployment-scoped protected Local mutation/retirement/restart campaign.
No runtime artifact, SDK ABI, ingress permission check or timeout changed.

### Signed admin clock preparation (C2)

Native preparation now accepts a credential-signed zero-slot draft, validates
its Authority and local node binding, and signs NAP1 over the normalized intent,
host-observed slot and physical Authority incarnation. The client verifies this
response against its draft, then signs the returned call. Preparation is not
permission: current actor credential, admin sequence and generation CAS checks
remain authoritative. Delayed submission may use that authenticated earlier
slot, never a future slot or changed incarnation. There is no new timeout or
expiry policy.

New native admin dispatch records are NAD2 and require the exact preparation.
NAD1 is deliberately rejected, not migrated or silently repaired. Populated
NAD1 histories in earlier checkpoints were disposable test fixtures; the live
startup smoke had empty admin history. No runtime artifact or SDK ABI changed.
The lifecycle owner exposes prepare/submit; resume-only administration cannot
create unprepared work. Recovery uses retained bytes, not a fresh host clock.
No HTTP/SSH admin endpoint or managed-client workflow is enabled by this change.

Storage regressions pass 3/3 (`native-admin-preparation-stores.log`); the CLI
suite passes 243 with 9 ignored (66.37s; `native-admin-preparation-cli.log`).
Final native regressions pass 3/3 (63.13s;
`native-admin-preparation-native-final.log`), including delayed capture, proof
tampering, changed intent, NAD1 rejection, publication failures, terminal
retirement and restart. Lifecycle fresh submission succeeds and exact retry
adds no commits; resume-only administration rejects unretained work. Normal
vosx build passes (52.10s; `native-admin-preparation-vosx-build.log`), as do
formatting and whitespace checks. Logs remain on disk under shared
`target/task-tmp`, not RAMFS.

Next remains authenticated admin ingress/client delivery, followed by the
protected Local mutation/retirement/restart campaign. Production latency and
the other original release gates remain open; this checkpoint is not a claim
that the branch is ready for master or production deployment.

The same C2 change now connects preparation/submission through the existing
four-entry lifecycle queue, production owner and node drive loop. Invalid
credential signatures and mismatched preparation are rejected before queueing.
Fresh preparation requires owner readiness; a running but recovering owner
may submit only an exact matching retained NAD2 record, reloaded from its
journal. Disconnecting the client does not cancel accepted work. Queue closure
rejects waiting preparation and submission requests as unavailable. These are
internal typed entry points, not transport authentication or a public endpoint;
generic HTTP invocation and operation transport-node restrictions are unchanged.

Queue-inclusive native regressions pass 3/3 (62.78s;
`native-admin-queue-native.log`), exercising fresh mutation through the queued
payload and type-erased lifecycle owner, retained classification, exact retry,
capacity, invalid input, disconnect and shutdown. The existing operation queue
regression passes 1/1 (0.03s; `native-admin-queue-operation-regression.log`).
Normal vosx build, formatting and whitespace checks pass
(`native-admin-queue-vosx-build.log`). No live transport campaign was run for
these internal admin entry points.

### Request-verified admin completion and HTTP delivery (C2)

Admin submission now returns a verified `NativeAuthorityAdminCompletion` through
the lifecycle queue. It carries a NAT2 retired certificate and
verifies its Authority signature, exact request-derived invocation, preparation
commitment and phase;
successful actor results must additionally match the complete signed call.
The client supplies its retained call and NAP1 preparation to verification.
An observed-but-unretired certificate cannot be completion. A signed empty
result is a terminal denial, not a transport failure. This is the pinned
Authority's attestation of native retirement, not independent journal replay;
server recovery continues to verify the complete NAD2 record and physical anchor.
NAT2 adds a signed commitment to the exact NAP1 token so the client can verify
its incarnation binding without possessing the server's full NAD2 record.
NAT1 is deliberately rejected; only disposable admin test histories used that
format, and the previous live startup smoke had no admin records. No runtime
artifact or SDK ABI changed.

NAS1 is a bounded canonical host-side frame containing the signed call and
matching NAP1. `POST /__agents/admin/prepare` accepts a signed zero-slot admin
draft and returns NAP1; `POST /__agents/admin` accepts NAS1 and returns NAT2
with HTTP 200 for success or 403 for a signed retired denial. Both require
`application/octet-stream` and reject query parameters. Incomplete work returns
503/504 and requires retry, never an unsigned terminal denial. The existing
120-second observation deadline and queue capacity are unchanged. A client
must retain the chosen preparation and final signed NAS1 before submitting,
and retain a verified completion before advancing its admin sequence.

These dedicated routes use signed-body authentication, not an asserted HTTP
transport identity: the native owner pins the destination node, and the bundled
Authority verifies credential activity, current Admin role and node ownership.
Generic actor HTTP invocation and operation transport-node restrictions remain
unchanged. During recovery only the exact admin submission route is available;
the owner permits only matching retained work, not fresh preparation. Adjacent
paths do not inherit that exception.

Validation: native admin tests pass 3/3 (47.99s;
`native-admin-nat2-native-verified.log`), including grant/denial retirement,
restart, malformed NAS1, wrong node, altered certificate, unretired certificate,
legacy NAT1 rejection and a validly signed different-incarnation preparation.
HTTP ingress regressions pass 4/4 (0.27s;
`native-admin-nat2-ingress-verified.log`), including malformed admin requests,
unchanged anonymous invocation rejection and recovery route boundaries.
Hardened admin stores pass 3/3 (5.23s; `native-admin-nat2-stores.log`). Normal
vosx build passes (27.24s; `native-admin-nat2-vosx-build.log`), as do formatting
and whitespace checks. Logs are in shared on-disk `target/task-tmp`.
These are separate native and HTTP regression checks, not a live HTTP admin
mutation campaign; no end-to-end transport success is claimed yet.

Managed-client persistence/orchestration and a live protected actor campaign
remain next. The endpoints alone do not close that campaign or the production
latency gate. No new review batch is introduced.

### Retained admin client transport (C2)

`vosx space prepare-admin <request-dir> --request <signed-draft> --http
127.0.0.1:<port>` retains a signed zero-slot draft before requesting NAP1.
`vosx space submit-admin <request-dir> --request <signed-NAS1> --http
127.0.0.1:<port>` retains the exact signed submission before delivery and
retains its verified NAT2 completion before reporting applied/denied. Use
separate request directories for preparation and submission. On retry, omit
`--request`: retained input takes precedence and is never re-signed, rebased or
replaced. A retained verified response avoids another network request entirely.
These are retained transport commands, not yet automatic fresh admin signing
or sequence selection. They do not touch operation credential reservations.

The existing immutable request/response store now has separate CSF1 roles
34/35 for admin preparation and 36/37 for admin submission/completion, using
private exclusively leased directories, bounded reads, request-bound response
validation and interrupted-publication recovery. Orphan responses cannot be
repaired by supplying fresh input. Replacement stages are rejected even when
their payload is otherwise valid. Local loopback HTTP remains mandatory, with
proxies and redirects disabled. Signed success/denial must agree with HTTP
200/403; unsigned errors and forged responses are never retained as completion.
The shared HTTP helper now takes an explicit denial size bound: Create keeps
its prior bound and admin uses NAT2's bound. No timeout was increased.

Validation: focused client storage/loopback tests pass 2/2 (1.89s;
`native-admin-client-tests-final.log`). They cover preparation, successful
mutation and denial responses, unavailable HTTP, forged responses, contradictory
HTTP status, exact retry, cached response after restart without networking,
exclusive leases, staged first publication, forbidden replacement and orphan
response preservation. The full CLI suite passes 246 with 9 ignored (55.45s;
`native-admin-client-cli.log`), including the new command parsing and existing
Create/Install/operation regressions. Normal vosx build passes (13.53s;
`native-admin-client-vosx-build.log`); formatting and whitespace checks pass.
Logs remain under shared on-disk `target/task-tmp`.

Next is automatic signing and credential-local admin sequence reservation,
followed by a live protected Local mutation/retirement/restart campaign. The
client's current loopback tests use synthetic signed responses, not native
daemon execution. Production latency and the other original gates stay open.

### Admin signing and credential-local reservation (C2)

Admin discovery now selects the successor of `admin_request_high_water`, never
the management or operation high-water marks. Deterministic signing helpers
validate the selected operator's active Admin API credential projection, use
its exact administration-generation CAS, sign a zero-slot draft, then sign
NAS1 using only that retained draft and its verified NAP1. Final signing reads
no clock, new generation or random ID. The native Authority remains responsible
for current policy and node ownership; client discovery is not authorization.

`CleanAdminCredentialReservation` gives this domain its own ACR1 image and
CSF1 role 38, distinct from CRS1 management/operation reservation state. Its
private wrapper exposes no Create/Install completion method. It leases one
Space/credential claim, binds the claim to the exact zero-slot draft invocation,
and refuses another draft while pending. Completion requires the matching
retained NAS1 and verified, synchronized NAT2; an observed result, missing
response or mismatched request cannot release the claim. Success and signed
denial are distinct terminal states. Terminal retry is exact, and a later
claim cannot be completed with an older response.

These primitives are not yet connected to a fresh admin CLI command. Required
orchestration remains: hold the admin lease across discovery, retain the draft
and claim before host preparation, retain NAP1, sign/retain NAS1, submit, then
retain NAT2 before finishing the claim. Retry must recover that chain without
discovery or re-signing once NAS1 exists. The protected live campaign and all
other original release gates remain open.

Validation: all 8 focused admin tests pass (6.34s;
`native-admin-signing-reservation.log`), including separate-domain reservation,
pending-work conflicts, exact terminal retry, later-claim isolation, deterministic
final signing, wrong signer, revoked/non-Admin credential and admin sequence
exhaustion. Discovery tests confirm exhausted management/operation domains do
not block selection of the admin successor. Full CLI suite: 248 passed,
9 ignored (55.26s; `native-admin-signing-cli.log`). Normal vosx build passes
(6.70s; `native-admin-signing-vosx-build.log`), as do formatting and whitespace
checks. Logs remain under shared on-disk `target/task-tmp`. These signing and
reservation checks use synthetic evidence; no new live campaign ran here.

### Fresh actor-role command and retained resume (C2)

`vosx space set-actor-role <space> --agent <id> --actor <id> --deployment <id>
--role <id>` grants the exact deployment-scoped role to the local operator;
`--principal <id>` selects another principal and `--revoke` removes the grant.
IDs are full 32-byte hex values. `--http` optionally selects a nonzero loopback
listener; otherwise the existing local-space resolver selects the daemon's
configured endpoint. Operator and node identities come from the existing local
identity/endpoint paths, and the Authority target uses the same bundled root
derivation as startup. No node private key is loaded by this command.

`vosx space set-actor-role <space> --resume` recovers the current admin attempt.
It rejects fresh role flags and never selects another credential sequence,
generation or draft. Once NAS1 exists, it does not rediscover, reprepare or
re-sign. The stored draft, NAP1 and NAS1 must agree; missing preparation is not
permission to reconstruct it. Verified NAT2 is retained before the attempt is
marked applied/denied. A pending attempt rejects a new fresh command before any
network access. Discovery failures before draft retention create no new admin
claim; rerun the original fresh command in that case.

Wiring exposed a necessary correction to the prior ACR1 primitive: denial does
not consume the admin sequence, so identical zero-slot drafts can occur in
later fresh attempts. ACR2 now separates the random local attempt ID from the
protocol invocation ID. Phase 0 binds the retained draft; phase 3 additionally
binds the exact retained NAS1 before dispatch. Only that bound request can
finish the attempt with NAT2. A fresh attempt after denial gets a distinct
directory and may select a new NAP1, while resume stays exact. ACR1 is rejected
without migration; it was only used in disposable tests before this command
was wired. CSF1 role 38 and the 165-byte bound remain unchanged. CRS1 operation
reservation semantics, actor ABI, PVM artifacts and timeout limits are unchanged.

The command owns an exclusive admin credential lease across discovery,
preparation, signing, delivery and terminal retention. The immutable draft is
published before its attempt claim; NAS1 is published before its binding is
made dispatchable. State lives under the space's private `admin-client` tree,
separate from management/operation reservations. Tests use synthetic signed
loopback responses, not native daemon finality. Next is the live protected
Local mutation/retirement/restart campaign, not another admin feature. Production
latency and all other original release gates remain open.

Validation: 10 focused admin tests pass (11.36s;
`native-admin-orchestration-acr2.log`). Full CLI suite passes 250 with 9 ignored
(60.62s; `native-admin-orchestration-cli.log`), including failed preparation,
failed submission, resume without discovery, cached terminal retry without
network access, fresh identical intent after denial, wrong node, missing
preparation and rejection of an old completion for a newly bound request.
Command parsing and built-binary help pass. Normal vosx build passes (6.68s;
`native-admin-orchestration-vosx-build.log`); formatting and whitespace checks
pass. Logs are under shared on-disk `target/task-tmp`.

### Protected LocalSigner campaign: constructor packaging correction

Continuation remains in C2, with C1/C2/C3 as the review groupings. No release
gate is waived and timeout limits are unchanged. In the disposable on-disk
`target/task-tmp/admin-startup-smoke.nHw46n` fixture, native readiness took
about 81 seconds. Fresh Create returned HTTP 504 with its signed request
retained; exact `--resume` subsequently returned a verified acknowledgement
for Local Agent
`aa05af450887c5a4463cb41d1b6753b037f661393c996daafc013f131702a813`.
This proves recovery of that Create, not acceptable first-response latency.

Building the existing LocalSigner example exposed a host packaging mismatch:
AAS2 uses `stringify!` and records `local_signer::[u8; 32]`, whereas `.vos_meta`
uses the macro's whitespace-free type rendering, `[u8;32]`. Constructor
validation now normalizes spaces for that comparison only. Schema bytes,
type identity, runtime ABI and bundled artifacts are unchanged. The regression
accepts the macro-generated spelling and rejects different lengths, element
types, missing module qualification and prefixed type names. Packaging the
same already-built ELF then succeeds: program
`8a46723f0a467494000778fb5a7c97111aa2c293cafd6b60b4fcb3558c9dc511`,
deployment `e3425df32ec374fed3b15394e8e33c1bc1a154941ee39946f7f3cdfdb8bdccc9`.
These are disposable example artifacts, not new system runtime pins.

Full CLI validation after the constructor fix: 251 passed, 9 ignored, zero
failures (69.07s; `protected-constructor-full-cli.log`). A separately opt-in
fixture helper subsequently passed and generated canonical constructor and
protected invocation inputs using real Rust codecs. It requires the explicitly
selected disposable root and isolated identity, uses a public test-only seed,
and refuses to replace different existing inputs. The first sandbox-only run
could not see the daemon PID; the host-visible run passed. Logs are
`protected-inputs.log` and `protected-inputs-host.log` in on-disk `task-tmp`.

The protected LocalSigner installation started at 2026-09-14 23:26:16 UTC and
returned a verified acknowledgement at 23:28:36 UTC on its first CLI attempt
(about 140 seconds, no HTTP timeout). Evidence is `protected-install-1.json`
and its empty error log in the fixture. This used the shared debug vosx binary;
it is not a release-profile performance measurement and does not close latency.
Deployment-scoped role administration started at 23:29:00 UTC and completed
at 23:29:31 UTC: `decision=applied`, `retirement_retained=true`,
`reservation_pending=false` (`protected-role-1.json`). This is the first live
fresh role-grant/retirement pass in this fixture, not a revoke or restart pass.
The protected `sign` invocation started at 23:30:25 UTC and failed during
`/__agents/prepare` with HTTP 503 (`protected-invoke-1.log`). Inspection found
that the new test fixture incorrectly supplied no role claim, while the
method's AMP2 policy requires actor role `51` repeated 32 times. The fixture
generator is corrected and has a regression for its required role claim.
The original retained intent and pending credential reservation remain
unchanged; this fixture must not be retried as if its bytes were corrected.
A bare diagnostic curl lacked authentication and returned 401; it supplies
no further evidence about the authenticated 503. A protected signature and
retirement verifier compiles but has not passed against live evidence.
Protected execution, revoke and restart are still open. Continue with a
fresh disposable campaign using the corrected generator, or a separately
reviewed safe pre-dispatch cancellation path; never edit the retained request
or clear its reservation manually. Do not expand production APIs merely to
repair this disposable test input.

The disposable daemon was stopped gracefully at 23:34:50 UTC (no force),
preserving its pending client reservation and all logs. `protected-down-1.json`
contains the CLI's plain-text clean-exit report despite `--format json`.
No live test daemon is intentionally left running by this checkpoint.
Final CLI suite: 252 passed, 11 explicitly ignored live helpers, zero failures
(62.89s; `protected-checkpoint-cli.log`). The fixture role regression passes;
formatting and whitespace checks pass. The signature verifier is compiled but
remains unexecuted because no successful protected invocation exists yet.

### Protected LocalSigner: package-validated preparation after restart

The fresh `target/task-tmp/admin-startup-smoke.Ju9XZz` campaign preserves the
earlier `nHw46n` fixture unchanged. Space ID:
`72f001368d4b60beae2b8904745f8bb7e56ff21eb1316aa97e5675277111e730`;
Local Agent `5a922e99d23060856a0fa0458bcacdc83ee75b0fbc75a2aec3371d91e1ea401f`;
actor `b92c9fda0626f356d597cbec3ed28d01a5d4df2c2fe1a992878a0884fc51a868`;
LocalSigner deployment `2b30caf6201f7f433d479a36ee8557d1b0331ef14b459ed8f37465dd25a75448`.
The same example PVM was packaged under this fixture's isolated producer.
HTTP/SSH use loopback ports 18089/2231. No system runtime or ABI repin occurred.

Observed native results (2026-09-14 UTC, shared debug binary):

- Startup 23:37:58–23:38:41, about 43s.
- Create 23:38:43–23:40:54, one HTTP 504 then exact resume.
- Install started 23:40:55, returned HTTP 504; exact resume at 23:44:10
  returned a verified acknowledgement at 23:45:05. No request was replaced.
- Signed deployment-scoped role grant 23:45:43–23:46:19, applied with signed
  retirement retained and no pending admin reservation.
- Protected invocation failed preparation with HTTP 503. Its role claim was
  correct, but the fixture still requested `Linear` for `#[msg(local)] sign`.
  The earlier role-only correction was insufficient. The original retained
  intent and pending operation reservation remain untouched.
- Restart 23:52:01–23:53:30, about 89s. Graceful shutdown before restart exceeded
  the CLI's five-second observation but the original daemon handle subsequently
  exited successfully; no force kill or concurrent replacement was used.

The generator now decodes the actual package's AMP2 artifact, checks `sign`
requires Local mode and the expected actor role, and uses its method mode.
It still refuses to overwrite different inputs. A separate `after-restart`
fixture intent (nonce `74` repeated 32 times, distinct filenames) was generated
without changing the pending `73` intent. Authenticated physical preparation
of this correct Local-mode request passes in 11.00s, verifying the canonical
ATP1 against the exact intent (`corrected-local-prepare.log`). No authorization
or invocation was issued by this diagnostic. Repeating the original Linear
request fails in 11.17s; server logging identifies `Route(Rejected)`
(`retained-linear-diagnostic.log`, `up-2.log`). This isolates a fixture error,
not evidence that protected execution has succeeded.

The result verifier now checks exact target, invocation, mode, origin, role,
message and gas as well as package identity, visible signature and retirement.
Distinct post-restart filenames/nonces prevent a cached earlier result from
being counted as fresh execution. The diagnostic is opt-in, loopback-only,
bounded, with proxies and redirects disabled; credentials are never logged.
Production preparation errors now log their typed supervisor cause without
changing the public response, authorization rules or timeout limits.

Next remains a fresh end-to-end protected campaign with these package-validated
inputs, then fresh protected execution after restart. Neither failed
reservation may be cleared or rewritten to make that test pass. Revoke,
yield/resume where applicable, latency and all other C1/C2/C3 gates remain open.
Do not expand production APIs merely to repair malformed disposable inputs.

Validation: full CLI 252 passed / 12 ignored / zero failures (65.05s,
`final-cli.log`); HTTP ingress 4 passed / zero failures (0.27s,
`final-ingress.log`); normal vosx build passed (17.54s,
`diagnostic-build.log`); formatting and whitespace checks pass. The final
graceful shutdown again outlasted the CLI's five-second wait, then the exact
daemon session exited zero without a force kill. No campaign daemon is left
running. Slow startup/Create/Install/shutdown remain release blockers.

### Protected LocalSigner: live execution and retirement

Fresh fixture: `target/task-tmp/admin-startup-smoke.hJuDDq`, isolated keys and
loopback HTTP/SSH ports 18090/2232. Space
`1c2d321fe40b4d01ce3effe2d78609ed814101da9a9956c2c464594d048d0de0`;
Local Agent `e2f7872c5613e2c0f528aa8832d98ab69bc85c45f94bfd2424056b9a243363ac`;
LocalSigner actor `ac795d819ad85a0df8c97c478778f1ea1ac7181f815adaeab0ec7d78f4441b23`;
deployment `74163fd504a81f2bb823fbc135c64ef565b3b259047fc00abfcf9d83ef11bc87`.
The example PVM is unchanged; it was packaged under the fresh isolated producer.
No runtime ABI/system artifact change was needed.

Native results on 2026-09-15 UTC (`timing.log`, per-attempt JSON/error logs):

- Startup 00:00:35–00:01:17, about 43s.
- Create 00:01:19–00:03:27, first attempt succeeds (128s).
- Install 00:03:31–00:07:36, succeeds after one HTTP 504 and exact resume (245s).
- Deployment-scoped role grant 00:07:36–00:08:23, applied with terminal retirement.
- Package-validated authenticated preparation passes (45.18s; `preflight.log`).
- Protected `Local` sign invocation 00:09:09–00:12:36 (207s), completes after
  two exact host-clock preparation retries. Both initial failures logged native
  `CapacityExhausted`; the third attempt retained its bound preparation and
  completed authorization, execution and positive retirement. No AOC5 was
  rebuilt or client reservation cleared (`invoke-attempt-{1,2,3}.log`).
- `verify.log` passes (0.06s): exact target, invocation, Local mode, principal,
  actor role, message, gas, package/deployment, Authority receipt-bearing
  authorization, visible Ed25519 signature and retained positive retirement.
  CLI reports `decision=issued`, `delivery_retired=true`,
  `reservation_pending=false` (`protected-invoke-1.json`).

The first scratch runner signalled its background wrapper instead of owning
the daemon PID directly and exited 143 after the successful verification.
Do not label that boundary a proven graceful shutdown. The exact daemon PID
was subsequently confirmed absent; `space down` cleaned its stale endpoint
(`down-confirmed.log`). The runner has been corrected to launch the executable
wrapper directly. `restart-campaign.sh` uses direct PID ownership and does not
start a replacement until prior process termination is established.

Actual restart began 00:14:30 and reached readiness 00:16:14 (about 104s).
Exact retained retry passed at 00:16:17: normalized JSON is identical before
and after restart (`cached-after-restart.json`). This is cached client recovery,
not proof of a new actor execution. Separately, a fresh protected invocation
with nonce `74` repeated 32 times ran 00:16:17–00:18:11 (114s) and succeeded on
its first CLI attempt. Its independently retained response and positive
retirement passed the same exact-request/signature verifier in 0.06s
(`protected-invoke-after-restart.json`, `verify-after-restart.log`). Both client
operation reservations are completed; no retained intent was rewritten.
This proves fresh protected signing after native restore, not merely replay of
the prior result. The example's private signature counter is not exposed by
its API, so these checks do not independently measure that counter's value.

The directly owned restart daemon received SIGTERM at 00:18:11 and exited
successfully at 00:19:28: a verified graceful shutdown taking 77s, without a
force kill. `restart-campaign.sh` completed with exit zero; no campaign daemon
is intentionally left running. This checkpoint changes review evidence only;
no production code, artifact, timeout, or reservation format changed. The live
signature/retirement verifier passes twice (0.06s each), package policy/input
validation passes, and documentation whitespace checks pass. The previous
252-test CLI and four-test ingress regression results remain the source
baseline, not a newly rerun release matrix.

These are debug-binary native correctness results, not acceptable production
performance. The transient native admission errors, latency, revoke,
yield/resume where applicable and other original C1/C2/C3 gates remain open.

### Protected LocalSigner: revoke, terminal denial and valid successor

The same `admin-startup-smoke.hJuDDq` fixture now passes the live
deployment-scoped role revocation workflow. No new space, actor, system artifact
or production API was introduced. Prior successful/failed requests are unchanged.
On 2026-09-15 UTC (`revoke-timing.log`):

- Restore began 00:20:56, ready 00:24:25 (209s).
- Role revoke 00:24:25–00:25:13 (48s), first attempt; signed admin terminal
  applied and retained, admin reservation not pending (`revoke.json`).
- Fresh protected call, nonce `75` repeated 32 times, 00:25:16–00:27:51 (155s),
  first attempt; returns `decision=denied`, `decision_retained=true`,
  `applied=false`, `reservation_pending=false` (`protected-invoke-revoked.json`).
- The denial verifier passes (0.32s; `verify-revoked.log`). It verifies canonical
  signed AOR1 denial against its exact retained AOQ1, exact ATP1/work commitment,
  actor/deployment, origin and actor-role claim. The credential reservation is
  terminal Denied for this nonce, and no actor application directory exists.
  This is not merely an HTTP error. Exact `--resume` returns identical normalized
  JSON (`revoked-cached.json`), without replacing the retained request.
- Role re-grant 00:27:52–00:28:20 (28s), first attempt; signed terminal applied
  and retained (`regrant.json`).
- A fresh protected call, nonce `76` repeated 32 times, 00:28:21–00:30:38 (137s),
  first attempt; successful signature and positive retirement verify (0.43s;
  `verify-regranted.log`, `protected-invoke-regranted.json`). Its retained
  authorization uses the same operation credential sequence as the denied
  request, but a different intent and directory. Thus denial did not consume
  the sequence or strand the client reservation. Admin sequencing stays separate.

The fixture helpers add explicit revoked/regranted phases with distinct files
and nonces. The denial-state assertion is intentionally run before the next
fresh call takes the credential reservation; the successor verification also
revalidates the historical signed denial without assuming it is still the
current reservation. Actor method mode and claims still come from the validated
package policy. This proves the actor-role revoke/deny/re-grant path, not every
credential revocation, expiry, abort, mixed-pending or recovery-capacity case.
Latency, yield/resume where applicable and the remaining original release gates
remain open. No timeout, ABI, runtime artifact or production policy changed.

Validation: full CLI 252 passed, 12 opt-in helpers ignored, zero failures
(63.24s; `revocation-full-cli.log`); live denied/successor verifiers pass as
above; formatting and whitespace checks pass. SIGTERM was requested at
00:32:01. The CLI's five-second observation expired, but the same daemon session
later exited zero and its exact PID was confirmed absent. No force kill was
used. Regression tests ran during this shutdown interval, so it is not an
isolated shutdown benchmark. All campaign data remains on disk under `target`;
the root `saga/agents` checkout is untouched.

### Native interpreter helper inlining (C2 latency)

After protected grant/revoke/restart coverage, the latency investigation returned
to the measured physical execution cost. Standard Refine intentionally uses the
conformance interpreter, independently of the capability kernel's backend
selection. No backend, ISA, gas, authorization or memory-check change is made.

The opt-in `profile_bundled_runtime_large_acknowledgement` probe repeats the
existing fixed ACK regression eight times. Its 793,734-byte input contains a
768KB installed program and a retained terminal result. Each run must halt and
decode a positive acknowledgement. It does not execute the synthetic actor and
does not append live-space history. Logs and CPU profiles are under shared
disk-backed `target/task-tmp`, not `/tmp`.

The baseline CPU profile (`ack-fixed-baseline.perf`) attributes 75.20% of the
main-core samples to the interpreter loop, 6.14% to readable-range checks,
3.60% to writable-range checks and 5.29% to opcode-terminator classification.
The change adds std-only inlining hints to those two memory wrappers, their
private range predicate and opcode classification. Constant scalar widths and
permissions can then be optimized at the caller while retaining all existing
checks, including wrapped-address fault ordering and atomic failing stores.
The no-std code path is unchanged. No guest artifact or ABI was repinned.

The candidate profile removes those out-of-line helper hotspots. Its first
timing run overlapped a PVM test build and is not the clean comparison. Separate
eight-run, unprofiled measurements, with no concurrent task build, give:

- Baseline restored by removing only the inlining attributes: median
  **1,278,893.5 us**, range 1,265,335–1,289,063 us
  (`ack-baseline-clean-repeat.log`).
- Inlining candidate: median **1,024,132 us**, range 1,006,396–1,076,125 us
  (`ack-inline-clean-repeat.log`), about **19.9% lower** for this fixed path.
- Every measured run consumes exactly **515,787,220 gas**. The same bundled
  PVM and fixed input are used; no validation or gas discount is responsible.

The candidate attributes were restored after the baseline recheck. This is
sequential microbenchmark evidence, not a production latency guarantee.
Startup, Create/Install/Invoke, shutdown and transient native admission failures
remain release blockers requiring end-to-end measurement on equivalent history.

Validation: PVM library **259 passed / 1 ignored** (0.47s), PVM vectors **20
passed** (0.21s; the vector runner also reports its filtered one-test subprocess),
SPI boundary **4 passed** (0.01s), and `vos-pvm --no-default-features` check
passes. Evidence: `ack-inline-pvm-tests.log`, `ack-inline-pvm-vectors.log`,
`ack-inline-no-std.log`. These include scalar fault ordering, flat/sparse memory
and standard execution boundaries. The full release matrix remains open.
Final CLI regression: **252 passed / 12 ignored / zero failures** (62.99s;
`ack-inline-cli-tests.log`). Normal vosx build passes (11.44s;
`ack-inline-vosx-build.log`); formatting and whitespace checks pass. No live
space was started or modified for this profiling checkpoint, and no profiler,
test or build process is left running.

### Management admission capacity diagnostics (C2, investigation only)

The two authorization-preparation `CapacityExhausted` responses in
`admin-startup-smoke.hJuDDq/up-1.log` cannot be attributed to a specific budget
from the retained logs. The native initial-capture path reserves the complete
authorization/ACK lifecycle plus conservative finalization/ACK headroom before
publishing the immutable management intent. It can reject either the composite
replay suffix budget or the remaining Ordered log slots; both previously
returned the same unqualified error.

The coordinator now logs `limit=replay_headroom` versus `limit=ordered_slots`,
along with the public Agent ID, initial/extension and retained-retry flags,
applied/remaining slots and pending/retiring counts. Slot exhaustion also logs
the required slot count including its existing safety margin. No signed
request, credential, message, or envelope bytes are logged. Admission limits,
callback ordering, retained envelopes and HTTP responses are unchanged.

The read-only projection path has a bounded certified-checkpoint retry, while
initial management capture has no corresponding retry. This is a candidate
gap, not a demonstrated cause of the historical errors. In particular, a
projection-pair budget check does not establish that the larger management
reservation fits. Do not simply wrap capture in that retry or rebase a retained
authorization clock. The next equivalent live campaign must identify the
failed budget before selecting a checkpoint change, and then verify exact
retained recovery and end-to-end timing. No live space was modified during
this investigation; the capacity and production-latency gates remain open.

Validation: focused `native_operation_` regressions **9 passed / zero failures**
(90.60s), including admission reopen, retained policy/issuance, denial and
partial retirement recovery. Normal vosx build passes (15.18s), as do formatting
and whitespace checks. Evidence in disk-backed `target/task-tmp`:
`management-capacity-native-operation.log` and
`management-capacity-vosx-build.log`. These are regression checks, not a
reproduction of either capacity rejection or a live latency measurement.

### Live capacity probe after native helper inlining (C2)

Restarted only the existing disposable `admin-startup-smoke.hJuDDq` space with
the capacity diagnostics enabled. Added an explicit ignored-fixture
`capacity-probe` phase using new invocation nonce `0x77` repeated 32 times;
earlier signed intents and reservations were not edited. The input generator
first refused before daemon readiness, with no request written; after readiness
it passed and created the new package-policy-validated LocalSigner intent.

- Restore: network start **00:58:34.789 UTC**, ready **01:01:37.125 UTC** on
  2026-09-15, approximately **182.34s**. History includes the prior revoke/regrant
  campaign, so this is not an equivalent-history before/after comparison.
- Fresh protected invocation: **01:02:08–01:04:11 UTC**, **123s**, first attempt.
  Verified signature and exact retained retirement (verifier 0.06s); issued,
  decision retained, delivery retired, reservation not pending. Exact cached
  retry returned identical normalized JSON before shutdown was requested.
- **No capacity failure reproduced.** This does not explain or close the two
  historical authorization-preparation failures. Do not infer that helper
  inlining repaired admission or that two-minute execution is acceptable.
- Ten-second restore CPU sample (99Hz): main-core samples **54.11%** in
  `blake2b_simd::avx2::compress1_loop`, **23.12%** in interpreter `run_inner`,
  **3.18%** in conformance `tick`, **2.26%** in conformance `dispatch_one`.
  Only three efficiency-core samples were collected and are not representative.
  Frame-pointer unwinding did not identify the hashing callers reliably; this
  sample identifies a hotspot, not the responsible validation layer. Both
  BLAKE2 and PVM already have optimized dev-profile package overrides.

Evidence: `up-capacity.log`, `inputs-capacity.log` (early refusal),
`inputs-capacity-ready.log`, `capacity-timing.log`, `capacity-attempt-1.json`,
`protected-invoke-capacity.json`, `verify-capacity.log`, `capacity-cached.json`
inside the disposable fixture. CPU evidence is in disk-backed task-tmp
`capacity-restore.perf` and `capacity-restore-perf.log`. No RAMFS scratch was
created. Next C2 action: isolate the restore hashing callers and construct a
repeatable initial-management admission boundary case before changing
checkpoint behavior. Production latency and admission gates remain open.

Shutdown: SIGTERM was sent at **01:04:33 UTC** to the exact daemon PID 3646916.
The CLI's five-second observation window expired, but the original foreground
session subsequently exited **0**, without force or restart. All campaign,
profiler, build and daemon handles from this probe are terminal. Formatting
and whitespace checks pass; no additional full release matrix is claimed.

### Restore phase sampling follow-up (C2)

Reopened the same disposable space after the capacity-probe invocation and
clean shutdown, without submitting another operation. Network started at
**01:06:25 UTC**, ready at **01:07:57.097 UTC** on 2026-09-15 (about **91s**).
This is different durable history from the preceding 182s restore; do not
attribute the difference to a code speedup (the daemon binary was unchanged).
The next latency comparison needs an identical saved journal baseline.

Ten-second DWARF-stack samples at 49Hz show phase variation: early main-core
samples were **76.09%** interpreter `run_inner`; later samples were **38.82%**
interpreter, **33.52%** BLAKE2 compression, **4.15%** conformance `tick`, and
**3.90%** conformance `dispatch_one`. Neither sample reliably resolved the
hashing call chain: the report contains unknown frames and an addr2line debug
record warning. Thus the earlier 54% hashing sample is not a whole-restore
breakdown and does not justify removing any particular validation pass.

Evidence: fixture `up-restore-callers.log`; disk-backed task-tmp
`restore-callers.perf`, `restore-callers-report.log`,
`restore-callers-hash.perf`. A larger-stack sample attempt exited 255 without
diagnostics and is not evidence; the subsequent 16KiB-stack sample completed.
The space was stopped with SIGTERM; the CLI confirmed clean exit and the
original daemon session exited 0. No live profiler or daemon remains.
No runtime, guest artifact, validation rule, or admission behavior changed in
this sampling follow-up. The C2 capacity diagnostics and protected probe are
one scoped review unit, not an additional release batch.

### Reproduced initial-management admission boundary (C2)

The explicit diagnostic
`native_operation_initial_capture_requires_more_headroom_than_projection`
passes against the real bundled Authority and native journal (**323.02s**;
`target/task-tmp/management-boundary-run.log`). It builds authenticated
projection Invoke/ACK history until initial management no longer fits. At that
point it proves all of the following:

- Initial capture returns `CapacityExhausted` before its publication callback;
  physical state is unchanged and no pending reservation exists.
- The smaller projection pair still fits, so its ordinary certified-checkpoint
  helper returns false and does not repair management capacity.
- Forcing an actual certified checkpoint makes the same management request
  admissible, with the exact same runtime envelope.

This confirms a missing initial-management capacity repair path. It does not
prove that either historical HTTP 503 had this cause, and production behavior
is not fixed yet. Next change: budget-aware certified checkpoint before fresh
management reservation, with exclusion against existing pending work and
retirement, preserving retained clocks and callback-failure retry semantics.
Do not reuse the smaller projection's fit predicate.

The test is ignored by default because filling and checkpointing the real
64MiB suffix takes several minutes. Run the named test with the existing vos
native feature set and `-- --ignored --test-threads=1`. Its body passed before
adding only this explicit-run annotation. The first compile failed for a
missing closure return type; `management-boundary.log` preserves that failure.
The successful test exited 0 and its disposable journal directory was removed
by the existing harness cleanup. No daemon or test remains running.

### Budget-aware initial management checkpoint repair (C2)

Fresh Create/Install, operation authorization and admin capture now use one
bounded checkpoint fallback on initial admission exhaustion. The existing
capture check supplies the full management lifecycle budget; after a certified
checkpoint it checks that same budget again, rather than a projection's
smaller Invoke/ACK budget. No limits or HTTP timeouts were increased.

The shared certificate/attachment implementation is extracted from the
existing projection checkpoint path; each caller retains its own fit check.
Committee authentication, signer refusal, proposal exclusion and reattachment
behavior are preserved. Existing pending management or retirement prevents
the fallback. The persistence callback is consumed at most once: its errors,
including `CapacityExhausted`, retain the exact reservation and never trigger
compaction. No signed request or retained observation clock is regenerated.

The explicit real-journal boundary test now calls production capture after
demonstrating that the projection helper does not compact; it no longer forces
a checkpoint. A separate routine regression checks a callback capacity error,
unchanged physical state, retained reservation and byte-identical exact retry.
This fixes the reproduced admission path, not the broader latency gate or
every possible source of the historical HTTP 503 responses.

Validation: native operation regressions **10 passed / 1 explicit diagnostic
ignored** (95.56s), checkpoint failure/attachment recovery **1 passed** (8.82s),
native admin regressions **3 passed** (51.76s), CLI **252 passed / 12 ignored**
(68.81s), normal vosx build passes (15.99s), formatting and whitespace checks
pass. Logs in disk-backed task-tmp: `management-checkpoint-regressions.log`,
`management-checkpoint-projection.log`, `management-checkpoint-admin.log`,
`management-checkpoint-cli.log`, `management-checkpoint-build.log`.
The explicit real-journal regression also **passed** against production capture
(357.53s; `management-checkpoint-boundary.log`), with no forced checkpoint.
Other checks overlapped this diagnostic, so its elapsed time is not a latency
benchmark. Its temporary journal was removed by harness cleanup and all test
and build handles exited 0. No live space was started for this fix.

### Compiled protected yield fixture prepared (C2, gate still open)

`vos/tests/fixtures/agent-yield` adds a separately locked test actor, not a
production example or system bundle. Its role-protected Local `run` mutates
state by 1/10/100 around two `Context::yield_now` awaits; completed value is
111. A LocalQuery exposes the final value for restart verification. Existing
host and client yield tests use scripted boundaries; this fixture enables the
missing compiled-actor native-ingress campaign without changing LocalSigner.

Host check, pinned-nightly PVM build and signed VOS3 packaging pass. The first
guest link lacked `pvm.ld`; the fixture now includes the canonical example
layout through a small linker-script include. Program ID:
`5a18bc7455ddf53d63691d6f91bb09c326ce3895fdd4397b11f22a71f47d254c`.
Disposable package is `admin-startup-smoke.hJuDDq/yield-probe/AgentYieldProbe.vos`
under disk-backed task-tmp. Evidence: `agent-yield-host-check.log`,
`agent-yield-guest-build.log` (first link failure),
`agent-yield-guest-build-linked.log`, `agent-yield-package.log`.
No daemon was started and no install, invocation or yield execution is claimed.
Next: the fixture README specifies the retained first yield, daemon restart,
exact resumes, terminal value, positive retirement and post-restart query.
This remains within C2; no runtime artifact repin or release gate is closed.

### Compiled yield campaign exposed actor-side export rejection (C2)

The disposable `admin-startup-smoke.hJuDDq` daemon restored from **01:36:22**
to **01:38:35 UTC** on 2026-09-15. Installing `AgentYieldProbe` as `yield-probe`
took **270s** (01:39:45–01:44:15), with one retained HTTP 504 and exact resume.
The deployment-scoped role grant then passed on its first client attempt in
**52s**. During that grant the new diagnostic reported
`initial=true retained=false limit=replay_headroom`; the checkpoint fallback
recovered and returned applied, retired, non-pending success. This is live
evidence of the admission repair, not an acceptable latency result.

The first protected invocation (`0x78` repeated 32 bytes) failed the yield
assertion after **104.25s**: native ingress retained `Completed(Ok(reply))`
with **status Panicked**, not a yielded continuation. Two exact retries returned
the same result. No resume or positive retirement was performed; the operation
reservation remains pending. Preserve its signed request and original package.
The daemon was stopped with SIGTERM at **01:48:26 UTC**, and the CLI and original
foreground session both confirmed clean exit. No daemon remains running.

Source inspection found an inconsistent actor-side guard: `yield_now` sets
`self_schedule`, `exit_status` exports that flag as `STATUS_YIELDED`, but
`__has_unexported_agent_effects` rejected the flag first. It now permits that
exported status while retaining checks for unsupported queues, stop, checkpoint
tokens and host I/O. The runtime still requires an actual SUSPEND capture and
rejects forged yielded output. The new context guard regression passes;
all **12 execution tests** pass, including a new physical forged-yield rejection
and existing continuation gas/work-budget checks. This is a source-level fix
for the inconsistency; a corrected compiled-actor live pass is still required.

Rebuilt the actor into a separate `yield-probe-fixed/AgentYieldProbe.vos`:
program `c372e1d40942975057b990870d77f70a5b1f5f2354a9165f2422ddcda6d09458`,
deployment `cc1ae24388142a49050c085191bcf0d20047fc116338eb903ae459d5e30883e7`.
**The fix requires rebuilding actor packages; a new host alone cannot repair
already installed actor code.** Existing runtime/system bundles were not
repinned; the final source/artifact rebuild remains part of C3.

Evidence: fixture `yield-install-timing.log`, `yield-install-{1,2}.*`,
`yield-grant-1.json`, `yield-first-slice-{1,2,3}.log`, `up-yield-1.log`;
task-tmp `yield-export-guard.log`, `yield-execution-guards.log`,
`yield-fixed-guest-build.log`, `yield-fixed-package.log`.
The new opt-in client helpers retain the first slice separately and verify two
resume exchanges, final 111, retirement and a separate post-restart LocalQuery.
They are not a completed campaign. Next: retire the exact retained Panicked
result through normal acknowledgement/reservation completion, preserve its
evidence, then install the corrected fixture under a fresh actor identity and
use new invocation IDs. Never overwrite `yield-run.intent` or its reservation.
CLI regression: **252 passed / 16 opt-in tests ignored**, zero failures
(61.58s; `yield-guard-cli.log`). Workspace/fixture formatting and whitespace
checks pass. All build/test/daemon handles from this campaign are terminal.
The fixture, helpers and source correction remain uncommitted for grouping
with the corrected native campaign; the root `saga/agents` checkout is unchanged.

### Native failure retirement returns NotFound (C2 terminal-result gap)

Restarted the disposable yield space: network start **01:56:00 UTC**, ready
**01:58:29 UTC**, 2026-09-15. Before any corrected install, the guarded helper
loaded the original `0x78` invocation, checked its original package/deployment
and retained Panicked reply, then used normal managed continuation to retire it.
The first attempt at **01:59:14 UTC** retained
**`Acknowledged(Err(NotFound))`**. Exact retries fail closed on that same saved
acknowledgement; the credential reservation was not released. The corrected
fixture was neither installed nor invoked. No signed request, reservation,
response, or progress record was replaced or cleared.

This is distinct from the actor-side yield export bug. Source tracing shows
`finalize_unseen_standard_outcome` preserves terminal failure by advancing only
its result-component clock. `StandardAgentRuntime::restore` accepts retained
invocation results only with status Done, and `acknowledge_clean_invocation`
looks up `invocation_results`, returning NotFound for this failure. The native
driver's exact-outcome verifier likewise derives a clock-only successor. The
client retains the Panicked response, but that is not a guest-authenticated
positive retirement fact. Do not manufacture one or treat absence as success.

Next required work is failure-result retention and acknowledgement across the
guest runtime, restored state and native exact-outcome validation, preserving
rollback of actor state, continuation consumption, authorization binding and
bounded result storage. This needs an updated/reproduced runtime artifact and
fresh native proof; changing the host alone cannot fix the already-pinned
guest. The saved negative CIP1 acknowledgement must remain immutable. Do not
claim the original failure recovered merely because a fresh fixture works.

The helper now has an explicit `VOSX_YIELD_SMOKE_PHASE=fixed` using separate
`yield-fixed-*` files, actor name `yield-probe-fixed`, invocation `0x80`, and
query `0x81`; original `0x78`/`0x79` inputs remain intact. Only the helper code
was prepared: the fixed campaign stopped at retirement before generating or
submitting fresh work. Build passes; the live retirement test intentionally
reports failure, not a passed gate. Evidence: fixture `up-yield-fixed.log`,
`yield-fixed-timing.log`, `yield-retire-original-{1,2,3}.log`,
`yield-retirement-diagnostic.log`; task-tmp `yield-fixed-helper-build.log`.

SIGTERM was sent at **02:03:24 UTC** to daemon PID 3719486. The CLI's five-second
observation expired, but the original daemon session then exited **0**, without
force. All daemon, campaign and diagnostic handles are terminal. Formatting
and whitespace checks pass; the changes remain uncommitted with the yield work.

### Terminal failure retention primitive (C2, staged; not yet dispatched)

Added `StandardAgentRuntime::retain_clean_terminal_failure` as the bounded,
atomic building block for the native NotFound retirement defect above. It
authenticates the original work, checks the exact resolved invocation and
terminal reply, retains its clean authorization binding, and optionally
consumes the exact resumed continuation. It does not accept actor lane output
or increment actor lane revisions. Duplicate results, retired identities,
invalid terminal status, excess result bytes, and missing continuations fail
without changing state. Restore now admits Forbidden/Panicked/OutOfGas only
with a valid clean binding and no committed observation; unbound legacy
failures and Yielded results remain rejected.

Three focused tests pass: failure retry/restart/exact positive ACK for all
three statuses; atomic rejection/capacity checks; resumed failure consumption
and retirement without actor-state changes. Four existing regression tests
also pass: Done retry/restart/ACK, both clean ACK capacity/error tests, and
the legacy clock-only terminal/error successor test. Focused build/test log:
`task-tmp/terminal-failure-retention-resume.log` (**3 passed**, 0 failed);
the four regressions were run directly from the same compiled test binary.
Formatting and whitespace checks pass.

**This is not an end-to-end fix or a closed gate.** The new primitive is not
called by guest dispatch yet. Clean Invoke/Resume still use the existing
clock-only failure finalizer, and the native exact-outcome verifier still
requires that successor. Keep those two paths coordinated: next wire the
clean terminal-reply path and independently derive/validate its exact retained
successor, including retries and resumed failures; leave legacy and typed-error
semantics explicit. Then rebuild/reproduce the runtime artifact and repeat
native failure retirement plus the corrected compiled yield campaign in a
fresh disposable space. Preserve the old fixture's immutable negative CIP1
and pending reservation. No new daemon, live mutation, artifact repin or
commit occurred in this step; changes stay in the existing C2 worktree chunk.
Production latency and all other original release gates remain open.

### Terminal failure dispatch and native verification (C2, artifact pending)

The preceding staged primitive is now connected in source. Clean Invoke and
Resume rebase Forbidden/Panicked/OutOfGas on pristine state and atomically
retain the authenticated reply; failure to retain leaves the prior state
unchanged. Typed `InvocationError` outcomes deliberately retain their existing
clock-only policy and remain a separate unresolved retirement case. Legacy
execution behavior is unchanged.

The native failed-reply verifier now derives the exact successor from prior
state and accepted work/authorization. It validates exact reply recovery on
Invoke retries, unseen admission slots, resumed continuation consumption, and
the entire resulting state. It rejects a clock-only failure successor, changed
reply bytes, changed accepted-work binding, and a continuation left behind
after terminal completion.

**Seven focused tests pass** (`task-tmp/terminal-failure-captured-resume.log`):
the three retention tests, interpreter-backed Invoke failure/rollback/retry/
restart/ACK, resumed failure/restart/ACK, and two native successor-validation
tests. Invoke covers all three terminal statuses with attempted actor writes
and a physical interpreter trap. Resume starts from a captured machine image
at the trap, inserted through the continuation commit path: this is a focused
restoration test, not the compiled actor's live two-yield campaign. The first
synthetic Resume fixture failed closed with InvalidAvailability because its
memory layout did not match the program; the captured image corrects that
fixture (`terminal-failure-resume-dispatch.log` preserves the failed attempt).
The full runtime-wire test group also passes: **74 passed, 0 failed, 1 ignored**
in **17.82s** (`task-tmp/terminal-failure-wire-regressions.log`); the ignored
case is the opt-in repeated-ACK CPU profiling probe. Formatting and whitespace
checks pass. These are source/interpreter checks, not bundled-guest release
certification.

**Do not deploy a fresh binary from this dirty tree yet:** the source verifier
expects retained failures while the bundled runtime still emits clock-only
failures. No bundled artifact or provenance pin changed in this step. Next
build a runtime candidate, verify the physical outer guest path, freeze and
independently reproduce its source/artifact, repin consistently, then rerun the
native and CLI checks and fresh disposable failure/yield/restart campaign.
The old negative CIP1 remains immutable. No daemon was started, no external
operation was submitted, and no commit/merge/push occurred. All changes remain
in the scoped C2 lifecycle worktree chunk; original release gates stay open.

### Physical terminal-failure runtime candidate (C2, reproduction next)

Built the dirty-tree guest with locked/offline `nightly-2026-03-20` and
converted it with the existing immutable `42f3f3bf` host builder. Candidate
evidence is in disk-backed `task-tmp/runtime-failure-candidate.t49q9i/`:
`build.log`, `identity.log`, `agent-runtime.pvm`, and `physical-lifecycle.log`.
The build completed in **21.74s**. Candidate identity:

- ProgramId `e701b268823d5ec276c4f9083448df114057d414b3c1d4d7336ef2c1d6a03247`;
- ELF BLAKE2b-256 `7172f949715231e3b6d7fceda10af20b9dee2b12dc05aaa7761809d815b96443`;
- PVM BLAKE2b-256 `bb2055e07d17028fc3504d5563229fc29735b0b0071dfc40563c054202edee9d`;
- PVM size **958,851 bytes**; ABI remains r16 (no wire schema change).

The opt-in `candidate_runtime_terminal_failure_lifecycle_matches_source`
test passes (**1 test, 2.26s**): five cases (Forbidden, Panicked, OutOfGas,
physical trap, restored trap) each execute completion, post-reopen exact
Invoke retry, ACK and repeated ACK through the compiled outer guest. All
**20 exchanges** match the full source transition bytes, including state.
The test requires `VOS_AGENT_RUNTIME_FAILURE_CANDIDATE` and is ignored by
default until the bundled artifact is repinned; make it a normal bundled
regression when that happens. This complements rather than replaces the
native-verifier rejection tests and the still-pending live compiled-yield
campaign. Typed-error retirement and production latency remain open.

Freeze this scoped C2 source chunk before independent reproduction, then
rebuild twice from that immutable revision and compare ELF/PVM bytes before
updating the runtime blob, ProgramId and provenance together. The dirty-tree
candidate alone is not reproducibility evidence. No bundled pin changed and
no live space was started during this step.

### Reproduced terminal-failure runtime pin (C2)

Source chunk **`2ef2220e035fb713a7dced8b6e49ef8d9bcd306b`** contains the
cooperative-yield export fix, authenticated terminal-failure retention,
clean dispatch/native verification, and scoped regression/live-test fixtures.
It is committed on `wip/ch08-runtime-directory`, not merged into `saga/agents`.
Two fresh source exports and independent targets reproduce byte-identical
ELF and PVM artifacts, also identical to the physically tested candidate.
Evidence: `task-tmp/runtime-failure-candidate.t49q9i/reproduce.sh`,
`first/`, `second/`, and `reproduction.log`. The pinned identity and digests
are the candidate values recorded immediately above; both guest builds used
locked/offline nightly-2026-03-20 and the immutable 42f3f3bf host builder.

The bundled PVM, `STANDARD_RUNTIME_PROGRAM_ID`, build-time digest, and
`support/production-artifacts.toml` now agree on that reproduced artifact.
System actor templates and ABI/schema remain unchanged. The physical
terminal-failure lifecycle test is now an ordinary bundled regression (an
explicit candidate environment variable remains available for future probes).

The normal native feature build initially exposed PVM-only gates on shared
validation helpers. Those pure helpers now compile under either `std` or
`pvm`; guest-only test fixtures retain their PVM gates. This does not alter
the reproduced guest code selection. The failed attempts remain in `cli.log`
and `build-cli.log`; they are not passing validation evidence.

Post-pin checks in the same evidence directory:

- `bundled.log`: **4 passed**, 0 failed, 1 optional profiling probe ignored,
  **4.01s**;
- `native.log`: **10 passed**, 0 failed, 1 expensive capacity diagnostic
  ignored, **90.55s**;
- `clean-break.log`: normal CLI build and retained/retired command surface
  checks pass; normal build **22.44s**;
- `cli-native-features.log`: **252 passed**, 0 failed, **17 ignored**, **67.29s**.
  Ignored diagnostics/live campaigns remain unproved by this suite.

Formatting and whitespace checks pass. All build/test process handles are
terminal; no daemon is running from this step.

The prior source/artifact mismatch warning is superseded by this coordinated
pin and successful normal build, not by a production-readiness declaration.
Existing spaces still pin their own old runtime; no implicit migration or
repair of the original negative CIP1 occurred. Next run the corrected
compiled-yield and failure-retirement campaign in a fresh disposable space,
then address typed-error retirement and the remaining original C1/C2/C3
gates, including production latency. No live space ran during this pin step.

### Fresh native compiled-yield first slice (C2, restart continuation pending)

Fresh disposable fixture `task-tmp/admin-startup-smoke.lU4S5Z` uses the
reproduced failure-retaining runtime and a new isolated operator/data tree.
Space `f9c20b4335a578d48b1fd9f719189aa0bc69c96f979419b0f831a2d498abff47`
has loopback HTTP `18091` and SSH `2233`; no old space was migrated or edited.
The actor rebuild produced corrected program
`c372e1d40942975057b990870d77f70a5b1f5f2354a9165f2422ddcda6d09458`,
new operator-signed deployment
`6f8eb2662d7a79446946c024bca1b1a8e6e99205dde4517d248ba3acab079344`.

Observed UTC timings on 2026-09-15:

- initial network start **02:40:31**, ready **02:41:08** (~36.5s);
- Local Create **02:41:37–02:43:39**, **122s**, first attempt;
- Install **02:43:43–02:47:33**, **230s**, one HTTP 504 followed by exact
  retained-request resume;
- actor-role grant **02:47:33–02:48:20**, **47s**, applied and retired;
- first slice **02:48:20–02:51:32**, **192.17s**, helper passed and retained
  cooperative Yielded sequence **1**, nonce `0x80`, with no progress past it.

The daemon recorded an initial management replay-headroom exhaustion at
**02:51:06.988**, applied slots **110**, remaining slots **3986**, one pending
member and no retiring pairs; checkpoint admission recovered within the
successful first-slice workflow. These timings are not acceptable production
latency evidence. Logs: `first-yield-timing.log`, `create-1.json`,
`install-{1,2}.{json,log}`, `grant-1.json`, `first-slice-1.log`, `up-1.log`.
Exact first-yield paths/sequence are in `yield-fixed-first-slice.json`.

SIGTERM was sent at **02:51:52 UTC** to PID **3762847**. The down command's
five-second observation expired, but the original foreground handle exited
**0** without force. A second daemon was started with `up-2.log` to test
actual continuation recovery. Resume, positive retirement, final value 111,
second restart, and live terminal-failure retirement remain unproved at this
checkpoint. The old `.hJuDDq` negative CIP1 and reservation are untouched.

### Native compiled-yield continuation after restart (C2)

The `.lU4S5Z` daemon restarted at **02:52:43 UTC** and became ready at
**02:54:07 UTC** on 2026-09-15 (~84.6s). The normal retained-client helper
`disposable_yield_resume_and_retire` then passed in **3.20s** (`resume-1.log`).
It verified exactly two Resume exchanges followed by ACK: second cooperative
yield sequence **2**, terminal Done with decoded value **111**, positive
retirement, and cached exact retry of the same authorization/application.
The original invocation nonce `0x80` and AuthorityReceipt remained unchanged.
This is the actual compiled actor running through native ingress after a
real daemon restart, not the synthetic continuation fixture.

Graceful shutdown was requested at **02:55:07 UTC** for PID **3780176**.
Again the down command's five-second observation expired, while the original
daemon handle exited **0** without force (`down-2.log`). A third start in
`up-3.log` is for the final fresh LocalQuery after another actual restart;
that query and live terminal-failure retirement are not yet proved here.

### Native compiled-yield final state verified (C2 live scenario passed)

The third `.lU4S5Z` start ran from **02:55:56 to 02:58:05 UTC** on
2026-09-15 (~129.1s). The fresh `0x81` LocalQuery through normal preparation,
invocation and acknowledgement passed in **116.80s**:
`value-after-restart-1.log` confirms decoded value **111** and positive
retirement. Together with the first-yield and resume checks above, this
proves the protected compiled Local actor's two cooperative yields, recovery
after a real restart, final completion, exact retirement/cached retry, and
durable final state after a second real restart. This specific live C2
scenario is passed; it is not a general lifecycle or production release pass.

Live terminal-failure retirement still needs a fresh failure on the new
runtime (the old `.hJuDDq` negative acknowledgement cannot be overwritten).
Typed errors, expiry/abort/mixed pending recovery, ordinary Shared finality,
Private/Attested and original release checks remain separate. Observed
Create/Install/first-invocation/query/replay latency remains a release concern.

At this handoff the **third disposable daemon is intentionally still running**
for the next failure-retirement campaign, avoiding an unnecessary replay.
Its foreground process handle is **25034**, with `up-3.log`; the first-yield
campaign and both follow-up helper handles are terminal and successful. No
new client invocation is pending from the successful yield/query scenario.
The wrapper is `task-tmp/admin-startup-smoke.lU4S5Z/cli.sh`, using isolated
XDG paths and disk scratch. Revalidate that handle/readiness before proceeding;
do not launch another daemon while this one is active. These evidence notes
remain uncommitted pending the related native failure result.

### Native Panicked-result retirement after restart (C2 live gap closed)

Reused the running `.lU4S5Z` disposable space with a separate actor
`7ec877c35afbb24b660dd7b9c2cc0f02a5dc821917992ad002320c7ab2dc0492`.
The known failing package was copied byte-identically from `.hJuDDq` without
editing its source evidence; its program is `5a18bc74…` and deployment
`747b21b0…`. This deliberately reproduces the old actor-side panic on the
**new runtime**, rather than migrating or repairing the old space.

UTC timings on 2026-09-15 (`failure-timing.log`): Install
**03:04:07–03:06:31** (**144s**, first attempt), role grant
**03:06:31–03:07:05** (**34s**, applied/retired), fresh nonce `0x78`
invocation **03:07:05–03:09:35** (**150.25s**). Inspection of
`failure-first-slice.log` confirmed the exact retained Direct
`Completed(Ok(InvocationReply { status: Panicked, ... }))`, empty reply,
gas remaining **999878404**, and no committed observation. The yield helper
intentionally failed its Yielded assertion; that failure is not reported as
a passing test or a transport failure.

Graceful shutdown was requested at **03:10:02 UTC** for PID **3783919**;
the down command's five-second observation expired, but the original daemon
exited **0** without force (`down-3.log`). Actual restart ran
**03:11:30–03:15:06 UTC** (~**216.8s**, `up-4.log`). Only after readiness,
`disposable_yield_retire_failed_first_slice` passed in **1.20s**
(`failure-retirement-1.log`): it verified the exact original program,
deployment, invocation and Panicked reply, preserved the original request
and response bytes, and obtained positive retirement through normal managed
continuation. `yield-failed-retired.json` records its exact store paths.

A subsequent normal `space invoke-local --resume --format json` returned
`decision=issued`, `decision_retained=true`, **`delivery_retired=true`** and
**`reservation_pending=false`** (`failure-cached-retry.json`). Thus the
new runtime fixes the observed Panicked-result/NotFound retirement defect
across native restart. The old `.hJuDDq` negative CIP1 and reservation remain
unchanged; this is not evidence that they were repaired.

Final shutdown was requested at **03:16:50 UTC** for PID **3804562**;
both the normal down command and original foreground handle exited **0**
without force (`down-4.log`). All campaign and daemon handles are terminal.
This supersedes the earlier running-daemon handoff. No production source or
artifact changed during these live campaigns; only this C2 evidence/closeout
summary changed. Typed errors still lack a general retained-error retirement
path, and the original expiry/abort/mixed-pending, profile/finality and release
gates remain open. Multi-minute fresh-work/replay latency remains unacceptable.

### Typed-error split: retryable client rejection versus durable runtime result (C2)

Tracing typed errors exposed two different paths. `InvocationError` already
classifies structurally admitted durable outcomes via
`is_durable_exact_outcome`. Non-durable errors such as ResultCapacity leave
runtime work unconsumed, but the client previously froze their response and
then constructed an ACK. The client now checks the verified outcome before
publishing an initial ASR1 or filling a pending Resume response: non-durable
rejection leaves the exact request pending and returns an error. It does not
reprepare, generate another invocation, advance to ACK, or clear historical
response/progress files. Existing poisoned historical responses are preserved
and refused for ACK; they are not silently repaired. Negative ACK records
keep their existing immutable behavior.

Loopback HTTP tests now inject a bound ResultCapacity reply, then prove the
same retained Invoke/Resume bytes are retried successfully. Resume progress
remains byte-identical across both transport failure and capacity rejection.
A separate historical-response test proves no ACK step is created and no
existing bytes are replaced. Validation: `typed-error-client-invoke.log`
**1 passed**; `typed-error-client-cli.log` **253 passed, 0 failed, 17 ignored**
in **66.12s**; final continuation checks after an error-message clarification
in `typed-error-client-resume.log` **4 passed**, **0.15s**; normal CLI build
`typed-error-client-build.log` passes in **11.84s**. All logs use disk-backed
task-tmp. Formatting/whitespace checks pass; no daemon was started.

**Durable typed errors remain broken, with executable evidence.** Two new
compiled-bundled-runtime regressions exercise InvalidActorOutput (after an
attempted actor write) and StaleIncarnation (before actor execution). Both
verify their expected error, full physical/source transition equality,
unchanged actor state and canonical restore, then require exact positive
ACK. Both fail with **`Acknowledged(Err(NotFound))`**:
`typed-error-runtime-red.log`, **0 passed, 2 failed**, **0.52s**. They are
explicitly marked ignored known C2 gaps so they are not mistaken for ordinary
passing tests; they **must pass and be unignored before release**:

```sh
cargo test --offline --locked -p vos --lib --features pvm,private-agent-store,http-ingress bundled_typed_error_ -- --ignored --nocapture --test-threads=1
```

Next within this C2 batch: retain an actual typed-error record with original
accepted work/authorization and storage scope, rather than fabricate an actor
reply. Cover unresolved/stale targets as well as failures after execution.
Recovery and ACK must use that exact binding without requiring the now-invalid
actor incarnation to become live again. Include errors in result capacity,
lifecycle debt, continuation consumption and positive-ACK mutual exclusion;
retain rollback and reject non-durable errors from terminal storage. Wire the
versioned state encoding, guest finalizers and native exact-error successor
verifier together, then reproduce/repin and run the two red gates plus existing
success/yield/Panicked regressions. No runtime artifact changed in this step;
client changes and these diagnostics remain uncommitted for the scoped batch.

### Typed-error ledger foundation checkpoint (C2, dispatch still pending)

The same C2 change now includes a private, canonical `SCER` v1 section for
authenticated durable invocation errors. Empty ledgers add no wire bytes.
Records bind the exact accepted work, authorization, and observed slot without
inventing a successful actor reply or requiring the failed target to exist.
Restore rejects malformed, duplicate, wrong-lane, and overlapping records.
Errors share the existing reply count/byte limits and participate in actor
lifecycle debt and runtime capability-change checks. Retention and positive
acknowledgement are atomic; failed admission preserves the original state.

Validation: the runtime wire group passed **78 tests, 0 failed, 3 ignored**
(`target/task-tmp/typed-error-ledger-wire.log` in the shared C2 target). New tests
cover control/Linear round trips, stale-target retirement after restore, exact
retry and divergence, positive ACK replay, combined capacity, resumed
continuation consumption, and noncanonical sections. The ignored bundled
typed-error regressions remain open release gates, not waived tests.
The normal `vosx` feature path also passed `cargo check --offline --locked -p
vosx --bin vosx` (13.76 s, warnings reported); formatting and diff checks passed.

This is a foundation checkpoint, **not end-to-end completion**: Invoke/Resume
dispatch and the native typed-error successor verifier still use the old
clock-only error path. Next, connect both to the ledger in this same C2 review
batch, run the source/native regression tests, then reproduce and pin a runtime
that passes the compiled typed-error retirement regressions. No runtime artifact
or ABI pin changed at this checkpoint. Multi-minute startup/Create/Install
latency and the previously listed finality/recovery/release gates remain open;
no timeout increase or production-readiness claim is implied.

### Typed-error dispatch and native verification checkpoint (C2)

Superseding the foundation-only checkpoint above, clean Invoke now recovers an
exact retained error before current actor lookup, retains authenticated durable
target errors from preflight, and retains durable execution errors on pristine
state. Resume terminal errors consume the exact continuation in that same
retention transaction. Native verification independently derives the retained
successor (including exact recovery), rejects clock-only/forged successors, and
checks the claimed typed error against the retained one. Positive ACK after
restore works for invalid actor output and stale incarnation in source dispatch.

Tests exposed and corrected two ordering issues: stale-target preflight returned
before retention, and route-policy rejection was incorrectly considered a fresh
actor outcome. Early retention is now limited to target-resolution errors; it
does not overwrite an existing attested result with a Direct-route rejection.

Validation on the final source of this checkpoint:

- Runtime wire tests: **79 passed, 0 failed, 3 ignored**, 21.17 s,
  `typed-error-dispatch-wire-verified.log` in shared C2 `target/task-tmp`.
- Native typed-error/hostile-successor/terminal-failure tests: **4 passed**,
  `typed-error-dispatch-native-tests.log`.
- Focused typed-error tests before the final policy-boundary adjustment:
  **6 passed, 2 bundled tests ignored**, `typed-error-dispatch-resume.log`.
- Normal CLI feature-path compile check passed (14.51 s, warnings),
  `typed-error-dispatch-native-final.log`; formatting and diff checks passed.

Still pending in this same uncommitted C2 batch: audit the policy-rejection
classification (`UnsupportedMethod` is also used for missing attestation, which
must not become a falsely durable client outcome), the remaining pre-admission
and resumed-target boundaries, then physical guest/native tests and reproducible
artifact pinning. **The bundled runtime remains unchanged and does not contain
the source fix.** Its two ignored typed-error regressions are still release
gates. Do not deploy this intermediate source/artifact combination as a completed
fix. Latency, finality, recovery/profile coverage, and final release gates remain
open exactly as previously recorded; root `saga/agents` and master are untouched.

### Attestation admission versus durable method rejection (C2)

The policy-classification gap from the preceding checkpoint is now corrected in
source. `authorize_clean_execution_with_proof` returns non-durable
`InvalidAuthorization` for missing, unexpected, or mismatched attestation;
`UnsupportedMethod` remains the durable error for an unsupported method/mode.
Invoke can therefore retain genuine durable preflight errors without mistaking
a wrong proof route for a completed actor result. No ABI variant was added.

The existing attested Invoke and Resume restart tests now assert both the
non-durable rejection and byte-identical runtime state, preserving the completed
result or pending continuation for the authenticated route. The AMP2 None-method
test rejects an unexpected attested route with `InvalidAuthorization`. A new
unsupported-method test verifies error retention, unchanged actor state, restore,
and positive ACK.

Validation (shared C2 `target/task-tmp`):

- `typed-error-policy-wire.log`: **79 passed, 0 failed, 3 ignored**, 20.98 s.
- `typed-error-unsupported-method.log`: new regression **1 passed**.
- `typed-error-policy-native-tests.log`: native successor tests **4 passed**.
- `typed-error-policy-native-check.log`: normal CLI `cargo check` passed,
  16.29 s (warnings); formatting and diff checks passed.

This supersedes the preceding policy-classification TODO, not the remaining
release gates. Next: finish the pre-admission/resumed-target audit, verify guest
feature/build compatibility, freeze the source, reproduce the runtime twice,
and pass the compiled typed-error regressions before pinning. The source batch
is still uncommitted and the bundled runtime unchanged. No timeout or latency
gate has been relaxed; production readiness remains unproven.

### Typed-error candidate passes physical retirement (C2 source freeze)

The remaining cooperative-Resume payload boundary now returns non-durable
`StaleContinuation`, not durable `InvalidInput`: an external Ready/Failed payload
does not match the supported saved continuation. The existing validation matrix
asserts unchanged state and non-durable classification for every rejected resume.
Native entry already rejects these payloads before execution. Restored standard
continuations require an existing, unsuspended actor with the exact incarnation,
deployment, program and lane; stale/deleted resumed targets are rejected at
restore, not admitted through a permissive host preflight.

Guest compilation passed with locked offline nightly-2026-03-20 (12.93 s,
`typed-error-guest-build-final.log`). A candidate converted with the frozen
42f3f3bf host builder is stored in shared C2
`target/task-tmp/runtime-typed-error-candidate.Wzrzuj/agent-runtime.pvm`:

- ProgramId: `0084d2f44458bd730e41dfeb40cee0e067ad4be4c33aa4659ba84dcfdae9b1ed`.
- PVM BLAKE2b-256: `ba22d85015db112b4c959c61d866e249f31405c76bf0c187a0bda6bdb9889958`.
- Both explicitly invoked compiled typed-error retirement regressions passed
  (2/2, 0.56 s), `physical-retirement.log`. The candidate hook is
  `VOS_AGENT_RUNTIME_TYPED_ERROR_CANDIDATE`; without it tests use the bundled blob.
- Broader wire/native tests passed **84/84, 3 ignored**, 21.43 s,
  `source-native-wire.log`, including the physical terminal-failure lifecycle
  with `VOS_AGENT_RUNTIME_FAILURE_CANDIDATE` pointing at this candidate.
- Resume admission regression passed; normal CLI compile check passed (4.77 s,
  warnings), `typed-error-admission-native-check.log`. Formatting/diff checks pass.

This proves the candidate fix, **not reproducibility or release readiness**.
Freeze this C2 source as one scoped commit, then independently rebuild it twice,
compare ELF/PVM bytes and identities, pin the reproduced runtime, and enable the
two bundled regressions normally. The current bundled blob/manifest are unchanged;
the ignored bundled gates must not be counted as passing for the shipped artifact.
No old retained negative acknowledgement was edited. Existing latency, finality,
recovery/profile and final integration/release gates remain open.

### Reproduced typed-error runtime pinned and regressions enabled (C2)

The runtime from immutable source `373d2520e50b1ebbd7ba2c6746515fcc977ca64f`
was independently built twice in isolated source/target/tmp directories by
`runtime-typed-error-candidate.Wzrzuj/reproduce.sh` under shared C2
`target/task-tmp`. The process completed successfully: both ELF files match,
both PVM files match, and the reproduced PVM matches the physically tested
candidate. No `/tmp` RAMFS build directory was used.

Pinned `vosx/blobs/agent_runtime.pvm` is **981474 bytes**:

- ProgramId `0084d2f44458bd730e41dfeb40cee0e067ad4be4c33aa4659ba84dcfdae9b1ed`.
- ELF BLAKE2b-256 `9ad799e6e5313f3b3fc215b50c3e58684c0349687c9cb7c44cffcbe965685b4e`.
- PVM BLAKE2b-256 `ba22d85015db112b4c959c61d866e249f31405c76bf0c187a0bda6bdb9889958`.

The manifest source/identity/digests, native standard-runtime ProgramId, CLI
build-time digest, and bundled PVM were updated together. Both formerly ignored
typed-error retirement regressions now run normally against the bundled artifact.
The SDK ABI identity and system template pins are unchanged.

Post-pin checks, without candidate overrides (logs in shared C2 `target/task-tmp`):

- `typed-error-pinned-wire-bundled.log`: **5 passed, 0 ignored**, 8.99 s,
  including invalid-output and stale-target positive retirement after restore.
- `typed-error-pinned-bundled.log`: broader physical authority/management and
  bundled tests **9 passed, 1 ignored profiling probe**, 115.09 s.
- `typed-error-pinned-cli.log`: **253 passed, 17 ignored**, 83.75 s.
- `typed-error-pinned-clean-break.log`: normal CLI build and retained/negative
  CLI-surface check passed; formatting/diff checks passed.

The source/artifact mismatch is closed for this C2 fix. This is not a claim that
all CLI ignores or release gates are satisfied. Live typed-error coverage,
expiry/abort/mixed-pending recovery, production latency, Shared finality,
Private/Attested and cross-runtime lifecycle coverage, and final C1/C2/C3
integration/release checks remain open. Old immutable negative-ACK fixtures are
untouched, no daemon was started, and root `saga/agents`/master were not changed.

### Repeatable native issuance latency probe (C2, no optimization claimed)

After pin `690df3de`, the existing physical test
`native_operation_approved_issuance_reopens_without_new_signatures` was profiled
in isolation, without a live disposable-space daemon or concurrent build.
Both runs passed against the newly bundled runtime. This provides a smaller
repeatable native recovery/retirement workload than the multi-minute live flow;
it does not reproduce equivalent live history or establish production timing.

- CPU-clock sampling at 99 Hz with 16 KiB DWARF stack snapshots: 20.02 s test,
  1703 samples, 27.109 MB on disk. BLAKE2 compression: **43.10% self**;
  interpreter loop: **10.75% self**.
- Repeat at 49 Hz with 65528-byte snapshots: 20.17 s test, 846 samples,
  52.971 MB on disk. BLAKE2: **43.50% self**; interpreter: **10.64% self**.
- Neither DWARF capture reliably unwound the hashing callers. Increasing the
  captured stack did not solve attribution. Do not interpret self samples as
  proof that a particular validation/replay layer is redundant.

Evidence is under shared C2 `target/task-tmp`, prefix
`typed-runtime-native-issuance` (`.perf`, `-profile.log`, `-self.txt`,
`-callers.txt`, `-stacks.txt`, and `-wide.*`/`-wide-callers.txt`). No `/tmp`
RAMFS scratch was used; both profiler processes finished. Source/runtime
behavior and pins are unchanged. Next latency step: obtain reliable caller
attribution with an instrumented host build or bounded test-only hashing
counters; repeating these same failed unwind settings is not useful. No
validation bypass, timeout increase, or latency-gate waiver is justified.

### Bounded host hashing counters (C2 latency attribution)

Opt-in test-only counters now cover `vos::crypto::blake2b_hash`, with source
caller propagation through the host `Hash::digest` wrapper. The native issuance
fixture enables them only with `VOS_TEST_HASH_PROFILE=1`. At most 128 domain/site
rows are retained; output contains time, calls, byte totals and source locations,
not hash payloads or digests. Production/guest code excludes these counters.

The existing native issuance/reopen/retirement test passed with instrumentation
(21.92 s). It recorded **53 rows, 41223 calls, 1620806767 bytes, 1.208 s** of
hash-wrapper time, so the row cap was not reached. Largest measured callers:

- Journal ordered-entry content IDs: 1607 calls, 865196157 bytes, 0.643 s.
- Raft physical-slot verification: 2679 calls, 389741136 bytes, 0.289 s.
- Artifact-batch chunk validation: 3636 calls, 158816806 bytes, 0.117 s.
- Journal replay-input content IDs: 313 calls, 116815173 bytes, 0.087 s.

Evidence: shared C2 `target/task-tmp/native-issuance-hash-counters.log`.
Crypto reference tests pass **8/8** (`native-hash-counter-crypto-tests.log`).
These are attribution measurements, not a latency improvement. The counters
do **not** cover the separate `vos-protocol`/SDK digest implementation or direct
SIMD users; 1.208 s of timed host wrappers does not account for the earlier
43% CPU hotspot. Next, attribute that remaining path before choosing a change.
Repeated journal/slot verification is measured, not proven redundant: preserve
all persisted-data validation until equivalent correctness is demonstrated.
No runtime artifact, timeout, or release gate changed.

### Protocol hashing attribution identifies repeated RuntimeBlob validation (C2)

An explicitly selected temporary `vos-protocol/hash-profile` diagnostic adds
per-thread, capped domain/site counters and caller propagation through protocol
blob identities. It is disabled by default, not enabled in guest/release builds,
and remains uncommitted diagnostic work. No payload bytes or digests are logged.
The same native issuance/reopen/retirement test passed (21.31 s), with both host
and protocol counters enabled. Evidence: shared C2
`target/task-tmp/native-issuance-protocol-hash-counters.log`.

Aggregating protocol rows by caller identifies the dominant path:

- `RuntimeBlob::validate` (`vos-agent-sdk/src/runtime.rs:85`): **44877 calls,
  8550121362 bytes, 6.270 s**.
- Owned package-artifact validation: 4717 calls, 291170761 bytes, 0.219 s.
- Program identity: 659 calls, 99219892 bytes, 0.075 s.
- Package decoder's borrowed-artifact hash check: 825 calls, 45977905 bytes,
  0.036 s. Its subsequent owned-copy revalidation is not the primary hotspot.

This accounts for the previously unattributed hashing cost without guessing a
caller from broken perf stacks. It does not yet identify which higher-level
validators repeatedly invoke `RuntimeBlob::validate`, nor prove that any check
can be removed. Next: propagate attribution through availability/work validation
and isolate duplicate verification within one immutable boundary. Preserve
verification at untrusted-byte boundaries; do not replace it with a global
cache. The temporary diagnostic must be removed or deliberately finalized before
release. No runtime pin, production behavior, timeout or latency gate changed.

### Single-pass journal runtime-work round-trip validation (C2 latency)

Caller propagation through availability/work validation identified SDK encoding
validation as the main measured blob-hashing layer: Invoke encoding hashed
5761172792 bytes (30152 blob calls, 4.225 s), ACK encoding 1143368864 bytes
(5984 calls, 0.842 s). The diagnostic native test passed in 21.60 s; evidence:
shared C2 `target/task-tmp/native-issuance-work-hash-counters.log`.

The journal decoder had a concrete duplicate pass: after SDK decoding had
fully validated a runtime-work value and its blob preimages, its canonical
round-trip check called SDK `encode`, which validated those same bytes again.
A private helper now decodes once and immediately re-encodes that untouched
owned value's body with the exact SDK header. The full byte-for-byte comparison
remains; constructed or mutated work still uses the normal validating encoder.
The helper handles the four clean journal tags without caching across calls or
skipping validation of persisted input.

The same instrumented native test passes after the change (21.37 s). Invoke
encoding drops to 5286552428 hashed bytes/27668 blob calls; ACK encoding drops
to 1014969152 bytes/5312 calls. This eliminates **603020076 hashed bytes and
3156 blob checks** from that workload. The wall-time difference is too small
for a production speedup claim. Evidence: `native-issuance-single-pass-journal.log`.

All temporary protocol/SDK features, profiling modules, host counters and caller
annotations were removed after measurement. The diagnostic source file was
deleted; the logs and measured inputs remain under disk-backed target. The
retained implementation change is only in `vos/src/agent/journal.rs`, with
regressions checking positive Invoke/ACK round trips and rejection of changed
blob bytes, trailing bytes and truncation. Journal tests pass **39/39**
(`single-pass-journal-tests.log`); normal CLI compile check passes (29.30 s,
warnings, `single-pass-journal-native-check.log`). No artifact pin or timeout
changed. The native issuance/reopen/retirement test also passes without any
diagnostic feature (20.10 s, `single-pass-journal-native-test.log`).
Most repeated runtime-work encoding validation remains to be addressed;
this reduction does not close the multi-minute production-latency gate.

### Borrowed journal authorization validation (C2)

`validate_clean_invocation_authorization` no longer clones an entire work item
and serializes an empty-state Direct Invoke solely to test whether encoding
succeeds. It calls the same SDK work-validity and authorization-binding
predicates on borrowed inputs, retaining runtime identity checks. All blob
preimages are still authenticated. A compile-time conservative bound covers
the bounded message, blob-reference framing, authorization and fixed fields
inside the SDK work envelope limit; actual journal encoding remains checked.

An equivalence regression compares the new predicate with the previous SDK
encoder-based result for both PublicPreflight and AuthorityReceipt, including
zero gas/identity, oversized messages, valid/altered/duplicate blobs,
maximum aggregate availability, and early observation slots.

Validation (shared C2 `target/task-tmp`):

- `borrowed-journal-authorization-tests.log`: **40 passed**, 0 failed, 0 ignored.
- `borrowed-journal-authorization-native-test.log`: native issuance/reopen/
  retirement test passed (19.98 s), without diagnostic features.
- `borrowed-journal-authorization-native-check.log`: normal CLI compile passed
  (4.71 s, warnings); formatting/diff checks passed.
- The pre-change same-test run passed in 19.84 s
  (`journal-authorization-baseline.log`). These timings do **not** demonstrate
  a wall-time improvement. The established reduction is removal of payload
  clones and temporary serialized buffers, not fewer blob authentications.

No artifact, timeout, or release gate changed. The production latency blocker
remains; further work must address the larger repeated validation boundaries,
not infer an end-to-end gain from this allocation-only change.

### ReplayInput size pass reuses its invocation validation (C2)

`ReplayInput::validate` previously authenticated its clean invocation inside
`validate_inner`, then invoked the ordinary encoder to measure size, hashing
the same preimages again. The size pass now calls a private encoder path that
reuses the completed Invoke validation while the same input is immutably
borrowed. It still serializes the complete record and enforces both nested SDK
and complete journal byte limits. Ordinary public encoding passes the normal
validation flag; persisted decoding still authenticates every incoming blob.
CleanManage, ACK and yielded-selector encoding retain their existing checks.
There is no cache or validation fact surviving mutation or a later call.

A six-mode regression compares the optimized bytes with ordinary encoding and
then mutates a blob to require rejection on the next validation. All **42**
selected tests pass (41 journal tests plus native issuance/reopen/retirement),
zero failed/ignored, 19.96 s; evidence is shared C2
`target/task-tmp/journal-size-single-pass-final.log`. Normal CLI compile check
passes (5.78 s, warnings, `journal-size-single-pass-native-check.log`), along with
formatting/diff checks. No diagnostic feature or runtime pin changed.

This removes a redundant hash pass by construction, but the overall native
test timing remains around 20 s: **no production latency improvement is proven**.
The multi-minute live workflows and the remaining finality/recovery/release
gates remain open. Avoid interpreting these narrowly passing tests as a fresh
live campaign or a completed final release matrix.

### Expiry recovery boundary audit (C2, abort remains unimplemented)

Two new regression boundaries distinguish exact historical recovery from fresh
application after expiry:

- Coordinator approval followed by a receipt-signing or acknowledgement-signing
  failure is reopened from retained stores. Changing its issuance slot to
  `requested_expires_at + 1` is rejected without changing either store, commit
  counts, dispatch counts or signer counts. A successor remains blocked by the
  pending operation. Recovery with the original immutable tuple succeeds, and
  another reopen returns identical evidence without signing/dispatching again.
  This is a coordinator/fake-dispatch test, **not** fresh application of an
  expired receipt or an authenticated advance of the live clock.
- The actual bundled runtime receives a previously unseen invocation observed
  after the signed receipt expiry. It returns non-durable `AuthorityExpired`
  with byte-identical state, both initially and after canonical restore. It
  retains neither an actor reply nor a typed-error outcome. Full guest output
  matches source dispatch; it cannot be counted as terminal delivery.

The bounded coordinator/compiled-expiry group passes **25 tests, zero failures**
in 3.12 s (`post-approval-expiry-bounded.log`, under shared C2 `target/task-tmp`).
The original 26-test run was deliberately interrupted after more than ten
minutes of active CPU in the 256-record capacity case; its log is preserved as
`post-approval-expiry-and-runtime.log`. The bounded rerun explicitly excludes
that case. Capacity was deferred, not passed or waived at that checkpoint;
the later "Full coordinator retention capacity verified in release mode"
checkpoint records its eventual full-size pass. No production behavior,
artifact or timeout changed.

The outstanding gate is still **post-issuance expiry/abort resolution**. SDK
issuance retirement evidence is not proof of application retirement, and the
system authority's pending-application checks must not be bypassed. Closing this
requires a durable, authenticated terminal resolution bound to the exact work,
proof that subsequent application cannot occur, and native/client recovery that
releases the reservation only after that resolution is retained and verified.
An expired rejection, deleting a store, or reusing a fresh issuance slot is not
such evidence. Live expiry/abort and mixed-pending gates remain open.

The historical-response regression now covers `AuthorityExpired`,
`InvalidAuthorization` and `StaleContinuation` alongside `ResultCapacity`.
Each preserves the exact stored request/response and refuses to create an ACK
progress step. The targeted CLI test passes (0.04 s), evidence in shared C2
`target/task-tmp/expiry-client-preservation.log`. This does not turn any of those
non-durable rejections into completed delivery or authorize reservation release.

Tracing the native completion path confirms NOC1 certifies the Authority's
authorization/issuance result pair, not application retirement. The current SDK
has Invoke/Resume/Acknowledge/Manage but no terminal abort/expiry work outcome.
Runtime ACK requires a retained result; client retirement requires a positive
bound ACK. These protections must remain intact.

Continue with the durable expiry/abort resolution described above, inside C2;
do not open another optimization or review batch. These source tests are not
that missing implementation. Post-issuance expiry/abort, mixed-pending, finality
and production latency remain release blockers. All test processes from this
checkpoint are stopped; no daemon was started and no artifact repin is needed.

### Durable expiry fence primitive (C2, delivery wiring remains open)

SDK `ExpiredBeforeExecution` now has its own canonical error tag (20), distinct
from non-durable `AuthorityExpired`. Standard-runtime retention validates the
signed exact-work receipt, requires a strictly post-expiry, non-regressing slot,
and refuses an existing result, acknowledgement or continuation. It shares the
bounded error ledger and never accepts actor writes. Restore validates the
post-expiry window for this error only; ordinary result/error acceptance still
requires a live receipt. Exact positive acknowledgement retires the fence.
The native verifier independently reconstructs and compares the entire successor,
rejecting unchanged state, substituted outcomes and extra state writes.

Validation: **11 targeted native/source/retention regressions passed** (1.32 s),
**165 SDK tests passed**, and CLI `cargo check` passed (15.52 s). Logs in shared
C2 `target/task-tmp`: `expiry-fence-native-regressions.log`,
`expiry-fence-sdk.log`, `expiry-fence-cli-check.log`. The initial restore test
failed because the binding decoder required a live receipt; the corrected
decoder preserves that requirement for ordinary results and validates expiry
fences separately. The final run above covers this correction.

This is a retention/verification primitive, **not** a live expiry-resolution pass.
Runtime Invoke still emits the existing non-durable expiry rejection; the current
bundle is unchanged and the physical regression confirms that behavior. Next,
connect authenticated native expiry delivery to this fence while preserving
recovery of already accepted work, then verify positive application retirement
before releasing the credential. ABI/schema audit, rebuilt/reproduced bundles,
management expiry, pre-expiry abort and live recovery remain required. Keep this
inside C2; do not treat the wire extension as a completed release cutover.

### Runtime expiry delivery (C2 source cutover)

Invoke now retains `ExpiredBeforeExecution` after signature/exact-work validation
when its signed receipt has expired and no result or continuation exists.
Existing retained outcomes recover first; existing actor replies/continuations
continue through their prior recovery paths. Actor proof/execution admission is
not needed to retain authenticated non-execution. Failure to retain, including
clock/capacity rejection, returns the original state. The runtime never resets
the invocation identity or changes actor state to resolve expiry.

The source lifecycle test exercises first delivery, exact retry, restore,
positive ACK and an old-slot Invoke after retirement. **16 source/native/error
and terminal-failure regressions passed**, 1.41 s, in shared C2
`target/task-tmp/expiry-delivery-source-final.log`. Its first assertion incorrectly
compared the authority clock as an actor revision; the corrected test asserts
unchanged actor lane bytes and linear/merge/local revision counters, while the
result clock advances as required. No production timeout changed.

The same lifecycle helper compares all guest output bytes with source using
`VOS_AGENT_RUNTIME_EXPIRY_CANDIDATE`, defaulting to the bundled runtime when no
candidate is specified. The old pin is deliberately not counted as passing this
new expectation. Independently reproduce/pin only after the remaining native
delivery/retirement checks.
Management expiry and pre-expiry abort remain separate unfinished original gates.

Candidate compiled from immutable source `e2a959354b613e3b60c30a9f50ca107ee0b56302`
using guest `nightly-2026-03-20` and the existing frozen `42f3f3bf` converter.
Evidence is in shared C2 `target/task-tmp/runtime-expiry-candidate.0bMrdx`:

- ProgramId `e83dda7dcbd3d5ca1827a1f7d70bb43ea0b930d497fc868024bf3e586627fd5c`;
  PVM size 983,895 bytes.
- ELF BLAKE2b-256 `f0c81c6ca300cdeaedf179cf2c1e79d22387a90071418127324f5b91a5b42632`;
  PVM BLAKE2b-256 `d0f03ebfec60e063ecbe86729dc362c164d3fa2f416593fe9d16aa9f4aa4eafe`.
- `physical-expiry.log`: **one passed**, 0.49 s, comparing full source/guest
  outputs for expiry, exact retry, restore, positive ACK and old-slot late Invoke.
- `physical-regressions.log`: **four passed**, 3.31 s, additionally covering the
  candidate's existing typed-error and terminal-failure lifecycle exchanges.

This is one isolated candidate build, not independent reproduction or a repin.
`build.sh`, source export, ELF/PVM and logs are retained on disk, not `/tmp`.

The managed-client reservation fixture now covers the expiry result through
delivery timeout, ACK timeout, exact positive ACK, offline completion replay and
successor reservation. A separate negative-ACK case proves the credential stays
pending and the saved request/response/progress remain identical on offline retry.
An initial test incorrectly expected a retained negative ACK to be overwritten;
the corrected test preserves that evidence and does not change client behavior.
**Three client tests passed**, 6.84 s, in shared C2
`target/task-tmp/expiry-delivery-client-preservation.log`. These use signed
issuance and scripted loopback HTTP, not a live daemon or a live clock advance.
The physical guest and client checks are complementary boundaries, not a single
end-to-end native expiry campaign. Live verification and final pinning remain open.

### Native expiry admission and candidate reproduction (C2)

Native `invoke_sdk` now captures its trusted logical slot before standard-runtime
preflight. For a structurally valid expired signed invocation, preflight verifies
the exact receipt/signature and lets the guest resolve non-execution without
requiring executable actor availability. Live-work availability rejection is
unchanged. Preflight does not mutate state or declare completion; the guest and
the native exact-successor verifier still enforce retention/clock/capacity rules.

The new host regression rejects unavailable live work and forged expired
receipts, allows the authenticated expired request, and verifies the source's
exact fence while rejecting an unchanged successor. The source/physical lifecycle
helper now covers both complete and missing availability through expiry, retry,
restore, positive ACK and late Invoke. **Five tests passed**, 1.17 s, in shared
C2 `target/task-tmp/expiry-native-preflight-physical.log`, using the independent
candidate copy. This is not a live daemon/trusted-clock campaign.
CLI `cargo check` also passed (5.14 s); evidence is
`target/task-tmp/expiry-native-preflight-cli-check.log` under shared C2.

The candidate's second isolated export/build of immutable `e2a95935` completed
successfully. Both ELF and PVM compare byte-identical with the first clean build;
the identities above are unchanged. Script/log/artifacts:
`target/task-tmp/runtime-expiry-candidate.0bMrdx/reproduce.sh`,
`reproduction.log` and `reproduction/`. All scratch remains on disk.

ABI audit: `vos-agent-sdk/src/contract.rs::CONTROL_SCHEMA_DESCRIPTOR` is the SDK
ABI identity itself; package/schema decoders also bind that identity. The new
canonical outcome tag changes the accepted runtime wire grammar. Therefore the
next artifact cutover must advance the clean ABI/schema identity and rebuild the
runtime plus affected system actor templates with matching tooling. The reproduced
r16 candidate proves the implementation, not that release cutover. Preserve old
fixtures; do not migrate/relabel them or claim the old bundle handles expiry.

### r17 ABI source cutover (artifact rebuild pending)

The SDK ABI is now `vos-agent-runtime-abi-260915-r17`; the corresponding
control schema is `8f7633be7ce92ce465f98ad1f4276b6d13bba987ba4c27c335bac560eb172b48`.
The schema hash test checks the constant against its ABI descriptor. Canonical
expiry-outcome coverage explicitly rejects an r16 header. Fifteen fixed golden
commitments across Authority, Catalog, invocation context and proof/public-I/O
fixtures were regenerated for the new ABI; bounds, round trips and mutation
rejection assertions remain intact. **All 165 SDK tests passed** in shared C2
`target/task-tmp/r17-sdk-goldens-3.log`. Earlier logs retain the expected stale
golden failures rather than hiding them.

Freeze this source for the r17 builder, runtime and system templates, then build
and independently reproduce matching artifacts before updating release pins.
Old r16 fixtures stay untouched. The current source/committed-blob mismatch is
an explicit intermediate cutover state, not a deployable build or a gate waiver.

### r17 runtime and system-template pin

Runtime, system-authority and system-catalog bundles now use immutable source
`5bbab66b98b2e26cf0e57ccc964c17687c66e8ca`, with a matching frozen vosx builder,
host `nightly-2025-05-09` and guest `nightly-2026-03-20`. Two independent source
exports and clean guest builds produced byte-identical runtime ELF/PVM and both
signed system templates. Public template signing remains non-authoritative;
spaces re-sign with their actual root. No operator identity or old space changed.

Runtime ProgramId is
`91b0a2176e1e3c12a0fc1673a738ad6492238bd07c33a959c3d41d2fb9cab893`.
The runtime PVM is 983,895 bytes; Authority/Catalog templates are 767,221/187,364
bytes. Exact hashes and source/builder revisions are pinned together in
`support/production-artifacts.toml`, `vosx/build.rs` and the protocol runtime ID.
The established service/registry/space-authority artifacts are unchanged.

Evidence under shared C2 `target/task-tmp/r17-release-candidate.fNbf43`:

- `build.log`, `reproduction.log`, scripts and retained source/target trees:
  both builds completed and all four byte comparisons passed.
- `physical-candidate.log`: **4 passed**, 4.06 s, against the r17 candidate.
- `post-pin-physical.log`: **7 passed**, 4.11 s, against the actual new bundle
  without candidate overrides, including expiry with missing availability.
- `post-pin-cli.log`: **255 passed, zero failed, 17 ignored**, 74.25 s. Ignored
  live/campaign cases remain gates, not inferred passes.
- `clean-break.log`: normal CLI rebuilt (52.04 s), retained commands and
  rejected legacy surfaces verified. The executable now embeds the new bundles.

All build/test handles from this checkpoint completed. Next is a new isolated r17
bootstrap/restart/ingress check, then live native expiry retirement. Earlier r16
fixture outcomes are historical only. Full library/features, Shared finality,
Private/Attested, management expiry/abort and production latency remain open;
this pin does not declare the branch master-ready.

### Fresh r17 bootstrap/restart/ingress smoke

Using the normal rebuilt CLI at source/pin `c4063a1e`, created a new isolated space
`acaa563eea78491062c30dc70b743f6bd6316d5199b666e058777a1e1548a5a8`
in shared C2 `target/task-tmp/r17-startup-smoke.ncMr4z`. Creation automatically
generated HTTP (8080) and SSH (2222) configuration. Only those fixture ports were
changed to loopback 18096/2238 to avoid collisions; no default feature was manually
enabled, no old identity was reused and no arbitrary actor was preinstalled.

`run.sh` completed both phases with exit zero: first start 05:43:12–05:43:51 UTC,
restart 05:43:51–05:44:49 UTC on 2026-09-15. Both reached `Space daemon ready`
(not recovery-only mode), returned HTTP `status: ok`, and completed SSH keyscan.
SSH public host-key output was byte-identical after restart. Both processes shut
down cleanly; no daemon is left running. Evidence: `new.json`, `run.log`,
`first.log`, `restart.log`, status JSON and SSH-key files alongside the scripts.
The native system-Agent startup path runs before the ready marker, and both
phases retained the same verified registry genesis root.

This closes the fresh r17 bootstrap/restart/ingress smoke, not ordinary-Agent
Create/Install, protected invocation or post-issuance expiry retirement on r17.
The 39/58-second startup times are still a production-latency concern, not an
acceptable-latency claim. Reuse only this disposable r17 fixture for the next
native lifecycle campaign; keep older r16 fixtures untouched.

The next native r17 Create attempt returned HTTP 504 after startup; its saved
`local-create.request` and pending credential were preserved. Exact `--resume`
after restart now **passes**, yielding verified Create acknowledgement for Agent
`1e0e2f54ccfc602777b5a45a1a975a2689471f0341ea64a6585ebea1ca2f65fb`.
Recovery startup was 05:53:53–05:56:28 UTC; exact resume completed at 05:56:43,
with byte-identical saved request, followed by clean shutdown at 05:56:44.
`create-resume.json` and `create-resume-run.log` are the successful evidence;
`create.json` remains the failed first output, not usable Create evidence.
The normal CLI also built the r17 Counter package in `counter-artifact/`.
The existing live Counter tests now accept explicitly selected `r17-startup`
only with the matching disposable-directory guard (`VOSX_INVOKE_SMOKE_SPACE`);
their compiled CLI test executable is used for the passing r17 campaign below.

Production-mode latency check: completed an offline, locked `cargo build --release
-p vosx --bin vosx -j 2` using the configured fat-LTO release profile and named
host toolchain (8m50s). Build log: `release-build.log` in this fixture. Scratch
stays on disk; no timeout, validation or optimization profile was weakened.
`install-release.sh` used that executable against the same disposable space and
verified Create result. Startup ran 06:07:11–06:09:52 UTC on 2026-09-15 (161s);
Install then returned HTTP 504 and the script exited 1, stopping its own daemon.
`install.stderr` explicitly reports an unknown outcome and retained exact bytes.
Do not treat the failed `install.json` as an acknowledgement or issue a fresh
Install intent. The retained nonce is
`3349341529a55cc2c75b4040de86fd840c81f8b4a5b9223cf6aa622ea640cd05`.

A five-second CPU sample of this release daemon during Install had 524 core
cycle samples, 77.57% in BLAKE2 compression, plus five atom samples all there.
See `release-install-profile.txt` and its raw `release-install.perf.data`.
Caller unwinding is insufficient to attribute that hashing to a precise path;
these samples do not justify removing validation or claiming a proven fix.
`resume-install-release.sh` completed with exit zero: release restart ran
06:15:33–06:16:33 UTC, then exact Install recovery completed at 06:16:41 (8s).
The before/after digest of the saved request matched, the CLI verified the
acknowledgement in `install-resume.json`, and the daemon shut down cleanly at
06:16:41. See `install-resume-run.log` and `install-resume-up.log`. This passes
recovered installation, not acceptable first-response latency.

The existing `real_daemon_counter_mutation_and_exact_retry` now passes on this
r17 fixture against the release daemon (one test, 90.67s). Readiness took 86s
(06:17:56–06:19:22 UTC); the managed invocation completed in 89.27s. The test
verifies the value seven, receipt-bearing authorization, positive retirement,
two rejected late Invoke retries and positive ACK retries. Invocation ID:
`f05af44532142c53c476f102d9e826387a03a8f4c80e9b408b804c5a800848d1`.
The daemon shut down cleanly at 06:21:52. `counter-release.sh` then started a
separate daemon for `real_daemon_counter_value_after_restart`. Readiness took
168s (06:21:52–06:24:40 UTC), then the test passed (one test, 90.33s; managed
attempt 88.87s), verifying the persisted value seven, positive retirement and
exact retries. Read invocation ID:
`5eb2acb17f5babdeafc5267e7b006c0da27fdbb5706ea0711e638c79f87ee534`.
The daemon shut down cleanly at 06:26:50 and the campaign exited zero. No test
daemon remains running. Evidence is in `counter-release-run.log` and
`counter-{mutation,read}-{up,test}.log`. The client is the existing debug test
executable, so this is release-daemon correctness coverage, not a pure release
CLI benchmark or protected/non-Public policy proof.

Scoped handoff: the r17 Counter install/mutate/restart-read baseline is closed;
do not rerun it merely for status. The live post-issuance unseen-expiry check
below now also passes. Next C2 work includes a caller-attributed investigation of release startup/operation
latency, preserving all validation and timeout limits. Original C1 recovery/
crash/capacity and C2 finality/profile/lifecycle gates remain open, followed by
C3 final-source release verification and review. No new feature work or review
batch is added by this campaign. The branch is not ready for master or ordinary
production use; disposable functional testing remains the supported scope.

### Live r17 unseen-expiry retirement campaign

The existing disposable r17 Counter harness now includes an expiry phase and
a distinct post-expiry restart-read intent. The client authorizes an increment
using a genuinely signed 180-second validity, retains but does not deliver the
application, and waits until wall-clock time is strictly after receipt expiry.
An internal helper accepts this test validity; the normal CLI still uses 3600
seconds. No server timeout, trusted clock, signature validation or bundled
runtime changes. Retried operations retain their original signed bytes.

`real_daemon_counter_unseen_expiry_and_retirement` passes against the configured
release daemon: one test, 234.39s including issuance and the real expiry wait.
The post-expiry managed attempt completed in 0.94s. It verifies the exact
`ExpiredBeforeExecution` result, durable positive retirement, late Invoke
rejection, positive ACK retries and completed managed retry. Invocation:
`c2abb3a44a524195bfa093167b20d73f3d878b107ec06060e3dcba959867c60d`;
signed expiry Unix slot `1789454148`. Startup ran 06:30:33–06:31:57 UTC on
2026-09-15; the test completed and daemon stopped cleanly at 06:35:51.
The separate restart-read phase also passes: one test, 63.56s (managed attempt
62.08s), returning seven rather than fourteen, with positive retirement and
exact retries. Its fresh invocation is
`c1a3ed0bf993a21faf0bc2a86741b8c8aeebe32dd9e4799469dcfbd2765292b4`.
Restart ran 06:35:51–06:39:00 (189s), the read completed at 06:40:03, and shutdown
completed cleanly at 06:40:46. The script exited zero; no test daemon remains.
Evidence: `expiry-release.sh`, `expiry-release-run.log`, `expiry-test.log`,
`expiry-up.log`, `expiry-read-test.log` and `expiry-read-up.log` in the same r17
fixture. This proves the expired increment did not mutate the Counter across
restart; the startup delay remains unacceptable.

The harness compiles. Focused managed-client regressions pass (3 tests, 0.38s,
14 explicitly ignored live tests); all three managed application/retirement
regressions pass (8.41s), including negative-ACK pending-evidence preservation.
Logs: `expiry-harness-build.log`, `expiry-client-regression.log`, and
`expiry-retirement-regression.log`. This is C2 coverage, not pre-expiry abort,
management expiry, mixed-pending/crash/capacity, Shared finality or full release
closure. The release daemon predates only this client/test harness refactor;
guest and server code are unchanged.

### Recovery attachment capacity-only projection (C2 latency)

Sampled test-only Rust backtraces finally provide usable caller attribution for
repeated journal Invoke encoding. The native issuance/reopen/retirement test
passes in 20.95s with instrumentation (`journal-callers.log`, same r17 fixture).
Of 38 periodic caller samples, 16 include `audit_recovery_capacity`, 11 include
physical-row verification, and seven include full `SharedAgentHost::show` from
recovery attachment. These are overlapping call-stack samples, not percentages
of CPU time or an exhaustive hash profile.

Eight recovery attachment checks read only applied/remaining ledger capacity
from a full status projection. They now use the existing `host.capacity` method
under the same host locks instead. Every fresh authenticated ledger audit,
physical-row verification, admission requirement, checkpoint decision and
barrier comparison remains. Only the unused actor-lane and snapshot status
queries are removed; no cached trust, capacity waiver or timeout change.
The initial attachment status and user-facing status still use their existing
paths. A physical host regression compares capacity-only facts to full status
after runtime upgrade/actor installation and checks missing-agent rejection.

The same instrumented native test passes after the change in 20.01s
(`journal-callers-capacity-only.log`). This single small timing difference does
not establish a production latency improvement. All temporary backtrace code
was removed; no profiling feature or source hook remains. Final-code checks:

- Six focused tests pass, 54.98s: native issuance/reopen, completion-write retry,
  partial result retirement, physical host capacity equivalence, exact Raft
  restart/duplicate behavior, and missing/corrupt physical-row rejection.
  Evidence: `capacity-only-recovery-tests.log`.
- Normal `vosx` compile check passes, 5.31s (existing warnings), in
  `capacity-only-cli-check.log`; diff checks pass.

This is a host-only change; no guest artifact or pin changed. The release binary
used by the preceding live campaigns does not yet include it. Multi-minute
release startup remains open: the measured caller paths still authenticate and
re-encode complete retained command history on capacity/recovery reads. Further
work must establish a safe immutable verification boundary there, not repeat
the failed perf unwind settings or infer a release gain from this small test.

### Single-read physical command canonicality reuse (C2)

The physical-row verifier already strictly decodes each command and compares
its complete canonical encoding with the authenticated payload. Recovery then
consumes that owned `ValidatedPhysicalEntry` directly, without mutation, but
was encoding the same command again solely to repeat the same equality check.
That second encoding is removed. The private wrapper has one construction
site, in `validate_physical_kind`; its ownership invariant is now documented.
Each new storage observation still verifies term, physical commitment, frame,
command canonicality and shape. Replay still checks generation, committee,
disposition and authority; no verification fact is cached across reads.

Six selected final-code tests pass (20.40s): native issuance/reopen, physical
command validation, authorized committee rotation/restart, snapshot rotation
evidence recovery, wrong generation/committee/authority refusal, and missing/
corrupt-row rejection. New cases rehash outer entries containing trailing or
truncated inner command bytes and still require rejection. Evidence:
`physical-canonical-reuse-tests.log` in the r17 fixture. Normal CLI compile check
passes (4.86s, existing warnings, `physical-canonical-reuse-cli.log`), as do
formatting and diff checks. This removes one command re-encoding per ordinary replayed audit
row, but does not establish a release wall-time improvement. No guest artifact,
timeout or release gate changes; the release executable still needs rebuilding
before measuring this and the preceding host-only change together.

### Updated release startup after host optimizations

The configured fat-LTO release build at code revision `2a4f17ea` passes in
5m49s, using offline locked dependencies, host nightly-2025-05-09 and `-j 2`.
This executable includes the capacity-only recovery projection and single-read
physical command canonicality reuse, plus the unchanged normal one-hour client
validity. No source diagnostic, guest artifact, validation or timeout change.
Build evidence: `release-host-2a4f17ea-build.log` in the existing r17 fixture.

`host-2a4f17ea-startup.sh` completed with exit zero. The disposable r17 space
became ready in **99 seconds**, 07:01:19–07:02:58 UTC on 2026-09-15. HTTP health
returned `status: ok`; SSH keyscan output exactly matched the original host key.
The daemon shut down cleanly at 07:02:58; none remains running. Evidence:
`host-2a4f17ea-startup.log`, `host-2a4f17ea-up.log`,
`host-2a4f17ea-status.json`, and `host-2a4f17ea-ssh-key.txt`.

This is updated release-mode correctness and latency evidence, not a controlled
before/after speedup: the fixture accumulated more retained history between
measurements. Ninety-nine seconds remains unacceptable; do not close the
latency gate. No Create/Install/mutation was repeated merely for status. Next
latency work must address repeated retained-history verification beyond these
small reductions. Ordinary Shared finality, broader terminal/recovery/profile
coverage and final-source release gates remain open in C1/C2/C3.

### Full coordinator retention capacity verified in release mode

The previously interrupted 256-record coordinator capacity test now completes
at its original full size. Every record is filled through `coordinate`; there
is no synthetic prefilled image, reduced limit, skipped validation or replaced
dispatcher path. The existing scripted actor and real Ed25519 signer remain
unchanged. New assertions require the overflowing call to preserve both store
images, both commit counts, both signer counts and the complete retained count,
in addition to the existing no-dispatch assertion. Reopening the full stores
must retain all 256 records and reject overflow without dispatch/signing again.

The configured release test build passes (10m56s); the full-capacity test passes
in **19.30s**, one test, zero failures or ignored tests. Evidence:
`full-capacity-release.log` in the r17 fixture. The named host toolchain,
offline locked dependencies and disk-backed scratch were used; the release
profile was not overridden. The debug-mode attempt remains historically
interrupted, not retroactively passed. This closes the full coordinator
retention-boundary check, not live mixed-pending/crash/GC capacity coverage or
acceptable production latency. No production code, artifact or limit changed.

The remaining 24 coordinator tests pass in the same release executable (0.08s),
with the already completed capacity case explicitly filtered, not rerun.
`coordinator-release-regressions.log` covers this complementary run: together
the two commands execute all 25 coordinator tests, zero failures/ignored.
Formatting and diff checks pass. The reusable release test executable is
shared target `release/deps/vos-215e14785cbfaec4`; its build is complete.

### Native recovery and physical capacity release matrix

At `c8788f98`, the existing release test executable completes the selected
native Create/Install startup, administration, operation retirement and pending
projection recovery matrix: **36 passed, zero failures, one explicit capacity
diagnostic ignored**, 262.63s. The ignored diagnostic was then run separately
with `--exact --ignored`: `native_operation_initial_capture_requires_more_headroom_than_projection`
passes, 259.78s. Together all 37 selected cases executed successfully; none is
counted as passed solely because it was filtered or ignored.

The capacity diagnostic fills authenticated Invoke/ACK history at the actual
64MiB journal boundary. It verifies management-capture refusal before intent
publication with unchanged physical state, distinguishes the smaller projection
budget, and successfully uses the production capture/checkpoint repair path.
It does not replace this history with a synthetic capacity counter. These are
native host fixtures with bundled artifacts and local network harnesses, not a
full daemon mixed-pending campaign. The 20 issuer regressions also pass (0.52s).

Evidence in the r17 fixture: `native-recovery-release-matrix.log`,
`native-64mib-capacity-release.log`, `issuer-release-regressions.log`.
Both native processes completed; no build or test process remains from these
runs. No production source, artifact, capacity limit or timeout changed.

Source audit distinguishes physical-journal checkpoint repair from operation
history reclamation. `DurableAuthorityOperationCoordinator` and
`DurableAuthorityOperationIssuer` retain successful issued records permanently
in their bounded images; fresh work is rejected at 256. Native terminal
retirement releases admission but does not prune those images. The passing
coordinator/issuer ceiling tests prove fail-closed behavior, not unbounded
service life. Removing records without independently reopenable consumption
evidence and preserved exact-retry/collision protection would be unsafe.
This remains a concrete retention/GC implementation gate alongside mixed-pending
recovery, pre-expiry abort/management expiry, Shared finality, profile coverage,
latency and final-source release verification. Keep the C1/C2/C3 grouping.

### Bounded single-pass issuer lookup for cross-image validation

Retention audit confirms that NRT1 binds the retired policy-result pair, not
actor application. Reclamation also has to preserve both exact images' call/
context/issuance bindings, signed responses, collision protection and source
dispatch evidence across interrupted multi-store publication. No record is
deleted based solely on a terminal certificate in this change.

The existing cross-image validator decoded the issuer's call prefix again for
each coordinator record, producing quadratic lookup work as retained history
grew. It now decodes each issuer record once into a temporary bounded BTreeMap,
then consumes matching invocation keys. All call, issuance-slot and consumed
acknowledgement comparisons remain, with explicit duplicate/orphan refusal.
The issuer's single-record and iterator paths share the complete decoder,
including private-resolution preimages. Full image verification on open and
publication is unchanged. No index survives the immutable check, no on-disk
format changes, and no trust is cached across writes or reopen.

Final-code targeted tests pass: **46 passed, zero failures/ignored**, 52.73s,
covering issuer/coordinator regression suites and native issuance/reopen. The
new test accepts valid reordered coordinator records, checks iterator results
against individual recovery, and rejects missing/duplicate rows, changed slots
and changed acknowledgement commitments. Evidence: `cross-image-linear-final.log`
in the r17 fixture. The long full coordinator-capacity test was explicitly
filtered in this debug run. The final optimized source at `4e8aa893` now
passes that full 256-record population, overflow and reopen test: **1 passed,
zero failures/ignored, 24.27s**, after a 12m59s configured release build
(`cross-image-full-capacity-release.log`). The remaining issuer/coordinator
tests pass from that same optimized executable: **45 passed, zero
failures/ignored, 0.96s** (`cross-image-release-regressions.log`). Together
these cover all 46 issuer/coordinator tests without filtering out capacity.
The earlier capacity run took 19.30s; these observations do not demonstrate
a performance improvement from the lookup change.
Normal CLI compilation passes (5.21s, existing warnings,
`cross-image-linear-cli.log`); formatting and diff checks pass.
The SDK no-default-features check also passes on `4e8aa893` (1.46s,
`final-source-sdk-no-std.log`): `cargo +nightly-2025-05-09 check --offline
--locked -p vos-agent-sdk --no-default-features`, using the shared disk-backed
target and scratch directory. This is the SDK check, not the whole workspace
feature matrix.
The unfiltered optimized library run uses the same `4e8aa893` executable with
`--test-threads=2` and disk-backed `TMPDIR`; its output is retained in
`final-source-release-library.log`. It completed with **1,813 passed, 20 failed,
three ignored, zero filtered**, in **3,696.62s** (exit 101). The 1,024-entry
inventory rotation test passed: all 514 authenticated queries, exact contents,
snapshot rotation and cleared pending reservations were checked. The failures
are the socket cases reconciled below. The three default-ignored cases are
native initial-capture capacity and two profiling probes. This long concurrent
test run is not an inventory latency benchmark.
The ignored native initial-capture case was then explicitly run from the same
optimized executable with `--exact
agent::clean_bootstrap::tests::physical::native_operation_initial_capture_requires_more_headroom_than_projection
--ignored --test-threads=1`: **1 passed, zero failures/ignored, 544.26s**,
`final-source-native-capacity.log`. It ran concurrently with the large
inventory test and used disk-backed scratch. This requalifies the real 64 MiB
admission/checkpoint boundary on the updated source; the duration is not a
controlled latency comparison with the earlier 259.78s run. Only the two
profiling probes remain intentionally unexecuted in this verification pass.

The restricted run reported 20 socket-dependent failures. The Merge test was
reproduced alone: it failed waiting for any local listening address, then
passed unchanged with socket access (1.09s, `final-source-merge-socket.log`).
The network/HTTP groups pass with socket access (**42 passed**, 8.97s,
`final-source-network-sockets.log`), and the node-level colliding-prefix Raft
test passes separately (0.02s, `final-source-node-socket.log`). Matching test
names confirms these reruns cover every failure in the final failure list. These are
separate passing reruns, not a successful exit from the restricted full run;
no timeout, assertion, or production behavior was changed.
Across these commands, all 1,834 non-profiling library tests have passing
evidence on `4e8aa893`. No test process from that campaign remains running.
No end-to-end latency gain is claimed. Authenticated history reclamation and
the 256-record lifetime ceiling remain unresolved.

A five-second CPU sample of the running optimized native library tests used
`perf record -F 99 --call-graph dwarf,16384` (270 samples, zero lost samples;
`library-native-profile.data` and `library-native-profile.txt` in the same
fixture). BLAKE2 compression accounts for roughly 67% of core-cycle samples
across the sampled thread names. Even with DWARF stack capture, higher-level
callers remain unresolved. This is a concurrently running test workload, not
a daemon latency measurement or evidence identifying a safe validation to
remove. The sampled library run's elapsed time includes this diagnostic.

A later brief debugger attachment resolved one live inventory-worker stack
using the explicit local executable and `set sysroot /` (the first attempt's
automatic target executable lookup failed across PID namespaces). Evidence:
`inventory-worker-local-symbols.log`; both attempts detached immediately after
stack capture. The resolved worker path is `reserve_projection_pair` → host
`capacity` → `audit_recovery_capacity` → physical-row verification → journal
RuntimeWork decoding → `InvocationWork::validate` → `availability_valid` →
BLAKE2. The inventory caller was waiting for `load_replicas`. This identifies
one actual hashing caller in the optimized workload, not its statistical share
or a production timing result. Source inspection confirms the capacity audit
walks the retained suffix within one read transaction and authenticates each
physical row. Any optimization must preserve those fresh row checks; the
snapshot is not justification for trusting cached capacity across reads.

The follow-up source audit confirms that reclamation cannot be an isolated
coordinator-vector deletion: native controller startup also bounds retirement
certificates to `MAX_AUTHORITY_OPERATION_COORDINATOR_RECORDS`, while dispatch
journal bounds allow twice that number for the authorization/issuance pair.
`NativeAuthorityOperationController::retire_issued` reloads both exact dispatch
records even for a previously certified retirement, then restores and releases
the native reservation. Any archive/reclamation implementation must retain a
verified retry lookup for those records, preserve invocation collisions and
slot high waters, and recover interrupted publication across the affected
stores. Raising one limit or deleting only coordinator/issuer rows would not
close the sustained-operation gate. No retention limits or records were changed
by this verification pass.

### Reuse validated invocation work within journal decoding

The resolved inventory-worker stack above led to a host-only duplicate check:
`decode_replay_operation` decodes and validates the complete SDK RuntimeWork,
then `ReplayInput::decode_body` called a validator that rehashed the same owned
invocation's availability preimages. Decoding now checks the enclosing runtime
and operation bindings without repeating that work validation. Constructed or
subsequently mutated ReplayInput values still validate invocation work in full.
Invoke, Resume and Acknowledge decoder paths all obtain their work from the
canonical SDK decoder; authorization, context, lifecycle-proof and yielded
result bindings remain checked. No validity is cached across calls or physical
reads. No SDK, wire format, guest artifact or retention limit changed.

The journal suite passes **41 tests**, zero failures/ignored (0.19s,
`journal-decoded-work-tests.log`). Added enclosing-journal checks verify exact
Invoke/ACK roundtrips, corrupted blob rejection, runtime substitution rejection
and full validation after mutation of a decoded value. The existing validation
equivalence test now exercises the complete constructed ReplayInput validator.
The follow-up Resume fixture now includes an actual availability blob and
checks corrupted wire, post-decode blob mutation and substituted yielded-actor
rejection at the decoder boundary. The complete journal suite passes again
on the final test source: **41 passed**, zero failures/ignored (0.16s,
`journal-decoded-work-resume-final.log`). Production code is unchanged from
`d80c837d` by this test-only follow-up.
Physical command byte/shape validation, native issuance/reopen and snapshot
rotation pass **3 tests** (42.91s, `journal-decoded-work-physical.log`); committee
transition, corrupt/missing rows and wrong-generation/authority rejection pass
**3 tests** (4.51s, `journal-decoded-work-ledger.log`). Normal CLI check passes
(13.06s, existing warnings, `journal-decoded-work-cli.log`). Formatting and
diff checks pass.

These are focused checks on the new host change. The completed optimized
inventory/full-library executable was built from the preceding `4e8aa893`
source, not this edit. Do not attribute its result to the new decoder. Neither
an end-to-end latency improvement nor completion of the remaining production
gates is established by this change.

### Reuse validated children at ordered-entry and Raft-command decode boundaries

The next two enclosing decode layers now also separate child validation from
enclosing-field validation. OrderedEntry decoding uses the already-validated,
bounded ReplayInput; Raft command decoding uses children returned by the
strict canonical `decode_nested` path. Constructed-value validation still
validates children, and fresh physical reads still check term, commitment,
strict frame bounds, canonical encodings and disposition compatibility.
No decoded object or validation result is cached across observations. No wire
format, SDK, guest artifact or admission/retention limit changes.

A new regression checks seven malformed child/enclosing-field cases through
both constructed validation and decoding, plus trailing/truncated command
frames. Final-source journal/Raft tests, physical byte/shape validation and
native approved issuance/reopen pass **74 tests**, zero failures/ignored,
27.75s (`nested-decoded-validation-final.log`). The initial 73-test run also
passed; the final run includes native issuance. Normal CLI check passes (6.17s,
existing warnings, `nested-decoded-validation-cli.log`); formatting and diff
checks pass. These tests do not establish an end-to-end latency improvement
or a full-suite pass on this newer host source. The completed `4e8aa893`
library run remains baseline evidence only.

The configured optimized build of `d2aa1efe` subsequently passed in 10m41s.
The same 74 focused tests pass in release mode: **74 passed**, zero
failures/ignored, 12.22s. Evidence is under the shared disk-backed target's
`task-tmp/decoder-fixed-history.Q5oYmW/`: `candidate-d2aa1efe-build.log` and
`candidate-release-regressions.log`.

A fixed-history comparison now establishes a scoped performance improvement.
The r17 daemon was confirmed stopped; its original database was not opened by
the probes. Two copies had identical initial SHA-256
`9a233b5e2354591794e6d9ca3dc2ca201b7cc229bf6e6767456bf90e0dcbebfb`.
The preserved `4e8aa893` and new `d2aa1efe` release executables used the same
toolchain/profile/features and the unchanged physical-decode probe. All four
ABBA runs passed with 46 rows, 44 commands and 33,750,544 bytes, checking exact
canonical command encodings. Compare `duplicate=false` across revisions;
the probe's separate duplicate mode is not the primary comparison.

Across eight measurements per revision, baseline median was **366.874 ms**
and candidate median **141.168 ms**, a **61.52% reduction** (2.60x ratio).
Ranges were 316.838–384.487 ms and 132.160–198.483 ms; timings varied, but every
candidate measurement was below every baseline measurement. `comparison.log`,
the individual paired logs, `compare.sh` and the scratch README retain the
procedure, inputs and executable digests. This is a fixed-history validation
improvement, not a daemon startup or Create/Install latency pass. The last
measured daemon still predates these decoder changes; production latency,
authenticated reclamation, finality and other original release gates remain
open. All comparison/build/test processes from this checkpoint have exited.

The actual release CLI was then built at `ec8bdb70` (production code unchanged
from `d2aa1efe`), using the same configured profile/toolchain: build passed in
6m12s. The isolated existing r17 fixture started at **09:20:26 UTC** on
2026-09-15 and reported ready at **09:22:18 UTC**, **112 seconds**. HTTP status
was `ok`, the SSH public-key output matched the original fixture byte-for-byte,
and shutdown completed cleanly at 09:22:18. No Create/Install or actor mutation
was submitted. The original 300-second observation deadline was unchanged.
Evidence in the same fixed-history directory: `daemon-ec8bdb70-build.log`,
`startup-ec8bdb70.sh`, `daemon-ec8bdb70-startup.log`, `daemon-ec8bdb70-up.log`,
`daemon-ec8bdb70-status.json` and `daemon-ec8bdb70-ssh-key.txt`.

This closes the startup functional regression check, not the latency gate.
The earlier 99-second startup and this 112-second startup are not a controlled
fixed-history A/B; this run provides no evidence of improved startup latency.
The scoped physical-decoder benchmark cannot substitute for locating and
reducing the remaining end-to-end startup work. No daemon from this smoke
test remains running.

### Startup timing separates pre-inventory recovery from query execution

A stack-only daemon diagnostic was refused by the OS (`ptrace: Operation not
permitted`). Its script stopped the daemon through its cleanup handler; a
process check confirmed no daemon remained. No debugger protection was changed
and no recovery store was reset. The failed attempt is preserved in
`startup-profile-run.log`, `startup-profile-stack-0.log` and
`startup-profile-up.log` in the fixed-history scratch directory.

The next run used the existing debug timing events from production_owner,
clean_bootstrap and shared_raft, with the same release executable and isolated
fixture. It started at **09:28:10 UTC**, became ready at **09:30:15 UTC**
(125 seconds), passed HTTP status and the byte-identical SSH identity check,
and shut down cleanly at **09:30:16 UTC** on 2026-09-15. Evidence:
`startup-timing.sh`, `startup-timing-run.log`, `startup-timing-up.log`, status
and SSH output files. This follows an interrupted diagnostic startup and has
extra logging; it is not a controlled performance comparison.

Inventory reconciliation began at 09:29:24.412900, roughly **74 seconds after
startup**. Inventory loading took **47.946 seconds**, across six authenticated
queries taking 7.726, 7.831, 7.970, 8.083, 8.132 and 8.201 seconds. Route
reconciliation completed at **50.527 seconds** from its start, about 2.581
seconds after inventory loading. The two agents yielded Credential, Agents,
and per-agent Replicas/Actors queries. The observed delay therefore includes
both a large pre-inventory interval and multi-second query execution; faster
physical decoding alone does not close either end-to-end gate. Finer
pre-inventory stage attribution and query execution attribution remain needed
before further changes. No process from this diagnostic remains running.

### Durable client acknowledgement before completion

The fresh Create CLI now persists the full verified MAA2 before marking its
credential reservation completed. CSF1 role 10 stores an immutable
`local-create.acknowledgement` in an exclusively leased private directory under
the operation's `acknowledgement/` child. Both load and publication verify the
canonical acknowledgement against the complete retained signed request;
loads also re-establish durability before proceeding. Different responses and
replacement-predecessor frames are refused. This retains the actual completion
evidence, not only its hash, as a prerequisite for safe lifecycle retirement.

The CLI still submits exact retries to the server: a local acknowledgement is
not presented as fresh route/publication evidence, and this change cannot make
the running HTTP smoke pass through a local cache. The running
`published-resume` script uses the preceding `d95b7afa` binary, without this
storage addition.

All **174 CLI tests pass**, zero fail, one existing compiled-runtime release
test remains ignored (`r16-client-ack-storage-final.log`, 2.85 seconds, under
`.worktrees/ch08-c2-native/target/task-tmp`). New coverage includes valid reopen,
signature and request substitution refusal, immutable bytes, interrupted initial
stage recovery, and preservation of rejected replacement evidence. The first
run exposed an accidentally identical “different request” fixture and a sandbox
socket denial; the fixture was corrected and the final suite ran with local
socket access. No guest artifact or existing store role changed.
The final native CLI build including acknowledgement storage also passes
(`r16-client-ack-cli-build.log`, 3.47 seconds); the live smoke above predates
only this client-side storage addition.

### Durable immutable Local Create request storage

`CleanLocalCreateRequestFile` stores one signed HTTP-compatible LCQ1 submission
in a dedicated private directory with an exclusive writer lease. It reuses the
existing no-follow directory-relative file operations, role-bound integrity
envelope, staged publication and file/directory syncing. New CSF1 role 7 and its
three-entry directory profile do not alter existing bootstrap or lifecycle file
roles. The caller must retain the lease while sending; this is not yet a
credential-wide sequence allocator or a CLI subcommand.

Publication validates the signed request and 1 MiB cap before writing. Identical
publication is an exact retry; different bytes are refused without replacing the
stored request. A complete initial stage can be recovered, but an attempted
replacement with a predecessor is refused even during reopen. Incomplete and
wrong-role evidence remains untouched for diagnosis. Loading validates the
signature/runtime binding again and re-syncs the exact file and directory before
returning retry bytes, including after an ambiguous earlier directory sync.

Remaining CLI work is unchanged in scope: discover the pinned descriptor and
Authority, allocate the next credential sequence safely, retain this request
before transmission, submit it through bounded HTTP, verify the exact returned
acknowledgement, and prove native Create/publication and restart/retry. No new
daemon smoke, artifact reproduction or master-readiness claim accompanies this
storage checkpoint.

**35/35 file-store and Local Create preparation tests pass** in 0.62s
(`r16-local-create-request-store-final.log`, locked/offline `vosx` binary tests,
disk scratch). The new cases cover immutable/exclusive publication and reopen,
initial-stage recovery, staged replacement refusal, incomplete-stage retention
and cross-role rejection. Existing bootstrap/lifecycle store regressions remain
green. Formatting and diff checks pass.

### Local Create response verification

`local_create::verify_acknowledgement` now verifies a canonical MAA2 response
against the exact retained LCQ1 request. It checks the Authority target against
the request before trusting the response key, verifies both the original
receipt signature and the post-application signature, reconstructs the approval
preimage from the call and signed receipt fields, and uses the SDK's exact
pending-call matcher. That matcher includes the complete created Agent identity.
Receipt validity is checked at its signed application slot, not the client's
current time, so a retained successful reply remains verifiable on later retry.

**36/36 preparation, acknowledgement and file-store tests pass** in 1.30s
(`r16-local-create-ack-final.log`, locked/offline `vosx` binary tests, disk scratch).
Negative cases cover truncation/trailing bytes, a different signed request,
either corrupted signature, and re-signed substitutions of approval commitment,
Authority target or created runtime identity. Formatting and diff checks pass.

This authenticates the issuer's exact application claim; it is not independent
journal replay, ordinary Shared genesis finality, or proof of live route
publication. HTTP client/subcommand wiring and the native end-to-end smoke
remain open. The existing `vos` HTTP-client dependency is `ureq` 2; it is not
currently a direct `vosx` dependency or an exported general-purpose client.

### Retained Local Create submission command

The native CLI now exposes:

```sh
vosx space submit-local-create /absolute/private/request-store --http 127.0.0.1:8080
```

This command requires an already published request store; it does not discover
descriptors, allocate a credential sequence or prepare a new request. The
submission client loads/re-syncs the exact LCQ1 bytes and retains the exclusive
store lease through response verification. It uses a fresh HTTP agent, disables
environment proxies and redirects, bounds connection time to 5 seconds and the
whole operation to 130 seconds, and bounds response bytes to the SDK MAA2 limit.
Only HTTP 201 with the expected binary content type and a verified exact
acknowledgement succeeds. Failures retain the request and warn that the outcome
may be unknown. JSON output includes the Agent ID and canonical acknowledgement
hex, not private key material.

The explicit plaintext socket is loopback-only, suitable for a local daemon or
a separately established local tunnel; this client does not provide direct
remote HTTPS configuration. `vosx` now depends directly on the already locked
`ureq` 2 package, without a version update. No fresh CLI build or real-daemon
Create smoke is claimed at this checkpoint. Fresh preparation/discovery and
safe sequence allocation still need command wiring before the complete Create
UX can be exercised.

Socket tests submit the actual bundled-runtime request to a simulated HTTP
server, compare every request byte, verify the lease remains held, accept a
correct signed acknowledgement, and reject redirects, 503, wrong content type,
truncated MAA2 and oversized bodies while preserving the original stored bytes.
These are client transport tests, not evidence of real native route publication.

**All `vosx` binary tests pass: 167 passed, zero failed, one ignored**, in 3.29s
(`r16-local-create-client-final.log`, locked/offline, serial tests with socket
access and disk scratch). The ignored compiled-runtime candidate test requires
fresh guest input/output paths and remains a release gate, not a passing test.
Formatting and diff checks pass.
