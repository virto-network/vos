# Agent saga review handoff — 2026-09-15

## Checkpoint and decision

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
