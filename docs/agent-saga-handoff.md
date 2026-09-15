# Agent saga review handoff — 2026-09-15

## Checkpoint and decision

Latest source qualification: the acknowledgement optimization described below
is ahead of the bundled r17 runtime. The frozen checkpoint remains unchanged;
current HEAD requires candidate PVM validation and final artifact reproduction.

Implementation checkpoint: `f76dabe1` on `wip/ch08-runtime-directory`.
At that checkpoint, `saga/agents` is `31b0cdbb`: 258 commits ahead, zero behind,
221 changed files, 71,025 insertions and 58,780 deletions. These counts exclude
this documentation handoff. Both worktrees were clean when inspected.

The checkpoint is available for review and isolated, disposable Local-space
testing. It is **not master-ready or production-ready**. No merge, push,
history rewrite, or release-gate waiver is part of this handoff. Existing data
must not be relabelled across the intentional r16/r17 clean break.

## Three review areas, not three completed batches

Keep the agreed C1/C2/C3 grouping. Internal checkpoint commits are not additional
review endpoints. The current integrated history has not yet been consolidated
into three independently verified commit ranges; do not assume that selecting
commits by title produces independently usable branches.

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
