# Agent saga: review entry point

This is the sole reviewer handoff. [The live checklist](agent-saga-status.md)
owns release scope, open gates and deferred work. Review read-only and return
findings for the implementation branch; avoid competing fixes on the review branch.

## Review boundary

The user requested completing the live plan before the next whole-branch review.
This batch follows qualified archive/preflight checkpoint `49be3bda`; its source boundary
is that checkpoint plus the implementation in the commit containing this guide.
Use the worktree diff until committed, then `git diff 49be3bda..saga/agents`
after verifying promotion and cleanliness. `master` remains `d2378274`.
The evidence qualifies candidate slices, not a release or customer capacity.

Use `git show 49be3bda:docs/agent-saga-review.md` for the preceding streaming
archive/preflight and phase-diagnostic evidence, and `git show b8d3a7e3:docs/agent-saga-review.md`
for paired checkpoint/retained-reply evidence. `6d3a4926` remains the earlier reviewed
recovery baseline, not the current work or next whole-branch review range.
Earlier backend, pruning and lifecycle chronology is in Git, not duplicated here.

Production Local remains image-based. Public fixed-three Shared startup/finality,
management, external ownership and pruning remain gated. Candidate tests do not
qualify customer load, released-daemon operation or artifact promotion.

## Current batch: invariants to review

AXJ1/AJB1 bytes and limits, source export admission, production image Local and
physical source-owner checks remain unchanged. A resumed quarantine requires the
same stable-lock intent, sealed initial heads, no exposure or `heads.next`, exact
archive identity and a new complete closure audit. No process epoch survives as
recovery authority, and wrong-identity residue stays inert in quarantine.

Promotion requires the opaque source-audit/rebind plan and renewed exact source
root/mark validation. It copies one typed payload at a time, excluding source
Heads, Genesis and superseded physical checkpoint/Local metadata. Common lane
declarations and root-producing contexts remain unchanged. Destination metadata
staging preserves only its exact current local predecessor envelope using the
existing owner-checked operation; it does not advance heads.

The new publication capability authenticates the genuine common QC and separately
signed binding for the actual destination store/node, then audits **both actual
endpoint trees** under the exclusive borrow through CAS. Exact-target retry still
requires the saved predecessor envelope and tree. Foreign/stale durable or staged
heads refuse. A synced exact `heads.next` can complete only after renewed audit;
no serving pin or materialization escapes this capability.

Binding-aware ledger preflight permits equality only for the exact installed
QC/binding and retains all reservation, configuration and later committed,
applied, snapshot or **uncommitted log suffix** guards. The final ledger restore
transaction still repeats its existing checks. Incoming recovery bodies must
match the exact QC-certified baseline before journal publication; a live manifest
or an empty substitute is not equivalent.

The genuine network source fixture additionally exercises quarantine reopening,
typed destination publication, certified ledger restore, fresh file-owner
reopening, signed Clerk Invoke/ACK and another reopening retaining the exact ACK
claim/reference root. Missing endpoint blocks refuse without repair. Staged-head
interruption/retry is on the same file owner; continuation uses the existing test
log adapter, **not a newly qualified destination network quorum**. Automatic durable
host-marker restart, nonempty custody import and real lagging-host reattachment
remain pending. Neither deadlines nor certificate/reservation guards are relaxed.

## This batch: source-specific qualification

All logs are under `.worktrees/ch08-c2-native/target`. Preserve failures and
do not inherit older counts after source changes. Frozen Rust source is the
complete Rust diff over `49be3bda`, SHA-256
`d2823a25714c679bcfb1a1d7457932a902e32d81badb49de21a30b55ffaeae1a`
(`git diff -- vos/src | sha256sum`, or cached after staging). Optimized
qualification is complete for this candidate slice; separate debug evidence is labeled below.

| Check | Evidence and limit |
| --- | --- |
| Default optimized build | Passed, 12 m 16 s; `external-archive-restore-release-build.log`, binary `release/deps/vos-59a730e87ba3c2af`. Default fat LTO/one codegen unit, no overrides. |
| Optimized core regressions | 266 distinct passed across journal store (122), Shared driver (14), host (34), commit (10), Raft (45), recovery (16) and supervisor (25); 3 ignored cases not counted. `external-archive-restore-release-focused-*.log`. Isolated loopback permission, no selector with zero matches. |
| Optimized external physical matrix | All 7 passed, 286.29 s; `external-archive-restore-release-physical.log`. Full outer/inner recompiler, file/network lifecycle, genuine archive/quarantine/destination restore, source checkpoint marker/journal/ledger interruptions and retained reply through two checkpoints. Destination automatic host-marker crash/restart and public catch-up are not qualified. |
| Optimized image checkpoint/restore | All 4 passed, 129.16 s; `external-archive-restore-release-image-checkpoints.log`. Common compaction/catch-up/reopen/continue and source/destination marker, journal and ledger interruptions. Default clean-runtime test adapter around physical Authority actor execution, not full outer PVM. |
| Supported feature builds | Final-source guest-only `agent-runtime` (0.13 s), guest plus `experimental-state-blocks` (0.13 s), and `vosx --all-targets --features experimental-state-blocks` (6.38 s) passed; `external-archive-restore-final-check-{guest,external-guest,cli}.log`. Offline, locked dependencies. |
| Formatting and diff | Stage child, physical fixture and Shared host pass pinned rustfmt. Journal store/replay/Shared driver/Raft retain exactly 1/1/2/1 baseline hunks from `49be3bda`, byte-identical apart from positions. No new formatter debt; diff checks pass. All five bundled artifact digests match unchanged production pins. |
| Debug build | Final predecessor-staging build passed, 21.93 s; `external-archive-restore-debug-build-predecessor.log`. The initial compile failure (non-PartialEq error in a test assertion) is preserved in `external-archive-restore-debug-build.log`; corrected test build passes. |
| Debug focused guards | Two disk resume preflights, bound common restore and certified baseline recovery tests passed on the earlier restore source; `external-archive-restore-debug-{resume,bound-ledger,recovery-baseline}.log`. The final optimized core matrix above reruns these guards. |
| Genuine external signed restore | Passed, 78.44 s; `external-archive-restore-debug-physical-predecessor.log`. Full outer/inner recompiler, actual source QC/archive, owned stage resume, missing predecessor/target block refusal, exact staged-head retry, destination binding/ledger restore, signed Clerk Invoke/ACK and two certified file-owner reopens. First physical failure (`MissingObject` from unstaged destination predecessor envelope) remains in `external-archive-restore-debug-physical-healthy.log`; fixed by owner-checked immutable staging, not a guard relaxation. |
| Independent source review | No demonstrated defects after cross-review of staging, endpoint publication and bound ledger preflight; debug execution caught the predecessor-staging prerequisite above. Automatic marker recovery and customer capacity remain unqualified. |

Whole-fixture durations are not request latency, throughput or failover bounds.
The following phase observations belong to preceding checkpoint `49be3bda`,
not new source qualification or a performance change in this restore slice.
One explicitly traced debug lifecycle passed (46.16 s),
`external-archive-debug-diagnostic-vm-phases.log`. Transfer Invoke is 734 ms:
six external executions (two caller inspections, preview, three overlapping
applies), actor 3–4 ms per preview/apply, outer execution 139–162 ms, quorum
95 ms. Post-reopen query is 823 ms, actor <1 ms; outer work/first inner-machine
creation are significant. Seven cold outer preparations occur once per thread;
later preparation is roughly 3 ms, so repeated compilation on every apply is
not demonstrated. Do not add overlapping replica durations as serial wall time.
Approximately 0.3 s remains outside measured VM/quorum buckets; journal/application
publication, queue/scheduling and validation lack complete attribution.

Source inspection identifies repeated full ~363 KiB work hashing/encoding,
actor-material resolution, authorization and runtime-metadata reconstruction.
Their individual shares are not measured. `outer_slices` counts **all** outer
host boundaries, not just state-block fetches or actor invocations. No cache/ABI
redesign or tuning pass follows from this single diagnostic.

An optimized traced lifecycle also passed (32.67 s),
`external-archive-preflight-release-diagnostic-vm-phases.log`. Transfer Invoke
is 688 ms and post-reopen `state_root` Invoke 670 ms, each with the same six
external executions. Actor work is 3.4–4.3 ms and 0.6–0.9 ms respectively,
versus outer execution of 131–162 ms per actor-bearing execution. Quorum takes
104/76 ms. Across 192 executions, seven cold outer preparations occur once
per thread (167–214 ms); warm preparation is median 2.7 ms, p95 3.8 ms.
Reopened workers' first inner-machine creation adds 59–65 ms separately.
Approximately 0.21–0.27 s per call remains outside measured VM/quorum buckets;
this does not identify its individual persistence, queue or validation shares.
These are instrumented single-sample observations, not a latency distribution,
stable speedup, or throughput evidence. Quiet optimized phase/load qualification
and actual retained capacity remain mandatory.

## Reproduction

Use the implementation worktree and disk-backed temporary storage:

```sh
export CARGO_TARGET_DIR=/home/daniel/src/virto/vos/.worktrees/ch08-c2-native/target
export TMPDIR="$CARGO_TARGET_DIR/task-tmp"
export JUST_TEMPDIR="$TMPDIR"
export CARGO_NET_OFFLINE=true
export CARGO_BUILD_JOBS=2
export RUST_MIN_STACK=16777216
export AUTHORITY_CANDIDATE_ELF="$CARGO_TARGET_DIR/agent-state-authority/riscv64em-vos/release/system_authority.elf"
export GREY_PVM=recompiler
export VOS_AGENT_PROFILE_REFINE_MACHINES=1
export VOS_AGENT_DISABLE_REFINE_ATTRIBUTION=1
export CLERK_AGENT_PACKAGE="$CARGO_TARGET_DIR/clerk-agent-canonical/clerk-ledger.vos"
cargo +nightly-2025-05-09 test --release --offline --locked -p vos \
  --features 'agent-runtime storage network http-ingress experimental-state-blocks' \
  --lib agent::clean_bootstrap::tests::physical::external_shared:: \
  -- --ignored --test-threads=1 --nocapture
```

Run physical qualification separately from compilation, with loopback socket
permission. For default-adapter Authority recovery, unset the outer-machine/profile
variables and select `agent::clean_bootstrap::tests::physical::recovery_expiry::`
or `agent::clean_bootstrap::tests::physical::common_checkpoint::` explicitly.

Pinned candidate SHA-256 values:

- Authority: `a88872c5de59d97905ccfb043268fa8ef6aea5a1c0e354b9c7c3255fed05e2ed`.
- External runtime, `agent-state-standard/riscv64em-vos/release/agent_runtime.elf`:
  `6511822a0f9d5b46bad657ac233786e0b5bcc75033262ec135d567bb747b25f0`.
- Canonical Clerk package:
  `628a9aafd357214b927d7165b82b01459269c553b2ec3244524b73d3eaf4be7c`.

Changed artifacts cannot inherit earlier evidence. Production pins remain in
`support/production-artifacts.toml` and `vosx/build.rs`; candidate tests do not
promote them. Default Authority fixtures use the native clean-runtime test adapter
around physical actor execution. Full outer-PVM execution requires the flag above
and remains a separate qualification boundary.

For diagnosis use `VOS_TEST_BOOTSTRAP_DIAGNOSTICS=1`,
`VOS_SHARED_RECOVERY_TIMING=1` and a narrow tracing filter. Phase diagnostics
are test-only and can affect timing while locks are held. Quiet optimized tests
are required before latency claims. Builds overriding release LTO/codegen are
diagnostic builds and must not be labeled the default release.

## Remaining review/release gates

The live checklist retains all mandatory gates: complete pending-scope recovery
across pruning, external root closure/export/reclamation, public lifecycle,
100,000 retained transfers, load/overload/failover/backup/restore, soak and
reproducible artifacts. External nodes are supplied later; local tooling/tests do
not close hardware acceptance. Public external Local, migration, dynamic
membership and other deferred capabilities remain outside v1.

Return severity, location, violated invariant, concrete scenario and regression.
Separate demonstrated defects from unqualified release gates.
