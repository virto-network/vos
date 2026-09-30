# Agent saga: review entry point

This is the sole reviewer handoff. [The live checklist](agent-saga-status.md)
owns release scope, open gates and deferred work. Review read-only and return
findings for the implementation branch; avoid competing fixes on the review branch.

## Review boundary

The user requested completing the live plan before the next whole-branch review.
This batch follows qualified checkpoint `b8d3a7e3`; its source boundary
is that checkpoint plus the implementation in the commit containing this guide.
Use the worktree diff until committed, then `git diff b8d3a7e3..saga/agents`
after verifying promotion and cleanliness. `master` remains `d2378274`.
The evidence qualifies candidate slices, not a release or customer capacity.

Use `git show b8d3a7e3:docs/agent-saga-review.md` for the preceding paired
checkpoint/retained-reply matrix. `6d3a4926` remains the earlier reviewed
recovery baseline, not the current work or next whole-branch review range.
Earlier backend, pruning and lifecycle chronology is in Git, not duplicated here.

Production Local remains image-based. Public fixed-three Shared startup/finality,
management, external ownership and pruning remain gated. Candidate tests do not
qualify customer load, released-daemon operation or artifact promotion.

## Current batch: invariants to review

AXJ1 is a streaming storage closure, not a transferable authority envelope. Its
independently selected source-head ID is checked before callbacks. Count,
history, per-class payload and wire budgets precede allocations; canonical order,
typed content hashes, exact mark/key membership, footer totals/archive identity
and finite-stream EOF must agree. Foreign Heads are bounded metadata only.
AJB1's format/ceilings and production image Local remain unchanged. The synthetic
65,537-history-node/blob test proves codec limits are independent of AJB1, not
100,000 signed Clerk transfers or a rooted external capacity workload.

Export requires an actual installed fixed-three common QC/local binding, exact
current heads/ordered boundary and detached transport. Newer Raft no-ops or
applied suffixes are refused. Lease and authority checks repeat after streaming.
Quota refusal does not revoke a healthy pin; physical export failures do.

Quarantine consumes a fresh, unexposed, intent-bound descriptor-pinned slot and
stages one typed record at a time. It owns a genuinely different physical store;
source heads are never published and invalid prefixes never pollute a live
permanent-history namespace. The read-only source view preserves actual scratch
instance/epoch, rejects mutators and rechecks initial heads before/after use.
Full existing root/mark audits precede a successful stage. This gives content
integrity only, not foreign QC authority or a serving availability token.

Foreign source replay separately authenticates the sealed roster's QC and the
original signed source binding. Local physical-store-ID checks remain unchanged;
no source-ID spoofing or conversion to `ValidatedExternalHead` is allowed.
Metadata-only rebind preserves certified C/L/M manifests and root-producing
contexts, replaces only empty destination Local metadata and publication
envelopes, and fences exact scratch/archive and destination store/epoch/heads.
Its physical claim is unsigned and cannot publish. The source predecessor
envelope is retained, not its obsolete root closure. Destination activation must
independently audit its own predecessor and target.

The healthy fixture uses the genuine network QC, signed Clerk/reference roots,
disk archive, actual quarantine and independently admitted destination genesis
and ledger foundation. It proves source/store substitution refusal and unchanged
destination heads/ledger, **not activation or catch-up**. Existing publication
fixtures remain offline: workers are isolated/retired after obtaining the real
quorum. Neither deadlines nor certificate/reservation guards are relaxed.

## This batch: source-specific qualification

All logs are under `.worktrees/ch08-c2-native/target`. Preserve failures and
do not inherit older counts after source changes. Frozen Rust source is the
complete staged diff over `b8d3a7e3`, including both new child modules, SHA-256
`717e383dcf382926d5e16307a198673358807ce7a8802d417171b4ec1775e786`
(`git diff --cached -- vos/src | sha256sum` before committing). Optimized
qualification is complete for this slice; separate debug evidence is labeled below.

| Check | Evidence and limit |
| --- | --- |
| Default optimized build | Passed, 13 m 11 s; `external-archive-preflight-release-build.log`, binary `release/deps/vos-59a730e87ba3c2af`. Default fat LTO/one codegen unit, no overrides. |
| Optimized core regressions | 264 distinct passed across journal store, Shared driver/host/commit/Raft/recovery and supervisor; 3 ignored cases not counted. `external-archive-preflight-release-focused-*.log`. One restricted listener failure passes with loopback permission (`external-archive-preflight-release-shared-host-loopback.log`); preserve the failure. The `recovery_staging` selector matched zero and is not evidence. |
| Optimized external physical matrix | All 7 passed, 288.13 s; `external-archive-preflight-release-physical.log`. Full outer/inner recompiler, file/network lifecycle, genuine archive/stage/source-audit/destination preflight, marker/journal/ledger checkpoint interruptions and retained reply through two checkpoints. No destination activation or customer-capacity claim. |
| Optimized image checkpoint/restore | All 4 passed, 130.82 s; `external-archive-preflight-release-image-checkpoints.log`. Common compaction/catch-up/reopen/continue and source/destination marker, journal and ledger interruptions. Default clean-runtime test adapter around physical Authority actor execution, not full outer PVM. |
| Supported feature builds | Guest-only `agent-runtime` (1.58 s), guest plus `experimental-state-blocks` (1.59 s), and `vosx --all-targets --features experimental-state-blocks` (18.20 s) passed; `external-archive-preflight-check-{guest,external-guest,cli}.log`. Offline, locked dependencies. |
| Formatting and diff | Both new child modules, physical fixture and Shared host pass pinned rustfmt. Parent journal store/replay/Shared driver retain exactly 1/1/2 baseline hunks from `b8d3a7e3`, byte-identical apart from line positions; no new formatter debt. Staged/unstaged diff checks pass. |
| Debug build | Passed; `external-archive-preflight-debug-build.log`, 26.17 s. Earlier stage build also passes (103 s). |
| Streaming codec | 10 passed; `external-archive-preflight-debug-codec.log`. Short I/O, malformed/truncated/duplicate/reordered/oversized frames, wrong source/scope, callback/writer failure, count/key budgets. |
| Real memory checkpoint codec | 3 passed on export source; `external-archive-debug-memory-{errors,roundtrip}.log`. Storage/codec evidence only, not external roots/scale. |
| Detached disk storage | 2 passed; `external-archive-preflight-debug-stage.log`. Fresh-slot intent/scope/existing-generation refusal, actual disk closure missing/extra refusal, read-only real-identity view and no exposure/publication. Image fixture, not external authority. |
| Metadata rebind | 3 passed; `external-archive-preflight-debug-rebind.log`. Common declarations preserved; scope/private-lane/divergent boundary and revision overflow refused. |
| Image path refusal | Passed on export source; `external-archive-debug-image-refusal.log`. No output or state change from candidate/default image owner. |
| Genuine external signed preflight | Passed, 80.42 s; `external-archive-preflight-debug-physical-healthy.log`. Full outer native PVM, real source QC/root/store, disk quarantine/source audit, independent destination genesis/foundation and unsigned rebind; both heads and destination ledger unchanged. Earlier export-only fixture (78.64 s) is narrower evidence. |
| Independent source review | No demonstrated defects in scoped export/stage/source-audit/rebind. Activation/recovery and capacity remain explicitly unqualified. |

Whole-fixture durations are not request latency, throughput or failover bounds.
One explicitly traced debug lifecycle passes (46.16 s),
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

An optimized traced lifecycle also passes (32.67 s),
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
