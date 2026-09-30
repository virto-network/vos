# Agent saga: review entry point

This is the sole reviewer handoff. [The live checklist](agent-saga-status.md)
owns release scope, open gates and deferred work. Review read-only and return
findings for the implementation branch; avoid competing fixes on the review branch.

## Review boundary

The user requested completing the live plan before the next whole-branch review.
This batch follows qualified checkpoint `64a687dc`; its source boundary
is that checkpoint plus the implementation in the commit containing this guide.
Use the worktree diff until committed, then `git diff 64a687dc..saga/agents`
after verifying promotion and cleanliness. `master` remains `d2378274`.
The evidence qualifies candidate slices, not a release or customer capacity.

Use `git show 64a687dc:docs/agent-saga-review.md` for the preceding expiry,
overwrite and signed Clerk matrix. `6d3a4926` remains the earlier reviewed
recovery baseline, not the current work or next whole-branch review range.
Earlier backend, pruning and lifecycle chronology is in Git, not duplicated here.

Production Local remains image-based. Public fixed-three Shared startup/finality,
management, external ownership and pruning remain gated. Candidate tests do not
qualify customer load, released-daemon operation or artifact promotion.

## Current batch: invariants to review

External Shared common checkpoint admission requires the genuine fixed-three QC,
the exact signed local node/store binding, fresh authenticated genesis and the
current physical foundation. Root-producing runtime/cursor provenance survives
compaction. The slot opener audits durable and staged endpoints read-only before
any staged-head action; the driver independently admits its serving pin. Raw
genesis replay cannot authenticate a later common checkpoint. Marker/journal/ledger
recovery completes only the exact signed predecessor/target. Missing block or
physical metadata reads revoke cached availability; restored bytes require a new
owner audit. The generic storage default refuses external publication unless an
explicit audited adapter implements it.

Ordinary signed Direct Linear/LinearizableQuery retained replies use the existing
public `InspectInvocation`, never an actor Invoke preview or fabricated historical
input. The guest must return unchanged state/roots and no block changes. The opaque
local proof binds physical owner epoch/head, request kind, work/auth commitments,
trusted inspection clock, authenticated current claim and exact terminal outcome.
Only explicit `NotReady` means absence. Invalid work/auth, I/O and execution errors
cannot authorize fresh fallback. Completed ACK still requires a real retirement;
acknowledged Invoke refuses rerun. Retained authorization is checked at its original
acceptance, not renewed or rejected merely because it expired later.

Strict-current availability is additive. Its authenticated message has the same
bounded claim payload but distinct tags/pending reply type; historical replies
cannot satisfy it, and old historical availability remains unchanged. Peers bind
the exact current C/L/runtime/root projection to an installed QC/local binding or
an actual current applied anchor. They do not execute another guest. A voter
majority uses the existing bounded Availability pool. No host/proposal lock crosses
peer I/O; lifecycle leases remain held. Final fingerprint/root/proof and monotonic
trusted-clock validation precedes delivery. Legitimate advancement is retryable
unavailability, not corruption. No historical index or guest ABI change is added.

The new physical fixtures collect a real network certificate while all voters
are attached, then isolate Raft and retire followers before source, and publish
offline. Crash assertions check consumed faults and exact canonical marker/head
endpoints. They qualify offline publication/recovery, not coordinated live
checkpoint/catch-up. Earlier failures correctly refused a certificate when the
remaining live quorum elected during source publication; guards/deadlines are
unchanged. Signed Clerk bootstrap/accounts/transfer and reference kernel checks
remain part of every fixture. Public startup, export, catch-up and reclamation
remain gated; no candidate artifact or experimental Local promotion is included.

## This batch: source-specific qualification

All logs are under `.worktrees/ch08-c2-native/target`. Preserve failures and
do not inherit older counts after source changes. Final optimized Rust source
is the tracked diff over `64a687dc` with SHA-256
`8f5ee40c5b051ef060d5f81f455a098fdde2de1b92ba9c00c346d7597a309b3a`
(`git diff -- vos/src | sha256sum` before committing). The separate unreferenced
archive draft is not compiled or qualified by this matrix.

| Check | Evidence and limit |
| --- | --- |
| Default optimized build | Passed, 14 m 52 s; `external-common-retained-release-final-build.log`, binary `release/deps/vos-59a730e87ba3c2af`. Default fat LTO/one codegen unit, no overrides. |
| Healthy external certified checkpoint/reopen | Passed, 62.63 s; `external-common-retained-release-final-certified_checkpoint_reopen_and_continue.log`. Heads/metadata/predecessor/target-block refusal and revoked-pin recovery, raw opener refusal, genuine QC/local bindings and fresh post-checkpoint Invoke/ACK. |
| Retained replies through two checkpoints | Passed, 47.14 s; `external-common-retained-release-final-retained_reply_survives_two_checkpoints.log`. UnACKed exact reply, authorization expiry, unchanged-slot retry, substitutions, missing blocks, wrong-kind/clock/root proof refusals, real ACK and exact post-second-checkpoint ACK. |
| Exact marker/journal/ledger cuts | All three passed, 53.21/49.17/49.82 s; `external-common-retained-release-final-checkpoint_recovers_{marker,journal,ledger}_crash.log`. Canonical signed endpoint assertions prove each actual cut, not merely owner absence. |
| Existing external network/file lifecycle | Passed, 38.37/25.66 s; `external-common-retained-release-final-install_invoke_ack_reopen.log`, `-file-lifecycle.log`. Full outer-PVM signed Clerk, reference roots and lost-response/reopen behavior. |
| Earlier boundary failures | Preserve `external-common-debug-healthy.log`, `external-common-debug-healthy2.log`, `external-common-retained-debug-healthy.log`. New physical index/term with unchanged logical roots correctly refused the older certificate. |
| Existing image common checkpoint/recovery | Four cases passed, 37.84/40.13/38.66/37.58 s: compaction/catch-up/reopen and source/destination marker/journal/ledger cuts. `external-common-retained-release-final-candidate_common_checkpoint_*.log`. Default clean-runtime adapter around physical Authority actor, not full outer PVM. |
| Custody/expiry regressions | Four cases passed: same-leader duplicate retry 54.62 s; expired-unadmitted intent 58.96 s; offline-origin expiry/reopen 156.20 s; competing durable intent 33.26 s. Final logs use the exact `candidate_*` test names. Same adapter boundary as above. |
| Focused same-source checks | 143 distinct passed, plus one ignored Shared-host case not counted. `external-common-retained-release-final-focused-*.log`: 5 retained classifiers, 2 pin-lifetime negatives, current/historical wire matching, checkpoint provenance/storage refusal, Shared commit/Raft/recovery/staging, image hosts and supervisor. Overlapping filter counts deduplicated. |
| Bounded availability-pool isolation | Passed, 0.03 s; `external-common-retained-release-final-pool-isolation-selected.log`. Current/historical confirmation still progresses with application outbound capacity exhausted. The earlier ignored-only selector matched zero tests and is not evidence. |
| Features/CLI | Guest and external-guest checks pass (2.06/2.08 s); external CLI all-target check passes (29.01 s). Ordinary CLI suite passes with loopback permission: 300 passed, 45 ignored, 83.22 s; `external-common-retained-final-vosx-test-loopback.log`. All 16 restricted-run failures were socket bind `PermissionDenied`; preserve `external-common-retained-final-vosx-test.log`, not a pass. |
| Format/artifacts | All eight tracked Rust files parsed with pinned rustfmt; remaining deltas are identical HEAD formatting debt only. Diff checks and candidate SHA-256 pins pass; no release pins were modified. |

Whole-fixture durations are not request latency, throughput or failover bounds.
The new path adds a read-only inspection for eligible fresh external calls;
measure that integrated cost. Full closure audits repeat on certified reopen,
and large-dataset maintenance costs remain unqualified.

Quiet single-call network observations on this source: transfer Invoke 854,255 us;
post-reopen state-root Invoke 812,063 us. These exclude the following ACK and are
not a distribution, warm/cold comparison, throughput or tuning pass. Both outer
and inner use the recompiler. Source inspection shows at least four outer runs
for a fresh routed leader call (directory, retained inspection, preview, apply),
with independent follower application. VM setup, locks, persistence and quorum
are not yet fully attributed; the isolated fixture currently lacks a tracing
subscriber for its existing VM counters. Do not claim the actor or VM dominates.

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
