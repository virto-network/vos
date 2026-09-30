# Agent saga: review entry point

This is the sole reviewer handoff. [The live checklist](agent-saga-status.md)
owns release scope, open gates and deferred work. Review read-only and return
findings for the implementation branch; avoid competing fixes on the review branch.

## Review boundary

The user requested completing the live plan before the next whole-branch review.
This batch follows reviewed baseline `6d3a4926`; its qualified source boundary
is that baseline plus the implementation in the commit containing this guide.
Use the worktree diff until committed, then `git diff 6d3a4926..saga/agents`
after verifying promotion and cleanliness. `master` remains `d2378274`.
The evidence qualifies candidate slices, not a release or customer capacity.

Use `git show 6d3a4926:docs/agent-saga-review.md` for the baseline's source-specific
test matrix and two reviewed fixes. `git diff 6c1bab2a..6d3a4926` is a historical
review-fix range, not the current work or next whole-branch review range.
Earlier backend, pruning and lifecycle chronology is in Git, not duplicated here.

Production Local remains image-based. Public fixed-three Shared startup/finality,
management, external ownership and pruning remain gated. Candidate tests do not
qualify customer load, released-daemon operation or artifact promotion.

## Current batch: invariants to review

Explicit expiry is a separate host recovery terminal for an admitted delegated
read with **no committed Invoke or published effect**. It never fabricates an
Invoke/ACK, renews authorization or clears evidence based on time alone. Two
authenticated voters bind the exact request, complete preterminal manifest,
committee, trusted time, semantic Ordered predecessor and physical prefix.
Existing Invoke evidence or an unresolved suffix refuses expiry.

The driver authenticates its expiry floor on open and advances it through verified
application. Hot manifest reads must agree with that floor. An exact applied
terminal or byte-identical certified baseline authorizes pending-record cleanup;
a peer boolean does not. Durable PAP2 cleanup checks the full query/work/auth and
optional signed owner registration under proposal exclusion. Competing unadmitted
WAL bytes stay unchanged. Owner-only replacement requires durable prior cleanup.
The floor fences old admission after terminal replacement, but does not preserve
an indefinite archive of old receipts or authorize clearing an unadmitted WAL.

Timed-out registration exclusion is released only after a stable applied prefix
proves an actual higher-term overwrite of that exact append. Preserve the prior
owner's reservation and original WAL. An admitted same-work request keeps custody;
missing/compacted rows and timeout alone do not prove overwrite.

External Shared candidate ownership uses the existing signed Linear-only contract.
Common genesis ancestry requires the exact authenticated initial external
checkpoint; do not normalize later claims or weaken majority availability.
Fresh stores are required for candidates created before that correction.
Durable block closure must precede root publication; missing blocks invalidate
serving availability. Public startup/Local selection retain their existing gates.

The network fixture now exercises signed Clerk bootstrap, two accounts and a
settled transfer, exact lost-response/reopen retry, ACK and reference kernel-root
comparison. That slice passes on this batch's corrected optimized source;
it does not qualify the customer workload.
The next external checkpoint slice initially requires ordinary Clerk results to
be acknowledged. Compaction removes historical Raft anchors: retained Ordered
blobs and a new common-root certificate alone cannot authenticate old ordinary
reply availability. The selected retention design is typed, exact-request-bound guest
inspection under the current common root, using the existing inspection contract
without a historical index or guest ABI change. It remains unimplemented and
unqualified; a newer certificate alone is not proof of the exact old outcome.

Candidate `ProjectionExpired` now maps to the existing nonretryable route
rejection, not retryable transport unavailability. Its focused optimized regression
passes; public integration is pending qualification. No new public API variant
is required. This remains part of the existing promotion gate.

## This batch: completed source-specific qualification

All logs below are under `.worktrees/ch08-c2-native/target`. Preserve failures
and do not inherit older counts after source changes.

| Check | Evidence and limit |
| --- | --- |
| Corrected default release build | Passed, 14m03s; `expiry-corrected-release-build.log`, binary `release/deps/vos-59a730e87ba3c2af`. Includes the call-local audit reuse, per-Agent expiry singleflight, terminal routing and bounded fixture retry. Physical qualification is separate. |
| Focused optimized matrix | All 188 passed, none ignored; `expiry-corrected-unit-*.log`. Recovery manifest, Raft ledger, staging, protocol/network/shared transport, Local driver/keyed paths, supervisor and exact host/mapper/replay regressions. |
| Supported feature checks and conditional prefix | Guest `agent-runtime` 6.76 s; external guest 1.95 s; production `vosx` with external feature 23.50 s. `expiry-corrected-check-guest.log`, `-guest-external.log`, `-vosx.log`; compile checks, not deployed CLI qualification. Conditional-prefix worker regression: one passed, `expiry-corrected-worker-prefix.log`. |
| Corrected optimized expiry/offline-origin/minority/common-import | Passed, 130.05 s; `expiry-corrected-release-offline.log`, quiet with diagnostics disabled. Covers offline expiry, minority noncleanup, actual follower RPC expiry, genuine two-of-three common certificate retry, exact terminal/floor export-import, pending-record preservation and reopen cleanup. This is candidate-slice qualification, not complete release qualification. |
| Competing durable intent | Passed, 25.94 s; `expiry-corrected-release-candidate_expired_dependency_preserves_competing_durable_intent.log`. Exact unadmitted WAL survives the admitted dependency's terminal recovery. |
| Overwritten registration | Passed, 57.80 s; `expiry-corrected-release-candidate_overwritten_registration_releases_remote_exclusion_without_reattachment.log`. Real election/registration RPC; completion uses the peer handler because this fixture lacks the node-loop dispatcher. |
| Same-leader timeout and duplicate rows | Passed, 51.58 s; `expiry-corrected-release-candidate_registered_same_leader_timeout_and_duplicate_rows_survive_reopen.log`. Exact custody survives repeated rows and reopen. |
| Signed full-outer three-network Clerk lifecycle | Passed, 33.92 s; `expiry-corrected-release-three_network_replicas_external_clerk_install_invoke_ack_reopen.log`. Signed bootstrap, two accounts and settled transfer match the reference kernel root; exact lost-response/reopen retry, ACK and complete three-replica claims pass. |
| Three-file external lifecycle/missing block | Passed, 23.86 s; `expiry-corrected-release-three_file_replicas_external_clerk_install_invoke_ack_reopen.log`. Complete claim comparison, reopen and missing-block refusal. |
| Pre-correction optimized expiry failure | Failed, 94.93 s; `expiry-resume-release-offline.log`. Successful votes at about 1.25–1.30 s were delayed by redundant capacity audits to 2.23–2.29 s beyond the unchanged 1.8-s wait; retries amplified the queue. The correction preserves deadlines, quorum, freshness and proof requirements. |
| Effective formatting/whitespace | Full formatter-output comparison parses all 16 changed Rust files, including the new expiry fixture, and finds no hunks intersecting changed code; `git diff --check` passes. Baseline-only debt is preserved; narrow hunk ranges alone are insufficient. |

Whole-fixture durations are not request latency, throughput or failover bounds.
The final network fixture samples bootstrap/account Invoke+ACK at 819/732/809 ms,
transfer Invoke at 655,052 us and post-reopen `state_root` Invoke at 694,568 us.
The latter samples exclude ACK and reopen time; these are single samples, not a
load result or latency distribution. The optimized passes do not qualify all
pending scopes or public lifecycle. Preserve earlier failure logs without
inheriting their source-specific outcomes.

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
cargo +nightly-2025-05-09 test --release --offline --locked -p vos \
  --features 'agent-runtime storage network http-ingress experimental-state-blocks' \
  --lib agent::clean_bootstrap::tests::physical::recovery_expiry:: \
  -- --ignored --test-threads=1 --nocapture
```

Run physical qualification separately from compilation, with loopback socket
permission. The common-checkpoint filter includes overwrite and earlier custody
regressions. For external lifecycle use
`agent::clean_bootstrap::tests::physical::external_shared::` and additionally set:

```sh
export VOS_AGENT_PROFILE_REFINE_MACHINES=1
export VOS_AGENT_DISABLE_REFINE_ATTRIBUTION=1
export CLERK_AGENT_PACKAGE="$CARGO_TARGET_DIR/clerk-agent-canonical/clerk-ledger.vos"
```

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
