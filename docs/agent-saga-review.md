# Agent saga: review entry point

This is the sole reviewer handoff. [The live checklist](agent-saga-status.md)
owns release scope and deferred work. Review read-only; return findings for the
implementation branch rather than applying competing fixes on the review branch.

## Checkpoint boundary

| Purpose | Branch / boundary |
| --- | --- |
| Reviewed baseline | `6c1bab2a`, the pending-read custody checkpoint |
| Implementation | `wip/ch08-runtime-directory`, synchronized with this checkpoint; apply later findings here |
| Reviewer target | `git diff 6c1bab2a..saga/agents`; verify the branch head first |
| Scope | Repeated-input evidence/retry admission and expired unadmitted registration; no production cutover |
| Mainline | `master` remains `d2378274`; no automatic push or mainline change |

This is a qualified review-fix checkpoint, not a release. Verify both branch
heads and clean working trees before review. Production multi-node startup,
public Shared management and pruning remain gated; production Local stays
image-based. No guest ABI, artifact pin or execution-authority change is included.

The previous batch's design, 16 exact-release physical fixtures and 238 focused
passes are historical baseline evidence, not qualification of these changes:
`git show 6c1bab2a:docs/agent-saga-review.md`. Do not duplicate that chronology here.

## Two review fixes

### Repeated input must not replace canonical recovery evidence

Custody keeps the first physically validated terminal Invoke and first positive
ACK. A later valid Ordered entry can repeat the same input and return a different
result, including a negative ACK; it must neither overwrite the original capsule
nor release its delivery obligation. Physical evidence is checked against the
exact Ordered position and input, using a bounded position-keyed result cache,
not the latest result for that input. Retained response lookup prefers the proven
capsule over a later repeated-input result.

Same-key reservation and already-reserved submission now independently require a
fresh quiescent committed/applied prefix under the per-Agent proposal guard.
An ambiguous uncommitted append retains its exclusion; a second caller cannot
append behind it merely because both callers already hold the same key.
The worker barrier is sampled again after draining committed work. Catch-up,
election or tail movement between samples is retryable unavailability, with the
reservation retained; a contradictory applied cursor against a stable sample
still fails as corruption.

This prevents invalid retries; it does **not** repair an old raw log containing
the same immutable Ordered entry at different Raft positions. Existing physical
publication binding still rejects that history. The regression repeats the same
ReplayInput in a new valid successor Ordered entry after the original commits;
it does not weaken those bindings or manufacture a publication.

### Unadmitted custody needs fresh delegation or exact execution evidence

Before a new owner registration mutates a reservation or appends a row, the
leader checks the original scoped delegation against current trusted time, or
requires exact retained terminal Invoke/positive-ACK evidence. It repeats the
check after validation/encoding immediately before append. A custody-only slot
is not execution evidence and does not waive freshness for another owner.

An exact already-applied owner registration remains an idempotent retry after
expiry. That does not authorize unseen execution or permit custody release.
An expired competing unadmitted WAL stays byte-identical and cannot acquire the
leader's exclusion or block a different fresh request by registering itself.

Review particularly: exact position/outcome binding after reopen; first-response
precedence; negative ACK non-retirement; both reservation and submission barriers;
freshness at append; and the distinction between applied custody and execution
authority. Existing legacy recovery, owner-only replacement, reservation ownership
and fresh post-peer-I/O evidence checks must remain intact.

## Qualification status

The earlier timeout fixture incorrectly reused an immutable Ordered entry at a
new Raft position and was correctly rejected. Its failure remains in
`custody-review-debug2-candidate_registered_same_leader_timeout_and_duplicate_rows_survive_reopen.log`.
The corrected fixture first proves timeout retries append nothing, then commits
valid repeated-input successor entries; qualification is below.

The first optimized matrix passed 17 of 18 cases. The former-leader pre-Invoke
case exposed a stale worker-snapshot comparison after successful follower
catch-up (`custody-review-physical-delegation.log`: 7 passed, 1 failed).
Post-drain barrier revalidation addresses that race without relaxing equality,
admission or deadlines. All 11 targeted final-source physical reruns pass. The
seven other checkpoint/custody cases remain explicitly earlier-source evidence; they
must not be counted as a full final-source 18-case rerun.

Do not inherit baseline counts or treat ignored/socket-restricted tests as passes.

| Check | Source-specific evidence |
| --- | --- |
| Exact-release build and focused units | Final build passed in 12m00s; 278 passed, 4 existing ignored, including all 35 Local journal tests and the deterministic barrier-drift test; `custody-review-final-release-build.log`, `custody-review-final-release-*.log` |
| Same-leader timeout, valid repeated inputs and reopen | Final source passed, 41.36 s; `custody-review-final-physical-candidate_registered_same_leader_timeout_and_duplicate_rows_survive_reopen.log` |
| Expired competing unadmitted intent, exact-release rerun | Final source passed, 45.33 s; `custody-review-final-physical-candidate_expired_unadmitted_intent_cannot_acquire_custody_after_election.log` |
| Final-source delegation and follower-delivery regressions | All 8 delegation/compatibility cases passed, 172.13 s; `custody-review-final-physical-delegation.log`. Follower delivery passed, 171.88 s; `custody-review-final-physical-candidate_registered_follower_delivery_survives_leader_reads_and_repeated_checkpoints.log`. |
| Previous checkpoint/custody physical regressions | 8 passed in 649.62 s immediately before the barrier-race correction; `custody-review-physical-common.log`. Follower delivery was rerun above; the other 7 are earlier-source evidence only. |
| Supported feature checks, default CLI and daemon smoke | Final minimal std and no-std experimental runtime passed; CLI 300 passed / 45 existing ignored (80.46 s); smoke 2 passed (13.87 s); `custody-review-final-feature-*.log`, `custody-review-final-cli.log`, `custody-review-final-shutdown-smoke.log` |
| Changed-range formatting and whitespace | Six Rust files pass changed-range rustfmt checks; `git diff --check` passes; baseline formatting left untouched |

Whole-fixture durations are not request latency, throughput or failover bounds.
Whole-manifest decoding/signature/provenance costs remain unqualified. The earlier
call-local proof reuse and staged writer publication do not establish capacity.

The pre-existing `std storage` without-network embedding build still has missing
network-gated route-adapter symbols. It is outside the approved v1 host/CLI
combination and is not silently counted as a supported passing feature check.

## Reproduction

Use the implementation worktree and disk-backed temporary storage, not `/tmp`:

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
  --lib agent::clean_bootstrap::tests::physical::common_checkpoint:: \
  -- --ignored --test-threads=1 --nocapture
```

The common-checkpoint filter includes the two new regressions as well as the
previous custody and common-checkpoint cases. Run the same command with filter
`agent::clean_bootstrap::tests::physical::candidate_projection_` for the six
delegation cases and two stale-registration/legacy-execution races.

Loopback fixtures need socket permission. Do not overlap physical qualification
with compilation. Verify the Authority candidate SHA-256:
`a88872c5de59d97905ccfb043268fa8ef6aea5a1c0e354b9c7c3255fed05e2ed`.
Another digest at the same path cannot inherit evidence. This is the unchanged
signed-delegation candidate, not bundled-artifact promotion. Release pins belong
to `support/production-artifacts.toml` and `vosx/build.rs`.

The default fixture uses the native clean-runtime test adapter around physical
Authority actor execution. Full outer-PVM execution additionally requires
`VOS_AGENT_PROFILE_REFINE_MACHINES=1`; disable instruction attribution with
`VOS_AGENT_DISABLE_REFINE_ATTRIBUTION=1` for timings. The default fixture cannot
substitute for full-outer-PVM or released-daemon qualification.

For diagnosis only, enable `VOS_TEST_BOOTSTRAP_DIAGNOSTICS=1`,
`VOS_SHARED_RECOVERY_TIMING=1` and the fixture tracing filter. Diagnostic builds
with `profile.release.lto=false` and `profile.release.codegen-units=16` are not
the default release and must be labeled separately.

## Remaining release boundary

The [live checklist](agent-saga-status.md) retains the release gates. In particular,
post-admission expired-unseen terminal resolution, legacy/management recovery
across pruning, and whole-manifest performance are **not qualified by these fixes**.
Registration timeout followed by overwrite still needs its stated liveness
qualification; preserving an unadmitted exclusion is not proof of recovery.

External Shared root closure/export/reclamation, public lifecycle, Clerk with
100,000 retained transfers, released workload/failure/backup/restore, soak and
reproducible artifacts remain open. External nodes will be supplied later;
local tooling/tests do not close that hardware acceptance gate. No release date
or completion percentage is established.

Return severity, location, violated invariant, concrete scenario and regression.
Separate demonstrated defects from unqualified release gates.
