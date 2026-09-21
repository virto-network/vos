# Agent saga: current status

This is the single live plan. The complete Agent Architecture Saga remains the
objective; a review checkpoint is not a release.

## Branch boundary

- Implementation: `wip/ch08-runtime-directory`, mixed-recovery P1 fix
  `8a4751f9`, following reviewed checkpoint `2b1e7f56`.
- Reviewer: `saga/agents`, fast-forwarded to the P1 fix and this evidence update.
  Previous functional source: `42928ddc`; network test correction: `6de58f82`.
- Master is unchanged; nothing is pushed. Review read-only and apply findings
  on implementation to avoid conflicting fixes.
- Detailed integration chronology: `42928ddc:docs/agent-saga-status.md`.
  Its pending-run statements are historical, not additional live tasks.

## Implemented checkpoint

- Mixed retired/unfinished recovery now completes unfinished Creates before
  fresh retired-generation Authority reads. A temporary physical opening checks
  application evidence without inserting the generation into the serving set.
  Normal positive ACK/finalization/retirement releases its reservations; only
  then can fresh Authority Query/ACK run. The complete exact verified set opens
  last. Neither the reservation guard nor fresh-decision comparison is relaxed.
- This recovery-only staging repeats unfinished-generation opening at final
  admission; it is not a startup performance optimization or incremental-state
  redesign. Errors keep ordinary routes unavailable and require authoritative
  store reopening after completion writes, as before.
- Shared reservation/archive leases survive startup, recovery, serving and
  route shutdown. Discovery does not create missing records.
- Unfinished Create recovery verifies live publication and positive ACK,
  observes physical application, finalizes at Authority and retires the request.
  Interrupted application/finalization phases remain recoverable.
- Completed Create recovery validates finalized issuer evidence and obtains a
  fresh decision from the pinned Authority. It must exactly match the archive
  before the deferred generation opens; pruned publication history is no longer
  required, and archives alone never grant finality.
- Inventory and genesis reads share durable Invoke/ACK recovery. PAP2 binds the
  request kind, target, nonce and exact work. Inventory remains credential-
  authenticated. The public genesis decision endpoint is now correctly declared
  Query; arbitrary Linear work is not admitted as checkpoint-safe reading.
- Production reconciliation publishes separate generation-scoped Shared
  adapters. Closed handles retain no backend; lifecycle/archive ownership lasts
  until routes drain. There is no extra idle thread per Agent.
- Real bootstrap finalizes Catalog registration. The acceptance fixture no
  longer synthesizes completion with an empty authoritative actor directory.
  Test clocks advance at durable phases without weakening runtime ordering.
- Boxed SDK management variants decode in separate frames, fixing a compiled
  Authority stack fault without raising stack/gas limits or relaxing validation.

The bundled native-outer scenario passes in 103.89s: real bootstrap, interrupted
Create finalization, root audit, production readiness, signed actor installation,
supervisor preparation/Invoke/ACK, actual publication-ACK pruning, two restarts,
fresh actor Invoke/ACK after each, interrupted read-record clearing without
duplicate Invoke/ACK, and backend release.

Limits: the ordinary actor is a small executable fixture. Subsequent management
continues from an immutable genesis issuer checkpoint in that fixture. This does
not qualify a released Shared Create/Install coordinator, CLI, multi-node
replication, backup, or throughput. Shared host-wide locking and whole-state
execution remain.
Retired startup currently performs one fresh Authority Query/ACK per ordinary
generation. Its whole-state cost is not qualified at large directory sizes.

## P1 follow-up qualification

Review: `target/agent-review-2b1e7f56.qETYMA/REVIEW.md`. The review identified the
dependency cycle from control flow; the new regression creates two real signed
generations, crashes with one retired and the other unfinished, then uses the
production bootstrap/controller recovery entry points. Both Agent-ID orderings
must pass, with the fresh read blocked before recovery, exactly five new ordered
operations (finalization/two ACKs plus fresh Query/ACK), durable retirement,
and actual installed-actor Invoke/ACK on both recovered generations.

Logs under `.worktrees/ch08-c2-native/target/task-tmp/`:

- First mixed-generation/serving run: pass, 201.39s
  (`mixed-shared-native-serving.log`).
- Final Shared recovery group (including durable-retirement assertion):
  7 pass / 1 ignored, 264.33s (`mixed-shared-native-final.log`).
- Shared host regressions: 23 pass / 1 ignored / 1 listener-startup failure under
  restricted sockets, 338.40s (`mixed-shared-host-tests.log`). That one network
  test passes in the socket-enabled rerun below; do not label the restricted
  suite itself green.
- Recovery-only staging finality/lease/nonexposure test: 1 pass, 3.55s
  (`mixed-shared-staging-guard.log`).
- Two-host merge network regression with local sockets enabled: 1 pass, 6.40s
  (`mixed-shared-merge-network.log`).

These use a native outer runtime with bundled physical Authority/actor execution.
The previous full outer-PVM, workspace and CLI results below remain pinned to
their previous source; they are not fresh qualification of this host-only fix.
No SDK, guest source, wire format, artifact or admission guard changed.
Run the new regression with the pinned host toolchain and disk-backed
`CARGO_TARGET_DIR` / `TMPDIR`:

```sh
cargo +nightly-2025-05-09 test --offline --locked -p vos --lib \
  --features 'agent-runtime storage network http-ingress' \
  native_shared_mixed_retired_unfinished_restart_both_agent_orders -- --nocapture
```

Setting `VOS_AGENT_PROFILE_REFINE_MACHINES=1` selects the full outer PVM for
this same two-generation test; that mode has not been rerun for this follow-up.

## Previous checkpoint qualification (`2b1e7f56`)

Logs are under `.worktrees/ch08-c2-native/target/task-tmp/shared-genesis-query.L6OPEp/`
unless stated otherwise. Counts are scoped, not an additive release total.

| Check | Result | Log |
| --- | --- | --- |
| Bundled lifecycle and post-restart actor serving, native outer | 1 pass, 103.89s | `ordinary-serving-restarts-fixed.log` |
| Candidate retired restart, pruning and read-clear crash | 1 pass, 94.09s | `retired-read-crash-test.log` |
| Projection commit/recovery regressions | 2 pass, 4.07s | `projection-regressions.log` |
| Supervisor/adapters | 56 pass, 0.06s | `supervisor-regressions.log` |
| Production owner | 18 pass, 0.29s | `production-owner-regressions.log` |
| Release CLI/package pins | 18 pass, 1.03s | `release-cli-tests.log` |
| Full outer-PVM lifecycle | 1 pass, 1,938.39s (32m18s) | `full-physical-checkpoint.log` |
| Default workspace library tests, local sockets enabled | 2,406 pass, 6 ignored; vos 1,590 pass in 215.73s | `workspace-lib-final.log` |
| Network regression group, local sockets enabled | 11 pass, 3.50s | `network-final.log` |
| Full CLI binary tests, local sockets enabled | 278 pass, 20 ignored, 83.76s | `cli-binary-tests.log` |

Other logs in parent `task-tmp/`: Authority source 75 pass/2 ignored in 52.29s
(`shared-genesis-query-source-tests.log`); expanded read-context refusals pass
in 0.75s (`shared-genesis-query-negative-source.log`); read-envelope substitutions
pass in 2.29s (`shared-genesis-read-envelope-fixed.log`); SDK decoder 182 pass
(`shared-decoder-sdk-tests.log`). Decoder dispatch frame decreased from 10,632
to 232 bytes; selected variants retain their own frames. Disassembly and prior
failures remain in `shared-decoder-candidate.bmL0nN/`. Failed source split was
removed; its evidence remains in `shared-inventory-candidate.Jcfgpx/`.

Run `just test-shared-agent-publication` with disk-backed `CARGO_TARGET_DIR` and
`JUST_TEMPDIR`. It clears the candidate override and enables the bundled outer
PVM. Native-outer results do not substitute for that gate. Formatting/diff pass.
The full-PVM run executed exact functional source `42928ddc`; before checkpoint
`2b1e7f56`, its only subsequent source change was network test correction
`6de58f82`. This is a debug-profile
multi-phase correctness scenario, not a per-request or production throughput
benchmark. Its long duration does not close the performance acceptance gates.
Before workspace recovery tests, rebuild the generated custom guest with
`just build-agent-recovery-fixture`. The first workspace attempt retained 22
failures: 20 listener failures under sandbox socket restrictions and two tests
using an older generated custom guest. The isolated custom-runtime lifecycle
passes after rebuilding (4.65s, `custom-runtime-rebuilt.log`). The restricted
run and focused failure remain in `workspace-lib-tests.log` and
`custom-runtime-regression.log`; do not count them as passing evidence.
The socket-enabled retry passed 1,589 vos tests but failed the physical peer
collision test's exact Timeout expectation (`workspace-lib-network-enabled.log`).
Its isolated retry passed. Equal inbound/outbound deadlines can instead produce
Transport when the remote stream expires first. The test now accepts only those
two errors, retains the four-second bound and verifies the intended handler was
called once. Exact error mapping has a separate regression; production behavior
is unchanged. The final workspace rerun passes. Its counts exclude child-process
test summaries; the additional exact I/O-mapping assertion is qualified by the
separate final network run.

## Artifact boundary

`support/production-artifacts.toml` and `vosx/build.rs` own the exact pins:

- Runtime source `2ccfacb82089f804dbdbfea7ebfcabf377e7dde3`, unchanged ABI r19.
- Template source `c5e751e7bc7992782bf7403f73b254c64e5c26c6`.
- Builder `3c5e44c769d4cc16c1c13a9949c60a154f378a57`.
- Authority package BLAKE2b-256
  `c53fe4d37b6b65f164aa8dc66f677e747adb81e55b4e0603d41a5a67cf24a918`.
- Independent Authority PVM/package reproduction matches the candidate;
  Catalog is unchanged. Evidence in implementation:
  `target/agent-release-reproduction/genesis-query.MxmejS/`.
- Fresh disposable spaces only. Package identity and PAP2 changes do not
  qualify old-store migration, downgrade, relocation or backup/restore.

## Checkpoint handoff and next action

The P1 follow-up passes its scoped recovery/staging regressions; the prior
workspace/CLI/full-PVM gates remain source-specific. `saga/agents` is ready for
read-only follow-up review, not production sign-off. Artifacts are unchanged.
Use [the review guide](agent-saga-review.md) for the P1 fix and the prior groups:
qualification/performance/discovery; and Shared lifecycle/recovery/ownership/
artifacts. Identify `ac1b2860` separately as mechanical formatting. No new
scaling redesign joins this checkpoint.

Next: collect reviewer findings, reproduce them on the latest implementation,
then apply fixes there before advancing the review branch again. Choose the
next release gate explicitly from the list below; do not treat this checkpoint
as completion of the full saga or silently add all remaining work to a new batch.

## Remaining full-saga release gates

- Common lifecycle/execution/publication/ACK/recovery semantics across standard
  and genuinely different custom runtimes and every promised profile.
- Released Shared Create/Install, replication, restart and recovery through
  production lifecycle/CLI entry points, not fixture-only orchestration.
- Native backup/restore after bootstrap, complete Agent CLI and multi-profile
  acceptance; no broadening allowlists to enable unsupported paths.
- Bounded authenticated Authority/issuer reclamation; full expiry, retry,
  retirement, busy-shutdown and mixed-pending fault matrices.
- Private/Attested cryptographic and cross-runtime proof acceptance, portable
  positive ACKs and resource/capacity boundaries.
- Touched-state/incremental publication, bounded directory costs, maintenance
  isolation, prepared execution and remaining cross-Agent lock removal.
- Released-binary latency/throughput/resource budgets across independent versus
  ordered Agents, idle namespaces, growing directories, saturation and tails.
  Concurrency tests do not establish thousands-active-user capacity.
- Release-matched workspace tests/lint, clean-break checks, examples, operator
  documentation and reproducibility.

Historical optimized Local Create/Install were about 15.6/19.7s despite four
passing ten-second readiness checks. These are not current throughput data.
Whole-state transport/restoration/publication and replay remain costly.
Historical broad results (workspace 2,406; CLI 271 pass/20 ignored; Private crypto
16 pass) are source-specific. Clippy at `ac1b2860` failed with 358 diagnostics,
including 279 unused items; do not delete incomplete profiles to hide that debt.

## History and housekeeping

Full prior chronology: `efd0f5ca:docs/agent-saga-status.md` (710 lines);
integration chronology: `42928ddc:docs/agent-saga-status.md`. Older inventories:
`9fe6762e`; r19: `7bd66a7d`; r18: `c8028394`; original handoffs: `a1ebce16`.
Other handoff documents are checkpoint evidence/navigation, not competing plans.
Frozen clients, failure bytes, stores and logs are preserved. Scratch is
disk-backed, not `/tmp`. Remove obsolete code only after checking callers,
feature gates and replacement coverage.
