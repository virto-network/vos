# Agent saga: read-only checkpoint review

## Contract and immutable target

Review `e20cbb7697a9df43e9f9b1d86d5b6ca60c5e768e`. On 2026-09-20 local
`saga/agents` was fast-forwarded from `31b0cdbb` to this commit at the user's
request. Its worktree is clean. Nothing was pushed; master was not changed.

Perform a READ-ONLY review. Do not apply fixes, format files, change branch
tips, commit, or push. Return findings to the user; the implementation agent
will reproduce and fix them on top of the latest work, then run regressions.
Use an isolated test output directory if building: the shared target has
previously overwritten a historical test client. Do not use /tmp (RAM-backed),
real user spaces, or stores from a different runtime generation.

Two consolidated review ranges, not hundreds of separate commit reviews:

1. `31b0cdbb..f79f0e3d`: clean-break architecture/native integration/lifecycle.
2. `f79f0e3d..e20cbb76`: integrated recovery, UX, performance and qualification.

Together:241 files,+79307/-59066. Neither range is independently deployable.
For architectural context also inspect `master..31b0cdbb`:259 commits covering
the preceding packaged Agent/runtime, journal, authority and replica foundation.
The checkpoint is not production-ready and does not finish the complete saga.

The latest implementation is elsewhere: `wip/ch08-runtime-directory` at
`7470d600`,12 commits after this checkpoint plus substantial uncommitted work.
That work includes ordinary Shared genesis/publication/replay-backed finality,
staged recovery, row-backed actor/Authority state and a compiler relocation fix.
Do not silently include it in checkpoint findings or patch either worktree.
If useful, report whether a checkpoint finding appears addressed there, but
require a regression test before considering it resolved.

## Functional evidence and limits

Preserved release executable SHA-256:
`d11e52eed2e917a53e025536972f375363d30355d602dee2e9e23a3f6950e2cc`.
Bundle verification reran successfully. Historical full host-feature suite:
1878 passed,0 failed,4 ignored at implementation-identical `45ff53e0`.
Historical final-source CLI suite:255 passed,0 failed,19 ignored.
Ignored tests are not evidence of coverage. Docs after the implementation
checkpoint record some results, so the frozen docs alone are not up to date.

Fresh disposable Local/Public-policy smoke passes automatic bundled system
bootstrap, generated HTTP/SSH configuration, HTTP status, SSH keyscan, Local
Create, Counter Install, mutation, positive retirement, exact retry and value7
after daemon restart. SSH keyscan does not qualify authenticated shell access.
Create29s, Install35s; initial/restart readiness14s/18s and later25s/21s.
Mutation/read tests take22.50s/22.58s including retry. All test daemons exited;
listeners were checked closed. The unchanged10s readiness gate FAILS.

Evidence under repository-relative
`.worktrees/ch08-c2-native/target/task-tmp/current-latency.0NCyjT/`:
`probe.sh`, `probe.log`, `invocation-probe.sh`, `invocation-probe.log`,
`mutation-test.log`, `read-test.log`, `frozen-client-build.log` and daemon logs.
The rebuilt client comes from clean detached `.worktrees/agent-review-e20cbb76`;
preserved `frozen-vosx-test` SHA-256:
`b6537475ef2020b22f6681d2f31f16366ce9469e859b6c882f8ed773a5ec15e7`.

Known open requirements: ordinary Shared native creation/finality/restart;
authenticated bounded-record reclamation; complete crash/expiry/busy-shutdown
and Private/Attested/cross-runtime proof coverage; full workspace lint/release
gates; acceptable production latency and demonstrated load capacity. Newer
dirty-source artifacts are unsealed; compiled full-capacity Authority enrollment
still exceeds the read quota. Do not transfer old release passes to that source.

## Performance review: separate evidence from hypotheses

Latest-release historical phase analysis covers45 complete Authority queries:
Invoke+ACK accounts for76.70% of measured phase time, persistence+clear2.85%.
These are host-plus-guest wall-time spans, NOT pure interpreter CPU shares.
Six serial inventory queries after Install total16.272s, nearly all16.275s of
inventory work. This explains much of visible completion latency.
Evidence: `current-latency.KD6UwR/{up,mutation-up,read-up}.log` under the same
task-tmp root; detailed incremental phase totals in the latest handoff.

An OLDER `8716f6a7` CPU sample attributed51.63% to interpreter `run_inner`,
about19.91% to conformance gas dispatch/tick/feed, and18.50% to BLAKE2.
Its incomplete call stacks and different generation prohibit attributing those
percentages to the current release. Prepared execution and decode optimizations
already exist in the checkpoint: establish what they actually avoid before
recommending them again. Older replay measurements likewise identify runtime
load/run as dominant, but are not a current controlled benchmark.

Neither these phase measurements nor gas counts establish that ZK proof
generation causes current Local latency. Trace the actual configured execution
path and measure proving/verification separately from PVM execution. Do not
equate gas with CPU time or assume enabling a proof-related feature means every
request generates a proof. No thousands-of-users throughput test has passed.

Investigate these architectural choices, with measurements and tradeoffs:

1. Execution amplification: count outer-runtime and nested actor calls for one
   read, mutation, Create and Install, including authorization, inventory,
   acknowledgement, retirement and reconciliation. Separate load/preparation,
   execution, hashing/encoding and durability. Identify repeated identical work.
2. Read/control separation: can one authenticated versioned projection replace
   six serial queries? Can verified snapshots serve reads without a mutating
   invocation/ACK cycle? Specify freshness, revocation, scope and replay safety.
3. Serialization: which queues/locks/ordered Authority heads serialize unrelated
   agents? Measure queue wait versus service time. Consider per-agent isolation,
   batching or partitioning only with explicit ordering/atomicity constraints.
4. State transport: quantify bytes copied, decoded and hashed in full-state
   transitions versus the touched state. Assess bounded row/delta approaches
   against complete commitments, resource quotas and recovery correctness.
5. VM backend: profile this exact release's outer/nested work, prepared-cache hit
   rate and gas-accounting overhead. Evaluate available execution backends with
   exact gas/output/exit/state-isolation equivalence, not a weakened fast path.
6. Recovery: measure scaling with journal length and agent count; assess trusted
   checkpoints/incremental reconstruction without discarding authenticated
   history. A faster startup does not alone fix live-operation cost.
7. Capacity: separate cold/warm and read/write/control workloads, same-agent
   versus many-agent contention. Report throughput, p50/p95/p99, CPU, memory,
   queue depth and saturation under fixed hardware/state sizes. Concurrency is
   not throughput; do not extrapolate thousands of users from single-user tests.

Locate the path through `vosx/src/commands/space/clean_startup.rs`, lifecycle
and invocation handlers; `vos/src/agent/{clean_bootstrap,local_journal_driver,
shared_journal_driver,execution,machine,replay}.rs`; SDK runtime;
`actors/system-authority`; and `pvm/runtime`. Verify names at the target commit.
Do not weaken authentication, exact retries, gas accounting, state commitments,
retirement or crash consistency to improve a benchmark.

## Requested findings format

For each finding: severity, exact commit/file/line, concrete scenario, observed
versus expected behavior, violated invariant, reproduction/test evidence,
proposed correction and likely overlap with newer work. Clearly label an
architectural hypothesis versus a demonstrated bug. Rank performance proposals
by measured cost, expected impact, semantic risk and validation needed. Return
findings and suggested tests only; the primary agent owns all fixes on latest.
