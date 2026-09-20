# Agent saga: current status

This is the authoritative status and remaining-work index. Other Agent handoff
documents are navigation or evidence, not competing plans. Updated 2026-09-20.

## Branches and qualification

- Reviewer branch: `saga/agents`, integrated checkpoint `16adf95e`.
- Implementation: `wip/ch08-runtime-directory`, recovery source `a1ebce16`,
  followed by artifact checkpoint `f9c362cb`, the lifecycle-envelope fix, and
  control-worker isolation `caeeac18`, not yet on the review branch.
- Master is unchanged; nothing has been pushed.
- Neither current branch is production-qualified. The full Agent Architecture
  Saga remains the objective; these checkpoints do not narrow it.
- Bundled artifacts and pins match the r18 source; independent reproduction and
  all 21 bundled Local host tests and CLI bundle verification pass. Disposable
  debug-binary bootstrap, HTTP/SSH, Create/resume, Install and restart pass;
  the ten-second readiness gate still fails. This is a review checkpoint only.
  Source tests and older preserved releases do not qualify a deployable binary.

Resolve branch tips with Git before review; these identifiers describe this
document's checkpoint, not a promise that a moving branch never advances.

## Implemented and evidenced

The review checkpoint includes bounded concurrent supervisor dispatch,
per-Agent Local execution leases, targeted actor lookup, reused directory
audits, inline backend release on retirement, refresh reconciliation outside
the serving coordinator, and catalog validation outside the registry mutex.
Authentication, exact retries, same-Agent ordering and ownership checks remain
required. See the [review guide](agent-saga-review.md).

The newer recovery source adds the r18 public management-history query. Every
Local reopen physically executes the admitted runtime, requires unchanged
state, and compares the returned history commitment with the host projection.
The original substituted-history regression now passes. Real custom-runtime
execution exercises a different state layout; test-only scripted fixtures now
retain actual history instead of bypassing the recovery check.

Source evidence: 172 SDK tests, 21 Local host tests, 13 real custom-runtime
tests (including compiled execution), and 56 supervisor/adapter tests pass.
The explicit fresh-build Local recipe passes. `vosx` checks. These are scoped
results, not a complete workspace, release, performance or Shared qualification.
Exact logs and limitations: [recovery contract](agent-recovery-contract.md).

## Current work and next checkpoint

1. Artifact reproduction and repinning are complete: the runtime and both system
   templates rebuild byte-for-byte from immutable r18 source. The 21 bundled Local,
   four package-admission, 18 release-package and three local-config tests pass.
2. The physical lifecycle probe exposed and verified a fix for stale 1 MiB
   retained-request/HTTP limits. Package endpoints now use protocol bounds with
   two process-wide upload permits; ordinary HTTP limits are unchanged. All 52
   HTTP tests and 105 clean CLI tests pass (one opt-in daemon test remains ignored).
3. Review this integrated recovery/artifact/envelope checkpoint using the
   [review guide](agent-saga-review.md). The reviewer reports findings; fixes
   remain on the implementation branch. No production sign-off is implied.
4. Next: consolidate control-worker isolation with reduction of repeated full
   inventory invocation/acknowledgement costs, without weakening freshness or ordering.
   Qualify the resulting binary with latency, independent-Agent isolation and
   recovery tests. Continue the remaining full-saga gates below.

The newer implementation moves lifecycle dispatch and periodic reconciliation
into one bounded control worker; the node loop only observes worker health.
Ordering, authenticated projections and complete publication remain owned by
the existing production owner. Cancellation hides admission without acquiring
that busy owner, drains/rejects queued requests, and reports worker failures at
collection. Idle-exit accounting includes active control work. This addresses
scheduling isolation, not the number or cost of physical inventory executions.
Keep the reviewer checkpoint stable until the next consolidated performance batch.

Control-worker evidence under the shared target's `task-tmp`: 19 owner/worker tests
in `control-worker-complete-tests.log`, 56 supervisor/adapter tests in
`control-worker-supervisor-tests.log`, and seven targeted node tests in
`control-worker-node-tests.log`. The pre-idle-accounting debug worker binary
(`9345a05e6aba0a3227daf5b204c9251894ac032fee1df17ab0ddb892a2de55ca`)
passes fresh bootstrap/HTTP/SSH/Create/Install/restart/shutdown in
`control-worker-lifecycle.Pn9l9R/probe.log`: readiness 26s, Create 52s, Install 71s,
restart 52s. This is neither a latency improvement nor release qualification.
The final idle-accounting binary
(`c766fa97f20a9fdc535fc404c7b3393210f2985827fb270e00015a5bba545bfd`)
also passes reopen and `space up --once` (`idle-mode.log` in the same directory).
That log measures six inventory queries at 26.453s; they still perform full
invocation and acknowledgement. This is the next cost to address, not evidence
that background scheduling alone made lifecycle operations fast.

Source commit `17fb38e9` removes duplicate Standard-runtime restoration from
management, invocation, resume and acknowledgement execution. Structural decode
feeds one fully validating restoration; the public state decoder remains fully
validated. `single-restore-wire-verified.log` records 108 passing wire tests
(four ignored), including identity-mismatch rejection and empty/sparse-state
equivalence. The optimized candidate guest builds; three physical comparison
tests in `single-restore-physical-cost.log` preserve exact outputs. Deterministic
gas falls from 403,857,168 to 401,982,082 for fresh invocation, 344,973,012 to
338,562,926 for retry, and 219,057,808 to 212,649,830 for acknowledgement on the
approximately 793 KiB fixtures. This modest reduction does not solve lifecycle
latency. Candidate ProgramId:
`d1569e3fbbbd01da0c6fc98be51129202ecee235a9c46500be36bf967380e76f`.
Logs/candidate are under the shared target's `task-tmp`; bundled artifacts and
the reviewer branch remain unchanged. Remaining work is reduced full-state and
projection execution cost, followed by artifact reproduction and qualification.

Source commit `1ef5f703` replaces three quadratic restoration operations:
remaining-forest scans/vector removal, duplicate installation-ID scans, and
rebuilding artifact usage for each actor. Indexed readiness preserves first-ready
ordering; a set and incremental hash/length accounting retain the same checks.
All 52 Standard tests pass, including the 4,096-actor round trip and a new
64-actor multi-branch forest with duplicate-ID, conflicting-length and cycle
rejections (`indexed-restore-standard-final.log`). All 108 wire tests pass
(four ignored) with candidate comparisons enabled
(`indexed-restore-wire-physical.log`). Optimized candidate ProgramId:
`413558cfebdadca3a5aaa438a2daeef425aa33e67309909d72e9313dfb03a07b`.
The small-directory physical fixtures retain exact outputs and lower gas than
the bundled baseline, but use slightly more gas than `17fb38e9` due to indexing
overhead. This removes specific quadratic operations, not whole-state execution.
Bundled artifacts and the reviewer branch are still unchanged.

An opt-in physical scaling regression now compares that candidate against the
bundled guest for a one-entry directory inspection, requiring exact output and
unchanged state. `directory-scaling-physical.log` records all cases passing:

| Stored actors | Bundled gas | Candidate gas |
| --- | ---: | ---: |
| 1 | 18,319,802 | 16,515,538 |
| 32 | 96,042,580 | 54,495,758 |
| 128 | 571,502,921 | 184,413,547 |
| 512 | 5,980,909,793 | 873,120,581 |

At 512 actors, input is 638,478 bytes; this debug-host run took 3.852s versus
0.887s. These measurements cover synthetic valid state and an optimized guest,
not live creation, released node throughput or memory budgets. Gas remains
strongly dependent on unrelated stored actors despite returning one entry.
Run `agent::wire::tests::physical_directory_inspection_scaling` with
`--ignored --exact --nocapture` and `VOS_AGENT_RUNTIME_COST_CANDIDATE` pointing to
the rebuilt candidate PVM. The environment variable is required intentionally;
the test must not silently substitute bundled bytes for the candidate.

Review-checkpoint (`16adf95e`) debug diagnostic: readiness 27s, Create/resume 54s, Install 65s, restart
37s, both shutdowns under one measured second. These are not production capacity
benchmarks; the unchanged 10s readiness test fails. Invocation, optimized release
performance and multi-profile acceptance are not qualified by this campaign.
Exact evidence: [recovery contract](agent-recovery-contract.md).

## Remaining full-saga acceptance gates

- A common execution/lifecycle/publication/acknowledgement/recovery contract
  qualified across standard and custom runtimes and promised profiles.
- Released ordinary Shared creation, authenticated genesis/finality, replication,
  restart and recovery. Partial archive/issuer/genesis source work is not a
  released end-to-end result.
- Native backup/restore after bootstrap; complete Agent CLI and multi-profile
  lifecycle acceptance. Do not enable unsupported backup by broadening allowlists.
- Authenticated bounded Authority/issuer record reclamation; exact retry,
  retirement, expiry, crash, busy shutdown and mixed pending-state matrices.
- Private/Attested cryptographic and cross-runtime proof acceptance, including
  portable positive acknowledgements and resource/capacity boundaries.
- Incremental/touched-state costs, bounded revision-consistent directory
  projections, node maintenance isolation, prepared execution and recovery
  scaling. The current runtime ABI/publication still carries whole state.
- Quantitative released-binary latency, throughput and resource budgets:
  same-Agent versus independent Agents, idle namespaces, growing directories,
  queue saturation, CPU/RAM/file descriptors and tail latency. Concurrency tests
  do not establish thousands-active-users capacity.
- Reproducible released artifacts; complete workspace tests/lint/formatting,
  clean-break checks, examples and operator documentation against that release.

Historical disposable Local testing passed bootstrap, ingress and counter
lifecycle at `e20cbb76`, but readiness and operation latency failed production
targets. It is historical evidence only, not a pass for later code.

## Historical evidence

Long chronological logs were compacted to eliminate contradictory current
instructions. Their complete contents remain in Git at `a1ebce16`:
`git show a1ebce16:docs/agent-saga-handoff.md` and
`git show a1ebce16:docs/agent-saga-review.md`; the old status is at the same
revision. Existing evidence directories and frozen binaries were not deleted.
