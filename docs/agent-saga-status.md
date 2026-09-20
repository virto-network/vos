# Agent saga: current status

This is the authoritative status and remaining-work index. Other Agent handoff
documents are navigation or evidence, not competing plans. Updated 2026-09-20.

## Branches and qualification

- Reviewer branch: `saga/agents`, advanced to this integrated review checkpoint
  from `1b977731`; resolve the exact tip with Git.
- Implementation: `wip/ch08-runtime-directory`, recovery source `a1ebce16`,
  followed by artifact checkpoint `f9c362cb` and the lifecycle-envelope fix.
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
4. Next: isolate synchronous node reconciliation and reduce its repeated full
   invocation/acknowledgement costs without weakening freshness or ordering.
   Qualify the resulting binary with latency, independent-Agent isolation and
   recovery tests. Continue the remaining full-saga gates below.

Current debug diagnostic: readiness 27s, Create/resume 54s, Install 65s, restart
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
