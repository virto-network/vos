# Agent saga: current status

This is the authoritative status and remaining-work index. Other handoffs are
navigation or checkpoint evidence, not competing plans. Updated 2026-09-20.
The complete Agent Architecture Saga remains the objective.

## Review boundary

Review the r19 retirement checkpoint on root `saga/agents`, with new delta
`c8028394..saga/agents`. Implementation continues on `wip/ch08-runtime-directory`
in `.worktrees/ch08-runtime-directory`. Master is unchanged;
nothing has been pushed. This is **not production qualification**.
See [review guide](agent-saga-review.md) for the two scoped review groups.

Foundation commits `930a5450`, `76d37d4d`, `493a098c` and source cutover
`3c5e44c7` introduce reference-only retirement, reuse retained SDK metadata,
and establish full SDK-to-execution correspondence before successful commit.
ABI r19 uses SDK work commitment as clean result identity; restore/retry/retirement
check exact equality and legacy APIs refuse clean results.
RuntimeWork and journal ACKs carry metadata and ordered references, not preimages.
Signature, scope, exact accepted binding, expiry/error retirement, capacity and
projection compaction checks remain. Custom-linear validates its own distinct
retained layout. No missing-byte hydration or old-state migration is provided.

The prior concurrency, Local lease/retirement, control-worker isolation, targeted
lookup, catalog isolation, public management recovery and indexed single-restore
work remains included. See [execution evidence](agent-execution-checkpoint-review.md)
and [recovery contract](agent-recovery-contract.md), whose earlier results are
explicitly checkpoint-specific.

## r19 evidence

Logs below are under `.worktrees/ch08-c2-native/target/task-tmp/`.
These scoped passes do not establish every full-saga acceptance gate.

- 179 SDK tests: `r19-compact-wire-sdk-final.log`. Includes commitment parity,
  hostile references, authorization substitution, r18-header refusal and a
  1 MiB artifact whose empty-state ACK frame is below 2 KiB.
- 52 Standard tests: `r19-compact-application-standard.log`.
- 99 source-wire tests: `r19-compact-transport-wire.log`; four ignored.
- 109 bundled wire tests: `r19-bundled-wire.log`; five opt-in tests ignored.
- 41 journal, 56 replay, 33 Local journal and 97 journal-store tests:
  `r19-compact-journal-final.log`, `r19-compact-replay.log`,
  `r19-compact-local-journal.log`, `r19-compact-journal-store.log`.
- 21 bundled Local recovery tests, without runtime candidate override:
  `r19-bundled-local.log`. Scripted guest rebuilt with r19.
- Four CLI bundled-admission tests: `r19-bundled-admission.log`.
- 12 custom-linear source tests: `r19-custom-source.log`; one physical test
  ignored there. Substituted message, gas and incarnation cannot retire accepted
  work, even with a newly matching unsigned preflight.
- Explicit physical Standard multi-megabyte yield/resume/retirement comparison:
  `r19-physical-yield-retire.log`. Custom physical scheduling/lifecycle and
  attested-context refusal: `r19-custom-physical.log`. Both pass.

At review checkpoint `7bd66a7d`, runtime, system templates and builder pin source
`3c5e44c769d4cc16c1c13a9949c60a154f378a57`; exact identities and hashes are
in `support/production-artifacts.toml`. The clean export
`r19-reproduction.VgKyCd/` produces byte-identical runtime ELF/PVM.
The prescribed independent all-artifact reproduction passes:
`r19-pinned-reproduction.log`, implementation
`target/agent-release-reproduction/run.catJ18`. Runtime and system templates
are integrated together. Release bundle generation/verification passes into
`r19-reproduction.VgKyCd/integrated-bundle`. These are optimized guests with
a debug CLI/host, not an optimized released-node throughput qualification.

## Integrated disposable lifecycle

Evidence: `indexed-lifecycle.r19.SWGRhK/`. Isolated XDG directories and explicit
space directory; no live user stores. Generated HTTP/SSH config is preserved in
`generated-local.toml`; only disposable ports changed to 18109/2253.
Counter rebuilt for r19. CLI SHA-256:
`9219bfa1731d6bd4dc1725f615d4b85c6524262a720b59b1a61b8d16af26f09f`.
Test client SHA-256:
`600fa6b2634e4da5013645c7cf7d4e4e34f826e02e2a0f2a8ffe0750f115c6b8`.

`probe.log` passes bootstrap, HTTP/SSH, Agent Create, Counter Install, restart
and shutdown: readiness 23s, Create 38s, Install 47s, restart 26s, shutdowns
0s/1s. Both probe daemons stopped.
Mutation/positive retirement/exact retry passes (`mutation-test.log`): managed
attempt 27.91s, test 29.86s. Read-after-restart passes (`read-test.log`): managed
attempt 29.56s, test 31.54s. Invocation-campaign readiness was 33s/28s and shutdown
2s/1s (`invocation-probe.log`). Both daemons stopped and the probe exited zero.
This is not non-Public policy or multi-profile proof qualification.
**The unchanged ten-second readiness target fails.**

## Performance: measured improvement and remaining cost

The fresh signed Credential query/retirement fixture passes. Compare
`indexed-authority-query-profile.log` (r18 baseline) with
`r19-authority-query-tagged-profile.log` (r19). The test-only all-input override
avoids the former 700 KB profiling threshold hiding compact ACKs; work tags
distinguish small management calls from retirement.

| Metric | r18 | r19 |
| --- | ---: | ---: |
| Invoke input bytes | 1,090,241 | 1,094,783 |
| Invoke gas | 763,079,916 | 853,869,674 |
| ACK input bytes | 1,092,566 | 9,220 |
| ACK gas | 276,552,182 | 20,952,819 |
| Invoke + ACK gas | 1,039,632,098 | 874,822,493 |

ACK input falls 99.2% and gas 92.4%, but Invoke gas rises 11.9%; the pair improves
only 15.9%. Additional management calls are not included in that pair.
Instrumented wall times are not release latency, and this does not establish
thousands-active-users capacity.

Source-based likely contributor to the Invoke regression: successful commit
repeats `resolve_clean_invocation` for full SDK-to-execution correspondence;
resolution recomputes ProgramId from actor bytes. This is not isolated causal
measurement. Preserve the check; reusing prior validation needs an explicit
immutable binding, not omission of authorization or correspondence validation.
Whole-state transport/publication and sequential directory projections remain.

## Next sequence

Implementation-only follow-up after review checkpoint `7bd66a7d`: Invoke and
Resume now retain an immutable resolved-invocation object through execution.
It borrows the original SDK work and privately owns the resolved inputs plus
the complete actor record. Commit still authenticates work/authorization and
requires the current actor record to match, while avoiding a second program
resolution. Unbound internal callers retain full correspondence validation.
All 100 source-wire tests pass, including stale-provenance, authorization and
state/reply equivalence (`resolved-invocation-wire-final.log`); all 52 Standard
tests pass (`resolved-standard.log`). Candidate guest
build passes (`resolved-runtime-guest-build.log`). Physical fresh invocation
preserves exact output and lowers gas from 465,388,608 to 402,186,858 on the
792,537-byte padded fixture (`resolved-physical-fresh-cost.log`, about 13.6%).
The multi-megabyte yield/resume/retirement comparison also passes
(`resolved-physical-resume.log`). This is not whole-query latency evidence or
released qualification; `saga/agents` and its bundles stay fixed for review.
Implementation runtime artifact is integrated, pinned to
`eef8890a`: isolated clean-source ELF matches the tested candidate byte-for-byte
(`resolved-reproduction.umoyY0/`). Only the runtime blob and its source/identity
pins change; ABI r19 and system templates stay unchanged. Bundled suite and
prescribed reproduction are tracked in `resolved-bundled-wire.log` and
`resolved-pinned-reproduction.log` (implementation verifier evidence
`target/agent-release-reproduction/run.MKZjct`). All 110 bundled wire tests pass,
five ignored, and prescribed runtime reproduction passes. All 21 bundled Local
recovery tests pass (`resolved-bundled-local.log`). The real Authority query
profile also passes (`resolved-authority-query-profile.log`): Invoke gas falls
from checkpoint 853,869,674 to 766,337,681 (10.3%), ACK uses 20,954,277, and the
pair totals 787,291,958 (24.3% below r18). Invoke alone remains about 0.4% above
r18. This supports the repeated-resolution attribution but does not establish
whole-query or released-node latency. Four CLI bundled-admission tests pass
(`resolved-bundled-admission.log`). The optimized runtime has not repeated the
full disposable CLI lifecycle campaign; the review checkpoint's recorded CLI
timings remain specific to that older runtime.

1. Reviewer examines `c8028394..saga/agents` read-only and returns findings;
   implementation applies fixes on latest source.
2. Address repeat Invoke validation through a safely bound resolved-work contract;
   measure total request cost without weakening commit checks.
3. Reduce authenticated inventory projection work with explicit revision,
   freshness, availability and ordering. Preserve same-head pagination, cache
   invalidation on refresh failure and durable retirement; no custom-state decoding
   shortcuts or discarded guest state.
4. Develop bounded touched-state access/incremental publication and qualify costs
   against directory growth, idle Agents and independent workloads.
5. Continue every full-saga gate below; the checkpoint does not narrow the goal.

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

## Historical evidence

Previous r18 checkpoint status/review is at `c8028394:docs/agent-saga-status.md`
and `c8028394:docs/agent-saga-review.md`. Intermediate r19 foundation evidence is
preserved at `3c5e44c7:docs/agent-saga-status.md`. Original long journals remain
at `a1ebce16:docs/agent-saga-handoff.md` and `a1ebce16:docs/agent-saga-review.md`.
Historical pending-work statements apply only to their checkpoints. Frozen
clients, failed-operation bytes, release-specific stores and evidence were not
deleted by this compaction. Keep scratch disk-backed, not RAM-backed /tmp.
