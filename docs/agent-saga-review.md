# Agent saga: review guide

[Current status](agent-saga-status.md) is authoritative for remaining work.
Review the actual `saga/agents` tip, advanced from `1b977731` for this handoff.
It includes recovery source `a1ebce16`, reproducible r18 artifacts `f9c362cb`,
and the lifecycle-envelope fix. This is a qualified scoped review checkpoint,
not a production-qualified release.

Keep two consolidated review groups:

1. Execution ownership and isolation: bounded admission, independent-Agent
   dispatch, same-Agent ordering, Local leases, lifecycle generations,
   retirement, refresh, shutdown and error recovery.
2. Runtime-independent state access and recovery: targeted lookup, directory
   snapshot reuse, pinned ownership, catalog scan boundaries, public history
   projection, exact guest/host recovery agreement, reproducible bundled bytes,
   durable package-bearing requests and bounded HTTP upload admission.

Useful fixed deltas: `29a745c2..1b977731` covers the reviewed execution work;
`1b977731..saga/agents` is the new integrated review delta. In particular, review
the two-per-process upload admission lifetime across HTTP cancellation, exact
endpoint body ceilings, and unchanged ordinary-body limits. Earlier Shared and
row-state work inherited through `29a745c2` remains subject to the full-saga
acceptance gates; these review groups do not retroactively qualify it.

Read [the execution checkpoint evidence](agent-execution-checkpoint-review.md)
and [the recovery contract](agent-recovery-contract.md). Distinguish measured
coordination from throughput, source tests from bundled-binary behavior, and
historical release results from current qualification.

The `16adf95e` debug campaign passes bootstrap, HTTP/SSH, retained Create/resume,
Counter Install and restart/shutdown. It does not rerun application invocation.
Readiness remains 27–37s and lifecycle operations 54–65s: unacceptable latency,
not a throughput benchmark. The ten-second test has not been relaxed or ignored.
Later implementation-only evidence belongs in the current status, not in this
checkpoint's qualification claims.

Review read-only: no fixes, formatting, branch movement, commits or pushes.
Return severity, exact commit/file/line, violated invariant, concrete scenario,
reproduction evidence, suggested regression and overlap with later work. Label
hypotheses separately from demonstrated defects. The implementation agent owns
all fixes on the latest source to avoid conflicting reviewer edits.

Use isolated disk-backed build output, disposable stores and exact artifact
generations. Never overwrite preserved clients or use live user spaces.

The former 10,533-line review/experiment journal remains at
`a1ebce16:docs/agent-saga-review.md`. It is historical evidence, not a competing
current plan.
