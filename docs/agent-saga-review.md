# Agent saga: review guide

[Current status](agent-saga-status.md) is authoritative for remaining work.
Review the actual `saga/agents` tip; at this handoff it is `1b977731`.
The r18 recovery source at `a1ebce16` is on the implementation branch and must
not be treated as an already-qualified review checkpoint.

Keep two consolidated review groups:

1. Execution ownership and isolation: bounded admission, independent-Agent
   dispatch, same-Agent ordering, Local leases, lifecycle generations,
   retirement, refresh, shutdown and error recovery.
2. Runtime-independent state access and recovery: targeted lookup, directory
   snapshot reuse, pinned ownership, catalog scan boundaries, public history
   projection and exact guest/host recovery agreement.

Useful fixed deltas: `29a745c2..1b977731` covers the reviewed execution work;
`1b977731..a1ebce16` covers the newer recovery source. The latter still needs
artifact qualification before advancing the review branch. Earlier Shared and
row-state work inherited through `29a745c2` remains subject to the full-saga
acceptance gates; these review groups do not retroactively qualify it.

Read [the execution checkpoint evidence](agent-execution-checkpoint-review.md)
and [the recovery contract](agent-recovery-contract.md). Distinguish measured
coordination from throughput, source tests from bundled-binary behavior, and
historical release results from current qualification.

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
