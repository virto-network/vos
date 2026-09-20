# Agent saga: review guide

[Current status](agent-saga-status.md) is authoritative for remaining work.
Review the actual `saga/agents` tip, advanced from `16adf95e` for this handoff.
It includes control-worker isolation, indexed single restoration, reproducible
optimized runtime artifacts, and physical Local lifecycle evidence. This is a scoped checkpoint,
not a production-qualified release.

Keep two consolidated review groups:

1. Control-worker ownership and isolation: bounded admission, serial control
   ordering, route exposure, cancellation during blocked inventory, rejected
   queued closures and transferred attachments, panic/error propagation,
   draining and idle-exit accounting. Examine `production_worker.rs`,
   `production_owner.rs`, `node.rs` and supervisor shutdown delegation.
2. Restoration and artifact integration: restore once without exposing unchecked
   state; preserve first-ready forest order, missing-parent/cycle/duplicate-ID
   refusal, artifact length consistency, capacity and suspension invariants.
   Examine `wire.rs`, `standard.rs`, pins and independent reproduction. Check
   physical output equivalence, not just native tests.

New delta: `16adf95e..saga/agents`, with implementation through `63d52425` and
bundled runtime update `066e6d3c`. Earlier Shared and
row-state work inherited through `29a745c2` remains subject to the full-saga
acceptance gates; these review groups do not retroactively qualify it.

Read [the execution checkpoint evidence](agent-execution-checkpoint-review.md)
and [the recovery contract](agent-recovery-contract.md). Distinguish measured
coordination from throughput, source tests from bundled-binary behavior, and
historical release results from current qualification.

The current debug binary passes fresh bootstrap, generated system packages and
ingress config, HTTP/SSH, Local Create, Counter Install, mutation, exact retry,
positive retirement, read after restart and shutdown. Readiness remains 25–40s,
Create 51s, Install 60s, and managed attempts approximately 32–34s: unacceptable
latency. The ten-second target is unchanged. The 512-actor one-entry inspection
uses approximately 85% less gas, but unrelated actors still increase its cost.
This is not touched-state, optimized-release or thousands-concurrent qualification.

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
