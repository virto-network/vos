# Agent saga: working plan

Follow [current status](agent-saga-status.md), the single authoritative plan and
acceptance-gate index. Do not use chronological notes from older commits as
current instructions.

The integrated review batch is **runtime-independent recovery, reproducible r18
artifacts and bounded lifecycle package envelopes**. Recovery source is committed
at `a1ebce16`, artifact reproduction at `f9c362cb`; the subsequent envelope fix
passes the disposable debug-binary lifecycle campaign. The unchanged readiness
gate still fails. Review `saga/agents`, not the older `1b977731` checkpoint.

The next work is synchronous node reconciliation and its repeated full-execution
costs, with explicit freshness, ordering, recovery and performance acceptance.

Use [the recovery contract and evidence](agent-recovery-contract.md) for this
batch, then [the review guide](agent-saga-review.md) for handoff. Do not expand
the batch into unrelated architecture work, disable tests, decode custom
runtime private state in the host, or claim full-saga completion.

The superseded 206-line working log is recoverable with
`git show a1ebce16:docs/agent-next-checkpoint.md`.
