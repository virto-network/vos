# Agent saga: working plan

Follow [current status](agent-saga-status.md), the single authoritative plan and
acceptance-gate index. Do not use chronological notes from older commits as
current instructions.

The integrated review batch is **control-worker isolation, indexed restoration,
reproducible optimized runtime artifacts and physical Local lifecycle evidence**.
Review `saga/agents`, new delta from `16adf95e`. Production latency remains
unacceptable; the ten-second readiness target is unchanged.

Next work addresses repeated authenticated inventory projections and bounded
touched-state execution/publication. Preserve freshness, ordering, runtime
independence and recovery. Continue all full-saga gates without narrowing scope.

Use [the recovery contract and evidence](agent-recovery-contract.md) for this
batch, then [the review guide](agent-saga-review.md) for handoff. Do not expand
the batch into unrelated architecture work, disable tests, decode custom
runtime private state in the host, or claim full-saga completion.

The superseded 206-line working log is recoverable with
`git show a1ebce16:docs/agent-next-checkpoint.md`.
