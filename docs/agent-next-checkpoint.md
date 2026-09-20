# Agent saga: working plan

Follow [current status](agent-saga-status.md), the single authoritative plan and
acceptance-gate index. Do not use chronological notes from older commits as
current instructions.

The active batch is **runtime-independent recovery plus r18 artifact
qualification**. Recovery source is committed at `a1ebce16`; its physical
regression and complete Local suite pass, including the repinned bundled runtime.
Immutable-source artifact reproduction also passes; disposable current-binary
startup/lifecycle qualification remains unfinished. The reviewer branch stays at
`1b977731` until the integrated batch is ready.

Use [the recovery contract and evidence](agent-recovery-contract.md) for this
batch, then [the review guide](agent-saga-review.md) for handoff. Do not expand
the batch into unrelated architecture work, disable tests, decode custom
runtime private state in the host, or claim full-saga completion.

The superseded 206-line working log is recoverable with
`git show a1ebce16:docs/agent-next-checkpoint.md`.
