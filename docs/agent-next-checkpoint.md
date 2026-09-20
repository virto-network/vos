# Agent saga: plan entry point

Follow [current status](agent-saga-status.md), the single authoritative plan and
acceptance-gate index. Do not use chronological notes from older commits as
current instructions.

Use [the review guide](agent-saga-review.md) for the exact reviewer boundary
on `saga/agents`; later implementation-only work is identified in current status.
Keep checkpoint hashes, next steps and qualification results there rather than
duplicating a potentially stale batch description here.

Preserve freshness, ordering, runtime independence and recovery. Continue all
full-saga gates without narrowing scope. Do not disable tests, decode custom
runtime private state in the host, or treat a scoped checkpoint as full-saga
completion.

The superseded 206-line working log is recoverable with
`git show a1ebce16:docs/agent-next-checkpoint.md`.
