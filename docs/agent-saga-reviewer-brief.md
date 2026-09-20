# Agent saga: reviewer entry point

Follow [the review guide](agent-saga-review.md) and [current status](agent-saga-status.md).
The reviewer checks `saga/agents`; implementation-only source must be identified
separately. Review read-only and return findings rather than applying fixes.

Current evidence is indexed by [the execution checkpoint](agent-execution-checkpoint-review.md)
and [the recovery contract](agent-recovery-contract.md). Neither source tests nor
historical single-user probes establish production or thousands-user readiness.

The frozen `e20cbb76` briefing, detailed performance questions, exact release
hashes and evidence paths remain available at
`a1ebce16:docs/agent-saga-reviewer-brief.md`. Use that snapshot only when reviewing
that older checkpoint.
