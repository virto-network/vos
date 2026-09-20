# Agent saga: implementation handoff

Start with [current status](agent-saga-status.md). It is the authoritative
remaining-work list; this file deliberately does not duplicate it.

- Implementation worktree: `.worktrees/ch08-runtime-directory`.
- Review worktree: repository root, branch `saga/agents`.
- Review-only workflow: reviewer returns findings; implementation agent applies
  fixes on the latest work and advances the review branch at qualified checkpoints.
- Current recovery design, test command and logs:
  [recovery contract](agent-recovery-contract.md).
- Current review boundary: [review guide](agent-saga-review.md).

Keep builds, test stores and logs on disk, not RAM-backed `/tmp`. Preserve frozen
clients, failed-operation bytes and release-specific stores. Do not mix stores
or artifacts from different runtime generations, change master, or push.

The former chronological handoff is preserved in full at
`a1ebce16:docs/agent-saga-handoff.md`. Retrieve it using `git show` when a
particular historical experiment is needed. Its branch tips, pending-work
statements and timings apply only to their recorded checkpoints.

Retained historical evidence includes:
`.worktrees/ch08-c2-native/target/task-tmp/current-latency.0NCyjT/` (frozen
`e20cbb76` disposable Local tests), plus the later recovery and isolation logs
named in the current evidence documents. None of those files was deleted by
the documentation cleanup.
