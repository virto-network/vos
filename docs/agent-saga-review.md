# Agent saga: signed Clerk transfer checkpoint

Review `a3d7c295..9a003d58` on `saga/agents`. This is an incremental,
test-focused checkpoint following the earlier opt-in Clerk Agent port. It is
**not** first-customer release or three-node Shared qualification. The
[live release plan](agent-saga-status.md) remains authoritative. Please return
findings without editing `saga/agents`; implementation continues on
`wip/ch08-runtime-directory`.

## What changed

- A host test runs real registrar-signed account creations and a debit-signed
  transfer through both Clerk's committed-map `LedgerView` and cipher-clerk's
  `MemLedger`. It checks accepted kernel statuses, the stored transfer, and
  byte-identical composite roots after bootstrap, creations and transfer.
- The existing ignored physical external-Local fixture, using the canonical
  signed Clerk Agent package, now invokes `bootstrap`, two `create_account`
  calls, `apply_transfer` and `state_root` through the Standard PVM. It checks
  archived `Status::Ok` for each mutation and matches the public root against
  the reference ledger. After reopening the locked file owner, a *fresh*
  Member-authorized `state_root` invocation returns that same root.
- A stale Clerk source comment was corrected: the Agent build has physical
  external-Local evidence, but transfer growth and released Shared behavior
  remain unqualified.

## Review questions

1. Does the parity test use equivalent signed inputs, timestamps and journal
   contents, or can it pass while the Agent's kernel behavior diverges?
2. Does the physical fixture actually execute each method and inspect its
   archived return, instead of treating a completed envelope or cached reply
   as success? Is the post-reopen root read a distinct signed invocation?
3. Do the test Authority receipts and role claims remain clearly fixture-only,
   without implying that production backend credentials and role grants work?
4. Did any test change weaken the signed package, physical journal, or fresh
   root selection boundaries?

## Evidence and limits

The Agent Clerk suite passed 15 tests and legacy Clerk passed 14. The physical
fixture passed with `CLERK_AGENT_PACKAGE` pointing at the canonical signed VOS3
artifact, `RUST_MIN_STACK=16777216`, and the experimental state-block feature;
the final run took 136 seconds. Workspace formatting and diff checks passed.
The full prototype gate and offline/locked `vosx --tests` check passed at the
preceding `a3d7c295` checkpoint; they were not rerun for this test-only code
change. Artifact IDs from this development build are not release pins.

Not covered: public external-state Install, production credential-role grants,
high-volume retained transfers, throughput, three-node Shared quorum/finality,
backup/restore, or release artifact reproduction. The external-state path is
still opt-in. The approved fresh dedicated-root rule preserves existing image
Local deployments; mixed-format migration is deferred.

Please report severity, commit/file/line, violated invariant, concrete
failure scenario and a regression. Distinguish demonstrated defects from
unmeasured design risks. Keep review scratch disk-backed and do not apply
fixes on `saga/agents`.
