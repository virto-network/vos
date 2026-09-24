# Agent saga: Clerk Agent Local checkpoint

Review the code through `49a0ae44` on `saga/agents` relative to `e3335407`;
the subsequent handoff-docs commit adds no code. This is one scoped,
opt-in Clerk Agent integration checkpoint, **not** first-customer release or
three-node Shared qualification. The [live release plan](agent-saga-status.md)
remains authoritative. Please return findings without editing `saga/agents`;
implementation continues on `wip/ch08-runtime-directory`.

## What changed

- `clerk-ledger` has an opt-in `agent` build over its existing state fields,
  cipher-clerk kernel, signatures and committed-root helpers. The legacy
  service build remains the default. Agent package methods carry exact
  Operator/Member role IDs and signed schema/policy metadata.
- The dual-ABI macro accepts an Agent-only `agent_linearizable` read mode and
  portable role ID beside the unchanged legacy role predicate. Explicit
  ordered reads avoid the external-state default-`Query` publication gap; they
  also add per-read publication cost that must be measured under load.
- The Agent artifact uses a clean refine entry and Agent-only linker layout.
  The canonical `vosx actor build` produced a signed VOS3 package admitted by
  the host's standard-PVM/package checks.
- With that exact package, the ignored physical external-Local fixture covers
  Create, Install, an anonymous Clerk read, ACK, an Operator note-commitment
  write, a Member count read, and exact result recovery after reopening the
  locked owner. It verifies archived `Status::Ok`, count one, and no duplicate
  head on retries. The original synthetic-package fixture also still passes.

## Review questions

1. Do Agent-only mode and role annotations preserve legacy dispatch while the
   signed Agent schema/policy enforces the exact intended mode and role?
   Check the macro, Clerk metadata tests, and package admission.
2. Does the Agent field-view rewrite continue to use the same Clerk kernel,
   signature checks, state fields and root calculation without bypassing lane
   access? Do not infer transfer/root parity from the note-commitment test.
3. Can the physical fixture accidentally treat a test-signed Authority role
   claim as evidence of a real backend credential grant, or replay a different
   package, request, result or generation after reopen?
4. Does the new entry/linker selection isolate the Agent PVM ABI without
   changing legacy actor execution or admitting an unsupported host call?

## Evidence and limits

The legacy Clerk suite passed 13 tests, the Agent suite 14, and `vos-macros`
passed 23. Both Clerk PVM builds and canonical package admission passed. The
physical external-Local fixture passed with Clerk and separately with its
original synthetic package. The default non-experimental `vos` library check,
formatting and diff checks passed. Artifact IDs from this development build
are not release pins. The full prototype/workspace and outer-PVM gates were
not rerun for this checkpoint.

Not covered: public external-state Install ingress, production credential-role
grants, transfer execution and kernel-root parity, three-node Shared lifecycle,
100,000 retained transfers, throughput, backup/restore, or release artifact
reproduction. The external-state path remains opt-in. The fresh dedicated-root
rule preserves existing image Local deployments; it is not a migration.

Please report severity, commit/file/line, violated invariant, concrete
failure scenario and a regression. Distinguish demonstrated defects from
unmeasured design risks. Keep review scratch disk-backed and do not apply
fixes on `saga/agents`.
