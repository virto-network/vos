# Agent saga checkpoint — 2026-09-19

The complete saga is **not finished**. This is a review/test-environment
checkpoint, not production or master sign-off. `saga/agents` remains at
`31b0cdbb`; nothing has merged or pushed.

## What can be tested

Release implementation `3a990280` builds and verifies its bundled artifacts.
SHA-256: `15f23e7bd959356c7f7a5997efb5f4ddb245b8fa07de84f67a358d78329a7e5a`.
The current runtime is independently reproduced; new spaces automatically
receive system packages and enabled HTTP/SSH configuration. The Local workflow
has live evidence for Create, Counter Install, increment, retirement/ACK retry,
and reading7 after restart. Latest release rechecks HTTP/SSH, retained Counter
recovery and conflict reporting; it does not remeasure fresh mutations.

Use disposable spaces only. Do not migrate valuable older-generation stores.
Preserve failed operations and exact request bytes; a timeout or unsigned HTTP
error does not prove failure. Retired historical Create replay after Install
returns409; retention is bounded, not indefinite server reply caching.

## Review organization

Keep two scoped batches, not one review per work-in-progress commit:

1. `31b0cdbb..f79f0e3d`: integrated clean-break architecture/lifecycle.
2. `f79f0e3d..c88a2729`: recovery, performance, artifact and qualification follow-ups.

The integrated diff remains large (228 files, about75.6k additions/59.0k
deletions at `c88a2729`). The old C1 boundary is not independently merge-ready.
See [review guide](agent-saga-review.md) and [evidence handoff](agent-saga-handoff.md).

## Remaining production work

| Requirement | Current evidence / gap |
| --- | --- |
| Startup and operation latency | Latest restart58s;10s gate fails. Earlier current-guest Create43s, Install65s, fresh managed calls29–35s. |
| Recovery performance | Before system owner:38 runtime executions30.95s, of which30 large calls30.59s; system owner34.94s total. Removing host bookkeeping alone cannot fix this. |
| Inventory performance | Two agents require six sequential authenticated queries; latest inventory21.34s. Calls reduced61→43, but no controlled overall speedup demonstrated. |
| Shutdown | Latest disposable probes pass within1–2s; general busy/crash matrix still incomplete. |
| Ordinary Shared genesis/finality | Native startup still installs `UnavailableAgentFinality`; production accepting bridge missing. System genesis is a separate path. |
| Authenticated reclamation | Issuer/coordinator bounded-record reclamation remains unfinished; invocation retirement is not proof of Authority application. |
| Recovery/proof qualification | Remaining mixed pending/crash/capacity cases, pre-expiry Abort/management expiry, cross-runtime portable positive ACK, and full Private/Attested cryptographic proof matrix. |
| Release integration | Final integrated test matrix, docs/examples/inventory audit and review sign-off remain. Focused passes do not replace them. |

Next performance step: attribute repeated large runtime calls during system
recovery and evaluate authenticated checkpoint scheduling/replay cost. Current
opportunistic checkpoint policy waits for32 retained physical entries. Do not
lower safety/retention bounds, omit replay, or publish readiness before recovery
to meet a latency number. Any scheduling change must prove exact recovery and
measure both restart and steady-state cost. The other gates remain in scope.
