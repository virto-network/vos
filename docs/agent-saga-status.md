# Agent saga checkpoint — 2026-09-19

The complete saga is **not finished**. This is a review/test-environment
checkpoint, not production or master sign-off. `saga/agents` remains at
`31b0cdbb`; nothing has merged or pushed.

## What can be tested

Release implementation `cca4c911` builds and verifies its bundled artifacts.
SHA-256: `697324387cf98331f0c237e228dfc9e98947c8a97f9f1204dfa3d8eca985ce20`.
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
2. `f79f0e3d..97503f48`: recovery, performance, artifact and qualification follow-ups
   (27 files, +2,844/-160 at this frozen checkpoint).

The integrated diff remains large (229 files, +75,715/-58,972 at `97503f48`).
These are review groupings, not independently deployable slices. Subsequent
review-handoff-only documentation edits belong with batch2. The old C1 boundary
is not independently merge-ready.
See [review guide](agent-saga-review.md) and [evidence handoff](agent-saga-handoff.md).

Freeze implementation here for review and disposable Local-space testing; do
not start another guest/artifact change merely to fill the remaining budget.
No merge or push is authorized by this checkpoint. When implementation resumes,
measure fresh Create/Install/invocation on the current release before claiming
that the startup optimizations improved operation latency. Preserve original
fixture paths and failure evidence. Then address authenticated initial inventory
with bounded equivalence/recovery checks and repeat release qualification.

## Remaining production work

| Requirement | Current evidence / gap |
| --- | --- |
| Startup and operation latency | Latest two restarts36s/29s;10s gate fails. Earlier current-guest Create43s, Install65s, fresh managed calls29–35s; not remeasured on latest host release. |
| Recovery performance | With8-entry scheduling, second pass system owner8.02s, including14 runtime calls6.39s. Shorter history helps; not a same-history A/B. |
| Inventory performance | Two agents require six sequential authenticated queries; latest inventory20.42s/19.77s. It now dominates observed startup. |
| Shutdown | Latest disposable probes pass within1–2s; general busy/crash matrix still incomplete. |
| Ordinary Shared genesis/finality | Native startup still installs `UnavailableAgentFinality`; production accepting bridge missing. System genesis is a separate path. |
| Authenticated reclamation | Issuer/coordinator bounded-record reclamation remains unfinished; invocation retirement is not proof of Authority application. |
| Recovery/proof qualification | Remaining mixed pending/crash/capacity cases, pre-expiry Abort/management expiry, cross-runtime portable positive ACK, and full Private/Attested cryptographic proof matrix. |
| Release integration | Final integrated test matrix, docs/examples/inventory audit and review sign-off remain. Focused passes do not replace them. |

Next performance step: address the roughly20s authenticated initial inventory.
Released checkpoint scheduling now triggers at8 retained physical entries;
safety tests, the complete514-query workload and two live restart passes succeed.
Observed periodic reconciliation3.71s/3.57s is not a broad throughput proof. Do not
lower safety/retention bounds, omit replay, or publish readiness before recovery
to meet a latency number. Any scheduling change must prove exact recovery and
measure both restart and steady-state cost. The other gates remain in scope.
