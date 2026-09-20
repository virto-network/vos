# Execution isolation / targeted access review checkpoint

This is a source-review checkpoint, not a deployment or architectural sign-off.

## Follow-up checkpoint: Local catalog validation isolation

Review the incremental change from `9acb7ef4` to the commit containing this
section. Checkout transfers the target driver into its exclusive execution
lease before scanning its catalog. The shared registry mutex now covers root
identity validation and ownership transfer, not catalog traversal. Same-Agent
work remains Busy; the lease retains the root lock. Failed validation returns
the untouched driver through normal lease cleanup. Pinned directory identity
is checked both before ownership transfer and after the scan.

Two physical-host regressions cover the new boundary: a deliberately held
catalog scan permits another Agent's checkout to finish, still excludes the
same Agent, and rejects injected catalog corruption without stranding ownership;
a directory replacement during scanning is rejected by the post-scan pin check.
These are coordination/tamper tests, not production throughput measurements.

Evidence logs are under the shared target's `task-tmp` directory:
`catalog-isolation-test.log`, `catalog-isolation-replacement.log`,
`catalog-isolation-local-final.log`, `catalog-isolation-supervisor.log`, and
`catalog-isolation-vosx-check.log`. Final Local suite: 20 passed, one known
recovery failure. Supervisor/adapter suite: 56 passed. `vosx` check passes.
Physical tests explicitly select the existing candidate runtime ELF; no bundled
artifact was replaced. The known substituted-management-history recovery failure
remains an acceptance failure, not an ignored or weakened test.

Limits: this removes cross-Agent lock contention caused by targeted checkout
catalog scans; it does not remove the scans themselves. Explicit lifecycle and
namespace audits still use the registry lock. Root identity filesystem checks,
node inventory scheduling, whole-state VM/publication costs and the remaining
release gates are unchanged. Prioritize runtime-independent recovery-history
binding next, before declaring the candidate safe for deployment.

## Follow-up checkpoint: supervisor refresh isolation

Review this incremental change from `817e528c` to the commit containing this
section, now carried on `saga/agents`. The change is confined to the supervisor
and checkpoint documentation; no runtime, catalog, store or artifact changes.

Refresh callbacks execute on one bounded maintenance worker, separate from
serving workers. The coordinator validates and reserves the complete proposed
generation before dispatching that callback, then checks its exact response and
publishes atomically. Old and proposed Agent lanes remain behind a lifecycle
barrier. Unrelated dispatch continues. Attach and subsequent refresh commands
wait in deferred storage bounded by the configured command-queue capacity;
excess control work returns Busy. Independent detach remains available.

Shutdown closes publication/admission, drains serving and maintenance workers,
rejects pending controls and refuses late refresh publication. Stale detach
tokens cannot retire the replacement generation. Refresh errors and panics
retire the affected attachment while leaving unrelated routes usable.

Evidence (host `nightly-2025-05-09`, offline/locked):

- 56 supervisor/adapter tests pass (`refresh-isolation-final.log`).
- Held-refresh regression: Agent B's immediate request completes before
  Agent A's refresh is released; A's request is refused behind the barrier.
- Shutdown regression: an in-flight refresh is drained but never published.
- Both preceding regressions pass 20 repetitions each
  (`refresh-isolation-repeat.log`); these are deterministic coordination tests,
  not throughput or latency-distribution measurements.
- Deferred control overload, stale detach, exact-generation replacement,
  refresh failure and panic cleanup pass.
- `vosx` binary check passes (`refresh-isolation-vosx-check.log`).

All logs remain in the shared target's `task-tmp` directory. Refresh tracing
records worker-queue wait and callback service time (not total deferred wait).

Limits at this checkpoint: Attach reconciliation and retirement callbacks can
still occupy the coordinator. Node inventory/reconciliation remains synchronous, and target
catalog traversal still holds the registry mutex. VM memory budgeting,
whole-state costs, generic-runtime recovery, bundle compatibility and release
qualification are unchanged. This does not claim complete maintenance isolation.

Next bounded implementation topic: move target-catalog traversal outside the
registry mutex while retaining exclusive Agent ownership and tamper checks.

## Reviewer follow-up: inline retirement

The P2 in `target/agent-review-92ce97f4.kUhgwO/REVIEW.md` is fixed in
the follow-up commit containing this section. Inline handles now share an
optional backend: retirement closes admission, drains the operation mutex,
takes and drops the backend, then publishes terminal status. Concurrent
retirement and join callers drain the same lock. Error, panic and poisoned-lock
paths still release ownership and report failure rather than success.

Regression evidence: 52 supervisor/adapter tests pass; 11 tests selected by
`inline_` pass, including a real Local root reopening while a closed handle
survives. Coverage includes in-flight operation draining, concurrent retirement/
join, retirement errors/panics, destructor panic, poisoned locks and dispatch
panic cleanup. Physical coverage uses the explicit candidate ELF described
below, not a repinned release. Logs: `inline-retirement-final.log` and
`inline-retirement-supervisor.log` in the shared target's `task-tmp` directory.

The reviewer's performance limits are unchanged: refresh still runs on the
supervisor coordinator, target-catalog validation still holds the registry
mutex, VM/image work remains whole-state, and concurrency lacks a measured VM
memory budget. Candidate recovery and bundled-runtime compatibility remain
open. This fix does not claim release or high-concurrency qualification.

## Original checkpoint

The implementation checkpoint is `92ce97f4`, now carried on `saga/agents` for
review. The previous review baseline is `e20cbb76`. Ongoing implementation uses
`wip/ch08-runtime-directory`. Please report findings without applying fixes.

For this follow-up, review the delta `29a745c2..92ce97f4`. That base preserves earlier unqualified Shared and
row-state work; this checkpoint does not retroactively qualify it. The full
delta from `e20cbb76` remains much larger than these review changes.

## Two consolidated review groups

1. Ownership and correctness: terminal continuation/ACK capacity; bounded
   supervisor worker pool; same-Agent ordering across attachments; deferred
   refresh/detach barriers; Local execution leases; per-Agent production route
   slots and inline adapters; shutdown and failure handling.
2. Targeted access: one verified directory snapshot per audit; exact actor
   lookup through a one-record public cursor request; pinned Agent directory
   ownership; request-time validation of only the touched Agent; namespace
   audits at lifecycle/reconciliation boundaries; physical auditing outside
   the host-wide mutex.

Start with `supervisor.rs`, `supervisor_lanes.rs`, `local_sdk_host.rs`,
`supervisor_adapters.rs`, and `production_owner.rs`. Then inspect the lookup
change in `driver.rs` and continuation changes in vosx. Native lifecycle
startup uses one inline attachment per Agent; the legacy aggregate Local
attachment API remains available and still serializes its own dispatches.
Inline attachments execute on the supervisor pool, not dedicated Agent threads.

## Evidence

Host toolchain: `nightly-2025-05-09`; offline, locked builds. Logs are in the
shared `.worktrees/ch08-c2-native/target/task-tmp` directory.

- Supervisor/adapter tests: 50 passed, including inline retirement and panic.
- Production-owner tests: 12 passed.
- Exact lookup cursor boundary test: 1 passed.
- Physical Local candidate suite: 17 passed, **1 failed** (see below).
- Physical two-Agent overlap and per-Agent authority audit test: passed. Both
  real drivers are acquired through one supervisor before either is released;
  both VM invocations then complete successfully. Auditing each leased Agent
  uses one directory execution and rejects an omitted authority projection.
- The physical lifecycle test compares targeted and audited material, checks
  missing actors, and verifies inspection does not mutate the image.
- Checkout validates one Agent slot with an idle neighbor present; replaced
  slot directories are refused. New unrelated namespace entries are detected
  by explicit lifecycle audits, not by serving requests.
- Continuation transport boundary tests: 8 passed at the preceding fix.
- `cargo check --offline --locked -p vosx --bin vosx`: passed, existing warnings.

Logs: `local-checkpoint-regressions.log`, `local-targeted-namespace.log`,
`local-overlap-audit.log`, `local-checkpoint-vosx-check.log`, and
`continuation-review-transport.log`.

Physical candidate tests explicitly select `AGENT_RUNTIME_CANDIDATE_ELF`:
`.worktrees/ch08-c2-native/target/task-tmp/row-resource-runtime.5B1apX/target/riscv64em-vos/release/agent_runtime.elf`
relative to the main repository root. No release artifact,
digest, or pin was replaced. Tests using this candidate are not bundled-binary
qualification.

## Known failure and remaining gates

`physical_reopen_rejects_substituted_host_management_history` still fails for
the candidate runtime. The host's native parity check is selected only for
`STANDARD_RUNTIME_PROGRAM_ID`; the candidate takes the generic-runtime path.
This is a pre-existing runtime-independent recovery-validation gap, not a
waived test. Default bundled runtime and current row-state source are also not
compatible. Neither issue is fixed by the execution ownership work.

Other important limits remain:

- Node inventory/reconciliation is still synchronous. Per-Agent auditing no
  longer holds the global host mutex, but coordinator/control-plane scheduling
  isolation is unfinished. There is no sustained request-latency evidence yet.
- Runtime input/output and image publication still carry whole state. A
  one-record directory response does not establish touched-state VM cost.
- Preparation caching and large-directory/idle-Agent scaling measurements
  remain to be qualified. No thousands-active-users capacity claim is made.
- Uncertain Local execution failure conservatively fails the physical host
  closed until reopen. Per-Agent fault containment and busy lifecycle races
  need more qualification; do not infer them from independent dispatch overlap.
- Pinning Agent directories retains one file descriptor per hosted Agent;
  deployment resource budgeting must include that cost.
- Full released Shared creation/replication/restart/recovery, native backup,
  and the broader saga acceptance gates remain open.

Reviewer focus: lease drop/error paths; exact generation/lifecycle exclusion;
bounded admission ownership; partitioned authority projections (including lag,
omissions, revocation and partial reconciliation); namespace audit boundaries;
and whether generic-runtime recovery validation needs a public contract change.

Recommended next implementation order: settle the runtime-independent recovery
contract and artifact compatibility, isolate node reconciliation with explicit
freshness/revocation rules, then run released-binary lifecycle and quantitative
scaling tests. Keep these separate from claims about full Shared acceptance.
