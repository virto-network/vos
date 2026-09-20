# Execution isolation / targeted access review checkpoint

This is a source-review checkpoint, not a deployment or architectural sign-off.
`saga/agents` stays frozen at `e20cbb76`; implementation is on
`wip/ch08-runtime-directory`. Please report findings without applying fixes.

For this follow-up, review the delta from `29a745c2` to the checkpoint commit
containing this document. That base preserves earlier unqualified Shared and
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
