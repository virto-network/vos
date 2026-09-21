# Agent saga: Shared lifecycle checkpoint review

Qualified `saga/agents` checkpoint: functional source `42928ddc`, relative to
`9cd2fa6a`, followed by evidence/documentation consolidation.
Test-only follow-up `6de58f82` covers the equal-deadline network error race.
All checkpoint gates are recorded in [current status](agent-saga-status.md).
The previous frozen guide is at `9cd2fa6a:docs/agent-saga-review.md`.

Review-readiness is not production or full-saga sign-off. The reviewer reads
`saga/agents` and returns findings; do not apply fixes, format files, move branches
or push. Implementation applies feedback on the latest source.

## Two consolidated review groups

1. Qualification, performance attribution and targeted CLI discovery:
   `4e92ae07..e194c28e` (include `4e92ae07`). This adds reproducible Local probes,
   journal/VM cost evidence, targeted authenticated descriptor discovery and r19
   fixtures. It explains measured cost and reduces discovery work; it does not
   solve whole-state transport or establish production throughput.
2. Shared lifecycle, recovery, ownership and artifacts: `29c1c3c9..42928ddc`
   (include `29c1c3c9`). Review noncreating discovery and leases, signed reservation
   retention, startup admission, physical finality/application evidence,
   generation-scoped serving, finalization/retirement, pruned-history recovery,
   decoder frame fixes and reproduced Authority packages together.

Treat `ac1b2860` as a separate mechanical formatting commit. Other documentation
commits record evidence and limitations. The total delta is substantial; these
groups are review organization, not a claim that the branch is a small patch.
Review `6de58f82` separately as a test-only correction: equal peer deadlines may
surface Timeout or Transport, but never a successful/fallback response; the
bounded wait, exact recipient assertion and direct error-mapping test remain.

## Invariants to challenge

- `vosx/src/commands/space/clean_store.rs` and `clean_startup.rs`: complete
  discovery, no path creation during reads, exclusive writer/archive ownership,
  orphan/corrupt/missing records, and shutdown/error-path lease release.
- `clean_genesis_recovery.rs` and `clean_operation_dispatch.rs`: signed Create
  scope; retained runtime/receipt consistency; incomplete versus retired phases;
  finalized issuer evidence; bootstrap-history requirements after old pending
  anchors are excluded. A completion marker alone must not qualify retirement.
- `clean_bootstrap.rs`: unfinished finality requires exact publication and
  positive ACK replay. Physical application precedes issuer ACK, Authority
  finalization and request retirement. Writes invalidate stale admission
  snapshots; interrupted phases reopen rather than silently release reservations.
- Retired recovery requires a fresh pinned-Authority `genesis_decision` Query
  whose canonical decision equals the archive, before opening the ordinary set.
  Examine nonce derivation, exact target/proposal/receipt binding, foreign/missing
  decisions, failures, read ACK/record-clear interruption and journal pruning.
  The host must not trust archives or decode Standard private state as authority.
- PAP2 separates authenticated inventory from public genesis reading but shares
  durable Invoke/ACK recovery. Schema and host must agree on Query mode; arbitrary
  Linear mutations must not enter the checkpoint-safe read path.
- `shared_host.rs`: exact authenticated initial Create evidence, including
  request, receipt, sequence, original slot and state commitment. A later mutation
  is not substitute genesis application evidence.
- `network/shared_agent.rs`, `supervisor_adapters.rs`, `production_owner.rs` and
  `local_lifecycle.rs`: per-generation identity, complete Authority projection,
  separate pinned system scope, replacement/retirement, and backend lifetime.
  Surviving closed handles must not retain physical memory, descriptors or locks.
- `vos-agent-sdk/src/wire.rs`: decoder frame isolation preserves tags, bounds,
  canonical validation and error semantics. No stack/gas limit was raised.
- Authority source, immutable template revision, package digests and bundle
  agree. The read-only genesis endpoint is Query; publication remains Linear.

Agent source paths above are under `vos/src/agent/` unless otherwise stated.
Use `git diff --ignore-all-space 9cd2fa6a..42928ddc` alongside the real diff;
do not discard whitespace-sensitive code or formatting changes without checking.

## Evidence and limits

[Current status](agent-saga-status.md) owns exact test results, log paths,
artifact revisions and remaining gates. Native-outer, full outer-PVM, source
tests and release-package checks have distinct scopes.

The expanded physical scenario covers real bootstrap, interrupted finalization,
authenticated root inventory, ordinary installed-actor serving, real pruning,
retired restart, read-clear crash recovery and backend release. It uses a small
executable actor and fixture orchestration; the subsequent issuer handoff is not
a released Shared lifecycle/CLI implementation. There is no multi-node capacity
or released Shared Create/Install qualification here.
Retired startup performs one fresh Authority Query/ACK per generation; challenge
its scaling separately from steady-state serving. Whole-state validation and
transport are still present, so this is not proportional-to-touched-data evidence.

Known release gaps remain: ordinary Shared production CLI/coordinator wiring,
multi-node lifecycle, Native backup, complete profile/custom-runtime semantics,
Private/Attested acceptance, bounded Authority/issuer reclamation, whole-state
costs, Shared host-wide locking, quantitative scaling and workspace lint debt.
Do not reclassify those as passed because this scoped lifecycle test succeeds.
Use fresh disposable spaces; old-store migration/PAP1 upgrade is unqualified.

Return severity, exact commit/file/line, violated invariant, concrete scenario,
reproduction evidence, suggested regression and overlap with later work. Mark
hypotheses separately from demonstrated defects. Keep test scratch disk-backed
and preserve failure bytes and release-specific logs.
