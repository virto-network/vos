# Agent saga: current status

This is the authoritative status and remaining-work index. Other handoffs are
navigation or checkpoint-specific evidence, not competing plans. Updated 2026-09-20.
The complete Agent Architecture Saga remains the objective.

## Review boundary

Review the inventory checkpoint on `saga/agents`, new delta
`7bd66a7d..saga/agents`. Implementation continues on `wip/ch08-runtime-directory`
in `.worktrees/ch08-runtime-directory`. Master is unchanged; nothing is pushed.
See [review guide](agent-saga-review.md) for two consolidated groups.
This qualifies a disposable Local/Public-policy test workflow, not production,
old-store migration, all-profile architecture or thousands-user capacity.

Source `eef8890a` reuses immutable invocation resolution while preserving
authentication and complete actor-record correspondence. Sources `525319d5`
and `2ccfacb8` add the signed bounded Inventory stream and host reconstruction.
Integration `9fe6762e` pins matched artifacts and tests physical fresh/cached
queries. The checkpoint adds interrupted compiled-Inventory recovery evidence.

Prior concurrency, Local lease/retirement, control-worker isolation, targeted
lookup, catalog isolation, public management recovery, indexed restoration and
r19 reference-only retirement remain included. Their checkpoint evidence is
linked from [execution evidence](agent-execution-checkpoint-review.md) and
[recovery contract](agent-recovery-contract.md), not retroactively extended to
unqualified profiles.

## What changed and what did not

- Invoke/Resume resolution is bound to the original SDK work and full actor
  record. Commit still authenticates work/authorization and rejects changed
  records. Unbound callers still perform full correspondence validation.
- Signed Inventory pages combine fresh credential claims and Agent/replica/actor
  rows at one head. Bounds are 64 total rows, eight complex rows, and the existing
  16 KiB wrapped reply ceiling. Strict cursors and visibility filtering remain.
- The host reconstructs complete descriptors and actor sets before publishing.
  Wrong bindings, inconsistent claims/head, incomplete/excess rosters, foreign
  actors, capacity overflow and transport failures invalidate reuse.
- An unchanged-head hint suppresses rows only after fresh authentication and
  exact Authority/credential/claims checks. Credential rotation fetches a new view.
- The old production per-Agent replica/actor fetch loops are removed.
  Standalone projection APIs still used by ingress/CLI remain intentionally.
- This reduces runtime execution count, not whole-state transport/restoration,
  publication, signature cost or durable ordering. No native fallback or
  custom-runtime private-state decoding was introduced.

ABI remains r19. Runtime and both system templates pin immutable source
`2ccfacb82089f804dbdbfea7ebfcabf377e7dde3`; template builder remains `3c5e44c7`.
Exact ProgramIds/digests are in `support/production-artifacts.toml`.
Use fresh disposable spaces; older stores and directory relocation are not
qualified migration or backup/restore workflows.

## Evidence

Logs below are under `.worktrees/ch08-c2-native/target/task-tmp/`.

- 182 SDK tests: `inventory-stream-sdk-final.log`; 75 Authority tests, two opt-in
  ignored: `inventory-stream-authority-final.log`; 52 Standard tests:
  `inventory-stream-standard-final.log`.
- 18 owner tests and 31 adapter tests: `inventory-host-owner.log`,
  `inventory-host-adapters.log`. Includes hostile cross-page data, revocation,
  Private filtering, credential rotation, cancellation and no partial publication.
- Scripted journal campaign: `inventory-host-suffix-rotation.log`, 212.73s.
  Seventeen complete 241-Agent refreshes produce 527 distinct signed queries and
  1,054 ordered entries. Exact inventory, bounded retained suffix, repeated
  checkpoints and no pending projection are checked. Uses native Standard and a
  purpose-built actor PVM, not the compiled production Authority.
- Independent byte-identical runtime ELF/PVM and both signed templates:
  `inventory-pinned-reproduction.log`, implementation
  `target/agent-release-reproduction/run.VMA5jz`.
- 110 bundled wire tests, five opt-in ignored: `inventory-bundled-wire.log`.
  All 21 Local tests: `inventory-bundled-local-configured.log`. The first run
  passed 19 but lacked the scripted guest path for two fixtures; its failed log
  remains at `inventory-bundled-local.log`. Corrected run explicitly uses the
  existing r19 `AGENT_SCRIPTED_RUNTIME_ELF`; no assertion was disabled.
- Four CLI bundled-admission tests: `inventory-bundled-admission.log`.
  CLI/test-client builds: `inventory-cli-build.log`, `inventory-cli-test-build.log`.
  Release bundle generation/verification passes in implementation
  `target/agent-release-reproduction/inventory-2ccfacb8/integrated-bundle`.
- Compiled Authority plus real outer PVM fresh Inventory and authenticated
  unchanged-head retirement: `inventory-bundled-physical-query.log`, 24.97s.
- Compiled Inventory interrupted recovery:
  `inventory-bundled-physical-recovery-final.log`, 53.41s. Reopens after Invoke,
  retires the exact pair, simulates failure clearing a durable ACK, reopens again
  without duplicate ordered entries, rejects competitors without state changes
  and accepts a fresh successor. Original scripted regression still passes:
  `inventory-original-recovery.log`. Initial new-test failure is retained in
  `inventory-bundled-physical-recovery.log`: synthetic Merge/Local methods absent
  from the real Authority correctly fail schema validation before admission;
  the test now asserts that exact rejection and unchanged state.

Immutable-resolution source/physical tests and earlier gas profiles remain
indexed at `9fe6762e:docs/agent-saga-status.md`. No broad release suite or
all-profile claim is inferred from these scoped passes.

## Frozen-binary disposable CLI campaign

Evidence: `indexed-lifecycle.inventory-final.JsB1oS/`. Scripts use frozen binary
copies and fixed-path isolated XDG/space directories. Generated HTTP/SSH defaults
are preserved; only test ports change to 18109/2253. No builds ran alongside
this final campaign. Guest artifacts are optimized; CLI/host are debug builds.

CLI SHA-256:
`8736f68f18fec28bfcbbd0311e84f2f4336a9b30a5c1c86adb7430e071aed315`.
Test-client SHA-256:
`337767089f28ca1c9623dd9f35b1b6488927ad944083943ec8edd6a532427a26`.

`probe.log` passes bootstrap, HTTP/SSH, Create, Install and restart:
13s readiness, 22s Create, 31s Install, 17s restart; both shutdowns below 1s.
`invocation-probe.log` passes mutation/positive retirement/exact retry in 28.79s
(managed attempt 26.76s) and read-after-restart in 30.80s (managed 28.65s).
Invocation readiness is 10s/11s, shutdown 2s/1s. Both scripts exited zero and
all four probe daemons stopped. This is Local/Public-policy acceptance only.
**The ten-second readiness gate still fails.**

Earlier diagnostic `indexed-lifecycle.inventory.kCJ8Bt/` also passed, but a
test-client build replaced its CLI during the campaign. Keep it as diagnostic
evidence, not a fixed-binary comparison; the frozen campaign supersedes it.

## Performance interpretation

The final run's first inventory is one query in 3.563s. After Create, a complete
two-Agent refresh is one query in 3.962s; the preceding lifecycle phase takes
13.820s. The prior resolved-runtime campaign required six queries and 19.793s
for the corresponding two-Agent inventory. This confirms reduced invocation
count and debug-host refresh work, not controlled released throughput.
An authenticated unchanged-head refresh still takes one query.

| Disposable debug-host operation | Prior resolved runtime | Inventory checkpoint |
| --- | ---: | ---: |
| Create | 37s | 22s |
| Install | 46s | 31s |
| Restart readiness | 26s | 17s |

The operations remain seconds-long. Mutation/read latency remains roughly
27–29s for the managed attempt: inventory batching does not solve that path.
Earlier immutable resolution reduced the measured Credential Invoke+ACK gas
24.3% versus r18; that profile does not establish the new Inventory query's
released cost. Large compiled directories, idle-Agent scaling, mixed load,
resource budgets and tail latency remain unqualified.

## Next sequence

1. Reviewer examines `7bd66a7d..saga/agents` read-only and returns findings.
   Apply fixes on latest implementation source; advance the reviewer branch only
   at qualified checkpoints. Do not mix reviewer edits with implementation work.
2. Establish released-binary phase/cost baselines for startup, managed
   invocation/ACK and inventory at fixed one-, two- and growing-Agent sizes.
   Keep exact binary/artifact identities, CPU/RAM/FD and queue/tail measurements.
   Do not treat the debug campaign as a passed production latency gate.
3. Address whole-state/touched-state and incremental-publication costs with an
   explicit common runtime contract, recovery invariants and growth acceptance;
   preserve fresh revision-consistent projections and scheduling isolation.
4. Continue every full-saga gate below. This checkpoint does not narrow the goal.

## Remaining full-saga acceptance gates

- A common execution/lifecycle/publication/acknowledgement/recovery contract
  qualified across standard and custom runtimes and promised profiles.
- Released ordinary Shared creation, authenticated genesis/finality, replication,
  restart and recovery. Partial archive/issuer/genesis source work is not a
  released end-to-end result.
- Native backup/restore after bootstrap; complete Agent CLI and multi-profile
  lifecycle acceptance. Do not enable unsupported backup by broadening allowlists.
- Authenticated bounded Authority/issuer record reclamation; exact retry,
  retirement, expiry, crash, busy shutdown and mixed pending-state matrices.
- Private/Attested cryptographic and cross-runtime proof acceptance, including
  portable positive acknowledgements and resource/capacity boundaries.
- Incremental/touched-state costs, bounded revision-consistent directory
  projections, node maintenance isolation, prepared execution and recovery
  scaling. The current runtime ABI/publication still carries whole state.
- Quantitative released-binary latency, throughput and resource budgets:
  same-Agent versus independent Agents, idle namespaces, growing directories,
  queue saturation, CPU/RAM/file descriptors and tail latency. Concurrency tests
  do not establish thousands-active-users capacity.
- Reproducible released artifacts; complete workspace tests/lint/formatting,
  clean-break checks, examples and operator documentation against that release.

## Historical evidence

Full pre-inventory status is at `9fe6762e:docs/agent-saga-status.md`; r19 reviewer
status is at `7bd66a7d:docs/agent-saga-status.md`; r18 status is at
`c8028394:docs/agent-saga-status.md`. Original long handoff/review journals remain
at `a1ebce16`. Historical pending-work statements apply only to those checkpoints.
This compaction deletes no frozen clients, failure bytes, stores or logs.
Keep scratch disk-backed, not RAM-backed /tmp.
