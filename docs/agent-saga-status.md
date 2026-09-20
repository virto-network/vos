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

## Historical reviewer checkpoint: debug-host CLI campaign

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

## Implementation follow-up: optimized-host baseline

Implementation-only qualification harness:
`bash scripts/check-agent-local-lifecycle.sh VOSX TEST_CLIENT COUNTER_PACKAGE [DISK_EVIDENCE_ROOT]`.
Build inputs first; the harness freezes and hashes them, creates a fresh isolated
space, verifies the embedded release bundle, checks generated ingress defaults,
runs Create/Install/restart/mutation/retirement/retry/read, and stops its exact
child daemons. It records millisecond phase timings and one-second Linux process
samples (RSS/high-water RSS, threads, CPU ticks and file descriptors). Samples
are not guaranteed resource peaks. The script exits nonzero if any readiness
exceeds ten seconds even when functional checks pass; zero matching Rust tests
cannot count as a pass. This harness does not establish load or all-profile gates.
The first optimized-host campaign is complete; the reviewer branch remains
`9cd2fa6a`. It does not change that checkpoint's debug-host evidence above.
Build: `cargo +nightly-2025-05-09 build --release --offline --locked -p vosx --bin vosx`,
normal fat LTO/single codegen unit, no profile override. Log:
`inventory-release-cli-build.log` (6m30s). Host source/artifacts are `9cd2fa6a`.
The test client remains the frozen debug client used above, not a release client.

Evidence is in implementation
`target/agent-lifecycle-qualification/indexed-lifecycle.FzlxZI/`; console log
`inventory-release-lifecycle.log` is under the task log root above.
Release CLI SHA-256:
`d101f21eb210a8e1ba975280098117768d62e64de22eec6d5428db2bec73818e`.
The embedded bundle, generated HTTP/SSH, Create/Install, restart, mutation,
positive retirement, exact retry and read-after-restart pass. All four daemons
stop normally and the test ports are closed. The harness exits **1 as intended**
because one restart exceeds the unchanged readiness gate:

| Phase | Milliseconds |
| --- | ---: |
| Fresh readiness | 8,068 |
| Create | 16,003 |
| Install | 21,974 |
| First restart readiness | 11,022 |
| Mutation readiness / test | 5,922 / 20,647 |
| Read readiness / test | 6,328 / 20,717 |

Managed mutation/read attempts take 18.91s/19.00s; client assertions add overhead.
Shutdowns are 307/305/914/1,017ms. Across daemon samples, maximum observed RSS is
288,204 KiB, reported RSS high-water 299,408 KiB, threads 42, FDs 264.
Initial-daemon last observed CPU time is 4,287 ticks at 100 ticks/s over roughly
45s of sampled lifetime. These are one-user samples, not hard capacity bounds.

The initial one-Agent inventory takes 2.528s; the post-Create two-Agent refresh
takes 2.750s, still one query. First restart spends about 5.936s opening the
Shared host (difference between cumulative recovery markers), then 2.815s in
inventory. Release optimization improves but does not eliminate execution/replay
cost. **The released-host readiness gate still fails**, and managed operations
remain seconds-long. Do not attribute all remaining delay to debug compilation.
The retained CLI/documentation clean-break check also passes
(`inventory-clean-break.log`).

### Replay/execution attribution (same frozen release binary)

Repeat evidence: implementation
`target/agent-lifecycle-qualification/indexed-lifecycle.Jtce5F/`, console log
`inventory-release-phase-profile.log`. The harness now accepts and records an
explicit `RUST_LOG`; this run adds `shared_host`, `shared_journal_driver` and
`local_journal_driver` debug categories to the normal filter. Binary/package
hashes match the baseline, and the script copy is frozen and hashed too.
Functional checks pass again; exit 1 is the expected readiness-gate failure
(restart 11,006ms). Create/Install take 15,638/20,974ms; managed mutation/read
attempts take 18.82/19.27s. This is a traced diagnostic repeat, not a load test.

Restart's journal materialization takes 5.490s between executor-setup and
materialize-current markers. Eight physical runtime calls inside that interval
total 5.198360s and 3,401,221,540 gas. Journal-store opening takes 38ms and the
next Raft-ledger stage 25ms; this restart is dominated by replayed computation,
not those store-opening stages. The physical timing includes program preparation
and `RefineContext::run`, not a separate ZK proving operation.

The harness also summarizes traced executions by **complete daemon phase**, not
by user request. Startup, maintenance, authentication and exact retries are included:

| Daemon phase | Traced runtime calls | Summed physical seconds |
| --- | ---: | ---: |
| Initial bootstrap + Create + Install | 127 | 27.953 |
| First restart | 30 | 6.978 |
| Mutation campaign | 90 | 14.148 |
| Read campaign | 90 | 14.452 |

`runtime-execution-summary.tsv` also records summed input bytes and gas; its
summary block was checked against the completed trace. Zero traced calls with
the default log filter means absent instrumentation, not zero execution.
Source inspection finds a fresh `materialize_current` in
`SharedJournalAgentDriver::replay_durable_clean_terminal_with_input` for durable
lifecycle evidence. That is an intentional verification boundary; its specific
share of managed-invocation time is not isolated by these logs. Do not replace it
with an unchecked cached result. Existing projection checkpoint cadence bounds
the suffix but does not bound its replay cost in time or gas.

## Implementation follow-up: targeted CLI discovery

Implementation-only targeted CLI discovery now replaces the old Agent-directory
walk plus separate replica fetch. Install and managed invocation seek immediately
before the requested Agent using the Inventory cursor order, then stop after its
complete roster. Minimum/maximum ID boundaries are tested. Exact query/head,
active API credential/owner, unchanged cross-page claims and roster generation
remain required. The small fixture uses one descriptor-discovery dispatch instead
of two; the separate retained credential query remains. This is not touched-state
guest execution or a claim that all invocation overhead is removed.

The public inventory HTTP route now admits the combined selector while retaining
API signature verification and exact canonical response binding. Tests reject
unsigned and selector-substituted requests before dispatch. Two focused discovery
tests pass (`targeted-cli-discovery-http.log`), as do 25 Local CLI tests, with 18
explicit live cases ignored (`targeted-cli-local-tests-sockets.log`), and the node
signature-admission regression (`targeted-inventory-http-admission.log`). The
first Local suite attempt lacked socket permission; its failure log is preserved.

Matched debug CLI/client functional campaign passes at implementation
`target/agent-lifecycle-qualification/indexed-lifecycle.YT7BM0/`, console log
`targeted-cli-lifecycle-http.log`: Create/Install/restart/mutation/retirement/retry
and read-after-restart all succeed. Exit 1 is the expected readiness-gate failure.
This run overlaps a test build during early phases, so it is not a performance
comparison. CLI SHA-256 is
`c96c327222d8542de2b61ea4062f30e3f0e7c1142130a6b48d295ef5d6374881`;
client SHA-256 is
`4fc762b0e03b9306bf0bca79c1b23c797e2cd0af602cdfaa8c14d3b3810dc647`.
The initial campaign `indexed-lifecycle.r6zMSu/` exposed the HTTP selector gap
(403 before descriptor dispatch); its evidence is retained. No artifacts or ABI
changed. Both node and CLI source changes must ship together; the fixed reviewer
node does not yet expose this selector over HTTP. Optimized results follow.

### Current optimized-host qualification

Production source `f98a7afc`, unchanged r19 artifacts; normal release build passes
(`targeted-release-cli-build.log`, 7m23s). Frozen evidence:
`target/agent-lifecycle-qualification/indexed-lifecycle.5HJ5w4/`;
console `targeted-release-lifecycle.log`. Release CLI SHA-256:
`5a3a5ca73272d97d4a763609069eb6fb999ba7b6c6bd83cdc803f0e0bfce244a`.
Client hash matches the targeted-discovery debug client above. No builds/tests
ran alongside this campaign. Functional lifecycle and all four scoped ten-second
readiness checks pass; all four shutdowns complete in 305–915ms. This supersedes
the implementation baseline's readiness outcome, not the fixed review checkpoint
or the still-open production latency/throughput gates.

| Phase | Milliseconds |
| --- | ---: |
| Fresh readiness | 8,190 |
| Create / Install | 15,639 / 19,702 |
| First restart readiness | 5,824 |
| Mutation readiness / test | 8,876 / 18,599 |
| Read readiness / test | 6,333 / 18,539 |

Managed mutation/read attempts take 16.88s/16.80s. Maximum sampled RSS is
271,544 KiB, reported high-water RSS 292,616 KiB, threads 42, FDs 264.
Whole-phase traced calls are 114/23/85/83 (initial/restart/mutation/read),
with summed physical time 28.046/3.053/15.365/13.063s. These are not per-request
counts. Compared with the preceding traced baseline, operations remain slow;
different retained journal suffixes also affect restart, so do not attribute the
entire restart improvement to targeted lookup or infer load capacity from one run.

Additional boundary/clean-break checks:

- Numeric cursor borrow across all 31 nonfinal bytes passes
  (`targeted-cursor-boundaries.log`). Authority targeted seeks match the complete
  visible directory for admin/owner, including filtered Private rows and absent
  predecessor IDs (`targeted-authority-seek.log`).
- Default-feature `cargo check --workspace --all-targets --offline --locked`
  passes (`targeted-workspace-check-final.log`). This exposed four stale physical
  test ACK payloads; they now use r19 `InvocationRetirement`, retaining forged
  authorization, divergent actor and exact-retry assertions.
- All five default-feature physical integration tests pass with the reproduced
  runtime explicitly supplied and ignored tests included
  (`r19-integration-cutover-final.log`, 3.55s). The stale exact ABI assertion is
  updated from r18 to r19. This is not the feature-gated attested-proof suite or
  full workspace test qualification. Initial failures remain in the log root.

### Diagnostic preparation/execution and lifecycle-verification split

The journal executor now traces preparation and execution separately, and a
`durable_terminal_verification` span identifies physical calls made inside the
fresh-verifier lifecycle boundary. No request contents are logged and no replay,
authentication, ledger or exact-state checks are bypassed. The qualification
summary retains its original columns and adds split-timing coverage plus nested
verification counts/time. A zero coverage count means missing instrumentation,
not measured zero preparation. Parsing the previous frozen trace reproduces all
original totals with zero split coverage.

Diagnostic evidence: implementation
`target/agent-lifecycle-qualification/indexed-lifecycle.XSj3X4/`, console
`terminal-replay-tracing-lifecycle.log`. Frozen **debug** CLI SHA-256:
`1a4f893e50ae9860aa9b496a0800aa3f87e7f7344aa443461de62272d168c41b`;
client remains `4fc762b0…`. All functional cases pass; all four daemons stop.
Exit 1 is the expected debug-host readiness failure (13.034/9.014/10.682/10.376s).
This does not replace the optimized-host qualification above.

| Complete daemon phase | Calls | Preparation seconds | Execution seconds | Calls inside fresh terminal verification |
| --- | ---: | ---: | ---: | ---: |
| Bootstrap + Create + Install | 126 | 0.963 | 33.347 | 16 |
| Restart | 23 | 0.434 | 3.009 | 0 |
| Mutation/retry | 85 | 0.658 | 14.987 | 0 |
| Read after restart | 83 | 0.648 | 13.866 | 0 |

Every traced execution has split timing. Create/Install take 21.409/30.692s;
their fresh durable verifications take 6.425/9.377s, including 14.323s of physical
execution across both. Mutation/read tests take 24.963/26.008s and **do not enter
this verification path**. Therefore fresh lifecycle replay is a substantial
Create/Install cost, but cannot explain ordinary managed invocation latency in
this campaign. Preparation is a small fraction of the traced execution path;
these debug measurements do not establish released percentages or account for
every source of request wall time. No proving-stage timing is inferred.

Feature-scoped host check passes (`terminal-replay-tracing-check.log`). Compiled
Inventory interrupted recovery passes (`terminal-replay-tracing-recovery.log`,
one test); management finalization across clock advancement also passes
(`terminal-replay-tracing-finalization.log`, one test). CLI build, shell syntax
and diff checks pass. The instrumentation is diagnostic, not a performance fix.

## Next sequence

Workspace gate follow-up: `cargo +nightly-2025-05-09 test --workspace --no-run
--offline --locked` passes at source `496c4ea0` (6m10s), log
`saga-workspace-test-build.log`. This builds default workspace test targets;
it does not run them or include every optional feature/standalone guest.
The serial `test --workspace --lib --offline --locked -- --test-threads=1`
campaign passes (`saga-workspace-lib-tests.log`): 2,406 tests, zero failures,
six explicitly ignored, counting each crate's final summary rather than nested
child-harness output. Includes 1,590 `vos`, 182 SDK and 120 PVM-proof library tests;
the main `vos` suite takes 226.74s. Uses disk-backed `TMPDIR` and the existing
`agent-r19-artifacts/scripted` ELF explicitly selected. This is the default
workspace library gate, not CLI binary tests, integration execution, ignored or
all-feature tests, or freshly rebuilt standalone guests. Other warnings remain;
this is not a lint/format gate pass.
Architecture and operator docs now distinguish protocol design from current
profile qualification and explicitly warn that post-bootstrap native backup is
unavailable. The production inventory owner's test-only descriptor import is
scoped to tests; no runtime or artifact behavior changes.

Additional gates at `d17794c5`:

- CLI binary suite (`cargo test -p vosx --bin vosx`, serial, offline/locked):
  271 passed, zero failures, 20 opt-in ignored, 85.15s;
  `saga-cli-bin-tests.log`. No live deployment test is implicitly enabled.
- `scripts/check-agent-clean-break.sh` passes against the current debug binary
  and operator docs (`saga-clean-break-final.log`), with offline Cargo and the
  pinned host toolchain. Retired commands, flags and paths remain absent.
- Explicit `private-agent-crypto` feature, `agent::private_crypto::tests`:
  16 passed, zero ignored, 2.29s (`saga-private-crypto-tests.log`). Includes
  hostile key/envelope substitutions, revocation/rotation, offline recovery,
  stable imports and the 4,096-entry invitation-history boundary. This does not
  qualify Private storage/network lifecycle or released recovery.
- The initial workspace `cargo fmt --all -- --check` failed with differences in
  44 files (`saga-workspace-format-check.log`). A dedicated mechanical follow-up
  applies the pinned formatter to those files; the check now passes
  (`saga-workspace-format-final.log`). Every changed Rust file was compared
  byte-for-byte against `rustfmt +nightly-2025-05-09 --edition 2024 --config
  skip_children=true --emit stdout` applied to its `e194c28e` predecessor; all
  match. There are no hand-written Rust changes in this batch. Review functional
  work before this formatting boundary, or inspect this batch independently.
  Post-format `check --workspace --all-targets --offline --locked` passes in
  37.44s (`saga-formatted-workspace-check.log`). Earlier executed test results
  remain attributed to their pre-format sources; tests were not rerun here.
  Bundled artifacts and their immutable source pins are unchanged. Lint warnings
  and the other release gates remain open.
- The repository's workspace Clippy command (the four exceptions already in
  `just check-all`, otherwise `-D warnings`) fails at `ac1b2860` with 358
  diagnostics in `vos` (`saga-workspace-clippy.log`). Of those, 279 report
  never-used/read/constructed items; the rest include enum layout and ordinary
  style findings. No new lint allowances or automatic deletions were applied.
  This is a failed release gate, not evidence that every unused API is obsolete:
  several belong to the incomplete Shared/Private integration below.

Shared production integration has begun with non-creating archive discovery in
`vosx`'s clean file layer. `CleanAgentGenesisArchiveStoreFactory` pins the private
parent descriptor, discovers bounded canonical space-scoped locators, and opens
existing archives under exclusive leases without creating missing directories.
Archive and committee discovery now share the same hardened directory walker.
The ordinary-genesis store suite passes: 13 tests, one existing opt-in ignored
(`shared-archive-discovery-tests.log`), including new missing-path, sorted/bounded
set, conflicting lease, foreign-space, symlink and replaced-parent regressions.
This is a prerequisite, not production activation: it is not yet called by startup.
Joint discovery now returns lease-owning `CleanSharedGenesisStartupEntry` values.
It rejects orphan archives before query-slot creation, binds each record to the
locator validated by `NativeSharedGenesisRecovery::open`, and rechecks archive,
lifecycle and committee sets before returning. Missing archive, empty archive slot
and structurally decoded record remain distinct; none is finality. All acquired
leases remain in the returned entries. The ordinary-genesis suite now passes 14
tests, one opt-in ignored (`shared-joint-discovery-tests.log`), adding empty-set,
orphan-before-mutation and malformed-intent preservation coverage. The new joint
path still needs positive signed-Shared reservation/record coverage, the public
creation entry point, and lifecycle-controller ownership. Do not activate it in
startup until owner-authenticated recovery succeeds before route publication.
No wire format, finality acceptance or bundled artifact was changed.

1. Reviewer examines `7bd66a7d..saga/agents` read-only and returns findings.
   Apply fixes on latest implementation source; advance the reviewer branch only
   at qualified checkpoints. Do not mix reviewer edits with implementation work.
2. Extend the optimized-host baseline to growing-Agent directories and independent
   versus same-Agent workloads. Shared reopen is now attributed to materialization;
   distinguish physical work kinds and repeated authorization/projection execution
   on the managed invocation/ACK path. Fresh terminal verification is now measured
   on Create/Install, but absent from the ordinary mutation/read campaign; do not
   optimize it expecting to solve that separate path. Keep exact
   identities, CPU/RAM/FD and queue/tail measurements. The latest scoped readiness
   pass does not establish production latency/capacity gates.
3. Address whole-state/touched-state and incremental-publication costs with an
   explicit common runtime contract, recovery invariants and growth acceptance;
   preserve fresh revision-consistent projections and scheduling isolation.
4. Complete ordinary Shared production integration as a cohesive functional
   batch, rather than deleting its currently unused components to satisfy lint.
   Startup still installs `UnavailableAgentFinality`. The root-pinned owner
   already has exact replay attestations and `recover_deferred_shared_generations`,
   but its ordinary genesis preparation/publication/recovery flow has no CLI/node
   caller. Wire durable, exclusively leased intent/issuer/query/reply/publication
   stores and the genesis archive into the lifecycle owner; recover the complete
   deferred set before exposing routes. Creation must go through signed issuance,
   publication and positive retirement. Never replace the unavailable verifier
   with archive-only acceptance or a permissive verifier. Acceptance requires a
   released create/replicate/restart/recovery campaign plus missing/substituted
   publication and interrupted-write refusal, not just the existing source tests.
5. Continue every full-saga gate below. This checkpoint does not narrow the goal.

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
