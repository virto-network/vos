# Agent saga: current status

This is the authoritative status and remaining-work index. Other handoffs are
navigation or checkpoint evidence, not competing plans. Updated 2026-09-20.

## Review checkpoint

Review the current `saga/agents` tip, with new delta `16adf95e..saga/agents`.
Implementation uses `wip/ch08-runtime-directory`; only qualified consolidated
checkpoints are fast-forwarded into the root reviewer worktree. Master is
unchanged; nothing has been pushed. This is **not production qualification**.
The complete Agent Architecture Saga remains the objective.

The new batch includes:

- `caeeac18`: bounded control worker moves lifecycle/reconciliation off the
  routing loop. Shutdown hides admission without acquiring the busy owner,
  rejects queued commands, drains work and reports failures. Idle-exit accounting
  includes active control work.
- `17fb38e9`: execution restores Standard-runtime state once, retaining all
  validation rather than restoring a validation clone and then restoring again.
- `1ef5f703`: indexed parent readiness preserves first-ready ordering; installation
  IDs and artifact accounting no longer rescan all previously restored actors.
- `63d52425`: physical one-entry directory scaling regression.
- `066e6d3c`: independently reproduced runtime bundled with matching pins.
  Runtime ABI remains r18; system actor templates are unchanged.
- The handoff adds the explicitly disposable Counter invocation campaign and
  compacts superseded status notes.

Earlier independent-Agent dispatch, Local leases, retirement, targeted lookup,
directory audit reuse, catalog isolation, public management-history recovery,
and bounded package envelopes remain included. See [review guide](agent-saga-review.md),
[execution evidence](agent-execution-checkpoint-review.md), and
[recovery contract](agent-recovery-contract.md).

## Current evidence and limitations

Logs below are under
`.worktrees/ch08-c2-native/target/task-tmp/` unless stated otherwise.

- 52 Standard tests pass, including 4,096-actor encode/restore and the new
  multi-branch forest invariants (`indexed-restore-standard-final.log`).
- 108 bundled wire tests pass, five opt-in tests ignored
  (`indexed-bundled-wire.log`). Explicit scaling test passes separately.
- 21 bundled Local recovery tests pass without a candidate override
  (`indexed-bundled-local.log`), including substituted-history rejection.
- 56 supervisor/adapter and 19 control-owner/worker tests pass on latest source
  (`indexed-final-supervisor.log`, `indexed-final-control.log`).
- Four CLI bundled admission tests pass (`indexed-bundled-admission.log`).
  Current CLI release bundle generation and verification pass.
- Independent pinned-source/builder reproduction passes
  (`indexed-runtime-reproduction-verifier.log`; implementation directory
  `target/agent-release-reproduction/run.S0FT3e`).
  Additional clean-source ELF/PVM comparison is preserved in
  `indexed-runtime-reproduction.Aa9Ag6`, including the verified CLI bundle.
  Exact source/toolchain/hash pins are in `support/production-artifacts.toml`.

Physical one-entry directory inspection preserves exact output and unchanged
state, but still transports and reconstructs the whole directory:

| Stored actors | Prior bundled gas | Current bundled gas |
| --- | ---: | ---: |
| 1 | 18,319,802 | 16,515,538 |
| 32 | 96,042,580 | 54,495,758 |
| 128 | 571,502,921 | 184,413,547 |
| 512 | 5,980,909,793 | 873,120,581 |

At 512 actors, input is 638,478 bytes; the first debug-host run took 3.852s
versus 0.887s. These are synthetic valid-state/optimized-guest measurements,
not released node throughput or memory-budget qualification.
Logs: `directory-scaling-physical.log`, `indexed-bundled-scaling.log`.
Run `agent::wire::tests::physical_directory_inspection_scaling` with
`--ignored --exact --nocapture`, `VOS_AGENT_RUNTIME_COST_CANDIDATE` pointing
to the new PVM and `VOS_AGENT_RUNTIME_COST_BASELINE` to preserved older bytes.
Without a baseline override it uses the current bundle; comparison against
identical bytes is not a speedup. Tiny invocation fixtures improve only modestly.

Disposable fresh-space evidence: `indexed-lifecycle.4yrvRK/`.
Debug CLI SHA-256:
`a17265ab927daf90c345e5119a15d0b5759401e7e896cd8b5073a2cb442dcc41`.
Bootstrap, generated system packages/config, HTTP/SSH, Local Create, Counter
Install, restart and shutdown pass (`probe.log`). Readiness 25s, Create 51s,
Install 60s, restart 34s; shutdowns 0–1 measured seconds.
Counter mutation, positive retirement, exact retry and read-after-restart pass
(`mutation-test.log`, `read-test.log`, `invocation-probe.log`).
Managed attempts took 32.38s and 33.82s; those daemon restarts took 30s and 40s.
These tests do not establish non-Public policy or multi-profile proof acceptance.
All probe daemons were stopped.

**Latency remains unacceptable:** the unchanged ten-second readiness target
fails; a two-Agent inventory refresh still took 25.604s. Scheduling isolation
and large-directory restoration gains do not eliminate serial authenticated
projection invocation/acknowledgement or whole-state costs.

## Next work

Implementation-only foundation: `InvocationRetirement` now has a bounded AIRT
codec carrying invocation metadata, message and ordered artifact references,
never their preimages. Its commitment is identical to InvocationWork; structural
receipt/PublicPreflight matching is available without claiming signature
verification or prior acceptance. All 176 SDK tests pass
(`compact-retirement-sdk-final.log`), covering field-by-field commitment parity,
strict decoding, malformed references, empty installation data, authorization
substitution and a 1 MiB artifact whose retirement frame is under 1 KiB.
This type is not yet connected to RuntimeWork or production ACK execution.
The runtime ABI and artifacts remain unchanged until the coordinated cutover;
no current-binary latency improvement is claimed from this foundation.

1. Reviewer examines the scoped checkpoint read-only and returns findings.
   Implementation agent applies fixes on latest source.
2. Implement a versioned reference-only retirement request bound to exact retained
   work and authorization. The current ACK transports and hashes actor artifact
   preimages without executing the actor. Preserve scope, receipt verification,
   exact retries, result identity, expiry/retirement ordering and custom-runtime
   recovery; do not manufacture an invalid InvocationWork with missing bytes or
   bypass its current validation. Qualify standard/custom guests and reproduce
   affected artifacts before integration.
3. Reduce authenticated inventory projection work with explicit revision,
   freshness, availability and ordering semantics. Do not skip durable
   acknowledgements, discard mutated guest state, or decode custom-runtime
   internals in the host as a shortcut.
4. Develop bounded touched-state access/incremental publication; qualify costs
   against directory growth, idle Agents and independent workloads.
5. Continue every full-saga gate below. This checkpoint does not narrow scope.

Current-bundle attribution (implementation investigation after the checkpoint):
`indexed-authority-query-profile.log` records the exact fresh signed Credential
query/retirement fixture passing. Invoke carries 1,090,241 bytes and uses
763,079,916 gas, 224,778,110 outer instructions and 5,552,434 inner instructions.
ACK carries 1,092,566 bytes and uses 276,552,182 gas, 101,031,943 outer
instructions and no inner execution. The PC resolver verifies exact PVM/ELF
equality (`indexed-authority-query-map.log`); the hottest mapped regions are
within `blake2b_simd::portable::compress1_loop`, with other hot locations in
program parsing, ActorMachine loading and memcpy
(`indexed-authority-query-symbols.log`). Observer timings are instrumented,
not production latency. This evidence prioritizes reducing authenticated byte
transport/rehashing alongside projection batching, not merely a faster actor
implementation. The existing client already enforces one complete Authority
head across pages and invalidates its cache after failed refreshes; retain both.

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

Historical disposable Local testing passed bootstrap, ingress and counter
lifecycle at `e20cbb76`, but readiness and operation latency failed production
targets. It is historical evidence only, not a pass for later code.


## Historical evidence

The pre-checkpoint status/evidence is retained at
`git show 066e6d3c:docs/agent-saga-status.md`. Original long journals are
preserved at `a1ebce16:docs/agent-saga-handoff.md` and
`a1ebce16:docs/agent-saga-review.md`. Historical pending-work statements apply
only to their recorded checkpoints. No preserved evidence or frozen clients
were deleted by this compaction.
