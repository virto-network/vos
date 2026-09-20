# Agent saga: current status

This is the authoritative status and remaining-work index. Other handoffs are
navigation or checkpoint evidence, not competing plans. Updated 2026-09-20.

## Review checkpoint

Review checkpoint `c8028394` on `saga/agents`, with delta
`16adf95e..c8028394`.
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

## Review-checkpoint evidence and limitations (r18, c8028394)

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

### Implementation-only cutover (r19, not a review/release checkpoint)

Foundation commits `930a5450`, `76d37d4d` and `493a098c` introduce bounded
reference-only `InvocationRetirement`, reuse it for retained acceptance metadata,
and check complete SDK-to-execution correspondence before successful commit.
The redundant Standard metadata implementation is removed. Retirement commitment
matches InvocationWork without manufacturing empty artifact preimages; structural
authorization matching does not substitute for signature or acceptance checks.

The in-progress source now uses ABI r19 and its control-schema pin. Clean results
use the authenticated SDK work commitment, with exact identity checked on
restore/retry/retirement; legacy recovery and ACK entry points refuse clean
results. The regression rejects a restored clean result carrying a legacy
commitment and verifies valid restore, retry and retirement. This is a clean
break, not old-state migration or a demonstrated latency improvement.

**Do not deploy this implementation yet:** RuntimeWork ACK now carries compact
InvocationRetirement. Host compilation and the source recovery suites below pass;
compiled custom/Standard guest and release artifact qualification remain open.
Bundled runtime/system templates and guest fixtures are
still r18; rebuild, reproduce and repin the affected artifacts together before
advancing `saga/agents`. The existing r18 checkpoint remains unchanged.

Source evidence: 178 SDK tests (`r19-sdk-round4.log`), 41 clean-wire tests
(`r19-clean-wire.log`) and 52 Standard tests (`r19-standard.log`) pass.
The broader `r19-source-wire.log` run has 99 passes, four ignored and **three
failures**: both `bundled_typed_error_*_requires_retirement` tests and
`bundled_unseen_expired_invocation_preserves_state_after_restore` report guest
Panic instead of Halt. Its `--skip bundled_runtime` filter did not exclude these
bundled tests; r19-host/r18-guest mismatch remains unqualified until the coordinated
rebuild and rerun. Do not count this as a passing full wire suite.
The corrected source-only filter (`--skip bundled_`) passes 99 tests with four
ignored (`r19-source-only-wire.log`); it does not qualify bundled execution.

Retained-acknowledgement recovery now consumes reference-only metadata directly;
full-work callers project to the same implementation after preimage validation.
It returns only an exact already-retained fact, never accepts unseen work, and
checks both work and authorization commitments. A restart regression rejects
altered message and structurally matching but different authorization without
mutation. Focused regression, 99 source-wire tests (four ignored), and 52 Standard
tests pass (`r19-retirement-recovery.log`, `r19-retirement-recovery-wire.log`,
`r19-retirement-recovery-standard.log`). Fresh retirement application now also
uses reference-only metadata; the full-work entry points validate preimages and
delegate to this one core. Receipt signatures, scope, exact retained binding,
observation ordering, stale-target error retirement, projection compaction and
capacity checks remain enforced. The direct compact regression checks unseen
work refusal, exact retry, and state equality with the full-work wrapper.
The 99 source-wire tests (four ignored) and 52 Standard tests pass
(`r19-compact-application-wire.log`, `r19-compact-application-standard.log`).
RuntimeWork ACK now encodes metadata/references, not artifact preimages. All 179
SDK tests pass (`r19-compact-wire-sdk-final.log`), including a 1 MiB artifact whose
empty-state ACK frame is under 2 KiB, malformed metadata and r18-header refusal.
Standard dispatch uses the compact core; the obsolete decoded/full-work ACK
dispatcher split is removed. Custom-linear compares the complete retirement
projection against its own retained canonical invocation (not Standard state).
Journal replay now persists compact retirement metadata and validates exact scope,
authorization and transition-proof identity. Local execution compares outcomes
against the same reference-only projection; Invoke/Resume still validate their
preimages. Shared journal constructors project the original invocation explicitly.
The host library check passes with `agent-runtime storage network http-ingress`
(`r19-compact-host-check3.log`); this is compilation, not recovery qualification.
Host test constructors are converted; test compilation passes
(`r19-compact-test-build2.log`). The wire corruption test now checks transported
references for ACK and preimages for Invoke. All 99 source-wire tests pass, with
four ignored (`r19-compact-transport-wire.log`). All 41 journal tests pass
(`r19-compact-journal-final.log`) after updating its corruption fixture to check
authenticated references for ACK and preimages for Invoke. Neither source suite
qualifies bundled guests.
Broader source suites pass: 56 replay (`r19-compact-replay.log`), 33 Local journal
(`r19-compact-local-journal.log`), 97 journal-store (`r19-compact-journal-store.log`),
and 12 custom-linear tests (`r19-custom-source.log`, one compiled-guest test
ignored). The custom test now rejects structurally rebound but substituted
message, gas and incarnation without deleting its retained result. This runtime
has a genuinely different state layout; these are source, not physical, tests.

The r19 Standard guest candidate build passes in the separate disk-backed target
`agent-r19-artifacts/runtime` under the shared build target
(`r19-runtime-guest-build.log`). CLI compilation also passes (`r19-vosx-check.log`).
The preserved r18 CLI rejects this ELF with `ABI probe did not halt: Panic`;
do not use it to validate r19 or infer a same-generation execution defect.
Direct r19-host/guest multi-megabyte yield-resume-retirement comparison passes
(`r19-physical-yield-retire.log`, 13.82s debug host). This establishes output
agreement for that fixture, not a latency benchmark. The custom guest build passes
in `agent-r19-artifacts/custom` (`r19-custom-guest-build.log`); its physical
scheduling/lifecycle and attested-context refusal test passes
(`r19-custom-physical.log`, 9.48s debug host). These steps do not change the pinned r18 bundle
or qualify mixed-generation startup; independent artifact reproduction remains.
Do not hydrate missing bytes or restore the
old full-work wire as a compatibility shortcut. Remove remaining transitional
full-work ACK wrappers once their callers are cut over.

### Remaining sequence

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
