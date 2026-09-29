# Agent saga: review entry point

This is the sole reviewer entry point. [The live checklist](agent-saga-status.md)
owns release scope. Review read-only and return findings for the latest
implementation branch; do not apply competing fixes on the review worktree.

## Checkpoint boundary

| Purpose | Branch / checkpoint |
| --- | --- |
| Reviewer target | Code `48df3995` plus this docs-only handoff; verify `saga/agents` contains the code checkpoint |
| Review range | `62ffbc20..48df3995` as **one batch**, not individual review assignments |
| Code checkpoint | `48df3995` on `wip/ch08-runtime-directory`: pruning and Linux x86-64 Agent recompiler default |
| Prior tested baseline | `62ffbc20`; `master` remains unchanged |
| Historical startup review | `f1bfa1bd..310ef841`; two findings fixed at `62ffbc20` |

The code commit changes 42 files (+1,942 / -43,868 lines); the documentation
handoff is separate. Verify branch heads before reviewing, and apply findings
on the implementation branch. Do not infer publication from a candidate hash.
This is not a release: batch 1 is not closed, batches 2/3 remain open, production
multi-node startup/public Shared management remain gated, and Local is image-based.

## Code checkpoint changes and review focus

Private host/storage/synchronization, the physical Agent Attested production
adapter, and public external-Local deployment/LCQ2 selection are removed.
Unsupported profiles/configurations fail before Agent writes. Existing external
roots and retained requests are preserved, not migrated or reinterpreted.
Shared enrollment cryptography, canonical contracts/commitments, generic proof
validation, the existing PVM/prover, legacy service callers, and core external-state
qualification fixtures remain. Separate candidate artifact build/probe tools
remain; retired `VOSX_EXPERIMENTAL_*` embedding inputs fail explicitly.

Pruning accounting, not total branch size: six Private files remove 41,802 lines,
including approximately 19,662 test-module lines; the physical Agent Attested
adapter removes 599 production lines plus approximately 387 exclusive test lines
across its host fixtures. CLI cleanup is net -537 lines including tests (-229 in
the retired positive daemon fixtures). Documentation consolidation removes about
3,600 net lines. These are not runtime savings. All removed source/history remains
recoverable from `62ffbc20`.

Refine now selects the existing backend for outer and inner execution.
**Agent execution now defaults to the recompiler on Linux x86-64;
`GREY_PVM=interpreter` selects the explicit reference backend.** The public Refine
API default is unchanged. Final focused default/reference, CLI and actual
image-daemon checks pass; this does not qualify a production release.
Compilation/backend errors are explicit, never an interpreter retry after a
native execution fault. Guest gas, host-call suspension/resume, permissions,
signed program identities and durable publication rules are not relaxed.

Immutable preparation is worker-local. The inner cache holds one exact program
of at most 2 MiB, keyed with the explicit backend; larger programs or unresolved
default selections bypass caching. This bounds admitted input bytes, not native
code/table overhead. Every invocation has fresh mutable state. Review cache
identity/eviction, invalid-entry validation, worker isolation and host-resume behavior.

Native full-memory snapshots/clones still scan/copy the address span and can
materialize a large flat image; native mapping does not inherit sparse snapshot
cost. Instruction-attribution fixtures explicitly use interpreter plus sparse
memory. Native memory descriptors now use atomic `MFD_CLOEXEC`; its regression
passes. Measure memory before making concurrency claims. Whole-runtime
control-state work and Shared serialization are not eliminated by a faster backend.

## Candidate correctness evidence

Logs below are in the disk-backed shared target,
`.worktrees/ch08-c2-native/target`. Counts qualify only the named slice; ignored
tests, fixture signers, and source-specific builds are not production evidence.

| Slice | Result / evidence |
| --- | --- |
| PVM and portability | 274 passed, 2 ignored, including atomic close-on-exec regression; `pvm_vectors` 20 pass after final changes; PVM no-default-feature check passes |
| SDK | 251 passed, 1 ignored; `wrap-final-sdk.log` |
| Minimal host | `std`-only library check passes; `wrap-final-minimal.log` |
| Final default/reference host parity | Same 48 tests pass: default (`GREY_PVM` unset) 54.23 s; explicit interpreter 64.00 s. Entire Local suite, opaque recovery, runtime boundaries, retained proof checks and exact HTTP refusal; `wrap-default-core-tests.log`, `wrap-final-interpreter-core-tests.log` |
| Retained proof contracts | 25 pass, including Attested fail-closed behavior; `wrap-core-retained-proof-tests.log` |
| Physical image Local lifecycle | Create/Install/Invoke, lost response/retry/reopen and reconciliation pass on both backends; `wrap-local-lifecycle-{interpreter,recompiler}.log` |
| Custom runtime / HTTP | Opaque-layout physical recovery and HTTP refusal pass with native execution (2 tests); strengthened exact refusal regression passes separately; `wrap-final-custom-ingress.log`, `wrap-final-http-refusal-exact.log` |
| Final optimized bundled differential | 4 pass, 1 ignored (1.89 s), after the inner cache; exact lifecycle/output/gas comparisons including Invoke/ACK and Resume; `wrap-runtime-backend-final-comparison.log` |
| Final default CLI | Build passes; `GREY_PVM` unset: 300 pass, 45 ignored (53.38 s); `wrap-final-default-cli-loopback.log` |
| Experimental CLI boundary | Unit and daemon-test binaries build; three retired-external refusal tests and retained external pending-Install file/reopen fixture pass; `wrap-v1-cli-experimental-{no-run,negative}.log`, `wrap-v1-external-file-fixture.log` |
| Actual binary refusal | Debug binary creates a Space then rejects obsolete external config without Agent roots, config mutation or endpoint (3.03 s); `wrap-v1-external-config-daemon-refusal.log` |
| Actual image daemon | Default backend startup/SIGTERM smoke passes (26.48 s); endpoint at 23.329 s, debug/concurrent-build evidence, not a startup-latency gate; `wrap-final-default-shutdown.log` |
| Build and static boundaries | Final core test build passes; clean-break CLI/negative-surface guard, selected formatting, shell syntax and diff checks pass; `wrap-default-core-build.log`, `wrap-final-clean-break.log` |
| Physical external-state Clerk | Both backends pass with rebuilt guests; artifact identities and limits below |

These tests do not establish full release-artifact or multi-node load qualification.
Broad unrelated lint debt is not silently fixed or suppressed by this checkpoint.
The first final CLI attempt had 16 socket-permission failures under the sandbox;
the identical suite passed with loopback access. That failed attempt is not
counted as passing evidence or a product failure.

## Measurements: real improvement, bounded conclusion

The optimized exact-bundled differential fixture separates preparation from
execution. Its first cold preparation is 128,865 us interpreter versus 242,333 us
native; one warm actor Invoke is 34,303 us versus 8,199 us execution, with
2,670 us versus 3,277 us preparation. These are selected identified operations,
not aggregate percentiles or production workloads. Native compilation is not free.
These timings are the pre-inner-cache `wrap-runtime-backend-fair-comparison.log`;
the final correctness rerun above supersedes its test result, not its historical timings.

The post-cache optimized fixtures run sequentially after compilation finished,
without concurrent builds. Authority passes on both backends (native 5.55 s,
interpreter 7.55 s whole fixture). Its first query includes the durable Invoke/ACK
owner; a second query uses the returned known head.

| Measured phase | Interpreter | Recompiler |
| --- | ---: | ---: |
| First marked complete Authority Query/ACK | 2.397044 s | 1.295262 s |
| Outer VM, first query execution | 1,102,027 us | 165,873 us |
| Inner creation, first query execution | 102,822 us | 176,000 us |
| Inner creation, second known-head query | 2,953 us | 2,274 us |
| Complete fixture signed-transfer call | 1,191,248 us | 313,576 us |

Authority evidence: `wrap-authority-postcache-{interpreter,recompiler}.log`.
The second query is warm for preparation but has different known-head semantics.
The VM phases do not sum to the complete Query/ACK time. Earlier
`wrap-authority-release-*` runs predate the cache and overlapped compilation;
comparing totals across those runs cannot isolate the cache's benefit.

Clerk evidence: `wrap-clerk-release-{interpreter,recompiler}.log`. Both complete
fixtures pass (58.93 s native, 165.29 s interpreter), including recovery and
reference-ledger checks. The method-call measurements include
Local execution/publication, not HTTP admission, Shared queues or quorum. One
native transfer execution is 150,040 us (including 140,399 us outer VM and
3,370 us inner invocation) after 2,694 us preparation. Additional inspection,
execution and persistence contribute to the 313,576 us complete method call:
one VM execution must not be presented as the whole transfer cost.
These are separate fixture runs with generated keys/events, not exact-input gas
parity or percentile benchmarks; exact bundled differential checks are separate.
Bootstrap/account/root timings remain in the logs.

These optimized test builds disable LTO. They are **not the exact release**,
cold-start capacity evidence, concurrent service benchmarks or the 300-client
gate. The complete query remains slower than the release latency target even
in this isolated fixture. Queue/quorum and cold/warm integrated customer-workflow
measurements remain required.
The optimized core build was launched before the final atomic close-on-exec and
explicit interpreter/sparse attribution hardening; its phase numbers are diagnostic,
not exact `48df3995` qualification. Final PVM, 48-test default/reference host,
CLI and daemon checks above exercise the final source. Exact release reproduction
and capacity qualification remain batch 3 gates.

## Clerk fixture and candidate artifacts

The unchanged ignored test
`agent::clean_bootstrap::tests::physical::native_external_local_create_finalizes_and_retries`
passes with `CLERK_AGENT_PACKAGE`: interpreter 265.85 s, native 135.24 s.
It covers external Create/Install/retry/recovery, Clerk bootstrap, two accounts,
a real signed transfer and exact public-root comparison with the reference ledger.
These are whole **debug** fixture durations, overlapping each other and an optimized
build, not transfer latencies or a valid production speedup ratio. System/issuer
fixture metadata and Local storage remain; no Shared quorum or public Clerk workflow
is qualified.

Logs: `wrap-clerk-{interpreter,recompiler}-rebuilt.log` and
`wrap-clerk-rebuild-guests.log`. Initial stale-guest attempts failed on both backends
before physical Create; the existing recipes rebuilt the experimental guests.
No assertion was weakened and no fixture semantics were changed to make them pass.
The failed attempts remain in `wrap-clerk-{interpreter,recompiler}-debug.log`.

Exact SHA-256 identities used, relative to the shared target:

| Artifact | SHA-256 |
| --- | --- |
| `agent-state-standard/riscv64em-vos/release/agent_runtime.elf` | `6511822a0f9d5b46bad657ac233786e0b5bcc75033262ec135d567bb747b25f0` |
| `agent-state-authority/riscv64em-vos/release/system_authority.elf` | `6e4bcbb69892a9d9ebcf301cc8adcd2196a3dcc20c6def261a84938ffe41b1a3` |
| `clerk-agent-canonical/clerk-ledger.vos` | `628a9aafd357214b927d7165b82b01459269c553b2ec3244524b73d3eaf4be7c` |

These are explicit candidates, not repinned released artifacts. Released pins
remain owned by `support/production-artifacts.toml` and `vosx/build.rs`.

## Reproduction boundaries

From the implementation worktree, use existing disk-backed directories:

```sh
export CARGO_TARGET_DIR=/home/daniel/src/virto/vos/.worktrees/ch08-c2-native/target
export TMPDIR="$CARGO_TARGET_DIR/task-tmp"
export JUST_TEMPDIR="$TMPDIR"
export CARGO_NET_OFFLINE=true
export RUST_MIN_STACK=16777216
export VOS_AGENT_DISABLE_REFINE_ATTRIBUTION=1
cargo +nightly-2025-05-09 test --locked -p vosx --bin vosx
cargo +nightly-2025-05-09 check --locked -p vos --no-default-features --features std --lib
```

Set `GREY_PVM=interpreter` or `GREY_PVM=recompiler` explicitly for parity runs.
Core fixtures use `--features 'agent-runtime storage network http-ingress
experimental-state-blocks'`. Authority fixtures additionally need
`VOS_AGENT_PROFILE_REFINE_MACHINES=1` to disable fixture-native outer execution;
keep attribution disabled for latency measurements. Loopback fixtures require
socket permission. Physical guest fixtures are ignored unless selected explicitly.

The existing `just build-agent-standard-state-guest` and
`just build-agent-state-authority-guest` recipes rebuild the external candidates.
For the Clerk fixture, set `CLERK_AGENT_PACKAGE` to the exact package above and
run its full test name with `--ignored --exact --test-threads=1`. Verify artifact
digests; a different file at the same path cannot inherit recorded evidence.
Candidate guest rebuilding is not the reproducible release-promotion gate.

## Tested admission/recovery baseline: 62ffbc20

This commit fixes both findings from the `f1bfa1bd..310ef841` review:

- Imported bootstrap plans recompute their complete root certification and exact
  derived Create/Authority-install decisions at admission, decode and reopen.
  Twelve mutation cases reject altered material; the reviewer's unchanged
  gas-mutation reproducer accepts the original and rejects the modified bundle.
- Unsupported incoming rosters fail before control-store creation/import; stored
  unsupported plans fail before import/owner initialization. Fresh-root rejection
  leaves no files and permits singleton retry; closed-owner restart preserves files.

Shared-target `fixed-startup-review-fixes-*` logs include `binding-tests.log`,
`certified-tests.log`, `public-reproducer.log`, `production-gate.log`,
`stored-roster-final.log`, `cli-suite.log`, `production-build.log` and
`std-check-final.log`. Original startup/reopen and post-Invoke/pre-ACK leader-loss
fixtures use physical runtime/Raft but candidate artifacts and fixture metadata,
not three released daemons. Full original review/reproduction details are at
`62ffbc20:docs/agent-saga-review.md`; the broader chronology and four removed
handoffs are preserved at the same commit. No evidence files or test stores were
deleted by documentation consolidation.

## What remains before the next release decision

Finish post-cache phase measurements and remaining backend/resource qualification
before closing batch 1. The recorded default-path checks are complete. Then follow
only the live plan:
real fixed-three-node Shared lifecycle/Clerk and retained growth (batch 2);
exact-release load, failure/backup/restore, soak and artifact qualification
(batch 3). No release date, completion percentage or production capacity claim
follows from these passing internal fixtures.

Review failure-before-write behavior, retained wire/enrollment contracts, cache
lifetime, native memory/fault/resume semantics and exact retry/recovery. Report
severity, location, violated invariant, concrete failure scenario and regression.
Distinguish demonstrated defects from unqualified release gates.
