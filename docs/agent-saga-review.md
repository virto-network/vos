# Agent saga: review entry point

This is the sole reviewer entry point. [The live checklist](agent-saga-status.md)
owns release scope. Review read-only and return findings for the latest
implementation branch; do not apply competing fixes on the review worktree.

## Checkpoint boundary

| Purpose | Branch / checkpoint |
| --- | --- |
| Reviewer target | `saga/agents` containing this common-checkpoint follow-up; verify the implementation fast-forward before reviewing |
| Review range | `6d2a9b38..saga/agents` as **one batch**: common snapshot authority, physical rebinding and candidate catch-up |
| Preceding code checkpoint | Scoped read delegation `6d2a9b38`; Shared journal/applied availability `7c1a1b7c`; backend follow-up `4ea0271c` |
| Prior tested baseline | `62ffbc20`; `master` remains unchanged |
| Historical startup review | `f1bfa1bd..310ef841`; two findings fixed at `62ffbc20` |

The current follow-up is one scoped checkpoint/catch-up batch, not release
qualification. Physical mutation entrypoints remain test-only while historical
pending-recovery retention is unresolved. The preceding pruning changed 42 files
(+1,942 / -43,868 lines). Documentation handoffs are separate. Verify branch
heads before reviewing, and apply findings
on the implementation branch. Do not infer publication from a candidate hash.
This is not a release: batch 1 is not closed, batches 2/3 remain open, production
multi-node startup/public Shared management remain gated, and Local is image-based.

### Common checkpoints: follow-up from `6d2a9b38`

The new common QC authenticates one exact Ordered projection, full fixed-three
committee, authority epoch and the preimage of the existing semantic ancestry
commitment. Independent physical checkpoint cadence must not change subsequent
Ordered claims. A separate owner signature binds that exact QC to the complete
AGS3 physical claim, including node/store identity. AGS3 and AGP1 are unchanged;
generic Raft snapshot bytes remain rejected.

Votes use the existing bounded availability request pool. Each voter reconstructs
and validates its own durable closure; another node's signed physical metadata is
not quorum evidence. Typed catch-up validates the source closure and independent
genesis pins before deriving destination Local state and publishing through its
own head CAS. Source/destination genesis envelopes may differ only in their
declared physical replica and locator node; all remaining intent fields must
match. V2 retains higher terms and full NodeId votes, rejects speculative or
changed cached membership, and refuses rollback. This first implementation
refuses any log suffix beyond the target rather than deleting
entries that may already be committed elsewhere.

Durable ACL1/ACR1 markers cover source compaction and destination import. A
failure quarantines the live owner until audited reopen; marker retirement
precedes reinsertion. Fixed-three followers can reattach without waiting to
become leader, while explicit promotion, pending-management and recovery
barriers remain enforced.

The crucial remaining gate is recovery retention: positive Authority projection
ACK intentionally removes guest result/error records. An offline origin may still
have an uncleared PAP2 that needs the exact prior Invoke/result/ACK history.
Neither current guest state nor another node's empty pending directory proves
that recovery is finished. The new boundary-only Query evidence must not be
extended into a general historical-availability fallback. Production compaction
and catch-up are therefore not enabled by this checkpoint; shared pending pins
or bounded certified recovery evidence are still required.

The passing candidate fixture covers a genuinely pruned Raft prefix, a detached
lagging third voter, exact unacknowledged boundary Query recovery, reopen, subsequent ACK
and continued common ordering despite different physical checkpoint cadence.
Each of three crash fixtures interrupts both source and destination after marker
creation, journal CAS, or ledger installation and completes the same workflow
after reopen. This is controlled byte export/import, not network
snapshot streaming, public startup or released-daemon qualification. External
state-block snapshots/export/reclamation remain unavailable. No tracked guest
artifact changes are needed for this host-only slice.

Evidence (logs in the shared target below; candidate/recompiler):

| Check | Result / log |
| --- | --- |
| Healthy fixed-three checkpoint/catch-up | 1 pass, 55.14 s; `common-snapshot-physical-healthy5.log` |
| Source and destination crash boundaries | 3 pass, 169.41 s; `common-snapshot-physical-crash-matrix.log` |
| Prior signed-read recovery matrix | 6 pass, 222.21 s; `common-snapshot-delegation-regressions.log` |
| Common certificates / V2 ledger | 9 / 34 pass; `common-snapshot-commit-final.log`, `common-snapshot-ledger-final.log` |
| Shared routes / host | 10 / 31 pass, 1 existing host test ignored; `common-snapshot-route-final.log`, `common-snapshot-host-final.log`; excludes the previously qualified five-minute raw-tail capacity fixture |
| Journal / shared replay | 105 / 7 pass, 1 existing journal test ignored; `common-snapshot-journal-final.log`, `common-snapshot-replay-final.log` |
| Protocol / authenticated transport | 16 / 18 pass; `common-snapshot-protocol-final.log`, `common-snapshot-network-final.log` |
| Feature boundaries | Minimal std-only / ordinary image-core checks and default CLI build pass; `common-snapshot-minimal-final.log`, `common-snapshot-image-final.log`, `common-snapshot-cli-final.log` |

The final experimental test binary is recorded in
`common-snapshot-tests-build5.log`. Rerun the new physical cases with the
candidate Authority ELF below, `GREY_PVM=recompiler`, disk-backed `TMPDIR`,
`RUST_MIN_STACK=16777216`, loopback permissions, and the filter
`agent::clean_bootstrap::tests::physical::common_checkpoint:: --ignored --test-threads=1`.
The candidate ELF is unchanged from `6d2a9b38`; no guest rebuild or artifact
promotion is part of this checkpoint. Total fixture runtimes are not service
latency or failover bounds. Changed-range Rust formatting, the new physical
fixture's formatting and `git diff --check` pass; repository-wide formatting
and unrelated warning cleanup are not part of this batch.

Independent read-only implementation review found no remaining scoped blocker.
Review particularly the common/physical authority separation, preserved semantic
ancestry, full-intent replica rebinding, Raft hard-state/configuration guards,
ambiguous-write quarantine and production gates. This does not sign off the
historical recovery-retention or public integration gaps above.

### Signed read recovery: follow-up from `0bec4f58`

User-authorized delegation binds the exact signed read to its admitted generation,
full committee, accepted preflight slot and exclusive expiry (at most 120 trusted
slots). Host gas/material remain derived from the certified bootstrap and admitted
Authority installation; the query signature does not directly sign those bytes.
Every replica derives the same pending work/authorization pair. Before unseen
proposal, the host independently validates the current clock, stable committee,
authenticated relay membership and original signature under the proposal guard.
It repeats the check after terminal preview, immediately before proposal.
The guest checks the immutable context and the existing credential/enrollment
policy; replay's accepted slot is never treated as a fresh wall-clock check.

Some/SSH is deliberately restricted to original attestors in the current voter
roster, whose authenticated keys permit signature verification before PAP2 writes.
Generic Invoke ingress refuses delegated projections. Exact locally applied
Invoke/positive-ACK evidence permits completion after expiry; unseen expired work
retains its reservation. No clock refresh, local-absence clearance or new
cancellation protocol is introduced. Repeated freshness checks read the existing
trusted clock directly, without extra runtime directory inspections; borrowed
pending validation avoids cloning artifact closures.

The query-only wire extension uses tags 2/3 and APQD/delegated-v2 signing and
commitment domains. None retains byte-identical APQ1 tags 0/1, APQS and v1
commitments, including embedded response bodies. AOC5/other authenticators are
unchanged. Old guests reject the new tags. Existing production authenticators
continue to emit None; the rebuilt candidate Authority is not a bundled-artifact
repin or a public startup enablement.

The offline-origin fixture stops and joins the attesting node's actual Network,
then supplies its frozen signed request to a surviving follower for authenticated
relay. This proves delegated authority and exact completion while origin is
offline, **not** autonomous discovery/replication of an origin-only pending file.
Expired-unseen terminal resolution, request availability, coherent artifact/emitter
cutover and released three-daemon qualification remain open. No failover latency
or production throughput bound follows from total fixture runtimes.

Evidence (shared target below; candidate/recompiler, not released daemons):

| Check | Result / log |
| --- | --- |
| Three-node physical crash matrix | 6 pass, 230.83 s; `delegation-projection-crash-matrix.log`: both pre-Invoke reopen orderings, origin Network offline, expired unseen retention, both post-Invoke orderings and post-ACK recovery after expiry |
| Portable SDK | 252 pass, 1 existing ignored; `delegation-sdk-tests.log` |
| Authority host suite | 82 pass, 2 fixture-export tests ignored; `delegation-authority-full-tests.log` |
| CLI | 300 pass, 45 ignored with loopback access; `delegation-cli-loopback-tests.log`; the initial restricted run failed only socket permissions |
| Protocol / authenticated transport | 15 / 16 pass; `delegation-protocol-tests.log`, `delegation-network-tests.log` |
| Feature boundary | Final experimental core test binary and default CLI build; minimal std-only core check passes (`delegation-core-build-final.log`, `delegation-minimal-check.log`) |

The rebuilt `agent-state-authority/riscv64em-vos/release/system_authority.elf`
has SHA-256 `a88872c5de59d97905ccfb043268fa8ef6aea5a1c0e354b9c7c3255fed05e2ed`.
Build evidence is `delegation-authority-guest-build-final.log`; reproduce with
`just build-agent-state-authority-guest` using the disk-backed environment below.
The prior candidate ELF is preserved under `agent-state-authority/` rather than
overwritten without recovery. No tracked bundled artifact or production pin changed.
Independent read-only implementation review found no remaining scoped findings;
it does not sign off the outstanding release boundaries.

With the final feature-enabled core test binary, rerun the physical matrix using
`AUTHORITY_CANDIDATE_ELF` set to the ELF above, `GREY_PVM=recompiler`,
`RUST_MIN_STACK=16777216`, disk-backed `TMPDIR`, and this test filter:
`agent::clean_bootstrap::tests::physical::candidate_projection_ --ignored --test-threads=1`.
Authenticated loopback transports require local socket permissions. The matrix
also checks legacy unseen-relay refusal, signed scope/time/signature/nonmember
negatives, ordinary-entry enforcement, generic supervisor/raw-network Invoke
refusal, the decoded exact Authority reply and the original positive ACK pair.

### Shared publication and recovery: `7c1a1b7c`

This connects the existing external executor to internal Shared journal replay;
it does not introduce another driver framework or enable public startup.
The admitted external profile is exactly three voters, signed Linear-only
capabilities, no scheduling/proof support, Install and completed Direct
Linear/LinearizableQuery plus ACK. Control Query, Resume, yield and Attested
execution are refused before proposal. Generic SDK/image behavior is unchanged.
Create uses the complete physical state commitment, never normalized Local roots.

Durable block publication precedes journal heads and exact V2 applied anchors.
Per-open verified availability pins avoid repeating full closure audits on every
request; detected missing/corrupt data invalidates the pin and requires an audited
reopen. Historical roots remain retained. Snapshot, compaction, portable import
and reclamation are deliberately unavailable for this external slice.

The transport now correlates applied-availability replies to authenticated voter,
generation, physical index/term and complete claim. Result delivery needs a
majority, including retained replies; no host/proposal mutex crosses collection.
A separate 32-request pool cannot be starved by the 160 application requests;
the existing 64 Raft slots and total 256 limit are unchanged. The 1.8-second
collection deadline is not a bound on host-lock/filesystem waiting. These replies
are fresh process evidence, not durable snapshot certificates. The external file
owner is not yet selected by public startup or attached to this transport.
Unused requests to a silent voter retain their permits until transport completion
or the two-second timeout; sustained minority-load qualification remains open.

Review found and fixed legal-gas admission, insufficient aggregate recovery
budget, Linear-only Merge-fence assumptions, and raw-preview/full-replay mismatch.
Install/Invoke/ACK now use exact candidate contexts, shared execution/reuse read
budgets and committed replay's existing physical-response validator before
proposal. The malformed-output regression physically demonstrates excess reported
gas and Control mutation refusal. Wrong reply lane is already rejected by wire
decoding; it is defense-in-depth coverage, not a newly discovered admission gap.
Preview plus application currently executes twice; no throughput improvement is
claimed for that correctness guard.

The new gate initially broke an existing singleton-image retry at a compacted
snapshot boundary. Its narrowly scoped fix retains live-lease, image-mode,
stable-committee and exact-result checks; it does not exempt three-voter or
external generations. The routed regression preserves the result without a new
Invoke after two snapshot/reopen cycles.

Current evidence (logs in the shared target below):

| Slice | Evidence |
| --- | --- |
| Physical three-file external Shared | 1 pass, 37.35 s; `external-shared-file-qualified.log` |
| Existing external Local lifecycle/recovery | 1 pass, 28.56 s; `shared-external-final-local-physical.log` |
| Existing image Shared finality/publication | 1 pass, 82.30 s; `shared-image-publication-refactor.log` |
| Shared replay/fence | 7 pass; `shared-external-final-shared-replay.log` |
| Three-node post-Invoke recovery | Both orderings pass, 29.24/29.29 s; `shared-external-final-crash-{former-first,successor-first}.log` |
| Three-node post-ACK/pre-clear recovery | 1 pass, 28.05 s; `shared-external-final-crash-after-ack.log` |
| Shared host | 31 pass, 1 ignored; `shared-checkpoint-host-final.log`; excludes the five-minute raw-tail capacity fixture, which passed separately earlier in this continuation |
| Protocol and live transport | 15 protocol and 16 network tests pass, including availability while application permits are exhausted |
| V2 applied-anchor ledger | 33 pass, including exact indexed physical-row checks and snapshot-prefix refusal; `shared-checkpoint-ledger-final.log` |
| Semantic preflight | Physical malformed-response matrix passes; `shared-external-semantic-preflight-test.log`; recovery-budget arithmetic unit also passes |
| Feature builds | Experimental core tests build; ordinary image core, minimal std-only core and default CLI checks pass; `shared-external-final-binary.log`, `shared-image-feature-final.log`, `shared-checkpoint-minimal-check.log`, `shared-checkpoint-cli-check.log` |

The external fixture uses **one real system-Authority replica** for enrolled,
credential-authorized Create, committee certification and physical publication/
positive ACK. Its ordinary target has three independently locked file owners,
fed identical committed slots through the existing application harness. Install
uses the fixture's pinned Authority signing key, not public management finalization;
Clerk's invoked method is `journal_id`, not a transfer/load run. Driver reopen is
not released-daemon restart. It covers exact lost-response recovery, ACK/reopen,
gas/context rejection and missing-block refusal, pin invalidation, read-only
reopen refusal and exact restoration. Do not call this ordinary-Agent network
quorum, public lifecycle, growing-ledger or 100,000-transfer qualification.

Independent review has no remaining findings in the corrected scoped changes.
At this checkpoint the pre-Invoke three-node crash fixture demonstrated an
unresolved release gate (`projection-before-invoke.log`): committed-only recovery
refused an unseen request while its reservation remained held. The user approved
scoped expiring signed recovery delegation on 2026-09-29. The follow-up must
preserve the original preflight and independently check current admission time;
that approval does not itself close the release gate.

### Backend follow-up: `4ea0271c`

This commit contains the reviewed backend correction and custom guest test;
its qualification is separate from the Shared checkpoint above.

Independent review found terminal inner-machine reuse could charge gas twice
under native execution. The fix restores the funded-block marker only on
generated Conformance terminal exits; invalid external entries preserve their
prior marker, and Jar semantics are unchanged. New repeated Halt/Panic/invalid
jump/fallthrough and invalid-entry tests pass: `wrap-terminal-gas-parity.log`
records 276 PVM tests plus 20 vectors; `wrap-terminal-no-std.log` records the
portable check. The original standalone reproducer is
`task-tmp/review_terminal_reinvoke.rs` in the shared target.

The normal, non-scripted custom-linear guest passes 36 exact-input backend
comparisons (18 each for Local and Shared), including management history,
retained Invoke/ACK, recovery-only behavior and one-shot scheduling. Evidence:
`custom-linear-backend-differential-final.log`; after the terminal gas fix,
`wrap-final-custom-exact.log` passes again in 2.20 s. ELF SHA-256:
`a8ec48426bc9dcea554c09f9da1c5edf089819aa51de90d927ca558c49239612`;
program ID `88d4c9d6c8bc4705a7cdc7150c06682ff26cff38e6808c4bd9679f6ec021b5a7`.
Build with the guest's normal `cargo actor` recipe, not `scripted-fixture`, and
set `AGENT_CUSTOM_RUNTIME_ELF` when selecting
`custom_linear::normal_custom_linear_exact_backend_lifecycle_and_recovery`.
These are guest semantics tests, not filesystem/quorum evidence. Independent
read-only review found no additional issue in the terminal fix; invalid external
entry handling and Jar behavior remain unchanged.

## Prior pruning/backend checkpoint and review focus

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

## Prior pruning/backend correctness evidence

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

For this checkpoint's three-file external Shared fixture, with those same
artifact digests and exports:

```sh
GREY_PVM=recompiler VOS_AGENT_PROFILE_REFINE_MACHINES=1 \
CLERK_AGENT_PACKAGE="$CARGO_TARGET_DIR/clerk-agent-canonical/clerk-ledger.vos" \
cargo +nightly-2025-05-09 test --offline --locked -p vos \
  --features 'agent-runtime storage network http-ingress experimental-state-blocks' \
  --lib agent::clean_bootstrap::tests::physical::external_shared::three_file_replicas_external_clerk_install_invoke_ack_reopen \
  -- --ignored --exact --test-threads=1 --nocapture
```

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

Finish remaining phase/resource qualification before closing batch 1. Close the
remaining signed-read recovery limits, certified snapshot/catch-up with root pinning, then
join the external file owner to public Shared startup and management. Existing
snapshots are source-node/store-bound; adding signatures alone is not cross-node
catch-up. Follow only the live plan:
real fixed-three-node Shared lifecycle/Clerk and retained growth (batch 2);
exact-release load, failure/backup/restore, soak and artifact qualification
(batch 3). No release date, completion percentage or production capacity claim
follows from these passing internal fixtures.

Review failure-before-write behavior, retained wire/enrollment contracts, cache
lifetime, native memory/fault/resume semantics and exact retry/recovery. Report
severity, location, violated invariant, concrete failure scenario and regression.
Distinguish demonstrated defects from unqualified release gates.
