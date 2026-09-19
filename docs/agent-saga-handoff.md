# Agent saga review handoff — 2026-09-15

## Checkpoint and decision

Review checkpoint and qualified Local-test release source: `8f96fad8`.
Use [current status](agent-saga-status.md) for remaining gates and
[the review guide](agent-saga-review.md) for the two current review ranges.
This log is reverse chronological: older statements about pending builds or
the then-current executable are historical, not additional current blockers.
The checkpoint is suitable for review/disposable Local testing only; the full
saga remains unfinished. No merge or push has been performed.

### 2026-09-19: complete clean-break recipe passes

At `bf013ff1`, the full `just clean-break-check` recipe was started unchanged,
with `RUSTUP_TOOLCHAIN=nightly-2025-05-09`, `CARGO_NET_OFFLINE=true`, the shared
`ch08-c2-native/target`, disk-backed TMPDIR, and local socket permission.
Exec session `74299` finished with exit0; log:
`target/task-tmp/decoded-input-release.RIkx3j/clean-break-recipe.log`.
Every test selection ran nonzero tests and passed:

| Selection | Passed | Ignored | Test time |
| --- | ---: | ---: | ---: |
| Clean bootstrap (`pvm`) | 75 | 1 | 805.26s |
| Production owner | 11 | 0 | 0.13s |
| Supervisor adapters | 27 | 0 | 0.03s |
| CLI clean-space modules | 94 | 0 | 51.22s |
| Private host | 63 | 0 | 81.91s |
| Private store | 40 | 0 | 3.31s |
| Private runtime | 21 | 0 | 0.02s |
| Portable recovery selection | 6 | 0 | 5.70s |
| System Authority actor | 58 | 0 | 102.52s |
| System Catalog actor | 10 | 0 | 24.77s |

SDK no-default-feature intra-doc-link checking and the final retained CLI/negative
surface script also pass. The ignored bootstrap case is the explicit 64MiB
initial-capture capacity diagnostic, not a pass. The full inventory-rotation
workload ran unchanged. Counts overlap other suites; do not add them as unique
coverage. Runtime source, lockfiles and artifacts are unchanged. Nested actor/docs
recipes used this worktree's disk-backed `target/task-tmp`, not `/tmp`.
Session74299 is terminal; there is no pending clean-break run to resume.
This closes `just clean-break-check`, not `just check-all`, workspace Clippy,
all examples, remaining proof/crash qualification, or production functionality
and latency gaps. The six portable tests do not independently close the missing
cross-runtime positive-ACK matrix.

### 2026-09-19: full post-pin host-feature regression passes

Session55057 finished with exit0: **1,876 passed, zero failed, three ignored**,
zero filtered, 1,403.60s. Full log:
`target/task-tmp/decoded-input-release.RIkx3j/host-feature-suite.log` in the shared
`ch08-c2-native` target. The run started at `ea13d293`; only documentation changed
during execution (HEAD at completion `45a22e3f`). Runtime source and pins remained
unchanged from the qualified `8f96fad8` implementation. Command:

```sh
cargo +nightly-2025-05-09 test --locked --offline -p vos --features 'agent-transition-proof private-agent-store http-ingress ssh-ingress' --lib -- --test-threads=1
```

Both `same_head_inventory_rotates_authenticated_suffix_past_1024_entries` and
`system_attach_checkpoints_and_drains_raw_tail_before_publishing_route` passed
in full, without shortened workloads or restarts. Three ignored diagnostics:

- `native_operation_initial_capture_requires_more_headroom_than_projection`:
  fills the real 64MiB journal boundary; capacity diagnostic not qualified here.
- `fixed_history_physical_decode_probe`: requires the explicit copied-DB fixture;
  timing diagnostic, not a release gate.
- `profile_bundled_runtime_large_acknowledgement`: fixed-work CPU profiling probe.

This closes the broad post-pin library reruns, not the full Private/Attested
cryptographic proof matrix, ordinary Shared integration, issuer reclamation,
workspace lint/recipes, remaining crash cases, or production latency gates.
Session55057 is terminal: do not poll or restart it as unfinished work.

### 2026-09-19: post-pin nested system-actor suites pass

With runtime source frozen at the current checkpoint, both nested actor suites
pass using nightly-2025-05-09, `--locked --offline --lib -- --test-threads=1`,
the shared target and disk-backed TMPDIR:

- `actors/system-authority/Cargo.toml`: 58 passed, zero failures/ignored,
  111.93s, session82369 exit0; `decoded-input-release.RIkx3j/system-authority-tests.log`.
- `actors/system-catalog/Cargo.toml`: 10 passed, zero failures/ignored,
  26.08s, session22543 exit0; `decoded-input-release.RIkx3j/system-catalog-tests.log`.

These nested workspaces are not covered by root workspace tests. The passing
Authority compaction tests do not close host issuer/coordinator reclamation.
Host-feature session55057 is still running the full authenticated-inventory
rotation workload; it has not been restarted, filtered, or shortened.

### 2026-09-19: post-pin SDK documentation gate passes

At `c22015ea`, with unchanged runtime source/pins, the SDK no-default-feature
documentation build passes with broken intra-doc links denied:

```sh
RUSTDOCFLAGS='-D rustdoc::broken_intra_doc_links' cargo +nightly-2025-05-09 doc --locked --offline -p vos-agent-sdk --no-default-features --no-deps
```

Exit0, 0.83s; log: shared
`target/task-tmp/decoded-input-release.RIkx3j/sdk-doc-check.log`. This checks SDK
intra-doc links only, not all examples or external links. Host-feature session
`55057` remains live, progressing through Local lifecycle recovery cases; poll
that same session before any rerun. No runtime source or artifact edits.

### 2026-09-19: post-pin default regression passes; host-feature run started

At source `ea13d293` (runtime/release implementation unchanged from `8f96fad8`),
the full default-library suite finished: 1,434 passed, zero failed, one ignored,
195.71s. Terminal test summary is in
`target/task-tmp/decoded-input-release.RIkx3j/default-suite.log`; process inspection
confirmed the previous Cargo/test processes were no longer running.

The broader host-feature suite was then started, with source frozen, using:

```sh
cargo +nightly-2025-05-09 test --locked --offline -p vos --features 'agent-transition-proof private-agent-store http-ingress ssh-ingress' --lib -- --test-threads=1
```

Live exec session: `55057`. Evidence log:
`target/task-tmp/decoded-input-release.RIkx3j/host-feature-suite.log` in the shared
`ch08-c2-native` target. Both runs use that shared target and its disk-backed
`task-tmp` as TMPDIR, with local socket permission. Poll the existing session or
inspect authoritative processes before starting another run. The host-feature
result is pending, not a pass; the previous run took about 25 minutes. No runtime
source or artifact changes accompany this qualification update.

The post-pin `bash scripts/check-agent-clean-break.sh` also passes (session13949,
exit0): locked offline CLI build, retained/retired help surfaces, rejection of
the removed dynamic dispatcher, retired-path absence, and the script's selected
operator-documentation checks. Log: `decoded-input-release.RIkx3j/clean-break-surface.log`.
This is only the surface gate, not the full `just clean-break-check` recipe or
the full documentation/examples sign-off. Build warnings remain; no lint
allowances or automatic fixes were applied. Host-feature session55057 remains
running and has passed the fresh bundled Authority query test.

Read-only inventory follow-up: `CleanAuthorityProjectionClient::load_inventory`
issues Credential + Agents + (AgentReplicas + Actors) per agent: six queries for
two agents with single-page results. Existing unchanged-complete-head reuse
already reduces a valid unchanged refresh to the fresh Credential query. The
projection route serializes execution through one worker and the system-owner
mutex (`supervisor_adapters.rs`), so caller-side parallel requests alone would
not parallelize guest execution. Aggregating authenticated bounded projections
would require protocol/actor changes and artifact requalification; this has not
been implemented or measured. Do not replace fresh credential checks with stale
inventory, assume parallel dispatch is safe, or infer an end-to-end speedup.

### 2026-09-19: decoded-input release and fresh Local lifecycle qualified

Release source `8f96fad8d46ab5f5421ddd3afb1fbe6011b09bea` builds locked/offline
with nightly-2025-05-09 in7m11s (session97380 exit0). SHA-256:
`ee49a636c477c1e3ef21d56f16e2c181307bd1e740ad20bee80b6da27e30e76d`.
`release bundle` and `release verify` pass with reproduced runtime ProgramId
`ebed0967a4d987e2f50f6e8908b294f713b0cf74583d1b5dc6648a8a542a049c`.
Evidence: shared `target/task-tmp/decoded-input-release.RIkx3j/`, including
`build.log`, verified `bundle/`, and preserved prior executable `vosx-before`
(SHA-256 `e76cf5428ebc443ec7cc6859c162ee7b9ec67e5fb03706b2ee9798051fa84106`).

Full CLI suite passes255 tests,0 failed,19 ignored in98.76s with loopback access
(session9925 exit0, `cli-suite-loopback.log`). The initial sandboxed run failed
15 socket-listener tests with `PermissionDenied`/`Operation not permitted`;
240 passed,19 ignored. Its `cli-suite.log` is preserved. No source fixes,
skipped failing tests or changed timeouts: the same binary/suite was rerun with
local socket permission. Its concurrent release build means suite wall time is
not a performance benchmark. Both jobs finished before the live probe started.

New disposable fixture `target/task-tmp/current-latency.coTfCk/` has isolated
XDG roots and name `current-latency-smoke`. SpaceId:
`2a6d0bf2c2eea7b123763caf399640fd1701b64899515f014ea5f54cea0eaab0`.
AgentId: `0b8915bf7b808aa62f68519a451f2de2b9dc794c3032a026b988fa7237f1c761`.
Generated config enabled HTTP8080 and SSH2222; only ports changed to18099/2243.
Only the immutable Counter package was copied, never a raw store. System
packages were installed automatically during startup. All prior fixtures remain
at original paths and were not opened with the new pin.

Guarded `probe.sh` passes (session59543 exit0):

- Initial readiness13s; HTTP status and SSH keyscan pass.
- Fresh Create25s and Install36s both return verified acknowledgements without
  retry/resume.
- Restart readiness19s; fresh managed increment20.04s (full test21.84s).
- Restart readiness26s; managed read20.33s (full test22.12s), value7 persists.
- Positive retirement, retired Invoke rejection and exact ACK retries pass.
  All shutdowns report0s at whole-second resolution; no forced cleanup.
  Post-probe process/listener checks find no test daemon or occupied test ports.

Mutation invocation `6c1869a1694bc23258f3a2fe5218d2e21e1831d1d9f0adde4660184da3b53b78`;
read invocation `590702442883dc4c3503182a808c3c8d498b6c8048c427b4adcedcc80918ee71`.
CLI test executable SHA-256:
`1eadc4862b50c9ec67a9b138f888d81316a8b13310045ed4bb06bd4768d5a3ad`.
Do not rerun the fresh mutation campaign or move/relabel the fixture stores.
The logs are `probe.log`, `up.log`, `mutation-up.log`, `read-up.log`,
`mutation-test.log`, `read-test.log`, plus exact Create/Install outputs.

Post-Create lifecycle8,058ms is followed by14,079ms route reconciliation,
including13,845ms inventory (six queries). Post-Install inventory15,681ms;
final route reconciliation16,353ms. Existing phase analysis parses all four
completed inventory loads; output is `decoded-input-release.RIkx3j/inventory-phases.json`.
Create/inventory are lower than the preceding fixture, but Install remains36s
and managed calls remain about20s. These differing generations/histories are
not controlled A/B evidence. All three readiness observations fail the10s gate.
SSH keyscan is not authenticated shell qualification; Counter Public-policy
success is not the full Private/Attested cryptographic matrix.

Review remains two groups, frozen at this implementation checkpoint:
`31b0cdbb..f79f0e3d` and `f79f0e3d..8f96fad8`. Batch2 is48 files,+4,946/-258;
integrated234 files,+77,744/-58,997. No merge/push. Full post-pin default/host
regressions and all remaining Shared, reclamation, proof and production gates
stay open. This closes release rebuild/fresh Local-test qualification only.

### 2026-09-19: independently reproduce and atomically pin decoded-input runtime

Exported immutable `330274bb139885b61e833bb63768a3024b5b9797` twice with
`git archive`, into separate source and target trees under shared disk-backed
`target/task-tmp/decoded-input-reproduction.ge5gNd/`. Both locked/offline
nightly-2026-03-20 builds pass in30.92s/30.88s. The preserved frozen converter
produces identical PVMs. Both ELF files, both PVMs, and the previously measured
candidate match byte-for-byte (session81910 exit0). Identities are exactly the
candidate IDs recorded below. Script, build logs, source trees, ELF/PVM bytes
and converter identity logs remain in that evidence directory.

Updated the runtime source/program/ELF/PVM provenance manifest, protocol
ProgramId, CLI build digest and committed PVM together. The PVM grows from
983,825 to984,164 bytes. System templates, public signing seed, outer ABI,
guest/host toolchains and other production artifacts remain unchanged.
No old space/store was opened or modified, and no release binary was rebuilt.

Focused post-pin verification (locked/offline nightly-2025-05-09, shared target
and disk-backed TMPDIR):

- CLI production-release checks:18 passed,0 failed in1.56s; session85573 exit0,
  `release-pin-tests.log`. Filtered integration binaries ran zero tests and
  are not counted as passes. Runtime byte/ProgramId pins, host-call surface,
  release-manifest semantics and self-contained bundle checks pass.
- Full wire module with the new bundled artifact and no candidate override:
  97 passed,0 failed,1 ignored in31.40s; session90601 exit0,
  `bundled-wire-tests.log`. The ignored test remains the fixed-work ACK CPU
  profiling diagnostic. Formatting, diff checks and bundled/independent PVM
  equality pass.

Next: rebuild the release from this pin, preserve the previous executable,
verify its bundle and use a NEW disposable space for Create/Install/Invoke,
restart, positive retirement/ACK and readiness/shutdown measurements. Previous
fixtures including `current-latency.VSCZEK` are now older-pin evidence: do not
boot them with the new executable. The old live-qualified release remains
`b16abf81`/SHA-256 `e76cf5428ebc443ec7cc6859c162ee7b9ec67e5fb03706b2ee9798051fa84106`.
New full CLI/default/host regression gates and all outstanding production work
remain open. A reproduced artifact and focused tests are not production sign-off.

### 2026-09-19: decoded-input validation reuse candidate reduces fresh Invoke/ACK gas

Implemented the next bounded optimization identified by the profile. The
guest now enters through `apply_standard_runtime_input`, which performs the
same complete SDK canonical decode before execution. Only its private Direct
Invoke/ACK continuations can mint the borrowed `ValidatedInvocationWork` token
for that exact immutable work. Standard recovery skips the redundant complete
availability validation, not scope/signature/slot checks, actor/ProgramId
resolution, exact retained-result matching, or public-I/O hashing. Public
constructed-work entry points still perform full validation. Guest Attested
Invoke/Resume retains the prior proof-host path and full validation; native
byte-input callers cannot select it. No ABI/domain/generation change.

Two new source regressions compare complete encoded transitions for fresh
Invoke, exact retry, ACK, ACK retry and retired Invoke. They also reject
corrupt preimages, truncation/trailing bytes, forged receipt signatures and
native Attested selection. Both pass with the four host features (session61937
exit0). The initial default-feature filtered probe selected zero tests and is
not qualification; the first compile exposed a WireError conversion, fixed
by mapping failed canonical decode to the existing fail-closed error.

Pinned guest build succeeds in14.30s (session13843 exit0). The isolated
candidate is NOT bundled or release-qualified. Candidate ProgramId:
`ebed0967a4d987e2f50f6e8908b294f713b0cf74583d1b5dc6648a8a542a049c`.
ELF BLAKE2b256:
`4a1930c4b8b6ba38daad3079ace97bb34903e446596346f3814d24eac11a505f`.
PVM BLAKE2b256:
`dfcf70ef5a335125176eb350e6fe3d857e9efc593a55860dee9761e4f2ac112f`.

Paired exact-input large-artifact tests compare complete output bytes:

| Work | Bundled gas | Candidate gas | Reduction |
| --- | ---: | ---: | ---: |
| Fresh Invoke | 463,462,521 | 405,201,877 | 12.6% |
| Retained Invoke retry | 404,577,747 | 346,317,879 | 14.4% |
| Fresh ACK | 278,766,249 | 220,499,368 | 20.9% |

The wire suite with both candidate environment selectors passes97 tests,
0 failed,1 ignored in29.71s (session25383 exit0). Tests without a candidate
selector retain their existing source/bundled coverage; do not describe this
as every case executing both PVMs. Formatting and diff checks pass.

The real bundled-Authority fresh credential query also passes on the candidate
outer PVM, including positive exact ACK and cleared pending projection
(session2212 exit0,15.01s with instruction observation). Observed candidate
Invoke gas555,039,116; ACK207,065,357. Its fixture runtime identity changes
with the candidate package, so this is successful real-workload qualification,
not identical-input/output A/B evidence or deployed wall-time speedup.
The test-only runtime fixture now accepts the explicit candidate selector only
when bundled-PVM profiling is requested; normal fixtures are unchanged.

Evidence is preserved in shared disk-backed
`target/task-tmp/decoded-input-candidate.81qO9E/`: `guest-build-fixed.log`,
`decoded-input-tests-fixed.log`, `wire-candidate.log`,
`authority-query-candidate.log`, `runtime.pvm`, and the guest target ELF.
Prior failed compile logs remain. Production artifact manifest, guest bundle,
runtime identity constants and release binary remain unchanged.

Before promotion: independently reproduce from the immutable candidate source
in two isolated source/target trees, require equality with the measured bytes,
atomically repin, rebuild the release and repeat fresh disposable lifecycle /
restart qualification plus the full regression gates. Do not boot preserved
older-pin stores with a candidate release or claim the production latency
gate is fixed. Ordinary Shared/finality and all other outstanding gates remain.

### 2026-09-19: exact-binary PC attribution identifies BLAKE2b as dominant cost

Extended the opt-in test observer with bounded-by-code-length outer instruction
counters, top PCs and4KiB regions. Count totals are asserted against all outer
instructions. Re-ran the successful bundled Authority query: session30885
exit0,19.29s; gas and instruction totals exactly match the preceding profile.
Instrumentation time is not release latency.

A compiler-test diagnostic maps observed PCs through the preserved ELF only
after `link_elf_spi(ELF)` matches the bundled PVM byte-for-byte. The diagnostic
also applies the final branch-target insertion offset map; the raw translation
map is NOT sufficient. The preliminary `authority-query-pc-map.log` omits that
relocation and must not be used for symbol attribution. Its corrected successor
is `authority-query-pc-map-relocated.log`; region mapping is in
`authority-query-region-map.log`. All corrected selected PCs map exactly, with
no nearest-address gap. The preserved ELF is
`role-length-reproduction.IeXBpW/target-a/riscv64em-vos/release/agent_runtime.elf`.

Five whole4KiB regions at PVM PCs `[16384,36864)` lie within ELF function
`blake2b_simd::portable::compress1_loop` (RISC-V symbols `0x3004cec` to
`0x300c5d4`). Together they account for:

- Invoke:144,017,192 of182,482,309 outer instructions, **at least78.9%**.
- ACK:82,520,526 of95,650,075 outer instructions, **at least86.3%**.

These are conservative lower bounds excluding partial boundary regions, not
percentages of wall time. `llvm-addr2line` may print local `.Lpcrel_hi17` labels;
the surrounding function range comes from `llvm-nm --numeric-sort --demangle`.
Other frequent PCs map to `vos_pvm_program::parse_compact_code_blob`,
`ActorMachine::load_at`, and compiler-builtins `memcpy`. Top individual-PC
counts alone would overemphasize those small loops and miss the large unrolled
hash function, which is why region aggregation was necessary.

Next bounded optimization target: redundant hashing of identical immutable
availability bytes across the canonical decoder and execution boundary.
The decoder already avoids duplicate nested-envelope and per-blob checks;
do not redo those optimizations. The canonical decode still validates Invoke
availability, while Standard recovery independently validates constructed work.
Any reuse must be unforgeably tied to the exact decoded value; public
constructed-value entry points must continue full validation. ProgramId and
BlobRef are separate digest domains, and public-I/O hashing is proof binding,
not removable overhead. No validation or hashing was removed in this step.

Compiler regression passes65 unit tests (1 opt-in diagnostic ignored) and
8 integration tests; the explicit exact-binary mapping diagnostic also passes.
New tests prove offset-map reporting preserves emitted code and handles both
inserted and unchanged boundaries. Production linker API/output is unchanged;
the optional relocation observer shares the existing implementation. Formatting
and diff checks pass. Evidence in shared `role-length-release.UnaSE1/`:
`authority-query-region-profile.log`, `authority-query-region-map.log`,
`compiler-profile-support-tests.log`. No guest repin, release rebuild or
deployment was performed; remaining production gates stay open.

### 2026-09-19: real bundled Authority query profile localizes cost to outer runtime

Added `native_bundled_authority_fresh_credential_query_retires_exact_pair`.
It uses the actual bundled Authority executable/schema/policies, re-signed only
for the existing fixture issuer. A valid enrolled SSH-node credential query
must return the exact query, active status and expected principal; no positive
ACK exists beforehand, and the exact retained positive ACK and cleared pending
projection are required afterward. This is a fresh successful query, not an
unknown-credential rejection or retained-result timing probe.

The normal test passes (session18710 exit0,3.62s). With
`VOS_AGENT_PROFILE_REFINE_MACHINES=1`, the existing fixture disables the native
outer-runtime shortcut and uses the bundled `agent_runtime.pvm`; the same test
passes (session74286 exit0,12.82s). Markers delimit just the measured query
after bootstrap. Both runs use locked/offline nightly-2025-05-09, the four host
features, shared target and disk-backed TMPDIR. No guest pin or executable
bytes changed. This is fixture-based attribution, not a deployed wall-time A/B.

| Fresh query transition | Input bytes | Gas | Outer instructions | Inner instructions |
| --- | ---: | ---: | ---: | ---: |
| Invoke | 772,026 | 611,555,466 | 182,482,309 | 5,442,329 |
| ACK | 774,351 | 263,780,712 | 95,650,075 | 0 |

Outer instructions account for97.1% of observed Invoke instructions and100%
of ACK instructions. Observer wall spans are3.804s outer/0.168s inner for
Invoke and2.024s outer for ACK; instrumentation adds overhead, so these are
not release latency numbers. Invoke has26 host calls; ACK has none. The outer
and inner observation intervals are separated at host calls by the observer.

This changes the next optimization target: first localize outer runtime
validation/encoding/hash work, rather than optimizing Authority actor policy
execution or its state. Do not infer the exact hot outer function from this
machine-level split alone. Retain this successful real-workload regression
alongside the synthetic large-artifact equivalence test for any candidate.
Logs: shared `target/task-tmp/role-length-release.UnaSE1/authority-query-native.log`
and `authority-query-pvm-profile.log`. Formatting and diff checks pass.
The full suites remain qualified at their earlier recorded source revisions;
this new test does not close the remaining production gates.

### 2026-09-19: current-pin inventory attribution narrows the performance target

Analyzed the retained current-release `current-latency.VSCZEK/up.log` without
opening, copying or mutating any store or starting another daemon. Unlike the
older phase table below, these measurements include the latest reproduced
runtime pin. The post-Create inventory (lines226–361) contains six authenticated
queries and takes16,677ms:

| Phase | Wall ms | Enclosed runtime ms | Runtime calls |
| --- | ---: | ---: | ---: |
| Prepare | 426 | 118.741 | 6 |
| Reserve/checkpoint | 2,208 | 44.256 | 2 |
| Identity | 400 | 126.324 | 6 |
| Persist pending | 224 | 0 | 0 |
| Reopen/check retained ACK | 504 | 121.696 | 6 |
| Invoke | 8,036 | 6,245.987 | 12 |
| Acknowledge | 4,679 | 2,905.777 | 12 |
| Complete pending | 195 | 0 | 0 |

The two cumulative timing families are differenced independently, resetting
at `reopen`. Phase totals are16,672ms;5ms remain between logged boundaries.
Runtime spans total9,562.781ms across44 calls. Of these,12 calls with encoded
inputs at least512KiB consume8,890.561ms; the other32 consume672.220ms.
In the inspected fresh-query trace, Invoke and ACK each contain one small
inspection and one large execution, not two large executions. Exact terminal
preflight reuse is logged. Do not count every runtime span as a repeated full
invocation, or remove replay based on that assumption.

The post-Install inventory (lines500–635) corroborates the concentration:
15,483ms total,44 runtime calls taking9,017.575ms, of which12 large-input calls
take8,372.321ms. Fresh unchanged-head credential-only refresh (lines405–429)
still costs2,450ms. Thus existing page reuse helps but does not make even one
authenticated query cheap. These are phase observations, not controlled A/B
or CPU instruction profiles; non-runtime residuals are not proven to be I/O.
Explicit pending persist/clear contributes only419ms after Create.

This rules out small inspection execution as the primary remaining target:
even eliminating all32 smaller runtime spans would recover only0.672s in the
measured16.677s inventory, before any associated host overhead. The next
bounded performance investigation should profile the actual bundled Authority
fresh Invoke/ACK workloads (not just the synthetic Counter) and separately
attribute reserve/checkpoint's2.164s and Invoke/ACK's3.563s outside runtime.
Preserve authenticated complete-head pagination, exact pending recovery and
positive ACK semantics. Do not introduce a new batch protocol or repin guests
without measured evidence and equivalence/recovery qualification.

Reproduction script and full output are in shared disk-backed
`target/task-tmp/role-length-release.UnaSE1/inventory-phases.py` and
`current-inventory-phases.json`. The parser asserts sequential complete phase
sequences, monotonic cumulative timing and at most5ms query boundary residual;
all four completed inventories in this log pass. No implementation, pin,
fixture or release binary changed. Full production gates remain open.

### 2026-09-19: reject legacy-state Shared finality experiment; keep review checkpoint clean

The uncommitted ordinary-finality experiment following `36e63581` was removed
after its live-reader test failed: it returned `Unavailable`, not the expected
`NotFinalized`. Evidence remains in shared disk-backed
`target/task-tmp/role-length-release.UnaSE1/finality-reader-test.log` and
`rejected-finality-experiment.patch`; no fixture or failure log was deleted.
The experiment's constructed-view unit test passed, but did not establish
compatibility with clean production replay.

This corrects the earlier ordinary Shared read/ownership audit below:
`materialized_system_authority_view` requires decoded Standard runtime
`system_authority` state. Clean descriptor conversion explicitly sets
`system_authority_genesis: None`; it does not initialize that legacy embedded
ledger. The failing clean replay fixture also uses opaque control bytes, so
its failure alone is not evidence about production decoding. Source inspection
establishes the separate embedded-ledger mismatch. Do not initialize legacy
authority state or weaken provenance checks to make this approach pass.

Ordinary Shared issuance/archive/finality must instead be integrated with the
clean system-authority actor's authenticated decision evidence and lifecycle.
The root-first reopen and non-reentrant ownership requirements from the prior
audit still apply. Native admission remains fail-closed. No production finality
implementation, guest artifact change, merge or push was made. The committed
`36e63581` implementation remains the review checkpoint; the reproduced release
binary is still the separately qualified `b16abf81` build.

After removing only the experiment's211 added Rust lines, all three source
files exactly match `36e63581`. Pinned-host formatting and `git diff --check`
pass. The restored provenance regression
`memory_clone_drops_root_provenance_while_original_remains_reverified` passes
(1 passed, 0 failed, 1,875 filtered out; session34702 exit0), using the same
four host features as the full host suite, offline/locked and disk-backed
TMPDIR. Log: `finality-experiment-removal-test.log` in the same evidence
directory. This verifies restoration, not completion of Shared finality.

### 2026-09-19: complete host-feature regression and mechanical formatting cleanup

Original host-feature session38510 completes successfully, exit0:1,873 passed,
0 failed,3 ignored in1,509.36s (25m09s). Started at `02dbc8c6`; runtime source
remained unchanged throughout, with only documentation commits added. Command:
offline/locked host nightly-2025-05-09 `cargo test -p vos --features
'agent-transition-proof private-agent-store http-ingress ssh-ingress' --lib --
--test-threads=1`. Loopback access and disk-backed TMPDIR were available.
Both the full inventory-rotation workload and system-attachment checkpoint/drain
passed. No workload reductions, source fixes, restarts or retries. Concurrent
supporting checks mean suite duration is not a controlled performance result.

The three ignored tests remain the explicit64MiB initial-capture diagnostic,
fixed-history copied-database timing probe and repeated large-ACK CPU profile.
Feature-enabled test success is not the remaining full cryptographic proof
qualification. Evidence: `target/task-tmp/role-length-release.UnaSE1/host-suite.log`.

Only after the suite terminated, applied pinned-host `cargo fmt --all`. Reviewed
all15 changed files: indentation, line wrapping and formatter-supplied trailing
commas only (117 insertions/80 deletions before documentation updates). The exact
recipe formatting check now exits0, as does `git diff --check`;
`format-fixed-check.log` is empty on success. No lint suppression, schema,
protocol, release artifact or source-provenance pin changed. The bundle continues
to reproduce from immutable `19d73390`; no claim is made that a rebuild of the
reformatted checkout has identical guest bytes. Full-suite evidence above is
explicitly pre-formatting. Workspace lint and functional production gaps remain.

Post-format focused verification passes: full wire module95 passed/1 ignored
in26.80s (session36530 exit0), including complete bundled/source transitions;
SDK165 passed/0 ignored in0.20s (session49262 exit0), including golden wire
commitments. Logs: `post-format-wire.log`, `post-format-sdk.log` in the same
evidence directory. These are not a rerun of all full-suite feature combinations.

### 2026-09-19: post-pin portable SDK and build-integration gates

At `cda6c997`, without changing the frozen runtime source:

- `cargo check -p vos --no-default-features --lib`:exit0 in2.04s;
  existing272 warnings remain, so this does not supersede the failed lint gate.
- `cargo test -p vos-agent-sdk --lib -- --test-threads=1`:165 passed,0 failed,
  none ignored in0.18s.
- `cargo test -p vosx --test build_actor_e2e --test build_task_e2e --
  --test-threads=1`:actor-build4 passed in29.27s, task-build1 passed in29.53s;
  session80400 exit0. This updates the older-generation build-integration
  evidence, not signed package reproduction or live deployment proof.

All commands use host nightly-2025-05-09, `--locked --offline`, shared target
and disk-backed TMPDIR; nested build integration also sets CARGO_NET_OFFLINE.
Logs under `target/task-tmp/role-length-release.UnaSE1/`: `no-std-check.log`,
`sdk-suite.log`, `build-integration.log`. The original host-feature run remains
active on its long inventory-rotation workload (session38510); do not restart it.
Source/release pins and fixture contents were not changed by this work.

### 2026-09-19: workspace Clippy release gate fails

At `7b45d2f0`, ran pinned-host offline/locked `cargo clippy --workspace` with
the exact `just check-all` lint flags: `-D warnings`, allowing only
`clippy::too_many_arguments`, `clippy::type_complexity`,
`clippy::result_unit_err`, `clippy::manual_async_fn`. Session48040 exits101:
vos library compilation reports351 prior errors. Counting diagnostic headers
(not individual methods/fields) gives258 unused/dead-code,1 unused-mut and92
other diagnostics. Large enum variants are among the latter. Do not assume
downstream workspace crates have passed: this run fails at vos.

Evidence: `target/task-tmp/role-length-release.UnaSE1/clippy-workspace.log`.
No source or lint configuration changed, and no autofix was applied. This is
another concrete release gate, separate from the passing targeted suites and
still-running host-feature session38510. Triage after the frozen suite: retire
only genuinely obsolete clean-break code; wire required production paths;
apply justified test/feature scoping and scoped lint fixes. Do not delete needed
Shared/authority integration or add a blanket dead-code allowance merely to
make this check green. The read-only check does not identify which diagnostics
predate this branch, and does not establish a new runtime correctness failure.

### 2026-09-19: post-pin nested actor, SDK documentation and static cutover gates

At `7bc52924`, with runtime source unchanged during the live host-feature run:

- `actors/system-authority` separate-workspace library suite:58 passed,0 failed,
  none ignored in129.70s; session24810 exit0.
- `actors/system-catalog` separate-workspace library suite:10 passed,0 failed,
  none ignored in32.46s; session97673 exit0.
- SDK no-default-feature/no-deps docs with
  `RUSTDOCFLAGS=-D rustdoc::broken_intra_doc_links`:exit0. This is an intra-doc
  gate, not a whole-book or external-link audit.
- `scripts/check-agent-clean-break.sh`:exit0, retained CLI and negative surface
  verified; session3434 exit0. Its debug vosx build took18.09s. This script alone
  is not the complete `just clean-break-check` recipe.

All cargo work used pinned host nightly-2025-05-09, locked/offline resolution
(the script via `CARGO_NET_OFFLINE=true`), shared target and disk-backed TMPDIR.
Evidence under `target/task-tmp/role-length-release.UnaSE1/`:
`system-authority-suite.log`, `system-catalog-suite.log`, `sdk-doc-check.log`,
`clean-break-static.log`. No release binary, source, guest artifact or fixture
changed. System-actor tests do not close host issuer/coordinator reclamation or
ordinary Shared issuance/finality. Host-feature session38510 still requires its
own terminal result; no restart occurred. Formatting remains a failed gate.

### 2026-09-19: pinned-toolchain formatting gate fails (read-only check)

At `b437af09`, both `cargo +nightly-2025-05-09 fmt --all -- --check` and the
`just check-all` recipe's exact formatting command, `cargo fmt -- --check`
with that same pinned toolchain, exit1. Their logs are byte-identical and show
40 diff locations across15 files. This is a real remaining release gate, not
a compiler/test failure or a missing formatter. No source files were changed.

Files: vos agent journal_store, production_owner, shared_host,
shared_journal_driver, standard and wire; vos ingress/server and node; SDK
authority_operation, catalog, proof, runtime and wire; CLI local_create and
local_operation_live_tests. Several differences are in tests, but guest-linked
files also appear. Apply the mechanical formatting as one scoped follow-up after
the running host-feature suite completes, check the resulting diff, and rerun
the gate. Do not assume rebuilt guest bytes are identical after source-location
changes; retain the immutable reproduced source pin unless a measured rebuild
and the required qualification justify another repin.

Evidence under shared `target/task-tmp/role-length-release.UnaSE1/`:
`format-check.log`, `format-recipe-check.log`. The host-feature suite remains a
separate live run, session38510, and must be polled rather than restarted.

### 2026-09-19: ordinary Shared finality read and ownership audit

Historical read-only audit while the post-pin host-feature suite ran. The
later experiment above invalidates this as a clean-production implementation
plan: these components require legacy embedded authority state. The proposed
permanent-fact read was:

1. `replay::materialized_system_authority_view` authenticates materialization,
   compares durable Heads with the materialized Heads/ID and reverified root
   identity, then constructs the opaque scope and authority view. Use this
   boundary; caller-supplied state/IDs do not substitute for replay.
2. `prove_decision(view.authority_state().decisions_root(), target, loader)`
   can follow `SystemAuthorityHistoryStore::load_system_authority_decision_node`.
   It verifies bounded canonical paths and exact node IDs against that root.
   A vacant proof is not finality. An occupied proof supplies the exact fact.
3. Load the content-addressed committee named by that fact, and call
   `verify_historical_provision(scope, provision, fact, committee)`. This checks
   root-generation scope, exact provision/fact closure and the original QC.
   That helper alone does NOT prove inclusion: it must follow step2 against
   the authenticated root, with no stale-head or alternate-store substitution.

There is also a startup/ownership dependency missing from the earlier bounded
plan. `SharedAgentHost::open_with_lease_and_root` scans a BTreeMap keyed by
AgentId, verifies each intent, then opens/inserts that generation. Thus an
ordinary generation can be verified before its system generation is opened.
`verify_and_prepare` calls the external finality verifier during construction
and synchronous `provision_intent`; the production bootstrap owner holds this
same host as `Arc<Mutex<SharedAgentHost>>`. A verifier that simply reacquires
that host is not a safe integration: construction has no completed host yet,
and provisioning while its mutex is held would deadlock on recursive locking.
This is an integration hazard inferred from the call graph, not an observed
deadlock in the current unavailable verifier.

Before wiring ordinary issuance, define a root-first authenticated reopen and
non-reentrant ownership path (or an equally strong independently pinned proof
source). Test both AgentId orderings, missing/corrupt root generation, changed
Heads/store identity, vacant/conflicting decisions, missing/wrong committee,
and repeated verification after restart. Keep admission fail-closed until the
root is ready; do not solve ordering with an accepting cache or root-bootstrap
QC standing in for ordinary finality. No runtime source changed in this audit.

### 2026-09-19: complete post-pin default-library regression

At `02dbc8c6d50acdbc06b984cff651cfa61c5fc136`, the offline/locked default
`cargo +nightly-2025-05-09 test -p vos --lib -- --test-threads=1` completes:
1,434 passed,0 failed,1 ignored in199.41s (session32510, exit0). Loopback
network access was available and TMPDIR remained in disk-backed shared target.
No fixes, retries or filters. Evidence:
`target/task-tmp/role-length-release.UnaSE1/default-suite.log`.
The full host-feature suite is the next gate; do not substitute this narrower
feature selection or earlier-generation host results for it. Production
latency, Shared integration, reclamation and remaining proof gates stay open.

### 2026-09-19: repinned release and fresh Local lifecycle qualified

Release `b16abf81948d64cc08ea34f683316f60c7f8759c` builds offline/locked with
host nightly-2025-05-09 in6m20s. Executable SHA-256:
`e76cf5428ebc443ec7cc6859c162ee7b9ec67e5fb03706b2ee9798051fa84106`.
Bundle creation and verification pass. The prior release is preserved as
`target/task-tmp/role-length-release.UnaSE1/vosx-before` (SHA-256 `a2e12ecd77cf393c3ddf8ecfabecb4d366fb3e55d0d0d14dcc4f221fca8ef08b`).
That directory also contains `build.log`, verified `bundle/` and `cli-suite.log`.
Full current-pin CLI suite passes255 tests/19 ignored in87.64s. Build and test
sessions47890/71145 both terminated successfully; no overlapping build ran
during the live latency probe.

Fresh fixture `target/task-tmp/current-latency.VSCZEK/` has isolated XDG roots;
space name `current-latency-smoke`, SpaceId
`85fcc4bcb030fafe9bb56f5acfffea0330132f2e160237d475b2c674bb71e01a`.
Generated config enables HTTP8080/SSH2222; only test ports changed to18099/2243.
System packages are automatic; only the immutable Counter package was copied.
Created AgentId: `59fe9c9ab2a9f9ac50893058e50333273ccbe490754597824964388345ce913b`.

Guarded `probe.sh` completed successfully (session77977, exit0): first readiness
15s; HTTP status/SSH keyscan pass; fresh Create30s and Install36s both return
verified acknowledgements without resume. Shutdown1s. Restart19s; managed fresh
increment20.71s (full test22.42s); shutdown1s. Restart24s; managed read19.90s
(full test21.51s), persisted value7, retirement/late-Invoke rejection and exact
ACK retry pass; shutdown1s. No forced cleanup; host process inspection after
completion found no vosx/cargo/rustc. SSH listener checks are not authenticated
shell qualification; these Public-policy probes do not prove non-Public policy.

Fresh Create lifecycle9,618ms is followed by route reconciliation16,930ms,
including16,677ms inventory. Install's final reconciliation16,108ms includes
15,483ms inventory. Readiness still fails10s and operation latency remains too
high. Older release timings are not a controlled same-history A/B.
CLI test executable SHA-256:
`7a5b078dbf5b911d87112b5766419a832e4a9a8b23507fe99f987370955336d4`.
Mutation invocation `60376c6faa3dcd95f2a813d15b2d9b2078abcffb0175fd23595f7be52f760273`;
read invocation `11b10d2bae585d9b3a807176fd08763af5217624f6da3e2596ad8bd8d6f65406`.
Do not rerun the fresh increment: retain its exact request/ACK files. Keep all
stores at original absolute paths. Full post-pin default/host library suites,
Shared integration, reclamation and remaining production gates stay open.

### 2026-09-19: independently reproduced artifact-role optimization repinned

Exported immutable source `19d733903930b1e8cf5ef861e5ce0440336cde6a` twice into
separate source and target directories. Offline locked guest builds with
nightly-2026-03-20 took25.53s/26.55s. Both ELF files match each other and the
saved measured candidate ELF; both converted PVMs likewise match the candidate.
ProgramId and hashes are those recorded in the candidate entry below.

Updated `support/production-artifacts.toml`, `STANDARD_RUNTIME_PROGRAM_ID`,
the vosx build-time digest and bundled PVM together. System templates and ABI
identity remain unchanged. Post-pin tests without candidate overrides pass:
release verifier18/18 (0.92s), bundled signing/admission4/4 (0.30s), clean outer
surface1/1 (0.11s), bundled runtime7 passed/1 ignored (5.97s). This is focused
qualification, not the full host-feature/CLI/default matrix or live release.

Evidence: shared `target/task-tmp/role-length-reproduction.IeXBpW/` contains
`reproduce.sh`, `reproduce.log`, independent source/target trees, build/identity
logs, both PVMs, `post-pin-release-tests.log`, `post-pin-runtime-tests.log`.
The existing release executable is still the prior `b131edc3` generation;
it has not been rebuilt or replaced. Next: preserve that executable, build and
verify the new release, create a fresh disposable space, and qualify
Create/Install/Invoke/ACK/restart before reporting new live latency. Do not boot
the previous runtime's fixtures with the new pin. Full production gates in the
status page remain open; no merge or push occurred.

### 2026-09-19: artifact-role length rejection candidate

`resolve_clean_invocation` now checks actual preimage length before computing
the domain-separated blob digest for schema/policy/constructor roles. If none
of those references has that length, the preimage cannot match any role.
Program identity is still computed independently from complete bytes. Possible
matches are still hashed; caller-supplied references are not trusted. Duplicate
and aliased-role rejection, application availability construction, signatures,
expiry, readiness and recovery are unchanged. This is not a validation cache.

New native regression checks same-length corruption of both schema and policy,
changed lengths with unchanged supplied references, and duplicates. Existing
role-alias regression also passes. Whole wire suite against the existing bundle:
95 passed/1 ignored in30.78s, including empty installation-data/resume coverage.
Repeated with COST/ACK/FAILURE/TYPED_ERROR/EXPIRY candidate overrides:95 passed/
1 ignored in30.18s (`wire-candidate.log`). Only tests consuming those overrides
execute the candidate PVM; the others remain native or bundled checks. This
covers candidate malformed ACK, retirement, terminal failures, durable typed
errors and expiry; it is not full Private/Attested proof qualification.

Candidate guest builds with pinned guest toolchain in16.99s. Paired benchmarks
against current bundle pass with identical complete output:

| Work | Bundled gas | Candidate gas | Reduction |
| --- | ---: | ---: | ---: |
| Fresh Invoke | 579,883,967 | 463,462,521 | 20.1% |
| Retained Invoke retry | 520,997,765 | 404,577,747 | 22.3% |
| Fresh ACK of retained result | 336,976,258 | 278,766,249 | 17.3% |

These are synthetic768KiB-program tests, not live inventory latency or a new
production release. Candidate ProgramId:
`e61dc1dacd564ac9371512eaaf9d35ad8f1e081f8e3b638ca9da9425e887e86b`.
ELF BLAKE2b-256: `c9c3e01f31e2b5939fe5e13f71cfdfecf9b68faeebf8e7192c94fdd34ed2c081`.
PVM BLAKE2b-256: `8f4dd034314963408c2f7650147aeb7311094a4528f936881155eb238eff9fd7`.
Evidence: shared `target/task-tmp/role-length-candidate.D59PGi/` contains saved
ELF/PVM and `cost.log`; adjacent `role-length-native-20260919.log`,
`role-length-guest-build-20260919.log`, `role-length-wire-regressions-20260919.log`.
No release pins changed. Independent reproduction, atomic repin and fresh
release qualification remain required. Preserve existing fixtures at their
original paths and do not boot them using a new-generation pin.

### 2026-09-19: fresh large-program Invoke baseline added without changing release pins

Added `bundled_runtime_large_fresh_invoke_validation_cost`: a valid tiny Public
actor has768KiB of inert read-only padding, starts without a retained invocation
result, returns Done and commits a lane change. The complete bundled guest
transition must equal native source output. An optional
`VOS_AGENT_RUNTIME_COST_CANDIDATE` must also preserve those bytes and use less
gas. This measures fresh execution rather than the existing retained-retry
benchmark, but is still synthetic, not Authority inventory throughput.

Current bundle baseline:792,481 input bytes,579,883,967 gas,1,400,409us in the
first passing run. Initial fixture development failed with InvalidActorOutput
because read-only padding relocates writable data; the helper now computes the
output address using zone-rounded read-only length. Zero-padding failure
fixtures retain their original address. No production code or artifact pin
changed. Host-feature `bundled_runtime_` filter passes7 tests/1 ignored in6.69s,
including the fresh baseline and existing failure/retirement/ACK cases.
Logs under shared `target/task-tmp`: `fresh-invoke-baseline-20260919.log` and
`fresh-invoke-bundled-regressions-20260919.log`.

The source trace finds full work/authorization verification in both
`recover_clean_invocation_error` and later `recover_clean_execution`, with
expiry and policy admission between them. Artifact resolution also occurs in
preflight and again before execution. These are optimization candidates, not
permission to drop checks: any reuse must be scoped to exact immutable work,
authorization, runtime identity and observed slot, preserve error precedence,
and not cross the interposed mutation/early-return paths unchecked. Production
latency remains unresolved; this test supplies the missing fresh-work baseline.

### 2026-09-19: current-pin inventory attribution for the review handoff

Read-only attribution at `97dac482`, using the already completed current-release
probe `target/task-tmp/current-latency.qEl4ba/read-up.log` in the shared
`ch08-c2-native` target. No daemon rerun, store mutation, or rebuild. This is the
initial inventory on the read-after-restart run, not fresh Create or Install.

The six query durations sum to17,909ms; the enclosing inventory log reports
17,912ms. They contain44 physical runtime calls, including12 inputs over700KB.
Runtime spans sum to11,471.194ms (64%);6,437.806ms lies outside those spans.
Summing successive cumulative phase deltas, resetting at each query and at the
execution family's `reopen`, gives:

| Phase | Total ms | Enclosed runtime ms | Outside runtime spans ms |
| --- | ---: | ---: | ---: |
| Prepare | 447 | 129.383 | 317.617 |
| Reserve/checkpoint | 1,778 | 42.320 | 1,735.680 |
| Identity | 377 | 126.858 | 250.142 |
| Persist pending | 218 | 0 | 218 |
| Reopen/check retained ACK | 466 | 125.869 | 340.131 |
| Invoke | 9,125 | 7,434.812 | 1,690.188 |
| Acknowledge | 5,302 | 3,611.952 | 1,690.048 |
| Complete pending | 194 | 0 | 194 |

Phase totals differ from summed query times by2ms due to boundaries/rounding.
This is wall-time attribution, not a CPU profile: the outside-runtime residual
must not be labelled disk I/O or a single validation function. Explicit pending
persist/complete phases total412ms and cannot explain the overall delay.
Invoke plus ACK account for14,427ms (81% of query time). The earlier18.3% gas
benchmark measures retained Invoke retries, not these fresh inventory Invokes.

Source audit confirms unchanged-head reuse is already implemented in
`CleanAuthorityProjectionClient::load_inventory`, with a fresh authenticated
active credential and exact claims; failed refreshes invalidate reuse. Parallel
dispatch is not a drop-in fix: the clean projection path persists one pending
query and rejects a different query while it is pending. Next bounded performance
work should measure fresh Invoke/ACK validation against this current pin, then
isolate reserve/checkpoint's host residual. Do not add another unchanged-head
cache, omit ACKs, or bypass authentication/readiness. Existing historical
measurements are not a controlled before/after comparison with this run.

### 2026-09-19: ordinary Shared finality gap traced to both production boundaries

Read-only audit at `00921e04`: native `clean_startup.rs` installs
`UnavailableAgentFinality` at line340; its verifier always returns Unavailable.
Repository-wide exact-word search for `AgentGenesisProvider` finds only its
trait and trust-boundary documentation in `vos/src/agent/genesis.rs`, no
implementation or caller. `CleanSystemAgentGenesisArchive` implements the
different `SystemAgentGenesisProvider` for root system bootstrap. The ordinary
gap therefore includes archive/issuance and lifecycle wiring, not merely
replacing a finality stub with an accepting implementation.

Reusable existing pieces: `AgentGenesisProvision` validates canonical links;
`SystemAuthorityDecisionFact` and `verify_provision_fact` exact-compare provision
content; `SystemAuthorityState::verify_historical_provision` checks trusted
scope, exact fact and historical committee/QC together. Their comments explicitly
say data validation alone is not an admission/sealing capability. The independent
`AgentGenesisFinalityVerifier` must source the permanent decision from authenticated
live system replay and must run again on generation reopen. Existing
`self_consistent_provision_never_bypasses_independent_finality` covers refusal
propagation/reverification sequencing using a fake verifier, not production proof.

Bounded implementation order within the existing goal: expose an authenticated
replay-backed exact genesis-fact read (scope, decision, committee/QC); connect
that read to an independent finality verifier; implement durable ordinary
proposal/catalog/provision issuance and reproduction; wire Shared provisioning
and reopen through both boundaries. Require negative tests for provider-only
self-consistency, wrong system generation, absent/unfinalized fact, altered
committee/evidence, and verifier unavailability after a prior successful open.
Do not grant acceptance from root bootstrap QC, provider response, or decoding
private Standard state outside authenticated replay. No source change or new
production readiness claim follows from this audit.

### 2026-09-19: complete post-pin host-feature regression

At `bf7ced06` (release implementation `b131edc3`), full host-feature library
suite passes1,871 tests, zero failures,3 ignored,1,450.60s (24m11s). Command:
`cargo +nightly-2025-05-09 test --locked --offline -p vos --features 'agent-transition-proof private-agent-store http-ingress ssh-ingress' --lib -- --test-threads=1`.
Shared target, disk-backed TMPDIR, serial socket-enabled run; session59361
terminal0. Evidence: `target/task-tmp/invoke-reproduction.OS8HAC/post-pin-host-suite.log`.
No source fixes, retries or workload reductions. The514-query inventory rotation,
system-attachment checkpoint/drain, new Invoke validation rejection/retirement
and large-retry benchmark all pass in this uninterrupted run.

Ignored: native-operation initial-capture64MiB headroom diagnostic, explicit
fixed-history physical decode timing probe, and repeated large-ACK CPU profiling
probe. They are not claimed as passes. This updates the earlier full host-feature
baseline for the new pin. It does not prove the missing ordinary Shared finality
bridge, authenticated reclamation, full Private/Attested cryptographic proofs,
the unimplemented/unqualified recovery cases, or acceptable production latency.
No merge, push or master/production sign-off follows from this regression result.

### 2026-09-19: complete post-pin default-library regression

At `e63db78b` (release implementation `b131edc3`), full default-feature library
suite passes1,434 tests, zero failures,1 ignored,198.17s. Command:
`cargo +nightly-2025-05-09 test --locked --offline -p vos --lib -- --test-threads=1`,
shared target and disk-backed TMPDIR. Session24727 terminal0; evidence
`target/task-tmp/invoke-reproduction.OS8HAC/post-pin-default-suite.log`.
No implementation changes needed. This supersedes the earlier default-feature
baseline for the repinned runtime, not the still-pending full post-pin host-feature
suite, cryptographic proof matrix or production gates.

### 2026-09-19: complete post-pin CLI regression

At `c1614b96` (release implementation `b131edc3`), full CLI unit/binary suite
passes255 tests, zero failures,19 ignored,68.54s. Command:
`cargo +nightly-2025-05-09 test --locked --offline -p vosx --bin vosx -- --test-threads=1`,
shared target, disk-backed TMPDIR and loopback socket access. Session40371
terminal0; evidence `target/task-tmp/invoke-reproduction.OS8HAC/post-pin-cli-suite.log`.
No source changes required. Ignored live campaigns are not counted as passes;
the completed new-generation Counter campaign is recorded below. Full post-pin
library and production gates remain outstanding.

### 2026-09-19: repinned release and fresh Local lifecycle qualification

Release source `b131edc3` built locked/offline nightly-2025-05-09 in6m05s,
session53025 terminal0. SHA-256:
`a2e12ecd77cf393c3ddf8ecfabecb4d366fb3e55d0d0d14dcc4f221fca8ef08b`.
Bundle creation/verification passes with the reproduced e815f4b0 runtime and
unchanged system template pins. Build, bundle and preserved previous executable
are under `target/task-tmp/invoke-release.HNhVWg/`. Previous executable checksum
remains69732438…; old fixtures were not reopened, relocated or reset.

Fresh fixture `target/task-tmp/current-latency.qEl4ba/` uses isolated XDG roots,
name `current-latency-smoke`, generated HTTP/SSH configuration with ports changed
only to18099/2243. Only the immutable Counter package was copied. Space ID:
`7852fc0a55f4d599fd461794ead6454321b96f0647b36f5347ffae51e470de7b`;
Local Agent `e690502f9954db2c631385fc35ce0c38cb23ad5f239107c955de18d020b2662c`.
First readiness17s; HTTP status/SSH keyscan pass; fresh Create35s and Install43s
both verify their signed acknowledgement without retry/resume. Shutdown<1s;
session19944 terminal0. Logs: probe.sh/probe.log/up.log, new.json, create.txt,
install.txt and HTTP/SSH evidence.

Next restart21s; fresh Counter increment managed23.48s/full test25.19s, pass;
shutdown<1s. Next restart29s; fresh read managed24.50s/full test26.29s, pass;
shutdown1s. Both test exact retirement, late-Invoke rejection, positive ACK retry
and managed resume; read verifies value7. Session52775 terminal0; host process
inspection finds no matching daemon. Logs: invoke-probe.sh/invoke-probe.log,
mutation-up.log/mutation-test.log, read-up.log/read-test.log. Counter is now7;
preserve original-path state and retained requests, do not fresh-increment again.

First-start system owner4,776ms, initial one-agent inventory11,283ms and route
reconciliation11,609ms. Create lifecycle11,198ms; publication31,359ms including
20,016ms reconciliation/19,772ms inventory. Final Install reconciliation18,570ms
includes17,942ms inventory. The large-retry deterministic gas improvement is
proven; these differing fixture/historical runs are not a controlled overall
speedup comparison. Startup still fails10s, and tens-of-seconds operations remain
unacceptable. Full post-pin suites and other production gates remain open.

### 2026-09-19: independently reproduced Invoke candidate and atomic repin

Exported immutable `24000c8add0a93ffbdf0a45f4ab3945d48583195` twice into
separate source directories with separate empty guest targets. Both locked/offline
nightly-2026-03-20 builds succeed, with identical ELF and PVM bytes. Reproduced
PVM also matches the earlier measured worktree candidate. Session45039 terminal0;
evidence `target/task-tmp/invoke-reproduction.OS8HAC/`, including `reproduce.sh`,
source-a/b, target-a/b, build/identity logs and runtime-a/b.pvm.

ProgramId `e815f4b010f7213290850189f5bc20fc54533068f0d73ea4982de9414b1135e9`;
ELF BLAKE2b256 `07c26a66d0fb477c116a158f296e8b72ba83de88bc937bcd54b70c7feea815ef`;
PVM BLAKE2b256 `cf0c0cb6799b2a808aa27300597110bd2df1e4225bc79fa268c5edf8dc907778`.
Updated provenance, host Standard ProgramId, CLI blob digest and embedded runtime
together. System templates and ABI generation unchanged.

Reproduced cost comparison again passes byte-identical output and
637,510,333→520,997,765 gas; explicit malformed/error ACK candidate test passes
(session30595 terminal0, cost.log/errors.log). Post-pin CLI compilation passes;
an initial incorrect test filter selected zero tests (pin-tests.log), not a pass
claim. Corrected selection passes18 release tests,4 bundled admission tests and
1 outer-surface test, session69863 terminal0; separate logs retained.
Post-pin physical bundled-runtime selection also passes6 tests/1 ignored in5.16s,
session48426 terminal0, `post-pin-runtime-tests.log`; no candidate override used.

The installed release executable is still the older `cca4c911` artifact. Rebuild,
fresh-space live qualification and broader post-pin regression remain required.
Do not reopen or relocate prior-generation fixtures under the new pin. The
earlier full-suite and live evidence applies to its recorded source/artifact,
not automatically to this repin. No end-to-end latency improvement claimed.

### 2026-09-19: same-call Invoke validation reuse candidate

`recover_clean_execution` and `recover_clean_invocation_error` now call a private
ACK-recovery continuation immediately after full work/authorization validation.
It retains acknowledgement matching and every exact retirement comparison.
Standalone ACK recovery still validates all availability preimages. No trust
cache, protocol change, signature bypass or unvalidated public entry point.
The initial full verifier and its NotCreated precedence are unchanged.

New native regression checks corrupted preimages, altered message and forged
signature through both recovering entry points before/after retirement, with
byte-identical state on rejection; valid retained reply and retired-Invoke
rejection pass. Session99870 terminal0 (build34.32s, test0.05s). Existing
acknowledgement selection31 passed/1 ignored in48.24s, session11541 terminal0.

Source candidate built locked/offline nightly-2026-03-20 in28.01s, session79735
terminal0. Frozen converter produces candidate ProgramId
`e815f4b010f7213290850189f5bc20fc54533068f0d73ea4982de9414b1135e9`.
Large Invoke retry input793,742 bytes: bundled637,510,333 gas versus candidate
520,997,765 (18.3% reduction), with byte-identical complete output. Timing in
that paired run1.707s/1.331s is diagnostic, not fresh-operation throughput.
Cost test session35567 terminal0. Bundled-runtime selection6 pass/1 ignored
in5.37s, session25630 terminal0; candidate override is consumed only by the
retired-Invoke and malformed-ACK cases in that selection, not every test.
The explicit `clean_acknowledgement_errors_are_byte_identical_and_fail_closed`
test also passes against the candidate (`candidate-errors.log`).

Evidence: shared `target/task-tmp/invoke-validation.5C7sn0/` with build, identity,
cost, acknowledgement and candidate logs. Native regression log remains in
`current-latency.p7U3OE/invoke-validation-regression.log`. Candidate uses current
worktree source; independent immutable-source reproduction, atomic provenance
repin, broader regression and release/live qualification remain required.
Committed runtime pins and the qualified release executable are unchanged.

### 2026-09-19: large Invoke retry validation baseline

Added `bundled_runtime_large_invoke_retry_validation_cost`, using a retained
receipt-bearing terminal result with768KiB availability. It isolates outer
validation/recovery, not fresh actor execution. The committed guest completes
with the exact expected reply: input793,742 bytes,637,510,333 gas,1,347,866us
in this run. With `VOS_AGENT_RUNTIME_COST_CANDIDATE`, the same test additionally
requires byte-identical whole output and strictly lower deterministic gas.
No production implementation or artifact changed.

The focused host-feature test passes1/1 in1.36s, session70838 terminal0;
evidence `target/task-tmp/current-latency.p7U3OE/large-invoke-retry-baseline.log`.
Source inspection locates a candidate duplicate: both `recover_clean_execution`
and `recover_clean_invocation_error` perform full work/authorization validation
then call `recover_clean_acknowledgement`, which validates the same immutable
work again. Any private continuation must retain signature/scope checks, error
precedence, exact retirement comparisons and malformed-preimage rejection.
This observation is not a measured candidate improvement or a release gate pass.

### 2026-09-19: no-std boundary and pinned maintained-example builds

`cargo +nightly-2025-05-09 check --locked --offline -p vos --no-default-features --lib`
passes5.04s (session4019 terminal0), with existing warnings. This is a library
compile boundary check, not embedded-target execution or a warning-free lint gate.
Evidence: `target/task-tmp/current-latency.p7U3OE/no-std-check.log`.

The actor example workspace used floating `nightly`, and `just build-examples`
overrode it explicitly. Pinned the actor workspace to `nightly-2026-03-20`,
matching the custom runtime workspace; removed the floating recipe override
and added `--locked` to all five builds. `CARGO_NET_OFFLINE=true just build-examples`
passes for Counter, Shared Board, Private Notes, Local Signer and the custom
Linear runtime. Session52550 terminal0; evidence
`target/task-tmp/current-latency.p7U3OE/build-examples.log`. Shared target and
disk-backed TMPDIR used throughout; no lockfile or production-pin changes.
`git diff --check` passes. These are source guest builds, not signed-package
reproduction, cross-profile deployment or full cryptographic proof qualification.

### 2026-09-19: ingress and extension qualification boundaries clarified

HTTP guide now reflects native operator API bootstrap and the live receipt-bearing
Public Counter mutation/restart campaign; it retains non-Public, yield/resume,
Private/Attested and crash-matrix gaps. Name-based adapter behavior is explicitly
separate from the qualified clean binary workflow. SSH guide and compact status
now distinguish listener/host-key smoke checks from unqualified authenticated
shell/route/proof behavior; an operator API credential is not evidence of SSH
credential enrollment. Extension guides no longer claim Local installation is
absent, but do not claim Counter evidence qualifies Substrate transactions.

Source boundaries checked: native startup bootstrap credential kind is Api;
SSH authenticates via `authenticate_ssh_public_key`; clean HTTP preparation
authenticates via `authenticate_clean_api`. No runtime changes or external
network transactions. Static clean-break gate and `git diff --check` pass;
evidence `target/task-tmp/current-latency.p7U3OE/ingress-docs-clean-break.log`.
Broader adapter/extension integration remains unqualified by this docs update.

### 2026-09-19: operator documentation aligned with qualified Local workflow

README, getting-started, operations, actor and example guides still advertised
the earlier absence of Local Create/Install/invocation. Updated them to the
implemented Linux commands, with Counter build/install instructions, canonical
ATQ1 invocation boundary, exact-resume guidance, bounded historical retention
and explicit disposable-test/Shared/proof limitations. Current release help
was checked for actor build, Local Install and managed invocation arguments;
package output naming was checked against the builder. The space-module header
was corrected; no executable production logic or artifact changed.

The static retired-command regex also falsely classified `install-local-actor`
as retired `install`. Added a complete-word boundary and executable matcher
regressions for retained Local verbs and retired whitespace/end-of-line/Markdown
forms. `bash scripts/check-agent-clean-break.sh` passes with offline Cargo,
shared target and disk-backed TMPDIR (build45.29s, session21222 terminal0).
Evidence: `target/task-tmp/current-latency.p7U3OE/docs-clean-break.log`.
`bash -n` and `git diff --check` pass. This is the static CLI/documentation gate,
not the entire `just clean-break-check` recipe or a full release documentation
audit. Remaining ingress/extension/example and proof/deployment gates stay open.

### 2026-09-19: complete current host-feature library regression

At `ba2d08ad`, the complete host-feature library suite passes1,869 tests,
zero failures,3 ignored,1,411.11s (23m31s); build13.02s. Command:
`cargo +nightly-2025-05-09 test --locked --offline -p vos --features 'agent-transition-proof private-agent-store http-ingress ssh-ingress' --lib -- --test-threads=1`.
Shared CARGO_TARGET_DIR and disk-backed TMPDIR; session14453 terminal0.
Evidence: `target/task-tmp/current-latency.p7U3OE/host-library-suite.log`.
One uninterrupted run, no source fixes, no narrowed workloads. The complete
514-query inventory rotation and system-attachment checkpoint/drain tests pass.
This supersedes the earlier full host-feature run with one outdated assertion
and its separate corrected rerun; current regression evidence is now all-green
for this precise suite, not for all production gates.

Ignored (not claimed as passing in this run): native-operation initial-capture
headroom diagnostic at the real64MiB journal boundary; fixed-history physical
decode timing probe requiring an explicit copied-db fixture; repeated large-ACK
CPU profiling probe. Their older evidence remains historical. Enabling
`agent-transition-proof` does not by itself establish the full Private/Attested
cryptographic proof matrix. Startup10s, ordinary Shared finality, authenticated
reclamation and remaining crash/proof/release requirements stay open.

### 2026-09-19: current-source default-feature library regression

At `7e096a31`, the complete default-feature library suite passes1,434 tests,
zero failures,1 ignored,200.90s. Command:
`cargo +nightly-2025-05-09 test --locked --offline -p vos --lib -- --test-threads=1`,
using the shared target and disk-backed TMPDIR. Session6085 terminal0;
evidence `target/task-tmp/current-latency.p7U3OE/default-library-suite.log`.
No source fixes or reduced workloads were needed. This updates the older
`206ea1e3` default-feature baseline, but does not substitute for a current full
host-feature suite, proof qualification or failing production readiness gate.

### 2026-09-19: current-source CLI regression and integration gates

Source `14b81955`, nightly-2025-05-09, locked/offline, shared CARGO_TARGET_DIR and
disk-backed TMPDIR. CLI binary/unit suite passes255 tests, zero failures,
19 ignored,73.34s (build0.27s). Command:
`cargo +nightly-2025-05-09 test --locked --offline -p vosx --bin vosx -- --test-threads=1`.
Session67943 terminal0. Ignored campaigns are not counted as passes; the two
explicit live Counter campaigns are recorded separately below.

Integration command:
`cargo +nightly-2025-05-09 test --locked --offline -p vosx --test build_actor_e2e --test build_task_e2e --test shutdown_smoke --no-fail-fast -- --test-threads=1`.
Actor-build4 pass25.48s; task-build1 passes28.19s; shutdown smoke fails11.68s
because no endpoint is published within the unchanged10s startup deadline.
It never reaches SIGTERM or the5s shutdown assertion. Build4.95s;
session9276 terminal101. No gates relaxed and no source changes required.

Evidence: `target/task-tmp/current-latency.p7U3OE/cli-suite.log` and
`cli-integration.log`. Failed smoke fixtures remain at their original paths:
`target/task-tmp/vosx-shutdown-450908-data-1789827038495611180` and
`target/task-tmp/vosx-shutdown-450908-config-1789827038495713962`.
The test child guard reaped its daemon; subsequent host process inspection found
no `vosx space up shutdown-smoke` process. Do not remove or relocate failure
evidence. Full library/proof and production gates are not closed by these runs.

### 2026-09-19: current-release fresh invocation and restart/read

Extended only the ignored live-test fixture whitelist for `current-latency-smoke`
with required `current-latency.` path prefix. It uses the same exact retained
Create request/ACK verification as `fresh-ack-smoke`; no success, retirement,
retry or value assertions were removed. No production runtime or artifact changed.
Locked/offline vosx test compilation passes26.03s (session69735 terminal0).

On the original `current-latency.p7U3OE` fixture, restart27s precedes a fresh
Counter increment: managed attempt25.33s, full test27.20s, pass. Shutdown2s;
next restart33s precedes a fresh read: managed attempt25.76s, full test27.56s,
pass. Both tests verify positive retirement, rejected post-retirement Invoke,
exact positive ACK retry and managed resume; read verifies persisted value7.
Both shutdowns complete within2s without forced cleanup. Probe session80905
terminal0; host process inspection finds no matching remaining daemon.
Both restarts still fail10s readiness. These Public-policy checks do not qualify
Private/Attested proofs or a general crash matrix. No controlled speedup claim.

Evidence under the same fixture root: `invoke-build.log`, `invoke-probe.sh`,
`invoke-probe.log`, `mutation-up.log`, `mutation-test.log`, `read-up.log`,
`read-test.log`. Release SHA-256 unchanged. Test executable SHA-256:
`ee6ab0da7f2063ef996ebfd8a17539028e4a4a489dc5f8ff00e201e7176a0116`.
Mutation ID `dea0f17e60e4b1b2ece77ab530f159c10f585edc8cdf8fc7a1bf22dc40751d8f`;
read ID `d74795a0cd4cd3d296bee5e8636fc38bf84ca8d708722a25477958b13bb484e6`.
Counter value is now7: preserve request stores; do not issue another fresh
increment when reproducing recovery. The probe guards against log overwrites.

### 2026-09-19: current-release fresh Create/Install measurement

No implementation or artifact changes. Verified release SHA-256 remains
`697324387cf98331f0c237e228dfc9e98947c8a97f9f1204dfa3d8eca985ce20`.
A new disposable `current-latency-smoke` space was generated with the release,
using isolated XDG roots under the shared target, not `/tmp`. Generated HTTP/SSH
configuration was enabled automatically; only ports changed to18099/2243.
Only the immutable Counter package was copied from the earlier fixture; no
host store was copied, moved or reset.

Results: first readiness18s (fails10s gate); HTTP status and SSH keyscan pass;
fresh Create38s and fresh Counter Install45s both exit0 with verified signed
acknowledgements and empty stderr, without retry/resume. SIGTERM completes in
less than1s; no forced cleanup. Probe session89278 terminal0; subsequent host
process inspection finds no matching qualification daemon. This is not a
controlled before/after comparison and does not remeasure fresh invocation.

The logs narrow the operation bottleneck: Create lifecycle takes13,029ms;
publication completes at33,901ms from lifecycle start, including20,705ms route
reconciliation (20,463ms inventory). Both Create and Install synchronously call
`self.reconcile()` before returning their successful result in
`vos/src/agent/production_owner.rs`. Install's final reconciliation takes19,570ms
(18,942ms inventory); do not attribute its entire45s wall time to this stage.
The initial one-agent inventory takes11,989ms across four queries; after Create,
two-agent inventory requires six queries. This explains why inventory work
matters beyond startup. Do not bypass authenticated publication to reduce it.

Evidence: shared `target/task-tmp/current-latency.p7U3OE/`, including `new.json`,
`probe.sh`, `probe.log`, `up.log`, HTTP/SSH output and `create.txt`/`install.txt`.
Space ID: `64877d8203099e9bb2ab739487853708087a7b380bb14507f2d8e7ac0847c6bf`.
Local Agent: `ba7d547d71e6e54f276abcd5bcc49486e103606b27393693eb63194646dc5fb2`.
Preserve this fixture at its original absolute path with its operation evidence.
The previous `fresh-ack-release.Of5a75` recovery fixture remains untouched.

### 2026-09-19: eight-entry release, two restart passes

Release `cca4c911` built locked/offline nightly-2025-05-09 in6m35s; SHA-256:
`697324387cf98331f0c237e228dfc9e98947c8a97f9f1204dfa3d8eca985ce20`.
Both bundle verifications pass with unchanged runtime/system pins. Two
successive probes used the original `fresh-ack-release.Of5a75` space without
relocation/reset or fresh mutation. Both pass HTTP, unchanged SSH identity,
live409 guidance, unchanged retained Create request, retained Counter read,
retirement and exact ACK retry. SIGTERM completes within1s in both, without
forced cleanup. Build/probe sessions86622/79561 terminal0; no remaining
vosx/cargo/rustc found after the run.

| Measurement | First pass | Second pass |
| --- | ---: | ---: |
| Readiness (10s gate) | 36s, fail | 29s, fail |
| System-owner cumulative | 14,447ms | 8,022ms |
| Runtime work before owner | 20 calls /12,307.4ms | 14 calls /6,385.3ms |
| Initial inventory | 20,422ms | 19,772ms |
| Initial full route reconciliation | 21,264ms | 20,562ms |
| Next periodic full reconciliation | 3,707ms | 3,567ms |

The first pass recovers existing history before the new policy can schedule
checkpoints. The second shows a shorter subsequent replay workload. These are
two observations, not a same-history A/B or a broad steady-state throughput
proof. Both complete one post-ready periodic refresh; more frequent checkpoint
work did not prevent these checks completing. Inventory now dominates this
fixture's remaining startup delay. No readiness gate is closed and no fresh
Create/Install/invocation latency improvement is inferred.

Evidence: shared `target/task-tmp/eight-entry-release.1zodLo/`: `build.log`,
`probe.sh`, `first-probe.log`, `second-probe.log`, and separate `first/`,
`second/` bundle/phase logs, HTTP/SSH output, conflict/request-integrity checks
and `read-test.log`. Prior release preserved as `vosx-before`. The release
and compact status now include8-entry scheduling; next investigate the roughly
20s authenticated initial inventory while preserving projection-head/credential
validation. Ordinary Shared finality, reclamation and proof/recovery gates also
remain part of the full objective.

### 2026-09-19: earlier idle checkpoint scheduling candidate

Existing owner-phase events now locate the expensive startup boundary:
`reproduce_genesis_archive`163ms → `open_shared_host`33,094ms; later provision,
drain and attachment finish the owner. This is32,931ms in the shared-host open
step, not evidence of two identical expensive owner opens. Runtime calls in
that interval need authenticated replay; do not skip them or trust an unsigned
materialized image.

Host scheduling now triggers idle system-projection checkpoints at8 retained
physical entries instead of32. This is not the protocol history/capacity limit,
issuer retention limit, or authorization policy. It uses the unchanged signed
snapshot/reattachment path and still skips reserved projections or management
work. Earlier scheduling trades more checkpoint work for a shorter future
cold-replay suffix; it cannot shorten the first reopen of an existing longer
suffix retroactively or guarantee10s startup (inventory remains expensive).

Tests:3 checkpoint threshold/exclusion/failure-recovery regressions pass11.19s;
full514-query rotation workload passes229.53s. It checks every ordered index,
authenticated monotonic snapshot and unchanged query result, now requiring at
most10 retained entries at each pre-dispatch sample (8 trigger plus completed
two-entry query). No workload or crash assertions removed. Evidence:
`target/task-tmp/eight-entry-checkpoint-tests.log`, session23585 terminal0;
build30.70s. These tests are not controlled production throughput measurements.

Release executable remains `3a990280` with32-entry scheduling. Candidate is
source-only until release rebuild and live qualification. Next measure a first
restart, a completed authenticated inventory cycle and a second restart on the
same original-path disposable fixture; record both replay and checkpoint/steady
state costs. Preserve all pending/crash evidence and unchanged readiness gates.

For a compact review/test-deployment summary, start with
[the current status](agent-saga-status.md). It does not replace this evidence
history or narrow the full saga objective.

### System-owner latency boundary confirmed

Existing `attachment-refresh-release.uESjEc/up.log` contains38 physical runtime
executions before `system_owner`, totaling30,946.6ms;30 inputs over700KB account
for30,588.7ms. System-owner cumulative time is34,937ms. These spans explain
most of that stage, but the logs do not label each runtime call as a particular
replay/management subtype. Avoid attributing all38 to one subtype without
further evidence. The source's opportunistic checkpoint trigger is32 retained
physical entries, not a10s replay-cost bound. Next inspect authenticated replay
and checkpoint scheduling; another administrative-status micro-optimization
cannot remove30s of guest execution. No new build or fixture mutation was
needed for this analysis.

### 2026-09-19: attachment-refresh release qualified

Release source `3a990280` built locked/offline with nightly-2025-05-09 in6m18s.
Executable SHA-256:
`15f23e7bd959356c7f7a5997efb5f4ddb245b8fa07de84f67a358d78329a7e5a`.
Bundle creation/verification pass with unchanged runtime/system pins. On the
original `fresh-ack-release.Of5a75` fixture, HTTP status and unchanged SSH key
pass, retired Create reports409 with inspect-evidence guidance, and request
bytes match their pre-probe SHA-256. Retained Counter read/retirement/exact ACK
retry passes2.54s (managed0.66s, NOT fresh invocation latency). SIGTERM exits
within1s without forced cleanup. Build/probe sessions90004/80115 terminal0;
post-run inspection found no vosx/cargo/rustc.

Startup58s still fails10s gate. Cumulative system-owner recovery34,937ms,
lifecycle controller35,391ms, production ready57,945ms. Initial inventory
loads in21,342ms and route reconciliation completes in22,328ms. Its six
queries now execute43 runtime calls: Credential8, each remaining page7.
The prior phase-logged release executed61 calls. This verifies removal of
repeated directory-query work, not a controlled end-to-end speedup: history,
checkpoint placement and host conditions differ, and owner recovery grew.

Across those six queries, phase totals (runtime contribution in parentheses):
prepare475ms (134.9), reserve/checkpoint1,976ms (21.5), identity403ms (136.5),
persist216ms (0), reopen593ms (132.6), Invoke11,428ms (9,419.7),
ACK6,029ms (4,025.2), complete214ms (0). Cumulative families were differenced
separately as documented below. Remaining reservation/Invoke/ACK host residuals
are roughly1.95/2.01/2.00s; physical runtime execution still dominates inventory.
System-owner recovery is now the largest observed startup stage and needs
its own bounded attribution before claiming readiness can meet10s.

Evidence: shared `target/task-tmp/attachment-refresh-release.uESjEc/`, including
`build.log`, `probe.sh`, `probe.log`, `bundle/`, `up.log`, `read-test.log`,
`conflict.stderr`, `request-before.sha256`, HTTP/SSH outputs and preserved
`vosx-before`. No old fixture was relocated or reset. No fresh Create/Install
or invocation latency was measured on this release. Full production gates
remain open; the existing two-batch review organization is unchanged.

### 2026-09-19: unchanged attachment refresh no longer queries actor lanes

`SharedAgentNetworkHost::refresh` previously called full host `list()`, which
builds administrative status and executes `engine_lanes()` through the runtime
actor-directory query. Refresh consumed only ownership/committee facts.
It now lists the existing authenticated attachment view and compares the same
generation, route, membership, committee-transition and role fingerprint.
An absent/stale/changed attachment still loads full status (including snapshot)
and follows the existing retire/rebuild path. Dispatch, capacity, Raft barrier,
admission and physical recovery checks remain in their existing owners.
No long-lived validation cache, guest change or new trust assertion is added.
Obsolete full-status fingerprint wrappers were removed.

The expanded attachment regression checks every narrow field against full
status, preserves the owner through three unchanged refreshes, then verifies
stale replacement, retired-handler rejection and restart recovery. Final-source
verification:8 network tests passed (0.60s), attachment regression passed
(3.37s),16 repeated system promotions passed (9.98s), native management
application/receipt recovery passed (42.19s). Session80564 terminal0; evidence
`target/task-tmp/attachment-refresh-final-tests.log`. Initial attachment check
also passed (`attachment-refresh-regression.log`, session5495).

The release executable remains `1c9ebdab` with SHA-256 `46c64811…`. This source
change is not yet release-built or live-performance-qualified. Next measure
the same preserved fixture and phase counters before attributing any startup
gain; the eliminated directory work is identified in source, not a measured
end-to-end improvement. All broader release gates remain open.

### Conflict-reporting release and phase qualification

Release source `1c9ebdab` (production change `12e45422`) built locked/offline
with nightly-2025-05-09 in6m49s. SHA-256:
`46c64811783cedc96c0b676f68edcdfca7c85fbea27bce2d23f00d3f53d767a2`.
Bundle creation/verification pass with unchanged guest/system pins. On the
original `fresh-ack-release.Of5a75` fixture, readiness took53s (fails10s gate),
HTTP passed and SSH identity matched. Original retired Create now reports409
with inspect-evidence guidance; SHA-256 confirms its request file unchanged.
Retained Counter read/retirement/exact ACK retry passed2.07s (managed0.54s;
this reuses the old read, not a fresh invocation latency measurement).
SIGTERM exited within1s without forced cleanup. Sessions53595/46572 terminal0;
post-run inspection found no vosx/cargo/rustc. No new functional speedup claimed.

Evidence under shared target `task-tmp/lifecycle-conflict-release.1bE9kx/`:
`build.log`, `probe.sh`, `probe.log`, `bundle/`, `up.log`, `status.json`,
`ssh-key.txt`, `conflict.stderr`, `request-before.sha256`, `read-test.log`.
Previous executable preserved as `vosx-before`. Fixture remains at its original
absolute path; this separate evidence directory does not contain relocated
host stores.

Enabled existing projection-phase logging. Summing deltas within each of the
two cumulative timing families for six initial inventory queries yields:

| Phase | Total ms | Enclosed runtime ms | Outside runtime spans ms |
| --- | ---: | ---: | ---: |
| Prepare | 1,733 | 272.6 | 1,460.4 |
| Reserve/checkpoint | 3,588 | 270.8 | 3,317.2 |
| Identity | 396 | 130.7 | 265.3 |
| Persist pending | 219 | 0 | 219 |
| Reopen/check retained ACK | 1,258 | 136.4 | 1,121.6 |
| Invoke | 13,451 | 9,504.8 | 3,946.2 |
| Acknowledge | 7,041 | 3,857.7 | 3,183.3 |
| Complete pending | 201 | 0 | 201 |

These are phase attribution on one run, not CPU profiling or controlled
before/after results. Preparation includes reattachment; reserve includes
opportunistic checkpoint and bounded reservation attempts. Runtime spans
include program load/run, not every surrounding validation. Logging/rounding
and boundary overhead remain. The explicit pending-record persist/clear
phases total420ms, so they cannot alone explain the multi-second residual.
Next bounded diagnosis should examine reserve/checkpoint's3.3s host residual
and repeated host validation around Invoke/ACK, retaining all binding, admission
and crash-recovery checks. Do not remove authenticated queries or infer that
all remaining cost is disk I/O. Full production release gates remain open.

### Inventory latency attribution from current release evidence

Analysis of existing `fresh-ack-release.Of5a75/framed-invoke-up.log` (no new
daemon/build) separates each completed startup inventory query from its
enclosed `physical Agent runtime execution` events. For two visible agents,
initial inventory required six sequential authenticated queries:

| Selector | Query ms | Runtime ms | Large calls (>700KB) | Outside runtime spans ms |
| --- | ---: | ---: | ---: | ---: |
| Credential | 4,466 | 2,351.5 | 2 | 2,114.5 |
| Agents | 4,579 | 2,330.1 | 2 | 2,248.9 |
| System-agent replicas | 4,708 | 2,275.3 | 2 | 2,432.7 |
| System-agent actors | 4,806 | 2,299.9 | 2 | 2,506.1 |
| Local-agent replicas | 4,824 | 2,218.4 | 2 | 2,605.6 |
| Local-agent actors | 5,191 | 2,269.5 | 2 | 2,921.5 |

Totals: queries28,574ms;61 runtime spans13,744.7ms;12 large calls12,687.8ms.
About14,829.3ms is outside those runtime spans. Rounding and outer query
boundaries apply; this residual is NOT attributed to one function, disk I/O,
or a replay category. Initial route reconciliation then totals29,554ms.
The later unchanged-head Credential refresh takes3,527ms, including2,336.8ms
in10 runtime spans, so the existing authenticated inventory reuse is active.

Source confirms each full refresh queries Credential, agent pages, then replica
and actor pages per agent; pagination can add queries. Each query still requires
authenticated dispatch and completion. Do not bypass these boundaries or use
stale unauthenticated inventory to satisfy readiness. Guest-only optimization
cannot remove the measured host-side residual.

Next bounded measurement: enable
`vos::agent::clean_bootstrap=debug` alongside current owner/driver logging in
the next release qualification. Existing `Authority projection phase complete`
events cover prepare/reserve/identity/persist, and execution events cover
reopen/invoke/acknowledge/complete. Each family reports cumulative elapsed time
from its own start; subtract consecutive values within a family, not across
families. These events were filtered out of the retained run, so their missing
attribution cannot be inferred. Combine this with the pending conflict-reporting
release rebuild rather than launching another independent optimization build.

### Lifecycle conflict reporting corrected (source, not rebuilt release)

Local Create/Install now map `Lifecycle(Conflict)` to HTTP409 with guidance to
inspect retained evidence. Other unavailable cases remain503; timeout remains
504. Create's existing scope/authorization403 mapping is unchanged. The CLI's
retained submission paths preserve requests and distinguish409 from transient
errors, explicitly warning that unsigned HTTP conflict is not a signed outcome
and does not prove the original operation failed. No lifecycle/issuer retention,
authentication, signed wire format, guest pin or completion state changed.

Tests: server conflict/unavailability mapping1 passed; client acknowledgement
and real-loopback409/request-preservation regression1 passed (2.58s); adjacent
Install tests7 passed/1 ignored (2.81s); noncanonical/unsigned ingress1 passed.
Logs under shared `target/task-tmp`: `lifecycle-conflict-server-test.log`,
`lifecycle-conflict-client-test.log`, `lifecycle-conflict-install-tests.log`,
`lifecycle-conflict-ingress-tests.log`. Sessions66512/4744/36573 terminal0.
The release binary remains `b7cfa17d`; this reporting fix needs its next release
rebuild and live qualification. It does not restore historical retired retries.

Evidence clarification: `submit-local-install` verifies and returns a retained
client ACK without contacting the server when one exists. The successful
Install retry commands below establish client exact-retry verification, NOT
server-side Install replay. Counter Invoke rejection and ACK retry tests do
contact the daemon, and fresh post-restart reads prove the value remains7.
Server-side Install replay remains unqualified by those CLI retry commands.

### Counter invocation and read-after-restart qualified

Unchanged release `b7cfa17d` passes the full Public Counter campaign on the
original `fresh-ack-release.Of5a75` fixture. Latest Install exact retry verified.
Increment-by7 completed in29.12s (full test31.03s), returned7 and completed
positive retirement. Two late Invoke replays rejected the consumed identity;
two ACK retries returned identical positive responses. After restart a fresh
value query returned7, completed in34.80s (full test36.71s), and passed the same
retirement/retry checks. Restarts54s/53s still fail the10s gate; both SIGTERM
shutdowns passed within2s without forced cleanup. Session11199 terminal0;
post-run inspection found no vosx/cargo/rustc. Not non-Public policy/proof
qualification; latency remains a production blocker.

Mutation: `79d4818fb02562f45c35a14e7285fe5ecc60ed624da2bb622f41076543fd23b6`.
Read: `f82147371d7a3ea729659a1362ef10cc8657344f295bd2f4616f92403247e02e`.
Do not issue another fresh increment to repeat this test; reuse retained intent.
Evidence under the same fixture: `framed-invoke-probe.sh`,
`framed-invoke-probe.log`, `framed-invoke-up.log`, `invoke-test-framed.log`,
`read-up.log`, `read-test.log`, `install-retry-framed.json`,
`framed-ack-test-build-fixed.log` (build3.03s).

Correction to prior diagnosis: the issuer deliberately retains only the latest
acknowledged decision plus bounded unacknowledged decisions. Its authorization
high-water rejects reuse of older acknowledged identifiers, and finalized
recovery consults only the latest acknowledged record. Moving lookup before
`pledge` would not recover old Create after Install. Extending historical server
retry requires an explicit retention/protocol decision, not bypassing checks.
The observed503 and its retry guidance remain limitations, not evidence of
failed creation. No production retry fix or expanded retention is claimed.

The test uses the existing framed stores at their original paths to load the
one retained Create request/ACK, verifies the signature against that exact
request, and checks SpaceID before deriving Counter coordinates. First loader
attempt treated framed bytes as raw wire and failed before mutation
(session70857 exit101, `invoke-test.log`; latest Install retry passed).
Corrected loader and full campaign pass above; failed logs and earlier503
evidence remain intact. Only test code changed, not the guest or release.

### Completed Create retry after Install: conflict found

The invocation qualification probe stopped before any mutation. Restart of the
same `fresh-ack-release.Of5a75` fixture reached readiness in60s, then
`space submit-local-create` with the original retained signed Create request
returned HTTP503. Server log: `Local Create did not complete:
Lifecycle(Conflict)`. No fresh Create or replacement nonce was submitted.
The probe exited1 (session54647); its cleanup stopped the exact daemon without
forced cleanup, and subsequent process inspection found no vosx/cargo/rustc.
Install retry, mutation and read-after-restart were NOT reached.

Source explanation: Local Install uses `CleanManagementIntentSlot::handoff_retired`
to replace the single retired per-Agent intent with its next signed request.
`CleanSystemAgentBootstrapOwner::create_local_agent` calls `slot.pledge` before
`recover_finalized_application`; `pledge` rejects a different current request.
Consequently an older completed Create cannot reach finalized issuer recovery
after that slot has advanced to Install. This is a retry-lifetime limitation,
not evidence that the previously acknowledged creation or installation failed.
Do not weaken slot authentication or relabel/reset the store to avoid it.
The correction above explains the bounded-retention contract: changing lookup
order is insufficient. Current retained retries and older retired replay must
not be conflated when qualifying the release.

Evidence: `invoke-probe.sh`, `invoke-probe.log`, `invoke-up.log`,
`create-retry.stderr` (503 error), and empty `create-retry.json` under the same
fixture. The original `create.json` acknowledgement text and all retained
requests/acknowledgements remain intact. The failed probe script is guarded
against reuse; use a new evidence path for further attempts.

The existing ignored Counter test now explicitly allows `fresh-ack-smoke`
only with the `fresh-ack-release.` fixture prefix and Counter-only checks.
It reuses the existing parent-directory guard and points to `counter.vos`.
The test binary builds successfully (4.97s; session62055 terminal0), but its
new campaign path has not executed because the prerequisite retry failed.
No production implementation or guest pin changed in this follow-up.

### Release `b7cfa17d`: restart and fresh Install

The same exact-path `fresh-ack-release.Of5a75` fixture restarted successfully
in54s. HTTP status passed and SSH host identity matched first startup.
This still fails the10s readiness gate. Cumulative phases: material34ms,
discovery48ms, admission51ms, system owner24,344ms, lifecycle controller24,605ms,
production ready53,913ms. Initial reconciliation took28,891ms. Retained-history
recovery and reconciliation dominate the observed restart stages; these logs
do not attribute every interval to an individual function or runtime call.

Fresh Counter Install into Agent `f7dd7306…` succeeded in65s, with a verified
installation acknowledgement and no timeout/resume. It used a copy of the
previously qualified `issuer-reuse-release.QR6Y4x/counter-dist/counter.vos`
package, name `counter`, no constructor bytes. Only the immutable package was
copied, not the old space stores or identity. Post-Install SIGTERM exited
successfully in under1s, with no forced cleanup. Session38226 is terminal0;
post-run inspection found no vosx/cargo/rustc. Binary checksum is unchanged.

Evidence in `fresh-ack-release.Of5a75`: `install-probe.sh`, `install-probe.log`,
`install-up.log`, `install-status.json`, `install-ssh-key.txt`, `install.txt`,
`install.stderr`, and `counter.vos`. Keep all fixture data at its original
absolute path. Create/Install now both succeed on the current release, but
their43s/65s timings are not acceptable production latency or a controlled
before/after comparison. Invocation, install retry/read-after-restart and the
broader release gates remain to be qualified. Do not repeat fresh Install
against this already installed actor to simulate a retry.

### Release `b7cfa17d`: fresh startup and Create

The locked/offline nightly-2025-05-09 release build passed in7m08s with the
unchanged production profile. Executable SHA-256:
`2b9b205e82d066b66683fe9e018ae353ba160b2cfa66fee4e1fd76606a770613`.
Its release bundle verifies and contains runtime `25bdad0f…`; authority/catalog
template identities are unchanged. This supersedes the older executable below.

A newly created isolated space automatically generated active HTTP/SSH config.
Only ports were changed to18098/2242 for isolation. First startup reached
readiness in21s; HTTP status was `ok` and SSH keyscan succeeded. The unchanged
10s startup gate therefore still fails. Cumulative startup phases were:
material36ms, discovery40ms, admission50ms, system owner5,359ms, lifecycle
controller5,361ms and production ready20,672ms. Initial route reconciliation
took15,180ms. These identify the remaining startup stages, not individual
hot functions.

Fresh `space create-local-agent fresh-ack-smoke` succeeded in43s without a
timeout/resume and returned a verified creation acknowledgement for Agent
`f7dd7306e364c65d7de953846f215675b031a0dba5af30e5f7f4415d1cf09a00`.
Immediate post-Create SIGTERM exited successfully within1s, without forced
cleanup. This is one shutdown observation, not universal busy-shutdown proof.
At this first probe, Install and fresh invocation had not been measured. Do not
compare these fresh-history timings directly with earlier retained-history
probes or infer that the14.74% fixed ACK gas saving explains the whole change.

Evidence and exact original-path fixture:
`target/task-tmp/fresh-ack-release.Of5a75/` in the shared target. Files include
`build.log`, `bundle/`, `new.json`, `probe.sh`, `probe.log`, `up.log`,
`status.json`, `ssh-key.txt`, `create.json` (CLI acknowledgement text, not JSON)
and `create.stderr`; the previous binary is preserved as `vosx-before`.
SpaceID: `0119ae586ab102b90dd606b390ef18d0d68a3c1422f2617f497d5bdf2cd971a1`.
Data/config/cache remain in this directory; never relocate raw stores for boot.
Build/probe sessions17725/70725 are terminal0; post-run process inspection
found no vosx/cargo/rustc. No existing fixture was modified.

The subsequent restart and Install are recorded above. Next measure invocation
and exact retained-request retry/read-after-restart, then update the review
handoff. Startup/Create/Install latency, ordinary Shared finality,
authenticated reclamation and full proof/recovery/release gates remain open.

### Fresh-ACK bundled artifact qualification

The fresh-ACK optimization is now in the checked-in guest. Two independent
immutable exports of source `4a208b19baa9dd36b216548681f5a3ab5add3401`, built
with nightly-2026-03-20 using separate targets, produced byte-identical ELFs
and PVMs. Conversion used the preserved, qualified builder from
`task-tmp/r17-release-candidate.fNbf43/builder/vosx`. Provenance, protocol
ProgramId, build-time digest and bundled bytes were updated together.

ProgramId: `25bdad0f9a1b0ca8450338d916adc41306d9d740f68bb5b2490ab8b8b9fb3da1`.
ELF BLAKE2b-256: `1698aff38de4b34eed9ca28c4718e2d1e7be60017d1f05d017dd1f4e8d011b72`.
PVM BLAKE2b-256: `a3cb1cfbc62cf5e5a9bb21edd892caccb41ce484da39e78577eedc9dc78f7a78`.
ABI remains `vos-agent-runtime-abi-260915-r17`; system templates are unchanged.

The fixed 793,734-byte ACK comparison has byte-identical complete output and
gas decreases from395,232,496 to336,976,182 (14.74%). All eight candidate
checks pass, covering malformed ACKs, retired retries, terminal failures,
typed errors, expiry and byte-identical fail-closed rejection. Post-pin release
checks pass18/18; ordinary physical runtime tests pass4/4 (4.08s). Both
explicit candidate tests also pass (3.20s), checking exact install lineage
after restart and Attested Invoke/Resume public-output binding. These are
execution/binding checks, not full cryptographic proof qualification.
Evidence lives in shared disk-backed
`target/task-tmp/fresh-ack-candidate.xCeHWs/`: `build-{a,b}.log`,
`identity-{a,b}.log`, `cost.log`, `candidate-tests.log`, `post-pin-tests.log`,
and `post-pin-explicit-tests.log`. Sessions10956/96781 are terminal0.

At the artifact-only checkpoint, the release executable still contained
implementation `206ea1e3` and the old runtime pin. The next step was to rebuild
the release, verify its bundle and test a fresh
isolated space before making any live latency claim. Preserve old-space
fixtures at their original paths; the new ProgramId is not permission to
rewrite existing deployment identities. Startup/Create/Install latency,
ordinary Shared finality wiring, authenticated issuer reclamation and the
remaining proof/recovery/release matrix are still open. No merge or push has
occurred. These changes belong to review batch2, not a new architecture batch.

### Source optimization qualification (before repinning)

Fresh-ACK source optimization now removes one redundant availability-validation
pass within a single immutable-work call chain. `recover_clean_acknowledgement`
already validates the work before returning no retained acknowledgement; its
sole private continuation previously called the full validator again. That
continuation now calls a private authorization helper after work validation,
retaining descriptor/scope checks, typed authorization matching and signature
verification. Other callers still use the full validator. The original
NotCreated-before-invalid-work error ordering is preserved. No public unchecked
entry point, cross-call authentication cache or durable result shortcut exists.

Acknowledgement-selected host-feature regressions pass:31 passed, zero failed,
one ignored,48.93s (build27.64s). New fresh-ACK negatives corrupt blob bytes
without changing their references, and corrupt the receipt signature; both
reject without state mutation before a valid fresh ACK and exact retry succeed.
Evidence: `task-tmp/fresh-ack-validation-reuse-tests.log`; session30763 terminal0.
The bundled-PVM tests in that selection still execute the old pinned artifact:
they are not candidate-gas qualification for this source change.

At this earlier source-only checkpoint, the change was not yet bundled or
performance-qualified. The planned next step was to build a candidate guest,
compare exact output/gas using the existing fixed large-ACK test and
`VOS_AGENT_RUNTIME_COST_CANDIDATE`, then independently reproduce and update pins
only after equivalence/hostile-frame checks pass. The release executable remains
`206ea1e3` and guest pin/source remain `79c7d1f0…` / `aad65049`. Do not claim a
live latency improvement or close any production gate from native tests alone.

### Outer-runtime instruction attribution

Instruction attribution now separates the outer AgentRuntime from nested
actors using the existing read-only Refine observer. The opt-in
`VOS_AGENT_PROFILE_REFINE_MACHINES=1` is test-only: it selects the bundled
outer runtime for the native system fixture, disables that fixture's native
clean-runtime shortcut, and profiles physical calls with inputs over700KB.
Ordinary test defaults and the production `RefineContext::run` path remain
unchanged. No guest memory or request bytes are recorded. Deliberately invalid
shape-only packages used by negative tests remain shape-only in profiling mode.

The existing `native_management_intent_executes_bundled_authority_and_recovers_receipt`
test passes with real-system-runtime profiling (149.94s, build29.89s), including
its lifecycle, exact receipt, negative-scope and recovery assertions. The same
test passes with normal defaults/profiling disabled (45.44s). Large nested calls
show274.6–276.9 million outer instructions versus11.2–19.5 million inner actor
instructions. Six large calls perform142.0–143.6 million outer instructions
with zero inner instructions and zero host calls. Thus the outer runtime is
the dominant instruction workload here; optimizing the nested Authority actor
alone cannot remove the measured cost. Machine identity and instruction count
do not identify a specific outer function: investigate outer work decoding,
validation and commitment computation rather than assuming any check is
redundant. Preserve exact authenticated bytes and gas semantics.

Observed slice times (roughly5.6–6.0s outer versus0.3–0.6s inner in nested
calls) include tracing overhead and are **not production latency measurements**.
This is a deterministic fixture with bundled code, not the preserved live-space
query. No new performance fix or release qualification is claimed.

Evidence under shared target `task-tmp`:
`prepared-runtime-real-machine-attribution-fixed.log` (session78827 exit0),
`prepared-runtime-machine-attribution-default.log` (session50103 exit0).
The initial `prepared-runtime-machine-attribution.log` run passed but emitted
no large profiles because its system fixture took the native shortcut.
`prepared-runtime-real-machine-attribution.log` records the first diagnostic
attempt's negative-fixture mismatch; the scoped fixture correction fixes it,
and the final complete run passes. Sessions48310/59846 are terminal0/101.
Reproduce via the host-feature library command with the exact test above,
`--nocapture --test-threads=1`, the opt-in variable and disk-backed TMPDIR.

### Fresh startup phase diagnosis

Targeted startup-smoke diagnosis used existing logging only; no source or
deadline change. With `RUST_LOG=info,vosx::commands::space::clean_startup=debug,
vos::agent::local_journal_driver=debug`, the isolated fresh-space test again
failed its10s endpoint deadline (test11.16s). Cumulative clean-startup phases:
bootstrap material89ms, lifecycle discovery93ms, operation admission107ms,
system owner7,254ms, admin recovery7,254ms, Local host7,256ms, lifecycle
controller7,257ms. `production_ready` was not reached. Source places the
remaining wait inside `node.start_clean_local_agent_production`; it is not a
delay in configuration generation or discovery. Two completed large runtime
calls before `system_owner` took1,503,768us and1,516,560us, with771,614/782,000
input bytes. Later logs show small calls and retry lookups before the deadline;
they do not report a completed large invocation in that final partial stage.
Do not attribute the unmeasured interval to one specific runtime subtype.

Evidence: `task-tmp/prepared-runtime-startup-phase-regression.log`; session72049
is terminal101. Failing directories remain at original paths under shared
task-tmp: `vosx-shutdown-427703-data-1789493555590592188` and
`vosx-shutdown-427703-config-1789493555590691458`. The diagnostic run preserved
the prior failure as well. Post-run inspection found no vosx or cargo process.
Next performance diagnosis should separate bundled system-owner bootstrap work
from initial production reconciliation, preserving authenticated completion
before readiness. Do not publish an endpoint early to bypass this gate.

### CLI qualification

Current CLI qualification on HEAD `04454ef0` (production implementation still
`206ea1e3`): unit/binary suite255 passed, zero failed,19 ignored,70.78s
(build50.41s). Separate integration targets: actor-build4 passed24.21s;
task-build1 passed24.76s; shutdown smoke failed11.24s because no endpoint was
published within the unchanged10s startup deadline. The SIGTERM/5s shutdown
phase was never reached, so this result is a startup failure, not a shutdown
failure. Combined CLI evidence:260 passed, one failed,19 ignored. No startup
gate extension or new production behavior was introduced.

Commands used locked/offline nightly-2025-05-09 and the shared target/disk
TMPDIR: `cargo test -p vosx --bin vosx -- --test-threads=1`, followed by
`cargo test -p vosx --test build_actor_e2e --test build_task_e2e --test
shutdown_smoke -- --test-threads=1`. Logs under shared `task-tmp`:
`prepared-runtime-cli-suite.log` and `prepared-runtime-cli-integration.log`.
Sessions64072 and22388 are terminal (exit0 and101). Failure cleanup kills and
joins only its own daemon; post-run process inspection found no vosx, cargo
or rustc. Failing data/config directories remain at their original paths:
`task-tmp/vosx-shutdown-426457-data-1789493399736676170` and
`task-tmp/vosx-shutdown-426457-config-1789493399736745123`. Daemon stderr was
empty; it does not identify the precise startup phase. Do not reset or move
this fixture as a substitute for diagnosing startup. The release executable
and pinned artifacts remain unchanged; current CLI qualification is not green.

### Host-feature qualification

The full host-feature library run on implementation `206ea1e3` is terminal
with **1,867 passed, one failed, three ignored**,1671.06s (build2m23s).
Command: `cargo +nightly-2025-05-09 test --locked --offline -p vos --features
'agent-transition-proof private-agent-store http-ingress ssh-ingress' --lib
-- --test-threads=1`. Evidence: shared target
`task-tmp/prepared-runtime-host-feature-library-suite.log`; session99230 exit101.
The sole failure is `same_head_inventory_rotates_authenticated_suffix_past_1024_entries`:
its line18475 expected the original certified snapshot at query513 (Raft10),
but opportunistic checkpointing had legitimately advanced it to Raft1033.
All descriptor/selector/nonce and preceding exact ordered-index checks passed.
The old assertion predates the idle32-entry checkpoint scheduling policy.

A test-only correction is now verified: sample every query's certified
snapshot and audited retained-entry count; require monotonic snapshot progress,
unchanged certificate at an unchanged index, repeated rotations, and at most34
retained entries (32-entry trigger plus a completed two-entry pair). Retain all
514 queries, exact selectors/nonces/descriptors,1,028-entry ordered progress,
final snapshot equality and no-pending-work/join checks. No production behavior
or gate was changed. Focused full-workload rerun passed:one test, zero failures,
279.07s (build38.69s); session37290 is terminal0. Log:
`task-tmp/prepared-runtime-inventory-rotation-regression.log`. The observation
helper has only this one test caller. The original failing log is preserved.
Evidence is a full suite with one outdated assertion plus its passing corrected
full-workload rerun, not a second all-green full-suite invocation. No known
host-feature regression remains from this run. Production latency, ordinary
Shared finality, authenticated reclamation and full proof/release gates remain
open; this test-only change does not require rebuilding the release executable.

### Default-feature qualification

Full default-feature `vos` library regression suite at source `206ea1e3`
(documentation-only HEAD `06008adf`) passes:1,434 passed, zero failed, one
ignored,219.66s. Command: `cargo +nightly-2025-05-09 test --locked --offline
-p vos --lib -- --test-threads=1`, with the shared target and disk-backed
TMPDIR. Evidence: `task-tmp/prepared-runtime-default-library-suite.log`;
session77273 is terminal0. This supersedes the older default-library baseline
for the current recovery and preparation-cache implementation. It does not
replace the host-feature matrix, CLI suite, cryptographic proof qualification,
or production release gates. No implementation change in this qualification.

Further analysis of the already-recorded `prepared-runtime-release.cJZtXj`
startup log (no new probe) isolates the pre-inventory phase:30 runtime calls
total23,634,791us, including20 large calls totaling23,203,656us. Registry
verification is logged at16:38:02.494, first inventory reconciliation starts
at16:38:30.493, and readiness at16:39:01.010. Thus roughly28s precedes the
30.516s initial inventory reconciliation. Both portions contain substantial
runtime execution; the59s startup is not explained solely by a readiness
timer or by the one periodic Credential query. These timing events lack
operation subtypes: do not label every pre-inventory call as replay or assume
it can be skipped without following its authenticated recovery requirements.

### Latest release probe

Release `206ea1e3` is now built and live-probed. Build passed6m48s with the
unchanged release profile (`cargo +nightly-2025-05-09 build --locked --offline
--release -p vosx`); bundle creation and verification pass with unchanged guest
pins. Executable SHA-256:
`8a7eda3426da2c74086881a0577516fa8e817c53672bc9df6f38118789b6e2ee`.

On the preserved space at its original absolute path, readiness took59s;
HTTP status and the original SSH identity passed. One complete periodic
Credential query took3,439ms and route reconciliation3,884ms. Its ten runtime
load/run spans totaled2,510,839us. Eight smaller executions took19.8–25.5ms;
the two large inputs still dominate:788,374bytes /1,535,769us /875,226,651gas
and790,499bytes /806,345us /385,264,799gas. They total2,342,114us, roughly93%
of measured runtime time. About928ms of the query is outside these spans.
The two earlier retry lookups took10,576/11,130us; four post-query route-audit
executions took23.8–24.3ms each. The earlier `8716f6a7` sample was4,780ms for
the query and5,602ms for reconciliation, with small calls77–98ms; retained
history and workload differ, so these are observations, not a controlled
end-to-end speedup or evidence that changed gas was charged for identical work.
The large calls remain about2.3s together: preparation reuse does not solve
their execution cost. No fresh Create or Install latency was measured.

Retained Counter read/positive retirement/exact retry passed (test2.04s,
managed attempt0.58s); no fresh actor mutation or replacement nonce. SIGTERM
sent during the next newly started Credential query passed the unchanged5s
deadline without forced cleanup. This is one busy-shutdown pass, not universal
qualification. Startup still fails the10s gate. Resident memory was225.4MiB
at readiness and232.1MiB after reconciliation; observed process high-water was
261.0MiB. There is no matching old-release memory baseline, so these values
do not isolate cache overhead or establish deployment-scale memory bounds.

Evidence: shared target `task-tmp/prepared-runtime-release.cJZtXj/` contains
`build.log`, `bundle/`, `probe.sh`, `probe.log`, `up.log`, `counter-test.log`,
HTTP/SSH evidence, and `memory-{ready,reconciled}.txt`. `vosx-before`,
`data-before` and `config-before` preserve pre-probe evidence, not a space to
boot at a new path. Build session16999 and probe session40044 are terminal0;
post-probe host process inspection found no vosx daemon. No merge or push.

Next bounded performance work should attribute the two large invocation
transitions and the startup work preceding readiness, not repeat immutable
preparation optimization. Keep exact authenticated work and gas semantics.
The full integrated release matrix, ordinary Shared finality wiring,
authenticated256-record reclamation, and proof qualification remain open.

### Preparation implementation checkpoint

Validated program-preparation reuse is now implemented after review checkpoint
`97c08c88`. `refine::PreparedProgram` owns executor-validated standard bytes and
private Conformance/standard-latency tables. Cold and prepared loads share the
fresh-state initializer; every invocation gets its own memory, permissions,
registers, arguments, gas, pending-call state and inner-machine dictionary.
The Agent replay executor retains one preparation keyed by exact program bytes,
bounded by the existing 1,280KiB program limit. Cache replacement/invalid-input
tests pass. Oversized programs and poisoned cache locks fall back to the cold
loader rather than introducing new execution admission rules. No authorization
or execution result is cached by this mechanism. Tables are cloned into each
interpreter; this avoids repeated derivation, not all allocation. Retained
tables add memory per executor; deployment-scale memory impact is unmeasured.

Release-mode load-only measurement on the bundled 983,442-byte runtime with a
790,499-byte input buffer, 20 alternating samples per path: first run cold mean
67,057us versus prepared 3,039us (one-time preparation74,970us). A repeat while
other checks were active measured87,139us versus3,492us (preparation99,356us).
The synthetic zero input is never executed; these are load measurements, not
valid management requests or end-to-end Create/Install improvements. The
ignored `refine::tests::prepared_program_load_measurement` test is reproducible
with `VOS_PVM_PREPARE_BENCH_PROGRAM` pointing to `vosx/blobs/agent_runtime.pvm`,
using `cargo +nightly-2025-05-09 test --locked --offline --release -p vos-pvm
--lib refine::tests::prepared_program_load_measurement -- --exact --ignored
--nocapture --test-threads=1` and the existing disk-backed target/TMPDIR.

Qualification: current `vos-pvm` library260 passed/zero failed/two ignored
(0.73s), including cold/prepared flat/sparse corpus equivalence, gas/exit/output/
register/permission/mapped-memory comparisons, invalid input, changed arguments,
fresh writable state, and repeated nested-machine execution. `vos-pvm
--no-default-features` check passes. Default-feature local-journal-driver module
32 passed/zero failed (42.43s), including cache admission/replacement and existing
exact-retry/authentication/preflight regressions. Focused host build1m44s.
Evidence in shared target `task-tmp/prepared-program-{runtime-tests,
local-driver-tests,load-measurement}.log`; sessions11202,10149,62749,94489,
85355,17719 are terminal. No probe daemon was started or fixture mutated.

Next: rebuild the host-feature release, verify its unchanged guest bundle,
repeat the preserved-space inventory timing and busy-shutdown probes, and
measure memory. The release executable is still source `8716f6a7`; this new
source is **not yet live-qualified**. Runtime guest pins and frozen two-batch
review ranges remain unchanged. No production latency gate is closed, and the
Shared finality, authenticated reclamation and final proof/matrix work remains.

### Previous profiling checkpoint

Existing per-runtime diagnostics captured one complete periodic Credential
cycle on unchanged release `8716f6a7`; no diagnostic code or rebuild was needed.
Readiness40s, Credential dispatch4,780ms, full route reconciliation5,602ms.
Ten physical runtime executions inside the query total2,950,015us. Two large
inputs dominate those spans:788,374bytes /1,480,849us /875,295,164gas and
790,499bytes /821,093us /385,264,799gas. Eight smaller calls take roughly77–98ms
each; four additional route-audit calls after the query take88–92ms each.
Two pre-dispatch retry lookups take about99ms each. Roughly1.83s of the query
lies outside the measured runtime load/run spans; do not attribute it all to
one host subsystem without further measurement.

Evidence: `task-tmp/runtime-timings.Ti3CYX/{probe.sh,probe.log,up.log}`. The probe
enabled existing `local_journal_driver` debug logs, waited for one complete
post-readiness reconciliation, then joined the daemon without forced cleanup.
Session95824 is terminal. No new actor mutation or client operation was submitted.
The larger gas allowance and executor source locate the large-input calls in
the invocation-transition path; there is no operation label in these timing
events, so don't claim each exact subtype solely from input size/order.

A specific next optimization candidate follows from source inspection:
`ConformanceState` gas simulation is used to precompute block costs in
`Interpreter::with_memory_and_mode`; `Machine::load_with` parses/validates and
rebuilds this immutable program preparation on every Refine load. Existing
`Interpreter::predecode` produces reusable tables for another backend path,
but Refine does not currently reuse them. Investigate an opaque, validated,
bounded prepared-program cache in the Agent executor/Refine path, with fresh
memory, registers, arguments, gas and inner-machine state for every call.
Do not expose caller-forgeable gas tables, reuse execution results, omit
availability bytes from exact acknowledgements, or alter charged gas. Require
cold/prepared differential tests for exits, gas, outputs and state isolation,
then measure the actual gain. This candidate is not implemented or qualified.

Bounded production inventory CPU profiling completed on the unchanged
`8716f6a7` release. An8s user-CPU-clock sample at99Hz captured492 samples with
zero lost samples (4.058MiB private `perf.data`). It started at a freshly logged
periodic Credential query after readiness64s. The logged query took4,441ms;
inventory/route reconciliation took5,226ms. Cleanup waited for a completed
reconciliation and joined the daemon without forced cleanup; this cleanup is
not a busy-shutdown gate. Probe session41052 is terminal.

Current symbol-level CPU sample shares: interpreter `run_inner`51.63%,
conformance gas `dispatch_one`9.55%, `tick`8.94%, `feed`1.42%, and BLAKE2
compression18.50%. Compact-code parsing and two SPI validation functions each
accounted for about1%. These are sample shares during this specific interval,
not wall-time percentages, per-invocation costs or a controlled comparison to
the older hashing-heavy campaign. The evidence now prioritizes runtime
execution/gas simulation over another blanket journal-hashing optimization.
Gas accounting, authorization and replay validation must not be disabled.

Evidence directory: `task-tmp/inventory-profile.BXFk2T/` contains `profile.sh`,
`probe.log`, `up.log`, `perf-record.log`, private `perf.data`, and `callers.txt`.
The installed profiler supports DWARF unwinding and the executable retains
unwind/symbol sections, but most recorded caller stacks were empty/incomplete;
the caller report cannot identify which individual runtime work dominates.
Next measure the individual runtime executions inside a projection or improve
stack capture before changing execution orchestration. No production source,
gas model, runtime pin or release executable changed in this profiling turn.

Safe-boundary cancellation is now live-tested on release `8716f6a7`, but the
five-second shutdown gate is **still not fully passing**. Both probes first
verified the retained Counter read/retirement/exact-retry path (no new mutation),
then waited for a newly logged Credential inventory query before signalling.
SIGINT passed within5s without forced cleanup (startup61s; session90632 exit0).
SIGTERM exceeded5s (startup37s; session82499 exit1); the daemon exited during
the following bounded cleanup after a further SIGINT, without SIGKILL. Do not
attribute the difference to signal type: both handlers set the same flag, and
per-call workload/timing differs. These are separate probe results, not a
controlled signal comparison or proof of a universal shutdown bound.

Logs/scripts under `task-tmp/issuer-reuse-release.QR6Y4x/`:
`counter-check.sh shutdown-read` / `shutdown-term-read`,
`counter-shutdown{,-term}-read-check.log`, and corresponding `-up.log` /
`-test.log` files. Each client test passed; retained managed attempt durations
were0.49/0.55s, not fresh invocation latency measurements. New logs preserve the
earlier forced-kill failures. Original state and requests remain unchanged in
identity. Host process inspection after the probes found no test/build/daemon
processes. Sessions30284 (build),90632 and82499 are terminal.

Release build passed6m34s and bundle/verification pass with unchanged guest pins.
Binary SHA-256: `4e7aa7dfa0b6e9680d33c4f46c5bf68e1553a439ad289e7703bbeb7919185d5a`.
`task-tmp/inventory-shutdown-release.DYH4h7/` contains build log, bundle,
previous executable and pre-probe forensic data/config copies. Remaining issue:
source cancellation cannot preempt one in-flight projection call; production
transport uses synchronous response waits. Profile that call and its durable
work before choosing further optimization/cancellation changes. `/usr/bin/perf`
is available; no new sampling has yet been run. Do not replace joins with
detached workers, shorten receive waits as a substitute for completion, or
extend the shutdown gate. Startup latency and other production gates remain open.

Inventory reconciliation now observes the node's shared shutdown signal between
durable projection calls. The node wires its existing signal into the owned
inventory source; the client checks before recovery/authenticated dispatch and
after each completed call, refusing further pages and discarding partial/cache
reuse. A `ShutdownRequested` result is a normal node stop only when that same
node signal is set; other errors remain fatal. No worker is detached and no
in-flight journal operation is interrupted or relabelled as complete.

All11 production-owner tests pass (0.17s), including a new transport-controlled
regression that stops before dispatch or after the Agents page, never starts
replica/actor pagination after the signal, and invalidates cached inventory.
All8 selected shutdown tests also pass (2.42s), including physical lifecycle
refusal after shutdown, owner/route join ordering and busy-outbox signal handling.
Logs: `task-tmp/inventory-shutdown-regressions.log` and
`task-tmp/inventory-shutdown-node-regressions.log`; sessions47472 and57808 terminal.
Configuration: locked/offline host features `agent-transition-proof
private-agent-store http-ingress ssh-ingress`.

This is safe-boundary cancellation, **not yet a passing five-second live gate**.
A single already-running projection call may itself be too slow. The new
release/probe results above still do not close the gate.

Current release (`668a86bb`) passes recovered-space restart/HTTP/stable SSH
identity with clean SIGINT shutdown in the idle-ingress probe: readiness30s,
HTTP status `ok`, SSH key equal to the original fixture, shutdown within5s.
Logs: `task-tmp/issuer-reuse-release.QR6Y4x/fixed-restart*`; session44307 terminal.

Counter functional qualification now passes against that same release:
mutation returned7 with positive retirement and exact-retry checks (39.55s test;
managed attempt38.01s), and a subsequent restart-read returned7 with the same
retirement/retry checks (32.42s test; managed attempt30.92s). The second check did
not repeat the mutation. The opt-in CLI test helper now explicitly allows this
disposable campaign, validates its XDG fixture root, and selects the actual
`counter` name / `counter-dist/counter.vos`; older fixtures retain their paths
and names. No production code or release executable changed for this adaptation.
CLI test binary build passed41.35s; log `pending-binding-release.QlSlXs/counter-campaign-build.log`.

**Shutdown remains a reproduced release failure after invocation.** Both phases
exceeded the unchanged5s SIGINT deadline; cleanup waited a further bounded5s
then killed and reaped only its own daemon. Overall probe sessions18429 and70435
exited1 despite their individual functional tests passing. Readiness was48s
before mutation and57s before the post-kill read. The original data and retained
requests remain in place. No data reset, repeated mutation or replacement nonce
was used; the second startup recovered after forced termination. Evidence:
`counter-check{.sh,.log}`, `counter-read-check.log`, `counter-{mutation,read}-{up,test}.log`
under the original fixture. The two managed preparation roots are
`agent-client/managed-counter-mutation` and `agent-client/managed-counter-read-after-restart`.

Logs show inventory reconciliation still progressing around shutdown. Code
inspection finds synchronous `drive_clean_agent_owner()` between shutdown checks
in `VosNode::run_forever_with`, with inventory queries dispatched synchronously.
This is the next shutdown investigation target, not yet a proven complete cause
or an implemented cancellation fix. Do not extend the5s gate or erase these
failures with the earlier idle-shutdown pass. Startup latency also remains above
the10s gate. Counter results do not qualify protected/non-Public policy or the
remaining production finality, retention and proof gates.

Live recovery and Counter Install now pass on release source `668a86bb` at the
original preserved-space path. Readiness took147s; the resumed Install reservation
then completed in92s with exit0 and a verified1,654-byte acknowledgement for
Agent `745ce15ee9860b2b50ddd80460add47e7fe518480cb5793af525ae26010e32ae`.
This was the first signed Install submission for the previously reserved nonce,
not recovery of an earlier sent Install. No new nonce, store reset, migration,
binding deletion or manual repair was used. The probe joined its own daemon
without forced cleanup; session `85175` is terminal and the subsequent host
process check found no remaining test/build/daemon processes.

Evidence: `task-tmp/issuer-reuse-release.QR6Y4x/recovery-install{,-probe,-up}`
JSON/logs/stderr, plus `create-probe.sh recovery-install`. Host startup passed
the former reconciliation failure and reached lifecycle-controller setup at
112,893ms; initial inventory/route reconciliation took31,945ms. Later Install
reconciliation took33,260ms, with individual inventory queries around4–6s.
These are observed phase timings, not a controlled before/after benchmark.
The147s startup still fails the10s release gate;92s Install is still too slow.
Subsequent restart/HTTP/SSH and Counter checks are recorded above, including
the post-invocation shutdown failures. Do not infer production qualification.

The configured release build passed in6m50s, and bundle creation/verification
pass with unchanged runtime/system pins. Executable SHA-256:
`51691210f3c98f46a40feae86bd06d79ee7d6233c98fc13b54b7f0af1cf994e8`.
Evidence directory: `task-tmp/pending-binding-release.QlSlXs/` holds `build.log`,
`bundle/`, `vosx-before`, and pre-recovery forensic `data-before` / `config-before`.
The same directory's `default-regression.log` records the four-case pending
binding regression passing under default features (3.34s; build1m40s).
Sessions `93556` (release) and `88296` (default test) are terminal.

Pre-publication pending-binding recovery is now implemented and regression-tested.
The physical test stages the actual replay-derived Shared projection/binding
before the head CAS, both with and without the immutable entry file, and with
empty and non-empty committed prefixes. Before the fix it failed reopening
with `CorruptResidue` (0.65s). After the fix all four cases reopen with the
applied cursor unchanged and reservation still pending, apply exactly once,
clear the reservation, and reopen again with identical completed status (2.86s).
Seven altered/missing reservation cases are rejected in every setup: no pending
record, different Ordered index/parent, physical index/term, payload commitment,
or entry ID. An initial test-helper compile error and a zero-ID error-variant
expectation were corrected; neither is counted as a production regression.

The ledger audit now projects Ordered index/parent from the authenticated
physical pending command. Reconciliation accepts a staged binding outside the
committed chain only for that exact next Ordered successor; all existing store,
route, payload, claim index/term/head and committee comparisons remain. This
does not mark the staged command applied or rewrite data: normal replay must
reconstruct and publish it before the ledger anchor advances. No wire, guest
pin, signed capacity or persisted-record format changes. The existing physical
snapshot/compaction/suffix-reopen regression also passes (2.12s).

Evidence under shared target `task-tmp/`: `pending-binding-regression-exact.log`
(reproduced failure), `pending-binding-fixed-exact.log` (initial passing cases),
`pending-binding-prefix-fixed.log` (four-case pass), and
`pending-binding-snapshot-regression.log`. Tests use locked/offline host features
`agent-transition-proof private-agent-store http-ingress ssh-ingress`.
Sessions `71810`, `90396`, `31487`, `65063`, `17284`, and `73433` are terminal.
The subsequent fixed release and live recovery/Install result are recorded above.

The detailed diagnostic now identifies the live failure: all 85 committed
Ordered anchors validate, but the retained pending command at Raft index113
has a binding for entry `4c26180c…` which is not in the committed Ordered chain.
Log: `task-tmp/reconciliation-release.B0uTZ2/reopen-debug.log`, failure at
2026-09-15T15:07:01Z. Reported ordered index85, snapshot base0, pending=true;
materialization completed at109,826ms. The process exited1 before readiness.
This is **not** the original-successor bug fixed below: its committed anchor
comparisons all passed. No store repair/reset or Install submission occurred.

Code inspection explains a legitimate crash boundary missing from reconciliation:
`journal_store::stage_sealed_dependencies` durably writes the Shared binding
before writing the Ordered anchor and before the head CAS. In contrast,
`validate_pending_binding` currently requires the pending entry in the committed
chain whenever a binding exists. A crash after dependency staging but before
head publication can therefore leave a recoverable reservation which open
rejects. Next add a physical regression at that boundary, then validate a
pre-CAS binding against the exact authenticated pending command and current
Ordered predecessor without treating it as applied. Recompute/replay the exact
reserved command before anchoring; do not drop the binding, skip mismatches, or
advance Raft merely because staged material exists. The binding may precede
even its immutable entry file, so tests must cover that earlier boundary too.

Diagnostic build at `66805f3e` passed in7m26s; executable SHA-256
`3ff273a7993621651afd911413a0538198cb0a382a33b883462bf35129ca617b`.
It predates the original-successor fix. Build log and pre-probe forensic copies
are in the same evidence directory. Sessions `64899` (build) and `47296`
(reopen) are terminal. The diagnostic-only suffix regression also passed1.99s;
log `task-tmp/reconciliation-diagnostic-test.log`, session `32539` terminal.

A deterministic Shared replay regression now reproduces an original-successor
bug: publish an Ordered entry, publish a Local entry, then retry the exact
Ordered entry. `AlreadyCommitted` previously constructed its publication
receipt with `current.id()`, so the receipt's successor differed from the
independently durable Ordered binding's successor. The regression failed on
that exact comparison (0.39s). Recovery now uses `stored_commit.successor()`;
the regression passes (0.52s), and all seven Shared replay tests pass (2.77s).
The retry does not re-execute the Ordered work or change current heads, and
the claim remains exact. No wire/guest pin or persisted record is changed.
This prevents new inconsistent recovery anchors; it does not repair an
already-inconsistent ledger. Whether the preserved fixture has this exact
mismatch was subsequently disproved by the detailed diagnostic above.
Evidence: `task-tmp/reconciliation-release.B0uTZ2/local-successor-regression.log`,
`local-successor-fixed.log`, and `shared-replay-fixed.log`. Test sessions
`53822`, `55289`, and `65621` are terminal. The diagnostic release build
session `64899` was started at `66805f3e` before this fix; it is not the fixed
release candidate. Its previous executable is preserved as `vosx-before`.

Diagnostic release at `2624cc0a` now localizes the preserved-space failure to
**journal/ledger reconciliation**: `published_checkpoint_validation` completed
successfully at 107,811ms, followed by `Shared journal open ledger reconciliation
failed error=CrossStoreMismatch` at 2026-09-15T14:53:17Z. Materialization completed
at 106,999ms. The process exited 1 before readiness or Install; no timeout,
repair or reset was used. The exact conflicting chain/anchor/binding remains
unknown, so this is localization, not a fix or proof the new policy caused it.
Next inspect reconciliation's ordered chain, ledger anchors, pending binding
and extra pre-snapshot bindings; do not weaken checkpoint authentication.

Build passed in 6m59s with the configured release profile. Binary SHA-256:
`5f7f2f2e879e0637a540462c36934dde81c3c7639a95e11499fe7c82d2434d9a`.
Evidence directory: `task-tmp/reopen-diagnostic-release.hiE5mF/`, containing
`build.log`, `reopen-debug.log`, `vosx-before`, and forensic `data-before` /
`config-before` copies taken before this run. Copies are evidence only, not
bootable replacements for the path-bound original. Sessions `64830` (build),
`99294` (test) and `16823` (reopen) are terminal.

The existing filesystem snapshot test now actually reopens after applying an
ordered suffix and before installing the second snapshot. It asserts exact
status preservation and no remaining command to apply. Previously its final
reopen tested only the second snapshot's empty suffix. The strengthened test
passes: 1 test, 2.35s, build31.52s, locked/offline host-feature configuration
`agent-transition-proof private-agent-store http-ingress ssh-ingress`.
Log: `suffix-reopen-test.log` in the same evidence directory. This rules out
a general suffix-reopen failure in that fixture, not the live failure above.
The test-only addition was made during the diagnostic release build; no
production source beyond `2624cc0a` was changed for that executable.

Follow-up diagnostic at the original fixture path reproduced the failure at
2026-09-15T14:37:19Z. Journal-driver materialization completed at 98,258ms
(executor setup completed at 320ms), and profile/ledger audit completed at
98,957ms. The failure is therefore after successful replay, in published
checkpoint validation or journal/ledger reconciliation, not in materialization
itself. It remains unproven which check fails or whether the checkpoint policy
caused the mismatch. Evidence: `task-tmp/cross-store-audit.bDsrWd/reopen-debug.log`.
That directory also holds forensic `data-before` and `config-before` copies,
taken before this diagnostic; they must not be booted at a different path.
No store repair or replacement was attempted. Narrow driver-open diagnostics
now distinguish those two validation stages while preserving their errors and
fail-closed behavior; the subsequent diagnostic release and result are above.
The three `projection_checkpoint` tests pass with those diagnostics (14.69s;
build 1m44s), using the locked/offline host-feature library configuration
`agent-transition-proof private-agent-store http-ingress ssh-ingress`.
This is focused regression coverage, not a reproduction or fix of the live
reopen failure.

Current preserved-space reopen is blocked: the checkpoint-policy release
exited during bootstrap at 2026-09-15T14:32:15Z with
`Shared journal operation failed error=CrossStoreMismatch`, surfaced as
`Host(CorruptResidue)`, before readiness or Install submission. Cause is not yet
localized; do not attribute it to the new policy or treat the fixture as
repairable without further evidence. The prior probe had stopped during
inventory startup, so interrupted-startup recovery is part of the investigation.
The original fixture path and all stores/request reservations remain untouched
after this failure. Log: `task-tmp/issuer-reuse-release.QR6Y4x/soft-install-up.log`;
probe session `6547` is terminal. No Install request was sent. Do not reset,
relabel, migrate or delete this failing fixture.

Release build at `53c98f7f` passes in 8m02s; `release bundle` and
`release verify` pass with the unchanged runtime pin. Build/bundle logs,
previous executable and SHA-256 evidence are in
`task-tmp/soft-checkpoint-release.CU2mct/`. Executable SHA-256:
`c6b4706944fcab89b13079d90257ccfdcd24e9139d0a19c40c795f55fa8b2d71`.
Build session `24832` is terminal; this build is not a passing live qualification.

Explicit native initial-capture headroom test now passes (320.79s; build30.99s).
The first policy-enabled run failed setup after192.07s because opportunistic
checkpoints prevented history reaching the hard boundary. The fixture now
reserves each exact projection pair before dispatch, using the real occupied
gate to suppress optional checkpoints during fill; no production knob or
synthetic capacity counter is used. Original budget, refusal-before-publication,
unchanged-state and authenticated management-repair assertions are unchanged.
Logs: `task-tmp/soft-checkpoint-headroom-exact.log` (failed setup) and
`task-tmp/soft-checkpoint-headroom-reserved.log` (pass). An earlier short-name
`--exact` command selected zero tests and is not counted. Test sessions `39390`
and `42310` are terminal. No task-owned test/build/daemon process remains live.

Opportunistic system-projection checkpoint policy is implemented with a
32-retained-Raft-entry soft threshold, derived from authenticated capacity
relative to the installed snapshot. It runs before fresh projection admission,
not during pending projection recovery. A physical command reservation skips
the attempt; the proposal mutex atomically refuses an occupied projection,
management-pending or management-retirement gate. Certificate, snapshot and
reattachment failures remain fail-closed. The existing hard-capacity checkpoint
path is unchanged; no wire, guest pin, signed capacity or issuer retention
limit changed. The threshold is a host scheduling candidate, not a proven
10-second startup bound.

Three focused tests pass (14.25s; build 1m23s): threshold/busy-gate boundaries,
physical snapshot preserving state and skipping a reserved pair, and existing
checkpoint failure/reattachment recovery. Three further physical lifecycle
tests pass (75.65s): Install handoff/retry/restart, accepted-finalization startup
recovery, and management-finalization clock-advance exact replay. Logs:
`task-tmp/opportunistic-checkpoint-tests.log` and
`task-tmp/opportunistic-checkpoint-lifecycle.log`. The release CLI was subsequently
rebuilt with this policy as recorded above; startup/Install latency remain unqualified.

The combined host-feature library suite at `f79f0e3d` is now complete:
1,862 passed, zero failed, three ignored, 2968.51s (49m28s), build 3m18s.
Enabled features: `agent-transition-proof private-agent-store http-ingress
ssh-ingress`, with defaults, locked/offline and serial socket-enabled tests.
Log: `task-tmp/current-host-feature-library-suite.log`; session `12062` is
terminal. The 514-query inventory rotation test and Shared-host attachment
checkpoint test passed. Ignored: native-operation initial-capture headroom,
fixed-history decode probe, and large-ACK profiling probe. The native headroom
case subsequently passed separately as recorded above; the others are
diagnostics. This suite predates both checkpoint changes above and does not
certify their full matrix, full cryptographic proof integration or release
readiness. No test/build processes from this checkpoint remain running.

Projection checkpoint admission now uses the existing authenticated ledger
capacity accessor instead of full host `show` status before and after snapshot
installation. Only remaining capacity was needed; deriving the actor-directory
status was unnecessary. The physical checkpoint failure/recovery regression
passes (10.22s; locked offline PVM-enabled build 32.83s), covering committee
mismatch, signing refusal, bad certificate installation and attachment/gate
recovery. Log: shared target `task-tmp/checkpoint-capacity-accessor.log`.
This is not an earlier-checkpoint policy or a measured startup improvement.
The release executable and ongoing full feature suite predate this small host
change; their evidence must remain tied to their recorded source revisions.

Counter packaging passes with the current CLI and isolated operator identity:
`actor build examples/actors/counter --name counter` completed its pinned guest
build in 27.18s. Package/PVM and build log are under
`task-tmp/issuer-reuse-release.QR6Y4x/counter-dist/` and `counter-build.log`;
ProgramId `0d2d77723e24432b0d2af5d1d94f5937fac528d2bbb3ce1391bd0905329fd402`.
The initial Install probe incorrectly supplied present-empty constructor data;
Counter requires absent data, so local validation rejected it before any signed
Install request was published or sent. Its reserved client nonce remains.
After correcting that input and selecting `--resume` to preserve the nonce,
the next probe exceeded its 180s daemon-readiness allowance before invoking
Install. Startup logs show serial inventory queries taking about 11s each.
No Install request file exists and no Install response-time result is claimed.
The isolated space, package and pending reservation are preserved. Evidence:
`install{,-probe,-up}` and `install-resume{,-probe,-up}` logs/JSON/stderr under
the same probe directory, plus `create-probe.sh install-resume`. Sessions
`5932` and `68538` are terminal and their daemons were joined without forced
cleanup. Do not allocate a replacement nonce or interpret this as an HTTP
Install failure: the corrected request was never submitted. The full feature
suite remains running in session `12062`; concurrent load limits timing claims.

Exact recovery of the timed-out Create now passes on the same release and
original fixture path. `create-local-agent --resume` returned a verified
1,520-byte acknowledgement for Agent
`745ce15ee9860b2b50ddd80460add47e7fe518480cb5793af525ae26010e32ae`
in 12s after readiness. The sole retained request compares byte-identically
to the saved pre-resume copy; the acknowledgement is durably present in that
same operation directory. No new Create request was generated. Startup on this
retained-history fixture took 129s, with the feature suite still concurrent;
this does not repair the initial 127s/HTTP-504 failure below. Evidence:
`task-tmp/issuer-reuse-release.QR6Y4x/create-resume{,-probe,-up}` JSON/logs,
`create-request-before-resume`, and `create-probe.sh resume`. Session `20128`
exited successfully and joined its daemon without forced cleanup. Install
latency is still unqualified. Feature-suite session `12062` remains live.

Initial Local Create was rechecked on the issuer-reuse release (`f79f0e3d`)
and is still not usable: one `create-local-agent` call returned HTTP 504 after
127 seconds, explicitly retaining the request with unknown outcome. The daemon
logged lifecycle completion at 66.976s and publication completion at 114.953s;
post-create inventory/reconciliation consumed 47.778s (inventory 46.551s).
These timings locate remaining work but are not controlled benchmarks: the
feature suite was running concurrently. The daemon reached readiness in 58s
on this third open of the disposable fixture. Evidence in shared target
`task-tmp/issuer-reuse-release.QR6Y4x/`: `create-probe.sh`, `create-probe.log`,
`create.stderr`, `create.json`, `create-up.log`. Session `56740` exited 1 and
its daemon was joined by cleanup without forced kill. All retained client and
space state is preserved in the original isolated directories. No retry or
Install was attempted. Publication in the daemon log is not proof the client
received its acknowledgement; use only exact retained recovery next, not a
fresh Create request. This result supersedes the earlier unmeasured-Create
qualification below; Install latency remains unqualified.

Release qualification at `f79f0e3d`: locked offline CLI release build passes
in 7m44s and now includes issuer validation reuse. Fresh `issuer-reuse-smoke`
creation generated HTTP and SSH ingress configuration without manual enabling;
only test ports changed to 18099/2241. First startup/restart passed in 30/44s,
with HTTP status `ok`, identical SSH host keys, and successful SIGINT shutdown
within the smoke's five-second allowance after both runs. The diagnostic smoke
permits 180s readiness; the unchanged 10s production startup gate still fails.
The concurrent feature suite makes these timings unsuitable for a controlled
performance comparison. Ordinary Create/Install latency is not requalified.
`release bundle` and `release verify` both pass with the unchanged `79c7d1f0…`
runtime pin. Evidence, rerunnable scripts, generated original config, preserved
previous executable, bundle, logs and executable SHA-256 are in shared target
`task-tmp/issuer-reuse-release.QR6Y4x/`. New executable SHA-256:
`317c92505ea7e1cf640b3e0da5a66851c0b595fc5b57d5f6efe94925dab7ae44`.
SpaceId: `1c041f9e9e00eaa4dbc719b45b3942851c7032cc508c6001ba7eb7574039a872`.
Build session `88238` and smoke session `14101` are terminal; no smoke daemon
is left running. The combined host-feature library suite remains active in
session `12062` (`task-tmp/current-host-feature-library-suite.log`); do not
count it as passed or launch a duplicate.

Full default-feature `vos` library suite at `0bf97332` passes: 1,429 passed,
zero failed, one ignored, 212.30s. Command: `cargo test --offline --locked
-p vos --lib -- --test-threads=1`, with approved local sockets and disk-backed
TMPDIR. The sole ignored test is
`agent::shared_raft::application_ledger_v2::fixed_history_physical_decode_probe`,
an opt-in timing probe requiring `VOS_AGENT_RAFT_BENCH_COPIED_DB`, not a release
gate. Evidence: shared target `task-tmp/current-default-library-suite.log`.
This includes the issuer validation optimization and default-feature test
guard correction. It does not qualify feature-gated PVM/Private/Attested
coverage, CLI startup/SIGTERM deadlines, live latency or the full release matrix.

Issuer validation reuse: candidate commits now reuse signature validation only
for byte-identical records at the same index under the exact same authority
in the live, already-validated issuer image. There is no persisted cache.
Changed/new records and all disk reopen paths still receive full verification;
image-wide envelope, ordering, invocation/sequence uniqueness, canonical bytes,
time and private-resolution relationships remain checked. All 22 issuer tests
pass with `--features agent-transition-proof` (28.94s; build 1m54s), including
new forged-signature, duplicate-record, high-water, authority, reopen and
precommit side-effect regressions. Log: `task-tmp/issuer-validation-reuse-pvm.log`.
The original two-test capacity baseline completed successfully in 1559.66s
(session `99095` is terminal). The candidate's same two selected capacity tests
pass in 52.04s (`task-tmp/operation-capacity-validation-reuse.log`, session
`99058` terminal). Feature sets and concurrent build load differ, so these
are indicative timings, not a controlled speedup or production latency result.
The 256-record ceiling and authenticated reclamation requirement remain.
No guest or ABI change; the previously qualified release CLI does not yet
include this host optimization.

The default-feature library test-build failure is now fixed: the two
`driver.rs` descriptor tests use a fixture that commits a PVM execution result,
so they now carry the same `pvm` guard as the fixture and execution method.
Default-feature library tests compile (1m06s), and both validation-reuse
regressions pass (0.35s). With `agent-transition-proof`, both descriptor tests
remain enabled and pass, together with the selected package descriptor test
(3/3, 0.01s; build 1m14s including Cargo lock wait). Logs:
`task-tmp/default-feature-test-gate.log` and `task-tmp/pvm-descriptor-test-gate.log`.
The original failure is preserved in `task-tmp/issuer-validation-reuse.log`.
This qualifies compilation and the selected tests, not the full library suite.

Current full CLI default suite at `1c787774`: 260 passed, 19 ignored, one
failure. Unit tests passed 255/255 selected (92.16s); actor-build integration
passed 4/4 (32.96s); task-build integration passed 1/1 (32.98s). Shutdown smoke
failed before SIGTERM at its unchanged 10-second endpoint-readiness deadline
(11.71s test duration). The exact test daemon was reaped; host process
inspection showed no remaining `vosx` process. This is a debug CLI suite,
not a release-mode latency benchmark, and it does not qualify the 19 ignored
tests. Evidence: shared target `task-tmp/review-head-cli-suite.log`.
The task-build test refreshed its stale `clerk-apply` fixture lockfile with
the SDK/protocol dependencies now required by `vos`; locked offline metadata
resolution passes with the corrected lock. No dependency version changed.
The separate coordinator capacity baseline remains live (session `99095`),
with over 21 minutes of CPU time observed; it is not counted as passed.

Review-head qualification at source `4f0b6ffb`: all 18 CLI
`production_release` tests pass (2.17s, locked offline build 24.38s).
The integration test binaries selected zero tests by this filter; this does
not rerun shutdown or the full CLI suite. Evidence: shared target
`task-tmp/review-head-release-pins.log`. The matching locked offline release
rebuild passed in 8m12s and includes the host pagination fix. Its process
(exec session `81791`) is terminal. Build log:
`task-tmp/review-head-release-build.log`. The resulting executable successfully
ran `release bundle` and `release verify`, retaining runtime pin `79c7d1f0…`.
Bundle, command logs and executable SHA-256 are preserved in
`task-tmp/review-head-bundle.LV6R83/`; executable SHA-256 is
`af3e2372489cd8461ce36c95e997a3f16cf21322c6158b283dd88a9328f1453c`.
This closes the stale release-executable gap, not live pagination qualification,
fresh-space smoke on this host revision, or ordinary Create/Install latency.
The review guide now identifies the current `79c7d1f0…` pin and separates
historical results; the old C1 boundary remains unsuitable for standalone
merge. No merge, push, runtime change or release-gate waiver was performed.

Issuer capacity safety regression: the full 256-record issuer test now
explicitly proves overflow preserves the exact image and commit count and
performs no receipt, acknowledgement, application or retirement signing. The
strengthened test passes (30.34s; locked offline build 34.35s), with evidence
in shared target `task-tmp/issuer-capacity-atomicity.log`. This does not reclaim
capacity or alter production behavior. A separate two-test baseline sequence
is still running its full-protocol coordinator capacity setup as of this
checkpoint (`task-tmp/operation-capacity-baseline.log`); do not count it as
passed or launch a replacement without checking its existing process handle.

System-actor and clean-break qualification at `c9c5ecce`: explicit locked
offline nested-workspace suites pass, with 58 Authority tests (139.27s) and
10 Catalog tests (27.36s), zero ignored. The Authority suite includes its
4,096-operation compaction regression; that does not close the distinct host
issuer's 256-record ceiling. `scripts/check-agent-clean-break.sh` also passes
with offline Cargo and isolated XDG directories: retired paths, CLI commands,
flags, unknown-command fallback and selected documentation references are
checked. Logs: shared target `task-tmp/system-actor-qualification.Rnl5Ia/`
`authority.log`, `catalog.log`, `clean-break.log`. The script rebuilt the debug
CLI, not the release executable. These are source actor tests and CLI-surface
checks, not full release or physical Shared-genesis qualification.

Portable documentation / wasm qualification at `ec779164`: the locked offline
SDK no-default-features documentation build passes with
`-D rustdoc::broken_intra_doc_links` (0.77s), and the standalone proof verifier
builds for `wasm32-unknown-unknown` (1m22s). These cover `agent-sdk-doc-check`
and `check-pvm-proof-wasm`; they do not verify external documentation links or
execute a cryptographic proof in a browser. Logs: shared target
`task-tmp/sdk-doc-current.log` and `task-tmp/verifier-wasm-current.log`.

Inventory pagination fix: the host now accepts non-final pages shortened by
the Authority's encoded-reply size bound. Previously it incorrectly required
every continuation page to fill the requested entry count and budgeted only
`ceil(entries / page_size)` calls, despite SDK-valid shorter pages. Agent,
replica and actor loops now permit at most the total-entry bound plus one page;
existing shape validation requires every non-final page to be nonempty and
advance its cursor. Exact query/head, total-entry, roster-count and descriptor
checks remain. All ten production-owner tests pass (0.16s), including a new
one-entry-per-page test spanning three agents with three replicas and actors
each, and the existing revocation/head/limit checks. Evidence: shared target
`task-tmp/inventory-short-pages.log`. This fixes host pagination correctness,
not the number of initial inventory calls. No guest ABI/artifact changed; the
previously built release CLI does not yet contain this host fix.

Ordinary-genesis promotion regression: all eight `agent::genesis::tests` pass
with a new test that rejects every independent-finality error even for a
self-consistent provision, checks repeated attempts consult the verifier,
rejects substituted contents before the trust call, and confirms a previous
successful promotion cannot bypass a later unavailable verifier. The test's
controlled verifier is deliberately synthetic; it proves call sequencing and
fail-closed promotion, not authenticated live-system publication or physical
Shared reopen. Production behavior remains unchanged. Final run log: shared
target `task-tmp/ordinary-genesis-finality-gate-final.log`. The production
issuance/publication/replay bridge identified below is still unimplemented.

No-std build qualification at `80362c21`: five explicit locked offline commands
pass: SDK check with no default features; `vos-raft` builds with no default
features for `thumbv7em-none-eabihf` and `riscv32imc-unknown-none-elf`;
`vos-pvm-proof` build with no default features; and `vos-pvm-proof-verifier`
build. These cover the commands in `just check-no-std` and
`just check-pvm-proof-no-std`, plus the SDK check. The two required embedded
targets were initially absent and were installed for nightly-2025-05-09 with
approved toolchain access; the skip-capable test wrapper was not counted as
qualification. Rerunnable evidence: shared target
`task-tmp/no-std-qualification.e0pLKx/check.sh` and `check.log` (one successful
command sequence, source revision recorded). This is build evidence, not
cryptographic proving, wasm qualification, or closure of the full release matrix.

Newest-pin release smoke at source `83737aee`: the locked offline CLI release
build passed in 6m49s. Fresh space `invoke-pin-smoke` was created with HTTP and
SSH enabled in its generated config; only test ports were changed to
127.0.0.1:18099/2241. First startup and restart passed in 27/37 seconds, with
HTTP status `ok`, identical SSH host key, and clean shutdown after both runs.
Evidence: shared target `task-tmp/invoke-pin-smoke.PqzkGQ/` contains `build.log`,
`new.json`, preserved `generated-local.toml`, `cli.sh`, `smoke.sh`, `smoke.log`,
both daemon logs/status/key files, and the prior CLI as `vosx-before`. The
current release CLI now contains the `79c7d1f0…` runtime pin and host preflight
reuse. This qualifies basic new-space/restart usability, not initial ordinary
Create/Install response times or the failing 10-second startup gate. Existing
older spaces were not migrated or relabelled; all original release gates remain.

The reproduced Invoke-authorization candidate (`79c7d1f0…`, frozen guest source
`aad65049`) is now pinned consistently in the production manifest, protocol
ProgramId, CLI build checksum and bundled PVM. Candidate Attested public-output
binding and restart-lineage checks passed before pinning (2.76s). After pinning,
all 18 CLI release-pin tests passed (1.28s), and all six feature-enabled physical
runtime integration tests passed with zero ignored. Logs are in shared target
`task-tmp/invoke-authorization-candidate.PGfgHq/post-pin-cli.log` and
`post-pin-physical.log`. The ABI and system templates are unchanged. A new
release CLI build and fresh-space smoke are still required: the existing
release executable and disposable spaces use the previous `db577aff…` pin.
Do not relabel those spaces to the new ProgramId. Full proof qualification,
production latency and the other original release gates remain open.

Invoke candidate reproduction at frozen source `aad6504974307698bd0484f65f29c5191832fe6a`:
two separate source/target/tmp guest builds passed in 29.88/30.46s, with
byte-identical ELF and PVM outputs. Frozen builder remains the previously
qualified `r17-release-candidate.fNbf43/builder/vosx`. Candidate ProgramId is
`79c7d1f0ed2feff40eaca198951656c705d687ab83bbd581a8895a13db0022a7`;
ELF BLAKE2b-256 `4d7f50c53208f69fea06a670895dd211dfcf08fda4c2f5d02b244a5bc7e5e90c`;
PVM BLAKE2b-256 `5e2a82c86cccb70b7320487b8e627d879b78924de2a6774670b4dd03ee96ff8b`.
Six candidate-selected tests passed (5.09s), covering physical terminal-failure
lifecycle, two typed-error retirements, unseen expiry, retired Invoke, and
fail-closed ACK errors. The baseline lifecycle also passed (2.46s). Both guest
versions match the entire source transition in the fixed lifecycle cases.
The first 6,049-byte Invoke consumed 40,164,903 gas on the current pin versus
36,041,920 on the candidate (10.3% less); corresponding ACK gas is unchanged.
This is a fixed-fixture gas result, not startup/Create/Install latency proof.
Evidence: shared target `task-tmp/invoke-authorization-candidate.PGfgHq/`
(`build.sh`, two build/identity logs, `physical-tests.log`,
`baseline-lifecycle.log`). Candidate remains unpinned pending remaining
artifact/integration qualification; the previously qualified CLI is unchanged.

Invoke authorization candidate: `apply_clean_invoke` no longer calls full
authorization verification immediately before `recover_clean_invocation_error`,
whose first operation is the identical full verification on unchanged arguments
and runtime state. The latter still checks blob preimages, scope and signature
before any mutation. Seven source-runtime regressions pass (0.54s): explicit
signature/scope/blob substitution preserves state, typed-error retirement,
unseen-expiry retirement, three expiry-fence cases, and unsupported-method
retirement. Locked offline build passed in 32.35s. Logs: shared target
`task-tmp/invoke-authorization-substitution.log` and
`task-tmp/invoke-authorization-regressions.log`. A preliminary legacy-execution
test also passed but does not qualify this clean Invoke change. The committed
guest pin and release CLI remain unchanged; independently reproduce and
physically compare this candidate before replacing any artifact. Source and
bundle qualification are not yet closed for this new optimization.

Preflight reuse regression follow-up: a small admitted scripted PVM produces
the same replay transition and exact RuntimeOutcome with and without reuse.
The same test proves a prepared computation cannot grant a missing replay
authentication capability and cannot bypass the runtime state-size limit.
The existing Attested provider test now injects an exact-match prepared tuple;
the proof provider remains authoritative. These three focused tests (including
the byte/gas/runtime mismatch and one-shot test) pass, with a locked offline
test build in 34.24s. Logs: shared target `task-tmp/terminal-preflight-equivalence.log`
and `task-tmp/terminal-preflight-equivalence-final.log`. Formatting followed the
build; no additional production behavior changed. This is physical scripted
runtime equivalence, not full bundled-system-workload qualification.

Release qualification of preflight reuse at `c1ab75a5`: locked offline release
build passed in 6m29s. The existing disposable space reopened, passed HTTP
status and the exact original SSH key check, and shut down cleanly. Each of
the four inventory queries emitted exactly one preflight-consumption event
and nine physical executions (previous probe: ten). Summed physical load/run
times per query were 3.029, 3.068, 3.036 and 3.000 seconds; inventory loading
took 23.834 seconds. Total readiness was 63 seconds, with more retained history
than the previous 55-second probe: do not report an end-to-end speedup or
production-latency closure. This confirms the production reuse path and smoke
behavior, not a controlled full-output equivalence benchmark. Evidence in
shared target `task-tmp/preflight-release.1ft0DF/`: `build.log`, `probe.sh`,
`up.log`, `status.json`, `ssh-key.txt`; the prior CLI is preserved as
`vosx-before`. The current shared-target release CLI now contains the reuse
change. Further substitution/invalidation coverage and final regression remain.

Terminal preflight reuse candidate: the host executor now retains at most one
completed Direct terminal-admission transition, matching full runtime program
bytes, canonical work bytes and gas before one-shot consumption by authenticated
replay. Mismatches consume the candidate and execute normally; other replay
operation kinds clear it. Restart starts empty. Attested execution still uses
the proof provider, and all existing transition/resource/publication checks
remain after reuse. Guest artifacts and checkpoint formats are unchanged.
The locked offline test build completed in 2m11s. Four focused tests passed
in 12.36s: exact-byte/gas/runtime substitution and single-use behavior, physical
pending projection Invoke/ACK recovery, checkpoint-failure gate recovery, and
existing Attested proof-binding consumption. Evidence in shared target
`task-tmp/terminal-preflight-build-test.log` and
`task-tmp/terminal-preflight-recovery-tests.log`. This is provisional: a fresh
release binary and physical reuse-count/output/latency comparison are still
required; the previously qualified CLI does not contain this host change.

Feature-enabled physical qualification at source `4b3a8c54`: all six
`agent_runtime_pvm` integration tests pass (6.19s, zero ignored), explicitly
including compiled-guest Attested Invoke/Resume and install-lineage restart.
The locked offline build used features
`pvm,private-agent-store,http-ingress,agent-transition-proof` and completed in
1m01s. `VOS_AGENT_RUNTIME_PVM` pointed to the pinned `vosx/blobs/agent_runtime.pvm`
(`db577aff…`); execution used a 12 GiB virtual-memory limit, disabled core dumps,
disk-backed TMPDIR, and a 180-second deadline. The isolated Attested test also
passed in 2.63s. Logs are in the shared target's `task-tmp/` directory:
`attested-db577-bounded-run.log` and `attested-db577-feature-physical.log`.
This verifies exact observed public-output binding and substitution rejection,
not generation/verification of a full cryptographic proof. That release gate
remains open; no production latency or full-suite claim follows from this run.

Current HEAD pins the independently reproduced authorization-reuse follow-up
(`db577aff…`), with 18 release-pin and five physical lifecycle/lineage checks
passing. Newest-pin fresh startup/restart now pass in 28/39 seconds with HTTP,
unchanged SSH key and clean shutdown; production latency remains failing.

Latest source qualification: the independently reproduced acknowledgement
optimization is now pinned, with 18 release-pin tests and five physical
lifecycle/lineage tests passing. Fresh-space startup/restart with HTTP/SSH now
pass; final release qualification and production latency remain open. The frozen
checkpoint below remains unchanged.

Implementation checkpoint: `f76dabe1` on `wip/ch08-runtime-directory`.
At that checkpoint, `saga/agents` is `31b0cdbb`: 258 commits ahead, zero behind,
221 changed files, 71,025 insertions and 58,780 deletions. These counts exclude
this documentation handoff. Both worktrees were clean when inspected.

The checkpoint is available for review and isolated, disposable Local-space
testing. It is **not master-ready or production-ready**. No merge, push,
history rewrite, or release-gate waiver is part of this handoff. Existing data
must not be relabelled across the intentional r16/r17 clean break.

## Three review areas, not three completed batches

Ordinary Shared finality wiring audit at `9d6d378d`: the CLI constructs
`UnavailableAgentFinality`, and `SharedAgentHost::verify_and_prepare` invokes
the independent verifier before accepting an AuthorityFinalized provision.
The repository has canonical decision/proof types and Standard-runtime
`FinalizeSystemAuthority` transitions/replay support; those are not absent.
However, no production implementation of the ordinary `AgentGenesisProvider`
or accepting `AgentGenesisFinalityVerifier` was found in `vos`, `vosx` or actors.
The configured `CleanSystemAgentGenesisArchive` implements the separate root
system-genesis provider, not ordinary-Agent issuance. The deployed clean
`actors/system-authority` application-finalization path does not by itself
establish an ordinary host-genesis decision proof.

Closing this gate therefore needs a clean production bridge spanning ordinary
provision issuance/archive, durable live-system decision publication, and
independent authenticated replay verification on initial admission and reopen.
Reuse the existing canonical invariants where appropriate, but do not revive
Standard-private-state decoding as the clean runtime-independent trust boundary,
substitute root bootstrap QC, or accept a provider's self-consistent response.
This audit changes no acceptance behavior and does not qualify Shared creation.

Standalone C1 audit (2026-09-15): do not treat the three-commit historical
boundary as a merge-ready recovery batch. Its `journal.rs` still encodes AJC3
checkpoints with the v3 identity domain. The later `fd7df8ec` recovery fix,
contained in the C2 range, introduces authenticated host-owned management
evidence and AJC4 checkpoints, deliberately rejecting AJC3. It also replaces
the Shared projection comparator's Standard-state decoding with that evidence.
Thus even a green historical C1 test run would not establish completion of the
required runtime-independent recovery / clean-break gate. `git diff --check`
passes for the historical C1 range; no historical build was run in this audit.
Review C1 as the portable-recovery foundation, then review its later recovery
follow-ups in C2 before deciding on integration. A separately mergeable complete
C1 batch requires dependency-aware extraction and fresh qualification; these
existing refs do not provide it. Preserve the integrated branch and its evidence.

Keep the agreed C1/C2/C3 grouping. Internal checkpoint commits are not additional
review endpoints. Two local review references now expose existing ancestry
boundaries, without rewriting or cherry-picking history. They are review
checkpoints, not declarations of completed batches or independently qualified
release branches. C3 remains pending.

| Review reference | Compare range | Size at frozen tip |
| --- | --- | --- |
| `review/agent-saga-ch08-c1-recovery` | `31b0cdbb..2eb94e4b` | 3 commits; 13 files; +3,278/-199 |
| `review/agent-saga-ch08-c2-native-integration` | `2eb94e4b..bb6c35b9` | 270 commits; 217 files; +68,596/-58,623 |
| C3 — final release | Not yet created | Depends on unfinished implementation and release gates |

The C1 tip is an ancestor of the C2 tip (integrated through merge `e72566ee`).
The two ranges cover the 273 commits ahead of `saga/agents` at `bb6c35b9`
without duplicating C1 commits. C2 includes later C1 recovery follow-ups and
provisional artifact/release work; it is not a pure native-lifecycle-only diff.
It remains a large review, not a small merge-ready patch. The old C1 boundary
was not rebuilt in this audit, so current integrated test results must not be
attributed to that historical tip. These refs are local and were not pushed;
`saga/agents` is unchanged.

Start review with:

```sh
git diff --stat saga/agents..review/agent-saga-ch08-c1-recovery
git diff saga/agents..review/agent-saga-ch08-c1-recovery -- vos/src/agent
git diff --stat review/agent-saga-ch08-c1-recovery..review/agent-saga-ch08-c2-native-integration
```

Use the per-area gates below to separate review comments from production
acceptance. Do not merge or declare C3 complete solely because the review refs
exist. Consolidating commits further, if desired, requires dependency-aware
preparation on separate branches, preserving this integrated evidence history.

| Area | Review focus | Still required |
| --- | --- | --- |
| C1 — recovery | Host-owned management evidence, physical checkpoint/GC/reopen, opaque-runtime Local lifecycle and portable recovery. | Remaining cross-runtime and positive-ack retirement coverage; preserve the distinction between scripted host-ABI tests and actual guest execution. |
| C2 — native lifecycle | Durable authorization/issuance/application/acknowledgement, native Local Create/Install, bundled system actors, first-up ingress, exact retry and restart. | Acceptable latency; authenticated reclamation beyond the 256 issued-record ceiling; ordinary Shared-agent finality; broader expiry/abort, mixed-pending and profile recovery. |
| C3 — release | Source/bundle identity, independent artifact reproduction, feature/no_std checks, docs/examples, physical and inventory qualification. | Final-source full regression and release matrix, required profile gates and fresh-space smoke after implementation closure; final scoped review ranges. |

The detailed requirements remain in [the current closeout plan](agent-saga-review.md#current-closeout-plan).
This handoff does not narrow them. Review C1/C2 implementation now; C3 cannot
certify release readiness while those implementation gates remain open.

## What has usable evidence

- Matching r17 runtime/system-template bundles were independently reproduced.
  Fresh bootstrap/restart and HTTP/SSH have passed.
- Local Create/Install exact recovery, Counter mutation, exact retries and
  restart reads have passed. Initial Create/Install HTTP 504s remain failures
  of first-response usability; successful recovery does not erase them.
- At `4e8aa893`, the broad optimized library run reported 1,813 passed,
  20 failed and three ignored. All 20 socket-dependent failures passed
  socket-enabled reruns. The ignored native-capacity test passed separately;
  the other two ignored tests were diagnostic probes. This is evidence across
  several commands, not a single green full-suite run.
- After the nested decoder changes at `d2aa1efe`, 74 focused tests passed in
  both debug and release. The full library suite was not rerun on that source.
- At `f76dabe1`, the CLI check and production-profile build passed. The release
  restart passed HTTP status, byte-identical SSH host key and clean shutdown.
  This reused a retained disposable fixture; it was not a new-space test.

## Performance: measured facts and remaining uncertainty

Newest-pin inventory phase probe (2026-09-15): the existing disposable fixture
reopened with the same release binary and additional debug filters, reached
HTTP readiness in 55 seconds, returned status `ok`, and shut down cleanly.
Evidence: shared target `task-tmp/authorization-pin-smoke.thZJrt/`
`inventory-probe.sh` and `inventory-probe.log`. Retained history advanced; this
is not a controlled comparison with the previous 28/39-second runs.

Inventory loading took 27.614 seconds across four sequential authenticated
queries (Credential, Agents, AgentReplicas, Actors): 6.696, 6.763, 6.990 and
7.163 seconds. Each query caused ten physical runtime executions; their summed
load/run times were 4.556, 4.530, 4.541 and 4.568 seconds respectively (about
66% of total inventory loading). Pending recovery rounded to zero milliseconds
in the earlier first-start log; it did not explain that log's 20.081-second load.

For the Credential query, the Invoke phase alone took 4.082 seconds after its
reopen marker; acknowledgement added 1.501 seconds. Two large physical runs
during Invoke each consumed exactly 919,907,960 gas on 783,846-byte inputs,
taking 1.616/1.624 seconds. Identical lengths and gas are not proof of identical
bytes or redundant authorization: trace their proposal/commit callers before
attempting reuse. The remaining eight executions include smaller runtime
inspection work and the large acknowledgement. The next optimization target
is the repeated Invoke execution path, not removing authenticated inventory
queries, skipping ACK, or relaxing readiness. No implementation change or
end-to-end speedup is claimed by this diagnostic run.

Source follow-up at `af132614` identifies the two execution sites:
`SharedRouteHandler::submit_clean_ordered_operation_with_admission` prepares
the reserved terminal-only query before Raft proposal. In
`SharedAgentJournalDriver::prepare_clean_ordered_operation_with_policy`,
`clean_invocation_is_terminal` executes the complete guest against current
materialized state to reject Yielded before consuming durable capacity.
`clean_invocation_terminal_outcome` returns only the outcome, discarding the
computed transition. After proposal, committed replay reaches
`StandardLocalReplayExecutor::execute_clean_invocation_transition` and executes
the guest again. This is terminal-admission preflight followed by replay, not
two inventory client dispatches or a five-second timer.

Do not remove the terminal check. A possible bounded optimization is a
single-use prepared transition consumed only after normal replay authentication
and exact equality of runtime program, canonical work (including every state
lane, authorization, availability bytes and observed slot), gas and execution
context. Mismatch, intervening state changes, restart, follower replay and
Attested contexts must retain normal execution/proof behavior. Returned outcome,
state/resource and publication checks must remain unchanged. This optimization
is not implemented or qualified; it needs substitution, one-shot consumption,
yield refusal, reopen and physical equivalence tests before performance claims.

Repeated authenticated history validation can rehash embedded artifact blobs.
A resolved library-test stack reached that work through capacity admission:
`reserve_projection_pair` → `audit_recovery_capacity` → physical-row validation
→ journal/runtime-work decoding → availability validation → BLAKE2.
This is a confirmed expensive path, not proof that it explains all daemon time.

Removing redundant nested validation preserves public constructed-value
validation, physical integrity checks and canonical encoding checks. On the
same copied 46-row, 33,750,544-byte history, the ABBA comparison measured median
decode time of **366.874 ms before versus 141.168 ms after** (about 62% lower).
There is no cross-observation validation cache and no bypass of authentication.

The latest `f76dabe1` release restart took **159 seconds**:

| Measured stage | Duration |
| --- | ---: |
| System-owner open/recovery | 95.515 s |
| Inventory reconciliation | 59.784 s |
| Of that reconciliation: inventory loading | 56.712 s |

The inventory figure includes authenticated queries, not just reading a local
table. Earlier release restarts took 99, 112 and 125 seconds, but retained
history changes between runs: these are not a controlled before/after series.
The decoder benchmark has **not** established acceptable startup or operation
latency. The internal split of system-owner recovery remains unmeasured.

Post-checkpoint diagnostic preparation adds debug-only cumulative owner-stage
timings for record/issuer validation, genesis preparation/archive reproduction,
Shared host open/provision, committed-entry draining, pending-projection recovery,
network attachment, and Authority/Catalog checks. Only static phase names and
elapsed milliseconds are logged; no payloads or identity material are added.
`cargo check --locked -p vosx` passed in 5.35 seconds with warnings. These new
markers were subsequently measured at `824b2c9c`, as below. Successive cumulative
timestamps must be subtracted to obtain each stage's duration.

### Owner-stage measurement at `824b2c9c`

The locked production-profile CLI build passed in 6m45s. A release restart of
the original disposable r17 fixture passed HTTP status, unchanged SSH identity
and clean shutdown, but readiness took **183 seconds** (09:57:13–10:00:16 UTC).
Within this run:

| Stage | Duration |
| --- | ---: |
| Owner record/issuer through genesis/archive preparation | 0.174 s |
| Shared host open, including committee binding before the marker | 119.009 s |
| System bootstrap provisioning | 0.784 s |
| Explicit post-open committed-entry drain and pending-projection check | about 0.001 s |
| Network attachment | 2.235 s |
| Authority/Catalog checks after attachment | 0.202 s |
| Inventory reconciliation | 56.682 s |

The dominant owner interval is `SharedAgentHost::open_with_root`, not genesis
preparation or the explicit post-open drain. Its internal replay/verification
split still needs measurement; this does not show that replay itself is cheap,
because reopening the host includes recovery. Retained history differs from
earlier runs, so 183 seconds is not an optimization comparison.

A preceding raw-copy probe failed with `Host(CorruptResidue)` before host open
completed; networking also reported sandbox `Operation not permitted`. Source
inspection found that the outer lease commits to the absolute host path and
the authority namespace is derived from that path. Relocating a directory copy
is not a supported reopen fixture. Neither copy nor original was repaired or
cleared. The successful probe instead used socket permission at the original
fixture path and therefore could advance that fixture's authenticated history.
The raw copy's Raft DB initially matched the original at SHA256
`ddef123679ad07d43c374f0340f14f36b4462a11642f2bd57bc7f750063a4a6a`;
matching bytes alone does not preserve the outer lease's path binding.

Next performance work should measure that owner stage internally on fixed
history, then address the measured repeated work while preserving recovery
proofs. Do not clear history, increase timeouts, skip checks, or infer that
retirement alone permits deleting issuer/coordinator records.

The next diagnostic source adds cumulative debug timings in
`SharedAgentHost::open_generation` for journal-store opening, Raft ledger,
artifact store, journal driver and exposure/restore. Nested driver timings
separate artifact audit, committee history, executor setup, materialization,
profile/ledger audit, reconciliation and final reverified-open bookkeeping.
Enable `vos::agent::shared_host=debug` and
`vos::agent::shared_journal_driver=debug` in addition to the prior modules.
These markers have only a CLI check pass (5.28 seconds, with warnings), not a
release timing result. Its log is `owner-startup-phases.5se4bH/shared-open-check.log`.
Source inspection shows `audit_recovery` is invoked by ledger opening,
committee-history loading and journal auditing. Their duration and safe scope
for reuse are not yet established; no audit was removed or cached.

### Replay attribution at `f2b17cb2`

The locked release CLI build passed in 6m35s. The original-path r17 restart
passed HTTP status, unchanged SSH identity and clean shutdown in **54 seconds**
(10:10:20–10:11:14 UTC). This was instrumentation-only source, not a performance
fix. The retained suffix started at **7 rows**, versus **85** in the preceding
183-second run. That prior log shows 92 rows at 09:59:55.374682, zero at
09:59:55.731954, and seven at shutdown. The shorter restart must not be
attributed to the new timing markers. The capacity-triggered certified
checkpoint path is present in `query_authority`; the row-count transition is
consistent with that path, not evidence of manual history deletion.

Measured generation-open durations on the seven-row suffix:

| Stage | Duration |
| --- | ---: |
| Journal-store opening | 44 ms |
| Raft ledger opening | 24 ms |
| Artifact-store opening | below 1 ms timer resolution |
| Journal driver total | 8,054 ms |
| Within driver: `materialize_current` replay | 7,898 ms |
| Within driver: committee history | 19 ms |
| Within driver: profile/ledger audit | 56 ms |
| Within driver: cross-store reconciliation | 80 ms |
| Exposure/restore after driver | 43 ms |
| Inventory reconciliation after owner startup | 41,798 ms |

In the earlier 119.009-second host-open interval, the three completed recovery
audits total only 847,082 microseconds (299,300 + 251,223 + 296,559). Auditing
therefore does not account for most of that interval. The new run directly
locates most driver-open time in replay; attributing the earlier interval to
replay is an inference from the call order and audit timestamps, not a direct
replay timing on the same 85-row history.

Next work should focus on replay execution and safe certified-checkpoint policy,
while separately addressing inventory-query execution. Do not remove audit
checks based on the earlier BLAKE2 sample: the sample and decoding benchmark
identify real work but do not explain most startup latency. Both builds and
the startup probe are terminal; no process remains to poll. Evidence is in
`shared-reopen-phases.LP4zS4/{build.log,run.log,up.log}`, with the probe script,
HTTP status and SSH-key evidence alongside them.

### Physical runtime attribution without another rebuild

The same `f2b17cb2` release executable, with the existing
`vos::agent::local_journal_driver=debug` timer enabled, passed original-path
startup/HTTP/SSH/shutdown in **75 seconds** (10:14:33–10:15:48 UTC). Its retained
suffix started at 20 rows, so this is again not a fixed-history comparison.

Between the driver `executor_setup` and `materialize_current` markers, replay
took **25,048 ms**. Eighteen `physical Agent runtime execution` records total
**24,304,768 microseconds**, approximately **97%** of replay time. The timer
includes `RefineContext::load` and `.run`, not just interpreted instructions;
it excludes the subsequent bounded output decode. Call inputs were roughly
789–793 KB, with alternating calls using about 933 million and 500 million gas.
This establishes physical runtime load/run as the dominant measured replay
cost, not repeated host-side ledger auditing. It does not yet separate loading,
outer-runtime execution, nested actor execution or specific guest functions.

Inventory reconciliation took **44,935 ms**, including **42,885 ms** loading
inventory. The next implementation investigation should target runtime-call
cost (and distinguish load from execution if needed), while preserving guest
semantics, exact outputs and gas accounting. More aggressive checkpointing
could limit replay length but would not by itself fix expensive live queries.
No cache, checkpoint-policy change, timeout change or new artifact pin was made.
Logs, script and HTTP/SSH evidence are in `runtime-replay-timings.J9kxo3/`.
The probe exited zero and its daemon is stopped.

### Source-only acknowledgement candidate

The wire acknowledgement path first called `recover_clean_acknowledgement`,
then called `acknowledge_clean_invocation`, which repeated the same recovery
validation before applying fresh work. That validation includes `work.validate`
on the large availability payload. The candidate introduces one combined
recovery/application method returning the acknowledgement and whether it was
newly applied. The wire layer preserves its original state for retained retries
and errors. Fresh application still performs all original authorization,
result-binding, capacity and retirement checks. The unchecked fresh helper is
private and only called immediately after successful recovery validation.

Three focused acknowledgement tests passed (0.86 s), including a new status,
exact-retry and substituted-request state-preservation test. Seven additional
terminal-failure/restart/exact-acknowledgement/Required-attestation tests passed
(0.23 s). The CLI check passed (5.55 s, warnings). Only whitespace formatting
changed between the focused test build and the final CLI check. Logs are
`runtime-replay-timings.J9kxo3/ack-status-{tests,recovery,check}.log`.

This is **not yet in the bundled PVM** and has no measured gas or production
latency improvement. Next: build a candidate runtime without changing the pin,
compare its fixed large-ACK output and gas against the bundle, run rejection
and retry coverage against the physical candidate, then independently reproduce
and repin only when the candidate is qualified. Preserve the frozen review
checkpoint for matching-source/bundle testing in the meantime.

### Acknowledgement candidate built and reproduced

Two independent exports of `e3e9cb85a23c6122743ef641f209c670d4d8b70f`, separate
guest targets and locked/offline `nightly-2026-03-20` builds completed in
27.62 s and 28.66 s. The existing frozen r17 builder converted both. ELF and
PVM comparisons are byte-identical. Candidate identities (BLAKE2b-256 for
files, ProgramId for the program):

- ELF: `192eb3707f5028c23bdb283b5ac27949d6c3b9a634265481bad7558eb1c19811`
- PVM: `039393a40e61e25096533dedd24354ad38fb2d2ec05182bc08d60d11ffeb2933`
- ProgramId: `891e74d48bed26dc93f744a48cc34a001fddf1f348d3e19570133be282117cb0`

The fixed 793,734-byte large-ACK test passes byte-identical complete output
against the bundled r17 runtime. Gas decreases from **515,760,196 to
457,383,570** (about **11.3%**). Single debug-host timings of 1.089 s and 1.048 s
are not a controlled production wall-time comparison. The candidate also
passes the physical terminal-failure lifecycle test (five cases with retries,
acknowledgement and repeated acknowledgement) and two physical typed-error
retirement tests, comparing complete guest output to source: three tests total,
2.56 s. Together with the gas comparison, four candidate physical tests passed.

Evidence is under `ack-recovery-candidate.dHhhcp/`: `build.sh`, `build.log`,
`runtime-build.log`, `identity.log`, `cost.log`, `physical-recovery.log`, and
the independent `second/` export/build/artifacts. Builds and tests are terminal.
The candidate is **not pinned**. Broader physical malformed/retry qualification,
atomic provenance/pin updates and final-source fresh-space checks remain before
promoting it; no production latency gate is closed by the gas result.

### Physical rejection qualification and native-test failure

`VOS_AGENT_RUNTIME_ACK_CANDIDATE` now selects the candidate in the physical
retired-invocation test and optionally adds physical output comparison to the
five forged/divergent acknowledgement rejection cases. A new physical test
requires truncated and trailing acknowledgement frames to produce `Panic`,
with a valid-frame `Halt` control. Five focused tests passed in 1.25 s, covering
those checks plus capacity and exact-retry status. The changes are test-only;
the previously reproduced candidate remains the same guest source.

The broader 31-test `acknowledgement` filter **aborted with stack overflow**;
it is not a passing qualification run. Isolated native Install/reopen before
acknowledgement passed in 12.00 s. The isolated startup-finalizes-saved-ACK
case still overflows at the normal stack limit. A debugger located the fault
in BTreeMap insertion during `StandardAgentRuntime::restore`, called from
`decode_standard_runtime_state` → `apply_clean_invoke` → native-test replay
inside Shared driver reopen. The sampled path does not reach acknowledgement
application, but there is no same-profile baseline comparison proving this is
pre-existing. Do not promote the candidate on the focused passes alone.

Evidence under `ack-recovery-candidate.dHhhcp/`: `ack-qualification.log`,
`ack-focused.log`, `native-ack-isolated.log`, `native-ack-remaining.log` and
`stack-diagnosis.log`. The debugger accidentally used the default temporary
directory; its exact failed fixture was moved from
`/tmp/vos-clean-system-bootstrap-bundled-authority-management-49266-1` to
`debugger-failed-fixture/` in this evidence directory, preserving it on disk
and removing that RAM-backed copy. The moved raw fixture is forensic evidence,
not a reopenable replacement for its path-bound original. Test/debugger
sessions are terminal. Next: resolve or establish the baseline for this native
stack failure without increasing stack limits or weakening assertions, then
finish pin qualification.

### Native stack failure resolved without changing the stack limit

The install fixture called its restart/recovery helper while retaining large
installation-setup frames. `check_install_startup` now runs that same recovery
helper on a normal-sized scoped worker, following the existing lifecycle-test
pattern. No assertions, production code, thread stack sizes or guest artifacts
changed. The previously overflowing exact native saved-ack startup test passes
in **16.80 s**. The original broader acknowledgement filter then passes:
**30 passed, zero failed, one ignored profiling probe**, **29.56 s**, with
`VOS_AGENT_RUNTIME_ACK_CANDIDATE` selecting the candidate where supported.
This resolves the observed stack failure; it does not establish when it first
appeared or replace final-source full-suite qualification.

Evidence: `ack-recovery-candidate.dHhhcp/native-stack-fixed.log` and
`ack-qualification-fixed.log`. `native-stack-build.log` records the 32.03-second
test build but selected zero tests due to a short filter combined with
`--exact`; it is build evidence only. The subsequent exact fully qualified
invocation and broader run above are the actual test evidence. Both are
terminal. Artifact pins remain unchanged pending promotion qualification.

### Reproduced acknowledgement runtime pinned

The runtime PVM, `support/production-artifacts.toml`, protocol ProgramId and
`vosx/build.rs` digest now use the independently reproduced `e3e9cb85` artifact
and identities listed above. The r17 ABI and system actor templates are
unchanged; the runtime ProgramId is new. Preserve old fixtures and do not
relabel their pinned identity. Use a new disposable space for the next smoke.

Post-pin verification without candidate overrides:

- CLI release-pin tests: **18 passed**, 0.88 s (34.71-second test build).
- Physical `agent_runtime_pvm` suite: **4 passed, one ignored**, 1.75 s.
- The ignored compiled directory-lineage/restart test was explicitly run with
  the new bundled PVM: **passed**. The Attested output-binding test is gated by
  `agent-transition-proof` and was not compiled/run in this feature selection.

The first integration run failed two stale assertions: a hardcoded r15 ABI
despite r17 source, and `AuthorityExpired` for an invocation already acknowledged
and retired. The latter is now asserted as `DivergentInvocation`, consistent
with the existing physical retired-invocation test and the runtime's retained
retirement check. State-preservation assertions remain. The final rerun above
uses corrected expectations, not changes to guest behavior.

Evidence under `ack-recovery-candidate.dHhhcp/`: `post-pin-cli.log`, initial
`post-pin-physical.log`, corrected `post-pin-physical-final.log`, and
`post-pin-lineage.log`. No full-suite or new-pin daemon latency pass is claimed.
Next: build the pinned CLI and run fresh-space bootstrap/restart/HTTP/SSH with
the matching runtime, then finish the remaining original release gates.

### Fresh-space smoke at `725f6240`

The pinned release CLI build passed in **6m32s**. A new isolated identity and
space were created successfully, with the generated `local.toml` enabling HTTP
on loopback 8080 and SSH on loopback 2222. The original default-port smoke
refused to start because a default port was already occupied; that service was
not touched. The generated config was preserved, then only this fixture's ports
were changed to loopback **18097/2239**.

First startup reached readiness in **32 s**, restart in **42 s**. Both passed
HTTP `status == ok`, SSH key acquisition and clean SIGINT shutdown. The final
raw `ssh-keyscan` file comparison failed because comment/banner lines arrived
in different order. A separate comparison established exactly one actual key
record in each file and byte-identical sorted non-comment records; no key data
was ignored. The script now compares key records rather than comment order.
Thus the original script exited one, while the explicit corrected identity
check passed; do not describe this as an unmodified one-command green run.

SpaceId: `b609a179190b8678f0b1223f0a25fec4e6dfb1390c3acda20add17cca978ba07`.
Genesis root: `60394853bfae8f28af589c52411a8de93181ddf6ee17c35bc44dfd38e061d072`.
Evidence: `ack-pin-fresh-smoke.31JLq5/` contains `build.log`, `new.json`,
`new.stderr`, `generated-local.toml`, initial `smoke.log`,
`isolated-smoke.log`, `first-up.log`, `restart-up.log`, HTTP responses,
SSH key records and the corrected `smoke.sh`. Both daemon runs and build are
terminal. Previous fixtures were untouched and all scratch is disk-backed.

This validates fresh bootstrap and restart with the new bundle, not new-pin
Create/Install latency, sustained capacity, ordinary Shared-agent finality or
the final production release matrix. Different histories make earlier timing
comparisons uncontrolled; the measured 11.3% gas reduction remains limited to
the fixed large acknowledgement test.

### Full CLI run: startup deadline remains failing

At `c441fabd`, the full socket-enabled `cargo test --locked -p vosx` run
reported **255 unit tests passed, 19 ignored**, four package-build integration
tests passed, and one build-task integration test passed. Shutdown smoke failed
to observe an endpoint within its unchanged **10-second startup deadline**.
Its preserved daemon log later reported `Address already in use`; the process
had exited when checked. The command is therefore **not green**: 260 passed,
19 ignored, one failed across its binaries. The SDK locked/offline
`--no-default-features` check also passed (0.20 s).

The shutdown test now uses loopback ephemeral ingress ports, detects early
child exit, and owns a guard that kills/reaps its exact child on panic paths.
Both startup (10 s) and SIGTERM-exit (5 s) deadlines and endpoint-removal
assertions are unchanged. The isolated rerun still failed startup readiness in
11.43 s overall; the child was subsequently confirmed absent. The guard fixes
test cleanup and port isolation, **not** the production latency gate. The
successful 32/42-second manual release smoke does not satisfy this test's
deadline or prove SIGTERM-after-readiness through this test. Earlier manual
smoke shutdown used SIGINT.

Logs: `ack-pin-fresh-smoke.31JLq5/full-cli.log`, `sdk-no-std.log` and
`shutdown-isolated.log`. The first failure's retained fixture is
`target/task-tmp/vosx-shutdown-69213-data-1789469988435677136` with its paired
config directory; all are disk-backed. The build-task test incidentally updated
its tracked fixture lockfile; only that generated change was reverted before
committing the shutdown-test patch. Tests and child processes are terminal.

### Source-only reuse of fresh acknowledgement authorization

Fresh acknowledgement already fully verified immutable work, authorization
and runtime identity before loading the retained result. It then called that
full verifier again with only a different observation slot. The follow-up keeps
the first full verification (blob validation, scope, issuer and signature) and
uses `matches_invoke` for the second slot-dependent check. PublicPreflight's
lower-bound slot condition and `InvalidAuthorization` error are retained. There
is no intervening mutation, no persistent validation cache and no weakening of
retained result/liveness/retirement checks.

A new test compares full verification with slot-only rechecking after admission
for signed receipts and PublicPreflight at zero, below/at/above the admission
slot and `u64::MAX`. The final acknowledgement run reports **31 passed, zero
failed, one ignored profiling probe**, **29.16 s**. Evidence:
`ack-recovery-candidate.dHhhcp/authorization-reuse-final.log` (the earlier pass
without the added equivalence test is `authorization-reuse-tests.log`).

This follow-up is not built into the bundled PVM and has no measured gas or
end-to-end speedup yet. Next: freeze and independently build a candidate,
compare exact output and gas against the current `891e74d4…` pin, and qualify
physical retry/rejection behavior before another pin change. The unchanged
10-second startup deadline remains failing.

### Authorization-reuse candidate reproduced and pinned

Independent exports of `126657f70b6e8523f57b6cfd3e476a75adaa048c` built with
locked/offline `nightly-2026-03-20` in **26.80 s** and **28.78 s**, using distinct
guest targets and the frozen r17 converter. ELF and PVM match byte-for-byte.
The PVM and matching provenance/build-time/protocol pins now use:

- ProgramId: `db577aff938689516493e01de59536218388e780dd7bf1f9f81ce056dbb764a9`
- ELF BLAKE2b-256: `ba471081c021bc0ada12d091941ed7b7099f44e7e72a75223b6066a28b1ef0fd`
- PVM BLAKE2b-256: `90774afca15a8911b9690f4621c838b4ef46b1aa1c1c11e739eff113ac49c8a7`

The fixed 793,734-byte acknowledgement output is identical to the preceding
`891e74d4…` pin, with gas **457,383,570 → 395,232,496** (13.6% lower). Relative
to the earlier 515,760,196 baseline, the two optimizations together reduce this
specific test's gas by about 23.4%. Single concurrent debug-host wall timings
are not evidence of production latency improvement.

Nine selected checks passed (4.69 s), including the gas comparison, candidate
physical malformed-frame/rejection/retry/retirement and terminal-failure/typed
error coverage, plus native acknowledgement capacity/status tests. Post-pin,
without candidate overrides, **18 CLI release checks** passed (0.72 s), **four
physical lifecycle tests** passed (1.68 s), and the separately enabled compiled
directory-lineage test passed. The Attested proof-feature gate and newest-pin
daemon smoke remain open, as does the original 10-second startup failure.

Evidence: `ack-authorization-candidate.rYKE8M/` contains `build.sh`, `build.log`,
the `first/` and `second/` source/build/artifact directories, `physical-tests.log`,
`post-pin-cli.log`, `post-pin-physical.log` and `post-pin-lineage.log`. No guest
ABI or system-template change was made; no existing fixture was relabelled.
All builds/tests from this checkpoint are terminal.

### Newest-pin release smoke

The locked release CLI build from `c5260e9f` completed in **6m26s**; its runtime
and production source match the `bb6c35b9` C2 review checkpoint (the intervening
commit only records review references). A new isolated space named
`authorization-pin-smoke` was created, generating the default HTTP/SSH config.
That generated config was retained, then only the test ports were changed to
loopback **18098/2240**. Prior fixtures and services were untouched.

The complete smoke script exited zero: **28 s first startup, 39 s restart**,
HTTP `status == ok` on both, exactly one SSH key record per run, identical
non-comment key records, and clean SIGINT shutdown after each run. No test
daemon remains. These are new-history observations, not controlled wall-time
speedup measurements. The 10-second startup test and Create/Install latency,
capacity, Shared finality and remaining release/profile gates are still open.

Evidence: `authorization-pin-smoke.thZJrt/` contains `build.log`, `new.json`,
`new.stderr`, `generated-local.toml`, `cli.sh`, `smoke.sh`, `smoke.log`,
`first-up.log`, `restart-up.log`, HTTP responses and SSH key records. All
scratch and fixture stores are disk-backed. Review refs remain frozen; neither
`saga/agents` nor master was advanced.

## Local evidence and resumption

Evidence is on disk under `.worktrees/ch08-c2-native/target/task-tmp/`, not `/tmp`:

- `decoder-fixed-history.Q5oYmW/`: `comparison.log`, paired baseline/candidate
  logs, `candidate-release-regressions.log`, `startup-phase-check.log`,
  `startup-phase-build.log`, `startup-phases-run.log`, `startup-phases-up.log`,
  status response and SSH-key comparison inputs.
- `r17-startup-smoke.ncMr4z/`: `final-source-release-library.log`,
  `final-source-network-sockets.log`, `final-source-merge-socket.log`,
  `final-source-node-socket.log`, and `final-source-native-capacity.log`.
- `owner-startup-phases.5se4bH/`: `build.log`, failed relocated-copy `run.log`
  and `up.log`, successful `original-run.log` and `original-up.log`, HTTP/SSH
  evidence and both probe scripts. The successful probe exited zero; neither
  probe remains running.

These are local evidence paths, not committed or portable release artifacts.
Preserve the fixture's config/locks authority stores as well as its data,
retained requests and logs. The latest smoke completed and stopped its daemon;
its session handle is no longer live. Do not restart it merely to poll status.

Before integration, inspect the complete diff and dependencies and establish
the three review boundaries without rewriting the existing implementation
branch. Before master, close every open requirement in the closeout plan and
qualify the final source, not just this checkpoint's focused tests.
