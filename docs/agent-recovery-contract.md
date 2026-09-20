# Runtime-independent management recovery binding

Status: source committed at `a1ebce16`, integrated after checkpoint `1b977731`.
The original physical reopen regression, broader guest/host coverage and repaired
scripted fixtures pass with rebuilt r18 guests. Bundled bytes and pins are updated
in the implementation worktree; independent reproduction and all 21 bundled Local
tests pass. CLI bundle verification and the disposable debug-binary startup and
lifecycle campaign pass, but the ten-second readiness gate fails. See [current status](agent-saga-status.md)
for the authoritative plan and branch qualification.

## Cause and boundary

Before this change, `AgentDriver::open_sdk` checked Local management history against the
standard runtime's private state only for `STANDARD_RUNTIME_PROGRAM_ID`. Other
admitted runtimes receive canonical-envelope and package checks but no equivalent
history comparison. Recommitting a canonical image with one substituted request
commitment therefore passed reopen with the candidate runtime. Existing signed
request checks on live execution do not establish recovery consistency.

The host must not decode every runtime's private state, and a second hash stored
beside the same unauthenticated history would not establish guest agreement.
Use a read-only runtime query instead. This adds recovery work, not a guest call
to every invocation, and does not claim to authenticate an arbitrary disk image
without the surrounding persistence/trust model.

## Semantic commitment

The portable SDK's `recovery` module provides a borrowed, bounded projection:
retirement watermark plus every retained consumed management decision, in
sequence order. Each entry binds authority commitment, request replay commitment,
epoch, sequence, original observed slot and exact typed success/error result.
Read-only query results and unconsumed rejections are excluded. Empty history
requires a zero watermark. Entries above the watermark have nonzero authority,
request and epoch; sequences and observation slots strictly increase, epochs do
not regress, and authority commitments are unique. The ceiling is 256 entries.

Domain-separated seed, entry-chain and final-summary hashes bind the runtime ABI,
entry order, count and watermark. Only one result is encoded at a time; runtimes
can map their own storage into borrowed entries without cloning their state or
adopting the host's `LMH1` representation. This helper validates projection shape,
not signatures. Local host history now has the corresponding projection method.

## Integration checklist for this work batch

1. Add a canonical read-only `InspectManagementHistory` request and a fixed-size
   commitment reply. Include it in authority-free/read-only classification,
   exact reply validation and unchanged-state enforcement across adapters.
   Bump the clean SDK ABI rather than silently accepting older runtimes.
2. Standard runtime computes the value from its retained dispositions. The real
   custom-linear runtime computes it from its own stored management work/results;
   it must not import the host history type or standard runtime decoder. Queries
   must validate Agent/runtime scope and reject supplied authority receipts.
3. `open_sdk` executes the admitted runtime against the recovered state, requires
   the exact query reply and byte-identical successor state, and compares the
   returned commitment with the host projection before exposing the driver.
   No program-ID exception or native fallback substitutes for this comparison.
4. Update scripted runtime fixtures to answer the explicit query. Exercise wrong
   commitment, changed state, malformed response, query failure and tampered
   history; preserve exact retry and acknowledged-history recovery behavior.
5. Rebuild candidate and bundled artifacts through the existing reproducible
   pipeline. Run physical standard/custom recovery and Local lifecycle suites,
   then the binary compatibility gates. Only afterward advance `saga/agents`.

Items 1–3 are implemented in source with the r18 ABI/control-schema pin. The
candidate standard runtime is built under `task-tmp/recovery-query-runtime`.
`recovery-query-physical.log` records the previously failing physical reopen
test passing. `recovery-query-custom.log` records a native custom-layout query
test covering exact projection, unchanged state, foreign scope and authority
refusal. The compiled custom-runtime gate now includes the query and passes:
all 13 tests, including the explicit compiled-guest test, pass in
`recovery-query-custom-full.log`. All 172 SDK tests pass in
`recovery-query-sdk.log`, and `vosx` checks in `recovery-query-vosx-check.log`.
Golden hashes and the control-schema pin were regenerated for the explicit ABI
change; old-ABI wire rejection remains tested.

The first broader Local run (`recovery-query-local-suite.log`) exposed two old
scripted fixtures lacking recovery history. They are now repaired: all 21 Local
tests pass in `recovery-scripted-local-suite.log`, including positive opaque
lifecycle/reopen, upgrade rejection, and the original substituted-history test.
The test-only `scripted-fixture` feature of the custom runtime executes the same
transition tables but physically retains actual management work/results in an
opaque control envelope. Its query derives the SDK commitment from that history.
Tables occupy a fixed, bounded read-only program region, filled before signing
and package admission. Nothing is patched after admission, and no program-ID
exception or host-native oracle is introduced. This fixture is deliberately
not an authenticating or deployable runtime; the normal custom runtime remains
the independent production-contract example.

The fixture uses a separate ELF optionally selected by `AGENT_SCRIPTED_RUNTIME_ELF`, built
with `cargo +nightly-2026-03-20 actor --offline --locked --features scripted-fixture`
inside `examples/agent-runtimes/custom-linear`. Its linker now computes the
read-write base from the page-rounded read-only extent, preserving the required
GP guard zone even with the larger fixture table. `just build-agent-recovery-fixture`
builds it at the default test lookup path under the selected Cargo target directory;
`build-test-artifacts` includes this prerequisite. `just test-local-agent-recovery`
builds both the standard candidate and scripted guest in separate disk-backed
directories before selecting the complete Local suite. For sandboxed execution,
set `JUST_TEMPDIR` to an existing writable disk-backed directory as well.
The complete fresh-build recipe passes (`recovery-recipe.log`: 21 Local tests).
Rebuilding the ordinary custom runtime with the adjusted linker layout also
passes all 13 tests, including compiled execution (`recovery-custom-normal-final.log`).
All 56 supervisor/adapter tests pass (`recovery-supervisor-final.log`).
Candidate bundled PVM/package bytes and provenance pins now come from the immutable
`a1ebce168605747c876955a299152dd60d18d59a` source export, using an isolated builder
cache. Their presence alone does not establish release qualification.

`recovery-release-reproduction.log` records independent immutable-source rebuilding
of all three artifacts, with exact digest, runtime identity and bundled-byte
comparisons passing. Evidence is also retained under the implementation target's
`agent-release-reproduction/run.VrpljE`. `recovery-bundled-local-suite.log` records
21 passing Local tests with `AGENT_RUNTIME_CANDIDATE_ELF` unset (78.74 seconds),
including substituted-history rejection and physical lifecycle/reopen. These
scoped checks do not establish released end-to-end or performance qualification.
CLI source checks also pass: four bundled-package admission tests
(`recovery-bundled-vosx.log`), 18 release-package tests (`recovery-release-tests.log`)
and three local configuration tests (`recovery-config-tests.log`).
The current debug CLI builds (`recovery-bundled-cli-build.log`) and its `release
bundle` followed by `release verify` passes. The verified output is retained at
`task-tmp/recovery-release.O1sinY/current-bundle` under the shared target. This is
not an optimized released-binary startup or throughput result.

The following earlier SDK/helper tests are preparation, not evidence for items 1–5.
Preparation evidence (offline/locked, host `nightly-2025-05-09`): all 170 SDK
tests and all three Local management-history tests pass. Logs are
`recovery-commitment-sdk-full.log` and `recovery-commitment-host.log` under the
shared target's `task-tmp`. Recovery source is committed on the implementation branch;
the reviewer branch includes the integrated batch described in the current status.
Shared replay, Private control recovery and broader release acceptance retain
their own existing gates; this Local recovery fix cannot qualify them by proxy.

## Physical lifecycle qualification and envelope regression

The first physical Create with r18 hit `CleanFileStoreError::Oversized`: its signed
runtime envelope outgrew independent 1 MiB client-store and HTTP body ceilings.
The fix binds Create/Install storage and exact POST routes to their protocol
envelope bounds. Ordinary routes retain 1 MiB; two process-wide upload permits
bound buffering and execution, including detached blocking work after HTTP
cancellation. Declared oversized bodies are rejected before buffering and streamed
bodies remain bounded. No signature, canonical decoding or Authority check is waived.

Evidence under the shared target's `task-tmp`:

- `r18-http-tests.log`: 52 pass, with `http-ingress` explicitly enabled.
- `r18-clean-cli-network.log`: 105 pass, one existing opt-in daemon test ignored.
- `r18-local-request-tests.log`: three durable/recovery request tests pass.
- `r18-create-envelope-test.log`: bundled signed submission regression passes.
- `r18-static-clean-break.log`: retained CLI/negative-surface check passes.
- `recovery-shutdown-network.log`: unchanged ten-second readiness test fails;
  the test now isolates its blob cache as well as data and configuration.

`r18-lifecycle.1BKWxo/probe-fixed.log` records debug binary SHA-256
`a4da3b143c298bbe4003f48963173cd4ba2184e615212b757997d488db30f25b`:
reopen/readiness 27s, exact pending Create resumed successfully in 54s, fresh Counter
Install in 65s, restart/recovery in 37s, both clean shutdowns under one measured
second. HTTP status and SSH host-key exchange pass. The original failed request
and logs remain in that directory; no operation identity or store was replaced.
This is functional evidence only: invocation was not repeated, the binary is not
optimized, and startup/operation latency remains unsuitable for production.
