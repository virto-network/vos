# Runtime-independent management recovery binding

Status: implementation in progress after checkpoint `1b977731`. The original
physical reopen regression now passes with an explicitly rebuilt r18 candidate.
Do not publish this as a qualified checkpoint until the broader guest/host
coverage, scripted fixtures and bundled artifact reproduction pass together.

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

The fixture uses a separate ELF selected by `AGENT_SCRIPTED_RUNTIME_ELF`, built
with `cargo +nightly-2026-03-20 actor --offline --locked --features scripted-fixture`
inside `examples/agent-runtimes/custom-linear`. Its linker now computes the
read-write base from the page-rounded read-only extent, preserving the required
GP guard zone even with the larger fixture table. `just test-local-agent-recovery`
builds both the standard candidate and scripted guest in separate disk-backed
directories before selecting the complete Local suite. For sandboxed execution,
set `JUST_TEMPDIR` to an existing writable disk-backed directory as well.
The complete fresh-build recipe passes (`recovery-recipe.log`: 21 Local tests).
Rebuilding the ordinary custom runtime with the adjusted linker layout also
passes all 13 tests, including compiled execution (`recovery-custom-normal-final.log`).
All 56 supervisor/adapter tests pass (`recovery-supervisor-final.log`).
No bundled PVM or provenance pin is replaced yet.

The following earlier SDK/helper tests are preparation, not evidence for items 1–5.
Preparation evidence (offline/locked, host `nightly-2025-05-09`): all 170 SDK
tests and all three Local management-history tests pass. Logs are
`recovery-commitment-sdk-full.log` and `recovery-commitment-host.log` under the
shared target's `task-tmp`. These changes remain in the implementation worktree;
the reviewer branch stays at `1b977731` until the integrated batch is ready.
Shared replay, Private control recovery and broader release acceptance retain
their own existing gates; this Local recovery fix cannot qualify them by proxy.
