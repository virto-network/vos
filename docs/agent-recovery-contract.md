# Runtime-independent management recovery binding

This is a semantic contract, not a release plan. Use the [live checklist](agent-saga-status.md)
for remaining work and the [review guide](agent-saga-review.md) for the current
checkpoint. Historical r18 qualification is summarized below with a Git reference;
it must not be read as qualification of later artifacts or current performance.

## Cause and boundary

Before the recovery-query change, `AgentDriver::open_sdk` compared Local management
history with private standard-runtime state only for `STANDARD_RUNTIME_PROGRAM_ID`.
An admitted custom runtime received canonical-envelope and package checks without
the equivalent history comparison. A substituted request commitment could therefore
survive recovery in an otherwise canonical image.

Live signed-request checks do not establish recovery consistency. The host must
not decode each runtime's private state, and a second host-side hash beside the
same unauthenticated history cannot establish guest agreement. Instead, execute a
read-only runtime query at recovery. This is not an extra query on every invocation
or a claim to authenticate arbitrary disk images without their persistence model.

## Semantic commitment

The SDK's `recovery` module supplies a borrowed, bounded projection: retirement
watermark plus all retained consumed management decisions in sequence order.
Each entry binds authority commitment, request replay commitment, epoch, sequence,
original observed slot and exact typed success/error result. Read-only query
results and unconsumed rejections are excluded.

Empty history requires a zero watermark. Above the watermark, authority, request
and epoch are nonzero; sequences and observation slots strictly increase; epochs
do not regress; authority commitments are unique. The ceiling is 256 entries.
Domain-separated seed, entry-chain and final-summary hashes bind runtime ABI,
order, count and watermark. Only one result is encoded at a time. Runtimes may
project their own storage without cloning it or adopting the host's `LMH1` layout.
This helper validates projection shape, not signatures.

## Required recovery behavior

1. `InspectManagementHistory` is authority-free and read-only, with an exact
   fixed-size commitment reply. Supplied authority receipts and foreign Agent or
   runtime scope are rejected. Any ABI change must be explicit, not silently
   accepted by older runtime artifacts.
2. The standard runtime computes the commitment from its retained dispositions.
   The custom-linear example computes it from its own management work/results,
   without importing the host history type or standard-runtime decoder.
3. `open_sdk` executes the admitted runtime against recovered state, requires the
   exact reply and byte-identical successor state, and compares the guest and host
   commitments before exposing the driver. No program-ID exception, native oracle
   or backend fallback may substitute for this comparison.
4. Regressions cover wrong commitment, state mutation, malformed reply, query
   failure, substituted history, exact retry and acknowledged-history recovery.
   Run physical standard and custom guests, not only native/scripted transitions.

## Historical qualification and reproduction

The original implementation source is `a1ebce16`, included in checkpoint `c8028394`
with r18 bundled artifacts. Its physical standard/custom recovery tests, 21 Local
tests, independent artifact reproduction and CLI bundle verification passed.
The ten-second readiness test failed; the debug lifecycle probe was functional
evidence, not production latency or capacity qualification.

The complete historical commands, artifact identities, failed/passing logs and
the related bounded HTTP/Create-envelope regression are preserved at:

```sh
git show 62ffbc20:docs/agent-recovery-contract.md
```

Current recipes are owned by `justfile`: `build-agent-recovery-fixture` builds
the custom scripted guest; `test-local-agent-recovery` builds candidate guests
and runs the Local suite; `test-shared-agent-publication` supplies the singleton
physical publication regression, not the released three-node lifecycle or
external-state qualification. Follow the [review guide](agent-saga-review.md) for disk-backed build
and temporary directories. Rebuild guests for the source/ABI being tested; old
passing logs or native-outer tests are not substitutes for physical qualification.

The scripted custom-runtime feature signs fixed transition tables before package
admission and retains actual management work/results in an opaque envelope.
Nothing is patched after admission. It is a fixture, not an authenticating or
deployable runtime; preserve the independent normal custom runtime as the public
contract example. Shared replay and broader release acceptance retain their own
gates and cannot be qualified by this Local recovery contract alone.

Host-side quorum expiry of a delegated read is separate recovery metadata. It
does not fabricate a guest result or alter this management-history ABI contract;
its integration and qualification status belong to the live checklist.
