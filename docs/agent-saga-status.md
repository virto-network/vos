# Agent saga checkpoint — 2026-09-19

The complete saga is **not finished**. This is a review/test-environment
checkpoint, not production or master sign-off. `saga/agents` remains at
`31b0cdbb`; nothing has merged or pushed.

## What can be tested

Latest source now pins decoded-input validation reuse from immutable
`330274bb139885b61e833bb63768a3024b5b9797`, ProgramId
`ebed0967a4d987e2f50f6e8908b294f713b0cf74583d1b5dc6648a8a542a049c`.
Two isolated ELF/PVM builds match each other and the measured candidate.
Paired exact-output tests use12.6% less fresh-Invoke gas and20.9% less ACK gas
than the preceding bundle. Post-pin release checks18/18 and bundled wire
checks97/1 ignored pass. The real candidate Authority-query test also passes.
Release implementation **`8f96fad8`** builds and verifies its bundled artifacts.
SHA-256: `ee49a636c477c1e3ef21d56f16e2c181307bd1e740ad20bee80b6da27e30e76d`.
Full CLI regression passes255 tests/19 ignored with loopback access. New spaces automatically
receive system packages and enabled HTTP/SSH configuration. The Local workflow
has live evidence for Create, Counter Install, increment, retirement/ACK retry,
and reading7 after restart. Latest release checks HTTP status and SSH listener
availability (not authenticated shell access). Earlier-generation probes cover
host-key persistence and conflict reporting. New-space probes verify fresh
Create (25s) and Counter Install (36s), with no retry/resume.
Fresh Counter increment takes20.04s and read-after-restart20.33s on this release;
value7, positive retirement and exact ACK retries pass. This is Public-policy
qualification, not the remaining Private/Attested proof matrix.
Readiness13s, then19s/26s after restarts, still fails the10s production gate.
All three clean shutdowns completed below1s at the probe's whole-second
resolution, with no forced cleanup. Fresh fixture: `current-latency.coTfCk`.
Older fixtures must stay with their original pins. The post-repin default-library
suite passes 1,434 tests, zero failures, one ignored in 195.71s. The post-repin
host-feature regression is running; its previous success remains historical.

Use disposable spaces only. Do not migrate valuable older-generation stores.
Preserve failed operations and exact request bytes; a timeout or unsigned HTTP
error does not prove failure. Retired historical Create replay after Install
returns409; retention is bounded, not indefinite server reply caching.

## Review organization

Keep two scoped batches, not one review per work-in-progress commit:

1. `31b0cdbb..f79f0e3d`: integrated clean-break architecture/lifecycle.
2. `f79f0e3d..8f96fad8`: recovery, performance, artifact and qualification follow-ups
   (48 files, +4,946/-258 at this frozen checkpoint).

The integrated diff remains large (234 files, +77,744/-58,997 at `8f96fad8`).
These are review groupings, not independently deployable slices. Subsequent
review-handoff documentation and disposable-fixture test updates belong with batch2. The old C1 boundary
is not independently merge-ready.
See [review guide](agent-saga-review.md) and [evidence handoff](agent-saga-handoff.md).

The qualified implementation is a review/disposable Local-space checkpoint,
not production/master sign-off.
The post-`36e63581` uncommitted Shared-finality experiment has been removed:
it depended on legacy embedded authority state absent from clean Create. Its
failed test and patch are preserved in the evidence directory; see the handoff.
The review and built release checkpoint is now `8f96fad8`. Ordinary Shared finality needs clean
system-authority actor integration, not a switch to the legacy replay helper.
No merge or push is authorized by this checkpoint. Fresh Create/Install/invocation
have now been measured, but not as a controlled before/after comparison.
Preserve original fixture paths and failure evidence. When implementation
resumes, address authenticated inventory
with bounded equivalence/recovery checks and repeat release qualification.

## Remaining production work

| Requirement | Current evidence / gap |
| --- | --- |
| Startup and operation latency | Current-release fresh readiness13s, restarts19s/26s;10s gate fails. Fresh Create25s, Install36s, managed increment20.04s and read-after-restart20.33s. |
| Recovery performance | With8-entry scheduling, second pass system owner8.02s, including14 runtime calls6.39s. Shorter history helps; not a same-history A/B. |
| Inventory performance | Two agents require six sequential authenticated queries. Current fresh Create lifecycle8.06s is followed by route reconciliation14.08s (inventory13.85s); post-Install inventory15.68s. Inventory still materially delays operation completion. |
| Shutdown | Latest disposable probes report0s at whole-second resolution and no forced cleanup; general busy/crash matrix still incomplete. |
| Ordinary Shared genesis/finality | Native startup still installs `UnavailableAgentFinality`; ordinary `AgentGenesisProvider` has no implementation/caller in current Rust sources. Production archive/issuance plus authenticated replay-backed finality integration are missing, not just a verifier switch. System genesis is a separate path. |
| Authenticated reclamation | Issuer/coordinator bounded-record reclamation remains unfinished; invocation retirement is not proof of Authority application. |
| Recovery/proof qualification | Remaining mixed pending/crash/capacity cases, pre-expiry Abort/management expiry, cross-runtime portable positive ACK, and full Private/Attested cryptographic proof matrix. |
| Formatting | Pinned-host formatting passes, including after decoded-input validation reuse. No lint allowances added. |
| Workspace lint | At7b45d2f0, the `check-all` Clippy flags fail in vos with351 diagnostics (258 unused/dead-code,1 unused-mut,92 others). Downstream workspace lint completion is unproven; no broad lint allowances added. |
| Cutover supporting gates | At7bc52924, system-authority58/58 and system-catalog10/10 tests pass; SDK no-default-feature intra-doc-link check and static clean-break CLI/docs check pass. Atcda6c997, SDK165/165 tests and vos no-default-feature library check pass. These do not substitute for the entire `just clean-break-check` or `just check-all` recipes. |
| Release integration | At8f96fad8: release build/bundle and fresh Local lifecycle pass; CLI255/19 ignored, release18/18 and wire97/1 ignored pass. Post-pin default library1,434/1 ignored passes at ea13d293 with unchanged runtime source. Post-pin host-feature suite is running; prior-pin1,873/3 ignored remains historical. Prior-pin actor-build4/task-build1 pass atcda6c997. Full cryptographic proof qualification and remaining sign-off stay open. |

The post-pin `scripts/check-agent-clean-break.sh` gate also passes: retained CLI,
removed compatibility surfaces/paths, and selected operator documentation.
This does not establish the full `just clean-break-check` recipe or workspace lint.
Post-pin supporting gates also pass: system-authority 58/58, system-catalog
10/10, and SDK no-default-feature documentation with broken intra-doc links denied.
These do not qualify all examples/external links or host issuer reclamation.

Next verification is completion of the full host-feature regression on the new pin.
Performance work must remain focused on the14–16s authenticated two-agent
inventory. Exact-binary profiling identified outer BLAKE2b cost, leading to
the now-released decoded-input validation reuse. Paired gas savings are proven;
the different live fixtures do not establish a controlled end-to-end speedup.
Create improved in this observation, but Install and managed operations remain
slow. Preserve complete-head authentication, recovery and positive ACKs;
do not lower safety/retention bounds or publish readiness before recovery.
