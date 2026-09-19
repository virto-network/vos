# Agent saga checkpoint — 2026-09-19

The complete saga is **not finished**. This is a review/test-environment
checkpoint, not production or master sign-off. `saga/agents` remains at
`31b0cdbb`; nothing has merged or pushed.

## What can be tested

Latest source now pins the independently reproduced artifact-role length
optimization from `19d73390`, ProgramId
`e61dc1dacd564ac9371512eaaf9d35ad8f1e081f8e3b638ca9da9425e887e86b`.
Paired synthetic tests show20.1% less fresh-Invoke gas with identical complete
output. Two isolated ELF/PVM builds match each other and the measured candidate.
Release rebuild, fresh Local lifecycle/restart qualification and the full CLI
suite pass. Full post-pin default-library regression passes1,434 tests/1 ignored;
host-feature regression remains pending. Do not boot older fixtures with the
new pin. See the handoff for evidence.

Release implementation `b16abf81` builds and verifies its bundled artifacts.
SHA-256: `e76cf5428ebc443ec7cc6859c162ee7b9ec67e5fb03706b2ee9798051fa84106`.
The runtime is independently reproduced; new spaces automatically
receive system packages and enabled HTTP/SSH configuration. The Local workflow
has live evidence for Create, Counter Install, increment, retirement/ACK retry,
and reading7 after restart. Latest release checks HTTP status and SSH listener
availability (not authenticated shell access). Earlier-generation probes cover
host-key persistence and conflict reporting. New-space probes verify fresh
Create (30s) and Counter Install (36s), with no retry/resume.
Fresh Counter increment takes20.71s and read-after-restart19.90s on this release;
value7, positive retirement and exact ACK retries pass. This is Public-policy
qualification, not the remaining Private/Attested proof matrix.

Use disposable spaces only. Do not migrate valuable older-generation stores.
Preserve failed operations and exact request bytes; a timeout or unsigned HTTP
error does not prove failure. Retired historical Create replay after Install
returns409; retention is bounded, not indefinite server reply caching.

## Review organization

Keep two scoped batches, not one review per work-in-progress commit:

1. `31b0cdbb..f79f0e3d`: integrated clean-break architecture/lifecycle.
2. `f79f0e3d..b16abf81`: recovery, performance, artifact and qualification follow-ups
   (40 files, +3,862/-216 at this frozen checkpoint).

The integrated diff remains large (231 files, +76,679/-58,974 at `b16abf81`).
These are review groupings, not independently deployable slices. Subsequent
review-handoff documentation and disposable-fixture test updates belong with batch2. The old C1 boundary
is not independently merge-ready.
See [review guide](agent-saga-review.md) and [evidence handoff](agent-saga-handoff.md).

Freeze implementation here for review and disposable Local-space testing; do
not start another guest/artifact change merely to fill the remaining budget.
No merge or push is authorized by this checkpoint. Fresh Create/Install/invocation
have now been measured, but not as a controlled before/after comparison.
Preserve original fixture paths and failure evidence. When implementation
resumes, address authenticated inventory
with bounded equivalence/recovery checks and repeat release qualification.

## Remaining production work

| Requirement | Current evidence / gap |
| --- | --- |
| Startup and operation latency | Current-release fresh readiness15s, restarts19s/24s;10s gate fails. Fresh Create30s, Install36s, managed increment20.71s and read-after-restart19.90s. |
| Recovery performance | With8-entry scheduling, second pass system owner8.02s, including14 runtime calls6.39s. Shorter history helps; not a same-history A/B. |
| Inventory performance | Two agents require six sequential authenticated queries. Current fresh Create lifecycle9.62s is followed by route reconciliation16.93s (inventory16.68s), so inventory still materially delays operation completion. |
| Shutdown | Latest disposable probes pass within1–2s; general busy/crash matrix still incomplete. |
| Ordinary Shared genesis/finality | Native startup still installs `UnavailableAgentFinality`; ordinary `AgentGenesisProvider` has no implementation/caller in current Rust sources. Production archive/issuance plus authenticated replay-backed finality integration are missing, not just a verifier switch. System genesis is a separate path. |
| Authenticated reclamation | Issuer/coordinator bounded-record reclamation remains unfinished; invocation retirement is not proof of Authority application. |
| Recovery/proof qualification | Remaining mixed pending/crash/capacity cases, pre-expiry Abort/management expiry, cross-runtime portable positive ACK, and full Private/Attested cryptographic proof matrix. |
| Formatting | Pinned-host `cargo fmt -- --check` atb437af09 fails:40 diff locations across15 files; `--all` reports the same output. No formatting applied while the host-feature suite runs. |
| Cutover supporting gates | At7bc52924, system-authority58/58 and system-catalog10/10 tests pass; SDK no-default-feature intra-doc-link check and static clean-break CLI/docs check pass. These do not substitute for the entire `just clean-break-check` or `just check-all` recipes. |
| Release integration | Current-pin CLI atb16abf81:255 passed/19 ignored; default library at02dbc8c6:1,434 passed/1 ignored. Last full host-feature library atbf7ced06:1,871 passed/3 ignored predates the latest pin; the new run remains pending. Actor-build4/task-build1 baseline also predates repin. Startup still fails10s. Full cryptographic proof qualification and remaining release audit/sign-off stay open. |

Next performance step: address the roughly17s authenticated two-agent inventory.
Released checkpoint scheduling now triggers at8 retained physical entries;
safety tests, the complete514-query workload and two live restart passes succeed.
Observed periodic reconciliation3.71s/3.57s is not a broad throughput proof. Do not
lower safety/retention bounds, omit replay, or publish readiness before recovery
to meet a latency number. Any scheduling change must prove exact recovery and
measure both restart and steady-state cost. The other gates remain in scope.
