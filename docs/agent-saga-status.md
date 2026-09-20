# Agent saga: current status

This is the single authoritative plan and qualification index. The objective
remains the complete Agent Architecture Saga, not just the next checkpoint.

## Branches and review boundary

- Reviewer: `saga/agents` at `9cd2fa6a`; use [review guide](agent-saga-review.md).
- Implementation: `wip/ch08-runtime-directory` in
  `.worktrees/ch08-runtime-directory`. Apply reviewer feedback here.
- Master is unchanged; nothing is pushed. Advance the review branch only at a
  qualified checkpoint, with its exact source/artifact/test boundary.
- Released ordinary Shared serving, backup, other profiles, production scaling
  and workspace lint remain incomplete. Disposable Local evidence is not
  production or old-store migration qualification.

## Latest implemented milestones

1. `d3e744b2` bundles the independently reproduced Authority publication stack
   fix from source `26f8f004`. The decoder releases its large nested scratch
   frame before validation; no stack/gas limit or validation is relaxed.
2. `efd0f5ca` adds owner-authenticated ordinary Shared provisioning and nonempty
   recovery. Exact live publication replay plus positive ACK establishes finality;
   decoded archives alone do not. The proof applies only to the requested
   generation and does not replace the host's default verifier.
3. The same batch scopes system route discovery/auditing to its independently
   pinned generation. A physical host may now contain ordinary generations
   without invalidating the system-only projection. Generic Shared audits still
   require a complete physical set.
4. Production startup already discovers and retains Shared lifecycle/archive
   leases, opens the system first, and recovers deferred generations before
   publishing routes. Ordinary CLI creation and supervisor serving are **not**
   wired end to end. Opening a physical generation does not make it callable.

### Current supervisor integration

Implementation follow-up extracts exact-generation supervisor access from the
existing Shared coordinator. A handle keeps a weak coordinator reference between
operations; execution retains the existing lifecycle lease, fingerprint,
authorization, request and lane checks. It does not hold the system lifecycle
owner mutex while waiting for an invocation. This avoids adding that extra
cross-Agent lock; physical host-wide locking still exists and is not qualified
as scalable.

The common execution path replaces unused terminal/reserved/ordinary dispatch
wrappers. Removed wrappers had no remaining callers. The new handle is not yet
installed by the production supervisor. Its regression checks cross-Agent refusal
and that surviving cloned handles cannot retain the physical host after shutdown.
The native-outer regression passes in 46.77s
(`shared-generation-route-handle-lifetime-fixed.log`). The initial boxed test-value
compile failure remains in `shared-generation-route-handle-lifetime.log`.
Workspace formatting and diff checks pass. The physical route-handle recipe
(started before the adapter below) is running in
`shared-generation-route-physical-recipe.log`; collect its terminal result before
claiming physical qualification of this extraction.
All eight Shared network tests pass in 0.34s
(`shared-generation-route-network-suite.log`).

The subsequent generation-specific adapter implements Invoke, Resume, ACK,
preparation and complete per-generation Authority auditing. It uses the existing
inline per-Agent backend, not an extra idle thread per Agent. Ordinary audits
explicitly reject the physical system-bootstrap generation, even if a projection
strips root-provenance flags from otherwise matching actors. The initial
worker-backed adapter test passed in 54.04s and its added root-scope test passed
in 55.93s (`shared-generation-supervisor-adapter.log`,
`shared-generation-supervisor-root-scope.log`). These are native-outer tests of
an actor-empty ordinary generation, not an actor-serving campaign.

The inline form passes in 56.02s (`shared-generation-inline-adapter.log`), and
all four existing inline-retirement/panic regressions pass in 0.01s
(`shared-generation-inline-retirement.log`). Formatting/diff checks pass.
These adapter checks are native-outer, not a current physical-recipe pass.
Production ownership must still
reconcile the complete ordinary generation set, replace stale generation handles
on reattachment, and retain lifecycle/archive leases until routes drain.

## Current evidence and limits

Logs below are under `.worktrees/ch08-c2-native/target/task-tmp/`.
Counts are scoped results, not an additive release total.

| Scope | Result | Evidence / limitation |
| --- | --- | --- |
| Bundled publication, native outer runtime | 1 pass, 36.02s | `shared-stack-bundled-publication.log`; before ordinary provisioning |
| Release CLI validation | 18 pass, 1.16s | `shared-stack-release-cli-tests.log` |
| Bundled Inventory with real outer PVM | 1 pass, 23.06s | `shared-stack-physical-inventory-test.log` |
| Full physical publication/retry boundaries | 1 pass, 510.61s | `shared-bundled-full-physical-publication.log`; before nonempty recovery |
| Strict nonempty recovery, native outer | 1 pass, 53.91s | `shared-owner-nonempty-recovery-strict.log`; archive-only finality refused |
| Nonempty recovery plus scoped system routes, native outer | 1 pass, 63.59s | `shared-owner-scoped-system-recovery-fixed.log` |
| Root-forgery refusal after scoped audit change | 1 pass, 2.48s | `shared-owner-scoped-system-root-refusals.log` |
| Shared host suite after scoped audit change | 23 pass, 1 opt-in ignored, 242.86s | `shared-owner-scoped-host-suite.log` |
| Real-PVM provisioning and nonempty recovery recipe | 1 pass, 783.51s | `shared-owner-nonempty-physical-recipe.log`; started before the scoped-system follow-up |

These runs precede the route-handle extraction. The real-PVM nonempty run does
not cover the subsequently added system-route assertions. Neither long physical
test duration is a single-operation latency measurement: both repeat many fault,
retry and replay boundaries.

The native retry test deliberately compares durable generation, route identity
and runtime state, not volatile attachment status or the mandatory Raft leader
initialization entry. Restart bootstrap runs on a normal separate thread, like
initial bootstrap, to avoid retaining the large fault fixture's caller frame.
No thread-stack limit was increased.

Run `just test-shared-agent-publication` for the expanded physical gate. Set
`JUST_TEMPDIR` to an existing disk-backed directory before invoking it; select a
disk-backed `CARGO_TARGET_DIR`. The recipe clears the candidate-runtime override.
Its current source includes more assertions than the completed 783.51s run.

### Artifact boundary

Exact pins remain in `support/production-artifacts.toml` and `vosx/build.rs`.

- Standard runtime source: `2ccfacb82089f804dbdbfea7ebfcabf377e7dde3`, ABI r19.
- System template source: `26f8f0046d96713bc7d778855f8bd278c8f1ff83`.
- Template builder: `3c5e44c769d4cc16c1c13a9949c60a154f378a57`.
- Independent Authority/Catalog PVMs and signed packages matched the first
  candidate byte-for-byte. Evidence:
  implementation `target/agent-release-reproduction/stackfix.ieuhLw/build.log`.
- Runtime bytes, ProgramId and ABI did not change with the template repin.
  The root review checkpoint still uses its earlier templates.
- Use fresh disposable spaces. Changed package identities do not qualify
  old-store migration, relocation or backup/restore.

## Next coherent batch

1. Qualify installed-actor Invoke/Resume/ACK through the generation adapter,
   including retirement, stale-generation refusal and independent-Agent dispatch.
2. Connect recovered ordinary Shared generations to supervisor ownership and
   complete signed Shared creation through the lifecycle/CLI. Keep one network
   owner and retain lifecycle/archive leases through worker retirement.
3. Run the current physical recipe, complete negative/missing/substituted
   publication and interrupted-write cases, then a released
   create/replicate/restart/recovery campaign. Do not substitute archive-only
   acceptance or a permissive finality verifier.
4. Reconcile source/artifact identities and broad regression gates, update the
   review guide, and advance `saga/agents` only to the qualified checkpoint.
5. Continue all full-saga gates below. This functional batch does not narrow
   the objective or silently expand into a separate performance redesign.

## Performance and broader gate status

The previous optimized Local campaign passed all four ten-second readiness
checks, but Create/Install still took about 15.6/19.7 seconds. That historical
single-user result is not current-artifact or throughput qualification.

Debug attribution found physical VM execution larger than preparation cost.
Fresh terminal verification was present on Create/Install and absent from the
ordinary mutation/read campaign. Do not optimize it expecting to solve that
separate request path. Whole-state ABI transport/restoration/publication, replay,
maintenance isolation and Shared host-wide locking remain open concerns.

Historical broad gates passed at their recorded sources: default workspace
library tests (2,406), CLI binary tests (271, 20 opt-in ignored), Private crypto
tests (16), clean-break checks, workspace formatting and all-target checking.
They are not fresh release gates for current source. Workspace Clippy failed at
`ac1b2860` with 358 diagnostics, including 279 unused-item diagnostics. Incomplete
profile integration is not evidence that those components should all be deleted.

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

## Historical evidence and housekeeping

The full 710-line chronological status, failure logs, exact earlier binary
identities and campaigns are preserved at
`efd0f5ca:docs/agent-saga-status.md` (retrieve with `git show`).
That snapshot's pending-run statements are historical; terminal results above
supersede them only for the named source/test scope.

Earlier inventories remain at `9fe6762e`; r19 review status at `7bd66a7d`;
r18 at `c8028394`; original handoff/review journals at `a1ebce16`.
The other handoff documents are navigation or checkpoint evidence, not competing
plans. Keep new current results here; consult Git for old chronological detail.

No frozen clients, failure bytes, stores or logs were deleted by this compaction.
Keep scratch disk-backed, not RAM-backed `/tmp`. Remove obsolete code only after
checking callers, feature gates and replacement coverage. Never infer completed
release gates from warnings disappearing or a smaller test subset passing.
