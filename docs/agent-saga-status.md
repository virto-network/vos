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
wrappers. Removed wrappers had no remaining callers. Its regression checks cross-Agent refusal
and that surviving cloned handles cannot retain the physical host after shutdown.
The native-outer regression passes in 46.77s
(`shared-generation-route-handle-lifetime-fixed.log`). The initial boxed test-value
compile failure remains in `shared-generation-route-handle-lifetime.log`.
Workspace formatting and diff checks pass. The physical route-handle recipe
passed in 768.14s (`shared-generation-route-physical-recipe.log`). It started
before the adapter below and does not qualify that adapter or production wiring.
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

### In-progress production integration — not qualified

**Current:** candidate completed-retirement restart passes after actual publication
ACK pruning, including refusal of premature retirement and recovery after read
ACK/record-clear interruption (94.09s). The earlier bundled startup pass covers
real bootstrap, interrupted Create finalization, root-directory validation,
production readiness and host release (109.09s). Installed-actor serving and full
physical/released lifecycle qualification are still being checked.
Latest bundled native-outer scenario now also installs an executable ordinary
actor through signed authorization/finalization, invokes and ACKs it through
the production supervisor, and invokes/ACKs it again after both restarts:
1 pass, 103.89s (`shared-genesis-query.L6OPEp/ordinary-serving-restarts-fixed.log`).
The initial serving-only pass was 102.78s (`ordinary-serving-fixed.log`);
initial test compile errors are retained in `ordinary-serving-test.log` and
`ordinary-serving-restarts.log`. Subsequent lifecycle issuer continuation in this
fixture uses an immutable genesis checkpoint; it does not qualify a released
Shared Install coordinator or CLI.
The full physical recipe is running (`full-physical-checkpoint.log`). Fresh
regressions in that same directory: supervisor 56 pass/0.06s, production owner
18 pass/0.29s, release CLI 18 pass/1.03s. Formatting/diff checks pass.
The diagnostic sequence below is historical evidence, not additional active plans.

On top of `c8656196`, uncommitted production wiring reconciles the complete
ordinary generation set, replaces stale handles on reattachment, and retains
lifecycle/archive leases until routes drain. The actual lifecycle-owned startup
regression fails: the recovered Shared Create still holds management admission,
so authenticated route publication correctly remains unready. Physical genesis
recovery alone does not complete the signed Create lifecycle.

Next, add durable Shared application observation, issuer application ACK,
Authority finalization and positive retirement through the existing management
contract. Preserve exact crash/retry recovery and the admission guard; do not
clear the reservation merely to make startup ready.

Evidence: `shared-production-generation-registry.log` fails at the readiness
assertion after 46.94s. All 20 existing production-owner regressions pass in
0.63s (`shared-production-owner-regressions.log`), but do not cover this missing
Shared lifecycle completion. This is not a review-ready checkpoint.

The first completion primitive now observes initial Create from the opened
Shared driver's authenticated replay evidence, bound to the exact genesis
input, request, receipt, sequence and original slot. It never decodes private
runtime state or treats archive bytes as application evidence. Its regression
rejects missing physical generations and substituted requests/receipts, and
preserves the observation after reopening with a later clock: 1 pass, 0.51s
(`shared-genesis-application-observation-fixed.log`; initial compile typo retained
in `shared-genesis-application-observation.log`). The physical custom-runtime
management regression also passes (1.38s,
`shared-genesis-application-custom-runtime.log`), including refusal to substitute
a later management mutation for initial Create evidence.

The primitive is now connected to issuer acknowledgement, Authority finalization
and original Create retirement after physical recovery. Recovery validates and
retains interrupted application/finalization phases; saved finalization work is
also preserved when rebuilding the publication-phase admission snapshot.
Completion invalidates that snapshot before writes, forcing store reopening
after an ambiguous failure.

The first completion run reached the old no-new-journal-entries assertion:
finalization and its two positive ACKs correctly add three entries
(`shared-production-create-completion-fixed.log`, 51.14s, failed assertion).
The next run exposed restored committee/publication reservations still holding
admission (`shared-production-create-retirement.log`, 50.73s). Their cleanup now
independently requires durable positive ACK evidence at the network boundary.
The expanded interrupted-finalization test now passes the crash/reopen boundary,
three-entry completion assertion and admission-released assertion, then fails
later at production startup with `ProjectionTransport` (53.63s,
`shared-production-interrupted-finalization.log`). The next immediate diagnostic
is the underlying authenticated inventory transport error, not the now-passing
admission guard. This failed full test is not a qualification pass.
The build check passes; workspace formatting passes after the latest edits.

Inventory follow-up: the new test incorrectly used a scripted API credential;
it now uses the bundled fixture's enrolled SSH credential and node attestation.
That correction alone still fails (52.38s, `shared-production-enrolled-inventory.log`).
Opt-in diagnostics expose a bundled Authority guest stack fault, not merely a
transport failure: PC 707122, fault address `0xfefcf000`, SP `0xfefcfba0`, below
the guest stack base `0xfefd0000` (`shared-production-inventory-guest-fault.log`,
52.05s). Exact ELF/PVM reproduction maps it to `decode_agent_identity`'s stack
write, called by `decode_management_request` (`shared-inventory-pc-map.log`,
1 diagnostic pass, 1.21s). Inventory validation re-decodes retained genesis
records; source inventory tests cannot establish guest stack safety.

A candidate separating inventory authentication from page construction still
faulted at the same stack boundary (53.20s). That ineffective source split was
removed. Candidate evidence is retained in `shared-inventory-candidate.Jcfgpx/`;
no bundled bytes or release pins changed. Next investigate nested decoder frame
overlap, preserving wire validation and stack limits. Two standalone source
inventory tests passed in 2.04s and all 20 production-owner regressions passed
in 0.21s (`shared-inventory-frame-source-tests-standalone.log`,
`shared-inventory-frame-owner-regressions.log`); neither resolves the guest fault.

At the preceding startup pass, completed-retirement records were still rejected
by the Shared recovery loader.
Safe reopening after retirement, including history-pruning boundaries, remains
mandatory before checkpoint qualification. Do not ship the partial completion
path or bypass live-history verification to make that restart pass.

Follow-up in progress: retired records now require matching finalized issuer
evidence and preserve bootstrap-history requirements without reserving old
journal anchors. Recovery compares a fresh pinned-Authority `genesis_decision`
result with the exact archived decision before opening the generation. The first
forced-checkpoint regression failed (`shared-retired-read-test.log`, 82.50s):
the existing read-only method was declared Linear, incompatible with the safe
Query checkpoint path. Its source declaration and context validation are being
corrected to Query; the host does not permit arbitrary Linear projection replay.
Pending read records use PAP2 and distinguish ingress-authenticated inventory
from the public genesis read, binding target, agent, nonce and exact invocation.
Candidate evidence: `shared-genesis-query.L6OPEp/retired-restart-test.log`
(97.58s) and `retired-read-crash-test.log` (94.09s), both pass. The latter also
rejects a premature CMR2 marker without finalized issuer evidence and reopens
after a durable read ACK with failed pending-record clear without duplicate
Invoke/ACK. Envelope target/nonce/mode substitution test: 1 pass, 2.29s
(`shared-genesis-read-envelope-fixed.log`; initial test mutation typo retained
in `shared-genesis-read-envelope-tests.log`). Existing pending projection
regressions: 2 pass, 4.07s (`shared-genesis-query.L6OPEp/projection-regressions.log`).

Authority source tests: 75 pass, 2 ignored, 52.29s
(`shared-genesis-query-source-tests.log`); expanded read-context refusals pass
in 0.75s (`shared-genesis-query-negative-source.log`). Source correction is
`c5e751e7bc7992782bf7403f73b254c64e5c26c6`. Independent reproduction in
`target/agent-release-reproduction/genesis-query.MxmejS/` matches candidate PVM
and package bytes; Catalog is unchanged. The latest bundle/source/hash pins are
updated but uncommitted. Fresh spaces only: PAP2 and package identity changes
are not qualified old-store migration.

Latest decoder candidate: boxed management variants now decode in separate
non-inlined frames. The dispatch decoder's generated frame decreases from
10,632 to 232 bytes (selected variants still have their own frames). SDK tests:
182 pass (`shared-decoder-sdk-tests.log`); standalone Authority: 75 pass,
2 ignored, 37.45s (`shared-decoder-authority-source-tests.log`). Candidate evidence:
`shared-decoder-candidate.bmL0nN/`, including disassembly and built templates.
Its initial startup regression passed the former guest fault and failed later with
`InvalidSystemAgent` (54.91s, `startup-test.log`). The authenticated system/root
projection failure is now resolved as follows.

The old fixture physically installed system actors but synthesized bootstrap
completion without invoking Authority Catalog finalization. Consequently its
authenticated actor directory was empty. The scenario now uses real bootstrap
and asserts exactly one authenticated root actor before production startup.
The fixture advances its logical clock at durable bootstrap phase boundaries;
without this, the unchanged runtime correctly rejects same-slot mutations with
`AuthoritySequenceConflict` (`real-bootstrap-denial.log`, 1.26s).
The corrected full candidate regression passes: 1 test, 85.54s
(`shared-decoder-candidate.bmL0nN/real-bootstrap-clock.log`). This uses native
outer execution and real Authority PVM execution, not the full outer-PVM recipe.
Formatting and diff checks pass. Decoder source is committed at
`cb3f48b8e466a358e4e36c45d8429aeb51205efb`; independent reproduction under
`target/agent-release-reproduction/management-decode.KuU7Kf/` matches both PVMs
and signed packages byte-for-byte. Catalog is unchanged. The Authority bundle
and source/digest pins are updated. The default bundled startup regression passes
without a candidate override: 1 test, 109.09s
(`shared-decoder-candidate.bmL0nN/bundled-real-bootstrap.log`). This is still native
outer execution, not complete released-node qualification.
All three existing Shared-controller regressions
pass in 3.94s (`shared-decoder-candidate.bmL0nN/controller-regressions.log`).
All 18 release CLI tests pass in 1.05s (`shared-decoder-candidate.bmL0nN/release-cli.log`),
including exact bundled pins and byte-reproducible packaging. Artifact integration
is committed at `cffffd2c`; production integration remains uncommitted pending
the remaining lifecycle gates. `saga/agents` is unchanged at `9cd2fa6a`.

### Next reviewer handoff — finish pending work first

The user selected completion of the pending functional batch before another
review, not an intermediate source-only handoff at `c8656196`. Keep `saga/agents`
at `9cd2fa6a` until production startup/system-root audit, completed-retirement
restart/pruning, installed ordinary actor serving and reproduced artifacts pass.
Then review the delta in two groups: qualification/performance/discovery; and
Shared lifecycle/recovery/ownership/artifacts. Identify `ac1b2860` separately as
mechanical formatting. Do not fold backup, additional profiles or a new scaling
redesign into this checkpoint; they remain full-saga gates below.

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
- System template source: `c5e751e7bc7992782bf7403f73b254c64e5c26c6`.
- Template builder: `3c5e44c769d4cc16c1c13a9949c60a154f378a57`.
- Independent Authority/Catalog packages match the genesis Query candidate
  byte-for-byte. Evidence:
  implementation `target/agent-release-reproduction/genesis-query.MxmejS/build.log`.
- Runtime bytes, ProgramId and ABI did not change with the template repin.
  The root review checkpoint still uses its earlier templates.
- Use fresh disposable spaces. Changed package identities do not qualify
  old-store migration, relocation or backup/restore.

## Next coherent batch

1. Complete the recovered Shared Create application/ACK/finalization/retirement
   sequence and make the production startup regression pass. Qualify per-generation
   replacement and shutdown while retaining one network owner and lifecycle leases.
2. Qualify installed-actor Invoke/Resume/ACK through the generation adapter,
   including retirement, stale-generation refusal and independent-Agent dispatch;
   complete signed Shared creation through the lifecycle/CLI.
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
