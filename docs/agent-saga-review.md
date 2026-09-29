# Agent saga: review entry point

This is the sole reviewer handoff. [The live checklist](agent-saga-status.md)
owns release scope and deferred work. Review read-only; return findings for the
implementation branch rather than applying competing fixes on the review branch.

## Checkpoint boundary

| Purpose | Branch / boundary |
| --- | --- |
| Reviewer target | `saga/agents`; review the custody batch with `git diff 7c850160..saga/agents` |
| Implementation | `wip/ch08-runtime-directory`, synchronized at this checkpoint; apply later findings here |
| Review scope | One bounded pending-read custody batch; candidate fixtures qualified, production gates unchanged |
| Mainline | `master` remains `d2378274`; no automatic push or mainline change |

Verify branch heads and working-tree status before reviewing. Candidate tests or
document changes do not establish publication to `saga/agents`. Production
multi-node startup/public Shared management and pruning remain gated; Local
stays image-based. This is not release or throughput qualification.

## Current batch: pending-read custody across checkpoints

The previous checkpoint preserves a boundary Query and supports authenticated
pruned-prefix catch-up. That does not protect an offline origin whose uncleared
PAP2 still needs an older Invoke/result/positive-ACK sequence. Guest ACK removes
retained results; an empty local pending directory cannot justify pruning.

The follow-up uses at most three slots, one per physical pending-record owner in
the fixed committee. Each signed registration binds generation, full committee,
monotonic owner sequence, exact completed predecessor, signed query, and original
work/preflight/artifacts. PAP2 is an unadmitted WAL intent: recoverable admission
requires the exact registration to be applied through Raft.

Physically validated Invoke and positive ACK evidence enrich a slot. The owner's
next signed registration replaces only its own completed slot after durable local
cleanup. Keeping the completed slot avoids a separate release round per read.
Forwarding followers retain their own delivery obligation. Several owners may
hold the same read; this slice allows only one distinct unfinished delegated
read per system Agent.

Custody is not execution authority. Original signatures/material, fresh delegated
admission, physical execution provenance and exact retry remain mandatory. A
losing, unadmitted local WAL stays intact while its node finishes another admitted
request from shared custody. Legacy reads and management/GenesisDecision remain
outside this protocol; expired-unseen cancellation is not implemented. Production
emitters still use legacy reads. This host-only batch repins no guest artifacts.

### Review focus

- AGC2 authenticates the exact manifest; AGC1 semantics stay unchanged. ACB2
  carries the certified baseline, never a newer live manifest. ASR4 retains
  baseline custody and typed metadata boundaries.
- Common authority remains distinct from each node/store's physical binding.
  Catch-up requires independent genesis/full-intent validation, exact scope,
  rollback/raw-suffix refusal and higher-term/full-vote preservation.
- Live evidence derives from exact applied registration/Ordered rows and
  independently validated execution, or the installed certified baseline.
  Slot decoding or an owner's signature alone proves no result.
- PAP2/PPR1 cleanup, registration retry, follower delivery and competing-WAL
  help retain exact reservation ownership through leadership changes.
  Neither expiry nor local absence releases custody.
- A legacy Invoke or positive ACK cannot acquire its first custody slot afterward.
  A racing signed local intent remains byte-identical while a proposal-locked,
  quiescent applied-prefix check proves exact legacy recovery. This is not custody
  admission; normal positive-ACK cleanup is still required. Existing same-request
  custody still requires every delivery owner's hold.
- Preparing manifest updates outside the database writer requires exact
  predecessor comparisons inside atomic publication. Preserve physical-row,
  reservation, committee, cursor and worker-metadata checks. Never refold a
  historical duplicate into a newer owner slot.
- Candidate construction reuses one fresh audited read view within a call;
  post-peer-I/O validation stays fresh. Empty Merge frontiers skip no-op import
  locking; nonempty imports retain every existing guard.

### Qualification status

The final default-release run passes all **16 physical fixtures**: four new
custody cases, four previous common checkpoints, six previous delegation cases,
and two signed-intent/legacy-execution races. Custody covers offline-origin
discovery, post-ACK/pre-cleanup recovery, follower delivery, and competing
unadmitted WALs.
The first three include three checkpoint/import cycles and source/destination
Marker, Journal and Ledger crash boundaries.

Qualification caught and fixed a legacy compatibility regression: adding first
custody after a legacy Invoke left its later ACK without Invoke evidence. Both
reopen orderings now pass. Two additional races persist signed intents before
legacy execution, then prove recovery without a new Invoke, incomplete custody,
or premature WAL cleanup. Existing same-request custody still requires each
delivery owner's hold. Earlier failing evidence remains in
`recovery-slots-release-delegation3.log`; it is not counted as qualification.

Final source-specific evidence; logs are in the shared target. The default-release
build (`recovery-slots-release-tests-build4.log`) passed in 13m27s. Physical fixtures
are not full outer-PVM, released-daemon, load or general release qualification.

| Check | Evidence |
| --- | --- |
| Final exact-release focused units | 238 passed, 4 existing ignored across manifest, certificate, ledger, driver, protocol, network, routes, host, journal, replay, PAP trailer, cache bound, empty-Merge lock and no-op snapshots; `recovery-slots-final4-release-*.log` |
| Final exact-release new custody fixtures | 4 passed, 604.03 s; `recovery-slots-release-custody4.log` |
| Final exact-release previous common checkpoints | 4 passed, 138.81 s; `recovery-slots-release-common4.log` |
| Final exact-release delegation and compatibility races | 8 passed, 192.62 s; `recovery-slots-release-delegation4.log` |
| Final default CLI and daemon smoke | 300 passed, 45 existing ignored (91.51 s); smoke 2 passed (14.61 s); `recovery-slots-final4-cli.log`, `recovery-slots-final4-shutdown-smoke.log` |
| Final feature boundary | Minimal std-only and no-std experimental runtime passed; `recovery-slots-final4-feature-*.log`; full host exact-release build passed |
| Formatting and whitespace | Changed-range rustfmt checks pass for all 12 Rust files, including the new module; `git diff --check` passes; unrelated baseline formatting is untouched |

An exploratory storage-without-network build failed ten missing route-adapter
symbols (`recovery-slots-final-feature-std-storage.log`). The affected code is
unchanged from `7c850160`: host methods lack the networking gate already required
by their adapter definitions. This is a recorded pre-existing embedding defect,
not a passed feature check or an approved v1 host combination. No unrelated fix
is included; the v1 default host/CLI includes networking.

The physical runs exposed two costs worth fixing within this batch. Manifest
validation held the database writer also needed by Raft heartbeats; preparing
outside that writer now uses exact atomic predecessor comparisons. Archived
response proofs also repeated live/baseline validation. One fresh call-local
audited view now reuses that evidence without caching it across calls or peer
I/O. The 1.8 s collection deadline and final fresh validation are unchanged.

Earlier failures remain recorded in `recovery-slots-release-discovery1.log`,
`recovery-slots-debug-discovery{5,7,8}.log`,
`recovery-slots-release-custody2.log` and
`recovery-slots-debug-follower-reuse2.log`. Earlier diagnostic writer waits reached
155–298 ms, and repeated local/peer proof work exceeded the unchanged 1.8 s
collection window. The final optimized custody fixtures pass after these scoped
fixes. That is functional evidence, not a controlled speedup benchmark:
whole-fixture completion and meeting a proof-collection deadline do not establish
request percentiles, failover bounds or service capacity.

## Reproduction

Use the implementation worktree and disk-backed temporary storage, not `/tmp`:

```sh
export CARGO_TARGET_DIR=/home/daniel/src/virto/vos/.worktrees/ch08-c2-native/target
export TMPDIR="$CARGO_TARGET_DIR/task-tmp"
export JUST_TEMPDIR="$TMPDIR"
export CARGO_NET_OFFLINE=true
export CARGO_BUILD_JOBS=2
export RUST_MIN_STACK=16777216
export AUTHORITY_CANDIDATE_ELF="$CARGO_TARGET_DIR/agent-state-authority/riscv64em-vos/release/system_authority.elf"
export GREY_PVM=recompiler
cargo +nightly-2025-05-09 test --release --offline --locked -p vos \
  --features 'agent-runtime storage network http-ingress experimental-state-blocks' \
  --lib agent::clean_bootstrap::tests::physical::common_checkpoint:: \
  -- --ignored --test-threads=1 --nocapture
```

Run the same command with filter
`agent::clean_bootstrap::tests::physical::candidate_projection_` for the six
previous delegation cases and two stale-registration race regressions.

Loopback fixtures need socket permission. Do not overlap physical qualification
with compilation. Verify the Authority candidate SHA-256:
`a88872c5de59d97905ccfb043268fa8ef6aea5a1c0e354b9c7c3255fed05e2ed`.
Another digest at the same path cannot inherit evidence. This is the unchanged
signed-delegation candidate, not bundled-artifact promotion. Release pins belong
to `support/production-artifacts.toml` and `vosx/build.rs`.

The default fixture uses the native clean-runtime test adapter around physical
Authority actor execution. Full outer-PVM execution additionally requires
`VOS_AGENT_PROFILE_REFINE_MACHINES=1`; disable instruction attribution with
`VOS_AGENT_DISABLE_REFINE_ATTRIBUTION=1` for timings. The default fixture cannot
substitute for that separate full-outer-PVM release gate or released daemons.

For diagnosis only, enable `VOS_TEST_BOOTSTRAP_DIAGNOSTICS=1`,
`VOS_SHARED_RECOVERY_TIMING=1` and the fixture tracing filter.
The diagnostic optimized build uses `profile.release.lto=false` and
`profile.release.codegen-units=16`, distinct from default release.
Whole-fixture times are not request latencies, percentiles or failover bounds.

## Prior checkpoints and remaining release boundary

Historical detail and old artifact identities live in Git, not duplicated active
instructions: `git show 7c850160:docs/agent-saga-review.md`.

| Checkpoint | Preserved evidence / purpose |
| --- | --- |
| `7c850160` | Common/physical authority separation, pruned-prefix catch-up, healthy physical workflow, three source/destination crash cases, six delegated-recovery regressions |
| `6d2a9b38` | Scoped signed delegation; offline-origin exact completion with a harness-supplied request, not autonomous origin-WAL discovery |
| `7c1a1b7c` | Shared journal/external availability and three-file Create/Install/Invoke/ACK recovery, not public startup |
| `4ea0271c` / `48df3995` | Recompiler/default-reference integration, custom-runtime parity, bounded preparation and unsupported-path removal, not service capacity |
| `62ffbc20` | Complete imported-plan certification and pre-write unsupported-roster rejection; both prior startup findings fixed |

The [live checklist](agent-saga-status.md) retains all release gates: complete
pending-recovery coverage, expired-unseen resolution, external root snapshots/
export/reclamation, public Shared lifecycle and Clerk with 100,000 retained
transfers, released workload/failure/backup/restore, soak and reproducible artifacts.
External nodes will be supplied later; tooling/local evidence cannot close those
gates. No completion percentage or release date is established.

Return severity, location, violated invariant, concrete scenario and regression.
Separate demonstrated defects from unqualified release gates.
