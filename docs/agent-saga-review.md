# Agent saga: fixed three-node startup and projection recovery

Candidate code checkpoint: `310ef841`. Review `f1bfa1bd..310ef841` as one
integration batch, grouped into the three areas below. It contains 30 commits
across 21 files; individual commits are implementation history, not separate
review assignments. Later handoff-only commits do not change that code range.

At preparation time `saga/agents` remains at `f1bfa1bd`; the candidate is on
`wip/ch08-runtime-directory`. Verify the head before reviewing. Review read-only
and return findings for application on the implementation branch. The
[live plan](agent-saga-status.md) owns release scope and evidence. The previous
guide is preserved in Git at `f1bfa1bd`.

This is not a release. Local remains image-based. Production multi-node startup
and public Shared management remain gated. Candidate Authority is not repinned.

## 1. One authenticated system lineage

Primary files: Authority `lib.rs` / `node_storage.rs`; host `bootstrap.rs` /
`clean_bootstrap.rs`; CLI `clean_genesis_archive.rs`, `clean_startup.rs` and
`local_config.rs`.

One certified bundle localizes to signed roster members without resigning
genesis or replacing root evidence. Fixed-roster configuration is bound to the
certified descriptor. Import is bounded, scoped and immutable; reopen uses
durable package identities. Preparation shares startup's validated construction.

Review wrong Space/operator/node rejection, canonical membership, replica-
independent commitments, physical admission and rejection before writes.
Resupplying a bundle must not repair missing/substituted completed root evidence.
Fresh import is not migration or an operator-facing enrollment CLI.

## 2. Replicated bootstrap and filesystem ownership

Primary files: `clean_bootstrap.rs`, `execution.rs`, `replay.rs`,
`{local,shared}_journal_driver.rs`, `shared_host.rs`, `network/shared_agent.rs`,
and CLI `clean_startup{,_tests}.rs`.

Bootstrap retains peers/owners while awaiting election. Followers recover exact
completed results from authenticated journal evidence, including original
authorization and management seals. Three startup file owners consume one
common bundle and reopen without resupplying it.

Review leader-no-op replication, replay/materialization, lagging metadata,
failure ownership and capacity headroom. Deferred promotion is restricted to
the matching fixed committee and retained work, without early route publication.
Optional multi-voter checkpoint scheduling skips the unavailable quorum
collector; mandatory capacity/certificate guards must still fail closed.

## 3. Route readiness and projection recovery

Primary files: `production_owner.rs`, `supervisor_adapters.rs`,
`clean_bootstrap.rs`, `shared_{host,journal_driver}.rs`, and network
`agent_protocol.rs`, `agent_network.rs`, `shared_agent.rs`.

Initial temporary unavailability retains unpublished participants. Followers
enqueue signed queries on the leader's bounded worker; acceptance proves only
admission. Results require locally applied exact Invoke and positive ACK
evidence. No VM work runs in the peer handler.

Recovery-only relay is distinct from fresh admission: it may carry another
node's attested query, but cannot create work absent from the leader's own
authenticated journal. The successor preserves original authorization. The
former leader retains its reservation until exact local ACK evidence permits
durable cleanup. Fresh sender/attestor binding is unchanged.

Prioritize unknown/mutated query rejection, fresh-versus-recovery dispatch,
original-clock binding, queue bounds, retired-handle ownership, stale-generation
races and reservation retention through failed cleanup. Missing/pruned history
is unavailable, never permission to fabricate results.

## Evidence and reproduction boundaries

Use offline/locked Cargo, host toolchain `nightly-2025-05-09`, and absolute
disk-backed `CARGO_TARGET_DIR` / `TMPDIR` under
`.worktrees/ch08-c2-native/target`. Do not use RAM-backed `/tmp`.
Core tests require features `agent-runtime storage network http-ingress`;
CLI uses `-p vosx --bin vosx`. Physical tests use `RUST_MIN_STACK=16777216`
and `VOS_AGENT_DISABLE_REFINE_ATTRIBUTION=1`. Loopback permission is required.
Candidate tests need `AUTHORITY_CANDIDATE_ELF` pointing to the qualified
`riscv64em-vos/release/system_authority.elf` in the shared target.

- CLI `candidate_fixed_roster_production_routes_start_from_common_bundle`
  with `--ignored --nocapture`: all three Nodes publish routes at startup and
  filesystem-owner reopen. Final code-checkpoint rerun passed: 130.16 s.
  This ran alongside the CLI suite; duration is whole-fixture time, not a
  latency benchmark. The earlier 71.07 s run is historical evidence only.
- Core `candidate_projection_recovers_after_leader_loss_and_former_leader_reopen`
  with `--ignored --nocapture`: leader loss after Invoke/before ACK, election,
  former-leader follower reopen, cross-node attestation relay and reservation
  release. Passed at this code checkpoint: 67.62 s. Real Raft and filesystem
  journals with physical runtime, but memory bootstrap/issuer metadata and a
  scripted bootstrap Catalog. Not three-daemon or HTTP qualification.
- Latest relay regressions: 26 protocol/network tests, 33 adapter tests,
  singleton pending-read recovery, std library build, formatting and diff checks.
- Earlier original-authorization tests include bundled Authority outer-PVM
  execution. Final code-checkpoint CLI suite: 298 passed, 44 ignored (41.19 s).
  CLI build passed (39.40 s). This does not include ignored physical cases
  except where explicitly listed above.

Shared-target logs use prefixes `fixed-system-projection-recovery-`,
`fixed-system-projection-original-authorization-` and
`fixed-system-review-checkpoint-`. Ignored, zero-selected and socket-permission
failures are not passing evidence. No independent artifact reproduction or
production-capacity claim follows from this batch.

## Explicitly open release gates

Leader loss before Invoke commits; remaining ACK/metadata-clear failure cases;
quorum checkpoint collection; actual three-daemon/HTTP startup/recovery;
operator CLI orchestration; public Shared Create/Install with finality; Shared
external-state Clerk and retained-data growth; 300-active-client load, overload,
backup/restore and final reproducible release artifacts.

Report severity, location, violated invariant, concrete failure scenario and
regression. Distinguish demonstrated defects from unqualified release gates.
