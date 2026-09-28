# Agent saga: archived Shared Create recovery checkpoint

Review changes after `e4bb4ed1` at the archived-Create checkpoint on
`saga/agents`. The [live plan](agent-saga-status.md) records
qualification and remains authoritative. This is a lifecycle-recovery
checkpoint, not a release or public Shared Create rollout. Return findings
without editing `saga/agents`; fixes belong on the implementation branch.

## What changed

- Startup still requires every existing deferred generation to have a matching
  authenticated lifecycle/archive entry. It also handles an archive retained
  before Authority publication or physical provisioning.
- An additional unapplied Create replays its authorization and independently
  selected committee, then executes/replays publication and its positive ACK.
  Only that owner-produced proof permits staging the physical intent under
  the existing host lease. Archive signatures alone are not finality.
- Existing deferred opening performs physical Create and application
  acknowledgement/finalization/retirement. No ordinary routes appear until
  the complete independently proved generation set has recovered.
- A missing generation with recorded application (including an unsigned ACK
  pledge), finalization or retirement is rejected rather than recreated.
- Test directories now use atomic creation without deleting existing paths:
  independent sandbox PID namespaces can otherwise choose the same fixture.

## Review questions

1. Can an extra archived entry bypass candidate/committee authentication or
   become a physical generation without a positively acknowledged Authority
   publication? Check `resume_unprovisioned_shared_genesis` and
   `stage_deferred_replay_verified`.
2. Does interruption after publication or intent staging preserve exact
   reservations and recovery under the original lease, without exposing a
   partial route set or duplicating publication?
3. Does the missing-generation guard cover both signed application ACKs and
   durable unsigned application observations, while admitting legitimate
   unapplied archives? Existing corruption and reservation guards must remain.

## Evidence and limits

Both extended physical tests passed serially (2 passed in 810.26 s). They
cover archived Create before/after publication, rejection of missing physical
data with signed or unsigned application observations, and a second restart
after durable intent staging but before physical application. Recovery
preserves the archive and exact publication counts, completes retirement,
then serves actor Install/Invoke/ACK.

Earlier overlapping runs reported `CorruptResidue`; their process-ID-based
fixture paths could collide across sandbox namespaces and delete a live
fixture. Atomic directory allocation and its focused collision regression
are included. The passing serial pair uses the corrected allocation.

The issuer pending-ACK regression, three controller regressions, deferred-host
lease/finality regression, fixture-isolation test and `cargo check -p vosx`
pass. Reproduce the physical pair with `CARGO_TARGET_DIR` and `TMPDIR` set to
an existing disk-backed build directory, not RAM-backed `/tmp`:

```sh
RUST_MIN_STACK=16777216 VOS_AGENT_PROFILE_REFINE_MACHINES=1 \
  cargo test --offline --locked -p vos --features pvm \
  native_shared_unprovisioned_archive_restarts --lib \
  -- --ignored --test-threads=1
```

These tests use real bundled outer-PVM execution and physical journals, but
memory-backed lifecycle stores. They do not qualify released-daemon/file-store
crashes, public Shared Create/Install, multi-node quorum, Shared external-state
Clerk growth, production throughput or backup/restore. Those remain release
gates in the live plan. Report severity, location, violated invariant, concrete
failure scenario and a regression, separating demonstrated defects from risks.
