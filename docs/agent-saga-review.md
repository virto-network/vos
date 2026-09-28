# Agent saga: retained live Shared Create checkpoint

Review the combined changes after `c90c83cc` at this checkpoint on
`saga/agents`. The
[live plan](agent-saga-status.md) is authoritative for release scope and gates.
Return findings without editing either branch; fixes belong on the latest
implementation work. This is not a release or public Shared Create rollout.

## Why this batch exists

Recovery could previously finish a retained Shared Create, but the running
lifecycle owner could not carry a new request through the same durable phases.
This batch connects reservation, preparation/endorsement, publication and
completion under that owner. It reuses the existing protocol and recovery
machinery; it does not introduce another wire format or regenerate artifacts.

## What changed

- A lazy, pinned file-store factory validates signed inputs before allocating
  per-Agent state. Admission counts the retained lifecycle inventory, including
  staged entries, while exact retries remain possible at capacity. Startup and
  admission share the strict empty-partial-parent recovery rule.
- The production lifecycle owner retains the Shared controller and factory.
  Existing retries borrow retained leases rather than reopening owned stores.
  Fresh startup still creates none of the ordinary Shared control roots.
- Preparation returns a sealed in-process candidate/committee pair. Endorsement
  cannot substitute a committee; existing signature pledges and quorum checks
  remain authoritative. Publication retains the original Create reservation
  and does not expose a route.
- Completion stages only the new generation outside the serving map, observes
  physical application and finishes signed ACK/finalization/retirement before
  admission. Live staging does not activate the global startup-recovery gate.
- Terminal retries return the original ACK and still perform a fresh Authority
  read. Successful startup recovery normalizes its retained in-memory phase so
  the same controller can handle that retry without repeating Create.

## Review questions

1. Can file allocation, discovery or exact retry disagree about capacity,
   ownership, signed identity or the selected replica roster? Check
   `CleanSharedGenesisStoreFactory` and `reserve_create_with`.
2. Can candidate preparation or endorsement substitute committee authority,
   bypass a durable pledge, or turn archive signatures into finality? Check
   `PreparedSharedGenesisEndorsement` and retained publication.
3. Can an ordinary generation become available before signed application
   finality and retirement? Check `complete_live_shared_genesis`,
   `stage_live_replay_verified` and `admit_live_replay_verified`.
4. Do warm completion retries and startup normalization preserve exact ACKs,
   fresh Authority reads, pending admission guards and missing-data rejection?
   Include the interruption after retirement but before host admission.
5. Does live staging leave existing serving generations outside the startup
   gate, while cold recovery still requires complete-set authentication?

## Evidence and limits

- File-store suite: 20 passed, one fixture-dependent test ignored. Covers
  retries, staged capacity/restart, malformed inputs, lease retention and
  parent replacement. Four controller regressions also pass.
- Physical preparation/publication: passed in 234.26 s. Exact retries append
  no duplicate journal entries; outsider endorsement is refused before signing.
- Final physical completion: passed in 526.89 s with a configured verifier
  refusing archive-only finality. Interrupted promotion leaves no ordinary
  handle; retries preserve the signed ACK and perform fresh Authority reads.
- Extended archived-startup recovery: passed in 447.92 s, including the exact
  terminal ACK retry through the recovered controller and actor Install/Invoke/ACK.
- Deferred-host lease/finality regression passes. `cargo check -p vosx`,
  the `std`-only core check, formatting and diff checks pass. Debug daemon
  startup/shutdown passes in 23.39 s with all three Shared control roots absent.

Reproduce physical tests with `CARGO_TARGET_DIR` and `TMPDIR` set to an existing
disk-backed build directory, not RAM-backed `/tmp`:

```sh
RUST_MIN_STACK=16777216 VOS_AGENT_PROFILE_REFINE_MACHINES=1 \
  cargo test --offline --locked -p vos --features pvm \
  native_shared_lifecycle_completion_gates_route_and_retries_ack --lib \
  -- --ignored --test-threads=1
RUST_MIN_STACK=16777216 VOS_AGENT_PROFILE_REFINE_MACHINES=1 \
  cargo test --offline --locked -p vos --features pvm \
  native_shared_unprovisioned_archive_restarts_after_publication --lib \
  -- --ignored --test-threads=1
```

Physical tests use bundled outer-PVM execution and real journals but memory
lifecycle stores and a one-voter fixture. The completion fault is a warm retry,
not a cold released-daemon crash. File-backed cold crash orchestration,
production endorsement collection, physical-capacity preflight, signed denial
retirement and Shared Install handoff remain pre-ingress work. Public Create
is still disabled. Three-node system lineage, external-state Shared Clerk,
performance/load, backup/restore and release artifact qualification remain
release gates. Report severity, location, violated invariant, concrete failure
scenario and a regression, separating demonstrated defects from risks.
