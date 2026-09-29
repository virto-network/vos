# Agent saga: Shared Install recovery and bundled expiry checkpoint

Review the combined implementation changes after `65f35760`. The
[live plan](agent-saga-status.md) records whether the checkpoint has reached
`saga/agents` and is authoritative for release scope. Review read-only; return
findings for application on the latest implementation branch.

This is an internal lifecycle/recovery checkpoint, not public Shared ingress,
three-node qualification or a release. It combines the intermediate commits into
three review areas rather than requiring a separate review for every commit.

## 1. Retained Shared lifecycle and file recovery

Primary files: `clean_genesis_recovery.rs`, `clean_bootstrap.rs`,
`clean_management_intent.rs`, `local_lifecycle.rs`, and CLI
`clean_store.rs` / `clean_startup.rs`.

The production lifecycle owner carries Create completion into successive signed
Install requests without reopening its own leases. Recovery restores retained
authorization/finalization before unrelated fresh Authority reads. Staged
handoffs retain exact predecessor/successor requests, packages and issuer state.
Policy denials retire with request-bound signed evidence and permit a subsequent
request without replaying the denied one.

Review capacity and ownership at every allocation; exact retry after ordinary
serving advances the journal; staged intent/issuer/actor-package replacement;
pending admission restoration; and route nonexposure before finality. Missing
or substituted data must not become a successful retry. An issuer archive alone
is not physical finality.

## 2. Signed Install failure and expiry

Primary files: SDK `authority.rs`, `runtime.rs`, `wire.rs`; host
`clean_authority_issuer.rs`, `standard.rs`, `wire.rs`,
`local_journal_driver.rs`, `shared_journal_driver.rs`, `shared_host.rs`;
and the system Authority actor.

Shared Install supports signed terminal application failures. Expired approved
Install has a distinct non-execution fence, not a renewed approval. Receipt
binding/signatures are unchanged; the expiry failure is valid only strictly
after the original deadline. Journal preview/replay require the exact expiry
outcome and changed durable state. The actor must not be installed. A success
already committed before expiry keeps its original result on later retry.

Review the distinction between policy denial, transient failure and signed
application failure; original receipt binding; durable observation before
signing; and exact timestamps/results across reopen. Verify that expired success,
unchanged fake fences and unauthenticated preview results cannot obtain finality.
Image-path receipt admission remains strict; this is not generic cancellation.

## 3. Bundles, validation ordering and qualification

Runtime, Authority and Catalog bundles now use immutable source/builder revision
`7316e52ddd98b083941ead6dd3ca5ba18b2e1a2c`. Program identity, build-time digests
and provenance move together. The reproduction script rebuilt all three blobs
byte-for-byte using the pinned builder. Catalog actor source is unchanged;
its compiled dependency closure changed. The earlier old/new contract comparison
covered normalized manifests and non-program artifacts, not behavioral equivalence.

Expiry file fixtures now use the bundled packages directly, with no candidate
environment override. Their test-only clock catches up to wall time and preserves
explicit forward jumps. One initial run failed Create preparation; an unchanged
diagnostic rerun passed, so that failure is not conclusively attributed.

Physical Local lookup and audit-directory construction now authenticate runtime
package/program consistency before directory execution. Borrowed directory
records reuse that check. Review the immutable-borrow/ownership boundary; the
regression requires rejection of substituted process bytes without a VM query.

## Evidence and reproduction

Latest completed default-path checks:

- Immutable-source runtime/Authority/Catalog reproduction: passed.
- Release verifier: 18 passed, one ignored.
- Driver tests: 35 passed; Local host tests: 21 passed.
- CLI unit suite with loopback access: 295 passed, 38 ignored.
- Bundled staged-expiry file recovery: one passed, 206.21 seconds.
- Bundled mixed expiry/retired-generation recovery: one passed, 552.55 seconds,
  exercising both Agent-ID orderings with default bundled packages.

Logs are under `.worktrees/ch08-c2-native/target/shared-expiry-*`. The default
CLI sandbox attempt had 16 socket-bind permission failures; the loopback-enabled
rerun passed. Ignored and zero-selected tests are not coverage.

Set absolute disk-backed `CARGO_TARGET_DIR` and `TMPDIR`; do not use RAM-backed
`/tmp`. Representative commands from the implementation worktree:

```sh
CARGO_NET_OFFLINE=true bash scripts/build-agent-release-artifacts.sh all
cargo +nightly-2025-05-09 test --offline --locked -p vosx --bin vosx -- --test-threads=2
RUST_MIN_STACK=16777216 VOS_AGENT_DISABLE_REFINE_ATTRIBUTION=1 \
  cargo +nightly-2025-05-09 test --offline --locked -p vosx \
  shared_install_file_owner_recovers_expiry_beside_retired_generation \
  -- --ignored --nocapture
```

The physical tests use production file owners, journals and synchronized staging
faults with owner drop/reopen, not process kills, power loss or multiple nodes.
Mixed coverage is one pending Install beside a retired Create, both Agent-ID
orderings; it is not arbitrary concurrent pending continuations.

## Explicitly not signed off

Public Shared Create/Install and endorsement collection; common three-node
system lineage; Shared external-state Clerk integration and retained growth;
backend-credential load/overload; failover/partition/backup/restore; full
workspace and release-binary qualification. Existing-deployment migration and
downgrade compatibility are not established by fresh-root tests. Production
Local remains image-based; external Local ingress stays deferred.

Report severity, location, violated invariant, a concrete failure scenario and
a regression. Distinguish demonstrated defects from unqualified release gates.
