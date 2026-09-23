# External-state constructor fixture

This compiled AgentActor has a required named `seed: u64` constructor argument,
a Linear counter and a `StorageMap<u64, u64>`. `advance` increments the counter
and replaces row 0; `stored` reads that row through a LinearizableQuery.
The constructor itself does not write rows during hydration.

Build with `just build-agent-state-actor`, using a disk-backed `CARGO_TARGET_DIR`
and `JUST_TEMPDIR`. The pinned build is offline/locked and writes a separate
`agent-state-actor` target, never a bundled artifact.

`compiled_create_install_constructor_invoke_retry_and_ack` creates and installs
through the physical standard guest using the emitted AAS2 schema. Seed 41 must
produce 42, then 43, and the subsequent row read must return 43. Exact retries
must not execute again; result retirement preserves the row. A separately signed
request cannot substitute seed 99 for the installed constructor argument object.

`just test-agent-state-prototype` builds this fixture and runs that test. It uses
a test Authority issuer and in-memory candidate staging; actor-package admission,
journal finality, process restart, production throughput and backup are separate
qualification gates. The live plan is `docs/agent-saga-status.md`.
