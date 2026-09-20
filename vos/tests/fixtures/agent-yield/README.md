# Protected AgentActor yield fixture

This is an explicit C2 native-lifecycle fixture, not a bundled system actor.
`run` requires actor role `51` repeated 32 bytes and mutates Local state by
1, 10, and 100, with a cooperative yield between the mutations. `value` is a
LocalQuery. A fresh completed run should return 111; a second fresh completed
run should return 222. Exact retries must not add another increment.

The fixture also exposes Local `row_set` and `row_yield`, plus LocalQuery
`row_get`, backed by `StorageMap<u64,u64>` under `s/rows/`. `row_yield` writes1,
yields once, then reads and replaces the value with2. These exercise the clean
STORAGE_R/ARD1 dispatch and resumed overlay reset. The artifact-dependent test
`compiled_storage_map_reads_writes_and_resumes_clean_slices` takes
`AGENT_STORAGE_PROBE_ELF`; it checks the compiled inner guest, not package
admission or a native daemon restart.

Local `row_rejected` writes inside a storage transaction and returns a refusal
from that transaction. The compiled regression checks both replacement and
insertion rollback: the method completes successfully, but exports no rows and
subsequent queries retain the original value or absence.

Build using disk-backed `CARGO_TARGET_DIR` and `TMPDIR`. From the repository
root, host type-check with:

```sh
cargo check --offline --locked --manifest-path vos/tests/fixtures/agent-yield/Cargo.toml
```

From `examples/actors`, reuse the canonical target configuration and layout:

```sh
cargo +nightly-2026-03-20 actor --offline --locked --manifest-path ../../vos/tests/fixtures/agent-yield/Cargo.toml
```

Package the resulting `riscv64em-vos/release/agent_yield_probe.elf` with
`vosx actor build`, using a disposable operator identity and output directory.
There are no constructor arguments. Do not replace any retained actor package
or signed intent from an earlier campaign.

Compilation and package admission are prerequisites, not execution evidence.
The native campaign must install the package, grant the deployment-scoped role,
retain the exact managed invocation and first yielded response, restart the
daemon, resume the exact continuation through ingress, observe the second
yield, and complete with 111. It must verify positive retirement, exact retry,
and a post-restart LocalQuery of 111. Do not assume mutations are externally
queryable between slices. Keep the same invocation and authorization across
both resumes; never re-authorize to recover a suspended invocation.

## Large-input qualification

`input_len(bytes)` is a read-only LocalQuery with the same explicit actor-role
requirement as `run`. It returns the decoded byte-vector length without changing
Local state. Use it to exercise the compiled Rust decoder at the clean message
boundary: the **complete encoded actor message**, including selector and argument
framing, must fit 16 KiB, not the byte vector alone. Archive alignment can make
the exact ceiling unrepresentable: use the largest naturally encoded message
that fits and reject the next payload size. Verify the returned payload length
and unchanged state; also verify a message one byte over the byte ceiling is
rejected before execution. Preserve the original protected-yield campaign and
its package.

Run the physical inner-executor regression from the repository root with
`AGENT_INPUT_PROBE_ELF` pointing to this freshly built ELF (and disk-backed
`CARGO_TARGET_DIR` and `TMPDIR`):

```sh
cargo +nightly-2025-05-09 test --locked --offline -p vos --features pvm --lib \
  agent::execution::tests::compiled_clean_guest_accepts_maximum_encoded_input \
  -- --ignored --exact --nocapture
```

The test explicitly fails if its artifact is unavailable. It links the real
Rust guest, supplies a clean protected-role context, initializes canonical Local
state with a small query, then checks the maximum query's reply and unchanged
state. This is inner execution coverage, not ingress authorization or release
artifact reproducibility.

The same explicit test also exercises `blob_len(hash, len)` through
`Context::invocation_blob`: a caller blob at the current aggregate availability
ceiling (192KiB) returns its verified length,
missing availability returns the fixture's missing sentinel, and wrong length
or a reference above48KiB returns its error sentinel. Each call preserves Local
state. Build the current fixture: an older input-only ELF cannot cover this
method. The API is clean-invocation-only and has no native test-store fallback.

Adding/type-checking this method is not physical PVM execution evidence. Build a
new disposable artifact from the current source and record its identity and
execution result before counting this boundary as qualified.
