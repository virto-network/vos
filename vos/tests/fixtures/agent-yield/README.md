# Protected AgentActor yield fixture

This is an explicit C2 native-lifecycle fixture, not a bundled system actor.
`run` requires actor role `51` repeated 32 bytes and mutates Local state by
1, 10, and 100, with a cooperative yield between the mutations. `value` is a
LocalQuery. A fresh completed run should return 111; a second fresh completed
run should return 222. Exact retries must not add another increment.

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
