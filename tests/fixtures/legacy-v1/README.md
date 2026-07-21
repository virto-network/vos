# Legacy v1 regression fixtures

These actors and recipes exercise the retired single-actor host, EffectLog
replay, old extension bridges, and proving benchmarks while their regression
coverage is being replaced. They are test inputs, not examples or supported
application templates. New application code should use
[`examples/actors`](../../../examples/actors/) and `.vos` v2 packages.

The fixture-local `justfile` preserves the historical bulk build used by the
legacy integration suite. Individual crates remain isolated workspaces so they
can still produce the exact ELFs expected by those tests.
