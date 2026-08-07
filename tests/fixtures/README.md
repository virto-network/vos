# Test fixtures

This directory contains executable workloads retained for integration and
compatibility testing. They are not the supported application-authoring
surface; public v2 actor examples live under [`examples`](../../examples/).

- `legacy-v1/` preserves retired single-actor and replay behavior.
- `v2/` contains focused package and registry fixtures.
- `provable/` contains proof-producing PVM workloads with heavyweight test
  dependencies.
- `extensions/` and `wasm/` exercise non-actor host interfaces.

Keeping these programs out of `examples/` prevents test-only ABI patterns and
specialized proving workloads from being mistaken for current application
templates.
