# VOS examples

The public actor examples use only the v2 source and package model. Application
authors build one canonical actor PVM; the pinned generic VOS service owns JAM
Refine and Accumulate.

The [`actors`](actors/) workspace contains four focused examples:

- `counter`: ordinary Rust state for Local or Raft consistency;
- `workflow`: an owned child suspends on a durable cross-root call and resumes
  from its exact machine checkpoint;
- `private-age` + `age-gate`: an ordinary and an attested method on one
  producer, with proof verification in a separate actor;
- `shared-board`: explicit `Map`, `List`, `Text`, and `Counter` fields merged
  across two CRDT replicas.

Build them without source-level `no_std` or `no_main` attributes:

```sh
cd examples/actors
cargo +nightly actor -p v2-counter
cargo +nightly actor -p v2-workflow
cargo +nightly actor -p v2-private-age
cargo +nightly actor -p v2-age-gate
cargo +nightly actor -p v2-shared-board
```

[`extensions`](extensions/) and [`wasm`](wasm/) contain native and WASM API
examples. They are separate from the canonical actor-PVM examples above.

The old single-actor replay samples are retained only as internal regression
fixtures under [`tests/fixtures/legacy-v1`](../tests/fixtures/legacy-v1/); they
are not an application API. Clerk is the larger acceptance application under
[`tests/acceptance/clerk`](../tests/acceptance/clerk/), not a beginner sample.
