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

Once the generic service ELF has been converted with `vosx service-pvm`, the
repository recipe packages every scenario from its project directory. This
also exercises Cargo target discovery for libraries whose explicit `[lib]`
name differs from the package name:

```sh
just package-examples dist/vos-service.pvm dist/examples
```

From the repository root, package the verifier with its cross-root producer
declared explicitly:

```sh
cargo run -p vosx -- build examples/actors/private-age \
  --service-pvm dist/vos-service.pvm
cargo run -p vosx -- build examples/actors/age-gate \
  --service-pvm dist/vos-service.pvm \
  --external-actor private-age
```

The dependency name is signed into the verifier package. A space resolves it
to the exact installed producer deployment; it is not an ambient route lookup.

[`extensions`](extensions/) and [`wasm`](wasm/) contain native and WASM API
examples. They are separate from the canonical actor-PVM examples above.

The old single-actor replay samples are retained only as internal regression
fixtures under [`tests/fixtures/legacy-v1`](../tests/fixtures/legacy-v1/); they
are not an application API. Clerk is the larger acceptance application under
[`tests/acceptance/clerk`](../tests/acceptance/clerk/), not a beginner sample.
