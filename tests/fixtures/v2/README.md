# Runtime v2 fixtures

These programs exercise v2-only package and registry invariants without being
published as beginner examples. In particular, `actors/crdt-counter` carries
the explicit `#[actor(crdt)]` metadata required by CRDT installation tests.

The similarly named fixture under `legacy-v1` intentionally remains a plain
actor: the retired v1 replay runtime cannot establish a slice-scoped CRDT
operation allocator.
