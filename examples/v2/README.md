# VOS v2 examples

These examples use the clean v2 actor source surface. Platform rustflags add
`no_std` and `no_main`; application source does not declare either attribute.

- `counter`: ordinary Rust state for Local or Raft consistency.
- `workflow`: a root calls its owned child by name; the child checkpoints on a
  durable cross-root call and resumes after the peer has accumulated a reply.
- `shared-board`: explicit `Map`, `List`, `Text`, and `Counter` fields. Its
  native test merges concurrent edits from two replicas in both orders.

Build the canonical actor ELFs:

```sh
cargo actor -p v2-counter
cargo actor -p v2-workflow
cargo actor -p v2-shared-board
```

Run the host-side convergence gate:

```sh
cargo test --workspace
```
