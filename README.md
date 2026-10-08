# VOS core

The new VOS core, under construction on branch `vos-core`. Its design is in
[`docs/design/core-model.md`](docs/design/core-model.md); the measurements
behind it are in [`docs/design/spikes.md`](docs/design/spikes.md).

This tree holds what the core is built on so far:

- `pvm/`: the Gray Paper 0.8.0 PVM: runtime (interpreter and JIT), RISC-V
  compiler, standard-program format, codec, and the STARK prover and
  verifier. `pvm/guest/` holds the guest toolchain.
- `support/vos-raft`: the `no_std` Raft core.
- `support/merkle-crdt`: the Merkle-CRDT DAG and sync.

The current build step is planned in
[`docs/design/slice-1-pvm-base.md`](docs/design/slice-1-pvm-base.md), which
also lists the parts of master that left this branch and where each returns.

`just` lists the checks: `just test`, `just vectors`, `just test-proof` and
`just ci`.
