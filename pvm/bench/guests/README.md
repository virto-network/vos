# Bench guests

PVM guests for the benches and tests in `pvm/bench`, built with the toolchain
in `pvm/guest`: `just build-bench-guests`.

- `workflows`: three workflows with suspension points (the snapshot bench).
- `actor`: a ledger handler hosted as an inner machine (the nesting bench).
- `agent`: an agent program hosting `actor` through JAM's inner-machine calls
  (the nesting bench).
- `hash-software`: BLAKE2b computed inside the PVM.
- `hash-precompile`: BLAKE2b through the VOS precompile, falling back to
  software when the host answers `WHAT`.
- `diverse`: a small mixed workload proven end to end by
  `tests/diverse_proof.rs`.
