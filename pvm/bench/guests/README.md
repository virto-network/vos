# Bench guests

PVM guests for the benches and tests in `pvm/bench`, built with the toolchain
in `pvm/guest`: `just build-bench-guests`.

- `workflows`: three workflows with suspension points (S1 snapshots).
- `actor`: a ledger handler hosted as an inner machine (S2).
- `agent`: an agent program hosting `actor` through JAM's inner-machine calls
  (S2).
- `hash-software`: BLAKE2b computed inside the PVM (S4, S5).
- `hash-precompile`: BLAKE2b through the VOS precompile, falling back to
  software when the host answers `WHAT` (S5b).
