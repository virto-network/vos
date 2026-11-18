# PVM conformance vectors

The runtime keeps three checked-in contracts, all for Gray Paper v0.8.0:

- `vectors-v080/*.gp080.json` is the instruction corpus. Its 170
  independently expected cases place every one of the 139 valid opcodes as a
  vector's initial instruction. A hard exact-set assertion rejects either a
  missing valid opcode or an accepted unlisted opcode. Every case runs on the
  interpreter and the recompiler, whose remaining gas must agree exactly.
  Exit counters follow full Ψ: halt and panic return zero, while host-call,
  page-fault and out-of-gas return their causing counter. Every case runs
  again through a loader's path: its program as a compact code blob through
  `deblob` (the 4 with an invalid program refused there), its pages mapped
  and filled with `pages` and `poke`, its run an inner machine's `invoke`
  on each backend's production memory.
- `vectors-v080-gas/*.gp080.json` contains independently derived block
  boundaries, block costs, exit precedence and remaining-gas outcomes. All 16
  cases run on both the interpreter and the recompiler, including panic,
  page-fault, out-of-gas and host-call resume boundaries. Together with the
  literal-reference scheduler differential gate, they cover the 32-entry
  reorder buffer, whole-width decode admission, five-start dispatch,
  persistent execution-unit contention (including independent DIV
  serialization), move-register clobber propagation, dependency chains,
  memory faults, out-of-gas, the complete two-position/zero-extended
  branch-latency equation (including mixed and out-of-code targets),
  validation of both branch successors before selection, implicit trailing
  traps, and the fact that `unlikely` and `ecalli` are not in the
  termination set.

- `boundaries.rs` holds the program and invocation boundaries at the
  public API, each program written out byte by byte (never through the
  crate's writer) and each outcome read from the text: `deblob`'s jump
  table at every width (zero, padded, five to eight bytes, past a
  register), the `machine` call's reader, Ψ's uncharged panic on an entry
  that is no instruction start (past the code, an operand byte) against an
  interior instruction start, the recompiler's own code bound against the
  interpreter and the service-code bound `W_C` at service admission, and
  Ψ_M's halt output (an empty length whatever its pointer, an unreadable
  range empty, an embedder's bound its own refusal), and operand decoding
  at its edges (A.5): a register nibble above 12, operand bytes past an
  instruction's skip and past the code, `load_imm_64`'s eight bytes past a
  short skip, an immediate-length field of 5 to 7. They run through the
  loader's `deblob` on the interpreter and, where the host has it, the
  recompiler.

The v0.8 opcode, instruction-category, and termination-set manifests are
frozen in `pvm_vectors.rs`. They are transcribed from Appendix A.5 and
equations A.19/A.20 and A.49--A.57 of the official `gavofyork/graypaper`
v0.8.0 release (commit `07f041dabd073f9018b418e9ee72e79dd2185401`). Expected
outcomes are hand-derived; they are never recorded from a runtime execution.

Regenerate the JSON from the reviewed tables with:

```sh
VOS_PVM_BLESS_VECTORS=1 cargo test -p vos-pvm --test pvm_vectors
```

Without that environment variable, the test fails on a missing, stale, or
unlisted vector. This makes the checked-in JSON—not an implementation run—the
release contract.
