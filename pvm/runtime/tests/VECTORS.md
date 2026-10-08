# PVM conformance vectors

The runtime keeps three checked-in contracts:

- `vectors/*.gp072.json` is the historical GP 0.7.2/Jar corpus. It preserves
  the private capability-runtime opcode profile and is not current-standard
  conformance evidence.
- `vectors-v080/*.gp080.json` is the Gray Paper v0.8.0 instruction corpus.
  Its 173 independently expected cases place every one of the 139 valid
  opcodes as a vector's initial instruction. A hard exact-set assertion
  rejects either a missing valid opcode or an accepted unlisted opcode. All
  172 cases run with the strict standard profile on the interpreter; the
  170 whose expected exit is not specific to historical per-instruction gas
  also run on the recompiler with exact block-gas parity at every applicable
  exit. Standard exit counters are exact on both backends: halt/panic return
  zero, while host-call, page-fault, and OOG return their causing counter.
- `vectors-v080-gas/*.gp080.json` contains independently derived v0.8.0
  block boundaries, block costs, exit precedence, and remaining-gas outcomes.
  All 16 cases run on both the interpreter and recompiler, including panic,
  page-fault, OOG, and host-call resume boundaries. Together with the
  literal-reference scheduler
  differential gate, cover the 32-entry reorder buffer, whole-width decode
  admission, five-start dispatch, persistent execution-unit contention
  (including independent DIV serialization), move-register clobber
  propagation, dependency chains, memory faults, OOG,
  the complete two-position/zero-extended branch-latency equation (including
  mixed and out-of-code targets), validation of both branch successors before
  selection, implicit trailing traps, and the fact that `unlikely` and
  `ecalli` are not in the termination set.

The v0.8 opcode, instruction-category, and termination-set manifests are
frozen in `pvm_vectors.rs`. They are transcribed from Appendix A.5 and
equations A.19/A.20 and A.49--A.57 of the official
`gavofyork/graypaper` v0.8.0 release
(commit `07f041dabd073f9018b418e9ee72e79dd2185401`). Expected outcomes are
hand-derived; they are never recorded from a runtime execution.

Regenerate the JSON from the reviewed tables with:

```sh
VOS_PVM_BLESS_VECTORS=1 cargo test -p vos-pvm --test pvm_vectors
```

Without that environment variable, the test fails on a missing, stale, or
unlisted vector. This makes the checked-in JSON—not an implementation run—the
release contract.
