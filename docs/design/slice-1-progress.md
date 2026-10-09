# Slice 1 progress

Results for each step of `slice-1-pvm-base.md`. Measurements were taken on
the reference laptop (Core Ultra 7 155H). Other work ran at the same time
(load average about 8–9), so timings carry some noise.

## Step 1.1: port, tooling and baseline

**Done:**

- `pvm/` is the saga's Gray Paper 0.8.0 layer (`766f4860`) plus the BLAKE2b
  precompile (`6659ddea`). The workspace is trimmed to `pvm/*` and
  `support/*`, and the saga's dependency on its agent SDK is replaced by a
  local 64 MiB bundle bound.
- **Guest toolchain** in `pvm/guest/`: the target spec, a linker script with
  the explicit read-write base, the cargo configuration and the pinned guest
  nightly.
- **`pvm/bench`:**
  - the S1 (`snapshots`) and S2 (`nesting`) harnesses and the S5b
    (`precompile`) harness, with their guests in `pvm/bench/guests/`;
  - `tests/precompile_agreement.rs`, which checks that the VOS precompile,
    the JAM fallback and all-software BLAKE2b agree. It fails, not skips,
    when its guests are missing.
- **`justfile`:** `test`, `vectors`, `test-proof`, `build-bench-guests`,
  `test-bench`, `bench`, `fmt-check`, `clippy`, `jar-check` and `ci`. The
  repository has no hosted CI. `ci` runs before every push through
  `.githooks/pre-push` (`just install-hooks`), and `.githooks/pre-commit`
  runs fmt and clippy.
- **Compiler fix:** a call whose return address has no translated
  instruction (a call to a function that never returns, at the end of a
  section) now gets a trap as its return target. Before, its jump-table
  entry stayed 0, which names the refine entry point, so a return would have
  restarted the program. The old warning claimed such a jump would panic,
  which was wrong.

**Baseline:**

| Suite | Result |
|---|---|
| Runtime (`vos-pvm`) | 276 library tests and 25 integration tests pass. Two library tests are `#[ignore]`d (a perf smoke and a measurement that needs environment variables). |
| Conformance vectors | pass on the interpreter and the JIT |
| Compiler | 75 tests pass; one `#[ignore]`d diagnostic |
| Program format, codec | 9 and 68 tests pass |
| vos-raft, merkle-crdt | pass |
| Prover library | 120 tests pass |
| Prover integration, default features | 30 of 31 suites pass. `prove_vos_actor` fails 5 of 35 (JAR blob fixtures, as on the unmodified saga). |
| Prover gates behind `debug-internals` | 8 suites, all pass (see below) |
| Verifier, precompile shim | pass |
| Bench agreement test | passes |
| fmt, clippy (`-D warnings`) | clean |
| `jar-check` | 230 remnants; joins `ci` after step 1.2 |

**Findings while setting up the baseline:**

- **The soundness gates were not running.** Eight gate suites, including
  the memory-zone, host-call dispatch, CPU halt and boundary gates, compile
  only with `--features debug-internals`, so a default test run executes
  none of them. `just test-proof` now enables the feature.
- **The precompile prototype had broken one of them unnoticed.**
  `host_call_dispatch_gate` encoded the host-call id as one byte and
  matched rows by the wire id. Both were fixed for the new `0x400` id and
  the separate dispatch code. Its soundness checks pass: a cleared or
  swapped precompile selector is rejected.
- **The settlement verifier's tests run nothing.** `settle_run` and
  `settle_transpile` "pass" in 0.00 s because the verifier program is not
  built. Step 1.2 ports them and makes them fail when the program is
  missing.
- **One test is parked:** `voucher_check_smoke.rs` sits in
  `pvm/proof/tests/to-port/`, uncompiled, because it depended on master's
  `vos` crate. Step 1.2 ports it back.
- **`#[ignore]`d tests:** two in the runtime, one in the compiler and one in
  the prover (`chip_isolated`). All are diagnostics or perf smokes. Step 1.2
  turns them into benches or deletes them.

**Benches on this tree** (match the spikes; medians):

| | Interpreter | JIT |
|---|---|---|
| Node host call from the agent | 0.12 µs | 0.10 µs |
| Agent machine per refine | 148 µs | 59 µs |
| Actor create + layout | 145 µs | 54 µs |
| Actor first call | 1.0 µs | 368 µs |
| Nested transfer, warm (fixed / per request) | 1,399 µs / 4.8 µs | 892 µs / 2.8 µs |
| Fresh machine per request | 156 µs | 463 µs |
| Snapshot restore, fresh machine | 1.6–2.3 ms | 0.08–0.10 ms (0.5–0.7 ms for the 2 MiB compute image) |
| Snapshot scan, all writable pages | 0.5–1.1 ms | — |

These are the numbers steps 1.4–1.6 must move: machine creation ≤ 50 µs,
pooled acquire plus reset ≤ 5 µs, and refine fixed cost ≤ 50 µs.

## Step 1.2: remove JAR (done)

**Stage 1, flip the defaults.** The `IsaMode` default, `Interpreter::with_memory`,
`GasSimulator::new` and the JIT's constructor now select the Gray Paper
profile. Everything that broke:

- 30 runtime unit tests, of two kinds:
  - JAR-only behaviour: the JAR gas simulator, the GP 0.7.2 per-instruction
    gas model, the private `ecall`. These are deleted in stage 3.
  - Generic instruction tests that hard-code JAR opcode numbers (reverse
    bytes is 111 in JAR, 110 in the Gray Paper) or JAR exits (trap as
    `Trap`). These are ported.
- One prover library test, in `actor.rs` (JAR blob tracing), deleted in
  stage 3.
- `prove_vos_actor`: the same 5 failures as before, on the checked-in JAR
  `.pvm` blobs of `hash-bench`. Several of its other "passing" tests skip
  silently because their fixtures (built on master's `vos` framework) are
  never built.

Every other prover suite passes, including all eight soundness gates and
the conformance vectors.

**Stage 2, port what must survive:**

- **The settlement verifier now builds, runs and accepts** as a standard
  program. Its program had not compiled since a package rename (it called
  the old crate name), which the skipping tests hid. Its tests now fail
  rather than skip when `just build-settle` has not run.
- **`pvm/guest/pvm.ld` fixes,** from linking it:
  - `.text` follows the data instead of sitting at a fixed `0x900000`,
    which a 192 MiB heap arena overlapped;
  - the GOT and relocated read-only data go with the read-write data, where
    `lld` had placed the orphan `.got` below the read-write base.
- **Gray Paper versions of the JAR-only proof gates,** written before their
  JAR versions were deleted:
  - an unhandled host call cannot claim the advanced PC
    (`unhandled_host_call_rejects_forged_resume_pc`);
  - an honest low-zone store is not provable: the CPU AIR rejects the row
    and `prove` refuses the trace (`standard_low_zone_access_is_not_provable`);
  - the acknowledged-host-call gates use a real precompile, since the
    lifecycle stubs they used are gone.
- **A compiled guest proves end to end.** The only `hash-bench` workload with
  source moved to `pvm/bench/guests/diverse`. `tests/diverse_proof.rs` checks
  its output against the same computation done natively, then proves and
  verifies the run on the refine path (about 12 s). The old `prove_diverse`
  passed even when proving failed.

**Stage 3, delete.** Everything in the plan's appendix is gone, and
`just jar-check` finds no remnant:

- runtime: the capability kernel, `cap.rs`, `vm_pool.rs`, the JAR snapshot
  and program formats, `IsaMode`, `GasModel` (with the GP 0.7.2
  per-instruction model), the `Trap` and `Ecall` exits, opcode 3 and the
  shifted unary numbering, the memory-latency tiers, the heap fields, the
  JIT's capability bitmap, and the JIT's register-definition peephole (it
  never fired under the Gray Paper profile, which clears it after every
  instruction);
- compiler: the JAR blob emitter, `link_elf`, the capability-manifest
  opcode encoding and the `0x800` dynamic-ecall marker (CSR `0x800` is now an
  unknown CSR and traps, like any other);
- prover: `actor.rs`, the lifecycle stubs and `ECALL_VOS_*` ids, the
  capability-manifest tracer, `benches/actors.rs`, the JAR blobs; the ISA
  profile no longer threads through side notes and segments, and its
  column is filled with the Gray Paper tag 0 until stage 4 removes it;
- guest shim: the capability slot and padding loaded on every precompile
  call;
- tests and fixtures built on master's `vos` framework (`fibonacci`,
  `clerk-refine-bench`, `voucher-check`, `voucher_check_smoke`), listed in
  the plan's return table for steps 2 and 5;
- the GP 0.7.2 vector corpus (124 files).

**Findings while deleting:**

- **The refine harness charged a JAR initialization fee.** It charged 1,500
  gas per mapped page before running, which Gray Paper 0.8.0's Ψ_M does not.
  For the settlement verifier, with its 192 MiB heap, that was 73,789,500 of
  the 102,671,695 gas first recorded in `spikes.md`. Without it the verify
  takes 10,677,000 instructions and 28,882,195 gas; `spikes.md` and the core
  model are corrected.
- **The v0.8.0 instruction corpus recorded per-instruction gas.** Its
  `expected.gas` was GP 0.7.2's flat model, and three cases depended on it.
  The column and those three cases are gone; every remaining case now runs
  on both backends with exact interpreter-JIT gas agreement, and the 16
  independently derived block-gas vectors pin the gas model. Every other
  expected value in the corpus is unchanged.
- **Invalid opcodes never execute under Ψ.** The interpreter charged invalid
  byte 3 as JAR's `ecall` (100 cycles, ending the block) and other invalid
  bytes at 1 cycle, while the JIT charges them nothing. This cannot matter:
  Gray Paper 0.8.0's `deblob` rejects any program with an invalid opcode at
  an instruction start, so the parity check rightly skips such programs.
- **The prover proves only runs whose memory instructions complete.** A
  run ending in a memory exception (a page fault, or a low-zone access,
  which panics) has no proof; proving refuses it before building the trace.
  This is the existing design, which the deleted JAR gate never exercised.
  It does not limit attestable methods, whose proofs are of completed
  calls, but the privacy track should state it.
- **Proof format.** The refine bundle format is now version 3: the slice-exit
  tags are renumbered without `Trap` and `Ecall`, and the machine-state
  commitment no longer hashes the ISA profile, the gas model, the heap
  fields or the memory tier (domain tags `refine-execution-transcript/v2`,
  `refine-machine-state/v3`). The proof's allowed host calls are now exactly
  the precompiles, so ProgramMemory commitments change only for programs
  that contained a lifecycle stub.
- **For step 1.3:** the Ristretto and scalar precompile ids (110–114) are
  still outside the VOS range `0x400..=0x4ff`, and the plan's remark that
  the JIT charges 10 gas inline per `ecalli` no longer holds: that charge
  was JAR's inline `GAS` capability and is gone.

**Stage 4, remove the ISA-profile column.** After stage 3 the column was
always 0, pinned through the ProgramMemory lookup. It now leaves both chips
and the program-memory tuple (34 → 33 limbs), with 0 substituted into the
three constraints that read it:

- `IsStandardMemH = IsLoad + IsStore`;
- `HostCallContinuesH = HostCallAcknowledged`;
- the acknowledgment-forbids-JAR constraint disappears.

A continued host call must now select exactly one precompile relation
(`precompile_selector_sum = continues`, which replaces the at-most-one
constraint). With the existing `selected_dispatch = continues · dispatch`, a
continued call's committed dispatch is never zero, which covers the plan's
"allowed ⇒ dispatch ≠ 0" without an inverse column. A new gate clears both
the selector and the dispatch on an acknowledged row; it fails under the old
constraint and passes under the new one. A second gate forges a complete,
consistent precompile continuation on a trap row; the AIR rejects it. Proof
format 22 (Poseidon2 variant 23).

Fable signed off on the constraint diff, with no blocking findings: the
substitutions are exact, the new constraint is strictly stronger, and
nothing else read the column. Follow-ups for the step 1.4 re-pin, which
changes the format again anyway:

- `HostCallContinuesH` is now an alias of `HostCallAcknowledged`, and
  `HostCallAllowed` is implied by a non-zero dispatch; both columns can go.
- The memory-exception boundary rests on one condition: a slice's committed
  exit kind stays bound to its final row, so a prover cannot drop a
  faulting step and present the prefix as a complete run. That binding is
  in the slice commitment, unchanged here.

**Step 1.2 is done.**

