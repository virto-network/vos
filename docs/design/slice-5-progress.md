# Slice 5: progress

The log of build step 5, against `slice-5-proving.md`. Every number is
tagged measured, model or projected.

## Step 5.2: the reference Poseidon2 and a SIMD hasher

**Gate: failed as first written** (`proving.md` §3.2), on the 8 threads
of an Intel Core Ultra 7 155H (AVX2, no AVX-512):
- a window-kernel segment proves on Poseidon2 in **1.75–1.85×** Blake2s's
  time, against 1.5× [measured];
- a leaf's commitment of 25M permutations takes **0.63 s**, against 0.5 s
  [measured, and projected from the permutation rate].

What dominates is the permutation itself: about 112M a segment, 95% in
leaves, take 58% of the Poseidon2 prove's cycles, and the packed
permutation runs at Plonky3's own speed on this machine.

### The decision: Poseidon2-M31 stays the segment channel

**The owner's, on 2026-10-16.** The gate becomes a segment's total cost,
its proving plus its leaf, against the Blake2s route's projection. Per
segment at the 32k cut:
- **Poseidon2:** about 5.6 s to prove [measured] plus a leaf of about
  1.5–3 s [projected]: about 7.1–8.6 s.
- **Blake2s:** about 3.1 s to prove [measured] plus a leaf with
  in-circuit Blake2s of about 4.5–6 s [projected]: about 7.6–9.1 s.
- **The Blake2s route would also** add a Blake2s gate to the recursion
  AIR and re-derive its padded shape and fixed point.
- **The fallback is dropped:** no Blake2s gate in the recursion AIR, and
  segments prove on Poseidon2-M31.

### The permutation

- **The reference arrangement** (`pvm/proof/src/poseidon2/mod.rs:318-355`,
  `permute_with` and `full_round`): the external matrix once, 4 full
  rounds, 14 partial rounds, 4 full rounds. A full round adds its
  constants, applies `x^5` to every word, then the external matrix; a
  partial round adds its constant to word 0, applies `x^5` to it, then
  the internal matrix. Before, each linear layer preceded its S-box layer
  and there was no first external matrix (Stwo's example order).
- **Plonky3's parameters at `f983316`:**
  - the external matrix `circ(2·M4, M4, M4, M4)` with Plonky3's
    `M4 = [[2,3,1,1],[1,2,3,1],[1,1,2,3],[3,1,1,2]]` (`apply_m4` and
    `apply_external_round_matrix`, `:250-296`); vos had HorizenLabs'
    `[[5,7,1,3],…]`;
  - the internal matrix `1 + diag(-2, 2^0, 2^1, …, 2^8, 2^10, 2^12, 2^13,
    2^14, 2^15, 2^16)` (`INTERNAL_DIAG_SHIFTS`, `INTERNAL_DIAGONAL`,
    `apply_internal_round_matrix`, `:229-310`); vos had
    `diag(2^1, …, 2^16)`;
  - the Grain round constants: unchanged, they were already Plonky3's
    `MERSENNE31_POSEIDON2_RC_16_EXTERNAL_INITIAL`, `_EXTERNAL_FINAL` and
    `_INTERNAL`, and `poseidon2_round_constants` still re-derives them.
- **The vectors, bit for bit** (`poseidon2::tests`):
  - `test_default_mersenne31_poseidon2_width_16`: input 0..15 under the
    reference constants;
  - `test_poseidon2_width_16_random`: Sage's vector under the constants
    `Xoroshiro128Plus` seed 1 draws (the generator and Plonky3's rejection
    sampling written out in the test), through `permute_with`;
  - the two matrices checked on unit vectors.
- **Modes unchanged:** the sponge (rate 8, capacity 8), the leaf and node
  layouts and the channel.
- **The settlement verifier** carries the same permutation. Its unused
  degree-2 permutation AIR fragment (`eval_permutation`) is deleted
  rather than rewritten untested; the recursion AIR's `p2` replaces it.
  On the PVM it accepts the regenerated fixture in **11,427,015
  instructions** [measured].

### The SIMD hasher

**Adapted, not depended on.** Plonky3 at `f983316` does not build on the
workspace's pinned nightly-2025-07-14 (`p3-util` uses `maybe_uninit_slice`,
stabilized later), and the pinned Stwo does not build on the nightlies
Plonky3 needs (`array_chunks` was removed), so the two cannot share a
toolchain. A dependency would also bring about fifteen crates into the
prover (`p3-field`, `-dft`, `-matrix`, `-mds`, `-poseidon1`, `-poseidon2`,
`-symmetric`, `-util`, `-maybe-rayon`, `rand` 0.10, `num-bigint` 0.5,
`itertools` 0.15, `paste`, `spin`, `tracing`) for the few functions used.

- **What was adapted** (`pvm/proof/src/poseidon2/packed/`, prover only):
  per instruction set, modular add and subtract, the fused round
  constant and `x^5` (`exp5`), and the rotations that multiply by the
  internal diagonal; the arrangement is written once over them. Headers
  name each source file at `f983316` and the change made;
  `LICENSE-PLONKY3-MIT` keeps the notice. The verifier stays on the
  scalar code, with no new dependency.
- **Sixteen lanes a call**, as one 512-bit, two 256-bit or four 128-bit
  registers a word, so independent lanes interleave. The instruction set
  is chosen at compile time by `target_feature`, as Stwo's `SimdBackend`
  chooses its own: AVX-512F, else AVX2, else NEON, else the scalar
  permutation lane by lane.
- **On `SimdBackend`** (`poseidon2/simd_backend.rs`): leaves (the lifted
  algorithm, sixteen sponges a block, finalized before the last lift),
  nodes and the grind. Roots and nonces equal `CpuBackend`'s; the grind
  returns the smallest nonce, as `CpuBackend`'s does.
- **A generic permutation over Stwo's `PackedM31`** was tried first:
  440 ns a permutation against Plonky3's 200 ns, both under a load
  average of about 24 [measured], so it was dropped.
- **Tests:** sixteen lanes equal the scalar permutation on 1,024 random
  states with `0`, `P` and `P - 1` among the words; leaves equal
  `CpuBackend`'s over lifted groups straddling a block and the sixteen-leaf
  boundary; nodes; the grind's nonce; a committed tree decommits,
  verifies, and refuses a changed value.
- **Where they ran:** AVX2 on this machine; the scalar fallback in a
  build without `target-cpu=native`; NEON under `qemu-aarch64`
  (`cargo test --target aarch64-unknown-linux-gnu`). The 11 Poseidon2
  tests pass on each. AVX-512F is compiled and linted
  (`-C target-feature=+avx512f`) but **not run**: this machine has no
  AVX-512. Its `exp5` reads sign bits with `vpcmpd` (F) where Plonky3 uses
  `vpmovd2m` (DQ).

### The gate's numbers

**Permutations** (`cargo bench --bench poseidon2`, load average 0.25)
[measured]:

| | 1 thread | 8 threads |
|---|---|---|
| scalar | 1.47 M/s | 7.05 M/s |
| packed (AVX2) | 10.78 M/s | 39.45 M/s |
| Plonky3's own packed, same machine (its own toolchain) | 11.7 M/s | 40.5 M/s |

- The 8 threads span the 155H's 6 P-cores (hyper-threaded) and its
  E-cores; 6, 12 and 16 threads reach 49, 44 and 51 M/s.
- **A leaf's commitment, 25M permutations:** 0.634 s projected from the
  rate, and **0.629 s** measured committing 176 columns of 2^20 rows
  (25.2M permutations) on `SimdBackend`. The same columns under Blake2s:
  0.118 s.

**A window-kernel segment** (spike 3's kernel, `n1000000-j2`, 32,768
steps and 8 pages, MOBILE, the full shape, since the `d165a7b6` seam is
not on `vos-core`), 5 segments, `RAYON_NUM_THREADS=8`, under
`systemd-run` at 16 GiB, load average 4.4–7.7 before the runs
[measured]:

| Channel | Prove, 5 segments | Per segment | Against Blake2s |
|---|---|---|---|
| Blake2s (format 24) | 14.94, 16.03, 16.19 s | 2.1–3.8 s | 1 |
| Poseidon2, this step | 27.01, 28.03, 29.91 s | 4.4–7.4 s | 1.75–1.85× |
| Poseidon2, before (spike 3's binary) | 102.98 s | 15.9–24.0 s | 6.4–6.9× |

- **What dominates** [measured]: per segment about 107M leaf
  permutations and 5.5M node permutations (77M and 1.6M for the
  868-step tail); the grind takes 16–36 ms. Under `perf`,
  `permute_x16` is 57.6% of the Poseidon2 prove's user cycles; Blake2s's
  compression is 20.0% of its prove's.
- The proofs verify standalone, 0.08 s a segment on Poseidon2 against
  0.026 s on Blake2s; proof sizes are unchanged (2.56–2.61 MB in
  bincode).

### Regenerated fixtures

- `pvm/proof/settlement-verifier/fixtures/bool_proof.postcard`, by
  `settle_fixture`.
- No other fixture or pinned constant depends on the permutation: the
  format 25 tests compute their commitments at run time, and the round
  constants did not change.

### Gates

- `just check`: green.
- `just test-proof`'s suites, under `systemd-run` at 16 GiB with
  `nice -n 10` and one test thread: green, the settlement verifier's PVM
  run included.
- Clippy with `-D warnings` for AVX-512F, the scalar fallback and
  aarch64 as well as the host.

## Step 5.5: the witness-input precompile, the run's ends and the io-hash

### The witness input, `0x401`

- **Served alike everywhere:** `vos_pvm::precompile::WitnessInput` serves a
  call: φ7 the destination, φ8 the capacity, `min(capacity, remaining)`
  bytes written there and their count in φ7, 0 at the end. The testkit's
  model and the tracer serve through it; the agent serves through its own
  `Machine::witness_input`, on VOS and JAM alike (the agent serves its
  kernels on both). A call that cannot pay stops the kernel out of gas, one
  whose bytes cannot land traps it, and a handler's call of `0x401` is an
  id the agent does not serve (`WHAT`).
- **Its price** (decided here): 2,500 a call, an actor's `input`, plus 24 a
  byte, an actor's per-byte price, charged before the bytes are written;
  the agent takes `PRECOMPILE_SERVING` (27,000) from the batch's meter a
  call, as for every precompile. A kernel's 64 KiB of arguments cost
  1,575,364 gas [model].
- **The record:** `Attest { program, witness_input, output }`: the bytes the
  kernel read, in call order, at most 4 MiB. **Deviation from the plan:**
  it replaces `arguments` rather than joining it. The kernel now reads its
  arguments through the input, so the two would hold the same bytes, and a
  step's sixteen attests at both caps would pass the work result's 4 MiB
  (`cap::step_result` sizes an attest at its arguments and output: about
  3.42 MiB of 4 MiB today, 4.42 MiB with both) [model].
- **`derive`'s prologue** (`TRANSPILER_VERSION` 3, 29 instructions): it
  reads the input into 17 zero pages past the kernel's read-write data
  (room for a request's 64 KiB and a byte), calls until a call returns 0,
  traps if it filled them, calls the entry on the bytes, and returns to
  the halt address with the output in φ7/φ8 and the io-hash in φ9..φ12.
  The loader maps no arguments and leaves φ8 at 0. `derive` admits
  `0x401` (`is_kernel_call`).
- **The image root:** each `Derivation` kernel (`records::Kernel`) names
  `image_root`, the page tree's root over its initial memory with no
  arguments (`vos_pvm_program::image`), computed in `Derivation::new` at
  install, the VOS node's and the JAM builder's alike.

### The io-hash

`compute_io_hash(public_args, output, roots)` (`vos_pvm_precompiles::io`):
BLAKE2b-256 of `vos/io/v1`, then the three fields SCALE-encoded (a compact
length and the bytes; a compact count and each `RootRead` as kind, space,
LE window and root, 73 bytes). On the PVM it hashes through `0x400`. The
SDK's attestable entry computes it on its encoded output, with no public
arguments and no roots, and the prologue leaves it in φ9..φ12.

### The AIR binding (format 26, Poseidon2 27)

- **CpuChip:** `IsWitnessEcall` selects dispatch 101, committed in
  PROGRAM_MEMORY like `0x400`'s. Its row reads φ7 and φ8 at its timestamp
  (the register reads Ristretto's ids share), writes the count to φ7 alone
  (`ResultIsReg`, `ResultRegIdx` 7), a count below 2^24 at a destination
  below 2^32; `WitnessNonEmpty` (with an inverse) is set exactly when the
  count is not zero. Four new emissions: `(φ8, count, lt = 0)` twice to
  CompareChip, so the count is at most φ8, and `(ts, destination, count)`
  twice to the new relation `WitnessCall` when non-empty. Four columns.
- **`WitnessInputChip`** (index 13; `chip_idx::COUNT` 32 → 33, so the
  component mask is a `u64`): one row a byte, 22 columns, 8 lookups. A
  call's first row consumes its tuple; while bytes are left a row is
  followed by the call's next byte, at its timestamp, the next address (a
  carry chain with every byte range-checked, no wrap past 2^32) and one
  fewer left; the last has one left; a row that does not start a call
  follows one that goes on. Each row writes its byte to the memory ledger.
- **The register ledger sorts reads before writes** within a timestamp
  (key `2·ts + is_write`). Without it a prover could order the witness
  call's φ7 read after its write and read the count as the destination;
  the same freedom let a step reading and writing one register (an ALU op
  whose destination is a source) read its own result. A same-register gap
  of 2^27 steps is now the limit, past the 100M-step budget.
- **The halt:** a halting step's `next_pc` is `PVM_HALT_ADDR`, in the
  tracer, the Refine prover's observation and CpuChip's two halt
  selectors, so a segment's `pc_out` is the halt address exactly when it
  ends at a halt.

### Tests

- live ≡ traced (`pvm/proof/tests/witness_input.rs`): each of the
  `kernels` actor's three kernels, attested on the agent's model on 0, 4
  and 200 values, re-runs from its attest (`kernel::trace_kernel`) to the
  same output and to `compute_io_hash(&[], output, &[])`, reading its
  recorded input whole; the agent's own tests hold its attests equal to
  the model's on VOS and JAM;
- the cursors at every call: one reader program, pinned on both sides
  (`tracking.rs` for the agent, `witness_input.rs` for the tracer): three
  bytes, none, four, a short read of three, a read at the end, cursors
  0, 3, 3, 7, 10;
- a short read returns its count and a read at the end 0: there, and
  `vos_pvm`'s unit tests;
- writes outside the named range refused: a write moved one byte past or
  before its destination, a byte past or short of the count, and a count
  past its capacity each fail verification (the last passes once the
  compare emission is removed); the column-level gates
  (`witness_input_gate.rs`) for every CpuChip and WitnessInputChip
  constraint, and the ledger's read-after-write;
- an oversize input refused: past 4 MiB by `WitnessInput`, the tracer and
  the agent; past a request's bytes by the prologue, on every host;
- the initial root equals the install's, the derivation's and the first
  segment's proven `memory_root`;
- a halting run's last segment ends at the halt address, and a segment
  cut just before the halting step ends at that step's pc; the chain
  verifies.

### Numbers

- **The `kernels` actor's kernels, re-traced** [measured]: `named` 891
  steps whatever its input; `digest` 1,797, 2,537 and 20,394 steps on 0,
  4 and 200 values; `areas` 925, 1,697 and 31,094. Each reads its input
  in two calls, the second at the end; the prologue, the entry's decoding
  and the io-hash's one compression are in every count.
- **The witness input's AIR cost** [model]: a row of 22 columns a byte
  in WitnessInputChip, and four columns on the CPU; a kernel's 64 KiB of
  arguments is a 2^16-row chip.
- **The gates** [measured, on this machine]: `just check` green, 1,006
  tests; `just test-proof` under `systemd-run` at 16 GiB with `nice -n
  10` and two threads green, 527 tests in its first suite, 1,002 s in all.

### The operand binding (format 26, Poseidon2 27)

Fable's review of 5.5 found CpuChip bound no register index or
register-source flag to the instruction: a ThreeReg row could drop its
ValB read, take any ValB, and write the sum to φ9, an arbitrary io-hash.
The fix, and the holes of the same class it turned up:

- **The flag bag is 80 bits in 10 bytes** (`PROG_MEMORY_N_FLAGS`; the
  instruction tuple 32 → 36 limbs). Byte 6 is the instruction's register
  accesses (`reg_access::access_shape`: ValB from φA or φB or none, ValD
  from φB or the immediate, the result to φA or φD or none) with the
  remainder bit of a division and the two operand swaps; bytes 7–9 the
  compare, branch and bitwise sub-operations, which were bound only as
  sums (an `And` could be applied as an `Or`, a `MinU` as a `CmovIz`
  writing anything). CpuChip recomposes bytes 6–9 from their bits, each
  boolean, in its own constraints (no new lookups); the indices are
  `ValBRegIdx = RegB + ValBFromA·(RegA − RegB)`, `ValDRegIdx = RegB`,
  `ResultRegIdx = RegA + ResultToD·(RegD − RegA) + 7·IsWitnessEcall`. A
  conditional move's result bit is its move, a witness call's its count.
- **Every instruction's write is recorded** (`tracing::recorded_write`,
  shared with the Refine prover's observation), even of the value the
  register held, so `ResultIsReg` is fixed by the instruction.
- **An immediate operand is the instruction's:** `RegValD` is ValD's
  source, its register or the immediate, pinned to `ImmBytes`; ValD was
  free on every immediate instruction (`LoadImm φ4 = 42` could load
  anything). `LoadImmJump` moves its immediate and `LoadImmJumpInd`'s
  result is its `imm_x`; both results were free.
- **Shift amounts:** the identity `RegValD = ShiftAmount + modulus·q` was
  over M31 with an unchecked 8-byte q, so any amount satisfied it, and it
  was ungated on immediate shifts. It is now on the low byte, with q's
  bits (3 and 4 columns), over the integers; `IsShiftConstrained = IsShift`.
- **MemoryChip** sorts by `2·ts + is_write`, as the register ledger does,
  and its `IsWrite` and `IsPadding` are boolean.
- **Lookup tables keyed by main columns:** Range256, BitwiseAnd and
  PowerOfTwo read their entries from main columns a prover fills, not
  their committed preprocessed ones; any Range256 check was void. They now
  read the preprocessed columns; their main traces are multiplicities.
- **Smaller ones:** the register ledger's `IsPadding` is boolean; the
  jump table's padding rows (tuple `(0, 0)`) take no multiplicity
  (`IsEntry`); a MemoryPage page is real on all its 32 rows, so it always
  produces its leaf; derive and ProgramMemory refuse a static jump to the
  halt address; a witness call that writes no bytes may name any
  destination, as the live call does.

Each forgery is a gate that the old code accepted and the new refuses:
`operand_binding_gate.rs` (12), `memory_ledger_gate.rs` (2),
`jump_table_gate.rs` (1), and `witness_input.rs`'s zero-count call
(which failed to prove before).

### Findings, not fixed here

An audit of the other chips for the same class reported these; they are
the next fixes:

- **The register ledger's merged read slots** (`Ts1..Ts3`) are not
  ordered: a read can take a stale value by riding an earlier row.
- **Mul and DivRem carries** are not range-checked, nor the top carry
  pinned: a product or quotient can be wrong; DivRem's `|r| < |d|` chain
  uses unchecked carries.
- **BLAKE2b:** the write addresses are pinned on row 0 only, and the
  main chip's `IsReal` is not held across its 96 rows.
- ~~**Ristretto:** ids 110–114 compute nothing tied to memory, row roles
  and source rows in the comb chips are free, `IsFixedBase` is not
  checked against the base point.~~ Resolved by removal: the chips and
  the ids are gone (below).
- **Shifts right:** nothing distinguishes `ShloR` from `SharR` in the
  AIR (both prove either quotient).
- `ShloL/ShloR/SharRImmAlt` take their operands unswapped and do not
  prove (completeness only).

### The Ristretto chips removed (format 28, Poseidon2 29)

The owner's decision: the Ristretto and scalar chips were unsound (the
finding above), derive already refused a kernel using them, and slice 7's
generic bignum chip replaces them.

- **Gone:** the eight chips (`RistrettoChip`, `RistrettoEcallChip`, the
  comb table, its anchor, scalar boundary, fixed-base consumer, compress
  and compress-output chips), their eleven relations, CpuChip's five
  `Is{110..114}Ecall` selectors and their emissions, the tracer's handlers
  and records, the side note's streams, the segment cutter's and cursors'
  streams, the shim's `ristretto` feature (`Scalar`, `RistrettoPoint`) and
  `curve25519-dalek` from the prover and the shim.
- **The ids:** 110–114 are no precompile anywhere: the tracer does not
  serve them (`proof_precompile_dispatch_id` is 0), the runtime neither
  serves nor prices them, and derive refuses a kernel reaching one; a test
  pins each.
- **The AIR:** `chip_idx::COUNT` 33 → 25, `BITWISE_AND_BYTE` at 24, so the
  component mask is a `u32` again. A witness-input call keeps its φ7 and
  φ8 register reads, now in a block of their own.
- **The full width** [measured]: a full canonical segment (every chip,
  mask `0x1ffffff`) commits **7,556 columns**: 173 preprocessed, 5,107
  main, 2,268 interaction, 8 composition. It was 13,037 with the
  Ristretto chips, at 32 chips. The full shape now fits under a kernel
  leaf's ~9,300-column headroom [model].
- **Tests:** the Ristretto suites are deleted (`comb_value_sweep`,
  `ristretto_ts_gate`, the Ristretto parts of `precompiles` and
  `chip_isolated`); the dispatch gates and the host-call pc gates now run
  on BLAKE2b and the witness input; the segment fixture threads three
  BLAKE2b compressions across its windows.
- **Gates** [measured, on this machine]: `just check` green, 998 tests;
  `just test-proof` under `systemd-run` at 16 GiB with `nice -n 10` green,
  465 tests (the prover's library 132 → 91 unit tests); `just
  test-bench-proof` green; clippy clean on every feature set of `just
  clippy` that touches the prover.

## Step 5.7: the items carried from slice 4

### Per-target limits (the owner's decision)

**Built:**
- **An agent runs on one target,** VOS or JAM (`cap::Target`): an
  agent runs on one host, so every instance installed into it takes its
  target. Its first install records it (`keys::target`); a later install
  naming another is refused, `Failure::Target` (13), and a JAM builder
  takes installs for JAM alone (`Error::Target`), as the agent refined
  from a witness does itself, its first install included, its refusal's
  detail JAM. `Admin::Install` and the
  `Installed` record name it; a workflow keeps it in its record (format
  5). The agent and the model hold every instance to the target's
  `cap::Limits` on every host, so a builder's simulation, the JAM refine
  and a VOS node replaying the batch agree. A refused install's detail
  is a `cap::Refused`, naming the limit and the figure, which the
  operator's CLI prints. An install now reads applied state, the
  agent's target: a host serving none traps on it, as on a request.
- **JAM's limits** (`cap::JAM`), each within VOS's (asserted):

  | | VOS | JAM |
  |---|---|---|
  | A step's writes | 256 KiB, rows by gas (about 3,125) | 16 KiB in at most 128 rows |
  | Messages, each's arguments | 16, 64 KiB | 8, 2 KiB |
  | Attests, each's arguments and output | 16, 64 KiB | 8, 2 KiB |
  | Pages a workflow's program may write | 4,096 | 256 |
  | Pages a step writes, pages held | 8 MiB, 576 | 256 KiB, 64 |
  | Checked at install: pages, program, kernels | — , 64 MiB, 1,024 | 256 (the whole heap), 512 KiB, 32 |
  | A kernel's gas | the caller's | the least of the caller's, its method's and 2,457,600 (4,096 compressions at 600) |

- **Derived from slice 4's budgets** (model, `vos_jam::gas::effects`): at
  VOS's caps a step's effects take up to about 1.40e9 gas of a package's
  own work, past PolkaJam's 1e9; at JAM's, 39.4M, 35.6 times fewer.
  `WORST_JAM_STEP`, a step restoring, storing and dropping every page a
  JAM workflow holds and ending it, with its effects at their limits, is
  839M of the 950M usable, asserted at compile time. The worst VOS
  ending with its effects is about 2.31e9.
- **`#[attestable(gas = N)]`** declares a kernel's gas. On JAM a kernel
  runs within the least of the caller's gas, the declared gas and
  2,457,600 (`Limits::kernel_gas`), what 4,096 compressions, each served
  in software (`PRECOMPILE_SERVING`), pay for; one declaring none takes
  2,457,600, and one declaring more is refused at install, by the agent
  (`Refused::KernelGas`) and, naming the method, by `vos_jam`'s
  derivation. The least holds even were an attesting instance's target
  another than the step's.
- **An attest is served apart** from the inlined frame a nested call
  takes a level (`Invocation::attest`, `#[inline(never)]`): computing its
  kernel's gas inline grew that frame past what 63 levels of the agent's
  stack hold.
- **One page price everywhere,** unchanged: the limits cap a step and
  never price it.
- **The JAM testnet** installs its actors for JAM, the shop built with
  the default heap (`lean`). So do the paired JAM tests, now for JAM
  throughout; those that drove VOS's caps on JAM drive JAM's: the
  budget lowered by four steps of 120 distinct puts, the ending at 56 of
  JAM's 64 pages beside 32 such steps (7 fit), the segments by 64
  computations of 48 pages, and an upgrade to the shop with a 640 KiB
  heap (`compact`).

**Tests:**
- at the edge of each JAM effect limit and one past it (messages, rows,
  bytes written; attests, 8 against 9, their arguments and their output,
  2 KiB against 2 KiB and a byte): `Cap` for JAM alone, on a VOS node and
  on the JAM-only host, as the model;
- a kernel past its declared 50,000 gas fails the step `OutOfGas` on JAM,
  and runs on VOS;
- installs past JAM's static limits are refused, `Cap`, each with its
  `Refused` detail and no record written: the pages (the shop's 4 MiB
  heap), the kernels (33), the program's bytes (640 KiB of data), and an
  attestable declaring 3,000,000 gas; the ledger, its attestable
  declaring none, and the default-heap shop install;
- an install for another target than its agent's is refused, `Target`;
  a refused first install records none;
- the builder refuses an install for VOS, its store untouched;
- a JAM workflow past its step's pages, and past its held pages, fails
  `Cap`; the same for VOS pauses;
- derived kernels run for both targets on both hosts, as the model;
- a compile-fail case: `#[attestable]` takes no role;
- `the_jam_limits_fit_a_package` prints and checks the figures above.

### DA: a waiting workflow's pages

**Chosen: the deterministic failure.** The core model (§12) and slice
4's F2 left re-export or failure open. Failing is a rule the agent
keeps, the same on every host and checkable on chain, where re-export
is a duty of the builder's, and a workflow whose builder was away past
retention would wait for good.

**Built:**
- JAM keeps a workflow's pages 27 days (`cap::JAM_PAGES_KEPT`): the
  imports DA, the D³L, keeps an exported segment at least 28 days (672
  epochs) after the report of the package that exported it (Gray Paper
  0.8.0, §14.3.1, and §16 for assurers), less a day's margin for a report
  before its batch time and a resuming refine after it, each by at most
  the session skew and a few slots. A workflow's record keeps the batch
  time from which every page it holds has been stored
  (`Workflow::stored`): its start's, then that of a step after which it
  holds no page an earlier step stored. A conservative bound, by one time per record,
  never a page's own.
- A step due at or past `stored` plus the keep, while the workflow
  holds pages, ends it `Failure::Expired` (12) without restoring or
  importing them, its pages dropped and its owner told.
- The builder no longer leaves such a workflow out of a sweep; one whose
  pages DA lacks within the keep still waits.

**Tests:** a JAM workflow resumed just within the keep and one just past
it, on both hosts, as the model; the builder over the emulated chain,
DA emptied: the workflow left out within the keep, then ended
`Expired` past it in a package that imports nothing.

### A heap per kind of invocation

**Built:**
- The SDK's arena is a section of its own, `.vos_heap`, which the
  guest's linker script places last in the read-write data, its state
  apart. The allocator bumps fresh memory from the arena's start.
- **The derivation** (transpiler version 2) holds the arena's first 512
  KiB (`INVOCATION_HEAP`) in the actor's program and in each kernel, all
  a handler or a kernel maps, and records the pages past them,
  `Derivation::heap`. An ELF whose arena does not end its read-write data
  from a page is refused (`DeriveError::Heap`), no longer derived whole.
- **One constant:** `vos_wire::abi::INVOCATION_HEAP`, which the
  compiler's `INVOCATION_HEAP` and the SDK's default heap,
  `PROGRAM_HEAP`, both are.
- **The allocator knows the invocation:** in an actor's program
  (`Heap`'s const parameter `ACTOR`) it gives a handler or a kernel the arena's first 512
  KiB alone, so an allocation past them fails at once, Rust's
  allocation-failure path, and the step traps, `Trapped`, whether or not
  the memory would be touched; before, it bumped into pages the program
  does not map, and only a store there faulted. A workflow's dispatch
  arm marks the invocation first (`heap::whole_arena`), its snapshot
  keeping the mark, and it allocates from the whole arena. The agent's
  own heap and other programs' (`program_runtime!` alone) are whole.
- **A workflow's machine** maps those pages itself past its program's
  read-write data, zeroed, and arms them with its writable pages: its
  record's `writable` counts them, so `ARM_PAGE` pays for them.
- **A kernel's layout** is its program's alone, the same whatever heap
  its actor declares. The pinned fixture is now the kernels actor built
  with a 4 MiB heap (`roomy`): 896 pages left out.
- On JAM a handler of the 4 MiB shop now maps 512 KiB, not 4 MiB (model:
  about 15,000 gas of loading a call, not about 124,000).

**Tests:**
- a kernel's layout and its handlers' program equal across the kernels
  actor built with the default heap and with 4 MiB;
- the actor's program is `link_elf_spi`'s but for the heap pages it
  leaves out, which are exactly the arena's past 512 KiB;
- a workflow computing over 1 MiB on the derived shop runs to its end
  beside a handler, on both hosts, as the model maps the same pages;
- a handler of an actor with a 2 MiB heap (`ample`) reserving 1 MiB it
  never touches traps, and reserving 256 KiB runs, as the model; a
  workflow reserving 1 MiB runs to its end; the allocator's own test, an
  actor's heap against a program's;
- an arena moved off its page, and another writable section named
  `.vos_heap`, are refused;
- the derivation the same in every process; the pins.

### Measurements

Measured with the processes bench (`ROWS=resume` and `ROWS=catch-up`),
on the reference laptop's pinning, on this step's code (92337a67), so
after 5373e6cf changed how a workflow is restored: its machine maps the
heap its program leaves out. Under `nice -n 10` and a 16 GiB scope, on a
quiet machine, load 0.4–2.9. The leader runs in the bench's process, so
it can deliver replies itself as the one-node bench does; its followers
are `vos node run` processes over QUIC. A first pass, on the slice's
base (b7c4fd69) and so before 5373e6cf, gave the same figures within
their spread (medians 1.77–1.92 ms on three nodes, 1.25–1.30 ms alone;
catch-up past the tail 2.24–2.55 s).

| A workflow's resume, a reply in to its step applied | Median | p99 |
|---|---|---|
| Three nodes, synced commits on NVMe (4 runs) | 1.73–1.79 ms | 2.55–3.34 ms |
| Node 1 alone, the same runs | 1.18–1.22 ms | 1.95–2.80 ms |
| Three nodes, stores on tmpfs (2 runs) | 0.91–0.98 ms | 1.80–1.88 ms |
| Node 1 alone, tmpfs | 0.70–0.71 ms | 1.02–1.27 ms |

- 603 resumes a row. Replication adds about 0.45 ms to the commit on
  disk (925–966 µs against 481–514 µs): the QUIC round trip and the
  follower's synced flush beside the leader's own. The step's refine,
  restoring the workflow, takes 0.47–0.59 ms; queueing, proposing and
  applying about 0.15 ms.

| A follower's catch-up (4 runs) | Within the kept tail | Beyond it |
|---|---|---|
| Missed while down | 40 fills, 9.6 MB of results in 5 entries | 224–232 fills, 54–56 MB in 28–29 entries |
| Names its leader | 0.22–0.27 s | 0.58–0.61 s |
| Has applied the leader's commit | 0.92–0.96 s, from the log | 2.32–2.35 s, from a snapshot |

- **The settings** (`vos_node::Config`): compaction once 1,024 entries
  or 64 MiB, a large result counted by its blob, are applied durably; a
  kept tail of at most 256 entries and 16 MiB; snapshot chunks of 1
  MiB; a result of 64 KiB or more stored as a blob.
- The kept tail held 9–10 results of about 1.9 MB (measured), so 4.4c's
  "4 to 8" was for results of 2–4 MB.
- The snapshot carried 402–410 rows, 0.25 MB: the agent's state, not
  the log missed. About 1.7 s of the catch-up passes between naming the
  leader and installing it, which fits a stream begun while the follower
  was down, resent every 2 s (`CHUNK_RESEND`) (model, from the code).

### Ristretto ids 110–114

Already so: `derive` refuses a kernel reaching any host call but a
precompile, and these are none. A test now pins it for each of the five
ids, beside BLAKE2b's precompile, which derives. Since removed, chips and
ids (step 5.5's last section).

### PolkaJam

- **The re-probe** (`nightly-2026-10-13`, still the installed version:
  polkajam and jamt 0.1.29, Gray Paper 0.8.0, the same sha256): on the
  interpreter every record PolkaJam produces is unchanged, gas included
  (fault tracking, counters, segments by `wp:` and `sr:`, the 14
  starved and re-entry records, `solicit` and `historical_lookup`); the
  availability race and late `wp:` imports dropping recur. Our JAM-only
  host now agrees on 34 of the 36 fault records; `fetch` kind 0 still
  differs. Results in `spikes/sj-jam-b/results/2026-10-16-*`; `probe.sh`
  takes the backend from `POLKAVM_BACKEND`.
- **The recompiler run still waits.** `vm.unprivileged_userfaultfd` is
  1 now, but PolkaVM's sandbox reads every CPU's L3 cache entry, and
  this machine's two low-power cores have none: every node fails at
  start, and neither core pinning off nor CPU affinity helps. It needs a
  PolkaJam build that tolerates them, or another machine. Kernel
  settings were not touched.
- **The testnet on the interpreter, with this step's code** (`just
  jam-testnet`): the agent and its actors installed for JAM, the
  workflow across three later packages (70 pages exported, 104
  imported), every package landed at its first attempt, each work result
  read back from DA equal to the simulation's and the VOS node's, the
  testnet logging no error. Refines 0.26M–41.9M gas each (measured, on
  our JAM-only host).

### Also

- **A cluster test's flake, fixed:** under load the compaction test's
  leader moved while it sent its fifty increments; each is now sent
  again at its sequence to whichever node leads, waiting 10 ms before the
  first retry and twice as long before each next, to 500 ms, so an
  election has time to end.

**Gates:** `just check` on each commit, 995 tests at the last; the node suites at the end: cluster and processes in it, the faults process tests and the five-process fault suite.
