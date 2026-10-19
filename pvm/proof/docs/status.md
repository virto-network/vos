# vos-pvm-proof — implementation status

A snapshot of which constraints / chips bind which PVM semantics
in-circuit, and which gaps remain prover-trusted.  Phase numbers
in `[brackets]` match the commit-message tags on the `zkvm`
branch — `git log --oneline --grep "Phase N"` finds the relevant
commit.

## What's bound

### Core ALU
- **Add / Sub** — carry-chain identity over 8 bytes, gated per
  opcode.  32-bit variants sign-extend `result[4..8]` to
  `0xFF · SignBitResult` `[19]`.
- **NegAdd** — sub with flipped sign, same carry chain `[2]`.
- **Mul** — schoolbook over 16 byte positions, 16-bit carry per
  position (`MulCarry` + `MulCarryHi`) `[12c, 15-mul-debug]`; every
  product byte and carry Range256-checked, so the chain is the exact
  integer product.
- **MulUpper UU / SU / SS** — high 64 of full product, with
  sign-correction columns `MulCorrTermA` / `TermB` /
  `MulCorrCarry` distinguishing the three signedness variants
  `[12c]`.
- **DivU / RemU 32 / 64** — schoolbook `q · d + r = b + 2^W·H` over
  the integers (quotient, remainder, `H` and every carry Range256-checked),
  `H = 0`, with `r < d` uniqueness via a separate carry chain
  (`DivCmpDiff` / `DivCmpCarry`) `[7a, 21]`.
- **DivS / RemS 64-bit** — sign-correction at the schoolbook's
  high bytes via `DivCorrHi` / `DivCorrCarry`:
  `H ≡ sq·d_u + sd·q_u + sr − sa + k  (mod 2^64)`, `k` the `MIN / −1`
  overflow, and `|r| < |d|` through magnitude chains `[16]`.
- **DivS / RemS 32-bit** — analogous 4-byte chain, the divisor's magnitude
  taken of its sign-extended low word `[18]`.

### Bitwise
- **And / Or / Xor / AndInv / OrInv / Xnor** — algebraic identity
  per byte, plus per-nibble AND lookup against
  `BitwiseLookupChip` for soundness `[6]`.

### Shifts
- **ShloL** (left) — encoded via `is_mul=true`; uses
  `PowerOfTwoChip` to bind `val_d = 2^shift_amount` `[6]`.
- **ShloR** (logical right) / **SharR** (arithmetic right) —
  encoded via `is_div_rem=true`; same power-of-two lookup `[6]`. ShloR
  is unsigned division (`H = 0`); SharR, flagged `is_shar_r` in the
  DivRem tuple, floor division (`H ≡ sq·d − sa`).
- **32-bit shift ShiftAmount uniqueness** — closed by an
  additional `val_d[4..8] = 0` constraint on `is_32bit ·
  is_shift_c` rows.  Without this, the [0, 63] PowerOfTwo table
  admits two byte-bounded ShiftAmount values for any
  modulus-32 reg_val_d, and a malicious prover could pick val_d
  = 2^32 (instead of 2^0) for shift-by-32 to forge a 0 result
  `[37]`.

### Compare
- **SetLtU** — `cmp_lt_flag = 1 - cmp_carry[7]` from the
  subtraction chain `[2]`.
- **SetLtS** — sign-aware `cmp_lt_s_flag` derived from
  `SignBitB` / `SignBitD`, both pinned by nibble-AND lookups to
  bit 7 of the multiplexed source byte (val_b[7] in 64-bit,
  val_b[3] in 32-bit) `[17]`.
- **Min / Max** (signed and unsigned) — multiplex on the
  appropriate `cmp_lt_*_flag` `[2]`.

### Branches
- **BranchEq / Ne / Lt / Ge / Le / Gt** (signed and unsigned) —
  share the compare chain; `branch_taken` then drives `next_pc`
  selection `[2]`.
- **Static branch / jump targets** — bound to canonical
  `pc + sign_extend(offset)` via `ProgramMemoryChip`'s
  `BranchTargetCanon` column `[15-branch-target-fix]`.
- **Dynamic dispatch** (`JumpInd`, `LoadImmJumpInd`) — bound to
  jump-table targets via `JumpTableChip` lookup
  `(addr=val_b+imm, target=next_pc) ∈ jump_table` `[13d]`.
- **Trap** — terminal-row constraint forbids any successor real
  row after a Trap step (gated on per-opcode `IsTrap`)
  `[13e-redux]`.

### BitManip
- **ReverseBytes** — `result[i] = val_d[7−i]` `[12b-1]`.
- **ZeroExtend16** — `result[0..2] = val_d[0..2]`,
  `result[2..8] = 0` `[12b-1]`.
- **SignExtend8 / SignExtend16** — `result[i] = 0xFF·SignExtBit`
  on bytes ≥ source-width, with `SignExtBit` pinned to bit 7 of
  the source byte via nibble-AND lookups `[12b-2, 17]`.
- **CountSetBits32 / 64** — per-byte popcount via new
  `PopcountChip` lookup table; `result[0] = sum(BytePopcount[..N])`
  (N = 4 if Is32Bit, 8 if 64-bit), `result[1..8] = 0` `[33]`.
- **LeadingZeroBits / TrailingZeroBits 32 / 64** — per-byte
  (lz, tz) via new `BitcountChip` lookup table; result formulas
  walk a "first-non-zero-byte" indicator built from Phase 29's
  `ValDByteInv` byte-zero-check infra.  TZ uses Phase 29's
  LSB-direction `ValDPartialNZ` chain; LZ uses two new
  cumulative-OR chains: `ValDPartialNZMsb[8]` (MSB direction
  over all 8 bytes, for LZ64) and `ValDPartialNZMsbLo[4]` (MSB
  over the low 4 bytes only, for LZ32).  Default fallback is
  64 / 32 when val_d (or low 4 bytes) is zero.  `result[1..8] = 0`
  `[34]`.
- **RotL64** — encoded via the mul-schoolbook (`val_d = 2^n`):
  `result = UnsignedProductLow + mul_high` (byte-wise sum, no
  carry — bits non-overlapping by construction) `[32]`.
- **RotR64 / RotR64Imm** — same shape as RotL64 but with the
  *complementary* power: `val_d = 2^((64 − n) mod 64)` so the
  schoolbook's low + high yield the rotated-right value.  The
  complement is pinned via a second shift-amount identity
  `RegValD + ShiftAmountCompl = 64 · ShiftQuotientCompl` plus a
  separate PowerOfTwo lookup keyed on `ShiftAmountCompl` `[35]`.
- **RotL32 / RotR32 / RotR32Imm** — 32-bit equivalents of Phase
  32/35: the 32-bit mul-schoolbook now writes low-32 to
  `UnsignedProductLow[0..4]` (re-routed) and high-32 to
  `mul_high[0..4]`; rotate result low 4 bytes = sum of the two
  halves, high 4 bytes = sign-extension via Phase 19.  The
  complementary shift identity uses modulus 32 (vs 64 for the
  64-bit variants); a `val_d[4..8] = 0` constraint pins
  ShiftAmount/ShiftAmountCompl ∈ [0, 31] uniquely `[36]`.
- **RotR64ImmAlt / RotR32ImmAlt** — swapped-operand variants
  where the immediate is the rotated value and `regs[rb]` is the
  shift amount.  Trace fill swaps val_b ← imm and val_d ←
  regs[rb] on these rows; reg_access also swaps val_b_read /
  val_d_read.  A new `val_b ↔ ImmBytes` constraint (low 4 bytes
  always; high 4 bytes match-or-zero gated on IsTruncated, same
  shape as the val_b ↔ reg_val_b cross-constraint) pins the
  swapped source.  All other rotate-r logic re-uses Phase 35/36
  via the existing IsRotateR64 / IsRotateR32 flags `[40]`.

### Sign-bit pinning
- `SignBitB / SignBitD / SignBitQ / SignBitR` — each pinned to
  bit 7 of its multiplexed source byte (val_b[7]/val_b[3] etc.)
  via two `BitwiseLookupChip` emissions per real row:
  `(HiNib, 8, 8·SignBit)` and `(Src − 16·HiNib, 0xF, same)`
  `[17, 18]`.
- `SignBitResult` — bit 7 of `result[3]`, drives 32-bit ALU
  result sign-extension `[19]`.
- `LoadSignBit` — bit 7 of multiplexed source byte
  (`result[0]/result[1]/result[3]` for I8/I16/I32), drives
  inactive-byte sign-extension on signed loads `[20]`.

### Memory
- **MemSize** — pinned to opcode-canonical width via
  `IsMemSize1/2/4/8` flags (each pinned by ProgramMemoryChip)
  `[23]`.
- **MemByteActive** — boolean per byte, monotonic prefix-1 of
  length MemSize, sum equals MemSize `[22]`.
- **Active-byte load result**: `result[i] = mem_value[i]` on
  load rows for active bytes `[15-load-result]`.
- **Inactive-byte load result**: `result[i] = 0xFF · LoadSignBit`
  on load rows for inactive bytes (signed: 0xFF·sign; unsigned:
  0) `[20]`.
- **MemAddr direct** (LoadU8/I8/U16/I16/U32/I32/U64,
  StoreU8/U16/U32/U64): `MemAddr = ImmBytes[0..4]` (the `addr =
  imm` pattern) `[25]`.
- **MemAddr indirect** (LoadInd*, StoreInd*, StoreImmInd*):
  byte-wise add-with-carry chain pinning
  `MemAddr = (val_b + ImmBytes) mod 2^32` `[26]`.
- **MemValue on direct stores** (StoreU8/U16/U32/U64): pinned to
  val_b active bytes `[24]`.

### Register-memory
- **Per-step ledger** (`RegisterMemoryChip` + boundary):
  every `regs_before[r]` read and `regs_after[r]` write at every
  PVM step appears in a per-(reg, value, ts) lookup, bound to
  the snapshot at boundary `[9]`.
- **Source-operand binding**: `ValBIsReg` / `ValDIsReg` flags
  + `RegValB` / `RegValD` columns tie `val_b` / `val_d` to
  the actual register snapshot `[9d, 9f, 9g]`.

### Program structure
- **Bytecode commitment**: `ProgramMemoryChip` preprocessed
  table holds `(pc, opcode, skip_len, reg_a/b/d, imm,
  flag_bag, imm_y_canon, branch_target_canon)` per
  basic-block-starting PC.  Verifier checks the program-hash
  matches the canonical decoding of `(code, bitmask)`
  `[13a/b/c, 13f]`.
- **PC sequencing**: `ProgramExecutionLookup` ties step `n`'s
  `next_pc` to step `n+1`'s `pc`, plus initial / final boundary
  via `ProgramBoundaryChip` `[4]`.

### Precompile
- **Blake2b ECALL** — `Blake2bChip` proves one full 12-round
  compression per ECALL.  Initial / final-state lookup against
  `Blake2bStateBoundary`, message-block lookup against memory,
  H-pointer / M-pointer / T / F binding to register snapshot
  `[8a/b/c, 8d, 9c, 9d, 9e]`.

## Open soundness gaps

**Register / RAM ledger read-consistency is BOUND (format v6).**
`RegisterMemoryChip` and `MemoryChip` enforce read-after-write
soundly against a from-scratch prover: each read's value is bound
cross-row to the previous same-key row's value (`#[mask_next_row]`
`prev_value` binding), the ledger is sorted by `(key, ts)` via a
range-checked sortedness gadget (self-contained 28-bit decomposition),
and `is_write` is part of the logup tuple (register ledger widened to
18 limbs; the RAM tuple already carried it) so a read can't masquerade
as a write to skip the check.  This closes the previously-honest-only
gap — in particular the closing read that pins `final_state.registers`
/ the voucher io-hash is now sound.  Gate:
`tests/ledger_readconsistency_gate.rs`; see
`docs/design/ledger-read-consistency.md`.  `proof.memory_commitment`
remains separately unbound (computed outside the circuit — an
in-circuit memory-image commitment is still future work).

**Per-opcode ISA coverage: no known gaps.**  Every PVM ISA opcode
reachable from RISC-V actor code (or from synthetic forge tests) is
bound by an algebraic constraint or terminally constrained.  The
items the earlier draft of this file listed have all been closed:

- Memory: MemValue on indirect stores `[28]`; MemValue on
  StoreImm / StoreImmInd `[27]`; MemAddr on direct StoreImm
  `[27]`.
- Divrem: DivS `r < d` uniqueness `[30]` + sign-of-r `[31]`;
  DivByZero binding `[29]`.
- Sign / extension: CmovIz / CmovNz val_d_is_zero `[29]`
  (shared byte-wise zero-check with DivByZero).
- Rotate: RotL64 `[32]`, RotR64 + RotR64Imm `[35]`, RotL32 +
  RotR32 + RotR32Imm `[36]`, RotR64ImmAlt + RotR32ImmAlt `[40]`.
- BitManip: CountSetBits 32/64 `[33]`, LeadingZeroBits +
  TrailingZeroBits 32/64 `[34]`. The retired Sbrk opcode was removed from
  the standard AIR beginning in proof format 12 and remains absent in the
  PCS-config-bound Refine-closure/sparse-memory format 20 (Poseidon2-M31
  format 21; Refine bundle v2).
- Smaller: 32-bit shift ShiftAmount uniqueness `[37]`;
  is_write discriminator forge tests `[39]`.

If further gaps surface (e.g. via a forge test or a careful
re-audit), they belong here when discovered.

## Test posture

- **Direct soundness tests** — every `*_negative.rs` suite has
  forge-the-result tests for the corresponding op family
  (alu, control_flow, memory, register ledger).  Phase 38
  extended coverage to every Phase-32–36 BitManip and rotate
  opcode (CountSetBits 32/64, LeadingZeroBits 32/64,
  TrailingZeroBits 64, RotL/R 32/64, RotR64 wraparound).
- **Coverage caveat**: the `forge_three_reg_result` /
  `forge_two_reg_result` helpers only mutate
  `step.regs_after[rd]`.  Forgery on auxiliary witness columns
  (e.g. directly mutating `SignBitB` while keeping val_b honest,
  forge `q' = q − 1, r' = r + d` on DivU, …) requires a
  column-level mutator the test harness doesn't currently
  provide — in those cases the regression sweep being green is
  the practical "doesn't break" signal, while the constraint's
  own integer-vs-field analysis is the soundness argument.
  Note that `forge_step_field` does cover step-level mutation
  (opcode, reg_a/b/d, imm, skip_len) used in the bitmanip suite
  for Phase 13b/13c authentication tests.
- **Performance baseline**: `prove_vos_actor` proves real RISC-V
  actor binaries (blake2b ECALL, fibonacci, hash benches) in
  ~5 min on a modern x86 desktop.

## How to read the source

- Start with `CpuChip::add_constraints` (`src/chips/cpu/constraints/`) — that's
  where 90% of the soundness work lives.
- Follow constraints by phase number tagged in comments
  (`Phase 13d:`, `Phase 16:`, …) — each tag points at one
  commit's worth of changes.
- `src/chips/cpu/columns.rs` is the canonical column listing —
  every Column has a doc-comment with which phase added it and
  what it binds.
- `src/chips/cpu/CONSTRAINTS.md` is the house rules — read it
  before adding any new constraint or lookup.

## Proof format history

The proof format numbers, before the registry (`src/format.rs`) and since:
one number per build, and what each changed.

```text
  1 — Rotate / BitManip / 32-bit-shift / Sbrk all bound;
      PROG_MEMORY_N_FLAGS = 48; 14 components.
  2 — `RegisterMemoryClosingChip` added at index 6,
      shifting every higher chip index by +1; closes the register-
      memory ledger by consuming a synthetic per-register read at
      `closing_ts = last_step.timestamp + 1`, pinning the final
      register COLUMN to the trace's true final register values.
      The FS-transcript also mixes `final_state.registers`, making
      a finished proof tamper-evident. (See the SCOPE note in
      `chips/register_memory_closing.rs`: the mix does NOT bind the
      separate metadata FIELD against a from-scratch prover.) Older
      proofs reject at the `format_version` gate.
  3 — FS-transcript also mixes
      `proof.initial_state.registers` (before the existing
      `final_state.registers` mix) — same tamper-evidence on the
      initial side; the boundary chip already commits `initial_regs`
      in its trace.
  4 — Boundary pc + timestamp join the FS mix (after the register
      mixes; order: initial regs, final regs, initial pc, initial
      ts, final pc, final ts). Their in-circuit commitments already
      existed — ProgramBoundaryChip commits (InitialPc,
      InitialTimestamp) and (FinalNextPc, FinalNextTimestamp),
      telescoped through CpuChip's program-execution relation. So
      the mix extends the SAME tamper-evidence the registers have to
      pc and timestamp; `verify_chain`'s whole-struct boundary
      equality stops comparing pure metadata for those fields.
      LIMITATION (shared with the register mix since v2): the mix is
      tamper-evidence, NOT a binding constraint — a from-scratch
      prover can still ship self-consistent boundary metadata that
      differs from the committed columns. True binding needs a
      boundary public-input constraint (the conservation-of-value
      chain-verification project). `memory_commitment` is weaker
      still — computed outside the circuit, not even mixed.
  5 — Boundary public-input binding (metadata→column): closes the
      v2–v4 metadata-vs-column gap. Verifiers recompute each boundary
      chip's logup claimed sum from `proof.{initial,final}_state`
      (registers, pc, timestamp) with the FS-drawn lookup elements
      and require equality with `proof.claimed_sums` — binding the
      metadata fields to the committed boundary COLUMNS. A
      from-scratch prover that commits honest columns and ships lying
      metadata is now rejected (gate: `tests/boundary_binding.rs`).
      pc/timestamp become genuine bound public inputs (their columns
      are pinned to the trace by CpuChip program-execution chaining).
      REGISTERS are bound metadata→column only: their column→trace
      link is `RegisterMemoryChip` read-consistency, which is NOT
      enforced cross-row (a separate, pre-existing gap — a malicious
      prover can still forge the closing read's value and hence the
      io-hash; see `chips/register_memory_closing.rs` and
      `docs/plans/roadmap.md`). No AIR change — the
      proof bytes an honest prover produces are unchanged apart from
      this version field; the bump exists because older verifiers
      ACCEPT metadata forgeries that v5 verifiers reject, and proofs
      over EMPTY traces (which bind nothing) now reject. The
      standalone verifier additionally requires `component_mask` to
      contain the three binding chips and to popcount-match
      `num_components`. `memory_commitment` remains outside the
      binding (no committed column; see `segment.rs`).
  6 — Register/RAM ledger read-consistency bound (closes the v5
      register column→trace gap). `RegisterMemoryChip` and `MemoryChip`
      gain a cross-row `prev_value` binding (`#[mask_next_row]`) and a
      `(key, ts)` sortedness range-check (self-contained 24-bit
      decomposition), and the register ledger tuple gains an `is_write`
      limb (17→18; CpuChip / boundary / closing producers + the verifier
      boundary-binding recompute updated). The B5 register read-run merge
      is disabled (one entry per row). So a from-scratch prover can no
      longer forge a register/RAM read — in particular the closing read
      that pins `final_state.registers` / the actor io-hash is now
      sound. AIR change: new columns + the wider register relation, so
      the proof bytes differ (gate: `tests/ledger_readconsistency_gate.rs`).
      `memory_commitment` is still outside the binding.
  7 — In-circuit RAM-image binding (closes the memory-continuity
      gap `memory_commitment` left open). RAM is committed as a page-keyed
      blake2b Merkle tree; per segment the prover proves a boundary
      multiproof binding the entering page images to `initial_state
      .memory_root` and the exit images to `final_state.memory_root`
      (`Memory{Page,Merkle,RootBoundary}Chip` + `Blake2bBoundaryChip`), and
      the RAM ledger forces every accessed address into a listed page
      (per-page ts=0 boundary write + closing read, group-start/end
      constraints). The roots join the FS mix and `MemoryRootBoundaryChip`'s
      claimed sum is bound to them closed-form (`boundary_binding`). So
      `verify_chain_standalone(proofs, commitment, expected_initial_root)`
      becomes sound for memory continuity, not only tamper-evident. New
      components (`COUNT` 28 → 31, `MemoryBoundaryChip` deleted), a wider
      `MemoryAccess` tuple (`is_closing`), and a new `MerkleNode` relation,
      so the proof bytes differ.
  8 — Ristretto memory-op `ts` binding (closes the
      money-path ts-forgery gap where the three ristretto memory producers
      set `ts` as a free witness). CpuChip gains five `Is{110..114}Ecall`
      gates that emit a `RistrettoCall` (RELATION A) producer + register
      reads (φ[7,8,9]) per ristretto ECALL step; RistrettoEcallChip moves
      to a uniform 96-row preprocessed period that consumes RELATION A at a
      preprocessed-pinned `InitGate` (so its block `ts` == the chained CpuChip
      step ts ∈ [initial_ts, final_ts), excluding 0 and `closing_ts`) and
      re-emits the anchored ts to the two comb chips via `RistrettoFixedScalarTs`
      / `RistrettoFixedOutTs` (Tier-2); the comb chips consume those and add
      intra-call ts/ptr equality + per-byte authenticated `Addr`. Three new
      relations, a wider CpuChip, and restructured ristretto chips — no new
      CHIPS (`COUNT` unchanged at 31) — so the proof bytes differ and older
      verifiers must reject.
  10 — Register/RAM ledger ordering deltas widen from 24 to 28 bits. The
       former hidden `2^24` timestamp ceiling made long software-arithmetic
       actor traces unprovable at their terminal segment. Twenty-eight bits
       cover the canonical 100M-gas actor-proof budget while remaining well
       below the M31 modulus, preserving the wrapped-negative rejection the
       sortedness proof relies on. AIR column counts change, so older
       verifiers must reject. Version 9 was already assigned to the
       Poseidon2-M31 PCS variant of format 8.
  12 — Gray Paper v0.8.0 unary-opcode table: removes the retired `sbrk`
       opcode and renumbers CountSetBits64 through ReverseBytes from
       102..=111 to 101..=110. Program identities and opcode-bound CPU
       traces change, so v10 native-channel proofs must be rejected.
       Version 11 was the Poseidon2-M31 PCS variant of format 10.
  13 — Poseidon2-M31 PCS variant of format 12.
  14 — ISA-profile-bound program memory. Every authenticated instruction
       tuple now carries the container-derived profile (standard v0.8 or
       frozen capability manifest), and opcode decoding uses that profile.
       This prevents valid service Tasks from being reinterpreted under
       the shifted v0.8 unary table during proof tracing. CpuChip and
       ProgramMemoryChip each gain one column/lookup limb.
  15 — Poseidon2-M31 PCS variant of format 14.
  16 — Standard host-call continuation and scalar-memory address binding.
       CpuChip commits whether a policy-supported ECALLI was acknowledged,
       constrains handled/cause PCs across segment boundaries, and binds the
       supported-call policy through ProgramMemory. ProgramMemory also
       authenticates the exact cryptographic precompile dispatch ID; every
       continued precompile row must select exactly that handler-call
       relation, while lifecycle/VOS stubs select none. This widens the
       program-memory tuple from 33 to 34 limbs. Standard load/store rows
       also prove that their full scalar range stays outside the protected
       low 64 KiB and does not wrap through 2^32. CPU/ProgramMemory columns
       and the program-memory lookup tuple change, so older proofs reject.
  17 — Poseidon2-M31 PCS variant of format 16.
  18 — Standard Refine proof-closure generation. Individual STARKs remain
       single-program machine-slice proofs; the new boundary bundle binds
       their exact outer/inner program identities, proof shapes, order,
       sparse memory states, and calls 9..=14 before/after transcript.
       Sparse entering images also replace the dense nearly-4-GiB Refine
       witness representation. Older proof/bundle combinations reject.
  19 — Poseidon2-M31 PCS variant of format 18.
  20 — Full PCS configuration is Fiat–Shamir-bound, including the lifting
       `Option` discriminant; proof-side verification also uses the exact
       AIR-derived lifted shape.
  21 — Poseidon2-M31 PCS variant of format 20.
  22 — Single ISA profile. The ISA-profile limb leaves CpuChip and the
       ProgramMemory preprocessed table (the program-memory tuple drops
       from 34 to 33 limbs), so program commitments change. A continued
       host call must select exactly one precompile relation; lifecycle
       stubs no longer continue. Older proofs reject.
  23 — Poseidon2-M31 PCS variant of format 22.
  24 — Dispatch-committed host-call policy. CpuChip drops the
       acknowledgment alias and the policy bit, which the committed
       precompile dispatch already implies; ProgramMemory drops the policy
       column (the program-memory tuple drops from 33 to 32 limbs), so
       program commitments change. Older proofs reject.
  25 — Poseidon2-M31 PCS variant of format 24.
  26–30 — the registry's ([`crate::format`]) on format 24's AIR: 26
       Poseidon2-M31 segments, 27 leaves and folds, 28 the wrap, 29
       device proofs, 30 credential proofs.
  31–34 — the registry's on the hardened segment AIR, which retires 24,
       26, 27 and 29 (28 and 30 prove other AIRs and keep their numbers).
       A run's ends and its witness input: a halting step continues at
       the halt address, so a segment's final pc is the halt address
       exactly when it ends at a halt; a kernel's witness-input call
       (0x401, dispatch 101) writes its count to φ7, at most φ8, and
       `WitnessInputChip` (index 13) writes exactly its bytes; the
       register ledger sorts a register's reads before its writes within
       a timestamp. The Ristretto and scalar chips removed: CpuChip drops
       its five `Is{110..114}Ecall` selectors, the eight chips and their
       eleven relations leave the AIR (`COUNT` 25, `BITWISE_AND_BYTE` at
       index 24) and ids 110–114 are no precompile. The AIR audit's
       hardening: MulChip and DivRemChip Range256-check every product
       byte, quotient and remainder byte, high half and carry their
       chains read, and booleanize the magnitude chains' carries, so each
       chain holds over the integers; DivRemChip pins the schoolbook's
       high half per operation (zero, signed correction with the
       `MIN / −1` overflow, or floor division for an arithmetic shift,
       flagged by the DivRem tuple's new `is_shar_r`, which flag byte 0's
       bit 3 commits in place of the implied `is_mul_upper`).
       Blake2bChip holds `IsReal` across a compression, refuses the
       trailing partial block, and derives its addresses by byte carries
       on every row. CpuChip: boolean add/sub and pc carries; a padding
       row's flag bytes zero, its flags and emission gates with them;
       equality bound both ways; signed min/max results; an 8-byte
       immediate store's high word (ImmYBytes and ProgramMemory's
       ImmYCanon carry 5 bytes, the program-memory tuple 37 limbs); a
       trap stays at its pc; ProgramMemory serves only instruction
       starts (a preprocessed IsInstruction); NextTimestamp
       range-checked; φ10's non-zeroness by its bytes' sum; 32-bit
       BLAKE2b pointers; the ImmAlt shifts' operand swap. The register
       ledger drops its merged read slots and starts each register's
       chain at its ts = 0 write. MemoryPageChip carries the program's
       layout as preprocessed regions and proves each page's permission,
       which MemoryChip enforces on every access. Program commitments
       change.
  35–37 — the registry's on the segment AIR without the columns and
       masks no constraint reads, which retires 31, 33 and 34. CpuChip
       drops `Gas` (the AIR proves no gas accounting), `RegAWritten`,
       `ShiftOp`, the unused limb of `PartNZTimesIndH`,
       `PartNZMsbTimesIndH`, `PartNZMsbLoTimesIndH`, `MemByteActiveMonoH`
       and `ValRPartNZTimesIndH`, and the next-row masks of `Timestamp`
       and `Pc`: 15 main columns and 27 samples. Segments (35) take 40
       queries and 24 bits of PoW; 36 is the legacy Blake2s format, 37
       the device format.
  36 retired — the legacy Blake2s segment format, 57 proven bits at its
       MOBILE shape, below the 60-bit floor, with the refine-bundle path
       that produced it; the default prover produces 35.
```
