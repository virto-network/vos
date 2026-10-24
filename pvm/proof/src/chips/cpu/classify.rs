//! Opcode → flag classification used to drive CpuChip's per-step witnesses.
//!
//! `OpcodeFlags` is the bag of category/sub-op booleans that mirrors the AIR's
//! per-row flag columns; `classify_opcode` populates one from a PVM Opcode.
//! `uses_immediate` and `dest_reg` are companion predicates used by both the
//! main-trace fill and the register-access derivation.

use vos_pvm::instruction::Opcode;

#[derive(Clone, Copy, Default)]
pub(crate) struct OpcodeFlags {
    pub is_add: bool,
    pub is_sub: bool,
    pub is_mul: bool,
    pub is_bitwise: bool,
    pub is_shift: bool,
    pub is_compare: bool,
    pub is_move: bool,
    pub is_32bit: bool,
    pub is_and: bool,
    pub is_or: bool,
    pub is_xor: bool,
    pub is_and_inv: bool,
    pub is_or_inv: bool,
    pub is_xnor: bool,
    pub is_neg_add: bool,
    pub is_set_lt_u: bool,
    pub is_set_lt_s: bool,
    /// Swap modifier for `SetGtSImm`/`SetGtUImm` (`SLT rd, x0, rs2` lowers
    /// to these). SetGt is computed as "swap operands + SetLt": the
    /// instruction keeps `is_set_lt_s`/`is_set_lt_u` (so the existing result
    /// constraint + compare partition apply), and `is_set_gt` swaps the
    /// operand source so `val_b = imm`, `val_d = regs[rb]` — making the
    /// signed/unsigned less-than comparison compute `imm < reg = reg > imm`,
    /// the greater-than result. NOT a compare-partition sub-flag.
    pub is_set_gt: bool,
    pub is_cmov_iz: bool,
    pub is_cmov_nz: bool,
    /// CmovIzImm/CmovNzImm operand swap: the register cmov convention puts
    /// the moved value in `val_b` and the condition in `val_d` (which
    /// `ValDIsZero` gates), but the imm variants move the IMMEDIATE guarded
    /// by `regs[rb]`. `is_cmov_imm` swaps the source so `val_b = imm`,
    /// `val_d = regs[rb]`. The swap mechanism mirrors `is_set_gt` /
    /// `is_imm_alt`; like every compare sub-flag it is committed
    /// per pc in ProgramMemory's flag bytes (byte 6), so a row cannot drop
    /// the swap and leave its moved value free. NOT a compare-partition
    /// sub-flag; co-occurs with `is_cmov_iz/nz`.
    pub is_cmov_imm: bool,
    pub is_min_s: bool,
    pub is_min_u: bool,
    pub is_max_s: bool,
    pub is_max_u: bool,
    pub shift_op: u8,
    pub is_branch: bool,
    pub is_br_eq: bool,
    pub is_br_ne: bool,
    pub is_br_lt_u: bool,
    pub is_br_ge_u: bool,
    pub is_br_le_u: bool,
    pub is_br_gt_u: bool,
    pub is_br_lt_s: bool,
    pub is_br_ge_s: bool,
    pub is_br_le_s: bool,
    pub is_br_gt_s: bool,
    pub is_jump: bool,
    pub is_div_rem: bool,
    pub div_rem_op: u8,
    pub is_load: bool,
    pub is_store: bool,
    pub is_mul_upper: bool,
    pub is_exit: bool,
    /// BitManip permutation/zero-extend ops.
    pub is_reverse_bytes: bool,
    pub is_zero_ext_16: bool,
    /// BitManip sign-extend ops.
    pub is_sign_ext_8: bool,
    pub is_sign_ext_16: bool,
    /// Per-opcode terminal flag.  True only for Opcode::Trap.
    /// Distinct from `is_exit`, which also covers Ecalli (soft exit, may
    /// resume) and JumpInd / LoadImmJumpInd (dynamic dispatch).  Drives the
    /// terminal-row constraint that forbids any successor real row after
    /// Trap.
    pub is_trap: bool,
    /// Per-opcode flag for `Opcode::JumpInd`.  Drives the
    /// runtime-target binding via JumpTableChip — `addr = (regs[reg_a]
    /// + imm) mod 2^32`, then `next_pc = jump_table[addr/2 - 1]` (the
    /// chip's preprocessed lookup).
    pub is_jump_ind: bool,
    /// Per-opcode flag for
    /// `Opcode::LoadImmJumpInd`.  Same JumpTableChip lookup as JumpInd
    /// but with `addr = (regs[rb] + imm_y) mod 2^32` (val_d + imm_y_low4
    /// in the AIR).  Bound via a separate carry chain into
    /// LoadImmJumpIndAddr.
    pub is_load_imm_jump_ind: bool,
    /// The three signedness variants of `is_mul_upper`, so the AIR can
    /// apply the correct sign correction to the result.
    /// `is_mul_upper_uu` ⇒ result = unsigned-product high 64.
    /// `is_mul_upper_su` ⇒ result = signed-unsigned high = unsigned high − sa·val_d.
    /// `is_mul_upper_ss` ⇒ result = signed-signed   high = unsigned high − sa·val_d − sb·val_b.
    pub is_mul_upper_uu: bool,
    pub is_mul_upper_su: bool,
    pub is_mul_upper_ss: bool,
    /// Signed div/rem variants (DivS32/DivS64/RemS32/RemS64).
    /// Drives the sign-correction at the divrem schoolbook's high bytes:
    ///   high(q_u·d_u + r_u) ≡ sq·d_u + sd·q_u + sr − sa  (mod 2^64)
    /// where sa/sd/sq/sr are the dividend/divisor/quotient/remainder
    /// sign bits.  Without this, signed divrem with any negative operand
    /// fails proving — the schoolbook's high bytes aren't zero in
    /// two's-complement.
    pub is_div_s: bool,
    /// Arithmetic right shifts (SharR32/SharR64 and their immediate forms):
    /// floor division by `2^n`, which DivRemChip tells from a logical
    /// shift's unsigned division by this flag in the DivRem tuple.
    pub is_shar_r: bool,
    /// Per-size signed-load flags (covers direct + indirect
    /// variants: LoadI8 / LoadIndI8 → is_load_i8, etc.).  Drive the
    /// inactive-byte sign-extension binding for `result[i]` on
    /// `i ≥ MemSize`.  Without this, a prover could write garbage in
    /// the high bytes of a load result; the interpreter writes
    /// `0xFF · sign_bit` for signed loads (and `0` for unsigned).
    pub is_load_i8: bool,
    pub is_load_i16: bool,
    pub is_load_i32: bool,
    /// Per-size memory-access flags covering both load and
    /// store variants.  Pin `MemSize = 1·is_mem_size_1 + 2·is_mem_size_2
    /// + 4·is_mem_size_4 + 8·is_mem_size_8`, so the prover can't pick a
    /// MemSize inconsistent with the opcode.  Exactly one is set per
    /// memory-op row, all zero on non-memory rows.
    pub is_mem_size_1: bool,
    pub is_mem_size_2: bool,
    pub is_mem_size_4: bool,
    pub is_mem_size_8: bool,
    /// 1 iff this opcode is `StoreU8 / StoreU16 / StoreU32 /
    /// StoreU64` (OneRegOneImm category — *direct* store, not Ind or
    /// Imm).  For these the trace fill's default arm puts `regs[ra]`
    /// (the source value) into `val_b`, so MemValue's active bytes
    /// can be pinned to `val_b`'s bytes by a single constraint.
    /// StoreInd* / StoreImm* / StoreImmInd* leave the source value in
    /// a different place and need their own bindings.
    pub is_store_direct: bool,
    /// 1 iff this opcode is one of the *direct* loads
    /// `LoadU8 / LoadI8 / LoadU16 / LoadI16 / LoadU32 / LoadI32 /
    /// LoadU64` (OneRegOneImm category).  For these the address is
    /// just the immediate (`addr = imm`); paired with IsStoreDirect
    /// drives the `MemAddr = ImmBytes[0..4]` binding.
    pub is_load_direct: bool,
    /// 1 iff this opcode is one of the *indirect* memory
    /// ops — LoadInd[U/I][8/16/32/64] (TwoRegOneImm), StoreInd[U/I]
    /// [8/16/32/64] (TwoRegOneImm), or StoreImmInd[U][8/16/32/64]
    /// (OneRegTwoImm).  For all three categories the trace fill
    /// puts the base register's value into `val_b` (regs[rb] for
    /// TwoRegOneImm, regs[ra] for OneRegTwoImm via the default
    /// match arm).  Drives the byte-wise add-with-carry chain
    /// pinning `MemAddr = (val_b + ImmBytes) mod 2^32`.
    pub is_mem_indirect: bool,
    /// 1 iff this opcode is one of `StoreImm[U][8/16/32/64]`
    /// (TwoImm category) or `StoreImmInd[U][8/16/32/64]`
    /// (OneRegTwoImm category).  In both cases the *value* written
    /// to memory is `imm_y` (already pinned to canonical via
    /// `ImmYCanon` in ProgramMemoryChip).  Drives the per-byte
    /// MemValue ↔ ImmYBytes binding: the low 4 bytes, and on an 8-byte
    /// store the high 4, each `ImmYBytes[4]`.
    pub is_store_imm_any: bool,
    /// 1 iff this opcode is one of `StoreImm[U][8/16/32/64]`
    /// (TwoImm only — the *direct*-addressing immediate-source
    /// store).  For these `addr = imm_x = step.imm`, so the
    /// MemAddr binding shape is the same as the direct-load path.
    pub is_store_imm_direct: bool,
    /// 1 iff this opcode is one of `StoreIndU[8/16/32/64]`
    /// (TwoRegOneImm — *register-source* indirect store).  For
    /// these the value written to memory is `regs[ra]`, which
    /// isn't in val_b (val_b holds the *base* regs[rb] for
    /// TwoRegOneImm).  Drives the RegValA column + producer
    /// emission to the register-memory ledger, plus the
    /// MemValue ↔ RegValA byte-wise binding.
    pub is_store_ind: bool,
    /// 1 iff this opcode is `RotL64` — rotate-left 64-bit.
    /// PVM defines `RotL64(a, n) = (a << n) | (a >> (64 − n))` for
    /// `n ∈ [0, 63]`.  Encoded via the existing mul-schoolbook
    /// (val_d = 2^n) which produces both the low 64 (= `a << n`
    /// truncated) and high 64 (= `a >> (64 − n)`) of `a · 2^n`.
    /// Since the rotation's two halves have non-overlapping bits
    /// (by construction), OR = byte-wise SUM, so
    /// `result = UnsignedProductLow + mul_high` (no carry).
    /// Drives the schoolbook re-route (low-64 → UnsignedProductLow)
    /// + the rotation result binding.
    pub is_rotate_l64: bool,
    /// 1 iff this opcode is `CountSetBits64` or `CountSetBits32`.
    /// Drives the per-byte popcount lookup `(val_d[i], BytePopcount[i]) ∈
    /// popcount` plus the result binding `result[0] =
    /// sum(BytePopcount[0..N])` (N = 8 for 64-bit, N = 4 for 32-bit) and
    /// `result[1..8] = 0`.
    pub is_count_set_bits: bool,
    /// 1 iff this opcode is `LeadingZeroBits64` or
    /// `LeadingZeroBits32`.  Drives the per-byte bitcount lookup
    /// `(val_d[i], BitOpLzByte[i], BitOpTzByte[i]) ∈ bitcount` plus
    /// the LZ result binding (sums over the first-non-zero MSB-direction
    /// indicator), with default `64` (or `32` if Is32Bit) when val_d
    /// is zero.  Result high bytes pinned to 0.
    pub is_lzb: bool,
    /// 1 iff this opcode is `TrailingZeroBits64` or
    /// `TrailingZeroBits32`.  Symmetric to is_lzb but using the
    /// LSB-direction first-non-zero indicator (ValDPartialNZ).
    pub is_tzb: bool,
    /// 1 iff this opcode is `RotR64` / `RotR64Imm`.
    /// PVM defines `RotR64(a, n) = (a >> n) | (a << (64 − n))` for
    /// `n ∈ [0, 63]`.  Encoded by setting `val_d = 2^((64 − n) mod
    /// 64)` (instead of `2^n` like RotL64); the mul-schoolbook
    /// then computes both halves of `a · 2^((64 − n) mod 64)`
    /// whose byte-wise sum equals the rotated-right value (no
    /// carry — bits non-overlapping by construction).
    pub is_rotate_r64: bool,
    /// 1 iff this opcode is `RotL32`.  Same shape as
    /// RotL64 but over a 32-bit value with sign-extension in the
    /// high 4 bytes.  Re-uses the 32-bit mul-schoolbook
    /// (val_d = 2^(n mod 32)) whose low-32 bytes go to
    /// UnsignedProductLow[0..4] and high-32 to mul_high[0..4]; the
    /// rotate result is byte-wise sum of those two halves over
    /// bytes 0..4.
    pub is_rotate_l32: bool,
    /// 1 iff this opcode is `RotR32` / `RotR32Imm`.
    /// Mirror of is_rotate_r64 but with modulus 32: val_d =
    /// 2^((32 − n) mod 32); result low 4 bytes = UnsignedProductLow
    /// + mul_high; high 4 bytes = sign-extension.
    pub is_rotate_r32: bool,
    /// 1 iff this opcode is an `ImmAlt` shift or rotate — the
    /// swapped-source variants where the immediate is the shifted value
    /// and `regs[rb]` is the shift amount (vs. the `Imm` variants where
    /// the convention is reversed).  Drives a swapped trace fill (val_b ←
    /// imm, val_d ← regs[rb]) plus a `val_b = ImmBytes` constraint
    /// pinning the new source.  Set alongside the shift's or rotate's own
    /// flags so their constraints fire.
    pub is_imm_alt: bool,
}

/// `OpcodeFlags` with `flags` set and `fields` given, the rest clear.
macro_rules! flags {
    ($($flag:ident),* $(; $($field:ident: $value:expr),*)?) => {
        OpcodeFlags {
            $($flag: true,)*
            $($($field: $value,)*)?
            ..OpcodeFlags::default()
        }
    };
}

pub(crate) fn classify_opcode(op: Opcode) -> OpcodeFlags {
    let flags = match op {
        Opcode::Add64 | Opcode::AddImm64 => flags!(is_add),
        Opcode::Add32 | Opcode::AddImm32 => flags!(is_add, is_32bit),
        Opcode::Sub64 => flags!(is_sub),
        Opcode::Sub32 => flags!(is_sub, is_32bit),
        Opcode::NegAddImm64 => flags!(is_sub, is_neg_add),
        Opcode::NegAddImm32 => flags!(is_sub, is_neg_add, is_32bit),
        Opcode::Mul64 | Opcode::MulImm64 => flags!(is_mul),
        Opcode::Mul32 | Opcode::MulImm32 => flags!(is_mul, is_32bit),
        // MulUpper: result = high 64 bits of 128-bit product
        Opcode::MulUpperUU => flags!(is_mul, is_mul_upper_uu),
        Opcode::MulUpperSS => flags!(is_mul, is_mul_upper_ss),
        Opcode::MulUpperSU => flags!(is_mul, is_mul_upper_su),
        Opcode::And | Opcode::AndImm => flags!(is_and),
        Opcode::Or | Opcode::OrImm => flags!(is_or),
        Opcode::Xor | Opcode::XorImm => flags!(is_xor),
        Opcode::AndInv => flags!(is_and_inv),
        Opcode::OrInv => flags!(is_or_inv),
        Opcode::Xnor => flags!(is_xnor),
        // Left shifts: constrained via mul (val_d = 2^shift_amount)
        Opcode::ShloL64 | Opcode::ShloLImm64 | Opcode::ShloLImmAlt64 => {
            flags!(is_shift, is_mul; is_imm_alt: op == Opcode::ShloLImmAlt64, shift_op: 0)
        }
        Opcode::ShloL32 | Opcode::ShloLImm32 | Opcode::ShloLImmAlt32 => {
            flags!(is_shift, is_mul, is_32bit; is_imm_alt: op == Opcode::ShloLImmAlt32, shift_op: 0)
        }
        // Logical right shifts: constrained via divrem (val_d = 2^shift_amount, result = quotient)
        Opcode::ShloR64 | Opcode::ShloRImm64 | Opcode::ShloRImmAlt64 => {
            flags!(is_shift, is_div_rem; is_imm_alt: op == Opcode::ShloRImmAlt64, shift_op: 1)
        }
        Opcode::ShloR32 | Opcode::ShloRImm32 | Opcode::ShloRImmAlt32 => {
            flags!(
                is_shift, is_div_rem, is_32bit;
                is_imm_alt: op == Opcode::ShloRImmAlt32, shift_op: 1
            )
        }
        // Arithmetic right shifts: floor division by val_d = 2^shift_amount
        // (divrem + power-of-two, like ShloR), told apart by is_shar_r.
        Opcode::SharR64 | Opcode::SharRImm64 | Opcode::SharRImmAlt64 => {
            flags!(
                is_shift, is_div_rem, is_shar_r;
                is_imm_alt: op == Opcode::SharRImmAlt64, shift_op: 2
            )
        }
        Opcode::SharR32 | Opcode::SharRImm32 | Opcode::SharRImmAlt32 => {
            flags!(
                is_shift, is_div_rem, is_shar_r, is_32bit;
                is_imm_alt: op == Opcode::SharRImmAlt32, shift_op: 2
            )
        }
        // RotL64 reuses the mul-schoolbook (val_d = 2^n)
        // to compute both halves of `a · 2^n`; result = low + high.
        Opcode::RotL64 => flags!(is_shift, is_mul, is_rotate_l64; shift_op: 3),
        // RotL32 — 32-bit mul-schoolbook re-route, val_d = 2^(n mod 32).
        Opcode::RotL32 => flags!(is_shift, is_32bit, is_mul, is_rotate_l32; shift_op: 3),
        // RotR64 + RotR64Imm — value in val_b, shift in
        // val_d.  Encoded via the mul-schoolbook with `val_d =
        // 2^((64 − n) mod 64)`; result = low + high (identical sum
        // shape to RotL64 but with the complementary shift amount).
        Opcode::RotR64 | Opcode::RotR64Imm => flags!(is_shift, is_mul, is_rotate_r64; shift_op: 4),
        // RotR64ImmAlt — value = imm, shift = regs[rb].
        // Set is_rotate_r64 so the existing rotate-r logic fires;
        // is_imm_alt drives the swapped trace fill.
        Opcode::RotR64ImmAlt => flags!(is_shift, is_mul, is_rotate_r64, is_imm_alt; shift_op: 4),
        // RotR32 + RotR32Imm — value in val_b, shift in val_d.
        // Same shape as RotR64 but with modulus 32.
        Opcode::RotR32 | Opcode::RotR32Imm => {
            flags!(is_shift, is_32bit, is_mul, is_rotate_r32; shift_op: 4)
        }
        // RotR32ImmAlt — same swap as RotR64ImmAlt but 32-bit.
        Opcode::RotR32ImmAlt => {
            flags!(is_shift, is_32bit, is_mul, is_rotate_r32, is_imm_alt; shift_op: 4)
        }
        // Compare
        Opcode::SetLtU | Opcode::SetLtUImm => flags!(is_set_lt_u),
        Opcode::SetLtS | Opcode::SetLtSImm => flags!(is_set_lt_s),
        // SetGt = swap operands + SetLt: keep is_set_lt_u (drives the
        // result + compare partition); is_set_gt swaps val_b/val_d so the
        // unsigned less-than becomes unsigned greater-than.
        Opcode::SetGtUImm => flags!(is_set_lt_u, is_set_gt),
        Opcode::SetGtSImm => flags!(is_set_lt_s, is_set_gt),
        Opcode::CmovIz | Opcode::CmovIzImm => {
            flags!(is_cmov_iz; is_cmov_imm: op == Opcode::CmovIzImm)
        }
        Opcode::CmovNz | Opcode::CmovNzImm => {
            flags!(is_cmov_nz; is_cmov_imm: op == Opcode::CmovNzImm)
        }
        Opcode::Min => flags!(is_min_s),
        Opcode::MinU => flags!(is_min_u),
        Opcode::Max => flags!(is_max_s),
        Opcode::MaxU => flags!(is_max_u),
        // Move
        Opcode::MoveReg | Opcode::LoadImm | Opcode::LoadImm64 => flags!(is_move),
        // BitManip (TwoReg unary ops).
        Opcode::ZeroExtend16 => flags!(is_zero_ext_16),
        Opcode::ReverseBytes => flags!(is_reverse_bytes),
        Opcode::SignExtend8 => flags!(is_sign_ext_8),
        Opcode::SignExtend16 => flags!(is_sign_ext_16),
        Opcode::CountSetBits64 => flags!(is_count_set_bits),
        Opcode::CountSetBits32 => flags!(is_count_set_bits, is_32bit),
        Opcode::LeadingZeroBits64 => flags!(is_lzb),
        Opcode::LeadingZeroBits32 => flags!(is_lzb, is_32bit),
        Opcode::TrailingZeroBits64 => flags!(is_tzb),
        Opcode::TrailingZeroBits32 => flags!(is_tzb, is_32bit),
        // Branches (conditional) — classify by comparison type
        // For Le/Gt variants we'll flip the operand order / invert
        Opcode::BranchEq | Opcode::BranchEqImm => flags!(is_br_eq),
        Opcode::BranchNe | Opcode::BranchNeImm => flags!(is_br_ne),
        // Unsigned: branch_taken = val_b < val_d
        Opcode::BranchLtU | Opcode::BranchLtUImm => flags!(is_br_lt_u),
        // Unsigned: branch_taken = val_b >= val_d (= !lt)
        Opcode::BranchGeU | Opcode::BranchGeUImm => flags!(is_br_ge_u),
        // Unsigned: branch_taken = val_b <= val_d (imm only; swap operands vs ge)
        Opcode::BranchLeUImm => flags!(is_br_le_u),
        // Unsigned: branch_taken = val_b > val_d (imm only)
        Opcode::BranchGtUImm => flags!(is_br_gt_u),
        // Signed: branch_taken = val_b < val_d (signed)
        Opcode::BranchLtS | Opcode::BranchLtSImm => flags!(is_br_lt_s),
        Opcode::BranchGeS | Opcode::BranchGeSImm => flags!(is_br_ge_s),
        Opcode::BranchLeSImm => flags!(is_br_le_s),
        Opcode::BranchGtSImm => flags!(is_br_gt_s),
        // DivRem
        Opcode::DivU64 => flags!(is_div_rem),
        Opcode::DivU32 => flags!(is_div_rem, is_32bit),
        Opcode::DivS64 => flags!(is_div_rem, is_div_s; div_rem_op: 1),
        Opcode::DivS32 => flags!(is_div_rem, is_32bit, is_div_s; div_rem_op: 1),
        Opcode::RemU64 => flags!(is_div_rem; div_rem_op: 2),
        Opcode::RemU32 => flags!(is_div_rem, is_32bit; div_rem_op: 2),
        Opcode::RemS64 => flags!(is_div_rem, is_div_s; div_rem_op: 3),
        Opcode::RemS32 => flags!(is_div_rem, is_32bit, is_div_s; div_rem_op: 3),
        // Loads — `is_mem_size_*` covers both load and store; set per
        // width.  `is_load_direct` set on the OneRegOneImm-category
        // direct loads (no Ind variant), driving the MemAddr ↔ ImmBytes
        // binding.
        Opcode::LoadU8 => flags!(is_mem_size_1, is_load_direct),
        Opcode::LoadIndU8 => flags!(is_mem_size_1, is_mem_indirect),
        Opcode::LoadU16 => flags!(is_mem_size_2, is_load_direct),
        Opcode::LoadIndU16 => flags!(is_mem_size_2, is_mem_indirect),
        Opcode::LoadU32 => flags!(is_mem_size_4, is_load_direct),
        Opcode::LoadIndU32 => flags!(is_mem_size_4, is_mem_indirect),
        Opcode::LoadU64 => flags!(is_mem_size_8, is_load_direct),
        Opcode::LoadIndU64 => flags!(is_mem_size_8, is_mem_indirect),
        Opcode::LoadI8 => flags!(is_load_i8, is_mem_size_1, is_load_direct),
        Opcode::LoadIndI8 => flags!(is_load_i8, is_mem_size_1, is_mem_indirect),
        Opcode::LoadI16 => flags!(is_load_i16, is_mem_size_2, is_load_direct),
        Opcode::LoadIndI16 => flags!(is_load_i16, is_mem_size_2, is_mem_indirect),
        Opcode::LoadI32 => flags!(is_load_i32, is_mem_size_4, is_load_direct),
        Opcode::LoadIndI32 => flags!(is_load_i32, is_mem_size_4, is_mem_indirect),
        // Stores — split by addressing mode.  is_store_direct is set
        // only on the OneRegOneImm-category direct stores; Ind / Imm
        // / ImmInd handle their source values differently.
        Opcode::StoreU8 => flags!(is_mem_size_1, is_store_direct),
        Opcode::StoreU16 => flags!(is_mem_size_2, is_store_direct),
        Opcode::StoreU32 => flags!(is_mem_size_4, is_store_direct),
        Opcode::StoreU64 => flags!(is_mem_size_8, is_store_direct),
        Opcode::StoreIndU8 => flags!(is_mem_size_1, is_mem_indirect, is_store_ind),
        Opcode::StoreImmIndU8 => flags!(is_mem_size_1, is_mem_indirect, is_store_imm_any),
        Opcode::StoreImmU8 => flags!(is_mem_size_1, is_store_imm_any, is_store_imm_direct),
        Opcode::StoreIndU16 => flags!(is_mem_size_2, is_mem_indirect, is_store_ind),
        Opcode::StoreImmIndU16 => flags!(is_mem_size_2, is_mem_indirect, is_store_imm_any),
        Opcode::StoreImmU16 => flags!(is_mem_size_2, is_store_imm_any, is_store_imm_direct),
        Opcode::StoreIndU32 => flags!(is_mem_size_4, is_mem_indirect, is_store_ind),
        Opcode::StoreImmIndU32 => flags!(is_mem_size_4, is_mem_indirect, is_store_imm_any),
        Opcode::StoreImmU32 => flags!(is_mem_size_4, is_store_imm_any, is_store_imm_direct),
        Opcode::StoreIndU64 => flags!(is_mem_size_8, is_mem_indirect, is_store_ind),
        Opcode::StoreImmIndU64 => flags!(is_mem_size_8, is_mem_indirect, is_store_imm_any),
        Opcode::StoreImmU64 => flags!(is_mem_size_8, is_store_imm_any, is_store_imm_direct),
        // Jumps (unconditional, non-sequential target)
        Opcode::Jump => flags!(is_jump),
        // LoadImmJump also moves its immediate, ValD, into φA.
        Opcode::LoadImmJump => flags!(is_jump, is_move),
        // Fallthrough/Unlikely: pure sequential terminators (basic-block hints
        // with no semantic effect).  All flags stay 0 so the default
        // sequential-PC identity (next_pc = pc + 1 + skip_len) constrains them
        // — see fallthrough_forged_next_pc_rejected and
        // unlikely_forged_next_pc_rejected in tests/isa/control_flow.rs.
        Opcode::Fallthrough | Opcode::Unlikely => flags!(),
        // JumpInd / LoadImmJumpInd: dynamic dispatch.  Both pinned via
        // JumpTableChip lookups; JumpInd uses (val_b+imm), LoadImmJumpInd
        // uses (val_d+imm_y) for the addr computation.
        Opcode::JumpInd => flags!(is_exit, is_jump_ind),
        Opcode::LoadImmJumpInd => flags!(is_exit, is_load_imm_jump_ind),
        // Ecalli: host call (execution exits, no ALU constraint)
        Opcode::Ecalli => flags!(is_exit),
        // Trap: causes panic exit
        Opcode::Trap | Opcode::Invalid => flags!(is_exit, is_trap),
    };
    flags.with_categories()
}

impl OpcodeFlags {
    /// The category flags, each set by its operations' own flags: the
    /// bitwise, compare and branch sub-operations, the stores' addressing
    /// modes, a load's size on a row that does not store, and the upper
    /// multiplications' signedness.
    fn with_categories(self) -> Self {
        let mem_size =
            self.is_mem_size_1 || self.is_mem_size_2 || self.is_mem_size_4 || self.is_mem_size_8;
        let is_store = self.is_store_direct || self.is_store_imm_any || self.is_store_ind;
        Self {
            is_bitwise: self.is_and
                || self.is_or
                || self.is_xor
                || self.is_and_inv
                || self.is_or_inv
                || self.is_xnor,
            is_compare: self.is_set_lt_u
                || self.is_set_lt_s
                || self.is_cmov_iz
                || self.is_cmov_nz
                || self.is_min_s
                || self.is_min_u
                || self.is_max_s
                || self.is_max_u,
            is_branch: self.is_br_eq
                || self.is_br_ne
                || self.is_br_lt_u
                || self.is_br_ge_u
                || self.is_br_le_u
                || self.is_br_gt_u
                || self.is_br_lt_s
                || self.is_br_ge_s
                || self.is_br_le_s
                || self.is_br_gt_s,
            is_store,
            is_load: mem_size && !is_store,
            is_mul_upper: self.is_mul_upper_uu || self.is_mul_upper_su || self.is_mul_upper_ss,
            ..self
        }
    }
}

pub(super) fn uses_immediate(op: Opcode) -> bool {
    matches!(
        op,
        Opcode::AddImm32
            | Opcode::AddImm64
            | Opcode::NegAddImm32
            | Opcode::NegAddImm64
            | Opcode::MulImm32
            | Opcode::MulImm64
            | Opcode::AndImm
            | Opcode::OrImm
            | Opcode::XorImm
            | Opcode::ShloLImm32
            | Opcode::ShloRImm32
            | Opcode::SharRImm32
            | Opcode::ShloLImmAlt32
            | Opcode::ShloRImmAlt32
            | Opcode::SharRImmAlt32
            | Opcode::ShloLImm64
            | Opcode::ShloRImm64
            | Opcode::SharRImm64
            | Opcode::ShloLImmAlt64
            | Opcode::ShloRImmAlt64
            | Opcode::SharRImmAlt64
            | Opcode::RotR64Imm
            | Opcode::RotR64ImmAlt
            | Opcode::RotR32Imm
            | Opcode::RotR32ImmAlt
            | Opcode::SetLtUImm
            | Opcode::SetLtSImm
            | Opcode::SetGtUImm
            | Opcode::SetGtSImm
            | Opcode::CmovIzImm
            | Opcode::CmovNzImm
            | Opcode::LoadImm
            | Opcode::LoadImm64
    )
}

pub(super) fn dest_reg(step: &crate::core::step::PvmStep) -> usize {
    use vos_pvm::instruction::InstructionCategory::*;
    match step.opcode.category() {
        ThreeReg => step.reg_d,
        _ => step.reg_a,
    }
}

/// Extract the 80 flags — category, sub-operation and register-access —
/// in the order matching ProgramMemoryChip's preprocessed columns.  Used by ProgramMemoryChip's
/// preprocessed-trace fill to pin flag values to the canonical
/// classify_opcode result.
pub(crate) fn classify_opcode_for_program_memory(
    op: Opcode,
) -> [u8; crate::lookups::PROG_MEMORY_N_FLAGS] {
    let f = classify_opcode(op);
    let shape = super::reg_access::access_shape(op);
    [
        f.is_add as u8,
        f.is_sub as u8,
        f.is_mul as u8,
        // Byte 0 bit 3: is_mul_upper is implied by its three variants
        // (bytes 2 and 3), so the slot commits is_shar_r.
        f.is_shar_r as u8,
        f.is_bitwise as u8,
        f.is_shift as u8,
        f.is_compare as u8,
        f.is_move as u8,
        f.is_32bit as u8,
        f.is_branch as u8,
        f.is_jump as u8,
        f.is_div_rem as u8,
        f.is_load as u8,
        f.is_store as u8,
        f.is_exit as u8,
        f.is_neg_add as u8,
        f.is_reverse_bytes as u8,
        f.is_zero_ext_16 as u8,
        f.is_sign_ext_8 as u8,
        f.is_sign_ext_16 as u8,
        f.is_trap as u8,
        f.is_jump_ind as u8,
        f.is_load_imm_jump_ind as u8,
        f.is_mul_upper_uu as u8,
        f.is_mul_upper_su as u8,
        f.is_mul_upper_ss as u8,
        f.is_div_s as u8,
        f.is_load_i8 as u8,
        f.is_load_i16 as u8,
        f.is_load_i32 as u8,
        f.is_mem_size_1 as u8,
        f.is_mem_size_2 as u8,
        f.is_mem_size_4 as u8,
        f.is_mem_size_8 as u8,
        f.is_store_direct as u8,
        f.is_load_direct as u8,
        f.is_mem_indirect as u8,
        f.is_store_imm_any as u8,
        f.is_store_imm_direct as u8,
        f.is_store_ind as u8,
        f.is_rotate_l64 as u8,
        f.is_count_set_bits as u8,
        f.is_lzb as u8,
        f.is_tzb as u8,
        f.is_rotate_r64 as u8,
        f.is_rotate_l32 as u8,
        f.is_rotate_r32 as u8,
        f.is_imm_alt as u8,
        // byte 6: the register accesses and the remaining operand modifiers.
        shape.val_b_is_reg as u8,
        shape.val_b_from_a as u8,
        shape.val_d_is_reg as u8,
        shape.result_is_reg as u8,
        shape.result_to_d as u8,
        (f.is_div_rem && f.div_rem_op >= 2) as u8,
        f.is_set_gt as u8,
        f.is_cmov_imm as u8,
        // byte 7: the compare sub-operations.
        f.is_set_lt_u as u8,
        f.is_set_lt_s as u8,
        f.is_cmov_iz as u8,
        f.is_cmov_nz as u8,
        f.is_min_s as u8,
        f.is_min_u as u8,
        f.is_max_s as u8,
        f.is_max_u as u8,
        // bytes 8 and 9: the branch conditions, then the bitwise
        // sub-operations.
        f.is_br_eq as u8,
        f.is_br_ne as u8,
        f.is_br_lt_u as u8,
        f.is_br_ge_u as u8,
        f.is_br_le_u as u8,
        f.is_br_gt_u as u8,
        f.is_br_lt_s as u8,
        f.is_br_ge_s as u8,
        f.is_br_le_s as u8,
        f.is_br_gt_s as u8,
        f.is_and as u8,
        f.is_or as u8,
        f.is_xor as u8,
        f.is_and_inv as u8,
        f.is_or_inv as u8,
        f.is_xnor as u8,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    impl OpcodeFlags {
        /// Every field, packed: `shift_op`, `div_rem_op`, then each flag in
        /// declaration order.
        fn packed(&self) -> u128 {
            let mut bits = u128::from(self.shift_op) | u128::from(self.div_rem_op) << 3;
            for (i, flag) in [
                self.is_add,
                self.is_sub,
                self.is_mul,
                self.is_bitwise,
                self.is_shift,
                self.is_compare,
                self.is_move,
                self.is_32bit,
                self.is_and,
                self.is_or,
                self.is_xor,
                self.is_and_inv,
                self.is_or_inv,
                self.is_xnor,
                self.is_neg_add,
                self.is_set_lt_u,
                self.is_set_lt_s,
                self.is_set_gt,
                self.is_cmov_iz,
                self.is_cmov_nz,
                self.is_cmov_imm,
                self.is_min_s,
                self.is_min_u,
                self.is_max_s,
                self.is_max_u,
                self.is_branch,
                self.is_br_eq,
                self.is_br_ne,
                self.is_br_lt_u,
                self.is_br_ge_u,
                self.is_br_le_u,
                self.is_br_gt_u,
                self.is_br_lt_s,
                self.is_br_ge_s,
                self.is_br_le_s,
                self.is_br_gt_s,
                self.is_jump,
                self.is_div_rem,
                self.is_load,
                self.is_store,
                self.is_mul_upper,
                self.is_exit,
                self.is_reverse_bytes,
                self.is_zero_ext_16,
                self.is_sign_ext_8,
                self.is_sign_ext_16,
                self.is_trap,
                self.is_jump_ind,
                self.is_load_imm_jump_ind,
                self.is_mul_upper_uu,
                self.is_mul_upper_su,
                self.is_mul_upper_ss,
                self.is_div_s,
                self.is_shar_r,
                self.is_load_i8,
                self.is_load_i16,
                self.is_load_i32,
                self.is_mem_size_1,
                self.is_mem_size_2,
                self.is_mem_size_4,
                self.is_mem_size_8,
                self.is_store_direct,
                self.is_load_direct,
                self.is_mem_indirect,
                self.is_store_imm_any,
                self.is_store_imm_direct,
                self.is_store_ind,
                self.is_rotate_l64,
                self.is_count_set_bits,
                self.is_lzb,
                self.is_tzb,
                self.is_rotate_r64,
                self.is_rotate_l32,
                self.is_rotate_r32,
                self.is_imm_alt,
            ]
            .into_iter()
            .enumerate()
            {
                bits |= u128::from(flag) << (6 + i);
            }
            bits
        }
    }

    /// The flags each opcode classifies to, packed: the program ids rest
    /// on them.
    const FLAGS: [(u8, u128); 139] = [
        (0, 0x10800000000000),
        (1, 0x0),
        (2, 0x0),
        (10, 0x800000000000),
        (20, 0x1000),
        (30, 0xc08000200000000000),
        (31, 0xc10000200000000000),
        (32, 0xc20000200000000000),
        (33, 0xc40000200000000000),
        (40, 0x40000000000),
        (50, 0x20800000000000),
        (51, 0x1000),
        (52, 0x108000100000000000),
        (53, 0x109000100000000000),
        (54, 0x110000100000000000),
        (55, 0x112000100000000000),
        (56, 0x120000100000000000),
        (57, 0x124000100000000000),
        (58, 0x140000100000000000),
        (59, 0x88000200000000000),
        (60, 0x90000200000000000),
        (61, 0xa0000200000000000),
        (62, 0xc0000200000000000),
        (70, 0x608000200000000000),
        (71, 0x610000200000000000),
        (72, 0x620000200000000000),
        (73, 0x640000200000000000),
        (80, 0x40000001000),
        (81, 0x180000000),
        (82, 0x280000000),
        (83, 0x480000000),
        (84, 0x1080000000),
        (85, 0x880000000),
        (86, 0x2080000000),
        (87, 0x4080000000),
        (88, 0x10080000000),
        (89, 0x8080000000),
        (90, 0x20080000000),
        (100, 0x1000),
        (101, 0x4000000000000000000),
        (102, 0x4000000000000002000),
        (103, 0x8000000000000000000),
        (104, 0x8000000000000002000),
        (105, 0x10000000000000000000),
        (106, 0x10000000000000002000),
        (107, 0x4000000000000),
        (108, 0x8000000000000),
        (109, 0x2000000000000),
        (110, 0x1000000000000),
        (120, 0x1208000200000000000),
        (121, 0x1210000200000000000),
        (122, 0x1220000200000000000),
        (123, 0x1240000200000000000),
        (124, 0x208000100000000000),
        (125, 0x209000100000000000),
        (126, 0x210000100000000000),
        (127, 0x212000100000000000),
        (128, 0x220000100000000000),
        (129, 0x224000100000000000),
        (130, 0x240000100000000000),
        (131, 0x2040),
        (132, 0x4200),
        (133, 0x10200),
        (134, 0x8200),
        (135, 0x2100),
        (136, 0x200800),
        (137, 0x400800),
        (138, 0x2500),
        (139, 0x80000002401),
        (140, 0x800080000002402),
        (141, 0x102080),
        (142, 0xa00800),
        (143, 0xc00800),
        (144, 0x100000000000000002500),
        (145, 0x100000000080000002401),
        (146, 0x100000800080000002402),
        (147, 0x5000800),
        (148, 0x6000800),
        (149, 0x40),
        (150, 0x100),
        (151, 0x500),
        (152, 0x80000000401),
        (153, 0x800080000000402),
        (154, 0x100080),
        (155, 0x100000000000000000500),
        (156, 0x100000000080000000401),
        (157, 0x100000800080000000402),
        (158, 0x20000000000000000504),
        (159, 0x120000000000000000504),
        (160, 0x80000000000000002504),
        (161, 0x180000000000000002504),
        (170, 0x180000000),
        (171, 0x280000000),
        (172, 0x480000000),
        (173, 0x4080000000),
        (174, 0x880000000),
        (175, 0x8080000000),
        (180, 0x40800000000000),
        (190, 0x2040),
        (191, 0x2080),
        (192, 0x2100),
        (193, 0x80000002000),
        (194, 0x400080000002008),
        (195, 0x80000002010),
        (196, 0x400080000002018),
        (197, 0x2500),
        (198, 0x80000002401),
        (199, 0x800080000002402),
        (200, 0x40),
        (201, 0x80),
        (202, 0x100),
        (203, 0x80000000000),
        (204, 0x400080000000008),
        (205, 0x80000000010),
        (206, 0x400080000000018),
        (207, 0x500),
        (208, 0x80000000401),
        (209, 0x800080000000402),
        (210, 0x4200),
        (211, 0x10200),
        (212, 0x8200),
        (213, 0x200400000000100),
        (214, 0x80400000000100),
        (215, 0x100400000000100),
        (216, 0x200800),
        (217, 0x400800),
        (218, 0x1000800),
        (219, 0x2000800),
        (220, 0x2000000000000000503),
        (221, 0x40000000000000002503),
        (222, 0x20000000000000000504),
        (223, 0x80000000000000002504),
        (224, 0x20200),
        (225, 0x40200),
        (226, 0x80200),
        (227, 0x20000800),
        (228, 0x40000800),
        (229, 0x8000800),
        (230, 0x10000800),
    ];

    #[test]
    fn every_opcode_classifies_to_its_flags() {
        let opcodes: Vec<u8> = (0..=u8::MAX)
            .filter(|&byte| Opcode::from_byte(byte).is_some())
            .collect();
        assert_eq!(opcodes, FLAGS.map(|(byte, _)| byte));
        for (byte, flags) in FLAGS {
            let op = Opcode::from_byte(byte).unwrap();
            assert_eq!(classify_opcode(op).packed(), flags, "{op:?}");
        }
    }
}
