//! Opcode → flag classification used to drive CpuChip's per-step witnesses.
//!
//! `OpcodeFlags` is the bag of category/sub-op booleans that mirrors the AIR's
//! per-row flag columns; `classify_opcode` populates one from a PVM Opcode.
//! `uses_immediate` and `dest_reg` are companion predicates used by both the
//! main-trace fill and the register-access derivation.

use javm::instruction::Opcode;

#[derive(Clone, Copy, Default)]
pub(super) struct OpcodeFlags {
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
    pub is_cmov_iz: bool,
    pub is_cmov_nz: bool,
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
    /// Phase 12b-1: BitManip permutation/zero-extend ops.
    pub is_reverse_bytes: bool,
    pub is_zero_ext_16: bool,
    /// Phase 12b-2: BitManip sign-extend ops.
    pub is_sign_ext_8: bool,
    pub is_sign_ext_16: bool,
    /// Phase 13e-redux: per-opcode terminal flag.  True only for Opcode::Trap.
    /// Distinct from `is_exit`, which also covers Ecalli (soft exit, may
    /// resume) and JumpInd / LoadImmJumpInd (dynamic dispatch).  Drives the
    /// terminal-row constraint that forbids any successor real row after
    /// Trap.
    pub is_trap: bool,
    /// Phase 13d: per-opcode flag for `Opcode::JumpInd`.  Drives the
    /// runtime-target binding via JumpTableChip — `addr = (regs[reg_a]
    /// + imm) mod 2^32`, then `next_pc = jump_table[addr/2 - 1]` (the
    /// chip's preprocessed lookup).
    pub is_jump_ind: bool,
    /// Phase 13d-loadimmjumpind: per-opcode flag for
    /// `Opcode::LoadImmJumpInd`.  Same JumpTableChip lookup as JumpInd
    /// but with `addr = (regs[rb] + imm_y) mod 2^32` (val_d + imm_y_low4
    /// in the AIR).  Bound via a separate carry chain into
    /// LoadImmJumpIndAddr.
    pub is_load_imm_jump_ind: bool,
    /// Phase 12c: split `is_mul_upper` into the three signedness variants
    /// so the AIR can apply the correct sign correction to the result.
    /// `is_mul_upper_uu` ⇒ result = unsigned-product high 64.
    /// `is_mul_upper_su` ⇒ result = signed-unsigned high = unsigned high − sa·val_d.
    /// `is_mul_upper_ss` ⇒ result = signed-signed   high = unsigned high − sa·val_d − sb·val_b.
    pub is_mul_upper_uu: bool,
    pub is_mul_upper_su: bool,
    pub is_mul_upper_ss: bool,
    /// Phase 16: signed div/rem variants (DivS32/DivS64/RemS32/RemS64).
    /// Drives the sign-correction at the divrem schoolbook's high bytes:
    ///   high(q_u·d_u + r_u) ≡ sq·d_u + sd·q_u + sr − sa  (mod 2^64)
    /// where sa/sd/sq/sr are the dividend/divisor/quotient/remainder
    /// sign bits.  Without this, signed divrem with any negative operand
    /// fails proving — the schoolbook's high bytes aren't zero in
    /// two's-complement.
    pub is_div_s: bool,
    /// Phase 20: per-size signed-load flags (covers direct + indirect
    /// variants: LoadI8 / LoadIndI8 → is_load_i8, etc.).  Drive the
    /// inactive-byte sign-extension binding for `result[i]` on
    /// `i ≥ MemSize`.  Without this, a prover could write garbage in
    /// the high bytes of a load result; the interpreter writes
    /// `0xFF · sign_bit` for signed loads (and `0` for unsigned).
    pub is_load_i8: bool,
    pub is_load_i16: bool,
    pub is_load_i32: bool,
    /// Phase 23: per-size memory-access flags covering both load and
    /// store variants.  Pin `MemSize = 1·is_mem_size_1 + 2·is_mem_size_2
    /// + 4·is_mem_size_4 + 8·is_mem_size_8`, so the prover can't pick a
    /// MemSize inconsistent with the opcode (closes the gap left at the
    /// end of Phase 22).  Exactly one is set per memory-op row, all
    /// zero on non-memory rows.
    pub is_mem_size_1: bool,
    pub is_mem_size_2: bool,
    pub is_mem_size_4: bool,
    pub is_mem_size_8: bool,
    /// Phase 24: 1 iff this opcode is `StoreU8 / StoreU16 / StoreU32 /
    /// StoreU64` (OneRegOneImm category — *direct* store, not Ind or
    /// Imm).  For these the trace fill's default arm puts `regs[ra]`
    /// (the source value) into `val_b`, so MemValue's active bytes
    /// can be pinned to `val_b`'s bytes by a single constraint.
    /// StoreInd* / StoreImm* / StoreImmInd* leave the source value in
    /// a different place and need their own bindings (deferred).
    pub is_store_direct: bool,
    /// Phase 25: 1 iff this opcode is one of the *direct* loads
    /// `LoadU8 / LoadI8 / LoadU16 / LoadI16 / LoadU32 / LoadI32 /
    /// LoadU64` (OneRegOneImm category).  For these the address is
    /// just the immediate (`addr = imm`); paired with IsStoreDirect
    /// drives the `MemAddr = ImmBytes[0..4]` binding.
    pub is_load_direct: bool,
    /// Phase 26: 1 iff this opcode is one of the *indirect* memory
    /// ops — LoadInd[U/I][8/16/32/64] (TwoRegOneImm), StoreInd[U/I]
    /// [8/16/32/64] (TwoRegOneImm), or StoreImmInd[U][8/16/32/64]
    /// (OneRegTwoImm).  For all three categories the trace fill
    /// puts the base register's value into `val_b` (regs[rb] for
    /// TwoRegOneImm, regs[ra] for OneRegTwoImm via the default
    /// match arm).  Drives the byte-wise add-with-carry chain
    /// pinning `MemAddr = (val_b + ImmBytes) mod 2^32`.
    pub is_mem_indirect: bool,
    /// Phase 27: 1 iff this opcode is one of `StoreImm[U][8/16/32/64]`
    /// (TwoImm category) or `StoreImmInd[U][8/16/32/64]`
    /// (OneRegTwoImm category).  In both cases the *value* written
    /// to memory is `imm_y` (already pinned to canonical via
    /// `ImmYCanon` in ProgramMemoryChip).  Drives the per-byte
    /// MemValue ↔ ImmYBytes binding for the low 4 bytes.  MemSize=8
    /// imm_y values are out of scope (would need ImmYBytesHi[4]).
    pub is_store_imm_any: bool,
    /// Phase 27: 1 iff this opcode is one of `StoreImm[U][8/16/32/64]`
    /// (TwoImm only — the *direct*-addressing immediate-source
    /// store).  For these `addr = imm_x = step.imm`, so the
    /// MemAddr binding shape is the same as Phase 25's direct path.
    pub is_store_imm_direct: bool,
    /// Phase 28: 1 iff this opcode is one of `StoreIndU[8/16/32/64]`
    /// (TwoRegOneImm — *register-source* indirect store).  For
    /// these the value written to memory is `regs[ra]`, which
    /// isn't in val_b (val_b holds the *base* regs[rb] for
    /// TwoRegOneImm).  Drives the new RegValA column + producer
    /// emission to the register-memory ledger, plus the
    /// MemValue ↔ RegValA byte-wise binding.
    pub is_store_ind: bool,
}

pub(super) fn classify_opcode(op: Opcode) -> OpcodeFlags {
    let mut f = OpcodeFlags::default();
    match op {
        Opcode::Add64 | Opcode::AddImm64 => { f.is_add = true; }
        Opcode::Add32 | Opcode::AddImm32 => { f.is_add = true; f.is_32bit = true; }
        Opcode::Sub64 => { f.is_sub = true; }
        Opcode::Sub32 => { f.is_sub = true; f.is_32bit = true; }
        Opcode::NegAddImm64 => { f.is_sub = true; f.is_neg_add = true; }
        Opcode::NegAddImm32 => { f.is_sub = true; f.is_neg_add = true; f.is_32bit = true; }
        Opcode::Mul64 | Opcode::MulImm64 => { f.is_mul = true; }
        Opcode::Mul32 | Opcode::MulImm32 => { f.is_mul = true; f.is_32bit = true; }
        // MulUpper: result = high 64 bits of 128-bit product
        Opcode::MulUpperUU => { f.is_mul = true; f.is_mul_upper = true; f.is_mul_upper_uu = true; }
        Opcode::MulUpperSS => { f.is_mul = true; f.is_mul_upper = true; f.is_mul_upper_ss = true; }
        Opcode::MulUpperSU => { f.is_mul = true; f.is_mul_upper = true; f.is_mul_upper_su = true; }
        Opcode::And | Opcode::AndImm => { f.is_bitwise = true; f.is_and = true; }
        Opcode::Or  | Opcode::OrImm  => { f.is_bitwise = true; f.is_or = true; }
        Opcode::Xor | Opcode::XorImm => { f.is_bitwise = true; f.is_xor = true; }
        Opcode::AndInv => { f.is_bitwise = true; f.is_and_inv = true; }
        Opcode::OrInv  => { f.is_bitwise = true; f.is_or_inv = true; }
        Opcode::Xnor   => { f.is_bitwise = true; f.is_xnor = true; }
        // Left shifts: constrained via mul (val_d = 2^shift_amount)
        Opcode::ShloL64 | Opcode::ShloLImm64 | Opcode::ShloLImmAlt64 => { f.is_shift = true; f.shift_op = 0; f.is_mul = true; }
        Opcode::ShloL32 | Opcode::ShloLImm32 | Opcode::ShloLImmAlt32 => { f.is_shift = true; f.shift_op = 0; f.is_mul = true; f.is_32bit = true; }
        // Logical right shifts: constrained via divrem (val_d = 2^shift_amount, result = quotient)
        Opcode::ShloR64 | Opcode::ShloRImm64 | Opcode::ShloRImmAlt64 => { f.is_shift = true; f.shift_op = 1; f.is_div_rem = true; f.div_rem_op = 0; }
        Opcode::ShloR32 | Opcode::ShloRImm32 | Opcode::ShloRImmAlt32 => { f.is_shift = true; f.shift_op = 1; f.is_div_rem = true; f.div_rem_op = 0; f.is_32bit = true; }
        // Arithmetic right shifts: same as logical right but with sign extension
        // Uses divrem + power-of-two (like ShloR). Sign extension handled separately.
        Opcode::SharR64 | Opcode::SharRImm64 | Opcode::SharRImmAlt64 => { f.is_shift = true; f.shift_op = 2; f.is_div_rem = true; f.div_rem_op = 0; }
        Opcode::SharR32 | Opcode::SharRImm32 | Opcode::SharRImmAlt32 => { f.is_shift = true; f.shift_op = 2; f.is_div_rem = true; f.div_rem_op = 0; f.is_32bit = true; }
        Opcode::RotL64 => { f.is_shift = true; f.shift_op = 3; }
        Opcode::RotL32 => { f.is_shift = true; f.shift_op = 3; f.is_32bit = true; }
        Opcode::RotR64 | Opcode::RotR64Imm | Opcode::RotR64ImmAlt => { f.is_shift = true; f.shift_op = 4; }
        Opcode::RotR32 | Opcode::RotR32Imm | Opcode::RotR32ImmAlt => { f.is_shift = true; f.shift_op = 4; f.is_32bit = true; }
        // Compare
        Opcode::SetLtU | Opcode::SetLtUImm => { f.is_compare = true; f.is_set_lt_u = true; }
        Opcode::SetLtS | Opcode::SetLtSImm => { f.is_compare = true; f.is_set_lt_s = true; }
        Opcode::SetGtUImm => { f.is_compare = true; f.is_set_lt_u = true; } // SetGt = swap + SetLt
        Opcode::SetGtSImm => { f.is_compare = true; f.is_set_lt_s = true; }
        Opcode::CmovIz | Opcode::CmovIzImm => { f.is_compare = true; f.is_cmov_iz = true; }
        Opcode::CmovNz | Opcode::CmovNzImm => { f.is_compare = true; f.is_cmov_nz = true; }
        Opcode::Min  => { f.is_compare = true; f.is_min_s = true; }
        Opcode::MinU => { f.is_compare = true; f.is_min_u = true; }
        Opcode::Max  => { f.is_compare = true; f.is_max_s = true; }
        Opcode::MaxU => { f.is_compare = true; f.is_max_u = true; }
        // Move
        Opcode::MoveReg | Opcode::LoadImm | Opcode::LoadImm64 => { f.is_move = true; }
        // BitManip (TwoReg unary ops).
        // Constrained (Phase 12b): ZeroExtend16, ReverseBytes (this commit).
        // Still prover-trusted: CountSetBits, LeadingZeroBits, TrailingZeroBits,
        // SignExtend8/16, Sbrk — see Phase 12a/12b-2/12f.
        Opcode::ZeroExtend16 => { f.is_zero_ext_16 = true; }
        Opcode::ReverseBytes => { f.is_reverse_bytes = true; }
        Opcode::SignExtend8 => { f.is_sign_ext_8 = true; }
        Opcode::SignExtend16 => { f.is_sign_ext_16 = true; }
        Opcode::CountSetBits64 | Opcode::CountSetBits32
        | Opcode::LeadingZeroBits64 | Opcode::LeadingZeroBits32
        | Opcode::TrailingZeroBits64 | Opcode::TrailingZeroBits32
        | Opcode::Sbrk
            => {}
        // Branches (conditional) — classify by comparison type
        // For Le/Gt variants we'll flip the operand order / invert
        Opcode::BranchEq | Opcode::BranchEqImm
            => { f.is_branch = true; f.is_br_eq = true; }
        Opcode::BranchNe | Opcode::BranchNeImm
            => { f.is_branch = true; f.is_br_ne = true; }
        // Unsigned: branch_taken = val_b < val_d
        Opcode::BranchLtU | Opcode::BranchLtUImm
            => { f.is_branch = true; f.is_br_lt_u = true; }
        // Unsigned: branch_taken = val_b >= val_d (= !lt)
        Opcode::BranchGeU | Opcode::BranchGeUImm
            => { f.is_branch = true; f.is_br_ge_u = true; }
        // Unsigned: branch_taken = val_b <= val_d (imm only; swap operands vs ge)
        Opcode::BranchLeUImm
            => { f.is_branch = true; f.is_br_le_u = true; }
        // Unsigned: branch_taken = val_b > val_d (imm only)
        Opcode::BranchGtUImm
            => { f.is_branch = true; f.is_br_gt_u = true; }
        // Signed: branch_taken = val_b < val_d (signed)
        Opcode::BranchLtS | Opcode::BranchLtSImm
            => { f.is_branch = true; f.is_br_lt_s = true; }
        Opcode::BranchGeS | Opcode::BranchGeSImm
            => { f.is_branch = true; f.is_br_ge_s = true; }
        Opcode::BranchLeSImm
            => { f.is_branch = true; f.is_br_le_s = true; }
        Opcode::BranchGtSImm
            => { f.is_branch = true; f.is_br_gt_s = true; }
        // DivRem
        Opcode::DivU64 => { f.is_div_rem = true; f.div_rem_op = 0; }
        Opcode::DivU32 => { f.is_div_rem = true; f.div_rem_op = 0; f.is_32bit = true; }
        Opcode::DivS64 => { f.is_div_rem = true; f.div_rem_op = 1; f.is_div_s = true; }
        Opcode::DivS32 => { f.is_div_rem = true; f.div_rem_op = 1; f.is_32bit = true; f.is_div_s = true; }
        Opcode::RemU64 => { f.is_div_rem = true; f.div_rem_op = 2; }
        Opcode::RemU32 => { f.is_div_rem = true; f.div_rem_op = 2; f.is_32bit = true; }
        Opcode::RemS64 => { f.is_div_rem = true; f.div_rem_op = 3; f.is_div_s = true; }
        Opcode::RemS32 => { f.is_div_rem = true; f.div_rem_op = 3; f.is_32bit = true; f.is_div_s = true; }
        // Loads — `is_mem_size_*` covers both load and store; set per
        // width.  `is_load_direct` set on the OneRegOneImm-category
        // direct loads (no Ind variant), driving the MemAddr ↔ ImmBytes
        // binding (Phase 25).
        Opcode::LoadU8
            => { f.is_load = true; f.is_mem_size_1 = true; f.is_load_direct = true; }
        Opcode::LoadIndU8
            => { f.is_load = true; f.is_mem_size_1 = true; f.is_mem_indirect = true; }
        Opcode::LoadU16
            => { f.is_load = true; f.is_mem_size_2 = true; f.is_load_direct = true; }
        Opcode::LoadIndU16
            => { f.is_load = true; f.is_mem_size_2 = true; f.is_mem_indirect = true; }
        Opcode::LoadU32
            => { f.is_load = true; f.is_mem_size_4 = true; f.is_load_direct = true; }
        Opcode::LoadIndU32
            => { f.is_load = true; f.is_mem_size_4 = true; f.is_mem_indirect = true; }
        Opcode::LoadU64
            => { f.is_load = true; f.is_mem_size_8 = true; f.is_load_direct = true; }
        Opcode::LoadIndU64
            => { f.is_load = true; f.is_mem_size_8 = true; f.is_mem_indirect = true; }
        Opcode::LoadI8
            => { f.is_load = true; f.is_load_i8 = true; f.is_mem_size_1 = true; f.is_load_direct = true; }
        Opcode::LoadIndI8
            => { f.is_load = true; f.is_load_i8 = true; f.is_mem_size_1 = true; f.is_mem_indirect = true; }
        Opcode::LoadI16
            => { f.is_load = true; f.is_load_i16 = true; f.is_mem_size_2 = true; f.is_load_direct = true; }
        Opcode::LoadIndI16
            => { f.is_load = true; f.is_load_i16 = true; f.is_mem_size_2 = true; f.is_mem_indirect = true; }
        Opcode::LoadI32
            => { f.is_load = true; f.is_load_i32 = true; f.is_mem_size_4 = true; f.is_load_direct = true; }
        Opcode::LoadIndI32
            => { f.is_load = true; f.is_load_i32 = true; f.is_mem_size_4 = true; f.is_mem_indirect = true; }
        // Stores — split by addressing mode (Phase 24 needs is_store_direct
        // set only on the OneRegOneImm-category direct stores; Ind / Imm
        // / ImmInd handle their source values differently).
        Opcode::StoreU8
            => { f.is_store = true; f.is_mem_size_1 = true; f.is_store_direct = true; }
        Opcode::StoreU16
            => { f.is_store = true; f.is_mem_size_2 = true; f.is_store_direct = true; }
        Opcode::StoreU32
            => { f.is_store = true; f.is_mem_size_4 = true; f.is_store_direct = true; }
        Opcode::StoreU64
            => { f.is_store = true; f.is_mem_size_8 = true; f.is_store_direct = true; }
        Opcode::StoreIndU8
            => { f.is_store = true; f.is_mem_size_1 = true; f.is_mem_indirect = true;
                 f.is_store_ind = true; }
        Opcode::StoreImmIndU8
            => { f.is_store = true; f.is_mem_size_1 = true; f.is_mem_indirect = true;
                 f.is_store_imm_any = true; }
        Opcode::StoreImmU8
            => { f.is_store = true; f.is_mem_size_1 = true;
                 f.is_store_imm_any = true; f.is_store_imm_direct = true; }
        Opcode::StoreIndU16
            => { f.is_store = true; f.is_mem_size_2 = true; f.is_mem_indirect = true;
                 f.is_store_ind = true; }
        Opcode::StoreImmIndU16
            => { f.is_store = true; f.is_mem_size_2 = true; f.is_mem_indirect = true;
                 f.is_store_imm_any = true; }
        Opcode::StoreImmU16
            => { f.is_store = true; f.is_mem_size_2 = true;
                 f.is_store_imm_any = true; f.is_store_imm_direct = true; }
        Opcode::StoreIndU32
            => { f.is_store = true; f.is_mem_size_4 = true; f.is_mem_indirect = true;
                 f.is_store_ind = true; }
        Opcode::StoreImmIndU32
            => { f.is_store = true; f.is_mem_size_4 = true; f.is_mem_indirect = true;
                 f.is_store_imm_any = true; }
        Opcode::StoreImmU32
            => { f.is_store = true; f.is_mem_size_4 = true;
                 f.is_store_imm_any = true; f.is_store_imm_direct = true; }
        Opcode::StoreIndU64
            => { f.is_store = true; f.is_mem_size_8 = true; f.is_mem_indirect = true;
                 f.is_store_ind = true; }
        Opcode::StoreImmIndU64
            => { f.is_store = true; f.is_mem_size_8 = true; f.is_mem_indirect = true;
                 f.is_store_imm_any = true; }
        Opcode::StoreImmU64
            => { f.is_store = true; f.is_mem_size_8 = true;
                 f.is_store_imm_any = true; f.is_store_imm_direct = true; }
        // Jumps (unconditional, non-sequential target)
        Opcode::Jump | Opcode::LoadImmJump
            => { f.is_jump = true; }
        // Fallthrough/Unlikely: pure sequential terminators (basic-block hints
        // with no semantic effect).  All flags stay 0 so the default
        // sequential-PC identity (next_pc = pc + 1 + skip_len) constrains them
        // — see fallthrough_forged_next_pc_rejected and
        // unlikely_forged_next_pc_rejected in tests/control_flow.rs.
        Opcode::Fallthrough | Opcode::Unlikely => {}
        // JumpInd / LoadImmJumpInd: dynamic dispatch.  Both pinned via
        // JumpTableChip lookups; JumpInd uses (val_b+imm), LoadImmJumpInd
        // uses (val_d+imm_y) for the addr computation.
        Opcode::JumpInd => { f.is_exit = true; f.is_jump_ind = true; }
        Opcode::LoadImmJumpInd => { f.is_exit = true; f.is_load_imm_jump_ind = true; }
        // Ecalli: host call (execution exits, no ALU constraint)
        Opcode::Ecalli | Opcode::Ecall => { f.is_exit = true; }
        // Trap: causes panic exit
        Opcode::Trap => { f.is_exit = true; f.is_trap = true; }
    }
    f
}

pub(super) fn uses_immediate(op: Opcode) -> bool {
    matches!(op,
        Opcode::AddImm32 | Opcode::AddImm64
        | Opcode::NegAddImm32 | Opcode::NegAddImm64
        | Opcode::MulImm32 | Opcode::MulImm64
        | Opcode::AndImm | Opcode::OrImm | Opcode::XorImm
        | Opcode::ShloLImm32 | Opcode::ShloRImm32 | Opcode::SharRImm32
        | Opcode::ShloLImmAlt32 | Opcode::ShloRImmAlt32 | Opcode::SharRImmAlt32
        | Opcode::ShloLImm64 | Opcode::ShloRImm64 | Opcode::SharRImm64
        | Opcode::ShloLImmAlt64 | Opcode::ShloRImmAlt64 | Opcode::SharRImmAlt64
        | Opcode::RotR64Imm | Opcode::RotR64ImmAlt | Opcode::RotR32Imm | Opcode::RotR32ImmAlt
        | Opcode::SetLtUImm | Opcode::SetLtSImm | Opcode::SetGtUImm | Opcode::SetGtSImm
        | Opcode::CmovIzImm | Opcode::CmovNzImm
        | Opcode::LoadImm | Opcode::LoadImm64
    )
}

pub(super) fn dest_reg(step: &crate::core::step::PvmStep) -> usize {
    use javm::instruction::InstructionCategory::*;
    match step.opcode.category() {
        ThreeReg => step.reg_d,
        _ => step.reg_a,
    }
}

/// Phase 13c (extended in 13e-redux + 13d + 13d-loadimmjumpind + 12c + 16 + 20 + 23 + 24 + 25 + 26 + 27 + 28):
/// extract the 40 category/sub-category flags in the order matching
/// ProgramMemoryChip's preprocessed columns.  Used by ProgramMemoryChip's
/// preprocessed-trace fill to pin flag values to the canonical
/// classify_opcode result.
pub(crate) fn classify_opcode_for_program_memory(op: Opcode) -> [u8; 40] {
    let f = classify_opcode(op);
    [
        f.is_add as u8, f.is_sub as u8, f.is_mul as u8, f.is_mul_upper as u8,
        f.is_bitwise as u8, f.is_shift as u8, f.is_compare as u8, f.is_move as u8,
        f.is_32bit as u8, f.is_branch as u8, f.is_jump as u8, f.is_div_rem as u8,
        f.is_load as u8, f.is_store as u8, f.is_exit as u8, f.is_neg_add as u8,
        f.is_reverse_bytes as u8, f.is_zero_ext_16 as u8,
        f.is_sign_ext_8 as u8, f.is_sign_ext_16 as u8,
        f.is_trap as u8, f.is_jump_ind as u8,
        f.is_load_imm_jump_ind as u8,
        f.is_mul_upper_uu as u8, f.is_mul_upper_su as u8, f.is_mul_upper_ss as u8,
        f.is_div_s as u8,
        f.is_load_i8 as u8, f.is_load_i16 as u8, f.is_load_i32 as u8,
        f.is_mem_size_1 as u8, f.is_mem_size_2 as u8,
        f.is_mem_size_4 as u8, f.is_mem_size_8 as u8,
        f.is_store_direct as u8,
        f.is_load_direct as u8,
        f.is_mem_indirect as u8,
        f.is_store_imm_any as u8, f.is_store_imm_direct as u8,
        f.is_store_ind as u8,
    ]
}
