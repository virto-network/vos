//! The cut's column families: the columns a program's code keeps,
//! computed from the code alone.

use super::*;

/// What an instruction or a host call may set, by which the families below
/// are taken.
#[derive(Clone, Copy)]
enum Use {
    /// An instruction of the opcode, its flags.
    Op(super::super::classify::OpcodeFlags),
    /// An `ecalli` naming the precompile.
    Call(u32),
}

/// A family's columns and whether a use sets them.
type Family = (&'static [Column], fn(Use) -> bool);

/// The CPU's columns that only some instructions or precompiles set, each
/// family with the uses that set it: a program holding none of a family's
/// uses has its columns cut. Every column of no family is set on every row
/// (the timestamps, the pc, the operands and the result, the flag bytes,
/// the register accesses, the signs, the zero tests of `val_d`, and the
/// helpers defined from them), and stays.
const FAMILIES: &[Family] = {
    use super::super::columns::Column::*;
    use crate::core::ecall::{ECALL_BLAKE2B_COMPRESS, ECALL_POSEIDON2, ECALL_WITNESS_INPUT};
    macro_rules! op {
        (|$f:ident| $predicate:expr) => {{
            fn uses(u: Use) -> bool {
                match u {
                    Use::Op($f) => $predicate,
                    Use::Call(_) => false,
                }
            }
            uses as fn(Use) -> bool
        }};
    }
    macro_rules! call {
        ($($id:expr),+) => {{
            fn uses(u: Use) -> bool {
                matches!(u, Use::Call(id) if $(id == $id)||+)
            }
            uses as fn(Use) -> bool
        }};
    }
    &[
        (&[IsAdd, IsAdd64bitH, IsAdd32bitH], op!(|f| f.is_add)),
        (&[Carry], op!(|f| f.is_add || f.is_sub)),
        (
            &[
                IsSub,
                IsSubNotNegaddH,
                IsSubNegaddH,
                IsSub64NotNegaddH,
                IsSub64NegaddH,
                IsSub32bitH,
            ],
            op!(|f| f.is_sub),
        ),
        (&[IsNegAdd], op!(|f| f.is_neg_add)),
        (&[IsMul, IsMul32bitH], op!(|f| f.is_mul)),
        (&[IsMulUpperUU], op!(|f| f.is_mul_upper_uu)),
        (&[IsMulUpperSU], op!(|f| f.is_mul_upper_su)),
        (&[IsMulUpperSS], op!(|f| f.is_mul_upper_ss)),
        (&[IsAnd], op!(|f| f.is_and)),
        (&[IsOr], op!(|f| f.is_or)),
        (&[IsXor], op!(|f| f.is_xor)),
        (&[IsAndInv], op!(|f| f.is_and_inv)),
        (&[IsOrInv], op!(|f| f.is_or_inv)),
        (&[IsXnor], op!(|f| f.is_xnor)),
        (&[IsShift, ShiftAmount], op!(|f| f.is_shift)),
        (
            &[
                IsShiftConstrained,
                ShiftQuotient,
                RealShiftCH,
                Is32ShiftCH,
                ShiftAmountPow2H,
            ],
            op!(|f| f.is_shift && f.shift_op <= 2
                || f.is_rotate_l64
                || f.is_rotate_r64
                || f.is_rotate_l32
                || f.is_rotate_r32),
        ),
        (&[IsSharR], op!(|f| f.is_shar_r)),
        (&[IsShloR], op!(|f| f.is_shlo_r)),
        (
            &[IsImmAlt, IsImmAltNotTruncH, IsImmAltTruncH],
            op!(|f| f.is_imm_alt),
        ),
        (&[IsRotateL64], op!(|f| f.is_rotate_l64)),
        (&[IsRotateR64], op!(|f| f.is_rotate_r64)),
        (&[IsRotateL32], op!(|f| f.is_rotate_l32)),
        (&[IsRotateR32], op!(|f| f.is_rotate_r32)),
        (
            &[
                ShiftAmountCompl,
                ShiftQuotientCompl,
                ShiftComplInv,
                ShiftComplGateH,
            ],
            op!(|f| f.is_rotate_r64 || f.is_rotate_r32 || f.is_shlo_r),
        ),
        (&[IsMove], op!(|f| f.is_move)),
        (&[IsSetLtU], op!(|f| f.is_set_lt_u)),
        (&[IsSetLtS], op!(|f| f.is_set_lt_s)),
        (&[IsSetGt], op!(|f| f.is_set_gt)),
        (&[IsCmovIz, IsCmovIzVdzH], op!(|f| f.is_cmov_iz)),
        (&[IsCmovNz, IsCmovNzNotVdzH], op!(|f| f.is_cmov_nz)),
        (&[IsCmovImm], op!(|f| f.is_cmov_imm)),
        (&[IsMinS], op!(|f| f.is_min_s)),
        (&[IsMinU], op!(|f| f.is_min_u)),
        (&[IsMaxS], op!(|f| f.is_max_s)),
        (&[IsMaxU], op!(|f| f.is_max_u)),
        (&[IsCmpVdzH], op!(|f| f.is_compare)),
        (
            &[
                CmpLtFlag,
                CmpLtSFlag,
                MinMaxLtFlag,
                CmpLtValBH,
                CmpLtValDH,
                IsCmpOrBranchEqH,
            ],
            op!(|f| f.is_compare || f.is_branch),
        ),
        (&[IsBrEq], op!(|f| f.is_br_eq)),
        (&[IsBrNe], op!(|f| f.is_br_ne)),
        (&[IsBrLtU], op!(|f| f.is_br_lt_u)),
        (&[IsBrGeU], op!(|f| f.is_br_ge_u)),
        (&[IsBrLeU], op!(|f| f.is_br_le_u)),
        (&[IsBrGtU], op!(|f| f.is_br_gt_u)),
        (&[IsBrLtS], op!(|f| f.is_br_lt_s)),
        (&[IsBrGeS], op!(|f| f.is_br_ge_s)),
        (&[IsBrLeS], op!(|f| f.is_br_le_s)),
        (&[IsBrGtS], op!(|f| f.is_br_gt_s)),
        (&[IsBranchTakenH], op!(|f| f.is_branch)),
        (&[IsJump], op!(|f| f.is_jump)),
        (
            &[BranchTaken, BranchTarget],
            op!(|f| f.is_branch || f.is_jump),
        ),
        (
            &[
                IsDivRem,
                DivRemOp,
                DivQuotient,
                DivRemainder,
                DivByZero,
                CpuDivActiveH,
                GateRemH,
                DivActiveQuotH,
                DivActiveRemH,
                IsDivRem32bitH,
                IsDivRemTimesVdzH,
                DbzActiveH,
                DbzActiveQuotH,
                DbzActiveRemH,
                DbzActiveRem64H,
                SignBitQ,
                SignBitR,
                SignQHiNib,
                SignRHiNib,
                SignSrcQ,
                SignSrcR,
                ValRByteInv,
                ValRPartialNZ,
                ValRByteIndicatorH,
                ValRByteIndMinus1H,
                ValRPartNZTimesIndH,
            ],
            op!(|f| f.is_div_rem),
        ),
        (
            &[IsDivS, IsDivSNotDbzH, DivSActivePartialH],
            op!(|f| f.is_div_s),
        ),
        (&[IsLoad, IsLoadLocalNotActiveH], op!(|f| f.is_load)),
        (
            &[
                MemAddr,
                MemValue,
                MemSize,
                MemByteActive,
                MemByteAddrCarry1,
                MemByteAddrCarry2,
                MemByteAddrCarry3,
                IsStandardMemH,
                MemLastAddrCarryH,
                MemRangeProductH,
                MemRangeInv,
                MemRangeTimesInvH,
            ],
            op!(|f| f.is_load || f.is_store),
        ),
        (&[IsMemSize1], op!(|f| f.is_mem_size_1)),
        (&[IsMemSize2], op!(|f| f.is_mem_size_2)),
        (&[IsMemSize4], op!(|f| f.is_mem_size_4)),
        (&[IsMemSize8], op!(|f| f.is_mem_size_8)),
        (&[IsLoadI8], op!(|f| f.is_load_i8)),
        (&[IsLoadI16], op!(|f| f.is_load_i16)),
        (&[IsLoadI32], op!(|f| f.is_load_i32)),
        (
            &[LoadSignSrc, LoadSignBit, LoadSignHiNib],
            op!(|f| f.is_load_i8 || f.is_load_i16 || f.is_load_i32),
        ),
        (&[IsStoreDirect], op!(|f| f.is_store_direct)),
        (&[IsLoadDirect], op!(|f| f.is_load_direct)),
        (&[IsMemIndirect, MemAddrCarry], op!(|f| f.is_mem_indirect)),
        (&[IsStoreImmAny], op!(|f| f.is_store_imm_any)),
        (&[IsStoreImmDirect], op!(|f| f.is_store_imm_direct)),
        (&[IsStoreInd, RegValA], op!(|f| f.is_store_ind)),
        (&[IsReverseBytes], op!(|f| f.is_reverse_bytes)),
        (&[IsZeroExt16], op!(|f| f.is_zero_ext_16)),
        (&[IsSignExt8], op!(|f| f.is_sign_ext_8)),
        (&[IsSignExt16], op!(|f| f.is_sign_ext_16)),
        (
            &[SignExtBit, SignExtSrcHiNib],
            op!(|f| f.is_sign_ext_8 || f.is_sign_ext_16),
        ),
        (
            &[IsCountSetBits, BytePopcount, Is64bitPopcountHiH],
            op!(|f| f.is_count_set_bits),
        ),
        (&[IsLzb, IsLzb64H, IsLzb32H], op!(|f| f.is_lzb)),
        (&[IsTzb, IsTzb64H, IsTzb32H], op!(|f| f.is_tzb)),
        (&[BitOpLzByte, BitOpTzByte], op!(|f| f.is_lzb || f.is_tzb)),
        (
            &[IsJumpInd, IsHaltJumpInd, JumpIndAddr, JumpIndCarry],
            op!(|f| f.is_jump_ind),
        ),
        (
            &[
                IsLoadImmJumpInd,
                IsHaltLoadImmJumpInd,
                LoadImmJumpIndAddr,
                LoadImmJumpIndCarry,
            ],
            op!(|f| f.is_load_imm_jump_ind),
        ),
        (
            &[ImmYBytes],
            op!(|f| f.is_store_imm_any || f.is_load_imm_jump_ind),
        ),
        (
            &[
                IsBlakeEcall,
                TLow,
                Flag,
                FlagInv,
                FlagBool,
                RealFlagBoolH,
                FlagTimesInvH,
            ],
            call!(ECALL_BLAKE2B_COMPRESS),
        ),
        (
            &[HPtr, MPtr],
            call!(ECALL_BLAKE2B_COMPRESS, ECALL_WITNESS_INPUT, ECALL_POSEIDON2),
        ),
        (
            &[
                IsWitnessEcall,
                WitnessNonEmpty,
                WitnessCountInv,
                WitnessCountTimesInvH,
            ],
            call!(ECALL_WITNESS_INPUT),
        ),
        (&[IsP2Ecall], call!(ECALL_POSEIDON2)),
        (
            &[HostCallAcknowledged, HostCallPrecompileDispatch],
            op!(|f| f.is_exit && !f.is_trap && !f.is_jump_ind && !f.is_load_imm_jump_ind),
        ),
    ]
};

impl CpuColumns {
    /// The columns every row may set: those of no family.
    pub fn always() -> Self {
        let mut set = Self::ALL;
        for (columns, _) in FAMILIES {
            for &column in *columns {
                set.0[column as usize / 64] &= !(1 << (column as usize % 64));
            }
        }
        set
    }

    /// The columns of the program `code`, its instruction starts marked in
    /// `bitmask`: every row's, and each family's whose uses an instruction
    /// of it or a precompile an `ecalli` of it names. An instruction start
    /// of no opcode is a trap's. From the code alone, so a path a run does
    /// not take is covered, and the set is the program's.
    pub fn of_code(code: &[u8], bitmask: &[u8]) -> Self {
        use vos_pvm::instruction::{Opcode, decode_opcode_fast};
        let mut uses = alloc::vec::Vec::new();
        for (pc, &byte) in code.iter().enumerate() {
            if bitmask.get(pc) != Some(&1) {
                continue;
            }
            let (op, category) = decode_opcode_fast(byte).unwrap_or((
                Opcode::Invalid,
                vos_pvm::instruction::InstructionCategory::NoArgs,
            ));
            uses.push(Use::Op(super::super::classify::classify_opcode(op)));
            if op == Opcode::Ecalli {
                let skip = vos_pvm::gas_cost::skip_distance(bitmask, pc);
                if let vos_pvm::args::Args::Imm { imm } =
                    vos_pvm::args::decode_args(code, pc, skip, category)
                    && let Ok(id) = u32::try_from(imm)
                {
                    uses.push(Use::Call(id));
                }
            }
        }
        Self::of_uses(&uses)
    }

    fn of_uses(uses: &[Use]) -> Self {
        let mut set = Self::always();
        for (columns, used) in FAMILIES {
            if uses.iter().any(|&u| used(u)) {
                for &column in *columns {
                    set.insert(column);
                }
            }
        }
        set
    }
}
