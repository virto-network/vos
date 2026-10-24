//! The tuples the CPU chip's rows send the arithmetic chips, and the flag
//! sums their multiplicities are, as lists of its columns: the constraints
//! and the interaction trace read the same lists, in the same order.

use super::columns::Column::{self, *};

/// MultiplicationLookup's tuple up to IsMulLo: the operands, the result,
/// the operands' signs and the rotate flags.
pub(super) const MUL_HEAD: [Column; 9] = [
    ValB,
    ValD,
    Result,
    SignBitB,
    SignBitD,
    IsRotateL64,
    IsRotateR64,
    IsRotateL32,
    IsRotateR32,
];

/// The multiplication's upper-half flags. IsMulLo, the tuple's limb after
/// [`MUL_HEAD`], is no column: it is `IsMul` less these.
pub(super) const MUL_UPPER: [Column; 3] = [IsMulUpperUU, IsMulUpperSU, IsMulUpperSS];

/// MultiplicationLookup's tuple after IsMulLo: the upper-half flags and the
/// width.
pub(super) const MUL_TAIL: [Column; 4] = [IsMulUpperUU, IsMulUpperSU, IsMulUpperSS, Is32Bit];

/// DivRemLookup's tuple: the operands, the quotient, the remainder, the
/// four signs, the operation's flags and whether the divisor is zero.
pub(super) const DIVREM: [Column; 13] = [
    ValB,
    ValD,
    DivQuotient,
    DivRemainder,
    SignBitB,
    SignBitD,
    SignBitQ,
    SignBitR,
    IsDivRem,
    DivByZero,
    Is32Bit,
    IsDivS,
    IsSharR,
];

/// CompareLookup's tuple: the operands and the unsigned less-than.
pub(super) const COMPARE: [Column; 3] = [ValB, ValD, CmpLtFlag];

/// The comparisons' flags; IsCompare is their sum.
pub(super) const COMPARE_FLAGS: [Column; 8] = [
    IsSetLtU, IsSetLtS, IsCmovIz, IsCmovNz, IsMinS, IsMinU, IsMaxS, IsMaxU,
];

/// The branches' flags; IsBranch is their sum.
pub(super) const BRANCH_FLAGS: [Column; 10] = [
    IsBrEq, IsBrNe, IsBrLtU, IsBrGeU, IsBrLeU, IsBrGtU, IsBrLtS, IsBrGeS, IsBrLeS, IsBrGtS,
];

/// The stores' flags; IsStore is their sum.
pub(super) const STORE_FLAGS: [Column; 3] = [IsStoreDirect, IsStoreImmAny, IsStoreInd];

/// BitwiseLookup's tuple: the operands, the result and the operation's
/// flags.
pub(super) const BITWISE: [Column; 9] = [
    ValB, ValD, Result, IsAnd, IsOr, IsXor, IsAndInv, IsOrInv, IsXnor,
];

/// The bitwise operations' flags; IsBitwise is their sum.
pub(super) const BITWISE_FLAGS: [Column; 6] = [IsAnd, IsOr, IsXor, IsAndInv, IsOrInv, IsXnor];

/// ProgramMemoryLookup's tuple, the instruction a step fetches: its pc,
/// opcode, length and registers, its immediate, the ten flag bytes, the
/// second immediate, the branch target and the host call's dispatch.
pub(super) const PROGRAM_MEMORY: [Column; 20] = [
    Pc,
    Opcode,
    SkipLen,
    RegA,
    RegB,
    RegD,
    ImmBytes,
    FlagByte0,
    FlagByte1,
    FlagByte2,
    FlagByte3,
    FlagByte4,
    FlagByte5,
    FlagByte6,
    FlagByte7,
    FlagByte8,
    FlagByte9,
    ImmYBytes,
    BranchTarget,
    HostCallPrecompileDispatch,
];

/// ByteToBits' tuples for flag bytes 0 to 5: each byte, and its eight
/// bits, low first, each a flag or a sum of flags (the categories IsBitwise,
/// IsCompare, IsBranch and IsStore). The program memory packs the flags in
/// this layout (`pack_flags`).
pub(super) const FLAG_BYTES: [(Column, [&[Column]; 8]); 6] = [
    (
        FlagByte0,
        [
            &[IsAdd],
            &[IsSub],
            &[IsMul],
            &[IsSharR],
            &BITWISE_FLAGS,
            &[IsShift],
            &COMPARE_FLAGS,
            &[IsMove],
        ],
    ),
    (
        FlagByte1,
        [
            &[Is32Bit],
            &BRANCH_FLAGS,
            &[IsJump],
            &[IsDivRem],
            &[IsLoad],
            &STORE_FLAGS,
            &[IsExit],
            &[IsNegAdd],
        ],
    ),
    (
        FlagByte2,
        [
            &[IsReverseBytes],
            &[IsZeroExt16],
            &[IsSignExt8],
            &[IsSignExt16],
            &[IsTrap],
            &[IsJumpInd],
            &[IsLoadImmJumpInd],
            &[IsMulUpperUU],
        ],
    ),
    (
        FlagByte3,
        [
            &[IsMulUpperSU],
            &[IsMulUpperSS],
            &[IsDivS],
            &[IsLoadI8],
            &[IsLoadI16],
            &[IsLoadI32],
            &[IsMemSize1],
            &[IsMemSize2],
        ],
    ),
    (
        FlagByte4,
        [
            &[IsMemSize4],
            &[IsMemSize8],
            &[IsStoreDirect],
            &[IsLoadDirect],
            &[IsMemIndirect],
            &[IsStoreImmAny],
            &[IsStoreImmDirect],
            &[IsStoreInd],
        ],
    ),
    (
        FlagByte5,
        [
            &[IsRotateL64],
            &[IsCountSetBits],
            &[IsLzb],
            &[IsTzb],
            &[IsRotateR64],
            &[IsRotateL32],
            &[IsRotateR32],
            &[IsImmAlt],
        ],
    ),
];

/// The registers a BLAKE2b call reads, in its slots' order (`Phi7`,
/// `Phi10`, `Phi11`, `Phi12`): φ[10] the flag, φ[7] the state's pointer,
/// φ[8] the message's, φ[9] the counter's low word. The precompile shim's
/// a0..a3 are φ[7..=10] after the transpiler's register map.
pub(super) const BLAKE2B_CALL_REGS: [u32; 4] = [10, 7, 8, 9];

/// The number of limbs `columns` hold.
#[cfg(feature = "prover")]
pub(super) fn width(columns: &[Column]) -> usize {
    columns.iter().map(|column| column.const_size()).sum()
}
