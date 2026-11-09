//! The per-program CPU (`docs/design/proving.md` §8): the CPU chip with the
//! columns its program's code never sets cut.
//!
//! - **The cut** ([`CpuColumns`]) is a set of the CPU's columns, computed
//!   from the program's code alone ([`CpuColumns::of_code`]): every column
//!   an instruction the code holds, or a precompile an `ecalli` of it names,
//!   may set, and the columns every row sets. The program's id and its
//!   transcript take it, so a proof's CPU is the program's.
//! - **The chip** ([`ProgramCpuChip`]) is [`CpuChip`](super::CpuChip)'s AIR
//!   with every cut column the constant zero: each constraint and relation
//!   entry kept, but those that are identically zero once the cut columns
//!   are, which neither the composition nor the interaction trace then
//!   holds. Its traces are a subset of the full CPU's, the cut columns
//!   zero: what the full AIR admits with those columns zero, the cut AIR
//!   admits, and nothing else, so it proves no statement the full CPU does
//!   not.
//! - **The code binds the cut:** an instruction's flags are its code's, by
//!   the program memory's lookup, so a step of an operation the code does
//!   not hold is refused by the full AIR as by the cut one; a cut that drops
//!   a column the program's run sets is a run the prover cannot prove (its
//!   constraints fail at the prover's own check), never a proof. The fill
//!   sets a column on its instructions' rows alone, so an honest run's
//!   cut columns are already zero and its cut trace is its full one.

use num_traits::{One, Zero};
use stwo::core::Fraction;
use stwo::core::fields::FieldExpOps;
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use stwo_constraint_framework::preprocessed_columns::PreProcessedColumnId;
use stwo_constraint_framework::{EvalAtRow, Relation, RelationEntry};

use super::columns::{Column, PreprocessedColumn, Row};
use super::constraints::{self, Lookups};
use crate::air_column::AirColumn;
use crate::framework::BuiltInComponent;
use crate::lookups::ComponentLookupElements;
use crate::trace::eval::TraceEval;

/// The CPU's column variants.
const VARIANTS: usize = Column::ALL_VARIANTS.len();

/// The words of a [`CpuColumns`].
pub const CPU_COLUMN_WORDS: usize = VARIANTS.div_ceil(64);

/// A set of the CPU's columns: bit `i` of word `i / 64` the `i`-th
/// [`Column`] variant, in declaration order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct CpuColumns([u64; CPU_COLUMN_WORDS]);

impl CpuColumns {
    /// Every column: the full CPU's.
    pub const ALL: Self = {
        let mut words = [u64::MAX; CPU_COLUMN_WORDS];
        let spare = CPU_COLUMN_WORDS * 64 - VARIANTS;
        words[CPU_COLUMN_WORDS - 1] >>= spare;
        Self(words)
    };

    /// No column.
    pub const NONE: Self = Self([0; CPU_COLUMN_WORDS]);

    /// Its words.
    pub fn words(&self) -> [u64; CPU_COLUMN_WORDS] {
        self.0
    }

    /// Whether it holds `column`.
    pub fn contains(&self, column: Column) -> bool {
        let index = column as usize;
        self.0[index / 64] >> (index % 64) & 1 == 1
    }

    /// It with `column`.
    pub fn insert(&mut self, column: Column) {
        let index = column as usize;
        self.0[index / 64] |= 1 << (index % 64);
    }

    /// Whether it holds every column `other` holds.
    pub fn covers(&self, other: &Self) -> bool {
        self.0
            .iter()
            .zip(other.0)
            .all(|(word, theirs)| theirs & !word == 0)
    }

    /// The trace columns it commits: each variant's limbs.
    pub fn width(&self) -> usize {
        Column::ALL_VARIANTS
            .iter()
            .filter(|&&column| self.contains(column))
            .map(|column| column.size())
            .sum()
    }

    /// Whether the trace column at `offset` is one of its variants' limbs.
    pub fn holds_offset(&self, offset: usize) -> bool {
        Column::ALL_VARIANTS
            .iter()
            .find(|column| (column.offset()..column.offset() + column.size()).contains(&offset))
            .is_some_and(|&column| self.contains(column))
    }
}

/// The most constraints a CPU's row holds that a [`ProgramCpuChip`] counts.
const CONSTRAINT_WORDS: usize = 16;

/// The CPU chip with the columns a [`CpuColumns`] does not hold cut: their
/// values zero, the constraints and relation entries that are then
/// identically zero omitted.
#[derive(Clone, Copy, Debug)]
pub struct ProgramCpuChip {
    columns: CpuColumns,
    /// Bit `i`: the `i`-th constraint in the AIR's order is kept.
    constraints: [u64; CONSTRAINT_WORDS],
    /// Bit `i`: the `i`-th relation entry is kept.
    fractions: u128,
}

impl ProgramCpuChip {
    /// The CPU over `columns`: the constraints and relation entries that are
    /// not identically zero once every other column is.
    pub fn new(columns: CpuColumns) -> Self {
        let mut zero = Zeros::default();
        let trace_eval =
            TraceEval::<PreprocessedColumn, Column, Zeros>::with_columns(&mut zero, |column| {
                columns.contains(column)
            });
        constraints::all(&mut zero, &Row::new(&trace_eval), &Lookups::dummy());
        Self {
            columns,
            constraints: zero.constraints,
            fractions: zero.fractions,
        }
    }

    /// Its columns.
    pub fn columns(&self) -> &CpuColumns {
        &self.columns
    }

    /// The relation entries it keeps, bit `i` the `i`-th in the AIR's order.
    pub fn kept_fractions(&self) -> u128 {
        self.fractions
    }

    /// The constraints it keeps.
    pub fn kept_constraints(&self) -> usize {
        self.constraints
            .iter()
            .map(|word| word.count_ones() as usize)
            .sum()
    }
}

impl BuiltInComponent for ProgramCpuChip {
    const LOG_CONSTRAINT_DEGREE_BOUND: u32 =
        <super::CpuChip as BuiltInComponent>::LOG_CONSTRAINT_DEGREE_BOUND;

    type PreprocessedColumn = PreprocessedColumn;
    type MainColumn = Column;
    type LookupElements = Lookups;

    fn trace_eval<E: EvalAtRow>(&self, eval: &mut E) -> TraceEval<PreprocessedColumn, Column, E> {
        TraceEval::with_columns(eval, |column| self.columns.contains(column))
    }

    fn add_constraints<E: EvalAtRow>(
        &self,
        eval: &mut E,
        trace_eval: TraceEval<PreprocessedColumn, Column, E>,
        lookups: &Lookups,
    ) {
        let mut kept = Kept {
            eval,
            constraints: &self.constraints,
            fractions: self.fractions,
            constraint: 0,
            fraction: 0,
        };
        constraints::all(&mut kept, &Row::new(&trace_eval), lookups);
    }
}

/// An evaluator forwarding to `eval` the constraints and relation entries a
/// [`ProgramCpuChip`] keeps, by their index in the AIR's order.
struct Kept<'a, E> {
    eval: &'a mut E,
    constraints: &'a [u64; CONSTRAINT_WORDS],
    fractions: u128,
    constraint: usize,
    fraction: usize,
}

impl<E> Kept<'_, E> {
    /// Whether the next relation entry is kept, counting it.
    fn take_fraction(&mut self) -> bool {
        let index = self.fraction;
        self.fraction += 1;
        assert!(index < 128, "a kept fraction past the mask");
        self.fractions >> index & 1 == 1
    }
}

impl<E: EvalAtRow> EvalAtRow for Kept<'_, E> {
    type F = E::F;
    type EF = E::EF;

    fn next_trace_mask(&mut self) -> Self::F {
        self.eval.next_trace_mask()
    }

    fn get_preprocessed_column(&mut self, column: PreProcessedColumnId) -> Self::F {
        self.eval.get_preprocessed_column(column)
    }

    fn next_interaction_mask<const N: usize>(
        &mut self,
        interaction: usize,
        offsets: [isize; N],
    ) -> [Self::F; N] {
        self.eval.next_interaction_mask(interaction, offsets)
    }

    fn next_extension_interaction_mask<const N: usize>(
        &mut self,
        interaction: usize,
        offsets: [isize; N],
    ) -> [Self::EF; N] {
        self.eval
            .next_extension_interaction_mask(interaction, offsets)
    }

    fn add_constraint<G>(&mut self, constraint: G)
    where
        Self::EF: core::ops::Mul<G, Output = Self::EF> + From<G>,
    {
        let index = self.constraint;
        self.constraint += 1;
        if self.constraints[index / 64] >> (index % 64) & 1 == 1 {
            self.eval.add_constraint(constraint);
        }
    }

    fn add_intermediate(&mut self, value: Self::F) -> Self::F {
        self.eval.add_intermediate(value)
    }

    fn add_extension_intermediate(&mut self, value: Self::EF) -> Self::EF {
        self.eval.add_extension_intermediate(value)
    }

    fn combine_ef(values: [Self::F; 4]) -> Self::EF {
        E::combine_ef(values)
    }

    fn add_to_relation<R: Relation<Self::F, Self::EF>>(
        &mut self,
        entry: RelationEntry<'_, Self::F, Self::EF, R>,
    ) {
        if self.take_fraction() {
            self.eval.add_to_relation(entry);
        }
    }

    fn write_logup_frac(&mut self, fraction: Fraction<Self::EF, Self::EF>) {
        if self.take_fraction() {
            self.eval.write_logup_frac(fraction);
        }
    }

    fn finalize_logup_batched(&mut self, batching: &alloc::vec::Vec<usize>) {
        self.eval.finalize_logup_batched(batching);
    }

    fn finalize_logup(&mut self) {
        self.eval.finalize_logup();
    }

    fn finalize_logup_in_pairs(&mut self) {
        self.eval.finalize_logup_in_pairs();
    }
}

/// Whether a value may be non-zero: `false` only for a value identically
/// zero, a sum of such and a product with one.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Live(bool);

/// An evaluator recording which constraints and relation entries' numerators
/// are identically zero ([`Live`]), the cut columns read as zero.
#[derive(Default)]
struct Zeros {
    constraints: [u64; CONSTRAINT_WORDS],
    fractions: u128,
    constraint: usize,
    fraction: usize,
}

impl EvalAtRow for Zeros {
    type F = Live;
    type EF = Live;

    fn next_interaction_mask<const N: usize>(
        &mut self,
        _interaction: usize,
        _offsets: [isize; N],
    ) -> [Live; N] {
        [Live(true); N]
    }

    fn get_preprocessed_column(&mut self, _column: PreProcessedColumnId) -> Live {
        Live(true)
    }

    fn add_constraint<G>(&mut self, constraint: G)
    where
        Live: core::ops::Mul<G, Output = Live> + From<G>,
    {
        let index = self.constraint;
        assert!(
            index < CONSTRAINT_WORDS * 64,
            "a CPU with more constraints than a ProgramCpuChip counts"
        );
        self.constraint += 1;
        if Live::from(constraint).0 {
            self.constraints[index / 64] |= 1 << (index % 64);
        }
    }

    fn combine_ef(values: [Live; 4]) -> Live {
        Live(values.iter().any(|value| value.0))
    }

    fn write_logup_frac(&mut self, fraction: Fraction<Live, Live>) {
        let index = self.fraction;
        assert!(
            index < 128,
            "a CPU with more relation entries than a ProgramCpuChip counts"
        );
        self.fraction += 1;
        if fraction.numerator.0 {
            self.fractions |= 1 << index;
        }
    }
}

impl Zero for Live {
    fn zero() -> Self {
        Self(false)
    }

    fn is_zero(&self) -> bool {
        !self.0
    }
}

impl One for Live {
    fn one() -> Self {
        Self(true)
    }
}

impl core::ops::Add for Live {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        Self(self.0 || other.0)
    }
}

impl core::ops::Sub for Live {
    type Output = Self;

    fn sub(self, other: Self) -> Self {
        Self(self.0 || other.0)
    }
}

impl core::ops::Mul for Live {
    type Output = Self;

    fn mul(self, other: Self) -> Self {
        Self(self.0 && other.0)
    }
}

impl core::ops::Neg for Live {
    type Output = Self;

    fn neg(self) -> Self {
        self
    }
}

impl core::ops::AddAssign for Live {
    fn add_assign(&mut self, other: Self) {
        *self = *self + other;
    }
}

impl core::ops::MulAssign for Live {
    fn mul_assign(&mut self, other: Self) {
        *self = *self * other;
    }
}

impl core::ops::AddAssign<BaseField> for Live {
    fn add_assign(&mut self, other: BaseField) {
        *self = *self + Self::from(other);
    }
}

impl core::ops::Add<BaseField> for Live {
    type Output = Self;

    fn add(self, other: BaseField) -> Self {
        self + Self::from(other)
    }
}

impl core::ops::Mul<BaseField> for Live {
    type Output = Self;

    fn mul(self, other: BaseField) -> Self {
        self * Self::from(other)
    }
}

impl core::ops::Add<SecureField> for Live {
    type Output = Self;

    fn add(self, other: SecureField) -> Self {
        self + Self::from(other)
    }
}

impl core::ops::Sub<SecureField> for Live {
    type Output = Self;

    fn sub(self, other: SecureField) -> Self {
        self - Self::from(other)
    }
}

impl core::ops::Mul<SecureField> for Live {
    type Output = Self;

    fn mul(self, other: SecureField) -> Self {
        self * Self::from(other)
    }
}

impl From<BaseField> for Live {
    fn from(value: BaseField) -> Self {
        Self(!value.is_zero())
    }
}

impl From<SecureField> for Live {
    fn from(value: SecureField) -> Self {
        Self(!value.is_zero())
    }
}

impl FieldExpOps for Live {
    /// May be non-zero: no constraint inverts, and a value it would invert
    /// is not known to be a polynomial's.
    fn inverse(&self) -> Self {
        Self(true)
    }
}

/// What an instruction or a host call may set, by which the families below
/// are taken.
#[cfg(feature = "prover")]
#[derive(Clone, Copy)]
enum Use {
    /// An instruction of the opcode, its flags.
    Op(super::classify::OpcodeFlags),
    /// An `ecalli` naming the precompile.
    Call(u32),
}

/// A family's columns and whether a use sets them.
#[cfg(feature = "prover")]
type Family = (&'static [Column], fn(Use) -> bool);

/// The CPU's columns that only some instructions or precompiles set, each
/// family with the uses that set it: a program holding none of a family's
/// uses has its columns cut. Every column of no family is set on every row
/// (the timestamps, the pc, the operands and the result, the flag bytes,
/// the register accesses, the signs, the zero tests of `val_d`, and the
/// helpers defined from them), and stays.
#[cfg(feature = "prover")]
const FAMILIES: &[Family] = {
    use super::columns::Column::*;
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

#[cfg(feature = "prover")]
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
            uses.push(Use::Op(super::classify::classify_opcode(op)));
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

#[cfg(feature = "prover")]
impl ProgramCpuChip {
    /// `trace`, a run's full CPU trace, with its cut columns zeroed: what
    /// the per-program CPU commits of it (its columns in [`Self::committed`]).
    pub fn cut(&self, trace: &mut crate::trace::component::ComponentTrace) {
        for (offset, column) in trace.original_trace.iter_mut().enumerate() {
            if !self.columns.holds_offset(offset) {
                column.data.fill(Zero::zero());
            }
        }
    }

    /// The columns of `trace` the per-program CPU commits, in order.
    pub fn committed<'a>(
        &self,
        trace: &'a crate::trace::component::ComponentTrace,
    ) -> impl Iterator<Item = &'a stwo::prover::backend::simd::column::BaseColumn> {
        let columns = self.columns;
        trace
            .original_trace
            .iter()
            .enumerate()
            .filter(move |(offset, _)| columns.holds_offset(*offset))
            .map(|(_, column)| column)
    }

    /// Its interaction trace and claimed sum over `trace` (cut,
    /// [`Self::cut`]): the kept relation entries', in the AIR's order.
    pub fn interaction_trace(
        &self,
        trace: &crate::trace::component::ComponentTrace,
        lookup_elements: &crate::lookups::AllLookupElements,
    ) -> (
        stwo::core::ColumnVec<
            stwo::prover::poly::circle::CircleEvaluation<
                stwo::prover::backend::simd::SimdBackend,
                BaseField,
                stwo::prover::poly::BitReversedOrder,
            >,
        >,
        SecureField,
    ) {
        super::interaction::interaction_trace(trace, lookup_elements, self.fractions)
    }
}

#[cfg(all(test, feature = "prover"))]
mod tests {
    use stwo::core::channel::Blake2sM31Channel;
    use stwo::prover::backend::simd::column::BaseColumn;
    use vos_pvm::PVM_REGISTER_COUNT;
    use vos_pvm::instruction::{InstructionCategory, Opcode, decode_opcode_fast};
    use vos_pvm::interpreter::Interpreter;

    use super::*;
    use crate::chips::CpuChip;
    use crate::core::ecall::{ECALL_BLAKE2B_COMPRESS, ECALL_POSEIDON2, ECALL_WITNESS_INPUT};
    use crate::core::tracing::TracingPvm;
    use crate::framework::{MachineComponent, MachineProverComponent};
    use crate::lookups::AllLookupElements;
    use crate::side_note::SideNote;

    /// Where the runs' data lies: past the protected zone.
    const BASE: u64 = vos_pvm::PVM_ZONE_SIZE as u64 + 0x1000;

    /// A run's memory: the zone, then 64 KiB.
    const MEMORY: usize = vos_pvm::PVM_ZONE_SIZE as usize + 0x10000;

    /// xorshift64*, for the runs' operands.
    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 >> 12;
            self.0 ^= self.0 << 25;
            self.0 ^= self.0 >> 27;
            self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
        }

        /// A value of the shapes the AIR special-cases, or any.
        fn value(&mut self) -> u64 {
            const EDGES: [u64; 14] = [
                0,
                1,
                2,
                31,
                32,
                63,
                64,
                0x7f,
                0x80,
                0xff,
                0x7fff_ffff,
                0x8000_0000,
                0xffff_ffff,
                u64::MAX,
            ];
            match self.next() % 4 {
                0 => EDGES[(self.next() % EDGES.len() as u64) as usize],
                1 => self.next() % 70,
                2 => (self.next() as i64 >> (self.next() % 64)) as u64,
                _ => self.next(),
            }
        }

        /// An address of the run's data, or a value.
        fn address(&mut self) -> u64 {
            if self.next().is_multiple_of(4) {
                self.value()
            } else {
                BASE + self.next() % 0x8000
            }
        }
    }

    /// Instruction `op` of `category` with registers `ra`, `rb` and `rd`,
    /// immediates `x` and `y`, its offset (from its pc, 0) `target`: the
    /// encoding `vos_pvm::args::decode_args` reads.
    fn encode(
        op: Opcode,
        category: InstructionCategory,
        regs: [u8; 3],
        x: u32,
        y: u32,
        target: u32,
    ) -> Vec<u8> {
        use InstructionCategory::*;
        let [ra, rb, rd] = regs;
        let mut bytes = vec![op as u8];
        let word = |bytes: &mut Vec<u8>, value: u32| bytes.extend_from_slice(&value.to_le_bytes());
        match category {
            NoArgs => {}
            OneImm => word(&mut bytes, x),
            OneRegExtImm => {
                bytes.push(ra);
                bytes.extend_from_slice(&(u64::from(x) | u64::from(y) << 32).to_le_bytes());
            }
            TwoImm => {
                bytes.push(4);
                word(&mut bytes, x);
                word(&mut bytes, y);
            }
            OneOffset => word(&mut bytes, target),
            OneRegOneImm => {
                bytes.push(ra);
                word(&mut bytes, x);
            }
            OneRegTwoImm => {
                bytes.push(ra | 4 << 4);
                word(&mut bytes, x);
                word(&mut bytes, y);
            }
            OneRegImmOffset => {
                bytes.push(ra | 4 << 4);
                word(&mut bytes, x);
                word(&mut bytes, target);
            }
            TwoReg => bytes.push(rd | ra << 4),
            TwoRegOneImm => {
                bytes.push(ra | rb << 4);
                word(&mut bytes, x);
            }
            TwoRegOneOffset => {
                bytes.push(ra | rb << 4);
                word(&mut bytes, target);
            }
            TwoRegTwoImm => {
                bytes.push(ra | rb << 4);
                bytes.push(4);
                word(&mut bytes, x);
                word(&mut bytes, y);
            }
            ThreeReg => {
                bytes.push(ra | rb << 4);
                bytes.push(rd);
            }
        }
        bytes
    }

    /// A run of one instruction of `op` on operands from `rng`, then a trap
    /// at its fallthrough and one at its target, traced whole with the
    /// precompiles served.
    fn run(op: Opcode, category: InstructionCategory, rng: &mut Rng) -> SideNote {
        let reg = |rng: &mut Rng| (rng.next() % 13) as u8;
        let regs = [reg(rng), reg(rng), reg(rng)];
        let call = [
            ECALL_BLAKE2B_COMPRESS,
            ECALL_WITNESS_INPUT,
            ECALL_POSEIDON2,
            rng.next() as u32,
        ];
        let x = match (op, rng.next() % 3) {
            (Opcode::Ecalli, _) => call[(rng.next() % 4) as usize],
            (_, 0) => rng.address() as u32,
            _ => rng.value() as u32,
        };
        let y = rng.value() as u32;
        let length = encode(op, category, regs, 0, 0, 0).len() as u32;
        let target = length + 1;
        let mut code = encode(op, category, regs, x, y, target);
        let mut bitmask = vec![1];
        bitmask.resize(code.len(), 0);
        code.extend([Opcode::Trap as u8; 2]);
        bitmask.extend([1, 1]);
        let mut registers = [0u64; PVM_REGISTER_COUNT];
        for (index, register) in registers.iter_mut().enumerate() {
            *register = match index {
                7 | 8 => rng.address(),
                _ if rng.next().is_multiple_of(2) => rng.address(),
                _ => rng.value(),
            };
        }
        if op == Opcode::JumpInd && rng.next().is_multiple_of(2) {
            registers[regs[0] as usize] =
                vos_pvm::PVM_HALT_ADDR.wrapping_sub(i64::from(x as i32) as u64);
        }
        let mut memory = vec![0u8; MEMORY];
        for byte in &mut memory[BASE as usize..] {
            *byte = rng.next() as u8 & 0x3f;
        }
        let pvm = Interpreter::new(code, bitmask, vec![], registers, memory, 100_000);
        let input: Vec<u8> = (0..rng.next() % 64).map(|_| rng.next() as u8).collect();
        let mut tracer = TracingPvm::new(pvm)
            .with_witness_input(input)
            .expect("an input under the cap");
        tracer.run_with_precompiles();
        tracer.into_side_note()
    }

    /// The values of a row's constraints over main columns in Stwo's
    /// storage order, the relation entries' constraints left out: the
    /// interaction is checked by its claimed sum and by the proofs.
    struct RowCheck<'a> {
        columns: Vec<&'a BaseColumn>,
        log_size: u32,
        row: usize,
        next: usize,
        values: Vec<SecureField>,
    }

    impl RowCheck<'_> {
        fn at(&self, row: usize) -> usize {
            use stwo::core::utils::{bit_reverse_index, coset_index_to_circle_domain_index};
            let row = row % (1 << self.log_size);
            bit_reverse_index(
                coset_index_to_circle_domain_index(row, self.log_size),
                self.log_size,
            )
        }
    }

    impl EvalAtRow for RowCheck<'_> {
        type F = SecureField;
        type EF = SecureField;

        fn next_interaction_mask<const N: usize>(
            &mut self,
            _interaction: usize,
            offsets: [isize; N],
        ) -> [SecureField; N] {
            let column = self.columns[self.next];
            self.next += 1;
            offsets.map(|offset| {
                let row = (self.row as isize + offset).rem_euclid(1 << self.log_size) as usize;
                column.as_slice()[self.at(row)].into()
            })
        }

        fn add_constraint<G>(&mut self, constraint: G)
        where
            SecureField: core::ops::Mul<G, Output = SecureField> + From<G>,
        {
            self.values.push(SecureField::from(constraint));
        }

        fn combine_ef(values: [SecureField; 4]) -> SecureField {
            SecureField::from_partial_evals(values)
        }

        fn write_logup_frac(&mut self, _fraction: Fraction<SecureField, SecureField>) {}
    }

    /// The first row and constraint of `chip`'s that `columns`, its main
    /// trace at `log_size`, fails, with the constraint's form.
    fn violation<C: BuiltInComponent>(
        chip: &C,
        log_size: u32,
        columns: Vec<&BaseColumn>,
        names: &[String],
    ) -> Option<String> {
        for row in 0..1 << log_size {
            let mut check = RowCheck {
                columns: columns.clone(),
                log_size,
                row,
                next: 0,
                values: Vec::new(),
            };
            let trace_eval = chip.trace_eval(&mut check);
            chip.add_constraints(&mut check, trace_eval, &C::LookupElements::dummy());
            if let Some(index) = check.values.iter().position(|value| !value.is_zero()) {
                let mut forms = stwo_constraint_framework::expr::ExprEvaluator::new();
                let trace_eval = chip.trace_eval(&mut forms);
                chip.add_constraints(&mut forms, trace_eval, &C::LookupElements::dummy());
                let mut form = forms.constraints[index].simplify_and_format();
                for (at, name) in names.iter().enumerate().rev() {
                    form = form.replace(&format!("trace_1_column_{at}_offset_0"), name);
                }
                return Some(format!("row {row}, constraint {index}: {form}"));
            }
        }
        None
    }

    /// The names of the trace columns `columns` commits, in order.
    fn names(columns: &CpuColumns) -> Vec<String> {
        Column::ALL_VARIANTS
            .iter()
            .filter(|&&column| columns.contains(column))
            .flat_map(|column| (0..column.size()).map(move |limb| format!("{column:?}[{limb}]")))
            .collect()
    }

    /// The per-program CPU of `side_note`'s code over its run, when the full
    /// CPU proves the run: the full trace's cut columns already zero (the
    /// fill row-local, so a program of many instructions is cut as each of
    /// them alone), its trace satisfies its constraints and states the full
    /// CPU's claimed sum. `Ok(false)` for a
    /// run the full CPU refuses (a fault the tracer records).
    fn check(side_note: &mut SideNote) -> Result<bool, String> {
        let columns = CpuColumns::of_code(&side_note.code, &side_note.bitmask);
        let chip = ProgramCpuChip::new(columns);
        let full = CpuChip.generate_component_trace(side_note);
        if violation(
            &CpuChip,
            full.log_size,
            full.original_trace.iter().collect(),
            &names(&CpuColumns::ALL),
        )
        .is_some()
        {
            return Ok(false);
        }
        let mut relations = AllLookupElements::default();
        CpuChip.draw_lookup_elements(&mut relations, (&mut Blake2sM31Channel::default()).into());
        let (_, full_sum) = CpuChip.generate_interaction_trace(&full, side_note, &relations);
        let mut cut = full.clone();
        chip.cut(&mut cut);
        let all = names(&CpuColumns::ALL);
        let set: Vec<&str> = (0..full.original_trace.len())
            .filter(|&at| full.original_trace[at].as_slice() != cut.original_trace[at].as_slice())
            .map(|at| all[at].split('[').next().unwrap_or_default())
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect();
        if !set.is_empty() {
            return Err(format!("the fill sets cut columns {}", set.join(", ")));
        }
        if let Some(violation) = violation(
            &chip,
            cut.log_size,
            chip.committed(&cut).collect(),
            &names(&columns),
        ) {
            return Err(violation);
        }
        let (_, sum) = chip.interaction_trace(&cut, &relations);
        if sum != full_sum {
            return Err("the cut's claimed sum is not the full CPU's".into());
        }
        Ok(true)
    }

    /// Every opcode, run on edge and random operands: a program of it alone
    /// proves its runs under its per-program CPU, with the full CPU's sum,
    /// and each opcode has runs the full CPU proves.
    #[test]
    fn every_opcodes_runs_hold_under_its_programs_cpu() {
        let mut rng = Rng(0x5eed_c0de_8808);
        let mut failures = std::collections::BTreeSet::new();
        let mut served = std::collections::BTreeSet::new();
        for byte in 0..=u8::MAX {
            let Some((op, category)) = decode_opcode_fast(byte) else {
                continue;
            };
            let mut proved = 0;
            for _ in 0..48 {
                let mut side_note = run(op, category, &mut rng);
                if side_note.steps.is_empty() {
                    continue;
                }
                let calls: Vec<u64> = side_note
                    .steps
                    .iter()
                    .filter_map(|step| step.served_ecall())
                    .collect();
                match check(&mut side_note) {
                    Ok(true) => {
                        proved += 1;
                        served.extend(calls);
                    }
                    Ok(false) => {}
                    Err(failure) => {
                        failures.insert(format!("{op:?}: {failure}"));
                    }
                }
            }
            if proved == 0 {
                failures.insert(format!("{op:?}: no run the full CPU proves"));
            }
        }
        assert!(
            failures.is_empty(),
            "{}",
            failures.into_iter().collect::<Vec<_>>().join("\n")
        );
        for call in [ECALL_BLAKE2B_COMPRESS, ECALL_WITNESS_INPUT, ECALL_POSEIDON2] {
            assert!(
                served.contains(&u64::from(call)),
                "no proved run serves {call:#x}"
            );
        }
    }

    /// The cut keeps the columns every row sets, and cuts the full CPU to
    /// fewer columns, constraints and relation entries for a program of
    /// few opcodes.
    #[test]
    fn a_small_programs_cpu_is_narrower() {
        let code = [Opcode::Add64 as u8, 0x21, 3, Opcode::Trap as u8];
        let columns = CpuColumns::of_code(&code, &[1, 0, 0, 1]);
        assert!(columns.covers(&CpuColumns::always()));
        assert!(CpuColumns::ALL.covers(&columns));
        assert!(
            columns.width() < CpuColumns::ALL.width(),
            "{}",
            columns.width()
        );
        let chip = ProgramCpuChip::new(columns);
        let full = ProgramCpuChip::new(CpuColumns::ALL);
        assert!(chip.kept_constraints() < full.kept_constraints());
        assert!(chip.kept_fractions().count_ones() < full.kept_fractions().count_ones());
        let traced = chip.trace_sizes(10);
        assert_eq!(traced[1].len(), columns.width());
        assert_eq!(full.trace_sizes(10)[1].len(), Column::COLUMNS_NUM);
    }

    /// The full CPU's every constraint and relation entry is live: a
    /// `ProgramCpuChip` of every column is `CpuChip`, the masks one each.
    #[test]
    fn the_full_cpu_keeps_everything() {
        let full = ProgramCpuChip::new(CpuColumns::ALL);
        let info = |chip: &dyn MachineComponent| chip.trace_sizes(10).0;
        assert_eq!(info(&full), info(&CpuChip));
        assert_eq!(CpuColumns::ALL.width(), Column::COLUMNS_NUM);
    }
}
