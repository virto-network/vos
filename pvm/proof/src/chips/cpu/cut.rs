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
//!   constraints fail at the prover's own check), never a proof. The
//!   per-program CPU's fill (`SideNote::cpu_rows_local`) sets a column on
//!   its instructions' rows alone, so an honest run's cut columns are
//!   already zero and its cut trace is a full-CPU trace of the run.

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

#[cfg(feature = "prover")]
mod fill;
#[cfg(feature = "prover")]
mod pin;

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
    /// CPU proves the run: its row-local fill a trace of the full CPU, its
    /// cut columns already zero (so a program of many instructions is cut
    /// as each of them alone), the cut trace satisfies the cut constraints
    /// and states the full CPU's claimed sum. `Ok(false)` for a
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
        side_note.cpu_rows_local = true;
        let full = CpuChip.generate_component_trace(side_note);
        side_note.cpu_rows_local = false;
        if let Some(violation) = violation(
            &CpuChip,
            full.log_size,
            full.original_trace.iter().collect(),
            &names(&CpuColumns::ALL),
        ) {
            return Err(format!("the row-local fill: {violation}"));
        }
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

    /// An evaluator at a random point: every mask a uniform M31 value in
    /// each limb, each constraint's value and each relation entry's
    /// numerator recorded in the AIR's order.
    struct AtRandom {
        rng: Rng,
        constraints: Vec<SecureField>,
        numerators: Vec<SecureField>,
    }

    impl EvalAtRow for AtRandom {
        type F = SecureField;
        type EF = SecureField;

        fn next_interaction_mask<const N: usize>(
            &mut self,
            _interaction: usize,
            _offsets: [isize; N],
        ) -> [SecureField; N] {
            core::array::from_fn(|_| {
                SecureField::from_m31_array(core::array::from_fn(|_| {
                    BaseField::from((self.rng.next() % ((1 << 31) - 1)) as u32)
                }))
            })
        }

        fn add_constraint<G>(&mut self, constraint: G)
        where
            SecureField: core::ops::Mul<G, Output = SecureField> + From<G>,
        {
            self.constraints.push(SecureField::from(constraint));
        }

        fn combine_ef(values: [SecureField; 4]) -> SecureField {
            SecureField::from_partial_evals(values)
        }

        fn write_logup_frac(&mut self, fraction: Fraction<SecureField, SecureField>) {
            self.numerators.push(fraction.numerator);
        }
    }

    /// Every constraint and relation entry a [`ProgramCpuChip`] drops is
    /// zero on the full CPU's AIR with the cut columns zero, at random
    /// points: the cut drops nothing live. Over each opcode's program and
    /// each precompile's call, every set of one column cut, and random
    /// sets, and random programs of a few opcodes.
    #[test]
    fn every_dropped_constraint_and_fraction_is_zero_at_random_points() {
        let opcodes: Vec<u8> = (0..=u8::MAX)
            .filter(|&byte| decode_opcode_fast(byte).is_some())
            .collect();
        let program = |opcodes: &[u8]| {
            let mut code: Vec<u8> = opcodes.iter().flat_map(|&op| [op, 0x21, 3]).collect();
            let mut bitmask: Vec<u8> = opcodes.iter().flat_map(|_| [1, 0, 0]).collect();
            code.push(Opcode::Trap as u8);
            bitmask.push(1);
            CpuColumns::of_code(&code, &bitmask)
        };
        let mut sets: Vec<CpuColumns> = opcodes.iter().map(|&op| program(&[op])).collect();
        let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
        for _ in 0..32 {
            let count = 2 + rng.next() % 6;
            let chosen: Vec<u8> = (0..count)
                .map(|_| opcodes[(rng.next() % opcodes.len() as u64) as usize])
                .collect();
            sets.push(program(&chosen));
        }
        for id in [ECALL_BLAKE2B_COMPRESS, ECALL_POSEIDON2, ECALL_WITNESS_INPUT] {
            let mut code = vec![Opcode::Ecalli as u8];
            code.extend(id.to_le_bytes());
            code.push(Opcode::Trap as u8);
            sets.push(CpuColumns::of_code(&code, &[1, 0, 0, 0, 0, 1]));
        }
        for &cut in Column::ALL_VARIANTS {
            let mut columns = CpuColumns::NONE;
            for &column in Column::ALL_VARIANTS {
                if column as usize != cut as usize {
                    columns.insert(column);
                }
            }
            sets.push(columns);
        }
        for _ in 0..64 {
            let mut columns = CpuColumns::NONE;
            let keep = rng.next() % 4;
            for &column in Column::ALL_VARIANTS {
                if rng.next() % 4 <= keep {
                    columns.insert(column);
                }
            }
            sets.push(columns);
        }
        for (set, columns) in sets.iter().enumerate() {
            let chip = ProgramCpuChip::new(*columns);
            for point in 0..2u64 {
                let mut random = AtRandom {
                    rng: Rng(1 + 2 * set as u64 + point),
                    constraints: Vec::new(),
                    numerators: Vec::new(),
                };
                let trace_eval = TraceEval::<PreprocessedColumn, Column, AtRandom>::with_columns(
                    &mut random,
                    |column| columns.contains(column),
                );
                constraints::all(&mut random, &Row::new(&trace_eval), &Lookups::dummy());
                assert!(!random.constraints.is_empty());
                for (index, value) in random.constraints.iter().enumerate() {
                    let kept = chip.constraints[index / 64] >> (index % 64) & 1 == 1;
                    assert!(kept || value.is_zero(), "set {set}: constraint {index}");
                }
                for (index, numerator) in random.numerators.iter().enumerate() {
                    let kept = chip.fractions >> index & 1 == 1;
                    assert!(kept || numerator.is_zero(), "set {set}: fraction {index}");
                }
            }
        }
    }
}
