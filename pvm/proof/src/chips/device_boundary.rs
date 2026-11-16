//! A device run's entry, halt and output (`crate::device`): the node's
//! boundary chips (the registers in and out, the program's boundary)
//! replaced by two, so that only the io-hash is public.
//!
//! - **DeviceBoundaryChip** (its claimed sum blinded): a row a register,
//!   preprocessed `(r, the layout's φr)`, so the entry is part of the
//!   program's identity, not a public value. Its rows PRODUCE each
//!   register's `ts = 0` write and its closing read at the halt's timestamp
//!   (the registers' ledger binds the read to the run's last value), and on
//!   its first row the entry `(ts 1, pc 0)` and CONSUME the halt
//!   `(final ts, HALT_PC)` of the program's execution, so the run is the
//!   program's from its entry to its halt and one segment; on φ9..12's rows
//!   it CONSUMES their final values in the `IoHash` relation. The final
//!   timestamp is one column, equal on every register's row.
//! - **DeviceIoChip** (its claimed sum public): four rows, preprocessed
//!   `r = 9..12`, PRODUCING `(r, value)` in the `IoHash` relation. The
//!   verifier recomputes its claimed sum from the public io-hash
//!   (`masked::device_bound_sums`), which pins the four values to it.

use crate::prelude::*;
use num_traits::{One, Zero};
use stwo::core::fields::m31::BaseField;
use stwo_constraint_framework::{EvalAtRow, RelationEntry};

use crate::air_column::{AirColumn, PreprocessedAirColumn};
use crate::core::step::{NUM_REGS, WORD_SIZE};
use crate::device::{ENTRY_PC, ENTRY_TIMESTAMP, HALT_PC};
use crate::framework::{BuiltInComponent, Logup};
use crate::lookups::{
    IoHashLookupElements, ProgramExecutionLookupElements, RegisterMemoryLookupElements,
};
use crate::trace::eval::TraceEval;

/// The io-hash's registers: φ9..12.
pub const IO_REGISTERS: core::ops::Range<usize> = 9..13;

#[derive(Clone, Copy)]
pub struct DeviceBoundaryChip;

#[derive(Debug, Copy, Clone, AirColumn)]
pub enum Column {
    /// The register's value at the halt, 8 LE limbs.
    #[size = 8]
    FinalValue,
    /// The halt's timestamp, 8 LE limbs, equal on every register's row
    /// (`#[mask_next_row]`).
    #[size = 8]
    #[mask_next_row]
    FinalTs,
}

#[derive(Debug, Copy, Clone, PreprocessedAirColumn)]
#[preprocessed_prefix = "devbound"]
pub enum PreprocessedColumn {
    /// 1 on the registers' rows, 0..13.
    #[size = 1]
    IsRegister,
    /// The row's register.
    #[size = 1]
    Register,
    /// Its value at the entry, the layout's, 8 LE limbs.
    #[size = 8]
    InitialValue,
    /// 1 on φ9..12's rows.
    #[size = 1]
    IsIo,
    /// 1 on row 0.
    #[size = 1]
    IsFirst,
    /// 1 on rows 0..12, whose successor holds the same final timestamp.
    #[size = 1]
    IsChained,
}

/// A timestamp's or a pc's LE limbs as constants.
fn limbs<F: From<BaseField>, const N: usize>(value: u64) -> [F; N] {
    core::array::from_fn(|i| F::from(BaseField::from(((value >> (8 * i)) & 0xff) as u32)))
}

impl BuiltInComponent for DeviceBoundaryChip {
    const LOGUP: Logup = Logup::Pairs;
    type PreprocessedColumn = PreprocessedColumn;
    type MainColumn = Column;
    type LookupElements = (
        RegisterMemoryLookupElements,
        ProgramExecutionLookupElements,
        IoHashLookupElements,
    );

    fn add_constraints<E: EvalAtRow>(
        &self,
        eval: &mut E,
        trace_eval: TraceEval<PreprocessedColumn, Column, E>,
        (registers, execution, io): &Self::LookupElements,
    ) {
        let final_value = crate::trace::trace_eval!(trace_eval, Column::FinalValue);
        let final_ts = crate::trace::trace_eval!(trace_eval, Column::FinalTs);
        let final_ts_next = crate::trace::trace_eval_next_row!(trace_eval, Column::FinalTs);
        let is_register =
            crate::trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::IsRegister);
        let register =
            crate::trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::Register);
        let initial =
            crate::trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::InitialValue);
        let is_io = crate::trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::IsIo);
        let is_first =
            crate::trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::IsFirst);
        let is_chained =
            crate::trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::IsChained);

        for (now, next) in final_ts.iter().zip(&final_ts_next) {
            eval.add_constraint(is_chained[0].clone() * (next.clone() - now.clone()));
        }

        // The register's entry write and its closing read at the halt.
        let mut write: Vec<E::F> = Vec::with_capacity(18);
        write.push(register[0].clone());
        write.extend(initial.iter().cloned());
        write.extend((0..WORD_SIZE).map(|_| E::F::zero()));
        write.push(E::F::one());
        eval.add_to_relation(RelationEntry::new(
            registers,
            is_register[0].clone().into(),
            &write,
        ));
        let mut close: Vec<E::F> = Vec::with_capacity(18);
        close.push(register[0].clone());
        close.extend(final_value.iter().cloned());
        close.extend(final_ts.iter().cloned());
        close.push(E::F::zero());
        eval.add_to_relation(RelationEntry::new(
            registers,
            is_register[0].clone().into(),
            &close,
        ));

        // The program's execution from its entry to its halt.
        let mut entry: Vec<E::F> = limbs::<E::F, WORD_SIZE>(ENTRY_TIMESTAMP).to_vec();
        entry.extend(limbs::<E::F, 4>(u64::from(ENTRY_PC)));
        eval.add_to_relation(RelationEntry::new(
            execution,
            is_first[0].clone().into(),
            &entry,
        ));
        let mut halt: Vec<E::F> = final_ts.to_vec();
        halt.extend(limbs::<E::F, 4>(u64::from(HALT_PC)));
        eval.add_to_relation(RelationEntry::new(
            execution,
            (-is_first[0].clone()).into(),
            &halt,
        ));

        // φ9..12 at the halt, the io-hash DeviceIoChip states.
        let mut output: Vec<E::F> = Vec::with_capacity(1 + WORD_SIZE);
        output.push(register[0].clone());
        output.extend(final_value.iter().cloned());
        eval.add_to_relation(RelationEntry::new(io, (-is_io[0].clone()).into(), &output));
    }
}

#[derive(Clone, Copy)]
pub struct DeviceIoChip;

#[derive(Debug, Copy, Clone, AirColumn)]
pub enum IoColumn {
    /// The register's value, 8 LE limbs.
    #[size = 8]
    Value,
}

#[derive(Debug, Copy, Clone, PreprocessedAirColumn)]
#[preprocessed_prefix = "devio"]
pub enum IoPreprocessedColumn {
    /// 1 on rows 0..4.
    #[size = 1]
    IsIo,
    /// The row's register, `9 + row`.
    #[size = 1]
    Register,
}

impl BuiltInComponent for DeviceIoChip {
    const LOGUP: Logup = Logup::Single;
    type PreprocessedColumn = IoPreprocessedColumn;
    type MainColumn = IoColumn;
    type LookupElements = IoHashLookupElements;

    fn add_constraints<E: EvalAtRow>(
        &self,
        eval: &mut E,
        trace_eval: TraceEval<IoPreprocessedColumn, IoColumn, E>,
        io: &IoHashLookupElements,
    ) {
        let value = crate::trace::trace_eval!(trace_eval, IoColumn::Value);
        let is_io = crate::trace::preprocessed_trace_eval!(trace_eval, IoPreprocessedColumn::IsIo);
        let register =
            crate::trace::preprocessed_trace_eval!(trace_eval, IoPreprocessedColumn::Register);
        let mut output: Vec<E::F> = Vec::with_capacity(1 + WORD_SIZE);
        output.push(register[0].clone());
        output.extend(value.iter().cloned());
        eval.add_to_relation(RelationEntry::new(io, is_io[0].clone().into(), &output));
    }
}

/// The claimed sum DeviceIoChip's rows produce for io-hash `io` (φ9..12 as
/// 32 LE bytes) under `io_relation`: what the verifier recomputes from the
/// public io-hash.
pub fn io_claimed_sum(
    io_relation: &IoHashLookupElements,
    io: &[u8; 32],
) -> stwo::core::fields::qm31::SecureField {
    use stwo::core::fields::FieldExpOps;
    use stwo_constraint_framework::Relation;
    io.chunks_exact(WORD_SIZE)
        .zip(IO_REGISTERS)
        .map(|(bytes, register)| {
            let mut tuple: Vec<BaseField> = Vec::with_capacity(1 + WORD_SIZE);
            tuple.push(BaseField::from(register as u32));
            tuple.extend(bytes.iter().map(|&byte| BaseField::from(u32::from(byte))));
            let denominator: stwo::core::fields::qm31::SecureField = io_relation.combine(&tuple);
            denominator.inverse()
        })
        .sum()
}

#[cfg(feature = "prover")]
mod fill;
