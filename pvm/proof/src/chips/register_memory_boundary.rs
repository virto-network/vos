use crate::prelude::*;
use num_traits::{One, Zero};
use stwo::core::fields::m31::BaseField;
use stwo_constraint_framework::{EvalAtRow, RelationEntry};

use crate::air_column::{AirColumn, PreprocessedAirColumn};
use crate::trace::eval::TraceEval;

use crate::{
    framework::{BuiltInComponent, Logup},
    lookups::RegisterMemoryLookupElements,
};

/// RegisterMemoryBoundaryChip: produces 13 register-memory logup entries for
/// the initial register state at ts=0.  Mirrors MemoryBoundaryChip but for
/// the PVM register file: (reg_addr\[1\], reg_val\[8\], reg_ts\[8\]=0) with
/// positive multiplicity.  The matching consumers live in RegisterMemoryChip
/// (the ledger).
#[derive(Clone, Copy)]
pub struct RegisterMemoryBoundaryChip;

#[derive(Debug, Copy, Clone, AirColumn)]
pub enum Column {
    /// Register index 0..NUM_REGS-1.
    #[size = 1]
    RegAddr,
    /// Initial u64 value as 8 LE bytes.
    #[size = 8]
    RegVal,
    /// 1 for real entries (0..NUM_REGS), 0 for padding rows.
    #[size = 1]
    IsReal,
}

#[derive(Debug, Copy, Clone, PreprocessedAirColumn)]
#[preprocessed_prefix = "regbnd"]
pub enum PreprocessedColumn {}

impl BuiltInComponent for RegisterMemoryBoundaryChip {
    const LOGUP: Logup = Logup::Single;
    type PreprocessedColumn = PreprocessedColumn;
    type MainColumn = Column;
    type LookupElements = RegisterMemoryLookupElements;

    fn add_constraints<E: EvalAtRow>(
        &self,
        eval: &mut E,
        trace_eval: TraceEval<PreprocessedColumn, Column, E>,
        lookup_elements: &RegisterMemoryLookupElements,
    ) {
        let reg_addr = crate::trace::trace_eval!(trace_eval, Column::RegAddr);
        let reg_val = crate::trace::trace_eval!(trace_eval, Column::RegVal);
        let is_real = crate::trace::trace_eval!(trace_eval, Column::IsReal);

        // IsReal is boolean: a row emits its tuple once or not at all.
        eval.add_constraint(is_real[0].clone() * (is_real[0].clone() - E::F::one()));

        let mut tuple: Vec<E::F> = Vec::with_capacity(18);
        tuple.push(reg_addr[0].clone());
        for col in &reg_val {
            tuple.push(col.clone());
        }
        for _ in 0..8 {
            tuple.push(E::F::zero());
        }
        // is_write = 1 (the boundary seeds are the registers' initial writes).
        tuple.push(E::F::from(BaseField::from(1u32)));

        eval.add_to_relation(RelationEntry::new(
            lookup_elements,
            is_real[0].clone().into(),
            &tuple,
        ));
    }
}

#[cfg(feature = "prover")]
mod fill;
