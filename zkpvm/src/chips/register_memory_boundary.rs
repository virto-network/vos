#[allow(unused_imports)]
use alloc::{boxed::Box, vec, vec::Vec};
use num_traits::Zero;
use stwo::core::fields::m31::BaseField;
#[cfg(feature = "prover")]
use stwo::{
    core::{ColumnVec, fields::qm31::SecureField},
    prover::{
        backend::simd::SimdBackend,
        poly::{BitReversedOrder, circle::CircleEvaluation},
    },
};
use stwo_constraint_framework::{EvalAtRow, RelationEntry};

use crate::air_column::{AirColumn, PreprocessedAirColumn};
use crate::core::step::NUM_REGS;
use crate::trace::eval::TraceEval;
#[cfg(feature = "prover")]
use crate::trace::{
    builder::{FinalizedTrace, TraceBuilder},
    component::ComponentTrace,
};

#[cfg(feature = "prover")]
use crate::framework::BuiltInProverComponent;
#[cfg(feature = "prover")]
use crate::lookups::{AllLookupElements, LogupTraceBuilder};
#[cfg(feature = "prover")]
use crate::side_note::SideNote;
use crate::{framework::BuiltInComponent, lookups::RegisterMemoryLookupElements};

/// RegisterMemoryBoundaryChip: produces 13 register-memory logup entries for
/// the initial register state at ts=0.  Mirrors MemoryBoundaryChip but for
/// the PVM register file: (reg_addr[1], reg_val[8], reg_ts[8]=0) with
/// positive multiplicity.  The matching consumers live in RegisterMemoryChip
/// (the ledger).
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

        let mut tuple: Vec<E::F> = Vec::with_capacity(17);
        tuple.push(reg_addr[0].clone());
        for col in &reg_val {
            tuple.push(col.clone());
        }
        for _ in 0..8 {
            tuple.push(E::F::zero());
        }

        eval.add_to_relation(RelationEntry::new(
            lookup_elements,
            is_real[0].clone().into(),
            &tuple,
        ));

        eval.finalize_logup();
    }
}

#[cfg(feature = "prover")]
impl BuiltInProverComponent for RegisterMemoryBoundaryChip {
    const IS_PRODUCER: bool = false;

    fn generate_main_trace_immut(&self, side_note: &SideNote) -> FinalizedTrace {
        let log_size = crate::trace::utils::ceil_log2_at_least_lanes(NUM_REGS);
        let mut trace = TraceBuilder::<Column>::new(log_size);

        for (row, &val) in side_note.initial_regs.iter().enumerate() {
            trace.fill_columns(row, row as u8, Column::RegAddr);
            trace.fill_columns(row, val, Column::RegVal);
            trace.fill_columns(row, true, Column::IsReal);
        }
        // Padding rows (row >= NUM_REGS) keep IsReal = 0 by default.

        trace.finalize_bit_reversed()
    }

    fn generate_interaction_trace(
        &self,
        component_trace: ComponentTrace,
        _side_note: &SideNote,
        lookup_elements: &AllLookupElements,
    ) -> (
        ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
        SecureField,
    ) {
        let log_size = component_trace.log_size();
        let mut logup = LogupTraceBuilder::new(log_size);

        let reg_lookup: &RegisterMemoryLookupElements = lookup_elements.as_ref();
        let reg_addr = crate::trace::original_base_column!(component_trace, Column::RegAddr);
        let reg_val = crate::trace::original_base_column!(component_trace, Column::RegVal);
        let is_real = crate::trace::original_base_column!(component_trace, Column::IsReal);

        use stwo::prover::backend::simd::m31::PackedBaseField;

        // Tuple: (reg_addr[1], reg_val[8], timestamp[8]=0) — 17 limbs.
        logup.add_to_relation_computed(
            reg_lookup,
            [is_real[0].clone()],
            |[real]| real.into(),
            17,
            |vec_idx| {
                let mut tuple = Vec::with_capacity(17);
                tuple.push(reg_addr[0].at(vec_idx));
                for col in &reg_val {
                    tuple.push(col.at(vec_idx));
                }
                for _ in 0..8 {
                    tuple.push(PackedBaseField::zero());
                }
                tuple
            },
        );

        logup.finalize()
    }
}
