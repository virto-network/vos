use num_traits::Zero;
use stwo::{
    core::{
        fields::{m31::BaseField, qm31::SecureField},
        ColumnVec,
    },
    prover::{
        backend::simd::{m31::LOG_N_LANES, SimdBackend},
        poly::{circle::CircleEvaluation, BitReversedOrder},
    },
};
use stwo_constraint_framework::{EvalAtRow, RelationEntry};

use zkpvm_air_column::{AirColumn, PreprocessedAirColumn};
use zkpvm_core::step::NUM_REGS;
use zkpvm_trace::{
    builder::{FinalizedTrace, TraceBuilder},
    component::ComponentTrace,
    eval::TraceEval,
};

use crate::{
    framework::BuiltInComponent,
    lookups::{AllLookupElements, LogupTraceBuilder, RegisterMemoryLookupElements},
    side_note::SideNote,
};

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

    fn generate_preprocessed_trace(&self, _log_size: u32, _side_note: &SideNote) -> FinalizedTrace {
        FinalizedTrace::empty()
    }

    fn generate_main_trace(&self, side_note: &mut SideNote) -> FinalizedTrace {
        let log_size = ((NUM_REGS as f64).log2().ceil() as u32).max(LOG_N_LANES);
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
        let reg_addr = zkpvm_trace::original_base_column!(component_trace, Column::RegAddr);
        let reg_val = zkpvm_trace::original_base_column!(component_trace, Column::RegVal);
        let is_real = zkpvm_trace::original_base_column!(component_trace, Column::IsReal);

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
                for col in &reg_val { tuple.push(col.at(vec_idx)); }
                for _ in 0..8 { tuple.push(PackedBaseField::zero()); }
                tuple
            },
        );

        logup.finalize()
    }

    fn add_constraints<E: EvalAtRow>(
        &self,
        eval: &mut E,
        trace_eval: TraceEval<PreprocessedColumn, Column, E>,
        lookup_elements: &RegisterMemoryLookupElements,
    ) {
        let reg_addr = zkpvm_trace::trace_eval!(trace_eval, Column::RegAddr);
        let reg_val = zkpvm_trace::trace_eval!(trace_eval, Column::RegVal);
        let is_real = zkpvm_trace::trace_eval!(trace_eval, Column::IsReal);

        let mut tuple: Vec<E::F> = Vec::with_capacity(17);
        tuple.push(reg_addr[0].clone());
        for col in &reg_val { tuple.push(col.clone()); }
        for _ in 0..8 { tuple.push(E::F::zero()); }

        eval.add_to_relation(RelationEntry::new(
            lookup_elements,
            is_real[0].clone().into(),
            &tuple,
        ));

        eval.finalize_logup();
    }
}
