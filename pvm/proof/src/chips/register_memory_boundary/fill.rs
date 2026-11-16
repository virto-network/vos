//! The chip's trace generation, the prover's half.

use super::*;
use crate::core::step::NUM_REGS;
use crate::framework::BuiltInProverComponent;
use crate::lookups::{AllLookupElements, LogupTraceBuilder};
use crate::side_note::SideNote;
use crate::trace::{
    builder::{FinalizedTrace, TraceBuilder},
    component::ComponentTrace,
};
use stwo::{
    core::{ColumnVec, fields::qm31::SecureField},
    prover::{
        backend::simd::SimdBackend,
        poly::{BitReversedOrder, circle::CircleEvaluation},
    },
};

impl BuiltInProverComponent for RegisterMemoryBoundaryChip {
    const IS_PRODUCER: bool = false;

    fn generate_main_trace_immut_min(
        &self,
        side_note: &SideNote,
        min_log_size: u32,
    ) -> FinalizedTrace {
        let log_size = crate::trace::utils::ceil_log2_at_least_lanes(NUM_REGS).max(min_log_size);
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
        component_trace: &ComponentTrace,
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

        // Tuple: (reg_addr[1], reg_val[8], timestamp[8]=0, is_write=1) — 18 limbs.
        logup.add_to_relation_computed(
            reg_lookup,
            [is_real[0].clone()],
            |[real]| real.into(),
            18,
            |vec_idx| {
                let mut tuple = Vec::with_capacity(18);
                tuple.push(reg_addr[0].at(vec_idx));
                for col in &reg_val {
                    tuple.push(col.at(vec_idx));
                }
                for _ in 0..8 {
                    tuple.push(PackedBaseField::zero());
                }
                tuple.push(PackedBaseField::broadcast(BaseField::from(1u32)));
                tuple
            },
        );

        logup.finalize()
    }
}
