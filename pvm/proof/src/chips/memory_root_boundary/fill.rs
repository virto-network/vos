//! The chip's trace generation, the prover's half.

use super::*;
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

impl BuiltInProverComponent for MemoryRootBoundaryChip {
    const IS_PRODUCER: bool = false;

    fn generate_main_trace_immut_min(
        &self,
        side_note: &SideNote,
        min_log_size: u32,
    ) -> FinalizedTrace {
        let log_size = stwo::prover::backend::simd::m31::LOG_N_LANES.max(min_log_size);
        let mut trace = TraceBuilder::<Column>::new(log_size);

        let (root_before, root_after) = match &side_note.memory_pages {
            Some(p) => (p.multiproof.root_before, p.multiproof.root_after),
            None => ([0u8; 32], [0u8; 32]),
        };
        trace.fill_columns_bytes(0, &root_before, Column::HashBefore);
        trace.fill_columns_bytes(0, &root_after, Column::HashAfter);
        trace.fill_columns(0, true, Column::IsReal);
        // Remaining rows are padding (IsReal = 0 by default).

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

        let merkle_lookup: &MerkleNodeLookupElements = lookup_elements.as_ref();
        let hash_before = crate::trace::original_base_column!(component_trace, Column::HashBefore);
        let hash_after = crate::trace::original_base_column!(component_trace, Column::HashAfter);
        let is_real = crate::trace::original_base_column!(component_trace, Column::IsReal);

        use stwo::prover::backend::simd::m31::PackedBaseField;

        logup.add_to_relation_computed(
            merkle_lookup,
            [is_real[0].clone()],
            |[real]| (-real).into(),
            66,
            move |vec_idx| {
                let mut tuple = Vec::with_capacity(66);
                tuple.push(PackedBaseField::zero()); // level
                tuple.push(PackedBaseField::zero()); // index
                for c in &hash_before {
                    tuple.push(c.at(vec_idx));
                }
                for c in &hash_after {
                    tuple.push(c.at(vec_idx));
                }
                tuple
            },
        );

        logup.finalize()
    }
}
