//! MemoryRootBoundaryChip — the single root sink of the in-AIR memory-page
//! Merkle trie (design §3.4).  Mirrors `register_memory_boundary.rs` but on the
//! `MerkleNode` relation: one real row that CONSUMES exactly one tuple
//! `(level=0, index=0, initial_root[32], final_root[32])` with multiplicity −1.
//!
//! Together with `MemoryPageChip` (leaf producers, +1 each) and
//! `MemoryMerkleChip` (merge rows: consume two children −1, produce parent +1),
//! the `MerkleNode` logup balance forces a single connected trie rooted at
//! `(0, 0)`, so this chip's consumed root is the genuine root of the listed
//! page set.  Its claimed sum is closed-form in the public roots and is bound
//! by `boundary_binding::expected_memory_root_sum`, exactly as the register /
//! program boundary chips bind their boundary states.

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
use crate::{framework::BuiltInComponent, lookups::MerkleNodeLookupElements};

pub struct MemoryRootBoundaryChip;

#[derive(Debug, Copy, Clone, AirColumn)]
pub enum Column {
    /// Entering (root-before) Merkle root, 32 bytes.
    #[size = 32]
    HashBefore,
    /// Exit (root-after) Merkle root, 32 bytes.
    #[size = 32]
    HashAfter,
    /// 1 on the single real row, 0 on padding.
    #[size = 1]
    IsReal,
}

#[derive(Debug, Copy, Clone, PreprocessedAirColumn)]
#[preprocessed_prefix = "memrootbnd"]
pub enum PreprocessedColumn {}

impl BuiltInComponent for MemoryRootBoundaryChip {
    type PreprocessedColumn = PreprocessedColumn;
    type MainColumn = Column;
    type LookupElements = MerkleNodeLookupElements;

    fn add_constraints<E: EvalAtRow>(
        &self,
        eval: &mut E,
        trace_eval: TraceEval<PreprocessedColumn, Column, E>,
        lookup_elements: &MerkleNodeLookupElements,
    ) {
        let hash_before = crate::trace::trace_eval!(trace_eval, Column::HashBefore);
        let hash_after = crate::trace::trace_eval!(trace_eval, Column::HashAfter);
        let is_real = crate::trace::trace_eval!(trace_eval, Column::IsReal);

        // Tuple: (level=0, index=0, hash_before[32], hash_after[32]) — 66 limbs.
        let mut tuple: Vec<E::F> = Vec::with_capacity(66);
        tuple.push(E::F::zero()); // level
        tuple.push(E::F::zero()); // index
        for c in &hash_before {
            tuple.push(c.clone());
        }
        for c in &hash_after {
            tuple.push(c.clone());
        }

        // Consume the root (negative multiplicity).
        eval.add_to_relation(RelationEntry::new(
            lookup_elements,
            (-is_real[0].clone()).into(),
            &tuple,
        ));

        eval.finalize_logup();
    }
}

#[cfg(feature = "prover")]
impl BuiltInProverComponent for MemoryRootBoundaryChip {
    const IS_PRODUCER: bool = false;

    fn generate_main_trace_immut(&self, side_note: &SideNote) -> FinalizedTrace {
        let log_size = stwo::prover::backend::simd::m31::LOG_N_LANES;
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
        component_trace: ComponentTrace,
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
