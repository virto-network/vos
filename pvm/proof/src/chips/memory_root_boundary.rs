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

use crate::prelude::*;
use num_traits::{One, Zero};
use stwo_constraint_framework::{EvalAtRow, RelationEntry};

use crate::air_column::{AirColumn, PreprocessedAirColumn};
use crate::trace::eval::TraceEval;

use crate::{
    framework::{BuiltInComponent, Logup},
    lookups::MerkleNodeLookupElements,
};

#[derive(Clone, Copy)]
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
    const LOGUP: Logup = Logup::Single;
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

        // A row consumes the root once or not at all.
        eval.add_constraint(is_real[0].clone() * (is_real[0].clone() - E::F::one()));

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
    }
}

#[cfg(feature = "prover")]
mod fill;
