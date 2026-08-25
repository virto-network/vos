//! MemoryMerkleChip — the internal merge rows of the in-AIR memory-page Merkle
//! boundary multiproof (design §1 / §3.3).  Each row is one `MergeNode`: it
//! recomputes a parent node hash from its two children over BOTH the entering
//! ("before") and exit ("after") passes, driving one blake2b node compression
//! per pass, and balances the `MerkleNode` relation so the trie schedule is
//! enforced.
//!
//! Per row:
//! - CONSUMES two `Blake2bCompression` tuples (before / after node hashes),
//!   message = `left ‖ right ‖ 0^64`, `h_in = H_AFTER_NODE_TAG`, `t = 192`,
//!   `f = 1`.  `Blake2bBoundaryChip` produced them; balance pins
//!   `HOut{Before,After}` to the real node compressions.
//! - PRODUCES the parent `MerkleNode` `(level, index, hb[0..32], ha[0..32])`.
//! - CONSUMES each COMPUTED child `(level+1, 2·index+bit, child_before,
//!   child_after)`; a WITNESS child is NOT consumed but its before/after
//!   hashes are forced equal (`IsWitness·(before − after) = 0`), the
//!   untouched-subtree-reuse rule (design §1 — without it a prover could forge
//!   `final_root` over an untouched subtree).
//! - `level` is range-checked to `[0, 19]`; internal `index` is deliberately
//!   NOT range-checked (a wrapped/huge index is unreachable from the pinned
//!   root `(0, 0)` and is orphaned by logup balance — design §1).

#[allow(unused_imports)]
use alloc::{boxed::Box, vec, vec::Vec};
use num_traits::{One, Zero};
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
use crate::lookups::{Blake2bCompressionLookupElements, MerkleNodeLookupElements};
use crate::trace::eval::TraceEval;
#[cfg(feature = "prover")]
use crate::trace::{
    builder::{FinalizedTrace, TraceBuilder},
    component::ComponentTrace,
};

use crate::framework::BuiltInComponent;
#[cfg(feature = "prover")]
use crate::framework::BuiltInProverComponent;
#[cfg(feature = "prover")]
use crate::lookups::{AllLookupElements, LogupTraceBuilder};
#[cfg(feature = "prover")]
use crate::side_note::SideNote;

pub struct MemoryMerkleChip;

#[derive(Debug, Copy, Clone, AirColumn)]
pub enum Column {
    /// Left child hash, entering pass (32 bytes).
    #[size = 32]
    LeftBefore,
    /// Right child hash, entering pass.
    #[size = 32]
    RightBefore,
    /// Left child hash, exit pass.
    #[size = 32]
    LeftAfter,
    /// Right child hash, exit pass.
    #[size = 32]
    RightAfter,
    /// Full 64-byte node compression output, entering pass (first 32 bytes =
    /// the produced parent hash).
    #[size = 64]
    HOutBefore,
    /// Full 64-byte node compression output, exit pass.
    #[size = 64]
    HOutAfter,
    /// Produced node level (single M31 limb), range-checked to `[0, 19]`.
    #[size = 1]
    Level,
    /// Produced node index at `level` (single M31 limb); children sit at
    /// `2·index` / `2·index + 1`.  NOT range-checked (design §1).
    #[size = 1]
    Index,
    /// 5-bit decomposition of `Level` for the `[0, 19]` range check.
    #[size = 5]
    LevelBits,
    /// 1 iff the left child is a witness sibling (untouched subtree).
    #[size = 1]
    IsWitnessLeft,
    /// 1 iff the right child is a witness sibling.
    #[size = 1]
    IsWitnessRight,
    /// 1 on real merge rows, 0 on padding.
    #[size = 1]
    IsReal,
    /// BOUND helper `(1 − IsWitnessLeft) · IsReal` — the left-child consume
    /// multiplicity (degree 1 so the logup stays degree 2).
    #[size = 1]
    ComputedLeftH,
    /// BOUND helper `(1 − IsWitnessRight) · IsReal`.
    #[size = 1]
    ComputedRightH,
}

#[derive(Debug, Copy, Clone, PreprocessedAirColumn)]
#[preprocessed_prefix = "memmerkle"]
pub enum PreprocessedColumn {}

impl BuiltInComponent for MemoryMerkleChip {
    const LOG_CONSTRAINT_DEGREE_BOUND: u32 = 1;

    type PreprocessedColumn = PreprocessedColumn;
    type MainColumn = Column;
    type LookupElements = (MerkleNodeLookupElements, Blake2bCompressionLookupElements);

    fn add_constraints<E: EvalAtRow>(
        &self,
        eval: &mut E,
        trace_eval: TraceEval<PreprocessedColumn, Column, E>,
        lookup_elements: &(MerkleNodeLookupElements, Blake2bCompressionLookupElements),
    ) {
        let (merkle_lookup, compression_lookup) = lookup_elements;

        let left_b = crate::trace::trace_eval!(trace_eval, Column::LeftBefore);
        let right_b = crate::trace::trace_eval!(trace_eval, Column::RightBefore);
        let left_a = crate::trace::trace_eval!(trace_eval, Column::LeftAfter);
        let right_a = crate::trace::trace_eval!(trace_eval, Column::RightAfter);
        let hout_b = crate::trace::trace_eval!(trace_eval, Column::HOutBefore);
        let hout_a = crate::trace::trace_eval!(trace_eval, Column::HOutAfter);
        let level = crate::trace::trace_eval!(trace_eval, Column::Level);
        let index = crate::trace::trace_eval!(trace_eval, Column::Index);
        let level_bits = crate::trace::trace_eval!(trace_eval, Column::LevelBits);
        let is_wl = crate::trace::trace_eval!(trace_eval, Column::IsWitnessLeft);
        let is_wr = crate::trace::trace_eval!(trace_eval, Column::IsWitnessRight);
        let is_real = crate::trace::trace_eval!(trace_eval, Column::IsReal);
        let comp_l = crate::trace::trace_eval!(trace_eval, Column::ComputedLeftH);
        let comp_r = crate::trace::trace_eval!(trace_eval, Column::ComputedRightH);

        let one = E::F::one();
        let two = E::F::from(BaseField::from(2u32));

        // ── Booleans ──────────────────────────────────────────────
        eval.add_constraint(is_real[0].clone() * (is_real[0].clone() - one.clone()));
        eval.add_constraint(is_wl[0].clone() * (is_wl[0].clone() - one.clone()));
        eval.add_constraint(is_wr[0].clone() * (is_wr[0].clone() - one.clone()));
        for b in &level_bits {
            eval.add_constraint(b.clone() * (b.clone() - one.clone()));
        }

        // ── Level range [0, 19] ───────────────────────────────────
        // 5-bit recomposition + two forbidden products: bit4·bit2 and bit4·bit3
        // are 0 ⇒ no value in [20, 31] passes (16..19 keep bit4 set with
        // bit2=bit3=0; 20..31 set bit4 with bit2 or bit3).
        let mut rec = E::F::zero();
        let mut pow = E::F::one();
        for b in &level_bits {
            rec += b.clone() * pow.clone();
            pow *= two.clone();
        }
        eval.add_constraint(rec - level[0].clone());
        eval.add_constraint(level_bits[4].clone() * level_bits[2].clone());
        eval.add_constraint(level_bits[4].clone() * level_bits[3].clone());

        // ── Witness shared-value (untouched-subtree reuse rule) ────
        for i in 0..32 {
            eval.add_constraint(is_wl[0].clone() * (left_b[i].clone() - left_a[i].clone()));
            eval.add_constraint(is_wr[0].clone() * (right_b[i].clone() - right_a[i].clone()));
        }

        // ── Computed-child multiplicity helpers ───────────────────
        eval.add_constraint(
            comp_l[0].clone() - (one.clone() - is_wl[0].clone()) * is_real[0].clone(),
        );
        eval.add_constraint(
            comp_r[0].clone() - (one.clone() - is_wr[0].clone()) * is_real[0].clone(),
        );

        // ── Emissions (fixed order; finalize_logup_in_pairs) ───────
        // The node compression `h_in` is the precomputed chaining state after
        // the node tag block, a circuit constant (same software core the host
        // `page_merkle` uses → identical by construction).
        let node_tag =
            crate::page_merkle::state_to_bytes(&crate::page_merkle::h_after_node_tag_words());
        let cst = |b: u8| E::F::from(BaseField::from(b as u32));
        let build_node_tuple = |l: &[E::F], r: &[E::F], hout: &[E::F]| -> Vec<E::F> {
            let mut t: Vec<E::F> = Vec::with_capacity(265);
            for &b in &node_tag {
                t.push(cst(b)); // h_in[64]
            }
            for v in l.iter().take(32) {
                t.push(v.clone()); // m[0..32] = left
            }
            for v in r.iter().take(32) {
                t.push(v.clone()); // m[32..64] = right
            }
            for _ in 0..64 {
                t.push(E::F::zero()); // m[64..128] pad
            }
            t.push(cst(192)); // t[0]
            for _ in 0..7 {
                t.push(E::F::zero()); // t[1..8]
            }
            t.push(one.clone()); // f
            for v in hout.iter().take(64) {
                t.push(v.clone()); // h_out[64]
            }
            t
        };

        // 1 + 2: blake2b node compressions (before / after) — CONSUME.
        let tuple_before = build_node_tuple(&left_b, &right_b, &hout_b);
        eval.add_to_relation(RelationEntry::new(
            compression_lookup,
            (-is_real[0].clone()).into(),
            &tuple_before,
        ));
        let tuple_after = build_node_tuple(&left_a, &right_a, &hout_a);
        eval.add_to_relation(RelationEntry::new(
            compression_lookup,
            (-is_real[0].clone()).into(),
            &tuple_after,
        ));

        // 3: parent node — PRODUCE.
        let mut parent: Vec<E::F> = Vec::with_capacity(66);
        parent.push(level[0].clone());
        parent.push(index[0].clone());
        for v in hout_b.iter().take(32) {
            parent.push(v.clone());
        }
        for v in hout_a.iter().take(32) {
            parent.push(v.clone());
        }
        eval.add_to_relation(RelationEntry::new(
            merkle_lookup,
            is_real[0].clone().into(),
            &parent,
        ));

        // 4 + 5: children — CONSUME (computed children only; witness mult = 0).
        let child_level = level[0].clone() + one.clone();
        let two_index = index[0].clone() * two.clone();
        let mut child_left: Vec<E::F> = Vec::with_capacity(66);
        child_left.push(child_level.clone());
        child_left.push(two_index.clone());
        for v in left_b.iter() {
            child_left.push(v.clone());
        }
        for v in left_a.iter() {
            child_left.push(v.clone());
        }
        eval.add_to_relation(RelationEntry::new(
            merkle_lookup,
            (-comp_l[0].clone()).into(),
            &child_left,
        ));

        let mut child_right: Vec<E::F> = Vec::with_capacity(66);
        child_right.push(child_level);
        child_right.push(two_index + one);
        for v in right_b.iter() {
            child_right.push(v.clone());
        }
        for v in right_a.iter() {
            child_right.push(v.clone());
        }
        eval.add_to_relation(RelationEntry::new(
            merkle_lookup,
            (-comp_r[0].clone()).into(),
            &child_right,
        ));

        eval.finalize_logup_in_pairs();
    }
}

#[cfg(feature = "prover")]
impl BuiltInProverComponent for MemoryMerkleChip {
    const IS_PRODUCER: bool = false;

    fn generate_main_trace_immut(&self, side_note: &SideNote) -> FinalizedTrace {
        use crate::page_merkle::{Child, node_full_output};

        let empty = Vec::new();
        let merges = match &side_note.memory_pages {
            Some(p) => &p.multiproof.merges,
            None => &empty,
        };
        let log_size = crate::trace::utils::ceil_log2_at_least_lanes(merges.len().max(1));
        let mut trace = TraceBuilder::<Column>::new(log_size);

        for (row, node) in merges.iter().enumerate() {
            trace.fill_columns_bytes(row, &node.child_before[0], Column::LeftBefore);
            trace.fill_columns_bytes(row, &node.child_before[1], Column::RightBefore);
            trace.fill_columns_bytes(row, &node.child_after[0], Column::LeftAfter);
            trace.fill_columns_bytes(row, &node.child_after[1], Column::RightAfter);

            let hout_b = node_full_output(&node.child_before[0], &node.child_before[1]);
            let hout_a = node_full_output(&node.child_after[0], &node.child_after[1]);
            trace.fill_columns_bytes(row, &hout_b, Column::HOutBefore);
            trace.fill_columns_bytes(row, &hout_a, Column::HOutAfter);

            trace.fill_columns_base_field(row, &[BaseField::from(node.level)], Column::Level);
            trace.fill_columns_base_field(row, &[BaseField::from(node.index)], Column::Index);
            let bits: [BaseField; 5] =
                core::array::from_fn(|b| BaseField::from((node.level >> b) & 1));
            trace.fill_columns_base_field(row, &bits, Column::LevelBits);

            let wl = matches!(node.left, Child::Witness(_));
            let wr = matches!(node.right, Child::Witness(_));
            trace.fill_columns(row, wl, Column::IsWitnessLeft);
            trace.fill_columns(row, wr, Column::IsWitnessRight);
            trace.fill_columns(row, true, Column::IsReal);
            trace.fill_columns(row, !wl, Column::ComputedLeftH);
            trace.fill_columns(row, !wr, Column::ComputedRightH);
        }
        // Padding rows keep all columns at 0 (IsReal = 0, helpers = 0).

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
        use stwo::prover::backend::simd::m31::PackedBaseField;

        let log_size = component_trace.log_size();
        let mut logup = LogupTraceBuilder::new(log_size);

        let merkle: &MerkleNodeLookupElements = lookup_elements.as_ref();
        let compression: &Blake2bCompressionLookupElements = lookup_elements.as_ref();

        let left_b = crate::trace::original_base_column!(component_trace, Column::LeftBefore);
        let right_b = crate::trace::original_base_column!(component_trace, Column::RightBefore);
        let left_a = crate::trace::original_base_column!(component_trace, Column::LeftAfter);
        let right_a = crate::trace::original_base_column!(component_trace, Column::RightAfter);
        let hout_b = crate::trace::original_base_column!(component_trace, Column::HOutBefore);
        let hout_a = crate::trace::original_base_column!(component_trace, Column::HOutAfter);
        let level = crate::trace::original_base_column!(component_trace, Column::Level);
        let index = crate::trace::original_base_column!(component_trace, Column::Index);
        let is_real = crate::trace::original_base_column!(component_trace, Column::IsReal);
        let comp_l = crate::trace::original_base_column!(component_trace, Column::ComputedLeftH);
        let comp_r = crate::trace::original_base_column!(component_trace, Column::ComputedRightH);

        let node_tag =
            crate::page_merkle::state_to_bytes(&crate::page_merkle::h_after_node_tag_words());
        let bc = move |b: u8| PackedBaseField::broadcast(BaseField::from(b as u32));

        // Node-compression tuple builder (265 limbs).  `Copy` (captures only
        // `node_tag` + `bc`, both `Copy`), so it's reused without cloning.
        let node_tuple = move |l: &[crate::trace::component::FinalizedColumn],
                               r: &[crate::trace::component::FinalizedColumn],
                               hout: &[crate::trace::component::FinalizedColumn],
                               v: usize|
              -> Vec<PackedBaseField> {
            let mut t = Vec::with_capacity(265);
            for &b in &node_tag {
                t.push(bc(b));
            }
            for c in l.iter().take(32) {
                t.push(c.at(v));
            }
            for c in r.iter().take(32) {
                t.push(c.at(v));
            }
            for _ in 0..64 {
                t.push(PackedBaseField::zero());
            }
            t.push(bc(192));
            for _ in 0..7 {
                t.push(PackedBaseField::zero());
            }
            t.push(PackedBaseField::one());
            for c in hout.iter().take(64) {
                t.push(c.at(v));
            }
            t
        };

        // 1: before node compression — CONSUME.
        {
            let (left_b, right_b, hout_b) = (left_b.clone(), right_b.clone(), hout_b.clone());
            logup.add_to_relation_computed(
                compression,
                [is_real[0].clone()],
                |[r]| (-r).into(),
                265,
                move |v| node_tuple(&left_b, &right_b, &hout_b, v),
            );
        }
        // 2: after node compression — CONSUME.
        {
            let (left_a, right_a, hout_a) = (left_a.clone(), right_a.clone(), hout_a.clone());
            logup.add_to_relation_computed(
                compression,
                [is_real[0].clone()],
                |[r]| (-r).into(),
                265,
                move |v| node_tuple(&left_a, &right_a, &hout_a, v),
            );
        }
        // 3: parent — PRODUCE.
        {
            let (level, index, hout_b, hout_a) =
                (level.clone(), index.clone(), hout_b.clone(), hout_a.clone());
            logup.add_to_relation_computed(
                merkle,
                [is_real[0].clone()],
                |[r]| r.into(),
                66,
                move |v| {
                    let mut t = Vec::with_capacity(66);
                    t.push(level[0].at(v));
                    t.push(index[0].at(v));
                    for c in hout_b.iter().take(32) {
                        t.push(c.at(v));
                    }
                    for c in hout_a.iter().take(32) {
                        t.push(c.at(v));
                    }
                    t
                },
            );
        }
        // 4: left child — CONSUME.
        {
            let (level, index, left_b, left_a) =
                (level.clone(), index.clone(), left_b.clone(), left_a.clone());
            logup.add_to_relation_computed(
                merkle,
                [comp_l[0].clone()],
                |[c]| (-c).into(),
                66,
                move |v| {
                    let mut t = Vec::with_capacity(66);
                    t.push(level[0].at(v) + PackedBaseField::one());
                    t.push(index[0].at(v) * PackedBaseField::broadcast(BaseField::from(2u32)));
                    for c in left_b.iter() {
                        t.push(c.at(v));
                    }
                    for c in left_a.iter() {
                        t.push(c.at(v));
                    }
                    t
                },
            );
        }
        // 5: right child — CONSUME.
        {
            let (level, index, right_b, right_a) = (
                level.clone(),
                index.clone(),
                right_b.clone(),
                right_a.clone(),
            );
            logup.add_to_relation_computed(
                merkle,
                [comp_r[0].clone()],
                |[c]| (-c).into(),
                66,
                move |v| {
                    let mut t = Vec::with_capacity(66);
                    t.push(level[0].at(v) + PackedBaseField::one());
                    t.push(
                        index[0].at(v) * PackedBaseField::broadcast(BaseField::from(2u32))
                            + PackedBaseField::one(),
                    );
                    for c in right_b.iter() {
                        t.push(c.at(v));
                    }
                    for c in right_a.iter() {
                        t.push(c.at(v));
                    }
                    t
                },
            );
        }

        logup.finalize()
    }
}
