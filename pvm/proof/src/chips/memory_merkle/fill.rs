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

impl BuiltInProverComponent for MemoryMerkleChip {
    const IS_PRODUCER: bool = false;

    fn generate_main_trace_immut_min(
        &self,
        side_note: &SideNote,
        min_log_size: u32,
    ) -> FinalizedTrace {
        use crate::page_merkle::{Child, node_full_output};

        let empty = Vec::new();
        let merges = match &side_note.memory_pages {
            Some(p) => &p.multiproof.merges,
            None => &empty,
        };
        let log_size =
            crate::trace::utils::ceil_log2_at_least_lanes(merges.len().max(1)).max(min_log_size);
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
        component_trace: &ComponentTrace,
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
