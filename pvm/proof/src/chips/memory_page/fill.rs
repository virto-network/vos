//! The chip's trace generation, the prover's half.

use super::*;
use crate::framework::BuiltInProverComponent;
use crate::lookups::{AllLookupElements, LogupTraceBuilder};
use crate::memory_layout::Permission;
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

/// The bits of a page index, and of a page's distance to its region's ends.
const PAGE_BITS: usize = DEPTH as usize;

impl BuiltInProverComponent for MemoryPageChip {
    const IS_PRODUCER: bool = false;

    fn generate_preprocessed_trace(&self, log_size: u32, side_note: &SideNote) -> FinalizedTrace {
        self.preprocessed_trace(log_size, side_note)
    }

    fn generate_main_trace_immut_min(
        &self,
        side_note: &SideNote,
        min_log_size: u32,
    ) -> FinalizedTrace {
        use crate::page_merkle::{leaf_block_outputs, state_to_bytes};

        let empty = Vec::new();
        let pages = match &side_note.memory_pages {
            Some(p) => &p.pages,
            None => &empty,
        };
        let closing_ts = crate::chips::register_memory_closing::closing_ts_for(side_note);
        let leaf_tag = state_to_bytes(&crate::page_merkle::h_after_leaf_tag_words());

        let num_rows_real = pages.len() * BLOCKS_PER_PAGE;
        let log_size =
            crate::trace::utils::ceil_log2_at_least_lanes(num_rows_real.max(1)).max(min_log_size);
        let mut trace = TraceBuilder::<Column>::new(log_size);
        let layout = side_note.layout();

        for (pi, page) in pages.iter().enumerate() {
            let before_arr: &[u8; crate::page_merkle::PAGE_SIZE] =
                page.before[..].try_into().expect("page image is PAGE_SIZE");
            let after_arr: &[u8; crate::page_merkle::PAGE_SIZE] =
                page.after[..].try_into().expect("page image is PAGE_SIZE");
            let outs_b = leaf_block_outputs(before_arr);
            let outs_a = leaf_block_outputs(after_arr);
            let idx_bits: [BaseField; 20] =
                core::array::from_fn(|k| BaseField::from((page.page_idx >> k) & 1));
            // Its region, if any: the selector, the bounds, and the two
            // distances inside them.
            let region = layout.region_of(page.page_idx);
            let select: [BaseField; REGIONS] =
                core::array::from_fn(|k| BaseField::from(u32::from(region == Some(k))));
            let (first, end) =
                region.map_or((0, 0), |k| (layout.regions[k].first, layout.regions[k].end));
            let (from_first, to_end) = match region {
                Some(_) => (page.page_idx - first, end - 1 - page.page_idx),
                None => (0, 0),
            };
            let bits = |value: u32| -> [BaseField; PAGE_BITS] {
                core::array::from_fn(|k| BaseField::from((value >> k) & 1))
            };

            for block in 0..BLOCKS_PER_PAGE {
                let row = pi * BLOCKS_PER_PAGE + block;
                let off = block * BLOCK_BYTES;
                trace.fill_columns_bytes(row, &before_arr[off..off + BLOCK_BYTES], Column::Before);
                trace.fill_columns_bytes(row, &after_arr[off..off + BLOCK_BYTES], Column::After);

                let hin_b = if block == 0 {
                    leaf_tag
                } else {
                    outs_b[block - 1]
                };
                let hin_a = if block == 0 {
                    leaf_tag
                } else {
                    outs_a[block - 1]
                };
                trace.fill_columns_bytes(row, &hin_b, Column::HInBefore);
                trace.fill_columns_bytes(row, &hin_a, Column::HInAfter);
                trace.fill_columns_bytes(row, &outs_b[block], Column::HOutBefore);
                trace.fill_columns_bytes(row, &outs_a[block], Column::HOutAfter);

                trace.fill_columns(row, closing_ts, Column::ClosingTs);
                trace.fill_columns_base_field(row, &idx_bits, Column::IdxBits);
                trace.fill_columns(row, true, Column::IsReal);
                trace.fill_columns(row, block != BLOCKS_PER_PAGE - 1, Column::ChainGateH);
                trace.fill_columns(row, block == 0, Column::Block0GateH);
                trace.fill_columns(row, block == BLOCKS_PER_PAGE - 1, Column::LastBlockGateH);
                trace.fill_columns_base_field(row, &select, Column::RegionSelect);
                trace.fill_columns(row, BaseField::from(first), Column::RegionFirstH);
                trace.fill_columns(row, BaseField::from(end), Column::RegionEndH);
                trace.fill_columns_base_field(row, &bits(from_first), Column::FromFirstBits);
                trace.fill_columns_base_field(row, &bits(to_end), Column::ToEndBits);
            }
        }
        // Padding rows keep IsReal = 0 and all helpers 0.

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

        let mem: &MemoryAccessLookupElements = lookup_elements.as_ref();
        let compression: &Blake2bCompressionLookupElements = lookup_elements.as_ref();
        let merkle: &MerkleNodeLookupElements = lookup_elements.as_ref();

        let before = crate::trace::original_base_column!(component_trace, Column::Before);
        let after = crate::trace::original_base_column!(component_trace, Column::After);
        let hin_b = crate::trace::original_base_column!(component_trace, Column::HInBefore);
        let hin_a = crate::trace::original_base_column!(component_trace, Column::HInAfter);
        let hout_b = crate::trace::original_base_column!(component_trace, Column::HOutBefore);
        let hout_a = crate::trace::original_base_column!(component_trace, Column::HOutAfter);
        let closing_ts = crate::trace::original_base_column!(component_trace, Column::ClosingTs);
        let idx_bits = crate::trace::original_base_column!(component_trace, Column::IdxBits);
        let is_real = crate::trace::original_base_column!(component_trace, Column::IsReal);
        let last_gate =
            crate::trace::original_base_column!(component_trace, Column::LastBlockGateH);
        let select = crate::trace::original_base_column!(component_trace, Column::RegionSelect);

        let block_lo = component_trace
            .preprocessed_base_column::<1, PreprocessedColumn>(PreprocessedColumn::BlockLo);
        let block_hi = component_trace
            .preprocessed_base_column::<1, PreprocessedColumn>(PreprocessedColumn::BlockHi);
        let t_block = component_trace
            .preprocessed_base_column::<8, PreprocessedColumn>(PreprocessedColumn::TBlock);
        let f_block = component_trace
            .preprocessed_base_column::<1, PreprocessedColumn>(PreprocessedColumn::FBlock);

        let bc = |b: u8| PackedBaseField::broadcast(BaseField::from(b as u32));
        let c16 = bc(16);
        let c128 = bc(128);
        let two = bc(2);

        let addr_bytes = {
            let (idx_bits, block_lo, block_hi) =
                (idx_bits.clone(), block_lo.clone(), block_hi.clone());
            move |v: usize| -> (
                PackedBaseField,
                PackedBaseField,
                PackedBaseField,
                PackedBaseField,
            ) {
                let nib = |lo: usize| {
                    idx_bits[lo].at(v)
                        + idx_bits[lo + 1].at(v) * two
                        + idx_bits[lo + 2].at(v) * bc(4)
                        + idx_bits[lo + 3].at(v) * bc(8)
                };
                let addr1 = block_hi[0].at(v) + nib(0) * c16;
                let addr2 = nib(4) + nib(8) * c16;
                let addr3 = nib(12) + nib(16) * c16;
                let addr0_base = block_lo[0].at(v) * c128;
                (addr0_base, addr1, addr2, addr3)
            }
        };

        // 1) 128 ts=0 writes, their last field 2·permission.
        for i in 0..BLOCK_BYTES {
            let (before, addr_bytes, is_real, select) = (
                before.clone(),
                addr_bytes.clone(),
                is_real.clone(),
                select.clone(),
            );
            logup.add_to_relation_computed(
                mem,
                [is_real[0].clone()],
                |[r]| r.into(),
                15,
                move |v| {
                    let (a0, a1, a2, a3) = addr_bytes(v);
                    let mut t = Vec::with_capacity(15);
                    t.push(a0 + bc(i as u8));
                    t.push(a1);
                    t.push(a2);
                    t.push(a3);
                    t.push(before[i].at(v));
                    for _ in 0..8 {
                        t.push(PackedBaseField::zero());
                    }
                    t.push(PackedBaseField::one());
                    let mut permission = PackedBaseField::zero();
                    for (k, column) in select.iter().enumerate() {
                        let code = if k < FIRST_WRITABLE {
                            Permission::Readable
                        } else {
                            Permission::Writable
                        };
                        permission += column.at(v) * bc(code as u8);
                    }
                    t.push(permission * two);
                    t
                },
            );
        }
        // 2) 128 closing reads.
        for i in 0..BLOCK_BYTES {
            let (after, closing_ts, addr_bytes, is_real) = (
                after.clone(),
                closing_ts.clone(),
                addr_bytes.clone(),
                is_real.clone(),
            );
            logup.add_to_relation_computed(
                mem,
                [is_real[0].clone()],
                |[r]| r.into(),
                15,
                move |v| {
                    let (a0, a1, a2, a3) = addr_bytes(v);
                    let mut t = Vec::with_capacity(15);
                    t.push(a0 + bc(i as u8));
                    t.push(a1);
                    t.push(a2);
                    t.push(a3);
                    t.push(after[i].at(v));
                    for c in closing_ts.iter().take(8) {
                        t.push(c.at(v));
                    }
                    t.push(PackedBaseField::zero());
                    t.push(PackedBaseField::one());
                    t
                },
            );
        }

        // 3+4) leaf compressions (before / after) — CONSUME.
        let comp_tuple = {
            let (t_block, f_block) = (t_block.clone(), f_block.clone());
            move |h_in: &[crate::trace::component::FinalizedColumn],
                  m: &[crate::trace::component::FinalizedColumn],
                  h_out: &[crate::trace::component::FinalizedColumn],
                  v: usize|
                  -> Vec<PackedBaseField> {
                let mut t = Vec::with_capacity(265);
                for c in h_in.iter().take(64) {
                    t.push(c.at(v));
                }
                for c in m.iter().take(128) {
                    t.push(c.at(v));
                }
                for c in t_block.iter().take(8) {
                    t.push(c.at(v));
                }
                t.push(f_block[0].at(v));
                for c in h_out.iter().take(64) {
                    t.push(c.at(v));
                }
                t
            }
        };
        {
            let (hin_b, before, hout_b, is_real, comp_tuple) = (
                hin_b.clone(),
                before.clone(),
                hout_b.clone(),
                is_real.clone(),
                comp_tuple.clone(),
            );
            logup.add_to_relation_computed(
                compression,
                [is_real[0].clone()],
                |[r]| (-r).into(),
                265,
                move |v| comp_tuple(&hin_b, &before, &hout_b, v),
            );
        }
        {
            let (hin_a, after, hout_a, is_real, comp_tuple) = (
                hin_a.clone(),
                after.clone(),
                hout_a.clone(),
                is_real.clone(),
                comp_tuple.clone(),
            );
            logup.add_to_relation_computed(
                compression,
                [is_real[0].clone()],
                |[r]| (-r).into(),
                265,
                move |v| comp_tuple(&hin_a, &after, &hout_a, v),
            );
        }

        // 5) leaf MerkleNode produce.
        {
            let (idx_bits, hout_b, hout_a, last_gate) = (
                idx_bits.clone(),
                hout_b.clone(),
                hout_a.clone(),
                last_gate.clone(),
            );
            logup.add_to_relation_computed(
                merkle,
                [last_gate[0].clone()],
                |[r]| r.into(),
                66,
                move |v| {
                    let mut t = Vec::with_capacity(66);
                    t.push(bc(DEPTH as u8));
                    let mut idx = PackedBaseField::zero();
                    let mut pow = PackedBaseField::one();
                    for b in idx_bits.iter().take(20) {
                        idx += b.at(v) * pow;
                        pow *= two;
                    }
                    t.push(idx);
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

        logup.finalize()
    }
}
