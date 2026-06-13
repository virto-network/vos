//! MemoryPageChip — one row per `(listed page, 128-byte block)` (design §3.2).
//! It is the bottom of the in-AIR memory-page Merkle trie and the producer of
//! the per-page RAM boundary entries.  Per row it:
//!
//! - PRODUCES 128 `ts=0` boundary writes (entering bytes) + 128 closing reads
//!   (exit bytes) into the `MemoryAccess` ledger (the entries `MemoryChip`
//!   injects and binds via read-consistency / sortedness / group constraints);
//! - CONSUMES this block's leaf `Blake2bCompression` over BOTH passes
//!   (`h_in → h_out`), with the per-block chaining enforced by cross-row
//!   constraints (`h_in` of block `k+1` equals `h_out` of block `k`; block 0
//!   starts from the leaf-tag chaining constant);
//! - on the last block of a page, PRODUCES the leaf `MerkleNode`
//!   `(DEPTH, page_idx, leaf_before, leaf_after)`.
//!
//! The page index is a 20-bit boolean decomposition (so leaf indices are
//! `< 2^DEPTH`, the one load-bearing index range-check — design §1) held
//! constant across the page's 32 rows; ledger byte addresses are degree-1 in
//! it (`addr = idx·4096 + block·128 + cell`).

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
use crate::framework::BuiltInComponent;
use crate::lookups::{
    Blake2bCompressionLookupElements, MemoryAccessLookupElements, MerkleNodeLookupElements,
};
use crate::page_merkle::DEPTH;
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

pub struct MemoryPageChip;

/// 128 bytes / block, 32 blocks / page.
const BLOCK_BYTES: usize = 128;
const BLOCKS_PER_PAGE: usize = 32;

#[derive(Debug, Copy, Clone, AirColumn)]
pub enum Column {
    /// Entering-image bytes of this block (leaf-compression message AND the
    /// ts=0-write values).
    #[size = 128]
    Before,
    /// Exit-image bytes of this block (after-pass message AND closing-read
    /// values).
    #[size = 128]
    After,
    /// Before-pass leaf chaining state ENTERING this block (`#[mask_next_row]`
    /// so the chain constraint can require `h_in` of block `k+1` to equal
    /// `h_out` of block `k`).
    #[size = 64]
    #[mask_next_row]
    HInBefore,
    /// After-pass leaf chaining state entering this block.
    #[size = 64]
    #[mask_next_row]
    HInAfter,
    /// Before-pass leaf chaining state LEAVING this block; first 32 bytes of
    /// the last block are the entering leaf digest.
    #[size = 64]
    HOutBefore,
    /// After-pass leaf chaining state leaving this block.
    #[size = 64]
    HOutAfter,
    /// Closing-read timestamp (`= final_state.timestamp`), 8 LE limbs.
    #[size = 8]
    ClosingTs,
    /// 20-bit boolean decomposition of the page index (so `idx < 2^DEPTH`);
    /// constant across the page's 32 rows (`#[mask_next_row]` replication).
    #[size = 20]
    #[mask_next_row]
    IdxBits,
    /// 1 on real rows, 0 on padding.
    #[size = 1]
    IsReal,
    /// BOUND helper `(1 − IsLastBlock) · IsReal`: gates the leaf chain
    /// continuity + page-index replication (degree-1 so they stay degree 2).
    #[size = 1]
    ChainGateH,
    /// BOUND helper `IsBlock0 · IsReal`: gates the block-0 `h_in` init.
    #[size = 1]
    Block0GateH,
    /// BOUND helper `IsLastBlock · IsReal`: gates the leaf `MerkleNode` produce.
    #[size = 1]
    LastBlockGateH,
}

#[derive(Debug, Copy, Clone, PreprocessedAirColumn)]
#[preprocessed_prefix = "mempage"]
pub enum PreprocessedColumn {
    /// 1 iff `row % 32 == 0`.
    #[size = 1]
    IsBlock0,
    /// 1 iff `row % 32 == 31`.
    #[size = 1]
    IsLastBlock,
    /// Low bit of the block index (`(row % 32) & 1`) — address bit 7.
    #[size = 1]
    BlockLo,
    /// High 4 bits of the block index (`(row % 32) >> 1`) — address bits 8..12.
    #[size = 1]
    BlockHi,
    /// `t` counter of THIS block's leaf compression (`128·(block+2)`), 8 LE
    /// limbs.
    #[size = 8]
    TBlock,
    /// `f` flag of this block's leaf compression (`(block == 31)`).
    #[size = 1]
    FBlock,
}

impl BuiltInComponent for MemoryPageChip {
    const LOG_CONSTRAINT_DEGREE_BOUND: u32 = 1;

    type PreprocessedColumn = PreprocessedColumn;
    type MainColumn = Column;
    type LookupElements = (
        MemoryAccessLookupElements,
        Blake2bCompressionLookupElements,
        MerkleNodeLookupElements,
    );

    fn add_constraints<E: EvalAtRow>(
        &self,
        eval: &mut E,
        trace_eval: TraceEval<PreprocessedColumn, Column, E>,
        lookup_elements: &(
            MemoryAccessLookupElements,
            Blake2bCompressionLookupElements,
            MerkleNodeLookupElements,
        ),
    ) {
        let (mem_lookup, compression_lookup, merkle_lookup) = lookup_elements;

        let before = crate::trace::trace_eval!(trace_eval, Column::Before);
        let after = crate::trace::trace_eval!(trace_eval, Column::After);
        let hin_b = crate::trace::trace_eval!(trace_eval, Column::HInBefore);
        let hin_a = crate::trace::trace_eval!(trace_eval, Column::HInAfter);
        let hin_b_next = crate::trace::trace_eval_next_row!(trace_eval, Column::HInBefore);
        let hin_a_next = crate::trace::trace_eval_next_row!(trace_eval, Column::HInAfter);
        let hout_b = crate::trace::trace_eval!(trace_eval, Column::HOutBefore);
        let hout_a = crate::trace::trace_eval!(trace_eval, Column::HOutAfter);
        let closing_ts = crate::trace::trace_eval!(trace_eval, Column::ClosingTs);
        let idx_bits = crate::trace::trace_eval!(trace_eval, Column::IdxBits);
        let idx_bits_next = crate::trace::trace_eval_next_row!(trace_eval, Column::IdxBits);
        let is_real = crate::trace::trace_eval!(trace_eval, Column::IsReal);
        let chain_gate = crate::trace::trace_eval!(trace_eval, Column::ChainGateH);
        let block0_gate = crate::trace::trace_eval!(trace_eval, Column::Block0GateH);
        let last_gate = crate::trace::trace_eval!(trace_eval, Column::LastBlockGateH);

        let is_block0 =
            crate::trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::IsBlock0);
        let is_last_block =
            crate::trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::IsLastBlock);
        let block_lo =
            crate::trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::BlockLo);
        let block_hi =
            crate::trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::BlockHi);
        let t_block =
            crate::trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::TBlock);
        let f_block =
            crate::trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::FBlock);

        let one = E::F::one();
        let two = E::F::from(BaseField::from(2u32));
        let c16 = E::F::from(BaseField::from(16u32));
        let c128 = E::F::from(BaseField::from(128u32));
        let cst = |b: u8| E::F::from(BaseField::from(b as u32));

        // ── Booleans ──────────────────────────────────────────────
        eval.add_constraint(is_real[0].clone() * (is_real[0].clone() - one.clone()));
        for b in &idx_bits {
            eval.add_constraint(b.clone() * (b.clone() - one.clone()));
        }

        // ── Gate helper definitions (degree 2) ────────────────────
        eval.add_constraint(
            chain_gate[0].clone() - (one.clone() - is_last_block[0].clone()) * is_real[0].clone(),
        );
        eval.add_constraint(block0_gate[0].clone() - is_block0[0].clone() * is_real[0].clone());
        eval.add_constraint(last_gate[0].clone() - is_last_block[0].clone() * is_real[0].clone());

        // ── Page-index replication within a page (degree 2) ───────
        for k in 0..20 {
            eval.add_constraint(
                chain_gate[0].clone() * (idx_bits_next[k].clone() - idx_bits[k].clone()),
            );
        }

        // ── Leaf chain continuity (degree 2) ──────────────────────
        // block 0 starts from the leaf-tag chaining constant; each subsequent
        // block's h_in equals the previous block's h_out.
        let leaf_tag =
            crate::page_merkle::state_to_bytes(&crate::page_merkle::h_after_leaf_tag_words());
        for i in 0..64 {
            eval.add_constraint(block0_gate[0].clone() * (hin_b[i].clone() - cst(leaf_tag[i])));
            eval.add_constraint(block0_gate[0].clone() * (hin_a[i].clone() - cst(leaf_tag[i])));
            eval.add_constraint(
                chain_gate[0].clone() * (hin_b_next[i].clone() - hout_b[i].clone()),
            );
            eval.add_constraint(
                chain_gate[0].clone() * (hin_a_next[i].clone() - hout_a[i].clone()),
            );
        }

        // ── Address-byte expressions (degree 1 in IdxBits) ────────
        // idx = Σ bit_i·2^i; nibbles n0..n4; addr_base = idx·4096 + block·128.
        let nibble = |lo: usize| -> E::F {
            idx_bits[lo].clone()
                + idx_bits[lo + 1].clone() * two.clone()
                + idx_bits[lo + 2].clone() * cst(4)
                + idx_bits[lo + 3].clone() * cst(8)
        };
        let n0 = nibble(0);
        let n1 = nibble(4);
        let n2 = nibble(8);
        let n3 = nibble(12);
        let n4 = nibble(16);
        let addr1 = block_hi[0].clone() + n0 * c16.clone();
        let addr2 = n1 + n2 * c16.clone();
        let addr3 = n3 + n4 * c16.clone();
        let addr0_base = block_lo[0].clone() * c128.clone();

        let mut idx_value = E::F::zero();
        let mut pow = E::F::one();
        for b in &idx_bits {
            idx_value += b.clone() * pow.clone();
            pow *= two.clone();
        }

        // ── Emissions (fixed order; finalize_logup_in_pairs) ──────
        // 1) 128 ts=0 boundary writes: (addr, before, 0, write=1, closing=0).
        for i in 0..BLOCK_BYTES {
            let mut tuple: Vec<E::F> = Vec::with_capacity(15);
            tuple.push(addr0_base.clone() + cst(i as u8));
            tuple.push(addr1.clone());
            tuple.push(addr2.clone());
            tuple.push(addr3.clone());
            tuple.push(before[i].clone());
            for _ in 0..8 {
                tuple.push(E::F::zero()); // ts = 0
            }
            tuple.push(one.clone()); // is_write = 1
            tuple.push(E::F::zero()); // is_closing = 0
            eval.add_to_relation(RelationEntry::new(
                mem_lookup,
                is_real[0].clone().into(),
                &tuple,
            ));
        }
        // 2) 128 closing reads: (addr, after, closing_ts, write=0, closing=1).
        for i in 0..BLOCK_BYTES {
            let mut tuple: Vec<E::F> = Vec::with_capacity(15);
            tuple.push(addr0_base.clone() + cst(i as u8));
            tuple.push(addr1.clone());
            tuple.push(addr2.clone());
            tuple.push(addr3.clone());
            tuple.push(after[i].clone());
            for limb in &closing_ts {
                tuple.push(limb.clone());
            }
            tuple.push(E::F::zero()); // is_write = 0
            tuple.push(one.clone()); // is_closing = 1
            eval.add_to_relation(RelationEntry::new(
                mem_lookup,
                is_real[0].clone().into(),
                &tuple,
            ));
        }

        // 3+4) leaf compressions (before / after) — CONSUME, current row only:
        // (h_in, m = block bytes, t, f, h_out).
        let comp_tuple = |h_in: &[E::F], m: &[E::F], h_out: &[E::F]| -> Vec<E::F> {
            let mut t: Vec<E::F> = Vec::with_capacity(265);
            for v in h_in.iter().take(64) {
                t.push(v.clone());
            }
            for v in m.iter().take(128) {
                t.push(v.clone());
            }
            for limb in &t_block {
                t.push(limb.clone());
            }
            t.push(f_block[0].clone());
            for v in h_out.iter().take(64) {
                t.push(v.clone());
            }
            t
        };
        eval.add_to_relation(RelationEntry::new(
            compression_lookup,
            (-is_real[0].clone()).into(),
            &comp_tuple(&hin_b, &before, &hout_b),
        ));
        eval.add_to_relation(RelationEntry::new(
            compression_lookup,
            (-is_real[0].clone()).into(),
            &comp_tuple(&hin_a, &after, &hout_a),
        ));

        // 5) leaf MerkleNode PRODUCE on the last block.
        let mut leaf: Vec<E::F> = Vec::with_capacity(66);
        leaf.push(cst(DEPTH as u8));
        leaf.push(idx_value);
        for v in hout_b.iter().take(32) {
            leaf.push(v.clone());
        }
        for v in hout_a.iter().take(32) {
            leaf.push(v.clone());
        }
        eval.add_to_relation(RelationEntry::new(
            merkle_lookup,
            last_gate[0].clone().into(),
            &leaf,
        ));

        eval.finalize_logup_in_pairs();
    }
}

#[cfg(feature = "prover")]
impl BuiltInProverComponent for MemoryPageChip {
    const IS_PRODUCER: bool = false;

    fn generate_preprocessed_trace(&self, log_size: u32, _side_note: &SideNote) -> FinalizedTrace {
        let mut trace = TraceBuilder::<PreprocessedColumn>::new(log_size);
        for row in 0..trace.num_rows() {
            let block = row % BLOCKS_PER_PAGE;
            trace.fill_columns(row, block == 0, PreprocessedColumn::IsBlock0);
            trace.fill_columns(
                row,
                block == BLOCKS_PER_PAGE - 1,
                PreprocessedColumn::IsLastBlock,
            );
            trace.fill_columns(row, (block & 1) as u8, PreprocessedColumn::BlockLo);
            trace.fill_columns(row, (block >> 1) as u8, PreprocessedColumn::BlockHi);
            trace.fill_columns(row, 128u64 * (block as u64 + 2), PreprocessedColumn::TBlock);
            trace.fill_columns(
                row,
                block == BLOCKS_PER_PAGE - 1,
                PreprocessedColumn::FBlock,
            );
        }
        trace.finalize_bit_reversed()
    }

    fn generate_main_trace_immut(&self, side_note: &SideNote) -> FinalizedTrace {
        use crate::page_merkle::{leaf_block_outputs, state_to_bytes};

        let empty = Vec::new();
        let pages = match &side_note.memory_pages {
            Some(p) => &p.pages,
            None => &empty,
        };
        let closing_ts = crate::chips::register_memory_closing::closing_ts_for(side_note);
        let leaf_tag = state_to_bytes(&crate::page_merkle::h_after_leaf_tag_words());

        let num_rows_real = pages.len() * BLOCKS_PER_PAGE;
        let log_size = crate::trace::utils::ceil_log2_at_least_lanes(num_rows_real.max(1));
        let mut trace = TraceBuilder::<Column>::new(log_size);

        for (pi, page) in pages.iter().enumerate() {
            let before_arr: &[u8; crate::page_merkle::PAGE_SIZE] =
                page.before[..].try_into().expect("page image is PAGE_SIZE");
            let after_arr: &[u8; crate::page_merkle::PAGE_SIZE] =
                page.after[..].try_into().expect("page image is PAGE_SIZE");
            let outs_b = leaf_block_outputs(before_arr);
            let outs_a = leaf_block_outputs(after_arr);
            let idx_bits: [BaseField; 20] =
                core::array::from_fn(|k| BaseField::from((page.page_idx >> k) & 1));

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
            }
        }
        // Padding rows keep IsReal = 0 and all helpers 0.

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

        // 1) 128 ts=0 writes.
        for i in 0..BLOCK_BYTES {
            let (before, addr_bytes, is_real) =
                (before.clone(), addr_bytes.clone(), is_real.clone());
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
                    t.push(PackedBaseField::zero());
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
