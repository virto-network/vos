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
//!
//! A page's permission: the program's layout is four regions of pages,
//! preprocessed constants, so part of its identity — two readable (the
//! read-only data, the argument window), two writable (the read-write data
//! with its heap, the stack). A row selects the region its page lies in
//! and proves `first ≤ page < end` by two 20-bit decompositions; selecting
//! none, the page is unmapped, which needs no proof since it only forbids.
//! The row's ts=0 writes carry the permission, `0` unmapped, `1` readable,
//! `2` writable, in their tuple's last field as `2·permission` (every other
//! producer's tuples carry 0 there, the closing reads 1), and `MemoryChip`
//! holds every access of the address to it.

use crate::prelude::*;
use num_traits::{One, Zero};
use stwo::core::fields::m31::BaseField;
use stwo_constraint_framework::{EvalAtRow, RelationEntry};

use crate::air_column::{AirColumn, PreprocessedAirColumn};
use crate::framework::BuiltInComponent;
use crate::lookups::{
    Blake2bCompressionLookupElements, MemoryAccessLookupElements, MerkleNodeLookupElements,
};
use crate::memory_layout::{FIRST_WRITABLE, REGIONS};
use crate::page_merkle::DEPTH;
use crate::trace::eval::TraceEval;

#[derive(Clone, Copy)]
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
    /// Closing-read timestamp, 8 LE limbs: a witness, bound to no final
    /// state; the ledger takes the one closing read as its group's last
    /// row. One value on every row, padding included (`#[mask_next_row]`):
    /// every page closes at the same timestamp.
    #[size = 8]
    #[mask_next_row]
    ClosingTs,
    /// 20-bit boolean decomposition of the page index (so `idx < 2^DEPTH`);
    /// constant across the page's 32 rows (`#[mask_next_row]` replication).
    #[size = 20]
    #[mask_next_row]
    IdxBits,
    /// 1 on real rows, 0 on padding; constant across a page's 32 rows
    /// (`#[mask_next_row]` replication), so every real page produces its
    /// leaf from block 0's `h_in` on.
    #[size = 1]
    #[mask_next_row]
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
    /// 1 on the region the page lies in, at most one: the page's
    /// permission, unmapped when none.
    #[size = 4]
    RegionSelect,
    /// The selected region's first page, `Σ RegionSelect·RegionFirst`.
    #[size = 1]
    RegionFirstH,
    /// The selected region's end page, `Σ RegionSelect·RegionEnd`.
    #[size = 1]
    RegionEndH,
    /// `page − first` on a selected region, as 20 bits: non-negative.
    #[size = 20]
    FromFirstBits,
    /// `end − 1 − page` on a selected region, as 20 bits: non-negative.
    #[size = 20]
    ToEndBits,
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
    /// The layout's regions' first pages, constant on every row.
    #[size = 4]
    RegionFirst,
    /// The layout's regions' end pages (exclusive), constant on every row.
    #[size = 4]
    RegionEnd,
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
        let closing_ts_next = crate::trace::trace_eval_next_row!(trace_eval, Column::ClosingTs);
        let idx_bits = crate::trace::trace_eval!(trace_eval, Column::IdxBits);
        let idx_bits_next = crate::trace::trace_eval_next_row!(trace_eval, Column::IdxBits);
        let is_real = crate::trace::trace_eval!(trace_eval, Column::IsReal);
        let is_real_next = crate::trace::trace_eval_next_row!(trace_eval, Column::IsReal);
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

        // ── One closing timestamp on every row (degree 1) ─────────
        for (next, ts) in closing_ts_next.iter().zip(&closing_ts) {
            eval.add_constraint(next.clone() - ts.clone());
        }

        // ── Gate helper definitions (degree 2) ────────────────────
        eval.add_constraint(
            chain_gate[0].clone() - (one.clone() - is_last_block[0].clone()) * is_real[0].clone(),
        );
        eval.add_constraint(block0_gate[0].clone() - is_block0[0].clone() * is_real[0].clone());
        eval.add_constraint(last_gate[0].clone() - is_last_block[0].clone() * is_real[0].clone());

        // ── Realness replication within a page (degree 2) ─────────
        eval.add_constraint(
            (one.clone() - is_last_block[0].clone())
                * (is_real_next[0].clone() - is_real[0].clone()),
        );

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

        // ── The page's permission ─────────────────────────────────
        // At most one region selected; on it, `first ≤ page < end` as two
        // non-negative 20-bit distances (the page and the bounds lie below
        // 2^20, so a negative distance, near p, has no decomposition).
        let select = crate::trace::trace_eval!(trace_eval, Column::RegionSelect);
        let first_h = crate::trace::trace_eval!(trace_eval, Column::RegionFirstH);
        let end_h = crate::trace::trace_eval!(trace_eval, Column::RegionEndH);
        let from_first = crate::trace::trace_eval!(trace_eval, Column::FromFirstBits);
        let to_end = crate::trace::trace_eval!(trace_eval, Column::ToEndBits);
        let region_first =
            crate::trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::RegionFirst);
        let region_end =
            crate::trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::RegionEnd);
        let mut selected = E::F::zero();
        let mut first = E::F::zero();
        let mut end = E::F::zero();
        let mut readable = E::F::zero();
        let mut writable = E::F::zero();
        for k in 0..REGIONS {
            eval.add_constraint(select[k].clone() * (select[k].clone() - one.clone()));
            selected += select[k].clone();
            first += select[k].clone() * region_first[k].clone();
            end += select[k].clone() * region_end[k].clone();
            if k < FIRST_WRITABLE {
                readable += select[k].clone();
            } else {
                writable += select[k].clone();
            }
        }
        eval.add_constraint(selected.clone() * (selected.clone() - one.clone()));
        eval.add_constraint(first_h[0].clone() - first);
        eval.add_constraint(end_h[0].clone() - end);
        for bit in from_first.iter().chain(&to_end) {
            eval.add_constraint(bit.clone() * (bit.clone() - one.clone()));
        }
        let bits_value = |bits: &[E::F]| -> E::F {
            let mut value = E::F::zero();
            let mut weight = E::F::one();
            for bit in bits {
                value += bit.clone() * weight.clone();
                weight *= two.clone();
            }
            value
        };
        eval.add_constraint(
            bits_value(&from_first) - (selected.clone() * idx_value.clone() - first_h[0].clone()),
        );
        eval.add_constraint(
            bits_value(&to_end)
                - (end_h[0].clone() - selected.clone() - selected * idx_value.clone()),
        );
        // The ts=0 writes' last field: 2·permission, the permission 0
        // unmapped, 1 readable, 2 writable.
        let permission_field = two.clone() * (readable + writable.clone() + writable);

        // ── Emissions (fixed order; finalize_logup_in_pairs) ──────
        // 1) 128 ts=0 boundary writes: (addr, before, 0, write=1,
        //    2·permission).
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
            tuple.push(permission_field.clone()); // not closing: 2·permission
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
    }
}

#[cfg(feature = "prover")]
mod fill;
#[cfg(feature = "prover")]
mod pin;
