//! Ristretto / scalar-family ECALL memory-producer chip with in-AIR
//! timestamp binding.
//!
//! Every `ECALL_RISTRETTO_SCALAR_MULT` (110), `ECALL_RISTRETTO_POINT_ADD`
//! (111), `ECALL_SCALAR_FROM_BYTES_MOD_ORDER_WIDE` (112) and
//! `ECALL_SCALAR_{MUL,ADD}_MOD_L` (113/114) call touches `flat_mem` during
//! its host handler (96 byte accesses each).  The MemoryChip ledger inserts
//! the matching CONSUMER tuples; this chip emits the matching PRODUCERS so
//! the lookup balances.
//!
//! Soundness — `ts` binding.  A from-scratch prover could otherwise set a
//! producer's `ts` to 0 (collides with the §2 per-page ts=0 boundary write →
//! entry forgery) or to `closing_ts` (sorts before the page closing read →
//! exit forgery), or to any in-range value.  This chip closes that gap with a
//! uniform 96-row PREPROCESSED period (mirroring blake2b's CallTs template):
//!
//!   * every call occupies exactly one 96-row block, point reads FIRST so the
//!     `ByteIdx == 0` row is real for both fixed- and variable-base calls
//!     (the "universal anchor");
//!   * `InitGate = is_real · IsByteIdx0_pp` is preprocessed-pinned, so its
//!     placement is not a free witness;
//!   * a prefix-monotonicity gate forces the real rows to a contiguous prefix
//!     so the ts-equality chain reaches every real row from `ByteIdx 0`;
//!   * the block consumes one `RistrettoCallLookupElements` (RELATION A) tuple
//!     at `InitGate`, balancing CpuChip's +1/ECALL-step producer — so the
//!     block's held `Ts` equals the chained CpuChip step Timestamp, which the
//!     ProgramBoundary chain pins to `[initial_ts, final_ts)` (excluding 0 and
//!     `closing_ts`);
//!   * each mem-op `Addr` is welded to the register-authenticated operand
//!     pointer + a per-byte no-wrap carry offset.
//!
//! For FIXED-BASE scalar_mult only the 32 point reads stay here; the scalar
//! reads / output writes are produced by `RistrettoCombScalarBoundaryChip` /
//! `RistrettoCombCompressOutputChip`.  Knowing `op.kind`, this chip re-emits
//! the already-anchored `ts` to those two chips via the `RistrettoFixedScalarTs`
//! / `RistrettoFixedOutTs` (Tier-2) producers, keyed on the authenticated
//! scalar / output pointer.

#[allow(unused_imports)]
use alloc::{boxed::Box, vec, vec::Vec};
use num_traits::One;
use stwo::core::fields::m31::BaseField;
#[cfg(feature = "prover")]
use stwo::{
    core::{ColumnVec, fields::qm31::SecureField},
    prover::{
        backend::simd::{SimdBackend, m31::LOG_N_LANES},
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
use crate::{
    framework::BuiltInComponent,
    lookups::{
        MemoryAccessLookupElements, RistrettoCallLookupElements, RistrettoFixedOutTsLookupElements,
        RistrettoFixedScalarTsLookupElements,
    },
};

pub struct RistrettoEcallChip;

/// Every ristretto-family call occupies one 96-row block: three 32-byte
/// sub-blocks (`ByteIdx` 0-31 / 32-63 / 64-95).
pub const ROWS_PER_CALL: usize = 96;

#[derive(Debug, Copy, Clone, AirColumn)]
pub enum Column {
    /// Memory address `active_ptr + offset` in 4 LE bytes.
    #[size = 4]
    Addr,
    /// Memory byte value at this address.
    #[size = 1]
    Value,
    /// Timestamp, 8 LE bytes.  Held constant across the 96-row block and
    /// pinned to the ECALL step ts via the RELATION-A consume at `InitGate`.
    #[size = 8]
    #[mask_next_row]
    Ts,
    /// 1 = write, 0 = read.  Pinned to the sub-block (`IsSub2_pp`).
    #[size = 1]
    IsWrite,
    /// 0 on padding rows.  Held to a contiguous prefix within each block.
    #[size = 1]
    #[mask_next_row]
    IsReal,
    /// `is_real · IsByteIdx0_pp` — the RELATION-A consume gate.  Preprocessed-
    /// pinned so its placement is not a free witness.
    #[size = 1]
    InitGate,
    /// `is_real · (1 − IsByteIdx95_pp)` — the held-constant / ts-equality gate.
    #[size = 1]
    HeldGate,
    /// `(1 − IsByteIdx95_pp) · (1 − is_real)` — the prefix-monotonicity gate.
    #[size = 1]
    PrefixMonoGate,
    /// `InitGate · IsFixedBase` — the Tier-2 producer gate.
    #[size = 1]
    FixedInitGate,
    /// Base pointer of sub-block 0 (ByteIdx 0-31), 4 LE bytes.  Held.
    #[size = 4]
    #[mask_next_row]
    Ptr0,
    /// Base pointer of sub-block 1 (ByteIdx 32-63), 4 LE bytes.  Held.
    #[size = 4]
    #[mask_next_row]
    Ptr1,
    /// Base pointer of sub-block 2 (ByteIdx 64-95), 4 LE bytes.  Held.
    #[size = 4]
    #[mask_next_row]
    Ptr2,
    /// One-hot id selectors (held across the block).  Exactly one is 1 on a
    /// real block; all 0 on trailing all-padding blocks.
    #[size = 1]
    #[mask_next_row]
    Is110,
    #[size = 1]
    #[mask_next_row]
    Is111,
    #[size = 1]
    #[mask_next_row]
    Is112,
    #[size = 1]
    #[mask_next_row]
    Is113,
    #[size = 1]
    #[mask_next_row]
    Is114,
    /// 1 iff this 110 block is a fixed-base scalar_mult (scalar reads + output
    /// writes are handled by the comb chips; only the 32 point reads are real
    /// here).  Held.
    #[size = 1]
    #[mask_next_row]
    IsFixedBase,
    /// `110·Is110 + … + 114·Is114` — the RELATION-A `id` limb.
    #[size = 1]
    Id,
    /// The active sub-block base pointer for this row
    /// (`IsSub0_pp·Ptr0 + IsSub1_pp·Ptr1 + IsSub2_pp·Ptr2`), 4 LE bytes.
    #[size = 4]
    RowPtr,
    /// The within-buffer byte offset for this row
    /// (`OffsetWithinSub_pp + 32·Is112·IsSub1_pp`).
    #[size = 1]
    RowOffset,
    /// Per-byte address-derivation carries (`Addr = RowPtr + RowOffset`, no
    /// 32-bit overflow so no field-wrap aliasing).
    #[size = 1]
    Carry0,
    #[size = 1]
    Carry1,
    #[size = 1]
    Carry2,
}

#[derive(Debug, Copy, Clone, PreprocessedAirColumn)]
#[preprocessed_prefix = "ristretto_ecall"]
pub enum PreprocessedColumn {
    /// 1 iff `r % 96 == 0` (block start / universal anchor row).
    #[size = 1]
    IsByteIdx0,
    /// 1 iff `r % 96 == 95` OR `r` is the final trace row.  Masks the held /
    /// prefix gates at every block boundary AND the cyclic last→row-0 wrap.
    #[size = 1]
    IsByteIdx95,
    /// 1 iff `r % 96 < 32` (sub-block 0).
    #[size = 1]
    IsSub0,
    /// 1 iff `32 <= r % 96 < 64` (sub-block 1).
    #[size = 1]
    IsSub1,
    /// 1 iff `64 <= r % 96 < 96` (sub-block 2 — output writes).  Doubles as
    /// the expected `IsWrite`.
    #[size = 1]
    IsSub2,
    /// `(r % 96) % 32` — the within-sub-block byte offset (0..31).
    #[size = 1]
    OffsetWithinSub,
}

/// Shared `IsByteIdx95` predicate: a block boundary OR the final trace row
/// (so the cyclic wrap never fires the held / prefix gates).
#[cfg(feature = "prover")]
#[inline]
fn is_byte_idx95(row: usize, num_rows: usize) -> bool {
    row % ROWS_PER_CALL == ROWS_PER_CALL - 1 || row + 1 == num_rows
}

impl BuiltInComponent for RistrettoEcallChip {
    type PreprocessedColumn = PreprocessedColumn;
    type MainColumn = Column;
    type LookupElements = (
        MemoryAccessLookupElements,
        RistrettoCallLookupElements,
        RistrettoFixedScalarTsLookupElements,
        RistrettoFixedOutTsLookupElements,
    );

    fn add_constraints<E: EvalAtRow>(
        &self,
        eval: &mut E,
        trace_eval: TraceEval<PreprocessedColumn, Column, E>,
        lookup_elements: &(
            MemoryAccessLookupElements,
            RistrettoCallLookupElements,
            RistrettoFixedScalarTsLookupElements,
            RistrettoFixedOutTsLookupElements,
        ),
    ) {
        let (mem_lookup, call_lookup, fixed_scalar_lookup, fixed_out_lookup) = lookup_elements;

        let addr = crate::trace::trace_eval!(trace_eval, Column::Addr);
        let value = crate::trace::trace_eval!(trace_eval, Column::Value);
        let ts = crate::trace::trace_eval!(trace_eval, Column::Ts);
        let is_write = crate::trace::trace_eval!(trace_eval, Column::IsWrite);
        let is_real = crate::trace::trace_eval!(trace_eval, Column::IsReal);
        let init_gate = crate::trace::trace_eval!(trace_eval, Column::InitGate);
        let held_gate = crate::trace::trace_eval!(trace_eval, Column::HeldGate);
        let prefix_mono_gate = crate::trace::trace_eval!(trace_eval, Column::PrefixMonoGate);
        let fixed_init_gate = crate::trace::trace_eval!(trace_eval, Column::FixedInitGate);
        let ptr0 = crate::trace::trace_eval!(trace_eval, Column::Ptr0);
        let ptr1 = crate::trace::trace_eval!(trace_eval, Column::Ptr1);
        let ptr2 = crate::trace::trace_eval!(trace_eval, Column::Ptr2);
        let is110 = crate::trace::trace_eval!(trace_eval, Column::Is110);
        let is111 = crate::trace::trace_eval!(trace_eval, Column::Is111);
        let is112 = crate::trace::trace_eval!(trace_eval, Column::Is112);
        let is113 = crate::trace::trace_eval!(trace_eval, Column::Is113);
        let is114 = crate::trace::trace_eval!(trace_eval, Column::Is114);
        let is_fixed = crate::trace::trace_eval!(trace_eval, Column::IsFixedBase);
        let id = crate::trace::trace_eval!(trace_eval, Column::Id);
        let row_ptr = crate::trace::trace_eval!(trace_eval, Column::RowPtr);
        let row_offset = crate::trace::trace_eval!(trace_eval, Column::RowOffset);
        let carry0 = crate::trace::trace_eval!(trace_eval, Column::Carry0);
        let carry1 = crate::trace::trace_eval!(trace_eval, Column::Carry1);
        let carry2 = crate::trace::trace_eval!(trace_eval, Column::Carry2);

        let is_byte0_pp =
            crate::trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::IsByteIdx0);
        let is_byte95_pp =
            crate::trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::IsByteIdx95);
        let is_sub0_pp =
            crate::trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::IsSub0);
        let is_sub1_pp =
            crate::trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::IsSub1);
        let is_sub2_pp =
            crate::trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::IsSub2);
        let offset_pp =
            crate::trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::OffsetWithinSub);

        let one = E::F::one();
        let f256 = E::F::from(BaseField::from(256u32));
        let f32 = E::F::from(BaseField::from(32u32));

        // ── (1) Booleans ──
        for b in [
            &is_real, &is_write, &is110, &is111, &is112, &is113, &is114, &is_fixed, &carry0,
            &carry1, &carry2,
        ] {
            eval.add_constraint(b[0].clone() * (one.clone() - b[0].clone()));
        }

        // ── (2) InitGate = is_real · IsByteIdx0_pp  (preprocessed-pinned) ──
        eval.add_constraint(init_gate[0].clone() - is_real[0].clone() * is_byte0_pp[0].clone());

        // ── HeldGate = is_real · (1 − IsByteIdx95_pp) ──
        eval.add_constraint(
            held_gate[0].clone() - is_real[0].clone() * (one.clone() - is_byte95_pp[0].clone()),
        );

        // ── PrefixMonoGate = (1 − IsByteIdx95_pp) · (1 − is_real) ──
        eval.add_constraint(
            prefix_mono_gate[0].clone()
                - (one.clone() - is_byte95_pp[0].clone()) * (one.clone() - is_real[0].clone()),
        );

        // ── FixedInitGate = InitGate · IsFixedBase ──
        eval.add_constraint(
            fixed_init_gate[0].clone() - init_gate[0].clone() * is_fixed[0].clone(),
        );

        // ── IsFixedBase only on a 110 block ──
        eval.add_constraint(is_fixed[0].clone() * (one.clone() - is110[0].clone()));

        // ── Id = 110·Is110 + … + 114·Is114 ──
        let id_expr = is110[0].clone() * E::F::from(BaseField::from(110u32))
            + is111[0].clone() * E::F::from(BaseField::from(111u32))
            + is112[0].clone() * E::F::from(BaseField::from(112u32))
            + is113[0].clone() * E::F::from(BaseField::from(113u32))
            + is114[0].clone() * E::F::from(BaseField::from(114u32));
        eval.add_constraint(id[0].clone() - id_expr);

        // ── (3) Prefix-monotonicity: a real row cannot follow a padding row
        // within a block, so real rows form a contiguous prefix from ByteIdx 0.
        let is_real_next = crate::trace::trace_eval_next_row!(trace_eval, Column::IsReal);
        eval.add_constraint(prefix_mono_gate[0].clone() * is_real_next[0].clone());

        // ── (4)/(5) ts-equality + ptr / id / kind held constant across the block ──
        let ts_next = crate::trace::trace_eval_next_row!(trace_eval, Column::Ts);
        let ptr0_next = crate::trace::trace_eval_next_row!(trace_eval, Column::Ptr0);
        let ptr1_next = crate::trace::trace_eval_next_row!(trace_eval, Column::Ptr1);
        let ptr2_next = crate::trace::trace_eval_next_row!(trace_eval, Column::Ptr2);
        let is110_next = crate::trace::trace_eval_next_row!(trace_eval, Column::Is110);
        let is111_next = crate::trace::trace_eval_next_row!(trace_eval, Column::Is111);
        let is112_next = crate::trace::trace_eval_next_row!(trace_eval, Column::Is112);
        let is113_next = crate::trace::trace_eval_next_row!(trace_eval, Column::Is113);
        let is114_next = crate::trace::trace_eval_next_row!(trace_eval, Column::Is114);
        let is_fixed_next = crate::trace::trace_eval_next_row!(trace_eval, Column::IsFixedBase);
        for i in 0..8 {
            eval.add_constraint(held_gate[0].clone() * (ts_next[i].clone() - ts[i].clone()));
        }
        for i in 0..4 {
            eval.add_constraint(held_gate[0].clone() * (ptr0_next[i].clone() - ptr0[i].clone()));
            eval.add_constraint(held_gate[0].clone() * (ptr1_next[i].clone() - ptr1[i].clone()));
            eval.add_constraint(held_gate[0].clone() * (ptr2_next[i].clone() - ptr2[i].clone()));
        }
        for (cur, nxt) in [
            (&is110, &is110_next),
            (&is111, &is111_next),
            (&is112, &is112_next),
            (&is113, &is113_next),
            (&is114, &is114_next),
            (&is_fixed, &is_fixed_next),
        ] {
            eval.add_constraint(held_gate[0].clone() * (nxt[0].clone() - cur[0].clone()));
        }

        // ── (6) is_write pinned to the sub-block ──
        eval.add_constraint(is_real[0].clone() * (is_write[0].clone() - is_sub2_pp[0].clone()));

        // ── RowPtr = IsSub0·Ptr0 + IsSub1·Ptr1 + IsSub2·Ptr2 (per byte) ──
        for i in 0..4 {
            eval.add_constraint(
                row_ptr[i].clone()
                    - is_sub0_pp[0].clone() * ptr0[i].clone()
                    - is_sub1_pp[0].clone() * ptr1[i].clone()
                    - is_sub2_pp[0].clone() * ptr2[i].clone(),
            );
        }

        // ── RowOffset = OffsetWithinSub_pp + 32·(Is112 · IsSub1_pp) ──
        // (reduce_wide's 64-byte input spans sub-blocks 0 and 1, so its
        // second half carries a +32 offset against the shared wide pointer.)
        eval.add_constraint(
            row_offset[0].clone()
                - offset_pp[0].clone()
                - f32.clone() * is112[0].clone() * is_sub1_pp[0].clone(),
        );

        // ── (7) Per-byte Addr authentication with a no-wrap carry ──
        // Addr = RowPtr + RowOffset as a true 32-bit sum (the final byte takes
        // no outgoing carry, so ptr+offset cannot field-wrap to an alias).
        eval.add_constraint(
            is_real[0].clone()
                * (addr[0].clone() + f256.clone() * carry0[0].clone()
                    - row_ptr[0].clone()
                    - row_offset[0].clone()),
        );
        eval.add_constraint(
            is_real[0].clone()
                * (addr[1].clone() + f256.clone() * carry1[0].clone()
                    - row_ptr[1].clone()
                    - carry0[0].clone()),
        );
        eval.add_constraint(
            is_real[0].clone()
                * (addr[2].clone() + f256.clone() * carry2[0].clone()
                    - row_ptr[2].clone()
                    - carry1[0].clone()),
        );
        eval.add_constraint(
            is_real[0].clone() * (addr[3].clone() - row_ptr[3].clone() - carry2[0].clone()),
        );

        // ── MemoryAccess producer: +is_real × (addr[4], value, ts[8], is_write, is_closing=0) ──
        let mut mem_tuple: Vec<E::F> = Vec::with_capacity(15);
        mem_tuple.extend_from_slice(&addr);
        mem_tuple.push(value[0].clone());
        mem_tuple.extend_from_slice(&ts);
        mem_tuple.push(is_write[0].clone());
        mem_tuple.push(E::F::from(BaseField::from(0u32))); // is_closing = 0
        eval.add_to_relation(RelationEntry::new(
            mem_lookup,
            is_real[0].clone().into(),
            &mem_tuple,
        ));

        // ── RELATION-A consumer: −InitGate × (id, ptr0[4], ptr1[4], ptr2[4], ts[8]) ──
        let mut call_tuple: Vec<E::F> = Vec::with_capacity(21);
        call_tuple.push(id[0].clone());
        call_tuple.extend_from_slice(&ptr0);
        call_tuple.extend_from_slice(&ptr1);
        call_tuple.extend_from_slice(&ptr2);
        call_tuple.extend_from_slice(&ts);
        eval.add_to_relation(RelationEntry::new(
            call_lookup,
            (-init_gate[0].clone()).into(),
            &call_tuple,
        ));

        // ── Tier-2 producers (fixed-base scalar_mult): re-emit the anchored
        // ts keyed on the authenticated scalar / output pointer.  For a 110
        // block the scalar buffer is sub-block 1 (Ptr1) and the output buffer
        // is sub-block 2 (Ptr2). ──
        let mut scalar_ts_tuple: Vec<E::F> = Vec::with_capacity(12);
        scalar_ts_tuple.extend_from_slice(&ptr1);
        scalar_ts_tuple.extend_from_slice(&ts);
        eval.add_to_relation(RelationEntry::new(
            fixed_scalar_lookup,
            fixed_init_gate[0].clone().into(),
            &scalar_ts_tuple,
        ));

        let mut out_ts_tuple: Vec<E::F> = Vec::with_capacity(12);
        out_ts_tuple.extend_from_slice(&ptr2);
        out_ts_tuple.extend_from_slice(&ts);
        eval.add_to_relation(RelationEntry::new(
            fixed_out_lookup,
            fixed_init_gate[0].clone().into(),
            &out_ts_tuple,
        ));

        eval.finalize_logup_in_pairs();
    }
}

/// A single ristretto-family call laid out as one 96-row block.
#[cfg(feature = "prover")]
struct CallBlock {
    id: u32,
    is_fixed: bool,
    /// Sub-block base pointers in trace-layout order (sub 0/1/2).
    ptr: [u32; 3],
    /// Sub-block byte payloads (sub 0/1/2).
    bytes: [[u8; 32]; 3],
    /// Which sub-blocks are real here (fixed-base 110 keeps only sub 0).
    real_sub: [bool; 3],
    ts: u64,
}

#[cfg(feature = "prover")]
fn collect_blocks(side_note: &SideNote) -> Vec<CallBlock> {
    use crate::core::ecall::{
        ECALL_RISTRETTO_POINT_ADD, ECALL_RISTRETTO_SCALAR_MULT,
        ECALL_SCALAR_FROM_BYTES_MOD_ORDER_WIDE,
    };
    use crate::core::tracing::ScalarMultKind;

    let mut out = Vec::new();
    // 110 scalar_mult: trace-layout sub0=point, sub1=scalar, sub2=output.
    for op in &side_note.ristretto_mem_ops {
        let is_fixed = op.kind == ScalarMultKind::FixedBasepoint;
        out.push(CallBlock {
            id: ECALL_RISTRETTO_SCALAR_MULT,
            is_fixed,
            ptr: [op.point_ptr, op.scalar_ptr, op.output_ptr],
            bytes: [op.point_bytes, op.scalar_bytes, op.out_bytes],
            // Fixed-base: only the 32 point reads stay here; the scalar reads
            // and output writes are produced by the comb chips.
            real_sub: [true, !is_fixed, !is_fixed],
            ts: op.ts,
        });
    }
    // 111 point_add: sub0=P, sub1=Q, sub2=output.
    for op in &side_note.ristretto_add_mem_ops {
        out.push(CallBlock {
            id: ECALL_RISTRETTO_POINT_ADD,
            is_fixed: false,
            ptr: [op.p_ptr, op.q_ptr, op.output_ptr],
            bytes: [op.p_bytes, op.q_bytes, op.out_bytes],
            real_sub: [true, true, true],
            ts: op.ts,
        });
    }
    // 112 reduce_wide: sub0=wide[0..32], sub1=wide[32..64] (same ptr), sub2=output.
    for op in &side_note.scalar_reduce_wide_mem_ops {
        let mut wide_lo = [0u8; 32];
        let mut wide_hi = [0u8; 32];
        wide_lo.copy_from_slice(&op.wide_bytes[0..32]);
        wide_hi.copy_from_slice(&op.wide_bytes[32..64]);
        out.push(CallBlock {
            id: ECALL_SCALAR_FROM_BYTES_MOD_ORDER_WIDE,
            is_fixed: false,
            ptr: [op.wide_ptr, op.wide_ptr, op.output_ptr],
            bytes: [wide_lo, wide_hi, op.out_bytes],
            real_sub: [true, true, true],
            ts: op.ts,
        });
    }
    // 113/114 binop: sub0=a, sub1=b, sub2=output.  op_id distinguishes the id.
    for op in &side_note.scalar_binop_mem_ops {
        out.push(CallBlock {
            id: op.op_id,
            is_fixed: false,
            ptr: [op.a_ptr, op.b_ptr, op.output_ptr],
            bytes: [op.a_bytes, op.b_bytes, op.out_bytes],
            real_sub: [true, true, true],
            ts: op.ts,
        });
    }
    out
}

#[cfg(feature = "prover")]
fn ristretto_ecall_log_size(side_note: &SideNote) -> u32 {
    let n_blocks = side_note.ristretto_mem_ops.len()
        + side_note.ristretto_add_mem_ops.len()
        + side_note.scalar_reduce_wide_mem_ops.len()
        + side_note.scalar_binop_mem_ops.len();
    let total = (n_blocks * ROWS_PER_CALL) as u32;
    // `n_blocks * 96` is never a power of two (96 = 2^5 · 3), so the trace is
    // always strictly larger than the real rows ⇒ ≥1 trailing padding row and
    // the final row is padding (the cyclic-wrap safety §4.1(8)).
    let log = 32u32 - total.saturating_sub(1).leading_zeros();
    log.max(LOG_N_LANES)
}

/// Compute `Addr = ptr + offset` as 4 LE bytes plus the three byte carries.
#[cfg(feature = "prover")]
fn addr_with_carries(ptr: u32, offset: u32) -> ([u8; 4], [u8; 3]) {
    let p = ptr.to_le_bytes();
    let s0 = p[0] as u32 + offset;
    let c0 = s0 >> 8;
    let s1 = p[1] as u32 + c0;
    let c1 = s1 >> 8;
    let s2 = p[2] as u32 + c1;
    let c2 = s2 >> 8;
    let a3 = (p[3] as u32).wrapping_add(c2) & 0xff;
    (
        [
            (s0 & 0xff) as u8,
            (s1 & 0xff) as u8,
            (s2 & 0xff) as u8,
            a3 as u8,
        ],
        [c0 as u8, c1 as u8, c2 as u8],
    )
}

#[cfg(feature = "prover")]
impl BuiltInProverComponent for RistrettoEcallChip {
    const IS_PRODUCER: bool = false;

    fn generate_preprocessed_trace(&self, log_size: u32, _side_note: &SideNote) -> FinalizedTrace {
        // Canonical-shape: use the (possibly forced) main-trace `log_size`
        // threaded by the erased layer. The 96-row period + the
        // `is_byte_idx95` final-row override are a pure function of
        // `log_size`, so the preprocessed columns are witness-independent.
        let mut trace = TraceBuilder::<PreprocessedColumn>::new(log_size);
        let num_rows = trace.num_rows();
        for row in 0..num_rows {
            let byte_idx = row % ROWS_PER_CALL;
            let sub = byte_idx / 32;
            trace.fill_columns(row, byte_idx == 0, PreprocessedColumn::IsByteIdx0);
            trace.fill_columns(
                row,
                is_byte_idx95(row, num_rows),
                PreprocessedColumn::IsByteIdx95,
            );
            trace.fill_columns(row, sub == 0, PreprocessedColumn::IsSub0);
            trace.fill_columns(row, sub == 1, PreprocessedColumn::IsSub1);
            trace.fill_columns(row, sub == 2, PreprocessedColumn::IsSub2);
            trace.fill_columns(
                row,
                (byte_idx % 32) as u8,
                PreprocessedColumn::OffsetWithinSub,
            );
        }
        trace.finalize_bit_reversed()
    }

    fn generate_main_trace_immut(&self, side_note: &SideNote) -> FinalizedTrace {
        self.generate_main_trace_immut_min(side_note, 0)
    }

    fn generate_main_trace_immut_min(
        &self,
        side_note: &SideNote,
        min_log_size: u32,
    ) -> FinalizedTrace {
        let log_size = ristretto_ecall_log_size(side_note).max(min_log_size);
        let mut trace = TraceBuilder::<Column>::new(log_size);
        let num_rows = trace.num_rows();
        let blocks = collect_blocks(side_note);

        for row in 0..num_rows {
            let byte_idx = row % ROWS_PER_CALL;
            let sub = byte_idx / 32;
            let off_in_sub = (byte_idx % 32) as u32;
            let block_idx = row / ROWS_PER_CALL;
            let is_byte95 = is_byte_idx95(row, num_rows);

            let block = blocks.get(block_idx);
            // Held columns + the per-row selection.
            let (ptr, id, is_fixed, real_sub, ts) = match block {
                Some(b) => (b.ptr, b.id, b.is_fixed, b.real_sub, b.ts),
                None => ([0u32; 3], 0u32, false, [false; 3], 0u64),
            };
            let is_real_row = real_sub[sub];

            // RowOffset = OffsetWithinSub + 32·(id==112 && sub==1).
            let row_offset = off_in_sub + if id == 112 && sub == 1 { 32 } else { 0 };
            // RowPtr = the active sub-block base pointer (0 on all-padding rows).
            let row_ptr = ptr[sub];

            // Held columns — filled on every row of the block.
            trace.fill_columns_bytes(row, &ptr[0].to_le_bytes(), Column::Ptr0);
            trace.fill_columns_bytes(row, &ptr[1].to_le_bytes(), Column::Ptr1);
            trace.fill_columns_bytes(row, &ptr[2].to_le_bytes(), Column::Ptr2);
            trace.fill_columns(row, (id == 110) as u8, Column::Is110);
            trace.fill_columns(row, (id == 111) as u8, Column::Is111);
            trace.fill_columns(row, (id == 112) as u8, Column::Is112);
            trace.fill_columns(row, (id == 113) as u8, Column::Is113);
            trace.fill_columns(row, (id == 114) as u8, Column::Is114);
            trace.fill_columns(row, is_fixed as u8, Column::IsFixedBase);
            trace.fill_columns(row, id as u8, Column::Id);
            trace.fill_columns_bytes(row, &ts.to_le_bytes(), Column::Ts);

            // RowPtr / RowOffset — constrained on every row.
            trace.fill_columns_bytes(row, &row_ptr.to_le_bytes(), Column::RowPtr);
            trace.fill_columns(row, row_offset as u8, Column::RowOffset);

            // Gates.
            let init_gate = is_real_row && byte_idx == 0;
            let held_gate = is_real_row && !is_byte95;
            let prefix_mono_gate = !is_byte95 && !is_real_row;
            let fixed_init_gate = init_gate && is_fixed;
            trace.fill_columns(row, init_gate, Column::InitGate);
            trace.fill_columns(row, held_gate, Column::HeldGate);
            trace.fill_columns(row, prefix_mono_gate, Column::PrefixMonoGate);
            trace.fill_columns(row, fixed_init_gate, Column::FixedInitGate);

            // is_write follows the sub-block on every row (the pin is gated by
            // is_real, but matching it everywhere keeps padding rows tidy).
            trace.fill_columns(row, (sub == 2) as u8, Column::IsWrite);

            if is_real_row {
                let (addr_bytes, carries) = addr_with_carries(row_ptr, row_offset);
                trace.fill_columns_bytes(row, &addr_bytes, Column::Addr);
                let value = block
                    .map(|b| b.bytes[sub][off_in_sub as usize])
                    .unwrap_or(0);
                trace.fill_columns(row, value, Column::Value);
                trace.fill_columns(row, 1u8, Column::IsReal);
                trace.fill_columns(row, carries[0], Column::Carry0);
                trace.fill_columns(row, carries[1], Column::Carry1);
                trace.fill_columns(row, carries[2], Column::Carry2);
            }
            // Padding rows: Addr/Value/IsReal/Carry default to 0.
        }
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

        let mem_lookup: &MemoryAccessLookupElements = lookup_elements.as_ref();
        let call_lookup: &RistrettoCallLookupElements = lookup_elements.as_ref();
        let fixed_scalar_lookup: &RistrettoFixedScalarTsLookupElements = lookup_elements.as_ref();
        let fixed_out_lookup: &RistrettoFixedOutTsLookupElements = lookup_elements.as_ref();

        let addr = crate::trace::original_base_column!(component_trace, Column::Addr);
        let value = crate::trace::original_base_column!(component_trace, Column::Value);
        let ts = crate::trace::original_base_column!(component_trace, Column::Ts);
        let is_write = crate::trace::original_base_column!(component_trace, Column::IsWrite);
        let is_real = crate::trace::original_base_column!(component_trace, Column::IsReal);
        let init_gate = crate::trace::original_base_column!(component_trace, Column::InitGate);
        let fixed_init_gate =
            crate::trace::original_base_column!(component_trace, Column::FixedInitGate);
        let ptr0 = crate::trace::original_base_column!(component_trace, Column::Ptr0);
        let ptr1 = crate::trace::original_base_column!(component_trace, Column::Ptr1);
        let ptr2 = crate::trace::original_base_column!(component_trace, Column::Ptr2);
        let id = crate::trace::original_base_column!(component_trace, Column::Id);

        use crate::trace::component::FinalizedColumn;

        // ── MemoryAccess producer (+is_real) ──
        let mut mem_tuple: Vec<FinalizedColumn<'_>> = addr.to_vec();
        mem_tuple.push(value[0].clone());
        mem_tuple.extend(ts.iter().cloned());
        mem_tuple.push(is_write[0].clone());
        mem_tuple.push(FinalizedColumn::Constant(BaseField::from(0u32))); // is_closing = 0
        logup.add_to_relation_with(mem_lookup, [is_real[0].clone()], |[r]| r.into(), &mem_tuple);

        // ── RELATION-A consumer (−InitGate) ──
        let mut call_tuple: Vec<FinalizedColumn<'_>> = Vec::with_capacity(21);
        call_tuple.push(id[0].clone());
        call_tuple.extend(ptr0.iter().cloned());
        call_tuple.extend(ptr1.iter().cloned());
        call_tuple.extend(ptr2.iter().cloned());
        call_tuple.extend(ts.iter().cloned());
        logup.add_to_relation_with(
            call_lookup,
            [init_gate[0].clone()],
            |[g]| (-g).into(),
            &call_tuple,
        );

        // ── Tier-2 scalar producer (+FixedInitGate) ──
        let mut scalar_ts_tuple: Vec<FinalizedColumn<'_>> = Vec::with_capacity(12);
        scalar_ts_tuple.extend(ptr1.iter().cloned());
        scalar_ts_tuple.extend(ts.iter().cloned());
        logup.add_to_relation_with(
            fixed_scalar_lookup,
            [fixed_init_gate[0].clone()],
            |[g]| g.into(),
            &scalar_ts_tuple,
        );

        // ── Tier-2 output producer (+FixedInitGate) ──
        let mut out_ts_tuple: Vec<FinalizedColumn<'_>> = Vec::with_capacity(12);
        out_ts_tuple.extend(ptr2.iter().cloned());
        out_ts_tuple.extend(ts.iter().cloned());
        logup.add_to_relation_with(
            fixed_out_lookup,
            [fixed_init_gate[0].clone()],
            |[g]| g.into(),
            &out_ts_tuple,
        );

        logup.finalize()
    }
}
