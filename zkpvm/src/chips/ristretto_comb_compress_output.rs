//! RistrettoCombCompressOutputChip — fixed-base scalar_mult output writes.
//!
//! Per fixed-base scalar mult call, 32 rows are emitted (one per output byte).
//! Each row:
//!
//!   - **Consumes** the corresponding byte of canonical s_can from
//!     `RistrettoCombCompressChip`'s row +43 via the
//!     `RistrettoCombCompressOutputLookupElements` boundary relation
//!     (multiplicity `-IsReal` × tuple `(CallIdx, ByteIdx, Value)`).
//!   - **Produces** a `MemoryAccessLookupElements` tuple at the actor's
//!     `(output_ptr + byte_idx, value, ts, is_write=1)` address (`+IsReal`).
//!
//! Timestamp / address binding (Phase A prereq 0.2).  `Ts` and `Addr` used to
//! be free witnesses (the ts-forgery gap).  This chip now consumes one
//! `RistrettoFixedOutTs` (Tier-2) tuple at the block's first row, balancing the
//! `RistrettoEcallChip` producer that re-emits the already-anchored ECALL ts
//! keyed on the register-authenticated `output_ptr`.  Intra-call ts-equality
//! and output-ptr-equality propagate that anchored ts + authenticated pointer
//! across the 32-row block, and `Addr = output_ptr + ByteIdx` (per-byte no-wrap
//! carry) welds every write address to the authenticated pointer.

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

use crate::framework::BuiltInComponent;
#[cfg(feature = "prover")]
use crate::framework::BuiltInProverComponent;
#[cfg(feature = "prover")]
use crate::lookups::{AllLookupElements, LogupTraceBuilder};
use crate::lookups::{
    MemoryAccessLookupElements, RistrettoCombCompressOutputLookupElements,
    RistrettoFixedOutTsLookupElements,
};
#[cfg(feature = "prover")]
use crate::side_note::SideNote;

pub struct RistrettoCombCompressOutputChip;

/// 32 rows per fixed-base scalar mult call (one per output byte).
pub const ROWS_PER_CALL: usize = 32;

#[derive(Debug, Copy, Clone, AirColumn)]
pub enum Column {
    /// 1 on real rows; 0 on padding.
    #[size = 1]
    IsReal,
    /// PVM memory address `output_ptr + byte_idx` in 4 LE bytes.
    #[size = 4]
    Addr,
    /// The byte value being written — bound to compress chip's
    /// row +43 byte at `(CallIdx, ByteIdx)` via the output relation.
    #[size = 1]
    Value,
    /// ECALL step timestamp, 8 LE bytes.  Held across the block and pinned to
    /// the anchored ECALL ts by the Tier-2 consume at the block's first row.
    #[size = 8]
    #[mask_next_row]
    Ts,
    /// Register-authenticated `output_ptr` (4 LE bytes), held across the block.
    /// Pinned by the Tier-2 consume; `Addr = OutPtr + ByteIdx`.
    #[size = 4]
    #[mask_next_row]
    OutPtr,
    /// `is_real · IsByteIdx0_pp` — the Tier-2 consume gate (block first row).
    #[size = 1]
    FirstRowGate,
    /// `is_real · (1 − IsLast_pp)` — the ts / ptr held-constant gate.
    #[size = 1]
    HeldGate,
    /// Per-byte `Addr = OutPtr + ByteIdx` carries.
    #[size = 1]
    Carry0,
    #[size = 1]
    Carry1,
    #[size = 1]
    Carry2,
}

#[derive(Debug, Copy, Clone, PreprocessedAirColumn)]
#[preprocessed_prefix = "ristretto_comb_compress_output"]
pub enum PreprocessedColumn {
    /// `CallIdx[r] = floor(r / 32)` on real rows; 0 on padding.
    #[size = 1]
    CallIdx,
    /// `ByteIdx[r] = r mod 32`.  Drives both the output-relation tuple AND the
    /// per-byte address offset (`Addr = output_ptr + ByteIdx`).
    #[size = 1]
    ByteIdx,
    /// 1 iff `r % 32 == 0` (block first row — the Tier-2 consume / anchor row).
    #[size = 1]
    IsByteIdx0,
    /// 1 iff `r % 32 == 31` (block last row — masks the held gate at the block
    /// boundary and the cyclic wrap).
    #[size = 1]
    IsLast,
}

impl BuiltInComponent for RistrettoCombCompressOutputChip {
    type PreprocessedColumn = PreprocessedColumn;
    type MainColumn = Column;
    type LookupElements = (
        MemoryAccessLookupElements,
        RistrettoCombCompressOutputLookupElements,
        RistrettoFixedOutTsLookupElements,
    );

    fn add_constraints<E: EvalAtRow>(
        &self,
        eval: &mut E,
        trace_eval: TraceEval<PreprocessedColumn, Column, E>,
        lookup_elements: &(
            MemoryAccessLookupElements,
            RistrettoCombCompressOutputLookupElements,
            RistrettoFixedOutTsLookupElements,
        ),
    ) {
        let (memory_lookup, output_lookup, fixed_out_lookup) = lookup_elements;

        let is_real = crate::trace::trace_eval!(trace_eval, Column::IsReal);
        let addr = crate::trace::trace_eval!(trace_eval, Column::Addr);
        let value = crate::trace::trace_eval!(trace_eval, Column::Value);
        let ts = crate::trace::trace_eval!(trace_eval, Column::Ts);
        let out_ptr = crate::trace::trace_eval!(trace_eval, Column::OutPtr);
        let first_row_gate = crate::trace::trace_eval!(trace_eval, Column::FirstRowGate);
        let held_gate = crate::trace::trace_eval!(trace_eval, Column::HeldGate);
        let carry0 = crate::trace::trace_eval!(trace_eval, Column::Carry0);
        let carry1 = crate::trace::trace_eval!(trace_eval, Column::Carry1);
        let carry2 = crate::trace::trace_eval!(trace_eval, Column::Carry2);
        let call_idx_pp =
            crate::trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::CallIdx);
        let byte_idx_pp =
            crate::trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::ByteIdx);
        let is_byte0_pp =
            crate::trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::IsByteIdx0);
        let is_last_pp =
            crate::trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::IsLast);

        let one = E::F::one();
        let f256 = E::F::from(BaseField::from(256u32));

        // Booleans.
        for b in [&is_real, &carry0, &carry1, &carry2] {
            eval.add_constraint(b[0].clone() * (one.clone() - b[0].clone()));
        }

        // Gate definitions (degree-2 helpers).
        eval.add_constraint(
            first_row_gate[0].clone() - is_real[0].clone() * is_byte0_pp[0].clone(),
        );
        eval.add_constraint(
            held_gate[0].clone() - is_real[0].clone() * (one.clone() - is_last_pp[0].clone()),
        );

        // Intra-call ts-equality + output-ptr-equality.
        let ts_next = crate::trace::trace_eval_next_row!(trace_eval, Column::Ts);
        let out_ptr_next = crate::trace::trace_eval_next_row!(trace_eval, Column::OutPtr);
        for i in 0..8 {
            eval.add_constraint(held_gate[0].clone() * (ts_next[i].clone() - ts[i].clone()));
        }
        for i in 0..4 {
            eval.add_constraint(
                held_gate[0].clone() * (out_ptr_next[i].clone() - out_ptr[i].clone()),
            );
        }

        // ── Addr = OutPtr + ByteIdx (per-byte no-wrap carry) ──
        eval.add_constraint(
            is_real[0].clone()
                * (addr[0].clone() + f256.clone() * carry0[0].clone()
                    - out_ptr[0].clone()
                    - byte_idx_pp[0].clone()),
        );
        eval.add_constraint(
            is_real[0].clone()
                * (addr[1].clone() + f256.clone() * carry1[0].clone()
                    - out_ptr[1].clone()
                    - carry0[0].clone()),
        );
        eval.add_constraint(
            is_real[0].clone()
                * (addr[2].clone() + f256.clone() * carry2[0].clone()
                    - out_ptr[2].clone()
                    - carry1[0].clone()),
        );
        eval.add_constraint(
            is_real[0].clone() * (addr[3].clone() - out_ptr[3].clone() - carry2[0].clone()),
        );

        // ── Relation emissions (all add_constraint above must precede the
        // first add_to_relation, so a failing constraint in a single-chip
        // debug-assert panics before any LogupAtRow is opened). ──

        // ── Tier-2 consumer: −FirstRowGate × (output_ptr[4], ts[8]) ──
        // Balances RistrettoEcallChip's +InitGate·IsFixedBase producer, forcing
        // OutPtr == authenticated output_ptr and Ts == the anchored ECALL ts.
        let mut fixed_tuple: Vec<E::F> = Vec::with_capacity(12);
        fixed_tuple.extend_from_slice(&out_ptr);
        fixed_tuple.extend_from_slice(&ts);
        eval.add_to_relation(RelationEntry::new(
            fixed_out_lookup,
            (-first_row_gate[0].clone()).into(),
            &fixed_tuple,
        ));

        // ── Output-relation consumer: −IsReal × (CallIdx, ByteIdx, Value) ──
        eval.add_to_relation(RelationEntry::new(
            output_lookup,
            (-is_real[0].clone()).into(),
            &[
                call_idx_pp[0].clone(),
                byte_idx_pp[0].clone(),
                value[0].clone(),
            ],
        ));

        // ── MemoryAccess producer: +IsReal × (Addr, Value, Ts, is_write=1, is_closing=0) ──
        let mut tuple: Vec<E::F> = Vec::with_capacity(15);
        tuple.extend_from_slice(&addr);
        tuple.push(value[0].clone());
        tuple.extend_from_slice(&ts);
        tuple.push(one);
        tuple.push(E::F::from(BaseField::from(0u32))); // is_closing = 0
        eval.add_to_relation(RelationEntry::new(
            memory_lookup,
            is_real[0].clone().into(),
            &tuple,
        ));

        eval.finalize_logup_in_pairs();
    }
}

#[cfg(feature = "prover")]
fn output_log_size(side_note: &SideNote) -> u32 {
    let n_rows = side_note.ristretto_comb_calls.len() * ROWS_PER_CALL;
    log_size_for(n_rows)
}

#[cfg(feature = "prover")]
fn log_size_for(n_rows: usize) -> u32 {
    if n_rows <= 1 {
        return LOG_N_LANES;
    }
    let n = n_rows as u32;
    let log = 32 - (n - 1).leading_zeros();
    log.max(LOG_N_LANES)
}

/// `Addr = ptr + offset` (offset ≤ 31) as 4 LE bytes plus 3 byte carries.
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
impl BuiltInProverComponent for RistrettoCombCompressOutputChip {
    const IS_PRODUCER: bool = false;

    fn generate_preprocessed_trace(&self, _log_size: u32, side_note: &SideNote) -> FinalizedTrace {
        let log_size = output_log_size(side_note);
        let mut trace = TraceBuilder::<PreprocessedColumn>::new(log_size);
        let num_rows = trace.num_rows();
        for row in 0..num_rows {
            let call_idx = (row / ROWS_PER_CALL) as u8;
            let byte_idx = (row % ROWS_PER_CALL) as u8;
            trace.fill_columns(row, call_idx, PreprocessedColumn::CallIdx);
            trace.fill_columns(row, byte_idx, PreprocessedColumn::ByteIdx);
            trace.fill_columns(row, byte_idx == 0, PreprocessedColumn::IsByteIdx0);
            trace.fill_columns(
                row,
                byte_idx as usize == ROWS_PER_CALL - 1,
                PreprocessedColumn::IsLast,
            );
        }
        trace.finalize_bit_reversed()
    }

    fn generate_main_trace_immut(&self, side_note: &SideNote) -> FinalizedTrace {
        let log_size = output_log_size(side_note);
        let mut trace = TraceBuilder::<Column>::new(log_size);
        let mut row = 0usize;
        for call in side_note.ristretto_comb_calls.iter() {
            let ts_bytes = call.ts.to_le_bytes();
            let out_ptr_bytes = call.output_ptr.to_le_bytes();
            for byte_idx in 0..ROWS_PER_CALL {
                let (addr_bytes, carries) = addr_with_carries(call.output_ptr, byte_idx as u32);
                let value = call.out_bytes[byte_idx];
                trace.fill_columns(row, 1u8, Column::IsReal);
                trace.fill_columns_bytes(row, &addr_bytes, Column::Addr);
                trace.fill_columns(row, value, Column::Value);
                trace.fill_columns_bytes(row, &ts_bytes, Column::Ts);
                trace.fill_columns_bytes(row, &out_ptr_bytes, Column::OutPtr);
                trace.fill_columns(row, (byte_idx == 0) as u8, Column::FirstRowGate);
                trace.fill_columns(row, (byte_idx != ROWS_PER_CALL - 1) as u8, Column::HeldGate);
                trace.fill_columns(row, carries[0], Column::Carry0);
                trace.fill_columns(row, carries[1], Column::Carry1);
                trace.fill_columns(row, carries[2], Column::Carry2);
                row += 1;
            }
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

        let memory: &MemoryAccessLookupElements = lookup_elements.as_ref();
        let output_relation: &RistrettoCombCompressOutputLookupElements = lookup_elements.as_ref();
        let fixed_out: &RistrettoFixedOutTsLookupElements = lookup_elements.as_ref();

        let is_real = crate::trace::original_base_column!(component_trace, Column::IsReal);
        let addr = crate::trace::original_base_column!(component_trace, Column::Addr);
        let value = crate::trace::original_base_column!(component_trace, Column::Value);
        let ts = crate::trace::original_base_column!(component_trace, Column::Ts);
        let out_ptr = crate::trace::original_base_column!(component_trace, Column::OutPtr);
        let first_row_gate =
            crate::trace::original_base_column!(component_trace, Column::FirstRowGate);
        let call_idx_pp =
            crate::trace::preprocessed_base_column!(component_trace, PreprocessedColumn::CallIdx);
        let byte_idx_pp =
            crate::trace::preprocessed_base_column!(component_trace, PreprocessedColumn::ByteIdx);

        use crate::trace::component::FinalizedColumn;
        use stwo::core::fields::m31::BaseField as BF;
        let one_col: FinalizedColumn<'_> = BF::from(1u32).into();

        // Tier-2 consumer (−FirstRowGate).
        let mut fixed_tuple: Vec<FinalizedColumn<'_>> = Vec::with_capacity(12);
        fixed_tuple.extend(out_ptr.iter().cloned());
        fixed_tuple.extend(ts.iter().cloned());
        logup.add_to_relation_with(
            fixed_out,
            [first_row_gate[0].clone()],
            |[g]| (-g).into(),
            &fixed_tuple,
        );

        // Output-relation consumer (-IsReal).
        logup.add_to_relation_with(
            output_relation,
            [is_real[0].clone()],
            |[r]| (-r).into(),
            &[
                call_idx_pp[0].clone(),
                byte_idx_pp[0].clone(),
                value[0].clone(),
            ],
        );

        // MemoryAccess producer (+IsReal).
        let mut tuple: Vec<FinalizedColumn<'_>> = Vec::with_capacity(15);
        tuple.extend(addr.iter().cloned());
        tuple.push(value[0].clone());
        tuple.extend(ts.iter().cloned());
        tuple.push(one_col);
        tuple.push(FinalizedColumn::Constant(BaseField::from(0u32))); // is_closing = 0
        logup.add_to_relation_with(memory, [is_real[0].clone()], |[r]| r.into(), &tuple);

        logup.finalize()
    }
}
