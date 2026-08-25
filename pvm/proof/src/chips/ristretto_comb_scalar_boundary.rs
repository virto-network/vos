//! RistrettoCombScalarBoundaryChip — fixed-base scalar_mult scalar reads.
//!
//! Closes two soundness gaps in one place:
//!  1. Binds the comb-anchor chip's per-window `ScalarWindow` values to the
//!     actor's input scalar bytes (via the
//!     `RistrettoCombScalarBoundaryLookupElements` 3-limb relation).
//!  2. Pins those scalar bytes to PVM memory by emitting standard
//!     `MemoryAccessLookupElements` producers.
//!
//! Per fixed-basepoint scalar mult call, the chip lays out 32 rows (one per
//! scalar byte).  Each row carries `IsReal`, the call's `CallIdx`, the two
//! 4-bit windows `LowNibble`/`HighNibble`, the `ScalarByte`, the address
//! `Addr` and timestamp `Ts`.
//!
//! Timestamp / address binding.  `Ts` and `Addr` are welded to the anchored
//! ECALL ts and register-authenticated pointer rather than free witnesses
//! (closing the ts-forgery gap).  This chip consumes one
//! `RistrettoFixedScalarTs` (Tier-2) tuple at the block's first row, balancing
//! the `RistrettoEcallChip` producer that re-emits the already-anchored ECALL
//! ts keyed on the register-authenticated `scalar_ptr`.  Intra-call ts-equality
//! and scalar-ptr-equality propagate that anchored ts + authenticated pointer
//! across the 32-row block, and `Addr = scalar_ptr + ByteIdx` (per-byte no-wrap
//! carry) welds every read address to the authenticated pointer.

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
        MemoryAccessLookupElements, RistrettoCombScalarBoundaryLookupElements,
        RistrettoFixedScalarTsLookupElements,
    },
};

pub struct RistrettoCombScalarBoundaryChip;

/// 32 scalar bytes per fixed-base scalar mult call.
pub const ROWS_PER_CALL: usize = 32;

#[derive(Debug, Copy, Clone, AirColumn)]
pub enum Column {
    /// 1 if this row witnesses an actual scalar byte; 0 if padding.
    #[size = 1]
    IsReal,
    /// Index of the scalar-mult call in `ristretto_comb_calls`.
    #[size = 1]
    CallIdx,
    /// Low 4-bit window of `ScalarByte` (`scalar[byte_idx] & 0x0F`).
    #[size = 1]
    LowNibble,
    /// High 4-bit window of `ScalarByte` (`scalar[byte_idx] >> 4`).
    #[size = 1]
    HighNibble,
    /// The scalar byte itself.
    #[size = 1]
    ScalarByte,
    /// Address `scalar_ptr + byte_idx` in 4 LE bytes.
    #[size = 4]
    Addr,
    /// ECALL step timestamp, 8 LE bytes.  Held across the block and pinned to
    /// the anchored ECALL ts by the Tier-2 consume at the block's first row.
    #[size = 8]
    #[mask_next_row]
    Ts,
    /// Register-authenticated `scalar_ptr` (4 LE bytes), held across the block.
    /// Pinned by the Tier-2 consume; `Addr = ScalarPtr + ByteIdx`.
    #[size = 4]
    #[mask_next_row]
    ScalarPtr,
    /// `is_real · IsByteIdx0_pp` — the Tier-2 consume gate (block first row).
    #[size = 1]
    FirstRowGate,
    /// `is_real · (1 − IsLast_pp)` — the ts / ptr held-constant gate.
    #[size = 1]
    HeldGate,
    /// Per-byte `Addr = ScalarPtr + ByteIdx` carries.
    #[size = 1]
    Carry0,
    #[size = 1]
    Carry1,
    #[size = 1]
    Carry2,
}

#[derive(Debug, Copy, Clone, PreprocessedAirColumn)]
#[preprocessed_prefix = "ristretto_comb_scalar_boundary"]
pub enum PreprocessedColumn {
    /// `WindowEven[row] = 2 * (row mod 32)` — even window index (low nibble).
    #[size = 1]
    WindowEven,
    /// `WindowOdd[row] = 2 * (row mod 32) + 1` — odd window index (high nibble).
    #[size = 1]
    WindowOdd,
    /// `ByteIdx[row] = row mod 32` — the per-byte address offset.
    #[size = 1]
    ByteIdx,
    /// 1 iff `row % 32 == 0` (block first row — the Tier-2 consume / anchor).
    #[size = 1]
    IsByteIdx0,
    /// 1 iff `row % 32 == 31` (block last row — masks the held gate).
    #[size = 1]
    IsLast,
}

impl BuiltInComponent for RistrettoCombScalarBoundaryChip {
    type PreprocessedColumn = PreprocessedColumn;
    type MainColumn = Column;
    type LookupElements = (
        RistrettoCombScalarBoundaryLookupElements,
        MemoryAccessLookupElements,
        RistrettoFixedScalarTsLookupElements,
    );

    fn add_constraints<E: EvalAtRow>(
        &self,
        eval: &mut E,
        trace_eval: TraceEval<PreprocessedColumn, Column, E>,
        lookup_elements: &(
            RistrettoCombScalarBoundaryLookupElements,
            MemoryAccessLookupElements,
            RistrettoFixedScalarTsLookupElements,
        ),
    ) {
        let (scalar_lookup, memory_lookup, fixed_scalar_lookup) = lookup_elements;

        let is_real = crate::trace::trace_eval!(trace_eval, Column::IsReal);
        let call_idx = crate::trace::trace_eval!(trace_eval, Column::CallIdx);
        let low_nibble = crate::trace::trace_eval!(trace_eval, Column::LowNibble);
        let high_nibble = crate::trace::trace_eval!(trace_eval, Column::HighNibble);
        let scalar_byte = crate::trace::trace_eval!(trace_eval, Column::ScalarByte);
        let addr = crate::trace::trace_eval!(trace_eval, Column::Addr);
        let ts = crate::trace::trace_eval!(trace_eval, Column::Ts);
        let scalar_ptr = crate::trace::trace_eval!(trace_eval, Column::ScalarPtr);
        let first_row_gate = crate::trace::trace_eval!(trace_eval, Column::FirstRowGate);
        let held_gate = crate::trace::trace_eval!(trace_eval, Column::HeldGate);
        let carry0 = crate::trace::trace_eval!(trace_eval, Column::Carry0);
        let carry1 = crate::trace::trace_eval!(trace_eval, Column::Carry1);
        let carry2 = crate::trace::trace_eval!(trace_eval, Column::Carry2);
        let win_even =
            crate::trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::WindowEven);
        let win_odd =
            crate::trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::WindowOdd);
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

        // ScalarByte = LowNibble + 16·HighNibble (gated by is_real).
        let f16 = E::F::from(BaseField::from(16u32));
        eval.add_constraint(
            is_real[0].clone()
                * (scalar_byte[0].clone() - low_nibble[0].clone() - f16 * high_nibble[0].clone()),
        );

        // Gate definitions.
        eval.add_constraint(
            first_row_gate[0].clone() - is_real[0].clone() * is_byte0_pp[0].clone(),
        );
        eval.add_constraint(
            held_gate[0].clone() - is_real[0].clone() * (one.clone() - is_last_pp[0].clone()),
        );

        // Intra-call ts-equality + scalar-ptr-equality.
        let ts_next = crate::trace::trace_eval_next_row!(trace_eval, Column::Ts);
        let scalar_ptr_next = crate::trace::trace_eval_next_row!(trace_eval, Column::ScalarPtr);
        for i in 0..8 {
            eval.add_constraint(held_gate[0].clone() * (ts_next[i].clone() - ts[i].clone()));
        }
        for i in 0..4 {
            eval.add_constraint(
                held_gate[0].clone() * (scalar_ptr_next[i].clone() - scalar_ptr[i].clone()),
            );
        }

        // ── Addr = ScalarPtr + ByteIdx (per-byte no-wrap carry) ──
        eval.add_constraint(
            is_real[0].clone()
                * (addr[0].clone() + f256.clone() * carry0[0].clone()
                    - scalar_ptr[0].clone()
                    - byte_idx_pp[0].clone()),
        );
        eval.add_constraint(
            is_real[0].clone()
                * (addr[1].clone() + f256.clone() * carry1[0].clone()
                    - scalar_ptr[1].clone()
                    - carry0[0].clone()),
        );
        eval.add_constraint(
            is_real[0].clone()
                * (addr[2].clone() + f256.clone() * carry2[0].clone()
                    - scalar_ptr[2].clone()
                    - carry1[0].clone()),
        );
        eval.add_constraint(
            is_real[0].clone() * (addr[3].clone() - scalar_ptr[3].clone() - carry2[0].clone()),
        );

        // ── Relation emissions (all add_constraint above must precede the
        // first add_to_relation, so a failing constraint in a single-chip
        // debug-assert panics before any LogupAtRow is opened). ──

        // ── Tier-2 consumer: −FirstRowGate × (scalar_ptr[4], ts[8]) ──
        let mut fixed_tuple: Vec<E::F> = Vec::with_capacity(12);
        fixed_tuple.extend_from_slice(&scalar_ptr);
        fixed_tuple.extend_from_slice(&ts);
        eval.add_to_relation(RelationEntry::new(
            fixed_scalar_lookup,
            (-first_row_gate[0].clone()).into(),
            &fixed_tuple,
        ));

        // ── Scalar-boundary emissions (low + high nibble) ──
        eval.add_to_relation(RelationEntry::new(
            scalar_lookup,
            (-is_real[0].clone()).into(),
            &[
                call_idx[0].clone(),
                win_even[0].clone(),
                low_nibble[0].clone(),
            ],
        ));
        eval.add_to_relation(RelationEntry::new(
            scalar_lookup,
            (-is_real[0].clone()).into(),
            &[
                call_idx[0].clone(),
                win_odd[0].clone(),
                high_nibble[0].clone(),
            ],
        ));

        // ── Memory ledger producer: +is_real × (addr[4], scalar_byte, ts[8], is_write=0, is_closing=0) ──
        let zero = E::F::from(BaseField::from(0u32));
        let mut tuple: Vec<E::F> = Vec::with_capacity(15);
        tuple.extend_from_slice(&addr);
        tuple.push(scalar_byte[0].clone());
        tuple.extend_from_slice(&ts);
        tuple.push(zero.clone()); // is_write = 0
        tuple.push(zero); // is_closing = 0
        eval.add_to_relation(RelationEntry::new(
            memory_lookup,
            is_real[0].clone().into(),
            &tuple,
        ));

        eval.finalize_logup_in_pairs();
    }
}

#[cfg(feature = "prover")]
impl BuiltInProverComponent for RistrettoCombScalarBoundaryChip {
    const IS_PRODUCER: bool = false;

    fn generate_preprocessed_trace(&self, log_size: u32, _side_note: &SideNote) -> FinalizedTrace {
        // Canonical-shape: use the (possibly forced) main-trace `log_size`.
        // WindowEven/Odd/ByteIdx/IsByteIdx0/IsLast are pure-positional
        // (row % ROWS_PER_CALL) ⇒ witness-independent preprocessed trace.
        let mut trace = TraceBuilder::<PreprocessedColumn>::new(log_size);
        let num_rows = trace.num_rows();
        for row in 0..num_rows {
            let byte_idx = (row % ROWS_PER_CALL) as u32;
            trace.fill_columns(
                row,
                BaseField::from(2 * byte_idx),
                PreprocessedColumn::WindowEven,
            );
            trace.fill_columns(
                row,
                BaseField::from(2 * byte_idx + 1),
                PreprocessedColumn::WindowOdd,
            );
            trace.fill_columns(row, byte_idx as u8, PreprocessedColumn::ByteIdx);
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
        self.generate_main_trace_immut_min(side_note, 0)
    }

    fn generate_main_trace_immut_min(
        &self,
        side_note: &SideNote,
        min_log_size: u32,
    ) -> FinalizedTrace {
        use crate::core::tracing::ScalarMultKind;
        let log_size = boundary_log_size(side_note).max(min_log_size);
        let mut trace = TraceBuilder::<Column>::new(log_size);

        // Walk `ristretto_comb_calls` and the parallel `ristretto_mem_ops`
        // filtered to FixedBasepoint records (produced in lock-step by
        // `ingest_ristretto_boundary`, so a positional zip is correct).
        let mut fixed_mem_ops = side_note
            .ristretto_mem_ops
            .iter()
            .filter(|op| op.kind == ScalarMultKind::FixedBasepoint);

        let mut row = 0usize;
        for (call_idx, call) in side_note.ristretto_comb_calls.iter().enumerate() {
            // Chip-isolated tests that populate ristretto_comb_calls without
            // ristretto_mem_ops fall back to zero scalar_ptr/ts — the Tier-2
            // consume then finds no producer and the open-chain harness
            // rejects, which is the desired behaviour for those tests.
            let mem_op = fixed_mem_ops.next();
            let scalar_ptr = mem_op.map(|op| op.scalar_ptr).unwrap_or(0);
            let ts = mem_op.map(|op| op.ts).unwrap_or(0);
            let ts_bytes = ts.to_le_bytes();
            let scalar_ptr_bytes = scalar_ptr.to_le_bytes();

            for byte_idx in 0..ROWS_PER_CALL {
                let byte = call.scalar[byte_idx];
                let low = byte & 0x0F;
                let high = (byte >> 4) & 0x0F;
                let (addr_bytes, carries) = addr_with_carries(scalar_ptr, byte_idx as u32);

                trace.fill_columns(row, 1u8, Column::IsReal);
                trace.fill_columns(row, call_idx as u8, Column::CallIdx);
                trace.fill_columns(row, low, Column::LowNibble);
                trace.fill_columns(row, high, Column::HighNibble);
                trace.fill_columns(row, byte, Column::ScalarByte);
                trace.fill_columns_bytes(row, &addr_bytes, Column::Addr);
                trace.fill_columns_bytes(row, &ts_bytes, Column::Ts);
                trace.fill_columns_bytes(row, &scalar_ptr_bytes, Column::ScalarPtr);
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

        let scalar: &RistrettoCombScalarBoundaryLookupElements = lookup_elements.as_ref();
        let memory: &MemoryAccessLookupElements = lookup_elements.as_ref();
        let fixed_scalar: &RistrettoFixedScalarTsLookupElements = lookup_elements.as_ref();

        let is_real = crate::trace::original_base_column!(component_trace, Column::IsReal);
        let call_idx = crate::trace::original_base_column!(component_trace, Column::CallIdx);
        let low_nibble = crate::trace::original_base_column!(component_trace, Column::LowNibble);
        let high_nibble = crate::trace::original_base_column!(component_trace, Column::HighNibble);
        let scalar_byte = crate::trace::original_base_column!(component_trace, Column::ScalarByte);
        let addr = crate::trace::original_base_column!(component_trace, Column::Addr);
        let ts = crate::trace::original_base_column!(component_trace, Column::Ts);
        let scalar_ptr = crate::trace::original_base_column!(component_trace, Column::ScalarPtr);
        let first_row_gate =
            crate::trace::original_base_column!(component_trace, Column::FirstRowGate);
        let win_even = crate::trace::preprocessed_base_column!(
            component_trace,
            PreprocessedColumn::WindowEven
        );
        let win_odd =
            crate::trace::preprocessed_base_column!(component_trace, PreprocessedColumn::WindowOdd);

        use crate::trace::component::FinalizedColumn;
        use stwo::core::fields::m31::BaseField as BF;
        let zero: FinalizedColumn<'_> = BF::from(0u32).into();

        // ── Tier-2 consumer (−FirstRowGate) ──
        let mut fixed_tuple: Vec<FinalizedColumn<'_>> = Vec::with_capacity(12);
        fixed_tuple.extend(scalar_ptr.iter().cloned());
        fixed_tuple.extend(ts.iter().cloned());
        logup.add_to_relation_with(
            fixed_scalar,
            [first_row_gate[0].clone()],
            |[g]| (-g).into(),
            &fixed_tuple,
        );

        // ── Scalar-boundary low-nibble emission ──
        logup.add_to_relation_with(
            scalar,
            [is_real[0].clone()],
            |[r]| (-r).into(),
            &[
                call_idx[0].clone(),
                win_even[0].clone(),
                low_nibble[0].clone(),
            ],
        );
        // ── Scalar-boundary high-nibble emission ──
        logup.add_to_relation_with(
            scalar,
            [is_real[0].clone()],
            |[r]| (-r).into(),
            &[
                call_idx[0].clone(),
                win_odd[0].clone(),
                high_nibble[0].clone(),
            ],
        );

        // ── Memory ledger producer (+is_real) ──
        let mut tuple: Vec<FinalizedColumn<'_>> = Vec::with_capacity(15);
        tuple.extend(addr.iter().cloned());
        tuple.push(scalar_byte[0].clone());
        tuple.extend(ts.iter().cloned());
        tuple.push(zero.clone()); // is_write = 0
        tuple.push(zero); // is_closing = 0
        logup.add_to_relation_with(memory, [is_real[0].clone()], |[r]| r.into(), &tuple);

        logup.finalize()
    }
}

#[cfg(feature = "prover")]
fn boundary_log_size(side_note: &SideNote) -> u32 {
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
