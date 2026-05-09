//! Session 2.1 step 8 R1e-bis Batch 4a — RistrettoCombCompressOutputChip.
//!
//! Sibling chip that closes the output-binding leg of the compress
//! chain.  Per fixed-base scalar mult call, 32 rows are emitted (one
//! per output byte).  Each row:
//!
//!   - **Consumes** the corresponding byte of canonical s_can from
//!     `RistrettoCombCompressChip`'s row +43 via the
//!     `RistrettoCombCompressOutputLookupElements` boundary relation
//!     (multiplicity `-IsReal` × tuple `(CallIdx, ByteIdx, Value)`).
//!   - **Produces** a `MemoryAccessLookupElements` tuple at the
//!     actor's claimed `(output_ptr + byte_idx, value, ts,
//!     is_write=1)` address (multiplicity `+IsReal`).
//!
//! Mirrors `RistrettoCombScalarBoundaryChip`'s 32-row-per-call shape
//! for the scalar-binding leg.  Together with that chip, every byte
//! the actor writes through `ECALL_RISTRETTO_SCALAR_MULT` is
//! mechanically traced to an in-circuit derivation: scalar bytes via
//! the comb-anchor + scalar-boundary chain; output bytes via this
//! chip + the compress chain.  The intermediate input point bytes
//! remain on `RistrettoEcallChip`'s producer side.

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
use crate::lookups::{MemoryAccessLookupElements, RistrettoCombCompressOutputLookupElements};
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
    /// ECALL step timestamp, 8 LE bytes.
    #[size = 8]
    Ts,
}

#[derive(Debug, Copy, Clone, PreprocessedAirColumn)]
#[preprocessed_prefix = "ristretto_comb_compress_output"]
pub enum PreprocessedColumn {
    /// `CallIdx[r] = floor(r / 32)` on real rows; 0 on padding.
    /// Drives the `call_idx` limb of the output-relation tuple.
    #[size = 1]
    CallIdx,
    /// `ByteIdx[r] = r mod 32`.  Drives both the `byte_idx` limb of
    /// the output-relation tuple AND the per-byte address offset
    /// (`Addr` column equals `output_ptr + ByteIdx` after carry).
    #[size = 1]
    ByteIdx,
}

impl BuiltInComponent for RistrettoCombCompressOutputChip {
    type PreprocessedColumn = PreprocessedColumn;
    type MainColumn = Column;
    type LookupElements = (
        MemoryAccessLookupElements,
        RistrettoCombCompressOutputLookupElements,
    );

    fn add_constraints<E: EvalAtRow>(
        &self,
        eval: &mut E,
        trace_eval: TraceEval<PreprocessedColumn, Column, E>,
        lookup_elements: &(
            MemoryAccessLookupElements,
            RistrettoCombCompressOutputLookupElements,
        ),
    ) {
        let (memory_lookup, output_lookup) = lookup_elements;

        let is_real = crate::trace::trace_eval!(trace_eval, Column::IsReal);
        let addr = crate::trace::trace_eval!(trace_eval, Column::Addr);
        let value = crate::trace::trace_eval!(trace_eval, Column::Value);
        let ts = crate::trace::trace_eval!(trace_eval, Column::Ts);
        let call_idx_pp =
            crate::trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::CallIdx);
        let byte_idx_pp =
            crate::trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::ByteIdx);

        // IsReal ∈ {0, 1}.
        eval.add_constraint(is_real[0].clone() * (E::F::one() - is_real[0].clone()));

        // ── Output-relation consumer ──
        // -IsReal × (CallIdx, ByteIdx, Value).  Balanced against
        // `RistrettoCombCompressChip`'s row +43 producer (which
        // emits +IsOutputProducer × the same tuple shape).
        eval.add_to_relation(RelationEntry::new(
            output_lookup,
            (-is_real[0].clone()).into(),
            &[
                call_idx_pp[0].clone(),
                byte_idx_pp[0].clone(),
                value[0].clone(),
            ],
        ));

        // ── MemoryAccess producer ──
        // +IsReal × (Addr[0..4], Value, Ts[0..8], is_write=1).  The
        // 14-limb tuple matches `MemoryChip`'s consumer side exactly.
        let one = E::F::one();
        let mut tuple: Vec<E::F> = Vec::with_capacity(14);
        tuple.extend_from_slice(&addr);
        tuple.push(value[0].clone());
        tuple.extend_from_slice(&ts);
        tuple.push(one);
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
        }
        trace.finalize_bit_reversed()
    }

    fn generate_main_trace_immut(&self, side_note: &SideNote) -> FinalizedTrace {
        let log_size = output_log_size(side_note);
        let mut trace = TraceBuilder::<Column>::new(log_size);
        let mut row = 0usize;
        for call in side_note.ristretto_comb_calls.iter() {
            let ts_bytes = call.ts.to_le_bytes();
            for byte_idx in 0..ROWS_PER_CALL {
                let addr = call.output_ptr.wrapping_add(byte_idx as u32);
                let addr_bytes = addr.to_le_bytes();
                let value = call.out_bytes[byte_idx];
                trace.fill_columns(row, 1u8, Column::IsReal);
                trace.fill_columns_bytes(row, &addr_bytes, Column::Addr);
                trace.fill_columns(row, value, Column::Value);
                trace.fill_columns_bytes(row, &ts_bytes, Column::Ts);
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

        let is_real = crate::trace::original_base_column!(component_trace, Column::IsReal);
        let addr = crate::trace::original_base_column!(component_trace, Column::Addr);
        let value = crate::trace::original_base_column!(component_trace, Column::Value);
        let ts = crate::trace::original_base_column!(component_trace, Column::Ts);
        let call_idx_pp =
            crate::trace::preprocessed_base_column!(component_trace, PreprocessedColumn::CallIdx);
        let byte_idx_pp =
            crate::trace::preprocessed_base_column!(component_trace, PreprocessedColumn::ByteIdx);

        use crate::trace::component::FinalizedColumn;
        use stwo::core::fields::m31::BaseField as BF;
        let one_col: FinalizedColumn<'_> = BF::from(1u32).into();

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
        let mut tuple: Vec<FinalizedColumn<'_>> = Vec::with_capacity(14);
        tuple.extend(addr.iter().cloned());
        tuple.push(value[0].clone());
        tuple.extend(ts.iter().cloned());
        tuple.push(one_col);
        logup.add_to_relation_with(memory, [is_real[0].clone()], |[r]| r.into(), &tuple);

        logup.finalize()
    }
}
