//! Step 13: Ristretto / scalar-reduce ECALL memory-producer chip.
//!
//! Each ECALL_RISTRETTO_SCALAR_MULT, ECALL_RISTRETTO_POINT_ADD, and
//! ECALL_SCALAR_FROM_BYTES_MOD_ORDER_WIDE call touches flat_mem
//! during its host-side handler (32 + 32 + 32 = 96 byte accesses
//! for scalar_mult / point_add; 64 + 32 = 96 for scalar_reduce).
//! The MemoryChip's ledger inserts the matching CONSUMER tuples;
//! this chip emits the matching PRODUCERS so the lookup balances.
//!
//! Trace shape: one row per byte access.  Per-row tuple:
//!   (addr[4 LE bytes], value[1], ts[8 LE bytes], is_write[1])
//!
//! Mirrors the Blake2bChip pattern (`h_rd_addr` / `m_rd_addr` /
//! `h_wr_addr` byte-buffer producers) but flatter — no field
//! arithmetic, no per-row constraints beyond "IsReal is bool".
//! Activates only when SideNote carries at least one
//! ristretto/scalar-reduce mem op.

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
use crate::{framework::BuiltInComponent, lookups::MemoryAccessLookupElements};

pub struct RistrettoEcallChip;

#[derive(Debug, Copy, Clone, AirColumn)]
pub enum Column {
    /// Address, 4 LE bytes.
    #[size = 4]
    Addr,
    /// Memory byte value at this address.
    #[size = 1]
    Value,
    /// Timestamp, 8 LE bytes.
    #[size = 8]
    Ts,
    /// 1 = write, 0 = read.
    #[size = 1]
    IsWrite,
    /// 0 on padding rows.
    #[size = 1]
    IsReal,
}

#[derive(Debug, Copy, Clone, PreprocessedAirColumn)]
#[preprocessed_prefix = "ristretto_ecall"]
pub enum PreprocessedColumn {
    #[size = 1]
    Reserved,
}

impl BuiltInComponent for RistrettoEcallChip {
    type PreprocessedColumn = PreprocessedColumn;
    type MainColumn = Column;
    type LookupElements = MemoryAccessLookupElements;

    fn add_constraints<E: EvalAtRow>(
        &self,
        eval: &mut E,
        trace_eval: TraceEval<PreprocessedColumn, Column, E>,
        lookup_elements: &MemoryAccessLookupElements,
    ) {
        let addr = crate::trace::trace_eval!(trace_eval, Column::Addr);
        let value = crate::trace::trace_eval!(trace_eval, Column::Value);
        let ts = crate::trace::trace_eval!(trace_eval, Column::Ts);
        let is_write = crate::trace::trace_eval!(trace_eval, Column::IsWrite);
        let is_real = crate::trace::trace_eval!(trace_eval, Column::IsReal);

        // IsReal, IsWrite must be boolean.
        eval.add_constraint(is_real[0].clone() * (E::F::one() - is_real[0].clone()));
        eval.add_constraint(is_write[0].clone() * (E::F::one() - is_write[0].clone()));

        // Producer tuple: (addr[4], value[1], ts[8], is_write[1]) — 14 elements,
        // matches MemoryChip's consumer side exactly.
        let mut tuple: Vec<E::F> = Vec::with_capacity(14);
        tuple.extend_from_slice(&addr);
        tuple.push(value[0].clone());
        tuple.extend_from_slice(&ts);
        tuple.push(is_write[0].clone());

        eval.add_to_relation(RelationEntry::new(
            lookup_elements,
            is_real[0].clone().into(),
            &tuple,
        ));

        eval.finalize_logup();
    }
}

#[cfg(feature = "prover")]
fn ristretto_ecall_log_size(side_note: &SideNote) -> u32 {
    use crate::core::tracing::ScalarMultKind;
    // FixedBasepoint scalar mults skip BOTH:
    //   - 32-byte scalar producers (handled by
    //     RistrettoCombScalarBoundaryChip; Batch 8).
    //   - 32-byte output producers (handled by
    //     RistrettoCombCompressOutputChip; Batch 4a).
    // Only the 32-byte INPUT POINT producers stay here.
    let n_scalar: usize = side_note
        .ristretto_mem_ops
        .iter()
        .map(|op| match op.kind {
            ScalarMultKind::FixedBasepoint => 32, // point only
            ScalarMultKind::Variable => 96,
        })
        .sum();
    let n_add = side_note.ristretto_add_mem_ops.len() * 96;
    let n_reduce = side_note.scalar_reduce_wide_mem_ops.len() * 96;
    let n_binop = side_note.scalar_binop_mem_ops.len() * 96;
    let total = (n_scalar + n_add + n_reduce + n_binop) as u32;
    let log = 32u32 - total.saturating_sub(1).leading_zeros();
    log.max(LOG_N_LANES)
}

#[cfg(feature = "prover")]
struct ByteAccess {
    addr: u32,
    value: u8,
    ts: u64,
    is_write: bool,
}

#[cfg(feature = "prover")]
fn collect_accesses(side_note: &SideNote) -> Vec<ByteAccess> {
    use crate::core::tracing::ScalarMultKind;
    let mut out = Vec::new();
    for op in &side_note.ristretto_mem_ops {
        // Scalar-byte producers: skipped for FixedBasepoint records —
        // `RistrettoCombScalarBoundaryChip` produces those tuples to
        // bind the scalar nibbles directly to the PVM memory ledger.
        if op.kind != ScalarMultKind::FixedBasepoint {
            for i in 0..32u32 {
                out.push(ByteAccess {
                    addr: op.scalar_ptr + i,
                    value: op.scalar_bytes[i as usize],
                    ts: op.ts,
                    is_write: false,
                });
            }
        }
        for i in 0..32u32 {
            out.push(ByteAccess {
                addr: op.point_ptr + i,
                value: op.point_bytes[i as usize],
                ts: op.ts,
                is_write: false,
            });
        }
        // Output-byte producers: skipped for FixedBasepoint records —
        // `RistrettoCombCompressOutputChip` produces those tuples
        // (Batch 4a) bound to the canonical s_can derived in-circuit
        // by the compress chain.
        if op.kind != ScalarMultKind::FixedBasepoint {
            for i in 0..32u32 {
                out.push(ByteAccess {
                    addr: op.output_ptr + i,
                    value: op.out_bytes[i as usize],
                    ts: op.ts,
                    is_write: true,
                });
            }
        }
    }
    for op in &side_note.ristretto_add_mem_ops {
        for i in 0..32u32 {
            out.push(ByteAccess {
                addr: op.p_ptr + i,
                value: op.p_bytes[i as usize],
                ts: op.ts,
                is_write: false,
            });
        }
        for i in 0..32u32 {
            out.push(ByteAccess {
                addr: op.q_ptr + i,
                value: op.q_bytes[i as usize],
                ts: op.ts,
                is_write: false,
            });
        }
        for i in 0..32u32 {
            out.push(ByteAccess {
                addr: op.output_ptr + i,
                value: op.out_bytes[i as usize],
                ts: op.ts,
                is_write: true,
            });
        }
    }
    for op in &side_note.scalar_reduce_wide_mem_ops {
        for i in 0..64u32 {
            out.push(ByteAccess {
                addr: op.wide_ptr + i,
                value: op.wide_bytes[i as usize],
                ts: op.ts,
                is_write: false,
            });
        }
        for i in 0..32u32 {
            out.push(ByteAccess {
                addr: op.output_ptr + i,
                value: op.out_bytes[i as usize],
                ts: op.ts,
                is_write: true,
            });
        }
    }
    for op in &side_note.scalar_binop_mem_ops {
        for i in 0..32u32 {
            out.push(ByteAccess {
                addr: op.a_ptr + i,
                value: op.a_bytes[i as usize],
                ts: op.ts,
                is_write: false,
            });
        }
        for i in 0..32u32 {
            out.push(ByteAccess {
                addr: op.b_ptr + i,
                value: op.b_bytes[i as usize],
                ts: op.ts,
                is_write: false,
            });
        }
        for i in 0..32u32 {
            out.push(ByteAccess {
                addr: op.output_ptr + i,
                value: op.out_bytes[i as usize],
                ts: op.ts,
                is_write: true,
            });
        }
    }
    out
}

#[cfg(feature = "prover")]
impl BuiltInProverComponent for RistrettoEcallChip {
    const IS_PRODUCER: bool = false;

    fn generate_preprocessed_trace(&self, _log_size: u32, side_note: &SideNote) -> FinalizedTrace {
        let log_size = ristretto_ecall_log_size(side_note);
        let mut trace = TraceBuilder::<PreprocessedColumn>::new(log_size);
        let num_rows = trace.num_rows();
        for row in 0..num_rows {
            trace.fill_columns(row, BaseField::from(0u32), PreprocessedColumn::Reserved);
        }
        trace.finalize_bit_reversed()
    }

    fn generate_main_trace_immut(&self, side_note: &SideNote) -> FinalizedTrace {
        let log_size = ristretto_ecall_log_size(side_note);
        let mut trace = TraceBuilder::<Column>::new(log_size);
        let num_rows = trace.num_rows();
        let accesses = collect_accesses(side_note);
        for row in 0..num_rows {
            if let Some(a) = accesses.get(row) {
                let addr_bytes = a.addr.to_le_bytes();
                trace.fill_columns_bytes(row, &addr_bytes, Column::Addr);
                trace.fill_columns(row, a.value, Column::Value);
                let ts_bytes = a.ts.to_le_bytes();
                trace.fill_columns_bytes(row, &ts_bytes, Column::Ts);
                trace.fill_columns(row, a.is_write as u8, Column::IsWrite);
                trace.fill_columns(row, 1u8, Column::IsReal);
            }
            // Padding rows: all zeros (fill_columns default), is_real = 0.
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
        let addr = crate::trace::original_base_column!(component_trace, Column::Addr);
        let value = crate::trace::original_base_column!(component_trace, Column::Value);
        let ts = crate::trace::original_base_column!(component_trace, Column::Ts);
        let is_write = crate::trace::original_base_column!(component_trace, Column::IsWrite);
        let is_real = crate::trace::original_base_column!(component_trace, Column::IsReal);

        let mut tuple: Vec<_> = addr.to_vec();
        tuple.push(value[0].clone());
        tuple.extend_from_slice(&ts);
        tuple.push(is_write[0].clone());

        logup.add_to_relation_with(
            mem_lookup,
            [is_real[0].clone()],
            |[real]| real.into(),
            &tuple,
        );

        logup.finalize()
    }
}
