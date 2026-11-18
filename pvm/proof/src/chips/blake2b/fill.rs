//! The chip's trace generation, the prover's half.

use super::*;
use crate::framework::BuiltInProverComponent;
use crate::lookups::{AllLookupElements, LogupTraceBuilder};
use crate::side_note::SideNote;
use crate::trace::{
    builder::{FinalizedTrace, TraceBuilder},
    component::{ComponentTrace, FinalizedColumn},
};
use compression::{
    add_compression_interaction_core, build_compression_rows, fill_compression_trace,
    fill_schedule_preprocessed,
};
use stwo::core::fields::m31::BaseField;
use stwo::{
    core::{ColumnVec, fields::qm31::SecureField},
    prover::{
        backend::simd::{
            SimdBackend,
            m31::{LOG_N_LANES, PackedBaseField},
        },
        poly::{BitReversedOrder, circle::CircleEvaluation},
    },
};
use trace::GRow;

/// Fill the ECALL memory-binding columns — `Blake2bChip`'s exclusive width
/// (`HPtr`/`MPtr`/`CallTs` and the address columns of `address.rs`) — on
/// every real row, and count the address range lookups once per compression
/// row that emits them (`h`'s first and last rows, `m`'s first).  Split from
/// `fill_compression_trace` because the boundary chip's `BoundaryColumn`
/// layout omits these columns entirely.
fn fill_ecall_binding_trace(
    trace: &mut TraceBuilder<Column>,
    side_note: &mut SideNote,
    rows: &[GRow],
) {
    for (row_idx, r) in rows.iter().enumerate() {
        trace.fill_columns_bytes(row_idx, &r.h_ptr, Column::HPtr);
        trace.fill_columns_bytes(row_idx, &r.m_ptr, Column::MPtr);
        trace.fill_columns_bytes(row_idx, &r.call_ts, Column::CallTs);
        let (h_ptr, m_ptr) = (u32::from_le_bytes(r.h_ptr), u32::from_le_bytes(r.m_ptr));
        address::fill::<64>(trace, row_idx, h_ptr, address::H);
        address::fill::<128>(trace, row_idx, m_ptr, address::M);
        if row_idx.is_multiple_of(96) {
            address::count_range_lookups::<64>(side_note, h_ptr, 2);
            address::count_range_lookups::<128>(side_note, m_ptr, 1);
        }
    }
}

impl BuiltInProverComponent for Blake2bChip {
    fn generate_preprocessed_trace(&self, log_size: u32, _side_note: &SideNote) -> FinalizedTrace {
        let mut trace = TraceBuilder::<PreprocessedColumn>::new(log_size);
        fill_schedule_preprocessed(&mut trace);
        let num_rows = trace.num_rows();
        let tail = num_rows / 96 * 96;
        for row in 0..num_rows {
            let continuity = row % 96 != 95 && row != num_rows - 1;
            trace.fill_columns(row, continuity, PreprocessedColumn::ContinuityGate);
            trace.fill_columns(row, row >= tail, PreprocessedColumn::IsTail);
        }
        trace.finalize_bit_reversed()
    }

    fn generate_main_trace_min(
        &self,
        side_note: &mut SideNote,
        min_log_size: u32,
    ) -> FinalizedTrace {
        if side_note.blake2b_calls.is_empty() {
            // Canonical-shape: forced present-but-empty (all-padding, is_real=0).
            let log_size = LOG_N_LANES.max(min_log_size);
            let trace = TraceBuilder::<Column>::new(log_size);
            return trace.finalize_bit_reversed();
        }
        let rows = build_compression_rows(&side_note.blake2b_calls, &side_note.blake2b_mem_ops);
        let num_rows = rows.len();
        let log_size = crate::trace::utils::ceil_log2_at_least_lanes(num_rows).max(min_log_size);
        let mut trace = TraceBuilder::<Column>::new(log_size);
        fill_compression_trace(&mut trace, side_note, &rows);
        fill_ecall_binding_trace(&mut trace, side_note, &rows);
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
        let log_size = component_trace.log_size();
        let mut logup = LogupTraceBuilder::new(log_size);

        let range256: &Range256LookupElements = lookup_elements.as_ref();
        let bitwise: &BitwiseAndByteLookupElements = lookup_elements.as_ref();
        // Arithmetic-core lookups (byte-wide AND / Range256 lookups +
        // output-AND lookups) — shared with Blake2bBoundaryChip.
        add_compression_interaction_core::<PreprocessedColumn, Column>(
            &mut logup,
            component_trace,
            range256,
            bitwise,
        );

        let init_gate = crate::trace::original_base_column!(component_trace, Column::InitGateH);
        let output_gate = crate::trace::original_base_column!(component_trace, Column::OutputGateH);
        let h_addr = address::AddressTrace::<64>::read(component_trace, address::H);
        let m_addr = address::AddressTrace::<128>::read(component_trace, address::M);
        h_addr.add_range_lookups(
            &mut logup,
            range256,
            [init_gate[0].clone(), output_gate[0].clone()],
        );
        m_addr.add_range_lookups(&mut logup, range256, [init_gate[0].clone()]);

        // ── Memory-access tuples (addr[4], value, ts[8], is_write, is_closing) ──
        let mem_lookup: &MemoryAccessLookupElements = lookup_elements.as_ref();
        let call_ts_cols = crate::trace::original_base_column!(component_trace, Column::CallTs);
        let h_words = Column::H.map(|col| component_trace.original_base_column::<8, _>(col));
        let m_words = Column::M.map(|col| component_trace.original_base_column::<8, _>(col));
        let output_cols = crate::trace::original_base_column!(component_trace, Column::Output);
        let zero = PackedBaseField::broadcast(BaseField::from(0u32));
        let one = PackedBaseField::broadcast(BaseField::from(1u32));
        let mut access = |addr: &dyn Fn(usize) -> [PackedBaseField; 4],
                          value: FinalizedColumn<'_>,
                          is_write: PackedBaseField,
                          gate: FinalizedColumn<'_>| {
            let ts = call_ts_cols.clone();
            logup.add_to_relation_computed(
                mem_lookup,
                [gate],
                |[g]| g.into(),
                15,
                move |v| {
                    let mut t = Vec::with_capacity(15);
                    t.extend(addr(v));
                    t.push(value.at(v));
                    t.extend(ts.iter().map(|col| col.at(v)));
                    t.push(is_write);
                    t.push(zero); // is_closing = 0
                    t
                },
            );
        };
        // 64 h reads and 128 m reads on the first row.
        for i in 0..64usize {
            let addr = h_addr.address(i);
            access(
                &addr,
                h_words[i / 8][i % 8].clone(),
                zero,
                init_gate[0].clone(),
            );
        }
        for k in 0..128usize {
            let addr = m_addr.address(k);
            access(
                &addr,
                m_words[k / 8][k % 8].clone(),
                zero,
                init_gate[0].clone(),
            );
        }
        // 64 digest writes on the last row.
        for i in 0..64usize {
            let addr = h_addr.address(i);
            access(&addr, output_cols[i].clone(), one, output_gate[0].clone());
        }

        // ── Blake2b-call consumer linking to CpuChip ECALL step ──
        // Tuple (h_ptr[0..4], m_ptr[0..4], t[0..8], F[1], CallTs[0..8]) = 25 limbs,
        // multiplicity −InitGateH so CpuChip's matching producer balances.
        let blake2b_call: &Blake2bCallLookupElements = lookup_elements.as_ref();
        let h_ptr_cols = crate::trace::original_base_column!(component_trace, Column::HPtr);
        let m_ptr_cols = crate::trace::original_base_column!(component_trace, Column::MPtr);
        let t_cols = crate::trace::original_base_column!(component_trace, Column::T);
        let f_col = crate::trace::original_base_column!(component_trace, Column::F);
        let call_cols: Vec<FinalizedColumn<'_>> = h_ptr_cols
            .into_iter()
            .chain(m_ptr_cols)
            .chain(t_cols.into_iter().take(8))
            .chain(f_col)
            .chain(call_ts_cols)
            .collect();
        logup.add_to_relation_computed(
            blake2b_call,
            [init_gate[0].clone()],
            |[g]| (-g).into(),
            25,
            move |v| call_cols.iter().map(|col| col.at(v)).collect(),
        );

        logup.finalize()
    }
}
