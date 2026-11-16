//! The chip's trace generation, the prover's half.

use super::*;
use crate::{
    framework::BuiltInProverComponent,
    lookups::{AllLookupElements, LogupTraceBuilder},
    side_note::SideNote,
    trace::{
        builder::{FinalizedTrace, TraceBuilder},
        component::ComponentTrace,
    },
};
use stwo::{
    core::{ColumnVec, fields::qm31::SecureField},
    prover::{
        backend::simd::{SimdBackend, m31::LOG_N_LANES},
        poly::{BitReversedOrder, circle::CircleEvaluation},
    },
};

/// One row: a byte a call writes, and where it lies in its call.
struct ByteRow {
    ts: u64,
    address: u32,
    value: u8,
    left: u32,
    first: bool,
}

/// Every witness-input call's bytes, call by call in step order.
fn byte_rows(side_note: &SideNote) -> Vec<ByteRow> {
    let mut rows = Vec::new();
    for step in &side_note.steps {
        let Some(write) = &step.witness else {
            continue;
        };
        let count = write.bytes.len() as u32;
        for (offset, &value) in write.bytes.iter().enumerate() {
            rows.push(ByteRow {
                ts: step.timestamp,
                address: write.address.wrapping_add(offset as u32),
                value,
                left: count - offset as u32,
                first: offset == 0,
            });
        }
    }
    rows
}

impl BuiltInProverComponent for WitnessInputChip {
    fn generate_main_trace_min(
        &self,
        side_note: &mut SideNote,
        min_log_size: u32,
    ) -> FinalizedTrace {
        let rows = byte_rows(side_note);
        let log_size = crate::trace::utils::ceil_log2_at_least_lanes(rows.len().max(1))
            .max(LOG_N_LANES)
            .max(min_log_size);
        let mut trace = TraceBuilder::<Column>::new(log_size);
        for (row, byte) in rows.iter().enumerate() {
            let last = byte.left == 1;
            let address = byte.address.to_le_bytes();
            trace.fill_columns(row, true, Column::IsReal);
            trace.fill_columns(row, byte.first, Column::IsFirst);
            trace.fill_columns(row, last, Column::IsLast);
            trace.fill_columns(row, !last, Column::Cont);
            trace.fill_columns(row, !byte.first, Column::Follows);
            trace.fill_columns(row, byte.ts, Column::Ts);
            trace.fill_columns_bytes(row, &address, Column::Addr);
            trace.fill_columns(row, byte.value, Column::Value);
            trace.fill_columns_base_field(row, &[BaseField::from(byte.left)], Column::Left);
            if !last {
                // The carries of `address + 1`, byte by byte.
                let mut carries = [0u8; 3];
                let mut carry_in = 1u16;
                for (i, carry) in carries.iter_mut().enumerate() {
                    let sum = address[i] as u16 + carry_in;
                    *carry = (sum >> 8) as u8;
                    carry_in = *carry as u16;
                }
                trace.fill_columns_bytes(row, &carries, Column::Carry);
            }
            side_note.add_range256(byte.value);
            for byte in address {
                side_note.add_range256(byte);
            }
        }
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
        use crate::trace::component::FinalizedColumn;
        let log_size = component_trace.log_size();
        let mut logup = LogupTraceBuilder::new(log_size);
        let call_lookup: &WitnessCallLookupElements = lookup_elements.as_ref();
        let mem_lookup: &MemoryAccessLookupElements = lookup_elements.as_ref();
        let range256: &Range256LookupElements = lookup_elements.as_ref();
        let is_real = crate::trace::original_base_column!(component_trace, Column::IsReal);
        let is_first = crate::trace::original_base_column!(component_trace, Column::IsFirst);
        let ts = crate::trace::original_base_column!(component_trace, Column::Ts);
        let addr = crate::trace::original_base_column!(component_trace, Column::Addr);
        let value = crate::trace::original_base_column!(component_trace, Column::Value);
        let left = crate::trace::original_base_column!(component_trace, Column::Left);

        let mut call: Vec<FinalizedColumn<'_>> = ts.to_vec();
        call.extend_from_slice(&addr);
        call.push(left[0].clone());
        for _ in 0..2 {
            logup.add_to_relation_with(
                call_lookup,
                [is_first[0].clone()],
                |[first]| (-first).into(),
                &call,
            );
        }
        let mut write: Vec<FinalizedColumn<'_>> = addr.to_vec();
        write.push(value[0].clone());
        write.extend_from_slice(&ts);
        write.push(FinalizedColumn::Constant(BaseField::from(1u32)));
        write.push(FinalizedColumn::Constant(BaseField::from(0u32)));
        logup.add_to_relation_with(
            mem_lookup,
            [is_real[0].clone()],
            |[real]| real.into(),
            &write,
        );
        for byte in value.iter().chain(addr.iter()) {
            logup.add_to_relation_with(
                range256,
                [is_real[0].clone()],
                |[real]| real.into(),
                core::slice::from_ref(byte),
            );
        }
        logup.finalize()
    }
}
