use num_traits::One;
use stwo::{
    core::{
        fields::{m31::BaseField, qm31::SecureField},
        ColumnVec,
    },
    prover::{
        backend::simd::{m31::LOG_N_LANES, SimdBackend},
        poly::{circle::CircleEvaluation, BitReversedOrder},
    },
};
use stwo_constraint_framework::{EvalAtRow, RelationEntry};

use zkpvm_air_column::{AirColumn, PreprocessedAirColumn};
use zkpvm_core::step::WORD_SIZE;
use zkpvm_trace::{
    builder::{FinalizedTrace, TraceBuilder},
    component::ComponentTrace,
    eval::TraceEval,
};

use crate::{
    framework::BuiltInComponent,
    lookups::{AllLookupElements, LogupTraceBuilder, MemoryAccessLookupElements},
    side_note::SideNote,
};

/// MemoryChip: proves read/write consistency of RAM accesses.
///
/// Each row is one memory access (Load or Store). The trace is sorted by
/// (address, timestamp). For consecutive accesses to the same address,
/// reads must return the value from the last write.
pub struct MemoryChip;

#[derive(Debug, Copy, Clone, AirColumn)]
pub enum Column {
    /// Memory address (4 limbs, u32)
    #[size = 4]
    Address,
    /// Value at this access (8 limbs)
    #[size = 8]
    Value,
    /// Timestamp of this access (8 limbs)
    #[size = 8]
    Timestamp,
    /// 1 = write, 0 = read
    #[size = 1]
    IsWrite,
    /// Value from the previous access to same address (8 limbs)
    #[size = 8]
    PrevValue,
    /// 1 if the next row accesses the same address
    #[size = 1]
    IsSameAddrNext,
    /// 1 if padding row
    #[size = 1]
    IsPadding,
    /// Access size in bytes (1,2,4,8)
    #[size = 1]
    AccessSize,
}

#[derive(Debug, Copy, Clone, PreprocessedAirColumn)]
#[preprocessed_prefix = "mem"]
pub enum PreprocessedColumn {}

/// A sorted memory access entry.
#[derive(Clone, Debug)]
struct MemEntry {
    address: u32,
    value: u64,
    timestamp: u64,
    is_write: bool,
    size: u8,
}

impl BuiltInComponent for MemoryChip {
    type PreprocessedColumn = PreprocessedColumn;
    type MainColumn = Column;
    type LookupElements = MemoryAccessLookupElements;

    fn generate_preprocessed_trace(&self, _log_size: u32, _side_note: &SideNote) -> FinalizedTrace {
        FinalizedTrace::empty()
    }

    fn generate_main_trace(&self, side_note: &mut SideNote) -> FinalizedTrace {
        let mut entries: Vec<MemEntry> = Vec::new();
        for step in &side_note.steps {
            if let Some(ref r) = step.mem_read {
                entries.push(MemEntry {
                    address: r.address,
                    value: r.value,
                    timestamp: step.timestamp,
                    is_write: false,
                    size: r.size,
                });
            }
            if let Some(ref w) = step.mem_write {
                entries.push(MemEntry {
                    address: w.address,
                    value: w.value,
                    timestamp: step.timestamp,
                    is_write: true,
                    size: w.size,
                });
            }
        }

        if entries.is_empty() {
            let log_size = LOG_N_LANES;
            let mut trace = TraceBuilder::<Column>::new(log_size);
            for row in 0..trace.num_rows() {
                trace.fill_columns(row, true, Column::IsPadding);
            }
            return trace.finalize_bit_reversed();
        }

        // Sort by (address, timestamp)
        entries.sort_by_key(|e| (e.address, e.timestamp));

        let num_entries = entries.len();
        let log_size = ((num_entries as f64).log2().ceil() as u32).max(LOG_N_LANES);
        let mut trace = TraceBuilder::<Column>::new(log_size);
        let num_rows = trace.num_rows();

        for (row, entry) in entries.iter().enumerate() {
            trace.fill_columns_bytes(row, &entry.address.to_le_bytes(), Column::Address);
            trace.fill_columns(row, entry.value, Column::Value);
            trace.fill_columns(row, entry.timestamp, Column::Timestamp);
            trace.fill_columns(row, entry.is_write, Column::IsWrite);
            trace.fill_columns(row, entry.size, Column::AccessSize);

            let prev_value = if row > 0 && entries[row - 1].address == entry.address {
                entries[row - 1].value
            } else {
                0
            };
            trace.fill_columns(row, prev_value, Column::PrevValue);

            let same_addr_next = row + 1 < num_entries && entries[row + 1].address == entry.address;
            trace.fill_columns(row, same_addr_next, Column::IsSameAddrNext);
            trace.fill_columns(row, false, Column::IsPadding);
        }

        for row in num_entries..num_rows {
            trace.fill_columns(row, true, Column::IsPadding);
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
        let is_pad = zkpvm_trace::original_base_column!(component_trace, Column::IsPadding);
        let address = zkpvm_trace::original_base_column!(component_trace, Column::Address);
        let value = zkpvm_trace::original_base_column!(component_trace, Column::Value);
        let timestamp = zkpvm_trace::original_base_column!(component_trace, Column::Timestamp);
        let is_write = zkpvm_trace::original_base_column!(component_trace, Column::IsWrite);
        let access_size = zkpvm_trace::original_base_column!(component_trace, Column::AccessSize);

        // Tuple: (addr[4], value[8], timestamp[8], is_write, size)
        let mut tuple: Vec<_> = address.to_vec();
        tuple.extend_from_slice(&value);
        tuple.extend_from_slice(&timestamp);
        tuple.push(is_write[0].clone());
        tuple.push(access_size[0].clone());

        // Consumer side (negative multiplicity)
        logup.add_to_relation_with(
            mem_lookup,
            [is_pad[0].clone()],
            |[pad]| {
                use stwo::prover::backend::simd::m31::PackedBaseField;
                (-(PackedBaseField::one() - pad)).into()
            },
            &tuple,
        );

        logup.finalize()
    }

    fn add_constraints<E: EvalAtRow>(
        &self,
        eval: &mut E,
        trace_eval: TraceEval<PreprocessedColumn, Column, E>,
        lookup_elements: &MemoryAccessLookupElements,
    ) {
        let is_pad = zkpvm_trace::trace_eval!(trace_eval, Column::IsPadding);
        let is_real = E::F::one() - is_pad[0].clone();

        let address = zkpvm_trace::trace_eval!(trace_eval, Column::Address);
        let value = zkpvm_trace::trace_eval!(trace_eval, Column::Value);
        let timestamp = zkpvm_trace::trace_eval!(trace_eval, Column::Timestamp);
        let is_write = zkpvm_trace::trace_eval!(trace_eval, Column::IsWrite);
        let prev_value = zkpvm_trace::trace_eval!(trace_eval, Column::PrevValue);
        let access_size = zkpvm_trace::trace_eval!(trace_eval, Column::AccessSize);

        // Read consistency: for reads, value must equal prev_value
        let is_read = E::F::one() - is_write[0].clone();
        for i in 0..WORD_SIZE {
            eval.add_constraint(
                is_real.clone() * is_read.clone() * (value[i].clone() - prev_value[i].clone())
            );
        }

        // Consumer lookup (negative multiplicity)
        let mut tuple: Vec<E::F> = address.to_vec();
        tuple.extend_from_slice(&value);
        tuple.extend_from_slice(&timestamp);
        tuple.push(is_write[0].clone());
        tuple.push(access_size[0].clone());

        eval.add_to_relation(RelationEntry::new(
            lookup_elements,
            (-is_real.clone()).into(),
            &tuple,
        ));

        eval.finalize_logup();
    }
}
