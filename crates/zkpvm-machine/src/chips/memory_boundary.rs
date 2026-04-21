use num_traits::{One, Zero};
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

/// MemoryBoundaryChip: produces logup entries for initial memory state.
///
/// For each byte address that is read without a prior write, provides
/// a byte-level memory access tuple (address, value_byte, timestamp=0, is_write=1)
/// with positive multiplicity.
pub struct MemoryBoundaryChip;

#[derive(Debug, Copy, Clone, AirColumn)]
pub enum Column {
    /// Byte address (4 limbs, u32)
    #[size = 4]
    Address,
    /// Single byte value
    #[size = 1]
    Value,
    /// 1 for real entries, 0 for padding
    #[size = 1]
    IsReal,
}

#[derive(Debug, Copy, Clone, PreprocessedAirColumn)]
#[preprocessed_prefix = "membnd"]
pub enum PreprocessedColumn {}

impl BuiltInComponent for MemoryBoundaryChip {
    type PreprocessedColumn = PreprocessedColumn;
    type MainColumn = Column;
    type LookupElements = MemoryAccessLookupElements;

    fn generate_preprocessed_trace(&self, _log_size: u32, _side_note: &SideNote) -> FinalizedTrace {
        FinalizedTrace::empty()
    }

    fn generate_main_trace(&self, side_note: &mut SideNote) -> FinalizedTrace {
        // Collect byte addresses that need initial values
        let initial_bytes = collect_initial_bytes(side_note);

        let num_entries = initial_bytes.len();
        let log_size = if num_entries == 0 {
            LOG_N_LANES
        } else {
            ((num_entries as f64).log2().ceil() as u32).max(LOG_N_LANES)
        };
        let mut trace = TraceBuilder::<Column>::new(log_size);

        for (row, &(addr, value)) in initial_bytes.iter().enumerate() {
            trace.fill_columns_bytes(row, &addr.to_le_bytes(), Column::Address);
            trace.fill_columns(row, value, Column::Value);
            trace.fill_columns(row, true, Column::IsReal);
        }
        // Remaining rows are padding (IsReal = 0 by default)

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
        let addr = zkpvm_trace::original_base_column!(component_trace, Column::Address);
        let value = zkpvm_trace::original_base_column!(component_trace, Column::Value);
        let is_real = zkpvm_trace::original_base_column!(component_trace, Column::IsReal);

        use stwo::prover::backend::simd::m31::PackedBaseField;

        // Byte-level tuple: (addr[4], value[1], timestamp[8]=0, is_write=1)
        logup.add_to_relation_computed(
            mem_lookup,
            [is_real[0].clone()],
            |[real]| real.into(),
            14,
            |vec_idx| {
                let mut tuple = Vec::with_capacity(14);
                for col in &addr { tuple.push(col.at(vec_idx)); }
                tuple.push(value[0].at(vec_idx));
                for _ in 0..8 { tuple.push(PackedBaseField::zero()); } // timestamp = 0
                tuple.push(PackedBaseField::one()); // is_write = 1
                tuple
            },
        );

        logup.finalize()
    }

    fn add_constraints<E: EvalAtRow>(
        &self,
        eval: &mut E,
        trace_eval: TraceEval<PreprocessedColumn, Column, E>,
        lookup_elements: &MemoryAccessLookupElements,
    ) {
        let addr = zkpvm_trace::trace_eval!(trace_eval, Column::Address);
        let value = zkpvm_trace::trace_eval!(trace_eval, Column::Value);
        let is_real = zkpvm_trace::trace_eval!(trace_eval, Column::IsReal);

        // Byte-level tuple: (addr[4], value[1], timestamp[8]=0, is_write=1)
        let mut tuple: Vec<E::F> = addr.to_vec();
        tuple.push(value[0].clone());
        for _ in 0..8 { tuple.push(E::F::zero()); }
        tuple.push(E::F::one());

        eval.add_to_relation(RelationEntry::new(
            lookup_elements,
            is_real[0].clone().into(),
            &tuple,
        ));

        eval.finalize_logup();
    }
}

/// Collect byte addresses that need initial values (read without prior write).
fn collect_initial_bytes(side_note: &SideNote) -> Vec<(u32, u8)> {
    use std::collections::HashMap;

    if side_note.initial_memory.is_empty() {
        return Vec::new();
    }

    // Decompose all accesses to byte level, find first access per byte address.
    // Blake2b precompile memory ops are interleaved by (addr, ts): for a byte
    // address touched by the precompile AND nothing earlier, the first access
    // is either the blake2b read (is_write=false) or write (is_write=true)
    // depending on which sorted first.  Since reads and writes at the same
    // ts sort stably with reads-before-writes by MemoryChip's insertion order,
    // AND regular steps have ts ≥ 1 while blake2b mem_ops also have ts ≥ 1
    // (matching their ECALL step), we need to compare ts across both sources.
    //
    // For first-read detection we only care about the minimum ts per address.
    let mut first_ts_is_write: HashMap<u32, (u64, bool)> = HashMap::new();
    let mut note = |addr: u32, ts: u64, is_write: bool| {
        first_ts_is_write
            .entry(addr)
            .and_modify(|cur| if ts < cur.0 { *cur = (ts, is_write); })
            .or_insert((ts, is_write));
    };
    for step in &side_note.steps {
        if let Some(ref r) = step.mem_read {
            for i in 0..r.size as u32 {
                note(r.address + i, step.timestamp, false);
            }
        }
        if let Some(ref w) = step.mem_write {
            for i in 0..w.size as u32 {
                note(w.address + i, step.timestamp, true);
            }
        }
    }
    for op in &side_note.blake2b_mem_ops {
        // Reads logged before writes at the same ts; note reads first so the
        // "is_write at earliest ts" resolves to false on ties.
        for i in 0..64u32 { note(op.h_ptr + i, op.ts, false); }
        for k in 0..128u32 { note(op.m_ptr + k, op.ts, false); }
        for i in 0..64u32 { note(op.h_ptr + i, op.ts, true); }
    }
    // Convert to (addr, is_write) of the first event.
    let first_is_write: HashMap<u32, bool> = first_ts_is_write
        .into_iter()
        .map(|(a, (_ts, w))| (a, w))
        .collect();

    let flat_mem = &side_note.initial_memory;
    let mut result: Vec<(u32, u8)> = Vec::new();
    for (&addr, &is_write) in &first_is_write {
        if is_write { continue; }
        let a = addr as usize;
        let value = if a < flat_mem.len() { flat_mem[a] } else { 0 };
        result.push((addr, value));
    }
    result.sort_by_key(|&(addr, _)| addr);
    result
}
