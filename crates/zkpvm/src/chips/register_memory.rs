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

use crate::air_column::{AirColumn, PreprocessedAirColumn};
use crate::core::step::NUM_REGS;
use crate::trace::{
    builder::{FinalizedTrace, TraceBuilder},
    component::ComponentTrace,
    eval::TraceEval,
};

use crate::{
    framework::BuiltInComponent,
    lookups::{AllLookupElements, LogupTraceBuilder, RegisterMemoryLookupElements},
    side_note::SideNote,
};

/// RegisterMemoryChip: PVM register-file ledger, analogous to MemoryChip but
/// indexed by register number (0..NUM_REGS-1) and valued as full u64s.
///
/// At Phase 9b only the initial-state writes (ts=0, from SideNote.initial_regs)
/// populate the ledger — CpuChip register-access emissions are added in
/// subsequent phases.  The ledger entries are sorted by (reg_addr, timestamp)
/// and the read-consistency constraint fires when a read is preceded by a
/// same-register entry (forcing read value = previous value).
pub struct RegisterMemoryChip;

#[derive(Debug, Copy, Clone, AirColumn)]
pub enum Column {
    /// Register index.
    #[size = 1]
    RegAddr,
    /// u64 value as 8 LE bytes.
    #[size = 8]
    Value,
    /// Timestamp of this access (u64 as 8 LE bytes).
    #[size = 8]
    Timestamp,
    /// 1 = write, 0 = read.
    #[size = 1]
    IsWrite,
    /// Previous value at same register (u64, 8 bytes).  0 on the first entry
    /// per register.
    #[size = 8]
    PrevValue,
    /// 1 if the next ledger row accesses the same register.
    #[size = 1]
    IsSameRegNext,
    /// 1 if padding row (beyond real ledger entries).
    #[size = 1]
    IsPadding,
}

#[derive(Debug, Copy, Clone, PreprocessedAirColumn)]
#[preprocessed_prefix = "regmem"]
pub enum PreprocessedColumn {}

/// A single register-level ledger entry.
#[derive(Clone, Debug)]
struct RegEntry {
    reg_addr: u8,
    value: u64,
    timestamp: u64,
    is_write: bool,
}

impl BuiltInComponent for RegisterMemoryChip {
    type PreprocessedColumn = PreprocessedColumn;
    type MainColumn = Column;
    type LookupElements = RegisterMemoryLookupElements;


    fn generate_main_trace(&self, side_note: &mut SideNote) -> FinalizedTrace {
        let mut entries: Vec<RegEntry> = Vec::new();

        // Initial register state: one synthetic write per register at ts=0.
        for (i, &val) in side_note.initial_regs.iter().enumerate() {
            entries.push(RegEntry {
                reg_addr: i as u8,
                value: val,
                timestamp: 0,
                is_write: true,
            });
        }

        // CpuChip register-access entries (Phase 9d).  Push in the same
        // ValB-read → ValD-read → Result-write order CpuChip uses so that,
        // if multiple accesses hit the same (addr, ts), the stable sort by
        // (reg_addr, timestamp) preserves that order and read-consistency
        // resolves correctly.
        for step in &side_note.steps {
            let acc = crate::chips::cpu::step_reg_accesses(step);
            if let Some((reg_idx, val)) = acc.val_b_read {
                entries.push(RegEntry { reg_addr: reg_idx, value: val, timestamp: step.timestamp, is_write: false });
            }
            if let Some((reg_idx, val)) = acc.val_d_read {
                entries.push(RegEntry { reg_addr: reg_idx, value: val, timestamp: step.timestamp, is_write: false });
            }
            if let Some((reg_idx, val)) = acc.result_write {
                entries.push(RegEntry { reg_addr: reg_idx, value: val, timestamp: step.timestamp, is_write: true });
            }
            // Phase 9e: blake2b ECALL register reads.
            for &(reg_idx, val) in &acc.ecall_reads {
                entries.push(RegEntry { reg_addr: reg_idx, value: val, timestamp: step.timestamp, is_write: false });
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

        // Sort by (reg_addr, timestamp) with stable order so reads-before-writes
        // are preserved on ties (matches MemoryChip pattern).
        entries.sort_by_key(|e| (e.reg_addr, e.timestamp));

        let num_entries = entries.len();
        let log_size = crate::trace::utils::ceil_log2_at_least_lanes(num_entries);
        let mut trace = TraceBuilder::<Column>::new(log_size);
        let num_rows = trace.num_rows();

        for (row, entry) in entries.iter().enumerate() {
            trace.fill_columns(row, entry.reg_addr, Column::RegAddr);
            trace.fill_columns(row, entry.value, Column::Value);
            trace.fill_columns(row, entry.timestamp, Column::Timestamp);
            trace.fill_columns(row, entry.is_write, Column::IsWrite);

            let prev_value: u64 = if row > 0 && entries[row - 1].reg_addr == entry.reg_addr {
                entries[row - 1].value
            } else {
                0
            };
            trace.fill_columns(row, prev_value, Column::PrevValue);

            let same_reg_next = row + 1 < num_entries
                && entries[row + 1].reg_addr == entry.reg_addr;
            trace.fill_columns(row, same_reg_next, Column::IsSameRegNext);
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

        let reg_lookup: &RegisterMemoryLookupElements = lookup_elements.as_ref();
        let is_pad = crate::trace::original_base_column!(component_trace, Column::IsPadding);
        let reg_addr = crate::trace::original_base_column!(component_trace, Column::RegAddr);
        let value = crate::trace::original_base_column!(component_trace, Column::Value);
        let timestamp = crate::trace::original_base_column!(component_trace, Column::Timestamp);

        // Tuple (reg_addr[1], value[8], timestamp[8]) = 17 limbs.  Consumer
        // side with negative multiplicity — matches the boundary chip and
        // (later) CpuChip producers.
        let mut tuple: Vec<_> = Vec::with_capacity(17);
        tuple.push(reg_addr[0].clone());
        tuple.extend_from_slice(&value);
        tuple.extend_from_slice(&timestamp);

        logup.add_to_relation_with(
            reg_lookup,
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
        lookup_elements: &RegisterMemoryLookupElements,
    ) {
        let is_pad = crate::trace::trace_eval!(trace_eval, Column::IsPadding);
        let is_real = E::F::one() - is_pad[0].clone();

        let reg_addr = crate::trace::trace_eval!(trace_eval, Column::RegAddr);
        let value = crate::trace::trace_eval!(trace_eval, Column::Value);
        let timestamp = crate::trace::trace_eval!(trace_eval, Column::Timestamp);
        let is_write = crate::trace::trace_eval!(trace_eval, Column::IsWrite);
        let prev_value = crate::trace::trace_eval!(trace_eval, Column::PrevValue);

        // Read consistency: for a read (is_write=0) that follows a same-reg
        // entry, the byte-wise value must equal prev_value.  Phase 9b's
        // ledger only has ts=0 writes so this constraint is a no-op here;
        // it becomes load-bearing in Phase 9d once CpuChip starts emitting
        // reads interleaved with writes.
        let is_read = E::F::one() - is_write[0].clone();
        for i in 0..8 {
            eval.add_constraint(
                is_real.clone() * is_read.clone() * (value[i].clone() - prev_value[i].clone())
            );
        }

        // Consumer lookup (negative multiplicity) — tuple mirrors the prover
        // side: (reg_addr[1], value[8], timestamp[8]).
        let mut tuple: Vec<E::F> = Vec::with_capacity(17);
        tuple.push(reg_addr[0].clone());
        for col in &value { tuple.push(col.clone()); }
        for col in &timestamp { tuple.push(col.clone()); }

        eval.add_to_relation(RelationEntry::new(
            lookup_elements,
            (-is_real.clone()).into(),
            &tuple,
        ));

        eval.finalize_logup();
    }
}

/// Compile-time check that NUM_REGS fits in a single byte for RegAddr.
const _: [(); (NUM_REGS <= u8::MAX as usize) as usize - 1] = [];
