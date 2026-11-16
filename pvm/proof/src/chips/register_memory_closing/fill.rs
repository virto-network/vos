//! The chip's trace generation, the prover's half.

use super::*;
use crate::framework::BuiltInProverComponent;
use crate::lookups::{AllLookupElements, LogupTraceBuilder};
use crate::side_note::SideNote;
use crate::trace::{
    builder::{FinalizedTrace, TraceBuilder},
    component::ComponentTrace,
};
use stwo::{
    core::{ColumnVec, fields::qm31::SecureField},
    prover::{
        backend::simd::SimdBackend,
        poly::{BitReversedOrder, circle::CircleEvaluation},
    },
};

impl BuiltInProverComponent for RegisterMemoryClosingChip {
    const IS_PRODUCER: bool = false;

    fn generate_main_trace_immut_min(
        &self,
        side_note: &SideNote,
        min_log_size: u32,
    ) -> FinalizedTrace {
        let log_size = crate::trace::utils::ceil_log2_at_least_lanes(NUM_REGS).max(min_log_size);
        let mut trace = TraceBuilder::<Column>::new(log_size);

        // Gate emissions on the same condition the ledger augmentation
        // uses (see `chips/register_memory.rs`'s
        // `build_entries_from_side_note`). When either gate fails — no
        // execution steps to bind a final state to, or the caller's
        // chip slice didn't opt into closing-chip semantics — the chip
        // produces zero rows (all-padding, IsReal=0) so the lookup
        // sum-to-zero check holds without matching consumers.
        if side_note.closing_chip_active && !side_note.steps.is_empty() {
            let closing_ts = closing_ts_for(side_note);
            for (row, &val) in side_note.final_regs.iter().enumerate() {
                trace.fill_columns(row, row as u8, Column::RegAddr);
                trace.fill_columns(row, val, Column::RegVal);
                trace.fill_columns(row, closing_ts, Column::Ts);
                trace.fill_columns(row, true, Column::IsReal);
            }
        }
        // Padding rows (row >= NUM_REGS, or every row when the gate is
        // off) keep all columns = 0 by default; IsReal=0 gates the
        // relation emission off.

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
        use stwo::prover::backend::simd::m31::PackedBaseField;
        let log_size = component_trace.log_size();
        let mut logup = LogupTraceBuilder::new(log_size);

        let reg_lookup: &RegisterMemoryLookupElements = lookup_elements.as_ref();
        let reg_addr = crate::trace::original_base_column!(component_trace, Column::RegAddr);
        let reg_val = crate::trace::original_base_column!(component_trace, Column::RegVal);
        let ts = crate::trace::original_base_column!(component_trace, Column::Ts);
        let is_real = crate::trace::original_base_column!(component_trace, Column::IsReal);

        // Tuple: (reg_addr[1], reg_val[8], timestamp[8], is_write=0) — 18 limbs.
        // Same emission order as `add_constraints` above — must match.
        logup.add_to_relation_computed(
            reg_lookup,
            [is_real[0].clone()],
            |[real]| real.into(),
            18,
            |vec_idx| {
                let mut tuple = Vec::with_capacity(18);
                tuple.push(reg_addr[0].at(vec_idx));
                for col in &reg_val {
                    tuple.push(col.at(vec_idx));
                }
                for col in &ts {
                    tuple.push(col.at(vec_idx));
                }
                tuple.push(PackedBaseField::broadcast(BaseField::from(0u32)));
                tuple
            },
        );

        logup.finalize()
    }
}

/// Closing-read timestamp for `side_note`'s synthetic register-final and
/// per-page memory-boundary ledger entries. One past the last real step's
/// timestamp so the synthetic entries sort strictly after every real access.
///
/// In real traces every precompile mem-op executes during a step, so its
/// timestamp is `<= last_step.timestamp` and `last_step.timestamp + 1`
/// already dominates them. Step-less synthetic harnesses (chip-isolated
/// tests) inject precompile mem-ops with no steps; the per-page
/// closing read must still sort strictly after every such access, so fall back
/// to one past the latest precompile mem-op timestamp.
///
/// `0` for genuinely empty traces (no steps and no precompile mem-ops) — the
/// boundary chip then has no producers either, the augmented ledger has no
/// synthetic closing-read entries, and the closing chip produces nothing
/// (every row is padding with `IsReal = 0`). Defined here (not on `SideNote`)
/// so `chips/register_memory.rs` can call the same helper without pulling the
/// chip module into a circular import.
pub fn closing_ts_for(side_note: &SideNote) -> u64 {
    match side_note.steps.last() {
        Some(last) => last.timestamp + 1,
        None => {
            let max_precompile_ts = (side_note.blake2b_mem_ops.iter().map(|m| m.ts))
                .chain(side_note.poseidon2_ops.iter().map(|op| op.ts))
                .max();
            match max_precompile_ts {
                Some(ts) => ts + 1,
                None => 0,
            }
        }
    }
}
