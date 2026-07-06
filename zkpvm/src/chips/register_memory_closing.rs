#[allow(unused_imports)]
use alloc::{boxed::Box, vec, vec::Vec};
use stwo::core::fields::m31::BaseField;
#[cfg(feature = "prover")]
use stwo::{
    core::{ColumnVec, fields::qm31::SecureField},
    prover::{
        backend::simd::SimdBackend,
        poly::{BitReversedOrder, circle::CircleEvaluation},
    },
};
use stwo_constraint_framework::{EvalAtRow, RelationEntry};

use crate::air_column::{AirColumn, PreprocessedAirColumn};
use crate::core::step::NUM_REGS;
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
use crate::{framework::BuiltInComponent, lookups::RegisterMemoryLookupElements};

/// RegisterMemoryClosingChip: produces 13 register-memory logup entries
/// for the **final** register state at `ts = closing_ts_for(side_note)`
/// (one past the last real step). Mirrors `RegisterMemoryBoundaryChip`
/// at the other end of the trace.
///
/// Why it exists: it pins the trace's final register state inside the
/// constraint system. The chip produces (reg, final_val_column,
/// closing_ts) into the register-memory relation; the augmented ledger
/// (`build_entries_from_side_note` appends 13 synthetic closing reads —
/// see `chips/register_memory.rs`) consumes the same tuples AND forces
/// `value == prev_value` via the read-consistency constraint, where
/// `prev_value` is the previous ledger row for that register (= the
/// actual last-written value). So the chip's final-value COLUMN is
/// forced to equal the trace's actual final register state.
///
/// BINDING — `proof.final_state.registers` is bound to the trace's TRUE
/// final register state end-to-end:
/// 1. metadata → column: the verifier-side boundary-binding check
///    (`boundary_binding`) recomputes this chip's per-component logup
///    claimed sum from the PUBLIC `final_state.registers`/`timestamp`
///    (a closed-form function of its thirteen (reg, value, closing_ts,
///    is_write=0) tuples) and requires equality with `proof.claimed_sums`
///    — closing the lying-METADATA attack (gate: `tests/boundary_binding.rs`).
/// 2. column → trace: this chip's RegVal column is pinned to the trace's
///    actual final register value by `RegisterMemoryChip` read-consistency,
///    which is now SOUND against a from-scratch prover — the closing read
///    sorts last (max ts) via the ledger's `(reg, ts)` sortedness gadget, its
///    `is_write = 0` is bound by the logup tuple, and the cross-row
///    `prev_value` binding forces its value to equal the previous (= last
///    real) row's value (see `RegisterMemoryChip` and
///    `docs/plans/ledger-read-consistency.md`).
///
/// The FS-transcript mix of the field (see `prove.rs`) makes a finished proof
/// tamper-evident and feeds the boundary states into the lookup-element draw
/// the binding check relies on.
pub struct RegisterMemoryClosingChip;

#[derive(Debug, Copy, Clone, AirColumn)]
pub enum Column {
    /// Register index 0..NUM_REGS-1.
    #[size = 1]
    RegAddr,
    /// Final u64 value as 8 LE bytes — `side_note.final_regs[reg]`.
    #[size = 8]
    RegVal,
    /// Closing timestamp as 8 LE bytes (same on every real row).
    /// One past `side_note.steps.last().unwrap().timestamp` so the
    /// synthetic closing-read entry sorts after every real access
    /// for the same register.
    #[size = 8]
    Ts,
    /// 1 for real entries (0..NUM_REGS), 0 for padding rows.
    #[size = 1]
    IsReal,
}

#[derive(Debug, Copy, Clone, PreprocessedAirColumn)]
#[preprocessed_prefix = "regclose"]
pub enum PreprocessedColumn {}

impl BuiltInComponent for RegisterMemoryClosingChip {
    type PreprocessedColumn = PreprocessedColumn;
    type MainColumn = Column;
    type LookupElements = RegisterMemoryLookupElements;

    fn add_constraints<E: EvalAtRow>(
        &self,
        eval: &mut E,
        trace_eval: TraceEval<PreprocessedColumn, Column, E>,
        lookup_elements: &RegisterMemoryLookupElements,
    ) {
        let reg_addr = crate::trace::trace_eval!(trace_eval, Column::RegAddr);
        let reg_val = crate::trace::trace_eval!(trace_eval, Column::RegVal);
        let ts = crate::trace::trace_eval!(trace_eval, Column::Ts);
        let is_real = crate::trace::trace_eval!(trace_eval, Column::IsReal);

        // Tuple shape: (reg_addr[1], reg_val[8], timestamp[8], is_write[1]) =
        // 18 limbs.  Mirrors the boundary chip's emission so consumers see the
        // same shape; differs in that `ts` is a runtime value here (per-row
        // column) instead of a hardcoded zero, and `is_write = 0` (a read).
        let mut tuple: Vec<E::F> = Vec::with_capacity(18);
        tuple.push(reg_addr[0].clone());
        for col in &reg_val {
            tuple.push(col.clone());
        }
        for col in &ts {
            tuple.push(col.clone());
        }
        // is_write = 0 (the closing entries are synthetic register reads).
        tuple.push(E::F::from(BaseField::from(0u32)));

        // Positive multiplicity = producer (matches boundary chip).
        // The augmented ledger row at ts=closing_ts consumes this with
        // negative multiplicity; balance forces the consumer's value
        // to equal what we produced, and read-consistency in the
        // ledger then forces *that* to equal the prev_value =
        // actual last value of the register in the trace.
        eval.add_to_relation(RelationEntry::new(
            lookup_elements,
            is_real[0].clone().into(),
            &tuple,
        ));

        eval.finalize_logup();
    }
}

#[cfg(feature = "prover")]
impl BuiltInProverComponent for RegisterMemoryClosingChip {
    const IS_PRODUCER: bool = false;

    fn generate_main_trace_immut(&self, side_note: &SideNote) -> FinalizedTrace {
        let log_size = crate::trace::utils::ceil_log2_at_least_lanes(NUM_REGS);
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
        component_trace: ComponentTrace,
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
/// already dominates them. Step-less synthetic harnesses (e.g. the ristretto
/// chip-isolated tests) inject precompile mem-ops with no steps; the per-page
/// closing read must still sort strictly after every such access, so fall back
/// to one past the latest precompile mem-op timestamp.
///
/// `0` for genuinely empty traces (no steps and no precompile mem-ops) — the
/// boundary chip then has no producers either, the augmented ledger has no
/// synthetic closing-read entries, and the closing chip produces nothing
/// (every row is padding with `IsReal = 0`). Defined here (not on `SideNote`)
/// so `chips/register_memory.rs` can call the same helper without pulling the
/// chip module into a circular import.
#[cfg(feature = "prover")]
pub fn closing_ts_for(side_note: &SideNote) -> u64 {
    match side_note.steps.last() {
        Some(last) => last.timestamp + 1,
        None => {
            let max_precompile_ts = side_note
                .blake2b_mem_ops
                .iter()
                .map(|m| m.ts)
                .chain(side_note.ristretto_mem_ops.iter().map(|m| m.ts))
                .chain(side_note.ristretto_add_mem_ops.iter().map(|m| m.ts))
                .chain(side_note.scalar_binop_mem_ops.iter().map(|m| m.ts))
                .chain(side_note.scalar_reduce_wide_mem_ops.iter().map(|m| m.ts))
                .max();
            match max_precompile_ts {
                Some(ts) => ts + 1,
                None => 0,
            }
        }
    }
}
