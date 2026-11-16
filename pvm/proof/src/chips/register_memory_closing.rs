use crate::prelude::*;
use stwo::core::fields::m31::BaseField;
use stwo_constraint_framework::{EvalAtRow, RelationEntry};

use crate::air_column::{AirColumn, PreprocessedAirColumn};
use crate::core::step::NUM_REGS;
use crate::trace::eval::TraceEval;

use crate::{
    framework::{BuiltInComponent, Logup},
    lookups::RegisterMemoryLookupElements,
};

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
///    — closing the lying-METADATA attack (gate: `tests/gates/boundary_binding.rs`).
/// 2. column → trace: this chip's RegVal column is pinned to the trace's
///    actual final register value by `RegisterMemoryChip` read-consistency,
///    which is sound against a from-scratch prover: the closing read
///    sorts last (max ts) via the ledger's `(reg, ts)` sortedness gadget, its
///    `is_write = 0` is bound by the logup tuple, and the cross-row
///    `prev_value` binding forces its value to equal the previous (= last
///    real) row's value (see `RegisterMemoryChip` and
///    `docs/design/ledger-read-consistency.md`).
///
/// The FS-transcript mix of the field (see `prove.rs`) makes a finished proof
/// tamper-evident and feeds the boundary states into the lookup-element draw
/// the binding check relies on.
#[derive(Clone, Copy)]
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
    const LOGUP: Logup = Logup::Single;
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
    }
}

#[cfg(feature = "prover")]
mod fill;
#[cfg(feature = "prover")]
pub use fill::closing_ts_for;
