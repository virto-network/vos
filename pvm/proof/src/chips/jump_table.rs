//! JumpTableChip — preprocessed table committing to the program's
//! jump_table[], which binds the JumpInd / LoadImmJumpInd targets.
//!
//! At runtime, JumpInd computes a virtual address `addr =
//! (regs[reg_a] + imm) mod 2^32` and dispatches to
//! `jump_table[addr/2 - 1]`.  The AIR can't reproduce that lookup
//! row-locally because jump_table[] is program-defined (not opcode-
//! defined); it lives in the side-note alongside `code` and `bitmask`.
//!
//! Soundness chain
//!   - The preprocessed columns `(Addr, Target)` are committed by the
//!     verifier-side Merkle root, which the verifier checks against
//!     the expected program commitment.  Two programs with different
//!     jump tables yield different commitments; a proof binds to
//!     the committed jump table.
//!   - Row N stores `Addr = 2*(N+1)` and `Target = jump_table[N]` for
//!     0 ≤ N < jump_table.len(); padding rows have `Addr = 0`,
//!     `Target = 0`, and Multiplicity = 0.
//!   - CpuChip emits `(JumpIndAddr, NextPc)` per JumpInd step, gated
//!     on IsJumpInd.  JumpTableChip's producer multiplicity counts
//!     those uses.  An attacker forging next_pc to a target not in
//!     the table — or to a target paired with a different addr —
//!     unbalances the lookup.
//!
//! See the matching CpuChip-side carry-chain constraint
//!   `is_jump_ind · (JumpIndAddr[i] + carry[i]·256
//!                   - val_b[i] - imm_bytes[i] - carry[i-1]) = 0`
//! that pins JumpIndAddr to the runtime-computed virtual address.

use crate::prelude::*;
use num_traits::One;
use stwo_constraint_framework::{EvalAtRow, RelationEntry};

use crate::air_column::{AirColumn, PreprocessedAirColumn};
use crate::trace::eval::TraceEval;

use crate::{
    framework::{BuiltInComponent, Logup},
    lookups::JumpTableLookupElements,
};

#[derive(Clone, Copy)]
pub struct JumpTableChip;

#[derive(Debug, Copy, Clone, AirColumn)]
pub enum Column {
    /// Number of CpuChip JumpInd steps that dispatched through this row.
    /// Filled from `side_note.jump_table_counts[N]` where N is the row
    /// index.  CpuChip's per-step JumpInd consumer emits 2 paired
    /// lookups, so this multiplicity is doubled at fill time.
    #[size = 1]
    Multiplicity,
}

#[derive(Debug, Copy, Clone, PreprocessedAirColumn)]
#[preprocessed_prefix = "jumptable"]
pub enum PreprocessedColumn {
    /// Virtual jump address at this row, as 4 little-endian bytes.
    /// Row N: `Addr = 2*(N+1)` (so addr=2 → idx 0, addr=4 → idx 1, …)
    /// for valid entries.  Padding rows: `Addr = 0`.
    #[size = 4]
    Addr,
    /// `jump_table[N]` as 4 little-endian bytes.  0 on padding rows.
    #[size = 4]
    Target,
    /// 1 on the table's entries, 0 on its padding rows, whose `(0, 0)`
    /// tuple no dynamic jump may use: a jump to address 0 panics.
    #[size = 1]
    IsEntry,
}

impl BuiltInComponent for JumpTableChip {
    const LOGUP: Logup = Logup::Single;
    type PreprocessedColumn = PreprocessedColumn;
    type MainColumn = Column;
    type LookupElements = JumpTableLookupElements;

    fn add_constraints<E: EvalAtRow>(
        &self,
        eval: &mut E,
        trace_eval: TraceEval<PreprocessedColumn, Column, E>,
        lookup_elements: &JumpTableLookupElements,
    ) {
        let addr = crate::trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::Addr);
        let target = crate::trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::Target);
        let is_entry =
            crate::trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::IsEntry);
        let mult = crate::trace::trace_eval!(trace_eval, Column::Multiplicity);
        eval.add_constraint((E::F::one() - is_entry[0].clone()) * mult[0].clone());

        // Tuple: (addr[4], target[4]) — 8 limbs.
        let mut tuple: Vec<E::F> = addr.to_vec();
        tuple.extend_from_slice(&target);

        // Producer (negative multiplicity).
        eval.add_to_relation(RelationEntry::new(
            lookup_elements,
            (-mult[0].clone()).into(),
            &tuple,
        ));
    }
}

#[cfg(feature = "prover")]
mod fill;
#[cfg(feature = "prover")]
mod pin;
