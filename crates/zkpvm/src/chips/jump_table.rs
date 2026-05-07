//! JumpTableChip — preprocessed table committing to the program's
//! jump_table[].  Closes the JumpInd / LoadImmJumpInd target-trust
//! soundness gap (Phase 13d).
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

#[allow(unused_imports)]
use alloc::{boxed::Box, vec, vec::Vec};
use stwo::core::fields::m31::BaseField;
#[cfg(feature = "prover")]
use stwo::{
    core::{
        fields::qm31::SecureField,
        ColumnVec,
    },
    prover::{
        backend::simd::SimdBackend,
        poly::{circle::CircleEvaluation, BitReversedOrder},
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

use crate::{
    framework::BuiltInComponent,
    lookups::JumpTableLookupElements,
};
#[cfg(feature = "prover")]
use crate::framework::BuiltInProverComponent;
#[cfg(feature = "prover")]
use crate::lookups::{AllLookupElements, LogupTraceBuilder};
#[cfg(feature = "prover")]
use crate::side_note::SideNote;

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
}

impl BuiltInComponent for JumpTableChip {
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
        let mult = crate::trace::trace_eval!(trace_eval, Column::Multiplicity);

        // Tuple: (addr[4], target[4]) — 8 limbs.
        let mut tuple: Vec<E::F> = addr.to_vec();
        tuple.extend_from_slice(&target);

        // Producer (negative multiplicity).
        eval.add_to_relation(RelationEntry::new(
            lookup_elements,
            (-mult[0].clone()).into(),
            &tuple,
        ));

        eval.finalize_logup();
    }
}

#[cfg(feature = "prover")]
impl BuiltInProverComponent for JumpTableChip {
    const IS_PRODUCER: bool = false;

    fn generate_preprocessed_trace(
        &self,
        _log_size: u32,
        side_note: &SideNote,
    ) -> FinalizedTrace {
        let log_size = chip_log_size(side_note.jump_table.len());
        let mut trace = TraceBuilder::<PreprocessedColumn>::new(log_size);
        let num_rows = trace.num_rows();

        for row in 0..num_rows {
            if row < side_note.jump_table.len() {
                let addr: u32 = 2 * ((row as u32) + 1);
                trace.fill_columns_bytes(row, &addr.to_le_bytes(), PreprocessedColumn::Addr);
                trace.fill_columns_bytes(
                    row, &side_note.jump_table[row].to_le_bytes(),
                    PreprocessedColumn::Target,
                );
            }
            // Padding rows: addr/target stay at 0.
        }

        trace.finalize_bit_reversed()
    }

    fn generate_main_trace_immut(&self, side_note: &SideNote) -> FinalizedTrace {
        let log_size = chip_log_size(side_note.jump_table.len());
        let mut trace = TraceBuilder::<Column>::new(log_size);
        let num_rows = trace.num_rows();

        for row in 0..num_rows {
            // CpuChip emits 2 paired JumpInd lookups per step (so the
            // per-pair degree stays under 4 — same trick as
            // ProgramMemory).  Producer multiplicity matches.
            let count = side_note
                .jump_table_counts
                .get(row)
                .copied()
                .unwrap_or(0);
            trace.fill_columns(row, BaseField::from(2 * count), Column::Multiplicity);
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

        let jt: &JumpTableLookupElements = lookup_elements.as_ref();
        let addr = crate::trace::preprocessed_base_column!(component_trace, PreprocessedColumn::Addr);
        let target = crate::trace::preprocessed_base_column!(component_trace, PreprocessedColumn::Target);
        let mult = crate::trace::original_base_column!(component_trace, Column::Multiplicity);

        let mut tuple: Vec<_> = addr.to_vec();
        tuple.extend_from_slice(&target);

        logup.add_to_relation_with(
            jt,
            [mult[0].clone()],
            |[m]| (-m).into(),
            &tuple,
        );

        logup.finalize()
    }
}

#[cfg(feature = "prover")]
fn chip_log_size(len: usize) -> u32 {
    crate::trace::utils::ceil_log2_at_least_lanes(len.max(1))
}
