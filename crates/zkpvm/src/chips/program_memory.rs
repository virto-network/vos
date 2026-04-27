//! ProgramMemoryChip — a preprocessed table mapping each basic-block-starting
//! PC of `code` to its decoded instruction tuple `(opcode, skip_len, reg_a,
//! reg_b, reg_d, imm)`.
//!
//! Phase 13a (this commit) wires the chip in producer-only form: the
//! preprocessed columns hold the canonical decoding, the main column
//! (Multiplicity) starts at zero on every row, and the chip's logup
//! claimed_sum is zero.  Phase 13b will add a CpuChip-side consumer emission
//! that demands `(pc, opcode, skip_len, reg_a, reg_b, reg_d, imm)` per real
//! step; ProgramMemoryChip then provides matching multiplicities, balancing
//! the lookup.  At that point, a prover claiming the wrong opcode/imm/regs
//! at any PC fails verification.
//!
//! Soundness chain:
//!   - The preprocessed columns commit, via the Merkle root the verifier
//!     checks against an expected program commitment, the canonical decoding
//!     of `code` + `bitmask`.  Two programs producing different decodings
//!     yield different commitments; a proof binds to the committed program.
//!   - The lookup tuple in `add_constraints` reads from preprocessed columns
//!     (not main), so the prover cannot smuggle a different tuple even if
//!     they tampered with main columns — main only contributes Multiplicity.
//!   - On non-basic-block-starting PCs all preprocessed fields are zero;
//!     CpuChip steps never have a fully-zero `(pc, opcode, …)` tuple at a
//!     non-zero pc, so consumer demand at those rows yields zero matches.
//!     Padding rows past `code.len()` similarly hold zero.

use alloc::{boxed::Box, vec, vec::Vec};
use stwo::core::fields::m31::BaseField;
#[cfg(feature = "prover")]
use stwo::{
    core::{
        fields::qm31::SecureField,
        ColumnVec,
    },
    prover::{
        backend::simd::{m31::LOG_N_LANES, SimdBackend},
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
    lookups::ProgramMemoryLookupElements,
};
#[cfg(feature = "prover")]
use crate::framework::BuiltInProverComponent;
#[cfg(feature = "prover")]
use crate::lookups::{AllLookupElements, LogupTraceBuilder};
#[cfg(feature = "prover")]
use crate::side_note::SideNote;

pub struct ProgramMemoryChip;

#[derive(Debug, Copy, Clone, AirColumn)]
pub enum Column {
    /// Number of CpuChip steps that fetched the instruction at this PC.  In
    /// Phase 13a this is always 0; Phase 13b populates it from CpuChip's
    /// per-step ProgramMemory consumer demand.
    #[size = 1]
    Multiplicity,
}

#[derive(Debug, Copy, Clone, PreprocessedAirColumn)]
#[preprocessed_prefix = "progmem"]
pub enum PreprocessedColumn {
    /// PC at this row (4 bytes, little-endian).  Equals the row index for
    /// rows in [0, code.len()); zero for padding rows past code.len().
    #[size = 4]
    Pc,
    /// Opcode byte at PC (0 if non-basic-block-start or padding).
    #[size = 1]
    Opcode,
    /// Skip length ℓ — distance to the next basic-block start (0 for
    /// non-BBS / padding).
    #[size = 1]
    SkipLen,
    /// Decoded reg_a (0 for ops without ra; 0 for non-BBS / padding).
    #[size = 1]
    RegA,
    /// Decoded reg_b (0 for ops without rb; 0 for non-BBS / padding).
    #[size = 1]
    RegB,
    /// Decoded reg_d (0 for ops without rd; 0 for non-BBS / padding).
    #[size = 1]
    RegD,
    /// Decoded immediate (0 for ops without an immediate; 0 for non-BBS /
    /// padding).
    #[size = 8]
    Imm,
}

impl BuiltInComponent for ProgramMemoryChip {
    type PreprocessedColumn = PreprocessedColumn;
    type MainColumn = Column;
    type LookupElements = ProgramMemoryLookupElements;

    fn add_constraints<E: EvalAtRow>(
        &self,
        eval: &mut E,
        trace_eval: TraceEval<PreprocessedColumn, Column, E>,
        lookup_elements: &ProgramMemoryLookupElements,
    ) {
        let pc = crate::trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::Pc);
        let opcode = crate::trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::Opcode);
        let skip_len = crate::trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::SkipLen);
        let reg_a = crate::trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::RegA);
        let reg_b = crate::trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::RegB);
        let reg_d = crate::trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::RegD);
        let imm = crate::trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::Imm);
        let mult = crate::trace::trace_eval!(trace_eval, Column::Multiplicity);

        // Tuple: (pc[4], opcode, skip_len, reg_a, reg_b, reg_d, imm[8]) — 18 limbs.
        // Sourced from preprocessed columns so the program identity binds
        // through the preprocessed Merkle commitment.
        let mut tuple: Vec<E::F> = pc.to_vec();
        tuple.push(opcode[0].clone());
        tuple.push(skip_len[0].clone());
        tuple.push(reg_a[0].clone());
        tuple.push(reg_b[0].clone());
        tuple.push(reg_d[0].clone());
        tuple.extend_from_slice(&imm);

        // Producer side: negative multiplicity, like the other table chips.
        eval.add_to_relation(RelationEntry::new(
            lookup_elements,
            (-mult[0].clone()).into(),
            &tuple,
        ));

        eval.finalize_logup();
    }
}

#[cfg(feature = "prover")]
impl BuiltInProverComponent for ProgramMemoryChip {
    fn generate_preprocessed_trace(
        &self,
        _log_size: u32,
        side_note: &SideNote,
    ) -> FinalizedTrace {
        let log_size = chip_log_size(side_note.code.len());
        let mut trace = TraceBuilder::<PreprocessedColumn>::new(log_size);
        let num_rows = trace.num_rows();

        for row in 0..num_rows {
            let pc = row as u32;
            // Always fill PC even on non-BBS / padding rows — keeps the
            // tuple definitionally `(pc, …)`.  Tuples on those rows are
            // (pc, 0, 0, 0, 0, 0, 0); consumers never demand them.
            trace.fill_columns_bytes(row, &pc.to_le_bytes(), PreprocessedColumn::Pc);

            let bbs = (row < side_note.code.len())
                && side_note.bitmask.get(row).copied().unwrap_or(0) == 1;
            if bbs {
                let (opcode, skip_len, ra, rb, rd, imm) = decode_at(
                    &side_note.code, &side_note.bitmask, row,
                );
                trace.fill_columns(row, opcode, PreprocessedColumn::Opcode);
                trace.fill_columns(row, skip_len, PreprocessedColumn::SkipLen);
                trace.fill_columns(row, ra, PreprocessedColumn::RegA);
                trace.fill_columns(row, rb, PreprocessedColumn::RegB);
                trace.fill_columns(row, rd, PreprocessedColumn::RegD);
                trace.fill_columns(row, imm, PreprocessedColumn::Imm);
            }
            // Non-BBS / padding rows: opcode/skip_len/regs/imm stay at 0.
        }

        trace.finalize_bit_reversed()
    }

    fn generate_main_trace(&self, side_note: &mut SideNote) -> FinalizedTrace {
        let log_size = chip_log_size(side_note.code.len());
        let mut trace = TraceBuilder::<Column>::new(log_size);
        let num_rows = trace.num_rows();

        for row in 0..num_rows {
            let pc = row as u32;
            let mult = side_note
                .program_memory_counts
                .get(&pc)
                .copied()
                .unwrap_or(0);
            trace.fill_columns(row, BaseField::from(mult), Column::Multiplicity);
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

        let prog_mem: &ProgramMemoryLookupElements = lookup_elements.as_ref();
        let pc = crate::trace::preprocessed_base_column!(component_trace, PreprocessedColumn::Pc);
        let opcode = crate::trace::preprocessed_base_column!(component_trace, PreprocessedColumn::Opcode);
        let skip_len = crate::trace::preprocessed_base_column!(component_trace, PreprocessedColumn::SkipLen);
        let reg_a = crate::trace::preprocessed_base_column!(component_trace, PreprocessedColumn::RegA);
        let reg_b = crate::trace::preprocessed_base_column!(component_trace, PreprocessedColumn::RegB);
        let reg_d = crate::trace::preprocessed_base_column!(component_trace, PreprocessedColumn::RegD);
        let imm = crate::trace::preprocessed_base_column!(component_trace, PreprocessedColumn::Imm);
        let mult = crate::trace::original_base_column!(component_trace, Column::Multiplicity);

        // Build tuple from preprocessed columns.
        let mut tuple: Vec<_> = pc.to_vec();
        tuple.push(opcode[0].clone());
        tuple.push(skip_len[0].clone());
        tuple.push(reg_a[0].clone());
        tuple.push(reg_b[0].clone());
        tuple.push(reg_d[0].clone());
        tuple.extend_from_slice(&imm);

        // Producer (negative multiplicity).
        logup.add_to_relation_with(
            prog_mem,
            [mult[0].clone()],
            |[m]| (-m).into(),
            &tuple,
        );

        logup.finalize()
    }
}

/// Compute the chip's log_size: at least LOG_N_LANES, large enough to hold
/// every PC in 0..code_len.  Uses ceil_log2 with a floor at LOG_N_LANES.
#[cfg(feature = "prover")]
fn chip_log_size(code_len: usize) -> u32 {
    crate::trace::utils::ceil_log2_at_least_lanes(code_len.max(1))
}

/// Decode the instruction at `pc` (which must be a basic-block start) into
/// (opcode, skip_len, ra, rb, rd, imm).  Mirrors the tracer's per-step
/// decoding so the preprocessed table tuple matches CpuChip's per-step
/// columns 1:1.  Used only at preprocessed-trace generation, hence prover-only.
#[cfg(feature = "prover")]
fn decode_at(code: &[u8], bitmask: &[u8], pc: usize) -> (u8, u8, u8, u8, u8, u64) {
    use javm::args;
    use javm::instruction::Opcode;

    let opcode_byte = code[pc];
    let opcode = Opcode::from_byte(opcode_byte).unwrap_or(Opcode::Trap);
    let category = opcode.category();
    let skip_len = crate::core::tracing::compute_skip(bitmask, pc);
    let decoded_args = args::decode_args(code, pc, skip_len as usize, category);
    let (ra, rb, rd) = crate::core::tracing::decode_reg_indices(opcode, &decoded_args);
    let imm = crate::core::tracing::decode_immediate(&decoded_args);
    (opcode_byte, skip_len as u8, ra as u8, rb as u8, rd as u8, imm)
}
