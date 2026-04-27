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
    // ── Phase 13c: category / sub-category flags ──
    // Each flag mirrors classify_opcode's output for the opcode at this PC.
    // Order MUST match the consumer-side tuple in CpuChip.add_constraints.
    #[size = 1] IsAdd,
    #[size = 1] IsSub,
    #[size = 1] IsMul,
    #[size = 1] IsMulUpper,
    #[size = 1] IsBitwise,
    #[size = 1] IsShift,
    #[size = 1] IsCompare,
    #[size = 1] IsMove,
    #[size = 1] Is32Bit,
    #[size = 1] IsBranch,
    #[size = 1] IsJump,
    #[size = 1] IsDivRem,
    #[size = 1] IsLoad,
    #[size = 1] IsStore,
    #[size = 1] IsExit,
    #[size = 1] IsNegAdd,
    #[size = 1] IsReverseBytes,
    #[size = 1] IsZeroExt16,
    #[size = 1] IsSignExt8,
    #[size = 1] IsSignExt16,
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
        // Phase 13c flags (in the canonical order — must match CpuChip consumer).
        let f_is_add = crate::trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::IsAdd);
        let f_is_sub = crate::trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::IsSub);
        let f_is_mul = crate::trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::IsMul);
        let f_is_mul_upper = crate::trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::IsMulUpper);
        let f_is_bitwise = crate::trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::IsBitwise);
        let f_is_shift = crate::trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::IsShift);
        let f_is_compare = crate::trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::IsCompare);
        let f_is_move = crate::trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::IsMove);
        let f_is_32bit = crate::trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::Is32Bit);
        let f_is_branch = crate::trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::IsBranch);
        let f_is_jump = crate::trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::IsJump);
        let f_is_div_rem = crate::trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::IsDivRem);
        let f_is_load = crate::trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::IsLoad);
        let f_is_store = crate::trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::IsStore);
        let f_is_exit = crate::trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::IsExit);
        let f_is_neg_add = crate::trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::IsNegAdd);
        let f_is_reverse_bytes = crate::trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::IsReverseBytes);
        let f_is_zero_ext_16 = crate::trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::IsZeroExt16);
        let f_is_sign_ext_8 = crate::trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::IsSignExt8);
        let f_is_sign_ext_16 = crate::trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::IsSignExt16);
        let mult = crate::trace::trace_eval!(trace_eval, Column::Multiplicity);

        // Tuple: (pc[4], opcode, skip_len, reg_a, reg_b, reg_d, imm[8], 20 flags) — 38 limbs.
        let mut tuple: Vec<E::F> = pc.to_vec();
        tuple.push(opcode[0].clone());
        tuple.push(skip_len[0].clone());
        tuple.push(reg_a[0].clone());
        tuple.push(reg_b[0].clone());
        tuple.push(reg_d[0].clone());
        tuple.extend_from_slice(&imm);
        tuple.push(f_is_add[0].clone());
        tuple.push(f_is_sub[0].clone());
        tuple.push(f_is_mul[0].clone());
        tuple.push(f_is_mul_upper[0].clone());
        tuple.push(f_is_bitwise[0].clone());
        tuple.push(f_is_shift[0].clone());
        tuple.push(f_is_compare[0].clone());
        tuple.push(f_is_move[0].clone());
        tuple.push(f_is_32bit[0].clone());
        tuple.push(f_is_branch[0].clone());
        tuple.push(f_is_jump[0].clone());
        tuple.push(f_is_div_rem[0].clone());
        tuple.push(f_is_load[0].clone());
        tuple.push(f_is_store[0].clone());
        tuple.push(f_is_exit[0].clone());
        tuple.push(f_is_neg_add[0].clone());
        tuple.push(f_is_reverse_bytes[0].clone());
        tuple.push(f_is_zero_ext_16[0].clone());
        tuple.push(f_is_sign_ext_8[0].clone());
        tuple.push(f_is_sign_ext_16[0].clone());

        // Producer: negative multiplicity.
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
                let d = decode_at(&side_note.code, &side_note.bitmask, row);
                trace.fill_columns(row, d.opcode, PreprocessedColumn::Opcode);
                trace.fill_columns(row, d.skip_len, PreprocessedColumn::SkipLen);
                trace.fill_columns(row, d.ra, PreprocessedColumn::RegA);
                trace.fill_columns(row, d.rb, PreprocessedColumn::RegB);
                trace.fill_columns(row, d.rd, PreprocessedColumn::RegD);
                trace.fill_columns(row, d.imm, PreprocessedColumn::Imm);
                // Phase 13c: per-flag fill, in the same order as the lookup tuple.
                let flag_cols = [
                    PreprocessedColumn::IsAdd, PreprocessedColumn::IsSub,
                    PreprocessedColumn::IsMul, PreprocessedColumn::IsMulUpper,
                    PreprocessedColumn::IsBitwise, PreprocessedColumn::IsShift,
                    PreprocessedColumn::IsCompare, PreprocessedColumn::IsMove,
                    PreprocessedColumn::Is32Bit, PreprocessedColumn::IsBranch,
                    PreprocessedColumn::IsJump, PreprocessedColumn::IsDivRem,
                    PreprocessedColumn::IsLoad, PreprocessedColumn::IsStore,
                    PreprocessedColumn::IsExit, PreprocessedColumn::IsNegAdd,
                    PreprocessedColumn::IsReverseBytes, PreprocessedColumn::IsZeroExt16,
                    PreprocessedColumn::IsSignExt8, PreprocessedColumn::IsSignExt16,
                ];
                for (i, col) in flag_cols.iter().enumerate() {
                    trace.fill_columns(row, d.flags[i], *col);
                }
            }
            // Non-BBS / padding rows: opcode/skip_len/regs/imm/flags stay at 0.
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
        let f_is_add = crate::trace::preprocessed_base_column!(component_trace, PreprocessedColumn::IsAdd);
        let f_is_sub = crate::trace::preprocessed_base_column!(component_trace, PreprocessedColumn::IsSub);
        let f_is_mul = crate::trace::preprocessed_base_column!(component_trace, PreprocessedColumn::IsMul);
        let f_is_mul_upper = crate::trace::preprocessed_base_column!(component_trace, PreprocessedColumn::IsMulUpper);
        let f_is_bitwise = crate::trace::preprocessed_base_column!(component_trace, PreprocessedColumn::IsBitwise);
        let f_is_shift = crate::trace::preprocessed_base_column!(component_trace, PreprocessedColumn::IsShift);
        let f_is_compare = crate::trace::preprocessed_base_column!(component_trace, PreprocessedColumn::IsCompare);
        let f_is_move = crate::trace::preprocessed_base_column!(component_trace, PreprocessedColumn::IsMove);
        let f_is_32bit = crate::trace::preprocessed_base_column!(component_trace, PreprocessedColumn::Is32Bit);
        let f_is_branch = crate::trace::preprocessed_base_column!(component_trace, PreprocessedColumn::IsBranch);
        let f_is_jump = crate::trace::preprocessed_base_column!(component_trace, PreprocessedColumn::IsJump);
        let f_is_div_rem = crate::trace::preprocessed_base_column!(component_trace, PreprocessedColumn::IsDivRem);
        let f_is_load = crate::trace::preprocessed_base_column!(component_trace, PreprocessedColumn::IsLoad);
        let f_is_store = crate::trace::preprocessed_base_column!(component_trace, PreprocessedColumn::IsStore);
        let f_is_exit = crate::trace::preprocessed_base_column!(component_trace, PreprocessedColumn::IsExit);
        let f_is_neg_add = crate::trace::preprocessed_base_column!(component_trace, PreprocessedColumn::IsNegAdd);
        let f_is_reverse_bytes = crate::trace::preprocessed_base_column!(component_trace, PreprocessedColumn::IsReverseBytes);
        let f_is_zero_ext_16 = crate::trace::preprocessed_base_column!(component_trace, PreprocessedColumn::IsZeroExt16);
        let f_is_sign_ext_8 = crate::trace::preprocessed_base_column!(component_trace, PreprocessedColumn::IsSignExt8);
        let f_is_sign_ext_16 = crate::trace::preprocessed_base_column!(component_trace, PreprocessedColumn::IsSignExt16);
        let mult = crate::trace::original_base_column!(component_trace, Column::Multiplicity);

        // Build the 38-limb tuple from preprocessed columns.
        let mut tuple: Vec<_> = pc.to_vec();
        tuple.push(opcode[0].clone());
        tuple.push(skip_len[0].clone());
        tuple.push(reg_a[0].clone());
        tuple.push(reg_b[0].clone());
        tuple.push(reg_d[0].clone());
        tuple.extend_from_slice(&imm);
        tuple.push(f_is_add[0].clone());
        tuple.push(f_is_sub[0].clone());
        tuple.push(f_is_mul[0].clone());
        tuple.push(f_is_mul_upper[0].clone());
        tuple.push(f_is_bitwise[0].clone());
        tuple.push(f_is_shift[0].clone());
        tuple.push(f_is_compare[0].clone());
        tuple.push(f_is_move[0].clone());
        tuple.push(f_is_32bit[0].clone());
        tuple.push(f_is_branch[0].clone());
        tuple.push(f_is_jump[0].clone());
        tuple.push(f_is_div_rem[0].clone());
        tuple.push(f_is_load[0].clone());
        tuple.push(f_is_store[0].clone());
        tuple.push(f_is_exit[0].clone());
        tuple.push(f_is_neg_add[0].clone());
        tuple.push(f_is_reverse_bytes[0].clone());
        tuple.push(f_is_zero_ext_16[0].clone());
        tuple.push(f_is_sign_ext_8[0].clone());
        tuple.push(f_is_sign_ext_16[0].clone());

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

/// Decoded instruction tuple at one PC.  Phase 13c adds the 20-flag bag.
#[cfg(feature = "prover")]
struct Decoded {
    opcode: u8,
    skip_len: u8,
    ra: u8,
    rb: u8,
    rd: u8,
    imm: u64,
    flags: [u8; 20],
}

/// Decode the instruction at `pc` (which must be a basic-block start) into
/// the canonical tuple consumed by CpuChip.  Mirrors the tracer's per-step
/// decoding plus classify_opcode's flag derivation, so the preprocessed
/// table 1:1 reproduces what CpuChip's main columns hold for the matching
/// step.  Used only at preprocessed-trace generation, hence prover-only.
#[cfg(feature = "prover")]
fn decode_at(code: &[u8], bitmask: &[u8], pc: usize) -> Decoded {
    use javm::args;
    use javm::instruction::Opcode;

    let opcode_byte = code[pc];
    let opcode = Opcode::from_byte(opcode_byte).unwrap_or(Opcode::Trap);
    let category = opcode.category();
    let skip_len = crate::core::tracing::compute_skip(bitmask, pc);
    let decoded_args = args::decode_args(code, pc, skip_len as usize, category);
    let (ra, rb, rd) = crate::core::tracing::decode_reg_indices(opcode, &decoded_args);
    let imm = crate::core::tracing::decode_immediate(&decoded_args);
    let f = crate::chips::cpu::classify_opcode_for_program_memory(opcode);
    Decoded {
        opcode: opcode_byte,
        skip_len: skip_len as u8,
        ra: ra as u8,
        rb: rb as u8,
        rd: rd as u8,
        imm,
        flags: f,
    }
}
