//! ProgramMemoryChip — a preprocessed table mapping each basic-block-starting
//! PC of `code` to its decoded instruction tuple `(opcode, skip_len, reg_a,
//! reg_b, reg_d, imm, flag_bytes[10], imm_y_canon[5], branch_target_canon,
//! host_call_precompile_dispatch)`.
//!
//! The tuple's flag bag carries per-opcode category/sub-category flags and
//! the instruction's register accesses, so a prover can't clear or swap
//! flags to skip or change per-op constraints, or read and write registers
//! other than the instruction's.  The 80 individual flag bits are packed
//! into 10 bytes on BOTH the prog_mem preprocessed table and CpuChip's main
//! trace.  CpuChip binds each individual flag column (or its
//! sum-of-sub-flags expression for the 5 folded category slots) to its
//! packed byte: by 6 byte-to-bits lookups per row for bytes 0..5, by its
//! own recomposition constraints for bytes 6..9.  The prog_mem tuple is 37
//! limbs.
//!
//! Soundness chain:
//!   - The preprocessed columns commit, via the Merkle root the verifier
//!     checks against an expected program commitment, the canonical decoding
//!     of `code` + `bitmask`.  Two programs producing different decodings
//!     yield different commitments; a proof binds to the committed program.
//!   - The lookup tuple in `add_constraints` reads from preprocessed columns
//!     (not main), so the prover cannot smuggle a different tuple even if
//!     they tampered with main columns — main only contributes Multiplicity.
//!   - On non-basic-block-starting PCs, and on padding rows past
//!     `code.len()`, all preprocessed fields but the pc are zero, and the
//!     preprocessed `IsInstruction` refuses them any multiplicity: a step
//!     of opcode 0 and no flags would otherwise fetch the zero tuple, a
//!     no-op that only advances its pc.
//!   - Each FlagByte_i on CpuChip is bound to the canonical
//!     packed byte via the prog_mem lookup balance; the byte-to-bits
//!     lookup or the recomposition binds each individual flag column to
//!     its bit slot in FlagByte_i.  Composed, every individual flag column
//!     is pinned to its canonical value for every real step.

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
use crate::{framework::BuiltInComponent, lookups::ProgramMemoryLookupElements};

pub struct ProgramMemoryChip;

#[derive(Debug, Copy, Clone, AirColumn)]
pub enum Column {
    /// Number of CpuChip steps that fetched the instruction at this PC.
    /// Populated from CpuChip's per-step ProgramMemory consumer demand.
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
    /// Exact encoded opcode byte at PC (0 if non-basic-block-start or
    /// padding). Retaining the raw byte prevents invalid encodings from
    /// aliasing canonical Trap.
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
    /// 10 packed flag bytes.  Each byte holds 8 of the 80
    /// canonical flags as bits 0..7.  Layout per byte is documented in
    /// `lookups/relations.rs` next to `PROG_MEMORY_N_FLAG_BYTES`.
    /// CpuChip's matching FlagByte0..9 main columns carry the same
    /// packing; a byte-to-bits lookup (bytes 0..5) or CpuChip's own
    /// recomposition (bytes 6..9) per row pins individual flag columns
    /// to their bit slot.
    #[size = 1]
    FlagByte0,
    #[size = 1]
    FlagByte1,
    #[size = 1]
    FlagByte2,
    #[size = 1]
    FlagByte3,
    #[size = 1]
    FlagByte4,
    #[size = 1]
    FlagByte5,
    #[size = 1]
    FlagByte6,
    #[size = 1]
    FlagByte7,
    #[size = 1]
    FlagByte8,
    #[size = 1]
    FlagByte9,
    /// Low 5 bytes of canonical `imm_y`, sign-extended from at most 4
    /// bytes, so byte 4 is each of its high bytes: LoadImmJumpInd's jump
    /// offset and an immediate store's value.  0 for ops without a second
    /// immediate.  Bound to CpuChip's ImmYBytes column via the prog_mem
    /// tuple lookup.
    #[size = 5]
    ImmYCanon,
    /// Canonical absolute target for static
    /// jumps/branches at this PC, as 4 little-endian bytes.  Computed
    /// from bytecode as `pc + sign_extend(signed_offset)`.  For ops
    /// whose target isn't determined by bytecode (JumpInd / LoadImmJumpInd
    /// — runtime-dependent on regs) and for non-branch/jump ops, this
    /// is 0.  Bound to CpuChip's BranchTarget column via the prog_mem
    /// tuple lookup, so a prover can't forge a static-jump destination.
    #[size = 4]
    BranchTargetCanon,
    /// Exact precompile dispatch identifier for an ECALLI instruction
    /// (100 or 101), or zero for any other instruction or
    /// identifier. Non-zero exactly for the calls the proof runtime handles,
    /// so it also commits the host-dispatch policy.
    #[size = 1]
    HostCallPrecompileDispatch,
    /// 1 iff an instruction starts at this PC. Only such a row is
    /// fetched: every other holds the zero tuple, which a step of opcode 0
    /// and no flags would match, a no-op that only advances its pc.
    #[size = 1]
    IsInstruction,
}

/// The packed flag bytes, in tuple order.
const FLAG_BYTES: [PreprocessedColumn; crate::lookups::PROG_MEMORY_N_FLAG_BYTES] = [
    PreprocessedColumn::FlagByte0,
    PreprocessedColumn::FlagByte1,
    PreprocessedColumn::FlagByte2,
    PreprocessedColumn::FlagByte3,
    PreprocessedColumn::FlagByte4,
    PreprocessedColumn::FlagByte5,
    PreprocessedColumn::FlagByte6,
    PreprocessedColumn::FlagByte7,
    PreprocessedColumn::FlagByte8,
    PreprocessedColumn::FlagByte9,
];

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
        let skip_len =
            crate::trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::SkipLen);
        let reg_a = crate::trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::RegA);
        let reg_b = crate::trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::RegB);
        let reg_d = crate::trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::RegD);
        let imm = crate::trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::Imm);
        let flag_bytes =
            FLAG_BYTES.map(|column| trace_eval.preprocessed_column_eval::<1>(column)[0].clone());
        let imm_y_canon =
            crate::trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::ImmYCanon);
        let branch_target_canon = crate::trace::preprocessed_trace_eval!(
            trace_eval,
            PreprocessedColumn::BranchTargetCanon
        );
        let host_call_precompile_dispatch = crate::trace::preprocessed_trace_eval!(
            trace_eval,
            PreprocessedColumn::HostCallPrecompileDispatch
        );
        let mult = crate::trace::trace_eval!(trace_eval, Column::Multiplicity);
        let is_instruction =
            crate::trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::IsInstruction);
        eval.add_constraint(
            (E::F::from(BaseField::from(1u32)) - is_instruction[0].clone()) * mult[0].clone(),
        );

        // Tuple: pc[4] + opcode + skip_len + reg_a + reg_b + reg_d + imm[8]
        //        + 10 packed flag bytes + imm_y_canon[5] + branch_target_canon[4]
        //        + host_call_precompile_dispatch = 37 limbs.
        let mut tuple: Vec<E::F> = pc.to_vec();
        tuple.push(opcode[0].clone());
        tuple.push(skip_len[0].clone());
        tuple.push(reg_a[0].clone());
        tuple.push(reg_b[0].clone());
        tuple.push(reg_d[0].clone());
        tuple.extend_from_slice(&imm);
        tuple.extend(flag_bytes);
        tuple.extend_from_slice(&imm_y_canon);
        tuple.extend_from_slice(&branch_target_canon);
        tuple.push(host_call_precompile_dispatch[0].clone());

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
    const IS_PRODUCER: bool = false;

    fn generate_preprocessed_trace(&self, _log_size: u32, side_note: &SideNote) -> FinalizedTrace {
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
                trace.fill_columns(row, true, PreprocessedColumn::IsInstruction);
                let d = decode_at(&side_note.code, &side_note.bitmask, row);
                trace.fill_columns(row, d.opcode, PreprocessedColumn::Opcode);
                trace.fill_columns(row, d.skip_len, PreprocessedColumn::SkipLen);
                trace.fill_columns(row, d.ra, PreprocessedColumn::RegA);
                trace.fill_columns(row, d.rb, PreprocessedColumn::RegB);
                trace.fill_columns(row, d.rd, PreprocessedColumn::RegD);
                trace.fill_columns(row, d.imm, PreprocessedColumn::Imm);
                trace.fill_columns_bytes(
                    row,
                    &d.branch_target_canon.to_le_bytes(),
                    PreprocessedColumn::BranchTargetCanon,
                );
                trace.fill_columns_bytes(
                    row,
                    &d.imm_y_canon.to_le_bytes()[..5],
                    PreprocessedColumn::ImmYCanon,
                );
                trace.fill_columns(
                    row,
                    d.host_call_precompile_dispatch,
                    PreprocessedColumn::HostCallPrecompileDispatch,
                );
                // Pack the canonical flags into their bytes (bit i of byte
                // k = flag[8*k + i]).
                for (column, byte) in FLAG_BYTES.into_iter().zip(pack_flags(&d.flags)) {
                    trace.fill_columns(row, byte, column);
                }
            }
            // Non-BBS / padding rows: opcode/skip_len/regs/imm/flag_bytes stay at 0.
        }

        trace.finalize_bit_reversed()
    }

    fn generate_main_trace_immut(&self, side_note: &SideNote) -> FinalizedTrace {
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
        let opcode =
            crate::trace::preprocessed_base_column!(component_trace, PreprocessedColumn::Opcode);
        let skip_len =
            crate::trace::preprocessed_base_column!(component_trace, PreprocessedColumn::SkipLen);
        let reg_a =
            crate::trace::preprocessed_base_column!(component_trace, PreprocessedColumn::RegA);
        let reg_b =
            crate::trace::preprocessed_base_column!(component_trace, PreprocessedColumn::RegB);
        let reg_d =
            crate::trace::preprocessed_base_column!(component_trace, PreprocessedColumn::RegD);
        let imm = crate::trace::preprocessed_base_column!(component_trace, PreprocessedColumn::Imm);
        let flag_bytes = FLAG_BYTES
            .map(|column| component_trace.preprocessed_base_column::<1, _>(column)[0].clone());
        let imm_y_canon =
            crate::trace::preprocessed_base_column!(component_trace, PreprocessedColumn::ImmYCanon);
        let branch_target_canon = crate::trace::preprocessed_base_column!(
            component_trace,
            PreprocessedColumn::BranchTargetCanon
        );
        let host_call_precompile_dispatch = crate::trace::preprocessed_base_column!(
            component_trace,
            PreprocessedColumn::HostCallPrecompileDispatch
        );
        let mult = crate::trace::original_base_column!(component_trace, Column::Multiplicity);

        // Build the 37-limb tuple from preprocessed columns.
        let mut tuple: Vec<_> = pc.to_vec();
        tuple.push(opcode[0].clone());
        tuple.push(skip_len[0].clone());
        tuple.push(reg_a[0].clone());
        tuple.push(reg_b[0].clone());
        tuple.push(reg_d[0].clone());
        tuple.extend_from_slice(&imm);
        tuple.extend(flag_bytes);
        tuple.extend_from_slice(&imm_y_canon);
        tuple.extend_from_slice(&branch_target_canon);
        tuple.push(host_call_precompile_dispatch[0].clone());

        // Producer (negative multiplicity).
        logup.add_to_relation_with(prog_mem, [mult[0].clone()], |[m]| (-m).into(), &tuple);

        logup.finalize()
    }
}

/// Compute the chip's log_size: at least LOG_N_LANES, large enough to hold
/// every PC in 0..code_len.  Uses ceil_log2 with a floor at LOG_N_LANES.
#[cfg(feature = "prover")]
fn chip_log_size(code_len: usize) -> u32 {
    crate::trace::utils::ceil_log2_at_least_lanes(code_len.max(1))
}

/// Decoded instruction tuple at one PC.  Keeps the flag array as the
/// source-of-truth (matches `classify_opcode_for_program_memory`) and
/// `pack_flags` derives the packed bytes that land in the preprocessed
/// FlagByte columns.
#[cfg(feature = "prover")]
struct Decoded {
    opcode: u8,
    skip_len: u8,
    ra: u8,
    rb: u8,
    rd: u8,
    imm: u64,
    host_call_precompile_dispatch: u8,
    flags: [u8; crate::lookups::PROG_MEMORY_N_FLAGS],
    branch_target_canon: u32,
    imm_y_canon: u64,
}

/// Pack the individual flag bits into little-endian bytes: `bytes[k]` has
/// bit `i` set iff `flags[8*k + i] == 1`.
#[cfg(feature = "prover")]
pub(crate) fn pack_flags(
    flags: &[u8; crate::lookups::PROG_MEMORY_N_FLAGS],
) -> [u8; crate::lookups::PROG_MEMORY_N_FLAG_BYTES] {
    let mut out = [0u8; crate::lookups::PROG_MEMORY_N_FLAG_BYTES];
    for (i, &f) in flags.iter().enumerate() {
        debug_assert!(f <= 1, "flag must be 0 or 1");
        out[i / 8] |= (f & 1) << (i % 8);
    }
    out
}

/// Decode the instruction at `pc` (which must be a basic-block start) into
/// the canonical tuple consumed by CpuChip.  Mirrors the tracer's per-step
/// decoding plus classify_opcode's flag derivation, so the preprocessed
/// table 1:1 reproduces what CpuChip's main columns hold for the matching
/// step.  Used only at preprocessed-trace generation, hence prover-only.
#[cfg(feature = "prover")]
fn decode_at(code: &[u8], bitmask: &[u8], pc: usize) -> Decoded {
    use vos_pvm::args;
    use vos_pvm::instruction::Opcode;

    let opcode_byte = code[pc];
    let opcode = Opcode::from_byte(opcode_byte).unwrap_or(Opcode::Trap);
    let category = opcode.category();
    let skip_len = crate::core::tracing::compute_skip(bitmask, pc);
    let decoded_args = args::decode_args(code, pc, skip_len as usize, category);
    let (ra, rb, rd) = crate::core::tracing::decode_reg_indices(opcode, &decoded_args);
    let imm = crate::core::tracing::decode_immediate(&decoded_args);
    let imm_y = crate::core::tracing::decode_imm_y(&decoded_args);
    let branch_target_canon = crate::core::tracing::decode_branch_target(&decoded_args);
    // Only the halt selector of a dynamic jump continues at the halt
    // address; a static jump there would end a segment at it, as a halt
    // does, where the machine panics. `derive` refuses such a program.
    assert_ne!(
        u64::from(branch_target_canon),
        vos_pvm::PVM_HALT_ADDR,
        "the instruction at {pc:#x} jumps statically to the halt address"
    );
    let f = crate::chips::cpu::classify_opcode_for_program_memory(opcode);
    let host_call_precompile_dispatch = if matches!(opcode, Opcode::Ecalli) {
        crate::core::ecall::proof_precompile_dispatch_id(imm)
    } else {
        0
    };
    Decoded {
        opcode: opcode_byte,
        skip_len: skip_len as u8,
        ra: ra as u8,
        rb: rb as u8,
        rd: rd as u8,
        imm,
        host_call_precompile_dispatch,
        flags: f,
        branch_target_canon,
        imm_y_canon: imm_y,
    }
}
