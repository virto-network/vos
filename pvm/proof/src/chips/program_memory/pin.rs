//! The chip's pin code: its preprocessed columns, which the preprocessed
//! root a verifier holds commits.

use super::*;
use crate::side_note::SideNote;
use crate::trace::builder::{FinalizedTrace, TraceBuilder};

impl ProgramMemoryChip {
    /// The preprocessed columns at `log_size`, `side_note` the program's
    /// (`BuiltInProverComponent::generate_preprocessed_trace`).
    pub(super) fn preprocessed_trace(&self, log_size: u32, side_note: &SideNote) -> FinalizedTrace {
        let log_size = chip_log_size(side_note.code.len()).max(log_size);
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
}

/// The least log size whose rows hold the table: a smaller one cannot pin
/// it.
pub(crate) fn table_log_size(side_note: &SideNote) -> u32 {
    chip_log_size(side_note.code.len())
}

/// Compute the chip's log_size: at least LOG_N_LANES, large enough to hold
/// every PC in 0..code_len.  Uses ceil_log2 with a floor at LOG_N_LANES.
pub(super) fn chip_log_size(code_len: usize) -> u32 {
    crate::trace::utils::ceil_log2_at_least_lanes(code_len.max(1))
}

/// Decoded instruction tuple at one PC.  Keeps the flag array as the
/// source-of-truth (matches `classify_opcode_for_program_memory`) and
/// `pack_flags` derives the packed bytes that land in the preprocessed
/// FlagByte columns.
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

/// Decode the instruction at `pc` (an instruction start) into
/// the canonical tuple consumed by CpuChip.  Mirrors the tracer's per-step
/// decoding plus classify_opcode's flag derivation, so the preprocessed
/// table 1:1 reproduces what CpuChip's main columns hold for the matching
/// step.  Used only at preprocessed-trace generation, hence prover-only.
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
    // does, where the machine panics. The pin's program is refused when a
    // static target is no basic block start (`kernel::kernel_side_note`,
    // as `derive`), so a pinned program never fails this.
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
