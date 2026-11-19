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
//! sum-of-sub-flags expression for the 4 folded category slots) to its
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

use crate::prelude::*;
use stwo::core::fields::m31::BaseField;
use stwo_constraint_framework::{EvalAtRow, RelationEntry};

use crate::air_column::{AirColumn, PreprocessedAirColumn};
use crate::trace::eval::TraceEval;

use crate::{
    framework::{BuiltInComponent, Logup},
    lookups::ProgramMemoryLookupElements,
};

#[derive(Clone, Copy)]
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
    const LOGUP: Logup = Logup::Single;
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
    }
}

#[cfg(feature = "prover")]
mod fill;
#[cfg(feature = "prover")]
mod pin;
#[cfg(feature = "prover")]
pub(crate) use pin::jumps_to_halt;
#[cfg(feature = "prover")]
pub(crate) use pin::pack_flags;
#[cfg(feature = "prover")]
pub(crate) use pin::table_log_size;
