//! Per-step register-access description shared between CpuChip (which fills
//! the producer side of the register-memory ledger) and RegisterMemoryChip
//! (which builds the ledger itself).
//!
//! The two chips must agree byte-for-byte on the (reg_idx, value, ts) tuples
//! they emit, otherwise the logup balance breaks.  Centralising the
//! derivation here keeps them in sync.

use super::classify::{classify_opcode, uses_immediate};
use crate::core::ecall::{ECALL_BLAKE2B_COMPRESS, ECALL_WITNESS_INPUT};
#[allow(unused_imports)]
use alloc::{boxed::Box, vec, vec::Vec};
use vos_pvm::instruction::Opcode;

/// Register-access descriptor for a single PVM step.  Used by both
/// CpuChip (to fill the ValB/ValD/Result register-source flags + indices) and
/// RegisterMemoryChip (to build the ledger).  Must stay in sync across the two
/// chips because the logup balance depends on matching (reg_idx, value, ts)
/// tuples on both sides.
pub(crate) struct StepRegAccesses {
    /// (reg_idx, value) if ValB came from a register read at this step.
    pub val_b_read: Option<(u8, u64)>,
    /// (reg_idx, value) if ValD came from a register read at this step.
    pub val_d_read: Option<(u8, u64)>,
    /// (reg_idx, value) if the step reads `regs[ra]` for a
    /// purpose not already captured by `val_b_read`.  Currently set
    /// only on `StoreInd[U][8/16/32/64]` rows — there val_b holds the
    /// *base* `regs[rb]`, while the value to be written is `regs[ra]`,
    /// neither of which lands in a column without this read.
    pub val_a_read: Option<(u8, u64)>,
    /// (reg_idx, value) if the step wrote a register.
    pub result_write: Option<(u8, u64)>,
    /// ECALL-specific register reads at the ECALL step's timestamp: they
    /// land in the ledger alongside the regular ValB/ValD reads and match
    /// the producers CpuChip emits gated by the call's selector.  Empty for
    /// every other step.
    pub ecall_reads: Vec<(u8, u64)>,
}

/// The register accesses an instruction's operands and result make, fixed
/// by its opcode alone: ProgramMemory commits them per pc, as five bits of
/// flag byte 6, and CpuChip pins each row's register-source flags and
/// indices to them.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct AccessShape {
    /// ValB reads a register: φA when `val_b_from_a`, otherwise φB. When
    /// it reads none, it is the immediate (the operand swaps CpuChip pins
    /// it on) or unused.
    pub val_b_is_reg: bool,
    pub val_b_from_a: bool,
    /// ValD reads φB; otherwise it is the immediate.
    pub val_d_is_reg: bool,
    /// The instruction writes a register: φD when `result_to_d`, otherwise
    /// φA. A conditional move writes it only when it moves; a call's
    /// writes are its precompile's (the witness input's count to φ7).
    pub result_is_reg: bool,
    pub result_to_d: bool,
}

/// The [`AccessShape`] of `opcode`.
pub(crate) fn access_shape(opcode: Opcode) -> AccessShape {
    use vos_pvm::instruction::InstructionCategory::*;
    let flags = classify_opcode(opcode);
    // The ImmAlt shifts and rotates, SetGt*Imm and Cmov*Imm swap their
    // sources: ValB is the immediate and ValD reads φB.
    let swapped = flags.is_imm_alt || flags.is_set_gt || flags.is_cmov_imm;
    let category = opcode.category();
    let (val_b_is_reg, val_b_from_a) = match category {
        ThreeReg | OneRegImmOffset => (true, true),
        TwoRegOneImm if swapped => (false, false),
        TwoRegOneImm => (true, false),
        TwoReg => (false, false),
        _ if uses_immediate(opcode) => (false, false),
        _ => (true, true),
    };
    let val_d_is_reg = match category {
        TwoRegOneImm => swapped,
        OneRegImmOffset => false,
        _ => !uses_immediate(opcode),
    };
    let result_is_reg = match category {
        NoArgs | OneImm | TwoImm | OneOffset | OneRegTwoImm | TwoRegOneOffset => false,
        OneRegOneImm => !matches!(opcode, Opcode::JumpInd) && !flags.is_store,
        OneRegImmOffset => matches!(opcode, Opcode::LoadImmJump),
        TwoRegOneImm => !flags.is_store,
        OneRegExtImm | TwoReg | TwoRegTwoImm | ThreeReg => true,
    };
    AccessShape {
        val_b_is_reg,
        val_b_from_a,
        val_d_is_reg,
        result_is_reg,
        result_to_d: result_is_reg && category == ThreeReg,
    }
}

/// The register an executed instruction writes, by its opcode's
/// [`AccessShape`] and its decoded registers: its destination, unless it is
/// a conditional move that does not move.
pub(crate) fn static_destination(
    opcode: Opcode,
    reg_a: usize,
    reg_b: usize,
    reg_d: usize,
    regs_before: &[u64],
) -> Option<usize> {
    let shape = access_shape(opcode);
    if !shape.result_is_reg {
        return None;
    }
    let flags = classify_opcode(opcode);
    // CmovIz[Imm] moves when φB is zero, CmovNz[Imm] when it is not.
    if (flags.is_cmov_iz && regs_before[reg_b] != 0)
        || (flags.is_cmov_nz && regs_before[reg_b] == 0)
    {
        return None;
    }
    Some(if shape.result_to_d { reg_d } else { reg_a })
}

/// The step's register reads and write, as the ledger records them.
///
/// Skipped cases: in-trace ValB/ValD get rewritten mid-step
/// for these, so the ledger tuple wouldn't match what the logup emits.
///   - shifts with `shift_op <= 2` rewrite ValD to `2^shift_amount`
///   - 32-bit add/sub/mul/divrem truncate both ValB and ValD to 32 bits
/// When emissions are dropped here, authentication is lost for those reads;
/// dedicated RegValB/RegValD columns and cross-constraints let the ledger
/// see the raw register values.
pub(crate) fn step_reg_accesses(step: &crate::core::step::PvmStep) -> StepRegAccesses {
    let shape = access_shape(step.opcode);
    let val_b_read = shape.val_b_is_reg.then(|| {
        let reg = if shape.val_b_from_a {
            step.reg_a
        } else {
            step.reg_b
        };
        (reg as u8, step.regs_before[reg])
    });
    let val_d_read = shape
        .val_d_is_reg
        .then(|| (step.reg_b as u8, step.regs_before[step.reg_b]));
    // StoreInd source-value read.  TwoRegOneImm's val_b
    // already covers reg_b (the base); val_a_read picks up reg_a
    // (the source value) for StoreInd[U][8/16/32/64].
    let val_a_read = if classify_opcode(step.opcode).is_store_ind {
        Some((step.reg_a as u8, step.regs_before[step.reg_a]))
    } else {
        None
    };
    let result_write = step.reg_write.map(|idx| (idx as u8, step.regs_after[idx]));
    // blake2b ECALL reads φ[7], φ[8], φ[9], φ[10] at this step's
    // ts.  The actor's a0/a1/a2/a3 (h_ptr/m_ptr/
    // t_low/f_flag) map to PVM φ[7/8/9/10] via grey-transpiler's
    // `map_register`.  CpuChip's `ECALL_REG_IDXS` (in
    // `constraints/host_call.rs` and `interaction.rs`) emits register-file
    // producers at [10, 7, 8, 9] — matching this ledger consumer per blake2b
    // ECALL step.
    // ECALL register-read ledger consumers.
    // These must match the producers CpuChip emits gated by the matching
    // Is*Ecall column, otherwise the register-memory logup balance breaks.
    //   blake2b: φ[7,8,9,10] (h_ptr/m_ptr/t_low/f_flag).
    //   witness input: φ[7,8] (destination/capacity), before the step's
    //   write of its count to φ[7].
    // Only a served call reads them (`PvmStep::served_ecall`): for any
    // other the CpuChip emits no producer.
    let ecall = step.served_ecall();
    let is_blake_ecall = ecall == Some(ECALL_BLAKE2B_COMPRESS as u64);
    let is_witness_ecall = ecall == Some(ECALL_WITNESS_INPUT as u64);
    let ecall_reads = if is_blake_ecall {
        vec![
            (7u8, step.regs_before[7]),
            (8u8, step.regs_before[8]),
            (9u8, step.regs_before[9]),
            (10u8, step.regs_before[10]),
        ]
    } else if is_witness_ecall {
        vec![(7u8, step.regs_before[7]), (8u8, step.regs_before[8])]
    } else {
        Vec::new()
    };
    StepRegAccesses {
        val_b_read,
        val_d_read,
        val_a_read,
        result_write,
        ecall_reads,
    }
}
