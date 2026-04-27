//! Phase 12b: BitManip TwoReg ops.  Positive + negative tests for the
//! constraints added in CpuChip.

use javm::instruction::Opcode;
use javm::interpreter::Interpreter;
use javm::PVM_REGISTER_COUNT;

use zkpvm::core::tracing::TracingPvm;
use zkpvm::{prove, verify};

fn prove_and_verify(
    steps: Vec<zkpvm::core::step::PvmStep>,
    code: &[u8],
    bitmask: &[u8],
) {
    let mut side_note = zkpvm::SideNote::new(steps, code.to_vec(), bitmask.to_vec());
    let proof = prove(&mut side_note).expect("proving failed");
    verify(proof, &side_note).expect("verification failed");
}

/// Encode a TwoReg instruction at `code[0..2]`: opcode + reg_byte where
/// rd = reg_byte & 0xF, ra = (reg_byte >> 4) & 0xF.
fn two_reg_program(op: Opcode, rd: u8, ra: u8) -> (Vec<u8>, Vec<u8>) {
    let reg_byte = (ra << 4) | (rd & 0xF);
    let code = vec![op as u8, reg_byte, Opcode::Trap as u8];
    let bitmask = vec![1, 0, 1];
    (code, bitmask)
}

// ── ReverseBytes ──

#[test]
fn prove_reverse_bytes() {
    let mut regs = [0u64; PVM_REGISTER_COUNT];
    regs[3] = 0x0123_4567_89AB_CDEF;

    // φ[2] = swap_bytes(φ[3]) = 0xEFCDAB8967452301
    let (code, bitmask) = two_reg_program(Opcode::ReverseBytes, 2, 3);

    let pvm = Interpreter::new(code.clone(), bitmask.clone(), vec![], regs, vec![0u8; 4 * 1024 * 1024], 10000, 25);
    let mut tracing = TracingPvm::new(pvm);
    let exit = tracing.run();
    assert_eq!(exit, javm::ExitReason::Trap);

    let steps = tracing.into_trace();
    assert_eq!(steps[0].opcode, Opcode::ReverseBytes);
    assert_eq!(steps[0].regs_after[2], 0xEFCD_AB89_6745_2301);

    prove_and_verify(steps, &code, &bitmask);
}

#[test]
#[should_panic(expected = "ConstraintsNotSatisfied")]
fn reverse_bytes_forged_result_rejected() {
    let mut regs = [0u64; PVM_REGISTER_COUNT];
    regs[3] = 0x0123_4567_89AB_CDEF;

    let (code, bitmask) = two_reg_program(Opcode::ReverseBytes, 2, 3);

    let pvm = Interpreter::new(code.clone(), bitmask.clone(), vec![], regs, vec![0u8; 4 * 1024 * 1024], 10000, 25);
    let mut tracing = TracingPvm::new(pvm);
    let _ = tracing.run();
    let mut steps = tracing.into_trace();

    // Forge: claim φ[2] = 0xDEADBEEF instead of swap_bytes(φ[3]).
    assert_eq!(steps[0].opcode, Opcode::ReverseBytes);
    steps[0].regs_after[2] = 0xDEAD_BEEF_DEAD_BEEF;

    prove_and_verify(steps, &code, &bitmask);
}

// ── ZeroExtend16 ──

#[test]
fn prove_zero_extend_16() {
    let mut regs = [0u64; PVM_REGISTER_COUNT];
    regs[3] = 0xFFFF_FFFF_FFFF_BEEF;

    // φ[2] = φ[3] & 0xFFFF = 0xBEEF
    let (code, bitmask) = two_reg_program(Opcode::ZeroExtend16, 2, 3);

    let pvm = Interpreter::new(code.clone(), bitmask.clone(), vec![], regs, vec![0u8; 4 * 1024 * 1024], 10000, 25);
    let mut tracing = TracingPvm::new(pvm);
    let exit = tracing.run();
    assert_eq!(exit, javm::ExitReason::Trap);

    let steps = tracing.into_trace();
    assert_eq!(steps[0].opcode, Opcode::ZeroExtend16);
    assert_eq!(steps[0].regs_after[2], 0xBEEF);

    prove_and_verify(steps, &code, &bitmask);
}

#[test]
#[should_panic(expected = "ConstraintsNotSatisfied")]
fn zero_extend_16_forged_upper_byte_rejected() {
    let mut regs = [0u64; PVM_REGISTER_COUNT];
    regs[3] = 0xFFFF_FFFF_FFFF_BEEF;

    let (code, bitmask) = two_reg_program(Opcode::ZeroExtend16, 2, 3);

    let pvm = Interpreter::new(code.clone(), bitmask.clone(), vec![], regs, vec![0u8; 4 * 1024 * 1024], 10000, 25);
    let mut tracing = TracingPvm::new(pvm);
    let _ = tracing.run();
    let mut steps = tracing.into_trace();

    // Forge: leave one of the upper bytes set instead of zeroing it.
    assert_eq!(steps[0].opcode, Opcode::ZeroExtend16);
    steps[0].regs_after[2] = 0x0000_0000_0001_BEEF; // byte 2 = 0x01, should be 0

    prove_and_verify(steps, &code, &bitmask);
}

#[test]
#[should_panic(expected = "ConstraintsNotSatisfied")]
fn zero_extend_16_forged_low_byte_rejected() {
    let mut regs = [0u64; PVM_REGISTER_COUNT];
    regs[3] = 0xFFFF_FFFF_FFFF_BEEF;

    let (code, bitmask) = two_reg_program(Opcode::ZeroExtend16, 2, 3);

    let pvm = Interpreter::new(code.clone(), bitmask.clone(), vec![], regs, vec![0u8; 4 * 1024 * 1024], 10000, 25);
    let mut tracing = TracingPvm::new(pvm);
    let _ = tracing.run();
    let mut steps = tracing.into_trace();

    // Forge: change a low byte (should equal val_d's low byte).
    assert_eq!(steps[0].opcode, Opcode::ZeroExtend16);
    steps[0].regs_after[2] = 0xCAFE; // low 16 = 0xCAFE, but val_d low 16 = 0xBEEF

    prove_and_verify(steps, &code, &bitmask);
}
