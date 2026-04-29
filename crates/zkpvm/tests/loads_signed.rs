//! Phase 20: signed-load inactive-byte sign-extension tests.
//!
//! Each test stores a byte/halfword/word with the high bit set, then
//! loads it as signed (LoadIndI8/LoadIndI16/LoadIndI32) and asserts
//! the destination register contains the sign-extended value.  Phase
//! 20 added the AIR constraint that pins inactive bytes of the load
//! result to `0xFF · LoadSignBit`; pre-Phase-20 those bytes were
//! prover-witnessed and unconstrained.

mod common;
use common::*;

use javm::interpreter::Interpreter;
use javm::instruction::Opcode;
use javm::PVM_REGISTER_COUNT;
use javm::ExitReason;

use zkpvm::core::tracing::TracingPvm;

#[test]
fn load_i8_negative_sign_extends() {
    // Store 0x80 (= -128 as i8 → sign-extend to 0xFFFFFFFFFFFFFF80)
    // and read it back via LoadIndI8.
    let mut regs = [0u64; PVM_REGISTER_COUNT];
    regs[0] = 0x80;
    regs[1] = 0x1000;
    let memory = vec![0u8; 4 * 1024 * 1024];

    let code = vec![
        Opcode::StoreIndU8 as u8, 0x10, 0, 0, 0, 0,
        Opcode::LoadIndI8 as u8,  0x12, 0, 0, 0, 0,
        Opcode::Trap as u8,
    ];
    let bitmask = vec![1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1];

    let pvm = Interpreter::new(code.clone(), bitmask.clone(), vec![], regs, memory, 10_000, 25);
    let mut tracing = TracingPvm::new(pvm);
    assert_eq!(tracing.run(), ExitReason::Trap);
    let steps = tracing.into_trace();

    // Sign-extended -128 as u64 = 0xFFFFFFFFFFFFFF80.
    assert_eq!(steps[1].regs_after[2], 0xFFFF_FFFF_FFFF_FF80);
    prove_and_verify(steps, &code, &bitmask);
}

#[test]
fn load_i16_negative_sign_extends() {
    let mut regs = [0u64; PVM_REGISTER_COUNT];
    regs[0] = 0x8000; // low 16 = -32768 (i16)
    regs[1] = 0x1000;
    let memory = vec![0u8; 4 * 1024 * 1024];

    let code = vec![
        Opcode::StoreIndU16 as u8, 0x10, 0, 0, 0, 0,
        Opcode::LoadIndI16 as u8,  0x12, 0, 0, 0, 0,
        Opcode::Trap as u8,
    ];
    let bitmask = vec![1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1];

    let pvm = Interpreter::new(code.clone(), bitmask.clone(), vec![], regs, memory, 10_000, 25);
    let mut tracing = TracingPvm::new(pvm);
    assert_eq!(tracing.run(), ExitReason::Trap);
    let steps = tracing.into_trace();

    assert_eq!(steps[1].regs_after[2], 0xFFFF_FFFF_FFFF_8000);
    prove_and_verify(steps, &code, &bitmask);
}

#[test]
fn load_i32_negative_sign_extends() {
    let mut regs = [0u64; PVM_REGISTER_COUNT];
    regs[0] = 0x8000_0000; // low 32 = INT32_MIN
    regs[1] = 0x1000;
    let memory = vec![0u8; 4 * 1024 * 1024];

    let code = vec![
        Opcode::StoreIndU32 as u8, 0x10, 0, 0, 0, 0,
        Opcode::LoadIndI32 as u8,  0x12, 0, 0, 0, 0,
        Opcode::Trap as u8,
    ];
    let bitmask = vec![1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1];

    let pvm = Interpreter::new(code.clone(), bitmask.clone(), vec![], regs, memory, 10_000, 25);
    let mut tracing = TracingPvm::new(pvm);
    assert_eq!(tracing.run(), ExitReason::Trap);
    let steps = tracing.into_trace();

    assert_eq!(steps[1].regs_after[2], 0xFFFF_FFFF_8000_0000);
    prove_and_verify(steps, &code, &bitmask);
}

#[test]
fn load_i8_positive_zero_extends() {
    // Sanity: positive byte loads with zero sign extension.
    let mut regs = [0u64; PVM_REGISTER_COUNT];
    regs[0] = 0x42;
    regs[1] = 0x1000;
    let memory = vec![0u8; 4 * 1024 * 1024];

    let code = vec![
        Opcode::StoreIndU8 as u8, 0x10, 0, 0, 0, 0,
        Opcode::LoadIndI8 as u8,  0x12, 0, 0, 0, 0,
        Opcode::Trap as u8,
    ];
    let bitmask = vec![1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1];

    let pvm = Interpreter::new(code.clone(), bitmask.clone(), vec![], regs, memory, 10_000, 25);
    let mut tracing = TracingPvm::new(pvm);
    assert_eq!(tracing.run(), ExitReason::Trap);
    let steps = tracing.into_trace();

    assert_eq!(steps[1].regs_after[2], 0x42);
    prove_and_verify(steps, &code, &bitmask);
}

#[test]
#[should_panic(expected = "failed")]
fn load_i8_negative_forged_high_byte_rejected() {
    // Store 0x80 (negative i8 → -128); honest load yields
    // 0xFFFFFFFFFFFFFF80.  Forge to drop the high 0xFF byte → mismatch
    // detected by the new inactive-byte sign-extension constraint.
    let mut regs = [0u64; PVM_REGISTER_COUNT];
    regs[0] = 0x80;
    regs[1] = 0x1000;
    let memory = vec![0u8; 4 * 1024 * 1024];

    let code = vec![
        Opcode::StoreIndU8 as u8, 0x10, 0, 0, 0, 0,
        Opcode::LoadIndI8 as u8,  0x12, 0, 0, 0, 0,
        Opcode::Trap as u8,
    ];
    let bitmask = vec![1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1];

    let pvm = Interpreter::new(code.clone(), bitmask.clone(), vec![], regs, memory, 10_000, 25);
    let mut tracing = TracingPvm::new(pvm);
    assert_eq!(tracing.run(), ExitReason::Trap);
    let mut steps = tracing.into_trace();

    // Forge regs_after to clear the topmost sign-extension byte
    // (mask off bit 56).  Honest = 0xFFFFFFFFFFFFFF80.
    steps[1].regs_after[2] = 0x00FF_FFFF_FFFF_FF80;
    prove_and_verify(steps, &code, &bitmask);
}
