//! Raw PVM tests — validates the javm+assembler pipeline at instruction level,
//! independent of any VOS abstraction.
//!
//! Disabled during the InvocationKernel migration: this file targets the
//! removed `javm::Pvm` / `ExitReason` / `initialize_program` API and the
//! renamed `Assembler::set_stack_size` → `set_stack_pages`. Port to the
//! new kernel API in a follow-up commit.
#![cfg(any())]

use grey_transpiler::assembler::{Assembler, Reg};
use javm::ExitReason;
use javm::program::initialize_program;
use vos::abi::hostcall::{self, accumulate};

/// Program that immediately halts.
fn program_halt() -> Vec<u8> {
    let mut asm = Assembler::new();
    asm.set_stack_size(4096);
    asm.jump_ind(Reg::RA, 0);
    asm.build()
}

/// Program that calls INFO hostcall to get service ID, stores at addr 0, then halts.
fn program_info() -> Vec<u8> {
    let mut asm = Assembler::new();
    asm.set_stack_size(4096);
    asm.ecalli(accumulate::INFO);
    asm.store_u64(Reg::A0, 0);
    asm.jump_ind(Reg::RA, 0);
    asm.build()
}

/// Program that writes "Hi" via DEBUG_WRITE hostcall, then halts.
fn program_debug_write() -> Vec<u8> {
    let mut asm = Assembler::new();
    asm.set_stack_size(4096);
    asm.load_imm(Reg::T0, 0x48); // 'H'
    asm.store_u8(Reg::T0, 0);
    asm.load_imm(Reg::T0, 0x69); // 'i'
    asm.store_u8(Reg::T0, 1);
    asm.load_imm(Reg::A0, 0); // buf at 0
    asm.load_imm(Reg::A1, 2); // 2 bytes
    asm.ecalli(hostcall::DEBUG_WRITE);
    asm.jump_ind(Reg::RA, 0);
    asm.build()
}

/// Program that yields N times, storing increasing counter at addr 0.
fn program_counting_yields(n: i32) -> Vec<u8> {
    let mut asm = Assembler::new();
    asm.set_stack_size(4096);

    asm.load_imm(Reg::S0, 1);
    asm.load_imm(Reg::S1, n + 1);

    let loop_start = asm.current_offset();
    asm.store_u64(Reg::S0, 0);
    asm.ecalli(accumulate::YIELD);
    asm.add_imm_64(Reg::S0, Reg::S0, 1);
    asm.sub_64(Reg::T0, Reg::S0, Reg::S1);
    let branch_pc = asm.current_offset();
    let rel = loop_start as i32 - branch_pc as i32;
    asm.branch_ne_imm(Reg::T0, 0, rel as u32);
    asm.jump_ind(Reg::RA, 0);

    asm.build()
}

#[test]
fn raw_pvm_halt() {
    let blob = program_halt();
    let mut pvm = initialize_program(&blob, &[], 100_000).expect("init");
    let (exit, _) = pvm.run();
    assert_eq!(exit, ExitReason::Halt);
}

#[test]
fn raw_pvm_info() {
    let blob = program_info();
    let mut pvm = initialize_program(&blob, &[], 100_000).expect("init");

    let (exit, _) = pvm.run();
    assert_eq!(exit, ExitReason::HostCall(accumulate::INFO));

    pvm.registers[7] = 42;
    let (exit, _) = pvm.run();
    assert_eq!(exit, ExitReason::Halt);

    let stored = pvm.read_u8(0).unwrap() as u64
        | (pvm.read_u8(1).unwrap() as u64) << 8
        | (pvm.read_u8(2).unwrap() as u64) << 16
        | (pvm.read_u8(3).unwrap() as u64) << 24;
    assert_eq!(stored, 42);
}

#[test]
fn raw_pvm_debug_write() {
    let blob = program_debug_write();
    let mut pvm = initialize_program(&blob, &[], 100_000).expect("init");

    let (exit, _) = pvm.run();
    assert_eq!(exit, ExitReason::HostCall(hostcall::DEBUG_WRITE));

    assert_eq!(pvm.registers[7], 0); // buf_ptr
    assert_eq!(pvm.registers[8], 2); // buf_len

    assert_eq!(pvm.read_u8(0), Some(0x48)); // 'H'
    assert_eq!(pvm.read_u8(1), Some(0x69)); // 'i'

    pvm.registers[7] = 2;
    let (exit, _) = pvm.run();
    assert_eq!(exit, ExitReason::Halt);
}

#[test]
fn raw_pvm_counting_yields() {
    let blob = program_counting_yields(3);
    let mut pvm = initialize_program(&blob, &[], 1_000_000).expect("init");

    for expected in 1..=3u8 {
        let (exit, _) = pvm.run();
        assert_eq!(exit, ExitReason::HostCall(accumulate::YIELD));
        let val = pvm.read_u8(0).unwrap();
        assert_eq!(val, expected, "iteration {expected}");
    }

    let (exit, _) = pvm.run();
    assert_eq!(exit, ExitReason::Halt);
}
