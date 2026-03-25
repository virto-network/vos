//! Integration tests for the PVM driver — builds tiny PVM programs
//! using grey-transpiler's assembler and runs them through the executor.

#![allow(dead_code)]

use grey_transpiler::assembler::{Assembler, Reg};
use javm::program::initialize_program;
use javm::ExitReason;
use pvx_abi::actor::ActorId;
use pvx_abi::syscall::Syscall;
use pvx::pvm_driver::{PvmDriver, RawMsg};
use pvx::scheduler::{Driver, Scheduler, TickResult};

// -- Program builders --

/// Program that immediately halts (returns via RA).
fn program_halt() -> Vec<u8> {
    let mut asm = Assembler::new();
    asm.set_stack_size(4096);
    // RA is pre-loaded with the halt address by initialize_program.
    asm.jump_ind(Reg::RA, 0);
    asm.build()
}

/// Program that calls SelfId syscall, stores result at addr 0, then halts.
fn program_self_id() -> Vec<u8> {
    let mut asm = Assembler::new();
    asm.set_stack_size(4096);
    asm.ecalli(Syscall::SelfId as u32);
    // a0 now contains the actor's ID
    asm.store_u64(Reg::A0, 0);
    asm.jump_ind(Reg::RA, 0);
    asm.build()
}

/// Program that writes "Hi" to stdout via FdWrite syscall, then halts.
fn program_write_stdout() -> Vec<u8> {
    let mut asm = Assembler::new();
    asm.set_stack_size(4096);
    // Write "Hi" into memory at address 0
    asm.load_imm(Reg::T0, 0x48); // 'H'
    asm.store_u8(Reg::T0, 0);
    asm.load_imm(Reg::T0, 0x69); // 'i'
    asm.store_u8(Reg::T0, 1);
    // FdWrite: a0=fd, a1=buf_ptr, a2=buf_len
    asm.load_imm(Reg::A0, 1); // stdout
    asm.load_imm(Reg::A1, 0); // buf at 0
    asm.load_imm(Reg::A2, 2); // 2 bytes
    asm.ecalli(Syscall::FdWrite as u32);
    asm.jump_ind(Reg::RA, 0);
    asm.build()
}

/// Program that yields once, then halts.
fn program_yield_then_halt() -> Vec<u8> {
    let mut asm = Assembler::new();
    asm.set_stack_size(4096);
    asm.ecalli(Syscall::Yield as u32);
    asm.jump_ind(Reg::RA, 0);
    asm.build()
}

/// Program that stores increasing values at addr 0 across N yields.
/// On each iteration: store counter, yield, increment, check, loop.
fn program_counting_yields(n: i32) -> Vec<u8> {
    let mut asm = Assembler::new();
    asm.set_stack_size(4096);

    // S0 = counter (starts at 1)
    // S1 = limit (n + 1)
    asm.load_imm(Reg::S0, 1);
    asm.load_imm(Reg::S1, n + 1);

    // loop_start:
    let loop_start = asm.current_offset();
    asm.store_u64(Reg::S0, 0);              // store counter at addr 0
    asm.ecalli(Syscall::Yield as u32);      // yield to executor
    asm.add_imm_64(Reg::S0, Reg::S0, 1);   // counter++
    asm.sub_64(Reg::T0, Reg::S0, Reg::S1); // T0 = counter - limit
    // branch_ne_imm target is PC-relative
    let branch_pc = asm.current_offset();
    let rel = loop_start as i32 - branch_pc as i32;
    asm.branch_ne_imm(Reg::T0, 0, rel as u32); // if T0 != 0, loop
    // fall through: halt
    asm.jump_ind(Reg::RA, 0);

    asm.build()
}

// -- Raw PVM tests (no driver, just javm directly) --

#[test]
fn raw_pvm_halt() {
    let blob = program_halt();
    let mut pvm = initialize_program(&blob, &[], 100_000).expect("init");
    let (exit, _) = pvm.run();
    assert_eq!(exit, ExitReason::Halt);
}

#[test]
fn raw_pvm_self_id() {
    let blob = program_self_id();
    let mut pvm = initialize_program(&blob, &[], 100_000).expect("init");

    // Run until host call (SelfId)
    let (exit, _) = pvm.run();
    assert_eq!(exit, ExitReason::HostCall(Syscall::SelfId as u32));

    // Simulate executor: write actor ID into a0
    pvm.registers[7] = 42;

    // Resume
    let (exit, _) = pvm.run();
    assert_eq!(exit, ExitReason::Halt);

    // Verify stored value
    let stored = pvm.read_u8(0).unwrap() as u64
        | (pvm.read_u8(1).unwrap() as u64) << 8
        | (pvm.read_u8(2).unwrap() as u64) << 16
        | (pvm.read_u8(3).unwrap() as u64) << 24;
    assert_eq!(stored, 42);
}

#[test]
fn raw_pvm_write_stdout() {
    let blob = program_write_stdout();
    let mut pvm = initialize_program(&blob, &[], 100_000).expect("init");

    let (exit, _) = pvm.run();
    assert_eq!(exit, ExitReason::HostCall(Syscall::FdWrite as u32));

    // Verify arguments
    assert_eq!(pvm.registers[7], 1); // fd=stdout
    assert_eq!(pvm.registers[8], 0); // buf=0
    assert_eq!(pvm.registers[9], 2); // len=2

    // Verify memory
    assert_eq!(pvm.read_u8(0), Some(0x48)); // 'H'
    assert_eq!(pvm.read_u8(1), Some(0x69)); // 'i'

    pvm.registers[7] = 2; // return bytes written
    let (exit, _) = pvm.run();
    assert_eq!(exit, ExitReason::Halt);
}

#[test]
fn raw_pvm_counting_yields() {
    let blob = program_counting_yields(3);
    let mut pvm = initialize_program(&blob, &[], 1_000_000).expect("init");

    for expected in 1..=3 {
        // Should hit Yield
        let (exit, _) = pvm.run();
        assert_eq!(exit, ExitReason::HostCall(Syscall::Yield as u32));
        // Counter stored at addr 0
        let val = pvm.read_u8(0).unwrap();
        assert_eq!(val, expected, "iteration {expected}");
    }

    // After 3 yields, should halt
    let (exit, _) = pvm.run();
    assert_eq!(exit, ExitReason::Halt);
}

// -- Driver tests --

#[test]
fn driver_spawn_and_halt() {
    let blob = program_halt();
    let mut driver = PvmDriver::new();
    let blob_idx = driver.register_blob(blob);

    let id = ActorId(1);
    assert_eq!(driver.spawn_blob(id, blob_idx), pvx_abi::actor::Status::Pending);
    // Polling runs the program to completion
    assert_eq!(driver.poll(id), pvx_abi::actor::Status::Done);
}

#[test]
fn driver_self_id_syscall() {
    let blob = program_self_id();
    let mut driver = PvmDriver::new();
    let blob_idx = driver.register_blob(blob);

    let id = ActorId(5);
    driver.spawn_blob(id, blob_idx);
    assert_eq!(driver.poll(id), pvx_abi::actor::Status::Done);
}

#[test]
fn driver_write_stdout_syscall() {
    let blob = program_write_stdout();
    let mut driver = PvmDriver::new();
    let blob_idx = driver.register_blob(blob);

    let id = ActorId(1);
    driver.spawn_blob(id, blob_idx);
    assert_eq!(driver.poll(id), pvx_abi::actor::Status::Done);
}

// -- Scheduler tests --

#[test]
fn scheduler_two_actors_halt() {
    let blob = program_halt();
    let mut driver = PvmDriver::new();
    let blob_idx = driver.register_blob(blob);

    let mut sched: Scheduler<RawMsg, PvmDriver, 4, 16> = Scheduler::new(driver);

    let a = sched.spawn().unwrap();
    sched.driver_mut().spawn_blob(a, blob_idx);
    let b = sched.spawn().unwrap();
    sched.driver_mut().spawn_blob(b, blob_idx);

    // spawn_blob returns Pending → actors start in Suspended state.
    // First tick: polls both suspended actors, they run and halt → Done.
    assert_eq!(sched.tick(), TickResult::Progress);
    // Both actors stopped → Done.
    assert_eq!(sched.tick(), TickResult::Done);
}

#[test]
fn scheduler_actor_with_self_id() {
    let blob = program_self_id();
    let mut driver = PvmDriver::new();
    let blob_idx = driver.register_blob(blob);

    let mut sched: Scheduler<RawMsg, PvmDriver, 4, 16> = Scheduler::new(driver);

    let id = sched.spawn().unwrap();
    sched.driver_mut().spawn_blob(id, blob_idx);

    // First tick polls the suspended actor → runs SelfId syscall → halts
    assert_eq!(sched.tick(), TickResult::Progress);
    assert_eq!(sched.tick(), TickResult::Done);
}
