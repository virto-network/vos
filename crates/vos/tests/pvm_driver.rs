//! Integration tests for the PVM driver — builds tiny PVM programs
//! using grey-transpiler's assembler and runs them through the runtime.

#![allow(dead_code)]

use grey_transpiler::assembler::{Assembler, Reg};
use javm::ExitReason;
use javm::program::initialize_program;
use vos::pvm_driver::{PvmDriver, RawMsg};
use vos::registry::Status;
use vos::scheduler::{Driver, Scheduler, TickResult};
use vos_abi::hostcall;
use vos_abi::service::ServiceId;

// -- Program builders --

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
    asm.ecalli(hostcall::INFO);
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

/// Program that yields once, then halts.
fn program_yield_then_halt() -> Vec<u8> {
    let mut asm = Assembler::new();
    asm.set_stack_size(4096);
    asm.ecalli(hostcall::YIELD);
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
    asm.ecalli(hostcall::YIELD);
    asm.add_imm_64(Reg::S0, Reg::S0, 1);
    asm.sub_64(Reg::T0, Reg::S0, Reg::S1);
    let branch_pc = asm.current_offset();
    let rel = loop_start as i32 - branch_pc as i32;
    asm.branch_ne_imm(Reg::T0, 0, rel as u32);
    asm.jump_ind(Reg::RA, 0);

    asm.build()
}

// -- Raw PVM tests --

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
    assert_eq!(exit, ExitReason::HostCall(hostcall::INFO));

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
        assert_eq!(exit, ExitReason::HostCall(hostcall::YIELD));
        let val = pvm.read_u8(0).unwrap();
        assert_eq!(val, expected, "iteration {expected}");
    }

    let (exit, _) = pvm.run();
    assert_eq!(exit, ExitReason::Halt);
}

// -- Driver tests --

#[test]
fn driver_spawn_and_halt() {
    let blob = program_halt();
    let mut driver = PvmDriver::new();
    let blob_idx = driver.register_blob(blob);

    let id = ServiceId(1);
    assert_eq!(driver.spawn_blob(id, blob_idx), Status::Pending);
    assert_eq!(driver.poll(id), Status::Done);
}

#[test]
fn driver_info_hostcall() {
    let blob = program_info();
    let mut driver = PvmDriver::new();
    let blob_idx = driver.register_blob(blob);

    let id = ServiceId(5);
    driver.spawn_blob(id, blob_idx);
    assert_eq!(driver.poll(id), Status::Done);
}

#[test]
fn driver_debug_write_hostcall() {
    let blob = program_debug_write();
    let mut driver = PvmDriver::new();
    let blob_idx = driver.register_blob(blob);

    let id = ServiceId(1);
    driver.spawn_blob(id, blob_idx);
    assert_eq!(driver.poll(id), Status::Done);
}

// -- Scheduler tests --

#[test]
fn scheduler_two_services_halt() {
    let blob = program_halt();
    let mut driver = PvmDriver::new();
    let blob_idx = driver.register_blob(blob);

    let mut sched: Scheduler<RawMsg, PvmDriver, 4, 16> = Scheduler::new(driver);

    let a = sched.spawn().unwrap();
    sched.driver_mut().spawn_blob(a, blob_idx);
    let b = sched.spawn().unwrap();
    sched.driver_mut().spawn_blob(b, blob_idx);

    assert_eq!(sched.tick(), TickResult::Progress);
    assert_eq!(sched.tick(), TickResult::Done);
}

#[test]
fn scheduler_service_with_info() {
    let blob = program_info();
    let mut driver = PvmDriver::new();
    let blob_idx = driver.register_blob(blob);

    let mut sched: Scheduler<RawMsg, PvmDriver, 4, 16> = Scheduler::new(driver);

    let id = sched.spawn().unwrap();
    sched.driver_mut().spawn_blob(id, blob_idx);

    assert_eq!(sched.tick(), TickResult::Progress);
    assert_eq!(sched.tick(), TickResult::Done);
}

/// Program that sends a TRANSFER to target service with memo data, then halts.
fn program_transfer_to(target: u32) -> Vec<u8> {
    let mut asm = Assembler::new();
    asm.set_stack_size(4096);
    // Write memo "PING" at address 0
    asm.load_imm(Reg::T0, 0x50); // 'P'
    asm.store_u8(Reg::T0, 0);
    asm.load_imm(Reg::T0, 0x49); // 'I'
    asm.store_u8(Reg::T0, 1);
    asm.load_imm(Reg::T0, 0x4E); // 'N'
    asm.store_u8(Reg::T0, 2);
    asm.load_imm(Reg::T0, 0x47); // 'G'
    asm.store_u8(Reg::T0, 3);
    // TRANSFER: a0=target, a1=amount, a2=gas_limit, a3=memo_ptr, a4=memo_len
    asm.load_imm(Reg::A0, target as i32);
    asm.load_imm(Reg::A1, 0); // amount
    asm.load_imm(Reg::A2, 0); // gas_limit
    asm.load_imm(Reg::A3, 0); // memo at addr 0
    asm.load_imm(Reg::A4, 4); // 4 bytes
    asm.ecalli(hostcall::TRANSFER);
    asm.jump_ind(Reg::RA, 0);
    asm.build()
}

#[test]
fn scheduler_transfer_routes_to_mailbox() {
    let sender_blob = program_transfer_to(2);
    let receiver_blob = program_yield_then_halt();
    let mut driver = PvmDriver::new();
    let sender_idx = driver.register_blob(sender_blob);
    let receiver_idx = driver.register_blob(receiver_blob);

    let mut sched: Scheduler<RawMsg, PvmDriver, 4, 16> = Scheduler::new(driver);

    let sender_id = sched.spawn().unwrap();
    sched.driver_mut().spawn_blob(sender_id, sender_idx);
    let receiver_id = sched.spawn().unwrap();
    sched.driver_mut().spawn_blob(receiver_id, receiver_idx);

    // First tick: sender sends TRANSFER → halts. Receiver yields → suspended.
    assert_eq!(sched.tick(), TickResult::Progress);

    // Verify the message arrived in the receiver's mailbox
    let entry = sched.registry.get(receiver_id).unwrap();
    assert!(
        !entry.mailbox.is_empty(),
        "receiver should have a pending message"
    );

    let msg = entry.mailbox.peek().unwrap();
    assert_eq!(&msg.data, b"PING");
}

/// Program that calls FETCH into a buffer at addr 0, stores return value at addr 256, then yields.
fn program_fetch_and_store() -> Vec<u8> {
    let mut asm = Assembler::new();
    asm.set_stack_size(4096);
    // First yield — let the runtime deliver a message
    asm.ecalli(hostcall::YIELD);
    // FETCH: a0=buf_ptr, a1=buf_len
    asm.load_imm(Reg::A0, 0); // buf at addr 0
    asm.load_imm(Reg::A1, 128); // buf_len
    asm.ecalli(hostcall::FETCH);
    // a0 now has bytes received — store at addr 256
    asm.store_u64(Reg::A0, 256);
    // Yield again so the test can inspect memory
    asm.ecalli(hostcall::YIELD);
    asm.jump_ind(Reg::RA, 0);
    asm.build()
}

#[test]
fn scheduler_transfer_fetch_round_trip() {
    use vos::MemoryAccess;

    let sender_blob = program_transfer_to(2);
    let receiver_blob = program_fetch_and_store();
    let mut driver = PvmDriver::new();
    let sender_idx = driver.register_blob(sender_blob);
    let receiver_idx = driver.register_blob(receiver_blob);

    let mut sched: Scheduler<RawMsg, PvmDriver, 4, 16> = Scheduler::new(driver);

    let sender_id = sched.spawn().unwrap();
    sched.driver_mut().spawn_blob(sender_id, sender_idx);
    let receiver_id = sched.spawn().unwrap();
    sched.driver_mut().spawn_blob(receiver_id, receiver_idx);

    // Tick 1: sender transfers → halts. Receiver yields → suspended.
    assert_eq!(sched.tick(), TickResult::Progress);

    // Tick 2: receiver has pending message → handle() stores as pending_msg,
    // then run: FETCH → gets data → stores len → yields.
    assert_eq!(sched.tick(), TickResult::Progress);

    // Read the bytes-received count from addr 256
    let mut count_buf = [0u8; 8];
    sched.driver().read_guest(receiver_id, 256, &mut count_buf);
    let bytes_received = u64::from_le_bytes(count_buf);
    assert_eq!(bytes_received as usize, 4); // "PING"

    // Read the actual data from addr 0
    let mut msg_buf = [0u8; 4];
    sched.driver().read_guest(receiver_id, 0, &mut msg_buf);
    assert_eq!(&msg_buf, b"PING");
}
