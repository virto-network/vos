//! Integration tests for the PVM driver — builds tiny PVM programs
//! using grey-transpiler's assembler and runs them through the runtime.

#![allow(dead_code)]

use grey_transpiler::assembler::{Assembler, Reg};
use javm::ExitReason;
use javm::program::initialize_program;
use vos::pvm_driver::{PvmDriver, RawMsg};
use vos::registry::Status;
use vos_abi::hostcall::{self, accumulate};
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

// -- Transfer + routing tests (using PvmDriver directly) --

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
    asm.ecalli(accumulate::TRANSFER);
    asm.jump_ind(Reg::RA, 0);
    asm.build()
}

#[test]
fn driver_transfer_queues_send() {
    let blob = program_transfer_to(2);
    let mut driver = PvmDriver::new();
    let blob_idx = driver.register_blob(blob);

    let id = ServiceId(1);
    driver.spawn_blob(id, blob_idx);
    let status = driver.poll(id);
    assert_eq!(status, Status::Done);

    // The transfer should be queued
    assert_eq!(driver.pending_sends.len(), 1);
    assert_eq!(driver.pending_sends[0].to, ServiceId(2));
    assert_eq!(&driver.pending_sends[0].msg.data, b"PING");
}

#[test]
fn driver_transfer_deliver_via_handle() {
    use vos::MemoryAccess;

    // Receiver: yields, then fetches, stores len at 256, yields again
    let receiver_blob = {
        let mut asm = Assembler::new();
        asm.set_stack_size(4096);
        asm.ecalli(accumulate::YIELD);
        asm.load_imm(Reg::A0, 0);
        asm.load_imm(Reg::A1, 128);
        asm.ecalli(hostcall::FETCH);
        asm.store_u64(Reg::A0, 256);
        asm.ecalli(accumulate::YIELD);
        asm.jump_ind(Reg::RA, 0);
        asm.build()
    };

    let mut driver = PvmDriver::new();
    let blob_idx = driver.register_blob(receiver_blob);

    let id = ServiceId(2);
    driver.spawn_blob(id, blob_idx);

    // First poll: runs until YIELD → suspended
    assert_eq!(driver.poll(id), Status::Pending);

    // Deliver "PING" message
    let msg = RawMsg::new(b"PING".to_vec());
    let status = driver.handle(id, &msg);
    assert_eq!(status, Status::Pending); // yields again after storing

    // Read the bytes-received count from addr 256
    let mut count_buf = [0u8; 8];
    driver.read_guest(id, 256, &mut count_buf);
    let bytes_received = u64::from_le_bytes(count_buf);
    assert_eq!(bytes_received as usize, 4);

    // Read the data from addr 0
    let mut msg_buf = [0u8; 4];
    driver.read_guest(id, 0, &mut msg_buf);
    assert_eq!(&msg_buf, b"PING");
}
