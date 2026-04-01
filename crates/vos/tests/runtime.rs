//! Integration tests for VosRuntime — the fresh-PVM-per-invocation model.

use grey_transpiler::assembler::{Assembler, Reg};
use vos_abi::hostcall::{self, accumulate};
use vos::runtime::VosRuntime;

/// Program that writes "Hi" via DEBUG_WRITE then halts.
fn program_debug_write() -> Vec<u8> {
    let mut asm = Assembler::new();
    asm.set_stack_size(4096);
    asm.load_imm(Reg::T0, 0x48); // 'H'
    asm.store_u8(Reg::T0, 0);
    asm.load_imm(Reg::T0, 0x69); // 'i'
    asm.store_u8(Reg::T0, 1);
    asm.load_imm(Reg::A0, 0);
    asm.load_imm(Reg::A1, 2);
    asm.ecalli(hostcall::DEBUG_WRITE);
    asm.jump_ind(Reg::RA, 0);
    asm.build()
}

/// Program that writes value 42 to storage key "x", then halts.
fn program_write_storage() -> Vec<u8> {
    let mut asm = Assembler::new();
    asm.set_stack_size(4096);

    // Write key "x" at addr 0
    asm.load_imm(Reg::T0, 0x78); // 'x'
    asm.store_u8(Reg::T0, 0);

    // Write value 42 at addr 16
    asm.load_imm(Reg::T0, 42);
    asm.store_u8(Reg::T0, 16);

    // WRITE: a0=key_ptr, a1=key_len, a2=val_ptr, a3=val_len
    asm.load_imm(Reg::A0, 0);  // key at 0
    asm.load_imm(Reg::A1, 1);  // key_len = 1
    asm.load_imm(Reg::A2, 16); // val at 16
    asm.load_imm(Reg::A3, 1);  // val_len = 1
    asm.ecalli(accumulate::WRITE);

    asm.jump_ind(Reg::RA, 0);
    asm.build()
}

/// Program that reads storage key "x" into addr 32, stores result at addr 48, then halts.
fn program_read_storage() -> Vec<u8> {
    let mut asm = Assembler::new();
    asm.set_stack_size(4096);

    // Write key "x" at addr 0
    asm.load_imm(Reg::T0, 0x78); // 'x'
    asm.store_u8(Reg::T0, 0);

    // READ: a0=key_ptr, a1=key_len, a2=val_buf_ptr, a3=val_buf_len
    asm.load_imm(Reg::A0, 0);  // key at 0
    asm.load_imm(Reg::A1, 1);  // key_len = 1
    asm.load_imm(Reg::A2, 32); // val_buf at 32
    asm.load_imm(Reg::A3, 16); // val_buf_len = 16
    asm.ecalli(accumulate::READ);

    // Store return value (bytes read) at addr 48
    asm.store_u64(Reg::A0, 48);

    asm.jump_ind(Reg::RA, 0);
    asm.build()
}

/// Program that sends a TRANSFER to target service 2 with memo "HI", then halts.
fn program_transfer_to(target: u32) -> Vec<u8> {
    let mut asm = Assembler::new();
    asm.set_stack_size(4096);
    // Write memo at addr 0
    asm.load_imm(Reg::T0, 0x48); // 'H'
    asm.store_u8(Reg::T0, 0);
    asm.load_imm(Reg::T0, 0x49); // 'I'
    asm.store_u8(Reg::T0, 1);
    // TRANSFER: a0=target, a1=amount, a2=gas, a3=memo_ptr, a4=memo_len
    asm.load_imm(Reg::A0, target as i32);
    asm.load_imm(Reg::A1, 0);
    asm.load_imm(Reg::A2, 0);
    asm.load_imm(Reg::A3, 0); // memo at 0
    asm.load_imm(Reg::A4, 2); // 2 bytes
    asm.ecalli(accumulate::TRANSFER);
    asm.jump_ind(Reg::RA, 0);
    asm.build()
}

/// Program that FETCHes an item into addr 0, writes its length to storage key "len", then halts.
fn program_fetch_and_store_len() -> Vec<u8> {
    let mut asm = Assembler::new();
    asm.set_stack_size(4096);

    // FETCH: a0=buf_ptr, a1=buf_len
    asm.load_imm(Reg::A0, 0);
    asm.load_imm(Reg::A1, 128);
    asm.ecalli(hostcall::FETCH);

    // Store return value (bytes fetched) as a single byte at addr 200
    asm.store_u8(Reg::A0, 200);

    // Write storage key "len" at addr 210
    asm.load_imm(Reg::T0, 0x6C); // 'l'
    asm.store_u8(Reg::T0, 210);
    asm.load_imm(Reg::T0, 0x65); // 'e'
    asm.store_u8(Reg::T0, 211);
    asm.load_imm(Reg::T0, 0x6E); // 'n'
    asm.store_u8(Reg::T0, 212);

    // WRITE: key="len" at 210, val=fetch result at 200
    asm.load_imm(Reg::A0, 210); // key_ptr
    asm.load_imm(Reg::A1, 3);   // key_len
    asm.load_imm(Reg::A2, 200); // val_ptr
    asm.load_imm(Reg::A3, 1);   // val_len
    asm.ecalli(accumulate::WRITE);

    asm.jump_ind(Reg::RA, 0);
    asm.build()
}

#[test]
fn runtime_single_service_debug_write() {
    let blob = program_debug_write();
    let mut rt = VosRuntime::new();
    let blob_idx = rt.register_blob(blob);
    let id = rt.register_service(blob_idx);
    rt.send_to(id, Vec::new());
    rt.run();
    // Service should have printed "Hi" to stderr and halted
}

#[test]
fn runtime_storage_persists_across_invocations() {
    // First invocation: write 42 to key "x"
    let write_blob = program_write_storage();
    let mut rt = VosRuntime::new();
    let blob_idx = rt.register_blob(write_blob);
    let id = rt.register_service(blob_idx);
    rt.send_to(id, Vec::new());
    rt.run();

    // Verify storage has the value
    let val = rt.hostcalls.storage.read(id, b"x");
    assert_eq!(val, Some(&[42u8][..]));
}

#[test]
fn runtime_transfer_routes_between_services() {
    // Service 1 sends TRANSFER to service 2
    // Service 2 receives it via FETCH and stores the length
    let sender_blob = program_transfer_to(2);
    let receiver_blob = program_fetch_and_store_len();

    let mut rt = VosRuntime::new();
    let sender_idx = rt.register_blob(sender_blob);
    let receiver_idx = rt.register_blob(receiver_blob);

    let sender_id = rt.register_service(sender_idx); // ServiceId(1)
    let receiver_id = rt.register_service(receiver_idx); // ServiceId(2)

    // Trigger sender
    rt.send_to(sender_id, Vec::new());
    rt.run();

    // Verify receiver stored the length of "HI" (2 bytes) in storage key "len"
    let val = rt.hostcalls.storage.read(receiver_id, b"len");
    assert_eq!(val, Some(&[2u8][..]));
}

#[test]
fn runtime_fresh_pvm_per_invocation() {
    // Invoke the same service twice — each gets a fresh PVM
    let blob = program_write_storage();
    let mut rt = VosRuntime::new();
    let blob_idx = rt.register_blob(blob);
    let id = rt.register_service(blob_idx);

    // First invocation
    rt.send_to(id, Vec::new());
    rt.run();
    assert_eq!(rt.hostcalls.storage.read(id, b"x"), Some(&[42u8][..]));

    // Second invocation — fresh PVM, but storage persists
    rt.send_to(id, Vec::new());
    rt.run();
    // Still 42 — the program writes 42 unconditionally
    assert_eq!(rt.hostcalls.storage.read(id, b"x"), Some(&[42u8][..]));
}
