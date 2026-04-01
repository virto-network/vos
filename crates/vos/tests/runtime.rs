//! Integration tests for VosRuntime — the fresh-PVM-per-invocation model.

use grey_transpiler::assembler::{Assembler, Reg};
use vos_abi::hostcall::{self, accumulate, refine};
use vos_abi::service::ServiceId;
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

/// Program that immediately halts (simplest possible service).
fn program_halt() -> Vec<u8> {
    let mut asm = Assembler::new();
    asm.set_stack_size(4096);
    asm.jump_ind(Reg::RA, 0);
    asm.build()
}

/// Program that calls INFO, stores result to storage key "id", then halts.
fn program_info_to_storage() -> Vec<u8> {
    let mut asm = Assembler::new();
    asm.set_stack_size(4096);

    // INFO → a0 = service ID
    asm.ecalli(accumulate::INFO);
    // Store ID at addr 200
    asm.store_u8(Reg::A0, 200);

    // Write storage key "id" at addr 210
    asm.load_imm(Reg::T0, 0x69); // 'i'
    asm.store_u8(Reg::T0, 210);
    asm.load_imm(Reg::T0, 0x64); // 'd'
    asm.store_u8(Reg::T0, 211);

    // WRITE: key="id" at 210 (2 bytes), val=service_id at 200 (1 byte)
    asm.load_imm(Reg::A0, 210); // key_ptr
    asm.load_imm(Reg::A1, 2);   // key_len
    asm.load_imm(Reg::A2, 200); // val_ptr
    asm.load_imm(Reg::A3, 1);   // val_len
    asm.ecalli(accumulate::WRITE);

    asm.jump_ind(Reg::RA, 0);
    asm.build()
}

#[test]
fn runtime_halt_only() {
    let blob = program_halt();
    let mut rt = VosRuntime::new();
    let blob_idx = rt.register_blob(blob);
    let id = rt.register_service(blob_idx);
    rt.send_to(id, Vec::new());
    rt.run();
    // Service should halt cleanly without persisting anything
}

#[test]
fn runtime_info_returns_service_id() {
    let blob = program_info_to_storage();
    let mut rt = VosRuntime::new();
    let blob_idx = rt.register_blob(blob);
    let id = rt.register_service(blob_idx);
    rt.send_to(id, Vec::new());
    rt.run();

    // Verify INFO returned the correct service ID
    let val = rt.hostcalls.storage.read(id, b"id");
    assert_eq!(val, Some(&[id.0 as u8][..]));
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

/// "Doubler" service: FETCHes one byte, doubles it, leaves result in a0/a1 for invoke output.
fn program_doubler() -> Vec<u8> {
    let mut asm = Assembler::new();
    asm.set_stack_size(4096);

    // FETCH input into addr 0
    asm.load_imm(Reg::A0, 0);   // buf_ptr
    asm.load_imm(Reg::A1, 128); // buf_len
    asm.ecalli(hostcall::FETCH);

    // Load byte at addr 0, double it, store at addr 200
    asm.load_u8(Reg::T0, 0);
    asm.add_64(Reg::T0, Reg::T0, Reg::T0); // double
    asm.store_u8(Reg::T0, 200);

    // Set output: a0 = output_ptr (200), a1 = output_len (1)
    asm.load_imm(Reg::A0, 200);
    asm.load_imm(Reg::A1, 1);

    asm.jump_ind(Reg::RA, 0);
    asm.build()
}

/// Caller service: writes a code_hash (service-ID convention) + input byte into memory,
/// calls INVOKE, reads the output, stores it to storage key "r".
fn program_invoke_doubler(target_id: u32) -> Vec<u8> {
    let mut asm = Assembler::new();
    asm.set_stack_size(4096);

    // Write code_hash at addr 0: first 4 bytes = target_id LE, rest = 0
    // (stack is zeroed, so we only need to write the first 4 bytes)
    let id_bytes = target_id.to_le_bytes();
    asm.load_imm(Reg::T0, id_bytes[0] as i32);
    asm.store_u8(Reg::T0, 0);
    if id_bytes[1] != 0 {
        asm.load_imm(Reg::T0, id_bytes[1] as i32);
        asm.store_u8(Reg::T0, 1);
    }
    // bytes 2,3 are 0 for small IDs, and bytes 4-31 are already 0

    // Write input byte (21) at addr 64
    asm.load_imm(Reg::T0, 21);
    asm.store_u8(Reg::T0, 64);

    // INVOKE: a0=hash_ptr(0), a1=input_ptr(64), a2=input_len(1), a3=gas(0=default), a4=output_ptr(128)
    asm.load_imm(Reg::A0, 0);   // hash_ptr
    asm.load_imm(Reg::A1, 64);  // input_ptr
    asm.load_imm(Reg::A2, 1);   // input_len
    asm.load_imm(Reg::A3, 0);   // gas (0 = default)
    asm.load_imm(Reg::A4, 128); // output_ptr
    asm.ecalli(refine::INVOKE);

    // a0 now contains output_len (should be 1)
    // Read the output byte from addr 128, store to storage key "r" at addr 180

    // Write key "r" at addr 180
    asm.load_imm(Reg::T0, 0x72); // 'r'
    asm.store_u8(Reg::T0, 180);

    // WRITE: key="r" at 180 (1 byte), val=invoke output at 128 (1 byte)
    asm.load_imm(Reg::A0, 180); // key_ptr
    asm.load_imm(Reg::A1, 1);   // key_len
    asm.load_imm(Reg::A2, 128); // val_ptr
    asm.load_imm(Reg::A3, 1);   // val_len
    asm.ecalli(accumulate::WRITE);

    asm.jump_ind(Reg::RA, 0);
    asm.build()
}

#[test]
fn runtime_invoke_by_service_id() {
    // Register a "doubler" service, then a "caller" that invokes it
    let doubler_blob = program_doubler();
    let caller_blob = program_invoke_doubler(1); // target = ServiceId(1)

    let mut rt = VosRuntime::new();
    let doubler_idx = rt.register_blob(doubler_blob);
    let caller_idx = rt.register_blob(caller_blob);

    let doubler_id = rt.register_service(doubler_idx); // ServiceId(1)
    let caller_id = rt.register_service(caller_idx);   // ServiceId(2)

    assert_eq!(doubler_id, ServiceId(1));

    // Trigger caller
    rt.send_to(caller_id, Vec::new());
    rt.run();

    // Caller invoked doubler with input=21, doubler returns 42
    // Caller stored result in storage key "r"
    let val = rt.hostcalls.storage.read(caller_id, b"r");
    assert_eq!(val, Some(&[42u8][..]), "invoke should return doubled value");
}
