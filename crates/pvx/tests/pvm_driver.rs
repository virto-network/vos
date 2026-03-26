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
    assert_eq!(driver.spawn_blob(id, blob_idx, None), pvx_abi::actor::Status::Pending);
    // Polling runs the program to completion
    assert_eq!(driver.poll(id), pvx_abi::actor::Status::Done);
}

#[test]
fn driver_self_id_syscall() {
    let blob = program_self_id();
    let mut driver = PvmDriver::new();
    let blob_idx = driver.register_blob(blob);

    let id = ActorId(5);
    driver.spawn_blob(id, blob_idx, None);
    assert_eq!(driver.poll(id), pvx_abi::actor::Status::Done);
}

#[test]
fn driver_write_stdout_syscall() {
    let blob = program_write_stdout();
    let mut driver = PvmDriver::new();
    let blob_idx = driver.register_blob(blob);

    let id = ActorId(1);
    driver.spawn_blob(id, blob_idx, None);
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
    sched.driver_mut().spawn_blob(a, blob_idx, None);
    let b = sched.spawn().unwrap();
    sched.driver_mut().spawn_blob(b, blob_idx, None);

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
    sched.driver_mut().spawn_blob(id, blob_idx, None);

    // First tick polls the suspended actor → runs SelfId syscall → halts
    assert_eq!(sched.tick(), TickResult::Progress);
    assert_eq!(sched.tick(), TickResult::Done);
}

/// Program that sends a 4-byte message to actor ID 2 via Send syscall, then halts.
fn program_send_to(target: u32) -> Vec<u8> {
    let mut asm = Assembler::new();
    asm.set_stack_size(4096);
    // Write payload "PING" at address 0
    asm.load_imm(Reg::T0, 0x50); // 'P'
    asm.store_u8(Reg::T0, 0);
    asm.load_imm(Reg::T0, 0x49); // 'I'
    asm.store_u8(Reg::T0, 1);
    asm.load_imm(Reg::T0, 0x4E); // 'N'
    asm.store_u8(Reg::T0, 2);
    asm.load_imm(Reg::T0, 0x47); // 'G'
    asm.store_u8(Reg::T0, 3);
    // Send: a0=target, a1=buf_ptr, a2=buf_len
    asm.load_imm(Reg::A0, target as i32);
    asm.load_imm(Reg::A1, 0); // buf at 0
    asm.load_imm(Reg::A2, 4); // 4 bytes
    asm.ecalli(Syscall::Send as u32);
    asm.jump_ind(Reg::RA, 0);
    asm.build()
}

#[test]
fn scheduler_send_routes_to_mailbox() {
    let sender_blob = program_send_to(2);
    let receiver_blob = program_yield_then_halt();
    let mut driver = PvmDriver::new();
    let sender_idx = driver.register_blob(sender_blob);
    let receiver_idx = driver.register_blob(receiver_blob);

    let mut sched: Scheduler<RawMsg, PvmDriver, 4, 16> = Scheduler::new(driver);

    let sender_id = sched.spawn().unwrap(); // ActorId(1)
    sched.driver_mut().spawn_blob(sender_id, sender_idx, None);
    let receiver_id = sched.spawn().unwrap(); // ActorId(2)
    sched.driver_mut().spawn_blob(receiver_id, receiver_idx, None);

    // First tick: sender runs Send syscall → queues PendingSend → halts.
    // Receiver runs yield → suspends.
    // drain_sends routes the message to receiver's mailbox.
    assert_eq!(sched.tick(), TickResult::Progress);

    // Verify the message arrived in the receiver's mailbox
    let entry = sched.registry.get(receiver_id).unwrap();
    assert!(!entry.mailbox.is_empty(), "receiver should have a pending message");

    // The message payload should be "PING" wrapped in a Header
    let msg = entry.mailbox.peek().unwrap();
    let header = msg.header().unwrap();
    assert_eq!(header.sender, sender_id);
    assert_eq!(msg.payload(), b"PING");
}

/// Program that calls Recv into a buffer at addr 0, stores the return
/// value (bytes received) at addr 256, then yields (so memory can be inspected).
fn program_recv_and_store() -> Vec<u8> {
    let mut asm = Assembler::new();
    asm.set_stack_size(4096);
    // First yield — let the executor deliver a message to us
    asm.ecalli(Syscall::Yield as u32);
    // Recv: a0=buf_ptr, a1=buf_len
    asm.load_imm(Reg::A0, 0);   // buf at addr 0
    asm.load_imm(Reg::A1, 128); // buf_len
    asm.ecalli(Syscall::Recv as u32);
    // a0 now has bytes received — store at addr 256
    asm.store_u64(Reg::A0, 256);
    // Yield again so the test can inspect memory before the actor is dropped
    asm.ecalli(Syscall::Yield as u32);
    asm.jump_ind(Reg::RA, 0);
    asm.build()
}

#[test]
fn scheduler_send_recv_round_trip() {
    use pvx::MemoryAccess;
    use pvx_abi::msg::Header;

    let sender_blob = program_send_to(2);
    let receiver_blob = program_recv_and_store();
    let mut driver = PvmDriver::new();
    let sender_idx = driver.register_blob(sender_blob);
    let receiver_idx = driver.register_blob(receiver_blob);

    let mut sched: Scheduler<RawMsg, PvmDriver, 4, 16> = Scheduler::new(driver);

    let sender_id = sched.spawn().unwrap(); // ActorId(1)
    sched.driver_mut().spawn_blob(sender_id, sender_idx, None);
    let receiver_id = sched.spawn().unwrap(); // ActorId(2)
    sched.driver_mut().spawn_blob(receiver_id, receiver_idx, None);

    // Tick 1: sender sends "PING" → halts. receiver yields → suspended.
    // drain_sends routes message to receiver's mailbox.
    assert_eq!(sched.tick(), TickResult::Progress);

    // Tick 2: receiver has a pending message → handle() stores it as pending_msg,
    // then run_actor resumes. Receiver calls Recv → gets the data → stores len → yields.
    assert_eq!(sched.tick(), TickResult::Progress);

    // Read the bytes-received count from addr 256
    let mut count_buf = [0u8; 8];
    sched.driver().read_guest(receiver_id, 256, &mut count_buf);
    let bytes_received = u64::from_le_bytes(count_buf);
    let expected_len = Header::SIZE + 4; // header(8) + "PING"(4)
    assert_eq!(bytes_received as usize, expected_len);

    // Read the actual message data from addr 0
    let mut msg_buf = [0u8; 64];
    sched.driver().read_guest(receiver_id, 0, &mut msg_buf[..expected_len]);

    // Parse: Header + payload
    let header = Header::from_bytes(&msg_buf).unwrap();
    assert_eq!(header.sender, sender_id);
    assert_eq!(header.payload_len, 4);
    let payload = &msg_buf[Header::SIZE..Header::SIZE + 4];
    assert_eq!(payload, b"PING");
}

// -- Snapshot / persistence tests --

use pvx::snapshot::{ActorStore, InstanceId};

#[test]
fn snapshot_capture_restore_via_store() {
    // Spawn a counting actor with an InstanceId, run partway (2 yields of 3),
    // extract the snapshot from the store, create a new driver, load the
    // snapshot into the new driver's store, spawn with same InstanceId → resumes.
    let blob = program_counting_yields(3);
    let mut driver = PvmDriver::new();
    let blob_idx = driver.register_blob(blob.clone());
    let iid = InstanceId { blob_idx: 0, instance: 0 };

    let id = ActorId(1);
    driver.spawn_blob(id, blob_idx, Some(iid));

    // Run 2 ticks (yield 1, yield 2) — snapshots saved to store on each yield
    assert_eq!(driver.poll(id), pvx_abi::actor::Status::Pending);
    assert_eq!(driver.poll(id), pvx_abi::actor::Status::Pending);

    // Verify the counter is at 2 via MemoryAccess
    use pvx::MemoryAccess;
    let mut buf = [0u8; 1];
    driver.read_guest(id, 0, &mut buf);
    assert_eq!(buf[0], 2);

    // Extract the snapshot from the store
    let snapshot = driver.store.load(iid).unwrap().unwrap();

    // Create a brand new driver and load the snapshot into its store
    let mut driver2 = PvmDriver::new();
    let blob_idx2 = driver2.register_blob(blob);
    driver2.store.save(iid, &snapshot).unwrap();

    // Spawn with same InstanceId — auto-restores from store
    let id2 = ActorId(1);
    driver2.spawn_blob(id2, blob_idx2, Some(iid));

    // Should resume from after yield 2: yield 3, then halt
    assert_eq!(driver2.poll(id2), pvx_abi::actor::Status::Pending); // yield 3
    assert_eq!(driver2.poll(id2), pvx_abi::actor::Status::Done);    // halt
}

#[test]
fn store_persist_and_resume() {
    // Spawn an actor with an InstanceId, run to yield, drop it.
    // Spawn again with the same InstanceId — auto-restores from store.
    let blob = program_counting_yields(3);
    let mut driver = PvmDriver::new();
    let blob_idx = driver.register_blob(blob);
    let iid = InstanceId { blob_idx: 0, instance: 0 };

    let id = ActorId(1);
    driver.spawn_blob(id, blob_idx, Some(iid));

    // Yield 1 — snapshot saved to store
    assert_eq!(driver.poll(id), pvx_abi::actor::Status::Pending);

    // Verify store has a snapshot
    assert!(driver.store.load(iid).unwrap().is_some());

    // Yield 2 — snapshot updated
    assert_eq!(driver.poll(id), pvx_abi::actor::Status::Pending);

    // Drop the actor
    driver.drop_actor(id);

    // Re-spawn with same InstanceId — should auto-restore from store
    let id2 = ActorId(2);
    driver.spawn_blob(id2, blob_idx, Some(iid));

    // Should resume from after yield 2, do yield 3 then halt
    assert_eq!(driver.poll(id2), pvx_abi::actor::Status::Pending); // yield 3
    assert_eq!(driver.poll(id2), pvx_abi::actor::Status::Done);    // halt
}

/// Program that calls Checkpoint, then halts.
fn program_checkpoint_then_halt() -> Vec<u8> {
    let mut asm = Assembler::new();
    asm.set_stack_size(4096);
    // Store a marker at addr 0
    asm.load_imm(Reg::T0, 0x42);
    asm.store_u8(Reg::T0, 0);
    asm.ecalli(Syscall::Checkpoint as u32);
    asm.jump_ind(Reg::RA, 0);
    asm.build()
}

#[test]
fn checkpoint_syscall() {
    let blob = program_checkpoint_then_halt();
    let mut driver = PvmDriver::new();
    let blob_idx = driver.register_blob(blob);
    let iid = InstanceId { blob_idx: 0, instance: 0 };

    let id = ActorId(1);
    driver.spawn_blob(id, blob_idx, Some(iid));

    // Run to completion (Checkpoint + Halt)
    assert_eq!(driver.poll(id), pvx_abi::actor::Status::Done);

    // Verify the store captured the snapshot at checkpoint time
    let snapshot = driver.store.load(iid).unwrap().expect("snapshot should exist");
    // The snapshot memory should contain our marker
    assert_eq!(snapshot.flat_mem[0], 0x42);
}
