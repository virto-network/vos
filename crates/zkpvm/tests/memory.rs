use javm::instruction::Opcode;
use javm::interpreter::Interpreter;
// Memory is now flat_mem in Interpreter
use javm::PVM_REGISTER_COUNT;

use zkpvm::core::tracing::TracingPvm;
use zkpvm::{prove, verify};

fn prove_and_verify(steps: Vec<zkpvm::core::step::PvmStep>, code: &[u8], bitmask: &[u8]) {
    for (i, s) in steps.iter().enumerate() {
        eprintln!("  step {i}: pc={} opcode={:?} mem_r={:?} mem_w={:?}",
            s.pc, s.opcode, s.mem_read.as_ref().map(|r| (r.address, r.value, r.size)),
            s.mem_write.as_ref().map(|w| (w.address, w.value, w.size)));
    }
    let mut side_note = zkpvm::SideNote::new(steps, code.to_vec(), bitmask.to_vec());
    match prove(&mut side_note) {
        Ok(proof) => verify(proof, &side_note).expect("verification failed"),
        Err(e) => panic!("proving failed: {e:?}"),
    }
}

#[test]
fn prove_store_only() {
    // Just a store followed by trap
    let mut regs = [0u64; PVM_REGISTER_COUNT];
    regs[0] = 42;
    regs[1] = 0x1000;

    let mut memory = vec![0u8; 4 * 1024 * 1024];

    let code = vec![
        Opcode::StoreIndU8 as u8, 0x10, 0, 0, 0, 0,
        Opcode::Trap as u8,
    ];
    let bitmask = vec![1, 0, 0, 0, 0, 0, 1];

    let pvm = Interpreter::new(code.clone(), bitmask.clone(), vec![], regs, memory, 10000, 25);
    let mut tracing = TracingPvm::new(pvm);
    let exit = tracing.run();
    assert_eq!(exit, javm::ExitReason::Trap);
    let steps = tracing.into_trace();
    assert_eq!(steps.len(), 2);
    assert!(steps[0].mem_write.is_some());
    prove_and_verify(steps, &code, &bitmask);
}

#[test]
fn prove_store_and_load_u8() {
    // Program:
    //   StoreIndU8: mem[φ[1] + 0] = φ[0] (store low byte of reg 0)
    //   LoadIndU8:  φ[2] = mem[φ[1] + 0] (load byte back)
    //   Trap
    let mut regs = [0u64; PVM_REGISTER_COUNT];
    regs[0] = 42;    // value to store
    regs[1] = 0x1000; // base address

    let mut memory = vec![0u8; 4 * 1024 * 1024];

    // StoreIndU8 (opcode 120): TwoRegOneImm [opcode, ra|(rb<<4), imm...]
    //   ra=0 (value source), rb=1 (base addr), imm=0 (offset)
    // LoadIndU8 (opcode 124): TwoRegOneImm [opcode, ra|(rb<<4), imm...]
    //   ra=2 (dest), rb=1 (base addr), imm=0 (offset)
    let code = vec![
        Opcode::StoreIndU8 as u8, 0x10, 0, 0, 0, 0,  // offset 0: StoreIndU8 ra=0,rb=1,imm=0
        Opcode::LoadIndU8 as u8, 0x12, 0, 0, 0, 0,   // offset 6: LoadIndU8 ra=2,rb=1,imm=0
        Opcode::Trap as u8,                            // offset 12
    ];
    let bitmask = vec![1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1];

    let pvm = Interpreter::new(code.clone(), bitmask.clone(), vec![], regs, memory, 10000, 25);
    let mut tracing = TracingPvm::new(pvm);
    let exit = tracing.run();
    assert_eq!(exit, javm::ExitReason::Trap);

    let steps = tracing.into_trace();
    assert_eq!(steps.len(), 3); // Store, Load, Trap

    // Verify memory was traced
    assert!(steps[0].mem_write.is_some());
    let w = steps[0].mem_write.as_ref().unwrap();
    assert_eq!(w.address, 0x1000);
    assert_eq!(w.value, 42);
    assert_eq!(w.size, 1);

    assert!(steps[1].mem_read.is_some());
    let r = steps[1].mem_read.as_ref().unwrap();
    assert_eq!(r.address, 0x1000);
    assert_eq!(r.value, 42);
    assert_eq!(r.size, 1);

    // φ[2] should have the loaded value
    assert_eq!(steps[1].regs_after[2], 42);

    prove_and_verify(steps, &code, &bitmask);
}

#[test]
fn prove_store_and_load_u64() {
    let mut regs = [0u64; PVM_REGISTER_COUNT];
    regs[0] = 0xDEAD_BEEF_CAFE_BABE;
    regs[1] = 0x2000;

    let mut memory = vec![0u8; 4 * 1024 * 1024];

    let code = vec![
        Opcode::StoreIndU64 as u8, 0x10, 0, 0, 0, 0,
        Opcode::LoadIndU64 as u8, 0x12, 0, 0, 0, 0,
        Opcode::Trap as u8,
    ];
    let bitmask = vec![1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1];

    let pvm = Interpreter::new(code.clone(), bitmask.clone(), vec![], regs, memory, 10000, 25);
    let mut tracing = TracingPvm::new(pvm);
    let exit = tracing.run();
    assert_eq!(exit, javm::ExitReason::Trap);

    let steps = tracing.into_trace();
    assert_eq!(steps[1].regs_after[2], 0xDEAD_BEEF_CAFE_BABE);

    prove_and_verify(steps, &code, &bitmask);
}

#[test]
fn prove_multiple_stores_same_addr() {
    // Write twice to the same address, then read
    let mut regs = [0u64; PVM_REGISTER_COUNT];
    regs[0] = 10;     // first value
    regs[1] = 0x1000;  // address
    regs[3] = 20;      // second value

    let mut memory = vec![0u8; 4 * 1024 * 1024];

    // Store 10, store 20, load (should get 20)
    let code = vec![
        Opcode::StoreIndU8 as u8, 0x10, 0, 0, 0, 0,  // mem[φ[1]+0] = φ[0]=10 (ra=0,rb=1)
        Opcode::StoreIndU8 as u8, 0x13, 0, 0, 0, 0,  // mem[φ[1]+0] = φ[3]=20 (ra=3,rb=1)
        Opcode::LoadIndU8 as u8, 0x12, 0, 0, 0, 0,   // φ[2] = mem[φ[1]+0] (ra=2,rb=1)
        Opcode::Trap as u8,
    ];
    let bitmask = vec![1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1];

    let pvm = Interpreter::new(code.clone(), bitmask.clone(), vec![], regs, memory, 10000, 25);
    let mut tracing = TracingPvm::new(pvm);
    let exit = tracing.run();
    eprintln!("exit: {exit:?}");

    let steps = tracing.into_trace();
    for (i, s) in steps.iter().enumerate() {
        eprintln!("  step {i}: pc={} opcode={:?} regs[0..4]={:?}", s.pc, s.opcode, &s.regs_after[..4]);
    }
    assert_eq!(exit, javm::ExitReason::Trap);
    assert_eq!(steps.len(), 4);
    assert_eq!(steps[2].regs_after[2], 20); // should read the second write

    prove_and_verify(steps, &code, &bitmask);
}

#[test]
fn prove_store_load_with_alu() {
    // ALU + memory mixed: compute a value, store it, load it back
    // φ[2] = φ[0] + φ[1] = 150
    // mem[0x1000] = φ[2]
    // φ[3] = mem[0x1000]
    let mut regs = [0u64; PVM_REGISTER_COUNT];
    regs[0] = 100;
    regs[1] = 50;
    regs[4] = 0x1000; // address register

    let mut memory = vec![0u8; 4 * 1024 * 1024];

    let code = vec![
        Opcode::Add64 as u8, 0x10, 2,                   // φ[2] = φ[0]+φ[1] = 150
        Opcode::StoreIndU8 as u8, 0x42, 0, 0, 0, 0,    // mem[φ[4]+0] = φ[2] (ra=2,rb=4)
        Opcode::LoadIndU8 as u8, 0x43, 0, 0, 0, 0,     // φ[3] = mem[φ[4]+0] (ra=3,rb=4)
        Opcode::Trap as u8,
    ];
    let bitmask = vec![1, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1];

    let pvm = Interpreter::new(code.clone(), bitmask.clone(), vec![], regs, memory, 10000, 25);
    let mut tracing = TracingPvm::new(pvm);
    let exit = tracing.run();
    assert_eq!(exit, javm::ExitReason::Trap);

    let steps = tracing.into_trace();
    assert_eq!(steps.len(), 4);
    assert_eq!(steps[0].regs_after[2], 150); // Add64
    assert_eq!(steps[2].regs_after[3], 150); // LoadIndU8 reads back 150

    prove_and_verify(steps, &code, &bitmask);
}
