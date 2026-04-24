use javm::instruction::Opcode;
use javm::interpreter::Interpreter;
// Memory is now flat_mem in Interpreter
use javm::PVM_REGISTER_COUNT;

use zkpvm::core::tracing::TracingPvm;
use zkpvm::{prove, verify, SideNote};

#[test]
fn prove_verify_add64() {
    // Build a PVM program: Add64 φ[2] = φ[0] + φ[1], then Trap
    let code = vec![
        Opcode::Add64 as u8, // offset 0: Add64
        0x10,                // ra=0 (0%16), rb=1 (16/16)
        2,                   // rd=2
        Opcode::Trap as u8,  // offset 3: Trap
    ];
    let bitmask = vec![1, 0, 0, 1];

    let mut registers = [0u64; PVM_REGISTER_COUNT];
    registers[0] = 100;
    registers[1] = 200;

    let pvm = Interpreter::new(
        code.clone(),
        bitmask.clone(),
        vec![],
        registers,
        vec![0u8; 4 * 1024 * 1024],
        1000u64,
        25,
    );

    let mut tracing = TracingPvm::new(pvm);
    let exit = tracing.run();
    assert_eq!(exit, javm::ExitReason::Trap); // Trap = Panic

    let steps = tracing.into_trace();
    eprintln!("Steps: {}", steps.len());
    for (i, s) in steps.iter().enumerate() {
        eprintln!("  step {i}: pc={} opcode={:?} regs_after[0..3]={:?} reg_write={:?}",
            s.pc, s.opcode, &s.regs_after[..3], s.reg_write);
    }
    assert_eq!(steps.len(), 2);
    // φ[rd] = φ[ra] + φ[rb] => φ[2] = φ[0] + φ[1] = 300
    assert_eq!(steps[0].regs_after[2], 300);

    let mut side_note = SideNote::new(steps, code, bitmask);
    eprintln!("Starting prove...");
    match prove(&mut side_note) {
        Ok(proof) => {
            eprintln!("Proof generated. Verifying...");
            match verify(proof, &side_note) {
                Ok(()) => eprintln!("Verification passed!"),
                Err(e) => panic!("verification failed: {e:?}"),
            }
        }
        Err(e) => panic!("proving failed: {e:?}"),
    }
}
