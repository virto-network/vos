use javm::instruction::Opcode;
use javm::interpreter::Interpreter;
// Memory is now flat_mem in Interpreter
use javm::PVM_REGISTER_COUNT;

use zkpvm_core::tracing::TracingPvm;
use zkpvm_machine::{prove, verify};

fn prove_and_verify(steps: Vec<zkpvm_core::step::PvmStep>, code: &[u8], bitmask: &[u8]) {
    let mut side_note = zkpvm_machine::SideNote::new(steps, code.to_vec(), bitmask.to_vec());
    let proof = prove(&mut side_note).expect("proving failed");
    verify(proof, &side_note).expect("verification failed");
}

// ── Jump ──

#[test]
fn prove_unconditional_jump() {
    // Program:
    //   0: Jump to offset 5      (Jump opcode=40, offset encoded as pc-relative)
    //   3: Trap (should be skipped)
    //   5: Add64 φ[2] = φ[0] + φ[1]
    //   8: Trap
    //
    // Jump target = pc + signed_offset. Jump at pc=0, target=5 means offset=5.
    // OneOffset encoding: [opcode, offset_bytes...]
    // skip_len determines how many offset bytes: with bitmask [1,0,0,1,...], skip=2, so lX=min(4,2)=2
    // offset = sign_extend(5, 2) = 5. target = pc + offset = 0 + 5 = 5.
    // But 5 must be a valid basic block start. We need bitmask[5]=1 and it must be a BB start.
    // In javm, basic block starts are computed from terminators. Jump at offset 0 is a terminator,
    // so offset 3 starts a new BB. The Add64 at offset 5 might not be a BB start unless
    // offset 3 is also a terminator.
    //
    // Simpler approach: use Fallthrough to skip to the Add64.
    // Actually, let's make offset 3 = Fallthrough (which is a terminator), so offset 5 is a BB start.
    // Wait, Fallthrough at 3 means 3 is a single-byte instruction → skip=0 → next_pc=4.
    // That doesn't help.
    //
    // Simplest: Jump forward over one instruction.
    // offset 0: Jump → target = 3 (just skip the next byte)
    // offset 1-2: data bytes (skip)
    // offset 3: Add64 φ[2] = φ[0] + φ[1]
    // offset 6: Trap
    //
    // But Jump target must be a basic block start. offset 3 is after a terminator (Jump), so it IS a BB start. ✓

    let mut regs = [0u64; PVM_REGISTER_COUNT];
    regs[0] = 10;
    regs[1] = 20;

    // Jump target = pc(0) + offset. We want target=3.
    // OneOffset: [opcode, imm_bytes...]. skip=2 → lX=min(4,2)=2.
    // signed_offset = target - pc = 3 - 0 = 3.
    // Encode 3 as 2-byte LE: [3, 0]
    let code = vec![
        Opcode::Jump as u8,  // offset 0
        3, 0,                // offset 1-2: signed_offset = 3 (2 bytes LE)
        Opcode::Add64 as u8, // offset 3: Add64
        0x10,                // ra=0, rb=1
        2,                   // rd=2
        Opcode::Trap as u8,  // offset 6
    ];
    let bitmask = vec![1, 0, 0, 1, 0, 0, 1];

    let pvm = Interpreter::new(code.clone(), bitmask.clone(), vec![], regs, vec![0u8; 4 * 1024 * 1024], 10000, 25);
    let mut tracing = TracingPvm::new(pvm);
    let exit = tracing.run();
    assert_eq!(exit, javm::ExitReason::Trap); // Trap

    let steps = tracing.into_trace();
    // Should be: Jump(pc=0→3), Add64(pc=3), Trap(pc=6)
    assert_eq!(steps.len(), 3);
    assert_eq!(steps[0].opcode, Opcode::Jump);
    assert_eq!(steps[0].next_pc, 3);
    assert_eq!(steps[1].opcode, Opcode::Add64);
    assert_eq!(steps[1].regs_after[2], 30); // 10 + 20
    assert_eq!(steps[2].opcode, Opcode::Trap);

    prove_and_verify(steps, &code, &bitmask);
}

// ── Fallthrough ──

#[test]
fn prove_fallthrough() {
    let mut regs = [0u64; PVM_REGISTER_COUNT];
    regs[0] = 5;
    regs[1] = 7;

    // Fallthrough (opcode 1) is a no-op terminator, advances to next instruction.
    let code = vec![
        Opcode::Fallthrough as u8, // offset 0
        Opcode::Add64 as u8,       // offset 1
        0x10,                       // ra=0, rb=1
        2,                          // rd=2
        Opcode::Trap as u8,        // offset 4
    ];
    let bitmask = vec![1, 1, 0, 0, 1];

    let pvm = Interpreter::new(code.clone(), bitmask.clone(), vec![], regs, vec![0u8; 4 * 1024 * 1024], 10000, 25);
    let mut tracing = TracingPvm::new(pvm);
    let exit = tracing.run();
    assert_eq!(exit, javm::ExitReason::Trap);

    let steps = tracing.into_trace();
    assert_eq!(steps.len(), 3); // Fallthrough, Add64, Trap
    assert_eq!(steps[0].opcode, Opcode::Fallthrough);
    assert_eq!(steps[0].next_pc, 1);
    assert_eq!(steps[1].regs_after[2], 12); // 5 + 7

    prove_and_verify(steps, &code, &bitmask);
}

// ── Branch taken ──

#[test]
fn prove_branch_eq_taken() {
    let mut regs = [0u64; PVM_REGISTER_COUNT];
    regs[0] = 42;
    regs[1] = 42; // equal → branch taken

    // BranchEq at pc=0 with equal regs → branch is taken.
    // Target = pc + offset = 0 + 5 = 5 (same as sequential next_pc).
    // This tests that the branch mechanism works even when target == fallthrough.
    let code = vec![
        Opcode::BranchEq as u8, // offset 0
        0x10,                    // ra=0, rb=1
        5, 0, 0,                 // signed_offset = 5 (target = offset 5)
        Opcode::Trap as u8,     // offset 5
    ];
    let bitmask = vec![1, 0, 0, 0, 0, 1];

    let pvm = Interpreter::new(code.clone(), bitmask.clone(), vec![], regs, vec![0u8; 4 * 1024 * 1024], 10000, 25);
    let mut tracing = TracingPvm::new(pvm);
    let exit = tracing.run();
    assert_eq!(exit, javm::ExitReason::Trap);

    let steps = tracing.into_trace();
    assert_eq!(steps.len(), 2); // BranchEq → Trap

    prove_and_verify(steps, &code, &bitmask);
}

// ── Branch not taken ──

#[test]
fn prove_branch_eq_not_taken() {
    let mut regs = [0u64; PVM_REGISTER_COUNT];
    regs[0] = 42;
    regs[1] = 99; // not equal → fall through

    // BranchEq at pc=0, falls through to pc=5 (sequential)
    // Sequential next_pc = pc + 1 + skip = 0 + 1 + 4 = 5
    let code = vec![
        Opcode::BranchEq as u8, // offset 0
        0x10,                    // ra=0, rb=1
        10, 0, 0,                // offset (irrelevant since not taken)
        Opcode::Trap as u8,     // offset 5
    ];
    let bitmask = vec![1, 0, 0, 0, 0, 1];

    let pvm = Interpreter::new(code.clone(), bitmask.clone(), vec![], regs, vec![0u8; 4 * 1024 * 1024], 10000, 25);
    let mut tracing = TracingPvm::new(pvm);
    let exit = tracing.run();
    assert_eq!(exit, javm::ExitReason::Trap);

    let steps = tracing.into_trace();
    assert_eq!(steps.len(), 2); // BranchEq (not taken) → Trap
    assert_eq!(steps[0].opcode, Opcode::BranchEq);
    assert!(!steps[0].branch_taken);
    assert_eq!(steps[0].next_pc, 5); // sequential

    prove_and_verify(steps, &code, &bitmask);
}

// ── Simple loop (Add64 in a loop via BranchNe) ──

#[test]
fn prove_loop_add() {
    // Program: accumulate φ[0] += 1 three times using a loop counter
    // φ[0] = 0 (accumulator)
    // φ[1] = 3 (counter)
    // φ[2] = 1 (constant 1)
    //
    // loop:
    //   0: Add64 φ[0] = φ[0] + φ[2]     (accum += 1)
    //   3: Sub64 φ[1] = φ[1] - φ[2]     (counter -= 1)
    //   6: BranchNe φ[1], φ[3] → loop   (if counter != 0, jump to 0)
    //   10: Trap
    //
    // φ[3] = 0 (zero register for comparison)

    let mut regs = [0u64; PVM_REGISTER_COUNT];
    regs[0] = 0;  // accumulator
    regs[1] = 3;  // counter
    regs[2] = 1;  // constant 1

    // Add64(ra=0,rb=2,rd=0): φ[0] = φ[0] + φ[2]
    // reg_byte = 0 | (2<<4) = 0x20, rd = 0
    // Sub64(ra=1,rb=2,rd=1): φ[1] = φ[1] - φ[2]
    // reg_byte = 1 | (2<<4) = 0x21, rd = 1
    // BranchNe(ra=1,rb=3,offset): if φ[1] != φ[3], jump
    // reg_byte = 1 | (3<<4) = 0x31
    // target = pc(6) + offset = 0 → offset = 0 - 6 = -6
    // -6 as signed 3-byte LE: 0xFA, 0xFF, 0xFF

    let code = vec![
        Opcode::Add64 as u8, 0x20, 0,       // offset 0: Add64 φ[0]=φ[0]+φ[2]
        Opcode::Sub64 as u8, 0x21, 1,       // offset 3: Sub64 φ[1]=φ[1]-φ[2]
        Opcode::BranchNe as u8, 0x31,       // offset 6: BranchNe φ[1] != φ[3]
        0xFA_u8, 0xFF, 0xFF,                 // offset = -6 (signed, 3 bytes LE)
        Opcode::Trap as u8,                  // offset 11
    ];
    let bitmask = vec![1, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 1];

    let pvm = Interpreter::new(code.clone(), bitmask.clone(), vec![], regs, vec![0u8; 4 * 1024 * 1024], 10000, 25);
    let mut tracing = TracingPvm::new(pvm);
    let exit = tracing.run();
    assert_eq!(exit, javm::ExitReason::Trap);

    let steps = tracing.into_trace();
    // 3 iterations × 3 instructions + Trap = 10 steps
    // iter 1: Add(0→1), Sub(3→2), Branch(taken → 0)
    // iter 2: Add(1→2), Sub(2→1), Branch(taken → 0)
    // iter 3: Add(2→3), Sub(1→0), Branch(NOT taken → 11)
    // Then: Trap
    assert_eq!(steps.len(), 10);

    // After 3 additions of 1: accumulator = 3
    assert_eq!(steps[8].regs_after[0], 3); // last Add step is at index 6
    // Actually let me check: steps are Add,Sub,Branch × 3 + Trap
    // step 0: Add(0+1=1), step 1: Sub(3-1=2), step 2: Branch(2!=0, taken)
    // step 3: Add(1+1=2), step 4: Sub(2-1=1), step 5: Branch(1!=0, taken)
    // step 6: Add(2+1=3), step 7: Sub(1-1=0), step 8: Branch(0!=0? no, not taken)
    // step 9: Trap
    assert_eq!(steps[6].regs_after[0], 3); // accumulator after 3rd Add
    assert_eq!(steps[7].regs_after[1], 0); // counter after 3rd Sub
    assert!(!steps[8].branch_taken); // last branch not taken (counter=0)

    prove_and_verify(steps, &code, &bitmask);
}
