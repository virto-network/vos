use javm::instruction::Opcode;
use javm::interpreter::Interpreter;
// Memory is now flat_mem in Interpreter
use javm::PVM_REGISTER_COUNT;

use zkpvm::core::tracing::TracingPvm;
use zkpvm::{prove, verify};

fn prove_and_verify(steps: Vec<zkpvm::core::step::PvmStep>, code: &[u8], bitmask: &[u8]) {
    let mut side_note = zkpvm::SideNote::new(steps, code.to_vec(), bitmask.to_vec());
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

// Negative test (Phase 12h): Fallthrough is classified with no special control-
// flow flags (is_branch=is_jump=is_exit=0), so the sequential-PC constraint
// (next_pc = pc + 1 + skip_len) must fire on it.  If the constraint is missing
// or mis-gated, a forged next_pc would produce a "valid" proof.
#[test]
#[should_panic(expected = "ConstraintsNotSatisfied")]
fn fallthrough_forged_next_pc_rejected() {
    let mut regs = [0u64; PVM_REGISTER_COUNT];
    regs[0] = 5;
    regs[1] = 7;

    let code = vec![
        Opcode::Fallthrough as u8,
        Opcode::Add64 as u8,
        0x10,
        2,
        Opcode::Trap as u8,
    ];
    let bitmask = vec![1, 1, 0, 0, 1];

    let pvm = Interpreter::new(code.clone(), bitmask.clone(), vec![], regs, vec![0u8; 4 * 1024 * 1024], 10000, 25);
    let mut tracing = TracingPvm::new(pvm);
    let _ = tracing.run();
    let mut steps = tracing.into_trace();

    // Forge: claim Fallthrough advances to pc=2 instead of pc=1.
    assert_eq!(steps[0].opcode, Opcode::Fallthrough);
    steps[0].next_pc = 2;

    // Honest proving must fail: the AIR's sequential-PC constraint catches the
    // mismatch between (pc + 1 + skip_len) and the forged next_pc.
    prove_and_verify(steps, &code, &bitmask);
}

#[test]
fn prove_unlikely() {
    // `Unlikely` is the basic-block-end hint counterpart of Fallthrough; the
    // AIR treats both as plain sequential terminators (no control-flow flag).
    let mut regs = [0u64; PVM_REGISTER_COUNT];
    regs[0] = 5;
    regs[1] = 7;

    let code = vec![
        Opcode::Unlikely as u8,
        Opcode::Add64 as u8,
        0x10,
        2,
        Opcode::Trap as u8,
    ];
    let bitmask = vec![1, 1, 0, 0, 1];

    let pvm = Interpreter::new(code.clone(), bitmask.clone(), vec![], regs, vec![0u8; 4 * 1024 * 1024], 10000, 25);
    let mut tracing = TracingPvm::new(pvm);
    let exit = tracing.run();
    assert_eq!(exit, javm::ExitReason::Trap);

    let steps = tracing.into_trace();
    assert_eq!(steps[0].opcode, Opcode::Unlikely);
    assert_eq!(steps[0].next_pc, 1);

    prove_and_verify(steps, &code, &bitmask);
}

// Phase 13d: JumpInd's `next_pc = jump_table[(regs[reg_a] + imm)/2 - 1]`
// is now bound by JumpTableChip — a preprocessed table committing to the
// program's jump_table[].  CpuChip's per-step JumpInd consumer demands
// `(addr = val_b + imm, target = next_pc)` against that table.  An
// attacker dispatching to a valid-but-wrong table entry (different addr
// from val_b+imm) breaks the lookup.
//
// LoadImmJumpInd is *not* covered yet — separate gap, filed as a
// tripwire below.  Its target uses regs[rb] + imm_y where imm_y is
// the SECOND immediate; the current trace stores step.imm = imm_x
// (the load value) and there's no column for imm_y, so binding
// requires either a new LoadImmJumpIndOffset column or piping imm_y
// through PvmStep.
// Phase 13d-loadimmjumpind: LoadImmJumpInd's `next_pc =
// jump_table[(regs[rb]+imm_y)/2 - 1]` is now bound by JumpTableChip via
// the same lookup as JumpInd, but with a separate carry chain pinning
// LoadImmJumpIndAddr = (val_d + imm_y) low 32 bits.
//
// Note: only the JUMP target is bound; the LOAD side
// (`regs[ra] = imm_x`) is still prover-trusted.  Filed as a follow-up.
#[test]
fn load_imm_jump_ind_positive_smoke() {
    let mut regs = [0u64; PVM_REGISTER_COUNT];
    regs[0] = 2; // honest target = jump_table[(2+0)/2 - 1] = jump_table[0] = 3

    let code = vec![
        Opcode::LoadImmJumpInd as u8, 0x01, 0,
        Opcode::Trap as u8, Opcode::Trap as u8, Opcode::Trap as u8,
    ];
    let bitmask = vec![1, 0, 0, 1, 1, 1];

    let pvm = Interpreter::new(
        code.clone(), bitmask.clone(), vec![3u32, 5u32], regs,
        vec![0u8; 4 * 1024 * 1024], 10000, 25,
    );
    let mut tracing = TracingPvm::new(pvm);
    let _ = tracing.run();
    let steps = tracing.into_trace();
    assert_eq!(steps[0].opcode, Opcode::LoadImmJumpInd);
    assert_eq!(steps[0].next_pc, 3);

    let mut side_note = zkpvm::SideNote::new(steps, code, bitmask)
        .with_jump_table(vec![3u32, 5u32]);
    let proof = prove(&mut side_note).expect("proving failed");
    verify(proof, &side_note).expect("verification failed");
}

#[test]
#[should_panic(expected = "failed")]
fn load_imm_jump_ind_forged_target_rejected() {
    let mut regs = [0u64; PVM_REGISTER_COUNT];
    regs[0] = 2; // honest target pc=3

    let code = vec![
        Opcode::LoadImmJumpInd as u8, 0x01, 0,
        Opcode::Trap as u8, Opcode::Trap as u8, Opcode::Trap as u8,
    ];
    let bitmask = vec![1, 0, 0, 1, 1, 1];

    let pvm = Interpreter::new(
        code.clone(), bitmask.clone(), vec![3u32, 5u32], regs,
        vec![0u8; 4 * 1024 * 1024], 10000, 25,
    );
    let mut tracing = TracingPvm::new(pvm);
    let _ = tracing.run();
    let mut steps = tracing.into_trace();
    assert_eq!(steps[0].next_pc, 3);

    // Forge: dispatch to jump_table[1] = pc=5 instead of jump_table[0] = pc=3.
    steps[0].next_pc = 5;
    steps[1].pc = 5;

    let mut side_note = zkpvm::SideNote::new(steps, code, bitmask)
        .with_jump_table(vec![3u32, 5u32]);
    let proof = prove(&mut side_note).expect("proving failed");
    verify(proof, &side_note).expect("verification failed");
}

#[test]
fn jump_ind_positive_smoke() {
    let mut regs = [0u64; PVM_REGISTER_COUNT];
    regs[0] = 2; // jump_table[0] index → target pc=3.

    let code = vec![
        Opcode::JumpInd as u8, 0, 0,
        Opcode::Trap as u8, Opcode::Trap as u8, Opcode::Trap as u8,
    ];
    let bitmask = vec![1, 0, 0, 1, 1, 1];

    let pvm = Interpreter::new(
        code.clone(), bitmask.clone(), vec![3u32, 5u32], regs,
        vec![0u8; 4 * 1024 * 1024], 10000, 25,
    );
    let mut tracing = TracingPvm::new(pvm);
    let _ = tracing.run();
    let steps = tracing.into_trace();
    assert_eq!(steps[0].opcode, Opcode::JumpInd);
    assert_eq!(steps[0].next_pc, 3);

    let mut side_note = zkpvm::SideNote::new(steps, code, bitmask)
        .with_jump_table(vec![3u32, 5u32]);
    let proof = prove(&mut side_note).expect("proving failed");
    verify(proof, &side_note).expect("verification failed");
}

#[test]
#[should_panic(expected = "failed")]
fn jump_ind_forged_target_rejected() {
    let mut regs = [0u64; PVM_REGISTER_COUNT];
    regs[0] = 2; // honest target pc=3.

    let code = vec![
        Opcode::JumpInd as u8, 0, 0,
        Opcode::Trap as u8, Opcode::Trap as u8, Opcode::Trap as u8,
    ];
    let bitmask = vec![1, 0, 0, 1, 1, 1];

    let pvm = Interpreter::new(
        code.clone(), bitmask.clone(), vec![3u32, 5u32], regs,
        vec![0u8; 4 * 1024 * 1024], 10000, 25,
    );
    let mut tracing = TracingPvm::new(pvm);
    let _ = tracing.run();
    let mut steps = tracing.into_trace();
    assert_eq!(steps[0].next_pc, 3);

    // Forge: dispatch to jump_table[1] = pc=5 instead of jump_table[0]=3.
    // val_b + imm = 2 + 0 = 2 (canonical addr for jump_table[0]).  The
    // JumpTableChip lookup demands (addr=2, target=jump_table[0]=3); we
    // claim (addr=2, target=5) — no matching producer → reject.
    steps[0].next_pc = 5;
    steps[1].pc = 5;

    let mut side_note = zkpvm::SideNote::new(steps, code, bitmask)
        .with_jump_table(vec![3u32, 5u32]);
    let proof = prove(&mut side_note).expect("proving failed");
    verify(proof, &side_note).expect("verification failed");
}

// Phase 15-branch-target-fix: ProgramMemoryChip now publishes the
// canonical absolute branch target as a preprocessed `BranchTargetCanon`
// column (= `pc + sign_extend(signed_offset)` for static jumps/branches,
// 0 for JumpInd/LoadImmJumpInd and non-branch ops).  CpuChip emits its
// `BranchTarget` column into the prog_mem tuple, so the existing
// per-step lookup pins it to the canonical decoding.
//
// This test forges a Jump's branch_target/next_pc/successor.pc to
// dispatch to a *different* valid BB start.  Pre-fix this passed (gap
// open); post-fix the prog_mem lookup mismatches the canonical and
// rejects.
#[test]
#[should_panic(expected = "failed")]
fn jump_forged_branch_target_rejected_by_prog_mem_lookup() {
    let mut regs = [0u64; PVM_REGISTER_COUNT];
    regs[0] = 0;
    regs[1] = 0;

    // Jump (opcode 40) at pc=0 with offset=4 → honest target=4.
    // sequential_next_pc = pc + 1 + skip = 0 + 1 + 2 = 3.
    // pc=3 has Trap (would-be fallthrough, dead under static jump).
    // pc=4 has Trap (honest jump target).
    // Both are valid BB starts; both decode to opcode=Trap.
    let code = vec![
        Opcode::Jump as u8, // pc=0
        4, 0,                // pc=1-2: signed_offset = 4 (2 bytes LE)
        Opcode::Trap as u8, // pc=3: would-be-fallthrough Trap (BB start)
        Opcode::Trap as u8, // pc=4: honest jump target (BB start)
    ];
    let bitmask = vec![1, 0, 0, 1, 1];

    let pvm = Interpreter::new(
        code.clone(), bitmask.clone(), vec![], regs,
        vec![0u8; 4 * 1024 * 1024], 10000, 25,
    );
    let mut tracing = TracingPvm::new(pvm);
    let _ = tracing.run();
    let mut steps = tracing.into_trace();
    assert_eq!(steps.len(), 2); // Jump → Trap@4
    assert_eq!(steps[0].opcode, Opcode::Jump);
    assert_eq!(steps[0].next_pc, 4);
    assert_eq!(steps[1].pc, 4);

    // Forge: dispatch to pc=3 instead of pc=4.  Both Traps in the program.
    steps[0].branch_target = 3;
    steps[0].next_pc = 3;
    steps[1].pc = 3;

    prove_and_verify(steps, &code, &bitmask);
}

// Phase 13e-redux: Trap has a per-opcode `IsTrap` flag (distinct from
// `IsExit`, which also covers Ecalli/JumpInd that legitimately have
// successors).  The terminal-row constraint
// `is_real · is_trap · (1 - is_padding_next) = 0` forbids any successor
// real row after Trap.
//
// This test forges a "second Trap" after the real one with all continuity
// fields (timestamp, pc, gas, regs) carefully consistent — even with the
// ProgramExecution chain + ProgramMemory tuple all balanced, the IsTrap
// terminal constraint catches the splice.  Before 13e-redux this test
// passed (gap open); the flip to `#[should_panic]` was the closure of
// the documented gap.
#[test]
#[should_panic(expected = "failed")]
fn trap_followed_by_trap_clone_rejected_by_terminal_constraint() {
    let mut regs = [0u64; PVM_REGISTER_COUNT];
    regs[0] = 5;
    regs[1] = 7;

    let code = vec![
        Opcode::Fallthrough as u8,
        Opcode::Add64 as u8, 0x10, 2,
        Opcode::Trap as u8,
    ];
    let bitmask = vec![1, 1, 0, 0, 1];

    let pvm = Interpreter::new(
        code.clone(), bitmask.clone(), vec![], regs,
        vec![0u8; 4 * 1024 * 1024], 10000, 25,
    );
    let mut tracing = TracingPvm::new(pvm);
    let _ = tracing.run();
    let mut steps = tracing.into_trace();
    assert_eq!(steps.len(), 3);
    let prev = steps[2].clone();
    assert_eq!(prev.opcode, Opcode::Trap);

    // Synthesize a "second Trap" step that consistently follows the first.
    // Trap.next_pc is unconstrained (is_exit=true), so the prover can set
    // it to any pc with a valid Trap (here: pc=4, the same Trap).
    let mut fake = prev.clone();
    fake.timestamp = prev.timestamp + 1;
    fake.pc = prev.next_pc;
    fake.regs_before = prev.regs_after;
    fake.gas_after = prev.gas_after.saturating_sub(1);
    fake.next_pc = fake.pc;
    steps.push(fake);

    prove_and_verify(steps, &code, &bitmask);
}

#[test]
#[should_panic(expected = "failed")]
fn trap_mid_trace_rejected() {
    let mut regs = [0u64; PVM_REGISTER_COUNT];
    regs[0] = 5;
    regs[1] = 7;

    // Honest program: Fallthrough → Add64 → Trap.
    let code = vec![
        Opcode::Fallthrough as u8,
        Opcode::Add64 as u8,
        0x10,
        2,
        Opcode::Trap as u8,
    ];
    let bitmask = vec![1, 1, 0, 0, 1];

    let pvm = Interpreter::new(code.clone(), bitmask.clone(), vec![], regs, vec![0u8; 4 * 1024 * 1024], 10000, 25);
    let mut tracing = TracingPvm::new(pvm);
    let _ = tracing.run();
    let mut steps = tracing.into_trace();
    assert_eq!(steps.len(), 3);
    assert_eq!(steps[2].opcode, Opcode::Trap);

    // Forge: take the original 3-step trace and append a fake post-Trap step
    // claiming continued execution (a Fallthrough).  The terminal-row
    // constraint sees Trap at row 2 with a real (non-padding) row 3 → reject.
    let mut fake = steps[0].clone(); // copy a Fallthrough step
    fake.timestamp = 4;
    fake.pc = 0;
    fake.next_pc = 1;
    steps.push(fake);

    prove_and_verify(steps, &code, &bitmask);
}

#[test]
#[should_panic(expected = "ConstraintsNotSatisfied")]
fn unlikely_forged_next_pc_rejected() {
    let mut regs = [0u64; PVM_REGISTER_COUNT];
    regs[0] = 5;
    regs[1] = 7;

    let code = vec![
        Opcode::Unlikely as u8,
        Opcode::Add64 as u8,
        0x10,
        2,
        Opcode::Trap as u8,
    ];
    let bitmask = vec![1, 1, 0, 0, 1];

    let pvm = Interpreter::new(code.clone(), bitmask.clone(), vec![], regs, vec![0u8; 4 * 1024 * 1024], 10000, 25);
    let mut tracing = TracingPvm::new(pvm);
    let _ = tracing.run();
    let mut steps = tracing.into_trace();

    assert_eq!(steps[0].opcode, Opcode::Unlikely);
    steps[0].next_pc = 2;

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

// ── Phase 41: Sbrk as terminal opcode ─────────────────────────────────────
// Sbrk panics on execution (JAR v0.8.0 removed it from the ISA in favour of
// the grow_heap hostcall).  Phase 41 marks Sbrk as is_exit + is_trap so the
// terminal-row constraint forbids any successor real row, matching the
// interpreter's panic-and-stop semantics.

#[test]
fn prove_sbrk_terminal() {
    let regs = [0u64; PVM_REGISTER_COUNT];
    let code = vec![Opcode::Sbrk as u8];
    let bitmask = vec![1];
    let pvm = Interpreter::new(
        code.clone(), bitmask.clone(), vec![], regs,
        vec![0u8; 4 * 1024 * 1024], 10000, 25,
    );
    let mut tracing = TracingPvm::new(pvm);
    let exit = tracing.run();
    assert_eq!(exit, javm::ExitReason::Panic);
    let steps = tracing.into_trace();
    assert_eq!(steps.len(), 1);
    assert_eq!(steps[0].opcode, Opcode::Sbrk);
    prove_and_verify(steps, &code, &bitmask);
}

#[test]
#[should_panic(expected = "failed")]
fn sbrk_followed_by_clone_rejected_by_terminal_constraint() {
    // Same shape as `trap_followed_by_trap_clone_rejected_by_terminal_constraint`
    // but for Sbrk: synthesize a "second Sbrk" step after the real one with
    // all continuity fields plausibly consistent.  The Phase 41 IsTrap flag
    // (set on Sbrk) drives Phase 13e-redux's terminal-row constraint
    // (`is_real · is_trap · (1 - is_padding_next) = 0`) → splice rejected.
    let regs = [0u64; PVM_REGISTER_COUNT];
    let code = vec![Opcode::Sbrk as u8];
    let bitmask = vec![1];
    let pvm = Interpreter::new(
        code.clone(), bitmask.clone(), vec![], regs,
        vec![0u8; 4 * 1024 * 1024], 10000, 25,
    );
    let mut tracing = TracingPvm::new(pvm);
    let _ = tracing.run();
    let mut steps = tracing.into_trace();
    assert_eq!(steps.len(), 1);
    let prev = steps[0].clone();
    let mut clone = prev.clone();
    clone.timestamp = prev.timestamp + 1;
    steps.push(clone);
    prove_and_verify(steps, &code, &bitmask);
}
