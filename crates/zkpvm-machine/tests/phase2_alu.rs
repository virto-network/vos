use javm::instruction::Opcode;
use javm::vm::Pvm;
use javm::Memory;
use javm::PVM_REGISTER_COUNT;

use zkpvm_core::tracing::TracingPvm;
use zkpvm_machine::{prove, verify};

/// Helper: build a PVM with a single three-register instruction followed by Trap.
/// Bytecode: [opcode, ra | (rb<<4), rd, Trap]
/// Bitmask:  [1, 0, 0, 1]
fn run_three_reg(opcode: Opcode, ra: u8, rb: u8, rd: u8, regs: [u64; PVM_REGISTER_COUNT]) -> Vec<zkpvm_core::step::PvmStep> {
    let code = vec![opcode as u8, ra | (rb << 4), rd, Opcode::Trap as u8];
    let bitmask = vec![1, 0, 0, 1];
    let pvm = Pvm::new(code, bitmask, vec![], regs, Memory::new(), 10000);
    let mut tracing = TracingPvm::new(pvm);
    let exit = tracing.run();
    assert_eq!(exit, javm::vm::ExitReason::Panic);
    tracing.into_trace()
}

/// Helper: build a PVM with a two-register + immediate instruction followed by Trap.
/// Bytecode: [opcode, ra | (rb<<4), imm_bytes..., Trap]
/// The immediate is sign-extended from `imm_len` bytes.
fn run_two_reg_imm(opcode: Opcode, ra: u8, rb: u8, imm: i64, regs: [u64; PVM_REGISTER_COUNT]) -> Vec<zkpvm_core::step::PvmStep> {
    // Encode: opcode, reg_byte, imm (up to 4 bytes LE), trap
    let imm_bytes = (imm as u64).to_le_bytes();
    let imm_len = 4usize; // use 4-byte immediate
    let mut code = vec![opcode as u8, ra | (rb << 4)];
    code.extend_from_slice(&imm_bytes[..imm_len]);
    code.push(Opcode::Trap as u8);
    // bitmask: 1 at start, 0s for args, 1 at trap
    let mut bitmask = vec![1u8];
    bitmask.extend(vec![0u8; 1 + imm_len]); // reg_byte + imm
    bitmask.push(1);
    let pvm = Pvm::new(code, bitmask, vec![], regs, Memory::new(), 10000);
    let mut tracing = TracingPvm::new(pvm);
    let exit = tracing.run();
    assert_eq!(exit, javm::vm::ExitReason::Panic);
    tracing.into_trace()
}

/// Helper: prove and verify a set of steps
fn prove_and_verify(steps: Vec<zkpvm_core::step::PvmStep>, code: &[u8], bitmask: &[u8]) {
    let mut side_note = zkpvm_machine::SideNote::new(steps, code.to_vec(), bitmask.to_vec());
    let proof = prove(&mut side_note).expect("proving failed");
    verify(proof, &side_note).expect("verification failed");
}

/// Helper: run a three-reg op, verify result, prove & verify
fn test_three_reg_op(opcode: Opcode, r0: u64, r1: u64, expected: u64) {
    let mut regs = [0u64; PVM_REGISTER_COUNT];
    regs[0] = r0;
    regs[1] = r1;
    let steps = run_three_reg(opcode, 0, 1, 2, regs);
    assert_eq!(steps[0].regs_after[2], expected, "opcode {:?}: {} op {} != {}", opcode, r0, r1, expected);
    let code = vec![opcode as u8, 0x10, 2, Opcode::Trap as u8];
    let bitmask = vec![1, 0, 0, 1];
    prove_and_verify(steps, &code, &bitmask);
}

// ── Add tests ──

#[test]
fn prove_add64() {
    test_three_reg_op(Opcode::Add64, 100, 200, 300);
}

#[test]
fn prove_add64_wrapping() {
    test_three_reg_op(Opcode::Add64, u64::MAX, 1, 0); // wrapping
}

#[test]
fn prove_add32() {
    // Add32 wraps at 2^32: result = (a + b) mod 2^32, zero-extended
    test_three_reg_op(Opcode::Add32, 0xFFFF_FFFE, 3, 1); // (2^32-2 + 3) mod 2^32 = 1
}

// ── Sub tests ──

#[test]
fn prove_sub64() {
    test_three_reg_op(Opcode::Sub64, 300, 100, 200);
}

#[test]
fn prove_sub64_underflow() {
    test_three_reg_op(Opcode::Sub64, 0, 1, u64::MAX); // wrapping underflow
}

#[test]
fn prove_sub32() {
    test_three_reg_op(Opcode::Sub32, 10, 3, 7);
}

// ── Bitwise tests ──

#[test]
fn prove_and() {
    test_three_reg_op(Opcode::And, 0xFF00_FF00_FF00_FF00, 0x0F0F_0F0F_0F0F_0F0F, 0x0F00_0F00_0F00_0F00);
}

#[test]
fn prove_or() {
    test_three_reg_op(Opcode::Or, 0xFF00, 0x00FF, 0xFFFF);
}

#[test]
fn prove_xor() {
    test_three_reg_op(Opcode::Xor, 0xAAAA, 0x5555, 0xFFFF);
}

// ── Move / LoadImm tests ──

#[test]
fn prove_move_reg() {
    // MoveReg is TwoReg: rd=reg_a, ra=reg_b in the encoding
    // MoveReg (opcode 100): φ'[rd] = φ[ra]
    // Encoding: [100, rd | (ra<<4)]
    // So rd=2, ra=0 => reg_byte = 2 | (0<<4) = 0x02
    let mut regs = [0u64; PVM_REGISTER_COUNT];
    regs[0] = 42;
    let code = vec![Opcode::MoveReg as u8, 0x02, Opcode::Trap as u8];
    let bitmask = vec![1, 0, 1];
    let pvm = Pvm::new(code.clone(), bitmask.clone(), vec![], regs, Memory::new(), 10000);
    let mut tracing = TracingPvm::new(pvm);
    let exit = tracing.run();
    assert_eq!(exit, javm::vm::ExitReason::Panic);
    let steps = tracing.into_trace();
    assert_eq!(steps[0].regs_after[2], 42);
    prove_and_verify(steps, &code, &bitmask);
}

#[test]
fn prove_load_imm() {
    // LoadImm (opcode 51): φ'[ra] = sign_extended(imm)
    // OneRegOneImm encoding: [51, ra_byte, imm_bytes...]
    let mut regs = [0u64; PVM_REGISTER_COUNT];
    let imm: u32 = 12345;
    let imm_bytes = imm.to_le_bytes();
    let mut code = vec![Opcode::LoadImm as u8, 2]; // ra=2
    code.extend_from_slice(&imm_bytes);
    code.push(Opcode::Trap as u8);
    let mut bitmask = vec![1, 0, 0, 0, 0, 0];
    bitmask.push(1);
    let pvm = Pvm::new(code.clone(), bitmask.clone(), vec![], regs, Memory::new(), 10000);
    let mut tracing = TracingPvm::new(pvm);
    let exit = tracing.run();
    assert_eq!(exit, javm::vm::ExitReason::Panic);
    let steps = tracing.into_trace();
    // LoadImm with 4-byte positive immediate should give us sign-extended value
    // imm = 12345 (positive, fits in 4 bytes) => sign_extend(12345, 4) = 12345
    assert_eq!(steps[0].regs_after[2], 12345);
    prove_and_verify(steps, &code, &bitmask);
}

// ── Multi-operation program ──

#[test]
fn prove_multi_op_program() {
    // Program: Add64, Sub64, And, MoveReg, Trap
    // φ[2] = φ[0] + φ[1]  (100 + 50 = 150)
    // φ[3] = φ[2] - φ[0]  (150 - 100 = 50)
    // φ[4] = φ[2] & φ[1]  (150 & 50 = 18)
    // φ[5] = φ[4]          (MoveReg)
    let mut regs = [0u64; PVM_REGISTER_COUNT];
    regs[0] = 100;
    regs[1] = 50;

    let code = vec![
        Opcode::Add64 as u8, 0x10, 2,      // Add64 ra=0, rb=1, rd=2
        Opcode::Sub64 as u8, 0x02, 3,      // Sub64 ra=2, rb=0, rd=3
        Opcode::And as u8, 0x12, 4,        // And ra=2, rb=1, rd=4
        Opcode::MoveReg as u8, 0x45,       // MoveReg rd=5, ra=4 => reg_byte = 5 | (4<<4) = 0x45
        Opcode::Trap as u8,
    ];
    let bitmask = vec![
        1, 0, 0,  // Add64
        1, 0, 0,  // Sub64
        1, 0, 0,  // And
        1, 0,     // MoveReg
        1,        // Trap
    ];

    let pvm = Pvm::new(code.clone(), bitmask.clone(), vec![], regs, Memory::new(), 10000);
    let mut tracing = TracingPvm::new(pvm);
    let exit = tracing.run();
    assert_eq!(exit, javm::vm::ExitReason::Panic);
    let steps = tracing.into_trace();

    assert_eq!(steps.len(), 5); // Add64 + Sub64 + And + MoveReg + Trap
    assert_eq!(steps[0].regs_after[2], 150);     // 100 + 50
    assert_eq!(steps[1].regs_after[3], 50);      // 150 - 100
    assert_eq!(steps[2].regs_after[4], 150 & 50); // 18
    assert_eq!(steps[3].regs_after[5], 18);       // MoveReg

    prove_and_verify(steps, &code, &bitmask);
}

// ── Immediate-op tests ──

#[test]
fn prove_add_imm64() {
    let mut regs = [0u64; PVM_REGISTER_COUNT];
    regs[1] = 100;
    let imm_bytes = 50i64.to_le_bytes();
    let mut code = vec![Opcode::AddImm64 as u8, 0x10]; // ra=0, rb=1
    code.extend_from_slice(&imm_bytes[..4]);
    code.push(Opcode::Trap as u8);
    let mut bitmask = vec![1u8, 0, 0, 0, 0, 0];
    bitmask.push(1);
    let pvm = Pvm::new(code.clone(), bitmask.clone(), vec![], regs, Memory::new(), 10000);
    let mut tracing = TracingPvm::new(pvm);
    tracing.run();
    let steps = tracing.into_trace();
    assert_eq!(steps[0].regs_after[0], 150);
    prove_and_verify(steps, &code, &bitmask);
}

#[test]
fn prove_neg_add_imm64() {
    let mut regs = [0u64; PVM_REGISTER_COUNT];
    regs[1] = 30;
    let imm_bytes = 100i64.to_le_bytes();
    let mut code = vec![Opcode::NegAddImm64 as u8, 0x10];
    code.extend_from_slice(&imm_bytes[..4]);
    code.push(Opcode::Trap as u8);
    let mut bitmask = vec![1u8, 0, 0, 0, 0, 0];
    bitmask.push(1);
    let pvm = Pvm::new(code.clone(), bitmask.clone(), vec![], regs, Memory::new(), 10000);
    let mut tracing = TracingPvm::new(pvm);
    tracing.run();
    let steps = tracing.into_trace();
    assert_eq!(steps[0].regs_after[0], 70); // 100 - 30
    prove_and_verify(steps, &code, &bitmask);
}

// ── Mul tests (now constrained via schoolbook multiplication) ──

#[test]
fn prove_mul64_small() {
    test_three_reg_op(Opcode::Mul64, 7, 6, 42);
}

#[test]
fn prove_mul64_large() {
    test_three_reg_op(Opcode::Mul64, 0x1_0000_0000, 0x1_0000_0000, 0); // overflows to 0 in low 64 bits
}

#[test]
fn prove_mul64_max() {
    // u64::MAX * 2 = wrapping: (2^64-1)*2 mod 2^64 = 2^65-2 mod 2^64 = 2^64-2 = u64::MAX-1
    test_three_reg_op(Opcode::Mul64, u64::MAX, 2, u64::MAX - 1);
}

#[test]
fn prove_mul32() {
    test_three_reg_op(Opcode::Mul32, 1000, 1000, 1_000_000);
}

#[test]
fn prove_mul32_overflow() {
    // 0x10000 * 0x10000 = 0x1_0000_0000, mod 2^32 = 0
    test_three_reg_op(Opcode::Mul32, 0x10000, 0x10000, 0);
}

// ── Bitwise tests (now constrained via algebraic identity on AND result) ──

#[test]
fn prove_xnor() {
    test_three_reg_op(Opcode::Xnor, 0xFF, 0x0F, !(0xFF ^ 0x0F));
}

#[test]
fn prove_and_inv() {
    test_three_reg_op(Opcode::AndInv, 0xFF, 0x0F, 0xFF & !0x0F);
}

#[test]
fn prove_or_inv() {
    // OrInv(a,b) = a | !b
    test_three_reg_op(Opcode::OrInv, 0xF0, 0x0F, 0xF0 | !0x0Fu64);
}

#[test]
fn prove_bitwise_large() {
    test_three_reg_op(Opcode::And, 0xDEAD_BEEF_CAFE_BABE, 0x1234_5678_9ABC_DEF0,
        0xDEAD_BEEF_CAFE_BABE & 0x1234_5678_9ABC_DEF0);
}

#[test]
fn prove_xor_self() {
    test_three_reg_op(Opcode::Xor, 0xAAAA_BBBB_CCCC_DDDD, 0xAAAA_BBBB_CCCC_DDDD, 0);
}

// ── Compare tests (SetLtU now constrained via cmp_carry chain) ──

#[test]
fn prove_set_lt_u_true() {
    // SetLtU: φ[rd] = (φ[ra] < φ[rb]) ? 1 : 0 (unsigned)
    test_three_reg_op(Opcode::SetLtU, 5, 10, 1);
}

#[test]
fn prove_set_lt_u_false() {
    test_three_reg_op(Opcode::SetLtU, 10, 5, 0);
}

#[test]
fn prove_set_lt_u_equal() {
    test_three_reg_op(Opcode::SetLtU, 42, 42, 0);
}

#[test]
fn prove_set_lt_u_large() {
    test_three_reg_op(Opcode::SetLtU, u64::MAX - 1, u64::MAX, 1);
}
