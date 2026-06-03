#![cfg(feature = "prover")]

use javm::instruction::Opcode;
use javm::interpreter::Interpreter;
// Memory is now flat_mem in Interpreter
use javm::PVM_REGISTER_COUNT;

use zkpvm::core::tracing::TracingPvm;
use zkpvm::{PcsPolicy, prove, prove_mobile, verify, verify_with_pcs_policy};

/// Helper: build a PVM with a single three-register instruction followed by Trap.
/// Bytecode: [opcode, ra | (rb<<4), rd, Trap]
/// Bitmask:  [1, 0, 0, 1]
fn run_three_reg(
    opcode: Opcode,
    ra: u8,
    rb: u8,
    rd: u8,
    regs: [u64; PVM_REGISTER_COUNT],
) -> Vec<zkpvm::core::step::PvmStep> {
    let code = vec![opcode as u8, ra | (rb << 4), rd, Opcode::Trap as u8];
    let bitmask = vec![1, 0, 0, 1];
    let pvm = Interpreter::new(
        code,
        bitmask,
        vec![],
        regs,
        vec![0u8; 4 * 1024 * 1024],
        10000,
        25,
    );
    let mut tracing = TracingPvm::new(pvm);
    let exit = tracing.run();
    assert_eq!(exit, javm::ExitReason::Trap);
    tracing.into_trace()
}

#[allow(dead_code)]
fn run_two_reg_imm(
    opcode: Opcode,
    ra: u8,
    rb: u8,
    imm: i64,
    regs: [u64; PVM_REGISTER_COUNT],
) -> Vec<zkpvm::core::step::PvmStep> {
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
    let pvm = Interpreter::new(
        code,
        bitmask,
        vec![],
        regs,
        vec![0u8; 4 * 1024 * 1024],
        10000,
        25,
    );
    let mut tracing = TracingPvm::new(pvm);
    let exit = tracing.run();
    assert_eq!(exit, javm::ExitReason::Trap);
    tracing.into_trace()
}

/// Helper: prove and verify a set of steps
fn prove_and_verify(steps: Vec<zkpvm::core::step::PvmStep>, code: &[u8], bitmask: &[u8]) {
    let mut side_note = zkpvm::SideNote::new(steps, code.to_vec(), bitmask.to_vec());
    let proof = prove(&mut side_note).expect("proving failed");
    verify(proof, &side_note).expect("verification failed");
}

/// Helper: run a three-reg op, verify result, prove & verify
fn test_three_reg_op(opcode: Opcode, r0: u64, r1: u64, expected: u64) {
    let mut regs = [0u64; PVM_REGISTER_COUNT];
    regs[0] = r0;
    regs[1] = r1;
    let steps = run_three_reg(opcode, 0, 1, 2, regs);
    assert_eq!(
        steps[0].regs_after[2], expected,
        "opcode {:?}: {} op {} != {}",
        opcode, r0, r1, expected
    );
    let code = vec![opcode as u8, 0x10, 2, Opcode::Trap as u8];
    let bitmask = vec![1, 0, 0, 1];
    prove_and_verify(steps, &code, &bitmask);
}

// ── Add tests ──

#[test]
fn prove_add64() {
    test_three_reg_op(Opcode::Add64, 100, 200, 300);
}

/// Smoke test for the MOBILE prover entry point.  Exercises
/// `prove_mobile()` + `verify_with_pcs_policy(MOBILE)` end-to-end on
/// the simplest workload (a single Add64) so the public API stays
/// regression-tested even when no real-actor benchmark is run in CI.
#[test]
fn prove_mobile_smoke() {
    let mut regs = [0u64; PVM_REGISTER_COUNT];
    regs[0] = 100;
    regs[1] = 200;
    let steps = run_three_reg(Opcode::Add64, 0, 1, 2, regs);
    let code = vec![Opcode::Add64 as u8, 0x10, 2, Opcode::Trap as u8];
    let bitmask = vec![1, 0, 0, 1];

    let mut side_note = zkpvm::SideNote::new(steps, code, bitmask);
    let proof = prove_mobile(&mut side_note).expect("MOBILE proving failed");
    verify_with_pcs_policy(proof, &side_note, &PcsPolicy::MOBILE)
        .expect("MOBILE verification failed");
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
    test_three_reg_op(
        Opcode::And,
        0xFF00_FF00_FF00_FF00,
        0x0F0F_0F0F_0F0F_0F0F,
        0x0F00_0F00_0F00_0F00,
    );
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
    let pvm = Interpreter::new(
        code.clone(),
        bitmask.clone(),
        vec![],
        regs,
        vec![0u8; 4 * 1024 * 1024],
        10000,
        25,
    );
    let mut tracing = TracingPvm::new(pvm);
    let exit = tracing.run();
    assert_eq!(exit, javm::ExitReason::Trap);
    let steps = tracing.into_trace();
    assert_eq!(steps[0].regs_after[2], 42);
    prove_and_verify(steps, &code, &bitmask);
}

#[test]
fn prove_load_imm() {
    // LoadImm (opcode 51): φ'[ra] = sign_extended(imm)
    // OneRegOneImm encoding: [51, ra_byte, imm_bytes...]
    let regs = [0u64; PVM_REGISTER_COUNT];
    let imm: u32 = 12345;
    let imm_bytes = imm.to_le_bytes();
    let mut code = vec![Opcode::LoadImm as u8, 2]; // ra=2
    code.extend_from_slice(&imm_bytes);
    code.push(Opcode::Trap as u8);
    let mut bitmask = vec![1, 0, 0, 0, 0, 0];
    bitmask.push(1);
    let pvm = Interpreter::new(
        code.clone(),
        bitmask.clone(),
        vec![],
        regs,
        vec![0u8; 4 * 1024 * 1024],
        10000,
        25,
    );
    let mut tracing = TracingPvm::new(pvm);
    let exit = tracing.run();
    assert_eq!(exit, javm::ExitReason::Trap);
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
        Opcode::Add64 as u8,
        0x10,
        2, // Add64 ra=0, rb=1, rd=2
        Opcode::Sub64 as u8,
        0x02,
        3, // Sub64 ra=2, rb=0, rd=3
        Opcode::And as u8,
        0x12,
        4, // And ra=2, rb=1, rd=4
        Opcode::MoveReg as u8,
        0x45, // MoveReg rd=5, ra=4 => reg_byte = 5 | (4<<4) = 0x45
        Opcode::Trap as u8,
    ];
    let bitmask = vec![
        1, 0, 0, // Add64
        1, 0, 0, // Sub64
        1, 0, 0, // And
        1, 0, // MoveReg
        1, // Trap
    ];

    let pvm = Interpreter::new(
        code.clone(),
        bitmask.clone(),
        vec![],
        regs,
        vec![0u8; 4 * 1024 * 1024],
        10000,
        25,
    );
    let mut tracing = TracingPvm::new(pvm);
    let exit = tracing.run();
    assert_eq!(exit, javm::ExitReason::Trap);
    let steps = tracing.into_trace();

    assert_eq!(steps.len(), 5); // Add64 + Sub64 + And + MoveReg + Trap
    assert_eq!(steps[0].regs_after[2], 150); // 100 + 50
    assert_eq!(steps[1].regs_after[3], 50); // 150 - 100
    assert_eq!(steps[2].regs_after[4], 150 & 50); // 18
    assert_eq!(steps[3].regs_after[5], 18); // MoveReg

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
    let pvm = Interpreter::new(
        code.clone(),
        bitmask.clone(),
        vec![],
        regs,
        vec![0u8; 4 * 1024 * 1024],
        10000,
        25,
    );
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
    let pvm = Interpreter::new(
        code.clone(),
        bitmask.clone(),
        vec![],
        regs,
        vec![0u8; 4 * 1024 * 1024],
        10000,
        25,
    );
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
    test_three_reg_op(
        Opcode::And,
        0xDEAD_BEEF_CAFE_BABE,
        0x1234_5678_9ABC_DEF0,
        0xDEAD_BEEF_CAFE_BABE & 0x1234_5678_9ABC_DEF0,
    );
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

// ── DivRem tests ──

#[test]
fn prove_div_u64() {
    test_three_reg_op(Opcode::DivU64, 100, 7, 100 / 7); // 14
}

#[test]
fn prove_div_u64_exact() {
    test_three_reg_op(Opcode::DivU64, 42, 6, 7);
}

#[test]
fn prove_div_u64_by_zero() {
    test_three_reg_op(Opcode::DivU64, 42, 0, u64::MAX);
}

#[test]
fn prove_rem_u64() {
    test_three_reg_op(Opcode::RemU64, 100, 7, 100 % 7); // 2
}

#[test]
fn prove_rem_u64_by_zero() {
    test_three_reg_op(Opcode::RemU64, 42, 0, 42); // rem by zero = dividend
}

#[test]
fn prove_div_u32() {
    test_three_reg_op(Opcode::DivU32, 1000, 30, 1000 / 30); // 33
}

#[test]
fn prove_rem_u32() {
    test_three_reg_op(Opcode::RemU32, 1000, 30, 1000 % 30); // 10
}

#[test]
fn prove_div_u64_large() {
    test_three_reg_op(Opcode::DivU64, u64::MAX, 2, u64::MAX / 2);
}

// ── BitManip tests ──

#[test]
fn prove_reverse_bytes() {
    // ReverseBytes is TwoReg: φ'[rd] = bswap(φ[ra])
    // Encoding: [opcode, rd | (ra<<4)]
    let mut regs = [0u64; PVM_REGISTER_COUNT];
    regs[0] = 0x0102030405060708;
    let code = vec![Opcode::ReverseBytes as u8, 0x01, Opcode::Trap as u8]; // rd=1, ra=0
    let bitmask = vec![1, 0, 1];
    let pvm = Interpreter::new(
        code.clone(),
        bitmask.clone(),
        vec![],
        regs,
        vec![0u8; 4 * 1024 * 1024],
        10000,
        25,
    );
    let mut tracing = TracingPvm::new(pvm);
    let exit = tracing.run();
    assert_eq!(exit, javm::ExitReason::Trap);
    let steps = tracing.into_trace();
    assert_eq!(steps[0].regs_after[1], 0x0807060504030201);
    let mut side_note = zkpvm::SideNote::new(steps, code, bitmask);
    let proof = prove(&mut side_note).expect("proving failed");
    verify(proof, &side_note).expect("verification failed");
}

// Phase 33: CountSetBits (CSB64 / CSB32) via PopcountChip.
#[test]
fn prove_count_set_bits_64_smoke() {
    // CountSetBits64 is TwoReg: φ'[rd] = popcount(φ[ra])
    let mut regs = [0u64; PVM_REGISTER_COUNT];
    regs[0] = 0x0F0F_0F0F_0F0F_0F0Fu64; // 8 bytes × 4 bits each = 32 ones
    let code = vec![Opcode::CountSetBits64 as u8, 0x01, Opcode::Trap as u8]; // rd=1, ra=0
    let bitmask = vec![1, 0, 1];
    let pvm = Interpreter::new(
        code.clone(),
        bitmask.clone(),
        vec![],
        regs,
        vec![0u8; 4 * 1024 * 1024],
        10000,
        25,
    );
    let mut tracing = TracingPvm::new(pvm);
    assert_eq!(tracing.run(), javm::ExitReason::Trap);
    let steps = tracing.into_trace();
    assert_eq!(steps[0].regs_after[1], 32);
    let mut side_note = zkpvm::SideNote::new(steps, code, bitmask);
    let proof = prove(&mut side_note).expect("proving failed");
    verify(proof, &side_note).expect("verification failed");
}

#[test]
fn prove_count_set_bits_64_full() {
    let mut regs = [0u64; PVM_REGISTER_COUNT];
    regs[0] = u64::MAX; // all 64 bits set
    let code = vec![Opcode::CountSetBits64 as u8, 0x01, Opcode::Trap as u8];
    let bitmask = vec![1, 0, 1];
    let pvm = Interpreter::new(
        code.clone(),
        bitmask.clone(),
        vec![],
        regs,
        vec![0u8; 4 * 1024 * 1024],
        10000,
        25,
    );
    let mut tracing = TracingPvm::new(pvm);
    tracing.run();
    let steps = tracing.into_trace();
    assert_eq!(steps[0].regs_after[1], 64);
    let mut side_note = zkpvm::SideNote::new(steps, code, bitmask);
    let proof = prove(&mut side_note).expect("proving failed");
    verify(proof, &side_note).expect("verification failed");
}

#[test]
fn prove_count_set_bits_64_zero() {
    let mut regs = [0u64; PVM_REGISTER_COUNT];
    regs[0] = 0;
    let code = vec![Opcode::CountSetBits64 as u8, 0x01, Opcode::Trap as u8];
    let bitmask = vec![1, 0, 1];
    let pvm = Interpreter::new(
        code.clone(),
        bitmask.clone(),
        vec![],
        regs,
        vec![0u8; 4 * 1024 * 1024],
        10000,
        25,
    );
    let mut tracing = TracingPvm::new(pvm);
    tracing.run();
    let steps = tracing.into_trace();
    assert_eq!(steps[0].regs_after[1], 0);
    let mut side_note = zkpvm::SideNote::new(steps, code, bitmask);
    let proof = prove(&mut side_note).expect("proving failed");
    verify(proof, &side_note).expect("verification failed");
}

#[test]
fn prove_count_set_bits_32_smoke() {
    let mut regs = [0u64; PVM_REGISTER_COUNT];
    // High 32 bits all set (should be ignored), low 32 bits = 0xFF (8 ones)
    regs[0] = 0xFFFF_FFFF_0000_00FFu64;
    let code = vec![Opcode::CountSetBits32 as u8, 0x01, Opcode::Trap as u8];
    let bitmask = vec![1, 0, 1];
    let pvm = Interpreter::new(
        code.clone(),
        bitmask.clone(),
        vec![],
        regs,
        vec![0u8; 4 * 1024 * 1024],
        10000,
        25,
    );
    let mut tracing = TracingPvm::new(pvm);
    tracing.run();
    let steps = tracing.into_trace();
    assert_eq!(steps[0].regs_after[1], 8);
    let mut side_note = zkpvm::SideNote::new(steps, code, bitmask);
    let proof = prove(&mut side_note).expect("proving failed");
    verify(proof, &side_note).expect("verification failed");
}

// Phase 34: LeadingZeroBits / TrailingZeroBits via BitcountChip.
#[test]
fn prove_leading_zero_bits_64_smoke() {
    let mut regs = [0u64; PVM_REGISTER_COUNT];
    regs[0] = 0x0000_0000_0001_0000u64; // bit 16 set → LZ = 47
    let code = vec![Opcode::LeadingZeroBits64 as u8, 0x01, Opcode::Trap as u8];
    let bitmask = vec![1, 0, 1];
    let pvm = Interpreter::new(
        code.clone(),
        bitmask.clone(),
        vec![],
        regs,
        vec![0u8; 4 * 1024 * 1024],
        10000,
        25,
    );
    let mut tracing = TracingPvm::new(pvm);
    assert_eq!(tracing.run(), javm::ExitReason::Trap);
    let steps = tracing.into_trace();
    assert_eq!(steps[0].regs_after[1], 47);
    let mut side_note = zkpvm::SideNote::new(steps, code, bitmask);
    let proof = prove(&mut side_note).expect("proving failed");
    verify(proof, &side_note).expect("verification failed");
}

#[test]
fn prove_leading_zero_bits_64_zero() {
    let mut regs = [0u64; PVM_REGISTER_COUNT];
    regs[0] = 0;
    let code = vec![Opcode::LeadingZeroBits64 as u8, 0x01, Opcode::Trap as u8];
    let bitmask = vec![1, 0, 1];
    let pvm = Interpreter::new(
        code.clone(),
        bitmask.clone(),
        vec![],
        regs,
        vec![0u8; 4 * 1024 * 1024],
        10000,
        25,
    );
    let mut tracing = TracingPvm::new(pvm);
    tracing.run();
    let steps = tracing.into_trace();
    assert_eq!(steps[0].regs_after[1], 64);
    let mut side_note = zkpvm::SideNote::new(steps, code, bitmask);
    let proof = prove(&mut side_note).expect("proving failed");
    verify(proof, &side_note).expect("verification failed");
}

#[test]
fn prove_leading_zero_bits_64_msb() {
    let mut regs = [0u64; PVM_REGISTER_COUNT];
    regs[0] = 1u64 << 63; // MSB set → LZ = 0
    let code = vec![Opcode::LeadingZeroBits64 as u8, 0x01, Opcode::Trap as u8];
    let bitmask = vec![1, 0, 1];
    let pvm = Interpreter::new(
        code.clone(),
        bitmask.clone(),
        vec![],
        regs,
        vec![0u8; 4 * 1024 * 1024],
        10000,
        25,
    );
    let mut tracing = TracingPvm::new(pvm);
    tracing.run();
    let steps = tracing.into_trace();
    assert_eq!(steps[0].regs_after[1], 0);
    let mut side_note = zkpvm::SideNote::new(steps, code, bitmask);
    let proof = prove(&mut side_note).expect("proving failed");
    verify(proof, &side_note).expect("verification failed");
}

#[test]
fn prove_leading_zero_bits_32_smoke() {
    let mut regs = [0u64; PVM_REGISTER_COUNT];
    // Low 32 bits = 1 → LZ32 = 31.  High 32 bits arbitrary (ignored).
    regs[0] = 0xDEAD_BEEF_0000_0001u64;
    let code = vec![Opcode::LeadingZeroBits32 as u8, 0x01, Opcode::Trap as u8];
    let bitmask = vec![1, 0, 1];
    let pvm = Interpreter::new(
        code.clone(),
        bitmask.clone(),
        vec![],
        regs,
        vec![0u8; 4 * 1024 * 1024],
        10000,
        25,
    );
    let mut tracing = TracingPvm::new(pvm);
    tracing.run();
    let steps = tracing.into_trace();
    assert_eq!(steps[0].regs_after[1], 31);
    let mut side_note = zkpvm::SideNote::new(steps, code, bitmask);
    let proof = prove(&mut side_note).expect("proving failed");
    verify(proof, &side_note).expect("verification failed");
}

#[test]
fn prove_leading_zero_bits_32_zero_low() {
    let mut regs = [0u64; PVM_REGISTER_COUNT];
    // Low 32 bits = 0, high 32 bits set → LZ32 = 32.
    regs[0] = 0xFFFF_FFFF_0000_0000u64;
    let code = vec![Opcode::LeadingZeroBits32 as u8, 0x01, Opcode::Trap as u8];
    let bitmask = vec![1, 0, 1];
    let pvm = Interpreter::new(
        code.clone(),
        bitmask.clone(),
        vec![],
        regs,
        vec![0u8; 4 * 1024 * 1024],
        10000,
        25,
    );
    let mut tracing = TracingPvm::new(pvm);
    tracing.run();
    let steps = tracing.into_trace();
    assert_eq!(steps[0].regs_after[1], 32);
    let mut side_note = zkpvm::SideNote::new(steps, code, bitmask);
    let proof = prove(&mut side_note).expect("proving failed");
    verify(proof, &side_note).expect("verification failed");
}

#[test]
fn prove_trailing_zero_bits_64_smoke() {
    let mut regs = [0u64; PVM_REGISTER_COUNT];
    regs[0] = 0x0000_0000_0010_0000u64; // bit 20 set → TZ = 20
    let code = vec![Opcode::TrailingZeroBits64 as u8, 0x01, Opcode::Trap as u8];
    let bitmask = vec![1, 0, 1];
    let pvm = Interpreter::new(
        code.clone(),
        bitmask.clone(),
        vec![],
        regs,
        vec![0u8; 4 * 1024 * 1024],
        10000,
        25,
    );
    let mut tracing = TracingPvm::new(pvm);
    tracing.run();
    let steps = tracing.into_trace();
    assert_eq!(steps[0].regs_after[1], 20);
    let mut side_note = zkpvm::SideNote::new(steps, code, bitmask);
    let proof = prove(&mut side_note).expect("proving failed");
    verify(proof, &side_note).expect("verification failed");
}

#[test]
fn prove_trailing_zero_bits_64_zero() {
    let mut regs = [0u64; PVM_REGISTER_COUNT];
    regs[0] = 0;
    let code = vec![Opcode::TrailingZeroBits64 as u8, 0x01, Opcode::Trap as u8];
    let bitmask = vec![1, 0, 1];
    let pvm = Interpreter::new(
        code.clone(),
        bitmask.clone(),
        vec![],
        regs,
        vec![0u8; 4 * 1024 * 1024],
        10000,
        25,
    );
    let mut tracing = TracingPvm::new(pvm);
    tracing.run();
    let steps = tracing.into_trace();
    assert_eq!(steps[0].regs_after[1], 64);
    let mut side_note = zkpvm::SideNote::new(steps, code, bitmask);
    let proof = prove(&mut side_note).expect("proving failed");
    verify(proof, &side_note).expect("verification failed");
}

#[test]
fn prove_trailing_zero_bits_64_lsb() {
    let mut regs = [0u64; PVM_REGISTER_COUNT];
    regs[0] = 1; // LSB set → TZ = 0
    let code = vec![Opcode::TrailingZeroBits64 as u8, 0x01, Opcode::Trap as u8];
    let bitmask = vec![1, 0, 1];
    let pvm = Interpreter::new(
        code.clone(),
        bitmask.clone(),
        vec![],
        regs,
        vec![0u8; 4 * 1024 * 1024],
        10000,
        25,
    );
    let mut tracing = TracingPvm::new(pvm);
    tracing.run();
    let steps = tracing.into_trace();
    assert_eq!(steps[0].regs_after[1], 0);
    let mut side_note = zkpvm::SideNote::new(steps, code, bitmask);
    let proof = prove(&mut side_note).expect("proving failed");
    verify(proof, &side_note).expect("verification failed");
}

#[test]
fn prove_trailing_zero_bits_32_zero_low() {
    let mut regs = [0u64; PVM_REGISTER_COUNT];
    // Low 32 bits = 0, high 32 bits set.  Interpreter: TZ32 of 0 = 32.
    regs[0] = 0xFFFF_FFFF_0000_0000u64;
    let code = vec![Opcode::TrailingZeroBits32 as u8, 0x01, Opcode::Trap as u8];
    let bitmask = vec![1, 0, 1];
    let pvm = Interpreter::new(
        code.clone(),
        bitmask.clone(),
        vec![],
        regs,
        vec![0u8; 4 * 1024 * 1024],
        10000,
        25,
    );
    let mut tracing = TracingPvm::new(pvm);
    tracing.run();
    let steps = tracing.into_trace();
    assert_eq!(steps[0].regs_after[1], 32);
    let mut side_note = zkpvm::SideNote::new(steps, code, bitmask);
    let proof = prove(&mut side_note).expect("proving failed");
    verify(proof, &side_note).expect("verification failed");
}

#[test]
fn prove_sign_extend_8() {
    let mut regs = [0u64; PVM_REGISTER_COUNT];
    regs[0] = 0x80; // -128 as i8
    let code = vec![Opcode::SignExtend8 as u8, 0x01, Opcode::Trap as u8]; // rd=1, ra=0
    let bitmask = vec![1, 0, 1];
    let pvm = Interpreter::new(
        code.clone(),
        bitmask.clone(),
        vec![],
        regs,
        vec![0u8; 4 * 1024 * 1024],
        10000,
        25,
    );
    let mut tracing = TracingPvm::new(pvm);
    tracing.run();
    let steps = tracing.into_trace();
    assert_eq!(steps[0].regs_after[1], 0xFFFFFFFFFFFFFF80); // sign-extended
    let mut side_note = zkpvm::SideNote::new(steps, code, bitmask);
    let proof = prove(&mut side_note).expect("proving failed");
    verify(proof, &side_note).expect("verification failed");
}

// ── CmovIz/CmovNz tests ──

#[test]
fn prove_cmov_iz_taken() {
    // CmovIz(ra=0, rb=1, rd=2): if φ[1]==0, φ'[2] = φ[0]
    let mut regs = [0u64; PVM_REGISTER_COUNT];
    regs[0] = 42; // value to move
    regs[1] = 0; // condition (zero → move)
    regs[2] = 99; // old value
    let steps = run_three_reg(Opcode::CmovIz, 0, 1, 2, regs);
    assert_eq!(steps[0].regs_after[2], 42);
    let code = vec![Opcode::CmovIz as u8, 0x10, 2, Opcode::Trap as u8];
    let bitmask = vec![1, 0, 0, 1];
    prove_and_verify(steps, &code, &bitmask);
}

#[test]
fn prove_cmov_iz_not_taken() {
    let mut regs = [0u64; PVM_REGISTER_COUNT];
    regs[0] = 42;
    regs[1] = 1; // not zero → don't move
    regs[2] = 99; // should stay 99
    let steps = run_three_reg(Opcode::CmovIz, 0, 1, 2, regs);
    assert_eq!(steps[0].regs_after[2], 99);
    let code = vec![Opcode::CmovIz as u8, 0x10, 2, Opcode::Trap as u8];
    let bitmask = vec![1, 0, 0, 1];
    prove_and_verify(steps, &code, &bitmask);
}

#[test]
fn prove_cmov_nz_taken() {
    let mut regs = [0u64; PVM_REGISTER_COUNT];
    regs[0] = 42;
    regs[1] = 5; // not zero → move
    let steps = run_three_reg(Opcode::CmovNz, 0, 1, 2, regs);
    assert_eq!(steps[0].regs_after[2], 42);
    let code = vec![Opcode::CmovNz as u8, 0x10, 2, Opcode::Trap as u8];
    let bitmask = vec![1, 0, 0, 1];
    prove_and_verify(steps, &code, &bitmask);
}

// ── MinU/MaxU tests ──

#[test]
fn prove_min_u() {
    test_three_reg_op(Opcode::MinU, 10, 20, 10);
}

#[test]
fn prove_min_u_equal() {
    test_three_reg_op(Opcode::MinU, 7, 7, 7);
}

#[test]
fn prove_max_u() {
    test_three_reg_op(Opcode::MaxU, 10, 20, 20);
}

#[test]
fn prove_max_u_large() {
    test_three_reg_op(Opcode::MaxU, u64::MAX, 0, u64::MAX);
}

// ── MulUpper tests ──

#[test]
fn prove_mul_upper_uu() {
    // MulUpperUU: result = high64(φ[ra] * φ[rb])
    // 0x1_0000_0000 * 0x1_0000_0000 = 0x1_0000_0000_0000_0000
    // high64 = 0x1
    test_three_reg_op(Opcode::MulUpperUU, 0x1_0000_0000, 0x1_0000_0000, 1);
}

#[test]
fn prove_mul_upper_uu_small() {
    // Small values: high64 = 0
    test_three_reg_op(Opcode::MulUpperUU, 7, 6, 0);
}

// ── Shift tests ──
#[test]
fn prove_shlo_l64() {
    // ShloL64: φ[rd] = φ[ra] << (φ[rb] % 64)
    // 1 << 10 = 1024
    test_three_reg_op(Opcode::ShloL64, 1, 10, 1 << 10);
}

#[test]
fn prove_shlo_l64_large() {
    test_three_reg_op(Opcode::ShloL64, 0xFF, 8, 0xFF00);
}

#[test]
fn prove_shlo_l64_overflow() {
    // Shift that loses bits: 1 << 63 = 0x8000_0000_0000_0000
    test_three_reg_op(Opcode::ShloL64, 1, 63, 1u64 << 63);
}

#[test]
fn prove_shlo_l32() {
    test_three_reg_op(Opcode::ShloL32, 1, 10, 1 << 10);
}

#[test]
fn prove_shlo_r64() {
    test_three_reg_op(Opcode::ShloR64, 1024, 4, 1024 >> 4); // 64
}

#[test]
fn prove_shlo_r64_large() {
    test_three_reg_op(
        Opcode::ShloR64,
        0xDEAD_BEEF_CAFE_BABE,
        16,
        0xDEAD_BEEF_CAFE_BABE >> 16,
    );
}

#[test]
fn prove_shlo_r32() {
    test_three_reg_op(Opcode::ShloR32, 0xFF00, 8, 0xFF);
}

// ── Signed compare tests ──

#[test]
fn prove_set_lt_s_negative() {
    // -1 < 0 (signed) → 1
    test_three_reg_op(Opcode::SetLtS, u64::MAX, 0, 1); // u64::MAX = -1 as i64
}

#[test]
fn prove_set_lt_s_positive() {
    // 5 < 10 (signed) → 1
    test_three_reg_op(Opcode::SetLtS, 5, 10, 1);
}

#[test]
fn prove_set_lt_s_false() {
    // 10 < 5 (signed) → 0
    test_three_reg_op(Opcode::SetLtS, 10, 5, 0);
}

#[test]
fn prove_set_lt_s_neg_vs_pos() {
    // -100 < 100 (signed) → 1
    let neg100 = (-100i64) as u64;
    test_three_reg_op(Opcode::SetLtS, neg100, 100, 1);
}

#[test]
fn prove_set_lt_s_pos_vs_neg() {
    // 100 < -100 (signed) → 0
    let neg100 = (-100i64) as u64;
    test_three_reg_op(Opcode::SetLtS, 100, neg100, 0);
}

fn prove_mul_upper_uu_large() {
    // Large but not max: schoolbook carries stay within u8
    test_three_reg_op(
        Opcode::MulUpperUU,
        0x0102030405060708,
        0x0807060504030201,
        ((0x0102030405060708u128 * 0x0807060504030201u128) >> 64) as u64,
    );
}

// ── Phase 32: RotL64 ──

#[test]
fn prove_rotate_l64_smoke() {
    // RotL64(0x123456789ABCDEF0, 16) = 0x56789ABCDEF01234.
    let a = 0x123456789ABCDEF0u64;
    let n = 16u64;
    test_three_reg_op(Opcode::RotL64, a, n, a.rotate_left(n as u32));
}

#[test]
fn prove_rotate_l64_zero() {
    // n = 0 → identity.
    test_three_reg_op(
        Opcode::RotL64,
        0xDEAD_BEEF_CAFE_BABE,
        0,
        0xDEAD_BEEF_CAFE_BABE,
    );
}

#[test]
fn prove_rotate_l64_full_word() {
    // n mod 64: shifting by 64 should be identity.  Encoded as
    // n = 64 → 64 mod 64 = 0.  Whether the interpreter picks
    // shift = n mod 64 or rotates by 64 directly, the answer is
    // the input unchanged.
    let a = 0x0123_4567_89AB_CDEFu64;
    test_three_reg_op(Opcode::RotL64, a, 64, a.rotate_left((64 % 64) as u32));
}

#[test]
fn prove_rotate_l64_by_one() {
    // Bit-level: rotating 0x8000000000000001 left by 1 → 0x3.
    test_three_reg_op(Opcode::RotL64, 0x8000_0000_0000_0001, 1, 0x3);
}

// ── Phase 35: RotR64 ──

#[test]
fn prove_rotate_r64_smoke() {
    let a = 0x123456789ABCDEF0u64;
    let n = 16u64;
    test_three_reg_op(Opcode::RotR64, a, n, a.rotate_right(n as u32));
}

#[test]
fn prove_rotate_r64_zero() {
    // n = 0 → identity.
    test_three_reg_op(
        Opcode::RotR64,
        0xDEAD_BEEF_CAFE_BABE,
        0,
        0xDEAD_BEEF_CAFE_BABE,
    );
}

#[test]
fn prove_rotate_r64_full_word() {
    // n = 64 → 64 mod 64 = 0 → identity.
    let a = 0x0123_4567_89AB_CDEFu64;
    test_three_reg_op(Opcode::RotR64, a, 64, a.rotate_right((64 % 64) as u32));
}

#[test]
fn prove_rotate_r64_by_one() {
    // Bit-level: rotating 0x3 right by 1 → 0x8000000000000001.
    test_three_reg_op(Opcode::RotR64, 0x3, 1, 0x8000_0000_0000_0001);
}

#[test]
fn prove_rotate_r64_by_one_zero_lsb() {
    // Rotating 0x2 right by 1 → 0x1 (no wraparound — LSB was 0).
    test_three_reg_op(Opcode::RotR64, 0x2, 1, 0x1);
}

// ── Phase 36: RotL32 / RotR32 ──

#[test]
fn prove_rotate_l32_smoke() {
    // RotL32 over the low 32 bits.  Sign-extension: result[31] becomes
    // bit 7 of result[3] which the AIR sign-extends.
    let a_lo = 0x12345678u32;
    let n = 8u32;
    let rotated = a_lo.rotate_left(n);
    let expected = ((rotated as i32) as i64) as u64; // sign-extended
    test_three_reg_op(Opcode::RotL32, a_lo as u64, n as u64, expected);
}

#[test]
fn prove_rotate_l32_zero() {
    let a_lo = 0xDEADBEEFu32;
    // RotL32 by 0 → identity but sign-extended.
    let expected = ((a_lo as i32) as i64) as u64;
    test_three_reg_op(Opcode::RotL32, a_lo as u64, 0, expected);
}

#[test]
fn prove_rotate_l32_msb() {
    // a = 1 << 31 — top bit set; rotating left by 1 gives 1.
    let a_lo: u32 = 1 << 31;
    let expected = (a_lo.rotate_left(1) as i32) as i64 as u64;
    test_three_reg_op(Opcode::RotL32, a_lo as u64, 1, expected);
}

#[test]
fn prove_rotate_r32_smoke() {
    let a_lo = 0x12345678u32;
    let n = 8u32;
    let rotated = a_lo.rotate_right(n);
    let expected = ((rotated as i32) as i64) as u64;
    test_three_reg_op(Opcode::RotR32, a_lo as u64, n as u64, expected);
}

#[test]
fn prove_rotate_r32_zero() {
    let a_lo = 0xDEADBEEFu32;
    let expected = ((a_lo as i32) as i64) as u64;
    test_three_reg_op(Opcode::RotR32, a_lo as u64, 0, expected);
}

#[test]
fn prove_rotate_r32_full_word() {
    let a_lo = 0xDEADBEEFu32;
    // n=32 → 32 mod 32 = 0 → identity.
    let expected = ((a_lo as i32) as i64) as u64;
    test_three_reg_op(Opcode::RotR32, a_lo as u64, 32, expected);
}

// ── Phase 40: RotR64ImmAlt / RotR32ImmAlt (swapped operand convention) ──

#[test]
fn prove_rotate_r64_imm_alt_smoke() {
    // RotR64ImmAlt: regs[ra] = imm.rotate_right((regs[rb] % 64) as u32).
    // The 4-byte encoded immediate is sign-extended to i64 before
    // becoming step.imm.  Use a positive-i32 imm to keep the
    // sign-extension a no-op and the math obvious.
    let imm: i32 = 0x12345678;
    let n: u64 = 16;
    let mut regs = [0u64; PVM_REGISTER_COUNT];
    regs[1] = n;
    let steps = run_two_reg_imm(Opcode::RotR64ImmAlt, 0, 1, imm as i64, regs);
    let expected = (imm as i64 as u64).rotate_right(n as u32);
    assert_eq!(
        steps[0].regs_after[0], expected,
        "RotR64ImmAlt: regs[0] = 0x{:x}, expected 0x{:x}",
        steps[0].regs_after[0], expected
    );
    let imm_bytes = (imm as u32).to_le_bytes();
    let code = vec![
        Opcode::RotR64ImmAlt as u8,
        0x10,
        imm_bytes[0],
        imm_bytes[1],
        imm_bytes[2],
        imm_bytes[3],
        Opcode::Trap as u8,
    ];
    let bitmask = vec![1, 0, 0, 0, 0, 0, 1];
    prove_and_verify(steps, &code, &bitmask);
}

#[test]
fn prove_rotate_r32_imm_alt_smoke() {
    // RotR32ImmAlt: regs[ra] = sign_extend_32(imm.rotate_right((regs[rb] % 32) as u32)).
    // Use a positive-i32 imm so the sign-extension to i64 is a no-op.
    let imm: i32 = 0x12345678;
    let n: u64 = 4;
    let mut regs = [0u64; PVM_REGISTER_COUNT];
    regs[1] = n;
    let steps = run_two_reg_imm(Opcode::RotR32ImmAlt, 0, 1, imm as i64, regs);
    let rotated = (imm as u32).rotate_right(n as u32);
    let expected = ((rotated as i32) as i64) as u64;
    assert_eq!(
        steps[0].regs_after[0], expected,
        "RotR32ImmAlt: regs[0] = 0x{:x}, expected 0x{:x}",
        steps[0].regs_after[0], expected
    );
    let imm_bytes = (imm as u32).to_le_bytes();
    let code = vec![
        Opcode::RotR32ImmAlt as u8,
        0x10,
        imm_bytes[0],
        imm_bytes[1],
        imm_bytes[2],
        imm_bytes[3],
        Opcode::Trap as u8,
    ];
    let bitmask = vec![1, 0, 0, 0, 0, 0, 1];
    prove_and_verify(steps, &code, &bitmask);
}

#[test]
fn prove_rotate_r32_imm_alt_negative_imm() {
    // RotR32ImmAlt with high-bit-set imm — exercises the imm
    // sign-extension to i64 (val_b high 4 bytes = 0xFF, low 4 bytes
    // = the actual rotated value).
    let imm: i32 = -1; // 0xFFFFFFFF as u32
    let n: u64 = 4;
    let mut regs = [0u64; PVM_REGISTER_COUNT];
    regs[1] = n;
    let steps = run_two_reg_imm(Opcode::RotR32ImmAlt, 0, 1, imm as i64, regs);
    // 0xFFFFFFFF rotated by anything = 0xFFFFFFFF; sign-ext to u64 = u64::MAX.
    assert_eq!(steps[0].regs_after[0], u64::MAX);
    let imm_bytes = (imm as u32).to_le_bytes();
    let code = vec![
        Opcode::RotR32ImmAlt as u8,
        0x10,
        imm_bytes[0],
        imm_bytes[1],
        imm_bytes[2],
        imm_bytes[3],
        Opcode::Trap as u8,
    ];
    let bitmask = vec![1, 0, 0, 0, 0, 0, 1];
    prove_and_verify(steps, &code, &bitmask);
}

#[test]
fn prove_rotate_r64_imm_alt_zero_shift() {
    // n=0 → identity (after the imm sign-extension to i64).
    let imm: i32 = 0x12345678; // positive → no sign extension
    let mut regs = [0u64; PVM_REGISTER_COUNT];
    regs[1] = 0;
    let steps = run_two_reg_imm(Opcode::RotR64ImmAlt, 0, 1, imm as i64, regs);
    assert_eq!(steps[0].regs_after[0], imm as i64 as u64);
    let imm_bytes = (imm as u32).to_le_bytes();
    let code = vec![
        Opcode::RotR64ImmAlt as u8,
        0x10,
        imm_bytes[0],
        imm_bytes[1],
        imm_bytes[2],
        imm_bytes[3],
        Opcode::Trap as u8,
    ];
    let bitmask = vec![1, 0, 0, 0, 0, 0, 1];
    prove_and_verify(steps, &code, &bitmask);
}

#[test]
fn prove_shlo_l64_negative_value() {
    // Exact values from blake2s step 242: left shift of a large (negative-looking) 64-bit value
    let mut regs = [0u64; PVM_REGISTER_COUNT];
    regs[0] = 0xFFFF_FFFF_B363_2DF8; // val_b: large 64-bit value
    // ShloLImm64: ra=0, rb=0, imm=16 (shift left by 16)
    let steps = run_two_reg_imm(Opcode::ShloLImm64, 0, 0, 16, regs);
    let expected = 0xFFFF_FFFF_B363_2DF8u64.wrapping_shl(16);
    assert_eq!(steps[0].regs_after[0], expected);
    let code = vec![
        Opcode::ShloLImm64 as u8,
        0x00,
        16,
        0,
        0,
        0,
        Opcode::Trap as u8,
    ];
    let bitmask = vec![1, 0, 0, 0, 0, 0, 1];
    prove_and_verify(steps, &code, &bitmask);
}
