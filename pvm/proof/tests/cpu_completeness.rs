#![cfg(feature = "prover")]

//! Honest runs the AIR once refused or proved as other than the machine's:
//! the `ImmAlt` shifts, branches whose target is their fallthrough, signed
//! minima and maxima, an 8-byte immediate store of a negative value, and a
//! BLAKE2b call whose flag register is a non-zero multiple of the field's
//! modulus.

mod common;
use common::*;

use vos_pvm::PVM_REGISTER_COUNT;
use vos_pvm::instruction::Opcode;
use vos_pvm::interpreter::Interpreter;
use vos_pvm_proof::core::tracing::{ECALL_BLAKE2B_COMPRESS, TracingPvm};

fn run(
    code: &[u8],
    bitmask: &[u8],
    registers: [u64; PVM_REGISTER_COUNT],
) -> Vec<vos_pvm_proof::core::step::PvmStep> {
    trace_until_opcode_zero(code.to_vec(), bitmask.to_vec(), registers)
}

/// `op φ0 = imm (op) φ1` with φ1 = `amount`: the immediate is the shifted
/// value, the register the amount.
fn prove_imm_alt(op: Opcode, imm: u8, amount: u64, expected: u64) {
    let code = [op as u8, 0x10, imm, Opcode::Trap as u8];
    let bitmask = [1, 0, 0, 1];
    let mut registers = [0u64; PVM_REGISTER_COUNT];
    registers[1] = amount;
    let steps = run(&code, &bitmask, registers);
    assert_eq!(steps[0].regs_after[0], expected, "{op:?}");
    prove_and_verify(steps, &code, &bitmask);
}

#[test]
fn imm_alt_left_shifts_prove() {
    prove_imm_alt(Opcode::ShloLImmAlt64, 5, 3, 40);
    prove_imm_alt(Opcode::ShloLImmAlt64, 0x80, 4, 0xffff_ffff_ffff_f800);
    prove_imm_alt(Opcode::ShloLImmAlt32, 0x81, 28, 0x0000_0000_1000_0000);
}

#[test]
fn imm_alt_right_shifts_prove() {
    prove_imm_alt(Opcode::ShloRImmAlt64, 0x80, 3, 0x1fff_ffff_ffff_fff0);
    prove_imm_alt(Opcode::ShloRImmAlt32, 0x70, 4, 7);
    prove_imm_alt(Opcode::SharRImmAlt64, 0x80, 3, 0xffff_ffff_ffff_fff0);
    prove_imm_alt(Opcode::SharRImmAlt32, 0x70, 4, 7);
}

/// `op φ0, φ1 → 3`, its target its fallthrough, with φ0 and φ1 as given:
/// whichever way the condition goes the run continues at 3.
fn prove_branch_to_fallthrough(op: Opcode, a: u64, b: u64) {
    let code = [op as u8, 0x10, 3, Opcode::Trap as u8];
    let bitmask = [1, 0, 0, 1];
    let mut registers = [0u64; PVM_REGISTER_COUNT];
    registers[0] = a;
    registers[1] = b;
    let steps = run(&code, &bitmask, registers);
    assert_eq!(steps[0].next_pc, 3);
    prove_and_verify(steps, &code, &bitmask);
}

#[test]
fn branches_to_their_fallthrough_prove() {
    for (a, b) in [(42, 42), (42, 99), (99, 42)] {
        for op in [
            Opcode::BranchEq,
            Opcode::BranchNe,
            Opcode::BranchLtU,
            Opcode::BranchGeU,
            Opcode::BranchLtS,
            Opcode::BranchGeS,
        ] {
            prove_branch_to_fallthrough(op, a, b);
        }
    }
}

#[test]
fn signed_minima_and_maxima_prove() {
    let minus_five = (-5i64) as u64;
    for (op, a, b, expected) in [
        (Opcode::Min, 5, 9, 5),
        (Opcode::Min, minus_five, 9, minus_five),
        (Opcode::Min, 9, minus_five, minus_five),
        (Opcode::Max, 5, 9, 9),
        (Opcode::Max, minus_five, 9, 9),
        (Opcode::Max, minus_five, minus_five, minus_five),
    ] {
        prove_three_reg(op, 2, 0, 1, a, b, expected);
    }
}

/// `StoreImmU64 [0x2_0000] = −2^31 + 1`: its high word is the immediate's
/// sign extension, 0xffff_ffff.
#[test]
fn a_negative_eight_byte_immediate_store_proves() {
    let code = [
        Opcode::StoreImmU64 as u8,
        3,
        0x00,
        0x00,
        0x02,
        0x01,
        0x00,
        0x00,
        0x80,
        Opcode::Trap as u8,
    ];
    let mut bitmask = [0u8; 10];
    bitmask[0] = 1;
    bitmask[9] = 1;
    let steps = run(&code, &bitmask, [0; PVM_REGISTER_COUNT]);
    let store = steps[0].mem_write.as_ref().expect("the store");
    assert_eq!(store.value, 0xffff_ffff_8000_0001);
    prove_and_verify(steps, &code, &bitmask);
}

/// A compression whose flag register φ10 is 2^31 − 1, the field's modulus:
/// non-zero, so it finalizes, though its base-256 combination is 0 in the
/// field.
#[test]
fn a_compression_flag_of_the_modulus_proves() {
    const H: u64 = 0x2_0000;
    let memory = vec![0u8; 0x3_0000];
    let mut code = vec![Opcode::Ecalli as u8];
    code.extend_from_slice(&ECALL_BLAKE2B_COMPRESS.to_le_bytes());
    code.push(Opcode::Trap as u8);
    let mut bitmask = vec![0; code.len()];
    bitmask[0] = 1;
    bitmask[code.len() - 1] = 1;
    let mut registers = [0u64; PVM_REGISTER_COUNT];
    registers[7] = H;
    registers[8] = H + 64;
    registers[10] = (1 << 31) - 1;
    let pvm = Interpreter::new(code, bitmask, vec![], registers, memory.clone(), 10_000);
    let mut tracer = TracingPvm::new(pvm);
    let _ = tracer.run_with_precompiles();
    assert!(tracer.blake2b_records[0].f, "a non-zero flag finalizes");
    let mut side_note = tracer
        .into_side_note()
        .with_initial_regs(registers)
        .with_memory(memory);
    let proof = vos_pvm_proof::prove(&mut side_note).expect("proving failed");
    vos_pvm_proof::verify(proof, &side_note).expect("verification failed");
}
