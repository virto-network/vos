#![cfg(feature = "prover")]

//! Honest runs the AIR once refused or proved as other than the machine's:
//! the `ImmAlt` shifts, branches whose target is their fallthrough, signed
//! minima and maxima, an 8-byte immediate store of a negative value, and a
//! BLAKE2b call whose flag register is a non-zero multiple of the field's
//! modulus; and the runs that stop where no proof ends a run, refused as
//! such before any trace, beside those that stop where one does.

use crate::common;
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

/// `code` (every byte an instruction start unless `bitmask` says) run with
/// `registers` and `gas` to its stop, as a raw run on the protected zone
/// and one page past it: how it stopped, and its side note.
fn stopped(
    code: &[u8],
    bitmask: &[u8],
    registers: &[u64],
    gas: vos_pvm::Gas,
) -> (vos_pvm::ExitReason, vos_pvm_proof::SideNote) {
    let memory = vec![0u8; vos_pvm::PVM_ZONE_SIZE as usize + 4096];
    let mut initial = [0u64; PVM_REGISTER_COUNT];
    initial[..registers.len()].copy_from_slice(registers);
    let pvm = Interpreter::new(
        code.to_vec(),
        bitmask.to_vec(),
        vec![],
        initial,
        memory.clone(),
        gas,
    );
    let mut tracer = TracingPvm::new(pvm);
    let exit = tracer.run_with_precompiles();
    (exit, tracer.into_side_note().with_memory(memory))
}

/// A run that stops at an instruction it does not complete is refused as
/// [`SegmentError::Stop`]: a load and a store in the protected zone, a load
/// of an unmapped page, a branch to no block start, a dynamic jump to no
/// table entry, and out of gas at an addition, a jump or a dynamic jump to
/// the halt address.
#[test]
fn a_run_stopped_where_no_proof_ends_is_refused() {
    use vos_pvm::ExitReason::{OutOfGas, PageFault, Panic};
    let page = u64::from(vos_pvm::PVM_ZONE_SIZE);
    let halt = vos_pvm::PVM_HALT_ADDR;
    let load = Opcode::LoadIndU64 as u8;
    let trap = Opcode::Trap as u8;
    for (name, at, code, bitmask, registers, gas, exit) in [
        (
            "zone load",
            0,
            vec![load, trap],
            vec![1, 1],
            vec![],
            100,
            Panic,
        ),
        (
            "zone store",
            0,
            vec![Opcode::StoreIndU64 as u8, trap],
            vec![1, 1],
            vec![],
            100,
            Panic,
        ),
        (
            "unmapped load",
            0,
            vec![load, 0x10, trap],
            vec![1, 0, 1],
            vec![0, 3 * page],
            100,
            PageFault(3 * vos_pvm::PVM_ZONE_SIZE),
        ),
        // The load of φ5's page completes, its register byte the branch's
        // opcode; the branch's target, 1, follows no terminator.
        (
            "branch",
            1,
            vec![load, Opcode::BranchNeImm as u8, trap],
            vec![1, 1, 1],
            vec![0, 0, 0, 0, 0, page],
            100,
            Panic,
        ),
        (
            "dynamic jump",
            0,
            vec![Opcode::JumpInd as u8, 0, trap],
            vec![1, 0, 1],
            vec![7],
            100,
            Panic,
        ),
        (
            "addition",
            0,
            vec![Opcode::AddImm64 as u8, 0, 1, trap],
            vec![1, 0, 0, 1],
            vec![],
            0,
            OutOfGas,
        ),
        (
            "jump",
            0,
            vec![Opcode::Jump as u8, 5, 0, 0, 0, trap],
            vec![1, 0, 0, 0, 0, 1],
            vec![],
            0,
            OutOfGas,
        ),
        (
            "halt",
            0,
            vec![Opcode::JumpInd as u8, 0, trap],
            vec![1, 0, 1],
            vec![halt],
            0,
            OutOfGas,
        ),
    ] {
        let (stop, mut side_note) = stopped(&code, &bitmask, &registers, gas);
        assert_eq!(stop, exit, "{name}");
        let last = side_note.steps.last().expect(name);
        assert!(last.exit, "{name}");
        assert_eq!(last.pc, at, "{name}");
        assert!(
            matches!(
                vos_pvm_proof::prove(&mut side_note),
                Err(vos_pvm_proof::SegmentError::Stop)
            ),
            "{name}"
        );
    }
}

/// A run that stops where a proof ends a run proves and verifies: a trap,
/// an unserved host call, a dynamic jump to the halt address, and out of
/// gas at a trap, a host call or a compression it cannot pay.
#[test]
fn a_run_stopped_where_a_proof_ends_proves() {
    use vos_pvm::ExitReason::{Halt, HostCall, OutOfGas, Panic};
    let trap = Opcode::Trap as u8;
    let host_call = vec![Opcode::Ecalli as u8, 99, trap];
    for (name, code, bitmask, registers, gas, exit) in [
        ("trap", vec![trap], vec![1], vec![], 100, Panic),
        (
            "host call",
            host_call.clone(),
            vec![1, 0, 1],
            vec![],
            100,
            HostCall(99),
        ),
        (
            "halt",
            vec![Opcode::JumpInd as u8, 0, trap],
            vec![1, 0, 1],
            vec![vos_pvm::PVM_HALT_ADDR],
            100,
            Halt,
        ),
        ("trap out of gas", vec![trap], vec![1], vec![], 0, OutOfGas),
        (
            "compression unpaid",
            vec![Opcode::Ecalli as u8, 0, 4, trap],
            vec![1, 0, 0, 1],
            vec![],
            100,
            OutOfGas,
        ),
        (
            "host call out of gas",
            host_call,
            vec![1, 0, 1],
            vec![],
            0,
            OutOfGas,
        ),
    ] {
        let (stop, mut side_note) = stopped(&code, &bitmask, &registers, gas);
        assert_eq!(stop, exit, "{name}");
        let proof = vos_pvm_proof::prove(&mut side_note).expect(name);
        vos_pvm_proof::verify(proof, &side_note).expect(name);
    }
}
