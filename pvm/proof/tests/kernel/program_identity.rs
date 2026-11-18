#![cfg(feature = "prover")]

//! Program-identity public API.
//!
//! A proof's preprocessed root is its program's commitment: verify_standalone
//! against one program's root accepts its proofs alone.

use crate::common;
use common::*;

use vos_pvm::PVM_REGISTER_COUNT;
use vos_pvm::instruction::Opcode;
use vos_pvm::interpreter::Interpreter;

use vos_pvm_proof::core::tracing::TracingPvm;
use vos_pvm_proof::{Commitment, SideNote, prove};
use vos_pvm_proof_verifier::verify_standalone;

fn trace_reverse_bytes_program() -> (Vec<u8>, Vec<u8>, Vec<vos_pvm_proof::core::step::PvmStep>) {
    let mut regs = [0u64; PVM_REGISTER_COUNT];
    regs[3] = 0x0123_4567_89AB_CDEF;
    let (code, bitmask) = two_reg_program(Opcode::ReverseBytes, 2, 3);
    let pvm = Interpreter::new(
        code.clone(),
        bitmask.clone(),
        vec![],
        regs,
        vec![0u8; 4 * 1024 * 1024],
        10_000,
    );
    let mut tracing = TracingPvm::new(pvm);
    let exit = tracing.run();
    assert_eq!(exit, vos_pvm::ExitReason::Panic);
    (code, bitmask, tracing.into_trace())
}

fn prove_program(
    code: &[u8],
    bitmask: &[u8],
    steps: Vec<vos_pvm_proof::core::step::PvmStep>,
) -> vos_pvm_proof::Proof {
    let mut side_note = SideNote::new(steps, code.to_vec(), bitmask.to_vec());
    prove(&mut side_note).expect("proving failed")
}

fn trace_raw_program(
    code: Vec<u8>,
    bitmask: Vec<u8>,
    regs: [u64; PVM_REGISTER_COUNT],
) -> (vos_pvm::ExitReason, Vec<vos_pvm_proof::core::step::PvmStep>) {
    let pvm = Interpreter::new(
        code,
        bitmask,
        vec![],
        regs,
        vec![0u8; 4 * 1024 * 1024],
        10_000,
    );
    let mut tracing = TracingPvm::new(pvm);
    let exit = tracing.run();
    (exit, tracing.into_trace())
}

#[test]
fn program_commitment_round_trip() {
    let (code, bitmask, steps) = trace_reverse_bytes_program();
    let proof = prove_program(&code, &bitmask, steps);

    // Extract the program commitment from the proof.
    let id_hash = proof.preprocessed_commitment().unwrap();

    // verify_standalone with the matching hash must accept.
    verify_standalone(proof, id_hash).expect("verification with matching hash failed");
}

#[test]
fn verify_standalone_rejects_wrong_program_hash() {
    let (code, bitmask, steps) = trace_reverse_bytes_program();
    let proof = prove_program(&code, &bitmask, steps);

    let wrong = Commitment::from_bytes(
        vos_pvm_proof::format::ChannelKind::Poseidon2M31,
        &[0x01u8; 32],
    )
    .unwrap();
    let res = verify_standalone(proof, wrong);
    assert!(res.is_err(), "verifier must reject a wrong program hash");
}

#[test]
fn different_programs_have_different_commitments() {
    // Two distinct programs (different opcode at PC 0) yield different
    // program commitments.  Otherwise a proof of one program would verify
    // against another's published hash.
    let (code_a, bitmask_a, steps_a) = trace_reverse_bytes_program();
    let proof_a = prove_program(&code_a, &bitmask_a, steps_a);
    let h_a = proof_a.preprocessed_commitment().unwrap();

    let mut regs_b = [0u64; PVM_REGISTER_COUNT];
    regs_b[3] = 0x12_34;
    let (code_b, bitmask_b) = two_reg_program(Opcode::ZeroExtend16, 2, 3);
    let pvm_b = Interpreter::new(
        code_b.clone(),
        bitmask_b.clone(),
        vec![],
        regs_b,
        vec![0u8; 4 * 1024 * 1024],
        10_000,
    );
    let mut tr_b = TracingPvm::new(pvm_b);
    let _ = tr_b.run();
    let proof_b = prove_program(&code_b, &bitmask_b, tr_b.into_trace());
    let h_b = proof_b.preprocessed_commitment().unwrap();

    assert_ne!(
        h_a, h_b,
        "different programs must have different commitments"
    );
}

#[test]
fn verify_standalone_rejects_proof_for_different_program() {
    // Generate proof of program A, hash of program B.
    // verify_standalone(proof_A, hash_B) must fail.
    let (code_a, bitmask_a, steps_a) = trace_reverse_bytes_program();
    let proof_a = prove_program(&code_a, &bitmask_a, steps_a);

    let mut regs_b = [0u64; PVM_REGISTER_COUNT];
    regs_b[3] = 0x12_34;
    let (code_b, bitmask_b) = two_reg_program(Opcode::ZeroExtend16, 2, 3);
    let pvm_b = Interpreter::new(
        code_b.clone(),
        bitmask_b.clone(),
        vec![],
        regs_b,
        vec![0u8; 4 * 1024 * 1024],
        10_000,
    );
    let mut tr_b = TracingPvm::new(pvm_b);
    let _ = tr_b.run();
    let proof_b = prove_program(&code_b, &bitmask_b, tr_b.into_trace());
    let hash_b = proof_b.preprocessed_commitment().unwrap();

    let res = verify_standalone(proof_a, hash_b);
    assert!(
        res.is_err(),
        "proof of A must not verify against B's commitment"
    );
}

#[test]
fn proof_tracer_records_opcode_zero_as_a_terminal_panic_row() {
    let (exit, steps) = trace_raw_program(
        vec![Opcode::Trap as u8],
        vec![1],
        [0u64; PVM_REGISTER_COUNT],
    );
    assert_eq!(exit, vos_pvm::ExitReason::Panic);
    assert_eq!(steps.len(), 1);
    assert_eq!(steps[0].opcode, Opcode::Trap);
    assert!(
        steps[0].exit,
        "opcode zero must remain a terminal trace row"
    );
}

#[test]
fn invalid_opcode_bytes_do_not_alias_canonical_trap_commitments() {
    let regs = [0u64; PVM_REGISTER_COUNT];
    let bitmask = vec![1];
    let (_, invalid_steps) = trace_raw_program(vec![77], bitmask.clone(), regs);
    let (_, trap_steps) = trace_raw_program(vec![Opcode::Trap as u8], bitmask.clone(), regs);
    let invalid_proof = prove_program(&[77], &bitmask, invalid_steps);
    let trap_proof = prove_program(&[Opcode::Trap as u8], &bitmask, trap_steps);
    let invalid_commitment = invalid_proof.preprocessed_commitment().unwrap();
    let trap_commitment = trap_proof.preprocessed_commitment().unwrap();
    assert_ne!(invalid_commitment, trap_commitment);
    verify_standalone(invalid_proof, trap_commitment)
        .expect_err("an invalid raw opcode must not alias canonical Trap");
}
