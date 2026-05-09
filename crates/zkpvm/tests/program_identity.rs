//! Phase 13f: program-identity public API.
//!
//! In zkpvm, a proof's preprocessed-trace Merkle root IS the program
//! commitment.  These tests demonstrate the publish-once / verify-many
//! workflow: run the prover once on representative input, extract the
//! commitment via `program_commitment_of_proof`, then check that
//! verify_standalone with that hash accepts only proofs of the same
//! program.

mod common;
use common::*;

use javm::PVM_REGISTER_COUNT;
use javm::instruction::Opcode;
use javm::interpreter::Interpreter;

use zkpvm::core::tracing::TracingPvm;
use zkpvm::{ProgramCommitment, SideNote, program_commitment_of_proof, prove};
use zkpvm_verifier::verify_standalone;

fn trace_reverse_bytes_program() -> (Vec<u8>, Vec<u8>, Vec<zkpvm::core::step::PvmStep>) {
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
        25,
    );
    let mut tracing = TracingPvm::new(pvm);
    let exit = tracing.run();
    assert_eq!(exit, javm::ExitReason::Trap);
    (code, bitmask, tracing.into_trace())
}

fn prove_program(
    code: &[u8],
    bitmask: &[u8],
    steps: Vec<zkpvm::core::step::PvmStep>,
) -> zkpvm::Proof {
    let mut side_note = SideNote::new(steps, code.to_vec(), bitmask.to_vec());
    prove(&mut side_note).expect("proving failed")
}

#[test]
fn program_commitment_round_trip() {
    let (code, bitmask, steps) = trace_reverse_bytes_program();
    let proof = prove_program(&code, &bitmask, steps);

    // Extract the program commitment from the proof.
    let id_hash = program_commitment_of_proof(&proof);

    // verify_standalone with the matching hash must accept.
    verify_standalone(proof, id_hash).expect("verification with matching hash failed");
}

#[test]
fn verify_standalone_rejects_wrong_program_hash() {
    let (code, bitmask, steps) = trace_reverse_bytes_program();
    let proof = prove_program(&code, &bitmask, steps);

    let wrong = ProgramCommitment::from(&[0xFFu8; 32][..]);
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
    let h_a = program_commitment_of_proof(&proof_a);

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
        25,
    );
    let mut tr_b = TracingPvm::new(pvm_b);
    let _ = tr_b.run();
    let proof_b = prove_program(&code_b, &bitmask_b, tr_b.into_trace());
    let h_b = program_commitment_of_proof(&proof_b);

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
        25,
    );
    let mut tr_b = TracingPvm::new(pvm_b);
    let _ = tr_b.run();
    let proof_b = prove_program(&code_b, &bitmask_b, tr_b.into_trace());
    let hash_b = program_commitment_of_proof(&proof_b);

    let res = verify_standalone(proof_a, hash_b);
    assert!(
        res.is_err(),
        "proof of A must not verify against B's commitment"
    );
}
