// Not under `poseidon2-channel`: builds a "wrong" commitment via
// `ProgramCommitment::from(&[u8])` — `Blake2sHash` has that conversion but
// `P2Hash` (the Poseidon2-M31 commitment) does not. Program-identity under P2
// is covered by `verifier/tests/poseidon2_canonical_segment.rs`.
#![cfg(all(feature = "prover", not(feature = "poseidon2-channel")))]

//! Program-identity public API.
//!
//! In vos-pvm-proof, a proof's preprocessed-trace Merkle root IS the program
//! commitment.  These tests demonstrate the publish-once / verify-many
//! workflow: run the prover once on representative input, extract the
//! commitment via `program_commitment_of_proof`, then check that
//! verify_standalone with that hash accepts only proofs of the same
//! program.

mod common;
use common::*;

use vos_pvm::PVM_REGISTER_COUNT;
use vos_pvm::instruction::Opcode;
use vos_pvm::interpreter::Interpreter;

use vos_pvm_proof::core::tracing::TracingPvm;
use vos_pvm_proof::{ProgramCommitment, SideNote, program_commitment_of_proof, prove};
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
        25,
    );
    let mut tracing = TracingPvm::new_conformance(pvm);
    let exit = tracing.run();
    assert_eq!(exit, vos_pvm::ExitReason::Panic);
    (code, bitmask, tracing.into_trace())
}

fn prove_program(
    code: &[u8],
    bitmask: &[u8],
    steps: Vec<vos_pvm_proof::core::step::PvmStep>,
) -> vos_pvm_proof::Proof {
    prove_program_with_mode(code, bitmask, steps, vos_pvm::IsaMode::Conformance)
}

fn prove_program_with_mode(
    code: &[u8],
    bitmask: &[u8],
    steps: Vec<vos_pvm_proof::core::step::PvmStep>,
    isa_mode: vos_pvm::IsaMode,
) -> vos_pvm_proof::Proof {
    let mut side_note =
        SideNote::new(steps, code.to_vec(), bitmask.to_vec()).with_isa_mode(isa_mode);
    prove(&mut side_note).expect("proving failed")
}

fn trace_raw_program(
    code: Vec<u8>,
    bitmask: Vec<u8>,
    regs: [u64; PVM_REGISTER_COUNT],
    isa_mode: vos_pvm::IsaMode,
) -> (vos_pvm::ExitReason, Vec<vos_pvm_proof::core::step::PvmStep>) {
    let pvm = Interpreter::new(
        code,
        bitmask,
        vec![],
        regs,
        vec![0u8; 4 * 1024 * 1024],
        10_000,
        25,
    );
    let mut tracing = TracingPvm::new_with_isa_mode(pvm, isa_mode);
    let exit = tracing.run();
    (exit, tracing.into_trace())
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
    let mut tr_b = TracingPvm::new_conformance(pvm_b);
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
    let mut tr_b = TracingPvm::new_conformance(pvm_b);
    let _ = tr_b.run();
    let proof_b = prove_program(&code_b, &bitmask_b, tr_b.into_trace());
    let hash_b = program_commitment_of_proof(&proof_b);

    let res = verify_standalone(proof_a, hash_b);
    assert!(
        res.is_err(),
        "proof of A must not verify against B's commitment"
    );
}

#[test]
fn capability_profile_matches_live_unary_semantics_and_is_commitment_bound() {
    // Encoded byte 102 is CountSetBits64 in the frozen capability profile,
    // but CountSetBits32 in standard v0.8. The low word has 8 set bits and
    // the high word has 32, making the divergent result visible (40 vs 8).
    let code = vec![102, 0x01, Opcode::Trap as u8];
    let bitmask = vec![1, 0, 1];
    let mut regs = [0u64; PVM_REGISTER_COUNT];
    regs[0] = 0xffff_ffff_0000_00ff;

    let (jar_exit, jar_steps) =
        trace_raw_program(code.clone(), bitmask.clone(), regs, vos_pvm::IsaMode::Jar);
    assert_eq!(jar_exit, vos_pvm::ExitReason::Trap);
    assert_eq!(jar_steps[0].regs_after[1], 40);

    let (standard_exit, standard_steps) = trace_raw_program(
        code.clone(),
        bitmask.clone(),
        regs,
        vos_pvm::IsaMode::Conformance,
    );
    assert_eq!(standard_exit, vos_pvm::ExitReason::Panic);
    assert_eq!(standard_steps[0].regs_after[1], 8);

    let jar_proof = prove_program_with_mode(&code, &bitmask, jar_steps, vos_pvm::IsaMode::Jar);
    let standard_proof = prove_program_with_mode(
        &code,
        &bitmask,
        standard_steps,
        vos_pvm::IsaMode::Conformance,
    );
    let jar_commitment = program_commitment_of_proof(&jar_proof);
    let standard_commitment = program_commitment_of_proof(&standard_proof);
    assert_ne!(jar_commitment, standard_commitment);
    verify_standalone(jar_proof, standard_commitment)
        .expect_err("a Jar trace must not verify against the standard profile commitment");
}

#[test]
fn proof_tracer_preserves_profile_specific_opcode_zero_exit() {
    let code = vec![Opcode::Trap as u8];
    let bitmask = vec![1];
    let regs = [0u64; PVM_REGISTER_COUNT];

    let (jar_exit, jar_steps) =
        trace_raw_program(code.clone(), bitmask.clone(), regs, vos_pvm::IsaMode::Jar);
    let (standard_exit, standard_steps) =
        trace_raw_program(code, bitmask, regs, vos_pvm::IsaMode::Conformance);

    assert_eq!(jar_exit, vos_pvm::ExitReason::Trap);
    assert_eq!(standard_exit, vos_pvm::ExitReason::Panic);
    for steps in [&jar_steps, &standard_steps] {
        assert_eq!(steps.len(), 1);
        assert_eq!(steps[0].opcode, Opcode::Trap);
        assert!(
            steps[0].exit,
            "opcode zero must remain a terminal trace row"
        );
    }
}

#[test]
fn invalid_opcode_bytes_do_not_alias_canonical_trap_commitments() {
    let regs = [0u64; PVM_REGISTER_COUNT];
    let bitmask = vec![1];
    let (_, invalid_steps) = trace_raw_program(
        vec![77],
        bitmask.clone(),
        regs,
        vos_pvm::IsaMode::Conformance,
    );
    let (_, trap_steps) = trace_raw_program(
        vec![Opcode::Trap as u8],
        bitmask.clone(),
        regs,
        vos_pvm::IsaMode::Conformance,
    );
    let invalid_proof = prove_program(&[77], &bitmask, invalid_steps);
    let trap_proof = prove_program(&[Opcode::Trap as u8], &bitmask, trap_steps);
    let invalid_commitment = program_commitment_of_proof(&invalid_proof);
    let trap_commitment = program_commitment_of_proof(&trap_proof);
    assert_ne!(invalid_commitment, trap_commitment);
    verify_standalone(invalid_proof, trap_commitment)
        .expect_err("an invalid raw opcode must not alias canonical Trap");
}

#[test]
fn profile_only_measurement_matches_canonical_proof_commitment() {
    let (code, bitmask, steps) = trace_reverse_bytes_program();
    let mut proven = SideNote::new(steps.clone(), code.clone(), bitmask.clone());
    let proof = vos_pvm_proof::prove_canonical(&mut proven, &[]).expect("canonical proof");
    let measured_side_note = SideNote::new(steps, code, bitmask);
    let measured =
        vos_pvm_proof::program_commitment_for_profile(&measured_side_note, &proof.log_sizes)
            .expect("profile-only program commitment");
    assert_eq!(measured, program_commitment_of_proof(&proof));
}
