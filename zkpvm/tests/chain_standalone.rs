#![cfg(feature = "prover")]

//! End-to-end test for the side-note-free `verify_chain_standalone`
//! (the trustless counterpart to `zkpvm::verify_chain`).
//!
//! Proves a small program as a 2-segment chain, then verifies the chain
//! with NO side notes — only the per-segment proofs + ONE expected program
//! commitment. Asserts:
//!   - the honest chain verifies;
//!   - a broken boundary (tampered continuity) is rejected;
//!   - a WRONG program commitment is rejected (program identity is pinned
//!     across every segment).

use javm::PVM_REGISTER_COUNT;
use javm::instruction::Opcode;
use javm::interpreter::Interpreter;

use zkpvm::core::tracing::TracingPvm;
use zkpvm::{SideNote, program_commitment_of_proof, prove};
use zkpvm_verifier::verify_chain_standalone;

/// Six chained Add64s + Trap (7 steps), cut into [0..3) and [3..7).
fn prove_two_segment_chain() -> (zkpvm::Proof, zkpvm::Proof) {
    let code = vec![
        Opcode::Add64 as u8,
        0x10,
        2,
        Opcode::Add64 as u8,
        0x12,
        3,
        Opcode::Add64 as u8,
        0x13,
        4,
        Opcode::Add64 as u8,
        0x14,
        5,
        Opcode::Add64 as u8,
        0x15,
        6,
        Opcode::Add64 as u8,
        0x16,
        7,
        Opcode::Trap as u8,
    ];
    let bitmask: Vec<u8> = vec![1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1];

    let mut regs = [0u64; PVM_REGISTER_COUNT];
    regs[0] = 100;
    regs[1] = 1;
    let initial_memory = vec![0u8; 4 * 1024 * 1024];
    let pvm = Interpreter::new(
        code.clone(),
        bitmask.clone(),
        vec![],
        regs,
        initial_memory.clone(),
        10_000,
        25,
    );
    let mut tracing = TracingPvm::new(pvm);
    assert_eq!(tracing.run(), javm::ExitReason::Trap);
    let all_steps = tracing.into_trace();
    assert_eq!(all_steps.len(), 7);

    let (seg1_steps, seg2_steps) = all_steps.split_at(3);
    let mut sn1 = SideNote::new(seg1_steps.to_vec(), code.clone(), bitmask.clone())
        .with_memory(initial_memory.clone());
    let mut sn2 = SideNote::new(seg2_steps.to_vec(), code.clone(), bitmask.clone())
        .with_memory(initial_memory.clone());

    let proof1 = prove(&mut sn1).expect("prove segment 1");
    let proof2 = prove(&mut sn2).expect("prove segment 2");
    assert_eq!(
        proof1.final_state, proof2.initial_state,
        "honest segments must chain (prove() produced the boundary states)"
    );
    (proof1, proof2)
}

#[test]
fn chain_standalone_accepts_honest_chain_and_rejects_forgeries() {
    let (proof1, proof2) = prove_two_segment_chain();

    // Both small segments pad to the same log_size, so they share ONE program
    // commitment — the precondition for pinning a single commitment across the
    // chain.  (Production deployments that want uniform segments pad the last
    // one to match; variable-size segments would need a per-segment
    // commitment, which the function's doc notes.)
    let commit1 = program_commitment_of_proof(&proof1);
    let commit2 = program_commitment_of_proof(&proof2);
    assert_eq!(
        commit1, commit2,
        "this test assumes uniform-size segments share a commitment"
    );

    // Honest chain verifies with NO side notes — just proofs + the commitment.
    verify_chain_standalone(&[proof1.clone(), proof2.clone()], commit1)
        .expect("honest 2-segment chain must verify standalone");

    // Broken boundary continuity is rejected.
    let mut proof2_forged = proof2.clone();
    proof2_forged.initial_state.timestamp += 1;
    verify_chain_standalone(&[proof1.clone(), proof2_forged], commit1)
        .expect_err("a tampered segment boundary must be rejected");

    // A WRONG program commitment is rejected (program identity is pinned across
    // every segment — a from-scratch prover can't splice in a foreign program).
    let mut wrong = commit1;
    wrong.0[0] ^= 0xFF;
    verify_chain_standalone(&[proof1, proof2], wrong)
        .expect_err("a wrong program commitment must be rejected");
}
