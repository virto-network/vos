// Not under `poseidon2-channel`: a Blake2s commitment is `[u8; 32]`, so
// `program_commitment_of_proof` / the standalone verifier's byte-level shapes
// line up with this test's assertions; under the Poseidon2-M31 PCS the
// canonical-chain coverage lives in `verifier/tests/poseidon2_canonical_segment.rs`.
#![cfg(all(feature = "prover", not(feature = "poseidon2-channel")))]

//! Focused test for the in-memory `zkpvm::prove_chain` convenience.
//!
//! A small multi-window synthetic trace proves as a canonical-shape chain:
//! `prove_chain` derives ONE forcing profile over the window bounds and proves
//! every window to it, so all segments share one program commitment. The
//! resulting per-segment proofs then verify trustlessly via
//! `verify_chain_standalone` against that single commitment — accepted by the
//! DEFAULT verifier (the conjectured-security floor), with NO `PcsPolicy::MOBILE`
//! at the call site even though canonical proving uses the MOBILE PCS config.

use javm::PVM_REGISTER_COUNT;
use javm::instruction::Opcode;
use javm::interpreter::Interpreter;

use zkpvm::core::tracing::TracingPvm;
use zkpvm::segment::segment_bounds;
use zkpvm::{SideNote, program_commitment_of_proof, prove_chain};
use zkpvm_verifier::verify_chain_standalone;

#[test]
fn prove_chain_verifies_as_canonical_chain() {
    // Six chained Add64s + Trap (7 steps) — the chain_standalone fixture.
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

    let full = SideNote::new(all_steps, code, bitmask).with_memory(initial_memory);
    // Multi-window cut: 4-step windows over 7 steps ⇒ [0,4), [4,7).
    let bounds = segment_bounds(full.steps.len(), 4);
    assert_eq!(bounds, vec![(0, 4), (4, 7)], "expected a 2-window chain");

    let (profile, proofs) = prove_chain(&full, &bounds).expect("prove_chain must succeed");
    assert_eq!(proofs.len(), bounds.len(), "one proof per window");
    assert_eq!(
        profile.len(),
        zkpvm::chip_idx::COUNT,
        "profile is a per-chip forcing floor"
    );

    // Canonical forcing ⇒ every window shares ONE program commitment.
    let commit = program_commitment_of_proof(&proofs[0]);
    for p in &proofs {
        assert_eq!(
            program_commitment_of_proof(p),
            commit,
            "canonical chain must share one program commitment"
        );
    }

    // prove_chain wired the boundary states, so the chain is continuous.
    for w in proofs.windows(2) {
        assert_eq!(
            w[0].final_state, w[1].initial_state,
            "segments must chain (prove_chain produced the boundary states)"
        );
    }

    // The DEFAULT trustless chain verifier accepts the MOBILE canonical chain —
    // no PcsPolicy::MOBILE needed (the conjectured-security floor accepts it).
    let expected_root = proofs[0].initial_state.memory_root;
    let final_root = verify_chain_standalone(&proofs, commit, expected_root)
        .expect("honest canonical chain must verify standalone under the default floor");
    assert_eq!(
        final_root,
        proofs.last().unwrap().final_state.memory_root,
        "verify_chain_standalone returns the chain's final root"
    );
}
