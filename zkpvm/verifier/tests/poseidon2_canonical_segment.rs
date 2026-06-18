#![cfg(feature = "poseidon2-channel")]

//! D1 backend spike (P5.0 / native-recursion Stage-0).
//!
//! GATE: ONE real 31-component **canonical** segment (the `prove_canonical`
//! path) proves+verifies end-to-end under the Poseidon2-M31 PCS — the
//! M31-algebraic Merkle commitment AND the M31-algebraic Fiat-Shamir transcript
//! (no Blake2s on commit or transcript). `program_commitment_of_proof` returns
//! a `P2Hash`.
//!
//! MECHANISM (D1-A2, RECORDED): the production framework generates the main /
//! preprocessed / logup-interaction traces on `SimdBackend` unchanged; the
//! committed columns are transplanted to `CpuBackend` (`recursion_pcs::for_commit`
//! = `to_cpu`) at the commit boundary, and the proof is driven through
//! `prove::<CpuBackend, P2MerkleChannel>` over `FrameworkComponent`s rewrapped as
//! `ComponentProver<CpuBackend>` (the `to_component_prover` return type flips to
//! the `ProverBackend` alias). No framework genericization (A1) and no
//! SimdBackend Poseidon2 commit op (A3) were needed — the transplant suffices.
//!
//! Run: `cargo test -p zkpvm-verifier --features poseidon2-channel \
//!         --test poseidon2_canonical_segment -- --nocapture`

use javm::PVM_REGISTER_COUNT;
use javm::instruction::Opcode;
use javm::interpreter::Interpreter;

use stwo::core::fields::m31::BaseField;
use zkpvm::core::tracing::TracingPvm;
use zkpvm::{SideNote, program_commitment_of_proof, prove_canonical};
use zkpvm_verifier::{PcsPolicy, verify_standalone_with_pcs_policy};

/// Prove a small but genuine program as ONE full 31-component canonical segment.
fn canonical_segment_proof() -> zkpvm::Proof {
    // Six chained Add64s + Trap (7 steps) — the `chain_standalone` program.
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
    let steps = tracing.into_trace();
    assert_eq!(steps.len(), 7);

    let mut sn = SideNote::new(steps, code, bitmask).with_memory(initial_memory);
    // Canonical proving = the FULL 31-component mask. The empty profile proves
    // each chip at its natural size — sufficient for a single self-consistent
    // segment (the multi-segment `{C_0,C_1}` re-bake that needs a uniform
    // profile is P5.1).
    prove_canonical(&mut sn, &[]).expect("prove_canonical under Poseidon2-M31")
}

#[test]
fn poseidon2_canonical_segment_round_trip() {
    let proof = canonical_segment_proof();

    // The full canonical AIR: all 31 components present.
    assert_eq!(
        proof.num_components,
        zkpvm::chip_idx::COUNT,
        "canonical proof must carry all 31 components"
    );
    assert_eq!(
        proof.component_mask,
        (1u32 << zkpvm::chip_idx::COUNT) - 1,
        "canonical mask must be the full 31-bit set"
    );

    // The program commitment is the preprocessed-trace Merkle root, now a
    // `P2Hash` (8 M31 limbs) — the commitment type flipped with the PCS.
    let commitment = program_commitment_of_proof(&proof);

    // Positive: the honest proof verifies through the Poseidon2-M31 verifier.
    // `prove_canonical` uses the MOBILE PCS config (blowup 2), so verify with the
    // matching policy (the default STANDARD policy floors blowup at 4).
    verify_standalone_with_pcs_policy(proof.clone(), commitment, &PcsPolicy::MOBILE)
        .expect("honest canonical segment must verify under Poseidon2-M31");

    // Negative: flip one M31 limb of the MAIN-trace commitment root. The
    // verifier re-derives Merkle roots through the SAME Poseidon2-M31 hasher and
    // mixes a different root into the FS transcript, so its decommitment no
    // longer matches — it MUST reject. This confirms the commitment binding runs
    // through the custom hasher rather than being vacuously accepted.
    let mut tampered = proof.clone();
    let orig = tampered.stark_proof.0.commitments[1].0[0];
    tampered.stark_proof.0.commitments[1].0[0] = orig + BaseField::from_u32_unchecked(1);
    assert!(
        verify_standalone_with_pcs_policy(tampered, commitment, &PcsPolicy::MOBILE).is_err(),
        "a tampered Poseidon2-M31 commitment root must be rejected"
    );
}
