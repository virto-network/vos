#![cfg(feature = "poseidon2-channel")]

//! One full canonical segment (`prove_canonical`, every component) proves
//! and verifies under the Poseidon2-M31 PCS: the Merkle commitments and the
//! Fiat-Shamir transcript are both Poseidon2-M31, with no Blake2s, and
//! `program_commitment_of_proof` returns a `P2Hash`.
//!
//! The proof is generated and committed on `SimdBackend`, as the Blake2s
//! stack's is. The verifier accepts the honest proof under the MOBILE policy,
//! rejects a main-trace root with one limb changed, and refuses a
//! non-canonical M31 root without panicking.
//!
//! Run: `cargo test -p vos-pvm-proof-verifier --features poseidon2-channel \
//!         --test poseidon2_canonical_segment -- --nocapture`

use vos_pvm::PVM_REGISTER_COUNT;
use vos_pvm::instruction::Opcode;
use vos_pvm::interpreter::Interpreter;

use stwo::core::fields::m31::BaseField;
use vos_pvm_proof::core::tracing::TracingPvm;
use vos_pvm_proof::{SideNote, program_commitment_of_proof, prove_canonical};
use vos_pvm_proof_verifier::{PcsPolicy, verify_standalone_with_pcs_policy};

/// Prove a small but genuine program as one full canonical segment.
fn canonical_segment_proof() -> vos_pvm_proof::Proof {
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
    );
    let mut tracing = TracingPvm::new(pvm);
    assert_eq!(tracing.run(), vos_pvm::ExitReason::Panic);
    let steps = tracing.into_trace();
    assert_eq!(steps.len(), 7);

    let mut sn = SideNote::new(steps, code, bitmask).with_memory(initial_memory);
    // Canonical proving = the full component mask. The empty profile proves
    // each chip at its natural size — sufficient for a single self-consistent
    // segment (the multi-segment `{C_0,C_1}` re-bake that needs a uniform
    // profile is P5.1).
    prove_canonical(&mut sn, &[]).expect("prove_canonical under Poseidon2-M31")
}

#[test]
fn poseidon2_canonical_segment_round_trip() {
    let proof = canonical_segment_proof();

    // The full canonical AIR: every component is present.
    assert!(
        (1..=u64::BITS as usize).contains(&vos_pvm_proof::chip_idx::COUNT),
        "component_mask must represent between 1 and 64 components"
    );
    let expected_component_mask = u64::MAX >> (u64::BITS as usize - vos_pvm_proof::chip_idx::COUNT);
    assert_eq!(
        proof.num_components,
        vos_pvm_proof::chip_idx::COUNT,
        "canonical proof must carry every component"
    );
    assert_eq!(
        proof.component_mask, expected_component_mask,
        "canonical mask must contain every component"
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

    // Serde can construct M31's public tuple field without reduction. Shared
    // hostile-proof preflight must reject such a root before Poseidon or field
    // arithmetic sees it, never merely rely on a debug-overflow panic.
    let mut noncanonical = proof;
    noncanonical.stark_proof.0.commitments[1].0[0] = BaseField::from_u32_unchecked(u32::MAX);
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        verify_standalone_with_pcs_policy(noncanonical, commitment, &PcsPolicy::MOBILE)
    }));
    assert!(outcome.is_ok(), "noncanonical Poseidon root panicked");
    assert!(
        outcome.unwrap().is_err(),
        "noncanonical Poseidon root was accepted"
    );
}
