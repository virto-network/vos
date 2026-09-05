use vos_pvm::instruction::Opcode;
use vos_pvm::interpreter::Interpreter;
// Memory is now flat_mem in Interpreter
use vos_pvm::PVM_REGISTER_COUNT;

use vos_pvm_proof::core::tracing::TracingPvm;
use vos_pvm_proof::{Proof, SideNote, prove};
use vos_pvm_proof_verifier::{CommitmentHash, verify_standalone};

fn assert_hostile_proof_rejected_without_panic(
    label: &str,
    proof: Proof,
    preprocessed_commitment: CommitmentHash,
    side_note: &SideNote,
) {
    let standalone = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        verify_standalone(proof.clone(), preprocessed_commitment)
    }));
    assert!(standalone.is_ok(), "standalone verifier panicked: {label}");
    assert!(
        standalone.unwrap().is_err(),
        "standalone verifier accepted hostile proof: {label}"
    );

    let prover_side = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        vos_pvm_proof::verify(proof, side_note)
    }));
    assert!(
        prover_side.is_ok(),
        "prover-side verifier panicked: {label}"
    );
    assert!(
        prover_side.unwrap().is_err(),
        "prover-side verifier accepted hostile proof: {label}"
    );
}

fn mutate_pcs_config(
    mut proof: Proof,
    mutate: impl FnOnce(&mut stwo::core::pcs::PcsConfig),
) -> Proof {
    mutate(&mut proof.pcs_config);
    proof.stark_proof.0.config = proof.pcs_config;
    proof
}

#[test]
fn standalone_verify_add64() {
    // Build and prove a simple program
    let code = vec![Opcode::Add64 as u8, 0x10, 2, Opcode::Trap as u8];
    let bitmask = vec![1, 0, 0, 1];

    let mut registers = [0u64; PVM_REGISTER_COUNT];
    registers[0] = 100;
    registers[1] = 200;

    let pvm = Interpreter::new(
        code.clone(),
        bitmask.clone(),
        vec![],
        registers,
        vec![0u8; 4 * 1024 * 1024],
        1000,
        25,
    );
    let mut tracing = TracingPvm::new_conformance(pvm);
    tracing.run();
    let steps = tracing.into_trace();

    let mut side_note = SideNote::new(steps, code, bitmask);
    let proof = prove(&mut side_note).expect("proving failed");

    // Extract the preprocessed commitment from the proof itself
    // (In production, this would be pre-computed from the program bytecode)
    let preprocessed_commitment = proof.stark_proof.commitments[0];

    // Verify using standalone verifier (no SideNote needed!)
    verify_standalone(proof.clone(), preprocessed_commitment)
        .expect("standalone verification failed");

    // Hostile claimed logs below the 16-lane trace floor used to reach an
    // unchecked `log_size - LOG_N_LANES` in both verifier funnels. They are
    // structural errors, never panics.
    for small_log in 1..=3 {
        let mut hostile = proof.clone();
        hostile.log_sizes.fill(small_log);
        assert_hostile_proof_rejected_without_panic(
            &format!("component log {small_log}"),
            hostile,
            preprocessed_commitment,
            &side_note,
        );
    }

    // Nested hostile shapes are rejected before either verifier enters Stwo.
    let mut hostile = proof.clone();
    let sample = hostile.stark_proof.sampled_values[0][0][0];
    hostile.stark_proof.0.sampled_values[0][0].resize(
        vos_pvm_proof::proof::MAX_PROOF_SAMPLES_PER_COLUMN + 1,
        sample,
    );
    assert_hostile_proof_rejected_without_panic(
        "oversized OODS samples",
        hostile,
        preprocessed_commitment,
        &side_note,
    );

    let mut hostile = proof.clone();
    hostile.claimed_sums[0] =
        stwo::core::fields::qm31::SecureField::from_u32_unchecked(u32::MAX, 0, 0, 0);
    assert_hostile_proof_rejected_without_panic(
        "noncanonical claimed-sum limb",
        hostile,
        preprocessed_commitment,
        &side_note,
    );

    let mut hostile = proof.clone();
    hostile.stark_proof.0.sampled_values[0][0][0] =
        stwo::core::fields::qm31::SecureField::from_u32_unchecked(u32::MAX, 0, 0, 0);
    assert_hostile_proof_rejected_without_panic(
        "noncanonical OODS-sample limb",
        hostile,
        preprocessed_commitment,
        &side_note,
    );

    let mut hostile = proof.clone();
    hostile.stark_proof.0.queried_values[0][0][0] =
        stwo::core::fields::m31::BaseField::from_u32_unchecked(u32::MAX);
    assert_hostile_proof_rejected_without_panic(
        "noncanonical queried-value limb",
        hostile,
        preprocessed_commitment,
        &side_note,
    );

    let mut hostile = proof.clone();
    hostile.stark_proof.0.commitments.clear();
    assert_hostile_proof_rejected_without_panic(
        "missing commitment trees",
        hostile,
        preprocessed_commitment,
        &side_note,
    );

    let mut hostile = proof.clone();
    hostile.stark_proof.0.queried_values[0].pop();
    assert_hostile_proof_rejected_without_panic(
        "missing queried-value column",
        hostile,
        preprocessed_commitment,
        &side_note,
    );

    let mut hostile = proof.clone();
    hostile.stark_proof.0.fri_proof.inner_layers.pop();
    assert_hostile_proof_rejected_without_panic(
        "missing FRI layer",
        hostile,
        preprocessed_commitment,
        &side_note,
    );

    let mut hostile = proof.clone();
    hostile.stark_proof.0.config.pow_bits ^= 1;
    assert_hostile_proof_rejected_without_panic(
        "outer/embedded PCS mismatch",
        hostile,
        preprocessed_commitment,
        &side_note,
    );

    for (label, hostile) in [
        (
            "zero FRI blowup",
            mutate_pcs_config(proof.clone(), |config| {
                config.fri_config.log_blowup_factor = 0;
            }),
        ),
        (
            "oversized FRI blowup",
            mutate_pcs_config(proof.clone(), |config| {
                config.fri_config.log_blowup_factor = 17;
            }),
        ),
        (
            "oversized FRI last layer",
            mutate_pcs_config(proof.clone(), |config| {
                config.fri_config.log_last_layer_degree_bound = 11;
            }),
        ),
        (
            "zero FRI fold step",
            mutate_pcs_config(proof.clone(), |config| {
                config.fri_config.fold_step = 0;
            }),
        ),
        (
            "unsupported FRI fold step",
            mutate_pcs_config(proof.clone(), |config| {
                config.fri_config.fold_step = 2;
            }),
        ),
        (
            "zero FRI queries",
            mutate_pcs_config(proof.clone(), |config| {
                config.fri_config.n_queries = 0;
            }),
        ),
        (
            "oversized FRI queries",
            mutate_pcs_config(proof.clone(), |config| {
                config.fri_config.n_queries = vos_pvm_proof::proof::MAX_FRI_QUERIES + 1;
            }),
        ),
        (
            "oversized proof-of-work bits",
            mutate_pcs_config(proof.clone(), |config| {
                config.pow_bits = 32;
            }),
        ),
        (
            "oversized lifting domain",
            mutate_pcs_config(proof.clone(), |config| {
                config.lifting_log_size = Some(vos_pvm_proof::proof::MAX_EXTENDED_LOG_SIZE + 1);
            }),
        ),
        (
            "proof-side recommitment amplification",
            mutate_pcs_config(proof.clone(), |config| {
                config.fri_config.log_blowup_factor =
                    vos_pvm_proof::proof::MAX_RECOMMIT_LOG_BLOWUP + 1;
            }),
        ),
    ] {
        assert_hostile_proof_rejected_without_panic(
            label,
            hostile,
            preprocessed_commitment,
            &side_note,
        );
    }

    // `None` and `Some(derived)` can describe the same effective tree height
    // for some AIR layouts, but are distinct signed protocol configurations.
    // Relabelling both outer and embedded config must fail cryptographically.
    let required_lifting = u32::try_from(proof.stark_proof.fri_proof.inner_layers.len()).unwrap()
        + 1
        + proof.pcs_config.fri_config.log_last_layer_degree_bound
        + proof.pcs_config.fri_config.log_blowup_factor;
    let hostile = mutate_pcs_config(proof.clone(), |config| {
        config.lifting_log_size = Some(required_lifting);
    });
    assert_hostile_proof_rejected_without_panic(
        "PCS lifting Option relabel",
        hostile,
        preprocessed_commitment,
        &side_note,
    );

    let mut hostile = proof.clone();
    hostile.component_mask = 0;
    assert_hostile_proof_rejected_without_panic(
        "component-mask metadata relabel",
        hostile,
        preprocessed_commitment,
        &side_note,
    );

    // Per-vector bounds alone used to permit multi-gigabyte Cartesian
    // products. Keep every individual vector within its protocol ceiling but
    // exceed the named aggregate heap budget; both owned-proof verifier
    // funnels must reject before entering Stwo. Refine's borrowed bundle
    // funnel separately runs the same check before cloning children.
    let mut aggregate = proof;
    aggregate.pcs_config.fri_config.n_queries = vos_pvm_proof::proof::MAX_FRI_QUERIES;
    aggregate.stark_proof.0.config = aggregate.pcs_config;
    let secure = aggregate.stark_proof.sampled_values[0][0][0];
    let base = aggregate.stark_proof.queried_values[0][0][0];
    for tree in aggregate.stark_proof.0.sampled_values.iter_mut() {
        for column in tree {
            column.resize(vos_pvm_proof::proof::MAX_PROOF_SAMPLES_PER_COLUMN, secure);
        }
    }
    for tree in aggregate.stark_proof.0.queried_values.iter_mut() {
        for column in tree {
            column.resize(vos_pvm_proof::proof::MAX_FRI_QUERIES, base);
        }
    }
    aggregate.stark_proof.0.sampled_values[0].resize(
        vos_pvm_proof::proof::MAX_PROOF_COLUMNS_PER_TREE,
        vec![secure; vos_pvm_proof::proof::MAX_PROOF_SAMPLES_PER_COLUMN],
    );
    aggregate.stark_proof.0.queried_values[0].resize(
        vos_pvm_proof::proof::MAX_PROOF_COLUMNS_PER_TREE,
        vec![base; vos_pvm_proof::proof::MAX_FRI_QUERIES],
    );
    let aggregate_bytes = vos_pvm_proof::proof::proof_owned_bytes(&aggregate);
    assert!(
        aggregate_bytes.is_none(),
        "aggregate hostile proof unexpectedly fit: {aggregate_bytes:?}"
    );
    assert_hostile_proof_rejected_without_panic(
        "aggregate nested payload",
        aggregate,
        preprocessed_commitment,
        &side_note,
    );
}

#[test]
fn standalone_verify_rejects_wrong_commitment() {
    let code = vec![Opcode::Trap as u8];
    let bitmask = vec![1];
    let registers = [0u64; PVM_REGISTER_COUNT];

    let pvm = Interpreter::new(
        code.clone(),
        bitmask.clone(),
        vec![],
        registers,
        vec![0u8; 4 * 1024 * 1024],
        1000,
        25,
    );
    let mut tracing = TracingPvm::new_conformance(pvm);
    tracing.run();
    let steps = tracing.into_trace();

    let mut side_note = SideNote::new(steps, code, bitmask);
    let proof = prove(&mut side_note).expect("proving failed");

    // Use a wrong commitment
    let wrong_commitment = vos_pvm_proof_verifier::CommitmentHash::default();

    let result = verify_standalone(proof, wrong_commitment);
    assert!(
        result.is_err(),
        "should reject wrong preprocessed commitment"
    );
}

// Phase 42: format_version is checked first, before any cryptographic
// work.  A proof with a mismatched format_version (simulating a future-
// AIR proof presented to today's verifier, or a deserialized older
// proof that lacks the field — serde-default 0) is rejected immediately.
#[test]
fn standalone_verify_rejects_format_version_mismatch() {
    let code = vec![Opcode::Trap as u8];
    let bitmask = vec![1];
    let registers = [0u64; PVM_REGISTER_COUNT];

    let pvm = Interpreter::new(
        code.clone(),
        bitmask.clone(),
        vec![],
        registers,
        vec![0u8; 4 * 1024 * 1024],
        1000,
        25,
    );
    let mut tracing = TracingPvm::new_conformance(pvm);
    tracing.run();
    let steps = tracing.into_trace();

    let mut side_note = SideNote::new(steps, code, bitmask);
    let mut proof = prove(&mut side_note).expect("proving failed");
    let preprocessed_commitment = proof.stark_proof.commitments[0];

    let mut explicitly_old = proof.clone();
    explicitly_old.format_version = 18;
    let old_error = verify_standalone(explicitly_old, preprocessed_commitment)
        .expect_err("format-18 proof must be rejected by format 20");
    assert!(format!("{old_error:?}").contains("format version"));

    // Stronger regression: construct all Stwo commitments/openings under the
    // actual pre-config-binding v18 transcript, then relabel only the outer
    // generation as current. The version field passes structural preflight,
    // but the current FS prefix must make cryptographic verification fail.
    let relabelled = vos_pvm_proof::prove_pre_config_relabel_for_test(&mut side_note)
        .expect("legacy-transcript adversarial proof generation failed");
    assert_eq!(
        relabelled.format_version,
        vos_pvm_proof::PROOF_FORMAT_VERSION
    );
    let relabelled_commitment = relabelled.stark_proof.commitments[0];
    assert!(
        verify_standalone(relabelled.clone(), relabelled_commitment).is_err(),
        "pre-config-binding transcript was accepted after relabelling"
    );
    assert!(
        vos_pvm_proof::verify(relabelled, &side_note).is_err(),
        "prover-side verifier accepted a relabelled v18 transcript"
    );

    // Forge: simulate a proof from a future AIR shape.
    proof.format_version = vos_pvm_proof::PROOF_FORMAT_VERSION + 1;

    let err = verify_standalone(proof, preprocessed_commitment)
        .expect_err("should reject mismatched format_version");
    let msg = format!("{err:?}");
    assert!(
        msg.contains("format version"),
        "expected format-version error, got: {msg}"
    );
}

// Phase 49: pcs_config policy floor.  A proof generated with a
// weaker PcsConfig (lower pow_bits / fewer FRI queries / smaller
// blowup) than PcsPolicy::STANDARD must be rejected by the
// default verify_standalone path before any cryptographic work.
#[test]
fn standalone_verify_rejects_weak_pcs_config() {
    use stwo::core::{fri::FriConfig, pcs::PcsConfig};
    use vos_pvm_proof::prove_with_config;

    let code = vec![Opcode::Trap as u8];
    let bitmask = vec![1];
    let registers = [0u64; PVM_REGISTER_COUNT];

    let pvm = Interpreter::new(
        code.clone(),
        bitmask.clone(),
        vec![],
        registers,
        vec![0u8; 4 * 1024 * 1024],
        1000,
        25,
    );
    let mut tracing = TracingPvm::new_conformance(pvm);
    tracing.run();
    let steps = tracing.into_trace();

    // Prove with a config below STANDARD policy: pow_bits = 0, only
    // 1 FRI query.  Honest prover output but at "test-grade" security.
    let weak_config = PcsConfig {
        pow_bits: 0,
        fri_config: FriConfig::new(0, 4, 1, 1),
        lifting_log_size: None,
    };
    let mut side_note = SideNote::new(steps, code, bitmask);
    let proof = prove_with_config(&mut side_note, weak_config).expect("proving failed");
    let preprocessed_commitment = proof.stark_proof.commitments[0];

    let err = vos_pvm_proof_verifier::verify_standalone(proof, preprocessed_commitment)
        .expect_err("default verify_standalone must reject weak pcs_config");
    let msg = format!("{err:?}");
    assert!(
        msg.contains("pow_bits") || msg.contains("n_queries"),
        "expected pcs_config policy rejection, got: {msg}"
    );
}

#[test]
fn standalone_verify_accepts_weak_pcs_config_with_relaxed_policy() {
    use stwo::core::{fri::FriConfig, pcs::PcsConfig};
    use vos_pvm_proof::prove_with_config;

    let code = vec![Opcode::Trap as u8];
    let bitmask = vec![1];
    let registers = [0u64; PVM_REGISTER_COUNT];

    let pvm = Interpreter::new(
        code.clone(),
        bitmask.clone(),
        vec![],
        registers,
        vec![0u8; 4 * 1024 * 1024],
        1000,
        25,
    );
    let mut tracing = TracingPvm::new_conformance(pvm);
    tracing.run();
    let steps = tracing.into_trace();

    let weak_config = PcsConfig {
        pow_bits: 0,
        fri_config: FriConfig::new(0, 4, 1, 1),
        lifting_log_size: None,
    };
    let mut side_note = SideNote::new(steps, code, bitmask);
    let proof = prove_with_config(&mut side_note, weak_config).expect("proving failed");
    let preprocessed_commitment = proof.stark_proof.commitments[0];

    // Relaxed policy that allows weaker configs (e.g. for test
    // harnesses).  The proof must verify under this policy.
    let test_policy = vos_pvm_proof_verifier::PcsPolicy {
        min_pow_bits: 0,
        min_fri_queries: 1,
        min_fri_log_blowup: 4,
    };
    vos_pvm_proof_verifier::verify_standalone_with_pcs_policy(
        proof,
        preprocessed_commitment,
        &test_policy,
    )
    .expect("relaxed-policy verify must accept the weak proof");
}

// Phase 43: log_size cap test.  We don't need to forge a giant proof
// — just call the variant with an unrealistically tight cap and check
// the early rejection fires.
#[test]
fn standalone_verify_rejects_oversized_log_size() {
    let code = vec![Opcode::Trap as u8];
    let bitmask = vec![1];
    let registers = [0u64; PVM_REGISTER_COUNT];

    let pvm = Interpreter::new(
        code.clone(),
        bitmask.clone(),
        vec![],
        registers,
        vec![0u8; 4 * 1024 * 1024],
        1000,
        25,
    );
    let mut tracing = TracingPvm::new_conformance(pvm);
    tracing.run();
    let steps = tracing.into_trace();

    let mut side_note = SideNote::new(steps, code, bitmask);
    let proof = prove(&mut side_note).expect("proving failed");
    let preprocessed_commitment = proof.stark_proof.commitments[0];

    // Cap = 0: even the smallest legitimate proof has log_sizes >= LOG_N_LANES.
    let err = vos_pvm_proof_verifier::verify_standalone_with_max_log_size(
        proof,
        preprocessed_commitment,
        0,
    )
    .expect_err("should reject — cap is zero");
    let msg = format!("{err:?}");
    assert!(msg.contains("outside 4..=0"), "got: {msg}");
}

#[test]
fn standalone_verify_rejects_zero_format_version() {
    // Pre-Phase-42 serialized proofs (which lack the field) deserialize
    // with serde default 0 → must be rejected.  Simulate by setting the
    // field to 0 directly.
    let code = vec![Opcode::Trap as u8];
    let bitmask = vec![1];
    let registers = [0u64; PVM_REGISTER_COUNT];

    let pvm = Interpreter::new(
        code.clone(),
        bitmask.clone(),
        vec![],
        registers,
        vec![0u8; 4 * 1024 * 1024],
        1000,
        25,
    );
    let mut tracing = TracingPvm::new_conformance(pvm);
    tracing.run();
    let steps = tracing.into_trace();

    let mut side_note = SideNote::new(steps, code, bitmask);
    let mut proof = prove(&mut side_note).expect("proving failed");
    let preprocessed_commitment = proof.stark_proof.commitments[0];

    proof.format_version = 0;

    let err = verify_standalone(proof, preprocessed_commitment)
        .expect_err("should reject format_version=0");
    let msg = format!("{err:?}");
    assert!(msg.contains("format version"), "got: {msg}");
}
