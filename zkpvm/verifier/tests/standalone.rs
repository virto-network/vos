use javm::instruction::Opcode;
use javm::interpreter::Interpreter;
// Memory is now flat_mem in Interpreter
use javm::PVM_REGISTER_COUNT;

use zkpvm::core::tracing::TracingPvm;
use zkpvm::{SideNote, prove};
use zkpvm_verifier::verify_standalone;

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
    let mut tracing = TracingPvm::new(pvm);
    tracing.run();
    let steps = tracing.into_trace();

    let mut side_note = SideNote::new(steps, code, bitmask);
    let proof = prove(&mut side_note).expect("proving failed");

    // Extract the preprocessed commitment from the proof itself
    // (In production, this would be pre-computed from the program bytecode)
    let preprocessed_commitment = proof.stark_proof.commitments[0];

    // Verify using standalone verifier (no SideNote needed!)
    verify_standalone(proof, preprocessed_commitment).expect("standalone verification failed");
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
    let mut tracing = TracingPvm::new(pvm);
    tracing.run();
    let steps = tracing.into_trace();

    let mut side_note = SideNote::new(steps, code, bitmask);
    let proof = prove(&mut side_note).expect("proving failed");

    // Use a wrong commitment
    let wrong_commitment = zkpvm_verifier::CommitmentHash::default();

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
    let mut tracing = TracingPvm::new(pvm);
    tracing.run();
    let steps = tracing.into_trace();

    let mut side_note = SideNote::new(steps, code, bitmask);
    let mut proof = prove(&mut side_note).expect("proving failed");
    let preprocessed_commitment = proof.stark_proof.commitments[0];

    // Forge: simulate a proof from a future AIR shape.
    proof.format_version = zkpvm::PROOF_FORMAT_VERSION + 1;

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
    use zkpvm::prove_with_config;

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
    let mut tracing = TracingPvm::new(pvm);
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

    let err = zkpvm_verifier::verify_standalone(proof, preprocessed_commitment)
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
    use zkpvm::prove_with_config;

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
    let mut tracing = TracingPvm::new(pvm);
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
    let test_policy = zkpvm_verifier::PcsPolicy {
        min_pow_bits: 0,
        min_fri_queries: 1,
        min_fri_log_blowup: 4,
    };
    zkpvm_verifier::verify_standalone_with_pcs_policy(proof, preprocessed_commitment, &test_policy)
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
    let mut tracing = TracingPvm::new(pvm);
    tracing.run();
    let steps = tracing.into_trace();

    let mut side_note = SideNote::new(steps, code, bitmask);
    let proof = prove(&mut side_note).expect("proving failed");
    let preprocessed_commitment = proof.stark_proof.commitments[0];

    // Cap = 0: even the smallest legitimate proof has log_sizes >= LOG_N_LANES.
    let err =
        zkpvm_verifier::verify_standalone_with_max_log_size(proof, preprocessed_commitment, 0)
            .expect_err("should reject — cap is zero");
    let msg = format!("{err:?}");
    assert!(msg.contains("exceeds cap"), "got: {msg}");
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
    let mut tracing = TracingPvm::new(pvm);
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
