use javm::instruction::Opcode;
use javm::interpreter::Interpreter;
// Memory is now flat_mem in Interpreter
use javm::PVM_REGISTER_COUNT;

use zkpvm::core::tracing::TracingPvm;
use zkpvm::{prove, SideNote};
use zkpvm_verifier::verify_standalone;

#[test]
fn standalone_verify_add64() {
    // Build and prove a simple program
    let code = vec![
        Opcode::Add64 as u8, 0x10, 2,
        Opcode::Trap as u8,
    ];
    let bitmask = vec![1, 0, 0, 1];

    let mut registers = [0u64; PVM_REGISTER_COUNT];
    registers[0] = 100;
    registers[1] = 200;

    let pvm = Interpreter::new(code.clone(), bitmask.clone(), vec![], registers, vec![0u8; 4 * 1024 * 1024], 1000, 25);
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

    let pvm = Interpreter::new(code.clone(), bitmask.clone(), vec![], registers, vec![0u8; 4 * 1024 * 1024], 1000, 25);
    let mut tracing = TracingPvm::new(pvm);
    tracing.run();
    let steps = tracing.into_trace();

    let mut side_note = SideNote::new(steps, code, bitmask);
    let proof = prove(&mut side_note).expect("proving failed");

    // Use a wrong commitment
    let wrong_commitment = zkpvm_verifier::CommitmentHash::default();

    let result = verify_standalone(proof, wrong_commitment);
    assert!(result.is_err(), "should reject wrong preprocessed commitment");
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

    let pvm = Interpreter::new(code.clone(), bitmask.clone(), vec![], registers, vec![0u8; 4 * 1024 * 1024], 1000, 25);
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

#[test]
fn standalone_verify_rejects_zero_format_version() {
    // Pre-Phase-42 serialized proofs (which lack the field) deserialize
    // with serde default 0 → must be rejected.  Simulate by setting the
    // field to 0 directly.
    let code = vec![Opcode::Trap as u8];
    let bitmask = vec![1];
    let registers = [0u64; PVM_REGISTER_COUNT];

    let pvm = Interpreter::new(code.clone(), bitmask.clone(), vec![], registers, vec![0u8; 4 * 1024 * 1024], 1000, 25);
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
