//! Fast guard tests for the program-agnostic `prover` extension's
//! public entry points — no ELF, no proving.
//!
//! The proof-level happy path + adversarial io/commitment rejections
//! for voucher-check live with the rest of the transition harness in
//! `prove_transition.rs` (`prove_transition_roundtrip_and_forgery_
//! rejected`, gated until chain-aware prove/verify lands — the
//! transition trace only proves as a segment chain).

use prover_extension::{program_commitment_bytes, prove_program, verify_proof_bytes};

/// Fast logic checks (no proving): program-id resolution + verify guards.
#[test]
fn unknown_program_and_malformed_inputs_reject() {
    // Unknown program_id resolves to no ELF → prove yields nothing.
    assert!(
        prove_program(b"no-such-program", &[]).is_none(),
        "an unknown program_id must not resolve to an ELF"
    );
    assert!(
        program_commitment_bytes(b"no-such-program").is_none(),
        "an unknown program_id has no commitment"
    );

    // Malformed verify inputs reject without panicking — in particular a
    // non-32-byte commitment must NOT reach the panicking `CommitmentHash`
    // ctor, and undecodable proof bytes are rejected.
    assert!(
        !verify_proof_bytes(&[0u8; 31], b"x", b"p", b"r"),
        "short commitment must reject"
    );
    assert!(
        !verify_proof_bytes(&[0u8; 32], b"not-a-proof", b"p", b"r"),
        "garbage proof must reject"
    );
}
