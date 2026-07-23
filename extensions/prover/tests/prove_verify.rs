//! Fast, program-agnostic guard tests for the `prover` extension's public
//! entry points — no ELF, no transpile, no proving.
//!
//! The real proof-level happy path (prove a segment chain → verify it
//! against a canonical commitment allowlist + io-binding) lives with the
//! systems that use the prover — e.g. the federation flow in
//! `vos/tests/elf_integration.rs`. Here we only pin the cheap reject/guard
//! paths that short-circuit before any STARK work.

use prover_extension::{
    decode_chain_manifest, encode_chain_manifest, encode_chain_manifest_anchored,
    verify_chain_segments, verify_chain_segments_anchored, verify_proof_bytes,
};

/// `verify` guards: malformed inputs reject without panicking — in
/// particular a non-32-byte commitment must NOT reach the panicking
/// `CommitmentHash` ctor, and undecodable proof bytes are rejected.
#[test]
fn verify_malformed_inputs_reject() {
    assert!(
        !verify_proof_bytes(&[0u8; 31], b"x", b"p", b"r"),
        "short commitment must reject"
    );
    assert!(
        !verify_proof_bytes(&[0u8; 32], b"not-a-proof", b"p", b"r"),
        "garbage proof must reject"
    );
}

/// Manifest codec round-trips an ordered hash list (order-preserving) plus the
/// entering-image root, and a garbled blob decodes to `None` (not a panic, not
/// a partial list). The legacy `encode_chain_manifest` produces the unanchored
/// (all-zero root) form; `encode_chain_manifest_anchored` carries a real root.
#[test]
fn manifest_codec_roundtrips() {
    let hashes: Vec<[u8; 32]> = (0u8..5).map(|i| [i; 32]).collect();

    // Legacy form: segment hashes preserved, entering root = unanchored sentinel.
    let blob = encode_chain_manifest(&hashes);
    let m = decode_chain_manifest(&blob).expect("legacy manifest must decode");
    assert_eq!(
        m.segments, hashes,
        "encode→decode must preserve the segment order"
    );
    assert_eq!(
        m.initial_root, [0u8; 32],
        "legacy encode is unanchored (zero root)"
    );

    // Anchored form: a non-zero entering root rides alongside the segments.
    let root = [0x11u8; 32];
    let anchored = encode_chain_manifest_anchored(root, &hashes);
    let ma = decode_chain_manifest(&anchored).expect("anchored manifest must decode");
    assert_eq!(
        ma.segments, hashes,
        "anchored encode→decode must preserve the segment order"
    );
    assert_eq!(
        ma.initial_root, root,
        "anchored encode→decode must preserve the entering root"
    );

    // Malformed: not a positive multiple of 32 carrying a root + ≥1 segment.
    assert!(
        decode_chain_manifest(&[0xFFu8; 7]).is_none(),
        "a malformed manifest blob must decode to None"
    );
    assert!(
        decode_chain_manifest(&[0xFFu8; 32]).is_none(),
        "a root-only manifest (no segments) must decode to None"
    );
}

/// `verify_chain` guards that short-circuit before any STARK work. The
/// allowlist is the concatenation of 32-byte commitments, so an empty or
/// non-multiple-of-32 allowlist, an empty chain, or an undecodable segment
/// blob must all reject (not panic).
#[test]
fn verify_chain_guards_reject() {
    let allowlist = [0u8; 32]; // one fabricated commitment
    let io = b"some-public-bytes";

    // Empty allowlist → reject (no accepted commitment to anchor to).
    assert!(
        !verify_chain_segments(&[], &[vec![0u8; 4]], io, &[1u8]),
        "an empty allowlist must reject"
    );
    // Non-multiple-of-32 allowlist → reject before any decode.
    assert!(
        !verify_chain_segments(&[0u8; 40], &[vec![0u8; 4]], io, &[1u8]),
        "a non-multiple-of-32 allowlist must reject"
    );
    // Empty chain → reject (no segments to anchor/verify).
    assert!(
        !verify_chain_segments(&allowlist, &[], io, &[1u8]),
        "an empty segment list must reject"
    );
    // A valid allowlist but garbage segment bytes → per-segment decode
    // fails → reject (no panic).
    assert!(
        !verify_chain_segments(&allowlist, &[vec![0xABu8; 32]], io, &[1u8]),
        "an undecodable segment blob must reject"
    );

    // The anchored variant is at least as strict: supplying an entering-image
    // anchor never turns a rejected chain into an accepted one, and it still
    // rejects the same pre-STARK guard inputs (no panic).
    let root = Some([0x22u8; 32]);
    assert!(
        !verify_chain_segments_anchored(&[], &[vec![0u8; 4]], root, io, &[1u8]),
        "empty allowlist must reject even with an anchor"
    );
    assert!(
        !verify_chain_segments_anchored(&allowlist, &[], root, io, &[1u8]),
        "empty chain must reject even with an anchor"
    );
    assert!(
        !verify_chain_segments_anchored(&allowlist, &[vec![0xABu8; 32]], root, io, &[1u8]),
        "an undecodable segment blob must reject even with an anchor"
    );
}
