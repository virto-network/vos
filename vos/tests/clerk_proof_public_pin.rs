//! Cross-crate io-binding pin for the External-mode voucher proof.
//!
//! The clerk-bridge verifier builds the proof's public inputs via
//! `cipher_clerk::voucher::proof::public_bytes(&voucher.proof_public(peer_key))`
//! and folds them through `vos::zk::compute_io_hash`; the voucher-check
//! guest binds the SAME `public_bytes` via `vos::zk::bind_io_bytes`. With
//! one explicit, domain-separated encoding owned by cipher-clerk, the two
//! sides agree *by construction* — there is no rkyv-layout / cross-crate
//! equivalence left to guard (the prior dual-encoding `canonical_bytes`
//! wart is gone, the D1 cleanup).
//!
//! So this is now a fast host-side canary that vos's io-hash primitive
//! composes with cipher-clerk's `public_bytes` the way the bridge expects
//! (deterministic, non-zero, domain-tagged, issuer-sensitive). The real
//! guest↔bridge equality is proven end-to-end by the federation e2e
//! (`elf_integration::clerk_ledger_two_bank_federation`), where both sides
//! run the same `public_bytes` through a real STARK.

use cipher_clerk::crypto::{Amount, AuthKey, Keypair};
use cipher_clerk::viewing_keys::EncryptedEnvelope;
use cipher_clerk::voucher::Voucher;
use cipher_clerk::voucher::proof::{VOUCHER_PROOF_DOMAIN, public_bytes};

/// The asserted return half voucher-check binds: the raw `1` success
/// marker (`bind_io_bytes(&public_bytes, &[1u8])`), matched by the bridge's
/// `return_bytes = vec![1u8]`.
const RETURN_BYTES: &[u8] = &[1u8];

/// A signed voucher. The amount commitment is raw bytes (not a real
/// Pedersen commit) — these tests pin *encoding*, not crypto validity.
fn sample_voucher() -> Voucher {
    let issuer = Keypair::generate();
    let envelope = EncryptedEnvelope {
        ephemeral_pub: AuthKey([7u8; 32]),
        ciphertext: vec![1, 2, 3, 4],
    };
    Voucher::sign(
        Amount([2u8; 32]),
        envelope,
        [0xAAu8; 32],
        [0xBBu8; 32],
        cipher_clerk::proof::Proof::default(),
        &issuer.secret,
    )
}

#[test]
fn proof_public_io_hash_is_deterministic_nonzero_and_domain_tagged() {
    let v = sample_voucher();
    let public = v.proof_public(&AuthKey([0x11u8; 32]));
    let pb = public_bytes(&public);
    // The explicit encoding is domain-separated — distinct from any rkyv
    // archive of the same struct, so it can't be cross-validated against
    // a wire-format signature payload.
    assert!(
        pb.starts_with(VOUCHER_PROOF_DOMAIN),
        "public_bytes must carry the voucher-proof domain tag"
    );
    // The exact value the guest binds via `bind_io_bytes(&pb, &[1u8])` and
    // the bridge recomputes: deterministic and never the cold-start zero.
    let h = vos::zk::compute_io_hash(&pb, RETURN_BYTES);
    assert_eq!(
        h,
        vos::zk::compute_io_hash(&public_bytes(&public), RETURN_BYTES),
        "io-hash over public_bytes must be deterministic"
    );
    assert_ne!(h, [0u8; 32], "a real binding is never the unbound sentinel");
}

#[test]
fn proof_public_issuer_is_caller_supplied_and_rebinds() {
    let v = sample_voucher();
    let p1 = v.proof_public(&AuthKey([0x11u8; 32]));
    let p2 = v.proof_public(&AuthKey([0x22u8; 32]));
    // issuer comes from the caller, not the voucher body — different
    // issuer ⇒ different public_bytes ⇒ different io-hash.
    assert_ne!(public_bytes(&p1), public_bytes(&p2));
    assert_ne!(
        vos::zk::compute_io_hash(&public_bytes(&p1), RETURN_BYTES),
        vos::zk::compute_io_hash(&public_bytes(&p2), RETURN_BYTES),
    );
    // The non-issuer fields are copied verbatim from the body.
    assert_eq!(p1.amount_commit.0, v.amount_commit.0);
    assert_eq!(p1.state_root_before, v.state_root_before);
    assert_eq!(p1.state_root_after, v.state_root_after);
}
