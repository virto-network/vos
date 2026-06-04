//! Cross-crate encoding pin for E4 (`Voucher::proof_public`).
//!
//! LOAD-BEARING: the clerk-bridge verifier builds the External-mode
//! proof's public inputs via `voucher.proof_public(peer_key).encode()`
//! (vos `Encode` = `rkyv::to_bytes`). This must be byte-identical to
//! cipher-clerk's own `Public::canonical_bytes` AND must yield the same
//! io-hash the voucher-check guest bound via `bind_io(&public, &1u8)`.
//! If rkyv ever diverges between the two crates, these fire HERE instead
//! of as a silently-rejected proof inside the federation e2e.

use cipher_clerk::crypto::{Amount, AuthKey, Keypair};
use cipher_clerk::viewing_keys::EncryptedEnvelope;
use cipher_clerk::voucher::Voucher;
use vos::Encode;

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
fn proof_public_canonical_bytes_equals_vos_encode() {
    let v = sample_voucher();
    let verifier = AuthKey([0x11u8; 32]);
    let public = v.proof_public(&verifier);
    assert_eq!(
        public.canonical_bytes(),
        Encode::encode(&public),
        "cipher-clerk canonical_bytes must equal vos::Encode::encode (rkyv 0.8 equivalence)"
    );
}

#[test]
fn proof_public_io_hash_matches_guest_binding() {
    let v = sample_voucher();
    let public = v.proof_public(&AuthKey([0x11u8; 32]));
    // The hash the guest binds via `bind_io(&public, &1u8)`.
    let h = vos::zk::compute_io_hash_typed(&public, &1u8);
    assert_eq!(h, vos::zk::compute_io_hash_typed(&public, &1u8));
    assert_ne!(h, [0u8; 32], "a real binding is never the unbound sentinel");
    // The exact equality chain the host `prover` verify relies on:
    // typed == byte-primitive over both the vos `Encode` bytes and the
    // cipher-clerk `canonical_bytes`.
    assert_eq!(h, vos::zk::compute_io_hash(&public.encode(), &1u8.encode()));
    assert_eq!(
        h,
        vos::zk::compute_io_hash(&public.canonical_bytes(), &1u8.encode())
    );
}

#[test]
fn proof_public_issuer_is_caller_supplied_and_rebinds() {
    let v = sample_voucher();
    let p1 = v.proof_public(&AuthKey([0x11u8; 32]));
    let p2 = v.proof_public(&AuthKey([0x22u8; 32]));
    // issuer comes from the caller, not the voucher body — different
    // issuer ⇒ different encoding ⇒ different io-hash.
    assert_ne!(Encode::encode(&p1), Encode::encode(&p2));
    assert_ne!(
        vos::zk::compute_io_hash_typed(&p1, &1u8),
        vos::zk::compute_io_hash_typed(&p2, &1u8),
    );
    // The non-issuer fields are copied verbatim from the body.
    assert_eq!(p1.amount_commit.0, v.amount_commit.0);
    assert_eq!(p1.state_root_before, v.state_root_before);
    assert_eq!(p1.state_root_after, v.state_root_after);
}
