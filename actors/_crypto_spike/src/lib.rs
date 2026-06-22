//! P2 feasibility fixture (not a production actor): proves ciphersuite-1's
//! crypto stack compiles + transpiles + runs correctly for riscv64em-javm in
//! pure no_std software, so the PVM-native messenger port (P2) needs no new
//! precompile for correctness. Exercises SHA-256, HKDF, X25519, Ed25519
//! sign/verify, AES-128-GCM with self-consistency checks (panic on a wrong
//! result), so a clean `vosx run` proves correct runtime execution on the PVM,
//! not just linkage. P2.0 (see docs/design/messaging-pvm-native.md) extends
//! this with `#[msg]` test-vector handlers checked bit-exact against host
//! RustCrypto. Build: `cd actors/_crypto_spike && cargo +nightly actor`.

use vos::prelude::*;

#[actor]
pub struct CryptoSpike {
    digest: Vec<u8>,
}

#[messages]
impl CryptoSpike {
    pub fn new() -> Self {
        Self {
            digest: crypto_self_check(),
        }
    }

    #[msg]
    async fn probe(&self) -> Vec<u8> {
        self.digest.clone()
    }
}

/// Run every ciphersuite-1 primitive on the PVM and assert self-consistency.
/// Returns a digest of the outputs (so nothing is optimised away). Panics on
/// any inconsistency — a clean run means the stack computes correctly.
fn crypto_self_check() -> Vec<u8> {
    use sha2::{Digest, Sha256};

    // SHA-256 + HKDF-SHA256.
    let mut h = Sha256::new();
    h.update(b"vos-crypto-spike");
    let digest = h.finalize();
    let hk = hkdf::Hkdf::<Sha256>::new(Some(&digest), b"ikm");
    let mut okm = [0u8; 32];
    hk.expand(b"info", &mut okm).expect("hkdf expand");

    // X25519 Diffie-Hellman agreement: a*B == b*A.
    let alice = x25519_dalek::StaticSecret::from([7u8; 32]);
    let bob = x25519_dalek::StaticSecret::from([11u8; 32]);
    let alice_pub = x25519_dalek::PublicKey::from(&alice);
    let bob_pub = x25519_dalek::PublicKey::from(&bob);
    let s1 = alice.diffie_hellman(&bob_pub);
    let s2 = bob.diffie_hellman(&alice_pub);
    assert!(s1.as_bytes() == s2.as_bytes(), "x25519 DH disagreement");

    // Ed25519 sign + verify round-trip.
    use ed25519_dalek::{Signer, Verifier};
    let signing = ed25519_dalek::SigningKey::from_bytes(&okm);
    let sig = signing.sign(b"message");
    let vk = signing.verifying_key();
    assert!(vk.verify(b"message", &sig).is_ok(), "ed25519 verify failed");
    assert!(
        vk.verify(b"tampered", &sig).is_err(),
        "ed25519 verified a wrong message"
    );

    // AES-128-GCM encrypt -> decrypt round-trip.
    use aes_gcm::aead::generic_array::GenericArray;
    use aes_gcm::aead::{Aead, KeyInit};
    let cipher = aes_gcm::Aes128Gcm::new(GenericArray::from_slice(&okm[..16]));
    let nonce = GenericArray::from_slice(&[0u8; 12]);
    let ct = cipher.encrypt(nonce, b"plaintext".as_ref()).expect("aead seal");
    let pt = cipher.decrypt(nonce, ct.as_ref()).expect("aead open");
    assert!(pt == b"plaintext", "aes-gcm round-trip mismatch");

    // Fold every output into one digest so nothing is dead-code-eliminated.
    let mut acc = Sha256::new();
    acc.update(digest);
    acc.update(okm);
    acc.update(s1.as_bytes());
    acc.update(sig.to_bytes());
    acc.update(&ct);
    acc.finalize().to_vec()
}
