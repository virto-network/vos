//! ECVRF over Ristretto255 (SHA-512) — a `no_std` verifiable random function
//! for VOS chronos bias resistance.
//!
//! A VRF lets a key holder produce, for any input, a pseudo-random output plus
//! a proof that the output was computed correctly from that input under their
//! public key — and *nobody*, including the holder, can choose the output
//! (it is a deterministic function of the secret key and the input). That is
//! exactly what chronos needs to kill the v0 leader's entropy grind: each raft
//! voter contributes a VRF output over the public round input
//! `α = blake2b(prev_beacon ‖ epoch)`, the committee combines them, and the
//! result is unbiasable as long as one voter is honest.
//!
//! ## Scope
//!
//! This is the reusable primitive ("D0"); the chronos round protocol,
//! voter-key enrolment, and committee combine layer on top of it (D1+). It is
//! pure software over `curve25519-dalek`'s serial backend — its PVM transpile
//! is gated through the real `chronos` actor ELF (`vos/tests/chronos_transpile.rs`)
//! — so it needs no precompile for correctness; the ristretto precompiles (zkpvm
//! ECALLs 110-114) are a measured performance follow-on.
//!
//! ## Ciphersuite (internal, not RFC-registered)
//!
//! This follows the ECVRF construction of RFC 9381 §5.1 over **Ristretto255**
//! with **SHA-512**. RFC 9381 registers P-256 and edwards25519 suites but **not**
//! ristretto255, so there are no official test vectors; correctness here rests on
//! the algebraic prove/verify identity (property-tested below: round-trip,
//! tamper-, wrong-key-, wrong-input-rejection, determinism) rather than on
//! cross-implementation vectors. The construction is internal to a VOS space
//! (every member runs this exact code); cross-ecosystem interop (drand/Sui-style
//! ristretto VRFs, or reverting to a registered edwards suite) is a deliberate
//! deferred choice, separately documented. Concretely:
//!
//! - **hash-to-curve** `H = ristretto_from_uniform(SHA-512(suite ‖ 0x01 ‖ pk ‖ α))`
//!   — the canonical Ristretto map (Elligator) over a 64-byte uniform expansion.
//! - **proof** `(Γ, c, s)` with `Γ = sk·H`, a 128-bit challenge
//!   `c = challenge(pk, H, Γ, k·B, k·H)`, and `s = k + c·sk` for a deterministic
//!   per-proof nonce `k = SHA-512(0x03 ‖ sk ‖ H) mod L`.
//! - **wire** `Γ(32) ‖ c(16) ‖ s(32)` = [`PROOF_LEN`] = 80 bytes.
//! - **output** `β = SHA-512(0x04 ‖ Γ)` (64 bytes), the verifiable random value
//!   a round contributes — **never key material**, only ever a public beacon /
//!   HKDF-`info` hedge downstream.

#![no_std]

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use sha2::{Digest, Sha512};
use zeroize::Zeroize;

/// Domain-separation tag for this ciphersuite. Any change re-forks every
/// derived value, so it carries a version suffix.
const SUITE: &[u8] = b"vos-chronos-ecvrf/ristretto255-sha512/v0";

const H2C_DOMAIN: u8 = 0x01;
const CHALLENGE_DOMAIN: u8 = 0x02;
const NONCE_DOMAIN: u8 = 0x03;
const OUTPUT_DOMAIN: u8 = 0x04;

/// Length of a serialized [`Proof`]: `Γ(32) ‖ c(16) ‖ s(32)`.
pub const PROOF_LEN: usize = 80;
/// Length of a [`PublicKey`] (a compressed Ristretto point).
pub const PUBLIC_KEY_LEN: usize = 32;
/// Length of the VRF output `β`.
pub const OUTPUT_LEN: usize = 64;

/// A VRF secret key — a Ristretto scalar. Zeroized on drop; never serialized by
/// this crate (the holder persists the 32-byte seed it was derived from, out of
/// band, exactly as the messenger CSPRNG seed is handled).
pub struct SecretKey(Scalar);

impl Drop for SecretKey {
    fn drop(&mut self) {
        // Scalar is Copy/POD; overwrite our copy. (curve25519-dalek's own
        // Zeroize is feature-gated; this clears the bytes we hold.)
        let mut bytes = self.0.to_bytes();
        bytes.zeroize();
        self.0 = Scalar::from_bytes_mod_order(bytes);
    }
}

/// A VRF public key — the compressed Ristretto point `pk = sk·B`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PublicKey {
    compressed: CompressedRistretto,
    point: RistrettoPoint,
}

impl PublicKey {
    /// The 32-byte wire encoding.
    pub fn to_bytes(&self) -> [u8; PUBLIC_KEY_LEN] {
        self.compressed.to_bytes()
    }

    /// Parse a public key, rejecting a non-canonical / invalid encoding.
    pub fn from_bytes(bytes: &[u8; PUBLIC_KEY_LEN]) -> Option<Self> {
        let compressed = CompressedRistretto(*bytes);
        let point = compressed.decompress()?;
        Some(Self { compressed, point })
    }
}

/// A VRF proof `(Γ, c, s)`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Proof {
    gamma: RistrettoPoint,
    /// A 128-bit challenge held in a canonical scalar (`c < 2^128`).
    c: Scalar,
    s: Scalar,
}

impl Proof {
    /// The 80-byte wire encoding `Γ(32) ‖ c[..16] ‖ s(32)`.
    pub fn to_bytes(&self) -> [u8; PROOF_LEN] {
        let mut out = [0u8; PROOF_LEN];
        out[..32].copy_from_slice(self.gamma.compress().as_bytes());
        out[32..48].copy_from_slice(&self.c.as_bytes()[..16]);
        out[48..].copy_from_slice(self.s.as_bytes());
        out
    }

    /// Parse a proof. Rejects a non-canonical `Γ`, a non-canonical `s`, or a
    /// challenge with bits set above 128 (the encoding only carries 16 bytes,
    /// so a faithful parse reconstructs `c` from exactly those).
    pub fn from_bytes(bytes: &[u8; PROOF_LEN]) -> Option<Self> {
        let mut g = [0u8; 32];
        g.copy_from_slice(&bytes[..32]);
        let gamma = CompressedRistretto(g).decompress()?;
        let mut c16 = [0u8; 32];
        c16[..16].copy_from_slice(&bytes[32..48]);
        let c = Scalar::from_canonical_bytes(c16).into_option()?;
        let mut s = [0u8; 32];
        s.copy_from_slice(&bytes[48..]);
        let s = Scalar::from_canonical_bytes(s).into_option()?;
        Some(Self { gamma, c, s })
    }
}

/// Derive a keypair deterministically from a 32-byte seed (the holder's secret
/// root). The seed is reduced into the scalar field; `pk = sk·B`.
pub fn keypair_from_seed(seed: &[u8; 32]) -> (SecretKey, PublicKey) {
    // Hash the seed into a uniform scalar so any 32-byte seed is a valid key
    // (rather than requiring a canonical scalar input).
    let mut h = Sha512::new();
    h.update(SUITE);
    h.update([0x00]);
    h.update(seed);
    let wide = h.finalize();
    let mut b = [0u8; 64];
    b.copy_from_slice(&wide);
    let sk = Scalar::from_bytes_mod_order_wide(&b);
    b.zeroize();
    let point = &sk * &RISTRETTO_BASEPOINT_POINT;
    let pk = PublicKey {
        compressed: point.compress(),
        point,
    };
    (SecretKey(sk), pk)
}

/// Hash-to-curve: map `(pk, alpha)` to a Ristretto point via Elligator over a
/// 64-byte SHA-512 expansion. The dominant un-accelerated cost in software.
fn hash_to_curve(pk: &PublicKey, alpha: &[u8]) -> RistrettoPoint {
    let mut h = Sha512::new();
    h.update(SUITE);
    h.update([H2C_DOMAIN]);
    h.update(pk.compressed.as_bytes());
    h.update(alpha);
    let wide = h.finalize();
    let mut b = [0u8; 64];
    b.copy_from_slice(&wide);
    RistrettoPoint::from_uniform_bytes(&b)
}

/// The 128-bit challenge. `prove` and `verify` call this identically, so the
/// proof self-verifies. Low 16 bytes of the transcript hash ⇒ `c < 2^128`.
fn challenge(
    pk: &PublicKey,
    h: &RistrettoPoint,
    gamma: &RistrettoPoint,
    u: &RistrettoPoint,
    v: &RistrettoPoint,
) -> Scalar {
    let mut hh = Sha512::new();
    hh.update(SUITE);
    hh.update([CHALLENGE_DOMAIN]);
    hh.update(pk.compressed.as_bytes());
    hh.update(h.compress().as_bytes());
    hh.update(gamma.compress().as_bytes());
    hh.update(u.compress().as_bytes());
    hh.update(v.compress().as_bytes());
    let wide = hh.finalize();
    let mut c16 = [0u8; 32];
    c16[..16].copy_from_slice(&wide[..16]);
    Scalar::from_bytes_mod_order(c16)
}

/// Deterministic per-proof nonce `k = SHA-512(suite ‖ 0x03 ‖ sk ‖ H) mod L`
/// (no entropy draw — `rand_core` is absent, so determinism is enforced).
fn nonce(sk: &Scalar, h: &RistrettoPoint) -> Scalar {
    let mut hh = Sha512::new();
    hh.update(SUITE);
    hh.update([NONCE_DOMAIN]);
    hh.update(sk.as_bytes());
    hh.update(h.compress().as_bytes());
    let wide = hh.finalize();
    let mut b = [0u8; 64];
    b.copy_from_slice(&wide);
    let k = Scalar::from_bytes_mod_order_wide(&b);
    b.zeroize();
    k
}

/// The VRF output `β = SHA-512(suite ‖ 0x04 ‖ Γ)` for a proof's `Γ`.
fn gamma_output(gamma: &RistrettoPoint) -> [u8; OUTPUT_LEN] {
    let mut hh = Sha512::new();
    hh.update(SUITE);
    hh.update([OUTPUT_DOMAIN]);
    hh.update(gamma.compress().as_bytes());
    let wide = hh.finalize();
    let mut b = [0u8; OUTPUT_LEN];
    b.copy_from_slice(&wide);
    b
}

/// Prove: produce a VRF proof for `alpha` under `sk` (whose public key is `pk`).
/// `Γ = sk·H`, `c = challenge(pk, H, Γ, k·B, k·H)`, `s = k + c·sk`.
pub fn prove(sk: &SecretKey, pk: &PublicKey, alpha: &[u8]) -> Proof {
    let h = hash_to_curve(pk, alpha);
    let gamma = &sk.0 * &h;
    let k = nonce(&sk.0, &h);
    let u = &k * &RISTRETTO_BASEPOINT_POINT; // k·B
    let v = &k * &h; // k·H
    let c = challenge(pk, &h, &gamma, &u, &v);
    let s = k + c * sk.0;
    Proof { gamma, c, s }
}

/// Verify a proof for `alpha` under `pk`. Returns the VRF output `β` iff valid,
/// `None` otherwise. Recomputes `U = s·B − c·pk`, `V = s·H − c·Γ` (point negation
/// done by negating the scalar — free in software) and accepts iff the
/// re-derived challenge matches.
pub fn verify(pk: &PublicKey, alpha: &[u8], proof: &Proof) -> Option<[u8; OUTPUT_LEN]> {
    let h = hash_to_curve(pk, alpha);
    let neg_c = -proof.c;
    let u = &proof.s * &RISTRETTO_BASEPOINT_POINT + &neg_c * &pk.point; // s·B − c·pk
    let v = &proof.s * &h + &neg_c * &proof.gamma; // s·H − c·Γ
    let c2 = challenge(pk, &h, &proof.gamma, &u, &v);
    if c2 == proof.c {
        Some(gamma_output(&proof.gamma))
    } else {
        None
    }
}

/// The VRF output `β` of a proof, independent of verification — callers that
/// have already verified (or only need the value) read it directly.
pub fn output(proof: &Proof) -> [u8; OUTPUT_LEN] {
    gamma_output(&proof.gamma)
}

#[cfg(test)]
mod tests {
    extern crate alloc;
    use super::*;

    const SEED_A: [u8; 32] = [7u8; 32];
    const SEED_B: [u8; 32] = [11u8; 32];
    const ALPHA: &[u8] = b"chronos: blake2b(prev_beacon || epoch)";

    #[test]
    fn prove_verify_round_trip_returns_the_output() {
        let (sk, pk) = keypair_from_seed(&SEED_A);
        let proof = prove(&sk, &pk, ALPHA);
        let beta = verify(&pk, ALPHA, &proof).expect("a valid proof must verify");
        assert_eq!(beta, output(&proof), "verify must return the proof's output");
    }

    #[test]
    fn tampered_proof_is_rejected() {
        let (sk, pk) = keypair_from_seed(&SEED_A);
        let proof = prove(&sk, &pk, ALPHA);
        // Perturb s.
        let bad = Proof {
            s: proof.s + Scalar::ONE,
            ..proof
        };
        assert!(verify(&pk, ALPHA, &bad).is_none(), "tampered s must fail");
        // Perturb gamma (use another point).
        let (sk2, _) = keypair_from_seed(&SEED_B);
        let other_gamma = &sk2.0 * &hash_to_curve(&pk, ALPHA);
        let bad2 = Proof {
            gamma: other_gamma,
            ..proof
        };
        assert!(verify(&pk, ALPHA, &bad2).is_none(), "tampered gamma must fail");
    }

    #[test]
    fn wrong_key_is_rejected() {
        let (sk, pk) = keypair_from_seed(&SEED_A);
        let (_, pk_b) = keypair_from_seed(&SEED_B);
        let proof = prove(&sk, &pk, ALPHA);
        assert!(
            verify(&pk_b, ALPHA, &proof).is_none(),
            "a proof must not verify under the wrong key"
        );
    }

    #[test]
    fn wrong_input_is_rejected() {
        let (sk, pk) = keypair_from_seed(&SEED_A);
        let proof = prove(&sk, &pk, ALPHA);
        assert!(
            verify(&pk, b"a different round", &proof).is_none(),
            "a proof must not verify for a different input"
        );
    }

    #[test]
    fn prove_is_deterministic() {
        let (sk1, pk1) = keypair_from_seed(&SEED_A);
        let (sk2, pk2) = keypair_from_seed(&SEED_A);
        assert_eq!(pk1.to_bytes(), pk2.to_bytes(), "same seed ⇒ same pk");
        let p1 = prove(&sk1, &pk1, ALPHA);
        let p2 = prove(&sk2, &pk2, ALPHA);
        assert_eq!(
            p1.to_bytes(),
            p2.to_bytes(),
            "same (seed, input) ⇒ byte-identical proof"
        );
        assert_eq!(output(&p1), output(&p2), "same (seed, input) ⇒ same output");
    }

    #[test]
    fn distinct_inputs_and_keys_diverge_the_output() {
        let (sk_a, pk_a) = keypair_from_seed(&SEED_A);
        let (sk_b, pk_b) = keypair_from_seed(&SEED_B);
        let beta_a = output(&prove(&sk_a, &pk_a, ALPHA));
        let beta_b = output(&prove(&sk_b, &pk_b, ALPHA));
        let beta_a2 = output(&prove(&sk_a, &pk_a, b"another round"));
        assert_ne!(beta_a, beta_b, "different keys ⇒ different output");
        assert_ne!(beta_a, beta_a2, "different input ⇒ different output");
    }

    #[test]
    fn proof_codec_round_trips_and_still_verifies() {
        let (sk, pk) = keypair_from_seed(&SEED_A);
        let proof = prove(&sk, &pk, ALPHA);
        let bytes = proof.to_bytes();
        assert_eq!(bytes.len(), PROOF_LEN);
        let parsed = Proof::from_bytes(&bytes).expect("a valid proof must parse");
        assert_eq!(bytes, parsed.to_bytes(), "codec must round-trip");
        assert!(
            verify(&pk, ALPHA, &parsed).is_some(),
            "a parsed proof must still verify"
        );
    }

    #[test]
    fn public_key_codec_round_trips() {
        let (_, pk) = keypair_from_seed(&SEED_A);
        let bytes = pk.to_bytes();
        let parsed = PublicKey::from_bytes(&bytes).expect("valid pk must parse");
        assert_eq!(bytes, parsed.to_bytes());
        // A garbage encoding is rejected (not a canonical Ristretto point).
        assert!(PublicKey::from_bytes(&[0xFFu8; 32]).is_none());
    }

    #[test]
    fn committee_xor_combine_is_order_independent() {
        // The chronos combine: XOR the voters' outputs; one honest, unpredictable
        // output randomises the round, and the fold is order-independent.
        let (sk_a, pk_a) = keypair_from_seed(&SEED_A);
        let (sk_b, pk_b) = keypair_from_seed(&SEED_B);
        let a = verify(&pk_a, ALPHA, &prove(&sk_a, &pk_a, ALPHA)).unwrap();
        let b = verify(&pk_b, ALPHA, &prove(&sk_b, &pk_b, ALPHA)).unwrap();
        let mut ab = [0u8; OUTPUT_LEN];
        let mut ba = [0u8; OUTPUT_LEN];
        for i in 0..OUTPUT_LEN {
            ab[i] = a[i] ^ b[i];
            ba[i] = b[i] ^ a[i];
        }
        assert_eq!(ab, ba);
        assert_ne!(ab, a, "the combine must depend on every contribution");
    }
}
