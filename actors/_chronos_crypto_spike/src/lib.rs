//! Phase D feasibility fixture (not a production actor): proves the
//! bias-resistance upgrade's crypto — Ristretto255 group ops + a minimal
//! ECVRF (keygen / prove / verify) + the committee XOR-combine — compiles,
//! transpiles (`link_elf`), and runs correctly for riscv64em-javm in pure
//! no_std software, using only `curve25519-dalek` (serial backend) and SHA-512.
//!
//! If a clean `vosx run` round-trips a VRF proof and rejects a tampered one,
//! the bias-resistant chronos v1 needs **no new precompile for correctness** —
//! the ristretto/scalar precompiles (zkpvm ECALLs 110-114, already defined and
//! cap-installed but un-handled in the vos runtime) become a *performance*
//! follow-on, exactly as the P2 spike showed for the messenger ciphersuite. The
//! dominant un-accelerated cost is hash-to-curve (Elligator); a hash-to-ristretto
//! ECALL can be added if profiling warrants it.
//!
//! Self-consistency only (panic on a wrong result), so a clean run proves
//! correct PVM *execution*, not just linkage. Build:
//! `cd actors/_chronos_crypto_spike && cargo +nightly actor`; run via
//! `vosx run target/riscv64em-javm/release/chronos_crypto_spike.elf`.

use vos::prelude::*;

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use sha2::{Digest, Sha512};

#[actor]
pub struct ChronosCryptoSpike {
    output: Vec<u8>,
}

#[messages]
impl ChronosCryptoSpike {
    pub fn new() -> Self {
        Self {
            output: ecvrf_self_check(),
        }
    }

    #[msg]
    async fn probe(&self) -> Vec<u8> {
        self.output.clone()
    }
}

/// Domain-separation suite tag (an ECVRF-RISTRETTO255-SHA512-style ciphersuite).
const SUITE: &[u8] = b"vos-chronos-ecvrf/ristretto255-sha512/v0";

/// An ECVRF proof: `Gamma (32) ‖ c (16) ‖ s (32)` = 80 bytes on the wire.
struct Proof {
    gamma: RistrettoPoint,
    c: Scalar, // a 128-bit challenge held in a canonical scalar
    s: Scalar,
}

/// Hash-to-curve via the Ristretto Elligator map over a 64-byte SHA-512
/// expansion of `(suite ‖ 0x01 ‖ pk ‖ alpha)`. This is the dominant
/// un-accelerated cost in software (no hash-to-ristretto ECALL yet).
fn hash_to_curve(pk: &CompressedRistretto, alpha: &[u8]) -> RistrettoPoint {
    let mut h = Sha512::new();
    h.update(SUITE);
    h.update([0x01]);
    h.update(pk.as_bytes());
    h.update(alpha);
    let wide = h.finalize();
    let mut b = [0u8; 64];
    b.copy_from_slice(&wide);
    RistrettoPoint::from_uniform_bytes(&b)
}

/// The 128-bit challenge: SHA-512 over the transcript, low 16 bytes folded
/// into a canonical scalar (`c < 2^128`, the RFC 9381 challenge width). prove
/// and verify call this identically, so the proof self-verifies.
fn challenge(
    pk: &CompressedRistretto,
    h: &RistrettoPoint,
    gamma: &RistrettoPoint,
    u: &RistrettoPoint,
    v: &RistrettoPoint,
) -> Scalar {
    let mut hh = Sha512::new();
    hh.update(SUITE);
    hh.update([0x02]);
    hh.update(pk.as_bytes());
    hh.update(h.compress().as_bytes());
    hh.update(gamma.compress().as_bytes());
    hh.update(u.compress().as_bytes());
    hh.update(v.compress().as_bytes());
    let wide = hh.finalize();
    let mut c16 = [0u8; 32];
    c16[..16].copy_from_slice(&wide[..16]);
    Scalar::from_bytes_mod_order(c16)
}

/// Deterministic per-proof nonce (no entropy draw — `rand_core` is absent):
/// `k = SHA-512(0x03 ‖ sk ‖ H) mod L`.
fn nonce(sk: &Scalar, h: &RistrettoPoint) -> Scalar {
    let mut hh = Sha512::new();
    hh.update([0x03]);
    hh.update(sk.as_bytes());
    hh.update(h.compress().as_bytes());
    let wide = hh.finalize();
    let mut b = [0u8; 64];
    b.copy_from_slice(&wide);
    Scalar::from_bytes_mod_order_wide(&b)
}

/// ECVRF prove: `Gamma = sk·H`, `c = challenge(…, k·B, k·H)`, `s = k + c·sk`.
fn prove(sk: &Scalar, pk: &CompressedRistretto, alpha: &[u8]) -> Proof {
    let h = hash_to_curve(pk, alpha);
    let gamma = sk * h;
    let k = nonce(sk, &h);
    let u = &k * RISTRETTO_BASEPOINT_POINT; // k·B
    let v = &k * h; // k·H
    let c = challenge(pk, &h, &gamma, &u, &v);
    let s = k + c * sk;
    Proof { gamma, c, s }
}

/// ECVRF verify: recompute `U = s·B − c·pk`, `V = s·H − c·Gamma`, and accept iff
/// the re-derived challenge matches. The point negation in `−c·pk` is done by
/// negating the scalar (`-c`, free in software — there is no negate ECALL, the
/// precompile path would fold it as `c·(L−1)`).
fn verify(pk_point: &RistrettoPoint, pk: &CompressedRistretto, alpha: &[u8], p: &Proof) -> bool {
    let h = hash_to_curve(pk, alpha);
    let neg_c = -p.c;
    let u = &p.s * RISTRETTO_BASEPOINT_POINT + &neg_c * pk_point; // s·B − c·pk
    let v = &p.s * h + &neg_c * p.gamma; // s·H − c·Gamma
    let c2 = challenge(pk, &h, &p.gamma, &u, &v);
    c2 == p.c
}

/// The VRF output `beta = SHA-512(0x04 ‖ Gamma)` — the verifiable random value
/// a round contributes (folded into the committee combine, never key material).
fn vrf_output(gamma: &RistrettoPoint) -> [u8; 64] {
    let mut hh = Sha512::new();
    hh.update([0x04]);
    hh.update(gamma.compress().as_bytes());
    let wide = hh.finalize();
    let mut b = [0u8; 64];
    b.copy_from_slice(&wide);
    b
}

/// 80-byte wire encoding: `Gamma (32) ‖ c[..16] ‖ s (32)`.
fn encode_proof(p: &Proof) -> Vec<u8> {
    let mut out = Vec::with_capacity(80);
    out.extend_from_slice(p.gamma.compress().as_bytes());
    out.extend_from_slice(&p.c.as_bytes()[..16]);
    out.extend_from_slice(p.s.as_bytes());
    out
}

/// Run the v1 ECVRF + committee-combine on the PVM and assert self-consistency.
/// Returns a digest of the outputs (so nothing is optimised away). Panics on any
/// inconsistency — a clean run means the stack computes correctly.
fn ecvrf_self_check() -> Vec<u8> {
    // Two committee members (raft voters), deterministic keys for the fixture.
    let sk_a = Scalar::from_bytes_mod_order([7u8; 32]);
    let sk_b = Scalar::from_bytes_mod_order([11u8; 32]);
    let pk_a_point = &sk_a * RISTRETTO_BASEPOINT_POINT;
    let pk_b_point = &sk_b * RISTRETTO_BASEPOINT_POINT;
    let pk_a = pk_a_point.compress();
    let pk_b = pk_b_point.compress();

    // The round input both members prove over: H(prev_beacon ‖ epoch) in
    // production; a fixed string here.
    let alpha: &[u8] = b"chronos: prev_beacon || epoch";

    let proof_a = prove(&sk_a, &pk_a, alpha);
    let proof_b = prove(&sk_b, &pk_b, alpha);

    // Each member's proof must verify against its own public key.
    assert!(
        verify(&pk_a_point, &pk_a, alpha, &proof_a),
        "ECVRF: a valid proof must verify (member A)"
    );
    assert!(
        verify(&pk_b_point, &pk_b, alpha, &proof_b),
        "ECVRF: a valid proof must verify (member B)"
    );

    // A tampered response must be rejected.
    let tampered = Proof {
        gamma: proof_a.gamma,
        c: proof_a.c,
        s: proof_a.s + Scalar::ONE,
    };
    assert!(
        !verify(&pk_a_point, &pk_a, alpha, &tampered),
        "ECVRF: a tampered proof must be rejected"
    );

    // A different input must not verify under the same proof.
    assert!(
        !verify(&pk_a_point, &pk_a, b"different round", &proof_a),
        "ECVRF: a proof must not verify for a different input"
    );

    // One member's proof must not verify under another's key.
    assert!(
        !verify(&pk_b_point, &pk_b, alpha, &proof_a),
        "ECVRF: a proof must not verify under the wrong key"
    );

    // Wire encoding is exactly 80 bytes (Gamma 32 + c 16 + s 32).
    let enc_a = encode_proof(&proof_a);
    assert_eq!(enc_a.len(), 80, "ECVRF proof must encode to 80 bytes");

    // Committee combine: XOR the members' VRF outputs into the round's
    // contributed entropy — one honest member randomises the result, killing
    // the leader's grind of the *initial* choice (the v1 bias-resistance step).
    let beta_a = vrf_output(&proof_a.gamma);
    let beta_b = vrf_output(&proof_b.gamma);
    let mut combined = [0u8; 64];
    for i in 0..64 {
        combined[i] = beta_a[i] ^ beta_b[i];
    }
    // XOR is order-independent: B⊕A == A⊕B.
    let mut combined_rev = [0u8; 64];
    for i in 0..64 {
        combined_rev[i] = beta_b[i] ^ beta_a[i];
    }
    assert!(
        combined == combined_rev,
        "committee XOR-combine must be order-independent"
    );

    // Fold everything into one digest so nothing is dead-code-eliminated.
    let mut acc = Sha512::new();
    acc.update(enc_a);
    acc.update(encode_proof(&proof_b));
    acc.update(combined);
    acc.finalize()[..32].to_vec()
}
