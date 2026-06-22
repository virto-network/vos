//! P2 feasibility fixture (not a production actor): proves ciphersuite-1's
//! crypto stack compiles + transpiles + runs correctly for riscv64em-javm in
//! pure no_std software, so the PVM-native messenger port (P2) needs no new
//! precompile for correctness. Exercises SHA-256, HKDF, X25519, Ed25519
//! sign/verify, AES-128-GCM with self-consistency checks (panic on a wrong
//! result), so a clean `vosx run` proves correct runtime execution on the PVM,
//! not just linkage.
//!
//! P2.0 (see docs/design/messaging-pvm-native.md) extends this with:
//!   - parametric `#[msg]` test-vector handlers (`sha256`/`hkdf`/`x25519`/
//!     `ed25519`/`aes`) that take an input and return the raw primitive output,
//!     so a host test can assert the PVM-computed bytes are bit-exact against
//!     host RustCrypto over the same inputs (correct *execution*, not just
//!     linkage); and
//!   - a self-scheduling `warm_rounds` handler that re-runs the whole crypto
//!     stack across `new_warm` re-entries (the recorded JAVM warm-restart bug
//!     surface) and asserts every round reproduces round 0 bit-for-bit, so the
//!     gate covers "clean across a warm restart".
//!
//! Build: `cd actors/_crypto_spike && cargo +nightly actor`.

use vos::prelude::*;

use sha2::{Digest, Sha256};

/// Fixed test-vector constants. The host P2.0 test (`vos/tests/crypto_spike_pvm.rs`)
/// MUST mirror these byte-for-byte to reproduce the expected outputs.
///
/// HKDF salt + info (the `hkdf` handler pins these; the input is the IKM).
pub const HKDF_SALT: &[u8] = b"vos-p2.0/hkdf-salt";
pub const HKDF_INFO: &[u8] = b"vos-p2.0/hkdf-info";
/// X25519 counterparty secret. The `x25519` handler derives the peer public
/// from this and returns DH(input_secret, peer_public).
pub const X25519_PEER_SK: [u8; 32] = [9u8; 32];
/// Number of warm-restart rounds the `warm_rounds` handler drives (round 0 is
/// the cold/restored entry; rounds 1.. are `new_warm` re-entries).
pub const WARM_ROUNDS: u32 = 4;
/// Number of BOOT_CONTEXT observations `boot_collect` gathers, one per
/// (re)instantiation (round 0 cold/restored; rounds 1.. are warm restarts).
pub const BOOT_ROUNDS: u32 = 4;
/// BOOT_CONTEXT wire layout: `boot_token(32) ‖ device_id(32) ‖ boot_epoch(u64)`.
pub const BOOT_CONTEXT_LEN: usize = 72;

#[actor]
pub struct CryptoSpike {
    /// The cold-start self-check digest (see [`crypto_self_check`]).
    digest: Vec<u8>,
    /// Warm-restart progress: rounds completed by `warm_rounds`.
    warm_round: u32,
    /// Round-0 self-check digest, retained across warm restarts to detect
    /// heap/branch corruption on a `new_warm` re-entry.
    warm_baseline: Vec<u8>,
    /// Order-dependent fold of every round's self-check digest. The host
    /// reproduces this chain to confirm every warm round executed correctly.
    warm_acc: Vec<u8>,
    /// BOOT_CONTEXT observations, one 72-byte record per (re)instantiation.
    boot_obs: Vec<Vec<u8>>,
}

#[messages]
impl CryptoSpike {
    pub fn new() -> Self {
        Self {
            digest: crypto_self_check(),
            warm_round: 0,
            warm_baseline: Vec::new(),
            warm_acc: Vec::new(),
            boot_obs: Vec::new(),
        }
    }

    /// The cold-start self-check digest (also the per-round digest the
    /// `warm_rounds` fold consumes). Lets the host reproduce the warm chain.
    #[msg]
    async fn probe(&self) -> Vec<u8> {
        self.digest.clone()
    }

    // ── Parametric test-vector handlers (bit-exact vs host RustCrypto) ──
    //
    // Wire names carry a `tv_` prefix because the `#[msg]` macro mints a
    // PascalCase message struct per handler (`tv_sha256` → `TvSha256`); an
    // un-prefixed `sha256` would mint `Sha256` and collide with `sha2::Sha256`.

    /// SHA-256 of the input.
    #[msg]
    async fn tv_sha256(&self, input: Vec<u8>) -> Vec<u8> {
        Sha256::digest(&input).to_vec()
    }

    /// HKDF-SHA256 with the input as IKM and the pinned salt/info, expanded to
    /// 64 bytes (two HMAC blocks, exercising the expand counter).
    #[msg]
    async fn tv_hkdf(&self, input: Vec<u8>) -> Vec<u8> {
        let hk = hkdf::Hkdf::<Sha256>::new(Some(HKDF_SALT), &input);
        let mut okm = [0u8; 64];
        hk.expand(HKDF_INFO, &mut okm).expect("hkdf expand 64 bytes");
        okm.to_vec()
    }

    /// X25519 Diffie-Hellman: DH(input_secret, peer_public), where the peer
    /// public is derived from the pinned [`X25519_PEER_SK`]. Input must be 32
    /// bytes (the local secret scalar; clamped internally by x25519-dalek).
    #[msg]
    async fn tv_x25519(&self, input: Vec<u8>) -> Vec<u8> {
        if input.len() != 32 {
            return Vec::new();
        }
        let mut sk = [0u8; 32];
        sk.copy_from_slice(&input);
        let local = x25519_dalek::StaticSecret::from(sk);
        let peer_pub =
            x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(X25519_PEER_SK));
        local.diffie_hellman(&peer_pub).as_bytes().to_vec()
    }

    /// Ed25519 signature. Input is `seed(32) ‖ message`; returns the 64-byte
    /// detached signature. Also verifies the signature in-PVM (panics on a
    /// failed round-trip) so a clean reply proves sign+verify both execute.
    #[msg]
    async fn tv_ed25519(&self, input: Vec<u8>) -> Vec<u8> {
        use ed25519_dalek::{Signer, Verifier};
        if input.len() < 32 {
            return Vec::new();
        }
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&input[..32]);
        let msg = &input[32..];
        let signing = ed25519_dalek::SigningKey::from_bytes(&seed);
        let sig = signing.sign(msg);
        let vk = signing.verifying_key();
        assert!(vk.verify(msg, &sig).is_ok(), "ed25519 self-verify failed");
        sig.to_bytes().to_vec()
    }

    /// AES-128-GCM seal. Input is `key(16) ‖ nonce(12) ‖ plaintext`; returns the
    /// ciphertext with the appended 16-byte tag. Also opens it in-PVM (panics on
    /// a failed round-trip) so a clean reply proves seal+open both execute.
    #[msg]
    async fn tv_aes(&self, input: Vec<u8>) -> Vec<u8> {
        use aes_gcm::aead::generic_array::GenericArray;
        use aes_gcm::aead::{Aead, KeyInit};
        if input.len() < 28 {
            return Vec::new();
        }
        let cipher = aes_gcm::Aes128Gcm::new(GenericArray::from_slice(&input[..16]));
        let nonce = GenericArray::from_slice(&input[16..28]);
        let pt = &input[28..];
        let ct = cipher.encrypt(nonce, pt).expect("aes-gcm seal");
        let back = cipher.decrypt(nonce, ct.as_ref()).expect("aes-gcm open");
        assert!(back == pt, "aes-gcm round-trip mismatch");
        ct
    }

    // ── Warm-restart gate ──

    /// Re-run the whole ciphersuite-1 self-check, fold its digest into an
    /// order-dependent accumulator, and self-schedule the next round until
    /// [`WARM_ROUNDS`] rounds have run. Round 0 is the cold/restored entry;
    /// rounds 1.. are `new_warm` re-entries (the JAVM warm-restart path). Every
    /// round must reproduce round 0's digest bit-for-bit — a divergence means
    /// the warm restart corrupted heap/branch execution, and the in-handler
    /// assert turns that into a guest panic the host test observes.
    #[msg]
    async fn warm_rounds(&mut self, ctx: &mut Context<Self>) {
        let d = crypto_self_check();
        if self.warm_round == 0 {
            self.warm_baseline = d.clone();
            self.warm_acc = vec![0u8; 32];
        } else {
            assert!(
                d == self.warm_baseline,
                "crypto diverged after a warm restart"
            );
        }
        // Order-dependent fold: acc' = SHA-256(acc ‖ digest).
        let mut h = Sha256::new();
        h.update(&self.warm_acc);
        h.update(&d);
        self.warm_acc = h.finalize().to_vec();
        self.warm_round += 1;

        if self.warm_round < WARM_ROUNDS {
            ctx.tell(ctx.id(), &Msg::new("warm_rounds"));
        }
    }

    /// Rounds completed so far — the host asserts this reaches [`WARM_ROUNDS`],
    /// proving the warm re-entries actually executed.
    #[msg]
    async fn warm_count(&self) -> u32 {
        self.warm_round
    }

    /// The warm-restart fold accumulator — the host reproduces the chain from
    /// `probe`'s digest and asserts equality.
    #[msg]
    async fn warm_result(&self) -> Vec<u8> {
        self.warm_acc.clone()
    }

    // ── BOOT_CONTEXT seam gate (P2.1) ──

    /// Read a fresh BOOT_CONTEXT each round and self-schedule until
    /// [`BOOT_ROUNDS`] records are gathered. Round 0 is the cold/restored
    /// entry; rounds 1.. are `new_warm` re-entries — the host mints a fresh
    /// `boot_token` + advances `boot_epoch` on every one, which `boot_report`
    /// lets the host verify (distinct tokens, monotonic epochs, stable device).
    #[msg]
    async fn boot_collect(&mut self, ctx: &mut Context<Self>) {
        let mut buf = [0u8; BOOT_CONTEXT_LEN];
        #[cfg(target_arch = "riscv64")]
        {
            let n = vos::hostcalls::boot_context(&mut buf) as usize;
            assert!(
                n == BOOT_CONTEXT_LEN,
                "boot_context returned the wrong length"
            );
        }
        // On host/wasm builds the ecall is unavailable; only the riscv64 ELF is
        // ever run, but the handler must still type-check for every flavor.
        self.boot_obs.push(buf.to_vec());

        if (self.boot_obs.len() as u32) < BOOT_ROUNDS {
            ctx.tell(ctx.id(), &Msg::new("boot_collect"));
        }
    }

    /// The concatenated BOOT_CONTEXT records (`BOOT_ROUNDS × 72` bytes).
    #[msg]
    async fn boot_report(&self) -> Vec<u8> {
        self.boot_obs.concat()
    }
}

/// Run every ciphersuite-1 primitive on the PVM and assert self-consistency.
/// Returns a digest of the outputs (so nothing is optimised away). Panics on
/// any inconsistency — a clean run means the stack computes correctly.
fn crypto_self_check() -> Vec<u8> {
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
