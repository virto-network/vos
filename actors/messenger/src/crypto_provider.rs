//! Deterministic mls-rs crypto provider: every entropy draw routed through the
//! host-seeded [`HostRand`] CSPRNG instead of `OsRng`.
//!
//! mls-rs takes randomness through its `CipherSuiteProvider`, but the stock
//! `RustCryptoProvider` draws `OsRng` *inside* `kem_generate` and the HPKE
//! ephemeral (`hpke_seal`/`hpke_setup_s`) — not via `random_bytes` — so a
//! deterministic provider can't just override `random_bytes`. The injection
//! seam is the `DhType::generate()` trait method: `DhKem::encap` (the HPKE
//! ephemeral) and `kem_generate` both route through it. So
//! [`DeterministicEcdh`] wraps the stock `Ecdh`, overriding `generate` to draw
//! the X25519 keypair from `HostRand`, and delegates the rest. The whole
//! provider then delegates every `CipherSuiteProvider` method to an inner
//! `RustCryptoCipherSuite` built over that KEM, overriding only `random_bytes`
//! (the one generic entropy hook).
//!
//! `signature_key_generate` still draws `OsRng`, but it is off the messenger's
//! path: the signing identity is built from the seed-derived signer
//! (`mls::derive_signer`) and handed to the Client, so mls-rs never generates a
//! signature key during create/commit/keypackage/welcome.
//!
//! Result: two providers from the same `(seed, boot context)` emit bit-identical
//! KeyPackages, commits, and Welcomes across restarts and re-dispatches — no
//! OS-entropy divergence, the reproducibility the messenger relies on.

use alloc::vec;
use alloc::vec::Vec;

// `Send + Sync` sharing of the (`!Sync`) HostRand across the Client's provider
// clones, mirroring mls-rs's own storage providers: a `spin::Mutex` (never
// contended in the single-threaded dispatch model) over an `Arc`. The host
// build uses `alloc::sync::Arc`; the no-atomics PVM target uses
// `portable_atomic_util::Arc`.
#[cfg(not(target_arch = "riscv64"))]
use alloc::sync::Arc;
#[cfg(target_arch = "riscv64")]
use portable_atomic_util::Arc;
use spin::Mutex;

use mls_rs_core::crypto::{
    CipherSuite, CipherSuiteProvider, CryptoProvider, HpkeCiphertext, HpkePublicKey, HpkeSecretKey,
    SignaturePublicKey, SignatureSecretKey,
};
use mls_rs_core::crypto::HpkePsk;
use mls_rs_crypto_hpke::dhkem::DhKem;
use mls_rs_crypto_rustcrypto::RustCryptoCipherSuite;
use mls_rs_crypto_rustcrypto::aead::Aead;
use mls_rs_crypto_rustcrypto::ecdh::Ecdh;
use mls_rs_crypto_rustcrypto::kdf::Kdf;
use mls_rs_crypto_traits::{DhType, KemId, SamplingMethod};
use zeroize::Zeroizing;

use crate::host_rand::HostRand;
use crate::mls::CIPHERSUITE;

/// A `HostRand` shared (and `Send + Sync`) across the Client's provider clones,
/// so every entropy draw within one boot advances the same ratchet in order.
pub(crate) type SharedRand = Arc<Mutex<HostRand>>;

fn draw<const N: usize>(rand: &SharedRand) -> [u8; N] {
    let mut out = [0u8; N];
    rand.lock()
        .draw_into(&mut out)
        .expect("host CSPRNG draw within MLS sizes never exceeds the HKDF ceiling");
    out
}

/// X25519 ECDH whose ephemeral/static keypair generation draws from `HostRand`
/// rather than `OsRng`. All other DH operations delegate to the stock `Ecdh`.
#[derive(Clone)]
pub(crate) struct DeterministicEcdh {
    inner: Ecdh,
    rand: SharedRand,
}

impl DhType for DeterministicEcdh {
    type Error = <Ecdh as DhType>::Error;

    fn generate(&self) -> Result<(HpkeSecretKey, HpkePublicKey), Self::Error> {
        // Draw the 32-byte X25519 secret from the CSPRNG; the stored secret is
        // the raw drawn bytes (matching the stock provider, whose `dh` does
        // `StaticSecret::from(bytes)`), so the inner `dh`/`to_public` round-trip
        // it consistently.
        let sk = draw::<32>(&self.rand);
        let public = x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(sk));
        Ok((
            HpkeSecretKey::from(sk.to_vec()),
            HpkePublicKey::from(public.to_bytes().to_vec()),
        ))
    }

    fn dh(
        &self,
        secret_key: &HpkeSecretKey,
        public_key: &HpkePublicKey,
    ) -> Result<Vec<u8>, Self::Error> {
        self.inner.dh(secret_key, public_key)
    }

    fn to_public(&self, secret_key: &HpkeSecretKey) -> Result<HpkePublicKey, Self::Error> {
        self.inner.to_public(secret_key)
    }

    fn bitmask_for_rejection_sampling(&self) -> SamplingMethod {
        self.inner.bitmask_for_rejection_sampling()
    }

    fn secret_key_size(&self) -> usize {
        self.inner.secret_key_size()
    }

    fn public_key_size(&self) -> usize {
        self.inner.public_key_size()
    }

    fn public_key_validate(&self, key: &HpkePublicKey) -> Result<(), Self::Error> {
        self.inner.public_key_validate(key)
    }
}

/// The inner cipher-suite provider, identical to the stock one except its KEM
/// uses [`DeterministicEcdh`].
type Inner = RustCryptoCipherSuite<DhKem<DeterministicEcdh, Kdf>, Kdf, Aead>;

/// `CipherSuiteProvider` delegating every operation to [`Inner`] (whose KEM +
/// HPKE ephemeral are already deterministic via [`DeterministicEcdh`]),
/// overriding only `random_bytes` to draw from `HostRand`.
#[derive(Clone)]
pub(crate) struct VosCipherSuiteProvider {
    inner: Inner,
    rand: SharedRand,
}

impl CipherSuiteProvider for VosCipherSuiteProvider {
    type Error = <Inner as CipherSuiteProvider>::Error;
    type HpkeContextS = <Inner as CipherSuiteProvider>::HpkeContextS;
    type HpkeContextR = <Inner as CipherSuiteProvider>::HpkeContextR;

    fn cipher_suite(&self) -> CipherSuite {
        self.inner.cipher_suite()
    }

    fn hash(&self, data: &[u8]) -> Result<Vec<u8>, Self::Error> {
        self.inner.hash(data)
    }

    fn mac(&self, key: &[u8], data: &[u8]) -> Result<Vec<u8>, Self::Error> {
        self.inner.mac(key, data)
    }

    fn aead_seal(
        &self,
        key: &[u8],
        data: &[u8],
        aad: Option<&[u8]>,
        nonce: &[u8],
    ) -> Result<Vec<u8>, Self::Error> {
        self.inner.aead_seal(key, data, aad, nonce)
    }

    fn aead_open(
        &self,
        key: &[u8],
        ciphertext: &[u8],
        aad: Option<&[u8]>,
        nonce: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, Self::Error> {
        self.inner.aead_open(key, ciphertext, aad, nonce)
    }

    fn aead_key_size(&self) -> usize {
        self.inner.aead_key_size()
    }

    fn aead_nonce_size(&self) -> usize {
        self.inner.aead_nonce_size()
    }

    fn kdf_extract(&self, salt: &[u8], ikm: &[u8]) -> Result<Zeroizing<Vec<u8>>, Self::Error> {
        self.inner.kdf_extract(salt, ikm)
    }

    fn kdf_expand(
        &self,
        prk: &[u8],
        info: &[u8],
        len: usize,
    ) -> Result<Zeroizing<Vec<u8>>, Self::Error> {
        self.inner.kdf_expand(prk, info, len)
    }

    fn kdf_extract_size(&self) -> usize {
        self.inner.kdf_extract_size()
    }

    fn hpke_seal(
        &self,
        remote_key: &HpkePublicKey,
        info: &[u8],
        aad: Option<&[u8]>,
        pt: &[u8],
    ) -> Result<HpkeCiphertext, Self::Error> {
        self.inner.hpke_seal(remote_key, info, aad, pt)
    }

    fn hpke_seal_psk(
        &self,
        remote_key: &HpkePublicKey,
        info: &[u8],
        aad: Option<&[u8]>,
        pt: &[u8],
        psk: HpkePsk<'_>,
    ) -> Result<HpkeCiphertext, Self::Error> {
        self.inner.hpke_seal_psk(remote_key, info, aad, pt, psk)
    }

    fn hpke_open(
        &self,
        ciphertext: &HpkeCiphertext,
        local_secret: &HpkeSecretKey,
        local_public: &HpkePublicKey,
        info: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Zeroizing<Vec<u8>>, Self::Error> {
        self.inner
            .hpke_open(ciphertext, local_secret, local_public, info, aad)
    }

    fn hpke_open_psk(
        &self,
        ciphertext: &HpkeCiphertext,
        local_secret: &HpkeSecretKey,
        local_public: &HpkePublicKey,
        info: &[u8],
        aad: Option<&[u8]>,
        psk: HpkePsk<'_>,
    ) -> Result<Zeroizing<Vec<u8>>, Self::Error> {
        self.inner
            .hpke_open_psk(ciphertext, local_secret, local_public, info, aad, psk)
    }

    fn hpke_setup_s(
        &self,
        remote_key: &HpkePublicKey,
        info: &[u8],
    ) -> Result<(Vec<u8>, Self::HpkeContextS), Self::Error> {
        self.inner.hpke_setup_s(remote_key, info)
    }

    fn hpke_setup_r(
        &self,
        kem_output: &[u8],
        local_secret: &HpkeSecretKey,
        local_public: &HpkePublicKey,
        info: &[u8],
    ) -> Result<Self::HpkeContextR, Self::Error> {
        self.inner
            .hpke_setup_r(kem_output, local_secret, local_public, info)
    }

    fn kem_derive(&self, ikm: &[u8]) -> Result<(HpkeSecretKey, HpkePublicKey), Self::Error> {
        self.inner.kem_derive(ikm)
    }

    fn kem_generate(&self) -> Result<(HpkeSecretKey, HpkePublicKey), Self::Error> {
        self.inner.kem_generate()
    }

    fn kem_public_key_validate(&self, key: &HpkePublicKey) -> Result<(), Self::Error> {
        self.inner.kem_public_key_validate(key)
    }

    fn random_bytes(&self, out: &mut [u8]) -> Result<(), Self::Error> {
        self.rand
            .lock()
            .draw_into(out)
            .expect("host CSPRNG draw within MLS sizes never exceeds the HKDF ceiling");
        Ok(())
    }

    fn signature_key_generate(
        &self,
    ) -> Result<(SignatureSecretKey, SignaturePublicKey), Self::Error> {
        // Off the messenger's path: the signing identity is the seed-derived
        // signer handed to the Client (`mls::derive_signer`), so mls-rs never
        // reaches this during create / commit / keypackage / welcome. The stock
        // path draws `OsRng`, which on the PVM target hits the no-entropy shim
        // and traps — an obscure failure for a call that "can't happen." Route
        // it through `HostRand` instead: a well-formed, deterministic Ed25519
        // keypair in the same 64-byte (seed‖public) `SignatureSecretKey`
        // encoding `derive_signer` produces — never a trap, even if some future
        // mls-rs path does reach it.
        let seed = draw::<32>(&self.rand);
        let signing = ed25519_dalek::SigningKey::from_bytes(&seed);
        let public = signing.verifying_key().to_bytes().to_vec();
        let keypair = signing.to_keypair_bytes().to_vec();
        Ok((
            SignatureSecretKey::from(keypair),
            SignaturePublicKey::from(public),
        ))
    }

    fn signature_key_derive_public(
        &self,
        secret_key: &SignatureSecretKey,
    ) -> Result<SignaturePublicKey, Self::Error> {
        self.inner.signature_key_derive_public(secret_key)
    }

    fn sign(&self, secret_key: &SignatureSecretKey, data: &[u8]) -> Result<Vec<u8>, Self::Error> {
        self.inner.sign(secret_key, data)
    }

    fn verify(
        &self,
        public_key: &SignaturePublicKey,
        signature: &[u8],
        data: &[u8],
    ) -> Result<(), Self::Error> {
        self.inner.verify(public_key, signature, data)
    }
}

/// `CryptoProvider` yielding [`VosCipherSuiteProvider`] over a shared `HostRand`.
#[derive(Clone)]
pub(crate) struct VosCryptoProvider {
    rand: SharedRand,
}

impl VosCryptoProvider {
    pub(crate) fn new(rand: HostRand) -> Self {
        VosCryptoProvider {
            rand: Arc::new(Mutex::new(rand)),
        }
    }
}

impl CryptoProvider for VosCryptoProvider {
    type CipherSuiteProvider = VosCipherSuiteProvider;

    fn supported_cipher_suites(&self) -> Vec<CipherSuite> {
        vec![CIPHERSUITE]
    }

    fn cipher_suite_provider(&self, cipher_suite: CipherSuite) -> Option<VosCipherSuiteProvider> {
        if cipher_suite != CIPHERSUITE {
            return None;
        }
        let kdf = Kdf::new(cipher_suite)?;
        let ecdh = Ecdh::new(cipher_suite)?;
        let det = DeterministicEcdh {
            inner: ecdh,
            rand: self.rand.clone(),
        };
        let kem_id = KemId::new(cipher_suite)?;
        let kem = DhKem::new(det, kdf, kem_id as u16, kem_id.n_secret());
        let aead = Aead::new(cipher_suite)?;
        let inner = RustCryptoCipherSuite::new(cipher_suite, kem, kdf, aead)?;
        Some(VosCipherSuiteProvider {
            inner,
            rand: self.rand.clone(),
        })
    }
}
