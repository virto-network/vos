//! P2.0b feasibility fixture (not a production actor): answers the make-or-break
//! open question behind the OpenMLS -> mls-rs library decision —
//! **does mls-rs's own framing/codec/TreeKEM code compile to a riscv64em-javm
//! ELF and transpile through `grey_transpiler::link_elf`?**
//!
//! It drives a MINIMAL mls-rs flow with ciphersuite 1
//! (CURVE25519_AES128 = MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519):
//!   - build two `Client`s (alice, bob) over the RustCrypto provider,
//!   - alice `create_group`,
//!   - bob `generate_key_package_message`,
//!   - alice `commit_builder().add_member(bob_kp).build()` (one commit),
//!   - alice `apply_pending_commit`,
//! and asserts the commit produced a welcome message — exercising mls-rs's
//! RFC-9420 codec (MlsMessage encode/decode), KeyPackage, and TreeKEM commit
//! path. Pure no_std / alloc-only (default features off => std + rayon dropped).
//!
//! Entropy: `os = "none"` has no OS RNG, so we register a DETERMINISTIC
//! getrandom backend (spike-only — proves linkage/codec, NOT secure key gen).
//!
//! Build: `cd actors/_mls_spike && cargo +nightly actor`.

use vos::prelude::*;

use mls_rs::client_builder::MlsConfig;
use mls_rs::identity::basic::{BasicCredential, BasicIdentityProvider};
use mls_rs::identity::SigningIdentity;
use mls_rs::{
    CipherSuite, CipherSuiteProvider, Client, CryptoProvider, ExtensionList,
};
use mls_rs_crypto_rustcrypto::RustCryptoProvider;

const CIPHERSUITE: CipherSuite = CipherSuite::CURVE25519_AES128;

// ── Deterministic getrandom backend (spike-only) ──
//
// `os = "none"` is an "unsupported target" for getrandom 0.2, so without a
// registered backend every entropy draw is a link error. We register a counter
// LCG: enough for create-group + commit to *run*, not for real security. The
// real port (P2.3) routes entropy through a deterministic CipherSuiteProvider.
fn spike_getrandom(buf: &mut [u8]) -> core::result::Result<(), getrandom::Error> {
    // The +e target has max-atomic-width 0 (no AtomicU64), and the runtime is
    // singlethread => a plain `static mut` LCG is sound here. (The real port
    // routes entropy through HostRand, never a static.)
    static mut STATE: u64 = 0x9E3779B97F4A7C15;
    // SAFETY: singlethread target; no concurrent access.
    let mut x = unsafe { STATE };
    for b in buf.iter_mut() {
        // splitmix64 step
        x = x.wrapping_add(0x9E3779B97F4A7C15);
        let mut z = x;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
        z ^= z >> 31;
        *b = z as u8;
    }
    // SAFETY: singlethread target; no concurrent access.
    unsafe {
        STATE = x;
    }
    Ok(())
}
getrandom::register_custom_getrandom!(spike_getrandom);

// ── critical-section no-op backend (spike-only) ──
//
// mls-rs's in-memory storage uses a `spin::Mutex` built on `portable-atomic`,
// which on a no-native-atomics target routes through `critical-section`. The
// PVM is singlethread with no interrupts/preemption, so acquire/release are
// no-ops. (The real port replaces the in-memory storage with an alloc BTreeMap
// GroupStateStorage — see P2.2 — and won't need this.)
struct SingleThreadCs;
critical_section::set_impl!(SingleThreadCs);
unsafe impl critical_section::Impl for SingleThreadCs {
    unsafe fn acquire() -> critical_section::RawRestoreState {}
    unsafe fn release(_: critical_section::RawRestoreState) {}
}

#[actor]
pub struct MlsSpike {
    /// Length of the RFC-9420 welcome `MlsMessage` produced by the add-member
    /// commit — a non-zero value proves the codec + TreeKEM path ran.
    welcome_len: u32,
    /// Length of the encoded commit `MlsMessage` — proves framing encode ran.
    commit_len: u32,
}

#[messages]
impl MlsSpike {
    pub fn new() -> Self {
        let (welcome_len, commit_len) = mls_self_check();
        Self {
            welcome_len,
            commit_len,
        }
    }

    /// Welcome-message length, so a clean `vosx run` reply proves the mls-rs
    /// create-group + add-member-commit flow executed inside the PVM.
    #[msg]
    async fn welcome_len(&self) -> u32 {
        self.welcome_len
    }

    /// Encoded-commit length (RFC-9420 framing).
    #[msg]
    async fn commit_len(&self) -> u32 {
        self.commit_len
    }
}

/// Build a ciphersuite-1 mls-rs `Client` with a basic credential.
fn make_client(crypto: RustCryptoProvider, name: &[u8]) -> Client<impl MlsConfig> {
    let cs = crypto
        .cipher_suite_provider(CIPHERSUITE)
        .expect("ciphersuite 1 provider");
    let (secret, public) = cs.signature_key_generate().expect("sig keygen");
    let cred = BasicCredential::new(name.to_vec());
    let signing_identity = SigningIdentity::new(cred.into_credential(), public);
    Client::builder()
        .identity_provider(BasicIdentityProvider)
        .crypto_provider(crypto)
        .signing_identity(signing_identity, secret, CIPHERSUITE)
        .build()
}

/// Run a minimal mls-rs create-group + add-member-commit and return
/// (welcome_len, commit_len). Panics on any inconsistency.
fn mls_self_check() -> (u32, u32) {
    let crypto = RustCryptoProvider::default();

    let alice = make_client(crypto.clone(), b"alice");
    let bob = make_client(crypto, b"bob");

    // Alice creates a group (default ratchet-tree ext config).
    let mut alice_group = alice
        .create_group(ExtensionList::default(), Default::default(), None)
        .expect("create_group");

    // Bob's key package (RFC-9420 KeyPackage encode).
    let bob_kp = bob
        .generate_key_package_message(Default::default(), Default::default(), None)
        .expect("generate_key_package_message");

    // Alice commits adding Bob — exercises TreeKEM + commit framing.
    let commit = alice_group
        .commit_builder()
        .add_member(bob_kp)
        .expect("add_member proposal")
        .build()
        .expect("commit build");

    alice_group.apply_pending_commit().expect("apply commit");

    // The add-member commit must carry exactly one welcome message.
    assert_eq!(
        commit.welcome_messages.len(),
        1,
        "add-member commit produced no welcome"
    );
    let welcome_len = mls_msg_len(&commit.welcome_messages[0]);
    let commit_len = mls_msg_len(&commit.commit_message);
    assert!(welcome_len > 0, "empty welcome message");
    assert!(commit_len > 0, "empty commit message");

    (welcome_len, commit_len)
}

/// Encode an `MlsMessage` to RFC-9420 wire bytes and return its length (also
/// round-trips encode -> decode to exercise the codec both ways).
fn mls_msg_len(msg: &mls_rs::MlsMessage) -> u32 {
    use mls_rs::MlsMessage;
    let bytes = msg.to_bytes().expect("MlsMessage encode");
    let decoded = MlsMessage::from_bytes(&bytes).expect("MlsMessage decode");
    let re = decoded.to_bytes().expect("MlsMessage re-encode");
    assert!(re == bytes, "MlsMessage codec round-trip mismatch");
    bytes.len() as u32
}
