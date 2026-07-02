//! MLS plumbing on mls-rs: client construction, identity, group helpers.
//!
//! mls-rs is Client-centric: a [`Client`] is built once per dispatch over the
//! restored [`store::VosStores`] (group-state + key-package storage), the
//! crypto provider, and a signing identity, then group lifecycle runs against
//! `Client`/`Group`. Unlike OpenMLS there is no per-call provider argument and
//! group mutations are not auto-persisted — callers must
//! `Group::write_to_storage()` before snapshotting the stores back into the
//! messenger's node-local state.
//!
//! The signer is derived deterministically from the node-local CSPRNG seed
//! (HKDF → Ed25519), so it is reproducible from the seed alone and never drawn
//! from OS entropy. Every other entropy draw mls-rs makes (KEM/HPKE/key-package
//! secrets) is routed through that same host-seeded CSPRNG by the custom
//! [`crate::crypto_provider::VosCryptoProvider`] installed on every `Client`, so
//! the whole client is deterministic in its `(seed, boot context)` — the
//! reproducibility the device-local actor relies on across restarts.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use mls_rs::client_builder::{MlsConfig, PaddingMode};
use mls_rs::group::Group;
use mls_rs::identity::SigningIdentity;
use mls_rs::mls_rules::{CommitOptions, DefaultMlsRules, EncryptionOptions};
use mls_rs::time::MlsTime;
use mls_rs::{CipherSuite, Client, ExtensionList, MlsMessage};
use mls_rs_core::crypto::{SignaturePublicKey, SignatureSecretKey};

use crate::crypto_provider::VosCryptoProvider;
use crate::host_rand::{HostRand, PublicBeacon};
use crate::store::{self, VosStores};

/// The one ciphersuite VOS messaging speaks (per docs/encryption.md):
/// `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` (== OpenMLS ciphersuite 1).
pub(crate) const CIPHERSUITE: CipherSuite = CipherSuite::CURVE25519_AES128;

/// Domain tag for deriving a channel's MLS GroupId from its name, so every
/// member computes the same id without coordination.
pub(crate) const GROUP_ID_DOMAIN_TAG: &[u8] = b"vos-msg-group/v1";

/// HKDF label deriving the Ed25519 signer seed from the CSPRNG root — domain
/// separated from the rest of the stream so the signer is reproducible without
/// exposing or being entangled with other draws.
const SIGNER_LABEL: &[u8] = b"vos-msg/mls-signer/v1";

/// Retain decryption keys for this many epochs behind the group's current one.
/// In mls-rs this is enforced by the storage layer's trim-on-write (there is no
/// client/group config knob), so it is the retention passed to [`store`].
pub(crate) const MAX_PAST_EPOCHS: usize = 64;

pub(crate) fn group_id_for(channel: &str) -> [u8; 32] {
    vos::crypto::blake2b_hash(GROUP_ID_DOMAIN_TAG, &[channel.as_bytes()])
}

/// 32 random bytes for a dynamically installed channel agent's replication id.
/// Random rather than name-derived so the sync group / gossip topic isn't
/// guessable from the channel name; members learn it from the registry's
/// replicated `AgentRow`. Not key material — host OS entropy is fine.
pub(crate) fn fresh_replication_id() -> Result<[u8; 32], String> {
    random_32()
}

/// 32 random bytes for a Commit row's Welcome routing token. Must NOT be
/// derivable from the joiner's public KeyPackage (a deterministic hash would
/// equal the directory's `kp_hash` and let a holder of both map the token back
/// to a nickname). A fresh random token leaks nothing; the joiner recognises
/// its own Welcome by trial-decryption. Not key material.
pub(crate) fn welcome_nonce() -> Result<[u8; 32], String> {
    random_32()
}

/// 32 non-key-material bytes, fresh per call. On the host this is OS entropy.
#[cfg(not(target_arch = "riscv64"))]
fn random_32() -> Result<[u8; 32], String> {
    let mut out = [0u8; 32];
    getrandom::getrandom(&mut out).map_err(|e| format!("OS entropy unavailable: {e}"))?;
    Ok(out)
}

/// A PVM actor has no OS entropy. These two callers ([`fresh_replication_id`],
/// [`welcome_nonce`]) need bytes that are *fresh per call* but NOT secret (a
/// replication id and a Welcome routing token — see their docs). Derive them
/// from the host-minted per-boot token (the BOOT_CONTEXT seam — fresh on every
/// refine entry, cold and warm) mixed with a monotonic per-boot counter, so two
/// draws in one dispatch differ. Never used for key material; that flows from
/// the host-seeded [`HostRand`] alone.
#[cfg(target_arch = "riscv64")]
fn random_32() -> Result<[u8; 32], String> {
    let mut ctx_buf = [0u8; 72];
    let _ = vos::hostcalls::boot_context(&mut ctx_buf);
    let n = next_token_counter();
    Ok(vos::crypto::blake2b_hash::<32>(
        b"vos-msg/token/v1",
        &[&ctx_buf[..32], &n.to_le_bytes()],
    ))
}

/// Monotonic per-boot counter for [`random_32`]. The PVM is single-threaded
/// (the target is `singlethread`), so a plain `static mut` is sound.
#[cfg(target_arch = "riscv64")]
fn next_token_counter() -> u64 {
    static mut COUNTER: u64 = 0;
    // SAFETY: single-threaded target; no concurrent access.
    unsafe {
        let v = COUNTER;
        COUNTER = COUNTER.wrapping_add(1);
        v
    }
}

/// The MLS rules baked into every Client: PURE ciphertext (application messages
/// are always `PrivateMessage`; `encrypt_control_messages=true` makes
/// commits/proposals `PrivateMessage` too) and the ratchet tree carried in-band
/// in commits/welcomes (so a Welcome is self-contained and join needs no
/// out-of-band tree).
fn vos_mls_rules() -> DefaultMlsRules {
    DefaultMlsRules::new()
        .with_encryption_options(EncryptionOptions::new(true, PaddingMode::default()))
        .with_commit_options(CommitOptions::new().with_ratchet_tree_extension(true))
}

/// Derive this member's Ed25519 signer deterministically from the 32-byte
/// CSPRNG seed: `ed_seed = HKDF-Expand(seed, SIGNER_LABEL)`, then the mls-rs
/// `SignatureSecretKey` is Ed25519's 64-byte keypair encoding (seed‖public) and
/// the public is the verifying key. Reproducible from the seed alone, never
/// from OS entropy — so the signing identity is stable across restarts and
/// reproducible from the seed alone.
pub(crate) fn derive_signer(seed: &[u8]) -> Result<(SignatureSecretKey, SignaturePublicKey), String> {
    let signing = ed25519_signer(seed)?;
    let public = signing.verifying_key().to_bytes().to_vec();
    let keypair = signing.to_keypair_bytes().to_vec(); // 64 bytes = seed ‖ public
    Ok((
        SignatureSecretKey::from(keypair),
        SignaturePublicKey::from(public),
    ))
}

/// The member's raw Ed25519 public key bytes — a stable identity reference
/// reproducible from the seed.
pub(crate) fn signer_public(seed: &[u8]) -> Result<Vec<u8>, String> {
    Ok(ed25519_signer(seed)?.verifying_key().to_bytes().to_vec())
}

fn ed25519_signer(seed: &[u8]) -> Result<ed25519_dalek::SigningKey, String> {
    if seed.len() != 32 {
        return Err("not registered — CSPRNG seed not provisioned".into());
    }
    let hk = Hkdf::<Sha256>::new(None, seed);
    let mut ed_seed = Zeroizing::new([0u8; 32]);
    hk.expand(SIGNER_LABEL, ed_seed.as_mut_slice())
        .map_err(|_| "signer derivation failed".to_string())?;
    Ok(ed25519_dalek::SigningKey::from_bytes(&ed_seed))
}

/// Restore the MLS stores from the persisted snapshot.
pub(crate) fn open_stores(snapshot: &[u8]) -> VosStores {
    store::restore(snapshot, MAX_PAST_EPOCHS)
}

/// Boot the per-dispatch MLS CSPRNG from the seed plus a fresh per-open token,
/// folding an optional verifiable-randomness beacon into the output branch.
/// Shared by the identity-bound client builders.
fn boot_host_rand(seed: &[u8], beacon: Option<[u8; 32]>) -> Result<HostRand, String> {
    let seed32 = seed_array(seed)?;
    let mut boot_token = [0u8; 32];
    #[cfg(not(target_arch = "riscv64"))]
    getrandom::getrandom(&mut boot_token)
        .map_err(|e| format!("OS entropy unavailable for the MLS CSPRNG boot token: {e}"))?;
    // PVM actor: the host mints a FRESH boot token on every refine (re)entry —
    // cold AND warm restart — via the BOOT_CONTEXT seam. Re-booting the
    // CSPRNG from it per dispatch is what defeats warm-restart nonce reuse: a
    // resurrected snapshot draws under a different token, so it never re-emits
    // used randomness.
    #[cfg(target_arch = "riscv64")]
    {
        let mut ctx_buf = [0u8; 72];
        let _ = vos::hostcalls::boot_context(&mut ctx_buf);
        boot_token.copy_from_slice(&ctx_buf[..32]);
    }
    let rand = HostRand::boot(&seed32, &boot_token, &[], 0, 0);
    if let Some(b) = beacon {
        rand.set_beacon(PublicBeacon(b));
    }
    Ok(rand)
}

/// Build the per-member identity-bound MLS Client over the restored stores, the
/// custom credential + [`crate::identity::VosIdentityProvider`], and the
/// seed-derived signing identity. Seed-only stream — see
/// [`build_bound_client_hedged`] for the verifiable-randomness variant.
pub(crate) fn build_bound_client(
    binding: &crate::identity::Binding,
    space_id: [u8; 32],
    seed: &[u8],
    stores: &VosStores,
) -> Result<Client<impl MlsConfig + use<>>, String> {
    build_bound_client_hedged(binding, space_id, seed, stores, None)
}

/// [`build_bound_client`], additionally folding a public verifiable-randomness
/// `beacon` into the MLS CSPRNG: boots [`HostRand`] from the seed plus a fresh
/// per-open token, with the beacon entering only the HKDF output branch, so
/// confidentiality still rests on the secret seed alone.
pub(crate) fn build_bound_client_hedged(
    binding: &crate::identity::Binding,
    space_id: [u8; 32],
    seed: &[u8],
    stores: &VosStores,
    beacon: Option<[u8; 32]>,
) -> Result<Client<impl MlsConfig + use<>>, String> {
    build_bound_client_with_rand(binding, space_id, seed, boot_host_rand(seed, beacon)?, stores)
}

/// Build the identity-bound Client over an explicit [`HostRand`]: the leaf
/// carries the custom credential `(peer_id, display_name, binding_cert)` and
/// [`crate::identity::VosIdentityProvider`] checks every leaf mls-rs validates
/// (added members, joined-tree members) against `space_id`. Two clients built
/// from the same seed + the same `HostRand` boot context emit bit-identical
/// KeyPackages, commits, and Welcomes — the determinism gate.
///
/// `use<>`: the returned Client captures none of the input lifetimes — it copies
/// the binding into a credential, derives owned signer keys, and clones the
/// stores — so callers may keep mutating `self` while it lives.
///
/// The MLS signer is still the seed-derived Ed25519 key and the
/// cert is a provisioned input (not drawn from entropy), so KeyPackage /
/// commit / Welcome bytes stay bit-identical given the same (seed, boot, ts)
/// — the determinism gate holds (proven by
/// `same_seed_boot_and_ts_yields_identical_bound_key_package`).
pub(crate) fn build_bound_client_with_rand(
    binding: &crate::identity::Binding,
    space_id: [u8; 32],
    seed: &[u8],
    rand: HostRand,
    stores: &VosStores,
) -> Result<Client<impl MlsConfig + use<>>, String> {
    let (secret, public) = derive_signer(seed)?;
    let signing_identity =
        SigningIdentity::new(crate::identity::vos_credential(binding), public);
    Ok(Client::builder()
        .crypto_provider(VosCryptoProvider::new(rand))
        .identity_provider(crate::identity::VosIdentityProvider::new(space_id))
        .group_state_storage(stores.group_state.clone())
        .key_package_repo(stores.key_packages.clone())
        .mls_rules(vos_mls_rules())
        .signing_identity(signing_identity, secret, CIPHERSUITE)
        .build())
}

fn seed_array(seed: &[u8]) -> Result<[u8; 32], String> {
    seed.try_into()
        .map_err(|_| "not registered — CSPRNG seed not provisioned".to_string())
}

/// Load this channel's group from the Client's storage.
pub(crate) fn load_group<C: MlsConfig>(
    client: &Client<C>,
    channel: &str,
) -> Result<Group<C>, String> {
    client
        .load_group(&group_id_for(channel))
        .map_err(|e| format!("no MLS group for channel '{channel}': {e:?}"))
}

/// Convert a Unix-epoch millisecond timestamp to an mls-rs `MlsTime` (which is
/// seconds-granular). Threading an explicit time — rather than letting mls-rs
/// fall back to `SystemTime::now()` — pins the KeyPackage/commit Lifetime so the
/// output bytes are deterministic given the time, and removes the wall-clock
/// read from the MLS path (the PVM actor has no clock; `ts_ms` comes from the
/// host/wire). See [`crate::now_ms`].
pub(crate) fn mls_time(ts_ms: u64) -> MlsTime {
    MlsTime::from(ts_ms / 1000)
}

/// Serialize a fresh KeyPackage for out-of-band transport, stamping its
/// Lifetime from `ts_ms` (not the wall clock). The private parts are inserted
/// into the Client's key-package storage automatically. The bytes are an
/// `MlsMessage`-wrapped KeyPackage (mls-rs framing).
pub(crate) fn new_key_package<C: MlsConfig>(
    client: &Client<C>,
    ts_ms: u64,
) -> Result<Vec<u8>, String> {
    let kp = client
        .generate_key_package_message(
            ExtensionList::default(),
            ExtensionList::default(),
            Some(mls_time(ts_ms)),
        )
        .map_err(|e| format!("KeyPackage build failed: {e:?}"))?;
    kp.to_bytes()
        .map_err(|e| format!("KeyPackage serialize failed: {e:?}"))
}

/// Deserialize a received serialized KeyPackage into the `MlsMessage` envelope
/// `add_member` consumes. Full cryptographic validation is deferred to commit
/// build time (mls-rs has no standalone validate hook).
pub(crate) fn parse_key_package(bytes: &[u8]) -> Result<MlsMessage, String> {
    let msg = MlsMessage::from_bytes(bytes)
        .map_err(|e| format!("KeyPackage deserialize failed: {e:?}"))?;
    if msg.wire_format() != mls_rs::WireFormat::KeyPackage {
        return Err("not a key package".into());
    }
    Ok(msg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{self, VosStores};

    // Distinct per-party seeds so each identity draws a distinct signer.
    const ALICE: [u8; 32] = [0xA1; 32];
    const BOB: [u8; 32] = [0xB2; 32];
    const CHARLIE: [u8; 32] = [0xC3; 32];
    // A fixed timestamp so KeyPackage/commit Lifetimes are reproducible.
    const TS_MS: u64 = 1_700_000_000_000;
    // One space id shared by every member of a group: the identity provider
    // rejects leaves bound to a different space, so co-members must agree on it.
    const SPACE: [u8; 32] = [0x11; 32];

    /// Open the stores from a party's persisted snapshot. The caller builds a
    /// client over them, runs an op, persists with `Group::write_to_storage`,
    /// then `store::snapshot`s back — exactly the per-dispatch cycle the
    /// messenger runs.
    fn stores(snap: &[u8]) -> VosStores {
        open_stores(snap)
    }

    /// A valid identity binding for a member: a distinct operator key (derived
    /// from `seed`, giving a distinct PeerId) signs the binding cert over the
    /// member's seed-derived MLS public key, that PeerId, and `space_id` — the
    /// exact triple [`crate::identity::verify_binding`] checks. Leaves built from
    /// it pass `validate_member` at create/add/join.
    fn test_binding(seed: &[u8], display_name: &str, space_id: &[u8; 32]) -> crate::identity::Binding {
        use ed25519_dalek::{Signer, SigningKey};
        let op = SigningKey::from_bytes(&seed_array(seed).unwrap());
        let mut peer_id = alloc::vec![0x00u8, 0x24, 0x08, 0x01, 0x12, 0x20];
        peer_id.extend_from_slice(&op.verifying_key().to_bytes());
        let mls_pubkey = signer_public(seed).unwrap();
        let cert = op
            .sign(&space_registry::binding_signed_bytes(&mls_pubkey, &peer_id, space_id))
            .to_bytes()
            .to_vec();
        crate::identity::Binding {
            peer_id,
            display_name: String::from(display_name),
            cert,
        }
    }

    /// The Welcome routing token must be fresh per invite and must never
    /// equal the directory's public `kp_hash`.
    #[test]
    fn welcome_nonce_is_fresh_and_unlinkable() {
        let n1 = welcome_nonce().unwrap();
        let n2 = welcome_nonce().unwrap();
        assert_ne!(n1, n2, "tokens must be fresh per invite");
        assert_ne!(
            n1,
            msg_directory::kp_hash(b"any serialized key package"),
            "token must not equal the directory's public kp_hash",
        );
    }

    /// The signer is derived deterministically from the seed (reproducible, no
    /// OsRng) and forks per seed. Full KeyPackage/commit/Welcome byte
    /// reproducibility comes from the custom `VosCryptoProvider` routing every
    /// KEM/HPKE draw through the same seed — asserted by
    /// `same_seed_boot_and_ts_yields_identical_key_package` and friends below.
    #[test]
    fn signer_is_deterministic_from_seed() {
        let (_, p1) = derive_signer(&ALICE).unwrap();
        let (_, p2) = derive_signer(&ALICE).unwrap();
        assert_eq!(p1.as_bytes(), p2.as_bytes(), "same seed ⇒ same signer");
        let (_, p3) = derive_signer(&BOB).unwrap();
        assert_ne!(p1.as_bytes(), p3.as_bytes(), "distinct seed ⇒ distinct signer");
        assert_eq!(signer_public(&ALICE).unwrap(), p1.as_bytes());
    }

    /// A created group survives the snapshot/restore boundary: reopen the
    /// stores and the group loads at the same epoch.
    #[test]
    fn group_survives_snapshot_boundary() {
        let alice_b = test_binding(&ALICE, "alice", &SPACE);
        let s = stores(&[]);
        let client = build_bound_client(&alice_b, SPACE, &ALICE, &s).unwrap();
        let mut group = client
            .create_group_with_id(
                group_id_for("general").to_vec(),
                ExtensionList::default(),
                ExtensionList::default(),
                None,
            )
            .unwrap();
        group.write_to_storage().unwrap();
        let snap = store::snapshot(&s);
        assert!(!snap.is_empty(), "a created group must persist");

        // Reopen from the snapshot and reload.
        let s2 = stores(&snap);
        let client2 = build_bound_client(&alice_b, SPACE, &ALICE, &s2).unwrap();
        let group2 = load_group(&client2, "general").unwrap();
        assert_eq!(group2.current_epoch(), 0);
        assert_eq!(group2.roster().members_iter().count(), 1);

        // Corrupt/empty snapshots degrade to a fresh (empty) store.
        assert!(build_bound_client(&alice_b, SPACE, &ALICE, &stores(&[1, 2, 3]))
            .unwrap()
            .load_group(&group_id_for("general"))
            .is_err());
    }

    /// The whole create → KeyPackage → add+welcome → join → exchange flow,
    /// crossing the persistence boundary after every step (exactly the
    /// per-dispatch open/snapshot cycle): Alice creates the channel group, Bob
    /// publishes a KeyPackage, Alice adds + welcomes him, both exchange
    /// application messages as serialized wire bytes.
    #[test]
    fn group_flow_survives_snapshot_boundaries() {
        let alice_b = test_binding(&ALICE, "alice", &SPACE);
        let bob_b = test_binding(&BOB, "bob", &SPACE);
        // Alice: create the group, persist.
        let s = stores(&[]);
        let alice = build_bound_client(&alice_b, SPACE, &ALICE, &s).unwrap();
        let mut alice_group = alice
            .create_group_with_id(
                group_id_for("general").to_vec(),
                ExtensionList::default(),
                ExtensionList::default(),
                None,
            )
            .unwrap();
        alice_group.write_to_storage().unwrap();
        let alice_snap = store::snapshot(&s);

        // Bob: publish a KeyPackage, persist.
        let s = stores(&[]);
        let bob = build_bound_client(&bob_b, SPACE, &BOB, &s).unwrap();
        let kp_bytes = new_key_package(&bob, crate::now_ms()).unwrap();
        let bob_snap = store::snapshot(&s);

        // Alice (fresh restore): add Bob, commit, persist.
        let s = stores(&alice_snap);
        let alice = build_bound_client(&alice_b, SPACE, &ALICE, &s).unwrap();
        let mut alice_group = load_group(&alice, "general").unwrap();
        let out = alice_group
            .commit_builder()
            .add_member(parse_key_package(&kp_bytes).unwrap())
            .unwrap()
            .build()
            .unwrap();
        let welcome_bytes = out.welcome_messages[0].to_bytes().unwrap();
        alice_group.apply_pending_commit().unwrap();
        alice_group.write_to_storage().unwrap();
        let alice_snap = store::snapshot(&s);

        // Bob (fresh restore): join from the Welcome wire bytes, persist.
        let s = stores(&bob_snap);
        let bob = build_bound_client(&bob_b, SPACE, &BOB, &s).unwrap();
        let welcome = MlsMessage::from_bytes(&welcome_bytes).unwrap();
        let (mut bob_group, _info) = bob.join_group(None, &welcome, None).unwrap();
        assert_eq!(bob_group.roster().members_iter().count(), 2);
        bob_group.write_to_storage().unwrap();
        let bob_snap = store::snapshot(&s);

        // Alice → Bob across the wire.
        let s = stores(&alice_snap);
        let alice = build_bound_client(&alice_b, SPACE, &ALICE, &s).unwrap();
        let mut alice_group = load_group(&alice, "general").unwrap();
        let wire = alice_group
            .encrypt_application_message(b"hello bob", Vec::new())
            .unwrap()
            .to_bytes()
            .unwrap();
        alice_group.write_to_storage().unwrap();
        let alice_snap = store::snapshot(&s);

        let s = stores(&bob_snap);
        let bob = build_bound_client(&bob_b, SPACE, &BOB, &s).unwrap();
        let mut bob_group = load_group(&bob, "general").unwrap();
        let (sender, text) = crate::tick::decrypt_app(&mut bob_group, &wire).unwrap();
        assert_eq!((sender.as_str(), text.as_str()), ("alice", "hello bob"));
        bob_group.write_to_storage().unwrap();
        let bob_snap = store::snapshot(&s);

        // Bob → Alice, each side restored from its latest snapshot.
        let s = stores(&bob_snap);
        let bob = build_bound_client(&bob_b, SPACE, &BOB, &s).unwrap();
        let mut bob_group = load_group(&bob, "general").unwrap();
        let wire_back = bob_group
            .encrypt_application_message(b"hi alice", Vec::new())
            .unwrap()
            .to_bytes()
            .unwrap();
        bob_group.write_to_storage().unwrap();

        let s = stores(&alice_snap);
        let alice = build_bound_client(&alice_b, SPACE, &ALICE, &s).unwrap();
        let mut alice_group = load_group(&alice, "general").unwrap();
        let (sender, text) = crate::tick::decrypt_app(&mut alice_group, &wire_back).unwrap();
        assert_eq!((sender.as_str(), text.as_str()), ("bob", "hi alice"));

        // Ciphertext privacy gate: the wire bytes never contain the plaintext.
        let needle = b"hello bob";
        assert!(
            !wire.windows(needle.len()).any(|w| w == needle),
            "MLS wire bytes must not leak plaintext"
        );
    }

    // ── Sequenced-chain integration (real MsgCtl state machine) ──

    /// Handler futures never await anything external, so a single poll with a
    /// no-op waker resolves them.
    fn run<F: core::future::Future>(fut: F) -> F::Output {
        use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
        fn raw() -> RawWaker {
            fn clone(_: *const ()) -> RawWaker {
                raw()
            }
            fn noop(_: *const ()) {}
            RawWaker::new(
                core::ptr::null(),
                &RawWakerVTable::new(clone, noop, noop, noop),
            )
        }
        let waker = unsafe { Waker::from_raw(raw()) };
        let mut cx = Context::from_waker(&waker);
        let mut fut = core::pin::pin!(fut);
        match fut.as_mut().poll(&mut cx) {
            Poll::Ready(out) => out,
            Poll::Pending => panic!("actor handler future was not immediately ready"),
        }
    }

    fn ctl_dispatch<M>(
        c: &mut msg_ctl::MsgCtl,
        msg: M,
    ) -> <msg_ctl::MsgCtl as vos::Message<M>>::Output
    where
        msg_ctl::MsgCtl: vos::Message<M>,
    {
        let mut ctx: vos::Context<msg_ctl::MsgCtl> =
            vos::Context::new(vos::actors::context::ServiceId(0));
        run(<msg_ctl::MsgCtl as vos::Message<M>>::handle(c, msg, &mut ctx))
    }

    fn submit(
        ctl: &mut msg_ctl::MsgCtl,
        epoch: u64,
        commit_body: Vec<u8>,
        welcome: Option<(Vec<u8>, [u8; 32])>,
    ) -> msg_ctl::CommitOutcome {
        let (welcome_bytes, hint) = welcome
            .map(|(w, h)| (w, h.to_vec()))
            .unwrap_or_default();
        ctl_dispatch(
            ctl,
            msg_ctl::Commit {
                epoch,
                ts_ms: 0,
                commit_body,
                welcome: welcome_bytes,
                welcome_hint: hint,
            },
        )
    }

    /// The property that breaks pure-CRDT designs: two members commit
    /// concurrently at the same epoch; the sequencer accepts exactly one, the
    /// loser catches up off the chain and re-issues, and both converge to
    /// identical group state.
    #[test]
    fn losing_commit_is_rejected_and_reissues_to_convergence() {
        let mut ctl = msg_ctl::MsgCtl::new();

        // Bootstrap: alice creates, adds bob (epoch 0 → 1) through the sequencer.
        let alice_b = test_binding(&ALICE, "alice", &SPACE);
        let bob_b = test_binding(&BOB, "bob", &SPACE);
        let charlie_b = test_binding(&CHARLIE, "charlie", &SPACE);
        let sa = stores(&[]);
        let alice = build_bound_client(&alice_b, SPACE, &ALICE, &sa).unwrap();
        let mut alice_group = alice
            .create_group_with_id(
                group_id_for("contended").to_vec(),
                ExtensionList::default(),
                ExtensionList::default(),
                None,
            )
            .unwrap();

        let sb = stores(&[]);
        let bob = build_bound_client(&bob_b, SPACE, &BOB, &sb).unwrap();
        let bob_kp = new_key_package(&bob, crate::now_ms()).unwrap();

        let out = alice_group
            .commit_builder()
            .add_member(parse_key_package(&bob_kp).unwrap())
            .unwrap()
            .build()
            .unwrap();
        let add_commit = out.commit_message.to_bytes().unwrap();
        let welcome = out.welcome_messages[0].to_bytes().unwrap();
        let outcome = submit(
            &mut ctl,
            0,
            add_commit,
            Some((welcome, msg_directory::kp_hash(&bob_kp))),
        );
        assert_eq!(outcome.status, msg_ctl::Status::Ok);
        alice_group.apply_pending_commit().unwrap();

        let row = ctl_dispatch(&mut ctl, msg_ctl::CommitAt { epoch: 0 }).unwrap();
        let welcome = MlsMessage::from_bytes(&row.welcome).unwrap();
        let (mut bob_group, _info) = bob.join_group(None, &welcome, None).unwrap();
        assert_eq!(alice_group.current_epoch(), 1);
        assert_eq!(bob_group.current_epoch(), 1);

        // The race: both commit at epoch 1. Alice adds charlie; bob rotates his
        // keys (self-update). Alice's reaches the sequencer first.
        let sc = stores(&[]);
        let charlie = build_bound_client(&charlie_b, SPACE, &CHARLIE, &sc).unwrap();
        let charlie_kp = new_key_package(&charlie, crate::now_ms()).unwrap();
        let alice_out = alice_group
            .commit_builder()
            .add_member(parse_key_package(&charlie_kp).unwrap())
            .unwrap()
            .build()
            .unwrap();
        let alice_commit = alice_out.commit_message.to_bytes().unwrap();
        let charlie_welcome = alice_out.welcome_messages[0].to_bytes().unwrap();

        let bob_out = bob_group.commit(Vec::new()).unwrap();
        assert!(bob_out.welcome_messages.is_empty());
        let bob_commit = bob_out.commit_message.to_bytes().unwrap();

        let outcome = submit(
            &mut ctl,
            1,
            alice_commit,
            Some((charlie_welcome, msg_directory::kp_hash(&charlie_kp))),
        );
        assert_eq!(outcome.status, msg_ctl::Status::Ok);
        alice_group.apply_pending_commit().unwrap();

        let outcome = submit(&mut ctl, 1, bob_commit, None);
        assert_eq!(
            outcome.status,
            msg_ctl::Status::EpochTaken,
            "the second commit for epoch 1 must lose"
        );

        // Loser path: drop the pending commit, process the winner off the
        // chain (auto-applied), rebuild at the new epoch.
        bob_group.clear_pending_commit();
        let row = ctl_dispatch(&mut ctl, msg_ctl::CommitAt { epoch: 1 }).unwrap();
        let received = bob_group
            .process_incoming_message(MlsMessage::from_bytes(&row.commit_body).unwrap())
            .unwrap();
        assert!(matches!(
            received,
            mls_rs::group::ReceivedMessage::Commit(_)
        ));
        assert_eq!(bob_group.current_epoch(), 2);

        let bob_retry = bob_group.commit(Vec::new()).unwrap();
        assert!(bob_retry.welcome_messages.is_empty());
        let outcome = submit(&mut ctl, 2, bob_retry.commit_message.to_bytes().unwrap(), None);
        assert_eq!(outcome.status, msg_ctl::Status::Ok);
        bob_group.apply_pending_commit().unwrap();

        // Alice processes bob's re-issued commit off the chain.
        let row = ctl_dispatch(&mut ctl, msg_ctl::CommitAt { epoch: 2 }).unwrap();
        alice_group
            .process_incoming_message(MlsMessage::from_bytes(&row.commit_body).unwrap())
            .unwrap();

        assert_eq!(alice_group.current_epoch(), 3);
        assert_eq!(bob_group.current_epoch(), 3);
        assert_eq!(
            alice_group.export_secret(b"convergence", &[], 32).unwrap().as_bytes(),
            bob_group.export_secret(b"convergence", &[], 32).unwrap().as_bytes(),
            "both members must land on identical group state"
        );
    }

    /// Post-compromise security through removal: once the Remove commit lands,
    /// the evicted member's processed commit reports `Removed` and later traffic
    /// is undecryptable to them.
    #[test]
    fn removed_member_cannot_decrypt_post_removal_traffic() {
        let alice_b = test_binding(&ALICE, "alice", &SPACE);
        let bob_b = test_binding(&BOB, "bob", &SPACE);
        let sa = stores(&[]);
        let alice = build_bound_client(&alice_b, SPACE, &ALICE, &sa).unwrap();
        let mut alice_group = alice
            .create_group_with_id(
                group_id_for("evict").to_vec(),
                ExtensionList::default(),
                ExtensionList::default(),
                None,
            )
            .unwrap();

        let sb = stores(&[]);
        let bob = build_bound_client(&bob_b, SPACE, &BOB, &sb).unwrap();
        let bob_kp = new_key_package(&bob, crate::now_ms()).unwrap();
        let out = alice_group
            .commit_builder()
            .add_member(parse_key_package(&bob_kp).unwrap())
            .unwrap()
            .build()
            .unwrap();
        let welcome_bytes = out.welcome_messages[0].to_bytes().unwrap();
        alice_group.apply_pending_commit().unwrap();
        let welcome = MlsMessage::from_bytes(&welcome_bytes).unwrap();
        let (mut bob_group, _info) = bob.join_group(None, &welcome, None).unwrap();

        // Alice evicts bob, located by his verified binding's display name.
        let bob_index = alice_group
            .roster()
            .members_iter()
            .find(|m| {
                crate::identity::member_binding(&m.signing_identity)
                    .is_some_and(|d| d.display_name == "bob")
            })
            .unwrap()
            .index;
        let remove = alice_group
            .commit_builder()
            .remove_member(bob_index)
            .unwrap()
            .build()
            .unwrap();
        assert!(remove.welcome_messages.is_empty());
        let remove_commit = remove.commit_message.to_bytes().unwrap();
        alice_group.apply_pending_commit().unwrap();

        let received = bob_group
            .process_incoming_message(MlsMessage::from_bytes(&remove_commit).unwrap())
            .unwrap();
        assert!(
            matches!(
                received,
                mls_rs::group::ReceivedMessage::Commit(desc)
                    if matches!(desc.effect, mls_rs::group::CommitEffect::Removed { .. })
            ),
            "bob's processed commit must report he was removed"
        );
        assert_eq!(alice_group.roster().members_iter().count(), 1);

        // Post-removal traffic is noise to bob.
        let wire = alice_group
            .encrypt_application_message(b"after the eviction", Vec::new())
            .unwrap()
            .to_bytes()
            .unwrap();
        assert!(
            crate::tick::decrypt_app(&mut bob_group, &wire).is_err(),
            "an evicted member must not decrypt post-removal traffic"
        );
    }

    /// The determinism gate: every mls-rs entropy draw flows through the
    /// host-seeded CSPRNG, so two providers from the same (seed, boot context)
    /// produce bit-identical KEM keypairs, HPKE ciphertexts (the ephemeral the
    /// stock provider drew from OsRng — the seam OpenMLS couldn't reach), and
    /// `random_bytes`; a different boot token forks every draw.
    #[test]
    fn host_seeded_provider_is_deterministic() {
        use crate::crypto_provider::VosCryptoProvider;
        use mls_rs_core::crypto::{CipherSuiteProvider, CryptoProvider};

        let token = [0x5Au8; 32];
        let csp = |seed: [u8; 32], tok: [u8; 32]| {
            VosCryptoProvider::new(HostRand::boot(&seed, &tok, &[], 0, 0))
                .cipher_suite_provider(CIPHERSUITE)
                .unwrap()
        };

        // Each comparison uses FRESH providers (a shared HostRand advances its
        // ratchet per draw, so reuse would not compare like-for-like).

        // Same seed + boot token ⇒ identical KEM keypair (X25519, via the
        // wrapped DhType::generate).
        assert_eq!(
            csp(ALICE, token).kem_generate().unwrap().1,
            csp(ALICE, token).kem_generate().unwrap().1,
            "same seed+boot must yield an identical KEM public key"
        );

        // Identical random_bytes.
        let mut ra = [0u8; 48];
        let mut rb = [0u8; 48];
        csp(ALICE, token).random_bytes(&mut ra).unwrap();
        csp(ALICE, token).random_bytes(&mut rb).unwrap();
        assert_eq!(ra, rb, "same seed+boot must yield identical random_bytes");

        // Identical HPKE seal to a fixed remote key — the ephemeral KEM key is
        // deterministic, so kem_output + ciphertext are bit-identical (the
        // ephemeral the stock provider drew from OsRng).
        let remote = csp(CHARLIE, token).kem_generate().unwrap().1;
        let ct_a = csp(ALICE, token)
            .hpke_seal(&remote, b"info", None, b"plaintext")
            .unwrap();
        let ct_b = csp(ALICE, token)
            .hpke_seal(&remote, b"info", None, b"plaintext")
            .unwrap();
        assert_eq!(
            ct_a.kem_output, ct_b.kem_output,
            "deterministic HPKE ephemeral must yield an identical kem_output"
        );
        assert_eq!(
            ct_a.ciphertext, ct_b.ciphertext,
            "deterministic HPKE seal must yield identical ciphertext"
        );

        // A different boot token forks every draw.
        assert_ne!(
            csp(ALICE, [0x99u8; 32]).kem_generate().unwrap().1,
            csp(ALICE, token).kem_generate().unwrap().1,
            "a different boot token must fork the KEM key"
        );
    }

    /// The chronos beacon hedge: folding the SAME beacon stays bit-identical
    /// (so the determinism gate + cross-member consistency hold), a DIFFERENT
    /// beacon forks the draw (the hedge actually mixes in), and folding any
    /// beacon differs from the seed-only stream (so absent chronos is a distinct
    /// no-op path). Mirrors `host_rand::beacon_is_output_info_only` at the
    /// provider level.
    #[test]
    fn beacon_hedge_keeps_determinism_and_forks_on_change() {
        use crate::crypto_provider::VosCryptoProvider;
        use crate::host_rand::PublicBeacon;
        use mls_rs_core::crypto::{CipherSuiteProvider, CryptoProvider};

        let token = [0x5Au8; 32];
        let csp = |beacon: Option<[u8; 32]>| {
            let rand = HostRand::boot(&ALICE, &token, &[], 0, 0);
            if let Some(b) = beacon {
                rand.set_beacon(PublicBeacon(b));
            }
            VosCryptoProvider::new(rand)
                .cipher_suite_provider(CIPHERSUITE)
                .unwrap()
        };
        let b1 = [0x11u8; 32];
        let b2 = [0x22u8; 32];

        assert_eq!(
            csp(Some(b1)).kem_generate().unwrap().1,
            csp(Some(b1)).kem_generate().unwrap().1,
            "same seed+boot+beacon must yield an identical KEM key"
        );
        assert_ne!(
            csp(Some(b1)).kem_generate().unwrap().1,
            csp(Some(b2)).kem_generate().unwrap().1,
            "a different beacon must fork the KEM key"
        );
        assert_ne!(
            csp(Some(b1)).kem_generate().unwrap().1,
            csp(None).kem_generate().unwrap().1,
            "folding a beacon must differ from the seed-only stream"
        );
    }

    /// Byte-determinism gate: a KeyPackage is bit-identical given the same
    /// (seed, boot token, timestamp) — the entropy is host-seeded and the
    /// Lifetime is pinned from `ts_ms` instead of the wall clock. A different
    /// timestamp forks it (the Lifetime changed).
    #[test]
    fn same_seed_boot_and_ts_yields_identical_key_package() {
        let token = [0x5Au8; 32];
        let binding = test_binding(&ALICE, "zoe", &SPACE);
        let mint = |ts: u64| {
            let s = stores(&[]);
            let client = build_bound_client_with_rand(
                &binding,
                SPACE,
                &ALICE,
                HostRand::boot(&ALICE, &token, &[], 0, 0),
                &s,
            )
            .unwrap();
            new_key_package(&client, ts).unwrap()
        };
        assert_eq!(
            mint(TS_MS),
            mint(TS_MS),
            "same seed+boot+ts must yield a byte-identical KeyPackage"
        );
        assert_ne!(
            mint(TS_MS),
            mint(TS_MS + 100_000_000),
            "a different timestamp must change the KeyPackage lifetime"
        );
    }

    /// The identity-bound KeyPackage (custom credential
    /// carrying peer_id + binding cert) is bit-identical given the same
    /// (seed, boot token, ts, binding). The binding is a deterministic
    /// credential input, not an entropy source, so the host-vs-PVM gate holds.
    #[test]
    fn same_seed_boot_and_ts_yields_identical_bound_key_package() {
        use crate::identity::Binding;
        let token = [0x5Au8; 32];
        let space_id = [0x11u8; 32];
        // The cert bytes only need to be stable here — KeyPackage generation
        // never validates them (validation is a verifier-side hook).
        let binding = Binding {
            peer_id: alloc::vec![0x22u8; 38],
            display_name: String::from("zoe"),
            cert: alloc::vec![0x33u8; 64],
        };
        let mint = |ts: u64| {
            let s = stores(&[]);
            let client = build_bound_client_with_rand(
                &binding,
                space_id,
                &ALICE,
                HostRand::boot(&ALICE, &token, &[], 0, 0),
                &s,
            )
            .unwrap();
            new_key_package(&client, ts).unwrap()
        };
        assert_eq!(
            mint(TS_MS),
            mint(TS_MS),
            "same seed+boot+ts+binding ⇒ byte-identical bound KeyPackage",
        );
        assert_ne!(
            mint(TS_MS),
            mint(TS_MS + 100_000_000),
            "a different timestamp must change the bound KeyPackage lifetime",
        );
    }

    /// The binding actually enters the signed KeyPackage: two distinct bindings
    /// (different PeerId) fork it, so the determinism gate above is meaningful.
    #[test]
    fn bound_key_package_differs_by_binding() {
        use crate::identity::Binding;
        let token = [0x5Au8; 32];
        let space_id = [0x11u8; 32];
        let kp = |b: &Binding| {
            let s = stores(&[]);
            let client = build_bound_client_with_rand(
                b,
                space_id,
                &ALICE,
                HostRand::boot(&ALICE, &token, &[], 0, 0),
                &s,
            )
            .unwrap();
            new_key_package(&client, TS_MS).unwrap()
        };
        let b1 = Binding {
            peer_id: alloc::vec![0x22u8; 38],
            display_name: String::from("zoe"),
            cert: alloc::vec![0x33u8; 64],
        };
        let mut b2 = b1.clone();
        b2.peer_id = alloc::vec![0x44u8; 38];
        assert_ne!(kp(&b1), kp(&b2), "distinct bindings fork the KeyPackage");
    }

    /// Byte-determinism gate for commits + Welcomes: an add-member commit and
    /// its Welcome are bit-identical given the same (seeds, boot token,
    /// commit_time) — every entropy draw (alice's + bob's KEM keys, the commit
    /// path secret, the HPKE seal ephemeral to bob) is host-seeded, and the
    /// commit/KeyPackage Lifetimes are pinned from the fixed timestamp.
    #[test]
    fn same_seed_boot_and_ts_yields_identical_commit_and_welcome() {
        let token = [0x5Au8; 32];
        let alice_b = test_binding(&ALICE, "alice", &SPACE);
        let bob_b = test_binding(&BOB, "bob", &SPACE);
        let run = || {
            let bs = stores(&[]);
            let bob = build_bound_client_with_rand(
                &bob_b,
                SPACE,
                &BOB,
                HostRand::boot(&BOB, &token, &[], 0, 0),
                &bs,
            )
            .unwrap();
            let kp = new_key_package(&bob, TS_MS).unwrap();

            let as_ = stores(&[]);
            let alice = build_bound_client_with_rand(
                &alice_b,
                SPACE,
                &ALICE,
                HostRand::boot(&ALICE, &token, &[], 0, 0),
                &as_,
            )
            .unwrap();
            let mut g = alice
                .create_group_with_id(
                    group_id_for("det").to_vec(),
                    ExtensionList::default(),
                    ExtensionList::default(),
                    Some(mls_time(TS_MS)),
                )
                .unwrap();
            let out = g
                .commit_builder()
                .commit_time(mls_time(TS_MS))
                .add_member(parse_key_package(&kp).unwrap())
                .unwrap()
                .build()
                .unwrap();
            (
                out.commit_message.to_bytes().unwrap(),
                out.welcome_messages[0].to_bytes().unwrap(),
            )
        };
        let (c1, w1) = run();
        let (c2, w2) = run();
        assert_eq!(c1, c2, "same seed+boot+ts must yield a byte-identical commit");
        assert_eq!(w1, w2, "same seed+boot+ts must yield a byte-identical welcome");
    }
}
