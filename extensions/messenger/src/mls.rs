//! MLS plumbing: provider persistence, identity, group lifecycle.
//!
//! OpenMLS keeps every secret (signature keys, KeyPackage private
//! parts, group ratchet state) in its `StorageProvider`. We use the
//! in-memory provider and snapshot its key-value map into the
//! extension's rkyv-persisted state after every mutating operation,
//! so MLS state survives daemon restarts while never leaving this
//! node. The map is small (one signer + a handful of groups), so
//! restore-per-dispatch is cheap and keeps the handler model simple
//! — no live cell to keep in sync with the persisted bytes.

use openmls::prelude::tls_codec::Serialize as TlsSerialize;
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::OpenMlsProvider;
use std::collections::HashMap;
use zeroize::Zeroize;

use crate::Messenger;
use crate::host_rand::{HostRand, VosProvider};

/// The one ciphersuite VOS messaging speaks (per docs/encryption.md).
pub(crate) const CIPHERSUITE: Ciphersuite =
    Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

/// Domain tag for deriving a channel's MLS GroupId from its name,
/// so every member computes the same id without coordination.
pub(crate) const GROUP_ID_DOMAIN_TAG: &[u8] = b"vos-msg-group/v1";

/// Tolerate this much application-message reordering per sender.
/// The merkle-CRDT log delivers each sender's messages in causal
/// (= per-sender) order, so gaps only come from skipped/garbage
/// envelopes — keep headroom anyway, the cost is bounded key
/// retention.
const OUT_OF_ORDER_TOLERANCE: u32 = 64;
const MAX_FORWARD_DISTANCE: u32 = 2000;

/// Retain decryption keys for this many epochs behind the group's
/// current one. The log and the commit chain replicate
/// independently, so application messages from recently-passed
/// epochs are routine; a message older than this window is dropped
/// undecryptably. Generous so a burst of membership changes between
/// a message being sent and a member draining it doesn't silently
/// lose it — the cost is bounded key-material retention.
const MAX_PAST_EPOCHS: usize = 64;

pub(crate) fn group_id_for(channel: &str) -> [u8; 32] {
    vos::crypto::blake2b_hash(GROUP_ID_DOMAIN_TAG, &[channel.as_bytes()])
}

fn random_32(provider: &VosProvider) -> Result<[u8; 32], String> {
    use openmls_traits::random::OpenMlsRand;
    provider
        .rand()
        .random_array::<32>()
        .map_err(|e| format!("rng failure: {e:?}"))
}

/// 32 random bytes from the crypto provider's RNG — the
/// replication id for a dynamically installed channel agent.
/// Random rather than name-derived so the sync group / gossip
/// topic isn't guessable from the channel name; members learn it
/// from the registry's replicated `AgentRow` instead.
pub(crate) fn fresh_replication_id(provider: &VosProvider) -> Result<[u8; 32], String> {
    random_32(provider)
}

/// 32 random bytes for a Commit row's Welcome routing token.
/// The token must NOT be derivable from the joiner's public
/// KeyPackage: a deterministic hash of the public KP equals the
/// directory's `kp_hash`, which would let anyone holding both the
/// replicated directory and the ctl chain map the token back to a
/// nickname (and link the same KP across channels). A fresh random
/// token leaks nothing; the joiner recognises its own Welcome by
/// trial-decryption (only a Welcome sealed to a KeyPackage it holds
/// stages successfully), so no public routing tag is needed.
pub(crate) fn welcome_nonce(provider: &VosProvider) -> Result<[u8; 32], String> {
    random_32(provider)
}

fn ratchet_config() -> SenderRatchetConfiguration {
    SenderRatchetConfiguration::new(OUT_OF_ORDER_TOLERANCE, MAX_FORWARD_DISTANCE)
}

pub(crate) fn create_config() -> MlsGroupCreateConfig {
    MlsGroupCreateConfig::builder()
        .wire_format_policy(PURE_CIPHERTEXT_WIRE_FORMAT_POLICY)
        .sender_ratchet_configuration(ratchet_config())
        .max_past_epochs(MAX_PAST_EPOCHS)
        .use_ratchet_tree_extension(true)
        .build()
}

pub(crate) fn join_config() -> MlsGroupJoinConfig {
    MlsGroupJoinConfig::builder()
        .wire_format_policy(PURE_CIPHERTEXT_WIRE_FORMAT_POLICY)
        .sender_ratchet_configuration(ratchet_config())
        .max_past_epochs(MAX_PAST_EPOCHS)
        .use_ratchet_tree_extension(true)
        .build()
}

// ── Provider persistence ──────────────────────────────────────────

/// Restore the MLS provider from the persisted snapshot, booting the
/// host-seeded CSPRNG over `seed` — the 32-byte confidentiality root held
/// in the messenger's node-local state. A per-boot uniqueness token is
/// drawn fresh from OS entropy on every call (see [`crate::host_rand`]), so
/// a clone or rollback can never re-emit used randomness. An unseeded or
/// malformed `seed` falls back to a fully OS-entropy ephemeral root: paths
/// that run before `register` provisions the durable seed draw nothing that
/// is persisted. An empty (or corrupt — only by operator tampering)
/// snapshot yields a fresh storage map.
pub(crate) fn open_provider(snapshot: &[u8], seed: &[u8]) -> VosProvider {
    let mut seed32 = [0u8; 32];
    if seed.len() == 32 {
        seed32.copy_from_slice(seed);
    } else {
        // Pre-`register` fallback root; nothing drawn here is persisted.
        getrandom::getrandom(&mut seed32)
            .expect("OS entropy unavailable for the MLS CSPRNG seed fallback");
    }
    // The per-boot uniqueness token is currently the ONLY live cross-boot
    // reuse defense: `device_id`/`boot_epoch`/`persisted_ctr` below are
    // host-fed by the deterministic PVM runtime (not yet wired) and left at
    // their freshness defaults here, and the ratchet state is reborn per
    // dispatch (never persisted). So a fresh token per open is load-bearing —
    // an entropy failure MUST abort, never silently boot a zero (and thus
    // replayable) stream. OS entropy here; a host-fed VM-generation value
    // takes its place once the messenger runs as a deterministic PVM actor.
    let mut boot_token = [0u8; 32];
    getrandom::getrandom(&mut boot_token)
        .expect("OS entropy unavailable for the MLS CSPRNG boot token");
    let rand = HostRand::boot(&seed32, &boot_token, &[], 0, 0);
    seed32.zeroize();
    boot_token.zeroize();
    let provider = VosProvider::new(rand);
    if let Some(map) = decode_store(snapshot) {
        *provider.storage().values.write().unwrap() = map;
    }
    provider
}

/// Snapshot the provider's storage back into persistable bytes.
pub(crate) fn snapshot_provider(provider: &VosProvider) -> Vec<u8> {
    let values = provider.storage().values.read().unwrap();
    let mut out = Vec::new();
    out.extend_from_slice(&(values.len() as u64).to_le_bytes());
    for (k, v) in values.iter() {
        out.extend_from_slice(&(k.len() as u64).to_le_bytes());
        out.extend_from_slice(&(v.len() as u64).to_le_bytes());
        out.extend_from_slice(k);
        out.extend_from_slice(v);
    }
    out
}

fn decode_store(bytes: &[u8]) -> Option<HashMap<Vec<u8>, Vec<u8>>> {
    if bytes.is_empty() {
        return None;
    }
    let read_u64 = |at: &mut usize| -> Option<u64> {
        let end = at.checked_add(8)?;
        let v = u64::from_le_bytes(bytes.get(*at..end)?.try_into().ok()?);
        *at = end;
        Some(v)
    };
    let mut at = 0usize;
    let count = read_u64(&mut at)?;
    let mut map = HashMap::new();
    // `checked_add` + `get` throughout: a corrupt or truncated
    // snapshot (e.g. a length field claiming more bytes than remain,
    // or one large enough to overflow `at + len`) must yield None so
    // `open_provider` falls back to a fresh provider, never panic.
    for _ in 0..count {
        let k_len = read_u64(&mut at)? as usize;
        let v_len = read_u64(&mut at)? as usize;
        let k_end = at.checked_add(k_len)?;
        let k = bytes.get(at..k_end)?.to_vec();
        at = k_end;
        let v_end = at.checked_add(v_len)?;
        let v = bytes.get(at..v_end)?.to_vec();
        at = v_end;
        map.insert(k, v);
    }
    Some(map)
}

// ── Identity & groups ─────────────────────────────────────────────

impl Messenger {
    /// This member's credential + the signer loaded from MLS
    /// storage. Errors when `register` hasn't run.
    pub(crate) fn identity(
        &self,
        provider: &VosProvider,
    ) -> Result<(CredentialWithKey, SignatureKeyPair), String> {
        if self.nickname.is_empty() {
            return Err("not registered — run `messenger register <nickname>` first".into());
        }
        let signer = SignatureKeyPair::read(
            provider.storage(),
            &self.signature_key,
            CIPHERSUITE.signature_algorithm(),
        )
        .ok_or_else(|| "signature key missing from MLS storage".to_string())?;
        let credential = BasicCredential::new(self.nickname.clone().into_bytes());
        Ok((
            CredentialWithKey {
                credential: credential.into(),
                signature_key: self.signature_key.clone().into(),
            },
            signer,
        ))
    }

    pub(crate) fn load_group(
        &self,
        provider: &VosProvider,
        channel: &str,
    ) -> Result<MlsGroup, String> {
        let gid = GroupId::from_slice(&group_id_for(channel));
        MlsGroup::load(provider.storage(), &gid)
            .map_err(|e| format!("MLS storage error: {e}"))?
            .ok_or_else(|| format!("no MLS group for channel '{channel}'"))
    }
}

/// Serialize a fresh KeyPackage for out-of-band transport (the
/// private parts stay in the provider's storage).
pub(crate) fn new_key_package(
    provider: &VosProvider,
    credential: CredentialWithKey,
    signer: &SignatureKeyPair,
) -> Result<Vec<u8>, String> {
    let bundle = KeyPackage::builder()
        .build(CIPHERSUITE, provider, signer, credential)
        .map_err(|e| format!("KeyPackage build failed: {e}"))?;
    bundle
        .key_package()
        .tls_serialize_detached()
        .map_err(|e| format!("KeyPackage serialize failed: {e}"))
}

/// Validate a received serialized KeyPackage.
pub(crate) fn parse_key_package(
    provider: &VosProvider,
    bytes: &[u8],
) -> Result<KeyPackage, String> {
    use openmls::prelude::tls_codec::Deserialize as TlsDeserialize;
    let kp_in = KeyPackageIn::tls_deserialize(&mut &bytes[..])
        .map_err(|e| format!("KeyPackage deserialize failed: {e}"))?;
    kp_in
        .validate(provider.crypto(), ProtocolVersion::Mls10)
        .map_err(|e| format!("KeyPackage invalid: {e}"))
}

/// Build this member's Ed25519 signer from a host-seeded CSPRNG draw rather
/// than `SignatureKeyPair::new()`. The stock constructor draws from `OsRng`,
/// which would leave the signing identity as the one key not reproducible
/// from the seed (breaking the determinism the PVM port needs) and is
/// unavailable in a deterministic PVM at all. Any 32 bytes are a valid
/// Ed25519 secret, so the single draw fully determines the keypair.
pub(crate) fn derive_signer(provider: &VosProvider) -> Result<SignatureKeyPair, String> {
    use openmls_traits::random::OpenMlsRand;
    let mut sk = provider
        .rand()
        .random_array::<32>()
        .map_err(|e| format!("signer rng failure: {e}"))?;
    let signing = ed25519_dalek::SigningKey::from_bytes(&sk);
    let public = signing.verifying_key().to_bytes().to_vec();
    let pair = SignatureKeyPair::from_raw(CIPHERSUITE.signature_algorithm(), sk.to_vec(), public);
    sk.zeroize();
    Ok(pair)
}

#[cfg(test)]
mod tests {
    use super::*;
    use openmls::prelude::tls_codec::Deserialize as TlsDeserialize;

    // Distinct per-party seeds so each test identity draws a distinct
    // signature key and key stream — a shared seed would collide.
    const ALICE: u8 = 0xA1;
    const BOB: u8 = 0xB2;
    const CHARLIE: u8 = 0xC3;

    /// A fresh provider over an empty store, seeded deterministically so a
    /// test's draws are reproducible. Production opens reseed per boot from
    /// OS entropy (see `open_provider`); the determinism property itself is
    /// asserted in `crate::host_rand`'s unit tests.
    fn provider(seed_byte: u8) -> VosProvider {
        open_provider(&[], &[seed_byte; 32])
    }

    /// Reopen a party's provider from its persisted snapshot under the same
    /// seed — exercising the per-dispatch open/snapshot cycle.
    fn reopen(snapshot: &[u8], seed_byte: u8) -> VosProvider {
        open_provider(snapshot, &[seed_byte; 32])
    }

    /// #7: the Welcome routing token must be fresh per invite and must
    /// never equal the directory's public `kp_hash` — otherwise a holder
    /// of both the directory and the ctl chain could map a join back to a
    /// nickname (and link the same KeyPackage across channels).
    #[test]
    fn welcome_nonce_is_fresh_and_unlinkable() {
        let p = provider(ALICE);
        let n1 = welcome_nonce(&p).unwrap();
        let n2 = welcome_nonce(&p).unwrap();
        assert_ne!(n1, n2, "tokens must be fresh per invite");
        // A token derived from the public KeyPackage would equal this.
        assert_ne!(
            n1,
            msg_directory::kp_hash(b"any serialized key package"),
            "token must not equal the directory's public kp_hash",
        );
    }

    fn make_identity(provider: &VosProvider, name: &str) -> (CredentialWithKey, SignatureKeyPair) {
        let keys = derive_signer(provider).unwrap();
        keys.store(provider.storage()).unwrap();
        let credential = BasicCredential::new(name.as_bytes().to_vec());
        (
            CredentialWithKey {
                credential: credential.into(),
                signature_key: keys.public().to_vec().into(),
            },
            keys,
        )
    }

    /// Round-trip the provider through the persistence snapshot —
    /// a stored signer must come back readable.
    #[test]
    fn provider_snapshot_round_trips() {
        let p = provider(ALICE);
        let (_, keys) = make_identity(&p, "alice");
        let snapshot = snapshot_provider(&p);

        let restored = reopen(&snapshot, ALICE);
        let read = SignatureKeyPair::read(
            restored.storage(),
            keys.public(),
            CIPHERSUITE.signature_algorithm(),
        );
        assert!(read.is_some(), "signer must survive snapshot/restore");
        // Corrupt/empty snapshots fall back to a fresh storage map.
        assert!(
            reopen(&[], ALICE)
                .storage()
                .values
                .read()
                .unwrap()
                .is_empty()
        );
        assert!(
            reopen(&[1, 2, 3], ALICE)
                .storage()
                .values
                .read()
                .unwrap()
                .is_empty()
        );
    }

    /// A corrupt snapshot — including length fields engineered to
    /// overflow the running offset — must degrade to a fresh
    /// provider, never panic. Regression for the unchecked
    /// `at + len` arithmetic in decode_store.
    #[test]
    fn corrupt_snapshots_yield_a_fresh_provider() {
        let empty = |bytes: &[u8]| {
            reopen(bytes, CHARLIE)
                .storage()
                .values
                .read()
                .unwrap()
                .is_empty()
        };
        // count=1 but no following length fields.
        assert!(empty(&1u64.to_le_bytes()));
        // count=1, k_len claiming u64::MAX (would overflow at+len),
        // v_len=0, no body.
        let mut overflow = Vec::new();
        overflow.extend_from_slice(&1u64.to_le_bytes());
        overflow.extend_from_slice(&u64::MAX.to_le_bytes());
        overflow.extend_from_slice(&0u64.to_le_bytes());
        assert!(empty(&overflow));
        // count=1, k_len longer than the remaining bytes.
        let mut truncated = Vec::new();
        truncated.extend_from_slice(&1u64.to_le_bytes());
        truncated.extend_from_slice(&64u64.to_le_bytes());
        truncated.extend_from_slice(&0u64.to_le_bytes());
        truncated.extend_from_slice(b"short");
        assert!(empty(&truncated));
        // A real snapshot still round-trips after these.
        let p = provider(CHARLIE);
        make_identity(&p, "carol");
        let snap = snapshot_provider(&p);
        assert!(!empty(&snap));
    }

    /// The whole Phase-1 cryptographic flow offline, crossing the
    /// persistence boundary after every step (exactly what the
    /// per-dispatch open/snapshot cycle does): Alice creates the
    /// channel group, Bob publishes a KeyPackage, Alice
    /// adds + welcomes him, both exchange application messages as
    /// serialized wire bytes.
    #[test]
    fn group_flow_survives_snapshot_boundaries() {
        // Alice: identity + group, then persist.
        let alice = provider(ALICE);
        let (alice_cred, alice_keys) = make_identity(&alice, "alice");
        let gid = GroupId::from_slice(&group_id_for("general"));
        MlsGroup::new_with_group_id(
            &alice,
            &alice_keys,
            &create_config(),
            gid.clone(),
            alice_cred,
        )
        .unwrap();
        let alice_snap = snapshot_provider(&alice);

        // Bob: identity + KeyPackage, then persist.
        let bob = provider(BOB);
        let (bob_cred, bob_keys) = make_identity(&bob, "bob");
        let kp_bytes = new_key_package(&bob, bob_cred, &bob_keys).unwrap();
        let bob_snap = snapshot_provider(&bob);

        // Alice (fresh restore): validate Bob's KP, add, commit.
        let alice = reopen(&alice_snap, ALICE);
        let kp = parse_key_package(&alice, &kp_bytes).unwrap();
        let mut group = MlsGroup::load(alice.storage(), &gid).unwrap().unwrap();
        let (_commit, welcome_out, _gi) = group
            .add_members(&alice, &alice_keys, core::slice::from_ref(&kp))
            .unwrap();
        group.merge_pending_commit(&alice).unwrap();
        let welcome_bytes = welcome_out.to_bytes().unwrap();
        let alice_snap = snapshot_provider(&alice);

        // Bob (fresh restore): join from the Welcome wire bytes.
        let bob = reopen(&bob_snap, BOB);
        let mls_msg = MlsMessageIn::tls_deserialize(&mut &welcome_bytes[..]).unwrap();
        let MlsMessageBodyIn::Welcome(welcome) = mls_msg.extract() else {
            panic!("expected a welcome");
        };
        let mut bob_group = StagedWelcome::new_from_welcome(&bob, &join_config(), welcome, None)
            .unwrap()
            .into_group(&bob)
            .unwrap();
        assert_eq!(bob_group.members().count(), 2);
        let bob_snap = snapshot_provider(&bob);

        // Alice → Bob across the wire.
        let alice = reopen(&alice_snap, ALICE);
        let mut alice_group = MlsGroup::load(alice.storage(), &gid).unwrap().unwrap();
        let wire = alice_group
            .create_message(&alice, &alice_keys, b"hello bob")
            .unwrap()
            .to_bytes()
            .unwrap();

        let bob = reopen(&bob_snap, BOB);
        let (sender, text) = crate::tick::decrypt_app(&bob, &mut bob_group, &wire).unwrap();
        assert_eq!((sender.as_str(), text.as_str()), ("alice", "hello bob"));

        // Bob → Alice, each side restored from its latest snapshot.
        let wire_back = bob_group
            .create_message(&bob, &bob_keys, b"hi alice")
            .unwrap()
            .to_bytes()
            .unwrap();
        let (sender, text) =
            crate::tick::decrypt_app(&alice, &mut alice_group, &wire_back).unwrap();
        assert_eq!((sender.as_str(), text.as_str()), ("bob", "hi alice"));

        // Ciphertext privacy gate: the wire bytes never contain
        // the plaintext.
        let needle = b"hello bob";
        assert!(
            !wire.windows(needle.len()).any(|w| w == needle),
            "MLS wire bytes must not leak plaintext"
        );
    }

    /// The determinism acceptance gate: two providers booted from the SAME
    /// seed and boot context produce a byte-identical signing key and
    /// KeyPackage — the determinism the eventual PVM port relies on, and proof
    /// the seam (rand-swap + seed-derived signer) is complete for key material.
    ///
    /// Commit/Welcome *wire* bytes are deliberately NOT asserted: HPKE Seal
    /// draws its ephemeral KEM key from hpke-rs's own per-call RNG, not the
    /// provider, so those bytes stay non-deterministic until a custom
    /// `OpenMlsCrypto` seam lands. The group *secret* state still converges
    /// (see `losing_commit_…`'s `export_secret` assertion).
    #[test]
    fn same_seed_yields_identical_key_package() {
        let mint = |seed: [u8; 32]| {
            // Fixed boot token so the stream is reproducible here; production
            // opens reseed per boot from OS entropy.
            let p = VosProvider::new(HostRand::boot(&seed, &[0u8; 32], b"dev", 0, 0));
            let (cred, signer) = make_identity(&p, "zoe");
            let kp = new_key_package(&p, cred, &signer).unwrap();
            (signer.public().to_vec(), kp)
        };
        let (pk1, kp1) = mint([0x5A; 32]);
        let (pk2, kp2) = mint([0x5A; 32]);
        assert_eq!(pk1, pk2, "same seed must yield the same signing key");
        assert_eq!(kp1, kp2, "same seed must yield byte-identical KeyPackages");

        let (pk3, kp3) = mint([0x6B; 32]);
        assert_ne!(pk1, pk3, "a different seed must yield a different signer");
        assert_ne!(
            kp1, kp3,
            "a different seed must yield a different KeyPackage"
        );
    }

    // ── Sequenced-chain integration (real MsgCtl state machine) ──

    /// Handler futures never await anything external, so a single
    /// poll with a no-op waker resolves them.
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
        run(<msg_ctl::MsgCtl as vos::Message<M>>::handle(
            c, msg, &mut ctx,
        ))
    }

    fn submit(
        ctl: &mut msg_ctl::MsgCtl,
        epoch: u64,
        commit: &MlsMessageOut,
        welcome: Option<(&MlsMessageOut, [u8; 32])>,
    ) -> msg_ctl::CommitOutcome {
        let (welcome_bytes, hint) = match welcome {
            Some((w, h)) => (w.to_bytes().unwrap(), h.to_vec()),
            None => (Vec::new(), Vec::new()),
        };
        ctl_dispatch(
            ctl,
            msg_ctl::Commit {
                epoch,
                ts_ms: 0,
                commit_body: commit.to_bytes().unwrap(),
                welcome: welcome_bytes,
                welcome_hint: hint,
            },
        )
    }

    fn process_and_merge(provider: &VosProvider, group: &mut MlsGroup, wire: &[u8]) {
        let msg = MlsMessageIn::tls_deserialize(&mut &wire[..]).unwrap();
        let processed = group
            .process_message(provider, msg.try_into_protocol_message().unwrap())
            .unwrap();
        match processed.into_content() {
            ProcessedMessageContent::StagedCommitMessage(staged) => {
                group.merge_staged_commit(provider, *staged).unwrap();
            }
            _ => panic!("expected a staged commit"),
        }
    }

    /// The Phase-2 property that breaks pure-CRDT designs: two
    /// members commit concurrently at the same epoch; the sequencer
    /// accepts exactly one, the loser catches up off the chain and
    /// re-issues, and both converge to identical group state.
    #[test]
    fn losing_commit_is_rejected_and_reissues_to_convergence() {
        let mut ctl = msg_ctl::MsgCtl::new();

        // Group bootstrap, all commits through the sequencer:
        // alice creates at epoch 0, adds bob (epoch 0 → 1).
        let alice = provider(ALICE);
        let (alice_cred, alice_keys) = make_identity(&alice, "alice");
        let gid = GroupId::from_slice(&group_id_for("contended"));
        let mut alice_group =
            MlsGroup::new_with_group_id(&alice, &alice_keys, &create_config(), gid, alice_cred)
                .unwrap();

        let bob = provider(BOB);
        let (bob_cred, bob_keys) = make_identity(&bob, "bob");
        let bob_kp = new_key_package(&bob, bob_cred, &bob_keys).unwrap();
        let kp = parse_key_package(&alice, &bob_kp).unwrap();
        let (add_commit, welcome, _) = alice_group
            .add_members(&alice, &alice_keys, core::slice::from_ref(&kp))
            .unwrap();
        let outcome = submit(
            &mut ctl,
            0,
            &add_commit,
            Some((&welcome, msg_directory::kp_hash(&bob_kp))),
        );
        assert_eq!(outcome.status, msg_ctl::STATUS_OK);
        alice_group.merge_pending_commit(&alice).unwrap();

        let row = ctl_dispatch(&mut ctl, msg_ctl::CommitAt { epoch: 0 }).unwrap();
        let welcome_in = MlsMessageIn::tls_deserialize(&mut &row.welcome[..]).unwrap();
        let MlsMessageBodyIn::Welcome(w) = welcome_in.extract() else {
            panic!("expected welcome");
        };
        let mut bob_group = StagedWelcome::new_from_welcome(&bob, &join_config(), w, None)
            .unwrap()
            .into_group(&bob)
            .unwrap();
        assert_eq!(alice_group.epoch().as_u64(), 1);
        assert_eq!(bob_group.epoch().as_u64(), 1);

        // The race: both commit at epoch 1. Alice adds charlie;
        // bob rotates his keys. Alice's reaches the sequencer
        // first.
        let charlie = provider(CHARLIE);
        let (charlie_cred, charlie_keys) = make_identity(&charlie, "charlie");
        let charlie_kp = new_key_package(&charlie, charlie_cred, &charlie_keys).unwrap();
        let ckp = parse_key_package(&alice, &charlie_kp).unwrap();
        let (alice_commit, charlie_welcome, _) = alice_group
            .add_members(&alice, &alice_keys, core::slice::from_ref(&ckp))
            .unwrap();
        let (bob_commit, none_welcome, _) = bob_group
            .self_update(&bob, &bob_keys, LeafNodeParameters::default())
            .unwrap()
            .into_contents();
        assert!(none_welcome.is_none());

        let outcome = submit(
            &mut ctl,
            1,
            &alice_commit,
            Some((&charlie_welcome, msg_directory::kp_hash(&charlie_kp))),
        );
        assert_eq!(outcome.status, msg_ctl::STATUS_OK);
        alice_group.merge_pending_commit(&alice).unwrap();

        let outcome = submit(&mut ctl, 1, &bob_commit, None);
        assert_eq!(
            outcome.status,
            msg_ctl::STATUS_EPOCH_TAKEN,
            "the second commit for epoch 1 must lose"
        );

        // Loser path: clear the pending commit, process the
        // winner off the chain, rebuild at the new epoch.
        bob_group.clear_pending_commit(bob.storage()).unwrap();
        let row = ctl_dispatch(&mut ctl, msg_ctl::CommitAt { epoch: 1 }).unwrap();
        process_and_merge(&bob, &mut bob_group, &row.commit_body);
        assert_eq!(bob_group.epoch().as_u64(), 2);

        let (bob_retry, none_welcome, _) = bob_group
            .self_update(&bob, &bob_keys, LeafNodeParameters::default())
            .unwrap()
            .into_contents();
        assert!(none_welcome.is_none());
        let outcome = submit(&mut ctl, 2, &bob_retry, None);
        assert_eq!(outcome.status, msg_ctl::STATUS_OK);
        bob_group.merge_pending_commit(&bob).unwrap();

        // Alice processes bob's re-issued commit off the chain.
        let row = ctl_dispatch(&mut ctl, msg_ctl::CommitAt { epoch: 2 }).unwrap();
        process_and_merge(&alice, &mut alice_group, &row.commit_body);

        assert_eq!(alice_group.epoch().as_u64(), 3);
        assert_eq!(bob_group.epoch().as_u64(), 3);
        assert_eq!(
            alice_group
                .export_secret(alice.crypto(), "convergence", &[], 32)
                .unwrap(),
            bob_group
                .export_secret(bob.crypto(), "convergence", &[], 32)
                .unwrap(),
            "both members must land on identical group state"
        );
    }

    /// Post-compromise security through removal: once the Remove
    /// commit lands, the evicted member's group goes inactive and
    /// later traffic is undecryptable to them.
    #[test]
    fn removed_member_cannot_decrypt_post_removal_traffic() {
        let alice = provider(ALICE);
        let (alice_cred, alice_keys) = make_identity(&alice, "alice");
        let gid = GroupId::from_slice(&group_id_for("evict"));
        let mut alice_group =
            MlsGroup::new_with_group_id(&alice, &alice_keys, &create_config(), gid, alice_cred)
                .unwrap();

        let bob = provider(BOB);
        let (bob_cred, bob_keys) = make_identity(&bob, "bob");
        let bob_kp = new_key_package(&bob, bob_cred, &bob_keys).unwrap();
        let kp = parse_key_package(&alice, &bob_kp).unwrap();
        let (_, welcome, _) = alice_group
            .add_members(&alice, &alice_keys, core::slice::from_ref(&kp))
            .unwrap();
        alice_group.merge_pending_commit(&alice).unwrap();
        let welcome_in =
            MlsMessageIn::tls_deserialize(&mut &welcome.to_bytes().unwrap()[..]).unwrap();
        let MlsMessageBodyIn::Welcome(w) = welcome_in.extract() else {
            panic!("expected welcome");
        };
        let mut bob_group = StagedWelcome::new_from_welcome(&bob, &join_config(), w, None)
            .unwrap()
            .into_group(&bob)
            .unwrap();

        // Alice evicts bob.
        let bob_index = alice_group
            .members()
            .find(|m| m.credential.serialized_content() == b"bob")
            .unwrap()
            .index;
        let (remove_commit, none_welcome, _) = alice_group
            .remove_members(&alice, &alice_keys, &[bob_index])
            .unwrap();
        assert!(none_welcome.is_none());
        alice_group.merge_pending_commit(&alice).unwrap();
        process_and_merge(&bob, &mut bob_group, &remove_commit.to_bytes().unwrap());
        assert!(!bob_group.is_active(), "bob's group must go inactive");
        assert_eq!(alice_group.members().count(), 1);

        // Post-removal traffic is noise to bob.
        let wire = alice_group
            .create_message(&alice, &alice_keys, b"after the eviction")
            .unwrap()
            .to_bytes()
            .unwrap();
        let result = crate::tick::decrypt_app(&bob, &mut bob_group, &wire);
        assert!(
            result.is_err(),
            "an evicted member must not decrypt post-removal traffic"
        );
    }
}
