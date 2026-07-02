//! Messenger actor — the E2EE edge of VOS messaging.
//!
//! Channels replicate as two PVM agents: `msg-<chan>-log`
//! (crdt-mode, the ciphertext envelope log) and `msg-<chan>-ctl`
//! (the sequenced MLS commit chain). Neither ever sees plaintext
//! or key material. This actor is where the
//! cryptography lives: it holds the member's MLS credential and
//! group state (RFC 9420 via mls-rs), encrypts on `send`,
//! decrypts on its poll `tick`, and keeps the decrypted
//! conversation in node-local actor state. It runs device-local
//! (`consistency = "local"`, never replicated), seeded once via the
//! host `device_secret` provisioning.
//!
//! Trust boundary: everything in this actor's state —
//! signature keys, ratchet secrets, plaintext history — is
//! device-local and never replicated. Peers, relays, and the
//! channel actors handle ciphertext only. The operator of *this*
//! node can read this node's plaintext: the standard end-to-end
//! assumption that your own device is yours.
//!
//! The invite flow is out-of-band, SimpleX-style: the invitee
//! prints a KeyPackage (`key_package`), hands it to the inviter
//! (link, QR, …), and the inviter's `invite` commits the
//! membership change; the Welcome rides the commit chain and the
//! invitee's `tick` picks it up by KeyPackage hash. The `msg-directory`
//! actor — sequenced single-use claims keyed by verified PeerId — is the
//! default invite path; the out-of-band hand-off coexists as a fallback.
//!
//! Why mls-rs (AWS) and not OpenMLS: this crate must also build as a
//! deterministic no_std riscv64 PVM actor (see the riscv64 dep flavor in
//! `Cargo.toml` and `vos/tests/messenger_transpile.rs`). OpenMLS is
//! irreducibly `std` — a non-optional `rayon` dependency (TreeKEM `par_iter`,
//! gated only against wasm32, so the PVM target would still pull it),
//! `SystemTime` in KeyPackage lifetimes, `std::collections` throughout — and,
//! decisively, its HPKE-Seal ephemeral KEM key is drawn by hpke-rs's own
//! per-call `from_entropy` RNG, a seam *structurally unreachable* through the
//! provider, so the deterministic CSPRNG could never cover it. mls-rs makes
//! std/rayon optional and routes both `kem_generate` and the HPKE ephemeral
//! through `DhType::generate`, so a custom `CipherSuiteProvider` closes every
//! entropy seam. (There was never an OpenMLS deployment to migrate from; this
//! is an initial-library choice.) A process-global `getrandom` custom backend
//! was rejected for the entropy seam: it is too broad (it would capture
//! libp2p/TLS/everything) yet too narrow (it intercepts only the one seed draw,
//! not the per-message provider draws the deterministic provider must cover).
//!
//! Besides the crypto/protocol submodules (`clients`, `crypto_provider`,
//! `host_rand`, `identity`, `mls`, `store`, `tick`), [`rows`] holds the
//! persisted state shapes (`ChannelEntry`, `PlainMessage`) and [`runtime`]
//! the PVM no_std environment shims (critical-section, getrandom). The actor
//! struct + its `#[messages]` handlers stay here.

use vos::prelude::*;

mod clients;
mod crypto_provider;
mod host_rand;
mod identity;
mod mls;
mod rows;
mod runtime;
mod store;
mod tick;

use clients::{
    ctl_commit, dir_announce_channel, dir_channels, dir_claim_kp, dir_publish_kp, dir_release_kp,
    hex_decode, hex_encode, log_post, reg_agents, reg_install, resolve,
};
use mls::{new_key_package, parse_key_package, welcome_nonce};
use mls_rs::ExtensionList;
pub use rows::{ChannelEntry, PlainMessage};

/// Per-channel agent naming convention. The manifest installs the
/// pair under these names; `create`/`join` address them by channel
/// name alone.
pub fn log_agent_name(channel: &str) -> String {
    format!("msg-{channel}-log")
}
pub fn ctl_agent_name(channel: &str) -> String {
    format!("msg-{channel}-ctl")
}

/// Whether `b` is a libp2p ed25519 PeerId (the fixed 38-byte
/// identity-multihash `00 24 08 01 12 20 ‖ key[32]`) — how an invite target is
/// distinguished from a (much larger) raw KeyPackage.
fn is_peer_id(b: &[u8]) -> bool {
    b.len() == 38 && b[..6] == [0x00, 0x24, 0x08, 0x01, 0x12, 0x20]
}

/// The per-space directory agent's instance name.
pub const DIRECTORY_AGENT: &str = "msg-directory";

/// KeyPackages auto-published on `register` — enough invites
/// before the member needs a replenish.
const REGISTER_KP_COUNT: usize = 3;

// ── Actor ─────────────────────────────────────────────────────────

#[actor]
pub struct Messenger {
    /// Operator-chosen display name, carried (non-authoritatively) in the
    /// MLS credential. Empty until `register`.
    nickname: String,
    /// This member's Ed25519 public key — a stable identity reference,
    /// reproducible from the seed (the signer is derived, not stored).
    signature_key: Vec<u8>,
    /// The operator's verified space PeerId (libp2p multihash bytes),
    /// the authoritative identity this member's MLS key is bound to. Empty
    /// until `bind_identity`.
    peer_id: Vec<u8>,
    /// The operator's binding cert: their identity key signing over
    /// `(mls_pubkey ‖ peer_id ‖ space_id)`. Travels in the MLS credential so
    /// any peer validating a leaf can confirm the key↔PeerId binding. Empty
    /// until `bind_identity`.
    binding_cert: Vec<u8>,
    /// The space id the binding cert is scoped to (32 bytes). Empty
    /// until `bind_identity`.
    space_id: Vec<u8>,
    /// Snapshot of the mls-rs storage providers — the group ratchet state
    /// (`GroupStateStorage`) and KeyPackage private parts
    /// (`KeyPackageStorage`). See `mls::open_stores` / `store::snapshot`.
    /// The signer is NOT here: it is derived from `csprng_seed`.
    mls_store: Vec<u8>,
    /// The 32-byte secret root of the host-seeded MLS CSPRNG (the only
    /// confidentiality source for freshly-drawn key material). Provisioned
    /// once — by an explicit `seed` message, or lazily from OS entropy on
    /// `register` — and held in this node-local, non-replicated state, never
    /// in the replicated DAG. Empty until provisioned. See
    /// `crate::host_rand` for the construction and why a replayer who lacks
    /// this seed cannot predict the stream despite PVM determinism.
    csprng_seed: Vec<u8>,
    /// Count of KeyPackages we've published and not yet seen consumed.
    /// Just a tally: a join consumes exactly one published KP, and the
    /// joiner can't influence *which* one an inviter claims, so the
    /// records are fungible — there's nothing to identify, only to
    /// count (a Welcome is matched by trial-decryption, not by a tag).
    published_kp_count: u32,
    channels: Vec<ChannelEntry>,
}

#[messages]
impl Messenger {
    pub fn new() -> Self {
        Messenger {
            nickname: String::new(),
            signature_key: Vec::new(),
            peer_id: Vec::new(),
            binding_cert: Vec::new(),
            space_id: Vec::new(),
            mls_store: Vec::new(),
            csprng_seed: Vec::new(),
            published_kp_count: 0,
            channels: Vec::new(),
        }
    }

    /// The identity binding for this member, or an error if `bind_identity`
    /// hasn't run yet. Every MLS client built for an operation carries it.
    fn binding(&self) -> core::result::Result<crate::identity::Binding, String> {
        if self.peer_id.is_empty() || self.binding_cert.is_empty() {
            return Err("not bound — run `messenger register` (binds your space \
                        identity) before this operation"
                .into());
        }
        Ok(crate::identity::Binding {
            peer_id: self.peer_id.clone(),
            display_name: self.nickname.clone(),
            cert: self.binding_cert.clone(),
        })
    }

    /// The bound space id as a fixed array.
    fn space_id_array(&self) -> core::result::Result<[u8; 32], String> {
        self.space_id
            .as_slice()
            .try_into()
            .map_err(|_| String::from("binding space id is malformed"))
    }

    /// The `(binding, space_id)` pair every MLS client build needs.
    fn bound_inputs(&self) -> core::result::Result<(crate::identity::Binding, [u8; 32]), String> {
        Ok((self.binding()?, self.space_id_array()?))
    }

    /// Restore the mls-rs storage providers (group state + key packages) from
    /// this node's persisted snapshot. The messenger keeps the returned stores
    /// alongside the Client built over them (via [`mls::build_bound_client`]) so it
    /// can [`store::snapshot`] them back after a mutating MLS op.
    ///
    /// Cost: each mutating op restores the full store, rebuilds the Client over
    /// it (re-derives the signer, reconstructs both providers + the CSPRNG), and
    /// re-serializes the whole store back — O(total MLS state) per dispatch.
    /// Sound at current group sizes; a scalability ceiling for a node in many or
    /// large groups. The Client can't be cached across dispatches because actor
    /// state must round-trip to bytes between messages.
    pub(crate) fn open_stores(&self) -> store::VosStores {
        mls::open_stores(&self.mls_store)
    }

    /// Provision the CSPRNG secret seed (the MLS confidentiality root) into
    /// node-local state, mirroring the clerk-bridge `bootstrap(ivk_secret)`
    /// precedent: a runtime secret injected by message, never carried in the
    /// public `AgentConfig.storage` install args. One-shot — a second call
    /// is refused so the stream can never be re-forked against already-drawn
    /// material. `register` provisions one from OS entropy if none was set,
    /// so this is for hosts that want to control the root explicitly (and is
    /// mandatory on the PVM actor build, where OS entropy is absent).
    ///
    /// One-shot and 32-byte-validated; the caller-role gate (Admin/System)
    /// is an open hardening decision, deferred with the rest of the seed
    /// provisioning model.
    #[msg]
    async fn seed(&mut self, seed_bytes: Vec<u8>) -> String {
        if !self.csprng_seed.is_empty() {
            return "seed already provisioned".into();
        }
        if seed_bytes.len() != 32 {
            return format!("seed must be exactly 32 bytes, got {}", seed_bytes.len());
        }
        self.csprng_seed = seed_bytes;
        "seed provisioned".into()
    }

    /// Create this node's messaging identity: a fresh seed-derived Ed25519
    /// MLS signer under display name `nickname`. Returns `mls_pubkey=<hex>`
    /// so the caller can have the operator sign a binding cert over it and
    /// call [`bind_identity`](Self::bind_identity) — KeyPackages aren't
    /// published until then (they carry the identity-bound credential).
    #[msg(cli)]
    async fn register(&mut self, nickname: String, _ctx: &mut Context<Self>) -> String {
        if !self.nickname.is_empty() {
            return format!("already registered as '{}'", self.nickname);
        }
        if nickname.is_empty() {
            return "usage: register <nickname>".into();
        }
        // Provision the CSPRNG root before the first draw if a host didn't
        // already do so via `seed` — on the host build this is fresh OS
        // entropy. The PVM actor has no OS entropy, so the seed is mandatory:
        // `seed` must be called first (the deterministic-port requirement).
        #[cfg(not(target_arch = "riscv64"))]
        if self.csprng_seed.is_empty() {
            let mut s = [0u8; 32];
            if getrandom::getrandom(&mut s).is_err() {
                return "seed generation failed: OS entropy unavailable".into();
            }
            self.csprng_seed = s.to_vec();
        }
        #[cfg(target_arch = "riscv64")]
        if self.csprng_seed.is_empty() {
            return "seed not provisioned — call `seed` with 32 bytes before \
                    `register` (a PVM actor has no OS entropy)"
                .into();
        }
        // The Ed25519 signing identity is derived deterministically from the
        // seed (not OsRng), so it is reproducible and under the same secret
        // root as the rest of the key material — see `mls::derive_signer`.
        self.signature_key = match mls::signer_public(&self.csprng_seed) {
            Ok(p) => p,
            Err(e) => return format!("key generation failed: {e}"),
        };
        self.nickname = nickname;
        // The caller signs a binding cert over this key and calls
        // `bind_identity`; publishing waits for the bound credential.
        format!("mls_pubkey={}", hex_encode(&self.signature_key))
    }

    /// Bind this member's MLS key to the operator's verified space PeerId.
    /// The operator's CLI identity key signs a cert over
    /// `(mls_pubkey ‖ peer_id ‖ space_id)`; we verify it against our own
    /// derived MLS key, store the binding, and publish the now
    /// identity-bound KeyPackages so peers can invite us by PeerId. A
    /// member can't be impersonated: a KeyPackage's credential carries this
    /// cert, and an inviter (and every group member, via the MLS leaf
    /// validator) refuses any MLS key the claimed PeerId never signed for.
    #[msg(cli)]
    async fn bind_identity(
        &mut self,
        peer_id: Vec<u8>,
        space_id: Vec<u8>,
        cert: Vec<u8>,
        ctx: &mut Context<Self>,
    ) -> String {
        if self.nickname.is_empty() {
            return "not registered — run `register` first".into();
        }
        if !self.peer_id.is_empty() {
            return format!("already bound to peer {}", hex_encode(&self.peer_id));
        }
        let space_arr: [u8; 32] = match space_id.as_slice().try_into() {
            Ok(a) => a,
            Err(_) => return "space_id must be 32 bytes".into(),
        };
        if !crate::identity::verify_binding(&self.signature_key, &peer_id, &cert, &space_arr) {
            return "binding cert does not verify against this member's MLS key \
                    — wrong operator key, peer id, or space id"
                .into();
        }
        self.peer_id = peer_id;
        self.binding_cert = cert;
        self.space_id = space_id;
        match self.stock_directory(ctx, REGISTER_KP_COUNT).await {
            Ok(n) => format!(
                "bound to peer {} ({n} key packages published)",
                hex_encode(&self.peer_id),
            ),
            Err(e) => format!(
                "bound to peer {} — directory unavailable ({e}); \
                 use `key_package` for out-of-band invites",
                hex_encode(&self.peer_id),
            ),
        }
    }

    /// Mint a KeyPackage and print it hex-encoded for out-of-band
    /// delivery to an inviter. One KeyPackage admits one join.
    #[msg(cli)]
    async fn key_package(&mut self, ctx: &mut Context<Self>) -> String {
        let (binding, space_id) = match self.bound_inputs() {
            Ok(x) => x,
            Err(e) => return e,
        };
        let beacon = crate::clients::chronos_beacon(ctx).await;
        let stores = self.open_stores();
        let client = match mls::build_bound_client_hedged(
            &binding,
            space_id,
            &self.csprng_seed,
            &stores,
            beacon,
        ) {
            Ok(c) => c,
            Err(e) => return e,
        };
        let kp_bytes = match new_key_package(&client, now_ms()) {
            Ok(b) => b,
            Err(e) => return e,
        };
        self.published_kp_count += 1;
        self.mls_store = store::snapshot(&stores);
        hex_encode(&kp_bytes)
    }

    /// Create a channel: a fresh MLS group with this member as its
    /// only occupant. When the channel's `msg-<name>-log` /
    /// `msg-<name>-ctl` agents aren't installed yet (no manifest
    /// entry), they're installed here — program rows cloned from an
    /// existing channel pair, fresh replication ids — and the
    /// host's spawn-reconcile brings them up within a few seconds
    /// on every member's node. Installing is Admin-gated; the
    /// pre-installed (manifest) path needs no role.
    #[msg(cli)]
    async fn create(&mut self, channel: String, ctx: &mut Context<Self>) -> String {
        if self.channel_index(&channel).is_some() {
            return format!("channel '{channel}' already known");
        }
        if let Err(e) = self.ensure_channel_agents(&channel, ctx).await {
            return e;
        }
        let (binding, space_id) = match self.bound_inputs() {
            Ok(x) => x,
            Err(e) => return e,
        };
        let beacon = crate::clients::chronos_beacon(ctx).await;
        let stores = self.open_stores();
        let client = match mls::build_bound_client_hedged(
            &binding,
            space_id,
            &self.csprng_seed,
            &stores,
            beacon,
        ) {
            Ok(c) => c,
            Err(e) => return e,
        };
        let mut group = match client.create_group_with_id(
            mls::group_id_for(&channel).to_vec(),
            ExtensionList::default(),
            ExtensionList::default(),
            Some(mls::mls_time(now_ms())),
        ) {
            Ok(g) => g,
            Err(e) => return format!("group creation failed: {e:?}"),
        };
        if let Err(e) = group.write_to_storage() {
            return format!("persisting group failed: {e:?}");
        }
        self.mls_store = store::snapshot(&stores);
        self.channels.push(ChannelEntry {
            name: channel.clone(),
            joined: true,
            removed: false,
            desynced: false,
            join_epoch: 0,
            next_epoch: 0,
            cursor_lamport: 0,
            cursor_id: Vec::new(),
            max_lamport: 0,
            own_ids: Vec::new(),
            messages: Vec::new(),
        });

        // Announce for discovery — best effort, the channel works
        // without a directory.
        let announced = async {
            let dir_id = resolve(ctx, DIRECTORY_AGENT).await?;
            dir_announce_channel(ctx, dir_id, &channel, &self.nickname).await
        }
        .await;
        match announced {
            Ok(msg_directory::Status::Ok) => format!("channel '{channel}' created and announced"),
            Ok(msg_directory::Status::Exists) => format!(
                "channel '{channel}' created — a channel of that name was already announced"
            ),
            Ok(other) => format!("channel '{channel}' created (announce failed: {other})"),
            Err(e) => format!("channel '{channel}' created (no directory: {e})"),
        }
    }

    /// Channels announced in this space's directory.
    #[msg(cli)]
    async fn channels(&self, ctx: &mut Context<Self>) -> String {
        let dir_id = match resolve(ctx, DIRECTORY_AGENT).await {
            Ok(id) => id,
            Err(e) => return format!("no directory: {e}"),
        };
        let mut out = String::new();
        let mut from = 0u64;
        loop {
            let rows = match dir_channels(ctx, dir_id, from, 64).await {
                Ok(rows) => rows,
                Err(e) => return e,
            };
            if rows.is_empty() {
                break;
            }
            from += rows.len() as u64;
            for row in rows {
                out.push_str(&format!("{} (created by {})\n", row.name, row.creator));
            }
        }
        if out.is_empty() {
            out.push_str("(no channels announced)");
        }
        out
    }

    /// Start watching a channel for a Welcome addressed to one of
    /// our published KeyPackages; `tick` completes the join.
    #[msg(cli)]
    async fn join(&mut self, channel: String) -> String {
        if self.nickname.is_empty() {
            return "not registered — run `messenger register <nickname>` first".into();
        }
        if self.channel_index(&channel).is_some() {
            return format!("channel '{channel}' already known");
        }
        if self.published_kp_count == 0 {
            return "no published KeyPackage — run `messenger key_package` and hand it to the inviter".into();
        }
        self.channels.push(ChannelEntry {
            name: channel.clone(),
            joined: false,
            removed: false,
            desynced: false,
            join_epoch: 0,
            next_epoch: 0,
            cursor_lamport: 0,
            cursor_id: Vec::new(),
            max_lamport: 0,
            own_ids: Vec::new(),
            messages: Vec::new(),
        });
        format!("watching '{channel}' for a welcome")
    }

    /// Add a member. `member` is either the invitee's verified PeerId
    /// (the 38-byte ed25519 multihash, hex) — resolved by claiming one of
    /// their directory-published KeyPackages by identity — or a raw hex
    /// KeyPackage from `key_package` on their node (out-of-band invite).
    /// Either way it becomes an MLS Add + Commit on the channel's sequenced
    /// chain, with the Welcome riding the same record.
    #[msg(cli)]
    async fn invite(&mut self, channel: String, member: String, ctx: &mut Context<Self>) -> String {
        if self.channel_index(&channel).is_none() {
            return format!("unknown channel '{channel}'");
        }
        // Identity-first: the target is either the member's verified
        // PeerId — claim their attested KeyPackage from the directory BY
        // identity — or a raw out-of-band KeyPackage (hundreds of bytes). A
        // PeerId is the fixed 38-byte ed25519 multihash; a KeyPackage is much
        // larger. A directory claim is remembered (with its owner key) so a
        // definitively-refused commit can return the package to the pool.
        let mut claimed_from: Option<(u32, String)> = None;
        let (kp_bytes, expected_peer) = match hex_decode(&member) {
            Some(b) if is_peer_id(&b) => {
                let dir_id = match resolve(ctx, DIRECTORY_AGENT).await {
                    Ok(id) => id,
                    Err(e) => return format!("can't reach the directory: {e}"),
                };
                let owner = hex_encode(&b);
                match dir_claim_kp(ctx, dir_id, &owner).await {
                    Ok(Some(bytes)) => {
                        claimed_from = Some((dir_id, owner));
                        (bytes, Some(b))
                    }
                    Ok(None) => {
                        return "no key packages published for that identity — ask them \
                                to run `messenger register`, or pass a key-package hex \
                                for an out-of-band invite"
                            .into();
                    }
                    Err(e) => return e,
                }
            }
            Some(b) if b.len() > 64 => (b, None),
            _ => return "invite target must be a peer id or a key-package hex".into(),
        };

        // Refuse a KeyPackage whose credential isn't a real enrolled member's,
        // and — on a directory claim — one that doesn't match the identity we
        // asked for (a substituted KeyPackage under a victim's name).
        if let Err(e) = self
            .verify_invite_target(ctx, &kp_bytes, expected_peer.as_deref())
            .await
        {
            if let Some((dir_id, owner)) = &claimed_from {
                let hash = msg_directory::kp_hash(&kp_bytes);
                let _ = dir_release_kp(ctx, *dir_id, owner, hash).await;
            }
            return e;
        }

        match self
            .commit_chain_op(
                ctx,
                &channel,
                ChainOp::Add {
                    kp_bytes: &kp_bytes,
                },
            )
            .await
        {
            Ok(epoch) => format!("invited — '{channel}' now at epoch {epoch}"),
            Err(e) => {
                // Compensate ONLY definite refusals: after an
                // indeterminate (transport) failure the commit may
                // have landed, and re-arming the package would hand
                // out a consumed KeyPackage.
                if let (Some((dir_id, owner)), ChainErr::Refused(_)) = (&claimed_from, &e) {
                    let hash = msg_directory::kp_hash(&kp_bytes);
                    if let Err(release_err) = dir_release_kp(ctx, *dir_id, owner, hash).await {
                        log::warn!("couldn't return the claimed key package: {release_err}");
                    }
                }
                e.into_message()
            }
        }
    }

    /// Verify a claimed/supplied KeyPackage is a real identity-bound, enrolled
    /// member's — and, when `expected_peer` is set (a directory claim by
    /// PeerId), that its credential actually binds to that identity. This is
    /// the inviter-side identity binding check: the substitution attack (publish a KP under
    /// a victim's directory name) is caught here, before the member is added.
    async fn verify_invite_target(
        &self,
        ctx: &mut Context<Self>,
        kp_bytes: &[u8],
        expected_peer: Option<&[u8]>,
    ) -> core::result::Result<(), String> {
        let kp = mls::parse_key_package(kp_bytes)?
            .into_key_package()
            .ok_or_else(|| String::from("not a key package"))?;
        let si = kp.signing_identity();
        let mls_pubkey = si.signature_key.as_bytes().to_vec();
        let dec = crate::identity::member_binding(si)
            .ok_or_else(|| String::from("key package carries no VOS identity credential"))?;
        let space_id = self.space_id_array()?;
        if !crate::identity::verify_binding(&mls_pubkey, &dec.peer_id, &dec.cert, &space_id) {
            return Err("key package's identity binding does not verify — refusing".into());
        }
        if let Some(expected) = expected_peer
            && dec.peer_id != expected
        {
            return Err("the directory returned a key package for a different identity \
                        than requested — refusing (possible substitution)"
                .into());
        }
        if !crate::clients::reg_is_member(ctx, &dec.peer_id).await? {
            return Err("that identity is not an enrolled member of this space".into());
        }
        Ok(())
    }

    /// Evict a member. MLS post-compromise security does the real
    /// work: the Remove commit rotates the group's secrets, so the
    /// removed member's keys decrypt nothing sent after it.
    #[msg(cli)]
    async fn remove(
        &mut self,
        channel: String,
        nickname: String,
        ctx: &mut Context<Self>,
    ) -> String {
        if self.channel_index(&channel).is_none() {
            return format!("unknown channel '{channel}'");
        }
        if nickname == self.nickname {
            return "refusing to remove yourself — have another member remove you".into();
        }
        match self
            .commit_chain_op(
                ctx,
                &channel,
                ChainOp::Remove {
                    nickname: &nickname,
                },
            )
            .await
        {
            Ok(epoch) => format!("removed '{nickname}' — '{channel}' now at epoch {epoch}"),
            Err(e) => e.into_message(),
        }
    }

    /// Rotate our own leaf keys (post-compromise heal): anyone who
    /// captured this device's secrets loses the channel from the
    /// new epoch on.
    #[msg(cli)]
    async fn update(&mut self, channel: String, ctx: &mut Context<Self>) -> String {
        if self.channel_index(&channel).is_none() {
            return format!("unknown channel '{channel}'");
        }
        match self
            .commit_chain_op(ctx, &channel, ChainOp::SelfUpdate)
            .await
        {
            Ok(epoch) => format!("rotated keys — '{channel}' now at epoch {epoch}"),
            Err(e) => e.into_message(),
        }
    }

    /// Encrypt `text` to the channel's current epoch and append it
    /// to the replicated ciphertext log.
    #[msg(cli)]
    async fn send(&mut self, channel: String, text: String, ctx: &mut Context<Self>) -> String {
        let Some(i) = self.channel_index(&channel) else {
            return format!("unknown channel '{channel}'");
        };
        if !self.channels[i].joined {
            return format!("not joined to '{channel}' yet");
        }
        if self.channels[i].desynced {
            // A degraded channel is read-only at its last good epoch (the
            // commit chain is bricked; see `tick::channel_drain_plan`). The
            // local group can still technically encrypt at that stale epoch,
            // but its membership can no longer be rotated — an eviction whose
            // commit was lost would never take effect — so emitting fresh
            // ciphertext could leak to a member who should have been removed.
            // Refuse, matching the membership-op gate in `commit_chain_op`.
            return format!(
                "channel '{channel}' is degraded (commit chain bricked) — it is \
                 read-only at the last good epoch; re-create or re-join to repair \
                 before sending"
            );
        }
        let (binding, space_id) = match self.bound_inputs() {
            Ok(x) => x,
            Err(e) => return e,
        };
        let beacon = crate::clients::chronos_beacon(ctx).await;
        let stores = self.open_stores();
        let client = match mls::build_bound_client_hedged(
            &binding,
            space_id,
            &self.csprng_seed,
            &stores,
            beacon,
        ) {
            Ok(c) => c,
            Err(e) => return e,
        };
        let mut group = match mls::load_group(&client, &channel) {
            Ok(g) => g,
            Err(e) => return e,
        };
        let msg_out = match group.encrypt_application_message(text.as_bytes(), Vec::new()) {
            Ok(m) => m,
            Err(e) => return format!("encryption failed: {e:?}"),
        };
        let Ok(body) = msg_out.to_bytes() else {
            return "serializing message failed".into();
        };
        let epoch = group.current_epoch();
        // Saturating: a poisoned channel whose lamports were driven
        // to u64::MAX must never panic (debug) or wrap to 0 (which
        // msg-log rejects) and wedge sending. Worst case under
        // attack, messages pile at MAX ordered by id — degraded
        // ordering, never a dead send path.
        let lamport = self.channels[i].max_lamport.saturating_add(1);
        let ts_ms = now_ms();
        let id = msg_log::envelope_id(
            msg_log::EnvelopeKind::App as u8,
            epoch,
            lamport,
            ts_ms,
            &[0u8; 32],
            &body,
        );

        let log_id = match resolve(ctx, &log_agent_name(&channel)).await {
            Ok(id) => id,
            Err(e) => return e,
        };
        // Persist the advanced sender ratchet BEFORE publishing the
        // ciphertext. If we crash after the post lands but before
        // persisting, the next boot would re-derive this generation
        // and re-encrypt under the same AES-GCM nonce — a key-stream
        // reuse break. Snapshotting first means the persisted ratchet
        // is always at least as advanced as anything posted; a crash
        // after persist but before post merely skips a generation
        // (harmless — receivers tolerate gaps).
        if let Err(e) = group.write_to_storage() {
            return format!("persisting send ratchet failed: {e:?}");
        }
        self.mls_store = store::snapshot(&stores);
        if let Err(e) = log_post(ctx, log_id, epoch, lamport, ts_ms, body).await {
            return e;
        }
        let entry = &mut self.channels[i];
        entry.max_lamport = lamport;
        entry.own_ids.push(id);
        entry.messages.push(PlainMessage {
            lamport,
            ts_ms,
            sender: self.nickname.clone(),
            text,
        });
        "sent".into()
    }

    /// The decrypted conversation, oldest first.
    #[msg(cli)]
    async fn history(&self, channel: String, limit: u32) -> String {
        let Some(i) = self.channel_index(&channel) else {
            return format!("unknown channel '{channel}'");
        };
        let mut msgs = self.channels[i].messages.clone();
        msgs.sort_by(|a, b| (a.lamport, a.ts_ms, &a.sender).cmp(&(b.lamport, b.ts_ms, &b.sender)));
        let limit = if limit == 0 { 50 } else { limit as usize };
        let skip = msgs.len().saturating_sub(limit);
        let mut out = String::new();
        for m in &msgs[skip..] {
            out.push_str(&format!("[{}] {}: {}\n", m.lamport, m.sender, m.text));
        }
        if out.is_empty() {
            out.push_str("(no messages)");
        }
        out
    }

    /// One-line-per-channel summary of local messaging state.
    #[msg(cli)]
    async fn status(&self) -> String {
        let mut out = String::new();
        if self.nickname.is_empty() {
            out.push_str("identity: (unregistered)\n");
        } else {
            out.push_str(&format!("identity: {}\n", self.nickname));
        }
        out.push_str(&format!(
            "key packages published: {}\n",
            self.published_kp_count
        ));
        let stores = self.open_stores();
        let client = self.bound_inputs().ok().and_then(|(binding, space_id)| {
            mls::build_bound_client(&binding, space_id, &self.csprng_seed, &stores).ok()
        });
        for c in &self.channels {
            if c.desynced {
                out.push_str(&format!(
                    "channel {}: degraded — read-only at last good epoch, \
                     the commit chain is bricked ({} messages readable)\n",
                    c.name,
                    c.messages.len()
                ));
            } else if c.joined {
                let (epoch, members) = client
                    .as_ref()
                    .and_then(|cl| mls::load_group(cl, &c.name).ok())
                    .map(|g| (g.current_epoch(), g.roster().members_iter().count()))
                    .unwrap_or((0, 0));
                out.push_str(&format!(
                    "channel {}: joined, epoch {epoch}, {members} members, {} messages\n",
                    c.name,
                    c.messages.len()
                ));
            } else if c.removed {
                out.push_str(&format!(
                    "channel {}: removed — awaiting re-invite ({} messages kept)\n",
                    c.name,
                    c.messages.len()
                ));
            } else {
                out.push_str(&format!("channel {}: waiting for welcome\n", c.name));
            }
        }
        if self.channels.is_empty() {
            out.push_str("(no channels)\n");
        }
        out
    }

    /// Poll loop (manifest `tick_ms`): advance commit chains, then
    /// decrypt new log envelopes.
    #[msg]
    async fn tick(&mut self, ctx: &mut Context<Self>) {
        tick::tick_channels(self, ctx).await;
    }

    /// On-demand drain: one full tick pass, now. Lets an operator
    /// (or a test) pull in pending welcomes/commits/messages
    /// without waiting out — or even configuring — the periodic
    /// `tick_ms`.
    #[msg(cli)]
    async fn sync(&mut self, ctx: &mut Context<Self>) -> String {
        tick::tick_channels(self, ctx).await;
        "synced".into()
    }
}

/// The messenger's actor [`vos::Context`] — threaded through every
/// helper that reaches the channel actors over the host invoke path
/// (`ask_raw` on the PVM actor, `ask_dispatch` on the host test build).
pub(crate) type MsgrCtx = vos::Context<Messenger>;

/// A membership change to commit onto the channel's sequenced
/// chain. Carried as a description (not a built commit) so a lost
/// race can rebuild the same operation against the new epoch.
enum ChainOp<'a> {
    Add { kp_bytes: &'a [u8] },
    Remove { nickname: &'a str },
    SelfUpdate,
}

/// How a failed chain op relates to the channel's chain. `Refused`
/// is a definitive no — local validation or the sequencer rejected
/// the operation and nothing landed, so compensating actions (like
/// releasing a claimed KeyPackage) are safe. `Indeterminate` means
/// the submission itself failed in transit: the commit MAY have
/// been accepted, so compensation must not fire.
enum ChainErr {
    Refused(String),
    Indeterminate(String),
}

impl ChainErr {
    fn into_message(self) -> String {
        match self {
            Self::Refused(m) | Self::Indeterminate(m) => m,
        }
    }
}

/// Every error produced *before* the commit reaches the sequencer
/// (resolution, MLS build, serialization, decoded refusals) is a
/// definitive `Refused`; only the `ctl_commit` transport failure is
/// marked `Indeterminate`, explicitly, at its call site.
impl From<String> for ChainErr {
    fn from(m: String) -> Self {
        Self::Refused(m)
    }
}

impl Messenger {
    fn channel_index(&self, name: &str) -> Option<usize> {
        self.channels.iter().position(|c| c.name == name)
    }

    /// Make sure the channel's `msg-<chan>-{log,ctl}` registry rows
    /// exist, installing whichever half is missing. Program identity
    /// comes from any already-installed `msg-*-log` / `msg-*-ctl`
    /// row (the manifest installs the first channel's pair, so a
    /// template always exists in a working space); each new agent
    /// gets a fresh random replication id, which peers pick up from
    /// the CRDT-synced row. Installed rows spawn via the host's
    /// spawn-reconcile — a send/invite racing that window answers
    /// "unreachable" and succeeds on retry.
    async fn ensure_channel_agents(
        &self,
        channel: &str,
        ctx: &mut Context<Self>,
    ) -> core::result::Result<(), String> {
        let log_name = log_agent_name(channel);
        let ctl_name = ctl_agent_name(channel);
        let log_missing = resolve(ctx, &log_name).await.is_err();
        let ctl_missing = resolve(ctx, &ctl_name).await.is_err();
        if !log_missing && !ctl_missing {
            return Ok(());
        }

        let rows = reg_agents(ctx).await.map_err(|e| {
            format!("channel agents not installed and the catalog is unavailable: {e}")
        })?;
        let template_for = |suffix: &str| {
            rows.iter()
                .find(|r| r.instance_name.starts_with("msg-") && r.instance_name.ends_with(suffix))
        };
        // Resolve every needed template BEFORE installing anything:
        // a missing template after the first install would leave a
        // half-pair of registry rows behind, replicated space-wide.
        let mut installs = Vec::new();
        for (missing, name, suffix) in [
            (log_missing, &log_name, "-log"),
            (ctl_missing, &ctl_name, "-ctl"),
        ] {
            if !missing {
                continue;
            }
            let Some(template) = template_for(suffix) else {
                return Err(format!(
                    "no installed msg-*{suffix} agent to clone program rows from — \
                     declare one channel in the space manifest first"
                ));
            };
            installs.push((name, template));
        }
        for (name, template) in installs {
            let rep_id = mls::fresh_replication_id()?;
            match reg_install(ctx, name, template, rep_id).await? {
                // EXISTS: someone else's create won the race (or a
                // peer's row synced in) — the post-condition holds.
                space_registry::Status::Ok | space_registry::Status::InstanceExists => {}
                code => return Err(format!("installing '{name}' failed (status {code})")),
            }
        }
        Ok(())
    }

    /// Mint `n` KeyPackages and publish them to the space
    /// directory, tallying them locally. Mints nothing when the
    /// directory is unreachable — out-of-band `key_package` remains
    /// the fallback.
    async fn stock_directory(
        &mut self,
        ctx: &mut Context<Self>,
        n: usize,
    ) -> core::result::Result<usize, String> {
        let dir_id = resolve(ctx, DIRECTORY_AGENT).await?;
        let (binding, space_id) = self.bound_inputs()?;
        // Published under the verified PeerId (hex), so an inviter claims by
        // identity — not a free-form nickname.
        let owner = hex_encode(&self.peer_id);
        // One beacon for the whole batch — every KeyPackage in this dispatch
        // hedges under the same finalized round.
        let beacon = crate::clients::chronos_beacon(ctx).await;
        // Every iteration propagates its errors with `?`, so reaching the
        // end means all `n` packages published.
        for _ in 0..n {
            let stores = self.open_stores();
            let client = mls::build_bound_client_hedged(
                &binding,
                space_id,
                &self.csprng_seed,
                &stores,
                beacon,
            )?;
            let kp_bytes = new_key_package(&client, now_ms())?;
            self.mls_store = store::snapshot(&stores);
            dir_publish_kp(ctx, dir_id, &owner, kp_bytes).await?;
            self.published_kp_count += 1;
        }
        Ok(n)
    }

    /// Build `op` as an MLS Commit at the group's current epoch and
    /// submit it to the channel's sequencer. If another member's
    /// commit won the epoch (or we're behind the chain), catch up
    /// through the regular ctl drain and rebuild the operation once
    /// at the new epoch — the loser re-issues, nobody forks.
    /// Returns the epoch the group advanced to.
    async fn commit_chain_op(
        &mut self,
        ctx: &mut Context<Self>,
        channel: &str,
        op: ChainOp<'_>,
    ) -> core::result::Result<u64, ChainErr> {
        if let Some(i) = self.channel_index(channel)
            && self.channels[i].desynced
        {
            return Err(format!(
                "channel '{channel}' is degraded (commit chain bricked) — it is \
                 read-only at the last good epoch; re-create or re-join to repair \
                 before making membership changes"
            )
            .into());
        }
        let ctl_id = resolve(ctx, &ctl_agent_name(channel)).await?;
        let (binding, space_id) = self.bound_inputs()?;
        // One beacon for both commit attempts — a retry re-derives the commit
        // under the same finalized round.
        let beacon = crate::clients::chronos_beacon(ctx).await;
        for attempt in 0..2 {
            let stores = self.open_stores();
            let client = mls::build_bound_client_hedged(
                &binding,
                space_id,
                &self.csprng_seed,
                &stores,
                beacon,
            )?;
            let mut group = mls::load_group(&client, channel)?;
            // mls-rs has no `is_active`; our own leaf missing from the roster
            // means a prior commit evicted us.
            if group.member_at_index(group.current_member_index()).is_none() {
                return Err(format!("no longer a member of '{channel}'").into());
            }
            let epoch = group.current_epoch();
            // One timestamp for this attempt: it stamps both the MLS commit
            // Lifetime (so the commit/Welcome bytes are deterministic given the
            // time, not the wall clock) and the ctl chain row.
            let ts_ms = now_ms();
            let commit_time = mls::mls_time(ts_ms);

            // Build the commit (leaves a pending commit on the group; applied
            // only once the sequencer accepts it).
            let (commit_msg, welcome_msg, welcome_token) = match &op {
                ChainOp::Add { kp_bytes } => {
                    let kp_msg = parse_key_package(kp_bytes)?;
                    let out = group
                        .commit_builder()
                        .commit_time(commit_time)
                        .add_member(kp_msg)
                        .map_err(|e| format!("add proposal failed: {e:?}"))?
                        .build()
                        .map_err(|e| format!("add commit failed: {e:?}"))?;
                    let welcome = out.welcome_messages.into_iter().next();
                    // Random routing token, NOT a hash of the joiner's public
                    // KeyPackage — see `mls::welcome_nonce`.
                    (out.commit_message, welcome, welcome_nonce()?.to_vec())
                }
                ChainOp::Remove { nickname } => {
                    // Nicknames are unverified and non-unique, so a group can
                    // hold two leaves both credentialed the same. Refuse an
                    // ambiguous target rather than evicting an arbitrary
                    // first-match (a Remove is binding and can't be rewound),
                    // and never let a nickname match resolve to our own leaf.
                    let own = group.current_member_index();
                    let matches: Vec<u32> = group
                        .roster()
                        .members_iter()
                        .filter(|m| {
                            crate::identity::member_binding(&m.signing_identity)
                                .map(|d| d.display_name.as_str() == *nickname)
                                .unwrap_or(false)
                        })
                        .map(|m| m.index)
                        .collect();
                    let target = match matches.as_slice() {
                        [] => {
                            return Err(
                                format!("'{nickname}' is not a member of '{channel}'").into()
                            );
                        }
                        [only] if *only == own => {
                            return Err(ChainErr::Refused(
                                "that nickname resolves to your own leaf — \
                                 have another member remove you"
                                    .into(),
                            ));
                        }
                        [only] => *only,
                        _ => {
                            return Err(format!(
                                "'{nickname}' is ambiguous ({} leaves share it) — \
                                 removal by nickname is unsafe here",
                                matches.len()
                            )
                            .into());
                        }
                    };
                    let out = group
                        .commit_builder()
                        .commit_time(commit_time)
                        .remove_member(target)
                        .map_err(|e| format!("remove proposal failed: {e:?}"))?
                        .build()
                        .map_err(|e| format!("remove commit failed: {e:?}"))?;
                    if !out.welcome_messages.is_empty() {
                        group.clear_pending_commit();
                        return Err(ChainErr::Refused(
                            "commit unexpectedly produced a welcome — \
                                    pending add proposals in the way"
                                .into(),
                        ));
                    }
                    (out.commit_message, None, Vec::new())
                }
                ChainOp::SelfUpdate => {
                    // An empty commit auto-includes an update path (the
                    // self-update / PCS-heal operation).
                    let out = group
                        .commit_builder()
                        .commit_time(commit_time)
                        .build()
                        .map_err(|e| format!("self-update commit failed: {e:?}"))?;
                    if !out.welcome_messages.is_empty() {
                        group.clear_pending_commit();
                        return Err(ChainErr::Refused(
                            "commit unexpectedly produced a welcome — \
                                    pending add proposals in the way"
                                .into(),
                        ));
                    }
                    (out.commit_message, None, Vec::new())
                }
            };
            let commit_body = commit_msg
                .to_bytes()
                .map_err(|e| format!("serializing commit failed: {e:?}"))?;
            let welcome = match welcome_msg {
                Some(w) => w
                    .to_bytes()
                    .map_err(|e| format!("serializing welcome failed: {e:?}"))?,
                None => Vec::new(),
            };

            // The one indeterminate failure: the submission itself
            // failed in transit (local follower drop, forward
            // timeout…) — the leader may still have accepted it.
            let outcome = match ctl_commit(
                ctx,
                ctl_id,
                epoch,
                ts_ms,
                commit_body,
                welcome,
                welcome_token,
            )
            .await
            {
                Ok(o) => o,
                Err(e) => return Err(ChainErr::Indeterminate(e)),
            };
            match outcome.status {
                msg_ctl::Status::Ok => {
                    group
                        .apply_pending_commit()
                        .map_err(|e| format!("applying own commit failed: {e:?}"))?;
                    group
                        .write_to_storage()
                        .map_err(|e| format!("persisting own commit failed: {e:?}"))?;
                    self.mls_store = store::snapshot(&stores);
                    if let Some(i) = self.channel_index(channel) {
                        self.channels[i].next_epoch = epoch + 1;
                    }
                    return Ok(epoch + 1);
                }
                msg_ctl::Status::EpochTaken | msg_ctl::Status::EpochGap if attempt == 0 => {
                    // Drop our rejected pending commit; the unapplied build
                    // wrote nothing to storage, so there is nothing to persist
                    // — drain_ctl re-syncs and re-snapshots from the chain.
                    group.clear_pending_commit();
                    let i = self
                        .channel_index(channel)
                        .ok_or_else(|| format!("unknown channel '{channel}'"))?;
                    tick::drain_ctl(self, i, ctx)
                        .await
                        .map_err(|e| format!("catching up on the chain failed: {e}"))?;
                }
                other => {
                    group.clear_pending_commit();
                    return Err(ChainErr::Refused(match other {
                        msg_ctl::Status::EpochTaken => format!(
                            "another commit won epoch {epoch} again — channel is contended, retry"
                        ),
                        msg_ctl::Status::EpochGap => format!(
                            "local group still behind the chain (next is {}) — wait for sync",
                            outcome.next_epoch
                        ),
                        code => format!("msg-ctl refused the commit (status {code})"),
                    }));
                }
            }
        }
        Err(ChainErr::Refused(
            "commit lost the race twice — channel is contended, try again".into(),
        ))
    }
}

/// The node's current wall-clock time in Unix-epoch milliseconds — the single
/// time seam the messenger feeds to MLS (KeyPackage/commit Lifetimes) and to the
/// wire (envelope/commit row `ts_ms`). On the host build this reads
/// `SystemTime`; the deterministic PVM actor has no clock, so it reads the host
/// wall-clock through the `NOW_MS` hostcall. The messenger is a `Local`
/// (non-replicated) actor, so a per-dispatch wall-clock is sound — its only use
/// is the MLS `Lifetime` a remote peer validates against its own clock, and the
/// stamped wire-row `ts_ms`; neither feeds a replicated state transition. The
/// deterministic crypto provider pins the entropy, so KeyPackage/commit bytes
/// remain a pure function of `(seed, boot token, ts_ms)`.
#[cfg(not(target_arch = "riscv64"))]
pub(crate) fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(target_arch = "riscv64")]
pub(crate) fn now_ms() -> u64 {
    vos::hostcalls::now_ms()
}
