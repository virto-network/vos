//! Messenger extension — the E2EE edge of VOS messaging.
//!
//! Channels replicate as two PVM agents: `msg-<chan>-log`
//! (crdt-mode, the ciphertext envelope log) and `msg-<chan>-ctl`
//! (the sequenced MLS commit chain). Neither ever sees plaintext
//! or key material. This native extension is where the
//! cryptography lives: it holds the member's MLS credential and
//! group state (RFC 9420 via mls-rs), encrypts on `send`,
//! decrypts on its poll `tick`, and keeps the decrypted
//! conversation in node-local extension state.
//!
//! Trust boundary: everything in this extension's state —
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
//! invitee's `tick` picks it up by KeyPackage hash. A directory
//! actor with sequenced single-use claims replaces the hand-off
//! in a later phase.
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

use vos::prelude::*;

mod clients;
mod crypto_provider;
mod host_rand;
mod mls;
mod store;
mod tick;

use clients::{
    ctl_commit, dir_announce_channel, dir_channels, dir_claim_kp, dir_publish_kp, dir_release_kp,
    hex_decode, hex_encode, log_post, reg_agents, reg_install, resolve,
};
use mls::{new_key_package, parse_key_package, welcome_nonce};
use mls_rs::ExtensionList;

// ── PVM-actor no_std runtime shims ────────────────────────────────
//
// The riscv64em-javm target has no native atomics and no OS entropy.
//
// `critical-section`: mls-rs's no_std build and the messenger's own
// `spin::Mutex` storage emulate atomics through `portable-atomic`, which needs a
// registered `critical_section::Impl`. The target is single-threaded with no
// interrupts/preemption, so acquire/release are no-ops.
#[cfg(target_arch = "riscv64")]
struct SingleThreadCriticalSection;
#[cfg(target_arch = "riscv64")]
critical_section::set_impl!(SingleThreadCriticalSection);
#[cfg(target_arch = "riscv64")]
unsafe impl critical_section::Impl for SingleThreadCriticalSection {
    unsafe fn acquire() -> critical_section::RawRestoreState {}
    unsafe fn release(_: critical_section::RawRestoreState) {}
}

// `getrandom`: every entropy draw the messenger makes flows through the
// host-seeded `HostRand` (see `crypto_provider`), so any `getrandom`/`OsRng`
// reachable inside the PVM — only mls-rs's off-path `signature_key_generate`,
// which the messenger never calls because it hands the Client a seed-derived
// signer — is a misuse. Fail loudly rather than hand back predictable bytes.
#[cfg(target_arch = "riscv64")]
fn pvm_no_os_entropy(_buf: &mut [u8]) -> core::result::Result<(), getrandom::Error> {
    Err(getrandom::Error::UNSUPPORTED)
}
#[cfg(target_arch = "riscv64")]
getrandom::register_custom_getrandom!(pvm_no_os_entropy);

/// Per-channel agent naming convention. The manifest installs the
/// pair under these names; `create`/`join` address them by channel
/// name alone.
pub fn log_agent_name(channel: &str) -> String {
    format!("msg-{channel}-log")
}
pub fn ctl_agent_name(channel: &str) -> String {
    format!("msg-{channel}-ctl")
}

/// The per-space directory agent's instance name.
pub const DIRECTORY_AGENT: &str = "msg-directory";

/// KeyPackages auto-published on `register` — enough invites
/// before the member needs a replenish.
const REGISTER_KP_COUNT: usize = 3;

// ── Persisted state shapes ────────────────────────────────────────

/// One decrypted message in the node-local store. Ordering is by
/// `(lamport, ts_ms, sender)` — same convergent key the log uses,
/// with display ties broken arbitrarily-but-stably.
#[derive(
    vos::rkyv::Archive, vos::rkyv::Serialize, vos::rkyv::Deserialize, Clone, Debug, PartialEq, Eq,
)]
#[rkyv(crate = vos::rkyv)]
pub struct PlainMessage {
    pub lamport: u64,
    pub ts_ms: u64,
    pub sender: String,
    pub text: String,
}

/// Local view of one channel.
#[derive(
    vos::rkyv::Archive, vos::rkyv::Serialize, vos::rkyv::Deserialize, Clone, Debug, PartialEq, Eq,
)]
#[rkyv(crate = vos::rkyv)]
pub struct ChannelEntry {
    pub name: String,
    /// `false` while waiting for a Welcome.
    pub joined: bool,
    /// `true` after the chain evicted us — the channel sits idle
    /// (history kept, no decryption possible) until a re-invite's
    /// Welcome arrives.
    pub removed: bool,
    /// `true` once a commit on the chain couldn't be applied to our
    /// group: the channel is frozen at its current epoch (no further
    /// commits processed, no new messages decrypted) pending repair,
    /// rather than re-fetching the bad record forever.
    pub desynced: bool,
    /// First epoch we hold keys for; envelopes below it are
    /// undecryptable history by MLS design.
    pub join_epoch: u64,
    /// Unjoined: ctl-chain scan position. Joined: next chain
    /// record to process.
    pub next_epoch: u64,
    /// Log read cursor (last consumed envelope).
    pub cursor_lamport: u64,
    pub cursor_id: Vec<u8>,
    /// Highest lamport seen anywhere in the channel — `send`
    /// stamps `max + 1`.
    pub max_lamport: u64,
    /// Envelope ids of our own posts not yet echoed back by the
    /// log drain (displayed at send time; MLS can't decrypt own
    /// traffic).
    pub own_ids: Vec<[u8; 32]>,
    /// The decrypted conversation.
    pub messages: Vec<PlainMessage>,
}

// ── Actor ─────────────────────────────────────────────────────────

#[actor]
pub struct Messenger {
    /// Operator-chosen display identity (the MLS BasicCredential).
    /// Empty until `register`.
    nickname: String,
    /// This member's Ed25519 public key — a stable identity reference,
    /// reproducible from the seed (the signer is derived, not stored).
    signature_key: Vec<u8>,
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
            mls_store: Vec::new(),
            csprng_seed: Vec::new(),
            published_kp_count: 0,
            channels: Vec::new(),
        }
    }

    /// Restore the mls-rs storage providers (group state + key packages) from
    /// this node's persisted snapshot. The messenger keeps the returned stores
    /// alongside the Client built over them (via [`mls::build_client`]) so it
    /// can [`store::snapshot`] them back after a mutating MLS op.
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
    /// mandatory for the deterministic PVM port, where OS entropy is absent).
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

    /// Create this node's messaging identity: an MLS credential
    /// under `nickname` with a fresh Ed25519 signer. Also stocks
    /// the space directory with a few KeyPackages so others can
    /// invite this member by name right away.
    #[msg(cli)]
    async fn register(&mut self, nickname: String, ctx: &mut Context<Self>) -> String {
        if !self.nickname.is_empty() {
            return format!("already registered as '{}'", self.nickname);
        }
        if nickname.is_empty() {
            return "usage: register <nickname>".into();
        }
        // Provision the CSPRNG root before the first draw if a host didn't
        // already do so via `seed` — on the host extension this is fresh OS
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

        match self.stock_directory(ctx, REGISTER_KP_COUNT).await {
            Ok(n) => format!(
                "registered as '{}' ({n} key packages published to the directory)",
                self.nickname
            ),
            Err(e) => format!(
                "registered as '{}' — directory unavailable ({e}); \
                 use `key_package` for out-of-band invites",
                self.nickname
            ),
        }
    }

    /// Mint a KeyPackage and print it hex-encoded for out-of-band
    /// delivery to an inviter. One KeyPackage admits one join.
    #[msg(cli)]
    async fn key_package(&mut self, ctx: &mut Context<Self>) -> String {
        let beacon = crate::clients::chronos_beacon(ctx).await;
        let stores = self.open_stores();
        let client = match mls::build_client_hedged(&self.nickname, &self.csprng_seed, &stores, beacon)
        {
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
        let beacon = crate::clients::chronos_beacon(ctx).await;
        let stores = self.open_stores();
        let client = match mls::build_client_hedged(&self.nickname, &self.csprng_seed, &stores, beacon)
        {
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
        let announced = match resolve(ctx, DIRECTORY_AGENT).await {
            Ok(dir_id) => dir_announce_channel(ctx, dir_id, &channel, &self.nickname.clone()).await,
            Err(e) => Err(e),
        };
        match announced {
            Ok(msg_directory::STATUS_OK) => format!("channel '{channel}' created and announced"),
            Ok(msg_directory::STATUS_EXISTS) => format!(
                "channel '{channel}' created — a channel of that name was already announced"
            ),
            Ok(code) => format!("channel '{channel}' created (announce failed, status {code})"),
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

    /// Add a member. `member` is either a nickname — resolved by
    /// claiming one of their directory-published KeyPackages — or
    /// a raw hex KeyPackage from `key_package` on their node
    /// (out-of-band invite). Either way it becomes an MLS Add +
    /// Commit on the channel's sequenced chain, with the Welcome
    /// riding the same record.
    #[msg(cli)]
    async fn invite(&mut self, channel: String, member: String, ctx: &mut Context<Self>) -> String {
        if self.channel_index(&channel).is_none() {
            return format!("unknown channel '{channel}'");
        }
        // A serialized KeyPackage is hundreds of bytes; anything
        // long and hex-shaped is one, anything else is a nickname.
        // A directory claim is remembered so a definitively-refused
        // commit can return the package to the pool instead of
        // leaking it from the member's inventory.
        let mut claimed_from: Option<u32> = None;
        let kp_bytes = match hex_decode(&member).filter(|b| b.len() > 64) {
            Some(bytes) => bytes,
            None => {
                let dir_id = match resolve(ctx, DIRECTORY_AGENT).await {
                    Ok(id) => id,
                    Err(e) => return format!("can't look up '{member}': {e}"),
                };
                match dir_claim_kp(ctx, dir_id, &member).await {
                    Ok(Some(bytes)) => {
                        claimed_from = Some(dir_id);
                        bytes
                    }
                    Ok(None) => {
                        return format!(
                            "'{member}' has no key packages left in the directory — \
                             ask them to run `messenger key_package` and pass you the hex"
                        );
                    }
                    Err(e) => return e,
                }
            }
        };
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
                if let (Some(dir_id), ChainErr::Refused(_)) = (claimed_from, &e) {
                    let hash = msg_directory::kp_hash(&kp_bytes);
                    if let Err(release_err) = dir_release_kp(ctx, dir_id, &member, hash).await {
                        log::warn!(
                            "couldn't return '{member}'s claimed key package: {release_err}"
                        );
                    }
                }
                e.into_message()
            }
        }
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
        let beacon = crate::clients::chronos_beacon(ctx).await;
        let stores = self.open_stores();
        let client = match mls::build_client_hedged(&self.nickname, &self.csprng_seed, &stores, beacon)
        {
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
            msg_log::ENVELOPE_KIND_APP,
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
        let client = mls::build_client(&self.nickname, &self.csprng_seed, &stores).ok();
        for c in &self.channels {
            if c.desynced {
                out.push_str(&format!(
                    "channel {}: desynced — needs repair ({} messages kept)\n",
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
/// helper that reaches the channel actors via `ask_dispatch`.
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
                space_registry::STATUS_OK | space_registry::STATUS_INSTANCE_EXISTS => {}
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
        // One beacon for the whole batch — every KeyPackage in this dispatch
        // hedges under the same finalized round.
        let beacon = crate::clients::chronos_beacon(ctx).await;
        let mut published = 0usize;
        for _ in 0..n {
            let stores = self.open_stores();
            let client =
                mls::build_client_hedged(&self.nickname, &self.csprng_seed, &stores, beacon)?;
            let kp_bytes = new_key_package(&client, now_ms())?;
            self.mls_store = store::snapshot(&stores);
            dir_publish_kp(ctx, dir_id, &self.nickname.clone(), kp_bytes).await?;
            self.published_kp_count += 1;
            published += 1;
        }
        Ok(published)
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
                "channel '{channel}' is desynced — repair it before making membership changes"
            )
            .into());
        }
        let ctl_id = resolve(ctx, &ctl_agent_name(channel)).await?;
        // One beacon for both commit attempts — a retry re-derives the commit
        // under the same finalized round.
        let beacon = crate::clients::chronos_beacon(ctx).await;
        for attempt in 0..2 {
            let stores = self.open_stores();
            let client =
                mls::build_client_hedged(&self.nickname, &self.csprng_seed, &stores, beacon)?;
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
                            m.signing_identity
                                .credential
                                .as_basic()
                                .map(|b| b.identifier() == nickname.as_bytes())
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
                msg_ctl::STATUS_OK => {
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
                msg_ctl::STATUS_EPOCH_TAKEN | msg_ctl::STATUS_EPOCH_GAP if attempt == 0 => {
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
                        msg_ctl::STATUS_EPOCH_TAKEN => format!(
                            "another commit won epoch {epoch} again — channel is contended, retry"
                        ),
                        msg_ctl::STATUS_EPOCH_GAP => format!(
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
/// wire (envelope/commit row `ts_ms`). On the host extension build this reads
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
