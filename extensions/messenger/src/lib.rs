//! Messenger extension — the E2EE edge of VOS messaging.
//!
//! Channels replicate as two PVM agents: `msg-<chan>-log`
//! (crdt-mode, the ciphertext envelope log) and `msg-<chan>-ctl`
//! (the sequenced MLS commit chain). Neither ever sees plaintext
//! or key material. This native extension is where the
//! cryptography lives: it holds the member's MLS credential and
//! group state (RFC 9420 via OpenMLS), encrypts on `send`,
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
//! Phase 1 invite flow is out-of-band, SimpleX-style: the invitee
//! prints a KeyPackage (`key_package`), hands it to the inviter
//! (link, QR, …), and the inviter's `invite` commits the
//! membership change; the Welcome rides the commit chain and the
//! invitee's `tick` picks it up by KeyPackage hash. A directory
//! actor with sequenced single-use claims replaces the hand-off
//! in a later phase.

use vos::prelude::*;

mod clients;
mod mls;
mod tick;

use clients::{
    ctl_commit, dir_announce_channel, dir_channels, dir_claim_kp, dir_publish_kp, hex_decode,
    hex_encode, log_post, reg_agents, reg_install, resolve,
};
use mls::{kp_hint, new_key_package, open_provider, parse_key_package, snapshot_provider};
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::OpenMlsProvider;

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

/// A KeyPackage we've published and not yet seen consumed — the
/// hash doubles as the Welcome routing hint.
#[derive(
    vos::rkyv::Archive, vos::rkyv::Serialize, vos::rkyv::Deserialize, Clone, Debug, PartialEq, Eq,
)]
#[rkyv(crate = vos::rkyv)]
pub struct KpRecord {
    pub hash: [u8; 32],
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
    /// Ed25519 public key locating our signer in MLS storage.
    signature_key: Vec<u8>,
    /// Snapshot of the OpenMLS storage map — every MLS secret
    /// (signer, KeyPackage private parts, group ratchets) lives
    /// in here. See `mls::open_provider`/`snapshot_provider`.
    mls_store: Vec<u8>,
    published_kps: Vec<KpRecord>,
    channels: Vec<ChannelEntry>,
}

#[messages]
impl Messenger {
    pub fn new() -> Self {
        Messenger {
            nickname: String::new(),
            signature_key: Vec::new(),
            mls_store: Vec::new(),
            published_kps: Vec::new(),
            channels: Vec::new(),
        }
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
        let provider = open_provider(&self.mls_store);
        let keys = match SignatureKeyPair::new(mls::CIPHERSUITE.signature_algorithm()) {
            Ok(k) => k,
            Err(e) => return format!("key generation failed: {e}"),
        };
        if let Err(e) = keys.store(provider.storage()) {
            return format!("storing signer failed: {e}");
        }
        self.signature_key = keys.public().to_vec();
        self.nickname = nickname;
        self.mls_store = snapshot_provider(&provider);

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
    async fn key_package(&mut self) -> String {
        let provider = open_provider(&self.mls_store);
        let (credential, signer) = match self.identity(&provider) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let kp_bytes = match new_key_package(&provider, credential, &signer) {
            Ok(b) => b,
            Err(e) => return e,
        };
        self.published_kps.push(KpRecord {
            hash: kp_hint(&kp_bytes),
        });
        self.mls_store = snapshot_provider(&provider);
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
        let provider = open_provider(&self.mls_store);
        let (credential, signer) = match self.identity(&provider) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let gid = GroupId::from_slice(&mls::group_id_for(&channel));
        if let Err(e) =
            MlsGroup::new_with_group_id(&provider, &signer, &mls::create_config(), gid, credential)
        {
            return format!("group creation failed: {e}");
        }
        self.mls_store = snapshot_provider(&provider);
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
        if self.published_kps.is_empty() {
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
        let kp_bytes = match hex_decode(&member).filter(|b| b.len() > 64) {
            Some(bytes) => bytes,
            None => {
                let dir_id = match resolve(ctx, DIRECTORY_AGENT).await {
                    Ok(id) => id,
                    Err(e) => return format!("can't look up '{member}': {e}"),
                };
                match dir_claim_kp(ctx, dir_id, &member).await {
                    Ok(Some(bytes)) => bytes,
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
            Err(e) => e,
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
            Err(e) => e,
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
            Err(e) => e,
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
        let provider = open_provider(&self.mls_store);
        let (_, signer) = match self.identity(&provider) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let mut group = match self.load_group(&provider, &channel) {
            Ok(g) => g,
            Err(e) => return e,
        };
        let msg_out = match group.create_message(&provider, &signer, text.as_bytes()) {
            Ok(m) => m,
            Err(e) => return format!("encryption failed: {e}"),
        };
        let Ok(body) = msg_out.to_bytes() else {
            return "serializing message failed".into();
        };
        let epoch = group.epoch().as_u64();
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
        self.mls_store = snapshot_provider(&provider);
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
            self.published_kps.len()
        ));
        let provider = open_provider(&self.mls_store);
        for c in &self.channels {
            if c.desynced {
                out.push_str(&format!(
                    "channel {}: desynced — needs repair ({} messages kept)\n",
                    c.name,
                    c.messages.len()
                ));
            } else if c.joined {
                let (epoch, members) = match self.load_group(&provider, &c.name) {
                    Ok(g) => (g.epoch().as_u64(), g.members().count()),
                    Err(_) => (0, 0),
                };
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
        let provider = open_provider(&self.mls_store);
        for (name, template) in installs {
            let rep_id = mls::fresh_replication_id(&provider)?;
            match reg_install(ctx, name, template, rep_id).await? {
                // EXISTS: someone else's create won the race (or a
                // peer's row synced in) — the post-condition holds.
                space_registry::STATUS_OK | space_registry::STATUS_INSTANCE_EXISTS => {}
                code => return Err(format!("installing '{name}' failed (status {code})")),
            }
        }
        Ok(())
    }

    pub(crate) fn holds_key_package(&self, hint: &[u8; 32]) -> bool {
        self.published_kps.iter().any(|k| k.hash == *hint)
    }

    /// Mint `n` KeyPackages and publish them to the space
    /// directory, recording their hashes locally so the tick
    /// recognises Welcomes that consume them. Mints nothing when
    /// the directory is unreachable — out-of-band `key_package`
    /// remains the fallback.
    async fn stock_directory(
        &mut self,
        ctx: &mut Context<Self>,
        n: usize,
    ) -> core::result::Result<usize, String> {
        let dir_id = resolve(ctx, DIRECTORY_AGENT).await?;
        let mut published = 0usize;
        for _ in 0..n {
            let provider = open_provider(&self.mls_store);
            let (credential, signer) = self.identity(&provider)?;
            let kp_bytes = new_key_package(&provider, credential, &signer)?;
            let hash = kp_hint(&kp_bytes);
            self.mls_store = snapshot_provider(&provider);
            dir_publish_kp(ctx, dir_id, &self.nickname.clone(), kp_bytes).await?;
            self.published_kps.push(KpRecord { hash });
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
    ) -> core::result::Result<u64, String> {
        if let Some(i) = self.channel_index(channel)
            && self.channels[i].desynced
        {
            return Err(format!(
                "channel '{channel}' is desynced — repair it before making membership changes"
            ));
        }
        let ctl_id = resolve(ctx, &ctl_agent_name(channel)).await?;
        for attempt in 0..2 {
            let provider = open_provider(&self.mls_store);
            let (_, signer) = self.identity(&provider)?;
            let mut group = self.load_group(&provider, channel)?;
            if !group.is_active() {
                return Err(format!("no longer a member of '{channel}'"));
            }
            let epoch = group.epoch().as_u64();

            let (commit_out, welcome_out, hint) = match &op {
                ChainOp::Add { kp_bytes } => {
                    let kp = parse_key_package(&provider, kp_bytes)?;
                    let (c, w, _info) = group
                        .add_members(&provider, &signer, core::slice::from_ref(&kp))
                        .map_err(|e| format!("add_members failed: {e}"))?;
                    (c, Some(w), kp_hint(kp_bytes).to_vec())
                }
                ChainOp::Remove { nickname } => {
                    // Nicknames are unverified and non-unique, so a
                    // group can hold two leaves both credentialed the
                    // same. Refuse an ambiguous target rather than
                    // evicting an arbitrary first-match (a Remove is
                    // binding and can't be rewound), and never let a
                    // nickname match resolve to our own leaf.
                    let own = group.own_leaf_index();
                    let matches: Vec<_> = group
                        .members()
                        .filter(|m| m.credential.serialized_content() == nickname.as_bytes())
                        .map(|m| m.index)
                        .collect();
                    let target = match matches.as_slice() {
                        [] => {
                            return Err(format!("'{nickname}' is not a member of '{channel}'"));
                        }
                        [only] if *only == own => {
                            return Err("that nickname resolves to your own leaf — \
                                 have another member remove you"
                                .into());
                        }
                        [only] => *only,
                        _ => {
                            return Err(format!(
                                "'{nickname}' is ambiguous ({} leaves share it) — \
                                 removal by nickname is unsafe here",
                                matches.len()
                            ));
                        }
                    };
                    let (c, w, _info) = group
                        .remove_members(&provider, &signer, &[target])
                        .map_err(|e| format!("remove_members failed: {e}"))?;
                    if w.is_some() {
                        let _ = group.clear_pending_commit(provider.storage());
                        return Err("commit unexpectedly produced a welcome — \
                                    pending add proposals in the way"
                            .into());
                    }
                    (c, None, Vec::new())
                }
                ChainOp::SelfUpdate => {
                    let (c, w, _info) = group
                        .self_update(&provider, &signer, LeafNodeParameters::default())
                        .map_err(|e| format!("self_update failed: {e}"))?
                        .into_contents();
                    if w.is_some() {
                        let _ = group.clear_pending_commit(provider.storage());
                        return Err("commit unexpectedly produced a welcome — \
                                    pending add proposals in the way"
                            .into());
                    }
                    (c, None, Vec::new())
                }
            };
            let commit_body = commit_out
                .to_bytes()
                .map_err(|e| format!("serializing commit failed: {e}"))?;
            let welcome = match welcome_out {
                Some(w) => w
                    .to_bytes()
                    .map_err(|e| format!("serializing welcome failed: {e}"))?,
                None => Vec::new(),
            };

            let outcome =
                ctl_commit(ctx, ctl_id, epoch, now_ms(), commit_body, welcome, hint).await?;
            match outcome.status {
                msg_ctl::STATUS_OK => {
                    group
                        .merge_pending_commit(&provider)
                        .map_err(|e| format!("merging own commit failed: {e}"))?;
                    self.mls_store = snapshot_provider(&provider);
                    if let Some(i) = self.channel_index(channel) {
                        self.channels[i].next_epoch = epoch + 1;
                    }
                    return Ok(epoch + 1);
                }
                msg_ctl::STATUS_EPOCH_TAKEN | msg_ctl::STATUS_EPOCH_GAP if attempt == 0 => {
                    let _ = group.clear_pending_commit(provider.storage());
                    self.mls_store = snapshot_provider(&provider);
                    let i = self
                        .channel_index(channel)
                        .ok_or_else(|| format!("unknown channel '{channel}'"))?;
                    tick::drain_ctl(self, i, ctx)
                        .await
                        .map_err(|e| format!("catching up on the chain failed: {e}"))?;
                }
                other => {
                    let _ = group.clear_pending_commit(provider.storage());
                    self.mls_store = snapshot_provider(&provider);
                    return Err(match other {
                        msg_ctl::STATUS_EPOCH_TAKEN => format!(
                            "another commit won epoch {epoch} again — channel is contended, retry"
                        ),
                        msg_ctl::STATUS_EPOCH_GAP => format!(
                            "local group still behind the chain (next is {}) — wait for sync",
                            outcome.next_epoch
                        ),
                        code => format!("msg-ctl refused the commit (status {code})"),
                    });
                }
            }
        }
        Err("commit lost the race twice — channel is contended, try again".into())
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}
