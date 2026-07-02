//! Msg-directory actor — the per-space messaging directory.
//!
//! Two tables: members' published MLS **KeyPackages** (so an
//! inviter can add someone by nickname without an out-of-band key
//! hand-off) and **channel announcements** (discovery). One
//! instance per space, shared by all channels.
//!
//! KeyPackages are meant for exactly one join each: `claim_kp`
//! hands out the first unclaimed package for a member and marks it
//! consumed. That single-use property is only as strong as the
//! agent's consistency mode — sequenced execution (raft) makes it
//! absolute; a crdt deployment can double-hand a package to two
//! concurrently-claiming inviters, which degrades to MLS's
//! known KeyPackage-reuse behaviour rather than anything worse
//! (the second Welcome simply fails to stage on the joiner, who
//! has already consumed the private part).
//!
//! Identity binding: the directory stores `(owner, kp)` rows
//! *opaquely* — it links no MLS library, so it can't inspect a
//! KeyPackage's credential. The binding to a verified identity is
//! enforced messenger-side: a member publishes under its own verified
//! PeerId (the `owner` is the PeerId, not a free nickname), and an
//! inviter that claims by PeerId refuses any returned package whose
//! embedded credential binds to a different identity (or an
//! unenrolled member). So a member listing a package under a victim's
//! PeerId here is harmless — the inviter catches the substitution.
//!
//! `claim_kp` is open to any publisher, so a member can drain
//! another's inventory (griefing): the victim's invite-by-name
//! then reports "no packages left" and the inviter falls back to
//! an out-of-band hand-off; the victim republishes (the quota
//! frees as packages are spent). A claimed package is only a
//! public KeyPackage — it lets the claimer add the victim to an
//! MLS group, but the victim's messenger only joins channels it
//! was locally asked to watch, so an unsolicited Welcome is inert.
//! Binding claims to real invite authorization is an identity-layer
//! follow-up.
//!
//! ## Module layout
//!
//! - [`consts`] — the KeyPackage-hash domain tag and sizing/quota bounds.
//! - [`rows`] — wire types (`KpRow`, `ChannelRow`) + the canonical
//!   KeyPackage hash.
//! - [`roles`] — the [`MsgDirectoryRole`] gate + [`MSG_DIRECTORY_SPACE_ROLE_MAP`].
//!
//! `Status` — the handler return type — lives here rather than in its own
//! module: every `#[msg]` handler below returns it, so it reads best kept
//! next to the actor it gates.

#![cfg_attr(target_arch = "riscv64", no_std)]
#![cfg_attr(target_arch = "wasm32", no_std)]

pub mod consts;
pub mod roles;
pub mod rows;

#[cfg(test)]
mod tests;

pub use consts::*;
pub use roles::{MSG_DIRECTORY_SPACE_ROLE_MAP, MsgDirectoryRole};
pub use rows::{ChannelRow, KpRow, kp_hash};

use vos::prelude::*;

// ── Status codes ──────────────────────────────────────────────────

/// Status returned by a directory mutation handler. `Ok` is `0`.
#[derive(
    vos::rkyv::Archive, vos::rkyv::Serialize, vos::rkyv::Deserialize, Clone, Copy, Debug, PartialEq, Eq,
)]
#[rkyv(crate = vos::rkyv)]
#[repr(u8)]
pub enum Status {
    /// Handler succeeded.
    Ok = 0,
    /// An argument was empty or otherwise malformed.
    InvalidInput = 1,
    /// A byte field exceeded its size budget.
    TooLarge = 2,
    /// The owner is at its KeyPackage quota.
    QuotaExceeded = 3,
    /// A channel with this name is already announced.
    Exists = 4,
}

impl Status {
    /// Decode a status byte (the over-the-wire discriminant) back into a
    /// `Status`. `None` for an unknown byte.
    pub fn from_u8(b: u8) -> Option<Self> {
        match b {
            0 => Some(Self::Ok),
            1 => Some(Self::InvalidInput),
            2 => Some(Self::TooLarge),
            3 => Some(Self::QuotaExceeded),
            4 => Some(Self::Exists),
            _ => None,
        }
    }
}

impl core::fmt::Display for Status {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Status::Ok => "ok",
            Status::InvalidInput => "invalid input",
            Status::TooLarge => "too large",
            Status::QuotaExceeded => "quota exceeded",
            Status::Exists => "exists",
        })
    }
}

// ── Actor ─────────────────────────────────────────────────────────

#[actor(
    role = MsgDirectoryRole,
    default_role = MsgDirectoryRole::Reader,
    space_role_map = MSG_DIRECTORY_SPACE_ROLE_MAP
)]
pub struct MsgDirectory {
    /// Sorted by `(owner, hash)`.
    key_packages: Vec<KpRow>,
    /// Sorted by `name`.
    channels: Vec<ChannelRow>,
}

#[messages]
impl MsgDirectory {
    pub fn new() -> Self {
        Self {
            key_packages: Vec::new(),
            channels: Vec::new(),
        }
    }

    /// Publish one KeyPackage under `owner`. Idempotent by content
    /// hash; bounded per member.
    #[msg(role = MsgDirectoryRole::Publisher)]
    async fn publish_kp(&mut self, owner: String, kp: Vec<u8>) -> Status {
        if owner.is_empty() || kp.is_empty() || owner.len() > MAX_NAME_BYTES {
            return Status::InvalidInput;
        }
        if kp.len() > MAX_KP_BYTES {
            return Status::TooLarge;
        }
        let hash = kp_hash(&kp);
        let pos = match self
            .key_packages
            .binary_search_by(|r| kp_key(&r.owner, &r.hash, &owner, &hash))
        {
            Ok(_) => return Status::Ok,
            Err(p) => p,
        };
        // Bound *live* (unclaimed) inventory, not lifetime
        // publishes — a member who has used up their packages must
        // be able to replenish. Claimed rows are spent and don't
        // count.
        let unclaimed = self
            .key_packages
            .iter()
            .filter(|r| r.owner == owner && !r.claimed)
            .count();
        if unclaimed >= MAX_KPS_PER_MEMBER {
            return Status::QuotaExceeded;
        }
        self.key_packages.insert(
            pos,
            KpRow {
                owner,
                hash,
                kp,
                claimed: false,
            },
        );
        Status::Ok
    }

    /// Claim one unclaimed KeyPackage for `owner`: marks it
    /// consumed and returns its bytes. Empty reply when none are
    /// left — the inviter falls back to an out-of-band hand-off.
    #[msg(role = MsgDirectoryRole::Publisher)]
    async fn claim_kp(&mut self, owner: String) -> Vec<u8> {
        for row in self.key_packages.iter_mut() {
            if row.owner == owner && !row.claimed {
                row.claimed = true;
                return row.kp.clone();
            }
        }
        Vec::new()
    }

    /// Return a claimed KeyPackage to the unclaimed pool — the
    /// compensating action for an inviter whose claim definitively
    /// failed to become a commit (the package was consumed from the
    /// owner's inventory but admits nobody). Only sound after a
    /// *decoded refusal*: when the commit submission failed at the
    /// transport level it may still have landed, and re-arming the
    /// package would hand a consumed KeyPackage to the next
    /// claimer. Idempotent — unknown or already-unclaimed rows are
    /// `Status::Ok` so retries are safe.
    #[msg(role = MsgDirectoryRole::Publisher)]
    async fn release_kp(&mut self, owner: String, hash: Vec<u8>) -> Status {
        let Ok(hash) = <[u8; 32]>::try_from(hash.as_slice()) else {
            return Status::InvalidInput;
        };
        if let Ok(pos) = self
            .key_packages
            .binary_search_by(|r| kp_key(&r.owner, &r.hash, &owner, &hash))
        {
            self.key_packages[pos].claimed = false;
        }
        Status::Ok
    }

    /// Unclaimed packages left for `owner` — the publisher's
    /// replenish signal.
    #[msg]
    async fn kp_count(&self, owner: String) -> u64 {
        self.key_packages
            .iter()
            .filter(|r| r.owner == owner && !r.claimed)
            .count() as u64
    }

    /// Announce a channel. First announcement wins; re-announcing
    /// the same name is `Status::Exists` so creators notice
    /// collisions.
    #[msg(role = MsgDirectoryRole::Publisher)]
    async fn announce_channel(&mut self, name: String, creator: String) -> Status {
        if name.is_empty() || name.len() > MAX_NAME_BYTES || creator.len() > MAX_NAME_BYTES {
            return Status::InvalidInput;
        }
        let pos = match self.channels.binary_search_by(|r| r.name.cmp(&name)) {
            Ok(_) => return Status::Exists,
            Err(p) => p,
        };
        self.channels.insert(pos, ChannelRow { name, creator });
        Status::Ok
    }

    /// Announced channels, name-sorted, byte-budgeted page from
    /// `from` (index into the sorted list).
    #[msg]
    async fn channels(&self, from: u64, limit: u32) -> Vec<ChannelRow> {
        let mut out = Vec::new();
        let mut budget = PAGE_BYTE_BUDGET;
        let mut idx = from as usize;
        while idx < self.channels.len() && out.len() < limit.min(64) as usize {
            let row = &self.channels[idx];
            let cost = 32 + row.name.len() + row.creator.len();
            if cost > budget && !out.is_empty() {
                break;
            }
            budget = budget.saturating_sub(cost);
            out.push(row.clone());
            idx += 1;
        }
        out
    }
}

// ── Helpers ───────────────────────────────────────────────────────

/// Total order on `(owner, hash)` for `binary_search_by`.
fn kp_key(
    a_owner: &str,
    a_hash: &[u8; 32],
    b_owner: &str,
    b_hash: &[u8; 32],
) -> core::cmp::Ordering {
    a_owner.cmp(b_owner).then_with(|| a_hash.cmp(b_hash))
}
