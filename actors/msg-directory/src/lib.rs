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

#![cfg_attr(target_arch = "riscv64", no_std)]
#![cfg_attr(target_arch = "wasm32", no_std)]

use vos::prelude::*;

// ── Constants ─────────────────────────────────────────────────────

/// Domain tag for KeyPackage hashes. The canonical computation for
/// the whole messaging stack: the publisher hashes the serialized
/// KeyPackage it minted, the directory dedupes by it, and the
/// Welcome routing hint on the msg-ctl chain carries the same
/// value so a joiner recognises which record admits it.
pub const KP_HASH_DOMAIN_TAG: &[u8] = b"vos-msg-kp/v1";

/// Bound on one serialized KeyPackage (typically a few hundred
/// bytes for the pinned ciphersuite).
pub const MAX_KP_BYTES: usize = 4 * 1024;

/// Bound on operator-controlled identity/name strings (nickname,
/// channel name, creator). Replicated to every node, so cap them so
/// a member can't bloat shared state with a giant string.
pub const MAX_NAME_BYTES: usize = 128;

/// Bound on a member's *live* (unclaimed) packages — caps the
/// inventory waiting to be claimed without ever locking a member
/// out of replenishing once their packages are spent. Claimed
/// rows are retained for the single-use marker but don't count.
pub const MAX_KPS_PER_MEMBER: usize = 16;

/// Byte budget for one `channels` page.
pub const PAGE_BYTE_BUDGET: usize = 12 * 1024;

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

// ── Wire types ────────────────────────────────────────────────────

/// One published KeyPackage. `kp` is opaque to the directory —
/// validation happens MLS-side on the inviter.
#[derive(
    vos::rkyv::Archive, vos::rkyv::Serialize, vos::rkyv::Deserialize, Clone, Debug, PartialEq, Eq,
)]
#[rkyv(crate = vos::rkyv)]
pub struct KpRow {
    pub owner: String,
    pub hash: [u8; 32],
    pub kp: Vec<u8>,
    pub claimed: bool,
}

/// One announced channel.
#[derive(
    vos::rkyv::Archive, vos::rkyv::Serialize, vos::rkyv::Deserialize, Clone, Debug, PartialEq, Eq,
)]
#[rkyv(crate = vos::rkyv)]
pub struct ChannelRow {
    pub name: String,
    pub creator: String,
}

/// Canonical KeyPackage hash — see [`KP_HASH_DOMAIN_TAG`].
pub fn kp_hash(serialized_kp: &[u8]) -> [u8; 32] {
    vos::crypto::blake2b_hash(KP_HASH_DOMAIN_TAG, &[serialized_kp])
}

// ── Roles ─────────────────────────────────────────────────────────

#[derive(
    vos::rkyv::Archive,
    vos::rkyv::Serialize,
    vos::rkyv::Deserialize,
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
)]
#[rkyv(crate = vos::rkyv)]
#[repr(u8)]
pub enum MsgDirectoryRole {
    None = 0,
    Reader = 1,
    Publisher = 2,
}

impl vos::RoleByte for MsgDirectoryRole {
    fn from_byte(b: u8) -> Option<Self> {
        match b {
            0 => Some(Self::None),
            1 => Some(Self::Reader),
            2 => Some(Self::Publisher),
            _ => None,
        }
    }
    fn as_byte(self) -> u8 {
        self as u8
    }
}

pub const MSG_DIRECTORY_SPACE_ROLE_MAP: vos::SpaceRoleMap<MsgDirectoryRole> = vos::SpaceRoleMap {
    admin: Some(MsgDirectoryRole::Publisher),
    developer: Some(MsgDirectoryRole::Publisher),
    member: Some(MsgDirectoryRole::Publisher),
    guest: None,
};

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

#[cfg(test)]
mod tests {
    use super::*;
    use vos::Message;
    use vos::actors::context::ServiceId;

    /// Handler futures never await anything external, so a single
    /// poll with a no-op waker resolves them — no executor (or
    /// vos `std` feature) needed in this crate's unit tests.
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

    fn dispatch<M>(d: &mut MsgDirectory, msg: M) -> <MsgDirectory as Message<M>>::Output
    where
        MsgDirectory: Message<M>,
    {
        let mut ctx: vos::Context<MsgDirectory> = vos::Context::new(ServiceId(0));
        run(<MsgDirectory as Message<M>>::handle(d, msg, &mut ctx))
    }

    fn publish(d: &mut MsgDirectory, owner: &str, kp: &[u8]) -> Status {
        dispatch(
            d,
            PublishKp {
                owner: owner.into(),
                kp: kp.to_vec(),
            },
        )
    }

    fn claim(d: &mut MsgDirectory, owner: &str) -> Vec<u8> {
        dispatch(
            d,
            ClaimKp {
                owner: owner.into(),
            },
        )
    }

    #[test]
    fn each_published_kp_is_claimable_exactly_once() {
        let mut d = MsgDirectory::new();
        assert_eq!(publish(&mut d, "bob", b"kp-one"), Status::Ok);
        assert_eq!(publish(&mut d, "bob", b"kp-two"), Status::Ok);
        assert_eq!(
            dispatch(
                &mut d,
                KpCount {
                    owner: "bob".into()
                }
            ),
            2
        );

        let first = claim(&mut d, "bob");
        let second = claim(&mut d, "bob");
        assert!(!first.is_empty() && !second.is_empty());
        assert_ne!(first, second, "each claim must consume a distinct package");
        assert!(
            claim(&mut d, "bob").is_empty(),
            "an exhausted member yields no package"
        );
        assert_eq!(
            dispatch(
                &mut d,
                KpCount {
                    owner: "bob".into()
                }
            ),
            0
        );
    }

    #[test]
    fn publish_is_idempotent_by_content() {
        let mut d = MsgDirectory::new();
        assert_eq!(publish(&mut d, "bob", b"same"), Status::Ok);
        assert_eq!(publish(&mut d, "bob", b"same"), Status::Ok);
        assert_eq!(
            dispatch(
                &mut d,
                KpCount {
                    owner: "bob".into()
                }
            ),
            1
        );
    }

    #[test]
    fn publish_validates_shape_and_quota() {
        let mut d = MsgDirectory::new();
        assert_eq!(publish(&mut d, "", b"kp"), Status::InvalidInput);
        assert_eq!(publish(&mut d, "bob", b""), Status::InvalidInput);
        let huge = vec![0u8; MAX_KP_BYTES + 1];
        assert_eq!(publish(&mut d, "bob", &huge), Status::TooLarge);
        for i in 0..MAX_KPS_PER_MEMBER {
            assert_eq!(
                publish(&mut d, "bob", format!("kp-{i}").as_bytes()),
                Status::Ok
            );
        }
        assert_eq!(
            publish(&mut d, "bob", b"one-too-many"),
            Status::QuotaExceeded
        );
        // Quota is per member.
        assert_eq!(publish(&mut d, "carol", b"kp"), Status::Ok);
        // Oversized owner / channel names are refused.
        let long = "x".repeat(MAX_NAME_BYTES + 1);
        assert_eq!(publish(&mut d, &long, b"kp"), Status::InvalidInput);
        assert_eq!(
            dispatch(
                &mut d,
                AnnounceChannel {
                    name: long,
                    creator: "alice".into(),
                },
            ),
            Status::InvalidInput,
        );
    }

    #[test]
    fn spent_packages_free_quota_for_replenishment() {
        // The quota bounds live inventory, not lifetime publishes —
        // a member who claimed all their packages must be able to
        // publish more. Otherwise a long-lived member locks out
        // after MAX_KPS_PER_MEMBER total invites.
        let mut d = MsgDirectory::new();
        for i in 0..MAX_KPS_PER_MEMBER {
            assert_eq!(
                publish(&mut d, "bob", format!("kp-{i}").as_bytes()),
                Status::Ok
            );
        }
        assert_eq!(publish(&mut d, "bob", b"blocked"), Status::QuotaExceeded);
        // Consume one; a slot frees up.
        assert!(!claim(&mut d, "bob").is_empty());
        assert_eq!(publish(&mut d, "bob", b"replenished"), Status::Ok);
    }

    #[test]
    fn released_kp_is_claimable_again() {
        let mut d = MsgDirectory::new();
        publish(&mut d, "bob", b"the-kp");
        let claimed = claim(&mut d, "bob");
        assert_eq!(claimed, b"the-kp");
        assert!(claim(&mut d, "bob").is_empty(), "single-use after claim");

        let hash = kp_hash(&claimed);
        assert_eq!(
            dispatch(
                &mut d,
                ReleaseKp {
                    owner: "bob".into(),
                    hash: hash.to_vec(),
                },
            ),
            Status::Ok,
        );
        assert_eq!(
            dispatch(
                &mut d,
                KpCount {
                    owner: "bob".into()
                }
            ),
            1,
            "released package counts as live inventory again"
        );
        assert_eq!(claim(&mut d, "bob"), b"the-kp", "released → claimable");
    }

    #[test]
    fn release_is_idempotent_and_tolerates_unknown_rows() {
        let mut d = MsgDirectory::new();
        publish(&mut d, "bob", b"kp");
        let hash = kp_hash(b"kp").to_vec();
        // Releasing an UNCLAIMED row is a no-op success.
        assert_eq!(
            dispatch(
                &mut d,
                ReleaseKp {
                    owner: "bob".into(),
                    hash: hash.clone(),
                },
            ),
            Status::Ok,
        );
        // Unknown owner/hash: still OK (retry-safe).
        assert_eq!(
            dispatch(
                &mut d,
                ReleaseKp {
                    owner: "nobody".into(),
                    hash,
                },
            ),
            Status::Ok,
        );
        // Malformed hash length is the one refused input.
        assert_eq!(
            dispatch(
                &mut d,
                ReleaseKp {
                    owner: "bob".into(),
                    hash: vec![0u8; 7],
                },
            ),
            Status::InvalidInput,
        );
        // Inventory unchanged throughout.
        assert_eq!(
            dispatch(
                &mut d,
                KpCount {
                    owner: "bob".into()
                }
            ),
            1
        );
    }

    #[test]
    fn claims_are_scoped_to_the_owner() {
        let mut d = MsgDirectory::new();
        publish(&mut d, "bob", b"bobs-kp");
        assert!(claim(&mut d, "carol").is_empty());
        assert_eq!(claim(&mut d, "bob"), b"bobs-kp");
    }

    #[test]
    fn channel_announcements_are_first_wins() {
        let mut d = MsgDirectory::new();
        assert_eq!(
            dispatch(
                &mut d,
                AnnounceChannel {
                    name: "general".into(),
                    creator: "alice".into(),
                },
            ),
            Status::Ok,
        );
        assert_eq!(
            dispatch(
                &mut d,
                AnnounceChannel {
                    name: "general".into(),
                    creator: "mallory".into(),
                },
            ),
            Status::Exists,
        );
        let rows = dispatch(&mut d, Channels { from: 0, limit: 10 });
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].creator, "alice");
    }
}
