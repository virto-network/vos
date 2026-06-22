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
//! Identity caveat: rows bind to a *nickname*, not a verified
//! space identity — anyone the role gate lets in can publish under
//! any name. Inviters must validate the claimed KeyPackage
//! cryptographically (the messenger does), and nickname↔identity
//! binding arrives with the platform identity layer.

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

/// Bound on stored (unclaimed + claimed) packages per member —
/// keeps a chatty publisher from bloating every replica.
pub const MAX_KPS_PER_MEMBER: usize = 16;

/// Byte budget for one `channels` page.
pub const PAGE_BYTE_BUDGET: usize = 12 * 1024;

// ── Status codes ──────────────────────────────────────────────────

pub const STATUS_OK: u8 = 0;
pub const STATUS_INVALID_INPUT: u8 = 1;
pub const STATUS_TOO_LARGE: u8 = 2;
pub const STATUS_QUOTA_EXCEEDED: u8 = 3;
pub const STATUS_EXISTS: u8 = 4;

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
    async fn publish_kp(&mut self, owner: String, kp: Vec<u8>) -> u8 {
        if owner.is_empty() || kp.is_empty() {
            return STATUS_INVALID_INPUT;
        }
        if kp.len() > MAX_KP_BYTES {
            return STATUS_TOO_LARGE;
        }
        let hash = kp_hash(&kp);
        let pos = match self
            .key_packages
            .binary_search_by(|r| kp_key(&r.owner, &r.hash, &owner, &hash))
        {
            Ok(_) => return STATUS_OK,
            Err(p) => p,
        };
        let held = self
            .key_packages
            .iter()
            .filter(|r| r.owner == owner)
            .count();
        if held >= MAX_KPS_PER_MEMBER {
            return STATUS_QUOTA_EXCEEDED;
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
        STATUS_OK
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
    /// the same name is `STATUS_EXISTS` so creators notice
    /// collisions.
    #[msg(role = MsgDirectoryRole::Publisher)]
    async fn announce_channel(&mut self, name: String, creator: String) -> u8 {
        if name.is_empty() {
            return STATUS_INVALID_INPUT;
        }
        let pos = match self.channels.binary_search_by(|r| r.name.cmp(&name)) {
            Ok(_) => return STATUS_EXISTS,
            Err(p) => p,
        };
        self.channels.insert(pos, ChannelRow { name, creator });
        STATUS_OK
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
    match a_owner.cmp(b_owner) {
        core::cmp::Ordering::Equal => a_hash.cmp(b_hash),
        other => other,
    }
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

    fn publish(d: &mut MsgDirectory, owner: &str, kp: &[u8]) -> u8 {
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
        assert_eq!(publish(&mut d, "bob", b"kp-one"), STATUS_OK);
        assert_eq!(publish(&mut d, "bob", b"kp-two"), STATUS_OK);
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
        assert_eq!(publish(&mut d, "bob", b"same"), STATUS_OK);
        assert_eq!(publish(&mut d, "bob", b"same"), STATUS_OK);
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
        assert_eq!(publish(&mut d, "", b"kp"), STATUS_INVALID_INPUT);
        assert_eq!(publish(&mut d, "bob", b""), STATUS_INVALID_INPUT);
        let huge = vec![0u8; MAX_KP_BYTES + 1];
        assert_eq!(publish(&mut d, "bob", &huge), STATUS_TOO_LARGE);
        for i in 0..MAX_KPS_PER_MEMBER {
            assert_eq!(
                publish(&mut d, "bob", format!("kp-{i}").as_bytes()),
                STATUS_OK
            );
        }
        assert_eq!(
            publish(&mut d, "bob", b"one-too-many"),
            STATUS_QUOTA_EXCEEDED
        );
        // Quota is per member.
        assert_eq!(publish(&mut d, "carol", b"kp"), STATUS_OK);
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
            STATUS_OK,
        );
        assert_eq!(
            dispatch(
                &mut d,
                AnnounceChannel {
                    name: "general".into(),
                    creator: "mallory".into(),
                },
            ),
            STATUS_EXISTS,
        );
        let rows = dispatch(&mut d, Channels { from: 0, limit: 10 });
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].creator, "alice");
    }
}
