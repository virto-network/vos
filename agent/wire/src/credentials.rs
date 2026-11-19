//! The credential actor's rows and ring of roots, as its rows hold them
//! (`identity-and-authority.md` §6, `proving.md` §8), over the tree of
//! [`vos_abi::credentials`]: the paths it serves, the claims a device
//! proves, and the freshness rule ingress and apply judge a root by.

use alloc::vec::Vec;

use scale::{Decode, DecodeError, Encode};

use vos_abi::credentials::{
    DEPTH, Digest, EMPTY, Tag, compress, digest, member_root, reduced, words,
};

use vos_abi::SpaceId;
use vos_abi::ids::{AgentId, InstanceId, MethodId};

/// The credential actor's handlers.
pub mod method {
    methods! {
        FOUND = "found";
        ENROLL = "enroll";
        ENROLL_MANY = "enroll_many";
        INVITE = "invite";
        CLAIM = "claim";
        OPEN = "open";
        CLAIM_OPEN = "claim_open";
        REVOKE = "revoke";
        REGISTER = "register";
        LIMIT = "limit";
        RESET = "reset";
        REVOKE_PERSON = "revoke_person";
        ENROLL_DEVICE = "enroll_device";
        CONFIRM_DEVICE = "confirm_device";
        REVOKE_DEVICE = "revoke_device";
        PATH = "path";
        ROOT = "root";
        FEED = "feed";
        FEED_AFTER = "feed_after";
        SET_ONIONS = "set_onions";
        ONIONS = "onions";
        HANDLE = "handle";
        COUNT = "count";
        OPENING = "opening";
    }
}

/// The most roots the ring keeps: it bounds storage, never freshness.
pub const RING: usize = 64;

/// The most members one `enroll_many` takes.
pub const ENROLL_MANY: usize = 256;

/// The most devices a person's limit admits.
pub const MAX_DEVICES: u8 = 16;

/// The period a person's enrollments are counted in: a year of batch
/// time, the home's lease's span between re-proofs (`light-node.md` §3.3).
pub const ENROLLMENT_PERIOD_MS: u64 = 365 * 24 * 3_600_000;

/// The devices a person enrolls in a period past its limit: replacements
/// of a lost or retired phone. Its devices of a period, those it held as
/// the period began and those it enrolled in it, are at most its limit and
/// these; the registrar's `reset` starts the count again.
pub const REPLACEMENTS: u8 = 2;

/// How long an owner digest an enrollment names awaits its device's
/// confirmation before another enrollment may name it: a day of batch
/// time, so no person holds another's digest from its own person.
pub const CONFIRM_MS: u64 = 24 * 3_600_000;

/// The most onions the space's set holds: one a gateway.
pub const MAX_ONIONS: usize = 16;

/// The most bytes one page of the tree's feed holds, encoded: under a
/// query's reply cap ([`vos_abi::abi::cap::REPLY`]) with room for its framing.
/// A page holds at least one change, and a change holds at most
/// [`ENROLL_MANY`] leaves, about 9 KiB.
pub const FEED_BYTES: usize = 48 << 10;

/// The role every write but the claims and a person's device methods is
/// under.
pub const REGISTRAR: &str = "registrar";

/// The actor's tables, by name: each tagged
/// `derive_id("vos/table/", name)`, plain rows. A table of one row is a
/// cell of the actor's (`vos_sdk::table::Cell`), its row under
/// [`RING_KEY`](tables::RING_KEY), the key of every cell.
pub mod tables {
    /// One row, a cell: the space's handle, 32 bytes, once founded.
    pub const HANDLE: &str = "handle";
    /// One row, a cell: the lowest slot never used, a `u64`.
    pub const NEXT: &str = "next";
    /// One row, a cell: the members enrolled, a `u64`.
    pub const COUNT: &str = "count";
    /// One row, a cell: the tree's writes, the feed's length, a `u64`.
    pub const CHANGED: &str = "changed";
    /// A `member` digest → its slot, a `u32`.
    pub const SLOTS: &str = "slots";
    /// `(level, index)`, one byte then four big-endian bytes → a digest,
    /// kept only when not the empty subtree's; level 0 holds the leaves.
    pub const NODES: &str = "nodes";
    /// Freed slots, keyed by their four big-endian bytes, in key order.
    pub const FREE: &str = "free";
    /// A `member` digest → its invitation's expiry, in milliseconds of
    /// batch time.
    pub const INVITES: &str = "invites";
    /// One row, under [`RING_KEY`]: the [`Ring`](super::Ring).
    pub const RING: &str = "ring";
    /// The ring's row's key, one byte: a cell's.
    pub const RING_KEY: u8 = 0;
    /// One row, under [`RING_KEY`]: the open claim's terms and its period's
    /// count, once the registrar opened it.
    pub const OPENING: &str = "opening";
    /// A person's id, a `u32` → its record: its limit and each device's
    /// `member` and `owner` digests.
    pub const PERSONS: &str = "persons";
    /// A confirmed device's `owner` digest → its person's id.
    pub const OWNERS: &str = "owners";
    /// An enrolled device's `owner` digest awaiting its own proof → its
    /// person's id.
    pub const PENDING: &str = "pending";
    /// A device's `member` digest → its person's id.
    pub const DEVICES: &str = "devices";
    /// One row, under [`RING_KEY`]: the persons ever registered, the next
    /// one's id.
    pub const PEOPLE: &str = "people";
    /// One row, under [`RING_KEY`]: the space's onion set, its gateways'
    /// [`Onion`](super::Onion)s.
    pub const ONIONS: &str = "onions";
    /// The tree's feed: a write's place in it, eight big-endian bytes, in
    /// key order → its [`Change`](super::Change).
    pub const CHANGES: &str = "changes";
    /// A root a write of the tree left → the place of the last write that
    /// left it, a `u64`: where `feed_after(root)` reads on from.
    pub const ROOTS: &str = "roots";
}

/// A path's 32 siblings, from the leaf's level up, each a digest: 1,024
/// bytes, no length.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Siblings(pub [Digest; DEPTH]);

impl Encode for Siblings {
    fn encode_to(&self, buf: &mut Vec<u8>) {
        for sibling in &self.0 {
            buf.extend_from_slice(sibling);
        }
    }
}

impl Decode for Siblings {
    fn decode(data: &[u8]) -> Result<(Self, usize), DecodeError> {
        let bytes = data.get(..DEPTH * 32).ok_or(DecodeError::UnexpectedEof)?;
        let siblings = core::array::from_fn(|i| bytes[32 * i..32 * i + 32].try_into().unwrap());
        Ok((Self(siblings), DEPTH * 32))
    }
}

/// What `path(member)` answers: the tree's root, the member's slot and the
/// siblings from its leaf up.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct Path {
    pub root: Digest,
    pub slot: u32,
    pub siblings: Siblings,
}

impl Path {
    /// Whether this path places `member`'s leaf under its root.
    pub fn proves(&self, member: &Digest) -> bool {
        let (Some(member), Some(root)) = (words(member), words(&self.root)) else {
            return false;
        };
        let mut siblings = [[0u32; 8]; DEPTH];
        for (words_of, sibling) in siblings.iter_mut().zip(&self.siblings.0) {
            match words(sibling) {
                Some(sibling) => *words_of = sibling,
                None => return false,
            }
        }
        member_root(&member, self.slot, &siblings) == root
    }
}

/// One root of the ring: a root and the batch time it became the tree's.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
pub struct RootEntry {
    pub root: Digest,
    pub since: u64,
}

/// One write of the tree, as its feed carries it: the leaves it set, each
/// at its slot (the empty leaf `E_0` for a revocation), in slot order, and
/// the root it left with the batch time that root became the tree's, the
/// entry it left in the ring. Two writes of one batch share that time: the
/// ring holds the second's root alone.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct Change {
    pub leaves: Vec<(u32, Digest)>,
    pub root: RootEntry,
}

impl Change {
    /// Its encoding's length: the leaves' count, each leaf's slot and
    /// digest, and the root's entry.
    pub fn encoded_len(&self) -> usize {
        4 + 36 * self.leaves.len() + 40
    }
}

/// A page of the tree's feed (`feed(from)`): the changes from the `from`th
/// on, as many as [`FEED_BYTES`] holds, and the feed's length, the changes
/// the tree has had. Its changes from the first, applied in order to the
/// empty tree, give each change's root.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct Feed {
    pub from: u64,
    pub changes: Vec<Change>,
    pub length: u64,
}

/// Why a root is not accepted: in no entry of the ring, or superseded more
/// than [`crate::defaults::ROOT_GRACE_MS`] before the time it is judged at.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
#[repr(u8)]
pub enum RootRefusal {
    #[codec(index = 0)]
    Unknown = 0,
    #[codec(index = 1)]
    Stale = 1,
}

/// The last [`RING`] roots, newest last, each from the batch time it became
/// the tree's root.
#[derive(Clone, Debug, Default, PartialEq, Eq, Encode, Decode)]
pub struct Ring(pub Vec<RootEntry>);

impl Ring {
    /// The ring an install writes: the empty tree's root, from `time`.
    pub fn installed(time: u64) -> Self {
        Self(alloc::vec![RootEntry {
            root: digest(&EMPTY[DEPTH]),
            since: time,
        }])
    }

    /// The tree's root, and since when.
    pub fn newest(&self) -> Option<&RootEntry> {
        self.0.last()
    }

    /// A write at batch time `time` left `root`: the newest entry's root
    /// replaced when it is from `time`, else a new entry, the oldest dropped
    /// past [`RING`].
    pub fn record(&mut self, root: Digest, time: u64) {
        match self.0.last_mut() {
            Some(newest) if newest.since == time => newest.root = root,
            _ => {
                self.0.push(RootEntry { root, since: time });
                if self.0.len() > RING {
                    self.0.remove(0);
                }
            }
        }
    }

    /// Whether `root` is accepted at `time`: the newest, or superseded at
    /// most [`crate::defaults::ROOT_GRACE_MS`] before `time`, by the time
    /// the next entry became the root. A root the ring holds twice is
    /// judged by its later entry.
    pub fn accepts(&self, root: &Digest, time: u64) -> Result<(), RootRefusal> {
        let at = self
            .0
            .iter()
            .rposition(|entry| entry.root == *root)
            .ok_or(RootRefusal::Unknown)?;
        match self.0.get(at + 1) {
            None => Ok(()),
            Some(next) if time.saturating_sub(next.since) <= crate::defaults::ROOT_GRACE_MS => {
                Ok(())
            }
            Some(_) => Err(RootRefusal::Stale),
        }
    }
}

/// The scope a guard named `name` gives in `space`'s agent `agent`, at
/// `instance` (`identity-and-authority.md` §7):
/// `C(T(scope), W(BLAKE2b-256("vos/cred/scope/v1" ‖ space ‖ agent ‖ instance ‖ name)))`,
/// the agent and the instance four little-endian bytes each, `name` as the
/// codec writes it (a `u32` little-endian length, then the bytes). No two
/// agents' guards of one name, in one space or two, share a pseudonym.
pub fn scope(space: &SpaceId, agent: AgentId, instance: InstanceId, name: &[u8]) -> Digest {
    let hash = vos_pvm_precompiles::blake2b_hash::<32>(
        b"vos/cred/scope/v1",
        &[
            &space.0,
            &agent.0.to_le_bytes(),
            &instance.0.to_le_bytes(),
            &(name.len() as u32).to_le_bytes(),
            name,
        ],
    );
    digest(&compress(&Tag::Scope.block(), &reduced(&hash)))
}

/// What a binding digest binds: one call of one method, in one space,
/// under one device program, once, before `expires_ms`.
#[derive(Clone, Copy, Debug)]
pub struct Bound<'a> {
    pub space: &'a SpaceId,
    pub agent: AgentId,
    pub instance: InstanceId,
    pub method: MethodId,
    /// The device program's id, which names the statement.
    pub program: &'a [u8; 32],
    pub arguments: &'a [u8],
    pub nonce: &'a [u8; 16],
    pub expires_ms: u64,
}

impl Bound<'_> {
    /// `b = BLAKE2b-256("vos/cred/binding/v1" ‖ space ‖ agent ‖ instance ‖
    /// method ‖ program ‖ arguments ‖ nonce ‖ expires_ms)`: the agent,
    /// instance and method four little-endian bytes each, the arguments as
    /// the codec writes them (a `u32` little-endian length, then the
    /// bytes), `expires_ms` eight little-endian bytes.
    pub fn digest(&self) -> [u8; 32] {
        let length = (self.arguments.len() as u32).to_le_bytes();
        vos_pvm_precompiles::blake2b_hash::<32>(
            b"vos/cred/binding/v1",
            &[
                &self.space.0,
                &self.agent.0.to_le_bytes(),
                &self.instance.0.to_le_bytes(),
                &self.method.0.to_le_bytes(),
                self.program,
                &length,
                self.arguments,
                self.nonce,
                &self.expires_ms.to_le_bytes(),
            ],
        )
    }
}

/// The stock `auth` kernel's claim, its public arguments: the member's
/// leaf under `map_root`, a root of the ring, and `nullifier` its
/// pseudonym in `scope`; then the call's `binding`. 128 bytes, the four
/// digests in order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
pub struct AuthClaim {
    pub map_root: Digest,
    pub scope: Digest,
    pub nullifier: Digest,
    pub binding: Digest,
}

/// The stock `owner` kernel's claim: `owner` the secret's owner digest,
/// then the call's `binding`. 64 bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
pub struct OwnerClaim {
    pub owner: Digest,
    pub binding: Digest,
}

impl AuthClaim {
    /// Its encoding's length.
    pub const BYTES: usize = 4 * 32;
}

impl OwnerClaim {
    /// Its encoding's length.
    pub const BYTES: usize = 2 * 32;
}

/// A claim's `binding`, its last 32 bytes (`light-node.md` §4.3): every
/// device kernel's claim ends with it. `None` for a claim shorter.
pub fn claim_binding(claim: &[u8]) -> Option<&Digest> {
    claim
        .len()
        .checked_sub(32)
        .map(|at| claim[at..].try_into().expect("a claim's last 32 bytes"))
}

/// The proof's public `binding` of the binding digest `b`:
/// `C(T(binding), W(b))`.
pub fn binding(b: &[u8; 32]) -> Digest {
    digest(&compress(&Tag::Binding.block(), &reduced(b)))
}

/// Why the credential actor refused a call: its handlers' error.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
#[repr(u8)]
pub enum CredentialError {
    /// A `member` digest with a word at or above p.
    #[codec(index = 0)]
    NotADigest = 0,
    /// The member is enrolled.
    #[codec(index = 1)]
    Enrolled = 1,
    /// The member is neither enrolled nor invited.
    #[codec(index = 2)]
    NotEnrolled = 2,
    /// Every slot is taken.
    #[codec(index = 3)]
    Full = 3,
    /// More than [`ENROLL_MANY`] members in one call.
    #[codec(index = 4)]
    TooMany = 4,
    /// The member holds no invitation.
    #[codec(index = 5)]
    NotInvited = 5,
    /// The invitation expired before the claim.
    #[codec(index = 6)]
    Expired = 6,
    /// The handle is set already.
    #[codec(index = 7)]
    Founded = 7,
    /// No handle is set yet: the actor takes no write before it is.
    #[codec(index = 8)]
    Unfounded = 8,
    /// The handle given is all zeros, which reads as none.
    #[codec(index = 9)]
    ZeroHandle = 9,
    /// The registrar takes no open claim.
    #[codec(index = 10)]
    Closed = 10,
    /// The open claim's work does not meet its difficulty under the
    /// current salt or the one before.
    #[codec(index = 11)]
    Work = 11,
    /// The open claims of the period reached its cap.
    #[codec(index = 12)]
    Cap = 12,
    /// A difficulty past [`MAX_DIFFICULTY`], a period of zero, or a
    /// person's limit of zero or past [`MAX_DEVICES`].
    #[codec(index = 13)]
    Terms = 13,
    /// The member or the owner digest is a device of a person already, or
    /// the owner digest awaits its confirmation.
    #[codec(index = 14)]
    Held = 14,
    /// The caller's owner digest is no person's confirmed device, or, to
    /// `confirm_device`, awaits no confirmation.
    #[codec(index = 15)]
    NoPerson = 15,
    /// The person holds as many devices as its limit.
    #[codec(index = 16)]
    Limit = 16,
    /// The member is no device of the caller's person.
    #[codec(index = 17)]
    NotYours = 17,
    /// The member holds an invitation: the registrar named it for its
    /// own claim.
    #[codec(index = 18)]
    Invited = 18,
    /// The person's devices of the period, its limit and its
    /// [`REPLACEMENTS`], are spent: the next period, or the registrar's
    /// `reset`, enrolls again.
    #[codec(index = 19)]
    Enrollments = 19,
}

/// The most leading zero bits an open claim's difficulty asks.
pub const MAX_DIFFICULTY: u8 = 64;

/// The open claim's terms as the registrar answers them
/// (`light-node.md` §3.3): the salt its work names now, its difficulty in
/// leading zero bits, the period the cap counts by, the cap, published, and
/// the claims left in the current period.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
pub struct Open {
    pub salt: [u8; 32],
    pub difficulty: u8,
    pub period_ms: u64,
    pub cap: u32,
    pub left: u32,
}

/// A gateway's onion service, as the space's registrar serves it
/// (`light-node.md` §6.1): the ed25519 key its `.onion` address encodes,
/// self-authenticating, and the SSH host key its onion's SSH port presents,
/// which a client pins as it pins the address.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
pub struct Onion {
    pub key: [u8; 32],
    pub ssh_host_key: [u8; 32],
}

/// The salt of the open claim's period `period`, from the registrar's
/// `seed`: `BLAKE2b-256("vos/cred/open/salt" ‖ seed ‖ period)`, the period
/// eight little-endian bytes. No query answers the seed, so no client makes
/// work before its period's salt is served.
pub fn open_salt(seed: &[u8; 32], period: u64) -> [u8; 32] {
    vos_pvm_precompiles::blake2b_hash::<32>(b"vos/cred/open/salt", &[seed, &period.to_le_bytes()])
}

/// The open claim's work for `member` in the space whose handle is
/// `handle`, under `salt`, at `nonce`: `BLAKE2b-256("vos/cred/open/work" ‖
/// handle ‖ member ‖ salt ‖ nonce)`, the nonce eight little-endian bytes.
pub fn open_work(handle: &[u8; 32], member: &Digest, salt: &[u8; 32], nonce: u64) -> [u8; 32] {
    vos_pvm_precompiles::blake2b_hash::<32>(
        b"vos/cred/open/work",
        &[handle, member, salt, &nonce.to_le_bytes()],
    )
}

/// Whether `work` starts with `difficulty` zero bits.
pub fn meets(work: &[u8; 32], difficulty: u8) -> bool {
    let difficulty = u32::from(difficulty);
    let mut zeros = 0;
    for byte in work {
        if *byte != 0 {
            zeros += byte.leading_zeros();
            break;
        }
        zeros += 8;
    }
    zeros >= difficulty
}

/// The key of the ring's row of the credential actor at `actor`: the row
/// [`tables::RING_KEY`] of its hashed table [`tables::RING`], which
/// ingress and the refine both read. Inline, so it is compiled only where
/// it is called: a pinned kernel that does not call it keeps its program
/// id.
#[inline]
pub fn ring_key(actor: InstanceId) -> Vec<u8> {
    let rows = vos_abi::abi::Rows::Table {
        tag: vos_abi::ids::derive_id("vos/table/", tables::RING),
        transform: vos_abi::keys::Transform::Hashed,
    };
    vos_abi::keys::row(actor, rows, &[tables::RING_KEY]).expect("a hashed row's key")
}

/// The time apply judges a proven call's root at ([`Ring::accepts`]): the
/// earlier of the batch's time and the call's expiry less
/// [`crate::defaults::CREDENTIAL_HORIZON_MS`]. Ingress judges at its clock
/// and refuses an expiry more than the horizon past it, so this is no
/// later than the time of any ingress that admitted the call; and apply
/// refuses an expiry before the batch's time, so it is no earlier than
/// the batch's time less the horizon. So no replica refuses at apply a
/// root an ingress admitted, and a superseded root binds every replica
/// within [`crate::defaults::ROOT_GRACE_MS`] and the horizon.
pub fn judged_at(batch_time: u64, expires_ms: u64) -> u64 {
    batch_time.min(expires_ms.saturating_sub(crate::defaults::CREDENTIAL_HORIZON_MS))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The ring: a write at the newest entry's time replaces its root,
    /// another appends, the oldest dropped past 64; a root is accepted while
    /// newest and for `ROOT_GRACE_MS` after it was superseded, judged by its
    /// later entry when held twice.
    #[test]
    fn the_ring_records_and_judges_freshness() {
        const AGE: u64 = crate::defaults::ROOT_GRACE_MS;
        let root = |n: u8| [n; 32];
        let mut ring = Ring::installed(5);
        assert_eq!(ring.newest().unwrap().root, digest(&EMPTY[DEPTH]));
        ring.record(root(1), 5);
        assert_eq!(
            ring.0,
            [RootEntry {
                root: root(1),
                since: 5
            }]
        );
        ring.record(root(2), 10);
        ring.record(root(3), 10);
        assert_eq!(ring.0.len(), 2);
        assert_eq!(ring.accepts(&root(2), 0), Err(RootRefusal::Unknown));
        assert_eq!(ring.accepts(&root(3), u64::MAX), Ok(()), "the newest");
        assert_eq!(ring.accepts(&root(1), 10 + AGE), Ok(()));
        assert_eq!(
            ring.accepts(&root(1), 10 + AGE + 1),
            Err(RootRefusal::Stale)
        );
        assert_eq!(ring.accepts(&root(1), 3), Ok(()), "before its successor");
        // root 1 again: its later entry is the newest.
        ring.record(root(1), 20);
        assert_eq!(ring.accepts(&root(1), u64::MAX), Ok(()));
        assert_eq!(
            ring.accepts(&root(3), 20 + AGE + 1),
            Err(RootRefusal::Stale)
        );
        for time in 21..21 + RING as u64 {
            ring.record(root(time as u8), time);
        }
        assert_eq!(ring.0.len(), RING);
        assert_eq!(ring.0[0].since, 20 + 1, "the oldest dropped");
        assert_eq!(ring.accepts(&root(3), 30), Err(RootRefusal::Unknown));
        assert_eq!(Ring::decode_exact(&ring.encode()), Some(ring));
    }

    /// Apply judges a root at the batch's time, or at the call's expiry
    /// less the horizon when that is earlier: never later than the clock
    /// of an ingress that admitted the call, never earlier than the
    /// batch's time less the horizon.
    #[test]
    fn apply_judges_a_root_no_later_than_its_ingress() {
        const HORIZON: u64 = crate::defaults::CREDENTIAL_HORIZON_MS;
        let batch = 1_000_000;
        assert_eq!(judged_at(batch, batch + HORIZON), batch);
        assert_eq!(judged_at(batch, batch + 2 * HORIZON), batch);
        assert_eq!(judged_at(batch, batch), batch - HORIZON);
        assert_eq!(judged_at(batch, batch + 60_000), batch + 60_000 - HORIZON);
        assert_eq!(judged_at(5, 10), 0);
        // Any ingress at `now` admitting an expiry of at most
        // `now + HORIZON`, applied at a batch no earlier than `now`.
        for now in [batch - 1, batch - HORIZON, batch - 30_000] {
            for expires in [now, now + 1, now + HORIZON / 2, now + HORIZON] {
                if expires >= batch {
                    let at = judged_at(batch, expires);
                    assert!(at <= now && at >= batch - HORIZON);
                }
            }
        }
    }

    /// A path's codec is its root, its slot and 1,024 bytes of siblings.
    #[test]
    fn a_path_round_trips() {
        let path = Path {
            root: [1; 32],
            slot: 7,
            siblings: Siblings(core::array::from_fn(|i| [i as u8; 32])),
        };
        let bytes = path.encode();
        assert_eq!(bytes.len(), 32 + 4 + DEPTH * 32);
        assert_eq!(Path::decode_exact(&bytes), Some(path));
        assert_eq!(Path::decode_exact(&bytes[..bytes.len() - 1]), None);
    }
}
