//! The credential actor: the members of a space, each a `member` digest at
//! a slot of a positional sparse Merkle tree of Poseidon2-M31 compressions,
//! depth 32 (`identity-and-authority.md` §6, `proving.md` §8). A member
//! proves its leaf under a root of the ring in zero knowledge; ingress and
//! apply accept a root while it is the newest, and for `ROOT_MAX_AGE` after
//! a write superseded it ([`vos_wire::credentials::Ring::accepts`]).
//!
//! A library actor, installed in the agent whose methods it guards. Its
//! rows are plain: `slots`, `nodes`, `free`, `invites` and `ring`
//! ([`vos_wire::credentials::tables`]). Each hash is one `0x402` call,
//! served natively by a VOS node and in software on JAM, so the tree is a
//! function of its writes on every host: an enrollment costs 33, the leaf
//! and 32 levels, a revocation 32, and an enrollment of many shares the
//! nodes they have in common.
//!
//! Every write but `claim`, `claim_open` and a person's device methods is
//! under the role `registrar`, and none is taken before
//! `found` sets the space's handle and the ring's first root.
//!
//! **The open claim** (`light-node.md` §3.3): a space that admits anyone,
//! a home-only space, has its registrar `open` it; then any caller enrolls
//! a member by work, a nonce whose hash over the space's handle, the
//! member and the period's salt starts with the difficulty's zero bits,
//! at most the cap's members a period. The work only stops a trivial loop;
//! the cap bounds what a home admits.
//!
//! **Persons** (`light-node.md` §3.8): each device of a member holds a
//! secret of its own, so a leaf and an owner digest of its own, which
//! nothing links. The registrar, which knows both digests of the member it
//! enrolls, records them as a person's first device with `register`, and
//! the person's limit of devices. A device of the person then enrolls
//! another, `enroll_device(member, owner)` under its owner proof, and
//! revokes any of the person's, `revoke_device(member)`. The digests it
//! names are its word, so a member or an owner digest any person holds, an
//! enrolled member and an invited one are refused, and the new owner digest
//! acts for the person only once its own proof confirms it
//! (`confirm_device`): owner digests are public in a ledger's log, and no
//! person takes another's. No query answers a person; the registrar and
//! the space's operators, who read its rows and the calls, link its
//! devices.
//!
//! **`once`** admits a nullifier once in its scope, and each device's
//! secret gives it its own: a guard under `once` admits a member once a
//! device, which the space's chrome states.
//!
//! **The stock kernels** (`light-node.md` §4.2): `auth` and `owner`, the
//! device kernels every space gets with this actor, written with the SDK
//! (`vos_sdk::p2`), their arguments read in place. Each is sized on the
//! credential kernels' public reference statement
//! (`vos_sdk::p2::reference`), and a release embeds their device programs.
//! Each claim ends with the call's `binding`, which the kernel carries
//! without reading; the claims carry no kind byte, the guard naming the
//! kernel.

#![no_std]

extern crate alloc;

use alloc::collections::BTreeMap;

use vos_sdk::p2::{self, InPlace, Secret, Tag, TagHash};
use vos_sdk::prelude::*;
use vos_wire::credentials::{
    self as tree, CredentialError, DEPTH, Digest, EMPTY, ENROLL_MANY, MAX_DEVICES, MAX_DIFFICULTY,
    Open, Path, Ring, RootEntry, Siblings, Words, tables::RING_KEY,
};

/// The open claim's terms and the current period's count.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
pub struct Opening {
    pub difficulty: u8,
    pub cap: u32,
    pub period_ms: u64,
    /// The salts' seed, drawn at the first opening and kept: no query
    /// answers it, though its replicas and its operators hold it.
    pub seed: [u8; 32],
    /// The period `count` is of, and the members it enrolled.
    pub period: u64,
    pub count: u32,
}

impl Opening {
    /// The members the period at `now` takes yet.
    fn left(&self, now: u64) -> u32 {
        if now / self.period_ms == self.period {
            self.cap.saturating_sub(self.count)
        } else {
            self.cap
        }
    }
}

/// A device of a person: its leaf's member digest and its owner digest.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
pub struct Device {
    pub member: Digest,
    pub owner: Digest,
}

/// A person's record: its devices, at most `limit`, the first the one the
/// registrar registered.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct Person {
    pub limit: u8,
    pub devices: Vec<Device>,
}

/// Auth's claim, the stock `auth` kernel's public arguments: the member's
/// leaf under `map_root`, and `nullifier` its pseudonym in `scope`.
#[derive(Clone, Copy, InPlace)]
#[repr(C)]
pub struct AuthClaim {
    pub map_root: p2::Digest,
    pub scope: p2::Digest,
    pub nullifier: p2::Digest,
    pub binding: p2::Digest,
}

/// Owner's claim, the stock `owner` kernel's public arguments: `owner` the
/// secret's owner digest.
#[derive(Clone, Copy, InPlace)]
#[repr(C)]
pub struct OwnerClaim {
    pub owner: p2::Digest,
    pub binding: p2::Digest,
}

/// The stock kernels' reference runs: the public reference statement, each
/// in its kernel's arguments.
mod reference {
    use vos_sdk::p2::reference::{BINDING, PATH, SCOPE, SECRET};

    use super::*;

    pub fn auth() -> credentials::Auth {
        let member = Tag::Member.hash(&SECRET);
        credentials::Auth {
            path: PATH,
            secret: SECRET,
            claim: AuthClaim {
                map_root: PATH.root(&Tag::Leaf.hash(&member)),
                scope: SCOPE,
                nullifier: Tag::Nf.hash(&SECRET).hash(&SCOPE),
                binding: BINDING,
            },
        }
    }

    pub fn owner() -> credentials::Owner {
        credentials::Owner {
            secret: SECRET,
            claim: OwnerClaim {
                owner: Tag::Owner.hash(&SECRET),
                binding: BINDING,
            },
        }
    }
}

#[actor(credentials)]
pub struct Credentials {
    /// The space's handle, 32 bytes its founder drew; zeros until `found`.
    handle: Digest,
    /// The lowest slot never used.
    next: u64,
    /// The members enrolled.
    count: u64,
    slots: Table<Digest, u32>,
    nodes: Table<(u8, u32), Digest>,
    free: Table<u32, (), Ordered>,
    invites: Table<Digest, u64>,
    ring: Table<u8, Ring>,
    opening: Table<u8, Opening>,
    persons: Table<u32, Person>,
    owners: Table<Digest, u32>,
    pending: Table<Digest, u32>,
    devices: Table<Digest, u32>,
    people: Table<u8, u32>,
}

#[messages]
impl Credentials {
    pub fn new() -> Self {
        Self {
            handle: [0; 32],
            next: 0,
            count: 0,
            slots: Table::default(),
            nodes: Table::default(),
            free: Table::default(),
            invites: Table::default(),
            ring: Table::default(),
            opening: Table::default(),
            persons: Table::default(),
            owners: Table::default(),
            pending: Table::default(),
            devices: Table::default(),
            people: Table::default(),
        }
    }

    /// Set the space's handle, once, and the ring's first root, the empty
    /// tree's: the install's step. A re-founded space's actor takes the
    /// ended space's handle.
    #[msg(role = "registrar")]
    pub async fn found(
        &mut self,
        ctx: &mut Command<Self>,
        handle: Digest,
    ) -> Result<(), CredentialError> {
        if self.handle != [0; 32] {
            return Err(CredentialError::Founded);
        }
        if handle == [0; 32] {
            return Err(CredentialError::ZeroHandle);
        }
        self.handle = handle;
        self.ring.insert(&RING_KEY, &Ring::installed(ctx.now()));
        Ok(())
    }

    /// Enroll `member` at the lowest free slot, else the lowest never used.
    #[msg(role = "registrar")]
    pub async fn enroll(
        &mut self,
        ctx: &mut Command<Self>,
        member: Digest,
    ) -> Result<u32, CredentialError> {
        self.founded()?;
        let leaf = self.admit(&member)?;
        let slot = self.place(&member, true)?;
        self.write(ctx.now(), BTreeMap::from([(slot, leaf)]));
        Ok(slot)
    }

    /// Enroll each of `members`, at most [`ENROLL_MANY`], in order, at the
    /// lowest slots never used: the re-founding runbook's re-seed, into a
    /// tree with no freed slot. Contiguous fresh slots share their upper
    /// nodes, so the most members fit one handler's gas whatever slots the
    /// tree has freed. One fails, and none is enrolled.
    #[msg(role = "registrar", gas = 100_000_000)]
    pub async fn enroll_many(
        &mut self,
        ctx: &mut Command<Self>,
        members: Vec<Digest>,
    ) -> Result<Vec<u32>, CredentialError> {
        self.founded()?;
        if members.len() > ENROLL_MANY {
            return Err(CredentialError::TooMany);
        }
        let mut leaves = BTreeMap::new();
        let mut slots = Vec::with_capacity(members.len());
        for member in &members {
            let leaf = self.admit(member)?;
            let slot = self.place(member, false)?;
            leaves.insert(slot, leaf);
            slots.push(slot);
        }
        if !leaves.is_empty() {
            self.write(ctx.now(), leaves);
        }
        Ok(slots)
    }

    /// Invite `member` to enroll itself until `expires_ms`, in batch time.
    /// The invitation names the digest, so a claim can enroll no other.
    #[msg(role = "registrar")]
    pub async fn invite(&mut self, member: Digest, expires_ms: u64) -> Result<(), CredentialError> {
        self.founded()?;
        tree::words(&member).ok_or(CredentialError::NotADigest)?;
        if self.slots.contains(&member) {
            return Err(CredentialError::Enrolled);
        }
        self.invites.insert(&member, &expires_ms);
        Ok(())
    }

    /// Enroll `member` on its invitation, by its expiry: any caller, whose
    /// authority is the invitation.
    #[msg]
    pub async fn claim(
        &mut self,
        ctx: &mut Command<Self>,
        member: Digest,
    ) -> Result<u32, CredentialError> {
        self.founded()?;
        let leaf = self.admit(&member)?;
        let expires = self
            .invites
            .get(&member)
            .ok_or(CredentialError::NotInvited)?;
        if ctx.now() > expires {
            return Err(CredentialError::Expired);
        }
        let slot = self.place(&member, true)?;
        self.write(ctx.now(), BTreeMap::from([(slot, leaf)]));
        Ok(slot)
    }

    /// Open claims to any caller whose work meets `difficulty`, at most
    /// `cap` members a period of `period_ms` of batch time; a cap of 0
    /// closes them. The salts' seed is drawn at the first opening.
    #[msg(role = "registrar")]
    pub async fn open(
        &mut self,
        ctx: &mut Command<Self>,
        difficulty: u8,
        cap: u32,
        period_ms: u64,
    ) -> Result<(), CredentialError> {
        self.founded()?;
        if difficulty > MAX_DIFFICULTY || period_ms == 0 {
            return Err(CredentialError::Terms);
        }
        let now = ctx.now();
        let period = now / period_ms;
        let opening = match self.opening.get(&RING_KEY) {
            Some(opening) => Opening {
                difficulty,
                cap,
                period_ms,
                period,
                count: if opening.period_ms == period_ms && opening.period == period {
                    opening.count
                } else {
                    0
                },
                ..opening
            },
            None => Opening {
                difficulty,
                cap,
                period_ms,
                seed: ctx.random(),
                period,
                count: 0,
            },
        };
        self.opening.insert(&RING_KEY, &opening);
        Ok(())
    }

    /// Enroll `member` by its work at `nonce`, under the period's salt or
    /// the one before: any caller, within the period's cap.
    #[msg]
    pub async fn claim_open(
        &mut self,
        ctx: &mut Command<Self>,
        member: Digest,
        nonce: u64,
    ) -> Result<u32, CredentialError> {
        self.founded()?;
        let leaf = self.admit(&member)?;
        let mut opening = self
            .opening
            .get(&RING_KEY)
            .filter(|opening| opening.cap > 0)
            .ok_or(CredentialError::Closed)?;
        let now = ctx.now();
        let period = now / opening.period_ms;
        if opening.left(now) == 0 {
            return Err(CredentialError::Cap);
        }
        let met = [Some(period), period.checked_sub(1)]
            .into_iter()
            .flatten()
            .any(|period| {
                let salt = tree::open_salt(&opening.seed, period);
                tree::meets(
                    &tree::open_work(&self.handle, &member, &salt, nonce),
                    opening.difficulty,
                )
            });
        if !met {
            return Err(CredentialError::Work);
        }
        if opening.period != period {
            opening.period = period;
            opening.count = 0;
        }
        opening.count += 1;
        self.opening.insert(&RING_KEY, &opening);
        let slot = self.place(&member, true)?;
        self.write(now, BTreeMap::from([(slot, leaf)]));
        Ok(slot)
    }

    /// Revoke `member`: its leaf back to the empty leaf, its slot freed for
    /// the next enrollment, or its invitation withdrawn; and dropped from
    /// its person.
    #[msg(role = "registrar")]
    pub async fn revoke(
        &mut self,
        ctx: &mut Command<Self>,
        member: Digest,
    ) -> Result<(), CredentialError> {
        self.founded()?;
        tree::words(&member).ok_or(CredentialError::NotADigest)?;
        self.unseat(ctx.now(), &member)
    }

    /// Record `member`, enrolled or invited until now or later, with its
    /// owner digest `owner` as the first device of a person of at most
    /// `limit` devices. An enrollment awaiting `owner`'s confirmation gives
    /// way: the registrar's word is the binding one.
    #[msg(role = "registrar")]
    pub async fn register(
        &mut self,
        ctx: &mut Command<Self>,
        member: Digest,
        owner: Digest,
        limit: u8,
    ) -> Result<(), CredentialError> {
        self.founded()?;
        tree::words(&member).ok_or(CredentialError::NotADigest)?;
        tree::words(&owner).ok_or(CredentialError::NotADigest)?;
        if limit == 0 || limit > MAX_DEVICES {
            return Err(CredentialError::Terms);
        }
        if !self.slots.contains(&member) {
            let expires = self
                .invites
                .get(&member)
                .ok_or(CredentialError::NotEnrolled)?;
            if ctx.now() > expires {
                return Err(CredentialError::Expired);
            }
        }
        self.unheld(&member, &owner)?;
        if self.pending.contains(&owner) {
            self.pending.remove(&owner);
        }
        let id = self.people.get(&RING_KEY).unwrap_or(0);
        let next = id.checked_add(1).ok_or(CredentialError::Full)?;
        self.people.insert(&RING_KEY, &next);
        let person = Person {
            limit,
            devices: Vec::new(),
        };
        self.seat(id, person, Device { member, owner });
        self.owners.insert(&owner, &id);
        Ok(())
    }

    /// Set the limit of `member`'s person to `limit`; devices past it stay
    /// enrolled, and the person enrolls none until it is below.
    #[msg(role = "registrar")]
    pub async fn limit(&mut self, member: Digest, limit: u8) -> Result<(), CredentialError> {
        self.founded()?;
        if limit == 0 || limit > MAX_DEVICES {
            return Err(CredentialError::Terms);
        }
        let id = self.devices.get(&member).ok_or(CredentialError::NoPerson)?;
        let mut person = self.persons.get(&id).expect("a device's person");
        person.limit = limit;
        self.persons.insert(&id, &person);
        Ok(())
    }

    /// Enroll `member` as a device of the person whose device proved the
    /// caller's owner digest, within the person's limit: its slot. Its
    /// leaf proves at once; `owner`, its owner digest, acts for the person
    /// once its own proof confirms it (`confirm_device`).
    #[msg(credential = Owner)]
    pub async fn enroll_device(
        &mut self,
        ctx: &mut Command<Self>,
        member: Digest,
        owner: Digest,
    ) -> Result<u32, CredentialError> {
        self.founded()?;
        let (id, person) = self.person_of(ctx.owner())?;
        if person.devices.len() >= usize::from(person.limit) {
            return Err(CredentialError::Limit);
        }
        let leaf = self.admit(&member)?;
        tree::words(&owner).ok_or(CredentialError::NotADigest)?;
        if self.invites.contains(&member) {
            return Err(CredentialError::Invited);
        }
        self.unheld(&member, &owner)?;
        if self.pending.contains(&owner) {
            return Err(CredentialError::Held);
        }
        let slot = self.place(&member, true)?;
        self.write(ctx.now(), BTreeMap::from([(slot, leaf)]));
        self.seat(id, person, Device { member, owner });
        self.pending.insert(&owner, &id);
        Ok(slot)
    }

    /// Confirm the caller's owner digest as its device's, named by an
    /// `enroll_device`: from now on it acts for the person.
    #[msg(credential = Owner)]
    pub async fn confirm_device(&mut self, ctx: &mut Command<Self>) -> Result<(), CredentialError> {
        self.founded()?;
        let owner = ctx.owner().ok_or(CredentialError::NoPerson)?;
        let id = self.pending.get(&owner).ok_or(CredentialError::NoPerson)?;
        self.pending.remove(&owner);
        self.owners.insert(&owner, &id);
        Ok(())
    }

    /// Revoke `member`, a device of the person whose device proved the
    /// caller's owner digest, the caller's own included, as `revoke` does.
    #[msg(credential = Owner)]
    pub async fn revoke_device(
        &mut self,
        ctx: &mut Command<Self>,
        member: Digest,
    ) -> Result<(), CredentialError> {
        self.founded()?;
        let (id, _) = self.person_of(ctx.owner())?;
        if self.devices.get(&member) != Some(id) {
            return Err(CredentialError::NotYours);
        }
        self.unseat(ctx.now(), &member)
    }

    /// `member`'s path: the tree's root, its slot and the 32 siblings from
    /// its leaf up; `None` when it is not enrolled.
    #[msg]
    pub async fn path(&self, member: Digest) -> Option<Path> {
        let slot = self.slots.get(&member)?;
        let siblings =
            core::array::from_fn(|level| tree::digest(&self.node(level, (slot >> level) ^ 1)));
        Some(Path {
            root: tree::digest(&self.node(DEPTH, 0)),
            slot,
            siblings: Siblings(siblings),
        })
    }

    /// The tree's root and the batch time it became the root; before
    /// `found`, the empty tree's from time 0.
    #[msg]
    pub async fn root(&self) -> RootEntry {
        self.ring
            .get(&RING_KEY)
            .and_then(|ring| ring.newest().copied())
            .unwrap_or(RootEntry {
                root: tree::digest(&EMPTY[DEPTH]),
                since: 0,
            })
    }

    /// The space's handle; zeros before `found`.
    #[msg]
    pub async fn handle(&self) -> Digest {
        self.handle
    }

    /// The members enrolled.
    #[msg]
    pub async fn count(&self) -> u64 {
        self.count
    }

    /// The open claim's terms now: its salt, its difficulty, its period,
    /// its cap and the claims the period takes yet; `None` while the
    /// registrar keeps it closed. A query reads at the last batch's time,
    /// so on a home no batch reached this period it names the salt before,
    /// and work under it is refused once two periods passed: the device
    /// asks again.
    #[msg]
    pub async fn opening(&self, ctx: &Query<Self>) -> Option<Open> {
        let opening = self
            .opening
            .get(&RING_KEY)
            .filter(|opening| opening.cap > 0)?;
        let now = ctx.now();
        Some(Open {
            salt: tree::open_salt(&opening.seed, now / opening.period_ms),
            difficulty: opening.difficulty,
            period_ms: opening.period_ms,
            cap: opening.cap,
            left: opening.left(now),
        })
    }

    /// The secret's member's leaf lies under `map_root` by `path`, and
    /// `nullifier` is its nullifier in `scope`. The next release's checks
    /// the nullifier first: another program, the same claims.
    #[attestable(device, reference = reference::auth)]
    pub fn auth(path: &p2::Path, secret: &Secret, #[public] claim: &AuthClaim) {
        if cfg!(feature = "next") {
            assert_eq!(Tag::Nf.hash(secret).hash(&claim.scope), claim.nullifier);
        }
        let member = Tag::Member.hash(secret);
        assert_eq!(path.root(&Tag::Leaf.hash(&member)), claim.map_root);
        if !cfg!(feature = "next") {
            assert_eq!(Tag::Nf.hash(secret).hash(&claim.scope), claim.nullifier);
        }
    }

    /// The secret's owner digest is `owner`.
    #[attestable(device, reference = reference::owner)]
    pub fn owner(secret: &Secret, #[public] claim: &OwnerClaim) {
        assert_eq!(Tag::Owner.hash(secret), claim.owner);
    }
}

impl Credentials {
    fn founded(&self) -> Result<(), CredentialError> {
        if self.handle == [0; 32] {
            Err(CredentialError::Unfounded)
        } else {
            Ok(())
        }
    }

    /// The person whose device's owner digest is `owner`, and its id.
    fn person_of(&self, owner: Option<Digest>) -> Result<(u32, Person), CredentialError> {
        let id = owner
            .and_then(|owner| self.owners.get(&owner))
            .ok_or(CredentialError::NoPerson)?;
        Ok((id, self.persons.get(&id).expect("an owner's person")))
    }

    /// Refuse a member or an owner digest a person holds.
    fn unheld(&self, member: &Digest, owner: &Digest) -> Result<(), CredentialError> {
        if self.devices.contains(member) || self.owners.contains(owner) {
            Err(CredentialError::Held)
        } else {
            Ok(())
        }
    }

    /// `device` added to the person `id`, `person` as it was; its owner
    /// digest indexed by the caller.
    fn seat(&mut self, id: u32, mut person: Person, device: Device) {
        self.devices.insert(&device.member, &id);
        person.devices.push(device);
        self.persons.insert(&id, &person);
    }

    /// `member`'s leaf emptied and its slot freed, or its invitation
    /// withdrawn; and the member dropped from its person, the person with
    /// it once it holds no device.
    fn unseat(&mut self, time: u64, member: &Digest) -> Result<(), CredentialError> {
        if let Some(slot) = self.slots.get(member) {
            self.slots.remove(member);
            self.free.insert(&slot, &());
            self.count -= 1;
            self.write(time, BTreeMap::from([(slot, EMPTY[0])]));
        } else if self.invites.contains(member) {
            self.invites.remove(member);
        } else {
            return Err(CredentialError::NotEnrolled);
        }
        if let Some(id) = self.devices.get(member) {
            self.devices.remove(member);
            let mut person = self.persons.get(&id).expect("a device's person");
            let at = person
                .devices
                .iter()
                .position(|device| device.member == *member)
                .expect("a device in its person");
            let owner = person.devices.remove(at).owner;
            // A registration may have taken an unconfirmed owner digest.
            if self.owners.get(&owner) == Some(id) {
                self.owners.remove(&owner);
            }
            if self.pending.get(&owner) == Some(id) {
                self.pending.remove(&owner);
            }
            if person.devices.is_empty() {
                self.persons.remove(&id);
            } else {
                self.persons.insert(&id, &person);
            }
        }
        Ok(())
    }

    /// `member`'s leaf, for a member neither enrolled nor malformed.
    fn admit(&self, member: &Digest) -> Result<Words, CredentialError> {
        let words = tree::words(member).ok_or(CredentialError::NotADigest)?;
        if self.slots.contains(member) {
            return Err(CredentialError::Enrolled);
        }
        Ok(tree::leaf(&words))
    }

    /// Give `member` the lowest freed slot when `reuse`, else (or when none
    /// is freed) the lowest never used, and drop its invitation.
    fn place(&mut self, member: &Digest, reuse: bool) -> Result<u32, CredentialError> {
        let lowest = if reuse { self.free.first() } else { None };
        let slot = match lowest {
            Some((slot, ())) => {
                self.free.remove(&slot);
                slot
            }
            None => {
                let slot = u32::try_from(self.next).map_err(|_| CredentialError::Full)?;
                self.next += 1;
                slot
            }
        };
        self.slots.insert(member, &slot);
        self.count += 1;
        if self.invites.contains(member) {
            self.invites.remove(member);
        }
        Ok(slot)
    }

    /// The node at `level`, `index`: its row, or the empty subtree's.
    fn node(&self, level: usize, index: u32) -> Words {
        self.nodes
            .get(&(level as u8, index))
            .and_then(|digest| tree::words(&digest))
            .unwrap_or(EMPTY[level])
    }

    /// Set the leaves at their slots, every node above them recomputed once,
    /// and the new root recorded in the ring at `time`.
    fn write(&mut self, time: u64, leaves: BTreeMap<u32, Words>) {
        let mut changed = leaves;
        for level in 0..=DEPTH {
            for (&index, node) in &changed {
                let key = (level as u8, index);
                if *node == EMPTY[level] {
                    self.nodes.remove(&key);
                } else {
                    self.nodes.insert(&key, &tree::digest(node));
                }
            }
            if level == DEPTH {
                break;
            }
            let mut parents = BTreeMap::new();
            for (&index, node) in &changed {
                if parents.contains_key(&(index >> 1)) {
                    continue;
                }
                let sibling = changed
                    .get(&(index ^ 1))
                    .copied()
                    .unwrap_or_else(|| self.node(level, index ^ 1));
                let parent = if index & 1 == 0 {
                    tree::compress(node, &sibling)
                } else {
                    tree::compress(&sibling, node)
                };
                parents.insert(index >> 1, parent);
            }
            changed = parents;
        }
        let root = changed[&0];
        let mut ring = self.ring.get(&RING_KEY).unwrap_or_default();
        ring.record(tree::digest(&root), time);
        self.ring.insert(&RING_KEY, &ring);
    }
}
