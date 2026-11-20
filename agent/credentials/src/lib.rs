//! The credential actor: the members of a space, each a `member` digest at
//! a slot of a positional sparse Merkle tree of Poseidon2-M31 compressions,
//! depth 32 (`identity-and-authority.md` §6, `proving.md` §8). A member
//! proves its leaf under a root of the ring in zero knowledge; ingress and
//! apply accept a root while it is the newest, and for `ROOT_GRACE_MS` after
//! a write superseded it ([`vos_wire::credentials::Ring::accepts`]).
//!
//! A library actor, installed in the agent whose methods it guards. Its
//! rows are plain: `slots`, `nodes`, `free`, `invites`, `ring`, `changes` and
//! `roots` ([`vos_wire::credentials::tables`]). Each hash is one `0x402` call,
//! served natively by a VOS node and in software on JAM, so the tree is a
//! function of its writes on every host: an enrollment costs 33, the leaf
//! and 32 levels, a revocation 32, and an enrollment of many shares the
//! nodes they have in common.
//!
//! **The tree's feed** (`light-node.md` §6.7): every write of the tree is
//! kept, in order, as a [`Change`]: the leaves it set and the root it left,
//! with that root's place in the ring. `feed(from)` serves them a page at a
//! time to any caller, and `feed_after(root)` from the last write that left
//! a root, so a device keeps the whole tree and computes its own path,
//! never asking for it: no query names a member, and a device reading on
//! names only the root it holds.
//!
//! Every write but `claim`, `claim_open` and a person's device methods is
//! under the role `registrar`, and none but the onion set's is taken
//! before `found` sets the space's handle and the ring's first root.
//!
//! **The onion set** (`light-node.md` §6.1): the space's gateways' onions,
//! each its key and its SSH host key, which the registrar sets and any
//! caller reads; a device pins it at enrollment and refreshes it through
//! any onion of it. Its answer is the gateway's to forge, as any answer
//! it relays is.
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
//! acts for the person only once its own proof confirms it beside its own
//! member digest (`confirm_device(member)`): owner digests are public in a ledger's log, and no
//! person takes another's. A digest awaiting its confirmation is held for
//! [`CONFIRM_MS`]; past that another enrollment may name it, so no person
//! keeps another's digest from its own person. No query answers a person;
//! the registrar and the space's operators, who read its rows and the
//! calls, link its devices.
//!
//! **A person's enrollments are counted:** its devices of a year
//! ([`ENROLLMENT_PERIOD_MS`]), those it held as the year began and those
//! it enrolled in it, are at most its limit and [`REPLACEMENTS`], past
//! which `enroll_device` is refused until the next year or the registrar's
//! `reset`. A device revoked and another enrolled gives a fresh leaf and a
//! fresh nullifier, so the count, not the devices held, is what bounds a
//! person's pseudonyms in a scope. The registrar expels a person whole
//! with `revoke_person`, every device in one write.
//!
//! **`once`** admits a nullifier once in its scope, and each device's
//! secret gives it its own: a guard under `once` admits a member once a
//! device, which the space's chrome states: a person at most its limit
//! and its replacements times in a scope within one period, and twice its
//! limit and three in one spanning a period's end.
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

use vos_abi::credentials as tree;
use vos_abi::credentials::{DEPTH, Digest, EMPTY, Words};
use vos_sdk::p2::{self, InPlace, Secret, Tag, TagHash};
use vos_sdk::prelude::*;
use vos_wire::credentials::{
    CONFIRM_MS, Change, CredentialError, ENROLL_MANY, ENROLLMENT_PERIOD_MS, FEED_BYTES, Feed,
    MAX_DEVICES, MAX_DIFFICULTY, MAX_ONIONS, Onion, Open, Path, REPLACEMENTS, Ring, RootEntry,
    Siblings, meets, open_salt, open_work,
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
/// registrar registered; and its devices of the enrollment period
/// `period` ([`ENROLLMENT_PERIOD_MS`]), those it held as the period began
/// and those it enrolled in it, at most `limit` and [`REPLACEMENTS`].
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct Person {
    pub limit: u8,
    pub devices: Vec<Device>,
    pub period: u64,
    pub enrolled: u8,
}

impl Person {
    /// The count moved to the period of `now`, if that is a later one:
    /// the devices held, carried into it.
    fn roll(&mut self, now: u64) {
        let period = now / ENROLLMENT_PERIOD_MS;
        if period != self.period {
            self.period = period;
            self.enrolled = self.devices.len() as u8;
        }
    }
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
    /// The space's handle, 32 bytes its founder drew; unset until `found`.
    handle: Cell<Digest>,
    /// The lowest slot never used.
    next: Cell<u64>,
    /// The members enrolled.
    count: Cell<u64>,
    slots: Table<Digest, u32>,
    nodes: Table<(u8, u32), Digest>,
    free: Table<u32, (), Ordered>,
    invites: Table<Digest, u64>,
    ring: Cell<Ring>,
    opening: Cell<Opening>,
    persons: Table<u32, Person>,
    owners: Table<Digest, u32>,
    /// Each owner digest an enrollment named, its person's, until its
    /// confirmation or, past the time kept with it, another enrollment.
    pending: Table<Digest, (u32, u64)>,
    devices: Table<Digest, u32>,
    people: Cell<u32>,
    onions: Cell<Vec<Onion>>,
    /// The tree's writes, the feed's length.
    changed: Cell<u64>,
    changes: Table<u64, Change, Ordered>,
    /// Each root a write left → the last write that left it.
    roots: Table<Digest, u64>,
}

#[messages]
impl Credentials {
    /// Set the space's handle, once, and the ring's first root, the empty
    /// tree's: the install's step. A re-founded space's actor takes the
    /// ended space's handle.
    #[msg(role = "registrar")]
    pub async fn found(
        &mut self,
        ctx: &mut Command<Self>,
        handle: Digest,
    ) -> Result<(), CredentialError> {
        if self.handle.is_set() {
            return Err(CredentialError::Founded);
        }
        if handle == [0; 32] {
            return Err(CredentialError::ZeroHandle);
        }
        self.handle.set(&handle);
        self.ring.set(&Ring::installed(ctx.now()));
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
        let mut counts = self.counts();
        for member in &members {
            let leaf = self.admit(member)?;
            let slot = self.place_in(&mut counts, member, false)?;
            leaves.insert(slot, leaf);
            slots.push(slot);
        }
        self.keep(counts);
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
        let opening = match self.opening.get() {
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
        self.opening.set(&opening);
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
            .get()
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
                let salt = open_salt(&opening.seed, period);
                meets(
                    &open_work(&self.handle.get_or_default(), &member, &salt, nonce),
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
        self.opening.set(&opening);
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
        let id = self.people.get().unwrap_or(0);
        let next = id.checked_add(1).ok_or(CredentialError::Full)?;
        self.people.set(&next);
        let person = Person {
            limit,
            devices: Vec::new(),
            period: ctx.now() / ENROLLMENT_PERIOD_MS,
            enrolled: 1,
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

    /// Start the count of `member`'s person's devices of the period again
    /// from those it holds now: the registrar's word, for a person whose
    /// replacements ran out.
    #[msg(role = "registrar")]
    pub async fn reset(
        &mut self,
        ctx: &mut Command<Self>,
        member: Digest,
    ) -> Result<(), CredentialError> {
        self.founded()?;
        let id = self.devices.get(&member).ok_or(CredentialError::NoPerson)?;
        let mut person = self.persons.get(&id).expect("a device's person");
        person.period = ctx.now() / ENROLLMENT_PERIOD_MS;
        person.enrolled = person.devices.len() as u8;
        self.persons.insert(&id, &person);
        Ok(())
    }

    /// Revoke every device of `member`'s person, as `revoke` revokes one,
    /// in one write, and the person with them: an expulsion no device of
    /// the person outruns by enrolling another.
    #[msg(role = "registrar")]
    pub async fn revoke_person(
        &mut self,
        ctx: &mut Command<Self>,
        member: Digest,
    ) -> Result<(), CredentialError> {
        self.founded()?;
        let id = self.devices.get(&member).ok_or(CredentialError::NoPerson)?;
        let person = self.persons.get(&id).expect("a device's person");
        let mut leaves = BTreeMap::new();
        for device in &person.devices {
            if let Ok(Some(slot)) = self.vacate(&device.member) {
                leaves.insert(slot, EMPTY[0]);
            }
            self.forget(id, device);
        }
        self.persons.remove(&id);
        if !leaves.is_empty() {
            self.write(ctx.now(), leaves);
        }
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
        let now = ctx.now();
        let (id, mut person) = self.person_of(ctx.owner())?;
        person.roll(now);
        if person.devices.len() >= usize::from(person.limit) {
            return Err(CredentialError::Limit);
        }
        if person.enrolled >= person.limit.saturating_add(REPLACEMENTS) {
            return Err(CredentialError::Enrollments);
        }
        let leaf = self.admit(&member)?;
        tree::words(&owner).ok_or(CredentialError::NotADigest)?;
        if self.invites.contains(&member) {
            return Err(CredentialError::Invited);
        }
        self.unheld(&member, &owner)?;
        if self
            .pending
            .get(&owner)
            .is_some_and(|(_, until)| now <= until)
        {
            return Err(CredentialError::Held);
        }
        let slot = self.place(&member, true)?;
        self.write(now, BTreeMap::from([(slot, leaf)]));
        person.enrolled += 1;
        self.seat(id, person, Device { member, owner });
        self.pending
            .insert(&owner, &(id, now.saturating_add(CONFIRM_MS)));
        Ok(slot)
    }

    /// Confirm the caller's owner digest as its device's, `member` its own
    /// member digest, named together by an `enroll_device`: from now on it
    /// acts for the person. An enrollment that named the digest beside
    /// another member, another person's, is no confirmation's.
    #[msg(credential = Owner)]
    pub async fn confirm_device(
        &mut self,
        ctx: &mut Command<Self>,
        member: Digest,
    ) -> Result<(), CredentialError> {
        self.founded()?;
        let owner = ctx.owner().ok_or(CredentialError::NoPerson)?;
        let (id, _) = self.pending.get(&owner).ok_or(CredentialError::NoPerson)?;
        let person = self.persons.get(&id).expect("a pending digest's person");
        if !person.devices.contains(&Device { member, owner }) {
            return Err(CredentialError::NoPerson);
        }
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
            .get()
            .and_then(|ring| ring.newest().copied())
            .unwrap_or(RootEntry {
                root: tree::digest(&EMPTY[DEPTH]),
                since: 0,
            })
    }

    /// The tree's feed from its `from`th change: as many changes as
    /// [`FEED_BYTES`] holds, at least one when there is one, and the
    /// feed's length.
    #[msg(gas = 100_000_000)]
    pub async fn feed(&self, from: u64) -> Feed {
        self.page(from)
    }

    /// The tree's feed after the last change that left `root`, a page as
    /// [`Credentials::feed`] gives it; `None` for a root no change left. A
    /// device reads on from the root it holds, which every member that
    /// read the feed as far holds, so its query names no place of its own
    /// that an answer could have written.
    #[msg(gas = 100_000_000)]
    pub async fn feed_after(&self, root: Digest) -> Option<Feed> {
        let last = self.roots.get(&root)?;
        Some(self.page(last + 1))
    }

    /// The feed's page from its `from`th change.
    fn page(&self, from: u64) -> Feed {
        let mut changes = Vec::new();
        let mut bytes = 0;
        for (_, change) in self.changes.iter(from.checked_sub(1).as_ref()) {
            bytes += change.encoded_len();
            if !changes.is_empty() && bytes > FEED_BYTES {
                break;
            }
            changes.push(change);
        }
        Feed {
            from,
            changes,
            length: self.changed.get_or_default(),
        }
    }

    /// Set the space's onion set, its gateways' onions, at most
    /// [`MAX_ONIONS`], each once: a device pins it at enrollment and
    /// refreshes it through any onion of it.
    #[msg(role = "registrar")]
    pub async fn set_onions(&mut self, onions: Vec<Onion>) -> Result<(), CredentialError> {
        let repeated = onions
            .iter()
            .enumerate()
            .any(|(at, onion)| onions[..at].iter().any(|seen| seen.key == onion.key));
        if onions.len() > MAX_ONIONS || repeated {
            return Err(CredentialError::TooMany);
        }
        self.onions.set(&onions);
        Ok(())
    }

    /// The space's onion set; empty until the registrar sets one.
    #[msg]
    pub async fn onions(&self) -> Vec<Onion> {
        self.onions.get_or_default()
    }

    /// The space's handle; zeros before `found`.
    #[msg]
    pub async fn handle(&self) -> Digest {
        self.handle.get_or_default()
    }

    /// The members enrolled.
    #[msg]
    pub async fn count(&self) -> u64 {
        self.count.get_or_default()
    }

    /// The open claim's terms now: its salt, its difficulty, its period,
    /// its cap and the claims the period takes yet; `None` while the
    /// registrar keeps it closed. A query reads at the last batch's time,
    /// so on a home no batch reached this period it names the salt before,
    /// and work under it is refused once two periods passed: the device
    /// asks again.
    #[msg]
    pub async fn opening(&self, ctx: &Query<Self>) -> Option<Open> {
        let opening = self.opening.get().filter(|opening| opening.cap > 0)?;
        let now = ctx.now();
        Some(Open {
            salt: open_salt(&opening.seed, now / opening.period_ms),
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
        if !self.handle.is_set() {
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
        if let Some(slot) = self.vacate(member)? {
            self.write(time, BTreeMap::from([(slot, EMPTY[0])]));
        }
        if let Some(id) = self.devices.get(member) {
            let mut person = self.persons.get(&id).expect("a device's person");
            person.roll(time);
            let at = person
                .devices
                .iter()
                .position(|device| device.member == *member)
                .expect("a device in its person");
            let device = person.devices.remove(at);
            self.forget(id, &device);
            if person.devices.is_empty() {
                self.persons.remove(&id);
            } else {
                self.persons.insert(&id, &person);
            }
        }
        Ok(())
    }

    /// `member`'s slot freed, its leaf left to the caller's write, if it is
    /// enrolled; else its invitation withdrawn.
    fn vacate(&mut self, member: &Digest) -> Result<Option<u32>, CredentialError> {
        if let Some(slot) = self.slots.get(member) {
            self.slots.remove(member);
            self.free.insert(&slot, &());
            self.count.set(&(self.count.get_or_default() - 1));
            Ok(Some(slot))
        } else if self.invites.contains(member) {
            self.invites.remove(member);
            Ok(None)
        } else {
            Err(CredentialError::NotEnrolled)
        }
    }

    /// `device` of the person `id` no longer indexed: its member, and its
    /// owner digest where the person holds or awaits it (a registration,
    /// or a later enrollment past its wait, may have taken it).
    fn forget(&mut self, id: u32, device: &Device) {
        self.devices.remove(&device.member);
        if self.owners.get(&device.owner) == Some(id) {
            self.owners.remove(&device.owner);
        }
        if self.pending.get(&device.owner).map(|(person, _)| person) == Some(id) {
            self.pending.remove(&device.owner);
        }
    }

    /// `member`'s leaf, for a member neither enrolled nor malformed.
    fn admit(&self, member: &Digest) -> Result<Words, CredentialError> {
        let words = tree::words(member).ok_or(CredentialError::NotADigest)?;
        if self.slots.contains(member) {
            return Err(CredentialError::Enrolled);
        }
        Ok(tree::leaf(&words))
    }

    /// [`Credentials::place_in`] for one member, the counts read and kept
    /// around it.
    fn place(&mut self, member: &Digest, reuse: bool) -> Result<u32, CredentialError> {
        let mut counts = self.counts();
        let slot = self.place_in(&mut counts, member, reuse)?;
        self.keep(counts);
        Ok(slot)
    }

    /// The lowest slot never used and the members enrolled, read once for
    /// a handler's placements.
    fn counts(&self) -> (u64, u64) {
        (self.next.get_or_default(), self.count.get_or_default())
    }

    /// Keep `counts` after a handler's placements.
    fn keep(&mut self, (next, count): (u64, u64)) {
        self.next.set(&next);
        self.count.set(&count);
    }

    /// Give `member` the lowest freed slot when `reuse`, else (or when none
    /// is freed) the lowest never used, counted in `counts`, and drop its
    /// invitation.
    fn place_in(
        &mut self,
        (next, count): &mut (u64, u64),
        member: &Digest,
        reuse: bool,
    ) -> Result<u32, CredentialError> {
        let lowest = if reuse { self.free.first() } else { None };
        let slot = match lowest {
            Some((slot, ())) => {
                self.free.remove(&slot);
                slot
            }
            None => {
                let slot = u32::try_from(*next).map_err(|_| CredentialError::Full)?;
                *next += 1;
                slot
            }
        };
        self.slots.insert(member, &slot);
        *count += 1;
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
    /// the new root recorded in the ring at `time`, and the write kept in
    /// the feed.
    fn write(&mut self, time: u64, leaves: BTreeMap<u32, Words>) {
        let set = leaves
            .iter()
            .map(|(&slot, leaf)| (slot, tree::digest(leaf)))
            .collect();
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
        let root = RootEntry {
            root: tree::digest(&changed[&0]),
            since: time,
        };
        let mut ring = self.ring.get_or_default();
        ring.record(root.root, time);
        self.ring.set(&ring);
        let length = self.changed.get_or_default();
        self.changes.insert(&length, &Change { leaves: set, root });
        self.roots.insert(&root.root, &length);
        self.changed.set(&(length + 1));
    }
}
