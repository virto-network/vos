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
//! Every write but `claim` is under the role `registrar`, and none is
//! taken before `found` sets the space's handle and the ring's first root.

#![no_std]

extern crate alloc;

use alloc::collections::BTreeMap;

use vos_sdk::prelude::*;
use vos_wire::credentials::{
    self as tree, CredentialError, DEPTH, Digest, EMPTY, ENROLL_MANY, Path, Ring, RootEntry,
    Siblings, Words, tables::RING_KEY,
};

#[actor]
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

    /// Revoke `member`: its leaf back to the empty leaf, its slot freed for
    /// the next enrollment; or its invitation withdrawn.
    #[msg(role = "registrar")]
    pub async fn revoke(
        &mut self,
        ctx: &mut Command<Self>,
        member: Digest,
    ) -> Result<(), CredentialError> {
        self.founded()?;
        tree::words(&member).ok_or(CredentialError::NotADigest)?;
        if let Some(slot) = self.slots.get(&member) {
            self.slots.remove(&member);
            self.free.insert(&slot, &());
            self.count -= 1;
            self.write(ctx.now(), BTreeMap::from([(slot, EMPTY[0])]));
            Ok(())
        } else if self.invites.contains(&member) {
            self.invites.remove(&member);
            Ok(())
        } else {
            Err(CredentialError::NotEnrolled)
        }
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
}

impl Credentials {
    fn founded(&self) -> Result<(), CredentialError> {
        if self.handle == [0; 32] {
            Err(CredentialError::Unfounded)
        } else {
            Ok(())
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
