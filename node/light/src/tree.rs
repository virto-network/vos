//! The member's credential tree, kept whole from the credential actor's
//! feed (`light-node.md` §6.7): every write of the tree read in order, a
//! page at a time, on the space's feed connection, and the member's path
//! computed here. So no query names the member, and its proofs are made
//! against the newest root the device has read, the one every member who
//! read the feed since holds.
//!
//! **Checked as it comes.** Each change names the root it left. A page's
//! changes are applied at once, each slot's last leaf, every node above
//! them computed once, and the tree they leave must have the root its last
//! change names: the one root a proof uses, which binds every leaf, so a
//! change before it that named another root left no leaf the device
//! keeps. A page that leaves another root, holds a leaf that is no digest,
//! a change of no leaves or out of slot order or older than the last, or
//! does not start at the keeper's place or overruns the feed's length, is
//! refused whole and the tree kept as it was. The answer is still the
//! gateway's word, as any answer it relays: a withheld change shows as
//! `RootStale` at the next proof, which [`TreeKeeper::unknown`] answers.
//!
//! **When.** The feed is read on a jittered timer of its own,
//! [`TreeKeeper::PERIOD_MS`] (30 s, between 15 s and 45 s), never because a
//! proof is about to be made: the feed's connection is one circuit of the
//! device's for as long as it is open, and a read just before each proof
//! would join the proofs through it. A page that says more follows is due
//! at once. The ring's limits are the path keeper's (`crate::PathKeeper`):
//! a root held at most one period behind the tree survives unless the
//! space makes 64 tree-changing batches within one period; a space faster
//! than that meets `RootUnknown`, and [`TreeKeeper::unknown`] makes the
//! feed due at once and halves the period (to at least
//! [`TreeKeeper::MIN_PERIOD_MS`]), which doubles back toward the default
//! at each read that finds the tree unchanged.
//!
//! **Kept on the device** ([`TreeKeeper::encode`], [`TreeKeeper::restore`]):
//! the leaves, the feed's place and the root, outside any synced scope
//! (`light-node.md` §3.1), so a restart reads only the changes since.

use std::collections::{BTreeMap, HashMap};

use scale::{Decode, Encode};
use vos_wire::credentials::{self, DEPTH, EMPTY, Feed, RootEntry, Words};

use crate::path::jitter;
use crate::{AuthWitness, DeviceError, Digest, wire};

/// The tree as the feed built it, the member's slot in it, and when to
/// read the feed again.
pub struct TreeKeeper {
    member: Digest,
    /// The member's leaf, `C(T(leaf), member)`.
    leaf: Words,
    /// Every node that is not its empty subtree's, by level and index;
    /// level 0 holds the leaves.
    nodes: HashMap<(u8, u32), Words>,
    /// The changes applied: the next one the feed is read from.
    cursor: u64,
    /// The root the last change left, and the batch time it became the
    /// root; the empty tree's from 0 before any.
    root: RootEntry,
    /// The member's slot, while its leaf is in the tree.
    slot: Option<u32>,
    /// When the timer is next due, by the client's clock in milliseconds.
    next: u64,
    /// The timer's period before its jitter.
    period: u64,
}

/// What a page did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Synced {
    /// The changes it applied.
    pub applied: u64,
    /// Whether the feed holds more: the next page is due at once.
    pub more: bool,
}

/// What [`TreeKeeper::encode`] keeps.
#[derive(Encode, Decode)]
struct Kept {
    cursor: u64,
    root: RootEntry,
    leaves: Vec<(u32, [u8; 32])>,
}

impl TreeKeeper {
    /// The timer's period, before its jitter of half a period either way:
    /// one twentieth of `ROOT_MAX_AGE`, the path keeper's.
    pub const PERIOD_MS: u64 = vos_wire::defaults::ROOT_MAX_AGE / 20;
    /// The least period a run of `RootUnknown` answers halves it to.
    pub const MIN_PERIOD_MS: u64 = 1_000;

    /// A keeper for `member` holding the empty tree: due at once.
    pub fn new(member: Digest) -> Self {
        Self {
            member,
            leaf: credentials::leaf(&member.0),
            nodes: HashMap::new(),
            cursor: 0,
            root: RootEntry {
                root: credentials::digest(&EMPTY[DEPTH]),
                since: 0,
            },
            slot: None,
            next: 0,
            period: Self::PERIOD_MS,
        }
    }

    /// A keeper for `member` from what [`TreeKeeper::encode`] kept: the
    /// tree rebuilt from its leaves, refused ([`DeviceError::Decode`])
    /// unless it decodes and its root is the one kept. Due at once.
    pub fn restore(member: Digest, bytes: &[u8]) -> Result<Self, DeviceError> {
        let kept = Kept::decode_exact(bytes).ok_or(DeviceError::Decode)?;
        let mut keeper = Self::new(member);
        let mut leaves = Vec::with_capacity(kept.leaves.len());
        for (slot, leaf) in &kept.leaves {
            leaves.push((*slot, credentials::words(leaf).ok_or(DeviceError::Decode)?));
        }
        let mut undo = Vec::new();
        keeper.set_leaves(&leaves, &mut undo);
        if keeper.top() != kept.root.root {
            return Err(DeviceError::Decode);
        }
        keeper.cursor = kept.cursor;
        keeper.root = kept.root;
        Ok(keeper)
    }

    /// The tree's leaves, the feed's place and the root, for
    /// [`TreeKeeper::restore`].
    pub fn encode(&self) -> Vec<u8> {
        let mut leaves: Vec<_> = self
            .nodes
            .iter()
            .filter(|((level, _), _)| *level == 0)
            .map(|(&(_, slot), leaf)| (slot, credentials::digest(leaf)))
            .collect();
        leaves.sort_unstable_by_key(|(slot, _)| *slot);
        Kept {
            cursor: self.cursor,
            root: self.root,
            leaves,
        }
        .encode()
    }

    /// The query of the feed's next page at `instance` of `agent`, the
    /// credential actor, signed by a fresh key over the agent's
    /// `identity`: it names the keeper's place, nothing of the member's.
    pub fn request(
        &self,
        agent: u32,
        identity: &[u8; 32],
        instance: u32,
        not_after: u64,
    ) -> Result<Vec<u8>, DeviceError> {
        wire::feed_query(agent, identity, instance, self.cursor, not_after)
    }

    /// Whether to read the feed now: the jittered timer is due, or a page
    /// said more follows, or a proof met an unknown root.
    pub fn due(&self, now_ms: u64) -> bool {
        now_ms >= self.next
    }

    /// The answer to [`TreeKeeper::request`], read at `now_ms`: its page
    /// applied, and the timer set (due at once while the feed holds more).
    pub fn ingest(&mut self, answer: &[u8], now_ms: u64) -> Result<Synced, DeviceError> {
        let page = wire::feed_answer(answer)?;
        let read = self.apply(&page)?;
        if read.more {
            self.next = now_ms;
        } else {
            if read.applied == 0 {
                self.period = (self.period * 2).min(Self::PERIOD_MS);
            }
            self.next = now_ms.saturating_add(self.period / 2 + jitter(self.period));
        }
        Ok(read)
    }

    /// `page` applied, the tree it leaves checked against the root its last
    /// change names; a page that fails is refused whole
    /// ([`DeviceError::Witness`]), the tree as it was. A page from a replica behind the keeper,
    /// whose feed is shorter than the keeper's place, holds nothing new.
    pub fn apply(&mut self, page: &Feed) -> Result<Synced, DeviceError> {
        let end = page
            .from
            .checked_add(page.changes.len() as u64)
            .ok_or(DeviceError::Decode)?;
        if page.length < self.cursor && page.changes.is_empty() {
            return Ok(Synced {
                applied: 0,
                more: false,
            });
        }
        if page.from != self.cursor || end > page.length {
            return Err(DeviceError::Decode);
        }
        let mut since = self.root.since;
        let mut leaves = BTreeMap::new();
        for change in &page.changes {
            let ordered = change.leaves.windows(2).all(|pair| pair[0].0 < pair[1].0);
            if change.root.since < since || !ordered || change.leaves.is_empty() {
                return Err(DeviceError::Witness);
            }
            since = change.root.since;
            for (slot, leaf) in &change.leaves {
                leaves.insert(*slot, credentials::words(leaf).ok_or(DeviceError::Witness)?);
            }
        }
        if let Some(last) = page.changes.last() {
            let leaves: Vec<_> = leaves.into_iter().collect();
            let (slot, root) = (self.slot, self.root);
            let mut undo = Vec::new();
            self.set_leaves(&leaves, &mut undo);
            if self.top() != last.root.root {
                self.undo(undo, slot, root);
                return Err(DeviceError::Witness);
            }
            self.root = last.root;
        }
        self.cursor = end;
        Ok(Synced {
            applied: page.changes.len() as u64,
            more: end < page.length,
        })
    }

    /// The member's path at the newest root the keeper holds, computed
    /// here; `None` while its leaf is not in the tree.
    pub fn witness(&self) -> Option<AuthWitness> {
        let slot = self.slot?;
        Some(AuthWitness {
            root: Digest::from_bytes(&self.root.root)?,
            slot,
            siblings: core::array::from_fn(|level| Digest(self.node(level, (slot >> level) ^ 1))),
        })
    }

    /// A `RootUnknown` or `RootStale` answer to a proof against the held
    /// root: the feed is due at once, and the period halved, to at least
    /// [`TreeKeeper::MIN_PERIOD_MS`].
    pub fn unknown(&mut self) {
        self.next = 0;
        self.period = (self.period / 2).max(Self::MIN_PERIOD_MS);
    }

    /// The root the last change left, and the batch time it became the
    /// root.
    pub fn root(&self) -> RootEntry {
        self.root
    }

    /// The changes applied: the feed's place.
    pub fn cursor(&self) -> u64 {
        self.cursor
    }

    /// The member's slot, while its leaf is in the tree.
    pub fn slot(&self) -> Option<u32> {
        self.slot
    }

    /// The timer's period now, before its jitter.
    pub fn period(&self) -> u64 {
        self.period
    }

    /// The member this keeper keeps the tree for.
    pub fn member(&self) -> &Digest {
        &self.member
    }

    fn node(&self, level: usize, index: u32) -> Words {
        self.nodes
            .get(&(level as u8, index))
            .copied()
            .unwrap_or(EMPTY[level])
    }

    fn top(&self) -> [u8; 32] {
        credentials::digest(&self.node(DEPTH, 0))
    }

    /// Set `leaves` (in slot order) and every node above them, once each,
    /// as the actor's write does; each node's previous value pushed to
    /// `undo`. The member's slot follows its leaf.
    fn set_leaves(&mut self, leaves: &[(u32, Words)], undo: &mut Vec<((u8, u32), Option<Words>)>) {
        for &(slot, leaf) in leaves {
            if leaf == self.leaf {
                self.slot = Some(slot);
            } else if self.slot == Some(slot) {
                self.slot = None;
            }
        }
        let mut changed: Vec<(u32, Words)> = leaves.to_vec();
        for (level, empty) in EMPTY.iter().enumerate() {
            for &(index, node) in &changed {
                let key = (level as u8, index);
                let previous = if node == *empty {
                    self.nodes.remove(&key)
                } else {
                    self.nodes.insert(key, node)
                };
                undo.push((key, previous));
            }
            if level == DEPTH {
                break;
            }
            let mut parents: Vec<(u32, Words)> = Vec::with_capacity(changed.len());
            for &(index, _) in &changed {
                if parents
                    .last()
                    .is_some_and(|(parent, _)| *parent == index >> 1)
                {
                    continue;
                }
                let (left, right) = (self.node(level, index & !1), self.node(level, index | 1));
                parents.push((index >> 1, credentials::compress(&left, &right)));
            }
            changed = parents;
        }
    }

    /// The nodes `undo` names back as they were, newest first, and the
    /// slot and root.
    fn undo(&mut self, undo: Vec<((u8, u32), Option<Words>)>, slot: Option<u32>, root: RootEntry) {
        for (key, previous) in undo.into_iter().rev() {
            match previous {
                Some(node) => self.nodes.insert(key, node),
                None => self.nodes.remove(&key),
            };
        }
        self.slot = slot;
        self.root = root;
    }
}
