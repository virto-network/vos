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
//! overruns the feed's length, is refused whole and the tree kept as it
//! was. What a gateway can make the
//! device hold is bounded: a page at most [`FEED_BYTES`] (or one change of
//! at most [`ENROLL_MANY`] leaves), and no slot past the lowest never used,
//! as the actor places members, so about two nodes a leaf. The answer is
//! still the gateway's word, as any answer it relays: a withheld change
//! shows as `RootStale` at the next proof, which [`TreeKeeper::unknown`]
//! answers. Until a read reaches the feed's end no path is given, since a
//! page may end between two writes of one batch, whose first root the
//! ring never holds.
//!
//! **What a query names.** The first read is `feed(0)`, every keeper's
//! first; each read after is `feed_after(root)`, the root the keeper
//! holds, which the actor answers from the last change that left it. So a
//! query names no place of the keeper's own: a gateway that padded its
//! answers with changes undoing each other left the device at the root
//! every member holds, where a place it wrote would mark the device in
//! every query after; and a root it forged fails the device's next proof.
//! A keeper off the real feed (its pages refused, or its root one no
//! change left: a fork a gateway served, a re-founded space) two reads in
//! a row drops its tree and reads from the start again; one such read, as
//! from a replica behind, holds nothing new.
//!
//! **When.** The feed is read on a jittered timer of its own,
//! [`TreeKeeper::PERIOD_MS`] (30 s, between 15 s and 45 s), never because a
//! proof is about to be made: the feed's connection is one circuit of the
//! device's for as long as it is open, and a read just before each proof
//! would join the proofs through it. A page that says more follows is due
//! at once. The credential actor's ring holds the last 64 roots, one a
//! tree-changing batch, and accepts a superseded root for `ROOT_GRACE_MS`
//! (90 s, two of the timer's longest gaps) while the ring still holds it:
//! a root held at most one period behind the tree survives, with time left
//! to prove and send, unless the space makes 64 tree-changing batches
//! within one period; a gateway that holds a change back marks the root
//! the device proves against for the grace at most, then the device meets
//! `RootStale` and reads again; a space faster than that
//! meets `RootUnknown`, and [`TreeKeeper::unknown`] makes the feed due
//! within [`TreeKeeper::UNKNOWN_SPREAD_MS`] (10 s), at a time drawn for
//! it, and halves the period (to at least [`TreeKeeper::MIN_PERIOD_MS`]),
//! which doubles back toward the default at each read that finds the tree
//! unchanged.
//!
//! **Kept on the device** ([`TreeKeeper::encode`], [`TreeKeeper::restore`]):
//! the leaves, the feed's place and the root, outside any synced scope
//! (`light-node.md` §3.1), so a restart reads only the changes since. That
//! first read names the root kept, which every member that read as far
//! holds: when few devices read the feed, its age can still link the new
//! circuit to the last.

use std::collections::{BTreeMap, HashMap};

use scale::{Decode, Encode};
use vos_abi::credentials::{self, DEPTH, EMPTY, Words};
use vos_wire::credentials::{ENROLL_MANY, FEED_BYTES, Feed, RootEntry};

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
    /// The lowest slot no change has set: the actor places a member at a
    /// freed slot or at the lowest never used, so no change sets a slot
    /// past it, which bounds the tree to about two nodes a leaf.
    fresh: u64,
    /// The member's slot, while its leaf is in the tree.
    slot: Option<u32>,
    /// Whether the last page read ended the feed: until it does, the root
    /// held may be one the ring never held (a page may end between two
    /// writes of one batch), and no path is given.
    caught_up: bool,
    /// When the timer is next due, by the client's clock in milliseconds.
    next: u64,
    /// The timer's period before its jitter.
    period: u64,
    /// Whether the next read starts at the feed's start: a keeper that has
    /// read nothing, or one that left the real feed and starts over.
    start: bool,
    /// The reads in a row that found the keeper off the feed: a page
    /// refused, or the root it holds one no change left.
    off: u8,
    /// The proofs refused against the root held since the last read that
    /// moved it: a root the ring never held (one a gateway forged, or a
    /// historical one it left the keeper at) is not kept for good.
    unknowns: u8,
}

/// The reads in a row off the feed after which a keeper starts over: one
/// may be a replica behind the keeper's, or a page cut short.
const OFF_FEED: u8 = 2;

/// What a page did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Synced {
    /// The changes it applied.
    pub applied: u64,
    /// Whether the feed holds more: the next page is due at once.
    pub more: bool,
    /// Whether the keeper left the real feed (its pages refused, or its
    /// root one no change left, `OFF_FEED` (two) reads in a row) and starts
    /// over from the feed's start, the tree it held dropped.
    pub reset: bool,
}

impl Synced {
    /// A keeper that starts over: nothing applied, its next read due at
    /// once from the feed's start.
    fn starting_over() -> Self {
        Self {
            applied: 0,
            more: true,
            reset: true,
        }
    }
}

/// What [`TreeKeeper::encode`] keeps.
#[derive(Encode, Decode)]
struct Kept {
    cursor: u64,
    root: RootEntry,
    fresh: u64,
    leaves: Vec<(u32, [u8; 32])>,
}

impl TreeKeeper {
    /// The timer's period, before its jitter of half a period either way:
    /// `FEED_PERIOD_MS`, which the root's grace is two longest gaps of.
    pub const PERIOD_MS: u64 = vos_wire::defaults::FEED_PERIOD_MS;
    /// The least period a run of `RootUnknown` answers halves it to.
    pub const MIN_PERIOD_MS: u64 = 1_000;
    /// The spread of the read a refused root brings forward: drawn
    /// uniformly below it, so the members a tree change leaves behind do
    /// not all read at once.
    pub const UNKNOWN_SPREAD_MS: u64 = 10_000;

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
            fresh: 0,
            slot: None,
            caught_up: false,
            next: 0,
            period: Self::PERIOD_MS,
            start: true,
            off: 0,
            unknowns: 0,
        }
    }

    /// A keeper for `member` from what [`TreeKeeper::encode`] kept: the
    /// tree rebuilt from its leaves, refused ([`DeviceError::Decode`])
    /// unless it decodes, its leaves lie below the lowest slot never used
    /// and its root is the one kept. Due at once, and no path given until
    /// a read finds the feed's end.
    pub fn restore(member: Digest, bytes: &[u8]) -> Result<Self, DeviceError> {
        let kept = Kept::decode_exact(bytes).ok_or(DeviceError::Decode)?;
        let mut keeper = Self::new(member);
        let mut leaves = Vec::with_capacity(kept.leaves.len());
        for (slot, leaf) in &kept.leaves {
            if u64::from(*slot) >= kept.fresh {
                return Err(DeviceError::Decode);
            }
            leaves.push((*slot, credentials::words(leaf).ok_or(DeviceError::Decode)?));
        }
        let mut undo = Vec::new();
        keeper.set_leaves(&leaves, &mut undo);
        if keeper.top() != kept.root.root {
            return Err(DeviceError::Decode);
        }
        keeper.cursor = kept.cursor;
        keeper.root = kept.root;
        keeper.fresh = kept.fresh;
        keeper.start = kept.cursor == 0;
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
            fresh: self.fresh,
            leaves,
        }
        .encode()
    }

    /// The query of the feed's next page at `instance` of `agent`, the
    /// credential actor, signed by a fresh key over the agent's
    /// `identity`: `feed(0)` from the feed's start, else `feed_after` the
    /// root the keeper holds. It names nothing of the member's, and no
    /// place of the keeper's own: a root is every member's that read the
    /// feed as far, and one a gateway forged fails the next proof, where
    /// the place a gateway's answers left (its padding, say) would be this
    /// device's alone in every query after.
    pub fn request(
        &self,
        agent: u32,
        identity: &[u8; 32],
        instance: u32,
        not_after: u64,
    ) -> Result<Vec<u8>, DeviceError> {
        if self.start {
            wire::feed_query(agent, identity, instance, 0, not_after)
        } else {
            wire::feed_after_query(agent, identity, instance, &self.root.root, not_after)
        }
    }

    /// Whether to read the feed now: the jittered timer is due, or a page
    /// said more follows, or a proof met an unknown root.
    pub fn due(&self, now_ms: u64) -> bool {
        now_ms >= self.next
    }

    /// The answer to [`TreeKeeper::request`], read at `now_ms`: its page
    /// applied, and the timer set (due at once while the feed holds more).
    /// A keeper off the real feed `OFF_FEED` (two) reads in a row (its pages
    /// refused, or its root one the actor knows no change leaving: a fork
    /// a gateway served, or a re-founded space) drops its tree and starts
    /// over from the feed's start ([`Synced::reset`]); a single such read,
    /// as from a replica behind, holds nothing new.
    pub fn ingest(&mut self, answer: &[u8], now_ms: u64) -> Result<Synced, DeviceError> {
        let page = if self.start {
            Some(wire::feed_answer(answer)?)
        } else {
            wire::feed_after_answer(answer)?
        };
        let read = match page {
            Some(page) => match self.read(&page, self.start) {
                Ok(read) => read,
                Err(DeviceError::Witness) => {
                    if !self.left() {
                        return Err(DeviceError::Witness);
                    }
                    Synced::starting_over()
                }
                Err(error) => return Err(error),
            },
            None if !self.left() => Synced {
                applied: 0,
                more: false,
                reset: false,
            },
            None => Synced::starting_over(),
        };
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

    /// A read off the real feed: whether it is the `OFF_FEED`th in a
    /// row, the tree then dropped and the next read from the feed's start.
    fn left(&mut self) -> bool {
        self.off = self.off.saturating_add(1);
        if self.off < OFF_FEED {
            return false;
        }
        let (next, period) = (self.next, self.period);
        *self = Self::new(self.member);
        (self.next, self.period) = (next, period);
        true
    }

    /// `page` applied, the tree it leaves checked against the root its last
    /// change names. A page not from the keeper's place, or past the
    /// feed's length, is refused ([`DeviceError::Decode`]); one past
    /// [`FEED_BYTES`] (but for a single change), with a change of no leaves
    /// or more than [`ENROLL_MANY`], out of slot order, older than the
    /// last, setting a slot past the lowest never used, or leaving another
    /// root, is refused whole ([`DeviceError::Witness`]): the tree as it
    /// was. A page from a replica behind the keeper, whose feed is shorter
    /// than the keeper's place, holds nothing new.
    pub fn apply(&mut self, page: &Feed) -> Result<Synced, DeviceError> {
        self.read(page, true)
    }

    /// `page` applied as [`TreeKeeper::apply`] does; from the keeper's
    /// place when `placed`, else from where the actor answered a
    /// `feed_after` (the last change that left the keeper's root).
    fn read(&mut self, page: &Feed, placed: bool) -> Result<Synced, DeviceError> {
        let end = page
            .from
            .checked_add(page.changes.len() as u64)
            .ok_or(DeviceError::Decode)?;
        if placed && page.length < self.cursor && page.changes.is_empty() {
            return Ok(Synced {
                applied: 0,
                more: false,
                reset: false,
            });
        }
        if (placed && page.from != self.cursor) || end > page.length {
            return Err(DeviceError::Decode);
        }
        let bytes: usize = page.changes.iter().map(|change| change.encoded_len()).sum();
        if page.changes.len() > 1 && bytes > FEED_BYTES {
            return Err(DeviceError::Witness);
        }
        let (mut since, mut fresh) = (self.root.since, self.fresh);
        let mut leaves = BTreeMap::new();
        for change in &page.changes {
            let ordered = change.leaves.windows(2).all(|pair| pair[0].0 < pair[1].0);
            let sized = !change.leaves.is_empty() && change.leaves.len() <= ENROLL_MANY;
            if change.root.since < since || !ordered || !sized {
                return Err(DeviceError::Witness);
            }
            since = change.root.since;
            for (slot, leaf) in &change.leaves {
                let slot64 = u64::from(*slot);
                if slot64 > fresh || (slot64 == fresh && *leaf == credentials::digest(&EMPTY[0])) {
                    return Err(DeviceError::Witness);
                }
                fresh = fresh.max(slot64 + 1);
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
        self.fresh = fresh;
        self.caught_up = end >= page.length;
        self.start = false;
        self.off = 0;
        if !page.changes.is_empty() {
            self.unknowns = 0;
        }
        Ok(Synced {
            applied: page.changes.len() as u64,
            more: !self.caught_up,
            reset: false,
        })
    }

    /// The member's path at the newest root the keeper holds, computed
    /// here; `None` while its leaf is not in the tree, or until a read
    /// found the feed's end.
    pub fn witness(&self) -> Option<AuthWitness> {
        if !self.caught_up {
            return None;
        }
        let slot = self.slot?;
        Some(AuthWitness {
            root: Digest::from_bytes(&self.root.root)?,
            slot,
            siblings: core::array::from_fn(|level| Digest(self.node(level, (slot >> level) ^ 1))),
        })
    }

    /// A `RootUnknown` or `RootStale` answer at `now_ms` to a proof
    /// against the held root: the feed due at a time drawn below
    /// [`TreeKeeper::UNKNOWN_SPREAD_MS`], not at once, so the read on the
    /// feed's circuit does not follow the refused proof by a fixed delay;
    /// and the period halved, to at least [`TreeKeeper::MIN_PERIOD_MS`].
    ///
    /// The `OFF_FEED`th (second) such answer in a row with no change read between
    /// drops the tree and reads the feed from its start: the root held is
    /// none the ring holds, though the gateway answers it with pages.
    pub fn unknown(&mut self, now_ms: u64) {
        self.unknowns = self.unknowns.saturating_add(1);
        if self.unknowns >= OFF_FEED {
            let period = self.period;
            *self = Self::new(self.member);
            self.period = period;
        }
        self.next = self
            .next
            .min(now_ms.saturating_add(jitter(Self::UNKNOWN_SPREAD_MS)));
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

    /// Whether the last page read ended the feed: the tree held is the
    /// feed's as it stood then.
    pub fn caught_up(&self) -> bool {
        self.caught_up
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

/// A uniform draw below `period` from the operating system; 0 if it has
/// no randomness to give.
fn jitter(period: u64) -> u64 {
    let mut bytes = [0; 8];
    if period == 0 || getrandom::getrandom(&mut bytes).is_err() {
        return 0;
    }
    u64::from_le_bytes(bytes) % period
}
