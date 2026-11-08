//! The credential tree kept from its feed: the member's path computed on
//! the device equals the path a tree rebuilt from its leaves gives, and
//! proves its member; each page checked against the root its last change
//! names and its changes' order, a page that fails refused whole and the tree kept as it was; a replica
//! behind the keeper giving nothing new; the tree kept and restored; and
//! the feed's timer.

use std::collections::BTreeMap;

use scale::Encode;
use vos_light::{DeviceError, Digest, Synced, TreeKeeper, derive_secret, member, wire};
use vos_wire::credentials::{
    self, Change, DEPTH, EMPTY, Feed, P, RootEntry, Words, compress, leaf,
};
use vos_wire::ingress::Response;
use vos_wire::result::Outcome;

/// A sparse tree rebuilt from its leaves at every read: the reference.
#[derive(Clone, Default)]
struct Tree {
    leaves: BTreeMap<u32, Words>,
}

impl Tree {
    fn node(&self, level: usize, index: u64) -> Words {
        let first = index << level;
        let last = (first + (1u64 << level) - 1).min(u64::from(u32::MAX));
        if self
            .leaves
            .range(first as u32..=last as u32)
            .next()
            .is_none()
        {
            return EMPTY[level];
        }
        if level == 0 {
            return self.leaves[&(index as u32)];
        }
        compress(
            &self.node(level - 1, 2 * index),
            &self.node(level - 1, 2 * index + 1),
        )
    }

    fn root(&self) -> [u8; 32] {
        credentials::digest(&self.node(DEPTH, 0))
    }

    fn siblings(&self, slot: u32) -> [Digest; DEPTH] {
        core::array::from_fn(|level| Digest(self.node(level, u64::from(slot >> level ^ 1))))
    }
}

/// The feed of a sequence of writes, and the reference after each.
struct Writes {
    tree: Tree,
    changes: Vec<Change>,
}

impl Writes {
    fn new() -> Self {
        Self {
            tree: Tree::default(),
            changes: Vec::new(),
        }
    }

    /// A write at `time` setting `leaves` (an empty leaf revokes).
    fn write(&mut self, time: u64, leaves: &[(u32, Words)]) {
        let mut set: Vec<(u32, [u8; 32])> = Vec::new();
        for &(slot, leaf) in leaves {
            if leaf == EMPTY[0] {
                self.tree.leaves.remove(&slot);
            } else {
                self.tree.leaves.insert(slot, leaf);
            }
            set.push((slot, credentials::digest(&leaf)));
        }
        set.sort_unstable_by_key(|(slot, _)| *slot);
        self.changes.push(Change {
            leaves: set,
            root: RootEntry {
                root: self.tree.root(),
                since: time,
            },
        });
    }

    /// The page of the changes `from..to`.
    fn page(&self, from: usize, to: usize) -> Feed {
        Feed {
            from: from as u64,
            changes: self.changes[from..to].to_vec(),
            length: self.changes.len() as u64,
        }
    }
}

/// A member digest by a seed.
fn other(seed: u32) -> Words {
    core::array::from_fn(|i| (seed.wrapping_mul(0x9e37_79b9) >> i) % P)
}

/// The feed's answer to a query of it, as a node sends it.
fn answer(page: &Feed) -> Vec<u8> {
    Response::Ran {
        outcome: Outcome::Done(page.encode()),
        at: 1,
    }
    .encode()
}

fn secret_member() -> Digest {
    member(&derive_secret(&[3; 32], &[0x42; 32]))
}

/// The writes of a space: enrollments one by one and many at once, the
/// member among them, revocations and a freed slot taken again.
fn writes(mine: &Digest) -> Writes {
    let mut writes = Writes::new();
    for slot in 0..5 {
        writes.write(1, &[(slot, leaf(&other(slot)))]);
    }
    let many: Vec<_> = (5..40).map(|slot| (slot, leaf(&other(slot)))).collect();
    writes.write(2, &many);
    writes.write(3, &[(17, EMPTY[0])]);
    writes.write(3, &[(17, leaf(&mine.0))]);
    writes.write(4, &[(3, EMPTY[0])]);
    writes.write(5, &[(40, leaf(&other(40)))]);
    writes
}

/// Synced page by page, the keeper's tree is the reference's after every
/// change; the member's path, computed here, is the reference's and
/// proves the member at the newest root; a revoked slot taken by another
/// drops the member's path.
#[test]
fn the_tree_kept_from_the_feed_gives_the_members_path() {
    let mine = secret_member();
    let writes = writes(&mine);
    let mut keeper = TreeKeeper::new(mine);
    assert_eq!(keeper.witness(), None);
    assert!(keeper.due(0));
    let mut at = 0;
    for to in [3, 5, 6, 8, writes.changes.len()] {
        let read = keeper.ingest(&answer(&writes.page(at, to)), 100).unwrap();
        assert_eq!(
            read,
            Synced {
                applied: (to - at) as u64,
                more: to < writes.changes.len(),
            }
        );
        at = to;
        assert_eq!(keeper.cursor(), to as u64);
        assert_eq!(keeper.root(), writes.changes[to - 1].root);
        assert_eq!(keeper.due(100), read.more);
    }
    let witness = keeper.witness().expect("the member's leaf is in the tree");
    assert_eq!(witness.slot, 17);
    assert_eq!(witness.root.to_bytes(), writes.tree.root());
    assert_eq!(witness.siblings, writes.tree.siblings(17));
    assert!(witness.proves(&mine));

    // The member's slot revoked and taken by another.
    let mut more = writes;
    more.write(6, &[(17, EMPTY[0])]);
    more.write(6, &[(17, leaf(&other(99)))]);
    let end = more.changes.len();
    keeper.apply(&more.page(at, end)).unwrap();
    assert_eq!(keeper.slot(), None);
    assert_eq!(keeper.witness(), None);
    assert_eq!(keeper.root().root, more.tree.root());
}

/// A change leaving another root than it names, a leaf that is no digest,
/// leaves out of slot order or none, or a root older than the last: the
/// page refused whole, and the tree, the place, the root and the path as
/// they were. A page not from the keeper's place, or past the feed's
/// length, refused. A replica behind the keeper: nothing new, no error.
#[test]
fn a_page_that_does_not_check_is_refused_whole() {
    let mine = secret_member();
    let writes = writes(&mine);
    let half = 8;
    let mut keeper = TreeKeeper::new(mine);
    keeper.apply(&writes.page(0, half)).unwrap();
    // No path until the feed's end is read: the page may end inside a batch.
    assert_eq!(keeper.witness(), None);
    let held = keeper.slot();
    let rest = writes.page(half, writes.changes.len());

    let forged: [fn(&mut Feed); 5] = [
        |page| page.changes[1].root.root = [1; 32],
        |page| page.changes[0].leaves[0].1 = [0xff; 32],
        |page| page.changes[0].leaves.clear(),
        |page| page.changes[0].root.since = 0,
        |page| {
            let leaves = &mut page.changes[0].leaves;
            leaves.push(leaves[0]);
        },
    ];
    for forge in forged {
        let mut page = rest.clone();
        forge(&mut page);
        assert_eq!(keeper.apply(&page), Err(DeviceError::Witness));
        assert_eq!(keeper.cursor(), half as u64);
        assert_eq!(keeper.root(), writes.changes[half - 1].root);
        assert_eq!(keeper.slot(), held);
    }
    let mut early = writes.page(half - 1, writes.changes.len());
    assert_eq!(keeper.apply(&early), Err(DeviceError::Decode));
    early.from = half as u64;
    early.changes.remove(0);
    early.changes.push(early.changes[0].clone());
    early.length = half as u64 + 1;
    assert_eq!(keeper.apply(&early), Err(DeviceError::Decode));
    let behind = Feed {
        from: half as u64,
        changes: Vec::new(),
        length: 4,
    };
    assert_eq!(
        keeper.apply(&behind),
        Ok(Synced {
            applied: 0,
            more: false
        })
    );
    assert_eq!(keeper.slot(), held);

    keeper.apply(&rest).unwrap();
    assert_eq!(keeper.root().root, writes.tree.root());
    assert!(keeper.witness().unwrap().proves(&mine));
    assert_eq!(
        wire::feed_answer(&[0xff]).map(|_| ()),
        Err(DeviceError::Decode)
    );
}

/// What the keeper keeps restores its tree, its place and the member's
/// path; bytes whose root is not their leaves' are refused.
#[test]
fn the_kept_tree_restores() {
    let mine = secret_member();
    let writes = writes(&mine);
    let mut keeper = TreeKeeper::new(mine);
    keeper.apply(&writes.page(0, writes.changes.len())).unwrap();
    let kept = keeper.encode();
    let mut restored = TreeKeeper::restore(mine, &kept).unwrap();
    assert_eq!(restored.cursor(), keeper.cursor());
    assert_eq!(restored.root(), keeper.root());
    assert!(restored.due(0));
    // A path once a read finds the feed's end, nothing new.
    assert_eq!(restored.witness(), None);
    let end = writes.changes.len();
    restored.apply(&writes.page(end, end)).unwrap();
    assert_eq!(restored.witness(), keeper.witness());
    assert!(keeper.witness().is_some());

    let mut forged = kept.clone();
    // The root's first byte, after the place's eight.
    forged[8] ^= 1;
    assert!(TreeKeeper::restore(mine, &forged).is_err());
    assert!(TreeKeeper::restore(mine, &kept[..kept.len() - 1]).is_err());
}

/// The feed's timer: due at once while a page says more; else between half
/// and one and a half periods on; `unknown` makes it due at once and
/// halves the period, to at least the least; a read that finds nothing new
/// doubles it back.
#[test]
fn the_feed_is_read_on_its_own_timer() {
    let mine = secret_member();
    let writes = writes(&mine);
    let period = TreeKeeper::PERIOD_MS;
    let mut keeper = TreeKeeper::new(mine);
    keeper.ingest(&answer(&writes.page(0, 2)), 1_000).unwrap();
    assert!(keeper.due(1_000));
    let end = writes.changes.len();
    keeper.ingest(&answer(&writes.page(2, end)), 1_000).unwrap();
    assert!(!keeper.due(1_000 + period / 2 - 1));
    assert!(keeper.due(1_000 + period * 3 / 2));

    keeper.unknown(1_000);
    assert!(keeper.due(1_000 + vos_light::PathKeeper::MOVED_SPREAD_MS));
    assert_eq!(keeper.period(), period / 2);
    for _ in 0..10 {
        keeper.unknown(1_000);
    }
    assert_eq!(keeper.period(), TreeKeeper::MIN_PERIOD_MS);
    let quiet = writes.page(end, end);
    keeper.ingest(&answer(&quiet), 2_000).unwrap();
    assert_eq!(keeper.period(), 2 * TreeKeeper::MIN_PERIOD_MS);
    assert!(!keeper.due(2_000 + TreeKeeper::MIN_PERIOD_MS - 1));
}

/// What a gateway can make the device hold is bounded: a slot past the
/// lowest never used, a change past `ENROLL_MANY` leaves, or a page past
/// `FEED_BYTES`, is refused, the tree as it was.
#[test]
fn a_page_past_the_feeds_bounds_is_refused() {
    let mine = secret_member();
    let mut keeper = TreeKeeper::new(mine);
    let mut sparse = Writes::new();
    sparse.write(1, &[(0, leaf(&other(1)))]);
    sparse.write(1, &[(1 << 30, leaf(&other(2)))]);
    assert_eq!(keeper.apply(&sparse.page(0, 2)), Err(DeviceError::Witness));
    let mut revoked = Writes::new();
    revoked.write(1, &[(0, EMPTY[0])]);
    assert_eq!(keeper.apply(&revoked.page(0, 1)), Err(DeviceError::Witness));
    let mut many = Writes::new();
    let leaves: Vec<_> = (0..257).map(|slot| (slot, leaf(&other(slot)))).collect();
    many.write(1, &leaves);
    assert_eq!(keeper.apply(&many.page(0, 1)), Err(DeviceError::Witness));
    let mut long = Writes::new();
    for slot in 0..700 {
        long.write(1, &[(slot, leaf(&other(slot)))]);
    }
    assert_eq!(keeper.apply(&long.page(0, 700)), Err(DeviceError::Witness));
    assert_eq!((keeper.cursor(), keeper.slot()), (0, None));
    keeper.apply(&long.page(0, 600)).unwrap();
    assert_eq!(keeper.root(), long.changes[599].root);
}

/// The member revoked at one slot and enrolled again at another within one
/// page: its path at the new slot.
#[test]
fn a_member_moved_within_one_page_keeps_its_path() {
    let mine = secret_member();
    let mut writes = writes(&mine);
    let at = writes.changes.len();
    writes.write(7, &[(17, EMPTY[0])]);
    writes.write(7, &[(41, leaf(&mine.0))]);
    writes.write(7, &[(17, leaf(&other(77)))]);
    let mut keeper = TreeKeeper::new(mine);
    keeper.apply(&writes.page(0, at)).unwrap();
    assert_eq!(keeper.slot(), Some(17));
    keeper
        .apply(&writes.page(at, writes.changes.len()))
        .unwrap();
    let witness = keeper.witness().unwrap();
    assert_eq!(witness.slot, 41);
    assert_eq!(witness.siblings, writes.tree.siblings(41));
    assert!(witness.proves(&mine));
}
