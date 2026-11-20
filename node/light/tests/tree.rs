//! The credential tree kept from its feed: the member's path computed on
//! the device equals the path a tree rebuilt from its leaves gives, and
//! proves its member; each page checked against the root its last change
//! names and its changes' order, a page that fails refused whole and the
//! tree kept as it was; a replica behind the keeper giving nothing new;
//! the tree kept and restored; the feed's timer; a query naming the root
//! held, never a place an answer wrote; and a keeper off the real feed
//! starting over.

mod common;

use scale::{Decode, Encode};
use vos_abi::credentials::{self, EMPTY, P, Words, leaf};
use vos_abi::ids::{AgentId, MethodId};
use vos_abi::result::Outcome;
use vos_light::{DeviceError, Digest, Synced, TreeKeeper, derive_secret, member, wire};
use vos_wire::credentials::Feed;
use vos_wire::ingress::QueryCall;
use vos_wire::ingress::Response;

use common::tree::{Writes, serve_feed};

/// The credential actor's answer over `writes` to `request`, a query of
/// `feed(from)` or of `feed_after(root)`: a page of at most four changes.
fn serve(writes: &Writes, request: &[u8]) -> Vec<u8> {
    let (_, query) = <(AgentId, QueryCall)>::decode_exact(&request[2..]).unwrap();
    let body = serve_feed(&writes.changes, &query, 4).expect("a query of the feed");
    Response::Ran {
        outcome: Outcome::Done(body),
        at: 1,
    }
    .encode()
}

/// `keeper`'s next query, as the gateway reads it: its method and
/// arguments (the key that signs it is drawn for it alone).
fn query_of(keeper: &TreeKeeper) -> (MethodId, Vec<u8>) {
    let request = keeper.request(4, &[0x1d; 32], 2, 900).unwrap();
    let (_, query) = <(AgentId, QueryCall)>::decode_exact(&request[2..]).unwrap();
    (query.method, query.arguments)
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

/// The answer to a `feed_after` query that found its root.
fn answer_after(page: &Feed) -> Vec<u8> {
    Response::Ran {
        outcome: Outcome::Done(Some(page.clone()).encode()),
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
    let mut writes = Writes::default();
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
        let page = writes.page(at, to);
        let answered = if at == 0 {
            answer(&page)
        } else {
            answer_after(&page)
        };
        let read = keeper.ingest(&answered, 100).unwrap();
        assert_eq!(
            read,
            Synced {
                applied: (to - at) as u64,
                more: to < writes.changes.len(),
                reset: false,
            }
        );
        at = to;
        assert_eq!(keeper.cursor(), to as u64);
        assert_eq!(keeper.root(), writes.changes[to - 1].root);
        assert_eq!(keeper.due(100), read.more);
    }
    let witness = keeper.witness().expect("the member's leaf is in the tree");
    assert_eq!(witness.slot, 17);
    assert_eq!(witness.root.to_bytes(), writes.tree.root().to_bytes());
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
    assert_eq!(keeper.root().root, more.tree.root().to_bytes());
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
            more: false,
            reset: false,
        })
    );
    assert_eq!(keeper.slot(), held);

    keeper.apply(&rest).unwrap();
    assert_eq!(keeper.root().root, writes.tree.root().to_bytes());
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
    keeper
        .ingest(&answer_after(&writes.page(2, end)), 1_000)
        .unwrap();
    assert!(!keeper.due(1_000 + period / 2 - 1));
    assert!(keeper.due(1_000 + period * 3 / 2));

    keeper.unknown(1_000);
    assert!(keeper.due(1_000 + TreeKeeper::UNKNOWN_SPREAD_MS));
    assert_eq!(keeper.period(), period / 2);
    for _ in 0..10 {
        keeper.unknown(1_000);
    }
    assert_eq!(keeper.period(), TreeKeeper::MIN_PERIOD_MS);
    assert_eq!(
        query_of(&keeper),
        (vos_wire::credentials::method::FEED, 0u64.encode()),
        "refused proof after proof with no change read between: read from the start"
    );
    keeper.ingest(&answer(&writes.page(0, end)), 2_000).unwrap();
    let quiet = writes.page(end, end);
    keeper.ingest(&answer_after(&quiet), 2_000).unwrap();
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
    let mut sparse = Writes::default();
    sparse.write(1, &[(0, leaf(&other(1)))]);
    sparse.write(1, &[(1 << 30, leaf(&other(2)))]);
    assert_eq!(keeper.apply(&sparse.page(0, 2)), Err(DeviceError::Witness));
    let mut revoked = Writes::default();
    revoked.write(1, &[(0, EMPTY[0])]);
    assert_eq!(keeper.apply(&revoked.page(0, 1)), Err(DeviceError::Witness));
    let mut many = Writes::default();
    let leaves: Vec<_> = (0..257).map(|slot| (slot, leaf(&other(slot)))).collect();
    many.write(1, &leaves);
    assert_eq!(keeper.apply(&many.page(0, 1)), Err(DeviceError::Witness));
    let mut long = Writes::default();
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

/// T1: a gateway pads its answers with changes that undo each other, so
/// the place the device reads on from would be its own, in every query on
/// every circuit after. The keeper holds the root every member holds, and
/// its next query is the one every keeper that read as far makes: it
/// names the root, not the place.
#[test]
fn a_padded_feed_leaves_no_mark_in_the_next_query() {
    let mine = secret_member();
    let writes = writes(&mine);
    let end = writes.changes.len();
    let mut honest = TreeKeeper::new(mine);
    honest.apply(&writes.page(0, end)).unwrap();

    let mut padded = writes.page(0, end - 1);
    let mut tree = Writes {
        changes: padded.changes.clone(),
        ..Writes::default()
    };
    for change in &padded.changes {
        for (slot, leaf) in &change.leaves {
            let leaf = credentials::words(leaf).unwrap();
            if leaf == EMPTY[0] {
                tree.tree.leaves.remove(slot);
            } else {
                tree.tree.leaves.insert(*slot, leaf);
            }
        }
    }
    let held = tree.tree.leaves[&0];
    for _ in 0..3 {
        tree.write(5, &[(0, leaf(&other(77)))]);
        tree.write(5, &[(0, held)]);
    }
    tree.changes.push(writes.changes[end - 1].clone());
    padded.changes = tree.changes[end - 1..].to_vec();
    padded.from = end as u64 - 1;
    padded.length = tree.changes.len() as u64;
    let mut marked = TreeKeeper::new(mine);
    marked.apply(&writes.page(0, end - 1)).unwrap();
    marked.apply(&padded).unwrap();
    assert_eq!(
        marked.cursor(),
        end as u64 + 6,
        "the place its answers wrote"
    );
    assert_eq!(marked.root(), honest.root());
    assert_eq!(query_of(&marked), query_of(&honest));

    let read = marked.ingest(
        &serve(&writes, &marked.request(4, &[0x1d; 32], 2, 900).unwrap()),
        0,
    );
    assert_eq!(read.unwrap().applied, 0);
    assert_eq!(marked.witness(), honest.witness());
}

/// T2: a keeper off the real feed finds its way back. One whose root the
/// actor knows no change leaving (a fork it was served, or a re-founded
/// space whose feed starts again, shorter or longer than its place) drops
/// its tree after two such reads and reads the feed from its start: its
/// member's path is the real tree's.
#[test]
fn a_keeper_off_the_feed_starts_over() {
    let mine = secret_member();
    let ours = writes(&mine);
    let mut shorter = Writes::default();
    shorter.write(1, &[(0, leaf(&other(50)))]);
    shorter.write(1, &[(1, leaf(&mine.0))]);
    shorter.write(2, &[(2, leaf(&other(51)))]);
    let mut longer = Writes::default();
    for slot in 0..19 {
        longer.write(1 + u64::from(slot), &[(slot, leaf(&other(60 + slot)))]);
    }
    longer.write(30, &[(19, leaf(&mine.0))]);
    assert_eq!((shorter.changes.len(), longer.changes.len()), (3, 20));
    for real in [shorter, longer] {
        let mut keeper = TreeKeeper::new(mine);
        keeper.apply(&ours.page(0, ours.changes.len())).unwrap();
        assert_eq!(keeper.cursor(), 10);
        let mut reset = false;
        for _ in 0..12 {
            let request = keeper.request(4, &[0x1d; 32], 2, 900).unwrap();
            if let Ok(read) = keeper.ingest(&serve(&real, &request), 0) {
                reset |= read.reset;
            }
        }
        assert!(reset);
        assert_eq!(keeper.root().root, real.tree.root().to_bytes());
        assert!(
            keeper
                .witness()
                .expect("the real tree's path")
                .proves(&mine)
        );
    }
}

/// T1: a gateway that ends its answers early, at a root the ring still
/// holds, marks the device's proofs for the root's grace alone. Past
/// `ROOT_GRACE_MS` after the change it held back, the root is `Stale`;
/// the refusal makes the feed due within the spread, and that one read on
/// the real feed gives the path at the newest root, which the ring accepts,
/// so the proof is made again with no other step. An honest keeper's
/// reads are less than one and a half periods apart, half the grace, so
/// its root stays good between its reads with as long again to prove.
#[test]
fn a_feed_held_back_meets_the_grace_and_one_read_proves_again() {
    use vos_wire::credentials::{Ring, RootRefusal};
    use vos_wire::defaults::ROOT_GRACE_MS;
    let longest = TreeKeeper::PERIOD_MS * 3 / 2;
    assert_eq!(ROOT_GRACE_MS, 2 * longest);
    let mine = secret_member();
    let quiet = writes(&mine);
    let end = quiet.changes.len();
    let mut honest = TreeKeeper::new(mine);
    honest.ingest(&answer(&quiet.page(0, end)), 0).unwrap();
    for read in 1..200u64 {
        let now = read * longest;
        assert!(honest.due(now), "read {read} later than the longest gap");
        let request = honest.request(4, &[0x1d; 32], 2, 900).unwrap();
        assert_eq!(
            honest
                .ingest(&serve(&quiet, &request), now)
                .unwrap()
                .applied,
            0
        );
    }

    let mine = secret_member();
    let mut writes = writes(&mine);
    let held = writes.changes.len();
    let superseded = 1_000_000;
    writes.write(superseded, &[(41, leaf(&other(41)))]);
    let mut ring = Ring::installed(0);
    for change in &writes.changes {
        ring.record(change.root.root, change.root.since);
    }

    // The gateway's answers end before the last change, the feed's
    // length its word.
    let mut cut = writes.page(0, held);
    cut.length = held as u64;
    let mut keeper = TreeKeeper::new(mine);
    keeper.ingest(&answer(&cut), superseded).unwrap();
    let old = keeper.witness().expect("a path at the root it was left at");
    assert_ne!(old.root.to_bytes(), writes.tree.root().to_bytes());
    assert_eq!(
        ring.accepts(&old.root.to_bytes(), superseded + ROOT_GRACE_MS),
        Ok(())
    );
    let now = superseded + ROOT_GRACE_MS + 1;
    assert_eq!(
        ring.accepts(&old.root.to_bytes(), now),
        Err(RootRefusal::Stale)
    );

    // The proof's `RootStale`: the feed due within the spread, then read.
    keeper.unknown(now);
    assert!(keeper.due(now + TreeKeeper::UNKNOWN_SPREAD_MS));
    let request = keeper.request(4, &[0x1d; 32], 2, 900).unwrap();
    let read = keeper
        .ingest(
            &serve(&writes, &request),
            now + TreeKeeper::UNKNOWN_SPREAD_MS,
        )
        .unwrap();
    assert_eq!(read.applied, 1);
    let fresh = keeper.witness().expect("the newest root's path");
    assert_eq!(fresh.root.to_bytes(), writes.tree.root().to_bytes());
    assert!(fresh.proves(&mine));
    assert_eq!(ring.accepts(&fresh.root.to_bytes(), u64::MAX), Ok(()));
}
