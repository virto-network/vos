//! The incremental replica against the full replay, over random DAGs and
//! random deliveries; equivocations, refusals, a cursor, the bounds on
//! parents and held nodes, and failed commits.

mod common;

use std::cell::Cell;
use std::collections::BTreeSet;

use common::{
    H, Ops, Rng, SCOPE, Server, Step, crdt, deliveries, generate, key, read, replay, wide_key,
};
use merkle_crdt::{
    Author, Changes, Cid, Error, Event, Loaded, MAX_HELD, MAX_HELD_PER_AUTHOR, MAX_PARENTS,
    MemStore, Node, Refusal, Replica, Rows, Scope, Store,
};
use proptest::prelude::*;

type Mem = Replica<H, Ops, MemStore<H>>;

fn replica() -> Mem {
    Replica::open(MemStore::new(), SCOPE).unwrap()
}

fn step() -> impl Strategy<Value = Step> {
    prop_oneof![
        6 => (any::<u8>(), prop::collection::vec((0..8u64, any::<u64>()), 0..4), any::<u64>())
            .prop_map(|(author, ops, pick)| Step::Record { author, ops, pick }),
        3 => (any::<u8>(), any::<u8>()).prop_map(|(from, to)| Step::Learn { from, to }),
        1 => (any::<u8>(), any::<u64>()).prop_map(|(author, value)| Step::Equivocate { author, value }),
        1 => any::<u8>().prop_map(|author| Step::BreakChain { author: author % 2 }),
        1 => any::<u64>().prop_map(|value| Step::Forge { value }),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(200))]

    /// Any delivery order, with duplicates and any batching, ends in the
    /// rows, heads and equivocations of the full replay; and two replicas
    /// fed different orders agree.
    #[test]
    fn incremental_apply_equals_full_rebuild(
        authors in 1u8..5,
        steps in prop::collection::vec(step(), 1..60),
        first in any::<u64>(),
        second in any::<u64>(),
    ) {
        let dag = generate(authors, &steps);
        let bytes: Vec<Vec<u8>> = dag.nodes.iter().map(|(_, b)| b.clone()).collect();
        let mut replicas = Vec::new();
        for seed in [first, second] {
            let mut replica = replica();
            let mut refused = BTreeSet::new();
            for batch in deliveries(&bytes, seed) {
                let report = replica.ingest(batch, None, &mut crdt).unwrap();
                refused.extend(report.refused.into_iter().map(|(cid, _)| cid.unwrap()));
            }
            prop_assert_eq!(replica.held(), 0);
            prop_assert_eq!(&refused, &dag.refused);
            let rebuilt = replay(replica.store().nodes().values().cloned(), &mut crdt);
            prop_assert_eq!(replica.store().rows(), &rebuilt.rows);
            prop_assert_eq!(replica.heads(), &rebuilt.heads);
            prop_assert_eq!(replica.equivocations(), &rebuilt.equivocations);
            prop_assert_eq!(replica.equivocations(), &dag.equivocations);
            prop_assert_eq!(&replica.have(), &rebuilt.latest);
            prop_assert!(replica.wanted().is_empty());
            let applied: BTreeSet<&Cid<H>> = dag.nodes.iter().map(|(c, _)| c).collect();
            prop_assert_eq!(rebuilt.nodes, applied.len() - dag.refused.len());
            replicas.push(replica);
        }
        prop_assert_eq!(replicas[0].store().rows(), replicas[1].store().rows());
        prop_assert_eq!(replicas[0].heads(), replicas[1].heads());
    }

    /// A replica that records its own operations between ingests ends
    /// where the replay of its store does.
    #[test]
    fn local_records_between_ingests_equal_full_rebuild(
        steps in prop::collection::vec(step(), 1..40),
        locals in prop::collection::vec((0..8u64, any::<u64>()), 1..20),
        seed in any::<u64>(),
    ) {
        let dag = generate(3, &steps);
        let bytes: Vec<Vec<u8>> = dag.nodes.iter().map(|(_, b)| b.clone()).collect();
        let mut replica = replica();
        let own = key(50);
        let mut locals = locals.into_iter();
        for batch in deliveries(&bytes, seed) {
            replica.ingest(batch, None, &mut crdt).unwrap();
            if let Some(op) = locals.next() {
                replica.record(&own, vec![op], &mut crdt).unwrap();
            }
        }
        for op in locals {
            replica.record(&own, vec![op], &mut crdt).unwrap();
        }
        replica.record(&own, vec![(0, 0)], &mut crdt).unwrap();
        let rebuilt = replay(replica.store().nodes().values().cloned(), &mut crdt);
        prop_assert_eq!(replica.store().rows(), &rebuilt.rows);
        prop_assert_eq!(replica.heads(), &rebuilt.heads);
        prop_assert_eq!(replica.heads().len(), 1);
    }
}

#[test]
fn equivocation_is_detected_kept_and_reported_once() {
    let author = key(0);
    let first = Node::<H, Ops>::sign(&author, &SCOPE, 0, vec![(1, 1)], BTreeSet::new());
    let twin = Node::<H, Ops>::sign(&author, &SCOPE, 0, vec![(1, 2)], BTreeSet::new());
    let third = Node::<H, Ops>::sign(&author, &SCOPE, 0, vec![(1, 3)], BTreeSet::new());
    let mut replica = replica();
    let report = replica.ingest([first.to_bytes()], None, &mut crdt).unwrap();
    assert!(report.equivocations.is_empty());
    let report = replica
        .ingest([twin.to_bytes(), third.to_bytes()], None, &mut crdt)
        .unwrap();
    assert_eq!(report.applied.len(), 2, "both twins are kept");
    assert_eq!(report.equivocations.len(), 1, "one report a pair");
    let found = &report.equivocations[0];
    assert_eq!((found.author, found.seq), (Author::from(&author), 0));
    assert_eq!(found.nodes[0], first.cid());
    assert_eq!(replica.heads().len(), 3);
    assert!(
        replica
            .equivocations()
            .contains(&(Author::from(&author), 0))
    );

    // A node after one twin is still applied: other authors may cite either.
    let other = Node::<H, Ops>::sign(&key(1), &SCOPE, 0, vec![], BTreeSet::from([twin.cid()]));
    let report = replica.ingest([other.to_bytes()], None, &mut crdt).unwrap();
    assert_eq!(report.applied, vec![other.cid()]);
}

/// The apply of a node is told it equivocates: the first node at a number
/// is not, every later one is, whichever batch brings it.
#[test]
fn an_equivocating_node_is_marked_at_its_apply() {
    let author = key(0);
    let first = Node::<H, Ops>::sign(&author, &SCOPE, 0, vec![(1, 1)], BTreeSet::new());
    let twin = Node::<H, Ops>::sign(&author, &SCOPE, 0, vec![(1, 2)], BTreeSet::new());
    let next = Node::<H, Ops>::sign(&author, &SCOPE, 1, vec![], BTreeSet::from([twin.cid()]));
    let mut marked = Vec::new();
    let mut mark = |event: merkle_crdt::Event<'_, H, Ops>, _: &mut dyn merkle_crdt::Rows| {
        marked.push((event.cid.clone(), event.equivocation));
    };
    let mut replica = replica();
    replica.ingest([first.to_bytes()], None, &mut mark).unwrap();
    replica
        .ingest([next.to_bytes(), twin.to_bytes()], None, &mut mark)
        .unwrap();
    assert_eq!(
        marked,
        [
            (first.cid(), false),
            (twin.cid(), true),
            (next.cid(), false)
        ]
    );
}

#[test]
fn signatures_are_refused_unless_the_authors() {
    let author = key(0);
    let node = Node::<H, Ops>::sign(&author, &SCOPE, 0, vec![(1, 1)], BTreeSet::new());

    // Operations changed after signing.
    let mut tampered = node.clone();
    tampered.payload.ops = vec![(1, 2)];
    // Another author's key over the same signature.
    let mut stolen = node.clone();
    stolen.payload.author = Author::from(&key(1));
    // Parents changed after signing.
    let mut moved = node.clone();
    moved.parents.insert(Cid([7; 32]));
    // The signature's scalar plus the group order: verifies loosely, not
    // strictly, and would frame the author as equivocating.
    let mut malleated = node.clone();
    let order: [u8; 32] = [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde,
        0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
    ];
    let mut carry = 0u16;
    for (s, l) in malleated.payload.signature[32..].iter_mut().zip(order) {
        let sum = *s as u16 + l as u16 + carry;
        *s = sum as u8;
        carry = sum >> 8;
    }

    let mut replica = replica();
    for forged in [tampered, stolen, moved, malleated] {
        let report = replica
            .ingest([forged.to_bytes()], None, &mut crdt)
            .unwrap();
        assert_eq!(
            report.refused,
            vec![(Some(forged.cid()), Refusal::BadSignature)]
        );
    }
    // Not the canonical encoding: trailing bytes, or the parents out of
    // order (the signature, over the parents in order, still verifies).
    let mut trailing = node.to_bytes();
    trailing.push(0);
    let parents = BTreeSet::from([Cid([1; 32]), Cid([2; 32])]);
    let two = Node::<H, Ops>::sign(&author, &SCOPE, 0, vec![], parents);
    let mut swapped = two.to_bytes();
    let end = swapped.len();
    let (front, back) = swapped[end - 64..].split_at_mut(32);
    front.swap_with_slice(back);
    for bytes in [trailing, swapped] {
        let report = replica.ingest([bytes], None, &mut crdt).unwrap();
        assert_eq!(report.refused, vec![(None, Refusal::Malformed)]);
    }
    assert!(replica.heads().is_empty());
    assert!(replica.store().rows().is_empty());

    let report = replica.ingest([node.to_bytes()], None, &mut crdt).unwrap();
    assert_eq!(report.applied, vec![node.cid()]);
}

#[test]
fn a_broken_chain_is_refused_with_its_descendants() {
    let author = key(0);
    let first = Node::<H, Ops>::sign(&author, &SCOPE, 0, vec![], BTreeSet::new());
    let gap = Node::<H, Ops>::sign(&author, &SCOPE, 2, vec![], BTreeSet::from([first.cid()]));
    let child = Node::<H, Ops>::sign(&key(1), &SCOPE, 0, vec![], BTreeSet::from([gap.cid()]));
    let mut replica = replica();
    // The child arrives first and is held; the gap's refusal releases it.
    let report = replica.ingest([child.to_bytes()], None, &mut crdt).unwrap();
    assert_eq!(report.held, vec![child.cid()]);
    let report = replica
        .ingest([first.to_bytes(), gap.to_bytes()], None, &mut crdt)
        .unwrap();
    assert_eq!(report.applied, vec![first.cid()]);
    assert_eq!(
        report.refused,
        vec![
            (Some(gap.cid()), Refusal::BrokenChain),
            (Some(child.cid()), Refusal::RefusedParent)
        ]
    );
    assert_eq!(replica.held(), 0);
    // Later arrivals naming a refused node are refused at once.
    let late = Node::<H, Ops>::sign(&key(2), &SCOPE, 0, vec![], BTreeSet::from([gap.cid()]));
    let report = replica.ingest([late.to_bytes()], None, &mut crdt).unwrap();
    assert_eq!(
        report.refused,
        vec![(Some(late.cid()), Refusal::RefusedParent)]
    );
}

#[test]
fn a_cursor_catches_up_out_of_causal_order_and_resumes() {
    let dag = generate(
        3,
        &(0..120u64)
            .map(|i| match i % 4 {
                3 => Step::Learn {
                    from: i as u8,
                    to: (i / 4) as u8,
                },
                _ => Step::Record {
                    author: i as u8,
                    ops: vec![(i % 7, i)],
                    pick: u64::MAX,
                },
            })
            .collect::<Vec<_>>(),
    );
    // Accepted in an order that is not causal.
    let mut accepted: Vec<Vec<u8>> = dag.nodes.iter().map(|(_, b)| b.clone()).collect();
    Rng(7).shuffle(&mut accepted);
    let items: Vec<(u64, Vec<u8>)> = accepted
        .into_iter()
        .enumerate()
        .map(|(i, b)| (10 + 3 * i as u64, b))
        .collect();
    let last = items.last().unwrap().0;
    let mut server = Server {
        items,
        page: 16,
        trips: 0,
    };
    let mut local = replica();
    // Read only the first page, then reopen the replica from its store.
    let (first, _) = server.since(None);
    local
        .ingest(
            first.iter().map(|(_, b)| b.clone()),
            Some(first.last().unwrap().0),
            &mut crdt,
        )
        .unwrap();
    let held = local.held();
    assert!(held > 0, "a page out of causal order holds nodes");
    let mut local = Mem::open(local.into_store(), SCOPE).unwrap();
    assert_eq!(local.held(), held, "held nodes survive reopening");
    read(&mut local, &mut server);
    assert_eq!(local.cursor(), Some(last));
    assert_eq!(local.held(), 0);
    let rebuilt = replay(local.store().nodes().values().cloned(), &mut crdt);
    assert_eq!(local.store().rows(), &rebuilt.rows);
    assert_eq!(local.heads(), &rebuilt.heads);
    assert_eq!(rebuilt.nodes, dag.nodes.len());

    // Nothing new: one round trip, nothing to ingest.
    let trips = server.trips;
    read(&mut local, &mut server);
    assert_eq!(server.trips, trips + 1);
}

/// `count` local nodes, recorded in turn by `authors` authors.
fn history(replica: &mut Mem, authors: u8, count: u64) {
    for i in 0..count {
        replica
            .record(
                &key((i % authors as u64) as u8),
                vec![(i % 5, i)],
                &mut crdt,
            )
            .unwrap();
    }
}

/// A store whose commits fail while `fail` is set.
struct Flaky {
    inner: MemStore<H>,
    fail: bool,
}

impl Store<H> for Flaky {
    type Error = &'static str;
    fn node(&self, cid: &Cid<H>) -> Result<Option<Vec<u8>>, Self::Error> {
        Ok(self.inner.node(cid).unwrap())
    }
    fn contains(&self, cid: &Cid<H>) -> Result<bool, Self::Error> {
        Ok(self.inner.contains(cid).unwrap())
    }
    fn held(&self, cid: &Cid<H>) -> Result<Option<Vec<u8>>, Self::Error> {
        Ok(self.inner.held(cid).unwrap())
    }
    fn authored(&self, author: &Author, seq: u64) -> Result<Option<Cid<H>>, Self::Error> {
        Ok(self.inner.authored(author, seq).unwrap())
    }
    fn is_authored(&self, author: &Author, seq: u64, cid: &Cid<H>) -> Result<bool, Self::Error> {
        Ok(self.inner.is_authored(author, seq, cid).unwrap())
    }
    fn row(&self, key: &[u8]) -> Result<Option<Vec<u8>>, Self::Error> {
        Ok(self.inner.row(key).unwrap())
    }
    fn load(&self) -> Result<Loaded<H>, Self::Error> {
        Ok(self.inner.load().unwrap())
    }
    fn commit(&mut self, changes: Changes<H>) -> Result<(), Self::Error> {
        if self.fail {
            return Err("injected");
        }
        self.inner.commit(changes).unwrap();
        Ok(())
    }
}

#[test]
fn a_failed_commit_moves_nothing_and_a_retry_completes() {
    let mut remote = replica();
    history(&mut remote, 1, 10);
    let bytes: Vec<Vec<u8>> = remote
        .outbox()
        .unwrap()
        .into_iter()
        .map(|node| node.bytes)
        .collect();
    let mut local = Replica::<H, Ops, _>::open(
        Flaky {
            inner: MemStore::new(),
            fail: false,
        },
        SCOPE,
    )
    .unwrap();
    // Hold the last five, then fail the batch that would release them.
    local
        .ingest(bytes[5..].to_vec(), Some(1), &mut crdt)
        .unwrap();
    assert_eq!(local.held(), 5);
    let heads = local.heads().clone();
    let mut inner = local.into_store();
    inner.fail = true;
    let mut failing = Replica::<H, Ops, _>::open(inner, SCOPE).unwrap();
    assert!(matches!(
        failing.ingest(bytes[..5].to_vec(), Some(2), &mut crdt),
        Err(Error::Store("injected"))
    ));
    assert_eq!(failing.heads(), &heads);
    assert_eq!(failing.held(), 5);
    assert_eq!(failing.cursor(), Some(1));
    assert!(failing.store().inner.rows().is_empty());
    assert!(matches!(
        failing.record(&key(9), vec![(1, 1)], &mut crdt),
        Err(Error::Store("injected"))
    ));
    assert!(failing.outbox().unwrap().is_empty());

    let mut inner = failing.into_store();
    inner.fail = false;
    let mut retry = Replica::<H, Ops, _>::open(inner, SCOPE).unwrap();
    let report = retry
        .ingest(bytes[..5].to_vec(), Some(2), &mut crdt)
        .unwrap();
    assert_eq!(report.applied.len(), 10);
    assert_eq!(retry.cursor(), Some(2));
    assert_eq!(retry.store().inner.rows(), remote.store().rows());
}

#[test]
fn the_outbox_holds_local_nodes_until_pushed() {
    let mut local = replica();
    let own = key(3);
    for i in 0..4 {
        local.record(&own, vec![(i, i)], &mut crdt).unwrap();
    }
    let outbox = local.outbox().unwrap();
    assert_eq!(
        outbox.iter().map(|node| node.seq).collect::<Vec<_>>(),
        vec![0, 1, 2, 3]
    );
    local.pushed(&[(Author::from(&own), 1)]).unwrap();
    let local = Mem::open(local.into_store(), SCOPE).unwrap();
    assert_eq!(
        local
            .outbox()
            .unwrap()
            .iter()
            .map(|node| node.seq)
            .collect::<Vec<_>>(),
        vec![2, 3]
    );
    // Each local node names its author's previous one.
    let (_, node) =
        merkle_crdt::validate::<H, Ops>(&SCOPE, &local.outbox().unwrap()[0].bytes).unwrap();
    assert_eq!(node.payload.seq, 2);
    assert!(node.parents.contains(&outbox[1].cid));
}

#[test]
fn a_forged_parent_releases_its_held_children_refused() {
    let honest = Node::<H, Ops>::sign(&key(0), &SCOPE, 0, vec![], BTreeSet::new());
    let mut forged = Node::<H, Ops>::sign(&key(1), &SCOPE, 0, vec![(1, 1)], BTreeSet::new());
    forged.payload.ops = vec![(1, 2)];
    let other = Node::<H, Ops>::sign(&key(2), &SCOPE, 0, vec![], BTreeSet::new());
    // Waits on the forged node and on one that never comes.
    let child = Node::<H, Ops>::sign(
        &key(3),
        &SCOPE,
        0,
        vec![],
        BTreeSet::from([forged.cid(), other.cid()]),
    );
    let mut replica = replica();
    let report = replica
        .ingest([child.to_bytes(), honest.to_bytes()], None, &mut crdt)
        .unwrap();
    assert_eq!(report.held, vec![child.cid()]);
    assert_eq!(replica.wanted().len(), 2);
    let report = replica
        .ingest([forged.to_bytes()], None, &mut crdt)
        .unwrap();
    assert_eq!(
        report.refused,
        vec![
            (Some(forged.cid()), Refusal::BadSignature),
            (Some(child.cid()), Refusal::RefusedParent)
        ]
    );
    assert_eq!(replica.held(), 0);
    assert!(
        replica.wanted().is_empty(),
        "nothing waits on the other parent"
    );
    let replica = Mem::open(replica.into_store(), SCOPE).unwrap();
    assert_eq!(replica.held(), 0);
}

#[test]
fn a_node_signed_for_another_scope_is_refused() {
    let node = Node::<H, Ops>::sign(&key(0), &Scope([8; 16]), 0, vec![(1, 1)], BTreeSet::new());
    let mut replica = replica();
    let report = replica.ingest([node.to_bytes()], None, &mut crdt).unwrap();
    assert_eq!(
        report.refused,
        vec![(Some(node.cid()), Refusal::BadSignature)]
    );
}

/// `count` nodes of `author`, each at sequence number 0 with no parents:
/// as many forks as it likes.
fn forks(author: u8, count: u64) -> Vec<Node<H, Ops>> {
    (0..count)
        .map(|i| Node::<H, Ops>::sign(&key(author), &SCOPE, 0, vec![(0, i)], BTreeSet::new()))
        .collect()
}

/// One author's forks do not decide the size of the next local node: it
/// names its author's previous node and the heads of authors that never
/// equivocated first, [`MAX_PARENTS`] in all. The heads it leaves are
/// still heads, applied alike everywhere, and the next local nodes name
/// them.
#[test]
fn a_local_node_stays_small_whatever_one_author_forks() {
    let forks = forks(77, 2_000);
    let other = Node::<H, Ops>::sign(&key(2), &SCOPE, 0, vec![(2, 2)], BTreeSet::new());
    let mut honest = replica();
    let all = forks.iter().chain([&other]).map(|node| node.to_bytes());
    let report = honest.ingest(all, None, &mut crdt).unwrap();
    assert_eq!(report.applied.len(), 2_001);
    assert_eq!(honest.heads().len(), 2_001);

    honest.record(&key(1), vec![(1, 1)], &mut crdt).unwrap();
    let local = honest.outbox().unwrap().pop().unwrap();
    assert!(local.bytes.len() <= 4_096, "{} bytes", local.bytes.len());
    let (_, node) = merkle_crdt::validate::<H, Ops>(&SCOPE, &local.bytes).unwrap();
    assert_eq!(node.parents.len(), MAX_PARENTS);
    assert!(node.parents.contains(&other.cid()), "an honest head first");
    assert_eq!(honest.heads().len(), 2_001 - MAX_PARENTS + 1);

    // A peer that has the same nodes has the same heads and rows: a head
    // no node names converges like any other.
    let mut peer = replica();
    let all = forks.iter().chain([&other]).map(|node| node.to_bytes());
    peer.ingest(all.chain([local.bytes.clone()]), None, &mut crdt)
        .unwrap();
    assert_eq!(peer.heads(), honest.heads());
    assert_eq!(peer.store().rows(), honest.store().rows());

    // The next local node names the first, a head, and merges more.
    let before = honest.heads().len();
    honest.record(&key(1), vec![(1, 2)], &mut crdt).unwrap();
    assert_eq!(honest.heads().len(), before - MAX_PARENTS + 1);
    let rebuilt = replay(honest.store().nodes().values().cloned(), &mut crdt);
    assert_eq!(honest.heads(), &rebuilt.heads);
    assert_eq!(honest.store().rows(), &rebuilt.rows);
}

#[test]
fn a_node_naming_more_than_max_parents_is_malformed() {
    let parents = |count: usize| -> BTreeSet<Cid<H>> {
        (0..count as u32)
            .map(|i| {
                let mut cid = [0; 32];
                cid[..4].copy_from_slice(&i.to_le_bytes());
                Cid(cid)
            })
            .collect()
    };
    let at_most = Node::<H, Ops>::sign(&key(1), &SCOPE, 0, vec![], parents(MAX_PARENTS));
    assert!(merkle_crdt::validate::<H, Ops>(&SCOPE, &at_most.to_bytes()).is_ok());
    let past = Node::<H, Ops>::sign(&key(1), &SCOPE, 0, vec![], parents(MAX_PARENTS + 1));
    assert_eq!(
        merkle_crdt::validate::<H, Ops>(&SCOPE, &past.to_bytes()).err(),
        Some((None, Refusal::Malformed))
    );
    assert!(merkle_crdt::Header::<H>::read(&past.to_bytes()).is_none());
}

/// A node of `key` at seq 0 naming a parent that does not exist.
fn orphan(key: &ed25519_dalek::SigningKey, index: u32) -> Node<H, Ops> {
    let mut parent = [0; 32];
    parent[..4].copy_from_slice(&index.to_le_bytes());
    Node::<H, Ops>::sign(key, &SCOPE, 0, vec![], BTreeSet::from([Cid(parent)]))
}

/// Nodes whose parents never arrive are held up to a bound, per author and
/// in all; past it they are dropped, not refused, and the caller can drop
/// the held ones too.
#[test]
fn held_nodes_are_bounded_and_can_be_dropped() {
    let mut local = replica();
    let one = key(66);
    let report = local
        .ingest(
            (0..1_000).map(|i| orphan(&one, i).to_bytes()),
            None,
            &mut crdt,
        )
        .unwrap();
    assert_eq!(local.held(), MAX_HELD_PER_AUTHOR);
    assert_eq!(report.held.len(), MAX_HELD_PER_AUTHOR);
    assert_eq!(report.dropped.len(), 1_000 - MAX_HELD_PER_AUTHOR);
    assert!(report.refused.is_empty());

    // Many authors: the bound in all.
    let authors = (MAX_HELD / MAX_HELD_PER_AUTHOR + 2) as u32;
    let many = (0..authors).flat_map(|author| {
        let key = wide_key(author);
        (0..MAX_HELD_PER_AUTHOR as u32).map(move |i| orphan(&key, 10_000 + i).to_bytes())
    });
    let report = local.ingest(many, None, &mut crdt).unwrap();
    assert_eq!(local.held(), MAX_HELD);
    assert!(!report.dropped.is_empty());

    // Reopened, the store holds what memory did; dropped, none.
    let mut local = Mem::open(local.into_store(), SCOPE).unwrap();
    assert_eq!(local.held(), MAX_HELD);
    assert_eq!(
        local.drop_held(Some(&Author::from(&one))).unwrap(),
        MAX_HELD_PER_AUTHOR
    );
    assert_eq!(local.held(), MAX_HELD - MAX_HELD_PER_AUTHOR);
    local.drop_held(None).unwrap();
    assert_eq!(local.held(), 0);
    assert!(local.wanted().is_empty());
    let local = Mem::open(local.into_store(), SCOPE).unwrap();
    assert_eq!(local.held(), 0);
}

/// A node dropped past the bound, delivered again once its parent is
/// applied, applies: a drop is not a refusal.
#[test]
fn a_dropped_node_applies_when_delivered_again() {
    let one = key(66);
    let parent = Node::<H, Ops>::sign(&key(5), &SCOPE, 0, vec![(5, 5)], BTreeSet::new());
    let child = Node::<H, Ops>::sign(&one, &SCOPE, 0, vec![], BTreeSet::from([parent.cid()]));
    let mut local = replica();
    local
        .ingest(
            (0..MAX_HELD_PER_AUTHOR as u32).map(|i| orphan(&one, i).to_bytes()),
            None,
            &mut crdt,
        )
        .unwrap();
    let report = local.ingest([child.to_bytes()], None, &mut crdt).unwrap();
    assert_eq!(report.dropped, vec![child.cid()]);
    let report = local
        .ingest([parent.to_bytes(), child.to_bytes()], None, &mut crdt)
        .unwrap();
    assert_eq!(report.applied, vec![parent.cid(), child.cid()]);
}

/// A row key no store takes fails the batch in every store, before
/// anything is committed.
#[test]
fn a_row_no_store_takes_fails_the_batch() {
    let long = vec![1; merkle_crdt::MAX_ROW_KEY + 1];
    for bad in [Vec::new(), long] {
        let mut write = |_: Event<'_, H, Ops>, rows: &mut dyn Rows| rows.write(&bad, Some(b"x"));
        let node = Node::<H, Ops>::sign(&key(1), &SCOPE, 0, vec![], BTreeSet::new());
        let mut local = replica();
        assert!(matches!(
            local.ingest([node.to_bytes()], None, &mut write),
            Err(Error::Row)
        ));
        assert!(matches!(
            local.record(&key(2), vec![], &mut write),
            Err(Error::Row)
        ));
        assert!(local.store().is_empty());
        assert!(local.heads().is_empty());
    }
}

/// A local node that does not decode, its operations past what decoding
/// takes, is refused before anything is written: no other replica could
/// apply it, nor anything the author signs after it.
#[test]
fn a_node_that_does_not_decode_is_not_recorded() {
    type Bytes = Vec<u8>;
    let mut nop = |_: Event<'_, H, Bytes>, _: &mut dyn Rows| {};
    let mut local = Replica::<H, Bytes, _>::open(MemStore::new(), SCOPE).unwrap();
    let ops = vec![0; merkle_crdt::MAX_DECODE_ITEMS + 1];
    assert!(matches!(
        local.record(&key(0), ops, &mut nop),
        Err(Error::Unencodable)
    ));
    assert!(local.outbox().unwrap().is_empty());
    assert!(local.store().is_empty());
    let cid = local.record(&key(0), vec![0; 16], &mut nop).unwrap();
    let outbox = local.outbox().unwrap();
    assert_eq!((outbox[0].cid.clone(), outbox[0].seq), (cid, 0));
}

/// A store counting the index lookups a replica makes.
struct Counting {
    inner: MemStore<H>,
    lookups: Cell<usize>,
}

impl Store<H> for Counting {
    type Error = std::convert::Infallible;
    fn node(&self, cid: &Cid<H>) -> Result<Option<Vec<u8>>, Self::Error> {
        self.inner.node(cid)
    }
    fn contains(&self, cid: &Cid<H>) -> Result<bool, Self::Error> {
        self.inner.contains(cid)
    }
    fn held(&self, cid: &Cid<H>) -> Result<Option<Vec<u8>>, Self::Error> {
        self.inner.held(cid)
    }
    fn authored(&self, author: &Author, seq: u64) -> Result<Option<Cid<H>>, Self::Error> {
        self.lookups.set(self.lookups.get() + 1);
        self.inner.authored(author, seq)
    }
    fn is_authored(&self, author: &Author, seq: u64, cid: &Cid<H>) -> Result<bool, Self::Error> {
        self.lookups.set(self.lookups.get() + 1);
        self.inner.is_authored(author, seq, cid)
    }
    fn row(&self, key: &[u8]) -> Result<Option<Vec<u8>>, Self::Error> {
        self.inner.row(key)
    }
    fn load(&self) -> Result<Loaded<H>, Self::Error> {
        self.inner.load()
    }
    fn commit(&mut self, changes: Changes<H>) -> Result<(), Self::Error> {
        self.inner.commit(changes)
    }
}

/// Applying a node after an author's forks costs a lookup a parent and one
/// more, however many forks there are.
#[test]
fn a_node_after_many_forks_costs_what_one_after_none_does() {
    let forks = forks(77, 500);
    let mut replica = Replica::<H, Ops, _>::open(
        Counting {
            inner: MemStore::new(),
            lookups: Cell::new(0),
        },
        SCOPE,
    )
    .unwrap();
    replica
        .ingest(forks.iter().map(|node| node.to_bytes()), None, &mut crdt)
        .unwrap();
    replica.store().lookups.set(0);
    let next = Node::<H, Ops>::sign(
        &key(77),
        &SCOPE,
        1,
        vec![],
        BTreeSet::from([forks[0].cid()]),
    );
    let report = replica.ingest([next.to_bytes()], None, &mut crdt).unwrap();
    assert_eq!(report.applied, vec![next.cid()]);
    assert!(
        replica.store().lookups.get() <= 2,
        "{} index lookups",
        replica.store().lookups.get()
    );
}

/// A store whose row reads fail.
struct Unreadable(MemStore<H>);

impl Store<H> for Unreadable {
    type Error = &'static str;
    fn node(&self, cid: &Cid<H>) -> Result<Option<Vec<u8>>, Self::Error> {
        Ok(self.0.node(cid).unwrap())
    }
    fn contains(&self, cid: &Cid<H>) -> Result<bool, Self::Error> {
        Ok(self.0.contains(cid).unwrap())
    }
    fn held(&self, cid: &Cid<H>) -> Result<Option<Vec<u8>>, Self::Error> {
        Ok(self.0.held(cid).unwrap())
    }
    fn authored(&self, author: &Author, seq: u64) -> Result<Option<Cid<H>>, Self::Error> {
        Ok(self.0.authored(author, seq).unwrap())
    }
    fn is_authored(&self, author: &Author, seq: u64, cid: &Cid<H>) -> Result<bool, Self::Error> {
        Ok(self.0.is_authored(author, seq, cid).unwrap())
    }
    fn row(&self, _: &[u8]) -> Result<Option<Vec<u8>>, Self::Error> {
        Err("unreadable")
    }
    fn load(&self) -> Result<Loaded<H>, Self::Error> {
        Ok(self.0.load().unwrap())
    }
    fn commit(&mut self, changes: Changes<H>) -> Result<(), Self::Error> {
        self.0.commit(changes).unwrap();
        Ok(())
    }
}

/// A read the store fails is the store's error, even where the CRDT took
/// the missing row for its own error.
#[test]
fn a_failed_read_is_the_stores_error() {
    struct Strict;
    impl merkle_crdt::Apply<H, Ops> for Strict {
        type Error = &'static str;
        fn apply(&mut self, _: Event<'_, H, Ops>, rows: &mut dyn Rows) -> Result<(), &'static str> {
            rows.read(b"k").ok_or("missing row").map(drop)
        }
    }
    let mut replica = Replica::<H, Ops, _>::open(Unreadable(MemStore::new()), SCOPE).unwrap();
    let node = Node::<H, Ops>::sign(&key(1), &SCOPE, 0, vec![], BTreeSet::new());
    let result = replica.ingest([node.to_bytes()], None, &mut Strict);
    assert!(
        matches!(result, Err(Error::Store("unreadable"))),
        "{:?}",
        result.err()
    );
    let result = replica.record(&key(2), vec![], &mut Strict);
    assert!(matches!(result, Err(Error::Store("unreadable"))));
}
