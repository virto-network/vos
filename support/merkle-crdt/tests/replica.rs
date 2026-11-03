//! The incremental replica against the full rebuild, over random DAGs and
//! random deliveries; equivocations, refusals, fetching, and failed
//! commits.

mod common;

use std::collections::BTreeSet;

use common::{H, Ops, Rng, Step, crdt, deliveries, generate, key};
use merkle_crdt::sync::{Feed, Page, Source, Want, serve};
use merkle_crdt::{
    Author, Changes, Cid, DagNode, Error, Loaded, MemStore, Node, Refusal, Replica, Signed, Store,
    rebuild,
};
use proptest::prelude::*;

type Mem = Replica<H, Ops, MemStore<H>>;

fn replica() -> Mem {
    Replica::open(MemStore::new()).unwrap()
}

fn step() -> impl Strategy<Value = Step> {
    prop_oneof![
        6 => (any::<u8>(), prop::collection::vec((0..8u64, any::<u64>()), 0..4), any::<u64>())
            .prop_map(|(author, ops, pick)| Step::Record { author, ops, pick }),
        3 => (any::<u8>(), any::<u8>()).prop_map(|(from, to)| Step::Learn { from, to }),
        1 => (any::<u8>(), any::<u64>()).prop_map(|(author, value)| Step::Equivocate { author, value }),
        1 => any::<u8>().prop_map(|author| Step::BreakChain { author: author % 2 }),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(200))]

    /// Any delivery order, with duplicates and any batching, ends in the
    /// rows, heads and equivocations of the full rebuild; and two replicas
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
            let rebuilt = rebuild::<H, Ops, _, _>(replica.store(), &mut crdt).unwrap();
            prop_assert_eq!(replica.store().rows(), &rebuilt.rows);
            prop_assert_eq!(replica.heads(), &rebuilt.heads);
            prop_assert_eq!(replica.equivocations(), &rebuilt.equivocations);
            prop_assert_eq!(replica.equivocations(), &dag.equivocations);
            let applied: BTreeSet<&Cid<H>> = dag.nodes.iter().map(|(c, _)| c).collect();
            prop_assert_eq!(rebuilt.nodes, applied.len() - dag.refused.len());
            replicas.push(replica);
        }
        prop_assert_eq!(replicas[0].store().rows(), replicas[1].store().rows());
        prop_assert_eq!(replicas[0].heads(), replicas[1].heads());
    }

    /// A replica that records its own operations between ingests ends
    /// where the rebuild of its store does.
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
        let rebuilt = rebuild::<H, Ops, _, _>(replica.store(), &mut crdt).unwrap();
        prop_assert_eq!(replica.store().rows(), &rebuilt.rows);
        prop_assert_eq!(replica.heads(), &rebuilt.heads);
        prop_assert_eq!(replica.heads().len(), 1);
    }
}

#[test]
fn equivocation_is_detected_kept_and_reported_once() {
    let author = key(0);
    let first = Node::<H, Ops>::sign(&author, 0, vec![(1, 1)], BTreeSet::new());
    let twin = Node::<H, Ops>::sign(&author, 0, vec![(1, 2)], BTreeSet::new());
    let third = Node::<H, Ops>::sign(&author, 0, vec![(1, 3)], BTreeSet::new());
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
    let other = Node::<H, Ops>::sign(&key(1), 0, vec![], BTreeSet::from([twin.cid()]));
    let report = replica.ingest([other.to_bytes()], None, &mut crdt).unwrap();
    assert_eq!(report.applied, vec![other.cid()]);
}

#[test]
fn signatures_are_refused_unless_the_authors() {
    let author = key(0);
    let node = Node::<H, Ops>::sign(&author, 0, vec![(1, 1)], BTreeSet::new());

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
    let two = Node::<H, Ops>::sign(&author, 0, vec![], parents);
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
    let first = Node::<H, Ops>::sign(&author, 0, vec![], BTreeSet::new());
    let gap = Node::<H, Ops>::sign(&author, 2, vec![], BTreeSet::from([first.cid()]));
    let child = Node::<H, Ops>::sign(&key(1), 0, vec![], BTreeSet::from([gap.cid()]));
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
    let late = Node::<H, Ops>::sign(&key(2), 0, vec![], BTreeSet::from([gap.cid()]));
    let report = replica.ingest([late.to_bytes()], None, &mut crdt).unwrap();
    assert_eq!(
        report.refused,
        vec![(Some(late.cid()), Refusal::RefusedParent)]
    );
}

/// A peer serving its store through [`serve`], counting round trips.
struct Peer<'a> {
    store: &'a MemStore<H>,
    budget: usize,
    trips: usize,
}

impl Source<H> for Peer<'_> {
    type Error = std::convert::Infallible;
    fn fetch(&mut self, want: &Want<H>) -> Result<Vec<Vec<u8>>, Self::Error> {
        self.trips += 1;
        serve(self.store, want, self.budget)
    }
}

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

#[test]
fn a_dag_walk_fetches_a_budget_a_round_trip() {
    let mut remote = replica();
    history(&mut remote, 3, 300);
    let mut local = replica();
    let mut peer = Peer {
        store: remote.store(),
        budget: 64 << 10,
        trips: 0,
    };
    let report = local
        .sync(remote.heads().clone(), &mut peer, &mut crdt)
        .unwrap();
    assert_eq!(report.applied.len(), 300);
    assert_eq!(peer.trips, 1, "300 small nodes fit one budget");
    assert_eq!(local.store().rows(), remote.store().rows());

    // A budget of about 20 nodes: the walk comes back newest first, the
    // replica holds those and asks for their parents.
    let mut local = replica();
    let mut peer = Peer {
        store: remote.store(),
        budget: 20 * 200,
        trips: 0,
    };
    local
        .sync(remote.heads().clone(), &mut peer, &mut crdt)
        .unwrap();
    assert_eq!(local.store().rows(), remote.store().rows());
    assert!(
        (10..=40).contains(&peer.trips),
        "{} round trips",
        peer.trips
    );

    // A peer ahead by a few nodes sends only those: `have` skips the rest.
    for i in 0..5 {
        remote.record(&key(1), vec![(i, i)], &mut crdt).unwrap();
    }
    let mut peer = Peer {
        store: remote.store(),
        budget: 64 << 10,
        trips: 0,
    };
    let report = local
        .sync(remote.heads().clone(), &mut peer, &mut crdt)
        .unwrap();
    assert_eq!(report.applied.len(), 5);
    assert_eq!(report.duplicates, 0, "nothing the replica had was sent");
    assert_eq!(local.store().rows(), remote.store().rows());
}

/// A server that numbers nodes as it accepted them, serving a page of at
/// most `page` items.
struct Server {
    items: Vec<(u64, Vec<u8>)>,
    page: usize,
    trips: usize,
}

impl Feed for Server {
    type Error = std::convert::Infallible;
    fn since(&mut self, position: Option<u64>) -> Result<Page, Self::Error> {
        self.trips += 1;
        let start = self
            .items
            .iter()
            .position(|(at, _)| position.is_none_or(|p| *at > p))
            .unwrap_or(self.items.len());
        let end = (start + self.page).min(self.items.len());
        Ok(Page {
            items: self.items[start..end].to_vec(),
            more: end < self.items.len(),
        })
    }
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
    // Read only the first pages, then reopen the replica from its store.
    let first = server.since(None).unwrap();
    local
        .ingest(
            first.items.iter().map(|(_, b)| b.clone()),
            Some(first.items.last().unwrap().0),
            &mut crdt,
        )
        .unwrap();
    let held = local.held();
    let mut local = Mem::open(local.into_store()).unwrap();
    assert_eq!(local.held(), held, "held nodes survive reopening");
    local.catch_up(&mut server, &mut crdt).unwrap();
    assert_eq!(local.cursor(), Some(last));
    assert_eq!(local.held(), 0);
    let rebuilt = rebuild::<H, Ops, _, _>(local.store(), &mut crdt).unwrap();
    assert_eq!(local.store().rows(), &rebuilt.rows);
    assert_eq!(rebuilt.nodes, dag.nodes.len());

    // Nothing new: one round trip, nothing applied.
    let trips = server.trips;
    let report = local.catch_up(&mut server, &mut crdt).unwrap();
    assert!(report.applied.is_empty());
    assert_eq!(server.trips, trips + 1);
}

#[test]
fn a_feed_going_backwards_is_refused() {
    struct Backwards;
    impl Feed for Backwards {
        type Error = ();
        fn since(&mut self, _: Option<u64>) -> Result<Page, ()> {
            Ok(Page {
                items: vec![(5, vec![]), (4, vec![])],
                more: false,
            })
        }
    }
    let mut local = replica();
    assert!(matches!(
        local.catch_up(&mut Backwards, &mut crdt),
        Err(Error::Disordered)
    ));
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
    fn authored(&self, author: &Author, seq: u64) -> Result<Vec<Cid<H>>, Self::Error> {
        Ok(self.inner.authored(author, seq).unwrap())
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
    let mut local = Replica::<H, Ops, _>::open(Flaky {
        inner: MemStore::new(),
        fail: false,
    })
    .unwrap();
    // Hold the last five, then fail the batch that would release them.
    local
        .ingest(bytes[5..].to_vec(), Some(1), &mut crdt)
        .unwrap();
    assert_eq!(local.held(), 5);
    let heads = local.heads().clone();
    let mut inner = local.into_store();
    inner.fail = true;
    let mut failing = Replica::<H, Ops, _>::open(inner).unwrap();
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
    let mut retry = Replica::<H, Ops, _>::open(inner).unwrap();
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
    let local = Mem::open(local.into_store()).unwrap();
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
    let node: DagNode<H, Signed<Ops>> =
        DagNode::from_bytes(&local.outbox().unwrap()[0].bytes).unwrap();
    assert_eq!(node.payload.seq, 2);
    assert!(node.parents.contains(&outbox[1].cid));
}
