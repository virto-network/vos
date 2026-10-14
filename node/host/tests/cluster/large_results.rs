//! Work results of 64 KiB or more, which travel as blobs their log entries
//! name: replicated, fetched by followers, applied on every replica alike,
//! and collected once the log is compacted past them.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use vos_checker::calls::done;
use vos_node::store::{BlobRef, EntryKind, LARGE_RESULT};
use vos_node::{CallError, Hooks, Node, Reply};
use vos_wire::batch::{Batch, Request};
use vos_wire::ids::AgentId;
use vos_wire::peer::NodeNumber;
use vos_wire::result::Outcome;
use vos_wire::{Decode, Encode};

use crate::common::{Cluster, compacting, wait_until};

/// Rows each call writes, of [`ROW`] bytes: within a step's 256 KiB.
const ROWS: u32 = 4;
const ROW: u32 = 60_000;
/// Calls the second batch holds: a result past 2 MiB.
const CALLS: u64 = 10;

/// Holds every refine while armed, counting those it held.
#[derive(Default)]
struct HoldRefines {
    armed: AtomicBool,
    held: AtomicUsize,
}

impl HoldRefines {
    fn arm(&self) {
        self.armed.store(true, Ordering::SeqCst);
    }

    fn release(&self) {
        self.armed.store(false, Ordering::SeqCst);
    }
}

impl Hooks for HoldRefines {
    fn fail_refine(&self, _: AgentId, _: &Batch) -> bool {
        if self.armed.load(Ordering::SeqCst) {
            self.held.fetch_add(1, Ordering::SeqCst);
            while self.armed.load(Ordering::SeqCst) {
                std::thread::sleep(Duration::from_millis(1));
            }
        }
        false
    }
}

/// Three nodes whose refines `hooks` can hold, each tuned further by
/// `tuning`.
fn cluster(
    hooks: &Arc<HoldRefines>,
    tuning: impl Fn(NodeNumber, &mut vos_node::Config) + Send + Sync + 'static,
) -> Cluster {
    let hooks = Arc::clone(hooks);
    Cluster::tuned(3, move |number, config| {
        config.hooks = hooks.clone();
        tuning(number, config);
    })
}

/// Alice's request filling the counter's rows, at `sequence` of the test's
/// session.
fn fill(cluster: &Cluster, sequence: u64) -> Request {
    Request {
        method: cluster.programs.method("fill"),
        arguments: (ROWS, ROW).encode(),
        ..cluster.request(sequence, 0)
    }
}

#[track_caller]
fn filled(reply: Result<Reply, CallError>) {
    match reply {
        Ok(Reply::Ran(Outcome::Done(bytes))) => assert_eq!(u32::decode(&bytes).unwrap().0, ROWS),
        other => panic!("not filled: {other:?}"),
    }
}

/// Fills at `leader` in two batches, `first` and the next `CALLS`: the
/// second is held back until all its calls are queued, so its result
/// passes 2 MiB. The index of each batch's entry.
fn two_batches(
    cluster: &Cluster,
    hooks: &HoldRefines,
    leader: NodeNumber,
    agent: AgentId,
    first: u64,
) -> Vec<u64> {
    let node = cluster.node(leader);
    let before = node.applied(agent).unwrap();
    hooks.arm();
    let held = hooks.held.load(Ordering::SeqCst);
    let alone = node.call(agent, fill(cluster, first));
    wait_until("the first batch's refine is held", || {
        hooks.held.load(Ordering::SeqCst) > held
    });
    let together: Vec<_> = (first + 1..=first + CALLS)
        .map(|sequence| node.call(agent, fill(cluster, sequence)))
        .collect();
    hooks.release();
    filled(smol::block_on(alone));
    for call in together {
        filled(smol::block_on(call));
    }
    let entries = results(node, agent, before + 1..=node.applied(agent).unwrap());
    assert_eq!(entries.len(), 2, "two batches: {entries:?}");
    entries.into_iter().map(|(index, _)| index).collect()
}

/// The work results `node` holds of `agent` at `indices`, with the blob of
/// each large one.
fn results(
    node: &Node,
    agent: AgentId,
    indices: std::ops::RangeInclusive<u64>,
) -> Vec<(u64, Option<BlobRef>)> {
    indices
        .filter_map(|index| {
            let entry = node.store().log_entry(agent, index).unwrap()?;
            match entry.kind {
                EntryKind::Result => Some((index, None)),
                EntryKind::LargeResult => {
                    assert!(entry.body.is_empty(), "a large result's body is its blob");
                    Some((index, entry.result_blob().copied()))
                }
                _ => None,
            }
        })
        .collect()
}

/// The blob of the large result at `index` on `node`.
#[track_caller]
fn blob_at(node: &Node, agent: AgentId, index: u64) -> BlobRef {
    match results(node, agent, index..=index)[..] {
        [(_, Some(blob))] => blob,
        ref other => panic!("no large result at {index}: {other:?}"),
    }
}

#[test]
fn a_large_result_travels_as_a_blob_and_applies_on_every_replica() {
    let hooks = Arc::new(HoldRefines::default());
    let cluster = cluster(&hooks, |_, _| {});
    let agent = cluster.counter_agent(&[1, 2, 3]);
    let leader = cluster.leader(agent);
    let indices = two_batches(&cluster, &hooks, leader, agent, 1);
    cluster.converged(agent);
    let blobs: Vec<BlobRef> = indices
        .iter()
        .map(|index| blob_at(cluster.node(leader), agent, *index))
        .collect();
    assert!(blobs[0].len as usize >= LARGE_RESULT, "{blobs:?}");
    assert!(blobs[1].len >= 2 << 20, "{blobs:?}");
    for number in 1..=3 {
        let node = cluster.node(number);
        for (index, blob) in indices.iter().zip(&blobs) {
            assert_eq!(blob_at(node, agent, *index), *blob, "node {number}");
            assert!(node.stores_blob(&blob.hash), "node {number} holds it");
        }
    }
    // A small result stays inline.
    assert_eq!(done(cluster.increment(leader, agent, 12, 5)), 5);
    let applied = cluster.node(leader).applied(agent).unwrap();
    assert_eq!(
        results(cluster.node(leader), agent, applied..=applied),
        [(applied, None)]
    );
}

/// A follower cut off while large results commit catches up through them
/// from the log, fetching their blobs.
#[test]
fn a_lagging_follower_catches_up_through_a_large_result() {
    let hooks = Arc::new(HoldRefines::default());
    let cluster = cluster(&hooks, |_, _| {});
    let agent = cluster.counter_agent(&[1, 2, 3]);
    let (leader, follower) = cluster.leader_and_follower(agent);
    wait_until("the follower applies the install", || {
        cluster.node(follower).applied(agent) >= cluster.node(leader).applied(agent)
    });
    cluster.hub.isolate(follower);
    let indices = two_batches(&cluster, &hooks, leader, agent, 1);
    let lagging = cluster.node(follower);
    assert!(lagging.applied(agent).unwrap() < indices[0]);
    let blob = blob_at(cluster.node(leader), agent, indices[1]);
    assert!(!lagging.stores_blob(&blob.hash));
    cluster.hub.heal();
    cluster.converged(agent);
    assert_eq!(blob_at(lagging, agent, indices[1]), blob);
    assert!(lagging.stores_blob(&blob.hash), "fetched");
}

/// A large result's blob stays while the log holds its entry, past the
/// blob store's horizon, and goes once the log is compacted past it.
#[test]
fn a_large_results_blob_goes_once_the_log_is_compacted_past_it() {
    let hooks = Arc::new(HoldRefines::default());
    let cluster = cluster(&hooks, |number, config| {
        compacting(number, config);
        config.compact_every = 32;
        config.blob_collect_every = Duration::from_millis(100);
        config.blob_horizon = Duration::from_secs(1);
    });
    let agent = cluster.counter_agent(&[1, 2, 3]);
    let leader = cluster.leader(agent);
    let indices = two_batches(&cluster, &hooks, leader, agent, 1);
    cluster.converged(agent);
    let blobs: Vec<BlobRef> = indices
        .iter()
        .map(|index| blob_at(cluster.node(leader), agent, *index))
        .collect();
    std::thread::sleep(Duration::from_secs(2));
    for (number, node) in cluster.running() {
        assert!(
            blobs.iter().all(|blob| node.stores_blob(&blob.hash)),
            "node {number} keeps them while its log names them"
        );
    }
    let last = *indices.last().unwrap();
    for sequence in 12..=60 {
        assert_eq!(
            done(cluster.increment(leader, agent, sequence, 1)),
            sequence - 11
        );
    }
    for number in 1..=3 {
        cluster.compacted_past(number, agent, last);
    }
    wait_until("every replica collects the blobs", || {
        cluster
            .running()
            .all(|(_, node)| blobs.iter().all(|blob| !node.stores_blob(&blob.hash)))
    });
}
