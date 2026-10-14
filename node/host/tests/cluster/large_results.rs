//! Work results of 64 KiB or more, which travel as blobs their log entries
//! name: replicated, fetched by followers, applied on every replica alike,
//! weighed toward compaction, and collected soon after the log is compacted
//! past them.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use vos_checker::calls::done;
use vos_net::Class;
use vos_node::blobs::Blobs;
use vos_node::store::{BlobRef, EntryKind, Fjall, LARGE_RESULT};
use vos_node::{CallError, Hooks, Node, Reply};
use vos_wire::batch::{Batch, Request};
use vos_wire::ids::AgentId;
use vos_wire::peer::NodeNumber;
use vos_wire::result::Outcome;
use vos_wire::{Decode, Encode};

use crate::common::{Cluster, compacting, log_start, wait_until};

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

/// A large result's blob stays while the log holds its entry, past its
/// brief horizon, and goes soon after the log is compacted past it: by
/// that horizon, not the store's hour.
#[test]
fn a_large_results_blob_goes_once_the_log_is_compacted_past_it() {
    let hooks = Arc::new(HoldRefines::default());
    let cluster = cluster(&hooks, |number, config| {
        compacting(number, config);
        config.compact_every = 32;
        config.blob_collect_every = Duration::from_millis(100);
        config.named_blob_horizon = Duration::from_secs(1);
        assert_eq!(config.blob_horizon, Duration::from_secs(3_600));
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

/// Large results make a compaction due by the bytes of their blobs, which
/// their entries' few bytes alone never would, and the tail a compaction
/// keeps counts them too.
#[test]
fn large_results_make_a_compaction_due_by_their_blobs() {
    let hooks = Arc::new(HoldRefines::default());
    let cluster = cluster(&hooks, |_, config| {
        config.compact_every = 1 << 20;
        config.compact_bytes = 2 << 20;
        config.compact_tail_bytes = 1 << 20;
    });
    let agent = cluster.counter_agent(&[1, 2, 3]);
    let leader = cluster.leader(agent);
    let indices = two_batches(&cluster, &hooks, leader, agent, 1);
    // The second result alone weighs past the tail's megabyte, so the log
    // keeps neither. An apply is durable, and so compactable, only once a
    // later synced flush covers it: small calls bring those flushes.
    let compacted =
        || (1..=3).all(|number| log_start(cluster.node(number), agent) > indices[1] - 1);
    for sequence in 12.. {
        if compacted() {
            break;
        }
        assert!(
            sequence < 112,
            "every node compacts past {}",
            indices[1] - 1
        );
        assert_eq!(
            done(cluster.increment(leader, agent, sequence, 1)),
            sequence - 11
        );
    }
}

/// Records the blob requests a node takes, and withholds blobs from the
/// nodes it is told to.
#[derive(Default)]
struct Serving {
    asked: Mutex<Vec<(NodeNumber, [u8; 32], Instant)>>,
    withheld: Mutex<BTreeSet<NodeNumber>>,
}

impl Serving {
    fn withhold(&self, from: &[NodeNumber]) {
        *self.withheld.lock().unwrap() = from.iter().copied().collect();
    }

    /// When each blob was asked for by `by`, in order.
    fn asked_by(&self, by: NodeNumber) -> BTreeMap<[u8; 32], Vec<Instant>> {
        let mut asked: BTreeMap<[u8; 32], Vec<Instant>> = BTreeMap::new();
        for (to, hash, at) in self.asked.lock().unwrap().iter() {
            if *to == by {
                asked.entry(*hash).or_default().push(*at);
            }
        }
        asked
    }
}

impl Hooks for Serving {
    fn serve_blob(&self, to: NodeNumber, hash: &[u8; 32]) -> bool {
        self.asked.lock().unwrap().push((to, *hash, Instant::now()));
        !self.withheld.lock().unwrap().contains(&to)
    }
}

/// Three nodes, each with its own [`Serving`].
fn serving_cluster() -> (Cluster, Vec<Arc<Serving>>) {
    let hooks: Vec<Arc<Serving>> = (0..3).map(|_| Arc::default()).collect();
    let each = hooks.clone();
    let cluster = Cluster::tuned(3, move |number, config| {
        config.hooks = each[usize::from(number) - 1].clone();
    });
    (cluster, hooks)
}

/// Each large result `node` holds of `agent` past `after`, by index.
fn large_blobs(node: &Node, agent: AgentId, after: u64) -> Vec<(u64, BlobRef)> {
    node.store()
        .raft(agent)
        .unwrap()
        .log
        .into_iter()
        .filter(|(index, _)| *index > after)
        .filter_map(|(index, entry)| Some((index, *entry.result_blob()?)))
        .collect()
}

/// A follower asks for each blob once, of the leader, as its entry comes,
/// and again only by a retry, the retry interval later: never of one
/// member and then another at once. The leader's blobs never reach it
/// here, so every blob stays in flight while the next results come.
#[test]
fn a_blob_is_asked_for_again_only_by_a_retry() {
    let (cluster, hooks) = serving_cluster();
    let agent = cluster.counter_agent(&[1, 2, 3]);
    let (leader, follower) = cluster.leader_and_follower(agent);
    cluster.hub.cut_class(leader, follower, Class::Bulk);
    let before = cluster.node(leader).applied(agent).unwrap();
    for sequence in 1..=5 {
        filled(smol::block_on(
            cluster.node(leader).call(agent, fill(&cluster, sequence)),
        ));
    }
    let blobs = large_blobs(cluster.node(leader), agent, before);
    assert_eq!(blobs.len(), 5, "{blobs:?}");
    // Each blob's asks, of any member, in order.
    let asks = || {
        let mut asks: BTreeMap<[u8; 32], Vec<(Instant, NodeNumber)>> = BTreeMap::new();
        for (number, serving) in (1..).zip(&hooks) {
            for (hash, times) in serving.asked_by(follower) {
                let asked = asks.entry(hash).or_default();
                asked.extend(times.into_iter().map(|at| (at, number)));
                asked.sort();
            }
        }
        asks
    };
    wait_until("the follower asks for every blob", || {
        let asks = asks();
        blobs.iter().all(|(_, blob)| asks.contains_key(&blob.hash))
    });
    // Past a retry or two.
    std::thread::sleep(Duration::from_millis(2_500));
    let asks = asks();
    for (index, blob) in &blobs {
        let asked = &asks[&blob.hash];
        assert_eq!(
            asked[0].1, leader,
            "the blob at {index} is asked of the leader"
        );
        for pair in asked.windows(2) {
            assert!(
                pair[1].0 - pair[0].0 >= Duration::from_millis(500),
                "the blob at {index} asked for again after {:?}: {asked:?}",
                pair[1].0 - pair[0].0
            );
        }
    }
    cluster.hub.heal();
    cluster.converged(agent);
}

/// A follower whose new leader lacks a blob turns to another member that
/// has it, once its ask of the leader waited past the retry interval.
#[test]
fn a_follower_turns_from_a_leader_lacking_a_blob_to_a_member_holding_it() {
    let (cluster, hooks) = serving_cluster();
    let agent = cluster.counter_agent(&[1, 2, 3]);
    let old = cluster.leader(agent);
    let mut others = (1..=3).filter(|number| *number != old);
    let (next, follower) = (others.next().unwrap(), others.next().unwrap());
    wait_until("every replica applies the install", || {
        let applied = cluster.node(old).applied(agent);
        cluster
            .running()
            .all(|(_, node)| node.applied(agent) >= applied)
    });
    let serving = |number: NodeNumber| &hooks[usize::from(number) - 1];
    // Only `next` takes the large result, and its leader withholds the blob.
    serving(old).withhold(&[1, 2, 3]);
    cluster.hub.partition(old, follower);
    let before = cluster.node(old).applied(agent).unwrap();
    let call = cluster.node(old).call(agent, fill(&cluster, 1));
    let mut entry = Vec::new();
    wait_until("the next leader holds the large result's entry", || {
        entry = large_blobs(cluster.node(next), agent, before);
        !entry.is_empty()
    });
    let blob = entry[0].1;
    // It leads, lacking the blob, and the follower takes the entry from it.
    cluster.hub.isolate(old);
    wait_until("the next leader leads", || cluster.node(next).leads(agent));
    wait_until("the follower holds the entry", || {
        !large_blobs(cluster.node(follower), agent, before).is_empty()
    });
    // The old leader serves the follower alone, and the follower nobody.
    serving(old).withhold(&[next]);
    serving(follower).withhold(&[1, 2, 3]);
    cluster.hub.heal();
    wait_until("the follower fetches the blob", || {
        cluster.node(follower).stores_blob(&blob.hash)
    });
    assert!(
        serving(next).asked_by(follower).contains_key(&blob.hash),
        "the follower asked its leader first"
    );
    assert!(
        !cluster.node(next).stores_blob(&blob.hash),
        "the leader still lacks it"
    );
    serving(old).withhold(&[]);
    serving(follower).withhold(&[]);
    cluster.converged(agent);
    drop(call);
}

/// Loses the result blob of every entry an armed node applies.
#[derive(Default)]
struct LoseBlobs(AtomicBool);

impl Hooks for LoseBlobs {
    fn lose_blob(&self, _: AgentId, _: u64) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

/// Three nodes, each with its own [`LoseBlobs`].
fn losing_cluster() -> (Cluster, Vec<Arc<LoseBlobs>>) {
    let hooks: Vec<Arc<LoseBlobs>> = (0..3).map(|_| Arc::default()).collect();
    let each = hooks.clone();
    let cluster = Cluster::tuned(3, move |number, config| {
        config.hooks = each[usize::from(number) - 1].clone();
    });
    (cluster, hooks)
}

/// A large result proposed at `leader`, which `follower` finds its blob
/// lost for as it applies it: it halts there. The entry's index and blob.
fn halted_on_a_large_result(
    cluster: &Cluster,
    hooks: &[Arc<LoseBlobs>],
    leader: NodeNumber,
    follower: NodeNumber,
    agent: AgentId,
) -> (u64, BlobRef) {
    let losing = &hooks[usize::from(follower) - 1].0;
    losing.store(true, Ordering::SeqCst);
    let before = cluster.node(leader).applied(agent).unwrap();
    filled(smol::block_on(
        cluster.node(leader).call(agent, fill(cluster, 1)),
    ));
    let [(index, blob)] = large_blobs(cluster.node(leader), agent, before)[..] else {
        panic!("one large result");
    };
    wait_until("the follower halts", || {
        cluster
            .node(follower)
            .replica(agent)
            .is_some_and(|status| status.halted)
    });
    assert!(cluster.node(follower).applied(agent).unwrap() < index);
    losing.store(false, Ordering::SeqCst);
    (index, blob)
}

/// Stopped node `number`'s disk loses `blob`, as a torn segment tail
/// would: the blob of the committed entry at `index`, which it had not
/// applied, and its segment's last record.
fn lose_on_disk(cluster: &Cluster, number: NodeNumber, agent: AgentId, index: u64, blob: &BlobRef) {
    let dir = cluster.dirs[usize::from(number) - 1].path();
    let open = || {
        let store = Fjall::open(dir.join("store")).unwrap();
        let blobs = Blobs::open(dir.join("blobs"), &store).unwrap();
        (store, blobs)
    };
    let (store, blobs) = open();
    assert!(blobs.contains(&blob.hash).unwrap());
    let rows = store.raft(agent).unwrap();
    assert!(
        rows.applied < index && rows.hard.commit >= index,
        "applied {} and committed {} around {index}",
        rows.applied,
        rows.hard.commit
    );
    drop((blobs, store));
    let segment = std::fs::read_dir(dir.join("blobs"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .max()
        .unwrap();
    let file = std::fs::OpenOptions::new()
        .write(true)
        .open(&segment)
        .unwrap();
    file.set_len(file.metadata().unwrap().len() - 10).unwrap();
    drop(file);
    let (store, blobs) = open();
    assert!(!blobs.contains(&blob.hash).unwrap(), "the blob is lost");
    drop((blobs, store));
}

/// A replica whose store lost the blob of an entry it holds halts rather
/// than retry the apply. Its disk did lose it: once restarted it keeps the
/// committed entry, fetches the blob again from a peer, and applies it.
#[test]
fn a_replica_that_lost_a_committed_entrys_blob_halts_and_fetches_it_again() {
    let (mut cluster, hooks) = losing_cluster();
    let agent = cluster.counter_agent(&[1, 2, 3]);
    let (leader, follower) = cluster.leader_and_follower(agent);
    wait_until("the follower applies the install", || {
        cluster.node(follower).applied(agent) >= cluster.node(leader).applied(agent)
    });
    let (index, blob) = halted_on_a_large_result(&cluster, &hooks, leader, follower, agent);
    assert_eq!(done(cluster.increment(leader, agent, 2, 1)), 1);
    cluster.stop(follower);
    lose_on_disk(&cluster, follower, agent, index, &blob);
    cluster.start(follower);
    cluster.converged(agent);
    let restarted = cluster.node(follower);
    assert!(restarted.stores_blob(&blob.hash), "fetched again");
    assert_eq!(large_blobs(restarted, agent, index - 1)[0], (index, blob));
}

/// The leader and one follower commit a large result while the other
/// follower is cut off; the first follower's disk then loses its blob,
/// and the leader stops. The restarted follower never forgot the entry,
/// so it never elects the other, which lacks it, and it neither campaigns
/// nor leads while the blob is away. Once a member holding the blob, the
/// old leader, is back, the entry applies everywhere.
#[test]
fn a_committed_entry_whose_blob_a_replica_lost_stays_committed() {
    let (mut cluster, hooks) = losing_cluster();
    let agent = cluster.counter_agent(&[1, 2, 3]);
    let (leader, follower) = cluster.leader_and_follower(agent);
    let other = (1..=3)
        .find(|number| ![leader, follower].contains(number))
        .unwrap();
    wait_until("every replica applies the install", || {
        let applied = cluster.node(leader).applied(agent);
        cluster
            .running()
            .all(|(_, node)| node.applied(agent) >= applied)
    });
    cluster.hub.isolate(other);
    let (index, blob) = halted_on_a_large_result(&cluster, &hooks, leader, follower, agent);
    cluster.stop(follower);
    lose_on_disk(&cluster, follower, agent, index, &blob);
    cluster.stop(leader);
    cluster.hub.heal();
    cluster.start(follower);
    // The one that kept the entry never votes for the other, which lacks
    // it, and neither campaigns nor leads while the blob is away: no
    // leader comes, for many election timeouts, until a member holding
    // the blob returns.
    let holds = |number: NodeNumber| {
        large_blobs(cluster.node(number), agent, index - 1).first() == Some(&(index, blob))
    };
    std::thread::sleep(Duration::from_secs(1));
    assert!(holds(follower), "the follower kept the entry");
    let committed = cluster
        .node(follower)
        .store()
        .raft(agent)
        .unwrap()
        .hard
        .commit;
    assert!(committed >= index, "committed through {committed}");
    for number in [follower, other] {
        let node = cluster.node(number);
        assert!(!node.leads(agent), "node {number} leads");
        assert!(
            !node.stores_blob(&blob.hash),
            "node {number} lacks the blob"
        );
        assert!(node.applied(agent).unwrap() < index);
    }
    cluster.start(leader);
    cluster.converged(agent);
    let leader = cluster.leader(agent);
    assert_eq!(done(cluster.increment(leader, agent, 2, 1)), 1);
}
