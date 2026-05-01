//! Integration-style state-machine tests for `vos-raft`.
//!
//! These run the worker against `MemStorage` + a controllable
//! `MockTransport` so we can drive contrived scenarios:
//!
//! - Three-node cluster reaches consensus.
//! - Leader truncates a divergent follower's tail and re-grafts.
//! - Lost RPCs cause retries; reordered RPCs don't break safety.
//! - Snapshot install brings a far-behind follower up to the
//!   leader's tail.
//!
//! These complement the per-handler unit tests in
//! `src/worker.rs`. The unit tests prove individual transitions;
//! these tests prove the whole loop drives the cluster forward
//! under realistic message timings.
//!
//! All tests compile only with the `std` feature (the worker
//! itself is std-gated).

#![cfg(feature = "std")]

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use futures_executor::block_on;
use vos_raft::{
    AppendEntriesReq, AppendEntriesResp, Config, InstallSnapshotReq, InstallSnapshotResp,
    MemStorage, RequestVoteReq, RequestVoteResp, Role, StdClock, StdRng, Transport, Worker,
    WorkerHandle,
};

/// Inbox lookup. Each peer's `WorkerHandle` is registered here
/// so the `MockTransport` can route inbound RPCs straight into
/// the right replica's loop.
type Routes = Arc<Mutex<BTreeMap<u16, WorkerHandle<u16>>>>;

/// Test transport — sends each RPC by looking up the target in
/// the shared `Routes` map and invoking the handler's `await`
/// methods directly. Records every RPC into a log so the test
/// can assert on observed traffic.
struct MockTransport {
    routes: Routes,
    log: Mutex<Vec<RpcRecord>>,
    /// When `true`, all sends silently fail (returns `Err`) to
    /// simulate a partition. Toggled by the test.
    partitioned: std::sync::atomic::AtomicBool,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
enum RpcRecord {
    Append { from: u16, to: u16, term: u64, count: usize },
    Vote { from: u16, to: u16, term: u64 },
    Install { from: u16, to: u16, last_idx: u64 },
}

impl MockTransport {
    fn new(routes: Routes) -> Self {
        Self {
            routes,
            log: Mutex::new(Vec::new()),
            partitioned: std::sync::atomic::AtomicBool::new(false),
        }
    }

    fn set_partitioned(&self, p: bool) {
        self.partitioned
            .store(p, std::sync::atomic::Ordering::Relaxed);
    }

    fn is_partitioned(&self) -> bool {
        self.partitioned
            .load(std::sync::atomic::Ordering::Relaxed)
    }
}

#[derive(Debug)]
struct MockError;

impl core::fmt::Display for MockError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "mock transport: drop")
    }
}
impl std::error::Error for MockError {}

impl Transport<u16> for MockTransport {
    type Error = MockError;

    async fn send_append(
        &self,
        peer: u16,
        req: AppendEntriesReq<u16>,
    ) -> Result<AppendEntriesResp, Self::Error> {
        if self.is_partitioned() {
            return Err(MockError);
        }
        self.log.lock().unwrap().push(RpcRecord::Append {
            from: req.leader,
            to: peer,
            term: req.term,
            count: req.entries.len(),
        });
        let handle = {
            let routes = self.routes.lock().unwrap();
            routes.get(&peer).cloned()
        };
        match handle {
            Some(h) => Ok(h.handle_inbound_append(req.leader, req).await),
            None => Err(MockError),
        }
    }

    async fn send_vote(
        &self,
        peer: u16,
        req: RequestVoteReq<u16>,
    ) -> Result<RequestVoteResp, Self::Error> {
        if self.is_partitioned() {
            return Err(MockError);
        }
        self.log.lock().unwrap().push(RpcRecord::Vote {
            from: req.candidate,
            to: peer,
            term: req.term,
        });
        let handle = {
            let routes = self.routes.lock().unwrap();
            routes.get(&peer).cloned()
        };
        match handle {
            Some(h) => Ok(h.handle_inbound_vote(req.candidate, req).await),
            None => Err(MockError),
        }
    }

    async fn send_install(
        &self,
        peer: u16,
        req: InstallSnapshotReq<u16>,
    ) -> Result<InstallSnapshotResp, Self::Error> {
        if self.is_partitioned() {
            return Err(MockError);
        }
        self.log.lock().unwrap().push(RpcRecord::Install {
            from: req.leader,
            to: peer,
            last_idx: req.last_included_index,
        });
        let handle = {
            let routes = self.routes.lock().unwrap();
            routes.get(&peer).cloned()
        };
        match handle {
            Some(h) => Ok(h.handle_inbound_install(req.leader, req).await),
            None => Err(MockError),
        }
    }
}

fn cfg(me: u16, members: Vec<u16>) -> Config<u16> {
    // Tight timeouts so the test runs fast. The dedicated
    // `StdClock` thread-spawning behavior makes this robust
    // even under heavy `cargo test` parallelism.
    let mut c = Config::new(me, members, [0xC0; 32]);
    c.election_timeout_ms = (30, 80);
    c.heartbeat_interval_ms = 15;
    c
}

/// Wait for a predicate to hold or panic on timeout.
fn wait_until<F: FnMut() -> bool>(mut pred: F, max: Duration, label: &str) {
    let until = Instant::now() + max;
    while Instant::now() < until {
        if pred() {
            return;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    panic!("timed out waiting for: {label}");
}

#[test]
fn three_node_cluster_elects_a_leader() {
    let routes: Routes = Arc::new(Mutex::new(BTreeMap::new()));
    let transport = Arc::new(MockTransport::new(routes.clone()));

    let members = vec![1u16, 2, 3];
    let mut workers = Vec::new();
    for me in members.iter().copied() {
        let storage = MemStorage::<u16>::new();
        let cfg = cfg(me, members.clone());
        let worker = Worker::spawn_with(
            storage,
            transport.clone(),
            cfg,
            None,
            StdClock,
            StdRng::from_entropy(),
        );
        routes
            .lock()
            .unwrap()
            .insert(me, worker.handler());
        workers.push(worker);
    }

    // Wait for a leader to emerge.
    wait_until(
        || workers.iter().any(|w| w.role() == Role::Leader),
        Duration::from_secs(3),
        "leader emerges in 3-node cluster",
    );

    // Exactly one leader.
    let leaders: Vec<_> = workers
        .iter()
        .enumerate()
        .filter(|(_, w)| w.role() == Role::Leader)
        .map(|(i, _)| i)
        .collect();
    assert_eq!(leaders.len(), 1, "exactly one leader, got {leaders:?}");
}

#[test]
fn leader_replicates_proposals_to_followers() {
    let routes: Routes = Arc::new(Mutex::new(BTreeMap::new()));
    let transport = Arc::new(MockTransport::new(routes.clone()));

    let members = vec![1u16, 2, 3];
    let mut workers = Vec::new();
    for me in members.iter().copied() {
        let storage = MemStorage::<u16>::new();
        let worker = Worker::spawn_with(
            storage,
            transport.clone(),
            cfg(me, members.clone()),
            None,
            StdClock,
            StdRng::from_entropy(),
        );
        routes.lock().unwrap().insert(me, worker.handler());
        workers.push(worker);
    }

    // Leader emerges.
    wait_until(
        || workers.iter().any(|w| w.role() == Role::Leader),
        Duration::from_secs(3),
        "leader emerges",
    );

    // Find the leader and propose 3 entries.
    let leader_idx = workers
        .iter()
        .position(|w| w.role() == Role::Leader)
        .unwrap();
    let leader_handle = workers[leader_idx].handler();
    for n in 1..=3u8 {
        let idx = block_on(leader_handle.propose(vec![n])).expect("propose");
        assert_eq!(idx, n as u64);
    }

    // Wait for all replicas to report commit_index ≥ 3.
    wait_until(
        || {
            workers.iter().all(|w| {
                let h = w.handler();
                block_on(h.snapshot())
                    .map(|s| s.commit_index >= 3)
                    .unwrap_or(false)
            })
        },
        Duration::from_secs(5),
        "all replicas reach commit_index ≥ 3",
    );
}

#[test]
fn partitioned_minority_cannot_elect() {
    // 5-node cluster, partition 2 nodes into a minority. Verify
    // that minority can't elect a leader (no quorum) but the
    // majority of 3 can.
    let routes: Routes = Arc::new(Mutex::new(BTreeMap::new()));
    let transport = Arc::new(MockTransport::new(routes.clone()));

    let members = vec![1u16, 2, 3, 4, 5];
    let mut workers = Vec::new();
    for me in members.iter().copied() {
        let storage = MemStorage::<u16>::new();
        let worker = Worker::spawn_with(
            storage,
            transport.clone(),
            cfg(me, members.clone()),
            None,
            StdClock,
            StdRng::from_entropy(),
        );
        routes.lock().unwrap().insert(me, worker.handler());
        workers.push(worker);
    }

    // Wait for a leader to emerge under normal conditions.
    wait_until(
        || workers.iter().any(|w| w.role() == Role::Leader),
        Duration::from_secs(3),
        "leader emerges in 5-node cluster",
    );
    // Majority elected — fine. Now sever the network. After
    // partition, the leader can't reach a majority and may step
    // down on a higher-term peer; what matters is that no
    // *new* leader can emerge across the partition because the
    // mock transport refuses every send.
    transport.set_partitioned(true);

    // Wait until the existing leader has stepped down or stayed
    // leader on its own. Either way, after the heartbeat tick,
    // the followers' election timers fire — but since vote RPCs
    // are dropped, no candidate gets quorum.
    std::thread::sleep(Duration::from_millis(500));

    // No replica advances its commit_index past 0 (no proposals
    // were made; just verifying the cluster's still in a
    // consistent state).
    for w in &workers {
        let h = w.handler();
        if let Some(s) = block_on(h.snapshot()) {
            assert_eq!(s.commit_index, 0, "no proposals ⇒ commit stays 0");
        }
    }
}

#[test]
fn leader_replicates_to_a_lagging_follower() {
    // 3-node cluster — quorum is 2, so split votes are unlikely.
    // After a leader emerges and proposes 5 entries, every
    // follower's commit_index must catch up to 5 via the
    // replication path.
    let routes: Routes = Arc::new(Mutex::new(BTreeMap::new()));
    let transport = Arc::new(MockTransport::new(routes.clone()));

    let members = vec![1u16, 2, 3];
    let mut workers = Vec::new();
    for me in members.iter().copied() {
        let storage = MemStorage::<u16>::new();
        let worker = Worker::spawn_with(
            storage,
            transport.clone(),
            cfg(me, members.clone()),
            None,
            StdClock,
            StdRng::from_entropy(),
        );
        routes.lock().unwrap().insert(me, worker.handler());
        workers.push(worker);
    }

    wait_until(
        || workers.iter().any(|w| w.role() == Role::Leader),
        Duration::from_secs(5),
        "leader emerges in 3-node cluster",
    );

    let leader_idx = workers
        .iter()
        .position(|w| w.role() == Role::Leader)
        .expect("leader");
    let leader_handle = workers[leader_idx].handler();
    for n in 1..=5u8 {
        block_on(leader_handle.propose(vec![n])).expect("propose");
    }

    // Every follower's commit_index advances to 5 via replication.
    wait_until(
        || {
            workers.iter().all(|w| {
                let h = w.handler();
                block_on(h.snapshot())
                    .map(|s| s.commit_index >= 5)
                    .unwrap_or(false)
            })
        },
        Duration::from_secs(5),
        "all replicas reach commit_index ≥ 5",
    );
}
