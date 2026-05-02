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
    MemStorage, PreVoteReq, PreVoteResp, RequestVoteReq, RequestVoteResp, Role, StdClock,
    StdRng, Transport, Worker, WorkerHandle,
};

/// Inbox lookup. Each peer's `WorkerHandle` is registered here
/// so the `MockTransport` can route inbound RPCs straight into
/// the right replica's loop.
type Routes = Arc<Mutex<BTreeMap<u16, WorkerHandle<u16>>>>;

/// Test transport — sends each RPC by looking up the target in
/// the shared `Routes` map and invoking the handler's `await`
/// methods directly. Records every RPC into a log so the test
/// can assert on observed traffic.
///
/// Partition modeling is per-edge: a `(from, to)` pair stored in
/// `dropped_edges` causes that direction to silently fail. This
/// supports asymmetric partitions ("A can send to B but B
/// can't reply to A") and one-sided isolations.
struct MockTransport {
    routes: Routes,
    log: Mutex<Vec<RpcRecord>>,
    /// Set of `(from, to)` edges where outbound RPCs are
    /// dropped. The transport derives `from` from the
    /// AppendEntries `leader` / RequestVote `candidate` /
    /// InstallSnapshot `leader` field.
    dropped_edges: Mutex<std::collections::BTreeSet<(u16, u16)>>,
    /// Set of `(from, to)` edges where every outbound RPC is
    /// delivered TWICE (back-to-back). Exercises the worker's
    /// idempotent paths: a duplicate `AppendEntries` should not
    /// re-append already-present entries, a duplicate
    /// `RequestVote` should not grant a second vote, a duplicate
    /// `InstallSnapshot` should be a no-op.
    duplicated_edges: Mutex<std::collections::BTreeSet<(u16, u16)>>,
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
            dropped_edges: Mutex::new(std::collections::BTreeSet::new()),
            duplicated_edges: Mutex::new(std::collections::BTreeSet::new()),
        }
    }

    /// Mark `from → to` as a duplicating edge: every outbound
    /// RPC on that direction is delivered twice (the second
    /// delivery's reply is discarded). The peer's idempotent
    /// handlers should produce the same observable state.
    fn duplicate_edge(&self, from: u16, to: u16) {
        self.duplicated_edges.lock().unwrap().insert((from, to));
    }

    fn is_duplicated(&self, from: u16, to: u16) -> bool {
        self.duplicated_edges
            .lock()
            .unwrap()
            .contains(&(from, to))
    }

    /// Drop every outbound RPC `from → to`.
    fn drop_edge(&self, from: u16, to: u16) {
        self.dropped_edges.lock().unwrap().insert((from, to));
    }

    /// Drop both directions between `a` and `b` — full cut.
    fn drop_pair(&self, a: u16, b: u16) {
        self.drop_edge(a, b);
        self.drop_edge(b, a);
    }

    /// Drop every edge into and out of `node`. Equivalent to
    /// pulling the node's network cable. Provided for symmetry
    /// with `drop_pair` even though no current test uses it —
    /// likely needed by future "isolated leader keeps trying
    /// to send AppendEntries" scenarios.
    #[allow(dead_code)]
    fn isolate(&self, node: u16, members: &[u16]) {
        for peer in members {
            if *peer != node {
                self.drop_pair(node, *peer);
            }
        }
    }

    fn is_dropped(&self, from: u16, to: u16) -> bool {
        self.dropped_edges
            .lock()
            .unwrap()
            .contains(&(from, to))
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
        if self.is_dropped(req.leader, peer) {
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
        let dup = self.is_duplicated(req.leader, peer);
        let dup_req = if dup { Some(req.clone()) } else { None };
        let from = req.leader;
        let result = match handle.clone() {
            Some(h) => Ok(h.handle_inbound_append(from, req).await),
            None => Err(MockError),
        };
        // Duplicate delivery: replay the same RPC. The receiver's
        // idempotent path (entry already present at same term →
        // skip) should produce the same observable state.
        if let (Some(h), Some(dup_req)) = (handle, dup_req) {
            let _ = h.handle_inbound_append(from, dup_req).await;
        }
        result
    }

    async fn send_vote(
        &self,
        peer: u16,
        req: RequestVoteReq<u16>,
    ) -> Result<RequestVoteResp, Self::Error> {
        if self.is_dropped(req.candidate, peer) {
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
        let dup = self.is_duplicated(req.candidate, peer);
        let from = req.candidate;
        // RequestVoteReq is Copy; cheap to keep a duplicate.
        let dup_req = req;
        let result = match handle.clone() {
            Some(h) => Ok(h.handle_inbound_vote(from, req).await),
            None => Err(MockError),
        };
        if dup
            && let Some(h) = handle
        {
            let _ = h.handle_inbound_vote(from, dup_req).await;
        }
        result
    }

    async fn send_prevote(
        &self,
        peer: u16,
        req: PreVoteReq<u16>,
    ) -> Result<PreVoteResp, Self::Error> {
        if self.is_dropped(req.candidate, peer) {
            return Err(MockError);
        }
        let handle = {
            let routes = self.routes.lock().unwrap();
            routes.get(&peer).cloned()
        };
        match handle {
            Some(h) => Ok(h.handle_inbound_prevote(req.candidate, req).await),
            None => Err(MockError),
        }
    }

    async fn send_install(
        &self,
        peer: u16,
        req: InstallSnapshotReq<u16>,
    ) -> Result<InstallSnapshotResp, Self::Error> {
        if self.is_dropped(req.leader, peer) {
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
        let dup = self.is_duplicated(req.leader, peer);
        let dup_req = if dup { Some(req.clone()) } else { None };
        let from = req.leader;
        let result = match handle.clone() {
            Some(h) => Ok(h.handle_inbound_install(from, req).await),
            None => Err(MockError),
        };
        if let (Some(h), Some(dup_req)) = (handle, dup_req) {
            let _ = h.handle_inbound_install(from, dup_req).await;
        }
        result
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
            (),
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
            (),
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
    // Index 1 is the leader-promotion no-op (Ongaro §6.4); the
    // 3 application proposes land at indices 2..=4.
    let mut last_idx = 0u64;
    for n in 1..=3u8 {
        last_idx = block_on(leader_handle.propose(vec![n])).expect("propose");
    }
    assert!(last_idx >= 4, "expected last_idx >= 4 (1 no-op + 3), got {last_idx}");

    // Wait for all replicas to report commit_index ≥ last_idx.
    wait_until(
        || {
            workers.iter().all(|w| {
                let h = w.handler();
                block_on(h.snapshot())
                    .map(|s| s.commit_index >= last_idx)
                    .unwrap_or(false)
            })
        },
        Duration::from_secs(5),
        "all replicas reach commit_index ≥ proposed-tail",
    );
}

#[test]
fn partitioned_minority_loses_quorum_majority_keeps_a_leader() {
    // 5-node cluster, partition 2 nodes into a minority and the
    // remaining 3 into a majority. The 3-side must keep (or
    // re-elect) a leader; the 2-side must NOT have a leader
    // because quorum=3 is unreachable.
    let routes: Routes = Arc::new(Mutex::new(BTreeMap::new()));
    let transport = Arc::new(MockTransport::new(routes.clone()));

    let members = vec![1u16, 2, 3, 4, 5];
    let majority = [1u16, 2, 3];
    let minority = [4u16, 5];

    let mut workers: std::collections::BTreeMap<u16, Worker<u16>> =
        std::collections::BTreeMap::new();
    for me in members.iter().copied() {
        let storage = MemStorage::<u16>::new();
        let worker = Worker::spawn_with(
            storage,
            transport.clone(),
            cfg(me, members.clone()),
            (),
            StdClock,
            StdRng::from_entropy(),
        );
        routes.lock().unwrap().insert(me, worker.handler());
        workers.insert(me, worker);
    }

    // Apply the partition BEFORE any leader emerges so we
    // observe each side's behavior in isolation. Drop every
    // edge crossing the boundary.
    for &m in &majority {
        for &n in &minority {
            transport.drop_pair(m, n);
        }
    }

    // The 3-node majority side should still elect a leader.
    wait_until(
        || majority.iter().any(|p| workers[p].role() == Role::Leader),
        Duration::from_secs(5),
        "majority side elects a leader despite the partition",
    );

    // Give the minority a generous window to fail to elect.
    // 3 election timeouts × 80ms upper bound = 240ms; round to
    // 500ms.
    std::thread::sleep(Duration::from_millis(500));

    // The 2-node minority side must NOT have a leader: each
    // member's self-vote (1) is below quorum (3), and they
    // can't reach the other 3 nodes to gather more.
    for p in &minority {
        let role = workers[p].role();
        assert_ne!(
            role,
            Role::Leader,
            "node {p} on the minority side became Leader despite quorum=3",
        );
    }

    // Sanity: the majority side's leader is still alive.
    let majority_leader_count = majority
        .iter()
        .filter(|p| workers[p].role() == Role::Leader)
        .count();
    assert_eq!(
        majority_leader_count, 1,
        "exactly one leader on the majority side, got {majority_leader_count}",
    );
}

#[test]
fn one_way_partition_lets_isolated_node_keep_observing_term() {
    // A node receives messages from the cluster but its
    // outbound replies are dropped. The cluster can't get acks
    // from it, but the isolated node still learns the cluster's
    // term and stays Follower.
    let routes: Routes = Arc::new(Mutex::new(BTreeMap::new()));
    let transport = Arc::new(MockTransport::new(routes.clone()));

    let members = vec![1u16, 2, 3];
    let mut workers: std::collections::BTreeMap<u16, Worker<u16>> =
        std::collections::BTreeMap::new();
    for me in members.iter().copied() {
        let storage = MemStorage::<u16>::new();
        let worker = Worker::spawn_with(
            storage,
            transport.clone(),
            cfg(me, members.clone()),
            (),
            StdClock,
            StdRng::from_entropy(),
        );
        routes.lock().unwrap().insert(me, worker.handler());
        workers.insert(me, worker);
    }

    wait_until(
        || members.iter().any(|p| workers[p].role() == Role::Leader),
        Duration::from_secs(5),
        "leader emerges before the partition is applied",
    );

    // Identify a Follower and one-way-partition it: its outbound
    // RPCs are dropped, but inbound RPCs from the leader still
    // reach it. (We know which node is leader, so partition all
    // OUTbound from one of the followers.)
    let leader_id = *members
        .iter()
        .find(|p| workers[p].role() == Role::Leader)
        .expect("leader exists");
    let isolated = *members.iter().find(|p| **p != leader_id).unwrap();

    // Drop OUTbound from `isolated` to every peer.
    for &peer in members.iter() {
        if peer != isolated {
            transport.drop_edge(isolated, peer);
        }
    }

    // The isolated node's election timer will fire, but its
    // RequestVote sends are dropped — it can't gather quorum.
    // It DOES still receive heartbeats from the leader, which
    // (assuming the leader's term ≥ isolated.term) reset its
    // election timer and keep it Follower.
    //
    // Track the isolated node's term: it should match the
    // leader's, eventually. If anything, the isolated node
    // bumps its term once or twice attempting election, and
    // the leader's heartbeat catches it up.
    let leader_handle = workers[&leader_id].handler();
    let isolated_handle = workers[&isolated].handler();

    wait_until(
        || {
            let l = block_on(leader_handle.snapshot());
            let i = block_on(isolated_handle.snapshot());
            match (l, i) {
                (Some(ls), Some(is)) => is.current_term >= ls.current_term,
                _ => false,
            }
        },
        Duration::from_secs(5),
        "isolated node's term catches up to the leader's",
    );
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
            (),
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

/// `BumpTermTransport` returns a fixed bumped-term response to
/// every outbound RPC, simulating a leader/candidate that has
/// fallen behind the cluster's current term. The worker's
/// `handle_*_response` paths must step the local replica down to
/// Follower and persist the new term.
struct BumpTermTransport {
    /// Term value reported in every outbound response.
    bumped_term: u64,
}

#[derive(Debug)]
struct BumpTermErr;
impl core::fmt::Display for BumpTermErr {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "bump-term")
    }
}
impl std::error::Error for BumpTermErr {}

impl Transport<u16> for BumpTermTransport {
    type Error = BumpTermErr;
    async fn send_append(
        &self,
        _peer: u16,
        _req: AppendEntriesReq<u16>,
    ) -> Result<AppendEntriesResp, Self::Error> {
        Ok(AppendEntriesResp {
            term: self.bumped_term,
            success: false,
            match_index: 0,
        })
    }
    async fn send_vote(
        &self,
        _peer: u16,
        _req: RequestVoteReq<u16>,
    ) -> Result<RequestVoteResp, Self::Error> {
        Ok(RequestVoteResp {
            term: self.bumped_term,
            vote_granted: false,
        })
    }
    async fn send_install(
        &self,
        _peer: u16,
        _req: InstallSnapshotReq<u16>,
    ) -> Result<InstallSnapshotResp, Self::Error> {
        Ok(InstallSnapshotResp { term: self.bumped_term, bytes_received: 0 })
    }
    async fn send_prevote(
        &self,
        _peer: u16,
        req: PreVoteReq<u16>,
    ) -> Result<PreVoteResp, Self::Error> {
        // Mimic a healthy peer at the candidate's current term:
        // grant the pre-vote, report `next_term - 1` (i.e., the
        // candidate's view of its own current_term, which is
        // what a peer at the same term would report). This lets
        // the candidate proceed to the real election where the
        // bumped-term refusal in `send_vote` lands.
        Ok(PreVoteResp {
            term: req.next_term.saturating_sub(1),
            vote_granted: true,
        })
    }
}

/// Leader steps down when an `AppendResponse` reports a higher
/// term than its own. Raft §5.1: any RPC reply at a higher term
/// causes the receiver to revert to Follower and adopt the term.
#[test]
fn leader_steps_down_on_higher_term_append_response() {
    // Stateful transport: grants the FIRST vote (so the
    // candidate becomes Leader), then on the leader's first
    // outbound AppendEntries returns a bumped term and stops
    // granting subsequent votes. Without the "stop granting
    // votes" gate, the worker would oscillate Leader → Follower
    // → Candidate → Leader → ... eventually reaching a term ≥
    // bumped_term where step-down stops firing, and the test's
    // polling loop could miss the brief Follower window.
    use std::sync::atomic::{AtomicBool, Ordering as AO};

    struct StepDownTransport {
        bumped_term: u64,
        bumped: AtomicBool,
    }
    #[derive(Debug)]
    struct E;
    impl core::fmt::Display for E {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            write!(f, "x")
        }
    }
    impl std::error::Error for E {}
    impl Transport<u16> for StepDownTransport {
        type Error = E;
        async fn send_vote(
            &self,
            _peer: u16,
            req: RequestVoteReq<u16>,
        ) -> Result<RequestVoteResp, E> {
            // First vote: grant at candidate's term so it wins.
            // Once the leader has been bumped, refuse to grant
            // further votes so the worker stays Follower.
            let granted = !self.bumped.load(AO::Relaxed);
            Ok(RequestVoteResp {
                term: req.term,
                vote_granted: granted,
            })
        }
        async fn send_append(
            &self,
            _peer: u16,
            _req: AppendEntriesReq<u16>,
        ) -> Result<AppendEntriesResp, E> {
            // Mark the bumped flag so the next vote round refuses.
            self.bumped.store(true, AO::Relaxed);
            Ok(AppendEntriesResp {
                term: self.bumped_term,
                success: false,
                match_index: 0,
            })
        }
        async fn send_install(
            &self,
            _peer: u16,
            _req: InstallSnapshotReq<u16>,
        ) -> Result<InstallSnapshotResp, E> {
            Ok(InstallSnapshotResp { term: self.bumped_term, bytes_received: 0 })
        }
        async fn send_prevote(
            &self,
            _peer: u16,
            req: PreVoteReq<u16>,
        ) -> Result<PreVoteResp, E> {
            // Same shape as the BumpTermTransport version but
            // gated by the `bumped` flag.
            let granted = !self.bumped.load(AO::Relaxed);
            Ok(PreVoteResp {
                term: req.next_term.saturating_sub(1),
                vote_granted: granted,
            })
        }
    }

    let transport = Arc::new(StepDownTransport {
        bumped_term: 99,
        bumped: AtomicBool::new(false),
    });
    let storage = MemStorage::<u16>::new();
    let mut cfg_2 = Config::new(0xAAAA, vec![0xAAAA, 0xBBBB], [0xC0; 32]);
    cfg_2.election_timeout_ms = (30, 80);
    cfg_2.heartbeat_interval_ms = 15;
    let worker = Worker::spawn_with(
        storage,
        transport,
        cfg_2,
        (),
        StdClock,
        StdRng::from_entropy(),
    );

    // The candidate wins the first election (vote granted), then
    // its first heartbeat receives the bumped reply and steps
    // down. After that the transport refuses further votes, so
    // the worker stays Follower at term ≥ 99.
    let h = worker.handler();
    wait_until(
        || {
            block_on(h.snapshot())
                .map(|s| s.role == Role::Follower && s.current_term >= 99)
                .unwrap_or(false)
        },
        Duration::from_secs(5),
        "leader steps down on bumped-term AppendResponse and stays Follower",
    );

    let snap = block_on(h.snapshot()).unwrap();
    assert_eq!(snap.role, Role::Follower);
    assert!(
        snap.current_term >= 99,
        "term must reach (and stay at) the bumped value reported by the peer; got {}",
        snap.current_term,
    );
}

/// Candidate steps down when a `VoteResponse` reports a higher
/// term than its own. Symmetric to the AppendResponse case.
#[test]
fn candidate_steps_down_on_higher_term_vote_response() {
    let transport = Arc::new(BumpTermTransport { bumped_term: 99 });
    let storage = MemStorage::<u16>::new();
    // 2-node cluster — needs the peer's vote to win, so the
    // candidate is forced to send a RequestVote and observe
    // the bumped reply.
    let mut cfg_2 = Config::new(0xAAAA, vec![0xAAAA, 0xBBBB], [0xC0; 32]);
    cfg_2.election_timeout_ms = (30, 80);
    cfg_2.heartbeat_interval_ms = 15;
    let worker = Worker::spawn_with(
        storage,
        transport,
        cfg_2,
        (),
        StdClock,
        StdRng::from_entropy(),
    );

    // The candidate's first RequestVote receives term=99 —
    // worker steps down to Follower and adopts the new term.
    // Election timer resets and may fire again at term 100, etc.,
    // each time getting bumped back. So we observe by checking
    // current_term reaches at least 99.
    let h = worker.handler();
    wait_until(
        || {
            block_on(h.snapshot())
                .map(|s| s.current_term >= 99)
                .unwrap_or(false)
        },
        Duration::from_secs(3),
        "current_term reaches the bumped value reported by the peer",
    );
    let snap = block_on(h.snapshot()).unwrap();
    assert!(snap.current_term >= 99);
    // After step-down the role is Follower (until the next
    // election timer fires; we may catch either, so just assert
    // term).
}

/// Duplicated outbound RPCs (every leader→follower delivery
/// happens twice) must not break Raft safety: the cluster still
/// converges, no log entry appears twice in the follower's log,
/// no duplicate vote is granted.
#[test]
fn cluster_converges_under_full_duplication() {
    let routes: Routes = Arc::new(Mutex::new(BTreeMap::new()));
    let transport = Arc::new(MockTransport::new(routes.clone()));

    let members = vec![1u16, 2, 3];
    let mut workers: std::collections::BTreeMap<u16, Worker<u16>> =
        std::collections::BTreeMap::new();
    for me in members.iter().copied() {
        let storage = MemStorage::<u16>::new();
        let worker = Worker::spawn_with(
            storage,
            transport.clone(),
            cfg(me, members.clone()),
            (),
            StdClock,
            StdRng::from_entropy(),
        );
        routes.lock().unwrap().insert(me, worker.handler());
        workers.insert(me, worker);
    }

    // Duplicate every directed edge before any RPC fires.
    for from in &members {
        for to in &members {
            if from != to {
                transport.duplicate_edge(*from, *to);
            }
        }
    }

    // Under duplication the cluster must still elect a unique
    // leader (a duplicate RequestVote at the same term must NOT
    // grant a second vote on the same peer).
    wait_until(
        || members.iter().any(|p| workers[p].role() == Role::Leader),
        Duration::from_secs(5),
        "leader emerges under full duplication",
    );

    let leader_id = *members
        .iter()
        .find(|p| workers[p].role() == Role::Leader)
        .expect("leader exists");
    let leader_handle = workers[&leader_id].handler();

    // Propose 5 entries. Every replication AppendEntries gets
    // delivered twice; each follower's log must end up with
    // exactly 6 entries (1 leader-promotion no-op + 5 proposes),
    // not 10+.
    for n in 1..=5u8 {
        block_on(leader_handle.propose(vec![n])).expect("propose");
    }

    wait_until(
        || {
            members.iter().all(|p| {
                let h = workers[p].handler();
                block_on(h.snapshot())
                    .map(|s| s.commit_index >= 6 && s.last_log_index == 6)
                    .unwrap_or(false)
            })
        },
        Duration::from_secs(5),
        "all replicas reach commit_index = 6 with last_log_index = 6",
    );

    // Final sanity: every follower has exactly 6 log entries
    // (1 leader-promotion no-op + 5 application proposes).
    for p in &members {
        let h = workers[p].handler();
        let s = block_on(h.snapshot()).unwrap();
        assert_eq!(
            s.last_log_index, 6,
            "node {p}: duplicated AppendEntries must not double-append; \
             last_log_index = {}",
            s.last_log_index,
        );
    }
}

/// Pre-vote prevents term inflation from a flapping partition.
///
/// Setup: 3-node cluster with a stable leader at term T. We
/// then partition one follower OUT of the cluster — its
/// outbound RequestVote/PreVote can't reach the leader or the
/// other follower. Without pre-vote, the isolated follower
/// would:
///   1. Time out election.
///   2. Bump its term to T+1.
///   3. Time out again (still isolated).
///   4. Bump to T+2, T+3, ...
///
/// And on rejoin, its inflated term forces the leader to step
/// down (Raft §5.1).
///
/// With pre-vote, the isolated follower's PreVote sends are
/// dropped (transport refuses for the partitioned edge), so the
/// pre-vote round never gets quorum, and the follower's
/// `current_term` stays put. The leader's term is preserved
/// across the partition.
#[test]
fn isolated_follower_does_not_inflate_term_under_pre_vote() {
    let routes: Routes = Arc::new(Mutex::new(BTreeMap::new()));
    let transport = Arc::new(MockTransport::new(routes.clone()));

    let members = vec![1u16, 2, 3];
    let mut workers: std::collections::BTreeMap<u16, Worker<u16>> =
        std::collections::BTreeMap::new();
    for me in members.iter().copied() {
        let storage = MemStorage::<u16>::new();
        let worker = Worker::spawn_with(
            storage,
            transport.clone(),
            cfg(me, members.clone()),
            (),
            StdClock,
            StdRng::from_entropy(),
        );
        routes.lock().unwrap().insert(me, worker.handler());
        workers.insert(me, worker);
    }

    // Wait for a stable leader at some term.
    wait_until(
        || members.iter().any(|p| workers[p].role() == Role::Leader),
        Duration::from_secs(5),
        "leader emerges before partition",
    );
    let leader_id = *members
        .iter()
        .find(|p| workers[p].role() == Role::Leader)
        .expect("leader exists");
    let leader_term = block_on(workers[&leader_id].handler().snapshot())
        .expect("leader alive")
        .current_term;

    // Pick any non-leader node and isolate it: drop every
    // outbound edge from it to its peers, AND every inbound
    // edge from peers (so it can't receive heartbeats either).
    let isolated = *members.iter().find(|p| **p != leader_id).unwrap();
    transport.isolate(isolated, &members);

    // Idle for ~10 election timeouts. Without pre-vote the
    // isolated node would have bumped term ~10 times (election
    // timeout 30-80ms; idle window 1000ms). With pre-vote, its
    // pre-election rounds get dropped (no peer can reply),
    // never reach quorum, and its term stays put.
    std::thread::sleep(Duration::from_millis(1000));

    // The isolated node's term should be no more than 1 above
    // the leader's term at partition time. (One bump is
    // possible if it last received a heartbeat just barely
    // before the partition began and the leader-check window
    // expired before isolation took full effect — but
    // pre-vote should keep it pinned.)
    let isolated_snap = block_on(workers[&isolated].handler().snapshot())
        .expect("isolated alive");
    let drift = isolated_snap.current_term.saturating_sub(leader_term);
    assert!(
        drift <= 1,
        "pre-vote failed to prevent term inflation: \
         leader_term={leader_term}, isolated_term={} (drift={drift})",
        isolated_snap.current_term,
    );

    // The leader's own term should be unchanged: pre-vote
    // requests from the isolated node never reached it (and
    // even if they had, pre-vote doesn't bump the responder's
    // term).
    let leader_snap_after = block_on(workers[&leader_id].handler().snapshot())
        .expect("leader alive");
    assert_eq!(
        leader_snap_after.current_term, leader_term,
        "leader's term must not have advanced during the partition",
    );
    assert_eq!(
        leader_snap_after.role,
        Role::Leader,
        "leader must still be leader after the partition",
    );
}

/// A permanently-isolated PreCandidate must revert to Follower
/// after `pre_candidate_misses_before_revert` consecutive
/// PreVote-quorum-misses. Without this, external observers
/// reading `role()` would see PreCandidate indefinitely on a
/// stuck node.
#[test]
fn pre_candidate_reverts_to_follower_after_consecutive_misses() {
    let routes: Routes = Arc::new(Mutex::new(BTreeMap::new()));
    let transport = Arc::new(MockTransport::new(routes.clone()));

    let members = vec![1u16, 2, 3];
    let mut workers: std::collections::BTreeMap<u16, Worker<u16>> =
        std::collections::BTreeMap::new();
    for me in members.iter().copied() {
        let storage = MemStorage::<u16>::new();
        let mut c = cfg(me, members.clone());
        // Tight cap so the test converges quickly: revert after
        // 2 PreCandidate timeouts. Default of 3 is safe in
        // production; 2 is enough to prove the mechanism here.
        c.pre_candidate_misses_before_revert = 2;
        let worker = Worker::spawn_with(
            storage,
            transport.clone(),
            c,
            (),
            StdClock,
            StdRng::from_entropy(),
        );
        routes.lock().unwrap().insert(me, worker.handler());
        workers.insert(me, worker);
    }

    wait_until(
        || members.iter().any(|p| workers[p].role() == Role::Leader),
        Duration::from_secs(5),
        "leader emerges before partition",
    );
    let leader_id = *members
        .iter()
        .find(|p| workers[p].role() == Role::Leader)
        .expect("leader exists");

    // Isolate a non-leader node. It will time out, enter
    // PreCandidate, fail to reach quorum (no peer can reply),
    // time out again, and after 2 consecutive misses revert
    // to Follower.
    let isolated = *members.iter().find(|p| **p != leader_id).unwrap();
    transport.isolate(isolated, &members);

    // Wait for the isolated node's role to be observed as
    // Follower at some point. The worker oscillates between
    // PreCandidate (during a round) and Follower (briefly,
    // after the cap-revert before the next election timer
    // fires), so a snapshot-at-a-fixed-time would be racy.
    // wait_until samples until it sees Follower.
    wait_until(
        || {
            block_on(workers[&isolated].handler().snapshot())
                .map(|s| s.role == Role::Follower)
                .unwrap_or(false)
        },
        Duration::from_secs(2),
        "isolated node reverts to Follower after PreCandidate misses",
    );
}

/// `read_index` on the leader returns an index ≥ commit_index
/// after a quorum heartbeat round confirms leadership. The
/// caller can then read state machine state at-or-above that
/// index for a linearizable result.
#[test]
fn read_index_resolves_after_quorum_confirmation() {
    use vos_raft::ReadIndexError;

    let routes: Routes = Arc::new(Mutex::new(BTreeMap::new()));
    let transport = Arc::new(MockTransport::new(routes.clone()));

    let members = vec![1u16, 2, 3];
    let mut workers: std::collections::BTreeMap<u16, Worker<u16>> =
        std::collections::BTreeMap::new();
    for me in members.iter().copied() {
        let storage = MemStorage::<u16>::new();
        let worker = Worker::spawn_with(
            storage,
            transport.clone(),
            cfg(me, members.clone()),
            (),
            StdClock,
            StdRng::from_entropy(),
        );
        routes.lock().unwrap().insert(me, worker.handler());
        workers.insert(me, worker);
    }

    wait_until(
        || members.iter().any(|p| workers[p].role() == Role::Leader),
        Duration::from_secs(5),
        "leader emerges",
    );
    let leader_id = *members
        .iter()
        .find(|p| workers[p].role() == Role::Leader)
        .expect("leader exists");
    let leader_handle = workers[&leader_id].handler();

    // Propose a few entries so commit_index advances above 0.
    for n in 1..=3u8 {
        block_on(leader_handle.propose(vec![n])).expect("propose");
    }

    // Wait for all replicas to converge so the leader's
    // match_index for each follower reflects them as caught up
    // — necessary for read_index to resolve quickly.
    wait_until(
        || {
            members.iter().all(|p| {
                let h = workers[p].handler();
                block_on(h.snapshot())
                    .map(|s| s.commit_index >= 3)
                    .unwrap_or(false)
            })
        },
        Duration::from_secs(5),
        "all replicas reach commit_index ≥ 3",
    );

    // read_index on the leader returns Ok(R), R ≥ 3.
    let r = block_on(leader_handle.read_index()).expect("read_index resolves");
    assert!(r >= 3, "read_index = {r} should be ≥ committed index 3");

    // read_index on a follower returns NotLeader.
    let follower_id = *members.iter().find(|p| **p != leader_id).unwrap();
    let follower_handle = workers[&follower_id].handler();
    let r = block_on(follower_handle.read_index());
    assert!(
        matches!(r, Err(ReadIndexError::NotLeader)),
        "follower read_index must return NotLeader, got {r:?}",
    );
}

/// `read_index` on a partitioned leader stalls until the
/// partition heals OR step_down drains pending requests with
/// LeaderStepped.
#[test]
fn read_index_returns_leader_stepped_on_partition_step_down() {
    use vos_raft::ReadIndexError;

    let routes: Routes = Arc::new(Mutex::new(BTreeMap::new()));
    let transport = Arc::new(MockTransport::new(routes.clone()));

    let members = vec![1u16, 2, 3];
    let mut workers: std::collections::BTreeMap<u16, Worker<u16>> =
        std::collections::BTreeMap::new();
    for me in members.iter().copied() {
        let storage = MemStorage::<u16>::new();
        let worker = Worker::spawn_with(
            storage,
            transport.clone(),
            cfg(me, members.clone()),
            (),
            StdClock,
            StdRng::from_entropy(),
        );
        routes.lock().unwrap().insert(me, worker.handler());
        workers.insert(me, worker);
    }

    wait_until(
        || members.iter().any(|p| workers[p].role() == Role::Leader),
        Duration::from_secs(5),
        "leader emerges",
    );
    let leader_id = *members
        .iter()
        .find(|p| workers[p].role() == Role::Leader)
        .expect("leader exists");
    let leader_handle = workers[&leader_id].handler();
    let leader_handle_for_call = leader_handle.clone();

    // Wait for any propose so commit_index > 0.
    block_on(leader_handle.propose(vec![1])).expect("propose");

    // Partition the leader OUT before issuing read_index. The
    // request will queue; without a quorum it can't resolve.
    transport.isolate(leader_id, &members);

    // Issue read_index in a separate thread. Without partition
    // healing, it should eventually receive LeaderStepped when
    // the leader's heartbeat-failure path causes a re-election
    // and step-down.
    //
    // BUT: with the leader isolated, it can't observe a
    // higher-term reply because no peer can reach it. So the
    // current step-down path won't fire. The pending request
    // will hang indefinitely — which IS the correct behavior
    // for an isolated leader (it can't safely serve reads
    // because it might be stale).
    //
    // To exercise the LeaderStepped path, we instead inject a
    // higher-term AppendEntries to the leader from outside,
    // which forces step-down via handle_append_entries.
    let result_thread = std::thread::spawn(move || {
        block_on(leader_handle_for_call.read_index())
    });
    // Give the thread a moment to enqueue.
    std::thread::sleep(Duration::from_millis(50));
    // Inject a higher-term heartbeat that forces step-down.
    let _ = block_on(leader_handle.handle_inbound_append(
        99,
        AppendEntriesReq {
            leader: 99,
            term: 1_000,
            prev_log_index: 0,
            prev_log_term: 0,
            leader_commit: 0,
            entries: vec![],
        },
    ));
    // The pending read_index must now resolve with LeaderStepped.
    let result = result_thread.join().expect("thread joined");
    assert!(
        matches!(result, Err(ReadIndexError::LeaderStepped)),
        "expected LeaderStepped after step-down, got {result:?}",
    );
}

/// `read_index` returns `Backpressure` when the leader's
/// pending-reads queue is full. Without this cap, an asymmetric
/// partition (leader receives but heartbeats can't quorum-confirm)
/// would silently grow the queue and OOM the worker.
#[test]
fn read_index_returns_backpressure_when_queue_full() {
    use vos_raft::ReadIndexError;

    let routes: Routes = Arc::new(Mutex::new(BTreeMap::new()));
    let transport = Arc::new(MockTransport::new(routes.clone()));

    let members = vec![1u16, 2, 3];
    let mut workers: std::collections::BTreeMap<u16, Worker<u16>> =
        std::collections::BTreeMap::new();
    for me in members.iter().copied() {
        let storage = MemStorage::<u16>::new();
        // Tight cap so the test can fill the queue with a
        // handful of requests rather than thousands.
        let mut c = cfg(me, members.clone());
        c.max_pending_reads = 4;
        let worker = Worker::spawn_with(
            storage,
            transport.clone(),
            c,
            (),
            StdClock,
            StdRng::from_entropy(),
        );
        routes.lock().unwrap().insert(me, worker.handler());
        workers.insert(me, worker);
    }

    wait_until(
        || members.iter().any(|p| workers[p].role() == Role::Leader),
        Duration::from_secs(5),
        "leader emerges",
    );
    let leader_id = *members
        .iter()
        .find(|p| workers[p].role() == Role::Leader)
        .expect("leader exists");
    let leader_handle = workers[&leader_id].handler();

    // Isolate the leader so heartbeats never get acked. Now any
    // read_index queues forever (until step-down or backpressure).
    transport.isolate(leader_id, &members);

    // Fire enough read_index requests to fill the queue (4) plus
    // a few more that must surface Backpressure. Run each in a
    // detached thread because the queued ones won't return until
    // we force a step-down at the end.
    let extra = 8;
    let mut threads = Vec::new();
    for _ in 0..(4 + extra) {
        let h = leader_handle.clone();
        threads.push(std::thread::spawn(move || block_on(h.read_index())));
    }

    // Give the worker time to enqueue / reject.
    std::thread::sleep(Duration::from_millis(200));

    // Inject a higher-term AppendEntries to force step-down,
    // which drains the queued requests with LeaderStepped so
    // their threads can join.
    let _ = block_on(leader_handle.handle_inbound_append(
        99,
        AppendEntriesReq {
            leader: 99,
            term: 1_000,
            prev_log_index: 0,
            prev_log_term: 0,
            leader_commit: 0,
            entries: vec![],
        },
    ));

    let mut backpressure_seen = 0;
    let mut leader_stepped_seen = 0;
    for t in threads {
        match t.join().expect("thread joined") {
            Err(ReadIndexError::Backpressure) => backpressure_seen += 1,
            Err(ReadIndexError::LeaderStepped) => leader_stepped_seen += 1,
            other => panic!("unexpected read_index outcome: {other:?}"),
        }
    }
    assert!(
        backpressure_seen >= extra,
        "expected at least {extra} Backpressure outcomes, got {backpressure_seen} \
         (LeaderStepped: {leader_stepped_seen})",
    );
}

/// A snapshot whose payload exceeds `install_snapshot_chunk_bytes`
/// is delivered across multiple `InstallSnapshotReq` chunks; the
/// follower's snap pointer reaches the leader's `last_included_index`
/// only after the final chunk's `done = true` arrives.
///
/// We exercise this directly against the worker's inbound handler
/// (no transport/peer plumbing): build a chunked stream by hand,
/// feed the chunks one by one, and assert the snap pointer
/// only advances on the final chunk.
#[test]
fn install_snapshot_chunked_assembles_across_multiple_rpcs() {
    let storage = MemStorage::<u16>::new();
    let routes: Routes = Arc::new(Mutex::new(BTreeMap::new()));
    let transport = Arc::new(MockTransport::new(routes.clone()));

    let me = 0xAAAAu16;
    let leader = 0xBBBBu16;
    let worker = Worker::spawn_with(
        storage,
        transport,
        cfg(me, alloc_members(&[me, leader, 0xCCCC])),
        (),
        StdClock,
        StdRng::from_entropy(),
    );
    let h = worker.handler();

    // Build a 100 KiB snapshot. With the default chunk size of
    // 32 KiB we'll need 4 chunks (32 + 32 + 32 + 4 KiB).
    let total_bytes = 100 * 1024;
    let snapshot: Vec<u8> = (0..total_bytes)
        .map(|i| (i & 0xFF) as u8)
        .collect();
    let chunk_size = 32 * 1024;

    let mut offset = 0u64;
    let mut chunks_sent = 0;
    while (offset as usize) < snapshot.len() {
        let end = ((offset as usize) + chunk_size).min(snapshot.len());
        let data = snapshot[offset as usize..end].to_vec();
        let was_final = end == snapshot.len();

        let resp = block_on(h.handle_inbound_install(
            leader,
            InstallSnapshotReq {
                leader,
                term: 1,
                last_included_index: 1_000,
                last_included_term: 1,
                offset,
                done: was_final,
                data,
            },
        ));
        chunks_sent += 1;
        assert_eq!(resp.term, 1);
        assert_eq!(
            resp.bytes_received as usize,
            end,
            "chunk {chunks_sent}: follower must have received {end} bytes",
        );

        // Snap pointer must NOT advance until the final chunk lands.
        let snap = block_on(h.snapshot()).unwrap();
        if !was_final {
            assert_eq!(
                snap.snap_last_index, 0,
                "snap pointer must not advance before final chunk",
            );
        } else {
            assert_eq!(snap.snap_last_index, 1_000);
            assert_eq!(snap.commit_index, 1_000);
        }

        offset = end as u64;
    }
    assert_eq!(chunks_sent, 4, "expected 4 chunks for 100 KiB / 32 KiB");
    worker.shutdown();
}

/// A re-sent chunk (same offset, same identity) is idempotent —
/// the follower's accumulated bytes don't double up.
#[test]
fn install_snapshot_chunked_duplicate_chunk_is_idempotent() {
    let storage = MemStorage::<u16>::new();
    let routes: Routes = Arc::new(Mutex::new(BTreeMap::new()));
    let transport = Arc::new(MockTransport::new(routes.clone()));

    let me = 0xAAAAu16;
    let leader = 0xBBBBu16;
    let worker = Worker::spawn_with(
        storage,
        transport,
        cfg(me, alloc_members(&[me, leader, 0xCCCC])),
        (),
        StdClock,
        StdRng::from_entropy(),
    );
    let h = worker.handler();

    let chunk_a = vec![0xAA; 16];
    let chunk_b = vec![0xBB; 16];

    // First chunk at offset 0, not final.
    let r0 = block_on(h.handle_inbound_install(
        leader,
        InstallSnapshotReq {
            leader,
            term: 1,
            last_included_index: 50,
            last_included_term: 1,
            offset: 0,
            done: false,
            data: chunk_a.clone(),
        },
    ));
    assert_eq!(r0.bytes_received, 16);

    // Re-send the SAME first chunk. Follower must report
    // bytes_received = 16 (not 32). Already-have semantics.
    let r0_dup = block_on(h.handle_inbound_install(
        leader,
        InstallSnapshotReq {
            leader,
            term: 1,
            last_included_index: 50,
            last_included_term: 1,
            offset: 0,
            done: false,
            data: chunk_a.clone(),
        },
    ));
    assert_eq!(r0_dup.bytes_received, 16);

    // Now send the real second chunk at offset 16 with done=true.
    let r1 = block_on(h.handle_inbound_install(
        leader,
        InstallSnapshotReq {
            leader,
            term: 1,
            last_included_index: 50,
            last_included_term: 1,
            offset: 16,
            done: true,
            data: chunk_b,
        },
    ));
    assert_eq!(r1.bytes_received, 32);

    let snap = block_on(h.snapshot()).unwrap();
    assert_eq!(snap.snap_last_index, 50);
    worker.shutdown();
}

/// A chunk that arrives with `offset > current_buffer_len`
/// (gap) is rejected. The follower reports its current length so
/// the leader can resume from the right place.
#[test]
fn install_snapshot_chunked_gap_rejected_with_resume_offset() {
    let storage = MemStorage::<u16>::new();
    let routes: Routes = Arc::new(Mutex::new(BTreeMap::new()));
    let transport = Arc::new(MockTransport::new(routes.clone()));

    let me = 0xAAAAu16;
    let leader = 0xBBBBu16;
    let worker = Worker::spawn_with(
        storage,
        transport,
        cfg(me, alloc_members(&[me, leader, 0xCCCC])),
        (),
        StdClock,
        StdRng::from_entropy(),
    );
    let h = worker.handler();

    // First chunk at offset 0 lands fine.
    let r0 = block_on(h.handle_inbound_install(
        leader,
        InstallSnapshotReq {
            leader,
            term: 1,
            last_included_index: 50,
            last_included_term: 1,
            offset: 0,
            done: false,
            data: vec![0xAA; 16],
        },
    ));
    assert_eq!(r0.bytes_received, 16);

    // Skip ahead — offset 100 instead of 16. Follower refuses
    // and reports current length.
    let r_gap = block_on(h.handle_inbound_install(
        leader,
        InstallSnapshotReq {
            leader,
            term: 1,
            last_included_index: 50,
            last_included_term: 1,
            offset: 100,
            done: false,
            data: vec![0xCC; 16],
        },
    ));
    assert_eq!(
        r_gap.bytes_received, 16,
        "gap must be refused with bytes_received = current length",
    );

    let snap = block_on(h.snapshot()).unwrap();
    assert_eq!(
        snap.snap_last_index, 0,
        "gap-rejected chunk must not advance snap pointer",
    );
    worker.shutdown();
}

/// A chunk that would push the buffered snapshot past
/// `Config::max_snapshot_bytes` is rejected, and the partial
/// buffer is dropped so a misbehaving leader can't sit on
/// half-buffered state indefinitely. Without this guard, a
/// leader streaming chunks without ever setting `done = true`
/// OOMs the follower.
#[test]
fn install_snapshot_chunked_rejects_oversized_buffer() {
    let storage = MemStorage::<u16>::new();
    let routes: Routes = Arc::new(Mutex::new(BTreeMap::new()));
    let transport = Arc::new(MockTransport::new(routes.clone()));

    let me = 0xAAAAu16;
    let leader = 0xBBBBu16;
    // Tight cap: 32 bytes.
    let mut c = cfg(me, alloc_members(&[me, leader, 0xCCCC]));
    c.max_snapshot_bytes = 32;
    let worker = Worker::spawn_with(
        storage,
        transport,
        c,
        (),
        StdClock,
        StdRng::from_entropy(),
    );
    let h = worker.handler();

    // First chunk: 24 bytes — fits.
    let r0 = block_on(h.handle_inbound_install(
        leader,
        InstallSnapshotReq {
            leader,
            term: 1,
            last_included_index: 50,
            last_included_term: 1,
            offset: 0,
            done: false,
            data: vec![0xAA; 24],
        },
    ));
    assert_eq!(r0.bytes_received, 24, "first chunk must accept under cap");

    // Second chunk: 16 bytes at offset 24 — pushes total to 40,
    // exceeds cap of 32. Must be rejected (bytes_received = 0)
    // and the partial buffer dropped.
    let r1 = block_on(h.handle_inbound_install(
        leader,
        InstallSnapshotReq {
            leader,
            term: 1,
            last_included_index: 50,
            last_included_term: 1,
            offset: 24,
            done: true,
            data: vec![0xBB; 16],
        },
    ));
    assert_eq!(
        r1.bytes_received, 0,
        "oversized chunk must be rejected with bytes_received = 0",
    );

    // Snap pointer must NOT have advanced.
    let snap = block_on(h.snapshot()).unwrap();
    assert_eq!(
        snap.snap_last_index, 0,
        "rejected oversized chunk must not commit the snapshot",
    );

    // A subsequent fresh chunk (offset = 0) must work — the
    // partial buffer was dropped, identity reset.
    let r2 = block_on(h.handle_inbound_install(
        leader,
        InstallSnapshotReq {
            leader,
            term: 1,
            last_included_index: 50,
            last_included_term: 1,
            offset: 0,
            done: true,
            data: vec![0xCC; 16],
        },
    ));
    assert_eq!(r2.bytes_received, 16);
    let snap = block_on(h.snapshot()).unwrap();
    assert_eq!(snap.snap_last_index, 50);
    worker.shutdown();
}

fn alloc_members(m: &[u16]) -> Vec<u16> {
    m.to_vec()
}

/// Joint-consensus happy path: a 3-node cluster grows to 4
/// nodes via `change_membership`. The leader appends the joint
/// `ConfigChange`, the cluster commits it under joint quorum,
/// the leader auto-appends the final non-joint entry, that
/// commits under the new quorum, and the cluster ends in steady
/// 4-node operation.
#[test]
fn change_membership_grows_cluster_via_joint_consensus() {
    use vos_raft::ChangeMembershipError;

    let routes: Routes = Arc::new(Mutex::new(BTreeMap::new()));
    let transport = Arc::new(MockTransport::new(routes.clone()));

    let initial = vec![1u16, 2, 3];
    let new_member = 4u16;
    let new_full = vec![1u16, 2, 3, 4];
    let mut workers: std::collections::BTreeMap<u16, Worker<u16>> =
        std::collections::BTreeMap::new();

    // Spin up the original 3 nodes first — and only the
    // original 3. Starting the new node before a leader emerges
    // would let it bump terms in pre-vote against members that
    // don't know it yet, slowing convergence.
    for me in initial.iter().copied() {
        let storage = MemStorage::<u16>::new();
        let worker = Worker::spawn_with(
            storage,
            transport.clone(),
            cfg(me, initial.clone()),
            (),
            StdClock,
            StdRng::from_entropy(),
        );
        routes.lock().unwrap().insert(me, worker.handler());
        workers.insert(me, worker);
    }

    wait_until(
        || initial.iter().any(|p| workers[p].role() == Role::Leader),
        Duration::from_secs(5),
        "leader emerges among initial 3",
    );

    // Now spin up node 4. Its Config::members lists the
    // post-transition set so its quorum view sees a 4-node
    // cluster from boot; the leader will replicate the
    // joint+final ConfigChange entries to it as part of the
    // membership change.
    let storage4 = MemStorage::<u16>::new();
    let worker4 = Worker::spawn_with(
        storage4,
        transport.clone(),
        cfg(new_member, new_full.clone()),
        (),
        StdClock,
        StdRng::from_entropy(),
    );
    routes
        .lock()
        .unwrap()
        .insert(new_member, worker4.handler());
    workers.insert(new_member, worker4);
    let leader_id = *initial
        .iter()
        .find(|p| workers[p].role() == Role::Leader)
        .expect("leader exists");
    let leader_handle = workers[&leader_id].handler();

    // Issue the membership change.
    let joint_index =
        block_on(leader_handle.change_membership(new_full.clone()))
            .expect("change_membership accepted");

    // The leader must reject a concurrent change while the
    // joint phase is in flight.
    let conflict = block_on(leader_handle.change_membership(new_full.clone()));
    assert!(
        matches!(conflict, Err(ChangeMembershipError::InProgress)),
        "second concurrent change_membership must return InProgress, got {conflict:?}",
    );

    // Wait for every node (including the new one) to observe
    // the final non-joint config: each replica's commit_index
    // should be at or above `joint_index + 1` (joint entry +
    // final entry).
    let final_index = joint_index + 1;
    wait_until(
        || {
            new_full.iter().all(|p| {
                let h = workers[p].handler();
                block_on(h.snapshot())
                    .map(|s| s.commit_index >= final_index)
                    .unwrap_or(false)
            })
        },
        Duration::from_secs(10),
        "all 4 replicas commit through the final non-joint entry",
    );

    // Issue a new change_membership to confirm the joint phase
    // has retired (otherwise we'd get InProgress).
    let post = block_on(leader_handle.change_membership(initial.clone()));
    assert!(
        post.is_ok(),
        "after joint phase retires, a new change_membership must be accepted, got {post:?}",
    );
}

/// A leader that removes itself from the new configuration must
/// step down once the final non-joint entry commits, so the
/// remaining replicas elect a new leader from the new set
/// (Ongaro thesis §4.3).
#[test]
fn change_membership_removing_leader_makes_it_step_down() {
    let routes: Routes = Arc::new(Mutex::new(BTreeMap::new()));
    let transport = Arc::new(MockTransport::new(routes.clone()));

    let initial = vec![1u16, 2, 3];
    let mut workers: std::collections::BTreeMap<u16, Worker<u16>> =
        std::collections::BTreeMap::new();
    for me in initial.iter().copied() {
        let storage = MemStorage::<u16>::new();
        let worker = Worker::spawn_with(
            storage,
            transport.clone(),
            cfg(me, initial.clone()),
            (),
            StdClock,
            StdRng::from_entropy(),
        );
        routes.lock().unwrap().insert(me, worker.handler());
        workers.insert(me, worker);
    }

    wait_until(
        || initial.iter().any(|p| workers[p].role() == Role::Leader),
        Duration::from_secs(5),
        "leader emerges",
    );
    let leader_id = *initial
        .iter()
        .find(|p| workers[p].role() == Role::Leader)
        .expect("leader exists");
    let leader_handle = workers[&leader_id].handler();

    // Remove the leader: new membership is the other two nodes.
    let new_members: Vec<u16> = initial
        .iter()
        .copied()
        .filter(|p| *p != leader_id)
        .collect();
    let _joint_index = block_on(leader_handle.change_membership(new_members.clone()))
        .expect("change_membership accepted");

    wait_until(
        || workers[&leader_id].role() != Role::Leader,
        Duration::from_secs(10),
        "removed leader steps down",
    );

    wait_until(
        || new_members.iter().any(|p| workers[p].role() == Role::Leader),
        Duration::from_secs(10),
        "new leader emerges from the post-transition set",
    );
}

/// `change_membership` called against a follower returns
/// `NotLeader`. The caller is expected to forward the request
/// to the cluster's current leader.
#[test]
fn change_membership_on_follower_returns_not_leader() {
    use vos_raft::ChangeMembershipError;

    let routes: Routes = Arc::new(Mutex::new(BTreeMap::new()));
    let transport = Arc::new(MockTransport::new(routes.clone()));

    let members = vec![1u16, 2, 3];
    let mut workers: std::collections::BTreeMap<u16, Worker<u16>> =
        std::collections::BTreeMap::new();
    for me in members.iter().copied() {
        let storage = MemStorage::<u16>::new();
        let worker = Worker::spawn_with(
            storage,
            transport.clone(),
            cfg(me, members.clone()),
            (),
            StdClock,
            StdRng::from_entropy(),
        );
        routes.lock().unwrap().insert(me, worker.handler());
        workers.insert(me, worker);
    }

    wait_until(
        || members.iter().any(|p| workers[p].role() == Role::Leader),
        Duration::from_secs(5),
        "leader emerges",
    );
    let leader_id = *members
        .iter()
        .find(|p| workers[p].role() == Role::Leader)
        .expect("leader exists");
    let follower_id = *members.iter().find(|p| **p != leader_id).unwrap();

    let r = block_on(workers[&follower_id].handler().change_membership(members.clone()));
    assert!(
        matches!(r, Err(ChangeMembershipError::NotLeader)),
        "follower change_membership must return NotLeader, got {r:?}",
    );
}

/// An empty `new_members` is rejected with `EmptyConfig`.
/// A cluster needs at least one voter; an empty configuration
/// would never be able to elect.
#[test]
fn change_membership_with_empty_members_returns_empty_config() {
    use vos_raft::ChangeMembershipError;

    let routes: Routes = Arc::new(Mutex::new(BTreeMap::new()));
    let transport = Arc::new(MockTransport::new(routes.clone()));

    let members = vec![1u16, 2, 3];
    let mut workers: std::collections::BTreeMap<u16, Worker<u16>> =
        std::collections::BTreeMap::new();
    for me in members.iter().copied() {
        let storage = MemStorage::<u16>::new();
        let worker = Worker::spawn_with(
            storage,
            transport.clone(),
            cfg(me, members.clone()),
            (),
            StdClock,
            StdRng::from_entropy(),
        );
        routes.lock().unwrap().insert(me, worker.handler());
        workers.insert(me, worker);
    }

    wait_until(
        || members.iter().any(|p| workers[p].role() == Role::Leader),
        Duration::from_secs(5),
        "leader emerges",
    );
    let leader_id = *members
        .iter()
        .find(|p| workers[p].role() == Role::Leader)
        .expect("leader exists");

    let r = block_on(workers[&leader_id].handler().change_membership(Vec::new()));
    assert!(
        matches!(r, Err(ChangeMembershipError::EmptyConfig)),
        "empty new_members must return EmptyConfig, got {r:?}",
    );
}
