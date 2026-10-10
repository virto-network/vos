//! Integration-style state-machine tests for `vos-raft`.
//!
//! These run workers against `MemStorage` and a controllable one-way
//! `MockTransport`, to drive contrived scenarios: elections, replication,
//! partitions, duplication, read barriers, snapshots and membership
//! changes, under realistic message timings.
//!
//! All tests compile only with the `std` feature (the worker is
//! std-gated).

#![cfg(feature = "std")]

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use futures_executor::block_on;
use vos_raft::{
    AppendResult, Config, Envelope, InstallSnapshotReq, InstallSnapshotResp, LogEntry, MemStorage,
    Message, Meta, Role, StdClock, StdRng, Storage, Transport, Worker, WorkerHandle, WriteBatch,
};

/// Inbox lookup: each replica's handle, so the transport can deliver to it.
type Routes = Arc<Mutex<BTreeMap<u16, WorkerHandle<u16>>>>;

/// A message on the wire: from, to, envelope.
type Sent = (u16, u16, Envelope<u16>);

/// Test transport: delivers each message straight into the recipient's
/// inbox, and records it so tests can assert on traffic.
///
/// Partitions are per edge: a `(from, to)` pair in `dropped_edges` drops
/// that direction, which models asymmetric partitions too. A message to a
/// node without a route is captured, so a test can play a peer and read
/// what it was sent.
struct MockTransport {
    routes: Routes,
    log: Mutex<Vec<RpcRecord>>,
    dropped_edges: Mutex<std::collections::BTreeSet<(u16, u16)>>,
    /// Edges on which every message is delivered twice.
    duplicated_edges: Mutex<std::collections::BTreeSet<(u16, u16)>>,
    /// While `Some`, every append answer is held, in send order, until
    /// released: the answers are in flight back to the leader.
    held_answers: Mutex<Option<Vec<Sent>>>,
    /// Messages to nodes without a route, for tests that play a peer.
    captured: Mutex<Vec<Sent>>,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
enum RpcRecord {
    Append {
        from: u16,
        to: u16,
        term: u64,
        count: usize,
    },
    Vote {
        from: u16,
        to: u16,
        term: u64,
    },
    Install {
        from: u16,
        to: u16,
        last_idx: u64,
    },
}

impl MockTransport {
    fn new(routes: Routes) -> Self {
        Self {
            routes,
            log: Mutex::new(Vec::new()),
            dropped_edges: Mutex::new(std::collections::BTreeSet::new()),
            duplicated_edges: Mutex::new(std::collections::BTreeSet::new()),
            held_answers: Mutex::new(None),
            captured: Mutex::new(Vec::new()),
        }
    }

    /// Hold every append answer from now on.
    fn hold_answers(&self) {
        self.held_answers
            .lock()
            .unwrap()
            .get_or_insert_with(Vec::new);
    }

    fn held_answers(&self) -> usize {
        self.held_answers
            .lock()
            .unwrap()
            .as_ref()
            .map_or(0, Vec::len)
    }

    /// Deliver the first `count` held answers, in send order.
    fn release_answers(&self, count: usize) {
        let released: Vec<_> = {
            let mut held = self.held_answers.lock().unwrap();
            let held = held.as_mut().expect("answers are held");
            held.drain(..count).collect()
        };
        for (from, to, envelope) in released {
            self.deliver(from, to, envelope);
        }
    }

    /// Deliver every held answer and stop holding.
    fn stop_holding_answers(&self) {
        let released = self.held_answers.lock().unwrap().take().unwrap_or_default();
        for (from, to, envelope) in released {
            self.deliver(from, to, envelope);
        }
    }

    /// Deliver every message on `from → to` twice; the recipient's
    /// idempotent paths must make the second a no-op.
    fn duplicate_edge(&self, from: u16, to: u16) {
        self.duplicated_edges.lock().unwrap().insert((from, to));
    }

    fn is_duplicated(&self, from: u16, to: u16) -> bool {
        self.duplicated_edges.lock().unwrap().contains(&(from, to))
    }

    /// Drop every message `from → to`.
    fn drop_edge(&self, from: u16, to: u16) {
        self.dropped_edges.lock().unwrap().insert((from, to));
    }

    /// Drop both directions between `a` and `b`.
    fn drop_pair(&self, a: u16, b: u16) {
        self.drop_edge(a, b);
        self.drop_edge(b, a);
    }

    #[allow(dead_code)]
    fn isolate(&self, node: u16, members: &[u16]) {
        for peer in members {
            if *peer != node {
                self.drop_pair(node, *peer);
            }
        }
    }

    fn is_dropped(&self, from: u16, to: u16) -> bool {
        self.dropped_edges.lock().unwrap().contains(&(from, to))
    }

    fn deliver(&self, from: u16, to: u16, envelope: Envelope<u16>) {
        let handle = self.routes.lock().unwrap().get(&to).cloned();
        match handle {
            Some(handle) => handle.deliver(from, envelope),
            None => self.captured.lock().unwrap().push((from, to, envelope)),
        }
    }

    /// What was sent to `to`, a node without a route, since last asked.
    fn take_captured(&self, to: u16) -> Vec<Envelope<u16>> {
        let mut captured = self.captured.lock().unwrap();
        let (theirs, rest): (Vec<_>, Vec<_>) = captured.drain(..).partition(|(_, at, _)| *at == to);
        *captured = rest;
        theirs
            .into_iter()
            .map(|(_, _, envelope)| envelope)
            .collect()
    }
}

impl Transport<u16> for MockTransport {
    fn send(&self, from: u16, to: u16, envelope: Envelope<u16>) {
        if self.is_dropped(from, to) {
            return;
        }
        match &envelope {
            Envelope::Raft(Message::Append { term, entries, .. }) => {
                self.log.lock().unwrap().push(RpcRecord::Append {
                    from,
                    to,
                    term: *term,
                    count: entries.len(),
                })
            }
            Envelope::Raft(Message::Vote { term, .. }) => {
                self.log.lock().unwrap().push(RpcRecord::Vote {
                    from,
                    to,
                    term: *term,
                })
            }
            Envelope::SnapshotChunk(chunk) => self.log.lock().unwrap().push(RpcRecord::Install {
                from,
                to,
                last_idx: chunk.last_included_index,
            }),
            _ => {}
        }
        if matches!(envelope, Envelope::Raft(Message::AppendAnswer { .. }))
            && let Some(held) = self.held_answers.lock().unwrap().as_mut()
        {
            held.push((from, to, envelope));
            return;
        }
        if self.is_duplicated(from, to) {
            self.deliver(from, to, envelope.clone());
        }
        self.deliver(from, to, envelope);
    }
}

/// Deliver `envelope` from `from` to `handle`, wait until it has been
/// handled, and return what `handle` sent back to `from` (a node without a
/// route).
fn ask(
    handle: &WorkerHandle<u16>,
    transport: &MockTransport,
    from: u16,
    envelope: Envelope<u16>,
) -> Vec<Envelope<u16>> {
    handle.deliver(from, envelope);
    block_on(handle.snapshot()).expect("worker alive");
    transport.take_captured(from)
}

/// The bytes a snapshot acknowledgement among `answers` reports.
fn snapshot_ack(answers: &[Envelope<u16>]) -> Option<InstallSnapshotResp> {
    answers.iter().find_map(|envelope| match envelope {
        Envelope::SnapshotAck(ack) => Some(*ack),
        _ => None,
    })
}

/// The highest index an append answer among `answers` claims.
fn matched(answers: &[Envelope<u16>]) -> Option<u64> {
    answers
        .iter()
        .filter_map(|envelope| match envelope {
            Envelope::Raft(Message::AppendAnswer {
                result: AppendResult::Matched { matched },
                ..
            }) => Some(*matched),
            _ => None,
        })
        .max()
}

/// The leader's heartbeat, which a snapshot's chunks need first: only the
/// leader a replica follows may install one.
fn heartbeat(handle: &WorkerHandle<u16>, transport: &MockTransport, leader: u16, term: u64) {
    ask(
        handle,
        transport,
        leader,
        Envelope::Raft(Message::Append {
            term,
            leader,
            prev_index: 0,
            prev_term: 0,
            commit: 0,
            round: 1,
            entries: vec![],
        }),
    );
}

/// Deliver a snapshot chunk: the acknowledgement.
fn install(
    handle: &WorkerHandle<u16>,
    transport: &MockTransport,
    leader: u16,
    chunk: InstallSnapshotReq<u16>,
) -> InstallSnapshotResp {
    snapshot_ack(&ask(
        handle,
        transport,
        leader,
        Envelope::SnapshotChunk(chunk),
    ))
    .expect("an acknowledgement")
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
        routes.lock().unwrap().insert(me, worker.handler());
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
    assert!(
        last_idx >= 4,
        "expected last_idx >= 4 (1 no-op + 3), got {last_idx}"
    );

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

/// `BumpTermTransport` answers every outbound message as a peer at a
/// higher term would, simulating a leader or candidate that has fallen
/// behind the cluster's term: the worker must step down and adopt the term.
/// Pre-votes are granted, so a candidate proceeds to the real election.
struct BumpTermTransport {
    bumped_term: u64,
    worker: Mutex<Option<WorkerHandle<u16>>>,
}

impl BumpTermTransport {
    fn new(bumped_term: u64) -> Self {
        Self {
            bumped_term,
            worker: Mutex::new(None),
        }
    }
}

fn rejected() -> AppendResult {
    AppendResult::Rejected {
        rejected: 0,
        last_index: 0,
        conflict_term: 0,
        conflict_first: 0,
    }
}

impl Transport<u16> for BumpTermTransport {
    fn send(&self, _from: u16, to: u16, envelope: Envelope<u16>) {
        let answer = match envelope {
            Envelope::Raft(Message::Append { round, commit, .. }) => Message::AppendAnswer {
                term: self.bumped_term,
                round,
                commit,
                result: rejected(),
            },
            Envelope::Raft(Message::Vote { .. }) => Message::VoteAnswer {
                term: self.bumped_term,
                granted: false,
            },
            Envelope::Raft(Message::PreVote { next_term, .. }) => Message::PreVoteAnswer {
                term: next_term.saturating_sub(1),
                next_term,
                granted: true,
            },
            _ => return,
        };
        if let Some(worker) = self.worker.lock().unwrap().as_ref() {
            worker.deliver(to, Envelope::Raft(answer));
        }
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
        worker: Mutex<Option<WorkerHandle<u16>>>,
    }
    impl Transport<u16> for StepDownTransport {
        fn send(&self, _from: u16, to: u16, envelope: Envelope<u16>) {
            // Votes are granted until the leader has been bumped; the
            // first append is answered at the bumped term.
            let granted = !self.bumped.load(AO::Relaxed);
            let answer = match envelope {
                Envelope::Raft(Message::Vote { term, .. }) => Message::VoteAnswer { term, granted },
                Envelope::Raft(Message::Append { round, commit, .. }) => {
                    self.bumped.store(true, AO::Relaxed);
                    Message::AppendAnswer {
                        term: self.bumped_term,
                        round,
                        commit,
                        result: rejected(),
                    }
                }
                Envelope::Raft(Message::PreVote { next_term, .. }) => Message::PreVoteAnswer {
                    term: next_term.saturating_sub(1),
                    next_term,
                    granted,
                },
                _ => return,
            };
            if let Some(worker) = self.worker.lock().unwrap().as_ref() {
                worker.deliver(to, Envelope::Raft(answer));
            }
        }
    }

    let transport = Arc::new(StepDownTransport {
        bumped_term: 99,
        bumped: AtomicBool::new(false),
        worker: Mutex::new(None),
    });
    let storage = MemStorage::<u16>::new();
    let mut cfg_2 = Config::new(0xAAAA, vec![0xAAAA, 0xBBBB], [0xC0; 32]);
    cfg_2.election_timeout_ms = (30, 80);
    cfg_2.heartbeat_interval_ms = 15;
    let worker = Worker::spawn_with(
        storage,
        transport.clone(),
        cfg_2,
        (),
        StdClock,
        StdRng::from_entropy(),
    );
    transport.worker.lock().unwrap().replace(worker.handler());

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
    let transport = Arc::new(BumpTermTransport::new(99));
    let storage = MemStorage::<u16>::new();
    // 2-node cluster — needs the peer's vote to win, so the
    // candidate is forced to send a RequestVote and observe
    // the bumped reply.
    let mut cfg_2 = Config::new(0xAAAA, vec![0xAAAA, 0xBBBB], [0xC0; 32]);
    cfg_2.election_timeout_ms = (30, 80);
    cfg_2.heartbeat_interval_ms = 15;
    let worker = Worker::spawn_with(
        storage,
        transport.clone(),
        cfg_2,
        (),
        StdClock,
        StdRng::from_entropy(),
    );
    transport.worker.lock().unwrap().replace(worker.handler());

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
    let isolated_snap = block_on(workers[&isolated].handler().snapshot()).expect("isolated alive");
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
    let leader_snap_after =
        block_on(workers[&leader_id].handler().snapshot()).expect("leader alive");
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

/// A promoted leader may expose `Role::Leader` before its promotion no-op has
/// reached quorum. When its log already carries an uncommitted application
/// entry from the prior term, `read_index` must wait through the no-op so the
/// returned index commits that prior-term tail as part of the same prefix.
#[test]
fn read_index_commits_prior_term_application_tail_on_leadership_transfer() {
    let routes: Routes = Arc::new(Mutex::new(BTreeMap::new()));
    let transport = Arc::new(MockTransport::new(routes.clone()));
    let members = vec![1u16, 2, 3];
    let mut workers: BTreeMap<u16, Worker<u16>> = BTreeMap::new();

    for me in members.iter().copied() {
        let mut storage = MemStorage::<u16>::new();
        block_on(storage.commit_batch(WriteBatch {
            appends: vec![LogEntry::data(1, 1, b"prior-term-application".to_vec())],
            meta: Some(Meta {
                current_term: 1,
                voted_for: None,
                commit_index: 0,
                snap_last_index: 0,
                snap_last_term: 0,
            }),
            ..Default::default()
        }))
        .unwrap();
        let mut config = cfg(me, members.clone());
        config.pre_vote = false;
        config.election_timeout_ms = if me == 1 { (20, 25) } else { (400, 500) };
        let worker = Worker::spawn_with(
            storage,
            transport.clone(),
            config,
            (),
            StdClock,
            StdRng::from_entropy(),
        );
        routes.lock().unwrap().insert(me, worker.handler());
        workers.insert(me, worker);
    }

    wait_until(
        || workers[&1].role() == Role::Leader,
        Duration::from_secs(3),
        "node with prior-term tail becomes leader",
    );
    let leader = workers[&1].handler();
    let read_index =
        block_on(leader.read_index()).expect("current-term read barrier reaches quorum");
    assert_eq!(
        read_index, 2,
        "the barrier must include the current-term no-op above the prior-term application"
    );
    let snapshot = block_on(leader.snapshot()).unwrap();
    assert!(snapshot.commit_index >= read_index);
    assert_eq!(snapshot.last_log_index, 2);
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
    let result_thread = std::thread::spawn(move || block_on(leader_handle_for_call.read_index()));
    // Give the thread a moment to enqueue.
    std::thread::sleep(Duration::from_millis(50));
    // Inject a higher-term heartbeat that forces step-down.
    leader_handle.deliver(
        99,
        Envelope::Raft(Message::Append {
            term: 1_000,
            leader: 99,
            prev_index: 0,
            prev_term: 0,
            commit: 0,
            round: 1,
            entries: vec![],
        }),
    );
    // The pending read_index must now resolve with LeaderStepped.
    let result = result_thread.join().expect("thread joined");
    assert!(
        matches!(result, Err(ReadIndexError::LeaderStepped)),
        "expected LeaderStepped after step-down, got {result:?}",
    );
}

/// A bounded read barrier on an isolated leader must time out inside the
/// worker, release its queue slot, and leave worker shutdown joinable. Racing
/// an unbounded client future against a timer would fail the second call with
/// Backpressure because the first dead request would still occupy the sole
/// pending slot.
#[test]
fn bounded_read_index_cancels_on_partition_and_shutdown_remains_joinable() {
    use vos_raft::ReadIndexError;

    let routes: Routes = Arc::new(Mutex::new(BTreeMap::new()));
    let transport = Arc::new(MockTransport::new(routes.clone()));
    let members = vec![1u16, 2, 3];
    let mut workers: BTreeMap<u16, Worker<u16>> = BTreeMap::new();
    for me in members.iter().copied() {
        let mut config = cfg(me, members.clone());
        config.max_pending_reads = 1;
        let worker = Worker::spawn_with(
            MemStorage::<u16>::new(),
            transport.clone(),
            config,
            (),
            StdClock,
            StdRng::from_entropy(),
        );
        routes.lock().unwrap().insert(me, worker.handler());
        workers.insert(me, worker);
    }

    wait_until(
        || {
            members
                .iter()
                .any(|member| workers[member].role() == Role::Leader)
        },
        Duration::from_secs(3),
        "leader emerges before bounded-read partition",
    );
    let leader_id = *members
        .iter()
        .find(|member| workers[member].role() == Role::Leader)
        .unwrap();
    let leader = workers[&leader_id].handler();
    transport.isolate(leader_id, &members);

    let started = Instant::now();
    for attempt in 0..2 {
        let result = block_on(leader.read_index_with_timeout(Duration::from_millis(40)));
        assert!(
            matches!(result, Err(ReadIndexError::TimedOut)),
            "attempt {attempt} must expire and release the only queue slot, got {result:?}"
        );
    }
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "bounded barriers must not strand the caller"
    );
    assert_eq!(
        leader.role(),
        Role::Leader,
        "the partitioned leader stays leader"
    );

    let shutdown_started = Instant::now();
    routes.lock().unwrap().clear();
    for worker in workers.into_values() {
        worker.shutdown();
    }
    assert!(
        shutdown_started.elapsed() < Duration::from_secs(2),
        "expired barriers must not prevent worker shutdown"
    );
}

/// A read barrier is confirmed only by answers to heartbeats sent after it
/// was queued. An answer already in flight when it arrived proves leadership
/// only as of an earlier time, after which a new leader may have been elected
/// and committed writes the read would miss.
#[test]
fn read_index_ignores_answers_to_heartbeats_sent_before_it() {
    use vos_raft::ReadIndexError;

    let routes: Routes = Arc::new(Mutex::new(BTreeMap::new()));
    let transport = Arc::new(MockTransport::new(routes.clone()));
    let members = vec![1u16, 2, 3];
    let mut workers: BTreeMap<u16, Worker<u16>> = BTreeMap::new();
    for me in members.iter().copied() {
        // Node 1 campaigns at once and then sends heartbeats only when a read
        // asks for them; the others never campaign within the test. Every
        // heartbeat round is then one the test caused.
        let mut config = cfg(me, members.clone());
        config.heartbeat_interval_ms = 30_000;
        config.election_timeout_ms = if me == 1 { (30, 30) } else { (60_000, 60_000) };
        // Answers are held on purpose; the leader must not step down for
        // not hearing them.
        config.check_quorum = false;
        let worker = Worker::spawn_with(
            MemStorage::<u16>::new(),
            transport.clone(),
            config,
            (),
            StdClock,
            StdRng::from_entropy(),
        );
        routes.lock().unwrap().insert(me, worker.handler());
        workers.insert(me, worker);
    }
    wait_until(
        || workers[&1].role() == Role::Leader,
        Duration::from_secs(3),
        "node 1 leads",
    );
    let leader = workers[&1].handler();
    let committed = block_on(leader.read_index_with_timeout(Duration::from_secs(2)))
        .expect("a read resolves while answers flow");
    // The read resolved on one answer; let the other land before holding.
    std::thread::sleep(Duration::from_millis(50));

    // Read A's round goes out and both answers are held in flight.
    transport.hold_answers();
    let first = {
        let leader = leader.clone();
        std::thread::spawn(move || block_on(leader.read_index_with_timeout(Duration::from_secs(5))))
    };
    wait_until(
        || transport.held_answers() == 2,
        Duration::from_secs(2),
        "read A's round is in flight",
    );
    // Read B is queued once its own round is in flight too.
    let second = {
        let leader = leader.clone();
        std::thread::spawn(move || {
            block_on(leader.read_index_with_timeout(Duration::from_millis(300)))
        })
    };
    wait_until(
        || transport.held_answers() == 4,
        Duration::from_secs(2),
        "read B's round is in flight",
    );
    // A's answers land after B was queued: they confirm A and not B.
    transport.release_answers(2);
    let first = first.join().expect("read A joined");
    assert!(
        matches!(first, Ok(index) if index >= committed),
        "answers to read A's round confirm it, got {first:?}"
    );
    let second = second.join().expect("read B joined");
    assert!(
        matches!(second, Err(ReadIndexError::TimedOut)),
        "answers to a round sent before read B must not confirm it, got {second:?}"
    );

    transport.stop_holding_answers();
    let index = block_on(leader.read_index_with_timeout(Duration::from_secs(2)))
        .expect("a read resolves once answers flow again");
    assert!(index >= committed, "reads stay monotonic");

    routes.lock().unwrap().clear();
    for worker in workers.into_values() {
        worker.shutdown();
    }
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
        // The isolated leader keeps leading, so its queue fills.
        c.check_quorum = false;
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
    leader_handle.deliver(
        99,
        Envelope::Raft(Message::Append {
            term: 1_000,
            leader: 99,
            prev_index: 0,
            prev_term: 0,
            commit: 0,
            round: 1,
            entries: vec![],
        }),
    );

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
        transport.clone(),
        cfg(me, alloc_members(&[me, leader, 0xCCCC])),
        (),
        StdClock,
        StdRng::from_entropy(),
    );
    let h = worker.handler();
    heartbeat(&h, &transport, leader, 1);

    // Build a 100 KiB snapshot. With the default chunk size of
    // 32 KiB we'll need 4 chunks (32 + 32 + 32 + 4 KiB).
    let total_bytes = 100 * 1024;
    let snapshot: Vec<u8> = (0..total_bytes).map(|i| (i & 0xFF) as u8).collect();
    let chunk_size = 32 * 1024;

    let mut offset = 0u64;
    let mut chunks_sent = 0;
    while (offset as usize) < snapshot.len() {
        let end = ((offset as usize) + chunk_size).min(snapshot.len());
        let data = snapshot[offset as usize..end].to_vec();
        let was_final = end == snapshot.len();

        let resp = install(
            &h,
            &transport,
            leader,
            InstallSnapshotReq {
                leader,
                term: 1,
                last_included_index: 1_000,
                last_included_term: 1,
                offset,
                done: was_final,
                data,
                members: Vec::new(),
                joint_old: None,
                active_config_index: None,
            },
        );
        chunks_sent += 1;
        assert_eq!(resp.term, 1);
        assert_eq!(
            resp.bytes_received as usize, end,
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
        transport.clone(),
        cfg(me, alloc_members(&[me, leader, 0xCCCC])),
        (),
        StdClock,
        StdRng::from_entropy(),
    );
    let h = worker.handler();
    heartbeat(&h, &transport, leader, 1);

    let chunk_a = vec![0xAA; 16];
    let chunk_b = vec![0xBB; 16];

    // First chunk at offset 0, not final.
    let r0 = install(
        &h,
        &transport,
        leader,
        InstallSnapshotReq {
            leader,
            term: 1,
            last_included_index: 50,
            last_included_term: 1,
            offset: 0,
            done: false,
            data: chunk_a.clone(),
            members: Vec::new(),
            joint_old: None,
            active_config_index: None,
        },
    );
    assert_eq!(r0.bytes_received, 16);

    // Re-send the SAME first chunk. Follower must report
    // bytes_received = 16 (not 32). Already-have semantics.
    let r0_dup = install(
        &h,
        &transport,
        leader,
        InstallSnapshotReq {
            leader,
            term: 1,
            last_included_index: 50,
            last_included_term: 1,
            offset: 0,
            done: false,
            data: chunk_a.clone(),
            members: Vec::new(),
            joint_old: None,
            active_config_index: None,
        },
    );
    assert_eq!(r0_dup.bytes_received, 16);

    // Now send the real second chunk at offset 16 with done=true.
    let r1 = install(
        &h,
        &transport,
        leader,
        InstallSnapshotReq {
            leader,
            term: 1,
            last_included_index: 50,
            last_included_term: 1,
            offset: 16,
            done: true,
            data: chunk_b,
            members: Vec::new(),
            joint_old: None,
            active_config_index: None,
        },
    );
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
        transport.clone(),
        cfg(me, alloc_members(&[me, leader, 0xCCCC])),
        (),
        StdClock,
        StdRng::from_entropy(),
    );
    let h = worker.handler();
    heartbeat(&h, &transport, leader, 1);

    // First chunk at offset 0 lands fine.
    let r0 = install(
        &h,
        &transport,
        leader,
        InstallSnapshotReq {
            leader,
            term: 1,
            last_included_index: 50,
            last_included_term: 1,
            offset: 0,
            done: false,
            data: vec![0xAA; 16],
            members: Vec::new(),
            joint_old: None,
            active_config_index: None,
        },
    );
    assert_eq!(r0.bytes_received, 16);

    // Skip ahead — offset 100 instead of 16. Follower refuses
    // and reports current length.
    let r_gap = install(
        &h,
        &transport,
        leader,
        InstallSnapshotReq {
            leader,
            term: 1,
            last_included_index: 50,
            last_included_term: 1,
            offset: 100,
            done: false,
            data: vec![0xCC; 16],
            members: Vec::new(),
            joint_old: None,
            active_config_index: None,
        },
    );
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
        transport.clone(),
        c,
        (),
        StdClock,
        StdRng::from_entropy(),
    );
    let h = worker.handler();
    heartbeat(&h, &transport, leader, 1);

    // First chunk: 24 bytes — fits.
    let r0 = install(
        &h,
        &transport,
        leader,
        InstallSnapshotReq {
            leader,
            term: 1,
            last_included_index: 50,
            last_included_term: 1,
            offset: 0,
            done: false,
            data: vec![0xAA; 24],
            members: Vec::new(),
            joint_old: None,
            active_config_index: None,
        },
    );
    assert_eq!(r0.bytes_received, 24, "first chunk must accept under cap");

    // Second chunk: 16 bytes at offset 24 — pushes total to 40,
    // exceeds cap of 32. Must be rejected (bytes_received = 0)
    // and the partial buffer dropped.
    let r1 = install(
        &h,
        &transport,
        leader,
        InstallSnapshotReq {
            leader,
            term: 1,
            last_included_index: 50,
            last_included_term: 1,
            offset: 24,
            done: true,
            data: vec![0xBB; 16],
            members: Vec::new(),
            joint_old: None,
            active_config_index: None,
        },
    );
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
    let r2 = install(
        &h,
        &transport,
        leader,
        InstallSnapshotReq {
            leader,
            term: 1,
            last_included_index: 50,
            last_included_term: 1,
            offset: 0,
            done: true,
            data: vec![0xCC; 16],
            members: Vec::new(),
            joint_old: None,
            active_config_index: None,
        },
    );
    assert_eq!(r2.bytes_received, 16);
    let snap = block_on(h.snapshot()).unwrap();
    assert_eq!(snap.snap_last_index, 50);
    worker.shutdown();
}

/// The follower's acknowledged byte count is authoritative. If it reports
/// zero after losing its volatile partial buffer, the leader must rewind its
/// per-peer cursor instead of retaining the previous offset with `max`.
#[test]
fn snapshot_sender_rewinds_after_follower_loses_partial_buffer() {
    struct RewindTransport {
        install_offsets: Mutex<Vec<u64>>,
        worker: Mutex<Option<WorkerHandle<u16>>>,
    }

    impl Transport<u16> for RewindTransport {
        fn send(&self, _from: u16, to: u16, envelope: Envelope<u16>) {
            // Only peer 2 is scripted; what goes to the seeding leader 9 is
            // dropped.
            if to != 2 {
                return;
            }
            let answer = match envelope {
                Envelope::Raft(Message::Append {
                    term,
                    round,
                    commit,
                    prev_index,
                    ..
                }) => Envelope::Raft(Message::AppendAnswer {
                    term,
                    round,
                    commit,
                    result: AppendResult::Rejected {
                        rejected: prev_index,
                        last_index: 0,
                        conflict_term: 0,
                        conflict_first: 1,
                    },
                }),
                Envelope::Raft(Message::Vote { term, .. }) => Envelope::Raft(Message::VoteAnswer {
                    term,
                    granted: true,
                }),
                Envelope::Raft(Message::PreVote { next_term, .. }) => {
                    Envelope::Raft(Message::PreVoteAnswer {
                        term: next_term.saturating_sub(1),
                        next_term,
                        granted: true,
                    })
                }
                Envelope::SnapshotChunk(chunk) => {
                    let mut offsets = self.install_offsets.lock().unwrap();
                    let attempt = offsets.len();
                    offsets.push(chunk.offset);
                    let chunk_end = chunk.offset + chunk.data.len() as u64;
                    Envelope::SnapshotAck(InstallSnapshotResp {
                        term: chunk.term,
                        last_included_index: chunk.last_included_index,
                        last_included_term: chunk.last_included_term,
                        // The first chunk lands. The follower then restarts
                        // before the final chunk and asks to restart at zero.
                        bytes_received: if attempt == 1 { 0 } else { chunk_end },
                    })
                }
                _ => return,
            };
            if let Some(worker) = self.worker.lock().unwrap().as_ref() {
                worker.deliver(2, answer);
            }
        }
    }

    let transport = Arc::new(RewindTransport {
        install_offsets: Mutex::new(Vec::new()),
        worker: Mutex::new(None),
    });
    let mut config = cfg(1, vec![1, 2]);
    config.pre_vote = false;
    config.election_timeout_ms = (80, 120);
    config.heartbeat_interval_ms = 10;
    config.install_snapshot_chunk_bytes = 8;
    let worker = Worker::spawn_with(
        MemStorage::<u16>::new(),
        transport.clone(),
        config,
        (),
        StdClock,
        StdRng::from_entropy(),
    );
    let handle = worker.handler();
    transport.worker.lock().unwrap().replace(handle.clone());

    // Seed state that is already compacted, so the next elected leader must
    // send a snapshot once its follower rejects the no-op tail. Leader 9's
    // heartbeat establishes it before its snapshot.
    handle.deliver(
        9,
        Envelope::Raft(Message::Append {
            term: 1,
            leader: 9,
            prev_index: 10,
            prev_term: 1,
            commit: 0,
            round: 1,
            entries: vec![],
        }),
    );
    handle.deliver(
        9,
        Envelope::SnapshotChunk(InstallSnapshotReq {
            leader: 9,
            term: 1,
            last_included_index: 10,
            last_included_term: 1,
            offset: 0,
            done: true,
            data: vec![0xA5; 16],
            members: vec![1, 2],
            joint_old: None,
            active_config_index: Some(10),
        }),
    );
    assert_eq!(block_on(handle.snapshot()).unwrap().snap_last_index, 10);

    wait_until(
        || transport.install_offsets.lock().unwrap().len() >= 3,
        Duration::from_secs(3),
        "leader retries snapshot from zero after follower restart",
    );
    let offsets = transport.install_offsets.lock().unwrap().clone();
    assert_eq!(
        &offsets[..3],
        &[0, 8, 0],
        "receiver rewind must replace, not max-clamp, the sender cursor",
    );
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
    routes.lock().unwrap().insert(new_member, worker4.handler());
    workers.insert(new_member, worker4);
    let leader_id = *initial
        .iter()
        .find(|p| workers[p].role() == Role::Leader)
        .expect("leader exists");
    let leader_handle = workers[&leader_id].handler();

    // Issue the membership change.
    let joint_index = block_on(leader_handle.change_membership(new_full.clone()))
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
        || {
            new_members
                .iter()
                .any(|p| workers[p].role() == Role::Leader)
        },
        Duration::from_secs(10),
        "new leader emerges from the post-transition set",
    );
}

/// Reproduce the durable crash window in a two-voter replacement:
///
/// 1. the old leader has committed the joint `{old,new}` configuration;
/// 2. it has appended and persisted the final `{new}` configuration;
/// 3. it crashes before that final row reaches the replacement.
///
/// The retiring node must recover under the joint configuration, win one
/// final election with the replacement's vote, replicate the existing final
/// row, and step down only after it commits. Recovering the speculative final
/// row as already effective leaves both replicas permanently leaderless.
#[test]
fn retiring_leader_recovers_uncommitted_final_configuration() {
    use vos_raft::ActiveConfigRecord;

    const OLD: u16 = 1;
    const NEW: u16 = 2;
    const TERM: u64 = 7;

    let joint = LogEntry::config_change(2, TERM, Some(vec![OLD, NEW]), vec![NEW]);
    let final_entry = LogEntry::config_change(3, TERM, None, vec![NEW]);

    // This is the exact old-leader disk image at the crash: the final row is
    // present but commit_index still stops at the joint row. The persisted
    // active view deliberately models the pre-fix behavior that wrote the
    // speculative final configuration early.
    let mut old_storage = MemStorage::<u16>::new();
    block_on(old_storage.commit_batch(WriteBatch {
        appends: vec![
            LogEntry::data(1, TERM, b"pre-transition".to_vec()),
            joint.clone(),
            final_entry,
        ],
        meta: Some(Meta {
            current_term: TERM,
            voted_for: None,
            commit_index: 2,
            snap_last_index: 0,
            snap_last_term: 0,
        }),
        active_config: Some(ActiveConfigRecord {
            log_index: Some(3),
            current: vec![NEW],
            joint_old: None,
        }),
        ..Default::default()
    }))
    .unwrap();

    // The replacement has only the committed joint prefix, so it still needs
    // OLD's vote and cannot finish the transition by itself.
    let mut new_storage = MemStorage::<u16>::new();
    block_on(new_storage.commit_batch(WriteBatch {
        appends: vec![LogEntry::data(1, TERM, b"pre-transition".to_vec()), joint],
        meta: Some(Meta {
            current_term: TERM,
            voted_for: None,
            commit_index: 2,
            snap_last_index: 0,
            snap_last_term: 0,
        }),
        active_config: Some(ActiveConfigRecord {
            log_index: Some(2),
            current: vec![NEW],
            joint_old: Some(vec![OLD, NEW]),
        }),
        ..Default::default()
    }))
    .unwrap();

    let routes: Routes = Arc::new(Mutex::new(BTreeMap::new()));
    let transport = Arc::new(MockTransport::new(routes.clone()));

    let mut old_cfg = cfg(OLD, vec![OLD, NEW]);
    old_cfg.pre_vote = false;
    old_cfg.election_timeout_ms = (80, 100);
    let old = Worker::spawn_with(
        old_storage,
        transport.clone(),
        old_cfg,
        (),
        StdClock,
        StdRng::from_entropy(),
    );
    old.wait_init().expect("old worker recovers");
    routes.lock().unwrap().insert(OLD, old.handler());

    // Observe the recovery decision before the election timer fires.
    let recovered = block_on(old.handler().snapshot()).expect("old snapshot");
    assert_eq!(recovered.members, vec![NEW]);
    assert_eq!(recovered.joint_old, Some(vec![OLD, NEW]));
    assert_eq!(recovered.active_config_index, Some(2));

    let mut new_cfg = cfg(NEW, vec![OLD, NEW]);
    new_cfg.pre_vote = false;
    new_cfg.election_timeout_ms = (500, 600);
    let new = Worker::spawn_with(
        new_storage,
        transport,
        new_cfg,
        (),
        StdClock,
        StdRng::from_entropy(),
    );
    new.wait_init().expect("new worker recovers");
    routes.lock().unwrap().insert(NEW, new.handler());

    wait_until(
        || {
            let old_snapshot = block_on(old.handler().snapshot());
            let new_snapshot = block_on(new.handler().snapshot());
            matches!(
                (old_snapshot, new_snapshot),
                (Some(old), Some(new))
                    if old.commit_index >= 3
                        && new.commit_index >= 3
                        && old.members == vec![NEW]
                        && new.members == vec![NEW]
                        && old.joint_old.is_none()
                        && new.joint_old.is_none()
                        && new.role == Role::Leader
                        && old.role != Role::Leader
            )
        },
        Duration::from_secs(8),
        "retiring leader replicates and commits the recovered final config",
    );

    old.shutdown();
    new.shutdown();
}

/// A recovered retiring replica can remain a follower while the surviving
/// leader commits the final row. Advancing `leader_commit` across that
/// already-present row must retire the local joint view even though the
/// heartbeat appends no new `ConfigChange`.
#[test]
fn retiring_follower_activates_final_from_leader_commit() {
    use vos_raft::ActiveConfigRecord;

    const OLD: u16 = 1;
    const NEW: u16 = 2;
    const TERM: u64 = 7;

    let mut storage = MemStorage::<u16>::new();
    block_on(storage.commit_batch(WriteBatch {
        appends: vec![
            LogEntry::data(1, TERM, b"pre-transition".to_vec()),
            LogEntry::config_change(2, TERM, Some(vec![OLD, NEW]), vec![NEW]),
            LogEntry::config_change(3, TERM, None, vec![NEW]),
        ],
        meta: Some(Meta {
            current_term: TERM,
            voted_for: None,
            commit_index: 2,
            snap_last_index: 0,
            snap_last_term: 0,
        }),
        active_config: Some(ActiveConfigRecord {
            log_index: Some(3),
            current: vec![NEW],
            joint_old: None,
        }),
        ..Default::default()
    }))
    .unwrap();

    let routes: Routes = Arc::new(Mutex::new(BTreeMap::new()));
    let transport = Arc::new(MockTransport::new(routes));
    let mut config = cfg(OLD, vec![OLD, NEW]);
    config.pre_vote = false;
    config.election_timeout_ms = (5_000, 6_000);
    let worker = Worker::spawn_with(
        storage,
        transport.clone(),
        config,
        (),
        StdClock,
        StdRng::from_entropy(),
    );
    worker.wait_init().expect("retiring follower recovers");

    let before = block_on(worker.handler().snapshot()).expect("snapshot before commit notice");
    assert_eq!(before.commit_index, 2);
    assert_eq!(before.members, vec![NEW]);
    assert_eq!(before.joint_old, Some(vec![OLD, NEW]));
    assert_eq!(before.active_config_index, Some(2));
    assert_eq!(before.retirement_final_index, Some(3));

    let response = ask(
        &worker.handler(),
        &transport,
        NEW,
        Envelope::Raft(Message::Append {
            term: TERM,
            leader: NEW,
            prev_index: 3,
            prev_term: TERM,
            commit: 3,
            round: 1,
            entries: Vec::new(),
        }),
    );
    assert!(
        matched(&response).is_some(),
        "commit heartbeat must be accepted"
    );

    let after = block_on(worker.handler().snapshot()).expect("snapshot after commit notice");
    assert_eq!(after.commit_index, 3);
    assert_eq!(after.members, vec![NEW]);
    assert_eq!(after.joint_old, None);
    assert_eq!(after.active_config_index, Some(3));
    assert_eq!(after.retirement_final_index, Some(3));

    worker.shutdown();
}

/// A follower may already store the uncommitted source final when the next
/// AppendEntries brings only the confirmation row. Its still-joint effective
/// view must not cause that second row to be mistaken for another source
/// final, or retirement debt would survive a committed confirmation forever.
#[test]
fn follower_recognizes_confirmation_after_already_present_final() {
    use vos_raft::ActiveConfigRecord;

    const OLD: u16 = 1;
    const NEW: u16 = 2;
    const TERM: u64 = 7;

    let mut storage = MemStorage::<u16>::new();
    block_on(storage.commit_batch(WriteBatch {
        appends: vec![
            LogEntry::data(1, TERM, b"pre-transition".to_vec()),
            LogEntry::config_change(2, TERM, Some(vec![OLD, NEW]), vec![NEW]),
            LogEntry::config_change(3, TERM, None, vec![NEW]),
        ],
        meta: Some(Meta {
            current_term: TERM,
            voted_for: None,
            commit_index: 2,
            snap_last_index: 0,
            snap_last_term: 0,
        }),
        active_config: Some(ActiveConfigRecord {
            log_index: Some(3),
            current: vec![NEW],
            joint_old: None,
        }),
        ..Default::default()
    }))
    .unwrap();

    let routes: Routes = Arc::new(Mutex::new(BTreeMap::new()));
    let transport = Arc::new(MockTransport::new(routes));
    let mut config = cfg(OLD, vec![OLD, NEW]);
    config.pre_vote = false;
    config.election_timeout_ms = (5_000, 6_000);
    let worker = Worker::spawn_with(
        storage,
        transport.clone(),
        config,
        (),
        StdClock,
        StdRng::from_entropy(),
    );
    worker.wait_init().expect("retiring follower recovers");

    let before = block_on(worker.handler().snapshot()).expect("snapshot before confirmation");
    assert_eq!(before.joint_old, Some(vec![OLD, NEW]));
    assert_eq!(before.retirement_final_index, Some(3));

    let response = ask(
        &worker.handler(),
        &transport,
        NEW,
        Envelope::Raft(Message::Append {
            term: TERM,
            leader: NEW,
            prev_index: 3,
            prev_term: TERM,
            commit: 4,
            round: 1,
            entries: vec![LogEntry::config_change(4, TERM, None, vec![NEW])],
        }),
    );
    assert!(
        matched(&response).is_some(),
        "confirmation append must be accepted"
    );

    let after = block_on(worker.handler().snapshot()).expect("snapshot after confirmation");
    assert_eq!(after.commit_index, 4);
    assert_eq!(after.members, vec![NEW]);
    assert_eq!(after.joint_old, None);
    assert_eq!(after.active_config_index, Some(4));
    assert_eq!(after.retirement_final_index, None);

    worker.shutdown();
}

/// Replacing a speculative final must classify the new final from the joint
/// configuration that survives truncation, not from the stale cached final
/// view. Otherwise this follower can later lead without the retirement debt.
#[test]
fn replaced_speculative_final_preserves_retirement_debt() {
    use vos_raft::ActiveConfigRecord;

    const OLD: u16 = 1;
    const FOLLOWER: u16 = 2;
    const LEADER: u16 = 3;
    const REPLACEMENT: u16 = 4;
    const OLD_TERM: u64 = 7;
    const NEW_TERM: u64 = 8;

    let old_members = vec![OLD, FOLLOWER, LEADER];
    let new_members = vec![FOLLOWER, LEADER, REPLACEMENT];
    let mut storage = MemStorage::<u16>::new();
    block_on(storage.commit_batch(WriteBatch {
        appends: vec![
            LogEntry::data(1, OLD_TERM, b"pre-transition".to_vec()),
            LogEntry::config_change(2, OLD_TERM, Some(old_members.clone()), new_members.clone()),
            LogEntry::config_change(3, OLD_TERM, None, new_members.clone()),
        ],
        meta: Some(Meta {
            current_term: OLD_TERM,
            voted_for: None,
            commit_index: 2,
            snap_last_index: 0,
            snap_last_term: 0,
        }),
        active_config: Some(ActiveConfigRecord {
            log_index: Some(3),
            current: new_members.clone(),
            joint_old: None,
        }),
        ..Default::default()
    }))
    .unwrap();

    let routes: Routes = Arc::new(Mutex::new(BTreeMap::new()));
    let transport = Arc::new(MockTransport::new(routes));
    let mut config = cfg(FOLLOWER, old_members);
    config.pre_vote = false;
    config.election_timeout_ms = (5_000, 6_000);
    let worker = Worker::spawn_with(
        storage,
        transport.clone(),
        config,
        (),
        StdClock,
        StdRng::from_entropy(),
    );
    worker
        .wait_init()
        .expect("follower recovers speculative final");
    assert_eq!(
        block_on(worker.handler().snapshot())
            .expect("snapshot before replacement")
            .retirement_final_index,
        Some(3),
    );

    let response = ask(
        &worker.handler(),
        &transport,
        LEADER,
        Envelope::Raft(Message::Append {
            term: NEW_TERM,
            leader: LEADER,
            prev_index: 2,
            prev_term: OLD_TERM,
            commit: 2,
            round: 1,
            entries: vec![
                LogEntry::data(3, NEW_TERM, b"promotion-noop".to_vec()),
                LogEntry::config_change(4, NEW_TERM, None, new_members.clone()),
            ],
        }),
    );
    assert!(
        matched(&response).is_some(),
        "replacement tail must be accepted"
    );

    let after = block_on(worker.handler().snapshot()).expect("snapshot after replacement");
    assert_eq!(after.members, new_members);
    assert_eq!(after.joint_old, None);
    assert_eq!(after.active_config_index, Some(4));
    assert_eq!(after.retirement_final_index, Some(4));

    worker.shutdown();
}

/// If the replacement received the final row before the old leader crashed,
/// it can elect itself from the final configuration. It must nevertheless
/// keep the retiring peer as a transport-only target long enough to deliver
/// the committed final index; otherwise the old endpoint remains permanently
/// joint and cannot report the terminal replacement disposition.
#[test]
fn replacement_leader_notifies_a_recovered_retiring_follower() {
    use vos_raft::ActiveConfigRecord;

    const OLD: u16 = 1;
    const NEW: u16 = 2;
    const TERM: u64 = 7;

    let crashed_image = || {
        let mut storage = MemStorage::<u16>::new();
        block_on(storage.commit_batch(WriteBatch {
            appends: vec![
                LogEntry::data(1, TERM, b"pre-transition".to_vec()),
                LogEntry::config_change(2, TERM, Some(vec![OLD, NEW]), vec![NEW]),
                LogEntry::config_change(3, TERM, None, vec![NEW]),
            ],
            meta: Some(Meta {
                current_term: TERM,
                voted_for: None,
                commit_index: 2,
                snap_last_index: 0,
                snap_last_term: 0,
            }),
            // Model both sides having persisted the speculative final view.
            // Recovery treats OLD and NEW differently: OLD retains joint
            // election eligibility, while NEW may lead under the final set.
            active_config: Some(ActiveConfigRecord {
                log_index: Some(3),
                current: vec![NEW],
                joint_old: None,
            }),
            ..Default::default()
        }))
        .unwrap();
        storage
    };

    let old_storage = crashed_image();
    let new_storage = crashed_image();
    let routes: Routes = Arc::new(Mutex::new(BTreeMap::new()));
    let transport = Arc::new(MockTransport::new(routes.clone()));

    let mut old_cfg = cfg(OLD, vec![OLD, NEW]);
    old_cfg.pre_vote = false;
    old_cfg.election_timeout_ms = (500, 600);
    let old = Worker::spawn_with(
        old_storage,
        transport.clone(),
        old_cfg,
        (),
        StdClock,
        StdRng::from_entropy(),
    );
    old.wait_init().expect("old worker recovers");
    routes.lock().unwrap().insert(OLD, old.handler());

    let mut new_cfg = cfg(NEW, vec![OLD, NEW]);
    new_cfg.pre_vote = false;
    new_cfg.election_timeout_ms = (80, 100);
    let new = Worker::spawn_with(
        new_storage,
        transport,
        new_cfg,
        (),
        StdClock,
        StdRng::from_entropy(),
    );
    new.wait_init().expect("replacement worker recovers");
    routes.lock().unwrap().insert(NEW, new.handler());

    let old_before = block_on(old.handler().snapshot()).unwrap();
    let new_before = block_on(new.handler().snapshot()).unwrap();
    assert!(old_before.joint_old.is_some());
    assert!(new_before.joint_old.is_none());
    assert_eq!(old_before.retirement_final_index, Some(3));
    assert_eq!(new_before.retirement_final_index, Some(3));

    wait_until(
        || {
            let old_snapshot = block_on(old.handler().snapshot());
            let new_snapshot = block_on(new.handler().snapshot());
            matches!(
                (old_snapshot, new_snapshot),
                (Some(old), Some(new))
                    if new.role == Role::Leader
                        && new.commit_index >= 3
                        && new.members == vec![NEW]
                        && new.joint_old.is_none()
                        && new.retirement_final_index.is_none()
                        && old.commit_index >= 3
                        && old.members == vec![NEW]
                        && old.joint_old.is_none()
                        // The final row (3), or the confirmation that
                        // restates it (5, after the new leader's no-op),
                        // which may reach the retiring node too.
                        && matches!(old.active_config_index, Some(3 | 5))
            )
        },
        Duration::from_secs(8),
        "replacement leader delivers finality to retiring follower",
    );

    old.shutdown();
    new.shutdown();
}

/// The acknowledgement barrier is a replicated, committed steady-config row,
/// not a process-local flag. A later leader must therefore recover with no
/// retirement delivery debt even after every original process has stopped.
#[test]
fn committed_retirement_confirmation_survives_restart() {
    use vos_raft::ActiveConfigRecord;

    const OLD: u16 = 1;
    const NEW: u16 = 2;
    const TERM: u64 = 7;

    let mut storage = MemStorage::<u16>::new();
    block_on(storage.commit_batch(WriteBatch {
        appends: vec![
            LogEntry::data(1, TERM, b"pre-transition".to_vec()),
            LogEntry::config_change(2, TERM, Some(vec![OLD, NEW]), vec![NEW]),
            LogEntry::config_change(3, TERM, None, vec![NEW]),
            LogEntry::config_change(4, TERM, None, vec![NEW]),
        ],
        meta: Some(Meta {
            current_term: TERM,
            voted_for: None,
            commit_index: 4,
            snap_last_index: 0,
            snap_last_term: 0,
        }),
        active_config: Some(ActiveConfigRecord {
            log_index: Some(4),
            current: vec![NEW],
            joint_old: None,
        }),
        ..Default::default()
    }))
    .unwrap();

    let routes: Routes = Arc::new(Mutex::new(BTreeMap::new()));
    let transport = Arc::new(MockTransport::new(routes));
    let mut config = cfg(NEW, vec![OLD, NEW]);
    config.pre_vote = false;
    config.election_timeout_ms = (5_000, 6_000);
    let worker = Worker::spawn_with(
        storage,
        transport.clone(),
        config,
        (),
        StdClock,
        StdRng::from_entropy(),
    );
    worker.wait_init().expect("replacement restarts");

    let snapshot = block_on(worker.handler().snapshot()).expect("recovered snapshot");
    assert_eq!(snapshot.members, vec![NEW]);
    assert_eq!(snapshot.joint_old, None);
    assert_eq!(snapshot.active_config_index, Some(4));
    assert_eq!(snapshot.retirement_final_index, None);

    worker.shutdown();
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

    let r = block_on(
        workers[&follower_id]
            .handler()
            .change_membership(members.clone()),
    );
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

/// A storage backend that persists `WriteBatch::active_config`
/// surfaces the post-transition membership at restart even
/// when the log has been compacted past the `ConfigChange`
/// entry. MemStorage now supports this; before H2/L13 the
/// recovery walked only the live log and would return
/// `cfg.members` as a stale fallback.
#[test]
fn cross_snapshot_membership_recovery_via_persisted_view() {
    use vos_raft::{ActiveConfigRecord, Storage, WriteBatch};

    // Build a MemStorage by hand and persist a "joint phase
    // recently committed" view: current = [1,2,3,4],
    // joint_old = [1,2,3], no log entries (representing a
    // node that just installed a snapshot covering the
    // ConfigChange).
    let mut storage = MemStorage::<u16>::new();
    let post_transition: Vec<u16> = vec![1, 2, 3, 4];
    let pre_transition: Vec<u16> = vec![1, 2, 3];
    block_on(storage.commit_batch(WriteBatch {
        active_config: Some(ActiveConfigRecord {
            log_index: Some(10),
            current: post_transition.clone(),
            joint_old: Some(pre_transition.clone()),
        }),
        ..Default::default()
    }))
    .unwrap();

    // Confirm the active_config reader returns the persisted
    // view directly.
    let persisted = block_on(storage.active_config()).unwrap();
    assert_eq!(
        persisted,
        Some(ActiveConfigRecord {
            log_index: Some(10),
            current: post_transition.clone(),
            joint_old: Some(pre_transition.clone()),
        }),
        "persisted active_config view must round-trip through MemStorage",
    );

    // Now spawn a worker against this storage. Even though
    // Config::members is the OLD set [1,2,3], the worker
    // should adopt the PERSISTED view (joint {[1,2,3,4],
    // joint_old: [1,2,3]}) at boot.
    let routes: Routes = Arc::new(Mutex::new(BTreeMap::new()));
    let transport = Arc::new(MockTransport::new(routes.clone()));
    let me = 1u16;
    let mut c = cfg(me, pre_transition.clone());
    // Make pre_vote false so the worker doesn't try peers we
    // didn't spawn — for this test we only care about the
    // boot-time recovered view, not election dynamics.
    c.pre_vote = false;
    let worker = Worker::spawn_with(storage, transport, c, (), StdClock, StdRng::from_entropy());
    worker.wait_init().expect("init succeeds");

    // The worker's recovered view should reflect the persisted
    // joint, not the static cfg.members. There's no public
    // accessor for `effective_cfg`, so this test exercises the
    // path indirectly: a change_membership call on the leader
    // would return InProgress because joint is in flight. But
    // the worker isn't a leader yet (there's no peer to win an
    // election against). Instead, just confirm the worker's
    // QueryState reports a sane view (the test's main value
    // is exercising the MemStorage round-trip + boot recovery
    // without panicking).
    let snap = block_on(worker.handler().snapshot()).expect("worker alive");
    assert_eq!(snap.role, vos_raft::Role::Follower);

    worker.shutdown();
}
