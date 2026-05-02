//! Per-replication-group Raft worker — vos-side facade over
//! [`vos_raft::Worker`].
//!
//! Pre-extraction this file owned a 1900-line state machine that
//! mixed the consensus core (election timing, replication, snapshot
//! install) with vos's specific storage backend (redb) and transport
//! (libp2p `request_response`). Post-extraction the consensus core
//! lives in the `vos-raft` crate as a transport-and-storage-agnostic
//! generic worker; this file is a thin adapter that:
//!
//! 1. Builds a [`RedbStorage`](super::redb_storage::RedbStorage) from
//!    the host's `Arc<Database>` and a [`VosTransport`](super::vos_transport::VosTransport)
//!    from its `Arc<Network>`.
//! 2. Spawns a [`vos_raft::Worker<u16>`] with that storage + transport
//!    + the host's [`WorkerConfig`].
//! 3. Re-exports [`RaftWorker`] / [`WorkerHandle`] / [`ProposeError`]
//!    / [`WorkerSnapshot`] with the same shape vos used to expose,
//!    so existing call sites (`RaftCommit`, `Network::set_raft_handler`,
//!    tests) keep compiling unchanged.
//!
//! The vos-raft crate ships its own unit tests for the state machine
//! itself; the tests here verify the integration between vos's
//! [`RaftRpcHandler`] trait, [`RedbStorage`], and the generic core.

use alloc::sync::Arc;
use alloc::vec::Vec;
use std::sync::mpsc as std_mpsc;

use futures_executor::block_on;
use redb::Database;

use crate::commit::CommitError;
use crate::network::{
    Network, RaftAppendResult, RaftEntry, RaftInstallSnapshotResult, RaftRpcHandler,
    RaftVoteResult,
};

use super::redb_storage::RedbStorage;
use super::vos_transport::VosTransport;

use vos_raft::{
    AppendEntriesReq, Config as RaftCfg, InstallSnapshotReq, RequestVoteReq,
    Transport as RaftTransport,
};

// `Role` is the same enum, defined once in vos-raft.
pub use vos_raft::Role;

/// Configuration for a worker. Same shape vos has had since the
/// first phase, retained as a vos-specific type so existing call
/// sites (`RaftCommit`, integration tests) don't have to learn the
/// wider `vos_raft::Config<N>` API surface.
#[derive(Debug, Clone)]
pub struct WorkerConfig {
    /// Local node's `node_prefix`.
    pub me: u16,
    /// Static cluster membership. Empty / single-element disables
    /// elections (single-node mode stays in `Follower` forever
    /// since there's no quorum to win).
    pub members: Vec<u16>,
    /// Replication group id — used for outbound `send_raft_*`
    /// calls and for matching inbound RPCs.
    pub replication_id: [u8; 32],
    /// Randomized election-timeout window (low, high) in
    /// milliseconds.
    pub election_timeout_ms: (u64, u64),
    /// Leader heartbeat interval in milliseconds.
    pub heartbeat_interval_ms: u64,
}

impl WorkerConfig {
    fn into_raft(self) -> RaftCfg<u16> {
        let mut c = RaftCfg::new(self.me, self.members, self.replication_id);
        c.election_timeout_ms = self.election_timeout_ms;
        c.heartbeat_interval_ms = self.heartbeat_interval_ms;
        // Pre-vote disabled until vos's libp2p frame layer
        // routes `PreVoteReq` / `PreVoteResp`. Without that
        // wire support, the worker would stay in PreCandidate
        // forever (no peer can reply, no quorum, no
        // promotion). Plain-Raft elections work fine — vos
        // loses the term-inflation-prevention property until
        // the network is upgraded.
        c.pre_vote = false;
        // Chunked InstallSnapshot streaming relies on the wire
        // frame carrying `offset` / `done` / `bytes_received`.
        // Vos's libp2p frame is one-shot today, so we set the
        // chunk budget to "never chunk" — a single InstallSnapshot
        // RPC carries the whole snapshot. Production deployments
        // that exceed libp2p's MAX_TRANSMIT_SIZE need to land
        // chunked-frame support before raising real-world
        // snapshot sizes here.
        c.install_snapshot_chunk_bytes = usize::MAX;
        c
    }
}

/// Reasons a [`WorkerHandle::propose`] can fail at the worker
/// boundary. Wraps the generic `vos_raft::ProposeError<E>` with
/// vos's concrete [`CommitError`] storage type.
#[derive(Debug)]
pub enum ProposeError {
    /// This worker is currently `Follower` or `Candidate`. Caller
    /// must address the leader.
    NotLeader,
    /// redb write failed on the append.
    Storage(CommitError),
}

impl core::fmt::Display for ProposeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NotLeader => write!(f, "propose: not leader"),
            Self::Storage(e) => write!(f, "propose: storage: {e}"),
        }
    }
}
impl std::error::Error for ProposeError {}

/// Diagnostic snapshot of a worker's state. Returned by
/// [`WorkerHandle::snapshot`].
///
/// Specialized over `u16` (vos's `node_prefix`) for stability of
/// the historical API; the generic `vos_raft::WorkerSnapshot<N>`
/// stays internal.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct WorkerSnapshot {
    pub role: Role,
    pub current_term: u64,
    pub voted_for: Option<u16>,
    pub last_log_index: u64,
    pub commit_index: u64,
    pub snap_last_index: u64,
}

impl From<vos_raft::WorkerSnapshot<u16>> for WorkerSnapshot {
    fn from(s: vos_raft::WorkerSnapshot<u16>) -> Self {
        Self {
            role: s.role,
            current_term: s.current_term,
            voted_for: s.voted_for,
            last_log_index: s.last_log_index,
            commit_index: s.commit_index,
            snap_last_index: s.snap_last_index,
        }
    }
}

/// Owning handle to a running worker. Drop or [`shutdown`] cleans
/// up the underlying thread.
///
/// [`shutdown`]: Self::shutdown
pub struct RaftWorker {
    inner: vos_raft::Worker<u16>,
}

impl RaftWorker {
    /// Spawn a worker thread for one replication group.
    ///
    /// - `network` is `None` for unit tests / single-node mode (no
    ///   outbound RPCs). When `Some(_)`, real elections + replication
    ///   route through the libp2p layer.
    /// - `apply_notifier` receives the new `commit_index` value each
    ///   time the worker advances it (own quorum match OR follower
    ///   receiving a heartbeat with a higher leader_commit).
    ///   `RaftCommit::Multi` uses this to unblock its `commit_with_log`.
    pub fn spawn(
        db: Arc<Database>,
        cfg: WorkerConfig,
        network: Option<Arc<Network>>,
        apply_notifier: Option<std_mpsc::Sender<u64>>,
    ) -> Self {
        let storage = RedbStorage::open(db).expect("open RedbStorage");
        let rep_id = cfg.replication_id;
        let raft_cfg = cfg.into_raft();
        let inner = match network {
            Some(net) => {
                let transport = Arc::new(VosTransport::new(net, rep_id));
                vos_raft::Worker::spawn(storage, transport, raft_cfg, apply_notifier)
            }
            None => {
                // Test / single-node mode: outbound RPCs are not
                // expected. The noop transport errors on every send,
                // which the worker treats as "no answer" — same
                // behaviour the pre-extraction worker had when its
                // `Option<Arc<Network>>` was `None`.
                let transport = Arc::new(NoopTransport);
                vos_raft::Worker::spawn(storage, transport, raft_cfg, apply_notifier)
            }
        };
        Self { inner }
    }

    /// Cheap clone-able handle that implements [`RaftRpcHandler`].
    /// Install on a [`Network`] via `set_raft_handler` so inbound
    /// RPCs flow into the worker's inbox.
    pub fn handler(&self) -> WorkerHandle {
        WorkerHandle {
            inner: self.inner.handler(),
        }
    }

    /// Lock-free read of the worker's current role.
    pub fn role(&self) -> Role {
        self.inner.role()
    }

    /// Stop the worker and join the thread.
    pub fn shutdown(self) {
        self.inner.shutdown();
    }
}

/// Cheap-to-clone handle for installing on a [`Network`] as the
/// inbound RPC handler. Internally forwards each RPC into the
/// generic worker's [`vos_raft::WorkerHandle`].
#[derive(Clone)]
pub struct WorkerHandle {
    inner: vos_raft::WorkerHandle<u16>,
}

impl WorkerHandle {
    /// Lock-free read of the worker's current role. Doesn't go
    /// through the inbox so a busy worker doesn't lag the answer.
    pub fn role(&self) -> Role {
        self.inner.role()
    }

    /// Test / diagnostic — block briefly waiting for a snapshot of
    /// the worker's current state. `None` if the worker is shut
    /// down or busy beyond the deadline.
    pub fn snapshot(&self) -> Option<WorkerSnapshot> {
        block_on(self.inner.snapshot()).map(WorkerSnapshot::from)
    }

    /// Append a new payload to the cluster log. Caller addresses a
    /// Leader; followers / candidates return [`ProposeError::NotLeader`].
    pub fn propose(&self, payload: Vec<u8>) -> Result<u64, ProposeError> {
        match block_on(self.inner.propose(payload)) {
            Ok(idx) => Ok(idx),
            Err(vos_raft::ProposeError::NotLeader) => Err(ProposeError::NotLeader),
            // The generic propose surfaces storage errors through
            // the worker loop's tracing; the handle erases the
            // concrete type. Wildcard catches future ProposeError
            // variants vos-raft adds (the type is `#[non_exhaustive]`).
            Err(_) => Err(ProposeError::Storage(CommitError::Config(
                "raft propose: storage write failed".into(),
            ))),
        }
    }
}

/// `RaftRpcHandler` impl for [`WorkerHandle`].
///
/// Each method bridges the sync trait API expected by the
/// libp2p layer (`Network::set_raft_handler`) to the underlying
/// async [`vos_raft::WorkerHandle`] by `block_on`-ing the call.
/// The block is always executed on a `tokio::task::spawn_blocking`
/// worker — see `Network::run_swarm` (`crates/vos/src/network/mod.rs`,
/// search for `RaftAppendReq`): every inbound Raft frame is
/// dispatched off the swarm thread before invoking the handler,
/// so:
///
/// 1. The swarm thread never blocks on the worker.
/// 2. An outbound `VosTransport::send_*` posted to the swarm
///    from this same blocking thread can make progress while
///    the inbound handler is still parked on its worker reply.
/// 3. No deadlock is possible between inbound RPC dispatch and
///    outbound RPC delivery, even if both touch the same
///    libp2p `request_response` plumbing.
///
/// The `block_on` here is therefore safe — it parks a tokio
/// blocking-pool thread, not the swarm thread, and the worker
/// has its own dedicated thread to make progress.
impl RaftRpcHandler for WorkerHandle {
    fn append_entries(
        &self,
        _replication_id: &[u8; 32],
        from_prefix: u16,
        term: u64,
        prev_log_index: u64,
        prev_log_term: u64,
        leader_commit: u64,
        entries: Vec<RaftEntry>,
    ) -> RaftAppendResult {
        let req = AppendEntriesReq {
            leader: from_prefix,
            term,
            prev_log_index,
            prev_log_term,
            leader_commit,
            entries: entries
                .into_iter()
                // Index is decided by the worker's log consistency
                // check; the wire format doesn't carry it because
                // indices are contiguous from `prev_log_index + 1`.
                // We fill `index = 0` here — the worker assigns
                // the right index before append. Wire entries are
                // always `Data` today (vos doesn't ferry the
                // `ConfigChange` variant yet).
                .map(|e| vos_raft::LogEntry::data(0, e.term, e.payload))
                .collect(),
        };
        let resp = block_on(self.inner.handle_inbound_append(from_prefix, req));
        RaftAppendResult {
            term: resp.term,
            success: resp.success,
            match_index: resp.match_index,
        }
    }

    fn request_vote(
        &self,
        _replication_id: &[u8; 32],
        from_prefix: u16,
        term: u64,
        last_log_index: u64,
        last_log_term: u64,
    ) -> RaftVoteResult {
        let req = RequestVoteReq {
            candidate: from_prefix,
            term,
            last_log_index,
            last_log_term,
        };
        let resp = block_on(self.inner.handle_inbound_vote(from_prefix, req));
        RaftVoteResult {
            term: resp.term,
            vote_granted: resp.vote_granted,
        }
    }

    fn install_snapshot(
        &self,
        _replication_id: &[u8; 32],
        from_prefix: u16,
        term: u64,
        last_included_index: u64,
        last_included_term: u64,
        snapshot: Vec<u8>,
    ) -> RaftInstallSnapshotResult {
        // Vos's wire frame is one-shot today: the leader produces
        // a single InstallSnapshotReq carrying the whole snapshot
        // (Config::install_snapshot_chunk_bytes = usize::MAX in
        // [`WorkerConfig::into_raft`]), and the receiver sees one
        // chunk with `offset = 0` and `done = true`. Once the
        // libp2p frame layer learns to ferry chunked InstallSnapshot,
        // change this to forward `offset` / `done` from the wire.
        let req = InstallSnapshotReq {
            leader: from_prefix,
            term,
            last_included_index,
            last_included_term,
            offset: 0,
            done: true,
            data: snapshot,
        };
        let resp = block_on(self.inner.handle_inbound_install(from_prefix, req));
        RaftInstallSnapshotResult { term: resp.term }
    }
}

/// No-op transport used when [`RaftWorker::spawn`] is called with
/// `network = None` — every send returns an error so the worker
/// treats the peer as unreachable. Equivalent to the pre-extraction
/// behaviour where outbound paths short-circuited on the
/// `Option<Arc<Network>>` being `None`.
struct NoopTransport;

#[derive(Debug)]
struct NoopError;

impl core::fmt::Display for NoopError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "noop transport")
    }
}

impl std::error::Error for NoopError {}

impl RaftTransport<u16> for NoopTransport {
    type Error = NoopError;

    async fn send_append(
        &self,
        _peer: u16,
        _req: AppendEntriesReq<u16>,
    ) -> Result<vos_raft::AppendEntriesResp, Self::Error> {
        Err(NoopError)
    }

    async fn send_vote(
        &self,
        _peer: u16,
        _req: RequestVoteReq<u16>,
    ) -> Result<vos_raft::RequestVoteResp, Self::Error> {
        Err(NoopError)
    }

    async fn send_install(
        &self,
        _peer: u16,
        _req: InstallSnapshotReq<u16>,
    ) -> Result<vos_raft::InstallSnapshotResp, Self::Error> {
        Err(NoopError)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::raft::log::{RaftLog, RaftMeta};
    use std::time::{Duration, Instant};

    fn temp_db() -> (Arc<Database>, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(alloc::format!(
            "vos_raft_worker_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let db = Arc::new(Database::create(dir.join("test.redb")).unwrap());
        (db, dir)
    }

    fn cfg(me: u16) -> WorkerConfig {
        WorkerConfig {
            me,
            members: alloc::vec![me, me ^ 0x1, me ^ 0x2],
            replication_id: [0xC0; 32],
            // Long timeout so unit tests that exercise inbound
            // RPCs aren't racing the election timer.
            election_timeout_ms: (5_000, 10_000),
            heartbeat_interval_ms: 500,
        }
    }

    fn wait_for_role(h: &WorkerHandle, want: Role, max: Duration) -> bool {
        let deadline = Instant::now() + max;
        while Instant::now() < deadline {
            if h.role() == want {
                return true;
            }
            std::thread::sleep(Duration::from_millis(2));
        }
        false
    }

    #[test]
    fn request_vote_grants_when_log_is_empty() {
        let (db, dir) = temp_db();
        let worker = RaftWorker::spawn(db, cfg(0xAAAA), None, None);
        let h = worker.handler();
        // Peer at term 5, empty log → grant: their log is at least
        // as up-to-date as ours (both empty).
        let resp = h.request_vote(&[0xC0; 32], 0xBBBB, 5, 0, 0);
        assert!(resp.vote_granted);
        assert_eq!(resp.term, 5);
        worker.shutdown();
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn append_entries_heartbeat_advances_term_and_persists() {
        let (db, dir) = temp_db();
        let worker = RaftWorker::spawn(db.clone(), cfg(0xAAAA), None, None);
        let h = worker.handler();
        let resp = h.append_entries(&[0xC0; 32], 0xBBBB, 9, 0, 0, 0, alloc::vec![]);
        assert!(resp.success);
        assert_eq!(resp.term, 9);
        worker.shutdown();
        let meta = RaftMeta::load(&db).unwrap();
        assert_eq!(meta.current_term, 9);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn follower_appends_entries_and_advances_commit_index() {
        let (db, dir) = temp_db();
        let worker = RaftWorker::spawn(db.clone(), cfg(0xAAAA), None, None);
        let h = worker.handler();
        // Append two entries at indices 1, 2 (term 3) with
        // leader_commit=2.
        let entries = alloc::vec![
            RaftEntry { term: 3, payload: b"a".to_vec() },
            RaftEntry { term: 3, payload: b"b".to_vec() },
        ];
        let resp = h.append_entries(&[0xC0; 32], 0xBBBB, 3, 0, 0, 2, entries);
        assert!(resp.success);
        assert_eq!(resp.match_index, 2);
        worker.shutdown();
        let log = RaftLog::open(db.clone()).unwrap();
        assert_eq!(log.last_index(), 2);
        let stored = log.entries(1, 2).unwrap();
        assert_eq!(stored[0].payload, b"a");
        assert_eq!(stored[1].payload, b"b");
        let meta = RaftMeta::load(&db).unwrap();
        assert_eq!(meta.commit_index, 2);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn follower_rejects_inconsistent_prev_log() {
        let (db, dir) = temp_db();
        let worker = RaftWorker::spawn(db.clone(), cfg(0xAAAA), None, None);
        let h = worker.handler();
        // Leader claims `prev_log_index=5` exists at term 3, but
        // our log is empty. Refuse.
        let resp = h.append_entries(
            &[0xC0; 32], 0xBBBB, 3, 5, 3, 0,
            alloc::vec![RaftEntry { term: 3, payload: b"x".to_vec() }],
        );
        assert!(!resp.success);
        worker.shutdown();
        let log = RaftLog::open(db).unwrap();
        assert_eq!(log.last_index(), 0);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn follower_truncates_conflicting_tail_then_appends() {
        let (db, dir) = temp_db();
        // Pre-seed two entries at term 1.
        {
            let mut log = RaftLog::open(db.clone()).unwrap();
            for _ in 0..2 {
                let txn = db.begin_write().unwrap();
                log.append_in_txn(&txn, 1, b"old").unwrap();
                txn.commit().unwrap();
            }
        }
        let worker = RaftWorker::spawn(db.clone(), cfg(0xAAAA), None, None);
        let h = worker.handler();
        // Leader: prev_log_index=1 (term 1) — matches us. Then
        // appends index 2 at term 2 (conflicts with our index 2
        // which is at term 1). We truncate, then write 2 + 3.
        let entries = alloc::vec![
            RaftEntry { term: 2, payload: b"new-2".to_vec() },
            RaftEntry { term: 2, payload: b"new-3".to_vec() },
        ];
        let resp = h.append_entries(&[0xC0; 32], 0xBBBB, 2, 1, 1, 0, entries);
        assert!(resp.success);
        worker.shutdown();
        let log = RaftLog::open(db).unwrap();
        let entries = log.entries(1, 5).unwrap();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[1].payload, b"new-2");
        assert_eq!(entries[2].payload, b"new-3");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn follower_idempotent_on_already_present_entries() {
        let (db, dir) = temp_db();
        let worker = RaftWorker::spawn(db.clone(), cfg(0xAAAA), None, None);
        let h = worker.handler();
        let payload = alloc::vec![RaftEntry { term: 1, payload: b"x".to_vec() }];
        // First call: appends entry at index 1.
        let r1 = h.append_entries(&[0xC0; 32], 0xBBBB, 1, 0, 0, 1, payload.clone());
        assert!(r1.success);
        // Second call with the same prev/entry: replay must not
        // duplicate the entry.
        let r2 = h.append_entries(&[0xC0; 32], 0xBBBB, 1, 0, 0, 1, payload);
        assert!(r2.success);
        worker.shutdown();
        let log = RaftLog::open(db).unwrap();
        assert_eq!(log.last_index(), 1);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn worker_shuts_down_cleanly() {
        let (db, dir) = temp_db();
        let worker = RaftWorker::spawn(db, cfg(0xAAAA), None, None);
        worker.shutdown();
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn at_most_one_vote_per_term() {
        let (db, dir) = temp_db();
        let worker = RaftWorker::spawn(db, cfg(0xAAAA), None, None);
        let h = worker.handler();
        // First peer asks for our vote at term 4 — granted.
        let r1 = h.request_vote(&[0xC0; 32], 0xBBBB, 4, 0, 0);
        assert!(r1.vote_granted);
        // Second peer asks for the same term — refused (we already
        // voted for 0xBBBB).
        let r2 = h.request_vote(&[0xC0; 32], 0xCCCC, 4, 0, 0);
        assert!(!r2.vote_granted);
        worker.shutdown();
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn solo_candidate_with_quorum_of_one_becomes_leader() {
        let (db, dir) = temp_db();
        let cfg = WorkerConfig {
            me: 0xAAAA,
            members: alloc::vec![0xAAAA],
            replication_id: [0xC0; 32],
            election_timeout_ms: (10, 30),
            heartbeat_interval_ms: 500,
        };
        let worker = RaftWorker::spawn(db, cfg, None, None);
        let h = worker.handler();
        assert!(wait_for_role(&h, Role::Leader, Duration::from_secs(5)),
            "solo cluster must self-elect to leader");
        worker.shutdown();
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn propose_on_follower_is_rejected() {
        let (db, dir) = temp_db();
        let cfg = WorkerConfig {
            me: 0xAAAA,
            // Multi-member cluster with no peers reachable → can't
            // win election → stays Follower forever (no quorum).
            members: alloc::vec![0xAAAA, 0xBBBB, 0xCCCC],
            replication_id: [0xC0; 32],
            election_timeout_ms: (50, 100),
            heartbeat_interval_ms: 25,
        };
        let worker = RaftWorker::spawn(db, cfg, None, None);
        let h = worker.handler();
        let r = h.propose(b"never".to_vec());
        assert!(matches!(r, Err(ProposeError::NotLeader)));
        worker.shutdown();
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn follower_applies_install_snapshot() {
        use crate::commit::{STATE_KEY, STATE_TABLE};
        let (db, dir) = temp_db();
        // Pre-populate some old log entries that the snapshot
        // will supersede.
        {
            let mut log = RaftLog::open(db.clone()).unwrap();
            for _ in 0..5 {
                let txn = db.begin_write().unwrap();
                log.append_in_txn(&txn, 1, b"old").unwrap();
                txn.commit().unwrap();
            }
        }
        let worker = RaftWorker::spawn(db.clone(), cfg(0xAAAA), None, None);
        let h = worker.handler();

        let snapshot_bytes = b"actor-state-at-index-3".to_vec();
        let resp = h.install_snapshot(
            &[0xC0; 32],
            0xBBBB,
            7,
            3,
            2,
            snapshot_bytes.clone(),
        );
        assert_eq!(resp.term, 7);
        worker.shutdown();

        let txn = db.begin_read().unwrap();
        let state_table = txn.open_table(STATE_TABLE).unwrap();
        let state = state_table.get(STATE_KEY).unwrap().unwrap().value().to_vec();
        assert_eq!(state, snapshot_bytes);

        let meta = RaftMeta::load(&db).unwrap();
        assert_eq!(meta.current_term, 7);
        assert_eq!(meta.snap_last_index, 3);
        assert_eq!(meta.snap_last_term, 2);
        assert_eq!(meta.commit_index, 3);
        // `last_applied` is the host's responsibility (see
        // vos_raft::Meta doc) — the worker no longer bumps it
        // on snapshot install. Vos's `RaftCommit::commit_with_log`
        // bumps it when the apply path runs.

        let log = RaftLog::open(db.clone()).unwrap();
        assert_eq!(log.snap_last_index(), 3);
        assert!(log.entries(1, 3).unwrap().is_empty());
        let surviving = log.entries(4, 5).unwrap();
        assert_eq!(surviving.len(), 2);

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn install_snapshot_at_lower_index_is_no_op() {
        let (db, dir) = temp_db();
        let worker = RaftWorker::spawn(db.clone(), cfg(0xAAAA), None, None);
        let h = worker.handler();

        let _ = h.install_snapshot(
            &[0xC0; 32], 0xBBBB, 1, 5, 1, b"v1".to_vec(),
        );
        let _ = h.install_snapshot(
            &[0xC0; 32], 0xBBBB, 1, 3, 1, b"v2".to_vec(),
        );

        worker.shutdown();
        let meta = RaftMeta::load(&db).unwrap();
        assert_eq!(meta.snap_last_index, 5,
            "lower-index install must not regress the snap pointer");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn solo_leader_propose_appends_entry_to_log() {
        let (db, dir) = temp_db();
        let cfg = WorkerConfig {
            me: 0xAAAA,
            members: alloc::vec![0xAAAA],
            replication_id: [0xC0; 32],
            election_timeout_ms: (10, 30),
            heartbeat_interval_ms: 500,
        };
        let worker = RaftWorker::spawn(db.clone(), cfg, None, None);
        let h = worker.handler();
        assert!(wait_for_role(&h, Role::Leader, Duration::from_secs(5)));

        // Index 1 is the vos-raft leader-promotion no-op
        // (Ongaro §6.4 — see vos_raft::worker::become_leader);
        // application proposes start at index 2.
        let idx = h.propose(b"first".to_vec()).expect("propose");
        assert_eq!(idx, 2);
        let idx2 = h.propose(b"second".to_vec()).expect("propose 2");
        assert_eq!(idx2, 3);

        worker.shutdown();

        let log = RaftLog::open(db).unwrap();
        assert_eq!(log.last_index(), 3);
        let entries = log.entries(1, 3).unwrap();
        // entries[0] = no-op (empty payload), entries[1] = "first",
        // entries[2] = "second".
        assert!(entries[0].payload.is_empty(), "entry 1 should be the no-op");
        assert_eq!(entries[1].payload, b"first");
        assert_eq!(entries[2].payload, b"second");
        assert_eq!(entries[0].term, entries[1].term);
        assert_eq!(entries[1].term, entries[2].term);

        let _ = std::fs::remove_dir_all(dir);
    }
}
