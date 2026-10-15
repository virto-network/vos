//! openraft 0.9 reference for the S3 log benchmarks: the same in-process
//! 3-node setup, redb layout and measurement as the vos-raft runs.
//!
//! `throughput`: one group, concurrent `client_write`s on the leader.
//! `groups <count> [heartbeat_ms]`: idle groups on one shared runtime.

use std::collections::BTreeMap;
use std::fmt::Debug;
use std::io::Cursor;
use std::ops::RangeBounds;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use openraft::error::{InstallSnapshotError, RPCError, RaftError, RemoteError};
use openraft::network::RPCOption;
use openraft::raft::{
    AppendEntriesRequest, AppendEntriesResponse, InstallSnapshotRequest, InstallSnapshotResponse,
    VoteRequest, VoteResponse,
};
use openraft::storage::{LogFlushed, RaftLogStorage, RaftStateMachine};
use openraft::{
    BasicNode, Config, Entry, EntryPayload, LogId, LogState, Raft, RaftLogReader, RaftNetwork,
    RaftNetworkFactory, RaftSnapshotBuilder, ServerState, Snapshot, SnapshotMeta, StorageError,
    StoredMembership, Vote,
};
use redb::{Database, Durability, TableDefinition};

openraft::declare_raft_types!(
    pub TC:
        D = Vec<u8>,
        R = (),
);

type NodeId = u64;

const LOG: TableDefinition<u64, &[u8]> = TableDefinition::new("log");
const META: TableDefinition<u8, &[u8]> = TableDefinition::new("meta");

// ── Log store: redb (one fsync per append) + in-memory mirror ─

#[derive(Default)]
struct LogInner {
    log: BTreeMap<u64, Entry<TC>>,
    vote: Option<Vote<NodeId>>,
    purged: Option<LogId<NodeId>>,
}

#[derive(Clone)]
struct LogStore {
    db: Option<Arc<Database>>,
    flusher: Option<std::sync::mpsc::Sender<(Vec<(u64, Vec<u8>)>, LogFlushed<TC>)>>,
    inner: Arc<Mutex<LogInner>>,
}

/// Background flusher: drains queued appends, writes them in one transaction
/// with one fsync, then completes their callbacks in order.
fn spawn_flusher(
    db: Arc<Database>,
) -> std::sync::mpsc::Sender<(Vec<(u64, Vec<u8>)>, LogFlushed<TC>)> {
    let (tx, rx) = std::sync::mpsc::channel::<(Vec<(u64, Vec<u8>)>, LogFlushed<TC>)>();
    std::thread::spawn(move || {
        while let Ok(first) = rx.recv() {
            let mut batch = vec![first];
            batch.extend(rx.try_iter());
            let mut txn = db.begin_write().unwrap();
            txn.set_durability(Durability::Immediate);
            {
                let mut t = txn.open_table(LOG).unwrap();
                for (rows, _) in &batch {
                    for (index, bytes) in rows {
                        t.insert(*index, bytes.as_slice()).unwrap();
                    }
                }
            }
            txn.commit().unwrap();
            for (_, callback) in batch {
                callback.log_io_completed(Ok(()));
            }
        }
    });
    tx
}

impl LogStore {
    fn new(db: Option<Arc<Database>>, background: bool) -> Self {
        Self {
            flusher: db.clone().filter(|_| background).map(spawn_flusher),
            db,
            inner: Arc::default(),
        }
    }

    fn write(&self, durable: bool, f: impl FnOnce(&redb::WriteTransaction)) {
        let Some(db) = &self.db else { return };
        let mut txn = db.begin_write().unwrap();
        txn.set_durability(if durable {
            Durability::Immediate
        } else {
            Durability::None
        });
        f(&txn);
        txn.commit().unwrap();
    }
}

fn encode(entry: &Entry<TC>) -> Vec<u8> {
    let mut out = entry.log_id.leader_id.term.to_le_bytes().to_vec();
    if let EntryPayload::Normal(data) = &entry.payload {
        out.extend_from_slice(data);
    }
    out
}

impl RaftLogReader<TC> for LogStore {
    async fn try_get_log_entries<RB: RangeBounds<u64> + Clone + Debug + Send>(
        &mut self,
        range: RB,
    ) -> Result<Vec<Entry<TC>>, StorageError<NodeId>> {
        let inner = self.inner.lock().unwrap();
        Ok(inner.log.range(range).map(|(_, e)| e.clone()).collect())
    }
}

impl RaftLogStorage<TC> for LogStore {
    type LogReader = Self;

    async fn get_log_state(&mut self) -> Result<LogState<TC>, StorageError<NodeId>> {
        let inner = self.inner.lock().unwrap();
        let last = inner
            .log
            .last_key_value()
            .map(|(_, e)| e.log_id)
            .or(inner.purged);
        Ok(LogState {
            last_purged_log_id: inner.purged,
            last_log_id: last,
        })
    }

    async fn get_log_reader(&mut self) -> Self::LogReader {
        self.clone()
    }

    async fn save_vote(&mut self, vote: &Vote<NodeId>) -> Result<(), StorageError<NodeId>> {
        self.write(true, |txn| {
            let mut t = txn.open_table(META).unwrap();
            t.insert(0, vote.leader_id.term.to_le_bytes().as_slice())
                .unwrap();
        });
        self.inner.lock().unwrap().vote = Some(*vote);
        Ok(())
    }

    async fn read_vote(&mut self) -> Result<Option<Vote<NodeId>>, StorageError<NodeId>> {
        Ok(self.inner.lock().unwrap().vote)
    }

    async fn append<I>(
        &mut self,
        entries: I,
        callback: LogFlushed<TC>,
    ) -> Result<(), StorageError<NodeId>>
    where
        I: IntoIterator<Item = Entry<TC>> + Send,
        I::IntoIter: Send,
    {
        let entries: Vec<Entry<TC>> = entries.into_iter().collect();
        if let Some(flusher) = &self.flusher {
            let rows = entries
                .iter()
                .map(|e| (e.log_id.index, encode(e)))
                .collect();
            let mut inner = self.inner.lock().unwrap();
            for entry in entries {
                inner.log.insert(entry.log_id.index, entry);
            }
            drop(inner);
            flusher.send((rows, callback)).expect("flusher");
            return Ok(());
        }
        self.write(true, |txn| {
            let mut t = txn.open_table(LOG).unwrap();
            for entry in &entries {
                t.insert(entry.log_id.index, encode(entry).as_slice())
                    .unwrap();
            }
        });
        let mut inner = self.inner.lock().unwrap();
        for entry in entries {
            inner.log.insert(entry.log_id.index, entry);
        }
        drop(inner);
        callback.log_io_completed(Ok(()));
        Ok(())
    }

    async fn truncate(&mut self, log_id: LogId<NodeId>) -> Result<(), StorageError<NodeId>> {
        let stale: Vec<u64> = {
            let mut inner = self.inner.lock().unwrap();
            let stale = inner.log.range(log_id.index..).map(|(i, _)| *i).collect();
            inner.log.split_off(&log_id.index);
            stale
        };
        self.write(true, |txn| {
            let mut t = txn.open_table(LOG).unwrap();
            for index in stale {
                t.remove(index).unwrap();
            }
        });
        Ok(())
    }

    async fn purge(&mut self, log_id: LogId<NodeId>) -> Result<(), StorageError<NodeId>> {
        let old: Vec<u64> = {
            let mut inner = self.inner.lock().unwrap();
            let old = inner.log.range(..=log_id.index).map(|(i, _)| *i).collect();
            inner.log = inner.log.split_off(&(log_id.index + 1));
            inner.purged = Some(log_id);
            old
        };
        self.write(false, |txn| {
            let mut t = txn.open_table(LOG).unwrap();
            for index in old {
                t.remove(index).unwrap();
            }
        });
        Ok(())
    }
}

// ── State machine: counts applied entries ────────────────────

#[derive(Clone, Default)]
struct StateMachine {
    inner: Arc<Mutex<(Option<LogId<NodeId>>, StoredMembership<NodeId, BasicNode>)>>,
}

impl RaftSnapshotBuilder<TC> for StateMachine {
    async fn build_snapshot(&mut self) -> Result<Snapshot<TC>, StorageError<NodeId>> {
        let (last, membership) = self.inner.lock().unwrap().clone();
        Ok(Snapshot {
            meta: SnapshotMeta {
                last_log_id: last,
                last_membership: membership,
                snapshot_id: format!("{:?}", last),
            },
            snapshot: Box::new(Cursor::new(Vec::new())),
        })
    }
}

impl RaftStateMachine<TC> for StateMachine {
    type SnapshotBuilder = Self;

    async fn applied_state(
        &mut self,
    ) -> Result<(Option<LogId<NodeId>>, StoredMembership<NodeId, BasicNode>), StorageError<NodeId>>
    {
        Ok(self.inner.lock().unwrap().clone())
    }

    async fn apply<I>(&mut self, entries: I) -> Result<Vec<()>, StorageError<NodeId>>
    where
        I: IntoIterator<Item = Entry<TC>> + Send,
        I::IntoIter: Send,
    {
        let mut inner = self.inner.lock().unwrap();
        let mut out = Vec::new();
        for entry in entries {
            inner.0 = Some(entry.log_id);
            if let EntryPayload::Membership(m) = entry.payload {
                inner.1 = StoredMembership::new(Some(entry.log_id), m);
            }
            out.push(());
        }
        Ok(out)
    }

    async fn get_snapshot_builder(&mut self) -> Self::SnapshotBuilder {
        self.clone()
    }

    async fn begin_receiving_snapshot(
        &mut self,
    ) -> Result<Box<Cursor<Vec<u8>>>, StorageError<NodeId>> {
        Ok(Box::new(Cursor::new(Vec::new())))
    }

    async fn install_snapshot(
        &mut self,
        meta: &SnapshotMeta<NodeId, BasicNode>,
        _snapshot: Box<Cursor<Vec<u8>>>,
    ) -> Result<(), StorageError<NodeId>> {
        *self.inner.lock().unwrap() = (meta.last_log_id, meta.last_membership.clone());
        Ok(())
    }

    async fn get_current_snapshot(&mut self) -> Result<Option<Snapshot<TC>>, StorageError<NodeId>> {
        Ok(None)
    }
}

// ── In-process network ───────────────────────────────────────

#[derive(Clone)]
struct Router {
    rafts: Arc<OnceLock<BTreeMap<NodeId, Raft<TC>>>>,
    rpcs: Arc<AtomicU64>,
}

struct Conn {
    router: Router,
    target: NodeId,
}

impl Conn {
    fn raft(&self) -> &Raft<TC> {
        &self.router.rafts.get().expect("bound")[&self.target]
    }
}

impl RaftNetworkFactory<TC> for Router {
    type Network = Conn;

    async fn new_client(&mut self, target: NodeId, _node: &BasicNode) -> Conn {
        Conn {
            router: self.clone(),
            target,
        }
    }
}

impl RaftNetwork<TC> for Conn {
    async fn append_entries(
        &mut self,
        rpc: AppendEntriesRequest<TC>,
        _option: RPCOption,
    ) -> Result<AppendEntriesResponse<NodeId>, RPCError<NodeId, BasicNode, RaftError<NodeId>>> {
        self.router.rpcs.fetch_add(1, Ordering::Relaxed);
        self.raft()
            .append_entries(rpc)
            .await
            .map_err(|e| RPCError::RemoteError(RemoteError::new(self.target, e)))
    }

    async fn install_snapshot(
        &mut self,
        rpc: InstallSnapshotRequest<TC>,
        _option: RPCOption,
    ) -> Result<
        InstallSnapshotResponse<NodeId>,
        RPCError<NodeId, BasicNode, RaftError<NodeId, InstallSnapshotError>>,
    > {
        self.router.rpcs.fetch_add(1, Ordering::Relaxed);
        self.raft()
            .install_snapshot(rpc)
            .await
            .map_err(|e| RPCError::RemoteError(RemoteError::new(self.target, e)))
    }

    async fn vote(
        &mut self,
        rpc: VoteRequest<NodeId>,
        _option: RPCOption,
    ) -> Result<VoteResponse<NodeId>, RPCError<NodeId, BasicNode, RaftError<NodeId>>> {
        self.router.rpcs.fetch_add(1, Ordering::Relaxed);
        self.raft()
            .vote(rpc)
            .await
            .map_err(|e| RPCError::RemoteError(RemoteError::new(self.target, e)))
    }
}

// ── Setup ────────────────────────────────────────────────────

async fn spawn_group(
    members: [NodeId; 3],
    dbs: Option<Vec<Arc<Database>>>,
    background: bool,
    heartbeat_ms: u64,
    rpcs: &Arc<AtomicU64>,
) -> Vec<Raft<TC>> {
    let config = Arc::new(
        Config {
            heartbeat_interval: heartbeat_ms,
            election_timeout_min: heartbeat_ms * 3 + 100,
            election_timeout_max: heartbeat_ms * 6 + 200,
            ..Default::default()
        }
        .validate()
        .unwrap(),
    );
    let router = Router {
        rafts: Arc::new(OnceLock::new()),
        rpcs: rpcs.clone(),
    };
    let mut rafts = BTreeMap::new();
    for (position, id) in members.iter().enumerate() {
        let db = dbs.as_ref().map(|dbs| dbs[position].clone());
        let raft = Raft::new(
            *id,
            config.clone(),
            router.clone(),
            LogStore::new(db, background),
            StateMachine::default(),
        )
        .await
        .unwrap();
        rafts.insert(*id, raft);
    }
    let _ = router.rafts.set(rafts.clone());
    let nodes: BTreeMap<NodeId, BasicNode> = members
        .iter()
        .map(|id| (*id, BasicNode::default()))
        .collect();
    rafts[&members[0]].initialize(nodes).await.unwrap();
    members.iter().map(|id| rafts[id].clone()).collect()
}

fn leader_of(rafts: &[Raft<TC>]) -> Option<usize> {
    rafts
        .iter()
        .position(|r| r.metrics().borrow().state == ServerState::Leader)
}

fn data_dir() -> std::path::PathBuf {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join(format!("data-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn percentile(sorted: &[Duration], p: f64) -> Duration {
    sorted[((sorted.len() - 1) as f64 * p) as usize]
}

fn throughput(storage: &str, payload: usize, concurrency: usize, seconds: u64) {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(8)
        .enable_all()
        .build()
        .unwrap();
    let rpcs = Arc::new(AtomicU64::new(0));
    let dir = data_dir();
    let dbs = storage.starts_with("redb").then(|| {
        (1..=3)
            .map(|n| {
                let path = dir.join(format!("node{n}.redb"));
                let _ = std::fs::remove_file(&path);
                Arc::new(Database::create(path).unwrap())
            })
            .collect()
    });
    let rafts = rt.block_on(spawn_group([1, 2, 3], dbs, storage == "redb-bg", 50, &rpcs));
    let deadline = Instant::now() + Duration::from_secs(10);
    let leader = loop {
        if let Some(leader) = leader_of(&rafts) {
            break rafts[leader].clone();
        }
        assert!(Instant::now() < deadline, "no leader elected");
        std::thread::sleep(Duration::from_millis(10));
    };
    std::thread::sleep(Duration::from_millis(300));

    let stop_at = Instant::now() + Duration::from_secs(seconds);
    let mut sorted: Vec<Duration> = rt.block_on(async move {
        let mut tasks = Vec::new();
        for _ in 0..concurrency {
            let leader = leader.clone();
            tasks.push(tokio::spawn(async move {
                let mut samples = Vec::new();
                while Instant::now() < stop_at {
                    let started = Instant::now();
                    leader
                        .client_write(vec![0xa5; payload])
                        .await
                        .expect("write");
                    samples.push(started.elapsed());
                }
                samples
            }));
        }
        let mut all = Vec::new();
        for task in tasks {
            all.extend(task.await.unwrap());
        }
        all
    });
    sorted.sort();
    let rate = sorted.len() as f64 / seconds as f64;
    println!(
        "openraft {storage:>7} payload {payload:>6} B  concurrency {concurrency:>3}: \
         {rate:>8.0} commits/s ({:>7.1} MiB/s)  p50 {:>7.2} ms  p99 {:>7.2} ms",
        rate * payload as f64 / (1024.0 * 1024.0),
        percentile(&sorted, 0.50).as_secs_f64() * 1e3,
        percentile(&sorted, 0.99).as_secs_f64() * 1e3,
    );
    rt.shutdown_background();
    let _ = std::fs::remove_dir_all(&dir);
}

fn cpu_seconds() -> f64 {
    let stat = std::fs::read_to_string("/proc/self/stat").unwrap();
    let fields: Vec<&str> = stat
        .rsplit(')')
        .next()
        .unwrap()
        .split_whitespace()
        .collect();
    (fields[11].parse::<f64>().unwrap() + fields[12].parse::<f64>().unwrap()) / 100.0
}

fn proc_status(field: &str) -> usize {
    std::fs::read_to_string("/proc/self/status")
        .unwrap()
        .lines()
        .find(|l| l.starts_with(field))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|n| n.parse().ok())
        .unwrap_or(0)
}

fn groups(count: usize, heartbeat_ms: u64) {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap();
    let rpcs = Arc::new(AtomicU64::new(0));
    let all: Vec<Vec<Raft<TC>>> = rt.block_on(async {
        let mut all = Vec::new();
        for g in 0..count as NodeId {
            all.push(
                spawn_group(
                    [g * 3 + 1, g * 3 + 2, g * 3 + 3],
                    None,
                    false,
                    heartbeat_ms,
                    &rpcs,
                )
                .await,
            );
        }
        all
    });
    let deadline = Instant::now() + Duration::from_secs(120);
    let leaders = || all.iter().filter(|g| leader_of(g).is_some()).count();
    while leaders() < count && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(100));
    }
    std::thread::sleep(Duration::from_secs(2));
    let elected = leaders();
    let cpu_before = cpu_seconds();
    let rpc_before = rpcs.load(Ordering::Relaxed);
    let window = Duration::from_secs(10);
    std::thread::sleep(window);
    let cpu = (cpu_seconds() - cpu_before) / window.as_secs_f64();
    let rate = (rpcs.load(Ordering::Relaxed) - rpc_before) as f64 / window.as_secs_f64();
    println!(
        "openraft, hb {heartbeat_ms} ms: {count} groups × 3 nodes, {elected} leaders, {} threads, \
         RSS {} MiB, idle CPU {:.1}% of one core, {rate:.0} RPC/s",
        proc_status("Threads:"),
        proc_status("VmRSS:") / 1024,
        cpu * 100.0,
    );
    rt.shutdown_background();
}

fn main() {
    let mode = std::env::args().nth(1).unwrap_or_default();
    match mode.as_str() {
        "throughput" => {
            for (storage, payload, concurrency) in [
                ("mem", 1024, 1),
                ("mem", 1024, 64),
                ("redb", 1024, 64),
                ("redb-bg", 1024, 1),
                ("redb-bg", 1024, 16),
                ("redb-bg", 1024, 64),
                ("redb-bg", 1024, 256),
                ("redb-bg", 16384, 64),
                ("redb-bg", 65536, 16),
            ] {
                throughput(storage, payload, concurrency, 4);
            }
        }
        "groups" => {
            let count = std::env::args()
                .nth(2)
                .and_then(|g| g.parse().ok())
                .unwrap_or(1000);
            let heartbeat = std::env::args()
                .nth(3)
                .and_then(|h| h.parse().ok())
                .unwrap_or(50);
            groups(count, heartbeat);
        }
        _ => eprintln!("usage: openraft_ref throughput | groups <count> [heartbeat_ms]"),
    }
}
