//! Raft log benchmarks for the per-agent log design.
//!
//! `throughput`: one 3-node group in one process, redb or memory storage,
//! concurrent proposers. Reports commits per second and propose→commit
//! latency on the leader.
//!
//! `groups`: G mostly idle groups × 3 nodes in one process. Reports threads,
//! idle CPU and RPC rate for vos-raft's per-thread `Worker` driver and for
//! `run_worker` futures on one shared tokio runtime.

use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use futures_channel::{mpsc, oneshot};
use redb::{Database, Durability, TableDefinition};
#[cfg(not(feature = "eager"))]
use vos_raft as raft;
#[cfg(feature = "eager")]
use vos_raft_eager as raft;

use raft::worker::run_worker;
use raft::{
    AppendEntriesReq, AppendEntriesResp, ApplySink, Config, EntryKind, InstallSnapshotReq,
    InstallSnapshotResp, LogEntry, MemStorage, Meta, PreVoteReq, PreVoteResp, RaftMsg,
    RequestVoteReq, RequestVoteResp, Rng, Role, Storage, TokioClock, Transport, Worker,
    WriteBatch,
};

type N = u32;

// ── Transport ───────────────────────────────────────────────

#[derive(Clone)]
enum PeerTx {
    Raw(mpsc::UnboundedSender<RaftMsg<N>>),
    Inbox(raft::worker::Inbox<N>),
}

impl PeerTx {
    fn send(&self, msg: RaftMsg<N>) -> bool {
        match self {
            Self::Raw(tx) => tx.unbounded_send(msg).is_ok(),
            Self::Inbox(inbox) => inbox.send(msg).is_ok(),
        }
    }
}

#[derive(Clone)]
struct InProc {
    me: N,
    peers: Arc<OnceLock<HashMap<N, PeerTx>>>,
    rpcs: Arc<AtomicU64>,
}

impl InProc {
    async fn call<R>(
        &self,
        peer: N,
        make: impl FnOnce(oneshot::Sender<R>) -> RaftMsg<N>,
    ) -> Result<R, String> {
        self.rpcs.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = oneshot::channel();
        let peers = self.peers.get().ok_or("peers not bound")?;
        if !peers.get(&peer).ok_or("unknown peer")?.send(make(tx)) {
            return Err("closed".into());
        }
        rx.await.map_err(|_| "dropped".to_string())
    }
}

impl Transport<N> for InProc {
    type Error = String;

    async fn send_append(&self, peer: N, req: AppendEntriesReq<N>) -> Result<AppendEntriesResp, String> {
        let from = self.me;
        self.call(peer, |reply| RaftMsg::AppendEntries { from, req, reply }).await
    }

    async fn send_vote(&self, peer: N, req: RequestVoteReq<N>) -> Result<RequestVoteResp, String> {
        let from = self.me;
        self.call(peer, |reply| RaftMsg::RequestVote { from, req, reply }).await
    }

    async fn send_prevote(&self, peer: N, req: PreVoteReq<N>) -> Result<PreVoteResp, String> {
        let from = self.me;
        self.call(peer, |reply| RaftMsg::PreVote { from, req, reply }).await
    }

    async fn send_install(
        &self,
        peer: N,
        req: InstallSnapshotReq<N>,
    ) -> Result<InstallSnapshotResp, String> {
        let from = self.me;
        self.call(peer, |reply| RaftMsg::InstallSnapshot { from, req, reply }).await
    }
}

// ── Commit notification and RNG ─────────────────────────────

#[derive(Clone)]
struct CommitSink(Arc<tokio::sync::watch::Sender<u64>>);

impl ApplySink for CommitSink {
    fn notify(&self, commit_index: u64) {
        self.0.send_replace(commit_index);
    }
}

struct XorShift(u64);

impl Rng for XorShift {
    fn next_u64(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}

// ── redb storage ────────────────────────────────────────────


fn encode_entry(entry: &LogEntry<N>) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&entry.term.to_le_bytes());
    match &entry.kind {
        EntryKind::Data { payload } => {
            out.push(0);
            out.extend_from_slice(payload);
        }
        EntryKind::ConfigChange { joint_old, members } => {
            out.push(1);
            let mut put = |list: &[N]| {
                out.extend_from_slice(&(list.len() as u32).to_le_bytes());
                for node in list {
                    out.extend_from_slice(&node.to_le_bytes());
                }
            };
            put(members);
            if let Some(old) = joint_old {
                put(old);
            }
        }
        _ => unreachable!("unknown entry kind"),
    }
    out
}

fn encode_meta(meta: &Meta<N>) -> Vec<u8> {
    let mut out = Vec::new();
    for value in [
        meta.current_term,
        meta.voted_for.map_or(u64::MAX, u64::from),
        meta.commit_index,
        meta.snap_last_index,
        meta.snap_last_term,
    ] {
        out.extend_from_slice(&value.to_le_bytes());
    }
    out
}

/// Durable log in redb (one fsync per batch); reads served from an in-memory
/// mirror, as a production backend would cache the log tail. Several groups
/// may share one database.
struct RedbStorage {
    backend: Backend,
    group: N,
    log: BTreeMap<u64, LogEntry<N>>,
    meta: Meta<N>,
}

enum Backend {
    /// Commit in the calling task (blocks an executor thread on fsync).
    Inline(Arc<Database>),
    /// Hand the write to the node's log writer, which commits the pending
    /// writes of every group in one transaction and one fsync.
    Writer(std::sync::mpsc::Sender<WriterReq>),
}

const LOG: TableDefinition<(N, u64), &[u8]> = TableDefinition::new("log");
const META: TableDefinition<N, &[u8]> = TableDefinition::new("meta");

/// One group's share of a store transaction. All groups on a node share one
/// log table keyed by (group, index).
struct TableWrite {
    group: N,
    remove: Vec<u64>,
    insert: Vec<(u64, Vec<u8>)>,
    meta: Option<Vec<u8>>,
}

impl TableWrite {
    fn apply(&self, txn: &redb::WriteTransaction) -> Result<(), String> {
        let mut log = txn.open_table(LOG).map_err(|e| e.to_string())?;
        for index in &self.remove {
            log.remove((self.group, *index)).map_err(|e| e.to_string())?;
        }
        for (index, bytes) in &self.insert {
            log.insert((self.group, *index), bytes.as_slice()).map_err(|e| e.to_string())?;
        }
        if let Some(meta) = &self.meta {
            let mut table = txn.open_table(META).map_err(|e| e.to_string())?;
            table.insert(self.group, meta.as_slice()).map_err(|e| e.to_string())?;
        }
        Ok(())
    }
}

struct WriterReq {
    write: TableWrite,
    durable: bool,
    done: oneshot::Sender<Result<(), String>>,
}

/// One writer thread per node: drains every queued write, commits them in a
/// single transaction (one fsync if any is durable) and acknowledges all.
fn spawn_log_writer(db: Arc<Database>, commits: Arc<AtomicU64>) -> std::sync::mpsc::Sender<WriterReq> {
    let (tx, rx) = std::sync::mpsc::channel::<WriterReq>();
    std::thread::spawn(move || {
        while let Ok(first) = rx.recv() {
            let mut reqs = vec![first];
            reqs.extend(rx.try_iter());
            let result = (|| {
                let mut txn = db.begin_write().map_err(|e| e.to_string())?;
                let durable = reqs.iter().any(|r| r.durable);
                txn.set_durability(if durable { Durability::Immediate } else { Durability::None });
                for req in &reqs {
                    req.write.apply(&txn)?;
                }
                txn.commit().map_err(|e| e.to_string())
            })();
            commits.fetch_add(1, Ordering::Relaxed);
            for req in reqs {
                let _ = req.done.send(result.clone());
            }
        }
    });
    tx
}

fn create_db(path: &std::path::Path) -> Arc<Database> {
    let _ = std::fs::remove_file(path);
    Arc::new(Database::create(path).expect("create redb"))
}

impl RedbStorage {
    fn create(path: &std::path::Path) -> Self {
        Self::shared(create_db(path), 0)
    }

    fn shared(db: Arc<Database>, group: N) -> Self {
        Self::with_backend(Backend::Inline(db), group)
    }

    fn with_backend(backend: Backend, group: N) -> Self {
        Self {
            backend,
            group,
            log: BTreeMap::new(),
            meta: Meta::default(),
        }
    }
}

impl Storage<N> for RedbStorage {
    type Error = String;

    fn last_index(&self) -> u64 {
        self.log
            .last_key_value()
            .map_or(self.meta.snap_last_index, |(index, _)| *index)
    }

    fn last_term(&self) -> u64 {
        self.log
            .last_key_value()
            .map_or(self.meta.snap_last_term, |(_, entry)| entry.term)
    }

    fn snap_last_index(&self) -> u64 {
        self.meta.snap_last_index
    }

    fn snap_last_term(&self) -> u64 {
        self.meta.snap_last_term
    }

    async fn term_at(&self, index: u64) -> Result<Option<u64>, String> {
        if index == 0 {
            return Ok(Some(0));
        }
        if index == self.meta.snap_last_index {
            return Ok(Some(self.meta.snap_last_term));
        }
        Ok(self.log.get(&index).map(|entry| entry.term))
    }

    async fn entries(&self, start: u64, end: u64) -> Result<Vec<LogEntry<N>>, String> {
        if start > end {
            return Ok(Vec::new());
        }
        Ok(self.log.range(start..=end).map(|(_, e)| e.clone()).collect())
    }

    async fn read_state(&self) -> Result<Vec<u8>, String> {
        Ok(Vec::new())
    }

    async fn load_meta(&self) -> Result<Meta<N>, String> {
        Ok(self.meta.clone())
    }

    async fn commit_batch(&mut self, batch: WriteBatch<N>) -> Result<(), String> {
        // A batch that only moves commit_index needs no fsync: commit_index
        // is volatile in Raft, and the next durable batch persists it.
        let commit_only = batch.appends.is_empty()
            && batch.truncate_after.is_none()
            && batch.compact_to.is_none()
            && batch.meta.as_ref().is_none_or(|m| {
                m.current_term == self.meta.current_term && m.voted_for == self.meta.voted_for
            });
        let mut remove: Vec<u64> = Vec::new();
        if let Some(after) = batch.truncate_after {
            remove.extend(self.log.range(after + 1..).map(|(i, _)| *i));
        }
        if let Some((to, _)) = batch.compact_to {
            remove.extend(self.log.range(..=to).map(|(i, _)| *i));
        }
        let write = TableWrite {
            group: self.group,
            remove,
            insert: batch.appends.iter().map(|e| (e.index, encode_entry(e))).collect(),
            meta: batch.meta.as_ref().map(encode_meta),
        };
        match &self.backend {
            Backend::Inline(db) => {
                let mut txn = db.begin_write().map_err(|e| e.to_string())?;
                txn.set_durability(if commit_only { Durability::None } else { Durability::Immediate });
                write.apply(&txn)?;
                txn.commit().map_err(|e| e.to_string())?;
            }
            Backend::Writer(writer) => {
                let (done, wait) = oneshot::channel();
                writer
                    .send(WriterReq {
                        write,
                        durable: !commit_only,
                        done,
                    })
                    .map_err(|_| "log writer gone".to_string())?;
                wait.await.map_err(|_| "log writer dropped".to_string())??;
            }
        }

        if let Some(after) = batch.truncate_after {
            self.log.split_off(&(after + 1));
        }
        if let Some((to, term)) = batch.compact_to {
            self.log = self.log.split_off(&(to + 1));
            self.meta.snap_last_index = to;
            self.meta.snap_last_term = term;
        }
        for entry in batch.appends {
            self.log.insert(entry.index, entry);
        }
        if let Some(meta) = batch.meta {
            self.meta = meta;
        }
        Ok(())
    }
}

// ── Cluster setup on a shared runtime ───────────────────────

struct Node {
    tx: mpsc::UnboundedSender<RaftMsg<N>>,
    role: Arc<AtomicU8>,
    commit: tokio::sync::watch::Receiver<u64>,
}

fn config(me: N, members: &[N], heartbeat_ms: u64) -> Config<N> {
    let mut cfg = Config::new(me, members.to_vec(), [7; 32]);
    cfg.heartbeat_interval_ms = heartbeat_ms;
    cfg.election_timeout_ms = (heartbeat_ms * 3 + 100, heartbeat_ms * 6 + 200);
    cfg
}

fn spawn_group<S: Storage<N> + Send + Sync + 'static>(
    rt: &tokio::runtime::Handle,
    members: &[N],
    mut storages: Vec<S>,
    heartbeat_ms: u64,
    rpcs: &Arc<AtomicU64>,
) -> Vec<Node> {
    let peers = Arc::new(OnceLock::new());
    let mut map = HashMap::new();
    let mut nodes = Vec::new();
    for (position, me) in members.iter().enumerate() {
        let (tx, rx) = mpsc::unbounded();
        map.insert(*me, PeerTx::Raw(tx.clone()));
        let (commit_tx, commit_rx) = tokio::sync::watch::channel(0u64);
        let role = Arc::new(AtomicU8::new(0));
        let transport = Arc::new(InProc {
            me: *me,
            peers: peers.clone(),
            rpcs: rpcs.clone(),
        });
        let storage = storages.remove(0);
        let cfg = config(*me, members, heartbeat_ms);
        let sink = CommitSink(Arc::new(commit_tx));
        let rng = XorShift(0x9e37_79b9_7f4a_7c15 ^ (u64::from(*me) << 17) ^ position as u64);
        rt.spawn(run_worker(
            storage,
            transport,
            cfg,
            rx,
            sink,
            TokioClock,
            rng,
            role.clone(),
            |_| {},
        ));
        nodes.push(Node {
            tx,
            role,
            commit: commit_rx,
        });
    }
    let _ = peers.set(map);
    nodes
}

fn leader_of(nodes: &[Node]) -> Option<usize> {
    nodes
        .iter()
        .position(|n| Role::from_u8(n.role.load(Ordering::Relaxed)) == Role::Leader)
}

fn percentile(sorted: &[Duration], p: f64) -> Duration {
    sorted[((sorted.len() - 1) as f64 * p) as usize]
}

/// A scratch directory on the real disk: /tmp is often tmpfs, where fsync is
/// free.
fn data_dir() -> std::path::PathBuf {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join(format!("data-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

// ── Throughput ──────────────────────────────────────────────

fn throughput(storage: &str, payload: usize, concurrency: usize, heartbeat_ms: u64, seconds: u64) {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(8)
        .enable_time()
        .build()
        .unwrap();
    let rpcs = Arc::new(AtomicU64::new(0));
    let members = [1, 2, 3];
    let dir = data_dir();
    let nodes = match storage {
        "redb" => spawn_group(
            rt.handle(),
            &members,
            members
                .iter()
                .map(|m| RedbStorage::create(&dir.join(format!("node{m}.redb"))))
                .collect(),
            heartbeat_ms,
            &rpcs,
        ),
        _ => spawn_group(
            rt.handle(),
            &members,
            members.iter().map(|_| MemStorage::<N>::new()).collect(),
            heartbeat_ms,
            &rpcs,
        ),
    };
    let deadline = Instant::now() + Duration::from_secs(10);
    let leader = loop {
        if let Some(leader) = leader_of(&nodes) {
            break leader;
        }
        assert!(Instant::now() < deadline, "no leader elected");
        std::thread::sleep(Duration::from_millis(10));
    };
    std::thread::sleep(Duration::from_millis(300));

    let tx = nodes[leader].tx.clone();
    let commit = nodes[leader].commit.clone();
    let stop_at = Instant::now() + Duration::from_secs(seconds);
    let latencies = rt.block_on(async move {
        let mut tasks = Vec::new();
        for _ in 0..concurrency {
            let tx = tx.clone();
            let mut commit = commit.clone();
            tasks.push(tokio::spawn(async move {
                let mut samples = Vec::new();
                while Instant::now() < stop_at {
                    let started = Instant::now();
                    let (reply, rx) = oneshot::channel();
                    tx.unbounded_send(RaftMsg::Propose {
                        payload: vec![0xa5; payload],
                        reply,
                    })
                    .expect("leader inbox");
                    let index = rx.await.expect("reply").expect("propose");
                    commit.wait_for(|c| *c >= index).await.expect("commit");
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
    let mut sorted = latencies;
    sorted.sort();
    let rate = sorted.len() as f64 / seconds as f64;
    println!(
        "{storage:>5} payload {:>6} B  concurrency {concurrency:>3}  heartbeat {heartbeat_ms:>3} ms: \
         {:>8.0} commits/s ({:>7.1} MiB/s)  p50 {:>7.2} ms  p99 {:>7.2} ms",
        payload,
        rate,
        rate * payload as f64 / (1024.0 * 1024.0),
        percentile(&sorted, 0.50).as_secs_f64() * 1e3,
        percentile(&sorted, 0.99).as_secs_f64() * 1e3,
    );
    rt.shutdown_background();
    let _ = std::fs::remove_dir_all(&dir);
}

// ── Many idle groups ────────────────────────────────────────

fn cpu_seconds() -> f64 {
    let stat = std::fs::read_to_string("/proc/self/stat").unwrap();
    let fields: Vec<&str> = stat.rsplit(')').next().unwrap().split_whitespace().collect();
    // utime and stime are fields 14 and 15; after the comm field they are
    // at offsets 11 and 12.
    let ticks: f64 = fields[11].parse::<f64>().unwrap() + fields[12].parse::<f64>().unwrap();
    ticks / 100.0
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

fn measure_idle(label: &str, groups: usize, rpcs: &Arc<AtomicU64>, leaders: impl Fn() -> usize) {
    let deadline = Instant::now() + Duration::from_secs(120);
    while leaders() < groups && Instant::now() < deadline {
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
        "{label:>22}: {groups} groups × 3 nodes, {elected} leaders, {} threads, RSS {} MiB, \
         idle CPU {:.1}% of one core, {:.0} RPC/s",
        proc_status("Threads:"),
        proc_status("VmRSS:") / 1024,
        cpu * 100.0,
        rate,
    );
}

fn groups_shared(groups: usize, heartbeat_ms: u64, worker_threads: usize) {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(worker_threads)
        .enable_time()
        .build()
        .unwrap();
    let rpcs = Arc::new(AtomicU64::new(0));
    let mut all = Vec::new();
    for group in 0..groups as N {
        let members = [group * 3 + 1, group * 3 + 2, group * 3 + 3];
        all.push(spawn_group(
            rt.handle(),
            &members,
            members.iter().map(|_| MemStorage::<N>::new()).collect(),
            heartbeat_ms,
            &rpcs,
        ));
    }
    measure_idle(
        &format!("shared runtime, hb {heartbeat_ms} ms"),
        groups,
        &rpcs,
        || all.iter().filter(|nodes| leader_of(nodes).is_some()).count(),
    );
    rt.shutdown_background();
}

fn groups_threaded(groups: usize, heartbeat_ms: u64) {
    let rpcs = Arc::new(AtomicU64::new(0));
    let mut all: Vec<Vec<Worker<N>>> = Vec::new();
    for group in 0..groups as N {
        let members = [group * 3 + 1, group * 3 + 2, group * 3 + 3];
        let peers = Arc::new(OnceLock::new());
        let mut workers = Vec::new();
        let mut map = HashMap::new();
        for me in members {
            let transport = Arc::new(InProc {
                me,
                peers: peers.clone(),
                rpcs: rpcs.clone(),
            });
            let worker = Worker::spawn(
                MemStorage::<N>::new(),
                transport,
                config(me, &members, heartbeat_ms),
                None,
            );
            map.insert(me, PeerTx::Inbox(worker.handler().sender()));
            workers.push(worker);
        }
        let _ = peers.set(map);
        all.push(workers);
    }
    measure_idle("thread per group", groups, &rpcs, || {
        all.iter()
            .filter(|w| w.iter().any(|w| w.role() == Role::Leader))
            .count()
    });
    for workers in all {
        for worker in workers {
            worker.shutdown();
        }
    }
}

fn main() {
    let mode = std::env::args().nth(1).unwrap_or_default();
    match mode.as_str() {
        "throughput" => {
            for (storage, payload, concurrency, heartbeat) in [
                ("mem", 1024, 1, 50),
                ("mem", 1024, 64, 50),
                ("redb", 1024, 1, 50),
                ("redb", 1024, 16, 50),
                ("redb", 1024, 64, 50),
                ("redb", 1024, 256, 50),
                ("redb", 1024, 64, 5),
                ("redb", 16384, 64, 50),
                ("redb", 65536, 16, 50),
            ] {
                throughput(storage, payload, concurrency, heartbeat, 4);
            }
        }
        "groups" => {
            let groups: usize = std::env::args().nth(2).and_then(|g| g.parse().ok()).unwrap_or(1000);
            let which = std::env::args().nth(3).unwrap_or_else(|| "shared".into());
            let heartbeat: u64 = std::env::args().nth(4).and_then(|h| h.parse().ok()).unwrap_or(50);
            match which.as_str() {
                "threaded" => groups_threaded(groups, heartbeat),
                _ => groups_shared(groups, heartbeat, 4),
            }
        }
        "disk" => disk(),
        "one" => {
            // `one <mem|redb> <payload bytes> <concurrency> [heartbeat_ms]`
            let arg = |n: usize| std::env::args().nth(n).unwrap_or_default();
            throughput(
                &arg(2),
                arg(3).parse().unwrap(),
                arg(4).parse().unwrap(),
                arg(5).parse().unwrap_or(50),
                4,
            );
        }
        "active" => {
            let groups: usize = std::env::args().nth(2).and_then(|g| g.parse().ok()).unwrap_or(16);
            let concurrency: usize = std::env::args().nth(3).and_then(|c| c.parse().ok()).unwrap_or(16);
            let layout = std::env::args().nth(4).unwrap_or_else(|| "separate".into());
            active(groups, concurrency, &layout);
        }
        _ => eprintln!(
            "usage: s3-raft throughput | groups <count> [shared|threaded] [heartbeat_ms] | disk \
             | active <groups> <concurrency> [separate|shared|node-log]"
        ),
    }
}

// ── Disk: raw append + fdatasync versus a redb commit ───────

fn disk() {
    use std::io::Write;
    let dir = data_dir();
    let window = Duration::from_secs(2);
    for (size, per_sync) in [(1024, 1), (1024, 64), (16384, 1), (65536, 1), (262_144, 1)] {
        let payload = vec![0xa5u8; size];

        let path = dir.join("raw.log");
        let _ = std::fs::remove_file(&path);
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .unwrap();
        let started = Instant::now();
        let mut syncs = 0u64;
        while started.elapsed() < window {
            for _ in 0..per_sync {
                file.write_all(&payload).unwrap();
            }
            file.sync_data().unwrap();
            syncs += 1;
        }
        let raw = started.elapsed().as_secs_f64() / syncs as f64;

        let db = create_db(&dir.join("bench.redb"));
        let table = TableDefinition::<u64, &[u8]>::new("log");
        let started = Instant::now();
        let mut commits = 0u64;
        let mut key = 0u64;
        while started.elapsed() < window {
            let mut txn = db.begin_write().unwrap();
            txn.set_durability(Durability::Immediate);
            {
                let mut t = txn.open_table(table).unwrap();
                for _ in 0..per_sync {
                    t.insert(key, payload.as_slice()).unwrap();
                    key += 1;
                }
            }
            txn.commit().unwrap();
            commits += 1;
        }
        let redb = started.elapsed().as_secs_f64() / commits as f64;
        println!(
            "{size:>7} B × {per_sync:>2} per sync: raw append+fdatasync {:>7.0} µs ({:>6.0} entries/s), \
             redb commit {:>7.0} µs ({:>6.0} entries/s)",
            raw * 1e6,
            per_sync as f64 / raw,
            redb * 1e6,
            per_sync as f64 / redb,
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

// ── Many active groups: separate stores versus one per node ─

fn active(groups: usize, concurrency: usize, layout: &str) {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(8)
        .enable_time()
        .build()
        .unwrap();
    let rpcs = Arc::new(AtomicU64::new(0));
    let dir = data_dir();
    let node_dbs: Vec<Arc<Database>> = (1..=3)
        .map(|n| create_db(&dir.join(format!("node{n}.redb"))))
        .collect();
    let writer_commits = Arc::new(AtomicU64::new(0));
    let writers: Vec<_> = node_dbs
        .iter()
        .map(|db| spawn_log_writer(db.clone(), writer_commits.clone()))
        .collect();
    let mut all = Vec::new();
    for group in 0..groups as N {
        let members = [group * 3 + 1, group * 3 + 2, group * 3 + 3];
        let storages = (0..3)
            .map(|n| match layout {
                "shared" => RedbStorage::shared(node_dbs[n].clone(), group),
                "node-log" => RedbStorage::with_backend(Backend::Writer(writers[n].clone()), group),
                _ => RedbStorage::create(&dir.join(format!("g{group}-n{n}.redb"))),
            })
            .collect();
        all.push(spawn_group(rt.handle(), &members, storages, 50, &rpcs));
    }
    let deadline = Instant::now() + Duration::from_secs(60);
    let leaders: Vec<usize> = loop {
        let found: Vec<Option<usize>> = all.iter().map(|nodes| leader_of(nodes)).collect();
        if found.iter().all(Option::is_some) {
            break found.into_iter().map(Option::unwrap).collect();
        }
        assert!(Instant::now() < deadline, "not every group elected a leader");
        std::thread::sleep(Duration::from_millis(20));
    };
    std::thread::sleep(Duration::from_millis(300));

    let seconds = 4;
    let commits_before = writer_commits.load(Ordering::Relaxed);
    let lost = Arc::new(AtomicU64::new(0));
    let stop_at = Instant::now() + Duration::from_secs(seconds);
    let mut tasks = Vec::new();
    for (nodes, leader) in all.iter().zip(&leaders) {
        for _ in 0..concurrency {
            let tx = nodes[*leader].tx.clone();
            let mut commit = nodes[*leader].commit.clone();
            let lost = lost.clone();
            tasks.push(rt.spawn(async move {
                let mut samples = Vec::new();
                while Instant::now() < stop_at {
                    let started = Instant::now();
                    let (reply, rx) = oneshot::channel();
                    tx.unbounded_send(RaftMsg::Propose {
                        payload: vec![0xa5; 1024],
                        reply,
                    })
                    .expect("leader inbox");
                    let Ok(index) = rx.await.expect("reply") else {
                        // Leadership moved; this proposer stops.
                        lost.fetch_add(1, Ordering::Relaxed);
                        break;
                    };
                    let committed = tokio::time::timeout_at(
                        tokio::time::Instant::from_std(stop_at + Duration::from_secs(1)),
                        commit.wait_for(|c| *c >= index),
                    )
                    .await;
                    if !matches!(committed, Ok(Ok(_))) {
                        lost.fetch_add(1, Ordering::Relaxed);
                        break;
                    }
                    samples.push(started.elapsed());
                }
                samples
            }));
        }
    }
    let mut sorted: Vec<Duration> = rt.block_on(async move {
        let mut all = Vec::new();
        for task in tasks {
            all.extend(task.await.unwrap());
        }
        all
    });
    sorted.sort();
    let node_commits = (writer_commits.load(Ordering::Relaxed) - commits_before) as f64 / 3.0;
    println!(
        "{layout:>8} stores: {groups:>4} active groups × {concurrency:>3} proposers, 1 KiB: \
         {:>8.0} commits/s total  p50 {:>7.2} ms  p99 {:>7.2} ms{}",
        sorted.len() as f64 / seconds as f64,
        percentile(&sorted, 0.50).as_secs_f64() * 1e3,
        percentile(&sorted, 0.99).as_secs_f64() * 1e3,
        if node_commits > 0.0 {
            format!("  ({:.0} store commits/s per node)", node_commits / seconds as f64)
        } else {
            String::new()
        },
    );
    let lost = lost.load(Ordering::Relaxed);
    if lost > 0 {
        println!("          {lost} proposers stopped after losing their leader");
    }
    rt.shutdown_background();
    let _ = std::fs::remove_dir_all(&dir);
}
