//! A node's start and stop: its data directory, its store and blobs, its
//! threads, and its space's network.

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread::JoinHandle;
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::SigningKey;
use vos_net::Network;
use vos_pvm::PvmBackend;
use vos_pvm::pool::{CodeHash, MachinePool, OuterMachines};
use vos_wire::defaults;
use vos_wire::ids::ProgramHash;
use vos_wire::ingress::NodeId;
use vos_wire::peer::{CreationRecord, Placement};

use super::{Config, Directory, Error, Inner, Node, Peers, Run, Settings, Tasks};
use crate::blobs::Blobs;
use crate::executor::Executors;
use crate::storage::StorageThread;
use crate::store::{Fjall, PersistMode};
use crate::{lock, seed};

/// The node's data directory: its store, and the operator's token. A
/// stopped node's store may be opened at `STORE` in it.
pub const STORE: &str = "store";
const BLOBS: &str = "blobs";
pub const ADMIN_TOKEN: &str = "admin.token";
/// The node's public key, in hex, in its data directory: for operator
/// commands on the node's host to pin its TLS by.
pub const NODE_KEY: &str = "node.key";

impl Node {
    /// Open the node's data directory `data` (its store and admin token),
    /// join its space and start every agent it replicates.
    pub fn open(data: impl AsRef<Path>, config: Config) -> Result<Self, Error> {
        let largest = defaults::MAX_HANDLER_GAS
            + defaults::STEP_RESERVE.max(defaults::INSTALL_RESERVE)
            + defaults::FINISH_RESERVE;
        if config.refine_gas < largest {
            return Err(Error::Gas);
        }
        let data = data.as_ref().to_path_buf();
        private_dir(&data).map_err(Error::Data)?;
        let store = Fjall::open(data.join(STORE))?;
        let secret = match store.node_secret()? {
            Some(secret) => secret,
            None => {
                let secret = seed();
                let mut batch = store.batch();
                batch.node_secret(&secret);
                batch.commit(PersistMode::SyncAll)?;
                secret
            }
        };
        // Each run's pair heartbeat outranks the last run's, whatever the
        // clock did between them.
        let incarnation = crate::liveness::next_incarnation(store.incarnation()?);
        let mut batch = store.batch();
        batch.incarnation(incarnation);
        batch.commit(PersistMode::SyncAll)?;
        let node_id = NodeId(SigningKey::from_bytes(&secret).verifying_key().to_bytes());
        let hex: String = node_id.0.iter().map(|byte| format!("{byte:02x}")).collect();
        std::fs::write(data.join(NODE_KEY), &hex)
            .map_err(|error| Error::Data(error.to_string()))?;
        let number = match &config.space {
            Some(space) => {
                space
                    .by_key(&node_id.0)
                    .ok_or_else(|| {
                        Error::Data(format!("this node's key, {hex}, is not in its space"))
                    })?
                    .number
            }
            None => 0,
        };
        let blobs = Blobs::open(data.join(BLOBS), &store)?;
        let pool = Arc::new(MachinePool::new());
        for hash in blobs.pinned()? {
            let blob = blobs
                .get(&hash)?
                .ok_or_else(|| Error::Program("a pinned program's blob is missing".into()))?;
            pool.install(&blob)
                .map_err(|error| Error::Program(format!("{error:?}")))?;
        }
        // Agent programs run only on executors, one at a time on each: keep
        // as many machines idle as can run at once.
        let program =
            OuterMachines::with_idle_limit(&config.agent, PvmBackend::Default, config.executors)
                .map_err(|error| Error::Program(format!("{error:?}")))?;
        let program_hash = ProgramHash(CodeHash::of(&config.agent).0);
        let records = store.agents()?;
        let mut placements = store.placements()?;
        let (network, arrivals): (Option<Arc<dyn Network>>, _) =
            match (&config.space, &config.peers) {
                (Some(space), Peers::Quic) if space.nodes().len() > 1 => {
                    let listen = config
                        .peer_bind
                        .unwrap_or(space.node(number).expect("this node is in its space").peer);
                    let (quic, arrivals) = vos_net::quic::Quic::bind(vos_net::quic::Config {
                        peers: space.peers(),
                        idle: config.quic_idle,
                        ..vos_net::quic::Config::new(number, secret, listen)
                    })
                    .map_err(|error| Error::Data(format!("{listen}: {error}")))?;
                    (Some(Arc::new(quic)), Some(arrivals))
                }
                (Some(space), Peers::Hub(hub)) => {
                    let (endpoint, arrivals) = hub.join(number);
                    endpoint.set_peers(space.peers());
                    (Some(Arc::new(endpoint)), Some(arrivals))
                }
                _ => (None, None),
            };
        // Frames of a class a test loses go before they reach the network.
        #[cfg(feature = "faults")]
        let network = match (network, &config.faults) {
            (Some(network), Some(faults)) => Some(Arc::new(crate::faults::Lossy {
                network,
                faults: Arc::clone(faults),
            }) as Arc<dyn Network>),
            (network, _) => network,
        };
        let runtime = Arc::new(smol::Executor::new());
        let (stop, stopped) = smol::channel::bounded::<()>(1);
        // One thread runs the node's tasks: its groups' drivers, leader and
        // apply loops, its ingress and its peers' messages. Calls keep their
        // lane's order by it (see `calls`).
        let threads: Vec<JoinHandle<()>> = vec![{
            let runtime = Arc::clone(&runtime);
            std::thread::Builder::new()
                .name("vos-node".into())
                .spawn(move || smol::block_on(runtime.run(stopped.recv())).unwrap_or(()))
                .expect("the node's thread starts")
        }];
        let next = records
            .iter()
            .filter(|record| CreationRecord::creator_of(record.agent) == number)
            .map(|record| (record.agent.0 & 0x00ff_ffff) + 1)
            .max()
            .unwrap_or(1);
        let settings = Settings::of(&config);
        let inner = Arc::new(Inner {
            storage: StorageThread::spawn(store.clone(), Arc::clone(&config.hooks)),
            store,
            blobs,
            executors: Executors::spawn(config.executors),
            pool,
            program: Arc::new(program),
            program_hash,
            settings,
            hooks: config.hooks,
            clock: config.clock,
            node_id,
            number,
            space: config.space,
            network,
            directory: Directory::default(),
            dropping: Mutex::new(HashMap::new()),
            runs: Mutex::new(HashMap::new()),
            dry_runs: Mutex::new(HashMap::new()),
            wanted: Mutex::new(HashMap::new()),
            drops: crate::peer::Drops::default(),
            next_agent: smol::lock::Mutex::new(next),
            runtime,
            tasks: Mutex::new(Tasks::default()),
            recording: smol::lock::Mutex::new(()),
            calls: crate::calls::Calls::default(),
            reads: crate::asking::Waits::default(),
            turn: AtomicU64::new(0),
            sent_across: AtomicU64::new(0),
            installed: AtomicU64::new(0),
            streamed: AtomicU64::new(0),
            stats: Arc::default(),
            closing: AtomicBool::new(false),
            retiring: Mutex::new(HashSet::new()),
            halted: AtomicBool::new(false),
            liveness: crate::liveness::Liveness::new(incarnation),
            relayed: AtomicU64::new(0),
        });
        for record in records {
            let agent = record.agent;
            let placement = match placements.remove(&agent) {
                Some(Some(placement)) => placement,
                Some(None) => {
                    tracing::error!(
                        agent = agent.0,
                        "an unreadable placement; its agent is not run until a placement comes"
                    );
                    continue;
                }
                None => Placement::created(&record),
            };
            let created = record.creator == number && placement.term == 0;
            // A retirement a crash cut short is finished: no group starts
            // for an agent its placement no longer names.
            let unfinished =
                !placement.admits(number) && inner.holds_replica(agent).unwrap_or(false);
            if unfinished {
                lock(&inner.retiring).insert(agent);
            }
            inner.learn(record, placement);
            if created {
                inner.announce(agent);
            }
            if unfinished {
                let retiring = Arc::clone(&inner);
                inner.spawn(async move { retiring.finish_retirement(agent).await });
            }
        }
        let mut liveness = None;
        if let Some(arrivals) = arrivals {
            let (stop, stopped) = smol::channel::bounded::<()>(1);
            let heard = arrivals.liveness.clone();
            let thread = {
                let inner = Arc::clone(&inner);
                std::thread::Builder::new()
                    .name("vos-liveness".into())
                    .spawn(move || crate::liveness::supervise(inner, heard, stopped))
                    .expect("the liveness thread starts")
            };
            liveness = Some((stop, thread));
            inner.spawn(crate::dispatch::dispatch(Arc::clone(&inner), arrivals));
        }
        inner.spawn(super::directory::resend_records(Arc::clone(&inner)));
        inner.spawn(crate::stats::probe(Arc::clone(&inner)));
        let collector = {
            let (stop, stopped) = mpsc::channel::<()>();
            let inner = Arc::clone(&inner);
            let thread = std::thread::Builder::new()
                .name("vos-blob-collect".into())
                .spawn(move || collect_blobs(&inner, &stopped))
                .expect("the blob collector's thread starts");
            Some((stop, thread))
        };
        Ok(Self {
            inner,
            data,
            secret,
            ingress_tls: config.ingress_tls,
            ingress: Mutex::new(None),
            stop: Some(stop),
            runtime: threads,
            liveness,
            collector,
        })
    }

    /// Stop every agent after its batch in flight, then the threads.
    /// Requests queued but not yet in a batch are not durable: their callers
    /// see `Stopped` and resend.
    pub fn shutdown(mut self) {
        self.stop_all();
    }

    fn stop_all(&mut self) {
        // Once is enough: the runtime is gone after it, and nothing it
        // never ran could be awaited.
        if self.runtime.is_empty() {
            return;
        }
        {
            let _runs = lock(&self.inner.runs);
            self.inner.closing.store(true, Ordering::SeqCst);
        }
        if let Some((stop, thread)) = self.liveness.take() {
            let _ = stop.try_send(());
            let _ = thread.join();
        }
        // A collection under way ends first: it waits on the writers.
        if let Some((stop, thread)) = self.collector.take() {
            let _ = stop.send(());
            let _ = thread.join();
        }
        // End the ingress and its connections while the runtime still runs
        // them, so none outlives the node holding its store.
        let ingress = lock(&self.ingress).take();
        if let Some((task, stop)) = ingress {
            let _ = stop.try_send(());
            smol::block_on(task);
        }
        let tasks = std::mem::take(&mut lock(&self.inner.tasks).list);
        let runs: Vec<Arc<Run>> = lock(&self.inner.runs).drain().map(|(_, run)| run).collect();
        for run in &runs {
            run.agent.stop();
            run.shared.stop();
            run.inbox.close();
            run.local.close();
        }
        smol::block_on(async {
            for task in tasks {
                task.cancel().await;
            }
            for run in runs {
                let tasks = std::mem::take(&mut *lock(&run.tasks));
                for task in tasks {
                    task.await;
                }
            }
        });
        if let Some(stop) = self.stop.take() {
            stop.close();
        }
        for runtime in self.runtime.drain(..) {
            let _ = runtime.join();
        }
        // The jobs left finish here, and what they hold goes with them: no
        // part of the node (its store and its lock among them) outlives it.
        self.inner.executors.close();
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        self.stop_all();
    }
}

/// Collect the blob store every `blob_collect_every` until stopped, on a
/// thread of its own: a collection with a blob to consider reads every
/// live log row, which the node's one runtime thread must not wait on.
fn collect_blobs(inner: &Inner, stopped: &mpsc::Receiver<()>) {
    while let Err(mpsc::RecvTimeoutError::Timeout) =
        stopped.recv_timeout(inner.settings.blob_collect_every)
    {
        let stopping = || inner.closing.load(Ordering::SeqCst);
        match smol::block_on(inner.blobs.collect(
            &inner.storage,
            inner.settings.blob_horizons,
            &stopping,
        )) {
            Ok(collected) => {
                if collected.removed + collected.moved + collected.segments_deleted > 0 {
                    tracing::info!(
                        removed = collected.removed,
                        moved = collected.moved,
                        segments_deleted = collected.segments_deleted,
                        "blobs collected"
                    );
                }
            }
            Err(error) => tracing::warn!("a blob collection failed: {error}"),
        }
    }
}

/// Write the operator's token, in hex, readable by its owner only.
pub(super) fn write_token(path: &Path, token: &[u8; 32]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let hex: String = token.iter().map(|byte| format!("{byte:02x}")).collect();
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(hex.as_bytes())?;
    file.sync_all()
}

/// Make `dir` if it is missing, readable by its owner only: it holds the
/// node's secret, in files its store makes without a mode of their own.
/// An empty directory, or a node's, that others can reach is made its
/// owner's alone; any other directory others can reach is refused, not
/// changed (it may be `/tmp`, or a home).
fn private_dir(dir: &Path) -> Result<(), String> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    let failed = |error: std::io::Error| format!("{}: {error}", dir.display());
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .map_err(failed)?;
    let mode = std::fs::metadata(dir).map_err(failed)?.permissions().mode();
    if mode & 0o077 == 0 {
        return Ok(());
    }
    let empty = std::fs::read_dir(dir).map_err(failed)?.next().is_none();
    if !empty && !dir.join(STORE).exists() {
        return Err(format!(
            "{}: others can reach this directory, and the node's secret would be in it; \
             run `chmod 700 {}`, or give a new directory",
            dir.display(),
            dir.display()
        ));
    }
    tracing::warn!(dir = %dir.display(), mode = format!("{mode:o}"), "taking others' access to the data directory away");
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(mode & 0o700)).map_err(failed)
}

/// Milliseconds since the Unix epoch, by the system clock.
pub fn wall_clock() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_millis() as u64)
}
