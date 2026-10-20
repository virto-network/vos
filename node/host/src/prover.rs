//! The prover worker on a node (`vos_node_prover`): its thread, the node
//! it reads (the logs of the agents it leads, their applied state, the
//! blob store) and its table, the node's own rows.
//!
//! A statement proved here reaches its agent through the agent's leader:
//! the worker hands it over ([`Unrecorded`]) and wakes the leader, whose
//! next batch proposes `Input::Proven` for each statement the agent has
//! not recorded. The table and the watermarks are node-local, never
//! replicated.

use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex, mpsc};
use std::thread::JoinHandle;
use std::time::Duration;

use vos_node_prover::{Backlog, Host, Job, Jobs, Options, Prover, Worker};
use vos_raft::Role;
use vos_venue::vos_statement::StatementId;
use vos_wire::ids::{AgentId, ProgramHash};
use vos_wire::peer::PeerMessage;
use vos_wire::result::{Attest, Step, WorkResult};
use vos_wire::{Decode, Encode, WindowClock, keys};

use crate::blobs::{Keep, blob_ref};
use crate::lock;
use crate::node::Inner;
use crate::store::{EntryKind, Fjall, NODE_AGENT, PersistMode};

/// How long an idle worker waits before it looks again: for a new record,
/// an anchor, or a proof another replica sends.
const IDLE: Duration = Duration::from_secs(1);

/// How often the worker writes its backlog to the log, while it has one.
const REPORT_EVERY: Duration = Duration::from_secs(60);

/// The statements proved here that their agents have still to record: by
/// agent, each statement's id and its proof.
#[derive(Default)]
pub(crate) struct Unrecorded(Mutex<HashMap<AgentId, Proofs>>);

/// Statements' windows and proofs, by statement id.
type Proofs = BTreeMap<[u8; 32], (u64, [u8; 32])>;

impl Unrecorded {
    fn add(&self, agent: AgentId, window: u64, id: [u8; 32], proof: [u8; 32]) {
        lock(&self.0)
            .entry(agent)
            .or_default()
            .insert(id, (window, proof));
    }

    /// `agent`'s, each its statement's id, its window and its proof.
    pub(crate) fn of(&self, agent: AgentId) -> Vec<([u8; 32], u64, [u8; 32])> {
        lock(&self.0)
            .get(&agent)
            .map(|waiting| {
                waiting
                    .iter()
                    .map(|(id, (window, proof))| (*id, *window, *proof))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// `agent`'s statement `id`, recorded.
    pub(crate) fn recorded(&self, agent: AgentId, id: &[u8; 32]) {
        let mut waiting = lock(&self.0);
        if let Some(of) = waiting.get_mut(&agent) {
            of.remove(id);
            if of.is_empty() {
                waiting.remove(&agent);
            }
        }
    }
}

/// The node as the worker reads it.
struct NodeHost(Arc<Inner>);

impl Host for NodeHost {
    fn leads(&self, agent: AgentId) -> bool {
        self.0.run(agent).is_some_and(|run| {
            let state = run.shared.state();
            state.role == Role::Leader && !state.stopped && run.agent.leading()
        })
    }

    fn agents(&self) -> Vec<AgentId> {
        lock(&self.0.runs).keys().copied().collect()
    }

    fn applied(&self, agent: AgentId) -> u64 {
        self.0
            .store
            .snapshot()
            .applied(agent)
            .ok()
            .flatten()
            .unwrap_or(0)
    }

    fn attests(&self, agent: AgentId, index: u64) -> Result<Option<Vec<Attest>>, String> {
        let Some(entry) = self
            .0
            .store
            .log_entry(agent, index)
            .map_err(|error| format!("{error:?}"))?
        else {
            return Ok(None);
        };
        let body = match entry.kind {
            EntryKind::Result => entry.body,
            EntryKind::LargeResult => {
                let Some(blob) = entry.result_blob() else {
                    return Ok(None);
                };
                match self
                    .0
                    .blobs
                    .get(&blob.hash)
                    .map_err(|error| format!("{error:?}"))?
                {
                    Some(body) => body,
                    None => return Ok(None),
                }
            }
            EntryKind::NoOp | EntryKind::Configuration => return Ok(Some(Vec::new())),
        };
        // A body that does not decode applied as no result: it attests
        // nothing.
        let Ok((result, _)) = WorkResult::decode(&body) else {
            return Ok(Some(Vec::new()));
        };
        Ok(Some(
            result
                .steps
                .into_iter()
                .flat_map(|step| match step {
                    Step::Ran(run) => run.attests,
                    _ => Vec::new(),
                })
                .collect(),
        ))
    }

    fn program(&self, hash: &ProgramHash) -> Option<Vec<u8>> {
        self.0.blobs.get(&hash.0).ok().flatten()
    }

    fn proven(&self, agent: AgentId, window: u64, id: &StatementId) -> Option<[u8; 32]> {
        let snapshot = self.0.store.snapshot();
        crate::fault::read::<[u8; 32]>(&snapshot, agent, &keys::proven(window, &id.0))
            .ok()
            .flatten()
    }

    fn keep(&self, proof: &[u8]) -> Result<[u8; 32], String> {
        let blob = blob_ref(proof);
        smol::block_on(self.0.blobs.put(blob, Arc::new(proof.to_vec()), Keep::Aged))?;
        Ok(blob.hash)
    }

    /// A pin under the node's own id, apart from every agent's program
    /// pins.
    fn hold(&self, hash: &[u8; 32], held: bool) {
        let mut batch = self.0.store.batch();
        match held {
            true => batch.pin(hash, NODE_AGENT),
            false => batch.unpin(hash, NODE_AGENT),
        }
        if let Err(error) = batch.commit(PersistMode::SyncAll) {
            tracing::warn!("a proof's pin was not written: {error:?}");
        }
    }

    fn proof(&self, agent: AgentId, hash: &[u8; 32]) -> Option<Vec<u8>> {
        if let Ok(Some(proof)) = self.0.blobs.get(hash) {
            return Some(proof);
        }
        let others: Vec<_> = self
            .0
            .placement(agent)
            .map(|placement| placement.replicas)
            .unwrap_or_default()
            .into_iter()
            .filter(|node| *node != self.0.number)
            .collect();
        self.0.want(agent, &[*hash], Keep::Aged);
        for to in others {
            self.0.send(
                to,
                &PeerMessage::BlobRequest {
                    agent,
                    hashes: vec![*hash],
                },
            );
        }
        None
    }

    fn record(&self, agent: AgentId, window: u64, id: StatementId, proof: [u8; 32]) {
        self.0.unrecorded.add(agent, window, id.0, proof);
        if let Some(run) = self.0.run(agent) {
            run.agent.wake();
        }
    }

    fn clock(&self) -> WindowClock {
        self.0.space_and_clock().1
    }
}

/// The worker's table in the node's store, each write synced.
struct NodeJobs(Fjall);

fn failed(error: crate::store::Error) -> String {
    format!("the prover's table: {error:?}")
}

impl Jobs for NodeJobs {
    fn get(&self, agent: AgentId, id: &StatementId) -> Result<Option<Job>, String> {
        let job = self.0.prover_job(agent, &id.0).map_err(failed)?;
        job.map(|bytes| {
            Job::decode_exact(&bytes).ok_or_else(|| "a prover's job does not decode".into())
        })
        .transpose()
    }

    fn put(&self, id: &StatementId, job: &Job) -> Result<(), String> {
        let mut batch = self.0.batch();
        batch.prover_job(job.agent, &id.0, Some(&job.encode()));
        batch.commit(PersistMode::SyncAll).map_err(failed)
    }

    fn remove(&self, agent: AgentId, id: &StatementId) -> Result<(), String> {
        let mut batch = self.0.batch();
        batch.prover_job(agent, &id.0, None);
        batch.commit(PersistMode::SyncAll).map_err(failed)
    }

    fn all(&self) -> Result<Vec<(StatementId, Job)>, String> {
        let mut jobs = Vec::new();
        for (_, id, bytes) in self.0.prover_jobs().map_err(failed)? {
            match Job::decode_exact(&bytes) {
                Some(job) => jobs.push((StatementId(id), job)),
                None => tracing::error!("a prover's job does not decode; it is not read"),
            }
        }
        Ok(jobs)
    }

    fn watermark(&self, agent: AgentId) -> Result<u64, String> {
        self.0.prover_mark(agent).map_err(failed)
    }

    /// Not synced: the jobs it reads past are, so a mark lost to a crash
    /// only has the scan read those records again, each to the job it made.
    fn set_watermark(&self, agent: AgentId, index: u64) -> Result<(), String> {
        let mut batch = self.0.batch();
        batch.prover_mark(agent, index);
        batch.commit(PersistMode::Buffer).map_err(failed)
    }
}

/// The worker's thread, and what stops it: none without a venue to submit
/// to.
pub(crate) fn start(
    inner: &Arc<Inner>,
    prover: Arc<dyn Prover>,
    options: Options,
) -> Option<(mpsc::Sender<()>, JoinHandle<()>)> {
    let venue = inner.venue.clone()?;
    let (stop, stopped) = mpsc::channel::<()>();
    let worker = Worker::open(
        NodeHost(Arc::clone(inner)),
        NodeJobs(inner.store.clone()),
        prover,
        venue,
        options,
    );
    let worker = match worker {
        Ok(worker) => worker,
        Err(error) => {
            tracing::error!(%error, "the prover's table does not open; nothing is proved");
            return None;
        }
    };
    inner.proving.store(true, Ordering::SeqCst);
    let thread = std::thread::Builder::new()
        .name("vos-prover".into())
        .spawn(move || work(worker, &stopped))
        .expect("the prover's thread starts");
    Some((stop, thread))
}

/// Step the worker until stopped, waiting [`IDLE`] whenever a step leaves
/// nothing to prove, and its backlog kept for the node to report.
fn work(mut worker: Worker<NodeHost, NodeJobs>, stopped: &mpsc::Receiver<()>) {
    let mut reported = std::time::Instant::now();
    loop {
        if worker.host().0.closing.load(Ordering::SeqCst) {
            return;
        }
        let wait = match worker.step() {
            Ok(stepped) if stepped.more => Duration::ZERO,
            Ok(_) => IDLE,
            Err(error) => {
                tracing::warn!(%error, "the prover's step failed; trying again");
                IDLE
            }
        };
        if let Ok(backlog) = worker.backlog() {
            if backlog.pending() > 0 && reported.elapsed() >= REPORT_EVERY {
                reported = std::time::Instant::now();
                report(&backlog);
            }
            *lock(&worker.host().0.backlog) = Some(backlog);
        }
        if let Err(error) = worker.prune() {
            tracing::warn!(%error, "the prover's table was not pruned");
        }
        match stopped.recv_timeout(wait) {
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            _ => return,
        }
    }
}

fn report(backlog: &Backlog) {
    tracing::info!(
        queued = backlog.queued,
        proved = backlog.proved,
        submitted = backlog.submitted,
        oldest = ?backlog.oldest,
        lost = backlog.lost,
        "the prover's backlog"
    );
}
