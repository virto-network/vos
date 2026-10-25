//! The prover worker on a node (`vos_node_prover`): its thread, the node
//! it reads (the agents' applied state, their records of the statements
//! waiting to be proved among it, and the blob store) and its table, the
//! node's own rows; and those records, which every replica's apply keeps
//! ([`attested`]).
//!
//! A statement proved here reaches its agent through the agent's leader:
//! the worker hands it over ([`Unrecorded`]) and wakes the leader, whose
//! next batch proposes `Input::Proven` for each statement the agent has
//! not recorded; a node no longer leading it sends it to the leader
//! (`PeerMessage::Proved`). The table is node-local, never replicated.

use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex, mpsc};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use vos_node_prover::{Backlog, Host, Job, Jobs, Options, Prover, Record, Worker};
use vos_raft::Role;
use vos_venue::vos_statement::StatementId;
use vos_wire::ids::{AgentId, ProgramHash};
use vos_wire::peer::{NodeNumber, PeerMessage};
use vos_wire::result::{Attest, InputRef, Step, WorkResult, Write};
use vos_wire::vos_anchor::MAX_ROOT_AGE_MS;
use vos_wire::{Decode, Encode, SpaceId, WindowClock, keys};

use crate::blobs::{Keep, blob_ref};
use crate::fault::{Fault, read};
use crate::lock;
use crate::node::Inner;
use crate::store::{Fjall, NODE_AGENT, PersistMode, Snapshot};

/// How long an idle worker waits before it looks again: for a new record,
/// an anchor, or a proof another replica sends.
const IDLE: Duration = Duration::from_secs(1);

/// How often the worker writes its backlog to the log, while it has one.
const REPORT_EVERY: Duration = Duration::from_secs(60);

/// The statements proved here that their agents have still to record: by
/// agent, each statement's id, its window, its proof and its record.
#[derive(Default)]
pub(crate) struct Unrecorded(Mutex<HashMap<AgentId, Proofs>>);

/// A proved statement waiting to be recorded: its window, its proof and
/// the digest of its record.
pub(crate) type Proved = (u64, [u8; 32], [u8; 32]);

/// Statements' proofs, by statement id.
type Proofs = BTreeMap<StatementId, Proved>;

impl Unrecorded {
    pub(crate) fn add(&self, agent: AgentId, id: StatementId, proved: Proved) {
        lock(&self.0).entry(agent).or_default().insert(id, proved);
    }

    /// `agent`'s, each its statement's id and what proved it.
    pub(crate) fn of(&self, agent: AgentId) -> Vec<(StatementId, Proved)> {
        lock(&self.0)
            .get(&agent)
            .map(|waiting| waiting.iter().map(|(id, proved)| (*id, *proved)).collect())
            .unwrap_or_default()
    }

    /// `agent`'s statement `id`, recorded.
    pub(crate) fn recorded(&self, agent: AgentId, id: &StatementId) {
        let mut waiting = lock(&self.0);
        if let Some(of) = waiting.get_mut(&agent) {
            of.remove(id);
            if of.is_empty() {
                waiting.remove(&agent);
            }
        }
    }
}

impl Inner {
    /// A replica of `agent` on node `from` proved its statement `id`, no
    /// longer leading it: recorded through this replica's leader, if it
    /// leads.
    pub(crate) fn on_proved(
        &self,
        from: NodeNumber,
        agent: AgentId,
        window: u64,
        id: [u8; 32],
        (proof, attested): ([u8; 32], [u8; 32]),
    ) {
        if !self.admit(agent, from) {
            return;
        }
        if let Some(run) = self.run(agent) {
            self.unrecorded
                .add(agent, StatementId(id), (window, proof, attested));
            run.agent.wake();
        }
    }

    /// Ask `agent`'s other replicas for the blob `hash`, which this node
    /// does not hold.
    fn fetch(&self, agent: AgentId, hash: &[u8; 32]) {
        let others: Vec<_> = self
            .placement(agent)
            .map(|placement| placement.replicas)
            .unwrap_or_default()
            .into_iter()
            .filter(|node| *node != self.number)
            .collect();
        self.want(agent, &[*hash], Keep::Aged);
        for to in others {
            self.send(
                to,
                &PeerMessage::BlobRequest {
                    agent,
                    hashes: vec![*hash],
                },
            );
        }
    }
}

/// The writes beside `result`'s, applied to `agent` as `snapshot` holds it,
/// that keep the records of its attests at a window's cut
/// (`keys::attested`): each it made, kept; each its `Proven` steps name,
/// kept without its witness, which no one proves again; and, when its time
/// crosses one of the agent's window boundaries, those of windows whose
/// roots have aged past `MaxRootAge` by it, dropped. The same writes on
/// every replica.
pub(crate) fn attested(
    snapshot: &Snapshot,
    agent: AgentId,
    result: &WorkResult,
) -> Result<Vec<Write>, Fault> {
    let mut writes = Vec::new();
    for step in &result.steps {
        let Step::Ran(run) = step else {
            continue;
        };
        if let InputRef::Proven {
            window, attested, ..
        } = run.input
        {
            let key = keys::attested(window, &attested);
            let record = snapshot
                .get(agent, &key)?
                .and_then(|bytes| Attest::decode_exact(&bytes));
            if let Some(attest) = record.filter(|attest| !attest.witness_input.is_empty()) {
                let proved = Attest {
                    witness_input: Vec::new(),
                    ..attest
                };
                writes.push(Write {
                    key,
                    value: Some(proved.encode()),
                });
            }
        }
        for attest in &run.attests {
            let Some(window) = attest.window else {
                continue;
            };
            writes.push(Write {
                key: keys::attested(window, &attest.digest()),
                value: Some(attest.encode()),
            });
        }
    }
    let space = read::<SpaceId>(snapshot, agent, &keys::space())?;
    let clock = read::<WindowClock>(snapshot, agent, &keys::clock())?;
    let mark = read::<u64>(snapshot, agent, &keys::batch_time())?.unwrap_or(0);
    let (Some(space), Some(clock)) = (space, clock) else {
        return Ok(writes);
    };
    if space == SpaceId::NONE || clock.window(mark) == clock.window(result.time) {
        return Ok(writes);
    }
    // The windows whose roots are anchored still: those whose boundary is
    // within `MaxRootAge` of the result's time.
    let live = clock
        .window(result.time.saturating_sub(MAX_ROOT_AGE_MS))
        .unwrap_or(0);
    for row in snapshot.scan(agent, &keys::attested_prefix(), None) {
        let (key, _) = row?;
        match keys::attested_entry(&key) {
            Some((window, _)) if window >= live => break,
            _ => writes.push(Write { key, value: None }),
        }
    }
    Ok(writes)
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

    fn attested(&self, agent: AgentId, from: u64) -> Result<Vec<Record>, String> {
        let snapshot = self.0.store.snapshot();
        let after = keys::attested_from(from);
        let mut records = Vec::new();
        for row in snapshot.scan(agent, &keys::attested_prefix(), Some(&after)) {
            let (key, value) = row.map_err(|error| format!("{error:?}"))?;
            let (Some((window, digest)), Some(attest)) =
                (keys::attested_entry(&key), Attest::decode_exact(&value))
            else {
                tracing::error!(agent = agent.0, "a record at a cut does not decode: no job");
                continue;
            };
            records.push((window, digest, attest));
        }
        Ok(records)
    }

    fn program(&self, agent: AgentId, hash: &ProgramHash) -> Option<Vec<u8>> {
        let program = self.0.blobs.get(&hash.0).ok().flatten();
        if program.is_none() {
            self.0.fetch(agent, &hash.0);
        }
        program
    }

    fn proven(&self, agent: AgentId, window: u64, id: &StatementId) -> Option<[u8; 32]> {
        let snapshot = self.0.store.snapshot();
        read::<[u8; 32]>(&snapshot, agent, &keys::proven(window, &id.0))
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
        if held {
            batch.pin(hash, NODE_AGENT);
        } else {
            batch.unpin(hash, NODE_AGENT);
        }
        if let Err(error) = batch.commit(PersistMode::SyncAll) {
            tracing::warn!("a proof's pin was not written: {error:?}");
        }
    }

    fn proof(&self, agent: AgentId, hash: &[u8; 32]) -> Option<Vec<u8>> {
        if let Ok(Some(proof)) = self.0.blobs.get(hash) {
            return Some(proof);
        }
        self.0.fetch(agent, hash);
        None
    }

    /// Through this node's leader, or, when another node leads `agent`,
    /// sent to it as well.
    fn record(
        &self,
        agent: AgentId,
        window: u64,
        id: StatementId,
        proof: [u8; 32],
        attested: [u8; 32],
    ) {
        self.0.unrecorded.add(agent, id, (window, proof, attested));
        let Some(run) = self.0.run(agent) else {
            return;
        };
        run.agent.wake();
        let leader = run.shared.state().leader;
        if let Some(leader) = leader.filter(|leader| *leader != self.0.number) {
            self.0.send(
                leader,
                &PeerMessage::Proved {
                    agent,
                    window,
                    id: id.0,
                    proof,
                    attested,
                },
            );
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

    fn stopping(&self) -> Result<bool, String> {
        self.0.prover_stopping().map_err(failed)
    }

    fn set_stopping(&self, stopping: bool) -> Result<(), String> {
        set_stopping(&self.0, stopping)
    }
}

/// Mark the node stopping, or running, for its prover's table: a proof
/// under way when it stops was stopped by its operator.
pub(crate) fn set_stopping(store: &Fjall, stopping: bool) -> Result<(), String> {
    let mut batch = store.batch();
    batch.prover_stopping(stopping);
    batch.commit(PersistMode::SyncAll).map_err(failed)
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
    let thread = std::thread::Builder::new()
        .name("vos-prover".into())
        .spawn(move || work(worker, &stopped))
        .expect("the prover's thread starts");
    Some((stop, thread))
}

/// Step the worker until stopped, waiting [`IDLE`] whenever a step leaves
/// nothing to prove, and its backlog kept for the node to report.
fn work(mut worker: Worker<NodeHost, NodeJobs>, stopped: &mpsc::Receiver<()>) {
    let mut reported = Instant::now();
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
                reported = Instant::now();
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
        "the prover's backlog"
    );
}
