//! The node: every agent's replica group, applier and leader loop on one
//! async thread, the executor threads for PVM work, the storage thread,
//! the machine pool, and the network to the space's other nodes.
//!
//! Per agent, a leader's batch runs strictly in order: refine, a dry run
//! of accumulate, the result proposed and replicated, and once this
//! replica has applied it, the replies, the outbox's deliveries and the
//! acknowledgements. Every replica applies the committed log the same way.

mod config;
mod directory;
mod open;
mod queue;

use std::collections::{BTreeSet, HashMap, HashSet};
use std::future::Future;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use vos_net::Network;
use vos_pvm::pool::{CodeHash, MachinePool, OuterMachines};
use vos_raft::Role;
use vos_wire::Decode;
use vos_wire::batch::{Admin, Message, Query, Request, Work};
use vos_wire::ids::{AgentId, InstanceId, MethodId, Principal, ProgramHash};
use vos_wire::ingress::{Contact, Grant, NodeId, Unplaced};
use vos_wire::peer::{CreationRecord, NodeNumber, Placement};
use vos_wire::records::unstored;
use vos_wire::result::{Outcome, Step, Write};

use crate::Hooks;
use crate::blobs::{Blobs, Keep};
use crate::executor::Executors;
use crate::group::{self, DryRun, Input as GroupInput, Local, Shared};
use crate::pvm::{self, Fault};
use crate::space::Space;
use crate::storage::{Change, StorageThread};
use crate::store::{BlobRef, Fjall, Snapshot};
use crate::tls::IngressTls;
use crate::{lock, seed, timeout};

pub(crate) use config::Settings;
pub use config::{CallError, Config, Error, Peers, ReplaceError, Reply};
pub(crate) use directory::Directory;
use open::write_token;
pub use open::{ADMIN_TOKEN, NODE_KEY, STORE, wall_clock};
pub(crate) use queue::{Agent, Answered, Pending};

/// An agent this node replicates: its queue, its group's shared state, the
/// group's inbox, and their tasks.
pub(crate) struct Run {
    pub(crate) agent: Arc<Agent>,
    pub(crate) shared: Arc<Shared>,
    pub(crate) inbox: smol::channel::Sender<GroupInput>,
    /// The leader loop's proposals and its retirement, never dropped.
    local: smol::channel::Sender<Local>,
    tasks: Mutex<Vec<smol::Task<()>>>,
}

/// How long a call waits for a new leader to apply what it took over.
const CATCH_UP: Duration = Duration::from_secs(10);
/// How long the node a replacement adds has to say it could run the
/// agent's program.
const CAPABLE: Duration = Duration::from_secs(10);
/// How long a replacement waits for its final configuration to commit.
const REPLACED: Duration = Duration::from_secs(30);
/// How long a replacement waits, once its node no longer leads, for the
/// final configuration to be announced: by this node as it steps down, or
/// by the node that took over.
const REPLACED_ELSEWHERE: Duration = Duration::from_secs(2);

/// A blob groups here asked for: which, and how it is kept once it
/// arrives.
struct Wanted {
    groups: BTreeSet<AgentId>,
    keep: Keep,
}

pub(crate) struct Inner {
    pub(crate) store: Fjall,
    pub(crate) blobs: Blobs,
    pub(crate) storage: StorageThread,
    pub(crate) executors: Executors,
    pub(crate) pool: Arc<MachinePool>,
    pub(crate) program: Arc<OuterMachines>,
    pub(crate) program_hash: ProgramHash,
    pub(crate) settings: Settings,
    pub(crate) hooks: Arc<dyn Hooks>,
    pub(crate) clock: Arc<dyn Fn() -> u64 + Send + Sync>,
    pub(crate) node_id: NodeId,
    /// This node's number in its space.
    pub(crate) number: NodeNumber,
    pub(crate) space: Option<Space>,
    pub(crate) network: Option<Arc<dyn Network>>,
    /// Where each agent runs, and the placements this node sends.
    pub(crate) directory: Directory,
    /// The agents' epochs a drop may still remove rows from, with how many
    /// drops run on each: no install is staged into one (`empty_epoch`),
    /// or a drop would take its rows.
    pub(crate) dropping: Mutex<HashMap<(AgentId, u8), usize>>,
    /// The agents this node replicates.
    pub(crate) runs: Mutex<HashMap<AgentId, Arc<Run>>>,
    dry_runs: Mutex<HashMap<AgentId, DryRun>>,
    /// The blobs groups here asked for.
    wanted: Mutex<HashMap<[u8; 32], Wanted>>,
    pub(crate) drops: crate::peer::Drops,
    /// The low 24 bits of the next agent id this node makes.
    next_agent: smol::lock::Mutex<u32>,
    pub(crate) runtime: Arc<smol::Executor<'static>>,
    /// Node-wide tasks: the dispatcher, the directory's resends, and the
    /// work groups hand off.
    tasks: Mutex<Tasks>,
    /// Held while a record or a placement is checked against the directory
    /// and stored. It orders `place` against `on_directory`: each reads,
    /// compares and writes, and neither may store over a newer placement.
    pub(crate) recording: smol::lock::Mutex<()>,
    /// Turns through an agent's replicas, for what goes to one of them.
    pub(crate) turn: AtomicU64,
    /// Messages sent toward other nodes.
    pub(crate) sent_across: AtomicU64,
    /// Snapshots this node's groups switched to.
    pub(crate) installed: AtomicU64,
    /// Snapshot streams this node's groups started to their followers.
    pub(crate) streamed: AtomicU64,
    /// How long its leaders' batches spend in each stage.
    pub(crate) stats: Arc<crate::stats::Stats>,
    /// The node is shutting down: no group starts or retires.
    pub(crate) closing: AtomicBool,
    /// Agents whose retirement is not yet written: no group starts for
    /// them until it is.
    pub(crate) retiring: Mutex<HashSet<AgentId>>,
    /// Storage failed: every group stopped, and the node sends no pair
    /// heartbeat.
    pub(crate) halted: AtomicBool,
    /// The pair heartbeat this node sends, and what it hears.
    pub(crate) liveness: crate::liveness::Liveness,
    /// Messages relayed to their agent's leader.
    pub(crate) relayed: AtomicU64,
    /// Clients' calls: their lanes, and the calls forwarded both ways.
    pub(crate) calls: crate::calls::Calls,
    /// The read indexes this replica asked its leaders for.
    pub(crate) reads: crate::asking::Waits<Option<u64>>,
}

impl Inner {
    pub(crate) fn run(&self, id: AgentId) -> Option<Arc<Run>> {
        lock(&self.runs).get(&id).cloned()
    }

    /// Why a call to `id` cannot be served here: a replica with no group
    /// running is stopping (or refused the group), and any other node
    /// names the replicas.
    pub(crate) fn absent(&self, id: AgentId) -> CallError {
        match self.directory.get(id) {
            Some(known) if known.placement.replicas.contains(&self.number) => CallError::Stopped,
            Some(known) => CallError::Elsewhere(
                known
                    .placement
                    .replicas
                    .iter()
                    .filter_map(|replica| self.contact(*replica))
                    .collect(),
            ),
            None => CallError::NoAgent,
        }
    }

    /// Where agent `id` runs, as this node last heard.
    pub(crate) fn placement(&self, id: AgentId) -> Option<Placement> {
        self.directory.get(id).map(|known| known.placement.clone())
    }

    /// How clients reach node `number`, from the space.
    pub(crate) fn contact(&self, number: NodeNumber) -> Option<Contact> {
        let node = self.space.as_ref()?.node(number)?;
        Some(Contact {
            address: node.ingress.clone(),
            node: NodeId(node.key),
        })
    }

    /// The node `contact` names, by its key.
    pub(crate) fn number_of(&self, contact: &Contact) -> Option<NodeNumber> {
        self.space
            .as_ref()?
            .nodes()
            .iter()
            .find(|node| node.key == contact.node.0)
            .map(|node| node.number)
    }

    /// That this node does not lead `shared`'s group, with its leader's
    /// address when known; or that the group stopped.
    pub(crate) fn not_leader(&self, shared: &Shared) -> CallError {
        if shared.state().stopped {
            return CallError::Stopped;
        }
        CallError::NotLeader(
            shared
                .state()
                .leader
                .filter(|leader| *leader != self.number)
                .and_then(|leader| self.contact(leader)),
        )
    }

    /// Agent `id`'s replica here, when its leader loop takes inputs and
    /// it has applied what its predecessors committed: else where calls go
    /// instead. While the group elects, it waits as a call does.
    ///
    /// Applied that far, the replica's marks hold every request an earlier
    /// leader answered, so ingress reads no gap after one.
    pub(crate) async fn leading(&self, id: AgentId) -> Result<Arc<Run>, CallError> {
        let run = self.run(id).ok_or_else(|| self.absent(id))?;
        let state = run.shared.state();
        if !state.stopped && !self.knows_leader(&run, &state) {
            self.settled(id).await?;
        }
        let caught_up = run.shared.wait(|state| {
            state.stopped
                || state
                    .leading_from
                    .is_none_or(|first| state.applied >= first)
        });
        if timeout(CATCH_UP, caught_up).await.is_none() {
            return Err(CallError::Failed(
                "the leader has not applied what it took over".into(),
            ));
        }
        if run.shared.state().stopped || lock(&run.agent.queue).stopped {
            return Err(CallError::Stopped);
        }
        if !lock(&run.agent.queue).leading {
            return Err(self.not_leader(&run.shared));
        }
        Ok(run)
    }

    /// Wait until agent `id`'s group here knows a leader, for a few
    /// election timeouts at most: a call to a group just created, or one
    /// electing, then goes where it should.
    pub(crate) async fn settled(&self, id: AgentId) -> Result<(), CallError> {
        let run = self.run(id).ok_or_else(|| self.absent(id))?;
        let electing = run
            .shared
            .wait(|state| state.stopped || self.knows_leader(&run, state));
        timeout(
            Duration::from_millis(4 * self.settings.election_timeout_ms.1),
            electing,
        )
        .await;
        Ok(())
    }

    /// Whether `run`'s group knows where calls go: a leader elsewhere, or
    /// this replica's leader loop taking inputs.
    pub(crate) fn knows_leader(&self, run: &Run, state: &group::State) -> bool {
        match state.leader {
            Some(leader) if leader == self.number => lock(&run.agent.queue).leading,
            Some(_) => true,
            None => false,
        }
    }

    /// Take out of the pool each program in `unpinned` that no agent here
    /// pins any more, as a restart would leave it. A program pinned again
    /// meanwhile is only loaded again on its next use, at the same gas.
    pub(crate) fn evict(&self, unpinned: &[[u8; 32]]) {
        for hash in unpinned {
            match self.blobs.pinned_by_any(hash) {
                Ok(false) => self.pool.uninstall(&CodeHash(*hash)),
                Ok(true) => {}
                Err(error) => tracing::warn!("a pin read failed: {error}"),
            }
        }
    }

    /// Halt once the store failed a flush, whichever path met the
    /// failure: the pair heartbeat and the records' resends look, so a
    /// node halts within one of their rounds.
    pub(crate) fn halt_if_store_failed(&self) {
        if self.storage.failed() && !self.halted.load(Ordering::SeqCst) {
            tracing::error!("a flush failed; the node stops and needs a restart");
            self.halt();
        }
    }

    /// Stop every agent: a commit failed, and storage takes no more.
    /// Queued and later calls answer `Stopped`.
    pub(crate) fn halt(&self) {
        self.halted.store(true, Ordering::SeqCst);
        let runs: Vec<Arc<Run>> = lock(&self.runs).values().cloned().collect();
        for run in runs {
            run.agent.stop();
            run.shared.stop();
        }
    }

    /// How long its stages took since it started: its leaders' batches'
    /// and its writer's.
    pub(crate) fn stats(&self) -> vos_wire::ingress::Stats {
        self.stats.wire(self.storage.stages())
    }

    /// This node's replica of `agent`, if it runs one: its Raft state, or
    /// `Unavailable` if the store cannot be read.
    pub(crate) fn replica_status(&self, agent: AgentId) -> vos_wire::ingress::Answer {
        use vos_wire::ingress::Answer;
        let Some(run) = self.run(agent) else {
            return Answer::NoAgent;
        };
        let state = run.shared.state();
        let snapshot = self.store.snapshot();
        // No count is none held; one that does not read is no answer.
        let sessions = match snapshot.get(agent, &vos_wire::keys::live_sessions()) {
            Ok(None) => Some(0),
            Ok(Some(bytes)) => unstored(&bytes)
                .and_then(|bytes| u64::decode(bytes).ok())
                .map(|(live, _)| live),
            Err(_) => None,
        };
        let outbox = snapshot
            .scan(agent, &vos_wire::keys::outbox_prefix(), None)
            .try_fold(0u64, |count, row| row.map(|_| count + 1));
        let (Ok(rows), Ok(last), Some(sessions), Ok(outbox)) = (
            self.store.agent_rows(agent),
            self.store.last_log_index(agent),
            sessions,
            outbox,
        ) else {
            return Answer::Unavailable;
        };
        let last = last.unwrap_or(0);
        Answer::Status(vos_wire::ingress::ReplicaStatus {
            term: state.term,
            leads: state.role == Role::Leader,
            leader: state.leader,
            commit: state.commit,
            applied: state.applied,
            log_start: rows.log_start,
            last_index: last.max(rows.log_start),
            halted: self.halted.load(Ordering::SeqCst),
            sessions,
            outbox,
            placement_term: self.placement(agent).map_or(0, |placement| placement.term),
        })
    }

    /// Hand the leader loop's `local` to agent `id`'s group. False when it
    /// has none here, or it stopped.
    pub(crate) fn propose(&self, id: AgentId, local: Local) -> bool {
        self.run(id)
            .is_some_and(|run| run.local.try_send(local).is_ok())
    }

    /// Confirm that this replica leads agent `id`'s group, by a read
    /// index, and wait until it has applied through that index: its
    /// applied state then holds everything committed before the call.
    pub(crate) async fn read_index(&self, id: AgentId) -> Result<u64, CallError> {
        let run = self.run(id).ok_or_else(|| self.absent(id))?;
        let index = self.confirm(id).await?;
        self.applied_through(&run, index).await?;
        Ok(index)
    }

    /// A read index from this replica's core: it leads, as a quorum has
    /// confirmed, and its applied state, through the index, holds every
    /// call answered before.
    pub(crate) async fn confirm(&self, id: AgentId) -> Result<u64, CallError> {
        let run = self.run(id).ok_or_else(|| self.absent(id))?;
        let (answer, answered) = smol::channel::bounded(1);
        if !self.propose(id, Local::ReadIndex { answer }) {
            return Err(CallError::Stopped);
        }
        let index = match answered.recv().await {
            Ok(Ok(index)) => index,
            Ok(Err(
                vos_raft::core::ReadIndexError::Backpressure
                | vos_raft::core::ReadIndexError::TimedOut,
            )) => {
                return Err(CallError::Failed(
                    "leadership was not confirmed in time".into(),
                ));
            }
            Ok(Err(_)) | Err(_) => return Err(self.not_leader(&run.shared)),
        };
        Ok(index)
    }

    /// Wait until `run`'s replica has applied through `index`, for
    /// [`CATCH_UP`] at most.
    pub(crate) async fn applied_through(&self, run: &Run, index: u64) -> Result<(), CallError> {
        let applied = run
            .shared
            .wait(|state| state.stopped || state.applied >= index);
        match timeout(CATCH_UP, applied).await {
            Some(state) if !state.stopped => Ok(()),
            Some(_) => Err(CallError::Stopped),
            None => Err(CallError::Failed(
                "the replica has not applied through its read index".into(),
            )),
        }
    }

    pub(crate) fn keep_dry_run(&self, id: AgentId, dry_run: DryRun) {
        lock(&self.dry_runs).insert(id, dry_run);
    }

    /// The writes of the leader's dry run of the result entry at `index`,
    /// of `term` and the batch `seed`, if it ran on the state that entry
    /// applies to.
    pub(crate) fn dry_run(
        &self,
        id: AgentId,
        index: u64,
        term: u64,
        seed: Option<[u8; 32]>,
    ) -> Option<Vec<Write>> {
        let kept = lock(&self.dry_runs).remove(&id)?;
        (kept.applied + 1 == index && kept.term == term && Some(kept.seed) == seed)
            .then_some(kept.writes)
    }

    /// Agent `id`'s group waits for `hashes`, to be kept as `keep` says
    /// (the longer, if another group waits too): tell it when they arrive.
    pub(crate) fn want(&self, id: AgentId, hashes: &[[u8; 32]], keep: Keep) {
        let mut wanted = lock(&self.wanted);
        for hash in hashes {
            let wanted = wanted.entry(*hash).or_insert(Wanted {
                groups: BTreeSet::new(),
                keep,
            });
            wanted.groups.insert(id);
            wanted.keep = wanted.keep.max(keep);
        }
    }

    /// How a blob some group here asked for is kept, if one did.
    pub(crate) fn wanted(&self, hash: &[u8; 32]) -> Option<Keep> {
        lock(&self.wanted).get(hash).map(|wanted| wanted.keep)
    }

    /// The groups that wanted `hash`, which arrived.
    pub(crate) fn arrived(&self, hash: &[u8; 32]) {
        let waiting = lock(&self.wanted)
            .remove(hash)
            .map(|wanted| wanted.groups)
            .unwrap_or_default();
        for id in waiting {
            if let Some(run) = self.run(id) {
                let _ = run.inbox.try_send(GroupInput::Blobs);
            }
        }
    }

    /// Replace the agent's replica `remove` by node `add`, at the agent's
    /// leader: once `add` says it could run the agent's program, a joint
    /// configuration, which the core finalizes; answered with the replicas
    /// once the final configuration commits.
    pub(crate) async fn replace(
        self: &Arc<Self>,
        agent: AgentId,
        remove: NodeNumber,
        add: NodeNumber,
    ) -> Result<Vec<NodeNumber>, ReplaceError> {
        let run = self.leading(agent).await.map_err(ReplaceError::Call)?;
        let placement = self
            .placement(agent)
            .ok_or(ReplaceError::Call(CallError::NoAgent))?;
        let unplaced = |why| Err(ReplaceError::Unplaced(why));
        if placement.joint || !placement.committed {
            return unplaced(Unplaced::InProgress);
        }
        if !placement.replicas.contains(&remove) {
            return unplaced(Unplaced::NotAReplica);
        }
        if placement.replicas.contains(&add) {
            return unplaced(Unplaced::AlreadyAReplica);
        }
        if self
            .space
            .as_ref()
            .and_then(|space| space.node(add))
            .is_none()
        {
            return unplaced(Unplaced::NotInTheSpace);
        }
        if !self.could_run(agent, add, CAPABLE).await {
            return unplaced(Unplaced::CannotRun);
        }
        let mut members: Vec<NodeNumber> = placement
            .replicas
            .iter()
            .copied()
            .filter(|node| *node != remove)
            .chain([add])
            .collect();
        members.sort_unstable();
        let (answer, answered) = smol::channel::bounded(1);
        let change = Local::ChangeMembership {
            current: placement.replicas.clone(),
            members,
            answer,
        };
        if !self.propose(agent, change) {
            return Err(ReplaceError::Call(CallError::Stopped));
        }
        let joint = match answered.recv().await {
            Ok(Ok(index)) => index,
            Ok(Err(vos_raft::core::ChangeMembershipError::NotLeader)) => {
                return Err(ReplaceError::Call(self.not_leader(&run.shared)));
            }
            Ok(Err(vos_raft::core::ChangeMembershipError::InProgress)) => {
                return unplaced(Unplaced::InProgress);
            }
            _ => return Err(ReplaceError::Call(CallError::Stopped)),
        };
        let mut until = Instant::now() + REPLACED;
        let mut leading = true;
        loop {
            if let Some(placement) = self.placement(agent)
                && placement.index > joint
                && !placement.joint
                && placement.committed
            {
                return Ok(placement.replicas);
            }
            if leading && run.shared.state().role != Role::Leader {
                leading = false;
                until = until.min(Instant::now() + REPLACED_ELSEWHERE);
            }
            if Instant::now() >= until {
                return Err(ReplaceError::TimedOut);
            }
            smol::Timer::after(Duration::from_millis(20)).await;
        }
    }

    /// Create an agent with `replicas` (this node alone when empty),
    /// running this node's agent program. Answered once a majority of the
    /// replicas hold its record durably.
    pub(crate) async fn create_agent(
        self: &Arc<Self>,
        replicas: Vec<NodeNumber>,
    ) -> Result<AgentId, CallError> {
        let mut replicas = if replicas.is_empty() {
            vec![self.number]
        } else {
            replicas
        };
        replicas.sort_unstable();
        replicas.dedup();
        let known = |node: &NodeNumber| match &self.space {
            Some(space) => space.node(*node).is_some(),
            None => *node == self.number,
        };
        if let Some(node) = replicas.iter().find(|node| !known(node)) {
            return Err(CallError::Failed(format!(
                "node {node} is not in the space"
            )));
        }
        let mut next = self.next_agent.lock().await;
        let agent = AgentId(u32::from(self.number) << 24 | *next);
        if *next >= 1 << 24 || agent == crate::store::NODE_AGENT {
            return Err(CallError::Failed(
                "this node's agent ids are exhausted".into(),
            ));
        }
        let record = CreationRecord {
            agent,
            replicas,
            creator: self.number,
            time: (self.clock)(),
            program: self.program_hash,
            accumulate_gas: self.settings.accumulate_gas,
        };
        let placement = Placement::created(&record);
        self.storage
            .commit(vec![
                Change::Agent(record.clone()),
                Change::Placement {
                    agent,
                    placement: placement.clone(),
                },
            ])
            .await
            .map_err(CallError::Failed)?;
        *next += 1;
        drop(next);
        self.learn(record.clone(), placement);
        self.announce(agent);
        if !self.held_by_majority(&record).await {
            return Err(CallError::Unconfirmed(agent));
        }
        Ok(agent)
    }

    /// Install a package: its programs stored, then the install queued at
    /// the leader, its entry naming their blobs.
    pub(crate) async fn install(
        &self,
        agent: AgentId,
        instance: InstanceId,
        program: Vec<u8>,
        attestables: Vec<(MethodId, Vec<u8>)>,
        roles: Vec<(Vec<u8>, u8)>,
    ) -> Result<Answered, CallError> {
        // A follower refuses before storing anything.
        self.settled(agent).await?;
        let run = self.run(agent).ok_or_else(|| self.absent(agent))?;
        if run.shared.state().role != Role::Leader {
            return Err(self.not_leader(&run.shared));
        }
        let pool = Arc::clone(&self.pool);
        let pooled = self
            .executors
            .run(move || {
                let mut stored = Vec::new();
                let mut pooled = |blob: Vec<u8>| -> Result<ProgramHash, CallError> {
                    let hash = pool
                        .install(&blob)
                        .map_err(|error| CallError::Failed(format!("{error:?}")))?;
                    let reference = BlobRef {
                        hash: hash.0,
                        len: blob.len() as u64,
                    };
                    stored.push((reference, Arc::new(blob)));
                    Ok(ProgramHash(hash.0))
                };
                let program = pooled(program)?;
                let attestables = attestables
                    .into_iter()
                    .map(|(method, blob)| Ok((method, pooled(blob)?)))
                    .collect::<Result<Vec<_>, CallError>>()?;
                Ok((program, attestables, stored))
            })
            .await
            .map_err(|panicked| CallError::Failed(panicked.0))?;
        let (program, attestables, stored) = pooled?;
        // Stored, a blob is kept by its age until the entry names it; the
        // apply then pins it.
        let mut references = Vec::with_capacity(stored.len());
        for (reference, blob) in stored {
            self.blobs
                .put(reference, blob)
                .await
                .map_err(CallError::Failed)?;
            references.push(reference);
        }
        let admin = Admin::Install {
            instance,
            program,
            attestables,
            roles,
        };
        let (answer, reply) = smol::channel::bounded(1);
        self.push(
            agent,
            Pending::Admin {
                admin,
                answer,
                blobs: references,
            },
        )?;
        self.admin_answer(reply).await
    }

    /// A queued admin command's answer, within the node's deadline. Sent
    /// again, an admin command is safe: an install and a role overwrite.
    async fn admin_answer(
        &self,
        reply: smol::channel::Receiver<Result<Answered, CallError>>,
    ) -> Result<Answered, CallError> {
        match timeout(self.settings.answered, reply.recv()).await {
            Some(answer) => answer.map_err(|_| CallError::Stopped)?,
            None => Err(CallError::TimedOut),
        }
    }

    /// Run `work` on an executor, off the thread every leader shares.
    pub(crate) async fn offload<T: Send + 'static>(
        &self,
        work: impl FnOnce() -> T + Send + 'static,
    ) -> Option<T> {
        self.executors.run(work).await.ok()
    }

    pub(crate) async fn admin(&self, agent: AgentId, admin: Admin) -> Result<Answered, CallError> {
        self.settled(agent).await?;
        let (answer, reply) = smol::channel::bounded(1);
        self.push(
            agent,
            Pending::Admin {
                admin,
                answer,
                blobs: Vec::new(),
            },
        )?;
        self.admin_answer(reply).await
    }

    /// A call: queued at once when the group knows where calls go, so
    /// calls made together share a batch; else once it does.
    pub(crate) fn call(
        self: &Arc<Self>,
        agent: AgentId,
        request: Request,
    ) -> impl Future<Output = Result<Answered, CallError>> + use<> {
        let (answer, reply) = smol::channel::bounded(1);
        let mut pending = Some(Pending::Request { request, answer });
        let known = self.run(agent).is_some_and(|run| {
            let state = run.shared.state();
            state.stopped || self.knows_leader(&run, &state)
        });
        let queued = known.then(|| self.push(agent, pending.take().expect("a pending call")));
        let inner = Arc::clone(self);
        async move {
            match queued {
                Some(queued) => queued?,
                None => {
                    inner.settled(agent).await?;
                    inner.push(agent, pending.take().expect("a pending call"))?;
                }
            }
            reply.recv().await.map_err(|_| CallError::Stopped)?
        }
    }

    /// Run a query on this replica's applied state, once it has applied
    /// what it recovered.
    pub(crate) async fn query(
        self: &Arc<Self>,
        agent: AgentId,
        caller: Principal,
        instance: InstanceId,
        method: MethodId,
        arguments: Vec<u8>,
    ) -> Result<(Outcome, u64), CallError> {
        let run = self.run(agent).ok_or_else(|| self.absent(agent))?;
        let state = run
            .shared
            .wait(|state| state.stopped || state.applied >= state.recovered)
            .await;
        if state.stopped {
            return Err(CallError::Stopped);
        }
        let snapshot = Arc::new(self.store.snapshot());
        let failed = |error: fjall::Error| CallError::Failed(error.to_string());
        let at = snapshot.applied(agent).map_err(failed)?.unwrap_or(0);
        let (time, seed) = snapshot
            .last_result(agent)
            .map_err(failed)?
            .unwrap_or((0, [0; 32]));
        let work = Work::Query(Query {
            time,
            seed,
            caller,
            instance,
            method,
            arguments,
        });
        let program = Arc::clone(&self.program);
        let pool = Arc::clone(&self.pool);
        let blobs = self.blobs.clone();
        let gas = self.settings.refine_gas;
        let failed = |fault: Fault| CallError::Failed(fault.message().to_string());
        let (output, _) = ran(self
            .executors
            .run(move || pvm::refine(&program, &pool, &blobs, snapshot, agent, &work, gas))
            .await)
        .map_err(failed)?;
        Ok((pvm::decode::<Outcome>(&output).map_err(failed)?, at))
    }

    /// Mark `epoch` of `agent`'s as one a drop runs on, before the drop can
    /// remove a row.
    pub(crate) fn dropping(&self, agent: AgentId, epoch: u8) {
        *lock(&self.dropping).entry((agent, epoch)).or_default() += 1;
    }

    /// A drop on `epoch` of `agent`'s ended.
    pub(crate) fn dropped(&self, agent: AgentId, epoch: u8) {
        let mut dropping = lock(&self.dropping);
        if let Some(running) = dropping.get_mut(&(agent, epoch)) {
            *running -= 1;
            if *running == 0 {
                dropping.remove(&(agent, epoch));
            }
        }
    }

    /// Whether a drop runs on `epoch` of `agent`'s.
    pub(crate) fn is_dropping(&self, agent: AgentId, epoch: u8) -> bool {
        lock(&self.dropping).contains_key(&(agent, epoch))
    }

    /// Run `task` on the node's thread until it ends or the node stops.
    pub(crate) fn spawn(&self, task: impl Future<Output = ()> + Send + 'static) {
        // A node shutting down runs nothing new: what such a task would do
        // (an old epoch dropped, say) is done again at the next start.
        if self.closing.load(Ordering::SeqCst) {
            return;
        }
        let task = self.runtime.spawn(task);
        lock(&self.tasks).push(task);
    }
}

/// The node's tasks, finished ones dropped whenever the list has doubled
/// since: a spawn costs the same however many tasks run.
#[derive(Default)]
struct Tasks {
    list: Vec<smol::Task<()>>,
    prune_at: usize,
}

impl Tasks {
    /// The fewest tasks the list holds before it is pruned.
    const PRUNE_AT: usize = 64;

    fn push(&mut self, task: smol::Task<()>) {
        if self.list.len() >= self.prune_at {
            self.list.retain(|task| !task.is_finished());
            self.prune_at = (2 * self.list.len()).max(Self::PRUNE_AT);
        }
        self.list.push(task);
    }
}

/// A value of an agent's applied state; `None` when absent or unreadable.
pub(crate) fn read<T: Decode>(
    snapshot: &Snapshot,
    agent: AgentId,
    key: &[u8],
) -> Result<Option<T>, Fault> {
    let bytes = snapshot
        .get(agent, key)
        .map_err(|error| Fault::Infrastructure(error.to_string()))?;
    Ok(bytes.and_then(|bytes| T::decode(unstored(&bytes)?).ok().map(|(value, _)| value)))
}

/// An executor's answer, a panic there being the node's fault.
pub(crate) fn ran<T>(
    answer: Result<Result<T, Fault>, crate::executor::Panicked>,
) -> Result<T, Fault> {
    answer
        .unwrap_or_else(|panicked| Err(Fault::Infrastructure(format!("panicked: {}", panicked.0))))
}

/// The reply a step gives its request.
pub(crate) fn reply(step: &Step) -> Reply {
    match step {
        Step::Ran(run) => Reply::Ran(run.outcome.clone()),
        Step::Refused { code, .. } => Reply::Refused(*code),
        // Not a request's step: the agent paired them wrongly.
        Step::Swept { .. } => Reply::Failed,
    }
}

/// A VOS node on one process.
pub struct Node {
    inner: Arc<Inner>,
    data: PathBuf,
    /// The seed of the node's key.
    secret: [u8; 32],
    ingress_tls: Option<IngressTls>,
    /// The ingress, and what stops it.
    ingress: Mutex<Option<(smol::Task<()>, smol::channel::Sender<()>)>>,
    stop: Option<smol::channel::Sender<()>>,
    runtime: Vec<JoinHandle<()>>,
    /// The pair heartbeat's thread, and what stops it.
    liveness: Option<(smol::channel::Sender<()>, JoinHandle<()>)>,
    /// The blob collector's thread, and what stops it.
    collector: Option<(mpsc::Sender<()>, JoinHandle<()>)>,
}

impl Node {
    /// The node's identity, its public key, which its TLS presents.
    pub fn id(&self) -> NodeId {
        self.inner.node_id
    }

    /// Snapshots this node's groups switched to.
    pub fn snapshots_installed(&self) -> u64 {
        self.inner.installed.load(Ordering::Relaxed)
    }

    /// Snapshot streams this node started to its followers.
    pub fn snapshots_streamed(&self) -> u64 {
        self.inner.streamed.load(Ordering::Relaxed)
    }

    /// Messages this node sent toward agents on other nodes, again on
    /// rounds included.
    pub fn messages_sent_across(&self) -> u64 {
        self.inner.sent_across.load(Ordering::Relaxed)
    }

    /// Messages this node relayed to their agent's leader.
    pub fn messages_relayed(&self) -> u64 {
        self.inner.relayed.load(Ordering::Relaxed)
    }

    /// The node's number in its space.
    pub fn number(&self) -> NodeNumber {
        self.inner.number
    }

    /// Create an agent running the node's agent program, replicated on
    /// this node alone. Blocks until its record is durable.
    pub fn create_agent(&self) -> Result<AgentId, CallError> {
        self.create_replicated(Vec::new())
    }

    /// Create an agent replicated on `replicas`. Blocks until a majority
    /// of them hold its record.
    pub fn create_replicated(&self, replicas: Vec<NodeNumber>) -> Result<AgentId, CallError> {
        let inner = Arc::clone(&self.inner);
        smol::block_on(
            self.inner
                .runtime
                .spawn(async move { inner.create_agent(replicas).await }),
        )
    }

    /// Replace `agent`'s replica `remove` by node `add`: the replicas once
    /// the change committed.
    pub fn replace(
        &self,
        agent: AgentId,
        remove: NodeNumber,
        add: NodeNumber,
    ) -> Result<Vec<NodeNumber>, ReplaceError> {
        let inner = Arc::clone(&self.inner);
        smol::block_on(
            self.inner
                .runtime
                .spawn(async move { inner.replace(agent, remove, add).await }),
        )
    }

    /// Where `agent` runs, as this node last heard.
    pub fn placement(&self, agent: AgentId) -> Option<Placement> {
        self.inner.placement(agent)
    }

    /// This node's replica of `agent`, as the operator's status route
    /// reports it, if it runs one.
    pub fn replica(&self, agent: AgentId) -> Option<vos_wire::ingress::ReplicaStatus> {
        match self.inner.replica_status(agent) {
            vos_wire::ingress::Answer::Status(status) => Some(status),
            _ => None,
        }
    }

    /// Whether this node's replica leads `agent`'s group.
    pub fn leads(&self, agent: AgentId) -> bool {
        self.inner
            .run(agent)
            .is_some_and(|run| run.shared.state().role == Role::Leader)
    }

    /// The last index this node's replica of `agent` applied.
    pub fn applied(&self, agent: AgentId) -> Option<u64> {
        Some(self.inner.run(agent)?.shared.state().applied)
    }

    /// Install a package as `instance` of `agent`: its actor program, the
    /// program of each attestable method, and its roles' bytes. The blobs
    /// are stored and pooled, then the install is queued and answered.
    pub fn install(
        &self,
        agent: AgentId,
        instance: InstanceId,
        program: &[u8],
        attestables: &[(MethodId, &[u8])],
        roles: Vec<(Vec<u8>, u8)>,
    ) -> impl Future<Output = Result<Reply, CallError>> + use<> {
        let inner = Arc::clone(&self.inner);
        let program = program.to_vec();
        let attestables: Vec<(MethodId, Vec<u8>)> = attestables
            .iter()
            .map(|(method, blob)| (*method, blob.to_vec()))
            .collect();
        // On the node's thread, as every queueing is.
        self.inner.runtime.spawn(async move {
            inner
                .install(agent, instance, program, attestables, roles)
                .await
                .map(|answered| answered.reply)
        })
    }

    /// Grant `principal` a role in `agent`, or (`None`) revoke it.
    pub fn set_role(
        &self,
        agent: AgentId,
        principal: Principal,
        role: Option<u8>,
    ) -> impl Future<Output = Result<Reply, CallError>> + use<> {
        let inner = Arc::clone(&self.inner);
        self.inner.runtime.spawn(async move {
            inner
                .admin(agent, Admin::SetRole(Grant { principal, role }))
                .await
                .map(|answered| answered.reply)
        })
    }

    /// A client request to `agent`, answered once its step is applied here.
    pub fn call(
        &self,
        agent: AgentId,
        request: Request,
    ) -> impl Future<Output = Result<Reply, CallError>> + use<> {
        let call = self.inner.call(agent, request);
        async move { call.await.map(|answered| answered.reply) }
    }

    /// Run a query handler on `agent`'s applied state. It never enters the
    /// log; its time and seed are the last applied work result's.
    pub fn query(
        &self,
        agent: AgentId,
        caller: Principal,
        instance: InstanceId,
        method: MethodId,
        arguments: Vec<u8>,
    ) -> impl Future<Output = Result<Outcome, CallError>> + use<> {
        let inner = Arc::clone(&self.inner);
        async move {
            inner
                .query(agent, caller, instance, method, arguments)
                .await
                .map(|(outcome, _)| outcome)
        }
    }

    /// Queue a message for `target` as delivery from its sender would.
    /// Delivery orders each pair's messages; this does not, so a test can
    /// deliver out of order.
    pub fn deliver(&self, target: AgentId, message: Message) -> Result<(), CallError> {
        self.inner.push(target, Pending::Message(message))
    }

    /// How long its stages took since it started, as its operator's stats
    /// route reports them.
    pub fn stats(&self) -> vos_wire::ingress::Stats {
        self.inner.stats()
    }

    /// The node's storage, to read applied state and the log.
    pub fn store(&self) -> &Fjall {
        &self.inner.store
    }

    /// The latest root of `agent`'s committed map `map`, the state version
    /// it holds, and a proof of `keys` against it, from one storage
    /// snapshot. Refused as building while a build is part-way through the
    /// map.
    pub fn prove<K: AsRef<[u8]>>(
        &self,
        agent: AgentId,
        map: vos_wire::ids::MapId,
        keys: &[K],
    ) -> Result<crate::roots::Proven, crate::roots::Error> {
        crate::roots::prove(&self.inner.store.snapshot(), agent, map, keys)
    }

    /// The blobs some agent keeps here: the programs its instances run.
    pub fn pinned(&self) -> Vec<[u8; 32]> {
        self.inner.blobs.pinned().unwrap_or_default()
    }

    /// Whether the blob store holds `hash`.
    pub fn stores_blob(&self, hash: &[u8; 32]) -> bool {
        self.inner.blobs.contains(hash).unwrap_or(false)
    }

    /// Whether the machine pool holds `program`: instances of it run
    /// without loading it first.
    pub fn pooled(&self, program: &[u8; 32]) -> bool {
        self.inner.pool.program(&CodeHash(*program)).is_some()
    }

    /// Serve the HTTP ingress on `address` (`127.0.0.1:0` picks a port):
    /// the address it listens on. The operator's token goes to the data
    /// directory, readable by its owner only. Without TLS, only a loopback
    /// address is served (`0.0.0.0` and `::` are not loopback).
    pub fn serve(&self, address: SocketAddr) -> Result<SocketAddr, Error> {
        let tls = match &self.ingress_tls {
            Some(tls) => Some(crate::tls::server_config(tls, &self.secret).map_err(Error::Data)?),
            None if address.ip().is_loopback() => None,
            None => {
                return Err(Error::Data(format!(
                    "{address}: plain HTTP serves loopback addresses only; give the ingress TLS"
                )));
            }
        };
        let token = seed();
        write_token(&self.data.join(ADMIN_TOKEN), &token)
            .map_err(|error| Error::Data(error.to_string()))?;
        let listener = smol::block_on(smol::net::TcpListener::bind(address))
            .map_err(|error| Error::Data(error.to_string()))?;
        let local = listener
            .local_addr()
            .map_err(|error| Error::Data(error.to_string()))?;
        let ingress = crate::ingress::Ingress::new(Arc::clone(&self.inner), token);
        let (stop, stopped) = smol::channel::bounded(1);
        let task = self
            .inner
            .runtime
            .spawn(ingress.serve(listener, tls, stopped));
        *lock(&self.ingress) = Some((task, stop));
        Ok(local)
    }
}

#[cfg(test)]
mod tests {
    use super::{Config, Node, Tasks};
    use std::sync::Arc;

    /// A node stopped while an executor runs a job holding its state (as
    /// a signature check did, and any job may) is gone once its stop
    /// returns, its store and the store's lock with it: it opens again on
    /// the same directory at once.
    #[test]
    fn a_node_stopped_while_a_job_holds_it_opens_again_at_once() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../agent/default/target/riscv64em-vos/release/vos-agent.elf"
        );
        let elf = std::fs::read(path).expect("run `just build-agent`");
        let agent = vos_pvm_compiler::link_elf_spi(&elf).expect("links");
        let dir = tempfile::tempdir().unwrap();
        let node = Node::open(dir.path(), Config::new(agent.clone())).unwrap();
        let (started, start) = std::sync::mpsc::channel();
        let held = Arc::clone(&node.inner);
        let job = node.inner.executors.run(move || {
            started.send(()).unwrap();
            std::thread::sleep(std::time::Duration::from_millis(600));
            drop(held);
        });
        start.recv().unwrap();
        node.shutdown();
        drop(job);
        let opened = Node::open(dir.path(), Config::new(agent));
        assert!(opened.is_ok(), "{:?}", opened.err());
    }

    /// An epoch a drop runs on is chosen for no install, though a pass of
    /// the drop has emptied it: the drop's next pass would take the
    /// install's rows.
    #[test]
    fn an_epoch_being_dropped_takes_no_install() {
        use crate::group::empty_epoch;
        use crate::storage::Change;
        use vos_wire::ids::AgentId;
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../agent/default/target/riscv64em-vos/release/vos-agent.elf"
        );
        let elf = std::fs::read(path).expect("run `just build-agent`");
        let agent_program = vos_pvm_compiler::link_elf_spi(&elf).expect("links");
        let dir = tempfile::tempdir().unwrap();
        let node = Node::open(dir.path(), Config::new(agent_program)).unwrap();
        let inner = &node.inner;
        let agent = AgentId(9);
        let commit = |change: Change| smol::block_on(inner.storage.commit(vec![change])).unwrap();
        // An abandoned install's rows in epoch 1: not empty, so not chosen.
        commit(Change::Stage {
            agent,
            epoch: 1,
            first: true,
            rows: vec![(b"\x01row".to_vec(), b"value".to_vec())],
        });
        assert_eq!(empty_epoch(inner, agent), Some(2));
        // Its drop runs, and one pass empties it.
        inner.dropping(agent, 1);
        commit(Change::DropEpoch {
            agent,
            epoch: 1,
            limit: usize::MAX,
        });
        assert_eq!(empty_epoch(inner, agent), Some(2), "chosen mid-drop");
        inner.dropped(agent, 1);
        assert_eq!(empty_epoch(inner, agent), Some(1));
        // A retirement's drops mark every epoch before their first pass,
        // and unmark each once it is gone.
        commit(Change::Stage {
            agent,
            epoch: 3,
            first: true,
            rows: vec![(b"\x01row".to_vec(), b"value".to_vec())],
        });
        let mut drops = Box::pin(crate::group::drop_stale_epochs(inner, agent));
        if smol::block_on(smol::future::poll_once(&mut drops)).is_none() {
            assert!(inner.is_dropping(agent, 3), "dropped unmarked");
            smol::block_on(drops);
        }
        assert!(!inner.is_dropping(agent, 3));
        assert_eq!(empty_epoch(inner, agent), Some(1));
    }

    #[test]
    fn finished_tasks_do_not_pile_up() {
        let executor = smol::Executor::new();
        let mut tasks = Tasks::default();
        for _ in 0..10_000 {
            tasks.push(executor.spawn(async {}));
            while executor.try_tick() {}
        }
        assert!(
            tasks.list.len() <= Tasks::PRUNE_AT + 1,
            "{}",
            tasks.list.len()
        );
        // Tasks still running are kept.
        let (_hold, held) = smol::channel::bounded::<()>(1);
        for _ in 0..200 {
            let held = held.clone();
            tasks.push(executor.spawn(async move {
                let _ = held.recv().await;
            }));
        }
        while executor.try_tick() {}
        assert!(tasks.list.len() >= 200);
    }
}
