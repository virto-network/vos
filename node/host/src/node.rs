//! The node: every agent's replica group, applier and leader loop on one
//! async thread, the executor threads for PVM work, the storage thread,
//! the machine pool, and the network to the space's other nodes.
//!
//! Per agent, a leader's batch runs strictly in order: refine, a dry run
//! of accumulate, the result proposed and replicated, and once this
//! replica has applied it, the replies, the outbox's deliveries and the
//! acknowledgements. Every replica applies the committed log the same way.

use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use std::future::Future;
use std::net::SocketAddr;
use std::panic::AssertUnwindSafe;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ed25519_dalek::SigningKey;
use smol::future::FutureExt;
use vos_net::{Class, Network, Refused};
use vos_pvm::PvmBackend;
use vos_pvm::pool::{CodeHash, MachinePool, OuterMachines};
use vos_raft::Role;
use vos_wire::batch::{Admin, Input, Message, Query, Request, Work};
use vos_wire::ids::{AgentId, InstanceId, MethodId, Principal, ProgramHash};
use vos_wire::ingress::{Contact, NodeId, Unplaced};
use vos_wire::peer::{CreationRecord, NodeNumber, Placement};
use vos_wire::records::unstored;
use vos_wire::result::{Outcome, Step, Write};
use vos_wire::{Decode, defaults};

use crate::Hooks;
use crate::blobs::Blobs;
use crate::executor::Executors;
use crate::group::{self, DryRun, Input as GroupInput, Local, Shared};
use crate::pvm::{self, Fault};
use crate::space::Space;
use crate::storage::{Change, StorageThread};
use crate::store::{Batch as _, BlobRef, Durability, Fjall, FjallSnapshot, LogEntry, Store, View};
use crate::tls::IngressTls;

/// How a node reaches the other nodes of its space.
#[derive(Clone)]
pub enum Peers {
    /// QUIC, listening on this node's peer address in the space.
    Quic,
    /// A hub in this process, for tests.
    Hub(vos_net::memory::Hub),
}

/// How a node runs.
pub struct Config {
    /// The agent program every agent runs, as a standard program.
    pub agent: Vec<u8>,
    /// Executor threads for PVM work.
    pub executors: usize,
    /// Client requests an agent queues before a call answers busy.
    pub queue: usize,
    /// The most inputs, and argument bytes, in one batch.
    pub max_inputs: usize,
    pub max_bytes: usize,
    /// How long a leader waits for more inputs after the first, when it
    /// found its queue empty.
    pub linger: Duration,
    pub refine_gas: u64,
    /// Accumulate's gas for the agents this node creates: their creation
    /// records carry it to every replica.
    pub accumulate_gas: u64,
    pub hooks: Arc<dyn Hooks>,
    /// Milliseconds since the Unix epoch: work-result time, and ingress's
    /// freshness checks. A test moves it.
    pub clock: Arc<dyn Fn() -> u64 + Send + Sync>,
    /// TLS on the ingress. Without it, the ingress serves loopback
    /// addresses only.
    pub ingress_tls: Option<IngressTls>,
    /// The space this node runs in. Without one, it is a space of one, as
    /// node 0.
    pub space: Option<Space>,
    pub peers: Peers,
    /// A replica group's election timeout, drawn between these, and its
    /// leader's heartbeat, in milliseconds.
    pub election_timeout_ms: (u64, u64),
    pub heartbeat_ms: u64,
    /// A group's log is compacted once this many entries past its start
    /// are applied durably, and keeps this many below the point it could
    /// compact to, for a follower a little behind.
    pub compact_every: u64,
    pub compact_tail: u64,
    /// About how many bytes of rows one snapshot chunk carries.
    pub snapshot_chunk: usize,
}

impl Config {
    pub fn new(agent: Vec<u8>) -> Self {
        Self {
            agent,
            executors: std::thread::available_parallelism()
                .map_or(1, |cores| cores.get().saturating_sub(1).max(1)),
            queue: 1024,
            max_inputs: 256,
            max_bytes: 1 << 20,
            linger: Duration::from_millis(2),
            refine_gas: defaults::REFINE_GAS,
            accumulate_gas: defaults::REFINE_GAS,
            hooks: Arc::new(crate::NoHooks),
            clock: Arc::new(wall_clock),
            ingress_tls: None,
            space: None,
            peers: Peers::Quic,
            election_timeout_ms: (1500, 3000),
            heartbeat_ms: 500,
            compact_every: 1024,
            compact_tail: 256,
            snapshot_chunk: 1 << 20,
        }
    }
}

/// How the node answered a request or an admin command.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reply {
    /// The step ran: the handler's reply, or its failure.
    Ran(Outcome),
    /// Refine refused it, with a code from [`vos_wire::abi::refusal`].
    Refused(u32),
    /// The agent program fails on a batch holding this input alone.
    Failed,
    /// A duplicate whose reply the window no longer keeps.
    TooOld,
}

/// Why a call has no reply.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CallError {
    /// The agent's queue is full.
    Busy,
    NoAgent,
    /// The agent's leader stopped before answering.
    Stopped,
    /// Storage or the agent program failed.
    Failed(String),
    /// This node does not lead the agent: its leader, when known.
    NotLeader(Option<Contact>),
    /// This node does not replicate the agent: its replicas.
    Elsewhere(Vec<Contact>),
    /// The agent is created, but a majority of its replicas does not hold
    /// its record yet: it reaches them as they return.
    Unconfirmed(AgentId),
}

#[derive(Debug)]
pub enum Error {
    Store(fjall::Error),
    /// The agent program does not load, or a stored program does not
    /// install.
    Program(String),
    /// The refine gas cannot fit the largest handler with the agent's
    /// reserves: some input could never be dispatched.
    Gas,
    /// A stored value the node cannot read.
    Unreadable(String),
    /// The data directory, the space, the network or the ingress's
    /// listener failed.
    Data(String),
}

impl From<fjall::Error> for Error {
    fn from(error: fjall::Error) -> Self {
        Error::Store(error)
    }
}

/// A reply, with the applied index of the state it reflects.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Answered {
    pub(crate) reply: Reply,
    pub(crate) at: u64,
}

pub(crate) type Answer = smol::channel::Sender<Result<Answered, CallError>>;

/// A queued input, with where its reply goes.
pub(crate) enum Pending {
    Request(Request, Answer),
    /// An admin command, with the blobs its entry names.
    Admin(Admin, Answer, Vec<BlobRef>),
    Message(Message),
    Ack {
        to: AgentId,
        sequence: u64,
    },
    /// The leader's sweep of expired sessions.
    Sweep,
}

impl Pending {
    pub(crate) fn input(&self) -> Input {
        match self {
            Pending::Request(request, _) => Input::Request(request.clone()),
            Pending::Admin(admin, _, _) => Input::Admin(admin.clone()),
            Pending::Message(message) => Input::Message(message.clone()),
            Pending::Ack { to, sequence } => Input::Ack {
                to: *to,
                sequence: *sequence,
            },
            Pending::Sweep => Input::Sweep,
        }
    }

    pub(crate) fn bytes(&self) -> usize {
        match self {
            Pending::Request(request, _) => request.arguments.len(),
            Pending::Message(message) => message.arguments.len(),
            Pending::Admin(..) | Pending::Ack { .. } | Pending::Sweep => 0,
        }
    }

    /// Counts against the queue cap: what a client queued.
    pub(crate) fn capped(&self) -> bool {
        matches!(self, Pending::Request(..) | Pending::Admin(..))
    }

    /// Counts against the cap on the messages other agents queue, which
    /// other nodes now fill. Acknowledgements do not: they open this
    /// agent's own windows, and the batch takes one per target.
    pub(crate) fn agents_sent(&self) -> bool {
        matches!(self, Pending::Message(_))
    }
}

#[derive(Default)]
pub(crate) struct Queue {
    pub(crate) inputs: VecDeque<Pending>,
    /// Capped inputs queued.
    pub(crate) capped: usize,
    /// Messages from other agents queued.
    pub(crate) from_agents: usize,
    pub(crate) stopped: bool,
    /// The leader loop takes inputs: set when this replica's leadership
    /// starts, and cleared with the refusal of what it left. Under the
    /// queue's lock, so no input is queued where no loop will take it.
    pub(crate) leading: bool,
}

pub(crate) struct Agent {
    pub(crate) queue: Mutex<Queue>,
    wake: smol::channel::Sender<()>,
    pub(crate) woken: smol::channel::Receiver<()>,
}

impl Agent {
    fn new() -> Self {
        let (wake, woken) = smol::channel::bounded(1);
        Self {
            queue: Mutex::new(Queue::default()),
            wake,
            woken,
        }
    }

    /// Stop the agent's leader after its batch in flight. Queued inputs are
    /// dropped: their callers see `Stopped`.
    pub(crate) fn stop(&self) {
        let dropped = {
            let mut queue = self.queue.lock().expect("the queue");
            queue.stopped = true;
            queue.capped = 0;
            queue.from_agents = 0;
            std::mem::take(&mut queue.inputs)
        };
        drop(dropped);
        let _ = self.wake.try_send(());
    }

    /// Answer every queued input with `error`: this node no longer leads.
    pub(crate) fn refuse(&self, error: &CallError) {
        let refused = {
            let mut queue = self.queue.lock().expect("the queue");
            queue.leading = false;
            queue.capped = 0;
            queue.from_agents = 0;
            std::mem::take(&mut queue.inputs)
        };
        for pending in refused {
            pending.refuse(error);
        }
    }
}

/// What the network sends through.
pub(crate) trait Wire: Send + Sync {
    fn send(
        &self,
        to: NodeNumber,
        class: Class,
        stream: u64,
        frame: Vec<u8>,
    ) -> Result<(), Refused>;

    /// Resolves once `to` can likely take another frame of `class`.
    fn ready(
        &self,
        to: NodeNumber,
        class: Class,
    ) -> std::pin::Pin<Box<dyn Future<Output = ()> + Send + '_>>;
}

impl<T: Network> Wire for T {
    fn send(
        &self,
        to: NodeNumber,
        class: Class,
        stream: u64,
        frame: Vec<u8>,
    ) -> Result<(), Refused> {
        Network::send(self, to, class, stream, frame)
    }

    fn ready(
        &self,
        to: NodeNumber,
        class: Class,
    ) -> std::pin::Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        Box::pin(Network::ready(self, to, class))
    }
}

/// The network endpoint the node holds.
enum Endpoint {
    Quic(Arc<vos_net::quic::Quic>),
    Hub(Arc<vos_net::memory::Endpoint>),
}

/// A placement's order: [`Placement::order`].
pub(crate) type Order = (u64, u64, bool);

/// What a node knows of an agent: its record, and where it runs.
#[derive(Clone, Debug)]
pub(crate) struct Known {
    pub(crate) record: CreationRecord,
    pub(crate) placement: Placement,
}

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
/// agent's program, and how long a replacement waits for its final
/// configuration to commit.
const CAPABLE: Duration = Duration::from_secs(10);
const REPLACED: Duration = Duration::from_secs(30);
/// How long a replacement waits once its node no longer leads: a leader
/// removing itself steps down as the final configuration commits, and
/// announces it as it does; another node that took over announces it once
/// it learns it committed.
const REPLACED_ELSEWHERE: Duration = Duration::from_secs(2);

/// Why a replica was not replaced.
#[derive(Debug)]
pub enum ReplaceError {
    Call(CallError),
    Unplaced(Unplaced),
    /// The change goes on: the agent's placement says where it is.
    TimedOut,
}

/// A group's inbox: Raft messages beyond it are dropped, and resent.
const GROUP_INBOX: usize = 1024;

// A work result as large as refine allows travels in one append.
const _: () = assert!(
    vos_net::Limits::DEFAULT.consensus >= vos_wire::abi::cap::WORK_RESULT + (1 << 20),
    "a consensus frame must hold the largest work result"
);

pub(crate) struct Inner {
    pub(crate) store: Fjall,
    pub(crate) blobs: Blobs,
    pub(crate) storage: StorageThread,
    pub(crate) executors: Executors,
    pub(crate) pool: Arc<MachinePool>,
    pub(crate) program: Arc<OuterMachines>,
    pub(crate) program_hash: ProgramHash,
    queue: usize,
    pub(crate) max_inputs: usize,
    pub(crate) max_bytes: usize,
    pub(crate) linger: Duration,
    pub(crate) refine_gas: u64,
    accumulate_gas: u64,
    pub(crate) hooks: Arc<dyn Hooks>,
    pub(crate) clock: Arc<dyn Fn() -> u64 + Send + Sync>,
    pub(crate) node_id: NodeId,
    /// This node's number in its space.
    pub(crate) number: NodeNumber,
    pub(crate) space: Option<Space>,
    pub(crate) network: Option<Arc<dyn Wire>>,
    pub(crate) election_timeout_ms: (u64, u64),
    pub(crate) heartbeat_ms: u64,
    pub(crate) compact_every: u64,
    pub(crate) compact_tail: u64,
    pub(crate) snapshot_chunk: usize,
    /// Every agent this node knows of, and where it runs.
    pub(crate) directory: Mutex<HashMap<AgentId, Known>>,
    /// For each agent whose placement this node announced, its order and
    /// the nodes yet to hold one at least as new.
    pub(crate) unacknowledged: Mutex<HashMap<AgentId, (Order, BTreeSet<NodeNumber>)>>,
    pub(crate) acknowledged: event_listener::Event,
    /// For each agent, the nodes that said they could not run its program.
    pub(crate) refusing: Mutex<HashMap<AgentId, BTreeSet<NodeNumber>>>,
    /// Who waits to hear whether a node could run an agent's program.
    pub(crate) capable: Mutex<HashMap<(AgentId, NodeNumber), smol::channel::Sender<bool>>>,
    /// The agents this node replicates.
    pub(crate) runs: Mutex<HashMap<AgentId, Arc<Run>>>,
    dry_runs: Mutex<HashMap<AgentId, DryRun>>,
    /// The groups each blob asked for is wanted by.
    wanted: Mutex<HashMap<[u8; 32], BTreeSet<AgentId>>>,
    pub(crate) drops: crate::peer::Drops,
    /// The low 24 bits of the next agent id this node makes.
    next_agent: smol::lock::Mutex<u32>,
    pub(crate) runtime: Arc<smol::Executor<'static>>,
    /// Node-wide tasks: the dispatcher and the directory's resends.
    tasks: Mutex<Vec<smol::Task<()>>>,
    /// Held while a creation record is checked and stored, so two records
    /// for one id are never both written.
    pub(crate) recording: smol::lock::Mutex<()>,
    /// Turns through an agent's replicas, for what goes to one of them.
    pub(crate) turn: std::sync::atomic::AtomicU64,
    /// Messages sent toward other nodes.
    pub(crate) sent_across: std::sync::atomic::AtomicU64,
    /// Snapshots this node's groups switched to.
    pub(crate) installed: std::sync::atomic::AtomicU64,
    /// The node is shutting down: no group starts or retires.
    pub(crate) closing: std::sync::atomic::AtomicBool,
    /// Agents whose retirement is not yet written: no group starts for
    /// them until it is.
    pub(crate) retiring: Mutex<HashSet<AgentId>>,
    /// Messages relayed to their agent's leader.
    pub(crate) relayed: std::sync::atomic::AtomicU64,
    /// Clients' calls: their lanes, and the calls forwarded both ways.
    pub(crate) calls: crate::calls::Calls,
    /// The read indexes this replica asked its leaders for.
    pub(crate) reads: crate::queries::Reads,
}

impl Inner {
    pub(crate) fn run(&self, id: AgentId) -> Option<Arc<Run>> {
        self.runs.lock().expect("the runs").get(&id).cloned()
    }

    /// Why a call to `id` cannot be served here: a replica with no group
    /// running is stopping (or refused the group), and any other node
    /// names the replicas.
    pub(crate) fn absent(&self, id: AgentId) -> CallError {
        match self.directory.lock().expect("the directory").get(&id) {
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
        self.directory
            .lock()
            .expect("the directory")
            .get(&id)
            .map(|known| known.placement.clone())
    }

    /// How clients reach node `number`, from the space.
    pub(crate) fn contact(&self, number: NodeNumber) -> Option<Contact> {
        let node = self.space.as_ref()?.node(number)?;
        Some(Contact {
            address: node.ingress.clone(),
            node: NodeId(node.key),
        })
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
        let caught_up = async {
            run.shared
                .wait(|state| {
                    state.stopped
                        || state
                            .leading_from
                            .is_none_or(|first| state.applied >= first)
                })
                .await;
            true
        };
        let late = async {
            smol::Timer::after(CATCH_UP).await;
            false
        };
        if !caught_up.or(late).await {
            return Err(CallError::Failed(
                "the leader has not applied what it took over".into(),
            ));
        }
        if run.shared.state().stopped || run.agent.queue.lock().expect("the queue").stopped {
            return Err(CallError::Stopped);
        }
        if !run.agent.queue.lock().expect("the queue").leading {
            return Err(self.not_leader(&run.shared));
        }
        Ok(run)
    }

    /// Wait until agent `id`'s group here knows a leader, for a few
    /// election timeouts at most: a call to a group just created, or one
    /// electing, then goes where it should.
    pub(crate) async fn settled(&self, id: AgentId) -> Result<(), CallError> {
        let run = self.run(id).ok_or_else(|| self.absent(id))?;
        let electing = async {
            run.shared
                .wait(|state| state.stopped || self.knows_leader(&run, state))
                .await;
        };
        electing
            .or(async {
                smol::Timer::after(Duration::from_millis(4 * self.election_timeout_ms.1)).await;
            })
            .await;
        Ok(())
    }

    /// Whether `run`'s group knows where calls go: a leader elsewhere, or
    /// this replica's leader loop taking inputs.
    pub(crate) fn knows_leader(&self, run: &Run, state: &group::State) -> bool {
        match state.leader {
            Some(leader) if leader == self.number => {
                run.agent.queue.lock().expect("the queue").leading
            }
            Some(_) => true,
            None => false,
        }
    }

    /// Queue `pending` for agent `id`, whose leader loop this node must
    /// run. Checked under the queue's lock, from any thread.
    pub(crate) fn push(&self, id: AgentId, pending: Pending) -> Result<(), CallError> {
        let run = self.run(id).ok_or_else(|| self.absent(id))?;
        let mut queue = run.agent.queue.lock().expect("the queue");
        if queue.stopped || run.shared.state().stopped {
            return Err(CallError::Stopped);
        }
        if !queue.leading {
            drop(queue);
            return Err(self.not_leader(&run.shared));
        }
        if pending.capped() {
            if queue.capped >= self.queue {
                return Err(CallError::Busy);
            }
            queue.capped += 1;
        }
        // Past the cap, the sender sends it again.
        if pending.agents_sent() {
            if queue.from_agents >= self.queue {
                return Err(CallError::Busy);
            }
            queue.from_agents += 1;
        }
        queue.inputs.push_back(pending);
        drop(queue);
        let _ = run.agent.wake.try_send(());
        Ok(())
    }

    /// Put inputs back at the front of agent `id`'s queue, in order.
    pub(crate) fn requeue(&self, agent: &Agent, inputs: Vec<Pending>) {
        let mut queue = agent.queue.lock().expect("the queue");
        if queue.stopped {
            return;
        }
        for pending in inputs.into_iter().rev() {
            if pending.capped() {
                queue.capped += 1;
            }
            if pending.agents_sent() {
                queue.from_agents += 1;
            }
            queue.inputs.push_front(pending);
        }
    }

    /// Stop every agent: a commit failed, and storage takes no more.
    /// Queued and later calls answer `Stopped`.
    pub(crate) fn halt(&self) {
        let runs: Vec<Arc<Run>> = self
            .runs
            .lock()
            .expect("the runs")
            .values()
            .cloned()
            .collect();
        for run in runs {
            run.agent.stop();
            run.shared.stop();
        }
    }

    /// Learn where an agent runs, and act on it.
    pub(crate) fn learn(self: &Arc<Self>, record: CreationRecord, placement: Placement) {
        let agent = record.agent;
        self.directory
            .lock()
            .expect("the directory")
            .insert(agent, Known { record, placement });
        self.reconsider(agent);
    }

    /// Start the agent's group where its placement names this node, and
    /// retire it where it no longer does: at once while this replica never
    /// held a committed configuration naming it (a configuration that never
    /// committed named it), else once a final configuration without it has
    /// committed and this replica does not lead.
    pub(crate) fn reconsider(self: &Arc<Self>, agent: AgentId) {
        // A group stopping with the node is not started again.
        if self.closing.load(std::sync::atomic::Ordering::SeqCst) {
            return;
        }
        let Some(known) = self
            .directory
            .lock()
            .expect("the directory")
            .get(&agent)
            .cloned()
        else {
            return;
        };
        // A member of the configuration before, while the new one has not
        // committed, may still be needed to vote.
        let named = known.placement.admits(self.number);
        match self.run(agent) {
            None if named => {
                if known.record.program != self.program_hash {
                    tracing::error!(
                        agent = agent.0,
                        "the agent runs another agent program than this node's; its group does not start here"
                    );
                    return;
                }
                // Created with it, a member; added later, a member of the
                // configuration before, so it never campaigns until the
                // configuration naming it reaches it.
                let members = if known.placement.index == 0 {
                    known.record.replicas.clone()
                } else {
                    known
                        .placement
                        .before
                        .iter()
                        .copied()
                        .filter(|node| *node != self.number)
                        .collect()
                };
                self.start(known.record, members);
            }
            Some(run) if !named => {
                let state = run.shared.state();
                let committed_final = known.placement.committed && !known.placement.joint;
                if !state.established || (committed_final && state.role != Role::Leader) {
                    self.retire_agent(agent);
                }
            }
            _ => {}
        }
    }

    /// Stop the agent's group here for good: its log, state and pins go,
    /// in a task of their own once the group has stopped; the record, the
    /// placement and the term and vote stay.
    fn retire_agent(self: &Arc<Self>, agent: AgentId) {
        let run = {
            let mut runs = self.runs.lock().expect("the runs");
            let Some(run) = runs.remove(&agent) else {
                return;
            };
            self.retiring.lock().expect("the retiring").insert(agent);
            run
        };
        tracing::info!(agent = agent.0, "this node no longer replicates the agent");
        run.agent.stop();
        run.shared.stop();
        run.inbox.close();
        run.local.close();
        let inner = Arc::clone(self);
        self.spawn(async move {
            let tasks = std::mem::take(&mut *run.tasks.lock().expect("the run's tasks"));
            for task in tasks {
                task.await;
            }
            inner.finish_retirement(agent).await;
        });
    }

    /// Write the agent's retirement, its group stopped, then reconsider
    /// the agent: a placement naming this node again may have come
    /// meanwhile.
    async fn finish_retirement(self: &Arc<Self>, agent: AgentId) {
        self.write_retirement(agent).await;
        self.retiring.lock().expect("the retiring").remove(&agent);
        self.reconsider(agent);
    }

    /// The agent's state moves to an epoch that holds no rows (not one a
    /// snapshot was staged in), the programs it named are unpinned, and
    /// every stale epoch is dropped.
    async fn write_retirement(&self, agent: AgentId) {
        let read = (|| {
            let snapshot = self.store.snapshot();
            let mut programs = Vec::new();
            for row in snapshot.scan(agent, &vos_wire::keys::installed_prefix(), None) {
                programs.push(row?.1);
            }
            let hard = self.store.raft(agent)?.hard;
            Ok::<_, fjall::Error>((group::programs(programs.iter()), hard))
        })();
        let (programs, hard) = match read {
            Ok(read) => read,
            Err(error) => {
                tracing::error!(agent = agent.0, "a retiring agent is unreadable: {error}");
                return;
            }
        };
        let Some(epoch) = group::empty_epoch(self, agent) else {
            tracing::error!(agent = agent.0, "a retiring agent has no empty epoch");
            return;
        };
        let mut changes = vec![Change::Retire {
            agent,
            epoch,
            hard: crate::store::HardState { commit: 0, ..hard },
        }];
        changes.extend(
            programs
                .into_iter()
                .map(|hash| Change::Unpin { hash, agent }),
        );
        if let Err(error) = self.storage.commit(changes).await {
            tracing::error!(agent = agent.0, "an agent did not retire: {error}");
            return;
        }
        group::drop_stale_epochs(self, agent).await;
    }

    /// Whether this node's store holds anything of `agent`'s replica: a
    /// log, an applied index, a membership, or rows in any epoch.
    fn holds_replica(&self, agent: AgentId) -> Result<bool, fjall::Error> {
        let rows = self.store.raft(agent)?;
        if !rows.log.is_empty()
            || rows.applied > 0
            || rows.log_start.0 > 0
            || rows.membership.is_some()
        {
            return Ok(true);
        }
        let current = self.store.snapshot().epoch(agent)?;
        Ok(self.store.epoch_holds_rows(agent, current)?
            || !self.store.stale_epochs(agent)?.is_empty())
    }

    /// Take `placement`, which this node's leadership of the agent gives,
    /// when it supersedes the one held: kept, acted on, and announced to
    /// every other node until each holds it. False when it was not kept.
    pub(crate) async fn place(self: &Arc<Self>, agent: AgentId, placement: Placement) -> bool {
        let _recording = self.recording.lock().await;
        let Some(known) = self
            .directory
            .lock()
            .expect("the directory")
            .get(&agent)
            .cloned()
        else {
            return true;
        };
        if !placement.supersedes(&known.placement) {
            return true;
        }
        let change = Change::Placement {
            agent,
            placement: placement.clone(),
        };
        if let Err(error) = self.storage.commit(vec![change]).await {
            tracing::warn!(agent = agent.0, "a placement was not kept: {error}");
            return false;
        }
        self.learn(known.record, placement);
        self.announce(agent);
        true
    }

    fn start(self: &Arc<Self>, record: CreationRecord, members: Vec<NodeNumber>) {
        // Under the runs' lock, which the node's shutdown takes to set
        // `closing`: a group starts before the shutdown takes the runs, or
        // not at all.
        let mut runs = self.runs.lock().expect("the runs");
        let id = record.agent;
        if self.closing.load(std::sync::atomic::Ordering::SeqCst)
            || self.retiring.lock().expect("the retiring").contains(&id)
        {
            return;
        }
        let shared = Arc::new(Shared::new(record, members));
        let agent = Arc::new(Agent::new());
        let (inbox, inputs) = smol::channel::bounded(GROUP_INBOX);
        let (local, locals) = smol::channel::unbounded();
        let guarded =
            |name: &'static str, work: std::pin::Pin<Box<dyn Future<Output = ()> + Send>>| {
                let shared = Arc::clone(&shared);
                let agent = Arc::clone(&agent);
                self.runtime.spawn(async move {
                    if AssertUnwindSafe(work).catch_unwind().await.is_err() {
                        tracing::error!(
                            agent = id.0,
                            "the agent's {name} panicked; the agent stops"
                        );
                        agent.stop();
                        shared.stop();
                    }
                })
            };
        let tasks = vec![
            guarded(
                "group",
                Box::pin(group::drive(
                    Arc::clone(self),
                    Arc::clone(&shared),
                    inputs,
                    locals,
                )),
            ),
            guarded(
                "applier",
                Box::pin(group::apply(Arc::clone(self), Arc::clone(&shared))),
            ),
            guarded(
                "leader",
                Box::pin(crate::leader::lead(
                    Arc::clone(self),
                    Arc::clone(&agent),
                    Arc::clone(&shared),
                )),
            ),
        ];
        runs.insert(
            id,
            Arc::new(Run {
                agent,
                shared,
                inbox,
                local,
                tasks: Mutex::new(tasks),
            }),
        );
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
        let applied = async {
            Some(
                run.shared
                    .wait(|state| state.stopped || state.applied >= index)
                    .await,
            )
        };
        let late = async {
            smol::Timer::after(CATCH_UP).await;
            None
        };
        match applied.or(late).await {
            Some(state) if !state.stopped => Ok(()),
            Some(_) => Err(CallError::Stopped),
            None => Err(CallError::Failed(
                "the replica has not applied through its read index".into(),
            )),
        }
    }

    /// Agent `id`'s leader loop stopped for good: its replica hands
    /// leadership over and never leads again.
    pub(crate) fn retire(&self, id: AgentId) {
        self.propose(id, Local::Retire);
    }

    pub(crate) fn keep_dry_run(&self, id: AgentId, dry_run: DryRun) {
        self.dry_runs
            .lock()
            .expect("the dry runs")
            .insert(id, dry_run);
    }

    /// The writes of the leader's dry run of `entry`, if it ran on the
    /// state the entry at `index` applies to: the same entry on the same
    /// state.
    pub(crate) fn dry_run(&self, id: AgentId, index: u64, entry: &LogEntry) -> Option<Vec<Write>> {
        let mut dry_runs = self.dry_runs.lock().expect("the dry runs");
        let kept = dry_runs.remove(&id)?;
        (kept.applied + 1 == index && kept.payload == entry.payload()).then_some(kept.writes)
    }

    /// Agent `id`'s group waits for `hashes`: tell it when they arrive.
    pub(crate) fn want(&self, id: AgentId, hashes: &[[u8; 32]]) {
        let mut wanted = self.wanted.lock().expect("the wanted blobs");
        for hash in hashes {
            wanted.entry(*hash).or_default().insert(id);
        }
    }

    /// Whether a group here asked for `hash`.
    pub(crate) fn is_wanted(&self, hash: &[u8; 32]) -> bool {
        self.wanted
            .lock()
            .expect("the wanted blobs")
            .contains_key(hash)
    }

    /// The groups that wanted `hash`, which arrived.
    pub(crate) fn arrived(&self, hash: &[u8; 32]) {
        let waiting = self
            .wanted
            .lock()
            .expect("the wanted blobs")
            .remove(hash)
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
        let mut until = std::time::Instant::now() + REPLACED;
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
                until = until.min(std::time::Instant::now() + REPLACED_ELSEWHERE);
            }
            if std::time::Instant::now() >= until {
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
            accumulate_gas: self.accumulate_gas,
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
        self.push(agent, Pending::Admin(admin, answer, references))?;
        reply.recv().await.map_err(|_| CallError::Stopped)?
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
        self.push(agent, Pending::Admin(admin, answer, Vec::new()))?;
        reply.recv().await.map_err(|_| CallError::Stopped)?
    }

    /// A call: queued at once when the group knows where calls go, so
    /// calls made together share a batch; else once it does.
    pub(crate) fn call(
        self: &Arc<Self>,
        agent: AgentId,
        request: Request,
    ) -> impl Future<Output = Result<Answered, CallError>> + use<> {
        let (answer, reply) = smol::channel::bounded(1);
        let mut pending = Some(Pending::Request(request, answer));
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
        let gas = self.refine_gas;
        let failed = |fault: Fault| CallError::Failed(fault.message().to_string());
        let output = ran(self
            .executors
            .run(move || pvm::refine(&program, &pool, &blobs, snapshot, agent, &work, gas))
            .await)
        .map_err(failed)?;
        Ok((pvm::decode::<Outcome>(&output).map_err(failed)?, at))
    }

    /// Commit changes to the node's own records.
    pub(crate) async fn commit(&self, changes: Vec<Change>) -> Result<(), String> {
        self.storage.commit(changes).await
    }

    /// Run `task` on the node's thread until it ends or the node stops.
    pub(crate) fn spawn(&self, task: impl Future<Output = ()> + Send + 'static) {
        // A node shutting down runs nothing new: what such a task would do
        // (an old epoch dropped, say) is done again at the next start.
        if self.closing.load(std::sync::atomic::Ordering::SeqCst) {
            return;
        }
        let task = self.runtime.spawn(task);
        let mut tasks = self.tasks.lock().expect("the node's tasks");
        tasks.retain(|task| !task.is_finished());
        tasks.push(task);
    }
}

/// A value of an agent's applied state; `None` when absent or unreadable.
pub(crate) fn read<T: Decode>(
    snapshot: &FjallSnapshot,
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

/// Milliseconds since the Unix epoch, by the system clock.
pub fn wall_clock() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_millis() as u64)
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

pub(crate) fn seed() -> [u8; 32] {
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed).expect("the operating system's randomness");
    seed
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
    endpoint: Option<Endpoint>,
    stop: Option<smol::channel::Sender<()>>,
    runtime: Option<JoinHandle<()>>,
}

/// The node's data directory: its store, and the operator's token.
const STORE: &str = "store";
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
                batch.commit(Durability::Synced)?;
                secret
            }
        };
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
        let (endpoint, arrivals) = match (&config.space, &config.peers) {
            (Some(space), Peers::Quic) if space.nodes().len() > 1 => {
                let listen = space.node(number).expect("this node is in its space").peer;
                let (quic, arrivals) = vos_net::quic::Quic::bind(vos_net::quic::Config {
                    peers: space.peers(),
                    ..vos_net::quic::Config::new(number, secret, listen)
                })
                .map_err(|error| Error::Data(format!("{listen}: {error}")))?;
                (Some(Endpoint::Quic(Arc::new(quic))), Some(arrivals))
            }
            (Some(space), Peers::Hub(hub)) => {
                let (endpoint, arrivals) = hub.join(number);
                endpoint.set_peers(space.peers());
                (Some(Endpoint::Hub(Arc::new(endpoint))), Some(arrivals))
            }
            _ => (None, None),
        };
        let network: Option<Arc<dyn Wire>> = match &endpoint {
            Some(Endpoint::Quic(quic)) => Some(Arc::clone(quic) as Arc<dyn Wire>),
            Some(Endpoint::Hub(hub)) => Some(Arc::clone(hub) as Arc<dyn Wire>),
            None => None,
        };
        let runtime = Arc::new(smol::Executor::new());
        let (stop, stopped) = smol::channel::bounded::<()>(1);
        let thread = {
            let runtime = Arc::clone(&runtime);
            std::thread::Builder::new()
                .name("vos-node".into())
                .spawn(move || smol::block_on(runtime.run(stopped.recv())).unwrap_or(()))
                .expect("the node's thread starts")
        };
        let next = records
            .iter()
            .filter(|record| CreationRecord::creator_of(record.agent) == number)
            .map(|record| (record.agent.0 & 0x00ff_ffff) + 1)
            .max()
            .unwrap_or(1);
        let inner = Arc::new(Inner {
            storage: StorageThread::spawn(store.clone(), Arc::clone(&config.hooks)),
            store,
            blobs,
            executors: Executors::spawn(config.executors),
            pool,
            program: Arc::new(program),
            program_hash,
            queue: config.queue,
            max_inputs: config.max_inputs.max(1),
            max_bytes: config.max_bytes,
            linger: config.linger,
            refine_gas: config.refine_gas,
            accumulate_gas: config.accumulate_gas,
            hooks: config.hooks,
            clock: config.clock,
            node_id,
            number,
            space: config.space,
            network,
            election_timeout_ms: config.election_timeout_ms,
            heartbeat_ms: config.heartbeat_ms,
            compact_every: config.compact_every,
            compact_tail: config.compact_tail,
            snapshot_chunk: config.snapshot_chunk,
            directory: Mutex::new(HashMap::new()),
            unacknowledged: Mutex::new(HashMap::new()),
            acknowledged: event_listener::Event::new(),
            refusing: Mutex::new(HashMap::new()),
            capable: Mutex::new(HashMap::new()),
            runs: Mutex::new(HashMap::new()),
            dry_runs: Mutex::new(HashMap::new()),
            wanted: Mutex::new(HashMap::new()),
            drops: crate::peer::Drops::default(),
            next_agent: smol::lock::Mutex::new(next),
            runtime,
            tasks: Mutex::new(Vec::new()),
            recording: smol::lock::Mutex::new(()),
            calls: crate::calls::Calls::default(),
            reads: crate::queries::Reads::default(),
            turn: std::sync::atomic::AtomicU64::new(0),
            sent_across: std::sync::atomic::AtomicU64::new(0),
            installed: std::sync::atomic::AtomicU64::new(0),
            closing: std::sync::atomic::AtomicBool::new(false),
            retiring: Mutex::new(HashSet::new()),
            relayed: std::sync::atomic::AtomicU64::new(0),
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
                inner.retiring.lock().expect("the retiring").insert(agent);
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
        if let Some(arrivals) = arrivals {
            inner.spawn(crate::dispatch::dispatch(Arc::clone(&inner), arrivals));
        }
        inner.spawn(crate::dispatch::resend_records(Arc::clone(&inner)));
        Ok(Self {
            inner,
            data,
            secret,
            ingress_tls: config.ingress_tls,
            ingress: Mutex::new(None),
            endpoint,
            stop: Some(stop),
            runtime: Some(thread),
        })
    }

    /// The node's identity, its public key, which its TLS presents.
    pub fn id(&self) -> NodeId {
        self.inner.node_id
    }

    /// Snapshots this node's groups switched to.
    pub fn snapshots_installed(&self) -> u64 {
        self.inner
            .installed
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Messages this node sent toward agents on other nodes, again on
    /// rounds included.
    pub fn messages_sent_across(&self) -> u64 {
        self.inner.messages_sent_across()
    }

    /// Messages this node relayed to their agent's leader.
    pub fn messages_relayed(&self) -> u64 {
        self.inner
            .relayed
            .load(std::sync::atomic::Ordering::Relaxed)
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
                .admin(agent, Admin::SetRole { principal, role })
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

    /// The node's storage, to read applied state and the log.
    pub fn store(&self) -> &Fjall {
        &self.inner.store
    }

    /// The blobs some agent keeps here: the programs its instances run.
    pub fn pinned(&self) -> Vec<[u8; 32]> {
        self.inner.blobs.pinned().unwrap_or_default()
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
        *self.ingress.lock().expect("the ingress") = Some((task, stop));
        Ok(local)
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
        if self.runtime.is_none() {
            return;
        }
        {
            let _runs = self.inner.runs.lock().expect("the runs");
            self.inner
                .closing
                .store(true, std::sync::atomic::Ordering::SeqCst);
        }
        // End the ingress and its connections while the runtime still runs
        // them, so none outlives the node holding its store.
        let ingress = self.ingress.lock().expect("the ingress").take();
        if let Some((task, stop)) = ingress {
            let _ = stop.try_send(());
            smol::block_on(task);
        }
        let tasks = std::mem::take(&mut *self.inner.tasks.lock().expect("the node's tasks"));
        let runs: Vec<Arc<Run>> = self
            .inner
            .runs
            .lock()
            .expect("the runs")
            .drain()
            .map(|(_, run)| run)
            .collect();
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
                let tasks = std::mem::take(&mut *run.tasks.lock().expect("the run's tasks"));
                for task in tasks {
                    task.await;
                }
            }
        });
        if let Some(stop) = self.stop.take() {
            let _ = stop.try_send(());
        }
        if let Some(runtime) = self.runtime.take() {
            let _ = runtime.join();
        }
        drop(self.endpoint.take());
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        self.stop_all();
    }
}

/// Write the operator's token, in hex, readable by its owner only.
fn write_token(path: &Path, token: &[u8; 32]) -> std::io::Result<()> {
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
