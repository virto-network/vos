//! The node: every agent's leader loop on one async thread, the executor
//! threads for PVM work, the storage thread and the machine pool.
//!
//! Per agent, a batch runs strictly in order: refine, accumulate, one
//! durable commit of the log entry and its writes, and only then the
//! replies, the outbox's deliveries and the acknowledgements.

use std::collections::{BTreeSet, HashMap, VecDeque};
use std::future::Future;
use std::panic::AssertUnwindSafe;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use smol::future::FutureExt;
use vos_pvm::PvmBackend;
use vos_pvm::pool::{CodeHash, MachinePool};
use vos_pvm::refine::PreparedProgram;
use vos_wire::abi::refusal;
use vos_wire::batch::{Admin, Batch, Input, Message, Query, Request, Work};
use vos_wire::ids::{AgentId, InstanceId, MethodId, Principal, ProgramHash};
use vos_wire::records::unstored;
use vos_wire::result::{Outcome, Outgoing, Step, WorkResult};
use vos_wire::{Decode, defaults, keys};

use crate::Hooks;
use crate::executor::Executors;
use crate::pvm::{self, Fault};
use crate::storage::{Change, StorageThread};
use crate::store::{Fjall, FjallSnapshot, LogEntry, NODE_AGENT, Store, View};

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
    pub accumulate_gas: u64,
    pub hooks: Arc<dyn Hooks>,
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
    /// An agent's applied index and its state version disagree.
    Inconsistent {
        agent: AgentId,
        applied: u64,
        version: u64,
    },
}

impl From<fjall::Error> for Error {
    fn from(error: fjall::Error) -> Self {
        Error::Store(error)
    }
}

type Answer = smol::channel::Sender<Reply>;

/// A queued input, with where its reply goes.
enum Pending {
    Request(Request, Answer),
    Admin(Admin, Answer),
    Message(Message),
    Ack { to: AgentId, sequence: u64 },
}

impl Pending {
    fn input(&self) -> Input {
        match self {
            Pending::Request(request, _) => Input::Request(request.clone()),
            Pending::Admin(admin, _) => Input::Admin(admin.clone()),
            Pending::Message(message) => Input::Message(message.clone()),
            Pending::Ack { to, sequence } => Input::Ack {
                to: *to,
                sequence: *sequence,
            },
        }
    }

    fn bytes(&self) -> usize {
        match self {
            Pending::Request(request, _) => request.arguments.len(),
            Pending::Message(message) => message.arguments.len(),
            Pending::Admin(..) | Pending::Ack { .. } => 0,
        }
    }

    /// Counts against the queue cap: what a client queued.
    fn capped(&self) -> bool {
        matches!(self, Pending::Request(..) | Pending::Admin(..))
    }
}

#[derive(Default)]
struct Queue {
    inputs: VecDeque<Pending>,
    /// Capped inputs queued.
    capped: usize,
    stopped: bool,
}

struct Agent {
    queue: Mutex<Queue>,
    wake: smol::channel::Sender<()>,
    woken: smol::channel::Receiver<()>,
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
    fn stop(&self) {
        let dropped = {
            let mut queue = self.queue.lock().expect("the queue");
            queue.stopped = true;
            queue.capped = 0;
            std::mem::take(&mut queue.inputs)
        };
        drop(dropped);
        let _ = self.wake.try_send(());
    }
}

struct Inner {
    store: Fjall,
    storage: StorageThread,
    executors: Executors,
    pool: Arc<MachinePool>,
    program: Arc<PreparedProgram>,
    program_hash: ProgramHash,
    queue: usize,
    max_inputs: usize,
    max_bytes: usize,
    linger: Duration,
    refine_gas: u64,
    accumulate_gas: u64,
    hooks: Arc<dyn Hooks>,
    agents: Mutex<HashMap<AgentId, Arc<Agent>>>,
    runtime: Arc<smol::Executor<'static>>,
}

impl Inner {
    fn agent(&self, id: AgentId) -> Option<Arc<Agent>> {
        self.agents.lock().expect("the agents").get(&id).cloned()
    }

    /// Queue `pending` for agent `id`.
    fn push(&self, id: AgentId, pending: Pending) -> Result<(), CallError> {
        let agent = self.agent(id).ok_or(CallError::NoAgent)?;
        let mut queue = agent.queue.lock().expect("the queue");
        if queue.stopped {
            return Err(CallError::Stopped);
        }
        if pending.capped() {
            if queue.capped >= self.queue {
                return Err(CallError::Busy);
            }
            queue.capped += 1;
        }
        queue.inputs.push_back(pending);
        drop(queue);
        let _ = agent.wake.try_send(());
        Ok(())
    }

    /// Put inputs back at the front of agent `id`'s queue, in order.
    fn requeue(&self, agent: &Agent, inputs: Vec<Pending>) {
        let mut queue = agent.queue.lock().expect("the queue");
        if queue.stopped {
            return;
        }
        for pending in inputs.into_iter().rev() {
            if pending.capped() {
                queue.capped += 1;
            }
            queue.inputs.push_front(pending);
        }
    }

    /// Stop every agent: a commit failed, and storage takes no more.
    /// Queued and later calls answer `Stopped`.
    fn halt(&self) {
        let agents: Vec<Arc<Agent>> = self
            .agents
            .lock()
            .expect("the agents")
            .values()
            .cloned()
            .collect();
        for agent in agents {
            agent.stop();
        }
    }

    fn start(self: &Arc<Self>, id: AgentId) -> smol::Task<()> {
        let agent = Arc::new(Agent::new());
        self.agents
            .lock()
            .expect("the agents")
            .insert(id, Arc::clone(&agent));
        let inner = Arc::clone(self);
        self.runtime.spawn(async move {
            let lead = async {
                match Leader::open(&inner, id) {
                    Ok(mut leader) => leader.lead(&inner, &agent).await,
                    Err(fault) => tracing::error!(
                        agent = id.0,
                        "the leader cannot start: {}",
                        fault.message()
                    ),
                }
            };
            if AssertUnwindSafe(lead).catch_unwind().await.is_err() {
                tracing::error!(agent = id.0, "the leader panicked; the agent stops");
            }
            agent.stop();
        })
    }
}

/// A value of an agent's applied state; `None` when absent or unreadable.
fn read<T: Decode>(
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
fn ran<T>(answer: Result<Result<T, Fault>, crate::executor::Panicked>) -> Result<T, Fault> {
    answer
        .unwrap_or_else(|panicked| Err(Fault::Infrastructure(format!("panicked: {}", panicked.0))))
}

/// The first wait before retrying a batch the node failed, doubled each
/// time up to [`MAX_BACKOFF`].
const BACKOFF: Duration = Duration::from_millis(50);
const MAX_BACKOFF: Duration = Duration::from_secs(5);

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_millis() as u64)
}

fn seed() -> [u8; 32] {
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed).expect("the operating system's randomness");
    seed
}

/// The reply a step gives its request.
fn reply(step: &Step) -> Reply {
    match step {
        Step::Ran(run) => Reply::Ran(run.outcome.clone()),
        Step::Refused { code, .. } => Reply::Refused(*code),
    }
}

/// An agent's leader: its batches, in order.
struct Leader {
    id: AgentId,
    version: u64,
    applied: u64,
    time: u64,
    /// Each sender's pair mark, as applied.
    marks: HashMap<AgentId, u64>,
    /// Each target's last message delivered by this process.
    delivered: HashMap<AgentId, u64>,
    max_inputs: usize,
    backoff: Duration,
}

impl Leader {
    /// Node::open checked the agent's applied index against its version; an
    /// agent created since has neither.
    fn open(inner: &Inner, id: AgentId) -> Result<Self, Fault> {
        let infrastructure = |error: fjall::Error| Fault::Infrastructure(error.to_string());
        let snapshot = inner.store.snapshot();
        let applied = snapshot.applied(id).map_err(infrastructure)?.unwrap_or(0);
        let time = match inner.store.log_entry(id, applied).map_err(infrastructure)? {
            Some(entry) => pvm::decode::<WorkResult>(&entry.entry)
                .map(|result| result.time)
                .unwrap_or(0),
            None => 0,
        };
        Ok(Self {
            id,
            version: applied,
            applied,
            time,
            marks: HashMap::new(),
            delivered: HashMap::new(),
            max_inputs: inner.max_inputs,
            backoff: BACKOFF,
        })
    }

    async fn lead(&mut self, inner: &Inner, agent: &Agent) {
        if let Err(fault) = self.recover(inner) {
            tracing::error!(agent = self.id.0, "recovery failed: {}", fault.message());
        }
        while let Some(pending) = self.take(inner, agent).await {
            if !self.run(inner, agent, pending).await {
                return;
            }
        }
    }

    /// Deliver every message in the outbox above its target's ack: what a
    /// crash may have left unsent.
    fn recover(&mut self, inner: &Inner) -> Result<(), Fault> {
        let snapshot = inner.store.snapshot();
        let mut targets = BTreeSet::new();
        for row in snapshot.scan(self.id, &keys::outbox_prefix(), None) {
            let (key, _) = row.map_err(|error| Fault::Infrastructure(error.to_string()))?;
            let to = key[key.len() - 12..key.len() - 8]
                .try_into()
                .expect("an outbox key holds its target");
            targets.insert(AgentId(u32::from_be_bytes(to)));
        }
        for to in targets {
            self.deliver(inner, &snapshot, to)?;
        }
        Ok(())
    }

    /// The next inputs, once there are any; `None` once stopped.
    async fn take(&mut self, inner: &Inner, agent: &Agent) -> Option<Vec<Pending>> {
        let mut waited = false;
        loop {
            {
                let queue = agent.queue.lock().expect("the queue");
                if queue.stopped {
                    return None;
                }
                if !queue.inputs.is_empty() {
                    break;
                }
            }
            agent.woken.recv().await.ok()?;
            waited = true;
        }
        if waited {
            smol::Timer::after(inner.linger).await;
        }
        let mut queue = agent.queue.lock().expect("the queue");
        if queue.stopped {
            return None;
        }
        let mut taken = Vec::new();
        let mut bytes = 0;
        while taken.len() < self.max_inputs {
            let Some(next) = queue.inputs.front() else {
                break;
            };
            if !taken.is_empty() && bytes + next.bytes() > inner.max_bytes {
                break;
            }
            let next = queue.inputs.pop_front().expect("a front input");
            bytes += next.bytes();
            if next.capped() {
                queue.capped -= 1;
            }
            taken.push(next);
        }
        Some(taken)
    }

    /// A sender's pair mark, as applied.
    fn mark(&mut self, snapshot: &FjallSnapshot, from: AgentId) -> Result<u64, Fault> {
        if let Some(mark) = self.marks.get(&from) {
            return Ok(*mark);
        }
        let mark = read::<u64>(snapshot, self.id, &keys::pair_in(from))?.unwrap_or(0);
        self.marks.insert(from, mark);
        Ok(mark)
    }

    /// Run one batch to its end. False when a hook stops the leader.
    async fn run(&mut self, inner: &Inner, agent: &Agent, mut pending: Vec<Pending>) -> bool {
        let snapshot = Arc::new(inner.store.snapshot());
        let senders: BTreeSet<AgentId> = pending
            .iter()
            .filter_map(|item| match item {
                Pending::Message(message) => Some(message.from),
                _ => None,
            })
            .collect();
        for from in senders {
            if let Err(fault) = self.mark(&snapshot, from) {
                self.retry(inner, agent, pending, fault).await;
                return true;
            }
        }
        // A message at or below its pair mark applied already: drop it and
        // acknowledge the mark instead.
        let mut acks: HashMap<AgentId, u64> = HashMap::new();
        let mut kept = Vec::with_capacity(pending.len());
        for item in pending.drain(..) {
            if let Pending::Message(message) = &item {
                let mark = self.marks[&message.from];
                if message.sequence <= mark {
                    raise(&mut acks, message.from, mark);
                    continue;
                }
            }
            kept.push(item);
        }
        let pending = kept;
        self.acknowledge(inner, acks);
        if pending.is_empty() {
            self.max_inputs = inner.max_inputs;
            return true;
        }
        let batch = Batch {
            version: self.version,
            time: now().max(self.time),
            seed: seed(),
            inputs: pending.iter().map(Pending::input).collect(),
        };
        match self.execute(inner, snapshot, &batch).await {
            Ok(result) => {
                self.applied += 1;
                self.version += 1;
                self.time = batch.time;
                self.max_inputs = inner.max_inputs;
                self.backoff = BACKOFF;
                if !inner.hooks.after_commit(self.id, self.applied) {
                    return false;
                }
                self.dispatch(inner, agent, pending, &result);
            }
            Err(Fault::Agent(message)) => self.fail(inner, agent, pending, message),
            Err(Fault::Storage(message)) => {
                tracing::error!(
                    agent = self.id.0,
                    "a commit failed ({message}); the node stops and needs a restart"
                );
                inner.halt();
                return false;
            }
            Err(Fault::Invariant(message)) => {
                tracing::error!(agent = self.id.0, "{message}; the agent stops");
                return false;
            }
            Err(fault) => self.retry(inner, agent, pending, fault).await,
        }
        true
    }

    /// Refine, accumulate and commit `batch`.
    async fn execute(
        &self,
        inner: &Inner,
        snapshot: Arc<FjallSnapshot>,
        batch: &Batch,
    ) -> Result<WorkResult, Fault> {
        let id = self.id;
        let program = Arc::clone(&inner.program);
        let pool = Arc::clone(&inner.pool);
        let store = inner.store.clone();
        let batch = batch.clone();
        let hooks = Arc::clone(&inner.hooks);
        let gas = inner.refine_gas;
        let state = Arc::clone(&snapshot);
        let output = ran(inner
            .executors
            .run(move || {
                if hooks.fail_refine(id, &batch) {
                    return Err(Fault::Agent("a hook failed the refine".into()));
                }
                pvm::refine(&program, &pool, &store, state, id, &Work::Batch(batch), gas)
            })
            .await)?;
        let result: WorkResult = pvm::decode(&output)?;
        let program = Arc::clone(&inner.program);
        let gas = inner.accumulate_gas;
        let applied = output.clone();
        let writes = ran(inner
            .executors
            .run(move || pvm::accumulate(&program, snapshot, id, applied, gas))
            .await)?;
        // The result applied, so the agent's version moves with the
        // node's applied index.
        let version = writes
            .iter()
            .find(|write| write.key == keys::version())
            .and_then(|write| write.value.as_deref())
            .and_then(unstored)
            .and_then(|bytes| u64::decode(bytes).ok())
            .map(|(version, _)| version);
        if version != Some(self.version + 1) {
            return Err(Fault::Invariant(format!(
                "accumulate skipped the work result: the agent's state is not at version {}",
                self.version
            )));
        }
        let change = Change::Log {
            agent: id,
            index: self.applied + 1,
            entry: LogEntry {
                term: 0,
                entry: output,
            },
            writes,
        };
        inner
            .storage
            .commit(vec![change])
            .await
            .map_err(Fault::Storage)?;
        Ok(result)
    }

    /// A batch the node failed: put it back whole and wait before the next
    /// try. No input is to blame, so none is dropped.
    async fn retry(&mut self, inner: &Inner, agent: &Agent, pending: Vec<Pending>, fault: Fault) {
        tracing::error!(
            agent = self.id.0,
            "the node failed a batch ({}); retrying in {:?}",
            fault.message(),
            self.backoff
        );
        inner.requeue(agent, pending);
        // Wait in short slices, so a stop does not wait out the backoff.
        let until = std::time::Instant::now() + self.backoff;
        while !agent.queue.lock().expect("the queue").stopped {
            let left = until.saturating_duration_since(std::time::Instant::now());
            if left.is_zero() {
                break;
            }
            smol::Timer::after(left.min(BACKOFF)).await;
        }
        self.backoff = (self.backoff * 2).min(MAX_BACKOFF);
    }

    /// A batch the agent program failed: requeue it shorter, until one input
    /// alone fails, which then fails its caller or is reported.
    fn fail(&mut self, inner: &Inner, agent: &Agent, mut pending: Vec<Pending>, failed: String) {
        if pending.len() > 1 {
            tracing::warn!(
                agent = self.id.0,
                inputs = pending.len(),
                "a batch failed ({failed}); retrying shorter"
            );
            self.max_inputs = (pending.len() / 2).max(1);
            inner.requeue(agent, pending);
            return;
        }
        let input = pending.pop().expect("one input");
        tracing::error!(
            agent = self.id.0,
            "the agent program fails on one input alone ({failed}); it is dropped"
        );
        if let Pending::Request(_, answer) | Pending::Admin(_, answer) = input {
            let _ = answer.try_send(Reply::Failed);
        }
    }

    /// After a durable commit: answer, requeue what the result did not
    /// cover, deliver the outbox and acknowledge applied messages.
    fn dispatch(
        &mut self,
        inner: &Inner,
        agent: &Agent,
        pending: Vec<Pending>,
        result: &WorkResult,
    ) {
        let snapshot = inner.store.snapshot();
        let mut acks: HashMap<AgentId, u64> = HashMap::new();
        let mut rest = Vec::new();
        let mut again = Vec::new();
        for (index, item) in pending.into_iter().enumerate() {
            let Some(step) = result.steps.get(index) else {
                rest.push(item);
                continue;
            };
            match item {
                Pending::Request(_, answer) | Pending::Admin(_, answer) => {
                    let _ = answer.try_send(reply(step));
                }
                Pending::Message(message) => match step {
                    Step::Ran(_) => {
                        self.marks.insert(message.from, message.sequence);
                        raise(&mut acks, message.from, message.sequence);
                    }
                    Step::Refused {
                        code: refusal::SEQUENCE,
                        ..
                    } => {
                        // At or below the mark, a duplicate: acknowledge
                        // it. Above, a gap: drop it for the sender's next
                        // delivery.
                        match self.mark(&snapshot, message.from) {
                            Ok(mark) if message.sequence <= mark => {
                                raise(&mut acks, message.from, mark);
                            }
                            Ok(_) => {}
                            Err(fault) => tracing::error!(
                                agent = self.id.0,
                                "a pair mark is unreadable: {}",
                                fault.message()
                            ),
                        }
                    }
                    Step::Refused { code, .. } => tracing::error!(
                        agent = self.id.0,
                        from = message.from.0,
                        sequence = message.sequence,
                        code,
                        "a message was refused and dropped"
                    ),
                },
                Pending::Ack { to, sequence } => {
                    // Ack again while the mark trails it: one ack clears
                    // at most `ACK_LIMIT` entries.
                    let marks =
                        read::<u64>(&snapshot, self.id, &keys::acked(to)).and_then(|acked| {
                            Ok((acked, read::<u64>(&snapshot, self.id, &keys::pair_out(to))?))
                        });
                    match marks {
                        Ok((acked, sent))
                            if acked.unwrap_or(0) < sequence.min(sent.unwrap_or(0)) =>
                        {
                            again.push(Pending::Ack { to, sequence });
                        }
                        Ok(_) => {}
                        Err(fault) => tracing::error!(
                            agent = self.id.0,
                            "an ack mark is unreadable: {}",
                            fault.message()
                        ),
                    }
                }
            }
        }
        inner.requeue(agent, rest);
        for pending in again {
            let _ = inner.push(self.id, pending);
        }
        let targets: BTreeSet<AgentId> = result
            .steps
            .iter()
            .filter_map(|step| match step {
                Step::Ran(run) => Some(run.messages.iter().map(|message| message.to)),
                Step::Refused { .. } => None,
            })
            .flatten()
            .collect();
        for to in targets {
            if let Err(fault) = self.deliver(inner, &snapshot, to) {
                // The outbox keeps them: the next send to `to`, or a
                // restart, delivers them.
                tracing::error!(
                    agent = self.id.0,
                    to = to.0,
                    "delivery failed: {}",
                    fault.message()
                );
            }
        }
        self.acknowledge(inner, acks);
    }

    /// Send the outbox's messages to `to` past those already delivered (or
    /// acknowledged), in order.
    fn deliver(
        &mut self,
        inner: &Inner,
        snapshot: &FjallSnapshot,
        to: AgentId,
    ) -> Result<(), Fault> {
        let after = match self.delivered.get(&to) {
            Some(delivered) => *delivered,
            None => read::<u64>(snapshot, self.id, &keys::acked(to))?.unwrap_or(0),
        };
        let mut prefix = keys::outbox(to, 0);
        prefix.truncate(prefix.len() - 8);
        let cursor = keys::outbox(to, after);
        for row in snapshot.scan(self.id, &prefix, Some(&cursor)) {
            let (key, value) = row.map_err(|error| Fault::Infrastructure(error.to_string()))?;
            let sequence = u64::from_be_bytes(key[key.len() - 8..].try_into().expect("a sequence"));
            let Some(outgoing) = unstored(&value).and_then(|bytes| Outgoing::decode(bytes).ok())
            else {
                tracing::error!(
                    agent = self.id.0,
                    to = to.0,
                    sequence,
                    "an unreadable outbox entry"
                );
                break;
            };
            let message = Message {
                from: self.id,
                sequence,
                instance: outgoing.0.instance,
                method: outgoing.0.method,
                arguments: outgoing.0.arguments,
            };
            if let Err(error) = inner.push(to, Pending::Message(message)) {
                tracing::warn!(
                    agent = self.id.0,
                    to = to.0,
                    "a message is not delivered: {error:?}"
                );
                break;
            }
            self.delivered.insert(to, sequence);
        }
        Ok(())
    }

    /// Acknowledge each sender's messages through the sequence given.
    fn acknowledge(&self, inner: &Inner, acks: HashMap<AgentId, u64>) {
        for (from, sequence) in acks {
            let ack = Pending::Ack {
                to: self.id,
                sequence,
            };
            if let Err(error) = inner.push(from, ack) {
                tracing::warn!(
                    agent = self.id.0,
                    to = from.0,
                    "an ack is not delivered: {error:?}"
                );
            }
        }
    }
}

fn raise(acks: &mut HashMap<AgentId, u64>, from: AgentId, sequence: u64) {
    let ack = acks.entry(from).or_insert(0);
    *ack = (*ack).max(sequence);
}

/// A VOS node on one process.
pub struct Node {
    inner: Arc<Inner>,
    leaders: Mutex<Vec<smol::Task<()>>>,
    next_agent: Mutex<u32>,
    stop: Option<smol::channel::Sender<()>>,
    runtime: Option<JoinHandle<()>>,
}

impl Node {
    /// Open the node's storage at `path` and start every agent it runs.
    pub fn open(path: impl AsRef<Path>, config: Config) -> Result<Self, Error> {
        let largest = defaults::MAX_HANDLER_GAS
            + defaults::STEP_RESERVE.max(defaults::INSTALL_RESERVE)
            + defaults::FINISH_RESERVE;
        if config.refine_gas < largest {
            return Err(Error::Gas);
        }
        let store = Fjall::open(path)?;
        let pool = Arc::new(MachinePool::new());
        for (_, blob) in store.programs()? {
            pool.install(&blob)
                .map_err(|error| Error::Program(format!("{error:?}")))?;
        }
        let program = PreparedProgram::new_with_backend(&config.agent, PvmBackend::Default)
            .map_err(|error| Error::Program(format!("{error:?}")))?;
        let program_hash = ProgramHash(CodeHash::of(&config.agent).0);
        let agents = store.agents()?;
        let snapshot = store.snapshot();
        for (agent, _) in &agents {
            let applied = snapshot.applied(*agent)?.unwrap_or(0);
            let version = read::<u64>(&snapshot, *agent, &keys::version())
                .map_err(|fault| Error::Unreadable(fault.message().to_string()))?
                .unwrap_or(0);
            if applied != version {
                return Err(Error::Inconsistent {
                    agent: *agent,
                    applied,
                    version,
                });
            }
        }
        drop(snapshot);
        let runtime = Arc::new(smol::Executor::new());
        let (stop, stopped) = smol::channel::bounded::<()>(1);
        let thread = {
            let runtime = Arc::clone(&runtime);
            std::thread::Builder::new()
                .name("vos-node".into())
                .spawn(move || smol::block_on(runtime.run(stopped.recv())).unwrap_or(()))
                .expect("the node's thread starts")
        };
        let inner = Arc::new(Inner {
            storage: StorageThread::spawn(store.clone(), Arc::clone(&config.hooks)),
            store,
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
            agents: Mutex::new(HashMap::new()),
            runtime,
        });
        let next = agents
            .iter()
            .map(|(agent, _)| agent.0 + 1)
            .max()
            .unwrap_or(1);
        let leaders = agents
            .iter()
            .map(|(agent, _)| inner.start(*agent))
            .collect();
        Ok(Self {
            inner,
            leaders: Mutex::new(leaders),
            next_agent: Mutex::new(next),
            stop: Some(stop),
            runtime: Some(thread),
        })
    }

    /// Create an agent running the node's agent program. Blocks until its
    /// registry entry is durable.
    pub fn create_agent(&self) -> Result<AgentId, CallError> {
        let mut next = self.next_agent.lock().expect("the next agent");
        let agent = AgentId(*next);
        assert_ne!(agent, NODE_AGENT, "agent ids are exhausted");
        let change = Change::Agent {
            agent,
            program: self.inner.program_hash,
        };
        smol::block_on(self.inner.storage.commit(vec![change])).map_err(CallError::Failed)?;
        *next += 1;
        let leader = self.inner.start(agent);
        self.leaders.lock().expect("the leaders").push(leader);
        Ok(agent)
    }

    /// Install a package as `instance` of `agent`: its actor program, the
    /// program of each attestable method, and its roles' bytes. Blocks until
    /// the blobs are durable and pooled, then queues the install.
    pub fn install(
        &self,
        agent: AgentId,
        instance: InstanceId,
        program: &[u8],
        attestables: &[(MethodId, &[u8])],
        roles: Vec<(Vec<u8>, u8)>,
    ) -> impl Future<Output = Result<Reply, CallError>> + use<> {
        let stored = (|| {
            let mut changes = Vec::new();
            let mut hash = |blob: &[u8]| -> Result<ProgramHash, CallError> {
                let hash = self
                    .inner
                    .pool
                    .install(blob)
                    .map_err(|error| CallError::Failed(format!("{error:?}")))?;
                let hash = ProgramHash(hash.0);
                changes.push(Change::Program {
                    hash,
                    blob: blob.to_vec(),
                });
                Ok(hash)
            };
            let program = hash(program)?;
            let attestables = attestables
                .iter()
                .map(|(method, blob)| Ok((*method, hash(blob)?)))
                .collect::<Result<Vec<_>, CallError>>()?;
            smol::block_on(self.inner.storage.commit(changes)).map_err(CallError::Failed)?;
            Ok(Admin::Install {
                instance,
                program,
                attestables,
                roles,
            })
        })();
        let queued = stored.and_then(|admin| self.admin(agent, admin));
        async move { queued?.recv().await.map_err(|_| CallError::Stopped) }
    }

    /// Grant `principal` a role in `agent`, or (`None`) revoke it.
    pub fn set_role(
        &self,
        agent: AgentId,
        principal: Principal,
        role: Option<u8>,
    ) -> impl Future<Output = Result<Reply, CallError>> + use<> {
        let queued = self.admin(agent, Admin::SetRole { principal, role });
        async move { queued?.recv().await.map_err(|_| CallError::Stopped) }
    }

    fn admin(
        &self,
        agent: AgentId,
        admin: Admin,
    ) -> Result<smol::channel::Receiver<Reply>, CallError> {
        let (answer, reply) = smol::channel::bounded(1);
        self.inner.push(agent, Pending::Admin(admin, answer))?;
        Ok(reply)
    }

    /// A client request to `agent`, answered once its step is durable.
    pub fn call(
        &self,
        agent: AgentId,
        request: Request,
    ) -> impl Future<Output = Result<Reply, CallError>> + use<> {
        let (answer, reply) = smol::channel::bounded(1);
        let queued = self.inner.push(agent, Pending::Request(request, answer));
        async move {
            queued?;
            reply.recv().await.map_err(|_| CallError::Stopped)
        }
    }

    /// Run a query handler on `agent`'s applied state. It never enters the
    /// log; its time and seed are the last applied batch's.
    pub fn query(
        &self,
        agent: AgentId,
        caller: Principal,
        instance: InstanceId,
        method: MethodId,
        arguments: Vec<u8>,
    ) -> impl Future<Output = Result<Outcome, CallError>> + use<> {
        let inner = Arc::clone(&self.inner);
        let known = inner.agent(agent).is_some();
        async move {
            if !known {
                return Err(CallError::NoAgent);
            }
            let snapshot = Arc::new(inner.store.snapshot());
            let applied = snapshot
                .applied(agent)
                .map_err(|error| CallError::Failed(error.to_string()))?
                .unwrap_or(0);
            let (time, seed) = match inner
                .store
                .log_entry(agent, applied)
                .map_err(|error| CallError::Failed(error.to_string()))?
            {
                Some(entry) => pvm::decode::<WorkResult>(&entry.entry)
                    .map(|result| (result.time, result.seed))
                    .unwrap_or((0, [0; 32])),
                None => (0, [0; 32]),
            };
            let work = Work::Query(Query {
                time,
                seed,
                caller,
                instance,
                method,
                arguments,
            });
            let program = Arc::clone(&inner.program);
            let pool = Arc::clone(&inner.pool);
            let store = inner.store.clone();
            let gas = inner.refine_gas;
            let failed = |fault: Fault| CallError::Failed(fault.message().to_string());
            let output = ran(inner
                .executors
                .run(move || pvm::refine(&program, &pool, &store, snapshot, agent, &work, gas))
                .await)
            .map_err(failed)?;
            pvm::decode::<Outcome>(&output).map_err(failed)
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

    /// Stop every leader after its batch in flight, then the threads.
    /// Requests queued but not yet in a batch are not durable: their callers
    /// see `Stopped` and resend.
    pub fn shutdown(mut self) {
        self.stop_all();
    }

    fn stop_all(&mut self) {
        let agents: Vec<Arc<Agent>> = self
            .inner
            .agents
            .lock()
            .expect("the agents")
            .values()
            .cloned()
            .collect();
        for agent in agents {
            agent.stop();
        }
        let leaders = std::mem::take(&mut *self.leaders.lock().expect("the leaders"));
        smol::block_on(async {
            for leader in leaders {
                leader.await;
            }
        });
        if let Some(stop) = self.stop.take() {
            let _ = stop.try_send(());
        }
        if let Some(runtime) = self.runtime.take() {
            let _ = runtime.join();
        }
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        self.stop_all();
    }
}
