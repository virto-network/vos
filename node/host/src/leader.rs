//! An agent's leader loop, while this node leads its group. Per batch, in
//! order: refine against the applied state, a dry run of accumulate on the
//! same state, the result proposed, and once this replica has applied it,
//! the replies, the outbox's deliveries and the acknowledgements.

use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;
use std::time::Duration;

use smol::future::FutureExt;
use vos_raft::Role;
use vos_wire::abi::refusal;
use vos_wire::batch::{Batch, Message, Work};
use vos_wire::ids::AgentId;
use vos_wire::keys;
use vos_wire::records::unstored;
use vos_wire::result::{Outgoing, Step, WorkResult};

use crate::group::{DryRun, Local, Shared, State};
use crate::node::{Agent, CallError, Inner, Pending, Reply, ran, read, reply, seed};
use crate::pvm::{self, Fault};
use crate::store::{BlobRef, EntryKind, FjallSnapshot, LogEntry, Store, View};

/// The first wait before retrying a batch the node failed, doubled each
/// time up to [`MAX_BACKOFF`].
const BACKOFF: Duration = Duration::from_millis(50);
const MAX_BACKOFF: Duration = Duration::from_secs(5);

/// Lead `agent` whenever this node's replica leads its group, until the
/// group stops.
pub(crate) async fn lead(inner: Arc<Inner>, agent: Arc<Agent>, shared: Arc<Shared>) {
    let mut backoff = BACKOFF;
    loop {
        let state = shared
            .wait(|state| state.stopped || state.leading_from.is_some())
            .await;
        if state.stopped {
            return;
        }
        let (term, first) = (
            state.term,
            state.leading_from.expect("a leader's first index"),
        );
        // Inputs queue from now on, while the term's no-op applies.
        agent.queue.lock().expect("the queue").leading = true;
        shared.update(|_| {});
        // Everything before the term's no-op applies first.
        let state = shared
            .wait(|state| state.stopped || !leads(state, term) || state.applied >= first)
            .await;
        if state.stopped {
            return;
        }
        if leads(&state, term) {
            match Leader::open(&inner, &shared, term) {
                Ok(mut leader) => {
                    backoff = BACKOFF;
                    if !leader.lead(&inner, &agent, &shared).await {
                        // A hook, or a broken invariant, stopped the
                        // leader for good: its replica hands leadership
                        // over and goes on applying, and callers go to
                        // the next leader.
                        agent.refuse(&inner.not_leader(&shared));
                        inner.retire(shared.agent);
                        return;
                    }
                }
                Err(fault) => {
                    // The node failed a read: try again while leading.
                    tracing::error!(
                        agent = shared.agent.0,
                        "the leader cannot start ({}); retrying in {backoff:?}",
                        fault.message()
                    );
                    let lost = async {
                        shared.wait(|state| !leads(state, term)).await;
                    };
                    lost.or(async {
                        smol::Timer::after(backoff).await;
                    })
                    .await;
                    backoff = (backoff * 2).min(MAX_BACKOFF);
                    if leads(&shared.state(), term) {
                        continue;
                    }
                }
            }
        }
        // No longer leading: what is queued goes to the next leader.
        agent.refuse(&inner.not_leader(&shared));
        shared
            .wait(|state| state.stopped || !leads(state, term))
            .await;
    }
}

/// Whether `state` is still this replica leading `term`.
fn leads(state: &State, term: u64) -> bool {
    state.role == Role::Leader && state.term == term && !state.stopped
}

struct Leader {
    id: AgentId,
    term: u64,
    version: u64,
    applied: u64,
    time: u64,
    /// Each sender's pair mark, as applied.
    marks: HashMap<AgentId, u64>,
    /// Each target's last message delivered by this leadership.
    delivered: HashMap<AgentId, u64>,
    max_inputs: usize,
    backoff: Duration,
    /// The inputs the last batch requeued because its result applied as no
    /// writes: a second time, the batch is shortened as a failing one is.
    skipped: bool,
}

/// How a batch ended.
enum Ran {
    Done(WorkResult),
    /// Leadership ended before the result applied here.
    Lost,
    /// The result applied, but accumulate skipped it or failed on it: the
    /// state was not the one it was refined on. Its inputs go again.
    Skipped,
}

impl Leader {
    fn open(inner: &Inner, shared: &Shared, term: u64) -> Result<Self, Fault> {
        let id = shared.agent;
        let infrastructure = |error: fjall::Error| Fault::Infrastructure(error.to_string());
        let snapshot = inner.store.snapshot();
        let applied = snapshot.applied(id).map_err(infrastructure)?.unwrap_or(0);
        let version = read::<u64>(&snapshot, id, &keys::version())?.unwrap_or(0);
        let time = snapshot
            .last_result(id)
            .map_err(infrastructure)?
            .map_or(0, |(time, _)| time);
        Ok(Self {
            id,
            term,
            version,
            applied,
            time,
            marks: HashMap::new(),
            delivered: HashMap::new(),
            max_inputs: inner.max_inputs,
            backoff: BACKOFF,
            skipped: false,
        })
    }

    /// Lead until leadership ends. False when a hook stops the leader.
    async fn lead(&mut self, inner: &Inner, agent: &Agent, shared: &Shared) -> bool {
        if let Err(fault) = self.recover(inner).await {
            tracing::error!(agent = self.id.0, "recovery failed: {}", fault.message());
        }
        while let Some(pending) = self.take(inner, agent, shared).await {
            if !self.run(inner, agent, shared, pending).await {
                return false;
            }
            if !leads(&shared.state(), self.term) {
                break;
            }
        }
        true
    }

    /// Deliver every message in the outbox above its target's ack: what a
    /// crash, or an earlier leader, may have left unsent. Each target's
    /// group here is let settle first: after a restart, it may not have
    /// elected yet.
    async fn recover(&mut self, inner: &Inner) -> Result<(), Fault> {
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
            let _ = inner.settled(to).await;
            self.deliver(inner, &snapshot, to)?;
        }
        Ok(())
    }

    /// The next inputs, once there are any; `None` once leadership ends or
    /// the agent stops.
    async fn take(
        &mut self,
        inner: &Inner,
        agent: &Agent,
        shared: &Shared,
    ) -> Option<Vec<Pending>> {
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
            if !leads(&shared.state(), self.term) {
                return None;
            }
            let woken = async { agent.woken.recv().await.is_ok() };
            let term = self.term;
            let lost = async {
                shared.wait(|state| !leads(state, term)).await;
                false
            };
            if !woken.or(lost).await {
                return None;
            }
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
    async fn run(
        &mut self,
        inner: &Inner,
        agent: &Agent,
        shared: &Shared,
        mut pending: Vec<Pending>,
    ) -> bool {
        let snapshot = Arc::new(inner.store.snapshot());
        // The batch is refined on this state, at its version: an entry an
        // earlier leadership left may have applied since this one opened.
        let read_state = read::<u64>(&snapshot, self.id, &keys::version()).and_then(|version| {
            let applied = snapshot
                .applied(self.id)
                .map_err(|error| Fault::Infrastructure(error.to_string()))?;
            Ok((version, applied))
        });
        match read_state {
            Ok((version, applied)) => {
                self.version = version.unwrap_or(0);
                self.applied = applied.unwrap_or(0);
            }
            Err(fault) => {
                self.retry(inner, agent, pending, fault).await;
                return true;
            }
        }
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
            time: (inner.clock)().max(self.time),
            seed: seed(),
            inputs: pending.iter().map(Pending::input).collect(),
        };
        let blobs: Vec<BlobRef> = pending
            .iter()
            .flat_map(|item| match item {
                Pending::Admin(_, _, blobs) => blobs.clone(),
                _ => Vec::new(),
            })
            .collect();
        match self.execute(inner, shared, snapshot, &batch, blobs).await {
            Ok(Ran::Done(result)) => {
                self.skipped = false;
                self.version += 1;
                self.time = batch.time;
                self.max_inputs = inner.max_inputs;
                self.backoff = BACKOFF;
                if !inner.hooks.after_commit(self.id, self.applied) {
                    return false;
                }
                self.dispatch(inner, agent, pending, &result);
            }
            Ok(Ran::Lost) => {
                let hint = inner.not_leader(shared);
                for item in pending {
                    item.refuse(&hint);
                }
            }
            Ok(Ran::Skipped) if self.skipped => {
                self.skipped = false;
                self.fail(inner, agent, pending, "applied as no writes again".into());
            }
            Ok(Ran::Skipped) => {
                tracing::warn!(
                    agent = self.id.0,
                    "a result applied as no writes; its inputs go again"
                );
                self.skipped = true;
                inner.requeue(agent, pending);
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

    /// Refine `batch`, dry-run accumulate on the same state, propose the
    /// result, and wait until this replica applied it.
    async fn execute(
        &mut self,
        inner: &Inner,
        shared: &Shared,
        snapshot: Arc<FjallSnapshot>,
        batch: &Batch,
        blobs: Vec<BlobRef>,
    ) -> Result<Ran, Fault> {
        let id = self.id;
        let program = Arc::clone(&inner.program);
        let pool = Arc::clone(&inner.pool);
        let store_blobs = inner.blobs.clone();
        let refined = batch.clone();
        let hooks = Arc::clone(&inner.hooks);
        let gas = inner.refine_gas;
        let state = Arc::clone(&snapshot);
        let output = ran(inner
            .executors
            .run(move || {
                if hooks.fail_refine(id, &refined) {
                    return Err(Fault::Agent("a hook failed the refine".into()));
                }
                pvm::refine(
                    &program,
                    &pool,
                    &store_blobs,
                    state,
                    id,
                    &Work::Batch(refined),
                    gas,
                )
            })
            .await)?;
        let result: WorkResult = pvm::decode(&output)?;
        // The dry run: a failure here isolates its input off the log.
        let program = Arc::clone(&inner.program);
        let gas = shared.record.accumulate_gas;
        let applied = output.clone();
        let state = Arc::clone(&snapshot);
        let hooks = Arc::clone(&inner.hooks);
        let dried = batch.clone();
        let writes = ran(inner
            .executors
            .run(move || {
                if hooks.fail_dry_run(id, &dried) {
                    return Err(Fault::Agent("a hook failed accumulate".into()));
                }
                pvm::accumulate(&program, state, id, applied, gas)
            })
            .await)?;
        let version = writes
            .iter()
            .find(|write| write.key == keys::version())
            .and_then(|write| write.value.as_deref())
            .and_then(unstored)
            .and_then(|bytes| vos_wire::Decode::decode(bytes).ok())
            .map(|(version, _): (u64, usize)| version);
        if version != Some(self.version + 1) {
            return Err(Fault::Invariant(format!(
                "accumulate skipped the work result: the agent's state is not at version {}",
                self.version
            )));
        }
        let entry = LogEntry {
            term: 0,
            kind: EntryKind::Result,
            blobs,
            body: output,
        };
        let payload = entry.payload();
        inner.keep_dry_run(
            id,
            DryRun {
                applied: self.applied,
                payload: payload.clone(),
                writes,
            },
        );
        let (answer, answered) = smol::channel::bounded(1);
        let term = self.term;
        let proposed = inner.propose(
            id,
            Local::Propose {
                term,
                payload,
                answer,
            },
        );
        if !proposed {
            return Ok(Ran::Lost);
        }
        let answer = async { Some(answered.recv().await) };
        let stopped = async {
            shared.wait(|state| state.stopped).await;
            None
        };
        let index = match answer.or(stopped).await {
            Some(Ok(Ok(index))) => index,
            _ => return Ok(Ran::Lost),
        };
        let state = shared
            .wait(|state| state.stopped || !leads(state, term) || state.applied >= index)
            .await;
        if state.applied < index {
            return Ok(Ran::Lost);
        }
        // The entry at its index is this leader's, of its term.
        let ours = inner
            .store
            .log_entry(id, index)
            .map_err(|error| Fault::Infrastructure(error.to_string()))?
            .is_some_and(|entry| entry.term == term);
        if !ours {
            return Ok(Ran::Lost);
        }
        self.applied = index;
        match shared.outcome(index) {
            Some(true) => Ok(Ran::Done(result)),
            _ => Ok(Ran::Skipped),
        }
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
        if let Pending::Request(_, answer) | Pending::Admin(_, answer, _) = input {
            let _ = answer.try_send(Ok(Reply::Failed));
        }
    }

    /// After this replica applied the result: answer, requeue what the
    /// result did not cover, deliver the outbox and acknowledge applied
    /// messages.
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
                Pending::Request(_, answer) | Pending::Admin(_, answer, _) => {
                    let _ = answer.try_send(Ok(reply(step)));
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
    /// acknowledged), in order. A target this node does not lead keeps
    /// them in the outbox for now.
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
            let Some(outgoing) = unstored(&value).and_then(|bytes| {
                <Outgoing as vos_wire::Decode>::decode(bytes)
                    .ok()
                    .map(|(outgoing, _)| outgoing)
            }) else {
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
                instance: outgoing.instance,
                method: outgoing.method,
                arguments: outgoing.arguments,
            };
            if let Err(error) = inner.push(to, Pending::Message(message)) {
                tracing::debug!(
                    agent = self.id.0,
                    to = to.0,
                    "a message waits in the outbox: {error:?}"
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
                tracing::debug!(
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

impl Pending {
    /// Answer that this node does not lead, when the input has a caller.
    pub(crate) fn refuse(self, hint: &CallError) {
        if let Pending::Request(_, answer) | Pending::Admin(_, answer, _) = self {
            let _ = answer.try_send(Err(hint.clone()));
        }
    }
}
