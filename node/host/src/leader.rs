//! An agent's leader loop, while this node leads its group. Per batch, in
//! order: refine against the applied state, a dry run of accumulate on the
//! same state, the result proposed, and once this replica has applied it,
//! the replies, the outbox's deliveries and the acknowledgements.

use std::collections::{BTreeSet, HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

use smol::future::FutureExt;
use vos_raft::Role;
use vos_wire::abi::refusal;
use vos_wire::batch::{Batch, Message, Request, Work};
use vos_wire::ids::{AgentId, SessionId};
use vos_wire::records::{SessionMark, unstored};
use vos_wire::result::{Outcome, Outgoing, Step, WorkResult};
use vos_wire::{expiry, keys};

use crate::group::{DryRun, Local, Shared, State};
use crate::node::{Agent, Answered, CallError, Inner, Pending, Reply, ran, read, reply, seed};
use crate::pvm::{self, Fault};
use crate::store::{BlobRef, EntryKind, FjallSnapshot, LogEntry, Store, View};

/// The first wait before retrying a batch the node failed, doubled each
/// time up to [`MAX_BACKOFF`].
const BACKOFF: Duration = Duration::from_millis(50);
const MAX_BACKOFF: Duration = Duration::from_secs(5);
/// How far this node's clock may trail the agent's time before the leader
/// says so.
const CLOCK_BOUND: u64 = 10_000;
/// What a sender sends a target past the target's acknowledgement at
/// once: entries, and bytes, at least one entry.
const WINDOW: usize = 256;
const WINDOW_BYTES: usize = 1 << 20;
/// How long a target's acknowledgement may stay behind its outbox before
/// its window goes again, doubled each time that brings nothing, up to
/// [`MAX_ROUND`].
const ROUND: Duration = Duration::from_secs(1);
const MAX_ROUND: Duration = Duration::from_secs(16);
/// How often an idle leader looks again at its first expiry row: a clock
/// stepped forward does not move a timer.
const SWEEP_RECHECK: Duration = Duration::from_secs(5);
/// How long a leader adds no sweep once one left its first due row in
/// place.
const SWEEP_PAUSE: Duration = Duration::from_secs(60);

/// What this leadership sent a target past its acknowledgement.
struct Window {
    /// The highest acknowledgement taken, from the queue or applied.
    acked: u64,
    /// The last sequence the outbox holds for the target, as last read.
    last: u64,
    /// The sequences sent past `acked`, with their sizes.
    sent: VecDeque<(u64, usize)>,
    bytes: usize,
    /// When the acknowledgement last moved, or the window last went again.
    since: Instant,
    /// How long after `since` it goes again.
    wait: Duration,
    /// Which replica of the target it goes through, when it goes through
    /// one: the same for a whole window, another each time it goes again.
    turn: u64,
}

impl Window {
    /// A window from `acked` on, through the replica `turn` picks first:
    /// each node starts at its own, so senders spread over the replicas.
    fn new(acked: u64, turn: u64) -> Self {
        Self {
            acked,
            last: acked,
            sent: VecDeque::new(),
            bytes: 0,
            since: Instant::now(),
            wait: ROUND,
            turn,
        }
    }

    /// The last sequence sent, or acknowledged.
    fn through(&self) -> u64 {
        self.sent
            .back()
            .map_or(self.acked, |(sequence, _)| *sequence)
    }

    fn ack(&mut self, sequence: u64) {
        if sequence <= self.acked {
            return;
        }
        self.acked = sequence;
        while let Some((sent, size)) = self.sent.front().copied() {
            if sent > sequence {
                break;
            }
            self.sent.pop_front();
            self.bytes -= size;
        }
        self.since = Instant::now();
        self.wait = ROUND;
    }

    fn full(&self, size: usize) -> bool {
        self.sent.len() >= WINDOW || (!self.sent.is_empty() && self.bytes + size > WINDOW_BYTES)
    }

    /// When it goes again, while the outbox holds more than was
    /// acknowledged.
    fn due(&self) -> Option<Instant> {
        (self.last > self.acked).then(|| self.since + self.wait)
    }

    /// Go back to the acknowledgement, waiting longer before the next time.
    fn rewind(&mut self) {
        self.sent.clear();
        self.bytes = 0;
        self.since = Instant::now();
        self.wait = (self.wait * 2).min(MAX_ROUND);
        self.turn += 1;
    }
}

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
    /// The node's clock trails the agent's time: batches are timed at the
    /// agent's.
    trailing: bool,
    /// Each sender's pair mark, as applied.
    marks: HashMap<AgentId, u64>,
    /// What this leadership sent each target.
    windows: HashMap<AgentId, Window>,
    max_inputs: usize,
    backoff: Duration,
    /// The inputs the last batch requeued because its result applied as no
    /// writes: a second time, the batch is shortened as a failing one is.
    skipped: bool,
    /// The first due expiry row when the last sweep applied, or failed
    /// alone, and when.
    swept: Option<((u64, SessionId), Instant)>,
    /// When the last batch ended.
    ended: Option<Instant>,
    /// That a sweep left its first due row in place, said once.
    stuck: bool,
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
        Ok(Self {
            id,
            term,
            version,
            applied,
            trailing: false,
            marks: HashMap::new(),
            windows: HashMap::new(),
            max_inputs: inner.max_inputs,
            backoff: BACKOFF,
            skipped: false,
            swept: None,
            ended: None,
            stuck: false,
        })
    }

    /// Lead until leadership ends. False when a hook stops the leader.
    async fn lead(&mut self, inner: &Inner, agent: &Agent, shared: &Shared) -> bool {
        if let Err(fault) = self.recover(inner).await {
            tracing::error!(agent = self.id.0, "recovery failed: {}", fault.message());
        }
        while let Some(pending) = self.take(inner, agent, shared).await {
            // Woken for a round, or between batches: windows due go again.
            if pending.is_empty() {
                // Woken by a timer alone: let the node's other tasks run.
                smol::future::yield_now().await;
            } else {
                if let Some(ended) = self.ended {
                    inner.stats.between.took(ended.elapsed());
                }
                let ran = self.run(inner, agent, shared, pending).await;
                self.ended = Some(Instant::now());
                if !ran {
                    return false;
                }
            }
            self.rounds(inner);
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
            if let Err(fault) = self.deliver(inner, &snapshot, to) {
                tracing::error!(
                    agent = self.id.0,
                    to = to.0,
                    "delivery failed: {}",
                    fault.message()
                );
                // A window all the same, whose round reads it again.
                let mut window = Window::new(0, u64::from(inner.number));
                window.last = 1;
                self.windows.entry(to).or_insert(window);
            }
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
            // Idle: a sweep due runs alone, after the node's other tasks.
            let sweep = self.sweep_wait(inner);
            if sweep == Some(Duration::ZERO) {
                smol::future::yield_now().await;
                return Some(vec![Pending::Sweep]);
            }
            let woken = async { Some(Some(agent.woken.recv().await.is_ok())) };
            let term = self.term;
            let lost = async {
                shared.wait(|state| !leads(state, term)).await;
                Some(Some(false))
            };
            let next = self.windows.values().filter_map(Window::due).min();
            let round = async {
                match next {
                    Some(at) => smol::Timer::at(at).await,
                    None => std::future::pending().await,
                };
                Some(None)
            };
            // Look at the first expiry row again.
            let recheck = async {
                match sweep {
                    Some(wait) => smol::Timer::after(wait).await,
                    None => std::future::pending().await,
                };
                None
            };
            match woken.or(lost).or(round).or(recheck).await {
                Some(Some(true)) => {}
                Some(Some(false)) => return None,
                Some(None) => return Some(Vec::new()),
                None => continue,
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
        let now = Instant::now();
        while taken.len() < self.max_inputs {
            let Some((next, _)) = queue.inputs.front() else {
                break;
            };
            if !taken.is_empty() && bytes + next.bytes() > inner.max_bytes {
                break;
            }
            let (next, queued) = queue.inputs.pop_front().expect("a front input");
            inner
                .stats
                .queued
                .took(now.saturating_duration_since(queued));
            bytes += next.bytes();
            if next.capped() {
                queue.capped -= 1;
            }
            if next.agents_sent() {
                queue.from_agents -= 1;
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

    /// How long until an idle leader sweeps, or looks again: zero when a
    /// sweep is due now, none when the agent holds no session.
    fn sweep_wait(&mut self, inner: &Inner) -> Option<Duration> {
        let snapshot = inner.store.snapshot();
        let first = match first_expiry(&snapshot, self.id) {
            Ok(Some(first)) => first,
            Ok(None) => return None,
            Err(_) => return Some(SWEEP_RECHECK),
        };
        let floor = read::<u64>(&snapshot, self.id, &keys::batch_time())
            .ok()
            .flatten()
            .unwrap_or(0);
        let now = (inner.clock)().max(floor);
        if self.sweeps(first, now) {
            return Some(Duration::ZERO);
        }
        let wait = match self.swept {
            // Paused on this row: until the pause ends.
            Some((left, at)) if left == first && expiry::due(first.0) <= now => {
                SWEEP_PAUSE.saturating_sub(at.elapsed())
            }
            _ => Duration::from_millis(expiry::due(first.0).saturating_sub(now)),
        };
        Some(wait.clamp(Duration::from_millis(1), SWEEP_RECHECK))
    }

    /// Whether a batch timed `time` sweeps, the first expiry row being
    /// `first`: once it is due, unless the last sweep left it in place a
    /// moment ago.
    fn sweeps(&mut self, first: (u64, SessionId), time: u64) -> bool {
        if expiry::due(first.0) > time {
            return false;
        }
        match self.swept {
            Some((left, at)) if left == first && at.elapsed() < SWEEP_PAUSE => {
                if !self.stuck {
                    self.stuck = true;
                    tracing::warn!(
                        agent = self.id.0,
                        "a sweep left its first due expiry row in place; sweeps pause"
                    );
                }
                false
            }
            _ => {
                self.stuck = false;
                true
            }
        }
    }

    /// Run one batch to its end. False when a hook stops the leader.
    async fn run(
        &mut self,
        inner: &Inner,
        agent: &Agent,
        shared: &Shared,
        mut pending: Vec<Pending>,
    ) -> bool {
        let taken = Instant::now();
        // Whether to sweep is decided below, on the batch's state.
        pending.retain(|item| !matches!(item, Pending::Sweep));
        let snapshot = Arc::new(inner.store.snapshot());
        let before = Arc::clone(&snapshot);
        // The batch is refined on this state, at its version and no earlier
        // than its time: an entry an earlier leadership left may have
        // applied since this one opened.
        let read_state = read::<u64>(&snapshot, self.id, &keys::version()).and_then(|version| {
            let applied = snapshot
                .applied(self.id)
                .map_err(|error| Fault::Infrastructure(error.to_string()))?;
            let floor = read::<u64>(&snapshot, self.id, &keys::batch_time())?;
            let first = first_expiry(&snapshot, self.id)?;
            Ok((version, applied, floor, first))
        });
        let (floor, first) = match read_state {
            Ok((version, applied, floor, first)) => {
                self.version = version.unwrap_or(0);
                self.applied = applied.unwrap_or(0);
                (floor.unwrap_or(0), first)
            }
            Err(fault) => {
                self.retry(inner, agent, pending, fault).await;
                return true;
            }
        };
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
        // acknowledge the mark instead. One past the next is a gap, dropped
        // for the sender's next delivery: only each sender's next in turn
        // reaches the batch.
        let mut acks: HashMap<AgentId, u64> = HashMap::new();
        let mut next: HashMap<AgentId, u64> = HashMap::new();
        // Each target's acknowledgement as applied, and where the highest
        // one taken for it sits in the batch: one goes in, the highest.
        let mut applied_acks: HashMap<AgentId, u64> = HashMap::new();
        let mut taken_acks: HashMap<AgentId, usize> = HashMap::new();
        let mut kept: Vec<Pending> = Vec::with_capacity(pending.len());
        for item in pending.drain(..) {
            match &item {
                Pending::Message(message) => {
                    let mark = self.marks[&message.from];
                    let expected = next.entry(message.from).or_insert(mark + 1);
                    if message.sequence <= mark {
                        raise(&mut acks, message.from, mark);
                        continue;
                    }
                    if message.sequence != *expected {
                        continue;
                    }
                    *expected += 1;
                }
                // One no higher than the applied acknowledgement would
                // only cost a log entry.
                Pending::Ack { to, sequence } => {
                    let applied = *applied_acks.entry(*to).or_insert_with(|| {
                        read::<u64>(&snapshot, self.id, &keys::acked(*to))
                            .ok()
                            .flatten()
                            .unwrap_or(0)
                    });
                    if *sequence <= applied {
                        continue;
                    }
                    if let Some(at) = taken_acks.get(to) {
                        if let Pending::Ack {
                            sequence: highest, ..
                        } = &mut kept[*at]
                        {
                            *highest = (*highest).max(*sequence);
                        }
                        continue;
                    }
                    taken_acks.insert(*to, kept.len());
                }
                _ => {}
            }
            kept.push(item);
        }
        let mut pending = kept;
        self.acknowledge(inner, acks);
        let time = self.time(inner, floor);
        // First, so a batch its gas or size cuts short keeps it.
        let sweeping = first.filter(|first| self.sweeps(*first, time));
        if sweeping.is_some() {
            pending.insert(0, Pending::Sweep);
        }
        // Once a sweep applied, or failed alone, the next waits while it left
        // the first due row in place.
        let swept = |leader: &mut Self| {
            if let Some(first) = sweeping {
                leader.swept = Some((first, Instant::now()));
            }
        };
        if pending.is_empty() {
            self.max_inputs = inner.max_inputs;
            return true;
        }
        let batch = Batch {
            version: self.version,
            time,
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
        inner.stats.prepare.took(taken.elapsed());
        match self.execute(inner, shared, snapshot, &batch, blobs).await {
            Ok(Ran::Done(result)) => {
                self.skipped = false;
                self.version += 1;
                self.max_inputs = inner.max_inputs;
                self.backoff = BACKOFF;
                swept(self);
                if !inner.hooks.after_commit(self.id, self.applied) {
                    return false;
                }
                let dispatching = Instant::now();
                self.dispatch(inner, agent, pending, &result, &before);
                inner.stats.dispatch.took(dispatching.elapsed());
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
            Err(Fault::Agent(message)) => {
                if pending.len() == 1 {
                    swept(self);
                }
                self.fail(inner, agent, pending, message);
            }
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

    /// A batch's time: the node's clock, held at the agent's time, `floor`,
    /// while the clock trails it. Leadership stays: every replica would
    /// trail an agent a fast clock once led.
    fn time(&mut self, inner: &Inner, floor: u64) -> u64 {
        let clock = (inner.clock)();
        let trailing = floor > clock.saturating_add(CLOCK_BOUND);
        if trailing && !self.trailing {
            tracing::error!(
                agent = self.id.0,
                behind_ms = floor - clock,
                "this node's clock trails the agent's time; its batches are timed at the agent's"
            );
        } else if !trailing && self.trailing {
            tracing::info!(
                agent = self.id.0,
                "this node's clock no longer trails the agent's time"
            );
        }
        self.trailing = trailing;
        clock.max(floor)
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
        let started = Instant::now();
        inner.stats.batch_inputs.record(batch.inputs.len() as u64);
        let program = Arc::clone(&inner.program);
        let pool = Arc::clone(&inner.pool);
        let store_blobs = inner.blobs.clone();
        let refined = batch.clone();
        let hooks = Arc::clone(&inner.hooks);
        let gas = inner.refine_gas;
        let state = Arc::clone(&snapshot);
        let queued = Instant::now();
        let (output, refine_gas) = ran(inner
            .executors
            .run(move || {
                let running = Instant::now();
                if hooks.fail_refine(id, &refined) {
                    let failed = Err(Fault::Agent("a hook failed the refine".into()));
                    return (failed, [queued, running, Instant::now()]);
                }
                let output = pvm::refine(
                    &program,
                    &pool,
                    &store_blobs,
                    state,
                    id,
                    &Work::Batch(refined),
                    gas,
                );
                (output, [queued, running, Instant::now()])
            })
            .await
            .map(|(output, [queued, running, finished])| {
                inner.stats.refine_queue.took(running - queued);
                inner.stats.refine.took(finished - running);
                inner.stats.resume.took(finished.elapsed());
                output
            }))?;
        let result: WorkResult = pvm::decode(&output)?;
        let inputs = batch.inputs.len().max(1) as u64;
        let step_gas: u64 = result
            .steps
            .iter()
            .map(|step| match step {
                Step::Ran(run) => run.gas_used,
                Step::Refused { .. } | Step::Swept { .. } => 0,
            })
            .sum();
        inner.stats.refine_gas.record(refine_gas / inputs);
        inner.stats.step_gas.record(step_gas / inputs);
        // The dry run: a failure here isolates its input off the log.
        let program = Arc::clone(&inner.program);
        let gas = shared.record.accumulate_gas;
        let applied = output.clone();
        let state = Arc::clone(&snapshot);
        let hooks = Arc::clone(&inner.hooks);
        let dried = batch.clone();
        let queued = Instant::now();
        let writes = ran(inner
            .executors
            .run(move || {
                let running = Instant::now();
                if hooks.fail_dry_run(id, &dried) {
                    let failed = Err(Fault::Agent("a hook failed accumulate".into()));
                    return (failed, [queued, running, Instant::now()]);
                }
                let writes = pvm::accumulate(&program, state, id, applied, gas);
                (writes, [queued, running, Instant::now()])
            })
            .await
            .map(|(writes, [queued, running, finished])| {
                inner.stats.dry_run_queue.took(running - queued);
                inner.stats.dry_run.took(finished - running);
                inner.stats.resume.took(finished.elapsed());
                writes
            }))?;
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
        let proposing = Instant::now();
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
        let (index, taken) = match answer.or(stopped).await {
            Some(Ok((Ok(index), taken))) => (index, taken),
            _ => return Ok(Ran::Lost),
        };
        inner
            .stats
            .propose
            .took(taken.saturating_duration_since(proposing));
        inner.stats.resume.took(taken.elapsed());
        let state = shared
            .wait(|state| state.stopped || !leads(state, term) || state.commit >= index)
            .await;
        if state.commit < index {
            return Ok(Ran::Lost);
        }
        // The commit's and the apply's ends as the driver and the applier
        // saw them: the time this task took to be polled again is the
        // runtime's, apart.
        let committed = state.commit_at.unwrap_or_else(Instant::now);
        inner
            .stats
            .commit
            .took(committed.saturating_duration_since(taken));
        inner.stats.resume.took(committed.elapsed());
        let state = shared
            .wait(|state| state.stopped || !leads(state, term) || state.applied >= index)
            .await;
        if state.applied < index {
            return Ok(Ran::Lost);
        }
        let applied = state.applied_at.unwrap_or_else(Instant::now);
        inner
            .stats
            .apply
            .took(applied.saturating_duration_since(committed));
        inner.stats.resume.took(applied.elapsed());
        inner.stats.batch.took(started.elapsed());
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
            let _ = answer.try_send(Ok(Answered {
                reply: Reply::Failed,
                at: self.applied,
            }));
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
        before: &FjallSnapshot,
    ) {
        let snapshot = inner.store.snapshot();
        let mut acks: HashMap<AgentId, u64> = HashMap::new();
        let mut rest = Vec::new();
        let mut again = Vec::new();
        let mut acked = BTreeSet::new();
        for (index, item) in pending.into_iter().enumerate() {
            let Some(step) = result.steps.get(index) else {
                rest.push(item);
                continue;
            };
            match item {
                Pending::Request(request, answer) => {
                    let answered = match step {
                        Step::Refused {
                            code: refusal::SEQUENCE,
                            ..
                        } => self
                            .duplicate(&snapshot, &request)
                            // The batch's sweep may have collected its
                            // session: the state it refined on holds it.
                            .and_then(|found| match found {
                                Some(found) => Ok(Some(found)),
                                None => self.duplicate(before, &request),
                            })
                            .map(|duplicate| duplicate.unwrap_or_else(|| reply(step)))
                            .map_err(|fault| CallError::Failed(fault.message().to_string())),
                        _ => Ok(reply(step)),
                    };
                    let at = self.applied;
                    let _ = answer.try_send(answered.map(|reply| Answered { reply, at }));
                }
                Pending::Admin(_, answer, _) => {
                    let _ = answer.try_send(Ok(Answered {
                        reply: reply(step),
                        at: self.applied,
                    }));
                }
                Pending::Sweep => {}
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
                    Step::Swept { .. } => tracing::error!(
                        agent = self.id.0,
                        "a message's step is a sweep; the message is dropped"
                    ),
                },
                Pending::Ack { to, sequence } => {
                    acked.insert(to);
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
        // The targets of new messages, and those whose acknowledgements
        // opened their windows.
        let mut targets: BTreeSet<AgentId> = result
            .steps
            .iter()
            .filter_map(|step| match step {
                Step::Ran(run) => Some(run.messages.iter().map(|message| message.to)),
                Step::Refused { .. } | Step::Swept { .. } => None,
            })
            .flatten()
            .collect();
        targets.extend(acked);
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

    /// The reply to `request`, refused out of its session's sequence, if it
    /// is at or below the session's applied mark: a duplicate, answered
    /// from the reply window, or `TooOld`. None for a gap.
    ///
    /// Ingress lets a duplicate through when it read the mark before this
    /// replica applied the original, as a new leader's does while it
    /// catches up: this answers it.
    fn duplicate(
        &self,
        snapshot: &FjallSnapshot,
        request: &Request,
    ) -> Result<Option<Reply>, Fault> {
        let Some(id) =
            read::<SessionId>(snapshot, self.id, &keys::session_index(&request.session))?
        else {
            return Ok(None);
        };
        let Some(mark) = read::<SessionMark>(snapshot, self.id, &keys::session(id))? else {
            return Ok(None);
        };
        if request.sequence > mark.sequence {
            return Ok(None);
        }
        let kept = read::<Outcome>(snapshot, self.id, &keys::reply(id, request.sequence))?;
        Ok(Some(kept.map_or(Reply::TooOld, Reply::Ran)))
    }

    /// Send `to` what the outbox holds past what this leadership sent it,
    /// in order, within its window.
    fn deliver(
        &mut self,
        inner: &Inner,
        snapshot: &FjallSnapshot,
        to: AgentId,
    ) -> Result<(), Fault> {
        let acked = read::<u64>(snapshot, self.id, &keys::acked(to))?.unwrap_or(0);
        let last = read::<u64>(snapshot, self.id, &keys::pair_out(to))?.unwrap_or(0);
        let turn = u64::from(inner.number);
        let window = self
            .windows
            .entry(to)
            .or_insert_with(|| Window::new(acked, turn));
        window.ack(acked);
        window.last = window.last.max(last);
        let after = window.through();
        if after >= window.last {
            return Ok(());
        }
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
            let size = outgoing.arguments.len() + 64;
            let window = self.windows.get_mut(&to).expect("the target's window");
            if window.full(size) {
                break;
            }
            let message = Message {
                from: self.id,
                sequence,
                instance: outgoing.instance,
                method: outgoing.method,
                arguments: outgoing.arguments,
            };
            // Nowhere to send it now, or a full queue here: it waits in the
            // outbox for the next round.
            if !inner.deliver_message(to, message, window.turn) {
                break;
            }
            window.sent.push_back((sequence, size));
            window.bytes += size;
        }
        Ok(())
    }

    /// Send again, from its acknowledgement, the window of each target
    /// whose acknowledgement stayed behind its outbox for its wait.
    fn rounds(&mut self, inner: &Inner) {
        let now = Instant::now();
        self.windows
            .retain(|_, window| window.last > window.acked || !window.sent.is_empty());
        let due: Vec<AgentId> = self
            .windows
            .iter()
            .filter(|(_, window)| window.due().is_some_and(|due| due <= now))
            .map(|(to, _)| *to)
            .collect();
        if due.is_empty() {
            return;
        }
        let snapshot = inner.store.snapshot();
        for to in due {
            self.windows.get_mut(&to).expect("a window due").rewind();
            if let Err(fault) = self.deliver(inner, &snapshot, to) {
                tracing::error!(
                    agent = self.id.0,
                    to = to.0,
                    "delivery failed: {}",
                    fault.message()
                );
            }
        }
    }

    /// Acknowledge each sender's messages through the sequence given.
    fn acknowledge(&self, inner: &Inner, acks: HashMap<AgentId, u64>) {
        for (sender, sequence) in acks {
            inner.acknowledge(sender, self.id, sequence);
        }
    }
}

/// The first row of `agent`'s expiry index: the oldest bucket, and its
/// session.
fn first_expiry(
    snapshot: &FjallSnapshot,
    agent: AgentId,
) -> Result<Option<(u64, SessionId)>, Fault> {
    for row in snapshot.scan(agent, &keys::expiry_prefix(), None) {
        let (key, _) = row.map_err(|error| Fault::Infrastructure(error.to_string()))?;
        if let Some(entry) = keys::expiry_entry(&key) {
            return Ok(Some(entry));
        }
    }
    Ok(None)
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
