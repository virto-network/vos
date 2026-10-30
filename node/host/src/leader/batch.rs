//! One batch, from the inputs taken to its end: filtered, timed, run, and
//! put back or failed when it does not end well.

use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;
use std::time::Instant;

use vos_wire::batch::Batch;
use vos_wire::ids::AgentId;
use vos_wire::keys;

use super::close::Closes;
use super::execute::{Flight, Launched};
use super::{Ended, Leader, is_due};
use crate::fault::{Fault, read};
use crate::node::{Answered, Pending, Reply};
use crate::store::{BlobRef, Snapshot, Unapplied};
use crate::{Backoff, lock, raise, random};

/// How far this node's clock may trail the agent's time before the leader
/// says so.
const CLOCK_BOUND: u64 = 10_000;

impl Leader {
    /// The duties due on `snapshot`, in a batch's order: the reads served,
    /// the reports, the proofs to record and the closes; none when a test's
    /// hook stopped the leader before a close.
    fn duties(&mut self, snapshot: &Snapshot) -> Result<Option<Vec<Pending>>, Fault> {
        let mut duties = self.resumes(snapshot)?;
        duties.extend(self.reports(snapshot)?);
        duties.extend(self.proofs(snapshot)?);
        Ok(match self.closes(snapshot)? {
            Closes::Due(closes) => {
                duties.extend(closes);
                Some(duties)
            }
            Closes::Stopped => None,
        })
    }

    /// Prepare one batch on the state the batches in flight leave, and
    /// launch it: it flies with them, up to the bound in flight, the
    /// oldest landing first once the bound is reached. A batch with an
    /// admin command, or with duties due, waits for those in flight to
    /// land: it runs on the applied state. False when a hook stops the
    /// leader.
    pub(super) async fn run(&mut self, mut pending: Vec<Pending>) -> bool {
        // An install's programs are pinned as it applies: a batch after
        // it refines once it has. Nor does a batch fly over one that did
        // not apply as proposed.
        let admin = pending
            .iter()
            .any(|item| matches!(item, Pending::Admin { .. }));
        if (admin || self.doomed || self.cut_short) && !self.land_all().await {
            self.agent.requeue(pending);
            return false;
        }
        let taken = Instant::now();
        // Whether to sweep, and what reads to serve, are decided below, on
        // the batch's state.
        pending.retain(|item| !matches!(item, Pending::Sweep(_) | Pending::Duty(_)));
        let snapshot = Arc::new(self.state());
        let before = Arc::clone(&snapshot);
        // The batch is refined on this state, at its version and no earlier
        // than its time: an entry an earlier leadership left may have
        // applied since this one opened.
        let read_state = read::<u64>(&snapshot, self.id, &keys::version()).and_then(|version| {
            let applied = snapshot.applied(self.id)?;
            let floor = read::<u64>(&snapshot, self.id, &keys::batch_time())?;
            let first = self.sweeps.first_due(&snapshot, self.id)?;
            Ok((version, applied, floor, first))
        });
        let (version, floor, first) = match read_state {
            Ok((version, applied, floor, first)) => {
                self.applied = match self.in_flight.back() {
                    Some(flight) => flight.index,
                    None => applied.unwrap_or(0),
                };
                (version.unwrap_or(0), floor.unwrap_or(0), first)
            }
            Err(fault) => {
                self.retry(pending, fault).await;
                return true;
            }
        };
        let senders: BTreeSet<AgentId> = pending
            .iter()
            .filter_map(|item| match item {
                Pending::Message(message) | Pending::Failed(message) => Some(message.from),
                _ => None,
            })
            .collect();
        for from in senders {
            if let Err(fault) = self.mark(&snapshot, from) {
                self.retry(pending, fault).await;
                return true;
            }
        }
        let mut pending = self.filter(&snapshot, pending);
        let time = self.time(floor);
        // First, so a batch its gas or size cuts short keeps it, with the
        // rows due at the batch's time, which refine takes by their keys.
        let sweeping = first.filter(|first| self.sweeps(*first, time));
        if sweeping.is_some() {
            match self.sweeps.due_rows(&snapshot, self.id, time) {
                Ok(due) => pending.insert(0, Pending::Sweep(due)),
                Err(fault) => {
                    self.retry(pending, fault).await;
                    return true;
                }
            }
        }
        match self.duties(&snapshot) {
            // Duties are made on the applied state, as their rows apply
            // apart from the agent's writes: those in flight land first,
            // and the batch is made again.
            Ok(Some(duties)) if !duties.is_empty() && !self.in_flight.is_empty() => {
                let pending = pending
                    .into_iter()
                    .filter(|item| !matches!(item, Pending::Sweep(_)))
                    .collect();
                if !self.land_all().await {
                    self.agent.requeue(pending);
                    return false;
                }
                return Box::pin(self.run(pending)).await;
            }
            Ok(Some(duties)) => pending.extend(duties),
            Ok(None) => {
                self.agent.requeue(pending);
                return false;
            }
            Err(fault) => {
                self.retry(pending, fault).await;
                return true;
            }
        }
        if pending.is_empty() {
            self.max_inputs = self.inner.settings.max_inputs;
            return true;
        }
        let batch = Batch {
            version,
            time,
            seed: random(),
            budget: self.inner.settings.refine_gas,
            inputs: pending.iter().map(Pending::input).collect(),
        };
        let blobs: Vec<BlobRef> = pending
            .iter()
            .flat_map(|item| match item {
                Pending::Admin { blobs, .. } => blobs.clone(),
                _ => Vec::new(),
            })
            .collect();
        self.inner.stats.prepare.took(taken.elapsed());
        match self.launch(snapshot, batch, blobs, None).await {
            Ok(Launched::Proposed {
                index,
                result,
                writes,
                proposed,
            }) => {
                self.sweeps.writes(&writes);
                // The batches after it read its senders' marks over its
                // writes: those it ran, and not those it cut short.
                for item in &pending {
                    if let Pending::Message(message) | Pending::Failed(message) = item {
                        self.marks.remove(&message.from);
                    }
                }
                // Inputs a result cut short go again once it lands: no
                // batch flies past them meanwhile, so none overtakes them.
                let ran = result.steps.iter().filter(|step| !is_due(step)).count();
                if ran < pending.len() {
                    self.cut_short = true;
                }
                self.in_flight.push_back(Flight {
                    pending,
                    result,
                    before,
                    index,
                    writes,
                    sweeping,
                    started: taken,
                    proposed,
                });
                let flying = self.in_flight.len() as u64;
                self.inner.stats.in_flight.record(flying);
                true
            }
            Ok(Launched::Lost) => {
                let hint = self.inner.not_leader(&self.shared);
                for item in pending {
                    item.refuse(&hint);
                }
                true
            }
            // Refined over batches in flight, the failure may be of a state
            // that never applies: those land, and the inputs go again, on
            // the applied state.
            Err(Fault::Agent(_)) if !self.in_flight.is_empty() => {
                let landed = self.land_all().await;
                self.agent.requeue(pending);
                landed
            }
            Err(Fault::Agent(message)) => {
                if let Some(first) = sweeping.filter(|_| pending.len() == 1) {
                    self.sweeps.swept(first);
                }
                self.fail(pending, message);
                true
            }
            Err(fault) if self.ended_by(&fault) => false,
            Err(fault) => {
                self.retry(pending, fault).await;
                true
            }
        }
    }

    /// The state the next batch runs on: the applied state, with the
    /// writes of the batches in flight over it.
    pub(super) fn state(&self) -> Snapshot {
        let snapshot = self.inner.store.snapshot();
        if self.in_flight.is_empty() {
            return snapshot;
        }
        let writes = self.in_flight.iter().flat_map(|flight| &flight.writes);
        snapshot.over(Arc::new(Unapplied::new(self.id, writes)))
    }

    /// Land the oldest batch in flight, once it applied here or leadership
    /// ended, and act on how it ended. False when a hook stops the leader.
    pub(super) async fn land_oldest(&mut self) -> bool {
        let Some(flight) = self.in_flight.pop_front() else {
            return true;
        };
        let ended = self.land(&flight).await;
        self.landed(flight, ended).await
    }

    /// Land every batch in flight. False when a hook stops the leader.
    pub(super) async fn land_all(&mut self) -> bool {
        while !self.in_flight.is_empty() {
            if !self.land_oldest().await {
                return false;
            }
        }
        true
    }

    /// Act on how `flight` ended. Once one did not apply as proposed, those
    /// after it ran over writes that never applied: they apply as no
    /// writes, or not at all, and their inputs go again, uncounted.
    async fn landed(&mut self, flight: Flight, ended: Result<Ended, Fault>) -> bool {
        let Flight {
            pending,
            result: _,
            before,
            index,
            sweeping,
            ..
        } = flight;
        let doomed = self.doomed;
        if !matches!(ended, Ok(Ended::Done(_))) {
            // What those after it took as consumed, or as swept, is not.
            self.doomed = true;
            self.marks.clear();
            self.sweeps.lost_writes();
        }
        if self.in_flight.is_empty() {
            self.doomed = false;
            self.cut_short = false;
        }
        match ended {
            Ok(Ended::Done(result)) => {
                self.skipped = false;
                self.max_inputs = self.inner.settings.max_inputs;
                self.backoff.reset();
                if let Some(first) = sweeping {
                    self.sweeps.swept(first);
                }
                if !self.inner.hooks.after_commit(self.id, index) {
                    return false;
                }
                let dispatching = Instant::now();
                self.settle(pending, &result, &before, index);
                self.inner.stats.dispatch.took(dispatching.elapsed());
            }
            Ok(Ended::Lost) => {
                let hint = self.inner.not_leader(&self.shared);
                for item in pending {
                    item.refuse(&hint);
                }
            }
            Ok(Ended::Skipped) if doomed => self.agent.requeue(pending),
            Ok(Ended::Skipped) if self.skipped => {
                self.skipped = false;
                self.fail(pending, "applied as no writes again".into());
            }
            Ok(Ended::Skipped) => {
                tracing::warn!(
                    agent = self.id.0,
                    "a result applied as no writes; its inputs go again"
                );
                self.skipped = true;
                self.agent.requeue(pending);
            }
            Err(fault) if self.ended_by(&fault) => return false,
            Err(fault) => self.retry(pending, fault).await,
        }
        true
    }

    /// Whether `fault` ends this leadership: a failed commit halts the
    /// node, a broken invariant stops the agent. Said once, here.
    pub(super) fn ended_by(&self, fault: &Fault) -> bool {
        match fault {
            Fault::Storage(message) => {
                tracing::error!(
                    agent = self.id.0,
                    "a commit failed ({message}); the node stops and needs a restart"
                );
                self.inner.halt();
                true
            }
            Fault::Invariant(message) => {
                tracing::error!(agent = self.id.0, "{message}; the agent stops");
                true
            }
            _ => false,
        }
    }

    /// What of `pending` goes into the batch, the marks of its messages'
    /// senders read. A message at or below its pair mark applied already:
    /// it is dropped, and the mark acknowledged instead. One past the next
    /// is a gap, dropped, and its sender told it is behind: only each
    /// sender's next in turn goes in. Of a target's acknowledgements, the
    /// highest goes in, if above the one applied.
    fn filter(&self, snapshot: &Snapshot, pending: Vec<Pending>) -> Vec<Pending> {
        let mut acks: HashMap<AgentId, u64> = HashMap::new();
        let mut next: HashMap<AgentId, u64> = HashMap::new();
        // Each target's acknowledgement as applied, and where the highest
        // one taken for it sits in the batch.
        let mut applied_acks: HashMap<AgentId, u64> = HashMap::new();
        let mut taken_acks: HashMap<AgentId, usize> = HashMap::new();
        let mut kept: Vec<Pending> = Vec::with_capacity(pending.len());
        let mut behind: BTreeSet<AgentId> = BTreeSet::new();
        for item in pending {
            match &item {
                Pending::Message(message) | Pending::Failed(message) => {
                    let mark = self.marks[&message.from];
                    let expected = next.entry(message.from).or_insert(mark + 1);
                    if message.sequence <= mark {
                        // Acknowledged only once applied: one a batch in
                        // flight consumes is acknowledged as it applies.
                        if let Some(applied) = self.applied_mark(message.from)
                            && message.sequence <= applied
                        {
                            raise(&mut acks, message.from, applied);
                        }
                        continue;
                    }
                    if message.sequence > *expected {
                        behind.insert(message.from);
                        continue;
                    }
                    // A second copy of one this batch holds.
                    if message.sequence < *expected {
                        continue;
                    }
                    *expected += 1;
                }
                // One no higher than the applied acknowledgement would
                // only cost a log entry.
                Pending::Ack { to, sequence } => {
                    let applied = *applied_acks.entry(*to).or_insert_with(|| {
                        read::<u64>(snapshot, self.id, &keys::acked(*to))
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
        self.acknowledge(acks);
        for sender in behind {
            self.inner.behind(sender, self.id);
        }
        kept
    }

    /// `from`'s pair mark as applied, read from the store: the only mark a
    /// message is acknowledged at. None when it cannot be read.
    fn applied_mark(&self, from: AgentId) -> Option<u64> {
        let snapshot = self.inner.store.snapshot();
        read::<u64>(&snapshot, self.id, &keys::pair_in(from))
            .ok()
            .map(|mark| mark.unwrap_or(0))
    }

    /// A batch's time: the node's clock, held at the agent's time, `floor`,
    /// while the clock trails it. Leadership stays: every replica would
    /// trail an agent a fast clock once led.
    pub(super) fn time(&mut self, floor: u64) -> u64 {
        let clock = (self.inner.clock)();
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

    /// A batch the node failed: put it back whole and wait before the next
    /// try. No input is to blame, so none is dropped.
    pub(super) async fn retry(&mut self, pending: Vec<Pending>, fault: Fault) {
        let wait = self.backoff.next();
        tracing::error!(
            agent = self.id.0,
            "the node failed a batch ({}); retrying in {wait:?}",
            fault.message(),
        );
        self.agent.requeue(pending);
        // Wait in short slices, so a stop does not wait out the backoff.
        let until = Instant::now() + wait;
        while !lock(&self.agent.queue).stopped {
            let left = until.saturating_duration_since(Instant::now());
            if left.is_zero() {
                break;
            }
            smol::Timer::after(left.min(Backoff::FIRST)).await;
        }
    }

    /// A batch the agent program failed: requeue it shorter, until one input
    /// alone fails. A request or an admin command then fails its caller.
    /// A message goes again, and failing alone a second time, on the state
    /// of a later batch, is asserted failed: consumed for good, so a
    /// transient failure never consumes one. Anything else is dropped.
    fn fail(&mut self, mut pending: Vec<Pending>, failed: String) {
        if pending.len() > 1 {
            tracing::warn!(
                agent = self.id.0,
                inputs = pending.len(),
                "a batch failed ({failed}); retrying shorter"
            );
            self.max_inputs = (pending.len() / 2).max(1);
            self.agent.requeue(pending);
            return;
        }
        let input = pending.pop().expect("one input");
        if let Pending::Message(message) = input {
            let named = (message.from, message.sequence);
            let again = if self.failing == Some(named) {
                self.failing = None;
                tracing::error!(
                    agent = self.id.0,
                    from = message.from.0,
                    sequence = message.sequence,
                    "the agent program fails on a message alone again ({failed}); it is consumed as failed"
                );
                Pending::Failed(message)
            } else {
                self.failing = Some(named);
                tracing::warn!(
                    agent = self.id.0,
                    from = message.from.0,
                    sequence = message.sequence,
                    "the agent program fails on a message alone ({failed}); it goes again"
                );
                Pending::Message(message)
            };
            self.agent.requeue(vec![again]);
            return;
        }
        tracing::error!(
            agent = self.id.0,
            "the agent program fails on one input alone ({failed}); it is dropped"
        );
        input.answer(Ok(Answered {
            reply: Reply::Failed,
            at: self.applied,
        }));
    }
}
