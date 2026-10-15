//! One batch, from the inputs taken to its end: filtered, timed, run, and
//! put back or failed when it does not end well.

use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;
use std::time::Instant;

use vos_wire::batch::Batch;
use vos_wire::ids::AgentId;
use vos_wire::keys;

use super::sweep::{due_rows, first_due};
use super::{BACKOFF, Leader, MAX_BACKOFF, Ran, raise};
use crate::fault::{Fault, read};
use crate::group::Shared;
use crate::node::{Agent, Answered, Inner, Pending, Reply};
use crate::store::{BlobRef, Snapshot};
use crate::{lock, seed};

/// How far this node's clock may trail the agent's time before the leader
/// says so.
const CLOCK_BOUND: u64 = 10_000;

impl Leader {
    /// Run one batch to its end. False when a hook stops the leader.
    pub(super) async fn run(
        &mut self,
        inner: &Inner,
        agent: &Agent,
        shared: &Shared,
        mut pending: Vec<Pending>,
    ) -> bool {
        let taken = Instant::now();
        // Whether to sweep is decided below, on the batch's state.
        pending.retain(|item| !matches!(item, Pending::Sweep(_)));
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
            let first = first_due(&snapshot, self.id)?;
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
                Pending::Message(message) | Pending::Failed(message) => Some(message.from),
                _ => None,
            })
            .collect();
        for from in senders {
            if let Err(fault) = self.mark(&snapshot, from) {
                self.retry(inner, agent, pending, fault).await;
                return true;
            }
        }
        let mut pending = self.filter(inner, &snapshot, pending);
        let time = self.time(inner, floor);
        // First, so a batch its gas or size cuts short keeps it, with the
        // rows due at the batch's time, which refine takes by their keys.
        let sweeping = first.filter(|first| self.sweeps(*first, time));
        if sweeping.is_some() {
            match due_rows(&snapshot, self.id, time) {
                Ok(due) => pending.insert(0, Pending::Sweep(due)),
                Err(fault) => {
                    self.retry(inner, agent, pending, fault).await;
                    return true;
                }
            }
        }
        // Once a sweep applied, or failed alone, the next waits while it left
        // the first due row in place.
        let swept = |leader: &mut Self| {
            if let Some(first) = sweeping {
                leader.swept = Some((first, Instant::now()));
            }
        };
        if pending.is_empty() {
            self.max_inputs = inner.settings.max_inputs;
            return true;
        }
        let batch = Batch {
            version: self.version,
            time,
            seed: seed(),
            budget: inner.settings.refine_gas,
            inputs: pending.iter().map(Pending::input).collect(),
        };
        let blobs: Vec<BlobRef> = pending
            .iter()
            .flat_map(|item| match item {
                Pending::Admin { blobs, .. } => blobs.clone(),
                _ => Vec::new(),
            })
            .collect();
        inner.stats.prepare.took(taken.elapsed());
        match self.execute(inner, shared, snapshot, batch, blobs).await {
            Ok(Ran::Done(result)) => {
                self.skipped = false;
                self.version += 1;
                self.max_inputs = inner.settings.max_inputs;
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

    /// What of `pending` goes into the batch, the marks of its messages'
    /// senders read. A message at or below its pair mark applied already:
    /// it is dropped, and the mark acknowledged instead. One past the next
    /// is a gap, dropped, and its sender told it is behind: only each
    /// sender's next in turn goes in. Of a target's acknowledgements, the
    /// highest goes in, if above the one applied.
    fn filter(&self, inner: &Inner, snapshot: &Snapshot, pending: Vec<Pending>) -> Vec<Pending> {
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
                        raise(&mut acks, message.from, mark);
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
        self.acknowledge(inner, acks);
        for sender in behind {
            inner.behind(sender, self.id);
        }
        kept
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
        let until = Instant::now() + self.backoff;
        while !lock(&agent.queue).stopped {
            let left = until.saturating_duration_since(Instant::now());
            if left.is_zero() {
                break;
            }
            smol::Timer::after(left.min(BACKOFF)).await;
        }
        self.backoff = (self.backoff * 2).min(MAX_BACKOFF);
    }

    /// A batch the agent program failed: requeue it shorter, until one input
    /// alone fails. A request or an admin command then fails its caller.
    /// A message goes again, and failing alone a second time, on the state
    /// of a later batch, is asserted failed: consumed for good, so a
    /// transient failure never consumes one. Anything else is dropped.
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
            inner.requeue(agent, vec![again]);
            return;
        }
        tracing::error!(
            agent = self.id.0,
            "the agent program fails on one input alone ({failed}); it is dropped"
        );
        if let Pending::Request { answer, .. } | Pending::Admin { answer, .. } = input {
            let _ = answer.try_send(Ok(Answered {
                reply: Reply::Failed,
                at: self.applied,
            }));
        }
    }
}
