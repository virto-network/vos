//! One batch, from the inputs taken to its end: filtered, timed, run, and
//! put back or failed when it does not end well.

use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;
use std::time::Instant;

use vos_wire::batch::Batch;
use vos_wire::ids::AgentId;
use vos_wire::keys;

use super::sweep::{due_rows, first_due};
use super::{Leader, Ran};
use crate::fault::{Fault, read};
use crate::node::{Answered, Pending, Reply};
use crate::store::{BlobRef, Snapshot};
use crate::{Backoff, lock, raise, seed};

/// How far this node's clock may trail the agent's time before the leader
/// says so.
const CLOCK_BOUND: u64 = 10_000;

impl Leader {
    /// Run one batch to its end. False when a hook stops the leader.
    pub(super) async fn run(&mut self, mut pending: Vec<Pending>) -> bool {
        let taken = Instant::now();
        // Whether to sweep is decided below, on the batch's state.
        pending.retain(|item| !matches!(item, Pending::Sweep(_)));
        let snapshot = Arc::new(self.inner.store.snapshot());
        let before = Arc::clone(&snapshot);
        // The batch is refined on this state, at its version and no earlier
        // than its time: an entry an earlier leadership left may have
        // applied since this one opened.
        let read_state = read::<u64>(&snapshot, self.id, &keys::version()).and_then(|version| {
            let applied = snapshot.applied(self.id)?;
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
            match due_rows(&snapshot, self.id, time) {
                Ok(due) => pending.insert(0, Pending::Sweep(due)),
                Err(fault) => {
                    self.retry(pending, fault).await;
                    return true;
                }
            }
        }
        if pending.is_empty() {
            self.max_inputs = self.inner.settings.max_inputs;
            return true;
        }
        let batch = Batch {
            version: self.version,
            time,
            seed: seed(),
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
        match self.execute(snapshot, batch, blobs).await {
            Ok(Ran::Done(result)) => {
                self.skipped = false;
                self.version += 1;
                self.max_inputs = self.inner.settings.max_inputs;
                self.backoff.reset();
                if let Some(first) = sweeping {
                    self.sweeps.swept(first);
                }
                if !self.inner.hooks.after_commit(self.id, self.applied) {
                    return false;
                }
                let dispatching = Instant::now();
                self.dispatch(pending, &result, &before);
                self.inner.stats.dispatch.took(dispatching.elapsed());
            }
            Ok(Ran::Lost) => {
                let hint = self.inner.not_leader(&self.shared);
                for item in pending {
                    item.refuse(&hint);
                }
            }
            Ok(Ran::Skipped) if self.skipped => {
                self.skipped = false;
                self.fail(pending, "applied as no writes again".into());
            }
            Ok(Ran::Skipped) => {
                tracing::warn!(
                    agent = self.id.0,
                    "a result applied as no writes; its inputs go again"
                );
                self.skipped = true;
                self.agent.requeue(pending);
            }
            Err(Fault::Agent(message)) => {
                if let Some(first) = sweeping.filter(|_| pending.len() == 1) {
                    self.sweeps.swept(first);
                }
                self.fail(pending, message);
            }
            Err(Fault::Storage(message)) => {
                tracing::error!(
                    agent = self.id.0,
                    "a commit failed ({message}); the node stops and needs a restart"
                );
                self.inner.halt();
                return false;
            }
            Err(Fault::Invariant(message)) => {
                tracing::error!(agent = self.id.0, "{message}; the agent stops");
                return false;
            }
            Err(fault) => self.retry(pending, fault).await,
        }
        true
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
        self.acknowledge(acks);
        for sender in behind {
            self.inner.behind(sender, self.id);
        }
        kept
    }

    /// A batch's time: the node's clock, held at the agent's time, `floor`,
    /// while the clock trails it. Leadership stays: every replica would
    /// trail an agent a fast clock once led.
    fn time(&mut self, floor: u64) -> u64 {
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
    async fn retry(&mut self, pending: Vec<Pending>, fault: Fault) {
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
