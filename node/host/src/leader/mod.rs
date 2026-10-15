//! An agent's leader loop, while this node leads its group. Per batch, in
//! order: refine against the applied state, a dry run of accumulate on the
//! same state, the result proposed, and once this replica has applied it,
//! the replies, the outbox's deliveries and the acknowledgements. Between
//! batches, the outbox's windows go again: in rounds, or at once when a
//! receiver finds this agent behind it.

mod batch;
mod execute;
mod outbox;
mod settle;
mod sweep;
mod window;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use smol::future::FutureExt;
use vos_raft::Role;
use vos_wire::ids::AgentId;
use vos_wire::keys;
use vos_wire::keys::Due;
use vos_wire::result::WorkResult;

use crate::fault::{Fault, read};
use crate::group::{Local, Shared, State};
use crate::node::{Agent, Inner, Pending};
use crate::store::Snapshot;
use crate::{lock, timeout};
use window::{BEHIND_EVERY, WINDOW, Window};

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
        lock(&agent.queue).leading = true;
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
                        inner.propose(shared.agent, Local::Retire);
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
                    timeout(backoff, shared.wait(|state| !leads(state, term))).await;
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
    /// The message that last failed alone, by its sender and sequence:
    /// failing alone again, it is asserted failed.
    failing: Option<(AgentId, u64)>,
    max_inputs: usize,
    backoff: Duration,
    /// The inputs the last batch requeued because its result applied as no
    /// writes: a second time, the batch is shortened as a failing one is.
    skipped: bool,
    /// The first row of the due index when the last sweep applied, or
    /// failed alone, and when.
    swept: Option<((u64, Due), Instant)>,
    /// When the last batch ended.
    ended: Option<Instant>,
    /// That a sweep left its first due row in place, said once.
    stuck: bool,
    /// When it last told senders whose messages the queue dropped full
    /// that they are behind.
    told: Option<Instant>,
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
            failing: None,
            max_inputs: inner.settings.max_inputs,
            backoff: BACKOFF,
            skipped: false,
            swept: None,
            ended: None,
            stuck: false,
            told: None,
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
            self.rounds(inner, agent);
            if !leads(&shared.state(), self.term) {
                break;
            }
        }
        true
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
            let (told, queued, untold) = {
                let mut queue = lock(&agent.queue);
                if queue.stopped {
                    return None;
                }
                // Senders whose messages it dropped full go again as its
                // room fits their windows, at most a queue's worth of
                // windows every `BEHIND_EVERY`, so those told have arrived.
                let now = Instant::now();
                let told = if self
                    .told
                    .is_none_or(|at| now.saturating_duration_since(at) >= BEHIND_EVERY)
                {
                    queue.untold(inner.settings.queue_cap, WINDOW)
                } else {
                    Vec::new()
                };
                if !told.is_empty() {
                    self.told = Some(now);
                }
                (told, !queue.inputs.is_empty(), !queue.dropped.is_empty())
            };
            for sender in told {
                inner.behind(sender, self.id);
            }
            if queued {
                break;
            }
            if !leads(&shared.state(), self.term) {
                return None;
            }
            // Idle: a sweep due runs alone, after the node's other tasks.
            let sweep = self.sweep_wait(inner);
            if sweep == Some(Duration::ZERO) {
                smol::future::yield_now().await;
                return Some(vec![Pending::Sweep(Vec::new())]);
            }
            // A receiver found this agent behind it: windows go again.
            if !lock(&agent.queue).behind.is_empty() {
                return Some(Vec::new());
            }
            let woken = async { Some(Some(agent.woken.recv().await.is_ok())) };
            let term = self.term;
            let lost = async {
                shared.wait(|state| !leads(state, term)).await;
                Some(Some(false))
            };
            let next = self.windows.values().filter_map(Window::next).min();
            let round = async {
                match next {
                    Some(at) => smol::Timer::at(at).await,
                    None => std::future::pending().await,
                };
                Some(None)
            };
            let recheck = async {
                match sweep {
                    Some(wait) => smol::Timer::after(wait).await,
                    None => std::future::pending().await,
                };
                None
            };
            // Senders still to tell: told at a `Behind`'s pace.
            let told = self.told;
            let tell = async {
                if !untold {
                    std::future::pending::<()>().await;
                }
                if let Some(at) = told {
                    smol::Timer::at(at + BEHIND_EVERY).await;
                }
                None
            };
            match woken.or(lost).or(round).or(recheck).or(tell).await {
                Some(Some(true)) => {}
                Some(Some(false)) => return None,
                Some(None) => return Some(Vec::new()),
                None => continue,
            }
            waited = true;
        }
        if waited {
            smol::Timer::after(inner.settings.linger).await;
        }
        let mut queue = lock(&agent.queue);
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
            if !taken.is_empty() && bytes + next.bytes() > inner.settings.max_bytes {
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
    fn mark(&mut self, snapshot: &Snapshot, from: AgentId) -> Result<u64, Fault> {
        if let Some(mark) = self.marks.get(&from) {
            return Ok(*mark);
        }
        let mark = read::<u64>(snapshot, self.id, &keys::pair_in(from))?.unwrap_or(0);
        self.marks.insert(from, mark);
        Ok(mark)
    }
}

fn raise(acks: &mut HashMap<AgentId, u64>, from: AgentId, sequence: u64) {
    let ack = acks.entry(from).or_insert(0);
    *ack = (*ack).max(sequence);
}
