//! An agent's leader loop, while this node leads its group. Per batch, in
//! order: refine against the applied state, a dry run of accumulate on the
//! same state, the result proposed, and once this replica has applied it,
//! the replies, the outbox's deliveries and the acknowledgements. Between
//! batches, the outbox's windows go again: in rounds, or at once when a
//! receiver finds this agent behind it.

mod anchor;
mod batch;
mod close;
mod cut;
mod execute;
mod outbox;
mod proven;
mod serve;
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
use vos_wire::result::{InputRef, Run, Step, WorkResult};

use crate::fault::{Fault, read};
use crate::group::{Local, Shared, State};
use crate::node::{Agent, Inner, Pending};
use crate::store::Snapshot;
use crate::{Backoff, lock, timeout};
use anchor::Anchoring;
use sweep::Sweeps;
use window::{BEHIND_EVERY, WINDOW, Window};

/// Lead `agent` whenever this node's replica leads its group, until the
/// group stops.
pub(crate) async fn lead(inner: Arc<Inner>, agent: Arc<Agent>, shared: Arc<Shared>) {
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
        if leads(&state, term) && !Leader::open(&inner, &agent, &shared, term).lead().await {
            // A hook, or a broken invariant, stopped the leader for good:
            // its replica hands leadership over and goes on applying, and
            // callers go to the next leader.
            agent.refuse(&inner.not_leader(&shared));
            inner.to_group(shared.agent, Local::Retire);
            return;
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

/// Whether `step` is a workflow's due step: one no input made.
fn is_due(step: &Step) -> bool {
    matches!(
        step,
        Step::Ran(Run {
            input: InputRef::Due { .. },
            ..
        })
    )
}

struct Leader {
    inner: Arc<Inner>,
    agent: Arc<Agent>,
    shared: Arc<Shared>,
    id: AgentId,
    term: u64,
    /// The index applied when the last batch read its state, then the
    /// index of its result.
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
    backoff: Backoff,
    /// The inputs the last batch requeued because its result applied as no
    /// writes: a second time, the batch is shortened as a failing one is.
    skipped: bool,
    sweeps: Sweeps,
    /// When the last batch ended.
    ended: Option<Instant>,
    /// When it last told senders whose messages the queue dropped full
    /// that they are behind.
    told: Option<Instant>,
    /// The representative's anchoring of the space's roots at the venue.
    anchoring: Anchoring,
}

/// What an idle leader takes.
enum Taken {
    /// Inputs for a batch.
    Inputs(Vec<Pending>),
    /// A sweep due: a batch with no inputs, which sweeps.
    Sweep,
    /// A `Cut` marker due: an empty result, unrefined.
    Marker,
    /// Reads proved at their cuts, reports or closes due: a batch with no
    /// inputs, which makes them.
    Serve,
    /// No input: the windows due go again.
    Rounds,
}

/// What woke an idle leader.
enum Woke {
    /// Its queue: inputs came, or it stopped.
    Queue,
    /// Leadership ended, or the queue's wakes did.
    Lost,
    /// A window is due to go again.
    Round,
    /// It looks again at its due index, or tells more senders.
    Recheck,
    /// Its replica's root builder finished a window's cut: a report, a
    /// close or a read may be due.
    Built,
}

/// How a batch ended.
enum Ended {
    Done(WorkResult),
    /// Leadership ended before the result applied here.
    Lost,
    /// The result applied, but accumulate skipped it or failed on it: the
    /// state was not the one it was refined on. Its inputs go again.
    Skipped,
}

impl Leader {
    /// A leadership of `term`. Each batch reads the state it runs on.
    fn open(inner: &Arc<Inner>, agent: &Arc<Agent>, shared: &Arc<Shared>, term: u64) -> Self {
        Self {
            inner: Arc::clone(inner),
            agent: Arc::clone(agent),
            shared: Arc::clone(shared),
            id: shared.agent,
            term,
            applied: 0,
            trailing: false,
            marks: HashMap::new(),
            windows: HashMap::new(),
            failing: None,
            max_inputs: inner.settings.max_inputs,
            backoff: Backoff::default(),
            skipped: false,
            sweeps: Sweeps::default(),
            ended: None,
            told: None,
            anchoring: Anchoring::default(),
        }
    }

    /// Lead until leadership ends. False when a hook stops the leader.
    async fn lead(&mut self) -> bool {
        if !self.recovered().await {
            return true;
        }
        while let Some(taken) = self.take().await {
            let pending = match taken {
                Taken::Inputs(pending) => Some(pending),
                Taken::Sweep | Taken::Serve => Some(Vec::new()),
                Taken::Marker => {
                    if !self.marker().await {
                        return false;
                    }
                    None
                }
                Taken::Rounds => None,
            };
            match pending {
                // Woken by a timer alone: let the node's other tasks run.
                None => smol::future::yield_now().await,
                Some(pending) => {
                    if let Some(ended) = self.ended {
                        self.inner.stats.between.took(ended.elapsed());
                    }
                    let ran = self.run(pending).await;
                    self.ended = Some(Instant::now());
                    if !ran {
                        return false;
                    }
                }
            }
            // Woken for a round, or between batches: windows due go again.
            self.rounds();
            if !leads(&self.shared.state(), self.term) {
                break;
            }
        }
        true
    }

    /// Recover the outbox before taking any input, trying again after a
    /// failed read while this replica leads: false once it no longer does.
    async fn recovered(&mut self) -> bool {
        loop {
            let Err(fault) = self.recover().await else {
                self.backoff.reset();
                return true;
            };
            let wait = self.backoff.next();
            tracing::error!(
                agent = self.id.0,
                "recovery failed ({}); retrying in {wait:?}",
                fault.message()
            );
            let term = self.term;
            timeout(wait, self.shared.wait(|state| !leads(state, term))).await;
            if !leads(&self.shared.state(), term) {
                return false;
            }
        }
    }

    /// What the leader takes next, once there is anything; `None` once
    /// leadership ends or the agent stops.
    async fn take(&mut self) -> Option<Taken> {
        let mut waited = false;
        loop {
            let built = self.shared.state().cuts_built;
            let (told, queued, untold, behind) = {
                let mut queue = lock(&self.agent.queue);
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
                    queue.untold(self.inner.settings.queue_cap, WINDOW)
                } else {
                    Vec::new()
                };
                if !told.is_empty() {
                    self.told = Some(now);
                }
                let (queued, untold) = (!queue.is_empty(), !queue.dropped.is_empty());
                (told, queued, untold, !queue.behind.is_empty())
            };
            for sender in told {
                self.inner.behind(sender, self.id);
            }
            if queued {
                break;
            }
            if !leads(&self.shared.state(), self.term) {
                return None;
            }
            // Idle: a sweep due runs alone, after the node's other tasks.
            let sweep = self.sweep_wait();
            if sweep == Some(Duration::ZERO) {
                smol::future::yield_now().await;
                return Some(Taken::Sweep);
            }
            // A window's boundary passed with no entry past it: a marker.
            let cut = self.cut_wait();
            if cut == Some(Duration::ZERO) {
                smol::future::yield_now().await;
                return Some(Taken::Marker);
            }
            // A read proved at its cut, a report, a close, or a waiting
            // anchor to try again.
            let anchor = self.anchor_wait();
            if self.serve_due()
                || self.duties_due()
                || self.proofs_due()
                || anchor == Some(Duration::ZERO)
            {
                smol::future::yield_now().await;
                return Some(Taken::Serve);
            }
            // A receiver found this agent behind it: windows go again.
            if behind {
                return Some(Taken::Rounds);
            }
            let woken = async {
                match self.agent.woken.recv().await {
                    Ok(()) => Woke::Queue,
                    Err(_) => Woke::Lost,
                }
            };
            let term = self.term;
            let lost = async {
                self.shared.wait(|state| !leads(state, term)).await;
                Woke::Lost
            };
            let next = self.windows.values().filter_map(Window::next).min();
            let round = async {
                match next {
                    Some(at) => smol::Timer::at(at).await,
                    None => std::future::pending().await,
                };
                Woke::Round
            };
            let recheck = async {
                match [sweep, cut, anchor].into_iter().flatten().min() {
                    Some(wait) => smol::Timer::after(wait).await,
                    None => std::future::pending().await,
                };
                Woke::Recheck
            };
            let shared = &self.shared;
            let finished = async {
                shared.wait(|state| state.cuts_built != built).await;
                Woke::Built
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
                Woke::Recheck
            };
            match woken
                .or(lost)
                .or(round)
                .or(recheck)
                .or(tell)
                .or(finished)
                .await
            {
                Woke::Queue => waited = true,
                Woke::Lost => return None,
                Woke::Round => return Some(Taken::Rounds),
                Woke::Recheck | Woke::Built => {}
            }
        }
        if waited {
            smol::Timer::after(self.inner.settings.linger).await;
        }
        let mut queue = lock(&self.agent.queue);
        if queue.stopped {
            return None;
        }
        let mut taken = Vec::new();
        let mut bytes = 0;
        let now = Instant::now();
        let max_bytes = self.inner.settings.max_bytes;
        while taken.len() < self.max_inputs {
            let fits = |next: &Pending| taken.is_empty() || bytes + next.bytes() <= max_bytes;
            let Some((next, queued)) = queue.pop_front_if(fits) else {
                break;
            };
            self.inner
                .stats
                .queued
                .took(now.saturating_duration_since(queued));
            bytes += next.bytes();
            taken.push(next);
        }
        Some(Taken::Inputs(taken))
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
