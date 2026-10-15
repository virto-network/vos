//! The writer's loop: each group of commits checked, written as one batch,
//! synced once when any change must be, and answered.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Instant;

use vos_wire::ids::AgentId;

use super::{Change, Commit, Shared};
use crate::Hooks;
use crate::lock;
use crate::store::{Fjall, PersistMode};

/// The writer's loop: one group of commits at a time.
pub(super) struct Writer {
    store: Fjall,
    hooks: Arc<dyn Hooks>,
    shared: Arc<Shared>,
    /// Applies written since the last synced flush, per agent.
    unsynced_applied: HashMap<AgentId, u64>,
    /// What the writer knows of each agent's rows: read once from the
    /// store, then kept in step with what it commits.
    agents: HashMap<AgentId, AgentState>,
    /// The failure of a flush, after which nothing more is written.
    failed: Option<String>,
}

/// An agent's epoch, applied index and log start, as committed.
#[derive(Clone, Copy, Debug)]
struct AgentState {
    epoch: u8,
    applied: u64,
    log_start: u64,
}

impl Writer {
    pub(super) fn new(store: Fjall, hooks: Arc<dyn Hooks>, shared: Arc<Shared>) -> Self {
        Self {
            store,
            hooks,
            shared,
            unsynced_applied: HashMap::new(),
            agents: HashMap::new(),
            failed: None,
        }
    }

    /// `agent`'s state as `pending` (this group so far) or the store has it.
    fn state(
        &mut self,
        pending: &HashMap<AgentId, AgentState>,
        agent: AgentId,
    ) -> Result<AgentState, String> {
        if let Some(&state) = pending.get(&agent).or_else(|| self.agents.get(&agent)) {
            return Ok(state);
        }
        let read = self
            .store
            .agent_rows(agent)
            .map_err(|error| error.to_string())?;
        let state = AgentState {
            epoch: read.epoch,
            applied: read.applied,
            log_start: read.log_start,
        };
        self.agents.insert(agent, state);
        Ok(state)
    }

    /// Why a commit must be refused, before any of it is written, or what
    /// it leaves each agent's state at. A refused commit writes nothing.
    fn check(
        &mut self,
        commit: &Commit,
        pending: &mut HashMap<AgentId, AgentState>,
    ) -> Result<(), String> {
        let mut after = pending.clone();
        for change in &commit.changes {
            match change {
                Change::Compact { agent, through, .. } => {
                    let durable = lock(&self.shared.durably_applied)
                        .get(agent)
                        .copied()
                        .unwrap_or(0);
                    let mut state = self.state(&after, *agent)?;
                    if *through > durable {
                        return Err(format!(
                            "compaction of agent {} through {through} passes its durably applied index",
                            agent.0
                        ));
                    }
                    if *through <= state.log_start {
                        return Err(format!(
                            "compaction of agent {} through {through} is at or below its log start",
                            agent.0
                        ));
                    }
                    state.log_start = *through;
                    after.insert(*agent, state);
                }
                Change::Apply {
                    agent,
                    epoch,
                    index,
                    ..
                } => {
                    let mut state = self.state(&after, *agent)?;
                    if *epoch != state.epoch || *index != state.applied + 1 {
                        return Err(format!(
                            "an apply of agent {} at {index} in epoch {epoch} is stale: it is at {} in epoch {}",
                            agent.0, state.applied, state.epoch
                        ));
                    }
                    state.applied = *index;
                    after.insert(*agent, state);
                }
                Change::Tree { agent, epoch, .. } => {
                    let state = self.state(&after, *agent)?;
                    if *epoch != state.epoch {
                        return Err(format!(
                            "a root build of agent {} in epoch {epoch} is stale: it is in epoch {}",
                            agent.0, state.epoch
                        ));
                    }
                }
                Change::Stage { agent, epoch, .. } | Change::DropEpoch { agent, epoch, .. } => {
                    if *epoch == self.state(&after, *agent)?.epoch {
                        return Err(format!(
                            "agent {}'s current epoch {epoch} is not staged into or dropped",
                            agent.0
                        ));
                    }
                    if let Change::Stage { first: true, .. } = change
                        && self
                            .store
                            .epoch_holds_rows(*agent, *epoch)
                            .map_err(|error| error.to_string())?
                    {
                        return Err(format!(
                            "agent {}'s epoch {epoch} still holds rows: clear it before an install",
                            agent.0
                        ));
                    }
                }
                Change::Truncate { agent, after: cut } => {
                    let state = self.state(&after, *agent)?;
                    if *cut < state.applied {
                        return Err(format!(
                            "a truncation of agent {} after {cut} is below its applied index {}",
                            agent.0, state.applied
                        ));
                    }
                }
                Change::Retire { agent, epoch, .. } => {
                    if *epoch == self.state(&after, *agent)?.epoch {
                        return Err(format!(
                            "agent {} retires into its current epoch {epoch}",
                            agent.0
                        ));
                    }
                    if self
                        .store
                        .epoch_holds_rows(*agent, *epoch)
                        .map_err(|error| error.to_string())?
                    {
                        return Err(format!(
                            "agent {} retires into epoch {epoch}, which holds rows",
                            agent.0
                        ));
                    }
                    after.insert(
                        *agent,
                        AgentState {
                            epoch: *epoch,
                            applied: 0,
                            log_start: 0,
                        },
                    );
                }
                Change::Switch { agent, switch } => {
                    let mut state = self.state(&after, *agent)?;
                    if switch.epoch == state.epoch || switch.index <= state.applied {
                        return Err(format!(
                            "a switch of agent {} to {} in epoch {} does not move past {} in epoch {}",
                            agent.0, switch.index, switch.epoch, state.applied, state.epoch
                        ));
                    }
                    state = AgentState {
                        epoch: switch.epoch,
                        applied: switch.index,
                        log_start: switch.index,
                    };
                    after.insert(*agent, state);
                }
                _ => {}
            }
        }
        *pending = after;
        Ok(())
    }

    pub(super) fn write(&mut self, group: Vec<Commit>) {
        if let Some(failure) = self.failed.clone() {
            let refusal = format!("the store failed earlier: {failure}");
            for commit in group {
                self.answer(commit, Err(refusal.clone()));
            }
            return;
        }
        self.hooks.before_commit();
        let started = Instant::now();
        self.shared.flush_commits.record(group.len() as u64);
        {
            let pending = lock(&self.shared.pending);
            for commit in &group {
                if let Some(queued) = pending.get(&commit.id) {
                    self.shared
                        .commit_queue
                        .took(started.saturating_duration_since(*queued));
                }
            }
        }
        let mut batch = self.store.batch();
        let mut synced = false;
        // Applies in this batch: they count only once it commits.
        let mut applied: HashMap<AgentId, u64> = HashMap::new();
        let dirty = vos_wire::keys::dirty_prefix();
        let mut dirtied = Vec::new();
        // Agents retired in this batch: nothing of theirs is applied.
        let mut retired = Vec::new();
        // Commits in order, each with its refusal if it has one; a refused
        // commit writes nothing, and is answered in its turn.
        let mut taken = Vec::with_capacity(group.len());
        let mut pending: HashMap<AgentId, AgentState> = HashMap::new();
        for commit in group {
            if let Err(refusal) = self.check(&commit, &mut pending) {
                taken.push((commit, Some(refusal)));
                continue;
            }
            for change in &commit.changes {
                synced |= change.synced();
                match change {
                    Change::Append {
                        agent,
                        index,
                        entry,
                    } => batch.append(*agent, *index, entry),
                    Change::Truncate { agent, after } => batch.truncate(*agent, *after),
                    Change::Compact {
                        agent,
                        through,
                        term,
                        membership,
                    } => batch.compact(*agent, *through, *term, membership.as_ref()),
                    Change::Hard { agent, hard, .. } => batch.hard_state(*agent, hard),
                    Change::Membership { agent, membership } => {
                        batch.membership(*agent, membership)
                    }
                    Change::Apply {
                        agent,
                        epoch,
                        index,
                        writes,
                    } => {
                        batch.apply(*agent, *epoch, *index, writes);
                        let entry = applied.entry(*agent).or_insert(*index);
                        *entry = (*entry).max(*index);
                        if writes.iter().any(|write| write.key.starts_with(&dirty)) {
                            dirtied.push(*agent);
                        }
                    }
                    Change::Stage {
                        agent, epoch, rows, ..
                    } => batch.stage(*agent, *epoch, rows),
                    Change::DropEpoch {
                        agent,
                        epoch,
                        limit,
                    } => batch.drop_epoch(*agent, *epoch, *limit),
                    Change::Switch { agent, switch } => {
                        batch.switch(*agent, switch);
                        let entry = applied.entry(*agent).or_insert(switch.index);
                        *entry = (*entry).max(switch.index);
                        dirtied.push(*agent);
                    }
                    Change::Pin { hash, agent } => batch.pin(hash, *agent),
                    Change::Unpin { hash, agent } => batch.unpin(hash, *agent),
                    Change::Barrier => {}
                    Change::Agent(record) => batch.agent(record),
                    Change::Placement { agent, placement } => batch.placement(*agent, placement),
                    Change::Retire {
                        agent,
                        epoch,
                        hard,
                        floor,
                    } => {
                        batch.retire(*agent, *epoch, hard, *floor);
                        retired.push(*agent);
                    }
                    Change::LastResult { agent, time, seed } => {
                        batch.last_result(*agent, *time, seed)
                    }
                    Change::Tree {
                        agent,
                        epoch,
                        writes,
                    } => batch.rows(*agent, *epoch, writes),
                }
            }
            taken.push((commit, None));
        }
        let durability = if synced {
            PersistMode::SyncAll
        } else {
            PersistMode::Buffer
        };
        let result = if self.hooks.fail_commit() {
            Err("a hook failed the commit".to_string())
        } else if synced && self.hooks.fail_sync() {
            // Written but not synced, and failed, as a failed fsync is.
            batch
                .commit(PersistMode::Buffer)
                .map_err(|error| error.to_string())
                .and(Err("a hook failed the sync".to_string()))
        } else {
            batch.commit(durability).map_err(|error| error.to_string())
        };
        if synced {
            self.shared.flush_synced.took(started.elapsed());
        } else {
            self.shared.flush_buffered.took(started.elapsed());
        }
        if let Err(failure) = &result {
            // What reached the disk is unknown, and with it every agent's
            // rows: nothing more is written over them.
            self.failed = Some(failure.clone());
            self.shared.failed.store(true, Ordering::SeqCst);
        } else {
            self.agents.extend(pending);
            // Marked once written and before the commits are answered: the
            // root builder wakes when the applier, answered, moves the
            // applied index, so it finds the mark for every row it can see.
            lock(&self.shared.dirtied).extend(dirtied);
            if !retired.is_empty() {
                let mut durable = lock(&self.shared.durably_applied);
                for agent in retired {
                    self.unsynced_applied.remove(&agent);
                    applied.remove(&agent);
                    durable.remove(&agent);
                }
            }
            for (agent, index) in applied {
                let entry = self.unsynced_applied.entry(agent).or_insert(index);
                *entry = (*entry).max(index);
            }
            if synced {
                // Every batch before this one shares the journal, so it is
                // durable now too.
                let mut durable = lock(&self.shared.durably_applied);
                for (agent, index) in self.unsynced_applied.drain() {
                    let entry = durable.entry(agent).or_insert(index);
                    *entry = (*entry).max(index);
                }
            }
        }
        for (commit, refusal) in taken {
            let answer = match refusal {
                Some(refusal) => Err(refusal),
                None => result.clone(),
            };
            self.answer(commit, answer);
        }
    }

    fn answer(&self, commit: Commit, result: Result<(), String>) {
        lock(&self.shared.pending).remove(&commit.id);
        let _ = commit.done.try_send(result);
    }
}
