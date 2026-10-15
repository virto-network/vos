//! A group's applier: the committed log applied in order, the same way on
//! every replica, with the pins of the programs its installs name.

use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;
use std::time::Instant;

use vos_wire::ids::AgentId;
use vos_wire::records::{Installed, unstored};
use vos_wire::result::{WorkResult, Write as StateWrite};
use vos_wire::{Decode, keys};

use super::Shared;
use crate::fault::Fault;
use crate::node::Inner;
use crate::storage::Change;
use crate::store::{EntryKind, LogEntry, Snapshot};
use crate::{Backoff, lock, timeout};

/// A leader's accumulate of its own result, run before proposing it, kept
/// so the apply of that entry need not run it again. It matches the result
/// entry right after the state's index, of the proposing leader's term,
/// carrying the batch's seed: a leader loop proposes its next result only
/// once the last one applied or was refused.
pub(crate) struct DryRun {
    /// The applied index the state was at.
    pub applied: u64,
    /// The term of the leader proposing the result.
    pub term: u64,
    /// The seed of the batch the result is of.
    pub seed: [u8; 32],
    pub writes: Vec<StateWrite>,
}

impl Inner {
    pub(crate) fn keep_dry_run(&self, id: AgentId, dry_run: DryRun) {
        lock(&self.dry_runs).insert(id, dry_run);
    }

    /// The writes of the leader's dry run of the result entry at `index`,
    /// of `term` and the batch `seed`, if it ran on the state that entry
    /// applies to.
    pub(crate) fn dry_run(
        &self,
        id: AgentId,
        index: u64,
        term: u64,
        seed: Option<[u8; 32]>,
    ) -> Option<Vec<StateWrite>> {
        let kept = lock(&self.dry_runs).remove(&id)?;
        (kept.applied + 1 == index && kept.term == term && Some(kept.seed) == seed)
            .then_some(kept.writes)
    }

    /// Commit `changes`, then take out of the pool the programs they unpin
    /// that no agent here pins any more.
    pub(crate) async fn commit_unpinning(&self, changes: Vec<Change>) -> Result<(), String> {
        let unpinned: Vec<[u8; 32]> = changes
            .iter()
            .filter_map(|change| match change {
                Change::Unpin { hash, .. } => Some(*hash),
                _ => None,
            })
            .collect();
        self.storage.commit(changes).await?;
        self.evict(&unpinned);
        Ok(())
    }
}

/// Apply `shared`'s committed log in order until the group stops.
pub(crate) async fn apply(inner: Arc<Inner>, shared: Arc<Shared>) {
    let mut backoff = Backoff::default();
    loop {
        let state = shared
            .wait(|state| state.stopped || state.applied < state.commit.min(state.written))
            .await;
        if state.stopped {
            return;
        }
        // A snapshot switch may move the applied index past it meanwhile.
        let applying = shared.applying.lock().await;
        let state = shared.state();
        if state.applied >= state.commit.min(state.written) {
            continue;
        }
        let index = state.applied + 1;
        let applied = apply_one(&inner, &shared, index).await;
        if applied.is_ok() {
            shared.update(|state| {
                state.applied = index;
                state.applied_at = Some(Instant::now());
            });
        }
        drop(applying);
        match applied {
            Ok(()) => backoff.reset(),
            Err(Fault::Storage(message)) => {
                tracing::error!(
                    agent = shared.agent.0,
                    "an apply failed ({message}); the node stops and needs a restart"
                );
                inner.halt();
                return;
            }
            Err(fault) => {
                // Never skipped: the same entry is applied again.
                let wait = backoff.next();
                tracing::error!(
                    agent = shared.agent.0,
                    index,
                    "the node failed an apply ({}); retrying in {wait:?}",
                    fault.message()
                );
                timeout(wait, shared.wait(|state| state.stopped)).await;
            }
        }
    }
}

/// Apply the entry at `index`: a work result's writes, from accumulate
/// with the creation record's gas; nothing for a no-op or a
/// configuration. A result accumulate fails on applies as no writes, on
/// every replica alike.
async fn apply_one(inner: &Inner, shared: &Shared, index: u64) -> Result<(), Fault> {
    let agent = shared.agent;
    let entry = inner
        .store
        .log_entry(agent, index)?
        .ok_or_else(|| Fault::Infrastructure(format!("the entry at {index} is missing")))?;
    let snapshot = Arc::new(inner.store.snapshot());
    let epoch = snapshot.epoch(agent)?;
    let mut rest = Vec::new();
    let writes = match entry.kind {
        EntryKind::Result | EntryKind::LargeResult => {
            let term = entry.term;
            let body = body(inner, agent, entry, index).await?;
            let result = WorkResult::decode(&body).ok().map(|(result, _)| result);
            let writes = if inner.hooks.fail_apply(agent, index, &body) {
                Vec::new()
            } else {
                let seed = result.as_ref().map(|result| result.seed);
                match inner.dry_run(agent, index, term, seed) {
                    Some(writes) => writes,
                    None => accumulate(inner, shared, &snapshot, body, index).await?,
                }
            };
            let took = writes.iter().any(|write| write.key == keys::version());
            shared.record_outcome(index, took);
            if let Some(result) = result {
                rest.push(Change::LastResult {
                    agent,
                    time: result.time,
                    seed: result.seed,
                });
            }
            writes
        }
        EntryKind::NoOp | EntryKind::Configuration => Vec::new(),
    };
    if repins(&snapshot, agent, &writes)? {
        rest.extend(pins(&snapshot, agent, &writes)?);
    }
    let mut changes = vec![Change::Apply {
        agent,
        epoch,
        index,
        writes,
    }];
    changes.extend(rest);
    inner
        .commit_unpinning(changes)
        .await
        .map_err(Fault::Storage)
}

/// A result entry's body: inline, or the blob a large one names, read off
/// the runtime thread.
///
/// The entry was written with its blobs, and its log row keeps them: a blob
/// missing is data the store lost, which no retry mends, so the node halts.
/// On its restart the recovery cut keeps a committed entry, its blobs
/// fetched again from the members, and takes one past the persisted commit,
/// for the leader to send again ([`crate::raft::recovery_cut`]).
async fn body(
    inner: &Inner,
    agent: AgentId,
    entry: LogEntry,
    index: u64,
) -> Result<Vec<u8>, Fault> {
    let Some(blob) = entry.result_blob().copied() else {
        return Ok(entry.body);
    };
    let blobs = inner.blobs.clone();
    let lost = inner.hooks.lose_blob(agent, index);
    match inner.offload(move || blobs.get(&blob.hash)).await {
        Some(Ok(Some(bytes))) if !lost => Ok(bytes),
        Some(Ok(_)) => Err(Fault::Storage(format!(
            "the result blob of the entry at {index} is lost"
        ))),
        Some(Err(error)) => Err(error.into()),
        None => Err(Fault::Infrastructure("a blob read panicked".into())),
    }
}

async fn accumulate(
    inner: &Inner,
    shared: &Shared,
    snapshot: &Arc<Snapshot>,
    result: Vec<u8>,
    index: u64,
) -> Result<Vec<StateWrite>, Fault> {
    let machines = inner.machines.clone();
    let state = Arc::clone(snapshot);
    let agent = shared.agent;
    let gas = shared.record.accumulate_gas;
    let accumulated = inner
        .executors
        .run(move || machines.accumulate(state, agent, result, gas))
        .await;
    match accumulated.map_err(Fault::from).flatten() {
        Ok(writes) => Ok(writes),
        Err(Fault::Agent(message)) => {
            tracing::warn!(
                agent = agent.0,
                index,
                "accumulate fails on the entry ({message}); it applies as no writes"
            );
            Ok(Vec::new())
        }
        Err(fault) => Err(fault),
    }
}

/// The prefixes of the rows that pin an agent's programs: its installed
/// instances', and its workflows' counts.
fn pin_prefixes() -> [Vec<u8>; 2] {
    [keys::installed_prefix(), keys::workflow_pins_prefix()]
}

/// Whether `writes` may change the programs `agent` pins: an install's
/// row written, or a workflows' pins row that appears or goes. A count
/// that only moves, as most workflows' starts and ends move it, changes
/// nothing.
fn repins(
    snapshot: &Snapshot,
    agent: AgentId,
    writes: &[StateWrite],
) -> Result<bool, fjall::Error> {
    let installed = keys::installed_prefix();
    for write in writes {
        if write.key.starts_with(&installed) {
            return Ok(true);
        }
        if keys::workflow_pins_entry(&write.key).is_some()
            && snapshot.get(agent, &write.key)?.is_some() != write.value.is_some()
        {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Rows of state, each a key and its value.
type Rows = Vec<(Vec<u8>, Vec<u8>)>;

/// The rows of `agent`'s state at `snapshot` that pin its programs.
fn pin_rows(snapshot: &Snapshot, agent: AgentId) -> Result<Rows, fjall::Error> {
    let mut rows = Vec::new();
    for prefix in pin_prefixes() {
        for row in snapshot.scan(agent, &prefix, None) {
            rows.push(row?);
        }
    }
    Ok(rows)
}

/// The programs `agent`'s state at `snapshot` pins.
pub(crate) fn pinned(
    snapshot: &Snapshot,
    agent: AgentId,
) -> Result<BTreeSet<[u8; 32]>, fjall::Error> {
    let rows = pin_rows(snapshot, agent)?;
    Ok(programs(rows.iter().map(|(key, value)| (key, value))))
}

/// The pins an apply's `writes` change: every program the agent's
/// installed instances name, or a workflow that has not ended runs, is
/// pinned, and one neither names any more is not.
fn pins(
    snapshot: &Snapshot,
    agent: AgentId,
    writes: &[StateWrite],
) -> Result<Vec<Change>, fjall::Error> {
    let mut rows: HashMap<Vec<u8>, Vec<u8>> = pin_rows(snapshot, agent)?.into_iter().collect();
    let before = programs(rows.iter());
    let prefixes = pin_prefixes();
    let pins_row = |key: &[u8]| prefixes.iter().any(|prefix| key.starts_with(prefix));
    for write in writes.iter().filter(|write| pins_row(&write.key)) {
        match &write.value {
            Some(value) => rows.insert(write.key.clone(), value.clone()),
            None => rows.remove(&write.key),
        };
    }
    let after = programs(rows.iter());
    Ok(pin_changes(agent, &before, &after))
}

/// The pins and unpins that take `agent` from pinning `before` to pinning
/// `after`.
pub(crate) fn pin_changes(
    agent: AgentId,
    before: &BTreeSet<[u8; 32]>,
    after: &BTreeSet<[u8; 32]>,
) -> Vec<Change> {
    let pinned = after
        .difference(before)
        .map(|hash| Change::Pin { hash: *hash, agent });
    let unpinned = before
        .difference(after)
        .map(|hash| Change::Unpin { hash: *hash, agent });
    pinned.chain(unpinned).collect()
}

/// The programs pinning rows pin: each installed instance's, its workflows
/// in it, and its attestables' kernels; and each program a workflow that
/// has not ended runs. Other rows pin nothing.
pub(crate) fn programs<'a>(
    rows: impl Iterator<Item = (&'a Vec<u8>, &'a Vec<u8>)>,
) -> BTreeSet<[u8; 32]> {
    let mut programs = BTreeSet::new();
    for (key, value) in rows {
        if let Some(program) = keys::workflow_pins_entry(key) {
            programs.insert(program.0);
            continue;
        }
        if !key.starts_with(&keys::installed_prefix()) {
            continue;
        }
        let Some((installed, _)) = unstored(value).and_then(|bytes| Installed::decode(bytes).ok())
        else {
            continue;
        };
        programs.extend(installed.programs().map(|hash| hash.0));
    }
    programs
}
