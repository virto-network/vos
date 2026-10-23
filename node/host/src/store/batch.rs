//! The store's writes: one atomic batch.

use std::collections::HashMap;

use fjall::PersistMode;
use vos_wire::Encode;
use vos_wire::ids::AgentId;
use vos_wire::peer::{CreationRecord, Placement};
use vos_wire::result::Write;

use super::keys::{
    NodeRow, agent_key, encode_entry, encode_hard, encode_last_result, encode_membership,
    encode_position, log_key, node_record, node_row, registry_prefix,
};
use super::{Error, Fjall, HardState, LogEntry, Membership, Result, Row, Switch};

impl Fjall {
    pub fn batch(&self) -> Batch {
        Batch {
            batch: self.database().batch(),
            store: self.clone(),
            appended: HashMap::new(),
            error: None,
        }
    }
}

/// An atomic group of writes: all of them or none survive a crash.
pub struct Batch {
    batch: fjall::OwnedWriteBatch,
    store: Fjall,
    /// The highest index this batch appended, per agent: a truncation
    /// later in the batch removes those too.
    appended: HashMap<AgentId, u64>,
    /// A read the batch needed failed: it then commits nothing.
    error: Option<Error>,
}

impl Batch {
    pub fn append(&mut self, agent: AgentId, index: u64, entry: &LogEntry) {
        self.batch
            .insert(self.store.log(), log_key(agent, index), encode_entry(entry));
        let last = self.appended.entry(agent).or_insert(index);
        *last = (*last).max(index);
    }

    /// Remove the agent's log entries after `after`, including any this
    /// batch appended.
    pub fn truncate(&mut self, agent: AgentId, after: u64) {
        let Some(stored) = self.checked(self.store.last_log_index(agent)) else {
            return;
        };
        let appended = self.appended.get(&agent).copied();
        let last = stored.max(appended).unwrap_or(0);
        for index in after.saturating_add(1)..=last {
            self.batch.remove(self.store.log(), log_key(agent, index));
        }
        if let Some(appended) = self.appended.get_mut(&agent) {
            *appended = (*appended).min(after);
        }
    }

    /// Remove the agent's log entries through `through`, whose term is
    /// `term`, and start the log after it, with `membership` the replica
    /// set in effect there, when known.
    pub fn compact(
        &mut self,
        agent: AgentId,
        through: u64,
        term: u64,
        membership: Option<&Membership>,
    ) {
        for row in self
            .store
            .log()
            .range(log_key(agent, 0)..=log_key(agent, through))
        {
            let Some(key) = self.checked(row.key()) else {
                return;
            };
            self.batch.remove(self.store.log(), key);
        }
        let start = [
            &encode_position(through, term)[..],
            &membership.map(encode_membership).unwrap_or_default(),
        ]
        .concat();
        self.set(agent, NodeRow::LogStart, start);
    }

    pub fn hard_state(&mut self, agent: AgentId, hard: &HardState) {
        self.set(agent, NodeRow::Hard, encode_hard(hard));
    }

    pub fn membership(&mut self, agent: AgentId, membership: &Membership) {
        self.set(agent, NodeRow::Membership, encode_membership(membership));
    }

    /// Apply a work result's writes, in order, to the agent's rows under
    /// `epoch`, and record `index` as its applied index.
    pub fn apply<'a>(
        &mut self,
        agent: AgentId,
        epoch: u8,
        index: u64,
        writes: impl IntoIterator<Item = &'a Write>,
    ) {
        self.rows(agent, epoch, writes);
        self.set(agent, NodeRow::Applied, index.to_be_bytes());
    }

    /// Write rows, in order, to the agent's rows under `epoch`: a value,
    /// or (`None`) a deletion.
    pub fn rows<'a>(
        &mut self,
        agent: AgentId,
        epoch: u8,
        writes: impl IntoIterator<Item = &'a Write>,
    ) {
        for write in writes {
            let partition = self.store.partition(&write.key);
            let key = agent_key(agent, epoch, &write.key);
            match &write.value {
                Some(value) => self.batch.insert(partition, key, value.as_slice()),
                None => self.batch.remove(partition, key),
            }
        }
    }

    /// Write a snapshot's rows (agent-relative keys) under `epoch`, beside
    /// the current one.
    pub fn stage(&mut self, agent: AgentId, epoch: u8, rows: &[Row]) {
        for (key, value) in rows {
            let partition = self.store.partition(key);
            self.batch
                .insert(partition, agent_key(agent, epoch, key), value.as_slice());
        }
    }

    /// Remove up to `limit` of the agent's rows under `epoch`.
    pub fn drop_epoch(&mut self, agent: AgentId, epoch: u8, limit: usize) {
        let prefix = agent_key(agent, epoch, &[]);
        let mut left = limit;
        for partition in [self.store.system(), self.store.state()] {
            for row in partition.prefix(&prefix).take(left) {
                match row.key() {
                    Ok(key) => {
                        self.batch.remove(partition, key);
                        left -= 1;
                    }
                    Err(error) => {
                        self.error.get_or_insert(error);
                        return;
                    }
                }
            }
        }
    }

    /// Switch the agent to the snapshot staged under `epoch`, at `index`
    /// and `term`: its epoch pointer, applied index, log start (with the
    /// replica set in effect there), hard state and membership, and its
    /// log, compacted through `index` and cut after it if `truncate_after`
    /// says so.
    pub fn switch(&mut self, agent: AgentId, switch: &Switch) {
        if let Some(after) = switch.truncate_after {
            self.truncate(agent, after);
        }
        self.compact(
            agent,
            switch.index,
            switch.term,
            switch.log_start_membership.as_ref(),
        );
        self.hard_state(agent, &switch.hard);
        self.membership(agent, &switch.membership);
        self.set(agent, NodeRow::Applied, switch.index.to_be_bytes());
        self.epoch(agent, switch.epoch);
    }

    /// Point the agent's reads at its rows under `epoch`.
    fn epoch(&mut self, agent: AgentId, epoch: u8) {
        self.set(agent, NodeRow::Epoch, [epoch]);
    }

    /// `agent` keeps the blob `hash`: a program it runs.
    pub fn pin(&mut self, hash: &[u8; 32], agent: AgentId) {
        self.batch
            .insert(self.store.blobs(), crate::blobs::pin_key(hash, agent.0), []);
    }

    pub fn unpin(&mut self, hash: &[u8; 32], agent: AgentId) {
        self.batch
            .remove(self.store.blobs(), crate::blobs::pin_key(hash, agent.0));
    }

    /// Record an agent's creation.
    pub fn agent(&mut self, record: &CreationRecord) {
        let key = [registry_prefix(), record.agent.0.to_be_bytes().to_vec()].concat();
        self.batch.insert(self.store.system(), key, record.encode());
    }

    /// Record where an agent runs.
    pub fn placement(&mut self, agent: AgentId, placement: &Placement) {
        self.batch.insert(
            self.store.system(),
            node_record(NodeRow::Placement, &agent.0.to_be_bytes()),
            placement.encode(),
        );
    }

    /// Retire the agent from this node: its log, applied index, log start,
    /// membership and last result go, its state moves to the stale epoch
    /// before `epoch`, and of its hard state only the term and vote stay
    /// (`hard`), so it never votes twice in a term if added again. `floor`,
    /// the last log position it held, bounds the votes it gives then.
    pub fn retire(&mut self, agent: AgentId, epoch: u8, hard: &HardState, floor: (u64, u64)) {
        self.set(agent, NodeRow::VoteFloor, encode_position(floor.0, floor.1));
        let Some(rows) = self.checked(self.store.agent_rows(agent)) else {
            return;
        };
        self.truncate(agent, rows.log_start);
        for row in [
            NodeRow::Applied,
            NodeRow::LogStart,
            NodeRow::Membership,
            NodeRow::LastResult,
        ] {
            self.batch.remove(self.store.system(), node_row(agent, row));
        }
        self.hard_state(agent, hard);
        self.epoch(agent, epoch);
    }

    /// The time and seed of the last work result applied to `agent`.
    pub fn last_result(&mut self, agent: AgentId, time: u64, seed: &[u8; 32]) {
        self.set(agent, NodeRow::LastResult, encode_last_result(time, seed));
    }

    /// Record the node's run, as its pair heartbeat numbers it.
    pub fn incarnation(&mut self, incarnation: u64) {
        self.batch.insert(
            self.store.system(),
            node_record(NodeRow::Incarnation, &[]),
            incarnation.to_be_bytes(),
        );
    }

    /// Record the node's secret seed.
    pub fn node_secret(&mut self, seed: &[u8; 32]) {
        self.batch
            .insert(self.store.system(), node_record(NodeRow::Secret, &[]), seed);
    }

    /// Record the seed of the node's anchor key `number`, past its first:
    /// numbered from 1, in the order they were made.
    pub fn anchor_secret(&mut self, number: u64, seed: &[u8; 32]) {
        self.batch.insert(
            self.store.system(),
            node_record(NodeRow::AnchorKey, &number.to_be_bytes()),
            seed,
        );
    }

    /// Write the prover's job of `agent`'s statement `id`, its encoding,
    /// or remove it (`None`).
    pub fn prover_job(&mut self, agent: AgentId, id: &[u8; 32], job: Option<&[u8]>) {
        let key = node_record(
            NodeRow::ProverJob,
            &[&agent.0.to_be_bytes()[..], id].concat(),
        );
        match job {
            Some(job) => self.batch.insert(self.store.system(), key, job),
            None => self.batch.remove(self.store.system(), key),
        }
    }

    /// Write the last index of `agent`'s log the prover read into jobs.
    pub fn prover_mark(&mut self, agent: AgentId, index: u64) {
        self.batch.insert(
            self.store.system(),
            node_record(NodeRow::ProverMark, &agent.0.to_be_bytes()),
            index.to_be_bytes(),
        );
    }

    /// Write the node's `row` for the agent.
    fn set(&mut self, agent: AgentId, row: NodeRow, value: impl Into<fjall::Slice>) {
        self.batch
            .insert(self.store.system(), node_row(agent, row), value);
    }

    /// What `read` read, or `None` once it failed: the batch then commits
    /// nothing.
    fn checked<T>(&mut self, read: Result<T>) -> Option<T> {
        read.map_err(|error| {
            self.error.get_or_insert(error);
        })
        .ok()
    }

    /// Commit the batch, returning once `mode` holds of it: handed to the
    /// operating system (`Buffer`), which survives a process crash but not
    /// a power loss, or synced to the disk.
    pub fn commit(self, mode: PersistMode) -> Result<()> {
        if let Some(error) = self.error {
            return Err(error);
        }
        // fjall skips an empty batch, sync and all: a synced commit of
        // nothing still syncs what came before it.
        if self.batch.is_empty() {
            if mode != PersistMode::Buffer {
                self.store.database().persist(mode)?;
            }
            return Ok(());
        }
        self.batch.durability(Some(mode)).commit()
    }
}
