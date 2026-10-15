//! vos-raft's core over the node's store: what one agent's replica writes,
//! reads back for a peer, compacts and recovers.
//!
//! A data entry's Raft payload is the store's entry payload (its kind, its
//! blobs and its body), or empty for a new leader's no-op. A configuration
//! entry is vos-raft's own. The snapshot pointer in the core's meta is not
//! the host's: the log start moves only by compaction and a snapshot
//! switch, in their own row.
//!
//! Recovery leaves no entry without its blob ([`recovery_cut`]). An entry
//! above the commit missing its blob was never reported durable: every
//! agent shares one journal, so its row can survive a crash its blob did
//! not, and cutting it forgets nothing this replica acknowledged (a disk
//! losing what it said it wrote is outside the trust model, core model,
//! section 5). A committed entry is never cut: the replica would vote
//! without it, and with another member lacking it elect a leader lacking
//! it too. At or below the applied index the state holds its effect, so
//! the log is compacted past it rather than left ending below it.

use vos_raft::core::{Load, Recovered, SnapshotSwitch, Write};
use vos_raft::{ActiveConfigRecord, EntryKind as RaftKind, LogEntry as RaftEntry, Meta};
use vos_wire::ids::AgentId;

use crate::blobs::Blobs;
use crate::storage::Change;
use crate::store::{
    self, EntryKind, Fjall, HardState, LogEntry, Membership, NodeNumber, RaftRows, Switch,
};

/// The store's entry for a Raft entry.
pub(crate) fn to_store(entry: &RaftEntry<NodeNumber>) -> LogEntry {
    match &entry.kind {
        RaftKind::Data { payload } if payload.is_empty() => LogEntry {
            term: entry.term,
            kind: EntryKind::NoOp,
            blobs: Vec::new(),
            body: Vec::new(),
        },
        // A payload this node cannot read is kept as the body of a work
        // result, which then fails to apply: it never panics the node. A
        // data payload never becomes a membership change.
        RaftKind::Data { payload } => LogEntry::from_payload(entry.term, payload)
            .filter(|parsed| parsed.kind != EntryKind::Configuration)
            .unwrap_or_else(|| LogEntry::result(entry.term, payload.clone())),
        RaftKind::ConfigChange { joint_old, members } => LogEntry {
            term: entry.term,
            kind: EntryKind::Configuration,
            blobs: Vec::new(),
            body: store::encode_configuration(members, joint_old.as_deref()),
        },
    }
}

/// The Raft entry for the store's entry at `index`.
pub(crate) fn to_raft(index: u64, entry: &LogEntry) -> RaftEntry<NodeNumber> {
    match entry.kind {
        EntryKind::NoOp => RaftEntry::data(index, entry.term, Vec::new()),
        EntryKind::Result | EntryKind::LargeResult => {
            RaftEntry::data(index, entry.term, entry.payload())
        }
        EntryKind::Configuration => match store::decode_configuration(&entry.body) {
            Some((members, joint_old)) => {
                RaftEntry::config_change(index, entry.term, joint_old, members)
            }
            None => RaftEntry::data(index, entry.term, entry.payload()),
        },
    }
}

/// What a Raft payload weighs in its log's byte counts (vos-raft's
/// `payload_weight`): its bytes, and a large result's blob, which goes once
/// the log is compacted past the entry. A program an install names stays
/// pinned while the agent runs it, so it weighs nothing here.
pub(crate) fn payload_weight(payload: &[u8]) -> u64 {
    (payload.len() as u64).saturating_add(LogEntry::result_len(payload).unwrap_or(0))
}

/// The writer's changes for one of the core's writes, in its order:
/// truncate, append, then the hard state and membership. The meta's
/// snapshot pointer is left out.
pub(crate) fn changes(agent: AgentId, write: &Write<NodeNumber>) -> Vec<Change> {
    let mut changes = Vec::with_capacity(write.entries.len() + 3);
    if let Some(after) = write.truncate_after {
        changes.push(Change::Truncate { agent, after });
    }
    for entry in &write.entries {
        changes.push(Change::Append {
            agent,
            index: entry.index,
            entry: to_store(entry),
        });
    }
    if let Some(meta) = &write.meta {
        changes.push(Change::Hard {
            agent,
            hard: HardState {
                term: meta.current_term,
                vote: meta.voted_for,
                commit: meta.commit_index,
            },
            sync: write.sync,
        });
    }
    if let Some(record) = &write.active_config {
        changes.push(Change::Membership {
            agent,
            membership: membership(record),
        });
    }
    changes
}

/// The blobs each entry `changes` append names, by its index: none for an
/// entry that names none.
pub(crate) fn named(changes: &[Change]) -> Vec<(u64, Vec<[u8; 32]>)> {
    changes
        .iter()
        .filter_map(|change| match change {
            Change::Append { index, entry, .. } if !entry.blobs.is_empty() => {
                Some((*index, entry.blobs.iter().map(|blob| blob.hash).collect()))
            }
            _ => None,
        })
        .collect()
}

/// The entries a load asks for, within its bytes.
pub(crate) fn load(
    store: &Fjall,
    agent: AgentId,
    load: &Load,
) -> store::Result<Vec<RaftEntry<NodeNumber>>> {
    Ok(store
        .log_range(agent, load.from, load.to, load.max_bytes)?
        .iter()
        .map(|(index, entry)| to_raft(*index, entry))
        .collect())
}

/// The compaction of the log through `through`, if the log still holds it,
/// with `configuration` in effect there, when the core knows it.
pub(crate) fn compaction(
    store: &Fjall,
    agent: AgentId,
    through: u64,
    configuration: Option<&ActiveConfigRecord<NodeNumber>>,
) -> store::Result<Option<Change>> {
    Ok(store
        .log_entry(agent, through)?
        .map(|entry| Change::Compact {
            agent,
            through,
            term: entry.term,
            membership: configuration.map(membership),
        }))
}

fn membership(record: &ActiveConfigRecord<NodeNumber>) -> Membership {
    Membership {
        index: record.log_index,
        members: record.current.clone(),
        joint_old: record.joint_old.clone(),
    }
}

fn record(membership: Membership) -> ActiveConfigRecord<NodeNumber> {
    ActiveConfigRecord {
        log_index: membership.index,
        current: membership.members,
        joint_old: membership.joint_old,
    }
}

/// The writer's switch to a snapshot staged under `epoch`, at `index` and
/// `term`, with the rows vos-raft's core computed for it: one synced batch.
pub(crate) fn switch_change(
    agent: AgentId,
    epoch: u8,
    index: u64,
    term: u64,
    switch: &SnapshotSwitch<NodeNumber>,
) -> Change {
    Change::Switch {
        agent,
        switch: Switch {
            epoch,
            index,
            term,
            hard: HardState {
                term: switch.meta.current_term,
                vote: switch.meta.voted_for,
                commit: switch.meta.commit_index,
            },
            membership: membership(&switch.active_config),
            log_start_membership: switch.log_start_config.as_ref().map(membership),
            truncate_after: switch.truncate_after,
        },
    }
}

/// What recovery must do to `agent`'s log so that no entry is left
/// without its blob, before its core is recovered and once the writer knows
/// its applied index: above the commit it recovers (its persisted commit,
/// or its applied index if higher), the log is cut at the first entry
/// missing a blob; a committed entry past the applied index stays, its
/// blobs to fetch again; at or below the applied index, the log is
/// compacted through it instead, with the membership in effect there.
pub fn recovery_cut(store: &Fjall, blobs: &Blobs, agent: AgentId) -> store::Result<Cut> {
    let rows = store.raft(agent)?;
    let missing = |entry: &LogEntry| -> store::Result<Vec<[u8; 32]>> {
        let mut missing = Vec::new();
        for blob in &entry.blobs {
            if !blobs.contains(&blob.hash)? {
                missing.push(blob.hash);
            }
        }
        Ok(missing)
    };
    let committed = rows.hard.commit.max(rows.applied);
    let mut cut = Cut::default();
    let mut applied_lost = false;
    for (index, entry) in &rows.log {
        let lost = missing(entry)?;
        if lost.is_empty() {
            continue;
        }
        if *index <= rows.applied {
            applied_lost = true;
        } else if *index <= committed {
            cut.refetch.push((*index, lost));
        } else {
            cut.changes.push(Change::Truncate {
                agent,
                after: index - 1,
            });
            cut.from = Some(*index);
            break;
        }
    }
    if applied_lost
        && let Some((_, at_applied)) = rows.log.iter().find(|(index, _)| *index == rows.applied)
    {
        let membership = rows
            .log
            .iter()
            .rev()
            .filter(|(index, entry)| {
                *index <= rows.applied && entry.kind == EntryKind::Configuration
            })
            .find_map(|(index, entry)| {
                let (members, joint_old) = store::decode_configuration(&entry.body)?;
                Some(Membership {
                    index: Some(*index),
                    members,
                    joint_old,
                })
            })
            .or(rows.log_start_membership.clone());
        cut.changes.insert(
            0,
            Change::Compact {
                agent,
                through: rows.applied,
                term: at_applied.term,
                membership,
            },
        );
    }
    Ok(cut)
}

/// Recovery's changes to one agent's log ([`recovery_cut`]).
#[derive(Default)]
pub struct Cut {
    pub changes: Vec<Change>,
    /// The index the log is cut from, if it is.
    pub from: Option<u64>,
    /// The committed entries past the applied index kept without their
    /// blobs, by index, with the blobs to fetch again.
    pub refetch: Vec<(u64, Vec<[u8; 32]>)>,
}

/// What the core recovers from the store's rows.
pub(crate) fn recovered(rows: RaftRows) -> Recovered<NodeNumber> {
    Recovered {
        meta: Meta {
            current_term: rows.hard.term,
            voted_for: rows.hard.vote,
            commit_index: rows.hard.commit,
            snap_last_index: rows.log_start.0,
            snap_last_term: rows.log_start.1,
        },
        entries: rows
            .log
            .iter()
            .map(|(index, entry)| to_raft(*index, entry))
            .collect(),
        active_config: rows.membership.map(record),
        log_start_config: rows.log_start_membership.map(record),
        applied: rows.applied,
        vote_floor: rows.vote_floor,
    }
}

mod reports;
pub(crate) use reports::{EntryReports, RECOVERED};

#[cfg(test)]
mod tests;
