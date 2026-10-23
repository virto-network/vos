//! The node log writer. It owns every commit: it takes all the commits
//! queued, writes them in one batch and syncs once when any change in them
//! must be synced, so agents committing together share one fsync. A leader
//! waits on its commit, which is the node's backpressure.
//!
//! Each change says whether it must be synced: appends, truncation, a term
//! or vote, membership and node records are; a commit-index move, an apply
//! and a compaction are not. A synced flush makes every earlier batch
//! durable too, as they share one journal: the writer records, per synced
//! flush, each agent's highest applied index up to it, and only that bounds
//! compaction, so the log on disk never starts past the applied index on
//! disk.
//!
//! A flush that fails leaves the disk unknown: some of it may have been
//! written, and synced or not. The writer then takes no more, and the node
//! halts until a restart reads what is there.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use vos_wire::ids::AgentId;
use vos_wire::peer::{CreationRecord, Placement};
use vos_wire::result::Write;

use crate::store::{Fjall, HardState, LogEntry, Membership, Row, Switch};
use crate::{Hooks, lock, raise};

/// How long the oldest pending commit may wait before the writer counts as
/// stalled, for a writer spawned without a node's config: the default
/// election timeout's upper end, as a node's own bound defaults to its.
pub(crate) const STALL_AFTER: Duration = Duration::from_secs(3);

/// The most bytes of entries and writes one flush takes, once it has any:
/// a guard, so one large commit cannot hold back every agent for long.
const FLUSH_CAP: usize = 8 << 20;

/// One change in a commit.
pub enum Change {
    /// A log entry appended at `index`.
    Append {
        agent: AgentId,
        index: u64,
        entry: LogEntry,
    },
    /// The log after `after` removed.
    Truncate {
        agent: AgentId,
        after: u64,
    },
    /// The log through `through`, at `term`, removed; `membership` was in
    /// effect there, when known.
    Compact {
        agent: AgentId,
        through: u64,
        term: u64,
        membership: Option<Membership>,
    },
    /// The term, vote and commit index; `sync` when the term or vote moved.
    Hard {
        agent: AgentId,
        hard: HardState,
        sync: bool,
    },
    Membership {
        agent: AgentId,
        membership: Membership,
    },
    /// A work result's writes applied at `index`, to the agent's rows
    /// under `epoch`: refused if that is no longer its epoch, or `index` is
    /// not past its applied index (an apply that raced a snapshot switch).
    Apply {
        agent: AgentId,
        epoch: u8,
        index: u64,
        writes: Vec<Write>,
    },
    /// A snapshot's rows written under `epoch`, beside the current one.
    /// The first chunk of an install says so, and is refused if the epoch
    /// still holds rows: an earlier install's, not yet cleared.
    Stage {
        agent: AgentId,
        epoch: u8,
        first: bool,
        rows: Vec<Row>,
    },
    /// Up to `limit` of the agent's rows under an old `epoch` removed.
    DropEpoch {
        agent: AgentId,
        epoch: u8,
        limit: usize,
    },
    /// The agent switched to the snapshot staged under `switch.epoch`.
    Switch {
        agent: AgentId,
        switch: Switch,
    },
    /// `agent` keeps the blob `hash`, a program it runs.
    Pin {
        hash: [u8; 32],
        agent: AgentId,
    },
    Unpin {
        hash: [u8; 32],
        agent: AgentId,
    },
    /// Nothing, synced: everything committed before it is durable once it
    /// is answered.
    Barrier,
    /// An agent's creation, as this node learned of it.
    Agent(CreationRecord),
    /// Where an agent runs, as this node last heard.
    Placement {
        agent: AgentId,
        placement: Placement,
    },
    /// The agent retired from this node: see [`crate::store::Batch::retire`].
    Retire {
        agent: AgentId,
        epoch: u8,
        hard: HardState,
        floor: (u64, u64),
    },
    /// The time and seed of the work result applied in the same commit.
    LastResult {
        agent: AgentId,
        time: u64,
        seed: [u8; 32],
    },
    /// A root build's batch of rows, written to the agent's rows under
    /// `epoch`: refused if that is no longer its epoch, so a build never
    /// lands in a snapshot installed or a retirement made meanwhile.
    Tree {
        agent: AgentId,
        epoch: u8,
        writes: Vec<Write>,
    },
    /// The seed of the node's anchor key `number`: see
    /// [`crate::store::Batch::anchor_secret`].
    AnchorKey {
        number: u64,
        seed: [u8; 32],
    },
}

impl Change {
    /// Whether the change must be on the disk before its commit is answered.
    fn synced(&self) -> bool {
        match self {
            Self::Apply { .. }
            | Self::Tree { .. }
            | Self::LastResult { .. }
            | Self::Compact { .. }
            | Self::Stage { .. }
            | Self::DropEpoch { .. } => false,
            Self::Hard { sync, .. } => *sync,
            Self::Append { .. }
            | Self::Truncate { .. }
            | Self::Membership { .. }
            | Self::Switch { .. }
            | Self::Pin { .. }
            | Self::Unpin { .. }
            | Self::Barrier
            | Self::Agent(_)
            | Self::Placement { .. }
            | Self::Retire { .. }
            | Self::AnchorKey { .. } => true,
        }
    }

    fn bytes(&self) -> usize {
        match self {
            Self::Append { entry, .. } => entry.body.len() + 64,
            Self::Apply { writes, .. } | Self::Tree { writes, .. } => writes
                .iter()
                .map(|write| write.key.len() + write.value.as_ref().map_or(0, Vec::len))
                .sum(),
            Self::Stage { rows, .. } => rows
                .iter()
                .map(|(key, value)| key.len() + value.len())
                .sum(),
            _ => 64,
        }
    }
}

struct Commit {
    id: u64,
    changes: Vec<Change>,
    done: smol::channel::Sender<Result<(), String>>,
}

/// What the writer shares with the node.
#[derive(Default)]
struct Shared {
    /// Each agent's highest applied index that a synced flush made durable.
    durably_applied: Mutex<HashMap<AgentId, u64>>,
    /// Commits queued or in flight, by id, with when they were queued.
    pending: Mutex<BTreeMap<u64, Instant>>,
    /// How long each synced flush took, written and synced, and each
    /// buffered one, written.
    flush_synced: crate::stats::Histogram,
    flush_buffered: crate::stats::Histogram,
    /// How many commits each flush took.
    flush_commits: crate::stats::Histogram,
    /// How long each commit waited in the queue before its flush began.
    commit_queue: crate::stats::Histogram,
    /// Whether a flush failed: the writer takes no more.
    failed: AtomicBool,
    /// Agents whose committed writes, or an installed snapshot, left dirty
    /// rows since their root builder last looked.
    dirtied: Mutex<HashSet<AgentId>>,
}

pub struct StorageThread {
    sender: Option<mpsc::Sender<Commit>>,
    thread: Option<JoinHandle<()>>,
    shared: Arc<Shared>,
    next: AtomicU64,
    stall_after: Duration,
}

impl StorageThread {
    pub fn spawn(store: Fjall, hooks: Arc<dyn Hooks>) -> Self {
        Self::spawn_with(store, hooks, STALL_AFTER)
    }

    /// A writer counted as stalled once its oldest pending commit waited
    /// `stall_after`.
    pub(crate) fn spawn_with(store: Fjall, hooks: Arc<dyn Hooks>, stall_after: Duration) -> Self {
        let (sender, receiver) = mpsc::channel::<Commit>();
        let shared = Arc::new(Shared::default());
        let mut writer = Writer::new(store, hooks, Arc::clone(&shared));
        let thread = std::thread::Builder::new()
            .name("vos-storage".into())
            .spawn(move || {
                let mut queued: Option<Commit> = None;
                loop {
                    let first = match queued.take() {
                        Some(commit) => commit,
                        None => match receiver.recv() {
                            Ok(commit) => commit,
                            Err(_) => return,
                        },
                    };
                    let mut bytes = first.changes.iter().map(Change::bytes).sum::<usize>();
                    let mut group = vec![first];
                    while let Ok(commit) = receiver.try_recv() {
                        let size = commit.changes.iter().map(Change::bytes).sum::<usize>();
                        if bytes + size > FLUSH_CAP {
                            queued = Some(commit);
                            break;
                        }
                        bytes += size;
                        group.push(commit);
                    }
                    writer.write(group);
                }
            })
            .expect("the storage thread starts");
        Self {
            sender: Some(sender),
            thread: Some(thread),
            shared,
            next: AtomicU64::new(0),
            stall_after,
        }
    }

    /// Commit `changes`, with whatever else is queued: answered once
    /// written, and synced first when any change must be.
    pub async fn commit(&self, changes: Vec<Change>) -> Result<(), String> {
        let (done, wait) = smol::channel::bounded(1);
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        lock(&self.shared.pending).insert(id, Instant::now());
        let commit = Commit { id, changes, done };
        if let Err(error) = self
            .sender
            .as_ref()
            .expect("the storage thread runs")
            .send(commit)
        {
            lock(&self.shared.pending).remove(&error.0.id);
            return Err("the storage thread stopped".to_string());
        }
        wait.recv()
            .await
            .map_err(|_| "the storage thread stopped".to_string())?
    }

    /// `agent` recovered with `applied` as its applied index, before any of
    /// its commits: the store synced what it recovered, so that is durable.
    pub fn recovered(&self, agent: AgentId, applied: u64) {
        raise(&mut lock(&self.shared.durably_applied), agent, applied);
    }

    /// Whether `agent`'s commits left dirty rows since this was last asked.
    pub(crate) fn take_dirtied(&self, agent: AgentId) -> bool {
        lock(&self.shared.dirtied).remove(&agent)
    }

    /// `agent`'s highest applied index a synced flush made durable.
    pub fn durably_applied(&self, agent: AgentId) -> u64 {
        lock(&self.shared.durably_applied)
            .get(&agent)
            .copied()
            .unwrap_or(0)
    }

    /// Its flushes' times and sizes, as stages.
    pub(crate) fn stages(&self) -> Vec<vos_wire::ingress::Stage> {
        vec![
            crate::stats::stage("flush_synced", &self.shared.flush_synced),
            crate::stats::stage("flush_buffered", &self.shared.flush_buffered),
            crate::stats::stage("flush_commits", &self.shared.flush_commits),
            crate::stats::stage("commit_queue", &self.shared.commit_queue),
        ]
    }

    /// Whether a flush failed: every commit since is refused, and the node
    /// must halt.
    pub(crate) fn failed(&self) -> bool {
        self.shared.failed.load(Ordering::SeqCst)
    }

    /// Whether a commit has waited longer than the stall bound.
    pub(crate) fn stalled(&self) -> bool {
        lock(&self.shared.pending)
            .values()
            .next()
            .is_some_and(|queued| queued.elapsed() > self.stall_after)
    }
}

impl Drop for StorageThread {
    fn drop(&mut self) {
        self.sender.take();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

mod writer;
use writer::Writer;

#[cfg(test)]
mod tests;
