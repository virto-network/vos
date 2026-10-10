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
//! compaction (section 9.5, invariant 4).

use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use vos_wire::ids::{AgentId, ProgramHash, SessionId};
use vos_wire::result::Write;

use crate::Hooks;
use crate::store::{Batch, Durability, Fjall, HardState, LogEntry, Membership, Store};

/// How long the oldest pending commit may wait before the writer counts as
/// stalled.
pub const STALL_AFTER: Duration = Duration::from_secs(1);

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
    /// A work result's writes applied at `index`.
    Apply {
        agent: AgentId,
        index: u64,
        writes: Vec<Write>,
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
    Agent {
        agent: AgentId,
        program: ProgramHash,
    },
    /// A client session opened for `key` at its `time`.
    Session {
        id: SessionId,
        key: [u8; 32],
        time: u64,
    },
    ForgetSession(SessionId),
}

impl Change {
    /// Whether the change must be on the disk before its commit is answered.
    fn synced(&self) -> bool {
        match self {
            Self::Apply { .. } | Self::Compact { .. } => false,
            Self::Hard { sync, .. } => *sync,
            _ => true,
        }
    }

    fn bytes(&self) -> usize {
        match self {
            Self::Append { entry, .. } => entry.body.len() + 64,
            Self::Apply { writes, .. } => writes
                .iter()
                .map(|write| write.key.len() + write.value.as_ref().map_or(0, Vec::len))
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
}

pub struct StorageThread {
    sender: Option<mpsc::Sender<Commit>>,
    thread: Option<JoinHandle<()>>,
    shared: Arc<Shared>,
    next: AtomicU64,
    stall_after: Duration,
}

/// The writer's loop: one group of commits at a time.
struct Writer {
    store: Fjall,
    hooks: Arc<dyn Hooks>,
    shared: Arc<Shared>,
    /// Applies written since the last synced flush, per agent.
    unsynced_applied: HashMap<AgentId, u64>,
}

impl Writer {
    /// Why a commit must be refused, before any of it is written. Only a
    /// compaction is refused, and with it its whole commit: keep
    /// compactions in commits of their own.
    fn refusal(&self, commit: &Commit) -> Option<String> {
        let durable = self.shared.durably_applied.lock().expect("unpoisoned");
        commit.changes.iter().find_map(|change| match change {
            Change::Compact { agent, through, .. }
                if *through > durable.get(agent).copied().unwrap_or(0) =>
            {
                Some(format!(
                    "compaction of agent {} through {through} passes its durably applied index",
                    agent.0
                ))
            }
            _ => None,
        })
    }

    fn write(&mut self, group: Vec<Commit>) {
        self.hooks.before_commit();
        let mut batch = self.store.batch();
        let mut synced = false;
        // Applies in this batch: they count only once it commits.
        let mut applied: HashMap<AgentId, u64> = HashMap::new();
        // Commits in order, each with its refusal if it has one; a refused
        // commit writes nothing, and is answered in its turn.
        let mut taken = Vec::with_capacity(group.len());
        for commit in group {
            if let Some(refusal) = self.refusal(&commit) {
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
                        index,
                        writes,
                    } => {
                        batch.apply(*agent, *index, writes);
                        let entry = applied.entry(*agent).or_insert(*index);
                        *entry = (*entry).max(*index);
                    }
                    Change::Pin { hash, agent } => batch.pin(hash, *agent),
                    Change::Unpin { hash, agent } => batch.unpin(hash, *agent),
                    Change::Barrier => {}
                    Change::Agent { agent, program } => batch.agent(*agent, program),
                    Change::Session { id, key, time } => batch.session(*id, key, *time),
                    Change::ForgetSession(id) => batch.forget_session(*id),
                }
            }
            taken.push((commit, None));
        }
        let durability = if synced {
            Durability::Synced
        } else {
            Durability::Buffered
        };
        let result = if self.hooks.fail_commit() {
            Err("a hook failed the commit".to_string())
        } else {
            batch.commit(durability).map_err(|error| error.to_string())
        };
        if result.is_ok() {
            for (agent, index) in applied {
                let entry = self.unsynced_applied.entry(agent).or_insert(index);
                *entry = (*entry).max(index);
            }
            if synced {
                // Every batch before this one shares the journal, so it is
                // durable now too.
                let mut durable = self.shared.durably_applied.lock().expect("unpoisoned");
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
        self.shared
            .pending
            .lock()
            .expect("unpoisoned")
            .remove(&commit.id);
        let _ = commit.done.try_send(result);
    }
}

impl StorageThread {
    pub fn spawn(store: Fjall, hooks: Arc<dyn Hooks>) -> Self {
        Self::spawn_with(store, hooks, STALL_AFTER)
    }

    pub fn spawn_with(store: Fjall, hooks: Arc<dyn Hooks>, stall_after: Duration) -> Self {
        let (sender, receiver) = mpsc::channel::<Commit>();
        let shared = Arc::new(Shared::default());
        let mut writer = Writer {
            store,
            hooks,
            shared: Arc::clone(&shared),
            unsynced_applied: HashMap::new(),
        };
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
        self.shared
            .pending
            .lock()
            .expect("unpoisoned")
            .insert(id, Instant::now());
        let commit = Commit { id, changes, done };
        if let Err(error) = self
            .sender
            .as_ref()
            .expect("the storage thread runs")
            .send(commit)
        {
            self.shared
                .pending
                .lock()
                .expect("unpoisoned")
                .remove(&error.0.id);
            return Err("the storage thread stopped".to_string());
        }
        wait.recv()
            .await
            .map_err(|_| "the storage thread stopped".to_string())?
    }

    /// `agent` recovered with `applied` as its applied index, before any of
    /// its commits: the store synced what it recovered, so that is durable.
    pub fn recovered(&self, agent: AgentId, applied: u64) {
        let mut durable = self.shared.durably_applied.lock().expect("unpoisoned");
        let entry = durable.entry(agent).or_insert(applied);
        *entry = (*entry).max(applied);
    }

    /// `agent`'s highest applied index a synced flush made durable.
    pub fn durably_applied(&self, agent: AgentId) -> u64 {
        self.shared
            .durably_applied
            .lock()
            .expect("unpoisoned")
            .get(&agent)
            .copied()
            .unwrap_or(0)
    }

    /// Whether a commit has waited longer than the stall bound.
    pub fn stalled(&self) -> bool {
        self.shared
            .pending
            .lock()
            .expect("unpoisoned")
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

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicBool;

    use super::*;
    use crate::NoHooks;

    const A: AgentId = AgentId(1);

    fn writer(dir: &std::path::Path) -> StorageThread {
        StorageThread::spawn(Fjall::open(dir).unwrap(), Arc::new(NoHooks))
    }

    fn apply(index: u64) -> Change {
        Change::Apply {
            agent: A,
            index,
            writes: Vec::new(),
        }
    }

    fn hard(term: u64, sync: bool) -> Change {
        Change::Hard {
            agent: A,
            hard: HardState {
                term,
                vote: None,
                commit: 0,
            },
            sync,
        }
    }

    #[test]
    fn the_durably_applied_index_moves_only_with_a_synced_flush() {
        let dir = tempfile::tempdir().unwrap();
        let writer = writer(dir.path());
        smol::block_on(writer.commit(vec![apply(5)])).unwrap();
        smol::block_on(writer.commit(vec![hard(1, false)])).unwrap();
        assert_eq!(
            writer.durably_applied(A),
            0,
            "buffered writes are not durable"
        );
        smol::block_on(writer.commit(vec![hard(2, true)])).unwrap();
        assert_eq!(
            writer.durably_applied(A),
            5,
            "a synced flush covers what came before"
        );
        writer.recovered(AgentId(2), 9);
        assert_eq!(writer.durably_applied(AgentId(2)), 9);
    }

    /// Fails the next commit, as a store fault would, then lets the rest
    /// through.
    struct FailOnce(AtomicBool);

    impl Hooks for FailOnce {
        fn fail_commit(&self) -> bool {
            self.0.swap(false, Ordering::Relaxed)
        }
    }

    #[test]
    fn applies_of_a_failed_batch_never_count_as_durable() {
        let dir = tempfile::tempdir().unwrap();
        let writer = StorageThread::spawn(
            Fjall::open(dir.path()).unwrap(),
            Arc::new(FailOnce(AtomicBool::new(true))),
        );
        assert!(smol::block_on(writer.commit(vec![apply(5)])).is_err());
        smol::block_on(writer.commit(vec![hard(1, true)])).unwrap();
        assert_eq!(writer.durably_applied(A), 0);
    }

    #[test]
    fn compaction_past_the_durably_applied_index_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let writer = writer(dir.path());
        let compact = |through| Change::Compact {
            agent: A,
            through,
            term: 1,
            membership: None,
        };
        smol::block_on(writer.commit(vec![apply(5)])).unwrap();
        assert!(smol::block_on(writer.commit(vec![compact(3)])).is_err());
        smol::block_on(writer.commit(vec![hard(1, true)])).unwrap();
        smol::block_on(writer.commit(vec![compact(3)])).unwrap();
        assert!(smol::block_on(writer.commit(vec![compact(6)])).is_err());
    }

    /// Holds every commit until released.
    struct Hold(AtomicBool);

    impl Hooks for Hold {
        fn before_commit(&self) {
            while self.0.load(Ordering::Relaxed) {
                std::thread::sleep(Duration::from_millis(1));
            }
        }
    }

    #[test]
    fn a_held_writer_reports_a_stall_until_it_drains() {
        let dir = tempfile::tempdir().unwrap();
        let hold = Arc::new(Hold(AtomicBool::new(true)));
        let writer = Arc::new(StorageThread::spawn_with(
            Fjall::open(dir.path()).unwrap(),
            Arc::clone(&hold) as Arc<dyn Hooks>,
            Duration::from_millis(50),
        ));
        assert!(!writer.stalled());
        let pending = {
            let writer = Arc::clone(&writer);
            std::thread::spawn(move || smol::block_on(writer.commit(vec![hard(1, true)])))
        };
        std::thread::sleep(Duration::from_millis(100));
        assert!(writer.stalled());
        hold.0.store(false, Ordering::Relaxed);
        pending.join().unwrap().unwrap();
        assert!(!writer.stalled());
    }
}
