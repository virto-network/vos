//! The storage thread. It owns every commit: it takes all the commits
//! queued, writes them in one batch and syncs once, so agents committing
//! together share one fsync. A leader waits on its commit, which is the
//! node's backpressure.

use std::sync::Arc;
use std::sync::mpsc;
use std::thread::JoinHandle;

use vos_wire::ids::{AgentId, ProgramHash, SessionId};
use vos_wire::result::Write;

use crate::Hooks;
use crate::store::{Batch, Durability, Fjall, LogEntry, Store};

/// One change in a commit.
pub(crate) enum Change {
    /// A work result appended at `index` and its writes applied.
    Log {
        agent: AgentId,
        index: u64,
        entry: LogEntry,
        writes: Vec<Write>,
    },
    Program {
        hash: ProgramHash,
        blob: Vec<u8>,
    },
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

struct Commit {
    changes: Vec<Change>,
    done: smol::channel::Sender<Result<(), String>>,
}

pub(crate) struct StorageThread {
    sender: Option<mpsc::Sender<Commit>>,
    thread: Option<JoinHandle<()>>,
}

impl StorageThread {
    pub(crate) fn spawn(store: Fjall, hooks: Arc<dyn Hooks>) -> Self {
        let (sender, receiver) = mpsc::channel::<Commit>();
        let thread = std::thread::Builder::new()
            .name("vos-storage".into())
            .spawn(move || {
                while let Ok(first) = receiver.recv() {
                    let group: Vec<Commit> =
                        std::iter::once(first).chain(receiver.try_iter()).collect();
                    hooks.before_commit();
                    let mut batch = store.batch();
                    for commit in &group {
                        for change in &commit.changes {
                            match change {
                                Change::Log {
                                    agent,
                                    index,
                                    entry,
                                    writes,
                                } => {
                                    batch.append(*agent, *index, entry);
                                    batch.apply(*agent, *index, writes);
                                }
                                Change::Program { hash, blob } => batch.program(hash, blob),
                                Change::Agent { agent, program } => batch.agent(*agent, program),
                                Change::Session { id, key, time } => batch.session(*id, key, *time),
                                Change::ForgetSession(id) => batch.forget_session(*id),
                            }
                        }
                    }
                    let result = if hooks.fail_commit() {
                        Err("a hook failed the commit".to_string())
                    } else {
                        batch
                            .commit(Durability::Synced)
                            .map_err(|error| error.to_string())
                    };
                    for commit in group {
                        let _ = commit.done.try_send(result.clone());
                    }
                }
            })
            .expect("the storage thread starts");
        Self {
            sender: Some(sender),
            thread: Some(thread),
        }
    }

    /// Commit `changes`, durably, with whatever else is queued.
    pub(crate) async fn commit(&self, changes: Vec<Change>) -> Result<(), String> {
        let (done, wait) = smol::channel::bounded(1);
        let commit = Commit { changes, done };
        self.sender
            .as_ref()
            .expect("the storage thread runs")
            .send(commit)
            .map_err(|_| "the storage thread stopped".to_string())?;
        wait.recv()
            .await
            .map_err(|_| "the storage thread stopped".to_string())?
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
