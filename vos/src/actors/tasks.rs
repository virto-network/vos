//! `vos::agent::Tasks` — parent-managed children.
//!
//! One embeddable rkyv field generalizing the scheduler pattern into
//! the framework: the parent owns every child's state as data in its
//! own actor state, so committing the parent commits everything —
//! children have nothing of their own to lose. A suspended task IS its
//! [`TaskRecord`]; resume is a cold re-invocation with the saved state.
//!
//! One [`Child`] abstraction, two variants — and a decision rule: a
//! child needing its own consistency tier, its own ACL/role surface,
//! external addressability, or an independent upgrade lifecycle is a
//! [`Child::Peer`]. Everything else — computation, long-running jobs,
//! provable checkers — is a [`Child::Task`].
//!
//! Concurrency = parent-level task interleaving via [`Tasks::drive`],
//! not intra-handler concurrent asks: each drive pass re-invokes every
//! runnable child once, synchronously (JAM refine is single-threaded
//! per work item, so intra-handler concurrency buys nothing on the
//! target platform).
//!
//! Failures are explicit, not policy: a failed task keeps its record
//! and status so the parent can [`inspect`](Tasks::status),
//! [`retry`](Tasks::retry), or [`cancel`](Tasks::cancel) — the silent
//! drop / resend-forever of the original scheduler example is exactly
//! what this API refuses to build in.

use alloc::vec::Vec;

/// Identity of a child a parent can spawn and drive.
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub enum Child {
    /// An anonymous pure blob invoked by its 32-byte code hash — the
    /// primary, JAM-aligned shape. No ServiceId, no storage row, no
    /// address: state lives in the parent's [`TaskRecord`], input is
    /// witness-delivered, and effects fold into the parent's keyspace.
    Task([u8; 32]),
    /// A registry agent with its own ServiceId, commit strategy, and
    /// ACL/role surface, driven by asks over the invoke channel.
    Peer(u32),
}

/// Where a task is in its lifecycle. Wire-stable discriminants.
#[repr(u8)]
#[derive(
    rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Debug, Clone, Copy, PartialEq, Eq,
)]
pub enum TaskStatus {
    /// Spawned (or retried) and not yet driven.
    Idle = 0,
    /// The child yielded — runnable again on the next drive pass.
    Yielded = 1,
    /// The child completed; [`Tasks::reply`] holds its final reply.
    Done = 2,
    /// The child trapped. Kept for inspection/retry, never re-driven
    /// implicitly.
    Panicked = 3,
    /// No blob/service answered to the child's identity.
    NotFound = 4,
    /// The child exhausted its gas budget.
    OutOfGas = 5,
    /// The child's reply exceeded the invoke output buffer.
    TooBig = 6,
}

impl TaskStatus {
    /// Will the next [`Tasks::drive`] pass re-invoke this task?
    pub fn is_runnable(self) -> bool {
        matches!(self, TaskStatus::Idle | TaskStatus::Yielded)
    }

    /// Terminal failure — eligible for [`Tasks::retry`].
    pub fn is_failed(self) -> bool {
        matches!(
            self,
            TaskStatus::Panicked | TaskStatus::NotFound | TaskStatus::OutOfGas | TaskStatus::TooBig
        )
    }
}

/// A suspended (or finished) task as a value: everything needed to
/// resume it lives here, serialized inside the parent's actor state.
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Debug, Clone, PartialEq)]
pub struct TaskRecord {
    pub child: Child,
    /// The child's serialized state as of its last work-result —
    /// authoritative and complete (the runtime echoes the input state
    /// when a child leaves it unchanged, so this never silently
    /// empties).
    pub state: Vec<u8>,
    /// The message the child is being driven with; re-delivered on
    /// every drive pass until the child completes.
    pub msg: Vec<u8>,
    pub status: TaskStatus,
    /// Reply bytes from the child's most recent work-result.
    pub reply: Vec<u8>,
    /// Storage row keys the child's witnessed reads need — resolved by
    /// the host against THIS parent's effective keyspace on every
    /// drive pass and staged into the child's witness buffer (see
    /// `lifecycle::invoke_hash_with_rows`). Empty for children that
    /// read no storage.
    pub row_keys: Vec<Vec<u8>>,
}

impl TaskRecord {
    /// Run one drive pass for this record: invoke the child with the
    /// saved `(state, msg)` and fold the outcome back in.
    #[cfg(feature = "pvm")]
    fn apply_drive_outcome(&mut self) {
        use super::lifecycle::{InvokeResult, invoke_hash_with_rows};
        use super::run::service_code_hash;

        let code_hash = match self.child {
            Child::Task(hash) => hash,
            Child::Peer(service_id) => service_code_hash(service_id),
        };
        let keys: Vec<&[u8]> = self.row_keys.iter().map(|k| k.as_slice()).collect();
        match invoke_hash_with_rows(&code_hash, &self.msg, &self.state, &keys) {
            InvokeResult::Done { state, reply } => {
                // An empty state envelope means the child ran with no
                // state delivery path at all (short error-shape
                // envelope) — keep what we had rather than wipe it.
                if !state.is_empty() {
                    self.state = state;
                }
                self.reply = reply;
                self.status = TaskStatus::Done;
            }
            InvokeResult::Yielded { state, reply } => {
                if !state.is_empty() {
                    self.state = state;
                }
                self.reply = reply;
                self.status = TaskStatus::Yielded;
            }
            InvokeResult::Panicked | InvokeResult::Error(_) => {
                self.status = TaskStatus::Panicked;
            }
            InvokeResult::NotFound => self.status = TaskStatus::NotFound,
            InvokeResult::OutOfGas => self.status = TaskStatus::OutOfGas,
            InvokeResult::TooBig => self.status = TaskStatus::TooBig,
        }
    }

    #[cfg(not(feature = "pvm"))]
    fn apply_drive_outcome(&mut self) {
        self.status = TaskStatus::NotFound;
    }
}

/// The parent's task table. Embed as an rkyv field of the parent
/// actor; spawn from handlers, drive from a tick handler.
#[derive(
    rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Debug, Clone, Default, PartialEq,
)]
pub struct Tasks {
    next_id: u64,
    records: Vec<(u64, TaskRecord)>,
}

/// Handle to a spawned task within its parent's [`Tasks`] table.
pub type TaskId = u64;

impl Tasks {
    pub fn new() -> Self {
        Self::default()
    }

    /// Queue a child with a dynamic message ([`TAG_DYNAMIC`]-framed, as
    /// [`crate::lifecycle::invoke`] would send it). Runs on the next
    /// [`drive`](Self::drive) pass.
    pub fn spawn(&mut self, child: Child, msg: &super::value::Msg) -> TaskId {
        let encoded = super::codec::Encode::encode(msg);
        let mut payload = Vec::with_capacity(1 + encoded.len());
        payload.push(super::value::TAG_DYNAMIC);
        payload.extend_from_slice(&encoded);
        self.spawn_raw(child, payload)
    }

    /// Queue a child with pre-encoded message bytes.
    pub fn spawn_raw(&mut self, child: Child, msg: Vec<u8>) -> TaskId {
        self.spawn_raw_with_rows(child, msg, Vec::new())
    }

    /// Queue a child that additionally names the storage row keys its
    /// witnessed reads need — the parent decides what the child may
    /// see of its keyspace.
    pub fn spawn_raw_with_rows(
        &mut self,
        child: Child,
        msg: Vec<u8>,
        row_keys: Vec<Vec<u8>>,
    ) -> TaskId {
        let id = self.next_id;
        self.next_id += 1;
        self.records.push((
            id,
            TaskRecord {
                child,
                state: Vec::new(),
                msg,
                status: TaskStatus::Idle,
                reply: Vec::new(),
                row_keys,
            },
        ));
        id
    }

    /// Re-invoke every runnable task once with its saved state, fold
    /// the results back into the records, and return how many tasks
    /// remain runnable — the parent's cue to schedule another drive
    /// pass (e.g. a self-`tick`). Outcomes surface distinctly per
    /// record; failed tasks stay put until the parent retries or
    /// cancels them.
    ///
    /// Children run over the PVM INVOKE channel; on non-PVM builds
    /// (host rlib compilation of actor crates) there is nothing to
    /// invoke into and every runnable record resolves `NotFound`.
    pub fn drive(&mut self) -> usize {
        for (_, record) in &mut self.records {
            if !record.status.is_runnable() {
                continue;
            }
            record.apply_drive_outcome();
        }
        self.pending()
    }

    /// Number of tasks the next [`drive`](Self::drive) pass would run.
    pub fn pending(&self) -> usize {
        self.records
            .iter()
            .filter(|(_, r)| r.status.is_runnable())
            .count()
    }

    pub fn status(&self, id: TaskId) -> Option<TaskStatus> {
        self.get(id).map(|r| r.status)
    }

    /// The task's most recent reply bytes.
    pub fn reply(&self, id: TaskId) -> Option<&[u8]> {
        self.get(id).map(|r| r.reply.as_slice())
    }

    /// Full record inspection.
    pub fn get(&self, id: TaskId) -> Option<&TaskRecord> {
        self.records.iter().find(|(i, _)| *i == id).map(|(_, r)| r)
    }

    /// Re-queue a failed task with its saved `(state, msg)` — the
    /// explicit retry the drive pass never does implicitly. `false`
    /// when the task doesn't exist or hasn't failed.
    pub fn retry(&mut self, id: TaskId) -> bool {
        match self.records.iter_mut().find(|(i, _)| *i == id) {
            Some((_, r)) if r.status.is_failed() => {
                r.status = TaskStatus::Idle;
                true
            }
            _ => false,
        }
    }

    /// Drop a task's record entirely. `false` when the id is unknown.
    pub fn cancel(&mut self, id: TaskId) -> bool {
        let before = self.records.len();
        self.records.retain(|(i, _)| *i != id);
        self.records.len() != before
    }

    /// Iterate all records (inspection / bookkeeping).
    pub fn iter(&self) -> impl Iterator<Item = (TaskId, &TaskRecord)> {
        self.records.iter().map(|(id, r)| (*id, r))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spawn_status_retry_cancel_lifecycle() {
        let mut tasks = Tasks::new();
        let a = tasks.spawn_raw(Child::Task([1u8; 32]), b"m".to_vec());
        let b = tasks.spawn_raw(Child::Peer(7), b"n".to_vec());
        assert_ne!(a, b);
        assert_eq!(tasks.status(a), Some(TaskStatus::Idle));
        assert_eq!(tasks.pending(), 2);

        // Only failed tasks are retryable.
        assert!(!tasks.retry(a), "an Idle task is not retryable");

        // Simulate a drive outcome and retry it.
        tasks.records[0].1.status = TaskStatus::Panicked;
        assert_eq!(tasks.pending(), 1);
        assert!(tasks.retry(a));
        assert_eq!(tasks.status(a), Some(TaskStatus::Idle));

        assert!(tasks.cancel(b));
        assert!(!tasks.cancel(b), "double-cancel is a no-op");
        assert_eq!(tasks.pending(), 1);
    }

    #[test]
    fn records_roundtrip_through_rkyv() {
        // The whole point: a Tasks table embeds in the parent's actor
        // state, so it must survive the state codec.
        use super::super::codec::{Decode, Encode};
        let mut tasks = Tasks::new();
        let id = tasks.spawn_raw(Child::Task([9u8; 32]), b"work".to_vec());
        tasks.records[0].1.state = b"mid-state".to_vec();
        tasks.records[0].1.status = TaskStatus::Yielded;

        let bytes = tasks.encode();
        let back = Tasks::decode(&bytes);
        assert_eq!(back, tasks);
        assert_eq!(back.status(id), Some(TaskStatus::Yielded));
        assert_eq!(back.get(id).unwrap().state, b"mid-state");
    }
}
