//! `JobQueue` — a minimal in-actor async-job registry.
//!
//! A `#[msg(job)]` handler *begins* a long-running job: it returns a
//! `u64` job id and does the work off the request path (a worker thread,
//! a per-tick advance, …). The client then polls the reserved
//! `job_poll(job_id) -> Vec<u8>` method until `done`, and finally calls
//! `job_release(job_id) -> u8`. `JobQueue` is the state helper an actor
//! embeds to back all three: it hands out monotonic ids, accumulates each
//! job's output, tracks terminal state + error, and drains output on poll.
//!
//! `job_poll` replies with the conventional wire shape — a
//! [`crate::value::Args`] carrying `data: Bytes`, `done: bool`,
//! `error: Str` — built by [`JobQueue::poll_reply`]. The dispatcher's
//! generic job driver decodes exactly that.
//!
//! Feature-light on purpose: `core` + `alloc` + `rkyv` only, so it
//! compiles under an extension's `default-features = false,
//! features = ["extension"]` (no_std) build as well as host/PVM/wasm.
//! Job ids are a plain monotonic `u64` — actor state is single-threaded
//! and rkyv-serialized, so no atomics or clock are needed.

use alloc::string::String;
use alloc::vec::Vec;

use crate::value::Args;

/// One tracked job.
#[derive(
    rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq, Eq, Default,
)]
#[rkyv(crate = rkyv)]
pub struct Job {
    /// Monotonic id handed out by [`JobQueue::begin`].
    pub id: u64,
    /// Output bytes accumulated by the worker; drained on each poll.
    pub chunks: Vec<u8>,
    /// Set once the job reaches a terminal state (finish or fail).
    pub done: bool,
    /// Non-empty on failure — the failure message.
    pub error: String,
    /// Set by [`JobQueue::release`]; pruned lazily by [`JobQueue::prune`].
    pub released: bool,
}

/// A monotonic-id job registry an actor embeds to back `#[msg(job)]`
/// handlers plus the reserved `job_poll` / `job_release` methods.
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, Default)]
#[rkyv(crate = rkyv)]
pub struct JobQueue {
    jobs: Vec<Job>,
    next_id: u64,
}

impl JobQueue {
    /// A fresh, empty queue. Ids start at 1 (0 is reserved as the
    /// "job refused" sentinel a `#[msg(job)]` handler can return).
    pub fn new() -> Self {
        Self {
            jobs: Vec::new(),
            next_id: 1,
        }
    }

    /// Register a fresh in-flight job and return its id. The id is never
    /// 0 (which callers use as "refused"), even across a `u64` wrap.
    pub fn begin(&mut self) -> u64 {
        let id = if self.next_id == 0 { 1 } else { self.next_id };
        self.next_id = id.wrapping_add(1);
        self.jobs.push(Job {
            id,
            chunks: Vec::new(),
            done: false,
            error: String::new(),
            released: false,
        });
        id
    }

    fn get_mut(&mut self, id: u64) -> Option<&mut Job> {
        self.jobs.iter_mut().find(|j| j.id == id)
    }

    /// Append output bytes to an in-flight job. No-op for an unknown or
    /// already-terminal job (a late worker write after finish is dropped).
    pub fn push(&mut self, id: u64, data: &[u8]) {
        if let Some(j) = self.get_mut(id)
            && !j.done
        {
            j.chunks.extend_from_slice(data);
        }
    }

    /// Mark a job successfully complete. Its already-pushed output stays
    /// pollable until the client drains and releases it.
    pub fn finish(&mut self, id: u64) {
        if let Some(j) = self.get_mut(id) {
            j.done = true;
        }
    }

    /// Mark a job failed with a message. Terminal, like [`Self::finish`].
    pub fn fail(&mut self, id: u64, msg: impl Into<String>) {
        if let Some(j) = self.get_mut(id) {
            j.done = true;
            j.error = msg.into();
        }
    }

    /// Drain a job's pending output. Returns `(data, done, error)`:
    /// `data` is the bytes pushed since the last poll (drained), `done`
    /// flips true at the terminal state, `error` is non-empty only on
    /// failure. A poll of an unknown / already-released id reports
    /// `done = true` with empty data and no error — benign for the driver,
    /// which only polls ids it was handed and stops at `done`.
    pub fn poll(&mut self, id: u64) -> (Vec<u8>, bool, String) {
        match self.get_mut(id) {
            Some(j) => {
                let data = core::mem::take(&mut j.chunks);
                (data, j.done, j.error.clone())
            }
            None => (Vec::new(), true, String::new()),
        }
    }

    /// The standard `job_poll` reply for `id`: an [`Args`] with
    /// `data: Bytes`, `done: bool`, `error: Str`. Encode it with
    /// `.encode()` to return from a `job_poll(job_id) -> Vec<u8>` handler.
    pub fn poll_reply(&mut self, id: u64) -> Args {
        let (data, done, error) = self.poll(id);
        Args::new()
            .with("data", data)
            .with("done", done)
            .with("error", error)
    }

    /// Drop a job by id, returning `true` if one was present. Idempotent —
    /// releasing an unknown / already-released id returns `false`.
    pub fn release(&mut self, id: u64) -> bool {
        let before = self.jobs.len();
        self.jobs.retain(|j| j.id != id);
        self.jobs.len() != before
    }

    /// Housekeeping: drop every job that is both terminal and released.
    /// (`release` already removes a job outright; `prune` exists for
    /// actors that mark `released` out of band rather than calling it.)
    pub fn prune(&mut self) {
        self.jobs.retain(|j| !(j.done && j.released));
    }

    /// Number of tracked (not-yet-released) jobs.
    pub fn len(&self) -> usize {
        self.jobs.len()
    }

    /// `true` when no jobs are tracked.
    pub fn is_empty(&self) -> bool {
        self.jobs.is_empty()
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;

    #[test]
    fn ids_are_monotonic_and_nonzero() {
        let mut q = JobQueue::new();
        assert_eq!(q.begin(), 1);
        assert_eq!(q.begin(), 2);
        assert_eq!(q.begin(), 3);
    }

    #[test]
    fn lifecycle_push_finish_poll_release() {
        let mut q = JobQueue::new();
        let id = q.begin();

        // Streaming: each poll drains what was pushed since the last one.
        q.push(id, b"hello ");
        q.push(id, b"world");
        let (data, done, error) = q.poll(id);
        assert_eq!(data, b"hello world");
        assert!(!done);
        assert!(error.is_empty());

        // A poll before any new bytes yields empty, still in-flight.
        let (data, done, _) = q.poll(id);
        assert!(data.is_empty());
        assert!(!done);

        // Terminal: finish flips done; leftover bytes still drain once.
        q.push(id, b"!");
        q.finish(id);
        let (data, done, error) = q.poll(id);
        assert_eq!(data, b"!");
        assert!(done);
        assert!(error.is_empty());

        // Post-terminal poll: done, empty.
        let (data, done, _) = q.poll(id);
        assert!(data.is_empty());
        assert!(done);

        // Release removes it; a subsequent poll reports benign done/empty.
        assert!(q.release(id));
        assert!(!q.release(id)); // idempotent
        let (data, done, error) = q.poll(id);
        assert!(data.is_empty());
        assert!(done);
        assert!(error.is_empty());
    }

    #[test]
    fn failed_job_is_terminal_with_error() {
        let mut q = JobQueue::new();
        let id = q.begin();
        q.fail(id, "boom");
        let (data, done, error) = q.poll(id);
        assert!(data.is_empty());
        assert!(done);
        assert_eq!(error, "boom");
    }

    #[test]
    fn push_after_terminal_is_dropped() {
        let mut q = JobQueue::new();
        let id = q.begin();
        q.finish(id);
        q.push(id, b"late"); // dropped — job already terminal
        let (data, _, _) = q.poll(id);
        assert!(data.is_empty());
    }

    #[test]
    fn poll_reply_has_conventional_shape() {
        let mut q = JobQueue::new();
        let id = q.begin();
        q.push(id, b"abc");
        q.finish(id);
        let args = q.poll_reply(id);
        assert_eq!(args.get_bytes("data"), Some(b"abc".to_vec()));
        assert_eq!(args.get_bool("done"), Some(true));
        assert_eq!(args.get_str("error"), Some(String::new()));
    }

    #[test]
    fn unknown_id_is_benign_done() {
        let mut q = JobQueue::new();
        let (data, done, error) = q.poll(999);
        assert!(data.is_empty());
        assert!(done);
        assert!(error.is_empty());
    }

    #[test]
    fn prune_drops_terminal_released_jobs() {
        let mut q = JobQueue::new();
        let a = q.begin();
        let b = q.begin();
        q.finish(a);
        // `a` still present until released.
        assert_eq!(q.len(), 2);
        q.release(a);
        assert_eq!(q.len(), 1);
        // `b` in-flight survives prune.
        q.prune();
        assert_eq!(q.len(), 1);
        assert!(!q.is_empty());
        let _ = b;
    }
}
