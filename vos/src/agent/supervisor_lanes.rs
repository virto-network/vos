//! Bounded ownership scheduler. A lane is an Agent, not an actor or attachment.
//! Jobs retain their payload/admission owners until returned or completed.
use std::collections::{BTreeMap, VecDeque};

use super::{AgentId, SpaceId};

type Job<T> = Box<dyn FnOnce() -> T + Send>;

/// Fixed worker ownership. Execution completions use a separate channel so
/// workers never wait for room in the supervisor's command queue during join.
/// The scheduler/admission layer bounds the number of outstanding completions.
pub(super) struct Pool<T> {
    sender: Option<std::sync::mpsc::SyncSender<Job<T>>>,
    pub completions: std::sync::mpsc::Receiver<Result<T, ()>>,
    workers: Vec<std::thread::JoinHandle<()>>,
}

impl<T: Send + 'static> Pool<T> {
    #[cfg(test)]
    pub fn new(workers: usize, capacity: usize) -> std::io::Result<Self> {
        Self::with_wake(workers, capacity, || {})
    }

    pub fn with_wake(
        workers: usize,
        capacity: usize,
        wake: impl Fn() + Send + Sync + 'static,
    ) -> std::io::Result<Self> {
        assert!(workers > 0 && capacity > 0);
        let (sender, receiver) = std::sync::mpsc::sync_channel::<Job<T>>(capacity);
        let receiver = std::sync::Arc::new(std::sync::Mutex::new(receiver));
        let (completed, completions) = std::sync::mpsc::channel();
        let wake = std::sync::Arc::new(wake);
        let mut pool = Self {
            sender: Some(sender),
            completions,
            workers: Vec::new(),
        };
        for index in 0..workers {
            let receiver = receiver.clone();
            let completed = completed.clone();
            let wake = wake.clone();
            let worker = std::thread::Builder::new()
                .name(format!("agent-exec-{index}"))
                .spawn(move || {
                    loop {
                        let job = match receiver.lock() {
                            Ok(receiver) => receiver.recv(),
                            Err(_) => return,
                        };
                        let Ok(job) = job else {
                            return;
                        };
                        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(job))
                            .map_err(|_| ());
                        if completed.send(result).is_err() {
                            return;
                        }
                        wake();
                    }
                })?;
            pool.workers.push(worker);
        }
        Ok(pool)
    }

    pub fn submit(&self, job: Job<T>) -> Result<(), Job<T>> {
        let Some(sender) = &self.sender else {
            return Err(job);
        };
        sender.try_send(job).map_err(|error| match error {
            std::sync::mpsc::TrySendError::Full(job)
            | std::sync::mpsc::TrySendError::Disconnected(job) => job,
        })
    }
}

impl<T> Drop for Pool<T> {
    fn drop(&mut self) {
        self.join();
    }
}

impl<T> Pool<T> {
    pub fn join(&mut self) {
        // Disconnect first, then join every worker. No task can outlive its owner.
        self.sender.take();
        for worker in self.workers.drain(..) {
            let _ = worker.join();
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct Lane(pub SpaceId, pub AgentId);

pub(super) struct Ready<T> {
    pub lane: Lane,
    pub ticket: Ticket,
    pub job: T,
}

#[derive(Clone, Copy)]
pub(super) struct Ticket {
    lane: Lane,
    serial: u64,
}

/// The supervisor alone mutates scheduling state; workers receive owned jobs.
/// A full lane cannot occupy a worker merely waiting for another job in it.
pub(super) struct Scheduler<T> {
    pending: VecDeque<Ready<T>>,
    active: BTreeMap<Lane, u64>,
    next_serial: u64,
    capacity: usize,
    workers: usize,
    closing: bool,
}

impl<T> Scheduler<T> {
    pub fn new(capacity: usize, workers: usize) -> Self {
        assert!(capacity > 0 && workers > 0);
        Self {
            pending: VecDeque::new(),
            active: BTreeMap::new(),
            next_serial: 0,
            capacity,
            workers,
            closing: false,
        }
    }

    /// Refusal returns ownership so the caller can reply and release its exact
    /// reservation. Capacity includes active work, not just queued jobs.
    pub fn submit(&mut self, lane: Lane, job: T) -> Result<(), T> {
        if self.closing || self.pending.len() + self.active.len() >= self.capacity {
            return Err(job);
        }
        let Some(serial) = self.next_serial.checked_add(1) else {
            return Err(job);
        };
        self.next_serial = serial;
        self.pending.push_back(Ready {
            lane,
            ticket: Ticket { lane, serial },
            job,
        });
        Ok(())
    }

    /// FIFO among runnable jobs; a busy Agent never blocks another Agent.
    #[cfg(test)]
    pub fn next(&mut self) -> Option<Ready<T>> {
        self.next_where(|_| true)
    }

    pub fn next_where(&mut self, mut runnable: impl FnMut(&T) -> bool) -> Option<Ready<T>> {
        if self.closing || self.active.len() >= self.workers {
            return None;
        }
        let mut seen = std::collections::BTreeSet::new();
        let index = self.pending.iter().position(|job| {
            seen.insert(job.lane) && !self.active.contains_key(&job.lane) && runnable(&job.job)
        })?;
        let ready = self.pending.remove(index)?;
        assert!(
            self.active
                .insert(ready.lane, ready.ticket.serial)
                .is_none()
        );
        Some(ready)
    }

    /// Completion must occur exactly once after the worker has stopped touching
    /// the job's driver. Unknown/duplicate completions are a coordinator fault.
    pub fn complete(&mut self, ticket: Ticket) -> bool {
        if self.active.get(&ticket.lane) != Some(&ticket.serial) {
            return false;
        }
        self.active.remove(&ticket.lane);
        true
    }

    /// Withdraw only queued work. Already running work must be joined before
    /// its generation or lease can be retired.
    pub fn cancel_where(&mut self, mut matches: impl FnMut(&T) -> bool) -> Vec<T> {
        let mut cancelled = Vec::new();
        let mut retained = VecDeque::new();
        while let Some(ready) = self.pending.pop_front() {
            if matches(&ready.job) {
                cancelled.push(ready.job);
            } else {
                retained.push_back(ready);
            }
        }
        self.pending = retained;
        cancelled
    }

    pub fn close(&mut self) -> Vec<T> {
        self.closing = true;
        self.cancel_where(|_| true)
    }

    #[cfg(test)]
    pub fn is_drained(&self) -> bool {
        self.pending.is_empty() && self.active.is_empty()
    }

    pub fn is_active(&self, lane: Lane) -> bool {
        self.active.contains_key(&lane)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn lane(agent: u8) -> Lane {
        Lane(SpaceId([1; 32]), AgentId([agent; 32]))
    }

    #[test]
    fn fixed_pool_executes_independent_jobs_concurrently_and_joins() {
        let pool = Pool::new(2, 2).unwrap();
        let (entered, observed) = std::sync::mpsc::channel();
        let (release_a, wait_a) = std::sync::mpsc::channel();
        let (release_b, wait_b) = std::sync::mpsc::channel();
        for (id, wait) in [(1, wait_a), (2, wait_b)] {
            let entered = entered.clone();
            assert!(
                pool.submit(Box::new(move || {
                    entered.send(id).unwrap();
                    wait.recv_timeout(std::time::Duration::from_secs(5))
                        .unwrap();
                    id
                }))
                .is_ok()
            );
        }
        // Both jobs must have entered before either is allowed to finish.
        let mut ids = vec![
            observed
                .recv_timeout(std::time::Duration::from_secs(5))
                .unwrap(),
            observed
                .recv_timeout(std::time::Duration::from_secs(5))
                .unwrap(),
        ];
        ids.sort();
        assert_eq!(ids, [1, 2]);
        release_a.send(()).unwrap();
        release_b.send(()).unwrap();
        for _ in 0..2 {
            assert!(pool.completions.recv().unwrap().is_ok());
        }
        drop(pool);
    }

    #[test]
    fn pool_reports_panics_without_stranding_completion() {
        let pool = Pool::new(1, 1).unwrap();
        assert!(
            pool.submit(Box::new(|| -> u8 { panic!("intentional job fault") }))
                .is_ok()
        );
        assert_eq!(
            pool.completions
                .recv_timeout(std::time::Duration::from_secs(5))
                .unwrap(),
            Err(())
        );
        assert!(pool.submit(Box::new(|| 7)).is_ok());
        assert_eq!(
            pool.completions
                .recv_timeout(std::time::Duration::from_secs(5))
                .unwrap(),
            Ok(7)
        );
    }

    #[test]
    fn independent_agents_run_while_same_agent_keeps_fifo_order() {
        let mut scheduler = Scheduler::new(5, 2);
        scheduler.submit(lane(1), 10).unwrap();
        scheduler.submit(lane(1), 11).unwrap();
        scheduler.submit(lane(2), 20).unwrap();
        let first = scheduler.next().unwrap();
        let second = scheduler.next().unwrap();
        assert_eq!(first.job, 10);
        assert_eq!(second.job, 20);
        assert!(scheduler.next().is_none());
        assert!(scheduler.complete(first.ticket));
        let next = scheduler.next().unwrap();
        assert_eq!(next.job, 11);
        assert!(
            !scheduler.complete(first.ticket),
            "stale completion cannot release a newer job"
        );
        assert!(scheduler.complete(next.ticket));
        assert!(!scheduler.complete(next.ticket));
        assert!(scheduler.complete(second.ticket));
        assert!(scheduler.is_drained());
    }

    #[test]
    fn capacity_counts_executing_jobs_and_returns_rejected_ownership() {
        let mut scheduler = Scheduler::new(2, 2);
        scheduler.submit(lane(1), 1).unwrap();
        let active = scheduler.next().unwrap();
        scheduler.submit(lane(2), 2).unwrap();
        assert_eq!(scheduler.submit(lane(3), 3), Err(3));
        assert_eq!(scheduler.close(), vec![2]);
        assert!(!scheduler.is_drained());
        assert!(scheduler.next().is_none());
        assert_eq!(scheduler.submit(lane(3), 4), Err(4));
        assert!(scheduler.complete(active.ticket));
        assert!(scheduler.is_drained());
    }

    #[test]
    fn cancelling_a_generation_preserves_other_jobs_order() {
        let mut scheduler = Scheduler::new(5, 2);
        for job in 0..4 {
            scheduler.submit(lane(1), job).unwrap();
        }
        let active = scheduler.next().unwrap();
        assert_eq!(active.job, 0);
        assert_eq!(
            scheduler.cancel_where(|job| *job == 1 || *job == 3),
            vec![1, 3]
        );
        assert!(scheduler.complete(active.ticket));
        assert_eq!(scheduler.next().unwrap().job, 2);
    }

    #[test]
    fn unavailable_attachment_cannot_reorder_jobs_within_an_agent() {
        let mut scheduler = Scheduler::new(4, 2);
        scheduler.submit(lane(1), 1).unwrap();
        scheduler.submit(lane(1), 2).unwrap();
        scheduler.submit(lane(2), 3).unwrap();
        assert_eq!(scheduler.next_where(|job| *job != 1).unwrap().job, 3);
        assert!(scheduler.next_where(|job| *job != 1).is_none());
        assert_eq!(scheduler.next().unwrap().job, 1);
    }
}
