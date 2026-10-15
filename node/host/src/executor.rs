//! The executor threads: a fixed pool for PVM work (refines, accumulates,
//! queries), which never touches storage I/O beyond snapshot reads.

use std::future::Future;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::{Mutex, PoisonError};
use std::thread::JoinHandle;

type Job = Box<dyn FnOnce() + Send>;

/// A job that panicked: its message, if it had one.
#[derive(Debug)]
pub(crate) struct Panicked(pub String);

pub(crate) struct Executors {
    jobs: smol::channel::Sender<Job>,
    threads: Mutex<Vec<JoinHandle<()>>>,
}

impl Executors {
    pub(crate) fn spawn(count: usize) -> Self {
        let (jobs, taken) = smol::channel::unbounded::<Job>();
        let threads = (0..count.max(1))
            .map(|index| {
                let taken = taken.clone();
                std::thread::Builder::new()
                    .name(format!("vos-executor-{index}"))
                    .spawn(move || {
                        while let Ok(job) = taken.recv_blocking() {
                            job();
                        }
                    })
                    .expect("an executor thread starts")
            })
            .collect();
        Self {
            jobs,
            threads: Mutex::new(threads),
        }
    }

    /// Take no more jobs, and wait for the threads to finish the ones
    /// taken, and with them all their jobs hold. The current thread is not
    /// waited for: the executors' last owner can go with a job one of them
    /// runs, and that thread ends on its own once the job returns.
    pub(crate) fn close(&self) {
        self.jobs.close();
        let threads =
            std::mem::take(&mut *self.threads.lock().unwrap_or_else(PoisonError::into_inner));
        let current = std::thread::current().id();
        for thread in threads {
            if thread.thread().id() != current {
                let _ = thread.join();
            }
        }
    }

    /// Run `work` on an executor thread. A panic in it is caught and
    /// returned, and the thread goes on.
    pub(crate) fn run<T, F>(&self, work: F) -> impl Future<Output = Result<T, Panicked>> + use<T, F>
    where
        T: Send + 'static,
        F: FnOnce() -> T + Send + 'static,
    {
        let (done, wait) = smol::channel::bounded(1);
        let job: Job = Box::new(move || {
            let result = catch_unwind(AssertUnwindSafe(work))
                .map_err(|panic| Panicked(crate::panic_message(&*panic)));
            let _ = done.try_send(result);
        });
        let sent = self.jobs.try_send(job).is_ok();
        async move {
            if !sent {
                return Err(Panicked("the executors stopped".into()));
            }
            wait.recv()
                .await
                .unwrap_or_else(|_| Err(Panicked("an executor dropped the job".into())))
        }
    }
}

impl Drop for Executors {
    fn drop(&mut self) {
        self.close();
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, mpsc};

    use super::*;

    /// Closing waits for the jobs already taken, so what they hold is gone
    /// once it returns.
    #[test]
    fn closing_waits_for_the_jobs_taken() {
        let executors = Executors::spawn(2);
        let held = Arc::new(());
        let job = {
            let held = Arc::clone(&held);
            executors.run(move || {
                std::thread::sleep(std::time::Duration::from_millis(100));
                drop(held);
            })
        };
        executors.close();
        assert_eq!(Arc::strong_count(&held), 1, "a job outlived the close");
        assert!(smol::block_on(job).is_ok());
        assert!(
            smol::block_on(executors.run(|| ())).is_err(),
            "a job taken after the close"
        );
    }

    /// The executors' last owner, dropped by a job on one of their threads,
    /// stops them without joining that thread.
    #[test]
    fn executors_dropped_by_their_own_job_stop_without_joining_it() {
        let executors = Arc::new(Executors::spawn(2));
        let held = Arc::clone(&executors);
        let (go, wait) = mpsc::channel::<()>();
        let job = executors.run(move || {
            wait.recv().unwrap();
            drop(held);
        });
        drop(executors);
        go.send(()).unwrap();
        assert!(
            smol::block_on(job).is_ok(),
            "the job dropping the last owner panicked"
        );
    }
}
