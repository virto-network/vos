//! The executor threads: a fixed pool for PVM work (refines, accumulates,
//! queries), which never touches storage I/O beyond snapshot reads.

use std::future::Future;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::mpsc;
use std::sync::{Arc, Mutex, PoisonError};
use std::thread::JoinHandle;

type Job = Box<dyn FnOnce() + Send>;

/// A job that panicked: its message, if it had one.
#[derive(Debug)]
pub(crate) struct Panicked(pub String);

pub(crate) struct Executors {
    sender: Option<mpsc::Sender<Job>>,
    threads: Vec<JoinHandle<()>>,
}

impl Executors {
    pub(crate) fn spawn(count: usize) -> Self {
        let (sender, receiver) = mpsc::channel::<Job>();
        let receiver = Arc::new(Mutex::new(receiver));
        let threads = (0..count.max(1))
            .map(|index| {
                let receiver = Arc::clone(&receiver);
                std::thread::Builder::new()
                    .name(format!("vos-executor-{index}"))
                    .spawn(move || {
                        loop {
                            let job = receiver
                                .lock()
                                .unwrap_or_else(PoisonError::into_inner)
                                .recv();
                            match job {
                                Ok(job) => job(),
                                Err(_) => break,
                            }
                        }
                    })
                    .expect("an executor thread starts")
            })
            .collect();
        Self {
            sender: Some(sender),
            threads,
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
            let result = catch_unwind(AssertUnwindSafe(work)).map_err(|panic| {
                let message = panic
                    .downcast_ref::<&str>()
                    .map(|message| (*message).to_string())
                    .or_else(|| panic.downcast_ref::<String>().cloned())
                    .unwrap_or_default();
                Panicked(message)
            });
            let _ = done.try_send(result);
        });
        let sent = self
            .sender
            .as_ref()
            .map(|sender| sender.send(job).is_ok())
            .unwrap_or(false);
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
        self.sender.take();
        // Their last owner can go with a job one of them runs: that thread
        // ends on its own once its job returns, and joining it would wait
        // for itself.
        let current = std::thread::current().id();
        for thread in self.threads.drain(..) {
            if thread.thread().id() != current {
                let _ = thread.join();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
