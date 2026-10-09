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
        for thread in self.threads.drain(..) {
            let _ = thread.join();
        }
    }
}
