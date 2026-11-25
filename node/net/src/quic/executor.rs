//! The network's executor and the tasks it runs.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Weak};

/// The network's executor, driven by one thread of its own. Every task of
/// the network runs on it, quinn's included, so a connection's readers are
/// polled in the order they were woken: the receiving side's turns rely
/// on it, which async-executor does not promise (a test below shows it
/// holds). A panic in a task ends the thread, and with it the network.
/// Tasks reach it by a [`Spawner`], which does not keep it alive.
pub struct Runner {
    executor: Arc<smol::Executor<'static>>,
    stop: smol::channel::Sender<()>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Runner {
    pub fn start() -> io::Result<Self> {
        let executor = Arc::new(smol::Executor::new());
        let (stop, stopped) = smol::channel::bounded::<()>(1);
        let thread = std::thread::Builder::new().name("vos-net".into()).spawn({
            let executor = Arc::clone(&executor);
            move || {
                let _ = smol::block_on(executor.run(stopped.recv()));
            }
        })?;
        Ok(Self {
            executor,
            stop,
            thread: Some(thread),
        })
    }

    pub fn spawner(&self) -> Spawner {
        Spawner(Arc::downgrade(&self.executor))
    }
}

impl Drop for Runner {
    /// Stop the thread; the executor then goes, with the tasks it still
    /// holds.
    fn drop(&mut self) {
        let _ = self.stop.try_send(());
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// Spawns on the network's executor while it runs.
#[derive(Clone, Debug)]
pub struct Spawner(Weak<smol::Executor<'static>>);

impl Spawner {
    pub fn spawn<T: Send + 'static>(
        &self,
        future: impl Future<Output = T> + Send + 'static,
    ) -> Option<smol::Task<T>> {
        Some(self.0.upgrade()?.spawn(future))
    }
}

/// Tasks that stop when their holder drops them; the finished ones are let
/// go as new ones come, in sweeps far enough apart that a spawn costs the
/// same however many tasks are held.
#[derive(Default)]
pub(super) struct Tasks {
    tasks: Vec<smol::Task<()>>,
    /// How many were held after the last sweep.
    swept: usize,
}

/// Tasks held before the first sweep.
const SWEEP: usize = 16;

impl Tasks {
    /// Spawn `future` and hold its task: `false` once the executor is gone.
    pub(super) fn spawn(
        &mut self,
        spawner: &Spawner,
        future: impl Future<Output = ()> + Send + 'static,
    ) -> bool {
        if self.tasks.len() >= 2 * self.swept.max(SWEEP) {
            self.tasks.retain(|task| !task.is_finished());
            self.swept = self.tasks.len();
        }
        let Some(task) = spawner.spawn(future) else {
            return false;
        };
        self.tasks.push(task);
        true
    }
}

/// quinn's smol runtime, spawning on the network's executor.
#[derive(Debug)]
pub struct Runtime(pub Spawner);

impl quinn::Runtime for Runtime {
    fn new_timer(&self, at: std::time::Instant) -> Pin<Box<dyn quinn::AsyncTimer>> {
        quinn::Runtime::new_timer(&quinn::SmolRuntime, at)
    }

    fn spawn(&self, future: Pin<Box<dyn Future<Output = ()> + Send>>) {
        if let Some(task) = self.0.spawn(future) {
            task.detach();
        }
    }

    fn wrap_udp_socket(
        &self,
        socket: std::net::UdpSocket,
    ) -> io::Result<Arc<dyn quinn::AsyncUdpSocket>> {
        quinn::Runtime::wrap_udp_socket(&quinn::SmolRuntime, socket)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    /// The receiving side's turns rely on the executor polling woken tasks
    /// in the order they woke, on its one thread.
    #[test]
    fn woken_tasks_are_polled_in_the_order_they_woke() {
        let runner = Runner::start().unwrap();
        let order = Arc::new(Mutex::new(Vec::new()));
        let (wakes, tasks): (Vec<_>, Vec<_>) = (0..8)
            .map(|i| {
                let (wake, woken) = smol::channel::bounded::<()>(1);
                let order = Arc::clone(&order);
                let task = runner
                    .spawner()
                    .spawn(async move {
                        let _ = woken.recv().await;
                        order.lock().unwrap().push(i);
                    })
                    .unwrap();
                (wake, task)
            })
            .unzip();
        // Every task waits, then all are woken at once, in an order of
        // their own.
        std::thread::sleep(std::time::Duration::from_millis(50));
        let woken = [3, 1, 7, 0, 6, 2, 5, 4];
        runner
            .spawner()
            .spawn(async move {
                for i in woken {
                    wakes[i].try_send(()).unwrap();
                }
            })
            .unwrap()
            .detach();
        smol::block_on(async {
            for task in tasks {
                task.await;
            }
        });
        assert_eq!(*order.lock().unwrap(), woken);
    }
}
