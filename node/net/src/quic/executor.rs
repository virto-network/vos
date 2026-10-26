//! The network's executor and the tasks it runs.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Weak};

/// The network's executor, driven by one thread of its own. Every task of
/// the network runs on it, quinn's included, so a connection's readers are
/// polled in the order they were woken: the receiving side's turns rely
/// on it. Tasks reach it by a [`Spawner`], which does not keep it alive.
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
/// go as new ones come.
#[derive(Default)]
pub(super) struct Tasks(Vec<smol::Task<()>>);

impl Tasks {
    /// Spawn `future` and hold its task: `false` once the executor is gone.
    pub(super) fn spawn(
        &mut self,
        spawner: &Spawner,
        future: impl Future<Output = ()> + Send + 'static,
    ) -> bool {
        self.0.retain(|task| !task.is_finished());
        let Some(task) = spawner.spawn(future) else {
            return false;
        };
        self.0.push(task);
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
