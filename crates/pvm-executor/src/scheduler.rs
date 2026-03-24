//! Scheduler — drives the executor's main loop.
//!
//! The scheduler is the top-level entry point. On each `tick()`:
//! 1. Deliver one pending message per actor (round-robin fairness)
//! 2. Poll suspended actors for async completion
//! 3. Handle any pending syscalls
//!
//! The scheduler itself is async — it can run inside Embassy or any
//! other async runtime, or be polled directly from a PVM `poll()` export.

use crate::registry::{ActorRegistry, ActorState};
use crate::syscall_handler::SyscallHandler;
use pvm_abi::actor::{ActorId, Status};

/// Result of a scheduler tick.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TickResult {
    /// At least one actor made progress.
    Progress,
    /// All actors are idle (no pending messages, nothing suspended).
    Idle,
    /// All actors have stopped.
    Done,
}

/// The scheduler drives actor execution.
///
/// Generic over:
/// - `Msg`: the message type flowing between actors
/// - `D`: the "driver" that actually calls into child PVM programs
/// - `N`: max actors
/// - `MC`: mailbox capacity per actor
pub struct Scheduler<Msg, D, const N: usize, const MC: usize> {
    pub registry: ActorRegistry<Msg, N, MC>,
    pub syscalls: SyscallHandler,
    driver: D,
}

/// The driver trait — abstracts how the executor calls into child programs.
///
/// In a real PVM executor, this calls the child's exported functions.
/// In tests, it can call Rust functions directly.
pub trait Driver<Msg> {
    /// Initialize a child actor.
    fn init(&mut self, id: ActorId) -> Status;

    /// Deliver a message to a child actor.
    fn handle(&mut self, id: ActorId, msg: &Msg) -> Status;

    /// Poll a suspended child actor for async completion.
    fn poll(&mut self, id: ActorId) -> Status;

    /// Clean up a stopped actor.
    fn drop_actor(&mut self, id: ActorId);
}

impl<Msg, D: Driver<Msg>, const N: usize, const MC: usize> Scheduler<Msg, D, N, MC> {
    /// Create a new scheduler with the given driver.
    pub fn new(driver: D) -> Self {
        Self {
            registry: ActorRegistry::new(),
            syscalls: SyscallHandler::new(),
            driver,
        }
    }

    /// Spawn a new actor. Calls `init()` on the child program.
    pub fn spawn(&mut self) -> Option<ActorId> {
        let id = self.registry.register()?;
        let status = self.driver.init(id);
        self.registry.update_state(id, status);
        Some(id)
    }

    /// Send a message to an actor.
    pub fn send(&mut self, target: ActorId, msg: Msg) -> Result<(), Msg> {
        self.registry.send(target, msg)
    }

    /// Run one round of the scheduler.
    pub fn tick(&mut self) -> TickResult {
        if self.registry.alive_count() == 0 {
            return TickResult::Done;
        }

        let mut progress = false;

        self.registry.tick(|id, state, msg| {
            let status = match (state, msg) {
                (ActorState::Suspended, _) => self.driver.poll(id),
                (ActorState::Running, Some(msg)) => self.driver.handle(id, msg),
                _ => Status::Ready,
            };

            if status == Status::Done || status == Status::Error {
                self.driver.drop_actor(id);
            }

            if status != Status::Ready || msg.is_some() {
                progress = true;
            }

            status
        });

        if progress {
            TickResult::Progress
        } else {
            TickResult::Idle
        }
    }

    /// Access the driver (e.g., for testing).
    pub fn driver(&self) -> &D {
        &self.driver
    }

    /// Access the driver mutably.
    pub fn driver_mut(&mut self) -> &mut D {
        &mut self.driver
    }
}
