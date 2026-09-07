//! Serialized read-only control boundary for the clean Shared system Agent.
//!
//! A [`CleanSystemAgentControlOwner`] moves the complete
//! [`CleanSystemAgentBootstrapOwner`] onto one dedicated worker thread.  The
//! cloneable [`CleanSystemAgentControl`] can inspect that owner only through a
//! capacity-one command channel; it cannot obtain the host, issuer, stores,
//! or any mutation/invocation capability.  Dropping the lifecycle owner first
//! closes admission and then joins the worker, even while cloned controls
//! remain alive.

use alloc::vec::Vec;
use core::fmt;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TryRecvError, TrySendError};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};

use super::clean_authority_issuer::CleanManagementIssuerStore;
use super::clean_bootstrap::{
    CleanSystemAgentBootstrapOwner, CleanSystemAgentBootstrapStore, CleanSystemAgentPins,
};
use super::sdk::authority::AuthorityReceipt;
use super::sdk::{AgentDescriptor, AgentId, AgentIdentity};
use super::shared_host::SharedAgentHostError;

/// Exact number of commands which may wait behind the operation currently
/// holding the clean Shared system Agent.
pub const CLEAN_SYSTEM_AGENT_CONTROL_QUEUE_CAPACITY: usize = 1;

const OWNER_RUNNING: u8 = 0;
const OWNER_CLOSING: u8 = 1;
const OWNER_CLOSED: u8 = 2;
const OWNER_FAILED: u8 = 3;

/// Stable errors exposed by the read-only control boundary.
///
/// Storage, issuer, and host implementation errors remain on the owner
/// thread. `QueryFailed` reports a failed durable read without leaking a
/// generic backend error through cloned handles.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CleanSystemAgentControlError {
    /// The sole waiting slot is occupied. The request was not admitted.
    Busy,
    /// Shutdown closed the request before it began executing. A read which was
    /// already executing may still complete successfully.
    Closed,
    /// The owner thread panicked, disconnected, or could not be started.
    OwnerFailed,
    /// The exact full SDK `AgentId` is not present in this host.
    NotFound,
    /// The owner remained alive, but its durable read failed closed.
    QueryFailed,
}

impl fmt::Display for CleanSystemAgentControlError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "clean system-Agent control failed: {self:?}")
    }
}

impl core::error::Error for CleanSystemAgentControlError {}

/// Externally meaningful bootstrap phase. A control is not published until
/// bootstrap has completed, so no provisional or backend-specific state can
/// escape this boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CleanSystemAgentControlPhase {
    Complete,
}

/// Immutable owner state returned from the worker as one bounded snapshot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CleanSystemAgentStatus {
    pins: CleanSystemAgentPins,
    creation_receipt: AuthorityReceipt,
    phase: CleanSystemAgentControlPhase,
    issuer_sequence_high_water: u64,
    issuer_acknowledged_through: u64,
}

impl CleanSystemAgentStatus {
    pub const fn pins(&self) -> &CleanSystemAgentPins {
        &self.pins
    }

    pub const fn creation_receipt(&self) -> &AuthorityReceipt {
        &self.creation_receipt
    }

    pub const fn descriptor(&self) -> &AgentDescriptor {
        self.pins.descriptor()
    }

    pub const fn identity(&self) -> &AgentIdentity {
        &self.pins.descriptor().identity
    }

    pub const fn phase(&self) -> CleanSystemAgentControlPhase {
        self.phase
    }

    pub const fn issuer_sequence_high_water(&self) -> u64 {
        self.issuer_sequence_high_water
    }

    pub const fn issuer_acknowledged_through(&self) -> u64 {
        self.issuer_acknowledged_through
    }
}

struct SharedControl {
    commands: SyncSender<Command>,
    state: Arc<AtomicU8>,
    // Admission and the Running -> Closing transition are serialized. No
    // caller holds this lock while waiting for the worker, so shutdown/join
    // cannot form a lock cycle with a request.
    admission: Mutex<()>,
}

/// Cloneable, bounded, read-only handle to one clean system-Agent owner thread.
///
/// All routing uses complete `vos_agent_sdk::AgentId` values. A handle cannot
/// mutate lifecycle state, invoke an actor, access an unauthenticated service route, or
/// extend the lifetime of the lifecycle guard's worker after shutdown.
#[derive(Clone)]
pub struct CleanSystemAgentControl {
    shared: Arc<SharedControl>,
}

impl fmt::Debug for CleanSystemAgentControl {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CleanSystemAgentControl")
            .field("running", &self.is_running())
            .finish_non_exhaustive()
    }
}

impl CleanSystemAgentControl {
    /// Whether the lifecycle owner is still admitting read operations.
    pub fn is_running(&self) -> bool {
        self.shared.state.load(Ordering::Acquire) == OWNER_RUNNING
    }

    /// List complete SDK Agent identifiers in canonical order.
    pub fn list(&self) -> Result<Vec<AgentId>, CleanSystemAgentControlError> {
        self.request(Command::List)
    }

    /// Read the exact immutable descriptor selected by a complete SDK ID.
    pub fn show(&self, agent: AgentId) -> Result<AgentDescriptor, CleanSystemAgentControlError> {
        self.request(|reply| Command::Show { agent, reply })
    }

    /// Revalidate the exact pinned system Agent in the live host, then read its
    /// immutable pins, creation evidence, and issuer progress.
    pub fn status(&self) -> Result<CleanSystemAgentStatus, CleanSystemAgentControlError> {
        self.request(Command::Status)
    }

    fn request<T>(
        &self,
        command: impl FnOnce(SyncSender<Result<T, CleanSystemAgentControlError>>) -> Command,
    ) -> Result<T, CleanSystemAgentControlError> {
        let result = {
            let _admission = self
                .shared
                .admission
                .lock()
                .map_err(|_| CleanSystemAgentControlError::OwnerFailed)?;
            match self.shared.state.load(Ordering::Acquire) {
                OWNER_RUNNING => {}
                OWNER_CLOSING | OWNER_CLOSED => {
                    return Err(CleanSystemAgentControlError::Closed);
                }
                _ => return Err(CleanSystemAgentControlError::OwnerFailed),
            }
            let (reply, result) = mpsc::sync_channel(1);
            match self.shared.commands.try_send(command(reply)) {
                Ok(()) => result,
                Err(TrySendError::Full(_)) => return Err(CleanSystemAgentControlError::Busy),
                Err(TrySendError::Disconnected(_)) => {
                    mark_owner_failed(&self.shared.state);
                    return Err(CleanSystemAgentControlError::OwnerFailed);
                }
            }
        };
        result.recv().unwrap_or_else(|_| {
            if matches!(
                self.shared.state.load(Ordering::Acquire),
                OWNER_CLOSING | OWNER_CLOSED
            ) {
                Err(CleanSystemAgentControlError::Closed)
            } else {
                mark_owner_failed(&self.shared.state);
                Err(CleanSystemAgentControlError::OwnerFailed)
            }
        })
    }
}

/// Non-cloneable lifecycle guard for a serialized clean Shared system Agent.
///
/// This is the only value which owns the worker's join handle. Explicit
/// shutdown and `Drop` both close admission before joining; cloned controls
/// become terminally `Closed` and cannot keep the bootstrap stores, issuer,
/// or filesystem host alive.
pub struct CleanSystemAgentControlOwner {
    control: CleanSystemAgentControl,
    worker: Option<JoinHandle<()>>,
}

impl fmt::Debug for CleanSystemAgentControlOwner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CleanSystemAgentControlOwner")
            .field("running", &self.control.is_running())
            .finish_non_exhaustive()
    }
}

impl CleanSystemAgentControlOwner {
    /// Move a fully bootstrapped owner onto its dedicated single-writer
    /// thread. The method returns only after that thread has taken ownership.
    pub fn start<P, R, I>(
        owner: CleanSystemAgentBootstrapOwner<P, R, I>,
    ) -> Result<Self, CleanSystemAgentControlError>
    where
        P: CleanSystemAgentBootstrapStore + Send + 'static,
        R: CleanSystemAgentBootstrapStore + Send + 'static,
        I: CleanManagementIssuerStore + Send + 'static,
    {
        let (commands, receiver) = mpsc::sync_channel(CLEAN_SYSTEM_AGENT_CONTROL_QUEUE_CAPACITY);
        let state = Arc::new(AtomicU8::new(OWNER_RUNNING));
        let worker_state = state.clone();
        let (ready, started) = mpsc::sync_channel(0);
        let worker = thread::Builder::new()
            .name("vos-clean-system-agent".into())
            .spawn(move || {
                let _ = ready.send(());
                let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    clean_system_agent_worker(owner, receiver, &worker_state)
                }));
                let terminal = match outcome {
                    Ok(true) => OWNER_CLOSED,
                    Ok(false) | Err(_) => OWNER_FAILED,
                };
                worker_state.store(terminal, Ordering::Release);
            })
            .map_err(|_| CleanSystemAgentControlError::OwnerFailed)?;
        if started.recv().is_err() {
            let _ = worker.join();
            return Err(CleanSystemAgentControlError::OwnerFailed);
        }
        Ok(Self {
            control: CleanSystemAgentControl {
                shared: Arc::new(SharedControl {
                    commands,
                    state,
                    admission: Mutex::new(()),
                }),
            },
            worker: Some(worker),
        })
    }

    /// Obtain a read-only handle. Clones are invalidated by owner shutdown.
    pub fn control(&self) -> CleanSystemAgentControl {
        self.control.clone()
    }

    pub fn is_running(&self) -> bool {
        self.control.is_running()
    }

    /// Stop admitting commands without waiting for the active read to finish.
    /// [`Self::shutdown_and_join`] or `Drop` still performs the mandatory join.
    pub fn request_shutdown(&self) {
        let admission = self.control.shared.admission.lock();
        // Poisoning can only come from a panic while changing lifecycle state;
        // fail closed and continue waking the worker.
        let _admission = match admission {
            Ok(admission) => admission,
            Err(poisoned) => poisoned.into_inner(),
        };
        if self
            .control
            .shared
            .state
            .compare_exchange(
                OWNER_RUNNING,
                OWNER_CLOSING,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
        {
            // A full channel already contains the wake-up. The state change,
            // rather than delivery of this best-effort marker, closes admission.
            let _ = self.control.shared.commands.try_send(Command::Wake);
        }
    }

    /// Close admission and join the owner thread. Returning success proves
    /// that the complete bootstrap owner was dropped on that thread.
    pub fn shutdown_and_join(mut self) -> Result<(), CleanSystemAgentControlError> {
        self.request_shutdown();
        self.join_worker()
    }

    fn join_worker(&mut self) -> Result<(), CleanSystemAgentControlError> {
        let Some(worker) = self.worker.take() else {
            return match self.control.shared.state.load(Ordering::Acquire) {
                OWNER_CLOSED => Ok(()),
                _ => Err(CleanSystemAgentControlError::OwnerFailed),
            };
        };
        if worker.join().is_err() {
            mark_owner_failed(&self.control.shared.state);
        }
        match self.control.shared.state.load(Ordering::Acquire) {
            OWNER_CLOSED => Ok(()),
            _ => Err(CleanSystemAgentControlError::OwnerFailed),
        }
    }
}

impl Drop for CleanSystemAgentControlOwner {
    fn drop(&mut self) {
        self.request_shutdown();
        // Do not hold the admission mutex while joining. Every production
        // command is a finite read and never has access to this lifecycle guard.
        let _ = self.join_worker();
    }
}

enum Command {
    List(SyncSender<Result<Vec<AgentId>, CleanSystemAgentControlError>>),
    Show {
        agent: AgentId,
        reply: SyncSender<Result<AgentDescriptor, CleanSystemAgentControlError>>,
    },
    Status(SyncSender<Result<CleanSystemAgentStatus, CleanSystemAgentControlError>>),
    Wake,
}

fn clean_system_agent_worker<P, R, I>(
    owner: CleanSystemAgentBootstrapOwner<P, R, I>,
    receiver: Receiver<Command>,
    state: &AtomicU8,
) -> bool
where
    P: CleanSystemAgentBootstrapStore,
    R: CleanSystemAgentBootstrapStore,
    I: CleanManagementIssuerStore,
{
    loop {
        if state.load(Ordering::Acquire) != OWNER_RUNNING {
            reject_queued_commands(&receiver);
            drop(owner);
            return true;
        }
        match receiver.recv() {
            Ok(command) if state.load(Ordering::Acquire) == OWNER_RUNNING => {
                run_command(&owner, command)
            }
            Ok(command) => reject_command(command),
            Err(_) => {
                drop(owner);
                return false;
            }
        }
    }
}

fn run_command<P, R, I>(owner: &CleanSystemAgentBootstrapOwner<P, R, I>, command: Command)
where
    P: CleanSystemAgentBootstrapStore,
    R: CleanSystemAgentBootstrapStore,
    I: CleanManagementIssuerStore,
{
    match command {
        Command::List(reply) => {
            let result = owner.list().map_err(map_host_read_error);
            let _ = reply.send(result);
        }
        Command::Show { agent, reply } => {
            let result = owner
                .show(agent)
                .map_err(map_host_read_error)
                .and_then(|descriptor| descriptor.ok_or(CleanSystemAgentControlError::NotFound));
            let _ = reply.send(result);
        }
        Command::Status(reply) => {
            let result = owner
                .show(owner.pins().agent())
                .map_err(|_| CleanSystemAgentControlError::QueryFailed)
                .and_then(|descriptor| descriptor.ok_or(CleanSystemAgentControlError::QueryFailed))
                .and_then(|descriptor| {
                    if descriptor != *owner.pins().descriptor() {
                        return Err(CleanSystemAgentControlError::QueryFailed);
                    }
                    Ok(CleanSystemAgentStatus {
                        pins: owner.pins().clone(),
                        creation_receipt: owner.creation_receipt().clone(),
                        phase: CleanSystemAgentControlPhase::Complete,
                        issuer_sequence_high_water: owner.issuer_sequence_high_water(),
                        issuer_acknowledged_through: owner.issuer_acknowledged_through(),
                    })
                });
            let _ = reply.send(result);
        }
        Command::Wake => {}
    }
}

fn reject_queued_commands(receiver: &Receiver<Command>) {
    loop {
        match receiver.try_recv() {
            Ok(command) => reject_command(command),
            Err(TryRecvError::Empty | TryRecvError::Disconnected) => return,
        }
    }
}

fn reject_command(command: Command) {
    match command {
        Command::List(reply) => {
            let _ = reply.send(Err(CleanSystemAgentControlError::Closed));
        }
        Command::Show { reply, .. } => {
            let _ = reply.send(Err(CleanSystemAgentControlError::Closed));
        }
        Command::Status(reply) => {
            let _ = reply.send(Err(CleanSystemAgentControlError::Closed));
        }
        Command::Wake => {}
    }
}

fn map_host_read_error(error: SharedAgentHostError) -> CleanSystemAgentControlError {
    match error {
        SharedAgentHostError::AgentNotFound => CleanSystemAgentControlError::NotFound,
        _ => CleanSystemAgentControlError::QueryFailed,
    }
}

fn mark_owner_failed(state: &AtomicU8) {
    let mut current = state.load(Ordering::Acquire);
    while current == OWNER_RUNNING {
        match state.compare_exchange_weak(
            OWNER_RUNNING,
            OWNER_FAILED,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => return,
            Err(observed) => current = observed,
        }
    }
}
