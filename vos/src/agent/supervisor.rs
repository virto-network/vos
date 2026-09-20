//! Bounded, full-identity routing ownership for Agent workers.
//!
//! This module deliberately stops at the process-local supervision seam. It
//! does not know about HTTP, SSH, network peers, legacy `ServiceId` values, or
//! any concrete Local/Shared/Private host. A concrete host contributes one
//! narrow [`AgentRoute`] adapter and one explicit [`AgentRouteWorkerOwner`].
//! The supervisor publishes immutable snapshots only after the adapter has
//! reconciled the exact identities which it claims to serve.

use core::fmt;
use core::num::NonZeroU64;
use std::collections::{BTreeMap, BTreeSet};
use std::panic::{self, AssertUnwindSafe};
use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TryRecvError, TrySendError};
use std::sync::{Arc, Mutex, RwLock};
use std::thread::{self, JoinHandle};

use super::sdk::{ActorId, AgentId, AgentProfile, DeploymentId, Hash, ProgramId, SpaceId};

#[path = "supervisor_lanes.rs"]
mod lanes;

/// Default maximum number of full actor routes published by one supervisor.
pub const DEFAULT_AGENT_SUPERVISOR_ROUTE_CAPACITY: usize = 4_096;
/// Default number of operations which may wait behind the active operation.
pub const DEFAULT_AGENT_SUPERVISOR_QUEUE_CAPACITY: usize = 64;
/// Default maximum number of executing and queued dispatches.
pub const DEFAULT_AGENT_SUPERVISOR_INFLIGHT_CAPACITY: usize = 65;
/// Default aggregate owned request capacity admitted across all dispatches.
pub const DEFAULT_AGENT_SUPERVISOR_PAYLOAD_CAPACITY_BYTES: usize = 8 * 1024 * 1024;

const SUPERVISOR_RUNNING: u8 = 0;
const SUPERVISOR_CLOSING: u8 = 1;
const SUPERVISOR_CLOSED: u8 = 2;
const SUPERVISOR_FAILED: u8 = 3;

/// Fixed process-local resource limits for one supervisor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AgentSupervisorLimits {
    route_capacity: usize,
    queue_capacity: usize,
    inflight_capacity: usize,
    payload_capacity_bytes: usize,
}

impl AgentSupervisorLimits {
    pub const fn new(
        route_capacity: usize,
        queue_capacity: usize,
        inflight_capacity: usize,
        payload_capacity_bytes: usize,
    ) -> Self {
        Self {
            route_capacity,
            queue_capacity,
            inflight_capacity,
            payload_capacity_bytes,
        }
    }

    pub const fn route_capacity(self) -> usize {
        self.route_capacity
    }

    pub const fn queue_capacity(self) -> usize {
        self.queue_capacity
    }

    pub const fn inflight_capacity(self) -> usize {
        self.inflight_capacity
    }

    pub const fn payload_capacity_bytes(self) -> usize {
        self.payload_capacity_bytes
    }

    fn validate(self) -> Result<Self, AgentSupervisorError> {
        if self.route_capacity == 0
            || self.queue_capacity == 0
            || self.inflight_capacity == 0
            || self.payload_capacity_bytes == 0
        {
            return Err(AgentSupervisorError::InvalidLimits);
        }
        Ok(self)
    }
}

impl Default for AgentSupervisorLimits {
    fn default() -> Self {
        Self::new(
            DEFAULT_AGENT_SUPERVISOR_ROUTE_CAPACITY,
            DEFAULT_AGENT_SUPERVISOR_QUEUE_CAPACITY,
            DEFAULT_AGENT_SUPERVISOR_INFLIGHT_CAPACITY,
            DEFAULT_AGENT_SUPERVISOR_PAYLOAD_CAPACITY_BYTES,
        )
    }
}

/// Opaque failure classes returned by a concrete route adapter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AgentRouteError {
    NotReady,
    Rejected,
    Unavailable,
}

/// Terminal outcome reported by an explicitly owned route worker.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AgentRouteWorkerError {
    Failed,
    Panicked,
}

/// Stable errors exposed by the supervisor boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AgentSupervisorError {
    InvalidLimits,
    InvalidIdentity,
    EmptyAttachment,
    RouteCapacityExceeded,
    DuplicateRoute,
    ProfileAmbiguity,
    GenerationExhausted,
    NotFound,
    StaleSnapshot,
    Busy,
    InflightBackpressure,
    PayloadTooLarge,
    PayloadBackpressure,
    Closed,
    OwnerFailed,
    ReconcileMismatch,
    Route(AgentRouteError),
    RoutePanicked,
    Worker(AgentRouteWorkerError),
}

impl fmt::Display for AgentSupervisorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "agent supervisor failed: {self:?}")
    }
}

impl std::error::Error for AgentSupervisorError {}

/// The only lookup key accepted by the supervisor.
///
/// In particular, there is no projected service namespace and no lookup by
/// Agent or Actor alone.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AgentRouteKey {
    space: SpaceId,
    agent: AgentId,
    actor: ActorId,
}

impl AgentRouteKey {
    pub fn new(
        space: SpaceId,
        agent: AgentId,
        actor: ActorId,
    ) -> Result<Self, AgentSupervisorError> {
        if space == SpaceId::ZERO || agent == AgentId::ZERO || actor == ActorId::ZERO {
            return Err(AgentSupervisorError::InvalidIdentity);
        }
        Ok(Self {
            space,
            agent,
            actor,
        })
    }

    pub const fn space(self) -> SpaceId {
        self.space
    }

    pub const fn agent(self) -> AgentId {
        self.agent
    }

    pub const fn actor(self) -> ActorId {
        self.actor
    }
}

/// Exact immutable identity a concrete adapter claims it can route.
///
/// The Agent runtime deployment is deliberately distinct from the actor
/// deployment/program identity. An Agent runtime upgrade therefore produces a
/// different snapshot even when the actor's own installation is unchanged.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AgentRouteIdentity {
    key: AgentRouteKey,
    incarnation: Hash,
    runtime_deployment: DeploymentId,
    actor_deployment: DeploymentId,
    actor_program: ProgramId,
    profile: AgentProfile,
}

impl AgentRouteIdentity {
    pub fn new(
        key: AgentRouteKey,
        incarnation: Hash,
        runtime_deployment: DeploymentId,
        actor_deployment: DeploymentId,
        actor_program: ProgramId,
        profile: AgentProfile,
    ) -> Result<Self, AgentSupervisorError> {
        if incarnation == Hash::ZERO
            || runtime_deployment == DeploymentId::ZERO
            || actor_deployment == DeploymentId::ZERO
            || actor_program == ProgramId::ZERO
        {
            return Err(AgentSupervisorError::InvalidIdentity);
        }
        Ok(Self {
            key,
            incarnation,
            runtime_deployment,
            actor_deployment,
            actor_program,
            profile,
        })
    }

    pub const fn key(self) -> AgentRouteKey {
        self.key
    }

    pub const fn incarnation(self) -> Hash {
        self.incarnation
    }

    pub const fn runtime_deployment(self) -> DeploymentId {
        self.runtime_deployment
    }

    pub const fn actor_deployment(self) -> DeploymentId {
        self.actor_deployment
    }

    pub const fn actor_program(self) -> ProgramId {
        self.actor_program
    }

    pub const fn profile(self) -> AgentProfile {
        self.profile
    }
}

/// A supervisor-minted generation proving one exact reconciliation completed.
///
/// Generations are never caller-selected or reused during a supervisor
/// lifetime, including when readiness reconciliation fails.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AgentRouteReadinessGeneration(NonZeroU64);

impl AgentRouteReadinessGeneration {
    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

/// Immutable, dispatchable route identity returned by [`AgentSupervisorHandle`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AgentRouteSnapshot {
    identity: AgentRouteIdentity,
    readiness_generation: AgentRouteReadinessGeneration,
}

impl AgentRouteSnapshot {
    pub const fn identity(self) -> AgentRouteIdentity {
        self.identity
    }

    pub const fn key(self) -> AgentRouteKey {
        self.identity.key
    }

    pub const fn incarnation(self) -> Hash {
        self.identity.incarnation
    }

    pub const fn runtime_deployment(self) -> DeploymentId {
        self.identity.runtime_deployment
    }

    pub const fn actor_deployment(self) -> DeploymentId {
        self.identity.actor_deployment
    }

    pub const fn actor_program(self) -> ProgramId {
        self.identity.actor_program
    }

    pub const fn profile(self) -> AgentProfile {
        self.identity.profile
    }

    pub const fn readiness_generation(self) -> AgentRouteReadinessGeneration {
        self.readiness_generation
    }
}

/// Narrow object-safe adapter implemented by a Local, Shared, Private, or
/// system host.
///
/// `reconcile` must report the exact proposed snapshots after checking its
/// durable state and worker readiness. The supervisor compares the returned
/// vector byte-for-field and publishes the complete attachment in one atomic
/// registry replacement. Accepted dispatches run on bounded execution workers.
/// One Agent is ordered across its actor routes and attachments; each adapter
/// also retains exclusive mutable access while a dispatch is executing.
pub trait AgentRoute: Send + 'static {
    fn reconcile(
        &mut self,
        proposed: &[AgentRouteSnapshot],
    ) -> Result<Vec<AgentRouteSnapshot>, AgentRouteError>;

    fn dispatch(
        &mut self,
        route: &AgentRouteSnapshot,
        payload: &[u8],
    ) -> Result<Vec<u8>, AgentRouteError>;
}

/// Exclusive lifecycle ownership for every worker reachable through a route
/// attachment.
///
/// The supervisor always removes the attachment's snapshots before calling
/// `request_retire`, and always calls `join`, even if retirement reports an
/// error or panics.
pub trait AgentRouteWorkerOwner: Send + 'static {
    fn request_retire(&mut self) -> Result<(), AgentRouteWorkerError>;
    fn join(self: Box<Self>) -> Result<(), AgentRouteWorkerError>;
}

/// One atomically published group of routes and its explicitly owned worker.
pub struct AgentRouteAttachment {
    identities: Vec<AgentRouteIdentity>,
    route: Box<dyn AgentRoute>,
    worker: Option<Box<dyn AgentRouteWorkerOwner>>,
}

impl fmt::Debug for AgentRouteAttachment {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AgentRouteAttachment")
            .field("identities", &self.identities)
            .field("owns_worker", &self.worker.is_some())
            .finish_non_exhaustive()
    }
}

impl AgentRouteAttachment {
    pub fn new<R, W>(identities: Vec<AgentRouteIdentity>, route: R, worker: W) -> Self
    where
        R: AgentRoute,
        W: AgentRouteWorkerOwner,
    {
        Self::from_boxed(identities, Box::new(route), Box::new(worker))
    }

    pub fn from_boxed(
        identities: Vec<AgentRouteIdentity>,
        route: Box<dyn AgentRoute>,
        worker: Box<dyn AgentRouteWorkerOwner>,
    ) -> Self {
        Self {
            identities,
            route,
            worker: Some(worker),
        }
    }

    pub fn identities(&self) -> &[AgentRouteIdentity] {
        &self.identities
    }

    pub(crate) fn replace_identities(&mut self, identities: Vec<AgentRouteIdentity>) {
        self.identities = identities;
    }
}

/// Token naming one complete atomic publication.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentRoutePublication {
    generation: AgentRouteReadinessGeneration,
    snapshots: Vec<AgentRouteSnapshot>,
}

impl AgentRoutePublication {
    pub const fn generation(&self) -> AgentRouteReadinessGeneration {
        self.generation
    }

    pub fn snapshots(&self) -> &[AgentRouteSnapshot] {
        &self.snapshots
    }
}

#[derive(Clone)]
struct PublishedRoute {
    snapshot: AgentRouteSnapshot,
    attachment: AgentRouteReadinessGeneration,
}

type PublishedRoutes = BTreeMap<AgentRouteKey, PublishedRoute>;

struct SupervisorShared {
    commands: SyncSender<Command>,
    state: AtomicU8,
    admission: Mutex<()>,
    published: RwLock<Arc<PublishedRoutes>>,
    inflight: AtomicUsize,
    admitted_payload_bytes: AtomicUsize,
    queued_dispatches: AtomicUsize,
    limits: AgentSupervisorLimits,
}

impl SupervisorShared {
    fn publish(&self, routes: PublishedRoutes) {
        let mut published = self
            .published
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *published = Arc::new(routes);
    }

    fn clear_publication(&self) {
        self.publish(PublishedRoutes::new());
    }

    fn published(&self) -> Result<Arc<PublishedRoutes>, AgentSupervisorError> {
        self.published
            .read()
            .map(|published| published.clone())
            .map_err(|_| AgentSupervisorError::OwnerFailed)
    }
}

/// Cloneable, bounded dispatch and immutable-snapshot handle.
///
/// This handle cannot attach, replace, unpublish, stop, or join a worker. A
/// cloned handle becomes terminal when its sole [`AgentSupervisorOwner`]
/// begins shutdown.
#[derive(Clone)]
pub struct AgentSupervisorHandle {
    shared: Arc<SupervisorShared>,
}

impl fmt::Debug for AgentSupervisorHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AgentSupervisorHandle")
            .field("running", &self.is_running())
            .field("limits", &self.shared.limits)
            .finish_non_exhaustive()
    }
}

impl AgentSupervisorHandle {
    /// Crate-private cancellation for the node's separately owned control worker.
    pub(crate) fn request_shutdown(&self) {
        let admission = self.shared.admission.lock();
        let _admission = match admission {
            Ok(admission) => admission,
            Err(poisoned) => poisoned.into_inner(),
        };
        if self.shared.state.compare_exchange(
            SUPERVISOR_RUNNING, SUPERVISOR_CLOSING, Ordering::AcqRel, Ordering::Acquire,
        ).is_ok() {
            self.shared.clear_publication();
            let _ = self.shared.commands.try_send(Command::Wake);
        }
    }

    pub fn is_running(&self) -> bool {
        self.shared.state.load(Ordering::Acquire) == SUPERVISOR_RUNNING
    }

    /// Resolve only a complete `(SpaceId, AgentId, ActorId)` key.
    pub fn snapshot(&self, key: AgentRouteKey) -> Result<AgentRouteSnapshot, AgentSupervisorError> {
        let state = self.shared.state.load(Ordering::Acquire);
        if state != SUPERVISOR_RUNNING {
            return Err(terminal_error(state));
        }
        let snapshot = self
            .shared
            .published()?
            .get(&key)
            .map(|published| published.snapshot);
        let state = self.shared.state.load(Ordering::Acquire);
        if state != SUPERVISOR_RUNNING {
            return Err(terminal_error(state));
        }
        snapshot.ok_or(AgentSupervisorError::NotFound)
    }

    /// Read all currently published snapshots in full-key canonical order.
    pub fn snapshots(&self) -> Result<Vec<AgentRouteSnapshot>, AgentSupervisorError> {
        let state = self.shared.state.load(Ordering::Acquire);
        if state != SUPERVISOR_RUNNING {
            return Err(terminal_error(state));
        }
        let snapshots = self
            .shared
            .published()?
            .values()
            .map(|published| published.snapshot)
            .collect();
        let state = self.shared.state.load(Ordering::Acquire);
        if state != SUPERVISOR_RUNNING {
            return Err(terminal_error(state));
        }
        Ok(snapshots)
    }

    /// Dispatch against one exact, still-current readiness snapshot.
    ///
    /// Both `Vec::len` and owned `Vec::capacity` must fit the aggregate byte
    /// limit so spare allocation cannot bypass queue accounting.
    pub fn dispatch(
        &self,
        snapshot: AgentRouteSnapshot,
        payload: Vec<u8>,
    ) -> Result<Vec<u8>, AgentSupervisorError> {
        let payload_bytes = payload.capacity().max(payload.len());
        let reservation = DispatchReservation::acquire(self.shared.clone(), payload_bytes)?;
        let (reply, result) = mpsc::sync_channel(1);
        {
            let _admission = self
                .shared
                .admission
                .lock()
                .map_err(|_| AgentSupervisorError::OwnerFailed)?;
            let state = self.shared.state.load(Ordering::Acquire);
            if state != SUPERVISOR_RUNNING {
                return Err(terminal_error(state));
            }
            let routes = self.shared.published()?;
            if routes
                .get(&snapshot.key())
                .is_none_or(|current| current.snapshot != snapshot)
            {
                return Err(AgentSupervisorError::StaleSnapshot);
            }
            reserve_counter(
                &self.shared.queued_dispatches,
                1,
                self.shared.limits.queue_capacity,
            )
            .map_err(|_| AgentSupervisorError::Busy)?;
            match self.shared.commands.try_send(Command::Dispatch {
                snapshot,
                payload,
                reply,
                admitted_at: std::time::Instant::now(),
            }) {
                Ok(()) => {}
                Err(TrySendError::Full(_)) => {
                    self.shared.queued_dispatches.fetch_sub(1, Ordering::AcqRel);
                    return Err(AgentSupervisorError::Busy);
                }
                Err(TrySendError::Disconnected(_)) => {
                    self.shared.queued_dispatches.fetch_sub(1, Ordering::AcqRel);
                    fail_closed_while_admitted(&self.shared);
                    return Err(AgentSupervisorError::OwnerFailed);
                }
            }
        }
        let result = result.recv().unwrap_or_else(|_| {
            let state = self.shared.state.load(Ordering::Acquire);
            if state == SUPERVISOR_CLOSING || state == SUPERVISOR_CLOSED {
                Err(AgentSupervisorError::Closed)
            } else {
                fail_closed(&self.shared);
                Err(AgentSupervisorError::OwnerFailed)
            }
        });
        drop(reservation);
        result
    }

    #[cfg(test)]
    fn queued_dispatches_for_test(&self) -> usize {
        self.shared.queued_dispatches.load(Ordering::Acquire)
    }

    #[cfg(test)]
    fn crash_worker_for_test(&self) -> Result<(), AgentSupervisorError> {
        let (reply, result) = mpsc::sync_channel(0);
        self.shared
            .commands
            .try_send(Command::Crash(reply))
            .map_err(|error| match error {
                TrySendError::Full(_) => AgentSupervisorError::Busy,
                TrySendError::Disconnected(_) => AgentSupervisorError::OwnerFailed,
            })?;
        result.recv().map_err(|_| AgentSupervisorError::OwnerFailed)
    }
}

struct DispatchReservation {
    shared: Arc<SupervisorShared>,
    payload_bytes: usize,
}

impl DispatchReservation {
    fn acquire(
        shared: Arc<SupervisorShared>,
        payload_bytes: usize,
    ) -> Result<Self, AgentSupervisorError> {
        if payload_bytes > shared.limits.payload_capacity_bytes {
            return Err(AgentSupervisorError::PayloadTooLarge);
        }
        reserve_counter(&shared.inflight, 1, shared.limits.inflight_capacity)
            .map_err(|_| AgentSupervisorError::InflightBackpressure)?;
        if reserve_counter(
            &shared.admitted_payload_bytes,
            payload_bytes,
            shared.limits.payload_capacity_bytes,
        )
        .is_err()
        {
            shared.inflight.fetch_sub(1, Ordering::AcqRel);
            return Err(AgentSupervisorError::PayloadBackpressure);
        }
        Ok(Self {
            shared,
            payload_bytes,
        })
    }
}

impl Drop for DispatchReservation {
    fn drop(&mut self) {
        self.shared
            .admitted_payload_bytes
            .fetch_sub(self.payload_bytes, Ordering::AcqRel);
        self.shared.inflight.fetch_sub(1, Ordering::AcqRel);
    }
}

fn reserve_counter(counter: &AtomicUsize, amount: usize, capacity: usize) -> Result<(), ()> {
    let mut current = counter.load(Ordering::Acquire);
    loop {
        let next = current.checked_add(amount).ok_or(())?;
        if next > capacity {
            return Err(());
        }
        match counter.compare_exchange_weak(current, next, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => return Ok(()),
            Err(observed) => current = observed,
        }
    }
}

/// Sole lifecycle owner for the supervisor and every attached route worker.
pub struct AgentSupervisorOwner {
    handle: AgentSupervisorHandle,
    worker: Option<JoinHandle<()>>,
}

impl fmt::Debug for AgentSupervisorOwner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AgentSupervisorOwner")
            .field("running", &self.handle.is_running())
            .finish_non_exhaustive()
    }
}

impl AgentSupervisorOwner {
    pub fn start(limits: AgentSupervisorLimits) -> Result<Self, AgentSupervisorError> {
        let limits = limits.validate()?;
        let (commands, receiver) = mpsc::sync_channel(limits.queue_capacity);
        let shared = Arc::new(SupervisorShared {
            commands,
            state: AtomicU8::new(SUPERVISOR_RUNNING),
            admission: Mutex::new(()),
            published: RwLock::new(Arc::new(PublishedRoutes::new())),
            inflight: AtomicUsize::new(0),
            admitted_payload_bytes: AtomicUsize::new(0),
            queued_dispatches: AtomicUsize::new(0),
            limits,
        });
        let worker_shared = shared.clone();
        let (ready, started) = mpsc::sync_channel(0);
        let worker = thread::Builder::new()
            .name("vos-agent-supervisor".into())
            .spawn(move || supervisor_thread(receiver, worker_shared, ready))
            .map_err(|_| AgentSupervisorError::OwnerFailed)?;
        if started.recv().is_err() {
            fail_closed(&shared);
            let _ = worker.join();
            return Err(AgentSupervisorError::OwnerFailed);
        }
        Ok(Self {
            handle: AgentSupervisorHandle { shared },
            worker: Some(worker),
        })
    }

    pub fn handle(&self) -> AgentSupervisorHandle {
        self.handle.clone()
    }

    /// Reconcile and atomically publish every route in one attachment.
    pub fn attach(
        &mut self,
        attachment: AgentRouteAttachment,
    ) -> Result<AgentRoutePublication, AgentSupervisorError> {
        let state = self.handle.shared.state.load(Ordering::Acquire);
        if state != SUPERVISOR_RUNNING {
            return Err(retirement_error(
                terminal_error(state),
                retire_unpublished(attachment),
            ));
        }
        let (reply, result) = mpsc::sync_channel(1);
        match self
            .handle
            .shared
            .commands
            .try_send(Command::Attach { attachment, reply })
        {
            Ok(()) => result.recv().unwrap_or_else(|_| {
                fail_closed(&self.handle.shared);
                Err(AgentSupervisorError::OwnerFailed)
            }),
            Err(TrySendError::Full(Command::Attach { attachment, .. })) => Err(retirement_error(
                AgentSupervisorError::Busy,
                retire_unpublished(attachment),
            )),
            Err(TrySendError::Disconnected(Command::Attach { attachment, .. })) => {
                fail_closed(&self.handle.shared);
                Err(retirement_error(
                    AgentSupervisorError::OwnerFailed,
                    retire_unpublished(attachment),
                ))
            }
            Err(_) => unreachable!("try_send preserved the Attach command variant"),
        }
    }

    /// Reconcile a live attachment against a replacement identity projection
    /// and atomically swap every route to one fresh readiness generation.
    ///
    /// The old snapshots remain visible while the adapter validates the
    /// complete replacement. Any adapter failure retires the attachment
    /// fail-closed; a successful replacement has no partially published
    /// intermediate state. Refresh validation runs on a bounded maintenance
    /// worker. Dispatch to old/proposed Agent lanes is refused until the
    /// lifecycle barrier completes; unrelated Agent lanes remain runnable.
    pub fn refresh(
        &mut self,
        publication: &AgentRoutePublication,
        identities: Vec<AgentRouteIdentity>,
    ) -> Result<AgentRoutePublication, AgentSupervisorError> {
        let state = self.handle.shared.state.load(Ordering::Acquire);
        if state != SUPERVISOR_RUNNING {
            return Err(terminal_error(state));
        }
        let (reply, result) = mpsc::sync_channel(1);
        match self.handle.shared.commands.try_send(Command::Refresh {
            publication: publication.clone(),
            identities,
            reply,
        }) {
            Ok(()) => result.recv().unwrap_or_else(|_| {
                fail_closed(&self.handle.shared);
                Err(AgentSupervisorError::OwnerFailed)
            }),
            Err(TrySendError::Full(_)) => Err(AgentSupervisorError::Busy),
            Err(TrySendError::Disconnected(_)) => {
                fail_closed(&self.handle.shared);
                Err(AgentSupervisorError::OwnerFailed)
            }
        }
    }

    /// Atomically unpublish a complete attachment, then retire and join it.
    pub fn detach(
        &mut self,
        publication: &AgentRoutePublication,
    ) -> Result<(), AgentSupervisorError> {
        let state = self.handle.shared.state.load(Ordering::Acquire);
        if state != SUPERVISOR_RUNNING {
            return Err(terminal_error(state));
        }
        let (reply, result) = mpsc::sync_channel(1);
        match self.handle.shared.commands.try_send(Command::Detach {
            publication: publication.clone(),
            reply,
        }) {
            Ok(()) => result.recv().unwrap_or_else(|_| {
                fail_closed(&self.handle.shared);
                Err(AgentSupervisorError::OwnerFailed)
            }),
            Err(TrySendError::Full(_)) => Err(AgentSupervisorError::Busy),
            Err(TrySendError::Disconnected(_)) => {
                fail_closed(&self.handle.shared);
                Err(AgentSupervisorError::OwnerFailed)
            }
        }
    }

    /// Stop admission and synchronously hide every route. Worker retirement
    /// and joins are completed by [`Self::shutdown_and_join`] or `Drop`.
    pub fn request_shutdown(&self) {
        self.handle.request_shutdown();
    }

    pub fn shutdown_and_join(mut self) -> Result<(), AgentSupervisorError> {
        self.request_shutdown();
        self.join_worker()
    }

    fn join_worker(&mut self) -> Result<(), AgentSupervisorError> {
        let Some(worker) = self.worker.take() else {
            return match self.handle.shared.state.load(Ordering::Acquire) {
                SUPERVISOR_CLOSED => Ok(()),
                _ => Err(AgentSupervisorError::OwnerFailed),
            };
        };
        if worker.join().is_err() {
            fail_closed(&self.handle.shared);
        }
        match self.handle.shared.state.load(Ordering::Acquire) {
            SUPERVISOR_CLOSED => Ok(()),
            _ => Err(AgentSupervisorError::OwnerFailed),
        }
    }
}

impl Drop for AgentSupervisorOwner {
    fn drop(&mut self) {
        self.request_shutdown();
        let _ = self.join_worker();
    }
}

enum Command {
    Attach {
        attachment: AgentRouteAttachment,
        reply: SyncSender<Result<AgentRoutePublication, AgentSupervisorError>>,
    },
    Refresh {
        publication: AgentRoutePublication,
        identities: Vec<AgentRouteIdentity>,
        reply: SyncSender<Result<AgentRoutePublication, AgentSupervisorError>>,
    },
    Detach {
        publication: AgentRoutePublication,
        reply: SyncSender<Result<(), AgentSupervisorError>>,
    },
    Dispatch {
        snapshot: AgentRouteSnapshot,
        payload: Vec<u8>,
        reply: SyncSender<Result<Vec<u8>, AgentSupervisorError>>,
        admitted_at: std::time::Instant,
    },
    Wake,
    #[cfg(test)]
    Crash(SyncSender<()>),
}

struct ActiveAttachment {
    snapshots: Vec<AgentRouteSnapshot>,
    route: Option<Box<dyn AgentRoute>>,
    worker: Option<Box<dyn AgentRouteWorkerOwner>>,
}

struct PendingDispatch {
    snapshot: AgentRouteSnapshot,
    payload: Vec<u8>,
    reply: SyncSender<Result<Vec<u8>, AgentSupervisorError>>,
    admitted_at: std::time::Instant,
    attachment: AgentRouteReadinessGeneration,
}

struct CompletedDispatch {
    pending: PendingDispatch,
    ticket: lanes::Ticket,
    route: Box<dyn AgentRoute>,
    result: Result<Vec<u8>, AgentSupervisorError>,
}

struct ActiveRefresh {
    old_generation: AgentRouteReadinessGeneration,
    lanes: BTreeSet<lanes::Lane>,
}

struct CompletedRefresh {
    old_generation: AgentRouteReadinessGeneration,
    generation: AgentRouteReadinessGeneration,
    snapshots: Vec<AgentRouteSnapshot>,
    route: Box<dyn AgentRoute>,
    result: Result<(), AgentSupervisorError>,
    reply: SyncSender<Result<AgentRoutePublication, AgentSupervisorError>>,
}

struct SupervisorWorker {
    routes: PublishedRoutes,
    attachments: BTreeMap<AgentRouteReadinessGeneration, ActiveAttachment>,
    next_generation: u64,
    dispatches: lanes::Scheduler<PendingDispatch>,
    pool: Option<lanes::Pool<CompletedDispatch>>,
    // One outstanding refresh reserves its proposed identities. Attach and
    // other refresh commands wait in bounded deferred control storage, so no
    // competing publication can invalidate that reservation before commit.
    refresh_pool: Option<lanes::Pool<CompletedRefresh>>,
    refreshing: Option<ActiveRefresh>,
    deferred: std::collections::VecDeque<Command>,
}

impl SupervisorWorker {
    fn new(limits: AgentSupervisorLimits) -> Self {
        Self {
            routes: PublishedRoutes::new(),
            attachments: BTreeMap::new(),
            next_generation: 1,
            dispatches: lanes::Scheduler::new(limits.inflight_capacity, Self::worker_count(limits)),
            pool: None,
            refresh_pool: None,
            refreshing: None,
            deferred: std::collections::VecDeque::new(),
        }
    }

    fn worker_count(limits: AgentSupervisorLimits) -> usize {
        std::thread::available_parallelism()
            .map_or(2, usize::from)
            .max(2)
            .min(limits.inflight_capacity)
    }

    fn run(&mut self, receiver: &Receiver<Command>, shared: &SupervisorShared) -> WorkerExit {
        loop {
            if self.collect_refresh_completions(shared).is_err()
                || self.collect_completions(shared).is_err()
                || self.start_dispatches(shared).is_err()
            {
                return WorkerExit::Failed;
            }
            let state = shared.state.load(Ordering::Acquire);
            if state != SUPERVISOR_RUNNING {
                return if state == SUPERVISOR_CLOSING {
                    WorkerExit::Closing
                } else {
                    WorkerExit::Failed
                };
            }
            let ready_control = self
                .deferred
                .iter()
                .position(|command| !self.control_busy(command));
            let command = match ready_control.map(|index| self.deferred.remove(index).unwrap()) {
                Some(command) => command,
                None => match receiver.recv() {
                    Ok(command) => command,
                    Err(_) => return WorkerExit::Failed,
                },
            };
            let state = shared.state.load(Ordering::Acquire);
            if state != SUPERVISOR_RUNNING {
                let terminal = terminal_error(state);
                return if reject_command(command, shared, terminal).is_ok()
                    && state == SUPERVISOR_CLOSING
                {
                    WorkerExit::Closing
                } else {
                    WorkerExit::Failed
                };
            }
            if self.control_busy(&command) {
                if self.deferred.len() >= shared.limits.queue_capacity {
                    if reject_command(command, shared, AgentSupervisorError::Busy).is_err() {
                        return WorkerExit::Failed;
                    }
                } else {
                    if let Command::Refresh { publication, .. }
                    | Command::Detach { publication, .. } = &command
                    {
                        self.cancel_attachment_dispatches(publication.generation, shared);
                    }
                    self.deferred.push_back(command);
                }
                continue;
            }
            match command {
                Command::Attach { attachment, reply } => {
                    let result = self.attach(attachment, shared);
                    let _ = reply.send(result);
                }
                Command::Refresh {
                    publication,
                    identities,
                    reply,
                } => {
                    if let Err(error) =
                        self.begin_refresh(publication, identities, reply.clone(), shared)
                    {
                        let _ = reply.send(Err(error));
                    }
                }
                Command::Detach { publication, reply } => {
                    let result = self.detach(publication, shared);
                    let _ = reply.send(result);
                }
                Command::Dispatch {
                    snapshot,
                    payload,
                    reply,
                    admitted_at,
                } => {
                    let published = self
                        .routes
                        .get(&snapshot.key())
                        .filter(|route| route.snapshot == snapshot);
                    if let Some(published) = published {
                        let pending = PendingDispatch {
                            snapshot,
                            payload,
                            reply,
                            admitted_at,
                            attachment: published.attachment,
                        };
                        let closing = self
                            .lane_blocked(lanes::Lane(snapshot.key().space, snapshot.key().agent));
                        if closing {
                            shared.queued_dispatches.fetch_sub(1, Ordering::AcqRel);
                            let _ = pending.reply.send(Err(AgentSupervisorError::StaleSnapshot));
                        } else if let Err(pending) = self.dispatches.submit(
                            lanes::Lane(snapshot.key().space, snapshot.key().agent),
                            pending,
                        ) {
                            shared.queued_dispatches.fetch_sub(1, Ordering::AcqRel);
                            let _ = pending.reply.send(Err(AgentSupervisorError::Busy));
                        }
                    } else {
                        shared.queued_dispatches.fetch_sub(1, Ordering::AcqRel);
                        let _ = reply.send(Err(AgentSupervisorError::StaleSnapshot));
                    }
                }
                Command::Wake => {}
                #[cfg(test)]
                Command::Crash(ready) => {
                    let _ = ready.send(());
                    panic!("intentional Agent supervisor worker crash");
                }
            }
        }
    }

    fn publication_busy(&self, publication: &AgentRoutePublication) -> bool {
        if self.refreshing.as_ref().is_some_and(|refresh| {
            refresh.old_generation == publication.generation
                || publication.snapshots.iter().any(|snapshot| {
                    refresh
                        .lanes
                        .contains(&lanes::Lane(snapshot.key().space, snapshot.key().agent))
                })
        }) {
            return true;
        }
        self.attachments.contains_key(&publication.generation)
            && publication.snapshots.iter().any(|snapshot| {
                self.dispatches
                    .is_active(lanes::Lane(snapshot.key().space, snapshot.key().agent))
            })
    }

    fn control_busy(&self, command: &Command) -> bool {
        match command {
            Command::Attach { .. } => self.refreshing.is_some(),
            Command::Refresh {
                publication,
                identities,
                ..
            } => {
                self.refreshing.is_some()
                    || self.publication_busy(publication)
                    || identities.iter().any(|identity| {
                        self.dispatches
                            .is_active(lanes::Lane(identity.key.space, identity.key.agent))
                    })
            }
            Command::Detach { publication, .. } => self.publication_busy(publication),
            _ => false,
        }
    }

    fn lane_blocked(&self, lane: lanes::Lane) -> bool {
        Self::lane_blocked_by(self.refreshing.as_ref(), &self.deferred, lane)
    }

    fn lane_blocked_by(
        refreshing: Option<&ActiveRefresh>,
        deferred: &std::collections::VecDeque<Command>,
        lane: lanes::Lane,
    ) -> bool {
        refreshing.is_some_and(|refresh| refresh.lanes.contains(&lane))
            || deferred.iter().any(|command| {
                let publication = match command {
                    Command::Refresh {
                        publication,
                        identities,
                        ..
                    } => {
                        if identities.iter().any(|identity| {
                            lanes::Lane(identity.key.space, identity.key.agent) == lane
                        }) {
                            return true;
                        }
                        publication
                    }
                    Command::Detach { publication, .. } => publication,
                    _ => return false,
                };
                publication
                    .snapshots
                    .iter()
                    .any(|snapshot| lanes::Lane(snapshot.key().space, snapshot.key().agent) == lane)
            })
    }

    fn cancel_attachment_dispatches(
        &mut self,
        generation: AgentRouteReadinessGeneration,
        shared: &SupervisorShared,
    ) {
        for pending in self
            .dispatches
            .cancel_where(|job| job.attachment == generation)
        {
            shared.queued_dispatches.fetch_sub(1, Ordering::AcqRel);
            let _ = pending.reply.send(Err(AgentSupervisorError::StaleSnapshot));
        }
    }

    fn start_dispatches(&mut self, shared: &SupervisorShared) -> Result<(), ()> {
        if shared.state.load(Ordering::Acquire) != SUPERVISOR_RUNNING {
            return Ok(());
        }
        while let Some(ready) = self.dispatches.next_where(|pending| {
            self.attachments
                .get(&pending.attachment)
                .is_none_or(|active| active.route.is_some())
                && !Self::lane_blocked_by(
                    self.refreshing.as_ref(),
                    &self.deferred,
                    lanes::Lane(pending.snapshot.key().space, pending.snapshot.key().agent),
                )
        }) {
            shared.queued_dispatches.fetch_sub(1, Ordering::AcqRel);
            let pending = ready.job;
            let Some(active) = self.attachments.get_mut(&pending.attachment) else {
                self.dispatches.complete(ready.ticket);
                let _ = pending.reply.send(Err(AgentSupervisorError::StaleSnapshot));
                continue;
            };
            if self.pool.is_none() {
                let commands = shared.commands.clone();
                self.pool = Some(
                    lanes::Pool::with_wake(
                        Self::worker_count(shared.limits),
                        shared.limits.inflight_capacity,
                        move || {
                            let _ = commands.try_send(Command::Wake);
                        },
                    )
                    .map_err(|_| ())?,
                );
            }
            let mut route = active.route.take().ok_or(())?;
            let limit = shared.limits.payload_capacity_bytes;
            let ticket = ready.ticket;
            let job = Box::new(move || {
                let started = std::time::Instant::now();
                let queue_wait_us = started.duration_since(pending.admitted_at).as_micros();
                let result = match panic::catch_unwind(AssertUnwindSafe(|| {
                    route.dispatch(&pending.snapshot, &pending.payload)
                })) {
                    Ok(Ok(output)) if output.len() <= limit && output.capacity() <= limit => {
                        Ok(output)
                    }
                    Ok(Ok(_)) => Err(AgentSupervisorError::PayloadTooLarge),
                    Ok(Err(error)) => Err(AgentSupervisorError::Route(error)),
                    Err(_) => Err(AgentSupervisorError::RoutePanicked),
                };
                tracing::debug!(
                    queue_wait_us,
                    service_us = started.elapsed().as_micros(),
                    payload_bytes = pending.payload.len(),
                    succeeded = result.is_ok(),
                    "Agent supervisor dispatch completed"
                );
                CompletedDispatch {
                    pending,
                    ticket,
                    route,
                    result,
                }
            });
            self.pool.as_ref().unwrap().submit(job).map_err(|_| ())?;
        }
        Ok(())
    }

    fn collect_completions(&mut self, shared: &SupervisorShared) -> Result<(), ()> {
        loop {
            let Some(pool) = self.pool.as_ref() else {
                return Ok(());
            };
            match pool.completions.try_recv() {
                Ok(Ok(completed)) => self.finish_dispatch(completed, shared)?,
                Ok(Err(())) => return Err(()),
                Err(TryRecvError::Empty) => return Ok(()),
                Err(TryRecvError::Disconnected) => return Err(()),
            }
        }
    }

    fn finish_dispatch(
        &mut self,
        completed: CompletedDispatch,
        shared: &SupervisorShared,
    ) -> Result<(), ()> {
        let CompletedDispatch {
            pending,
            ticket,
            route,
            mut result,
        } = completed;
        if !self.dispatches.complete(ticket) {
            return Err(());
        }
        let active = self.attachments.get_mut(&pending.attachment).ok_or(())?;
        if active.route.replace(route).is_some() {
            return Err(());
        }
        if let Err(error) = result {
            if error != AgentSupervisorError::Route(AgentRouteError::Rejected) {
                self.cancel_attachment_dispatches(pending.attachment, shared);
                result = Err(self.fail_attachment(pending.attachment, shared, error));
            }
        }
        let _ = pending.reply.send(result);
        Ok(())
    }

    fn attach(
        &mut self,
        mut attachment: AgentRouteAttachment,
        shared: &SupervisorShared,
    ) -> Result<AgentRoutePublication, AgentSupervisorError> {
        let preparation = self.prepare_snapshots(&mut attachment, shared);
        let (generation, snapshots) = match preparation {
            Ok(prepared) => prepared,
            Err(error) => {
                return Err(retirement_error(error, retire_unpublished(attachment)));
            }
        };

        let reconciled =
            panic::catch_unwind(AssertUnwindSafe(|| attachment.route.reconcile(&snapshots)));
        match reconciled {
            Ok(Ok(actual)) if actual == snapshots => {}
            Ok(Ok(_)) => {
                return Err(retirement_error(
                    AgentSupervisorError::ReconcileMismatch,
                    retire_unpublished(attachment),
                ));
            }
            Ok(Err(error)) => {
                return Err(retirement_error(
                    AgentSupervisorError::Route(error),
                    retire_unpublished(attachment),
                ));
            }
            Err(_) => {
                return Err(retirement_error(
                    AgentSupervisorError::RoutePanicked,
                    retire_unpublished(attachment),
                ));
            }
        }

        let publication = AgentRoutePublication {
            generation,
            snapshots: snapshots.clone(),
        };
        let admission = shared.admission.lock();
        let _admission = match admission {
            Ok(admission) => admission,
            Err(_) => {
                return Err(retirement_error(
                    AgentSupervisorError::OwnerFailed,
                    retire_unpublished(attachment),
                ));
            }
        };
        let state = shared.state.load(Ordering::Acquire);
        if state != SUPERVISOR_RUNNING {
            drop(_admission);
            return Err(retirement_error(
                terminal_error(state),
                retire_unpublished(attachment),
            ));
        }

        let mut next = self.routes.clone();
        for snapshot in &snapshots {
            let replaced = next.insert(
                snapshot.key(),
                PublishedRoute {
                    snapshot: *snapshot,
                    attachment: generation,
                },
            );
            debug_assert!(replaced.is_none());
        }
        let active = ActiveAttachment {
            snapshots,
            route: Some(attachment.route),
            worker: attachment.worker.take(),
        };
        let replaced = self.attachments.insert(generation, active);
        debug_assert!(replaced.is_none());
        self.routes = next;
        shared.publish(self.routes.clone());
        Ok(publication)
    }

    fn prepare_snapshots(
        &mut self,
        attachment: &mut AgentRouteAttachment,
        shared: &SupervisorShared,
    ) -> Result<(AgentRouteReadinessGeneration, Vec<AgentRouteSnapshot>), AgentSupervisorError>
    {
        self.prepare_projected_snapshots(&mut attachment.identities, None, shared)
    }

    fn prepare_projected_snapshots(
        &mut self,
        identities: &mut Vec<AgentRouteIdentity>,
        replacing: Option<AgentRouteReadinessGeneration>,
        shared: &SupervisorShared,
    ) -> Result<(AgentRouteReadinessGeneration, Vec<AgentRouteSnapshot>), AgentSupervisorError>
    {
        if replacing.is_none() && identities.is_empty() {
            return Err(AgentSupervisorError::EmptyAttachment);
        }
        let replaced_routes = replacing
            .and_then(|generation| self.attachments.get(&generation))
            .map_or(0, |active| active.snapshots.len());
        let retained_routes = self.routes.len().saturating_sub(replaced_routes);
        if identities.len() > shared.limits.route_capacity
            || retained_routes
                .checked_add(identities.len())
                .is_none_or(|count| count > shared.limits.route_capacity)
        {
            return Err(AgentSupervisorError::RouteCapacityExceeded);
        }
        identities.sort_by_key(|identity| identity.key);
        for pair in identities.windows(2) {
            if pair[0].key == pair[1].key {
                return Err(AgentSupervisorError::DuplicateRoute);
            }
        }
        if identities.iter().any(|identity| {
            self.routes
                .get(&identity.key)
                .is_some_and(|published| Some(published.attachment) != replacing)
        }) {
            return Err(AgentSupervisorError::DuplicateRoute);
        }

        let mut profiles = BTreeMap::<(SpaceId, AgentId), AgentProfile>::new();
        for published in self.routes.values() {
            if Some(published.attachment) == replacing {
                continue;
            }
            let identity = published.snapshot.identity;
            profiles.insert((identity.key.space, identity.key.agent), identity.profile);
        }
        for identity in identities.iter() {
            let agent = (identity.key.space, identity.key.agent);
            if profiles
                .insert(agent, identity.profile)
                .is_some_and(|profile| profile != identity.profile)
            {
                return Err(AgentSupervisorError::ProfileAmbiguity);
            }
        }

        let raw_generation = self.next_generation;
        self.next_generation = self
            .next_generation
            .checked_add(1)
            .ok_or(AgentSupervisorError::GenerationExhausted)?;
        let generation = AgentRouteReadinessGeneration(
            NonZeroU64::new(raw_generation).ok_or(AgentSupervisorError::GenerationExhausted)?,
        );
        Ok((
            generation,
            identities
                .iter()
                .map(|identity| AgentRouteSnapshot {
                    identity: *identity,
                    readiness_generation: generation,
                })
                .collect(),
        ))
    }

    fn begin_refresh(
        &mut self,
        publication: AgentRoutePublication,
        mut identities: Vec<AgentRouteIdentity>,
        reply: SyncSender<Result<AgentRoutePublication, AgentSupervisorError>>,
        shared: &SupervisorShared,
    ) -> Result<(), AgentSupervisorError> {
        let old_generation = publication.generation;
        let Some(active) = self.attachments.get(&old_generation) else {
            return Err(AgentSupervisorError::StaleSnapshot);
        };
        if active.snapshots != publication.snapshots {
            return Err(AgentSupervisorError::StaleSnapshot);
        }

        let (generation, snapshots) =
            match self.prepare_projected_snapshots(&mut identities, Some(old_generation), shared) {
                Ok(prepared) => prepared,
                Err(error) => return Err(self.fail_attachment(old_generation, shared, error)),
            };

        if self.refresh_pool.is_none() {
            let commands = shared.commands.clone();
            self.refresh_pool = Some(
                lanes::Pool::with_wake(1, 1, move || {
                    let _ = commands.try_send(Command::Wake);
                })
                .map_err(|_| {
                    self.fail_attachment(old_generation, shared, AgentSupervisorError::OwnerFailed)
                })?,
            );
        }
        self.cancel_attachment_dispatches(old_generation, shared);
        let blocked = publication
            .snapshots
            .iter()
            .chain(&snapshots)
            .map(|snapshot| lanes::Lane(snapshot.key().space, snapshot.key().agent))
            .collect();
        let mut route = self
            .attachments
            .get_mut(&old_generation)
            .and_then(|active| active.route.take())
            .ok_or(AgentSupervisorError::OwnerFailed)?;
        self.refreshing = Some(ActiveRefresh {
            old_generation,
            lanes: blocked,
        });
        let admitted_at = std::time::Instant::now();
        let job = Box::new(move || {
            let started = std::time::Instant::now();
            let result = match panic::catch_unwind(AssertUnwindSafe(|| route.reconcile(&snapshots)))
            {
                Ok(Ok(actual)) if actual == snapshots => Ok(()),
                Ok(Ok(_)) => Err(AgentSupervisorError::ReconcileMismatch),
                Ok(Err(error)) => Err(AgentSupervisorError::Route(error)),
                Err(_) => Err(AgentSupervisorError::RoutePanicked),
            };
            tracing::debug!(
                queue_wait_us = started.duration_since(admitted_at).as_micros(),
                service_us = started.elapsed().as_micros(),
                routes = snapshots.len(),
                succeeded = result.is_ok(),
                "Agent supervisor refresh reconciled"
            );
            CompletedRefresh {
                old_generation,
                generation,
                snapshots,
                route,
                result,
                reply,
            }
        });
        if self.refresh_pool.as_ref().unwrap().submit(job).is_err() {
            self.refreshing = None;
            return Err(self.fail_attachment(
                old_generation,
                shared,
                AgentSupervisorError::OwnerFailed,
            ));
        }
        Ok(())
    }

    fn collect_refresh_completions(&mut self, shared: &SupervisorShared) -> Result<(), ()> {
        let Some(pool) = self.refresh_pool.as_ref() else {
            return Ok(());
        };
        match pool.completions.try_recv() {
            Ok(Ok(completed)) => self.finish_refresh(completed, shared),
            Ok(Err(())) | Err(TryRecvError::Disconnected) => Err(()),
            Err(TryRecvError::Empty) => Ok(()),
        }
    }

    fn finish_refresh(
        &mut self,
        completed: CompletedRefresh,
        shared: &SupervisorShared,
    ) -> Result<(), ()> {
        let CompletedRefresh {
            old_generation,
            generation,
            snapshots,
            route,
            result,
            reply,
        } = completed;
        if self
            .refreshing
            .take()
            .is_none_or(|refresh| refresh.old_generation != old_generation)
        {
            return Err(());
        }
        let active = self.attachments.get_mut(&old_generation).ok_or(())?;
        if active.route.replace(route).is_some() {
            return Err(());
        }
        let result = match result {
            Ok(()) => self.publish_refresh(old_generation, generation, snapshots, shared),
            Err(error) => Err(self.fail_attachment(old_generation, shared, error)),
        };
        let _ = reply.send(result);
        Ok(())
    }

    fn publish_refresh(
        &mut self,
        old_generation: AgentRouteReadinessGeneration,
        generation: AgentRouteReadinessGeneration,
        snapshots: Vec<AgentRouteSnapshot>,
        shared: &SupervisorShared,
    ) -> Result<AgentRoutePublication, AgentSupervisorError> {
        let replacement = AgentRoutePublication {
            generation,
            snapshots: snapshots.clone(),
        };
        let admission = shared.admission.lock();
        let _admission = match admission {
            Ok(admission) => admission,
            Err(_) => {
                return Err(self.fail_attachment(
                    old_generation,
                    shared,
                    AgentSupervisorError::OwnerFailed,
                ));
            }
        };
        let state = shared.state.load(Ordering::Acquire);
        if state != SUPERVISOR_RUNNING {
            drop(_admission);
            return Err(self.fail_attachment(old_generation, shared, terminal_error(state)));
        }

        let mut active = self
            .attachments
            .remove(&old_generation)
            .ok_or(AgentSupervisorError::OwnerFailed)?;
        let mut next = self.routes.clone();
        next.retain(|_, published| published.attachment != old_generation);
        for snapshot in &snapshots {
            let replaced = next.insert(
                snapshot.key(),
                PublishedRoute {
                    snapshot: *snapshot,
                    attachment: generation,
                },
            );
            debug_assert!(replaced.is_none());
        }
        active.snapshots = snapshots;
        let replaced = self.attachments.insert(generation, active);
        debug_assert!(replaced.is_none());
        self.routes = next;
        shared.publish(self.routes.clone());
        Ok(replacement)
    }

    fn detach(
        &mut self,
        publication: AgentRoutePublication,
        shared: &SupervisorShared,
    ) -> Result<(), AgentSupervisorError> {
        let Some(active) = self.attachments.get(&publication.generation) else {
            return Err(AgentSupervisorError::StaleSnapshot);
        };
        if active.snapshots != publication.snapshots {
            return Err(AgentSupervisorError::StaleSnapshot);
        }
        let active = self
            .unpublish(publication.generation, shared)
            .ok_or(AgentSupervisorError::StaleSnapshot)?;
        retire_active(active)
    }

    fn fail_attachment(
        &mut self,
        generation: AgentRouteReadinessGeneration,
        shared: &SupervisorShared,
        primary: AgentSupervisorError,
    ) -> AgentSupervisorError {
        let cleanup = self
            .unpublish(generation, shared)
            .map_or(Ok(()), retire_active);
        retirement_error(primary, cleanup)
    }

    fn unpublish(
        &mut self,
        generation: AgentRouteReadinessGeneration,
        shared: &SupervisorShared,
    ) -> Option<ActiveAttachment> {
        let admission = shared.admission.lock();
        let _admission = match admission {
            Ok(admission) => admission,
            Err(poisoned) => poisoned.into_inner(),
        };
        let active = self.attachments.remove(&generation)?;
        let keys = active
            .snapshots
            .iter()
            .map(|snapshot| snapshot.key())
            .collect::<BTreeSet<_>>();
        self.routes.retain(|key, _| !keys.contains(key));
        if shared.state.load(Ordering::Acquire) == SUPERVISOR_RUNNING {
            shared.publish(self.routes.clone());
        } else {
            shared.clear_publication();
        }
        Some(active)
    }

    fn retire_all(&mut self, shared: &SupervisorShared) -> Result<(), AgentSupervisorError> {
        let mut error = None;
        for pending in self.dispatches.close() {
            shared.queued_dispatches.fetch_sub(1, Ordering::AcqRel);
            let _ = pending
                .reply
                .send(Err(terminal_error(shared.state.load(Ordering::Acquire))));
        }
        for command in self.deferred.drain(..) {
            if let Err(failure) = reject_command(
                command,
                shared,
                terminal_error(shared.state.load(Ordering::Acquire)),
            ) {
                error.get_or_insert(failure);
            }
        }
        if let Some(mut pool) = self.pool.take() {
            pool.join();
            for completion in pool.completions.try_iter() {
                if completion
                    .and_then(|completed| self.finish_dispatch(completed, shared))
                    .is_err()
                {
                    error.get_or_insert(AgentSupervisorError::OwnerFailed);
                }
            }
        }
        if let Some(mut pool) = self.refresh_pool.take() {
            pool.join();
            for completion in pool.completions.try_iter() {
                if completion
                    .and_then(|completed| self.finish_refresh(completed, shared))
                    .is_err()
                {
                    error.get_or_insert(AgentSupervisorError::OwnerFailed);
                }
            }
        }
        for (_, active) in core::mem::take(&mut self.attachments) {
            if let Err(retirement) = retire_active(active) {
                error.get_or_insert(retirement);
            }
        }
        self.routes.clear();
        error.map_or(Ok(()), Err)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WorkerExit {
    Closing,
    Failed,
}

fn supervisor_thread(
    receiver: Receiver<Command>,
    shared: Arc<SupervisorShared>,
    ready: SyncSender<()>,
) {
    let mut worker = SupervisorWorker::new(shared.limits);
    let _ = ready.send(());
    let outcome = panic::catch_unwind(AssertUnwindSafe(|| worker.run(&receiver, &shared)));
    let graceful = matches!(outcome, Ok(WorkerExit::Closing));
    {
        let admission = shared.admission.lock();
        let _admission = match admission {
            Ok(admission) => admission,
            Err(poisoned) => poisoned.into_inner(),
        };
        shared.clear_publication();
        if !graceful {
            shared.state.store(SUPERVISOR_FAILED, Ordering::Release);
        }
    }
    let queued = reject_queued_commands(
        &receiver,
        &shared,
        if graceful {
            AgentSupervisorError::Closed
        } else {
            AgentSupervisorError::OwnerFailed
        },
    );
    let retired = worker.retire_all(&shared);
    let terminal = if graceful && queued.is_ok() && retired.is_ok() {
        SUPERVISOR_CLOSED
    } else {
        SUPERVISOR_FAILED
    };
    shared.state.store(terminal, Ordering::Release);
}

fn reject_queued_commands(
    receiver: &Receiver<Command>,
    shared: &SupervisorShared,
    terminal: AgentSupervisorError,
) -> Result<(), AgentSupervisorError> {
    let mut cleanup_error = None;
    loop {
        let command = match receiver.try_recv() {
            Ok(command) => command,
            Err(TryRecvError::Empty | TryRecvError::Disconnected) => break,
        };
        if let Err(error) = reject_command(command, shared, terminal) {
            cleanup_error.get_or_insert(error);
        }
    }
    cleanup_error.map_or(Ok(()), Err)
}

fn reject_command(
    command: Command,
    shared: &SupervisorShared,
    terminal: AgentSupervisorError,
) -> Result<(), AgentSupervisorError> {
    match command {
        Command::Attach { attachment, reply } => {
            let result = retire_unpublished(attachment);
            let _ = reply.send(Err(result.err().unwrap_or(terminal)));
            result
        }
        Command::Refresh { reply, .. } => {
            let _ = reply.send(Err(terminal));
            Ok(())
        }
        Command::Detach { reply, .. } => {
            let _ = reply.send(Err(terminal));
            Ok(())
        }
        Command::Dispatch { reply, .. } => {
            shared.queued_dispatches.fetch_sub(1, Ordering::AcqRel);
            let _ = reply.send(Err(terminal));
            Ok(())
        }
        Command::Wake => Ok(()),
        #[cfg(test)]
        Command::Crash(reply) => {
            let _ = reply.send(());
            Ok(())
        }
    }
}

pub(crate) fn retire_unpublished(
    attachment: AgentRouteAttachment,
) -> Result<(), AgentSupervisorError> {
    let AgentRouteAttachment {
        route, mut worker, ..
    } = attachment;
    let retirement = worker
        .take()
        .ok_or(AgentSupervisorError::OwnerFailed)
        .and_then(retire_worker);
    let route_drop = panic::catch_unwind(AssertUnwindSafe(|| drop(route)))
        .map_err(|_| AgentSupervisorError::RoutePanicked);
    retirement.and(route_drop)
}

fn retire_active(active: ActiveAttachment) -> Result<(), AgentSupervisorError> {
    let ActiveAttachment {
        route, mut worker, ..
    } = active;
    let retirement = worker
        .take()
        .ok_or(AgentSupervisorError::OwnerFailed)
        .and_then(retire_worker);
    let route_drop = panic::catch_unwind(AssertUnwindSafe(|| drop(route)))
        .map_err(|_| AgentSupervisorError::RoutePanicked);
    retirement.and(route_drop)
}

fn retire_worker(mut worker: Box<dyn AgentRouteWorkerOwner>) -> Result<(), AgentSupervisorError> {
    let stop = panic::catch_unwind(AssertUnwindSafe(|| worker.request_retire()))
        .map_err(|_| AgentSupervisorError::Worker(AgentRouteWorkerError::Panicked))
        .and_then(|result| result.map_err(AgentSupervisorError::Worker));
    let join = panic::catch_unwind(AssertUnwindSafe(|| worker.join()))
        .map_err(|_| AgentSupervisorError::Worker(AgentRouteWorkerError::Panicked))
        .and_then(|result| result.map_err(AgentSupervisorError::Worker));
    stop.and(join)
}

fn retirement_error(
    primary: AgentSupervisorError,
    retirement: Result<(), AgentSupervisorError>,
) -> AgentSupervisorError {
    retirement.err().unwrap_or(primary)
}

fn terminal_error(state: u8) -> AgentSupervisorError {
    match state {
        SUPERVISOR_CLOSING | SUPERVISOR_CLOSED => AgentSupervisorError::Closed,
        _ => AgentSupervisorError::OwnerFailed,
    }
}

fn fail_closed(shared: &SupervisorShared) {
    let admission = shared.admission.lock();
    let _admission = match admission {
        Ok(admission) => admission,
        Err(poisoned) => poisoned.into_inner(),
    };
    fail_closed_while_admitted(shared);
}

fn fail_closed_while_admitted(shared: &SupervisorShared) {
    if shared.state.load(Ordering::Acquire) == SUPERVISOR_RUNNING {
        shared.state.store(SUPERVISOR_FAILED, Ordering::Release);
    }
    shared.clear_publication();
    let _ = shared.commands.try_send(Command::Wake);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicBool;
    use std::time::{Duration, Instant};

    struct FakeRoute {
        reconcile: ReconcileBehavior,
        dispatch: DispatchBehavior,
    }

    enum ReconcileBehavior {
        Ready,
        Mismatch,
        Block {
            started: SyncSender<()>,
            release: Receiver<()>,
        },
        BlockAfterReady {
            calls: u8,
            started: SyncSender<()>,
            release: Receiver<()>,
        },
        MismatchAfterReady {
            calls: u8,
        },
        FailureAfterReady {
            calls: u8,
            panic: bool,
        },
    }

    enum DispatchBehavior {
        Echo,
        BlockOnce {
            started: SyncSender<()>,
            release: Receiver<()>,
        },
        Error(AgentRouteError),
        Panic,
        Oversized(usize),
    }

    impl FakeRoute {
        fn ready() -> Self {
            Self {
                reconcile: ReconcileBehavior::Ready,
                dispatch: DispatchBehavior::Echo,
            }
        }

        fn with_dispatch(dispatch: DispatchBehavior) -> Self {
            Self {
                reconcile: ReconcileBehavior::Ready,
                dispatch,
            }
        }
    }

    impl AgentRoute for FakeRoute {
        fn reconcile(
            &mut self,
            proposed: &[AgentRouteSnapshot],
        ) -> Result<Vec<AgentRouteSnapshot>, AgentRouteError> {
            match &mut self.reconcile {
                ReconcileBehavior::Ready => Ok(proposed.to_vec()),
                ReconcileBehavior::FailureAfterReady { calls, panic } => {
                    *calls += 1;
                    if *calls == 1 {
                        return Ok(proposed.to_vec());
                    }
                    if *panic {
                        panic!("intentional refresh panic");
                    }
                    Err(AgentRouteError::Unavailable)
                }
                ReconcileBehavior::Mismatch => {
                    let mut actual = proposed.to_vec();
                    actual[0].identity.actor_program = ProgramId([0xfe; 32]);
                    Ok(actual)
                }
                ReconcileBehavior::Block { started, release } => {
                    started.send(()).map_err(|_| AgentRouteError::Unavailable)?;
                    release.recv().map_err(|_| AgentRouteError::Unavailable)?;
                    Ok(proposed.to_vec())
                }
                ReconcileBehavior::BlockAfterReady {
                    calls,
                    started,
                    release,
                } => {
                    *calls = calls.saturating_add(1);
                    if *calls > 1 {
                        started.send(()).map_err(|_| AgentRouteError::Unavailable)?;
                        release.recv().map_err(|_| AgentRouteError::Unavailable)?;
                    }
                    Ok(proposed.to_vec())
                }
                ReconcileBehavior::MismatchAfterReady { calls } => {
                    *calls = calls.saturating_add(1);
                    let mut actual = proposed.to_vec();
                    if *calls > 1 {
                        actual[0].identity.actor_program = ProgramId([0xfe; 32]);
                    }
                    Ok(actual)
                }
            }
        }

        fn dispatch(
            &mut self,
            _route: &AgentRouteSnapshot,
            payload: &[u8],
        ) -> Result<Vec<u8>, AgentRouteError> {
            let behavior = core::mem::replace(&mut self.dispatch, DispatchBehavior::Echo);
            match behavior {
                DispatchBehavior::Echo => Ok(payload.to_vec()),
                DispatchBehavior::BlockOnce { started, release } => {
                    started.send(()).map_err(|_| AgentRouteError::Unavailable)?;
                    release.recv().map_err(|_| AgentRouteError::Unavailable)?;
                    Ok(payload.to_vec())
                }
                DispatchBehavior::Error(error) => Err(error),
                DispatchBehavior::Panic => panic!("intentional fake route panic"),
                DispatchBehavior::Oversized(bytes) => Ok(vec![0; bytes]),
            }
        }
    }

    #[derive(Default)]
    struct WorkerRecord {
        events: Mutex<Vec<&'static str>>,
        joined: AtomicBool,
    }

    struct FakeWorker {
        record: Arc<WorkerRecord>,
        visibility_probe: Option<(AgentSupervisorHandle, AgentRouteKey)>,
        retire_error: Option<AgentRouteWorkerError>,
        join_error: Option<AgentRouteWorkerError>,
        panic_retire: bool,
        panic_join: bool,
    }

    impl FakeWorker {
        fn new(record: Arc<WorkerRecord>) -> Self {
            Self {
                record,
                visibility_probe: None,
                retire_error: None,
                join_error: None,
                panic_retire: false,
                panic_join: false,
            }
        }

        fn probing(
            record: Arc<WorkerRecord>,
            handle: AgentSupervisorHandle,
            key: AgentRouteKey,
        ) -> Self {
            Self {
                visibility_probe: Some((handle, key)),
                ..Self::new(record)
            }
        }
    }

    impl AgentRouteWorkerOwner for FakeWorker {
        fn request_retire(&mut self) -> Result<(), AgentRouteWorkerError> {
            if let Some((handle, key)) = &self.visibility_probe {
                let hidden = matches!(
                    handle.snapshot(*key),
                    Err(AgentSupervisorError::NotFound
                        | AgentSupervisorError::Closed
                        | AgentSupervisorError::OwnerFailed)
                );
                self.record.events.lock().unwrap().push(if hidden {
                    "hidden-before-stop"
                } else {
                    "visible-at-stop"
                });
            }
            self.record.events.lock().unwrap().push("stop");
            if self.panic_retire {
                panic!("intentional worker retirement panic");
            }
            self.retire_error.map_or(Ok(()), Err)
        }

        fn join(self: Box<Self>) -> Result<(), AgentRouteWorkerError> {
            self.record.events.lock().unwrap().push("join");
            self.record.joined.store(true, Ordering::Release);
            if self.panic_join {
                panic!("intentional worker join panic");
            }
            self.join_error.map_or(Ok(()), Err)
        }
    }

    fn limits(
        routes: usize,
        queue: usize,
        inflight: usize,
        payload: usize,
    ) -> AgentSupervisorLimits {
        AgentSupervisorLimits::new(routes, queue, inflight, payload)
    }

    fn identity(space: u8, agent: u8, actor: u8, profile: AgentProfile) -> AgentRouteIdentity {
        AgentRouteIdentity::new(
            AgentRouteKey::new(
                SpaceId([space; 32]),
                AgentId([agent; 32]),
                ActorId([actor; 32]),
            )
            .unwrap(),
            Hash([actor.wrapping_add(1); 32]),
            DeploymentId([actor.wrapping_add(2); 32]),
            DeploymentId([actor.wrapping_add(3); 32]),
            ProgramId([actor.wrapping_add(4); 32]),
            profile,
        )
        .unwrap()
    }

    fn attachment(
        identities: Vec<AgentRouteIdentity>,
        route: FakeRoute,
        record: Arc<WorkerRecord>,
    ) -> AgentRouteAttachment {
        AgentRouteAttachment::new(identities, route, FakeWorker::new(record))
    }

    fn wait_until(mut predicate: impl FnMut() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(3);
        while !predicate() {
            assert!(Instant::now() < deadline, "condition was not reached");
            thread::yield_now();
        }
    }

    #[test]
    fn independent_agents_execute_before_either_is_released() {
        let mut owner = AgentSupervisorOwner::start(limits(4, 4, 4, 128)).unwrap();
        let mut calls = Vec::new();
        let mut started = Vec::new();
        let mut releases = Vec::new();
        for agent in [1, 2] {
            let (entered, observed) = mpsc::sync_channel(1);
            let (release, wait) = mpsc::sync_channel(1);
            let identity = identity(1, agent, 3, AgentProfile::Local);
            owner
                .attach(attachment(
                    vec![identity],
                    FakeRoute::with_dispatch(DispatchBehavior::BlockOnce {
                        started: entered,
                        release: wait,
                    }),
                    Arc::new(WorkerRecord::default()),
                ))
                .unwrap();
            let handle = owner.handle();
            let snapshot = handle.snapshot(identity.key()).unwrap();
            calls.push(thread::spawn(move || {
                handle.dispatch(snapshot, vec![agent])
            }));
            started.push(observed);
            releases.push(release);
        }
        let overlap = started
            .iter()
            .all(|entered| entered.recv_timeout(Duration::from_secs(3)).is_ok());
        for release in releases {
            let _ = release.send(());
        }
        for call in calls {
            assert!(call.join().unwrap().is_ok());
        }
        owner.shutdown_and_join().unwrap();
        assert!(
            overlap,
            "independent routes must both execute before either is released"
        );
    }

    #[test]
    fn same_agent_different_attachments_preserve_execution_order() {
        let mut owner = AgentSupervisorOwner::start(limits(4, 4, 4, 128)).unwrap();
        let mut calls = Vec::new();
        let mut starts = Vec::new();
        let mut releases = Vec::new();
        for actor in [1, 2] {
            let (entered, observed) = mpsc::sync_channel(1);
            let (release, wait) = mpsc::sync_channel(1);
            let identity = identity(1, 1, actor, AgentProfile::Local);
            owner
                .attach(attachment(
                    vec![identity],
                    FakeRoute::with_dispatch(DispatchBehavior::BlockOnce {
                        started: entered,
                        release: wait,
                    }),
                    Arc::new(WorkerRecord::default()),
                ))
                .unwrap();
            let handle = owner.handle();
            let snapshot = handle.snapshot(identity.key()).unwrap();
            calls.push(thread::spawn(move || {
                handle.dispatch(snapshot, vec![actor])
            }));
            if actor == 1 {
                observed.recv_timeout(Duration::from_secs(3)).unwrap();
            }
            starts.push(observed);
            releases.push(release);
        }
        wait_until(|| owner.handle().queued_dispatches_for_test() == 1);
        assert!(starts[1].try_recv().is_err());
        releases[0].send(()).unwrap();
        starts[1].recv_timeout(Duration::from_secs(3)).unwrap();
        releases[1].send(()).unwrap();
        for call in calls {
            assert!(call.join().unwrap().is_ok());
        }
        owner.shutdown_and_join().unwrap();
    }

    #[test]
    fn waiting_detach_does_not_block_an_independent_agent() {
        let mut owner = AgentSupervisorOwner::start(limits(4, 4, 4, 128)).unwrap();
        let a = identity(1, 1, 1, AgentProfile::Local);
        let b = identity(1, 2, 1, AgentProfile::Local);
        let (entered, started) = mpsc::sync_channel(1);
        let (release, wait) = mpsc::sync_channel(1);
        let publication = owner
            .attach(attachment(
                vec![a],
                FakeRoute::with_dispatch(DispatchBehavior::BlockOnce {
                    started: entered,
                    release: wait,
                }),
                Arc::new(WorkerRecord::default()),
            ))
            .unwrap();
        owner
            .attach(attachment(
                vec![b],
                FakeRoute::ready(),
                Arc::new(WorkerRecord::default()),
            ))
            .unwrap();
        let handle = owner.handle();
        let first = handle.clone();
        let snapshot = handle.snapshot(a.key()).unwrap();
        let call = thread::spawn(move || first.dispatch(snapshot, vec![1]));
        started.recv_timeout(Duration::from_secs(3)).unwrap();
        let (reply, detached) = mpsc::sync_channel(1);
        assert!(
            handle
                .shared
                .commands
                .try_send(Command::Detach { publication, reply })
                .is_ok()
        );
        let (done, completed) = mpsc::sync_channel(1);
        let second = handle.clone();
        let snapshot = handle.snapshot(b.key()).unwrap();
        let other = thread::spawn(move || {
            let _ = done.send(second.dispatch(snapshot, vec![2]));
        });
        let result = completed.recv_timeout(Duration::from_secs(3));
        let still_waiting = detached.try_recv().is_err();
        release.send(()).unwrap();
        assert!(call.join().unwrap().is_ok());
        other.join().unwrap();
        assert_eq!(
            detached.recv_timeout(Duration::from_secs(3)).unwrap(),
            Ok(())
        );
        assert_eq!(result.unwrap(), Ok(vec![2]));
        assert!(still_waiting, "detach must wait for its own running job");
        assert!(matches!(
            handle.snapshot(a.key()),
            Err(AgentSupervisorError::NotFound)
        ));
        owner.shutdown_and_join().unwrap();
    }

    #[test]
    fn zero_identities_and_zero_limits_are_rejected_before_publication() {
        assert_eq!(
            AgentSupervisorOwner::start(limits(0, 1, 1, 1)).unwrap_err(),
            AgentSupervisorError::InvalidLimits
        );
        assert_eq!(
            AgentRouteKey::new(SpaceId::ZERO, AgentId([1; 32]), ActorId([2; 32])),
            Err(AgentSupervisorError::InvalidIdentity)
        );
        let key = AgentRouteKey::new(SpaceId([1; 32]), AgentId([2; 32]), ActorId([3; 32])).unwrap();
        for (incarnation, runtime, actor, program) in [
            (
                Hash::ZERO,
                DeploymentId([4; 32]),
                DeploymentId([5; 32]),
                ProgramId([6; 32]),
            ),
            (
                Hash([3; 32]),
                DeploymentId::ZERO,
                DeploymentId([5; 32]),
                ProgramId([6; 32]),
            ),
            (
                Hash([3; 32]),
                DeploymentId([4; 32]),
                DeploymentId::ZERO,
                ProgramId([6; 32]),
            ),
            (
                Hash([3; 32]),
                DeploymentId([4; 32]),
                DeploymentId([5; 32]),
                ProgramId::ZERO,
            ),
        ] {
            assert_eq!(
                AgentRouteIdentity::new(
                    key,
                    incarnation,
                    runtime,
                    actor,
                    program,
                    AgentProfile::Local,
                ),
                Err(AgentSupervisorError::InvalidIdentity)
            );
        }
    }

    #[test]
    fn route_is_invisible_until_exact_readiness_is_reconciled() {
        let owner = AgentSupervisorOwner::start(limits(4, 2, 2, 64)).unwrap();
        let handle = owner.handle();
        let primary = identity(1, 2, 3, AgentProfile::Local);
        // Reusing the exact AgentId and ActorId in another Space remains a
        // distinct full route; there is no projected Agent/Actor-only index.
        let other_space = identity(9, 2, 3, AgentProfile::Local);
        let key = primary.key();
        let (started_tx, started_rx) = mpsc::sync_channel(0);
        let (release_tx, release_rx) = mpsc::sync_channel(0);
        let record = Arc::new(WorkerRecord::default());
        let route = FakeRoute {
            reconcile: ReconcileBehavior::Block {
                started: started_tx,
                release: release_rx,
            },
            dispatch: DispatchBehavior::Echo,
        };

        let attach = thread::spawn(move || {
            let mut owner = owner;
            let result = owner.attach(attachment(vec![primary, other_space], route, record));
            (owner, result)
        });
        started_rx.recv_timeout(Duration::from_secs(3)).unwrap();
        assert_eq!(handle.snapshot(key), Err(AgentSupervisorError::NotFound));
        assert_eq!(
            handle.snapshot(other_space.key()),
            Err(AgentSupervisorError::NotFound)
        );
        assert!(handle.snapshots().unwrap().is_empty());
        release_tx.send(()).unwrap();
        let (owner, publication) = attach.join().unwrap();
        let publication = publication.unwrap();
        assert_eq!(publication.snapshots().len(), 2);
        assert_eq!(handle.snapshot(key).unwrap().key(), key);
        assert_eq!(
            handle.snapshot(other_space.key()).unwrap().key(),
            other_space.key()
        );
        assert_eq!(
            handle.snapshot(key).unwrap().readiness_generation(),
            handle
                .snapshot(other_space.key())
                .unwrap()
                .readiness_generation()
        );
        owner.shutdown_and_join().unwrap();
    }

    #[test]
    fn duplicate_profile_ambiguity_and_mismatched_readiness_are_rejected() {
        let mut owner = AgentSupervisorOwner::start(limits(4, 2, 2, 64)).unwrap();
        let handle = owner.handle();
        let local = identity(1, 2, 3, AgentProfile::Local);

        let duplicate_record = Arc::new(WorkerRecord::default());
        assert_eq!(
            owner
                .attach(attachment(
                    vec![local, local],
                    FakeRoute::ready(),
                    duplicate_record.clone(),
                ))
                .unwrap_err(),
            AgentSupervisorError::DuplicateRoute
        );
        assert!(duplicate_record.joined.load(Ordering::Acquire));
        assert_eq!(
            handle.snapshot(local.key()),
            Err(AgentSupervisorError::NotFound)
        );

        let mismatch = identity(1, 2, 4, AgentProfile::Local);
        let mismatch_sibling = identity(1, 2, 5, AgentProfile::Local);
        let mismatch_record = Arc::new(WorkerRecord::default());
        assert_eq!(
            owner
                .attach(attachment(
                    vec![mismatch, mismatch_sibling],
                    FakeRoute {
                        reconcile: ReconcileBehavior::Mismatch,
                        dispatch: DispatchBehavior::Echo,
                    },
                    mismatch_record.clone(),
                ))
                .unwrap_err(),
            AgentSupervisorError::ReconcileMismatch
        );
        assert!(mismatch_record.joined.load(Ordering::Acquire));
        assert_eq!(
            handle.snapshot(mismatch.key()),
            Err(AgentSupervisorError::NotFound)
        );
        assert_eq!(
            handle.snapshot(mismatch_sibling.key()),
            Err(AgentSupervisorError::NotFound)
        );

        let live_record = Arc::new(WorkerRecord::default());
        owner
            .attach(attachment(vec![local], FakeRoute::ready(), live_record))
            .unwrap();
        let ambiguous = identity(1, 2, 6, AgentProfile::Shared);
        let ambiguous_record = Arc::new(WorkerRecord::default());
        assert_eq!(
            owner
                .attach(attachment(
                    vec![ambiguous],
                    FakeRoute::ready(),
                    ambiguous_record.clone(),
                ))
                .unwrap_err(),
            AgentSupervisorError::ProfileAmbiguity
        );
        assert!(ambiguous_record.joined.load(Ordering::Acquire));
        assert_eq!(
            handle.snapshot(ambiguous.key()),
            Err(AgentSupervisorError::NotFound)
        );

        let active_duplicate_record = Arc::new(WorkerRecord::default());
        assert_eq!(
            owner
                .attach(attachment(
                    vec![local],
                    FakeRoute::ready(),
                    active_duplicate_record.clone(),
                ))
                .unwrap_err(),
            AgentSupervisorError::DuplicateRoute
        );
        assert!(active_duplicate_record.joined.load(Ordering::Acquire));
        owner.shutdown_and_join().unwrap();
    }

    #[test]
    fn detached_and_replaced_routes_reject_stale_snapshot_generations() {
        let mut owner = AgentSupervisorOwner::start(limits(2, 2, 2, 64)).unwrap();
        let handle = owner.handle();
        let identity = identity(1, 2, 3, AgentProfile::Private);
        let first_record = Arc::new(WorkerRecord::default());
        let first = owner
            .attach(attachment(
                vec![identity],
                FakeRoute::ready(),
                first_record.clone(),
            ))
            .unwrap();
        let stale = handle.snapshot(identity.key()).unwrap();
        assert_eq!(handle.dispatch(stale, vec![1, 2]).unwrap(), vec![1, 2]);
        owner.detach(&first).unwrap();
        assert!(first_record.joined.load(Ordering::Acquire));
        assert_eq!(
            handle.dispatch(stale, vec![3]),
            Err(AgentSupervisorError::StaleSnapshot)
        );

        let mut upgraded_identity = identity;
        upgraded_identity.runtime_deployment = DeploymentId([0xa5; 32]);
        let second_record = Arc::new(WorkerRecord::default());
        owner
            .attach(attachment(
                vec![upgraded_identity],
                FakeRoute::ready(),
                second_record,
            ))
            .unwrap();
        let current = handle.snapshot(identity.key()).unwrap();
        assert!(current.readiness_generation() > stale.readiness_generation());
        assert_eq!(current.runtime_deployment(), DeploymentId([0xa5; 32]));
        assert_eq!(current.actor_deployment(), stale.actor_deployment());
        assert_eq!(current.actor_program(), stale.actor_program());
        assert_eq!(current.incarnation(), stale.incarnation());
        assert_eq!(
            handle.dispatch(stale, vec![4]),
            Err(AgentSupervisorError::StaleSnapshot)
        );
        assert_eq!(handle.dispatch(current, vec![5]).unwrap(), vec![5]);
        owner.shutdown_and_join().unwrap();
    }

    #[test]
    fn held_refresh_allows_unrelated_dispatch_and_blocks_its_own_agent() {
        let mut owner = AgentSupervisorOwner::start(limits(3, 4, 4, 128)).unwrap();
        let a = identity(1, 1, 1, AgentProfile::Local);
        let b = identity(1, 2, 1, AgentProfile::Local);
        let (entered, observed) = mpsc::sync_channel(1);
        let (release, wait) = mpsc::sync_channel(1);
        let publication = owner
            .attach(attachment(
                vec![a],
                FakeRoute {
                    reconcile: ReconcileBehavior::BlockAfterReady {
                        calls: 0,
                        started: entered,
                        release: wait,
                    },
                    dispatch: DispatchBehavior::Echo,
                },
                Arc::new(WorkerRecord::default()),
            ))
            .unwrap();
        owner
            .attach(attachment(
                vec![b],
                FakeRoute::ready(),
                Arc::new(WorkerRecord::default()),
            ))
            .unwrap();
        let handle = owner.handle();
        let old = handle.snapshot(a.key()).unwrap();
        let independent = handle.snapshot(b.key()).unwrap();
        let mut upgraded = a;
        upgraded.runtime_deployment = DeploymentId([0xa5; 32]);
        let refresh = thread::spawn(move || {
            let result = owner.refresh(&publication, vec![upgraded]);
            (owner, result)
        });
        observed.recv_timeout(Duration::from_secs(3)).unwrap();
        let (done, completed) = mpsc::sync_channel(1);
        let client = handle.clone();
        let call = thread::spawn(move || {
            let same = client.dispatch(old, vec![1]);
            let other = client.dispatch(independent, vec![2]);
            let _ = done.send((same, other));
        });
        let before_release = completed.recv_timeout(Duration::from_secs(3));
        assert_eq!(handle.snapshot(a.key()).unwrap(), old);
        release.send(()).unwrap();
        let (owner, result) = refresh.join().unwrap();
        call.join().unwrap();
        assert_eq!(
            before_release.unwrap(),
            (Err(AgentSupervisorError::StaleSnapshot), Ok(vec![2]))
        );
        let updated = result.unwrap().snapshots()[0];
        assert_eq!(handle.snapshot(a.key()).unwrap(), updated);
        assert_eq!(handle.snapshot(b.key()).unwrap(), independent);
        assert_eq!(
            handle.dispatch(old, vec![3]),
            Err(AgentSupervisorError::StaleSnapshot)
        );
        assert_eq!(handle.dispatch(updated, vec![4]), Ok(vec![4]));
        owner.shutdown_and_join().unwrap();
    }

    #[test]
    fn refresh_error_and_panic_retire_only_the_affected_attachment() {
        for panics in [false, true] {
            let mut owner = AgentSupervisorOwner::start(limits(2, 2, 2, 64)).unwrap();
            let a = identity(1, 1, 1, AgentProfile::Local);
            let b = identity(1, 2, 1, AgentProfile::Local);
            let record = Arc::new(WorkerRecord::default());
            let publication = owner
                .attach(attachment(
                    vec![a],
                    FakeRoute {
                        reconcile: ReconcileBehavior::FailureAfterReady {
                            calls: 0,
                            panic: panics,
                        },
                        dispatch: DispatchBehavior::Echo,
                    },
                    record.clone(),
                ))
                .unwrap();
            owner
                .attach(attachment(
                    vec![b],
                    FakeRoute::ready(),
                    Arc::new(WorkerRecord::default()),
                ))
                .unwrap();
            let handle = owner.handle();
            let independent = handle.snapshot(b.key()).unwrap();
            let expected = if panics {
                AgentSupervisorError::RoutePanicked
            } else {
                AgentSupervisorError::Route(AgentRouteError::Unavailable)
            };
            assert_eq!(owner.refresh(&publication, vec![a]), Err(expected));
            assert_eq!(
                handle.snapshot(a.key()),
                Err(AgentSupervisorError::NotFound)
            );
            assert!(record.joined.load(Ordering::Acquire));
            assert_eq!(handle.dispatch(independent, vec![9]), Ok(vec![9]));
            owner.shutdown_and_join().unwrap();
        }
    }

    #[test]
    fn held_refresh_bounds_deferred_control_and_rejects_stale_detach() {
        let mut owner = AgentSupervisorOwner::start(limits(2, 2, 2, 64)).unwrap();
        let a = identity(1, 1, 1, AgentProfile::Local);
        let (entered, observed) = mpsc::sync_channel(1);
        let (release, wait) = mpsc::sync_channel(1);
        let publication = owner
            .attach(attachment(
                vec![a],
                FakeRoute {
                    reconcile: ReconcileBehavior::BlockAfterReady {
                        calls: 0,
                        started: entered,
                        release: wait,
                    },
                    dispatch: DispatchBehavior::Echo,
                },
                Arc::new(WorkerRecord::default()),
            ))
            .unwrap();
        let handle = owner.handle();
        let (reply, refreshed) = mpsc::sync_channel(1);
        handle
            .shared
            .commands
            .send(Command::Refresh {
                publication: publication.clone(),
                identities: vec![a],
                reply,
            })
            .unwrap();
        observed.recv_timeout(Duration::from_secs(3)).unwrap();
        let mut results = Vec::new();
        for _ in 0..3 {
            let (reply, result) = mpsc::sync_channel(1);
            handle
                .shared
                .commands
                .send(Command::Detach {
                    publication: publication.clone(),
                    reply,
                })
                .unwrap();
            results.push(result);
        }
        let refused = results[2].recv_timeout(Duration::from_secs(3));
        let pending = results[0].try_recv().is_err() && results[1].try_recv().is_err();
        release.send(()).unwrap();
        let replacement = refreshed
            .recv_timeout(Duration::from_secs(3))
            .unwrap()
            .unwrap();
        assert_eq!(refused.unwrap(), Err(AgentSupervisorError::Busy));
        assert!(pending);
        for result in &results[..2] {
            assert_eq!(
                result.recv_timeout(Duration::from_secs(3)).unwrap(),
                Err(AgentSupervisorError::StaleSnapshot)
            );
        }
        let current = handle.snapshot(a.key()).unwrap();
        assert_eq!(current, replacement.snapshots()[0]);
        assert_eq!(handle.dispatch(current, vec![7]), Ok(vec![7]));
        owner.shutdown_and_join().unwrap();
    }

    #[test]
    fn shutdown_drains_held_refresh_without_publishing_its_completion() {
        let mut owner = AgentSupervisorOwner::start(limits(2, 2, 2, 64)).unwrap();
        let a = identity(1, 1, 1, AgentProfile::Local);
        let (entered, observed) = mpsc::sync_channel(1);
        let (release, wait) = mpsc::sync_channel(1);
        let record = Arc::new(WorkerRecord::default());
        let publication = owner
            .attach(attachment(
                vec![a],
                FakeRoute {
                    reconcile: ReconcileBehavior::BlockAfterReady {
                        calls: 0,
                        started: entered,
                        release: wait,
                    },
                    dispatch: DispatchBehavior::Echo,
                },
                record.clone(),
            ))
            .unwrap();
        let handle = owner.handle();
        let (reply, result) = mpsc::sync_channel(1);
        handle
            .shared
            .commands
            .send(Command::Refresh {
                publication,
                identities: vec![a],
                reply,
            })
            .unwrap();
        observed.recv_timeout(Duration::from_secs(3)).unwrap();
        owner.request_shutdown();
        let shutdown = thread::spawn(move || owner.shutdown_and_join());
        let unpublished = handle.snapshot(a.key()).is_err();
        release.send(()).unwrap();
        assert_eq!(
            result.recv_timeout(Duration::from_secs(3)).unwrap(),
            Err(AgentSupervisorError::Closed)
        );
        shutdown.join().unwrap().unwrap();
        assert!(unpublished);
        assert!(record.joined.load(Ordering::Acquire));
        assert!(handle.snapshot(a.key()).is_err());
    }

    #[test]
    fn refresh_atomically_replaces_runtime_generation_and_rejects_aba_snapshot() {
        let mut owner = AgentSupervisorOwner::start(limits(2, 2, 2, 64)).unwrap();
        let handle = owner.handle();
        let initial = identity(1, 2, 3, AgentProfile::Shared);
        let (started_tx, started_rx) = mpsc::sync_channel(0);
        let (release_tx, release_rx) = mpsc::sync_channel(0);
        let record = Arc::new(WorkerRecord::default());
        let publication = owner
            .attach(attachment(
                vec![initial],
                FakeRoute {
                    reconcile: ReconcileBehavior::BlockAfterReady {
                        calls: 0,
                        started: started_tx,
                        release: release_rx,
                    },
                    dispatch: DispatchBehavior::Echo,
                },
                record,
            ))
            .unwrap();
        let old = handle.snapshot(initial.key()).unwrap();
        let mut upgraded = initial;
        upgraded.runtime_deployment = DeploymentId([0xa5; 32]);

        let refresh = thread::spawn(move || {
            let result = owner.refresh(&publication, vec![upgraded]);
            (owner, result)
        });
        started_rx.recv_timeout(Duration::from_secs(3)).unwrap();
        // Snapshot reads never observe an empty or half-reconciled route set:
        // the old generation stays current until the complete swap.
        assert_eq!(handle.snapshot(initial.key()).unwrap(), old);
        release_tx.send(()).unwrap();
        let (owner, replacement) = refresh.join().unwrap();
        let replacement = replacement.unwrap();
        let current = handle.snapshot(initial.key()).unwrap();
        assert_eq!(current, replacement.snapshots()[0]);
        assert_eq!(current.runtime_deployment(), DeploymentId([0xa5; 32]));
        assert!(current.readiness_generation() > old.readiness_generation());
        assert_eq!(
            handle.dispatch(old, vec![1]),
            Err(AgentSupervisorError::StaleSnapshot)
        );
        assert_eq!(handle.dispatch(current, vec![2]).unwrap(), vec![2]);
        owner.shutdown_and_join().unwrap();
    }

    #[test]
    fn refresh_mismatch_retires_attachment_and_rejected_request_does_not() {
        let mut owner = AgentSupervisorOwner::start(limits(2, 2, 2, 64)).unwrap();
        let handle = owner.handle();
        let identity = identity(1, 2, 3, AgentProfile::Local);
        let record = Arc::new(WorkerRecord::default());
        let publication = owner
            .attach(attachment(
                vec![identity],
                FakeRoute {
                    reconcile: ReconcileBehavior::MismatchAfterReady { calls: 0 },
                    dispatch: DispatchBehavior::Echo,
                },
                record.clone(),
            ))
            .unwrap();
        assert_eq!(
            owner.refresh(&publication, vec![identity]),
            Err(AgentSupervisorError::ReconcileMismatch)
        );
        assert_eq!(
            handle.snapshot(identity.key()),
            Err(AgentSupervisorError::NotFound)
        );
        assert!(record.joined.load(Ordering::Acquire));

        let request_record = Arc::new(WorkerRecord::default());
        owner
            .attach(attachment(
                vec![identity],
                FakeRoute::with_dispatch(DispatchBehavior::Error(AgentRouteError::Rejected)),
                request_record,
            ))
            .unwrap();
        let snapshot = handle.snapshot(identity.key()).unwrap();
        assert_eq!(
            handle.dispatch(snapshot, vec![3]),
            Err(AgentSupervisorError::Route(AgentRouteError::Rejected))
        );
        assert_eq!(handle.snapshot(identity.key()).unwrap(), snapshot);
        assert_eq!(handle.dispatch(snapshot, vec![4]).unwrap(), vec![4]);
        owner.shutdown_and_join().unwrap();
    }

    #[test]
    fn route_count_queue_payload_and_inflight_are_bounded() {
        let mut owner = AgentSupervisorOwner::start(limits(1, 1, 2, 16)).unwrap();
        let record = Arc::new(WorkerRecord::default());
        assert_eq!(
            owner
                .attach(attachment(
                    vec![
                        identity(1, 2, 3, AgentProfile::Local),
                        identity(1, 2, 4, AgentProfile::Local),
                    ],
                    FakeRoute::ready(),
                    record.clone(),
                ))
                .unwrap_err(),
            AgentSupervisorError::RouteCapacityExceeded
        );
        assert!(record.joined.load(Ordering::Acquire));
        owner.shutdown_and_join().unwrap();

        let mut owner = AgentSupervisorOwner::start(limits(1, 1, 3, 128)).unwrap();
        let handle = owner.handle();
        let identity = identity(1, 2, 3, AgentProfile::Local);
        let (started_tx, started_rx) = mpsc::sync_channel(0);
        let (release_tx, release_rx) = mpsc::sync_channel(0);
        owner
            .attach(attachment(
                vec![identity],
                FakeRoute::with_dispatch(DispatchBehavior::BlockOnce {
                    started: started_tx,
                    release: release_rx,
                }),
                Arc::new(WorkerRecord::default()),
            ))
            .unwrap();
        let snapshot = handle.snapshot(identity.key()).unwrap();
        let first_handle = handle.clone();
        let first = thread::spawn(move || first_handle.dispatch(snapshot, vec![1]));
        started_rx.recv_timeout(Duration::from_secs(3)).unwrap();
        let second_handle = handle.clone();
        let second = thread::spawn(move || second_handle.dispatch(snapshot, vec![2]));
        wait_until(|| handle.queued_dispatches_for_test() == 1);
        assert_eq!(
            handle.dispatch(snapshot, vec![3]),
            Err(AgentSupervisorError::Busy)
        );
        release_tx.send(()).unwrap();
        assert_eq!(first.join().unwrap().unwrap(), vec![1]);
        assert_eq!(second.join().unwrap().unwrap(), vec![2]);
        owner.shutdown_and_join().unwrap();

        let mut owner = AgentSupervisorOwner::start(limits(1, 1, 2, 8)).unwrap();
        let handle = owner.handle();
        let (started_tx, started_rx) = mpsc::sync_channel(0);
        let (release_tx, release_rx) = mpsc::sync_channel(0);
        owner
            .attach(attachment(
                vec![identity],
                FakeRoute::with_dispatch(DispatchBehavior::BlockOnce {
                    started: started_tx,
                    release: release_rx,
                }),
                Arc::new(WorkerRecord::default()),
            ))
            .unwrap();
        let snapshot = handle.snapshot(identity.key()).unwrap();
        let first_handle = handle.clone();
        let first = thread::spawn(move || first_handle.dispatch(snapshot, vec![1; 6]));
        started_rx.recv_timeout(Duration::from_secs(3)).unwrap();
        assert_eq!(
            handle.dispatch(snapshot, vec![2; 3]),
            Err(AgentSupervisorError::PayloadBackpressure)
        );
        release_tx.send(()).unwrap();
        assert_eq!(first.join().unwrap().unwrap(), vec![1; 6]);
        assert_eq!(
            handle.dispatch(snapshot, vec![3; 9]),
            Err(AgentSupervisorError::PayloadTooLarge)
        );
        owner.shutdown_and_join().unwrap();

        let mut owner = AgentSupervisorOwner::start(limits(1, 1, 1, 16)).unwrap();
        let handle = owner.handle();
        let (started_tx, started_rx) = mpsc::sync_channel(0);
        let (release_tx, release_rx) = mpsc::sync_channel(0);
        owner
            .attach(attachment(
                vec![identity],
                FakeRoute::with_dispatch(DispatchBehavior::BlockOnce {
                    started: started_tx,
                    release: release_rx,
                }),
                Arc::new(WorkerRecord::default()),
            ))
            .unwrap();
        let snapshot = handle.snapshot(identity.key()).unwrap();
        let first_handle = handle.clone();
        let first = thread::spawn(move || first_handle.dispatch(snapshot, vec![1]));
        started_rx.recv_timeout(Duration::from_secs(3)).unwrap();
        assert_eq!(
            handle.dispatch(snapshot, vec![2]),
            Err(AgentSupervisorError::InflightBackpressure)
        );
        release_tx.send(()).unwrap();
        first.join().unwrap().unwrap();
        owner.shutdown_and_join().unwrap();
    }

    #[test]
    fn explicit_detach_and_shutdown_unpublish_before_stop_and_join() {
        let mut owner = AgentSupervisorOwner::start(limits(2, 2, 2, 64)).unwrap();
        let handle = owner.handle();
        let first = identity(1, 2, 3, AgentProfile::Shared);
        let first_record = Arc::new(WorkerRecord::default());
        let publication = owner
            .attach(AgentRouteAttachment::new(
                vec![first],
                FakeRoute::ready(),
                FakeWorker::probing(first_record.clone(), handle.clone(), first.key()),
            ))
            .unwrap();
        owner.detach(&publication).unwrap();
        assert_eq!(
            first_record.events.lock().unwrap().as_slice(),
            ["hidden-before-stop", "stop", "join"]
        );
        assert!(first_record.joined.load(Ordering::Acquire));

        let second = identity(1, 3, 4, AgentProfile::Private);
        let second_record = Arc::new(WorkerRecord::default());
        owner
            .attach(AgentRouteAttachment::new(
                vec![second],
                FakeRoute::ready(),
                FakeWorker::probing(second_record.clone(), handle.clone(), second.key()),
            ))
            .unwrap();
        owner.shutdown_and_join().unwrap();
        assert_eq!(
            second_record.events.lock().unwrap().as_slice(),
            ["hidden-before-stop", "stop", "join"]
        );
        assert!(second_record.joined.load(Ordering::Acquire));
        assert_eq!(
            handle.snapshot(second.key()),
            Err(AgentSupervisorError::Closed)
        );

        let third = identity(2, 4, 5, AgentProfile::Local);
        let third_record = Arc::new(WorkerRecord::default());
        let dropped_handle;
        {
            let mut dropped_owner = AgentSupervisorOwner::start(limits(1, 1, 1, 64)).unwrap();
            dropped_handle = dropped_owner.handle();
            dropped_owner
                .attach(AgentRouteAttachment::new(
                    vec![third],
                    FakeRoute::ready(),
                    FakeWorker::probing(third_record.clone(), dropped_handle.clone(), third.key()),
                ))
                .unwrap();
        }
        assert_eq!(
            third_record.events.lock().unwrap().as_slice(),
            ["hidden-before-stop", "stop", "join"]
        );
        assert!(third_record.joined.load(Ordering::Acquire));
        assert_eq!(
            dropped_handle.snapshot(third.key()),
            Err(AgentSupervisorError::Closed)
        );
    }

    #[test]
    fn adapter_failure_or_panic_is_unpublished_and_its_worker_is_joined() {
        let mut owner = AgentSupervisorOwner::start(limits(2, 2, 2, 64)).unwrap();
        let handle = owner.handle();
        let failed = identity(1, 2, 3, AgentProfile::Local);
        let failed_record = Arc::new(WorkerRecord::default());
        owner
            .attach(attachment(
                vec![failed],
                FakeRoute::with_dispatch(DispatchBehavior::Error(AgentRouteError::Unavailable)),
                failed_record.clone(),
            ))
            .unwrap();
        let snapshot = handle.snapshot(failed.key()).unwrap();
        assert_eq!(
            handle.dispatch(snapshot, vec![1]),
            Err(AgentSupervisorError::Route(AgentRouteError::Unavailable))
        );
        assert_eq!(
            handle.snapshot(failed.key()),
            Err(AgentSupervisorError::NotFound)
        );
        assert!(failed_record.joined.load(Ordering::Acquire));

        let panicked = identity(1, 3, 4, AgentProfile::Local);
        let panic_record = Arc::new(WorkerRecord::default());
        owner
            .attach(attachment(
                vec![panicked],
                FakeRoute::with_dispatch(DispatchBehavior::Panic),
                panic_record.clone(),
            ))
            .unwrap();
        let snapshot = handle.snapshot(panicked.key()).unwrap();
        assert_eq!(
            handle.dispatch(snapshot, vec![2]),
            Err(AgentSupervisorError::RoutePanicked)
        );
        assert_eq!(
            handle.snapshot(panicked.key()),
            Err(AgentSupervisorError::NotFound)
        );
        assert!(panic_record.joined.load(Ordering::Acquire));
        assert!(handle.is_running());
        owner.shutdown_and_join().unwrap();
    }

    #[test]
    fn oversized_adapter_reply_is_fail_closed_for_that_attachment() {
        let mut owner = AgentSupervisorOwner::start(limits(1, 1, 1, 8)).unwrap();
        let handle = owner.handle();
        let identity = identity(1, 2, 3, AgentProfile::Local);
        let record = Arc::new(WorkerRecord::default());
        owner
            .attach(attachment(
                vec![identity],
                FakeRoute::with_dispatch(DispatchBehavior::Oversized(9)),
                record.clone(),
            ))
            .unwrap();
        let snapshot = handle.snapshot(identity.key()).unwrap();
        assert_eq!(
            handle.dispatch(snapshot, vec![1]),
            Err(AgentSupervisorError::PayloadTooLarge)
        );
        assert_eq!(
            handle.snapshot(identity.key()),
            Err(AgentSupervisorError::NotFound)
        );
        assert!(record.joined.load(Ordering::Acquire));
        owner.shutdown_and_join().unwrap();
    }

    #[test]
    fn worker_retirement_failure_and_panic_still_join_and_stay_unpublished() {
        let mut owner = AgentSupervisorOwner::start(limits(2, 2, 2, 64)).unwrap();
        let handle = owner.handle();
        let failed = identity(1, 2, 3, AgentProfile::Local);
        let failed_record = Arc::new(WorkerRecord::default());
        let mut failed_worker = FakeWorker::new(failed_record.clone());
        failed_worker.join_error = Some(AgentRouteWorkerError::Failed);
        let publication = owner
            .attach(AgentRouteAttachment::new(
                vec![failed],
                FakeRoute::ready(),
                failed_worker,
            ))
            .unwrap();
        assert_eq!(
            owner.detach(&publication),
            Err(AgentSupervisorError::Worker(AgentRouteWorkerError::Failed))
        );
        assert_eq!(
            handle.snapshot(failed.key()),
            Err(AgentSupervisorError::NotFound)
        );
        assert!(failed_record.joined.load(Ordering::Acquire));

        let panicked = identity(1, 3, 4, AgentProfile::Local);
        let panic_record = Arc::new(WorkerRecord::default());
        let mut panic_worker = FakeWorker::new(panic_record.clone());
        panic_worker.panic_retire = true;
        let publication = owner
            .attach(AgentRouteAttachment::new(
                vec![panicked],
                FakeRoute::ready(),
                panic_worker,
            ))
            .unwrap();
        assert_eq!(
            owner.detach(&publication),
            Err(AgentSupervisorError::Worker(
                AgentRouteWorkerError::Panicked
            ))
        );
        assert_eq!(
            handle.snapshot(panicked.key()),
            Err(AgentSupervisorError::NotFound)
        );
        assert!(panic_record.joined.load(Ordering::Acquire));
        owner.shutdown_and_join().unwrap();
    }

    #[test]
    fn supervisor_worker_panic_unpublishes_and_joins_all_attachments() {
        let mut owner = AgentSupervisorOwner::start(limits(1, 2, 2, 64)).unwrap();
        let handle = owner.handle();
        let identity = identity(1, 2, 3, AgentProfile::Local);
        let record = Arc::new(WorkerRecord::default());
        owner
            .attach(attachment(
                vec![identity],
                FakeRoute::ready(),
                record.clone(),
            ))
            .unwrap();
        handle.crash_worker_for_test().unwrap();
        wait_until(|| !handle.is_running());
        assert_eq!(
            handle.snapshot(identity.key()),
            Err(AgentSupervisorError::OwnerFailed)
        );
        assert_eq!(
            owner.shutdown_and_join(),
            Err(AgentSupervisorError::OwnerFailed)
        );
        assert!(record.joined.load(Ordering::Acquire));
    }
}
