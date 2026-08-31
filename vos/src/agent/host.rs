//! Durable multi-agent host.
//!
//! An [`AgentHost`] owns one filesystem directory and any number of agent
//! runtime instances. Each image remains independently replaceable and is
//! addressed by its full [`AgentId`]. Runtime packages and programs live in
//! each image's mandatory content-addressed catalog closure.

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TryRecvError, TrySendError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use fs2::FileExt;

use super::authority::{ActorInvocationReceipt, AgentAuthorityBinding, AgentAuthorityReceipt};
use super::driver::{AgentDriver, AgentDriverError, AgentTrustProvider, FileAgentStore};
use super::execution::{
    ActorExecutionError, ActorExecutionReply, ActorInvocation, MAX_EXECUTION_AVAILABILITY_BYTES,
    MAX_EXECUTION_BLOBS, MAX_EXECUTION_GAS, MAX_EXECUTION_MESSAGE_BYTES,
    MAX_EXECUTION_POLICY_BYTES, MAX_EXECUTION_PROGRAM_BYTES, MAX_EXECUTION_STATE_BYTES,
};
use super::package::{
    MAX_ENCODED_PACKAGE_BYTES, MAX_PACKAGE_DIAGNOSTICS_BYTES, MAX_PACKAGE_INTERFACES_BYTES,
    MAX_PACKAGE_SCHEMAS_BYTES, MAX_PACKAGE_TASK_BYTES, Package, PackageError,
};
use super::{ActorDirectoryPage, ActorEntry, AgentConfig, AgentIdentity, LifecycleRequest};
use crate::service::{
    ActorId, AgentId, CapabilityId, DeploymentId, Hash, InvocationId, NodeId, ProgramId, SpaceId,
};

const IMAGE_SUFFIX: &str = ".agent-image";
const HOST_LOCK_FILE: &str = ".agent-host.lock";
const HOST_SCOPE_FILE: &str = ".agent-host.scope";
const HOST_SCOPE_TEMP_FILE: &str = ".agent-host.scope.tmp";
const HOST_SCOPE_MAGIC: &[u8; 8] = b"VOSAHST1";
const HOST_SCOPE_ENCODED_LEN: usize = HOST_SCOPE_MAGIC.len() + 32 + 32;

/// Maximum number of Agent-host operations waiting behind the one active
/// operation. The bounded queue is intentional: callers receive explicit
/// backpressure instead of growing daemon memory while a PVM or durable store
/// operation is in progress.
pub const DEFAULT_AGENT_HOST_QUEUE_CAPACITY: usize = 64;

/// Maximum cumulative caller-owned payload retained by active and queued
/// Agent-host operations. This complements the command-count bound: a small
/// number of otherwise valid packages must not retain unbounded daemon memory
/// while the serialized worker is busy.
pub const DEFAULT_AGENT_HOST_PAYLOAD_CAPACITY_BYTES: usize = 32 * 1024 * 1024;

const WORKER_RUNNING: u8 = 0;
const WORKER_SHUTTING_DOWN: u8 = 1;
const WORKER_STOPPED: u8 = 2;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentHostError {
    Unavailable,
    InvalidScope,
    ScopeMismatch,
    InvalidScopeBinding,
    DirectoryInUse,
    InvalidQueueCapacity,
    InvalidImageName,
    DuplicateAgent,
    AgentNotFound,
    IdentityMismatch,
    Overloaded,
    ShuttingDown,
    WorkerStopped,
    WorkerPanicked,
    Driver(AgentDriverError),
}

impl core::fmt::Display for AgentHostError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "agent host: {self:?}")
    }
}

impl std::error::Error for AgentHostError {}

impl From<AgentDriverError> for AgentHostError {
    fn from(error: AgentDriverError) -> Self {
        Self::Driver(error)
    }
}

/// Stable ownership token for one configured Agent data-root slot.
///
/// `stable_lock_path` must live outside `root`. The token therefore remains
/// exclusive if a backup/restore workflow renames and replaces the complete
/// data directory. [`AgentHost`] additionally locks an inode inside `root` as
/// defense in depth. Production setup must durably create the configured
/// parent directories first; this helper syncs the immediate parent of any
/// leaf it creates, but cannot make an arbitrarily deep new ancestor chain
/// crash-durable.
pub struct AgentHostRootLease {
    root: PathBuf,
    scope: AgentHostScope,
    _stable_lock: File,
}

impl core::fmt::Debug for AgentHostRootLease {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("AgentHostRootLease")
            .field("root", &self.root)
            .field("scope", &self.scope)
            .finish_non_exhaustive()
    }
}

impl AgentHostRootLease {
    pub fn acquire(
        root: impl Into<PathBuf>,
        stable_lock_path: impl Into<PathBuf>,
        scope: AgentHostScope,
    ) -> Result<Self, AgentHostError> {
        let scope = scope.validate()?;
        let requested_root = absolute_agent_host_path(root.into())?;
        let requested_lock = absolute_agent_host_path(stable_lock_path.into())?;
        if requested_lock.starts_with(&requested_root) {
            return Err(AgentHostError::InvalidScopeBinding);
        }
        let stable_lock_path = canonical_lock_path(requested_lock)?;
        let stable_lock = open_agent_host_lock(&stable_lock_path)?;
        // Root creation and validation happen only after winning the stable
        // slot lock. A losing daemon/backup process must not recreate or
        // otherwise mutate a live owner's replaceable data tree.
        let root = ensure_agent_host_root(requested_root)?;
        if stable_lock_path.starts_with(&root) {
            return Err(AgentHostError::InvalidScopeBinding);
        }
        Ok(Self {
            root,
            scope,
            _stable_lock: stable_lock,
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub const fn scope(&self) -> AgentHostScope {
        self.scope
    }
}

/// One process-local owner of a directory of durable agents.
pub struct AgentHost {
    root: PathBuf,
    scope: AgentHostScope,
    agents: BTreeMap<AgentId, AgentDriver<FileAgentStore>>,
    trust: Arc<dyn AgentTrustProvider>,
    _directory_lock: File,
    _root_lease: AgentHostRootLease,
}

/// Immutable space and exact machine boundary for one Local Agent directory.
///
/// A Local image is not portable between nodes. Binding this at the directory
/// owner prevents a copied image—or a create request for another space—from
/// being admitted merely because a caller-selected trust provider recognizes
/// its authority key. Production construction must derive `node` from the
/// full authenticated Node identity, never a compact routing prefix.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AgentHostScope {
    pub space: SpaceId,
    pub node: NodeId,
}

impl AgentHostScope {
    pub fn validate(self) -> Result<Self, AgentHostError> {
        if self.space == SpaceId::ZERO || self.node == NodeId::ZERO {
            return Err(AgentHostError::InvalidScope);
        }
        Ok(self)
    }

    fn admits(self, config: &AgentConfig) -> bool {
        config.identity.space == self.space
            && config.identity.profile == super::AgentProfile::Local
            && config.replicas.len() == 1
            && config.replicas[0].node == self.node
    }
}

/// Exact lifecycle operation prepared by the serialized Agent host for an
/// authenticated authority to approve.
///
/// Private construction makes the tuple internally consistent, but does not
/// prove which [`AgentHostControl`] produced it: callers can legitimately open
/// generic hosts with their own trust providers. A production issuer must
/// prepare through its own privately held handle and must never accept this
/// value from an untrusted caller as provenance. Principal, credential,
/// sequence, and validity remain authority-owned inputs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedLifecycleRequest {
    authority: AgentAuthorityBinding,
    space: SpaceId,
    agent: AgentId,
    capability: CapabilityId,
    request: LifecycleRequest,
}

impl PreparedLifecycleRequest {
    fn new(config: &AgentConfig, request: LifecycleRequest) -> Result<Self, AgentHostError> {
        let capability = request
            .required_capability()
            .ok_or(AgentHostError::Driver(AgentDriverError::InvalidRuntime))?;
        Ok(Self {
            authority: config.authority.clone(),
            space: config.identity.space,
            agent: config.identity.agent,
            capability: CapabilityId::named(capability),
            request,
        })
    }

    pub fn authority(&self) -> &AgentAuthorityBinding {
        &self.authority
    }

    pub const fn space(&self) -> SpaceId {
        self.space
    }

    pub const fn agent(&self) -> AgentId {
        self.agent
    }

    pub const fn capability(&self) -> CapabilityId {
        self.capability
    }

    pub fn request(&self) -> &LifecycleRequest {
        &self.request
    }

    pub fn operation(&self) -> Hash {
        self.request.commitment()
    }
}

type AgentHostJob = Box<dyn FnOnce(Option<&mut AgentHost>) + Send + 'static>;

enum AgentHostCommand {
    Run {
        job: AgentHostJob,
        activity: AgentHostActivity,
    },
    Wake,
}

struct AgentHostActivity {
    active_requests: Arc<AtomicUsize>,
    admitted_payload_bytes: Arc<AtomicUsize>,
    last_activity: Arc<Mutex<Instant>>,
    payload_bytes: usize,
    admitted: bool,
}

impl AgentHostActivity {
    fn reserve(handle: &AgentHostHandle, payload_bytes: usize) -> Result<Self, AgentHostError> {
        if payload_bytes > handle.payload_capacity_bytes {
            return Err(AgentHostError::Overloaded);
        }
        let mut admitted = handle.admitted_payload_bytes.load(Ordering::Acquire);
        loop {
            let Some(next) = admitted.checked_add(payload_bytes) else {
                return Err(AgentHostError::Overloaded);
            };
            if next > handle.payload_capacity_bytes {
                return Err(AgentHostError::Overloaded);
            }
            match handle.admitted_payload_bytes.compare_exchange_weak(
                admitted,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(current) => admitted = current,
            }
        }
        handle.active_requests.fetch_add(1, Ordering::AcqRel);
        Ok(Self {
            active_requests: handle.active_requests.clone(),
            admitted_payload_bytes: handle.admitted_payload_bytes.clone(),
            last_activity: handle.last_activity.clone(),
            payload_bytes,
            admitted: true,
        })
    }

    fn cancel_admission(&mut self) {
        self.admitted = false;
    }
}

impl Drop for AgentHostActivity {
    fn drop(&mut self) {
        // Publish completion before making the active count zero. An idle
        // observer which sees zero with Acquire must therefore also see this
        // timestamp, including when a long request straddles its threshold.
        if self.admitted
            && let Ok(mut activity) = self.last_activity.lock()
        {
            *activity = Instant::now();
        }
        self.admitted_payload_bytes
            .fetch_sub(self.payload_bytes, Ordering::AcqRel);
        self.active_requests.fetch_sub(1, Ordering::Release);
    }
}

/// Cloneable, bounded command handle for one process-local Agent host.
///
/// The underlying [`AgentHost`] is never shared through a mutex. One worker
/// owns it for its complete lifetime and serializes PVM execution with durable
/// image updates. All operations retain their signed receipt parameters and
/// use full [`AgentId`] / [`ActorId`] values; this handle never projects an
/// Agent into the transitional 32-bit service routing namespace.
#[derive(Clone)]
pub struct AgentHostHandle {
    commands: SyncSender<AgentHostCommand>,
    state: Arc<AtomicU8>,
    active_requests: Arc<AtomicUsize>,
    admitted_payload_bytes: Arc<AtomicUsize>,
    payload_capacity_bytes: usize,
    last_activity: Arc<Mutex<Instant>>,
    scope: AgentHostScope,
}

impl core::fmt::Debug for AgentHostHandle {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("AgentHostHandle")
            .field("scope", &self.scope)
            .field("running", &self.is_running())
            .field(
                "active_requests",
                &self.active_requests.load(Ordering::Acquire),
            )
            .field(
                "admitted_payload_bytes",
                &self.admitted_payload_bytes.load(Ordering::Acquire),
            )
            .field("payload_capacity_bytes", &self.payload_capacity_bytes)
            .finish_non_exhaustive()
    }
}

impl AgentHostHandle {
    /// Whether the worker is still accepting new operations.
    pub fn is_running(&self) -> bool {
        self.state.load(Ordering::Acquire) == WORKER_RUNNING
    }

    pub fn scope(&self) -> AgentHostScope {
        self.scope
    }

    /// Time since the last admitted operation completed. An active or queued
    /// operation reports zero so a node's idle policy cannot shut the worker
    /// down underneath durable work.
    pub fn idle_for(&self) -> Duration {
        if self.active_requests.load(Ordering::Acquire) != 0 {
            return Duration::ZERO;
        }
        self.last_activity
            .lock()
            .map(|activity| activity.elapsed())
            .unwrap_or(Duration::ZERO)
    }

    #[cfg(test)]
    pub(crate) fn crash_worker_for_test(&self) -> Result<(), AgentHostError> {
        self.request(0, |_| -> Result<(), AgentHostError> {
            panic!("intentional Agent-host worker crash")
        })
    }

    #[cfg(test)]
    pub(crate) fn block_worker_for_test(
        &self,
        active: SyncSender<()>,
        release: Receiver<()>,
    ) -> Result<(), AgentHostError> {
        self.request(0, move |_| {
            active.send(()).map_err(|_| AgentHostError::Unavailable)?;
            release.recv().map_err(|_| AgentHostError::Unavailable)?;
            Ok(())
        })
    }

    #[cfg(test)]
    fn admitted_payload_bytes_for_test(&self) -> usize {
        self.admitted_payload_bytes.load(Ordering::Acquire)
    }

    pub fn identities(&self) -> Result<Vec<AgentIdentity>, AgentHostError> {
        self.request(0, |host| Ok(host.identities().cloned().collect()))
    }

    pub fn identity(&self, agent: AgentId) -> Result<Option<AgentIdentity>, AgentHostError> {
        self.request(0, move |host| Ok(host.identity(agent).cloned()))
    }

    pub fn revision(&self, agent: AgentId) -> Result<Option<u64>, AgentHostError> {
        self.request(0, move |host| Ok(host.revision(agent)))
    }

    pub fn prepare_create(
        &self,
        config: AgentConfig,
        runtime_package: Package,
    ) -> Result<PreparedLifecycleRequest, AgentHostError> {
        if !self.scope.admits(&config) {
            return Err(AgentHostError::ScopeMismatch);
        }
        validate_package_shape_before_reservation(&runtime_package)?;
        let payload_bytes = payload_sum([
            agent_config_heap_payload_bytes(&config),
            package_heap_payload_bytes(&runtime_package),
        ]);
        self.request(payload_bytes, move |host| {
            host.prepare_create(&config, &runtime_package)
        })
    }

    pub fn prepare_actor_install(
        &self,
        agent: AgentId,
        name: String,
        parent: Option<ActorId>,
        package: Package,
    ) -> Result<PreparedLifecycleRequest, AgentHostError> {
        validate_actor_name_and_parent(&name, parent)?;
        validate_package_shape_before_reservation(&package)?;
        let payload_bytes = payload_sum([name.capacity(), package_heap_payload_bytes(&package)]);
        self.request(payload_bytes, move |host| {
            host.prepare_actor_install(agent, name, parent, &package)
        })
    }

    pub fn prepare_actor_upgrade(
        &self,
        agent: AgentId,
        actor: ActorId,
        from_deployment: DeploymentId,
        package: Package,
    ) -> Result<PreparedLifecycleRequest, AgentHostError> {
        validate_actor_and_deployment(actor, from_deployment)?;
        validate_package_shape_before_reservation(&package)?;
        let payload_bytes = package_heap_payload_bytes(&package);
        self.request(payload_bytes, move |host| {
            host.prepare_actor_upgrade(agent, actor, from_deployment, &package)
        })
    }

    pub fn prepare_actor_suspend(
        &self,
        agent: AgentId,
        actor: ActorId,
    ) -> Result<PreparedLifecycleRequest, AgentHostError> {
        validate_actor(actor)?;
        self.request(0, move |host| host.prepare_actor_suspend(agent, actor))
    }

    pub fn prepare_actor_resume(
        &self,
        agent: AgentId,
        actor: ActorId,
    ) -> Result<PreparedLifecycleRequest, AgentHostError> {
        validate_actor(actor)?;
        self.request(0, move |host| host.prepare_actor_resume(agent, actor))
    }

    pub fn prepare_actor_remove(
        &self,
        agent: AgentId,
        actor: ActorId,
        expected_deployment: DeploymentId,
    ) -> Result<PreparedLifecycleRequest, AgentHostError> {
        validate_actor_and_deployment(actor, expected_deployment)?;
        self.request(0, move |host| {
            host.prepare_actor_remove(agent, actor, expected_deployment)
        })
    }

    pub fn prepare_runtime_upgrade(
        &self,
        agent: AgentId,
        from_deployment: DeploymentId,
        package: Package,
    ) -> Result<PreparedLifecycleRequest, AgentHostError> {
        if from_deployment == DeploymentId::ZERO {
            return Err(invalid_lifecycle_request());
        }
        validate_package_shape_before_reservation(&package)?;
        let payload_bytes = package_heap_payload_bytes(&package);
        self.request(payload_bytes, move |host| {
            host.prepare_runtime_upgrade(agent, from_deployment, &package)
        })
    }

    pub fn create(
        &self,
        config: AgentConfig,
        runtime_package: Package,
        authority: AgentAuthorityReceipt,
    ) -> Result<AgentIdentity, AgentHostError> {
        if !self.scope.admits(&config) {
            return Err(AgentHostError::ScopeMismatch);
        }
        validate_agent_receipt_shape(&authority)?;
        validate_package_shape_before_reservation(&runtime_package)?;
        let payload_bytes = payload_sum([
            agent_config_heap_payload_bytes(&config),
            package_heap_payload_bytes(&runtime_package),
            agent_receipt_heap_payload_bytes(&authority),
        ]);
        self.request(payload_bytes, move |host| {
            host.create(config, runtime_package, &authority)
        })
    }

    pub fn inspect(
        &self,
        agent: AgentId,
        after: Option<ActorId>,
        limit: u16,
    ) -> Result<ActorDirectoryPage, AgentHostError> {
        if limit == 0 || limit > super::standard::MAX_DIRECTORY_PAGE {
            return Err(invalid_lifecycle_request());
        }
        self.request(0, move |host| host.inspect(agent, after, limit))
    }

    pub fn install_actor(
        &self,
        agent: AgentId,
        authority: AgentAuthorityReceipt,
        name: String,
        parent: Option<ActorId>,
        package: Package,
    ) -> Result<ActorEntry, AgentHostError> {
        validate_agent_receipt_shape(&authority)?;
        validate_actor_name_and_parent(&name, parent)?;
        validate_package_shape_before_reservation(&package)?;
        let payload_bytes = payload_sum([
            agent_receipt_heap_payload_bytes(&authority),
            name.capacity(),
            package_heap_payload_bytes(&package),
        ]);
        self.request(payload_bytes, move |host| {
            host.install_actor(agent, &authority, name, parent, &package)
        })
    }

    pub fn upgrade_actor(
        &self,
        agent: AgentId,
        authority: AgentAuthorityReceipt,
        actor: ActorId,
        from_deployment: DeploymentId,
        package: Package,
    ) -> Result<ActorEntry, AgentHostError> {
        validate_agent_receipt_shape(&authority)?;
        validate_actor_and_deployment(actor, from_deployment)?;
        validate_package_shape_before_reservation(&package)?;
        let payload_bytes = payload_sum([
            agent_receipt_heap_payload_bytes(&authority),
            package_heap_payload_bytes(&package),
        ]);
        self.request(payload_bytes, move |host| {
            host.upgrade_actor(agent, &authority, actor, from_deployment, &package)
        })
    }

    pub fn suspend_actor(
        &self,
        agent: AgentId,
        authority: AgentAuthorityReceipt,
        actor: ActorId,
    ) -> Result<ActorEntry, AgentHostError> {
        validate_agent_receipt_shape(&authority)?;
        validate_actor(actor)?;
        let payload_bytes = agent_receipt_heap_payload_bytes(&authority);
        self.request(payload_bytes, move |host| {
            host.suspend_actor(agent, &authority, actor)
        })
    }

    pub fn resume_actor(
        &self,
        agent: AgentId,
        authority: AgentAuthorityReceipt,
        actor: ActorId,
    ) -> Result<ActorEntry, AgentHostError> {
        validate_agent_receipt_shape(&authority)?;
        validate_actor(actor)?;
        let payload_bytes = agent_receipt_heap_payload_bytes(&authority);
        self.request(payload_bytes, move |host| {
            host.resume_actor(agent, &authority, actor)
        })
    }

    pub fn remove_actor(
        &self,
        agent: AgentId,
        authority: AgentAuthorityReceipt,
        actor: ActorId,
        expected_deployment: DeploymentId,
    ) -> Result<(), AgentHostError> {
        validate_agent_receipt_shape(&authority)?;
        validate_actor_and_deployment(actor, expected_deployment)?;
        let payload_bytes = agent_receipt_heap_payload_bytes(&authority);
        self.request(payload_bytes, move |host| {
            host.remove_actor(agent, &authority, actor, expected_deployment)
        })
    }

    pub fn upgrade_runtime(
        &self,
        agent: AgentId,
        authority: AgentAuthorityReceipt,
        from_deployment: DeploymentId,
        package: Package,
    ) -> Result<AgentIdentity, AgentHostError> {
        validate_agent_receipt_shape(&authority)?;
        if from_deployment == DeploymentId::ZERO {
            return Err(invalid_lifecycle_request());
        }
        validate_package_shape_before_reservation(&package)?;
        let payload_bytes = payload_sum([
            agent_receipt_heap_payload_bytes(&authority),
            package_heap_payload_bytes(&package),
        ]);
        self.request(payload_bytes, move |host| {
            host.upgrade_runtime(agent, &authority, from_deployment, &package)
        })
    }

    pub fn invoke(
        &self,
        agent: AgentId,
        invocation: ActorInvocation,
        authority: ActorInvocationReceipt,
    ) -> Result<ActorExecutionReply, AgentHostError> {
        validate_invocation_receipt_shape(&authority)?;
        validate_invocation_shape_before_reservation(&invocation)?;
        let payload_bytes = payload_sum([
            invocation_heap_payload_bytes(&invocation),
            invocation_receipt_heap_payload_bytes(&authority),
        ]);
        self.request(payload_bytes, move |host| {
            host.invoke(agent, invocation, &authority)
        })
    }

    pub fn acknowledge_invocation(
        &self,
        agent: AgentId,
        invocation: ActorInvocation,
        authority: ActorInvocationReceipt,
    ) -> Result<(), AgentHostError> {
        validate_invocation_receipt_shape(&authority)?;
        validate_invocation_shape_before_reservation(&invocation)?;
        let payload_bytes = payload_sum([
            invocation_heap_payload_bytes(&invocation),
            invocation_receipt_heap_payload_bytes(&authority),
        ]);
        self.request(payload_bytes, move |host| {
            host.acknowledge_invocation(agent, invocation, &authority)
        })
    }

    fn request<T, F>(&self, heap_payload_bytes: usize, operation: F) -> Result<T, AgentHostError>
    where
        T: Send + 'static,
        F: FnOnce(&mut AgentHost) -> Result<T, AgentHostError> + Send + 'static,
    {
        match self.state.load(Ordering::Acquire) {
            WORKER_RUNNING => {}
            WORKER_SHUTTING_DOWN => return Err(AgentHostError::ShuttingDown),
            _ => return Err(AgentHostError::WorkerStopped),
        }
        let (reply, result) = mpsc::sync_channel(1);
        let payload_bytes = heap_payload_bytes
            .checked_add(core::mem::size_of::<AgentHostCommand>())
            .and_then(|bytes| bytes.checked_add(core::mem::size_of::<F>()))
            .and_then(|bytes| {
                bytes.checked_add(core::mem::size_of::<SyncSender<Result<T, AgentHostError>>>())
            })
            .unwrap_or(usize::MAX);
        let activity = AgentHostActivity::reserve(self, payload_bytes)?;
        let command = AgentHostCommand::Run {
            job: Box::new(move |host| {
                let response = match host {
                    Some(host) => operation(host),
                    None => Err(AgentHostError::ShuttingDown),
                };
                let _ = reply.send(response);
            }),
            activity,
        };
        match self.commands.try_send(command) {
            Ok(()) => {}
            Err(TrySendError::Full(mut command)) => {
                cancel_agent_host_admission(&mut command);
                return Err(AgentHostError::Overloaded);
            }
            Err(TrySendError::Disconnected(mut command)) => {
                cancel_agent_host_admission(&mut command);
                return Err(AgentHostError::WorkerStopped);
            }
        }
        result.recv().unwrap_or(Err(AgentHostError::WorkerStopped))
    }
}

fn payload_sum<const N: usize>(parts: [usize; N]) -> usize {
    parts.into_iter().fold(0, usize::saturating_add)
}

fn vector_allocation_bytes<T>(capacity: usize) -> usize {
    capacity.saturating_mul(core::mem::size_of::<T>())
}

fn authority_binding_heap_payload_bytes(binding: &AgentAuthorityBinding) -> usize {
    binding.public_key.capacity()
}

fn agent_config_heap_payload_bytes(config: &AgentConfig) -> usize {
    payload_sum([
        authority_binding_heap_payload_bytes(&config.authority),
        vector_allocation_bytes::<super::AgentReplica>(config.replicas.capacity()),
    ])
}

fn package_heap_payload_bytes(package: &Package) -> usize {
    let task_program_bytes = package
        .task_dependencies
        .iter()
        .fold(0usize, |total, dependency| {
            total.saturating_add(dependency.pvm.capacity())
        });
    let diagnostic_bytes = package.diagnostics.as_ref().map_or(0, |diagnostics| {
        payload_sum([
            diagnostics.elf.as_ref().map_or(0, Vec::capacity),
            diagnostics.source_map.as_ref().map_or(0, Vec::capacity),
        ])
    });
    payload_sum([
        package.manifest.name.capacity(),
        package.pvm.capacity(),
        package.generated_interfaces.capacity(),
        package.role_policies.capacity(),
        package.schemas.capacity(),
        package.agent_schema.capacity(),
        vector_allocation_bytes::<crate::service::PackageTaskDependency>(
            package.task_dependencies.capacity(),
        ),
        task_program_bytes,
        diagnostic_bytes,
        package.deployment_signature.public_key.capacity(),
        package.deployment_signature.signature.capacity(),
    ])
}

fn agent_receipt_heap_payload_bytes(receipt: &AgentAuthorityReceipt) -> usize {
    payload_sum([
        authority_binding_heap_payload_bytes(&receipt.claim.authority),
        receipt.signature.capacity(),
    ])
}

fn invocation_heap_payload_bytes(invocation: &ActorInvocation) -> usize {
    let blob_bytes = invocation.availability.iter().fold(0usize, |total, blob| {
        total.saturating_add(blob.bytes.capacity())
    });
    payload_sum([
        invocation.message.capacity(),
        vector_allocation_bytes::<super::execution::RuntimeBlob>(
            invocation.availability.capacity(),
        ),
        blob_bytes,
    ])
}

fn invocation_receipt_heap_payload_bytes(receipt: &ActorInvocationReceipt) -> usize {
    payload_sum([
        authority_binding_heap_payload_bytes(&receipt.claim.authority),
        receipt.signature.capacity(),
    ])
}

fn invalid_package_shape(error: PackageError) -> AgentHostError {
    AgentHostError::Driver(AgentDriverError::Package(error))
}

/// Reject unbounded package shapes before inspecting nested allocations.
///
/// Semantic package validation, including PVM parsing, artifact hashing,
/// canonical encoding, and signature checks, belongs to the serialized
/// driver operation after payload admission.
fn validate_package_shape_before_reservation(package: &Package) -> Result<(), AgentHostError> {
    if package.task_dependencies.len() > crate::service::MAX_PACKAGE_TASK_DEPENDENCIES {
        return Err(invalid_package_shape(PackageError::ArtifactsTooLarge));
    }
    if package.manifest.name.is_empty()
        || package.manifest.name.len() > crate::service::MAX_ACTOR_NAME_BYTES
    {
        return Err(invalid_package_shape(PackageError::EmptyName));
    }
    if package.pvm.is_empty() {
        return Err(invalid_package_shape(PackageError::EmptyProgram));
    }
    if package.pvm.len() > MAX_EXECUTION_PROGRAM_BYTES
        || package.generated_interfaces.len() > MAX_PACKAGE_INTERFACES_BYTES
        || package.schemas.len() > MAX_PACKAGE_SCHEMAS_BYTES
    {
        return Err(invalid_package_shape(PackageError::ArtifactsTooLarge));
    }
    if package.role_policies.len() > MAX_EXECUTION_POLICY_BYTES
        || package.agent_schema.len() > super::schema::MAX_ENCODED_BYTES
    {
        return Err(invalid_package_shape(PackageError::InvalidActorArtifacts));
    }

    // The dependency count is bounded above before either traversal.
    let task_bytes = package
        .task_dependencies
        .iter()
        .try_fold(0usize, |total, dependency| {
            total.checked_add(dependency.pvm.len())
        });
    if task_bytes.is_none_or(|bytes| bytes > MAX_PACKAGE_TASK_BYTES)
        || package
            .task_dependencies
            .iter()
            .any(|dependency| dependency.pvm.len() > MAX_EXECUTION_PROGRAM_BYTES)
    {
        return Err(invalid_package_shape(PackageError::ArtifactsTooLarge));
    }

    let diagnostic_bytes = package.diagnostics.as_ref().map_or(Some(0), |diagnostics| {
        diagnostics
            .elf
            .as_ref()
            .map_or(0, |bytes| bytes.len())
            .checked_add(
                diagnostics
                    .source_map
                    .as_ref()
                    .map_or(0, |bytes| bytes.len()),
            )
    });
    if diagnostic_bytes.is_none_or(|bytes| bytes > MAX_PACKAGE_DIAGNOSTICS_BYTES) {
        return Err(invalid_package_shape(PackageError::ArtifactsTooLarge));
    }

    // This is only a necessary lower bound on canonical size. The driver
    // performs the exact encoding-size check after admission.
    let dynamic_bytes = [
        package.manifest.name.len(),
        package.pvm.len(),
        package.generated_interfaces.len(),
        package.role_policies.len(),
        package.schemas.len(),
        package.agent_schema.len(),
        task_bytes.unwrap_or(usize::MAX),
        diagnostic_bytes.unwrap_or(usize::MAX),
        package.deployment_signature.public_key.len(),
        package.deployment_signature.signature.len(),
    ]
    .into_iter()
    .try_fold(0usize, usize::checked_add);
    if dynamic_bytes.is_none_or(|bytes| bytes > MAX_ENCODED_PACKAGE_BYTES) {
        return Err(invalid_package_shape(PackageError::ArtifactsTooLarge));
    }
    Ok(())
}

fn invalid_invocation_shape() -> AgentHostError {
    AgentHostError::Driver(AgentDriverError::Execution(
        ActorExecutionError::InvalidInput,
    ))
}

/// Apply only fixed-cost and bounded length checks before payload admission.
/// Content hashes, ordering, and complete invocation validation remain owned
/// by the serialized driver operation.
fn validate_invocation_shape_before_reservation(
    invocation: &ActorInvocation,
) -> Result<(), AgentHostError> {
    if invocation.invocation == InvocationId::ZERO
        || invocation.actor == ActorId::ZERO
        || invocation.deployment == DeploymentId::ZERO
        || invocation.program == ProgramId::ZERO
        || invocation.gas == 0
        || invocation.gas > MAX_EXECUTION_GAS
        || !invocation.auth.validate()
        || invocation.message.is_empty()
        || invocation.message.len() > MAX_EXECUTION_MESSAGE_BYTES
        || invocation.availability.len() > MAX_EXECUTION_BLOBS
    {
        return Err(invalid_invocation_shape());
    }

    // The availability count is bounded above before this traversal. Blob
    // reference hashing and canonical ordering are intentionally deferred.
    let availability_bytes = invocation
        .availability
        .iter()
        .try_fold(0usize, |total, blob| total.checked_add(blob.bytes.len()));
    if invocation
        .availability
        .iter()
        .any(|blob| blob.bytes.len() > MAX_EXECUTION_STATE_BYTES)
        || availability_bytes.is_none_or(|bytes| bytes > MAX_EXECUTION_AVAILABILITY_BYTES)
    {
        return Err(invalid_invocation_shape());
    }
    Ok(())
}

fn invalid_lifecycle_request() -> AgentHostError {
    AgentHostError::Driver(AgentDriverError::Lifecycle(
        super::LifecycleError::InvalidRequest,
    ))
}

fn validate_actor(actor: ActorId) -> Result<(), AgentHostError> {
    if actor == ActorId::ZERO {
        return Err(invalid_lifecycle_request());
    }
    Ok(())
}

fn validate_actor_and_deployment(
    actor: ActorId,
    deployment: DeploymentId,
) -> Result<(), AgentHostError> {
    validate_actor(actor)?;
    if deployment == DeploymentId::ZERO {
        return Err(invalid_lifecycle_request());
    }
    Ok(())
}

fn validate_actor_name_and_parent(
    name: &str,
    parent: Option<ActorId>,
) -> Result<(), AgentHostError> {
    if name.is_empty()
        || name.len() > crate::service::MAX_ACTOR_NAME_BYTES
        || parent == Some(ActorId::ZERO)
    {
        return Err(invalid_lifecycle_request());
    }
    Ok(())
}

fn validate_agent_receipt_shape(receipt: &AgentAuthorityReceipt) -> Result<(), AgentHostError> {
    if receipt.signature.len() != super::authority::ED25519_SIGNATURE_BYTES
        || !receipt.claim.authority.validate()
    {
        return Err(AgentHostError::Driver(AgentDriverError::Authority(
            super::authority::AuthorityError::InvalidSignature,
        )));
    }
    Ok(())
}

fn validate_invocation_receipt_shape(
    receipt: &ActorInvocationReceipt,
) -> Result<(), AgentHostError> {
    if receipt.signature.len() != super::authority::ED25519_SIGNATURE_BYTES
        || !receipt.claim.authority.validate()
    {
        return Err(AgentHostError::Driver(AgentDriverError::Authority(
            super::authority::AuthorityError::InvalidSignature,
        )));
    }
    Ok(())
}

fn cancel_agent_host_admission(command: &mut AgentHostCommand) {
    if let AgentHostCommand::Run { activity, .. } = command {
        activity.cancel_admission();
    }
}

/// Owning lifecycle guard for an [`AgentHostHandle`] worker.
///
/// Dropping this value requests terminal shutdown and joins the worker. A
/// restart deliberately creates a new control with [`Self::open`]; cloned old
/// handles remain stopped and cannot race commands into the reopened image.
pub struct AgentHostControl {
    handle: AgentHostHandle,
    worker: Option<JoinHandle<()>>,
}

impl core::fmt::Debug for AgentHostControl {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("AgentHostControl")
            .field("scope", &self.handle.scope())
            .field("running", &self.is_running())
            .finish_non_exhaustive()
    }
}

impl AgentHostControl {
    pub fn open(
        lease: AgentHostRootLease,
        trust: Arc<dyn AgentTrustProvider>,
    ) -> Result<Self, AgentHostError> {
        Self::open_with_queue_capacity(lease, trust, DEFAULT_AGENT_HOST_QUEUE_CAPACITY)
    }

    pub fn open_with_queue_capacity(
        lease: AgentHostRootLease,
        trust: Arc<dyn AgentTrustProvider>,
        queue_capacity: usize,
    ) -> Result<Self, AgentHostError> {
        if queue_capacity == 0 {
            return Err(AgentHostError::InvalidQueueCapacity);
        }
        let scope = lease.scope();
        let host = AgentHost::open(lease, trust)?;
        let (commands, receiver) = mpsc::sync_channel(queue_capacity);
        let state = Arc::new(AtomicU8::new(WORKER_RUNNING));
        let active_requests = Arc::new(AtomicUsize::new(0));
        let admitted_payload_bytes = Arc::new(AtomicUsize::new(0));
        let last_activity = Arc::new(Mutex::new(Instant::now()));
        let worker_state = state.clone();
        let worker = thread::Builder::new()
            .name("vos-local-agent-host".into())
            .spawn(move || agent_host_worker(host, receiver, worker_state))
            .map_err(|_| AgentHostError::Unavailable)?;
        Ok(Self {
            handle: AgentHostHandle {
                commands,
                state,
                active_requests,
                admitted_payload_bytes,
                payload_capacity_bytes: DEFAULT_AGENT_HOST_PAYLOAD_CAPACITY_BYTES,
                last_activity,
                scope,
            },
            worker: Some(worker),
        })
    }

    pub fn handle(&self) -> AgentHostHandle {
        self.handle.clone()
    }

    /// Stop admitting operations and wake an idle worker. The operation which
    /// already owns the host, if any, is allowed to finish; queued operations
    /// are answered with [`AgentHostError::ShuttingDown`].
    pub fn request_shutdown(&self) {
        if self
            .handle
            .state
            .compare_exchange(
                WORKER_RUNNING,
                WORKER_SHUTTING_DOWN,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
        {
            // A full queue already guarantees that the worker will wake. The
            // state transition, not this best-effort message, is authoritative.
            let _ = self.handle.commands.try_send(AgentHostCommand::Wake);
        }
    }

    pub fn is_running(&self) -> bool {
        self.handle.is_running()
    }

    pub fn shutdown(mut self) -> Result<(), AgentHostError> {
        self.request_shutdown();
        self.join_worker()
    }

    fn join_worker(&mut self) -> Result<(), AgentHostError> {
        let Some(worker) = self.worker.take() else {
            return Ok(());
        };
        worker.join().map_err(|_| AgentHostError::WorkerPanicked)
    }
}

impl Drop for AgentHostControl {
    fn drop(&mut self) {
        self.request_shutdown();
        let _ = self.join_worker();
    }
}

struct WorkerStateGuard(Arc<AtomicU8>);

impl Drop for WorkerStateGuard {
    fn drop(&mut self) {
        self.0.store(WORKER_STOPPED, Ordering::Release);
    }
}

fn agent_host_worker(
    mut host: AgentHost,
    receiver: Receiver<AgentHostCommand>,
    state: Arc<AtomicU8>,
) {
    let _stopped = WorkerStateGuard(state.clone());
    loop {
        if state.load(Ordering::Acquire) != WORKER_RUNNING {
            reject_queued_agent_host_jobs(&receiver);
            return;
        }
        match receiver.recv() {
            Ok(AgentHostCommand::Run { job, activity }) => {
                if state.load(Ordering::Acquire) == WORKER_RUNNING {
                    job(Some(&mut host));
                } else {
                    job(None);
                }
                drop(activity);
            }
            Ok(AgentHostCommand::Wake) => {}
            Err(_) => return,
        }
    }
}

fn reject_queued_agent_host_jobs(receiver: &Receiver<AgentHostCommand>) {
    loop {
        match receiver.try_recv() {
            Ok(AgentHostCommand::Run { job, activity }) => {
                job(None);
                drop(activity);
            }
            Ok(AgentHostCommand::Wake) => {}
            Err(TryRecvError::Empty | TryRecvError::Disconnected) => return,
        }
    }
}

impl AgentHost {
    /// Open every canonical image in `root`.
    ///
    /// Runtime state is validated by executing the exact runtime named in the
    /// image. A missing runtime or malformed image fails the complete open;
    /// the host never exposes a partially recovered directory.
    pub fn open(
        lease: AgentHostRootLease,
        trust: Arc<dyn AgentTrustProvider>,
    ) -> Result<Self, AgentHostError> {
        let root = lease.root().to_path_buf();
        let scope = lease.scope();
        let directory_lock = lock_agent_host_directory(&root)?;
        let scope_state = read_agent_host_scope(&root, scope)?;
        if scope_state.scope().is_some_and(|bound| bound != scope) {
            return Err(AgentHostError::ScopeMismatch);
        }
        let mut discovered = Vec::new();
        for entry in fs::read_dir(&root).map_err(|_| AgentHostError::Unavailable)? {
            let entry = entry.map_err(|_| AgentHostError::Unavailable)?;
            let file_type = entry.file_type().map_err(|_| AgentHostError::Unavailable)?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| AgentHostError::InvalidImageName)?;
            if !name.ends_with(IMAGE_SUFFIX) {
                continue;
            }
            if !file_type.is_file() {
                return Err(AgentHostError::InvalidImageName);
            }
            let encoded = &name[..name.len() - IMAGE_SUFFIX.len()];
            let agent = decode_agent_id(encoded).ok_or(AgentHostError::InvalidImageName)?;
            discovered.push((agent, entry.path()));
        }
        discovered.sort_unstable_by_key(|(agent, _)| *agent);
        if discovered.windows(2).any(|pair| pair[0].0 == pair[1].0) {
            return Err(AgentHostError::DuplicateAgent);
        }
        match scope_state {
            AgentHostScopeState::Bound(_) => {}
            AgentHostScopeState::Staged(_) if discovered.is_empty() => {
                publish_agent_host_scope(
                    &root,
                    &root.join(HOST_SCOPE_TEMP_FILE),
                    &root.join(HOST_SCOPE_FILE),
                )?;
            }
            AgentHostScopeState::Absent if discovered.is_empty() => {
                write_agent_host_scope(&root, scope)?;
            }
            AgentHostScopeState::Staged(_) | AgentHostScopeState::Absent => {
                // Never infer or overwrite the scope of a pre-sidecar image. An
                // explicit offline migration can authenticate that image first;
                // merely trying a caller-selected scope must not poison it.
                return Err(AgentHostError::InvalidScopeBinding);
            }
        }

        let mut agents = BTreeMap::new();
        for (agent, path) in discovered {
            let store = FileAgentStore::new(path);
            let driver = AgentDriver::open(store, trust.clone())?;
            if driver.image().config.identity.agent != agent {
                return Err(AgentHostError::IdentityMismatch);
            }
            if !scope.admits(&driver.image().config) {
                return Err(AgentHostError::ScopeMismatch);
            }
            agents.insert(agent, driver);
        }
        Ok(Self {
            root,
            scope,
            agents,
            trust,
            _directory_lock: directory_lock,
            _root_lease: lease,
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn scope(&self) -> AgentHostScope {
        self.scope
    }

    pub fn len(&self) -> usize {
        self.agents.len()
    }

    pub fn is_empty(&self) -> bool {
        self.agents.is_empty()
    }

    /// Immutable agent identities in canonical ID order.
    pub fn identities(&self) -> impl ExactSizeIterator<Item = &AgentIdentity> {
        self.agents
            .values()
            .map(|driver| &driver.image().config.identity)
    }

    pub fn identity(&self, agent: AgentId) -> Option<&AgentIdentity> {
        self.agents
            .get(&agent)
            .map(|driver| &driver.image().config.identity)
    }

    /// Validate a Local creation target and runtime package without writing
    /// the image or consuming an authority sequence.
    pub fn prepare_create(
        &self,
        config: &AgentConfig,
        runtime_package: &Package,
    ) -> Result<PreparedLifecycleRequest, AgentHostError> {
        if !self.scope.admits(config) {
            return Err(AgentHostError::ScopeMismatch);
        }
        if let Some(driver) = self.agents.get(&config.identity.agent)
            && driver.image().config != *config
        {
            return Err(AgentHostError::DuplicateAgent);
        }
        let request = AgentDriver::<FileAgentStore>::create_request(
            config,
            runtime_package,
            self.trust.as_ref(),
        )?;
        PreparedLifecycleRequest::new(config, request)
    }

    pub fn prepare_actor_install(
        &self,
        agent: AgentId,
        name: String,
        parent: Option<ActorId>,
        package: &Package,
    ) -> Result<PreparedLifecycleRequest, AgentHostError> {
        let driver = self
            .agents
            .get(&agent)
            .ok_or(AgentHostError::AgentNotFound)?;
        let request = driver.actor_install_request(name, parent, package)?;
        PreparedLifecycleRequest::new(&driver.image().config, request)
    }

    pub fn prepare_actor_upgrade(
        &self,
        agent: AgentId,
        actor: ActorId,
        from_deployment: DeploymentId,
        package: &Package,
    ) -> Result<PreparedLifecycleRequest, AgentHostError> {
        let driver = self
            .agents
            .get(&agent)
            .ok_or(AgentHostError::AgentNotFound)?;
        let request = driver.actor_upgrade_request(actor, from_deployment, package)?;
        PreparedLifecycleRequest::new(&driver.image().config, request)
    }

    pub fn prepare_actor_suspend(
        &self,
        agent: AgentId,
        actor: ActorId,
    ) -> Result<PreparedLifecycleRequest, AgentHostError> {
        let driver = self
            .agents
            .get(&agent)
            .ok_or(AgentHostError::AgentNotFound)?;
        let request = driver.actor_suspend_request(actor)?;
        PreparedLifecycleRequest::new(&driver.image().config, request)
    }

    pub fn prepare_actor_resume(
        &self,
        agent: AgentId,
        actor: ActorId,
    ) -> Result<PreparedLifecycleRequest, AgentHostError> {
        let driver = self
            .agents
            .get(&agent)
            .ok_or(AgentHostError::AgentNotFound)?;
        let request = driver.actor_resume_request(actor)?;
        PreparedLifecycleRequest::new(&driver.image().config, request)
    }

    pub fn prepare_actor_remove(
        &self,
        agent: AgentId,
        actor: ActorId,
        expected_deployment: DeploymentId,
    ) -> Result<PreparedLifecycleRequest, AgentHostError> {
        let driver = self
            .agents
            .get(&agent)
            .ok_or(AgentHostError::AgentNotFound)?;
        let request =
            AgentDriver::<FileAgentStore>::actor_remove_request(actor, expected_deployment)?;
        PreparedLifecycleRequest::new(&driver.image().config, request)
    }

    pub fn prepare_runtime_upgrade(
        &self,
        agent: AgentId,
        from_deployment: DeploymentId,
        package: &Package,
    ) -> Result<PreparedLifecycleRequest, AgentHostError> {
        let driver = self
            .agents
            .get(&agent)
            .ok_or(AgentHostError::AgentNotFound)?;
        let request = driver.runtime_upgrade_request(from_deployment, package)?;
        PreparedLifecycleRequest::new(&driver.image().config, request)
    }

    /// Create a durable empty agent with its explicitly selected runtime.
    pub fn create(
        &mut self,
        config: AgentConfig,
        runtime_package: Package,
        authority: &AgentAuthorityReceipt,
    ) -> Result<AgentIdentity, AgentHostError> {
        if !self.scope.admits(&config) {
            return Err(AgentHostError::ScopeMismatch);
        }
        let agent = config.identity.agent;
        if self.agents.contains_key(&agent) {
            self.agents
                .get_mut(&agent)
                .expect("agent presence checked above")
                .retry_create(&config, &runtime_package, authority)?;
            return Ok(self
                .agents
                .get(&agent)
                .expect("agent presence checked above")
                .image()
                .config
                .identity
                .clone());
        }
        let path = self.image_path(agent);
        if path.exists() {
            // A prior Create may have reached the atomic image rename before
            // its final directory sync (or before the caller received the
            // response). Reopen the exact durable closure and recover only
            // the same authority disposition; mismatched or corrupt images
            // still fail closed.
            let mut driver = AgentDriver::open(FileAgentStore::new(&path), self.trust.clone())?;
            if driver.image().config.identity.agent != agent {
                return Err(AgentHostError::IdentityMismatch);
            }
            let identity = driver.retry_create(&config, &runtime_package, authority)?;
            self.agents.insert(agent, driver);
            return Ok(identity);
        }
        let store = FileAgentStore::new(path);
        let driver = AgentDriver::create(
            runtime_package,
            config,
            store,
            self.trust.clone(),
            authority,
        )?;
        self.agents.insert(agent, driver);
        Ok(self
            .agents
            .get(&agent)
            .expect("agent was inserted above")
            .image()
            .config
            .identity
            .clone())
    }

    pub fn inspect(
        &mut self,
        agent: AgentId,
        after: Option<ActorId>,
        limit: u16,
    ) -> Result<ActorDirectoryPage, AgentHostError> {
        self.agents
            .get_mut(&agent)
            .ok_or(AgentHostError::AgentNotFound)?
            .inspect(after, limit)
            .map_err(Into::into)
    }

    pub fn install_actor(
        &mut self,
        agent: AgentId,
        authority: &AgentAuthorityReceipt,
        name: String,
        parent: Option<ActorId>,
        package: &Package,
    ) -> Result<ActorEntry, AgentHostError> {
        self.agents
            .get_mut(&agent)
            .ok_or(AgentHostError::AgentNotFound)?
            .install_actor(authority, name, parent, package)
            .map_err(Into::into)
    }

    pub fn upgrade_actor(
        &mut self,
        agent: AgentId,
        authority: &AgentAuthorityReceipt,
        actor: ActorId,
        from_deployment: DeploymentId,
        package: &Package,
    ) -> Result<ActorEntry, AgentHostError> {
        self.agents
            .get_mut(&agent)
            .ok_or(AgentHostError::AgentNotFound)?
            .upgrade_actor(authority, actor, from_deployment, package)
            .map_err(Into::into)
    }

    pub fn suspend_actor(
        &mut self,
        agent: AgentId,
        authority: &AgentAuthorityReceipt,
        actor: ActorId,
    ) -> Result<ActorEntry, AgentHostError> {
        self.agents
            .get_mut(&agent)
            .ok_or(AgentHostError::AgentNotFound)?
            .suspend_actor(authority, actor)
            .map_err(Into::into)
    }

    pub fn resume_actor(
        &mut self,
        agent: AgentId,
        authority: &AgentAuthorityReceipt,
        actor: ActorId,
    ) -> Result<ActorEntry, AgentHostError> {
        self.agents
            .get_mut(&agent)
            .ok_or(AgentHostError::AgentNotFound)?
            .resume_actor(authority, actor)
            .map_err(Into::into)
    }

    pub fn remove_actor(
        &mut self,
        agent: AgentId,
        authority: &AgentAuthorityReceipt,
        actor: ActorId,
        expected_deployment: DeploymentId,
    ) -> Result<(), AgentHostError> {
        self.agents
            .get_mut(&agent)
            .ok_or(AgentHostError::AgentNotFound)?
            .remove_actor(authority, actor, expected_deployment)
            .map_err(Into::into)
    }

    pub fn upgrade_runtime(
        &mut self,
        agent: AgentId,
        authority: &AgentAuthorityReceipt,
        from_deployment: DeploymentId,
        package: &Package,
    ) -> Result<AgentIdentity, AgentHostError> {
        self.agents
            .get_mut(&agent)
            .ok_or(AgentHostError::AgentNotFound)?
            .upgrade_runtime(authority, from_deployment, package)
            .map_err(Into::into)
    }

    pub fn invoke(
        &mut self,
        agent: AgentId,
        invocation: ActorInvocation,
        authority: &ActorInvocationReceipt,
    ) -> Result<ActorExecutionReply, AgentHostError> {
        self.agents
            .get_mut(&agent)
            .ok_or(AgentHostError::AgentNotFound)?
            .invoke(invocation, authority)
            .map_err(Into::into)
    }

    pub fn acknowledge_invocation(
        &mut self,
        agent: AgentId,
        invocation: ActorInvocation,
        authority: &ActorInvocationReceipt,
    ) -> Result<(), AgentHostError> {
        self.agents
            .get_mut(&agent)
            .ok_or(AgentHostError::AgentNotFound)?
            .acknowledge_invocation(invocation, authority)
            .map_err(Into::into)
    }

    pub fn revision(&self, agent: AgentId) -> Option<u64> {
        self.agents
            .get(&agent)
            .map(|driver| driver.image().revision)
    }

    fn image_path(&self, agent: AgentId) -> PathBuf {
        self.root
            .join(format!("{}{}", encode_agent_id(agent), IMAGE_SUFFIX))
    }
}

fn ensure_agent_host_root(root: PathBuf) -> Result<PathBuf, AgentHostError> {
    let root = absolute_agent_host_path(root)?;
    let created = match fs::symlink_metadata(&root) {
        Ok(metadata) => {
            if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
                return Err(AgentHostError::InvalidScopeBinding);
            }
            false
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir_all(&root).map_err(|_| AgentHostError::Unavailable)?;
            true
        }
        Err(_) => return Err(AgentHostError::Unavailable),
    };
    let metadata = fs::symlink_metadata(&root).map_err(|_| AgentHostError::Unavailable)?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        return Err(AgentHostError::InvalidScopeBinding);
    }
    if created && let Some(parent) = root.parent() {
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| AgentHostError::Unavailable)?;
    }
    fs::canonicalize(root).map_err(|_| AgentHostError::Unavailable)
}

fn absolute_agent_host_path(path: PathBuf) -> Result<PathBuf, AgentHostError> {
    if path.is_absolute() {
        Ok(path)
    } else {
        Ok(std::env::current_dir()
            .map_err(|_| AgentHostError::Unavailable)?
            .join(path))
    }
}

fn canonical_lock_path(path: PathBuf) -> Result<PathBuf, AgentHostError> {
    let path = if path.is_absolute() {
        path
    } else {
        std::env::current_dir()
            .map_err(|_| AgentHostError::Unavailable)?
            .join(path)
    };
    let file_name = path
        .file_name()
        .ok_or(AgentHostError::InvalidScopeBinding)?
        .to_owned();
    let parent = path.parent().ok_or(AgentHostError::InvalidScopeBinding)?;
    fs::create_dir_all(parent).map_err(|_| AgentHostError::Unavailable)?;
    let parent = fs::canonicalize(parent).map_err(|_| AgentHostError::Unavailable)?;
    Ok(parent.join(file_name))
}

fn open_agent_host_lock(path: &Path) -> Result<File, AgentHostError> {
    let existed = match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
                return Err(AgentHostError::InvalidScopeBinding);
            }
            true
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(_) => return Err(AgentHostError::Unavailable),
    };
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options
        .open(path)
        .map_err(|_| AgentHostError::Unavailable)?;
    if !file
        .metadata()
        .map_err(|_| AgentHostError::Unavailable)?
        .file_type()
        .is_file()
    {
        return Err(AgentHostError::InvalidScopeBinding);
    }
    FileExt::try_lock_exclusive(&file).map_err(|error| {
        if error.kind() == std::io::ErrorKind::WouldBlock {
            AgentHostError::DirectoryInUse
        } else {
            AgentHostError::Unavailable
        }
    })?;
    if !existed {
        file.sync_all().map_err(|_| AgentHostError::Unavailable)?;
        if let Some(parent) = path.parent() {
            File::open(parent)
                .and_then(|directory| directory.sync_all())
                .map_err(|_| AgentHostError::Unavailable)?;
        }
    }
    Ok(file)
}

fn lock_agent_host_directory(root: &Path) -> Result<File, AgentHostError> {
    open_agent_host_lock(&root.join(HOST_LOCK_FILE))
}

#[derive(Clone, Copy)]
enum AgentHostScopeState {
    Absent,
    Bound(AgentHostScope),
    Staged(AgentHostScope),
}

impl AgentHostScopeState {
    const fn scope(self) -> Option<AgentHostScope> {
        match self {
            Self::Absent => None,
            Self::Bound(scope) | Self::Staged(scope) => Some(scope),
        }
    }
}

fn read_agent_host_scope(
    root: &Path,
    requested: AgentHostScope,
) -> Result<AgentHostScopeState, AgentHostError> {
    let path = root.join(HOST_SCOPE_FILE);
    let temp = root.join(HOST_SCOPE_TEMP_FILE);
    let final_scope = read_agent_host_scope_file(&path)?;
    let staged_scope = read_agent_host_scope_file(&temp)?;
    match (final_scope, staged_scope) {
        (Some(bound), Some(staged)) => {
            if bound != staged {
                return Err(AgentHostError::InvalidScopeBinding);
            }
            if bound != requested {
                return Err(AgentHostError::ScopeMismatch);
            }
            fs::remove_file(temp).map_err(|_| AgentHostError::Unavailable)?;
            sync_agent_host_directory(root)?;
            Ok(AgentHostScopeState::Bound(bound))
        }
        (Some(bound), None) => Ok(AgentHostScopeState::Bound(bound)),
        (None, Some(staged)) => {
            if staged != requested {
                return Err(AgentHostError::ScopeMismatch);
            }
            Ok(AgentHostScopeState::Staged(staged))
        }
        (None, None) => Ok(AgentHostScopeState::Absent),
    }
}

fn read_agent_host_scope_file(path: &Path) -> Result<Option<AgentHostScope>, AgentHostError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(AgentHostError::Unavailable),
    };
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() != HOST_SCOPE_ENCODED_LEN as u64
    {
        return Err(AgentHostError::InvalidScopeBinding);
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let mut file = options
        .open(path)
        .map_err(|_| AgentHostError::Unavailable)?;
    let opened_metadata = file.metadata().map_err(|_| AgentHostError::Unavailable)?;
    if !opened_metadata.file_type().is_file()
        || opened_metadata.len() != HOST_SCOPE_ENCODED_LEN as u64
    {
        return Err(AgentHostError::InvalidScopeBinding);
    }
    let mut encoded = [0; HOST_SCOPE_ENCODED_LEN];
    file.read_exact(&mut encoded)
        .map_err(|_| AgentHostError::InvalidScopeBinding)?;
    let mut trailing = [0; 1];
    if file
        .read(&mut trailing)
        .map_err(|_| AgentHostError::InvalidScopeBinding)?
        != 0
    {
        return Err(AgentHostError::InvalidScopeBinding);
    }
    if &encoded[..HOST_SCOPE_MAGIC.len()] != HOST_SCOPE_MAGIC {
        return Err(AgentHostError::InvalidScopeBinding);
    }
    let mut space = [0; 32];
    space.copy_from_slice(&encoded[HOST_SCOPE_MAGIC.len()..HOST_SCOPE_MAGIC.len() + 32]);
    let mut node = [0; 32];
    node.copy_from_slice(&encoded[HOST_SCOPE_MAGIC.len() + 32..]);
    Ok(Some(AgentHostScope {
        space: SpaceId(space),
        node: NodeId(node),
    }))
}

fn write_agent_host_scope(root: &Path, scope: AgentHostScope) -> Result<(), AgentHostError> {
    let path = root.join(HOST_SCOPE_FILE);
    let temp = root.join(HOST_SCOPE_TEMP_FILE);
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let mut file = options
        .open(&temp)
        .map_err(|_| AgentHostError::InvalidScopeBinding)?;
    file.write_all(HOST_SCOPE_MAGIC)
        .and_then(|()| file.write_all(&scope.space.0))
        .and_then(|()| file.write_all(&scope.node.0))
        .and_then(|()| file.sync_all())
        .map_err(|_| AgentHostError::Unavailable)?;
    publish_agent_host_scope(root, &temp, &path)
}

fn publish_agent_host_scope(root: &Path, temp: &Path, path: &Path) -> Result<(), AgentHostError> {
    // A recovered staging inode may predate this process. Re-establish its
    // durability before making it the canonical binding, even though the
    // ordinary writer already synced it before reaching this helper.
    let staged_metadata =
        fs::symlink_metadata(temp).map_err(|_| AgentHostError::InvalidScopeBinding)?;
    if !staged_metadata.file_type().is_file()
        || staged_metadata.file_type().is_symlink()
        || staged_metadata.len() != HOST_SCOPE_ENCODED_LEN as u64
    {
        return Err(AgentHostError::InvalidScopeBinding);
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let staged = options
        .open(temp)
        .map_err(|_| AgentHostError::InvalidScopeBinding)?;
    let metadata = staged.metadata().map_err(|_| AgentHostError::Unavailable)?;
    if !metadata.file_type().is_file() || metadata.len() != HOST_SCOPE_ENCODED_LEN as u64 {
        return Err(AgentHostError::InvalidScopeBinding);
    }
    staged.sync_all().map_err(|_| AgentHostError::Unavailable)?;
    fs::hard_link(temp, path).map_err(|_| AgentHostError::InvalidScopeBinding)?;
    fs::remove_file(temp).map_err(|_| AgentHostError::Unavailable)?;
    sync_agent_host_directory(root)
}

fn sync_agent_host_directory(root: &Path) -> Result<(), AgentHostError> {
    File::open(root)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| AgentHostError::Unavailable)
}

fn encode_agent_id(agent: AgentId) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(64);
    for byte in agent.0 {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn decode_agent_id(input: &str) -> Option<AgentId> {
    if input.len() != 64 || !input.is_ascii() {
        return None;
    }
    let mut bytes = [0u8; 32];
    for (index, pair) in input.as_bytes().chunks_exact(2).enumerate() {
        bytes[index] = (decode_nibble(pair[0])? << 4) | decode_nibble(pair[1])?;
    }
    Some(AgentId(bytes))
}

fn decode_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service::SpaceId;

    struct NoTrust;

    impl AgentTrustProvider for NoTrust {
        fn current_logical_slot(&self) -> Option<u64> {
            None
        }

        fn authority_for_space(
            &self,
            _space: SpaceId,
        ) -> Option<super::super::authority::AgentAuthorityBinding> {
            None
        }

        fn verify_package(&self, _agent: &AgentConfig, _package: &Package) -> bool {
            false
        }
    }

    struct RemoveOnDrop(PathBuf);

    impl Drop for RemoveOnDrop {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn empty_host_directory(test: &str) -> (PathBuf, PathBuf, RemoveOnDrop) {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let base = std::env::temp_dir().join(format!(
            "vos-agent-host-{test}-{}-{unique}",
            std::process::id()
        ));
        (
            base.join("data"),
            base.join("owner.lock"),
            RemoveOnDrop(base),
        )
    }

    fn scope() -> AgentHostScope {
        AgentHostScope {
            space: SpaceId([1; 32]),
            node: NodeId([2; 32]),
        }
    }

    fn lease(root: &Path, lock: &Path, scope: AgentHostScope) -> AgentHostRootLease {
        AgentHostRootLease::acquire(root, lock, scope).unwrap()
    }

    fn encoded_scope(scope: AgentHostScope) -> Vec<u8> {
        let mut encoded = Vec::new();
        encoded.extend_from_slice(HOST_SCOPE_MAGIC);
        encoded.extend_from_slice(&scope.space.0);
        encoded.extend_from_slice(&scope.node.0);
        encoded
    }

    fn payload_test_runtime_package() -> Package {
        let pvm = vos_pvm_program::build_standard_program(&vos_pvm_program::StandardProgram {
            ro_data: Vec::new(),
            rw_data: Vec::new(),
            heap_pages: 0,
            stack_size: vos_pvm_program::PAGE_SIZE,
            code: vos_pvm_program::CodeBlob {
                jump_table: Vec::new(),
                code: vec![0],
                bitmask: vec![1],
            },
        })
        .unwrap();
        let generated_interfaces = b"agent-runtime-lifecycle".to_vec();
        let schemas = b"agent-runtime-schema".to_vec();
        let public_key = b"payload-test-producer".to_vec();
        let package = Package {
            manifest: super::super::package::PackageManifest {
                name: "payload-test-runtime".into(),
                platform: crate::service::PLATFORM_ID,
                execution_semantics: super::super::EXECUTION_SEMANTICS_ID,
                kind: super::super::PackageKind::AgentRuntime {
                    contract: super::super::contract::RuntimePackageContract::canonical(),
                    capabilities: super::super::RuntimeCapabilities::standard(),
                },
                program: crate::service::ProgramId::of_pvm(&pvm),
                interfaces_hash: crate::service::artifact_hash(
                    b"interfaces",
                    &generated_interfaces,
                ),
                role_policies_hash: crate::service::artifact_hash(b"role-policies", &[]),
                schemas_hash: crate::service::artifact_hash(b"schemas", &schemas),
                agent_schema_hash: crate::service::artifact_hash(b"agent-schema", &[]),
                dependencies_hash: crate::service::task_dependencies_hash(&[]),
            },
            pvm,
            generated_interfaces,
            role_policies: Vec::new(),
            schemas,
            agent_schema: Vec::new(),
            task_dependencies: Vec::new(),
            diagnostics: None,
            deployment_signature: crate::service::DeploymentSignature {
                producer: crate::service::ProducerId::of_public_key(&public_key),
                public_key,
                signature: vec![1],
            },
        };
        package.validate().unwrap();
        package
    }

    fn payload_test_authority(agent: AgentId) -> AgentAuthorityBinding {
        let public_key = super::super::authority::ed25519_public_key_wire([0x71; 32]);
        AgentAuthorityBinding {
            agent,
            actor: ActorId([0x72; 32]),
            deployment: DeploymentId([0x73; 32]),
            program: ProgramId([0x74; 32]),
            producer: crate::service::ProducerId::of_public_key(&public_key),
            public_key,
        }
    }

    fn payload_test_config(
        runtime_package: &Package,
        replicas: Vec<super::super::AgentReplica>,
    ) -> AgentConfig {
        let owner = crate::service::PrincipalId([0x75; 32]);
        let creation_nonce = Hash([0x76; 32]);
        let agent = AgentId::derive(scope().space, owner, &creation_nonce.0);
        AgentConfig {
            identity: AgentIdentity {
                space: scope().space,
                agent,
                owner,
                profile: super::super::AgentProfile::Local,
                runtime_deployment: DeploymentId([0x77; 32]),
                runtime_program: runtime_package.manifest.program,
                runtime_producer: runtime_package.deployment_signature.producer,
            },
            creation_nonce,
            authority: payload_test_authority(agent),
            runtime_package: crate::service::BlobRef {
                hash: Hash([0x78; 32]),
                len: 1,
            },
            runtime_contract: super::super::contract::RuntimePackageContract::canonical(),
            capabilities: super::super::RuntimeCapabilities::standard(),
            replicas,
        }
    }

    fn payload_test_invocation_receipt(agent: AgentId) -> ActorInvocationReceipt {
        ActorInvocationReceipt {
            claim: super::super::authority::ActorInvocationClaim {
                authority: payload_test_authority(agent),
                space: scope().space,
                agent,
                principal: None,
                credential: None,
                authorization: Hash([0x79; 32]),
                auth: super::super::execution::ActorInvocationAuth::anonymous(),
                valid_from: 1,
                valid_until: 2,
            },
            signature: vec![0; super::super::authority::ED25519_SIGNATURE_BYTES],
        }
    }

    fn wait_for_payload(handle: &AgentHostHandle, predicate: impl Fn(usize) -> bool) -> usize {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let payload = handle.admitted_payload_bytes_for_test();
            if predicate(payload) {
                return payload;
            }
            assert!(
                Instant::now() < deadline,
                "timed out waiting for Agent-host payload reservation; current={payload}"
            );
            thread::sleep(Duration::from_millis(1));
        }
    }

    #[test]
    fn agent_image_names_are_canonical() {
        let agent = AgentId([0xab; 32]);
        let encoded = encode_agent_id(agent);
        assert_eq!(encoded.len(), 64);
        assert_eq!(decode_agent_id(&encoded), Some(agent));
        assert_eq!(decode_agent_id(&encoded.to_uppercase()), None);
        assert_eq!(decode_agent_id("ab"), None);
    }

    #[test]
    fn worker_handle_is_bounded_and_shutdown_is_terminal() {
        fn assert_send<T: Send>() {}
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send::<AgentHostControl>();
        assert_send_sync::<AgentHostHandle>();

        let (directory, lock, _remove) = empty_host_directory("bounded-worker");
        let control = AgentHostControl::open_with_queue_capacity(
            lease(&directory, &lock, scope()),
            Arc::new(NoTrust),
            1,
        )
        .unwrap();
        let handle = control.handle();

        let (active, active_rx) = mpsc::sync_channel(0);
        let (release, release_rx) = mpsc::sync_channel(0);
        let active_handle = handle.clone();
        let active_thread = thread::spawn(move || {
            active_handle.request(0, move |_| {
                active.send(()).unwrap();
                release_rx.recv().unwrap();
                Ok(())
            })
        });
        active_rx.recv().unwrap();
        assert_eq!(handle.idle_for(), Duration::ZERO);

        let (queued_reply, queued_result) = mpsc::sync_channel(1);
        handle
            .commands
            .try_send(AgentHostCommand::Run {
                job: Box::new(move |host| {
                    queued_reply
                        .send(if host.is_some() {
                            Ok(())
                        } else {
                            Err(AgentHostError::ShuttingDown)
                        })
                        .unwrap();
                }),
                activity: AgentHostActivity::reserve(&handle, 1024).unwrap(),
            })
            .map_err(|_| ())
            .unwrap();
        let admitted_before_full_send = handle.admitted_payload_bytes_for_test();
        assert_eq!(handle.identities(), Err(AgentHostError::Overloaded));
        assert_eq!(
            handle.admitted_payload_bytes_for_test(),
            admitted_before_full_send,
            "a full command channel must release the rejected reservation"
        );

        control.request_shutdown();
        assert_eq!(handle.identities(), Err(AgentHostError::ShuttingDown));
        release.send(()).unwrap();
        assert_eq!(active_thread.join().unwrap(), Ok(()));
        assert_eq!(
            queued_result.recv().unwrap(),
            Err(AgentHostError::ShuttingDown)
        );
        control.shutdown().unwrap();
        assert_eq!(handle.admitted_payload_bytes_for_test(), 0);
        assert_eq!(handle.identities(), Err(AgentHostError::WorkerStopped));
    }

    #[test]
    fn worker_payload_budget_backpressures_and_releases_on_completion() {
        let (directory, lock, _remove) = empty_host_directory("payload-budget");
        let control = AgentHostControl::open_with_queue_capacity(
            lease(&directory, &lock, scope()),
            Arc::new(NoTrust),
            4,
        )
        .unwrap();
        let handle = control.handle();

        let (active, active_rx) = mpsc::sync_channel(0);
        let (release, release_rx) = mpsc::sync_channel(0);
        let active_handle = handle.clone();
        let active_thread = thread::spawn(move || {
            active_handle.request(DEFAULT_AGENT_HOST_PAYLOAD_CAPACITY_BYTES / 2, move |_| {
                active.send(()).unwrap();
                release_rx.recv().unwrap();
                Ok(())
            })
        });
        active_rx.recv().unwrap();
        let admitted = handle.admitted_payload_bytes_for_test();
        assert!(admitted > DEFAULT_AGENT_HOST_PAYLOAD_CAPACITY_BYTES / 2);
        assert_eq!(
            handle.request(DEFAULT_AGENT_HOST_PAYLOAD_CAPACITY_BYTES / 2, |_| Ok(())),
            Err(AgentHostError::Overloaded)
        );
        assert_eq!(handle.admitted_payload_bytes_for_test(), admitted);

        release.send(()).unwrap();
        assert_eq!(active_thread.join().unwrap(), Ok(()));
        wait_for_payload(&handle, |payload| payload == 0);
        assert_eq!(
            handle.request(DEFAULT_AGENT_HOST_PAYLOAD_CAPACITY_BYTES / 2, |_| Ok(())),
            Ok(())
        );
        wait_for_payload(&handle, |payload| payload == 0);
        control.shutdown().unwrap();
    }

    #[test]
    fn nested_package_capacity_is_rejected_without_leaking_reservation() {
        let (directory, lock, _remove) = empty_host_directory("nested-payload-budget");
        let control =
            AgentHostControl::open(lease(&directory, &lock, scope()), Arc::new(NoTrust)).unwrap();
        let handle = control.handle();

        let mut package = payload_test_runtime_package();
        package.diagnostics = Some(crate::service::PackageDiagnostics {
            // Length remains zero, so the package's canonical wire is small;
            // retaining its caller-selected spare capacity is what admission
            // must account for.
            elf: Some(Vec::with_capacity(
                DEFAULT_AGENT_HOST_PAYLOAD_CAPACITY_BYTES + 1,
            )),
            source_map: Some(Vec::with_capacity(1024)),
        });
        package.task_dependencies = Vec::with_capacity(256);
        assert!(package.validate().is_ok());
        assert!(package_heap_payload_bytes(&package) > DEFAULT_AGENT_HOST_PAYLOAD_CAPACITY_BYTES);

        assert_eq!(
            handle.prepare_runtime_upgrade(AgentId([3; 32]), DeploymentId([4; 32]), package,),
            Err(AgentHostError::Overloaded)
        );
        assert_eq!(handle.admitted_payload_bytes_for_test(), 0);

        // Dependency programs are nested allocations, separate from the outer
        // dependency-vector storage. Keep a direct regression assertion even
        // though runtime packages correctly reject non-empty dependencies.
        let mut nested = payload_test_runtime_package();
        let dependency_program = Vec::with_capacity(4 * 1024 * 1024);
        nested
            .task_dependencies
            .push(crate::service::PackageTaskDependency {
                binding: crate::service::TaskDependency {
                    task: Hash([5; 32]),
                    program: crate::service::ProgramId([6; 32]),
                    witness_address: 1,
                    witness_capacity: 1,
                },
                pvm: dependency_program,
            });
        assert!(
            package_heap_payload_bytes(&nested)
                >= nested.task_dependencies[0].pvm.capacity().saturating_add(
                    vector_allocation_bytes::<crate::service::PackageTaskDependency>(
                        nested.task_dependencies.capacity()
                    )
                )
        );

        control.shutdown().unwrap();
    }

    #[test]
    fn oversized_shapes_are_rejected_before_worker_or_payload_admission() {
        const SHAPE_STRESS_ITEMS: usize = 65_536;

        let runtime_package = payload_test_runtime_package();
        let replica = super::super::AgentReplica {
            node: scope().node,
            principal: crate::service::PrincipalId([0x7a; 32]),
            role: super::super::ReplicaRole::Voter,
        };
        let oversized_config =
            payload_test_config(&runtime_package, vec![replica; SHAPE_STRESS_ITEMS]);

        let mut oversized_dependencies = payload_test_runtime_package();
        let dependency = crate::service::PackageTaskDependency {
            binding: crate::service::TaskDependency {
                task: Hash([0x7b; 32]),
                program: ProgramId([0x7c; 32]),
                witness_address: 1,
                witness_capacity: 1,
            },
            pvm: Vec::new(),
        };
        oversized_dependencies.task_dependencies = vec![dependency; SHAPE_STRESS_ITEMS];

        let invocation_agent = AgentId([0x7d; 32]);
        let blob = super::super::execution::RuntimeBlob {
            reference: crate::service::BlobRef {
                hash: Hash([0x7e; 32]),
                len: 0,
            },
            bytes: Vec::new(),
        };
        let oversized_invocation = ActorInvocation {
            invocation: InvocationId([0x7f; 32]),
            actor: ActorId([0x80; 32]),
            incarnation: Hash([0x83; 32]),
            deployment: DeploymentId([0x81; 32]),
            program: ProgramId([0x82; 32]),
            mode: super::super::MethodMode::Query,
            auth: super::super::execution::ActorInvocationAuth::anonymous(),
            message: vec![1],
            availability: vec![blob; SHAPE_STRESS_ITEMS],
            gas: 1,
        };
        let invocation_receipt = payload_test_invocation_receipt(invocation_agent);

        let (directory, lock, _remove) = empty_host_directory("oversized-shapes");
        let control =
            AgentHostControl::open(lease(&directory, &lock, scope()), Arc::new(NoTrust)).unwrap();
        let handle = control.handle();

        let (active, active_rx) = mpsc::sync_channel(0);
        let (release, release_rx) = mpsc::sync_channel(0);
        let active_handle = handle.clone();
        let active_thread =
            thread::spawn(move || active_handle.block_worker_for_test(active, release_rx));
        active_rx.recv().unwrap();
        let active_payload = handle.admitted_payload_bytes_for_test();

        let (done, done_rx) = mpsc::sync_channel(1);
        let shape_handle = handle.clone();
        let shape_thread = thread::spawn(move || {
            let config_result = shape_handle.prepare_create(oversized_config, runtime_package);
            let payload_after_config = shape_handle.admitted_payload_bytes_for_test();
            let package_result = shape_handle.prepare_runtime_upgrade(
                AgentId([0x83; 32]),
                DeploymentId([0x84; 32]),
                oversized_dependencies,
            );
            let payload_after_package = shape_handle.admitted_payload_bytes_for_test();
            let invocation_result =
                shape_handle.invoke(invocation_agent, oversized_invocation, invocation_receipt);
            let payload_after_invocation = shape_handle.admitted_payload_bytes_for_test();
            done.send((
                config_result,
                payload_after_config,
                package_result,
                payload_after_package,
                invocation_result,
                payload_after_invocation,
            ))
            .unwrap();
        });

        let outcome = done_rx.recv_timeout(Duration::from_secs(5));
        if outcome.is_err() {
            let payload = handle.admitted_payload_bytes_for_test();
            release.send(()).unwrap();
            assert_eq!(active_thread.join().unwrap(), Ok(()));
            shape_thread.join().unwrap();
            control.shutdown().unwrap();
            panic!("oversized shape reached the serialized worker; admitted payload was {payload}");
        }
        let (
            config_result,
            payload_after_config,
            package_result,
            payload_after_package,
            invocation_result,
            payload_after_invocation,
        ) = outcome.unwrap();
        assert_eq!(config_result, Err(AgentHostError::ScopeMismatch));
        assert_eq!(payload_after_config, active_payload);
        assert_eq!(
            package_result,
            Err(invalid_package_shape(PackageError::ArtifactsTooLarge))
        );
        assert_eq!(payload_after_package, active_payload);
        assert_eq!(invocation_result, Err(invalid_invocation_shape()));
        assert_eq!(payload_after_invocation, active_payload);

        release.send(()).unwrap();
        assert_eq!(active_thread.join().unwrap(), Ok(()));
        shape_thread.join().unwrap();
        wait_for_payload(&handle, |payload| payload == 0);
        control.shutdown().unwrap();
    }

    #[test]
    fn worker_panic_releases_active_and_queued_payload() {
        let (directory, lock, _remove) = empty_host_directory("payload-panic");
        let control = AgentHostControl::open_with_queue_capacity(
            lease(&directory, &lock, scope()),
            Arc::new(NoTrust),
            4,
        )
        .unwrap();
        let handle = control.handle();

        let (active, active_rx) = mpsc::sync_channel(0);
        let (release, release_rx) = mpsc::sync_channel(0);
        let crashing_handle = handle.clone();
        let crashing = thread::spawn(move || {
            crashing_handle.request(
                DEFAULT_AGENT_HOST_PAYLOAD_CAPACITY_BYTES / 4,
                move |_| -> Result<(), AgentHostError> {
                    active.send(()).unwrap();
                    release_rx.recv().unwrap();
                    panic!("intentional Agent-host payload cleanup crash")
                },
            )
        });
        active_rx.recv().unwrap();
        let active_payload = handle.admitted_payload_bytes_for_test();

        let queued_handle = handle.clone();
        let queued = thread::spawn(move || {
            queued_handle.request(DEFAULT_AGENT_HOST_PAYLOAD_CAPACITY_BYTES / 4, |_| Ok(()))
        });
        wait_for_payload(&handle, |payload| payload > active_payload);
        release.send(()).unwrap();

        assert_eq!(crashing.join().unwrap(), Err(AgentHostError::WorkerStopped));
        assert_eq!(queued.join().unwrap(), Err(AgentHostError::WorkerStopped));
        wait_for_payload(&handle, |payload| payload == 0);
        assert_eq!(control.shutdown(), Err(AgentHostError::WorkerPanicked));
    }

    #[test]
    fn zero_capacity_is_rejected() {
        let (directory, lock, _remove) = empty_host_directory("zero-capacity");
        assert!(matches!(
            AgentHostControl::open_with_queue_capacity(
                lease(&directory, &lock, scope()),
                Arc::new(NoTrust),
                0,
            ),
            Err(AgentHostError::InvalidQueueCapacity)
        ));
    }

    #[test]
    fn zero_or_partial_scope_is_rejected() {
        let (directory, lock, _remove) = empty_host_directory("invalid-scope");
        assert!(matches!(
            AgentHostRootLease::acquire(
                &directory,
                &lock,
                AgentHostScope {
                    space: SpaceId::ZERO,
                    node: NodeId([2; 32]),
                },
            ),
            Err(AgentHostError::InvalidScope)
        ));
        assert!(matches!(
            AgentHostRootLease::acquire(
                directory,
                lock,
                AgentHostScope {
                    space: SpaceId([1; 32]),
                    node: NodeId::ZERO,
                },
            ),
            Err(AgentHostError::InvalidScope)
        ));
    }

    #[test]
    fn directory_scope_is_durable_and_has_one_live_owner() {
        let (directory, lock, _remove) = empty_host_directory("directory-owner");
        let control =
            AgentHostControl::open(lease(&directory, &lock, scope()), Arc::new(NoTrust)).unwrap();
        assert!(matches!(
            AgentHostRootLease::acquire(&directory, &lock, scope()),
            Err(AgentHostError::DirectoryInUse)
        ));
        let moved = directory.with_extension("live-root");
        fs::rename(&directory, &moved).unwrap();
        assert!(matches!(
            AgentHostRootLease::acquire(&directory, &lock, scope()),
            Err(AgentHostError::DirectoryInUse)
        ));
        assert!(
            !directory.exists(),
            "a losing lease acquisition must not recreate the live owner's renamed root"
        );
        fs::rename(&moved, &directory).unwrap();
        control.shutdown().unwrap();

        let wrong_scope = AgentHostScope {
            space: scope().space,
            node: NodeId([3; 32]),
        };
        assert!(matches!(
            AgentHostControl::open(lease(&directory, &lock, wrong_scope), Arc::new(NoTrust),),
            Err(AgentHostError::ScopeMismatch)
        ));

        AgentHostControl::open(lease(&directory, &lock, scope()), Arc::new(NoTrust))
            .unwrap()
            .shutdown()
            .unwrap();
    }

    #[test]
    fn stable_lease_is_released_after_process_crash() {
        const CHILD_ROOT: &str = "VOS_AGENT_HOST_LEASE_CHILD_ROOT";
        const CHILD_LOCK: &str = "VOS_AGENT_HOST_LEASE_CHILD_LOCK";
        const CHILD_READY: &str = "VOS_AGENT_HOST_LEASE_CHILD_READY";

        if let (Some(root), Some(lock), Some(ready)) = (
            std::env::var_os(CHILD_ROOT),
            std::env::var_os(CHILD_LOCK),
            std::env::var_os(CHILD_READY),
        ) {
            let _lease = AgentHostRootLease::acquire(root, lock, scope()).unwrap();
            fs::write(ready, b"ready").unwrap();
            loop {
                thread::park_timeout(Duration::from_secs(60));
            }
        }

        let (directory, lock, _remove) = empty_host_directory("process-crash");
        let ready = directory.parent().unwrap().join("child-ready");
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("agent::host::tests::stable_lease_is_released_after_process_crash")
            .arg("--test-threads=1")
            .env(CHILD_ROOT, &directory)
            .env(CHILD_LOCK, &lock)
            .env(CHILD_READY, &ready)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while !ready.is_file() {
            if let Some(status) = child.try_wait().unwrap() {
                panic!("Agent-host lease child exited before acquiring the lock: {status}");
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!("Agent-host lease child did not acquire the lock in time");
            }
            thread::sleep(Duration::from_millis(10));
        }
        assert!(matches!(
            AgentHostRootLease::acquire(&directory, &lock, scope()),
            Err(AgentHostError::DirectoryInUse)
        ));

        child.kill().unwrap();
        child.wait().unwrap();
        let recovered = AgentHostRootLease::acquire(&directory, &lock, scope()).unwrap();
        drop(recovered);
    }

    #[test]
    fn malformed_directory_scope_fails_closed() {
        let (directory, lock, _remove) = empty_host_directory("malformed-scope");
        fs::create_dir_all(&directory).unwrap();
        fs::write(directory.join(HOST_SCOPE_FILE), b"truncated").unwrap();
        assert!(matches!(
            AgentHostControl::open(lease(&directory, &lock, scope()), Arc::new(NoTrust),),
            Err(AgentHostError::InvalidScopeBinding)
        ));
    }

    #[test]
    fn unbound_existing_images_are_not_claimed_by_a_guessed_scope() {
        let (directory, lock, _remove) = empty_host_directory("unbound-image");
        fs::create_dir_all(&directory).unwrap();
        fs::write(
            directory.join(format!(
                "{}{}",
                encode_agent_id(AgentId([9; 32])),
                IMAGE_SUFFIX
            )),
            b"legacy image placeholder",
        )
        .unwrap();
        assert!(matches!(
            AgentHostControl::open(lease(&directory, &lock, scope()), Arc::new(NoTrust),),
            Err(AgentHostError::InvalidScopeBinding)
        ));
        assert!(!directory.join(HOST_SCOPE_FILE).exists());
        fs::write(directory.join(HOST_SCOPE_TEMP_FILE), encoded_scope(scope())).unwrap();
        assert!(matches!(
            AgentHostControl::open(lease(&directory, &lock, scope()), Arc::new(NoTrust),),
            Err(AgentHostError::InvalidScopeBinding)
        ));
        assert!(!directory.join(HOST_SCOPE_FILE).exists());
        assert!(directory.join(HOST_SCOPE_TEMP_FILE).is_file());
    }

    #[test]
    fn stable_lease_must_live_outside_the_replaceable_root() {
        let (directory, _lock, _remove) = empty_host_directory("inside-lock");
        assert!(matches!(
            AgentHostRootLease::acquire(
                &directory,
                directory.join("locks").join("owner.lock"),
                scope(),
            ),
            Err(AgentHostError::InvalidScopeBinding)
        ));
    }

    #[test]
    fn matching_staged_scope_is_recovered_but_mismatched_scope_is_not_overwritten() {
        let (directory, lock, _remove) = empty_host_directory("scope-recovery");
        let first_lease = lease(&directory, &lock, scope());
        fs::write(directory.join(HOST_SCOPE_TEMP_FILE), encoded_scope(scope())).unwrap();
        AgentHostControl::open(first_lease, Arc::new(NoTrust))
            .unwrap()
            .shutdown()
            .unwrap();
        assert!(directory.join(HOST_SCOPE_FILE).is_file());
        assert!(!directory.join(HOST_SCOPE_TEMP_FILE).exists());

        fs::remove_file(directory.join(HOST_SCOPE_FILE)).unwrap();
        let wrong_scope = AgentHostScope {
            space: scope().space,
            node: NodeId([3; 32]),
        };
        fs::write(
            directory.join(HOST_SCOPE_TEMP_FILE),
            encoded_scope(wrong_scope),
        )
        .unwrap();
        assert!(matches!(
            AgentHostControl::open(lease(&directory, &lock, scope()), Arc::new(NoTrust),),
            Err(AgentHostError::ScopeMismatch)
        ));
        assert!(!directory.join(HOST_SCOPE_FILE).exists());
        assert_eq!(
            fs::read(directory.join(HOST_SCOPE_TEMP_FILE)).unwrap(),
            encoded_scope(wrong_scope)
        );
    }

    #[cfg(unix)]
    #[test]
    fn scope_binding_symlinks_fail_without_touching_their_target() {
        use std::os::unix::fs::symlink;

        let (directory, lock, _remove) = empty_host_directory("scope-symlink");
        let lease = lease(&directory, &lock, scope());
        let target = directory.parent().unwrap().join("untouched");
        fs::write(&target, b"untouched").unwrap();
        symlink(&target, directory.join(HOST_SCOPE_FILE)).unwrap();
        assert!(matches!(
            AgentHostControl::open(lease, Arc::new(NoTrust)),
            Err(AgentHostError::InvalidScopeBinding)
        ));
        assert_eq!(fs::read(target).unwrap(), b"untouched");
    }
}
