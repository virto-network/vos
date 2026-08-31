//! Durable Local system-Agent host.
//!
//! An [`AgentHost`] owns one filesystem directory and the one system Agent
//! selected by independently configured root pins. The clean generation is a
//! journal rooted at `<full-agent-id>.agent`; retired `.agent-image` files are
//! rejected and are never migrated implicitly.

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

pub use super::local_journal_driver::LocalMergeAuthenticator;
#[cfg(feature = "network")]
pub use super::local_journal_driver::{
    Ed25519NodeMergeAuthenticator, Ed25519NodeMergeAuthenticatorError,
};

use super::authority::{
    ActorInvocationReceipt, AgentAuthorityBinding, AgentAuthorityReceipt, AuthorityError,
};
use super::bootstrap::{
    SystemAgentGenesisBootstrapError, SystemAgentGenesisLocator, SystemAgentGenesisProposal,
    SystemAgentGenesisProvider, SystemAgentGenesisProviderError,
    seal_prepared_system_agent_genesis, validate_prepared_system_agent_genesis_root,
};
use super::committee::RootAnchorPins;
use super::driver::AgentTrustProvider;
use super::execution::{
    ActorExecutionError, ActorExecutionReply, ActorInvocation, MAX_EXECUTION_AVAILABILITY_BYTES,
    MAX_EXECUTION_BLOBS, MAX_EXECUTION_GAS, MAX_EXECUTION_MESSAGE_BYTES,
    MAX_EXECUTION_POLICY_BYTES, MAX_EXECUTION_PROGRAM_BYTES, MAX_EXECUTION_STATE_BYTES,
    RuntimeBlob,
};
use super::journal::ReplayOperation;
use super::journal_store::{AgentJournalStore, FileAgentJournalStore, JournalStoreError};
use super::local_journal_driver::{
    LocalJournalAgentDriver, LocalJournalDriverError, LocalLifecycleOperation,
    LocalReplayExecutorError, LocalSettledAcknowledgementResult, LocalSettledInvocationResult,
};
use super::package::{
    MAX_ENCODED_PACKAGE_BYTES, MAX_PACKAGE_DIAGNOSTICS_BYTES, MAX_PACKAGE_INTERFACES_BYTES,
    MAX_PACKAGE_SCHEMAS_BYTES, MAX_PACKAGE_TASK_BYTES, Package, PackageError,
};
use super::replay::{ReplayError, ReplayMaterializationSourceError, ReplaySealedGenesis};
use super::{
    ActorDirectoryPage, ActorEntry, AgentConfig, AgentConfigError, AgentIdentity, LifecycleError,
    LifecycleReply, LifecycleRequest, PackageKind,
};
use crate::service::wire::ServiceWire;
use crate::service::{
    ActorId, AgentId, BlobRef, CapabilityId, DeploymentId, Hash, InvocationId, NodeId, ProgramId,
    SpaceId,
};

const JOURNAL_SUFFIX: &str = ".agent";
const JOURNAL_LOCK_SUFFIX: &str = ".agent-lock";
const LEGACY_IMAGE_SUFFIX: &str = ".agent-image";
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
    InvalidJournalName,
    LegacyGeneration,
    DuplicateAgent,
    AgentNotFound,
    IdentityMismatch,
    Overloaded,
    ShuttingDown,
    WorkerStopped,
    WorkerPanicked,
    InvalidConfig(AgentConfigError),
    Package(PackageError),
    Lifecycle(LifecycleError),
    Execution(ActorExecutionError),
    Authority(AuthorityError),
    Journal(AgentHostJournalError),
    Bootstrap(SystemAgentGenesisBootstrapError),
    Provider(SystemAgentGenesisProviderError),
    InvalidAuthority,
    TrustUnavailable,
    Conflict,
    InvalidRuntime,
    InvocationAcknowledged,
}

impl core::fmt::Display for AgentHostError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "agent host: {self:?}")
    }
}

impl std::error::Error for AgentHostError {}

/// Public, host-stable projection of the crate-private journal adapter errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentHostJournalError {
    InvalidPath,
    ScopeMismatch,
    DirectoryInUse,
    LegacyGeneration,
    NotInitialized,
    Conflict,
    GcPending,
    InvalidClass,
    NonCanonical,
    LimitExceeded,
    Backpressure,
    MissingObject,
    Corrupt,
    Unavailable,
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
    agents: BTreeMap<AgentId, LocalJournalAgentDriver<FileAgentJournalStore>>,
    trust: Arc<dyn AgentTrustProvider>,
    merge: Arc<dyn LocalMergeAuthenticator>,
    genesis: Arc<dyn SystemAgentGenesisProvider>,
    root_pins: RootAnchorPins,
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
            .ok_or(AgentHostError::InvalidRuntime)?;
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
        self.request(0, |host| host.identities())
    }

    pub fn identity(&self, agent: AgentId) -> Result<Option<AgentIdentity>, AgentHostError> {
        self.request(0, move |host| host.identity(agent))
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
    AgentHostError::Package(error)
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
    AgentHostError::Execution(ActorExecutionError::InvalidInput)
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
    AgentHostError::Lifecycle(super::LifecycleError::InvalidRequest)
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
        return Err(AgentHostError::Authority(
            super::authority::AuthorityError::InvalidSignature,
        ));
    }
    Ok(())
}

fn validate_invocation_receipt_shape(
    receipt: &ActorInvocationReceipt,
) -> Result<(), AgentHostError> {
    if receipt.signature.len() != super::authority::ED25519_SIGNATURE_BYTES
        || !receipt.claim.authority.validate()
    {
        return Err(AgentHostError::Authority(
            super::authority::AuthorityError::InvalidSignature,
        ));
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
        merge: Arc<dyn LocalMergeAuthenticator>,
        genesis: Arc<dyn SystemAgentGenesisProvider>,
        root_pins: RootAnchorPins,
    ) -> Result<Self, AgentHostError> {
        Self::open_with_queue_capacity(
            lease,
            trust,
            merge,
            genesis,
            root_pins,
            DEFAULT_AGENT_HOST_QUEUE_CAPACITY,
        )
    }

    pub fn open_with_queue_capacity(
        lease: AgentHostRootLease,
        trust: Arc<dyn AgentTrustProvider>,
        merge: Arc<dyn LocalMergeAuthenticator>,
        genesis: Arc<dyn SystemAgentGenesisProvider>,
        root_pins: RootAnchorPins,
        queue_capacity: usize,
    ) -> Result<Self, AgentHostError> {
        if queue_capacity == 0 {
            return Err(AgentHostError::InvalidQueueCapacity);
        }
        let scope = lease.scope();
        let host = AgentHost::open(lease, trust, merge, genesis, root_pins)?;
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
    /// Open the one independently pinned Local system Agent in `root`.
    ///
    /// Startup probes the configured provider locator even when no journal is
    /// present. An archived provider-first Create is therefore completed after
    /// a crash before the first destination write. Conversely, generation
    /// residue without its exact archive fails closed and is never re-minted.
    pub fn open(
        lease: AgentHostRootLease,
        trust: Arc<dyn AgentTrustProvider>,
        merge: Arc<dyn LocalMergeAuthenticator>,
        genesis: Arc<dyn SystemAgentGenesisProvider>,
        root_pins: RootAnchorPins,
    ) -> Result<Self, AgentHostError> {
        let root = lease.root().to_path_buf();
        let scope = lease.scope();
        validate_host_root_capabilities(scope, merge.as_ref(), &root_pins)?;
        let system_agent = root_pins.record().system_agent();
        let directory_lock = lock_agent_host_directory(&root)?;
        let scope_state = read_agent_host_scope(&root, scope)?;
        if scope_state.scope().is_some_and(|bound| bound != scope) {
            return Err(AgentHostError::ScopeMismatch);
        }
        let mut journals = Vec::new();
        let mut journal_locks = Vec::new();
        for entry in fs::read_dir(&root).map_err(|_| AgentHostError::Unavailable)? {
            let entry = entry.map_err(|_| AgentHostError::Unavailable)?;
            let file_type = entry.file_type().map_err(|_| AgentHostError::Unavailable)?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| AgentHostError::InvalidJournalName)?;
            if matches!(
                name.as_str(),
                HOST_LOCK_FILE | HOST_SCOPE_FILE | HOST_SCOPE_TEMP_FILE
            ) {
                continue;
            }
            let folded_name = name.to_ascii_lowercase();
            if matches!(
                folded_name.as_str(),
                HOST_LOCK_FILE | HOST_SCOPE_FILE | HOST_SCOPE_TEMP_FILE
            ) {
                return Err(AgentHostError::InvalidJournalName);
            }
            if folded_name.ends_with(LEGACY_IMAGE_SUFFIX) {
                return Err(AgentHostError::LegacyGeneration);
            }
            if folded_name.ends_with(JOURNAL_LOCK_SUFFIX) {
                if !name.ends_with(JOURNAL_LOCK_SUFFIX) {
                    return Err(AgentHostError::InvalidJournalName);
                }
                if !file_type.is_file() || file_type.is_symlink() {
                    return Err(AgentHostError::InvalidJournalName);
                }
                let encoded = &name[..name.len() - JOURNAL_LOCK_SUFFIX.len()];
                let agent = decode_agent_id(encoded).ok_or(AgentHostError::InvalidJournalName)?;
                if agent != system_agent {
                    return Err(AgentHostError::ScopeMismatch);
                }
                journal_locks.push(agent);
                continue;
            }
            if !folded_name.ends_with(JOURNAL_SUFFIX) {
                continue;
            }
            if !name.ends_with(JOURNAL_SUFFIX) {
                return Err(AgentHostError::InvalidJournalName);
            }
            if !file_type.is_dir() || file_type.is_symlink() {
                return Err(AgentHostError::InvalidJournalName);
            }
            let encoded = &name[..name.len() - JOURNAL_SUFFIX.len()];
            let agent = decode_agent_id(encoded).ok_or(AgentHostError::InvalidJournalName)?;
            if agent != system_agent {
                return Err(AgentHostError::ScopeMismatch);
            }
            journals.push(agent);
        }
        journals.sort_unstable();
        journal_locks.sort_unstable();
        if journals.windows(2).any(|pair| pair[0] == pair[1])
            || journal_locks.windows(2).any(|pair| pair[0] == pair[1])
        {
            return Err(AgentHostError::DuplicateAgent);
        }
        let generation_residue = !journals.is_empty() || !journal_locks.is_empty();
        match scope_state {
            AgentHostScopeState::Bound(_) => {}
            AgentHostScopeState::Staged(_) if !generation_residue => {
                publish_agent_host_scope(
                    &root,
                    &root.join(HOST_SCOPE_TEMP_FILE),
                    &root.join(HOST_SCOPE_FILE),
                )?;
            }
            AgentHostScopeState::Absent if !generation_residue => {
                write_agent_host_scope(&root, scope)?;
            }
            AgentHostScopeState::Staged(_) | AgentHostScopeState::Absent => {
                // Never infer or overwrite the scope of a journal or stable
                // lock left by a pre-sidecar generation.
                return Err(AgentHostError::InvalidScopeBinding);
            }
        }

        let mut agents = BTreeMap::new();
        let locator = SystemAgentGenesisLocator {
            space: scope.space,
            agent: system_agent,
            node: scope.node,
        };
        match genesis.reproduce(locator) {
            Ok(provision) => {
                let (sealed, catalog, _, _) = prepare_archived_genesis(
                    trust.clone(),
                    merge.clone(),
                    genesis.as_ref(),
                    &root_pins,
                    provision,
                )?;
                let driver = open_archived_system_agent(
                    &root,
                    scope,
                    sealed,
                    &catalog,
                    trust.clone(),
                    merge.clone(),
                )?;
                let identity = driver.identity().map_err(map_local_driver_error)?;
                if identity.agent != system_agent || identity.space != scope.space {
                    return Err(AgentHostError::IdentityMismatch);
                }
                agents.insert(system_agent, driver);
            }
            Err(SystemAgentGenesisProviderError::NotConfigured) if !generation_residue => {}
            Err(error) => return Err(AgentHostError::Provider(error)),
        }
        Ok(Self {
            root,
            scope,
            agents,
            trust,
            merge,
            genesis,
            root_pins,
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

    /// Immutable Agent identities in canonical ID order.
    pub fn identities(&self) -> Result<Vec<AgentIdentity>, AgentHostError> {
        self.agents
            .values()
            .map(|driver| driver.identity().map_err(map_local_driver_error))
            .collect()
    }

    pub fn identity(&self, agent: AgentId) -> Result<Option<AgentIdentity>, AgentHostError> {
        self.agents
            .get(&agent)
            .map(|driver| driver.identity().map_err(map_local_driver_error))
            .transpose()
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
        if config.identity.agent != self.system_agent() {
            return Err(AgentHostError::ScopeMismatch);
        }
        if let Some(driver) = self.agents.get(&config.identity.agent)
            && driver.config().map_err(map_local_driver_error)? != *config
        {
            return Err(AgentHostError::DuplicateAgent);
        }
        validate_system_create_target(
            self.scope,
            self.system_agent(),
            config,
            runtime_package,
            &self.root_pins,
            self.trust.as_ref(),
        )?;
        let request = LifecycleRequest::Create(config.clone());
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
        let operation = driver
            .actor_install_operation(name, parent, package)
            .map_err(map_local_driver_error)?;
        PreparedLifecycleRequest::new(
            &driver.config().map_err(map_local_driver_error)?,
            operation.request().clone(),
        )
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
        let operation = driver
            .actor_upgrade_operation(actor, from_deployment, package)
            .map_err(map_local_driver_error)?;
        PreparedLifecycleRequest::new(
            &driver.config().map_err(map_local_driver_error)?,
            operation.request().clone(),
        )
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
        let operation = driver
            .actor_suspend_operation(actor)
            .map_err(map_local_driver_error)?;
        PreparedLifecycleRequest::new(
            &driver.config().map_err(map_local_driver_error)?,
            operation.request().clone(),
        )
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
        let operation = driver
            .actor_resume_operation(actor)
            .map_err(map_local_driver_error)?;
        PreparedLifecycleRequest::new(
            &driver.config().map_err(map_local_driver_error)?,
            operation.request().clone(),
        )
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
        let operation = driver
            .actor_remove_operation(actor, expected_deployment)
            .map_err(map_local_driver_error)?;
        PreparedLifecycleRequest::new(
            &driver.config().map_err(map_local_driver_error)?,
            operation.request().clone(),
        )
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
        let operation = driver
            .runtime_upgrade_operation(from_deployment, package)
            .map_err(map_local_driver_error)?;
        PreparedLifecycleRequest::new(
            &driver.config().map_err(map_local_driver_error)?,
            operation.request().clone(),
        )
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
        if config.identity.agent != self.system_agent() {
            return Err(AgentHostError::ScopeMismatch);
        }
        let agent = config.identity.agent;
        validate_system_create_shape(self.scope, agent, &config, &runtime_package)?;
        let locator = self.genesis_locator();
        let (sealed, catalog, archived_config, archived_receipt) =
            match self.genesis.reproduce(locator) {
                Ok(provision) => prepare_archived_genesis(
                    self.trust.clone(),
                    self.merge.clone(),
                    self.genesis.as_ref(),
                    &self.root_pins,
                    provision,
                )?,
                Err(SystemAgentGenesisProviderError::NotConfigured) => {
                    if generation_path_exists(&self.journal_path(agent))?
                        || generation_path_exists(&self.journal_lock_path(agent))?
                    {
                        return Err(AgentHostError::Provider(
                            SystemAgentGenesisProviderError::NotConfigured,
                        ));
                    }
                    let (create, supplied_catalog) =
                        LocalJournalAgentDriver::<FileAgentJournalStore>::system_genesis_input(
                            config.clone(),
                            &runtime_package,
                            authority.clone(),
                            &self.root_pins,
                            &self.trust,
                            &self.merge,
                        )
                        .map_err(map_local_driver_error)?;
                    let prepared =
                        LocalJournalAgentDriver::<FileAgentJournalStore>::prepare_system_genesis(
                            create,
                            config.replicas[0],
                            &supplied_catalog,
                            self.trust.clone(),
                            self.merge.clone(),
                        )
                        .map_err(map_local_driver_error)?;
                    validate_prepared_system_agent_genesis_root(&prepared, &self.root_pins)
                        .map_err(AgentHostError::Bootstrap)?;
                    let proposal = SystemAgentGenesisProposal::from_prepared(locator, &prepared)
                        .map_err(AgentHostError::Bootstrap)?;
                    let returned = self
                        .genesis
                        .create(&proposal, &supplied_catalog)
                        .map_err(AgentHostError::Provider)?;
                    let reproduced = self
                        .genesis
                        .reproduce(locator)
                        .map_err(AgentHostError::Provider)?;
                    if returned != reproduced {
                        return Err(AgentHostError::Conflict);
                    }
                    let archived_catalog =
                        load_archived_catalog(self.genesis.as_ref(), reproduced.proposal())?;
                    if archived_catalog != supplied_catalog || reproduced.proposal() != &proposal {
                        return Err(AgentHostError::Conflict);
                    }
                    let sealed =
                        seal_prepared_system_agent_genesis(prepared, &self.root_pins, &reproduced)
                            .map_err(AgentHostError::Bootstrap)?;
                    (sealed, archived_catalog, config.clone(), authority.clone())
                }
                Err(error) => return Err(AgentHostError::Provider(error)),
            };
        require_exact_create_caller(
            &catalog,
            &archived_config,
            &archived_receipt,
            &config,
            &runtime_package,
            authority,
        )?;
        if let Some(driver) = self.agents.get(&agent) {
            let current = driver.config().map_err(map_local_driver_error)?;
            if current != config {
                return Err(AgentHostError::Conflict);
            }
            return Ok(current.identity);
        }
        let driver = open_archived_system_agent(
            &self.root,
            self.scope,
            sealed,
            &catalog,
            self.trust.clone(),
            self.merge.clone(),
        )?;
        let identity = driver.identity().map_err(map_local_driver_error)?;
        if identity != config.identity {
            return Err(AgentHostError::IdentityMismatch);
        }
        self.agents.insert(agent, driver);
        Ok(identity)
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
            .map_err(map_local_driver_error)
    }

    pub fn install_actor(
        &mut self,
        agent: AgentId,
        authority: &AgentAuthorityReceipt,
        name: String,
        parent: Option<ActorId>,
        package: &Package,
    ) -> Result<ActorEntry, AgentHostError> {
        let driver = self
            .agents
            .get_mut(&agent)
            .ok_or(AgentHostError::AgentNotFound)?;
        let operation = driver
            .actor_install_operation(name, parent, package)
            .map_err(map_local_driver_error)?;
        match apply_local_lifecycle(driver, authority.clone(), operation)? {
            LifecycleReply::Installed(entry) => Ok(entry),
            _ => Err(AgentHostError::InvalidRuntime),
        }
    }

    pub fn upgrade_actor(
        &mut self,
        agent: AgentId,
        authority: &AgentAuthorityReceipt,
        actor: ActorId,
        from_deployment: DeploymentId,
        package: &Package,
    ) -> Result<ActorEntry, AgentHostError> {
        let driver = self
            .agents
            .get_mut(&agent)
            .ok_or(AgentHostError::AgentNotFound)?;
        let operation = driver
            .actor_upgrade_operation(actor, from_deployment, package)
            .map_err(map_local_driver_error)?;
        match apply_local_lifecycle(driver, authority.clone(), operation)? {
            LifecycleReply::Upgraded(entry) => Ok(entry),
            _ => Err(AgentHostError::InvalidRuntime),
        }
    }

    pub fn suspend_actor(
        &mut self,
        agent: AgentId,
        authority: &AgentAuthorityReceipt,
        actor: ActorId,
    ) -> Result<ActorEntry, AgentHostError> {
        let driver = self
            .agents
            .get_mut(&agent)
            .ok_or(AgentHostError::AgentNotFound)?;
        let operation = driver
            .actor_suspend_operation(actor)
            .map_err(map_local_driver_error)?;
        match apply_local_lifecycle(driver, authority.clone(), operation)? {
            LifecycleReply::Suspended(entry) => Ok(entry),
            _ => Err(AgentHostError::InvalidRuntime),
        }
    }

    pub fn resume_actor(
        &mut self,
        agent: AgentId,
        authority: &AgentAuthorityReceipt,
        actor: ActorId,
    ) -> Result<ActorEntry, AgentHostError> {
        let driver = self
            .agents
            .get_mut(&agent)
            .ok_or(AgentHostError::AgentNotFound)?;
        let operation = driver
            .actor_resume_operation(actor)
            .map_err(map_local_driver_error)?;
        match apply_local_lifecycle(driver, authority.clone(), operation)? {
            LifecycleReply::Resumed(entry) => Ok(entry),
            _ => Err(AgentHostError::InvalidRuntime),
        }
    }

    pub fn remove_actor(
        &mut self,
        agent: AgentId,
        authority: &AgentAuthorityReceipt,
        actor: ActorId,
        expected_deployment: DeploymentId,
    ) -> Result<(), AgentHostError> {
        let driver = self
            .agents
            .get_mut(&agent)
            .ok_or(AgentHostError::AgentNotFound)?;
        let operation = driver
            .actor_remove_operation(actor, expected_deployment)
            .map_err(map_local_driver_error)?;
        match apply_local_lifecycle(driver, authority.clone(), operation)? {
            LifecycleReply::Removed(removed) if removed == actor => Ok(()),
            _ => Err(AgentHostError::InvalidRuntime),
        }
    }

    pub fn upgrade_runtime(
        &mut self,
        agent: AgentId,
        authority: &AgentAuthorityReceipt,
        from_deployment: DeploymentId,
        package: &Package,
    ) -> Result<AgentIdentity, AgentHostError> {
        let driver = self
            .agents
            .get_mut(&agent)
            .ok_or(AgentHostError::AgentNotFound)?;
        let operation = driver
            .runtime_upgrade_operation(from_deployment, package)
            .map_err(map_local_driver_error)?;
        match apply_local_lifecycle(driver, authority.clone(), operation)? {
            LifecycleReply::RuntimeUpgraded(identity) => Ok(identity),
            _ => Err(AgentHostError::InvalidRuntime),
        }
    }

    pub fn invoke(
        &mut self,
        agent: AgentId,
        invocation: ActorInvocation,
        authority: &ActorInvocationReceipt,
    ) -> Result<ActorExecutionReply, AgentHostError> {
        match self
            .agents
            .get_mut(&agent)
            .ok_or(AgentHostError::AgentNotFound)?
            .invoke_synchronous(invocation, authority.clone())
            .map_err(map_local_driver_error)?
        {
            LocalSettledInvocationResult::Final(Ok(reply)) => Ok(reply),
            LocalSettledInvocationResult::Final(Err(error)) => {
                Err(AgentHostError::Execution(error))
            }
            LocalSettledInvocationResult::Acknowledged => {
                Err(AgentHostError::InvocationAcknowledged)
            }
        }
    }

    pub fn acknowledge_invocation(
        &mut self,
        agent: AgentId,
        invocation: ActorInvocation,
        authority: &ActorInvocationReceipt,
    ) -> Result<(), AgentHostError> {
        match self
            .agents
            .get_mut(&agent)
            .ok_or(AgentHostError::AgentNotFound)?
            .acknowledge_invocation_synchronous(invocation, authority.clone())
            .map_err(map_local_driver_error)?
        {
            LocalSettledAcknowledgementResult::Acknowledged => Ok(()),
            LocalSettledAcknowledgementResult::Divergent => Err(AgentHostError::Execution(
                ActorExecutionError::DivergentInvocation,
            )),
        }
    }

    pub fn revision(&self, agent: AgentId) -> Option<u64> {
        self.agents
            .get(&agent)
            .map(LocalJournalAgentDriver::publication_revision)
    }

    fn system_agent(&self) -> AgentId {
        self.root_pins.record().system_agent()
    }

    fn genesis_locator(&self) -> SystemAgentGenesisLocator {
        SystemAgentGenesisLocator {
            space: self.scope.space,
            agent: self.system_agent(),
            node: self.scope.node,
        }
    }

    fn journal_path(&self, agent: AgentId) -> PathBuf {
        self.root
            .join(format!("{}{}", encode_agent_id(agent), JOURNAL_SUFFIX))
    }

    fn journal_lock_path(&self, agent: AgentId) -> PathBuf {
        self.root
            .join(format!("{}{}", encode_agent_id(agent), JOURNAL_LOCK_SUFFIX))
    }
}

fn validate_host_root_capabilities(
    scope: AgentHostScope,
    merge: &dyn LocalMergeAuthenticator,
    root_pins: &RootAnchorPins,
) -> Result<(), AgentHostError> {
    root_pins.validate().map_err(|error| {
        AgentHostError::Bootstrap(SystemAgentGenesisBootstrapError::Authority(error))
    })?;
    if root_pins.record().space() != scope.space || merge.node() != scope.node {
        return Err(AgentHostError::ScopeMismatch);
    }
    Ok(())
}

fn validate_system_create_shape(
    scope: AgentHostScope,
    system_agent: AgentId,
    config: &AgentConfig,
    runtime_package: &Package,
) -> Result<(), AgentHostError> {
    if config.identity.agent != system_agent || !scope.admits(config) {
        return Err(AgentHostError::ScopeMismatch);
    }
    config.validate().map_err(AgentHostError::InvalidConfig)?;
    runtime_package
        .validate()
        .map_err(AgentHostError::Package)?;
    let PackageKind::AgentRuntime {
        contract,
        capabilities,
    } = runtime_package.manifest.kind
    else {
        return Err(AgentHostError::Package(PackageError::WrongKind));
    };
    if runtime_package.deployment_id() != config.identity.runtime_deployment
        || runtime_package.manifest.program != config.identity.runtime_program
        || runtime_package.deployment_signature.producer != config.identity.runtime_producer
        || BlobRef::of_bytes(&runtime_package.encode()) != config.runtime_package
        || contract != config.runtime_contract
        || capabilities != config.capabilities
    {
        return Err(AgentHostError::InvalidRuntime);
    }
    Ok(())
}

fn validate_system_create_target(
    scope: AgentHostScope,
    system_agent: AgentId,
    config: &AgentConfig,
    runtime_package: &Package,
    root_pins: &RootAnchorPins,
    trust: &dyn AgentTrustProvider,
) -> Result<(), AgentHostError> {
    validate_system_create_shape(scope, system_agent, config, runtime_package)?;
    let marker = config
        .system_authority_genesis
        .as_ref()
        .ok_or(AgentHostError::InvalidConfig(
            AgentConfigError::InvalidSystemAuthorityGenesis,
        ))?;
    marker
        .validate_root_config(root_pins.record(), config, marker.initial_sequence())
        .map_err(|_| {
            AgentHostError::InvalidConfig(AgentConfigError::InvalidSystemAuthorityGenesis)
        })?;
    if root_pins.genesis_claim().sequence() != marker.initial_sequence() {
        return Err(AgentHostError::InvalidConfig(
            AgentConfigError::InvalidSystemAuthorityGenesis,
        ));
    }
    let anchored = trust
        .authority_for_space(config.identity.space)
        .ok_or(AgentHostError::TrustUnavailable)?;
    if anchored != config.authority {
        return Err(AgentHostError::InvalidAuthority);
    }
    if !trust.verify_package(config, runtime_package) {
        return Err(AgentHostError::Package(PackageError::InvalidSignature));
    }
    Ok(())
}

fn archived_create_parts(
    proposal: &SystemAgentGenesisProposal,
) -> Result<(AgentConfig, AgentAuthorityReceipt), AgentHostError> {
    let ReplayOperation::Management { request } = &proposal.create().operation else {
        return Err(AgentHostError::Bootstrap(
            SystemAgentGenesisBootstrapError::InvalidProposal,
        ));
    };
    let LifecycleRequest::Authorized { admission, request } = request else {
        return Err(AgentHostError::Bootstrap(
            SystemAgentGenesisBootstrapError::InvalidProposal,
        ));
    };
    let LifecycleRequest::Create(config) = request.as_ref() else {
        return Err(AgentHostError::Bootstrap(
            SystemAgentGenesisBootstrapError::InvalidProposal,
        ));
    };
    Ok((config.clone(), admission.receipt.clone()))
}

fn load_archived_catalog(
    provider: &dyn SystemAgentGenesisProvider,
    proposal: &SystemAgentGenesisProposal,
) -> Result<Vec<RuntimeBlob>, AgentHostError> {
    let mut catalog = Vec::new();
    catalog
        .try_reserve_exact(proposal.catalog().len())
        .map_err(|_| AgentHostError::Unavailable)?;
    for reference in proposal.catalog() {
        let bytes = provider
            .load_catalog(proposal.locator(), reference)
            .map_err(AgentHostError::Provider)?
            .ok_or(AgentHostError::Provider(
                SystemAgentGenesisProviderError::Corrupt,
            ))?;
        if !reference.matches(&bytes) {
            return Err(AgentHostError::Provider(
                SystemAgentGenesisProviderError::Corrupt,
            ));
        }
        catalog.push(RuntimeBlob {
            reference: reference.clone(),
            bytes,
        });
    }
    Ok(catalog)
}

fn prepare_archived_genesis(
    trust: Arc<dyn AgentTrustProvider>,
    merge: Arc<dyn LocalMergeAuthenticator>,
    provider: &dyn SystemAgentGenesisProvider,
    root_pins: &RootAnchorPins,
    provision: super::bootstrap::SystemAgentGenesisProvision,
) -> Result<
    (
        ReplaySealedGenesis,
        Vec<RuntimeBlob>,
        AgentConfig,
        AgentAuthorityReceipt,
    ),
    AgentHostError,
> {
    let proposal = provision.proposal();
    let (config, receipt) = archived_create_parts(proposal)?;
    let catalog = load_archived_catalog(provider, proposal)?;
    let prepared = LocalJournalAgentDriver::<FileAgentJournalStore>::prepare_system_genesis(
        proposal.create().clone(),
        proposal.replica(),
        &catalog,
        trust,
        merge,
    )
    .map_err(map_local_driver_error)?;
    let expected = SystemAgentGenesisProposal::from_prepared(proposal.locator(), &prepared)
        .map_err(AgentHostError::Bootstrap)?;
    if expected != *proposal {
        return Err(AgentHostError::Conflict);
    }
    let sealed = seal_prepared_system_agent_genesis(prepared, root_pins, &provision)
        .map_err(AgentHostError::Bootstrap)?;
    Ok((sealed, catalog, config, receipt))
}

fn require_exact_create_caller(
    catalog: &[RuntimeBlob],
    archived_config: &AgentConfig,
    archived_receipt: &AgentAuthorityReceipt,
    supplied_config: &AgentConfig,
    supplied_package: &Package,
    supplied_receipt: &AgentAuthorityReceipt,
) -> Result<(), AgentHostError> {
    let supplied_bytes = supplied_package.encode();
    if archived_config != supplied_config
        || archived_receipt != supplied_receipt
        || catalog.len() != 1
        || catalog[0].reference != supplied_config.runtime_package
        || catalog[0].bytes != supplied_bytes
    {
        return Err(AgentHostError::Conflict);
    }
    Ok(())
}

fn open_archived_system_agent(
    root: &Path,
    scope: AgentHostScope,
    sealed: ReplaySealedGenesis,
    catalog: &[RuntimeBlob],
    trust: Arc<dyn AgentTrustProvider>,
    merge: Arc<dyn LocalMergeAuthenticator>,
) -> Result<LocalJournalAgentDriver<FileAgentJournalStore>, AgentHostError> {
    let agent = sealed.genesis().runtime().agent;
    let journal = root.join(format!("{}{}", encode_agent_id(agent), JOURNAL_SUFFIX));
    let stable_lock = root.join(format!("{}{}", encode_agent_id(agent), JOURNAL_LOCK_SUFFIX));
    let store = FileAgentJournalStore::open_reverified(journal, stable_lock, scope.node, &sealed)
        .map_err(map_journal_error)?;
    let genesis = store.genesis().map_err(map_journal_error)?;
    let heads = store.heads().map_err(map_journal_error)?;
    match (genesis, heads) {
        (Some(_), Some(_)) => {
            LocalJournalAgentDriver::open(store, trust, merge).map_err(map_local_driver_error)
        }
        // `initialize` publishes genesis before initial heads. Reusing the
        // exact root-admitted seal is the one canonical repair for a crash at
        // that boundary; both writes are immutable and conflict checked.
        (None, None) | (Some(_), None) => {
            // This store-bound preflight deliberately rechecks current root
            // and package trust before installing immutable bytes. It does
            // not re-authenticate the Create receipt or re-execute Replay;
            // those happened exactly once while preparing `sealed`.
            LocalJournalAgentDriver::create(store, sealed, catalog, trust, merge)
                .map_err(map_local_driver_error)
        }
        (None, Some(_)) => Err(map_journal_error(JournalStoreError::Corrupt)),
    }
}

fn apply_local_lifecycle(
    driver: &mut LocalJournalAgentDriver<FileAgentJournalStore>,
    authority: AgentAuthorityReceipt,
    operation: LocalLifecycleOperation,
) -> Result<LifecycleReply, AgentHostError> {
    let (request, catalog) = operation.into_parts();
    driver
        .lifecycle(authority, request, &catalog)
        .map_err(map_local_driver_error)?
        .result
        .map_err(AgentHostError::Lifecycle)
}

fn generation_path_exists(path: &Path) -> Result<bool, AgentHostError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err(AgentHostError::Unavailable),
    }
}

fn map_journal_error(error: JournalStoreError) -> AgentHostError {
    let projected = match error {
        JournalStoreError::InvalidPath => AgentHostJournalError::InvalidPath,
        JournalStoreError::ScopeMismatch => AgentHostJournalError::ScopeMismatch,
        JournalStoreError::DirectoryInUse => AgentHostJournalError::DirectoryInUse,
        JournalStoreError::LegacyGeneration => AgentHostJournalError::LegacyGeneration,
        JournalStoreError::NotInitialized => AgentHostJournalError::NotInitialized,
        JournalStoreError::Conflict => AgentHostJournalError::Conflict,
        JournalStoreError::GcPending => AgentHostJournalError::GcPending,
        JournalStoreError::InvalidClass => AgentHostJournalError::InvalidClass,
        JournalStoreError::NonCanonical => AgentHostJournalError::NonCanonical,
        JournalStoreError::LimitExceeded => AgentHostJournalError::LimitExceeded,
        JournalStoreError::Backpressure => AgentHostJournalError::Backpressure,
        JournalStoreError::MissingObject => AgentHostJournalError::MissingObject,
        JournalStoreError::Corrupt => AgentHostJournalError::Corrupt,
        JournalStoreError::Unavailable => AgentHostJournalError::Unavailable,
    };
    AgentHostError::Journal(projected)
}

fn map_local_executor_error(error: LocalReplayExecutorError) -> AgentHostError {
    match error {
        LocalReplayExecutorError::InvalidProfile | LocalReplayExecutorError::WrongReplica => {
            AgentHostError::ScopeMismatch
        }
        LocalReplayExecutorError::TrustUnavailable => AgentHostError::TrustUnavailable,
        LocalReplayExecutorError::InvalidAuthority => AgentHostError::InvalidAuthority,
        LocalReplayExecutorError::Package(error) => AgentHostError::Package(error),
        LocalReplayExecutorError::Store(error) => map_journal_error(error),
        LocalReplayExecutorError::InvalidState
        | LocalReplayExecutorError::InvalidRequest
        | LocalReplayExecutorError::ArtifactUnavailable(_)
        | LocalReplayExecutorError::InvalidArtifact(_)
        | LocalReplayExecutorError::RuntimeExit { .. }
        | LocalReplayExecutorError::RuntimeOutput
        | LocalReplayExecutorError::RuntimeStateTooLarge => AgentHostError::InvalidRuntime,
    }
}

fn map_local_driver_error(error: LocalJournalDriverError) -> AgentHostError {
    match error {
        LocalJournalDriverError::Store(error) => map_journal_error(error),
        LocalJournalDriverError::Executor(error) => map_local_executor_error(error),
        LocalJournalDriverError::Lifecycle(error) => AgentHostError::Lifecycle(error),
        LocalJournalDriverError::Conflict => AgentHostError::Conflict,
        LocalJournalDriverError::InvalidResult => AgentHostError::InvalidRuntime,
        LocalJournalDriverError::Replay(error) => match error {
            ReplayError::Source(ReplayMaterializationSourceError::Journal(error)) => {
                map_journal_error(error)
            }
            ReplayError::Source(ReplayMaterializationSourceError::Resolver(never)) => {
                match never {}
            }
            ReplayError::Executor(error) => map_local_executor_error(error),
            ReplayError::UncommittedInvocation(error) => AgentHostError::Execution(error),
            ReplayError::MissingOrdered(_)
            | ReplayError::MissingLocal(_)
            | ReplayError::MissingMergeEvent(_)
            | ReplayError::MissingMergeFrontier(_)
            | ReplayError::MissingMergeSeal(_)
            | ReplayError::MissingLaneState(_)
            | ReplayError::MissingArtifactClosure(_)
            | ReplayError::MissingInvocationIndex(_)
            | ReplayError::MissingCheckpoint(_)
            | ReplayError::InvalidRecord
            | ReplayError::ScopeMismatch
            | ReplayError::ChainMismatch
            | ReplayError::ReplayLimit
            | ReplayError::InvalidCausalHeight
            | ReplayError::NonMinimalFrontier
            | ReplayError::StaleMergeBranch(_)
            | ReplayError::UnauthenticatedMergeEvent(_)
            | ReplayError::InvalidOrderedBase
            | ReplayError::UnavailableOrderedBase
            | ReplayError::InvalidFence
            | ReplayError::StalePreFenceEvent(_)
            | ReplayError::RuntimeMismatch
            | ReplayError::InvalidRuntimeUpgrade
            | ReplayError::InvalidManagementTransition
            | ReplayError::InvalidPosition
            | ReplayError::CrossLaneMutation
            | ReplayError::TerminalMutation
            | ReplayError::ForbiddenMergeProducts
            | ReplayError::InvocationOwnership(_) => AgentHostError::InvalidRuntime,
        },
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

    struct NoMerge(NodeId);

    impl LocalMergeAuthenticator for NoMerge {
        fn node(&self) -> NodeId {
            self.0
        }

        fn sign_event(&self, _event: &mut super::super::journal::MergeEvent) -> bool {
            false
        }

        fn verify_event(&self, _event: &super::super::journal::MergeEvent) -> bool {
            false
        }
    }

    struct NoGenesis;

    impl SystemAgentGenesisProvider for NoGenesis {
        fn create(
            &self,
            _proposal: &SystemAgentGenesisProposal,
            _catalog: &[RuntimeBlob],
        ) -> Result<
            super::super::bootstrap::SystemAgentGenesisProvision,
            SystemAgentGenesisProviderError,
        > {
            Err(SystemAgentGenesisProviderError::NotConfigured)
        }

        fn reproduce(
            &self,
            _locator: SystemAgentGenesisLocator,
        ) -> Result<
            super::super::bootstrap::SystemAgentGenesisProvision,
            SystemAgentGenesisProviderError,
        > {
            Err(SystemAgentGenesisProviderError::NotConfigured)
        }

        fn load_catalog(
            &self,
            _locator: SystemAgentGenesisLocator,
            _reference: &BlobRef,
        ) -> Result<Option<Vec<u8>>, SystemAgentGenesisProviderError> {
            Ok(None)
        }
    }

    fn test_system_agent() -> AgentId {
        AgentId([9; 32])
    }

    fn test_root_pins(scope: AgentHostScope) -> RootAnchorPins {
        use super::super::committee::{
            AuthorityClaimCommitment, AuthorityClaimDomain, AuthorityCommittee,
            AuthorityCommitteeMember, AuthorityMemberRole, RootAnchorRecord,
        };

        let authority_binding = Hash([0x41; 32]);
        let member = AuthorityCommitteeMember::new(
            NodeId([0x42; 32]),
            [0x43; 32],
            AuthorityMemberRole::Voter,
        )
        .unwrap();
        let committee =
            AuthorityCommittee::new(scope.space, authority_binding, 1, None, vec![member]).unwrap();
        let root_record = RootAnchorRecord::new(
            1,
            scope.space,
            test_system_agent(),
            authority_binding,
            Hash([0x44; 32]),
            committee,
        )
        .unwrap();
        let claim = AuthorityClaimCommitment::from_payload_commitment(
            AuthorityClaimDomain::SystemAgentGenesis,
            1,
            Hash([0x45; 32]),
        )
        .unwrap();
        RootAnchorPins::new(
            root_record.clone(),
            root_record.config_version(),
            root_record.id(),
            root_record.config_commitment(),
            claim,
        )
        .unwrap()
    }

    fn open_empty_control(lease: AgentHostRootLease) -> Result<AgentHostControl, AgentHostError> {
        let scope = lease.scope();
        AgentHostControl::open(
            lease,
            Arc::new(NoTrust),
            Arc::new(NoMerge(scope.node)),
            Arc::new(NoGenesis),
            test_root_pins(scope),
        )
    }

    fn open_empty_control_with_capacity(
        lease: AgentHostRootLease,
        capacity: usize,
    ) -> Result<AgentHostControl, AgentHostError> {
        let scope = lease.scope();
        AgentHostControl::open_with_queue_capacity(
            lease,
            Arc::new(NoTrust),
            Arc::new(NoMerge(scope.node)),
            Arc::new(NoGenesis),
            test_root_pins(scope),
            capacity,
        )
    }

    const FIXTURE_AUTHORITY_SEED: [u8; 32] = [0x61; 32];
    const FIXTURE_PACKAGE_KEY: &[u8] = b"vos-host-journal-fixture-package";

    struct FixtureTrust {
        space: SpaceId,
        authority: AgentAuthorityBinding,
        slot_reads: Arc<AtomicUsize>,
    }

    impl AgentTrustProvider for FixtureTrust {
        fn current_logical_slot(&self) -> Option<u64> {
            self.slot_reads.fetch_add(1, Ordering::SeqCst);
            Some(10)
        }

        fn authority_for_space(&self, space: SpaceId) -> Option<AgentAuthorityBinding> {
            (space == self.space).then(|| self.authority.clone())
        }

        fn verify_package(&self, config: &AgentConfig, package: &Package) -> bool {
            config.identity.space == self.space
                && package.deployment_signature.public_key == FIXTURE_PACKAGE_KEY
                && package.deployment_signature.producer
                    == crate::service::ProducerId::of_public_key(FIXTURE_PACKAGE_KEY)
                && package.deployment_signature.signature == fixture_package_signature(package)
        }
    }

    struct RecordingGenesis {
        provision: super::super::bootstrap::SystemAgentGenesisProvision,
        catalog: Vec<RuntimeBlob>,
        journal: PathBuf,
        stable_lock: PathBuf,
        archived: Mutex<bool>,
        create_saw_clean_destination: std::sync::atomic::AtomicBool,
        refuse_create: std::sync::atomic::AtomicBool,
        creates: AtomicUsize,
    }

    impl RecordingGenesis {
        fn new(
            provision: super::super::bootstrap::SystemAgentGenesisProvision,
            catalog: Vec<RuntimeBlob>,
            root: &Path,
        ) -> Self {
            let agent = provision.proposal().locator().agent;
            Self {
                provision,
                catalog,
                journal: root.join(format!("{}{}", encode_agent_id(agent), JOURNAL_SUFFIX)),
                stable_lock: root.join(format!(
                    "{}{}",
                    encode_agent_id(agent),
                    JOURNAL_LOCK_SUFFIX
                )),
                archived: Mutex::new(false),
                create_saw_clean_destination: std::sync::atomic::AtomicBool::new(false),
                refuse_create: std::sync::atomic::AtomicBool::new(false),
                creates: AtomicUsize::new(0),
            }
        }

        fn archive_for_test(&self) {
            assert_eq!(
                self.create(self.provision.proposal(), &self.catalog)
                    .unwrap(),
                self.provision
            );
        }
    }

    impl SystemAgentGenesisProvider for RecordingGenesis {
        fn create(
            &self,
            proposal: &SystemAgentGenesisProposal,
            catalog: &[RuntimeBlob],
        ) -> Result<
            super::super::bootstrap::SystemAgentGenesisProvision,
            SystemAgentGenesisProviderError,
        > {
            self.creates.fetch_add(1, Ordering::SeqCst);
            if proposal != self.provision.proposal() || catalog != self.catalog {
                return Err(SystemAgentGenesisProviderError::Conflict);
            }
            let clean = !self.journal.exists() && !self.stable_lock.exists();
            self.create_saw_clean_destination
                .store(clean, Ordering::SeqCst);
            if !clean {
                return Err(SystemAgentGenesisProviderError::Refused);
            }
            if self.refuse_create.load(Ordering::SeqCst) {
                return Err(SystemAgentGenesisProviderError::Refused);
            }
            *self
                .archived
                .lock()
                .map_err(|_| SystemAgentGenesisProviderError::Unavailable)? = true;
            Ok(self.provision.clone())
        }

        fn reproduce(
            &self,
            locator: SystemAgentGenesisLocator,
        ) -> Result<
            super::super::bootstrap::SystemAgentGenesisProvision,
            SystemAgentGenesisProviderError,
        > {
            if locator != self.provision.proposal().locator() {
                return Err(SystemAgentGenesisProviderError::Conflict);
            }
            if *self
                .archived
                .lock()
                .map_err(|_| SystemAgentGenesisProviderError::Unavailable)?
            {
                Ok(self.provision.clone())
            } else {
                Err(SystemAgentGenesisProviderError::NotConfigured)
            }
        }

        fn load_catalog(
            &self,
            locator: SystemAgentGenesisLocator,
            reference: &BlobRef,
        ) -> Result<Option<Vec<u8>>, SystemAgentGenesisProviderError> {
            if locator != self.provision.proposal().locator() {
                return Err(SystemAgentGenesisProviderError::Conflict);
            }
            if !*self
                .archived
                .lock()
                .map_err(|_| SystemAgentGenesisProviderError::Unavailable)?
            {
                return Err(SystemAgentGenesisProviderError::NotConfigured);
            }
            Ok(self
                .catalog
                .iter()
                .find(|blob| &blob.reference == reference)
                .map(|blob| blob.bytes.clone()))
        }
    }

    struct JournalFixture {
        config: AgentConfig,
        runtime_package: Package,
        create_receipt: AgentAuthorityReceipt,
        trust: Arc<dyn AgentTrustProvider>,
        merge: Arc<dyn LocalMergeAuthenticator>,
        provider: Arc<RecordingGenesis>,
        pins: RootAnchorPins,
        slot_reads: Arc<AtomicUsize>,
    }

    fn fixture_package_signature(package: &Package) -> Vec<u8> {
        Hash::digest(
            b"vos/agent/host-fixture-package-signature",
            &[FIXTURE_PACKAGE_KEY, &package.signing_message()],
        )
        .0
        .to_vec()
    }

    fn fixture_runtime_package() -> Package {
        let pvm = include_bytes!("../../../vosx/blobs/agent_runtime.pvm").to_vec();
        let interfaces = b"host-journal-runtime-interface".to_vec();
        let schemas = b"host-journal-runtime-schema".to_vec();
        let mut package = Package {
            manifest: super::super::package::PackageManifest {
                name: "host-journal-runtime".into(),
                platform: crate::service::PLATFORM_ID,
                execution_semantics: super::super::EXECUTION_SEMANTICS_ID,
                kind: PackageKind::AgentRuntime {
                    contract: super::super::contract::RuntimePackageContract::canonical(),
                    capabilities: super::super::RuntimeCapabilities::standard(),
                },
                program: ProgramId::of_pvm(&pvm),
                interfaces_hash: crate::service::artifact_hash(b"interfaces", &interfaces),
                role_policies_hash: crate::service::artifact_hash(b"role-policies", &[]),
                schemas_hash: crate::service::artifact_hash(b"schemas", &schemas),
                agent_schema_hash: crate::service::artifact_hash(b"agent-schema", &[]),
                dependencies_hash: crate::service::task_dependencies_hash(&[]),
            },
            pvm,
            generated_interfaces: interfaces,
            role_policies: Vec::new(),
            schemas,
            agent_schema: Vec::new(),
            task_dependencies: Vec::new(),
            diagnostics: None,
            deployment_signature: crate::service::DeploymentSignature {
                producer: crate::service::ProducerId::of_public_key(FIXTURE_PACKAGE_KEY),
                public_key: FIXTURE_PACKAGE_KEY.to_vec(),
                signature: Vec::new(),
            },
        };
        package.deployment_signature.signature = fixture_package_signature(&package);
        package
    }

    fn fixture_authority(agent: AgentId) -> (ed25519_dalek::SigningKey, AgentAuthorityBinding) {
        let key = ed25519_dalek::SigningKey::from_bytes(&FIXTURE_AUTHORITY_SEED);
        let public_key =
            super::super::authority::ed25519_public_key_wire(key.verifying_key().to_bytes());
        let binding = AgentAuthorityBinding {
            agent,
            actor: ActorId([0x63; 32]),
            deployment: DeploymentId([0x64; 32]),
            program: ProgramId([0x65; 32]),
            producer: crate::service::ProducerId::of_public_key(&public_key),
            public_key,
        };
        (key, binding)
    }

    fn fixture_receipt(
        key: &ed25519_dalek::SigningKey,
        config: &AgentConfig,
        request: &LifecycleRequest,
        sequence: u64,
    ) -> AgentAuthorityReceipt {
        use ed25519_dalek::Signer as _;

        let claim = super::super::authority::AgentAuthorityClaim {
            authority: config.authority.clone(),
            space: config.identity.space,
            agent: config.identity.agent,
            principal: config.identity.owner,
            credential: crate::service::CredentialId([0x66; 32]),
            capability: CapabilityId::named(request.required_capability().unwrap()),
            operation: request.commitment(),
            sequence,
            valid_from: 1,
            valid_until: 100,
        };
        AgentAuthorityReceipt {
            signature: key.sign(&claim.signing_message().0).to_bytes().to_vec(),
            claim,
        }
    }

    fn journal_fixture(journal_root: &Path) -> JournalFixture {
        use super::super::committee::{
            AuthorityClaimCommitment, AuthorityClaimDomain, AuthorityCommittee,
            AuthorityCommitteeMember, AuthorityMemberRole, AuthorityQuorumCertificate,
            AuthoritySignature, AuthoritySignerId, RootAnchorRecord, SystemAgentGenesisClaim,
            SystemAgentGenesisEvidence,
        };
        use ed25519_dalek::{Signer as _, SigningKey};

        let scope = scope();
        let package = fixture_runtime_package();
        let owner = crate::service::PrincipalId([0x67; 32]);
        let creation_nonce = Hash([0x68; 32]);
        let agent = AgentId::derive(scope.space, owner, &creation_nonce.0);
        let (authority_key, authority) = fixture_authority(agent);
        let committee_keys = [
            SigningKey::from_bytes(&[0x69; 32]),
            SigningKey::from_bytes(&[0x6a; 32]),
            SigningKey::from_bytes(&[0x6b; 32]),
        ];
        let mut members = committee_keys
            .iter()
            .enumerate()
            .map(|(index, key)| {
                AuthorityCommitteeMember::new(
                    NodeId([(index + 1) as u8; 32]),
                    key.verifying_key().to_bytes(),
                    AuthorityMemberRole::Voter,
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        members.sort_by_key(AuthorityCommitteeMember::signer);
        let binding = authority.commitment();
        let committee = AuthorityCommittee::new(scope.space, binding, 1, None, members).unwrap();
        let root_record = RootAnchorRecord::new(
            1,
            scope.space,
            agent,
            binding,
            Hash([0x6c; 32]),
            committee.clone(),
        )
        .unwrap();
        let system_authority_genesis = super::super::system_authority::SystemAuthorityGenesis::new(
            root_record.id(),
            root_record.config_version(),
            root_record.config_commitment(),
            committee.clone(),
            1,
            8,
            8,
        )
        .unwrap();
        let config = AgentConfig {
            identity: AgentIdentity {
                space: scope.space,
                agent,
                owner,
                profile: super::super::AgentProfile::Local,
                runtime_deployment: package.deployment_id(),
                runtime_program: package.manifest.program,
                runtime_producer: package.deployment_signature.producer,
            },
            creation_nonce,
            authority: authority.clone(),
            system_authority_genesis: Some(system_authority_genesis),
            runtime_package: BlobRef::of_bytes(&package.encode()),
            runtime_contract: super::super::contract::RuntimePackageContract::canonical(),
            capabilities: super::super::RuntimeCapabilities::standard(),
            replicas: vec![super::super::AgentReplica {
                node: scope.node,
                principal: owner,
                role: super::super::ReplicaRole::Voter,
            }],
        };
        let request = LifecycleRequest::Create(config.clone());
        let receipt = fixture_receipt(&authority_key, &config, &request, 1);
        let slot_reads = Arc::new(AtomicUsize::new(0));
        let trust: Arc<dyn AgentTrustProvider> = Arc::new(FixtureTrust {
            space: scope.space,
            authority,
            slot_reads: slot_reads.clone(),
        });
        let merge: Arc<dyn LocalMergeAuthenticator> = Arc::new(NoMerge(scope.node));
        // Production pins carry the exact replay-derived genesis claim. This
        // construction-only fixture needs the independently pinned root
        // record before it can deterministically derive that claim below.
        let configured_root = RootAnchorPins::new(
            root_record.clone(),
            root_record.config_version(),
            root_record.id(),
            root_record.config_commitment(),
            AuthorityClaimCommitment::from_payload_commitment(
                AuthorityClaimDomain::SystemAgentGenesis,
                1,
                Hash([0x6d; 32]),
            )
            .unwrap(),
        )
        .unwrap();
        let (input, catalog) =
            LocalJournalAgentDriver::<FileAgentJournalStore>::system_genesis_input(
                config.clone(),
                &package,
                receipt.clone(),
                &configured_root,
                &trust,
                &merge,
            )
            .unwrap();
        let prepared = LocalJournalAgentDriver::<FileAgentJournalStore>::prepare_system_genesis(
            input,
            config.replicas[0],
            &catalog,
            trust.clone(),
            merge.clone(),
        )
        .unwrap();
        let locator = SystemAgentGenesisLocator {
            space: scope.space,
            agent,
            node: scope.node,
        };
        let proposal = SystemAgentGenesisProposal::from_prepared(locator, &prepared).unwrap();
        let claim = SystemAgentGenesisClaim::new(&root_record, proposal.expectations()).unwrap();
        let message = AuthorityQuorumCertificate::signing_message(
            committee.authority_binding(),
            committee.epoch(),
            committee.commitment(),
            claim.authority_claim(),
        );
        let mut signatures = committee_keys[..2]
            .iter()
            .map(|key| {
                AuthoritySignature::new(
                    AuthoritySignerId::of_raw_ed25519(&key.verifying_key().to_bytes()),
                    key.sign(&message.0).to_bytes(),
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        signatures.sort_by_key(AuthoritySignature::signer);
        let evidence = SystemAgentGenesisEvidence::new(
            claim.clone(),
            AuthorityQuorumCertificate::new(&committee, claim.authority_claim(), signatures)
                .unwrap(),
        )
        .unwrap();
        let pins = RootAnchorPins::new(
            root_record.clone(),
            root_record.config_version(),
            root_record.id(),
            root_record.config_commitment(),
            claim.authority_claim(),
        )
        .unwrap();
        let provision = super::super::bootstrap::SystemAgentGenesisProvision::new(
            proposal,
            pins.clone(),
            evidence,
        )
        .unwrap();
        let provider = Arc::new(RecordingGenesis::new(provision, catalog, journal_root));
        JournalFixture {
            config,
            runtime_package: package,
            create_receipt: receipt,
            trust,
            merge,
            provider,
            pins,
            slot_reads,
        }
    }

    fn fixture_invocation(config: &AgentConfig) -> (ActorInvocation, ActorInvocationReceipt) {
        use ed25519_dalek::Signer as _;

        let invocation = ActorInvocation {
            invocation: InvocationId([0x6d; 32]),
            actor: ActorId([0x6e; 32]),
            incarnation: Hash([0x6f; 32]),
            deployment: DeploymentId([0x70; 32]),
            program: ProgramId([0x71; 32]),
            mode: super::super::MethodMode::Query,
            auth: super::super::execution::ActorInvocationAuth::anonymous(),
            message: vec![1],
            availability: Vec::new(),
            gas: 1_000_000,
        };
        let claim = super::super::authority::ActorInvocationClaim {
            authority: config.authority.clone(),
            space: config.identity.space,
            agent: config.identity.agent,
            principal: None,
            credential: None,
            authorization: invocation.authorization_message(),
            auth: invocation.auth.clone(),
            valid_from: 1,
            valid_until: 100,
        };
        let key = ed25519_dalek::SigningKey::from_bytes(&FIXTURE_AUTHORITY_SEED);
        let receipt = ActorInvocationReceipt {
            signature: key.sign(&claim.signing_message().0).to_bytes().to_vec(),
            claim,
        };
        (invocation, receipt)
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
            system_authority_genesis: None,
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
    fn agent_journal_names_are_canonical() {
        let agent = AgentId([0xab; 32]);
        let encoded = encode_agent_id(agent);
        assert_eq!(encoded.len(), 64);
        assert_eq!(decode_agent_id(&encoded), Some(agent));
        assert_eq!(decode_agent_id(&encoded.to_uppercase()), None);
        assert_eq!(decode_agent_id("ab"), None);
    }

    #[test]
    fn provider_precedes_destination_and_advanced_heads_reopen() {
        let (directory, lock, _remove) = empty_host_directory("journal-reopen");
        let fixture = journal_fixture(&directory);
        let fixture_preparation_slot_reads = fixture.slot_reads.load(Ordering::SeqCst);
        let journal = fixture.provider.journal.clone();
        let journal_lock = fixture.provider.stable_lock.clone();
        assert!(!journal.exists());
        assert!(!journal_lock.exists());

        let control = AgentHostControl::open(
            lease(&directory, &lock, scope()),
            fixture.trust.clone(),
            fixture.merge.clone(),
            fixture.provider.clone(),
            fixture.pins.clone(),
        )
        .unwrap();
        let handle = control.handle();
        assert!(handle.identities().unwrap().is_empty());
        let identity = handle
            .create(
                fixture.config.clone(),
                fixture.runtime_package.clone(),
                fixture.create_receipt.clone(),
            )
            .unwrap();
        assert_eq!(identity, fixture.config.identity);
        assert!(
            fixture
                .provider
                .create_saw_clean_destination
                .load(Ordering::SeqCst),
            "provider archive must complete before `.agent` or `.agent-lock` exists"
        );
        assert_eq!(fixture.provider.creates.load(Ordering::SeqCst), 1);
        assert_eq!(
            fixture.slot_reads.load(Ordering::SeqCst),
            fixture_preparation_slot_reads + 1,
            "provider-miss Create samples the trusted slot exactly once"
        );
        assert!(journal.is_dir());
        assert!(journal_lock.is_file());

        // Response-loss retry reproduces the archived proposal and does not
        // resample or reissue genesis.
        assert_eq!(
            handle
                .create(
                    fixture.config.clone(),
                    fixture.runtime_package.clone(),
                    fixture.create_receipt.clone(),
                )
                .unwrap(),
            fixture.config.identity
        );
        assert_eq!(fixture.provider.creates.load(Ordering::SeqCst), 1);
        assert_eq!(
            fixture.slot_reads.load(Ordering::SeqCst),
            fixture_preparation_slot_reads + 1,
            "an exact archived Create retry must not resample the slot"
        );

        let (invocation, invocation_receipt) = fixture_invocation(&fixture.config);
        assert_eq!(
            handle.invoke(
                fixture.config.identity.agent,
                invocation.clone(),
                invocation_receipt.clone(),
            ),
            Err(AgentHostError::Execution(ActorExecutionError::NotFound))
        );
        let advanced = handle
            .revision(fixture.config.identity.agent)
            .unwrap()
            .unwrap();
        assert!(advanced > 0);
        control.shutdown().unwrap();

        let reopened = AgentHostControl::open(
            lease(&directory, &lock, scope()),
            fixture.trust.clone(),
            fixture.merge.clone(),
            fixture.provider.clone(),
            fixture.pins.clone(),
        )
        .unwrap();
        let reopened_handle = reopened.handle();
        assert_eq!(
            reopened_handle
                .revision(fixture.config.identity.agent)
                .unwrap(),
            Some(advanced),
            "advanced heads must use Local open, never genesis re-initialization"
        );
        reopened.shutdown().unwrap();
    }

    #[test]
    fn archived_startup_create_and_partial_initialization_repair_are_idempotent() {
        let (directory, lock, _remove) = empty_host_directory("journal-partial-init");
        let fixture = journal_fixture(&directory);
        let journal = fixture.provider.journal.clone();
        let journal_lock = fixture.provider.stable_lock.clone();

        // Model a provider transaction that committed while the host was
        // absent. Startup must reproduce that exact provision before opening
        // either destination path and then complete journal initialization.
        fixture.provider.archive_for_test();
        assert!(
            fixture
                .provider
                .create_saw_clean_destination
                .load(Ordering::SeqCst)
        );
        assert!(!journal.exists());
        assert!(!journal_lock.exists());
        let created = AgentHostControl::open(
            lease(&directory, &lock, scope()),
            fixture.trust.clone(),
            fixture.merge.clone(),
            fixture.provider.clone(),
            fixture.pins.clone(),
        )
        .unwrap();
        assert_eq!(
            created
                .handle()
                .revision(fixture.config.identity.agent)
                .unwrap(),
            Some(0)
        );
        created.shutdown().unwrap();
        assert!(journal.join("genesis").is_file());
        assert!(journal.join("heads").is_file());

        // `initialize` commits immutable genesis before initial heads. The
        // exact archived seal is the sole capability allowed to repair that
        // recoverable boundary.
        fs::remove_file(journal.join("heads")).unwrap();
        let repaired = AgentHostControl::open(
            lease(&directory, &lock, scope()),
            fixture.trust.clone(),
            fixture.merge.clone(),
            fixture.provider.clone(),
            fixture.pins.clone(),
        )
        .unwrap();
        assert_eq!(
            repaired
                .handle()
                .revision(fixture.config.identity.agent)
                .unwrap(),
            Some(0)
        );
        assert!(journal.join("heads").is_file());
        assert_eq!(fixture.provider.creates.load(Ordering::SeqCst), 1);
        repaired.shutdown().unwrap();
    }

    #[test]
    fn provider_refusal_precedes_every_agent_destination_write() {
        let (directory, lock, _remove) = empty_host_directory("journal-provider-refusal");
        let fixture = journal_fixture(&directory);
        fixture.provider.refuse_create.store(true, Ordering::SeqCst);
        let control = AgentHostControl::open(
            lease(&directory, &lock, scope()),
            fixture.trust.clone(),
            fixture.merge.clone(),
            fixture.provider.clone(),
            fixture.pins.clone(),
        )
        .unwrap();
        assert_eq!(
            control.handle().create(
                fixture.config.clone(),
                fixture.runtime_package.clone(),
                fixture.create_receipt.clone(),
            ),
            Err(AgentHostError::Provider(
                SystemAgentGenesisProviderError::Refused
            ))
        );
        assert!(
            fixture
                .provider
                .create_saw_clean_destination
                .load(Ordering::SeqCst)
        );
        assert_eq!(fixture.provider.creates.load(Ordering::SeqCst), 1);
        assert!(!fixture.provider.journal.exists());
        assert!(!fixture.provider.stable_lock.exists());
        control.shutdown().unwrap();
    }

    #[test]
    fn retired_images_and_unarchived_lock_residue_fail_closed() {
        let (directory, lock, _remove) = empty_host_directory("retired-generation");
        let first = open_empty_control(lease(&directory, &lock, scope())).unwrap();
        first.shutdown().unwrap();
        fs::write(
            directory.join(format!(
                "{}{}",
                encode_agent_id(test_system_agent()),
                LEGACY_IMAGE_SUFFIX
            )),
            b"retired image",
        )
        .unwrap();
        assert!(matches!(
            open_empty_control(lease(&directory, &lock, scope())),
            Err(AgentHostError::LegacyGeneration)
        ));

        fs::remove_file(directory.join(format!(
            "{}{}",
            encode_agent_id(test_system_agent()),
            LEGACY_IMAGE_SUFFIX
        )))
        .unwrap();
        fs::write(
            directory.join(format!(
                "{}{}",
                encode_agent_id(test_system_agent()),
                JOURNAL_LOCK_SUFFIX
            )),
            b"orphan lock",
        )
        .unwrap();
        assert!(matches!(
            open_empty_control(lease(&directory, &lock, scope())),
            Err(AgentHostError::Provider(
                SystemAgentGenesisProviderError::NotConfigured
            ))
        ));
    }

    #[test]
    fn generation_aliases_are_rejected_instead_of_ignored() {
        let (directory, lock, _remove) = empty_host_directory("generation-aliases");
        let first = open_empty_control(lease(&directory, &lock, scope())).unwrap();
        first.shutdown().unwrap();
        let encoded = encode_agent_id(test_system_agent());

        let uppercase_journal = directory.join(format!("{encoded}.AGENT"));
        fs::create_dir(&uppercase_journal).unwrap();
        assert!(matches!(
            open_empty_control(lease(&directory, &lock, scope())),
            Err(AgentHostError::InvalidJournalName)
        ));
        fs::remove_dir(&uppercase_journal).unwrap();

        let uppercase_lock = directory.join(format!("{encoded}.AGENT-LOCK"));
        fs::write(&uppercase_lock, b"alias").unwrap();
        assert!(matches!(
            open_empty_control(lease(&directory, &lock, scope())),
            Err(AgentHostError::InvalidJournalName)
        ));
        fs::remove_file(&uppercase_lock).unwrap();

        let uppercase_legacy = directory.join(format!("{encoded}.AGENT-IMAGE"));
        fs::write(&uppercase_legacy, b"retired alias").unwrap();
        assert!(matches!(
            open_empty_control(lease(&directory, &lock, scope())),
            Err(AgentHostError::LegacyGeneration)
        ));
        fs::remove_file(&uppercase_legacy).unwrap();

        let uppercase_id = directory.join(format!(
            "{}.agent",
            encode_agent_id(AgentId([0xab; 32])).to_uppercase()
        ));
        fs::create_dir(&uppercase_id).unwrap();
        assert!(matches!(
            open_empty_control(lease(&directory, &lock, scope())),
            Err(AgentHostError::InvalidJournalName)
        ));
        fs::remove_dir(&uppercase_id).unwrap();

        let malformed = directory.join("not-an-agent.agent");
        fs::create_dir(&malformed).unwrap();
        assert!(matches!(
            open_empty_control(lease(&directory, &lock, scope())),
            Err(AgentHostError::InvalidJournalName)
        ));
        fs::remove_dir(&malformed).unwrap();

        // The exact host lock and durable scope metadata remain admitted.
        let reopened = open_empty_control(lease(&directory, &lock, scope())).unwrap();
        reopened.shutdown().unwrap();
    }

    #[test]
    fn worker_handle_is_bounded_and_shutdown_is_terminal() {
        fn assert_send<T: Send>() {}
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send::<AgentHostControl>();
        assert_send_sync::<AgentHostHandle>();

        let (directory, lock, _remove) = empty_host_directory("bounded-worker");
        let control =
            open_empty_control_with_capacity(lease(&directory, &lock, scope()), 1).unwrap();
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
        let control =
            open_empty_control_with_capacity(lease(&directory, &lock, scope()), 4).unwrap();
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
        let control = open_empty_control(lease(&directory, &lock, scope())).unwrap();
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
        let control = open_empty_control(lease(&directory, &lock, scope())).unwrap();
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
        let control =
            open_empty_control_with_capacity(lease(&directory, &lock, scope()), 4).unwrap();
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
            open_empty_control_with_capacity(lease(&directory, &lock, scope()), 0),
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
        let control = open_empty_control(lease(&directory, &lock, scope())).unwrap();
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
            open_empty_control(lease(&directory, &lock, wrong_scope)),
            Err(AgentHostError::ScopeMismatch)
        ));

        open_empty_control(lease(&directory, &lock, scope()))
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
            open_empty_control(lease(&directory, &lock, scope())),
            Err(AgentHostError::InvalidScopeBinding)
        ));
    }

    #[test]
    fn unbound_existing_journals_are_not_claimed_by_a_guessed_scope() {
        let (directory, lock, _remove) = empty_host_directory("unbound-journal");
        fs::create_dir_all(&directory).unwrap();
        fs::create_dir(directory.join(format!(
            "{}{}",
            encode_agent_id(test_system_agent()),
            JOURNAL_SUFFIX
        )))
        .unwrap();
        assert!(matches!(
            open_empty_control(lease(&directory, &lock, scope())),
            Err(AgentHostError::InvalidScopeBinding)
        ));
        assert!(!directory.join(HOST_SCOPE_FILE).exists());
        fs::write(directory.join(HOST_SCOPE_TEMP_FILE), encoded_scope(scope())).unwrap();
        assert!(matches!(
            open_empty_control(lease(&directory, &lock, scope())),
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
        open_empty_control(first_lease).unwrap().shutdown().unwrap();
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
            open_empty_control(lease(&directory, &lock, scope())),
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
            open_empty_control(lease),
            Err(AgentHostError::InvalidScopeBinding)
        ));
        assert_eq!(fs::read(target).unwrap(), b"untouched");
    }
}
