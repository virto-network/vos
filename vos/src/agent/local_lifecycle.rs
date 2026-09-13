//! Native ownership boundary for signed Local Agent lifecycle operations.

use std::sync::mpsc;
use std::sync::{Arc, Mutex};

use super::clean_authority_issuer::{CleanManagementIssuerStore, CleanManagementReceiptSigner};
use super::clean_bootstrap::{CleanSystemAgentBootstrapOwner, CleanSystemAgentBootstrapStore};
use super::local_sdk_host::LocalAgentHost;
use super::package_admission::AdmittedRuntimePackage;
use super::sdk::authority::{AuthorityCredentialCall, ManagementApplicationAck};
use super::sdk::{AgentDescriptor, AgentId, AgentProfile, ManagementRequest, SpaceId};
use super::shared_host::SharedAgentHostError;
use super::supervisor_adapters::{AgentRouteAdapterError, AgentRouteHostAttachment};

pub const LOCAL_LIFECYCLE_QUEUE_CAPACITY: usize = 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LocalLifecycleIngressError {
    Unavailable,
    Busy,
    Invalid,
}

impl std::fmt::Display for LocalLifecycleIngressError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "Local lifecycle ingress: {self:?}")
    }
}

impl std::error::Error for LocalLifecycleIngressError {}

pub type LocalCreateResult =
    Result<(AgentId, ManagementApplicationAck), super::production_owner::AgentProductionOwnerError>;

pub(crate) struct PendingLocalCreate {
    pub descriptor: AgentDescriptor,
    pub call: AuthorityCredentialCall,
    pub runtime: AdmittedRuntimePackage,
    pub reply: mpsc::SyncSender<LocalCreateResult>,
}

#[derive(Default)]
pub(crate) struct LocalLifecycleQueue {
    channel: Mutex<
        Option<(
            mpsc::SyncSender<PendingLocalCreate>,
            mpsc::Receiver<PendingLocalCreate>,
        )>,
    >,
}

impl LocalLifecycleQueue {
    pub(crate) fn open(&self) -> Result<(), LocalLifecycleIngressError> {
        let mut channel = self
            .channel
            .lock()
            .map_err(|_| LocalLifecycleIngressError::Unavailable)?;
        if channel.is_some() {
            return Err(LocalLifecycleIngressError::Busy);
        }
        *channel = Some(mpsc::sync_channel(LOCAL_LIFECYCLE_QUEUE_CAPACITY));
        Ok(())
    }

    pub(crate) fn submit(
        &self,
        descriptor: AgentDescriptor,
        call: AuthorityCredentialCall,
        runtime: AdmittedRuntimePackage,
    ) -> Result<mpsc::Receiver<LocalCreateResult>, LocalLifecycleIngressError> {
        let channel = self
            .channel
            .lock()
            .map_err(|_| LocalLifecycleIngressError::Unavailable)?;
        let (sender, _) = channel
            .as_ref()
            .ok_or(LocalLifecycleIngressError::Unavailable)?;
        let (reply, receiver) = mpsc::sync_channel(1);
        sender
            .try_send(PendingLocalCreate {
                descriptor,
                call,
                runtime,
                reply,
            })
            .map_err(|error| match error {
                mpsc::TrySendError::Full(_) => LocalLifecycleIngressError::Busy,
                mpsc::TrySendError::Disconnected(_) => LocalLifecycleIngressError::Unavailable,
            })?;
        Ok(receiver)
    }

    pub(crate) fn pop(&self) -> Result<Option<PendingLocalCreate>, LocalLifecycleIngressError> {
        let channel = self
            .channel
            .lock()
            .map_err(|_| LocalLifecycleIngressError::Unavailable)?;
        let Some((_, receiver)) = channel.as_ref() else {
            return Ok(None);
        };
        match receiver.try_recv() {
            Ok(request) => Ok(Some(request)),
            Err(mpsc::TryRecvError::Empty) => Ok(None),
            Err(mpsc::TryRecvError::Disconnected) => Err(LocalLifecycleIngressError::Unavailable),
        }
    }

    pub(crate) fn close(&self) {
        if let Ok(mut channel) = self.channel.lock() {
            if let Some((_, receiver)) = channel.take() {
                for pending in receiver.try_iter() {
                    let _ = pending.reply.try_send(Err(
                        super::production_owner::AgentProductionOwnerError::InvalidConfiguration,
                    ));
                }
            }
        }
    }
}

/// Open the same two independent durable images on every retry. Implementors
/// derive paths from the configured Space and Agent, never caller path strings.
pub trait LocalLifecycleStoreFactory {
    type Intent: CleanManagementIssuerStore;
    type Issuer: CleanManagementIssuerStore;
    type Error;

    fn open(
        &mut self,
        space: SpaceId,
        agent: AgentId,
    ) -> Result<(Self::Intent, Self::Issuer), Self::Error>;
}

/// Type-erased, node-owned lifecycle access. It is deliberately not an ingress
/// trait: only the production owner may coordinate creation and publication.
pub(crate) trait NativeLocalLifecycle: Send {
    fn node(&self) -> Result<super::sdk::NodeId, SharedAgentHostError>;
    fn system_attachment(
        &self,
        capacity: usize,
    ) -> Result<AgentRouteHostAttachment, AgentRouteAdapterError>;
    fn local_attachment(
        &self,
        capacity: usize,
    ) -> Result<AgentRouteHostAttachment, AgentRouteAdapterError>;
    fn create(
        &mut self,
        descriptor: AgentDescriptor,
        call: AuthorityCredentialCall,
        runtime: AdmittedRuntimePackage,
    ) -> Result<(AgentId, ManagementApplicationAck), SharedAgentHostError>;
}

impl<P, R, I, F, S> NativeLocalLifecycle for LocalLifecycleController<P, R, I, F, S>
where
    P: CleanSystemAgentBootstrapStore + Send + 'static,
    R: CleanSystemAgentBootstrapStore + Send + 'static,
    I: CleanManagementIssuerStore + Send + 'static,
    F: LocalLifecycleStoreFactory + Send,
    S: CleanManagementReceiptSigner + Send,
{
    fn node(&self) -> Result<super::sdk::NodeId, SharedAgentHostError> {
        Ok(self
            .local
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?
            .node())
    }
    fn system_attachment(
        &self,
        capacity: usize,
    ) -> Result<AgentRouteHostAttachment, AgentRouteAdapterError> {
        LocalLifecycleController::system_attachment(self, capacity)
    }
    fn local_attachment(
        &self,
        capacity: usize,
    ) -> Result<AgentRouteHostAttachment, AgentRouteAdapterError> {
        LocalLifecycleController::local_attachment(self, capacity)
    }
    fn create(
        &mut self,
        descriptor: AgentDescriptor,
        call: AuthorityCredentialCall,
        runtime: AdmittedRuntimePackage,
    ) -> Result<(AgentId, ManagementApplicationAck), SharedAgentHostError> {
        LocalLifecycleController::create(self, descriptor, call, runtime)
    }
}

/// Retains one system owner and one physical Local host across route-worker
/// retirement. Lifecycle calls lock system then Local; route workers lock only
/// their own host. Never call route-worker methods while either guard is held.
/// Native shutdown must stop lifecycle callers and retire/join route workers
/// before dropping this controller's final owner references.
pub struct LocalLifecycleController<P, R, I, F, S>
where
    P: CleanSystemAgentBootstrapStore,
    R: CleanSystemAgentBootstrapStore,
    I: CleanManagementIssuerStore,
{
    system: Arc<Mutex<CleanSystemAgentBootstrapOwner<P, R, I>>>,
    local: Arc<Mutex<LocalAgentHost>>,
    stores: F,
    signer: S,
}

impl<P, R, I, F, S> LocalLifecycleController<P, R, I, F, S>
where
    P: CleanSystemAgentBootstrapStore + Send + 'static,
    R: CleanSystemAgentBootstrapStore + Send + 'static,
    I: CleanManagementIssuerStore + Send + 'static,
    F: LocalLifecycleStoreFactory,
    S: CleanManagementReceiptSigner,
{
    pub fn new(
        system: CleanSystemAgentBootstrapOwner<P, R, I>,
        local: LocalAgentHost,
        stores: F,
        signer: S,
    ) -> Result<Self, SharedAgentHostError> {
        if local.space() != system.pins().space() || local.node() != system.pins().node() {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        Ok(Self {
            system: Arc::new(Mutex::new(system)),
            local: Arc::new(Mutex::new(local)),
            stores,
            signer,
        })
    }

    pub fn system_attachment(
        &self,
        capacity: usize,
    ) -> Result<AgentRouteHostAttachment, AgentRouteAdapterError> {
        super::supervisor_adapters::system_agent_supervisor_attachment_shared(
            self.system.clone(),
            capacity,
        )
    }

    pub fn local_attachment(
        &self,
        capacity: usize,
    ) -> Result<AgentRouteHostAttachment, AgentRouteAdapterError> {
        super::supervisor_adapters::local_agent_supervisor_attachment_shared(
            self.local.clone(),
            capacity,
        )
    }

    /// Complete Create/application/finalization, retaining evidence for later
    /// authenticated publication. This does not itself publish ingress routes.
    pub fn create(
        &mut self,
        descriptor: AgentDescriptor,
        call: AuthorityCredentialCall,
        runtime: AdmittedRuntimePackage,
    ) -> Result<(AgentId, ManagementApplicationAck), SharedAgentHostError> {
        let mut system = self
            .system
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        let mut local = self
            .local
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        if descriptor.identity.profile != AgentProfile::Local
            || descriptor.identity.space != local.space()
            || descriptor.replicas.len() != 1
            || descriptor.replicas[0].node != local.node()
        {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        super::driver::verify_clean_runtime_package_binding(&descriptor, &runtime)
            .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
        // Authenticate before a filesystem factory can create a directory.
        super::clean_management_intent::CleanManagementIntent::new(
            system.authority_target(),
            call.managed,
            ManagementRequest::Create(Box::new(descriptor.clone())),
            call.clone(),
            &super::clean_bootstrap::RawCredentialVerifier,
        )
        .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
        let (intent, issuer) = self
            .stores
            .open(descriptor.identity.space, descriptor.identity.agent)
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        system.create_local_agent(
            intent,
            issuer,
            descriptor,
            call,
            &mut local,
            runtime,
            &mut self.signer,
        )
    }
}
