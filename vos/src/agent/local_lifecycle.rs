//! Native ownership boundary for signed Local Agent lifecycle operations.

use std::sync::{Arc, Mutex};

use super::clean_authority_issuer::{CleanManagementIssuerStore, CleanManagementReceiptSigner};
use super::clean_bootstrap::{CleanSystemAgentBootstrapOwner, CleanSystemAgentBootstrapStore};
use super::local_sdk_host::LocalAgentHost;
use super::package_admission::AdmittedRuntimePackage;
use super::sdk::authority::{AuthorityCredentialCall, ManagementApplicationAck};
use super::sdk::{AgentDescriptor, AgentId, AgentProfile, ManagementRequest, SpaceId};
use super::shared_host::SharedAgentHostError;
use super::supervisor_adapters::{AgentRouteAdapterError, AgentRouteHostAttachment};

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
