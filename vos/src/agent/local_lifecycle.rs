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

/// Canonical signed Create submission: LCQ1 followed by length-prefixed AMRQ,
/// ACC3 and an exact admitted VOS3 runtime package. This is untrusted request
/// data, not an Authority approval or a genesis-finality proof.
pub struct LocalCreateSubmission {
    descriptor: AgentDescriptor,
    call: AuthorityCredentialCall,
    runtime: AdmittedRuntimePackage,
}

impl LocalCreateSubmission {
    pub const MAX_BYTES: usize = 16
        + super::sdk::wire::MAX_MANAGEMENT_REQUEST_WIRE_BYTES
        + super::sdk::wire::MAX_AUTHORITY_CREDENTIAL_CALL_WIRE_BYTES
        + super::sdk::package::MAX_PACKAGE_ENCODED_BYTES;

    pub fn new(
        descriptor: AgentDescriptor,
        call: AuthorityCredentialCall,
        runtime: AdmittedRuntimePackage,
    ) -> Result<Self, crate::service::wire::DecodeError> {
        use crate::service::wire::DecodeError;
        if descriptor.identity.profile != AgentProfile::Local {
            return Err(DecodeError::NonCanonical);
        }
        super::driver::verify_clean_runtime_package_binding(&descriptor, &runtime)
            .map_err(|_| DecodeError::NonCanonical)?;
        super::clean_management_intent::CleanManagementIntent::new(
            call.authority,
            call.managed,
            ManagementRequest::Create(Box::new(descriptor.clone())),
            call.clone(),
            &super::clean_bootstrap::RawCredentialVerifier,
        )
        .map_err(|_| DecodeError::NonCanonical)?;
        Ok(Self {
            descriptor,
            call,
            runtime,
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        use super::sdk::wire::CanonicalWire as _;
        let mut bytes = b"LCQ1".to_vec();
        let mut encoder = crate::service::wire::Encoder(&mut bytes);
        encoder.bytes(
            &ManagementRequest::Create(Box::new(self.descriptor.clone()))
                .encode()
                .expect("validated Create"),
        );
        encoder.bytes(&self.call.encode().expect("validated credential call"));
        encoder.bytes(self.runtime.exact_bytes());
        bytes
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, crate::service::wire::DecodeError> {
        use super::sdk::wire::CanonicalWire as _;
        use crate::service::wire::{DecodeError, Decoder};
        if bytes.len() > Self::MAX_BYTES {
            return Err(DecodeError::LimitExceeded);
        }
        if bytes.get(..4) != Some(b"LCQ1") {
            return Err(DecodeError::InvalidTag);
        }
        let mut decoder = Decoder::new(&bytes[4..]);
        let request = decoder.bytes_ref()?;
        let call = decoder.bytes_ref()?;
        let package = decoder.bytes_ref()?;
        if !decoder.exhausted() {
            return Err(DecodeError::TrailingBytes);
        }
        if request.len() > super::sdk::wire::MAX_MANAGEMENT_REQUEST_WIRE_BYTES
            || call.len() > super::sdk::wire::MAX_AUTHORITY_CREDENTIAL_CALL_WIRE_BYTES
            || package.len() > super::sdk::package::MAX_PACKAGE_ENCODED_BYTES
        {
            return Err(DecodeError::LimitExceeded);
        }
        let ManagementRequest::Create(descriptor) =
            ManagementRequest::decode(request).map_err(|_| DecodeError::NonCanonical)?
        else {
            return Err(DecodeError::NonCanonical);
        };
        let call = AuthorityCredentialCall::decode(call).map_err(|_| DecodeError::NonCanonical)?;
        let runtime = super::package_admission::admit_runtime_package(package)
            .map_err(|_| DecodeError::NonCanonical)?;
        Self::new(*descriptor, call, runtime)
    }

    pub fn into_parts(
        self,
    ) -> (
        AgentDescriptor,
        AuthorityCredentialCall,
        AdmittedRuntimePackage,
    ) {
        (self.descriptor, self.call, self.runtime)
    }
}

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

    /// Discover existing per-Agent store candidates before routes or lifecycle
    /// writers start. Return a sorted, unique, bounded list; never truncate.
    /// Names are not authority or evidence of pending work. The caller must
    /// open and independently verify every candidate's intent/issuer images.
    fn discover(&mut self, space: SpaceId, maximum: usize) -> Result<Vec<AgentId>, Self::Error>;

    /// Open a discovered store without recreating a missing Agent directory.
    /// Normal exclusive leasing and staged-image reconciliation still apply.
    fn open_existing(
        &mut self,
        space: SpaceId,
        agent: AgentId,
    ) -> Result<(Self::Intent, Self::Issuer), Self::Error>;

    fn open(
        &mut self,
        space: SpaceId,
        agent: AgentId,
    ) -> Result<(Self::Intent, Self::Issuer), Self::Error>;
}

/// Verified request/storage scope retained before startup publishes routes.
/// Pending entries are not approvals or proof of physical application. Keeping
/// both stores alive preserves their exclusive leases through recovery setup.
pub struct LocalLifecycleRecovery<I: CleanManagementIssuerStore, J: CleanManagementIssuerStore> {
    pub(crate) entries: Vec<LocalLifecycleRecoveryEntry<I, J>>,
}

pub(crate) struct LocalLifecycleRecoveryEntry<
    I: CleanManagementIssuerStore,
    J: CleanManagementIssuerStore,
> {
    pub(crate) agent: AgentId,
    pub(crate) intent: super::clean_management_intent::CleanManagementIntentSlot<I>,
    pub(crate) issuer: super::clean_authority_issuer::DurableCleanManagementIssuer<J>,
    pub(crate) finalized: Option<ManagementApplicationAck>,
}

impl<I: CleanManagementIssuerStore, J: CleanManagementIssuerStore> LocalLifecycleRecovery<I, J> {
    pub fn len(&self) -> usize {
        self.entries.len()
    }
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Load every discovered candidate through existing-only stores before ingress
/// starts. The Authority target must come from independently selected bootstrap
/// pins, not from a candidate's own signed request. This function never invokes
/// policy, signs receipts, retires results, or publishes a route.
pub fn discover_local_lifecycle_recovery<F: LocalLifecycleStoreFactory>(
    factory: &mut F,
    authority: super::sdk::authority::AuthorityActorTarget,
    maximum: usize,
) -> Result<LocalLifecycleRecovery<F::Intent, F::Issuer>, SharedAgentHostError> {
    use super::clean_authority_issuer::DurableCleanManagementIssuer;
    use super::clean_bootstrap::RawCredentialVerifier;
    use super::clean_management_intent::{CleanManagementIntent, CleanManagementIntentSlot};
    if !authority.is_valid() {
        return Err(SharedAgentHostError::ScopeMismatch);
    }
    let candidates = factory
        .discover(authority.space, maximum)
        .map_err(|_| SharedAgentHostError::Unavailable)?;
    if candidates.len() > maximum
        || candidates.iter().any(|agent| *agent == AgentId::ZERO)
        || candidates.windows(2).any(|pair| pair[0] >= pair[1])
    {
        return Err(SharedAgentHostError::ScopeMismatch);
    }
    let mut entries = Vec::with_capacity(candidates.len());
    for agent in candidates {
        let (intent_store, issuer_store) = factory
            .open_existing(authority.space, agent)
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        let intent = CleanManagementIntentSlot::open(intent_store)
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        if let Some(request) = intent.intent() {
            let managed = request.call().managed;
            if managed.space != authority.space
                || managed.agent != agent
                || managed.profile != AgentProfile::Local
            {
                return Err(SharedAgentHostError::ScopeMismatch);
            }
            request
                .verify(authority, managed, &RawCredentialVerifier)
                .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
        }
        let issuer = DurableCleanManagementIssuer::open(
            issuer_store,
            authority.binding,
            authority.space,
            agent,
        )
        .map_err(|_| SharedAgentHostError::Unavailable)?;
        let finalized = if let Some(request) = intent.intent() {
            let recovered = issuer
                .recover_finalized_application(
                    authority,
                    request.call().managed,
                    request.request(),
                    request.call(),
                    &RawCredentialVerifier,
                )
                .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
            let final_work = intent
                .finalization_work()
                .map_err(|_| SharedAgentHostError::Unavailable)?;
            if final_work.is_some() && issuer.sequence_high_water() == 0 {
                return Err(SharedAgentHostError::ScopeMismatch);
            }
            if let Some((_, acknowledgement)) = recovered {
                // A different outstanding issuance cannot be hidden behind
                // the previous finalized acknowledgement during startup.
                if issuer.has_pending_decision()
                    || issuer.retained_decisions() != 0
                    || issuer.sequence_high_water() != issuer.acknowledged_through()
                {
                    return Err(SharedAgentHostError::ScopeMismatch);
                }
                let Some(super::sdk::RuntimeWork::Invoke { invocation, .. }) = final_work else {
                    return Err(SharedAgentHostError::ScopeMismatch);
                };
                let Some(super::sdk::RuntimeWork::Invoke { observed_slot, .. }) = intent
                    .authorization_work()
                    .map_err(|_| SharedAgentHostError::Unavailable)?
                else {
                    return Err(SharedAgentHostError::ScopeMismatch);
                };
                if acknowledgement.applied_at < *observed_slot
                    || invocation.message
                        != CleanManagementIntent::finalization_message(&acknowledgement)
                {
                    return Err(SharedAgentHostError::ScopeMismatch);
                }
                Some(acknowledgement)
            } else {
                if intent
                    .retirement_complete()
                    .map_err(|_| SharedAgentHostError::Unavailable)?
                {
                    return Err(SharedAgentHostError::ScopeMismatch);
                }
                None
            }
        } else {
            if issuer.sequence_high_water() != 0
                || issuer.has_pending_decision()
                || issuer.retained_decisions() != 0
            {
                return Err(SharedAgentHostError::ScopeMismatch);
            }
            None
        };
        entries.push(LocalLifecycleRecoveryEntry {
            agent,
            intent,
            issuer,
            finalized,
        });
    }
    Ok(LocalLifecycleRecovery { entries })
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
