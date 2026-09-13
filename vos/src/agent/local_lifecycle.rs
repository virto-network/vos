//! Native ownership boundary for signed Local Agent lifecycle operations.

use std::collections::BTreeMap;
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

/// A signed server-side retirement of one exact denied Create. This is not an
/// application acknowledgement, policy approval, or evidence of a live route.
/// Construct only by verifying against an independently retained submission.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalCreateDenial {
    bytes: Vec<u8>,
}

impl LocalCreateDenial {
    pub const MAX_BYTES: usize = super::clean_management_intent::MAX_INTENT_BYTES;

    pub fn exact_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl LocalCreateSubmission {
    /// The caller must establish this submission's Space, operator and Authority
    /// from its own retained request/pins before treating denial as completion.
    /// No runtime replay or access to the server's stores is needed here.
    pub fn verify_denial(
        &self,
        bytes: &[u8],
    ) -> Result<LocalCreateDenial, crate::service::wire::DecodeError> {
        super::clean_management_intent::verify_denial_record(
            bytes,
            &ManagementRequest::Create(Box::new(self.descriptor.clone())),
            &self.call,
        )?;
        Ok(LocalCreateDenial {
            bytes: bytes.to_vec(),
        })
    }

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

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LocalCreateDisposition {
    Created(AgentId, ManagementApplicationAck),
    Denied(LocalCreateDenial),
}

pub type LocalCreateResult =
    Result<LocalCreateDisposition, super::production_owner::AgentProductionOwnerError>;

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

/// Open the independent intent/issuer images and retained Create runtime under
/// the same exclusive lifecycle lease on every retry. Implementors derive paths
/// from the configured Space and Agent, never caller path strings.
pub trait LocalLifecycleStoreFactory {
    type Intent: super::clean_authority_issuer::CleanManagementRuntimeStore;
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
    authority: super::sdk::authority::AuthorityActorTarget,
    pub(crate) entries: Vec<LocalLifecycleRecoveryEntry<I, J>>,
}

/// Startup admission derived only from verified, still-leased lifecycle stores.
/// Covers completed work, issued receipts, and saved initial-Create
/// authorization. Issuer eligibility is not approval, and application must be
/// independently observed from the Local image before acknowledgement signing.
pub struct LocalLifecycleStartupAdmission {
    pub(crate) authority: super::sdk::authority::AuthorityActorTarget,
    order: Vec<usize>,
    pub(crate) retirements: Vec<[super::sdk::RuntimeWork; 2]>,
    pub(crate) pending: Vec<
        Vec<(
            super::clean_management_intent::ManagementJournalAnchor,
            super::sdk::RuntimeWork,
        )>,
    >,
}

impl LocalLifecycleStartupAdmission {
    pub(crate) fn is_empty(&self) -> bool {
        self.retirements.is_empty() && self.pending.is_empty()
    }
}

pub(crate) struct LocalLifecycleRecoveryEntry<
    I: CleanManagementIssuerStore,
    J: CleanManagementIssuerStore,
> {
    pub(crate) agent: AgentId,
    pub(crate) intent: super::clean_management_intent::CleanManagementIntentSlot<I>,
    pub(crate) issuer: super::clean_authority_issuer::DurableCleanManagementIssuer<J>,
    pub(crate) finalized: Option<ManagementApplicationAck>,
    pub(crate) observed: Option<ManagementApplicationAck>,
    pub(crate) issued: Option<super::sdk::authority::AuthorityReceipt>,
    pub(crate) unissued_creation: bool,
}

impl<I: CleanManagementIssuerStore, J: CleanManagementIssuerStore> LocalLifecycleRecovery<I, J> {
    pub fn startup_admission(
        &self,
    ) -> Result<LocalLifecycleStartupAdmission, SharedAgentHostError> {
        let mut retirements = Vec::new();
        let mut pending = Vec::new();
        let mut credentials = Vec::new();
        for (index, entry) in self.entries.iter().enumerate() {
            if entry
                .intent
                .denial_complete()
                .map_err(|_| SharedAgentHostError::Unavailable)?
            {
                continue;
            }
            let retired = entry
                .intent
                .retirement_complete()
                .map_err(|_| SharedAgentHostError::Unavailable)?;
            if let Some(intent) = entry.intent.intent() {
                credentials.push(RecoveryOrderEntry {
                    index,
                    credential: intent.call().credential,
                    sequence: intent.call().request_sequence.get(),
                    needs_authorization: entry.unissued_creation,
                    needs_finalization_preparation: !retired
                        && entry
                            .intent
                            .finalization_work()
                            .map_err(|_| SharedAgentHostError::Unavailable)?
                            .is_none(),
                    ready: retired || entry.issued.is_some() || entry.unissued_creation,
                });
            }
            if retired {
                continue;
            }
            let authorization = entry
                .intent
                .authorization_work()
                .map_err(|_| SharedAgentHostError::Unavailable)?;
            let finalization = entry
                .intent
                .finalization_work()
                .map_err(|_| SharedAgentHostError::Unavailable)?;
            match (authorization, finalization, &entry.finalized) {
                (None, None, None)
                    if entry.issuer.sequence_high_water() == 0
                        && !entry.issuer.has_pending_decision()
                        && entry.issuer.retained_decisions() == 0 => {}
                (Some(authorization), Some(finalization), Some(_)) => {
                    retirements.push([authorization.clone(), finalization.clone()]);
                }
                (Some(authorization), finalization, None)
                    if entry.issued.is_some() || entry.unissued_creation =>
                {
                    let authorization_anchor = entry
                        .intent
                        .authorization_anchor()
                        .map_err(|_| SharedAgentHostError::Unavailable)?
                        .ok_or(SharedAgentHostError::ScopeMismatch)?;
                    let mut group = vec![(authorization_anchor.clone(), authorization.clone())];
                    if let Some(finalization) = finalization {
                        let finalization_anchor = entry
                            .intent
                            .finalization_anchor()
                            .map_err(|_| SharedAgentHostError::Unavailable)?
                            .ok_or(SharedAgentHostError::ScopeMismatch)?;
                        group.push((finalization_anchor.clone(), finalization.clone()));
                    }
                    pending.push(group);
                }
                // Earlier phases still need protected phase extension; never
                // expose traffic or checkpoint away their retained anchors.
                _ => return Err(SharedAgentHostError::Conflict),
            }
        }
        let mut order = ordered_authorization_recovery(credentials)?;
        let successors: BTreeMap<_, _> = self
            .entries
            .iter()
            .filter(|entry| entry.unissued_creation)
            .map(|entry| {
                let call = entry
                    .intent
                    .intent()
                    .expect("validated unissued intent")
                    .call();
                (call.credential, call.request_sequence.get())
            })
            .collect();
        // Only already-issued predecessors need early retirement. Independent
        // unissued calls retain the existing all-authorizations-first pipeline.
        order.retain(|index| {
            let entry = &self.entries[*index];
            let call = entry.intent.intent().expect("ordered intent").call();
            entry.issued.is_some()
                && !entry.intent.retirement_complete().unwrap_or(false)
                && successors
                    .get(&call.credential)
                    .is_some_and(|sequence| call.request_sequence.get() < *sequence)
        });
        let saved_slot = |index: usize, finalization: bool| -> Result<u64, SharedAgentHostError> {
            let slot = &self.entries[index].intent;
            let work = if finalization {
                slot.finalization_work()
            } else {
                slot.authorization_work()
            }
            .map_err(|_| SharedAgentHostError::Unavailable)?;
            match work {
                Some(super::sdk::RuntimeWork::Invoke { observed_slot, .. }) => Ok(*observed_slot),
                _ => Err(SharedAgentHostError::ScopeMismatch),
            }
        };
        let mut predecessors = order
            .into_iter()
            .map(|index| Ok((saved_slot(index, true)?, index)))
            .collect::<Result<Vec<_>, SharedAgentHostError>>()?;
        // Stable ties preserve the per-credential order validated above.
        predecessors.sort_by_key(|(slot, _)| *slot);
        let earliest_authorization = self
            .entries
            .iter()
            .enumerate()
            .filter(|(_, entry)| entry.unissued_creation)
            .map(|(index, _)| saved_slot(index, false))
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .min();
        if predecessors
            .last()
            .zip(earliest_authorization)
            .is_some_and(|((slot, _), authorization)| *slot > authorization)
        {
            return Err(SharedAgentHostError::Conflict);
        }
        let order = predecessors.into_iter().map(|(_, index)| index).collect();
        Ok(LocalLifecycleStartupAdmission {
            authority: self.authority,
            order,
            retirements,
            pending,
        })
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

struct RecoveryOrderEntry {
    index: usize,
    credential: super::sdk::CredentialId,
    sequence: u64,
    needs_authorization: bool,
    needs_finalization_preparation: bool,
    ready: bool,
}

/// Sort by signed credential sequence, never by the Agent directory name.
/// Ambiguous sequence reuse and overtaking a known client-only predecessor
/// reject before attachment. Authority replay remains the approval boundary.
fn ordered_authorization_recovery(
    mut calls: Vec<RecoveryOrderEntry>,
) -> Result<Vec<usize>, SharedAgentHostError> {
    calls.sort_unstable_by_key(|call| (call.credential, call.sequence));
    let mut previous = None;
    let mut waiting_for_client = false;
    let mut needs_fresh_clock = false;
    let mut order = Vec::with_capacity(calls.len());
    for call in calls {
        if call.sequence == 0 || previous == Some((call.credential, call.sequence)) {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        if previous.is_none_or(|(credential, _)| credential != call.credential) {
            waiting_for_client = false;
            needs_fresh_clock = false;
        }
        // A fresh predecessor finalization can advance the runtime clock past
        // its successor's immutable authorization envelope. Until live capture
        // prevents that overlap, reject this set before executing either call.
        if (waiting_for_client || needs_fresh_clock) && call.needs_authorization {
            return Err(SharedAgentHostError::Conflict);
        }
        waiting_for_client |= !call.ready;
        needs_fresh_clock |= call.needs_finalization_preparation;
        previous = Some((call.credential, call.sequence));
        order.push(call.index);
    }
    Ok(order)
}

#[test]
fn unissued_recovery_orders_credentials_and_rejects_ambiguous_predecessors() {
    let a = super::sdk::CredentialId([1; 32]);
    let b = super::sdk::CredentialId([2; 32]);
    let call = |index, credential, sequence, ready| RecoveryOrderEntry {
        index,
        credential,
        sequence,
        needs_authorization: ready,
        needs_finalization_preparation: false,
        ready,
    };
    assert_eq!(
        ordered_authorization_recovery(vec![call(0, a, 2, true), call(1, a, 1, true)]).unwrap(),
        vec![1, 0]
    );
    assert_eq!(
        ordered_authorization_recovery(vec![call(0, b, 1, true), call(1, a, 1, true)]).unwrap(),
        vec![1, 0]
    );
    assert!(matches!(
        ordered_authorization_recovery(vec![call(0, a, 1, true), call(1, a, 1, true)]),
        Err(SharedAgentHostError::ScopeMismatch)
    ));
    assert!(matches!(
        ordered_authorization_recovery(vec![call(0, a, 2, true), call(1, a, 1, false)]),
        Err(SharedAgentHostError::Conflict)
    ));
    assert_eq!(
        ordered_authorization_recovery(vec![call(0, a, 1, true), call(1, a, 2, false)]).unwrap(),
        vec![0, 1]
    );
    let mut predecessor = call(0, a, 1, true);
    predecessor.needs_finalization_preparation = true;
    assert!(matches!(
        ordered_authorization_recovery(vec![predecessor, call(1, a, 2, true)]),
        Err(SharedAgentHostError::Conflict)
    ));
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
        let observed = if let Some(request) = intent.intent() {
            issuer
                .recover_observed_application(
                    authority,
                    request.call().managed,
                    request.request(),
                    request.call(),
                    &RawCredentialVerifier,
                )
                .map_err(|_| SharedAgentHostError::ScopeMismatch)?
                .map(|(_, ack)| ack)
        } else {
            None
        };
        if observed.is_some()
            && (issuer.has_pending_decision()
                || issuer.retained_decisions() != 0
                || issuer.sequence_high_water() != issuer.acknowledged_through())
        {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        if let Some(super::sdk::RuntimeWork::Invoke { invocation, .. }) = intent
            .finalization_work()
            .map_err(|_| SharedAgentHostError::Unavailable)?
        {
            let acknowledgement = observed
                .as_ref()
                .ok_or(SharedAgentHostError::ScopeMismatch)?;
            let Some(super::sdk::RuntimeWork::Invoke { observed_slot, .. }) = intent
                .authorization_work()
                .map_err(|_| SharedAgentHostError::Unavailable)?
            else {
                return Err(SharedAgentHostError::ScopeMismatch);
            };
            if acknowledgement.applied_at < *observed_slot
                || invocation.message
                    != CleanManagementIntent::finalization_message(acknowledgement)
            {
                return Err(SharedAgentHostError::ScopeMismatch);
            }
        }
        let issued = if let Some(request) = intent.intent() {
            issuer
                .recover_issued_application(
                    authority,
                    request.call().managed,
                    request.request(),
                    request.call(),
                    &RawCredentialVerifier,
                )
                .map_err(|_| SharedAgentHostError::ScopeMismatch)?
        } else {
            None
        };
        if observed.is_some() && issued.is_none() {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        let denied = intent
            .denial_complete()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        if denied
            && (issuer.sequence_high_water() != 0
                || issuer.has_pending_decision()
                || issuer.retained_decisions() != 0)
        {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        let unissued_creation = if !denied
            && issued.is_none()
            && intent
                .authorization_work()
                .map_err(|_| SharedAgentHostError::Unavailable)?
                .is_some()
        {
            let request = intent.intent().ok_or(SharedAgentHostError::ScopeMismatch)?;
            issuer
                .can_resume_initial_creation(
                    authority,
                    request.call().managed,
                    request.request(),
                    request.call(),
                    &RawCredentialVerifier,
                )
                .map_err(|_| SharedAgentHostError::ScopeMismatch)?
        } else {
            false
        };
        entries.push(LocalLifecycleRecoveryEntry {
            agent,
            intent,
            issuer,
            finalized,
            observed,
            issued,
            unissued_creation,
        });
    }
    Ok(LocalLifecycleRecovery { authority, entries })
}

fn load_create_runtime<B: super::clean_authority_issuer::CleanManagementRuntimeStore>(
    intent: &mut super::clean_management_intent::CleanManagementIntentSlot<B>,
) -> Result<AdmittedRuntimePackage, SharedAgentHostError> {
    let bytes = intent
        .load_runtime()
        .map_err(|_| SharedAgentHostError::Unavailable)?
        .ok_or(SharedAgentHostError::Unavailable)?;
    let runtime = super::package_admission::admit_runtime_package(&bytes)
        .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
    let ManagementRequest::Create(descriptor) = intent
        .intent()
        .ok_or(SharedAgentHostError::ScopeMismatch)?
        .request()
    else {
        return Err(SharedAgentHostError::ScopeMismatch);
    };
    super::driver::verify_clean_runtime_package_binding(descriptor, &runtime)
        .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
    Ok(runtime)
}

/// Type-erased, node-owned lifecycle access. It is deliberately not an ingress
/// trait: only the production owner may coordinate creation and publication.
pub(crate) trait NativeLocalLifecycle: Send {
    /// Only a retained, signed completion may turn a failed Create into a
    /// terminal denial. Other implementations conservatively retain the error.
    fn retained_denial(
        &mut self,
        _submission: &LocalCreateSubmission,
    ) -> Result<Option<LocalCreateDenial>, SharedAgentHostError> {
        Ok(None)
    }
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
    F::Intent: Send,
    F::Issuer: Send,
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

    fn retained_denial(
        &mut self,
        submission: &LocalCreateSubmission,
    ) -> Result<Option<LocalCreateDenial>, SharedAgentHostError> {
        let system = self
            .system
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        if submission.call.authority != system.authority_target() {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        let Some((intent, _)) = self
            .retained_stores
            .get_mut(&submission.descriptor.identity.agent)
        else {
            return Ok(None);
        };
        let Some(bytes) = intent
            .load()
            .map_err(|_| SharedAgentHostError::Unavailable)?
        else {
            return Ok(None);
        };
        if !bytes.starts_with(b"CND1") {
            return Ok(None);
        }
        submission
            .verify_denial(&bytes)
            .map(Some)
            .map_err(|_| SharedAgentHostError::ScopeMismatch)
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
    F: LocalLifecycleStoreFactory,
{
    system: Arc<Mutex<CleanSystemAgentBootstrapOwner<P, R, I>>>,
    local: Arc<Mutex<LocalAgentHost>>,
    stores: F,
    // Retain exclusive handles across retries, including ambiguous commits.
    // Parsed protocol state is reopened from these handles for every call.
    retained_stores: BTreeMap<AgentId, (F::Intent, F::Issuer)>,
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
            retained_stores: BTreeMap::new(),
            signer,
        })
    }

    /// Adopt stores previously verified against independently selected pins.
    /// This transfers leases without opening their paths again. The caller
    /// must separately seed system-network recovery before publishing routes;
    /// this constructor then rechecks physical Local application, completes
    /// finalization under pending admission, and retires results before normal
    /// lifecycle/route access.
    pub fn with_recovery(
        mut system: CleanSystemAgentBootstrapOwner<P, R, I>,
        mut local: LocalAgentHost,
        stores: F,
        mut signer: S,
        mut recovery: LocalLifecycleRecovery<F::Intent, F::Issuer>,
    ) -> Result<Self, SharedAgentHostError> {
        if recovery.authority != system.authority_target()
            || local.space() != system.pins().space()
            || local.node() != system.pins().node()
        {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        // Validate the entire set before retiring any member. Incomplete
        // phases require their own protected recovery protocol, not omission.
        let admission = recovery.startup_admission()?;
        for entry in &mut recovery.entries {
            if (entry.unissued_creation
                || entry
                    .intent
                    .denial_complete()
                    .map_err(|_| SharedAgentHostError::Unavailable)?)
                && system.finish_denied_management_intent(
                    &mut entry.intent,
                    &entry.issuer,
                    &local,
                    &mut signer,
                )?
            {
                entry.unissued_creation = false;
            }
        }
        let mut runtimes = BTreeMap::new();
        for (index, entry) in recovery.entries.iter_mut().enumerate() {
            if entry.unissued_creation
                || (entry.issued.is_some()
                    && entry.observed.is_none()
                    && matches!(
                        local.show(entry.agent),
                        Err(super::local_sdk_host::LocalAgentHostError::NotFound)
                    ))
            {
                runtimes.insert(index, load_create_runtime(&mut entry.intent)?);
            }
        }
        // Verify physical images before advancing any required predecessor.
        // Its saved finalization clock was checked against every unissued
        // authorization by startup_admission; no envelope is rewritten.
        if !admission.order.is_empty() {
            for entry in &recovery.entries {
                if let Some(receipt) = &entry.issued {
                    if entry.observed.is_none()
                        && matches!(
                            local.show(entry.agent),
                            Err(super::local_sdk_host::LocalAgentHostError::NotFound)
                        )
                    {
                        continue;
                    }
                    local
                        .observe_management_application(
                            entry.agent,
                            entry
                                .intent
                                .intent()
                                .ok_or(SharedAgentHostError::ScopeMismatch)?
                                .request(),
                            receipt,
                        )
                        .map_err(|_| SharedAgentHostError::Unavailable)?;
                }
            }
        }
        for &index in &admission.order {
            let entry = &mut recovery.entries[index];
            let intent = entry
                .intent
                .intent()
                .ok_or(SharedAgentHostError::ScopeMismatch)?;
            let managed = intent.call().managed;
            let receipt = entry
                .issued
                .as_ref()
                .ok_or(SharedAgentHostError::ScopeMismatch)?;
            let observation = local
                .observe_management_application(entry.agent, intent.request(), receipt)
                .map_err(|_| SharedAgentHostError::Unavailable)?;
            let acknowledgement = entry
                .issuer
                .observe_local_application(&observation, &mut signer)
                .map_err(|_| SharedAgentHostError::Unavailable)?;
            if entry
                .observed
                .as_ref()
                .is_some_and(|saved| saved != &acknowledgement)
            {
                return Err(SharedAgentHostError::ScopeMismatch);
            }
            entry.observed = Some(acknowledgement.clone());
            if entry.finalized.is_none() {
                system.finalize_management_intent_with_admission(
                    &mut entry.intent,
                    managed,
                    &acknowledgement,
                    &mut entry.issuer,
                    true,
                )?;
                entry.finalized = Some(acknowledgement.clone());
                let authorization = entry
                    .intent
                    .authorization_work()
                    .map_err(|_| SharedAgentHostError::Unavailable)?
                    .ok_or(SharedAgentHostError::ScopeMismatch)?;
                let finalization = entry
                    .intent
                    .finalization_work()
                    .map_err(|_| SharedAgentHostError::Unavailable)?
                    .ok_or(SharedAgentHostError::ScopeMismatch)?;
                system.handoff_recovered_management(&[[authorization, finalization]])?;
            }
            system.finish_management_intent_retirement(
                &mut entry.intent,
                managed,
                &acknowledgement,
                &entry.issuer,
            )?;
        }
        // Runtime availability is checked before executing any unissued call.
        // The issuer eligibility check does not replace durable actor replay.
        for entry in &mut recovery.entries {
            if entry.unissued_creation {
                let managed = entry
                    .intent
                    .intent()
                    .ok_or(SharedAgentHostError::ScopeMismatch)?
                    .call()
                    .managed;
                entry.issued = Some(system.issue_management_intent(
                    &mut entry.intent,
                    managed,
                    &mut entry.issuer,
                    &mut signer,
                )?);
            }
        }
        let mut observations = Vec::new();
        let mut creates = Vec::new();
        for (index, entry) in recovery.entries.iter_mut().enumerate() {
            if let Some(receipt) = &entry.issued {
                let request = entry
                    .intent
                    .intent()
                    .ok_or(SharedAgentHostError::ScopeMismatch)?
                    .request()
                    .clone();
                if entry.observed.is_none()
                    && matches!(
                        local.show(entry.agent),
                        Err(super::local_sdk_host::LocalAgentHostError::NotFound)
                    )
                {
                    let ManagementRequest::Create(descriptor) = &request else {
                        return Err(SharedAgentHostError::ScopeMismatch);
                    };
                    let runtime = runtimes
                        .remove(&index)
                        .ok_or(SharedAgentHostError::ScopeMismatch)?;
                    creates.push((index, runtime, (**descriptor).clone(), receipt.clone()));
                    continue;
                }
                // A finalized issuer cannot replace the actual Local image.
                let observation = local
                    .observe_management_application(entry.agent, &request, receipt)
                    .map_err(|_| SharedAgentHostError::Unavailable)?;
                observations.push((index, observation));
            }
        }
        for (index, runtime, descriptor, receipt) in creates {
            let request = ManagementRequest::Create(Box::new(descriptor.clone()));
            let agent = local
                .create_agent(runtime, descriptor, receipt.clone())
                .map_err(|error| {
                    crate::log::warn!("Local lifecycle recovery Create failed: {error:?}");
                    SharedAgentHostError::Unavailable
                })?;
            let observation = local
                .observe_management_application(agent, &request, &receipt)
                .map_err(|_| SharedAgentHostError::Unavailable)?;
            observations.push((index, observation));
        }
        // Check all physical images before signing a missing acknowledgement
        // for any member. An issued receipt alone is not application proof.
        for (index, observation) in observations {
            let entry = &mut recovery.entries[index];
            let acknowledgement = entry
                .issuer
                .observe_local_application(&observation, &mut signer)
                .map_err(|_| SharedAgentHostError::Unavailable)?;
            if entry
                .observed
                .as_ref()
                .is_some_and(|saved| saved != &acknowledgement)
            {
                return Err(SharedAgentHostError::ScopeMismatch);
            }
            entry.observed = Some(acknowledgement);
        }
        let mut recovered_pairs = Vec::new();
        for entry in &mut recovery.entries {
            if entry.finalized.is_none()
                && let Some(acknowledgement) = &entry.observed
            {
                // Saved work keeps its clock. Missing finalization is reserved
                // before publication, without releasing the predecessor gate.
                let managed = entry
                    .intent
                    .intent()
                    .ok_or(SharedAgentHostError::ScopeMismatch)?
                    .call()
                    .managed;
                system.finalize_management_intent_with_admission(
                    &mut entry.intent,
                    managed,
                    acknowledgement,
                    &mut entry.issuer,
                    true,
                )?;
                entry.finalized = Some(acknowledgement.clone());
                recovered_pairs.push([
                    entry
                        .intent
                        .authorization_work()
                        .map_err(|_| SharedAgentHostError::Unavailable)?
                        .ok_or(SharedAgentHostError::ScopeMismatch)?
                        .clone(),
                    entry
                        .intent
                        .finalization_work()
                        .map_err(|_| SharedAgentHostError::Unavailable)?
                        .ok_or(SharedAgentHostError::ScopeMismatch)?
                        .clone(),
                ]);
            }
        }
        if !recovered_pairs.is_empty() {
            system.handoff_recovered_management(
                &recovered_pairs
                    .iter()
                    .map(|pair| [&pair[0], &pair[1]])
                    .collect::<Vec<_>>(),
            )?;
        }
        for entry in &mut recovery.entries {
            if entry
                .intent
                .retirement_complete()
                .map_err(|_| SharedAgentHostError::Unavailable)?
            {
                continue;
            }
            if let Some(acknowledgement) = &entry.finalized {
                let managed = entry
                    .intent
                    .intent()
                    .ok_or(SharedAgentHostError::ScopeMismatch)?
                    .call()
                    .managed;
                system.finish_management_intent_retirement(
                    &mut entry.intent,
                    managed,
                    acknowledgement,
                    &entry.issuer,
                )?;
            }
        }
        let mut controller = Self::new(system, local, stores, signer)?;
        for entry in recovery.entries {
            if controller
                .retained_stores
                .insert(
                    entry.agent,
                    (entry.intent.into_store(), entry.issuer.into_store()),
                )
                .is_some()
            {
                return Err(SharedAgentHostError::ScopeMismatch);
            }
        }
        Ok(controller)
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

    #[cfg(test)]
    pub(crate) fn ordered_index_for_test(&self) -> Result<u64, SharedAgentHostError> {
        self.system
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?
            .ordered_index_for_test()
    }

    #[cfg(test)]
    pub(crate) fn fail_finalization_once_for_test(&mut self, phase: u8) {
        self.system
            .lock()
            .unwrap()
            .fail_finalization_once_for_test(phase);
    }

    #[cfg(test)]
    pub(crate) fn into_parts_for_test(
        self,
    ) -> (
        CleanSystemAgentBootstrapOwner<P, R, I>,
        LocalAgentHost,
        F,
        S,
    ) {
        let Self {
            system,
            local,
            stores,
            retained_stores,
            signer,
        } = self;
        drop(retained_stores);
        let system = Arc::try_unwrap(system)
            .ok()
            .expect("retire system route workers first")
            .into_inner()
            .unwrap();
        let local = Arc::try_unwrap(local)
            .ok()
            .expect("retire local route workers first")
            .into_inner()
            .unwrap();
        (system, local, stores, signer)
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
        let entry = self.retained_stores.entry(descriptor.identity.agent);
        let (intent, issuer) = match entry {
            std::collections::btree_map::Entry::Occupied(entry) => entry.into_mut(),
            std::collections::btree_map::Entry::Vacant(entry) => {
                let stores = self
                    .stores
                    .open(descriptor.identity.space, descriptor.identity.agent)
                    .map_err(|_| SharedAgentHostError::Unavailable)?;
                entry.insert(stores)
            }
        };
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
