//! Durable issuance of clean SDK management authority decisions.
//!
//! This component deliberately does not evaluate policy. Its caller supplies
//! an explicit, already-authorized decision and an external signer. The
//! issuer only binds that decision to one immutable Agent authority route,
//! allocates the route-local management sequence, and durably remembers the
//! exact signed result until the caller explicitly reports that the latest
//! decision was observed in durable Agent state.

use core::{convert::Infallible, fmt, num::NonZeroU64};

use crate::agent::sdk::authority::{
    AgentAuthorityBinding, AuthorityActorTarget, AuthorityCredentialCall,
    AuthorityCredentialVerifier, AuthorityEvidence, AuthorityIssuer, AuthorityLaneRoots,
    AuthorityOperationKind, AuthorityReceipt, AuthorityReceiptSelector, ManagedAgentTarget,
    ManagementApplicationAck, ManagementApproval,
};
use crate::agent::sdk::wire::{CanonicalWire, management_reply_commitment};
use crate::agent::sdk::{
    ActorId, AgentId, AgentProfile, BlobRef, DeploymentId, Hash, InvocationId, ManagementReply,
    ManagementRequest, PrincipalId, ProducerId, ProgramId, SpaceId,
};
use vos_protocol::wire::{DecodeError, Decoder, Encoder};

/// The guest and issuer retain the same maximum unacknowledged decision
/// window. A full window cannot consume another authorization until an exact
/// latest receipt is explicitly acknowledged.
pub const MAX_CLEAN_MANAGEMENT_ISSUER_DECISIONS: usize =
    super::standard::MAX_AUTHORITY_DISPOSITIONS;
/// Maximum complete canonical issuer image accepted from durable storage.
pub const MAX_CLEAN_MANAGEMENT_ISSUER_IMAGE_BYTES: usize = 512 * 1024;
pub(crate) const MAX_AUTHORIZED_DECISION_BYTES: usize = 1_024;
const CLEAN_MANAGEMENT_ISSUER_MAGIC: [u8; 4] = *b"CIS2";

/// Minimal durable whole-image boundary owned by the clean Agent issuer.
///
/// `commit` returns success only after the complete byte slice is recoverable
/// following restart. Implementations are single-writer and may use an atomic
/// file replace, a database transaction, or a quorum commit. No service-host
/// storage contract or private signing material crosses this boundary.
pub trait CleanManagementIssuerStore {
    type Error;

    fn load(&mut self) -> Result<Option<Vec<u8>>, Self::Error>;

    fn commit(&mut self, image: &[u8]) -> Result<(), Self::Error>;
}

/// Policy-selected context which is visible in the signed SDK receipt.
///
/// This is data, not proof that policy ran. Possession of the separately
/// injected [`CleanManagementReceiptSigner`] remains the signing capability;
/// callers must construct this value only after their policy engine has made
/// the represented decision.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CleanManagementDecisionContext {
    pub space: SpaceId,
    pub agent: AgentId,
    pub runtime_deployment: DeploymentId,
    pub evidence: AuthorityEvidence,
    pub lane_roots: AuthorityLaneRoots,
    pub epoch: u64,
    pub valid_from: u64,
    pub expires_at: u64,
}

/// One explicit policy decision submitted to the durable issuer.
///
/// `authorization_id` is chosen by the upstream policy workflow, is stable
/// across retries, and must increase for every genuinely new decision on one
/// issuer route. It is deliberately distinct from `decision_sequence`, which
/// is allocated here. The durable authorization high-water makes reuse of an
/// acknowledged identifier fail closed without retaining an unbounded map.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorizedCleanManagementDecision {
    authorization_id: NonZeroU64,
    space: SpaceId,
    agent: AgentId,
    runtime_deployment: DeploymentId,
    operation: AuthorityOperationKind,
    actor: Option<ActorId>,
    actor_deployment: Option<DeploymentId>,
    creation_authority: Option<AgentAuthorityBinding>,
    evidence: AuthorityEvidence,
    lane_roots: AuthorityLaneRoots,
    epoch: u64,
    valid_from: u64,
    expires_at: u64,
    request: Hash,
    application: Option<CleanManagementApplicationContext>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CleanManagementApplicationContext {
    authorization_invocation: InvocationId,
    acknowledgement_invocation: InvocationId,
    authority: AuthorityActorTarget,
    managed: ManagedAgentTarget,
    credential_call: Hash,
    approval: Hash,
}

impl AuthorizedCleanManagementDecision {
    /// Convert one exact, runtime-authenticated authority-actor result into
    /// the only general management value accepted by the durable issuer.
    ///
    /// This constructor and [`DurableCleanManagementIssuer::issue`] are
    /// crate-private so an SDK caller cannot synthesize MAP2 with the public
    /// actor helper and reach the signer. The eventual coordinator must call
    /// this only for the exact result of the configured actor's authenticated
    /// Linear transition. The credential signature is reverified, the
    /// retained signed call must be byte-for-byte selected by the approval,
    /// and both complete routes must agree with independently loaded system-
    /// and managed-Agent targets. For Agent creation, the selected authority
    /// binding must also be the complete binding embedded in the request.
    pub(crate) fn from_approval<V: AuthorityCredentialVerifier>(
        expected_authority: AuthorityActorTarget,
        expected_managed: ManagedAgentTarget,
        request: &ManagementRequest,
        call: &AuthorityCredentialCall,
        approval: &ManagementApproval,
        credential_verifier: &V,
    ) -> Result<Self, CleanManagementDecisionError> {
        call.verify_with(credential_verifier)
            .map_err(|_| CleanManagementDecisionError::InvalidApproval)?;
        let binding = expected_authority.binding;
        if !expected_authority.is_valid()
            || !expected_managed.is_valid()
            || !request.is_valid()
            || !approval.matches_call(call)
            || !approval.plan.matches_request(request)
            || call.authority != expected_authority
            || approval.authority != expected_authority
            || call.managed != expected_managed
            || approval.managed != expected_managed
            || approval.epoch < binding.initial_epoch
            || matches!(
                request,
                ManagementRequest::Create(descriptor) if descriptor.authority != binding
            )
        {
            return Err(CleanManagementDecisionError::InvalidApproval);
        }
        let decision = Self::from_verified_approval_parts(
            approval.authorization_sequence,
            CleanManagementDecisionContext {
                space: approval.managed.space,
                agent: approval.managed.agent,
                runtime_deployment: approval.managed.runtime_deployment,
                evidence: approval.evidence.clone(),
                lane_roots: approval.lane_roots,
                epoch: approval.epoch,
                valid_from: approval.valid_from,
                expires_at: approval.expires_at,
            },
            request,
            Some(CleanManagementApplicationContext {
                authorization_invocation: call.invocation,
                acknowledgement_invocation: approval.acknowledgement_invocation,
                authority: approval.authority,
                managed: approval.managed,
                credential_call: approval.credential_call,
                approval: approval.commitment(),
            }),
        )?;
        (decision.request == approval.plan_commitment)
            .then_some(decision)
            .ok_or(CleanManagementDecisionError::InvalidApproval)
    }

    /// Test-only seam for constructing retained decisions directly. Production
    /// callers must enter through [`Self::from_approval`].
    #[cfg(test)]
    pub(crate) fn new(
        authorization_id: NonZeroU64,
        context: CleanManagementDecisionContext,
        request: &ManagementRequest,
    ) -> Result<Self, CleanManagementDecisionError> {
        Self::from_verified_approval_parts(authorization_id, context, request, None)
    }

    /// Bind fields from an already verified, exact authority-actor approval
    /// to the durable signed selector. Keeping this constructor private makes
    /// [`Self::from_approval`] the sole production entry point.
    fn from_verified_approval_parts(
        authorization_id: NonZeroU64,
        context: CleanManagementDecisionContext,
        request: &ManagementRequest,
        application: Option<CleanManagementApplicationContext>,
    ) -> Result<Self, CleanManagementDecisionError> {
        if !request.is_valid() {
            return Err(CleanManagementDecisionError::InvalidRequest);
        }
        match request {
            ManagementRequest::Create(descriptor)
                if descriptor.identity.space != context.space
                    || descriptor.identity.agent != context.agent
                    || descriptor.identity.runtime_deployment != context.runtime_deployment =>
            {
                return Err(CleanManagementDecisionError::InvalidDecision);
            }
            ManagementRequest::UpgradeRuntime(upgrade)
                if upgrade.from_deployment != context.runtime_deployment =>
            {
                return Err(CleanManagementDecisionError::InvalidDecision);
            }
            _ => {}
        }
        let operation = request
            .authority_operation()
            .ok_or(CleanManagementDecisionError::ReadOnlyRequest)?;
        let actor = request.authority_actor();
        let value = Self {
            authorization_id,
            space: context.space,
            agent: context.agent,
            runtime_deployment: context.runtime_deployment,
            operation,
            actor: actor.map(|(actor, _)| actor),
            actor_deployment: actor.map(|(_, deployment)| deployment),
            creation_authority: match request {
                ManagementRequest::Create(descriptor) => Some(descriptor.authority),
                _ => None,
            },
            evidence: context.evidence,
            lane_roots: context.lane_roots,
            epoch: context.epoch,
            valid_from: context.valid_from,
            expires_at: context.expires_at,
            request: request.commitment(),
            application,
        };
        value
            .is_valid()
            .then_some(value)
            .ok_or(CleanManagementDecisionError::InvalidDecision)
    }

    pub const fn authorization_id(&self) -> NonZeroU64 {
        self.authorization_id
    }

    pub const fn space(&self) -> SpaceId {
        self.space
    }

    pub const fn agent(&self) -> AgentId {
        self.agent
    }

    pub const fn operation(&self) -> AuthorityOperationKind {
        self.operation
    }

    pub const fn request(&self) -> Hash {
        self.request
    }

    pub(crate) fn canonical_bytes(&self) -> Vec<u8> {
        encode_authorized_decision(self)
    }

    /// Recover one previously persisted, fully validated decision. This stays
    /// crate-private so decoding durable bootstrap state cannot become a
    /// public authority-minting surface.
    pub(crate) fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        decode_authorized_decision(bytes)
    }

    /// Mint one of the two decisions certified by the independently signed
    /// first-system root bootstrap. The root-certification commitment binds
    /// the complete bootstrap material and remains part of every receipt.
    pub(crate) fn from_root_bootstrap(
        authorization_id: NonZeroU64,
        descriptor: &crate::agent::sdk::AgentDescriptor,
        request: &ManagementRequest,
        root_certification: Hash,
        valid_from: u64,
        expires_at: u64,
    ) -> Result<Self, CleanManagementDecisionError> {
        if root_certification == Hash::ZERO || valid_from > expires_at {
            return Err(CleanManagementDecisionError::InvalidDecision);
        }
        Self::from_verified_approval_parts(
            authorization_id,
            CleanManagementDecisionContext {
                space: descriptor.identity.space,
                agent: descriptor.identity.agent,
                runtime_deployment: descriptor.identity.runtime_deployment,
                evidence: AuthorityEvidence {
                    package: None,
                    proof: None,
                    commitment: root_certification,
                },
                lane_roots: AuthorityLaneRoots::default(),
                epoch: descriptor.authority.initial_epoch,
                valid_from,
                expires_at,
            },
            request,
            None,
        )
    }

    pub(crate) fn matches_creation(&self, descriptor: &crate::agent::sdk::AgentDescriptor) -> bool {
        self.is_valid()
            && self.operation == AuthorityOperationKind::CreateAgent
            && self.space == descriptor.identity.space
            && self.agent == descriptor.identity.agent
            && self.runtime_deployment == descriptor.identity.runtime_deployment
            && self.actor.is_none()
            && self.actor_deployment.is_none()
            && self.application.is_none()
            && self.creation_authority == Some(descriptor.authority)
            && self.request == ManagementRequest::Create(Box::new(descriptor.clone())).commitment()
    }

    pub(crate) fn matches_receipt(
        &self,
        binding: AgentAuthorityBinding,
        receipt: &AuthorityReceipt,
    ) -> bool {
        receipt.selector
            == selector_for(
                &binding,
                self,
                receipt.selector.decision_sequence,
                receipt.selector.acknowledged_through,
            )
    }

    fn is_valid(&self) -> bool {
        self.space != SpaceId::ZERO
            && self.agent != AgentId::ZERO
            && self.runtime_deployment != DeploymentId::ZERO
            && self.operation.uses_management_decision_journal()
            && self.request != Hash::ZERO
            && self.evidence.is_valid()
            && self.lane_roots.is_valid()
            && self.valid_from <= self.expires_at
            && self.application.is_none_or(|application| {
                application.authorization_invocation != InvocationId::ZERO
                    && application.acknowledgement_invocation != InvocationId::ZERO
                    && application.acknowledgement_invocation
                        != application.authorization_invocation
                    && application.authority.is_valid()
                    && application.managed.is_valid()
                    && application.authority.space == self.space
                    && application.managed.space == self.space
                    && application.managed.agent == self.agent
                    && application.managed.runtime_deployment == self.runtime_deployment
                    && application.credential_call != Hash::ZERO
                    && application.approval != Hash::ZERO
            })
            && match (self.operation, self.creation_authority) {
                (AuthorityOperationKind::CreateAgent, Some(binding)) => binding.is_valid(),
                (AuthorityOperationKind::CreateAgent, None) => false,
                (_, None) => true,
                (_, Some(_)) => false,
            }
            && match (
                self.operation.requires_actor(),
                self.actor,
                self.actor_deployment,
            ) {
                (true, Some(actor), Some(deployment)) => {
                    actor != ActorId::ZERO && deployment != DeploymentId::ZERO
                }
                (false, None, None) => true,
                _ => false,
            }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CleanManagementDecisionError {
    InvalidRequest,
    ReadOnlyRequest,
    InvalidDecision,
    InvalidApproval,
}

impl fmt::Display for CleanManagementDecisionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "invalid authorized management decision: {self:?}"
        )
    }
}

impl core::error::Error for CleanManagementDecisionError {}

/// External signer invoked only after the exact selector pledge is durable.
///
/// A callback failure or crash can submit the identical bytes again. Signers
/// must therefore be deterministic/idempotent for an exact message. The
/// issuer never stores a private key and never invokes this callback for an
/// exact retained retry.
pub trait CleanManagementReceiptSigner {
    type Error;

    fn public_key(&self) -> [u8; 32];

    fn sign_authority_receipt(&mut self, message: &[u8]) -> Result<[u8; 64], Self::Error>;

    fn sign_management_application_ack(&mut self, message: &[u8]) -> Result<[u8; 64], Self::Error>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CleanManagementIssuerRejection {
    Poisoned,
    WrongRoute,
    WrongSigner,
    DivergentRetry,
    AuthorizationRegressed,
    EpochRegressed,
    PendingDecision,
    JournalFull,
    SequenceExhausted,
    InvalidObservation,
    ObservationNotLatest,
    ApplicationAckRequired,
    ApplicationFinalizationRequired,
    DivergentApplicationAck,
}

/// Issuance/open/acknowledgement error. `Signer` is uninhabited for methods
/// which never invoke the external signer.
#[derive(Debug)]
pub enum CleanManagementIssuerError<StorageError, SignerError = Infallible> {
    Storage(StorageError),
    Signer(SignerError),
    InvalidState,
    Rejected(CleanManagementIssuerRejection),
}

impl<StorageError: fmt::Display, SignerError: fmt::Display> fmt::Display
    for CleanManagementIssuerError<StorageError, SignerError>
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Storage(error) => write!(formatter, "clean management issuer storage: {error}"),
            Self::Signer(error) => write!(formatter, "clean management issuer signer: {error}"),
            Self::InvalidState => formatter.write_str("invalid clean management issuer state"),
            Self::Rejected(error) => {
                write!(formatter, "clean management issuer rejected: {error:?}")
            }
        }
    }
}

impl<StorageError, SignerError> core::error::Error
    for CleanManagementIssuerError<StorageError, SignerError>
where
    StorageError: core::error::Error + 'static,
    SignerError: core::error::Error + 'static,
{
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct RetainedDecision {
    sequence: u64,
    decision: Vec<u8>,
    receipt: Vec<u8>,
    application_ack: Option<Vec<u8>>,
    application_finalized: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct PendingDecision {
    sequence: u64,
    decision: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PendingApplicationAck {
    sequence: u64,
    acknowledgement_invocation: InvocationId,
    application: Hash,
    reopened_state: Hash,
    applied_at: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct CleanManagementIssuerImage {
    binding: AgentAuthorityBinding,
    space: SpaceId,
    agent: AgentId,
    authorization_high_water: u64,
    decision_sequence_high_water: u64,
    acknowledged_through: u64,
    epoch_high_water: Option<u64>,
    acknowledged: Option<RetainedDecision>,
    retained: Vec<RetainedDecision>,
    pending: Option<PendingDecision>,
    pending_application_ack: Option<PendingApplicationAck>,
}

impl CleanManagementIssuerImage {
    fn empty(binding: AgentAuthorityBinding, space: SpaceId, agent: AgentId) -> Self {
        Self {
            binding,
            space,
            agent,
            authorization_high_water: 0,
            decision_sequence_high_water: 0,
            acknowledged_through: 0,
            epoch_high_water: None,
            acknowledged: None,
            retained: Vec::new(),
            pending: None,
            pending_application_ack: None,
        }
    }

    fn has_valid_envelope(&self) -> bool {
        if !self.binding.is_valid()
            || self.space == SpaceId::ZERO
            || self.agent == AgentId::ZERO
            || self.acknowledged_through > self.decision_sequence_high_water
            || self.retained.len() > MAX_CLEAN_MANAGEMENT_ISSUER_DECISIONS
            || self
                .epoch_high_water
                .is_some_and(|epoch| epoch < self.binding.initial_epoch)
            || (self.acknowledged_through == 0) != self.acknowledged.is_none()
            || (self.pending.is_some() && self.pending_application_ack.is_some())
        {
            return false;
        }
        if self.decision_sequence_high_water == 0 {
            if self.authorization_high_water != 0
                || self.acknowledged_through != 0
                || self.epoch_high_water.is_some()
                || self.acknowledged.is_some()
                || !self.retained.is_empty()
                || self.pending_application_ack.is_some()
            {
                return false;
            }
        } else if self.authorization_high_water == 0 || self.epoch_high_water.is_none() {
            return false;
        }
        let retained_count = self
            .decision_sequence_high_water
            .saturating_sub(self.acknowledged_through);
        if retained_count > MAX_CLEAN_MANAGEMENT_ISSUER_DECISIONS as u64
            || usize::try_from(retained_count).ok() != Some(self.retained.len())
        {
            return false;
        }
        let pending_decision_valid = self.pending.as_ref().is_none_or(|pending| {
            self.retained.len() < MAX_CLEAN_MANAGEMENT_ISSUER_DECISIONS
                && pending.sequence
                    == self
                        .decision_sequence_high_water
                        .checked_add(1)
                        .unwrap_or(0)
                && pending.decision.len() <= MAX_AUTHORIZED_DECISION_BYTES
        });
        let pending_application_valid = self.pending_application_ack.is_none_or(|pending| {
            pending.sequence == self.decision_sequence_high_water
                && pending.sequence > self.acknowledged_through
                && pending.acknowledgement_invocation != InvocationId::ZERO
                && pending.application != Hash::ZERO
                && pending.reopened_state != Hash::ZERO
                && self
                    .retained
                    .last()
                    .is_some_and(|record| record.sequence == pending.sequence)
        });
        pending_decision_valid && pending_application_valid
    }

    fn is_valid(&self) -> bool {
        if !self.has_valid_envelope() {
            return false;
        }

        let mut previous_authorization = None;
        let mut previous_epoch = None;
        let mut unacknowledged_application = false;
        let mut actor_finalization_pending = false;
        if let Some(record) = &self.acknowledged {
            if record.sequence != self.acknowledged_through
                || record.decision.len() > MAX_AUTHORIZED_DECISION_BYTES
                || record.receipt.len() > crate::agent::sdk::wire::MAX_AUTHORITY_RECEIPT_WIRE_BYTES
                || record.application_ack.as_ref().is_some_and(|bytes| {
                    bytes.len() > crate::agent::sdk::wire::MAX_MANAGEMENT_APPLICATION_ACK_WIRE_BYTES
                })
            {
                return false;
            }
            let Ok(decision) = decode_authorized_decision(&record.decision) else {
                return false;
            };
            let Ok(receipt) = AuthorityReceipt::decode(&record.receipt) else {
                return false;
            };
            let embedded_acknowledgement = receipt.selector.acknowledged_through;
            let expected = selector_for(
                &self.binding,
                &decision,
                record.sequence,
                embedded_acknowledgement,
            );
            if decision.space != self.space
                || decision.agent != self.agent
                || decision
                    .creation_authority
                    .is_some_and(|binding| binding != self.binding)
                || decision
                    .application
                    .is_some_and(|application| application.authority.binding != self.binding)
                || receipt.selector != expected
                || !self.binding.accepts(&receipt)
                || receipt.public_key != self.binding.public_key
                || receipt.encode().ok().as_deref() != Some(record.receipt.as_slice())
                || !crate::agent::authority::verify_raw_ed25519(
                    &receipt.public_key,
                    &receipt.signing_bytes(),
                    &receipt.signature,
                )
                || match (
                    &decision.application,
                    &record.application_ack,
                    record.application_finalized,
                ) {
                    (None, None, false) => false,
                    (Some(_), Some(bytes), _) => {
                        let Ok(ack) = ManagementApplicationAck::decode(bytes) else {
                            return false;
                        };
                        ack.encode().ok().as_deref() != Some(bytes.as_slice())
                            || !application_ack_matches_decision(
                                &self.binding,
                                &decision,
                                &receipt,
                                &ack,
                            )
                    }
                    _ => true,
                }
            {
                return false;
            }
            previous_authorization = Some(decision.authorization_id.get());
            previous_epoch = Some(decision.epoch);
            actor_finalization_pending =
                decision.application.is_some() && !record.application_finalized;
        }
        if actor_finalization_pending && (!self.retained.is_empty() || self.pending.is_some()) {
            return false;
        }
        for (index, record) in self.retained.iter().enumerate() {
            // A post-application acknowledgement retires the complete
            // retained prefix. An application-bearing decision must
            // therefore be the final unacknowledged record; otherwise a
            // later receipt could retire it without ever finalizing its
            // authority-actor effect.
            if unacknowledged_application {
                return false;
            }
            let Some(expected_sequence) = self
                .acknowledged_through
                .checked_add(index as u64)
                .and_then(|value| value.checked_add(1))
            else {
                return false;
            };
            if record.sequence != expected_sequence
                || record.decision.len() > MAX_AUTHORIZED_DECISION_BYTES
                || record.receipt.len() > crate::agent::sdk::wire::MAX_AUTHORITY_RECEIPT_WIRE_BYTES
                || record.application_ack.is_some()
                || record.application_finalized
            {
                return false;
            }
            let Ok(decision) = decode_authorized_decision(&record.decision) else {
                return false;
            };
            if decision.space != self.space
                || decision.agent != self.agent
                || decision
                    .creation_authority
                    .is_some_and(|binding| binding != self.binding)
                || decision
                    .application
                    .is_some_and(|application| application.authority.binding != self.binding)
                || previous_authorization
                    .is_some_and(|previous| previous >= decision.authorization_id.get())
                || previous_epoch.is_some_and(|previous| previous > decision.epoch)
            {
                return false;
            }
            let Ok(receipt) = AuthorityReceipt::decode(&record.receipt) else {
                return false;
            };
            let expected = selector_for(
                &self.binding,
                &decision,
                record.sequence,
                self.acknowledged_through,
            );
            if receipt.selector != expected
                || !self.binding.accepts(&receipt)
                || receipt.public_key != self.binding.public_key
                || receipt.encode().ok().as_deref() != Some(record.receipt.as_slice())
                || !crate::agent::authority::verify_raw_ed25519(
                    &receipt.public_key,
                    &receipt.signing_bytes(),
                    &receipt.signature,
                )
            {
                return false;
            }
            previous_authorization = Some(decision.authorization_id.get());
            previous_epoch = Some(decision.epoch);
            unacknowledged_application = decision.application.is_some();
        }
        if let Some(last) = self.retained.last() {
            let Ok(decision) = decode_authorized_decision(&last.decision) else {
                return false;
            };
            if last.sequence != self.decision_sequence_high_water
                || decision.authorization_id.get() != self.authorization_high_water
                || Some(decision.epoch) != self.epoch_high_water
            {
                return false;
            }
        } else if let Some(acknowledged) = &self.acknowledged {
            let Ok(decision) = decode_authorized_decision(&acknowledged.decision) else {
                return false;
            };
            if decision.authorization_id.get() != self.authorization_high_water
                || Some(decision.epoch) != self.epoch_high_water
            {
                return false;
            }
        }

        if self.pending.is_some() && unacknowledged_application {
            return false;
        }
        if let Some(pending) = &self.pending {
            let Ok(decision) = decode_authorized_decision(&pending.decision) else {
                return false;
            };
            if decision.space != self.space
                || decision.agent != self.agent
                || decision
                    .creation_authority
                    .is_some_and(|binding| binding != self.binding)
                || decision
                    .application
                    .is_some_and(|application| application.authority.binding != self.binding)
                || decision.authorization_id.get() <= self.authorization_high_water
                || decision.epoch < self.epoch_high_water.unwrap_or(self.binding.initial_epoch)
                || selector_for(
                    &self.binding,
                    &decision,
                    pending.sequence,
                    self.acknowledged_through,
                )
                .validate()
                .is_err()
            {
                return false;
            }
        }
        if let Some(pending) = self.pending_application_ack {
            let Some(record) = self.retained.last() else {
                return false;
            };
            let Ok(decision) = decode_authorized_decision(&record.decision) else {
                return false;
            };
            let Ok(receipt) = AuthorityReceipt::decode(&record.receipt) else {
                return false;
            };
            let Some(application) = decision.application else {
                return false;
            };
            if application.authority.binding != self.binding
                || pending.acknowledgement_invocation != application.acknowledgement_invocation
                || !receipt.selector.is_live_at(pending.applied_at)
            {
                return false;
            }
        }
        true
    }
}

impl CleanManagementIssuerImage {
    fn encode(&self) -> Vec<u8> {
        let mut output = Vec::new();
        output.extend_from_slice(&CLEAN_MANAGEMENT_ISSUER_MAGIC);
        let mut encoder = Encoder(&mut output);
        encoder.fixed(crate::agent::sdk::RUNTIME_ABI_ID.as_bytes());
        encode_binding(&mut encoder, self.binding);
        encoder.fixed(self.space.as_bytes());
        encoder.fixed(self.agent.as_bytes());
        encoder.u64(self.authorization_high_water);
        encoder.u64(self.decision_sequence_high_water);
        encoder.u64(self.acknowledged_through);
        encoder.option(&self.epoch_high_water, |encoder, epoch| encoder.u64(*epoch));
        encoder.option(&self.acknowledged, encode_retained_decision);
        encoder.list(&self.retained, |encoder, record| {
            encode_retained_decision(encoder, record);
        });
        encoder.option(&self.pending, |encoder, pending| {
            encoder.u64(pending.sequence);
            encoder.bytes(&pending.decision);
        });
        encoder.option(&self.pending_application_ack, |encoder, pending| {
            encoder.u64(pending.sequence);
            encoder.fixed(pending.acknowledgement_invocation.as_bytes());
            encoder.fixed(pending.application.as_bytes());
            encoder.fixed(pending.reopened_state.as_bytes());
            encoder.u64(pending.applied_at);
        });
        output
    }

    fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        if bytes.len() > MAX_CLEAN_MANAGEMENT_ISSUER_IMAGE_BYTES {
            return Err(DecodeError::LimitExceeded);
        }
        let mut decoder = Decoder::new(bytes);
        if decoder.take(CLEAN_MANAGEMENT_ISSUER_MAGIC.len())? != CLEAN_MANAGEMENT_ISSUER_MAGIC {
            return Err(DecodeError::InvalidTag);
        }
        if Hash(decoder.fixed()?) != crate::agent::sdk::RUNTIME_ABI_ID {
            return Err(DecodeError::InvalidPlatform);
        }
        let binding = decode_binding(&mut decoder)?;
        let space = SpaceId(decoder.fixed()?);
        let agent = AgentId(decoder.fixed()?);
        let authorization_high_water = decoder.u64()?;
        let decision_sequence_high_water = decoder.u64()?;
        let acknowledged_through = decoder.u64()?;
        let epoch_high_water = decoder.option(Decoder::u64)?;
        let acknowledged = decoder.option(decode_retained_decision)?;
        let retained_len = decoder.u32()? as usize;
        if retained_len > MAX_CLEAN_MANAGEMENT_ISSUER_DECISIONS {
            return Err(DecodeError::LimitExceeded);
        }
        let mut retained = Vec::new();
        for _ in 0..retained_len {
            let record = decode_retained_decision(&mut decoder)?;
            retained
                .try_reserve(1)
                .map_err(|_| DecodeError::LimitExceeded)?;
            retained.push(record);
        }
        let pending = decoder.option(|decoder| {
            let sequence = decoder.u64()?;
            let decision = decoder.bytes_bounded(MAX_AUTHORIZED_DECISION_BYTES)?;
            Ok(PendingDecision { sequence, decision })
        })?;
        let pending_application_ack = decoder.option(|decoder| {
            Ok(PendingApplicationAck {
                sequence: decoder.u64()?,
                acknowledgement_invocation: InvocationId(decoder.fixed()?),
                application: Hash(decoder.fixed()?),
                reopened_state: Hash(decoder.fixed()?),
                applied_at: decoder.u64()?,
            })
        })?;
        let value = Self {
            binding,
            space,
            agent,
            authorization_high_water,
            decision_sequence_high_water,
            acknowledged_through,
            epoch_high_water,
            acknowledged,
            retained,
            pending,
            pending_application_ack,
        };
        if !decoder.exhausted() || !value.is_valid() {
            return Err(DecodeError::NonCanonical);
        }
        Ok(value)
    }
}

/// Durable, host-independent clean management receipt issuer.
///
/// One backend image belongs to exactly one `(authority binding, space,
/// agent)` route. Any storage commit error is an ambiguous durability
/// boundary and poisons the live handle; callers must reopen it before doing
/// more work.
pub struct DurableCleanManagementIssuer<B: CleanManagementIssuerStore> {
    store: B,
    image: CleanManagementIssuerImage,
    poisoned: bool,
}

impl<B: CleanManagementIssuerStore> DurableCleanManagementIssuer<B> {
    pub fn open(
        mut store: B,
        binding: AgentAuthorityBinding,
        space: SpaceId,
        agent: AgentId,
    ) -> Result<Self, CleanManagementIssuerError<B::Error>> {
        if !binding.is_valid() || space == SpaceId::ZERO || agent == AgentId::ZERO {
            return Err(CleanManagementIssuerError::InvalidState);
        }
        let image = match store.load().map_err(CleanManagementIssuerError::Storage)? {
            Some(bytes) => {
                if bytes.len() > MAX_CLEAN_MANAGEMENT_ISSUER_IMAGE_BYTES {
                    return Err(CleanManagementIssuerError::InvalidState);
                }
                let decoded = CleanManagementIssuerImage::decode(&bytes)
                    .map_err(|_| CleanManagementIssuerError::InvalidState)?;
                if decoded.encode() != bytes
                    || decoded.binding != binding
                    || decoded.space != space
                    || decoded.agent != agent
                {
                    return Err(CleanManagementIssuerError::InvalidState);
                }
                decoded
            }
            None => CleanManagementIssuerImage::empty(binding, space, agent),
        };
        Ok(Self {
            store,
            image,
            poisoned: false,
        })
    }

    pub const fn sequence_high_water(&self) -> u64 {
        self.image.decision_sequence_high_water
    }

    pub const fn acknowledged_through(&self) -> u64 {
        self.image.acknowledged_through
    }

    pub fn retained_decisions(&self) -> usize {
        self.image.retained.len()
    }

    pub const fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    pub const fn has_pending_decision(&self) -> bool {
        self.image.pending.is_some()
    }

    pub fn into_store(self) -> B {
        self.store
    }

    /// Allocate, pledge, sign, and retain one exact authorized decision.
    /// Exact retained retries return before inspecting or invoking `signer`.
    pub(crate) fn issue<S: CleanManagementReceiptSigner>(
        &mut self,
        decision: &AuthorizedCleanManagementDecision,
        signer: &mut S,
    ) -> Result<AuthorityReceipt, CleanManagementIssuerError<B::Error, S::Error>> {
        self.ensure_live()?;
        if !decision.is_valid()
            || decision.space != self.image.space
            || decision.agent != self.image.agent
            || decision
                .creation_authority
                .is_some_and(|binding| binding != self.image.binding)
            || decision
                .application
                .is_some_and(|application| application.authority.binding != self.image.binding)
        {
            return Err(CleanManagementIssuerError::Rejected(
                CleanManagementIssuerRejection::WrongRoute,
            ));
        }
        let decision_bytes = encode_authorized_decision(decision);
        if decision_bytes.len() > MAX_AUTHORIZED_DECISION_BYTES {
            return Err(CleanManagementIssuerError::InvalidState);
        }

        if let Some(retained) = self
            .image
            .acknowledged
            .iter()
            .chain(self.image.retained.iter())
            .find(|retained| {
                decode_authorized_decision(&retained.decision)
                    .is_ok_and(|existing| existing.authorization_id == decision.authorization_id)
            })
        {
            if retained.decision != decision_bytes {
                return Err(CleanManagementIssuerError::Rejected(
                    CleanManagementIssuerRejection::DivergentRetry,
                ));
            }
            return AuthorityReceipt::decode(&retained.receipt)
                .map_err(|_| CleanManagementIssuerError::InvalidState);
        }
        if self
            .image
            .acknowledged
            .as_ref()
            .is_some_and(|record| record.application_ack.is_some() && !record.application_finalized)
        {
            return Err(CleanManagementIssuerError::Rejected(
                CleanManagementIssuerRejection::ApplicationFinalizationRequired,
            ));
        }
        if self.image.pending_application_ack.is_some() {
            return Err(CleanManagementIssuerError::Rejected(
                CleanManagementIssuerRejection::ApplicationAckRequired,
            ));
        }
        if self.image.retained.iter().any(|record| {
            decode_authorized_decision(&record.decision)
                .map(|decision| decision.application.is_some())
                .unwrap_or(true)
        }) {
            return Err(CleanManagementIssuerError::Rejected(
                CleanManagementIssuerRejection::ApplicationAckRequired,
            ));
        }
        if decision.authorization_id.get() <= self.image.authorization_high_water {
            return Err(CleanManagementIssuerError::Rejected(
                CleanManagementIssuerRejection::AuthorizationRegressed,
            ));
        }

        let pending = match self.image.pending.clone() {
            Some(pending) => {
                let existing = decode_authorized_decision(&pending.decision)
                    .map_err(|_| CleanManagementIssuerError::InvalidState)?;
                if existing.authorization_id != decision.authorization_id {
                    return Err(CleanManagementIssuerError::Rejected(
                        CleanManagementIssuerRejection::PendingDecision,
                    ));
                }
                if pending.decision != decision_bytes {
                    return Err(CleanManagementIssuerError::Rejected(
                        CleanManagementIssuerRejection::DivergentRetry,
                    ));
                }
                pending
            }
            None => {
                if signer.public_key() != self.image.binding.public_key {
                    return Err(CleanManagementIssuerError::Rejected(
                        CleanManagementIssuerRejection::WrongSigner,
                    ));
                }
                if decision.epoch
                    < self
                        .image
                        .epoch_high_water
                        .unwrap_or(self.image.binding.initial_epoch)
                {
                    return Err(CleanManagementIssuerError::Rejected(
                        CleanManagementIssuerRejection::EpochRegressed,
                    ));
                }
                if self.image.retained.len() == MAX_CLEAN_MANAGEMENT_ISSUER_DECISIONS {
                    return Err(CleanManagementIssuerError::Rejected(
                        CleanManagementIssuerRejection::JournalFull,
                    ));
                }
                let sequence = self
                    .image
                    .decision_sequence_high_water
                    .checked_add(1)
                    .ok_or(CleanManagementIssuerError::Rejected(
                        CleanManagementIssuerRejection::SequenceExhausted,
                    ))?;
                let selector = selector_for(
                    &self.image.binding,
                    decision,
                    sequence,
                    self.image.acknowledged_through,
                );
                if selector.validate().is_err() {
                    return Err(CleanManagementIssuerError::Rejected(
                        CleanManagementIssuerRejection::WrongRoute,
                    ));
                }
                let pending = PendingDecision {
                    sequence,
                    decision: decision_bytes.clone(),
                };
                let mut pledged = self.image.clone();
                pledged.pending = Some(pending.clone());
                self.commit_candidate::<S::Error>(pledged)?;
                pending
            }
        };

        if signer.public_key() != self.image.binding.public_key {
            return Err(CleanManagementIssuerError::Rejected(
                CleanManagementIssuerRejection::WrongSigner,
            ));
        }
        let selector = selector_for(
            &self.image.binding,
            decision,
            pending.sequence,
            self.image.acknowledged_through,
        );
        let mut receipt = AuthorityReceipt {
            selector,
            public_key: self.image.binding.public_key,
            signature: [0; 64],
        };
        let message = receipt.signing_bytes();
        receipt.signature = signer
            .sign_authority_receipt(&message)
            .map_err(CleanManagementIssuerError::Signer)?;
        if receipt.validate_shape().is_err()
            || !crate::agent::authority::verify_raw_ed25519(
                &receipt.public_key,
                &message,
                &receipt.signature,
            )
        {
            return Err(CleanManagementIssuerError::Rejected(
                CleanManagementIssuerRejection::WrongSigner,
            ));
        }
        let receipt_bytes = receipt
            .encode()
            .map_err(|_| CleanManagementIssuerError::InvalidState)?;
        let mut completed = self.image.clone();
        completed.pending = None;
        completed.authorization_high_water = decision.authorization_id.get();
        completed.decision_sequence_high_water = pending.sequence;
        completed.epoch_high_water = Some(decision.epoch);
        completed.retained.push(RetainedDecision {
            sequence: pending.sequence,
            decision: decision_bytes,
            receipt: receipt_bytes,
            application_ack: None,
            application_finalized: false,
        });
        self.commit_candidate::<S::Error>(completed)?;
        Ok(receipt)
    }

    /// Pledge and sign an acknowledgement only after the caller has reopened
    /// the exact durable managed-Agent result. The pledge is committed before
    /// invoking the signer, so a crash or signer failure can only retry the
    /// same acknowledgement bytes. A completed exact retry returns the stored
    /// acknowledgement without inspecting or invoking `signer`.
    pub(crate) fn observe_durable_application<S: CleanManagementReceiptSigner>(
        &mut self,
        receipt: &AuthorityReceipt,
        application: &ManagementReply,
        reopened_state: Hash,
        applied_at: u64,
        signer: &mut S,
    ) -> Result<ManagementApplicationAck, CleanManagementIssuerError<B::Error, S::Error>> {
        self.ensure_live()?;
        if self.image.pending.is_some() {
            return Err(CleanManagementIssuerError::Rejected(
                CleanManagementIssuerRejection::PendingDecision,
            ));
        }
        let receipt_bytes = receipt.encode().map_err(|_| {
            CleanManagementIssuerError::Rejected(CleanManagementIssuerRejection::InvalidObservation)
        })?;
        if !self.image.binding.accepts(receipt)
            || receipt.selector.space != self.image.space
            || receipt.selector.agent != self.image.agent
            || !receipt
                .selector
                .operation
                .uses_management_decision_journal()
            || !crate::agent::authority::verify_raw_ed25519(
                &receipt.public_key,
                &receipt.signing_bytes(),
                &receipt.signature,
            )
        {
            return Err(CleanManagementIssuerError::Rejected(
                CleanManagementIssuerRejection::InvalidObservation,
            ));
        }

        let sequence = receipt.selector.decision_sequence;
        if sequence <= self.image.acknowledged_through {
            let Some(record) =
                self.image.acknowledged.as_ref().filter(|record| {
                    record.sequence == sequence && record.receipt == receipt_bytes
                })
            else {
                return Err(CleanManagementIssuerError::Rejected(
                    CleanManagementIssuerRejection::InvalidObservation,
                ));
            };
            let decision = decode_authorized_decision(&record.decision)
                .map_err(|_| CleanManagementIssuerError::InvalidState)?;
            let acknowledgement = record
                .application_ack
                .as_ref()
                .ok_or(CleanManagementIssuerError::InvalidState)
                .and_then(|bytes| {
                    ManagementApplicationAck::decode(bytes)
                        .map_err(|_| CleanManagementIssuerError::InvalidState)
                })?;
            if acknowledgement.reopened_state != reopened_state
                || acknowledgement.applied_at != applied_at
                || acknowledgement.application != *application
                || !application_ack_matches_decision(
                    &self.image.binding,
                    &decision,
                    receipt,
                    &acknowledgement,
                )
            {
                return Err(CleanManagementIssuerError::Rejected(
                    CleanManagementIssuerRejection::DivergentApplicationAck,
                ));
            }
            return Ok(acknowledgement);
        }
        if sequence != self.image.decision_sequence_high_water {
            return Err(CleanManagementIssuerError::Rejected(
                CleanManagementIssuerRejection::ObservationNotLatest,
            ));
        }
        let Some(record) = self
            .image
            .retained
            .last()
            .filter(|record| record.sequence == sequence && record.receipt == receipt_bytes)
            .cloned()
        else {
            return Err(CleanManagementIssuerError::Rejected(
                CleanManagementIssuerRejection::InvalidObservation,
            ));
        };
        let decision = decode_authorized_decision(&record.decision)
            .map_err(|_| CleanManagementIssuerError::InvalidState)?;
        let Some(application_route) = decision.application else {
            return Err(CleanManagementIssuerError::Rejected(
                CleanManagementIssuerRejection::ApplicationAckRequired,
            ));
        };
        let requested = PendingApplicationAck {
            sequence,
            acknowledgement_invocation: application_route.acknowledgement_invocation,
            application: management_reply_commitment(application),
            reopened_state,
            applied_at,
        };
        if application_route.acknowledgement_invocation == InvocationId::ZERO
            || application_route.acknowledgement_invocation
                == application_route.authorization_invocation
            || reopened_state == Hash::ZERO
            || !receipt.selector.is_live_at(applied_at)
        {
            return Err(CleanManagementIssuerError::Rejected(
                CleanManagementIssuerRejection::InvalidObservation,
            ));
        }
        // A caller without the independently loaded signing capability must
        // not be able to durably pledge arbitrary application parameters and
        // freeze this issuer route. This check is non-mutating; the actual
        // signature remains strictly after the pledge.
        if signer.public_key() != self.image.binding.public_key {
            return Err(CleanManagementIssuerError::Rejected(
                CleanManagementIssuerRejection::WrongSigner,
            ));
        }
        match self.image.pending_application_ack {
            Some(existing) if existing != requested => {
                return Err(CleanManagementIssuerError::Rejected(
                    CleanManagementIssuerRejection::DivergentApplicationAck,
                ));
            }
            Some(_) => {}
            None => {
                let mut pledged = self.image.clone();
                pledged.pending_application_ack = Some(requested);
                self.commit_candidate::<S::Error>(pledged)?;
            }
        }
        let mut acknowledgement =
            application_ack_for(&decision, receipt, application.clone(), requested, [0; 64])
                .ok_or(CleanManagementIssuerError::InvalidState)?;
        let message = acknowledgement.signing_bytes();
        acknowledgement.signature = signer
            .sign_management_application_ack(&message)
            .map_err(CleanManagementIssuerError::Signer)?;
        if !application_ack_matches_decision(
            &self.image.binding,
            &decision,
            receipt,
            &acknowledgement,
        ) {
            return Err(CleanManagementIssuerError::Rejected(
                CleanManagementIssuerRejection::WrongSigner,
            ));
        }
        let acknowledgement_bytes = acknowledgement
            .encode()
            .map_err(|_| CleanManagementIssuerError::InvalidState)?;
        let mut completed = self.image.clone();
        completed.acknowledged_through = sequence;
        let mut acknowledged = record;
        acknowledged.application_ack = Some(acknowledgement_bytes);
        completed.acknowledged = Some(acknowledged);
        completed.retained.clear();
        completed.pending_application_ack = None;
        self.commit_candidate::<S::Error>(completed)?;
        Ok(acknowledgement)
    }

    /// Recover a previously pledged or signed application acknowledgement
    /// using its original durable state/slot, never a caller's newer image.
    /// None means this exact issued receipt has no application pledge yet.
    pub(crate) fn recover_application_ack<S: CleanManagementReceiptSigner>(
        &mut self,
        receipt: &AuthorityReceipt,
        application: &ManagementReply,
        signer: &mut S,
    ) -> Result<Option<ManagementApplicationAck>, CleanManagementIssuerError<B::Error, S::Error>>
    {
        self.ensure_live()?;
        let receipt_bytes = receipt.encode().map_err(|_| {
            CleanManagementIssuerError::Rejected(CleanManagementIssuerRejection::InvalidObservation)
        })?;
        let record = self
            .image
            .acknowledged
            .iter()
            .chain(self.image.retained.iter())
            .find(|record| {
                record.sequence == receipt.selector.decision_sequence
                    && record.receipt == receipt_bytes
            })
            .ok_or(CleanManagementIssuerError::Rejected(
                CleanManagementIssuerRejection::InvalidObservation,
            ))?;
        let original = if let Some(bytes) = &record.application_ack {
            let acknowledgement = ManagementApplicationAck::decode(bytes)
                .map_err(|_| CleanManagementIssuerError::InvalidState)?;
            Some((acknowledgement.reopened_state, acknowledgement.applied_at))
        } else if let Some(pending) = self.image.pending_application_ack {
            if pending.sequence != record.sequence {
                return Err(CleanManagementIssuerError::Rejected(
                    CleanManagementIssuerRejection::DivergentApplicationAck,
                ));
            }
            Some((pending.reopened_state, pending.applied_at))
        } else {
            None
        };
        original
            .map(|(state, slot)| {
                self.observe_durable_application(receipt, application, state, slot, signer)
            })
            .transpose()
    }

    /// Local callers cannot substitute an in-memory result for the physical
    /// host's exact durable observation. Denials are never signed as applied.
    pub(crate) fn observe_local_application<S: CleanManagementReceiptSigner>(
        &mut self,
        observation: &super::local_sdk_host::LocalManagementObservation,
        signer: &mut S,
    ) -> Result<ManagementApplicationAck, CleanManagementIssuerError<B::Error, S::Error>> {
        let application = observation.result().as_ref().map_err(|_| {
            CleanManagementIssuerError::Rejected(CleanManagementIssuerRejection::InvalidObservation)
        })?;
        if let Some(acknowledgement) =
            self.recover_application_ack(observation.receipt(), application, signer)?
        {
            return Ok(acknowledgement);
        }
        self.observe_durable_application(
            observation.receipt(),
            application,
            observation.reopened_state(),
            observation.applied_at(),
            signer,
        )
    }

    /// Retire the issuer-side two-phase barrier only after the authority
    /// actor has durably consumed the exact stored acknowledgement. A crash
    /// before this marker is committed is recovered by replaying the same
    /// MAA2 to the actor; its Linear exact-retry record makes that replay
    /// idempotent. No later decision may be issued while this barrier is set.
    ///
    /// This method is crate-private because a relay observing an in-memory
    /// `true` result is not sufficient. The owning coordinator may call it
    /// only after reopening the exact authority-actor transition.
    pub(crate) fn observe_durable_actor_finalization(
        &mut self,
        acknowledgement: &ManagementApplicationAck,
    ) -> Result<bool, CleanManagementIssuerError<B::Error>> {
        self.ensure_live()?;
        if self.image.pending.is_some() || self.image.pending_application_ack.is_some() {
            return Err(CleanManagementIssuerError::InvalidState);
        }
        let acknowledgement_bytes = acknowledgement.encode().map_err(|_| {
            CleanManagementIssuerError::Rejected(CleanManagementIssuerRejection::InvalidObservation)
        })?;
        let Some(record) = self.image.acknowledged.as_ref() else {
            return Err(CleanManagementIssuerError::Rejected(
                CleanManagementIssuerRejection::InvalidObservation,
            ));
        };
        if record.sequence != self.image.acknowledged_through
            || record.application_ack.as_deref() != Some(acknowledgement_bytes.as_slice())
        {
            return Err(CleanManagementIssuerError::Rejected(
                CleanManagementIssuerRejection::DivergentApplicationAck,
            ));
        }
        let decision = decode_authorized_decision(&record.decision)
            .map_err(|_| CleanManagementIssuerError::InvalidState)?;
        let receipt = AuthorityReceipt::decode(&record.receipt)
            .map_err(|_| CleanManagementIssuerError::InvalidState)?;
        if !application_ack_matches_decision(
            &self.image.binding,
            &decision,
            &receipt,
            acknowledgement,
        ) {
            return Err(CleanManagementIssuerError::Rejected(
                CleanManagementIssuerRejection::InvalidObservation,
            ));
        }
        if record.application_finalized {
            return Ok(false);
        }

        let mut completed = self.image.clone();
        completed
            .acknowledged
            .as_mut()
            .ok_or(CleanManagementIssuerError::InvalidState)?
            .application_finalized = true;
        self.commit_candidate::<Infallible>(completed)?;
        Ok(true)
    }

    /// Persist an Agent-owned proof boundary that the exact latest issued
    /// receipt and its resulting state are durably recoverable, then retire
    /// the complete acknowledged prefix. This method is crate-private on
    /// purpose: an authority client must not advance the watermark merely
    /// because it observed a successful in-memory result. The owning Agent
    /// coordinator may call it only after reopening or committing the exact
    /// resulting Agent image. Restricting observation to the latest receipt
    /// also prevents an acknowledgement from invalidating later outstanding
    /// receipts whose signed watermark is older.
    pub(crate) fn observe_durable(
        &mut self,
        receipt: &AuthorityReceipt,
    ) -> Result<bool, CleanManagementIssuerError<B::Error>> {
        self.ensure_live()?;
        if self.image.pending.is_some() {
            return Err(CleanManagementIssuerError::Rejected(
                CleanManagementIssuerRejection::PendingDecision,
            ));
        }
        if self.image.pending_application_ack.is_some() {
            return Err(CleanManagementIssuerError::Rejected(
                CleanManagementIssuerRejection::ApplicationAckRequired,
            ));
        }
        if self
            .image
            .acknowledged
            .as_ref()
            .is_some_and(|record| record.application_ack.is_some() && !record.application_finalized)
        {
            return Err(CleanManagementIssuerError::Rejected(
                CleanManagementIssuerRejection::ApplicationFinalizationRequired,
            ));
        }
        let receipt_bytes = receipt.encode().map_err(|_| {
            CleanManagementIssuerError::Rejected(CleanManagementIssuerRejection::InvalidObservation)
        })?;
        if !self.image.binding.accepts(receipt)
            || receipt.selector.space != self.image.space
            || receipt.selector.agent != self.image.agent
            || !receipt
                .selector
                .operation
                .uses_management_decision_journal()
            || !crate::agent::authority::verify_raw_ed25519(
                &receipt.public_key,
                &receipt.signing_bytes(),
                &receipt.signature,
            )
        {
            return Err(CleanManagementIssuerError::Rejected(
                CleanManagementIssuerRejection::InvalidObservation,
            ));
        }
        let sequence = receipt.selector.decision_sequence;
        if sequence <= self.image.acknowledged_through {
            return Ok(false);
        }
        if sequence != self.image.decision_sequence_high_water {
            return Err(CleanManagementIssuerError::Rejected(
                CleanManagementIssuerRejection::ObservationNotLatest,
            ));
        }
        let exact_latest = self.image.retained.last().is_some_and(|retained| {
            retained.sequence == sequence && retained.receipt == receipt_bytes
        });
        if !exact_latest {
            return Err(CleanManagementIssuerError::Rejected(
                CleanManagementIssuerRejection::InvalidObservation,
            ));
        }
        let decision = decode_authorized_decision(
            &self
                .image
                .retained
                .last()
                .ok_or(CleanManagementIssuerError::InvalidState)?
                .decision,
        )
        .map_err(|_| CleanManagementIssuerError::InvalidState)?;
        if decision.application.is_some() {
            return Err(CleanManagementIssuerError::Rejected(
                CleanManagementIssuerRejection::ApplicationAckRequired,
            ));
        }
        let mut acknowledged = self.image.clone();
        acknowledged.acknowledged_through = sequence;
        acknowledged.acknowledged = acknowledged.retained.last().cloned();
        acknowledged.retained.clear();
        self.commit_candidate::<Infallible>(acknowledged)?;
        Ok(true)
    }

    fn ensure_live<SignerError>(
        &self,
    ) -> Result<(), CleanManagementIssuerError<B::Error, SignerError>> {
        if self.poisoned {
            Err(CleanManagementIssuerError::Rejected(
                CleanManagementIssuerRejection::Poisoned,
            ))
        } else {
            Ok(())
        }
    }

    fn commit_candidate<SignerError>(
        &mut self,
        candidate: CleanManagementIssuerImage,
    ) -> Result<(), CleanManagementIssuerError<B::Error, SignerError>> {
        // The current image was fully audited at open. Each caller constructs
        // only one of the three narrow transitions above and validates its
        // new decision/receipt before reaching this boundary. Rechecking all
        // retained Ed25519 signatures here would turn issuance into O(n^2);
        // keep this commit guard structural and perform the full audit once
        // on every restart.
        if !candidate.has_valid_envelope() {
            self.poisoned = true;
            return Err(CleanManagementIssuerError::InvalidState);
        }
        let bytes = candidate.encode();
        if bytes.len() > MAX_CLEAN_MANAGEMENT_ISSUER_IMAGE_BYTES {
            self.poisoned = true;
            return Err(CleanManagementIssuerError::InvalidState);
        }
        if let Err(error) = self.store.commit(&bytes) {
            self.poisoned = true;
            return Err(CleanManagementIssuerError::Storage(error));
        }
        self.image = candidate;
        Ok(())
    }
}

fn selector_for(
    binding: &AgentAuthorityBinding,
    decision: &AuthorizedCleanManagementDecision,
    sequence: u64,
    acknowledged_through: u64,
) -> AuthorityReceiptSelector {
    AuthorityReceiptSelector {
        policy: binding.policy,
        issuer: binding.issuer,
        space: decision.space,
        agent: decision.agent,
        operation: decision.operation,
        runtime_deployment: decision.runtime_deployment,
        actor: decision.actor,
        actor_deployment: decision.actor_deployment,
        evidence: decision.evidence.clone(),
        lane_roots: decision.lane_roots,
        epoch: decision.epoch,
        decision_sequence: sequence,
        acknowledged_through,
        valid_from: decision.valid_from,
        expires_at: decision.expires_at,
        request: decision.request,
    }
}

fn application_ack_for(
    decision: &AuthorizedCleanManagementDecision,
    receipt: &AuthorityReceipt,
    applied: ManagementReply,
    pending: PendingApplicationAck,
    signature: [u8; 64],
) -> Option<ManagementApplicationAck> {
    let application = decision.application?;
    if pending.acknowledgement_invocation != application.acknowledgement_invocation
        || pending.application != management_reply_commitment(&applied)
    {
        return None;
    }
    Some(ManagementApplicationAck {
        authorization_invocation: application.authorization_invocation,
        acknowledgement_invocation: application.acknowledgement_invocation,
        authority: application.authority,
        managed: application.managed,
        credential_call: application.credential_call,
        approval: application.approval,
        authorization_sequence: decision.authorization_id,
        request: decision.request,
        receipt: receipt.clone(),
        application: applied,
        reopened_state: pending.reopened_state,
        applied_at: pending.applied_at,
        signature,
    })
}

fn application_ack_matches_decision(
    binding: &AgentAuthorityBinding,
    decision: &AuthorizedCleanManagementDecision,
    receipt: &AuthorityReceipt,
    acknowledgement: &ManagementApplicationAck,
) -> bool {
    let Some(application) = decision.application else {
        return false;
    };
    acknowledgement.validate_shape().is_ok()
        && acknowledgement.authority.binding == *binding
        && acknowledgement.authorization_invocation == application.authorization_invocation
        && acknowledgement.acknowledgement_invocation == application.acknowledgement_invocation
        && acknowledgement.authority == application.authority
        && acknowledgement.managed == application.managed
        && acknowledgement.credential_call == application.credential_call
        && acknowledgement.approval == application.approval
        && acknowledgement.authorization_sequence == decision.authorization_id
        && acknowledgement.request == decision.request
        && acknowledgement.receipt == *receipt
        && crate::agent::authority::verify_raw_ed25519(
            &binding.public_key,
            &acknowledgement.signing_bytes(),
            &acknowledgement.signature,
        )
}

fn encode_retained_decision(encoder: &mut Encoder<'_>, record: &RetainedDecision) {
    encoder.u64(record.sequence);
    encoder.bytes(&record.decision);
    encoder.bytes(&record.receipt);
    encoder.option(&record.application_ack, |encoder, bytes| {
        encoder.bytes(bytes)
    });
    encoder.bool(record.application_finalized);
}

fn decode_retained_decision(decoder: &mut Decoder<'_>) -> Result<RetainedDecision, DecodeError> {
    let sequence = decoder.u64()?;
    let decision = decoder.bytes_bounded(MAX_AUTHORIZED_DECISION_BYTES)?;
    let receipt =
        decoder.bytes_bounded(crate::agent::sdk::wire::MAX_AUTHORITY_RECEIPT_WIRE_BYTES)?;
    let application_ack = decoder.option(|decoder| {
        decoder.bytes_bounded(crate::agent::sdk::wire::MAX_MANAGEMENT_APPLICATION_ACK_WIRE_BYTES)
    })?;
    let application_finalized = decoder.bool()?;
    Ok(RetainedDecision {
        sequence,
        decision,
        receipt,
        application_ack,
        application_finalized,
    })
}

fn encode_authorized_decision(value: &AuthorizedCleanManagementDecision) -> Vec<u8> {
    let mut bytes = Vec::new();
    let mut encoder = Encoder(&mut bytes);
    encoder.u8(2);
    encoder.u64(value.authorization_id.get());
    encoder.fixed(value.space.as_bytes());
    encoder.fixed(value.agent.as_bytes());
    encoder.fixed(value.runtime_deployment.as_bytes());
    encoder.u8(value.operation as u8);
    encode_optional_id(&mut encoder, value.actor.map(|value| value.0));
    encode_optional_id(&mut encoder, value.actor_deployment.map(|value| value.0));
    encoder.option(&value.creation_authority, |encoder, binding| {
        encode_binding(encoder, *binding)
    });
    encode_optional_blob(&mut encoder, &value.evidence.package);
    encode_optional_blob(&mut encoder, &value.evidence.proof);
    encoder.fixed(value.evidence.commitment.as_bytes());
    encode_lane_roots(&mut encoder, value.lane_roots);
    encoder.u64(value.epoch);
    encoder.u64(value.valid_from);
    encoder.u64(value.expires_at);
    encoder.fixed(value.request.as_bytes());
    encoder.option(&value.application, |encoder, application| {
        encoder.fixed(application.authorization_invocation.as_bytes());
        encoder.fixed(application.acknowledgement_invocation.as_bytes());
        encode_authority_actor_target(encoder, application.authority);
        encode_managed_agent_target(encoder, application.managed);
        encoder.fixed(application.credential_call.as_bytes());
        encoder.fixed(application.approval.as_bytes());
    });
    bytes
}

fn decode_authorized_decision(
    bytes: &[u8],
) -> Result<AuthorizedCleanManagementDecision, DecodeError> {
    if bytes.len() > MAX_AUTHORIZED_DECISION_BYTES {
        return Err(DecodeError::LimitExceeded);
    }
    let mut decoder = Decoder::new(bytes);
    if decoder.u8()? != 2 {
        return Err(DecodeError::InvalidTag);
    }
    let authorization_id = NonZeroU64::new(decoder.u64()?).ok_or(DecodeError::NonCanonical)?;
    let value = AuthorizedCleanManagementDecision {
        authorization_id,
        space: SpaceId(decoder.fixed()?),
        agent: AgentId(decoder.fixed()?),
        runtime_deployment: DeploymentId(decoder.fixed()?),
        operation: decode_management_operation(decoder.u8()?)?,
        actor: decode_optional_id(&mut decoder)?.map(ActorId),
        actor_deployment: decode_optional_id(&mut decoder)?.map(DeploymentId),
        creation_authority: decoder.option(decode_binding)?,
        evidence: AuthorityEvidence {
            package: decode_optional_blob(&mut decoder)?,
            proof: decode_optional_blob(&mut decoder)?,
            commitment: Hash(decoder.fixed()?),
        },
        lane_roots: decode_lane_roots(&mut decoder)?,
        epoch: decoder.u64()?,
        valid_from: decoder.u64()?,
        expires_at: decoder.u64()?,
        request: Hash(decoder.fixed()?),
        application: decoder.option(|decoder| {
            Ok(CleanManagementApplicationContext {
                authorization_invocation: InvocationId(decoder.fixed()?),
                acknowledgement_invocation: InvocationId(decoder.fixed()?),
                authority: decode_authority_actor_target(decoder)?,
                managed: decode_managed_agent_target(decoder)?,
                credential_call: Hash(decoder.fixed()?),
                approval: Hash(decoder.fixed()?),
            })
        })?,
    };
    if !decoder.exhausted() || !value.is_valid() || encode_authorized_decision(&value) != bytes {
        return Err(DecodeError::NonCanonical);
    }
    Ok(value)
}

fn encode_binding(encoder: &mut Encoder<'_>, binding: AgentAuthorityBinding) {
    encoder.fixed(binding.policy.as_bytes());
    encode_issuer(encoder, binding.issuer);
    encoder.fixed(&binding.public_key);
    encoder.u64(binding.initial_epoch);
}

fn encode_authority_actor_target(encoder: &mut Encoder<'_>, target: AuthorityActorTarget) {
    encoder.fixed(target.space.as_bytes());
    encoder.fixed(target.system_agent.as_bytes());
    encoder.fixed(target.system_runtime_deployment.as_bytes());
    encode_binding(encoder, target.binding);
}

fn decode_authority_actor_target(
    decoder: &mut Decoder<'_>,
) -> Result<AuthorityActorTarget, DecodeError> {
    let value = AuthorityActorTarget {
        space: SpaceId(decoder.fixed()?),
        system_agent: AgentId(decoder.fixed()?),
        system_runtime_deployment: DeploymentId(decoder.fixed()?),
        binding: decode_binding(decoder)?,
    };
    value
        .is_valid()
        .then_some(value)
        .ok_or(DecodeError::NonCanonical)
}

fn encode_managed_agent_target(encoder: &mut Encoder<'_>, target: ManagedAgentTarget) {
    encoder.fixed(target.space.as_bytes());
    encoder.fixed(target.agent.as_bytes());
    encoder.fixed(target.owner.as_bytes());
    encoder.u8(target.profile as u8);
    encoder.fixed(target.runtime_deployment.as_bytes());
    encoder.fixed(target.transition_producer.as_bytes());
}

fn decode_managed_agent_target(
    decoder: &mut Decoder<'_>,
) -> Result<ManagedAgentTarget, DecodeError> {
    let value = ManagedAgentTarget {
        space: SpaceId(decoder.fixed()?),
        agent: AgentId(decoder.fixed()?),
        owner: PrincipalId(decoder.fixed()?),
        profile: match decoder.u8()? {
            0 => AgentProfile::Local,
            1 => AgentProfile::Shared,
            2 => AgentProfile::Private,
            _ => return Err(DecodeError::InvalidTag),
        },
        runtime_deployment: DeploymentId(decoder.fixed()?),
        transition_producer: ProducerId(decoder.fixed()?),
    };
    value
        .is_valid()
        .then_some(value)
        .ok_or(DecodeError::NonCanonical)
}

fn decode_binding(decoder: &mut Decoder<'_>) -> Result<AgentAuthorityBinding, DecodeError> {
    let value = AgentAuthorityBinding {
        policy: Hash(decoder.fixed()?),
        issuer: decode_issuer(decoder)?,
        public_key: decoder.fixed()?,
        initial_epoch: decoder.u64()?,
    };
    value
        .is_valid()
        .then_some(value)
        .ok_or(DecodeError::NonCanonical)
}

fn encode_issuer(encoder: &mut Encoder<'_>, issuer: AuthorityIssuer) {
    encoder.fixed(issuer.principal.as_bytes());
    encoder.fixed(issuer.actor.as_bytes());
    encoder.fixed(issuer.deployment.as_bytes());
    encoder.fixed(issuer.program.as_bytes());
    encoder.fixed(issuer.producer.as_bytes());
}

fn decode_issuer(decoder: &mut Decoder<'_>) -> Result<AuthorityIssuer, DecodeError> {
    let value = AuthorityIssuer {
        principal: PrincipalId(decoder.fixed()?),
        actor: ActorId(decoder.fixed()?),
        deployment: DeploymentId(decoder.fixed()?),
        program: ProgramId(decoder.fixed()?),
        producer: ProducerId(decoder.fixed()?),
    };
    value
        .is_valid()
        .then_some(value)
        .ok_or(DecodeError::NonCanonical)
}

fn encode_optional_id(encoder: &mut Encoder<'_>, value: Option<[u8; 32]>) {
    encoder.option(&value, |encoder, value| encoder.fixed(value));
}

fn decode_optional_id(decoder: &mut Decoder<'_>) -> Result<Option<[u8; 32]>, DecodeError> {
    decoder.option(Decoder::fixed)
}

fn encode_optional_blob(encoder: &mut Encoder<'_>, value: &Option<BlobRef>) {
    encoder.option(value, |encoder, value| {
        encoder.fixed(value.hash.as_bytes());
        encoder.u64(value.len);
    });
}

fn decode_optional_blob(decoder: &mut Decoder<'_>) -> Result<Option<BlobRef>, DecodeError> {
    decoder.option(|decoder| {
        Ok(BlobRef {
            hash: Hash(decoder.fixed()?),
            len: decoder.u64()?,
        })
    })
}

fn encode_lane_roots(encoder: &mut Encoder<'_>, roots: AuthorityLaneRoots) {
    encode_optional_id(encoder, roots.control.map(|value| value.0));
    encode_optional_id(encoder, roots.linear.map(|value| value.0));
    encode_optional_id(encoder, roots.merge.map(|value| value.0));
    encode_optional_id(encoder, roots.local.map(|value| value.0));
}

fn decode_lane_roots(decoder: &mut Decoder<'_>) -> Result<AuthorityLaneRoots, DecodeError> {
    Ok(AuthorityLaneRoots {
        control: decode_optional_id(decoder)?.map(Hash),
        linear: decode_optional_id(decoder)?.map(Hash),
        merge: decode_optional_id(decoder)?.map(Hash),
        local: decode_optional_id(decoder)?.map(Hash),
    })
}

fn decode_management_operation(tag: u8) -> Result<AuthorityOperationKind, DecodeError> {
    match tag {
        0 => Ok(AuthorityOperationKind::CreateAgent),
        1 => Ok(AuthorityOperationKind::InstallActor),
        2 => Ok(AuthorityOperationKind::UpgradeActor),
        3 => Ok(AuthorityOperationKind::SuspendActor),
        4 => Ok(AuthorityOperationKind::ResumeActor),
        5 => Ok(AuthorityOperationKind::RemoveActor),
        6 => Ok(AuthorityOperationKind::UpgradeRuntime),
        8 => Ok(AuthorityOperationKind::ChangeReplicaSet),
        _ => Err(DecodeError::InvalidTag),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use ed25519_dalek::{Signer as _, SigningKey, Verifier as _};

    use super::*;

    #[derive(Clone, Debug, Default)]
    struct MemoryImageStore {
        inner: Arc<Mutex<MemoryImageState>>,
    }

    #[derive(Debug, Default)]
    struct MemoryImageState {
        image: Option<Vec<u8>>,
        commits: usize,
        fail_before: Option<usize>,
        fail_after: Option<usize>,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct MemoryStoreError;

    impl fmt::Display for MemoryStoreError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("injected memory-store failure")
        }
    }

    impl core::error::Error for MemoryStoreError {}

    impl MemoryImageStore {
        fn image(&self) -> Option<Vec<u8>> {
            self.inner.lock().unwrap().image.clone()
        }

        fn replace_image(&self, image: Vec<u8>) {
            self.inner.lock().unwrap().image = Some(image);
        }

        fn fail_before_next_commit(&self) {
            let mut inner = self.inner.lock().unwrap();
            inner.fail_before = Some(inner.commits + 1);
        }

        fn fail_after_commit(&self, offset: usize) {
            let mut inner = self.inner.lock().unwrap();
            inner.fail_after = Some(inner.commits + offset);
        }
    }

    impl CleanManagementIssuerStore for MemoryImageStore {
        type Error = MemoryStoreError;

        fn load(&mut self) -> Result<Option<Vec<u8>>, Self::Error> {
            Ok(self.image())
        }

        fn commit(&mut self, image: &[u8]) -> Result<(), Self::Error> {
            let mut inner = self.inner.lock().unwrap();
            inner.commits += 1;
            let commit = inner.commits;
            if inner.fail_before == Some(commit) {
                inner.fail_before = None;
                return Err(MemoryStoreError);
            }
            inner.image = Some(image.to_vec());
            if inner.fail_after == Some(commit) {
                inner.fail_after = None;
                return Err(MemoryStoreError);
            }
            Ok(())
        }
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct TestSignerError;

    impl fmt::Display for TestSignerError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("injected signer failure")
        }
    }

    impl core::error::Error for TestSignerError {}

    struct CountingSigner {
        key: SigningKey,
        calls: usize,
        fail_next: bool,
    }

    impl CountingSigner {
        fn new(seed: u8) -> Self {
            Self {
                key: SigningKey::from_bytes(&[seed; 32]),
                calls: 0,
                fail_next: false,
            }
        }
    }

    impl CleanManagementReceiptSigner for CountingSigner {
        type Error = TestSignerError;

        fn public_key(&self) -> [u8; 32] {
            self.key.verifying_key().to_bytes()
        }

        fn sign_authority_receipt(&mut self, message: &[u8]) -> Result<[u8; 64], Self::Error> {
            self.calls += 1;
            if self.fail_next {
                self.fail_next = false;
                return Err(TestSignerError);
            }
            Ok(self.key.sign(message).to_bytes())
        }

        fn sign_management_application_ack(
            &mut self,
            message: &[u8],
        ) -> Result<[u8; 64], Self::Error> {
            self.calls += 1;
            if self.fail_next {
                self.fail_next = false;
                return Err(TestSignerError);
            }
            Ok(self.key.sign(message).to_bytes())
        }
    }

    struct TestCredentialVerifier;

    impl AuthorityCredentialVerifier for TestCredentialVerifier {
        fn verify(&self, public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
            ed25519_dalek::VerifyingKey::from_bytes(public_key).is_ok_and(|key| {
                key.verify(message, &ed25519_dalek::Signature::from_bytes(signature))
                    .is_ok()
            })
        }
    }

    impl crate::agent::sdk::authority::AuthorityVerifier for TestCredentialVerifier {
        fn verify(&self, public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
            ed25519_dalek::VerifyingKey::from_bytes(public_key).is_ok_and(|key| {
                key.verify(message, &ed25519_dalek::Signature::from_bytes(signature))
                    .is_ok()
            })
        }
    }

    #[derive(Clone)]
    struct Fixture {
        binding: AgentAuthorityBinding,
        space: SpaceId,
        agent: AgentId,
        context: CleanManagementDecisionContext,
    }

    fn fixture(signer: &CountingSigner) -> Fixture {
        let public_key = signer.public_key();
        let space = SpaceId([0x11; 32]);
        let agent = AgentId([0x12; 32]);
        let binding = AgentAuthorityBinding {
            policy: Hash([0x13; 32]),
            issuer: AuthorityIssuer {
                principal: PrincipalId([0x14; 32]),
                actor: ActorId([0x15; 32]),
                deployment: DeploymentId([0x16; 32]),
                program: ProgramId([0x17; 32]),
                producer: ProducerId::of_public_key(&public_key),
            },
            public_key,
            initial_epoch: 3,
        };
        Fixture {
            binding,
            space,
            agent,
            context: CleanManagementDecisionContext {
                space,
                agent,
                runtime_deployment: DeploymentId([0x18; 32]),
                evidence: AuthorityEvidence {
                    package: None,
                    proof: None,
                    commitment: Hash([0x19; 32]),
                },
                lane_roots: AuthorityLaneRoots::default(),
                epoch: 3,
                valid_from: 10,
                expires_at: 10_000,
            },
        }
    }

    fn request(tag: u8) -> ManagementRequest {
        ManagementRequest::RemoveLeaf {
            actor: ActorId([tag; 32]),
            expected_deployment: DeploymentId([tag.wrapping_add(1); 32]),
        }
    }

    fn application(request: &ManagementRequest) -> ManagementReply {
        match request {
            ManagementRequest::RemoveLeaf { actor, .. } => ManagementReply::Removed(*actor),
            _ => panic!("issuer test fixture uses only RemoveLeaf requests"),
        }
    }

    fn decision(
        fixture: &Fixture,
        authorization_id: u64,
        request: &ManagementRequest,
    ) -> AuthorizedCleanManagementDecision {
        AuthorizedCleanManagementDecision::new(
            NonZeroU64::new(authorization_id).unwrap(),
            fixture.context.clone(),
            request,
        )
        .unwrap()
    }

    fn open(
        store: MemoryImageStore,
        fixture: &Fixture,
    ) -> DurableCleanManagementIssuer<MemoryImageStore> {
        DurableCleanManagementIssuer::open(store, fixture.binding, fixture.space, fixture.agent)
            .unwrap()
    }

    fn approved_call(
        fixture: &Fixture,
        authorization_sequence: u64,
        request: &ManagementRequest,
    ) -> (AuthorityCredentialCall, ManagementApproval) {
        let credential_key = SigningKey::from_bytes(&[0x29; 32]);
        let credential_public_key = credential_key.verifying_key().to_bytes();
        let mut call = AuthorityCredentialCall {
            invocation: crate::agent::sdk::InvocationId::ZERO,
            authority: crate::agent::sdk::authority::AuthorityActorTarget {
                space: fixture.space,
                system_agent: AgentId([0x22; 32]),
                system_runtime_deployment: DeploymentId([0x23; 32]),
                binding: fixture.binding,
            },
            managed: crate::agent::sdk::authority::ManagedAgentTarget {
                space: fixture.space,
                agent: fixture.agent,
                owner: PrincipalId([0x26; 32]),
                profile: crate::agent::sdk::AgentProfile::Local,
                runtime_deployment: fixture.context.runtime_deployment,
                transition_producer: ProducerId([0x27; 32]),
            },
            principal: PrincipalId([0x24; 32]),
            credential: crate::agent::sdk::CredentialId::of_public_key(&credential_public_key),
            request_sequence: NonZeroU64::new(authorization_sequence).unwrap(),
            credential_public_key,
            authenticated_node: Some(crate::agent::sdk::NodeId([0x25; 32])),
            requested_valid_from: 1,
            requested_expires_at: 20_000,
            plan: request.authorization_plan().unwrap(),
            signature: [0; 64],
        };
        call.invocation = call.expected_invocation();
        call.signature = credential_key.sign(&call.signing_bytes()).to_bytes();
        let approval = ManagementApproval::from_call(
            &call,
            NonZeroU64::new(authorization_sequence).unwrap(),
            fixture.context.evidence.clone(),
            fixture.context.lane_roots,
            fixture.context.epoch,
            fixture.context.valid_from,
            fixture.context.expires_at,
        )
        .unwrap();
        (call, approval)
    }

    #[test]
    fn exact_actor_approval_is_the_only_durable_issuer_input() {
        let store = MemoryImageStore::default();
        let mut signer = CountingSigner::new(0x28);
        let fixture = fixture(&signer);
        let request = request(0x2a);
        let (call, approval) = approved_call(&fixture, 1, &request);
        let decision = AuthorizedCleanManagementDecision::from_approval(
            call.authority,
            call.managed,
            &request,
            &call,
            &approval,
            &TestCredentialVerifier,
        )
        .unwrap();
        assert_eq!(decision.authorization_id(), approval.authorization_sequence);
        assert_eq!(decision.request(), request.commitment());

        let mut substituted_request = request.clone();
        let ManagementRequest::RemoveLeaf { actor, .. } = &mut substituted_request else {
            unreachable!()
        };
        *actor = ActorId([0x2b; 32]);
        assert_eq!(substituted_request.is_valid(), true);
        assert_ne!(substituted_request.commitment(), request.commitment());
        assert_eq!(
            AuthorizedCleanManagementDecision::from_approval(
                call.authority,
                call.managed,
                &substituted_request,
                &call,
                &approval,
                &TestCredentialVerifier,
            ),
            Err(CleanManagementDecisionError::InvalidApproval)
        );

        let receipt = open(store, &fixture).issue(&decision, &mut signer).unwrap();
        assert!(decision.matches_receipt(fixture.binding, &receipt));

        let mut forged_call = call.clone();
        forged_call.signature[0] ^= 1;
        assert_eq!(
            AuthorizedCleanManagementDecision::from_approval(
                call.authority,
                call.managed,
                &request,
                &forged_call,
                &approval,
                &TestCredentialVerifier,
            ),
            Err(CleanManagementDecisionError::InvalidApproval)
        );

        let mut wrong_binding = fixture.binding;
        wrong_binding.issuer.principal = PrincipalId([0x2b; 32]);
        let mut wrong_authority = call.authority;
        wrong_authority.binding = wrong_binding;
        assert_eq!(
            AuthorizedCleanManagementDecision::from_approval(
                wrong_authority,
                call.managed,
                &request,
                &call,
                &approval,
                &TestCredentialVerifier,
            ),
            Err(CleanManagementDecisionError::InvalidApproval)
        );

        let mut wrong_authority_route = call.authority;
        wrong_authority_route.system_agent = AgentId([0x2e; 32]);
        assert_eq!(
            AuthorizedCleanManagementDecision::from_approval(
                wrong_authority_route,
                call.managed,
                &request,
                &call,
                &approval,
                &TestCredentialVerifier,
            ),
            Err(CleanManagementDecisionError::InvalidApproval)
        );
        let mut wrong_managed_route = call.managed;
        wrong_managed_route.runtime_deployment = DeploymentId([0x2f; 32]);
        assert_eq!(
            AuthorizedCleanManagementDecision::from_approval(
                call.authority,
                wrong_managed_route,
                &request,
                &call,
                &approval,
                &TestCredentialVerifier,
            ),
            Err(CleanManagementDecisionError::InvalidApproval)
        );

        let mut wrong_policy = fixture.binding;
        wrong_policy.policy = Hash([0x2c; 32]);
        let mut wrong_authority = call.authority;
        wrong_authority.binding = wrong_policy;
        assert_eq!(
            AuthorizedCleanManagementDecision::from_approval(
                wrong_authority,
                call.managed,
                &request,
                &call,
                &approval,
                &TestCredentialVerifier,
            ),
            Err(CleanManagementDecisionError::InvalidApproval)
        );
        let mut wrong_key = fixture.binding;
        wrong_key.public_key = SigningKey::from_bytes(&[0x2d; 32])
            .verifying_key()
            .to_bytes();
        wrong_key.issuer.producer = ProducerId::of_public_key(&wrong_key.public_key);
        let mut wrong_authority = call.authority;
        wrong_authority.binding = wrong_key;
        assert_eq!(
            AuthorizedCleanManagementDecision::from_approval(
                wrong_authority,
                call.managed,
                &request,
                &call,
                &approval,
                &TestCredentialVerifier,
            ),
            Err(CleanManagementDecisionError::InvalidApproval)
        );
        let mut wrong_initial_epoch = fixture.binding;
        wrong_initial_epoch.initial_epoch -= 1;
        let mut wrong_authority = call.authority;
        wrong_authority.binding = wrong_initial_epoch;
        assert_eq!(
            AuthorizedCleanManagementDecision::from_approval(
                wrong_authority,
                call.managed,
                &request,
                &call,
                &approval,
                &TestCredentialVerifier,
            ),
            Err(CleanManagementDecisionError::InvalidApproval)
        );

        let mut regressed_epoch = approval;
        regressed_epoch.epoch = fixture.binding.initial_epoch - 1;
        assert_eq!(regressed_epoch.validate_shape(), Ok(()));
        assert_eq!(
            AuthorizedCleanManagementDecision::from_approval(
                call.authority,
                call.managed,
                &request,
                &call,
                &regressed_epoch,
                &TestCredentialVerifier,
            ),
            Err(CleanManagementDecisionError::InvalidApproval)
        );
    }

    #[test]
    fn application_ack_is_pledged_after_reopen_and_is_exact_across_restart() {
        let store = MemoryImageStore::default();
        let mut signer = CountingSigner::new(0x28);
        let fixture = fixture(&signer);
        let management_request = request(0x2c);
        let application = application(&management_request);
        let (call, approval) = approved_call(&fixture, 1, &management_request);
        let approved_decision = AuthorizedCleanManagementDecision::from_approval(
            call.authority,
            call.managed,
            &management_request,
            &call,
            &approval,
            &TestCredentialVerifier,
        )
        .unwrap();
        let mut issuer = open(store.clone(), &fixture);
        let receipt = issuer.issue(&approved_decision, &mut signer).unwrap();
        assert_eq!(
            issuer
                .recover_application_ack(&receipt, &application, &mut signer)
                .unwrap(),
            None
        );
        let mut unissued = receipt.clone();
        unissued.signature[0] ^= 1;
        let calls_before_recovery = signer.calls;
        assert!(
            issuer
                .recover_application_ack(&unissued, &application, &mut signer)
                .is_err()
        );
        assert_eq!(signer.calls, calls_before_recovery);

        let second_request = request(0x2f);
        let (second_call, second_approval) = approved_call(&fixture, 2, &second_request);
        let second_decision = AuthorizedCleanManagementDecision::from_approval(
            second_call.authority,
            second_call.managed,
            &second_request,
            &second_call,
            &second_approval,
            &TestCredentialVerifier,
        )
        .unwrap();
        let before_blocked_issue = store.image().unwrap();
        let calls_before_blocked_issue = signer.calls;
        assert!(matches!(
            issuer.issue(&second_decision, &mut signer),
            Err(CleanManagementIssuerError::Rejected(
                CleanManagementIssuerRejection::ApplicationAckRequired
            ))
        ));
        assert_eq!(store.image().unwrap(), before_blocked_issue);
        assert_eq!(signer.calls, calls_before_blocked_issue);

        assert!(matches!(
            issuer.observe_durable(&receipt),
            Err(CleanManagementIssuerError::Rejected(
                CleanManagementIssuerRejection::ApplicationAckRequired
            ))
        ));

        let reopened_state = Hash([0x2e; 32]);
        let applied_at = fixture.context.valid_from;
        let before_pledge = store.image().unwrap();
        let mut wrong_signer = CountingSigner::new(0x2d);
        assert!(matches!(
            issuer.observe_durable_application(
                &receipt,
                &application,
                reopened_state,
                applied_at,
                &mut wrong_signer,
            ),
            Err(CleanManagementIssuerError::Rejected(
                CleanManagementIssuerRejection::WrongSigner
            ))
        ));
        assert_eq!(store.image().unwrap(), before_pledge);
        assert!(issuer.image.pending_application_ack.is_none());

        signer.fail_next = true;
        assert!(matches!(
            issuer.observe_durable_application(
                &receipt,
                &application,
                reopened_state,
                applied_at,
                &mut signer,
            ),
            Err(CleanManagementIssuerError::Signer(TestSignerError))
        ));
        assert_ne!(store.image().unwrap(), before_pledge);
        assert!(issuer.image.pending_application_ack.is_some());
        assert!(matches!(
            issuer.issue(&decision(&fixture, 2, &request(0x2f)), &mut signer),
            Err(CleanManagementIssuerError::Rejected(
                CleanManagementIssuerRejection::ApplicationAckRequired
            ))
        ));

        drop(issuer);
        let mut issuer = open(store.clone(), &fixture);
        let wrong_application = ManagementReply::Removed(ActorId([0x2d; 32]));
        let image_after_pledge = issuer.image.clone();
        let calls = signer.calls;
        assert!(matches!(
            issuer.recover_application_ack(&receipt, &wrong_application, &mut signer),
            Err(CleanManagementIssuerError::Rejected(
                CleanManagementIssuerRejection::DivergentApplicationAck
            ))
        ));
        assert_eq!(issuer.image, image_after_pledge);
        assert_eq!(signer.calls, calls);
        assert!(matches!(
            issuer.observe_durable_application(
                &receipt,
                &wrong_application,
                reopened_state,
                applied_at,
                &mut signer,
            ),
            Err(CleanManagementIssuerError::Rejected(
                CleanManagementIssuerRejection::DivergentApplicationAck
            ))
        ));
        assert_eq!(issuer.image, image_after_pledge);
        assert_eq!(signer.calls, calls);
        assert!(matches!(
            issuer.observe_durable_application(
                &receipt,
                &application,
                Hash([0x30; 32]),
                applied_at,
                &mut signer,
            ),
            Err(CleanManagementIssuerError::Rejected(
                CleanManagementIssuerRejection::DivergentApplicationAck
            ))
        ));
        assert_eq!(signer.calls, calls);

        let acknowledgement = issuer
            .recover_application_ack(&receipt, &application, &mut signer)
            .unwrap()
            .unwrap();
        assert_eq!(acknowledgement.reopened_state, reopened_state);
        assert_eq!(acknowledgement.applied_at, applied_at);
        assert!(acknowledgement.matches_pending(&call, &approval));
        assert_eq!(
            acknowledgement.acknowledgement_invocation,
            approval.acknowledgement_invocation
        );
        assert_eq!(acknowledgement.verify_with(&TestCredentialVerifier), Ok(()));
        assert_eq!(issuer.acknowledged_through(), 1);
        assert_eq!(issuer.retained_decisions(), 0);
        assert!(
            !issuer
                .image
                .acknowledged
                .as_ref()
                .unwrap()
                .application_finalized
        );

        drop(issuer);
        let mut issuer = open(store, &fixture);
        let mut unavailable_signer = CountingSigner::new(0x31);
        unavailable_signer.fail_next = true;
        let completed_image = issuer.image.clone();
        assert!(matches!(
            issuer.observe_durable_application(
                &receipt,
                &wrong_application,
                reopened_state,
                applied_at,
                &mut unavailable_signer,
            ),
            Err(CleanManagementIssuerError::Rejected(
                CleanManagementIssuerRejection::DivergentApplicationAck
            ))
        ));
        assert_eq!(issuer.image, completed_image);
        assert_eq!(unavailable_signer.calls, 0);
        let exact_retry = issuer
            .recover_application_ack(&receipt, &application, &mut unavailable_signer)
            .unwrap()
            .unwrap();
        assert_eq!(exact_retry, acknowledgement);
        assert_eq!(unavailable_signer.calls, 0);
        assert!(matches!(
            issuer.issue(&second_decision, &mut unavailable_signer),
            Err(CleanManagementIssuerError::Rejected(
                CleanManagementIssuerRejection::ApplicationFinalizationRequired
            ))
        ));
        assert!(matches!(
            issuer.observe_durable_application(
                &receipt,
                &application,
                Hash([0x32; 32]),
                applied_at,
                &mut unavailable_signer,
            ),
            Err(CleanManagementIssuerError::Rejected(
                CleanManagementIssuerRejection::DivergentApplicationAck
            ))
        ));

        let mut forged_acknowledgement = acknowledgement.clone();
        forged_acknowledgement.signature[0] ^= 1;
        assert!(matches!(
            issuer.observe_durable_actor_finalization(&forged_acknowledgement),
            Err(CleanManagementIssuerError::Rejected(
                CleanManagementIssuerRejection::DivergentApplicationAck
            ))
        ));
        assert!(matches!(
            issuer.observe_durable_actor_finalization(&acknowledgement),
            Ok(true)
        ));
        assert!(matches!(
            issuer.observe_durable_actor_finalization(&acknowledgement),
            Ok(false)
        ));
        assert!(
            issuer
                .image
                .acknowledged
                .as_ref()
                .unwrap()
                .application_finalized
        );
        assert!(issuer.issue(&second_decision, &mut signer).is_ok());

        // A restart image cannot splice valid later receipts behind a rolled-
        // back finalization marker, even though every individual signature is
        // authentic.
        let mut rolled_back_barrier = issuer.image.clone();
        rolled_back_barrier
            .acknowledged
            .as_mut()
            .unwrap()
            .application_finalized = false;
        assert!(CleanManagementIssuerImage::decode(&rolled_back_barrier.encode()).is_err());
    }

    #[test]
    fn application_ack_recovers_an_ambiguous_final_commit_without_resigning() {
        let store = MemoryImageStore::default();
        let mut signer = CountingSigner::new(0x34);
        let fixture = fixture(&signer);
        let management_request = request(0x35);
        let application = application(&management_request);
        let (call, approval) = approved_call(&fixture, 1, &management_request);
        let decision = AuthorizedCleanManagementDecision::from_approval(
            call.authority,
            call.managed,
            &management_request,
            &call,
            &approval,
            &TestCredentialVerifier,
        )
        .unwrap();
        let mut issuer = open(store.clone(), &fixture);
        let receipt = issuer.issue(&decision, &mut signer).unwrap();
        let reopened_state = Hash([0x37; 32]);
        let applied_at = fixture.context.valid_from;
        store.fail_after_commit(2);
        assert!(matches!(
            issuer.observe_durable_application(
                &receipt,
                &application,
                reopened_state,
                applied_at,
                &mut signer,
            ),
            Err(CleanManagementIssuerError::Storage(MemoryStoreError))
        ));
        assert!(issuer.is_poisoned());
        let calls = signer.calls;

        drop(issuer);
        let mut issuer = open(store, &fixture);
        let mut unavailable_signer = CountingSigner::new(0x38);
        unavailable_signer.fail_next = true;
        let acknowledgement = issuer
            .recover_application_ack(&receipt, &application, &mut unavailable_signer)
            .unwrap()
            .unwrap();
        assert!(acknowledgement.matches_pending(&call, &approval));
        assert_eq!(acknowledgement.verify_with(&TestCredentialVerifier), Ok(()));
        assert_eq!(unavailable_signer.calls, 0);
        assert_eq!(signer.calls, calls);
    }

    #[test]
    fn exact_retry_restart_and_pending_recovery_are_sign_once_bound() {
        let store = MemoryImageStore::default();
        let mut signer = CountingSigner::new(0x21);
        let fixture = fixture(&signer);
        let mut issuer = open(store.clone(), &fixture);
        let first_request = request(0x31);
        let first = decision(&fixture, 1, &first_request);

        let receipt = issuer.issue(&first, &mut signer).unwrap();
        let exact_bytes = receipt.encode().unwrap();
        assert_eq!(receipt.selector.decision_sequence, 1);
        assert_eq!(receipt.selector.acknowledged_through, 0);
        assert_eq!(signer.calls, 1);

        let mut unavailable_signer = CountingSigner::new(0x22);
        let retry = issuer.issue(&first, &mut unavailable_signer).unwrap();
        assert_eq!(retry.encode().unwrap(), exact_bytes);
        assert_eq!(unavailable_signer.calls, 0);

        let divergent = decision(&fixture, 1, &request(0x32));
        assert!(matches!(
            issuer.issue(&divergent, &mut signer),
            Err(CleanManagementIssuerError::Rejected(
                CleanManagementIssuerRejection::DivergentRetry
            ))
        ));
        assert_eq!(store.image().unwrap(), issuer.image.encode());

        drop(issuer);
        let mut issuer = open(store.clone(), &fixture);
        let retry = issuer.issue(&first, &mut unavailable_signer).unwrap();
        assert_eq!(retry.encode().unwrap(), exact_bytes);
        assert_eq!(unavailable_signer.calls, 0);

        let second = decision(&fixture, 2, &request(0x33));
        signer.fail_next = true;
        assert!(matches!(
            issuer.issue(&second, &mut signer),
            Err(CleanManagementIssuerError::Signer(TestSignerError))
        ));
        assert_eq!(issuer.sequence_high_water(), 1);
        assert_eq!(issuer.retained_decisions(), 1);

        drop(issuer);
        let mut issuer = open(store.clone(), &fixture);
        let second_receipt = issuer.issue(&second, &mut signer).unwrap();
        assert_eq!(second_receipt.selector.decision_sequence, 2);
        assert_eq!(issuer.sequence_high_water(), 2);

        let third = decision(&fixture, 3, &request(0x34));
        store.fail_after_commit(2);
        assert!(matches!(
            issuer.issue(&third, &mut signer),
            Err(CleanManagementIssuerError::Storage(MemoryStoreError))
        ));
        assert!(issuer.is_poisoned());
        assert!(matches!(
            issuer.issue(&third, &mut signer),
            Err(CleanManagementIssuerError::Rejected(
                CleanManagementIssuerRejection::Poisoned
            ))
        ));

        drop(issuer);
        let mut issuer = open(store, &fixture);
        let calls = signer.calls;
        let recovered = issuer.issue(&third, &mut signer).unwrap();
        assert_eq!(recovered.selector.decision_sequence, 3);
        assert_eq!(signer.calls, calls, "durable signed retry skips the signer");
    }

    #[test]
    fn full_journal_requires_exact_latest_observation_and_rejects_forged_ack() {
        let store = MemoryImageStore::default();
        let mut signer = CountingSigner::new(0x41);
        let fixture = fixture(&signer);
        let mut issuer = open(store.clone(), &fixture);
        let repeated_request = request(0x42);
        let mut first = None;
        let mut latest = None;
        for authorization_id in 1..=MAX_CLEAN_MANAGEMENT_ISSUER_DECISIONS as u64 {
            let receipt = issuer
                .issue(
                    &decision(&fixture, authorization_id, &repeated_request),
                    &mut signer,
                )
                .unwrap();
            first.get_or_insert_with(|| receipt.clone());
            latest = Some(receipt);
        }
        assert_eq!(
            issuer.retained_decisions(),
            MAX_CLEAN_MANAGEMENT_ISSUER_DECISIONS
        );
        let full_image = store.image().unwrap();
        let calls = signer.calls;
        let next = decision(
            &fixture,
            MAX_CLEAN_MANAGEMENT_ISSUER_DECISIONS as u64 + 1,
            &repeated_request,
        );
        assert!(matches!(
            issuer.issue(&next, &mut signer),
            Err(CleanManagementIssuerError::Rejected(
                CleanManagementIssuerRejection::JournalFull
            ))
        ));
        assert_eq!(signer.calls, calls);
        assert_eq!(store.image().unwrap(), full_image);

        assert!(matches!(
            issuer.observe_durable(first.as_ref().unwrap()),
            Err(CleanManagementIssuerError::Rejected(
                CleanManagementIssuerRejection::ObservationNotLatest
            ))
        ));
        assert_eq!(store.image().unwrap(), full_image);

        let mut forged = latest.clone().unwrap();
        forged.selector.acknowledged_through = 1;
        forged.signature = signer.key.sign(&forged.signing_bytes()).to_bytes();
        assert!(crate::agent::authority::verify_raw_ed25519(
            &forged.public_key,
            &forged.signing_bytes(),
            &forged.signature,
        ));
        assert!(matches!(
            issuer.observe_durable(&forged),
            Err(CleanManagementIssuerError::Rejected(
                CleanManagementIssuerRejection::InvalidObservation
            ))
        ));
        assert_eq!(store.image().unwrap(), full_image);

        let latest = latest.unwrap();
        assert!(matches!(issuer.observe_durable(&latest), Ok(true)));
        assert_eq!(
            issuer.acknowledged_through(),
            MAX_CLEAN_MANAGEMENT_ISSUER_DECISIONS as u64
        );
        assert_eq!(issuer.retained_decisions(), 0);
        assert!(matches!(issuer.observe_durable(&latest), Ok(false)));
        let mut unavailable_signer = CountingSigner::new(0x43);
        let acknowledged_retry = issuer
            .issue(
                &decision(
                    &fixture,
                    MAX_CLEAN_MANAGEMENT_ISSUER_DECISIONS as u64,
                    &repeated_request,
                ),
                &mut unavailable_signer,
            )
            .unwrap();
        assert_eq!(
            acknowledged_retry.encode().unwrap(),
            latest.encode().unwrap()
        );
        assert_eq!(unavailable_signer.calls, 0);

        drop(issuer);
        let mut issuer = open(store, &fixture);
        let progressed = issuer.issue(&next, &mut signer).unwrap();
        assert_eq!(
            progressed.selector.decision_sequence,
            MAX_CLEAN_MANAGEMENT_ISSUER_DECISIONS as u64 + 1
        );
        assert_eq!(
            progressed.selector.acknowledged_through,
            MAX_CLEAN_MANAGEMENT_ISSUER_DECISIONS as u64
        );
        assert!(matches!(
            issuer.issue(&decision(&fixture, 1, &repeated_request), &mut signer),
            Err(CleanManagementIssuerError::Rejected(
                CleanManagementIssuerRejection::AuthorizationRegressed
            ))
        ));
    }

    #[test]
    fn periodic_observation_crosses_twice_capacity_with_restart() {
        let store = MemoryImageStore::default();
        let mut signer = CountingSigner::new(0x51);
        let fixture = fixture(&signer);
        let repeated_request = request(0x52);
        let mut issuer = open(store.clone(), &fixture);
        let last_sequence = 2 * MAX_CLEAN_MANAGEMENT_ISSUER_DECISIONS as u64 + 37;
        let mut acknowledged = 0;
        let mut latest_decision = None;
        let mut latest_receipt = None;
        for sequence in 1..=last_sequence {
            let current = decision(&fixture, sequence, &repeated_request);
            let receipt = issuer.issue(&current, &mut signer).unwrap();
            assert_eq!(receipt.selector.decision_sequence, sequence);
            assert_eq!(receipt.selector.acknowledged_through, acknowledged);
            latest_decision = Some(current);
            latest_receipt = Some(receipt.clone());
            if sequence % 64 == 0 {
                assert!(matches!(issuer.observe_durable(&receipt), Ok(true)));
                acknowledged = sequence;
            }
            if sequence % 73 == 0 {
                drop(issuer);
                issuer = open(store.clone(), &fixture);
            }
        }
        assert_eq!(issuer.sequence_high_water(), last_sequence);
        assert_eq!(issuer.acknowledged_through(), acknowledged);
        assert_eq!(
            issuer.retained_decisions(),
            usize::try_from(last_sequence - acknowledged).unwrap()
        );
        assert_eq!(signer.calls, last_sequence as usize);

        drop(issuer);
        let mut issuer = open(store, &fixture);
        let calls = signer.calls;
        let retry = issuer
            .issue(latest_decision.as_ref().unwrap(), &mut signer)
            .unwrap();
        assert_eq!(
            retry.encode().unwrap(),
            latest_receipt.unwrap().encode().unwrap()
        );
        assert_eq!(signer.calls, calls);
    }

    #[test]
    fn restore_is_canonical_bounded_and_read_only_requests_never_enter_journal() {
        let store = MemoryImageStore::default();
        let mut signer = CountingSigner::new(0x61);
        let fixture = fixture(&signer);
        assert_eq!(
            AuthorizedCleanManagementDecision::new(
                NonZeroU64::new(1).unwrap(),
                fixture.context.clone(),
                &ManagementRequest::InspectResources,
            ),
            Err(CleanManagementDecisionError::ReadOnlyRequest)
        );

        let mut issuer = open(store.clone(), &fixture);
        issuer
            .issue(&decision(&fixture, 1, &request(0x62)), &mut signer)
            .unwrap();
        let canonical = store.image().unwrap();
        for rejected_magic in [b"CMI1", b"CMI2"] {
            let mut previous_generation = canonical.clone();
            previous_generation[..4].copy_from_slice(rejected_magic);
            assert!(CleanManagementIssuerImage::decode(&previous_generation).is_err());
        }
        let mut forged_ack = issuer.image.clone();
        forged_ack.decision_sequence_high_water = 2;
        forged_ack.acknowledged_through = 2;
        forged_ack.authorization_high_water = 2;
        forged_ack.acknowledged = forged_ack.retained.last().cloned();
        forged_ack.retained.clear();
        drop(issuer);
        assert_eq!(open(store.clone(), &fixture).sequence_high_water(), 1);

        store.replace_image(forged_ack.encode());
        assert!(matches!(
            DurableCleanManagementIssuer::open(
                store.clone(),
                fixture.binding,
                fixture.space,
                fixture.agent
            ),
            Err(CleanManagementIssuerError::InvalidState)
        ));

        let mut trailing = canonical.clone();
        trailing.push(0);
        store.replace_image(trailing);
        assert!(matches!(
            DurableCleanManagementIssuer::open(
                store.clone(),
                fixture.binding,
                fixture.space,
                fixture.agent
            ),
            Err(CleanManagementIssuerError::InvalidState)
        ));

        store.replace_image(vec![0; MAX_CLEAN_MANAGEMENT_ISSUER_IMAGE_BYTES + 1]);
        assert!(matches!(
            DurableCleanManagementIssuer::open(
                store.clone(),
                fixture.binding,
                fixture.space,
                fixture.agent
            ),
            Err(CleanManagementIssuerError::InvalidState)
        ));

        store.replace_image(canonical);
        let mut issuer = open(store.clone(), &fixture);
        store.fail_before_next_commit();
        let calls = signer.calls;
        assert!(matches!(
            issuer.issue(&decision(&fixture, 2, &request(0x63)), &mut signer),
            Err(CleanManagementIssuerError::Storage(MemoryStoreError))
        ));
        assert_eq!(signer.calls, calls, "a failed pledge never reaches signing");
        assert!(issuer.is_poisoned());
        drop(issuer);
        assert_eq!(open(store, &fixture).sequence_high_water(), 1);
    }
}
