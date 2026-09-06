//! Guest-verifiable authority receipt model.

use core::num::NonZeroU64;

use alloc::vec::Vec;

use crate::{
    ActorId, AgentId, BlobRef, CredentialId, DeploymentId, Hash, InvocationContext, InvocationId,
    InvocationRoleClaims, ManagementRequest, MethodMode, NodeId, PrincipalId, ProducerId,
    ProgramId, SpaceId,
};

pub const AUTHORITY_PUBLIC_KEY_BYTES: usize = 32;
pub const AUTHORITY_SIGNATURE_BYTES: usize = 64;
pub const CREDENTIAL_PUBLIC_KEY_BYTES: usize = 32;
pub const CREDENTIAL_SIGNATURE_BYTES: usize = 64;

/// Exact installed system-authority route selected by a credential call.
///
/// The complete issuer is carried here so an authority Principal or Producer
/// cannot be changed while retaining the same actor/deployment/program tuple.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuthorityActorTarget {
    pub space: SpaceId,
    pub system_agent: AgentId,
    pub system_runtime_deployment: DeploymentId,
    pub issuer: AuthorityIssuer,
}

impl AuthorityActorTarget {
    pub fn is_valid(self) -> bool {
        self.space != SpaceId::ZERO
            && self.system_agent != AgentId::ZERO
            && self.system_runtime_deployment != DeploymentId::ZERO
            && self.issuer.is_valid()
    }
}

/// Exact Agent route whose management request is being authorized.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ManagedAgentTarget {
    pub space: SpaceId,
    pub agent: AgentId,
    pub runtime_deployment: DeploymentId,
}

impl ManagedAgentTarget {
    pub fn is_valid(self) -> bool {
        self.space != SpaceId::ZERO
            && self.agent != AgentId::ZERO
            && self.runtime_deployment != DeploymentId::ZERO
    }
}

/// Policy operation selected by an authority receipt. Tags are stable wire
/// values; unknown tags fail closed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum AuthorityOperationKind {
    CreateAgent = 0,
    InstallActor = 1,
    UpgradeActor = 2,
    SuspendActor = 3,
    ResumeActor = 4,
    RemoveActor = 5,
    UpgradeRuntime = 6,
    InvokeActor = 7,
    ChangeReplicaSet = 8,
    InvitePrivateNode = 9,
    RevokePrivateNode = 10,
    RecoverPrivateAgent = 11,
    PublishCatalog = 12,
}

impl AuthorityOperationKind {
    pub const fn requires_actor(self) -> bool {
        matches!(
            self,
            Self::InstallActor
                | Self::UpgradeActor
                | Self::SuspendActor
                | Self::ResumeActor
                | Self::RemoveActor
                | Self::InvokeActor
        )
    }

    /// Whether this operation participates in the standard Agent management
    /// decision journal. Invocation, Private-Agent, and catalog receipts use
    /// their own replay domains and therefore carry zero in both management
    /// replay fields.
    pub const fn uses_management_decision_journal(self) -> bool {
        matches!(
            self,
            Self::CreateAgent
                | Self::InstallActor
                | Self::UpgradeActor
                | Self::SuspendActor
                | Self::ResumeActor
                | Self::RemoveActor
                | Self::UpgradeRuntime
                | Self::ChangeReplicaSet
        )
    }
}

/// Exact visible authority actor which issued the receipt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuthorityIssuer {
    pub principal: PrincipalId,
    pub actor: ActorId,
    pub deployment: DeploymentId,
    pub program: ProgramId,
    pub producer: ProducerId,
}

impl AuthorityIssuer {
    pub fn is_valid(self) -> bool {
        self.principal.0 != PrincipalId::ZERO.0
            && self.actor.0 != ActorId::ZERO.0
            && self.deployment.0 != DeploymentId::ZERO.0
            && self.program.0 != ProgramId::ZERO.0
            && self.producer.0 != ProducerId::ZERO.0
    }
}

/// One directly authenticated credential request to the system authority
/// actor. The signature covers every preceding field and the complete
/// canonical [`ManagementRequest`] bytes; it never covers itself.
///
/// This call is deliberately self-authenticating and carries no role or
/// capability grant. It can therefore enter the authority actor through a
/// non-circular public preflight before that actor has made a policy decision.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorityCredentialCall {
    pub invocation: InvocationId,
    pub authority: AuthorityActorTarget,
    pub managed: ManagedAgentTarget,
    pub principal: PrincipalId,
    pub credential: CredentialId,
    pub credential_public_key: [u8; CREDENTIAL_PUBLIC_KEY_BYTES],
    pub authenticated_node: Option<NodeId>,
    pub requested_valid_from: u64,
    pub requested_expires_at: u64,
    pub request: ManagementRequest,
    pub signature: [u8; CREDENTIAL_SIGNATURE_BYTES],
}

impl AuthorityCredentialCall {
    /// Bytes verified by the injected Ed25519 implementation.
    pub fn signing_bytes(&self) -> Vec<u8> {
        crate::wire::authority_credential_call_signing_bytes(self)
    }

    /// Commitment of the complete signed call, including its signature.
    pub fn commitment(&self) -> Hash {
        Hash::digest(
            b"vos/agent/authority-credential-call/v1",
            &[&self.signing_bytes(), &self.signature],
        )
    }

    pub fn validate_shape(&self) -> Result<(), AuthorityActorProtocolError> {
        if self.invocation == InvocationId::ZERO
            || !self.authority.is_valid()
            || !self.managed.is_valid()
            || self.authority.space != self.managed.space
        {
            return Err(AuthorityActorProtocolError::InvalidTarget);
        }
        if self.principal == PrincipalId::ZERO
            || self.credential == CredentialId::ZERO
            || self.credential_public_key == [0; CREDENTIAL_PUBLIC_KEY_BYTES]
            || CredentialId::of_public_key(&self.credential_public_key) != self.credential
            || self.authenticated_node == Some(NodeId::ZERO)
        {
            return Err(AuthorityActorProtocolError::InvalidCaller);
        }
        if self.requested_valid_from > self.requested_expires_at {
            return Err(AuthorityActorProtocolError::InvalidValidity);
        }
        if !mutating_request_matches_targets(&self.authority, &self.managed, &self.request) {
            return Err(AuthorityActorProtocolError::InvalidRequest);
        }
        if self.signature == [0; CREDENTIAL_SIGNATURE_BYTES] {
            return Err(AuthorityActorProtocolError::InvalidSignature);
        }
        if crate::wire::authority_credential_call_encoded_len(self)
            > crate::MAX_INVOCATION_MESSAGE_BYTES
        {
            return Err(AuthorityActorProtocolError::LimitExceeded);
        }
        Ok(())
    }

    /// Verify the credential signature without choosing a crypto provider.
    pub fn verify_with<V: AuthorityCredentialVerifier>(
        &self,
        verifier: &V,
    ) -> Result<(), AuthorityActorProtocolError> {
        self.validate_shape()?;
        if !verifier.verify(
            &self.credential_public_key,
            &self.signing_bytes(),
            &self.signature,
        ) {
            return Err(AuthorityActorProtocolError::InvalidSignature);
        }
        Ok(())
    }

    /// Exact public-preflight binding to the clean actor invocation context.
    /// Signature verification remains a separate injected operation.
    pub fn matches_invocation_context(&self, context: &InvocationContext) -> bool {
        self.validate_shape().is_ok()
            && context.validate()
            && context.invocation == self.invocation
            && context.actor == self.authority.issuer.actor
            && context.mode == MethodMode::Linear
            && context.origin.principal == Some(self.principal)
            && context.origin.credential == Some(self.credential)
            && context.origin.transport_node == self.authenticated_node
            && context.origin.actor.is_none()
            && context.origin.capability.is_none()
            && context.roles == InvocationRoleClaims::none()
    }
}

/// Ed25519 verification is injected by the host or guest actor. The portable
/// SDK intentionally provides no key store, host call, or crypto provider.
pub trait AuthorityCredentialVerifier {
    fn verify(
        &self,
        public_key: &[u8; CREDENTIAL_PUBLIC_KEY_BYTES],
        message: &[u8],
        signature: &[u8; CREDENTIAL_SIGNATURE_BYTES],
    ) -> bool;
}

/// Deterministic policy output consumed by the durable management issuer.
///
/// `authorization_sequence` belongs to the authority actor and is stable
/// across exact retries. It is not the management receipt's decision
/// sequence; the durable issuer allocates and acknowledges that separate
/// replay clock.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ManagementApproval {
    pub credential_call: Hash,
    pub authorization_sequence: NonZeroU64,
    pub authority: AuthorityActorTarget,
    pub managed: ManagedAgentTarget,
    pub principal: PrincipalId,
    pub credential: CredentialId,
    pub credential_public_key: [u8; CREDENTIAL_PUBLIC_KEY_BYTES],
    pub authenticated_node: Option<NodeId>,
    pub evidence: AuthorityEvidence,
    pub lane_roots: AuthorityLaneRoots,
    pub epoch: u64,
    pub valid_from: u64,
    pub expires_at: u64,
    pub request: ManagementRequest,
    pub request_commitment: Hash,
}

impl ManagementApproval {
    #[allow(clippy::too_many_arguments)]
    pub fn from_call(
        call: &AuthorityCredentialCall,
        authorization_sequence: NonZeroU64,
        evidence: AuthorityEvidence,
        lane_roots: AuthorityLaneRoots,
        epoch: u64,
        valid_from: u64,
        expires_at: u64,
    ) -> Result<Self, AuthorityActorProtocolError> {
        call.validate_shape()?;
        let value = Self {
            credential_call: call.commitment(),
            authorization_sequence,
            authority: call.authority,
            managed: call.managed,
            principal: call.principal,
            credential: call.credential,
            credential_public_key: call.credential_public_key,
            authenticated_node: call.authenticated_node,
            evidence,
            lane_roots,
            epoch,
            valid_from,
            expires_at,
            request: call.request.clone(),
            request_commitment: call.request.commitment(),
        };
        value.validate_shape()?;
        if !value.matches_call(call) {
            return Err(AuthorityActorProtocolError::MismatchedCall);
        }
        Ok(value)
    }

    pub fn validate_shape(&self) -> Result<(), AuthorityActorProtocolError> {
        if self.credential_call == Hash::ZERO
            || !self.authority.is_valid()
            || !self.managed.is_valid()
            || self.authority.space != self.managed.space
        {
            return Err(AuthorityActorProtocolError::InvalidTarget);
        }
        if self.principal == PrincipalId::ZERO
            || self.credential == CredentialId::ZERO
            || self.credential_public_key == [0; CREDENTIAL_PUBLIC_KEY_BYTES]
            || CredentialId::of_public_key(&self.credential_public_key) != self.credential
            || self.authenticated_node == Some(NodeId::ZERO)
        {
            return Err(AuthorityActorProtocolError::InvalidCaller);
        }
        if self.epoch == 0 || self.valid_from > self.expires_at {
            return Err(AuthorityActorProtocolError::InvalidValidity);
        }
        if !self.evidence.is_valid()
            || !self.lane_roots.is_valid()
            || !mutating_request_matches_targets(&self.authority, &self.managed, &self.request)
            || self.request_commitment == Hash::ZERO
            || self.request_commitment != self.request.commitment()
        {
            return Err(AuthorityActorProtocolError::InvalidRequest);
        }
        if crate::wire::management_approval_encoded_len(self) > crate::MAX_INVOCATION_REPLY_BYTES {
            return Err(AuthorityActorProtocolError::LimitExceeded);
        }
        Ok(())
    }

    /// Check the retained call preimage and ensure policy only narrows the
    /// caller-requested validity interval.
    pub fn matches_call(&self, call: &AuthorityCredentialCall) -> bool {
        self.validate_shape().is_ok()
            && call.validate_shape().is_ok()
            && self.credential_call == call.commitment()
            && self.authority == call.authority
            && self.managed == call.managed
            && self.principal == call.principal
            && self.credential == call.credential
            && self.credential_public_key == call.credential_public_key
            && self.authenticated_node == call.authenticated_node
            && self.valid_from >= call.requested_valid_from
            && self.expires_at <= call.requested_expires_at
            && self.request == call.request
            && self.request_commitment == call.request.commitment()
    }

    pub fn commitment(&self) -> Hash {
        crate::wire::management_approval_commitment(self)
    }
}

fn mutating_request_matches_targets(
    authority: &AuthorityActorTarget,
    managed: &ManagedAgentTarget,
    request: &ManagementRequest,
) -> bool {
    if !request.is_valid() || request.authority_operation().is_none() {
        return false;
    }
    match request {
        ManagementRequest::Create(descriptor) => {
            descriptor.identity.space == managed.space
                && descriptor.identity.agent == managed.agent
                && descriptor.identity.runtime_deployment == managed.runtime_deployment
                && descriptor.authority.issuer == authority.issuer
        }
        ManagementRequest::UpgradeRuntime(upgrade) => {
            upgrade.from_deployment == managed.runtime_deployment
        }
        _ => true,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthorityActorProtocolError {
    InvalidTarget,
    InvalidCaller,
    InvalidValidity,
    InvalidRequest,
    InvalidSignature,
    LimitExceeded,
    MismatchedCall,
}

impl core::fmt::Display for AuthorityActorProtocolError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            formatter,
            "invalid authority actor protocol value: {self:?}"
        )
    }
}

impl core::error::Error for AuthorityActorProtocolError {}

/// Immutable trust anchor selected when an Agent is created.
///
/// A receipt is self-describing so a runtime can verify its signature, but
/// those self-described fields are not themselves a trust decision. Every
/// Agent therefore persists this independently supplied binding and requires
/// exact policy, issuer, and key equality before consuming a receipt. The
/// epoch is a floor for later authority rotations and prevents a newly
/// created Agent from accepting evidence from an already-retired epoch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AgentAuthorityBinding {
    pub policy: Hash,
    pub issuer: AuthorityIssuer,
    pub public_key: [u8; AUTHORITY_PUBLIC_KEY_BYTES],
    pub initial_epoch: u64,
}

impl AgentAuthorityBinding {
    pub fn is_valid(self) -> bool {
        self.policy != Hash::ZERO
            && self.issuer.is_valid()
            && self.public_key != [0; AUTHORITY_PUBLIC_KEY_BYTES]
            && ProducerId::of_public_key(&self.public_key) == self.issuer.producer
            && self.initial_epoch != 0
    }

    /// Whether this immutable anchor selects the signer and policy carried by
    /// `receipt`. Request, target, operation, liveness, and signature checks
    /// remain separate so callers cannot accidentally treat a trust match as
    /// complete authorization.
    pub fn accepts(self, receipt: &AuthorityReceipt) -> bool {
        self.is_valid()
            && receipt.selector.policy == self.policy
            && receipt.selector.issuer == self.issuer
            && receipt.public_key == self.public_key
            && receipt.selector.epoch >= self.initial_epoch
    }

    pub fn commitment(self) -> Hash {
        Hash::digest(
            b"vos/agent/authority-binding/v1",
            &[
                self.policy.as_bytes(),
                self.issuer.principal.as_bytes(),
                self.issuer.actor.as_bytes(),
                self.issuer.deployment.as_bytes(),
                self.issuer.program.as_bytes(),
                self.issuer.producer.as_bytes(),
                &self.public_key,
                &self.initial_epoch.to_le_bytes(),
            ],
        )
    }
}

/// Relevant lane commitments selected at authorization time. Missing lanes
/// are explicit and cannot be confused with a zero root.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AuthorityLaneRoots {
    pub control: Option<Hash>,
    pub linear: Option<Hash>,
    pub merge: Option<Hash>,
    pub local: Option<Hash>,
}

impl AuthorityLaneRoots {
    pub fn is_valid(self) -> bool {
        option_hash_valid(self.control)
            && option_hash_valid(self.linear)
            && option_hash_valid(self.merge)
            && option_hash_valid(self.local)
    }
}

fn option_hash_valid(value: Option<Hash>) -> bool {
    match value {
        Some(value) => value.0 != Hash::ZERO.0,
        None => true,
    }
}

/// Optional package/proof objects plus the mandatory complete evidence
/// commitment used by the policy decision.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorityEvidence {
    pub package: Option<BlobRef>,
    pub proof: Option<BlobRef>,
    pub commitment: Hash,
}

impl AuthorityEvidence {
    pub fn is_valid(&self) -> bool {
        self.commitment != Hash::ZERO
            && self.package.as_ref().is_none_or(valid_reference)
            && self.proof.as_ref().is_none_or(valid_reference)
    }
}

fn valid_reference(reference: &BlobRef) -> bool {
    reference.hash != Hash::ZERO
        && reference.len != 0
        && reference.len <= crate::MAX_CATALOG_ARTIFACT_BYTES
}

/// Complete policy selector signed by the authority actor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorityReceiptSelector {
    pub policy: Hash,
    pub issuer: AuthorityIssuer,
    pub space: SpaceId,
    pub agent: AgentId,
    pub operation: AuthorityOperationKind,
    pub runtime_deployment: DeploymentId,
    pub actor: Option<ActorId>,
    pub actor_deployment: Option<DeploymentId>,
    pub evidence: AuthorityEvidence,
    pub lane_roots: AuthorityLaneRoots,
    /// Monotonic policy/committee epoch.
    pub epoch: u64,
    /// Binding-global sequence in the clean management decision journal.
    /// This is nonzero only for operations selected by
    /// [`AuthorityOperationKind::uses_management_decision_journal`].
    pub decision_sequence: u64,
    /// Inclusive clean-management sequence watermark whose older exact
    /// results the authority has durably observed and permits the Agent to
    /// discard. Unrelated operation domains carry zero here and above.
    pub acknowledged_through: u64,
    /// First logical slot at which this decision may be consumed.
    pub valid_from: u64,
    /// Last logical slot at which this decision may be consumed, inclusive.
    pub expires_at: u64,
    /// Hash of the exact canonical request bytes authorized by this receipt.
    pub request: Hash,
}

impl AuthorityReceiptSelector {
    pub fn validate(&self) -> Result<(), AuthorityReceiptError> {
        let valid_management_replay = if self.operation.uses_management_decision_journal() {
            self.decision_sequence != 0 && self.acknowledged_through < self.decision_sequence
        } else {
            self.decision_sequence == 0 && self.acknowledged_through == 0
        };
        if self.policy == Hash::ZERO
            || !self.issuer.is_valid()
            || self.space == SpaceId::ZERO
            || self.agent == AgentId::ZERO
            || self.runtime_deployment == DeploymentId::ZERO
            || self.request == Hash::ZERO
            || !valid_management_replay
            || self.valid_from > self.expires_at
            || !self.evidence.is_valid()
            || !self.lane_roots.is_valid()
        {
            return Err(AuthorityReceiptError::InvalidSelector);
        }
        match (
            self.operation.requires_actor(),
            self.actor,
            self.actor_deployment,
        ) {
            (true, Some(actor), Some(deployment))
                if actor != ActorId::ZERO && deployment != DeploymentId::ZERO => {}
            (false, None, None) => {}
            _ => return Err(AuthorityReceiptError::InvalidSelector),
        }
        Ok(())
    }

    pub fn is_live_at(&self, logical_slot: u64) -> bool {
        logical_slot >= self.valid_from && logical_slot <= self.expires_at
    }
}

/// Signed, self-describing authority evidence. The verifier implementation is
/// supplied by the guest runtime so the SDK does not choose a cryptographic
/// provider or introduce host calls.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorityReceipt {
    pub selector: AuthorityReceiptSelector,
    pub public_key: [u8; AUTHORITY_PUBLIC_KEY_BYTES],
    pub signature: [u8; AUTHORITY_SIGNATURE_BYTES],
}

impl AuthorityReceipt {
    pub fn signing_bytes(&self) -> Vec<u8> {
        crate::wire::authority_signing_bytes(self)
    }

    pub fn commitment(&self) -> Hash {
        Hash::digest(
            b"vos/authority/receipt",
            &[&self.signing_bytes(), &self.signature],
        )
    }

    pub fn validate_shape(&self) -> Result<(), AuthorityReceiptError> {
        self.selector.validate()?;
        if self.public_key == [0; AUTHORITY_PUBLIC_KEY_BYTES]
            || self.signature == [0; AUTHORITY_SIGNATURE_BYTES]
        {
            return Err(AuthorityReceiptError::InvalidSignature);
        }
        if ProducerId::of_public_key(&self.public_key) != self.selector.issuer.producer {
            return Err(AuthorityReceiptError::WrongSigner);
        }
        Ok(())
    }

    pub fn verify_at<V: AuthorityVerifier>(
        &self,
        logical_slot: u64,
        verifier: &V,
    ) -> Result<(), AuthorityReceiptError> {
        self.validate_shape()?;
        if !self.selector.is_live_at(logical_slot) {
            return Err(AuthorityReceiptError::Expired);
        }
        if !verifier.verify(&self.public_key, &self.signing_bytes(), &self.signature) {
            return Err(AuthorityReceiptError::InvalidSignature);
        }
        Ok(())
    }
}

pub trait AuthorityVerifier {
    fn verify(&self, public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthorityReceiptError {
    InvalidSelector,
    WrongSigner,
    InvalidSignature,
    Expired,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_signature(public_key: &[u8; 32], message: &[u8]) -> [u8; 64] {
        let first = Hash::digest(
            b"vos/test/credential-signature/first",
            &[public_key, message],
        );
        let second = Hash::digest(
            b"vos/test/credential-signature/second",
            &[public_key, message],
        );
        let mut signature = [0; 64];
        signature[..32].copy_from_slice(first.as_bytes());
        signature[32..].copy_from_slice(second.as_bytes());
        signature
    }

    struct TestCredentialVerifier;

    impl AuthorityCredentialVerifier for TestCredentialVerifier {
        fn verify(&self, public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
            *signature == test_signature(public_key, message)
        }
    }

    fn authority_target() -> AuthorityActorTarget {
        AuthorityActorTarget {
            space: SpaceId([21; 32]),
            system_agent: AgentId([22; 32]),
            system_runtime_deployment: DeploymentId([23; 32]),
            issuer: AuthorityIssuer {
                principal: PrincipalId([24; 32]),
                actor: ActorId([25; 32]),
                deployment: DeploymentId([26; 32]),
                program: ProgramId([27; 32]),
                producer: ProducerId([28; 32]),
            },
        }
    }

    fn managed_target() -> ManagedAgentTarget {
        ManagedAgentTarget {
            space: authority_target().space,
            agent: AgentId([29; 32]),
            runtime_deployment: DeploymentId([30; 32]),
        }
    }

    fn mutating_request() -> ManagementRequest {
        ManagementRequest::Suspend {
            actor: ActorId([31; 32]),
            expected_deployment: DeploymentId([32; 32]),
        }
    }

    fn credential_call(request: ManagementRequest) -> AuthorityCredentialCall {
        let public_key = [33; CREDENTIAL_PUBLIC_KEY_BYTES];
        let mut call = AuthorityCredentialCall {
            invocation: InvocationId([34; 32]),
            authority: authority_target(),
            managed: managed_target(),
            principal: PrincipalId([35; 32]),
            credential: CredentialId::of_public_key(&public_key),
            credential_public_key: public_key,
            authenticated_node: Some(NodeId([36; 32])),
            requested_valid_from: 100,
            requested_expires_at: 120,
            request,
            signature: [1; CREDENTIAL_SIGNATURE_BYTES],
        };
        call.signature = test_signature(&public_key, &call.signing_bytes());
        call
    }

    fn resign(call: &mut AuthorityCredentialCall) {
        call.signature = test_signature(&call.credential_public_key, &call.signing_bytes());
    }

    fn approval(call: &AuthorityCredentialCall) -> ManagementApproval {
        ManagementApproval::from_call(
            call,
            NonZeroU64::new(7).unwrap(),
            AuthorityEvidence {
                package: None,
                proof: None,
                commitment: Hash([37; 32]),
            },
            AuthorityLaneRoots {
                control: Some(Hash([38; 32])),
                linear: Some(Hash([39; 32])),
                merge: None,
                local: None,
            },
            3,
            101,
            119,
        )
        .unwrap()
    }

    fn selector(producer: ProducerId) -> AuthorityReceiptSelector {
        AuthorityReceiptSelector {
            policy: Hash([1; 32]),
            issuer: AuthorityIssuer {
                principal: PrincipalId([2; 32]),
                actor: ActorId([3; 32]),
                deployment: DeploymentId([4; 32]),
                program: ProgramId([5; 32]),
                producer,
            },
            space: SpaceId([6; 32]),
            agent: AgentId([7; 32]),
            operation: AuthorityOperationKind::InvokeActor,
            runtime_deployment: DeploymentId([8; 32]),
            actor: Some(ActorId([9; 32])),
            actor_deployment: Some(DeploymentId([10; 32])),
            evidence: AuthorityEvidence {
                package: None,
                proof: None,
                commitment: Hash([11; 32]),
            },
            lane_roots: AuthorityLaneRoots {
                linear: Some(Hash([12; 32])),
                ..AuthorityLaneRoots::default()
            },
            epoch: 4,
            decision_sequence: 0,
            acknowledged_through: 0,
            valid_from: 20,
            expires_at: 30,
            request: Hash([13; 32]),
        }
    }

    fn binding(public_key: [u8; 32]) -> AgentAuthorityBinding {
        let selector = selector(ProducerId::of_public_key(&public_key));
        AgentAuthorityBinding {
            policy: selector.policy,
            issuer: selector.issuer,
            public_key,
            initial_epoch: selector.epoch,
        }
    }

    #[test]
    fn selector_binds_actor_and_runtime_deployments() {
        let key = [14; 32];
        let value = selector(ProducerId::of_public_key(&key));
        assert_eq!(value.validate(), Ok(()));
        let mut missing_actor = value.clone();
        missing_actor.actor = None;
        assert_eq!(
            missing_actor.validate(),
            Err(AuthorityReceiptError::InvalidSelector)
        );
    }

    #[test]
    fn logical_expiry_is_inclusive_and_deterministic() {
        let key = [14; 32];
        let value = selector(ProducerId::of_public_key(&key));
        assert!(!value.is_live_at(19));
        assert!(value.is_live_at(20));
        assert!(value.is_live_at(30));
        assert!(!value.is_live_at(31));
    }

    #[test]
    fn management_replay_fields_are_nonzero_and_scoped_away_from_invocations() {
        let key = [14; 32];
        let invocation = selector(ProducerId::of_public_key(&key));
        assert_eq!(invocation.validate(), Ok(()));

        let mut invalid_invocation = invocation.clone();
        invalid_invocation.decision_sequence = 1;
        assert_eq!(
            invalid_invocation.validate(),
            Err(AuthorityReceiptError::InvalidSelector)
        );

        let mut management = invocation;
        management.operation = AuthorityOperationKind::SuspendActor;
        management.decision_sequence = 9;
        management.acknowledged_through = 8;
        assert_eq!(management.validate(), Ok(()));

        let mut zero_sequence = management.clone();
        zero_sequence.decision_sequence = 0;
        zero_sequence.acknowledged_through = 0;
        assert_eq!(
            zero_sequence.validate(),
            Err(AuthorityReceiptError::InvalidSelector)
        );
        management.acknowledged_through = management.decision_sequence;
        assert_eq!(
            management.validate(),
            Err(AuthorityReceiptError::InvalidSelector)
        );
    }

    #[test]
    fn authority_binding_is_independent_of_self_described_receipt_fields() {
        let public_key = [14; 32];
        let anchor = binding(public_key);
        let receipt = AuthorityReceipt {
            selector: selector(ProducerId::of_public_key(&public_key)),
            public_key,
            signature: [15; 64],
        };
        assert!(anchor.is_valid());
        assert!(anchor.accepts(&receipt));
        assert_ne!(anchor.commitment(), Hash::ZERO);

        let mut attacker = receipt.clone();
        attacker.selector.policy = Hash([16; 32]);
        assert!(!anchor.accepts(&attacker));
        attacker = receipt.clone();
        attacker.selector.epoch = anchor.initial_epoch - 1;
        assert!(!anchor.accepts(&attacker));
        attacker = receipt;
        attacker.public_key = [17; 32];
        assert!(!anchor.accepts(&attacker));
    }

    #[test]
    fn credential_call_uses_injected_verification_and_exact_clean_preflight() {
        let call = credential_call(mutating_request());
        assert_eq!(call.validate_shape(), Ok(()));
        assert_eq!(call.verify_with(&TestCredentialVerifier), Ok(()));
        assert_ne!(
            call.principal,
            PrincipalId::of_public_key(&call.credential_public_key),
            "a revocable credential is not the durable Principal identity"
        );

        let context = InvocationContext {
            invocation: call.invocation,
            actor: call.authority.issuer.actor,
            mode: MethodMode::Linear,
            origin: crate::InvocationOrigin {
                principal: Some(call.principal),
                transport_node: call.authenticated_node,
                credential: Some(call.credential),
                actor: None,
                capability: None,
            },
            roles: InvocationRoleClaims::none(),
            observed_slot: 99,
        };
        assert!(call.matches_invocation_context(&context));

        let mut granted = context;
        granted.roles.space = Some(crate::RoleId([40; 32]));
        assert!(!call.matches_invocation_context(&granted));
        let mut relayed = context;
        relayed.origin.actor = Some(ActorId([41; 32]));
        assert!(!call.matches_invocation_context(&relayed));
        let mut wrong_credential = context;
        wrong_credential.origin.credential = Some(CredentialId([42; 32]));
        assert!(!call.matches_invocation_context(&wrong_credential));
    }

    #[test]
    fn credential_call_rejects_zero_mismatch_and_read_only_shapes() {
        let call = credential_call(mutating_request());

        let mut zero = call.clone();
        zero.invocation = InvocationId::ZERO;
        assert_eq!(
            zero.validate_shape(),
            Err(AuthorityActorProtocolError::InvalidTarget)
        );
        let mut wrong_credential = call.clone();
        wrong_credential.credential = CredentialId([43; 32]);
        assert_eq!(
            wrong_credential.validate_shape(),
            Err(AuthorityActorProtocolError::InvalidCaller)
        );
        let mut wrong_space = call.clone();
        wrong_space.managed.space = SpaceId([44; 32]);
        assert_eq!(
            wrong_space.validate_shape(),
            Err(AuthorityActorProtocolError::InvalidTarget)
        );
        let mut reverse_validity = call;
        reverse_validity.requested_valid_from = 121;
        assert_eq!(
            reverse_validity.validate_shape(),
            Err(AuthorityActorProtocolError::InvalidValidity)
        );

        for request in [
            ManagementRequest::InspectResources,
            ManagementRequest::InspectActors {
                after: None,
                limit: 1,
            },
        ] {
            assert_eq!(
                credential_call(request).validate_shape(),
                Err(AuthorityActorProtocolError::InvalidRequest)
            );
        }
    }

    #[test]
    fn approval_binds_exact_call_and_narrows_requested_validity() {
        let call = credential_call(mutating_request());
        let value = approval(&call);
        assert_eq!(value.validate_shape(), Ok(()));
        assert!(value.matches_call(&call));
        assert_ne!(value.commitment(), Hash::ZERO);

        let mut wider = value.clone();
        wider.valid_from = call.requested_valid_from - 1;
        assert!(!wider.matches_call(&call));
        let mut divergent = call.clone();
        divergent.signature[0] ^= 1;
        assert!(!value.matches_call(&divergent));
        let mut wrong_request = value;
        wrong_request.request_commitment = Hash([45; 32]);
        assert_eq!(
            wrong_request.validate_shape(),
            Err(AuthorityActorProtocolError::InvalidRequest)
        );
    }

    #[test]
    fn create_and_runtime_upgrade_cross_check_exact_targets() {
        let authority_public_key = [46; AUTHORITY_PUBLIC_KEY_BYTES];
        let mut authority = authority_target();
        authority.issuer.producer = ProducerId::of_public_key(&authority_public_key);
        let owner = PrincipalId([47; 32]);
        let creation_nonce = Hash([48; 32]);
        let agent = AgentId::derive(authority.space, owner, creation_nonce.as_bytes());
        let managed = ManagedAgentTarget {
            space: authority.space,
            agent,
            runtime_deployment: DeploymentId([49; 32]),
        };
        let descriptor = crate::AgentDescriptor {
            identity: crate::AgentIdentity {
                space: managed.space,
                agent: managed.agent,
                owner,
                profile: crate::AgentProfile::Local,
                runtime_deployment: managed.runtime_deployment,
                runtime_program: ProgramId([50; 32]),
                runtime_producer: ProducerId([51; 32]),
            },
            creation_nonce,
            authority: AgentAuthorityBinding {
                policy: Hash([52; 32]),
                issuer: authority.issuer,
                public_key: authority_public_key,
                initial_epoch: 2,
            },
            runtime_package: BlobRef {
                hash: Hash([53; 32]),
                len: 1,
            },
            runtime_contract: crate::contract::RuntimePackageContract::canonical(),
            capabilities: crate::RuntimeCapabilities::standard(),
            replicas: alloc::vec![crate::AgentReplica {
                node: NodeId([54; 32]),
                principal: owner,
                role: crate::ReplicaRole::Voter,
            }],
        };
        assert!(descriptor.validate().is_ok());

        let mut create = credential_call(ManagementRequest::Create(alloc::boxed::Box::new(
            descriptor.clone(),
        )));
        create.authority = authority;
        create.managed = managed;
        resign(&mut create);
        assert_eq!(create.validate_shape(), Ok(()));

        let mut wrong_issuer = descriptor.clone();
        wrong_issuer.authority.issuer.principal = PrincipalId([55; 32]);
        let mut wrong_issuer_call = create.clone();
        wrong_issuer_call.request = ManagementRequest::Create(alloc::boxed::Box::new(wrong_issuer));
        resign(&mut wrong_issuer_call);
        assert_eq!(
            wrong_issuer_call.validate_shape(),
            Err(AuthorityActorProtocolError::InvalidRequest)
        );

        let mut wrong_issuer = descriptor.clone();
        wrong_issuer.authority.public_key = [62; AUTHORITY_PUBLIC_KEY_BYTES];
        wrong_issuer.authority.issuer.producer =
            ProducerId::of_public_key(&wrong_issuer.authority.public_key);
        assert!(wrong_issuer.validate().is_ok());
        let mut wrong_issuer_call = create.clone();
        wrong_issuer_call.request = ManagementRequest::Create(alloc::boxed::Box::new(wrong_issuer));
        resign(&mut wrong_issuer_call);
        assert_eq!(
            wrong_issuer_call.validate_shape(),
            Err(AuthorityActorProtocolError::InvalidRequest)
        );

        let mut wrong_target = create;
        wrong_target.managed.runtime_deployment = DeploymentId([56; 32]);
        resign(&mut wrong_target);
        assert_eq!(
            wrong_target.validate_shape(),
            Err(AuthorityActorProtocolError::InvalidRequest)
        );

        let upgrade = crate::RuntimeUpgrade {
            from_deployment: managed.runtime_deployment,
            to_deployment: DeploymentId([57; 32]),
            to_program: ProgramId([58; 32]),
            producer: ProducerId([59; 32]),
            package: BlobRef {
                hash: Hash([60; 32]),
                len: 1,
            },
            contract: crate::contract::RuntimePackageContract::canonical(),
            capabilities: crate::RuntimeCapabilities::standard(),
        };
        let mut upgrade_call = credential_call(ManagementRequest::UpgradeRuntime(
            alloc::boxed::Box::new(upgrade.clone()),
        ));
        upgrade_call.authority = authority;
        upgrade_call.managed = managed;
        resign(&mut upgrade_call);
        assert_eq!(upgrade_call.validate_shape(), Ok(()));

        let mut wrong_from = upgrade;
        wrong_from.from_deployment = DeploymentId([61; 32]);
        upgrade_call.request =
            ManagementRequest::UpgradeRuntime(alloc::boxed::Box::new(wrong_from));
        resign(&mut upgrade_call);
        assert_eq!(
            upgrade_call.validate_shape(),
            Err(AuthorityActorProtocolError::InvalidRequest)
        );
    }
}
