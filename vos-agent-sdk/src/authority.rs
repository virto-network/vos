//! Guest-verifiable authority receipt model.

use core::num::NonZeroU64;

use alloc::vec::Vec;

use crate::private::NodeEncryptionEnrollment;
use crate::{
    ActorId, AgentId, BlobRef, CredentialId, DeploymentId, Hash, InvocationContext, InvocationId,
    InvocationRoleClaims, ManagementReply, ManagementRequest, MethodMode, NodeId, PrincipalId,
    ProducerId, ProgramId, SpaceId,
};

pub const AUTHORITY_PUBLIC_KEY_BYTES: usize = 32;
pub const AUTHORITY_SIGNATURE_BYTES: usize = 64;
pub const CREDENTIAL_PUBLIC_KEY_BYTES: usize = 32;
pub const CREDENTIAL_SIGNATURE_BYTES: usize = 64;

/// Exact installed system-authority route selected by a credential call.
///
/// The complete independently selected binding is carried here. An issuer
/// identity alone is not a trust anchor: policy, signing key, and initial
/// epoch must not be substituted while retaining the same actor route.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuthorityActorTarget {
    pub space: SpaceId,
    pub system_agent: AgentId,
    pub system_runtime_deployment: DeploymentId,
    pub binding: AgentAuthorityBinding,
}

impl AuthorityActorTarget {
    pub fn is_valid(self) -> bool {
        self.space != SpaceId::ZERO
            && self.system_agent != AgentId::ZERO
            && self.system_runtime_deployment != DeploymentId::ZERO
            && self.binding.is_valid()
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
    /// Rotate a Private Agent's owner/data epoch without changing members.
    RotatePrivateKeys = 13,
    /// Select a new content-addressed resource policy for a Private Agent.
    SetPrivateResourcePolicy = 14,
    /// Apply one owner-signed Private actor lifecycle control. The exact
    /// lifecycle request is committed by the PCTL and the actor is exposed in
    /// the receipt selector; Private controls do not expose a deployment.
    PrivateActorLifecycle = 15,
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
                | Self::PrivateActorLifecycle
        )
    }

    /// Private lifecycle controls bind an actor but deliberately keep its
    /// encrypted deployment details inside the signed PCTL request.
    pub const fn requires_actor_deployment(self) -> bool {
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
    /// Monotonic sequence in this credential's management-call domain.
    /// The authority actor accepts exactly the successor of its durable
    /// per-credential high-water mark.
    pub request_sequence: NonZeroU64,
    pub credential_public_key: [u8; CREDENTIAL_PUBLIC_KEY_BYTES],
    pub authenticated_node: Option<NodeId>,
    pub requested_valid_from: u64,
    pub requested_expires_at: u64,
    pub request: ManagementRequest,
    pub signature: [u8; CREDENTIAL_SIGNATURE_BYTES],
}

impl AuthorityCredentialCall {
    /// Commitment of every caller-selected field except the derived
    /// invocation and the signature. Keeping those two outputs out of this
    /// preimage avoids a circular derivation while still binding the complete
    /// management request and caller/target tuple.
    pub fn invocation_payload_commitment(&self) -> Hash {
        crate::wire::authority_credential_call_invocation_payload_commitment(self)
    }

    pub fn derive_invocation(
        credential: CredentialId,
        request_sequence: NonZeroU64,
        payload: Hash,
    ) -> InvocationId {
        InvocationId(
            Hash::digest(
                b"vos/agent/authority-management-invocation/v2",
                &[
                    crate::RUNTIME_ABI_ID.as_bytes(),
                    credential.as_bytes(),
                    &request_sequence.get().to_le_bytes(),
                    payload.as_bytes(),
                ],
            )
            .0,
        )
    }

    pub fn expected_invocation(&self) -> InvocationId {
        Self::derive_invocation(
            self.credential,
            self.request_sequence,
            self.invocation_payload_commitment(),
        )
    }

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
        if self.invocation != self.expected_invocation() {
            return Err(AuthorityActorProtocolError::InvalidTarget);
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
            && context.actor == self.authority.binding.issuer.actor
            && context.mode == MethodMode::Linear
            && context.origin.principal == Some(self.principal)
            && context.origin.credential == Some(self.credential)
            && context.origin.transport_node == self.authenticated_node
            && context.origin.actor.is_none()
            && context.origin.capability.is_none()
            && context.roles == InvocationRoleClaims::none()
    }
}

/// Credential ingress family retained by the system authority. Both kinds
/// use canonical Ed25519 public keys; the distinct tag prevents an API key
/// from being silently reclassified as an SSH enrollment (or vice versa).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum AuthorityCredentialKind {
    Ssh = 0,
    Api = 1,
}

/// Built-in Space role assigned to one enrolled Principal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum AuthorityBuiltinRole {
    Member = 0,
    Developer = 1,
    Admin = 2,
}

/// One typed credential enrollment. [`CredentialId`] remains derived from
/// the exact public key and is never interchangeable with a Principal or Node.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuthorityCredentialEnrollment {
    pub credential: CredentialId,
    pub kind: AuthorityCredentialKind,
    pub public_key: [u8; CREDENTIAL_PUBLIC_KEY_BYTES],
}

impl AuthorityCredentialEnrollment {
    pub fn from_public_key(
        kind: AuthorityCredentialKind,
        public_key: [u8; CREDENTIAL_PUBLIC_KEY_BYTES],
    ) -> Self {
        Self {
            credential: CredentialId::of_public_key(&public_key),
            kind,
            public_key,
        }
    }

    pub fn is_valid(self) -> bool {
        self.credential != CredentialId::ZERO
            && self.public_key != [0; CREDENTIAL_PUBLIC_KEY_BYTES]
            && CredentialId::of_public_key(&self.public_key) == self.credential
    }
}

/// One Admin-only mutation of the built-in identity authority.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuthorityAdminOperation {
    /// Enroll a Principal with Member role and its first active credential.
    EnrollPrincipal {
        principal: PrincipalId,
        credential: AuthorityCredentialEnrollment,
    },
    AddCredential {
        principal: PrincipalId,
        credential: AuthorityCredentialEnrollment,
    },
    RevokeCredential {
        principal: PrincipalId,
        credential: CredentialId,
    },
    /// Enroll one exact NEN1 transport/encryption identity. The enclosing
    /// Admin signature authorizes its Principal binding while NEN1's nested
    /// transport signature independently proves possession of the full
    /// Ed25519 PeerId.
    EnrollNode {
        enrollment: NodeEncryptionEnrollment,
    },
    UnbindNodeOwner {
        node: NodeId,
        owner: PrincipalId,
    },
    SetBuiltinRole {
        principal: PrincipalId,
        role: AuthorityBuiltinRole,
    },
}

impl AuthorityAdminOperation {
    pub fn validate_shape(&self) -> bool {
        match self {
            Self::EnrollPrincipal {
                principal,
                credential,
            }
            | Self::AddCredential {
                principal,
                credential,
            } => *principal != PrincipalId::ZERO && credential.is_valid(),
            Self::RevokeCredential {
                principal,
                credential,
            } => *principal != PrincipalId::ZERO && *credential != CredentialId::ZERO,
            Self::EnrollNode { enrollment } => enrollment.validate_shape(),
            Self::UnbindNodeOwner { node, owner } => {
                *node != NodeId::ZERO && *owner != PrincipalId::ZERO
            }
            Self::SetBuiltinRole { principal, .. } => *principal != PrincipalId::ZERO,
        }
    }

    pub fn commitment(&self) -> Hash {
        crate::wire::authority_admin_operation_commitment(self)
    }
}

/// Self-authenticating Admin mutation admitted through an unsigned Public
/// preflight. The credential signature covers the complete target, exact
/// Principal/Credential/transport Node tuple, logical slot, CAS generation,
/// and operation. Runtime Public admission does not authenticate these fields;
/// the authority actor verifies them against its durable state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorityAdminCall {
    pub invocation: InvocationId,
    pub authority: AuthorityActorTarget,
    pub administrator: PrincipalId,
    pub credential: CredentialId,
    /// Monotonic sequence in this credential's identity-administration
    /// domain. It is independent from the global projection generation.
    pub request_sequence: NonZeroU64,
    pub credential_public_key: [u8; CREDENTIAL_PUBLIC_KEY_BYTES],
    pub authenticated_node: NodeId,
    pub observed_slot: u64,
    pub expected_generation: NonZeroU64,
    pub operation: AuthorityAdminOperation,
    pub signature: [u8; CREDENTIAL_SIGNATURE_BYTES],
}

impl AuthorityAdminCall {
    /// Commitment of every caller-selected field except the derived
    /// invocation and signature.
    pub fn invocation_payload_commitment(&self) -> Hash {
        crate::wire::authority_admin_call_invocation_payload_commitment(self)
    }

    pub fn derive_invocation(
        credential: CredentialId,
        request_sequence: NonZeroU64,
        payload: Hash,
    ) -> InvocationId {
        InvocationId(
            Hash::digest(
                b"vos/agent/authority-admin-invocation/v3",
                &[
                    crate::RUNTIME_ABI_ID.as_bytes(),
                    credential.as_bytes(),
                    &request_sequence.get().to_le_bytes(),
                    payload.as_bytes(),
                ],
            )
            .0,
        )
    }

    pub fn expected_invocation(&self) -> InvocationId {
        Self::derive_invocation(
            self.credential,
            self.request_sequence,
            self.invocation_payload_commitment(),
        )
    }

    pub fn signing_bytes(&self) -> Vec<u8> {
        crate::wire::authority_admin_call_signing_bytes(self)
    }

    pub fn commitment(&self) -> Hash {
        Hash::digest(
            b"vos/agent/authority-admin-call/v2",
            &[&self.signing_bytes(), &self.signature],
        )
    }

    pub fn next_generation(&self) -> Option<NonZeroU64> {
        self.expected_generation
            .get()
            .checked_add(1)
            .and_then(NonZeroU64::new)
    }

    pub fn validate_shape(&self) -> Result<(), AuthorityActorProtocolError> {
        if self.invocation == InvocationId::ZERO || !self.authority.is_valid() {
            return Err(AuthorityActorProtocolError::InvalidTarget);
        }
        if self.administrator == PrincipalId::ZERO
            || self.credential == CredentialId::ZERO
            || self.credential_public_key == [0; CREDENTIAL_PUBLIC_KEY_BYTES]
            || CredentialId::of_public_key(&self.credential_public_key) != self.credential
            || self.authenticated_node == NodeId::ZERO
        {
            return Err(AuthorityActorProtocolError::InvalidCaller);
        }
        if !self.operation.validate_shape() || self.next_generation().is_none() {
            return Err(AuthorityActorProtocolError::InvalidRequest);
        }
        if self.invocation != self.expected_invocation() {
            return Err(AuthorityActorProtocolError::InvalidTarget);
        }
        if self.signature == [0; CREDENTIAL_SIGNATURE_BYTES] {
            return Err(AuthorityActorProtocolError::InvalidSignature);
        }
        if crate::wire::authority_admin_call_encoded_len(self) > crate::MAX_INVOCATION_MESSAGE_BYTES
        {
            return Err(AuthorityActorProtocolError::LimitExceeded);
        }
        Ok(())
    }

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

    pub fn matches_invocation_context(&self, context: &InvocationContext) -> bool {
        self.validate_shape().is_ok()
            && context.validate()
            && context.invocation == self.invocation
            && context.actor == self.authority.binding.issuer.actor
            && context.mode == MethodMode::Linear
            && context.observed_slot == self.observed_slot
            && context.origin.principal == Some(self.administrator)
            && context.origin.credential == Some(self.credential)
            && context.origin.transport_node == Some(self.authenticated_node)
            && context.origin.actor.is_none()
            && context.origin.capability.is_none()
            && context.roles == InvocationRoleClaims::none()
    }
}

/// Canonical applied Admin result. Embedding the complete signed call makes
/// the deterministic `expected + 1` generation part of that signature's
/// closure without storing an authority signing secret in actor state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorityAdminResult {
    pub call: AuthorityAdminCall,
    pub generation: NonZeroU64,
}

impl AuthorityAdminResult {
    pub fn from_call(call: AuthorityAdminCall) -> Result<Self, AuthorityActorProtocolError> {
        call.validate_shape()?;
        let generation = call
            .next_generation()
            .ok_or(AuthorityActorProtocolError::InvalidRequest)?;
        let result = Self { call, generation };
        result.validate_shape()?;
        Ok(result)
    }

    pub fn validate_shape(&self) -> Result<(), AuthorityActorProtocolError> {
        self.call.validate_shape()?;
        if self.call.next_generation() != Some(self.generation) {
            return Err(AuthorityActorProtocolError::InvalidApplication);
        }
        if crate::wire::authority_admin_result_encoded_len(self) > crate::MAX_INVOCATION_REPLY_BYTES
        {
            return Err(AuthorityActorProtocolError::LimitExceeded);
        }
        Ok(())
    }

    pub fn verify_with<V: AuthorityCredentialVerifier>(
        &self,
        verifier: &V,
    ) -> Result<(), AuthorityActorProtocolError> {
        self.validate_shape()?;
        self.call.verify_with(verifier)
    }

    pub fn commitment(&self) -> Hash {
        crate::wire::authority_admin_result_commitment(self)
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
    /// Distinct invocation ID reserved by the authority actor for the
    /// post-durability acknowledgement before this approval is published.
    pub acknowledgement_invocation: InvocationId,
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
    /// Derive the acknowledgement invocation reserved alongside one exact
    /// signed credential call. The authority actor must collision-check this
    /// value against every retained authorization and acknowledgement ID
    /// before admitting the call.
    pub fn derive_acknowledgement_invocation(call: &AuthorityCredentialCall) -> InvocationId {
        InvocationId(
            Hash::digest(
                b"vos/agent/management-acknowledgement-invocation/v1",
                &[
                    crate::RUNTIME_ABI_ID.as_bytes(),
                    call.invocation.as_bytes(),
                    call.commitment().as_bytes(),
                ],
            )
            .0,
        )
    }

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
            acknowledgement_invocation: Self::derive_acknowledgement_invocation(call),
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
            || self.acknowledgement_invocation == InvocationId::ZERO
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
            && self.acknowledgement_invocation == Self::derive_acknowledgement_invocation(call)
            && self.acknowledgement_invocation != call.invocation
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

/// Authority-signed acknowledgement produced only after the managed Agent's
/// exact result has been durably reopened.
///
/// Authorization and acknowledgement are distinct actor invocations. Reusing
/// the authorization invocation identifier for a different acknowledgement
/// message would violate the runtime's exact-retry contract, so both IDs are
/// explicit and must differ. The actor retains the ACC2 and MAP1 preimages;
/// this bounded message carries their commitments rather than embedding them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ManagementApplicationAck {
    pub authorization_invocation: InvocationId,
    pub acknowledgement_invocation: InvocationId,
    pub authority: AuthorityActorTarget,
    pub managed: ManagedAgentTarget,
    pub credential_call: Hash,
    pub approval: Hash,
    pub authorization_sequence: NonZeroU64,
    pub request: Hash,
    pub receipt: AuthorityReceipt,
    /// Exact typed reply durably reopened for this authorized request.
    pub application: ManagementReply,
    pub reopened_state: Hash,
    pub applied_at: u64,
    pub signature: [u8; AUTHORITY_SIGNATURE_BYTES],
}

impl ManagementApplicationAck {
    /// Bytes covered by the post-application authority signature.
    pub fn signing_bytes(&self) -> Vec<u8> {
        crate::wire::management_application_ack_signing_bytes(self)
    }

    pub fn commitment(&self) -> Hash {
        Hash::digest(
            b"vos/agent/management-application-ack/v2",
            &[&self.signing_bytes(), &self.signature],
        )
    }

    pub fn validate_shape(&self) -> Result<(), AuthorityActorProtocolError> {
        if self.authorization_invocation == InvocationId::ZERO
            || self.acknowledgement_invocation == InvocationId::ZERO
            || self.authorization_invocation == self.acknowledgement_invocation
            || !self.authority.is_valid()
            || !self.managed.is_valid()
            || self.authority.space != self.managed.space
        {
            return Err(AuthorityActorProtocolError::InvalidTarget);
        }
        if self.credential_call == Hash::ZERO
            || self.approval == Hash::ZERO
            || self.request == Hash::ZERO
            || !crate::wire::management_reply_valid(&self.application)
            || self.reopened_state == Hash::ZERO
            || self.signature == [0; AUTHORITY_SIGNATURE_BYTES]
        {
            return Err(AuthorityActorProtocolError::InvalidApplication);
        }
        let selector = &self.receipt.selector;
        if self.receipt.validate_shape().is_err()
            || !self.authority.binding.accepts(&self.receipt)
            || selector.space != self.managed.space
            || selector.agent != self.managed.agent
            || selector.runtime_deployment != self.managed.runtime_deployment
            || !selector.operation.uses_management_decision_journal()
            || selector.request != self.request
            || !selector.is_live_at(self.applied_at)
        {
            return Err(AuthorityActorProtocolError::InvalidApplication);
        }
        if crate::wire::management_application_ack_encoded_len(self)
            > crate::MAX_INVOCATION_MESSAGE_BYTES
        {
            return Err(AuthorityActorProtocolError::LimitExceeded);
        }
        Ok(())
    }

    /// Verify both the original receipt and the distinct post-application
    /// signature using the independently selected binding key.
    pub fn verify_with<V: AuthorityVerifier>(
        &self,
        verifier: &V,
    ) -> Result<(), AuthorityActorProtocolError> {
        self.validate_shape()?;
        self.receipt
            .verify_at(self.applied_at, verifier)
            .map_err(|_| AuthorityActorProtocolError::InvalidSignature)?;
        if !verifier.verify(
            &self.authority.binding.public_key,
            &self.signing_bytes(),
            &self.signature,
        ) {
            return Err(AuthorityActorProtocolError::InvalidSignature);
        }
        Ok(())
    }

    /// Match the exact actor-retained credential call and approval preimages.
    pub fn matches_pending(
        &self,
        call: &AuthorityCredentialCall,
        approval: &ManagementApproval,
    ) -> bool {
        self.validate_shape().is_ok()
            && approval.matches_call(call)
            && self.authorization_invocation == call.invocation
            && self.acknowledgement_invocation == approval.acknowledgement_invocation
            && self.authority == call.authority
            && self.authority == approval.authority
            && self.managed == call.managed
            && self.managed == approval.managed
            && self.credential_call == call.commitment()
            && self.credential_call == approval.credential_call
            && self.approval == approval.commitment()
            && self.authorization_sequence == approval.authorization_sequence
            && self.request == approval.request_commitment
            && management_application_reply_shape_matches(call, &self.application)
            && receipt_matches_approval(&self.receipt, approval)
    }

    /// Bind the acknowledgement to its own Linear actor invocation. The
    /// signature, rather than caller identity, authenticates the issuer, so a
    /// client may safely relay the exact acknowledgement bytes.
    pub fn matches_invocation_context(&self, context: &InvocationContext) -> bool {
        self.validate_shape().is_ok()
            && context.validate()
            && context.invocation == self.acknowledgement_invocation
            && context.actor == self.authority.binding.issuer.actor
            && context.mode == MethodMode::Linear
            && context.origin.actor.is_none()
            && context.origin.capability.is_none()
            && context.roles == InvocationRoleClaims::none()
    }
}

/// Match application facts using only fields present in ACC2. Every variant is
/// exact against the call except `ReplicasChanged`: its generation also binds
/// the Agent creation nonce, which ACC2 intentionally does not duplicate. The
/// authority actor must compare that value with its projected replica
/// transition before accepting MAA2; this SDK boundary only rejects zero or a
/// reply of the wrong variant.
fn management_application_reply_shape_matches(
    call: &AuthorityCredentialCall,
    application: &ManagementReply,
) -> bool {
    match (&call.request, application) {
        (ManagementRequest::Create(descriptor), ManagementReply::Created(identity)) => {
            *identity == descriptor.identity
        }
        (ManagementRequest::Install(install), ManagementReply::Installed(entry)) => {
            *entry == install.entry
        }
        (ManagementRequest::UpgradeActor(upgrade), ManagementReply::Upgraded(entry)) => {
            entry.actor == upgrade.actor
                && entry.deployment == upgrade.to_deployment
                && entry.program == upgrade.to_program
                && entry.package == upgrade.package
                && entry.agent_schema == upgrade.agent_schema
                && entry.method_policy == upgrade.method_policy
                && entry.constructor_abi == upgrade.constructor_abi
                && entry.state_layout == upgrade.state_layout
                && entry.lanes == upgrade.requirements.lanes
        }
        (
            ManagementRequest::Suspend {
                actor,
                expected_deployment,
            },
            ManagementReply::Suspended(entry),
        ) => entry.actor == *actor && entry.deployment == *expected_deployment && entry.suspended,
        (
            ManagementRequest::Resume {
                actor,
                expected_deployment,
            },
            ManagementReply::Resumed(entry),
        ) => entry.actor == *actor && entry.deployment == *expected_deployment && !entry.suspended,
        (ManagementRequest::RemoveLeaf { actor, .. }, ManagementReply::Removed(removed)) => {
            actor == removed
        }
        (
            ManagementRequest::UpgradeRuntime(upgrade),
            ManagementReply::RuntimeUpgraded(identity),
        ) => {
            identity.space == call.managed.space
                && identity.agent == call.managed.agent
                && identity.runtime_deployment == upgrade.to_deployment
                && identity.runtime_program == upgrade.to_program
                && identity.runtime_producer == upgrade.producer
        }
        (
            ManagementRequest::ChangeReplicas { .. },
            ManagementReply::ReplicasChanged { generation },
        ) => *generation != Hash::ZERO,
        (ManagementRequest::InspectActors { .. }, _)
        | (ManagementRequest::InspectResources, _)
        | (_, ManagementReply::Actors(_))
        | (_, ManagementReply::Resources(_))
        | (_, ManagementReply::Created(_))
        | (_, ManagementReply::Installed(_))
        | (_, ManagementReply::Upgraded(_))
        | (_, ManagementReply::Suspended(_))
        | (_, ManagementReply::Resumed(_))
        | (_, ManagementReply::Removed(_))
        | (_, ManagementReply::RuntimeUpgraded(_))
        | (_, ManagementReply::ReplicasChanged { .. }) => false,
    }
}

fn receipt_matches_approval(receipt: &AuthorityReceipt, approval: &ManagementApproval) -> bool {
    let selector = &receipt.selector;
    let actor = approval.request.authority_actor();
    selector.policy == approval.authority.binding.policy
        && selector.issuer == approval.authority.binding.issuer
        && selector.space == approval.managed.space
        && selector.agent == approval.managed.agent
        && Some(selector.operation) == approval.request.authority_operation()
        && selector.runtime_deployment == approval.managed.runtime_deployment
        && selector.actor == actor.map(|(actor, _)| actor)
        && selector.actor_deployment == actor.map(|(_, deployment)| deployment)
        && selector.evidence == approval.evidence
        && selector.lane_roots == approval.lane_roots
        && selector.epoch == approval.epoch
        && selector.valid_from == approval.valid_from
        && selector.expires_at == approval.expires_at
        && selector.request == approval.request_commitment
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
                && descriptor.authority == authority.binding
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
    InvalidApplication,
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
        match (self.operation.requires_actor(), self.actor) {
            (true, Some(actor)) if actor != ActorId::ZERO => {}
            (false, None) => {}
            _ => return Err(AuthorityReceiptError::InvalidSelector),
        }
        match (
            self.operation.requires_actor_deployment(),
            self.actor_deployment,
        ) {
            (true, Some(deployment)) if deployment != DeploymentId::ZERO => {}
            (false, None) => {}
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

    impl AuthorityVerifier for TestCredentialVerifier {
        fn verify(&self, public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
            *signature == test_signature(public_key, message)
        }
    }

    fn authority_target() -> AuthorityActorTarget {
        let public_key = [28; AUTHORITY_PUBLIC_KEY_BYTES];
        AuthorityActorTarget {
            space: SpaceId([21; 32]),
            system_agent: AgentId([22; 32]),
            system_runtime_deployment: DeploymentId([23; 32]),
            binding: AgentAuthorityBinding {
                policy: Hash([20; 32]),
                issuer: AuthorityIssuer {
                    principal: PrincipalId([24; 32]),
                    actor: ActorId([25; 32]),
                    deployment: DeploymentId([26; 32]),
                    program: ProgramId([27; 32]),
                    producer: ProducerId::of_public_key(&public_key),
                },
                public_key,
                initial_epoch: 1,
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
            invocation: InvocationId::ZERO,
            authority: authority_target(),
            managed: managed_target(),
            principal: PrincipalId([35; 32]),
            credential: CredentialId::of_public_key(&public_key),
            request_sequence: NonZeroU64::new(1).unwrap(),
            credential_public_key: public_key,
            authenticated_node: Some(NodeId([36; 32])),
            requested_valid_from: 100,
            requested_expires_at: 120,
            request,
            signature: [1; CREDENTIAL_SIGNATURE_BYTES],
        };
        call.invocation = call.expected_invocation();
        call.signature = test_signature(&public_key, &call.signing_bytes());
        call
    }

    fn resign(call: &mut AuthorityCredentialCall) {
        call.invocation = call.expected_invocation();
        call.signature = test_signature(&call.credential_public_key, &call.signing_bytes());
    }

    fn admin_call() -> AuthorityAdminCall {
        let public_key = [45; CREDENTIAL_PUBLIC_KEY_BYTES];
        let mut call = AuthorityAdminCall {
            invocation: InvocationId::ZERO,
            authority: authority_target(),
            administrator: PrincipalId([47; 32]),
            credential: CredentialId::of_public_key(&public_key),
            request_sequence: NonZeroU64::new(1).unwrap(),
            credential_public_key: public_key,
            authenticated_node: NodeId([48; 32]),
            observed_slot: 101,
            expected_generation: NonZeroU64::new(3).unwrap(),
            operation: AuthorityAdminOperation::EnrollPrincipal {
                principal: PrincipalId([49; 32]),
                credential: AuthorityCredentialEnrollment::from_public_key(
                    AuthorityCredentialKind::Ssh,
                    [50; CREDENTIAL_PUBLIC_KEY_BYTES],
                ),
            },
            signature: [1; CREDENTIAL_SIGNATURE_BYTES],
        };
        call.invocation = call.expected_invocation();
        call.signature = test_signature(&public_key, &call.signing_bytes());
        call
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

    fn application_ack(
        call: &AuthorityCredentialCall,
        approval: &ManagementApproval,
    ) -> ManagementApplicationAck {
        let (actor, deployment) = match call.request {
            ManagementRequest::Suspend {
                actor,
                expected_deployment,
            } => (actor, expected_deployment),
            _ => panic!("application acknowledgement fixture requires Suspend"),
        };
        let application = ManagementReply::Suspended(crate::ActorEntry {
            actor,
            name: "fixture".into(),
            parent: None,
            deployment,
            program: ProgramId([40; 32]),
            package: BlobRef::of_bytes(b"fixture-package"),
            agent_schema: BlobRef::of_bytes(b"fixture-schema"),
            method_policy: BlobRef::of_bytes(b"fixture-policy"),
            constructor_abi: Hash([41; 32]),
            installation_data: None,
            state_layout: Hash([42; 32]),
            lanes: crate::LaneSet::NONE,
            suspended: true,
        });
        let actor = approval.request.authority_actor();
        let mut receipt = AuthorityReceipt {
            selector: AuthorityReceiptSelector {
                policy: approval.authority.binding.policy,
                issuer: approval.authority.binding.issuer,
                space: approval.managed.space,
                agent: approval.managed.agent,
                operation: approval.request.authority_operation().unwrap(),
                runtime_deployment: approval.managed.runtime_deployment,
                actor: actor.map(|(actor, _)| actor),
                actor_deployment: actor.map(|(_, deployment)| deployment),
                evidence: approval.evidence.clone(),
                lane_roots: approval.lane_roots,
                epoch: approval.epoch,
                decision_sequence: 1,
                acknowledged_through: 0,
                valid_from: approval.valid_from,
                expires_at: approval.expires_at,
                request: approval.request_commitment,
            },
            public_key: approval.authority.binding.public_key,
            signature: [1; AUTHORITY_SIGNATURE_BYTES],
        };
        receipt.signature = test_signature(&receipt.public_key, &receipt.signing_bytes());
        let mut ack = ManagementApplicationAck {
            authorization_invocation: call.invocation,
            acknowledgement_invocation: approval.acknowledgement_invocation,
            authority: call.authority,
            managed: call.managed,
            credential_call: call.commitment(),
            approval: approval.commitment(),
            authorization_sequence: approval.authorization_sequence,
            request: approval.request_commitment,
            application,
            receipt,
            reopened_state: Hash([44; 32]),
            applied_at: approval.valid_from,
            signature: [1; AUTHORITY_SIGNATURE_BYTES],
        };
        ack.signature = test_signature(&ack.authority.binding.public_key, &ack.signing_bytes());
        ack
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
            actor: call.authority.binding.issuer.actor,
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
    fn admin_call_and_result_bind_exact_caller_context_operation_and_generation() {
        let call = admin_call();
        assert_eq!(call.validate_shape(), Ok(()));
        assert_eq!(call.verify_with(&TestCredentialVerifier), Ok(()));
        let context = InvocationContext {
            invocation: call.invocation,
            actor: call.authority.binding.issuer.actor,
            mode: MethodMode::Linear,
            origin: crate::InvocationOrigin {
                principal: Some(call.administrator),
                transport_node: Some(call.authenticated_node),
                credential: Some(call.credential),
                actor: None,
                capability: None,
            },
            roles: InvocationRoleClaims::none(),
            observed_slot: call.observed_slot,
        };
        assert!(call.matches_invocation_context(&context));

        let result = AuthorityAdminResult::from_call(call.clone()).unwrap();
        assert_eq!(result.generation.get(), call.expected_generation.get() + 1);
        assert_eq!(result.verify_with(&TestCredentialVerifier), Ok(()));

        let mut cross_node = call.clone();
        cross_node.authenticated_node = NodeId([51; 32]);
        assert_ne!(cross_node.signing_bytes(), call.signing_bytes());
        assert!(!cross_node.matches_invocation_context(&context));
        let mut stale = call.clone();
        stale.expected_generation = NonZeroU64::new(2).unwrap();
        assert_ne!(stale.signing_bytes(), call.signing_bytes());
        let mut forged = call;
        forged.signature[0] ^= 1;
        assert_eq!(
            forged.verify_with(&TestCredentialVerifier),
            Err(AuthorityActorProtocolError::InvalidSignature),
        );
    }

    #[test]
    fn approval_binds_exact_call_and_narrows_requested_validity() {
        let call = credential_call(mutating_request());
        let value = approval(&call);
        assert_eq!(value.validate_shape(), Ok(()));
        assert!(value.matches_call(&call));
        assert_eq!(
            value.acknowledgement_invocation,
            ManagementApproval::derive_acknowledgement_invocation(&call)
        );
        assert_ne!(value.acknowledgement_invocation, call.invocation);
        assert_ne!(value.commitment(), Hash::ZERO);

        let mut wider = value.clone();
        wider.valid_from = call.requested_valid_from - 1;
        assert!(!wider.matches_call(&call));
        let mut divergent = call.clone();
        divergent.signature[0] ^= 1;
        assert!(!value.matches_call(&divergent));
        let mut wrong_acknowledgement = value.clone();
        wrong_acknowledgement.acknowledgement_invocation = InvocationId([46; 32]);
        assert_eq!(wrong_acknowledgement.validate_shape(), Ok(()));
        assert!(!wrong_acknowledgement.matches_call(&call));
        let mut wrong_request = value;
        wrong_request.request_commitment = Hash([45; 32]);
        assert_eq!(
            wrong_request.validate_shape(),
            Err(AuthorityActorProtocolError::InvalidRequest)
        );
    }

    #[test]
    fn application_ack_requires_distinct_invocation_exact_pending_preimages_and_two_signatures() {
        let call = credential_call(mutating_request());
        let approval = approval(&call);
        let ack = application_ack(&call, &approval);
        assert_eq!(ack.validate_shape(), Ok(()));
        assert!(ack.matches_pending(&call, &approval));
        assert_eq!(ack.verify_with(&TestCredentialVerifier), Ok(()));
        assert_ne!(ack.commitment(), Hash::ZERO);

        let context = InvocationContext {
            invocation: ack.acknowledgement_invocation,
            actor: ack.authority.binding.issuer.actor,
            mode: MethodMode::Linear,
            origin: crate::InvocationOrigin {
                principal: None,
                transport_node: None,
                credential: None,
                actor: None,
                capability: None,
            },
            roles: InvocationRoleClaims::none(),
            observed_slot: ack.applied_at,
        };
        assert!(ack.matches_invocation_context(&context));

        let mut reused_invocation = ack.clone();
        reused_invocation.acknowledgement_invocation = reused_invocation.authorization_invocation;
        assert_eq!(
            reused_invocation.validate_shape(),
            Err(AuthorityActorProtocolError::InvalidTarget)
        );
        let mut wrong_approval = ack.clone();
        wrong_approval.approval = Hash([45; 32]);
        assert!(!wrong_approval.matches_pending(&call, &approval));
        let mut wrong_reserved_invocation = ack.clone();
        wrong_reserved_invocation.acknowledgement_invocation = InvocationId([46; 32]);
        wrong_reserved_invocation.signature = test_signature(
            &wrong_reserved_invocation.authority.binding.public_key,
            &wrong_reserved_invocation.signing_bytes(),
        );
        assert!(!wrong_reserved_invocation.matches_pending(&call, &approval));
        let mut expired = ack.clone();
        expired.applied_at = expired.receipt.selector.expires_at + 1;
        assert_eq!(
            expired.validate_shape(),
            Err(AuthorityActorProtocolError::InvalidApplication)
        );
        let mut forged_receipt = ack.clone();
        forged_receipt.receipt.signature[0] ^= 1;
        forged_receipt.signature = test_signature(
            &forged_receipt.authority.binding.public_key,
            &forged_receipt.signing_bytes(),
        );
        assert_eq!(
            forged_receipt.verify_with(&TestCredentialVerifier),
            Err(AuthorityActorProtocolError::InvalidSignature)
        );
        let mut forged_ack = ack.clone();
        forged_ack.signature[0] ^= 1;
        assert_eq!(
            forged_ack.verify_with(&TestCredentialVerifier),
            Err(AuthorityActorProtocolError::InvalidSignature)
        );
        let mut wrong_context = context;
        wrong_context.invocation = call.invocation;
        assert!(!ack.matches_invocation_context(&wrong_context));
    }

    #[test]
    fn create_and_runtime_upgrade_cross_check_exact_targets() {
        let authority_public_key = [46; AUTHORITY_PUBLIC_KEY_BYTES];
        let mut authority = authority_target();
        authority.binding.policy = Hash([52; 32]);
        authority.binding.public_key = authority_public_key;
        authority.binding.issuer.producer = ProducerId::of_public_key(&authority_public_key);
        authority.binding.initial_epoch = 2;
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
            authority: authority.binding,
            private_recovery: None,
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
