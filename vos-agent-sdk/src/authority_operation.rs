//! Self-authenticating authority calls for non-management operation domains.
//!
//! Management keeps its ACC1/MAP1/MAA1 replay protocol. This sibling family
//! covers invocation, catalog, and Private-Agent controls without widening or
//! accepting those older wire generations. A call authenticates the complete
//! requested intent with a credential signature; an approval materializes the
//! exact selector which an authority signer may turn into an [`AuthorityReceipt`].

use alloc::vec::Vec;
use core::num::NonZeroU64;

use vos_protocol::wire::{DecodeError, Decoder, Encoder};

use crate::authority::{
    AuthorityActorTarget, AuthorityCredentialVerifier, AuthorityEvidence, AuthorityLaneRoots,
    AuthorityOperationKind, AuthorityReceipt, AuthorityReceiptSelector, AuthorityVerifier,
    CREDENTIAL_PUBLIC_KEY_BYTES, CREDENTIAL_SIGNATURE_BYTES, ManagedAgentTarget,
};
use crate::catalog::{
    CatalogActorTarget, CatalogAlias, CatalogMutationKind, CatalogMutationRequest,
    CatalogPublication,
};
use crate::private::{
    MAX_PRIVATE_NODES, PrivateControlOperation, PrivateControlRecord, PrivateNodeIdentity,
};
use crate::wire::CanonicalWire;
use crate::{
    ActorId, AgentId, CredentialId, DeploymentId, Hash, InvocationContext, InvocationId,
    InvocationOrigin, InvocationRoleClaims, InvocationWork, MethodMode, NodeId, PrincipalId,
    SpaceId,
};

const HEADER_BYTES: usize = 4 + 32;

/// AOC1 is intentionally small even though the generic invocation message
/// ceiling is larger. Private ciphertext and actor messages are represented
/// only by exact commitments here.
pub const MAX_AUTHORITY_OPERATION_CALL_WIRE_BYTES: usize = 4 * 1024;
/// AOP1 repeats the call's identity tuple and one complete receipt selector.
pub const MAX_AUTHORITY_OPERATION_APPROVAL_WIRE_BYTES: usize = 4 * 1024;

/// Typed non-management authority intent.
///
/// Repeated target fields are deliberate: they let an approval fully
/// materialize a receipt selector while matching the original canonical
/// operation preimage at the eventual consumer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuthorityOperationIntent {
    InvokeActor {
        managed: ManagedAgentTarget,
        operation_invocation: InvocationId,
        actor: ActorId,
        actor_deployment: DeploymentId,
        work: Hash,
        origin: InvocationOrigin,
        roles: InvocationRoleClaims,
    },
    Catalog {
        managed: ManagedAgentTarget,
        operation_invocation: InvocationId,
        catalog: CatalogActorTarget,
        alias: CatalogAlias,
        kind: CatalogMutationKind,
        publication: CatalogPublication,
        publication_commitment: Hash,
        /// Zero denotes no current entry. The authority deterministically
        /// allocates `expected_current_generation + 1`.
        expected_current_generation: u64,
    },
    InvitePrivateNode {
        managed: ManagedAgentTarget,
        control: Hash,
        control_sequence: u64,
        control_previous: Option<Hash>,
        epoch: u64,
        node: NodeId,
        node_identity: Hash,
    },
    RevokePrivateNode {
        managed: ManagedAgentTarget,
        control: Hash,
        control_sequence: u64,
        control_previous: Option<Hash>,
        epoch: u64,
        node: NodeId,
        member_set: Hash,
    },
    RecoverPrivateAgent {
        managed: ManagedAgentTarget,
        control: Hash,
        control_sequence: u64,
        control_previous: Option<Hash>,
        epoch: u64,
        member_set: Hash,
        recovery_evidence: Hash,
    },
}

impl AuthorityOperationIntent {
    /// Bind every immutable field of one actor invocation while keeping the
    /// potentially 8 KiB message out of the authority call itself.
    pub fn invoke(work: &InvocationWork) -> Result<Self, AuthorityOperationProtocolError> {
        if !work.validate() {
            return Err(AuthorityOperationProtocolError::InvalidIntent);
        }
        Ok(Self::InvokeActor {
            managed: ManagedAgentTarget {
                space: work.space,
                agent: work.agent,
                runtime_deployment: work.runtime_deployment,
            },
            operation_invocation: work.invocation,
            actor: work.actor,
            actor_deployment: work.deployment,
            work: work.commitment(),
            origin: work.origin,
            roles: work.roles,
        })
    }

    /// Construct the exact catalog request template. The authority allocates
    /// the next generation; no caller-selected next generation is accepted.
    pub fn catalog(
        operation_invocation: InvocationId,
        catalog: CatalogActorTarget,
        alias: CatalogAlias,
        kind: CatalogMutationKind,
        publication: CatalogPublication,
        expected_current_generation: u64,
    ) -> Result<Self, AuthorityOperationProtocolError> {
        let value = Self::Catalog {
            managed: ManagedAgentTarget {
                space: publication.identity.space,
                agent: publication.identity.agent,
                runtime_deployment: publication.identity.runtime_deployment,
            },
            operation_invocation,
            catalog,
            alias,
            kind,
            publication_commitment: catalog_publication_commitment(&publication),
            publication,
            expected_current_generation,
        };
        value.validate_shape()?;
        Ok(value)
    }

    /// Project an exact signed PCTL record into the authority policy fields
    /// relevant to Invite, Revoke, or offline Recover.
    pub fn private_control(
        runtime_deployment: DeploymentId,
        control: &PrivateControlRecord,
    ) -> Result<Self, AuthorityOperationProtocolError> {
        if runtime_deployment == DeploymentId::ZERO || !control.validate_shape() {
            return Err(AuthorityOperationProtocolError::InvalidIntent);
        }
        let managed = ManagedAgentTarget {
            space: control.space,
            agent: control.agent,
            runtime_deployment,
        };
        let commitment = control.commitment();
        let value = match &control.operation {
            PrivateControlOperation::Invite { node, epoch, .. } => Self::InvitePrivateNode {
                managed,
                control: commitment,
                control_sequence: control.sequence,
                control_previous: control.previous,
                epoch: *epoch,
                node: node.node,
                node_identity: private_node_identity_commitment(node),
            },
            PrivateControlOperation::Revoke { node, next_epoch } => Self::RevokePrivateNode {
                managed,
                control: commitment,
                control_sequence: control.sequence,
                control_previous: control.previous,
                epoch: next_epoch.epoch,
                node: *node,
                member_set: private_member_set_commitment(
                    next_epoch.sealed_owner_keys.iter().map(|key| key.node),
                )
                .ok_or(AuthorityOperationProtocolError::InvalidIntent)?,
            },
            PrivateControlOperation::Recover {
                replacement_nodes,
                next_epoch,
                ..
            } => Self::RecoverPrivateAgent {
                managed,
                control: commitment,
                control_sequence: control.sequence,
                control_previous: control.previous,
                epoch: next_epoch.epoch,
                member_set: private_member_set_commitment(
                    replacement_nodes.iter().map(|node| node.node),
                )
                .ok_or(AuthorityOperationProtocolError::InvalidIntent)?,
                recovery_evidence: private_recovery_evidence_commitment(control)
                    .ok_or(AuthorityOperationProtocolError::InvalidIntent)?,
            },
            PrivateControlOperation::RotateKeys { .. }
            | PrivateControlOperation::SetResourcePolicy { .. }
            | PrivateControlOperation::ActorLifecycle { .. } => {
                return Err(AuthorityOperationProtocolError::UnsupportedIntent);
            }
        };
        value.validate_shape()?;
        Ok(value)
    }

    pub fn operation(&self) -> AuthorityOperationKind {
        match self {
            Self::InvokeActor { .. } => AuthorityOperationKind::InvokeActor,
            Self::Catalog { .. } => AuthorityOperationKind::PublishCatalog,
            Self::InvitePrivateNode { .. } => AuthorityOperationKind::InvitePrivateNode,
            Self::RevokePrivateNode { .. } => AuthorityOperationKind::RevokePrivateNode,
            Self::RecoverPrivateAgent { .. } => AuthorityOperationKind::RecoverPrivateAgent,
        }
    }

    pub fn managed(&self) -> ManagedAgentTarget {
        match self {
            Self::InvokeActor { managed, .. }
            | Self::Catalog { managed, .. }
            | Self::InvitePrivateNode { managed, .. }
            | Self::RevokePrivateNode { managed, .. }
            | Self::RecoverPrivateAgent { managed, .. } => *managed,
        }
    }

    pub fn validate_shape(&self) -> Result<(), AuthorityOperationProtocolError> {
        let valid = match self {
            Self::InvokeActor {
                managed,
                operation_invocation,
                actor,
                actor_deployment,
                work,
                origin,
                roles,
            } => {
                managed.is_valid()
                    && *operation_invocation != InvocationId::ZERO
                    && *actor != ActorId::ZERO
                    && *actor_deployment != DeploymentId::ZERO
                    && *work != Hash::ZERO
                    && origin.validate()
                    && roles.validate_for(*origin)
            }
            Self::Catalog {
                managed,
                operation_invocation,
                catalog,
                alias,
                publication,
                publication_commitment,
                expected_current_generation,
                ..
            } => {
                managed.is_valid()
                    && *operation_invocation != InvocationId::ZERO
                    && catalog.is_valid()
                    && alias.is_valid()
                    && publication.is_valid()
                    && publication.identity.space == managed.space
                    && publication.identity.agent == managed.agent
                    && publication.identity.runtime_deployment == managed.runtime_deployment
                    && catalog.space == managed.space
                    && *publication_commitment != Hash::ZERO
                    && *publication_commitment == catalog_publication_commitment(publication)
                    && expected_current_generation.checked_add(1).is_some()
                    && self.catalog_request_unchecked().is_some()
            }
            Self::InvitePrivateNode {
                managed,
                control,
                control_sequence,
                control_previous,
                node,
                node_identity,
                ..
            } => {
                managed.is_valid()
                    && *control != Hash::ZERO
                    && valid_owner_control_position(*control_sequence, *control_previous)
                    && *node != NodeId::ZERO
                    && *node_identity != Hash::ZERO
            }
            Self::RevokePrivateNode {
                managed,
                control,
                control_sequence,
                control_previous,
                node,
                member_set,
                ..
            } => {
                managed.is_valid()
                    && *control != Hash::ZERO
                    && valid_owner_control_position(*control_sequence, *control_previous)
                    && *node != NodeId::ZERO
                    && *member_set != Hash::ZERO
            }
            Self::RecoverPrivateAgent {
                managed,
                control,
                control_sequence,
                control_previous,
                member_set,
                recovery_evidence,
                ..
            } => {
                managed.is_valid()
                    && *control != Hash::ZERO
                    && valid_recovery_control_position(*control_sequence, *control_previous)
                    && *member_set != Hash::ZERO
                    && *recovery_evidence != Hash::ZERO
            }
        };
        valid
            .then_some(())
            .ok_or(AuthorityOperationProtocolError::InvalidIntent)
    }

    /// The exact hash placed in the resulting authority receipt selector.
    pub fn request_commitment(&self) -> Option<Hash> {
        self.validate_shape().ok()?;
        match self {
            Self::InvokeActor { work, .. } => Some(*work),
            Self::Catalog { .. } => self
                .catalog_request_unchecked()
                .map(|request| request.commitment()),
            Self::InvitePrivateNode { control, .. }
            | Self::RevokePrivateNode { control, .. }
            | Self::RecoverPrivateAgent { control, .. } => Some(*control),
        }
    }

    /// Materialize the catalog operation after allocating the next generation.
    pub fn catalog_request(&self) -> Option<CatalogMutationRequest> {
        self.validate_shape().ok()?;
        self.catalog_request_unchecked()
    }

    fn catalog_request_unchecked(&self) -> Option<CatalogMutationRequest> {
        let Self::Catalog {
            operation_invocation,
            catalog,
            alias,
            kind,
            publication,
            expected_current_generation,
            ..
        } = self
        else {
            return None;
        };
        let generation = expected_current_generation
            .checked_add(1)
            .and_then(NonZeroU64::new)?;
        let request = CatalogMutationRequest {
            invocation: *operation_invocation,
            catalog: *catalog,
            alias: alias.clone(),
            generation,
            kind: *kind,
            publication: publication.clone(),
        };
        request.validate_shape().is_ok().then_some(request)
    }

    pub fn matches_invocation_work(&self, work: &InvocationWork) -> bool {
        if self.validate_shape().is_err() {
            return false;
        }
        let Ok(expected) = Self::invoke(work) else {
            return false;
        };
        self == &expected
    }

    pub fn matches_catalog_request(&self, request: &CatalogMutationRequest) -> bool {
        self.validate_shape().is_ok() && self.catalog_request_unchecked().as_ref() == Some(request)
    }

    pub fn matches_private_control(&self, control: &PrivateControlRecord) -> bool {
        self.validate_shape().is_ok()
            && Self::private_control(self.managed().runtime_deployment, control)
                .is_ok_and(|expected| self == &expected)
    }

    fn selector_actor(&self) -> (Option<ActorId>, Option<DeploymentId>) {
        match self {
            Self::InvokeActor {
                actor,
                actor_deployment,
                ..
            } => (Some(*actor), Some(*actor_deployment)),
            _ => (None, None),
        }
    }

    fn matches_authority(&self, authority: AuthorityActorTarget) -> bool {
        if self.managed().space != authority.space {
            return false;
        }
        match self {
            Self::Catalog { catalog, .. } => {
                catalog.space == authority.space
                    && catalog.system_agent == authority.system_agent
                    && catalog.system_runtime_deployment == authority.system_runtime_deployment
                    && catalog.authority == authority.binding
            }
            _ => true,
        }
    }

    fn matches_caller(
        &self,
        principal: PrincipalId,
        credential: CredentialId,
        authenticated_node: Option<NodeId>,
    ) -> bool {
        match self {
            Self::InvokeActor { origin, .. } => {
                origin.principal == Some(principal)
                    && origin.credential == Some(credential)
                    && origin.transport_node == authenticated_node
            }
            _ => true,
        }
    }
}

fn valid_owner_control_position(sequence: u64, previous: Option<Hash>) -> bool {
    match (sequence, previous) {
        (0, None) => true,
        (0, Some(_)) | (_, None) => false,
        (_, Some(previous)) => previous != Hash::ZERO,
    }
}

fn valid_recovery_control_position(sequence: u64, previous: Option<Hash>) -> bool {
    match (sequence, previous) {
        (_, None) => true,
        (0, Some(_)) => false,
        (_, Some(previous)) => previous != Hash::ZERO,
    }
}

/// Commitment repeated beside the full publication so a policy cannot
/// authorize one public identity while a catalog request carries another.
pub fn catalog_publication_commitment(publication: &CatalogPublication) -> Hash {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"ACPB");
    bytes.extend_from_slice(crate::RUNTIME_ABI_ID.as_bytes());
    crate::wire::encode_catalog_publication(&mut Encoder(&mut bytes), publication);
    Hash::digest(b"vos/agent/authority-catalog-publication/v1", &[&bytes])
}

fn private_node_identity_commitment(node: &PrivateNodeIdentity) -> Hash {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"APNI");
    bytes.extend_from_slice(crate::RUNTIME_ABI_ID.as_bytes());
    crate::wire::encode_private_node(&mut Encoder(&mut bytes), node);
    Hash::digest(b"vos/agent/authority-private-node/v1", &[&bytes])
}

fn private_member_set_commitment(nodes: impl Iterator<Item = NodeId>) -> Option<Hash> {
    let nodes: Vec<NodeId> = nodes.collect();
    if nodes.is_empty()
        || nodes.len() > MAX_PRIVATE_NODES
        || nodes.iter().any(|node| *node == NodeId::ZERO)
        || !nodes.windows(2).all(|pair| pair[0] < pair[1])
    {
        return None;
    }
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"APMS");
    bytes.extend_from_slice(crate::RUNTIME_ABI_ID.as_bytes());
    Encoder(&mut bytes).list(&nodes, |encoder, node| encoder.fixed(node.as_bytes()));
    Some(Hash::digest(
        b"vos/agent/authority-private-member-set/v1",
        &[&bytes],
    ))
}

fn private_recovery_evidence_commitment(control: &PrivateControlRecord) -> Option<Hash> {
    let PrivateControlOperation::Recover {
        superseded_heads,
        next_epoch,
        replacement_nodes,
        historical_keyring,
    } = &control.operation
    else {
        return None;
    };
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"APRE");
    bytes.extend_from_slice(crate::RUNTIME_ABI_ID.as_bytes());
    let mut encoder = Encoder(&mut bytes);
    encoder.list(superseded_heads, |encoder, head| {
        encoder.fixed(head.as_bytes())
    });
    crate::wire::encode_private_epoch(&mut encoder, next_epoch);
    encoder.list(replacement_nodes, crate::wire::encode_private_node);
    crate::wire::encode_private_recovery_keyring_grant(&mut encoder, historical_keyring);
    Some(Hash::digest(
        b"vos/agent/authority-private-recovery-evidence/v1",
        &[&bytes],
    ))
}

/// Credential-signed request to the exact installed authority actor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorityOperationCall {
    pub invocation: InvocationId,
    pub authority: AuthorityActorTarget,
    pub principal: PrincipalId,
    pub credential: CredentialId,
    pub credential_public_key: [u8; CREDENTIAL_PUBLIC_KEY_BYTES],
    pub authenticated_node: Option<NodeId>,
    pub requested_valid_from: u64,
    pub requested_expires_at: u64,
    pub intent: AuthorityOperationIntent,
    pub signature: [u8; CREDENTIAL_SIGNATURE_BYTES],
}

impl AuthorityOperationCall {
    pub fn signing_bytes(&self) -> Vec<u8> {
        authority_operation_call_signing_bytes(self)
    }

    pub fn commitment(&self) -> Hash {
        Hash::digest(
            b"vos/agent/authority-operation-call/v1",
            &[&self.signing_bytes(), &self.signature],
        )
    }

    pub fn validate_shape(&self) -> Result<(), AuthorityOperationProtocolError> {
        if self.invocation == InvocationId::ZERO
            || !self.authority.is_valid()
            || !self.intent.matches_authority(self.authority)
        {
            return Err(AuthorityOperationProtocolError::InvalidTarget);
        }
        if self.principal == PrincipalId::ZERO
            || self.credential == CredentialId::ZERO
            || self.credential_public_key == [0; CREDENTIAL_PUBLIC_KEY_BYTES]
            || CredentialId::of_public_key(&self.credential_public_key) != self.credential
            || self.authenticated_node == Some(NodeId::ZERO)
        {
            return Err(AuthorityOperationProtocolError::InvalidCaller);
        }
        self.intent.validate_shape()?;
        if !self
            .intent
            .matches_caller(self.principal, self.credential, self.authenticated_node)
        {
            return Err(AuthorityOperationProtocolError::InvalidCaller);
        }
        if self.requested_valid_from > self.requested_expires_at {
            return Err(AuthorityOperationProtocolError::InvalidValidity);
        }
        if self.signature == [0; CREDENTIAL_SIGNATURE_BYTES] {
            return Err(AuthorityOperationProtocolError::InvalidSignature);
        }
        if authority_operation_call_encoded_len(self) > MAX_AUTHORITY_OPERATION_CALL_WIRE_BYTES {
            return Err(AuthorityOperationProtocolError::LimitExceeded);
        }
        Ok(())
    }

    pub fn verify_with<V: AuthorityCredentialVerifier>(
        &self,
        verifier: &V,
    ) -> Result<(), AuthorityOperationProtocolError> {
        self.validate_shape()?;
        if !verifier.verify(
            &self.credential_public_key,
            &self.signing_bytes(),
            &self.signature,
        ) {
            return Err(AuthorityOperationProtocolError::InvalidSignature);
        }
        Ok(())
    }

    /// Bind the self-authenticating message to its public authority-actor
    /// invocation. Requested application roles are inside the signed intent,
    /// never ambient roles on this ingress call.
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

/// Deterministic policy output for one non-management operation call.
///
/// `authorization_sequence` is the authority actor's own exact-retry clock.
/// It is intentionally distinct from the selector's management decision
/// clock, which must remain zero for every operation in this protocol.
/// Shape validation alone cannot reconstruct `operation_call`: before signing
/// a receipt, a consumer must reopen the retained AOC1 preimage and require
/// [`AuthorityOperationApproval::matches_call`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorityOperationApproval {
    pub operation_call: Hash,
    pub authorization_sequence: NonZeroU64,
    pub invocation: InvocationId,
    pub authority: AuthorityActorTarget,
    pub principal: PrincipalId,
    pub credential: CredentialId,
    pub credential_public_key: [u8; CREDENTIAL_PUBLIC_KEY_BYTES],
    pub authenticated_node: Option<NodeId>,
    pub intent: AuthorityOperationIntent,
    pub selector: AuthorityReceiptSelector,
}

impl AuthorityOperationApproval {
    #[allow(clippy::too_many_arguments)]
    /// Build an approval directly from its retained call preimage. Code which
    /// decodes an AOP1 instead must make the equivalent `matches_call` check
    /// before signing the materialized selector.
    pub fn from_call(
        call: &AuthorityOperationCall,
        authorization_sequence: NonZeroU64,
        evidence: AuthorityEvidence,
        lane_roots: AuthorityLaneRoots,
        epoch: u64,
        valid_from: u64,
        expires_at: u64,
    ) -> Result<Self, AuthorityOperationProtocolError> {
        call.validate_shape()?;
        if valid_from < call.requested_valid_from
            || expires_at > call.requested_expires_at
            || valid_from > expires_at
        {
            return Err(AuthorityOperationProtocolError::InvalidValidity);
        }
        let (actor, actor_deployment) = call.intent.selector_actor();
        let request = call
            .intent
            .request_commitment()
            .ok_or(AuthorityOperationProtocolError::InvalidIntent)?;
        let value = Self {
            operation_call: call.commitment(),
            authorization_sequence,
            invocation: call.invocation,
            authority: call.authority,
            principal: call.principal,
            credential: call.credential,
            credential_public_key: call.credential_public_key,
            authenticated_node: call.authenticated_node,
            intent: call.intent.clone(),
            selector: AuthorityReceiptSelector {
                policy: call.authority.binding.policy,
                issuer: call.authority.binding.issuer,
                space: call.intent.managed().space,
                agent: call.intent.managed().agent,
                operation: call.intent.operation(),
                runtime_deployment: call.intent.managed().runtime_deployment,
                actor,
                actor_deployment,
                evidence,
                lane_roots,
                epoch,
                decision_sequence: 0,
                acknowledged_through: 0,
                valid_from,
                expires_at,
                request,
            },
        };
        value.validate_shape()?;
        if !value.matches_call(call) {
            return Err(AuthorityOperationProtocolError::MismatchedCall);
        }
        Ok(value)
    }

    pub fn validate_shape(&self) -> Result<(), AuthorityOperationProtocolError> {
        if self.operation_call == Hash::ZERO
            || self.invocation == InvocationId::ZERO
            || !self.authority.is_valid()
            || !self.intent.matches_authority(self.authority)
        {
            return Err(AuthorityOperationProtocolError::InvalidTarget);
        }
        if self.principal == PrincipalId::ZERO
            || self.credential == CredentialId::ZERO
            || self.credential_public_key == [0; CREDENTIAL_PUBLIC_KEY_BYTES]
            || CredentialId::of_public_key(&self.credential_public_key) != self.credential
            || self.authenticated_node == Some(NodeId::ZERO)
        {
            return Err(AuthorityOperationProtocolError::InvalidCaller);
        }
        self.intent.validate_shape()?;
        if !self
            .intent
            .matches_caller(self.principal, self.credential, self.authenticated_node)
        {
            return Err(AuthorityOperationProtocolError::InvalidCaller);
        }
        let managed = self.intent.managed();
        let (actor, actor_deployment) = self.intent.selector_actor();
        if self.selector.validate().is_err()
            || self.selector.policy != self.authority.binding.policy
            || self.selector.issuer != self.authority.binding.issuer
            || self.selector.space != managed.space
            || self.selector.agent != managed.agent
            || self.selector.runtime_deployment != managed.runtime_deployment
            || self.selector.operation != self.intent.operation()
            || self.selector.actor != actor
            || self.selector.actor_deployment != actor_deployment
            || self.selector.epoch < self.authority.binding.initial_epoch
            || self.selector.decision_sequence != 0
            || self.selector.acknowledged_through != 0
            || self.intent.request_commitment() != Some(self.selector.request)
        {
            return Err(AuthorityOperationProtocolError::InvalidApproval);
        }
        if authority_operation_approval_encoded_len(self)
            > MAX_AUTHORITY_OPERATION_APPROVAL_WIRE_BYTES
        {
            return Err(AuthorityOperationProtocolError::LimitExceeded);
        }
        Ok(())
    }

    pub fn matches_call(&self, call: &AuthorityOperationCall) -> bool {
        self.validate_shape().is_ok()
            && call.validate_shape().is_ok()
            && self.operation_call == call.commitment()
            && self.invocation == call.invocation
            && self.authority == call.authority
            && self.principal == call.principal
            && self.credential == call.credential
            && self.credential_public_key == call.credential_public_key
            && self.authenticated_node == call.authenticated_node
            && self.intent == call.intent
            && self.selector.valid_from >= call.requested_valid_from
            && self.selector.expires_at <= call.requested_expires_at
    }

    pub fn commitment(&self) -> Hash {
        authority_operation_approval_commitment(self)
    }

    /// Match the complete selector and independently selected signing key.
    pub fn matches_receipt(&self, receipt: &AuthorityReceipt) -> bool {
        self.validate_shape().is_ok()
            && receipt.validate_shape().is_ok()
            && receipt.selector == self.selector
            && receipt.public_key == self.authority.binding.public_key
            && self.authority.binding.accepts(receipt)
    }

    pub fn verify_receipt_at<V: AuthorityVerifier>(
        &self,
        receipt: &AuthorityReceipt,
        logical_slot: u64,
        verifier: &V,
    ) -> Result<(), AuthorityOperationProtocolError> {
        if !self.matches_receipt(receipt) {
            return Err(AuthorityOperationProtocolError::InvalidApproval);
        }
        receipt
            .verify_at(logical_slot, verifier)
            .map_err(|_| AuthorityOperationProtocolError::InvalidSignature)
    }

    pub fn matches_invocation_work(&self, work: &InvocationWork) -> bool {
        self.validate_shape().is_ok()
            && self.intent.matches_invocation_work(work)
            && self.selector.request == work.commitment()
    }

    pub fn matches_catalog_request(&self, request: &CatalogMutationRequest) -> bool {
        self.validate_shape().is_ok()
            && self.intent.matches_catalog_request(request)
            && self.selector.request == request.commitment()
    }

    pub fn matches_private_control(&self, control: &PrivateControlRecord) -> bool {
        self.validate_shape().is_ok()
            && self.intent.matches_private_control(control)
            && self.selector.request == control.commitment()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthorityOperationProtocolError {
    InvalidTarget,
    InvalidCaller,
    InvalidValidity,
    InvalidIntent,
    UnsupportedIntent,
    InvalidSignature,
    InvalidApproval,
    LimitExceeded,
    MismatchedCall,
}

impl core::fmt::Display for AuthorityOperationProtocolError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            formatter,
            "invalid authority operation protocol value: {self:?}"
        )
    }
}

impl core::error::Error for AuthorityOperationProtocolError {}

fn encode_managed(encoder: &mut Encoder<'_>, value: ManagedAgentTarget) {
    encoder.fixed(value.space.as_bytes());
    encoder.fixed(value.agent.as_bytes());
    encoder.fixed(value.runtime_deployment.as_bytes());
}

fn decode_managed(decoder: &mut Decoder<'_>) -> Result<ManagedAgentTarget, DecodeError> {
    let value = ManagedAgentTarget {
        space: SpaceId(decoder.fixed()?),
        agent: AgentId(decoder.fixed()?),
        runtime_deployment: DeploymentId(decoder.fixed()?),
    };
    value
        .is_valid()
        .then_some(value)
        .ok_or(DecodeError::NonCanonical)
}

fn encode_intent(encoder: &mut Encoder<'_>, value: &AuthorityOperationIntent) {
    match value {
        AuthorityOperationIntent::InvokeActor {
            managed,
            operation_invocation,
            actor,
            actor_deployment,
            work,
            origin,
            roles,
        } => {
            encoder.u8(0);
            encode_managed(encoder, *managed);
            encoder.fixed(operation_invocation.as_bytes());
            encoder.fixed(actor.as_bytes());
            encoder.fixed(actor_deployment.as_bytes());
            encoder.fixed(work.as_bytes());
            crate::wire::encode_origin(encoder, *origin);
            crate::wire::encode_invocation_roles(encoder, *roles);
        }
        AuthorityOperationIntent::Catalog {
            managed,
            operation_invocation,
            catalog,
            alias,
            kind,
            publication,
            publication_commitment,
            expected_current_generation,
        } => {
            encoder.u8(1);
            encode_managed(encoder, *managed);
            encoder.fixed(operation_invocation.as_bytes());
            crate::wire::encode_catalog_actor_target(encoder, *catalog);
            crate::wire::encode_catalog_alias(encoder, alias);
            crate::wire::encode_catalog_mutation_kind(encoder, *kind);
            crate::wire::encode_catalog_publication(encoder, publication);
            encoder.fixed(publication_commitment.as_bytes());
            encoder.u64(*expected_current_generation);
        }
        AuthorityOperationIntent::InvitePrivateNode {
            managed,
            control,
            control_sequence,
            control_previous,
            epoch,
            node,
            node_identity,
        } => {
            encoder.u8(2);
            encode_managed(encoder, *managed);
            encode_private_control_common(
                encoder,
                *control,
                *control_sequence,
                *control_previous,
                *epoch,
            );
            encoder.fixed(node.as_bytes());
            encoder.fixed(node_identity.as_bytes());
        }
        AuthorityOperationIntent::RevokePrivateNode {
            managed,
            control,
            control_sequence,
            control_previous,
            epoch,
            node,
            member_set,
        } => {
            encoder.u8(3);
            encode_managed(encoder, *managed);
            encode_private_control_common(
                encoder,
                *control,
                *control_sequence,
                *control_previous,
                *epoch,
            );
            encoder.fixed(node.as_bytes());
            encoder.fixed(member_set.as_bytes());
        }
        AuthorityOperationIntent::RecoverPrivateAgent {
            managed,
            control,
            control_sequence,
            control_previous,
            epoch,
            member_set,
            recovery_evidence,
        } => {
            encoder.u8(4);
            encode_managed(encoder, *managed);
            encode_private_control_common(
                encoder,
                *control,
                *control_sequence,
                *control_previous,
                *epoch,
            );
            encoder.fixed(member_set.as_bytes());
            encoder.fixed(recovery_evidence.as_bytes());
        }
    }
}

fn decode_intent(decoder: &mut Decoder<'_>) -> Result<AuthorityOperationIntent, DecodeError> {
    let value = match decoder.u8()? {
        0 => {
            let managed = decode_managed(decoder)?;
            let operation_invocation = InvocationId(decoder.fixed()?);
            let actor = ActorId(decoder.fixed()?);
            let actor_deployment = DeploymentId(decoder.fixed()?);
            let work = Hash(decoder.fixed()?);
            let origin = crate::wire::decode_origin(decoder)?;
            let roles = crate::wire::decode_invocation_roles(decoder, origin)?;
            AuthorityOperationIntent::InvokeActor {
                managed,
                operation_invocation,
                actor,
                actor_deployment,
                work,
                origin,
                roles,
            }
        }
        1 => AuthorityOperationIntent::Catalog {
            managed: decode_managed(decoder)?,
            operation_invocation: InvocationId(decoder.fixed()?),
            catalog: crate::wire::decode_catalog_actor_target(decoder)?,
            alias: crate::wire::decode_catalog_alias(decoder)?,
            kind: crate::wire::decode_catalog_mutation_kind(decoder)?,
            publication: crate::wire::decode_catalog_publication(decoder)?,
            publication_commitment: Hash(decoder.fixed()?),
            expected_current_generation: decoder.u64()?,
        },
        2 => {
            let managed = decode_managed(decoder)?;
            let (control, control_sequence, control_previous, epoch) =
                decode_private_control_common(decoder)?;
            AuthorityOperationIntent::InvitePrivateNode {
                managed,
                control,
                control_sequence,
                control_previous,
                epoch,
                node: NodeId(decoder.fixed()?),
                node_identity: Hash(decoder.fixed()?),
            }
        }
        3 => {
            let managed = decode_managed(decoder)?;
            let (control, control_sequence, control_previous, epoch) =
                decode_private_control_common(decoder)?;
            AuthorityOperationIntent::RevokePrivateNode {
                managed,
                control,
                control_sequence,
                control_previous,
                epoch,
                node: NodeId(decoder.fixed()?),
                member_set: Hash(decoder.fixed()?),
            }
        }
        4 => {
            let managed = decode_managed(decoder)?;
            let (control, control_sequence, control_previous, epoch) =
                decode_private_control_common(decoder)?;
            AuthorityOperationIntent::RecoverPrivateAgent {
                managed,
                control,
                control_sequence,
                control_previous,
                epoch,
                member_set: Hash(decoder.fixed()?),
                recovery_evidence: Hash(decoder.fixed()?),
            }
        }
        _ => return Err(DecodeError::InvalidTag),
    };
    value
        .validate_shape()
        .is_ok()
        .then_some(value)
        .ok_or(DecodeError::NonCanonical)
}

fn encode_private_control_common(
    encoder: &mut Encoder<'_>,
    control: Hash,
    sequence: u64,
    previous: Option<Hash>,
    epoch: u64,
) {
    encoder.fixed(control.as_bytes());
    encoder.u64(sequence);
    encoder.option(&previous, |encoder, previous| {
        encoder.fixed(previous.as_bytes())
    });
    encoder.u64(epoch);
}

fn decode_private_control_common(
    decoder: &mut Decoder<'_>,
) -> Result<(Hash, u64, Option<Hash>, u64), DecodeError> {
    Ok((
        Hash(decoder.fixed()?),
        decoder.u64()?,
        decoder.option(|decoder| Ok(Hash(decoder.fixed()?)))?,
        decoder.u64()?,
    ))
}

fn encode_call_unsigned(encoder: &mut Encoder<'_>, value: &AuthorityOperationCall) {
    encoder.fixed(value.invocation.as_bytes());
    crate::wire::encode_authority_actor_target(encoder, value.authority);
    crate::wire::encode_credential_caller(
        encoder,
        value.principal,
        value.credential,
        &value.credential_public_key,
        value.authenticated_node,
    );
    encoder.u64(value.requested_valid_from);
    encoder.u64(value.requested_expires_at);
    encode_intent(encoder, &value.intent);
}

fn authority_operation_call_signing_bytes(value: &AuthorityOperationCall) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"AOCS");
    bytes.extend_from_slice(crate::RUNTIME_ABI_ID.as_bytes());
    encode_call_unsigned(&mut Encoder(&mut bytes), value);
    bytes
}

fn authority_operation_call_encoded_len(value: &AuthorityOperationCall) -> usize {
    let mut bytes = Vec::new();
    encode_call_unsigned(&mut Encoder(&mut bytes), value);
    HEADER_BYTES
        .saturating_add(bytes.len())
        .saturating_add(CREDENTIAL_SIGNATURE_BYTES)
}

impl CanonicalWire for AuthorityOperationCall {
    const MAGIC: [u8; 4] = *b"AOC1";
    const MAX_ENCODED_BYTES: usize = MAX_AUTHORITY_OPERATION_CALL_WIRE_BYTES;

    fn validate_wire(&self) -> bool {
        self.validate_shape().is_ok()
    }

    fn encode_body(&self, encoder: &mut Encoder<'_>) {
        encode_call_unsigned(encoder, self);
        encoder.0.extend_from_slice(&self.signature);
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let invocation = InvocationId(decoder.fixed()?);
        let authority = crate::wire::decode_authority_actor_target(decoder)?;
        let (principal, credential, credential_public_key, authenticated_node) =
            crate::wire::decode_credential_caller(decoder)?;
        let value = Self {
            invocation,
            authority,
            principal,
            credential,
            credential_public_key,
            authenticated_node,
            requested_valid_from: decoder.u64()?,
            requested_expires_at: decoder.u64()?,
            intent: decode_intent(decoder)?,
            signature: decoder
                .take(CREDENTIAL_SIGNATURE_BYTES)?
                .try_into()
                .map_err(|_| DecodeError::Truncated)?,
        };
        value
            .validate_shape()
            .is_ok()
            .then_some(value)
            .ok_or(DecodeError::NonCanonical)
    }
}

fn encode_approval_body(encoder: &mut Encoder<'_>, value: &AuthorityOperationApproval) {
    encoder.fixed(value.operation_call.as_bytes());
    encoder.u64(value.authorization_sequence.get());
    encoder.fixed(value.invocation.as_bytes());
    crate::wire::encode_authority_actor_target(encoder, value.authority);
    crate::wire::encode_credential_caller(
        encoder,
        value.principal,
        value.credential,
        &value.credential_public_key,
        value.authenticated_node,
    );
    encode_intent(encoder, &value.intent);
    crate::wire::encode_authority_selector(encoder, &value.selector);
}

fn authority_operation_approval_encoded_len(value: &AuthorityOperationApproval) -> usize {
    let mut bytes = Vec::new();
    encode_approval_body(&mut Encoder(&mut bytes), value);
    HEADER_BYTES.saturating_add(bytes.len())
}

fn authority_operation_approval_commitment(value: &AuthorityOperationApproval) -> Hash {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"AOPC");
    bytes.extend_from_slice(crate::RUNTIME_ABI_ID.as_bytes());
    encode_approval_body(&mut Encoder(&mut bytes), value);
    Hash::digest(b"vos/agent/authority-operation-approval/v1", &[&bytes])
}

impl CanonicalWire for AuthorityOperationApproval {
    const MAGIC: [u8; 4] = *b"AOP1";
    const MAX_ENCODED_BYTES: usize = MAX_AUTHORITY_OPERATION_APPROVAL_WIRE_BYTES;

    fn validate_wire(&self) -> bool {
        self.validate_shape().is_ok()
    }

    fn encode_body(&self, encoder: &mut Encoder<'_>) {
        encode_approval_body(encoder, self);
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let operation_call = Hash(decoder.fixed()?);
        let authorization_sequence =
            NonZeroU64::new(decoder.u64()?).ok_or(DecodeError::NonCanonical)?;
        let invocation = InvocationId(decoder.fixed()?);
        let authority = crate::wire::decode_authority_actor_target(decoder)?;
        let (principal, credential, credential_public_key, authenticated_node) =
            crate::wire::decode_credential_caller(decoder)?;
        let value = Self {
            operation_call,
            authorization_sequence,
            invocation,
            authority,
            principal,
            credential,
            credential_public_key,
            authenticated_node,
            intent: decode_intent(decoder)?,
            selector: crate::wire::decode_authority_selector(decoder)?,
        };
        value
            .validate_shape()
            .is_ok()
            .then_some(value)
            .ok_or(DecodeError::NonCanonical)
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;
    use alloc::vec;

    use super::*;
    use crate::authority::{
        AUTHORITY_PUBLIC_KEY_BYTES, AUTHORITY_SIGNATURE_BYTES, AgentAuthorityBinding,
        AuthorityIssuer,
    };
    use crate::private::{
        EncryptedObjectKind, EncryptedPrivateObject, PRIVATE_NONCE_BYTES, PRIVATE_SIGNATURE_BYTES,
        PrivateControlSigner, PrivateKeyEpoch, PrivateRecoveryKeyringGrant, SealedPrivateKey,
        SealedRecoveryKey,
    };
    use crate::wire::WireError;
    use crate::{
        AgentIdentity, AgentProfile, BlobRef, CapabilityId, InvocationRoleClaims, ProducerId,
        ProgramId, RoleId, RuntimeBlob,
    };

    fn test_signature(public_key: &[u8; 32], message: &[u8]) -> [u8; 64] {
        let first = Hash::digest(b"vos/test/aoc-signature/first", &[public_key, message]);
        let second = Hash::digest(b"vos/test/aoc-signature/second", &[public_key, message]);
        let mut signature = [0; 64];
        signature[..32].copy_from_slice(first.as_bytes());
        signature[32..].copy_from_slice(second.as_bytes());
        signature
    }

    struct TestVerifier;

    impl AuthorityCredentialVerifier for TestVerifier {
        fn verify(&self, public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
            *signature == test_signature(public_key, message)
        }
    }

    impl AuthorityVerifier for TestVerifier {
        fn verify(&self, public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
            *signature == test_signature(public_key, message)
        }
    }

    fn authority_target() -> AuthorityActorTarget {
        let public_key = [0x19; AUTHORITY_PUBLIC_KEY_BYTES];
        AuthorityActorTarget {
            space: SpaceId([0x11; 32]),
            system_agent: AgentId([0x12; 32]),
            system_runtime_deployment: DeploymentId([0x13; 32]),
            binding: AgentAuthorityBinding {
                policy: Hash([0x14; 32]),
                issuer: AuthorityIssuer {
                    principal: PrincipalId([0x15; 32]),
                    actor: ActorId([0x16; 32]),
                    deployment: DeploymentId([0x17; 32]),
                    program: ProgramId([0x18; 32]),
                    producer: ProducerId::of_public_key(&public_key),
                },
                public_key,
                initial_epoch: 2,
            },
        }
    }

    fn credential_key() -> [u8; CREDENTIAL_PUBLIC_KEY_BYTES] {
        [0x21; CREDENTIAL_PUBLIC_KEY_BYTES]
    }

    fn caller_principal() -> PrincipalId {
        PrincipalId([0x22; 32])
    }

    fn caller_node() -> NodeId {
        NodeId([0x23; 32])
    }

    fn invocation_work() -> InvocationWork {
        let key = credential_key();
        InvocationWork {
            space: authority_target().space,
            agent: AgentId([0x31; 32]),
            runtime_deployment: DeploymentId([0x32; 32]),
            invocation: InvocationId([0x33; 32]),
            actor: ActorId([0x34; 32]),
            incarnation: Hash([0x35; 32]),
            deployment: DeploymentId([0x36; 32]),
            program: ProgramId([0x37; 32]),
            mode: MethodMode::Linear,
            origin: InvocationOrigin {
                principal: Some(caller_principal()),
                transport_node: Some(caller_node()),
                credential: Some(CredentialId::of_public_key(&key)),
                actor: None,
                capability: None,
            },
            roles: InvocationRoleClaims {
                space: Some(RoleId([0x38; 32])),
                actor: None,
            },
            message: vec![0x39; 32],
            installation_data: None,
            availability: Vec::<RuntimeBlob>::new(),
            gas: 40,
            recovery_only: false,
        }
    }

    fn call_with_intent(
        intent: AuthorityOperationIntent,
        discriminator: u8,
    ) -> AuthorityOperationCall {
        call_with_authenticated_node(intent, discriminator, Some(caller_node()))
    }

    fn call_with_authenticated_node(
        intent: AuthorityOperationIntent,
        discriminator: u8,
        authenticated_node: Option<NodeId>,
    ) -> AuthorityOperationCall {
        let key = credential_key();
        let mut call = AuthorityOperationCall {
            invocation: InvocationId([discriminator; 32]),
            authority: authority_target(),
            principal: caller_principal(),
            credential: CredentialId::of_public_key(&key),
            credential_public_key: key,
            authenticated_node,
            requested_valid_from: 10,
            requested_expires_at: 30,
            intent,
            signature: [0; CREDENTIAL_SIGNATURE_BYTES],
        };
        call.signature = test_signature(&call.credential_public_key, &call.signing_bytes());
        call.validate_shape().unwrap();
        call
    }

    fn invoke_call() -> AuthorityOperationCall {
        call_with_intent(
            AuthorityOperationIntent::invoke(&invocation_work()).unwrap(),
            0x41,
        )
    }

    fn approval(call: &AuthorityOperationCall) -> AuthorityOperationApproval {
        AuthorityOperationApproval::from_call(
            call,
            NonZeroU64::new(7).unwrap(),
            AuthorityEvidence {
                package: Some(BlobRef {
                    hash: Hash([0x42; 32]),
                    len: 43,
                }),
                proof: None,
                commitment: Hash([0x44; 32]),
            },
            AuthorityLaneRoots {
                control: Some(Hash([0x45; 32])),
                linear: Some(Hash([0x46; 32])),
                merge: None,
                local: None,
            },
            3,
            12,
            28,
        )
        .unwrap()
    }

    fn receipt(approval: &AuthorityOperationApproval) -> AuthorityReceipt {
        let mut receipt = AuthorityReceipt {
            selector: approval.selector.clone(),
            public_key: approval.authority.binding.public_key,
            signature: [0; AUTHORITY_SIGNATURE_BYTES],
        };
        receipt.signature = test_signature(&receipt.public_key, &receipt.signing_bytes());
        receipt
    }

    fn catalog_target() -> CatalogActorTarget {
        let authority = authority_target();
        CatalogActorTarget {
            space: authority.space,
            system_agent: authority.system_agent,
            system_runtime_deployment: authority.system_runtime_deployment,
            actor: ActorId([0x51; 32]),
            deployment: DeploymentId([0x52; 32]),
            program: ProgramId([0x53; 32]),
            authority: authority.binding,
        }
    }

    fn catalog_publication() -> CatalogPublication {
        CatalogPublication {
            identity: AgentIdentity {
                space: authority_target().space,
                agent: AgentId([0x54; 32]),
                owner: caller_principal(),
                profile: AgentProfile::Shared,
                runtime_deployment: DeploymentId([0x55; 32]),
                runtime_program: ProgramId([0x56; 32]),
                runtime_producer: ProducerId([0x57; 32]),
            },
            actor: ActorId([0x58; 32]),
            actor_deployment: DeploymentId([0x59; 32]),
            actor_program: ProgramId([0x5a; 32]),
            actor_package: BlobRef {
                hash: Hash([0x5b; 32]),
                len: 92,
            },
            content: BlobRef {
                hash: Hash([0x5c; 32]),
                len: 93,
            },
        }
    }

    fn catalog_intent(kind: CatalogMutationKind) -> AuthorityOperationIntent {
        AuthorityOperationIntent::catalog(
            InvocationId([0x5d; 32]),
            catalog_target(),
            CatalogAlias {
                namespace: "examples".to_string(),
                name: "linear".to_string(),
            },
            kind,
            catalog_publication(),
            4,
        )
        .unwrap()
    }

    fn private_node(discriminator: u8) -> PrivateNodeIdentity {
        let transport_identity = vec![discriminator; 48];
        PrivateNodeIdentity {
            node: NodeId::of_authenticated_peer(&transport_identity),
            principal: caller_principal(),
            transport_identity,
            encryption_public_key: [discriminator.wrapping_add(1); 32],
            authority_binding: Hash([discriminator.wrapping_add(2); 32]),
            transport_signature: [discriminator.wrapping_add(3); PRIVATE_SIGNATURE_BYTES],
        }
    }

    fn sealed(node: &PrivateNodeIdentity, discriminator: u8) -> SealedPrivateKey {
        SealedPrivateKey {
            node: node.node,
            recipient_key: node.encryption_public_key,
            sealed: vec![discriminator; 48],
        }
    }

    fn private_epoch(
        space: SpaceId,
        agent: AgentId,
        node: &PrivateNodeIdentity,
        epoch: u64,
    ) -> PrivateKeyEpoch {
        PrivateKeyEpoch {
            space,
            agent,
            epoch,
            owner_key_commitment: Hash([0x61; 32]),
            data_key_commitment: Hash([0x62; 32]),
            recovery_key_commitment: Hash([0x63; 32]),
            recovery_encryption_public_key: [0x64; 32],
            sealed_recovery_data_key: SealedRecoveryKey {
                recipient_key: [0x64; 32],
                sealed: vec![0x65; 48],
            },
            sealed_owner_keys: vec![sealed(node, 0x66)],
            sealed_data_keys: vec![sealed(node, 0x67)],
        }
    }

    fn private_controls() -> [PrivateControlRecord; 3] {
        let space = authority_target().space;
        let agent = AgentId([0x68; 32]);
        let node = private_node(0x69);
        let invite = PrivateControlRecord {
            space,
            agent,
            sequence: 1,
            previous: Some(Hash([0x6a; 32])),
            operation: PrivateControlOperation::Invite {
                node: node.clone(),
                epoch: 2,
                sealed_owner_key: sealed(&node, 0x6b),
                sealed_data_key: sealed(&node, 0x6c),
                historical_grants: Vec::new(),
            },
            signer: PrivateControlSigner::Owner,
            signer_public_key: [0x6d; 32],
            signature: [0x6e; PRIVATE_SIGNATURE_BYTES],
        };
        let revoke = PrivateControlRecord {
            space,
            agent,
            sequence: 2,
            previous: Some(invite.commitment()),
            operation: PrivateControlOperation::Revoke {
                node: NodeId([0x6f; 32]),
                next_epoch: private_epoch(space, agent, &node, 3),
            },
            signer: PrivateControlSigner::Owner,
            signer_public_key: [0x70; 32],
            signature: [0x71; PRIVATE_SIGNATURE_BYTES],
        };
        let next_epoch = private_epoch(space, agent, &node, 4);
        let recover = PrivateControlRecord {
            space,
            agent,
            sequence: 9,
            previous: None,
            operation: PrivateControlOperation::Recover {
                superseded_heads: Vec::new(),
                next_epoch: next_epoch.clone(),
                replacement_nodes: vec![node.clone()],
                historical_keyring: PrivateRecoveryKeyringGrant {
                    key_commitment: Hash([0x72; 32]),
                    sealed_keys: vec![sealed(&node, 0x73)],
                    ciphertext: EncryptedPrivateObject {
                        space,
                        agent,
                        epoch: next_epoch.epoch,
                        kind: EncryptedObjectKind::Control,
                        content: Hash([0x74; 32]),
                        nonce: [0x75; PRIVATE_NONCE_BYTES],
                        ciphertext: vec![0x76; 96],
                    },
                },
            },
            signer: PrivateControlSigner::Recovery,
            signer_public_key: [0x77; 32],
            signature: [0x78; PRIVATE_SIGNATURE_BYTES],
        };
        assert!(invite.validate_shape());
        assert!(revoke.validate_shape());
        assert!(recover.validate_shape());
        [invite, revoke, recover]
    }

    #[test]
    fn aoc1_and_aop1_are_distinct_bounded_canonical_golden_wires() {
        let call = invoke_call();
        let call_bytes = call.encode().unwrap();
        assert_eq!(call_bytes.get(..4), Some(b"AOC1".as_slice()));
        assert!(call_bytes.len() <= MAX_AUTHORITY_OPERATION_CALL_WIRE_BYTES);
        assert_eq!(
            AuthorityOperationCall::decode(&call_bytes),
            Ok(call.clone())
        );
        assert_eq!(
            Hash::digest(b"vos/test/aoc1-golden", &[&call_bytes]).0,
            [
                229, 185, 59, 51, 254, 104, 91, 8, 11, 89, 10, 7, 219, 61, 154, 143, 186, 44, 101,
                155, 71, 34, 92, 241, 65, 175, 127, 61, 160, 191, 220, 78,
            ]
        );

        let approval = approval(&call);
        let approval_bytes = approval.encode().unwrap();
        assert_eq!(approval_bytes.get(..4), Some(b"AOP1".as_slice()));
        assert!(approval_bytes.len() <= MAX_AUTHORITY_OPERATION_APPROVAL_WIRE_BYTES);
        assert_eq!(
            AuthorityOperationApproval::decode(&approval_bytes),
            Ok(approval.clone())
        );
        assert_ne!(call.commitment(), approval.commitment());
        assert_eq!(
            Hash::digest(b"vos/test/aop1-golden", &[&approval_bytes]).0,
            [
                228, 145, 52, 113, 184, 191, 23, 207, 52, 68, 46, 211, 113, 7, 87, 3, 160, 165,
                222, 57, 139, 53, 71, 245, 169, 11, 234, 57, 201, 236, 29, 213,
            ]
        );
    }

    #[test]
    fn call_authenticates_exact_identity_validity_intent_and_ingress_context() {
        let call = invoke_call();
        assert_eq!(call.verify_with(&TestVerifier), Ok(()));
        let context = InvocationContext {
            invocation: call.invocation,
            actor: call.authority.binding.issuer.actor,
            mode: MethodMode::Linear,
            origin: InvocationOrigin {
                principal: Some(call.principal),
                transport_node: call.authenticated_node,
                credential: Some(call.credential),
                actor: None,
                capability: None,
            },
            roles: InvocationRoleClaims::none(),
            observed_slot: 11,
        };
        assert!(call.matches_invocation_context(&context));

        let original = call.commitment();
        let mut changed = call.clone();
        changed.requested_expires_at -= 1;
        assert_ne!(changed.commitment(), original);
        assert_eq!(
            changed.verify_with(&TestVerifier),
            Err(AuthorityOperationProtocolError::InvalidSignature)
        );

        let mut changed = call.clone();
        changed.authenticated_node = Some(NodeId([0x79; 32]));
        assert_ne!(changed.commitment(), original);
        assert!(!changed.matches_invocation_context(&context));

        let mut changed_context = context;
        changed_context.origin.capability = Some(CapabilityId([0x7a; 32]));
        assert!(!call.matches_invocation_context(&changed_context));
        changed_context = context;
        changed_context.roles.space = Some(RoleId([0x7b; 32]));
        assert!(!call.matches_invocation_context(&changed_context));

        let mut bad_key = call;
        bad_key.credential_public_key[0] ^= 1;
        assert_eq!(bad_key.encode(), Err(WireError::InvalidValue));
    }

    #[test]
    fn credential_call_without_transport_node_is_canonical_and_exact() {
        let mut work = invocation_work();
        work.origin.transport_node = None;
        let call = call_with_authenticated_node(
            AuthorityOperationIntent::invoke(&work).unwrap(),
            0x7c,
            None,
        );
        let bytes = call.encode().unwrap();
        assert_eq!(AuthorityOperationCall::decode(&bytes), Ok(call.clone()));
        assert_eq!(call.verify_with(&TestVerifier), Ok(()));

        let mut context = InvocationContext {
            invocation: call.invocation,
            actor: call.authority.binding.issuer.actor,
            mode: MethodMode::Linear,
            origin: InvocationOrigin {
                principal: Some(call.principal),
                transport_node: None,
                credential: Some(call.credential),
                actor: None,
                capability: None,
            },
            roles: InvocationRoleClaims::none(),
            observed_slot: 11,
        };
        assert!(call.matches_invocation_context(&context));

        context.origin.transport_node = Some(caller_node());
        assert!(!call.matches_invocation_context(&context));

        let with_transport = invoke_call();
        let mut transport_context = context;
        transport_context.invocation = with_transport.invocation;
        assert!(with_transport.matches_invocation_context(&transport_context));
        transport_context.origin.transport_node = Some(NodeId([0x7d; 32]));
        assert!(!with_transport.matches_invocation_context(&transport_context));
    }

    #[test]
    fn invoke_approval_binds_complete_work_origin_roles_and_exact_receipt() {
        let call = invoke_call();
        let approval = approval(&call);
        let work = invocation_work();
        assert!(approval.matches_call(&call));
        assert!(approval.matches_invocation_work(&work));
        assert_eq!(
            approval.selector.operation,
            AuthorityOperationKind::InvokeActor
        );
        assert_eq!(approval.selector.decision_sequence, 0);
        assert_eq!(approval.selector.acknowledged_through, 0);
        assert_eq!(approval.selector.request, work.commitment());

        // AOP1 cannot reconstruct its retained AOC1 preimage. A substituted
        // nonzero commitment is structurally canonical, so a signer must
        // reopen the call and require `matches_call` before issuing a receipt.
        let mut detached = approval.clone();
        detached.operation_call = Hash([0x7e; 32]);
        assert_eq!(detached.validate_shape(), Ok(()));
        assert!(!detached.matches_call(&call));

        let receipt = receipt(&approval);
        assert!(approval.matches_receipt(&receipt));
        assert_eq!(
            approval.verify_receipt_at(&receipt, 20, &TestVerifier),
            Ok(())
        );

        let mut changed = work.clone();
        changed.message.push(1);
        assert!(!approval.matches_invocation_work(&changed));
        changed = work.clone();
        changed.roles = InvocationRoleClaims {
            space: None,
            actor: Some(RoleId([0x7c; 32])),
        };
        assert!(!approval.matches_invocation_work(&changed));
        changed = work;
        changed.origin.actor = Some(ActorId([0x7d; 32]));
        assert!(!approval.matches_invocation_work(&changed));

        let mut forged_receipt = receipt.clone();
        forged_receipt.selector.evidence.commitment = Hash([0x7e; 32]);
        assert!(!approval.matches_receipt(&forged_receipt));
        forged_receipt = receipt;
        forged_receipt.selector.decision_sequence = 1;
        assert!(forged_receipt.validate_shape().is_err());
        assert!(!approval.matches_receipt(&forged_receipt));
    }

    #[test]
    fn catalog_intent_allocates_next_generation_and_rejects_every_substitution() {
        for kind in [CatalogMutationKind::Publish, CatalogMutationKind::Withdraw] {
            let intent = catalog_intent(kind);
            let request = intent.catalog_request().unwrap();
            assert_eq!(request.generation, NonZeroU64::new(5).unwrap());
            assert!(intent.matches_catalog_request(&request));
            let call = call_with_intent(intent.clone(), 0x7f);
            let approval = approval(&call);
            assert!(approval.matches_catalog_request(&request));
            assert_eq!(approval.selector.request, request.commitment());
            assert_eq!(
                approval.selector.operation,
                AuthorityOperationKind::PublishCatalog
            );
            assert_eq!(approval.selector.decision_sequence, 0);
            assert_eq!(approval.selector.acknowledged_through, 0);

            let mut changed = request.clone();
            changed.alias.name.push('x');
            assert!(!approval.matches_catalog_request(&changed));
            changed = request.clone();
            changed.kind = if kind == CatalogMutationKind::Publish {
                CatalogMutationKind::Withdraw
            } else {
                CatalogMutationKind::Publish
            };
            assert!(!approval.matches_catalog_request(&changed));
            changed = request.clone();
            changed.publication.content.hash = Hash([0x80; 32]);
            assert!(!approval.matches_catalog_request(&changed));
            changed = request;
            changed.generation = NonZeroU64::new(6).unwrap();
            assert!(!approval.matches_catalog_request(&changed));

            let mut mismatched = intent;
            if let AuthorityOperationIntent::Catalog { publication, .. } = &mut mismatched {
                publication.content.hash = Hash([0x81; 32]);
            }
            assert_eq!(
                mismatched.validate_shape(),
                Err(AuthorityOperationProtocolError::InvalidIntent)
            );
        }
    }

    #[test]
    fn private_intents_bind_exact_pctl_node_membership_and_recovery_evidence() {
        let runtime = DeploymentId([0x82; 32]);
        let controls = private_controls();
        let expected_operations = [
            AuthorityOperationKind::InvitePrivateNode,
            AuthorityOperationKind::RevokePrivateNode,
            AuthorityOperationKind::RecoverPrivateAgent,
        ];
        for (index, (control, operation)) in controls.iter().zip(expected_operations).enumerate() {
            let intent = AuthorityOperationIntent::private_control(runtime, control).unwrap();
            assert_eq!(intent.operation(), operation);
            assert!(intent.matches_private_control(control));
            let call = call_with_intent(intent, 0x83 + index as u8);
            let approval = approval(&call);
            assert!(approval.matches_private_control(control));
            assert_eq!(approval.selector.request, control.commitment());
            assert_eq!(approval.selector.decision_sequence, 0);
            assert_eq!(approval.selector.acknowledged_through, 0);
        }

        let invite_intent =
            AuthorityOperationIntent::private_control(runtime, &controls[0]).unwrap();
        let mut changed_invite = controls[0].clone();
        let PrivateControlOperation::Invite { node, .. } = &mut changed_invite.operation else {
            unreachable!()
        };
        node.transport_signature[0] ^= 1;
        assert!(!invite_intent.matches_private_control(&changed_invite));

        let revoke_intent =
            AuthorityOperationIntent::private_control(runtime, &controls[1]).unwrap();
        let mut changed_revoke = controls[1].clone();
        let PrivateControlOperation::Revoke { next_epoch, .. } = &mut changed_revoke.operation
        else {
            unreachable!()
        };
        next_epoch.sealed_owner_keys[0].sealed[0] ^= 1;
        assert!(!revoke_intent.matches_private_control(&changed_revoke));

        let mut changed_revoke_members = controls[1].clone();
        let replacement = private_node(0x89);
        let PrivateControlOperation::Revoke { next_epoch, .. } =
            &mut changed_revoke_members.operation
        else {
            unreachable!()
        };
        next_epoch.sealed_owner_keys[0] = sealed(&replacement, 0x8a);
        next_epoch.sealed_data_keys[0] = sealed(&replacement, 0x8b);
        assert!(changed_revoke_members.validate_shape());
        assert!(!revoke_intent.matches_private_control(&changed_revoke_members));

        let recovery_intent =
            AuthorityOperationIntent::private_control(runtime, &controls[2]).unwrap();
        let mut changed_recovery = controls[2].clone();
        let PrivateControlOperation::Recover {
            historical_keyring, ..
        } = &mut changed_recovery.operation
        else {
            unreachable!()
        };
        historical_keyring.ciphertext.ciphertext[0] ^= 1;
        assert!(!recovery_intent.matches_private_control(&changed_recovery));

        let mut changed_recovery_members = controls[2].clone();
        let replacement = private_node(0x8c);
        let PrivateControlOperation::Recover {
            next_epoch,
            replacement_nodes,
            historical_keyring,
            ..
        } = &mut changed_recovery_members.operation
        else {
            unreachable!()
        };
        replacement_nodes[0] = replacement.clone();
        next_epoch.sealed_owner_keys[0] = sealed(&replacement, 0x8d);
        next_epoch.sealed_data_keys[0] = sealed(&replacement, 0x8e);
        historical_keyring.sealed_keys[0] = sealed(&replacement, 0x8f);
        assert!(changed_recovery_members.validate_shape());
        assert!(!recovery_intent.matches_private_control(&changed_recovery_members));
    }

    #[test]
    fn every_intent_roundtrips_but_old_unknown_trailing_and_oversize_wires_fail_closed() {
        let runtime = DeploymentId([0x84; 32]);
        let controls = private_controls();
        let intents = [
            AuthorityOperationIntent::invoke(&invocation_work()).unwrap(),
            catalog_intent(CatalogMutationKind::Publish),
            catalog_intent(CatalogMutationKind::Withdraw),
            AuthorityOperationIntent::private_control(runtime, &controls[0]).unwrap(),
            AuthorityOperationIntent::private_control(runtime, &controls[1]).unwrap(),
            AuthorityOperationIntent::private_control(runtime, &controls[2]).unwrap(),
        ];
        for (index, intent) in intents.into_iter().enumerate() {
            let call = call_with_intent(intent, 0x85 + index as u8);
            let encoded = call.encode().unwrap();
            assert_eq!(AuthorityOperationCall::decode(&encoded), Ok(call.clone()));
            let approved = approval(&call);
            assert!(approved.matches_call(&call));
            assert_eq!(
                AuthorityOperationApproval::decode(&approved.encode().unwrap()),
                Ok(approved)
            );
        }

        let call = invoke_call();
        let bytes = call.encode().unwrap();
        let mut old = bytes.clone();
        old[..4].copy_from_slice(b"ACC1");
        assert!(AuthorityOperationCall::decode(&old).is_err());
        let mut old_abi = bytes.clone();
        old_abi[4] ^= 1;
        assert!(AuthorityOperationCall::decode(&old_abi).is_err());
        let mut trailing = bytes;
        trailing.push(0);
        assert!(AuthorityOperationCall::decode(&trailing).is_err());
        assert_eq!(
            AuthorityOperationCall::decode(&vec![0; MAX_AUTHORITY_OPERATION_CALL_WIRE_BYTES + 1]),
            Err(WireError::LimitExceeded)
        );

        let approved = approval(&call);
        let mut old = approved.encode().unwrap();
        old[..4].copy_from_slice(b"MAP1");
        assert!(AuthorityOperationApproval::decode(&old).is_err());
        let mut trailing = approved.encode().unwrap();
        trailing.push(0);
        assert!(AuthorityOperationApproval::decode(&trailing).is_err());
        assert_eq!(
            AuthorityOperationApproval::decode(&vec![
                0;
                MAX_AUTHORITY_OPERATION_APPROVAL_WIRE_BYTES
                    + 1
            ]),
            Err(WireError::LimitExceeded)
        );

        let mut unknown = Decoder::new(&[0xff]);
        assert_eq!(decode_intent(&mut unknown), Err(DecodeError::InvalidTag));
    }
}
