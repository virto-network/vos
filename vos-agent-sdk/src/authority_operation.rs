//! Self-authenticating authority calls for non-management operation domains.
//!
//! Management keeps its ACC2/MAP1/MAA2 replay protocol. This sibling family
//! covers invocation, catalog, and Private-Agent controls without widening or
//! accepting those older wire generations. A call authenticates the complete
//! requested intent with a credential signature; an approval materializes the
//! exact selector which an authority signer may turn into an [`AuthorityReceipt`].
//! AOI1 proves only durable receipt issuance; the separate PCA1 protocol proves
//! that a Private runtime later applied and reopened an exact PCTL control.

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

/// AOC3 is intentionally small even though the generic invocation message
/// ceiling is larger. Private ciphertext and actor messages are represented
/// only by exact commitments here.
pub const MAX_AUTHORITY_OPERATION_CALL_WIRE_BYTES: usize = 4 * 1024;
/// AOP3 repeats the call's identity tuple and one complete receipt selector.
pub const MAX_AUTHORITY_OPERATION_APPROVAL_WIRE_BYTES: usize = 4 * 1024;
/// AOI1 contains one complete receipt and fixed-size retained-preimage
/// commitments; it never embeds the AOC3 or AOP3 bytes themselves.
pub const MAX_AUTHORITY_OPERATION_ISSUANCE_ACK_WIRE_BYTES: usize = 4 * 1024;
/// PCA1 is a fixed-size acknowledgement of one durably reopened Private
/// control application. It carries commitments and the resulting projection,
/// never the variable-size PCTL ciphertext or Node list.
pub const MAX_PRIVATE_CONTROL_APPLICATION_ACK_WIRE_BYTES: usize = 4 * 1024;

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
        catalog: CatalogActorTarget,
        alias: CatalogAlias,
        kind: CatalogMutationKind,
        publication: CatalogPublication,
        publication_commitment: Hash,
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
    /// both the invocation and generation; neither is caller-selected.
    pub fn catalog(
        catalog: CatalogActorTarget,
        alias: CatalogAlias,
        kind: CatalogMutationKind,
        publication: CatalogPublication,
    ) -> Result<Self, AuthorityOperationProtocolError> {
        let value = Self::Catalog {
            managed: ManagedAgentTarget {
                space: publication.identity.space,
                agent: publication.identity.agent,
                runtime_deployment: publication.identity.runtime_deployment,
            },
            catalog,
            alias,
            kind,
            publication_commitment: catalog_publication_commitment(&publication),
            publication,
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
                catalog,
                alias,
                publication,
                publication_commitment,
                ..
            } => {
                managed.is_valid()
                    && catalog.is_valid()
                    && alias.is_valid()
                    && publication.is_valid()
                    && publication.identity.space == managed.space
                    && publication.identity.agent == managed.agent
                    && publication.identity.runtime_deployment == managed.runtime_deployment
                    && catalog.space == managed.space
                    && *publication_commitment != Hash::ZERO
                    && *publication_commitment == catalog_publication_commitment(publication)
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
    pub fn request_commitment(
        &self,
        authorization_sequence: NonZeroU64,
        operation_call: Hash,
    ) -> Option<Hash> {
        self.validate_shape().ok()?;
        match self {
            Self::InvokeActor { work, .. } => Some(*work),
            Self::Catalog { .. } => self
                .catalog_request_unchecked(authorization_sequence, operation_call)
                .map(|request| request.commitment()),
            Self::InvitePrivateNode { control, .. }
            | Self::RevokePrivateNode { control, .. }
            | Self::RecoverPrivateAgent { control, .. } => Some(*control),
        }
    }

    /// Materialize the catalog operation from the authority actor's exact
    /// global decision sequence. Callers never select a generation, so an
    /// otherwise-authorized stale or extreme value cannot freeze an alias.
    pub fn catalog_request(
        &self,
        authorization_sequence: NonZeroU64,
        operation_call: Hash,
    ) -> Option<CatalogMutationRequest> {
        self.validate_shape().ok()?;
        self.catalog_request_unchecked(authorization_sequence, operation_call)
    }

    fn catalog_request_unchecked(
        &self,
        authorization_sequence: NonZeroU64,
        operation_call: Hash,
    ) -> Option<CatalogMutationRequest> {
        let Self::Catalog {
            catalog,
            alias,
            kind,
            publication,
            ..
        } = self
        else {
            return None;
        };
        if operation_call == Hash::ZERO {
            return None;
        }
        let sequence = authorization_sequence.get().to_le_bytes();
        let request = CatalogMutationRequest {
            invocation: InvocationId(
                Hash::digest(
                    b"vos/agent/authority-catalog-mutation-invocation/v1",
                    &[
                        crate::RUNTIME_ABI_ID.as_bytes(),
                        operation_call.as_bytes(),
                        &sequence,
                    ],
                )
                .0,
            ),
            catalog: *catalog,
            alias: alias.clone(),
            generation: authorization_sequence,
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

    pub fn matches_catalog_request(
        &self,
        authorization_sequence: NonZeroU64,
        operation_call: Hash,
        request: &CatalogMutationRequest,
    ) -> bool {
        self.validate_shape().is_ok()
            && self
                .catalog_request_unchecked(authorization_sequence, operation_call)
                .as_ref()
                == Some(request)
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

/// Commit one canonically sorted, unique, nonempty post-application Private
/// Node set without embedding that list in AOC3 or PCA1.
pub fn private_member_set_commitment(nodes: impl Iterator<Item = NodeId>) -> Option<Hash> {
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
    /// Monotonic sequence in this credential's general-operation domain.
    /// The authority accepts exactly the successor of its durable high-water.
    pub request_sequence: NonZeroU64,
    pub credential_public_key: [u8; CREDENTIAL_PUBLIC_KEY_BYTES],
    pub authenticated_node: Option<NodeId>,
    pub requested_valid_from: u64,
    pub requested_expires_at: u64,
    pub intent: AuthorityOperationIntent,
    pub signature: [u8; CREDENTIAL_SIGNATURE_BYTES],
}

impl AuthorityOperationCall {
    /// Commitment of every caller-selected field except the derived
    /// invocation and signature. Excluding those outputs avoids a circular
    /// derivation while binding the complete caller, target, validity, and
    /// operation-intent tuple.
    pub fn invocation_payload_commitment(&self) -> Hash {
        authority_operation_call_invocation_payload_commitment(self)
    }

    pub fn derive_invocation(
        credential: CredentialId,
        request_sequence: NonZeroU64,
        payload: Hash,
    ) -> InvocationId {
        InvocationId(
            Hash::digest(
                b"vos/agent/authority-operation-authorization-invocation/v3",
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
        authority_operation_call_signing_bytes(self)
    }

    pub fn commitment(&self) -> Hash {
        Hash::digest(
            b"vos/agent/authority-operation-call/v3",
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
        if self.invocation != self.expected_invocation() {
            return Err(AuthorityOperationProtocolError::InvalidTarget);
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
/// For catalog operations it is also the only source of the mutation
/// generation; the credential-signed intent contains no caller-selected
/// generation.
/// It is intentionally distinct from the selector's management decision
/// clock, which must remain zero for every operation in this protocol.
/// Shape validation alone cannot reconstruct `operation_call`: before signing
/// a receipt, a consumer must reopen the retained AOC3 preimage and require
/// [`AuthorityOperationApproval::matches_call`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorityOperationApproval {
    pub operation_call: Hash,
    pub authorization_sequence: NonZeroU64,
    pub invocation: InvocationId,
    /// Distinct Linear invocation reserved for acknowledging durable receipt
    /// issuance. Its derivation commits the complete signed AOC3 preimage.
    pub acknowledgement_invocation: InvocationId,
    pub authority: AuthorityActorTarget,
    pub principal: PrincipalId,
    pub credential: CredentialId,
    pub request_sequence: NonZeroU64,
    pub credential_public_key: [u8; CREDENTIAL_PUBLIC_KEY_BYTES],
    pub authenticated_node: Option<NodeId>,
    pub intent: AuthorityOperationIntent,
    pub selector: AuthorityReceiptSelector,
}

impl AuthorityOperationApproval {
    /// Deterministically reserve a distinct acknowledgement invocation for
    /// one exact call. An authority actor must still collision-check this ID
    /// against every retained authorization and acknowledgement invocation
    /// before admitting the call.
    pub fn derive_acknowledgement_invocation(call: &AuthorityOperationCall) -> InvocationId {
        Self::derive_acknowledgement_invocation_from_call_parts(
            call.credential,
            call.request_sequence,
            call.invocation,
            call.invocation_payload_commitment(),
            call.commitment(),
        )
    }

    /// Recompute the AOI1 invocation after the AOC3 preimage has compacted.
    /// Every input is retained in the credential-bounded latest-result row.
    pub fn derive_acknowledgement_invocation_from_call_parts(
        credential: CredentialId,
        request_sequence: NonZeroU64,
        authorization_invocation: InvocationId,
        invocation_payload: Hash,
        operation_call: Hash,
    ) -> InvocationId {
        InvocationId(
            Hash::digest(
                b"vos/agent/authority-operation-issuance-acknowledgement-invocation/v3",
                &[
                    crate::RUNTIME_ABI_ID.as_bytes(),
                    credential.as_bytes(),
                    &request_sequence.get().to_le_bytes(),
                    authorization_invocation.as_bytes(),
                    invocation_payload.as_bytes(),
                    operation_call.as_bytes(),
                ],
            )
            .0,
        )
    }

    #[allow(clippy::too_many_arguments)]
    /// Build an approval directly from its retained call preimage. Code which
    /// decodes an AOP3 instead must make the equivalent `matches_call` check
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
        let operation_call = call.commitment();
        let request = call
            .intent
            .request_commitment(authorization_sequence, operation_call)
            .ok_or(AuthorityOperationProtocolError::InvalidIntent)?;
        let value = Self {
            operation_call,
            authorization_sequence,
            invocation: call.invocation,
            acknowledgement_invocation: Self::derive_acknowledgement_invocation(call),
            authority: call.authority,
            principal: call.principal,
            credential: call.credential,
            request_sequence: call.request_sequence,
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
            || self.acknowledgement_invocation == InvocationId::ZERO
            || self.acknowledgement_invocation == self.invocation
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
            || self
                .intent
                .request_commitment(self.authorization_sequence, self.operation_call)
                != Some(self.selector.request)
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
            && self.acknowledgement_invocation == Self::derive_acknowledgement_invocation(call)
            && self.acknowledgement_invocation != call.invocation
            && self.authority == call.authority
            && self.principal == call.principal
            && self.credential == call.credential
            && self.request_sequence == call.request_sequence
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
            && self.intent.matches_catalog_request(
                self.authorization_sequence,
                self.operation_call,
                request,
            )
            && self.selector.request == request.commitment()
    }

    /// Materialize the exact catalog request authorized by this approval.
    /// Its generation is the approval's authority-assigned decision sequence.
    pub fn catalog_request(&self) -> Option<CatalogMutationRequest> {
        self.validate_shape().ok()?;
        self.intent
            .catalog_request(self.authorization_sequence, self.operation_call)
    }

    pub fn matches_private_control(&self, control: &PrivateControlRecord) -> bool {
        self.validate_shape().is_ok()
            && self.intent.matches_private_control(control)
            && self.selector.request == control.commitment()
    }
}

/// Authority-signed proof that one exact non-management receipt was issued.
///
/// The actor retains the AOC3 and AOP3 preimages until this AOI1 verifies and
/// matches both. Only then may its authorization sequence become a retirement
/// fact. Receipt issuance and acknowledgement use distinct Linear invocation
/// IDs so exact retries can never reinterpret one message as the other.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorityOperationIssuanceAck {
    pub authorization_invocation: InvocationId,
    pub acknowledgement_invocation: InvocationId,
    pub authority: AuthorityActorTarget,
    pub operation_call: Hash,
    pub approval: Hash,
    pub authorization_sequence: NonZeroU64,
    pub receipt: AuthorityReceipt,
    /// Logical slot at which the exact receipt was durably issued.
    pub issued_at: u64,
    pub signature: [u8; crate::authority::AUTHORITY_SIGNATURE_BYTES],
}

impl AuthorityOperationIssuanceAck {
    /// Bytes covered by the issuance-acknowledgement authority signature.
    pub fn signing_bytes(&self) -> Vec<u8> {
        authority_operation_issuance_ack_signing_bytes(self)
    }

    pub fn commitment(&self) -> Hash {
        Hash::digest(
            b"vos/agent/authority-operation-issuance-ack/v1",
            &[&self.signing_bytes(), &self.signature],
        )
    }

    pub fn validate_shape(&self) -> Result<(), AuthorityOperationProtocolError> {
        if self.authorization_invocation == InvocationId::ZERO
            || self.acknowledgement_invocation == InvocationId::ZERO
            || self.authorization_invocation == self.acknowledgement_invocation
            || !self.authority.is_valid()
        {
            return Err(AuthorityOperationProtocolError::InvalidTarget);
        }
        if self.operation_call == Hash::ZERO
            || self.approval == Hash::ZERO
            || self.signature == [0; crate::authority::AUTHORITY_SIGNATURE_BYTES]
        {
            return Err(AuthorityOperationProtocolError::InvalidAcknowledgement);
        }
        let selector = &self.receipt.selector;
        if self.receipt.validate_shape().is_err()
            || !self.authority.binding.accepts(&self.receipt)
            || selector.space != self.authority.space
            || selector.operation.uses_management_decision_journal()
            || selector.decision_sequence != 0
            || selector.acknowledged_through != 0
            || !selector.is_live_at(self.issued_at)
        {
            return Err(AuthorityOperationProtocolError::InvalidAcknowledgement);
        }
        if authority_operation_issuance_ack_encoded_len(self)
            > MAX_AUTHORITY_OPERATION_ISSUANCE_ACK_WIRE_BYTES
        {
            return Err(AuthorityOperationProtocolError::LimitExceeded);
        }
        Ok(())
    }

    /// Verify both the issued receipt and AOI1 signature with an independently
    /// selected authority binding. The encoded target is never its own trust
    /// anchor.
    pub fn verify_with<V: AuthorityVerifier>(
        &self,
        authority: crate::authority::AgentAuthorityBinding,
        verifier: &V,
    ) -> Result<(), AuthorityOperationProtocolError> {
        self.validate_shape()?;
        if authority != self.authority.binding || !authority.accepts(&self.receipt) {
            return Err(AuthorityOperationProtocolError::InvalidAcknowledgement);
        }
        self.receipt
            .verify_at(self.issued_at, verifier)
            .map_err(|_| AuthorityOperationProtocolError::InvalidSignature)?;
        if !verifier.verify(
            &authority.public_key,
            &self.signing_bytes(),
            &self.signature,
        ) {
            return Err(AuthorityOperationProtocolError::InvalidSignature);
        }
        Ok(())
    }

    /// Match the exact actor-retained AOC3 and AOP3 preimages. A valid AOI1
    /// must not retire anything unless this check and `verify_with` both pass.
    pub fn matches_pending(
        &self,
        call: &AuthorityOperationCall,
        approval: &AuthorityOperationApproval,
    ) -> bool {
        self.validate_shape().is_ok()
            && approval.matches_call(call)
            && self.authorization_invocation == call.invocation
            && self.authorization_invocation == approval.invocation
            && self.acknowledgement_invocation == approval.acknowledgement_invocation
            && self.authority == call.authority
            && self.authority == approval.authority
            && self.operation_call == call.commitment()
            && self.operation_call == approval.operation_call
            && self.approval == approval.commitment()
            && self.authorization_sequence == approval.authorization_sequence
            && approval.matches_receipt(&self.receipt)
    }

    /// Bind AOI1 to its reserved Linear authority-actor invocation. The
    /// authority signatures, not the relay's identity, authenticate issuance;
    /// canonical principal/credential/Node relay fields are intentionally not
    /// constrained. The runtime observation must equal the signed issuance
    /// slot rather than merely fall within the receipt validity interval.
    pub fn matches_invocation_context(&self, context: &InvocationContext) -> bool {
        self.validate_shape().is_ok()
            && context.validate()
            && context.invocation == self.acknowledgement_invocation
            && context.actor == self.authority.binding.issuer.actor
            && context.mode == MethodMode::Linear
            && context.observed_slot == self.issued_at
            && context.origin.actor.is_none()
            && context.origin.capability.is_none()
            && context.roles == InvocationRoleClaims::none()
    }

    /// Convert an exact, verified AOI1 into the only fact which may advance
    /// the authority actor's durable retirement floor.
    pub fn verified_retirement_fact<V: AuthorityVerifier>(
        &self,
        call: &AuthorityOperationCall,
        approval: &AuthorityOperationApproval,
        verifier: &V,
    ) -> Result<AuthorityOperationRetirementFact, AuthorityOperationProtocolError> {
        if !self.matches_pending(call, approval) {
            return Err(AuthorityOperationProtocolError::MismatchedAcknowledgement);
        }
        self.verify_with(call.authority.binding, verifier)?;
        Ok(AuthorityOperationRetirementFact {
            authority: self.authority,
            authorization_sequence: self.authorization_sequence,
            issuance_ack: self.commitment(),
        })
    }
}

/// Fixed-size observation produced only after a Private runtime has durably
/// reopened one applied PCTL control.
///
/// The complete Node list, transport identities, and sealed grants remain in
/// the Private control protocol. This projection carries only the exact
/// resulting policy commitments needed by the authority actor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PrivateControlApplicationFact {
    pub managed: ManagedAgentTarget,
    pub operation: AuthorityOperationKind,
    pub control: Hash,
    pub control_sequence: u64,
    pub control_previous: Option<Hash>,
    pub epoch: u64,
    pub post_member_set: Hash,
    /// Commitment of the complete durably reopened Private control state.
    pub reopened_control_state: Hash,
    /// Exact reopened control head. A valid application makes the authorized
    /// PCTL control the new head, so this must equal `control`.
    pub reopened_control_head: Hash,
    pub applied_at: u64,
}

impl PrivateControlApplicationFact {
    pub fn validate_shape(&self) -> Result<(), AuthorityOperationProtocolError> {
        let valid_position = match self.operation {
            AuthorityOperationKind::InvitePrivateNode
            | AuthorityOperationKind::RevokePrivateNode => {
                valid_owner_control_position(self.control_sequence, self.control_previous)
            }
            AuthorityOperationKind::RecoverPrivateAgent => {
                valid_recovery_control_position(self.control_sequence, self.control_previous)
            }
            _ => false,
        };
        if !self.managed.is_valid()
            || self.control == Hash::ZERO
            || self.post_member_set == Hash::ZERO
            || self.reopened_control_state == Hash::ZERO
            || self.reopened_control_head != self.control
            || !valid_position
        {
            return Err(AuthorityOperationProtocolError::InvalidApplication);
        }
        Ok(())
    }

    pub fn commitment(&self) -> Hash {
        private_control_application_fact_commitment(self)
    }

    fn matches_intent(&self, intent: &AuthorityOperationIntent) -> bool {
        if self.validate_shape().is_err() {
            return false;
        }
        match intent {
            AuthorityOperationIntent::InvitePrivateNode {
                managed,
                control,
                control_sequence,
                control_previous,
                epoch,
                ..
            } => {
                self.managed == *managed
                    && self.operation == AuthorityOperationKind::InvitePrivateNode
                    && self.control == *control
                    && self.control_sequence == *control_sequence
                    && self.control_previous == *control_previous
                    && self.epoch == *epoch
            }
            AuthorityOperationIntent::RevokePrivateNode {
                managed,
                control,
                control_sequence,
                control_previous,
                epoch,
                member_set,
                ..
            } => {
                self.managed == *managed
                    && self.operation == AuthorityOperationKind::RevokePrivateNode
                    && self.control == *control
                    && self.control_sequence == *control_sequence
                    && self.control_previous == *control_previous
                    && self.epoch == *epoch
                    && self.post_member_set == *member_set
            }
            AuthorityOperationIntent::RecoverPrivateAgent {
                managed,
                control,
                control_sequence,
                control_previous,
                epoch,
                member_set,
                ..
            } => {
                self.managed == *managed
                    && self.operation == AuthorityOperationKind::RecoverPrivateAgent
                    && self.control == *control
                    && self.control_sequence == *control_sequence
                    && self.control_previous == *control_previous
                    && self.epoch == *epoch
                    && self.post_member_set == *member_set
            }
            AuthorityOperationIntent::InvokeActor { .. }
            | AuthorityOperationIntent::Catalog { .. } => false,
        }
    }
}

/// Authority-signed proof that one exact Private control was durably applied
/// and reopened after its non-management receipt had been issued.
///
/// PCA1 is distinct from AOI1: issuance alone never proves application. Its
/// three invocation IDs reserve independent exact-retry domains for AOC3,
/// AOI1, and PCA1. The AOC3/AOP3 commitments are repeated for auditability;
/// the invocation pair, authorization sequence, and AOI1 commitment are also
/// sufficient to match an issuance tombstone after those preimages retire.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrivateControlApplicationAck {
    pub authorization_invocation: InvocationId,
    pub issuance_invocation: InvocationId,
    pub application_invocation: InvocationId,
    pub authority: AuthorityActorTarget,
    pub operation_call: Hash,
    pub approval: Hash,
    pub issuance_ack: Hash,
    pub authorization_sequence: NonZeroU64,
    pub receipt: AuthorityReceipt,
    /// Exact AOI1 issuance slot, repeated under the PCA1 signature so a PCA1
    /// reopened after AOI1 compaction still proves application ordering.
    pub issued_at: u64,
    pub application: PrivateControlApplicationFact,
    pub signature: [u8; crate::authority::AUTHORITY_SIGNATURE_BYTES],
}

impl PrivateControlApplicationAck {
    /// Derive PCA1's third invocation from the exact verified AOI1.
    pub fn derive_application_invocation(issuance: &AuthorityOperationIssuanceAck) -> InvocationId {
        Self::derive_application_invocation_from_issuance(
            issuance.authority,
            issuance.authorization_invocation,
            issuance.acknowledgement_invocation,
            issuance.authorization_sequence,
            issuance.commitment(),
        )
    }

    /// Derive the PCA1 invocation from the fixed-size AOI1 tombstone tuple.
    /// Callers must authenticate that tuple from durable authority state; this
    /// deterministic helper does not make ambient values trustworthy.
    pub fn derive_application_invocation_from_issuance(
        authority: AuthorityActorTarget,
        authorization_invocation: InvocationId,
        issuance_invocation: InvocationId,
        authorization_sequence: NonZeroU64,
        issuance_ack: Hash,
    ) -> InvocationId {
        private_control_application_invocation(
            authority,
            authorization_invocation,
            issuance_invocation,
            authorization_sequence,
            issuance_ack,
        )
    }

    pub fn signing_bytes(&self) -> Vec<u8> {
        private_control_application_ack_signing_bytes(self)
    }

    pub fn commitment(&self) -> Hash {
        Hash::digest(
            b"vos/agent/private-control-application-ack/v1",
            &[&self.signing_bytes(), &self.signature],
        )
    }

    pub fn validate_shape(&self) -> Result<(), AuthorityOperationProtocolError> {
        if self.authorization_invocation == InvocationId::ZERO
            || self.issuance_invocation == InvocationId::ZERO
            || self.application_invocation == InvocationId::ZERO
            || self.authorization_invocation == self.issuance_invocation
            || self.authorization_invocation == self.application_invocation
            || self.issuance_invocation == self.application_invocation
            || !self.authority.is_valid()
            || self.authority.space != self.application.managed.space
        {
            return Err(AuthorityOperationProtocolError::InvalidTarget);
        }
        if self.operation_call == Hash::ZERO
            || self.approval == Hash::ZERO
            || self.issuance_ack == Hash::ZERO
            || self.signature == [0; crate::authority::AUTHORITY_SIGNATURE_BYTES]
            || self.issued_at > self.application.applied_at
            || self.application.validate_shape().is_err()
        {
            return Err(AuthorityOperationProtocolError::InvalidApplication);
        }
        if self.application_invocation
            != Self::derive_application_invocation_from_issuance(
                self.authority,
                self.authorization_invocation,
                self.issuance_invocation,
                self.authorization_sequence,
                self.issuance_ack,
            )
        {
            return Err(AuthorityOperationProtocolError::InvalidTarget);
        }
        let selector = &self.receipt.selector;
        if self.receipt.validate_shape().is_err()
            || !self.authority.binding.accepts(&self.receipt)
            || selector.space != self.application.managed.space
            || selector.agent != self.application.managed.agent
            || selector.runtime_deployment != self.application.managed.runtime_deployment
            || selector.operation != self.application.operation
            || selector.operation.uses_management_decision_journal()
            || selector.decision_sequence != 0
            || selector.acknowledged_through != 0
            || selector.request != self.application.control
            || !selector.is_live_at(self.issued_at)
            || !selector.is_live_at(self.application.applied_at)
        {
            return Err(AuthorityOperationProtocolError::InvalidApplication);
        }
        if private_control_application_ack_encoded_len(self)
            > MAX_PRIVATE_CONTROL_APPLICATION_ACK_WIRE_BYTES
        {
            return Err(AuthorityOperationProtocolError::LimitExceeded);
        }
        Ok(())
    }

    /// Verify the receipt and PCA1 signature with an independently selected
    /// authority binding. The encoded target is never its own trust anchor.
    pub fn verify_with<V: AuthorityVerifier>(
        &self,
        authority: crate::authority::AgentAuthorityBinding,
        verifier: &V,
    ) -> Result<(), AuthorityOperationProtocolError> {
        self.validate_shape()?;
        if authority != self.authority.binding || !authority.accepts(&self.receipt) {
            return Err(AuthorityOperationProtocolError::InvalidApplication);
        }
        self.receipt
            .verify_at(self.issued_at, verifier)
            .map_err(|_| AuthorityOperationProtocolError::InvalidSignature)?;
        self.receipt
            .verify_at(self.application.applied_at, verifier)
            .map_err(|_| AuthorityOperationProtocolError::InvalidSignature)?;
        if !verifier.verify(
            &authority.public_key,
            &self.signing_bytes(),
            &self.signature,
        ) {
            return Err(AuthorityOperationProtocolError::InvalidSignature);
        }
        Ok(())
    }

    /// Match all retained AOC3/AOP3/AOI1 preimages and the exact runtime
    /// application observation. Verification remains a separate explicit step.
    pub fn matches_pending(
        &self,
        call: &AuthorityOperationCall,
        approval: &AuthorityOperationApproval,
        issuance: &AuthorityOperationIssuanceAck,
        application: &PrivateControlApplicationFact,
    ) -> bool {
        self.validate_shape().is_ok()
            && issuance.matches_pending(call, approval)
            && application.matches_intent(&call.intent)
            && self.application == *application
            && self.authorization_invocation == call.invocation
            && self.authorization_invocation == approval.invocation
            && self.authorization_invocation == issuance.authorization_invocation
            && self.issuance_invocation == approval.acknowledgement_invocation
            && self.issuance_invocation == issuance.acknowledgement_invocation
            && self.application_invocation == Self::derive_application_invocation(issuance)
            && self.authority == call.authority
            && self.authority == approval.authority
            && self.authority == issuance.authority
            && self.operation_call == call.commitment()
            && self.operation_call == approval.operation_call
            && self.operation_call == issuance.operation_call
            && self.approval == approval.commitment()
            && self.approval == issuance.approval
            && self.issuance_ack == issuance.commitment()
            && self.authorization_sequence == approval.authorization_sequence
            && self.authorization_sequence == issuance.authorization_sequence
            && self.receipt == issuance.receipt
            && self.issued_at == issuance.issued_at
            && self.application.applied_at >= issuance.issued_at
    }

    /// Verify the complete pending chain, including both authority signatures
    /// and the receipt at issuance and application time.
    pub fn verify_pending_with<V: AuthorityVerifier>(
        &self,
        call: &AuthorityOperationCall,
        approval: &AuthorityOperationApproval,
        issuance: &AuthorityOperationIssuanceAck,
        application: &PrivateControlApplicationFact,
        authority: crate::authority::AgentAuthorityBinding,
        verifier: &V,
    ) -> Result<(), AuthorityOperationProtocolError> {
        if !self.matches_pending(call, approval, issuance, application) {
            return Err(AuthorityOperationProtocolError::MismatchedApplication);
        }
        issuance.verify_with(authority, verifier)?;
        self.verify_with(authority, verifier)
    }

    /// Match the compact issuance tuple retained after AOC3/AOP3/AOI1
    /// preimages have retired. The PCA1 signature still must be independently
    /// verified; this method deliberately does not reconstruct discarded data.
    pub fn matches_issuance_tombstone(
        &self,
        authority: AuthorityActorTarget,
        authorization_invocation: InvocationId,
        issuance_invocation: InvocationId,
        authorization_sequence: NonZeroU64,
        issuance_ack: Hash,
    ) -> bool {
        self.validate_shape().is_ok()
            && self.authority == authority
            && self.authorization_invocation == authorization_invocation
            && self.issuance_invocation == issuance_invocation
            && self.authorization_sequence == authorization_sequence
            && self.issuance_ack == issuance_ack
            && self.application_invocation
                == Self::derive_application_invocation_from_issuance(
                    authority,
                    authorization_invocation,
                    issuance_invocation,
                    authorization_sequence,
                    issuance_ack,
                )
    }

    /// Verify a PCA1 after issuance preimages have compacted, using the exact
    /// authenticated tombstone tuple and an independently selected binding.
    pub fn verify_issuance_tombstone_with<V: AuthorityVerifier>(
        &self,
        authority: AuthorityActorTarget,
        authorization_invocation: InvocationId,
        issuance_invocation: InvocationId,
        authorization_sequence: NonZeroU64,
        issuance_ack: Hash,
        verifier: &V,
    ) -> Result<(), AuthorityOperationProtocolError> {
        if !self.matches_issuance_tombstone(
            authority,
            authorization_invocation,
            issuance_invocation,
            authorization_sequence,
            issuance_ack,
        ) {
            return Err(AuthorityOperationProtocolError::MismatchedApplication);
        }
        self.verify_with(authority.binding, verifier)
    }

    /// Bind PCA1 to its third exact Linear authority-actor invocation. As with
    /// AOI1, relay identity is not authority; the signature authenticates the
    /// message and the observed slot must equal the signed application slot.
    pub fn matches_invocation_context(&self, context: &InvocationContext) -> bool {
        self.validate_shape().is_ok()
            && context.validate()
            && context.invocation == self.application_invocation
            && context.actor == self.authority.binding.issuer.actor
            && context.mode == MethodMode::Linear
            && context.observed_slot == self.application.applied_at
            && context.origin.actor.is_none()
            && context.origin.capability.is_none()
            && context.roles == InvocationRoleClaims::none()
    }
}

/// Verified issuance evidence for exactly one authorization sequence.
/// Fields are private so callers cannot manufacture a retirement capability
/// without reopening the retained AOC3/AOP3 and verifying AOI1.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuthorityOperationRetirementFact {
    authority: AuthorityActorTarget,
    authorization_sequence: NonZeroU64,
    issuance_ack: Hash,
}

impl AuthorityOperationRetirementFact {
    pub const fn authority(&self) -> AuthorityActorTarget {
        self.authority
    }

    pub const fn authorization_sequence(&self) -> NonZeroU64 {
        self.authorization_sequence
    }

    pub const fn issuance_ack(&self) -> Hash {
        self.issuance_ack
    }
}

/// Durable inclusive prefix of issued non-management authorizations.
///
/// Out-of-order verified facts must remain pending. The actor may advance this
/// floor only one sequence at a time, durably committing the new floor before
/// discarding the corresponding AOC3/AOP3/AOI1 preimages. On restart it
/// reopens this value from its own authenticated Linear state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuthorityOperationRetirementFloor {
    authority: AuthorityActorTarget,
    retired_through: u64,
}

impl AuthorityOperationRetirementFloor {
    pub fn initial(
        authority: AuthorityActorTarget,
    ) -> Result<Self, AuthorityOperationProtocolError> {
        if !authority.is_valid() {
            return Err(AuthorityOperationProtocolError::InvalidTarget);
        }
        Ok(Self {
            authority,
            retired_through: 0,
        })
    }

    /// Reopen a floor only from the authority actor's already-authenticated
    /// durable state. This constructor does not make an ambient host value
    /// trustworthy.
    pub fn reopen_durable(
        authority: AuthorityActorTarget,
        retired_through: u64,
    ) -> Result<Self, AuthorityOperationProtocolError> {
        if !authority.is_valid() {
            return Err(AuthorityOperationProtocolError::InvalidTarget);
        }
        Ok(Self {
            authority,
            retired_through,
        })
    }

    pub const fn authority(&self) -> AuthorityActorTarget {
        self.authority
    }

    pub const fn retired_through(&self) -> u64 {
        self.retired_through
    }

    /// Advance only the immediately adjacent sequence. Duplicate, stale,
    /// out-of-order, cross-authority, and overflow transitions fail closed.
    pub fn advance(
        &mut self,
        fact: AuthorityOperationRetirementFact,
    ) -> Result<(), AuthorityOperationProtocolError> {
        let Some(next) = self.retired_through.checked_add(1) else {
            return Err(AuthorityOperationProtocolError::NonContiguousRetirement);
        };
        if fact.authority != self.authority
            || fact.authorization_sequence.get() != next
            || fact.issuance_ack == Hash::ZERO
        {
            return Err(AuthorityOperationProtocolError::NonContiguousRetirement);
        }
        self.retired_through = next;
        Ok(())
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
    InvalidAcknowledgement,
    InvalidApplication,
    LimitExceeded,
    MismatchedCall,
    MismatchedAcknowledgement,
    MismatchedApplication,
    NonContiguousRetirement,
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
            catalog,
            alias,
            kind,
            publication,
            publication_commitment,
        } => {
            encoder.u8(1);
            encode_managed(encoder, *managed);
            crate::wire::encode_catalog_actor_target(encoder, *catalog);
            crate::wire::encode_catalog_alias(encoder, alias);
            crate::wire::encode_catalog_mutation_kind(encoder, *kind);
            crate::wire::encode_catalog_publication(encoder, publication);
            encoder.fixed(publication_commitment.as_bytes());
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
            catalog: crate::wire::decode_catalog_actor_target(decoder)?,
            alias: crate::wire::decode_catalog_alias(decoder)?,
            kind: crate::wire::decode_catalog_mutation_kind(decoder)?,
            publication: crate::wire::decode_catalog_publication(decoder)?,
            publication_commitment: Hash(decoder.fixed()?),
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
    encode_call_invocation_payload(encoder, value);
}

fn encode_call_invocation_payload(encoder: &mut Encoder<'_>, value: &AuthorityOperationCall) {
    crate::wire::encode_authority_actor_target(encoder, value.authority);
    crate::wire::encode_credential_caller(
        encoder,
        value.principal,
        value.credential,
        &value.credential_public_key,
        value.authenticated_node,
    );
    encoder.u64(value.request_sequence.get());
    encoder.u64(value.requested_valid_from);
    encoder.u64(value.requested_expires_at);
    encode_intent(encoder, &value.intent);
}

fn authority_operation_call_invocation_payload_commitment(value: &AuthorityOperationCall) -> Hash {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"OCP3");
    bytes.extend_from_slice(crate::RUNTIME_ABI_ID.as_bytes());
    encode_call_invocation_payload(&mut Encoder(&mut bytes), value);
    Hash::digest(
        b"vos/agent/authority-operation-invocation-payload/v3",
        &[&bytes],
    )
}

fn authority_operation_call_signing_bytes(value: &AuthorityOperationCall) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"AO3S");
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
    const MAGIC: [u8; 4] = *b"AOC3";
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
            request_sequence: NonZeroU64::new(decoder.u64()?).ok_or(DecodeError::NonCanonical)?,
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
    encoder.fixed(value.acknowledgement_invocation.as_bytes());
    crate::wire::encode_authority_actor_target(encoder, value.authority);
    crate::wire::encode_credential_caller(
        encoder,
        value.principal,
        value.credential,
        &value.credential_public_key,
        value.authenticated_node,
    );
    encoder.u64(value.request_sequence.get());
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
    bytes.extend_from_slice(b"AO3C");
    bytes.extend_from_slice(crate::RUNTIME_ABI_ID.as_bytes());
    encode_approval_body(&mut Encoder(&mut bytes), value);
    Hash::digest(b"vos/agent/authority-operation-approval/v3", &[&bytes])
}

impl CanonicalWire for AuthorityOperationApproval {
    const MAGIC: [u8; 4] = *b"AOP3";
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
        let acknowledgement_invocation = InvocationId(decoder.fixed()?);
        let authority = crate::wire::decode_authority_actor_target(decoder)?;
        let (principal, credential, credential_public_key, authenticated_node) =
            crate::wire::decode_credential_caller(decoder)?;
        let value = Self {
            operation_call,
            authorization_sequence,
            invocation,
            acknowledgement_invocation,
            authority,
            principal,
            credential,
            request_sequence: NonZeroU64::new(decoder.u64()?).ok_or(DecodeError::NonCanonical)?,
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

fn encode_issuance_ack_unsigned(encoder: &mut Encoder<'_>, value: &AuthorityOperationIssuanceAck) {
    encoder.fixed(value.authorization_invocation.as_bytes());
    encoder.fixed(value.acknowledgement_invocation.as_bytes());
    crate::wire::encode_authority_actor_target(encoder, value.authority);
    encoder.fixed(value.operation_call.as_bytes());
    encoder.fixed(value.approval.as_bytes());
    encoder.u64(value.authorization_sequence.get());
    crate::wire::encode_authority_receipt_body(encoder, &value.receipt);
    encoder.u64(value.issued_at);
}

fn authority_operation_issuance_ack_signing_bytes(
    value: &AuthorityOperationIssuanceAck,
) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"AOIS");
    bytes.extend_from_slice(crate::RUNTIME_ABI_ID.as_bytes());
    encode_issuance_ack_unsigned(&mut Encoder(&mut bytes), value);
    bytes
}

fn authority_operation_issuance_ack_encoded_len(value: &AuthorityOperationIssuanceAck) -> usize {
    let mut body = Vec::new();
    encode_issuance_ack_unsigned(&mut Encoder(&mut body), value);
    HEADER_BYTES
        .saturating_add(body.len())
        .saturating_add(crate::authority::AUTHORITY_SIGNATURE_BYTES)
}

impl CanonicalWire for AuthorityOperationIssuanceAck {
    const MAGIC: [u8; 4] = *b"AOI1";
    const MAX_ENCODED_BYTES: usize = MAX_AUTHORITY_OPERATION_ISSUANCE_ACK_WIRE_BYTES;

    fn validate_wire(&self) -> bool {
        self.validate_shape().is_ok()
    }

    fn encode_body(&self, encoder: &mut Encoder<'_>) {
        encode_issuance_ack_unsigned(encoder, self);
        encoder.0.extend_from_slice(&self.signature);
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let value = Self {
            authorization_invocation: InvocationId(decoder.fixed()?),
            acknowledgement_invocation: InvocationId(decoder.fixed()?),
            authority: crate::wire::decode_authority_actor_target(decoder)?,
            operation_call: Hash(decoder.fixed()?),
            approval: Hash(decoder.fixed()?),
            authorization_sequence: NonZeroU64::new(decoder.u64()?)
                .ok_or(DecodeError::NonCanonical)?,
            receipt: crate::wire::decode_authority_receipt_body(decoder)?,
            issued_at: decoder.u64()?,
            signature: decoder
                .take(crate::authority::AUTHORITY_SIGNATURE_BYTES)?
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

fn encode_private_control_operation(encoder: &mut Encoder<'_>, operation: AuthorityOperationKind) {
    encoder.u8(operation as u8);
}

fn decode_private_control_operation(
    decoder: &mut Decoder<'_>,
) -> Result<AuthorityOperationKind, DecodeError> {
    match decoder.u8()? {
        value if value == AuthorityOperationKind::InvitePrivateNode as u8 => {
            Ok(AuthorityOperationKind::InvitePrivateNode)
        }
        value if value == AuthorityOperationKind::RevokePrivateNode as u8 => {
            Ok(AuthorityOperationKind::RevokePrivateNode)
        }
        value if value == AuthorityOperationKind::RecoverPrivateAgent as u8 => {
            Ok(AuthorityOperationKind::RecoverPrivateAgent)
        }
        _ => Err(DecodeError::InvalidTag),
    }
}

fn encode_private_control_application_fact(
    encoder: &mut Encoder<'_>,
    value: &PrivateControlApplicationFact,
) {
    encode_managed(encoder, value.managed);
    encode_private_control_operation(encoder, value.operation);
    encoder.fixed(value.control.as_bytes());
    encoder.u64(value.control_sequence);
    encoder.option(&value.control_previous, |encoder, previous| {
        encoder.fixed(previous.as_bytes());
    });
    encoder.u64(value.epoch);
    encoder.fixed(value.post_member_set.as_bytes());
    encoder.fixed(value.reopened_control_state.as_bytes());
    encoder.fixed(value.reopened_control_head.as_bytes());
    encoder.u64(value.applied_at);
}

fn decode_private_control_application_fact(
    decoder: &mut Decoder<'_>,
) -> Result<PrivateControlApplicationFact, DecodeError> {
    let value = PrivateControlApplicationFact {
        managed: decode_managed(decoder)?,
        operation: decode_private_control_operation(decoder)?,
        control: Hash(decoder.fixed()?),
        control_sequence: decoder.u64()?,
        control_previous: decoder.option(|decoder| Ok(Hash(decoder.fixed()?)))?,
        epoch: decoder.u64()?,
        post_member_set: Hash(decoder.fixed()?),
        reopened_control_state: Hash(decoder.fixed()?),
        reopened_control_head: Hash(decoder.fixed()?),
        applied_at: decoder.u64()?,
    };
    value
        .validate_shape()
        .is_ok()
        .then_some(value)
        .ok_or(DecodeError::NonCanonical)
}

fn private_control_application_fact_commitment(value: &PrivateControlApplicationFact) -> Hash {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"PCAF");
    bytes.extend_from_slice(crate::RUNTIME_ABI_ID.as_bytes());
    encode_private_control_application_fact(&mut Encoder(&mut bytes), value);
    Hash::digest(b"vos/agent/private-control-application-fact/v1", &[&bytes])
}

fn private_control_application_invocation(
    authority: AuthorityActorTarget,
    authorization_invocation: InvocationId,
    issuance_invocation: InvocationId,
    authorization_sequence: NonZeroU64,
    issuance_ack: Hash,
) -> InvocationId {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"PCAI");
    bytes.extend_from_slice(crate::RUNTIME_ABI_ID.as_bytes());
    crate::wire::encode_authority_actor_target(&mut Encoder(&mut bytes), authority);
    bytes.extend_from_slice(authorization_invocation.as_bytes());
    bytes.extend_from_slice(issuance_invocation.as_bytes());
    bytes.extend_from_slice(&authorization_sequence.get().to_le_bytes());
    bytes.extend_from_slice(issuance_ack.as_bytes());
    InvocationId(
        Hash::digest(
            b"vos/agent/private-control-application-invocation/v1",
            &[&bytes],
        )
        .0,
    )
}

fn encode_private_control_application_ack_unsigned(
    encoder: &mut Encoder<'_>,
    value: &PrivateControlApplicationAck,
) {
    encoder.fixed(value.authorization_invocation.as_bytes());
    encoder.fixed(value.issuance_invocation.as_bytes());
    encoder.fixed(value.application_invocation.as_bytes());
    crate::wire::encode_authority_actor_target(encoder, value.authority);
    encoder.fixed(value.operation_call.as_bytes());
    encoder.fixed(value.approval.as_bytes());
    encoder.fixed(value.issuance_ack.as_bytes());
    encoder.u64(value.authorization_sequence.get());
    crate::wire::encode_authority_receipt_body(encoder, &value.receipt);
    encoder.u64(value.issued_at);
    encode_private_control_application_fact(encoder, &value.application);
}

fn private_control_application_ack_signing_bytes(value: &PrivateControlApplicationAck) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"PCAS");
    bytes.extend_from_slice(crate::RUNTIME_ABI_ID.as_bytes());
    encode_private_control_application_ack_unsigned(&mut Encoder(&mut bytes), value);
    bytes
}

fn private_control_application_ack_encoded_len(value: &PrivateControlApplicationAck) -> usize {
    let mut body = Vec::new();
    encode_private_control_application_ack_unsigned(&mut Encoder(&mut body), value);
    HEADER_BYTES
        .saturating_add(body.len())
        .saturating_add(crate::authority::AUTHORITY_SIGNATURE_BYTES)
}

impl CanonicalWire for PrivateControlApplicationAck {
    const MAGIC: [u8; 4] = *b"PCA1";
    const MAX_ENCODED_BYTES: usize = MAX_PRIVATE_CONTROL_APPLICATION_ACK_WIRE_BYTES;

    fn validate_wire(&self) -> bool {
        self.validate_shape().is_ok()
    }

    fn encode_body(&self, encoder: &mut Encoder<'_>) {
        encode_private_control_application_ack_unsigned(encoder, self);
        encoder.0.extend_from_slice(&self.signature);
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let value = Self {
            authorization_invocation: InvocationId(decoder.fixed()?),
            issuance_invocation: InvocationId(decoder.fixed()?),
            application_invocation: InvocationId(decoder.fixed()?),
            authority: crate::wire::decode_authority_actor_target(decoder)?,
            operation_call: Hash(decoder.fixed()?),
            approval: Hash(decoder.fixed()?),
            issuance_ack: Hash(decoder.fixed()?),
            authorization_sequence: NonZeroU64::new(decoder.u64()?)
                .ok_or(DecodeError::NonCanonical)?,
            receipt: crate::wire::decode_authority_receipt_body(decoder)?,
            issued_at: decoder.u64()?,
            application: decode_private_control_application_fact(decoder)?,
            signature: decoder
                .take(crate::authority::AUTHORITY_SIGNATURE_BYTES)?
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
            invocation: InvocationId::ZERO,
            authority: authority_target(),
            principal: caller_principal(),
            credential: CredentialId::of_public_key(&key),
            request_sequence: NonZeroU64::new(u64::from(discriminator)).unwrap(),
            credential_public_key: key,
            authenticated_node,
            requested_valid_from: 10,
            requested_expires_at: 30,
            intent,
            signature: [0; CREDENTIAL_SIGNATURE_BYTES],
        };
        call.invocation = call.expected_invocation();
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
        approval_with_sequence(call, 7)
    }

    fn approval_with_sequence(
        call: &AuthorityOperationCall,
        authorization_sequence: u64,
    ) -> AuthorityOperationApproval {
        AuthorityOperationApproval::from_call(
            call,
            NonZeroU64::new(authorization_sequence).unwrap(),
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

    fn issuance_ack(
        call: &AuthorityOperationCall,
        approval: &AuthorityOperationApproval,
    ) -> AuthorityOperationIssuanceAck {
        let mut acknowledgement = AuthorityOperationIssuanceAck {
            authorization_invocation: call.invocation,
            acknowledgement_invocation: approval.acknowledgement_invocation,
            authority: call.authority,
            operation_call: call.commitment(),
            approval: approval.commitment(),
            authorization_sequence: approval.authorization_sequence,
            receipt: receipt(approval),
            issued_at: 20,
            signature: [0; AUTHORITY_SIGNATURE_BYTES],
        };
        acknowledgement.signature = test_signature(
            &acknowledgement.authority.binding.public_key,
            &acknowledgement.signing_bytes(),
        );
        acknowledgement.validate_shape().unwrap();
        acknowledgement
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
            catalog_target(),
            CatalogAlias {
                namespace: "examples".to_string(),
                name: "linear".to_string(),
            },
            kind,
            catalog_publication(),
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

    fn private_call(control: &PrivateControlRecord, discriminator: u8) -> AuthorityOperationCall {
        call_with_intent(
            AuthorityOperationIntent::private_control(DeploymentId([0x79; 32]), control).unwrap(),
            discriminator,
        )
    }

    fn private_application_fact(call: &AuthorityOperationCall) -> PrivateControlApplicationFact {
        let (control, control_sequence, control_previous, epoch, post_member_set) =
            match &call.intent {
                AuthorityOperationIntent::InvitePrivateNode {
                    control,
                    control_sequence,
                    control_previous,
                    epoch,
                    node,
                    ..
                } => (
                    *control,
                    *control_sequence,
                    *control_previous,
                    *epoch,
                    private_member_set_commitment(core::iter::once(*node)).unwrap(),
                ),
                AuthorityOperationIntent::RevokePrivateNode {
                    control,
                    control_sequence,
                    control_previous,
                    epoch,
                    member_set,
                    ..
                }
                | AuthorityOperationIntent::RecoverPrivateAgent {
                    control,
                    control_sequence,
                    control_previous,
                    epoch,
                    member_set,
                    ..
                } => (
                    *control,
                    *control_sequence,
                    *control_previous,
                    *epoch,
                    *member_set,
                ),
                AuthorityOperationIntent::InvokeActor { .. }
                | AuthorityOperationIntent::Catalog { .. } => unreachable!(),
            };
        let value = PrivateControlApplicationFact {
            managed: call.intent.managed(),
            operation: call.intent.operation(),
            control,
            control_sequence,
            control_previous,
            epoch,
            post_member_set,
            reopened_control_state: Hash([0x7b; 32]),
            reopened_control_head: control,
            applied_at: 24,
        };
        value.validate_shape().unwrap();
        assert!(value.matches_intent(&call.intent));
        value
    }

    fn private_application_ack(
        call: &AuthorityOperationCall,
        approved: &AuthorityOperationApproval,
        issuance: &AuthorityOperationIssuanceAck,
        application: PrivateControlApplicationFact,
    ) -> PrivateControlApplicationAck {
        let mut acknowledgement = PrivateControlApplicationAck {
            authorization_invocation: call.invocation,
            issuance_invocation: issuance.acknowledgement_invocation,
            application_invocation: PrivateControlApplicationAck::derive_application_invocation(
                issuance,
            ),
            authority: call.authority,
            operation_call: call.commitment(),
            approval: approved.commitment(),
            issuance_ack: issuance.commitment(),
            authorization_sequence: approved.authorization_sequence,
            receipt: issuance.receipt.clone(),
            issued_at: issuance.issued_at,
            application,
            signature: [0; AUTHORITY_SIGNATURE_BYTES],
        };
        resign_private_application_ack(&mut acknowledgement);
        acknowledgement.validate_shape().unwrap();
        acknowledgement
    }

    fn resign_private_application_ack(acknowledgement: &mut PrivateControlApplicationAck) {
        acknowledgement.signature = test_signature(
            &acknowledgement.authority.binding.public_key,
            &acknowledgement.signing_bytes(),
        );
    }

    #[test]
    fn aoc3_aop3_and_aoi1_are_distinct_bounded_canonical_golden_wires() {
        let call = invoke_call();
        let call_bytes = call.encode().unwrap();
        assert_eq!(call_bytes.get(..4), Some(b"AOC3".as_slice()));
        assert!(call_bytes.len() <= MAX_AUTHORITY_OPERATION_CALL_WIRE_BYTES);
        assert_eq!(
            AuthorityOperationCall::decode(&call_bytes),
            Ok(call.clone())
        );
        assert_eq!(
            Hash::digest(b"vos/test/aoc3-golden", &[&call_bytes]).0,
            [
                253, 99, 119, 122, 117, 95, 211, 240, 53, 9, 140, 171, 245, 6, 16, 211, 38, 251,
                87, 128, 209, 3, 98, 60, 94, 186, 106, 18, 36, 100, 245, 102,
            ]
        );

        let approval = approval(&call);
        let approval_bytes = approval.encode().unwrap();
        assert_eq!(approval_bytes.get(..4), Some(b"AOP3".as_slice()));
        assert!(approval_bytes.len() <= MAX_AUTHORITY_OPERATION_APPROVAL_WIRE_BYTES);
        assert_eq!(
            AuthorityOperationApproval::decode(&approval_bytes),
            Ok(approval.clone())
        );
        assert_ne!(call.commitment(), approval.commitment());
        assert_eq!(
            Hash::digest(b"vos/test/aop3-golden", &[&approval_bytes]).0,
            [
                157, 208, 130, 32, 56, 135, 223, 31, 209, 214, 33, 243, 128, 124, 201, 172, 174, 9,
                9, 175, 159, 207, 201, 48, 147, 240, 212, 6, 144, 173, 59, 241,
            ]
        );

        let acknowledgement = issuance_ack(&call, &approval);
        let acknowledgement_bytes = acknowledgement.encode().unwrap();
        assert_eq!(acknowledgement_bytes.get(..4), Some(b"AOI1".as_slice()));
        assert!(acknowledgement_bytes.len() <= MAX_AUTHORITY_OPERATION_ISSUANCE_ACK_WIRE_BYTES);
        assert_eq!(
            AuthorityOperationIssuanceAck::decode(&acknowledgement_bytes),
            Ok(acknowledgement)
        );
        assert_eq!(
            Hash::digest(b"vos/test/aoi1-golden", &[&acknowledgement_bytes]).0,
            [
                154, 98, 170, 195, 138, 191, 62, 130, 135, 31, 148, 78, 180, 19, 252, 60, 209, 25,
                217, 195, 191, 27, 196, 110, 62, 1, 68, 105, 23, 95, 157, 142,
            ]
        );
    }

    #[test]
    fn pca1_is_a_distinct_canonical_tombstone_checkable_application_proof() {
        let controls = private_controls();
        let call = private_call(&controls[0], 0x7c);
        let approved = approval_with_sequence(&call, 8);
        let issuance = issuance_ack(&call, &approved);
        let application = private_application_fact(&call);
        let acknowledgement = private_application_ack(&call, &approved, &issuance, application);

        let encoded = acknowledgement.encode().unwrap();
        assert_eq!(encoded.get(..4), Some(b"PCA1".as_slice()));
        assert!(encoded.len() <= MAX_PRIVATE_CONTROL_APPLICATION_ACK_WIRE_BYTES);
        assert_eq!(
            PrivateControlApplicationAck::decode(&encoded),
            Ok(acknowledgement.clone())
        );
        assert_eq!(
            Hash::digest(b"vos/test/pca1-golden", &[&encoded]).0,
            [
                102, 164, 249, 242, 154, 94, 14, 77, 3, 253, 254, 27, 155, 245, 170, 80, 248, 194,
                204, 157, 68, 127, 244, 220, 130, 27, 180, 40, 106, 206, 183, 35,
            ]
        );
        assert_ne!(application.commitment(), Hash::ZERO);
        assert_ne!(acknowledgement.commitment(), issuance.commitment());
        assert_ne!(
            acknowledgement.authorization_invocation,
            acknowledgement.issuance_invocation
        );
        assert_ne!(
            acknowledgement.authorization_invocation,
            acknowledgement.application_invocation
        );
        assert_ne!(
            acknowledgement.issuance_invocation,
            acknowledgement.application_invocation
        );
        assert_eq!(
            acknowledgement.application_invocation,
            PrivateControlApplicationAck::derive_application_invocation_from_issuance(
                issuance.authority,
                issuance.authorization_invocation,
                issuance.acknowledgement_invocation,
                issuance.authorization_sequence,
                issuance.commitment(),
            )
        );
        assert!(acknowledgement.matches_pending(&call, &approved, &issuance, &application,));
        assert_eq!(
            acknowledgement.verify_pending_with(
                &call,
                &approved,
                &issuance,
                &application,
                call.authority.binding,
                &TestVerifier,
            ),
            Ok(())
        );
        assert!(acknowledgement.matches_issuance_tombstone(
            issuance.authority,
            issuance.authorization_invocation,
            issuance.acknowledgement_invocation,
            issuance.authorization_sequence,
            issuance.commitment(),
        ));
        assert_eq!(
            acknowledgement.verify_issuance_tombstone_with(
                issuance.authority,
                issuance.authorization_invocation,
                issuance.acknowledgement_invocation,
                issuance.authorization_sequence,
                issuance.commitment(),
                &TestVerifier,
            ),
            Ok(())
        );

        let context = InvocationContext {
            invocation: acknowledgement.application_invocation,
            actor: acknowledgement.authority.binding.issuer.actor,
            mode: MethodMode::Linear,
            origin: InvocationOrigin::anonymous(),
            roles: InvocationRoleClaims::none(),
            observed_slot: application.applied_at,
        };
        assert!(acknowledgement.matches_invocation_context(&context));
        let mut relayed = context;
        relayed.origin.principal = Some(call.principal);
        relayed.origin.credential = Some(call.credential);
        relayed.origin.transport_node = call.authenticated_node;
        assert!(acknowledgement.matches_invocation_context(&relayed));

        let mut wrong_context = context;
        wrong_context.invocation = issuance.acknowledgement_invocation;
        assert!(!acknowledgement.matches_invocation_context(&wrong_context));
        wrong_context = context;
        wrong_context.observed_slot += 1;
        assert!(!acknowledgement.matches_invocation_context(&wrong_context));
        wrong_context = context;
        wrong_context.actor = ActorId([0x7d; 32]);
        assert!(!acknowledgement.matches_invocation_context(&wrong_context));
        wrong_context = context;
        wrong_context.mode = MethodMode::Merge;
        assert!(!acknowledgement.matches_invocation_context(&wrong_context));
        wrong_context = context;
        wrong_context.origin.capability = Some(CapabilityId([0x7e; 32]));
        assert!(!acknowledgement.matches_invocation_context(&wrong_context));

        for (index, control) in controls[1..].iter().enumerate() {
            let call = private_call(control, 0x7f + index as u8);
            let approved = approval(&call);
            let issuance = issuance_ack(&call, &approved);
            let application = private_application_fact(&call);
            let acknowledgement = private_application_ack(&call, &approved, &issuance, application);
            assert!(acknowledgement.matches_pending(&call, &approved, &issuance, &application,));
            assert_eq!(
                acknowledgement.verify_pending_with(
                    &call,
                    &approved,
                    &issuance,
                    &application,
                    call.authority.binding,
                    &TestVerifier,
                ),
                Ok(())
            );
        }
    }

    #[test]
    fn pca1_rejects_substitution_bad_ordering_and_unverified_signatures() {
        let controls = private_controls();
        let call = private_call(&controls[0], 0x7e);
        let approved = approval(&call);
        let issuance = issuance_ack(&call, &approved);
        let application = private_application_fact(&call);
        let acknowledgement = private_application_ack(&call, &approved, &issuance, application);

        let mut before_issuance = acknowledgement.clone();
        before_issuance.application.applied_at = issuance.issued_at - 1;
        resign_private_application_ack(&mut before_issuance);
        assert_eq!(
            before_issuance.validate_shape(),
            Err(AuthorityOperationProtocolError::InvalidApplication)
        );

        let mut issuance_before_validity = acknowledgement.clone();
        issuance_before_validity.issued_at = approved.selector.valid_from - 1;
        resign_private_application_ack(&mut issuance_before_validity);
        assert_eq!(
            issuance_before_validity.validate_shape(),
            Err(AuthorityOperationProtocolError::InvalidApplication)
        );

        let mut after_expiry = acknowledgement.clone();
        after_expiry.application.applied_at = approved.selector.expires_at + 1;
        resign_private_application_ack(&mut after_expiry);
        assert_eq!(
            after_expiry.validate_shape(),
            Err(AuthorityOperationProtocolError::InvalidApplication)
        );

        let mut wrong_head = acknowledgement.clone();
        wrong_head.application.reopened_control_head = Hash([0x7f; 32]);
        resign_private_application_ack(&mut wrong_head);
        assert_eq!(
            wrong_head.validate_shape(),
            Err(AuthorityOperationProtocolError::InvalidApplication)
        );
        let mut missing_state = acknowledgement.clone();
        missing_state.application.reopened_control_state = Hash::ZERO;
        resign_private_application_ack(&mut missing_state);
        assert_eq!(
            missing_state.validate_shape(),
            Err(AuthorityOperationProtocolError::InvalidApplication)
        );
        let mut missing_members = acknowledgement.clone();
        missing_members.application.post_member_set = Hash::ZERO;
        resign_private_application_ack(&mut missing_members);
        assert_eq!(
            missing_members.validate_shape(),
            Err(AuthorityOperationProtocolError::InvalidApplication)
        );

        let mut substituted = acknowledgement.clone();
        substituted.operation_call = Hash([0x80; 32]);
        resign_private_application_ack(&mut substituted);
        assert_eq!(
            substituted.verify_with(call.authority.binding, &TestVerifier),
            Ok(())
        );
        assert!(!substituted.matches_pending(&call, &approved, &issuance, &application,));
        assert_eq!(
            substituted.verify_pending_with(
                &call,
                &approved,
                &issuance,
                &application,
                call.authority.binding,
                &TestVerifier,
            ),
            Err(AuthorityOperationProtocolError::MismatchedApplication)
        );

        let mut wrong_issued_at = acknowledgement.clone();
        wrong_issued_at.issued_at -= 1;
        resign_private_application_ack(&mut wrong_issued_at);
        assert_eq!(wrong_issued_at.validate_shape(), Ok(()));
        assert!(!wrong_issued_at.matches_pending(&call, &approved, &issuance, &application,));

        let mut wrong_application_invocation = acknowledgement.clone();
        wrong_application_invocation.application_invocation = InvocationId([0x81; 32]);
        resign_private_application_ack(&mut wrong_application_invocation);
        assert_eq!(
            wrong_application_invocation.validate_shape(),
            Err(AuthorityOperationProtocolError::InvalidTarget)
        );
        let mut reused_issuance_invocation = acknowledgement.clone();
        reused_issuance_invocation.application_invocation =
            reused_issuance_invocation.issuance_invocation;
        resign_private_application_ack(&mut reused_issuance_invocation);
        assert_eq!(
            reused_issuance_invocation.validate_shape(),
            Err(AuthorityOperationProtocolError::InvalidTarget)
        );

        let mut bad_signature = acknowledgement.clone();
        bad_signature.signature[0] ^= 1;
        assert_eq!(bad_signature.validate_shape(), Ok(()));
        assert_eq!(
            bad_signature.verify_with(call.authority.binding, &TestVerifier),
            Err(AuthorityOperationProtocolError::InvalidSignature)
        );
        let mut bad_receipt = acknowledgement.clone();
        bad_receipt.receipt.signature[0] ^= 1;
        resign_private_application_ack(&mut bad_receipt);
        assert_eq!(bad_receipt.validate_shape(), Ok(()));
        assert_eq!(
            bad_receipt.verify_with(call.authority.binding, &TestVerifier),
            Err(AuthorityOperationProtocolError::InvalidSignature)
        );
        let mut unrelated_binding = call.authority.binding;
        unrelated_binding.policy = Hash([0x82; 32]);
        assert_eq!(
            acknowledgement.verify_with(unrelated_binding, &TestVerifier),
            Err(AuthorityOperationProtocolError::InvalidApplication)
        );

        assert!(!acknowledgement.matches_issuance_tombstone(
            issuance.authority,
            issuance.authorization_invocation,
            issuance.acknowledgement_invocation,
            NonZeroU64::new(issuance.authorization_sequence.get() + 1).unwrap(),
            issuance.commitment(),
        ));
        assert!(!acknowledgement.matches_issuance_tombstone(
            issuance.authority,
            issuance.authorization_invocation,
            InvocationId([0x83; 32]),
            issuance.authorization_sequence,
            issuance.commitment(),
        ));
        assert!(!acknowledgement.matches_issuance_tombstone(
            issuance.authority,
            issuance.authorization_invocation,
            issuance.acknowledgement_invocation,
            issuance.authorization_sequence,
            Hash([0x84; 32]),
        ));

        let revoke_call = private_call(&controls[1], 0x85);
        let revoke_approval = approval(&revoke_call);
        let revoke_issuance = issuance_ack(&revoke_call, &revoke_approval);
        let mut wrong_revoke_application = private_application_fact(&revoke_call);
        wrong_revoke_application.post_member_set = Hash([0x86; 32]);
        assert_eq!(wrong_revoke_application.validate_shape(), Ok(()));
        let wrong_revoke_ack = private_application_ack(
            &revoke_call,
            &revoke_approval,
            &revoke_issuance,
            wrong_revoke_application,
        );
        assert!(!wrong_revoke_ack.matches_pending(
            &revoke_call,
            &revoke_approval,
            &revoke_issuance,
            &wrong_revoke_application,
        ));
    }

    #[test]
    fn pca1_old_truncated_trailing_and_oversize_wires_fail_closed() {
        let controls = private_controls();
        let call = private_call(&controls[2], 0x85);
        let approved = approval(&call);
        let issuance = issuance_ack(&call, &approved);
        let application = private_application_fact(&call);
        let acknowledgement = private_application_ack(&call, &approved, &issuance, application);
        let encoded = acknowledgement.encode().unwrap();

        let mut old = encoded.clone();
        old[..4].copy_from_slice(b"AOI1");
        assert!(PrivateControlApplicationAck::decode(&old).is_err());
        let mut old_abi = encoded.clone();
        old_abi[4] ^= 1;
        assert!(PrivateControlApplicationAck::decode(&old_abi).is_err());
        let mut truncated = encoded.clone();
        truncated.pop();
        assert!(PrivateControlApplicationAck::decode(&truncated).is_err());
        let mut trailing = encoded;
        trailing.push(0);
        assert!(PrivateControlApplicationAck::decode(&trailing).is_err());
        assert_eq!(
            PrivateControlApplicationAck::decode(&vec![
                0;
                MAX_PRIVATE_CONTROL_APPLICATION_ACK_WIRE_BYTES
                    + 1
            ]),
            Err(WireError::LimitExceeded)
        );

        let mut unsigned = acknowledgement;
        unsigned.signature = [0; AUTHORITY_SIGNATURE_BYTES];
        assert_eq!(unsigned.encode(), Err(WireError::InvalidValue));
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
        changed.invocation = changed.expected_invocation();
        assert_eq!(
            changed.verify_with(&TestVerifier),
            Err(AuthorityOperationProtocolError::InvalidSignature)
        );

        let mut changed_sequence = call.clone();
        changed_sequence.request_sequence =
            NonZeroU64::new(call.request_sequence.get() + 1).unwrap();
        assert_eq!(
            changed_sequence.validate_shape(),
            Err(AuthorityOperationProtocolError::InvalidTarget)
        );
        changed_sequence.invocation = changed_sequence.expected_invocation();
        assert_eq!(
            changed_sequence.verify_with(&TestVerifier),
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
        let approved = approval(&call);
        assert_eq!(approved.authenticated_node, None);
        assert!(approved.matches_call(&call));
        let acknowledged = issuance_ack(&call, &approved);
        assert_eq!(
            acknowledged.verify_with(call.authority.binding, &TestVerifier),
            Ok(())
        );
        assert!(acknowledged.matches_pending(&call, &approved));

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
    fn issuance_ack_binds_pending_preimages_receipt_slot_and_own_invocation() {
        let call = invoke_call();
        let approval = approval(&call);
        let acknowledgement = issuance_ack(&call, &approval);
        assert_eq!(
            approval.acknowledgement_invocation,
            AuthorityOperationApproval::derive_acknowledgement_invocation(&call)
        );
        assert_ne!(approval.acknowledgement_invocation, call.invocation);
        assert_eq!(
            acknowledgement.verify_with(call.authority.binding, &TestVerifier),
            Ok(())
        );
        let mut unrelated_binding = call.authority.binding;
        unrelated_binding.policy = Hash([0x8f; 32]);
        assert!(unrelated_binding.is_valid());
        assert_eq!(
            acknowledgement.verify_with(unrelated_binding, &TestVerifier),
            Err(AuthorityOperationProtocolError::InvalidAcknowledgement)
        );
        assert!(acknowledgement.matches_pending(&call, &approval));

        let context = InvocationContext {
            invocation: acknowledgement.acknowledgement_invocation,
            actor: acknowledgement.authority.binding.issuer.actor,
            mode: MethodMode::Linear,
            origin: InvocationOrigin::anonymous(),
            roles: InvocationRoleClaims::none(),
            observed_slot: acknowledgement.issued_at,
        };
        assert!(acknowledgement.matches_invocation_context(&context));
        let mut changed_context = context;
        changed_context.invocation = call.invocation;
        assert!(!acknowledgement.matches_invocation_context(&changed_context));
        changed_context = context;
        changed_context.origin.actor = Some(ActorId([0x90; 32]));
        assert!(!acknowledgement.matches_invocation_context(&changed_context));
        changed_context = context;
        changed_context.observed_slot += 1;
        assert!(!acknowledgement.matches_invocation_context(&changed_context));

        let mut relayed_context = context;
        relayed_context.origin = InvocationOrigin {
            principal: Some(call.principal),
            transport_node: call.authenticated_node,
            credential: Some(call.credential),
            actor: None,
            capability: None,
        };
        assert!(acknowledgement.matches_invocation_context(&relayed_context));

        let mut same_invocation = acknowledgement.clone();
        same_invocation.acknowledgement_invocation = same_invocation.authorization_invocation;
        assert_eq!(
            same_invocation.validate_shape(),
            Err(AuthorityOperationProtocolError::InvalidTarget)
        );

        let mut different_call = call.clone();
        different_call.requested_expires_at -= 1;
        different_call.invocation = different_call.expected_invocation();
        different_call.signature = test_signature(
            &different_call.credential_public_key,
            &different_call.signing_bytes(),
        );
        assert_eq!(different_call.validate_shape(), Ok(()));
        assert_ne!(
            AuthorityOperationApproval::derive_acknowledgement_invocation(&different_call),
            approval.acknowledgement_invocation
        );
        assert!(!acknowledgement.matches_pending(&different_call, &approval));

        let mut changed_approval = approval.clone();
        changed_approval.authorization_sequence = NonZeroU64::new(8).unwrap();
        assert_eq!(changed_approval.validate_shape(), Ok(()));
        assert!(!acknowledgement.matches_pending(&call, &changed_approval));

        let mut changed = acknowledgement.clone();
        changed.authority.system_agent = AgentId([0x91; 32]);
        assert_eq!(changed.validate_shape(), Ok(()));
        assert!(!changed.matches_pending(&call, &approval));
        assert_eq!(
            changed.verify_with(call.authority.binding, &TestVerifier),
            Err(AuthorityOperationProtocolError::InvalidSignature)
        );

        let mut changed = acknowledgement.clone();
        changed.issued_at -= 1;
        assert_eq!(changed.validate_shape(), Ok(()));
        assert_eq!(
            changed.verify_with(call.authority.binding, &TestVerifier),
            Err(AuthorityOperationProtocolError::InvalidSignature)
        );

        let mut invalid_receipt_signature = acknowledgement.clone();
        invalid_receipt_signature.receipt.signature[0] ^= 1;
        invalid_receipt_signature.signature = test_signature(
            &invalid_receipt_signature.authority.binding.public_key,
            &invalid_receipt_signature.signing_bytes(),
        );
        assert_eq!(invalid_receipt_signature.validate_shape(), Ok(()));
        assert_eq!(
            invalid_receipt_signature.verify_with(call.authority.binding, &TestVerifier),
            Err(AuthorityOperationProtocolError::InvalidSignature)
        );

        let mut invalid_ack_signature = acknowledgement.clone();
        invalid_ack_signature.signature[0] ^= 1;
        assert_eq!(invalid_ack_signature.validate_shape(), Ok(()));
        assert_eq!(
            invalid_ack_signature.verify_with(call.authority.binding, &TestVerifier),
            Err(AuthorityOperationProtocolError::InvalidSignature)
        );

        let mut management_replay = acknowledgement.clone();
        management_replay.receipt.selector.decision_sequence = 1;
        assert_eq!(
            management_replay.validate_shape(),
            Err(AuthorityOperationProtocolError::InvalidAcknowledgement)
        );
        management_replay = acknowledgement.clone();
        management_replay.receipt.selector.acknowledged_through = 1;
        assert_eq!(
            management_replay.validate_shape(),
            Err(AuthorityOperationProtocolError::InvalidAcknowledgement)
        );

        let mut outside_validity = acknowledgement.clone();
        outside_validity.issued_at = outside_validity.receipt.selector.expires_at + 1;
        assert_eq!(
            outside_validity.validate_shape(),
            Err(AuthorityOperationProtocolError::InvalidAcknowledgement)
        );

        let mut changed = acknowledgement;
        changed.receipt.selector.request = Hash([0x92; 32]);
        assert_eq!(changed.validate_shape(), Ok(()));
        assert!(!changed.matches_pending(&call, &approval));
        assert_eq!(
            changed.verify_with(call.authority.binding, &TestVerifier),
            Err(AuthorityOperationProtocolError::InvalidSignature)
        );
    }

    #[test]
    fn verified_issuance_facts_advance_only_one_contiguous_authority_prefix() {
        let make_fact = |discriminator, sequence| {
            let call = call_with_intent(
                AuthorityOperationIntent::invoke(&invocation_work()).unwrap(),
                discriminator,
            );
            let approval = approval_with_sequence(&call, sequence);
            issuance_ack(&call, &approval)
                .verified_retirement_fact(&call, &approval, &TestVerifier)
                .unwrap()
        };
        let first = make_fact(0x93, 1);
        let second = make_fact(0x94, 2);
        let third = make_fact(0x95, 3);
        assert_eq!(first.authority(), authority_target());
        assert_eq!(first.authorization_sequence().get(), 1);
        assert_ne!(first.issuance_ack(), Hash::ZERO);

        let mut floor = AuthorityOperationRetirementFloor::initial(authority_target()).unwrap();
        assert_eq!(
            floor.advance(second),
            Err(AuthorityOperationProtocolError::NonContiguousRetirement)
        );
        assert_eq!(floor.retired_through(), 0);
        assert_eq!(floor.advance(first), Ok(()));
        assert_eq!(floor.retired_through(), 1);
        assert_eq!(
            floor.advance(first),
            Err(AuthorityOperationProtocolError::NonContiguousRetirement)
        );
        assert_eq!(floor.advance(second), Ok(()));

        let reopened = AuthorityOperationRetirementFloor::reopen_durable(
            floor.authority(),
            floor.retired_through(),
        )
        .unwrap();
        assert_eq!(reopened, floor);

        let mut cross_authority = third;
        cross_authority.authority.system_agent = AgentId([0x96; 32]);
        assert_eq!(
            floor.advance(cross_authority),
            Err(AuthorityOperationProtocolError::NonContiguousRetirement)
        );
        assert_eq!(floor.retired_through(), 2);
        assert_eq!(floor.advance(third), Ok(()));
        assert_eq!(floor.retired_through(), 3);

        let mut exhausted =
            AuthorityOperationRetirementFloor::reopen_durable(authority_target(), u64::MAX)
                .unwrap();
        assert_eq!(
            exhausted.advance(third),
            Err(AuthorityOperationProtocolError::NonContiguousRetirement)
        );
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

        // AOP3 cannot reconstruct its retained AOC3 preimage. A substituted
        // nonzero commitment is structurally canonical, so a signer must
        // reopen the call and require `matches_call` before issuing a receipt.
        let mut detached = approval.clone();
        detached.operation_call = Hash([0x7e; 32]);
        assert_eq!(detached.validate_shape(), Ok(()));
        assert!(!detached.matches_call(&call));
        let mut wrong_acknowledgement = approval.clone();
        wrong_acknowledgement.acknowledgement_invocation = InvocationId([0x7f; 32]);
        assert_eq!(wrong_acknowledgement.validate_shape(), Ok(()));
        assert!(!wrong_acknowledgement.matches_call(&call));

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
    fn catalog_approval_owns_generation_and_rejects_every_substitution() {
        for kind in [CatalogMutationKind::Publish, CatalogMutationKind::Withdraw] {
            let intent = catalog_intent(kind);
            let call = call_with_intent(intent.clone(), 0x7f);
            let approval = approval(&call);
            let request = approval.catalog_request().unwrap();
            assert_eq!(request.generation, approval.authorization_sequence);
            assert!(intent.matches_catalog_request(
                approval.authorization_sequence,
                approval.operation_call,
                &request,
            ));
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
            changed = request.clone();
            changed.generation = NonZeroU64::new(6).unwrap();
            assert!(!approval.matches_catalog_request(&changed));

            let next = approval_with_sequence(&call, 8);
            let next_request = next.catalog_request().unwrap();
            assert_eq!(next_request.generation, NonZeroU64::new(8).unwrap());
            assert_ne!(next_request.invocation, request.invocation);
            assert_ne!(next.selector.request, approval.selector.request);
            assert!(!approval.matches_catalog_request(&next_request));

            let distinct_call = call_with_intent(intent.clone(), 0x80);
            let distinct = approval_with_sequence(&distinct_call, 7);
            let distinct_request = distinct.catalog_request().unwrap();
            assert_eq!(distinct_request.generation, request.generation);
            assert_ne!(distinct.operation_call, approval.operation_call);
            assert_ne!(distinct_request.invocation, request.invocation);
            assert_ne!(distinct_request.commitment(), request.commitment());
            assert_eq!(approval.catalog_request(), Some(request.clone()));

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
        let replacement = private_node(0x6c);
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
        old[..4].copy_from_slice(b"AOC1");
        assert!(AuthorityOperationCall::decode(&old).is_err());
        let mut old = bytes.clone();
        old[..4].copy_from_slice(b"AOC2");
        assert!(AuthorityOperationCall::decode(&old).is_err());
        let mut wrong_family = bytes.clone();
        wrong_family[..4].copy_from_slice(b"ACC2");
        assert!(AuthorityOperationCall::decode(&wrong_family).is_err());
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
        old[..4].copy_from_slice(b"AOP1");
        assert!(AuthorityOperationApproval::decode(&old).is_err());
        let mut old = approved.encode().unwrap();
        old[..4].copy_from_slice(b"AOP2");
        assert!(AuthorityOperationApproval::decode(&old).is_err());
        let mut wrong_family = approved.encode().unwrap();
        wrong_family[..4].copy_from_slice(b"MAP1");
        assert!(AuthorityOperationApproval::decode(&wrong_family).is_err());
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

        let acknowledgement = issuance_ack(&call, &approved);
        let encoded = acknowledgement.encode().unwrap();
        let mut old = encoded.clone();
        old[..4].copy_from_slice(b"MAA1");
        assert!(AuthorityOperationIssuanceAck::decode(&old).is_err());
        let mut trailing = encoded;
        trailing.push(0);
        assert!(AuthorityOperationIssuanceAck::decode(&trailing).is_err());
        assert_eq!(
            AuthorityOperationIssuanceAck::decode(&vec![
                0;
                MAX_AUTHORITY_OPERATION_ISSUANCE_ACK_WIRE_BYTES
                    + 1
            ]),
            Err(WireError::LimitExceeded)
        );

        let mut unknown = Decoder::new(&[0xff]);
        assert_eq!(decode_intent(&mut unknown), Err(DecodeError::InvalidTag));
    }
}
