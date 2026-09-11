//! Self-authenticating authority calls for non-management operation domains.
//!
//! Management keeps its ACC3/MAP2/MAA2 replay protocol. This sibling family
//! covers invocation, catalog, and Private-Agent controls without widening or
//! accepting those older wire generations. A call authenticates the complete
//! requested intent with a credential signature; an approval materializes the
//! exact selector which an authority signer may turn into an [`AuthorityReceipt`].
//! AOI1 proves only durable receipt issuance; the separate PCA2 protocol proves
//! that a Private runtime later applied and reopened an exact PCTL control.
//! PAR1 is the mutually exclusive terminal proof that the issued capability
//! was retired after an unchanged, nondurable guest denial.

use alloc::vec::Vec;
use core::num::NonZeroU64;

use vos_protocol::wire::{DecodeError, Decoder, Encoder};

use crate::authority::{
    AuthorityActorTarget, AuthorityCredentialVerifier, AuthorityEvidence,
    AuthorityIngressAuthentication, AuthorityLaneRoots, AuthorityOperationKind, AuthorityReceipt,
    AuthorityReceiptSelector, AuthorityVerifier, CREDENTIAL_PUBLIC_KEY_BYTES,
    CREDENTIAL_SIGNATURE_BYTES, ManagedAgentTarget,
};
use crate::catalog::{
    CatalogActorTarget, CatalogAlias, CatalogMutationKind, CatalogMutationRequest,
    CatalogPublication,
};
use crate::private::{
    MAX_PRIVATE_NODES, PrivateActorLifecycleKind, PrivateControlOperation, PrivateControlRecord,
    PrivateNodeIdentity,
};
use crate::wire::CanonicalWire;
use crate::{
    ActorId, AgentId, AgentProfile, BlobRef, CredentialId, DeploymentId, Hash, InvocationContext,
    InvocationId, InvocationOrigin, InvocationRoleClaims, InvocationWork, MethodMode, NodeId,
    PrincipalId, ProducerId, SpaceId,
};

const HEADER_BYTES: usize = 4 + 32;

/// AOC5 remains bounded while carrying the complete 256-member NodeId list
/// authenticated by an offline recovery proof. Private ciphertext and actor
/// messages are still represented only by exact commitments here.
pub const MAX_AUTHORITY_OPERATION_CALL_WIRE_BYTES: usize = 16 * 1024;
/// AOP5 repeats the call's identity tuple and one complete receipt selector.
pub const MAX_AUTHORITY_OPERATION_APPROVAL_WIRE_BYTES: usize = 16 * 1024;
/// Standalone PRA1 proof ceiling. Its only variable field is a canonical list
/// containing at most every Node supported by a Private agent.
pub const MAX_PRIVATE_RECOVERY_AUTHORITY_PROOF_WIRE_BYTES: usize = 12 * 1024;
/// AOI1 contains one complete receipt and fixed-size retained-preimage
/// commitments; it never embeds the AOC5 or AOP5 bytes themselves.
pub const MAX_AUTHORITY_OPERATION_ISSUANCE_ACK_WIRE_BYTES: usize = 4 * 1024;
/// PCA2 is a fixed-size acknowledgement of one durably reopened Private
/// control application. It carries commitments and the resulting projection,
/// never the variable-size PCTL ciphertext or Node list.
pub const MAX_PRIVATE_CONTROL_APPLICATION_ACK_WIRE_BYTES: usize = 4 * 1024;
/// PAR1 is a fixed-size terminal acknowledgement of one Private application
/// capability retired without applying its PCTL control or guest outcome.
pub const MAX_PRIVATE_CONTROL_APPLICATION_RETIREMENT_ACK_WIRE_BYTES: usize = 4 * 1024;

/// Offline signer used only to authenticate one compact authority recovery
/// proof. It is intentionally separate from Principal credentials and from
/// the authority actor's receipt-signing key.
pub trait PrivateRecoveryAuthorityProofSigner {
    fn recovery_public_key(&self) -> [u8; 32];
    fn sign_private_recovery_authority_proof(&self, message: &[u8]) -> [u8; 64];
}

pub trait PrivateRecoveryAuthorityProofVerifier {
    fn verify_private_recovery_authority_proof(
        &self,
        public_key: &[u8; 32],
        message: &[u8],
        signature: &[u8; 64],
    ) -> bool;
}

/// Compact proof of recovery-key possession for one exact PCTL Recover.
///
/// The authority can verify this bounded object without receiving the PCTL's
/// potentially large encrypted historical keyring. The full PCTL recovery
/// evidence is committed by `recovery_evidence`; the exact replacement NodeId
/// list remains visible so policy can validate every enrolled owner identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrivateRecoveryAuthorityProof {
    pub managed: ManagedAgentTarget,
    pub control: Hash,
    pub control_sequence: u64,
    pub control_previous: Option<Hash>,
    pub next_epoch: u64,
    pub superseded_authority_head: Option<Hash>,
    pub replacement_nodes: Vec<NodeId>,
    pub replacement_member_set: Hash,
    pub replacement_identity_set: Hash,
    pub recovery_evidence: Hash,
    pub recovery_public_key: [u8; 32],
    pub signature: [u8; 64],
}

impl PrivateRecoveryAuthorityProof {
    /// Derive and sign the unique compact proof for one exact recovery PCTL.
    /// The signer must be the same recovery key named by that PCTL.
    pub fn from_control<S: PrivateRecoveryAuthorityProofSigner>(
        managed: ManagedAgentTarget,
        control: &PrivateControlRecord,
        superseded_authority_head: Option<Hash>,
        signer: &S,
    ) -> Result<Self, AuthorityOperationProtocolError> {
        let PrivateControlOperation::Recover {
            superseded_heads,
            next_epoch,
            replacement_nodes,
            ..
        } = &control.operation
        else {
            return Err(AuthorityOperationProtocolError::InvalidIntent);
        };
        let recovery_public_key = signer.recovery_public_key();
        if !managed.is_valid()
            || managed.profile != AgentProfile::Private
            || managed.space != control.space
            || managed.agent != control.agent
            || !control.validate_shape()
            || control.signer != crate::private::PrivateControlSigner::Recovery
            || control.signer_public_key != recovery_public_key
            || superseded_authority_head == Some(Hash::ZERO)
            || superseded_authority_head
                .is_some_and(|head| superseded_heads.binary_search(&head).is_err())
        {
            return Err(AuthorityOperationProtocolError::InvalidIntent);
        }
        let replacement_node_ids: Vec<NodeId> =
            replacement_nodes.iter().map(|node| node.node).collect();
        let mut value = Self {
            managed,
            control: control.commitment(),
            control_sequence: control.sequence,
            control_previous: control.previous,
            next_epoch: next_epoch.epoch,
            superseded_authority_head,
            replacement_member_set: private_member_set_commitment(
                replacement_node_ids.iter().copied(),
            )
            .ok_or(AuthorityOperationProtocolError::InvalidIntent)?,
            replacement_identity_set: private_node_identity_set_commitment(
                replacement_nodes.iter(),
            )
            .ok_or(AuthorityOperationProtocolError::InvalidIntent)?,
            replacement_nodes: replacement_node_ids,
            recovery_evidence: private_recovery_evidence_commitment(control)
                .ok_or(AuthorityOperationProtocolError::InvalidIntent)?,
            recovery_public_key,
            signature: [0; 64],
        };
        value.signature = signer.sign_private_recovery_authority_proof(&value.signing_bytes());
        value.validate_shape()?;
        if !value.matches_control(control) {
            return Err(AuthorityOperationProtocolError::MismatchedCall);
        }
        Ok(value)
    }

    pub fn signing_bytes(&self) -> Vec<u8> {
        private_recovery_authority_proof_signing_bytes(self)
    }

    pub fn commitment(&self) -> Hash {
        Hash::digest(
            b"vos/agent/private-recovery-authority-proof/v1",
            &[&self.signing_bytes(), &self.signature],
        )
    }

    pub fn validate_shape(&self) -> Result<(), AuthorityOperationProtocolError> {
        if !self.managed.is_valid()
            || self.managed.profile != AgentProfile::Private
            || self.control == Hash::ZERO
            || !valid_recovery_control_position(self.control_sequence, self.control_previous)
            || self.next_epoch == 0
            || self.superseded_authority_head == Some(Hash::ZERO)
            || self.replacement_nodes.is_empty()
            || self.replacement_nodes.len() > MAX_PRIVATE_NODES
            || self
                .replacement_nodes
                .iter()
                .any(|node| *node == NodeId::ZERO)
            || !self
                .replacement_nodes
                .windows(2)
                .all(|pair| pair[0] < pair[1])
            || private_member_set_commitment(self.replacement_nodes.iter().copied())
                != Some(self.replacement_member_set)
            || self.replacement_identity_set == Hash::ZERO
            || self.recovery_evidence == Hash::ZERO
            || self.recovery_public_key == [0; 32]
            || self.signature == [0; 64]
            || private_recovery_authority_proof_encoded_len(self)
                > MAX_PRIVATE_RECOVERY_AUTHORITY_PROOF_WIRE_BYTES
        {
            return Err(AuthorityOperationProtocolError::InvalidIntent);
        }
        Ok(())
    }

    pub fn verify_with<V: PrivateRecoveryAuthorityProofVerifier>(
        &self,
        verifier: &V,
    ) -> Result<(), AuthorityOperationProtocolError> {
        self.validate_shape()?;
        if !verifier.verify_private_recovery_authority_proof(
            &self.recovery_public_key,
            &self.signing_bytes(),
            &self.signature,
        ) {
            return Err(AuthorityOperationProtocolError::InvalidSignature);
        }
        Ok(())
    }

    pub fn matches_control(&self, control: &PrivateControlRecord) -> bool {
        let PrivateControlOperation::Recover {
            superseded_heads,
            next_epoch,
            replacement_nodes,
            ..
        } = &control.operation
        else {
            return false;
        };
        self.validate_shape().is_ok()
            && control.validate_shape()
            && control.signer == crate::private::PrivateControlSigner::Recovery
            && control.signer_public_key == self.recovery_public_key
            && control.space == self.managed.space
            && control.agent == self.managed.agent
            && control.commitment() == self.control
            && control.sequence == self.control_sequence
            && control.previous == self.control_previous
            && next_epoch.epoch == self.next_epoch
            && replacement_nodes
                .iter()
                .map(|node| node.node)
                .eq(self.replacement_nodes.iter().copied())
            && private_member_set_commitment(replacement_nodes.iter().map(|node| node.node))
                == Some(self.replacement_member_set)
            && private_node_identity_set_commitment(replacement_nodes.iter())
                == Some(self.replacement_identity_set)
            && private_recovery_evidence_commitment(control) == Some(self.recovery_evidence)
            && self
                .superseded_authority_head
                .is_none_or(|head| superseded_heads.binary_search(&head).is_ok())
    }
}

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
        proof: PrivateRecoveryAuthorityProof,
    },
    RotatePrivateKeys {
        managed: ManagedAgentTarget,
        control: Hash,
        control_sequence: u64,
        control_previous: Option<Hash>,
        epoch: u64,
        member_set: Hash,
    },
    SetPrivateResourcePolicy {
        managed: ManagedAgentTarget,
        control: Hash,
        control_sequence: u64,
        control_previous: Option<Hash>,
        policy: BlobRef,
    },
    PrivateActorLifecycle {
        managed: ManagedAgentTarget,
        control: Hash,
        control_sequence: u64,
        control_previous: Option<Hash>,
        actor: ActorId,
        lifecycle: PrivateActorLifecycleKind,
        request: Hash,
    },
}

impl AuthorityOperationIntent {
    /// Bind every immutable field of one actor invocation while keeping the
    /// potentially 8 KiB message out of the authority call itself.
    pub fn invoke(
        managed: ManagedAgentTarget,
        work: &InvocationWork,
    ) -> Result<Self, AuthorityOperationProtocolError> {
        if !managed.is_valid()
            || managed.space != work.space
            || managed.agent != work.agent
            || managed.runtime_deployment != work.runtime_deployment
            || !work.validate()
        {
            return Err(AuthorityOperationProtocolError::InvalidIntent);
        }
        Ok(Self::InvokeActor {
            managed,
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
                owner: publication.identity.owner,
                profile: publication.identity.profile,
                runtime_deployment: publication.identity.runtime_deployment,
                transition_producer: publication.identity.transition_producer,
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

    /// Project an exact owner-signed PCTL record into the authority policy
    /// fields. Offline Recover requires a separate recovery-key-signed PRA1
    /// and is intentionally rejected by this constructor.
    pub fn private_control(
        managed: ManagedAgentTarget,
        control: &PrivateControlRecord,
    ) -> Result<Self, AuthorityOperationProtocolError> {
        if !managed.is_valid()
            || managed.profile != AgentProfile::Private
            || managed.space != control.space
            || managed.agent != control.agent
            || !control.validate_shape()
        {
            return Err(AuthorityOperationProtocolError::InvalidIntent);
        }
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
            PrivateControlOperation::Recover { .. } => {
                return Err(AuthorityOperationProtocolError::InvalidIntent);
            }
            PrivateControlOperation::RotateKeys { next_epoch } => Self::RotatePrivateKeys {
                managed,
                control: commitment,
                control_sequence: control.sequence,
                control_previous: control.previous,
                epoch: next_epoch.epoch,
                member_set: private_member_set_commitment(
                    next_epoch.sealed_owner_keys.iter().map(|key| key.node),
                )
                .ok_or(AuthorityOperationProtocolError::InvalidIntent)?,
            },
            PrivateControlOperation::SetResourcePolicy { policy } => {
                Self::SetPrivateResourcePolicy {
                    managed,
                    control: commitment,
                    control_sequence: control.sequence,
                    control_previous: control.previous,
                    policy: policy.clone(),
                }
            }
            PrivateControlOperation::ActorLifecycle {
                actor,
                operation,
                request,
            } => Self::PrivateActorLifecycle {
                managed,
                control: commitment,
                control_sequence: control.sequence,
                control_previous: control.previous,
                actor: *actor,
                lifecycle: *operation,
                request: *request,
            },
        };
        value.validate_shape()?;
        Ok(value)
    }

    /// Admit one already-signed compact proof for offline recovery. Building
    /// the proof from a PCTL is kept on [`PrivateRecoveryAuthorityProof`] so a
    /// normal Principal or Admin credential can never stand in for recovery
    /// key possession.
    pub fn private_recovery_control(
        proof: PrivateRecoveryAuthorityProof,
    ) -> Result<Self, AuthorityOperationProtocolError> {
        proof.validate_shape()?;
        Ok(Self::RecoverPrivateAgent { proof })
    }

    pub fn operation(&self) -> AuthorityOperationKind {
        match self {
            Self::InvokeActor { .. } => AuthorityOperationKind::InvokeActor,
            Self::Catalog { .. } => AuthorityOperationKind::PublishCatalog,
            Self::InvitePrivateNode { .. } => AuthorityOperationKind::InvitePrivateNode,
            Self::RevokePrivateNode { .. } => AuthorityOperationKind::RevokePrivateNode,
            Self::RecoverPrivateAgent { .. } => AuthorityOperationKind::RecoverPrivateAgent,
            Self::RotatePrivateKeys { .. } => AuthorityOperationKind::RotatePrivateKeys,
            Self::SetPrivateResourcePolicy { .. } => {
                AuthorityOperationKind::SetPrivateResourcePolicy
            }
            Self::PrivateActorLifecycle { .. } => AuthorityOperationKind::PrivateActorLifecycle,
        }
    }

    pub fn managed(&self) -> ManagedAgentTarget {
        match self {
            Self::InvokeActor { managed, .. }
            | Self::Catalog { managed, .. }
            | Self::InvitePrivateNode { managed, .. }
            | Self::RevokePrivateNode { managed, .. }
            | Self::RotatePrivateKeys { managed, .. }
            | Self::SetPrivateResourcePolicy { managed, .. }
            | Self::PrivateActorLifecycle { managed, .. } => *managed,
            Self::RecoverPrivateAgent { proof } => proof.managed,
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
                    && publication.identity.owner == managed.owner
                    && publication.identity.profile == managed.profile
                    && publication.identity.runtime_deployment == managed.runtime_deployment
                    && publication.identity.transition_producer == managed.transition_producer
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
                    && managed.profile == AgentProfile::Private
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
                    && managed.profile == AgentProfile::Private
                    && *control != Hash::ZERO
                    && valid_owner_control_position(*control_sequence, *control_previous)
                    && *node != NodeId::ZERO
                    && *member_set != Hash::ZERO
            }
            Self::RecoverPrivateAgent { proof } => proof.validate_shape().is_ok(),
            Self::RotatePrivateKeys {
                managed,
                control,
                control_sequence,
                control_previous,
                epoch,
                member_set,
            } => {
                managed.is_valid()
                    && managed.profile == AgentProfile::Private
                    && *control != Hash::ZERO
                    && valid_owner_control_position(*control_sequence, *control_previous)
                    && *epoch != 0
                    && *member_set != Hash::ZERO
            }
            Self::SetPrivateResourcePolicy {
                managed,
                control,
                control_sequence,
                control_previous,
                policy,
            } => {
                managed.is_valid()
                    && managed.profile == AgentProfile::Private
                    && *control != Hash::ZERO
                    && valid_owner_control_position(*control_sequence, *control_previous)
                    && valid_private_blob(policy)
            }
            Self::PrivateActorLifecycle {
                managed,
                control,
                control_sequence,
                control_previous,
                actor,
                request,
                ..
            } => {
                managed.is_valid()
                    && managed.profile == AgentProfile::Private
                    && *control != Hash::ZERO
                    && valid_owner_control_position(*control_sequence, *control_previous)
                    && *actor != ActorId::ZERO
                    && *request != Hash::ZERO
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
            | Self::RotatePrivateKeys { control, .. }
            | Self::SetPrivateResourcePolicy { control, .. }
            | Self::PrivateActorLifecycle { control, .. } => Some(*control),
            // Recover is authorized by the exact recovery-key-signed PRA1,
            // not merely by the PCTL it projects. Multiple valid PRA1 values
            // can name the same control while selecting different authority
            // projection heads; the receipt must therefore bind the complete
            // proof commitment so those values cannot be mixed after issuance.
            Self::RecoverPrivateAgent { proof } => Some(proof.commitment()),
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
        let Ok(expected) = Self::invoke(self.managed(), work) else {
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
        if self.validate_shape().is_err() {
            return false;
        }
        match self {
            Self::RecoverPrivateAgent { proof } => proof.matches_control(control),
            _ => Self::private_control(self.managed(), control)
                .is_ok_and(|expected| self == &expected),
        }
    }

    fn selector_actor(&self) -> (Option<ActorId>, Option<DeploymentId>) {
        match self {
            Self::InvokeActor {
                actor,
                actor_deployment,
                ..
            } => (Some(*actor), Some(*actor_deployment)),
            Self::PrivateActorLifecycle { actor, .. } => (Some(*actor), None),
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

fn valid_private_blob(value: &BlobRef) -> bool {
    value.hash != Hash::ZERO && value.len != 0 && value.len <= crate::MAX_CATALOG_ARTIFACT_BYTES
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
/// Node set without embedding that list in AOC5 or PCA2.
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

/// Commit the exact canonical full identities behind a replacement NodeId
/// list. The authority recomputes this from its enrollment rows, preventing a
/// caller from substituting another transport or encryption identity for the
/// same NodeId.
pub fn private_node_identity_set_commitment<'a>(
    nodes: impl Iterator<Item = &'a PrivateNodeIdentity>,
) -> Option<Hash> {
    let nodes: Vec<&PrivateNodeIdentity> = nodes.collect();
    if nodes.is_empty()
        || nodes.len() > MAX_PRIVATE_NODES
        || nodes.iter().any(|node| !node.validate())
        || !nodes.windows(2).all(|pair| pair[0].node < pair[1].node)
    {
        return None;
    }
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"APIS");
    bytes.extend_from_slice(crate::RUNTIME_ABI_ID.as_bytes());
    Encoder(&mut bytes).list(&nodes, |encoder, node| {
        crate::wire::encode_private_node(encoder, node)
    });
    Some(Hash::digest(
        b"vos/agent/authority-private-node-identity-set/v1",
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

/// Ingress-authenticated request to the exact installed authority actor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorityOperationCall {
    pub invocation: InvocationId,
    pub authority: AuthorityActorTarget,
    pub principal: PrincipalId,
    pub credential: CredentialId,
    /// Monotonic sequence in this credential's general-operation domain.
    /// The authority accepts exactly the successor of its durable high-water.
    pub request_sequence: NonZeroU64,
    pub authentication: AuthorityIngressAuthentication,
    pub requested_valid_from: u64,
    pub requested_expires_at: u64,
    pub intent: AuthorityOperationIntent,
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
                b"vos/agent/authority-operation-authorization-invocation/v5",
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
            b"vos/agent/authority-operation-call/v5",
            &[&self.signing_bytes(), &self.authentication.signature()],
        )
    }

    pub const fn credential_public_key(&self) -> [u8; CREDENTIAL_PUBLIC_KEY_BYTES] {
        self.authentication.credential_public_key()
    }

    pub const fn authenticated_node(&self) -> Option<NodeId> {
        self.authentication.attesting_node()
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
            || !self.authentication.validate_shape(self.credential)
        {
            return Err(AuthorityOperationProtocolError::InvalidCaller);
        }
        self.intent.validate_shape()?;
        if !self
            .intent
            .matches_caller(self.principal, self.credential, self.authenticated_node())
        {
            return Err(AuthorityOperationProtocolError::InvalidCaller);
        }
        if self.requested_valid_from > self.requested_expires_at {
            return Err(AuthorityOperationProtocolError::InvalidValidity);
        }
        if self.invocation != self.expected_invocation() {
            return Err(AuthorityOperationProtocolError::InvalidTarget);
        }
        if authority_operation_call_encoded_len(self) > MAX_AUTHORITY_OPERATION_CALL_WIRE_BYTES {
            return Err(AuthorityOperationProtocolError::LimitExceeded);
        }
        Ok(())
    }

    pub fn verify_api_with<V: AuthorityCredentialVerifier>(
        &self,
        verifier: &V,
    ) -> Result<(), AuthorityOperationProtocolError> {
        self.validate_shape()?;
        let AuthorityIngressAuthentication::ApiCredentialSignature {
            credential_public_key,
            signature,
        } = self.authentication
        else {
            return Err(AuthorityOperationProtocolError::InvalidCaller);
        };
        if !verifier.verify(&credential_public_key, &self.signing_bytes(), &signature) {
            return Err(AuthorityOperationProtocolError::InvalidSignature);
        }
        Ok(())
    }

    pub fn verify_ssh_node_attestation_with<V: AuthorityCredentialVerifier>(
        &self,
        node_public_key: &[u8; CREDENTIAL_PUBLIC_KEY_BYTES],
        verifier: &V,
    ) -> Result<(), AuthorityOperationProtocolError> {
        self.validate_shape()?;
        let AuthorityIngressAuthentication::SshNodeAttestation { signature, .. } =
            self.authentication
        else {
            return Err(AuthorityOperationProtocolError::InvalidCaller);
        };
        if !verifier.verify(node_public_key, &self.signing_bytes(), &signature) {
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
            && context.origin.transport_node == self.authenticated_node()
            && context.origin.actor.is_none()
            && context.origin.capability.is_none()
            && context.roles == InvocationRoleClaims::none()
    }
}

/// Deterministic policy output for one non-management operation call.
///
/// `authorization_sequence` is the authority actor's own exact-retry clock.
/// For catalog operations it is also the only source of the mutation
/// generation; the ingress-authenticated intent contains no caller-selected
/// generation.
/// It is intentionally distinct from the selector's management decision
/// clock, which must remain zero for every operation in this protocol.
/// Shape validation alone cannot reconstruct `operation_call`: before signing
/// a receipt, a consumer must reopen the retained AOC5 preimage and require
/// [`AuthorityOperationApproval::matches_call`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorityOperationApproval {
    pub operation_call: Hash,
    pub authorization_sequence: NonZeroU64,
    pub invocation: InvocationId,
    /// Distinct Linear invocation reserved for acknowledging durable receipt
    /// issuance. Its derivation commits the complete signed AOC5 preimage.
    pub acknowledgement_invocation: InvocationId,
    pub authority: AuthorityActorTarget,
    pub principal: PrincipalId,
    pub credential: CredentialId,
    pub request_sequence: NonZeroU64,
    pub authentication: AuthorityIngressAuthentication,
    pub intent: AuthorityOperationIntent,
    pub selector: AuthorityReceiptSelector,
}

impl AuthorityOperationApproval {
    pub const fn credential_public_key(&self) -> [u8; CREDENTIAL_PUBLIC_KEY_BYTES] {
        self.authentication.credential_public_key()
    }

    pub const fn authenticated_node(&self) -> Option<NodeId> {
        self.authentication.attesting_node()
    }

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

    /// Recompute the AOI1 invocation after the AOC5 preimage has compacted.
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
                b"vos/agent/authority-operation-issuance-acknowledgement-invocation/v5",
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
    /// decodes an AOP5 instead must make the equivalent `matches_call` check
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
            authentication: call.authentication,
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
            || !self.authentication.validate_shape(self.credential)
        {
            return Err(AuthorityOperationProtocolError::InvalidCaller);
        }
        self.intent.validate_shape()?;
        if !self.intent.matches_caller(
            self.principal,
            self.credential,
            self.authentication.attesting_node(),
        ) {
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
            && self.authentication == call.authentication
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
            && self
                .intent
                .request_commitment(self.authorization_sequence, self.operation_call)
                == Some(self.selector.request)
    }
}

/// Authority-signed proof that one exact non-management receipt was issued.
///
/// The actor retains the AOC5 and AOP5 preimages until this AOI1 verifies and
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

    /// Match the exact actor-retained AOC5 and AOP5 preimages. A valid AOI1
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
    /// Exact commitment of the complete node-local PCRS3 value constructed
    /// from the durably reopened Store position and Private runtime image.
    pub reopened_runtime_state: Hash,
    /// Exact commitment of the successor replica-stable Private runtime
    /// projection. Unlike PCRS3, this projection can be carried and checked by
    /// another replica without disclosing its node-local runtime image.
    pub stable_projection: Hash,
    /// Exact reopened control head. A valid application makes the authorized
    /// PCTL control the new head, so this must equal `control`.
    pub reopened_control_head: Hash,
    pub applied_at: u64,
}

impl PrivateControlApplicationFact {
    pub fn validate_shape(&self) -> Result<(), AuthorityOperationProtocolError> {
        let valid_position = match self.operation {
            AuthorityOperationKind::InvitePrivateNode
            | AuthorityOperationKind::RevokePrivateNode
            | AuthorityOperationKind::RotatePrivateKeys
            | AuthorityOperationKind::SetPrivateResourcePolicy
            | AuthorityOperationKind::PrivateActorLifecycle => {
                valid_owner_control_position(self.control_sequence, self.control_previous)
            }
            AuthorityOperationKind::RecoverPrivateAgent => {
                valid_recovery_control_position(self.control_sequence, self.control_previous)
            }
            _ => false,
        };
        if !self.managed.is_valid()
            || self.managed.profile != AgentProfile::Private
            || self.control == Hash::ZERO
            || self.post_member_set == Hash::ZERO
            || self.reopened_runtime_state == Hash::ZERO
            || self.stable_projection == Hash::ZERO
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
            AuthorityOperationIntent::RecoverPrivateAgent { proof } => {
                self.managed == proof.managed
                    && self.operation == AuthorityOperationKind::RecoverPrivateAgent
                    && self.control == proof.control
                    && self.control_sequence == proof.control_sequence
                    && self.control_previous == proof.control_previous
                    && self.epoch == proof.next_epoch
                    && self.post_member_set == proof.replacement_member_set
            }
            AuthorityOperationIntent::RotatePrivateKeys {
                managed,
                control,
                control_sequence,
                control_previous,
                epoch,
                member_set,
            } => {
                self.managed == *managed
                    && self.operation == AuthorityOperationKind::RotatePrivateKeys
                    && self.control == *control
                    && self.control_sequence == *control_sequence
                    && self.control_previous == *control_previous
                    && self.epoch == *epoch
                    && self.post_member_set == *member_set
            }
            AuthorityOperationIntent::SetPrivateResourcePolicy {
                managed,
                control,
                control_sequence,
                control_previous,
                ..
            }
            | AuthorityOperationIntent::PrivateActorLifecycle {
                managed,
                control,
                control_sequence,
                control_previous,
                ..
            } => {
                self.managed == *managed
                    && self.operation == intent.operation()
                    && self.control == *control
                    && self.control_sequence == *control_sequence
                    && self.control_previous == *control_previous
            }
            AuthorityOperationIntent::InvokeActor { .. }
            | AuthorityOperationIntent::Catalog { .. } => false,
        }
    }
}

/// Authority-signed proof that one exact Private control was durably applied
/// and reopened after its non-management receipt had been issued.
///
/// PCA2 is distinct from AOI1: issuance alone never proves application. Its
/// three invocation IDs reserve independent exact-retry domains for AOC5,
/// AOI1, and PCA2. The AOC5/AOP5 commitments are repeated for auditability;
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
    /// Exact AOI1 issuance slot, repeated under the PCA2 signature so a PCA2
    /// reopened after AOI1 compaction still proves application ordering.
    pub issued_at: u64,
    pub application: PrivateControlApplicationFact,
    pub signature: [u8; crate::authority::AUTHORITY_SIGNATURE_BYTES],
}

impl PrivateControlApplicationAck {
    /// Derive PCA2's third invocation from the exact verified AOI1.
    pub fn derive_application_invocation(issuance: &AuthorityOperationIssuanceAck) -> InvocationId {
        Self::derive_application_invocation_from_issuance(
            issuance.authority,
            issuance.authorization_invocation,
            issuance.acknowledgement_invocation,
            issuance.authorization_sequence,
            issuance.commitment(),
        )
    }

    /// Derive the PCA2 invocation from the fixed-size AOI1 tombstone tuple.
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
            b"vos/agent/private-control-application-ack/v2",
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
            || (selector.operation != AuthorityOperationKind::RecoverPrivateAgent
                && selector.request != self.application.control)
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

    /// Verify the receipt and PCA2 signature with an independently selected
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

    /// Match all retained AOC5/AOP5/AOI1 preimages and the exact runtime
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

    /// Match the compact issuance tuple retained after AOC5/AOP5/AOI1
    /// preimages have retired. The PCA2 signature still must be independently
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

    /// Verify a PCA2 after issuance preimages have compacted, using the exact
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

    /// Bind PCA2 to its third exact Linear authority-actor invocation. As with
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

/// Authority-signed terminal retirement of one issued Private application
/// capability which did not apply its PCTL control.
///
/// PAR1 deliberately contains no guest outcome, error, successor state, or
/// application fact. The trusted host may request it only after an exact
/// runtime attempt returned a deterministic management denial and reopened
/// the byte-identical predecessor. It shares PCA2's third invocation because
/// application and unapplied retirement are mutually exclusive resolutions
/// of the same issued capability.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrivateControlApplicationRetirementAck {
    pub authorization_invocation: InvocationId,
    pub issuance_invocation: InvocationId,
    pub application_invocation: InvocationId,
    pub authority: AuthorityActorTarget,
    pub operation_call: Hash,
    pub approval: Hash,
    pub issuance_ack: Hash,
    pub authorization_sequence: NonZeroU64,
    pub receipt: AuthorityReceipt,
    pub issued_at: u64,
    /// Exact logical slot pledged before the runtime attempt which produced
    /// the eligible unchanged denial. This is never relay or acceptance time.
    pub resolved_at: u64,
    pub signature: [u8; crate::authority::AUTHORITY_SIGNATURE_BYTES],
}

impl PrivateControlApplicationRetirementAck {
    /// Derive the shared PCA2/PAR1 terminal-resolution invocation.
    pub fn derive_application_invocation(issuance: &AuthorityOperationIssuanceAck) -> InvocationId {
        PrivateControlApplicationAck::derive_application_invocation(issuance)
    }

    /// Derive the shared terminal-resolution invocation from an authenticated
    /// compact AOI1 tombstone tuple.
    pub fn derive_application_invocation_from_issuance(
        authority: AuthorityActorTarget,
        authorization_invocation: InvocationId,
        issuance_invocation: InvocationId,
        authorization_sequence: NonZeroU64,
        issuance_ack: Hash,
    ) -> InvocationId {
        PrivateControlApplicationAck::derive_application_invocation_from_issuance(
            authority,
            authorization_invocation,
            issuance_invocation,
            authorization_sequence,
            issuance_ack,
        )
    }

    pub fn signing_bytes(&self) -> Vec<u8> {
        private_control_application_retirement_ack_signing_bytes(self)
    }

    pub fn commitment(&self) -> Hash {
        Hash::digest(
            b"vos/agent/private-control-application-retirement-ack/v1",
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
        {
            return Err(AuthorityOperationProtocolError::InvalidTarget);
        }
        if self.operation_call == Hash::ZERO
            || self.approval == Hash::ZERO
            || self.issuance_ack == Hash::ZERO
            || self.signature == [0; crate::authority::AUTHORITY_SIGNATURE_BYTES]
            || self.issued_at > self.resolved_at
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
            || selector.space != self.authority.space
            || !matches!(
                selector.operation,
                AuthorityOperationKind::InvitePrivateNode
                    | AuthorityOperationKind::RevokePrivateNode
                    | AuthorityOperationKind::RecoverPrivateAgent
                    | AuthorityOperationKind::RotatePrivateKeys
                    | AuthorityOperationKind::SetPrivateResourcePolicy
                    | AuthorityOperationKind::PrivateActorLifecycle
            )
            || selector.operation.uses_management_decision_journal()
            || selector.decision_sequence != 0
            || selector.acknowledged_through != 0
            || !selector.is_live_at(self.issued_at)
            || !selector.is_live_at(self.resolved_at)
            || private_control_application_retirement_ack_encoded_len(self)
                > MAX_PRIVATE_CONTROL_APPLICATION_RETIREMENT_ACK_WIRE_BYTES
        {
            return Err(AuthorityOperationProtocolError::InvalidApplication);
        }
        Ok(())
    }

    /// Verify the receipt and PAR1 signature with an independently selected
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
            .verify_at(self.resolved_at, verifier)
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

    /// Match all retained AOC5/AOP5/AOI1 preimages. Verification remains a
    /// separate explicit step; no guest denial is encoded in PAR1.
    pub fn matches_pending(
        &self,
        call: &AuthorityOperationCall,
        approval: &AuthorityOperationApproval,
        issuance: &AuthorityOperationIssuanceAck,
    ) -> bool {
        self.validate_shape().is_ok()
            && !matches!(
                call.intent,
                AuthorityOperationIntent::InvokeActor { .. }
                    | AuthorityOperationIntent::Catalog { .. }
            )
            && issuance.matches_pending(call, approval)
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
            && self.resolved_at >= issuance.issued_at
    }

    pub fn verify_pending_with<V: AuthorityVerifier>(
        &self,
        call: &AuthorityOperationCall,
        approval: &AuthorityOperationApproval,
        issuance: &AuthorityOperationIssuanceAck,
        authority: crate::authority::AgentAuthorityBinding,
        verifier: &V,
    ) -> Result<(), AuthorityOperationProtocolError> {
        if !self.matches_pending(call, approval, issuance) {
            return Err(AuthorityOperationProtocolError::MismatchedApplication);
        }
        issuance.verify_with(authority, verifier)?;
        self.verify_with(authority, verifier)
    }

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

    pub fn matches_invocation_context(&self, context: &InvocationContext) -> bool {
        self.validate_shape().is_ok()
            && context.validate()
            && context.invocation == self.application_invocation
            && context.actor == self.authority.binding.issuer.actor
            && context.mode == MethodMode::Linear
            && context.observed_slot == self.resolved_at
            && context.origin.actor.is_none()
            && context.origin.capability.is_none()
            && context.roles == InvocationRoleClaims::none()
    }
}

/// Verified issuance evidence for exactly one authorization sequence.
/// Fields are private so callers cannot manufacture a retirement capability
/// without reopening the retained AOC5/AOP5 and verifying AOI1.
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
/// discarding the corresponding AOC5/AOP5/AOI1 preimages. On restart it
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
    encoder.fixed(value.owner.as_bytes());
    encoder.u8(value.profile as u8);
    encoder.fixed(value.runtime_deployment.as_bytes());
    encoder.fixed(value.transition_producer.as_bytes());
}

fn decode_managed(decoder: &mut Decoder<'_>) -> Result<ManagedAgentTarget, DecodeError> {
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

fn encode_private_recovery_authority_proof_unsigned(
    encoder: &mut Encoder<'_>,
    value: &PrivateRecoveryAuthorityProof,
) {
    encode_managed(encoder, value.managed);
    encode_private_control_position(
        encoder,
        value.control,
        value.control_sequence,
        value.control_previous,
    );
    encoder.u64(value.next_epoch);
    encoder.option(&value.superseded_authority_head, |encoder, head| {
        encoder.fixed(head.as_bytes())
    });
    encoder.list(&value.replacement_nodes, |encoder, node| {
        encoder.fixed(node.as_bytes())
    });
    encoder.fixed(value.replacement_member_set.as_bytes());
    encoder.fixed(value.replacement_identity_set.as_bytes());
    encoder.fixed(value.recovery_evidence.as_bytes());
    encoder.fixed(&value.recovery_public_key);
}

fn encode_private_recovery_authority_proof(
    encoder: &mut Encoder<'_>,
    value: &PrivateRecoveryAuthorityProof,
) {
    encode_private_recovery_authority_proof_unsigned(encoder, value);
    encoder.0.extend_from_slice(&value.signature);
}

fn decode_private_recovery_authority_proof(
    decoder: &mut Decoder<'_>,
) -> Result<PrivateRecoveryAuthorityProof, DecodeError> {
    let managed = decode_managed(decoder)?;
    let (control, control_sequence, control_previous) = decode_private_control_position(decoder)?;
    let value = PrivateRecoveryAuthorityProof {
        managed,
        control,
        control_sequence,
        control_previous,
        next_epoch: decoder.u64()?,
        superseded_authority_head: decoder.option(|decoder| Ok(Hash(decoder.fixed()?)))?,
        replacement_nodes: decoder
            .list_bounded(MAX_PRIVATE_NODES, |decoder| Ok(NodeId(decoder.fixed()?)))?,
        replacement_member_set: Hash(decoder.fixed()?),
        replacement_identity_set: Hash(decoder.fixed()?),
        recovery_evidence: Hash(decoder.fixed()?),
        recovery_public_key: decoder.fixed()?,
        signature: decoder
            .take(64)?
            .try_into()
            .map_err(|_| DecodeError::Truncated)?,
    };
    value
        .validate_shape()
        .is_ok()
        .then_some(value)
        .ok_or(DecodeError::NonCanonical)
}

fn private_recovery_authority_proof_signing_bytes(
    value: &PrivateRecoveryAuthorityProof,
) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"PRAS");
    bytes.extend_from_slice(crate::RUNTIME_ABI_ID.as_bytes());
    encode_private_recovery_authority_proof_unsigned(&mut Encoder(&mut bytes), value);
    bytes
}

fn private_recovery_authority_proof_encoded_len(value: &PrivateRecoveryAuthorityProof) -> usize {
    let mut body = Vec::new();
    encode_private_recovery_authority_proof(&mut Encoder(&mut body), value);
    HEADER_BYTES.saturating_add(body.len())
}

impl CanonicalWire for PrivateRecoveryAuthorityProof {
    const MAGIC: [u8; 4] = *b"PRA1";
    const MAX_ENCODED_BYTES: usize = MAX_PRIVATE_RECOVERY_AUTHORITY_PROOF_WIRE_BYTES;

    fn validate_wire(&self) -> bool {
        self.validate_shape().is_ok()
    }

    fn encode_body(&self, encoder: &mut Encoder<'_>) {
        encode_private_recovery_authority_proof(encoder, self);
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        decode_private_recovery_authority_proof(decoder)
    }
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
        AuthorityOperationIntent::RecoverPrivateAgent { proof } => {
            encoder.u8(4);
            encode_private_recovery_authority_proof(encoder, proof);
        }
        AuthorityOperationIntent::RotatePrivateKeys {
            managed,
            control,
            control_sequence,
            control_previous,
            epoch,
            member_set,
        } => {
            encoder.u8(5);
            encode_managed(encoder, *managed);
            encode_private_control_common(
                encoder,
                *control,
                *control_sequence,
                *control_previous,
                *epoch,
            );
            encoder.fixed(member_set.as_bytes());
        }
        AuthorityOperationIntent::SetPrivateResourcePolicy {
            managed,
            control,
            control_sequence,
            control_previous,
            policy,
        } => {
            encoder.u8(6);
            encode_managed(encoder, *managed);
            encode_private_control_position(
                encoder,
                *control,
                *control_sequence,
                *control_previous,
            );
            encode_private_blob(encoder, policy);
        }
        AuthorityOperationIntent::PrivateActorLifecycle {
            managed,
            control,
            control_sequence,
            control_previous,
            actor,
            lifecycle,
            request,
        } => {
            encoder.u8(7);
            encode_managed(encoder, *managed);
            encode_private_control_position(
                encoder,
                *control,
                *control_sequence,
                *control_previous,
            );
            encoder.fixed(actor.as_bytes());
            encoder.u8(*lifecycle as u8);
            encoder.fixed(request.as_bytes());
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
        4 => AuthorityOperationIntent::RecoverPrivateAgent {
            proof: decode_private_recovery_authority_proof(decoder)?,
        },
        5 => {
            let managed = decode_managed(decoder)?;
            let (control, control_sequence, control_previous, epoch) =
                decode_private_control_common(decoder)?;
            AuthorityOperationIntent::RotatePrivateKeys {
                managed,
                control,
                control_sequence,
                control_previous,
                epoch,
                member_set: Hash(decoder.fixed()?),
            }
        }
        6 => {
            let managed = decode_managed(decoder)?;
            let (control, control_sequence, control_previous) =
                decode_private_control_position(decoder)?;
            AuthorityOperationIntent::SetPrivateResourcePolicy {
                managed,
                control,
                control_sequence,
                control_previous,
                policy: decode_private_blob(decoder)?,
            }
        }
        7 => {
            let managed = decode_managed(decoder)?;
            let (control, control_sequence, control_previous) =
                decode_private_control_position(decoder)?;
            AuthorityOperationIntent::PrivateActorLifecycle {
                managed,
                control,
                control_sequence,
                control_previous,
                actor: ActorId(decoder.fixed()?),
                lifecycle: decode_private_lifecycle(decoder)?,
                request: Hash(decoder.fixed()?),
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
    encode_private_control_position(encoder, control, sequence, previous);
    encoder.u64(epoch);
}

fn encode_private_control_position(
    encoder: &mut Encoder<'_>,
    control: Hash,
    sequence: u64,
    previous: Option<Hash>,
) {
    encoder.fixed(control.as_bytes());
    encoder.u64(sequence);
    encoder.option(&previous, |encoder, previous| {
        encoder.fixed(previous.as_bytes())
    });
}

fn decode_private_control_common(
    decoder: &mut Decoder<'_>,
) -> Result<(Hash, u64, Option<Hash>, u64), DecodeError> {
    let (control, sequence, previous) = decode_private_control_position(decoder)?;
    Ok((control, sequence, previous, decoder.u64()?))
}

fn decode_private_control_position(
    decoder: &mut Decoder<'_>,
) -> Result<(Hash, u64, Option<Hash>), DecodeError> {
    Ok((
        Hash(decoder.fixed()?),
        decoder.u64()?,
        decoder.option(|decoder| Ok(Hash(decoder.fixed()?)))?,
    ))
}

fn encode_private_blob(encoder: &mut Encoder<'_>, value: &BlobRef) {
    encoder.fixed(value.hash.as_bytes());
    encoder.u64(value.len);
}

fn decode_private_blob(decoder: &mut Decoder<'_>) -> Result<BlobRef, DecodeError> {
    Ok(BlobRef {
        hash: Hash(decoder.fixed()?),
        len: decoder.u64()?,
    })
}

fn decode_private_lifecycle(
    decoder: &mut Decoder<'_>,
) -> Result<PrivateActorLifecycleKind, DecodeError> {
    match decoder.u8()? {
        0 => Ok(PrivateActorLifecycleKind::Install),
        1 => Ok(PrivateActorLifecycleKind::Upgrade),
        2 => Ok(PrivateActorLifecycleKind::Suspend),
        3 => Ok(PrivateActorLifecycleKind::Resume),
        4 => Ok(PrivateActorLifecycleKind::Remove),
        _ => Err(DecodeError::InvalidTag),
    }
}

fn encode_call_unsigned(encoder: &mut Encoder<'_>, value: &AuthorityOperationCall) {
    encoder.fixed(value.invocation.as_bytes());
    encode_call_invocation_payload(encoder, value);
}

fn encode_call_invocation_payload(encoder: &mut Encoder<'_>, value: &AuthorityOperationCall) {
    crate::wire::encode_authority_actor_target(encoder, value.authority);
    encoder.fixed(value.principal.as_bytes());
    encoder.fixed(value.credential.as_bytes());
    encoder.u64(value.request_sequence.get());
    encoder.u64(value.requested_valid_from);
    encoder.u64(value.requested_expires_at);
    encode_intent(encoder, &value.intent);
    crate::wire::encode_authority_ingress_authentication_unsigned(encoder, value.authentication);
}

fn authority_operation_call_invocation_payload_commitment(value: &AuthorityOperationCall) -> Hash {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"OCP5");
    bytes.extend_from_slice(crate::RUNTIME_ABI_ID.as_bytes());
    encode_call_invocation_payload(&mut Encoder(&mut bytes), value);
    Hash::digest(
        b"vos/agent/authority-operation-invocation-payload/v5",
        &[&bytes],
    )
}

fn authority_operation_call_signing_bytes(value: &AuthorityOperationCall) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"AO5S");
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
    const MAGIC: [u8; 4] = *b"AOC5";
    const MAX_ENCODED_BYTES: usize = MAX_AUTHORITY_OPERATION_CALL_WIRE_BYTES;

    fn validate_wire(&self) -> bool {
        self.validate_shape().is_ok()
    }

    fn encode_body(&self, encoder: &mut Encoder<'_>) {
        encode_call_unsigned(encoder, self);
        encoder
            .0
            .extend_from_slice(&self.authentication.signature());
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let invocation = InvocationId(decoder.fixed()?);
        let authority = crate::wire::decode_authority_actor_target(decoder)?;
        let principal = PrincipalId(decoder.fixed()?);
        let credential = CredentialId(decoder.fixed()?);
        let value = Self {
            invocation,
            authority,
            principal,
            credential,
            request_sequence: NonZeroU64::new(decoder.u64()?).ok_or(DecodeError::NonCanonical)?,
            requested_valid_from: decoder.u64()?,
            requested_expires_at: decoder.u64()?,
            intent: decode_intent(decoder)?,
            authentication: crate::wire::decode_authority_ingress_authentication(decoder)?,
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
    encoder.fixed(value.principal.as_bytes());
    encoder.fixed(value.credential.as_bytes());
    encoder.u64(value.request_sequence.get());
    encode_intent(encoder, &value.intent);
    crate::wire::encode_authority_selector(encoder, &value.selector);
    crate::wire::encode_authority_ingress_authentication(encoder, value.authentication);
}

fn authority_operation_approval_encoded_len(value: &AuthorityOperationApproval) -> usize {
    let mut bytes = Vec::new();
    encode_approval_body(&mut Encoder(&mut bytes), value);
    HEADER_BYTES.saturating_add(bytes.len())
}

fn authority_operation_approval_commitment(value: &AuthorityOperationApproval) -> Hash {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"AO5C");
    bytes.extend_from_slice(crate::RUNTIME_ABI_ID.as_bytes());
    encode_approval_body(&mut Encoder(&mut bytes), value);
    Hash::digest(b"vos/agent/authority-operation-approval/v5", &[&bytes])
}

impl CanonicalWire for AuthorityOperationApproval {
    const MAGIC: [u8; 4] = *b"AOP5";
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
        let principal = PrincipalId(decoder.fixed()?);
        let credential = CredentialId(decoder.fixed()?);
        let value = Self {
            operation_call,
            authorization_sequence,
            invocation,
            acknowledgement_invocation,
            authority,
            principal,
            credential,
            request_sequence: NonZeroU64::new(decoder.u64()?).ok_or(DecodeError::NonCanonical)?,
            intent: decode_intent(decoder)?,
            selector: crate::wire::decode_authority_selector(decoder)?,
            authentication: crate::wire::decode_authority_ingress_authentication(decoder)?,
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
        value if value == AuthorityOperationKind::RotatePrivateKeys as u8 => {
            Ok(AuthorityOperationKind::RotatePrivateKeys)
        }
        value if value == AuthorityOperationKind::SetPrivateResourcePolicy as u8 => {
            Ok(AuthorityOperationKind::SetPrivateResourcePolicy)
        }
        value if value == AuthorityOperationKind::PrivateActorLifecycle as u8 => {
            Ok(AuthorityOperationKind::PrivateActorLifecycle)
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
    encoder.fixed(value.reopened_runtime_state.as_bytes());
    encoder.fixed(value.stable_projection.as_bytes());
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
        reopened_runtime_state: Hash(decoder.fixed()?),
        stable_projection: Hash(decoder.fixed()?),
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
    bytes.extend_from_slice(b"PCAF2");
    bytes.extend_from_slice(crate::RUNTIME_ABI_ID.as_bytes());
    encode_private_control_application_fact(&mut Encoder(&mut bytes), value);
    Hash::digest(b"vos/agent/private-control-application-fact/v2", &[&bytes])
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
    bytes.extend_from_slice(b"PCAS2");
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
    const MAGIC: [u8; 4] = *b"PCA2";
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

fn encode_private_control_application_retirement_ack_unsigned(
    encoder: &mut Encoder<'_>,
    value: &PrivateControlApplicationRetirementAck,
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
    encoder.u64(value.resolved_at);
}

fn private_control_application_retirement_ack_signing_bytes(
    value: &PrivateControlApplicationRetirementAck,
) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"PARS");
    bytes.extend_from_slice(crate::RUNTIME_ABI_ID.as_bytes());
    encode_private_control_application_retirement_ack_unsigned(&mut Encoder(&mut bytes), value);
    bytes
}

fn private_control_application_retirement_ack_encoded_len(
    value: &PrivateControlApplicationRetirementAck,
) -> usize {
    let mut body = Vec::new();
    encode_private_control_application_retirement_ack_unsigned(&mut Encoder(&mut body), value);
    HEADER_BYTES
        .saturating_add(body.len())
        .saturating_add(crate::authority::AUTHORITY_SIGNATURE_BYTES)
}

impl CanonicalWire for PrivateControlApplicationRetirementAck {
    const MAGIC: [u8; 4] = *b"PAR1";
    const MAX_ENCODED_BYTES: usize = MAX_PRIVATE_CONTROL_APPLICATION_RETIREMENT_ACK_WIRE_BYTES;

    fn validate_wire(&self) -> bool {
        self.validate_shape().is_ok()
    }

    fn encode_body(&self, encoder: &mut Encoder<'_>) {
        encode_private_control_application_retirement_ack_unsigned(encoder, self);
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
            resolved_at: decoder.u64()?,
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

    impl PrivateRecoveryAuthorityProofVerifier for TestVerifier {
        fn verify_private_recovery_authority_proof(
            &self,
            public_key: &[u8; 32],
            message: &[u8],
            signature: &[u8; 64],
        ) -> bool {
            *signature == test_signature(public_key, message)
        }
    }

    struct TestRecoverySigner([u8; 32]);

    impl PrivateRecoveryAuthorityProofSigner for TestRecoverySigner {
        fn recovery_public_key(&self) -> [u8; 32] {
            self.0
        }

        fn sign_private_recovery_authority_proof(&self, message: &[u8]) -> [u8; 64] {
            test_signature(&self.0, message)
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

    fn caller_node_key() -> [u8; CREDENTIAL_PUBLIC_KEY_BYTES] {
        [0x24; CREDENTIAL_PUBLIC_KEY_BYTES]
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

    fn invocation_target(work: &InvocationWork) -> ManagedAgentTarget {
        ManagedAgentTarget {
            space: work.space,
            agent: work.agent,
            owner: caller_principal(),
            profile: AgentProfile::Shared,
            runtime_deployment: work.runtime_deployment,
            transition_producer: ProducerId([0x2a; 32]),
        }
    }

    fn private_target(
        runtime_deployment: DeploymentId,
        control: &PrivateControlRecord,
    ) -> ManagedAgentTarget {
        ManagedAgentTarget {
            space: control.space,
            agent: control.agent,
            owner: caller_principal(),
            profile: AgentProfile::Private,
            runtime_deployment,
            transition_producer: ProducerId([0x2b; 32]),
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
        let authentication = match authenticated_node {
            Some(node) => AuthorityIngressAuthentication::SshNodeAttestation {
                credential_public_key: key,
                node,
                request_binding: Hash([discriminator.wrapping_add(1); 32]),
                signature: [1; CREDENTIAL_SIGNATURE_BYTES],
            },
            None => AuthorityIngressAuthentication::ApiCredentialSignature {
                credential_public_key: key,
                signature: [1; CREDENTIAL_SIGNATURE_BYTES],
            },
        };
        let mut call = AuthorityOperationCall {
            invocation: InvocationId::ZERO,
            authority: authority_target(),
            principal: caller_principal(),
            credential: CredentialId::of_public_key(&key),
            request_sequence: NonZeroU64::new(u64::from(discriminator)).unwrap(),
            authentication,
            requested_valid_from: 10,
            requested_expires_at: 30,
            intent,
        };
        call.invocation = call.expected_invocation();
        let signer = if call.authenticated_node().is_some() {
            caller_node_key()
        } else {
            key
        };
        let signature = test_signature(&signer, &call.signing_bytes());
        match &mut call.authentication {
            AuthorityIngressAuthentication::ApiCredentialSignature {
                signature: value, ..
            }
            | AuthorityIngressAuthentication::SshNodeAttestation {
                signature: value, ..
            } => *value = signature,
        }
        call.validate_shape().unwrap();
        call
    }

    fn resign_operation_call(call: &mut AuthorityOperationCall, signer: &[u8; 32]) {
        let signature = test_signature(signer, &call.signing_bytes());
        match &mut call.authentication {
            AuthorityIngressAuthentication::ApiCredentialSignature {
                signature: value, ..
            }
            | AuthorityIngressAuthentication::SshNodeAttestation {
                signature: value, ..
            } => *value = signature,
        }
    }

    fn invoke_call() -> AuthorityOperationCall {
        let work = invocation_work();
        call_with_intent(
            AuthorityOperationIntent::invoke(invocation_target(&work), &work).unwrap(),
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
                transition_producer: ProducerId([0x5d; 32]),
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

    fn private_controls() -> Vec<PrivateControlRecord> {
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
        let rotate = PrivateControlRecord {
            space,
            agent,
            sequence: 3,
            previous: Some(revoke.commitment()),
            operation: PrivateControlOperation::RotateKeys {
                next_epoch: private_epoch(space, agent, &node, 4),
            },
            signer: PrivateControlSigner::Owner,
            signer_public_key: [0x79; 32],
            signature: [0x7a; PRIVATE_SIGNATURE_BYTES],
        };
        let resource = PrivateControlRecord {
            space,
            agent,
            sequence: 4,
            previous: Some(rotate.commitment()),
            operation: PrivateControlOperation::SetResourcePolicy {
                policy: BlobRef::of_bytes(b"private-resource-policy"),
            },
            signer: PrivateControlSigner::Owner,
            signer_public_key: [0x7b; 32],
            signature: [0x7c; PRIVATE_SIGNATURE_BYTES],
        };
        let lifecycle = PrivateControlRecord {
            space,
            agent,
            sequence: 5,
            previous: Some(resource.commitment()),
            operation: PrivateControlOperation::ActorLifecycle {
                actor: ActorId([0x7d; 32]),
                operation: PrivateActorLifecycleKind::Upgrade,
                request: Hash([0x7e; 32]),
            },
            signer: PrivateControlSigner::Owner,
            signer_public_key: [0x7f; 32],
            signature: [0x80; PRIVATE_SIGNATURE_BYTES],
        };
        assert!(invite.validate_shape());
        assert!(revoke.validate_shape());
        assert!(recover.validate_shape());
        assert!(rotate.validate_shape());
        assert!(resource.validate_shape());
        assert!(lifecycle.validate_shape());
        vec![invite, revoke, recover, rotate, resource, lifecycle]
    }

    fn private_intent(
        runtime: DeploymentId,
        control: &PrivateControlRecord,
    ) -> AuthorityOperationIntent {
        let managed = private_target(runtime, control);
        if matches!(control.operation, PrivateControlOperation::Recover { .. }) {
            let proof = PrivateRecoveryAuthorityProof::from_control(
                managed,
                control,
                None,
                &TestRecoverySigner(control.signer_public_key),
            )
            .unwrap();
            AuthorityOperationIntent::private_recovery_control(proof).unwrap()
        } else {
            AuthorityOperationIntent::private_control(managed, control).unwrap()
        }
    }

    fn private_call(control: &PrivateControlRecord, discriminator: u8) -> AuthorityOperationCall {
        call_with_intent(
            private_intent(DeploymentId([0x79; 32]), control),
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
                } => (
                    *control,
                    *control_sequence,
                    *control_previous,
                    *epoch,
                    *member_set,
                ),
                AuthorityOperationIntent::RecoverPrivateAgent { proof } => (
                    proof.control,
                    proof.control_sequence,
                    proof.control_previous,
                    proof.next_epoch,
                    proof.replacement_member_set,
                ),
                AuthorityOperationIntent::RotatePrivateKeys {
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
                AuthorityOperationIntent::SetPrivateResourcePolicy {
                    control,
                    control_sequence,
                    control_previous,
                    ..
                }
                | AuthorityOperationIntent::PrivateActorLifecycle {
                    control,
                    control_sequence,
                    control_previous,
                    ..
                } => (
                    *control,
                    *control_sequence,
                    *control_previous,
                    3,
                    Hash([0x90; 32]),
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
            reopened_runtime_state: Hash([0x7b; 32]),
            stable_projection: Hash([0x7c; 32]),
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

    fn private_application_retirement_ack(
        call: &AuthorityOperationCall,
        approved: &AuthorityOperationApproval,
        issuance: &AuthorityOperationIssuanceAck,
        resolved_at: u64,
    ) -> PrivateControlApplicationRetirementAck {
        let mut acknowledgement = PrivateControlApplicationRetirementAck {
            authorization_invocation: call.invocation,
            issuance_invocation: issuance.acknowledgement_invocation,
            application_invocation:
                PrivateControlApplicationRetirementAck::derive_application_invocation(issuance),
            authority: call.authority,
            operation_call: call.commitment(),
            approval: approved.commitment(),
            issuance_ack: issuance.commitment(),
            authorization_sequence: approved.authorization_sequence,
            receipt: issuance.receipt.clone(),
            issued_at: issuance.issued_at,
            resolved_at,
            signature: [0; AUTHORITY_SIGNATURE_BYTES],
        };
        resign_private_application_retirement_ack(&mut acknowledgement);
        acknowledgement.validate_shape().unwrap();
        acknowledgement
    }

    fn resign_private_application_retirement_ack(
        acknowledgement: &mut PrivateControlApplicationRetirementAck,
    ) {
        acknowledgement.signature = test_signature(
            &acknowledgement.authority.binding.public_key,
            &acknowledgement.signing_bytes(),
        );
    }

    #[test]
    fn aoc5_aop5_and_aoi1_are_distinct_bounded_canonical_golden_wires() {
        let call = invoke_call();
        let call_bytes = call.encode().unwrap();
        assert_eq!(call_bytes.get(..4), Some(b"AOC5".as_slice()));
        assert!(call_bytes.len() <= MAX_AUTHORITY_OPERATION_CALL_WIRE_BYTES);
        assert_eq!(
            AuthorityOperationCall::decode(&call_bytes),
            Ok(call.clone())
        );
        assert_eq!(
            Hash::digest(b"vos/test/aoc5-golden", &[&call_bytes]).0,
            [
                0x1e, 0x6c, 0x73, 0x7f, 0xc9, 0xb0, 0x19, 0xb6, 0xf3, 0x4e, 0xf8, 0x14, 0xb3, 0xd1,
                0xb2, 0x4a, 0x31, 0x1b, 0xee, 0xff, 0xa0, 0x18, 0x13, 0x69, 0x24, 0xf4, 0x06, 0x7a,
                0xbc, 0xab, 0x55, 0xee,
            ]
        );

        let approval = approval(&call);
        let approval_bytes = approval.encode().unwrap();
        assert_eq!(approval_bytes.get(..4), Some(b"AOP5".as_slice()));
        assert!(approval_bytes.len() <= MAX_AUTHORITY_OPERATION_APPROVAL_WIRE_BYTES);
        assert_eq!(
            AuthorityOperationApproval::decode(&approval_bytes),
            Ok(approval.clone())
        );
        let mut old_approval = approval_bytes.clone();
        old_approval[..4].copy_from_slice(b"AOP4");
        assert!(AuthorityOperationApproval::decode(&old_approval).is_err());
        assert_ne!(call.commitment(), approval.commitment());
        assert_eq!(
            Hash::digest(b"vos/test/aop5-golden", &[&approval_bytes]).0,
            [
                0x36, 0xfc, 0x09, 0xab, 0x5e, 0x1a, 0xed, 0xd8, 0xe9, 0x52, 0x47, 0xaa, 0x58, 0x5d,
                0xa4, 0x0b, 0x49, 0x59, 0x0d, 0x5a, 0x01, 0xf2, 0xca, 0x0b, 0x1f, 0xe0, 0xc1, 0x3e,
                0xbf, 0x3f, 0xd4, 0xc0,
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
                0x26, 0xc7, 0xa5, 0x2b, 0x1c, 0x4a, 0x30, 0x4b, 0x18, 0xe9, 0x87, 0x7e, 0x64, 0x3d,
                0x62, 0xc5, 0x54, 0x49, 0x3b, 0x7c, 0x78, 0x4f, 0x7f, 0x85, 0x2a, 0x3b, 0x0c, 0x0b,
                0x2f, 0x8c, 0x75, 0xf4,
            ]
        );
    }

    #[test]
    fn pca2_is_a_distinct_canonical_tombstone_checkable_application_proof() {
        let controls = private_controls();
        let call = private_call(&controls[0], 0x7c);
        let approved = approval_with_sequence(&call, 8);
        let issuance = issuance_ack(&call, &approved);
        let application = private_application_fact(&call);
        let acknowledgement = private_application_ack(&call, &approved, &issuance, application);

        let mut wrong_profile_application = application;
        wrong_profile_application.managed.profile = AgentProfile::Shared;
        assert_eq!(
            wrong_profile_application.validate_shape(),
            Err(AuthorityOperationProtocolError::InvalidApplication)
        );
        let mut wrong_profile_acknowledgement = acknowledgement.clone();
        wrong_profile_acknowledgement.application.managed.profile = AgentProfile::Shared;
        assert_eq!(
            wrong_profile_acknowledgement.validate_shape(),
            Err(AuthorityOperationProtocolError::InvalidApplication)
        );

        let encoded = acknowledgement.encode().unwrap();
        assert_eq!(encoded.get(..4), Some(b"PCA2".as_slice()));
        assert!(encoded.len() <= MAX_PRIVATE_CONTROL_APPLICATION_ACK_WIRE_BYTES);
        assert_eq!(
            PrivateControlApplicationAck::decode(&encoded),
            Ok(acknowledgement.clone())
        );
        assert_eq!(
            Hash::digest(b"vos/test/pca2-golden", &[&encoded]).0,
            [
                0x42, 0x18, 0xf5, 0x1b, 0x94, 0xfa, 0xcf, 0x05, 0x91, 0x22, 0x35, 0x98, 0xea, 0x90,
                0x76, 0x9e, 0x76, 0x7a, 0x90, 0x10, 0x38, 0x28, 0xd8, 0x8d, 0xff, 0x02, 0x23, 0x72,
                0x2b, 0x39, 0xbe, 0x64,
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
        relayed.origin.transport_node = call.authenticated_node();
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
    fn par1_is_a_distinct_canonical_tombstone_checkable_retirement_proof() {
        let control = &private_controls()[0];
        let call = private_call(control, 0x8a);
        let approved = approval_with_sequence(&call, 9);
        let issuance = issuance_ack(&call, &approved);
        let retirement = private_application_retirement_ack(&call, &approved, &issuance, 24);
        let application = private_application_fact(&call);
        let applied = private_application_ack(&call, &approved, &issuance, application);

        let encoded = retirement.encode().unwrap();
        assert_eq!(encoded.get(..4), Some(b"PAR1".as_slice()));
        assert!(encoded.len() <= MAX_PRIVATE_CONTROL_APPLICATION_RETIREMENT_ACK_WIRE_BYTES);
        assert_eq!(
            PrivateControlApplicationRetirementAck::decode(&encoded),
            Ok(retirement.clone())
        );
        assert_ne!(retirement.commitment(), issuance.commitment());
        assert_ne!(retirement.commitment(), applied.commitment());
        assert_ne!(retirement.signing_bytes(), applied.signing_bytes());
        assert_eq!(
            retirement.application_invocation,
            applied.application_invocation
        );
        assert!(retirement.matches_pending(&call, &approved, &issuance));
        assert_eq!(
            retirement.verify_pending_with(
                &call,
                &approved,
                &issuance,
                call.authority.binding,
                &TestVerifier,
            ),
            Ok(())
        );
        assert!(retirement.matches_issuance_tombstone(
            issuance.authority,
            issuance.authorization_invocation,
            issuance.acknowledgement_invocation,
            issuance.authorization_sequence,
            issuance.commitment(),
        ));
        assert_eq!(
            retirement.verify_issuance_tombstone_with(
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
            invocation: retirement.application_invocation,
            actor: retirement.authority.binding.issuer.actor,
            mode: MethodMode::Linear,
            origin: InvocationOrigin::anonymous(),
            roles: InvocationRoleClaims::none(),
            observed_slot: retirement.resolved_at,
        };
        assert!(retirement.matches_invocation_context(&context));
        let mut wrong = context;
        wrong.observed_slot += 1;
        assert!(!retirement.matches_invocation_context(&wrong));
    }

    #[test]
    fn par1_rejects_substitution_bad_ordering_and_unverified_signatures() {
        let control = &private_controls()[1];
        let call = private_call(control, 0x8b);
        let approved = approval(&call);
        let issuance = issuance_ack(&call, &approved);
        let retirement = private_application_retirement_ack(&call, &approved, &issuance, 24);

        let mut before_issuance = retirement.clone();
        before_issuance.resolved_at = issuance.issued_at - 1;
        resign_private_application_retirement_ack(&mut before_issuance);
        assert_eq!(
            before_issuance.validate_shape(),
            Err(AuthorityOperationProtocolError::InvalidApplication)
        );

        let mut after_expiry = retirement.clone();
        after_expiry.resolved_at = approved.selector.expires_at + 1;
        resign_private_application_retirement_ack(&mut after_expiry);
        assert_eq!(
            after_expiry.validate_shape(),
            Err(AuthorityOperationProtocolError::InvalidApplication)
        );

        let mut substituted = retirement.clone();
        substituted.operation_call = Hash([0x8c; 32]);
        resign_private_application_retirement_ack(&mut substituted);
        assert_eq!(
            substituted.verify_with(call.authority.binding, &TestVerifier),
            Ok(())
        );
        assert!(!substituted.matches_pending(&call, &approved, &issuance));

        let mut wrong_invocation = retirement.clone();
        wrong_invocation.application_invocation = InvocationId([0x8d; 32]);
        resign_private_application_retirement_ack(&mut wrong_invocation);
        assert_eq!(
            wrong_invocation.validate_shape(),
            Err(AuthorityOperationProtocolError::InvalidTarget)
        );

        let mut bad_signature = retirement;
        bad_signature.signature[0] ^= 1;
        assert_eq!(
            bad_signature.verify_with(call.authority.binding, &TestVerifier),
            Err(AuthorityOperationProtocolError::InvalidSignature)
        );
    }

    #[test]
    fn par1_old_truncated_trailing_and_oversize_wires_fail_closed() {
        let control = &private_controls()[2];
        let call = private_call(control, 0x8e);
        let approved = approval(&call);
        let issuance = issuance_ack(&call, &approved);
        let retirement = private_application_retirement_ack(&call, &approved, &issuance, 24);
        let encoded = retirement.encode().unwrap();

        let mut old = encoded.clone();
        old[..4].copy_from_slice(b"PCA2");
        assert!(PrivateControlApplicationRetirementAck::decode(&old).is_err());
        let mut old_abi = encoded.clone();
        old_abi[4] ^= 1;
        assert!(PrivateControlApplicationRetirementAck::decode(&old_abi).is_err());
        let mut truncated = encoded.clone();
        truncated.pop();
        assert!(PrivateControlApplicationRetirementAck::decode(&truncated).is_err());
        let mut trailing = encoded;
        trailing.push(0);
        assert!(PrivateControlApplicationRetirementAck::decode(&trailing).is_err());
        assert_eq!(
            PrivateControlApplicationRetirementAck::decode(&vec![
                0;
                MAX_PRIVATE_CONTROL_APPLICATION_RETIREMENT_ACK_WIRE_BYTES
                    + 1
            ]),
            Err(WireError::LimitExceeded)
        );

        let mut unsigned = retirement;
        unsigned.signature = [0; AUTHORITY_SIGNATURE_BYTES];
        assert_eq!(unsigned.encode(), Err(WireError::InvalidValue));
    }

    #[test]
    fn pca2_rejects_substitution_bad_ordering_and_unverified_signatures() {
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
        missing_state.application.reopened_runtime_state = Hash::ZERO;
        resign_private_application_ack(&mut missing_state);
        assert_eq!(
            missing_state.validate_shape(),
            Err(AuthorityOperationProtocolError::InvalidApplication)
        );
        let mut missing_projection = acknowledgement.clone();
        missing_projection.application.stable_projection = Hash::ZERO;
        resign_private_application_ack(&mut missing_projection);
        assert_eq!(
            missing_projection.validate_shape(),
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
        let mut substituted_runtime_state = acknowledgement.clone();
        substituted_runtime_state.application.reopened_runtime_state = Hash([0x87; 32]);
        assert_eq!(substituted_runtime_state.validate_shape(), Ok(()));
        assert_ne!(
            substituted_runtime_state.application.commitment(),
            application.commitment()
        );
        assert_eq!(
            substituted_runtime_state.verify_with(call.authority.binding, &TestVerifier),
            Err(AuthorityOperationProtocolError::InvalidSignature)
        );
        let mut substituted_stable_projection = acknowledgement.clone();
        substituted_stable_projection.application.stable_projection = Hash([0x88; 32]);
        assert_eq!(substituted_stable_projection.validate_shape(), Ok(()));
        assert_ne!(
            substituted_stable_projection.application.commitment(),
            application.commitment()
        );
        assert_eq!(
            substituted_stable_projection.verify_with(call.authority.binding, &TestVerifier),
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
    fn pca2_rejects_pca1_old_layout_truncated_trailing_and_oversize_wires() {
        let controls = private_controls();
        let call = private_call(&controls[2], 0x85);
        let approved = approval(&call);
        let issuance = issuance_ack(&call, &approved);
        let application = private_application_fact(&call);
        let acknowledgement = private_application_ack(&call, &approved, &issuance, application);
        let encoded = acknowledgement.encode().unwrap();

        let mut old_pca1 = encoded.clone();
        old_pca1[..4].copy_from_slice(b"PCA1");
        assert!(PrivateControlApplicationAck::decode(&old_pca1).is_err());
        let stable_projection = acknowledgement.application.stable_projection.0;
        let stable_offset = encoded
            .windows(stable_projection.len())
            .position(|window| window == stable_projection)
            .expect("fixture stable projection has one canonical preimage");
        let mut old_layout = encoded.clone();
        old_layout.drain(stable_offset..stable_offset + stable_projection.len());
        assert!(PrivateControlApplicationAck::decode(&old_layout).is_err());
        old_layout[..4].copy_from_slice(b"PCA1");
        assert!(PrivateControlApplicationAck::decode(&old_layout).is_err());
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
        assert_eq!(
            call.verify_ssh_node_attestation_with(&caller_node_key(), &TestVerifier),
            Ok(())
        );
        assert!(call.verify_api_with(&TestVerifier).is_err());
        let context = InvocationContext {
            invocation: call.invocation,
            actor: call.authority.binding.issuer.actor,
            mode: MethodMode::Linear,
            origin: InvocationOrigin {
                principal: Some(call.principal),
                transport_node: call.authenticated_node(),
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
            changed.verify_ssh_node_attestation_with(&caller_node_key(), &TestVerifier),
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
            changed_sequence.verify_ssh_node_attestation_with(&caller_node_key(), &TestVerifier),
            Err(AuthorityOperationProtocolError::InvalidSignature)
        );

        let mut changed = call.clone();
        let AuthorityIngressAuthentication::SshNodeAttestation { node, .. } =
            &mut changed.authentication
        else {
            unreachable!();
        };
        *node = NodeId([0x79; 32]);
        assert_ne!(changed.commitment(), original);
        assert!(!changed.matches_invocation_context(&context));

        let mut changed_context = context;
        changed_context.origin.capability = Some(CapabilityId([0x7a; 32]));
        assert!(!call.matches_invocation_context(&changed_context));
        changed_context = context;
        changed_context.roles.space = Some(RoleId([0x7b; 32]));
        assert!(!call.matches_invocation_context(&changed_context));

        let mut bad_key = call;
        let AuthorityIngressAuthentication::SshNodeAttestation {
            credential_public_key,
            ..
        } = &mut bad_key.authentication
        else {
            unreachable!();
        };
        credential_public_key[0] ^= 1;
        assert_eq!(bad_key.encode(), Err(WireError::InvalidValue));
    }

    #[test]
    fn credential_call_without_transport_node_is_canonical_and_exact() {
        let mut work = invocation_work();
        work.origin.transport_node = None;
        let call = call_with_authenticated_node(
            AuthorityOperationIntent::invoke(invocation_target(&work), &work).unwrap(),
            0x7c,
            None,
        );
        let bytes = call.encode().unwrap();
        assert_eq!(AuthorityOperationCall::decode(&bytes), Ok(call.clone()));
        assert_eq!(call.verify_api_with(&TestVerifier), Ok(()));
        assert!(
            call.verify_ssh_node_attestation_with(&caller_node_key(), &TestVerifier)
                .is_err()
        );
        let approved = approval(&call);
        assert_eq!(approved.authenticated_node(), None);
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
            transport_node: call.authenticated_node(),
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
        resign_operation_call(&mut different_call, &caller_node_key());
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
            let work = invocation_work();
            let call = call_with_intent(
                AuthorityOperationIntent::invoke(invocation_target(&work), &work).unwrap(),
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

        // AOP5 cannot reconstruct its retained AOC5 preimage. A substituted
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
            for substitute in [
                |managed: &mut ManagedAgentTarget| managed.owner = PrincipalId([0x81; 32]),
                |managed: &mut ManagedAgentTarget| managed.profile = AgentProfile::Private,
                |managed: &mut ManagedAgentTarget| {
                    managed.transition_producer = ProducerId([0x82; 32])
                },
            ] {
                let mut substituted = intent.clone();
                let AuthorityOperationIntent::Catalog { managed, .. } = &mut substituted else {
                    unreachable!();
                };
                substitute(managed);
                assert_eq!(
                    substituted.validate_shape(),
                    Err(AuthorityOperationProtocolError::InvalidIntent),
                );
            }
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
            AuthorityOperationKind::RotatePrivateKeys,
            AuthorityOperationKind::SetPrivateResourcePolicy,
            AuthorityOperationKind::PrivateActorLifecycle,
        ];
        for (index, (control, operation)) in controls.iter().zip(expected_operations).enumerate() {
            let intent = private_intent(runtime, control);
            assert_eq!(intent.operation(), operation);
            assert!(intent.matches_private_control(control));

            let mut wrong_profile = intent.clone();
            let managed = match &mut wrong_profile {
                AuthorityOperationIntent::InvitePrivateNode { managed, .. }
                | AuthorityOperationIntent::RevokePrivateNode { managed, .. }
                | AuthorityOperationIntent::RotatePrivateKeys { managed, .. }
                | AuthorityOperationIntent::SetPrivateResourcePolicy { managed, .. }
                | AuthorityOperationIntent::PrivateActorLifecycle { managed, .. } => managed,
                AuthorityOperationIntent::RecoverPrivateAgent { proof } => &mut proof.managed,
                AuthorityOperationIntent::InvokeActor { .. }
                | AuthorityOperationIntent::Catalog { .. } => unreachable!(),
            };
            managed.profile = AgentProfile::Shared;
            assert_eq!(
                wrong_profile.validate_shape(),
                Err(AuthorityOperationProtocolError::InvalidIntent)
            );

            let call = call_with_intent(intent, 0x83 + index as u8);
            let approval = approval(&call);
            assert!(approval.matches_private_control(control));
            let expected_request = match &call.intent {
                AuthorityOperationIntent::RecoverPrivateAgent { proof } => proof.commitment(),
                _ => control.commitment(),
            };
            assert_eq!(approval.selector.request, expected_request);
            assert_eq!(approval.selector.decision_sequence, 0);
            assert_eq!(approval.selector.acknowledged_through, 0);
            if operation == AuthorityOperationKind::PrivateActorLifecycle {
                let PrivateControlOperation::ActorLifecycle { actor, .. } = &control.operation
                else {
                    unreachable!()
                };
                assert_eq!(approval.selector.actor, Some(*actor));
                assert_eq!(approval.selector.actor_deployment, None);
            } else {
                assert_eq!(approval.selector.actor, None);
                assert_eq!(approval.selector.actor_deployment, None);
            }
        }

        let invite_intent = AuthorityOperationIntent::private_control(
            private_target(runtime, &controls[0]),
            &controls[0],
        )
        .unwrap();
        let mut changed_invite = controls[0].clone();
        let PrivateControlOperation::Invite { node, .. } = &mut changed_invite.operation else {
            unreachable!()
        };
        node.transport_signature[0] ^= 1;
        assert!(!invite_intent.matches_private_control(&changed_invite));

        let revoke_intent = AuthorityOperationIntent::private_control(
            private_target(runtime, &controls[1]),
            &controls[1],
        )
        .unwrap();
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

        assert_eq!(
            AuthorityOperationIntent::private_control(
                private_target(runtime, &controls[2]),
                &controls[2],
            ),
            Err(AuthorityOperationProtocolError::InvalidIntent)
        );
        let recovery_intent = private_intent(runtime, &controls[2]);
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

        let rotate_intent = AuthorityOperationIntent::private_control(
            private_target(runtime, &controls[3]),
            &controls[3],
        )
        .unwrap();
        let mut changed_rotate = controls[3].clone();
        let PrivateControlOperation::RotateKeys { next_epoch } = &mut changed_rotate.operation
        else {
            unreachable!()
        };
        next_epoch.sealed_owner_keys[0].sealed[0] ^= 1;
        assert!(!rotate_intent.matches_private_control(&changed_rotate));

        let resource_intent = AuthorityOperationIntent::private_control(
            private_target(runtime, &controls[4]),
            &controls[4],
        )
        .unwrap();
        let mut changed_resource = controls[4].clone();
        let PrivateControlOperation::SetResourcePolicy { policy } = &mut changed_resource.operation
        else {
            unreachable!()
        };
        policy.hash.0[0] ^= 1;
        assert!(!resource_intent.matches_private_control(&changed_resource));

        let lifecycle_intent = AuthorityOperationIntent::private_control(
            private_target(runtime, &controls[5]),
            &controls[5],
        )
        .unwrap();
        let mut changed_lifecycle = controls[5].clone();
        let PrivateControlOperation::ActorLifecycle { request, .. } =
            &mut changed_lifecycle.operation
        else {
            unreachable!()
        };
        request.0[0] ^= 1;
        assert!(!lifecycle_intent.matches_private_control(&changed_lifecycle));
    }

    #[test]
    fn recover_receipt_selector_binds_the_exact_pra1_not_only_its_pctl() {
        let runtime = DeploymentId([0x90; 32]);
        let mut control = private_controls()[2].clone();
        let first_head = Hash([0x91; 32]);
        let second_head = Hash([0x92; 32]);
        let PrivateControlOperation::Recover {
            superseded_heads, ..
        } = &mut control.operation
        else {
            unreachable!()
        };
        *superseded_heads = vec![first_head, second_head];
        control.previous = Some(first_head);
        let signer = TestRecoverySigner(control.signer_public_key);
        let managed = private_target(runtime, &control);
        let first = PrivateRecoveryAuthorityProof::from_control(
            managed,
            &control,
            Some(first_head),
            &signer,
        )
        .unwrap();
        let second = PrivateRecoveryAuthorityProof::from_control(
            managed,
            &control,
            Some(second_head),
            &signer,
        )
        .unwrap();
        assert!(first.matches_control(&control));
        assert!(second.matches_control(&control));
        assert_ne!(first.commitment(), second.commitment());

        let first_call = call_with_intent(
            AuthorityOperationIntent::RecoverPrivateAgent {
                proof: first.clone(),
            },
            0x93,
        );
        let second_call = call_with_intent(
            AuthorityOperationIntent::RecoverPrivateAgent {
                proof: second.clone(),
            },
            0x94,
        );
        let first_approval = approval(&first_call);
        let second_approval = approval(&second_call);
        assert_eq!(first_approval.selector.request, first.commitment());
        assert_eq!(second_approval.selector.request, second.commitment());
        assert_ne!(
            first_approval.selector.request,
            second_approval.selector.request
        );
        assert!(!first_approval.matches_call(&second_call));
        assert!(!second_approval.matches_call(&first_call));
    }

    #[test]
    fn pra1_binds_every_recovery_field_and_supports_the_full_private_node_limit() {
        let runtime = DeploymentId([0x93; 32]);
        let mut control = private_controls()[2].clone();
        let authority_head = Hash([0x94; 32]);
        let PrivateControlOperation::Recover {
            superseded_heads, ..
        } = &mut control.operation
        else {
            unreachable!()
        };
        superseded_heads.push(authority_head);
        control.previous = Some(authority_head);
        let signer = TestRecoverySigner(control.signer_public_key);
        let managed = private_target(runtime, &control);
        let proof = PrivateRecoveryAuthorityProof::from_control(
            managed,
            &control,
            Some(authority_head),
            &signer,
        )
        .unwrap();
        assert_eq!(proof.verify_with(&TestVerifier), Ok(()));
        assert!(proof.matches_control(&control));
        let encoded = proof.encode().unwrap();
        assert_eq!(encoded.get(..4), Some(b"PRA1".as_slice()));
        assert_eq!(
            PrivateRecoveryAuthorityProof::decode(&encoded),
            Ok(proof.clone())
        );
        let mut old = encoded;
        old[..4].copy_from_slice(b"PRA0");
        assert!(PrivateRecoveryAuthorityProof::decode(&old).is_err());

        let mut substitutions = Vec::new();
        let mut changed = proof.clone();
        changed.managed.profile = AgentProfile::Shared;
        assert_eq!(
            changed.validate_shape(),
            Err(AuthorityOperationProtocolError::InvalidIntent)
        );
        substitutions.push(changed);
        let mut changed = proof.clone();
        changed.managed.runtime_deployment = DeploymentId([0x95; 32]);
        substitutions.push(changed);
        let mut changed = proof.clone();
        changed.control = Hash([0x96; 32]);
        substitutions.push(changed);
        let mut changed = proof.clone();
        changed.control_sequence += 1;
        substitutions.push(changed);
        let mut changed = proof.clone();
        changed.control_previous = Some(Hash([0x97; 32]));
        substitutions.push(changed);
        let mut changed = proof.clone();
        changed.next_epoch += 1;
        substitutions.push(changed);
        let mut changed = proof.clone();
        changed.superseded_authority_head = Some(Hash([0x98; 32]));
        substitutions.push(changed);
        let mut changed = proof.clone();
        changed.replacement_nodes[0] = NodeId([0x99; 32]);
        changed.replacement_member_set =
            private_member_set_commitment(changed.replacement_nodes.iter().copied()).unwrap();
        substitutions.push(changed);
        let mut changed = proof.clone();
        changed.replacement_member_set = Hash([0x9a; 32]);
        substitutions.push(changed);
        let mut changed = proof.clone();
        changed.replacement_identity_set = Hash([0x9b; 32]);
        substitutions.push(changed);
        let mut changed = proof.clone();
        changed.recovery_evidence = Hash([0x9c; 32]);
        substitutions.push(changed);
        let mut changed = proof.clone();
        changed.recovery_public_key = [0x9d; 32];
        substitutions.push(changed);
        let mut changed = proof.clone();
        changed.signature[0] ^= 1;
        substitutions.push(changed);
        for changed in substitutions {
            assert_ne!(changed.verify_with(&TestVerifier), Ok(()));
        }

        let mut relabeled_pctl_signature = proof.clone();
        relabeled_pctl_signature.signature = control.signature;
        assert_eq!(
            relabeled_pctl_signature.verify_with(&TestVerifier),
            Err(AuthorityOperationProtocolError::InvalidSignature)
        );

        let replacement_nodes: Vec<NodeId> = (1..=MAX_PRIVATE_NODES)
            .map(|index| {
                let mut bytes = [0; 32];
                bytes[30..].copy_from_slice(&(index as u16).to_be_bytes());
                NodeId(bytes)
            })
            .collect();
        let mut maximum = PrivateRecoveryAuthorityProof {
            managed: proof.managed,
            control: Hash([0xa0; 32]),
            control_sequence: 4_096,
            control_previous: Some(Hash([0xa1; 32])),
            next_epoch: 4_097,
            superseded_authority_head: Some(Hash([0xa2; 32])),
            replacement_member_set: private_member_set_commitment(
                replacement_nodes.iter().copied(),
            )
            .unwrap(),
            replacement_nodes,
            replacement_identity_set: Hash([0xa3; 32]),
            recovery_evidence: Hash([0xa4; 32]),
            recovery_public_key: signer.recovery_public_key(),
            signature: [0; 64],
        };
        maximum.signature = signer.sign_private_recovery_authority_proof(&maximum.signing_bytes());
        assert_eq!(maximum.verify_with(&TestVerifier), Ok(()));
        let maximum_proof_wire = maximum.encode().unwrap();
        assert!(maximum_proof_wire.len() <= MAX_PRIVATE_RECOVERY_AUTHORITY_PROOF_WIRE_BYTES);
        let maximum_call = call_with_intent(
            AuthorityOperationIntent::private_recovery_control(maximum).unwrap(),
            0xa5,
        );
        let maximum_call_wire = maximum_call.encode().unwrap();
        let maximum_approval_wire = approval(&maximum_call).encode().unwrap();
        assert_eq!(maximum_proof_wire.len(), 8_699);
        assert_eq!(maximum_call_wire.len(), 9_309);
        assert_eq!(maximum_approval_wire.len(), 9_870);
        assert!(maximum_call_wire.len() <= MAX_AUTHORITY_OPERATION_CALL_WIRE_BYTES);
        assert!(maximum_approval_wire.len() <= MAX_AUTHORITY_OPERATION_APPROVAL_WIRE_BYTES);
    }

    #[test]
    fn every_intent_roundtrips_but_old_unknown_trailing_and_oversize_wires_fail_closed() {
        let runtime = DeploymentId([0x84; 32]);
        let controls = private_controls();
        let work = invocation_work();
        let intents = vec![
            AuthorityOperationIntent::invoke(invocation_target(&work), &work).unwrap(),
            catalog_intent(CatalogMutationKind::Publish),
            catalog_intent(CatalogMutationKind::Withdraw),
            private_intent(runtime, &controls[0]),
            private_intent(runtime, &controls[1]),
            private_intent(runtime, &controls[2]),
            private_intent(runtime, &controls[3]),
            private_intent(runtime, &controls[4]),
            private_intent(runtime, &controls[5]),
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
        old[..4].copy_from_slice(b"AOC4");
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
        old[..4].copy_from_slice(b"AOP4");
        assert!(AuthorityOperationApproval::decode(&old).is_err());
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
