//! Clean, portable policy actor for standard Agent management.
//!
//! The actor accepts canonical `ACC3` management calls, canonical `AOC5`
//! general-operation calls, and self-authenticating `AAD4` identity-admin calls
//! delivered with an exact clean `AIC1` invocation context. It performs policy,
//! credential, and Admin-accessibility checks inside the guest and retains exact
//! results for replay. Agent and actor lifecycle approvals remain pending until
//! separately signed exact durable-application acknowledgements are observed;
//! general-operation approvals remain exact-retryable until a signed `AOI1`
//! issuance acknowledgement advances their contiguous retirement floor. A
//! distinct signed `PCA2` acknowledgement is required before Private control
//! state or membership becomes policy-visible. A mutually exclusive signed
//! `PAR1` acknowledgement retires an unapplied Private capability without
//! making a guest denial or synthetic control transition policy-visible.

#![cfg_attr(target_arch = "riscv64", no_std)]

mod genesis_publication;
mod node_storage;
use genesis_publication::GenesisPublicationRecord;

use core::cmp::{max, min};
use core::num::NonZeroU64;

use ed25519_dalek::{Signature, VerifyingKey};
use vos::agent_sdk::authority::{
    AgentAuthorityBinding, AuthorityActorProjection, AuthorityActorProjectionPage,
    AuthorityActorRoleGrant, AuthorityActorTarget, AuthorityAdminCall, AuthorityAdminOperation,
    AuthorityAdminResult, AuthorityAgentProjection, AuthorityAgentProjectionPage,
    AuthorityAgentReplicaProjectionPage, AuthorityBuiltinRole, AuthorityCapabilityGrant,
    AuthorityCredentialCall, AuthorityCredentialEnrollment, AuthorityCredentialKind,
    AuthorityCredentialProjection, AuthorityCredentialStatus, AuthorityCredentialVerifier,
    AuthorityEvidence, AuthorityIngressAuthentication, AuthorityInventoryCursor,
    AuthorityInventoryEntry, AuthorityInventoryPosition, AuthorityInventoryProjectionPage,
    AuthorityIssuer, AuthorityLaneRoots, AuthorityOperationKind, AuthorityProjectionHead,
    AuthorityProjectionQuery, AuthorityProjectionSelector, AuthorityVerifier,
    CompactAgentDescriptor, CompactInstallActor, CompactReplicaSlot,
    MAX_AUTHORITY_PRINCIPAL_GRANTS, ManagedAgentTarget, ManagementApplicationAck,
    ManagementApproval, ManagementAuthorizationPlan,
};
use vos::agent_sdk::authority_operation::{
    AuthorityOperationApproval, AuthorityOperationCall, AuthorityOperationIntent,
    AuthorityOperationIssuanceAck, MAX_PRIVATE_RECOVERY_AUTHORITY_PROOF_WIRE_BYTES,
    PrivateControlApplicationAck, PrivateControlApplicationFact,
    PrivateControlApplicationRetirementAck, PrivateRecoveryAuthorityProof,
    PrivateRecoveryAuthorityProofVerifier, private_member_set_commitment,
    private_node_identity_set_commitment,
};
use vos::agent_sdk::contract::{
    ActorAbiRange, RuntimeMigrationPolicy, RuntimePackageContract, RuntimeResourceLimits,
};
use vos::agent_sdk::private::{
    ED25519_TRANSPORT_PEER_ID_BYTES, MAX_PRIVATE_NODES, NodeEncryptionEnrollment,
    NodeEncryptionEnrollmentVerifier, PRIVATE_SIGNATURE_BYTES, PrivateNodeIdentity,
    recovery_signing_public_key_commitment, valid_x25519_public_key,
};
use vos::agent_sdk::wire::CanonicalWire as _;
use vos::agent_sdk::{
    ActorId, AgentId, AgentIdentity, AgentProfile, AgentReplica, CapabilityId, CredentialId,
    DeploymentId, Hash, InvocationContext, InvocationId, MAX_AGENT_REPLICAS,
    MAX_INVOCATION_MESSAGE_BYTES, MAX_INVOCATION_REPLY_BYTES, MAX_RUNTIME_STATE_BYTES,
    ManagementReply, PrincipalId, PrivateRecoveryBinding, ProducerId, ProgramId, RUNTIME_ABI_ID,
    ReplicaRole, RoleId, RuntimeCapabilities, RuntimeRequirements, SpaceId,
    replica_roster_commitment, replica_set_generation,
};
use vos::prelude::*;

#[cfg(test)]
use vos::agent_sdk::ManagementRequest;

/// Fixed installation-data wire for [`SystemAuthorityConfiguration`].
pub const SYSTEM_AUTHORITY_CONFIGURATION_MAGIC: [u8; 4] = *b"SAC5";

/// The root admission consumes exactly one Create decision and one authority
/// actor Install decision before this portable issuer can run.
pub const ROOT_BOOTSTRAP_AUTHORIZATION_HIGH_WATER: u64 = 2;

/// Maximum durable rows in each caller table.
pub const MAX_AUTHORITY_CREDENTIALS: usize = 64;
/// One bootstrap Node plus a full old and disjoint replacement membership.
/// Historical recovery members stay enrolled so every retained PRA1 remains
/// independently verifiable; 513 rows are therefore the minimum cap which
/// permits replacement of every Node in a maximum-size Private Agent.
pub const MAX_AUTHORITY_NODES: usize = 2 * MAX_PRIVATE_NODES + 1;
pub const MAX_AUTHORITY_PRINCIPALS: usize = 64;
/// Aggregate durable AMP2 authorization grants. A stricter per-Principal SDK
/// bound guarantees that one credential projection always fits one reply.
pub const MAX_AUTHORITY_AUTHORIZATION_GRANTS: usize =
    MAX_AUTHORITY_PRINCIPALS * MAX_AUTHORITY_PRINCIPAL_GRANTS;
/// Maximum Agents for which this actor retains lifecycle policy state.
pub const MAX_MANAGED_AGENTS: usize = 256;
/// Actor-directory rows retained across all managed Agents. One Agent may use
/// the complete standard-runtime actor ceiling; the authority's aggregate
/// state-image limit is the intentionally stricter multi-Agent bound.
pub const MAX_MANAGED_ACTORS: usize = vos::agent_sdk::STANDARD_MAX_ACTORS as usize;
/// Removed installation identities remain consumed and cannot be reused. This
/// is the maximum number of two-hash tombstone payloads that could fit in an
/// otherwise empty canonical actor state; aggregate state sizing is stricter.
pub const MAX_RETIRED_ACTOR_INSTALLATIONS: usize =
    MAX_RUNTIME_STATE_BYTES / (2 * core::mem::size_of::<[u8; 32]>());
/// Exact pending approvals are deliberately bounded by the credential table:
/// each credential may have at most one application-bearing request in flight.
/// Completed results compact to one exact latest acknowledgement per credential.
pub const MAX_EXACT_RETRY_RECORDS: usize = 128;
/// One Private Agent may consume the runtime's complete bounded resolution
/// ceiling. Compact rows preserve exact PCA2/PAR1 retry and invocation
/// collision identity after a later control supersedes the current projection.
pub const MAX_PRIVATE_APPLICATION_RECORDS: usize = 4_096;
/// Recovery applications retain one complete canonical PRA1 for exact replay.
/// The lower independent cap keeps that variable state below 768 KiB; the
/// exact serialized-state ceiling remains authoritative for all row metadata.
pub const MAX_PRIVATE_RECOVERY_APPLICATION_RECORDS: usize = 64;
/// Worst-case canonical ACC3/AOC5/AAD4 calls plus MAP2/AOP5/AAR4 results and
/// MAA2/AOI1 acknowledgements retained by the bounded exact-retry tables. This
/// leaves over one MiB of the standard state ceiling for row metadata and
/// actor framing.
pub const MAX_RETAINED_EXACT_WIRE_BYTES: usize = MAX_AUTHORITY_CREDENTIALS
    * (MAX_INVOCATION_MESSAGE_BYTES + MAX_INVOCATION_REPLY_BYTES + MAX_INVOCATION_MESSAGE_BYTES);
/// Policy will never authorize farther than this many logical slots after the
/// slot at which unseen work was accepted.
pub const MAX_APPROVAL_VALIDITY_SLOTS: u64 = 4_096;

const CONFIG_FIXED_FIELDS: usize = 21;
const CONFIG_U64_FIELDS: usize = 3;
const CONFIG_ENCODED_BYTES: usize = SYSTEM_AUTHORITY_CONFIGURATION_MAGIC.len()
    + 32
    + CONFIG_FIXED_FIELDS * 32
    + CONFIG_U64_FIELDS * 8
    + 1
    + ED25519_TRANSPORT_PEER_ID_BYTES
    + PRIVATE_SIGNATURE_BYTES;
const EVIDENCE_DOMAIN: &[u8] = b"vos/system-authority/policy-evidence/v1";
const OPERATION_EVIDENCE_DOMAIN: &[u8] = b"vos/system-authority/operation-evidence/v1";
const STATE_INTEGRITY_DOMAIN: &[u8] = b"vos/system-authority/state-integrity/v17";

const _: () = assert!(MAX_RETAINED_EXACT_WIRE_BYTES < MAX_RUNTIME_STATE_BYTES);

#[derive(
    vos::rkyv::Archive,
    vos::rkyv::Serialize,
    vos::rkyv::Deserialize,
    Clone,
    Copy,
    Debug,
    Default,
    PartialEq,
    Eq,
)]
#[rkyv(crate = vos::rkyv)]
pub struct AuthorityIssuerState {
    pub principal: [u8; 32],
    pub actor: [u8; 32],
    pub deployment: [u8; 32],
    pub program: [u8; 32],
    pub producer: [u8; 32],
}

impl AuthorityIssuerState {
    fn sdk(self) -> AuthorityIssuer {
        AuthorityIssuer {
            principal: PrincipalId(self.principal),
            actor: ActorId(self.actor),
            deployment: DeploymentId(self.deployment),
            program: ProgramId(self.program),
            producer: ProducerId(self.producer),
        }
    }
}

#[derive(
    vos::rkyv::Archive,
    vos::rkyv::Serialize,
    vos::rkyv::Deserialize,
    Clone,
    Copy,
    Debug,
    Default,
    PartialEq,
    Eq,
)]
#[rkyv(crate = vos::rkyv)]
pub struct AuthorityBindingState {
    pub policy: [u8; 32],
    pub issuer: AuthorityIssuerState,
    pub public_key: [u8; 32],
    pub initial_epoch: u64,
}

impl AuthorityBindingState {
    fn sdk(self) -> AgentAuthorityBinding {
        AgentAuthorityBinding {
            policy: Hash(self.policy),
            issuer: self.issuer.sdk(),
            public_key: self.public_key,
            initial_epoch: self.initial_epoch,
        }
    }
}

/// Immutable installation configuration. The first caller is deliberately an
/// Admin: no ambient host identity is consulted during bootstrap.
#[derive(
    vos::rkyv::Archive,
    vos::rkyv::Serialize,
    vos::rkyv::Deserialize,
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
)]
#[rkyv(crate = vos::rkyv)]
pub struct SystemAuthorityConfiguration {
    pub space: [u8; 32],
    pub system_agent: [u8; 32],
    pub system_runtime_deployment: [u8; 32],
    pub system_runtime_program: [u8; 32],
    pub system_runtime_producer: [u8; 32],
    /// Stable online transition-proof signer identity for the system Agent.
    pub system_transition_producer: [u8; 32],
    /// Exact bundled standard-runtime package admitted for the system Agent.
    pub system_runtime_package: AuthorityBlobRow,
    pub binding: AuthorityBindingState,
    /// Exact durable issuer sequence already consumed by root admission.
    pub bootstrap_authorization_high_water: u64,
    pub bootstrap_system_agent_creation_nonce: [u8; 32],
    pub bootstrap_principal: [u8; 32],
    /// Principal authenticated by the bootstrap replica's transport key.
    /// This is distinct from the founding owner/Admin principal above.
    pub bootstrap_replica_principal: [u8; 32],
    pub bootstrap_credential_public_key: [u8; 32],
    /// Canonical [`vos::agent_sdk::authority::AuthorityCredentialKind`] tag.
    pub bootstrap_credential_kind: u8,
    pub bootstrap_node: [u8; 32],
    pub bootstrap_node_transport_public_key: [u8; 32],
    pub bootstrap_node_transport_peer_id: [u8; ED25519_TRANSPORT_PEER_ID_BYTES],
    pub bootstrap_node_encryption_public_key: [u8; 32],
    pub bootstrap_node_transport_signature: [u8; PRIVATE_SIGNATURE_BYTES],
}

impl Default for SystemAuthorityConfiguration {
    fn default() -> Self {
        Self {
            space: [0; 32],
            system_agent: [0; 32],
            system_runtime_deployment: [0; 32],
            system_runtime_program: [0; 32],
            system_runtime_producer: [0; 32],
            system_transition_producer: [0; 32],
            system_runtime_package: AuthorityBlobRow {
                hash: [0; 32],
                len: 0,
            },
            binding: AuthorityBindingState::default(),
            bootstrap_authorization_high_water: 0,
            bootstrap_system_agent_creation_nonce: [0; 32],
            bootstrap_principal: [0; 32],
            bootstrap_replica_principal: [0; 32],
            bootstrap_credential_public_key: [0; 32],
            bootstrap_credential_kind: 0,
            bootstrap_node: [0; 32],
            bootstrap_node_transport_public_key: [0; 32],
            bootstrap_node_transport_peer_id: [0; ED25519_TRANSPORT_PEER_ID_BYTES],
            bootstrap_node_encryption_public_key: [0; 32],
            bootstrap_node_transport_signature: [0; PRIVATE_SIGNATURE_BYTES],
        }
    }
}

impl SystemAuthorityConfiguration {
    fn bootstrap_node_enrollment(self) -> NodeEncryptionEnrollment {
        NodeEncryptionEnrollment {
            space: SpaceId(self.space),
            principal: PrincipalId(self.bootstrap_principal),
            node: vos::agent_sdk::NodeId(self.bootstrap_node),
            transport_public_key: self.bootstrap_node_transport_public_key,
            transport_peer_id: self.bootstrap_node_transport_peer_id,
            encryption_public_key: self.bootstrap_node_encryption_public_key,
            transport_signature: self.bootstrap_node_transport_signature,
        }
    }

    pub fn is_valid(self) -> bool {
        self.space != [0; 32]
            && self.system_agent != [0; 32]
            && self.system_runtime_deployment != [0; 32]
            && self.system_runtime_program != [0; 32]
            && self.system_runtime_producer != [0; 32]
            && self.system_transition_producer != [0; 32]
            && self.system_transition_producer != self.system_runtime_producer
            && authority_blob_is_valid(&self.system_runtime_package, false)
            && self.bootstrap_authorization_high_water == ROOT_BOOTSTRAP_AUTHORIZATION_HIGH_WATER
            && self.bootstrap_system_agent_creation_nonce != [0; 32]
            && self.bootstrap_principal != [0; 32]
            && self.bootstrap_replica_principal != [0; 32]
            && AgentId::derive(
                SpaceId(self.space),
                PrincipalId(self.bootstrap_principal),
                &self.bootstrap_system_agent_creation_nonce,
            )
            .0 == self.system_agent
            && PrincipalId::of_public_key(&self.bootstrap_node_transport_public_key).0
                == self.bootstrap_replica_principal
            && canonical_credential_public_key(&self.bootstrap_credential_public_key)
            && CredentialId::of_public_key(&self.bootstrap_credential_public_key)
                != CredentialId::ZERO
            && matches!(self.bootstrap_credential_kind, 0 | 1)
            && self
                .bootstrap_node_enrollment()
                .verify_with(&Ed25519CredentialVerifier)
            && self.binding.sdk().is_valid()
    }

    /// One exact clean-generation installation-data representation.
    pub fn encode(self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(CONFIG_ENCODED_BYTES);
        bytes.extend_from_slice(&SYSTEM_AUTHORITY_CONFIGURATION_MAGIC);
        bytes.extend_from_slice(RUNTIME_ABI_ID.as_bytes());
        bytes.extend_from_slice(&self.space);
        bytes.extend_from_slice(&self.system_agent);
        bytes.extend_from_slice(&self.system_runtime_deployment);
        bytes.extend_from_slice(&self.system_runtime_program);
        bytes.extend_from_slice(&self.system_runtime_producer);
        bytes.extend_from_slice(&self.system_transition_producer);
        bytes.extend_from_slice(&self.system_runtime_package.hash);
        bytes.extend_from_slice(&self.system_runtime_package.len.to_le_bytes());
        bytes.extend_from_slice(&self.binding.policy);
        bytes.extend_from_slice(&self.binding.issuer.principal);
        bytes.extend_from_slice(&self.binding.issuer.actor);
        bytes.extend_from_slice(&self.binding.issuer.deployment);
        bytes.extend_from_slice(&self.binding.issuer.program);
        bytes.extend_from_slice(&self.binding.issuer.producer);
        bytes.extend_from_slice(&self.binding.public_key);
        bytes.extend_from_slice(&self.binding.initial_epoch.to_le_bytes());
        bytes.extend_from_slice(&self.bootstrap_authorization_high_water.to_le_bytes());
        bytes.extend_from_slice(&self.bootstrap_system_agent_creation_nonce);
        bytes.extend_from_slice(&self.bootstrap_principal);
        bytes.extend_from_slice(&self.bootstrap_replica_principal);
        bytes.extend_from_slice(&self.bootstrap_credential_public_key);
        bytes.push(self.bootstrap_credential_kind);
        bytes.extend_from_slice(&self.bootstrap_node);
        bytes.extend_from_slice(&self.bootstrap_node_transport_public_key);
        bytes.extend_from_slice(&self.bootstrap_node_transport_peer_id);
        bytes.extend_from_slice(&self.bootstrap_node_encryption_public_key);
        bytes.extend_from_slice(&self.bootstrap_node_transport_signature);
        bytes
    }

    /// Decode SAC5 exactly. Prior clean generations, truncation, and trailing
    /// data are all rejected; there is no legacy constructor fallback.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != CONFIG_ENCODED_BYTES
            || bytes.get(..4) != Some(SYSTEM_AUTHORITY_CONFIGURATION_MAGIC.as_slice())
            || bytes.get(4..36) != Some(RUNTIME_ABI_ID.as_bytes().as_slice())
        {
            return None;
        }
        let mut cursor = 36;
        let space = take_fixed(bytes, &mut cursor)?;
        let system_agent = take_fixed(bytes, &mut cursor)?;
        let system_runtime_deployment = take_fixed(bytes, &mut cursor)?;
        let system_runtime_program = take_fixed(bytes, &mut cursor)?;
        let system_runtime_producer = take_fixed(bytes, &mut cursor)?;
        let system_transition_producer = take_fixed(bytes, &mut cursor)?;
        let system_runtime_package = AuthorityBlobRow {
            hash: take_fixed(bytes, &mut cursor)?,
            len: u64::from_le_bytes(bytes.get(cursor..cursor + 8)?.try_into().ok()?),
        };
        cursor += 8;
        let policy = take_fixed(bytes, &mut cursor)?;
        let issuer = AuthorityIssuerState {
            principal: take_fixed(bytes, &mut cursor)?,
            actor: take_fixed(bytes, &mut cursor)?,
            deployment: take_fixed(bytes, &mut cursor)?,
            program: take_fixed(bytes, &mut cursor)?,
            producer: take_fixed(bytes, &mut cursor)?,
        };
        let public_key = take_fixed(bytes, &mut cursor)?;
        let initial_epoch = u64::from_le_bytes(bytes.get(cursor..cursor + 8)?.try_into().ok()?);
        cursor += 8;
        let bootstrap_authorization_high_water =
            u64::from_le_bytes(bytes.get(cursor..cursor + 8)?.try_into().ok()?);
        cursor += 8;
        let bootstrap_system_agent_creation_nonce = take_fixed(bytes, &mut cursor)?;
        let bootstrap_principal = take_fixed(bytes, &mut cursor)?;
        let bootstrap_replica_principal = take_fixed(bytes, &mut cursor)?;
        let bootstrap_credential_public_key = take_fixed(bytes, &mut cursor)?;
        let bootstrap_credential_kind = *bytes.get(cursor)?;
        cursor += 1;
        let bootstrap_node = take_fixed(bytes, &mut cursor)?;
        let bootstrap_node_transport_public_key = take_fixed(bytes, &mut cursor)?;
        let bootstrap_node_transport_peer_id = take_array(bytes, &mut cursor)?;
        let bootstrap_node_encryption_public_key = take_fixed(bytes, &mut cursor)?;
        let bootstrap_node_transport_signature = take_array(bytes, &mut cursor)?;
        if cursor != bytes.len() {
            return None;
        }
        let value = Self {
            space,
            system_agent,
            system_runtime_deployment,
            system_runtime_program,
            system_runtime_producer,
            system_transition_producer,
            system_runtime_package,
            binding: AuthorityBindingState {
                policy,
                issuer,
                public_key,
                initial_epoch,
            },
            bootstrap_authorization_high_water,
            bootstrap_system_agent_creation_nonce,
            bootstrap_principal,
            bootstrap_replica_principal,
            bootstrap_credential_public_key,
            bootstrap_credential_kind,
            bootstrap_node,
            bootstrap_node_transport_public_key,
            bootstrap_node_transport_peer_id,
            bootstrap_node_encryption_public_key,
            bootstrap_node_transport_signature,
        };
        value.is_valid().then_some(value)
    }
}

fn take_fixed(bytes: &[u8], cursor: &mut usize) -> Option<[u8; 32]> {
    take_array(bytes, cursor)
}

fn take_array<const N: usize>(bytes: &[u8], cursor: &mut usize) -> Option<[u8; N]> {
    let value = bytes
        .get(*cursor..cursor.checked_add(N)?)?
        .try_into()
        .ok()?;
    *cursor += N;
    Some(value)
}

#[derive(
    vos::rkyv::Archive,
    vos::rkyv::Serialize,
    vos::rkyv::Deserialize,
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
)]
#[rkyv(crate = vos::rkyv)]
#[repr(u8)]
pub enum BuiltinPrincipalRole {
    Member = 0,
    Developer = 1,
    Admin = 2,
}

#[derive(
    vos::rkyv::Archive,
    vos::rkyv::Serialize,
    vos::rkyv::Deserialize,
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
)]
#[rkyv(crate = vos::rkyv)]
#[repr(u8)]
pub enum CredentialStatus {
    Active = 0,
    Revoked = 1,
}

#[derive(
    vos::rkyv::Archive, vos::rkyv::Serialize, vos::rkyv::Deserialize, Clone, Debug, PartialEq, Eq,
)]
#[rkyv(crate = vos::rkyv)]
pub struct CredentialRow {
    pub credential: [u8; 32],
    pub principal: [u8; 32],
    /// Canonical AuthorityCredentialKind tag.
    pub kind: u8,
    pub public_key: [u8; 32],
    pub status: CredentialStatus,
    /// Highest admitted ACC3 request sequence for this credential. Revocation
    /// never erases this replay boundary.
    pub management_request_high_water: u64,
    /// Reserved for the clean-break sequenced AOC generation. Keeping it in
    /// this state generation avoids a second schema transition when general
    /// operation retirement is compacted.
    pub operation_request_high_water: u64,
    /// Highest applied AAD4 request sequence for this credential. Revocation
    /// never erases this replay boundary.
    pub admin_request_high_water: u64,
}

#[derive(
    vos::rkyv::Archive, vos::rkyv::Serialize, vos::rkyv::Deserialize, Clone, Debug, PartialEq, Eq,
)]
#[rkyv(crate = vos::rkyv)]
pub struct NodeOwnerRow {
    pub node: [u8; 32],
    pub owner: [u8; 32],
    pub space: [u8; 32],
    pub transport_public_key: [u8; 32],
    pub transport_peer_id: [u8; ED25519_TRANSPORT_PEER_ID_BYTES],
    pub encryption_public_key: [u8; 32],
    pub transport_signature: [u8; PRIVATE_SIGNATURE_BYTES],
    pub enrollment_commitment: [u8; 32],
}

impl NodeOwnerRow {
    fn from_enrollment(enrollment: NodeEncryptionEnrollment) -> Self {
        Self {
            node: enrollment.node.0,
            owner: enrollment.principal.0,
            space: enrollment.space.0,
            transport_public_key: enrollment.transport_public_key,
            transport_peer_id: enrollment.transport_peer_id,
            encryption_public_key: enrollment.encryption_public_key,
            transport_signature: enrollment.transport_signature,
            enrollment_commitment: enrollment.commitment().0,
        }
    }

    fn enrollment(&self) -> NodeEncryptionEnrollment {
        NodeEncryptionEnrollment {
            space: SpaceId(self.space),
            principal: PrincipalId(self.owner),
            node: vos::agent_sdk::NodeId(self.node),
            transport_public_key: self.transport_public_key,
            transport_peer_id: self.transport_peer_id,
            encryption_public_key: self.encryption_public_key,
            transport_signature: self.transport_signature,
        }
    }
}

#[derive(
    vos::rkyv::Archive, vos::rkyv::Serialize, vos::rkyv::Deserialize, Clone, Debug, PartialEq, Eq,
)]
#[rkyv(crate = vos::rkyv)]
pub struct PrincipalRoleRow {
    pub principal: [u8; 32],
    pub role: BuiltinPrincipalRole,
}

#[derive(
    vos::rkyv::Archive, vos::rkyv::Serialize, vos::rkyv::Deserialize, Clone, Debug, PartialEq, Eq,
)]
#[rkyv(crate = vos::rkyv)]
pub struct SpaceRoleGrantRow {
    pub principal: [u8; 32],
    pub role: [u8; 32],
}

#[derive(
    vos::rkyv::Archive, vos::rkyv::Serialize, vos::rkyv::Deserialize, Clone, Debug, PartialEq, Eq,
)]
#[rkyv(crate = vos::rkyv)]
pub struct ActorRoleGrantRow {
    pub principal: [u8; 32],
    pub agent: [u8; 32],
    pub actor: [u8; 32],
    pub deployment: [u8; 32],
    pub role: [u8; 32],
}

#[derive(
    vos::rkyv::Archive, vos::rkyv::Serialize, vos::rkyv::Deserialize, Clone, Debug, PartialEq, Eq,
)]
#[rkyv(crate = vos::rkyv)]
pub struct CapabilityGrantRow {
    pub principal: [u8; 32],
    pub agent: [u8; 32],
    pub actor: [u8; 32],
    pub deployment: [u8; 32],
    pub capability: [u8; 32],
}

#[derive(
    vos::rkyv::Archive,
    vos::rkyv::Serialize,
    vos::rkyv::Deserialize,
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
)]
#[rkyv(crate = vos::rkyv)]
pub struct ManagedReplicaRow {
    pub node: [u8; 32],
    pub principal: [u8; 32],
    /// Canonical [`ReplicaRole`] tag.
    pub role: u8,
}

impl ManagedReplicaRow {
    fn from_sdk(replica: AgentReplica) -> Self {
        Self {
            node: replica.node.0,
            principal: replica.principal.0,
            role: replica.role as u8,
        }
    }

    fn sdk(self) -> Option<AgentReplica> {
        let role = match self.role {
            value if value == ReplicaRole::Voter as u8 => ReplicaRole::Voter,
            value if value == ReplicaRole::Observer as u8 => ReplicaRole::Observer,
            _ => return None,
        };
        Some(AgentReplica {
            node: vos::agent_sdk::NodeId(self.node),
            principal: PrincipalId(self.principal),
            role,
        })
    }
}

#[derive(
    vos::rkyv::Archive,
    vos::rkyv::Serialize,
    vos::rkyv::Deserialize,
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
)]
#[rkyv(crate = vos::rkyv)]
pub struct RuntimeContractRow {
    pub lifecycle_abi: [u8; 32],
    pub actor_abi_minimum: u32,
    pub actor_abi_maximum: u32,
    pub control_schema: [u8; 32],
    pub max_runtime_state_bytes: u32,
    pub max_artifact_references: u32,
    pub max_artifact_referenced_bytes: u64,
    pub max_proof_material_bytes: u64,
    pub migration: u8,
}

impl RuntimeContractRow {
    fn from_sdk(contract: RuntimePackageContract) -> Self {
        Self {
            lifecycle_abi: contract.lifecycle_abi.0,
            actor_abi_minimum: contract.actor_abis.minimum,
            actor_abi_maximum: contract.actor_abis.maximum,
            control_schema: contract.control_schema.0,
            max_runtime_state_bytes: contract.resources.max_runtime_state_bytes,
            max_artifact_references: contract.resources.max_artifact_references,
            max_artifact_referenced_bytes: contract.resources.max_artifact_referenced_bytes,
            max_proof_material_bytes: contract.resources.max_proof_material_bytes,
            migration: contract.migration as u8,
        }
    }

    fn sdk(self) -> Option<RuntimePackageContract> {
        let migration = match self.migration {
            value if value == RuntimeMigrationPolicy::None as u8 => RuntimeMigrationPolicy::None,
            _ => return None,
        };
        let contract = RuntimePackageContract {
            lifecycle_abi: Hash(self.lifecycle_abi),
            actor_abis: ActorAbiRange {
                minimum: self.actor_abi_minimum,
                maximum: self.actor_abi_maximum,
            },
            control_schema: Hash(self.control_schema),
            resources: RuntimeResourceLimits {
                max_runtime_state_bytes: self.max_runtime_state_bytes,
                max_artifact_references: self.max_artifact_references,
                max_artifact_referenced_bytes: self.max_artifact_referenced_bytes,
                max_proof_material_bytes: self.max_proof_material_bytes,
            },
            migration,
        };
        contract.is_valid().then_some(contract)
    }
}

#[derive(
    vos::rkyv::Archive, vos::rkyv::Serialize, vos::rkyv::Deserialize, Clone, Debug, PartialEq, Eq,
)]
#[rkyv(crate = vos::rkyv)]
pub struct RuntimeCapabilitiesRow {
    pub lanes: u8,
    pub scheduling: bool,
    pub proof_systems: Vec<[u8; 32]>,
    pub max_actors: u32,
}

impl RuntimeCapabilitiesRow {
    fn from_sdk(capabilities: RuntimeCapabilities) -> Self {
        Self {
            lanes: capabilities.lanes.bits(),
            scheduling: capabilities.scheduling,
            proof_systems: capabilities
                .proof_systems
                .as_slice()
                .iter()
                .map(|system| system.0)
                .collect(),
            max_actors: capabilities.max_actors,
        }
    }

    fn sdk(&self) -> Option<RuntimeCapabilities> {
        let proof_systems = self
            .proof_systems
            .iter()
            .copied()
            .map(Hash)
            .collect::<Vec<_>>();
        let capabilities = RuntimeCapabilities {
            lanes: vos::agent_sdk::LaneSet::from_bits(self.lanes)?,
            scheduling: self.scheduling,
            proof_systems: vos::agent_sdk::ProofSystemSet::from_sorted(&proof_systems).ok()?,
            max_actors: self.max_actors,
        };
        capabilities.validate().is_ok().then_some(capabilities)
    }
}

#[derive(
    vos::rkyv::Archive,
    vos::rkyv::Serialize,
    vos::rkyv::Deserialize,
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
)]
#[rkyv(crate = vos::rkyv)]
pub struct PrivateRecoveryBindingRow {
    pub signing_key_commitment: [u8; 32],
    pub encryption_public_key: [u8; 32],
}

impl PrivateRecoveryBindingRow {
    fn from_sdk(binding: PrivateRecoveryBinding) -> Self {
        Self {
            signing_key_commitment: binding.signing_key_commitment.0,
            encryption_public_key: binding.encryption_public_key,
        }
    }

    fn sdk(self) -> Option<PrivateRecoveryBinding> {
        let binding = PrivateRecoveryBinding {
            signing_key_commitment: Hash(self.signing_key_commitment),
            encryption_public_key: self.encryption_public_key,
        };
        binding.is_valid().then_some(binding)
    }
}

#[derive(
    vos::rkyv::Archive, vos::rkyv::Serialize, vos::rkyv::Deserialize, Clone, Debug, PartialEq, Eq,
)]
#[rkyv(crate = vos::rkyv)]
pub struct ManagedAgentRow {
    pub agent: [u8; 32],
    pub owner: [u8; 32],
    pub profile: u8,
    pub runtime_deployment: [u8; 32],
    pub runtime_program: [u8; 32],
    pub runtime_producer: [u8; 32],
    pub transition_producer: [u8; 32],
    pub authority: AuthorityBindingState,
    pub creation_nonce: [u8; 32],
    pub private_recovery: Option<PrivateRecoveryBindingRow>,
    pub runtime_package: AuthorityBlobRow,
    pub runtime_contract: RuntimeContractRow,
    pub capabilities: RuntimeCapabilitiesRow,
    pub replicas: Vec<ManagedReplicaRow>,
    pub replica_generation: [u8; 32],
}

#[derive(
    vos::rkyv::Archive,
    vos::rkyv::Serialize,
    vos::rkyv::Deserialize,
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
)]
#[rkyv(crate = vos::rkyv)]
pub struct AuthorityBlobRow {
    pub hash: [u8; 32],
    pub len: u64,
}

#[derive(
    vos::rkyv::Archive, vos::rkyv::Serialize, vos::rkyv::Deserialize, Clone, Debug, PartialEq, Eq,
)]
#[rkyv(crate = vos::rkyv)]
pub struct ManagedActorRow {
    pub agent: [u8; 32],
    pub actor: [u8; 32],
    pub name: String,
    pub parent: Option<[u8; 32]>,
    pub deployment: [u8; 32],
    pub program: [u8; 32],
    pub producer: [u8; 32],
    pub package: AuthorityBlobRow,
    pub agent_schema: AuthorityBlobRow,
    pub method_policy: AuthorityBlobRow,
    pub constructor_abi: [u8; 32],
    pub installation_data: Option<AuthorityBlobRow>,
    pub state_layout: [u8; 32],
    pub lanes: u8,
    pub scheduling: bool,
    pub proof_systems: Vec<[u8; 32]>,
    pub actor_abi: u32,
    /// The first post-bootstrap system-Agent install is the root catalog
    /// admitted by authorization sequence three. It may not be suspended or
    /// removed; only the same compatibility checks as an in-place upgrade may
    /// evolve its package projection.
    pub root_provenance: bool,
    pub suspended: bool,
    // Runtime-selected incarnation and lifecycle debt are deliberately absent:
    // neither is carried by ACC3/MAP2/MAA2, so the authority cannot prove them
    // from the signed durable-reopen protocol.
    pub installation_id: [u8; 32],
    pub registry_reservation: [u8; 32],
    pub install_request: [u8; 32],
}

#[derive(
    vos::rkyv::Archive, vos::rkyv::Serialize, vos::rkyv::Deserialize, Clone, Debug, PartialEq, Eq,
)]
#[rkyv(crate = vos::rkyv)]
pub struct RetiredActorInstallationRow {
    pub agent: [u8; 32],
    pub installation_id: [u8; 32],
}

fn root_managed_agent(config: SystemAuthorityConfiguration) -> ManagedAgentRow {
    let mut row = ManagedAgentRow {
        agent: config.system_agent,
        owner: config.bootstrap_principal,
        profile: AgentProfile::Shared as u8,
        runtime_deployment: config.system_runtime_deployment,
        runtime_program: config.system_runtime_program,
        runtime_producer: config.system_runtime_producer,
        transition_producer: config.system_transition_producer,
        authority: config.binding,
        creation_nonce: config.bootstrap_system_agent_creation_nonce,
        private_recovery: None,
        runtime_package: config.system_runtime_package,
        runtime_contract: RuntimeContractRow::from_sdk(RuntimePackageContract::canonical()),
        capabilities: RuntimeCapabilitiesRow::from_sdk(RuntimeCapabilities::standard()),
        replicas: vec![ManagedReplicaRow {
            node: config.bootstrap_node,
            principal: config.bootstrap_replica_principal,
            role: ReplicaRole::Voter as u8,
        }],
        replica_generation: [0; 32],
    };
    row.replica_generation = managed_replica_generation(&config, &row)
        .expect("valid root replica generation")
        .0;
    row
}

fn managed_replica_rows(replicas: &[AgentReplica]) -> Vec<ManagedReplicaRow> {
    replicas
        .iter()
        .copied()
        .map(ManagedReplicaRow::from_sdk)
        .collect()
}

fn managed_replica_generation(
    configuration: &SystemAuthorityConfiguration,
    row: &ManagedAgentRow,
) -> Option<Hash> {
    let profile = agent_profile(row.profile)?;
    let replicas = row
        .replicas
        .iter()
        .copied()
        .map(ManagedReplicaRow::sdk)
        .collect::<Option<Vec<_>>>()?;
    Some(replica_set_generation(
        &AgentIdentity {
            space: SpaceId(configuration.space),
            agent: AgentId(row.agent),
            owner: PrincipalId(row.owner),
            profile,
            runtime_deployment: DeploymentId(row.runtime_deployment),
            runtime_program: ProgramId(row.runtime_program),
            runtime_producer: ProducerId(row.runtime_producer),
            transition_producer: ProducerId(row.transition_producer),
        },
        Hash(row.creation_nonce),
        &replicas,
    ))
}

#[derive(
    vos::rkyv::Archive, vos::rkyv::Serialize, vos::rkyv::Deserialize, Clone, Debug, PartialEq, Eq,
)]
#[rkyv(crate = vos::rkyv)]
pub enum PendingManagementEffect {
    None,
    Create(ManagedAgentRow),
    ChangeReplicas {
        agent: [u8; 32],
        from_generation: [u8; 32],
        to_generation: [u8; 32],
        replicas: Vec<ManagedReplicaRow>,
    },
    InstallActor {
        agent: [u8; 32],
        actor: [u8; 32],
        parent: Option<[u8; 32]>,
        installation_id: [u8; 32],
    },
    UpgradeActor {
        agent: [u8; 32],
        actor: [u8; 32],
        from_deployment: [u8; 32],
        to_deployment: [u8; 32],
    },
    SetActorSuspended {
        agent: [u8; 32],
        actor: [u8; 32],
        deployment: [u8; 32],
        suspended: bool,
    },
    RemoveActor {
        agent: [u8; 32],
        actor: [u8; 32],
        deployment: [u8; 32],
        installation_id: [u8; 32],
    },
    UpgradeRuntime {
        agent: [u8; 32],
        from_deployment: [u8; 32],
        to_deployment: [u8; 32],
        to_program: [u8; 32],
        producer: [u8; 32],
        package: AuthorityBlobRow,
        contract: RuntimeContractRow,
        capabilities: RuntimeCapabilitiesRow,
    },
}

#[derive(
    vos::rkyv::Archive, vos::rkyv::Serialize, vos::rkyv::Deserialize, Clone, Debug, PartialEq, Eq,
)]
#[rkyv(crate = vos::rkyv)]
pub struct ExactRetryRecord {
    pub invocation: [u8; 32],
    /// Deterministic MAA2 invocation reserved atomically with this ACC3.
    pub acknowledgement_invocation: [u8; 32],
    pub credential: [u8; 32],
    pub request_sequence: u64,
    pub credential_call: [u8; 32],
    pub credential_call_bytes: Vec<u8>,
    pub approval_commitment: [u8; 32],
    pub authorization_sequence: u64,
    pub approval: Vec<u8>,
    pub effect: PendingManagementEffect,
}

/// The newest finalized management application for one credential. The ACC3
/// and MAA2 preimages are retained so the credential/request-sequence binding
/// and acknowledgement signature remain independently checkable, but MAP2 is
/// never synthesized after finalization. Older calls are rejected by the
/// credential high-water mark.
#[derive(
    vos::rkyv::Archive, vos::rkyv::Serialize, vos::rkyv::Deserialize, Clone, Debug, PartialEq, Eq,
)]
#[rkyv(crate = vos::rkyv)]
pub struct LatestManagementAckRow {
    pub credential: [u8; 32],
    pub request_sequence: u64,
    pub authorization_invocation: [u8; 32],
    pub acknowledgement_invocation: [u8; 32],
    pub authorization_sequence: u64,
    pub credential_call: [u8; 32],
    pub credential_call_bytes: Vec<u8>,
    pub approval: [u8; 32],
    pub request: [u8; 32],
    pub application: [u8; 32],
    pub acknowledgement: [u8; 32],
    pub acknowledgement_bytes: Vec<u8>,
    pub reopened_state: [u8; 32],
    pub applied_at: u64,
}

/// Exact retained AOC5/AOP5 pair and, once observed, its exact AOI1. An
/// out-of-order acknowledgement remains here until every earlier global
/// authorization position is safe to cross.
#[derive(
    vos::rkyv::Archive, vos::rkyv::Serialize, vos::rkyv::Deserialize, Clone, Debug, PartialEq, Eq,
)]
#[rkyv(crate = vos::rkyv)]
pub struct AuthorityOperationRetryRecord {
    pub invocation: [u8; 32],
    pub acknowledgement_invocation: [u8; 32],
    pub credential: [u8; 32],
    pub request_sequence: u64,
    /// Commitment of every caller-selected AOC5 field except the derived
    /// invocation and signature. This permits exact ID reconstruction after
    /// the full call preimage compacts.
    pub invocation_payload: [u8; 32],
    pub operation_call: [u8; 32],
    pub operation_call_bytes: Vec<u8>,
    pub approval_commitment: [u8; 32],
    pub authorization_sequence: u64,
    pub role: BuiltinPrincipalRole,
    pub observed_slot: u64,
    pub approval: Vec<u8>,
    pub issuance_ack: Option<[u8; 32]>,
    pub issuance_ack_bytes: Option<Vec<u8>>,
    pub issued_at: Option<u64>,
    /// Deterministic PCA2 invocation reserved atomically with a Private AOI1.
    pub private_application_invocation: Option<[u8; 32]>,
}

/// The newest durably issued operation for one credential. Exact AOI1 bytes
/// remain retryable, while the AOC5/AOP5 preimages are intentionally absent.
/// Older requests are rejected by the credential's monotonic high-water.
#[derive(
    vos::rkyv::Archive, vos::rkyv::Serialize, vos::rkyv::Deserialize, Clone, Debug, PartialEq, Eq,
)]
#[rkyv(crate = vos::rkyv)]
pub struct LatestOperationAckRow {
    pub credential: [u8; 32],
    pub request_sequence: u64,
    pub invocation_payload: [u8; 32],
    pub authorization_invocation: [u8; 32],
    pub acknowledgement_invocation: [u8; 32],
    pub authorization_sequence: u64,
    pub operation_call: [u8; 32],
    pub approval: [u8; 32],
    pub issuance_ack: [u8; 32],
    pub issuance_ack_bytes: Vec<u8>,
    pub issued_at: u64,
    pub private_application_invocation: Option<[u8; 32]>,
    pub private_operation: Option<RetiredPrivateOperationRow>,
}

/// Exact Private-control intent fields which remain after the AOC5/AOP5/AOI1
/// preimages retire. They let PCA2 prove the original operation without
/// reconstructing or relabeling discarded bytes.
#[derive(
    vos::rkyv::Archive, vos::rkyv::Serialize, vos::rkyv::Deserialize, Clone, Debug, PartialEq, Eq,
)]
#[rkyv(crate = vos::rkyv)]
pub struct RetiredPrivateOperationRow {
    pub agent: [u8; 32],
    pub runtime_deployment: [u8; 32],
    pub principal: [u8; 32],
    pub operation: u8,
    pub control: [u8; 32],
    pub control_sequence: u64,
    pub control_previous: Option<[u8; 32]>,
    pub epoch: u64,
    /// Exact Invite/Revoke membership target retained from AOC5. The other
    /// Private operations do not select one Node.
    pub node: Option<[u8; 32]>,
    /// Invite's exact transport/encryption identity commitment. A separate
    /// enrollment projection can bind this retained value before admission.
    pub node_identity: Option<[u8; 32]>,
    /// Revoke and Rotate fix the complete post-apply set in AOC5. Invite fixes
    /// the invited Node identity, while only PCA2 can report the resulting set.
    pub post_member_set: Option<[u8; 32]>,
    /// Exact canonical PRA1 bytes, present only for Recover. Keeping the proof
    /// makes issuance retirement, PCA retry, and state replay independently
    /// re-verifiable without retaining the larger AOC5.
    pub recovery_proof_bytes: Option<Vec<u8>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct PrivateApplicationSource {
    credential: [u8; 32],
    request_sequence: u64,
    invocation_payload: [u8; 32],
    private: RetiredPrivateOperationRow,
}

/// Current policy-visible Private control projection. Creation supplies the
/// genesis membership; only exact PCA2 application facts advance the head.
#[derive(
    vos::rkyv::Archive, vos::rkyv::Serialize, vos::rkyv::Deserialize, Clone, Debug, PartialEq, Eq,
)]
#[rkyv(crate = vos::rkyv)]
pub struct PrivateAgentProjectionRow {
    pub agent: [u8; 32],
    pub owner: [u8; 32],
    pub runtime_deployment: [u8; 32],
    /// Immutable membership admitted by the finalized Private Create. It is
    /// retained because later PCA transitions cannot reconstruct genesis from
    /// a compacted management history.
    pub genesis_members: Vec<[u8; 32]>,
    pub genesis_member_set: [u8; 32],
    pub control_head: Option<[u8; 32]>,
    pub control_sequence: Option<u64>,
    pub epoch: u64,
    /// Canonically sorted, unique Private member NodeIds. The commitment is
    /// redundant by design so reconstruction can reject either field drifting.
    pub members: Vec<[u8; 32]>,
    pub member_set: [u8; 32],
    /// Commitment of the latest node-local PCRS3 reopened-state proof.
    pub reopened_runtime_state: Option<[u8; 32]>,
    /// Commitment of the latest successor replica-stable runtime projection.
    pub stable_projection: Option<[u8; 32]>,
    pub applied_at: Option<u64>,
    pub application_invocation: Option<[u8; 32]>,
    pub application_ack: Option<[u8; 32]>,
    /// The latest exact PCA2 remains available for signed reconstruction.
    pub application_ack_bytes: Option<Vec<u8>>,
}

/// Compact, append-only PCA2 audit record. A cryptographic chain protects the
/// transition history while retaining every application invocation and PCA2
/// commitment for collision rejection and exact retry.
#[derive(
    vos::rkyv::Archive, vos::rkyv::Serialize, vos::rkyv::Deserialize, Clone, Debug, PartialEq, Eq,
)]
#[rkyv(crate = vos::rkyv)]
pub struct PrivateApplicationRecord {
    pub credential: [u8; 32],
    pub request_sequence: u64,
    pub invocation_payload: [u8; 32],
    pub authorization_invocation: [u8; 32],
    pub issuance_invocation: [u8; 32],
    pub application_invocation: [u8; 32],
    pub authorization_sequence: u64,
    pub operation_call: [u8; 32],
    pub approval: [u8; 32],
    pub issuance_ack: [u8; 32],
    pub application_ack: [u8; 32],
    pub agent: [u8; 32],
    pub owner: [u8; 32],
    pub runtime_deployment: [u8; 32],
    pub operation: u8,
    pub control: [u8; 32],
    pub control_sequence: u64,
    pub control_previous: Option<[u8; 32]>,
    pub epoch: u64,
    /// Present only when the applied operation selects an Invite/Revoke Node.
    pub node: Option<[u8; 32]>,
    pub node_identity: Option<[u8; 32]>,
    /// Exact canonical PRA1 bytes for Recover; absent for every other control.
    pub recovery_proof_bytes: Option<Vec<u8>>,
    pub member_set: [u8; 32],
    pub reopened_runtime_state: [u8; 32],
    pub stable_projection: [u8; 32],
    pub issued_at: u64,
    pub applied_at: u64,
}

/// Compact, append-only PAR1 terminal-resolution record. It retains the exact
/// issued Private capability for collision rejection and idempotent retry but
/// carries no guest outcome and never participates in the applied-control
/// projection or its commitment chain.
#[derive(
    vos::rkyv::Archive, vos::rkyv::Serialize, vos::rkyv::Deserialize, Clone, Debug, PartialEq, Eq,
)]
#[rkyv(crate = vos::rkyv)]
pub struct PrivateApplicationRetirementRecord {
    pub credential: [u8; 32],
    pub request_sequence: u64,
    pub invocation_payload: [u8; 32],
    pub authorization_invocation: [u8; 32],
    pub issuance_invocation: [u8; 32],
    pub application_invocation: [u8; 32],
    pub authorization_sequence: u64,
    pub operation_call: [u8; 32],
    pub approval: [u8; 32],
    pub issuance_ack: [u8; 32],
    pub retirement_ack: [u8; 32],
    pub private_operation: RetiredPrivateOperationRow,
    pub issued_at: u64,
    pub resolved_at: u64,
}

#[derive(
    vos::rkyv::Archive, vos::rkyv::Serialize, vos::rkyv::Deserialize, Clone, Debug, PartialEq, Eq,
)]
#[rkyv(crate = vos::rkyv)]
pub struct AdminRetryRecord {
    pub credential: [u8; 32],
    pub request_sequence: u64,
    pub invocation: [u8; 32],
    pub call_commitment: [u8; 32],
    pub call_bytes: Vec<u8>,
    pub result_commitment: [u8; 32],
    pub result_bytes: Vec<u8>,
    pub generation: u64,
}

#[derive(
    vos::rkyv::Archive, vos::rkyv::Serialize, vos::rkyv::Deserialize, Clone, Debug, PartialEq, Eq,
)]
#[rkyv(crate = vos::rkyv)]
pub struct AuthorityLinearState {
    initialized: bool,
    state_revision: u64,
    epoch: u64,
    authorization_sequence: u64,
    administration_generation: u64,
    credentials: Vec<CredentialRow>,
    nodes: node_storage::NodeTable,
    roles: Vec<PrincipalRoleRow>,
    space_role_grants: Vec<SpaceRoleGrantRow>,
    actor_role_grants: Vec<ActorRoleGrantRow>,
    capability_grants: Vec<CapabilityGrantRow>,
    managed_agents: Vec<ManagedAgentRow>,
    managed_actors: Vec<ManagedActorRow>,
    retired_actor_installations: Vec<RetiredActorInstallationRow>,
    retries: Vec<ExactRetryRecord>,
    latest_management_acks: Vec<LatestManagementAckRow>,
    genesis_publications: Vec<GenesisPublicationRecord>,
    operation_retries: Vec<AuthorityOperationRetryRecord>,
    operation_retirement_floor: u64,
    latest_operation_acks: Vec<LatestOperationAckRow>,
    private_agents: Vec<PrivateAgentProjectionRow>,
    private_applications: Vec<PrivateApplicationRecord>,
    private_application_retirements: Vec<PrivateApplicationRetirementRecord>,
    private_application_commitment: [u8; 32],
    admin_retries: Vec<AdminRetryRecord>,
    /// Redundant digest of the exact clean-generation state image with this
    /// field zeroed. The runtime journal remains the authenticity boundary;
    /// this commitment makes accidental or partial reconstructed-state drift
    /// fail closed instead of being mistaken for compacted history.
    state_integrity_commitment: [u8; 32],
}

impl AuthorityLinearState {
    fn inert() -> Self {
        Self {
            initialized: false,
            state_revision: 0,
            epoch: 0,
            authorization_sequence: 0,
            administration_generation: 0,
            credentials: Vec::new(),
            nodes: node_storage::NodeTable::empty(),
            roles: Vec::new(),
            space_role_grants: Vec::new(),
            actor_role_grants: Vec::new(),
            capability_grants: Vec::new(),
            managed_agents: Vec::new(),
            managed_actors: Vec::new(),
            retired_actor_installations: Vec::new(),
            retries: Vec::new(),
            latest_management_acks: Vec::new(),
            genesis_publications: Vec::new(),
            operation_retries: Vec::new(),
            operation_retirement_floor: 0,
            latest_operation_acks: Vec::new(),
            private_agents: Vec::new(),
            private_applications: Vec::new(),
            private_application_retirements: Vec::new(),
            private_application_commitment: [0; 32],
            admin_retries: Vec::new(),
            state_integrity_commitment: [0; 32],
        }
    }

    fn bootstrap(config: SystemAuthorityConfiguration) -> Self {
        let credential = CredentialId::of_public_key(&config.bootstrap_credential_public_key);
        let mut credentials = Vec::with_capacity(1);
        credentials.push(CredentialRow {
            credential: credential.0,
            principal: config.bootstrap_principal,
            kind: config.bootstrap_credential_kind,
            public_key: config.bootstrap_credential_public_key,
            status: CredentialStatus::Active,
            management_request_high_water: 0,
            operation_request_high_water: 0,
            admin_request_high_water: 0,
        });
        let nodes = node_storage::NodeTable::pending_bootstrap(NodeOwnerRow::from_enrollment(
            config.bootstrap_node_enrollment(),
        ));
        let mut roles = Vec::with_capacity(1);
        roles.push(PrincipalRoleRow {
            principal: config.bootstrap_principal,
            role: BuiltinPrincipalRole::Admin,
        });
        let mut managed_agents = Vec::with_capacity(1);
        managed_agents.push(root_managed_agent(config));
        let mut state = Self {
            initialized: true,
            state_revision: 0,
            epoch: config.binding.initial_epoch,
            authorization_sequence: config.bootstrap_authorization_high_water,
            administration_generation: 1,
            credentials,
            nodes,
            roles,
            space_role_grants: Vec::new(),
            actor_role_grants: Vec::new(),
            capability_grants: Vec::new(),
            managed_agents,
            managed_actors: Vec::new(),
            retired_actor_installations: Vec::new(),
            retries: Vec::new(),
            latest_management_acks: Vec::new(),
            genesis_publications: Vec::new(),
            operation_retries: Vec::new(),
            operation_retirement_floor: config.bootstrap_authorization_high_water,
            latest_operation_acks: Vec::new(),
            private_agents: Vec::new(),
            private_applications: Vec::new(),
            private_application_retirements: Vec::new(),
            private_application_commitment: initial_private_application_commitment(config).0,
            admin_retries: Vec::new(),
            state_integrity_commitment: [0; 32],
        };
        // Every field above is already canonical and bounded. Serialization
        // failure is unreachable for this fixed bootstrap image; fail inert if
        // that invariant is ever broken by a future state-shape change.
        if !refresh_state_integrity_commitment(&config, &mut state) {
            return Self::inert();
        }
        state
    }
}

fn computed_state_integrity_commitment(
    configuration: &SystemAuthorityConfiguration,
    state: &AuthorityLinearState,
) -> Option<Hash> {
    let mut image = state.clone();
    image.state_integrity_commitment = [0; 32];
    let configuration_bytes = configuration.encode();
    let state_bytes = vos::rkyv::to_bytes::<vos::rkyv::rancor::Error>(&image).ok()?;
    if !genesis_publication::state_bytes_fit(state, state_bytes.len()) {
        return None;
    }
    Some(Hash::digest(
        STATE_INTEGRITY_DOMAIN,
        &[
            RUNTIME_ABI_ID.as_bytes(),
            &configuration_bytes,
            &state_bytes,
        ],
    ))
}

fn refresh_state_integrity_commitment(
    configuration: &SystemAuthorityConfiguration,
    state: &mut AuthorityLinearState,
) -> bool {
    let Some(next_revision) = state.state_revision.checked_add(1) else {
        return false;
    };
    let mut candidate = state.clone();
    candidate.state_revision = next_revision;
    let Some(commitment) = computed_state_integrity_commitment(configuration, &candidate) else {
        return false;
    };
    candidate.state_integrity_commitment = commitment.0;
    *state = candidate;
    true
}

/// Linear policy state for one Space's built-in system Agent.
#[actor(agent, state_version = 20)]
pub struct SystemAuthority {
    #[state(const)]
    configuration: SystemAuthorityConfiguration,
    state: AuthorityLinearState,
    #[storage(linear, prefix = "s/authority-nodes/")]
    node_certificates: vos::storage::StorageMap<[u8; 32], NodeOwnerRow>,
}

#[messages(agent)]
impl SystemAuthority {
    fn new(configuration: &[u8]) -> Self {
        let Some(configuration) = SystemAuthorityConfiguration::decode(configuration) else {
            return Self {
                configuration: SystemAuthorityConfiguration::default(),
                state: AuthorityLinearState::inert(),
                node_certificates: Default::default(),
            };
        };
        Self {
            configuration,
            state: AuthorityLinearState::bootstrap(configuration),
            node_certificates: Default::default(),
        }
    }

    /// Verify and authorize one exact ACC3 call. Refusal is represented by an
    /// empty byte string and never mutates Linear state.
    #[msg(linear)]
    fn authorize(&mut self, call: Vec<u8>, ctx: &mut Context<Self>) -> Vec<u8> {
        let Some(context) = ctx.agent_invocation_context().copied() else {
            return Vec::new();
        };
        authorize_call(&self.configuration, &mut self.state, &call, &context)
    }

    /// Finalize a pending policy effect only after the durable issuer signs a
    /// canonical MAA2 post-reopen acknowledgement. Exact acknowledgement
    /// retries return `true` without changing state.
    #[msg(linear)]
    fn finalize(&mut self, ack: Vec<u8>, ctx: &mut Context<Self>) -> bool {
        let Some(context) = ctx.agent_invocation_context().copied() else {
            return false;
        };
        finalize_application(&self.configuration, &mut self.state, &ack, &context)
    }

    /// Publish one certified ordinary Shared genesis against an exact pending
    /// Create authorization. Publication is distinct from application finality.
    /// Supply the complete canonical provision as invocation availability;
    /// the message carries only its exact content hash and length.
    #[msg(linear)]
    fn publish_genesis(
        &mut self,
        authorization: Vec<u8>,
        provision_hash: Vec<u8>,
        provision_len: u64,
        ctx: &mut Context<Self>,
    ) -> Vec<u8> {
        let Some(context) = ctx.agent_invocation_context().copied() else {
            return Vec::new();
        };
        genesis_publication::publish_from_blob(
            &self.configuration,
            &mut self.state,
            &authorization,
            &provision_hash,
            provision_len,
            &context,
            |reference| ctx.invocation_blob(reference).ok().flatten(),
        )
    }

    /// Read a permanent decision through an authenticated runtime invocation.
    #[msg(linear)]
    fn genesis_decision(&mut self, agent: Vec<u8>, ctx: &mut Context<Self>) -> Vec<u8> {
        let Some(context) = ctx.agent_invocation_context().copied() else {
            return Vec::new();
        };
        genesis_publication::read(&self.configuration, &self.state, &agent, &context)
    }

    /// Verify one exact ingress-authenticated AOC5 and return its canonical AOP5.
    /// The approval shares the management authorization clock and remains
    /// retained until its exact signed AOI1 is consumed.
    #[msg(linear)]
    fn authorize_operation(&mut self, call: Vec<u8>, ctx: &mut Context<Self>) -> Vec<u8> {
        let Some(context) = ctx.agent_invocation_context().copied() else {
            return Vec::new();
        };
        authorize_operation_call(&self.configuration, &mut self.state, &call, &context)
    }

    /// Consume one exact authority-signed AOI1 issuance acknowledgement.
    /// Out-of-order acknowledgements remain durable; only a contiguous global
    /// prefix advances the retirement floor and releases retained preimages.
    #[msg(linear)]
    fn acknowledge_issuance(&mut self, ack: Vec<u8>, ctx: &mut Context<Self>) -> bool {
        let Some(context) = ctx.agent_invocation_context().copied() else {
            return false;
        };
        acknowledge_operation_issuance(&self.configuration, &mut self.state, &ack, &context)
    }

    /// Resolve one issued Private capability after its exact AOI1 chain is
    /// known. PCA2 advances the Private policy projection; PAR1 only retires
    /// the unused capability. Both share one invocation and are mutually
    /// exclusive exact-retry results.
    #[msg(linear)]
    fn resolve_private_application(&mut self, ack: Vec<u8>, ctx: &mut Context<Self>) -> bool {
        let Some(context) = ctx.agent_invocation_context().copied() else {
            return false;
        };
        resolve_private_application(&self.configuration, &mut self.state, &ack, &context)
    }

    /// Apply one self-authenticating Admin identity mutation. The enclosing
    /// invocation uses unsigned PublicPreflight admission; this handler binds
    /// the exact context and verifies the active Admin credential itself.
    #[msg(linear)]
    fn administer(&mut self, call: Vec<u8>, ctx: &mut Context<Self>) -> Vec<u8> {
        let Some(context) = ctx.agent_invocation_context().copied() else {
            return Vec::new();
        };
        administer_call(&self.configuration, &mut self.state, &call, &context)
    }

    /// Resolve the exact credential signing this request. A revoked
    /// credential may still prove possession and receive its revoked status;
    /// unknown, substituted, or corrupt state fails closed.
    #[msg(query)]
    fn credential_projection(&self, query: Vec<u8>) -> Vec<u8> {
        credential_projection(&self.configuration, &self.state, &query)
    }

    /// Bounded, revision-consistent credential and directory stream. One
    /// query authenticates the complete page; no per-row invocation is needed.
    #[msg(query)]
    fn inventory_projection_page(&self, query: Vec<u8>) -> Vec<u8> {
        inventory_projection_page(&self.configuration, &self.state, &query)
    }

    /// Return one bounded, full-ID ordered Agent policy page. Private entries
    /// are visible only to their owner or an Admin and never carry aliases.
    #[msg(query)]
    fn agent_projection_page(&self, query: Vec<u8>) -> Vec<u8> {
        agent_projection_page(&self.configuration, &self.state, &query)
    }

    /// Return one bounded slice of an exact Agent's replica roster. Consumers
    /// reconstruct the descriptor only from pages sharing the Agent row's
    /// state head, replica count, and replica generation.
    #[msg(query)]
    fn agent_replica_projection_page(&self, query: Vec<u8>) -> Vec<u8> {
        agent_replica_projection_page(&self.configuration, &self.state, &query)
    }

    /// Return one bounded Actor policy/status/artifact page for an exact
    /// Agent. Private inventories are owner/Admin-only.
    #[msg(query)]
    fn actor_projection_page(&self, query: Vec<u8>) -> Vec<u8> {
        actor_projection_page(&self.configuration, &self.state, &query)
    }

    /// Return the exact Authority committee used to verify ordinary genesis
    /// publication. Callers must authenticate this actor's query execution;
    /// untrusted response bytes alone do not establish committee authority.
    #[msg(query)]
    fn genesis_signing_committee(&self) -> Vec<u8> {
        genesis_publication::signing_committee(&self.configuration)
    }
}

/// Existing handlers publish their inline candidate only on success. Row
/// handles share an overlay, so their writes need an equivalent refusal
/// boundary. Success leaves rows staged for the runtime commit, never
/// committed independently of inline state or the reply.
fn authority_row_transaction<T: AuthorityMutationOutcome>(operation: impl FnOnce() -> T) -> T {
    match vos::storage::with_transaction(|| {
        let outcome = operation();
        if outcome.accepted() { Ok(outcome) } else { Err(outcome) }
    }) {
        Ok(outcome) | Err(outcome) => outcome,
    }
}

trait AuthorityMutationOutcome {
    fn accepted(&self) -> bool;
}

impl AuthorityMutationOutcome for bool {
    fn accepted(&self) -> bool { *self }
}

impl AuthorityMutationOutcome for Vec<u8> {
    fn accepted(&self) -> bool { !self.is_empty() }
}

fn resolve_private_application(
    configuration: &SystemAuthorityConfiguration,
    state: &mut AuthorityLinearState,
    encoded_ack: &[u8],
    context: &InvocationContext,
) -> bool {
    authority_row_transaction(|| resolve_private_application_staged(configuration, state, encoded_ack, context))
}

fn resolve_private_application_staged(
    configuration: &SystemAuthorityConfiguration,
    state: &mut AuthorityLinearState,
    encoded_ack: &[u8],
    context: &InvocationContext,
) -> bool {
    if encoded_ack.starts_with(b"PCA2") {
        acknowledge_private_control_application(configuration, state, encoded_ack, context)
    } else if encoded_ack.starts_with(b"PAR1") {
        retire_private_control_application(configuration, state, encoded_ack, context)
    } else {
        false
    }
}

struct Ed25519CredentialVerifier;

#[cfg(test)]
mod genesis_certificate_backend_tests {
    use super::*;
    use ed25519_dalek::{Signer as _, SigningKey};
    use vos::agent::committee::{
        AuthorityClaimCommitment, AuthorityClaimDomain, AuthorityCommittee,
        AuthorityCommitteeMember, AuthorityMemberRole, AuthorityQuorumCertificate,
        AuthoritySignature,
    };

    #[test]
    fn authority_strict_backend_verifies_exact_genesis_qc() {
        let key = SigningKey::from_bytes(&[0x61; 32]);
        let member = AuthorityCommitteeMember::new(
            vos::service::NodeId([0x62; 32]),
            key.verifying_key().to_bytes(),
            AuthorityMemberRole::Voter,
        )
        .unwrap();
        let signer = member.signer();
        let committee = AuthorityCommittee::new(
            vos::service::SpaceId([0x63; 32]),
            vos::service::Hash([0x64; 32]),
            1,
            None,
            vec![member],
        )
        .unwrap();
        let claim = AuthorityClaimCommitment::of_bytes(
            AuthorityClaimDomain::AgentGenesis,
            3,
            b"exact ordinary genesis claim",
        );
        let message = AuthorityQuorumCertificate::signing_message(
            committee.authority_binding(),
            committee.epoch(),
            committee.commitment(),
            claim,
        );
        let signature = key.sign(&message.0).to_bytes();
        let certificate = AuthorityQuorumCertificate::new(
            &committee,
            claim,
            vec![AuthoritySignature::new(signer, signature).unwrap()],
        )
        .unwrap();
        let strict = |public: &[u8; 32], message: &[u8], signature: &[u8; 64]| {
            AuthorityCredentialVerifier::verify(
                &Ed25519CredentialVerifier,
                public,
                message,
                signature,
            )
        };
        assert!(certificate.verify_with(&committee, claim, strict).is_ok());
        let mut invalid_signature = signature;
        invalid_signature[0] ^= 1;
        let invalid = AuthorityQuorumCertificate::new(
            &committee,
            claim,
            vec![AuthoritySignature::new(signer, invalid_signature).unwrap()],
        )
        .unwrap();
        assert!(invalid.verify_with(&committee, claim, strict).is_err());
        let other_claim = AuthorityClaimCommitment::of_bytes(
            AuthorityClaimDomain::AgentGenesis,
            3,
            b"substituted ordinary genesis claim",
        );
        assert!(
            certificate
                .verify_with(&committee, other_claim, strict)
                .is_err()
        );
    }
}

fn canonical_credential_public_key(public_key: &[u8; 32]) -> bool {
    VerifyingKey::from_bytes(public_key).is_ok_and(|key| !key.is_weak())
}

impl AuthorityCredentialVerifier for Ed25519CredentialVerifier {
    fn verify(&self, public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
        let Ok(verifying_key) = VerifyingKey::from_bytes(public_key) else {
            return false;
        };
        !verifying_key.is_weak()
            && verifying_key
                .verify_strict(message, &Signature::from_bytes(signature))
                .is_ok()
    }
}

impl NodeEncryptionEnrollmentVerifier for Ed25519CredentialVerifier {
    fn verify(&self, public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
        <Self as AuthorityCredentialVerifier>::verify(self, public_key, message, signature)
    }
}

impl PrivateRecoveryAuthorityProofVerifier for Ed25519CredentialVerifier {
    fn verify_private_recovery_authority_proof(
        &self,
        public_key: &[u8; 32],
        message: &[u8],
        signature: &[u8; 64],
    ) -> bool {
        <Self as AuthorityCredentialVerifier>::verify(self, public_key, message, signature)
    }
}

impl AuthorityVerifier for Ed25519CredentialVerifier {
    fn verify(&self, public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
        <Self as AuthorityCredentialVerifier>::verify(self, public_key, message, signature)
    }
}

fn projection_head(state: &AuthorityLinearState) -> Option<AuthorityProjectionHead> {
    Some(AuthorityProjectionHead {
        state_revision: NonZeroU64::new(state.state_revision)?,
        epoch: NonZeroU64::new(state.epoch)?,
        authorization_sequence: NonZeroU64::new(state.authorization_sequence)?,
        administration_generation: NonZeroU64::new(state.administration_generation)?,
        state_commitment: Hash(state.state_integrity_commitment),
    })
}

fn authenticated_projection_query(
    configuration: &SystemAuthorityConfiguration,
    state: &AuthorityLinearState,
    encoded_query: &[u8],
    allow_revoked: bool,
) -> Option<(
    AuthorityProjectionQuery,
    usize,
    PrincipalId,
    BuiltinPrincipalRole,
)> {
    if encoded_query.is_empty()
        || encoded_query.len() > MAX_INVOCATION_MESSAGE_BYTES
        || !authority_state_is_valid(configuration, state)
    {
        return None;
    }
    let query = AuthorityProjectionQuery::decode(encoded_query).ok()?;
    if !authority_target_matches(configuration, &query.authority) {
        return None;
    }
    let credential_index = state
        .credentials
        .binary_search_by(|row| row.credential.cmp(&query.credential.0))
        .ok()?;
    let credential = &state.credentials[credential_index];
    if credential.public_key != query.credential_public_key()
        || (!allow_revoked && credential.status != CredentialStatus::Active)
    {
        return None;
    }
    match query.authentication {
        AuthorityIngressAuthentication::ApiCredentialSignature { .. } => {
            if credential.kind != AuthorityCredentialKind::Api as u8
                || query.verify_api_with(&Ed25519CredentialVerifier).is_err()
            {
                return None;
            }
        }
        AuthorityIngressAuthentication::SshNodeAttestation { node, .. } => {
            if credential.kind != AuthorityCredentialKind::Ssh as u8 {
                return None;
            }
            let attester = enrolled_node(state, node)?;
            if attester.space != configuration.space
                || query
                    .verify_ssh_node_attestation_with(
                        &attester.transport_public_key,
                        &Ed25519CredentialVerifier,
                    )
                    .is_err()
            {
                return None;
            }
        }
    }
    let principal = PrincipalId(credential.principal);
    let role_index = state
        .roles
        .binary_search_by(|row| row.principal.cmp(&principal.0))
        .ok()?;
    Some((
        query,
        credential_index,
        principal,
        state.roles[role_index].role,
    ))
}

fn credential_projection(
    configuration: &SystemAuthorityConfiguration,
    state: &AuthorityLinearState,
    encoded_query: &[u8],
) -> Vec<u8> {
    let Some((query, credential_index, principal, role)) =
        authenticated_projection_query(configuration, state, encoded_query, true)
    else {
        return Vec::new();
    };
    if query.selector != AuthorityProjectionSelector::Credential {
        return Vec::new();
    }
    projected_credential(state, query, credential_index, principal, role)
        .and_then(|projection| projection.encode().ok())
        .unwrap_or_default()
}

fn projected_credential(
    state: &AuthorityLinearState,
    query: AuthorityProjectionQuery,
    credential_index: usize,
    principal: PrincipalId,
    role: BuiltinPrincipalRole,
) -> Option<AuthorityCredentialProjection> {
    let credential = &state.credentials[credential_index];
    let kind = match credential.kind {
        value if value == AuthorityCredentialKind::Ssh as u8 => AuthorityCredentialKind::Ssh,
        value if value == AuthorityCredentialKind::Api as u8 => AuthorityCredentialKind::Api,
        _ => return None,
    };
    let status = match credential.status {
        CredentialStatus::Active => AuthorityCredentialStatus::Active,
        CredentialStatus::Revoked => AuthorityCredentialStatus::Revoked,
    };
    let head = projection_head(state)?;
    let space_roles = state
        .space_role_grants
        .iter()
        .filter(|grant| grant.principal == principal.0)
        .map(|grant| RoleId(grant.role))
        .collect();
    let actor_roles = state
        .actor_role_grants
        .iter()
        .filter(|grant| grant.principal == principal.0)
        .map(|grant| AuthorityActorRoleGrant {
            agent: AgentId(grant.agent),
            actor: ActorId(grant.actor),
            deployment: DeploymentId(grant.deployment),
            role: RoleId(grant.role),
        })
        .collect();
    let capabilities = state
        .capability_grants
        .iter()
        .filter(|grant| grant.principal == principal.0)
        .map(|grant| AuthorityCapabilityGrant {
            agent: AgentId(grant.agent),
            actor: ActorId(grant.actor),
            deployment: DeploymentId(grant.deployment),
            capability: CapabilityId(grant.capability),
        })
        .collect();
    Some(AuthorityCredentialProjection {
        query,
        head,
        principal,
        status,
        kind,
        builtin_role: match role {
            BuiltinPrincipalRole::Member => AuthorityBuiltinRole::Member,
            BuiltinPrincipalRole::Developer => AuthorityBuiltinRole::Developer,
            BuiltinPrincipalRole::Admin => AuthorityBuiltinRole::Admin,
        },
        management_request_high_water: credential.management_request_high_water,
        operation_request_high_water: credential.operation_request_high_water,
        admin_request_high_water: credential.admin_request_high_water,
        space_roles,
        actor_roles,
        capabilities,
    })
}

fn private_agent_visible_to(
    row: &ManagedAgentRow,
    principal: PrincipalId,
    role: BuiltinPrincipalRole,
) -> bool {
    row.profile != AgentProfile::Private as u8
        || row.owner == principal.0
        || role == BuiltinPrincipalRole::Admin
}

fn inventory_projection_page(
    configuration: &SystemAuthorityConfiguration,
    state: &AuthorityLinearState,
    encoded_query: &[u8],
) -> Vec<u8> {
    let Some((query, credential_index, principal, role)) =
        authenticated_projection_query(configuration, state, encoded_query, true)
    else {
        return Vec::new();
    };
    let AuthorityProjectionSelector::Inventory {
        after,
        limit,
        known_head,
    } = query.selector
    else {
        return Vec::new();
    };
    let Some(credential) = projected_credential(state, query, credential_index, principal, role)
    else {
        return Vec::new();
    };
    let active = credential.status == AuthorityCredentialStatus::Active;
    let unchanged = active && after.is_none() && known_head == Some(credential.head);
    let (entries, mut has_more) = if !active || unchanged {
        (Vec::new(), false)
    } else {
        let Some(rows) = inventory_rows(
            configuration,
            state,
            principal,
            role,
            after,
            usize::from(limit),
        ) else {
            return Vec::new();
        };
        rows
    };
    let mut page = AuthorityInventoryProjectionPage {
        credential,
        unchanged,
        entries,
        next: None,
    };
    loop {
        if page.entries.is_empty() && has_more {
            // Claims plus at least one row must fit. Never turn truncation
            // into a terminal-looking empty inventory or skip an oversized row.
            return Vec::new();
        }
        page.next = has_more
            .then(|| page.entries.last().map(AuthorityInventoryEntry::cursor))
            .flatten();
        if let Ok(encoded) = page.encode() {
            return encoded;
        }
        if page.entries.pop().is_none() {
            return Vec::new();
        }
        has_more = true;
    }
}

/// Materialize at most `limit` rows plus one lookahead cursor. The enclosing
/// query has already verified state and credential once. This is still a
/// whole-state actor execution, not a claim of touched-state storage access.
fn inventory_rows(
    configuration: &SystemAuthorityConfiguration,
    state: &AuthorityLinearState,
    principal: PrincipalId,
    role: BuiltinPrincipalRole,
    after: Option<AuthorityInventoryCursor>,
    limit: usize,
) -> Option<(Vec<AuthorityInventoryEntry>, bool)> {
    let mut entries = Vec::with_capacity(limit);
    let mut complex_rows = 0;
    let first = after.map_or(0, |cursor| {
        state
            .managed_agents
            .partition_point(|row| row.agent < cursor.agent.0)
    });
    for row in &state.managed_agents[first..] {
        if !private_agent_visible_to(row, principal, role) {
            continue;
        }
        let agent = AgentId(row.agent);
        let cursor = AuthorityInventoryCursor {
            agent,
            position: AuthorityInventoryPosition::Agent,
        };
        if after.is_none_or(|after| cursor > after) {
            if entries.len() == limit
                || complex_rows == vos::agent_sdk::authority::MAX_AUTHORITY_PROJECTION_PAGE_ENTRIES
            {
                return Some((entries, true));
            }
            complex_rows += 1;
            entries.push(AuthorityInventoryEntry::Agent(managed_agent_projection(
                configuration,
                row,
            )?));
        }
        let replica_start = match after
            .filter(|cursor| cursor.agent == agent)
            .map(|cursor| cursor.position)
        {
            Some(AuthorityInventoryPosition::Actor(_)) => row.replicas.len(),
            Some(AuthorityInventoryPosition::Replica(node)) => row
                .replicas
                .partition_point(|replica| replica.node <= node.0),
            _ => 0,
        };
        for replica in &row.replicas[replica_start..] {
            if entries.len() == limit {
                return Some((entries, true));
            }
            entries.push(AuthorityInventoryEntry::Replica {
                agent,
                replica: replica.sdk()?,
            });
        }
        let after_actor = match after
            .filter(|cursor| cursor.agent == agent)
            .map(|cursor| cursor.position)
        {
            Some(AuthorityInventoryPosition::Actor(actor)) => Some(actor.0),
            _ => None,
        };
        let actor_start = state.managed_actors.partition_point(|actor| {
            actor.agent < row.agent
                || actor.agent == row.agent && after_actor.is_some_and(|after| actor.actor <= after)
        });
        for actor in state.managed_actors[actor_start..]
            .iter()
            .take_while(|actor| actor.agent == row.agent)
        {
            if entries.len() == limit
                || complex_rows == vos::agent_sdk::authority::MAX_AUTHORITY_PROJECTION_PAGE_ENTRIES
            {
                return Some((entries, true));
            }
            complex_rows += 1;
            entries.push(AuthorityInventoryEntry::Actor(managed_actor_projection(
                actor,
            )?));
        }
    }
    Some((entries, false))
}

fn agent_projection_page(
    configuration: &SystemAuthorityConfiguration,
    state: &AuthorityLinearState,
    encoded_query: &[u8],
) -> Vec<u8> {
    let Some((query, _, principal, role)) =
        authenticated_projection_query(configuration, state, encoded_query, false)
    else {
        return Vec::new();
    };
    let AuthorityProjectionSelector::Agents { after, limit } = query.selector else {
        return Vec::new();
    };
    let mut candidates = state.managed_agents.iter().filter(|row| {
        after.is_none_or(|after| row.agent > after.0)
            && private_agent_visible_to(row, principal, role)
    });
    let mut entries = Vec::with_capacity(usize::from(limit));
    for row in candidates.by_ref().take(usize::from(limit)) {
        let Some(entry) = managed_agent_projection(configuration, row) else {
            return Vec::new();
        };
        entries.push(entry);
    }
    let mut has_more = candidates.next().is_some();
    let Some(head) = projection_head(state) else {
        return Vec::new();
    };
    loop {
        if entries.is_empty() && has_more {
            // A nonempty first row must fit by itself. Never emit an empty
            // terminal-looking page when a hostile future row shape does not.
            return Vec::new();
        }
        let next = has_more
            .then(|| entries.last().map(|entry| entry.identity.agent))
            .flatten();
        let page = AuthorityAgentProjectionPage {
            query: query.clone(),
            head,
            entries: entries.clone(),
            next,
        };
        if let Ok(encoded) = page.encode() {
            return encoded;
        }
        if entries.pop().is_none() {
            return Vec::new();
        }
        has_more = true;
    }
}

fn agent_replica_projection_page(
    configuration: &SystemAuthorityConfiguration,
    state: &AuthorityLinearState,
    encoded_query: &[u8],
) -> Vec<u8> {
    let Some((query, _, principal, role)) =
        authenticated_projection_query(configuration, state, encoded_query, false)
    else {
        return Vec::new();
    };
    let AuthorityProjectionSelector::AgentReplicas {
        agent,
        after,
        limit,
    } = query.selector
    else {
        return Vec::new();
    };
    let Ok(agent_index) = managed_agent(state, agent) else {
        return Vec::new();
    };
    let row = &state.managed_agents[agent_index];
    if !private_agent_visible_to(row, principal, role) {
        return Vec::new();
    }
    let mut candidates = row
        .replicas
        .iter()
        .filter(|replica| after.is_none_or(|after| replica.node > after.0));
    let mut entries = Vec::with_capacity(usize::from(limit));
    for replica in candidates.by_ref().take(usize::from(limit)) {
        let Some(replica) = replica.sdk() else {
            return Vec::new();
        };
        entries.push(replica);
    }
    let mut has_more = candidates.next().is_some();
    let Some(head) = projection_head(state) else {
        return Vec::new();
    };
    let Ok(replica_count) = row.replicas.len().try_into() else {
        return Vec::new();
    };
    loop {
        if entries.is_empty() && has_more {
            return Vec::new();
        }
        let next = has_more
            .then(|| entries.last().map(|entry| entry.node))
            .flatten();
        let page = AuthorityAgentReplicaProjectionPage {
            query: query.clone(),
            head,
            replica_count,
            replica_generation: Hash(row.replica_generation),
            entries: entries.clone(),
            next,
        };
        if let Ok(encoded) = page.encode() {
            return encoded;
        }
        if entries.pop().is_none() {
            return Vec::new();
        }
        has_more = true;
    }
}

fn actor_projection_page(
    configuration: &SystemAuthorityConfiguration,
    state: &AuthorityLinearState,
    encoded_query: &[u8],
) -> Vec<u8> {
    let Some((query, _, principal, role)) =
        authenticated_projection_query(configuration, state, encoded_query, false)
    else {
        return Vec::new();
    };
    let AuthorityProjectionSelector::Actors {
        agent,
        after,
        limit,
    } = query.selector
    else {
        return Vec::new();
    };
    let Ok(agent_index) = managed_agent(state, agent) else {
        return Vec::new();
    };
    if !private_agent_visible_to(&state.managed_agents[agent_index], principal, role) {
        return Vec::new();
    }
    let mut candidates = state
        .managed_actors
        .iter()
        .filter(|row| row.agent == agent.0 && after.is_none_or(|after| row.actor > after.0));
    let mut entries = Vec::with_capacity(usize::from(limit));
    for row in candidates.by_ref().take(usize::from(limit)) {
        let Some(entry) = managed_actor_projection(row) else {
            return Vec::new();
        };
        entries.push(entry);
    }
    let mut has_more = candidates.next().is_some();
    let Some(head) = projection_head(state) else {
        return Vec::new();
    };
    loop {
        if entries.is_empty() && has_more {
            return Vec::new();
        }
        let next = has_more
            .then(|| entries.last().map(|entry| entry.entry.actor))
            .flatten();
        let page = AuthorityActorProjectionPage {
            query: query.clone(),
            head,
            entries: entries.clone(),
            next,
        };
        if let Ok(encoded) = page.encode() {
            return encoded;
        }
        if entries.pop().is_none() {
            return Vec::new();
        }
        has_more = true;
    }
}

fn exact_retry_count(state: &AuthorityLinearState) -> usize {
    state
        .retries
        .len()
        .saturating_add(state.operation_retries.len())
}

fn credential_index(
    state: &AuthorityLinearState,
    credential: CredentialId,
) -> core::result::Result<usize, usize> {
    state
        .credentials
        .binary_search_by(|row| row.credential.cmp(&credential.0))
}

fn credential_has_pending_application(
    state: &AuthorityLinearState,
    credential: CredentialId,
) -> bool {
    state
        .retries
        .iter()
        .any(|record| record.credential == credential.0)
        || state.latest_management_acks.iter().any(|record| {
            record.credential == credential.0
                && record.authorization_sequence > state.operation_retirement_floor
        })
        || state
            .operation_retries
            .iter()
            .any(|record| record.credential == credential.0)
        || state.latest_operation_acks.iter().any(|record| {
            record.credential == credential.0
                && (record.authorization_sequence > state.operation_retirement_floor
                    || (record.private_operation.is_some()
                        && !private_operation_source_is_resolved(
                            state,
                            record.authorization_invocation,
                            record.acknowledgement_invocation,
                            record.authorization_sequence,
                        )))
        })
}

fn principal_has_pending_application(state: &AuthorityLinearState, principal: PrincipalId) -> bool {
    state.credentials.iter().any(|credential| {
        credential.principal == principal.0
            && credential_has_pending_application(state, CredentialId(credential.credential))
    })
}

fn authorize_call(
    configuration: &SystemAuthorityConfiguration,
    state: &mut AuthorityLinearState,
    encoded_call: &[u8],
    context: &InvocationContext,
) -> Vec<u8> {
    authority_row_transaction(|| authorize_call_staged(configuration, state, encoded_call, context))
}

fn authorize_call_staged(
    configuration: &SystemAuthorityConfiguration,
    state: &mut AuthorityLinearState,
    encoded_call: &[u8],
    context: &InvocationContext,
) -> Vec<u8> {
    if encoded_call.len() > MAX_INVOCATION_MESSAGE_BYTES {
        return Vec::new();
    }
    let Ok(call) = AuthorityCredentialCall::decode(encoded_call) else {
        return Vec::new();
    };
    if !call.matches_invocation_context(context)
        || !authority_target_matches(configuration, &call.authority)
        || call.verify_with(&Ed25519CredentialVerifier).is_err()
    {
        return Vec::new();
    }

    if !authority_state_is_valid(configuration, state) {
        return Vec::new();
    }
    let call_commitment = call.commitment();
    let acknowledgement_invocation = ManagementApproval::derive_acknowledgement_invocation(&call);
    match retry_record(state, call.invocation) {
        Ok(index) => {
            let record = &state.retries[index];
            if record.credential_call != call_commitment.0
                || record.credential_call_bytes != encoded_call
                || record.acknowledgement_invocation != acknowledgement_invocation.0
            {
                return Vec::new();
            }
            let Ok(approval) = ManagementApproval::decode(&record.approval) else {
                return Vec::new();
            };
            if approval.matches_call(&call)
                && approval.commitment().0 == record.approval_commitment
                && approval.authorization_sequence.get() == record.authorization_sequence
                && approval.acknowledgement_invocation.0 == record.acknowledgement_invocation
                && authority_target_matches(configuration, &approval.authority)
            {
                return record.approval.clone();
            }
            return Vec::new();
        }
        Err(index) => {
            let Some(role) = authenticated_role(state, &call) else {
                return Vec::new();
            };
            let Ok(caller_index) = credential_index(state, call.credential) else {
                return Vec::new();
            };
            if exact_retry_count(state) >= MAX_EXACT_RETRY_RECORDS
                || state.credentials[caller_index]
                    .management_request_high_water
                    .checked_add(1)
                    != Some(call.request_sequence.get())
                || credential_has_pending_application(state, call.credential)
                || !invocation_pair_is_available(state, call.invocation, acknowledgement_invocation)
            {
                return Vec::new();
            }
            let Some(effect) = policy_effect(configuration, state, &call, role) else {
                return Vec::new();
            };
            let Some(authorization_sequence) = state.authorization_sequence.checked_add(1) else {
                return Vec::new();
            };
            let Some(nonzero_sequence) = NonZeroU64::new(authorization_sequence) else {
                return Vec::new();
            };
            let Some((valid_from, expires_at)) = narrowed_validity(&call, context.observed_slot)
            else {
                return Vec::new();
            };

            let policy = Hash(configuration.binding.policy);
            let role_byte = [role as u8];
            let sequence_bytes = authorization_sequence.to_le_bytes();
            let observed_slot_bytes = context.observed_slot.to_le_bytes();
            let evidence = AuthorityEvidence {
                package: None,
                proof: None,
                commitment: Hash::digest(
                    EVIDENCE_DOMAIN,
                    &[
                        policy.as_bytes(),
                        call_commitment.as_bytes(),
                        &role_byte,
                        &sequence_bytes,
                        &observed_slot_bytes,
                    ],
                ),
            };
            let Ok(approval) = ManagementApproval::from_call(
                &call,
                nonzero_sequence,
                evidence,
                AuthorityLaneRoots::default(),
                state.epoch,
                valid_from,
                expires_at,
            ) else {
                return Vec::new();
            };
            if approval.acknowledgement_invocation != acknowledgement_invocation {
                return Vec::new();
            }
            let Ok(approval_bytes) = approval.encode() else {
                return Vec::new();
            };
            if approval_bytes.len() > MAX_INVOCATION_REPLY_BYTES {
                return Vec::new();
            }

            let record = ExactRetryRecord {
                invocation: call.invocation.0,
                acknowledgement_invocation: acknowledgement_invocation.0,
                credential: call.credential.0,
                request_sequence: call.request_sequence.get(),
                credential_call: call_commitment.0,
                credential_call_bytes: encoded_call.to_vec(),
                approval_commitment: approval.commitment().0,
                authorization_sequence,
                approval: approval_bytes.clone(),
                effect,
            };
            let mut candidate = state.clone();
            candidate.authorization_sequence = authorization_sequence;
            candidate.credentials[caller_index].management_request_high_water =
                call.request_sequence.get();
            candidate.retries.insert(index, record);
            // Management records remain in their own exact journal. They are
            // merely durable pass-through positions for the shared general
            // operation retirement floor.
            if !advance_operation_retirement_floor(&mut candidate)
                || !refresh_state_integrity_commitment(configuration, &mut candidate)
                || !authority_state_is_valid(configuration, &candidate)
            {
                return Vec::new();
            }
            *state = candidate;
            approval_bytes
        }
    }
}

fn authorize_operation_call(
    configuration: &SystemAuthorityConfiguration,
    state: &mut AuthorityLinearState,
    encoded_call: &[u8],
    context: &InvocationContext,
) -> Vec<u8> {
    authority_row_transaction(|| authorize_operation_call_staged(configuration, state, encoded_call, context))
}

fn authorize_operation_call_staged(
    configuration: &SystemAuthorityConfiguration,
    state: &mut AuthorityLinearState,
    encoded_call: &[u8],
    context: &InvocationContext,
) -> Vec<u8> {
    if encoded_call.len() > MAX_INVOCATION_MESSAGE_BYTES {
        return Vec::new();
    }
    let Ok(call) = AuthorityOperationCall::decode(encoded_call) else {
        return Vec::new();
    };
    if !call.matches_invocation_context(context)
        || !authority_target_matches(configuration, &call.authority)
    {
        return Vec::new();
    }
    // Operation authentication may read enrolled SSH attesters. Keep that
    // state-dependent check after the audit, but reject malformed/cross-context
    // requests before any table-sized work.
    if !authority_state_is_valid(configuration, state) {
        return Vec::new();
    }
    let Some(role) = authenticated_operation_role(configuration, state, &call) else {
        return Vec::new();
    };

    let call_commitment = call.commitment();
    let acknowledgement_invocation =
        AuthorityOperationApproval::derive_acknowledgement_invocation(&call);
    match operation_retry_record(state, call.invocation) {
        Ok(index) => {
            let record = &state.operation_retries[index];
            if record.operation_call != call_commitment.0
                || record.operation_call_bytes != encoded_call
                || record.credential != call.credential.0
                || record.request_sequence != call.request_sequence.get()
                || record.invocation_payload != call.invocation_payload_commitment().0
                || record.acknowledgement_invocation != acknowledgement_invocation.0
            {
                return Vec::new();
            }
            let Ok(approval) = AuthorityOperationApproval::decode(&record.approval) else {
                return Vec::new();
            };
            if approval.matches_call(&call)
                && approval.commitment().0 == record.approval_commitment
                && approval.authorization_sequence.get() == record.authorization_sequence
                && approval.acknowledgement_invocation.0 == record.acknowledgement_invocation
                && authority_target_matches(configuration, &approval.authority)
            {
                return record.approval.clone();
            }
            Vec::new()
        }
        Err(index) => {
            let Ok(caller_index) = credential_index(state, call.credential) else {
                return Vec::new();
            };
            // Once AOI1 has advanced the floor, AOP5 bytes are intentionally
            // gone. The signed per-credential sequence rejects every retired
            // AOC5 without synthesizing a result from commitments.
            if exact_retry_count(state) >= MAX_EXACT_RETRY_RECORDS
                || state.credentials[caller_index]
                    .operation_request_high_water
                    .checked_add(1)
                    != Some(call.request_sequence.get())
                || credential_has_pending_application(state, call.credential)
                || !invocation_pair_is_available(state, call.invocation, acknowledgement_invocation)
            {
                return Vec::new();
            }
            if !operation_policy_allows(configuration, state, &call, role) {
                return Vec::new();
            }
            let Some(authorization_sequence) = state.authorization_sequence.checked_add(1) else {
                return Vec::new();
            };
            let Some(nonzero_sequence) = NonZeroU64::new(authorization_sequence) else {
                return Vec::new();
            };
            let Some((valid_from, expires_at)) = narrowed_validity_window(
                call.requested_valid_from,
                call.requested_expires_at,
                context.observed_slot,
            ) else {
                return Vec::new();
            };

            let evidence = operation_evidence(
                configuration,
                call_commitment,
                role,
                authorization_sequence,
                context.observed_slot,
            );
            let Ok(approval) = AuthorityOperationApproval::from_call(
                &call,
                nonzero_sequence,
                evidence,
                AuthorityLaneRoots::default(),
                state.epoch,
                valid_from,
                expires_at,
            ) else {
                return Vec::new();
            };
            if approval.acknowledgement_invocation != acknowledgement_invocation
                || !approval.matches_call(&call)
            {
                return Vec::new();
            }
            let Ok(approval_bytes) = approval.encode() else {
                return Vec::new();
            };
            if approval_bytes.len() > MAX_INVOCATION_REPLY_BYTES {
                return Vec::new();
            }
            let record = AuthorityOperationRetryRecord {
                invocation: call.invocation.0,
                acknowledgement_invocation: acknowledgement_invocation.0,
                credential: call.credential.0,
                request_sequence: call.request_sequence.get(),
                invocation_payload: call.invocation_payload_commitment().0,
                operation_call: call_commitment.0,
                operation_call_bytes: encoded_call.to_vec(),
                approval_commitment: approval.commitment().0,
                authorization_sequence,
                role,
                observed_slot: context.observed_slot,
                approval: approval_bytes.clone(),
                issuance_ack: None,
                issuance_ack_bytes: None,
                issued_at: None,
                private_application_invocation: None,
            };
            let mut candidate = state.clone();
            candidate.authorization_sequence = authorization_sequence;
            candidate.credentials[caller_index].operation_request_high_water =
                call.request_sequence.get();
            candidate.operation_retries.insert(index, record);
            if !refresh_state_integrity_commitment(configuration, &mut candidate)
                || !authority_state_is_valid(configuration, &candidate)
            {
                return Vec::new();
            }
            *state = candidate;
            approval_bytes
        }
    }
}

fn operation_evidence(
    configuration: &SystemAuthorityConfiguration,
    call: Hash,
    role: BuiltinPrincipalRole,
    authorization_sequence: u64,
    observed_slot: u64,
) -> AuthorityEvidence {
    AuthorityEvidence {
        package: None,
        proof: None,
        commitment: Hash::digest(
            OPERATION_EVIDENCE_DOMAIN,
            &[
                &configuration.binding.policy,
                call.as_bytes(),
                &[role as u8],
                &authorization_sequence.to_le_bytes(),
                &observed_slot.to_le_bytes(),
            ],
        ),
    }
}

fn administer_call(
    configuration: &SystemAuthorityConfiguration,
    state: &mut AuthorityLinearState,
    encoded_call: &[u8],
    context: &InvocationContext,
) -> Vec<u8> {
    authority_row_transaction(|| administer_call_staged(configuration, state, encoded_call, context))
}

fn administer_call_staged(
    configuration: &SystemAuthorityConfiguration,
    state: &mut AuthorityLinearState,
    encoded_call: &[u8],
    context: &InvocationContext,
) -> Vec<u8> {
    if encoded_call.len() > MAX_INVOCATION_MESSAGE_BYTES {
        return Vec::new();
    }
    let Ok(call) = AuthorityAdminCall::decode(encoded_call) else {
        return Vec::new();
    };
    if !call.matches_invocation_context(context)
        || !authority_target_matches(configuration, &call.authority)
        || call.verify_with(&Ed25519CredentialVerifier).is_err()
    {
        return Vec::new();
    }

    // Reject malformed, cross-context and unsigned requests before scanning
    // stored certificates. All valid-call state checks still run before retry
    // lookup or mutation; bad signatures must not consume table-sized work.
    if !authority_state_is_valid(configuration, state) {
        return Vec::new();
    }

    let call_commitment = call.commitment();
    if let Ok(index) = admin_retry_record(state, call.credential) {
        let record = &state.admin_retries[index];
        if record.invocation == call.invocation.0 {
            if record.call_commitment != call_commitment.0
                || record.call_bytes != encoded_call
                || record.request_sequence != call.request_sequence.get()
            {
                return Vec::new();
            }
            let Ok(result) = AuthorityAdminResult::decode(&record.result_bytes) else {
                return Vec::new();
            };
            if result.call == call
                && result.generation.get() == record.generation
                && result.commitment().0 == record.result_commitment
                && result.verify_with(&Ed25519CredentialVerifier).is_ok()
                && authority_target_matches(configuration, &result.call.authority)
            {
                return record.result_bytes.clone();
            }
            return Vec::new();
        }
    }

    let Ok(caller_index) = credential_index(state, call.credential) else {
        return Vec::new();
    };
    if !admin_invocation_is_available(state, call.invocation)
        || call.expected_generation.get() != state.administration_generation
        || state.credentials[caller_index]
            .admin_request_high_water
            .checked_add(1)
            != Some(call.request_sequence.get())
        || credential_has_pending_application(state, call.credential)
        || !authenticated_admin(state, &call)
    {
        return Vec::new();
    }
    let Some(generation) = call.next_generation() else {
        return Vec::new();
    };
    let mut candidate = state.clone();
    candidate.credentials[caller_index].admin_request_high_water = call.request_sequence.get();
    if !apply_admin_operation(configuration, &mut candidate, &call.operation) {
        return Vec::new();
    }
    candidate.administration_generation = generation.get();
    let Ok(result) = AuthorityAdminResult::from_call(call.clone()) else {
        return Vec::new();
    };
    let Ok(result_bytes) = result.encode() else {
        return Vec::new();
    };
    if result_bytes.len() > MAX_INVOCATION_REPLY_BYTES {
        return Vec::new();
    }
    let record = AdminRetryRecord {
        credential: call.credential.0,
        request_sequence: call.request_sequence.get(),
        invocation: call.invocation.0,
        call_commitment: call_commitment.0,
        call_bytes: encoded_call.to_vec(),
        result_commitment: result.commitment().0,
        result_bytes: result_bytes.clone(),
        generation: generation.get(),
    };
    match candidate
        .admin_retries
        .binary_search_by(|row| row.credential.cmp(&call.credential.0))
    {
        Ok(index) => candidate.admin_retries[index] = record,
        Err(index) => candidate.admin_retries.insert(index, record),
    }
    if !refresh_state_integrity_commitment(configuration, &mut candidate)
        || !authority_state_is_valid(configuration, &candidate)
    {
        return Vec::new();
    }
    *state = candidate;
    result_bytes
}

fn authenticated_admin(state: &AuthorityLinearState, call: &AuthorityAdminCall) -> bool {
    let Ok(credential_index) = state
        .credentials
        .binary_search_by(|row| row.credential.cmp(&call.credential.0))
    else {
        return false;
    };
    let credential = &state.credentials[credential_index];
    if credential.principal != call.administrator.0
        || credential.public_key != call.credential_public_key
        || credential.status != CredentialStatus::Active
    {
        return false;
    }
    if enrolled_node_owner(state, call.authenticated_node) != Some(call.administrator) {
        return false;
    }
    state
        .roles
        .binary_search_by(|row| row.principal.cmp(&call.administrator.0))
        .ok()
        .is_some_and(|index| state.roles[index].role == BuiltinPrincipalRole::Admin)
}

fn space_role_grant(
    state: &AuthorityLinearState,
    principal: PrincipalId,
    role: RoleId,
) -> core::result::Result<usize, usize> {
    state
        .space_role_grants
        .binary_search_by(|row| (row.principal, row.role).cmp(&(principal.0, role.0)))
}

fn actor_role_grant(
    state: &AuthorityLinearState,
    principal: PrincipalId,
    agent: AgentId,
    actor: ActorId,
    deployment: DeploymentId,
    role: RoleId,
) -> core::result::Result<usize, usize> {
    state.actor_role_grants.binary_search_by(|row| {
        (
            row.principal,
            row.agent,
            row.actor,
            row.deployment,
            row.role,
        )
            .cmp(&(principal.0, agent.0, actor.0, deployment.0, role.0))
    })
}

fn capability_grant(
    state: &AuthorityLinearState,
    principal: PrincipalId,
    agent: AgentId,
    actor: ActorId,
    deployment: DeploymentId,
    capability: CapabilityId,
) -> core::result::Result<usize, usize> {
    state.capability_grants.binary_search_by(|row| {
        (
            row.principal,
            row.agent,
            row.actor,
            row.deployment,
            row.capability,
        )
            .cmp(&(principal.0, agent.0, actor.0, deployment.0, capability.0))
    })
}

fn authorization_grant_count(state: &AuthorityLinearState) -> usize {
    state
        .space_role_grants
        .len()
        .saturating_add(state.actor_role_grants.len())
        .saturating_add(state.capability_grants.len())
}

fn principal_authorization_grant_count(
    state: &AuthorityLinearState,
    principal: PrincipalId,
) -> usize {
    state
        .space_role_grants
        .iter()
        .filter(|row| row.principal == principal.0)
        .count()
        .saturating_add(
            state
                .actor_role_grants
                .iter()
                .filter(|row| row.principal == principal.0)
                .count(),
        )
        .saturating_add(
            state
                .capability_grants
                .iter()
                .filter(|row| row.principal == principal.0)
                .count(),
        )
}

fn actor_accepts_authorization_grant(
    configuration: &SystemAuthorityConfiguration,
    state: &AuthorityLinearState,
    agent: AgentId,
    actor: ActorId,
    deployment: DeploymentId,
) -> bool {
    !protected_authority_actor(configuration, actor)
        && managed_actor(state, agent, actor)
            .ok()
            .is_some_and(|index| state.managed_actors[index].deployment == deployment.0)
        && !state.retries.iter().any(|record| match &record.effect {
            PendingManagementEffect::UpgradeActor {
                agent: pending_agent,
                actor: pending_actor,
                ..
            }
            | PendingManagementEffect::SetActorSuspended {
                agent: pending_agent,
                actor: pending_actor,
                ..
            }
            | PendingManagementEffect::RemoveActor {
                agent: pending_agent,
                actor: pending_actor,
                ..
            } => *pending_agent == agent.0 && *pending_actor == actor.0,
            PendingManagementEffect::InstallActor {
                agent: pending_agent,
                actor: pending_actor,
                ..
            } => *pending_agent == agent.0 && *pending_actor == actor.0,
            PendingManagementEffect::None
            | PendingManagementEffect::Create(_)
            | PendingManagementEffect::ChangeReplicas { .. }
            | PendingManagementEffect::UpgradeRuntime { .. } => false,
        })
}

fn can_add_authorization_grant(state: &AuthorityLinearState, principal: PrincipalId) -> bool {
    state
        .roles
        .binary_search_by(|row| row.principal.cmp(&principal.0))
        .is_ok()
        && authorization_grant_count(state) < MAX_AUTHORITY_AUTHORIZATION_GRANTS
        && principal_authorization_grant_count(state, principal) < MAX_AUTHORITY_PRINCIPAL_GRANTS
}

fn apply_admin_operation(
    configuration: &SystemAuthorityConfiguration,
    state: &mut AuthorityLinearState,
    operation: &AuthorityAdminOperation,
) -> bool {
    match operation {
        AuthorityAdminOperation::EnrollPrincipal {
            principal,
            credential,
        } => {
            if state.roles.len() >= MAX_AUTHORITY_PRINCIPALS
                || state.credentials.len() >= MAX_AUTHORITY_CREDENTIALS
                || state
                    .roles
                    .binary_search_by(|row| row.principal.cmp(&principal.0))
                    .is_ok()
            {
                return false;
            }
            let Err(role_index) = state
                .roles
                .binary_search_by(|row| row.principal.cmp(&principal.0))
            else {
                return false;
            };
            let Err(credential_index) = state
                .credentials
                .binary_search_by(|row| row.credential.cmp(&credential.credential.0))
            else {
                return false;
            };
            state.roles.insert(
                role_index,
                PrincipalRoleRow {
                    principal: principal.0,
                    role: BuiltinPrincipalRole::Member,
                },
            );
            state
                .credentials
                .insert(credential_index, credential_row(*principal, *credential));
        }
        AuthorityAdminOperation::AddCredential {
            principal,
            credential,
        } => {
            if state.credentials.len() >= MAX_AUTHORITY_CREDENTIALS
                || state
                    .roles
                    .binary_search_by(|row| row.principal.cmp(&principal.0))
                    .is_err()
            {
                return false;
            }
            let Err(index) = state
                .credentials
                .binary_search_by(|row| row.credential.cmp(&credential.credential.0))
            else {
                return false;
            };
            state
                .credentials
                .insert(index, credential_row(*principal, *credential));
        }
        AuthorityAdminOperation::RevokeCredential {
            principal,
            credential,
        } => {
            let Ok(index) = state
                .credentials
                .binary_search_by(|row| row.credential.cmp(&credential.0))
            else {
                return false;
            };
            if state.credentials[index].principal != principal.0
                || state.credentials[index].status != CredentialStatus::Active
                || active_credential_count(state, *principal) <= 1
                || credential_has_pending_application(state, *credential)
            {
                return false;
            }
            state.credentials[index].status = CredentialStatus::Revoked;
        }
        AuthorityAdminOperation::EnrollNode { enrollment } => {
            if state.nodes.len() >= MAX_AUTHORITY_NODES
                || enrollment.space != SpaceId(configuration.space)
                || !valid_x25519_public_key(&enrollment.encryption_public_key)
                || !enrollment.verify_with(&Ed25519CredentialVerifier)
                || state
                    .roles
                    .binary_search_by(|row| row.principal.cmp(&enrollment.principal.0))
                    .is_err()
            {
                return false;
            }
            if !insert_enrolled_node(state, *enrollment) {
                return false;
            }
        }
        AuthorityAdminOperation::UnbindNodeOwner { node, owner } => {
            if enrolled_node_owner(state, *node) != Some(*owner)
                || node_is_in_use(configuration, state, *node)
                || !remove_enrolled_node(state, *node, *owner)
            {
                return false;
            }
        }
        AuthorityAdminOperation::SetBuiltinRole { principal, role } => {
            let Ok(index) = state
                .roles
                .binary_search_by(|row| row.principal.cmp(&principal.0))
            else {
                return false;
            };
            let role = builtin_role(*role);
            if state.roles[index].role == role
                || principal_has_pending_application(state, *principal)
            {
                return false;
            }
            state.roles[index].role = role;
        }
        AuthorityAdminOperation::SetSpaceRole {
            principal,
            role,
            granted,
        } => match (*granted, space_role_grant(state, *principal, *role)) {
            (true, Err(index)) if can_add_authorization_grant(state, *principal) => {
                state.space_role_grants.insert(
                    index,
                    SpaceRoleGrantRow {
                        principal: principal.0,
                        role: role.0,
                    },
                );
            }
            (false, Ok(index)) => {
                state.space_role_grants.remove(index);
            }
            _ => return false,
        },
        AuthorityAdminOperation::SetActorRole {
            principal,
            agent,
            actor,
            deployment,
            role,
            granted,
        } => match (
            *granted,
            actor_role_grant(state, *principal, *agent, *actor, *deployment, *role),
        ) {
            (true, Err(index))
                if can_add_authorization_grant(state, *principal)
                    && actor_accepts_authorization_grant(
                        configuration,
                        state,
                        *agent,
                        *actor,
                        *deployment,
                    ) =>
            {
                state.actor_role_grants.insert(
                    index,
                    ActorRoleGrantRow {
                        principal: principal.0,
                        agent: agent.0,
                        actor: actor.0,
                        deployment: deployment.0,
                        role: role.0,
                    },
                );
            }
            (false, Ok(index)) => {
                state.actor_role_grants.remove(index);
            }
            _ => return false,
        },
        AuthorityAdminOperation::SetCapability {
            principal,
            agent,
            actor,
            deployment,
            capability,
            granted,
        } => match (
            *granted,
            capability_grant(state, *principal, *agent, *actor, *deployment, *capability),
        ) {
            (true, Err(index))
                if can_add_authorization_grant(state, *principal)
                    && actor_accepts_authorization_grant(
                        configuration,
                        state,
                        *agent,
                        *actor,
                        *deployment,
                    ) =>
            {
                state.capability_grants.insert(
                    index,
                    CapabilityGrantRow {
                        principal: principal.0,
                        agent: agent.0,
                        actor: actor.0,
                        deployment: deployment.0,
                        capability: capability.0,
                    },
                );
            }
            (false, Ok(index)) => {
                state.capability_grants.remove(index);
            }
            _ => return false,
        },
    }
    true
}

fn node_is_in_use(
    configuration: &SystemAuthorityConfiguration,
    state: &AuthorityLinearState,
    node: vos::agent_sdk::NodeId,
) -> bool {
    if node.0 == configuration.bootstrap_node
        || state.managed_agents.iter().any(|managed| {
            managed
                .replicas
                .iter()
                .any(|replica| replica.node == node.0)
        })
        || state.private_agents.iter().any(|private| {
            private.members.contains(&node.0) || private.genesis_members.contains(&node.0)
        })
        || state.private_applications.iter().any(|application| {
            application.node == Some(node.0)
                || application
                    .recovery_proof_bytes
                    .as_deref()
                    .and_then(|bytes| PrivateRecoveryAuthorityProof::decode(bytes).ok())
                    .is_some_and(|proof| proof.replacement_nodes.contains(&node))
        })
        || state.latest_operation_acks.iter().any(|record| {
            record.private_operation.as_ref().is_some_and(|operation| {
                !private_operation_source_is_retired(
                    state,
                    record.authorization_invocation,
                    record.acknowledgement_invocation,
                    record.authorization_sequence,
                ) && (operation.node == Some(node.0)
                    || recovery_proof_from_retired(operation)
                        .is_some_and(|proof| proof.replacement_nodes.contains(&node)))
            })
        })
    {
        return true;
    }
    if state.retries.iter().any(|record| {
        AuthorityCredentialCall::decode(&record.credential_call_bytes)
            .is_ok_and(|call| call.authenticated_node == Some(node))
            || match &record.effect {
                PendingManagementEffect::Create(row) => {
                    row.replicas.iter().any(|replica| replica.node == node.0)
                }
                PendingManagementEffect::ChangeReplicas { replicas, .. } => {
                    replicas.iter().any(|replica| replica.node == node.0)
                }
                _ => false,
            }
    }) {
        return true;
    }
    state.operation_retries.iter().any(|record| {
        AuthorityOperationCall::decode(&record.operation_call_bytes)
            .ok()
            .and_then(|call| {
                if call.authenticated_node() == Some(node) {
                    return Some(node);
                }
                let retired = private_operation_source_is_retired(
                    state,
                    record.invocation,
                    record.acknowledgement_invocation,
                    record.authorization_sequence,
                );
                match call.intent {
                    AuthorityOperationIntent::InvitePrivateNode { node, .. }
                    | AuthorityOperationIntent::RevokePrivateNode { node, .. }
                        if !retired =>
                    {
                        Some(node)
                    }
                    AuthorityOperationIntent::RecoverPrivateAgent { proof } if !retired => {
                        proof.replacement_nodes.contains(&node).then_some(node)
                    }
                    AuthorityOperationIntent::InvokeActor { .. }
                    | AuthorityOperationIntent::Catalog { .. }
                    | AuthorityOperationIntent::InvitePrivateNode { .. }
                    | AuthorityOperationIntent::RevokePrivateNode { .. }
                    | AuthorityOperationIntent::RecoverPrivateAgent { .. }
                    | AuthorityOperationIntent::RotatePrivateKeys { .. }
                    | AuthorityOperationIntent::SetPrivateResourcePolicy { .. }
                    | AuthorityOperationIntent::PrivateActorLifecycle { .. } => None,
                }
            })
            == Some(node)
    })
}

fn credential_row(
    principal: PrincipalId,
    credential: AuthorityCredentialEnrollment,
) -> CredentialRow {
    CredentialRow {
        credential: credential.credential.0,
        principal: principal.0,
        kind: credential.kind as u8,
        public_key: credential.public_key,
        status: CredentialStatus::Active,
        management_request_high_water: 0,
        operation_request_high_water: 0,
        admin_request_high_water: 0,
    }
}

fn credential_matches_active_enrollment(
    row: &CredentialRow,
    principal: PrincipalId,
    credential: AuthorityCredentialEnrollment,
) -> bool {
    row.credential == credential.credential.0
        && row.principal == principal.0
        && row.kind == credential.kind as u8
        && row.public_key == credential.public_key
        && row.status == CredentialStatus::Active
}

fn builtin_role(role: AuthorityBuiltinRole) -> BuiltinPrincipalRole {
    match role {
        AuthorityBuiltinRole::Member => BuiltinPrincipalRole::Member,
        AuthorityBuiltinRole::Developer => BuiltinPrincipalRole::Developer,
        AuthorityBuiltinRole::Admin => BuiltinPrincipalRole::Admin,
    }
}

fn active_credential_count(state: &AuthorityLinearState, principal: PrincipalId) -> usize {
    state
        .credentials
        .iter()
        .filter(|row| row.principal == principal.0 && row.status == CredentialStatus::Active)
        .count()
}

fn admin_retry_record(
    state: &AuthorityLinearState,
    credential: CredentialId,
) -> core::result::Result<usize, usize> {
    state
        .admin_retries
        .binary_search_by(|record| record.credential.cmp(&credential.0))
}

fn admin_invocation_is_available(state: &AuthorityLinearState, invocation: InvocationId) -> bool {
    invocation != InvocationId::ZERO
        && state
            .genesis_publications
            .iter()
            .all(|record| record.invocation != invocation.0)
        && state
            .admin_retries
            .iter()
            .all(|record| record.invocation != invocation.0)
        && state.retries.iter().all(|record| {
            record.invocation != invocation.0 && record.acknowledgement_invocation != invocation.0
        })
        && state.latest_management_acks.iter().all(|record| {
            record.authorization_invocation != invocation.0
                && record.acknowledgement_invocation != invocation.0
        })
        && state.operation_retries.iter().all(|record| {
            record.invocation != invocation.0
                && record.acknowledgement_invocation != invocation.0
                && record.private_application_invocation != Some(invocation.0)
        })
        && state.latest_operation_acks.iter().all(|record| {
            record.authorization_invocation != invocation.0
                && record.acknowledgement_invocation != invocation.0
                && record.private_application_invocation != Some(invocation.0)
        })
        && state.private_applications.iter().all(|record| {
            record.authorization_invocation != invocation.0
                && record.issuance_invocation != invocation.0
                && record.application_invocation != invocation.0
        })
        && state.private_application_retirements.iter().all(|record| {
            record.authorization_invocation != invocation.0
                && record.issuance_invocation != invocation.0
                && record.application_invocation != invocation.0
        })
}

fn finalize_application(
    configuration: &SystemAuthorityConfiguration,
    state: &mut AuthorityLinearState,
    encoded_ack: &[u8],
    context: &InvocationContext,
) -> bool {
    authority_row_transaction(|| finalize_application_staged(configuration, state, encoded_ack, context))
}

fn finalize_application_staged(
    configuration: &SystemAuthorityConfiguration,
    state: &mut AuthorityLinearState,
    encoded_ack: &[u8],
    context: &InvocationContext,
) -> bool {
    if encoded_ack.len() > MAX_INVOCATION_MESSAGE_BYTES {
        return false;
    }
    let Ok(ack) = ManagementApplicationAck::decode(encoded_ack) else {
        return false;
    };
    if !ack.matches_invocation_context(context)
        || !authority_target_matches(configuration, &ack.authority)
        || ack.verify_with(&Ed25519CredentialVerifier).is_err()
    {
        return false;
    }
    if !authority_state_is_valid(configuration, state) {
        return false;
    }
    let ack_commitment = ack.commitment();

    // Only the newest completed application for a credential remains
    // exact-retryable. Older MAA2 values are rejected by the credential
    // request high-water rather than reconstructed from discarded MAP2 bytes.
    if let Some(record) = state
        .latest_management_acks
        .iter()
        .find(|record| record.acknowledgement_invocation == ack.acknowledgement_invocation.0)
    {
        return record.authorization_invocation == ack.authorization_invocation.0
            && record.authorization_sequence == ack.authorization_sequence.get()
            && record.credential_call == ack.credential_call.0
            && record.approval == ack.approval.0
            && record.request == ack.request.0
            && record.application
                == vos::agent_sdk::wire::management_reply_commitment(&ack.application).0
            && record.acknowledgement == ack_commitment.0
            && record.acknowledgement_bytes == encoded_ack
            && record.reopened_state == ack.reopened_state.0
            && record.applied_at == ack.applied_at;
    }

    let Some(record_index) = state
        .retries
        .iter()
        .position(|record| record.acknowledgement_invocation == ack.acknowledgement_invocation.0)
    else {
        return false;
    };
    let record = &state.retries[record_index];
    if record.invocation != ack.authorization_invocation.0 {
        return false;
    }
    if record.credential_call != ack.credential_call.0
        || record.approval_commitment != ack.approval.0
        || record.authorization_sequence != ack.authorization_sequence.get()
    {
        return false;
    }
    let Ok(call) = AuthorityCredentialCall::decode(&record.credential_call_bytes) else {
        return false;
    };
    let Ok(approval) = ManagementApproval::decode(&record.approval) else {
        return false;
    };
    if !ack.matches_pending(&call, &approval) {
        return false;
    }

    let Some(plan) = application_plan(configuration, state, &record.effect, &call, &ack) else {
        return false;
    };
    let latest = LatestManagementAckRow {
        credential: record.credential,
        request_sequence: record.request_sequence,
        authorization_invocation: record.invocation,
        acknowledgement_invocation: record.acknowledgement_invocation,
        authorization_sequence: record.authorization_sequence,
        credential_call: record.credential_call,
        credential_call_bytes: record.credential_call_bytes.clone(),
        approval: record.approval_commitment,
        request: ack.request.0,
        application: vos::agent_sdk::wire::management_reply_commitment(&ack.application).0,
        acknowledgement: ack_commitment.0,
        acknowledgement_bytes: encoded_ack.to_vec(),
        reopened_state: ack.reopened_state.0,
        applied_at: ack.applied_at,
    };
    let mut candidate = state.clone();
    apply_application_plan(&mut candidate, plan);
    candidate.retries.remove(record_index);
    match candidate
        .latest_management_acks
        .binary_search_by(|record| record.credential.cmp(&latest.credential))
    {
        Ok(index) => {
            if candidate.latest_management_acks[index].request_sequence >= latest.request_sequence {
                return false;
            }
            candidate.latest_management_acks[index] = latest;
        }
        Err(index) => candidate.latest_management_acks.insert(index, latest),
    }
    if !refresh_state_integrity_commitment(configuration, &mut candidate)
        || !authority_state_is_valid(configuration, &candidate)
    {
        return false;
    }
    *state = candidate;
    true
}

fn acknowledge_operation_issuance(
    configuration: &SystemAuthorityConfiguration,
    state: &mut AuthorityLinearState,
    encoded_ack: &[u8],
    context: &InvocationContext,
) -> bool {
    authority_row_transaction(|| acknowledge_operation_issuance_staged(configuration, state, encoded_ack, context))
}

fn acknowledge_operation_issuance_staged(
    configuration: &SystemAuthorityConfiguration,
    state: &mut AuthorityLinearState,
    encoded_ack: &[u8],
    context: &InvocationContext,
) -> bool {
    if encoded_ack.len() > MAX_INVOCATION_MESSAGE_BYTES {
        return false;
    }
    let Ok(ack) = AuthorityOperationIssuanceAck::decode(encoded_ack) else {
        return false;
    };
    if !ack.matches_invocation_context(context)
        || !authority_target_matches(configuration, &ack.authority)
        || ack
            .verify_with(configuration.binding.sdk(), &Ed25519CredentialVerifier)
            .is_err()
    {
        return false;
    }
    if !authority_state_is_valid(configuration, state) {
        return false;
    }
    let ack_commitment = ack.commitment();

    // The credential-bounded latest result makes an exact AOI1 retry
    // idempotent after its AOC5/AOP5 preimages compact. It deliberately cannot
    // answer an AOC5 retry.
    if let Some(latest) = state
        .latest_operation_acks
        .iter()
        .find(|row| row.acknowledgement_invocation == ack.acknowledgement_invocation.0)
    {
        return latest.authorization_invocation == ack.authorization_invocation.0
            && latest.authorization_sequence == ack.authorization_sequence.get()
            && latest.issuance_ack == ack_commitment.0
            && latest.issuance_ack_bytes == encoded_ack;
    }

    let Some(record_index) = state
        .operation_retries
        .iter()
        .position(|record| record.acknowledgement_invocation == ack.acknowledgement_invocation.0)
    else {
        return false;
    };
    let record = &state.operation_retries[record_index];
    if record.invocation != ack.authorization_invocation.0
        || record.operation_call != ack.operation_call.0
        || record.approval_commitment != ack.approval.0
        || record.authorization_sequence != ack.authorization_sequence.get()
    {
        return false;
    }
    if record.issuance_ack.is_some() {
        return record.issuance_ack == Some(ack_commitment.0)
            && record.issuance_ack_bytes.as_deref() == Some(encoded_ack)
            && record.issued_at == Some(ack.issued_at);
    }
    let Ok(call) = AuthorityOperationCall::decode(&record.operation_call_bytes) else {
        return false;
    };
    let Ok(approval) = AuthorityOperationApproval::decode(&record.approval) else {
        return false;
    };
    let Ok(fact) = ack.verified_retirement_fact(&call, &approval, &Ed25519CredentialVerifier)
    else {
        return false;
    };
    if fact.authority() != configured_authority_target(configuration)
        || fact.authorization_sequence().get() != record.authorization_sequence
        || fact.issuance_ack() != ack_commitment
    {
        return false;
    }
    let private_application_invocation = retained_private_operation(&call)
        .map(|_| PrivateControlApplicationAck::derive_application_invocation(&ack));
    if private_application_invocation
        .is_some_and(|invocation| !private_application_invocation_is_unreserved(state, invocation))
    {
        return false;
    }

    let mut candidate = state.clone();
    let record = &mut candidate.operation_retries[record_index];
    record.issuance_ack = Some(ack_commitment.0);
    record.issuance_ack_bytes = Some(encoded_ack.to_vec());
    record.issued_at = Some(ack.issued_at);
    record.private_application_invocation =
        private_application_invocation.map(|invocation| invocation.0);
    if !advance_operation_retirement_floor(&mut candidate)
        || !refresh_state_integrity_commitment(configuration, &mut candidate)
        || !authority_state_is_valid(configuration, &candidate)
    {
        return false;
    }
    *state = candidate;
    true
}

fn acknowledge_private_control_application(
    configuration: &SystemAuthorityConfiguration,
    state: &mut AuthorityLinearState,
    encoded_ack: &[u8],
    context: &InvocationContext,
) -> bool {
    if encoded_ack.len() > MAX_INVOCATION_MESSAGE_BYTES {
        return false;
    }
    let Ok(ack) = PrivateControlApplicationAck::decode(encoded_ack) else {
        return false;
    };
    if !ack.matches_invocation_context(context)
        || !authority_target_matches(configuration, &ack.authority)
        || ack
            .verify_with(configuration.binding.sdk(), &Ed25519CredentialVerifier)
            .is_err()
    {
        return false;
    }
    if !authority_state_is_valid(configuration, state) {
        return false;
    }
    let ack_commitment = ack.commitment();

    if let Some(record) = state
        .private_applications
        .iter()
        .find(|record| record.application_invocation == ack.application_invocation.0)
    {
        return record.authorization_invocation == ack.authorization_invocation.0
            && record.issuance_invocation == ack.issuance_invocation.0
            && record.authorization_sequence == ack.authorization_sequence.get()
            && record.application_ack == ack_commitment.0;
    }
    if private_application_resolution_count(state) >= MAX_PRIVATE_APPLICATION_RECORDS
        || state.private_application_retirements.iter().any(|record| {
            record.authorization_invocation == ack.authorization_invocation.0
                || record.issuance_invocation == ack.issuance_invocation.0
                || record.application_invocation == ack.application_invocation.0
                || record.authorization_sequence == ack.authorization_sequence.get()
        })
        || state.private_applications.iter().any(|record| {
            record.authorization_invocation == ack.authorization_invocation.0
                || record.issuance_invocation == ack.issuance_invocation.0
                || record.authorization_sequence == ack.authorization_sequence.get()
        })
    {
        return false;
    }

    let Some(source) = private_application_source(configuration, state, &ack) else {
        return false;
    };
    let target = ack.application.managed;
    let Ok(managed_index) = managed_agent(state, target.agent) else {
        return false;
    };
    let managed = &state.managed_agents[managed_index];
    if managed.profile != AgentProfile::Private as u8
        || managed.owner != source.private.principal
        || managed.authority != configuration.binding
        || !retired_private_operation_matches_application(&source.private, &ack.application)
    {
        return false;
    }
    let Ok(private_index) = private_agent(state, target.agent) else {
        return false;
    };
    if ack.application.operation == AuthorityOperationKind::RecoverPrivateAgent {
        let Some(proof) = recovery_proof_from_retired(&source.private) else {
            return false;
        };
        if !recovery_application_capacity_available(state)
            || !recovery_proof_matches_managed_state(configuration, state, managed, &proof)
            || !recovery_position_matches_projection(&state.private_agents[private_index], &proof)
        {
            return false;
        }
    }
    let record = PrivateApplicationRecord {
        credential: source.credential,
        request_sequence: source.request_sequence,
        invocation_payload: source.invocation_payload,
        authorization_invocation: ack.authorization_invocation.0,
        issuance_invocation: ack.issuance_invocation.0,
        application_invocation: ack.application_invocation.0,
        authorization_sequence: ack.authorization_sequence.get(),
        operation_call: ack.operation_call.0,
        approval: ack.approval.0,
        issuance_ack: ack.issuance_ack.0,
        application_ack: ack_commitment.0,
        agent: target.agent.0,
        owner: managed.owner,
        runtime_deployment: target.runtime_deployment.0,
        operation: ack.application.operation as u8,
        control: ack.application.control.0,
        control_sequence: ack.application.control_sequence,
        control_previous: ack.application.control_previous.map(|previous| previous.0),
        epoch: ack.application.epoch,
        node: source.private.node,
        node_identity: source.private.node_identity,
        recovery_proof_bytes: source.private.recovery_proof_bytes.clone(),
        member_set: ack.application.post_member_set.0,
        reopened_runtime_state: ack.application.reopened_runtime_state.0,
        stable_projection: ack.application.stable_projection.0,
        issued_at: ack.issued_at,
        applied_at: ack.application.applied_at,
    };

    let mut candidate = state.clone();
    if !apply_private_application_transition(&mut candidate.private_agents[private_index], &record)
    {
        return false;
    }
    let projection = &mut candidate.private_agents[private_index];
    projection.application_ack_bytes = Some(encoded_ack.to_vec());
    candidate.private_application_commitment =
        private_application_commitment(Hash(candidate.private_application_commitment), &record).0;
    candidate.private_applications.push(record);
    if !synchronize_private_managed_replicas(configuration, &mut candidate, private_index)
        || !refresh_state_integrity_commitment(configuration, &mut candidate)
        || !authority_state_is_valid(configuration, &candidate)
    {
        return false;
    }
    *state = candidate;
    true
}

fn retire_private_control_application(
    configuration: &SystemAuthorityConfiguration,
    state: &mut AuthorityLinearState,
    encoded_ack: &[u8],
    context: &InvocationContext,
) -> bool {
    if encoded_ack.len() > MAX_INVOCATION_MESSAGE_BYTES {
        return false;
    }
    let Ok(ack) = PrivateControlApplicationRetirementAck::decode(encoded_ack) else {
        return false;
    };
    if !ack.matches_invocation_context(context)
        || !authority_target_matches(configuration, &ack.authority)
        || ack
            .verify_with(configuration.binding.sdk(), &Ed25519CredentialVerifier)
            .is_err()
    {
        return false;
    }
    if !authority_state_is_valid(configuration, state) {
        return false;
    }
    let ack_commitment = ack.commitment();

    if let Some(record) = state
        .private_application_retirements
        .iter()
        .find(|record| record.application_invocation == ack.application_invocation.0)
    {
        return record.authorization_invocation == ack.authorization_invocation.0
            && record.issuance_invocation == ack.issuance_invocation.0
            && record.authorization_sequence == ack.authorization_sequence.get()
            && record.retirement_ack == ack_commitment.0
            && record.resolved_at == ack.resolved_at;
    }
    if private_application_resolution_count(state) >= MAX_PRIVATE_APPLICATION_RECORDS
        || state.private_applications.iter().any(|record| {
            record.authorization_invocation == ack.authorization_invocation.0
                || record.issuance_invocation == ack.issuance_invocation.0
                || record.application_invocation == ack.application_invocation.0
                || record.authorization_sequence == ack.authorization_sequence.get()
        })
        || state.private_application_retirements.iter().any(|record| {
            record.authorization_invocation == ack.authorization_invocation.0
                || record.issuance_invocation == ack.issuance_invocation.0
                || record.authorization_sequence == ack.authorization_sequence.get()
        })
    {
        return false;
    }

    let Some(source) = private_application_retirement_source(configuration, state, &ack) else {
        return false;
    };
    let private = &source.private;
    let Ok(managed_index) = managed_agent(state, AgentId(private.agent)) else {
        return false;
    };
    let managed = &state.managed_agents[managed_index];
    if managed.profile != AgentProfile::Private as u8
        || managed.owner != private.principal
        || managed.authority != configuration.binding
        || !retired_private_operation_matches_retirement(private, &ack)
    {
        return false;
    }
    let record = PrivateApplicationRetirementRecord {
        credential: source.credential,
        request_sequence: source.request_sequence,
        invocation_payload: source.invocation_payload,
        authorization_invocation: ack.authorization_invocation.0,
        issuance_invocation: ack.issuance_invocation.0,
        application_invocation: ack.application_invocation.0,
        authorization_sequence: ack.authorization_sequence.get(),
        operation_call: ack.operation_call.0,
        approval: ack.approval.0,
        issuance_ack: ack.issuance_ack.0,
        retirement_ack: ack_commitment.0,
        private_operation: source.private,
        issued_at: ack.issued_at,
        resolved_at: ack.resolved_at,
    };

    let mut candidate = state.clone();
    candidate.private_application_retirements.push(record);
    if !refresh_state_integrity_commitment(configuration, &mut candidate)
        || !authority_state_is_valid(configuration, &candidate)
    {
        return false;
    }
    *state = candidate;
    true
}

fn synchronize_private_managed_replicas(
    configuration: &SystemAuthorityConfiguration,
    state: &mut AuthorityLinearState,
    private_index: usize,
) -> bool {
    let Some(projection) = state.private_agents.get(private_index) else {
        return false;
    };
    let Ok(managed_index) = managed_agent(state, AgentId(projection.agent)) else {
        return false;
    };
    let owner = projection.owner;
    let replicas = projection
        .members
        .iter()
        .map(|node| ManagedReplicaRow {
            node: *node,
            principal: owner,
            role: ReplicaRole::Observer as u8,
        })
        .collect::<Vec<_>>();
    let row = &mut state.managed_agents[managed_index];
    row.replicas = replicas;
    let Some(generation) = managed_replica_generation(configuration, row) else {
        return false;
    };
    row.replica_generation = generation.0;
    true
}

fn private_application_source(
    configuration: &SystemAuthorityConfiguration,
    state: &AuthorityLinearState,
    ack: &PrivateControlApplicationAck,
) -> Option<PrivateApplicationSource> {
    if let Some(record) = state.operation_retries.iter().find(|record| {
        record.acknowledgement_invocation == ack.issuance_invocation.0
            && record.invocation == ack.authorization_invocation.0
    }) {
        if record.operation_call != ack.operation_call.0
            || record.approval_commitment != ack.approval.0
            || record.issuance_ack != Some(ack.issuance_ack.0)
            || record.authorization_sequence != ack.authorization_sequence.get()
            || record.issued_at != Some(ack.issued_at)
            || record.private_application_invocation != Some(ack.application_invocation.0)
        {
            return None;
        }
        let call = AuthorityOperationCall::decode(&record.operation_call_bytes).ok()?;
        let approval = AuthorityOperationApproval::decode(&record.approval).ok()?;
        let issuance =
            AuthorityOperationIssuanceAck::decode(record.issuance_ack_bytes.as_deref()?).ok()?;
        if ack
            .verify_pending_with(
                &call,
                &approval,
                &issuance,
                &ack.application,
                configuration.binding.sdk(),
                &Ed25519CredentialVerifier,
            )
            .is_err()
        {
            return None;
        }
        return Some(PrivateApplicationSource {
            credential: record.credential,
            request_sequence: record.request_sequence,
            invocation_payload: record.invocation_payload,
            private: retained_private_operation(&call)?,
        });
    }

    let retired = state.latest_operation_acks.iter().find(|record| {
        record.acknowledgement_invocation == ack.issuance_invocation.0
            && record.authorization_invocation == ack.authorization_invocation.0
    })?;
    let sequence = NonZeroU64::new(retired.authorization_sequence)?;
    if retired.operation_call != ack.operation_call.0
        || retired.approval != ack.approval.0
        || retired.issuance_ack != ack.issuance_ack.0
        || retired.issued_at != ack.issued_at
        || retired.private_application_invocation != Some(ack.application_invocation.0)
        || ack
            .verify_issuance_tombstone_with(
                configured_authority_target(configuration),
                InvocationId(retired.authorization_invocation),
                InvocationId(retired.acknowledgement_invocation),
                sequence,
                Hash(retired.issuance_ack),
                &Ed25519CredentialVerifier,
            )
            .is_err()
    {
        return None;
    }
    Some(PrivateApplicationSource {
        credential: retired.credential,
        request_sequence: retired.request_sequence,
        invocation_payload: retired.invocation_payload,
        private: retired.private_operation.clone()?,
    })
}

fn private_application_retirement_source(
    configuration: &SystemAuthorityConfiguration,
    state: &AuthorityLinearState,
    ack: &PrivateControlApplicationRetirementAck,
) -> Option<PrivateApplicationSource> {
    if let Some(record) = state.operation_retries.iter().find(|record| {
        record.acknowledgement_invocation == ack.issuance_invocation.0
            && record.invocation == ack.authorization_invocation.0
    }) {
        if record.operation_call != ack.operation_call.0
            || record.approval_commitment != ack.approval.0
            || record.issuance_ack != Some(ack.issuance_ack.0)
            || record.authorization_sequence != ack.authorization_sequence.get()
            || record.issued_at != Some(ack.issued_at)
            || record.private_application_invocation != Some(ack.application_invocation.0)
        {
            return None;
        }
        let call = AuthorityOperationCall::decode(&record.operation_call_bytes).ok()?;
        let approval = AuthorityOperationApproval::decode(&record.approval).ok()?;
        let issuance =
            AuthorityOperationIssuanceAck::decode(record.issuance_ack_bytes.as_deref()?).ok()?;
        if ack
            .verify_pending_with(
                &call,
                &approval,
                &issuance,
                configuration.binding.sdk(),
                &Ed25519CredentialVerifier,
            )
            .is_err()
        {
            return None;
        }
        return Some(PrivateApplicationSource {
            credential: record.credential,
            request_sequence: record.request_sequence,
            invocation_payload: record.invocation_payload,
            private: retained_private_operation(&call)?,
        });
    }

    let retired = state.latest_operation_acks.iter().find(|record| {
        record.acknowledgement_invocation == ack.issuance_invocation.0
            && record.authorization_invocation == ack.authorization_invocation.0
    })?;
    let sequence = NonZeroU64::new(retired.authorization_sequence)?;
    let issuance = AuthorityOperationIssuanceAck::decode(&retired.issuance_ack_bytes).ok()?;
    if retired.operation_call != ack.operation_call.0
        || retired.approval != ack.approval.0
        || retired.issuance_ack != ack.issuance_ack.0
        || retired.issued_at != ack.issued_at
        || retired.private_application_invocation != Some(ack.application_invocation.0)
        || issuance.receipt != ack.receipt
        || issuance.issued_at != ack.issued_at
        || ack
            .verify_issuance_tombstone_with(
                configured_authority_target(configuration),
                InvocationId(retired.authorization_invocation),
                InvocationId(retired.acknowledgement_invocation),
                sequence,
                Hash(retired.issuance_ack),
                &Ed25519CredentialVerifier,
            )
            .is_err()
    {
        return None;
    }
    Some(PrivateApplicationSource {
        credential: retired.credential,
        request_sequence: retired.request_sequence,
        invocation_payload: retired.invocation_payload,
        private: retired.private_operation.clone()?,
    })
}

fn retained_private_operation(call: &AuthorityOperationCall) -> Option<RetiredPrivateOperationRow> {
    let managed = call.intent.managed();
    let (
        operation,
        control,
        control_sequence,
        control_previous,
        epoch,
        node,
        node_identity,
        post_member_set,
        recovery_proof_bytes,
    ) = match &call.intent {
        AuthorityOperationIntent::InvitePrivateNode {
            control,
            control_sequence,
            control_previous,
            epoch,
            node,
            node_identity,
            ..
        } => (
            AuthorityOperationKind::InvitePrivateNode,
            *control,
            *control_sequence,
            *control_previous,
            *epoch,
            Some(*node),
            Some(*node_identity),
            None,
            None,
        ),
        AuthorityOperationIntent::RevokePrivateNode {
            control,
            control_sequence,
            control_previous,
            epoch,
            node,
            member_set,
            ..
        } => (
            AuthorityOperationKind::RevokePrivateNode,
            *control,
            *control_sequence,
            *control_previous,
            *epoch,
            Some(*node),
            None,
            Some(*member_set),
            None,
        ),
        AuthorityOperationIntent::RecoverPrivateAgent { proof } => (
            AuthorityOperationKind::RecoverPrivateAgent,
            proof.control,
            proof.control_sequence,
            proof.control_previous,
            proof.next_epoch,
            None,
            None,
            Some(proof.replacement_member_set),
            Some(proof.encode().ok()?),
        ),
        AuthorityOperationIntent::RotatePrivateKeys {
            control,
            control_sequence,
            control_previous,
            epoch,
            member_set,
            ..
        } => (
            AuthorityOperationKind::RotatePrivateKeys,
            *control,
            *control_sequence,
            *control_previous,
            *epoch,
            None,
            None,
            Some(*member_set),
            None,
        ),
        AuthorityOperationIntent::SetPrivateResourcePolicy {
            control,
            control_sequence,
            control_previous,
            ..
        } => (
            AuthorityOperationKind::SetPrivateResourcePolicy,
            *control,
            *control_sequence,
            *control_previous,
            0,
            None,
            None,
            None,
            None,
        ),
        AuthorityOperationIntent::PrivateActorLifecycle {
            control,
            control_sequence,
            control_previous,
            ..
        } => (
            AuthorityOperationKind::PrivateActorLifecycle,
            *control,
            *control_sequence,
            *control_previous,
            0,
            None,
            None,
            None,
            None,
        ),
        AuthorityOperationIntent::InvokeActor { .. } | AuthorityOperationIntent::Catalog { .. } => {
            return None;
        }
    };
    Some(RetiredPrivateOperationRow {
        agent: managed.agent.0,
        runtime_deployment: managed.runtime_deployment.0,
        principal: call.principal.0,
        operation: operation as u8,
        control: control.0,
        control_sequence,
        control_previous: control_previous.map(|previous| previous.0),
        epoch,
        node: node.map(|node| node.0),
        node_identity: node_identity.map(|identity| identity.0),
        post_member_set: post_member_set.map(|member_set| member_set.0),
        recovery_proof_bytes,
    })
}

fn retired_private_operation_matches_application(
    source: &RetiredPrivateOperationRow,
    application: &PrivateControlApplicationFact,
) -> bool {
    let operation_fields_match =
        if source.operation == AuthorityOperationKind::InvitePrivateNode as u8 {
            source.epoch == application.epoch && source.post_member_set.is_none()
        } else if matches!(
            private_operation_kind(source.operation),
            Some(
                AuthorityOperationKind::RevokePrivateNode
                    | AuthorityOperationKind::RecoverPrivateAgent
                    | AuthorityOperationKind::RotatePrivateKeys
            )
        ) {
            source.epoch == application.epoch
                && source.post_member_set == Some(application.post_member_set.0)
        } else if matches!(
            private_operation_kind(source.operation),
            Some(
                AuthorityOperationKind::SetPrivateResourcePolicy
                    | AuthorityOperationKind::PrivateActorLifecycle
            )
        ) {
            source.epoch == 0 && source.post_member_set.is_none()
        } else {
            false
        };
    source.agent == application.managed.agent.0
        && source.runtime_deployment == application.managed.runtime_deployment.0
        && source.operation == application.operation as u8
        && source.control == application.control.0
        && source.control_sequence == application.control_sequence
        && source.control_previous == application.control_previous.map(|previous| previous.0)
        && operation_fields_match
}

fn retired_private_operation_matches_retirement(
    source: &RetiredPrivateOperationRow,
    retirement: &PrivateControlApplicationRetirementAck,
) -> bool {
    let selector = &retirement.receipt.selector;
    let expected_request = if source.operation == AuthorityOperationKind::RecoverPrivateAgent as u8
    {
        let Some(proof) = recovery_proof_from_retired(source) else {
            return false;
        };
        proof.commitment()
    } else {
        Hash(source.control)
    };
    selector.agent == AgentId(source.agent)
        && selector.runtime_deployment == DeploymentId(source.runtime_deployment)
        && private_operation_kind(source.operation) == Some(selector.operation)
        && selector.request == expected_request
}

fn member_set_commitment(members: &[[u8; 32]]) -> Option<Hash> {
    private_member_set_commitment(members.iter().copied().map(vos::agent_sdk::NodeId))
}

fn next_private_members(
    projection: &PrivateAgentProjectionRow,
    operation: u8,
    node: Option<[u8; 32]>,
) -> Option<(Vec<[u8; 32]>, Hash)> {
    let node = node?;
    if node == [0; 32]
        || projection.members.is_empty()
        || projection.members.len() > MAX_PRIVATE_NODES
        || member_set_commitment(&projection.members)?.0 != projection.member_set
    {
        return None;
    }
    let mut members = projection.members.clone();
    match members.binary_search(&node) {
        Err(index) if operation == AuthorityOperationKind::InvitePrivateNode as u8 => {
            if members.len() >= MAX_PRIVATE_NODES {
                return None;
            }
            members.insert(index, node);
        }
        Ok(index) if operation == AuthorityOperationKind::RevokePrivateNode as u8 => {
            members.remove(index);
        }
        _ => return None,
    }
    let commitment = member_set_commitment(&members)?;
    Some((members, commitment))
}

fn private_control_position_is_next(
    projection: &PrivateAgentProjectionRow,
    control_sequence: u64,
    control_previous: Option<Hash>,
) -> bool {
    let expected_sequence = match projection.control_sequence {
        Some(sequence) => sequence.checked_add(1),
        None => Some(0),
    };
    expected_sequence == Some(control_sequence)
        && projection.control_head == control_previous.map(|previous| previous.0)
}

fn apply_private_application_transition(
    projection: &mut PrivateAgentProjectionRow,
    record: &PrivateApplicationRecord,
) -> bool {
    // `applied_at` is a monotonic observation, not the ordering key. Exact
    // control sequence and predecessor-head checks order distinct transitions
    // which legitimately share one authority-observed slot.
    if record.operation == AuthorityOperationKind::RecoverPrivateAgent as u8 {
        let retired = RetiredPrivateOperationRow {
            agent: record.agent,
            runtime_deployment: record.runtime_deployment,
            principal: record.owner,
            operation: record.operation,
            control: record.control,
            control_sequence: record.control_sequence,
            control_previous: record.control_previous,
            epoch: record.epoch,
            node: record.node,
            node_identity: record.node_identity,
            post_member_set: Some(record.member_set),
            recovery_proof_bytes: record.recovery_proof_bytes.clone(),
        };
        let Some(proof) = recovery_proof_from_retired(&retired) else {
            return false;
        };
        if projection.agent != record.agent
            || projection.owner != record.owner
            || !recovery_position_matches_projection(projection, &proof)
            || record.member_set != proof.replacement_member_set.0
            || projection
                .applied_at
                .is_some_and(|applied_at| record.applied_at < applied_at)
        {
            return false;
        }
        projection.control_head = Some(record.control);
        projection.control_sequence = Some(record.control_sequence);
        projection.epoch = record.epoch;
        projection.members = proof.replacement_nodes.iter().map(|node| node.0).collect();
        projection.member_set = record.member_set;
        projection.reopened_runtime_state = Some(record.reopened_runtime_state);
        projection.stable_projection = Some(record.stable_projection);
        projection.applied_at = Some(record.applied_at);
        projection.application_invocation = Some(record.application_invocation);
        projection.application_ack = Some(record.application_ack);
        return true;
    }
    let expected_sequence = match projection.control_sequence {
        Some(sequence) => sequence.checked_add(1),
        None => Some(0),
    };
    let expected_previous = projection.control_head;
    let (members, member_set, valid_epoch) = match private_operation_kind(record.operation) {
        Some(AuthorityOperationKind::InvitePrivateNode) => {
            let Some((members, member_set)) =
                next_private_members(projection, record.operation, record.node)
            else {
                return false;
            };
            (members, member_set, record.epoch == projection.epoch)
        }
        Some(AuthorityOperationKind::RevokePrivateNode) => {
            let Some((members, member_set)) =
                next_private_members(projection, record.operation, record.node)
            else {
                return false;
            };
            (
                members,
                member_set,
                projection.epoch.checked_add(1) == Some(record.epoch),
            )
        }
        Some(AuthorityOperationKind::RotatePrivateKeys) => (
            projection.members.clone(),
            Hash(projection.member_set),
            projection.epoch.checked_add(1) == Some(record.epoch),
        ),
        Some(
            AuthorityOperationKind::SetPrivateResourcePolicy
            | AuthorityOperationKind::PrivateActorLifecycle,
        ) => (
            projection.members.clone(),
            Hash(projection.member_set),
            record.epoch == projection.epoch,
        ),
        Some(AuthorityOperationKind::RecoverPrivateAgent) | None => return false,
        Some(_) => return false,
    };
    if projection.agent != record.agent
        || projection.owner != record.owner
        || expected_sequence != Some(record.control_sequence)
        || expected_previous != record.control_previous
        || !valid_epoch
        || record.member_set != member_set.0
        || projection
            .applied_at
            .is_some_and(|applied_at| record.applied_at < applied_at)
    {
        return false;
    }
    projection.control_head = Some(record.control);
    projection.control_sequence = Some(record.control_sequence);
    projection.epoch = record.epoch;
    projection.members = members;
    projection.member_set = record.member_set;
    projection.reopened_runtime_state = Some(record.reopened_runtime_state);
    projection.stable_projection = Some(record.stable_projection);
    projection.applied_at = Some(record.applied_at);
    projection.application_invocation = Some(record.application_invocation);
    projection.application_ack = Some(record.application_ack);
    true
}

fn advance_operation_retirement_floor(state: &mut AuthorityLinearState) -> bool {
    loop {
        let Some(next) = state.operation_retirement_floor.checked_add(1) else {
            return state.operation_retirement_floor == state.authorization_sequence;
        };
        if next > state.authorization_sequence {
            return true;
        }
        // Pending ACC3/MAP2 or the credential-bounded latest MAA2 row proves
        // that this shared authorization position contains no AOC material.
        // A credential cannot advance again while its completed management
        // position remains ahead of this floor, so this pass-through set is
        // bounded by the credential table rather than operation history.
        if state
            .retries
            .iter()
            .any(|record| record.authorization_sequence == next)
            || state
                .latest_management_acks
                .iter()
                .any(|record| record.authorization_sequence == next)
        {
            state.operation_retirement_floor = next;
            continue;
        }
        let Some(index) = state
            .operation_retries
            .iter()
            .position(|record| record.authorization_sequence == next)
        else {
            return false;
        };
        let record = &state.operation_retries[index];
        let Some(issuance_ack) = record.issuance_ack else {
            return true;
        };
        let Some(issued_at) = record.issued_at else {
            return false;
        };
        let Ok(call) = AuthorityOperationCall::decode(&record.operation_call_bytes) else {
            return false;
        };
        let Some(issuance_ack_bytes) = record.issuance_ack_bytes.clone() else {
            return false;
        };
        let latest = LatestOperationAckRow {
            credential: record.credential,
            request_sequence: record.request_sequence,
            invocation_payload: record.invocation_payload,
            authorization_invocation: record.invocation,
            acknowledgement_invocation: record.acknowledgement_invocation,
            authorization_sequence: record.authorization_sequence,
            operation_call: record.operation_call,
            approval: record.approval_commitment,
            issuance_ack,
            issuance_ack_bytes,
            issued_at,
            private_application_invocation: record.private_application_invocation,
            private_operation: retained_private_operation(&call),
        };
        // The durable floor is advanced before the retireable AOC5/AOP5
        // buffers are removed. Actor state commits atomically, while this
        // ordering preserves the protocol's reopen rule explicitly.
        state.operation_retirement_floor = next;
        match state
            .latest_operation_acks
            .binary_search_by(|row| row.credential.cmp(&latest.credential))
        {
            Ok(latest_index) => {
                let previous = &state.latest_operation_acks[latest_index];
                if previous.request_sequence.checked_add(1) != Some(latest.request_sequence)
                    || (previous.private_operation.is_some()
                        && !private_operation_source_is_resolved(
                            state,
                            previous.authorization_invocation,
                            previous.acknowledgement_invocation,
                            previous.authorization_sequence,
                        ))
                {
                    return false;
                }
                state.latest_operation_acks[latest_index] = latest;
            }
            Err(latest_index) => {
                if latest.request_sequence != 1 {
                    return false;
                }
                state.latest_operation_acks.insert(latest_index, latest);
            }
        }
        state.operation_retries.remove(index);
    }
}

enum ApplicationPlan {
    None,
    Create {
        index: usize,
        row: ManagedAgentRow,
        private: Option<(usize, PrivateAgentProjectionRow)>,
    },
    ChangeReplicas {
        index: usize,
        replicas: Vec<ManagedReplicaRow>,
        generation: [u8; 32],
    },
    InstallActor {
        index: usize,
        row: ManagedActorRow,
    },
    ReplaceActor {
        index: usize,
        row: ManagedActorRow,
    },
    RemoveActor {
        index: usize,
        retired_index: usize,
        retired: RetiredActorInstallationRow,
    },
    UpgradeRuntime {
        index: usize,
        private_index: Option<usize>,
        to_deployment: [u8; 32],
        to_program: [u8; 32],
        producer: [u8; 32],
        package: AuthorityBlobRow,
        contract: RuntimeContractRow,
        capabilities: RuntimeCapabilitiesRow,
    },
}

fn application_plan(
    configuration: &SystemAuthorityConfiguration,
    state: &AuthorityLinearState,
    effect: &PendingManagementEffect,
    call: &AuthorityCredentialCall,
    acknowledgement: &ManagementApplicationAck,
) -> Option<ApplicationPlan> {
    if reconstruction_effect(configuration, state, call).as_ref() != Some(effect) {
        return None;
    }
    match effect {
        PendingManagementEffect::None => Some(ApplicationPlan::None),
        PendingManagementEffect::Create(row) => {
            if state.managed_agents.len() >= MAX_MANAGED_AGENTS
                || row.authority != configuration.binding
                || state
                    .roles
                    .binary_search_by(|role| role.principal.cmp(&row.owner))
                    .is_err()
            {
                return None;
            }
            let index = state
                .managed_agents
                .binary_search_by(|existing| existing.agent.cmp(&row.agent))
                .err()?;
            let ManagementAuthorizationPlan::Create {
                descriptor,
                replicas,
                descriptor_commitment,
            } = &call.plan
            else {
                return None;
            };
            let descriptor = reconstructed_create_descriptor(
                state,
                descriptor,
                replicas,
                *descriptor_commitment,
            )?;
            if acknowledgement.application != ManagementReply::Created(descriptor.identity.clone())
            {
                return None;
            }
            let private = if descriptor.identity.profile == AgentProfile::Private {
                let members = descriptor
                    .replicas
                    .iter()
                    .map(|replica| replica.node.0)
                    .collect::<Vec<_>>();
                let member_set = member_set_commitment(&members)?;
                let private_index = state
                    .private_agents
                    .binary_search_by(|existing| existing.agent.cmp(&row.agent))
                    .err()?;
                Some((
                    private_index,
                    PrivateAgentProjectionRow {
                        agent: row.agent,
                        owner: row.owner,
                        runtime_deployment: row.runtime_deployment,
                        genesis_members: members.clone(),
                        genesis_member_set: member_set.0,
                        control_head: None,
                        control_sequence: None,
                        epoch: 0,
                        members,
                        member_set: member_set.0,
                        reopened_runtime_state: None,
                        stable_projection: None,
                        applied_at: None,
                        application_invocation: None,
                        application_ack: None,
                        application_ack_bytes: None,
                    },
                ))
            } else {
                None
            };
            Some(ApplicationPlan::Create {
                index,
                row: row.clone(),
                private,
            })
        }
        PendingManagementEffect::ChangeReplicas {
            agent,
            from_generation,
            to_generation,
            replicas,
        } => {
            let ManagementAuthorizationPlan::ChangeReplicas {
                expected_generation,
                replicas: slots,
                replica_roster_commitment,
            } = &call.plan
            else {
                return None;
            };
            let requested = reconstructed_replica_roster(state, slots, *replica_roster_commitment)?;
            let index = managed_agent(state, call.managed.agent).ok()?;
            let row = &state.managed_agents[index];
            if row.agent != *agent
                || row.replica_generation != *from_generation
                || expected_generation.0 != *from_generation
                || managed_replica_rows(&requested) != *replicas
                || acknowledgement.application
                    != (ManagementReply::ReplicasChanged {
                        generation: Hash(*to_generation),
                    })
            {
                return None;
            }
            Some(ApplicationPlan::ChangeReplicas {
                index,
                replicas: replicas.clone(),
                generation: *to_generation,
            })
        }
        PendingManagementEffect::InstallActor { .. } => {
            let ManagementAuthorizationPlan::Install(install) = &call.plan else {
                return None;
            };
            let root_provenance = call.managed.agent.0 == configuration.system_agent
                && acknowledgement.authorization_sequence.get()
                    == configuration
                        .bootstrap_authorization_high_water
                        .checked_add(1)?;
            let row = installed_actor_row(
                call.managed.agent,
                install,
                install.lineage_commitment(),
                root_provenance,
            );
            if acknowledgement.application != ManagementReply::Installed(install.entry.clone()) {
                return None;
            }
            let index = managed_actor(state, call.managed.agent, install.entry.actor).err()?;
            Some(ApplicationPlan::InstallActor { index, row })
        }
        PendingManagementEffect::UpgradeActor { .. } => {
            let ManagementAuthorizationPlan::UpgradeActor(upgrade) = &call.plan else {
                return None;
            };
            let index = managed_actor(state, call.managed.agent, upgrade.actor).ok()?;
            let row = upgraded_actor_row(&state.managed_actors[index], upgrade)?;
            if acknowledgement.application != ManagementReply::Upgraded(managed_actor_entry(&row)?)
            {
                return None;
            }
            Some(ApplicationPlan::ReplaceActor { index, row })
        }
        PendingManagementEffect::SetActorSuspended { suspended, .. } => {
            let (actor, expected_deployment, requested_suspended) = match &call.plan {
                ManagementAuthorizationPlan::Suspend {
                    actor,
                    expected_deployment,
                } => (*actor, *expected_deployment, true),
                ManagementAuthorizationPlan::Resume {
                    actor,
                    expected_deployment,
                } => (*actor, *expected_deployment, false),
                _ => return None,
            };
            if requested_suspended != *suspended {
                return None;
            }
            let index = managed_actor(state, call.managed.agent, actor).ok()?;
            let mut row = state.managed_actors[index].clone();
            if row.deployment != expected_deployment.0 || row.suspended == *suspended {
                return None;
            }
            row.suspended = *suspended;
            let expected_application = if *suspended {
                ManagementReply::Suspended(managed_actor_entry(&row)?)
            } else {
                ManagementReply::Resumed(managed_actor_entry(&row)?)
            };
            if acknowledgement.application != expected_application {
                return None;
            }
            Some(ApplicationPlan::ReplaceActor { index, row })
        }
        PendingManagementEffect::RemoveActor { .. } => {
            let ManagementAuthorizationPlan::RemoveLeaf {
                actor,
                expected_deployment,
            } = &call.plan
            else {
                return None;
            };
            let index = managed_actor(state, call.managed.agent, *actor).ok()?;
            let row = &state.managed_actors[index];
            if row.deployment != expected_deployment.0
                || state.retired_actor_installations.len() >= MAX_RETIRED_ACTOR_INSTALLATIONS
                || acknowledgement.application != ManagementReply::Removed(*actor)
            {
                return None;
            }
            let retired = RetiredActorInstallationRow {
                agent: call.managed.agent.0,
                installation_id: row.installation_id,
            };
            let retired_index = retired_actor_installation(
                state,
                call.managed.agent,
                vos::agent_sdk::InstallationId(row.installation_id),
            )
            .err()?;
            Some(ApplicationPlan::RemoveActor {
                index,
                retired_index,
                retired,
            })
        }
        PendingManagementEffect::UpgradeRuntime {
            agent,
            from_deployment,
            to_deployment,
            to_program,
            producer,
            package,
            contract,
            capabilities,
        } => {
            let index = state
                .managed_agents
                .binary_search_by(|row| row.agent.cmp(agent))
                .ok()?;
            let row = &state.managed_agents[index];
            if row.authority != configuration.binding
                || row.runtime_deployment != *from_deployment
                || *to_deployment == [0; 32]
                || *to_program == [0; 32]
                || *producer == [0; 32]
                || *producer == row.transition_producer
                || !authority_blob_is_valid(package, false)
                || contract.sdk().is_none()
                || capabilities.sdk().is_none()
            {
                return None;
            }
            let private_index = if row.profile == AgentProfile::Private as u8 {
                Some(
                    state
                        .private_agents
                        .binary_search_by(|private| private.agent.cmp(agent))
                        .ok()?,
                )
            } else {
                None
            };
            let mut upgraded = row.clone();
            upgraded.runtime_deployment = *to_deployment;
            upgraded.runtime_program = *to_program;
            upgraded.runtime_producer = *producer;
            upgraded.runtime_package = *package;
            upgraded.runtime_contract = *contract;
            upgraded.capabilities = capabilities.clone();
            if acknowledgement.application
                != ManagementReply::RuntimeUpgraded(managed_agent_identity(
                    configuration,
                    &upgraded,
                )?)
            {
                return None;
            }
            Some(ApplicationPlan::UpgradeRuntime {
                index,
                private_index,
                to_deployment: *to_deployment,
                to_program: *to_program,
                producer: *producer,
                package: *package,
                contract: *contract,
                capabilities: capabilities.clone(),
            })
        }
    }
}

fn apply_application_plan(state: &mut AuthorityLinearState, plan: ApplicationPlan) {
    match plan {
        ApplicationPlan::None => {}
        ApplicationPlan::Create {
            index,
            row,
            private,
        } => {
            state.managed_agents.insert(index, row);
            if let Some((private_index, private)) = private {
                state.private_agents.insert(private_index, private);
            }
        }
        ApplicationPlan::ChangeReplicas {
            index,
            replicas,
            generation,
        } => {
            state.managed_agents[index].replicas = replicas;
            state.managed_agents[index].replica_generation = generation;
        }
        ApplicationPlan::InstallActor { index, row } => state.managed_actors.insert(index, row),
        ApplicationPlan::ReplaceActor { index, row } => state.managed_actors[index] = row,
        ApplicationPlan::RemoveActor {
            index,
            retired_index,
            retired,
        } => {
            state.managed_actors.remove(index);
            state
                .retired_actor_installations
                .insert(retired_index, retired);
        }
        ApplicationPlan::UpgradeRuntime {
            index,
            private_index,
            to_deployment,
            to_program,
            producer,
            package,
            contract,
            capabilities,
        } => {
            let row = &mut state.managed_agents[index];
            row.runtime_deployment = to_deployment;
            row.runtime_program = to_program;
            row.runtime_producer = producer;
            row.runtime_package = package;
            row.runtime_contract = contract;
            row.capabilities = capabilities;
            if let Some(private_index) = private_index {
                state.private_agents[private_index].runtime_deployment = to_deployment;
            }
        }
    }
}

fn retry_record(
    state: &AuthorityLinearState,
    invocation: InvocationId,
) -> core::result::Result<usize, usize> {
    state
        .retries
        .binary_search_by(|record| record.invocation.cmp(&invocation.0))
}

fn operation_retry_record(
    state: &AuthorityLinearState,
    invocation: InvocationId,
) -> core::result::Result<usize, usize> {
    state
        .operation_retries
        .binary_search_by(|record| record.invocation.cmp(&invocation.0))
}

fn invocation_pair_is_available(
    state: &AuthorityLinearState,
    authorization: InvocationId,
    acknowledgement: InvocationId,
) -> bool {
    authorization != InvocationId::ZERO
        && acknowledgement != InvocationId::ZERO
        && authorization != acknowledgement
        && state.genesis_publications.iter().all(|record| {
            record.invocation != authorization.0 && record.invocation != acknowledgement.0
        })
        && state.retries.iter().all(|record| {
            record.invocation != authorization.0
                && record.invocation != acknowledgement.0
                && record.acknowledgement_invocation != authorization.0
                && record.acknowledgement_invocation != acknowledgement.0
        })
        && state.latest_management_acks.iter().all(|record| {
            record.authorization_invocation != authorization.0
                && record.authorization_invocation != acknowledgement.0
                && record.acknowledgement_invocation != authorization.0
                && record.acknowledgement_invocation != acknowledgement.0
        })
        && state.operation_retries.iter().all(|record| {
            record.invocation != authorization.0
                && record.invocation != acknowledgement.0
                && record.acknowledgement_invocation != authorization.0
                && record.acknowledgement_invocation != acknowledgement.0
                && record.private_application_invocation != Some(authorization.0)
                && record.private_application_invocation != Some(acknowledgement.0)
        })
        && state.latest_operation_acks.iter().all(|record| {
            record.authorization_invocation != authorization.0
                && record.authorization_invocation != acknowledgement.0
                && record.acknowledgement_invocation != authorization.0
                && record.acknowledgement_invocation != acknowledgement.0
                && record.private_application_invocation != Some(authorization.0)
                && record.private_application_invocation != Some(acknowledgement.0)
        })
        && state.admin_retries.iter().all(|record| {
            record.invocation != authorization.0 && record.invocation != acknowledgement.0
        })
        && state.private_applications.iter().all(|record| {
            record.authorization_invocation != authorization.0
                && record.authorization_invocation != acknowledgement.0
                && record.issuance_invocation != authorization.0
                && record.issuance_invocation != acknowledgement.0
                && record.application_invocation != authorization.0
                && record.application_invocation != acknowledgement.0
        })
        && state.private_application_retirements.iter().all(|record| {
            record.authorization_invocation != authorization.0
                && record.authorization_invocation != acknowledgement.0
                && record.issuance_invocation != authorization.0
                && record.issuance_invocation != acknowledgement.0
                && record.application_invocation != authorization.0
                && record.application_invocation != acknowledgement.0
        })
}

fn private_application_invocation_is_unreserved(
    state: &AuthorityLinearState,
    application: InvocationId,
) -> bool {
    application != InvocationId::ZERO
        && state
            .genesis_publications
            .iter()
            .all(|record| record.invocation != application.0)
        && state.retries.iter().all(|record| {
            record.invocation != application.0 && record.acknowledgement_invocation != application.0
        })
        && state.latest_management_acks.iter().all(|record| {
            record.authorization_invocation != application.0
                && record.acknowledgement_invocation != application.0
        })
        && state.operation_retries.iter().all(|record| {
            record.invocation != application.0
                && record.acknowledgement_invocation != application.0
                && record.private_application_invocation != Some(application.0)
        })
        && state.latest_operation_acks.iter().all(|record| {
            record.authorization_invocation != application.0
                && record.acknowledgement_invocation != application.0
                && record.private_application_invocation != Some(application.0)
        })
        && state
            .admin_retries
            .iter()
            .all(|record| record.invocation != application.0)
        && state.private_applications.iter().all(|record| {
            record.authorization_invocation != application.0
                && record.issuance_invocation != application.0
                && record.application_invocation != application.0
        })
        && state.private_application_retirements.iter().all(|record| {
            record.authorization_invocation != application.0
                && record.issuance_invocation != application.0
                && record.application_invocation != application.0
        })
}

fn authenticated_role(
    state: &AuthorityLinearState,
    call: &AuthorityCredentialCall,
) -> Option<BuiltinPrincipalRole> {
    authenticated_credential_role(
        state,
        call.principal,
        call.credential,
        &call.credential_public_key,
        call.authenticated_node,
    )
}

fn authenticated_operation_role(
    configuration: &SystemAuthorityConfiguration,
    state: &AuthorityLinearState,
    call: &AuthorityOperationCall,
) -> Option<BuiltinPrincipalRole> {
    let credential = state
        .credentials
        .binary_search_by(|row| row.credential.cmp(&call.credential.0))
        .ok()
        .map(|index| &state.credentials[index])?;
    if credential.principal != call.principal.0
        || credential.public_key != call.credential_public_key()
        || credential.status != CredentialStatus::Active
    {
        return None;
    }
    match call.authentication {
        AuthorityIngressAuthentication::ApiCredentialSignature { .. } => {
            if credential.kind != AuthorityCredentialKind::Api as u8
                || call.verify_api_with(&Ed25519CredentialVerifier).is_err()
            {
                return None;
            }
        }
        AuthorityIngressAuthentication::SshNodeAttestation { node, .. } => {
            if credential.kind != AuthorityCredentialKind::Ssh as u8 {
                return None;
            }
            let attester = enrolled_node(state, node)?;
            if attester.space != configuration.space
                || call
                    .verify_ssh_node_attestation_with(
                        &attester.transport_public_key,
                        &Ed25519CredentialVerifier,
                    )
                    .is_err()
            {
                return None;
            }
        }
    }
    state
        .roles
        .binary_search_by(|row| row.principal.cmp(&call.principal.0))
        .ok()
        .map(|index| state.roles[index].role)
}

/// Credential possession authenticates a principal without requiring a
/// transport Node. If a Node is present, it is additional bound evidence and
/// must be explicitly enrolled to the same principal. Admin calls retain
/// their separate mandatory-Node path in `authenticated_admin`.
fn authenticated_credential_role(
    state: &AuthorityLinearState,
    principal: PrincipalId,
    credential_id: CredentialId,
    credential_public_key: &[u8; 32],
    authenticated_node: Option<vos::agent_sdk::NodeId>,
) -> Option<BuiltinPrincipalRole> {
    let credential = state
        .credentials
        .binary_search_by(|row| row.credential.cmp(&credential_id.0))
        .ok()
        .map(|index| &state.credentials[index])?;
    if credential.principal != principal.0
        || credential.public_key != *credential_public_key
        || credential.status != CredentialStatus::Active
    {
        return None;
    }
    if let Some(node) = authenticated_node {
        if enrolled_node_owner(state, node) != Some(principal) {
            return None;
        }
    }
    state
        .roles
        .binary_search_by(|row| row.principal.cmp(&principal.0))
        .ok()
        .map(|index| state.roles[index].role)
}

/// Called only after certificate/role verification, inside the Admin candidate
/// and row transaction. Retain table capacity and duplicate refusal here so a
/// backend change cannot silently turn enrollment into replacement.
fn insert_enrolled_node(state: &mut AuthorityLinearState, enrollment: NodeEncryptionEnrollment) -> bool {
    state.nodes.insert_verified(&mut node_storage::rows(), &NodeOwnerRow::from_enrollment(enrollment))
}

fn remove_enrolled_node(state: &mut AuthorityLinearState, node: vos::agent_sdk::NodeId, owner: PrincipalId) -> bool {
    state.nodes.remove(&mut node_storage::rows(), node.0, owner.0)
}

/// Owner-only policy checks must not materialize transport certificates. This
/// lookup is the owner-index boundary for the row-backed table cutover.
fn enrolled_node_owner(
    state: &AuthorityLinearState,
    node: vos::agent_sdk::NodeId,
) -> Option<PrincipalId> {
    state.nodes.owner(node.0).map(PrincipalId)
}

/// Certificate consumers receive an owned row, never a reference whose
/// lifetime assumes the entire persistent table is an inline vector.
fn enrolled_node(
    state: &AuthorityLinearState,
    node: vos::agent_sdk::NodeId,
) -> Option<NodeOwnerRow> {
    state.nodes.get(&node_storage::rows(), node.0)
}

fn enrolled_private_identity(
    state: &AuthorityLinearState,
    node: vos::agent_sdk::NodeId,
    owner: PrincipalId,
) -> Option<PrivateNodeIdentity> {
    let row = enrolled_node(state, node)?;
    if row.owner != owner.0 {
        return None;
    }
    let enrollment = row.enrollment();
    let identity = enrollment.verified_private_identity(&Ed25519CredentialVerifier)?;
    identity.matches_enrollment(&enrollment).then_some(identity)
}

fn enrolled_private_identity_commitment(
    state: &AuthorityLinearState,
    node: vos::agent_sdk::NodeId,
    owner: PrincipalId,
) -> Option<Hash> {
    let identity = enrolled_private_identity(state, node, owner)?;
    Some(vos::agent_sdk::wire::authority_private_node_identity_commitment(&identity))
}

fn replicas_are_enrolled(state: &AuthorityLinearState, replicas: &[AgentReplica]) -> bool {
    replicas.iter().all(|replica| {
        enrolled_node_owner(state, replica.node) == Some(replica.principal)
    })
}

fn enrolled_replicas_for_slots(
    state: &AuthorityLinearState,
    slots: &[CompactReplicaSlot],
) -> Option<Vec<AgentReplica>> {
    slots
        .iter()
        .map(|slot| {
            let principal = enrolled_node_owner(state, slot.node)?;
            Some(AgentReplica {
                node: slot.node,
                principal,
                role: slot.role,
            })
        })
        .collect()
}

fn reconstructed_create_descriptor(
    state: &AuthorityLinearState,
    descriptor: &CompactAgentDescriptor,
    slots: &[CompactReplicaSlot],
    descriptor_commitment: Hash,
) -> Option<vos::agent_sdk::AgentDescriptor> {
    let descriptor = descriptor.with_replicas(enrolled_replicas_for_slots(state, slots)?);
    (descriptor.validate().is_ok()
        && descriptor.commitment() == descriptor_commitment
        && descriptor_replicas_are_enrolled(state, &descriptor))
    .then_some(descriptor)
}

fn reconstructed_replica_roster(
    state: &AuthorityLinearState,
    slots: &[CompactReplicaSlot],
    roster_commitment: Hash,
) -> Option<Vec<AgentReplica>> {
    let replicas = enrolled_replicas_for_slots(state, slots)?;
    (replica_roster_commitment(&replicas) == roster_commitment).then_some(replicas)
}

fn descriptor_replicas_are_enrolled(
    state: &AuthorityLinearState,
    descriptor: &vos::agent_sdk::AgentDescriptor,
) -> bool {
    replicas_are_enrolled(state, &descriptor.replicas)
        && (descriptor.identity.profile != AgentProfile::Private
            || descriptor
                .replicas
                .iter()
                .all(|replica| replica.principal == descriptor.identity.owner))
}

fn managed_agent_row_from_descriptor(
    configuration: &SystemAuthorityConfiguration,
    descriptor: &vos::agent_sdk::AgentDescriptor,
) -> Option<ManagedAgentRow> {
    let mut row = ManagedAgentRow {
        agent: descriptor.identity.agent.0,
        owner: descriptor.identity.owner.0,
        profile: descriptor.identity.profile as u8,
        runtime_deployment: descriptor.identity.runtime_deployment.0,
        runtime_program: descriptor.identity.runtime_program.0,
        runtime_producer: descriptor.identity.runtime_producer.0,
        transition_producer: descriptor.identity.transition_producer.0,
        authority: configuration.binding,
        creation_nonce: descriptor.creation_nonce.0,
        private_recovery: descriptor
            .private_recovery
            .map(PrivateRecoveryBindingRow::from_sdk),
        runtime_package: authority_blob(&descriptor.runtime_package),
        runtime_contract: RuntimeContractRow::from_sdk(descriptor.runtime_contract),
        capabilities: RuntimeCapabilitiesRow::from_sdk(descriptor.capabilities),
        replicas: managed_replica_rows(&descriptor.replicas),
        replica_generation: [0; 32],
    };
    row.replica_generation = managed_replica_generation(configuration, &row)?.0;
    Some(row)
}

fn replica_change_effect(
    configuration: &SystemAuthorityConfiguration,
    state: &AuthorityLinearState,
    row: &ManagedAgentRow,
    expected_generation: Hash,
    replicas: &[AgentReplica],
) -> Option<PendingManagementEffect> {
    if row.profile != AgentProfile::Shared as u8
        || expected_generation.0 != row.replica_generation
        || !replicas_are_enrolled(state, replicas)
    {
        return None;
    }
    let projected = managed_replica_rows(replicas);
    let mut updated = row.clone();
    updated.replicas.clone_from(&projected);
    let to_generation = managed_replica_generation(configuration, &updated)?.0;
    (to_generation != row.replica_generation).then_some(PendingManagementEffect::ChangeReplicas {
        agent: row.agent,
        from_generation: row.replica_generation,
        to_generation,
        replicas: projected,
    })
}

fn policy_effect(
    configuration: &SystemAuthorityConfiguration,
    state: &AuthorityLinearState,
    call: &AuthorityCredentialCall,
    role: BuiltinPrincipalRole,
) -> Option<PendingManagementEffect> {
    match &call.plan {
        ManagementAuthorizationPlan::Create {
            descriptor,
            replicas,
            descriptor_commitment,
        } => {
            let descriptor = reconstructed_create_descriptor(
                state,
                descriptor,
                replicas,
                *descriptor_commitment,
            )?;
            if descriptor.authority != configuration.binding.sdk()
                || !profile_allowed(role, descriptor.identity.profile)
                || (role != BuiltinPrincipalRole::Admin
                    && descriptor.identity.owner != call.principal)
                || state
                    .roles
                    .binary_search_by(|row| row.principal.cmp(&descriptor.identity.owner.0))
                    .is_err()
                || managed_agent(state, call.managed.agent).is_ok()
                || pending_create_exists(state, call.managed.agent)
                || live_and_pending_agent_count(state) >= MAX_MANAGED_AGENTS
            {
                return None;
            }
            Some(PendingManagementEffect::Create(
                managed_agent_row_from_descriptor(configuration, &descriptor)?,
            ))
        }
        ManagementAuthorizationPlan::Install(_)
        | ManagementAuthorizationPlan::UpgradeActor(_)
        | ManagementAuthorizationPlan::Suspend { .. }
        | ManagementAuthorizationPlan::Resume { .. }
        | ManagementAuthorizationPlan::RemoveLeaf { .. } => {
            lifecycle_owner(configuration, state, call, role)?;
            if pending_runtime_transition_conflicts(state, call)
                || pending_actor_effect_conflicts(state, call)
            {
                return None;
            }
            projected_actor_effect(configuration, state, call)
        }
        ManagementAuthorizationPlan::ChangeReplicas {
            expected_generation,
            replicas: slots,
            replica_roster_commitment,
        } => {
            let row = lifecycle_owner(configuration, state, call, role)?;
            if pending_runtime_transition_conflicts(state, call)
                || pending_replica_transition_conflicts(state, call)
            {
                return None;
            }
            let replicas = reconstructed_replica_roster(state, slots, *replica_roster_commitment)?;
            replica_change_effect(configuration, state, row, *expected_generation, &replicas)
        }
        ManagementAuthorizationPlan::UpgradeRuntime(upgrade) => {
            let row = lifecycle_owner(configuration, state, call, role)?;
            if upgrade.producer.0 == row.transition_producer
                || pending_runtime_transition_conflicts(state, call)
                || state.managed_actors.iter().any(|actor| {
                    actor.agent == row.agent
                        && managed_actor_projection(actor).is_none_or(|projection| {
                            !upgrade.contract.supports(projection.contract)
                                || !upgrade.capabilities.satisfies(projection.requirements)
                        })
                })
            {
                return None;
            }
            Some(PendingManagementEffect::UpgradeRuntime {
                agent: row.agent,
                from_deployment: row.runtime_deployment,
                to_deployment: upgrade.to_deployment.0,
                to_program: upgrade.to_program.0,
                producer: upgrade.producer.0,
                package: authority_blob(&upgrade.package),
                contract: RuntimeContractRow::from_sdk(upgrade.contract),
                capabilities: RuntimeCapabilitiesRow::from_sdk(upgrade.capabilities),
            })
        }
    }
}

fn operation_policy_allows(
    configuration: &SystemAuthorityConfiguration,
    state: &AuthorityLinearState,
    call: &AuthorityOperationCall,
    role: BuiltinPrincipalRole,
) -> bool {
    let target = call.intent.managed();
    let Ok(managed_index) = managed_agent(state, target.agent) else {
        return false;
    };
    let managed = &state.managed_agents[managed_index];
    if target.space != SpaceId(configuration.space)
        || target.owner != PrincipalId(managed.owner)
        || target.profile as u8 != managed.profile
        || managed.runtime_deployment != target.runtime_deployment.0
        || target.transition_producer != ProducerId(managed.transition_producer)
        || managed.authority != configuration.binding
    {
        return false;
    }

    match &call.intent {
        AuthorityOperationIntent::InvokeActor {
            actor,
            actor_deployment,
            origin,
            roles,
            ..
        } => {
            if origin.actor.is_some() {
                return false;
            }
            let exact_claim_is_granted = match (origin.capability, roles.space, roles.actor) {
                (None, None, None) => true,
                (Some(capability), None, None) => capability_grant(
                    state,
                    call.principal,
                    target.agent,
                    *actor,
                    *actor_deployment,
                    capability,
                )
                .is_ok(),
                (None, Some(role), None) => space_role_grant(state, call.principal, role).is_ok(),
                (None, None, Some(role)) => actor_role_grant(
                    state,
                    call.principal,
                    target.agent,
                    *actor,
                    *actor_deployment,
                    role,
                )
                .is_ok(),
                _ => false,
            };
            exact_claim_is_granted
                && managed_actor(state, target.agent, *actor)
                    .ok()
                    .is_some_and(|index| {
                        let row = &state.managed_actors[index];
                        row.deployment == actor_deployment.0 && !row.suspended
                    })
        }
        AuthorityOperationIntent::Catalog {
            catalog,
            publication,
            ..
        } => {
            if role != BuiltinPrincipalRole::Admin && managed.owner != call.principal.0 {
                return false;
            }
            let Ok(catalog_index) =
                managed_actor(state, AgentId(configuration.system_agent), catalog.actor)
            else {
                return false;
            };
            let catalog_row = &state.managed_actors[catalog_index];
            if !catalog_row.root_provenance
                || catalog_row.suspended
                || catalog_row.deployment != catalog.deployment.0
                || catalog_row.program != catalog.program.0
            {
                return false;
            }
            let Ok(publication_actor_index) = managed_actor(state, target.agent, publication.actor)
            else {
                return false;
            };
            let publication_actor = &state.managed_actors[publication_actor_index];
            publication.identity.space == SpaceId(configuration.space)
                && publication.identity.agent == AgentId(managed.agent)
                && publication.identity.owner == PrincipalId(managed.owner)
                && publication.identity.profile == AgentProfile::Shared
                && managed.profile == AgentProfile::Shared as u8
                && publication.identity.runtime_deployment
                    == DeploymentId(managed.runtime_deployment)
                && publication.identity.runtime_program == ProgramId(managed.runtime_program)
                && publication.identity.runtime_producer == ProducerId(managed.runtime_producer)
                && publication.identity.transition_producer
                    == ProducerId(managed.transition_producer)
                && publication_actor.deployment == publication.actor_deployment.0
                && publication_actor.program == publication.actor_program.0
                && publication_actor.package.hash == publication.actor_package.hash.0
                && publication_actor.package.len == publication.actor_package.len
                && !publication_actor.suspended
        }
        AuthorityOperationIntent::InvitePrivateNode {
            control_sequence,
            control_previous,
            epoch,
            node,
            node_identity,
            ..
        } => {
            let Ok(index) = private_agent(state, target.agent) else {
                return false;
            };
            let projection = &state.private_agents[index];
            managed.profile == AgentProfile::Private as u8
                && managed.owner == call.principal.0
                && projection.owner == managed.owner
                && projection.runtime_deployment == managed.runtime_deployment
                && enrolled_private_identity_commitment(state, *node, PrincipalId(managed.owner))
                    == Some(*node_identity)
                && private_application_resolution_count(state) < MAX_PRIVATE_APPLICATION_RECORDS
                && !outstanding_private_operation_exists(state, target.agent)
                && private_control_position_is_next(
                    projection,
                    *control_sequence,
                    *control_previous,
                )
                && *epoch == projection.epoch
                && next_private_members(
                    projection,
                    AuthorityOperationKind::InvitePrivateNode as u8,
                    Some(node.0),
                )
                .is_some()
        }
        AuthorityOperationIntent::RevokePrivateNode {
            control_sequence,
            control_previous,
            epoch,
            node,
            member_set,
            ..
        } => {
            let Ok(index) = private_agent(state, target.agent) else {
                return false;
            };
            let projection = &state.private_agents[index];
            let next_members = next_private_members(
                projection,
                AuthorityOperationKind::RevokePrivateNode as u8,
                Some(node.0),
            );
            managed.profile == AgentProfile::Private as u8
                && managed.owner == call.principal.0
                && projection.owner == managed.owner
                && projection.runtime_deployment == managed.runtime_deployment
                && private_application_resolution_count(state) < MAX_PRIVATE_APPLICATION_RECORDS
                && !outstanding_private_operation_exists(state, target.agent)
                && private_control_position_is_next(
                    projection,
                    *control_sequence,
                    *control_previous,
                )
                && projection.epoch.checked_add(1) == Some(*epoch)
                && next_members.is_some_and(|(_, expected)| expected == *member_set)
        }
        AuthorityOperationIntent::RotatePrivateKeys {
            control_sequence,
            control_previous,
            epoch,
            member_set,
            ..
        } => {
            let Ok(index) = private_agent(state, target.agent) else {
                return false;
            };
            let projection = &state.private_agents[index];
            managed.profile == AgentProfile::Private as u8
                && managed.owner == call.principal.0
                && projection.owner == managed.owner
                && projection.runtime_deployment == managed.runtime_deployment
                && private_application_resolution_count(state) < MAX_PRIVATE_APPLICATION_RECORDS
                && !outstanding_private_operation_exists(state, target.agent)
                && private_control_position_is_next(
                    projection,
                    *control_sequence,
                    *control_previous,
                )
                && projection.epoch.checked_add(1) == Some(*epoch)
                && *member_set == Hash(projection.member_set)
        }
        AuthorityOperationIntent::SetPrivateResourcePolicy {
            control_sequence,
            control_previous,
            ..
        }
        | AuthorityOperationIntent::PrivateActorLifecycle {
            control_sequence,
            control_previous,
            ..
        } => {
            let Ok(index) = private_agent(state, target.agent) else {
                return false;
            };
            let projection = &state.private_agents[index];
            managed.profile == AgentProfile::Private as u8
                && managed.owner == call.principal.0
                && projection.owner == managed.owner
                && projection.runtime_deployment == managed.runtime_deployment
                && private_application_resolution_count(state) < MAX_PRIVATE_APPLICATION_RECORDS
                && !outstanding_private_operation_exists(state, target.agent)
                && private_control_position_is_next(
                    projection,
                    *control_sequence,
                    *control_previous,
                )
        }
        AuthorityOperationIntent::RecoverPrivateAgent { proof } => {
            let Ok(index) = private_agent(state, target.agent) else {
                return false;
            };
            let projection = &state.private_agents[index];
            // Principal role is intentionally irrelevant here: only the exact
            // owner credential plus the descriptor-pinned recovery key can
            // authorize recovery. An Admin credential cannot substitute for
            // either proof.
            managed.owner == call.principal.0
                && projection.owner == managed.owner
                && projection.runtime_deployment == managed.runtime_deployment
                && private_application_resolution_count(state) < MAX_PRIVATE_APPLICATION_RECORDS
                && recovery_authorization_capacity_available(state)
                && !outstanding_private_operation_exists(state, target.agent)
                && recovery_proof_matches_managed_state(configuration, state, managed, proof)
                && recovery_position_matches_projection(projection, proof)
        }
    }
}

fn private_operation_source_is_applied(
    state: &AuthorityLinearState,
    authorization_invocation: [u8; 32],
    issuance_invocation: [u8; 32],
    authorization_sequence: u64,
) -> bool {
    state.private_applications.iter().any(|record| {
        record.authorization_invocation == authorization_invocation
            && record.issuance_invocation == issuance_invocation
            && record.authorization_sequence == authorization_sequence
    })
}

fn private_operation_source_is_retired(
    state: &AuthorityLinearState,
    authorization_invocation: [u8; 32],
    issuance_invocation: [u8; 32],
    authorization_sequence: u64,
) -> bool {
    state.private_application_retirements.iter().any(|record| {
        record.authorization_invocation == authorization_invocation
            && record.issuance_invocation == issuance_invocation
            && record.authorization_sequence == authorization_sequence
    })
}

fn private_operation_source_is_resolved(
    state: &AuthorityLinearState,
    authorization_invocation: [u8; 32],
    issuance_invocation: [u8; 32],
    authorization_sequence: u64,
) -> bool {
    private_operation_source_is_applied(
        state,
        authorization_invocation,
        issuance_invocation,
        authorization_sequence,
    ) || private_operation_source_is_retired(
        state,
        authorization_invocation,
        issuance_invocation,
        authorization_sequence,
    )
}

fn private_application_resolution_count(state: &AuthorityLinearState) -> usize {
    state
        .private_applications
        .len()
        .saturating_add(state.private_application_retirements.len())
}

fn outstanding_private_operation_exists(state: &AuthorityLinearState, agent: AgentId) -> bool {
    state.operation_retries.iter().any(|record| {
        AuthorityOperationCall::decode(&record.operation_call_bytes)
            .ok()
            .and_then(|call| retained_private_operation(&call))
            .is_some_and(|private| {
                private.agent == agent.0
                    && !private_operation_source_is_resolved(
                        state,
                        record.invocation,
                        record.acknowledgement_invocation,
                        record.authorization_sequence,
                    )
            })
    }) || state.latest_operation_acks.iter().any(|record| {
        record.private_operation.as_ref().is_some_and(|private| {
            private.agent == agent.0
                && !private_operation_source_is_resolved(
                    state,
                    record.authorization_invocation,
                    record.acknowledgement_invocation,
                    record.authorization_sequence,
                )
        })
    })
}

fn retained_recovery_application_count(state: &AuthorityLinearState) -> usize {
    let applied = completed_recovery_application_count(state);
    let active = state
        .operation_retries
        .iter()
        .filter(|record| {
            AuthorityOperationCall::decode(&record.operation_call_bytes)
                .ok()
                .and_then(|call| retained_private_operation(&call))
                .is_some_and(|private| {
                    private.operation == AuthorityOperationKind::RecoverPrivateAgent as u8
                        && !private_operation_source_is_resolved(
                            state,
                            record.invocation,
                            record.acknowledgement_invocation,
                            record.authorization_sequence,
                        )
                })
        })
        .count();
    let retired = state
        .latest_operation_acks
        .iter()
        .filter(|record| {
            record.private_operation.as_ref().is_some_and(|private| {
                private.operation == AuthorityOperationKind::RecoverPrivateAgent as u8
                    && !private_operation_source_is_resolved(
                        state,
                        record.authorization_invocation,
                        record.acknowledgement_invocation,
                        record.authorization_sequence,
                    )
            })
        })
        .count();
    applied.saturating_add(active).saturating_add(retired)
}

fn completed_recovery_application_count(state: &AuthorityLinearState) -> usize {
    let applied = state
        .private_applications
        .iter()
        .filter(|record| record.operation == AuthorityOperationKind::RecoverPrivateAgent as u8)
        .count();
    let retired = state
        .private_application_retirements
        .iter()
        .filter(|record| {
            record.private_operation.operation == AuthorityOperationKind::RecoverPrivateAgent as u8
        })
        .count();
    applied.saturating_add(retired)
}

fn recovery_authorization_capacity_available(state: &AuthorityLinearState) -> bool {
    retained_recovery_application_count(state) < MAX_PRIVATE_RECOVERY_APPLICATION_RECORDS
}

fn recovery_application_capacity_available(state: &AuthorityLinearState) -> bool {
    completed_recovery_application_count(state) < MAX_PRIVATE_RECOVERY_APPLICATION_RECORDS
}

fn profile_allowed(role: BuiltinPrincipalRole, profile: AgentProfile) -> bool {
    match role {
        BuiltinPrincipalRole::Member => profile == AgentProfile::Private,
        BuiltinPrincipalRole::Developer => {
            matches!(profile, AgentProfile::Private | AgentProfile::Local)
        }
        BuiltinPrincipalRole::Admin => true,
    }
}

fn lifecycle_owner<'a>(
    configuration: &SystemAuthorityConfiguration,
    state: &'a AuthorityLinearState,
    call: &AuthorityCredentialCall,
    role: BuiltinPrincipalRole,
) -> Option<&'a ManagedAgentRow> {
    let index = managed_agent(state, call.managed.agent).ok()?;
    let row = &state.managed_agents[index];
    if row.runtime_deployment != call.managed.runtime_deployment.0
        || row.owner != call.managed.owner.0
        || row.profile != call.managed.profile as u8
        || row.transition_producer != call.managed.transition_producer.0
        || row.authority != configuration.binding
        || (role != BuiltinPrincipalRole::Admin && row.owner != call.principal.0)
    {
        return None;
    }
    Some(row)
}

fn managed_agent(
    state: &AuthorityLinearState,
    agent: AgentId,
) -> core::result::Result<usize, usize> {
    state
        .managed_agents
        .binary_search_by(|row| row.agent.cmp(&agent.0))
}

fn private_agent(
    state: &AuthorityLinearState,
    agent: AgentId,
) -> core::result::Result<usize, usize> {
    state
        .private_agents
        .binary_search_by(|row| row.agent.cmp(&agent.0))
}

fn pending_create_exists(state: &AuthorityLinearState, agent: AgentId) -> bool {
    state.retries.iter().any(|record| {
        matches!(
            &record.effect,
            PendingManagementEffect::Create(row) if row.agent == agent.0
        )
    })
}

fn pending_replica_transition_conflicts(
    state: &AuthorityLinearState,
    call: &AuthorityCredentialCall,
) -> bool {
    state.retries.iter().any(|record| {
        record.invocation != call.invocation.0
            && matches!(
                &record.effect,
                PendingManagementEffect::ChangeReplicas {
                    agent: pending_agent,
                    ..
                } if *pending_agent == call.managed.agent.0
            )
    })
}

fn live_and_pending_agent_count(state: &AuthorityLinearState) -> usize {
    state.managed_agents.len()
        + state
            .retries
            .iter()
            .filter(|record| matches!(record.effect, PendingManagementEffect::Create(_)))
            .count()
}

fn managed_actor(
    state: &AuthorityLinearState,
    agent: AgentId,
    actor: ActorId,
) -> core::result::Result<usize, usize> {
    state.managed_actors.binary_search_by(|row| {
        row.agent
            .cmp(&agent.0)
            .then_with(|| row.actor.cmp(&actor.0))
    })
}

fn retired_actor_installation(
    state: &AuthorityLinearState,
    agent: AgentId,
    installation: vos::agent_sdk::InstallationId,
) -> core::result::Result<usize, usize> {
    state.retired_actor_installations.binary_search_by(|row| {
        row.agent
            .cmp(&agent.0)
            .then_with(|| row.installation_id.cmp(&installation.0))
    })
}

fn protected_authority_actor(configuration: &SystemAuthorityConfiguration, actor: ActorId) -> bool {
    actor.0 == configuration.binding.issuer.actor
}

fn actor_has_authorization_grants(
    state: &AuthorityLinearState,
    agent: AgentId,
    actor: ActorId,
) -> bool {
    state
        .actor_role_grants
        .iter()
        .any(|grant| grant.agent == agent.0 && grant.actor == actor.0)
        || state
            .capability_grants
            .iter()
            .any(|grant| grant.agent == agent.0 && grant.actor == actor.0)
}

fn pending_actor_effect_conflicts(
    state: &AuthorityLinearState,
    call: &AuthorityCredentialCall,
) -> bool {
    let (actor, installation, parent, disrupts_children) = match &call.plan {
        ManagementAuthorizationPlan::Install(install) => {
            if state.managed_actors.len()
                + state
                    .retries
                    .iter()
                    .filter(|record| {
                        record.invocation != call.invocation.0
                            && matches!(record.effect, PendingManagementEffect::InstallActor { .. })
                    })
                    .count()
                >= MAX_MANAGED_ACTORS
            {
                return true;
            }
            (
                install.entry.actor,
                Some(install.installation_id),
                install.entry.parent,
                false,
            )
        }
        ManagementAuthorizationPlan::UpgradeActor(upgrade) => (upgrade.actor, None, None, false),
        ManagementAuthorizationPlan::Suspend { actor, .. }
        | ManagementAuthorizationPlan::RemoveLeaf { actor, .. } => (*actor, None, None, true),
        ManagementAuthorizationPlan::Resume { actor, .. } => (*actor, None, None, false),
        _ => return false,
    };
    state.retries.iter().any(|record| {
        if record.invocation == call.invocation.0 {
            return false;
        }
        match &record.effect {
            PendingManagementEffect::InstallActor {
                agent,
                actor: pending_actor,
                parent: pending_parent,
                installation_id,
            } => {
                *pending_actor == actor.0
                    || (*agent == call.managed.agent.0
                        && (installation.is_some_and(|value| value.0 == *installation_id)
                            || (disrupts_children && *pending_parent == Some(actor.0))))
            }
            PendingManagementEffect::UpgradeActor {
                agent,
                actor: pending_actor,
                ..
            } => *agent == call.managed.agent.0 && *pending_actor == actor.0,
            PendingManagementEffect::SetActorSuspended {
                agent,
                actor: pending_actor,
                suspended,
                ..
            } => {
                *agent == call.managed.agent.0
                    && (*pending_actor == actor.0
                        || (*suspended && parent == Some(ActorId(*pending_actor))))
            }
            PendingManagementEffect::RemoveActor {
                agent,
                actor: pending_actor,
                ..
            } => {
                *agent == call.managed.agent.0
                    && (*pending_actor == actor.0 || parent == Some(ActorId(*pending_actor)))
            }
            _ => false,
        }
    })
}

fn pending_runtime_transition_conflicts(
    state: &AuthorityLinearState,
    call: &AuthorityCredentialCall,
) -> bool {
    let incoming_runtime_upgrade =
        matches!(&call.plan, ManagementAuthorizationPlan::UpgradeRuntime(_));
    state.retries.iter().any(|record| {
        if record.invocation == call.invocation.0 {
            return false;
        }
        if !incoming_runtime_upgrade {
            return matches!(
                &record.effect,
                PendingManagementEffect::UpgradeRuntime { agent, .. }
                    if *agent == call.managed.agent.0
            );
        }
        let pending_agent = match &record.effect {
            PendingManagementEffect::None => {
                let Ok(pending) = AuthorityCredentialCall::decode(&record.credential_call_bytes)
                else {
                    return true;
                };
                pending.managed.agent.0
            }
            PendingManagementEffect::Create(row) => row.agent,
            PendingManagementEffect::ChangeReplicas { agent, .. }
            | PendingManagementEffect::InstallActor { agent, .. }
            | PendingManagementEffect::UpgradeActor { agent, .. }
            | PendingManagementEffect::SetActorSuspended { agent, .. }
            | PendingManagementEffect::RemoveActor { agent, .. }
            | PendingManagementEffect::UpgradeRuntime { agent, .. } => *agent,
        };
        pending_agent == call.managed.agent.0
    })
}

fn projected_actor_effect(
    configuration: &SystemAuthorityConfiguration,
    state: &AuthorityLinearState,
    call: &AuthorityCredentialCall,
) -> Option<PendingManagementEffect> {
    let agent = call.managed.agent;
    let managed = &state.managed_agents[managed_agent(state, agent).ok()?];
    let profile = agent_profile(managed.profile)?;
    let runtime_contract = managed.runtime_contract.sdk()?;
    let runtime_capabilities = managed.capabilities.sdk()?;
    match &call.plan {
        ManagementAuthorizationPlan::Install(install) => {
            if protected_authority_actor(configuration, install.entry.actor)
                || install.entry.suspended
                || install.entry.validate_for_profile(profile).is_err()
                || !install.requirements.supported_by(profile)
                || !runtime_contract.supports(install.contract)
                || !runtime_capabilities.satisfies(install.requirements)
                || state.managed_actors.len() >= MAX_MANAGED_ACTORS
                || state
                    .managed_actors
                    .iter()
                    .any(|row| row.actor == install.entry.actor.0)
                || state.managed_actors.iter().any(|row| {
                    row.agent == agent.0 && row.installation_id == install.installation_id.0
                })
                || retired_actor_installation(state, agent, install.installation_id).is_ok()
            {
                return None;
            }
            let expected_actor = match install.entry.parent {
                Some(parent) => {
                    let parent_index = managed_actor(state, agent, parent).ok()?;
                    if state.managed_actors[parent_index].suspended {
                        return None;
                    }
                    ActorId::owned_child(parent, &install.entry.name)
                }
                None => ActorId::top_level(agent, &install.entry.name),
            };
            if expected_actor != install.entry.actor {
                return None;
            }
            Some(PendingManagementEffect::InstallActor {
                agent: agent.0,
                actor: install.entry.actor.0,
                parent: install.entry.parent.map(|parent| parent.0),
                installation_id: install.installation_id.0,
            })
        }
        ManagementAuthorizationPlan::UpgradeActor(upgrade) => {
            if protected_authority_actor(configuration, upgrade.actor)
                || !upgrade.requirements.supported_by(profile)
                || !runtime_contract.supports(upgrade.contract)
                || !runtime_capabilities.satisfies(upgrade.requirements)
                || actor_has_authorization_grants(state, agent, upgrade.actor)
            {
                return None;
            }
            let row = &state.managed_actors[managed_actor(state, agent, upgrade.actor).ok()?];
            let proof_systems = upgrade
                .requirements
                .proof_systems
                .as_slice()
                .iter()
                .map(|system| system.0)
                .collect::<Vec<_>>();
            if row.deployment != upgrade.from_deployment.0
                || row.constructor_abi != upgrade.constructor_abi.0
                || row.state_layout != upgrade.state_layout.0
                || row.lanes != upgrade.requirements.lanes.bits()
                || row.scheduling != upgrade.requirements.scheduling
                || row.proof_systems != proof_systems
                || row.actor_abi != upgrade.contract.actor_abi
                || (row.lanes != 0 && row.program != upgrade.to_program.0)
            {
                return None;
            }
            Some(PendingManagementEffect::UpgradeActor {
                agent: agent.0,
                actor: upgrade.actor.0,
                from_deployment: upgrade.from_deployment.0,
                to_deployment: upgrade.to_deployment.0,
            })
        }
        ManagementAuthorizationPlan::Suspend {
            actor,
            expected_deployment,
        }
        | ManagementAuthorizationPlan::Resume {
            actor,
            expected_deployment,
        } => {
            if protected_authority_actor(configuration, *actor) {
                return None;
            }
            let row = &state.managed_actors[managed_actor(state, agent, *actor).ok()?];
            let suspended = matches!(&call.plan, ManagementAuthorizationPlan::Suspend { .. });
            if row.root_provenance
                || row.deployment != expected_deployment.0
                || row.suspended == suspended
            {
                return None;
            }
            Some(PendingManagementEffect::SetActorSuspended {
                agent: agent.0,
                actor: actor.0,
                deployment: expected_deployment.0,
                suspended,
            })
        }
        ManagementAuthorizationPlan::RemoveLeaf {
            actor,
            expected_deployment,
        } => {
            if protected_authority_actor(configuration, *actor)
                || state.retired_actor_installations.len() >= MAX_RETIRED_ACTOR_INSTALLATIONS
                || actor_has_authorization_grants(state, agent, *actor)
            {
                return None;
            }
            let row = &state.managed_actors[managed_actor(state, agent, *actor).ok()?];
            if row.root_provenance
                || row.deployment != expected_deployment.0
                || state.managed_actors.iter().any(|candidate| {
                    candidate.agent == agent.0 && candidate.parent == Some(actor.0)
                })
            {
                return None;
            }
            Some(PendingManagementEffect::RemoveActor {
                agent: agent.0,
                actor: actor.0,
                deployment: expected_deployment.0,
                installation_id: row.installation_id,
            })
        }
        _ => None,
    }
}

fn agent_profile(tag: u8) -> Option<AgentProfile> {
    match tag {
        value if value == AgentProfile::Local as u8 => Some(AgentProfile::Local),
        value if value == AgentProfile::Shared as u8 => Some(AgentProfile::Shared),
        value if value == AgentProfile::Private as u8 => Some(AgentProfile::Private),
        _ => None,
    }
}

fn authority_blob(reference: &vos::agent_sdk::BlobRef) -> AuthorityBlobRow {
    AuthorityBlobRow {
        hash: reference.hash.0,
        len: reference.len,
    }
}

fn authority_blob_sdk(row: AuthorityBlobRow) -> vos::agent_sdk::BlobRef {
    vos::agent_sdk::BlobRef {
        hash: Hash(row.hash),
        len: row.len,
    }
}

fn managed_agent_identity(
    configuration: &SystemAuthorityConfiguration,
    row: &ManagedAgentRow,
) -> Option<AgentIdentity> {
    Some(AgentIdentity {
        space: SpaceId(configuration.space),
        agent: AgentId(row.agent),
        owner: PrincipalId(row.owner),
        profile: agent_profile(row.profile)?,
        runtime_deployment: DeploymentId(row.runtime_deployment),
        runtime_program: ProgramId(row.runtime_program),
        runtime_producer: ProducerId(row.runtime_producer),
        transition_producer: ProducerId(row.transition_producer),
    })
}

fn managed_agent_projection(
    configuration: &SystemAuthorityConfiguration,
    row: &ManagedAgentRow,
) -> Option<AuthorityAgentProjection> {
    let projection = AuthorityAgentProjection {
        identity: managed_agent_identity(configuration, row)?,
        creation_nonce: Hash(row.creation_nonce),
        authority: row.authority.sdk(),
        private_recovery: row
            .private_recovery
            .and_then(PrivateRecoveryBindingRow::sdk),
        runtime_package: authority_blob_sdk(row.runtime_package),
        runtime_contract: row.runtime_contract.sdk()?,
        capabilities: row.capabilities.sdk()?,
        replica_count: row.replicas.len().try_into().ok()?,
        replica_generation: Hash(row.replica_generation),
    };
    projection.validate_shape().ok().map(|()| projection)
}

fn managed_actor_entry(row: &ManagedActorRow) -> Option<vos::agent_sdk::ActorEntry> {
    Some(vos::agent_sdk::ActorEntry {
        actor: ActorId(row.actor),
        name: row.name.clone(),
        parent: row.parent.map(ActorId),
        deployment: DeploymentId(row.deployment),
        program: ProgramId(row.program),
        package: vos::agent_sdk::BlobRef {
            hash: Hash(row.package.hash),
            len: row.package.len,
        },
        agent_schema: vos::agent_sdk::BlobRef {
            hash: Hash(row.agent_schema.hash),
            len: row.agent_schema.len,
        },
        method_policy: vos::agent_sdk::BlobRef {
            hash: Hash(row.method_policy.hash),
            len: row.method_policy.len,
        },
        constructor_abi: Hash(row.constructor_abi),
        installation_data: row
            .installation_data
            .as_ref()
            .map(|data| vos::agent_sdk::BlobRef {
                hash: Hash(data.hash),
                len: data.len,
            }),
        state_layout: Hash(row.state_layout),
        lanes: vos::agent_sdk::LaneSet::from_bits(row.lanes)?,
        suspended: row.suspended,
    })
}

fn managed_actor_projection(row: &ManagedActorRow) -> Option<AuthorityActorProjection> {
    let proof_systems = row
        .proof_systems
        .iter()
        .copied()
        .map(Hash)
        .collect::<Vec<_>>();
    let projection = AuthorityActorProjection {
        agent: AgentId(row.agent),
        entry: managed_actor_entry(row)?,
        producer: ProducerId(row.producer),
        contract: vos::agent_sdk::contract::ActorPackageContract {
            actor_abi: row.actor_abi,
        },
        requirements: RuntimeRequirements {
            lanes: vos::agent_sdk::LaneSet::from_bits(row.lanes)?,
            scheduling: row.scheduling,
            proof_systems: vos::agent_sdk::ProofSystemSet::from_sorted(&proof_systems).ok()?,
        },
        root_provenance: row.root_provenance,
        installation_id: vos::agent_sdk::InstallationId(row.installation_id),
        registry_reservation: Hash(row.registry_reservation),
        install_request: Hash(row.install_request),
    };
    projection.validate_shape().ok().map(|()| projection)
}

fn installed_actor_row(
    agent: AgentId,
    install: &CompactInstallActor,
    plan_commitment: Hash,
    root_provenance: bool,
) -> ManagedActorRow {
    ManagedActorRow {
        agent: agent.0,
        actor: install.entry.actor.0,
        name: install.entry.name.clone(),
        parent: install.entry.parent.map(|value| value.0),
        deployment: install.entry.deployment.0,
        program: install.entry.program.0,
        producer: install.producer.0,
        package: authority_blob(&install.entry.package),
        agent_schema: authority_blob(&install.entry.agent_schema),
        method_policy: authority_blob(&install.entry.method_policy),
        constructor_abi: install.entry.constructor_abi.0,
        installation_data: install.entry.installation_data.as_ref().map(authority_blob),
        state_layout: install.entry.state_layout.0,
        lanes: install.requirements.lanes.bits(),
        scheduling: install.requirements.scheduling,
        proof_systems: install
            .requirements
            .proof_systems
            .as_slice()
            .iter()
            .map(|system| system.0)
            .collect(),
        actor_abi: install.contract.actor_abi,
        root_provenance,
        suspended: false,
        installation_id: install.installation_id.0,
        registry_reservation: install.registry_reservation.0,
        install_request: plan_commitment.0,
    }
}

fn upgraded_actor_row(
    current: &ManagedActorRow,
    upgrade: &vos::agent_sdk::UpgradeActor,
) -> Option<ManagedActorRow> {
    let proof_systems = upgrade
        .requirements
        .proof_systems
        .as_slice()
        .iter()
        .map(|system| system.0)
        .collect::<Vec<_>>();
    if current.actor != upgrade.actor.0
        || current.deployment != upgrade.from_deployment.0
        || current.constructor_abi != upgrade.constructor_abi.0
        || current.state_layout != upgrade.state_layout.0
        || current.lanes != upgrade.requirements.lanes.bits()
        || current.scheduling != upgrade.requirements.scheduling
        || current.proof_systems != proof_systems
        || current.actor_abi != upgrade.contract.actor_abi
        || (current.lanes != 0 && current.program != upgrade.to_program.0)
    {
        return None;
    }
    let mut row = current.clone();
    row.deployment = upgrade.to_deployment.0;
    row.program = upgrade.to_program.0;
    row.producer = upgrade.producer.0;
    row.package = authority_blob(&upgrade.package);
    row.agent_schema = authority_blob(&upgrade.agent_schema);
    row.method_policy = authority_blob(&upgrade.method_policy);
    row.constructor_abi = upgrade.constructor_abi.0;
    row.state_layout = upgrade.state_layout.0;
    row.lanes = upgrade.requirements.lanes.bits();
    row.scheduling = upgrade.requirements.scheduling;
    row.proof_systems = proof_systems;
    row.actor_abi = upgrade.contract.actor_abi;
    Some(row)
}

fn actor_projection_is_valid(
    configuration: &SystemAuthorityConfiguration,
    state: &AuthorityLinearState,
) -> bool {
    if state.managed_actors.len() > MAX_MANAGED_ACTORS
        || state.retired_actor_installations.len() > MAX_RETIRED_ACTOR_INSTALLATIONS
        || state
            .managed_actors
            .iter()
            .filter(|row| row.root_provenance)
            .count()
            > 1
        || state
            .managed_actors
            .windows(2)
            .any(|pair| (pair[0].agent, pair[0].actor) >= (pair[1].agent, pair[1].actor))
        || state.retired_actor_installations.windows(2).any(|pair| {
            (pair[0].agent, pair[0].installation_id) >= (pair[1].agent, pair[1].installation_id)
        })
    {
        return false;
    }
    let mut actor_ids = state
        .managed_actors
        .iter()
        .map(|row| row.actor)
        .collect::<Vec<_>>();
    actor_ids.sort_unstable();
    if actor_ids.windows(2).any(|pair| pair[0] == pair[1]) {
        return false;
    }
    let mut installation_ids = state
        .managed_actors
        .iter()
        .map(|row| (row.agent, row.installation_id))
        .collect::<Vec<_>>();
    installation_ids.sort_unstable();
    if installation_ids.windows(2).any(|pair| pair[0] == pair[1]) {
        return false;
    }
    for row in &state.managed_actors {
        let Ok(agent_index) = managed_agent(state, AgentId(row.agent)) else {
            return false;
        };
        let managed = &state.managed_agents[agent_index];
        let Some(profile) = agent_profile(managed.profile) else {
            return false;
        };
        let Some(runtime_contract) = managed.runtime_contract.sdk() else {
            return false;
        };
        let Some(runtime_capabilities) = managed.capabilities.sdk() else {
            return false;
        };
        let Some(projection) = managed_actor_projection(row) else {
            return false;
        };
        let Some(lanes) = vos::agent_sdk::LaneSet::from_bits(row.lanes) else {
            return false;
        };
        let expected_actor = match row.parent {
            Some(parent) => {
                if managed_actor(state, AgentId(row.agent), ActorId(parent)).is_err() {
                    return false;
                }
                ActorId::owned_child(ActorId(parent), &row.name)
            }
            None => ActorId::top_level(AgentId(row.agent), &row.name),
        };
        if row.agent == [0; 32]
            || row.actor == [0; 32]
            || protected_authority_actor(configuration, ActorId(row.actor))
            || row.name.is_empty()
            || row.name.len() > vos::agent_sdk::MAX_ACTOR_NAME_BYTES
            || expected_actor.0 != row.actor
            || row.deployment == [0; 32]
            || row.program == [0; 32]
            || row.producer == [0; 32]
            || !authority_blob_is_valid(&row.package, false)
            || !authority_blob_is_valid(&row.agent_schema, false)
            || !authority_blob_is_valid(&row.method_policy, false)
            || row
                .installation_data
                .as_ref()
                .is_some_and(|blob| !authority_blob_is_valid(blob, true))
            || row.constructor_abi == [0; 32]
            || row.state_layout == [0; 32]
            || !lanes.supported_by(profile)
            || row.proof_systems.len() > vos::agent_sdk::proof_system::MAX_PROOF_SYSTEMS
            || row.proof_systems.iter().any(|system| *system == [0; 32])
            || row.proof_systems.windows(2).any(|pair| pair[0] >= pair[1])
            || row.actor_abi == 0
            || !runtime_contract.supports(projection.contract)
            || !runtime_capabilities.satisfies(projection.requirements)
            || (row.root_provenance && row.agent != configuration.system_agent)
            || row.installation_id == [0; 32]
            || row.registry_reservation == [0; 32]
            || row.install_request == [0; 32]
            || retired_actor_installation(
                state,
                AgentId(row.agent),
                vos::agent_sdk::InstallationId(row.installation_id),
            )
            .is_ok()
        {
            return false;
        }
    }
    state.retired_actor_installations.iter().all(|row| {
        row.agent != [0; 32]
            && row.installation_id != [0; 32]
            && managed_agent(state, AgentId(row.agent)).is_ok()
    })
}

fn authority_blob_is_valid(row: &AuthorityBlobRow, installation_data: bool) -> bool {
    row.hash != [0; 32]
        && if installation_data {
            row.len <= vos::agent_sdk::MAX_INSTALLATION_DATA_BYTES as u64
        } else {
            row.len != 0 && row.len <= vos::agent_sdk::MAX_CATALOG_ARTIFACT_BYTES
        }
}

fn node_owner_row_is_valid(
    configuration: &SystemAuthorityConfiguration,
    state: &AuthorityLinearState,
    row: &NodeOwnerRow,
) -> bool {
    let enrollment = row.enrollment();
    row.space == configuration.space
        && state
            .roles
            .binary_search_by(|role| role.principal.cmp(&row.owner))
            .is_ok()
        && enrollment.verify_with(&Ed25519CredentialVerifier)
        && valid_x25519_public_key(&row.encryption_public_key)
        && enrollment.commitment().0 == row.enrollment_commitment
}

fn managed_agent_projection_is_valid(
    configuration: &SystemAuthorityConfiguration,
    state: &AuthorityLinearState,
    row: &ManagedAgentRow,
) -> bool {
    let Some(profile) = agent_profile(row.profile) else {
        return false;
    };
    if row.agent == [0; 32]
        || row.owner == [0; 32]
        || row.creation_nonce == [0; 32]
        || AgentId::derive(
            SpaceId(configuration.space),
            PrincipalId(row.owner),
            &row.creation_nonce,
        )
        .0 != row.agent
        || row.runtime_deployment == [0; 32]
        || row.runtime_program == [0; 32]
        || row.runtime_producer == [0; 32]
        || row.transition_producer == [0; 32]
        || row.transition_producer == row.runtime_producer
        || row.authority != configuration.binding
        || match (profile, row.private_recovery) {
            (AgentProfile::Private, Some(binding)) => binding.sdk().is_none(),
            (AgentProfile::Private, None) | (_, Some(_)) => true,
            _ => false,
        }
        || !authority_blob_is_valid(&row.runtime_package, false)
        || row.runtime_contract.sdk().is_none()
        || row.capabilities.sdk().is_none()
        || row.replicas.is_empty()
        || row.replicas.len() > MAX_AGENT_REPLICAS
        || !row
            .replicas
            .windows(2)
            .all(|pair| pair[0].node < pair[1].node)
        || row.replicas.iter().any(|replica| {
            replica.node == [0; 32]
                || replica.principal == [0; 32]
                || replica.sdk().is_none()
                || enrolled_node_owner(state, vos::agent_sdk::NodeId(replica.node)).is_none_or(|owner| {
                    if row.agent == configuration.system_agent
                        && replica.node == configuration.bootstrap_node
                    {
                        // The founding operator owns and enrolls the Node,
                        // while the physical replica principal is bound to
                        // that Node's authenticated transport key.
                        owner.0 != configuration.bootstrap_principal
                            || replica.principal != configuration.bootstrap_replica_principal
                    } else {
                        owner.0 != replica.principal
                    }
                })
        })
        || state
            .roles
            .binary_search_by(|role| role.principal.cmp(&row.owner))
            .is_err()
        || managed_replica_generation(configuration, row).map(|value| value.0)
            != Some(row.replica_generation)
        || managed_agent_projection(configuration, row).is_none()
    {
        return false;
    }
    match profile {
        AgentProfile::Local => row.replicas.len() == 1,
        AgentProfile::Shared => row
            .replicas
            .iter()
            .any(|replica| replica.role == ReplicaRole::Voter as u8),
        AgentProfile::Private => row.replicas.iter().all(|replica| {
            replica.principal == row.owner && replica.role == ReplicaRole::Observer as u8
        }),
    }
}

fn authorization_grants_are_valid(
    configuration: &SystemAuthorityConfiguration,
    state: &AuthorityLinearState,
) -> bool {
    if authorization_grant_count(state) > MAX_AUTHORITY_AUTHORIZATION_GRANTS
        || state
            .space_role_grants
            .windows(2)
            .any(|pair| (pair[0].principal, pair[0].role) >= (pair[1].principal, pair[1].role))
        || state.actor_role_grants.windows(2).any(|pair| {
            (
                pair[0].principal,
                pair[0].agent,
                pair[0].actor,
                pair[0].deployment,
                pair[0].role,
            ) >= (
                pair[1].principal,
                pair[1].agent,
                pair[1].actor,
                pair[1].deployment,
                pair[1].role,
            )
        })
        || state.capability_grants.windows(2).any(|pair| {
            (
                pair[0].principal,
                pair[0].agent,
                pair[0].actor,
                pair[0].deployment,
                pair[0].capability,
            ) >= (
                pair[1].principal,
                pair[1].agent,
                pair[1].actor,
                pair[1].deployment,
                pair[1].capability,
            )
        })
    {
        return false;
    }
    for role in &state.roles {
        if principal_authorization_grant_count(state, PrincipalId(role.principal))
            > MAX_AUTHORITY_PRINCIPAL_GRANTS
        {
            return false;
        }
    }
    state.space_role_grants.iter().all(|grant| {
        grant.role != [0; 32]
            && state
                .roles
                .binary_search_by(|row| row.principal.cmp(&grant.principal))
                .is_ok()
    }) && state.actor_role_grants.iter().all(|grant| {
        grant.role != [0; 32]
            && state
                .roles
                .binary_search_by(|row| row.principal.cmp(&grant.principal))
                .is_ok()
            && !protected_authority_actor(configuration, ActorId(grant.actor))
            && managed_actor(state, AgentId(grant.agent), ActorId(grant.actor))
                .ok()
                .is_some_and(|index| state.managed_actors[index].deployment == grant.deployment)
    }) && state.capability_grants.iter().all(|grant| {
        grant.capability != [0; 32]
            && state
                .roles
                .binary_search_by(|row| row.principal.cmp(&grant.principal))
                .is_ok()
            && !protected_authority_actor(configuration, ActorId(grant.actor))
            && managed_actor(state, AgentId(grant.agent), ActorId(grant.actor))
                .ok()
                .is_some_and(|index| state.managed_actors[index].deployment == grant.deployment)
    })
}

fn narrowed_validity(call: &AuthorityCredentialCall, observed_slot: u64) -> Option<(u64, u64)> {
    narrowed_validity_window(
        call.requested_valid_from,
        call.requested_expires_at,
        observed_slot,
    )
}

fn narrowed_validity_window(
    requested_valid_from: u64,
    requested_expires_at: u64,
    observed_slot: u64,
) -> Option<(u64, u64)> {
    let horizon = observed_slot.saturating_add(MAX_APPROVAL_VALIDITY_SLOTS);
    let valid_from = max(requested_valid_from, observed_slot);
    let expires_at = min(requested_expires_at, horizon);
    (valid_from <= expires_at).then_some((valid_from, expires_at))
}

fn authority_target_matches(
    configuration: &SystemAuthorityConfiguration,
    target: &AuthorityActorTarget,
) -> bool {
    target.space == SpaceId(configuration.space)
        && target.system_agent == AgentId(configuration.system_agent)
        && target.system_runtime_deployment == DeploymentId(configuration.system_runtime_deployment)
        && target.binding == configuration.binding.sdk()
}

fn configured_authority_target(
    configuration: &SystemAuthorityConfiguration,
) -> AuthorityActorTarget {
    AuthorityActorTarget {
        space: SpaceId(configuration.space),
        system_agent: AgentId(configuration.system_agent),
        system_runtime_deployment: DeploymentId(configuration.system_runtime_deployment),
        binding: configuration.binding.sdk(),
    }
}

fn encode_optional_hash(bytes: &mut Vec<u8>, value: Option<[u8; 32]>) {
    if let Some(value) = value {
        bytes.push(1);
        bytes.extend_from_slice(&value);
    } else {
        bytes.push(0);
    }
}

fn encode_optional_bytes(bytes: &mut Vec<u8>, value: Option<&[u8]>) {
    if let Some(value) = value {
        bytes.push(1);
        bytes.extend_from_slice(&(value.len() as u64).to_le_bytes());
        bytes.extend_from_slice(value);
    } else {
        bytes.push(0);
    }
}

fn initial_private_application_commitment(configuration: SystemAuthorityConfiguration) -> Hash {
    Hash::digest(
        b"vos/system-authority/private-application-root/v5",
        &[RUNTIME_ABI_ID.as_bytes(), &configuration.encode()],
    )
}

fn private_application_commitment(previous: Hash, record: &PrivateApplicationRecord) -> Hash {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&record.credential);
    bytes.extend_from_slice(&record.request_sequence.to_le_bytes());
    bytes.extend_from_slice(&record.invocation_payload);
    bytes.extend_from_slice(&record.authorization_invocation);
    bytes.extend_from_slice(&record.issuance_invocation);
    bytes.extend_from_slice(&record.application_invocation);
    bytes.extend_from_slice(&record.authorization_sequence.to_le_bytes());
    bytes.extend_from_slice(&record.operation_call);
    bytes.extend_from_slice(&record.approval);
    bytes.extend_from_slice(&record.issuance_ack);
    bytes.extend_from_slice(&record.application_ack);
    bytes.extend_from_slice(&record.agent);
    bytes.extend_from_slice(&record.owner);
    bytes.extend_from_slice(&record.runtime_deployment);
    bytes.push(record.operation);
    bytes.extend_from_slice(&record.control);
    bytes.extend_from_slice(&record.control_sequence.to_le_bytes());
    encode_optional_hash(&mut bytes, record.control_previous);
    bytes.extend_from_slice(&record.epoch.to_le_bytes());
    encode_optional_hash(&mut bytes, record.node);
    encode_optional_hash(&mut bytes, record.node_identity);
    encode_optional_bytes(&mut bytes, record.recovery_proof_bytes.as_deref());
    bytes.extend_from_slice(&record.member_set);
    bytes.extend_from_slice(&record.reopened_runtime_state);
    bytes.extend_from_slice(&record.stable_projection);
    bytes.extend_from_slice(&record.issued_at.to_le_bytes());
    bytes.extend_from_slice(&record.applied_at.to_le_bytes());
    Hash::digest(
        b"vos/system-authority/private-application/v5",
        &[previous.as_bytes(), &bytes],
    )
}

fn private_application_chain_is_valid(
    configuration: &SystemAuthorityConfiguration,
    state: &AuthorityLinearState,
) -> bool {
    let mut commitment = initial_private_application_commitment(*configuration);
    for record in &state.private_applications {
        commitment = private_application_commitment(commitment, record);
    }
    commitment.0 == state.private_application_commitment
}

fn private_operation_kind(tag: u8) -> Option<AuthorityOperationKind> {
    match tag {
        value if value == AuthorityOperationKind::InvitePrivateNode as u8 => {
            Some(AuthorityOperationKind::InvitePrivateNode)
        }
        value if value == AuthorityOperationKind::RevokePrivateNode as u8 => {
            Some(AuthorityOperationKind::RevokePrivateNode)
        }
        value if value == AuthorityOperationKind::RecoverPrivateAgent as u8 => {
            Some(AuthorityOperationKind::RecoverPrivateAgent)
        }
        value if value == AuthorityOperationKind::RotatePrivateKeys as u8 => {
            Some(AuthorityOperationKind::RotatePrivateKeys)
        }
        value if value == AuthorityOperationKind::SetPrivateResourcePolicy as u8 => {
            Some(AuthorityOperationKind::SetPrivateResourcePolicy)
        }
        value if value == AuthorityOperationKind::PrivateActorLifecycle as u8 => {
            Some(AuthorityOperationKind::PrivateActorLifecycle)
        }
        _ => None,
    }
}

fn recovery_proof_from_retired(
    row: &RetiredPrivateOperationRow,
) -> Option<PrivateRecoveryAuthorityProof> {
    if row.operation != AuthorityOperationKind::RecoverPrivateAgent as u8
        || row.node.is_some()
        || row.node_identity.is_some()
    {
        return None;
    }
    let encoded = row.recovery_proof_bytes.as_deref()?;
    if encoded.is_empty() || encoded.len() > MAX_PRIVATE_RECOVERY_AUTHORITY_PROOF_WIRE_BYTES {
        return None;
    }
    let proof = PrivateRecoveryAuthorityProof::decode(encoded).ok()?;
    if proof.encode().ok().as_deref() != Some(encoded)
        || proof.verify_with(&Ed25519CredentialVerifier).is_err()
        || proof.managed.agent.0 != row.agent
        || proof.managed.runtime_deployment.0 != row.runtime_deployment
        || proof.control.0 != row.control
        || proof.control_sequence != row.control_sequence
        || proof.control_previous.map(|previous| previous.0) != row.control_previous
        || proof.next_epoch != row.epoch
        || Some(proof.replacement_member_set.0) != row.post_member_set
    {
        return None;
    }
    Some(proof)
}

fn enrolled_private_identity_set_commitment(
    state: &AuthorityLinearState,
    nodes: &[vos::agent_sdk::NodeId],
    owner: PrincipalId,
) -> Option<Hash> {
    let identities = nodes
        .iter()
        .copied()
        .map(|node| enrolled_private_identity(state, node, owner))
        .collect::<Option<Vec<_>>>()?;
    private_node_identity_set_commitment(identities.iter())
}

fn recovery_proof_matches_managed_state(
    configuration: &SystemAuthorityConfiguration,
    state: &AuthorityLinearState,
    managed: &ManagedAgentRow,
    proof: &PrivateRecoveryAuthorityProof,
) -> bool {
    managed.profile == AgentProfile::Private as u8
        && proof.managed.space == SpaceId(configuration.space)
        && proof.managed.agent == AgentId(managed.agent)
        && proof.managed.owner == PrincipalId(managed.owner)
        && proof.managed.profile == AgentProfile::Private
        && proof.managed.transition_producer == ProducerId(managed.transition_producer)
        && managed.private_recovery.is_some_and(|binding| {
            binding.signing_key_commitment
                == recovery_signing_public_key_commitment(&proof.recovery_public_key).0
        })
        && proof.verify_with(&Ed25519CredentialVerifier).is_ok()
        && enrolled_private_identity_set_commitment(
            state,
            &proof.replacement_nodes,
            PrincipalId(managed.owner),
        ) == Some(proof.replacement_identity_set)
}

fn retired_recovery_matches_managed_state(
    configuration: &SystemAuthorityConfiguration,
    state: &AuthorityLinearState,
    row: &RetiredPrivateOperationRow,
) -> bool {
    let Some(proof) = recovery_proof_from_retired(row) else {
        return false;
    };
    let Ok(managed_index) = managed_agent(state, AgentId(row.agent)) else {
        return false;
    };
    let managed = &state.managed_agents[managed_index];
    row.principal == managed.owner
        && recovery_proof_matches_managed_state(configuration, state, managed, &proof)
}

fn recovery_position_matches_projection(
    projection: &PrivateAgentProjectionRow,
    proof: &PrivateRecoveryAuthorityProof,
) -> bool {
    let sequence_advances = projection
        .control_sequence
        .is_none_or(|sequence| proof.control_sequence > sequence);
    proof.superseded_authority_head == projection.control_head.map(Hash)
        && sequence_advances
        && proof.next_epoch > projection.epoch
}

fn retained_recovery_source_is_valid(
    configuration: &SystemAuthorityConfiguration,
    state: &AuthorityLinearState,
    row: &RetiredPrivateOperationRow,
    authorization_invocation: [u8; 32],
    issuance_invocation: [u8; 32],
    authorization_sequence: u64,
) -> bool {
    if row.operation != AuthorityOperationKind::RecoverPrivateAgent as u8 {
        return true;
    }
    if private_operation_source_is_resolved(
        state,
        authorization_invocation,
        issuance_invocation,
        authorization_sequence,
    ) {
        return recovery_proof_from_retired(row).is_some();
    }
    if !retired_recovery_matches_managed_state(configuration, state, row) {
        return false;
    }
    let Some(proof) = recovery_proof_from_retired(row) else {
        return false;
    };
    private_agent(state, AgentId(row.agent)).is_ok_and(|index| {
        recovery_position_matches_projection(&state.private_agents[index], &proof)
    })
}

fn retired_private_operation_is_valid(row: &RetiredPrivateOperationRow) -> bool {
    let valid_position = match (row.control_sequence, row.control_previous) {
        (0, None) => true,
        (0, Some(_)) | (_, None) => false,
        (_, Some(previous)) => previous != [0; 32],
    };
    let valid_operation = if row.operation == AuthorityOperationKind::InvitePrivateNode as u8 {
        row.node.is_some_and(|node| node != [0; 32])
            && row
                .node_identity
                .is_some_and(|identity| identity != [0; 32])
            && row.post_member_set.is_none()
            && row.recovery_proof_bytes.is_none()
    } else if row.operation == AuthorityOperationKind::RevokePrivateNode as u8 {
        row.node.is_some_and(|node| node != [0; 32])
            && row.node_identity.is_none()
            && row
                .post_member_set
                .is_some_and(|member_set| member_set != [0; 32])
            && row.recovery_proof_bytes.is_none()
    } else if row.operation == AuthorityOperationKind::RecoverPrivateAgent as u8 {
        recovery_proof_from_retired(row).is_some()
    } else if row.operation == AuthorityOperationKind::RotatePrivateKeys as u8 {
        row.epoch != 0
            && row.node.is_none()
            && row.node_identity.is_none()
            && row
                .post_member_set
                .is_some_and(|member_set| member_set != [0; 32])
            && row.recovery_proof_bytes.is_none()
    } else if matches!(
        private_operation_kind(row.operation),
        Some(
            AuthorityOperationKind::SetPrivateResourcePolicy
                | AuthorityOperationKind::PrivateActorLifecycle
        )
    ) {
        row.epoch == 0
            && row.node.is_none()
            && row.node_identity.is_none()
            && row.post_member_set.is_none()
            && row.recovery_proof_bytes.is_none()
    } else {
        false
    };
    row.agent != [0; 32]
        && row.runtime_deployment != [0; 32]
        && row.principal != [0; 32]
        && row.control != [0; 32]
        && valid_position
        && valid_operation
}

fn private_application_fact(
    configuration: &SystemAuthorityConfiguration,
    state: &AuthorityLinearState,
    record: &PrivateApplicationRecord,
) -> Option<PrivateControlApplicationFact> {
    let row = &state.managed_agents[managed_agent(state, AgentId(record.agent)).ok()?];
    let identity = managed_agent_identity(configuration, row)?;
    if identity.space != SpaceId(configuration.space) || identity.owner.0 != record.owner {
        return None;
    }
    let fact = PrivateControlApplicationFact {
        managed: ManagedAgentTarget {
            space: identity.space,
            agent: identity.agent,
            owner: identity.owner,
            profile: identity.profile,
            runtime_deployment: DeploymentId(record.runtime_deployment),
            transition_producer: identity.transition_producer,
        },
        operation: private_operation_kind(record.operation)?,
        control: Hash(record.control),
        control_sequence: record.control_sequence,
        control_previous: record.control_previous.map(Hash),
        epoch: record.epoch,
        post_member_set: Hash(record.member_set),
        reopened_runtime_state: Hash(record.reopened_runtime_state),
        stable_projection: Hash(record.stable_projection),
        reopened_control_head: Hash(record.control),
        applied_at: record.applied_at,
    };
    fact.validate_shape().is_ok().then_some(fact)
}

fn private_application_record_source(
    configuration: &SystemAuthorityConfiguration,
    state: &AuthorityLinearState,
    record: &PrivateApplicationRecord,
) -> Option<PrivateApplicationSource> {
    let fact = private_application_fact(configuration, state, record)?;
    let request_sequence = NonZeroU64::new(record.request_sequence)?;
    let authorization_invocation = AuthorityOperationCall::derive_invocation(
        CredentialId(record.credential),
        request_sequence,
        Hash(record.invocation_payload),
    );
    let issuance_invocation =
        AuthorityOperationApproval::derive_acknowledgement_invocation_from_call_parts(
            CredentialId(record.credential),
            request_sequence,
            authorization_invocation,
            Hash(record.invocation_payload),
            Hash(record.operation_call),
        );
    let credential =
        &state.credentials[credential_index(state, CredentialId(record.credential)).ok()?];
    if credential.principal != record.owner
        || credential.operation_request_high_water < record.request_sequence
        || authorization_invocation.0 != record.authorization_invocation
        || issuance_invocation.0 != record.issuance_invocation
    {
        return None;
    }
    let private = RetiredPrivateOperationRow {
        agent: record.agent,
        runtime_deployment: record.runtime_deployment,
        principal: record.owner,
        operation: record.operation,
        control: record.control,
        control_sequence: record.control_sequence,
        control_previous: record.control_previous,
        epoch: if matches!(
            private_operation_kind(record.operation),
            Some(
                AuthorityOperationKind::SetPrivateResourcePolicy
                    | AuthorityOperationKind::PrivateActorLifecycle
            )
        ) {
            0
        } else {
            record.epoch
        },
        node: record.node,
        node_identity: record.node_identity,
        post_member_set: matches!(
            private_operation_kind(record.operation),
            Some(
                AuthorityOperationKind::RevokePrivateNode
                    | AuthorityOperationKind::RecoverPrivateAgent
                    | AuthorityOperationKind::RotatePrivateKeys
            )
        )
        .then_some(record.member_set),
        recovery_proof_bytes: record.recovery_proof_bytes.clone(),
    };
    if let Some(active) = state.operation_retries.iter().find(|source| {
        source.invocation == record.authorization_invocation
            && source.acknowledgement_invocation == record.issuance_invocation
    }) {
        let call = AuthorityOperationCall::decode(&active.operation_call_bytes).ok()?;
        if active.credential != record.credential
            || active.request_sequence != record.request_sequence
            || active.invocation_payload != record.invocation_payload
            || active.authorization_sequence != record.authorization_sequence
            || active.operation_call != record.operation_call
            || active.approval_commitment != record.approval
            || active.issuance_ack != Some(record.issuance_ack)
            || active.issued_at != Some(record.issued_at)
            || active.private_application_invocation != Some(record.application_invocation)
            || retained_private_operation(&call).as_ref() != Some(&private)
        {
            return None;
        }
    } else if let Some(latest) = state.latest_operation_acks.iter().find(|source| {
        source.authorization_invocation == record.authorization_invocation
            && source.acknowledgement_invocation == record.issuance_invocation
    }) && (latest.credential != record.credential
        || latest.request_sequence != record.request_sequence
        || latest.invocation_payload != record.invocation_payload
        || latest.authorization_sequence != record.authorization_sequence
        || latest.operation_call != record.operation_call
        || latest.approval != record.approval
        || latest.issuance_ack != record.issuance_ack
        || latest.issued_at != record.issued_at
        || latest.private_application_invocation != Some(record.application_invocation)
        || latest.private_operation.as_ref() != Some(&private))
    {
        return None;
    }
    (retired_private_operation_is_valid(&private)
        && (private.operation != AuthorityOperationKind::RecoverPrivateAgent as u8
            || retired_recovery_matches_managed_state(configuration, state, &private))
        && retired_private_operation_matches_application(&private, &fact))
    .then_some(PrivateApplicationSource {
        credential: record.credential,
        request_sequence: record.request_sequence,
        invocation_payload: record.invocation_payload,
        private,
    })
}

fn private_application_retirement_record_source(
    configuration: &SystemAuthorityConfiguration,
    state: &AuthorityLinearState,
    record: &PrivateApplicationRetirementRecord,
) -> Option<PrivateApplicationSource> {
    let request_sequence = NonZeroU64::new(record.request_sequence)?;
    let authorization_sequence = NonZeroU64::new(record.authorization_sequence)?;
    let authorization_invocation = AuthorityOperationCall::derive_invocation(
        CredentialId(record.credential),
        request_sequence,
        Hash(record.invocation_payload),
    );
    let issuance_invocation =
        AuthorityOperationApproval::derive_acknowledgement_invocation_from_call_parts(
            CredentialId(record.credential),
            request_sequence,
            authorization_invocation,
            Hash(record.invocation_payload),
            Hash(record.operation_call),
        );
    let credential =
        &state.credentials[credential_index(state, CredentialId(record.credential)).ok()?];
    let private = &record.private_operation;
    let managed = &state.managed_agents[managed_agent(state, AgentId(private.agent)).ok()?];
    if credential.principal != private.principal
        || credential.operation_request_high_water < record.request_sequence
        || managed.profile != AgentProfile::Private as u8
        || managed.owner != private.principal
        || managed.authority != configuration.binding
        || authorization_invocation.0 != record.authorization_invocation
        || issuance_invocation.0 != record.issuance_invocation
        || PrivateControlApplicationRetirementAck::derive_application_invocation_from_issuance(
            configured_authority_target(configuration),
            authorization_invocation,
            issuance_invocation,
            authorization_sequence,
            Hash(record.issuance_ack),
        )
        .0 != record.application_invocation
    {
        return None;
    }
    if let Some(active) = state.operation_retries.iter().find(|source| {
        source.invocation == record.authorization_invocation
            && source.acknowledgement_invocation == record.issuance_invocation
    }) {
        let call = AuthorityOperationCall::decode(&active.operation_call_bytes).ok()?;
        if active.credential != record.credential
            || active.request_sequence != record.request_sequence
            || active.invocation_payload != record.invocation_payload
            || active.authorization_sequence != record.authorization_sequence
            || active.operation_call != record.operation_call
            || active.approval_commitment != record.approval
            || active.issuance_ack != Some(record.issuance_ack)
            || active.issued_at != Some(record.issued_at)
            || active.private_application_invocation != Some(record.application_invocation)
            || retained_private_operation(&call).as_ref() != Some(private)
        {
            return None;
        }
    } else if let Some(latest) = state.latest_operation_acks.iter().find(|source| {
        source.authorization_invocation == record.authorization_invocation
            && source.acknowledgement_invocation == record.issuance_invocation
    }) && (latest.credential != record.credential
        || latest.request_sequence != record.request_sequence
        || latest.invocation_payload != record.invocation_payload
        || latest.authorization_sequence != record.authorization_sequence
        || latest.operation_call != record.operation_call
        || latest.approval != record.approval
        || latest.issuance_ack != record.issuance_ack
        || latest.issued_at != record.issued_at
        || latest.private_application_invocation != Some(record.application_invocation)
        || latest.private_operation.as_ref() != Some(private))
    {
        return None;
    }
    retired_private_operation_is_valid(private).then_some(PrivateApplicationSource {
        credential: record.credential,
        request_sequence: record.request_sequence,
        invocation_payload: record.invocation_payload,
        private: private.clone(),
    })
}

fn private_genesis_projection(
    state: &AuthorityLinearState,
    managed: &ManagedAgentRow,
) -> Option<PrivateAgentProjectionRow> {
    if managed.profile != AgentProfile::Private as u8 {
        return None;
    }
    let current = &state.private_agents[private_agent(state, AgentId(managed.agent)).ok()?];
    let members = current.genesis_members.clone();
    let member_set = member_set_commitment(&members)?;
    if member_set.0 != current.genesis_member_set {
        return None;
    }
    Some(PrivateAgentProjectionRow {
        agent: managed.agent,
        owner: managed.owner,
        runtime_deployment: managed.runtime_deployment,
        genesis_members: members.clone(),
        genesis_member_set: member_set.0,
        control_head: None,
        control_sequence: None,
        epoch: 0,
        members,
        member_set: member_set.0,
        reopened_runtime_state: None,
        stable_projection: None,
        applied_at: None,
        application_invocation: None,
        application_ack: None,
        application_ack_bytes: None,
    })
}

fn private_projection_fields_match(
    left: &PrivateAgentProjectionRow,
    right: &PrivateAgentProjectionRow,
) -> bool {
    left.agent == right.agent
        && left.owner == right.owner
        && left.runtime_deployment == right.runtime_deployment
        && left.genesis_members == right.genesis_members
        && left.genesis_member_set == right.genesis_member_set
        && left.control_head == right.control_head
        && left.control_sequence == right.control_sequence
        && left.epoch == right.epoch
        && left.members == right.members
        && left.member_set == right.member_set
        && left.reopened_runtime_state == right.reopened_runtime_state
        && left.stable_projection == right.stable_projection
        && left.applied_at == right.applied_at
        && left.application_invocation == right.application_invocation
        && left.application_ack == right.application_ack
}

fn private_projection_is_valid(
    configuration: &SystemAuthorityConfiguration,
    state: &AuthorityLinearState,
) -> bool {
    let private_managed_count = state
        .managed_agents
        .iter()
        .filter(|managed| managed.profile == AgentProfile::Private as u8)
        .count();
    if state.private_agents.len() != private_managed_count
        || state.private_agents.len() > MAX_MANAGED_AGENTS
        || private_application_resolution_count(state) > MAX_PRIVATE_APPLICATION_RECORDS
        || retained_recovery_application_count(state) > MAX_PRIVATE_RECOVERY_APPLICATION_RECORDS
        || state.private_application_commitment == [0; 32]
        || !sorted_unique_by(&state.private_agents, |row| row.agent)
        || !private_application_chain_is_valid(configuration, state)
    {
        return false;
    }

    for row in &state.private_agents {
        let Ok(managed_index) = managed_agent(state, AgentId(row.agent)) else {
            return false;
        };
        let managed = &state.managed_agents[managed_index];
        let genesis = row.control_head.is_none()
            && row.control_sequence.is_none()
            && row.reopened_runtime_state.is_none()
            && row.stable_projection.is_none()
            && row.applied_at.is_none()
            && row.application_invocation.is_none()
            && row.application_ack.is_none()
            && row.application_ack_bytes.is_none();
        let applied = row.control_head.is_some()
            && row.control_sequence.is_some()
            && row.reopened_runtime_state.is_some()
            && row.stable_projection.is_some()
            && row.applied_at.is_some()
            && row.application_invocation.is_some()
            && row.application_ack.is_some()
            && row.application_ack_bytes.is_some();
        if managed.profile != AgentProfile::Private as u8
            || managed.owner != row.owner
            || managed.runtime_deployment != row.runtime_deployment
            || managed.replicas.len() != row.members.len()
            || !managed
                .replicas
                .iter()
                .zip(&row.members)
                .all(|(replica, member)| {
                    replica.node == *member
                        && replica.principal == row.owner
                        && replica.role == ReplicaRole::Observer as u8
                })
            || row.members.is_empty()
            || row.members.len() > MAX_PRIVATE_NODES
            || row.members.iter().any(|node| *node == [0; 32])
            || !row.members.windows(2).all(|pair| pair[0] < pair[1])
            || member_set_commitment(&row.members).map(|commitment| commitment.0)
                != Some(row.member_set)
            || row.member_set == [0; 32]
            || row.genesis_members.is_empty()
            || row.genesis_members.len() > MAX_PRIVATE_NODES
            || row.genesis_members.iter().any(|node| *node == [0; 32])
            || !row.genesis_members.windows(2).all(|pair| pair[0] < pair[1])
            || member_set_commitment(&row.genesis_members).map(|commitment| commitment.0)
                != Some(row.genesis_member_set)
            || row.genesis_member_set == [0; 32]
            || (!genesis && !applied)
            || (genesis && row.epoch != 0)
            || row.control_head == Some([0; 32])
            || row.reopened_runtime_state == Some([0; 32])
            || row.stable_projection == Some([0; 32])
            || row.application_invocation == Some([0; 32])
            || row.application_ack == Some([0; 32])
        {
            return false;
        }
    }

    let mut application_ids = state
        .private_applications
        .iter()
        .map(|record| record.application_invocation)
        .collect::<Vec<_>>();
    application_ids.extend(
        state
            .private_application_retirements
            .iter()
            .map(|record| record.application_invocation),
    );
    application_ids.sort_unstable();
    if application_ids.windows(2).any(|pair| pair[0] == pair[1]) {
        return false;
    }
    let mut source_sequences = state
        .private_applications
        .iter()
        .map(|record| record.authorization_sequence)
        .collect::<Vec<_>>();
    source_sequences.extend(
        state
            .private_application_retirements
            .iter()
            .map(|record| record.authorization_sequence),
    );
    source_sequences.sort_unstable();
    if source_sequences.windows(2).any(|pair| pair[0] == pair[1]) {
        return false;
    }

    let mut replay = Vec::with_capacity(private_managed_count);
    for managed in state
        .managed_agents
        .iter()
        .filter(|managed| managed.profile == AgentProfile::Private as u8)
    {
        let Some(genesis) = private_genesis_projection(state, managed) else {
            return false;
        };
        replay.push(genesis);
    }
    for record in &state.private_applications {
        let Some(sequence) = NonZeroU64::new(record.authorization_sequence) else {
            return false;
        };
        let valid_node_identity =
            if record.operation == AuthorityOperationKind::InvitePrivateNode as u8 {
                record.node.is_some_and(|node| {
                    record.node_identity.is_some_and(|identity| {
                        enrolled_private_identity_commitment(
                            state,
                            vos::agent_sdk::NodeId(node),
                            PrincipalId(record.owner),
                        ) == Some(Hash(identity))
                    })
                })
            } else if record.operation == AuthorityOperationKind::RevokePrivateNode as u8 {
                record.node.is_some_and(|node| node != [0; 32]) && record.node_identity.is_none()
            } else if record.operation == AuthorityOperationKind::RecoverPrivateAgent as u8 {
                record.node.is_none()
                    && record.node_identity.is_none()
                    && record.recovery_proof_bytes.is_some()
            } else if matches!(
                private_operation_kind(record.operation),
                Some(
                    AuthorityOperationKind::RotatePrivateKeys
                        | AuthorityOperationKind::SetPrivateResourcePolicy
                        | AuthorityOperationKind::PrivateActorLifecycle
                )
            ) {
                record.node.is_none() && record.node_identity.is_none()
            } else {
                false
            };
        if record.credential == [0; 32]
            || record.request_sequence == 0
            || record.invocation_payload == [0; 32]
            || record.authorization_invocation == [0; 32]
            || record.issuance_invocation == [0; 32]
            || record.application_invocation == [0; 32]
            || record.application_ack == [0; 32]
            || record.operation_call == [0; 32]
            || record.approval == [0; 32]
            || record.issuance_ack == [0; 32]
            || record.owner == [0; 32]
            || !valid_node_identity
            || record.issued_at > record.applied_at
            || PrivateControlApplicationAck::derive_application_invocation_from_issuance(
                configured_authority_target(configuration),
                InvocationId(record.authorization_invocation),
                InvocationId(record.issuance_invocation),
                sequence,
                Hash(record.issuance_ack),
            )
            .0 != record.application_invocation
            || private_application_record_source(configuration, state, record).is_none()
        {
            return false;
        }
        let Ok(index) = replay.binary_search_by(|row| row.agent.cmp(&record.agent)) else {
            return false;
        };
        if !apply_private_application_transition(&mut replay[index], record) {
            return false;
        }
    }
    for record in &state.private_application_retirements {
        if record.credential == [0; 32]
            || record.request_sequence == 0
            || record.invocation_payload == [0; 32]
            || record.authorization_invocation == [0; 32]
            || record.issuance_invocation == [0; 32]
            || record.application_invocation == [0; 32]
            || record.operation_call == [0; 32]
            || record.approval == [0; 32]
            || record.issuance_ack == [0; 32]
            || record.retirement_ack == [0; 32]
            || record.issued_at > record.resolved_at
            || private_application_retirement_record_source(configuration, state, record).is_none()
        {
            return false;
        }
    }
    if replay.len() != state.private_agents.len()
        || !replay
            .iter()
            .zip(&state.private_agents)
            .all(|(expected, actual)| private_projection_fields_match(expected, actual))
    {
        return false;
    }

    for row in &state.private_agents {
        let Some(application_invocation) = row.application_invocation else {
            continue;
        };
        let Some(record) = state
            .private_applications
            .iter()
            .rev()
            .find(|record| record.agent == row.agent)
        else {
            return false;
        };
        let Some(encoded) = row.application_ack_bytes.as_deref() else {
            return false;
        };
        let Ok(ack) = PrivateControlApplicationAck::decode(encoded) else {
            return false;
        };
        let Some(source) = private_application_record_source(configuration, state, record) else {
            return false;
        };
        let Some(sequence) = NonZeroU64::new(record.authorization_sequence) else {
            return false;
        };
        if ack.encode().ok().as_deref() != Some(encoded)
            || ack.application_invocation.0 != application_invocation
            || ack.commitment().0 != record.application_ack
            || ack.application != private_application_fact(configuration, state, record).unwrap()
            || ack.operation_call.0 != record.operation_call
            || ack.approval.0 != record.approval
            || ack.issuance_ack.0 != record.issuance_ack
            || ack.issued_at != record.issued_at
            || ack
                .verify_issuance_tombstone_with(
                    configured_authority_target(configuration),
                    InvocationId(record.authorization_invocation),
                    InvocationId(record.issuance_invocation),
                    sequence,
                    Hash(record.issuance_ack),
                    &Ed25519CredentialVerifier,
                )
                .is_err()
            || source.private.principal != row.owner
        {
            return false;
        }
    }
    true
}

fn authority_state_is_valid(
    configuration: &SystemAuthorityConfiguration,
    state: &AuthorityLinearState,
) -> bool {
    state.initialized
        && configuration.is_valid()
        && state.state_revision != 0
        && state.epoch >= configuration.binding.initial_epoch
        && state.epoch != 0
        && state.administration_generation != 0
        && state.credentials.len() <= MAX_AUTHORITY_CREDENTIALS
        && state.nodes.len() <= MAX_AUTHORITY_NODES
        && state.roles.len() <= MAX_AUTHORITY_PRINCIPALS
        && state.managed_agents.len() <= MAX_MANAGED_AGENTS
        && state.genesis_publications.len() <= MAX_MANAGED_AGENTS
        && sorted_unique_by(&state.genesis_publications, |row| row.agent)
        && state
            .genesis_publications
            .iter()
            .all(|row| genesis_publication::record_is_valid(configuration, row))
        && state.managed_actors.len() <= MAX_MANAGED_ACTORS
        && state.retired_actor_installations.len() <= MAX_RETIRED_ACTOR_INSTALLATIONS
        && exact_retry_count(state) <= MAX_EXACT_RETRY_RECORDS
        && state.latest_management_acks.len() <= state.credentials.len()
        && state.latest_operation_acks.len() <= state.credentials.len()
        && state.private_agents.len() <= MAX_MANAGED_AGENTS
        && private_application_resolution_count(state) <= MAX_PRIVATE_APPLICATION_RECORDS
        && state.operation_retirement_floor >= configuration.bootstrap_authorization_high_water
        && state.operation_retirement_floor <= state.authorization_sequence
        && state.private_application_commitment != [0; 32]
        && state.state_integrity_commitment != [0; 32]
        && computed_state_integrity_commitment(configuration, state)
            .is_some_and(|commitment| commitment.0 == state.state_integrity_commitment)
        && sorted_unique_by(&state.credentials, |row| row.credential)
        && state.nodes.index_is_valid()
        && sorted_unique_by(&state.roles, |row| row.principal)
        && sorted_unique_by(&state.managed_agents, |row| row.agent)
        && sorted_unique_by(&state.retries, |row| row.invocation)
        && sorted_unique_by(&state.latest_management_acks, |row| row.credential)
        && sorted_unique_by(&state.operation_retries, |row| row.invocation)
        && sorted_unique_by(&state.latest_operation_acks, |row| row.credential)
        && sorted_unique_by(&state.admin_retries, |row| row.credential)
        && state.credentials.iter().all(|row| {
            row.credential != [0; 32]
                && row.principal != [0; 32]
                && matches!(row.kind, 0 | 1)
                && canonical_credential_public_key(&row.public_key)
                && CredentialId::of_public_key(&row.public_key).0 == row.credential
                && state
                    .roles
                    .binary_search_by(|role| role.principal.cmp(&row.principal))
                    .is_ok()
        })
        && state.nodes.all_certificates(&node_storage::rows(), |row| {
            node_owner_row_is_valid(configuration, state, row)
        })
        && state.roles.iter().all(|row| {
            row.principal != [0; 32]
                && state.credentials.iter().any(|credential| {
                    credential.principal == row.principal
                        && credential.status == CredentialStatus::Active
                })
        })
        && authorization_grants_are_valid(configuration, state)
        && accessible_admin_exists(state)
        && state
            .managed_agents
            .iter()
            .all(|row| managed_agent_projection_is_valid(configuration, state, row))
        && actor_projection_is_valid(configuration, state)
        && state.retries.iter().all(|row| {
            row.invocation != [0; 32]
                && row.acknowledgement_invocation != [0; 32]
                && row.acknowledgement_invocation != row.invocation
                && row.credential_call != [0; 32]
                && !row.credential_call_bytes.is_empty()
                && row.credential_call_bytes.len() <= MAX_INVOCATION_MESSAGE_BYTES
                && row.approval_commitment != [0; 32]
                && row.authorization_sequence != 0
                && row.authorization_sequence <= state.authorization_sequence
                && !row.approval.is_empty()
                && row.approval.len() <= MAX_INVOCATION_REPLY_BYTES
                && retry_finalization_shape_is_valid(row)
        })
        && state.operation_retries.iter().all(|row| {
            row.invocation != [0; 32]
                && row.acknowledgement_invocation != [0; 32]
                && row.acknowledgement_invocation != row.invocation
                && row.operation_call != [0; 32]
                && !row.operation_call_bytes.is_empty()
                && row.operation_call_bytes.len() <= MAX_INVOCATION_MESSAGE_BYTES
                && row.approval_commitment != [0; 32]
                && row.authorization_sequence > state.operation_retirement_floor
                && row.authorization_sequence <= state.authorization_sequence
                && !row.approval.is_empty()
                && row.approval.len() <= MAX_INVOCATION_REPLY_BYTES
                && operation_retry_ack_shape_is_valid(row)
        })
        && state
            .latest_operation_acks
            .iter()
            .all(|row| latest_operation_ack_is_valid(configuration, state, row))
        && state
            .admin_retries
            .iter()
            .all(|row| admin_retry_shape_is_valid(configuration, state, row))
        && state.admin_retries.len() <= state.credentials.len()
        && state.administration_generation
            == state
                .credentials
                .iter()
                .try_fold(1_u64, |generation, credential| {
                    generation.checked_add(credential.admin_request_high_water)
                })
                .unwrap_or(0)
        && admin_generations_are_unique(&state.admin_retries)
        && all_invocation_identifiers_are_unique(state)
        && private_projection_is_valid(configuration, state)
        && admin_compact_state_is_valid(configuration, state)
        && authorization_history_reconstructs_policy(configuration, state)
}

fn authorization_history_reconstructs_policy(
    configuration: &SystemAuthorityConfiguration,
    state: &AuthorityLinearState,
) -> bool {
    let Some(management_count) = state.credentials.iter().try_fold(0_u64, |total, row| {
        total.checked_add(row.management_request_high_water)
    }) else {
        return false;
    };
    let Some(operation_count) = state.credentials.iter().try_fold(0_u64, |total, row| {
        total.checked_add(row.operation_request_high_water)
    }) else {
        return false;
    };
    let Some(expected_authorization_sequence) = configuration
        .bootstrap_authorization_high_water
        .checked_add(management_count)
        .and_then(|value| value.checked_add(operation_count))
    else {
        return false;
    };
    if expected_authorization_sequence != state.authorization_sequence {
        return false;
    }

    for credential in &state.credentials {
        let pending = state
            .retries
            .iter()
            .find(|record| record.credential == credential.credential);
        if state
            .retries
            .iter()
            .filter(|record| record.credential == credential.credential)
            .count()
            > 1
        {
            return false;
        }
        let latest = state
            .latest_management_acks
            .binary_search_by(|record| record.credential.cmp(&credential.credential))
            .ok()
            .map(|index| &state.latest_management_acks[index]);
        match (credential.management_request_high_water, pending, latest) {
            (0, None, None) => {}
            (high_water, Some(pending), latest) => {
                if pending.request_sequence != high_water
                    || latest.is_some_and(|latest| {
                        latest.request_sequence.checked_add(1) != Some(high_water)
                    })
                    || (high_water > 1 && latest.is_none())
                {
                    return false;
                }
            }
            (high_water, None, Some(latest)) if latest.request_sequence == high_water => {}
            _ => return false,
        }
        let latest_management_is_unretired = latest
            .is_some_and(|latest| latest.authorization_sequence > state.operation_retirement_floor);
        if pending.is_some() && latest_management_is_unretired {
            return false;
        }

        let operation_pending = state
            .operation_retries
            .iter()
            .find(|record| record.credential == credential.credential);
        if state
            .operation_retries
            .iter()
            .filter(|record| record.credential == credential.credential)
            .count()
            > 1
        {
            return false;
        }
        let operation_latest = state
            .latest_operation_acks
            .binary_search_by(|record| record.credential.cmp(&credential.credential))
            .ok()
            .map(|index| &state.latest_operation_acks[index]);
        match (
            credential.operation_request_high_water,
            operation_pending,
            operation_latest,
        ) {
            (0, None, None) => {}
            (high_water, Some(pending), latest) => {
                if pending.request_sequence != high_water
                    || latest.is_some_and(|latest| {
                        latest.request_sequence.checked_add(1) != Some(high_water)
                            || (latest.private_operation.is_some()
                                && !private_operation_source_is_resolved(
                                    state,
                                    latest.authorization_invocation,
                                    latest.acknowledgement_invocation,
                                    latest.authorization_sequence,
                                ))
                    })
                    || (high_water > 1 && latest.is_none())
                {
                    return false;
                }
            }
            (high_water, None, Some(latest)) if latest.request_sequence == high_water => {}
            _ => return false,
        }
        let latest_operation_is_unsettled = operation_latest.is_some_and(|latest| {
            latest.authorization_sequence > state.operation_retirement_floor
                || (latest.private_operation.is_some()
                    && !private_operation_source_is_resolved(
                        state,
                        latest.authorization_invocation,
                        latest.acknowledgement_invocation,
                        latest.authorization_sequence,
                    ))
        });
        if operation_pending.is_some() && latest_operation_is_unsettled {
            return false;
        }
        if (pending.is_some() || latest_management_is_unretired)
            && (operation_pending.is_some() || latest_operation_is_unsettled)
        {
            return false;
        }
    }

    if !state
        .retries
        .iter()
        .all(|record| pending_management_record_is_valid(configuration, state, record))
        || !state
            .latest_management_acks
            .iter()
            .all(|record| latest_management_ack_is_valid(configuration, state, record))
        || !state
            .operation_retries
            .iter()
            .all(|record| active_operation_record_is_valid(configuration, state, record))
    {
        return false;
    }

    let mut retained_sequences = Vec::with_capacity(
        state
            .retries
            .len()
            .saturating_add(state.latest_management_acks.len())
            .saturating_add(state.operation_retries.len())
            .saturating_add(state.latest_operation_acks.len()),
    );
    retained_sequences.extend(
        state
            .retries
            .iter()
            .map(|record| record.authorization_sequence),
    );
    retained_sequences.extend(
        state
            .latest_management_acks
            .iter()
            .map(|record| record.authorization_sequence),
    );
    retained_sequences.extend(
        state
            .operation_retries
            .iter()
            .map(|record| record.authorization_sequence),
    );
    retained_sequences.extend(
        state
            .latest_operation_acks
            .iter()
            .map(|record| record.authorization_sequence),
    );
    retained_sequences.sort_unstable();
    retained_sequences.iter().all(|sequence| {
        *sequence > configuration.bootstrap_authorization_high_water
            && *sequence <= state.authorization_sequence
    }) && retained_sequences.windows(2).all(|pair| pair[0] != pair[1])
}

fn pending_management_record_is_valid(
    configuration: &SystemAuthorityConfiguration,
    state: &AuthorityLinearState,
    record: &ExactRetryRecord,
) -> bool {
    let Ok(call) = AuthorityCredentialCall::decode(&record.credential_call_bytes) else {
        return false;
    };
    let Ok(approval) = ManagementApproval::decode(&record.approval) else {
        return false;
    };
    call.invocation.0 == record.invocation
        && call.credential.0 == record.credential
        && call.request_sequence.get() == record.request_sequence
        && call.commitment().0 == record.credential_call
        && call.encode().ok().as_deref() == Some(record.credential_call_bytes.as_slice())
        && call.verify_with(&Ed25519CredentialVerifier).is_ok()
        && authority_target_matches(configuration, &call.authority)
        && approval.commitment().0 == record.approval_commitment
        && approval.encode().ok().as_deref() == Some(record.approval.as_slice())
        && approval.authorization_sequence.get() == record.authorization_sequence
        && approval.acknowledgement_invocation.0 == record.acknowledgement_invocation
        && approval.matches_call(&call)
        && state.credentials.iter().any(|credential| {
            credential.credential == record.credential
                && credential.principal == call.principal.0
                && credential.public_key == call.credential_public_key
                && credential.management_request_high_water == record.request_sequence
        })
        && reconstruction_effect(configuration, state, &call).as_ref() == Some(&record.effect)
}

fn latest_management_ack_is_valid(
    configuration: &SystemAuthorityConfiguration,
    state: &AuthorityLinearState,
    record: &LatestManagementAckRow,
) -> bool {
    let Ok(call) = AuthorityCredentialCall::decode(&record.credential_call_bytes) else {
        return false;
    };
    let Ok(ack) = ManagementApplicationAck::decode(&record.acknowledgement_bytes) else {
        return false;
    };
    record.credential != [0; 32]
        && record.request_sequence != 0
        && record.authorization_invocation != [0; 32]
        && record.acknowledgement_invocation != [0; 32]
        && record.authorization_invocation != record.acknowledgement_invocation
        && record.authorization_sequence != 0
        && record.credential_call != [0; 32]
        && record.approval != [0; 32]
        && record.request != [0; 32]
        && record.application != [0; 32]
        && record.acknowledgement != [0; 32]
        && record.reopened_state != [0; 32]
        && record.credential_call_bytes.len() <= MAX_INVOCATION_MESSAGE_BYTES
        && record.acknowledgement_bytes.len() <= MAX_INVOCATION_MESSAGE_BYTES
        && call.credential.0 == record.credential
        && call.request_sequence.get() == record.request_sequence
        && call.invocation.0 == record.authorization_invocation
        && call.commitment().0 == record.credential_call
        && call.encode().ok().as_deref() == Some(record.credential_call_bytes.as_slice())
        && call.verify_with(&Ed25519CredentialVerifier).is_ok()
        && authority_target_matches(configuration, &call.authority)
        && ack.authorization_invocation.0 == record.authorization_invocation
        && ack.acknowledgement_invocation.0 == record.acknowledgement_invocation
        && ack.authorization_sequence.get() == record.authorization_sequence
        && ack.credential_call.0 == record.credential_call
        && ack.approval.0 == record.approval
        && ack.request.0 == record.request
        && ack.request == call.plan.commitment()
        && vos::agent_sdk::wire::management_reply_commitment(&ack.application).0
            == record.application
        && ack.commitment().0 == record.acknowledgement
        && ack.encode().ok().as_deref() == Some(record.acknowledgement_bytes.as_slice())
        && ack.reopened_state.0 == record.reopened_state
        && ack.applied_at == record.applied_at
        && ack.verify_with(&Ed25519CredentialVerifier).is_ok()
        && authority_target_matches(configuration, &ack.authority)
        && state.credentials.iter().any(|credential| {
            credential.credential == record.credential
                && credential.principal == call.principal.0
                && credential.public_key == call.credential_public_key
                && credential.management_request_high_water >= record.request_sequence
        })
}

fn active_operation_record_is_valid(
    configuration: &SystemAuthorityConfiguration,
    state: &AuthorityLinearState,
    record: &AuthorityOperationRetryRecord,
) -> bool {
    let Ok(call) = AuthorityOperationCall::decode(&record.operation_call_bytes) else {
        return false;
    };
    let Ok(approval) = AuthorityOperationApproval::decode(&record.approval) else {
        return false;
    };
    let Some((valid_from, expires_at)) = narrowed_validity_window(
        call.requested_valid_from,
        call.requested_expires_at,
        record.observed_slot,
    ) else {
        return false;
    };
    let recovery_shape = retained_private_operation(&call).is_none_or(|private| {
        retired_private_operation_is_valid(&private)
            && retained_recovery_source_is_valid(
                configuration,
                state,
                &private,
                record.invocation,
                record.acknowledgement_invocation,
                record.authorization_sequence,
            )
    });
    if record.credential == [0; 32]
        || record.request_sequence == 0
        || record.invocation_payload == [0; 32]
        || call.invocation.0 != record.invocation
        || call.credential.0 != record.credential
        || call.request_sequence.get() != record.request_sequence
        || call.invocation_payload_commitment().0 != record.invocation_payload
        || call.commitment().0 != record.operation_call
        || call.encode().ok().as_deref() != Some(record.operation_call_bytes.as_slice())
        || authenticated_operation_role(configuration, state, &call) != Some(record.role)
        || !authority_target_matches(configuration, &call.authority)
        || approval.commitment().0 != record.approval_commitment
        || approval.encode().ok().as_deref() != Some(record.approval.as_slice())
        || approval.authorization_sequence.get() != record.authorization_sequence
        || approval.acknowledgement_invocation.0 != record.acknowledgement_invocation
        || !approval.matches_call(&call)
        || approval.selector.evidence
            != operation_evidence(
                configuration,
                call.commitment(),
                record.role,
                record.authorization_sequence,
                record.observed_slot,
            )
        || approval.selector.valid_from != valid_from
        || approval.selector.expires_at != expires_at
        || state.credentials.iter().all(|credential| {
            credential.credential != record.credential
                || credential.operation_request_high_water != record.request_sequence
        })
        || !recovery_shape
    {
        return false;
    }
    if let Some(encoded_ack) = record.issuance_ack_bytes.as_deref() {
        let Ok(ack) = AuthorityOperationIssuanceAck::decode(encoded_ack) else {
            return false;
        };
        ack.commitment().0 == record.issuance_ack.unwrap_or([0; 32])
            && ack.encode().ok().as_deref() == Some(encoded_ack)
            && ack.issued_at == record.issued_at.unwrap_or(u64::MAX)
            && ack.matches_pending(&call, &approval)
            && ack
                .verify_with(configuration.binding.sdk(), &Ed25519CredentialVerifier)
                .is_ok()
    } else {
        true
    }
}

fn reconstruction_effect(
    configuration: &SystemAuthorityConfiguration,
    state: &AuthorityLinearState,
    call: &AuthorityCredentialCall,
) -> Option<PendingManagementEffect> {
    match &call.plan {
        ManagementAuthorizationPlan::Create {
            descriptor,
            replicas,
            descriptor_commitment,
        } => {
            let descriptor = reconstructed_create_descriptor(
                state,
                descriptor,
                replicas,
                *descriptor_commitment,
            )?;
            if descriptor.authority != configuration.binding.sdk()
                || managed_agent(state, descriptor.identity.agent).is_ok()
                || state.retries.iter().any(|record| {
                    record.invocation != call.invocation.0
                        && matches!(
                            &record.effect,
                            PendingManagementEffect::Create(row)
                                if row.agent == descriptor.identity.agent.0
                        )
                })
                || state.managed_agents.len()
                    + state
                        .retries
                        .iter()
                        .filter(|record| {
                            record.invocation != call.invocation.0
                                && matches!(record.effect, PendingManagementEffect::Create(_))
                        })
                        .count()
                    >= MAX_MANAGED_AGENTS
            {
                return None;
            }
            Some(PendingManagementEffect::Create(
                managed_agent_row_from_descriptor(configuration, &descriptor)?,
            ))
        }
        ManagementAuthorizationPlan::Install(_)
        | ManagementAuthorizationPlan::UpgradeActor(_)
        | ManagementAuthorizationPlan::Suspend { .. }
        | ManagementAuthorizationPlan::Resume { .. }
        | ManagementAuthorizationPlan::RemoveLeaf { .. } => {
            reconstruction_lifecycle_row(configuration, state, call)?;
            if pending_runtime_transition_conflicts(state, call)
                || pending_actor_effect_conflicts(state, call)
            {
                return None;
            }
            projected_actor_effect(configuration, state, call)
        }
        ManagementAuthorizationPlan::ChangeReplicas {
            expected_generation,
            replicas: slots,
            replica_roster_commitment,
        } => {
            let row = reconstruction_lifecycle_row(configuration, state, call)?;
            if pending_runtime_transition_conflicts(state, call)
                || pending_replica_transition_conflicts(state, call)
            {
                return None;
            }
            let replicas = reconstructed_replica_roster(state, slots, *replica_roster_commitment)?;
            replica_change_effect(configuration, state, row, *expected_generation, &replicas)
        }
        ManagementAuthorizationPlan::UpgradeRuntime(upgrade) => {
            let row = reconstruction_lifecycle_row(configuration, state, call)?;
            if upgrade.producer.0 == row.transition_producer
                || pending_runtime_transition_conflicts(state, call)
            {
                return None;
            }
            Some(PendingManagementEffect::UpgradeRuntime {
                agent: row.agent,
                from_deployment: row.runtime_deployment,
                to_deployment: upgrade.to_deployment.0,
                to_program: upgrade.to_program.0,
                producer: upgrade.producer.0,
                package: authority_blob(&upgrade.package),
                contract: RuntimeContractRow::from_sdk(upgrade.contract),
                capabilities: RuntimeCapabilitiesRow::from_sdk(upgrade.capabilities),
            })
        }
    }
}

fn reconstruction_lifecycle_row<'a>(
    configuration: &SystemAuthorityConfiguration,
    state: &'a AuthorityLinearState,
    call: &AuthorityCredentialCall,
) -> Option<&'a ManagedAgentRow> {
    let row = &state.managed_agents[managed_agent(state, call.managed.agent).ok()?];
    (row.runtime_deployment == call.managed.runtime_deployment.0
        && row.owner == call.managed.owner.0
        && row.profile == call.managed.profile as u8
        && row.transition_producer == call.managed.transition_producer.0
        && row.authority == configuration.binding)
        .then_some(row)
}

fn accessible_admin_exists(state: &AuthorityLinearState) -> bool {
    state.roles.iter().any(|role| {
        role.role == BuiltinPrincipalRole::Admin
            && state.credentials.iter().any(|credential| {
                credential.principal == role.principal
                    && credential.status == CredentialStatus::Active
            })
            && state.nodes.indices().any(|node| node.owner == role.principal)
    })
}

fn admin_retry_shape_is_valid(
    configuration: &SystemAuthorityConfiguration,
    state: &AuthorityLinearState,
    record: &AdminRetryRecord,
) -> bool {
    if record.credential == [0; 32]
        || record.request_sequence == 0
        || record.invocation == [0; 32]
        || record.call_commitment == [0; 32]
        || record.call_bytes.is_empty()
        || record.call_bytes.len() > MAX_INVOCATION_MESSAGE_BYTES
        || record.result_commitment == [0; 32]
        || record.result_bytes.is_empty()
        || record.result_bytes.len() > MAX_INVOCATION_REPLY_BYTES
        || record.generation <= 1
        || record.generation > state.administration_generation
    {
        return false;
    }
    let Ok(call) = AuthorityAdminCall::decode(&record.call_bytes) else {
        return false;
    };
    let Ok(result) = AuthorityAdminResult::decode(&record.result_bytes) else {
        return false;
    };
    call.credential.0 == record.credential
        && call.request_sequence.get() == record.request_sequence
        && call.invocation.0 == record.invocation
        && call.commitment().0 == record.call_commitment
        && call.encode().ok().as_deref() == Some(record.call_bytes.as_slice())
        && call
            .next_generation()
            .is_some_and(|generation| generation.get() == record.generation)
        && call.verify_with(&Ed25519CredentialVerifier).is_ok()
        && authority_target_matches(configuration, &call.authority)
        && result.call == call
        && result.generation.get() == record.generation
        && result.commitment().0 == record.result_commitment
        && result.encode().ok().as_deref() == Some(record.result_bytes.as_slice())
        && result.verify_with(&Ed25519CredentialVerifier).is_ok()
        && state.credentials.iter().any(|credential| {
            credential.credential == record.credential
                && credential.principal == call.administrator.0
                && credential.public_key == call.credential_public_key
                && credential.admin_request_high_water == record.request_sequence
        })
}

fn admin_generations_are_unique(records: &[AdminRetryRecord]) -> bool {
    records.iter().enumerate().all(|(index, record)| {
        records.iter().enumerate().all(|(other_index, other)| {
            index == other_index || record.generation != other.generation
        })
    })
}

fn admin_compact_state_is_valid(
    configuration: &SystemAuthorityConfiguration,
    state: &AuthorityLinearState,
) -> bool {
    for credential in &state.credentials {
        let latest = state
            .admin_retries
            .binary_search_by(|record| record.credential.cmp(&credential.credential))
            .ok()
            .map(|index| &state.admin_retries[index]);
        match (credential.admin_request_high_water, latest) {
            (0, None) => {}
            (high_water, Some(latest)) if latest.request_sequence == high_water => {}
            _ => return false,
        }
    }
    if state.administration_generation == 1 {
        return state.admin_retries.is_empty();
    }
    let Some(latest) = state
        .admin_retries
        .iter()
        .max_by_key(|record| record.generation)
    else {
        return false;
    };
    if latest.generation != state.administration_generation {
        return false;
    }
    let Ok(call) = AuthorityAdminCall::decode(&latest.call_bytes) else {
        return false;
    };
    admin_operation_postcondition(configuration, state, &call.operation)
}

fn admin_operation_postcondition(
    configuration: &SystemAuthorityConfiguration,
    state: &AuthorityLinearState,
    operation: &AuthorityAdminOperation,
) -> bool {
    match operation {
        AuthorityAdminOperation::EnrollPrincipal {
            principal,
            credential,
        } => {
            state
                .roles
                .binary_search_by(|row| row.principal.cmp(&principal.0))
                .ok()
                .is_some_and(|index| state.roles[index].role == BuiltinPrincipalRole::Member)
                && state
                    .credentials
                    .binary_search_by(|row| row.credential.cmp(&credential.credential.0))
                    .ok()
                    .is_some_and(|index| {
                        let row = &state.credentials[index];
                        credential_matches_active_enrollment(row, *principal, *credential)
                    })
        }
        AuthorityAdminOperation::AddCredential {
            principal,
            credential,
        } => state
            .credentials
            .binary_search_by(|row| row.credential.cmp(&credential.credential.0))
            .ok()
            .is_some_and(|index| {
                let row = &state.credentials[index];
                credential_matches_active_enrollment(row, *principal, *credential)
            }),
        AuthorityAdminOperation::RevokeCredential {
            principal,
            credential,
        } => state
            .credentials
            .binary_search_by(|row| row.credential.cmp(&credential.0))
            .ok()
            .is_some_and(|index| {
                state.credentials[index].principal == principal.0
                    && state.credentials[index].status == CredentialStatus::Revoked
            }),
        AuthorityAdminOperation::EnrollNode { enrollment } =>
            state.nodes.certificate_matches(&NodeOwnerRow::from_enrollment(*enrollment))
                && enrollment.space == SpaceId(configuration.space),
        AuthorityAdminOperation::UnbindNodeOwner { node, .. } =>
            enrolled_node_owner(state, *node).is_none(),
        AuthorityAdminOperation::SetBuiltinRole { principal, role } => state
            .roles
            .binary_search_by(|row| row.principal.cmp(&principal.0))
            .ok()
            .is_some_and(|index| state.roles[index].role == builtin_role(*role)),
        AuthorityAdminOperation::SetSpaceRole {
            principal,
            role,
            granted,
        } => space_role_grant(state, *principal, *role).is_ok() == *granted,
        AuthorityAdminOperation::SetActorRole {
            principal,
            agent,
            actor,
            deployment,
            role,
            granted,
        } => {
            actor_role_grant(state, *principal, *agent, *actor, *deployment, *role).is_ok()
                == *granted
        }
        AuthorityAdminOperation::SetCapability {
            principal,
            agent,
            actor,
            deployment,
            capability,
            granted,
        } => {
            capability_grant(state, *principal, *agent, *actor, *deployment, *capability).is_ok()
                == *granted
        }
    }
}

fn operation_retry_ack_shape_is_valid(record: &AuthorityOperationRetryRecord) -> bool {
    match (
        record.issuance_ack,
        record.issuance_ack_bytes.as_deref(),
        record.issued_at,
        record.private_application_invocation,
    ) {
        (None, None, None, None) => true,
        (Some(ack), Some(bytes), Some(_), private_application_invocation) => {
            let Ok(call) = AuthorityOperationCall::decode(&record.operation_call_bytes) else {
                return false;
            };
            let Ok(issuance) = AuthorityOperationIssuanceAck::decode(bytes) else {
                return false;
            };
            let expected = retained_private_operation(&call)
                .map(|_| PrivateControlApplicationAck::derive_application_invocation(&issuance).0);
            ack != [0; 32]
                && !bytes.is_empty()
                && bytes.len() <= MAX_INVOCATION_MESSAGE_BYTES
                && private_application_invocation == expected
        }
        _ => false,
    }
}

fn latest_operation_ack_is_valid(
    configuration: &SystemAuthorityConfiguration,
    state: &AuthorityLinearState,
    record: &LatestOperationAckRow,
) -> bool {
    let Some(request_sequence) = NonZeroU64::new(record.request_sequence) else {
        return false;
    };
    let Some(authorization_sequence) = NonZeroU64::new(record.authorization_sequence) else {
        return false;
    };
    let Ok(ack) = AuthorityOperationIssuanceAck::decode(&record.issuance_ack_bytes) else {
        return false;
    };
    let authorization_invocation = AuthorityOperationCall::derive_invocation(
        CredentialId(record.credential),
        request_sequence,
        Hash(record.invocation_payload),
    );
    let acknowledgement_invocation =
        AuthorityOperationApproval::derive_acknowledgement_invocation_from_call_parts(
            CredentialId(record.credential),
            request_sequence,
            authorization_invocation,
            Hash(record.invocation_payload),
            Hash(record.operation_call),
        );
    let private_shape = match (
        record.private_operation.as_ref(),
        record.private_application_invocation,
    ) {
        (None, None) => true,
        (Some(private), Some(application_invocation)) => {
            retired_private_operation_is_valid(private)
                && retained_recovery_source_is_valid(
                    configuration,
                    state,
                    private,
                    record.authorization_invocation,
                    record.acknowledgement_invocation,
                    record.authorization_sequence,
                )
                && PrivateControlApplicationAck::derive_application_invocation_from_issuance(
                    configured_authority_target(configuration),
                    InvocationId(record.authorization_invocation),
                    InvocationId(record.acknowledgement_invocation),
                    authorization_sequence,
                    Hash(record.issuance_ack),
                )
                .0 == application_invocation
        }
        _ => false,
    };
    record.credential != [0; 32]
        && record.invocation_payload != [0; 32]
        && record.authorization_invocation != [0; 32]
        && record.acknowledgement_invocation != [0; 32]
        && record.authorization_invocation != record.acknowledgement_invocation
        && record.operation_call != [0; 32]
        && record.approval != [0; 32]
        && record.issuance_ack != [0; 32]
        && !record.issuance_ack_bytes.is_empty()
        && record.issuance_ack_bytes.len() <= MAX_INVOCATION_MESSAGE_BYTES
        && record.authorization_sequence <= state.operation_retirement_floor
        && authorization_invocation.0 == record.authorization_invocation
        && acknowledgement_invocation.0 == record.acknowledgement_invocation
        && ack.authorization_invocation.0 == record.authorization_invocation
        && ack.acknowledgement_invocation.0 == record.acknowledgement_invocation
        && ack.operation_call.0 == record.operation_call
        && ack.approval.0 == record.approval
        && ack.authorization_sequence == authorization_sequence
        && ack.issued_at == record.issued_at
        && ack.commitment().0 == record.issuance_ack
        && ack.encode().ok().as_deref() == Some(record.issuance_ack_bytes.as_slice())
        && ack
            .verify_with(configuration.binding.sdk(), &Ed25519CredentialVerifier)
            .is_ok()
        && authority_target_matches(configuration, &ack.authority)
        && state.credentials.iter().any(|credential| {
            credential.credential == record.credential
                && credential.operation_request_high_water >= record.request_sequence
        })
        && private_shape
}

fn retry_finalization_shape_is_valid(record: &ExactRetryRecord) -> bool {
    record.credential != [0; 32] && record.request_sequence != 0
}

fn all_invocation_identifiers_are_unique(state: &AuthorityLinearState) -> bool {
    let mut identifiers = Vec::with_capacity(
        state
            .retries
            .len()
            .saturating_mul(2)
            .saturating_add(state.latest_management_acks.len().saturating_mul(2))
            .saturating_add(state.operation_retries.len().saturating_mul(3))
            .saturating_add(state.latest_operation_acks.len().saturating_mul(3))
            .saturating_add(state.admin_retries.len())
            .saturating_add(state.genesis_publications.len())
            .saturating_add(state.private_applications.len().saturating_mul(3))
            .saturating_add(
                state
                    .private_application_retirements
                    .len()
                    .saturating_mul(3),
            ),
    );
    for record in &state.genesis_publications {
        identifiers.push(record.invocation);
    }
    for record in &state.retries {
        identifiers.push(record.invocation);
        identifiers.push(record.acknowledgement_invocation);
    }
    for record in &state.latest_management_acks {
        identifiers.push(record.authorization_invocation);
        identifiers.push(record.acknowledgement_invocation);
    }
    for record in &state.operation_retries {
        let resolved = record.private_application_invocation.is_some()
            && private_operation_source_is_resolved(
                state,
                record.invocation,
                record.acknowledgement_invocation,
                record.authorization_sequence,
            );
        if !resolved {
            identifiers.push(record.invocation);
            identifiers.push(record.acknowledgement_invocation);
            if let Some(application_invocation) = record.private_application_invocation {
                identifiers.push(application_invocation);
            }
        }
    }
    for record in &state.latest_operation_acks {
        let resolved = record.private_application_invocation.is_some()
            && private_operation_source_is_resolved(
                state,
                record.authorization_invocation,
                record.acknowledgement_invocation,
                record.authorization_sequence,
            );
        if !resolved {
            identifiers.push(record.authorization_invocation);
            identifiers.push(record.acknowledgement_invocation);
            if let Some(application_invocation) = record.private_application_invocation {
                identifiers.push(application_invocation);
            }
        }
    }
    identifiers.extend(state.admin_retries.iter().map(|record| record.invocation));
    for record in &state.private_applications {
        identifiers.push(record.authorization_invocation);
        identifiers.push(record.issuance_invocation);
        identifiers.push(record.application_invocation);
    }
    for record in &state.private_application_retirements {
        identifiers.push(record.authorization_invocation);
        identifiers.push(record.issuance_invocation);
        identifiers.push(record.application_invocation);
    }
    identifiers.sort_unstable();
    identifiers.windows(2).all(|pair| pair[0] != pair[1])
}

fn sorted_unique_by<T, F>(rows: &[T], key: F) -> bool
where
    F: Fn(&T) -> [u8; 32],
{
    rows.windows(2).all(|pair| key(&pair[0]) < key(&pair[1]))
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    #[test]
    fn node_access_preserves_certificate_and_exact_owner_boundaries() {
        vos::storage::mock::reset();
        let config = configuration();
        let mut state = AuthorityLinearState::bootstrap(config);
        let node = vos::agent_sdk::NodeId(config.bootstrap_node);
        let owner = PrincipalId(config.bootstrap_principal);
        let original = enrolled_node(&state, node).unwrap();
        assert_eq!(enrolled_node_owner(&state, node), Some(owner));
        let mut detached = enrolled_node(&state, node).unwrap();
        detached.transport_signature[0] ^= 1;
        assert_eq!(enrolled_node(&state, node), Some(original.clone()));
        assert!(!insert_enrolled_node(&mut state, config.bootstrap_node_enrollment()));
        let before = state.clone();
        assert!(!remove_enrolled_node(&mut state, node, PrincipalId([0xff; 32])));
        assert_eq!(state, before);
        assert!(remove_enrolled_node(&mut state, node, owner));
        assert_eq!(enrolled_node_owner(&state, node), None);
        assert_eq!(enrolled_node(&state, node), None);
        assert!(insert_enrolled_node(&mut state, config.bootstrap_node_enrollment()));
        assert_eq!(enrolled_node(&state, node), Some(original));
        assert!(state.nodes.index_is_valid());
        vos::storage::mock::reset();
    }

    #[test]
    fn node_certificate_storage_binds_header_and_refuses_rebootstrap() {
        use node_storage::{NodeRows, bootstrap, insert_verified, read, remove};
        use vos::storage::mock;
        mock::reset();
        let config = configuration();
        let certificate = NodeOwnerRow::from_enrollment(config.bootstrap_node_enrollment());
        let mut rows = NodeRows::default();
        rows.__init(b"test/authority-nodes/");
        let index = bootstrap(&mut rows, &certificate).unwrap();
        assert_eq!(read(&rows, &index), Some(certificate.clone()));
        assert!(bootstrap(&mut rows, &certificate).is_none());
        assert!(insert_verified(&mut rows, &certificate).is_none());
        // A fresh handle must see persisted rows, not synthesize constructor data.
        mock::commit_dispatch();
        let mut restored = NodeRows::default();
        restored.__init(b"test/authority-nodes/");
        assert_eq!(read(&restored, &index), Some(certificate.clone()));
        assert!(bootstrap(&mut restored, &certificate).is_none());
        let mut wrong_owner = index;
        wrong_owner.owner[0] ^= 1;
        assert!(read(&restored, &wrong_owner).is_none());
        assert!(!remove(&mut restored, &wrong_owner));
        // Even an otherwise decodable certificate cannot diverge from the
        // header commitment. Refusing an operation restores the original row.
        assert!(!authority_row_transaction(|| {
            let mut corrupted = certificate.clone();
            corrupted.transport_signature[0] ^= 1;
            restored.insert(&index.node, &corrupted);
            assert!(read(&restored, &index).is_none());
            assert!(!remove(&mut restored, &index));
            false
        }));
        assert_eq!(read(&restored, &index), Some(certificate));
        assert!(remove(&mut restored, &index));
        assert!(read(&restored, &index).is_none());
        assert!(!remove(&mut restored, &index));
        mock::reset();
    }

    #[test]
    fn generated_authority_loader_initializes_certificate_namespace_without_seeding() {
        use vos::{Actor, storage::mock};
        mock::reset();
        let config = configuration();
        let installation = config.encode();
        let mut actor = <SystemAuthority as Actor>::__load_agent_state(
            Some(&installation), None, None, None,
        ).unwrap();
        assert_eq!(SystemAuthority::STATE_SCHEMA_VERSION, 20);
        assert!(actor.node_certificates.is_empty());
        let seed = NodeOwnerRow::from_enrollment(config.bootstrap_node_enrollment());
        assert!(node_storage::bootstrap(&mut actor.node_certificates, &seed).is_some());
        let linear = actor.__save_agent_lane(vos::agent::StateLane::Linear);
        mock::commit_dispatch();
        let mut restored = <SystemAuthority as Actor>::__load_agent_state(
            Some(&installation), Some(&linear), None, None,
        ).unwrap();
        assert_eq!(restored.node_certificates.get(&seed.node), Some(seed.clone()));
        // Restore must leave existing certificates untouched, even if corrupt;
        // validation refuses corruption rather than repairing it in a constructor.
        let mut corrupted = seed.clone();
        corrupted.transport_signature[0] ^= 1;
        restored.node_certificates.insert(&seed.node, &corrupted);
        mock::commit_dispatch();
        let reopened = <SystemAuthority as Actor>::__load_agent_state(
            Some(&installation), Some(&linear), None, None,
        ).unwrap();
        assert_eq!(reopened.node_certificates.get(&seed.node), Some(corrupted));
        assert!(node_storage::read(
            &reopened.node_certificates, &node_storage::NodeIndexRow::of_verified(&seed),
        ).is_none());
        assert_eq!(reopened.__save_agent_lane(vos::agent::StateLane::Linear), linear);
        mock::reset();
    }

    #[test]
    fn node_table_bootstrap_is_lazy_atomic_and_not_recreated_on_restore() {
        use node_storage::{NodeRows, NodeTable};
        use vos::{Decode, Encode};
        use vos::storage::mock;
        mock::reset();
        let config = configuration();
        let seed = NodeOwnerRow::from_enrollment(config.bootstrap_node_enrollment());
        let next = NodeOwnerRow::from_enrollment(signed_node_enrollment(
            SpaceId(config.space), ADMIN_PRINCIPAL, 0x32,
        ));
        let mut table = NodeTable::pending_bootstrap(seed.clone());
        // Constructor/query access needs no initialized handle and writes no rows.
        let mut rows = NodeRows::default();
        assert_eq!(table.get(&rows, seed.node), Some(seed.clone()));
        assert_eq!(table.owner(seed.node), Some(seed.owner));
        rows.__init(b"test/authority-node-table/");
        let pending = table.clone();
        assert!(!table.insert_verified(&mut rows, &seed));
        assert_eq!(table, pending);
        assert!(rows.is_empty());
        // A conflicting storage generation must not consume the inline seed.
        rows.insert(&next.node, &next);
        assert!(!table.insert_verified(&mut rows, &next));
        assert_eq!(table, pending);
        assert!(rows.get(&seed.node).is_none());
        rows.remove(&next.node);
        // Later Authority refusal rolls back both staged bootstrap certificates;
        // the caller publishes its inline candidate only on acceptance.
        let mut candidate = table.clone();
        assert!(!authority_row_transaction(|| {
            assert!(candidate.insert_verified(&mut rows, &next));
            false
        }));
        assert!(rows.is_empty());
        assert_eq!(table, pending);
        assert!(table.insert_verified(&mut rows, &next));
        assert!(table.index_is_valid());
        let encoded = table.encode();
        mock::commit_dispatch();
        let restored = NodeTable::try_decode(&encoded).unwrap();
        assert_eq!(restored, table);
        assert_eq!(restored.get(&rows, seed.node), Some(seed.clone()));
        assert_eq!(restored.get(&rows, next.node), Some(next.clone()));
        rows.remove(&seed.node);
        assert!(restored.get(&rows, seed.node).is_none());
        // Owner-only projections need no certificate fetch, but removal must
        // verify the actual row and refuse a missing/substituted certificate.
        assert_eq!(table.owner(seed.node), Some(seed.owner));
        let before = table.clone();
        assert!(!table.remove(&mut rows, seed.node, seed.owner));
        assert_eq!(table, before);
        assert!(!table.remove(&mut rows, next.node, [0xff; 32]));
        assert_eq!(table, before);
        assert!(table.remove(&mut rows, next.node, next.owner));
        assert_eq!(table.owner(next.node), None);
        mock::reset();
    }

    #[test]
    fn node_table_full_capacity_uses_compact_header_and_refuses_overflow() {
        use node_storage::{NodeRows, NodeTable};
        use vos::{Decode, Encode};
        use vos::storage::mock;
        mock::reset();
        let config = configuration();
        let seed = NodeOwnerRow::from_enrollment(config.bootstrap_node_enrollment());
        let mut table = NodeTable::pending_bootstrap(seed.clone());
        let mut rows = NodeRows::default();
        rows.__init(b"test/authority-node-capacity/");
        for ordinal in 0..MAX_AUTHORITY_NODES - 1 {
            let mut key_bytes = [0x53; 32];
            key_bytes[..8].copy_from_slice(&(ordinal as u64).to_le_bytes());
            let key = SigningKey::from_bytes(&key_bytes);
            let owner_slot = ordinal % MAX_AUTHORITY_PRINCIPALS;
            let owner = if owner_slot == 0 { ADMIN_PRINCIPAL }
                else { PrincipalId([0x80 + owner_slot as u8; 32]) };
            let mut enrollment = NodeEncryptionEnrollment::from_keys(
                SpaceId(config.space), owner,
                key.verifying_key().to_bytes(), [0x42; 32], [1; PRIVATE_SIGNATURE_BYTES],
            );
            resign_node_enrollment(&mut enrollment, &key);
            let certificate = NodeOwnerRow::from_enrollment(enrollment);
            assert!(table.insert_verified(&mut rows, &certificate));
        }
        assert_eq!(rows.len() as usize, MAX_AUTHORITY_NODES);
        assert!(table.index_is_valid());
        let encoded = table.encode();
        assert!(encoded.len() < 36 * 1024, "node index alone must remain compact");
        let before = table.clone();
        let mut overflow = seed.clone();
        overflow.node = [0xfe; 32];
        assert!(!table.insert_verified(&mut rows, &overflow));
        assert_eq!(table, before);
        assert_eq!(rows.len() as usize, MAX_AUTHORITY_NODES);
        mock::commit_dispatch();
        let restored = NodeTable::try_decode(&encoded).unwrap();
        assert_eq!(restored, table);
        assert_eq!(restored.get(&rows, seed.node), Some(seed));
        mock::reset();
    }

    #[test]
    fn node_table_owner_slot_compaction_preserves_certificate_bindings() {
        use node_storage::{NodeRows, NodeTable};
        use vos::storage::mock;
        mock::reset();
        let config = configuration();
        let seed = NodeOwnerRow::from_enrollment(config.bootstrap_node_enrollment());
        let next = NodeOwnerRow::from_enrollment(signed_node_enrollment(
            SpaceId(config.space), PrincipalId([0xcc; 32]), 0x32,
        ));
        let last = NodeOwnerRow::from_enrollment(signed_node_enrollment(
            SpaceId(config.space), PrincipalId([0xdd; 32]), 0x33,
        ));
        let mut rows = NodeRows::default();
        rows.__init(b"test/authority-node-owners/");
        let mut table = NodeTable::pending_bootstrap(seed.clone());
        assert!(table.insert_verified(&mut rows, &next));
        assert!(table.insert_verified(&mut rows, &last));
        assert!(table.remove(&mut rows, seed.node, seed.owner));
        assert!(table.index_is_valid());
        assert_eq!(table.owner(next.node), Some(next.owner));
        assert_eq!(table.owner(last.node), Some(last.owner));
        assert_eq!(table.get(&rows, next.node), Some(next.clone()));
        assert_eq!(table.get(&rows, last.node), Some(last.clone()));
        assert!(table.remove(&mut rows, next.node, next.owner));
        assert_eq!(table.get(&rows, last.node), Some(last.clone()));
        assert!(table.remove(&mut rows, last.node, last.owner));
        assert!(table.index_is_valid());
        assert!(rows.is_empty());
        // An empty, already-materialized table does not recreate bootstrap.
        assert_eq!(table.get(&rows, seed.node), None);
        mock::reset();
    }

    #[test]
    fn authority_refusal_rolls_back_rows_without_changing_reply_conventions() {
        use vos::storage::{StorageMap, mock};
        mock::reset();
        let mut rows = StorageMap::<u64, u64>::default();
        rows.__init(b"test/authority-transaction/");
        assert!(authority_row_transaction(|| {
            rows.insert(&1, &41);
            true
        }));
        assert!(!authority_row_transaction(|| {
            rows.insert(&1, &99);
            rows.insert(&2, &99);
            false
        }));
        assert_eq!(rows.get(&1), Some(41));
        assert_eq!(rows.get(&2), None);
        let refusal: Vec<u8> = authority_row_transaction(|| {
            assert!(authority_row_transaction(|| {
                rows.remove(&1);
                true
            }));
            Vec::new()
        });
        assert!(refusal.is_empty());
        assert_eq!(rows.get(&1), Some(41));
        assert_eq!(rows.len(), 1);
        let reply = authority_row_transaction(|| {
            rows.insert(&2, &42);
            vec![1, 2, 3]
        });
        assert_eq!(reply, vec![1, 2, 3]);
        assert_eq!(rows.get(&2), Some(42));
        mock::reset();
    }
    use alloc::boxed::Box;
    use alloc::vec;
    use ed25519_dalek::{Signer as _, SigningKey};
    use std::collections::BTreeMap;
    use vos::Message;
    use vos::abi::service::ServiceId;
    use vos::agent::StateLane;
    use vos::agent_sdk::authority::{
        AuthorityCredentialKind, AuthorityOperationKind, AuthorityReceipt,
        AuthorityReceiptSelector, MAX_AUTHORITY_PROJECTION_PAGE_ENTRIES, ManagementApplicationAck,
        ManagementApproval,
    };
    use vos::agent_sdk::authority_operation::{
        AuthorityOperationApproval, AuthorityOperationCall, AuthorityOperationIntent,
        AuthorityOperationIssuanceAck, PrivateControlApplicationAck, PrivateControlApplicationFact,
        private_member_set_commitment,
    };
    use vos::agent_sdk::catalog::{
        CatalogActorTarget, CatalogAlias, CatalogMutationKind, CatalogPublication,
    };
    use vos::agent_sdk::contract::{ActorPackageContract, RuntimePackageContract};
    use vos::agent_sdk::private::PrivateActorLifecycleKind;
    use vos::agent_sdk::{
        ActorEntry, AgentDescriptor, AgentIdentity, AgentReplica, BlobRef, InstallActor,
        InstallationData, InstallationId, InvocationOrigin, InvocationRoleClaims, LaneSet,
        MethodMode, NodeId, ProofSystemSet, ReplicaRole, RoleId, RuntimeCapabilities,
        RuntimeRequirements, UpgradeActor,
    };

    const ADMIN_PRINCIPAL: PrincipalId = PrincipalId([0x31; 32]);
    const ADMIN_NODE: NodeId = NodeId([
        0x14, 0x74, 0xc7, 0x7f, 0xe2, 0x1c, 0x0e, 0x0e, 0x49, 0x7f, 0xe5, 0x18, 0x98, 0x22, 0x97,
        0x7b, 0x51, 0xb6, 0xdf, 0xc1, 0xc0, 0xc2, 0x55, 0x6a, 0x29, 0xbf, 0x66, 0xf7, 0x4e, 0xb0,
        0x54, 0xf8,
    ]);
    const OBSERVED_SLOT: u64 = 100;

    fn signing(byte: u8) -> SigningKey {
        SigningKey::from_bytes(&[byte; 32])
    }

    fn signed_node_enrollment(
        space: SpaceId,
        principal: PrincipalId,
        signing_byte: u8,
    ) -> NodeEncryptionEnrollment {
        let key = signing(signing_byte);
        let encryption_byte = signing_byte.wrapping_add(1) & 0x7f;
        let encryption_byte = if encryption_byte < 2 {
            2
        } else {
            encryption_byte
        };
        let mut enrollment = NodeEncryptionEnrollment::from_keys(
            space,
            principal,
            key.verifying_key().to_bytes(),
            [encryption_byte; 32],
            [1; PRIVATE_SIGNATURE_BYTES],
        );
        resign_node_enrollment(&mut enrollment, &key);
        enrollment
    }

    fn resign_node_enrollment(enrollment: &mut NodeEncryptionEnrollment, key: &SigningKey) {
        enrollment.transport_signature = [1; PRIVATE_SIGNATURE_BYTES];
        enrollment.transport_signature = key.sign(&enrollment.signing_bytes()).to_bytes();
    }

    fn node_enrollment(
        config: SystemAuthorityConfiguration,
        principal: PrincipalId,
    ) -> NodeEncryptionEnrollment {
        signed_node_enrollment(SpaceId(config.space), principal, principal.0[0])
    }

    fn node_for_principal(config: SystemAuthorityConfiguration, principal: PrincipalId) -> NodeId {
        node_enrollment(config, principal).node
    }

    fn configuration() -> SystemAuthorityConfiguration {
        let authority_key = signing(0x71).verifying_key().to_bytes();
        let space = SpaceId([0x11; 32]);
        let creation_nonce = Hash([0x12; 32]);
        let bootstrap_enrollment = signed_node_enrollment(space, ADMIN_PRINCIPAL, 0x31);
        assert_eq!(bootstrap_enrollment.node, ADMIN_NODE);
        SystemAuthorityConfiguration {
            space: space.0,
            system_agent: AgentId::derive(space, ADMIN_PRINCIPAL, creation_nonce.as_bytes()).0,
            system_runtime_deployment: [0x13; 32],
            system_runtime_program: [0x19; 32],
            system_runtime_producer: [0x1a; 32],
            system_transition_producer: [0x1c; 32],
            system_runtime_package: AuthorityBlobRow {
                hash: [0x1b; 32],
                len: 1_024,
            },
            binding: AuthorityBindingState {
                policy: [0x14; 32],
                issuer: AuthorityIssuerState {
                    principal: [0x15; 32],
                    actor: [0x16; 32],
                    deployment: [0x17; 32],
                    program: [0x18; 32],
                    producer: ProducerId::of_public_key(&authority_key).0,
                },
                public_key: authority_key,
                initial_epoch: 7,
            },
            bootstrap_authorization_high_water: ROOT_BOOTSTRAP_AUTHORIZATION_HIGH_WATER,
            bootstrap_system_agent_creation_nonce: creation_nonce.0,
            bootstrap_principal: ADMIN_PRINCIPAL.0,
            bootstrap_replica_principal: PrincipalId::of_public_key(
                &bootstrap_enrollment.transport_public_key,
            )
            .0,
            bootstrap_credential_public_key: signing(0x21).verifying_key().to_bytes(),
            bootstrap_credential_kind: 0,
            bootstrap_node: bootstrap_enrollment.node.0,
            bootstrap_node_transport_public_key: bootstrap_enrollment.transport_public_key,
            bootstrap_node_transport_peer_id: bootstrap_enrollment.transport_peer_id,
            bootstrap_node_encryption_public_key: bootstrap_enrollment.encryption_public_key,
            bootstrap_node_transport_signature: bootstrap_enrollment.transport_signature,
        }
    }

    fn actor() -> SystemAuthority {
        vos::storage::mock::reset();
        SystemAuthority::new(&configuration().encode())
    }

    fn authority_target(config: SystemAuthorityConfiguration) -> AuthorityActorTarget {
        AuthorityActorTarget {
            space: SpaceId(config.space),
            system_agent: AgentId(config.system_agent),
            system_runtime_deployment: DeploymentId(config.system_runtime_deployment),
            binding: config.binding.sdk(),
        }
    }

    fn descriptor(
        config: SystemAuthorityConfiguration,
        owner: PrincipalId,
        profile: AgentProfile,
        nonce_byte: u8,
    ) -> AgentDescriptor {
        let creation_nonce = Hash([nonce_byte; 32]);
        let space = SpaceId(config.space);
        let agent = AgentId::derive(space, owner, creation_nonce.as_bytes());
        let replica_role = match profile {
            AgentProfile::Private => ReplicaRole::Observer,
            AgentProfile::Local | AgentProfile::Shared => ReplicaRole::Voter,
        };
        AgentDescriptor {
            identity: AgentIdentity {
                space,
                agent,
                owner,
                profile,
                runtime_deployment: DeploymentId([nonce_byte.wrapping_add(1); 32]),
                runtime_program: ProgramId([nonce_byte.wrapping_add(2); 32]),
                runtime_producer: ProducerId([nonce_byte.wrapping_add(3); 32]),
                transition_producer: ProducerId([nonce_byte.wrapping_add(0x20); 32]),
            },
            creation_nonce,
            authority: config.binding.sdk(),
            private_recovery: (profile == AgentProfile::Private).then_some(
                vos::agent_sdk::PrivateRecoveryBinding {
                    signing_key_commitment: recovery_signing_public_key_commitment(
                        &signing(nonce_byte.wrapping_add(4))
                            .verifying_key()
                            .to_bytes(),
                    ),
                    // Keep every marker-derived descriptor fixture on a
                    // canonical X25519 public key, including marker bytes with
                    // the high bit set.
                    encryption_public_key: [0x42; 32],
                },
            ),
            runtime_package: BlobRef::of_bytes(&[nonce_byte]),
            runtime_contract: RuntimePackageContract::canonical(),
            capabilities: RuntimeCapabilities::standard(),
            replicas: vec![AgentReplica {
                node: node_for_principal(config, owner),
                principal: owner,
                role: replica_role,
            }],
        }
    }

    fn target_for(descriptor: &AgentDescriptor) -> vos::agent_sdk::authority::ManagedAgentTarget {
        vos::agent_sdk::authority::ManagedAgentTarget {
            space: descriptor.identity.space,
            agent: descriptor.identity.agent,
            owner: descriptor.identity.owner,
            profile: descriptor.identity.profile,
            runtime_deployment: descriptor.identity.runtime_deployment,
            transition_producer: descriptor.identity.transition_producer,
        }
    }

    fn system_target(
        config: SystemAuthorityConfiguration,
    ) -> vos::agent_sdk::authority::ManagedAgentTarget {
        vos::agent_sdk::authority::ManagedAgentTarget {
            space: SpaceId(config.space),
            agent: AgentId(config.system_agent),
            owner: PrincipalId(config.bootstrap_principal),
            profile: AgentProfile::Shared,
            runtime_deployment: DeploymentId(config.system_runtime_deployment),
            transition_producer: ProducerId(config.system_transition_producer),
        }
    }

    fn actor_install(agent: AgentId, name: &str, marker: u8) -> InstallActor {
        let package = BlobRef::of_bytes(&[marker, 1]);
        let agent_schema = BlobRef::of_bytes(&[marker, 2]);
        let method_policy = BlobRef::of_bytes(&[marker, 3]);
        let installation_bytes = vec![marker, 4];
        let installation_data = InstallationData {
            reference: BlobRef::of_bytes(&installation_bytes),
            bytes: installation_bytes,
        };
        let lanes = LaneSet::of(vos::agent_sdk::StateLane::Merge);
        let entry = ActorEntry {
            actor: ActorId::top_level(agent, name),
            name: name.into(),
            parent: None,
            deployment: DeploymentId([marker; 32]),
            program: ProgramId([marker.wrapping_add(1); 32]),
            package: package.clone(),
            agent_schema: agent_schema.clone(),
            method_policy: method_policy.clone(),
            constructor_abi: Hash([marker.wrapping_add(2); 32]),
            installation_data: Some(installation_data.reference.clone()),
            state_layout: Hash([marker.wrapping_add(3); 32]),
            lanes,
            suspended: false,
        };
        InstallActor {
            installation_id: InstallationId([marker.wrapping_add(4); 32]),
            registry_reservation: Hash([marker.wrapping_add(5); 32]),
            producer: ProducerId([marker.wrapping_add(6); 32]),
            package,
            agent_schema,
            method_policy,
            constructor_abi: entry.constructor_abi,
            installation_data: Some(installation_data),
            state_layout: entry.state_layout,
            contract: ActorPackageContract::canonical(),
            requirements: RuntimeRequirements {
                lanes,
                scheduling: false,
                proof_systems: ProofSystemSet::EMPTY,
            },
            entry,
        }
    }

    fn catalog_install(config: SystemAuthorityConfiguration) -> InstallActor {
        actor_install(AgentId(config.system_agent), "system-catalog", 0x24)
    }

    fn actor_upgrade(install: &InstallActor, marker: u8) -> UpgradeActor {
        UpgradeActor {
            actor: install.entry.actor,
            from_deployment: install.entry.deployment,
            to_deployment: DeploymentId([marker; 32]),
            // The fixture is stateful, so the runtime's no-migration rule
            // requires an exact program identity across an in-place upgrade.
            to_program: install.entry.program,
            producer: ProducerId([marker.wrapping_add(1); 32]),
            package: BlobRef::of_bytes(&[marker, 1]),
            agent_schema: BlobRef::of_bytes(&[marker, 2]),
            method_policy: BlobRef::of_bytes(&[marker, 3]),
            constructor_abi: install.constructor_abi,
            state_layout: install.state_layout,
            contract: install.contract,
            requirements: install.requirements,
        }
    }

    fn assert_installed_projection(
        row: &ManagedActorRow,
        agent: AgentId,
        install: &InstallActor,
        root_provenance: bool,
    ) {
        assert_eq!(row.agent, agent.0);
        assert_eq!(row.actor, install.entry.actor.0);
        assert_eq!(row.name, install.entry.name);
        assert_eq!(row.parent, install.entry.parent.map(|parent| parent.0));
        assert_eq!(row.deployment, install.entry.deployment.0);
        assert_eq!(row.program, install.entry.program.0);
        assert_eq!(row.producer, install.producer.0);
        assert_eq!(row.package, authority_blob(&install.package));
        assert_eq!(row.agent_schema, authority_blob(&install.agent_schema));
        assert_eq!(row.method_policy, authority_blob(&install.method_policy));
        assert_eq!(row.constructor_abi, install.constructor_abi.0);
        assert_eq!(
            row.installation_data,
            install
                .installation_data
                .as_ref()
                .map(|data| authority_blob(&data.reference))
        );
        assert_eq!(row.state_layout, install.state_layout.0);
        assert_eq!(row.lanes, install.requirements.lanes.bits());
        assert_eq!(row.scheduling, install.requirements.scheduling);
        assert_eq!(
            row.proof_systems,
            install
                .requirements
                .proof_systems
                .as_slice()
                .iter()
                .map(|system| system.0)
                .collect::<Vec<_>>()
        );
        assert_eq!(row.actor_abi, install.contract.actor_abi);
        assert_eq!(row.root_provenance, root_provenance);
        assert!(!row.suspended);
        assert_eq!(row.installation_id, install.installation_id.0);
        assert_eq!(row.registry_reservation, install.registry_reservation.0);
        assert_eq!(
            row.install_request,
            ManagementRequest::Install(Box::new(install.clone()))
                .commitment()
                .0
        );
    }

    #[allow(clippy::too_many_arguments)]
    fn credential_call(
        config: SystemAuthorityConfiguration,
        key: &SigningKey,
        principal: PrincipalId,
        node: Option<NodeId>,
        invocation_byte: u8,
        managed: vos::agent_sdk::authority::ManagedAgentTarget,
        request: ManagementRequest,
    ) -> AuthorityCredentialCall {
        let public_key = key.verifying_key().to_bytes();
        let plan = request
            .authorization_plan()
            .expect("management credential fixtures must be mutating");
        let mut call = AuthorityCredentialCall {
            invocation: InvocationId::ZERO,
            authority: authority_target(config),
            managed,
            principal,
            credential: CredentialId::of_public_key(&public_key),
            request_sequence: NonZeroU64::new(1).unwrap(),
            credential_public_key: public_key,
            authenticated_node: node,
            requested_valid_from: 1,
            requested_expires_at: 10_000,
            plan,
            signature: [1; 64],
        };
        let _ = invocation_byte;
        call.invocation = call.expected_invocation();
        resign(&mut call, key);
        call
    }

    fn create_call(
        config: SystemAuthorityConfiguration,
        key: &SigningKey,
        principal: PrincipalId,
        node: Option<NodeId>,
        invocation_byte: u8,
        profile: AgentProfile,
        nonce_byte: u8,
    ) -> AuthorityCredentialCall {
        let descriptor = descriptor(config, principal, profile, nonce_byte);
        let managed = target_for(&descriptor);
        credential_call(
            config,
            key,
            principal,
            node,
            invocation_byte,
            managed,
            ManagementRequest::Create(Box::new(descriptor)),
        )
    }

    fn resign(call: &mut AuthorityCredentialCall, key: &SigningKey) {
        call.signature = [1; 64];
        call.signature = key.sign(&call.signing_bytes()).to_bytes();
    }

    fn refresh_management_call(call: &mut AuthorityCredentialCall, key: &SigningKey) {
        call.invocation = call.expected_invocation();
        resign(call, key);
    }

    fn prepare_management_call(
        actor: &SystemAuthority,
        call: &mut AuthorityCredentialCall,
        key: &SigningKey,
    ) {
        let index = credential_index(&actor.state, call.credential)
            .expect("fixture credential must already be enrolled");
        call.request_sequence = NonZeroU64::new(
            actor.state.credentials[index]
                .management_request_high_water
                .checked_add(1)
                .expect("fixture management sequence must not exhaust"),
        )
        .unwrap();
        refresh_management_call(call, key);
    }

    fn context(call: &AuthorityCredentialCall) -> InvocationContext {
        InvocationContext {
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
            observed_slot: OBSERVED_SLOT,
        }
    }

    fn dispatch_bytes(
        actor: &mut SystemAuthority,
        bytes: Vec<u8>,
        invocation_context: Option<InvocationContext>,
    ) -> Vec<u8> {
        let mut ctx = Context::new(ServiceId(0));
        if let Some(invocation_context) = invocation_context {
            ctx.__set_agent_invocation_context(invocation_context);
        }
        block_on(<SystemAuthority as Message<Authorize>>::handle(
            actor,
            Authorize { call: bytes },
            &mut ctx,
        ))
    }

    fn dispatch(actor: &mut SystemAuthority, call: &AuthorityCredentialCall) -> Vec<u8> {
        dispatch_bytes(
            actor,
            call.encode().expect("valid ACC3 fixture"),
            Some(context(call)),
        )
    }

    fn operation_call(
        config: SystemAuthorityConfiguration,
        key: &SigningKey,
        principal: PrincipalId,
        node: Option<NodeId>,
        invocation_byte: u8,
        intent: AuthorityOperationIntent,
    ) -> AuthorityOperationCall {
        let public_key = key.verifying_key().to_bytes();
        let authentication = match node {
            Some(node) => AuthorityIngressAuthentication::SshNodeAttestation {
                credential_public_key: public_key,
                node,
                request_binding: Hash::digest(
                    b"vos/test/system-authority/ssh-request-binding/v1",
                    &[&principal.0, &[invocation_byte]],
                ),
                signature: [1; 64],
            },
            None => AuthorityIngressAuthentication::ApiCredentialSignature {
                credential_public_key: public_key,
                signature: [1; 64],
            },
        };
        let mut call = AuthorityOperationCall {
            invocation: InvocationId::ZERO,
            authority: authority_target(config),
            principal,
            credential: CredentialId::of_public_key(&public_key),
            request_sequence: NonZeroU64::new(1).unwrap(),
            authentication,
            requested_valid_from: 1,
            requested_expires_at: 10_000,
            intent,
        };
        call.invocation = call.expected_invocation();
        resign_operation_call(&mut call, key);
        call
    }

    fn invoke_operation_call(
        config: SystemAuthorityConfiguration,
        key: &SigningKey,
        principal: PrincipalId,
        node: Option<NodeId>,
        invocation_byte: u8,
        operation_invocation_byte: u8,
        managed: vos::agent_sdk::authority::ManagedAgentTarget,
        installed: &InstallActor,
    ) -> AuthorityOperationCall {
        let public_key = key.verifying_key().to_bytes();
        operation_call(
            config,
            key,
            principal,
            node,
            invocation_byte,
            AuthorityOperationIntent::InvokeActor {
                managed,
                operation_invocation: InvocationId([operation_invocation_byte; 32]),
                actor: installed.entry.actor,
                actor_deployment: installed.entry.deployment,
                work: Hash([operation_invocation_byte.wrapping_add(1); 32]),
                origin: InvocationOrigin {
                    principal: Some(principal),
                    transport_node: node,
                    credential: Some(CredentialId::of_public_key(&public_key)),
                    actor: None,
                    capability: None,
                },
                roles: InvocationRoleClaims::none(),
            },
        )
    }

    fn resign_operation_call(call: &mut AuthorityOperationCall, key: &SigningKey) {
        let signer = match call.authentication {
            AuthorityIngressAuthentication::ApiCredentialSignature { .. } => key.clone(),
            AuthorityIngressAuthentication::SshNodeAttestation { node, .. }
                if node == ADMIN_NODE =>
            {
                signing(0x31)
            }
            AuthorityIngressAuthentication::SshNodeAttestation { .. } => {
                signing(call.principal.0[0])
            }
        };
        let signature = signer.sign(&call.signing_bytes()).to_bytes();
        match &mut call.authentication {
            AuthorityIngressAuthentication::ApiCredentialSignature {
                signature: value, ..
            }
            | AuthorityIngressAuthentication::SshNodeAttestation {
                signature: value, ..
            } => *value = signature,
        }
    }

    fn resign_ssh_operation_call(call: &mut AuthorityOperationCall, attesting_key: &SigningKey) {
        let AuthorityIngressAuthentication::SshNodeAttestation { signature, .. } =
            &mut call.authentication
        else {
            panic!("fixture must use SSH Node attestation")
        };
        *signature = [1; 64];
        let signature = attesting_key.sign(&call.signing_bytes()).to_bytes();
        let AuthorityIngressAuthentication::SshNodeAttestation {
            signature: value, ..
        } = &mut call.authentication
        else {
            unreachable!()
        };
        *value = signature;
    }

    fn prepare_operation_call(
        actor: &SystemAuthority,
        call: &mut AuthorityOperationCall,
        key: &SigningKey,
    ) {
        let index = credential_index(&actor.state, call.credential)
            .expect("fixture credential must already be enrolled");
        call.request_sequence = NonZeroU64::new(
            actor.state.credentials[index]
                .operation_request_high_water
                .checked_add(1)
                .expect("fixture operation sequence must not exhaust"),
        )
        .unwrap();
        call.invocation = call.expected_invocation();
        resign_operation_call(call, key);
    }

    fn operation_context(call: &AuthorityOperationCall) -> InvocationContext {
        InvocationContext {
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
            observed_slot: OBSERVED_SLOT,
        }
    }

    fn dispatch_operation_bytes(
        actor: &mut SystemAuthority,
        bytes: Vec<u8>,
        invocation_context: Option<InvocationContext>,
    ) -> Vec<u8> {
        let mut ctx = Context::new(ServiceId(0));
        if let Some(invocation_context) = invocation_context {
            ctx.__set_agent_invocation_context(invocation_context);
        }
        block_on(<SystemAuthority as Message<AuthorizeOperation>>::handle(
            actor,
            AuthorizeOperation { call: bytes },
            &mut ctx,
        ))
    }

    fn dispatch_operation(actor: &mut SystemAuthority, call: &AuthorityOperationCall) -> Vec<u8> {
        dispatch_operation_bytes(
            actor,
            call.encode().expect("valid AOC5 fixture"),
            Some(operation_context(call)),
        )
    }

    fn operation_issuance_ack(
        config: SystemAuthorityConfiguration,
        call: &AuthorityOperationCall,
        approval: &AuthorityOperationApproval,
    ) -> AuthorityOperationIssuanceAck {
        let mut receipt = AuthorityReceipt {
            selector: approval.selector.clone(),
            public_key: config.binding.public_key,
            signature: [1; 64],
        };
        resign_receipt(&mut receipt);
        let mut ack = AuthorityOperationIssuanceAck {
            authorization_invocation: call.invocation,
            acknowledgement_invocation: approval.acknowledgement_invocation,
            authority: call.authority,
            operation_call: call.commitment(),
            approval: approval.commitment(),
            authorization_sequence: approval.authorization_sequence,
            receipt,
            issued_at: OBSERVED_SLOT,
            signature: [1; 64],
        };
        resign_operation_ack(&mut ack);
        ack
    }

    fn resign_operation_ack(ack: &mut AuthorityOperationIssuanceAck) {
        ack.signature = [1; 64];
        ack.signature = signing(0x71).sign(&ack.signing_bytes()).to_bytes();
    }

    fn operation_ack_context(ack: &AuthorityOperationIssuanceAck) -> InvocationContext {
        InvocationContext {
            invocation: ack.acknowledgement_invocation,
            actor: ack.authority.binding.issuer.actor,
            mode: MethodMode::Linear,
            origin: InvocationOrigin::anonymous(),
            roles: InvocationRoleClaims::none(),
            observed_slot: ack.issued_at,
        }
    }

    fn dispatch_operation_ack_bytes(
        actor: &mut SystemAuthority,
        bytes: Vec<u8>,
        invocation_context: Option<InvocationContext>,
    ) -> bool {
        let mut ctx = Context::new(ServiceId(0));
        if let Some(invocation_context) = invocation_context {
            ctx.__set_agent_invocation_context(invocation_context);
        }
        block_on(<SystemAuthority as Message<AcknowledgeIssuance>>::handle(
            actor,
            AcknowledgeIssuance { ack: bytes },
            &mut ctx,
        ))
    }

    fn dispatch_operation_ack(
        actor: &mut SystemAuthority,
        ack: &AuthorityOperationIssuanceAck,
    ) -> bool {
        dispatch_operation_ack_bytes(
            actor,
            ack.encode().expect("valid AOI1 fixture"),
            Some(operation_ack_context(ack)),
        )
    }

    fn authorize_and_issue_operation(
        actor: &mut SystemAuthority,
        call: &AuthorityOperationCall,
    ) -> (AuthorityOperationApproval, AuthorityOperationIssuanceAck) {
        let approval = AuthorityOperationApproval::decode(&dispatch_operation(actor, call))
            .expect("operation fixture must be authorized");
        let issuance = operation_issuance_ack(actor.configuration, call, &approval);
        assert!(dispatch_operation_ack(actor, &issuance));
        (approval, issuance)
    }

    fn private_application_fact(
        call: &AuthorityOperationCall,
        post_member_set: Hash,
        reopened_runtime_state: Hash,
        applied_at: u64,
    ) -> PrivateControlApplicationFact {
        let (operation, control, control_sequence, control_previous, epoch) = match &call.intent {
            AuthorityOperationIntent::InvitePrivateNode {
                control,
                control_sequence,
                control_previous,
                epoch,
                ..
            } => (
                AuthorityOperationKind::InvitePrivateNode,
                *control,
                *control_sequence,
                *control_previous,
                *epoch,
            ),
            AuthorityOperationIntent::RevokePrivateNode {
                control,
                control_sequence,
                control_previous,
                epoch,
                ..
            } => (
                AuthorityOperationKind::RevokePrivateNode,
                *control,
                *control_sequence,
                *control_previous,
                *epoch,
            ),
            AuthorityOperationIntent::RecoverPrivateAgent { proof } => (
                AuthorityOperationKind::RecoverPrivateAgent,
                proof.control,
                proof.control_sequence,
                proof.control_previous,
                proof.next_epoch,
            ),
            AuthorityOperationIntent::RotatePrivateKeys {
                control,
                control_sequence,
                control_previous,
                epoch,
                ..
            } => (
                AuthorityOperationKind::RotatePrivateKeys,
                *control,
                *control_sequence,
                *control_previous,
                *epoch,
            ),
            AuthorityOperationIntent::SetPrivateResourcePolicy {
                control,
                control_sequence,
                control_previous,
                ..
            } => (
                AuthorityOperationKind::SetPrivateResourcePolicy,
                *control,
                *control_sequence,
                *control_previous,
                0,
            ),
            AuthorityOperationIntent::PrivateActorLifecycle {
                control,
                control_sequence,
                control_previous,
                ..
            } => (
                AuthorityOperationKind::PrivateActorLifecycle,
                *control,
                *control_sequence,
                *control_previous,
                0,
            ),
            AuthorityOperationIntent::InvokeActor { .. }
            | AuthorityOperationIntent::Catalog { .. } => {
                panic!("Private application fixture requires a Private intent")
            }
        };
        PrivateControlApplicationFact {
            managed: call.intent.managed(),
            operation,
            control,
            control_sequence,
            control_previous,
            epoch,
            post_member_set,
            reopened_runtime_state,
            stable_projection: Hash::digest(
                b"vos/test/private-runtime-stable-projection",
                &[reopened_runtime_state.as_bytes()],
            ),
            reopened_control_head: control,
            applied_at,
        }
    }

    fn fixture_member_set(nodes: impl IntoIterator<Item = NodeId>) -> Hash {
        let mut nodes = nodes.into_iter().collect::<Vec<_>>();
        nodes.sort_unstable();
        private_member_set_commitment(nodes.into_iter())
            .expect("fixture member set is canonical and bounded")
    }

    fn private_application_ack(
        call: &AuthorityOperationCall,
        approval: &AuthorityOperationApproval,
        issuance: &AuthorityOperationIssuanceAck,
        application: PrivateControlApplicationFact,
    ) -> PrivateControlApplicationAck {
        let mut ack = PrivateControlApplicationAck {
            authorization_invocation: call.invocation,
            issuance_invocation: approval.acknowledgement_invocation,
            application_invocation: PrivateControlApplicationAck::derive_application_invocation(
                issuance,
            ),
            authority: call.authority,
            operation_call: call.commitment(),
            approval: approval.commitment(),
            issuance_ack: issuance.commitment(),
            authorization_sequence: approval.authorization_sequence,
            receipt: issuance.receipt.clone(),
            issued_at: issuance.issued_at,
            application,
            signature: [1; 64],
        };
        resign_private_application_ack(&mut ack);
        ack
    }

    fn resign_private_application_ack(ack: &mut PrivateControlApplicationAck) {
        ack.signature = [1; 64];
        ack.signature = signing(0x71).sign(&ack.signing_bytes()).to_bytes();
    }

    fn private_application_retirement_ack(
        call: &AuthorityOperationCall,
        approval: &AuthorityOperationApproval,
        issuance: &AuthorityOperationIssuanceAck,
        resolved_at: u64,
    ) -> PrivateControlApplicationRetirementAck {
        let mut ack = PrivateControlApplicationRetirementAck {
            authorization_invocation: call.invocation,
            issuance_invocation: approval.acknowledgement_invocation,
            application_invocation:
                PrivateControlApplicationRetirementAck::derive_application_invocation(issuance),
            authority: call.authority,
            operation_call: call.commitment(),
            approval: approval.commitment(),
            issuance_ack: issuance.commitment(),
            authorization_sequence: approval.authorization_sequence,
            receipt: issuance.receipt.clone(),
            issued_at: issuance.issued_at,
            resolved_at,
            signature: [1; 64],
        };
        resign_private_application_retirement_ack(&mut ack);
        ack
    }

    fn resign_private_application_retirement_ack(ack: &mut PrivateControlApplicationRetirementAck) {
        ack.signature = [1; 64];
        ack.signature = signing(0x71).sign(&ack.signing_bytes()).to_bytes();
    }

    fn private_application_context(ack: &PrivateControlApplicationAck) -> InvocationContext {
        InvocationContext {
            invocation: ack.application_invocation,
            actor: ack.authority.binding.issuer.actor,
            mode: MethodMode::Linear,
            origin: InvocationOrigin::anonymous(),
            roles: InvocationRoleClaims::none(),
            observed_slot: ack.application.applied_at,
        }
    }

    fn private_application_retirement_context(
        ack: &PrivateControlApplicationRetirementAck,
    ) -> InvocationContext {
        InvocationContext {
            invocation: ack.application_invocation,
            actor: ack.authority.binding.issuer.actor,
            mode: MethodMode::Linear,
            origin: InvocationOrigin::anonymous(),
            roles: InvocationRoleClaims::none(),
            observed_slot: ack.resolved_at,
        }
    }

    fn dispatch_private_application_bytes(
        actor: &mut SystemAuthority,
        bytes: Vec<u8>,
        invocation_context: Option<InvocationContext>,
    ) -> bool {
        let mut ctx = Context::new(ServiceId(0));
        if let Some(invocation_context) = invocation_context {
            ctx.__set_agent_invocation_context(invocation_context);
        }
        block_on(
            <SystemAuthority as Message<ResolvePrivateApplication>>::handle(
                actor,
                ResolvePrivateApplication { ack: bytes },
                &mut ctx,
            ),
        )
    }

    fn dispatch_private_application(
        actor: &mut SystemAuthority,
        ack: &PrivateControlApplicationAck,
    ) -> bool {
        dispatch_private_application_bytes(
            actor,
            ack.encode().expect("valid PCA2 fixture"),
            Some(private_application_context(ack)),
        )
    }

    fn dispatch_private_application_retirement(
        actor: &mut SystemAuthority,
        ack: &PrivateControlApplicationRetirementAck,
    ) -> bool {
        dispatch_private_application_bytes(
            actor,
            ack.encode().expect("valid PAR1 fixture"),
            Some(private_application_retirement_context(ack)),
        )
    }

    fn receipt_for(
        config: SystemAuthorityConfiguration,
        approval: &ManagementApproval,
        decision_sequence: u64,
    ) -> AuthorityReceipt {
        let actor = approval.plan.authority_actor();
        let mut receipt = AuthorityReceipt {
            selector: AuthorityReceiptSelector {
                policy: approval.authority.binding.policy,
                issuer: approval.authority.binding.issuer,
                space: approval.managed.space,
                agent: approval.managed.agent,
                operation: approval.plan.authority_operation(),
                runtime_deployment: approval.managed.runtime_deployment,
                actor: actor.map(|(actor, _)| actor),
                actor_deployment: actor.map(|(_, deployment)| deployment),
                evidence: approval.evidence.clone(),
                lane_roots: approval.lane_roots,
                epoch: approval.epoch,
                decision_sequence,
                acknowledged_through: decision_sequence - 1,
                valid_from: approval.valid_from,
                expires_at: approval.expires_at,
                request: approval.plan_commitment,
            },
            public_key: config.binding.public_key,
            signature: [1; 64],
        };
        receipt.signature = signing(0x71).sign(&receipt.signing_bytes()).to_bytes();
        receipt
    }

    fn application_ack(
        config: SystemAuthorityConfiguration,
        state: &AuthorityLinearState,
        call: &AuthorityCredentialCall,
        approval: &ManagementApproval,
    ) -> ManagementApplicationAck {
        let application = match &call.plan {
            ManagementAuthorizationPlan::Create { descriptor, .. } => {
                ManagementReply::Created(descriptor.identity.clone())
            }
            ManagementAuthorizationPlan::Install(install) => {
                ManagementReply::Installed(install.entry.clone())
            }
            ManagementAuthorizationPlan::UpgradeActor(upgrade) => {
                let index = managed_actor(state, call.managed.agent, upgrade.actor)
                    .expect("upgrade fixture actor must be installed");
                let row = upgraded_actor_row(&state.managed_actors[index], upgrade)
                    .expect("upgrade fixture must be valid");
                ManagementReply::Upgraded(
                    managed_actor_entry(&row).expect("upgrade fixture entry must be valid"),
                )
            }
            ManagementAuthorizationPlan::Suspend {
                actor,
                expected_deployment,
            }
            | ManagementAuthorizationPlan::Resume {
                actor,
                expected_deployment,
            } => {
                let index = managed_actor(state, call.managed.agent, *actor)
                    .expect("suspension fixture actor must be installed");
                let mut row = state.managed_actors[index].clone();
                assert_eq!(row.deployment, expected_deployment.0);
                row.suspended = matches!(&call.plan, ManagementAuthorizationPlan::Suspend { .. });
                let entry = managed_actor_entry(&row).expect("suspension fixture entry is valid");
                if row.suspended {
                    ManagementReply::Suspended(entry)
                } else {
                    ManagementReply::Resumed(entry)
                }
            }
            ManagementAuthorizationPlan::RemoveLeaf { actor, .. } => {
                ManagementReply::Removed(*actor)
            }
            ManagementAuthorizationPlan::UpgradeRuntime(_) => {
                let effect = reconstruction_effect(&config, state, call)
                    .expect("runtime-upgrade fixture must be permitted");
                let PendingManagementEffect::UpgradeRuntime {
                    agent,
                    to_deployment,
                    to_program,
                    producer,
                    ..
                } = effect
                else {
                    panic!("runtime-upgrade fixture must retain its exact effect");
                };
                let index = state
                    .managed_agents
                    .binary_search_by(|row| row.agent.cmp(&agent))
                    .expect("runtime-upgrade fixture Agent must exist");
                let mut row = state.managed_agents[index].clone();
                row.runtime_deployment = to_deployment;
                row.runtime_program = to_program;
                row.runtime_producer = producer;
                ManagementReply::RuntimeUpgraded(
                    managed_agent_identity(&config, &row)
                        .expect("runtime-upgrade fixture identity must be valid"),
                )
            }
            ManagementAuthorizationPlan::ChangeReplicas { .. } => {
                let effect = reconstruction_effect(&config, state, call)
                    .expect("replica-change fixture must be permitted");
                let PendingManagementEffect::ChangeReplicas { to_generation, .. } = effect else {
                    panic!("replica-change fixture must retain its exact effect");
                };
                ManagementReply::ReplicasChanged {
                    generation: Hash(to_generation),
                }
            }
        };
        let mut ack = ManagementApplicationAck {
            authorization_invocation: call.invocation,
            acknowledgement_invocation: approval.acknowledgement_invocation,
            authority: call.authority,
            managed: call.managed,
            credential_call: call.commitment(),
            approval: approval.commitment(),
            authorization_sequence: approval.authorization_sequence,
            request: approval.plan_commitment,
            application,
            receipt: receipt_for(config, approval, approval.authorization_sequence.get()),
            reopened_state: Hash([0x73; 32]),
            applied_at: approval.valid_from,
            signature: [1; 64],
        };
        resign_ack(&mut ack);
        ack
    }

    fn resign_receipt(receipt: &mut AuthorityReceipt) {
        receipt.signature = [1; 64];
        receipt.signature = signing(0x71).sign(&receipt.signing_bytes()).to_bytes();
    }

    fn resign_ack(ack: &mut ManagementApplicationAck) {
        ack.signature = [1; 64];
        ack.signature = signing(0x71).sign(&ack.signing_bytes()).to_bytes();
    }

    fn acknowledgement_context(ack: &ManagementApplicationAck) -> InvocationContext {
        InvocationContext {
            invocation: ack.acknowledgement_invocation,
            actor: ack.authority.binding.issuer.actor,
            mode: MethodMode::Linear,
            origin: InvocationOrigin::anonymous(),
            roles: InvocationRoleClaims::none(),
            observed_slot: ack.applied_at,
        }
    }

    fn dispatch_ack_bytes(
        actor: &mut SystemAuthority,
        bytes: Vec<u8>,
        invocation_context: Option<InvocationContext>,
    ) -> bool {
        let mut ctx = Context::new(ServiceId(0));
        if let Some(invocation_context) = invocation_context {
            ctx.__set_agent_invocation_context(invocation_context);
        }
        block_on(<SystemAuthority as Message<Finalize>>::handle(
            actor,
            Finalize { ack: bytes },
            &mut ctx,
        ))
    }

    #[allow(clippy::too_many_arguments)]
    fn admin_call(
        config: SystemAuthorityConfiguration,
        key: &SigningKey,
        administrator: PrincipalId,
        authenticated_node: NodeId,
        invocation_byte: u8,
        expected_generation: u64,
        operation: AuthorityAdminOperation,
    ) -> AuthorityAdminCall {
        let public_key = key.verifying_key().to_bytes();
        let mut call = AuthorityAdminCall {
            invocation: InvocationId::ZERO,
            authority: authority_target(config),
            administrator,
            credential: CredentialId::of_public_key(&public_key),
            request_sequence: NonZeroU64::new(expected_generation).unwrap(),
            credential_public_key: public_key,
            authenticated_node,
            observed_slot: OBSERVED_SLOT,
            expected_generation: NonZeroU64::new(expected_generation).unwrap(),
            operation,
            signature: [1; 64],
        };
        let _ = invocation_byte;
        call.invocation = call.expected_invocation();
        resign_admin(&mut call, key);
        call
    }

    fn resign_admin(call: &mut AuthorityAdminCall, key: &SigningKey) {
        call.signature = [1; 64];
        call.signature = key.sign(&call.signing_bytes()).to_bytes();
    }

    fn refresh_admin_call(call: &mut AuthorityAdminCall, key: &SigningKey) {
        call.invocation = call.expected_invocation();
        resign_admin(call, key);
    }

    fn prepare_admin_call(
        actor: &SystemAuthority,
        call: &mut AuthorityAdminCall,
        key: &SigningKey,
    ) {
        let index = credential_index(&actor.state, call.credential)
            .expect("fixture Admin credential must already be enrolled");
        call.request_sequence = NonZeroU64::new(
            actor.state.credentials[index]
                .admin_request_high_water
                .checked_add(1)
                .expect("fixture Admin sequence must not exhaust"),
        )
        .unwrap();
        refresh_admin_call(call, key);
    }

    fn admin_context(call: &AuthorityAdminCall) -> InvocationContext {
        InvocationContext {
            invocation: call.invocation,
            actor: call.authority.binding.issuer.actor,
            mode: MethodMode::Linear,
            origin: InvocationOrigin {
                principal: Some(call.administrator),
                transport_node: Some(call.authenticated_node),
                credential: Some(call.credential),
                actor: None,
                capability: None,
            },
            roles: InvocationRoleClaims::none(),
            observed_slot: call.observed_slot,
        }
    }

    fn dispatch_admin_bytes(
        actor: &mut SystemAuthority,
        bytes: Vec<u8>,
        invocation_context: Option<InvocationContext>,
    ) -> Vec<u8> {
        let mut ctx = Context::new(ServiceId(0));
        if let Some(invocation_context) = invocation_context {
            ctx.__set_agent_invocation_context(invocation_context);
        }
        block_on(<SystemAuthority as Message<Administer>>::handle(
            actor,
            Administer { call: bytes },
            &mut ctx,
        ))
    }

    fn dispatch_admin(actor: &mut SystemAuthority, call: &AuthorityAdminCall) -> Vec<u8> {
        dispatch_admin_bytes(
            actor,
            call.encode().expect("valid AAD4 fixture"),
            Some(admin_context(call)),
        )
    }

    fn dispatch_fixture_admin(
        actor: &mut SystemAuthority,
        _invocation: InvocationId,
        operation: AuthorityAdminOperation,
    ) {
        let key = signing(0x21);
        let mut call = admin_call(
            actor.configuration,
            &key,
            ADMIN_PRINCIPAL,
            ADMIN_NODE,
            1,
            actor.state.administration_generation,
            operation,
        );
        let caller = credential_index(&actor.state, call.credential).unwrap();
        call.request_sequence =
            NonZeroU64::new(actor.state.credentials[caller].admin_request_high_water + 1).unwrap();
        call.invocation = call.expected_invocation();
        resign_admin(&mut call, &key);
        assert!(!dispatch_admin(actor, &call).is_empty());
    }

    /// Build a canonical Admin history without revalidating its entire prefix
    /// after every fixture operation. Tests using this helper validate the
    /// completed state once, exercising the same replay invariant in linear
    /// rather than quadratic signature-verification time.
    fn record_fixture_admin(
        actor: &mut SystemAuthority,
        _invocation: InvocationId,
        operation: AuthorityAdminOperation,
    ) {
        let key = signing(0x21);
        let mut call = admin_call(
            actor.configuration,
            &key,
            ADMIN_PRINCIPAL,
            ADMIN_NODE,
            1,
            actor.state.administration_generation,
            operation,
        );
        let caller = credential_index(&actor.state, call.credential).unwrap();
        call.request_sequence =
            NonZeroU64::new(actor.state.credentials[caller].admin_request_high_water + 1).unwrap();
        call.invocation = call.expected_invocation();
        resign_admin(&mut call, &key);
        assert!(authenticated_admin(&actor.state, &call));
        let generation = call.next_generation().unwrap();
        actor.state.credentials[caller].admin_request_high_water = call.request_sequence.get();
        assert!(apply_admin_operation(
            &actor.configuration,
            &mut actor.state,
            &call.operation,
        ));
        actor.state.administration_generation = generation.get();
        let result = AuthorityAdminResult::from_call(call.clone()).unwrap();
        let call_bytes = call.encode().unwrap();
        let result_bytes = result.encode().unwrap();
        let index = actor
            .state
            .admin_retries
            .binary_search_by(|record| record.credential.cmp(&call.credential.0));
        let record = AdminRetryRecord {
            credential: call.credential.0,
            request_sequence: call.request_sequence.get(),
            invocation: call.invocation.0,
            call_commitment: call.commitment().0,
            call_bytes,
            result_commitment: result.commitment().0,
            result_bytes,
            generation: generation.get(),
        };
        match index {
            Ok(index) => actor.state.admin_retries[index] = record,
            Err(index) => actor.state.admin_retries.insert(index, record),
        }
        // Bulk fixtures deliberately seal once after the full prefix is
        // assembled. Re-hashing the growing identity projection here would
        // make the explicit table-bound test quadratic without exercising a
        // different replay invariant.
    }

    /// Apply one signed management request and its exact signed MAA2 while
    /// assembling a long finalized prefix. Only the newest exact pair is
    /// retained, matching production compaction, and the caller seals and
    /// validates the completed prefix once.
    fn record_fixture_finalized_management(
        actor: &mut SystemAuthority,
        mut call: AuthorityCredentialCall,
        key: &SigningKey,
    ) -> (AuthorityCredentialCall, Vec<u8>, ManagementApplicationAck) {
        prepare_management_call(actor, &mut call, key);
        let configuration = actor.configuration;
        let encoded_call = call.encode().unwrap();
        assert!(call.verify_with(&Ed25519CredentialVerifier).is_ok());
        assert!(!credential_has_pending_application(
            &actor.state,
            call.credential,
        ));
        let role = authenticated_role(&actor.state, &call).unwrap();
        let effect = policy_effect(&configuration, &actor.state, &call, role).unwrap();
        let authorization_sequence = actor.state.authorization_sequence.checked_add(1).unwrap();
        let sequence = NonZeroU64::new(authorization_sequence).unwrap();
        let (valid_from, expires_at) = narrowed_validity(&call, OBSERVED_SLOT).unwrap();
        let approval = ManagementApproval::from_call(
            &call,
            sequence,
            AuthorityEvidence {
                package: None,
                proof: None,
                commitment: Hash::digest(
                    EVIDENCE_DOMAIN,
                    &[
                        &configuration.binding.policy,
                        call.commitment().as_bytes(),
                        &[role as u8],
                        &authorization_sequence.to_le_bytes(),
                        &OBSERVED_SLOT.to_le_bytes(),
                    ],
                ),
            },
            AuthorityLaneRoots::default(),
            actor.state.epoch,
            valid_from,
            expires_at,
        )
        .unwrap();
        let approval_bytes = approval.encode().unwrap();
        let acknowledgement = application_ack(configuration, &actor.state, &call, &approval);
        assert!(acknowledgement.matches_pending(&call, &approval));
        assert!(
            acknowledgement
                .verify_with(&Ed25519CredentialVerifier)
                .is_ok()
        );
        let plan = application_plan(
            &configuration,
            &actor.state,
            &effect,
            &call,
            &acknowledgement,
        )
        .unwrap();
        let acknowledgement_bytes = acknowledgement.encode().unwrap();
        let latest = LatestManagementAckRow {
            credential: call.credential.0,
            request_sequence: call.request_sequence.get(),
            authorization_invocation: call.invocation.0,
            acknowledgement_invocation: approval.acknowledgement_invocation.0,
            authorization_sequence,
            credential_call: call.commitment().0,
            credential_call_bytes: encoded_call,
            approval: approval.commitment().0,
            request: acknowledgement.request.0,
            application: vos::agent_sdk::wire::management_reply_commitment(
                &acknowledgement.application,
            )
            .0,
            acknowledgement: acknowledgement.commitment().0,
            acknowledgement_bytes,
            reopened_state: acknowledgement.reopened_state.0,
            applied_at: acknowledgement.applied_at,
        };

        apply_application_plan(&mut actor.state, plan);
        actor.state.authorization_sequence = authorization_sequence;
        let caller = credential_index(&actor.state, call.credential).unwrap();
        actor.state.credentials[caller].management_request_high_water = call.request_sequence.get();
        match actor
            .state
            .latest_management_acks
            .binary_search_by(|record| record.credential.cmp(&latest.credential))
        {
            Ok(index) => actor.state.latest_management_acks[index] = latest,
            Err(index) => actor.state.latest_management_acks.insert(index, latest),
        }
        assert!(advance_operation_retirement_floor(&mut actor.state));
        (call, approval_bytes, acknowledgement)
    }

    fn enrollment(
        key: &SigningKey,
        kind: AuthorityCredentialKind,
    ) -> AuthorityCredentialEnrollment {
        AuthorityCredentialEnrollment::from_public_key(kind, key.verifying_key().to_bytes())
    }

    fn block_on<F: core::future::Future>(future: F) -> F::Output {
        let waker = std::task::Waker::noop();
        let mut context = core::task::Context::from_waker(waker);
        let mut future = core::pin::pin!(future);
        loop {
            if let core::task::Poll::Ready(output) = future.as_mut().poll(&mut context) {
                return output;
            }
        }
    }

    fn dispatch_ack(actor: &mut SystemAuthority, ack: &ManagementApplicationAck) -> bool {
        dispatch_ack_bytes(
            actor,
            ack.encode().expect("valid MAA2 fixture"),
            Some(acknowledgement_context(ack)),
        )
    }

    fn dispatch_application_ack(
        actor: &mut SystemAuthority,
        call: &AuthorityCredentialCall,
        approval: &ManagementApproval,
    ) -> bool {
        let ack = application_ack(actor.configuration, &actor.state, call, approval);
        dispatch_ack(actor, &ack)
    }

    fn enroll(
        actor: &mut SystemAuthority,
        key: &SigningKey,
        principal: PrincipalId,
        node: NodeId,
        role: BuiltinPrincipalRole,
    ) {
        let enrollment = node_enrollment(actor.configuration, principal);
        assert_eq!(enrollment.node, node);
        enroll_exact(actor, key, enrollment, role);
    }

    fn enroll_exact(
        actor: &mut SystemAuthority,
        key: &SigningKey,
        node_enrollment: NodeEncryptionEnrollment,
        role: BuiltinPrincipalRole,
    ) {
        let principal = node_enrollment.principal;
        let node = node_enrollment.node;
        let credential = enrollment(key, AuthorityCredentialKind::Ssh);
        let invocation = |step: u8| {
            InvocationId(
                Hash::digest(
                    b"vos/test/system-authority/admin-fixture/v1",
                    &[&principal.0, &node.0, &credential.credential.0, &[step]],
                )
                .0,
            )
        };
        dispatch_fixture_admin(
            actor,
            invocation(0),
            AuthorityAdminOperation::EnrollPrincipal {
                principal,
                credential,
            },
        );
        dispatch_fixture_admin(
            actor,
            invocation(1),
            AuthorityAdminOperation::EnrollNode {
                enrollment: node_enrollment,
            },
        );
        let role = match role {
            BuiltinPrincipalRole::Member => return,
            BuiltinPrincipalRole::Developer => AuthorityBuiltinRole::Developer,
            BuiltinPrincipalRole::Admin => AuthorityBuiltinRole::Admin,
        };
        dispatch_fixture_admin(
            actor,
            invocation(2),
            AuthorityAdminOperation::SetBuiltinRole { principal, role },
        );
    }

    fn enroll_additional_node(
        actor: &mut SystemAuthority,
        principal: PrincipalId,
        signing_byte: u8,
    ) -> NodeId {
        let enrollment =
            signed_node_enrollment(SpaceId(actor.configuration.space), principal, signing_byte);
        let invocation = InvocationId(
            Hash::digest(
                b"vos/test/system-authority/additional-node/v1",
                &[enrollment.commitment().as_bytes()],
            )
            .0,
        );
        dispatch_fixture_admin(
            actor,
            invocation,
            AuthorityAdminOperation::EnrollNode { enrollment },
        );
        enrollment.node
    }

    fn enrolled_identity_commitment(
        actor: &SystemAuthority,
        node: NodeId,
        principal: PrincipalId,
    ) -> Hash {
        enrolled_private_identity_commitment(&actor.state, node, principal)
            .expect("fixture node must have one exact enrolled Private identity")
    }

    #[allow(clippy::too_many_arguments)]
    fn signed_recovery_proof(
        actor: &SystemAuthority,
        managed: ManagedAgentTarget,
        owner: PrincipalId,
        recovery_key: &SigningKey,
        control: Hash,
        control_sequence: u64,
        control_previous: Option<Hash>,
        next_epoch: u64,
        superseded_authority_head: Option<Hash>,
        mut replacement_nodes: Vec<NodeId>,
        recovery_evidence: Hash,
    ) -> PrivateRecoveryAuthorityProof {
        replacement_nodes.sort_unstable();
        let replacement_identities = replacement_nodes
            .iter()
            .copied()
            .map(|node| {
                enrolled_private_identity(&actor.state, node, owner)
                    .expect("replacement Node must have an exact owner identity")
            })
            .collect::<Vec<_>>();
        let mut proof = PrivateRecoveryAuthorityProof {
            managed,
            control,
            control_sequence,
            control_previous,
            next_epoch,
            superseded_authority_head,
            replacement_member_set: private_member_set_commitment(
                replacement_nodes.iter().copied(),
            )
            .unwrap(),
            replacement_identity_set: private_node_identity_set_commitment(
                replacement_identities.iter(),
            )
            .unwrap(),
            replacement_nodes,
            recovery_evidence,
            recovery_public_key: recovery_key.verifying_key().to_bytes(),
            signature: [1; 64],
        };
        proof.signature = recovery_key.sign(&proof.signing_bytes()).to_bytes();
        proof
    }

    fn insert_live(actor: &mut SystemAuthority, descriptor: &AgentDescriptor) {
        let config = actor.configuration;
        let mut call = credential_call(
            config,
            &signing(0x21),
            ADMIN_PRINCIPAL,
            Some(ADMIN_NODE),
            0x90,
            target_for(descriptor),
            ManagementRequest::Create(Box::new(descriptor.clone())),
        );
        prepare_management_call(actor, &mut call, &signing(0x21));
        let approval = ManagementApproval::decode(&dispatch(actor, &call))
            .expect("fixture Create must be authorized");
        assert!(dispatch_application_ack(actor, &call, &approval));
    }

    fn api_projection_query(
        config: SystemAuthorityConfiguration,
        key: &SigningKey,
        nonce: u8,
        selector: AuthorityProjectionSelector,
    ) -> AuthorityProjectionQuery {
        let public_key = key.verifying_key().to_bytes();
        let mut query = AuthorityProjectionQuery {
            authority: authority_target(config),
            credential: CredentialId::of_public_key(&public_key),
            nonce: Hash([nonce; 32]),
            selector,
            authentication: AuthorityIngressAuthentication::ApiCredentialSignature {
                credential_public_key: public_key,
                signature: [1; 64],
            },
        };
        let signature = key.sign(&query.signing_bytes()).to_bytes();
        let AuthorityIngressAuthentication::ApiCredentialSignature {
            signature: query_signature,
            ..
        } = &mut query.authentication
        else {
            unreachable!();
        };
        *query_signature = signature;
        query
    }

    fn ssh_projection_query(
        config: SystemAuthorityConfiguration,
        credential_key: &SigningKey,
        attesting_node: NodeId,
        attesting_key: &SigningKey,
        nonce: u8,
        selector: AuthorityProjectionSelector,
    ) -> AuthorityProjectionQuery {
        let public_key = credential_key.verifying_key().to_bytes();
        let mut query = AuthorityProjectionQuery {
            authority: authority_target(config),
            credential: CredentialId::of_public_key(&public_key),
            nonce: Hash([nonce; 32]),
            selector,
            authentication: AuthorityIngressAuthentication::SshNodeAttestation {
                credential_public_key: public_key,
                node: attesting_node,
                request_binding: Hash::digest(
                    b"vos/test/system-authority/projection-request-binding/v1",
                    &[&[nonce]],
                ),
                signature: [1; 64],
            },
        };
        let signature = attesting_key.sign(&query.signing_bytes()).to_bytes();
        let AuthorityIngressAuthentication::SshNodeAttestation {
            signature: query_signature,
            ..
        } = &mut query.authentication
        else {
            unreachable!();
        };
        *query_signature = signature;
        query
    }

    fn install_catalog_projection(actor: &mut SystemAuthority) -> InstallActor {
        let config = actor.configuration;
        let install = catalog_install(config);
        let mut call = credential_call(
            config,
            &signing(0x21),
            ADMIN_PRINCIPAL,
            Some(ADMIN_NODE),
            0x23,
            system_target(config),
            ManagementRequest::Install(Box::new(install.clone())),
        );
        prepare_management_call(actor, &mut call, &signing(0x21));
        let approval = ManagementApproval::decode(&dispatch(actor, &call))
            .expect("root catalog install must be authorized");
        assert_eq!(approval.authorization_sequence.get(), 3);
        assert!(dispatch_application_ack(actor, &call, &approval));
        install
    }

    #[test]
    fn sac5_configuration_is_exact_and_clean_generation_bound() {
        let config = configuration();
        let encoded = config.encode();
        assert_eq!(encoded.len(), CONFIG_ENCODED_BYTES);
        assert_eq!(encoded.get(..4), Some(b"SAC5".as_slice()));
        assert_eq!(SystemAuthorityConfiguration::decode(&encoded), Some(config));
        assert_eq!(
            <SystemAuthority as vos::Actor>::STATE_SCHEMA_VERSION,
            20,
            "row-backed node headers require the new clean state generation",
        );

        let mut old_generation = encoded.clone();
        old_generation[..4].copy_from_slice(b"SAC2");
        assert_eq!(SystemAuthorityConfiguration::decode(&old_generation), None);
        let mut old_sac3_shape = vec![0; CONFIG_ENCODED_BYTES - 40];
        old_sac3_shape[..4].copy_from_slice(b"SAC3");
        assert_eq!(SystemAuthorityConfiguration::decode(&old_sac3_shape), None);
        let mut old_sac4_shape = encoded.clone();
        old_sac4_shape[..4].copy_from_slice(b"SAC4");
        let replica_principal_offset = 4 + 32 + 16 * 32 + 3 * 8;
        old_sac4_shape.drain(replica_principal_offset..replica_principal_offset + 32);
        assert_eq!(SystemAuthorityConfiguration::decode(&old_sac4_shape), None);
        let mut wrong_abi = encoded.clone();
        wrong_abi[4] ^= 1;
        assert_eq!(SystemAuthorityConfiguration::decode(&wrong_abi), None);
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert_eq!(SystemAuthorityConfiguration::decode(&trailing), None);
        assert_eq!(
            SystemAuthorityConfiguration::decode(&encoded[..encoded.len() - 1]),
            None
        );
        let mut invalid_kind = encoded.clone();
        let credential_kind_offset =
            encoded.len() - 1 - 3 * 32 - ED25519_TRANSPORT_PEER_ID_BYTES - PRIVATE_SIGNATURE_BYTES;
        invalid_kind[credential_kind_offset] = 2;
        assert_eq!(SystemAuthorityConfiguration::decode(&invalid_kind), None);
        let mut weak_key = [0; 32];
        weak_key[0] = 1;
        assert!(!canonical_credential_public_key(&weak_key));
        let mut inaccessible = config;
        inaccessible.bootstrap_credential_public_key = weak_key;
        assert!(!inaccessible.is_valid());
        assert_eq!(
            SystemAuthorityConfiguration::decode(&inaccessible.encode()),
            None
        );
        let mut missing_program = config;
        missing_program.system_runtime_program = [0; 32];
        assert_eq!(
            SystemAuthorityConfiguration::decode(&missing_program.encode()),
            None
        );
        let mut missing_producer = config;
        missing_producer.system_runtime_producer = [0; 32];
        assert_eq!(
            SystemAuthorityConfiguration::decode(&missing_producer.encode()),
            None
        );
        let mut missing_transition_producer = config;
        missing_transition_producer.system_transition_producer = [0; 32];
        assert_eq!(
            SystemAuthorityConfiguration::decode(&missing_transition_producer.encode()),
            None
        );
        let mut reused_runtime_producer = config;
        reused_runtime_producer.system_transition_producer =
            reused_runtime_producer.system_runtime_producer;
        assert_eq!(
            SystemAuthorityConfiguration::decode(&reused_runtime_producer.encode()),
            None
        );
        for altered_high_water in [0, 1, 3, u64::MAX] {
            let mut altered = config;
            altered.bootstrap_authorization_high_water = altered_high_water;
            assert!(!altered.is_valid());
            assert_eq!(
                SystemAuthorityConfiguration::decode(&altered.encode()),
                None
            );
        }

        let mut wrong_node = config;
        wrong_node.bootstrap_node[0] ^= 1;
        assert_eq!(
            SystemAuthorityConfiguration::decode(&wrong_node.encode()),
            None
        );
        let mut wrong_transport_key = config;
        wrong_transport_key.bootstrap_node_transport_public_key[0] ^= 1;
        assert_eq!(
            SystemAuthorityConfiguration::decode(&wrong_transport_key.encode()),
            None
        );
        let mut wrong_replica_principal = config;
        wrong_replica_principal.bootstrap_replica_principal[0] ^= 1;
        assert_eq!(
            SystemAuthorityConfiguration::decode(&wrong_replica_principal.encode()),
            None
        );
        let mut wrong_peer_id = config;
        wrong_peer_id.bootstrap_node_transport_peer_id[6] ^= 1;
        assert_eq!(
            SystemAuthorityConfiguration::decode(&wrong_peer_id.encode()),
            None
        );
        let mut high_bit_x25519 = config;
        high_bit_x25519.bootstrap_node_encryption_public_key[31] |= 0x80;
        assert_eq!(
            SystemAuthorityConfiguration::decode(&high_bit_x25519.encode()),
            None
        );
        let mut wrong_transport_signature = config;
        wrong_transport_signature.bootstrap_node_transport_signature[0] ^= 1;
        assert_eq!(
            SystemAuthorityConfiguration::decode(&wrong_transport_signature.encode()),
            None
        );

        let inert = SystemAuthority::new(&old_generation);
        assert!(!inert.state.initialized);
        assert!(inert.state.credentials.is_empty());
    }

    #[test]
    fn projection_authentication_is_kind_exact_and_projects_durable_high_waters() {
        let config = configuration();
        let bootstrap_credential_key = signing(0x21);
        let ingress_node_key = signing(0x31);
        let mut actor = actor();

        let bootstrap_query = ssh_projection_query(
            config,
            &bootstrap_credential_key,
            ADMIN_NODE,
            &ingress_node_key,
            0x81,
            AuthorityProjectionSelector::Credential,
        );
        let initial_bytes =
            credential_projection(&config, &actor.state, &bootstrap_query.encode().unwrap());
        let initial = AuthorityCredentialProjection::decode(&initial_bytes).unwrap();
        assert_eq!(initial.query, bootstrap_query);
        assert_eq!(initial.principal, ADMIN_PRINCIPAL);
        assert_eq!(initial.kind, AuthorityCredentialKind::Ssh);
        assert_eq!(initial.status, AuthorityCredentialStatus::Active);
        assert_eq!(initial.management_request_high_water, 0);
        assert_eq!(initial.operation_request_high_water, 0);
        assert_eq!(initial.admin_request_high_water, 0);
        assert_eq!(
            initial.head.state_commitment.0,
            actor.state.state_integrity_commitment
        );
        assert_eq!(
            credential_projection(&config, &actor.state, &initial.query.encode().unwrap()),
            initial_bytes,
            "a read-only exact retry over unchanged state is byte-identical",
        );

        let wrong_kind_query = api_projection_query(
            config,
            &bootstrap_credential_key,
            0x82,
            AuthorityProjectionSelector::Credential,
        );
        assert!(
            credential_projection(&config, &actor.state, &wrong_kind_query.encode().unwrap())
                .is_empty()
        );

        let ssh_principal = PrincipalId([0x83; 32]);
        let ssh_key = signing(0x84);
        dispatch_fixture_admin(
            &mut actor,
            InvocationId([0x85; 32]),
            AuthorityAdminOperation::EnrollPrincipal {
                principal: ssh_principal,
                credential: enrollment(&ssh_key, AuthorityCredentialKind::Ssh),
            },
        );
        let ssh_query = ssh_projection_query(
            config,
            &ssh_key,
            ADMIN_NODE,
            &ingress_node_key,
            0x86,
            AuthorityProjectionSelector::Credential,
        );
        let ssh_projection = AuthorityCredentialProjection::decode(&credential_projection(
            &config,
            &actor.state,
            &ssh_query.encode().unwrap(),
        ))
        .unwrap();
        assert_eq!(ssh_projection.principal, ssh_principal);
        assert_eq!(ssh_projection.kind, AuthorityCredentialKind::Ssh);
        assert_ne!(
            actor.state.nodes.indices().next().unwrap().owner, ssh_principal.0,
            "an enrolled ingress Node attests the SSH session, not user ownership",
        );

        let mut substituted_binding = ssh_query.clone();
        let AuthorityIngressAuthentication::SshNodeAttestation {
            request_binding, ..
        } = &mut substituted_binding.authentication
        else {
            unreachable!();
        };
        request_binding.0[0] ^= 1;
        assert!(
            credential_projection(
                &config,
                &actor.state,
                &substituted_binding.encode().unwrap()
            )
            .is_empty()
        );

        let api_principal = PrincipalId([0x87; 32]);
        let api_key = signing(0x88);
        let replacement_key = signing(0x89);
        dispatch_fixture_admin(
            &mut actor,
            InvocationId([0x8a; 32]),
            AuthorityAdminOperation::EnrollPrincipal {
                principal: api_principal,
                credential: enrollment(&api_key, AuthorityCredentialKind::Api),
            },
        );
        dispatch_fixture_admin(
            &mut actor,
            InvocationId([0x8b; 32]),
            AuthorityAdminOperation::AddCredential {
                principal: api_principal,
                credential: enrollment(&replacement_key, AuthorityCredentialKind::Api),
            },
        );
        let catalog = install_catalog_projection(&mut actor);
        let operation = invoke_operation_call(
            config,
            &api_key,
            api_principal,
            None,
            0x8c,
            0x8d,
            system_target(config),
            &catalog,
        );
        authorize_and_issue_operation(&mut actor, &operation);
        dispatch_fixture_admin(
            &mut actor,
            InvocationId([0x8e; 32]),
            AuthorityAdminOperation::RevokeCredential {
                principal: api_principal,
                credential: CredentialId::of_public_key(&api_key.verifying_key().to_bytes()),
            },
        );

        let revoked_query = api_projection_query(
            config,
            &api_key,
            0x8f,
            AuthorityProjectionSelector::Credential,
        );
        let revoked_bytes =
            credential_projection(&config, &actor.state, &revoked_query.encode().unwrap());
        let revoked = AuthorityCredentialProjection::decode(&revoked_bytes).unwrap();
        assert_eq!(revoked.principal, api_principal);
        assert_eq!(revoked.status, AuthorityCredentialStatus::Revoked);
        assert_eq!(revoked.management_request_high_water, 0);
        assert_eq!(revoked.operation_request_high_water, 1);
        assert_eq!(revoked.admin_request_high_water, 0);
        let revoked_inventory_query = api_projection_query(
            config,
            &api_key,
            0x90,
            AuthorityProjectionSelector::Agents {
                after: None,
                limit: 1,
            },
        );
        assert!(
            agent_projection_page(
                &config,
                &actor.state,
                &revoked_inventory_query.encode().unwrap()
            )
            .is_empty()
        );

        let linear = <SystemAuthority as vos::Actor>::__save_agent_lane(&actor, StateLane::Linear);
        let reopened = <SystemAuthority as vos::Actor>::__load_agent_state(
            Some(&config.encode()),
            Some(&linear),
            None,
            None,
        )
        .expect("projection credential rows restart");
        assert_eq!(
            credential_projection(&config, &reopened.state, &revoked_query.encode().unwrap()),
            revoked_bytes,
        );

        let mut corrupt = reopened.state.clone();
        corrupt.credentials[0].operation_request_high_water ^= 1;
        assert!(
            credential_projection(&config, &corrupt, &bootstrap_query.encode().unwrap()).is_empty(),
            "the complete state is validated before any page is returned",
        );
    }

    fn inventory_query(
        actor: &SystemAuthority,
        key: &SigningKey,
        after: Option<AuthorityInventoryCursor>,
        limit: u16,
        known_head: Option<AuthorityProjectionHead>,
    ) -> AuthorityProjectionQuery {
        ssh_projection_query(
            actor.configuration,
            key,
            ADMIN_NODE,
            &signing(0x31),
            0xb1,
            AuthorityProjectionSelector::Inventory {
                after,
                limit,
                known_head,
            },
        )
    }

    fn inventory_page(
        actor: &SystemAuthority,
        query: &AuthorityProjectionQuery,
    ) -> AuthorityInventoryProjectionPage {
        let bytes =
            inventory_projection_page(&actor.configuration, &actor.state, &query.encode().unwrap());
        assert!(bytes.len() <= MAX_INVOCATION_REPLY_BYTES);
        assert!(
            vos::actors::value::desc::encode_value(&vos::actors::value::Value::Bytes(
                bytes.clone()
            ))
            .len()
                <= MAX_INVOCATION_REPLY_BYTES
        );
        let page = AuthorityInventoryProjectionPage::decode(&bytes).unwrap();
        assert_eq!(&page.credential.query, query);
        page
    }

    fn drain_inventory(
        actor: &SystemAuthority,
        key: &SigningKey,
        limit: u16,
    ) -> Vec<AuthorityInventoryEntry> {
        let mut after = None;
        let mut rows = Vec::new();
        let mut head = None;
        for _ in 0..64 {
            let query = inventory_query(actor, key, after, limit, None);
            let page = inventory_page(actor, &query);
            assert!(!page.unchanged);
            assert_eq!(
                *head.get_or_insert(page.credential.head),
                page.credential.head
            );
            rows.extend(page.entries);
            match page.next {
                Some(next) => {
                    assert_eq!(rows.last().map(AuthorityInventoryEntry::cursor), Some(next));
                    after = Some(next);
                }
                None => return rows,
            }
        }
        panic!("small fixture must complete with bounded pages");
    }

    #[test]
    fn inventory_stream_pages_match_directory_and_filter_private_rows() {
        let config = configuration();
        let mut actor = actor();
        let catalog = install_catalog_projection(&mut actor);
        let owner = PrincipalId([0x93; 32]);
        let owner_key = signing(0x94);
        enroll(
            &mut actor,
            &owner_key,
            owner,
            node_for_principal(config, owner),
            BuiltinPrincipalRole::Member,
        );
        let foreign = PrincipalId([0x95; 32]);
        let foreign_key = signing(0x96);
        enroll(
            &mut actor,
            &foreign_key,
            foreign,
            node_for_principal(config, foreign),
            BuiltinPrincipalRole::Member,
        );
        let descriptors = [
            descriptor(config, owner, AgentProfile::Private, 0x97),
            descriptor(config, foreign, AgentProfile::Private, 0x98),
            descriptor(config, foreign, AgentProfile::Private, 0x99),
        ];
        for descriptor in &descriptors {
            insert_live(&mut actor, descriptor);
        }
        let before = <SystemAuthority as vos::Actor>::__save_agent_lane(&actor, StateLane::Linear);
        let rows = drain_inventory(&actor, &signing(0x21), 8);
        assert!(rows.len() > 8);
        assert_eq!(drain_inventory(&actor, &signing(0x21), 1), rows);
        assert_eq!(drain_inventory(&actor, &signing(0x21), 2), rows);
        assert_eq!(drain_inventory(&actor, &signing(0x21), 64), rows);
        assert!(
            inventory_page(
                &actor,
                &inventory_query(&actor, &signing(0x21), None, 64, None)
            )
            .next
            .is_none()
        );
        assert!(
            rows.windows(2)
                .all(|pair| pair[0].cursor() < pair[1].cursor())
        );
        let member = drain_inventory(&actor, &owner_key, 2);
        let visible = rows
            .iter()
            .filter(|entry| {
                entry.cursor().agent != descriptors[1].identity.agent
                    && entry.cursor().agent != descriptors[2].identity.agent
            })
            .cloned()
            .collect::<Vec<_>>();
        assert_eq!(
            member, visible,
            "hidden Agents must also hide their replica/actor rows"
        );
        // CLI targeted discovery starts after the greatest possible row of
        // the preceding Agent ID, which need not exist in this directory.
        // Seeking must agree with the complete authenticated view, including
        // when the requested Private Agent is invisible to the caller.
        for descriptor in &descriptors {
            let target = descriptor.identity.agent;
            let mut predecessor = target.0;
            for byte in predecessor.iter_mut().rev() {
                let (value, borrow) = byte.overflowing_sub(1);
                *byte = value;
                if !borrow {
                    break;
                }
            }
            let after = (predecessor != [0; 32]).then_some(AuthorityInventoryCursor {
                agent: AgentId(predecessor),
                position: AuthorityInventoryPosition::Actor(ActorId([0xff; 32])),
            });
            for (key, complete) in [(&signing(0x21), &rows), (&owner_key, &member)] {
                let page = inventory_page(&actor, &inventory_query(&actor, key, after, 2, None));
                let expected = complete
                    .iter()
                    .filter(|entry| entry.cursor().agent >= target)
                    .take(2)
                    .cloned()
                    .collect::<Vec<_>>();
                assert_eq!(page.entries, expected);
            }
        }
        for descriptor in &descriptors {
            let projected = rows
                .iter()
                .find_map(|entry| match entry {
                    AuthorityInventoryEntry::Agent(row)
                        if row.identity.agent == descriptor.identity.agent =>
                    {
                        Some(row)
                    }
                    _ => None,
                })
                .unwrap();
            let replicas = rows
                .iter()
                .filter_map(|entry| match entry {
                    AuthorityInventoryEntry::Replica { agent, replica }
                        if *agent == descriptor.identity.agent =>
                    {
                        Some(replica.clone())
                    }
                    _ => None,
                })
                .collect();
            assert_eq!(
                projected.reconstruct_descriptor(replicas).unwrap(),
                *descriptor
            );
        }
        assert!(
            rows.iter()
                .any(|entry| matches!(entry, AuthorityInventoryEntry::Actor(row)
            if row.entry == catalog.entry && row.installation_id == catalog.installation_id))
        );
        assert_eq!(
            before,
            <SystemAuthority as vos::Actor>::__save_agent_lane(&actor, StateLane::Linear)
        );

        // A page cursor inside an invisible Agent cannot disclose its children.
        let query = inventory_query(
            &actor,
            &owner_key,
            Some(AuthorityInventoryCursor {
                agent: descriptors[1].identity.agent,
                position: AuthorityInventoryPosition::Agent,
            }),
            8,
            None,
        );
        let page = inventory_page(&actor, &query);
        assert!(
            page.entries
                .iter()
                .all(|entry| entry.cursor().agent != descriptors[1].identity.agent)
        );
    }

    #[test]
    fn inventory_stream_authentication_cache_and_revocation_are_fresh() {
        let config = configuration();
        let mut actor = actor();
        install_catalog_projection(&mut actor);
        let principal = PrincipalId([0x83; 32]);
        let key = signing(0x84);
        enroll(
            &mut actor,
            &key,
            principal,
            node_for_principal(config, principal),
            BuiltinPrincipalRole::Member,
        );
        let query = inventory_query(&actor, &key, None, 8, None);
        let first = inventory_page(&actor, &query);
        assert!(!first.entries.is_empty());
        let partial = inventory_page(&actor, &inventory_query(&actor, &key, None, 1, None));
        assert!(partial.next.is_some());
        let cached_query = inventory_query(&actor, &key, None, 8, Some(first.credential.head));
        let cached = inventory_page(&actor, &cached_query);
        assert!(cached.unchanged);
        assert!(cached.entries.is_empty());
        assert!(cached.next.is_none());

        let mut wrong_nonce = cached_query.clone();
        wrong_nonce.nonce = Hash([0xe1; 32]);
        let mut wrong_authority = cached_query.clone();
        wrong_authority.authority.binding.initial_epoch += 1;
        let mut wrong_head = cached_query.clone();
        let mut head = first.credential.head;
        head.state_commitment = Hash([0xe2; 32]);
        wrong_head.selector = AuthorityProjectionSelector::Inventory {
            after: None,
            limit: 8,
            known_head: Some(head),
        };
        for substituted in [wrong_nonce, wrong_authority, wrong_head] {
            // Each field is included in the signature; an unchanged hint does
            // not bypass authentication or state validation.
            assert!(
                inventory_projection_page(&config, &actor.state, &substituted.encode().unwrap())
                    .is_empty()
            );
        }
        let mut substituted = cached_query.clone();
        substituted.selector = AuthorityProjectionSelector::Inventory {
            after: None,
            limit: 1,
            known_head: Some(first.credential.head),
        };
        assert!(
            inventory_projection_page(&config, &actor.state, &substituted.encode().unwrap())
                .is_empty()
        );
        let wrong_kind = api_projection_query(config, &key, 0xb2, query.selector);
        assert!(
            inventory_projection_page(&config, &actor.state, &wrong_kind.encode().unwrap())
                .is_empty()
        );

        dispatch_fixture_admin(
            &mut actor,
            InvocationId([0xb3; 32]),
            AuthorityAdminOperation::SetBuiltinRole {
                principal,
                role: AuthorityBuiltinRole::Developer,
            },
        );
        let changed = inventory_page(&actor, &cached_query);
        assert!(!changed.unchanged);
        assert_ne!(changed.credential.head, first.credential.head);
        assert_eq!(
            changed.credential.builtin_role,
            AuthorityBuiltinRole::Developer
        );
        assert_eq!(changed.entries, first.entries);
        let continued = inventory_page(
            &actor,
            &inventory_query(&actor, &key, partial.next, 1, None),
        );
        assert_ne!(
            continued.credential.head, partial.credential.head,
            "a consumer must reject pagination across an intervening Authority mutation"
        );
        assert_eq!(continued.credential.head, changed.credential.head);
        dispatch_fixture_admin(
            &mut actor,
            InvocationId([0xb5; 32]),
            AuthorityAdminOperation::AddCredential {
                principal,
                credential: enrollment(&signing(0x85), AuthorityCredentialKind::Ssh),
            },
        );
        let credential = CredentialId::of_public_key(&key.verifying_key().to_bytes());
        dispatch_fixture_admin(
            &mut actor,
            InvocationId([0xb4; 32]),
            AuthorityAdminOperation::RevokeCredential {
                principal,
                credential,
            },
        );
        let revoked = inventory_page(&actor, &cached_query);
        assert_eq!(
            revoked.credential.status,
            AuthorityCredentialStatus::Revoked
        );
        assert!(!revoked.unchanged);
        assert!(revoked.entries.is_empty());
        assert!(revoked.next.is_none());
        let linear = <SystemAuthority as vos::Actor>::__save_agent_lane(&actor, StateLane::Linear);
        let reopened = <SystemAuthority as vos::Actor>::__load_agent_state(
            Some(&config.encode()),
            Some(&linear),
            None,
            None,
        )
        .unwrap();
        assert_eq!(inventory_page(&reopened, &cached_query), revoked);
        let mut corrupt = actor.state.clone();
        corrupt.credentials[0].operation_request_high_water ^= 1;
        assert!(
            inventory_projection_page(&config, &corrupt, &cached_query.encode().unwrap())
                .is_empty()
        );
    }

    #[test]
    fn projection_pages_are_full_ordered_private_filtered_and_head_stable() {
        let config = configuration();
        let mut actor = actor();
        let catalog = install_catalog_projection(&mut actor);
        let second_actor = actor_install(AgentId(config.system_agent), "second-system", 0x91);
        let mut install_call = credential_call(
            config,
            &signing(0x21),
            ADMIN_PRINCIPAL,
            Some(ADMIN_NODE),
            0x92,
            system_target(config),
            ManagementRequest::Install(Box::new(second_actor.clone())),
        );
        prepare_management_call(&actor, &mut install_call, &signing(0x21));
        let install_approval = ManagementApproval::decode(&dispatch(&mut actor, &install_call))
            .expect("second system Actor installs");
        assert!(dispatch_application_ack(
            &mut actor,
            &install_call,
            &install_approval,
        ));

        let first_owner = PrincipalId([0x93; 32]);
        let first_key = signing(0x94);
        enroll(
            &mut actor,
            &first_key,
            first_owner,
            node_for_principal(config, first_owner),
            BuiltinPrincipalRole::Member,
        );
        let second_owner = PrincipalId([0x95; 32]);
        let second_key = signing(0x96);
        enroll(
            &mut actor,
            &second_key,
            second_owner,
            node_for_principal(config, second_owner),
            BuiltinPrincipalRole::Member,
        );
        let extra_first_owner_node =
            signed_node_enrollment(SpaceId(config.space), first_owner, 0xad);
        dispatch_fixture_admin(
            &mut actor,
            InvocationId([0xae; 32]),
            AuthorityAdminOperation::EnrollNode {
                enrollment: extra_first_owner_node.clone(),
            },
        );
        let mut first_private = descriptor(config, first_owner, AgentProfile::Private, 0x97);
        first_private.replicas.push(AgentReplica {
            node: extra_first_owner_node.node,
            principal: first_owner,
            role: ReplicaRole::Observer,
        });
        first_private
            .replicas
            .sort_unstable_by_key(|replica| replica.node);
        first_private.validate().unwrap();
        let second_private = descriptor(config, second_owner, AgentProfile::Private, 0x98);
        insert_live(&mut actor, &first_private);
        insert_live(&mut actor, &second_private);

        let mut after = None;
        let mut admin_entries = Vec::new();
        let mut stable_head = None;
        for ordinal in 0..MAX_MANAGED_AGENTS {
            let query = ssh_projection_query(
                config,
                &signing(0x21),
                ADMIN_NODE,
                &signing(0x31),
                0xa0_u8.wrapping_add(ordinal as u8),
                AuthorityProjectionSelector::Agents { after, limit: 1 },
            );
            let page = AuthorityAgentProjectionPage::decode(&agent_projection_page(
                &config,
                &actor.state,
                &query.encode().unwrap(),
            ))
            .unwrap();
            assert_eq!(page.query, query);
            assert_eq!(stable_head.get_or_insert(page.head), &page.head);
            admin_entries.extend(page.entries);
            let Some(next) = page.next else {
                break;
            };
            assert_eq!(
                Some(next),
                admin_entries.last().map(|entry| entry.identity.agent)
            );
            after = Some(next);
        }
        assert_eq!(admin_entries.len(), 3);
        assert!(
            admin_entries
                .windows(2)
                .all(|pair| pair[0].identity.agent < pair[1].identity.agent)
        );
        let projected_private = admin_entries
            .iter()
            .find(|entry| entry.identity.agent == first_private.identity.agent)
            .unwrap();
        assert_eq!(projected_private.identity, first_private.identity);
        assert_eq!(
            projected_private.creation_nonce,
            first_private.creation_nonce
        );
        assert_eq!(projected_private.authority, first_private.authority);
        assert_eq!(
            projected_private.private_recovery,
            first_private.private_recovery
        );
        assert_eq!(
            projected_private.runtime_package,
            first_private.runtime_package
        );
        assert_eq!(
            projected_private.runtime_contract,
            first_private.runtime_contract
        );
        assert_eq!(projected_private.capabilities, first_private.capabilities);
        assert_eq!(
            usize::from(projected_private.replica_count),
            first_private.replicas.len()
        );
        assert_eq!(
            projected_private.replica_generation,
            first_private.replica_generation()
        );

        let mut replica_after = None;
        let mut projected_replicas = Vec::new();
        let mut first_replica_page = None;
        for ordinal in 0..MAX_AGENT_REPLICAS {
            let query = ssh_projection_query(
                config,
                &signing(0x21),
                ADMIN_NODE,
                &signing(0x31),
                0xd0_u8.wrapping_add(ordinal as u8),
                AuthorityProjectionSelector::AgentReplicas {
                    agent: first_private.identity.agent,
                    after: replica_after,
                    limit: 1,
                },
            );
            let page = AuthorityAgentReplicaProjectionPage::decode(&agent_replica_projection_page(
                &config,
                &actor.state,
                &query.encode().unwrap(),
            ))
            .unwrap();
            assert_eq!(stable_head, Some(page.head));
            assert!(page.matches_agent_at_head(projected_private, stable_head.unwrap()));
            first_replica_page.get_or_insert_with(|| page.clone());
            projected_replicas.extend(page.entries);
            let Some(next) = page.next else {
                break;
            };
            assert_eq!(
                Some(next),
                projected_replicas.last().map(|replica| replica.node)
            );
            replica_after = Some(next);
        }
        assert_eq!(projected_replicas, first_private.replicas);
        assert_eq!(
            projected_private
                .reconstruct_descriptor(projected_replicas)
                .unwrap(),
            first_private
        );
        let first_replica_page = first_replica_page.unwrap();
        assert!(first_replica_page.next.is_some());

        let member_query = ssh_projection_query(
            config,
            &first_key,
            ADMIN_NODE,
            &signing(0x31),
            0xa8,
            AuthorityProjectionSelector::Agents {
                after: None,
                limit: MAX_AUTHORITY_PROJECTION_PAGE_ENTRIES as u16,
            },
        );
        let member_page = AuthorityAgentProjectionPage::decode(&agent_projection_page(
            &config,
            &actor.state,
            &member_query.encode().unwrap(),
        ))
        .unwrap();
        assert!(
            member_page
                .entries
                .iter()
                .any(|entry| entry.identity.agent == first_private.identity.agent)
        );
        assert!(
            member_page
                .entries
                .iter()
                .all(|entry| entry.identity.agent != second_private.identity.agent)
        );

        let mut actor_after = None;
        let mut actor_entries = Vec::new();
        for ordinal in 0..MAX_MANAGED_ACTORS {
            let query = ssh_projection_query(
                config,
                &signing(0x21),
                ADMIN_NODE,
                &signing(0x31),
                0xb0_u8.wrapping_add(ordinal as u8),
                AuthorityProjectionSelector::Actors {
                    agent: AgentId(config.system_agent),
                    after: actor_after,
                    limit: 1,
                },
            );
            let page = AuthorityActorProjectionPage::decode(&actor_projection_page(
                &config,
                &actor.state,
                &query.encode().unwrap(),
            ))
            .unwrap();
            assert_eq!(stable_head, Some(page.head));
            actor_entries.extend(page.entries);
            let Some(next) = page.next else {
                break;
            };
            actor_after = Some(next);
        }
        assert_eq!(actor_entries.len(), 2);
        assert!(
            actor_entries
                .windows(2)
                .all(|pair| pair[0].entry.actor < pair[1].entry.actor)
        );
        for expected in [&catalog, &second_actor] {
            let projected = actor_entries
                .iter()
                .find(|entry| entry.entry.actor == expected.entry.actor)
                .unwrap();
            assert_eq!(projected.entry, expected.entry);
            assert_eq!(projected.producer, expected.producer);
            assert_eq!(projected.contract, expected.contract);
            assert_eq!(projected.requirements, expected.requirements);
            assert_eq!(projected.installation_id, expected.installation_id);
            assert_eq!(
                projected.registry_reservation,
                expected.registry_reservation
            );
            assert_eq!(
                projected.install_request,
                ManagementRequest::Install(Box::new(expected.clone())).commitment()
            );
        }
        assert!(actor_entries.iter().any(|entry| entry.root_provenance));
        assert!(
            actor_entries
                .iter()
                .filter(|entry| entry.root_provenance)
                .all(|entry| entry.entry.actor == catalog.entry.actor)
        );

        dispatch_fixture_admin(
            &mut actor,
            InvocationId([0xaf; 32]),
            AuthorityAdminOperation::SetBuiltinRole {
                principal: first_owner,
                role: AuthorityBuiltinRole::Developer,
            },
        );
        let changed_head_query = ssh_projection_query(
            config,
            &signing(0x21),
            ADMIN_NODE,
            &signing(0x31),
            0xdf,
            AuthorityProjectionSelector::AgentReplicas {
                agent: first_private.identity.agent,
                after: first_replica_page.next,
                limit: 1,
            },
        );
        let changed_head_page =
            AuthorityAgentReplicaProjectionPage::decode(&agent_replica_projection_page(
                &config,
                &actor.state,
                &changed_head_query.encode().unwrap(),
            ))
            .unwrap();
        assert_ne!(first_replica_page.head, changed_head_page.head);
        assert!(
            !changed_head_page.matches_agent_at_head(projected_private, first_replica_page.head)
        );
        assert!(changed_head_page.matches_agent_at_head(projected_private, changed_head_page.head));
    }

    #[test]
    fn durable_scoped_grants_drive_exact_operation_policy_and_mutation_time_bound() {
        let config = configuration();
        let mut actor = actor();
        let catalog = install_catalog_projection(&mut actor);
        let principal = PrincipalId([0xc1; 32]);
        let key = signing(0xc2);
        dispatch_fixture_admin(
            &mut actor,
            InvocationId([0xc3; 32]),
            AuthorityAdminOperation::EnrollPrincipal {
                principal,
                credential: enrollment(&key, AuthorityCredentialKind::Api),
            },
        );
        let space_role = RoleId([0xc4; 32]);
        let actor_role = RoleId([0xc5; 32]);
        let capability = CapabilityId([0xc6; 32]);
        for (invocation, operation) in [
            (
                0xc7,
                AuthorityAdminOperation::SetSpaceRole {
                    principal,
                    role: space_role,
                    granted: true,
                },
            ),
            (
                0xc8,
                AuthorityAdminOperation::SetActorRole {
                    principal,
                    agent: AgentId(config.system_agent),
                    actor: catalog.entry.actor,
                    deployment: catalog.entry.deployment,
                    role: actor_role,
                    granted: true,
                },
            ),
            (
                0xc9,
                AuthorityAdminOperation::SetCapability {
                    principal,
                    agent: AgentId(config.system_agent),
                    actor: catalog.entry.actor,
                    deployment: catalog.entry.deployment,
                    capability,
                    granted: true,
                },
            ),
        ] {
            dispatch_fixture_admin(&mut actor, InvocationId([invocation; 32]), operation);
        }

        let query =
            api_projection_query(config, &key, 0xca, AuthorityProjectionSelector::Credential);
        let projected = AuthorityCredentialProjection::decode(&credential_projection(
            &config,
            &actor.state,
            &query.encode().unwrap(),
        ))
        .unwrap();
        assert_eq!(projected.space_roles, vec![space_role]);
        assert_eq!(
            projected.actor_roles,
            vec![AuthorityActorRoleGrant {
                agent: AgentId(config.system_agent),
                actor: catalog.entry.actor,
                deployment: catalog.entry.deployment,
                role: actor_role,
            }]
        );
        assert_eq!(
            projected.capabilities,
            vec![AuthorityCapabilityGrant {
                agent: AgentId(config.system_agent),
                actor: catalog.entry.actor,
                deployment: catalog.entry.deployment,
                capability,
            }]
        );

        for (ordinal, claim) in [(0_u8, 0_u8), (1_u8, 1_u8), (2_u8, 2_u8)] {
            let mut call = invoke_operation_call(
                config,
                &key,
                principal,
                None,
                0xcb_u8.wrapping_add(ordinal),
                0xd0_u8.wrapping_add(ordinal),
                system_target(config),
                &catalog,
            );
            let AuthorityOperationIntent::InvokeActor { origin, roles, .. } = &mut call.intent
            else {
                unreachable!();
            };
            match claim {
                0 => roles.space = Some(space_role),
                1 => roles.actor = Some(actor_role),
                2 => origin.capability = Some(capability),
                _ => unreachable!(),
            }
            prepare_operation_call(&actor, &mut call, &key);
            authorize_and_issue_operation(&mut actor, &call);
        }

        let mut substituted = invoke_operation_call(
            config,
            &key,
            principal,
            None,
            0xd3,
            0xd4,
            system_target(config),
            &catalog,
        );
        let AuthorityOperationIntent::InvokeActor { origin, .. } = &mut substituted.intent else {
            unreachable!();
        };
        origin.capability = Some(CapabilityId([0xd5; 32]));
        prepare_operation_call(&actor, &mut substituted, &key);
        let before = actor.state.clone();
        assert!(dispatch_operation(&mut actor, &substituted).is_empty());
        assert_eq!(actor.state, before);

        for ordinal in 0..(MAX_AUTHORITY_PRINCIPAL_GRANTS - 3) {
            let mut role = [0xe0; 32];
            role[..8].copy_from_slice(&(ordinal as u64).to_le_bytes());
            assert!(apply_admin_operation(
                &config,
                &mut actor.state,
                &AuthorityAdminOperation::SetSpaceRole {
                    principal,
                    role: RoleId(role),
                    granted: true,
                },
            ));
        }
        assert_eq!(
            principal_authorization_grant_count(&actor.state, principal),
            MAX_AUTHORITY_PRINCIPAL_GRANTS
        );
        assert!(!apply_admin_operation(
            &config,
            &mut actor.state,
            &AuthorityAdminOperation::SetSpaceRole {
                principal,
                role: RoleId([0xef; 32]),
                granted: true,
            },
        ));
        assert!(refresh_state_integrity_commitment(
            &config,
            &mut actor.state
        ));
        assert!(authority_state_is_valid(&config, &actor.state));
    }

    #[test]
    fn root_seed_starts_at_sequence_two_authorizes_catalog_install_as_three_and_restarts() {
        let config = configuration();
        let expected_seed = root_managed_agent(config);
        let mut actor = actor();
        assert_ne!(
            config.bootstrap_principal,
            config.bootstrap_replica_principal
        );
        assert_eq!(expected_seed.owner, config.bootstrap_principal);
        assert_eq!(
            expected_seed.replicas[0].principal,
            config.bootstrap_replica_principal,
        );
        assert_eq!(
            actor.state.authorization_sequence,
            ROOT_BOOTSTRAP_AUTHORIZATION_HIGH_WATER
        );
        assert_eq!(actor.state.managed_agents, vec![expected_seed.clone()]);
        assert!(authority_state_is_valid(&config, &actor.state));

        let install = catalog_install(config);
        let request = ManagementRequest::Install(Box::new(install.clone()));
        let call = credential_call(
            config,
            &signing(0x21),
            ADMIN_PRINCIPAL,
            Some(ADMIN_NODE),
            0x2b,
            system_target(config),
            request,
        );
        let approval_bytes = dispatch(&mut actor, &call);
        let approval =
            ManagementApproval::decode(&approval_bytes).expect("catalog Install approved");
        assert_eq!(approval.authorization_sequence.get(), 3);
        assert_eq!(actor.state.authorization_sequence, 3);
        assert_eq!(actor.state.managed_agents, vec![expected_seed.clone()]);
        assert!(actor.state.managed_actors.is_empty());
        assert!(matches!(
            &actor.state.retries[0].effect,
            PendingManagementEffect::InstallActor {
                agent,
                actor,
                parent,
                installation_id,
            } if *agent == config.system_agent
                && *actor == install.entry.actor.0
                && parent.is_none()
                && *installation_id == install.installation_id.0
        ));
        assert!(authority_state_is_valid(&config, &actor.state));

        let ack = application_ack(config, &actor.state, &call, &approval);
        let install_plan = ManagementAuthorizationPlan::from_request(&ManagementRequest::Install(
            Box::new(install.clone()),
        ))
        .expect("install fixture has a compact authorization plan");
        let ManagementAuthorizationPlan::Install(compact_install) = &install_plan else {
            unreachable!()
        };
        let expected_actor = installed_actor_row(
            AgentId(config.system_agent),
            compact_install,
            install_plan.commitment(),
            true,
        );
        assert!(dispatch_ack(&mut actor, &ack));
        assert_eq!(actor.state.managed_actors, vec![expected_actor.clone()]);
        assert_installed_projection(
            &actor.state.managed_actors[0],
            AgentId(config.system_agent),
            &install,
            true,
        );
        assert_eq!(actor.state.managed_actors[0].name, "system-catalog");
        assert!(actor.state.managed_actors[0].root_provenance);
        assert_eq!(
            actor.state.managed_actors[0].installation_data,
            install
                .installation_data
                .as_ref()
                .map(|data| authority_blob(&data.reference))
        );
        let protected = actor.state.clone();
        for (invocation, request) in [
            (
                0x2c,
                ManagementRequest::Suspend {
                    actor: install.entry.actor,
                    expected_deployment: install.entry.deployment,
                },
            ),
            (
                0x2d,
                ManagementRequest::Resume {
                    actor: install.entry.actor,
                    expected_deployment: install.entry.deployment,
                },
            ),
            (
                0x2e,
                ManagementRequest::RemoveLeaf {
                    actor: install.entry.actor,
                    expected_deployment: install.entry.deployment,
                },
            ),
        ] {
            let protected_call = credential_call(
                config,
                &signing(0x21),
                ADMIN_PRINCIPAL,
                Some(ADMIN_NODE),
                invocation,
                system_target(config),
                request,
            );
            assert!(dispatch(&mut actor, &protected_call).is_empty());
            assert_eq!(actor.state, protected);
        }
        let mut incompatible = actor_upgrade(&install, 0x2f);
        incompatible.state_layout = Hash([0x30; 32]);
        let incompatible_call = credential_call(
            config,
            &signing(0x21),
            ADMIN_PRINCIPAL,
            Some(ADMIN_NODE),
            0x32,
            system_target(config),
            ManagementRequest::UpgradeActor(Box::new(incompatible)),
        );
        assert!(dispatch(&mut actor, &incompatible_call).is_empty());
        assert_eq!(actor.state, protected);

        let linear = <SystemAuthority as vos::Actor>::__save_agent_lane(&actor, StateLane::Linear);
        let mut restarted = <SystemAuthority as vos::Actor>::__load_agent_state(
            Some(&config.encode()),
            Some(&linear),
            None,
            None,
        )
        .expect("seeded SAC5 authority state restarts");
        assert_eq!(restarted.state.authorization_sequence, 3);
        assert_eq!(restarted.state.managed_agents, vec![expected_seed]);
        assert_eq!(restarted.state.managed_actors, vec![expected_actor]);
        assert!(authority_state_is_valid(&config, &restarted.state));
        assert!(
            dispatch(&mut restarted, &call).is_empty(),
            "a finalized ACC3 older than the credential high-water is not synthesized"
        );
        let finalized = restarted.state.clone();
        assert!(dispatch_ack(&mut restarted, &ack));
        assert_eq!(restarted.state, finalized);
    }

    #[test]
    fn actor_projection_changes_only_after_exact_acknowledged_lifecycle_operations() {
        let config = configuration();
        let mut actor = actor();
        let managed_descriptor = descriptor(config, ADMIN_PRINCIPAL, AgentProfile::Local, 0x4f);
        insert_live(&mut actor, &managed_descriptor);
        let managed = target_for(&managed_descriptor);
        let install = actor_install(managed.agent, "lifecycle", 0x50);
        let mut install_call = credential_call(
            config,
            &signing(0x21),
            ADMIN_PRINCIPAL,
            Some(ADMIN_NODE),
            0x51,
            managed,
            ManagementRequest::Install(Box::new(install.clone())),
        );
        prepare_management_call(&actor, &mut install_call, &signing(0x21));
        let install_approval = ManagementApproval::decode(&dispatch(&mut actor, &install_call))
            .expect("valid Install is approved");
        assert_eq!(install_approval.authorization_sequence.get(), 4);
        assert!(actor.state.managed_actors.is_empty());
        let approval_head = projection_head(&actor.state).expect("approval has a signed head");

        let mut duplicate = credential_call(
            config,
            &signing(0x21),
            ADMIN_PRINCIPAL,
            Some(ADMIN_NODE),
            0x52,
            managed,
            ManagementRequest::Install(Box::new(install.clone())),
        );
        prepare_management_call(&actor, &mut duplicate, &signing(0x21));
        let pending = actor.state.clone();
        assert!(dispatch(&mut actor, &duplicate).is_empty());
        assert_eq!(actor.state, pending);

        let install_ack = application_ack(config, &actor.state, &install_call, &install_approval);
        let install_plan = ManagementAuthorizationPlan::from_request(&ManagementRequest::Install(
            Box::new(install.clone()),
        ))
        .expect("install fixture has a compact authorization plan");
        let ManagementAuthorizationPlan::Install(compact_install) = &install_plan else {
            unreachable!()
        };
        let installed = installed_actor_row(
            managed.agent,
            compact_install,
            install_plan.commitment(),
            false,
        );
        assert!(dispatch_ack(&mut actor, &install_ack));
        let acknowledged_head = projection_head(&actor.state).expect("Ack has a signed head");
        assert_eq!(acknowledged_head.epoch, approval_head.epoch);
        assert_eq!(
            acknowledged_head.authorization_sequence,
            approval_head.authorization_sequence
        );
        assert_eq!(
            acknowledged_head.administration_generation,
            approval_head.administration_generation
        );
        assert!(acknowledged_head.state_revision > approval_head.state_revision);
        assert_ne!(
            acknowledged_head.state_commitment,
            approval_head.state_commitment
        );
        assert_eq!(actor.state.managed_actors, vec![installed.clone()]);
        assert_installed_projection(
            &actor.state.managed_actors[0],
            managed.agent,
            &install,
            false,
        );

        let mut stale_upgrade = actor_upgrade(&install, 0x53);
        stale_upgrade.from_deployment = DeploymentId([0x54; 32]);
        let mut stale_call = credential_call(
            config,
            &signing(0x21),
            ADMIN_PRINCIPAL,
            Some(ADMIN_NODE),
            0x55,
            managed,
            ManagementRequest::UpgradeActor(Box::new(stale_upgrade)),
        );
        prepare_management_call(&actor, &mut stale_call, &signing(0x21));
        let before_stale = actor.state.clone();
        assert!(dispatch(&mut actor, &stale_call).is_empty());
        assert_eq!(actor.state, before_stale);

        let upgrade = actor_upgrade(&install, 0x56);
        let mut upgrade_call = credential_call(
            config,
            &signing(0x21),
            ADMIN_PRINCIPAL,
            Some(ADMIN_NODE),
            0x57,
            managed,
            ManagementRequest::UpgradeActor(Box::new(upgrade.clone())),
        );
        prepare_management_call(&actor, &mut upgrade_call, &signing(0x21));
        let before_upgrade_ack = actor.state.managed_actors.clone();
        let upgrade_approval = ManagementApproval::decode(&dispatch(&mut actor, &upgrade_call))
            .expect("compatible UpgradeActor is approved");
        assert_eq!(upgrade_approval.authorization_sequence.get(), 5);
        assert_eq!(actor.state.managed_actors, before_upgrade_ack);
        let upgrade_ack = application_ack(config, &actor.state, &upgrade_call, &upgrade_approval);
        let mut divergent_ack = upgrade_ack.clone();
        divergent_ack.request = Hash([0x58; 32]);
        divergent_ack.receipt.selector.request = divergent_ack.request;
        resign_receipt(&mut divergent_ack.receipt);
        resign_ack(&mut divergent_ack);
        let before_divergent_ack = actor.state.clone();
        assert!(!dispatch_ack(&mut actor, &divergent_ack));
        assert_eq!(actor.state, before_divergent_ack);
        assert!(dispatch_ack(&mut actor, &upgrade_ack));
        let upgraded = upgraded_actor_row(&installed, &upgrade).expect("compatible row update");
        assert_eq!(actor.state.managed_actors, vec![upgraded.clone()]);
        let projected = &actor.state.managed_actors[0];
        assert_eq!(projected.deployment, upgrade.to_deployment.0);
        assert_eq!(projected.program, upgrade.to_program.0);
        assert_eq!(projected.producer, upgrade.producer.0);
        assert_eq!(projected.package, authority_blob(&upgrade.package));
        assert_eq!(
            projected.agent_schema,
            authority_blob(&upgrade.agent_schema)
        );
        assert_eq!(
            projected.method_policy,
            authority_blob(&upgrade.method_policy)
        );
        assert_eq!(projected.installation_data, installed.installation_data);
        assert_eq!(projected.installation_id, installed.installation_id);
        assert_eq!(
            projected.registry_reservation,
            installed.registry_reservation
        );
        assert_eq!(projected.install_request, installed.install_request);

        let mut stale_after_upgrade = credential_call(
            config,
            &signing(0x21),
            ADMIN_PRINCIPAL,
            Some(ADMIN_NODE),
            0x59,
            managed,
            ManagementRequest::Suspend {
                actor: install.entry.actor,
                expected_deployment: install.entry.deployment,
            },
        );
        prepare_management_call(&actor, &mut stale_after_upgrade, &signing(0x21));
        let before_stale = actor.state.clone();
        assert!(dispatch(&mut actor, &stale_after_upgrade).is_empty());
        assert_eq!(actor.state, before_stale);

        let mut suspend_call = credential_call(
            config,
            &signing(0x21),
            ADMIN_PRINCIPAL,
            Some(ADMIN_NODE),
            0x5a,
            managed,
            ManagementRequest::Suspend {
                actor: install.entry.actor,
                expected_deployment: upgrade.to_deployment,
            },
        );
        prepare_management_call(&actor, &mut suspend_call, &signing(0x21));
        let suspend_approval = ManagementApproval::decode(&dispatch(&mut actor, &suspend_call))
            .expect("exact Suspend is approved");
        assert_eq!(suspend_approval.authorization_sequence.get(), 6);
        assert!(!actor.state.managed_actors[0].suspended);
        assert!(dispatch_application_ack(
            &mut actor,
            &suspend_call,
            &suspend_approval,
        ));
        assert!(actor.state.managed_actors[0].suspended);

        let mut resume_call = credential_call(
            config,
            &signing(0x21),
            ADMIN_PRINCIPAL,
            Some(ADMIN_NODE),
            0x5b,
            managed,
            ManagementRequest::Resume {
                actor: install.entry.actor,
                expected_deployment: upgrade.to_deployment,
            },
        );
        prepare_management_call(&actor, &mut resume_call, &signing(0x21));
        let resume_approval = ManagementApproval::decode(&dispatch(&mut actor, &resume_call))
            .expect("exact Resume is approved");
        assert_eq!(resume_approval.authorization_sequence.get(), 7);
        assert!(actor.state.managed_actors[0].suspended);
        assert!(dispatch_application_ack(
            &mut actor,
            &resume_call,
            &resume_approval,
        ));
        assert!(!actor.state.managed_actors[0].suspended);

        let mut remove_call = credential_call(
            config,
            &signing(0x21),
            ADMIN_PRINCIPAL,
            Some(ADMIN_NODE),
            0x5c,
            managed,
            ManagementRequest::RemoveLeaf {
                actor: install.entry.actor,
                expected_deployment: upgrade.to_deployment,
            },
        );
        prepare_management_call(&actor, &mut remove_call, &signing(0x21));
        let remove_approval = ManagementApproval::decode(&dispatch(&mut actor, &remove_call))
            .expect("exact RemoveLeaf is approved");
        assert_eq!(remove_approval.authorization_sequence.get(), 8);
        assert_eq!(actor.state.managed_actors.len(), 1);
        assert!(dispatch_application_ack(
            &mut actor,
            &remove_call,
            &remove_approval,
        ));
        assert!(actor.state.managed_actors.is_empty());
        assert_eq!(
            actor.state.retired_actor_installations,
            vec![RetiredActorInstallationRow {
                agent: managed.agent.0,
                installation_id: install.installation_id.0,
            }]
        );

        let mut reuse = actor_install(managed.agent, "replacement", 0x5d);
        reuse.installation_id = install.installation_id;
        let mut reuse_call = credential_call(
            config,
            &signing(0x21),
            ADMIN_PRINCIPAL,
            Some(ADMIN_NODE),
            0x5e,
            managed,
            ManagementRequest::Install(Box::new(reuse)),
        );
        prepare_management_call(&actor, &mut reuse_call, &signing(0x21));
        let before_reuse = actor.state.clone();
        assert!(dispatch(&mut actor, &reuse_call).is_empty());
        assert_eq!(actor.state, before_reuse);

        let linear = <SystemAuthority as vos::Actor>::__save_agent_lane(&actor, StateLane::Linear);
        let restarted = <SystemAuthority as vos::Actor>::__load_agent_state(
            Some(&config.encode()),
            Some(&linear),
            None,
            None,
        )
        .expect("acknowledged actor lifecycle projection restarts");
        assert_eq!(restarted.state, actor.state);
        assert!(authority_state_is_valid(&config, &restarted.state));
    }

    #[test]
    fn shared_replica_projection_requires_exact_cas_and_maa2_generation() {
        let config = configuration();
        let mut actor = actor();
        let additional_node = enroll_additional_node(&mut actor, ADMIN_PRINCIPAL, 0x65);
        let shared = descriptor(config, ADMIN_PRINCIPAL, AgentProfile::Shared, 0x66);
        insert_live(&mut actor, &shared);
        let managed = target_for(&shared);
        let shared_index = managed_agent(&actor.state, managed.agent).unwrap();
        let original = actor.state.managed_agents[shared_index].clone();

        let mut replacement = shared.replicas.clone();
        replacement.push(AgentReplica {
            node: additional_node,
            principal: ADMIN_PRINCIPAL,
            role: ReplicaRole::Observer,
        });
        replacement.sort_by_key(|replica| replica.node);
        let mut change = credential_call(
            config,
            &signing(0x21),
            ADMIN_PRINCIPAL,
            Some(ADMIN_NODE),
            0x67,
            managed,
            ManagementRequest::ChangeReplicas {
                expected_generation: Hash(original.replica_generation),
                replicas: replacement.clone(),
            },
        );
        prepare_management_call(&actor, &mut change, &signing(0x21));
        let approval = ManagementApproval::decode(&dispatch(&mut actor, &change))
            .expect("exact Shared replica CAS is approved");
        assert_eq!(actor.state.managed_agents[shared_index], original);

        let acknowledgement = application_ack(config, &actor.state, &change, &approval);
        let expected_generation = match acknowledgement.application {
            ManagementReply::ReplicasChanged { generation } => generation,
            _ => panic!("replica change must produce an exact typed application fact"),
        };
        let mut wrong_generation = acknowledgement.clone();
        wrong_generation.application = ManagementReply::ReplicasChanged {
            generation: Hash([0x68; 32]),
        };
        resign_ack(&mut wrong_generation);
        let before_wrong_generation = actor.state.clone();
        assert!(!dispatch_ack(&mut actor, &wrong_generation));
        assert_eq!(actor.state, before_wrong_generation);

        let mut wrong_variant = acknowledgement.clone();
        wrong_variant.application = ManagementReply::Removed(ActorId([0x69; 32]));
        resign_ack(&mut wrong_variant);
        let before_wrong_variant = actor.state.clone();
        assert!(!dispatch_ack(&mut actor, &wrong_variant));
        assert_eq!(actor.state, before_wrong_variant);

        assert!(dispatch_ack(&mut actor, &acknowledgement));
        let projected = &actor.state.managed_agents[shared_index];
        assert_eq!(projected.replicas, managed_replica_rows(&replacement));
        assert_eq!(projected.replica_generation, expected_generation.0);

        let unbind_in_use = admin_call(
            config,
            &signing(0x21),
            ADMIN_PRINCIPAL,
            ADMIN_NODE,
            0x6a,
            actor.state.administration_generation,
            AuthorityAdminOperation::UnbindNodeOwner {
                node: additional_node,
                owner: ADMIN_PRINCIPAL,
            },
        );
        let before_unbind = actor.state.clone();
        assert!(dispatch_admin(&mut actor, &unbind_in_use).is_empty());
        assert_eq!(actor.state, before_unbind);

        let mut stale_revert = credential_call(
            config,
            &signing(0x21),
            ADMIN_PRINCIPAL,
            Some(ADMIN_NODE),
            0x6b,
            managed,
            ManagementRequest::ChangeReplicas {
                expected_generation: Hash(original.replica_generation),
                replicas: shared.replicas.clone(),
            },
        );
        prepare_management_call(&actor, &mut stale_revert, &signing(0x21));
        let before_stale = actor.state.clone();
        assert!(dispatch(&mut actor, &stale_revert).is_empty());
        assert_eq!(actor.state, before_stale);

        for (invocation, profile, nonce) in [
            (0x6c, AgentProfile::Local, 0x6d),
            (0x6e, AgentProfile::Private, 0x6f),
        ] {
            let descriptor = descriptor(config, ADMIN_PRINCIPAL, profile, nonce);
            insert_live(&mut actor, &descriptor);
            let index = managed_agent(&actor.state, descriptor.identity.agent).unwrap();
            let row = actor.state.managed_agents[index].clone();
            let mut proposed = descriptor.replicas.clone();
            proposed.push(AgentReplica {
                node: additional_node,
                principal: ADMIN_PRINCIPAL,
                role: ReplicaRole::Observer,
            });
            proposed.sort_by_key(|replica| replica.node);
            let mut denied = credential_call(
                config,
                &signing(0x21),
                ADMIN_PRINCIPAL,
                Some(ADMIN_NODE),
                invocation,
                target_for(&descriptor),
                ManagementRequest::ChangeReplicas {
                    expected_generation: Hash(row.replica_generation),
                    replicas: proposed,
                },
            );
            prepare_management_call(&actor, &mut denied, &signing(0x21));
            let before = actor.state.clone();
            assert!(dispatch(&mut actor, &denied).is_empty());
            assert_eq!(actor.state, before);
        }

        let mut corrupt_generation = actor.state.clone();
        corrupt_generation.managed_agents[shared_index].replica_generation[0] ^= 1;
        assert!(!authority_state_is_valid(&config, &corrupt_generation));
        let mut corrupt_roster = actor.state.clone();
        corrupt_roster.managed_agents[shared_index].replicas[0].principal[0] ^= 1;
        assert!(!authority_state_is_valid(&config, &corrupt_roster));

        let linear = <SystemAuthority as vos::Actor>::__save_agent_lane(&actor, StateLane::Linear);
        let restarted = <SystemAuthority as vos::Actor>::__load_agent_state(
            Some(&config.encode()),
            Some(&linear),
            None,
            None,
        )
        .expect("exact replica projection restarts");
        assert_eq!(restarted.state, actor.state);
    }

    #[test]
    fn acc3_authorizes_full_replica_limit_and_rejects_principal_substitution() {
        let config = configuration();
        let key = signing(0x21);
        let mut actor = actor();

        for ordinal in 0_u64..(MAX_AGENT_REPLICAS as u64 - 1) {
            let mut seed = [0xa5; 32];
            seed[..8].copy_from_slice(&ordinal.to_le_bytes());
            let transport_key = SigningKey::from_bytes(&seed);
            let mut enrollment = NodeEncryptionEnrollment::from_keys(
                SpaceId(config.space),
                ADMIN_PRINCIPAL,
                transport_key.verifying_key().to_bytes(),
                [0x42; 32],
                [1; PRIVATE_SIGNATURE_BYTES],
            );
            resign_node_enrollment(&mut enrollment, &transport_key);
            assert!(enrolled_node(&actor.state, enrollment.node).is_none());
            assert!(insert_enrolled_node(&mut actor.state, enrollment));
        }
        assert_eq!(actor.state.nodes.len(), MAX_AGENT_REPLICAS);
        assert!(refresh_state_integrity_commitment(
            &config,
            &mut actor.state
        ));
        assert!(authority_state_is_valid(&config, &actor.state));

        // This establishes the inline header bound, not physical guest work
        // budgets or the complete state at every Authority capacity shape.
        let enrolled_state_bytes =
            <SystemAuthority as vos::Actor>::__save_agent_lane(&actor, StateLane::Linear).len();
        println!("full replica enrollment Linear bytes={enrolled_state_bytes} inner_state_limit={}",
            vos::agent::execution::MAX_EXECUTION_STATE_TOTAL_BYTES);
        assert!(enrolled_state_bytes <= vos::agent::execution::MAX_EXECUTION_STATE_TOTAL_BYTES,
            "row-backed enrollment header must fit the physical inline ceiling");

        let mut descriptor = descriptor(config, ADMIN_PRINCIPAL, AgentProfile::Shared, 0xa6);
        descriptor.replicas = actor
            .state
            .nodes
            .indices()
            .map(|row| AgentReplica {
                node: NodeId(row.node),
                principal: ADMIN_PRINCIPAL,
                role: ReplicaRole::Voter,
            })
            .collect();
        assert_eq!(descriptor.replicas.len(), MAX_AGENT_REPLICAS);
        assert_eq!(descriptor.validate(), Ok(()));
        let managed = target_for(&descriptor);

        let mut substituted_descriptor = descriptor.clone();
        substituted_descriptor.replicas[0].principal = PrincipalId([0xa7; 32]);
        let substituted_create = credential_call(
            config,
            &key,
            ADMIN_PRINCIPAL,
            Some(ADMIN_NODE),
            0xa8,
            managed,
            ManagementRequest::Create(Box::new(substituted_descriptor)),
        );
        assert!(substituted_create.encode().unwrap().len() <= MAX_INVOCATION_MESSAGE_BYTES);
        let before_substituted_create = actor.state.clone();
        assert!(dispatch(&mut actor, &substituted_create).is_empty());
        assert_eq!(actor.state, before_substituted_create);

        let create = credential_call(
            config,
            &key,
            ADMIN_PRINCIPAL,
            Some(ADMIN_NODE),
            0xa9,
            managed,
            ManagementRequest::Create(Box::new(descriptor.clone())),
        );
        assert!(create.encode().unwrap().len() <= MAX_INVOCATION_MESSAGE_BYTES);
        let create_approval = ManagementApproval::decode(&dispatch(&mut actor, &create))
            .expect("a full 256-replica Create must fit and authorize");
        assert!(dispatch_application_ack(
            &mut actor,
            &create,
            &create_approval,
        ));

        let managed_index = managed_agent(&actor.state, managed.agent).unwrap();
        let expected_generation =
            Hash(actor.state.managed_agents[managed_index].replica_generation);
        let mut replacement = descriptor.replicas.clone();
        replacement[MAX_AGENT_REPLICAS - 1].role = ReplicaRole::Observer;
        let mut substituted_replacement = replacement.clone();
        substituted_replacement[0].principal = PrincipalId([0xaa; 32]);
        let mut substituted_change = credential_call(
            config,
            &key,
            ADMIN_PRINCIPAL,
            Some(ADMIN_NODE),
            0xab,
            managed,
            ManagementRequest::ChangeReplicas {
                expected_generation,
                replicas: substituted_replacement,
            },
        );
        prepare_management_call(&actor, &mut substituted_change, &key);
        assert!(substituted_change.encode().unwrap().len() <= MAX_INVOCATION_MESSAGE_BYTES);
        let before_substituted_change = actor.state.clone();
        assert!(dispatch(&mut actor, &substituted_change).is_empty());
        assert_eq!(actor.state, before_substituted_change);

        let mut change = credential_call(
            config,
            &key,
            ADMIN_PRINCIPAL,
            Some(ADMIN_NODE),
            0xac,
            managed,
            ManagementRequest::ChangeReplicas {
                expected_generation,
                replicas: replacement.clone(),
            },
        );
        prepare_management_call(&actor, &mut change, &key);
        assert!(change.encode().unwrap().len() <= MAX_INVOCATION_MESSAGE_BYTES);
        let change_approval = ManagementApproval::decode(&dispatch(&mut actor, &change))
            .expect("a full 256-replica ChangeReplicas must fit and authorize");
        assert!(dispatch_application_ack(
            &mut actor,
            &change,
            &change_approval,
        ));
        assert_eq!(
            actor.state.managed_agents[managed_index].replicas,
            managed_replica_rows(&replacement)
        );
        assert!(authority_state_is_valid(&config, &actor.state));
    }

    #[test]
    fn pending_parent_and_runtime_transitions_are_serialized() {
        let config = configuration();
        let descriptor = descriptor(config, ADMIN_PRINCIPAL, AgentProfile::Local, 0x7f);
        let managed = target_for(&descriptor);
        let mut actor = actor();
        insert_live(&mut actor, &descriptor);

        let parent = actor_install(managed.agent, "parent", 0x80);
        let mut parent_call = credential_call(
            config,
            &signing(0x21),
            ADMIN_PRINCIPAL,
            Some(ADMIN_NODE),
            0x81,
            managed,
            ManagementRequest::Install(Box::new(parent.clone())),
        );
        prepare_management_call(&actor, &mut parent_call, &signing(0x21));
        let parent_approval = ManagementApproval::decode(&dispatch(&mut actor, &parent_call))
            .expect("parent install approved");
        assert!(dispatch_application_ack(
            &mut actor,
            &parent_call,
            &parent_approval,
        ));

        let mut child = actor_install(managed.agent, "child", 0x82);
        child.entry.parent = Some(parent.entry.actor);
        child.entry.actor = ActorId::owned_child(parent.entry.actor, &child.entry.name);
        let mut child_call = credential_call(
            config,
            &signing(0x21),
            ADMIN_PRINCIPAL,
            Some(ADMIN_NODE),
            0x83,
            managed,
            ManagementRequest::Install(Box::new(child.clone())),
        );
        prepare_management_call(&actor, &mut child_call, &signing(0x21));
        let child_approval = ManagementApproval::decode(&dispatch(&mut actor, &child_call))
            .expect("child install approved");
        assert_eq!(actor.state.managed_actors.len(), 1);

        for (invocation, request) in [
            (
                0x84,
                ManagementRequest::Suspend {
                    actor: parent.entry.actor,
                    expected_deployment: parent.entry.deployment,
                },
            ),
            (
                0x85,
                ManagementRequest::RemoveLeaf {
                    actor: parent.entry.actor,
                    expected_deployment: parent.entry.deployment,
                },
            ),
        ] {
            let mut call = credential_call(
                config,
                &signing(0x21),
                ADMIN_PRINCIPAL,
                Some(ADMIN_NODE),
                invocation,
                managed,
                request,
            );
            prepare_management_call(&actor, &mut call, &signing(0x21));
            let before = actor.state.clone();
            assert!(dispatch(&mut actor, &call).is_empty());
            assert_eq!(actor.state, before);
        }

        let runtime_request =
            ManagementRequest::UpgradeRuntime(Box::new(vos::agent_sdk::RuntimeUpgrade {
                from_deployment: managed.runtime_deployment,
                to_deployment: DeploymentId([0x86; 32]),
                to_program: ProgramId([0x87; 32]),
                producer: ProducerId([0x88; 32]),
                package: BlobRef::of_bytes(b"serialized-runtime-upgrade"),
                contract: RuntimePackageContract::canonical(),
                capabilities: RuntimeCapabilities::standard(),
            }));
        let mut blocked_runtime = credential_call(
            config,
            &signing(0x21),
            ADMIN_PRINCIPAL,
            Some(ADMIN_NODE),
            0x89,
            managed,
            runtime_request.clone(),
        );
        prepare_management_call(&actor, &mut blocked_runtime, &signing(0x21));
        let before = actor.state.clone();
        assert!(dispatch(&mut actor, &blocked_runtime).is_empty());
        assert_eq!(actor.state, before);

        assert!(dispatch_application_ack(
            &mut actor,
            &child_call,
            &child_approval,
        ));
        let mut runtime_call = credential_call(
            config,
            &signing(0x21),
            ADMIN_PRINCIPAL,
            Some(ADMIN_NODE),
            0x8a,
            managed,
            runtime_request,
        );
        prepare_management_call(&actor, &mut runtime_call, &signing(0x21));
        assert!(ManagementApproval::decode(&dispatch(&mut actor, &runtime_call)).is_ok());

        let mut child_suspend = credential_call(
            config,
            &signing(0x21),
            ADMIN_PRINCIPAL,
            Some(ADMIN_NODE),
            0x8b,
            managed,
            ManagementRequest::Suspend {
                actor: child.entry.actor,
                expected_deployment: child.entry.deployment,
            },
        );
        prepare_management_call(&actor, &mut child_suspend, &signing(0x21));
        let before = actor.state.clone();
        assert!(dispatch(&mut actor, &child_suspend).is_empty());
        assert_eq!(actor.state, before);
        assert!(authority_state_is_valid(&config, &actor.state));
    }

    #[test]
    fn root_seed_and_authorization_high_water_cannot_drift() {
        let config = configuration();
        let actor = actor();

        let mut missing_seed = actor.state.clone();
        missing_seed.managed_agents.clear();
        assert!(!authority_state_is_valid(&config, &missing_seed));

        let mut altered_seed = actor.state.clone();
        altered_seed.managed_agents[0].runtime_program[0] ^= 1;
        assert!(!authority_state_is_valid(&config, &altered_seed));

        let mut altered_profile = actor.state.clone();
        altered_profile.managed_agents[0].profile = AgentProfile::Local as u8;
        assert!(!authority_state_is_valid(&config, &altered_profile));

        for altered_high_water in [0, 1, 3, u64::MAX] {
            let mut altered = actor.state.clone();
            altered.authorization_sequence = altered_high_water;
            assert!(!authority_state_is_valid(&config, &altered));
        }
    }

    #[test]
    fn authority_and_cross_agent_actor_targets_fail_closed() {
        let config = configuration();
        let authority_actor = ActorId(config.binding.issuer.actor);
        let authority_deployment = DeploymentId(config.binding.issuer.deployment);
        let mut forged_install = actor_install(
            AgentId(config.system_agent),
            "forged-system-authority",
            0x60,
        );
        forged_install.entry.actor = authority_actor;
        let mut forged_upgrade = actor_upgrade(&catalog_install(config), 0x61);
        forged_upgrade.actor = authority_actor;
        forged_upgrade.from_deployment = authority_deployment;
        let requests = [
            ManagementRequest::Install(Box::new(forged_install)),
            ManagementRequest::UpgradeActor(Box::new(forged_upgrade)),
            ManagementRequest::Suspend {
                actor: authority_actor,
                expected_deployment: authority_deployment,
            },
            ManagementRequest::Resume {
                actor: authority_actor,
                expected_deployment: authority_deployment,
            },
            ManagementRequest::RemoveLeaf {
                actor: authority_actor,
                expected_deployment: authority_deployment,
            },
        ];
        let mut actor = actor();
        assert!(protected_authority_actor(&config, authority_actor));
        for (offset, request) in requests.into_iter().enumerate() {
            let call = credential_call(
                config,
                &signing(0x21),
                ADMIN_PRINCIPAL,
                Some(ADMIN_NODE),
                0x62 + u8::try_from(offset).unwrap(),
                system_target(config),
                request,
            );
            let before = actor.state.clone();
            assert!(dispatch(&mut actor, &call).is_empty());
            assert_eq!(actor.state, before);
        }

        let descriptor = descriptor(config, ADMIN_PRINCIPAL, AgentProfile::Local, 0x68);
        insert_live(&mut actor, &descriptor);
        let managed = target_for(&descriptor);
        let install = actor_install(managed.agent, "agent-scoped", 0x69);
        let mut install_call = credential_call(
            config,
            &signing(0x21),
            ADMIN_PRINCIPAL,
            Some(ADMIN_NODE),
            0x6a,
            managed,
            ManagementRequest::Install(Box::new(install.clone())),
        );
        prepare_management_call(&actor, &mut install_call, &signing(0x21));
        let approval = ManagementApproval::decode(&dispatch(&mut actor, &install_call)).unwrap();
        assert!(dispatch_application_ack(
            &mut actor,
            &install_call,
            &approval,
        ));

        let mut cross_agent = credential_call(
            config,
            &signing(0x21),
            ADMIN_PRINCIPAL,
            Some(ADMIN_NODE),
            0x6b,
            system_target(config),
            ManagementRequest::Suspend {
                actor: install.entry.actor,
                expected_deployment: install.entry.deployment,
            },
        );
        prepare_management_call(&actor, &mut cross_agent, &signing(0x21));
        let before = actor.state.clone();
        assert!(dispatch(&mut actor, &cross_agent).is_empty());
        assert_eq!(actor.state, before);

        let wrong_agent_install = actor_install(managed.agent, "wrong-agent", 0x6c);
        let mut wrong_agent_call = credential_call(
            config,
            &signing(0x21),
            ADMIN_PRINCIPAL,
            Some(ADMIN_NODE),
            0x6d,
            system_target(config),
            ManagementRequest::Install(Box::new(wrong_agent_install)),
        );
        prepare_management_call(&actor, &mut wrong_agent_call, &signing(0x21));
        assert!(dispatch(&mut actor, &wrong_agent_call).is_empty());
        assert_eq!(actor.state, before);
    }

    #[test]
    fn actor_projection_rejects_unbacked_rows_corruption_and_explicit_limit_overflow() {
        let config = configuration();
        let install = catalog_install(config);
        let call = credential_call(
            config,
            &signing(0x21),
            ADMIN_PRINCIPAL,
            Some(ADMIN_NODE),
            0x70,
            system_target(config),
            ManagementRequest::Install(Box::new(install)),
        );
        let mut actor = actor();
        let approval = ManagementApproval::decode(&dispatch(&mut actor, &call)).unwrap();
        assert!(dispatch_application_ack(&mut actor, &call, &approval));
        let row = actor.state.managed_actors[0].clone();

        let mut altered = actor.state.clone();
        altered.managed_actors[0].deployment[0] ^= 1;
        assert!(!authority_state_is_valid(&config, &altered));

        let mut lost_root_provenance = actor.state.clone();
        lost_root_provenance.managed_actors[0].root_provenance = false;
        assert!(!authority_state_is_valid(&config, &lost_root_provenance));

        let mut duplicate = actor.state.clone();
        duplicate.managed_actors.push(row.clone());
        assert!(!authority_state_is_valid(&config, &duplicate));

        let mut unbacked = AuthorityLinearState::bootstrap(config);
        unbacked.managed_actors.push(row.clone());
        assert!(!authority_state_is_valid(&config, &unbacked));

        let mut unsupported_actor_abi = actor.state.clone();
        unsupported_actor_abi.managed_agents[0]
            .runtime_contract
            .actor_abi_minimum = vos::agent_sdk::contract::ACTOR_ABI + 1;
        unsupported_actor_abi.managed_agents[0]
            .runtime_contract
            .actor_abi_maximum = vos::agent_sdk::contract::ACTOR_ABI + 1;
        assert!(!authority_state_is_valid(&config, &unsupported_actor_abi));

        let mut unsupported_actor_lane = actor.state.clone();
        unsupported_actor_lane.managed_agents[0].capabilities.lanes =
            LaneSet::of(vos::agent_sdk::StateLane::Linear).bits();
        assert!(!authority_state_is_valid(&config, &unsupported_actor_lane));

        let later_install = actor_install(AgentId(config.system_agent), "later-system", 0x72);
        let mut later_call = credential_call(
            config,
            &signing(0x21),
            ADMIN_PRINCIPAL,
            Some(ADMIN_NODE),
            0x73,
            system_target(config),
            ManagementRequest::Install(Box::new(later_install.clone())),
        );
        prepare_management_call(&actor, &mut later_call, &signing(0x21));
        let later_approval =
            ManagementApproval::decode(&dispatch(&mut actor, &later_call)).unwrap();
        assert!(dispatch_application_ack(
            &mut actor,
            &later_call,
            &later_approval,
        ));
        assert!(authority_state_is_valid(&config, &actor.state));
        let root_index = actor
            .state
            .managed_actors
            .iter()
            .position(|candidate| candidate.root_provenance)
            .unwrap();
        let later_index = managed_actor(
            &actor.state,
            AgentId(config.system_agent),
            later_install.entry.actor,
        )
        .unwrap();

        let mut deleted_marker = actor.state.clone();
        deleted_marker.managed_actors[root_index].root_provenance = false;
        assert!(!authority_state_is_valid(&config, &deleted_marker));

        let mut moved_marker = deleted_marker;
        moved_marker.managed_actors[later_index].root_provenance = true;
        assert!(!authority_state_is_valid(&config, &moved_marker));

        let mut marked_later = actor.state.clone();
        marked_later.managed_actors[later_index].root_provenance = true;
        assert!(!authority_state_is_valid(&config, &marked_later));

        assert_eq!(
            MAX_MANAGED_ACTORS,
            vos::agent_sdk::STANDARD_MAX_ACTORS as usize
        );
        let mut actor_overflow = AuthorityLinearState::bootstrap(config);
        actor_overflow.managed_actors = vec![row; MAX_MANAGED_ACTORS + 1];
        assert!(!authority_state_is_valid(&config, &actor_overflow));

        assert_eq!(
            MAX_RETIRED_ACTOR_INSTALLATIONS,
            MAX_RUNTIME_STATE_BYTES / (2 * core::mem::size_of::<[u8; 32]>())
        );
        let mut retired_overflow = AuthorityLinearState::bootstrap(config);
        retired_overflow.retired_actor_installations = vec![
            RetiredActorInstallationRow {
                agent: config.system_agent,
                installation_id: [0x71; 32],
            };
            MAX_RETIRED_ACTOR_INSTALLATIONS + 1
        ];
        assert!(!authority_state_is_valid(&config, &retired_overflow));
    }

    #[test]
    fn acknowledged_system_runtime_upgrade_is_the_only_seed_runtime_evolution() {
        let config = configuration();
        let mut actor = actor();
        let reused_signer_request =
            ManagementRequest::UpgradeRuntime(Box::new(vos::agent_sdk::RuntimeUpgrade {
                from_deployment: DeploymentId(config.system_runtime_deployment),
                to_deployment: DeploymentId([0x28; 32]),
                to_program: ProgramId([0x29; 32]),
                producer: ProducerId(config.system_transition_producer),
                package: BlobRef::of_bytes(b"runtime-reusing-transition-signer"),
                contract: RuntimePackageContract::canonical(),
                capabilities: RuntimeCapabilities::standard(),
            }));
        let reused_signer_call = credential_call(
            config,
            &signing(0x21),
            ADMIN_PRINCIPAL,
            Some(ADMIN_NODE),
            0x2b,
            system_target(config),
            reused_signer_request,
        );
        let before_reused_signer = actor.state.clone();
        assert!(reused_signer_call.validate_shape().is_err());
        assert!(
            policy_effect(
                &config,
                &actor.state,
                &reused_signer_call,
                BuiltinPrincipalRole::Admin,
            )
            .is_none(),
            "state-transition policy must independently reject role-reused signers",
        );
        assert_eq!(actor.state, before_reused_signer);

        let request = ManagementRequest::UpgradeRuntime(Box::new(vos::agent_sdk::RuntimeUpgrade {
            from_deployment: DeploymentId(config.system_runtime_deployment),
            to_deployment: DeploymentId([0x2c; 32]),
            to_program: ProgramId([0x2d; 32]),
            producer: ProducerId([0x2e; 32]),
            package: BlobRef::of_bytes(b"compatible-system-runtime"),
            contract: RuntimePackageContract::canonical(),
            capabilities: RuntimeCapabilities::standard(),
        }));
        let call = credential_call(
            config,
            &signing(0x21),
            ADMIN_PRINCIPAL,
            Some(ADMIN_NODE),
            0x2f,
            system_target(config),
            request,
        );
        let approval = ManagementApproval::decode(&dispatch(&mut actor, &call)).unwrap();
        assert_eq!(approval.authorization_sequence.get(), 3);
        let mut substituted = application_ack(config, &actor.state, &call, &approval);
        let ManagementReply::RuntimeUpgraded(identity) = &mut substituted.application else {
            unreachable!();
        };
        identity.transition_producer = ProducerId([0xef; 32]);
        resign_ack(&mut substituted);
        let before_substitution = actor.state.clone();
        assert!(!dispatch_ack(&mut actor, &substituted));
        assert_eq!(actor.state, before_substitution);
        assert!(dispatch_application_ack(&mut actor, &call, &approval));
        let system = &actor.state.managed_agents
            [managed_agent(&actor.state, AgentId(config.system_agent)).unwrap()];
        assert_eq!(system.runtime_deployment, [0x2c; 32]);
        assert_eq!(system.runtime_program, [0x2d; 32]);
        assert_eq!(system.runtime_producer, [0x2e; 32]);
        assert_eq!(
            system.transition_producer, config.system_transition_producer,
            "runtime upgrades preserve the independently authenticated transition signer",
        );
        assert!(authority_state_is_valid(&config, &actor.state));

        let mut unbacked_drift = actor.state.clone();
        let index = managed_agent(&unbacked_drift, AgentId(config.system_agent)).unwrap();
        unbacked_drift.managed_agents[index].runtime_program[0] ^= 1;
        assert!(!authority_state_is_valid(&config, &unbacked_drift));
    }

    #[test]
    fn acc3_requires_exact_wire_and_aic1_and_never_falls_back() {
        let config = configuration();
        let key = signing(0x21);
        let call = create_call(
            config,
            &key,
            ADMIN_PRINCIPAL,
            Some(ADMIN_NODE),
            1,
            AgentProfile::Local,
            2,
        );

        let mut actor = actor();
        let before = actor.state.clone();
        let encoded = call.encode().unwrap();
        let mut old_magic = encoded.clone();
        old_magic[..4].copy_from_slice(b"ACC2");
        assert!(dispatch_bytes(&mut actor, old_magic, Some(context(&call))).is_empty());
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(dispatch_bytes(&mut actor, trailing, Some(context(&call))).is_empty());
        assert_eq!(actor.state, before);
        assert!(dispatch_bytes(&mut actor, encoded.clone(), None).is_empty());
        assert_eq!(actor.state, before);

        let mut wrong_mode = context(&call);
        wrong_mode.mode = MethodMode::Merge;
        assert!(dispatch_bytes(&mut actor, encoded.clone(), Some(wrong_mode)).is_empty());
        assert_eq!(actor.state, before);

        let mut claimed_role = context(&call);
        claimed_role.roles.space = Some(RoleId([0x99; 32]));
        assert!(dispatch_bytes(&mut actor, encoded, Some(claimed_role)).is_empty());
        assert_eq!(actor.state, before);
    }

    #[test]
    fn caller_key_principal_node_and_signature_are_not_interchangeable() {
        let config = configuration();
        let admin_key = signing(0x21);
        let base = create_call(
            config,
            &admin_key,
            ADMIN_PRINCIPAL,
            Some(ADMIN_NODE),
            3,
            AgentProfile::Local,
            4,
        );

        let mut cases = Vec::new();
        let mut wrong_principal = base.clone();
        wrong_principal.principal = PrincipalId([0x32; 32]);
        refresh_management_call(&mut wrong_principal, &admin_key);
        cases.push(wrong_principal);

        let other_key = signing(0x22);
        let mut wrong_key = base.clone();
        wrong_key.credential_public_key = other_key.verifying_key().to_bytes();
        wrong_key.credential = CredentialId::of_public_key(&wrong_key.credential_public_key);
        refresh_management_call(&mut wrong_key, &other_key);
        cases.push(wrong_key);

        let mut unknown_node = base.clone();
        unknown_node.authenticated_node = Some(NodeId([0x42; 32]));
        refresh_management_call(&mut unknown_node, &admin_key);
        cases.push(unknown_node);

        let mut bad_signature = base;
        bad_signature.signature[0] ^= 1;
        cases.push(bad_signature);

        for call in cases {
            let mut actor = actor();
            let before = actor.state.clone();
            assert!(dispatch(&mut actor, &call).is_empty());
            assert_eq!(actor.state, before, "a denial must not mutate state");
        }

        let no_node = create_call(
            config,
            &admin_key,
            ADMIN_PRINCIPAL,
            None,
            0x43,
            AgentProfile::Local,
            0x44,
        );
        let mut actor = actor();
        assert!(ManagementApproval::decode(&dispatch(&mut actor, &no_node)).is_ok());
    }

    #[test]
    fn aoc5_api_exact_retry_restart_and_compaction_are_explicit() {
        let config = configuration();
        let mut actor = actor();
        let catalog = install_catalog_projection(&mut actor);
        assert_eq!(actor.state.operation_retirement_floor, 3);

        let api_key = signing(0x83);
        dispatch_fixture_admin(
            &mut actor,
            InvocationId([0x80; 32]),
            AuthorityAdminOperation::AddCredential {
                principal: ADMIN_PRINCIPAL,
                credential: enrollment(&api_key, AuthorityCredentialKind::Api),
            },
        );

        let call = invoke_operation_call(
            config,
            &api_key,
            ADMIN_PRINCIPAL,
            None,
            0x81,
            0x82,
            system_target(config),
            &catalog,
        );
        assert_eq!(call.validate_shape(), Ok(()));
        assert_eq!(call.verify_api_with(&Ed25519CredentialVerifier), Ok(()));
        assert!(call.matches_invocation_context(&operation_context(&call)));
        assert_eq!(
            authenticated_operation_role(&config, &actor.state, &call),
            Some(BuiltinPrincipalRole::Admin),
        );
        assert!(operation_policy_allows(
            &config,
            &actor.state,
            &call,
            BuiltinPrincipalRole::Admin,
        ));
        let caller_index = credential_index(&actor.state, call.credential).unwrap();
        assert_eq!(
            actor.state.credentials[caller_index].operation_request_high_water,
            0,
        );
        assert!(!credential_has_pending_application(
            &actor.state,
            call.credential,
        ));
        assert!(invocation_pair_is_available(
            &actor.state,
            call.invocation,
            AuthorityOperationApproval::derive_acknowledgement_invocation(&call),
        ));
        let approval_bytes = dispatch_operation(&mut actor, &call);
        let approval = AuthorityOperationApproval::decode(&approval_bytes).unwrap();
        assert_eq!(approval.authorization_sequence.get(), 4);
        assert_eq!(approval.authenticated_node(), None);
        assert!(approval.matches_call(&call));
        assert_eq!(dispatch_operation(&mut actor, &call), approval_bytes);
        assert_eq!(actor.state.operation_retries.len(), 1);
        assert_eq!(actor.state.operation_retirement_floor, 3);

        let mut wrong_kind = call.clone();
        wrong_kind.authentication = AuthorityIngressAuthentication::SshNodeAttestation {
            credential_public_key: api_key.verifying_key().to_bytes(),
            node: ADMIN_NODE,
            request_binding: Hash([0x85; 32]),
            signature: [1; 64],
        };
        let AuthorityOperationIntent::InvokeActor { origin, .. } = &mut wrong_kind.intent else {
            unreachable!()
        };
        origin.transport_node = Some(ADMIN_NODE);
        wrong_kind.invocation = wrong_kind.expected_invocation();
        resign_ssh_operation_call(&mut wrong_kind, &signing(0x31));
        assert_eq!(
            wrong_kind.verify_ssh_node_attestation_with(
                &signing(0x31).verifying_key().to_bytes(),
                &Ed25519CredentialVerifier,
            ),
            Ok(()),
        );
        let before_wrong_kind = actor.state.clone();
        assert!(dispatch_operation(&mut actor, &wrong_kind).is_empty());
        assert_eq!(actor.state, before_wrong_kind);

        let linear = <SystemAuthority as vos::Actor>::__save_agent_lane(&actor, StateLane::Linear);
        let mut restarted = <SystemAuthority as vos::Actor>::__load_agent_state(
            Some(&config.encode()),
            Some(&linear),
            None,
            None,
        )
        .expect("pending AOC5/AOP5 must restart");
        assert_eq!(dispatch_operation(&mut restarted, &call), approval_bytes);

        let ack = operation_issuance_ack(config, &call, &approval);
        assert!(dispatch_operation_ack(&mut restarted, &ack));
        assert!(restarted.state.operation_retries.is_empty());
        assert_eq!(restarted.state.operation_retirement_floor, 4);
        assert_eq!(restarted.state.latest_operation_acks.len(), 1);
        assert!(dispatch_operation_ack(&mut restarted, &ack));

        // Compaction deliberately ends AOC exact retry: the high-water and
        // latest AOI cannot be used to invent AOP5 bytes.
        let retired_state = restarted.state.clone();
        assert!(dispatch_operation(&mut restarted, &call).is_empty());
        assert_eq!(restarted.state, retired_state);
        assert!(authority_state_is_valid(&config, &restarted.state));

        let mut corrupt_ack = restarted.state.clone();
        corrupt_ack.latest_operation_acks[0].issuance_ack[0] ^= 1;
        assert!(!authority_state_is_valid(&config, &corrupt_ack));
        let mut corrupt_floor = restarted.state.clone();
        corrupt_floor.operation_retirement_floor -= 1;
        assert!(!authority_state_is_valid(&config, &corrupt_floor));
        let mut corrupt_payload = restarted.state.clone();
        corrupt_payload.latest_operation_acks[0].invocation_payload[0] ^= 1;
        assert!(!authority_state_is_valid(&config, &corrupt_payload));
    }

    #[test]
    fn aoc5_ssh_cross_owner_attestation_retries_across_reconnect_and_restart() {
        let config = configuration();
        let mut actor = actor();
        let catalog = install_catalog_projection(&mut actor);
        let principal = PrincipalId([0x90; 32]);
        let credential_key = signing(0x91);
        let principal_node = node_for_principal(config, principal);
        enroll(
            &mut actor,
            &credential_key,
            principal,
            principal_node,
            BuiltinPrincipalRole::Member,
        );
        assert_ne!(
            principal,
            PrincipalId(enrolled_node(&actor.state, ADMIN_NODE).unwrap().owner),
        );

        let call = invoke_operation_call(
            config,
            &credential_key,
            principal,
            Some(ADMIN_NODE),
            0x92,
            0x93,
            system_target(config),
            &catalog,
        );
        assert_eq!(call.authenticated_node(), Some(ADMIN_NODE));
        assert_eq!(
            call.verify_ssh_node_attestation_with(
                &signing(0x31).verifying_key().to_bytes(),
                &Ed25519CredentialVerifier,
            ),
            Ok(()),
        );
        let approval_bytes = dispatch_operation(&mut actor, &call);
        let approval = AuthorityOperationApproval::decode(&approval_bytes).unwrap();
        assert!(approval.matches_call(&call));
        assert_eq!(dispatch_operation(&mut actor, &call), approval_bytes);

        let reconnected = invoke_operation_call(
            config,
            &credential_key,
            principal,
            Some(ADMIN_NODE),
            0x92,
            0x93,
            system_target(config),
            &catalog,
        );
        assert_eq!(
            reconnected, call,
            "reconnect preserves the stable request binding"
        );

        let linear = <SystemAuthority as vos::Actor>::__save_agent_lane(&actor, StateLane::Linear);
        let mut restarted = <SystemAuthority as vos::Actor>::__load_agent_state(
            Some(&config.encode()),
            Some(&linear),
            None,
            None,
        )
        .expect("pending SSH-authenticated AOC5/AOP5 must restart");
        assert_eq!(
            dispatch_operation(&mut restarted, &reconnected),
            approval_bytes
        );

        let mut changed_binding = call.clone();
        let AuthorityIngressAuthentication::SshNodeAttestation {
            request_binding, ..
        } = &mut changed_binding.authentication
        else {
            unreachable!()
        };
        request_binding.0[0] ^= 1;
        changed_binding.invocation = changed_binding.expected_invocation();
        resign_ssh_operation_call(&mut changed_binding, &signing(0x31));
        assert_ne!(changed_binding.invocation, call.invocation);
        let before_changed_binding = restarted.state.clone();
        assert!(dispatch_operation(&mut restarted, &changed_binding).is_empty());
        assert_eq!(restarted.state, before_changed_binding);

        let mut wrong_kind = call.clone();
        wrong_kind.authentication = AuthorityIngressAuthentication::ApiCredentialSignature {
            credential_public_key: credential_key.verifying_key().to_bytes(),
            signature: [1; 64],
        };
        let AuthorityOperationIntent::InvokeActor { origin, .. } = &mut wrong_kind.intent else {
            unreachable!()
        };
        origin.transport_node = None;
        wrong_kind.invocation = wrong_kind.expected_invocation();
        resign_operation_call(&mut wrong_kind, &credential_key);
        assert_eq!(
            wrong_kind.verify_api_with(&Ed25519CredentialVerifier),
            Ok(()),
        );
        let before_wrong_kind = restarted.state.clone();
        assert!(dispatch_operation(&mut restarted, &wrong_kind).is_empty());
        assert_eq!(restarted.state, before_wrong_kind);
    }

    #[test]
    fn out_of_order_aoi1_waits_for_gap_and_crosses_management_without_retiring_it() {
        let config = configuration();
        let mut actor = actor();
        let catalog = install_catalog_projection(&mut actor);
        let management_key = signing(0x86);
        let management_principal = PrincipalId([0x87; 32]);
        let management_node = node_for_principal(config, management_principal);
        enroll(
            &mut actor,
            &management_key,
            management_principal,
            management_node,
            BuiltinPrincipalRole::Admin,
        );
        let second_key = signing(0x88);
        let second_principal = PrincipalId([0x89; 32]);
        let second_node = node_for_principal(config, second_principal);
        enroll(
            &mut actor,
            &second_key,
            second_principal,
            second_node,
            BuiltinPrincipalRole::Admin,
        );
        let first_call = invoke_operation_call(
            config,
            &signing(0x21),
            ADMIN_PRINCIPAL,
            Some(ADMIN_NODE),
            0x85,
            0x86,
            system_target(config),
            &catalog,
        );
        let first_bytes = dispatch_operation(&mut actor, &first_call);
        let first = AuthorityOperationApproval::decode(&first_bytes).unwrap();
        assert_eq!(first.authorization_sequence.get(), 4);

        let runtime_call = credential_call(
            config,
            &management_key,
            management_principal,
            Some(management_node),
            0x87,
            system_target(config),
            ManagementRequest::UpgradeRuntime(Box::new(vos::agent_sdk::RuntimeUpgrade {
                from_deployment: DeploymentId(config.system_runtime_deployment),
                to_deployment: DeploymentId([0x88; 32]),
                to_program: ProgramId([0x89; 32]),
                producer: ProducerId([0x8a; 32]),
                package: BlobRef::of_bytes(b"pending-runtime-pass-through"),
                contract: RuntimePackageContract::canonical(),
                capabilities: RuntimeCapabilities::standard(),
            })),
        );
        let runtime_approval = ManagementApproval::decode(&dispatch(&mut actor, &runtime_call))
            .expect("management position must share the global sequence");
        assert_eq!(runtime_approval.authorization_sequence.get(), 5);
        let management_journal = actor.state.retries.clone();
        assert_eq!(actor.state.operation_retirement_floor, 3);

        let second_call = invoke_operation_call(
            config,
            &second_key,
            second_principal,
            Some(second_node),
            0x8b,
            0x8c,
            system_target(config),
            &catalog,
        );
        let second_bytes = dispatch_operation(&mut actor, &second_call);
        let second = AuthorityOperationApproval::decode(&second_bytes).unwrap();
        assert_eq!(second.authorization_sequence.get(), 6);
        let second_ack = operation_issuance_ack(config, &second_call, &second);
        assert!(dispatch_operation_ack(&mut actor, &second_ack));
        assert_eq!(actor.state.operation_retirement_floor, 3);
        assert_eq!(actor.state.operation_retries.len(), 2);
        assert!(
            actor.state.operation_retries.iter().any(|record| {
                record.authorization_sequence == 6 && record.issuance_ack.is_some()
            })
        );
        assert_eq!(actor.state.retries, management_journal);

        let linear = <SystemAuthority as vos::Actor>::__save_agent_lane(&actor, StateLane::Linear);
        let mut restarted = <SystemAuthority as vos::Actor>::__load_agent_state(
            Some(&config.encode()),
            Some(&linear),
            None,
            None,
        )
        .expect("out-of-order AOI1 must restart");
        assert_eq!(
            dispatch_operation(&mut restarted, &second_call),
            second_bytes
        );
        let first_ack = operation_issuance_ack(config, &first_call, &first);
        assert!(dispatch_operation_ack(&mut restarted, &first_ack));
        assert_eq!(restarted.state.operation_retirement_floor, 6);
        assert!(restarted.state.operation_retries.is_empty());
        let mut compacted = restarted
            .state
            .latest_operation_acks
            .iter()
            .map(|record| record.authorization_sequence)
            .collect::<Vec<_>>();
        compacted.sort_unstable();
        assert_eq!(compacted, vec![4, 6]);
        // Sequence five was crossed but the separate management journal was
        // neither finalized nor compacted.
        assert_eq!(restarted.state.retries, management_journal);
        assert!(!restarted.state.retries.is_empty());
        assert!(dispatch_operation_ack(&mut restarted, &second_ack));
        assert!(authority_state_is_valid(&config, &restarted.state));
    }

    #[test]
    fn operation_domains_collisions_and_signed_substitutions_fail_closed() {
        let config = configuration();
        let mut actor = actor();
        let catalog = install_catalog_projection(&mut actor);
        let collision_admin_key = signing(0x94);
        let collision_admin_principal = PrincipalId([0x95; 32]);
        let collision_admin_node = node_for_principal(config, collision_admin_principal);
        enroll(
            &mut actor,
            &collision_admin_key,
            collision_admin_principal,
            collision_admin_node,
            BuiltinPrincipalRole::Admin,
        );
        let call = invoke_operation_call(
            config,
            &signing(0x21),
            ADMIN_PRINCIPAL,
            Some(ADMIN_NODE),
            0x91,
            0x92,
            system_target(config),
            &catalog,
        );

        let before_cross_domain = actor.state.clone();
        assert!(
            dispatch_bytes(
                &mut actor,
                call.encode().unwrap(),
                Some(operation_context(&call)),
            )
            .is_empty()
        );
        assert_eq!(actor.state, before_cross_domain);

        let approval_bytes = dispatch_operation(&mut actor, &call);
        let approval = AuthorityOperationApproval::decode(&approval_bytes).unwrap();
        let mut substituted_call = call.clone();
        substituted_call.requested_expires_at -= 1;
        substituted_call.invocation = substituted_call.expected_invocation();
        resign_operation_call(&mut substituted_call, &signing(0x21));
        let before_substitution = actor.state.clone();
        assert!(dispatch_operation(&mut actor, &substituted_call).is_empty());
        assert_eq!(actor.state, before_substitution);

        let ack = operation_issuance_ack(config, &call, &approval);
        let mut substituted_ack = ack.clone();
        substituted_ack.operation_call = Hash([0x93; 32]);
        resign_operation_ack(&mut substituted_ack);
        assert!(
            substituted_ack
                .verify_with(config.binding.sdk(), &Ed25519CredentialVerifier)
                .is_ok()
        );
        let before_ack = actor.state.clone();
        assert!(!dispatch_operation_ack(&mut actor, &substituted_ack));
        assert_eq!(actor.state, before_ack);

        assert!(!dispatch_ack_bytes(
            &mut actor,
            ack.encode().unwrap(),
            Some(operation_ack_context(&ack)),
        ));
        assert_eq!(actor.state, before_ack);

        for collision in [
            actor.state.latest_management_acks[0].authorization_invocation,
            actor.state.latest_management_acks[0].acknowledgement_invocation,
        ] {
            let mut colliding = call.clone();
            colliding.invocation = InvocationId(collision);
            resign_operation_call(&mut colliding, &signing(0x21));
            assert!(colliding.encode().is_err());
        }

        let mut admin = admin_call(
            config,
            &collision_admin_key,
            collision_admin_principal,
            collision_admin_node,
            0x94,
            actor.state.administration_generation,
            AuthorityAdminOperation::EnrollPrincipal {
                principal: PrincipalId([0x97; 32]),
                credential: enrollment(&signing(0x98), AuthorityCredentialKind::Api),
            },
        );
        prepare_admin_call(&actor, &mut admin, &collision_admin_key);
        assert!(!dispatch_admin(&mut actor, &admin).is_empty());
        let mut admin_collision = call.clone();
        admin_collision.invocation = admin.invocation;
        resign_operation_call(&mut admin_collision, &signing(0x21));
        assert!(admin_collision.encode().is_err());

        let mut corrupt_call = actor.state.clone();
        corrupt_call.operation_retries[0].operation_call_bytes[4] ^= 1;
        assert!(!authority_state_is_valid(&config, &corrupt_call));
        let mut corrupt_approval = actor.state.clone();
        corrupt_approval.operation_retries[0].approval[4] ^= 1;
        assert!(!authority_state_is_valid(&config, &corrupt_approval));
        let mut corrupt_role = actor.state.clone();
        corrupt_role.operation_retries[0].role = BuiltinPrincipalRole::Member;
        assert!(!authority_state_is_valid(&config, &corrupt_role));
    }

    #[test]
    fn catalog_aoi1_proves_only_issuance_and_never_catalog_application() {
        let config = configuration();
        let mut actor = actor();
        let catalog_install = install_catalog_projection(&mut actor);
        let catalog = CatalogActorTarget {
            space: SpaceId(config.space),
            system_agent: AgentId(config.system_agent),
            system_runtime_deployment: DeploymentId(config.system_runtime_deployment),
            actor: catalog_install.entry.actor,
            deployment: catalog_install.entry.deployment,
            program: catalog_install.entry.program,
            authority: config.binding.sdk(),
        };
        let publication = CatalogPublication {
            identity: vos::agent_sdk::AgentIdentity {
                space: SpaceId(config.space),
                agent: AgentId(config.system_agent),
                owner: ADMIN_PRINCIPAL,
                profile: AgentProfile::Shared,
                runtime_deployment: DeploymentId(config.system_runtime_deployment),
                runtime_program: ProgramId(config.system_runtime_program),
                runtime_producer: ProducerId(config.system_runtime_producer),
                transition_producer: ProducerId(config.system_transition_producer),
            },
            actor: catalog_install.entry.actor,
            actor_deployment: catalog_install.entry.deployment,
            actor_program: catalog_install.entry.program,
            actor_package: catalog_install.package.clone(),
            content: BlobRef::of_bytes(b"published-system-catalog"),
        };
        let intent = AuthorityOperationIntent::catalog(
            catalog,
            CatalogAlias {
                namespace: "system".into(),
                name: "catalog".into(),
            },
            CatalogMutationKind::Publish,
            publication.clone(),
        )
        .unwrap();
        let call = operation_call(
            config,
            &signing(0x21),
            ADMIN_PRINCIPAL,
            Some(ADMIN_NODE),
            0xa2,
            intent,
        );
        let managed_before = actor.state.managed_agents.clone();
        let actors_before = actor.state.managed_actors.clone();
        let approval = AuthorityOperationApproval::decode(&dispatch_operation(&mut actor, &call))
            .expect("exact catalog route and publication must authorize");
        assert!(
            approval
                .catalog_request()
                .is_some_and(|request| approval.matches_catalog_request(&request))
        );
        assert_eq!(actor.state.managed_agents, managed_before);
        assert_eq!(actor.state.managed_actors, actors_before);

        let ack = operation_issuance_ack(config, &call, &approval);
        assert!(dispatch_operation_ack(&mut actor, &ack));
        assert_eq!(actor.state.managed_agents, managed_before);
        assert_eq!(actor.state.managed_actors, actors_before);
        assert_eq!(actor.state.operation_retirement_floor, 4);

        let mut wrong_catalog = catalog;
        wrong_catalog.deployment = DeploymentId([0xa3; 32]);
        let wrong_intent = AuthorityOperationIntent::catalog(
            wrong_catalog,
            CatalogAlias {
                namespace: "system".into(),
                name: "wrong-route".into(),
            },
            CatalogMutationKind::Publish,
            publication,
        )
        .unwrap();
        let wrong_call = operation_call(
            config,
            &signing(0x21),
            ADMIN_PRINCIPAL,
            Some(ADMIN_NODE),
            0xa5,
            wrong_intent,
        );
        let before = actor.state.clone();
        assert!(dispatch_operation(&mut actor, &wrong_call).is_empty());
        assert_eq!(actor.state, before);
    }

    #[test]
    fn private_recovery_requires_exact_owner_and_descriptor_pinned_key() {
        let config = configuration();
        let owner = PrincipalId([0xb1; 32]);
        let owner_node = node_for_principal(config, owner);
        let owner_key = signing(0xb3);
        let admin_key = signing(0x21);
        let mut actor = actor();
        enroll(
            &mut actor,
            &owner_key,
            owner,
            owner_node,
            BuiltinPrincipalRole::Member,
        );
        let descriptor = descriptor(config, owner, AgentProfile::Private, 0xb4);
        insert_live(&mut actor, &descriptor);
        let managed = target_for(&descriptor);
        let generic_replica_change = credential_call(
            config,
            &owner_key,
            owner,
            None,
            0xa8,
            managed,
            ManagementRequest::ChangeReplicas {
                expected_generation: Hash([0xa9; 32]),
                replicas: vec![AgentReplica {
                    node: NodeId([0xf7; 32]),
                    principal: owner,
                    role: ReplicaRole::Observer,
                }],
            },
        );
        let before_replica_change = actor.state.clone();
        assert!(dispatch(&mut actor, &generic_replica_change).is_empty());
        assert_eq!(actor.state, before_replica_change);
        let invited_node = enroll_additional_node(&mut actor, owner, 0xf6);
        let invited_identity = enrolled_identity_commitment(&actor, invited_node, owner);
        let invited_member_set = fixture_member_set([descriptor.replicas[0].node, invited_node]);
        let invite = AuthorityOperationIntent::InvitePrivateNode {
            managed,
            control: Hash([0xb5; 32]),
            control_sequence: 0,
            control_previous: None,
            epoch: 0,
            node: invited_node,
            node_identity: invited_identity,
        };
        for (offset, intent) in [invite.clone()].into_iter().enumerate() {
            let admin_call = operation_call(
                config,
                &signing(0x21),
                ADMIN_PRINCIPAL,
                Some(ADMIN_NODE),
                0xba + u8::try_from(offset).unwrap(),
                intent.clone(),
            );
            let before = actor.state.clone();
            assert!(dispatch_operation(&mut actor, &admin_call).is_empty());
            assert_eq!(actor.state, before, "Admin has no Private-Agent keys");
        }

        let invite_call = operation_call(config, &owner_key, owner, Some(owner_node), 0xbc, invite);
        let (invite_approval, invite_issuance) =
            authorize_and_issue_operation(&mut actor, &invite_call);
        let invite_application = private_application_ack(
            &invite_call,
            &invite_approval,
            &invite_issuance,
            private_application_fact(
                &invite_call,
                invited_member_set,
                Hash([0xbd; 32]),
                OBSERVED_SLOT + 1,
            ),
        );
        assert!(dispatch_private_application(
            &mut actor,
            &invite_application
        ));

        let recovery_key = signing(0xb8);
        let proof = signed_recovery_proof(
            &actor,
            managed,
            owner,
            &recovery_key,
            Hash([0xbe; 32]),
            7,
            Some(Hash([0xbf; 32])),
            3,
            Some(Hash([0xb5; 32])),
            vec![owner_node],
            Hash([0xc0; 32]),
        );
        let recover = AuthorityOperationIntent::RecoverPrivateAgent {
            proof: proof.clone(),
        };

        let admin_call = operation_call(
            config,
            &admin_key,
            ADMIN_PRINCIPAL,
            Some(ADMIN_NODE),
            0xc1,
            recover.clone(),
        );
        let before = actor.state.clone();
        assert!(dispatch_operation(&mut actor, &admin_call).is_empty());
        assert_eq!(
            actor.state, before,
            "Admin cannot substitute for recovery possession"
        );

        let mut wrong_key_proof = proof.clone();
        wrong_key_proof.recovery_public_key = signing(0xc2).verifying_key().to_bytes();
        wrong_key_proof.signature = signing(0xc2)
            .sign(&wrong_key_proof.signing_bytes())
            .to_bytes();
        let mut wrong_key_call = operation_call(
            config,
            &owner_key,
            owner,
            Some(owner_node),
            0xc2,
            AuthorityOperationIntent::RecoverPrivateAgent {
                proof: wrong_key_proof,
            },
        );
        prepare_operation_call(&actor, &mut wrong_key_call, &owner_key);
        assert!(dispatch_operation(&mut actor, &wrong_key_call).is_empty());
        assert_eq!(actor.state, before, "descriptor recovery pin is immutable");

        let mut stale_head = proof.clone();
        stale_head.superseded_authority_head = Some(Hash([0xc3; 32]));
        stale_head.signature = recovery_key.sign(&stale_head.signing_bytes()).to_bytes();
        let mut nonadvancing_sequence = proof.clone();
        nonadvancing_sequence.control_sequence = 0;
        nonadvancing_sequence.control_previous = None;
        nonadvancing_sequence.signature = recovery_key
            .sign(&nonadvancing_sequence.signing_bytes())
            .to_bytes();
        let mut substituted_identities = proof.clone();
        substituted_identities.replacement_identity_set = Hash([0xc4; 32]);
        substituted_identities.signature = recovery_key
            .sign(&substituted_identities.signing_bytes())
            .to_bytes();
        let mut bad_signature = proof.clone();
        bad_signature.signature[0] ^= 1;
        for (marker, hostile) in [
            (0xc5, stale_head),
            (0xc6, nonadvancing_sequence),
            (0xc7, substituted_identities),
            (0xc8, bad_signature),
        ] {
            let mut call = operation_call(
                config,
                &owner_key,
                owner,
                Some(owner_node),
                marker,
                AuthorityOperationIntent::RecoverPrivateAgent { proof: hostile },
            );
            prepare_operation_call(&actor, &mut call, &owner_key);
            assert!(dispatch_operation(&mut actor, &call).is_empty());
            assert_eq!(actor.state, before);
        }

        let mut recover_call =
            operation_call(config, &owner_key, owner, Some(owner_node), 0xca, recover);
        prepare_operation_call(&actor, &mut recover_call, &owner_key);
        let (approval, issuance) = authorize_and_issue_operation(&mut actor, &recover_call);
        // Recovery is likewise ordered by its signed fork position and may
        // share the superseded Invite application's observation slot.
        let pca = private_application_ack(
            &recover_call,
            &approval,
            &issuance,
            private_application_fact(
                &recover_call,
                proof.replacement_member_set,
                Hash([0xc4; 32]),
                OBSERVED_SLOT + 1,
            ),
        );
        assert!(dispatch_private_application(&mut actor, &pca));
        let projection = &actor.state.private_agents[0];
        assert_eq!(projection.control_head, Some(proof.control.0));
        assert_eq!(projection.control_sequence, Some(7));
        assert_eq!(projection.epoch, 3);
        assert_eq!(projection.members, vec![owner_node.0]);
        assert_eq!(projection.member_set, proof.replacement_member_set.0);
        assert!(authority_state_is_valid(&config, &actor.state));

        let before_retry = actor.state.clone();
        assert!(dispatch_private_application(&mut actor, &pca));
        assert_eq!(actor.state, before_retry);

        // Capacity reserves the 64th slot before PCA, yet applies that slot
        // using the completed-row bound. Once 64 are complete, a 65th cannot
        // be authorized. Fixture duplication is deliberate: these helpers
        // count bounded storage occupancy, while replay validity is exercised
        // by the exact ceremony above.
        let completed = actor.state.private_applications.last().unwrap().clone();
        let mut boundary = actor.state.clone();
        boundary.private_applications =
            vec![completed.clone(); MAX_PRIVATE_RECOVERY_APPLICATION_RECORDS - 1];
        let reserved = boundary
            .latest_operation_acks
            .iter_mut()
            .find(|row| {
                row.private_operation.as_ref().is_some_and(|private| {
                    private.operation == AuthorityOperationKind::RecoverPrivateAgent as u8
                })
            })
            .unwrap();
        reserved.authorization_invocation[0] ^= 1;
        let reserved_authorization = reserved.authorization_invocation;
        let reserved_issuance = reserved.acknowledgement_invocation;
        let reserved_sequence = reserved.authorization_sequence;
        assert_eq!(
            completed_recovery_application_count(&boundary),
            MAX_PRIVATE_RECOVERY_APPLICATION_RECORDS - 1
        );
        assert_eq!(
            retained_recovery_application_count(&boundary),
            MAX_PRIVATE_RECOVERY_APPLICATION_RECORDS
        );
        assert!(recovery_application_capacity_available(&boundary));
        assert!(!recovery_authorization_capacity_available(&boundary));
        let mut finished_reserved = completed.clone();
        finished_reserved.authorization_invocation = reserved_authorization;
        finished_reserved.issuance_invocation = reserved_issuance;
        finished_reserved.authorization_sequence = reserved_sequence;
        boundary.private_applications.push(finished_reserved);
        assert_eq!(
            completed_recovery_application_count(&boundary),
            MAX_PRIVATE_RECOVERY_APPLICATION_RECORDS
        );
        assert_eq!(
            retained_recovery_application_count(&boundary),
            MAX_PRIVATE_RECOVERY_APPLICATION_RECORDS
        );
        assert!(!recovery_application_capacity_available(&boundary));
        assert!(!recovery_authorization_capacity_available(&boundary));

        let mut corrupt_proof = actor.state.clone();
        corrupt_proof
            .private_applications
            .last_mut()
            .unwrap()
            .recovery_proof_bytes
            .as_mut()
            .unwrap()[4] ^= 1;
        assert!(refresh_state_integrity_commitment(
            &config,
            &mut corrupt_proof
        ));
        assert!(!authority_state_is_valid(&config, &corrupt_proof));
    }

    #[test]
    fn genesis_private_recovery_supersedes_none_and_reconciles_a_fork_jump() {
        let config = configuration();
        let owner = PrincipalId([0xc5; 32]);
        let owner_node = node_for_principal(config, owner);
        let owner_key = signing(0xc7);
        let mut actor = actor();
        enroll(
            &mut actor,
            &owner_key,
            owner,
            owner_node,
            BuiltinPrincipalRole::Member,
        );
        let descriptor = descriptor(config, owner, AgentProfile::Private, 0xc8);
        insert_live(&mut actor, &descriptor);
        let replacement = enroll_additional_node(&mut actor, owner, 0xcd);
        let recovery_key = signing(0xcc);
        let proof = signed_recovery_proof(
            &actor,
            target_for(&descriptor),
            owner,
            &recovery_key,
            Hash([0xce; 32]),
            9,
            Some(Hash([0xcf; 32])),
            4,
            None,
            vec![replacement],
            Hash([0xd0; 32]),
        );
        let mut call = operation_call(
            config,
            &owner_key,
            owner,
            Some(owner_node),
            0xd1,
            AuthorityOperationIntent::RecoverPrivateAgent {
                proof: proof.clone(),
            },
        );
        prepare_operation_call(&actor, &mut call, &owner_key);
        let (approval, issuance) = authorize_and_issue_operation(&mut actor, &call);
        let pca = private_application_ack(
            &call,
            &approval,
            &issuance,
            private_application_fact(
                &call,
                proof.replacement_member_set,
                Hash([0xd2; 32]),
                OBSERVED_SLOT + 1,
            ),
        );

        // A PCA is authenticated by its retained source, not by the managed
        // route that happens to be current when delivery occurs. A compatible
        // runtime upgrade after physical recovery therefore cannot strand the
        // already-issued recovery acknowledgement or invalidate its retained
        // proof after application.
        let old_managed = target_for(&descriptor);
        let new_deployment = DeploymentId([0xd3; 32]);
        let mut upgrade_call = credential_call(
            config,
            &signing(0x21),
            ADMIN_PRINCIPAL,
            Some(ADMIN_NODE),
            0xd4,
            old_managed,
            ManagementRequest::UpgradeRuntime(Box::new(vos::agent_sdk::RuntimeUpgrade {
                from_deployment: old_managed.runtime_deployment,
                to_deployment: new_deployment,
                to_program: ProgramId([0xd5; 32]),
                producer: ProducerId([0xd6; 32]),
                package: BlobRef::of_bytes(b"compatible-post-recovery-runtime"),
                contract: RuntimePackageContract::canonical(),
                capabilities: RuntimeCapabilities::standard(),
            })),
        );
        prepare_management_call(&actor, &mut upgrade_call, &signing(0x21));
        let upgrade_approval = ManagementApproval::decode(&dispatch(&mut actor, &upgrade_call))
            .expect("runtime upgrade authorized after recovery issuance");
        let mut upgrade_ack =
            application_ack(config, &actor.state, &upgrade_call, &upgrade_approval);
        upgrade_ack.applied_at = OBSERVED_SLOT + 2;
        resign_ack(&mut upgrade_ack);
        assert!(upgrade_ack.matches_pending(&upgrade_call, &upgrade_approval));
        let upgrade_record = actor
            .state
            .retries
            .iter()
            .find(|record| record.invocation == upgrade_call.invocation.0)
            .expect("runtime upgrade must retain its exact authorization record");
        assert_eq!(
            reconstruction_effect(&config, &actor.state, &upgrade_call).as_ref(),
            Some(&upgrade_record.effect),
        );
        assert!(
            application_plan(
                &config,
                &actor.state,
                &upgrade_record.effect,
                &upgrade_call,
                &upgrade_ack,
            )
            .is_some()
        );
        assert!(dispatch_ack(&mut actor, &upgrade_ack));

        assert!(dispatch_private_application(&mut actor, &pca));
        assert_eq!(actor.state.private_agents[0].control_sequence, Some(9));
        assert_eq!(actor.state.private_agents[0].epoch, 4);
        assert_eq!(actor.state.private_agents[0].members, vec![replacement.0]);
        assert_eq!(
            actor.state.private_agents[0].runtime_deployment,
            new_deployment.0
        );
        assert_eq!(
            actor.state.private_applications[0].runtime_deployment,
            old_managed.runtime_deployment.0
        );
        assert!(authority_state_is_valid(&config, &actor.state));

        let linear = <SystemAuthority as vos::Actor>::__save_agent_lane(&actor, StateLane::Linear);
        let restarted = <SystemAuthority as vos::Actor>::__load_agent_state(
            Some(&config.encode()),
            Some(&linear),
            None,
            None,
        )
        .expect("genesis recovery state must reopen exactly");
        assert_eq!(restarted.state, actor.state);
    }

    #[test]
    fn tombstoned_pca2_advances_only_the_exact_private_projection_and_restarts() {
        let config = configuration();
        let owner = PrincipalId([0xc1; 32]);
        let owner_node = node_for_principal(config, owner);
        let owner_key = signing(0xc3);
        let mut actor = actor();
        enroll(
            &mut actor,
            &owner_key,
            owner,
            owner_node,
            BuiltinPrincipalRole::Member,
        );
        let descriptor = descriptor(config, owner, AgentProfile::Private, 0xc4);
        let managed = target_for(&descriptor);
        let initial_member_set =
            fixture_member_set(descriptor.replicas.iter().map(|replica| replica.node));
        insert_live(&mut actor, &descriptor);
        assert_eq!(actor.state.private_agents.len(), 1);
        assert_eq!(actor.state.private_agents[0].owner, owner.0);
        assert_eq!(actor.state.private_agents[0].control_head, None);
        assert_eq!(actor.state.private_agents[0].control_sequence, None);
        assert_eq!(actor.state.private_agents[0].epoch, 0);
        assert_eq!(
            actor.state.private_agents[0].members,
            vec![descriptor.replicas[0].node.0]
        );
        assert_eq!(
            actor.state.private_agents[0].member_set,
            initial_member_set.0
        );

        let invited_node = enroll_additional_node(&mut actor, owner, 0xf0);
        let invited_identity = enrolled_identity_commitment(&actor, invited_node, owner);
        let invited_member_set = fixture_member_set([descriptor.replicas[0].node, invited_node]);
        let invite_control = Hash([0xc5; 32]);
        let invite_call = operation_call(
            config,
            &owner_key,
            owner,
            Some(owner_node),
            0xc6,
            AuthorityOperationIntent::InvitePrivateNode {
                managed,
                control: invite_control,
                control_sequence: 0,
                control_previous: None,
                epoch: 0,
                node: invited_node,
                node_identity: invited_identity,
            },
        );
        let private_before_issuance = actor.state.private_agents.clone();
        let (invite_approval, invite_issuance) =
            authorize_and_issue_operation(&mut actor, &invite_call);
        assert_eq!(actor.state.private_agents, private_before_issuance);
        assert!(actor.state.operation_retries.is_empty());
        assert_eq!(actor.state.latest_operation_acks.len(), 1);

        let invite_pca = private_application_ack(
            &invite_call,
            &invite_approval,
            &invite_issuance,
            private_application_fact(
                &invite_call,
                invited_member_set,
                Hash([0xc8; 32]),
                OBSERVED_SLOT + 1,
            ),
        );
        let authorization_sequence = actor.state.authorization_sequence;
        let retirement_floor = actor.state.operation_retirement_floor;
        let mut management_projection = actor.state.managed_agents.clone();
        let actor_projection = actor.state.managed_actors.clone();
        let management_journal = actor.state.retries.clone();
        assert!(dispatch_private_application(&mut actor, &invite_pca));
        let projected_index = management_projection
            .binary_search_by(|row| row.agent.cmp(&managed.agent.0))
            .unwrap();
        management_projection[projected_index].replicas = actor.state.private_agents[0]
            .members
            .iter()
            .map(|node| ManagedReplicaRow {
                node: *node,
                principal: owner.0,
                role: ReplicaRole::Observer as u8,
            })
            .collect();
        management_projection[projected_index].replica_generation =
            managed_replica_generation(&config, &management_projection[projected_index])
                .unwrap()
                .0;
        assert_eq!(actor.state.authorization_sequence, authorization_sequence);
        assert_eq!(actor.state.operation_retirement_floor, retirement_floor);
        assert_eq!(actor.state.managed_agents, management_projection);
        assert_eq!(actor.state.managed_actors, actor_projection);
        assert_eq!(actor.state.retries, management_journal);
        assert_eq!(actor.state.private_applications.len(), 1);
        let projected = &actor.state.private_agents[0];
        assert_eq!(projected.control_head, Some(invite_control.0));
        assert_eq!(projected.control_sequence, Some(0));
        assert_eq!(projected.epoch, 0);
        let mut expected_members = vec![descriptor.replicas[0].node.0, invited_node.0];
        expected_members.sort_unstable();
        assert_eq!(projected.members, expected_members);
        assert_eq!(projected.member_set, invited_member_set.0);
        assert_eq!(projected.reopened_runtime_state, Some([0xc8; 32]));
        assert_eq!(
            projected.stable_projection,
            Some(invite_pca.application.stable_projection.0)
        );
        assert_eq!(projected.applied_at, Some(OBSERVED_SLOT + 1));
        assert_eq!(
            projected.application_invocation,
            Some(invite_pca.application_invocation.0)
        );
        assert_eq!(projected.application_ack, Some(invite_pca.commitment().0));
        let applied = &actor.state.private_applications[0];
        assert_eq!(applied.reopened_runtime_state, [0xc8; 32]);
        assert_eq!(
            applied.stable_projection,
            invite_pca.application.stable_projection.0
        );

        let after_invite = actor.state.clone();
        assert!(dispatch_private_application(&mut actor, &invite_pca));
        assert_eq!(actor.state, after_invite);
        let mut divergent_retry = invite_pca.clone();
        divergent_retry.application.reopened_runtime_state = Hash([0xc9; 32]);
        resign_private_application_ack(&mut divergent_retry);
        assert!(!dispatch_private_application(&mut actor, &divergent_retry));
        assert_eq!(actor.state, after_invite);
        let mut divergent_projection = invite_pca.clone();
        divergent_projection.application.stable_projection = Hash([0xc9; 32]);
        resign_private_application_ack(&mut divergent_projection);
        assert!(!dispatch_private_application(
            &mut actor,
            &divergent_projection,
        ));
        assert_eq!(actor.state, after_invite);

        let linear = <SystemAuthority as vos::Actor>::__save_agent_lane(&actor, StateLane::Linear);
        let mut restarted = <SystemAuthority as vos::Actor>::__load_agent_state(
            Some(&config.encode()),
            Some(&linear),
            None,
            None,
        )
        .expect("PCA2 projection restarts");
        assert_eq!(restarted.state, actor.state);
        assert!(dispatch_private_application(&mut restarted, &invite_pca));

        let revoke_control = Hash([0xca; 32]);
        let mut revoke_call = operation_call(
            config,
            &owner_key,
            owner,
            Some(owner_node),
            0xcb,
            AuthorityOperationIntent::RevokePrivateNode {
                managed,
                control: revoke_control,
                control_sequence: 1,
                control_previous: Some(invite_control),
                epoch: 1,
                node: invited_node,
                member_set: initial_member_set,
            },
        );
        prepare_operation_call(&restarted, &mut revoke_call, &owner_key);
        let (revoke_approval, revoke_issuance) =
            authorize_and_issue_operation(&mut restarted, &revoke_call);
        let revoke_pca = private_application_ack(
            &revoke_call,
            &revoke_approval,
            &revoke_issuance,
            private_application_fact(
                &revoke_call,
                initial_member_set,
                Hash([0xcc; 32]),
                OBSERVED_SLOT + 2,
            ),
        );
        assert!(dispatch_private_application(&mut restarted, &revoke_pca));
        let projected = &restarted.state.private_agents[0];
        assert_eq!(projected.control_head, Some(revoke_control.0));
        assert_eq!(projected.control_sequence, Some(1));
        assert_eq!(projected.epoch, 1);
        assert_eq!(projected.members, vec![descriptor.replicas[0].node.0]);
        assert_eq!(projected.member_set, initial_member_set.0);
        assert_eq!(restarted.state.private_applications.len(), 2);
        let after_revoke = restarted.state.clone();
        assert!(dispatch_private_application(&mut restarted, &invite_pca));
        assert_eq!(restarted.state, after_revoke);
        assert!(authority_state_is_valid(&config, &restarted.state));
    }

    #[test]
    fn par1_retires_without_projecting_and_is_exclusive_with_pca2() {
        let config = configuration();
        let owner = PrincipalId([0x39; 32]);
        let owner_node = node_for_principal(config, owner);
        let owner_key = signing(0x3a);
        let mut actor = actor();
        enroll(
            &mut actor,
            &owner_key,
            owner,
            owner_node,
            BuiltinPrincipalRole::Member,
        );
        let descriptor = descriptor(config, owner, AgentProfile::Private, 0x34);
        let managed = target_for(&descriptor);
        insert_live(&mut actor, &descriptor);
        let invited_node = enroll_additional_node(&mut actor, owner, 0xe0);
        let invited_identity = enrolled_identity_commitment(&actor, invited_node, owner);
        let intent = AuthorityOperationIntent::InvitePrivateNode {
            managed,
            control: Hash([0x35; 32]),
            control_sequence: 0,
            control_previous: None,
            epoch: 0,
            node: invited_node,
            node_identity: invited_identity,
        };
        let call = operation_call(
            config,
            &owner_key,
            owner,
            Some(owner_node),
            0x36,
            intent.clone(),
        );
        let (approval, issuance) = authorize_and_issue_operation(&mut actor, &call);
        assert!(actor.state.operation_retries.is_empty());
        assert_eq!(actor.state.latest_operation_acks.len(), 1);
        let unresolved_state = actor.state.clone();
        vos::storage::mock::commit_dispatch();
        let unresolved_rows = vos::storage::mock::snapshot();
        let private_agents = actor.state.private_agents.clone();
        let managed_agents = actor.state.managed_agents.clone();
        let managed_actors = actor.state.managed_actors.clone();
        let applications = actor.state.private_applications.clone();
        let application_commitment = actor.state.private_application_commitment;
        let retirement =
            private_application_retirement_ack(&call, &approval, &issuance, OBSERVED_SLOT + 1);

        assert!(dispatch_private_application_retirement(
            &mut actor,
            &retirement
        ));
        assert_eq!(actor.state.private_application_retirements.len(), 1);
        assert_eq!(actor.state.private_agents, private_agents);
        assert_eq!(actor.state.managed_agents, managed_agents);
        assert_eq!(actor.state.managed_actors, managed_actors);
        assert_eq!(actor.state.private_applications, applications);
        assert_eq!(
            actor.state.private_application_commitment,
            application_commitment
        );
        assert!(authority_state_is_valid(&config, &actor.state));

        let after_retirement = actor.state.clone();
        assert!(dispatch_private_application_retirement(
            &mut actor,
            &retirement
        ));
        assert_eq!(actor.state, after_retirement);

        let member_set = fixture_member_set([descriptor.replicas[0].node, invited_node]);
        let application = private_application_ack(
            &call,
            &approval,
            &issuance,
            private_application_fact(&call, member_set, Hash([0x37; 32]), OBSERVED_SLOT + 1),
        );
        assert!(!dispatch_private_application(&mut actor, &application));
        assert_eq!(actor.state, after_retirement);

        let mut divergent_retirement = retirement.clone();
        divergent_retirement.resolved_at += 1;
        resign_private_application_retirement_ack(&mut divergent_retirement);
        assert!(!dispatch_private_application_retirement(
            &mut actor,
            &divergent_retirement
        ));
        assert_eq!(actor.state, after_retirement);
        let mut bad_signature = retirement.clone();
        bad_signature.signature[0] ^= 1;
        assert!(!dispatch_private_application_retirement(
            &mut actor,
            &bad_signature
        ));
        assert_eq!(actor.state, after_retirement);
        let mut wrong_context = private_application_retirement_context(&retirement);
        wrong_context.observed_slot += 1;
        assert!(!dispatch_private_application_bytes(
            &mut actor,
            retirement.encode().unwrap(),
            Some(wrong_context),
        ));
        assert_eq!(actor.state, after_retirement);

        let linear = <SystemAuthority as vos::Actor>::__save_agent_lane(&actor, StateLane::Linear);
        let mut restarted = <SystemAuthority as vos::Actor>::__load_agent_state(
            Some(&config.encode()),
            Some(&linear),
            None,
            None,
        )
        .expect("PAR1 retirement restarts");
        assert_eq!(restarted.state, actor.state);
        assert!(dispatch_private_application_retirement(
            &mut restarted,
            &retirement
        ));
        assert_eq!(restarted.state, actor.state);

        // A retired invite did not add this node to any policy projection and
        // must not keep the otherwise-unused enrollment pinned.
        dispatch_fixture_admin(
            &mut restarted,
            InvocationId([0x45; 32]),
            AuthorityAdminOperation::UnbindNodeOwner {
                node: invited_node,
                owner,
            },
        );
        assert!(enrolled_node_owner(&restarted.state, invited_node).is_none());

        // Retirement resolves the pending capability without advancing its
        // PCTL position, so a fresh credential request may retry that same
        // predecessor position.
        let retry_node = enroll_additional_node(&mut restarted, owner, 0xe3);
        let retry_intent = AuthorityOperationIntent::InvitePrivateNode {
            managed,
            control: Hash([0x38; 32]),
            control_sequence: 0,
            control_previous: None,
            epoch: 0,
            node: retry_node,
            node_identity: enrolled_identity_commitment(&restarted, retry_node, owner),
        };
        let mut retry_call = operation_call(
            config,
            &owner_key,
            owner,
            Some(owner_node),
            0x39,
            retry_intent,
        );
        prepare_operation_call(&restarted, &mut retry_call, &owner_key);
        assert!(
            AuthorityOperationApproval::decode(&dispatch_operation(&mut restarted, &retry_call,))
                .is_ok()
        );

        // Whichever terminal resolution commits first owns the shared third
        // invocation: the reverse PCA2-then-PAR1 race also fails closed.
        vos::storage::mock::reset();
        vos::storage::mock::commit(unresolved_rows.into_iter().map(|(key, value)| (key, Some(value))).collect());
        let mut applied_actor = SystemAuthority {
            configuration: config,
            state: unresolved_state,
            node_certificates: Default::default(),
        };
        assert!(dispatch_private_application(
            &mut applied_actor,
            &application
        ));
        let after_application = applied_actor.state.clone();
        assert!(!dispatch_private_application_retirement(
            &mut applied_actor,
            &retirement
        ));
        assert_eq!(applied_actor.state, after_application);
        assert!(authority_state_is_valid(&config, &applied_actor.state));
    }

    #[test]
    fn private_rotation_resource_policy_and_actor_lifecycle_are_restartable() {
        let config = configuration();
        let owner = PrincipalId([0x41; 32]);
        let owner_node = node_for_principal(config, owner);
        let owner_key = signing(0x43);
        let mut actor = actor();
        enroll(
            &mut actor,
            &owner_key,
            owner,
            owner_node,
            BuiltinPrincipalRole::Member,
        );
        let descriptor = descriptor(config, owner, AgentProfile::Private, 0x44);
        let managed = target_for(&descriptor);
        insert_live(&mut actor, &descriptor);
        let member_set = fixture_member_set(descriptor.replicas.iter().map(|replica| replica.node));

        let rotate_control = Hash([0x45; 32]);
        let rotate = AuthorityOperationIntent::RotatePrivateKeys {
            managed,
            control: rotate_control,
            control_sequence: 0,
            control_previous: None,
            epoch: 1,
            member_set,
        };
        let resource = AuthorityOperationIntent::SetPrivateResourcePolicy {
            managed,
            control: Hash([0x46; 32]),
            control_sequence: 0,
            control_previous: None,
            policy: BlobRef::of_bytes(b"private-resource-policy"),
        };
        let lifecycle = AuthorityOperationIntent::PrivateActorLifecycle {
            managed,
            control: Hash([0x47; 32]),
            control_sequence: 0,
            control_previous: None,
            actor: ActorId([0x48; 32]),
            lifecycle: PrivateActorLifecycleKind::Install,
            request: Hash([0x49; 32]),
        };

        // Administrator status never substitutes for the Private owner key.
        for intent in [rotate.clone(), resource.clone(), lifecycle.clone()] {
            let call = operation_call(
                config,
                &signing(0x21),
                ADMIN_PRINCIPAL,
                Some(ADMIN_NODE),
                0x4a,
                intent,
            );
            let before = actor.state.clone();
            assert!(dispatch_operation(&mut actor, &call).is_empty());
            assert_eq!(actor.state, before);
        }

        let mut wrong_rotate_epoch = rotate.clone();
        let AuthorityOperationIntent::RotatePrivateKeys { epoch, .. } = &mut wrong_rotate_epoch
        else {
            unreachable!()
        };
        *epoch = 2;
        let mut wrong_rotate_members = rotate.clone();
        let AuthorityOperationIntent::RotatePrivateKeys {
            member_set: wrong_member_set_field,
            ..
        } = &mut wrong_rotate_members
        else {
            unreachable!()
        };
        *wrong_member_set_field = Hash([0x4b; 32]);
        for invalid in [wrong_rotate_epoch, wrong_rotate_members] {
            let call = operation_call(config, &owner_key, owner, Some(owner_node), 0x4c, invalid);
            let before = actor.state.clone();
            assert!(dispatch_operation(&mut actor, &call).is_empty());
            assert_eq!(actor.state, before);
        }

        let rotate_call = operation_call(config, &owner_key, owner, Some(owner_node), 0x4d, rotate);
        let rotate_approval_bytes = dispatch_operation(&mut actor, &rotate_call);
        let rotate_approval = AuthorityOperationApproval::decode(&rotate_approval_bytes).unwrap();
        assert_eq!(
            dispatch_operation(&mut actor, &rotate_call),
            rotate_approval_bytes
        );
        let rotate_issuance = operation_issuance_ack(config, &rotate_call, &rotate_approval);
        assert!(dispatch_operation_ack(&mut actor, &rotate_issuance));
        assert_eq!(rotate_approval.selector.request, rotate_control);
        assert_eq!(
            rotate_approval.selector.operation,
            AuthorityOperationKind::RotatePrivateKeys
        );
        assert_eq!(rotate_approval.selector.actor, None);
        assert_eq!(rotate_approval.selector.actor_deployment, None);

        // Until the exact PCA2 arrives no second control position can be
        // authorized, even though it points at the pending PCTL.
        let mut pending_resource = operation_call(
            config,
            &owner_key,
            owner,
            Some(owner_node),
            0x4e,
            AuthorityOperationIntent::SetPrivateResourcePolicy {
                managed,
                control: Hash([0x4f; 32]),
                control_sequence: 1,
                control_previous: Some(rotate_control),
                policy: BlobRef::of_bytes(b"pending-resource-policy"),
            },
        );
        prepare_operation_call(&actor, &mut pending_resource, &owner_key);
        let before_pending = actor.state.clone();
        assert!(dispatch_operation(&mut actor, &pending_resource).is_empty());
        assert_eq!(actor.state, before_pending);

        let rotate_application = private_application_fact(
            &rotate_call,
            member_set,
            Hash([0x50; 32]),
            OBSERVED_SLOT + 1,
        );
        let mut wrong_epoch = private_application_ack(
            &rotate_call,
            &rotate_approval,
            &rotate_issuance,
            rotate_application,
        );
        wrong_epoch.application.epoch = 2;
        resign_private_application_ack(&mut wrong_epoch);
        let before_application = actor.state.clone();
        assert!(!dispatch_private_application(&mut actor, &wrong_epoch));
        assert_eq!(actor.state, before_application);
        let mut wrong_members = wrong_epoch.clone();
        wrong_members.application.epoch = 1;
        wrong_members.application.post_member_set = Hash([0x51; 32]);
        resign_private_application_ack(&mut wrong_members);
        assert!(!dispatch_private_application(&mut actor, &wrong_members));
        assert_eq!(actor.state, before_application);

        let rotate_pca = private_application_ack(
            &rotate_call,
            &rotate_approval,
            &rotate_issuance,
            rotate_application,
        );
        assert!(dispatch_private_application(&mut actor, &rotate_pca));
        assert!(dispatch_private_application(&mut actor, &rotate_pca));
        assert_eq!(actor.state.private_agents[0].epoch, 1);
        assert_eq!(actor.state.private_agents[0].member_set, member_set.0);
        assert_eq!(actor.state.private_agents[0].members.len(), 1);

        let resource_control = Hash([0x52; 32]);
        let mut resource_call = operation_call(
            config,
            &owner_key,
            owner,
            Some(owner_node),
            0x53,
            AuthorityOperationIntent::SetPrivateResourcePolicy {
                managed,
                control: resource_control,
                control_sequence: 1,
                control_previous: Some(rotate_control),
                policy: BlobRef::of_bytes(b"private-resource-policy"),
            },
        );
        prepare_operation_call(&actor, &mut resource_call, &owner_key);
        let (resource_approval, resource_issuance) =
            authorize_and_issue_operation(&mut actor, &resource_call);
        assert_eq!(resource_approval.selector.request, resource_control);
        assert_eq!(
            resource_approval.selector.operation,
            AuthorityOperationKind::SetPrivateResourcePolicy
        );
        assert_eq!(resource_approval.selector.actor, None);
        assert_eq!(resource_approval.selector.actor_deployment, None);

        let mut resource_application = private_application_fact(
            &resource_call,
            member_set,
            Hash([0x54; 32]),
            OBSERVED_SLOT + 2,
        );
        resource_application.epoch = 1;
        let mut wrong_resource_epoch = private_application_ack(
            &resource_call,
            &resource_approval,
            &resource_issuance,
            resource_application,
        );
        wrong_resource_epoch.application.epoch = 0;
        resign_private_application_ack(&mut wrong_resource_epoch);
        let before_resource_application = actor.state.clone();
        assert!(!dispatch_private_application(
            &mut actor,
            &wrong_resource_epoch
        ));
        assert_eq!(actor.state, before_resource_application);
        let mut wrong_resource_members = wrong_resource_epoch.clone();
        wrong_resource_members.application.epoch = 1;
        wrong_resource_members.application.post_member_set = Hash([0x55; 32]);
        resign_private_application_ack(&mut wrong_resource_members);
        assert!(!dispatch_private_application(
            &mut actor,
            &wrong_resource_members
        ));
        assert_eq!(actor.state, before_resource_application);

        let resource_pca = private_application_ack(
            &resource_call,
            &resource_approval,
            &resource_issuance,
            resource_application,
        );
        assert!(dispatch_private_application(&mut actor, &resource_pca));
        assert!(dispatch_private_application(&mut actor, &resource_pca));
        assert_eq!(
            actor.state.private_agents[0].control_head,
            Some(resource_control.0)
        );
        assert_eq!(actor.state.private_agents[0].control_sequence, Some(1));
        assert_eq!(actor.state.private_agents[0].epoch, 1);
        assert_eq!(actor.state.private_agents[0].member_set, member_set.0);

        let lifecycle_control = Hash([0x56; 32]);
        let lifecycle_actor = ActorId([0x57; 32]);
        let mut lifecycle_call = operation_call(
            config,
            &owner_key,
            owner,
            Some(owner_node),
            0x58,
            AuthorityOperationIntent::PrivateActorLifecycle {
                managed,
                control: lifecycle_control,
                control_sequence: 2,
                control_previous: Some(resource_control),
                actor: lifecycle_actor,
                lifecycle: PrivateActorLifecycleKind::Upgrade,
                request: Hash([0x59; 32]),
            },
        );
        prepare_operation_call(&actor, &mut lifecycle_call, &owner_key);
        let (lifecycle_approval, lifecycle_issuance) =
            authorize_and_issue_operation(&mut actor, &lifecycle_call);
        assert_eq!(lifecycle_approval.selector.request, lifecycle_control);
        assert_eq!(
            lifecycle_approval.selector.operation,
            AuthorityOperationKind::PrivateActorLifecycle
        );
        assert_eq!(lifecycle_approval.selector.actor, Some(lifecycle_actor));
        assert_eq!(lifecycle_approval.selector.actor_deployment, None);
        let mut lifecycle_application = private_application_fact(
            &lifecycle_call,
            member_set,
            Hash([0x5a; 32]),
            OBSERVED_SLOT + 2,
        );
        lifecycle_application.epoch = 1;
        let mut older_lifecycle_application = lifecycle_application;
        older_lifecycle_application.applied_at = OBSERVED_SLOT + 1;
        let older_lifecycle_pca = private_application_ack(
            &lifecycle_call,
            &lifecycle_approval,
            &lifecycle_issuance,
            older_lifecycle_application,
        );
        let before_lifecycle_application = actor.state.clone();
        assert!(!dispatch_private_application(
            &mut actor,
            &older_lifecycle_pca
        ));
        assert_eq!(actor.state, before_lifecycle_application);
        // The exact sequence/head chain orders this distinct control even
        // though it shares the resource application's observed slot.
        let lifecycle_pca = private_application_ack(
            &lifecycle_call,
            &lifecycle_approval,
            &lifecycle_issuance,
            lifecycle_application,
        );
        assert!(dispatch_private_application(&mut actor, &lifecycle_pca));
        assert!(dispatch_private_application(&mut actor, &lifecycle_pca));
        assert_eq!(
            actor.state.private_agents[0].control_head,
            Some(lifecycle_control.0)
        );
        assert_eq!(actor.state.private_agents[0].control_sequence, Some(2));
        assert_eq!(actor.state.private_agents[0].epoch, 1);
        assert_eq!(actor.state.private_agents[0].member_set, member_set.0);
        assert_eq!(
            actor.state.private_agents[0].applied_at,
            Some(OBSERVED_SLOT + 2)
        );

        let linear = <SystemAuthority as vos::Actor>::__save_agent_lane(&actor, StateLane::Linear);
        let mut restarted = <SystemAuthority as vos::Actor>::__load_agent_state(
            Some(&config.encode()),
            Some(&linear),
            None,
            None,
        )
        .expect("the applied Private control sequence restarts from exact state");
        assert_eq!(restarted.state, actor.state);
        assert!(dispatch_private_application(&mut restarted, &rotate_pca));
        assert!(dispatch_private_application(&mut restarted, &resource_pca));
        assert!(dispatch_private_application(&mut restarted, &lifecycle_pca));
        assert_eq!(restarted.state, actor.state);
        assert!(authority_state_is_valid(&config, &restarted.state));
    }

    #[test]
    fn pending_pca2_source_remains_valid_when_aoi_floor_later_compacts_it() {
        let config = configuration();
        let owner = PrincipalId([0xd1; 32]);
        let owner_node = node_for_principal(config, owner);
        let owner_key = signing(0xd3);
        let mut actor = actor();
        enroll(
            &mut actor,
            &owner_key,
            owner,
            owner_node,
            BuiltinPrincipalRole::Member,
        );
        let gap_key = signing(0xd2);
        dispatch_fixture_admin(
            &mut actor,
            InvocationId([0xd2; 32]),
            AuthorityAdminOperation::AddCredential {
                principal: owner,
                credential: enrollment(&gap_key, AuthorityCredentialKind::Api),
            },
        );
        let gap_descriptor = descriptor(config, owner, AgentProfile::Private, 0xdc);
        let gap_managed = target_for(&gap_descriptor);
        insert_live(&mut actor, &gap_descriptor);
        let descriptor = descriptor(config, owner, AgentProfile::Private, 0xd4);
        let managed = target_for(&descriptor);
        insert_live(&mut actor, &descriptor);
        let gap_node = enroll_additional_node(&mut actor, owner, 0xf0);
        let gap_node_identity = enrolled_identity_commitment(&actor, gap_node, owner);
        let invited_node = enroll_additional_node(&mut actor, owner, 0xf1);
        let invited_identity = enrolled_identity_commitment(&actor, invited_node, owner);

        let gap_call = operation_call(
            config,
            &gap_key,
            owner,
            None,
            0xd5,
            AuthorityOperationIntent::InvitePrivateNode {
                managed: gap_managed,
                control: Hash([0xd6; 32]),
                control_sequence: 0,
                control_previous: None,
                epoch: 0,
                node: gap_node,
                node_identity: gap_node_identity,
            },
        );
        let gap_approval =
            AuthorityOperationApproval::decode(&dispatch_operation(&mut actor, &gap_call)).unwrap();
        let gap_issuance = operation_issuance_ack(config, &gap_call, &gap_approval);

        let target_call = operation_call(
            config,
            &owner_key,
            owner,
            Some(owner_node),
            0xd8,
            AuthorityOperationIntent::InvitePrivateNode {
                managed,
                control: Hash([0xd9; 32]),
                control_sequence: 0,
                control_previous: None,
                epoch: 0,
                node: invited_node,
                node_identity: invited_identity,
            },
        );
        let (target_approval, target_issuance) =
            authorize_and_issue_operation(&mut actor, &target_call);
        assert_eq!(actor.state.operation_retirement_floor, 4);
        assert_eq!(actor.state.operation_retries.len(), 2);
        assert!(actor.state.operation_retries.iter().any(|record| {
            record.invocation == target_call.invocation.0 && record.issuance_ack.is_some()
        }));
        let member_set = fixture_member_set([descriptor.replicas[0].node, invited_node]);
        let pca = private_application_ack(
            &target_call,
            &target_approval,
            &target_issuance,
            private_application_fact(
                &target_call,
                member_set,
                Hash([0xdb; 32]),
                OBSERVED_SLOT + 1,
            ),
        );
        assert!(dispatch_private_application(&mut actor, &pca));
        assert!(actor.state.latest_operation_acks.is_empty());

        assert!(dispatch_operation_ack(&mut actor, &gap_issuance));
        assert!(actor.state.operation_retries.is_empty());
        assert_eq!(actor.state.latest_operation_acks.len(), 2);
        assert_eq!(actor.state.operation_retirement_floor, 6);
        let after_compaction = actor.state.clone();
        assert!(dispatch_private_application(&mut actor, &pca));
        assert_eq!(actor.state, after_compaction);
        assert!(authority_state_is_valid(&config, &actor.state));
    }

    #[test]
    fn par1_resolves_an_active_aoi_source_before_its_gap_compacts() {
        let config = configuration();
        let owner = PrincipalId([0x2a; 32]);
        let owner_node = node_for_principal(config, owner);
        let owner_key = signing(0x2b);
        let gap_key = signing(0x2c);
        let mut actor = actor();
        enroll(
            &mut actor,
            &owner_key,
            owner,
            owner_node,
            BuiltinPrincipalRole::Member,
        );
        dispatch_fixture_admin(
            &mut actor,
            InvocationId([0x2d; 32]),
            AuthorityAdminOperation::AddCredential {
                principal: owner,
                credential: enrollment(&gap_key, AuthorityCredentialKind::Api),
            },
        );
        let gap_descriptor = descriptor(config, owner, AgentProfile::Private, 0x2e);
        let target_descriptor = descriptor(config, owner, AgentProfile::Private, 0x2f);
        let gap_managed = target_for(&gap_descriptor);
        let target_managed = target_for(&target_descriptor);
        insert_live(&mut actor, &gap_descriptor);
        insert_live(&mut actor, &target_descriptor);
        let gap_node = enroll_additional_node(&mut actor, owner, 0xe1);
        let target_node = enroll_additional_node(&mut actor, owner, 0xe2);

        let gap_call = operation_call(
            config,
            &gap_key,
            owner,
            None,
            0x40,
            AuthorityOperationIntent::InvitePrivateNode {
                managed: gap_managed,
                control: Hash([0x41; 32]),
                control_sequence: 0,
                control_previous: None,
                epoch: 0,
                node: gap_node,
                node_identity: enrolled_identity_commitment(&actor, gap_node, owner),
            },
        );
        let gap_approval =
            AuthorityOperationApproval::decode(&dispatch_operation(&mut actor, &gap_call)).unwrap();
        let gap_issuance = operation_issuance_ack(config, &gap_call, &gap_approval);

        let target_call = operation_call(
            config,
            &owner_key,
            owner,
            Some(owner_node),
            0x42,
            AuthorityOperationIntent::InvitePrivateNode {
                managed: target_managed,
                control: Hash([0x43; 32]),
                control_sequence: 0,
                control_previous: None,
                epoch: 0,
                node: target_node,
                node_identity: enrolled_identity_commitment(&actor, target_node, owner),
            },
        );
        let (target_approval, target_issuance) =
            authorize_and_issue_operation(&mut actor, &target_call);
        assert_eq!(actor.state.operation_retries.len(), 2);
        assert!(actor.state.latest_operation_acks.is_empty());
        assert!(outstanding_private_operation_exists(
            &actor.state,
            target_managed.agent
        ));
        let projections = actor.state.private_agents.clone();
        let retirement = private_application_retirement_ack(
            &target_call,
            &target_approval,
            &target_issuance,
            OBSERVED_SLOT + 1,
        );

        assert!(dispatch_private_application_retirement(
            &mut actor,
            &retirement
        ));
        assert_eq!(actor.state.operation_retries.len(), 2);
        assert!(actor.state.latest_operation_acks.is_empty());
        assert!(!outstanding_private_operation_exists(
            &actor.state,
            target_managed.agent
        ));
        assert_eq!(actor.state.private_agents, projections);
        assert_eq!(actor.state.private_applications.len(), 0);

        assert!(dispatch_operation_ack(&mut actor, &gap_issuance));
        assert!(actor.state.operation_retries.is_empty());
        assert_eq!(actor.state.latest_operation_acks.len(), 2);
        assert!(authority_state_is_valid(&config, &actor.state));
        let after_compaction = actor.state.clone();
        assert!(dispatch_private_application_retirement(
            &mut actor,
            &retirement
        ));
        assert_eq!(actor.state, after_compaction);

        let member_set = fixture_member_set([target_descriptor.replicas[0].node, target_node]);
        let application = private_application_ack(
            &target_call,
            &target_approval,
            &target_issuance,
            private_application_fact(
                &target_call,
                member_set,
                Hash([0x44; 32]),
                OBSERVED_SLOT + 1,
            ),
        );
        assert!(!dispatch_private_application(&mut actor, &application));
        assert_eq!(actor.state, after_compaction);

        let linear = <SystemAuthority as vos::Actor>::__save_agent_lane(&actor, StateLane::Linear);
        let mut restarted = <SystemAuthority as vos::Actor>::__load_agent_state(
            Some(&config.encode()),
            Some(&linear),
            None,
            None,
        )
        .expect("active-source PAR1 compaction restarts");
        assert!(dispatch_private_application_retirement(
            &mut restarted,
            &retirement
        ));
        assert_eq!(restarted.state, actor.state);
    }

    #[test]
    fn delayed_old_runtime_pca2_is_authenticated_by_its_source_after_upgrade() {
        let config = configuration();
        let owner = PrincipalId([0xe1; 32]);
        let owner_node = node_for_principal(config, owner);
        let owner_key = signing(0xe3);
        let mut actor = actor();
        enroll(
            &mut actor,
            &owner_key,
            owner,
            owner_node,
            BuiltinPrincipalRole::Member,
        );
        let descriptor = descriptor(config, owner, AgentProfile::Private, 0xe4);
        let old_managed = target_for(&descriptor);
        insert_live(&mut actor, &descriptor);
        let invited_node = enroll_additional_node(&mut actor, owner, 0xf2);
        let invited_identity = enrolled_identity_commitment(&actor, invited_node, owner);
        let invite_call = operation_call(
            config,
            &owner_key,
            owner,
            Some(owner_node),
            0xe5,
            AuthorityOperationIntent::InvitePrivateNode {
                managed: old_managed,
                control: Hash([0xe6; 32]),
                control_sequence: 0,
                control_previous: None,
                epoch: 0,
                node: invited_node,
                node_identity: invited_identity,
            },
        );
        let (invite_approval, invite_issuance) =
            authorize_and_issue_operation(&mut actor, &invite_call);
        let member_set = fixture_member_set([descriptor.replicas[0].node, invited_node]);
        let delayed_pca = private_application_ack(
            &invite_call,
            &invite_approval,
            &invite_issuance,
            private_application_fact(
                &invite_call,
                member_set,
                Hash([0xe8; 32]),
                OBSERVED_SLOT + 1,
            ),
        );

        let new_deployment = DeploymentId([0xe9; 32]);
        let mut upgrade_call = credential_call(
            config,
            &signing(0x21),
            ADMIN_PRINCIPAL,
            Some(ADMIN_NODE),
            0xea,
            old_managed,
            ManagementRequest::UpgradeRuntime(Box::new(vos::agent_sdk::RuntimeUpgrade {
                from_deployment: old_managed.runtime_deployment,
                to_deployment: new_deployment,
                to_program: ProgramId([0xeb; 32]),
                producer: ProducerId([0xec; 32]),
                package: BlobRef::of_bytes(b"compatible-private-runtime"),
                contract: RuntimePackageContract::canonical(),
                capabilities: RuntimeCapabilities::standard(),
            })),
        );
        prepare_management_call(&actor, &mut upgrade_call, &signing(0x21));
        let upgrade_approval = ManagementApproval::decode(&dispatch(&mut actor, &upgrade_call))
            .expect("runtime upgrade authorized");
        let mut upgrade_ack =
            application_ack(config, &actor.state, &upgrade_call, &upgrade_approval);
        upgrade_ack.applied_at = OBSERVED_SLOT + 2;
        resign_ack(&mut upgrade_ack);
        assert!(dispatch_ack(&mut actor, &upgrade_ack));
        let managed_index = managed_agent(&actor.state, old_managed.agent).unwrap();
        assert_eq!(
            actor.state.managed_agents[managed_index].runtime_deployment,
            new_deployment.0
        );
        assert_eq!(
            actor.state.private_agents[0].runtime_deployment,
            new_deployment.0
        );

        assert!(dispatch_private_application(&mut actor, &delayed_pca));
        assert_eq!(
            actor.state.private_applications[0].runtime_deployment,
            old_managed.runtime_deployment.0
        );
        assert_eq!(
            actor.state.private_agents[0].runtime_deployment,
            new_deployment.0
        );
        assert_eq!(actor.state.private_agents[0].control_head, Some([0xe6; 32]));
        assert!(authority_state_is_valid(&config, &actor.state));
    }

    #[test]
    fn pca2_rejects_missing_issuance_substitution_and_cross_domain_collisions() {
        let config = configuration();
        let owner = PrincipalId([0xa1; 32]);
        let owner_node = node_for_principal(config, owner);
        let owner_key = signing(0xa3);
        let mut actor = actor();
        enroll(
            &mut actor,
            &owner_key,
            owner,
            owner_node,
            BuiltinPrincipalRole::Member,
        );
        let descriptor = descriptor(config, owner, AgentProfile::Private, 0xa4);
        let managed = target_for(&descriptor);
        insert_live(&mut actor, &descriptor);
        let invited_node = enroll_additional_node(&mut actor, owner, 0xf3);
        let invited_identity = enrolled_identity_commitment(&actor, invited_node, owner);
        let member_set = fixture_member_set([descriptor.replicas[0].node, invited_node]);
        let call = operation_call(
            config,
            &owner_key,
            owner,
            Some(owner_node),
            0xa5,
            AuthorityOperationIntent::InvitePrivateNode {
                managed,
                control: Hash([0xa6; 32]),
                control_sequence: 0,
                control_previous: None,
                epoch: 0,
                node: invited_node,
                node_identity: invited_identity,
            },
        );
        let approval =
            AuthorityOperationApproval::decode(&dispatch_operation(&mut actor, &call)).unwrap();
        let issuance = operation_issuance_ack(config, &call, &approval);
        let pca = private_application_ack(
            &call,
            &approval,
            &issuance,
            private_application_fact(&call, member_set, Hash([0xa8; 32]), OBSERVED_SLOT + 1),
        );
        let before_issuance = actor.state.clone();
        assert!(!dispatch_private_application(&mut actor, &pca));
        assert_eq!(actor.state, before_issuance);
        assert!(dispatch_operation_ack(&mut actor, &issuance));

        let baseline = actor.state.clone();
        let encoded = pca.encode().unwrap();
        let mut wrong_context = private_application_context(&pca);
        wrong_context.observed_slot += 1;
        assert!(!dispatch_private_application_bytes(
            &mut actor,
            encoded,
            Some(wrong_context),
        ));
        assert_eq!(actor.state, baseline);

        let mut old_pca1 = pca.encode().unwrap();
        old_pca1[..4].copy_from_slice(b"PCA1");
        assert!(!dispatch_private_application_bytes(
            &mut actor,
            old_pca1,
            Some(private_application_context(&pca)),
        ));
        let stable_projection = pca.application.stable_projection.0;
        let mut old_layout = pca.encode().unwrap();
        let stable_offset = old_layout
            .windows(stable_projection.len())
            .position(|window| window == stable_projection)
            .expect("fixture stable projection has one canonical preimage");
        old_layout.drain(stable_offset..stable_offset + stable_projection.len());
        assert!(!dispatch_private_application_bytes(
            &mut actor,
            old_layout,
            Some(private_application_context(&pca)),
        ));

        let mut bad_signature = pca.clone();
        bad_signature.signature[0] ^= 1;
        assert!(!dispatch_private_application(&mut actor, &bad_signature));
        let mut substituted_runtime_state = pca.clone();
        substituted_runtime_state.application.reopened_runtime_state = Hash([0xb4; 32]);
        assert!(!dispatch_private_application(
            &mut actor,
            &substituted_runtime_state,
        ));
        let mut substituted_stable_projection = pca.clone();
        substituted_stable_projection.application.stable_projection = Hash([0xb5; 32]);
        assert!(!dispatch_private_application(
            &mut actor,
            &substituted_stable_projection,
        ));
        assert_eq!(actor.state, baseline);

        let mut wrong_call = pca.clone();
        wrong_call.operation_call = Hash([0xa9; 32]);
        resign_private_application_ack(&mut wrong_call);
        assert!(!dispatch_private_application(&mut actor, &wrong_call));

        let mut wrong_approval = pca.clone();
        wrong_approval.approval = Hash([0xaa; 32]);
        resign_private_application_ack(&mut wrong_approval);
        assert!(!dispatch_private_application(&mut actor, &wrong_approval));

        let mut wrong_issuance = pca.clone();
        wrong_issuance.issuance_ack = Hash([0xab; 32]);
        wrong_issuance.application_invocation =
            PrivateControlApplicationAck::derive_application_invocation_from_issuance(
                wrong_issuance.authority,
                wrong_issuance.authorization_invocation,
                wrong_issuance.issuance_invocation,
                wrong_issuance.authorization_sequence,
                wrong_issuance.issuance_ack,
            );
        resign_private_application_ack(&mut wrong_issuance);
        assert!(!dispatch_private_application(&mut actor, &wrong_issuance));

        let mut wrong_issued_at = pca.clone();
        wrong_issued_at.issued_at += 1;
        resign_private_application_ack(&mut wrong_issued_at);
        assert!(!dispatch_private_application(&mut actor, &wrong_issued_at));

        let mut wrong_authority = pca.clone();
        wrong_authority.authority.system_agent = AgentId([0xac; 32]);
        wrong_authority.application_invocation =
            PrivateControlApplicationAck::derive_application_invocation_from_issuance(
                wrong_authority.authority,
                wrong_authority.authorization_invocation,
                wrong_authority.issuance_invocation,
                wrong_authority.authorization_sequence,
                wrong_authority.issuance_ack,
            );
        resign_private_application_ack(&mut wrong_authority);
        assert!(!dispatch_private_application(&mut actor, &wrong_authority));

        let mut wrong_target = pca.clone();
        wrong_target.application.managed.runtime_deployment = DeploymentId([0xad; 32]);
        wrong_target.receipt.selector.runtime_deployment = DeploymentId([0xad; 32]);
        resign_receipt(&mut wrong_target.receipt);
        resign_private_application_ack(&mut wrong_target);
        assert!(!dispatch_private_application(&mut actor, &wrong_target));

        let mut wrong_control = pca.clone();
        wrong_control.application.control = Hash([0xae; 32]);
        wrong_control.application.reopened_control_head = Hash([0xae; 32]);
        wrong_control.receipt.selector.request = Hash([0xae; 32]);
        resign_receipt(&mut wrong_control.receipt);
        resign_private_application_ack(&mut wrong_control);
        assert!(!dispatch_private_application(&mut actor, &wrong_control));

        let mut wrong_operation = pca.clone();
        wrong_operation.application.operation = AuthorityOperationKind::RevokePrivateNode;
        wrong_operation.receipt.selector.operation = AuthorityOperationKind::RevokePrivateNode;
        resign_receipt(&mut wrong_operation.receipt);
        resign_private_application_ack(&mut wrong_operation);
        assert!(!dispatch_private_application(&mut actor, &wrong_operation));
        assert_eq!(actor.state, baseline);

        let mut collision_actor = SystemAuthority {
            configuration: actor.configuration,
            state: actor.state.clone(),
            node_certificates: Default::default(),
        };
        let collision_key = signing(0xaf);
        let collision_principal = PrincipalId([0xb0; 32]);
        let mut collision_admin = admin_call(
            config,
            &signing(0x21),
            ADMIN_PRINCIPAL,
            ADMIN_NODE,
            1,
            collision_actor.state.administration_generation,
            AuthorityAdminOperation::EnrollPrincipal {
                principal: collision_principal,
                credential: enrollment(&collision_key, AuthorityCredentialKind::Ssh),
            },
        );
        assert_ne!(collision_admin.invocation, pca.application_invocation);
        collision_admin.invocation = pca.application_invocation;
        resign_admin(&mut collision_admin, &signing(0x21));
        let collision_state = collision_actor.state.clone();
        assert!(collision_admin.encode().is_err());
        assert_eq!(collision_actor.state, collision_state);
        assert!(dispatch_private_application(&mut collision_actor, &pca));

        assert!(dispatch_private_application(&mut actor, &pca));
        let after_application = actor.state.clone();
        let mut colliding_operation = call.clone();
        colliding_operation.invocation = pca.application_invocation;
        resign_operation_call(&mut colliding_operation, &owner_key);
        assert!(colliding_operation.encode().is_err());
        let mut colliding_management = create_call(
            config,
            &signing(0x21),
            ADMIN_PRINCIPAL,
            Some(ADMIN_NODE),
            1,
            AgentProfile::Local,
            0xb1,
        );
        colliding_management.invocation = pca.application_invocation;
        resign(&mut colliding_management, &signing(0x21));
        assert!(colliding_management.encode().is_err());
        let mut colliding_admin = admin_call(
            config,
            &signing(0x21),
            ADMIN_PRINCIPAL,
            ADMIN_NODE,
            1,
            actor.state.administration_generation,
            AuthorityAdminOperation::EnrollPrincipal {
                principal: PrincipalId([0xb2; 32]),
                credential: enrollment(&signing(0xb3), AuthorityCredentialKind::Ssh),
            },
        );
        colliding_admin.invocation = pca.application_invocation;
        resign_admin(&mut colliding_admin, &signing(0x21));
        assert!(colliding_admin.encode().is_err());
        assert_eq!(actor.state, after_application);
    }

    #[test]
    fn private_projection_rejects_out_of_order_gaps_forks_epochs_and_slot_rollback() {
        let config = configuration();
        let owner = PrincipalId([0x61; 32]);
        let owner_node = node_for_principal(config, owner);
        let owner_key = signing(0x63);
        let mut actor = actor();
        enroll(
            &mut actor,
            &owner_key,
            owner,
            owner_node,
            BuiltinPrincipalRole::Member,
        );
        let descriptor = descriptor(config, owner, AgentProfile::Private, 0x64);
        let managed = target_for(&descriptor);
        insert_live(&mut actor, &descriptor);
        let initial_member_set =
            fixture_member_set(descriptor.replicas.iter().map(|replica| replica.node));
        let invited_node = enroll_additional_node(&mut actor, owner, 0xf4);
        let invited_identity = enrolled_identity_commitment(&actor, invited_node, owner);
        let invited_member_set = fixture_member_set([descriptor.replicas[0].node, invited_node]);

        let first_control = Hash([0x65; 32]);
        let first_call = operation_call(
            config,
            &owner_key,
            owner,
            Some(owner_node),
            0x66,
            AuthorityOperationIntent::InvitePrivateNode {
                managed,
                control: first_control,
                control_sequence: 0,
                control_previous: None,
                epoch: 0,
                node: invited_node,
                node_identity: invited_identity,
            },
        );
        let (first_approval, first_issuance) =
            authorize_and_issue_operation(&mut actor, &first_call);
        let first_pca = private_application_ack(
            &first_call,
            &first_approval,
            &first_issuance,
            private_application_fact(
                &first_call,
                invited_member_set,
                Hash([0x68; 32]),
                OBSERVED_SLOT + 1,
            ),
        );
        assert!(dispatch_private_application(&mut actor, &first_pca));

        let second_control = Hash([0x69; 32]);
        let mut second_call = operation_call(
            config,
            &owner_key,
            owner,
            Some(owner_node),
            0x6a,
            AuthorityOperationIntent::RevokePrivateNode {
                managed,
                control: second_control,
                control_sequence: 1,
                control_previous: Some(first_control),
                epoch: 1,
                node: invited_node,
                member_set: initial_member_set,
            },
        );
        prepare_operation_call(&actor, &mut second_call, &owner_key);
        let (second_approval, second_issuance) =
            authorize_and_issue_operation(&mut actor, &second_call);
        let second_pca = private_application_ack(
            &second_call,
            &second_approval,
            &second_issuance,
            private_application_fact(
                &second_call,
                initial_member_set,
                Hash([0x6b; 32]),
                OBSERVED_SLOT + 2,
            ),
        );

        let third_control = Hash([0x6c; 32]);
        let third_node = enroll_additional_node(&mut actor, owner, 0xf5);
        let third_identity = enrolled_identity_commitment(&actor, third_node, owner);
        let third_member_set = fixture_member_set([descriptor.replicas[0].node, third_node]);
        let mut third_call = operation_call(
            config,
            &owner_key,
            owner,
            Some(owner_node),
            0x6e,
            AuthorityOperationIntent::InvitePrivateNode {
                managed,
                control: third_control,
                control_sequence: 2,
                control_previous: Some(second_control),
                epoch: 1,
                node: third_node,
                node_identity: third_identity,
            },
        );
        prepare_operation_call(&actor, &mut third_call, &owner_key);
        let before_out_of_order = actor.state.clone();
        assert!(dispatch_operation(&mut actor, &third_call).is_empty());
        assert_eq!(actor.state, before_out_of_order);
        assert!(dispatch_private_application(&mut actor, &second_pca));
        let (third_approval, third_issuance) =
            authorize_and_issue_operation(&mut actor, &third_call);
        let third_pca = private_application_ack(
            &third_call,
            &third_approval,
            &third_issuance,
            private_application_fact(
                &third_call,
                third_member_set,
                Hash([0x70; 32]),
                OBSERVED_SLOT + 3,
            ),
        );
        assert!(dispatch_private_application(&mut actor, &third_pca));

        let hostile = [
            (
                0x71,
                AuthorityOperationIntent::InvitePrivateNode {
                    managed,
                    control: Hash([0x72; 32]),
                    control_sequence: 1,
                    control_previous: Some(first_control),
                    epoch: 0,
                    node: NodeId([0xf6; 32]),
                    node_identity: Hash([0x73; 32]),
                },
            ),
            (
                0x75,
                AuthorityOperationIntent::InvitePrivateNode {
                    managed,
                    control: Hash([0x76; 32]),
                    control_sequence: 4,
                    control_previous: Some(third_control),
                    epoch: 1,
                    node: NodeId([0xf7; 32]),
                    node_identity: Hash([0x77; 32]),
                },
            ),
            (
                0x79,
                AuthorityOperationIntent::InvitePrivateNode {
                    managed,
                    control: Hash([0x7a; 32]),
                    control_sequence: 3,
                    control_previous: Some(Hash([0x7b; 32])),
                    epoch: 1,
                    node: NodeId([0xf8; 32]),
                    node_identity: Hash([0x7c; 32]),
                },
            ),
            (
                0x7e,
                AuthorityOperationIntent::RevokePrivateNode {
                    managed,
                    control: Hash([0x7f; 32]),
                    control_sequence: 3,
                    control_previous: Some(third_control),
                    epoch: 3,
                    node: third_node,
                    member_set: initial_member_set,
                },
            ),
            // A duplicate Invite and absent Revoke are invalid even at the
            // exact current control position.
            (
                0x80,
                AuthorityOperationIntent::InvitePrivateNode {
                    managed,
                    control: Hash([0x81; 32]),
                    control_sequence: 3,
                    control_previous: Some(third_control),
                    epoch: 1,
                    node: third_node,
                    node_identity: Hash([0x82; 32]),
                },
            ),
            (
                0x84,
                AuthorityOperationIntent::RevokePrivateNode {
                    managed,
                    control: Hash([0x85; 32]),
                    control_sequence: 3,
                    control_previous: Some(third_control),
                    epoch: 2,
                    node: NodeId([0xfa; 32]),
                    member_set: initial_member_set,
                },
            ),
            // Even a present-node Revoke must advertise the exact removal.
            (
                0x87,
                AuthorityOperationIntent::RevokePrivateNode {
                    managed,
                    control: Hash([0x88; 32]),
                    control_sequence: 3,
                    control_previous: Some(third_control),
                    epoch: 2,
                    node: third_node,
                    member_set: third_member_set,
                },
            ),
        ];
        for (invocation, intent) in hostile {
            let mut call = operation_call(
                config,
                &owner_key,
                owner,
                Some(owner_node),
                invocation,
                intent,
            );
            prepare_operation_call(&actor, &mut call, &owner_key);
            let before = actor.state.clone();
            assert!(dispatch_operation(&mut actor, &call).is_empty());
            assert_eq!(actor.state, before);
        }

        let fourth_node = enroll_additional_node(&mut actor, owner, 0xf9);
        let fourth_identity = enrolled_identity_commitment(&actor, fourth_node, owner);
        let fourth_member_set =
            fixture_member_set([descriptor.replicas[0].node, third_node, fourth_node]);
        let mut fourth_call = operation_call(
            config,
            &owner_key,
            owner,
            Some(owner_node),
            0x89,
            AuthorityOperationIntent::InvitePrivateNode {
                managed,
                control: Hash([0x8a; 32]),
                control_sequence: 3,
                control_previous: Some(third_control),
                epoch: 1,
                node: fourth_node,
                node_identity: fourth_identity,
            },
        );
        prepare_operation_call(&actor, &mut fourth_call, &owner_key);
        let (fourth_approval, fourth_issuance) =
            authorize_and_issue_operation(&mut actor, &fourth_call);

        let mut fork = operation_call(
            config,
            &owner_key,
            owner,
            Some(owner_node),
            0x8c,
            AuthorityOperationIntent::InvitePrivateNode {
                managed,
                control: Hash([0x8d; 32]),
                control_sequence: 3,
                control_previous: Some(third_control),
                epoch: 1,
                node: NodeId([0xfb; 32]),
                node_identity: Hash([0x8e; 32]),
            },
        );
        prepare_operation_call(&actor, &mut fork, &owner_key);
        assert!(dispatch_operation(&mut actor, &fork).is_empty());

        let wrong_member_set = private_application_ack(
            &fourth_call,
            &fourth_approval,
            &fourth_issuance,
            private_application_fact(
                &fourth_call,
                third_member_set,
                Hash([0x8f; 32]),
                OBSERVED_SLOT + 4,
            ),
        );
        assert!(!dispatch_private_application(&mut actor, &wrong_member_set));
        let rollback = private_application_ack(
            &fourth_call,
            &fourth_approval,
            &fourth_issuance,
            private_application_fact(
                &fourth_call,
                fourth_member_set,
                Hash([0x90; 32]),
                OBSERVED_SLOT + 2,
            ),
        );
        assert!(!dispatch_private_application(&mut actor, &rollback));
        assert!(authority_state_is_valid(&config, &actor.state));
    }

    #[test]
    fn private_projection_reconstruction_rejects_corruption_and_explicit_overflow() {
        let config = configuration();
        let owner = PrincipalId([0x51; 32]);
        let owner_node = node_for_principal(config, owner);
        let owner_key = signing(0x53);
        let mut actor = actor();
        enroll(
            &mut actor,
            &owner_key,
            owner,
            owner_node,
            BuiltinPrincipalRole::Member,
        );
        let descriptor = descriptor(config, owner, AgentProfile::Private, 0x54);
        let managed = target_for(&descriptor);
        insert_live(&mut actor, &descriptor);
        let invited_node = enroll_additional_node(&mut actor, owner, 0xf6);
        let invited_identity = enrolled_identity_commitment(&actor, invited_node, owner);
        let member_set = fixture_member_set([descriptor.replicas[0].node, invited_node]);
        let call = operation_call(
            config,
            &owner_key,
            owner,
            Some(owner_node),
            0x55,
            AuthorityOperationIntent::InvitePrivateNode {
                managed,
                control: Hash([0x56; 32]),
                control_sequence: 0,
                control_previous: None,
                epoch: 0,
                node: invited_node,
                node_identity: invited_identity,
            },
        );
        let (approval, issuance) = authorize_and_issue_operation(&mut actor, &call);
        let pca = private_application_ack(
            &call,
            &approval,
            &issuance,
            private_application_fact(&call, member_set, Hash([0x58; 32]), OBSERVED_SLOT + 1),
        );
        assert!(dispatch_private_application(&mut actor, &pca));
        assert!(authority_state_is_valid(&config, &actor.state));

        let mut missing_projection = actor.state.clone();
        missing_projection.private_agents.clear();
        assert!(!authority_state_is_valid(&config, &missing_projection));

        let mut wrong_owner = actor.state.clone();
        wrong_owner.private_agents[0].owner[0] ^= 1;
        assert!(!authority_state_is_valid(&config, &wrong_owner));

        let mut wrong_runtime = actor.state.clone();
        wrong_runtime.private_agents[0].runtime_deployment[0] ^= 1;
        assert!(!authority_state_is_valid(&config, &wrong_runtime));

        let mut wrong_head = actor.state.clone();
        wrong_head.private_agents[0].control_head = Some([0x59; 32]);
        assert!(!authority_state_is_valid(&config, &wrong_head));

        let mut wrong_sequence = actor.state.clone();
        wrong_sequence.private_agents[0].control_sequence = Some(1);
        assert!(!authority_state_is_valid(&config, &wrong_sequence));

        let mut wrong_member_set = actor.state.clone();
        wrong_member_set.private_agents[0].member_set[0] ^= 1;
        assert!(!authority_state_is_valid(&config, &wrong_member_set));

        let mut missing_member = actor.state.clone();
        missing_member.private_agents[0].members.pop();
        assert!(!authority_state_is_valid(&config, &missing_member));

        let mut rewritten_members = actor.state.clone();
        rewritten_members.private_agents[0].members = vec![descriptor.replicas[0].node.0];
        rewritten_members.private_agents[0].member_set =
            fixture_member_set(descriptor.replicas.iter().map(|replica| replica.node)).0;
        assert!(!authority_state_is_valid(&config, &rewritten_members));

        let mut duplicate_member = actor.state.clone();
        let member = duplicate_member.private_agents[0].members[0];
        duplicate_member.private_agents[0].members.push(member);
        assert!(!authority_state_is_valid(&config, &duplicate_member));

        let mut unsorted_members = actor.state.clone();
        unsorted_members.private_agents[0].members.swap(0, 1);
        assert!(!authority_state_is_valid(&config, &unsorted_members));

        let mut too_many_members = actor.state.clone();
        too_many_members.private_agents[0].members = (1..=MAX_PRIVATE_NODES + 1)
            .map(|ordinal| {
                let mut node = [0; 32];
                node[30..].copy_from_slice(&u16::try_from(ordinal).unwrap().to_be_bytes());
                node
            })
            .collect();
        assert!(!authority_state_is_valid(&config, &too_many_members));

        let mut wrong_exact_ack = actor.state.clone();
        wrong_exact_ack.private_agents[0]
            .application_ack_bytes
            .as_mut()
            .unwrap()[0] ^= 1;
        assert!(!authority_state_is_valid(&config, &wrong_exact_ack));

        let mut broken_chain = actor.state.clone();
        broken_chain.private_application_commitment[0] ^= 1;
        assert!(!authority_state_is_valid(&config, &broken_chain));

        let mut rewritten_audit = actor.state.clone();
        rewritten_audit.private_applications[0].control[0] ^= 1;
        rewritten_audit.private_application_commitment =
            initial_private_application_commitment(config).0;
        for record in &rewritten_audit.private_applications {
            rewritten_audit.private_application_commitment = private_application_commitment(
                Hash(rewritten_audit.private_application_commitment),
                record,
            )
            .0;
        }
        assert!(!authority_state_is_valid(&config, &rewritten_audit));

        let mut rewritten_source = actor.state.clone();
        rewritten_source.latest_operation_acks[0].operation_call[0] ^= 1;
        assert!(refresh_state_integrity_commitment(
            &config,
            &mut rewritten_source
        ));
        assert!(!authority_state_is_valid(&config, &rewritten_source));

        let mut rewritten_reservation = actor.state.clone();
        rewritten_reservation.latest_operation_acks[0].private_application_invocation = None;
        assert!(refresh_state_integrity_commitment(
            &config,
            &mut rewritten_reservation
        ));
        assert!(!authority_state_is_valid(&config, &rewritten_reservation));

        let mut rewritten_target = actor.state.clone();
        rewritten_target.latest_operation_acks[0]
            .private_operation
            .as_mut()
            .unwrap()
            .node = Some([0xfe; 32]);
        assert!(refresh_state_integrity_commitment(
            &config,
            &mut rewritten_target
        ));
        assert!(!authority_state_is_valid(&config, &rewritten_target));

        let mut collision = actor.state.clone();
        collision.latest_operation_acks[0].private_application_invocation =
            Some(collision.latest_operation_acks[0].authorization_invocation);
        assert!(refresh_state_integrity_commitment(&config, &mut collision));
        assert!(!authority_state_is_valid(&config, &collision));

        let mut rewritten_application_invocation = actor.state.clone();
        rewritten_application_invocation.private_applications[0].application_invocation =
            rewritten_application_invocation.private_applications[0].authorization_invocation;
        assert!(!authority_state_is_valid(
            &config,
            &rewritten_application_invocation
        ));

        assert_eq!(MAX_PRIVATE_APPLICATION_RECORDS, 4_096);
        let mut overflow = actor.state.clone();
        overflow.private_applications =
            vec![actor.state.private_applications[0].clone(); MAX_PRIVATE_APPLICATION_RECORDS + 1];
        assert!(!authority_state_is_valid(&config, &overflow));
    }

    #[test]
    fn general_operation_compacts_beyond_the_legacy_retry_bound() {
        let config = configuration();
        let key = signing(0x21);
        let mut actor = SystemAuthority::new(&config.encode());
        let catalog = install_catalog_projection(&mut actor);
        let mut first_call = None;
        let mut first_ack = None;
        let mut latest_call = None;
        let mut latest_ack = None;
        let mut compact_size = 0;

        for ordinal in 0..=MAX_EXACT_RETRY_RECORDS {
            let mut call = invoke_operation_call(
                config,
                &key,
                ADMIN_PRINCIPAL,
                Some(ADMIN_NODE),
                0xd5,
                0xd6,
                system_target(config),
                &catalog,
            );
            let AuthorityOperationIntent::InvokeActor { work, .. } = &mut call.intent else {
                unreachable!()
            };
            *work = Hash::digest(
                b"vos/test/system-authority/compacted-operation/v1",
                &[&u64::try_from(ordinal).unwrap().to_le_bytes()],
            );
            prepare_operation_call(&actor, &mut call, &key);
            let (approval, ack) = authorize_and_issue_operation(&mut actor, &call);
            if ordinal == 0 {
                compact_size = vos::rkyv::to_bytes::<vos::rkyv::rancor::Error>(&actor.state)
                    .unwrap()
                    .len();
                first_call = Some(call.clone());
                first_ack = Some(ack.clone());
            }
            latest_call = Some(call);
            latest_ack = Some(ack);
            assert_eq!(approval.request_sequence.get(), ordinal as u64 + 1);
            assert_eq!(actor.state.latest_operation_acks.len(), 1);
            assert!(actor.state.operation_retries.is_empty());
        }

        let credential = credential_index(
            &actor.state,
            CredentialId::of_public_key(&key.verifying_key().to_bytes()),
        )
        .unwrap();
        assert_eq!(
            actor.state.credentials[credential].operation_request_high_water,
            u64::try_from(MAX_EXACT_RETRY_RECORDS).unwrap() + 1
        );
        assert!(authority_state_is_valid(&config, &actor.state));
        let final_size = vos::rkyv::to_bytes::<vos::rkyv::rancor::Error>(&actor.state)
            .unwrap()
            .len();
        assert!(final_size <= compact_size + 64);

        let linear = <SystemAuthority as vos::Actor>::__save_agent_lane(&actor, StateLane::Linear);
        let mut restarted = <SystemAuthority as vos::Actor>::__load_agent_state(
            Some(&config.encode()),
            Some(&linear),
            None,
            None,
        )
        .expect("compacted latest AOI1 must restart");
        let before = restarted.state.clone();
        assert!(dispatch_operation(&mut restarted, &first_call.unwrap()).is_empty());
        assert!(!dispatch_operation_ack(&mut restarted, &first_ack.unwrap()));
        assert_eq!(restarted.state, before);
        assert!(dispatch_operation_ack(&mut restarted, &latest_ack.unwrap()));
        assert_eq!(restarted.state, before);
        assert!(dispatch_operation(&mut restarted, &latest_call.unwrap()).is_empty());
        assert_eq!(restarted.state, before);
    }

    #[test]
    fn built_in_roles_enforce_the_creation_profile_lattice() {
        let cases = [
            (BuiltinPrincipalRole::Member, AgentProfile::Private, true),
            (BuiltinPrincipalRole::Member, AgentProfile::Local, false),
            (BuiltinPrincipalRole::Member, AgentProfile::Shared, false),
            (BuiltinPrincipalRole::Developer, AgentProfile::Private, true),
            (BuiltinPrincipalRole::Developer, AgentProfile::Local, true),
            (BuiltinPrincipalRole::Developer, AgentProfile::Shared, false),
            (BuiltinPrincipalRole::Admin, AgentProfile::Private, true),
            (BuiltinPrincipalRole::Admin, AgentProfile::Local, true),
            (BuiltinPrincipalRole::Admin, AgentProfile::Shared, true),
        ];

        for (ordinal, (role, profile, allowed)) in cases.into_iter().enumerate() {
            let config = configuration();
            let key = signing(0x30 + ordinal as u8);
            let principal = PrincipalId([0x50 + ordinal as u8; 32]);
            let node = node_for_principal(config, principal);
            let mut actor = actor();
            enroll(&mut actor, &key, principal, node, role);
            let call = create_call(
                config,
                &key,
                principal,
                Some(node),
                20 + ordinal as u8,
                profile,
                40 + ordinal as u8,
            );
            let before = actor.state.clone();
            let reply = dispatch(&mut actor, &call);
            assert_eq!(!reply.is_empty(), allowed, "{role:?} / {profile:?}");
            if allowed {
                let approval = ManagementApproval::decode(&reply).unwrap();
                assert!(approval.matches_call(&call));
                assert_eq!(approval.valid_from, OBSERVED_SLOT);
                assert_eq!(
                    approval.expires_at,
                    OBSERVED_SLOT + MAX_APPROVAL_VALIDITY_SLOTS
                );
                assert_eq!(actor.state.managed_agents, vec![root_managed_agent(config)]);
                assert!(matches!(
                    actor.state.retries.last().map(|record| &record.effect),
                    Some(PendingManagementEffect::Create(_))
                ));
            } else {
                assert_eq!(actor.state, before);
            }
        }
    }

    #[test]
    fn only_admin_may_create_for_another_principal() {
        let config = configuration();
        let beneficiary = PrincipalId([0x81; 32]);
        let descriptor = descriptor(config, beneficiary, AgentProfile::Private, 0x82);
        let managed = target_for(&descriptor);

        let member_key = signing(0x83);
        let member = PrincipalId([0x84; 32]);
        let member_node = node_for_principal(config, member);
        let mut actor = actor();
        enroll(
            &mut actor,
            &signing(0x80),
            beneficiary,
            node_for_principal(config, beneficiary),
            BuiltinPrincipalRole::Member,
        );
        enroll(
            &mut actor,
            &member_key,
            member,
            member_node,
            BuiltinPrincipalRole::Member,
        );
        let member_call = credential_call(
            config,
            &member_key,
            member,
            Some(member_node),
            0x86,
            managed,
            ManagementRequest::Create(Box::new(descriptor.clone())),
        );
        let before = actor.state.clone();
        assert!(dispatch(&mut actor, &member_call).is_empty());
        assert_eq!(actor.state, before);

        let admin_call = credential_call(
            config,
            &signing(0x21),
            ADMIN_PRINCIPAL,
            Some(ADMIN_NODE),
            0x87,
            managed,
            ManagementRequest::Create(Box::new(descriptor)),
        );
        assert!(!dispatch(&mut actor, &admin_call).is_empty());
    }

    #[test]
    fn admin_cannot_create_an_agent_owned_by_an_unenrolled_principal() {
        let config = configuration();
        let owner = PrincipalId([0x88; 32]);
        let descriptor = descriptor(config, owner, AgentProfile::Private, 0x89);
        let call = credential_call(
            config,
            &signing(0x21),
            ADMIN_PRINCIPAL,
            Some(ADMIN_NODE),
            0x8a,
            target_for(&descriptor),
            ManagementRequest::Create(Box::new(descriptor)),
        );
        let mut actor = actor();
        let before = actor.state.clone();
        assert!(dispatch(&mut actor, &call).is_empty());
        assert_eq!(actor.state, before);
    }

    #[test]
    fn lifecycle_requires_exact_managed_row_and_owner_or_admin() {
        let config = configuration();
        let owner_key = signing(0x91);
        let owner = PrincipalId([0x92; 32]);
        let owner_node = node_for_principal(config, owner);
        let outsider_key = signing(0x94);
        let outsider = PrincipalId([0x95; 32]);
        let outsider_node = node_for_principal(config, outsider);
        let managed_descriptor = descriptor(config, owner, AgentProfile::Private, 0x97);
        let managed = target_for(&managed_descriptor);

        let mut actor = actor();
        enroll(
            &mut actor,
            &owner_key,
            owner,
            owner_node,
            BuiltinPrincipalRole::Member,
        );
        enroll(
            &mut actor,
            &outsider_key,
            outsider,
            outsider_node,
            BuiltinPrincipalRole::Developer,
        );
        insert_live(&mut actor, &managed_descriptor);

        let install = actor_install(managed.agent, "owned", 0x98);
        let mut install_call = credential_call(
            config,
            &signing(0x21),
            ADMIN_PRINCIPAL,
            Some(ADMIN_NODE),
            0x99,
            managed,
            ManagementRequest::Install(Box::new(install.clone())),
        );
        prepare_management_call(&actor, &mut install_call, &signing(0x21));
        let install_approval = ManagementApproval::decode(&dispatch(&mut actor, &install_call))
            .expect("admin installs the owned actor");
        assert!(dispatch_application_ack(
            &mut actor,
            &install_call,
            &install_approval,
        ));
        let request = ManagementRequest::Suspend {
            actor: install.entry.actor,
            expected_deployment: install.entry.deployment,
        };

        let outsider_call = credential_call(
            config,
            &outsider_key,
            outsider,
            Some(outsider_node),
            0xa1,
            managed,
            request.clone(),
        );
        let before = actor.state.clone();
        assert!(dispatch(&mut actor, &outsider_call).is_empty());
        assert_eq!(actor.state, before);

        let owner_call = credential_call(
            config,
            &owner_key,
            owner,
            Some(owner_node),
            0xa0,
            managed,
            request.clone(),
        );
        let owner_approval = ManagementApproval::decode(&dispatch(&mut actor, &owner_call))
            .expect("owner may suspend an exactly projected actor");
        assert!(dispatch_application_ack(
            &mut actor,
            &owner_call,
            &owner_approval,
        ));

        let mut admin_call = credential_call(
            config,
            &signing(0x21),
            ADMIN_PRINCIPAL,
            Some(ADMIN_NODE),
            0xa2,
            managed,
            ManagementRequest::Resume {
                actor: install.entry.actor,
                expected_deployment: install.entry.deployment,
            },
        );
        prepare_management_call(&actor, &mut admin_call, &signing(0x21));
        let admin_approval = ManagementApproval::decode(&dispatch(&mut actor, &admin_call))
            .expect("admin may resume an exactly projected actor");
        assert!(dispatch_application_ack(
            &mut actor,
            &admin_call,
            &admin_approval,
        ));

        let mismatched_target = vos::agent_sdk::authority::ManagedAgentTarget {
            runtime_deployment: DeploymentId([0xaa; 32]),
            ..managed
        };
        let mut mismatch = credential_call(
            config,
            &signing(0x21),
            ADMIN_PRINCIPAL,
            Some(ADMIN_NODE),
            0xa3,
            mismatched_target,
            request,
        );
        prepare_management_call(&actor, &mut mismatch, &signing(0x21));
        let before = actor.state.clone();
        assert!(dispatch(&mut actor, &mismatch).is_empty());
        assert_eq!(actor.state, before);
    }

    #[test]
    fn exact_binding_cannot_be_reinterpreted_under_another_policy() {
        let config = configuration();
        let key = signing(0x21);
        let mut call = create_call(
            config,
            &key,
            ADMIN_PRINCIPAL,
            Some(ADMIN_NODE),
            0xb1,
            AgentProfile::Local,
            0xb2,
        );
        call.authority.binding.policy = Hash([0xb3; 32]);
        let ManagementAuthorizationPlan::Create {
            descriptor,
            replicas,
            descriptor_commitment,
        } = &mut call.plan
        else {
            unreachable!()
        };
        descriptor.authority = call.authority.binding;
        *descriptor_commitment = descriptor
            .with_replicas(
                replicas
                    .iter()
                    .map(|slot| AgentReplica {
                        node: slot.node,
                        principal: descriptor.identity.owner,
                        role: slot.role,
                    })
                    .collect(),
            )
            .commitment();
        refresh_management_call(&mut call, &key);
        assert_eq!(call.validate_shape(), Ok(()));

        let mut actor = actor();
        let before = actor.state.clone();
        assert!(dispatch(&mut actor, &call).is_empty());
        assert_eq!(actor.state, before);
    }

    #[test]
    fn exact_retry_is_byte_identical_and_invocation_conflicts_fail_closed() {
        let config = configuration();
        let key = signing(0x21);
        let call = create_call(
            config,
            &key,
            ADMIN_PRINCIPAL,
            Some(ADMIN_NODE),
            0xc1,
            AgentProfile::Local,
            0xc2,
        );
        let mut actor = actor();
        let first = dispatch(&mut actor, &call);
        assert!(!first.is_empty());
        let after_first = actor.state.clone();
        let retry = dispatch(&mut actor, &call);
        assert_eq!(retry, first);
        assert_eq!(actor.state, after_first);

        let mut conflict = call;
        conflict.requested_expires_at -= 1;
        refresh_management_call(&mut conflict, &key);
        let before_conflict = actor.state.clone();
        assert!(dispatch(&mut actor, &conflict).is_empty());
        assert_eq!(actor.state, before_conflict);
    }

    #[test]
    fn full_width_credential_principal_and_node_ids_do_not_alias() {
        let (left_key, right_key) = credential_prefix_collision();
        let left_credential = CredentialId::of_public_key(&left_key.verifying_key().to_bytes());
        let right_credential = CredentialId::of_public_key(&right_key.verifying_key().to_bytes());
        assert_eq!(&left_credential.0[..2], &right_credential.0[..2]);
        assert_ne!(left_credential, right_credential);

        let mut left_principal_bytes = [0xdd; 32];
        left_principal_bytes[31] = 1;
        let mut right_principal_bytes = left_principal_bytes;
        right_principal_bytes[31] = 2;
        let left_principal = PrincipalId(left_principal_bytes);
        let right_principal = PrincipalId(right_principal_bytes);
        let config = configuration();
        let left_node_enrollment =
            signed_node_enrollment(SpaceId(config.space), left_principal, 0xee);
        let right_node_enrollment =
            signed_node_enrollment(SpaceId(config.space), right_principal, 0xef);
        let left_node = left_node_enrollment.node;
        let right_node = right_node_enrollment.node;
        assert_ne!(left_node, right_node);
        let mut actor = actor();
        enroll_exact(
            &mut actor,
            &left_key,
            left_node_enrollment,
            BuiltinPrincipalRole::Member,
        );
        enroll_exact(
            &mut actor,
            &right_key,
            right_node_enrollment,
            BuiltinPrincipalRole::Member,
        );
        let mut left_descriptor = descriptor(config, left_principal, AgentProfile::Private, 0xd2);
        left_descriptor.replicas[0].node = left_node;
        let left = credential_call(
            config,
            &left_key,
            left_principal,
            Some(left_node),
            0xd1,
            target_for(&left_descriptor),
            ManagementRequest::Create(Box::new(left_descriptor)),
        );
        let mut right_descriptor = descriptor(config, right_principal, AgentProfile::Private, 0xd4);
        right_descriptor.replicas[0].node = right_node;
        let right = credential_call(
            config,
            &right_key,
            right_principal,
            Some(right_node),
            0xd3,
            target_for(&right_descriptor),
            ManagementRequest::Create(Box::new(right_descriptor)),
        );
        assert!(!dispatch(&mut actor, &left).is_empty());
        assert!(!dispatch(&mut actor, &right).is_empty());

        let mut confused = right;
        confused.authenticated_node = Some(left_node);
        refresh_management_call(&mut confused, &right_key);
        let before = actor.state.clone();
        assert!(dispatch(&mut actor, &confused).is_empty());
        assert_eq!(actor.state, before);
    }

    fn credential_prefix_collision() -> (SigningKey, SigningKey) {
        let mut seen = BTreeMap::<[u8; 2], [u8; 32]>::new();
        for ordinal in 1u32..10_000 {
            let mut seed = [0u8; 32];
            seed[..4].copy_from_slice(&ordinal.to_le_bytes());
            seed[31] = 0x5a;
            let key = SigningKey::from_bytes(&seed);
            let credential = CredentialId::of_public_key(&key.verifying_key().to_bytes());
            let prefix = [credential.0[0], credential.0[1]];
            if let Some(previous) = seen.insert(prefix, seed) {
                let previous = SigningKey::from_bytes(&previous);
                if previous.verifying_key() != key.verifying_key() {
                    return (previous, key);
                }
            }
        }
        panic!("deterministic fixture failed to find a two-byte credential prefix collision")
    }

    #[test]
    fn finalized_management_compacts_beyond_four_thousand_lifecycle_operations() {
        let config = configuration();
        let mut actor = actor();
        let descriptor = descriptor(config, ADMIN_PRINCIPAL, AgentProfile::Local, 0xf1);
        insert_live(&mut actor, &descriptor);
        let managed = target_for(&descriptor);
        let install = actor_install(managed.agent, "compacted-worker", 0xf2);
        let install_call = credential_call(
            config,
            &signing(0x21),
            ADMIN_PRINCIPAL,
            Some(ADMIN_NODE),
            0xf0,
            managed,
            ManagementRequest::Install(Box::new(install.clone())),
        );
        let (_, _, first_ack) =
            record_fixture_finalized_management(&mut actor, install_call, &signing(0x21));
        let compact_size_after_first =
            vos::rkyv::to_bytes::<vos::rkyv::rancor::Error>(&actor.state)
                .unwrap()
                .len();

        // Model the 4,095 discarded exact predecessors directly. The durable
        // journal is their authenticity boundary; the actor state retains the
        // cumulative credential/global high-waters and their exact projected
        // effect. The final (4,096th) transition below is retained and fully
        // signed, then the complete compact image is validated once.
        let caller = credential_index(
            &actor.state,
            CredentialId::of_public_key(&signing(0x21).verifying_key().to_bytes()),
        )
        .unwrap();
        actor.state.credentials[caller].management_request_high_water += 4_095;
        actor.state.authorization_sequence += 4_095;
        actor.state.operation_retirement_floor += 4_095;
        let installed = managed_actor(&actor.state, managed.agent, install.entry.actor).unwrap();
        actor.state.managed_actors[installed].suspended = true;

        let final_call = credential_call(
            config,
            &signing(0x21),
            ADMIN_PRINCIPAL,
            Some(ADMIN_NODE),
            0xf3,
            managed,
            ManagementRequest::Resume {
                actor: install.entry.actor,
                expected_deployment: install.entry.deployment,
            },
        );
        let (latest_call, latest_approval, latest_ack) =
            record_fixture_finalized_management(&mut actor, final_call, &signing(0x21));
        assert!(refresh_state_integrity_commitment(
            &actor.configuration,
            &mut actor.state,
        ));
        assert!(authority_state_is_valid(&config, &actor.state));

        let credential = credential_index(
            &actor.state,
            CredentialId::of_public_key(&signing(0x21).verifying_key().to_bytes()),
        )
        .unwrap();
        assert_eq!(
            actor.state.credentials[credential].management_request_high_water, 4_098,
            "Create + Install + 4,096 finalized lifecycle calls share one monotonic credential clock",
        );
        assert_eq!(actor.state.authorization_sequence, 4_100);
        assert_eq!(actor.state.operation_retirement_floor, 4_100);
        assert!(actor.state.retries.is_empty());
        assert_eq!(actor.state.latest_management_acks.len(), 1);
        assert_eq!(
            actor.state.managed_actors
                [managed_actor(&actor.state, managed.agent, install.entry.actor).unwrap()]
            .suspended,
            false,
        );
        let final_size = vos::rkyv::to_bytes::<vos::rkyv::rancor::Error>(&actor.state)
            .unwrap()
            .len();
        assert!(final_size <= compact_size_after_first + 64);

        let completed = actor.state.clone();
        assert!(dispatch(&mut actor, &latest_call).is_empty());
        assert_ne!(latest_approval, Vec::<u8>::new());
        assert_eq!(actor.state, completed);
        assert!(dispatch_ack(&mut actor, &latest_ack));
        assert_eq!(actor.state, completed);
        assert!(!dispatch_ack(&mut actor, &first_ack));
        assert_eq!(actor.state, completed);

        let linear = <SystemAuthority as vos::Actor>::__save_agent_lane(&actor, StateLane::Linear);
        let restarted = <SystemAuthority as vos::Actor>::__load_agent_state(
            Some(&config.encode()),
            Some(&linear),
            None,
            None,
        )
        .expect("compacted lifecycle high-water must survive restart");
        assert_eq!(restarted.state, actor.state);
    }

    #[test]
    fn admin_latest_exact_result_survives_long_compacted_churn_and_restart() {
        let config = configuration();
        let key = signing(0x21);
        let principal = PrincipalId([0xf1; 32]);
        let first_call = admin_call(
            config,
            &key,
            ADMIN_PRINCIPAL,
            ADMIN_NODE,
            0xf0,
            1,
            AuthorityAdminOperation::EnrollPrincipal {
                principal,
                credential: enrollment(&signing(0xf2), AuthorityCredentialKind::Api),
            },
        );
        let mut actor = actor();
        let first_result = dispatch_admin(&mut actor, &first_call);
        assert!(!first_result.is_empty());
        let compact_size_after_first =
            vos::rkyv::to_bytes::<vos::rkyv::rancor::Error>(&actor.state)
                .unwrap()
                .len();
        for ordinal in 0..512_u64 {
            record_fixture_admin(
                &mut actor,
                InvocationId::ZERO,
                AuthorityAdminOperation::SetBuiltinRole {
                    principal,
                    role: if ordinal & 1 == 0 {
                        AuthorityBuiltinRole::Developer
                    } else {
                        AuthorityBuiltinRole::Member
                    },
                },
            );
        }
        assert!(refresh_state_integrity_commitment(
            &actor.configuration,
            &mut actor.state,
        ));
        assert!(authority_state_is_valid(&config, &actor.state));
        assert_eq!(actor.state.admin_retries.len(), 1);
        assert_eq!(actor.state.administration_generation, 514);
        let root_credential = credential_index(
            &actor.state,
            CredentialId::of_public_key(&key.verifying_key().to_bytes()),
        )
        .unwrap();
        assert_eq!(
            actor.state.credentials[root_credential].admin_request_high_water,
            513,
        );
        let final_size = vos::rkyv::to_bytes::<vos::rkyv::rancor::Error>(&actor.state)
            .unwrap()
            .len();
        assert!(final_size <= compact_size_after_first + 64);

        let latest = &actor.state.admin_retries[0];
        let latest_call = AuthorityAdminCall::decode(&latest.call_bytes).unwrap();
        let latest_result = latest.result_bytes.clone();
        let compacted = actor.state.clone();
        assert_eq!(dispatch_admin(&mut actor, &latest_call), latest_result);
        assert_eq!(actor.state, compacted);
        assert!(dispatch_admin(&mut actor, &first_call).is_empty());
        assert_eq!(actor.state, compacted);

        let linear = <SystemAuthority as vos::Actor>::__save_agent_lane(&actor, StateLane::Linear);
        let mut restarted = <SystemAuthority as vos::Actor>::__load_agent_state(
            Some(&config.encode()),
            Some(&linear),
            None,
            None,
        )
        .expect("compacted Admin high-water must survive restart");
        assert_eq!(dispatch_admin(&mut restarted, &latest_call), latest_result);
        assert_eq!(restarted.state, actor.state);
    }

    #[test]
    fn genesis_committee_query_uses_configured_authority_not_transport_key() {
        use vos::agent::committee::{AuthorityCommittee, AuthorityMemberRole};
        use vos::service::ServiceWire as _;
        let config = configuration();
        let actor = actor();
        let before = <SystemAuthority as vos::Actor>::__save_agent_lane(&actor, StateLane::Linear);
        let bytes = genesis_publication::signing_committee(&actor.configuration);
        let committee = AuthorityCommittee::decode(&bytes).unwrap();
        assert_eq!(committee.space().0, config.space);
        assert_eq!(committee.authority_binding().0, config.binding.sdk().commitment().0);
        assert_eq!(committee.epoch(), 1);
        assert_eq!(committee.previous_committee(), None);
        assert_eq!(committee.members().len(), 1);
        let member = &committee.members()[0];
        assert_eq!(member.role(), AuthorityMemberRole::Voter);
        assert_eq!(member.node().0, config.bootstrap_node);
        assert_eq!(*member.public_key(), config.bootstrap_credential_public_key);
        assert_ne!(*member.public_key(), config.bootstrap_node_transport_public_key);
        assert_eq!(bytes, genesis_publication::signing_committee(&actor.configuration));
        assert!(before == <SystemAuthority as vos::Actor>::__save_agent_lane(&actor, StateLane::Linear));
        let invalid = SystemAuthority::new(&[]);
        assert!(genesis_publication::signing_committee(&invalid.configuration).is_empty());
    }

    #[test]
    fn shared_create_budget_denies_atomically_and_recovers_after_ack() {
        let config = configuration();
        let mut actor = actor();
        let mut calls = Vec::new();
        for marker in 0x90u8..0xb0 {
            let key = signing(marker);
            let principal = PrincipalId([marker; 32]);
            let node = node_for_principal(config, principal);
            enroll(
                &mut actor,
                &key,
                principal,
                node,
                BuiltinPrincipalRole::Admin,
            );
            calls.push(create_call(
                config,
                &key,
                principal,
                Some(node),
                marker,
                AgentProfile::Shared,
                marker.wrapping_add(0x10),
            ));
        }
        let mut approvals = Vec::new();
        let mut denied = None;
        for (index, call) in calls.iter().enumerate() {
            let before = actor.state.clone();
            let reply = dispatch(&mut actor, call);
            if reply.is_empty() {
                assert_eq!(actor.state, before, "capacity denial must be atomic");
                denied = Some(index);
                break;
            }
            approvals.push(reply);
        }
        let denied = denied.expect("pending reservations must exhaust the byte budget");
        assert!(denied > 1);
        assert!(actor.state.retries.len() < MAX_EXACT_RETRY_RECORDS);
        assert!(live_and_pending_agent_count(&actor.state) < MAX_MANAGED_AGENTS);
        let archived = vos::rkyv::to_bytes::<vos::rkyv::rancor::Error>(&actor.state)
            .unwrap()
            .len();
        let publication = genesis_publication::reserved_publication_bytes(&actor.state).unwrap();
        let terminal = genesis_publication::reserved_terminal_bytes(&actor.state).unwrap();
        assert!(archived + publication + terminal <= MAX_RUNTIME_STATE_BYTES);
        println!(
            "Shared Create capacity: admitted={denied} archived={archived} publication_reserved={publication} terminal_reserved={terminal}"
        );
        let linear = <SystemAuthority as vos::Actor>::__save_agent_lane(&actor, StateLane::Linear);
        let mut restarted = <SystemAuthority as vos::Actor>::__load_agent_state(
            Some(&config.encode()),
            Some(&linear),
            None,
            None,
        )
        .expect("capacity-limited state must remain restartable");
        assert_eq!(restarted.state, actor.state);
        assert!(dispatch(&mut restarted, &calls[denied]).is_empty());
        assert_eq!(restarted.state, actor.state);
        assert_eq!(dispatch(&mut restarted, &calls[0]), approvals[0]);
        let approval = ManagementApproval::decode(&approvals[0]).unwrap();
        assert!(dispatch_application_ack(
            &mut restarted,
            &calls[0],
            &approval
        ));
        assert!(!dispatch(&mut restarted, &calls[denied]).is_empty());
        assert!(authority_state_is_valid(&config, &restarted.state));
    }

    #[test]
    fn shared_create_reservations_accumulate_and_release_independently() {
        let config = configuration();
        let mut actor = actor();
        let mut calls = Vec::new();
        for marker in [0x51, 0x52] {
            let key = signing(marker);
            let principal = PrincipalId([marker; 32]);
            let node = node_for_principal(config, principal);
            enroll(
                &mut actor,
                &key,
                principal,
                node,
                BuiltinPrincipalRole::Admin,
            );
            calls.push(create_call(
                config,
                &key,
                principal,
                Some(node),
                marker,
                AgentProfile::Shared,
                marker.wrapping_add(0x10),
            ));
        }
        let first = dispatch(&mut actor, &calls[0]);
        assert!(!first.is_empty());
        let publication = genesis_publication::reserved_publication_bytes(&actor.state).unwrap();
        let terminal = genesis_publication::reserved_terminal_bytes(&actor.state).unwrap();
        assert!(publication > 0 && terminal > 0);
        let second = dispatch(&mut actor, &calls[1]);
        assert!(!second.is_empty());
        assert_eq!(actor.state.retries.len(), 2);
        // Equal-shape descriptors and signed envelopes have equal reservation
        // sizes despite independently authenticated owners and credentials.
        assert_eq!(
            genesis_publication::reserved_publication_bytes(&actor.state),
            Some(2 * publication)
        );
        assert_eq!(
            genesis_publication::reserved_terminal_bytes(&actor.state),
            Some(2 * terminal)
        );
        let budget_edge = MAX_RUNTIME_STATE_BYTES - 2 * (publication + terminal);
        assert!(genesis_publication::state_bytes_fit(
            &actor.state,
            budget_edge
        ));
        assert!(!genesis_publication::state_bytes_fit(
            &actor.state,
            budget_edge + 1
        ));
        let linear = <SystemAuthority as vos::Actor>::__save_agent_lane(&actor, StateLane::Linear);
        let mut restarted = <SystemAuthority as vos::Actor>::__load_agent_state(
            Some(&config.encode()),
            Some(&linear),
            None,
            None,
        )
        .expect("multiple pending reservations must survive restart");
        assert_eq!(restarted.state, actor.state);
        assert_eq!(dispatch(&mut restarted, &calls[0]), first);
        assert_eq!(dispatch(&mut restarted, &calls[1]), second);
        let approval = ManagementApproval::decode(&first).unwrap();
        assert!(dispatch_application_ack(
            &mut restarted,
            &calls[0],
            &approval
        ));
        assert_eq!(restarted.state.retries.len(), 1);
        assert_eq!(
            genesis_publication::reserved_publication_bytes(&restarted.state),
            Some(publication)
        );
        assert_eq!(
            genesis_publication::reserved_terminal_bytes(&restarted.state),
            Some(terminal)
        );
        assert_eq!(dispatch(&mut restarted, &calls[1]), second);
        let approval = ManagementApproval::decode(&second).unwrap();
        assert!(dispatch_application_ack(
            &mut restarted,
            &calls[1],
            &approval
        ));
        assert!(restarted.state.retries.is_empty());
        assert_eq!(
            genesis_publication::reserved_publication_bytes(&restarted.state),
            Some(0)
        );
        assert_eq!(
            genesis_publication::reserved_terminal_bytes(&restarted.state),
            Some(0)
        );
        assert!(authority_state_is_valid(&config, &restarted.state));
    }

    #[test]
    fn signed_genesis_publication_survives_restart_and_expired_exact_retry() {
        exercise_signed_genesis_publication(None);
    }

    #[test]
    fn node_mutation_rows_and_header_survive_restart_and_exact_retry() {
        exercise_node_mutations(None, 1);
    }

    #[test]
    fn node_mutation_at_declared_capacity_preserves_complete_state() {
        exercise_node_mutations(None, MAX_AUTHORITY_NODES - 1);
    }

    #[test]
    #[ignore = "exports an explicit signed fixture for compiled Authority node mutations"]
    fn export_signed_node_mutation_fixture() {
        let directory = std::env::var("AUTHORITY_NODE_FIXTURE").expect("set new fixture directory");
        std::fs::create_dir(&directory).expect("fixture directory must not exist");
        let initial_nodes = std::env::var("AUTHORITY_NODE_INITIAL_COUNT")
            .map(|value| value.parse::<usize>().expect("numeric initial count"))
            .unwrap_or(1);
        exercise_node_mutations(Some(std::path::Path::new(&directory)), initial_nodes);
    }

    fn exercise_node_mutations(export: Option<&std::path::Path>, initial_nodes: usize) {
        use vos::{Actor, Encode, storage::mock};
        assert!((1..MAX_AUTHORITY_NODES).contains(&initial_nodes));
        let mut actor = actor();
        let config = actor.configuration;
        for ordinal in 0..initial_nodes - 1 {
            let mut seed = [0x53; 32];
            seed[..8].copy_from_slice(&(ordinal as u64).to_le_bytes());
            let transport_key = SigningKey::from_bytes(&seed);
            let mut enrollment = NodeEncryptionEnrollment::from_keys(
                SpaceId(config.space), ADMIN_PRINCIPAL, transport_key.verifying_key().to_bytes(),
                [0x42; 32], [1; PRIVATE_SIGNATURE_BYTES],
            );
            resign_node_enrollment(&mut enrollment, &transport_key);
            assert!(enrollment.verify_with(&Ed25519CredentialVerifier));
            assert!(insert_enrolled_node(&mut actor.state, enrollment));
        }
        if initial_nodes != 1 { assert!(refresh_state_integrity_commitment(&config, &mut actor.state)); }
        assert!(authority_state_is_valid(&config, &actor.state));
        assert_eq!(actor.state.nodes.len(), initial_nodes);
        mock::commit_dispatch();
        let initial_rows = mock::snapshot();
        let key = signing(0x21);
        let enrollment = signed_node_enrollment(SpaceId(config.space), ADMIN_PRINCIPAL, 0x32);
        let call = admin_call(config, &key, ADMIN_PRINCIPAL, ADMIN_NODE, 0x91, 1,
            AuthorityAdminOperation::EnrollNode { enrollment });
        let mut bad = call.clone();
        bad.signature[0] ^= 1;
        let initial_linear = actor.__save_agent_lane(StateLane::Linear);
        assert!(dispatch_admin(&mut actor, &bad).is_empty());
        assert_eq!(actor.__save_agent_lane(StateLane::Linear), initial_linear);
        mock::commit_dispatch();
        assert_eq!(mock::snapshot(), initial_rows, "refusal must not change or materialize rows");
        let enrolled_reply = dispatch_admin(&mut actor, &call);
        assert!(!enrolled_reply.is_empty());
        assert_eq!(actor.state.nodes.len(), initial_nodes + 1);
        let enrolled_linear = actor.__save_agent_lane(StateLane::Linear);
        mock::commit_dispatch();
        let enrolled_rows = mock::snapshot();
        assert!(!enrolled_rows.is_empty());
        actor = <SystemAuthority as Actor>::__load_agent_state(
            Some(&config.encode()), Some(&enrolled_linear), None, None,
        ).unwrap();
        assert_eq!(dispatch_admin(&mut actor, &call), enrolled_reply);
        assert!(dispatch_admin(&mut actor, &bad).is_empty());
        assert_eq!(actor.__save_agent_lane(StateLane::Linear), enrolled_linear);
        mock::commit_dispatch();
        assert_eq!(mock::snapshot(), enrolled_rows);
        let mut removal = admin_call(config, &key, ADMIN_PRINCIPAL, ADMIN_NODE, 0x92, 2,
            AuthorityAdminOperation::UnbindNodeOwner { node: enrollment.node, owner: ADMIN_PRINCIPAL });
        prepare_admin_call(&actor, &mut removal, &key);
        let removed_reply = dispatch_admin(&mut actor, &removal);
        assert!(!removed_reply.is_empty());
        let removed_linear = actor.__save_agent_lane(StateLane::Linear);
        mock::commit_dispatch();
        let removed_rows = mock::snapshot();
        assert_ne!(removed_rows, enrolled_rows);
        actor = <SystemAuthority as Actor>::__load_agent_state(
            Some(&config.encode()), Some(&removed_linear), None, None,
        ).unwrap();
        assert!(enrolled_node(&actor.state, enrollment.node).is_none());
        assert_eq!(actor.state.nodes.len(), initial_nodes);
        assert!(enrolled_node(&actor.state, ADMIN_NODE).is_some());
        assert_eq!(dispatch_admin(&mut actor, &removal), removed_reply);
        assert_eq!(actor.__save_agent_lane(StateLane::Linear), removed_linear);
        mock::commit_dispatch();
        assert_eq!(mock::snapshot(), removed_rows);
        if let Some(directory) = export {
            use std::io::Write as _;
            for (name, bytes) in [
                ("configuration", config.encode()),
                ("initial-linear", initial_linear),
                ("initial-rows", initial_rows.encode()),
                ("enrolled-linear", enrolled_linear), ("removed-linear", removed_linear),
                ("enrolled-rows", enrolled_rows.encode()), ("removed-rows", removed_rows.encode()),
                ("enroll-call", call.encode().unwrap()), ("bad-call", bad.encode().unwrap()),
                ("remove-call", removal.encode().unwrap()),
                ("enroll-context", admin_context(&call).encode().unwrap()),
                ("remove-context", admin_context(&removal).encode().unwrap()),
                ("enroll-reply", enrolled_reply), ("remove-reply", removed_reply),
            ] {
                std::fs::OpenOptions::new().write(true).create_new(true).open(directory.join(name))
                    .unwrap().write_all(&bytes).unwrap();
            }
        }
        mock::reset();
    }

    #[test]
    #[ignore = "exports an explicit signed fixture for compiled Authority guest execution"]
    fn export_signed_genesis_publication_fixture() {
        let directory = std::env::var("AUTHORITY_PUBLICATION_FIXTURE")
            .expect("set AUTHORITY_PUBLICATION_FIXTURE to a new disk-backed directory");
        std::fs::create_dir(&directory).expect("fixture directory must not already exist");
        exercise_signed_genesis_publication(Some(std::path::Path::new(&directory)));
    }

    fn exercise_signed_genesis_publication(export: Option<&std::path::Path>) {
        vos::storage::mock::reset();
        use vos::agent::committee::{
            AuthorityCommittee, AuthorityCommitteeMember, AuthorityMemberRole,
            AuthorityQuorumCertificate, AuthoritySignature,
        };
        use vos::agent::genesis::*;
        use vos::agent::journal::{
            AgentJournalGenesisId, ReplayInput, ReplayOperation, RuntimeBinding,
            system_genesis_artifact_closure_commitment,
        };
        use vos::service::{self as host, ServiceWire as _};

        let mut config = configuration();
        config.binding.initial_epoch = 1;
        // Ordinary replicas belong to the enrolled owner, independently of
        // the node's authenticated transport key. Do not rewrite bootstrap
        // ownership to make the genesis roster pass transport validation.
        let owner = PrincipalId(config.bootstrap_principal);
        assert_ne!(owner.0, config.bootstrap_replica_principal);
        assert!(config.is_valid());
        let mut actor = SystemAuthority::new(&config.encode());
        let mut descriptor = descriptor(config, owner, AgentProfile::Shared, 0xe2);
        // Materialize a genuine row-backed table before exporting the fixture,
        // so physical publication must read persisted certificates, not only
        // the constructor's pending bootstrap seed.
        let additional = signed_node_enrollment(SpaceId(config.space), owner, 0x32);
        assert!(additional.verify_with(&Ed25519CredentialVerifier));
        assert!(insert_enrolled_node(&mut actor.state, additional));
        assert!(refresh_state_integrity_commitment(&config, &mut actor.state));
        vos::storage::mock::commit_dispatch();
        descriptor.replicas[0].node = NodeId(config.bootstrap_node);
        assert!(authority_state_is_valid(&config, &actor.state));
        let request = ManagementRequest::Create(Box::new(descriptor.clone()));
        let call = credential_call(
            config,
            &signing(0x21),
            owner,
            Some(ADMIN_NODE),
            0xe1,
            target_for(&descriptor),
            request.clone(),
        );
        let approval_bytes = dispatch(&mut actor, &call);
        assert!(
            !approval_bytes.is_empty(),
            "fixture Shared Create must be authorized"
        );
        let approval = ManagementApproval::decode(&approval_bytes).unwrap();
        let receipt = receipt_for(config, &approval, 7);
        let space = host::SpaceId(config.space);
        let agent = host::AgentId(descriptor.identity.agent.0);
        let runtime = RuntimeBinding {
            space,
            agent,
            deployment: host::DeploymentId(descriptor.identity.runtime_deployment.0),
            program: host::ProgramId(descriptor.identity.runtime_program.0),
            producer: host::ProducerId(descriptor.identity.runtime_producer.0),
            package: host::BlobRef {
                hash: host::Hash(descriptor.runtime_package.hash.0),
                len: descriptor.runtime_package.len,
            },
            runtime_abi: vos::agent::RUNTIME_ABI_ID,
            execution_semantics: vos::agent::EXECUTION_SEMANTICS_ID,
        };
        let catalog = vec![runtime.package.clone()];
        // The test signs a synthetic post-state claim, not a replay proof.
        let expectations = AgentGenesisExpectations::new(
            runtime.commitment(),
            host::Hash(request.commitment().0),
            host::Hash([0xe5; 32]),
            system_genesis_artifact_closure_commitment(&catalog).unwrap(),
            7,
        )
        .unwrap();
        let proposal = AgentGenesisProposal::new(
            AgentGenesisLocator { space, agent },
            ReplayInput {
                runtime,
                operation: ReplayOperation::CleanManage {
                    request,
                    authority: receipt,
                    observed_slot: OBSERVED_SLOT,
                },
            },
            expectations,
            catalog,
        )
        .unwrap();
        let peer = config.bootstrap_node_transport_peer_id.to_vec();
        let replicas = AgentReplicaCommittee::new(
            space,
            agent,
            vos::agent::AgentProfile::Shared,
            vec![
                AgentReplicaMember::new(
                    vos::agent::AgentReplica {
                        node: host::NodeId(config.bootstrap_node),
                        principal: host::PrincipalId(owner.0),
                        role: vos::agent::ReplicaRole::Voter,
                    },
                    peer.clone(),
                    config.bootstrap_node_transport_public_key,
                    Some(derive_replica_raft_slot(&peer)),
                )
                .unwrap(),
            ],
        )
        .unwrap();
        let member = AuthorityCommitteeMember::new(
            host::NodeId(config.bootstrap_node),
            config.bootstrap_credential_public_key,
            AuthorityMemberRole::Voter,
        )
        .unwrap();
        let signer = member.signer();
        let committee = AuthorityCommittee::new(
            space,
            host::Hash(config.binding.sdk().commitment().0),
            1,
            None,
            vec![member],
        )
        .unwrap();
        let claim = AgentGenesisClaim::new(
            host::AgentId(config.system_agent),
            AgentJournalGenesisId::new([0xe6; 32]),
            AgentGenesisAdmissionId::from_bytes([0xe7; 32]),
            &proposal,
            &replicas,
        )
        .unwrap();
        let message = AuthorityQuorumCertificate::signing_message(
            committee.authority_binding(),
            committee.epoch(),
            committee.commitment(),
            claim.authority_claim(),
        );
        let qc = AuthorityQuorumCertificate::new(
            &committee,
            claim.authority_claim(),
            vec![
                AuthoritySignature::new(signer, signing(0x21).sign(&message.0).to_bytes()).unwrap(),
            ],
        )
        .unwrap();
        let evidence = AgentGenesisEvidence::new(claim, qc).unwrap();
        let decision = AgentGenesisDecision::new(&proposal, &replicas, &evidence).unwrap();
        let provision = AgentGenesisProvision::new(proposal, replicas, evidence, decision).unwrap();
        let bytes = provision.encode();
        let expected = provision.decision().encode();
        let provision_ref = vos::agent_sdk::BlobRef::of_bytes(&bytes);
        let mut context = context(&call);
        context.invocation = provision.publication_invocation(call.invocation).unwrap();
        let before = actor.state.clone();
        let mut wrong_actor = context;
        wrong_actor.actor = ActorId([0xfa; 32]);
        let mut wrong_mode = context;
        wrong_mode.mode = MethodMode::Query;
        let mut wrong_invocation = context;
        wrong_invocation.invocation = InvocationId([0xfb; 32]);
        let mut expired = context;
        expired.observed_slot = approval.expires_at + 1;
        for rejected in [wrong_actor, wrong_mode, wrong_invocation, expired] {
            assert!(
                genesis_publication::publish(
                    &config,
                    &mut actor.state,
                    &call.invocation.0,
                    &bytes,
                    &rejected,
                )
                .is_empty()
            );
            assert_eq!(actor.state, before);
        }
        for supplied in [None, Some(vec![0xff; bytes.len()])] {
            assert!(genesis_publication::publish_from_blob(
                &config, &mut actor.state, &call.invocation.0,
                &provision_ref.hash.0, provision_ref.len, &context, |_| supplied,
            ).is_empty());
            assert_eq!(actor.state, before);
        }
        assert!(genesis_publication::publish_from_blob(
            &config, &mut actor.state, &call.invocation.0,
            &provision_ref.hash.0, vos::agent::execution::MAX_EXECUTION_AVAILABILITY_BYTES as u64 + 1, &context,
            |_| panic!("oversized reference must reject before lookup"),
        ).is_empty());
        assert_eq!(actor.state, before);
        let pending_linear = <SystemAuthority as vos::Actor>::__save_agent_lane(&actor, StateLane::Linear);
        assert_eq!(genesis_publication::publish_from_blob(
            &config, &mut actor.state, &call.invocation.0,
            &provision_ref.hash.0, provision_ref.len, &context,
            |reference| { assert_eq!(reference, &provision_ref); Some(bytes.clone()) },
        ), expected);
        assert_eq!(actor.state.genesis_publications.len(), 1);
        assert_eq!(actor.state.managed_agents, vec![root_managed_agent(config)]);
        assert_eq!(provision.proposal().catalog(), &[host::BlobRef::of_bytes(&[0xe2])]);
        let linear = <SystemAuthority as vos::Actor>::__save_agent_lane(&actor, StateLane::Linear);
        if let Some(directory) = export {
            use std::io::Write as _;
            for (name, bytes) in [
                ("configuration", config.encode()),
                ("pending-linear", pending_linear),
                ("published-linear", linear.clone()),
                ("node-rows", vos::Encode::encode(&vos::storage::mock::snapshot())),
                ("provision", bytes.clone()),
                ("runtime-catalog", vec![0xe2]),
                ("decision", expected.clone()),
                ("context", context.encode().unwrap()),
                ("authorization", call.invocation.0.to_vec()),
            ] {
                std::fs::OpenOptions::new().write(true).create_new(true)
                    .open(directory.join(name)).unwrap().write_all(&bytes).unwrap();
            }
        }
        let mut restarted = <SystemAuthority as vos::Actor>::__load_agent_state(
            Some(&config.encode()),
            Some(&linear),
            None,
            None,
        )
        .expect("signed publication must survive Linear restart");
        assert_eq!(restarted.state, actor.state);
        context.observed_slot = approval.expires_at + 1;
        assert_eq!(
            genesis_publication::publish_from_blob(
                &config,
                &mut restarted.state,
                &call.invocation.0,
                &provision_ref.hash.0,
                provision_ref.len,
                &context,
                |_| Some(bytes.clone()),
            ),
            expected
        );
        assert_eq!(restarted.state, actor.state);
        assert_eq!(
            genesis_publication::read(&config, &restarted.state, &agent.0, &context,),
            expected
        );
        assert_eq!(dispatch(&mut restarted, &call), approval_bytes);
        let ack = application_ack(config, &restarted.state, &call, &approval);
        assert!(dispatch_ack(&mut restarted, &ack));
        assert!(restarted.state.retries.is_empty());
        let finalized = restarted.state.clone();
        assert_eq!(
            genesis_publication::publish(
                &config,
                &mut restarted.state,
                &call.invocation.0,
                &bytes,
                &context,
            ),
            expected
        );
        assert_eq!(restarted.state, finalized);
        let pending_bytes = vos::rkyv::to_bytes::<vos::rkyv::rancor::Error>(&before)
            .unwrap()
            .len();
        let published_bytes = vos::rkyv::to_bytes::<vos::rkyv::rancor::Error>(&actor.state)
            .unwrap()
            .len();
        let finalized_bytes = vos::rkyv::to_bytes::<vos::rkyv::rancor::Error>(&finalized)
            .unwrap()
            .len();
        println!(
            "publication sizing: pending={pending_bytes} published={published_bytes} finalized={finalized_bytes} provision={} call={} approval={} state_limit={} provision_wire_limit={}",
            bytes.len(),
            call.encode().unwrap().len(),
            approval_bytes.len(),
            MAX_RUNTIME_STATE_BYTES,
            MAX_AGENT_GENESIS_PROVISION_BYTES,
        );
        assert!(published_bytes > pending_bytes);
        let publication_reserved =
            genesis_publication::reserved_publication_bytes(&before).unwrap();
        let terminal_reserved = genesis_publication::reserved_terminal_bytes(&before).unwrap();
        let reserved = publication_reserved + terminal_reserved;
        assert!(publication_reserved >= published_bytes - pending_bytes);
        assert!(terminal_reserved >= finalized_bytes - published_bytes);
        assert_eq!(
            genesis_publication::reserved_terminal_bytes(&actor.state),
            Some(terminal_reserved)
        );
        assert_eq!(
            genesis_publication::reserved_terminal_bytes(&finalized),
            Some(0)
        );
        assert!(reserved >= published_bytes - pending_bytes);
        assert!(genesis_publication::state_bytes_fit(
            &before,
            MAX_RUNTIME_STATE_BYTES - reserved,
        ));
        assert!(!genesis_publication::state_bytes_fit(
            &before,
            MAX_RUNTIME_STATE_BYTES - reserved + 1,
        ));
        assert!(!genesis_publication::state_bytes_fit(&before, usize::MAX));
        assert_eq!(
            genesis_publication::reserved_publication_bytes(&actor.state),
            Some(0)
        );
        assert_eq!(
            genesis_publication::reserved_publication_bytes(&finalized),
            Some(0)
        );
        assert!(bytes.len() <= MAX_CLEAN_CREATE_GENESIS_PROVISION_BYTES);
        assert!(MAX_CLEAN_CREATE_GENESIS_PROVISION_BYTES < MAX_RUNTIME_STATE_BYTES);
        assert!(published_bytes <= MAX_RUNTIME_STATE_BYTES);
        assert!(finalized_bytes <= MAX_RUNTIME_STATE_BYTES);
        let finalized_lane =
            <SystemAuthority as vos::Actor>::__save_agent_lane(&restarted, StateLane::Linear);
        let after_ack_restart = <SystemAuthority as vos::Actor>::__load_agent_state(
            Some(&config.encode()),
            Some(&finalized_lane),
            None,
            None,
        )
        .expect("publication must remain readable after acknowledged-state restart");
        assert_eq!(after_ack_restart.state, finalized);
        assert_eq!(
            genesis_publication::read(&config, &after_ack_restart.state, &agent.0, &context,),
            expected
        );
        let fresh = InvocationId([0xfc; 32]);
        assert!(admin_invocation_is_available(&restarted.state, fresh));
        assert!(private_application_invocation_is_unreserved(
            &restarted.state,
            fresh
        ));
        assert!(!admin_invocation_is_available(
            &restarted.state,
            context.invocation
        ));
        assert!(!invocation_pair_is_available(
            &restarted.state,
            context.invocation,
            fresh
        ));
        assert!(!invocation_pair_is_available(
            &restarted.state,
            fresh,
            context.invocation
        ));
        assert!(!private_application_invocation_is_unreserved(
            &restarted.state,
            context.invocation,
        ));
    }

    #[test]
    fn malformed_genesis_publication_preserves_pending_create_across_restart() {
        let config = configuration();
        let call = create_call(
            config,
            &signing(0x21),
            ADMIN_PRINCIPAL,
            Some(ADMIN_NODE),
            0xe1,
            AgentProfile::Shared,
            0xe2,
        );
        let mut actor = actor();
        let approval = dispatch(&mut actor, &call);
        assert!(!approval.is_empty());
        let before = actor.state.clone();
        let mut valid_context = context(&call);
        valid_context.invocation = InvocationId([0xe3; 32]);
        let mut wrong_actor = valid_context;
        wrong_actor.actor = ActorId([0xe4; 32]);
        let mut wrong_mode = valid_context;
        wrong_mode.mode = MethodMode::Query;
        let mut zero_invocation = valid_context;
        zero_invocation.invocation = InvocationId::ZERO;
        for invocation_context in [
            None,
            Some(valid_context),
            Some(wrong_actor),
            Some(wrong_mode),
        ] {
            let mut ctx = Context::new(ServiceId(0));
            if let Some(value) = invocation_context {
                ctx.__set_agent_invocation_context(value);
            }
            let result = block_on(<SystemAuthority as Message<PublishGenesis>>::handle(
                &mut actor,
                PublishGenesis {
                    authorization: call.invocation.0.to_vec(),
                    provision_hash: vec![0xff; 32],
                    provision_len: 32,
                },
                &mut ctx,
            ));
            assert!(result.is_empty());
            assert_eq!(actor.state, before);
        }
        // The public Context setter rejects a zero invocation before dispatch;
        // exercise the publication boundary directly for this invalid context.
        assert!(
            genesis_publication::publish(
                &config,
                &mut actor.state,
                &call.invocation.0,
                &[0xff; 32],
                &zero_invocation,
            )
            .is_empty()
        );
        assert_eq!(actor.state, before);
        let linear = <SystemAuthority as vos::Actor>::__save_agent_lane(&actor, StateLane::Linear);
        let mut restarted = <SystemAuthority as vos::Actor>::__load_agent_state(
            Some(&config.encode()),
            Some(&linear),
            None,
            None,
        )
        .expect("rejected publication must leave a restartable pending authorization");
        assert_eq!(restarted.state, before);
        assert!(restarted.state.genesis_publications.is_empty());
        assert_eq!(dispatch(&mut restarted, &call), approval);
        assert_eq!(restarted.state, before);
    }

    #[test]
    fn pending_create_and_exact_reply_survive_linear_restart_without_becoming_live() {
        let config = configuration();
        let call = create_call(
            config,
            &signing(0x21),
            ADMIN_PRINCIPAL,
            Some(ADMIN_NODE),
            0xe1,
            AgentProfile::Local,
            0xe2,
        );
        let mut actor = actor();
        let approval = dispatch(&mut actor, &call);
        assert!(!approval.is_empty());
        let decoded_approval = ManagementApproval::decode(&approval).unwrap();
        let reserved = ManagementApproval::derive_acknowledgement_invocation(&call);
        assert_eq!(decoded_approval.acknowledgement_invocation, reserved);
        assert_eq!(
            actor.state.retries[0].acknowledgement_invocation,
            reserved.0
        );
        assert_eq!(actor.state.managed_agents, vec![root_managed_agent(config)]);

        let linear = <SystemAuthority as vos::Actor>::__save_agent_lane(&actor, StateLane::Linear);
        let installation_data = config.encode();
        let mut restarted = <SystemAuthority as vos::Actor>::__load_agent_state(
            Some(&installation_data),
            Some(&linear),
            None,
            None,
        )
        .expect("valid durable Linear restart");
        assert_eq!(restarted.configuration, config);
        assert_eq!(
            restarted.state.managed_agents,
            vec![root_managed_agent(config)]
        );
        assert_eq!(
            restarted.state.retries[0].acknowledgement_invocation,
            reserved.0
        );
        assert_eq!(dispatch(&mut restarted, &call), approval);
        assert_eq!(
            restarted.state.managed_agents,
            vec![root_managed_agent(config)]
        );
    }

    #[test]
    fn signed_post_reopen_ack_atomically_activates_create_and_replays_idempotently() {
        let config = configuration();
        let call = create_call(
            config,
            &signing(0x21),
            ADMIN_PRINCIPAL,
            Some(ADMIN_NODE),
            0xe3,
            AgentProfile::Local,
            0xe4,
        );
        let mut actor = actor();
        let approval_bytes = dispatch(&mut actor, &call);
        let approval = ManagementApproval::decode(&approval_bytes).unwrap();
        assert_eq!(
            approval.plan.authority_operation(),
            AuthorityOperationKind::CreateAgent
        );
        assert_eq!(actor.state.managed_agents, vec![root_managed_agent(config)]);

        let ack = application_ack(config, &actor.state, &call, &approval);
        let ack_bytes = ack.encode().unwrap();
        assert_eq!(ack_bytes.get(..4), Some(b"MAA2".as_slice()));
        assert!(dispatch_ack(&mut actor, &ack));
        let live = &actor.state.managed_agents
            [managed_agent(&actor.state, call.managed.agent).expect("acknowledged Agent is live")];
        assert_eq!(live.agent, call.managed.agent.0);
        assert_eq!(live.authority, config.binding);
        assert!(actor.state.retries.is_empty());
        assert_eq!(actor.state.latest_management_acks.len(), 1);

        let after_finalize = actor.state.clone();
        assert!(dispatch_ack(&mut actor, &ack));
        assert_eq!(actor.state, after_finalize);

        let linear = <SystemAuthority as vos::Actor>::__save_agent_lane(&actor, StateLane::Linear);
        let installation_data = config.encode();
        let mut restarted = <SystemAuthority as vos::Actor>::__load_agent_state(
            Some(&installation_data),
            Some(&linear),
            None,
            None,
        )
        .unwrap();
        let before_retry = restarted.state.clone();
        assert!(dispatch_ack(&mut restarted, &ack));
        assert_eq!(restarted.state, before_retry);
    }

    #[test]
    fn acknowledgement_signature_context_preimage_and_ids_fail_closed() {
        let config = configuration();
        let call = create_call(
            config,
            &signing(0x21),
            ADMIN_PRINCIPAL,
            Some(ADMIN_NODE),
            0x67,
            AgentProfile::Local,
            0x68,
        );
        let mut pending = actor();
        let approval = ManagementApproval::decode(&dispatch(&mut pending, &call)).unwrap();
        let valid = application_ack(config, &pending.state, &call, &approval);

        let mut variants = Vec::new();
        let mut bad_ack_signature = valid.clone();
        bad_ack_signature.signature[0] ^= 1;
        variants.push(bad_ack_signature);

        let mut bad_receipt_signature = valid.clone();
        bad_receipt_signature.receipt.signature[0] ^= 1;
        resign_ack(&mut bad_receipt_signature);
        variants.push(bad_receipt_signature);

        let mut wrong_request = valid.clone();
        wrong_request.request = Hash([0x6a; 32]);
        wrong_request.receipt.selector.request = wrong_request.request;
        resign_receipt(&mut wrong_request.receipt);
        resign_ack(&mut wrong_request);
        variants.push(wrong_request);

        let mut wrong_authorization = valid.clone();
        wrong_authorization.authorization_invocation = InvocationId([0x6b; 32]);
        resign_ack(&mut wrong_authorization);
        variants.push(wrong_authorization);

        let mut unreserved_acknowledgement = valid.clone();
        unreserved_acknowledgement.acknowledgement_invocation = InvocationId([0x6d; 32]);
        resign_ack(&mut unreserved_acknowledgement);
        variants.push(unreserved_acknowledgement);

        let mut reused_authorization_id = valid.clone();
        reused_authorization_id.acknowledgement_invocation = call.invocation;
        // This shape is intrinsically invalid, so retain its canonical valid
        // predecessor bytes and prove the decoder/actor rejects the mutation.
        let mut reused_id_bytes = valid.encode().unwrap();
        let ack_id_offset = 36 + 32;
        reused_id_bytes[ack_id_offset..ack_id_offset + 32]
            .copy_from_slice(call.invocation.as_bytes());

        for ack in variants {
            let mut actor = SystemAuthority {
                configuration: pending.configuration,
                state: pending.state.clone(),
                node_certificates: Default::default(),
            };
            let before = actor.state.clone();
            assert!(!dispatch_ack(&mut actor, &ack));
            assert_eq!(actor.state, before);
            assert_eq!(actor.state.managed_agents, vec![root_managed_agent(config)]);
        }

        let mut actor = SystemAuthority {
            configuration: pending.configuration,
            state: pending.state.clone(),
            node_certificates: Default::default(),
        };
        let before = actor.state.clone();
        assert!(!dispatch_ack_bytes(
            &mut actor,
            reused_id_bytes,
            Some(acknowledgement_context(&reused_authorization_id))
        ));
        assert_eq!(actor.state, before);

        let mut wrong_context = acknowledgement_context(&valid);
        wrong_context.invocation = InvocationId([0x6c; 32]);
        let before = actor.state.clone();
        assert!(!dispatch_ack_bytes(
            &mut actor,
            valid.encode().unwrap(),
            Some(wrong_context)
        ));
        assert_eq!(actor.state, before);

        let before = actor.state.clone();
        assert!(!dispatch_ack_bytes(
            &mut actor,
            b"legacy acknowledgement".to_vec(),
            Some(acknowledgement_context(&valid))
        ));
        assert_eq!(actor.state, before);
    }

    #[test]
    fn acknowledgement_invocation_is_reserved_before_approval_mutation() {
        let config = configuration();
        let key = signing(0x21);
        let candidate = create_call(
            config,
            &key,
            ADMIN_PRINCIPAL,
            Some(ADMIN_NODE),
            0x75,
            AgentProfile::Local,
            0x76,
        );
        let candidate_ack = ManagementApproval::derive_acknowledgement_invocation(&candidate);

        // ACC3 authorization IDs are credential/sequence/payload-derived and
        // cannot canonically claim the separately derived MAA2 domain.
        let blocker = create_call(
            config,
            &key,
            ADMIN_PRINCIPAL,
            Some(ADMIN_NODE),
            0x77,
            AgentProfile::Local,
            0x78,
        );
        assert_ne!(blocker.invocation, candidate_ack);
        let mut forged_blocker = blocker.clone();
        forged_blocker.invocation = candidate_ack;
        resign(&mut forged_blocker, &key);
        assert!(forged_blocker.encode().is_err());
        let mut actor = actor();
        let blocker_approval = ManagementApproval::decode(&dispatch(&mut actor, &blocker)).unwrap();
        assert_eq!(actor.state.retries.len(), 1);

        let before = actor.state.clone();
        assert!(dispatch(&mut actor, &candidate).is_empty());
        assert_eq!(actor.state, before);

        // The reciprocal substitution is likewise noncanonical before the
        // actor sees it.
        let mut authorization_collision = create_call(
            config,
            &key,
            ADMIN_PRINCIPAL,
            Some(ADMIN_NODE),
            0x79,
            AgentProfile::Local,
            0x7a,
        );
        assert_ne!(
            authorization_collision.invocation,
            blocker_approval.acknowledgement_invocation
        );
        authorization_collision.invocation = blocker_approval.acknowledgement_invocation;
        resign(&mut authorization_collision, &key);
        assert!(authorization_collision.encode().is_err());
        assert_eq!(actor.state, before);
    }

    #[test]
    fn acknowledgement_invocation_conflict_is_not_an_exact_retry() {
        let config = configuration();
        let call = create_call(
            config,
            &signing(0x21),
            ADMIN_PRINCIPAL,
            Some(ADMIN_NODE),
            0x6d,
            AgentProfile::Local,
            0x6e,
        );
        let mut actor = actor();
        let approval = ManagementApproval::decode(&dispatch(&mut actor, &call)).unwrap();
        let ack = application_ack(config, &actor.state, &call, &approval);
        assert!(dispatch_ack(&mut actor, &ack));

        let mut conflict = ack.clone();
        conflict.reopened_state = Hash([0x70; 32]);
        resign_ack(&mut conflict);
        let before = actor.state.clone();
        assert!(!dispatch_ack(&mut actor, &conflict));
        assert_eq!(actor.state, before);

        let mut other_call = create_call(
            config,
            &signing(0x21),
            ADMIN_PRINCIPAL,
            Some(ADMIN_NODE),
            0x72,
            AgentProfile::Local,
            0x74,
        );
        assert_ne!(other_call.invocation, ack.acknowledgement_invocation);
        other_call.invocation = ack.acknowledgement_invocation;
        resign(&mut other_call, &signing(0x21));
        let before = actor.state.clone();
        assert!(other_call.encode().is_err());
        assert_eq!(actor.state, before);
    }

    #[test]
    fn exact_node_enrollment_and_replica_use_reject_substitution_and_unbind() {
        let config = configuration();
        let admin_key = signing(0x21);
        let principal = PrincipalId([0x79; 32]);
        let principal_key = signing(0x78);
        let transport_key = signing(0x7a);
        let mut actor = actor();

        let enroll_principal = admin_call(
            config,
            &admin_key,
            ADMIN_PRINCIPAL,
            ADMIN_NODE,
            0x70,
            1,
            AuthorityAdminOperation::EnrollPrincipal {
                principal,
                credential: enrollment(&principal_key, AuthorityCredentialKind::Ssh),
            },
        );
        assert!(!dispatch_admin(&mut actor, &enroll_principal).is_empty());

        for (index, profile) in [
            AgentProfile::Shared,
            AgentProfile::Local,
            AgentProfile::Private,
        ]
        .into_iter()
        .enumerate()
        {
            let mut descriptor = descriptor(config, principal, profile, 0x60 + index as u8);
            descriptor.replicas[0].node = NodeId([0x7b + index as u8; 32]);
            let call = credential_call(
                config,
                &admin_key,
                ADMIN_PRINCIPAL,
                Some(ADMIN_NODE),
                0x73 + index as u8,
                target_for(&descriptor),
                ManagementRequest::Create(Box::new(descriptor)),
            );
            let before = actor.state.clone();
            assert!(dispatch(&mut actor, &call).is_empty());
            assert_eq!(actor.state, before);
        }

        let good = signed_node_enrollment(SpaceId(config.space), principal, 0x7a);

        let mut wrong_peer_id = good;
        wrong_peer_id.transport_peer_id[6] ^= 1;
        let mut wrong_transport_key = good;
        wrong_transport_key.transport_public_key[0] ^= 1;
        let mut high_bit_x25519 = good;
        high_bit_x25519.encryption_public_key[31] |= 0x80;
        resign_node_enrollment(&mut high_bit_x25519, &transport_key);
        let mut low_order_x25519 = good;
        low_order_x25519.encryption_public_key =
            vos::agent_sdk::private::X25519_LOW_ORDER_PUBLIC_KEYS[1];
        resign_node_enrollment(&mut low_order_x25519, &transport_key);
        for (index, invalid) in [
            wrong_peer_id,
            wrong_transport_key,
            high_bit_x25519,
            low_order_x25519,
        ]
        .into_iter()
        .enumerate()
        {
            let call = admin_call(
                config,
                &admin_key,
                ADMIN_PRINCIPAL,
                ADMIN_NODE,
                0x80 + index as u8,
                2,
                AuthorityAdminOperation::EnrollNode {
                    enrollment: invalid,
                },
            );
            assert!(call.encode().is_err());
        }

        let mut wrong_space = good;
        wrong_space.space = SpaceId([0x7d; 32]);
        resign_node_enrollment(&mut wrong_space, &transport_key);
        let mut missing_owner = good;
        missing_owner.principal = PrincipalId([0x7e; 32]);
        resign_node_enrollment(&mut missing_owner, &transport_key);
        let mut wrong_signature = good;
        wrong_signature.transport_signature[0] ^= 1;
        for (index, invalid) in [wrong_space, missing_owner, wrong_signature]
            .into_iter()
            .enumerate()
        {
            let call = admin_call(
                config,
                &admin_key,
                ADMIN_PRINCIPAL,
                ADMIN_NODE,
                0x84 + index as u8,
                2,
                AuthorityAdminOperation::EnrollNode {
                    enrollment: invalid,
                },
            );
            let before = actor.state.clone();
            assert!(dispatch_admin(&mut actor, &call).is_empty());
            assert_eq!(actor.state, before);
        }

        let enroll_node = admin_call(
            config,
            &admin_key,
            ADMIN_PRINCIPAL,
            ADMIN_NODE,
            0x87,
            2,
            AuthorityAdminOperation::EnrollNode { enrollment: good },
        );
        assert!(!dispatch_admin(&mut actor, &enroll_node).is_empty());
        assert_eq!(
            enrolled_node(&actor.state, good.node).unwrap().enrollment(),
            good
        );

        let duplicate = admin_call(
            config,
            &admin_key,
            ADMIN_PRINCIPAL,
            ADMIN_NODE,
            0x88,
            3,
            AuthorityAdminOperation::EnrollNode { enrollment: good },
        );
        let before_duplicate = actor.state.clone();
        assert!(dispatch_admin(&mut actor, &duplicate).is_empty());
        assert_eq!(actor.state, before_duplicate);

        let mut local = descriptor(config, principal, AgentProfile::Local, 0x68);
        local.replicas[0].node = good.node;
        insert_live(&mut actor, &local);
        let unbind = admin_call(
            config,
            &admin_key,
            ADMIN_PRINCIPAL,
            ADMIN_NODE,
            0x89,
            3,
            AuthorityAdminOperation::UnbindNodeOwner {
                node: good.node,
                owner: principal,
            },
        );
        let before_unbind = actor.state.clone();
        assert!(dispatch_admin(&mut actor, &unbind).is_empty());
        assert_eq!(actor.state, before_unbind);
    }

    #[test]
    fn admin_operations_are_canonical_exact_and_survive_restart() {
        let config = configuration();
        let admin_key = signing(0x21);
        let principal = PrincipalId([0x81; 32]);
        let first_key = signing(0x82);
        let second_key = signing(0x83);
        let first_node_enrollment = signed_node_enrollment(SpaceId(config.space), principal, 0x84);
        let second_node_enrollment = signed_node_enrollment(SpaceId(config.space), principal, 0x85);
        let first_node = first_node_enrollment.node;
        let mut actor = actor();

        let enroll_call = admin_call(
            config,
            &admin_key,
            ADMIN_PRINCIPAL,
            ADMIN_NODE,
            0x81,
            1,
            AuthorityAdminOperation::EnrollPrincipal {
                principal,
                credential: enrollment(&first_key, AuthorityCredentialKind::Api),
            },
        );
        let enrolled = dispatch_admin(&mut actor, &enroll_call);
        let result = AuthorityAdminResult::decode(&enrolled).unwrap();
        assert_eq!(result.call, enroll_call);
        assert_eq!(result.generation.get(), 2);
        assert!(actor.state.nodes.indices().all(|row| row.owner != principal.0));

        let linear = <SystemAuthority as vos::Actor>::__save_agent_lane(&actor, StateLane::Linear);
        let mut actor = <SystemAuthority as vos::Actor>::__load_agent_state(
            Some(&config.encode()),
            Some(&linear),
            None,
            None,
        )
        .expect("canonical Admin state restarts");
        let after_restart = actor.state.clone();
        assert_eq!(dispatch_admin(&mut actor, &enroll_call), enrolled);
        assert_eq!(actor.state, after_restart);

        let operations = [
            (
                0x82,
                AuthorityAdminOperation::AddCredential {
                    principal,
                    credential: enrollment(&second_key, AuthorityCredentialKind::Ssh),
                },
            ),
            (
                0x83,
                AuthorityAdminOperation::EnrollNode {
                    enrollment: first_node_enrollment,
                },
            ),
            (
                0x84,
                AuthorityAdminOperation::EnrollNode {
                    enrollment: second_node_enrollment,
                },
            ),
            (
                0x85,
                AuthorityAdminOperation::SetBuiltinRole {
                    principal,
                    role: AuthorityBuiltinRole::Developer,
                },
            ),
            (
                0x86,
                AuthorityAdminOperation::RevokeCredential {
                    principal,
                    credential: enrollment(&first_key, AuthorityCredentialKind::Api).credential,
                },
            ),
            (
                0x87,
                AuthorityAdminOperation::UnbindNodeOwner {
                    node: first_node,
                    owner: principal,
                },
            ),
        ];
        for (offset, (invocation, operation)) in operations.into_iter().enumerate() {
            let expected_generation = u64::try_from(offset).unwrap() + 2;
            let call = admin_call(
                config,
                &admin_key,
                ADMIN_PRINCIPAL,
                ADMIN_NODE,
                invocation,
                expected_generation,
                operation,
            );
            let result = AuthorityAdminResult::decode(&dispatch_admin(&mut actor, &call)).unwrap();
            assert_eq!(result.generation.get(), expected_generation + 1);
        }
        assert_eq!(actor.state.administration_generation, 8);
        assert_eq!(
            actor
                .state
                .nodes
                .indices()
                .filter(|row| row.owner == principal.0)
                .count(),
            1
        );
        let first = actor
            .state
            .credentials
            .iter()
            .find(|row| {
                row.credential
                    == enrollment(&first_key, AuthorityCredentialKind::Api)
                        .credential
                        .0
            })
            .unwrap();
        assert_eq!(first.status, CredentialStatus::Revoked);
        assert!(authority_state_is_valid(&config, &actor.state));

        let linear = <SystemAuthority as vos::Actor>::__save_agent_lane(&actor, StateLane::Linear);
        let mut reopened = <SystemAuthority as vos::Actor>::__load_agent_state(
            Some(&config.encode()),
            Some(&linear),
            None,
            None,
        )
        .expect("complete canonical Admin history restarts");
        let before_retry = reopened.state.clone();
        assert!(
            dispatch_admin(&mut reopened, &enroll_call).is_empty(),
            "only the credential's newest finalized AAR4 remains exact-retryable"
        );
        assert_eq!(reopened.state, before_retry);
    }

    #[test]
    fn cross_credential_revoke_and_unbind_wait_for_pending_authority_work() {
        let config = configuration();
        let admin_key = signing(0x21);
        let worker_key = signing(0x8a);
        let worker_credential = enrollment(&worker_key, AuthorityCredentialKind::Ssh).credential;
        let mut actor = actor();

        dispatch_fixture_admin(
            &mut actor,
            InvocationId([0x8b; 32]),
            AuthorityAdminOperation::AddCredential {
                principal: ADMIN_PRINCIPAL,
                credential: enrollment(&worker_key, AuthorityCredentialKind::Ssh),
            },
        );
        let worker_node = enroll_additional_node(&mut actor, ADMIN_PRINCIPAL, 0x8c);
        let catalog = install_catalog_projection(&mut actor);
        let mut pending_call = invoke_operation_call(
            config,
            &worker_key,
            ADMIN_PRINCIPAL,
            Some(worker_node),
            0x8d,
            0x8e,
            system_target(config),
            &catalog,
        );
        resign_ssh_operation_call(&mut pending_call, &signing(0x8c));
        let approval =
            AuthorityOperationApproval::decode(&dispatch_operation(&mut actor, &pending_call))
                .expect("the secondary credential must retain one pending AOC5/AOP5");

        for (invocation, operation) in [
            (
                0x8f,
                AuthorityAdminOperation::RevokeCredential {
                    principal: ADMIN_PRINCIPAL,
                    credential: worker_credential,
                },
            ),
            (
                0x90,
                AuthorityAdminOperation::UnbindNodeOwner {
                    node: worker_node,
                    owner: ADMIN_PRINCIPAL,
                },
            ),
        ] {
            let mut mutation = admin_call(
                config,
                &admin_key,
                ADMIN_PRINCIPAL,
                ADMIN_NODE,
                invocation,
                actor.state.administration_generation,
                operation,
            );
            prepare_admin_call(&actor, &mut mutation, &admin_key);
            let before = actor.state.clone();
            assert!(dispatch_admin(&mut actor, &mutation).is_empty());
            assert_eq!(actor.state, before);
        }

        let issuance = operation_issuance_ack(config, &pending_call, &approval);
        assert!(dispatch_operation_ack(&mut actor, &issuance));
        assert!(!credential_has_pending_application(
            &actor.state,
            worker_credential,
        ));

        for (invocation, operation) in [
            (
                0x91,
                AuthorityAdminOperation::RevokeCredential {
                    principal: ADMIN_PRINCIPAL,
                    credential: worker_credential,
                },
            ),
            (
                0x92,
                AuthorityAdminOperation::UnbindNodeOwner {
                    node: worker_node,
                    owner: ADMIN_PRINCIPAL,
                },
            ),
        ] {
            let mut mutation = admin_call(
                config,
                &admin_key,
                ADMIN_PRINCIPAL,
                ADMIN_NODE,
                invocation,
                actor.state.administration_generation,
                operation,
            );
            prepare_admin_call(&actor, &mut mutation, &admin_key);
            assert!(!dispatch_admin(&mut actor, &mutation).is_empty());
        }
        assert!(authority_state_is_valid(&config, &actor.state));
    }

    #[test]
    fn admin_call_rejects_forged_cross_bound_and_ambient_contexts() {
        let config = configuration();
        let key = signing(0x21);
        let operation = AuthorityAdminOperation::EnrollPrincipal {
            principal: PrincipalId([0x91; 32]),
            credential: enrollment(&signing(0x92), AuthorityCredentialKind::Ssh),
        };
        let call = admin_call(
            config,
            &key,
            ADMIN_PRINCIPAL,
            ADMIN_NODE,
            0x91,
            1,
            operation,
        );
        let mut actor = actor();
        let pristine = actor.state.clone();

        let mut forged = call.clone();
        forged.signature[0] ^= 1;
        assert!(
            dispatch_admin_bytes(
                &mut actor,
                forged.encode().unwrap(),
                Some(admin_context(&forged)),
            )
            .is_empty()
        );

        let mut cross_space = call.clone();
        cross_space.authority.space = SpaceId([0xa1; 32]);
        refresh_admin_call(&mut cross_space, &key);
        assert!(dispatch_admin(&mut actor, &cross_space).is_empty());

        let mut cross_target = call.clone();
        cross_target.authority.system_agent = AgentId([0xa2; 32]);
        refresh_admin_call(&mut cross_target, &key);
        assert!(dispatch_admin(&mut actor, &cross_target).is_empty());

        let mut cross_node = call.clone();
        cross_node.authenticated_node = NodeId([0xa3; 32]);
        refresh_admin_call(&mut cross_node, &key);
        assert!(dispatch_admin(&mut actor, &cross_node).is_empty());

        let mut cross_principal = call.clone();
        cross_principal.administrator = PrincipalId([0xa4; 32]);
        refresh_admin_call(&mut cross_principal, &key);
        assert!(dispatch_admin(&mut actor, &cross_principal).is_empty());

        let mut weak_enrollment = call.clone();
        let mut weak_key = [0; 32];
        weak_key[0] = 1;
        weak_enrollment.operation = AuthorityAdminOperation::EnrollPrincipal {
            principal: PrincipalId([0xa5; 32]),
            credential: AuthorityCredentialEnrollment::from_public_key(
                AuthorityCredentialKind::Api,
                weak_key,
            ),
        };
        refresh_admin_call(&mut weak_enrollment, &key);
        assert!(dispatch_admin(&mut actor, &weak_enrollment).is_empty());

        let mut wrong_context = admin_context(&call);
        wrong_context.origin.transport_node = Some(NodeId([0xa6; 32]));
        assert!(
            dispatch_admin_bytes(&mut actor, call.encode().unwrap(), Some(wrong_context),)
                .is_empty()
        );
        let mut wrong_slot = admin_context(&call);
        wrong_slot.observed_slot += 1;
        assert!(
            dispatch_admin_bytes(&mut actor, call.encode().unwrap(), Some(wrong_slot),).is_empty()
        );
        let mut ambient_role = admin_context(&call);
        ambient_role.roles.space = Some(RoleId([0xa7; 32]));
        assert!(
            dispatch_admin_bytes(&mut actor, call.encode().unwrap(), Some(ambient_role),)
                .is_empty()
        );
        let mut wrong_credential = admin_context(&call);
        wrong_credential.origin.credential = Some(CredentialId([0xa8; 32]));
        assert!(
            dispatch_admin_bytes(&mut actor, call.encode().unwrap(), Some(wrong_credential),)
                .is_empty()
        );
        assert!(dispatch_admin_bytes(&mut actor, call.encode().unwrap(), None).is_empty());
        assert_eq!(actor.state, pristine);
    }

    #[test]
    fn admin_generation_and_invocation_conflicts_fail_closed() {
        let config = configuration();
        let key = signing(0x21);
        let principal = PrincipalId([0xb1; 32]);
        let mut actor = actor();
        let call = admin_call(
            config,
            &key,
            ADMIN_PRINCIPAL,
            ADMIN_NODE,
            0xb1,
            1,
            AuthorityAdminOperation::EnrollPrincipal {
                principal,
                credential: enrollment(&signing(0xb2), AuthorityCredentialKind::Api),
            },
        );
        let first = dispatch_admin(&mut actor, &call);
        assert!(!first.is_empty());
        let after_first = actor.state.clone();
        assert_eq!(dispatch_admin(&mut actor, &call), first);
        assert_eq!(actor.state, after_first);

        let stale = admin_call(
            config,
            &key,
            ADMIN_PRINCIPAL,
            ADMIN_NODE,
            0xb3,
            1,
            AuthorityAdminOperation::EnrollNode {
                enrollment: signed_node_enrollment(SpaceId(config.space), principal, 0xb3),
            },
        );
        assert!(dispatch_admin(&mut actor, &stale).is_empty());

        let mut conflict = call;
        conflict.operation = AuthorityAdminOperation::EnrollNode {
            enrollment: signed_node_enrollment(SpaceId(config.space), principal, 0xb4),
        };
        refresh_admin_call(&mut conflict, &key);
        assert!(dispatch_admin(&mut actor, &conflict).is_empty());
        assert_eq!(actor.state, after_first);

        let colliding_management = create_call(
            config,
            &key,
            ADMIN_PRINCIPAL,
            Some(ADMIN_NODE),
            0xb1,
            AgentProfile::Local,
            0xb5,
        );
        assert_ne!(colliding_management.invocation, conflict.invocation);
        let mut forged_management_collision = colliding_management;
        forged_management_collision.invocation = conflict.invocation;
        resign(&mut forged_management_collision, &key);
        assert!(forged_management_collision.encode().is_err());
        assert_eq!(actor.state, after_first);

        let mut management_first = SystemAuthority::new(&config.encode());
        let management = create_call(
            config,
            &key,
            ADMIN_PRINCIPAL,
            Some(ADMIN_NODE),
            0xb6,
            AgentProfile::Local,
            0xb7,
        );
        assert!(!dispatch(&mut management_first, &management).is_empty());
        let colliding_admin = admin_call(
            config,
            &key,
            ADMIN_PRINCIPAL,
            ADMIN_NODE,
            0xb6,
            1,
            AuthorityAdminOperation::EnrollPrincipal {
                principal: PrincipalId([0xb8; 32]),
                credential: enrollment(&signing(0xb9), AuthorityCredentialKind::Ssh),
            },
        );
        assert_ne!(colliding_admin.invocation, management.invocation);
        let mut forged_admin_collision = colliding_admin.clone();
        forged_admin_collision.invocation = management.invocation;
        resign_admin(&mut forged_admin_collision, &key);
        assert!(forged_admin_collision.encode().is_err());
        let before_collision = management_first.state.clone();
        assert!(dispatch_admin(&mut management_first, &colliding_admin).is_empty());
        assert_eq!(management_first.state, before_collision);
    }

    #[test]
    fn admin_lockout_safety_requires_an_accessible_admin() {
        let config = configuration();
        let bootstrap_key = signing(0x21);
        let inaccessible = PrincipalId([0xc1; 32]);
        let inaccessible_key = signing(0xc2);
        let replacement_key = signing(0xc3);
        let replacement_node_enrollment =
            signed_node_enrollment(SpaceId(config.space), inaccessible, 0xc4);
        let replacement_node = replacement_node_enrollment.node;
        let mut actor = actor();

        let enroll = admin_call(
            config,
            &bootstrap_key,
            ADMIN_PRINCIPAL,
            ADMIN_NODE,
            0xc1,
            1,
            AuthorityAdminOperation::EnrollPrincipal {
                principal: inaccessible,
                credential: enrollment(&inaccessible_key, AuthorityCredentialKind::Ssh),
            },
        );
        assert!(!dispatch_admin(&mut actor, &enroll).is_empty());
        let promote = admin_call(
            config,
            &bootstrap_key,
            ADMIN_PRINCIPAL,
            ADMIN_NODE,
            0xc2,
            2,
            AuthorityAdminOperation::SetBuiltinRole {
                principal: inaccessible,
                role: AuthorityBuiltinRole::Admin,
            },
        );
        assert!(!dispatch_admin(&mut actor, &promote).is_empty());
        assert!(
            actor
                .state
                .nodes
                .indices()
                .all(|row| row.owner != inaccessible.0)
        );
        let mut no_node_admin = admin_call(
            config,
            &inaccessible_key,
            inaccessible,
            ADMIN_NODE,
            0xc0,
            3,
            AuthorityAdminOperation::AddCredential {
                principal: inaccessible,
                credential: enrollment(&signing(0xcf), AuthorityCredentialKind::Api),
            },
        );
        prepare_admin_call(&actor, &mut no_node_admin, &inaccessible_key);
        let before = actor.state.clone();
        assert!(dispatch_admin(&mut actor, &no_node_admin).is_empty());
        assert_eq!(actor.state, before);

        for (invocation, operation) in [
            (
                0xc5,
                AuthorityAdminOperation::SetBuiltinRole {
                    principal: ADMIN_PRINCIPAL,
                    role: AuthorityBuiltinRole::Member,
                },
            ),
            (
                0xc6,
                AuthorityAdminOperation::UnbindNodeOwner {
                    node: ADMIN_NODE,
                    owner: ADMIN_PRINCIPAL,
                },
            ),
        ] {
            let denied = admin_call(
                config,
                &bootstrap_key,
                ADMIN_PRINCIPAL,
                ADMIN_NODE,
                invocation,
                3,
                operation,
            );
            let before = actor.state.clone();
            assert!(dispatch_admin(&mut actor, &denied).is_empty());
            assert_eq!(actor.state, before);
        }

        let add_replacement = admin_call(
            config,
            &bootstrap_key,
            ADMIN_PRINCIPAL,
            ADMIN_NODE,
            0xc7,
            3,
            AuthorityAdminOperation::AddCredential {
                principal: ADMIN_PRINCIPAL,
                credential: enrollment(&replacement_key, AuthorityCredentialKind::Api),
            },
        );
        assert!(!dispatch_admin(&mut actor, &add_replacement).is_empty());
        let mut revoke_bootstrap = admin_call(
            config,
            &replacement_key,
            ADMIN_PRINCIPAL,
            ADMIN_NODE,
            0xc8,
            4,
            AuthorityAdminOperation::RevokeCredential {
                principal: ADMIN_PRINCIPAL,
                credential: CredentialId::of_public_key(&bootstrap_key.verifying_key().to_bytes()),
            },
        );
        prepare_admin_call(&actor, &mut revoke_bootstrap, &replacement_key);
        assert!(!dispatch_admin(&mut actor, &revoke_bootstrap).is_empty());
        let mut revoke_last = admin_call(
            config,
            &replacement_key,
            ADMIN_PRINCIPAL,
            ADMIN_NODE,
            0xc9,
            5,
            AuthorityAdminOperation::RevokeCredential {
                principal: ADMIN_PRINCIPAL,
                credential: CredentialId::of_public_key(
                    &replacement_key.verifying_key().to_bytes(),
                ),
            },
        );
        prepare_admin_call(&actor, &mut revoke_last, &replacement_key);
        let before = actor.state.clone();
        assert!(dispatch_admin(&mut actor, &revoke_last).is_empty());
        assert_eq!(actor.state, before);

        let mut bind_replacement = admin_call(
            config,
            &replacement_key,
            ADMIN_PRINCIPAL,
            ADMIN_NODE,
            0xca,
            5,
            AuthorityAdminOperation::EnrollNode {
                enrollment: replacement_node_enrollment,
            },
        );
        prepare_admin_call(&actor, &mut bind_replacement, &replacement_key);
        assert!(!dispatch_admin(&mut actor, &bind_replacement).is_empty());
        let mut demote_bootstrap = admin_call(
            config,
            &replacement_key,
            ADMIN_PRINCIPAL,
            ADMIN_NODE,
            0xcb,
            6,
            AuthorityAdminOperation::SetBuiltinRole {
                principal: ADMIN_PRINCIPAL,
                role: AuthorityBuiltinRole::Member,
            },
        );
        prepare_admin_call(&actor, &mut demote_bootstrap, &replacement_key);
        assert!(!dispatch_admin(&mut actor, &demote_bootstrap).is_empty());
        let mut unbind_last_admin_node = admin_call(
            config,
            &inaccessible_key,
            inaccessible,
            replacement_node,
            0xcc,
            7,
            AuthorityAdminOperation::UnbindNodeOwner {
                node: replacement_node,
                owner: inaccessible,
            },
        );
        prepare_admin_call(&actor, &mut unbind_last_admin_node, &inaccessible_key);
        let before = actor.state.clone();
        assert!(dispatch_admin(&mut actor, &unbind_last_admin_node).is_empty());
        assert_eq!(actor.state, before);
    }

    #[test]
    fn admin_state_rejects_reordered_duplicates_and_forged_retry_bytes() {
        let config = configuration();
        let mut actor = actor();
        let call = admin_call(
            config,
            &signing(0x21),
            ADMIN_PRINCIPAL,
            ADMIN_NODE,
            0xd1,
            1,
            AuthorityAdminOperation::EnrollPrincipal {
                principal: PrincipalId([0xd1; 32]),
                credential: enrollment(&signing(0xd2), AuthorityCredentialKind::Ssh),
            },
        );
        assert!(!dispatch_admin(&mut actor, &call).is_empty());
        let bind = admin_call(
            config,
            &signing(0x21),
            ADMIN_PRINCIPAL,
            ADMIN_NODE,
            0xd2,
            2,
            AuthorityAdminOperation::EnrollNode {
                enrollment: signed_node_enrollment(
                    SpaceId(config.space),
                    PrincipalId([0xd1; 32]),
                    0xd3,
                ),
            },
        );
        assert!(!dispatch_admin(&mut actor, &bind).is_empty());
        assert!(authority_state_is_valid(&config, &actor.state));

        let mut reordered = actor.state.clone();
        reordered.credentials.swap(0, 1);
        assert!(!authority_state_is_valid(&config, &reordered));
        let mut duplicate_history = actor.state.clone();
        duplicate_history
            .admin_retries
            .push(duplicate_history.admin_retries[0].clone());
        assert!(!authority_state_is_valid(&config, &duplicate_history));
        let mut duplicate = actor.state.clone();
        duplicate.roles.push(duplicate.roles[0].clone());
        assert!(!authority_state_is_valid(&config, &duplicate));
        let mut forged = actor.state.clone();
        forged.admin_retries[0].result_bytes[0] ^= 1;
        assert!(!authority_state_is_valid(&config, &forged));
        let mut substituted = actor.state.clone();
        substituted.admin_retries[0].call_commitment[0] ^= 1;
        assert!(!authority_state_is_valid(&config, &substituted));
        let mut unsigned_role_change = actor.state.clone();
        let enrolled = unsigned_role_change
            .roles
            .iter_mut()
            .find(|row| row.principal == [0xd1; 32])
            .unwrap();
        enrolled.role = BuiltinPrincipalRole::Developer;
        assert!(!authority_state_is_valid(&config, &unsigned_role_change));
        let mut invalid_kind = actor.state.clone();
        invalid_kind
            .credentials
            .iter_mut()
            .find(|row| row.principal == [0xd1; 32])
            .unwrap()
            .kind = 2;
        assert!(!authority_state_is_valid(&config, &invalid_kind));
        let node = actor.state.nodes.indices().find(|row| row.owner == [0xd1; 32]).unwrap().node;
        let original = enrolled_node(&actor.state, NodeId(node)).unwrap();
        let corruptions: [fn(&mut NodeOwnerRow); 7] = [
            |row| row.owner = [0xd4; 32],
            |row| row.space[0] ^= 1,
            |row| row.transport_public_key[0] ^= 1,
            |row| row.transport_peer_id[6] ^= 1,
            |row| row.encryption_public_key[31] |= 0x80,
            |row| row.transport_signature[0] ^= 1,
            |row| row.enrollment_commitment[0] ^= 1,
        ];
        for corrupt in corruptions {
            assert!(!authority_row_transaction(|| {
                let mut changed = original.clone();
                corrupt(&mut changed);
                node_storage::rows().insert(&node, &changed);
                assert!(!authority_state_is_valid(&config, &actor.state));
                false
            }));
            assert_eq!(enrolled_node(&actor.state, NodeId(node)), Some(original.clone()));
        }

        let mut orphaned_agent = actor.state.clone();
        orphaned_agent.managed_agents.push(ManagedAgentRow {
            agent: [0xd5; 32],
            owner: [0xd6; 32],
            profile: AgentProfile::Private as u8,
            creation_nonce: [0xda; 32],
            runtime_deployment: [0xd7; 32],
            runtime_program: [0xd8; 32],
            runtime_producer: [0xd9; 32],
            transition_producer: [0xdf; 32],
            authority: config.binding,
            private_recovery: Some(PrivateRecoveryBindingRow {
                signing_key_commitment: [0xdc; 32],
                encryption_public_key: [0xdd; 32],
            }),
            runtime_package: AuthorityBlobRow {
                hash: [0xde; 32],
                len: 1,
            },
            runtime_contract: RuntimeContractRow::from_sdk(RuntimePackageContract::canonical()),
            capabilities: RuntimeCapabilitiesRow::from_sdk(RuntimeCapabilities::standard()),
            replicas: Vec::new(),
            replica_generation: [0xdb; 32],
        });
        assert!(!authority_state_is_valid(&config, &orphaned_agent));
    }

    #[test]
    fn authority_identity_tables_enforce_explicit_bounds() {
        let config = configuration();
        let mut actor = actor();
        for ordinal in 1..MAX_AUTHORITY_PRINCIPALS {
            let mut seed = [0xe1; 32];
            seed[..8].copy_from_slice(&(ordinal as u64).to_le_bytes());
            let key = SigningKey::from_bytes(&seed);
            let mut principal = [0xe2; 32];
            principal[..8].copy_from_slice(&(ordinal as u64).to_le_bytes());
            let principal = PrincipalId(principal);
            let node_enrollment = signed_node_enrollment(
                SpaceId(config.space),
                principal,
                u8::try_from(ordinal).unwrap().wrapping_add(0x80),
            );
            let credential = enrollment(&key, AuthorityCredentialKind::Ssh);
            let invocation = |step: u8| {
                InvocationId(
                    Hash::digest(
                        b"vos/test/system-authority/bounded-admin-history/v1",
                        &[&(ordinal as u64).to_le_bytes(), &[step]],
                    )
                    .0,
                )
            };
            record_fixture_admin(
                &mut actor,
                invocation(0),
                AuthorityAdminOperation::EnrollPrincipal {
                    principal,
                    credential,
                },
            );
            record_fixture_admin(
                &mut actor,
                invocation(1),
                AuthorityAdminOperation::EnrollNode {
                    enrollment: node_enrollment,
                },
            );
        }
        assert!(refresh_state_integrity_commitment(
            &actor.configuration,
            &mut actor.state,
        ));
        assert_eq!(actor.state.roles.len(), MAX_AUTHORITY_PRINCIPALS);
        assert_eq!(actor.state.credentials.len(), MAX_AUTHORITY_CREDENTIALS);
        assert_eq!(actor.state.nodes.len(), MAX_AUTHORITY_CREDENTIALS);
        assert!(authority_state_is_valid(&config, &actor.state));

        let call = admin_call(
            config,
            &signing(0x21),
            ADMIN_PRINCIPAL,
            ADMIN_NODE,
            0xe4,
            actor.state.administration_generation,
            AuthorityAdminOperation::EnrollPrincipal {
                principal: PrincipalId([0xe4; 32]),
                credential: enrollment(&signing(0xe5), AuthorityCredentialKind::Api),
            },
        );
        let before = actor.state.clone();
        assert!(dispatch_admin(&mut actor, &call).is_empty());
        assert_eq!(actor.state, before);
    }

    #[test]
    fn maximum_private_membership_can_be_replaced_disjointly_within_state_bound() {
        let config = configuration();
        let owner = PrincipalId([0x51; 32]);
        let owner_node = node_for_principal(config, owner);
        let owner_key = signing(0x53);
        let mut actor = actor();
        enroll(
            &mut actor,
            &owner_key,
            owner,
            owner_node,
            BuiltinPrincipalRole::Member,
        );

        // Keep 512 exact owner enrollments at once: a maximum old membership
        // plus a fully disjoint maximum replacement. The extra authority row
        // is the bootstrap Node, proving the 2*N+1 table boundary. This test
        // starts from a valid persisted projection so it isolates retained
        // recovery-state sizing from the separately covered ACC3 Create path.
        for ordinal in 0_u64..511 {
            let mut seed = [0x5a; 32];
            seed[..8].copy_from_slice(&ordinal.to_le_bytes());
            let key = SigningKey::from_bytes(&seed);
            let mut enrollment = NodeEncryptionEnrollment::from_keys(
                SpaceId(config.space),
                owner,
                key.verifying_key().to_bytes(),
                [0x42; 32],
                [1; PRIVATE_SIGNATURE_BYTES],
            );
            resign_node_enrollment(&mut enrollment, &key);
            assert!(insert_enrolled_node(&mut actor.state, enrollment));
        }
        assert!(actor.state.nodes.index_is_valid());
        assert_eq!(actor.state.nodes.len(), MAX_AUTHORITY_NODES);
        let owner_nodes = actor
            .state
            .nodes
            .indices()
            .filter(|row| row.owner == owner.0)
            .map(|row| NodeId(row.node))
            .collect::<Vec<_>>();
        assert_eq!(owner_nodes.len(), 2 * MAX_PRIVATE_NODES);
        let old_nodes = owner_nodes[..MAX_PRIVATE_NODES].to_vec();
        let replacement_nodes = owner_nodes[MAX_PRIVATE_NODES..].to_vec();

        let descriptor = descriptor(config, owner, AgentProfile::Private, 0x55);
        let mut managed = managed_agent_row_from_descriptor(&config, &descriptor).unwrap();
        managed.replicas = old_nodes
            .iter()
            .map(|node| ManagedReplicaRow {
                node: node.0,
                principal: owner.0,
                role: ReplicaRole::Observer as u8,
            })
            .collect();
        managed.replica_generation = managed_replica_generation(&config, &managed).unwrap().0;
        let managed_index = actor
            .state
            .managed_agents
            .binary_search_by(|row| row.agent.cmp(&managed.agent))
            .unwrap_err();
        actor
            .state
            .managed_agents
            .insert(managed_index, managed.clone());
        let genesis_member_set = fixture_member_set(old_nodes.iter().copied());
        actor.state.private_agents.push(PrivateAgentProjectionRow {
            agent: managed.agent,
            owner: managed.owner,
            runtime_deployment: managed.runtime_deployment,
            genesis_members: old_nodes.iter().map(|node| node.0).collect(),
            genesis_member_set: genesis_member_set.0,
            control_head: None,
            control_sequence: None,
            epoch: 0,
            members: old_nodes.iter().map(|node| node.0).collect(),
            member_set: genesis_member_set.0,
            reopened_runtime_state: None,
            stable_projection: None,
            applied_at: None,
            application_invocation: None,
            application_ack: None,
            application_ack_bytes: None,
        });
        actor.state.private_agents.sort_by_key(|row| row.agent);
        assert!(refresh_state_integrity_commitment(
            &config,
            &mut actor.state
        ));
        assert!(authority_state_is_valid(&config, &actor.state));

        let proof = signed_recovery_proof(
            &actor,
            target_for(&descriptor),
            owner,
            &signing(0x59),
            Hash([0x5b; 32]),
            5,
            Some(Hash([0x5c; 32])),
            2,
            None,
            replacement_nodes.clone(),
            Hash([0x5d; 32]),
        );
        assert_eq!(proof.replacement_nodes.len(), MAX_PRIVATE_NODES);
        let call = operation_call(
            config,
            &owner_key,
            owner,
            Some(owner_node),
            0x5e,
            AuthorityOperationIntent::RecoverPrivateAgent {
                proof: proof.clone(),
            },
        );
        let (approval, issuance) = authorize_and_issue_operation(&mut actor, &call);
        let pca = private_application_ack(
            &call,
            &approval,
            &issuance,
            private_application_fact(
                &call,
                proof.replacement_member_set,
                Hash([0x5f; 32]),
                OBSERVED_SLOT + 1,
            ),
        );
        assert!(dispatch_private_application(&mut actor, &pca));
        assert_eq!(
            actor.state.private_agents[0].members.len(),
            MAX_PRIVATE_NODES
        );
        assert_eq!(
            actor.state.private_agents[0].members,
            replacement_nodes
                .iter()
                .map(|node| node.0)
                .collect::<Vec<_>>()
        );
        assert!(authority_state_is_valid(&config, &actor.state));
        let state_bytes = vos::rkyv::to_bytes::<vos::rkyv::rancor::Error>(&actor.state).unwrap();
        assert!(state_bytes.len() <= MAX_RUNTIME_STATE_BYTES);

        let mut oversized_image = actor.state.clone();
        oversized_image.private_agents[0].application_ack_bytes =
            Some(vec![0; MAX_RUNTIME_STATE_BYTES]);
        assert!(computed_state_integrity_commitment(&config, &oversized_image).is_none());
        assert!(!refresh_state_integrity_commitment(
            &config,
            &mut oversized_image
        ));

        let mut over_node_bound = actor.state.clone();
        let key = signing(0x60);
        let mut enrollment = NodeEncryptionEnrollment::from_keys(
            SpaceId(config.space),
            owner,
            key.verifying_key().to_bytes(),
            [0x42; 32],
            [1; PRIVATE_SIGNATURE_BYTES],
        );
        resign_node_enrollment(&mut enrollment, &key);
        over_node_bound
            .nodes
            .inject_index_for_test(&NodeOwnerRow::from_enrollment(enrollment));
        assert!(refresh_state_integrity_commitment(
            &config,
            &mut over_node_bound
        ));
        assert!(!authority_state_is_valid(&config, &over_node_bound));
    }

    #[test]
    fn read_only_management_has_no_acc3_actor_message() {
        let config = configuration();
        let request = ManagementRequest::InspectResources;
        assert!(request.authorization_plan().is_none());
        let context_call = create_call(
            config,
            &signing(0x21),
            ADMIN_PRINCIPAL,
            Some(ADMIN_NODE),
            0x62,
            AgentProfile::Local,
            0x61,
        );

        let mut actor = actor();
        let before = actor.state.clone();
        assert!(
            dispatch_bytes(
                &mut actor,
                request.commitment().0.to_vec(),
                Some(context(&context_call)),
            )
            .is_empty()
        );
        assert_eq!(actor.state, before);
    }

    #[test]
    fn approval_validity_is_narrowed_and_impossible_windows_are_denied() {
        let config = configuration();
        let key = signing(0x21);
        let mut call = create_call(
            config,
            &key,
            ADMIN_PRINCIPAL,
            Some(ADMIN_NODE),
            0x63,
            AgentProfile::Local,
            0x64,
        );
        call.requested_valid_from = OBSERVED_SLOT + 10;
        call.requested_expires_at = u64::MAX;
        refresh_management_call(&mut call, &key);
        let mut actor = actor();
        let reply = dispatch(&mut actor, &call);
        let approval = ManagementApproval::decode(&reply).unwrap();
        assert_eq!(approval.valid_from, OBSERVED_SLOT + 10);
        assert_eq!(
            approval.expires_at,
            OBSERVED_SLOT + MAX_APPROVAL_VALIDITY_SLOTS
        );

        let mut impossible = create_call(
            config,
            &key,
            ADMIN_PRINCIPAL,
            Some(ADMIN_NODE),
            0x65,
            AgentProfile::Local,
            0x66,
        );
        impossible.requested_valid_from = OBSERVED_SLOT + MAX_APPROVAL_VALIDITY_SLOTS + 1;
        impossible.requested_expires_at = u64::MAX;
        refresh_management_call(&mut impossible, &key);
        let before = actor.state.clone();
        assert!(dispatch(&mut actor, &impossible).is_empty());
        assert_eq!(actor.state, before);
    }

    #[test]
    fn generated_agent_schema_marks_authority_methods_as_explicit_linear_public_preflight() {
        let method = SystemAuthorityMsg::AGENT_METHODS;
        assert_eq!(method.len(), 14);
        assert_eq!(method[0].name, "authorize");
        assert_eq!(method[0].mode, vos::agent_sdk::schema::MethodMode::Linear);
        assert!(method[0].explicit);
        assert_eq!(method[1].name, "finalize");
        assert_eq!(method[1].mode, vos::agent_sdk::schema::MethodMode::Linear);
        assert!(method[1].explicit);
        assert_eq!(method[2].name, "publish_genesis");
        assert_eq!(method[2].mode, vos::agent_sdk::schema::MethodMode::Linear);
        assert!(method[2].explicit);
        assert_eq!(method[3].name, "genesis_decision");
        assert_eq!(method[3].mode, vos::agent_sdk::schema::MethodMode::Linear);
        assert!(method[3].explicit);
        assert_eq!(method[4].name, "authorize_operation");
        assert_eq!(method[4].mode, vos::agent_sdk::schema::MethodMode::Linear);
        assert!(method[4].explicit);
        assert_eq!(method[5].name, "acknowledge_issuance");
        assert_eq!(method[5].mode, vos::agent_sdk::schema::MethodMode::Linear);
        assert!(method[5].explicit);
        assert_eq!(method[6].name, "resolve_private_application");
        assert_eq!(method[6].mode, vos::agent_sdk::schema::MethodMode::Linear);
        assert!(method[6].explicit);
        assert_eq!(method[7].name, "administer");
        assert_eq!(method[7].mode, vos::agent_sdk::schema::MethodMode::Linear);
        assert!(method[7].explicit);
        for (index, name) in [
            "credential_projection",
            "inventory_projection_page",
            "agent_projection_page",
            "agent_replica_projection_page",
            "actor_projection_page",
            "genesis_signing_committee",
        ]
        .iter()
        .enumerate()
        {
            assert_eq!(method[index + 8].name, *name);
            assert_eq!(
                method[index + 8].mode,
                vos::agent_sdk::schema::MethodMode::Query
            );
            assert!(method[index + 8].explicit);
        }
        assert_eq!(SystemAuthorityMsg::AGENT_AUTHORIZATIONS.len(), 14);
        assert!(
            SystemAuthorityMsg::AGENT_AUTHORIZATIONS
                .iter()
                .all(|method| {
                    matches!(
                        method.selector,
                        vos::metadata::AgentAuthorizationSelectorMeta::Public
                    )
                })
        );
    }
}
