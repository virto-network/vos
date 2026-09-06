//! Clean, portable policy actor for standard Agent management.
//!
//! The actor accepts canonical `ACC1` management calls, canonical `AOC1`
//! general-operation calls, and self-authenticating `AAD1` identity-admin calls
//! delivered with an exact clean `AIC1` invocation context. It performs policy,
//! credential, and Admin-accessibility checks inside the guest and retains exact
//! results for replay. Agent and actor lifecycle approvals remain pending until
//! separately signed exact durable-application acknowledgements are observed;
//! general-operation approvals remain exact-retryable until a signed `AOI1`
//! issuance acknowledgement advances their contiguous retirement floor. A
//! distinct signed `PCA1` acknowledgement is required before Private control
//! state or membership becomes policy-visible.

#![cfg_attr(target_arch = "riscv64", no_std)]

use core::cmp::{max, min};
use core::num::NonZeroU64;

use ed25519_dalek::{Signature, VerifyingKey};
use vos::agent_sdk::authority::{
    AgentAuthorityBinding, AuthorityActorTarget, AuthorityAdminCall, AuthorityAdminOperation,
    AuthorityAdminResult, AuthorityBuiltinRole, AuthorityCredentialCall,
    AuthorityCredentialEnrollment, AuthorityCredentialVerifier, AuthorityEvidence, AuthorityIssuer,
    AuthorityLaneRoots, AuthorityOperationKind, AuthorityVerifier, ManagedAgentTarget,
    ManagementApplicationAck, ManagementApproval,
};
use vos::agent_sdk::authority_operation::{
    AuthorityOperationApproval, AuthorityOperationCall, AuthorityOperationIntent,
    AuthorityOperationIssuanceAck, PrivateControlApplicationAck, PrivateControlApplicationFact,
    private_member_set_commitment,
};
use vos::agent_sdk::private::MAX_PRIVATE_NODES;
use vos::agent_sdk::wire::CanonicalWire as _;
use vos::agent_sdk::{
    ActorId, AgentId, AgentProfile, CredentialId, DeploymentId, Hash, InvocationContext,
    InvocationId, InvocationRoleClaims, MAX_INVOCATION_MESSAGE_BYTES, MAX_INVOCATION_REPLY_BYTES,
    MAX_RUNTIME_STATE_BYTES, ManagementRequest, PrincipalId, ProducerId, ProgramId, RUNTIME_ABI_ID,
    SpaceId,
};
use vos::prelude::*;

/// Fixed installation-data wire for [`SystemAuthorityConfiguration`].
pub const SYSTEM_AUTHORITY_CONFIGURATION_MAGIC: [u8; 4] = *b"SAC2";

/// The root admission consumes exactly one Create decision and one authority
/// actor Install decision before this portable issuer can run.
pub const ROOT_BOOTSTRAP_AUTHORIZATION_HIGH_WATER: u64 = 2;

/// Maximum durable rows in each caller table.
pub const MAX_AUTHORITY_CREDENTIALS: usize = 64;
pub const MAX_AUTHORITY_NODES: usize = 64;
pub const MAX_AUTHORITY_PRINCIPALS: usize = 64;
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
/// Exact approvals are deliberately bounded. Saturation fails closed; records
/// from general operations are retired only by their explicitly ordered AOI1
/// acknowledgement floor.
pub const MAX_EXACT_RETRY_RECORDS: usize = 128;
/// Compact retired-operation identities preserve cross-domain invocation
/// collision safety after AOC1/AOP1/AOI1 preimages are discarded. Saturation
/// fails closed because an invocation ID must never become reusable.
pub const MAX_RETIRED_AUTHORITY_OPERATIONS: usize = 4_096;
/// One Private Agent may consume the runtime's complete bounded control-chain
/// ceiling. Compact rows preserve exact PCA1 retry and invocation collision
/// identity after a later control supersedes the current projection.
pub const MAX_PRIVATE_APPLICATION_RECORDS: usize = 4_096;
/// Worst-case canonical ACC1/AOC1/AAD1 calls plus MAP1/AOP1/AAR1 results and
/// MAA1/AOI1 acknowledgements retained by the bounded exact-retry tables. This
/// leaves over one MiB of the standard state ceiling for row metadata and
/// actor framing.
pub const MAX_RETAINED_EXACT_WIRE_BYTES: usize = MAX_EXACT_RETRY_RECORDS
    * (MAX_INVOCATION_MESSAGE_BYTES + MAX_INVOCATION_REPLY_BYTES + MAX_INVOCATION_MESSAGE_BYTES);
/// Policy will never authorize farther than this many logical slots after the
/// slot at which unseen work was accepted.
pub const MAX_APPROVAL_VALIDITY_SLOTS: u64 = 4_096;

const CONFIG_FIXED_FIELDS: usize = 15;
const CONFIG_U64_FIELDS: usize = 2;
const CONFIG_ENCODED_BYTES: usize = SYSTEM_AUTHORITY_CONFIGURATION_MAGIC.len()
    + 32
    + CONFIG_FIXED_FIELDS * 32
    + CONFIG_U64_FIELDS * 8
    + 1;
const EVIDENCE_DOMAIN: &[u8] = b"vos/system-authority/policy-evidence/v1";
const OPERATION_EVIDENCE_DOMAIN: &[u8] = b"vos/system-authority/operation-evidence/v1";

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
    Default,
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
    pub binding: AuthorityBindingState,
    /// Exact durable issuer sequence already consumed by root admission.
    pub bootstrap_authorization_high_water: u64,
    pub bootstrap_principal: [u8; 32],
    pub bootstrap_credential_public_key: [u8; 32],
    /// Canonical [`vos::agent_sdk::authority::AuthorityCredentialKind`] tag.
    pub bootstrap_credential_kind: u8,
    pub bootstrap_node: [u8; 32],
}

impl SystemAuthorityConfiguration {
    pub fn is_valid(self) -> bool {
        self.space != [0; 32]
            && self.system_agent != [0; 32]
            && self.system_runtime_deployment != [0; 32]
            && self.system_runtime_program != [0; 32]
            && self.system_runtime_producer != [0; 32]
            && self.bootstrap_authorization_high_water == ROOT_BOOTSTRAP_AUTHORIZATION_HIGH_WATER
            && self.bootstrap_principal != [0; 32]
            && canonical_credential_public_key(&self.bootstrap_credential_public_key)
            && CredentialId::of_public_key(&self.bootstrap_credential_public_key)
                != CredentialId::ZERO
            && matches!(self.bootstrap_credential_kind, 0 | 1)
            && self.bootstrap_node != [0; 32]
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
        bytes.extend_from_slice(&self.binding.policy);
        bytes.extend_from_slice(&self.binding.issuer.principal);
        bytes.extend_from_slice(&self.binding.issuer.actor);
        bytes.extend_from_slice(&self.binding.issuer.deployment);
        bytes.extend_from_slice(&self.binding.issuer.program);
        bytes.extend_from_slice(&self.binding.issuer.producer);
        bytes.extend_from_slice(&self.binding.public_key);
        bytes.extend_from_slice(&self.binding.initial_epoch.to_le_bytes());
        bytes.extend_from_slice(&self.bootstrap_authorization_high_water.to_le_bytes());
        bytes.extend_from_slice(&self.bootstrap_principal);
        bytes.extend_from_slice(&self.bootstrap_credential_public_key);
        bytes.push(self.bootstrap_credential_kind);
        bytes.extend_from_slice(&self.bootstrap_node);
        bytes
    }

    /// Decode SAC2 exactly. Prior clean generations, truncation, and trailing
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
        let bootstrap_principal = take_fixed(bytes, &mut cursor)?;
        let bootstrap_credential_public_key = take_fixed(bytes, &mut cursor)?;
        let bootstrap_credential_kind = *bytes.get(cursor)?;
        cursor += 1;
        let bootstrap_node = take_fixed(bytes, &mut cursor)?;
        if cursor != bytes.len() {
            return None;
        }
        let value = Self {
            space,
            system_agent,
            system_runtime_deployment,
            system_runtime_program,
            system_runtime_producer,
            binding: AuthorityBindingState {
                policy,
                issuer,
                public_key,
                initial_epoch,
            },
            bootstrap_authorization_high_water,
            bootstrap_principal,
            bootstrap_credential_public_key,
            bootstrap_credential_kind,
            bootstrap_node,
        };
        value.is_valid().then_some(value)
    }
}

fn take_fixed(bytes: &[u8], cursor: &mut usize) -> Option<[u8; 32]> {
    let value = bytes
        .get(*cursor..cursor.checked_add(32)?)?
        .try_into()
        .ok()?;
    *cursor += 32;
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
}

#[derive(
    vos::rkyv::Archive, vos::rkyv::Serialize, vos::rkyv::Deserialize, Clone, Debug, PartialEq, Eq,
)]
#[rkyv(crate = vos::rkyv)]
pub struct NodeOwnerRow {
    pub node: [u8; 32],
    pub owner: [u8; 32],
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
pub struct ManagedAgentRow {
    pub agent: [u8; 32],
    pub owner: [u8; 32],
    pub profile: u8,
    pub runtime_deployment: [u8; 32],
    pub runtime_program: [u8; 32],
    pub runtime_producer: [u8; 32],
    pub authority: AuthorityBindingState,
}

#[derive(
    vos::rkyv::Archive, vos::rkyv::Serialize, vos::rkyv::Deserialize, Clone, Debug, PartialEq, Eq,
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
    // neither is carried by ACC1/MAP1/MAA1, so the authority cannot prove them
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
    ManagedAgentRow {
        agent: config.system_agent,
        owner: config.bootstrap_principal,
        profile: AgentProfile::Shared as u8,
        runtime_deployment: config.system_runtime_deployment,
        runtime_program: config.system_runtime_program,
        runtime_producer: config.system_runtime_producer,
        authority: config.binding,
    }
}

#[derive(
    vos::rkyv::Archive, vos::rkyv::Serialize, vos::rkyv::Deserialize, Clone, Debug, PartialEq, Eq,
)]
#[rkyv(crate = vos::rkyv)]
pub enum PendingManagementEffect {
    None,
    Create(ManagedAgentRow),
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
    },
}

#[derive(
    vos::rkyv::Archive, vos::rkyv::Serialize, vos::rkyv::Deserialize, Clone, Debug, PartialEq, Eq,
)]
#[rkyv(crate = vos::rkyv)]
pub struct ExactRetryRecord {
    pub invocation: [u8; 32],
    /// Deterministic MAA1 invocation reserved atomically with this ACC1.
    pub acknowledgement_invocation: [u8; 32],
    pub credential_call: [u8; 32],
    pub credential_call_bytes: Vec<u8>,
    pub approval_commitment: [u8; 32],
    pub authorization_sequence: u64,
    pub approval: Vec<u8>,
    pub effect: PendingManagementEffect,
    pub finalized: bool,
    pub acknowledgement: Option<[u8; 32]>,
    pub acknowledgement_bytes: Option<Vec<u8>>,
    pub reopened_state: Option<[u8; 32]>,
    pub applied_at: Option<u64>,
}

/// Exact retained AOC1/AOP1 pair and, once observed, its exact AOI1. An
/// out-of-order acknowledgement remains here until every earlier global
/// authorization position is safe to cross.
#[derive(
    vos::rkyv::Archive, vos::rkyv::Serialize, vos::rkyv::Deserialize, Clone, Debug, PartialEq, Eq,
)]
#[rkyv(crate = vos::rkyv)]
pub struct AuthorityOperationRetryRecord {
    pub invocation: [u8; 32],
    pub acknowledgement_invocation: [u8; 32],
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
    /// Deterministic PCA1 invocation reserved atomically with a Private AOI1.
    pub private_application_invocation: Option<[u8; 32]>,
}

/// Compact collision tombstone retained after the durable retirement floor
/// has crossed one general authorization. The exact AOC1/AOP1/AOI1 preimages
/// are intentionally absent, but their invocation pair and signed AOI1
/// commitment can never be admitted again.
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
pub struct RetiredAuthorityOperationRow {
    pub invocation: [u8; 32],
    pub acknowledgement_invocation: [u8; 32],
    pub authorization_sequence: u64,
    pub operation_call: [u8; 32],
    pub approval: [u8; 32],
    pub issuance_ack: [u8; 32],
    pub issued_at: u64,
    pub private_application_invocation: Option<[u8; 32]>,
    pub private_operation: Option<RetiredPrivateOperationRow>,
}

/// Exact Private-control intent fields which remain after the AOC1/AOP1/AOI1
/// preimages retire. They let PCA1 prove the original operation without
/// reconstructing or relabeling discarded bytes.
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
pub struct RetiredPrivateOperationRow {
    pub agent: [u8; 32],
    pub runtime_deployment: [u8; 32],
    pub principal: [u8; 32],
    pub operation: u8,
    pub control: [u8; 32],
    pub control_sequence: u64,
    pub control_previous: Option<[u8; 32]>,
    pub epoch: u64,
    /// Exact membership target retained from AOC1. Recover has no single
    /// target and is not authorizable in this generation.
    pub node: Option<[u8; 32]>,
    /// Invite's exact transport/encryption identity commitment. A separate
    /// enrollment projection can bind this retained value before admission.
    pub node_identity: Option<[u8; 32]>,
    /// Revoke fixes the complete post-apply set in AOC1. Invite fixes the
    /// invited Node identity, while only PCA1 can report the resulting set.
    pub post_member_set: Option<[u8; 32]>,
}

/// Current policy-visible Private control projection. Creation supplies the
/// genesis membership; only exact PCA1 application facts advance the head.
#[derive(
    vos::rkyv::Archive, vos::rkyv::Serialize, vos::rkyv::Deserialize, Clone, Debug, PartialEq, Eq,
)]
#[rkyv(crate = vos::rkyv)]
pub struct PrivateAgentProjectionRow {
    pub agent: [u8; 32],
    pub owner: [u8; 32],
    pub runtime_deployment: [u8; 32],
    pub control_head: Option<[u8; 32]>,
    pub control_sequence: Option<u64>,
    pub epoch: u64,
    /// Canonically sorted, unique Private member NodeIds. The commitment is
    /// redundant by design so reconstruction can reject either field drifting.
    pub members: Vec<[u8; 32]>,
    pub member_set: [u8; 32],
    pub reopened_control_state: Option<[u8; 32]>,
    pub applied_at: Option<u64>,
    pub application_invocation: Option<[u8; 32]>,
    pub application_ack: Option<[u8; 32]>,
    /// The latest exact PCA1 remains available for signed reconstruction.
    pub application_ack_bytes: Option<Vec<u8>>,
}

/// Compact, append-only PCA1 audit record. A cryptographic chain protects the
/// transition history while retaining every application invocation and PCA1
/// commitment for collision rejection and exact retry.
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
pub struct PrivateApplicationRecord {
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
    pub node: [u8; 32],
    pub node_identity: Option<[u8; 32]>,
    pub member_set: [u8; 32],
    pub reopened_control_state: [u8; 32],
    pub issued_at: u64,
    pub applied_at: u64,
}

#[derive(
    vos::rkyv::Archive, vos::rkyv::Serialize, vos::rkyv::Deserialize, Clone, Debug, PartialEq, Eq,
)]
#[rkyv(crate = vos::rkyv)]
pub struct AdminRetryRecord {
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
    epoch: u64,
    authorization_sequence: u64,
    administration_generation: u64,
    credentials: Vec<CredentialRow>,
    nodes: Vec<NodeOwnerRow>,
    roles: Vec<PrincipalRoleRow>,
    managed_agents: Vec<ManagedAgentRow>,
    managed_actors: Vec<ManagedActorRow>,
    retired_actor_installations: Vec<RetiredActorInstallationRow>,
    retries: Vec<ExactRetryRecord>,
    operation_retries: Vec<AuthorityOperationRetryRecord>,
    operation_retirement_floor: u64,
    operation_retirement_commitment: [u8; 32],
    retired_authority_operations: Vec<RetiredAuthorityOperationRow>,
    private_agents: Vec<PrivateAgentProjectionRow>,
    private_applications: Vec<PrivateApplicationRecord>,
    private_application_commitment: [u8; 32],
    admin_retries: Vec<AdminRetryRecord>,
}

impl AuthorityLinearState {
    fn inert() -> Self {
        Self {
            initialized: false,
            epoch: 0,
            authorization_sequence: 0,
            administration_generation: 0,
            credentials: Vec::new(),
            nodes: Vec::new(),
            roles: Vec::new(),
            managed_agents: Vec::new(),
            managed_actors: Vec::new(),
            retired_actor_installations: Vec::new(),
            retries: Vec::new(),
            operation_retries: Vec::new(),
            operation_retirement_floor: 0,
            operation_retirement_commitment: [0; 32],
            retired_authority_operations: Vec::new(),
            private_agents: Vec::new(),
            private_applications: Vec::new(),
            private_application_commitment: [0; 32],
            admin_retries: Vec::new(),
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
        });
        let mut nodes = Vec::with_capacity(1);
        nodes.push(NodeOwnerRow {
            node: config.bootstrap_node,
            owner: config.bootstrap_principal,
        });
        let mut roles = Vec::with_capacity(1);
        roles.push(PrincipalRoleRow {
            principal: config.bootstrap_principal,
            role: BuiltinPrincipalRole::Admin,
        });
        let mut managed_agents = Vec::with_capacity(1);
        managed_agents.push(root_managed_agent(config));
        Self {
            initialized: true,
            epoch: config.binding.initial_epoch,
            authorization_sequence: config.bootstrap_authorization_high_water,
            administration_generation: 1,
            credentials,
            nodes,
            roles,
            managed_agents,
            managed_actors: Vec::new(),
            retired_actor_installations: Vec::new(),
            retries: Vec::new(),
            operation_retries: Vec::new(),
            operation_retirement_floor: config.bootstrap_authorization_high_water,
            operation_retirement_commitment: initial_operation_retirement_commitment(config).0,
            retired_authority_operations: Vec::new(),
            private_agents: Vec::new(),
            private_applications: Vec::new(),
            private_application_commitment: initial_private_application_commitment(config).0,
            admin_retries: Vec::new(),
        }
    }
}

/// Linear policy state for one Space's built-in system Agent.
#[actor(agent, state_version = 7)]
pub struct SystemAuthority {
    #[state(const)]
    configuration: SystemAuthorityConfiguration,
    state: AuthorityLinearState,
}

#[messages(agent)]
impl SystemAuthority {
    fn new(configuration: &[u8]) -> Self {
        let Some(configuration) = SystemAuthorityConfiguration::decode(configuration) else {
            return Self {
                configuration: SystemAuthorityConfiguration::default(),
                state: AuthorityLinearState::inert(),
            };
        };
        Self {
            configuration,
            state: AuthorityLinearState::bootstrap(configuration),
        }
    }

    /// Verify and authorize one exact ACC1 call. Refusal is represented by an
    /// empty byte string and never mutates Linear state.
    #[msg(linear)]
    fn authorize(&mut self, call: Vec<u8>, ctx: &mut Context<Self>) -> Vec<u8> {
        let Some(context) = ctx.agent_invocation_context().copied() else {
            return Vec::new();
        };
        authorize_call(&self.configuration, &mut self.state, &call, &context)
    }

    /// Finalize a pending policy effect only after the durable issuer signs a
    /// canonical MAA1 post-reopen acknowledgement. Exact acknowledgement
    /// retries return `true` without changing state.
    #[msg(linear)]
    fn finalize(&mut self, ack: Vec<u8>, ctx: &mut Context<Self>) -> bool {
        let Some(context) = ctx.agent_invocation_context().copied() else {
            return false;
        };
        finalize_application(&self.configuration, &mut self.state, &ack, &context)
    }

    /// Verify one exact credential-signed AOC1 and return its canonical AOP1.
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

    /// Consume one authority-signed PCA1 only after its exact AOI1 chain is
    /// known. This advances the Private policy projection, never the global
    /// authorization clock or the management/catalog projections.
    #[msg(linear)]
    fn acknowledge_private_application(&mut self, ack: Vec<u8>, ctx: &mut Context<Self>) -> bool {
        let Some(context) = ctx.agent_invocation_context().copied() else {
            return false;
        };
        acknowledge_private_control_application(
            &self.configuration,
            &mut self.state,
            &ack,
            &context,
        )
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
}

struct Ed25519CredentialVerifier;

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

impl AuthorityVerifier for Ed25519CredentialVerifier {
    fn verify(&self, public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
        <Self as AuthorityCredentialVerifier>::verify(self, public_key, message, signature)
    }
}

fn exact_retry_count(state: &AuthorityLinearState) -> usize {
    state
        .retries
        .len()
        .saturating_add(state.operation_retries.len())
        .saturating_add(state.admin_retries.len())
}

fn authorize_call(
    configuration: &SystemAuthorityConfiguration,
    state: &mut AuthorityLinearState,
    encoded_call: &[u8],
    context: &InvocationContext,
) -> Vec<u8> {
    if encoded_call.len() > MAX_INVOCATION_MESSAGE_BYTES
        || !authority_state_is_valid(configuration, state)
    {
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
            if exact_retry_count(state) >= MAX_EXACT_RETRY_RECORDS {
                return Vec::new();
            }
            if !invocation_pair_is_available(state, call.invocation, acknowledgement_invocation) {
                return Vec::new();
            }

            let Some(role) = authenticated_role(state, &call) else {
                return Vec::new();
            };
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
                credential_call: call_commitment.0,
                credential_call_bytes: encoded_call.to_vec(),
                approval_commitment: approval.commitment().0,
                authorization_sequence,
                approval: approval_bytes.clone(),
                effect,
                finalized: false,
                acknowledgement: None,
                acknowledgement_bytes: None,
                reopened_state: None,
                applied_at: None,
            };
            // Every fallible check precedes this point. These two mutations
            // form the single Linear decision transition.
            state.authorization_sequence = authorization_sequence;
            state.retries.insert(index, record);
            // Management records remain in their own exact journal. They are
            // merely durable pass-through positions for the shared general
            // operation retirement floor.
            advance_operation_retirement_floor(state);
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
    if encoded_call.len() > MAX_INVOCATION_MESSAGE_BYTES
        || !authority_state_is_valid(configuration, state)
    {
        return Vec::new();
    }
    let Ok(call) = AuthorityOperationCall::decode(encoded_call) else {
        return Vec::new();
    };
    if !call.matches_invocation_context(context)
        || !authority_target_matches(configuration, &call.authority)
        || call.verify_with(&Ed25519CredentialVerifier).is_err()
    {
        return Vec::new();
    }

    let call_commitment = call.commitment();
    let acknowledgement_invocation =
        AuthorityOperationApproval::derive_acknowledgement_invocation(&call);
    match operation_retry_record(state, call.invocation) {
        Ok(index) => {
            let record = &state.operation_retries[index];
            if record.operation_call != call_commitment.0
                || record.operation_call_bytes != encoded_call
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
            // Once AOI1 has advanced the floor, the AOP1 bytes are
            // intentionally gone. A replayed retired AOC1 is rejected via its
            // collision tombstone; no approval is synthesized from hashes.
            if exact_retry_count(state) >= MAX_EXACT_RETRY_RECORDS
                || state.retired_authority_operations.len() >= MAX_RETIRED_AUTHORITY_OPERATIONS
                || !invocation_pair_is_available(state, call.invocation, acknowledgement_invocation)
            {
                return Vec::new();
            }
            let Some(role) = authenticated_operation_role(state, &call) else {
                return Vec::new();
            };
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
            state.authorization_sequence = authorization_sequence;
            state.operation_retries.insert(index, record);
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
    if encoded_call.len() > MAX_INVOCATION_MESSAGE_BYTES
        || !authority_state_is_valid(configuration, state)
    {
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

    let call_commitment = call.commitment();
    match admin_retry_record(state, call.invocation) {
        Ok(index) => {
            let record = &state.admin_retries[index];
            if record.call_commitment != call_commitment.0
                || record.call_bytes != encoded_call
                || record.invocation != call.invocation.0
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
            Vec::new()
        }
        Err(index) => {
            if exact_retry_count(state) >= MAX_EXACT_RETRY_RECORDS
                || !admin_invocation_is_available(state, call.invocation)
                || call.expected_generation.get() != state.administration_generation
                || !authenticated_admin(state, &call)
            {
                return Vec::new();
            }
            let Some(generation) = call.next_generation() else {
                return Vec::new();
            };
            let mut candidate = state.clone();
            if !apply_admin_operation(&mut candidate, &call.operation) {
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
            candidate.admin_retries.insert(
                index,
                AdminRetryRecord {
                    invocation: call.invocation.0,
                    call_commitment: call_commitment.0,
                    call_bytes: encoded_call.to_vec(),
                    result_commitment: result.commitment().0,
                    result_bytes: result_bytes.clone(),
                    generation: generation.get(),
                },
            );
            if !authority_state_is_valid(configuration, &candidate) {
                return Vec::new();
            }
            *state = candidate;
            result_bytes
        }
    }
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
    let Ok(node_index) = state
        .nodes
        .binary_search_by(|row| row.node.cmp(&call.authenticated_node.0))
    else {
        return false;
    };
    if state.nodes[node_index].owner != call.administrator.0 {
        return false;
    }
    state
        .roles
        .binary_search_by(|row| row.principal.cmp(&call.administrator.0))
        .ok()
        .is_some_and(|index| state.roles[index].role == BuiltinPrincipalRole::Admin)
}

fn apply_admin_operation(
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
            {
                return false;
            }
            state.credentials[index].status = CredentialStatus::Revoked;
        }
        AuthorityAdminOperation::BindNodeOwner { node, owner } => {
            if state.nodes.len() >= MAX_AUTHORITY_NODES
                || state
                    .roles
                    .binary_search_by(|row| row.principal.cmp(&owner.0))
                    .is_err()
            {
                return false;
            }
            let Err(index) = state.nodes.binary_search_by(|row| row.node.cmp(&node.0)) else {
                return false;
            };
            state.nodes.insert(
                index,
                NodeOwnerRow {
                    node: node.0,
                    owner: owner.0,
                },
            );
        }
        AuthorityAdminOperation::UnbindNodeOwner { node, owner } => {
            let Ok(index) = state.nodes.binary_search_by(|row| row.node.cmp(&node.0)) else {
                return false;
            };
            if state.nodes[index].owner != owner.0 {
                return false;
            }
            state.nodes.remove(index);
        }
        AuthorityAdminOperation::SetBuiltinRole { principal, role } => {
            let Ok(index) = state
                .roles
                .binary_search_by(|row| row.principal.cmp(&principal.0))
            else {
                return false;
            };
            let role = builtin_role(*role);
            if state.roles[index].role == role {
                return false;
            }
            state.roles[index].role = role;
        }
    }
    true
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
    }
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
    invocation: InvocationId,
) -> core::result::Result<usize, usize> {
    state
        .admin_retries
        .binary_search_by(|record| record.invocation.cmp(&invocation.0))
}

fn admin_invocation_is_available(state: &AuthorityLinearState, invocation: InvocationId) -> bool {
    invocation != InvocationId::ZERO
        && state
            .admin_retries
            .iter()
            .all(|record| record.invocation != invocation.0)
        && state.retries.iter().all(|record| {
            record.invocation != invocation.0 && record.acknowledgement_invocation != invocation.0
        })
        && state.operation_retries.iter().all(|record| {
            record.invocation != invocation.0
                && record.acknowledgement_invocation != invocation.0
                && record.private_application_invocation != Some(invocation.0)
        })
        && state.retired_authority_operations.iter().all(|record| {
            record.invocation != invocation.0
                && record.acknowledgement_invocation != invocation.0
                && record.private_application_invocation != Some(invocation.0)
        })
        && state
            .private_applications
            .iter()
            .all(|record| record.application_invocation != invocation.0)
}

fn finalize_application(
    configuration: &SystemAuthorityConfiguration,
    state: &mut AuthorityLinearState,
    encoded_ack: &[u8],
    context: &InvocationContext,
) -> bool {
    if encoded_ack.len() > MAX_INVOCATION_MESSAGE_BYTES
        || !authority_state_is_valid(configuration, state)
    {
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
    let ack_commitment = ack.commitment();

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
    if record.finalized {
        return record.invocation == ack.authorization_invocation.0
            && record.acknowledgement == Some(ack_commitment.0)
            && record.acknowledgement_bytes.as_deref() == Some(encoded_ack)
            && record.reopened_state == Some(ack.reopened_state.0)
            && record.applied_at == Some(ack.applied_at);
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
    let mut candidate = state.clone();
    apply_application_plan(&mut candidate, plan);
    let record = &mut candidate.retries[record_index];
    record.finalized = true;
    record.acknowledgement = Some(ack_commitment.0);
    record.acknowledgement_bytes = Some(encoded_ack.to_vec());
    record.reopened_state = Some(ack.reopened_state.0);
    record.applied_at = Some(ack.applied_at);
    if !authority_state_is_valid(configuration, &candidate) {
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
    if encoded_ack.len() > MAX_INVOCATION_MESSAGE_BYTES
        || !authority_state_is_valid(configuration, state)
    {
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
    let ack_commitment = ack.commitment();

    // A compact tombstone makes an exact AOI1 retry idempotent after its full
    // preimages have been retired. It deliberately cannot answer an AOC1
    // retry, because reconstructing AOP1 bytes from commitments is forbidden.
    if let Some(retired) = state
        .retired_authority_operations
        .iter()
        .find(|row| row.acknowledgement_invocation == ack.acknowledgement_invocation.0)
    {
        return retired.invocation == ack.authorization_invocation.0
            && retired.authorization_sequence == ack.authorization_sequence.get()
            && retired.issuance_ack == ack_commitment.0;
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
    if encoded_ack.len() > MAX_INVOCATION_MESSAGE_BYTES
        || !authority_state_is_valid(configuration, state)
    {
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
    if state.private_applications.len() >= MAX_PRIVATE_APPLICATION_RECORDS
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
        || managed.owner != source.principal
        || managed.authority != configuration.binding
        || !retired_private_operation_matches_application(&source, &ack.application)
    {
        return false;
    }
    // Offline Recover requires a separately authenticated recovery-proof
    // policy and is deliberately unavailable in this generation.
    if ack.application.operation == AuthorityOperationKind::RecoverPrivateAgent {
        return false;
    }
    let Some(node) = source.node else {
        return false;
    };
    let Ok(private_index) = private_agent(state, target.agent) else {
        return false;
    };
    let record = PrivateApplicationRecord {
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
        node,
        node_identity: source.node_identity,
        member_set: ack.application.post_member_set.0,
        reopened_control_state: ack.application.reopened_control_state.0,
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
    if !authority_state_is_valid(configuration, &candidate) {
        return false;
    }
    *state = candidate;
    true
}

fn private_application_source(
    configuration: &SystemAuthorityConfiguration,
    state: &AuthorityLinearState,
    ack: &PrivateControlApplicationAck,
) -> Option<RetiredPrivateOperationRow> {
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
        return retained_private_operation(&call);
    }

    let retired = state.retired_authority_operations.iter().find(|record| {
        record.acknowledgement_invocation == ack.issuance_invocation.0
            && record.invocation == ack.authorization_invocation.0
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
                InvocationId(retired.invocation),
                InvocationId(retired.acknowledgement_invocation),
                sequence,
                Hash(retired.issuance_ack),
                &Ed25519CredentialVerifier,
            )
            .is_err()
    {
        return None;
    }
    retired.private_operation
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
        ),
        AuthorityOperationIntent::RecoverPrivateAgent {
            control,
            control_sequence,
            control_previous,
            epoch,
            member_set,
            ..
        } => (
            AuthorityOperationKind::RecoverPrivateAgent,
            *control,
            *control_sequence,
            *control_previous,
            *epoch,
            None,
            None,
            Some(*member_set),
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
    })
}

fn retired_private_operation_matches_application(
    source: &RetiredPrivateOperationRow,
    application: &PrivateControlApplicationFact,
) -> bool {
    source.agent == application.managed.agent.0
        && source.runtime_deployment == application.managed.runtime_deployment.0
        && source.operation == application.operation as u8
        && source.control == application.control.0
        && source.control_sequence == application.control_sequence
        && source.control_previous == application.control_previous.map(|previous| previous.0)
        && source.epoch == application.epoch
        && source
            .post_member_set
            .is_none_or(|member_set| member_set == application.post_member_set.0)
}

fn member_set_commitment(members: &[[u8; 32]]) -> Option<Hash> {
    private_member_set_commitment(members.iter().copied().map(vos::agent_sdk::NodeId))
}

fn next_private_members(
    projection: &PrivateAgentProjectionRow,
    operation: u8,
    node: [u8; 32],
) -> Option<(Vec<[u8; 32]>, Hash)> {
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
    let expected_sequence = match projection.control_sequence {
        Some(sequence) => sequence.checked_add(1),
        None => Some(0),
    };
    let expected_previous = projection.control_head;
    let valid_epoch = if record.operation == AuthorityOperationKind::InvitePrivateNode as u8 {
        record.epoch == projection.epoch
    } else if record.operation == AuthorityOperationKind::RevokePrivateNode as u8 {
        projection.epoch.checked_add(1) == Some(record.epoch)
    } else {
        false
    };
    let Some((members, member_set)) =
        next_private_members(projection, record.operation, record.node)
    else {
        return false;
    };
    if projection.agent != record.agent
        || projection.owner != record.owner
        || expected_sequence != Some(record.control_sequence)
        || expected_previous != record.control_previous
        || !valid_epoch
        || record.member_set != member_set.0
        || projection
            .applied_at
            .is_some_and(|applied_at| record.applied_at <= applied_at)
    {
        return false;
    }
    projection.control_head = Some(record.control);
    projection.control_sequence = Some(record.control_sequence);
    projection.epoch = record.epoch;
    projection.members = members;
    projection.member_set = record.member_set;
    projection.reopened_control_state = Some(record.reopened_control_state);
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
        // ACC1/MAP1/MAA1 rows remain byte-exactly retained in their separate
        // journal. A management position merely proves there is no general
        // AOC1/AOP1 material to retire at this shared sequence number.
        if state
            .retries
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
        if state.retired_authority_operations.len() >= MAX_RETIRED_AUTHORITY_OPERATIONS {
            return false;
        }
        let retired = RetiredAuthorityOperationRow {
            invocation: record.invocation,
            acknowledgement_invocation: record.acknowledgement_invocation,
            authorization_sequence: record.authorization_sequence,
            operation_call: record.operation_call,
            approval: record.approval_commitment,
            issuance_ack,
            issued_at,
            private_application_invocation: record.private_application_invocation,
            private_operation: retained_private_operation(&call),
        };
        // The durable floor is advanced before the retireable AOC1/AOP1/AOI1
        // buffers are removed. Actor state commits atomically, while this
        // ordering preserves the protocol's reopen rule explicitly.
        state.operation_retirement_floor = next;
        state.operation_retirement_commitment =
            operation_retirement_commitment(Hash(state.operation_retirement_commitment), &retired)
                .0;
        state.retired_authority_operations.push(retired);
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
            let ManagementRequest::Create(descriptor) = &call.request else {
                return None;
            };
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
                        control_head: None,
                        control_sequence: None,
                        epoch: 0,
                        members,
                        member_set: member_set.0,
                        reopened_control_state: None,
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
        PendingManagementEffect::InstallActor { .. } => {
            let ManagementRequest::Install(install) = &call.request else {
                return None;
            };
            let root_provenance = call.managed.agent.0 == configuration.system_agent
                && acknowledgement.authorization_sequence.get()
                    == configuration
                        .bootstrap_authorization_high_water
                        .checked_add(1)?;
            let row = installed_actor_row(call.managed.agent, install, root_provenance);
            let index = managed_actor(state, call.managed.agent, install.entry.actor).err()?;
            Some(ApplicationPlan::InstallActor { index, row })
        }
        PendingManagementEffect::UpgradeActor { .. } => {
            let ManagementRequest::UpgradeActor(upgrade) = &call.request else {
                return None;
            };
            let index = managed_actor(state, call.managed.agent, upgrade.actor).ok()?;
            let row = upgraded_actor_row(&state.managed_actors[index], upgrade)?;
            Some(ApplicationPlan::ReplaceActor { index, row })
        }
        PendingManagementEffect::SetActorSuspended { suspended, .. } => {
            let (actor, expected_deployment, requested_suspended) = match &call.request {
                ManagementRequest::Suspend {
                    actor,
                    expected_deployment,
                } => (*actor, *expected_deployment, true),
                ManagementRequest::Resume {
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
            Some(ApplicationPlan::ReplaceActor { index, row })
        }
        PendingManagementEffect::RemoveActor { .. } => {
            let ManagementRequest::RemoveLeaf {
                actor,
                expected_deployment,
            } = &call.request
            else {
                return None;
            };
            let index = managed_actor(state, call.managed.agent, *actor).ok()?;
            let row = &state.managed_actors[index];
            if row.deployment != expected_deployment.0
                || state.retired_actor_installations.len() >= MAX_RETIRED_ACTOR_INSTALLATIONS
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
            Some(ApplicationPlan::UpgradeRuntime {
                index,
                private_index,
                to_deployment: *to_deployment,
                to_program: *to_program,
                producer: *producer,
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
        } => {
            let row = &mut state.managed_agents[index];
            row.runtime_deployment = to_deployment;
            row.runtime_program = to_program;
            row.runtime_producer = producer;
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
        && state.retries.iter().all(|record| {
            record.invocation != authorization.0
                && record.invocation != acknowledgement.0
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
        && state.retired_authority_operations.iter().all(|record| {
            record.invocation != authorization.0
                && record.invocation != acknowledgement.0
                && record.acknowledgement_invocation != authorization.0
                && record.acknowledgement_invocation != acknowledgement.0
                && record.private_application_invocation != Some(authorization.0)
                && record.private_application_invocation != Some(acknowledgement.0)
        })
        && state.admin_retries.iter().all(|record| {
            record.invocation != authorization.0 && record.invocation != acknowledgement.0
        })
        && state.private_applications.iter().all(|record| {
            record.application_invocation != authorization.0
                && record.application_invocation != acknowledgement.0
        })
}

fn private_application_invocation_is_unreserved(
    state: &AuthorityLinearState,
    application: InvocationId,
) -> bool {
    application != InvocationId::ZERO
        && state.retries.iter().all(|record| {
            record.invocation != application.0 && record.acknowledgement_invocation != application.0
        })
        && state.operation_retries.iter().all(|record| {
            record.invocation != application.0
                && record.acknowledgement_invocation != application.0
                && record.private_application_invocation != Some(application.0)
        })
        && state.retired_authority_operations.iter().all(|record| {
            record.invocation != application.0
                && record.acknowledgement_invocation != application.0
                && record.private_application_invocation != Some(application.0)
        })
        && state
            .admin_retries
            .iter()
            .all(|record| record.invocation != application.0)
        && state
            .private_applications
            .iter()
            .all(|record| record.application_invocation != application.0)
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
    state: &AuthorityLinearState,
    call: &AuthorityOperationCall,
) -> Option<BuiltinPrincipalRole> {
    authenticated_credential_role(
        state,
        call.principal,
        call.credential,
        &call.credential_public_key,
        call.authenticated_node,
    )
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
        let node = state
            .nodes
            .binary_search_by(|row| row.node.cmp(&node.0))
            .ok()
            .map(|index| &state.nodes[index])?;
        if node.owner != principal.0 {
            return None;
        }
    }
    state
        .roles
        .binary_search_by(|row| row.principal.cmp(&principal.0))
        .ok()
        .map(|index| state.roles[index].role)
}

fn policy_effect(
    configuration: &SystemAuthorityConfiguration,
    state: &AuthorityLinearState,
    call: &AuthorityCredentialCall,
    role: BuiltinPrincipalRole,
) -> Option<PendingManagementEffect> {
    match &call.request {
        ManagementRequest::Create(descriptor) => {
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
            Some(PendingManagementEffect::Create(ManagedAgentRow {
                agent: descriptor.identity.agent.0,
                owner: descriptor.identity.owner.0,
                profile: descriptor.identity.profile as u8,
                runtime_deployment: descriptor.identity.runtime_deployment.0,
                runtime_program: descriptor.identity.runtime_program.0,
                runtime_producer: descriptor.identity.runtime_producer.0,
                authority: configuration.binding,
            }))
        }
        ManagementRequest::InspectActors { .. } | ManagementRequest::InspectResources => None,
        ManagementRequest::Install(_)
        | ManagementRequest::UpgradeActor(_)
        | ManagementRequest::Suspend { .. }
        | ManagementRequest::Resume { .. }
        | ManagementRequest::RemoveLeaf { .. } => {
            lifecycle_owner(configuration, state, call, role)?;
            if pending_runtime_transition_conflicts(state, call)
                || pending_actor_effect_conflicts(state, call)
            {
                return None;
            }
            projected_actor_effect(configuration, state, call)
        }
        ManagementRequest::ChangeReplicas { .. } => {
            let row = lifecycle_owner(configuration, state, call, role)?;
            if row.profile == AgentProfile::Private as u8
                || pending_runtime_transition_conflicts(state, call)
            {
                return None;
            }
            Some(PendingManagementEffect::None)
        }
        ManagementRequest::UpgradeRuntime(upgrade) => {
            let row = lifecycle_owner(configuration, state, call, role)?;
            if pending_runtime_transition_conflicts(state, call) {
                return None;
            }
            Some(PendingManagementEffect::UpgradeRuntime {
                agent: row.agent,
                from_deployment: row.runtime_deployment,
                to_deployment: upgrade.to_deployment.0,
                to_program: upgrade.to_program.0,
                producer: upgrade.producer.0,
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
        || managed.runtime_deployment != target.runtime_deployment.0
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
            // This generation has no durable arbitrary RoleId or delegated
            // capability table. Only the credential identity itself is
            // provable, so richer origin/role claims fail closed.
            if origin.actor.is_some()
                || origin.capability.is_some()
                || *roles != InvocationRoleClaims::none()
            {
                return false;
            }
            managed_actor(state, target.agent, *actor)
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
                && state.private_applications.len() < MAX_PRIVATE_APPLICATION_RECORDS
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
                    node.0,
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
                node.0,
            );
            managed.profile == AgentProfile::Private as u8
                && managed.owner == call.principal.0
                && projection.owner == managed.owner
                && projection.runtime_deployment == managed.runtime_deployment
                && state.private_applications.len() < MAX_PRIVATE_APPLICATION_RECORDS
                && !outstanding_private_operation_exists(state, target.agent)
                && private_control_position_is_next(
                    projection,
                    *control_sequence,
                    *control_previous,
                )
                && projection.epoch.checked_add(1) == Some(*epoch)
                && next_members.is_some_and(|(_, expected)| expected == *member_set)
        }
        // The AOC1 projection commits recovery evidence but does not prove a
        // recovery kit or the current private control-chain head. Until an
        // authenticated application fact supplies those checks, recovery is
        // not authorizable here; Admin credentials never substitute for keys.
        AuthorityOperationIntent::RecoverPrivateAgent { .. } => false,
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

fn outstanding_private_operation_exists(state: &AuthorityLinearState, agent: AgentId) -> bool {
    state.operation_retries.iter().any(|record| {
        AuthorityOperationCall::decode(&record.operation_call_bytes)
            .ok()
            .and_then(|call| retained_private_operation(&call))
            .is_some_and(|private| {
                private.agent == agent.0
                    && !private_operation_source_is_applied(
                        state,
                        record.invocation,
                        record.acknowledgement_invocation,
                        record.authorization_sequence,
                    )
            })
    }) || state.retired_authority_operations.iter().any(|record| {
        record.private_operation.is_some_and(|private| {
            private.agent == agent.0
                && !private_operation_source_is_applied(
                    state,
                    record.invocation,
                    record.acknowledgement_invocation,
                    record.authorization_sequence,
                )
        })
    })
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

fn live_and_pending_agent_count(state: &AuthorityLinearState) -> usize {
    state.managed_agents.len()
        + state
            .retries
            .iter()
            .filter(|record| {
                !record.finalized && matches!(record.effect, PendingManagementEffect::Create(_))
            })
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

fn pending_actor_effect_conflicts(
    state: &AuthorityLinearState,
    call: &AuthorityCredentialCall,
) -> bool {
    let (actor, installation, parent, disrupts_children) = match &call.request {
        ManagementRequest::Install(install) => {
            if state.managed_actors.len()
                + state
                    .retries
                    .iter()
                    .filter(|record| {
                        record.invocation != call.invocation.0
                            && !record.finalized
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
        ManagementRequest::UpgradeActor(upgrade) => (upgrade.actor, None, None, false),
        ManagementRequest::Suspend { actor, .. } | ManagementRequest::RemoveLeaf { actor, .. } => {
            (*actor, None, None, true)
        }
        ManagementRequest::Resume { actor, .. } => (*actor, None, None, false),
        _ => return false,
    };
    state.retries.iter().any(|record| {
        if record.invocation == call.invocation.0 || record.finalized {
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
    let incoming_runtime_upgrade = matches!(&call.request, ManagementRequest::UpgradeRuntime(_));
    state.retries.iter().any(|record| {
        if record.invocation == call.invocation.0 || record.finalized {
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
            PendingManagementEffect::InstallActor { agent, .. }
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
    match &call.request {
        ManagementRequest::Install(install) => {
            if protected_authority_actor(configuration, install.entry.actor)
                || install.entry.suspended
                || install.validate_for_profile(profile).is_err()
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
        ManagementRequest::UpgradeActor(upgrade) => {
            if protected_authority_actor(configuration, upgrade.actor)
                || !upgrade.requirements.supported_by(profile)
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
        ManagementRequest::Suspend {
            actor,
            expected_deployment,
        }
        | ManagementRequest::Resume {
            actor,
            expected_deployment,
        } => {
            if protected_authority_actor(configuration, *actor) {
                return None;
            }
            let row = &state.managed_actors[managed_actor(state, agent, *actor).ok()?];
            let suspended = matches!(&call.request, ManagementRequest::Suspend { .. });
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
        ManagementRequest::RemoveLeaf {
            actor,
            expected_deployment,
        } => {
            if protected_authority_actor(configuration, *actor)
                || state.retired_actor_installations.len() >= MAX_RETIRED_ACTOR_INSTALLATIONS
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

fn installed_actor_row(
    agent: AgentId,
    install: &vos::agent_sdk::InstallActor,
    root_provenance: bool,
) -> ManagedActorRow {
    let request = ManagementRequest::Install(Box::new(install.clone()));
    ManagedActorRow {
        agent: agent.0,
        actor: install.entry.actor.0,
        name: install.entry.name.clone(),
        parent: install.entry.parent.map(|value| value.0),
        deployment: install.entry.deployment.0,
        program: install.entry.program.0,
        producer: install.producer.0,
        package: authority_blob(&install.package),
        agent_schema: authority_blob(&install.agent_schema),
        method_policy: authority_blob(&install.method_policy),
        constructor_abi: install.constructor_abi.0,
        installation_data: install
            .installation_data
            .as_ref()
            .map(|data| authority_blob(&data.reference)),
        state_layout: install.state_layout.0,
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
        install_request: request.commitment().0,
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
        let Some(profile) = agent_profile(state.managed_agents[agent_index].profile) else {
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

fn initial_operation_retirement_commitment(configuration: SystemAuthorityConfiguration) -> Hash {
    Hash::digest(
        b"vos/system-authority/operation-retirement-root/v2",
        &[RUNTIME_ABI_ID.as_bytes(), &configuration.encode()],
    )
}

fn operation_retirement_commitment(previous: Hash, record: &RetiredAuthorityOperationRow) -> Hash {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&record.invocation);
    bytes.extend_from_slice(&record.acknowledgement_invocation);
    bytes.extend_from_slice(&record.authorization_sequence.to_le_bytes());
    bytes.extend_from_slice(&record.operation_call);
    bytes.extend_from_slice(&record.approval);
    bytes.extend_from_slice(&record.issuance_ack);
    bytes.extend_from_slice(&record.issued_at.to_le_bytes());
    encode_optional_hash(&mut bytes, record.private_application_invocation);
    if let Some(private) = record.private_operation {
        bytes.push(1);
        bytes.extend_from_slice(&private.agent);
        bytes.extend_from_slice(&private.runtime_deployment);
        bytes.extend_from_slice(&private.principal);
        bytes.push(private.operation);
        bytes.extend_from_slice(&private.control);
        bytes.extend_from_slice(&private.control_sequence.to_le_bytes());
        encode_optional_hash(&mut bytes, private.control_previous);
        bytes.extend_from_slice(&private.epoch.to_le_bytes());
        encode_optional_hash(&mut bytes, private.node);
        encode_optional_hash(&mut bytes, private.node_identity);
        encode_optional_hash(&mut bytes, private.post_member_set);
    } else {
        bytes.push(0);
    }
    Hash::digest(
        b"vos/system-authority/operation-retirement/v2",
        &[previous.as_bytes(), &bytes],
    )
}

fn encode_optional_hash(bytes: &mut Vec<u8>, value: Option<[u8; 32]>) {
    if let Some(value) = value {
        bytes.push(1);
        bytes.extend_from_slice(&value);
    } else {
        bytes.push(0);
    }
}

fn operation_retirement_chain_is_valid(
    configuration: &SystemAuthorityConfiguration,
    state: &AuthorityLinearState,
) -> bool {
    let mut commitment = initial_operation_retirement_commitment(*configuration);
    for record in &state.retired_authority_operations {
        commitment = operation_retirement_commitment(commitment, record);
    }
    commitment.0 == state.operation_retirement_commitment
}

fn initial_private_application_commitment(configuration: SystemAuthorityConfiguration) -> Hash {
    Hash::digest(
        b"vos/system-authority/private-application-root/v1",
        &[RUNTIME_ABI_ID.as_bytes(), &configuration.encode()],
    )
}

fn private_application_commitment(previous: Hash, record: &PrivateApplicationRecord) -> Hash {
    let mut bytes = Vec::new();
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
    bytes.extend_from_slice(&record.node);
    encode_optional_hash(&mut bytes, record.node_identity);
    bytes.extend_from_slice(&record.member_set);
    bytes.extend_from_slice(&record.reopened_control_state);
    bytes.extend_from_slice(&record.issued_at.to_le_bytes());
    bytes.extend_from_slice(&record.applied_at.to_le_bytes());
    Hash::digest(
        b"vos/system-authority/private-application/v1",
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
        _ => None,
    }
}

fn retired_private_operation_is_valid(row: RetiredPrivateOperationRow) -> bool {
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
    } else if row.operation == AuthorityOperationKind::RevokePrivateNode as u8 {
        row.node.is_some_and(|node| node != [0; 32])
            && row.node_identity.is_none()
            && row
                .post_member_set
                .is_some_and(|member_set| member_set != [0; 32])
    } else {
        // Recovery AOC1 remains un-authorizable until an offline recovery
        // proof policy exists, so a retired Recover tombstone is unbacked.
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
    record: &PrivateApplicationRecord,
) -> Option<PrivateControlApplicationFact> {
    let fact = PrivateControlApplicationFact {
        managed: ManagedAgentTarget {
            space: SpaceId(configuration.space),
            agent: AgentId(record.agent),
            runtime_deployment: DeploymentId(record.runtime_deployment),
        },
        operation: private_operation_kind(record.operation)?,
        control: Hash(record.control),
        control_sequence: record.control_sequence,
        control_previous: record.control_previous.map(Hash),
        epoch: record.epoch,
        post_member_set: Hash(record.member_set),
        reopened_control_state: Hash(record.reopened_control_state),
        reopened_control_head: Hash(record.control),
        applied_at: record.applied_at,
    };
    fact.validate_shape().is_ok().then_some(fact)
}

fn private_application_record_source(
    configuration: &SystemAuthorityConfiguration,
    state: &AuthorityLinearState,
    record: &PrivateApplicationRecord,
) -> Option<RetiredPrivateOperationRow> {
    let fact = private_application_fact(configuration, record)?;
    let source = if let Some(active) = state.operation_retries.iter().find(|source| {
        source.invocation == record.authorization_invocation
            && source.acknowledgement_invocation == record.issuance_invocation
    }) {
        if active.authorization_sequence != record.authorization_sequence
            || active.operation_call != record.operation_call
            || active.approval_commitment != record.approval
            || active.issuance_ack != Some(record.issuance_ack)
            || active.issued_at != Some(record.issued_at)
            || active.private_application_invocation != Some(record.application_invocation)
        {
            return None;
        }
        let call = AuthorityOperationCall::decode(&active.operation_call_bytes).ok()?;
        retained_private_operation(&call)?
    } else {
        let retired = state.retired_authority_operations.iter().find(|source| {
            source.invocation == record.authorization_invocation
                && source.acknowledgement_invocation == record.issuance_invocation
        })?;
        if retired.authorization_sequence != record.authorization_sequence
            || retired.operation_call != record.operation_call
            || retired.approval != record.approval
            || retired.issuance_ack != record.issuance_ack
            || retired.issued_at != record.issued_at
            || retired.private_application_invocation != Some(record.application_invocation)
        {
            return None;
        }
        retired.private_operation?
    };
    (source.principal == record.owner
        && source.node == Some(record.node)
        && source.node_identity == record.node_identity
        && retired_private_operation_matches_application(&source, &fact))
    .then_some(source)
}

fn private_genesis_projection(
    state: &AuthorityLinearState,
    managed: &ManagedAgentRow,
) -> Option<PrivateAgentProjectionRow> {
    if managed.profile != AgentProfile::Private as u8 {
        return None;
    }
    let mut descriptor = None;
    for record in &state.retries {
        if !record.finalized
            || !matches!(
                &record.effect,
                PendingManagementEffect::Create(row) if row.agent == managed.agent
            )
        {
            continue;
        }
        if descriptor.is_some() {
            return None;
        }
        let call = AuthorityCredentialCall::decode(&record.credential_call_bytes).ok()?;
        let ManagementRequest::Create(candidate) = call.request else {
            return None;
        };
        descriptor = Some(candidate);
    }
    let descriptor = descriptor?;
    if descriptor.identity.agent.0 != managed.agent
        || descriptor.identity.owner.0 != managed.owner
        || descriptor.identity.profile != AgentProfile::Private
    {
        return None;
    }
    let members = descriptor
        .replicas
        .iter()
        .map(|replica| replica.node.0)
        .collect::<Vec<_>>();
    let member_set = member_set_commitment(&members)?;
    Some(PrivateAgentProjectionRow {
        agent: managed.agent,
        owner: managed.owner,
        runtime_deployment: managed.runtime_deployment,
        control_head: None,
        control_sequence: None,
        epoch: 0,
        members,
        member_set: member_set.0,
        reopened_control_state: None,
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
        && left.control_head == right.control_head
        && left.control_sequence == right.control_sequence
        && left.epoch == right.epoch
        && left.members == right.members
        && left.member_set == right.member_set
        && left.reopened_control_state == right.reopened_control_state
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
        || state.private_applications.len() > MAX_PRIVATE_APPLICATION_RECORDS
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
            && row.reopened_control_state.is_none()
            && row.applied_at.is_none()
            && row.application_invocation.is_none()
            && row.application_ack.is_none()
            && row.application_ack_bytes.is_none();
        let applied = row.control_head.is_some()
            && row.control_sequence.is_some()
            && row.reopened_control_state.is_some()
            && row.applied_at.is_some()
            && row.application_invocation.is_some()
            && row.application_ack.is_some()
            && row.application_ack_bytes.is_some();
        if managed.profile != AgentProfile::Private as u8
            || managed.owner != row.owner
            || managed.runtime_deployment != row.runtime_deployment
            || row.members.is_empty()
            || row.members.len() > MAX_PRIVATE_NODES
            || row.members.iter().any(|node| *node == [0; 32])
            || !row.members.windows(2).all(|pair| pair[0] < pair[1])
            || member_set_commitment(&row.members).map(|commitment| commitment.0)
                != Some(row.member_set)
            || row.member_set == [0; 32]
            || (!genesis && !applied)
            || (genesis && row.epoch != 0)
            || row.control_head == Some([0; 32])
            || row.reopened_control_state == Some([0; 32])
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
    application_ids.sort_unstable();
    if application_ids.windows(2).any(|pair| pair[0] == pair[1]) {
        return false;
    }
    let mut source_sequences = state
        .private_applications
        .iter()
        .map(|record| record.authorization_sequence)
        .collect::<Vec<_>>();
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
                record
                    .node_identity
                    .is_some_and(|identity| identity != [0; 32])
            } else if record.operation == AuthorityOperationKind::RevokePrivateNode as u8 {
                record.node_identity.is_none()
            } else {
                false
            };
        if record.application_invocation == [0; 32]
            || record.application_ack == [0; 32]
            || record.operation_call == [0; 32]
            || record.approval == [0; 32]
            || record.issuance_ack == [0; 32]
            || record.owner == [0; 32]
            || record.node == [0; 32]
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
        let Some(source) = private_application_source(configuration, state, &ack) else {
            return false;
        };
        if ack.encode().ok().as_deref() != Some(encoded)
            || ack.application_invocation.0 != application_invocation
            || ack.commitment().0 != record.application_ack
            || ack.application != private_application_fact(configuration, record).unwrap()
            || source.principal != row.owner
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
        && state.epoch >= configuration.binding.initial_epoch
        && state.epoch != 0
        && state.administration_generation != 0
        && state.credentials.len() <= MAX_AUTHORITY_CREDENTIALS
        && state.nodes.len() <= MAX_AUTHORITY_NODES
        && state.roles.len() <= MAX_AUTHORITY_PRINCIPALS
        && state.managed_agents.len() <= MAX_MANAGED_AGENTS
        && state.managed_actors.len() <= MAX_MANAGED_ACTORS
        && state.retired_actor_installations.len() <= MAX_RETIRED_ACTOR_INSTALLATIONS
        && exact_retry_count(state) <= MAX_EXACT_RETRY_RECORDS
        && state.retired_authority_operations.len() <= MAX_RETIRED_AUTHORITY_OPERATIONS
        && state.private_agents.len() <= MAX_MANAGED_AGENTS
        && state.private_applications.len() <= MAX_PRIVATE_APPLICATION_RECORDS
        && state.operation_retirement_floor >= configuration.bootstrap_authorization_high_water
        && state.operation_retirement_floor <= state.authorization_sequence
        && state.operation_retirement_commitment != [0; 32]
        && state.private_application_commitment != [0; 32]
        && sorted_unique_by(&state.credentials, |row| row.credential)
        && sorted_unique_by(&state.nodes, |row| row.node)
        && sorted_unique_by(&state.roles, |row| row.principal)
        && sorted_unique_by(&state.managed_agents, |row| row.agent)
        && sorted_unique_by(&state.retries, |row| row.invocation)
        && sorted_unique_by(&state.operation_retries, |row| row.invocation)
        && state
            .retired_authority_operations
            .windows(2)
            .all(|pair| pair[0].authorization_sequence < pair[1].authorization_sequence)
        && sorted_unique_by(&state.admin_retries, |row| row.invocation)
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
        && state.nodes.iter().all(|row| {
            row.node != [0; 32]
                && row.owner != [0; 32]
                && state
                    .roles
                    .binary_search_by(|role| role.principal.cmp(&row.owner))
                    .is_ok()
        })
        && state.roles.iter().all(|row| {
            row.principal != [0; 32]
                && state.credentials.iter().any(|credential| {
                    credential.principal == row.principal
                        && credential.status == CredentialStatus::Active
                })
        })
        && accessible_admin_exists(state)
        && state.managed_agents.iter().all(|row| {
            row.agent != [0; 32]
                && row.owner != [0; 32]
                && matches!(row.profile, 0..=2)
                && row.runtime_deployment != [0; 32]
                && row.runtime_program != [0; 32]
                && row.runtime_producer != [0; 32]
                && row.authority == configuration.binding
                && state
                    .roles
                    .binary_search_by(|role| role.principal.cmp(&row.owner))
                    .is_ok()
        })
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
        && state.retired_authority_operations.iter().all(|row| {
            row.invocation != [0; 32]
                && row.acknowledgement_invocation != [0; 32]
                && row.invocation != row.acknowledgement_invocation
                && row.authorization_sequence > configuration.bootstrap_authorization_high_water
                && row.authorization_sequence <= state.operation_retirement_floor
                && row.operation_call != [0; 32]
                && row.approval != [0; 32]
                && row.issuance_ack != [0; 32]
                && retired_operation_private_application_shape_is_valid(configuration, row)
        })
        && state
            .admin_retries
            .iter()
            .all(|row| admin_retry_shape_is_valid(configuration, state, row))
        && state.administration_generation
            == u64::try_from(state.admin_retries.len())
                .ok()
                .and_then(|count| count.checked_add(1))
                .unwrap_or(0)
        && admin_generations_are_unique(&state.admin_retries)
        && all_invocation_identifiers_are_unique(state)
        && operation_retirement_chain_is_valid(configuration, state)
        && private_projection_is_valid(configuration, state)
        && admin_history_reconstructs_identity(configuration, state)
        && authorization_history_reconstructs_policy(configuration, state)
}

enum AuthorizationHistoryRecord<'a> {
    Management(&'a ExactRetryRecord),
    Operation(&'a AuthorityOperationRetryRecord),
    RetiredOperation(&'a RetiredAuthorityOperationRow),
}

impl AuthorizationHistoryRecord<'_> {
    fn sequence(&self) -> u64 {
        match self {
            Self::Management(record) => record.authorization_sequence,
            Self::Operation(record) => record.authorization_sequence,
            Self::RetiredOperation(record) => record.authorization_sequence,
        }
    }
}

fn authorization_history_reconstructs_policy(
    configuration: &SystemAuthorityConfiguration,
    state: &AuthorityLinearState,
) -> bool {
    let mut replay = AuthorityLinearState::bootstrap(*configuration);
    // Identity history is reconstructed independently. General-operation
    // records retain the role actually used at admission, while management
    // Create effects still require their owner to remain enrolled.
    replay.credentials.clone_from(&state.credentials);
    replay.nodes.clone_from(&state.nodes);
    replay.roles.clone_from(&state.roles);
    let mut history = Vec::with_capacity(
        state
            .retries
            .len()
            .saturating_add(state.operation_retries.len())
            .saturating_add(state.retired_authority_operations.len()),
    );
    history.extend(
        state
            .retries
            .iter()
            .map(AuthorizationHistoryRecord::Management),
    );
    history.extend(
        state
            .operation_retries
            .iter()
            .map(AuthorizationHistoryRecord::Operation),
    );
    history.extend(
        state
            .retired_authority_operations
            .iter()
            .map(AuthorizationHistoryRecord::RetiredOperation),
    );
    history.sort_unstable_by_key(AuthorizationHistoryRecord::sequence);
    let mut private_applications = state.private_applications.iter().collect::<Vec<_>>();
    private_applications.sort_unstable_by_key(|record| record.authorization_sequence);
    let mut private_application_index = 0;
    let Some(expected_history_len) = state
        .authorization_sequence
        .checked_sub(configuration.bootstrap_authorization_high_water)
        .and_then(|len| usize::try_from(len).ok())
    else {
        return false;
    };
    if history.len() != expected_history_len {
        return false;
    }

    let mut expected_floor = configuration.bootstrap_authorization_high_water;
    let mut floor_blocked = false;
    for history_record in history {
        let Some(expected_sequence) = replay.authorization_sequence.checked_add(1) else {
            return false;
        };
        if history_record.sequence() != expected_sequence {
            return false;
        }
        while private_application_index < private_applications.len()
            && private_applications[private_application_index].authorization_sequence
                < expected_sequence
        {
            if !apply_private_application_for_policy_reconstruction(
                configuration,
                &mut replay,
                private_applications[private_application_index],
            ) {
                return false;
            }
            private_application_index += 1;
        }
        match history_record {
            AuthorizationHistoryRecord::Management(record) => {
                let Ok(call) = AuthorityCredentialCall::decode(&record.credential_call_bytes)
                else {
                    return false;
                };
                let Ok(approval) = ManagementApproval::decode(&record.approval) else {
                    return false;
                };
                if call.invocation.0 != record.invocation
                    || call.commitment().0 != record.credential_call
                    || call.encode().ok().as_deref()
                        != Some(record.credential_call_bytes.as_slice())
                    || call.verify_with(&Ed25519CredentialVerifier).is_err()
                    || !authority_target_matches(configuration, &call.authority)
                    || approval.commitment().0 != record.approval_commitment
                    || approval.encode().ok().as_deref() != Some(record.approval.as_slice())
                    || approval.authorization_sequence.get() != record.authorization_sequence
                    || approval.acknowledgement_invocation.0 != record.acknowledgement_invocation
                    || !approval.matches_call(&call)
                    || reconstruction_effect(configuration, &replay, &call).as_ref()
                        != Some(&record.effect)
                {
                    return false;
                }
                replay.authorization_sequence = expected_sequence;
                if record.finalized {
                    let Some(encoded_ack) = record.acknowledgement_bytes.as_deref() else {
                        return false;
                    };
                    let Ok(ack) = ManagementApplicationAck::decode(encoded_ack) else {
                        return false;
                    };
                    if ack.commitment().0 != record.acknowledgement.unwrap_or([0; 32])
                        || ack.encode().ok().as_deref() != Some(encoded_ack)
                        || ack.verify_with(&Ed25519CredentialVerifier).is_err()
                        || !authority_target_matches(configuration, &ack.authority)
                        || !ack.matches_pending(&call, &approval)
                    {
                        return false;
                    }
                    let Some(plan) =
                        application_plan(configuration, &replay, &record.effect, &call, &ack)
                    else {
                        return false;
                    };
                    apply_application_plan(&mut replay, plan);
                }
                replay.retries.push(record.clone());
                if !floor_blocked {
                    expected_floor = expected_sequence;
                }
            }
            AuthorizationHistoryRecord::Operation(record) => {
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
                if call.invocation.0 != record.invocation
                    || call.commitment().0 != record.operation_call
                    || call.encode().ok().as_deref() != Some(record.operation_call_bytes.as_slice())
                    || call.verify_with(&Ed25519CredentialVerifier).is_err()
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
                    || !operation_policy_allows(configuration, &replay, &call, record.role)
                {
                    return false;
                }
                if let Some(encoded_ack) = record.issuance_ack_bytes.as_deref() {
                    let Ok(ack) = AuthorityOperationIssuanceAck::decode(encoded_ack) else {
                        return false;
                    };
                    if ack.commitment().0 != record.issuance_ack.unwrap_or([0; 32])
                        || ack.encode().ok().as_deref() != Some(encoded_ack)
                        || ack.issued_at != record.issued_at.unwrap_or(u64::MAX)
                        || !ack.matches_pending(&call, &approval)
                        || ack
                            .verify_with(configuration.binding.sdk(), &Ed25519CredentialVerifier)
                            .is_err()
                    {
                        return false;
                    }
                }
                replay.authorization_sequence = expected_sequence;
                replay.operation_retries.push(record.clone());
                if !floor_blocked {
                    // An acknowledged adjacent record would already have
                    // compacted. The first retained operation is therefore
                    // the unique unacknowledged floor gap.
                    if record.issuance_ack.is_some() {
                        return false;
                    }
                    floor_blocked = true;
                }
            }
            AuthorizationHistoryRecord::RetiredOperation(record) => {
                if floor_blocked {
                    return false;
                }
                replay.authorization_sequence = expected_sequence;
                replay.retired_authority_operations.push(*record);
                expected_floor = expected_sequence;
            }
        }
    }
    while private_application_index < private_applications.len() {
        if !apply_private_application_for_policy_reconstruction(
            configuration,
            &mut replay,
            private_applications[private_application_index],
        ) {
            return false;
        }
        private_application_index += 1;
    }
    replay.authorization_sequence == state.authorization_sequence
        && expected_floor == state.operation_retirement_floor
        && replay.managed_agents == state.managed_agents
        && replay.managed_actors == state.managed_actors
        && replay.retired_actor_installations == state.retired_actor_installations
        && replay.private_agents.len() == state.private_agents.len()
        && replay
            .private_agents
            .iter()
            .zip(&state.private_agents)
            .all(|(expected, actual)| private_projection_fields_match(expected, actual))
}

fn apply_private_application_for_policy_reconstruction(
    configuration: &SystemAuthorityConfiguration,
    state: &mut AuthorityLinearState,
    record: &PrivateApplicationRecord,
) -> bool {
    let Some(source) = private_application_record_source(configuration, state, record) else {
        return false;
    };
    if source.principal != record.owner
        || source.node != Some(record.node)
        || record.operation == AuthorityOperationKind::RecoverPrivateAgent as u8
    {
        return false;
    }
    let Ok(index) = private_agent(state, AgentId(record.agent)) else {
        return false;
    };
    if !apply_private_application_transition(&mut state.private_agents[index], record) {
        return false;
    }
    state.private_applications.push(*record);
    true
}

fn reconstruction_effect(
    configuration: &SystemAuthorityConfiguration,
    state: &AuthorityLinearState,
    call: &AuthorityCredentialCall,
) -> Option<PendingManagementEffect> {
    match &call.request {
        ManagementRequest::Create(descriptor) => {
            if descriptor.authority != configuration.binding.sdk()
                || managed_agent(state, descriptor.identity.agent).is_ok()
                || state.retries.iter().any(|record| {
                    record.invocation != call.invocation.0
                        && !record.finalized
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
                                && !record.finalized
                                && matches!(record.effect, PendingManagementEffect::Create(_))
                        })
                        .count()
                    >= MAX_MANAGED_AGENTS
            {
                return None;
            }
            Some(PendingManagementEffect::Create(ManagedAgentRow {
                agent: descriptor.identity.agent.0,
                owner: descriptor.identity.owner.0,
                profile: descriptor.identity.profile as u8,
                runtime_deployment: descriptor.identity.runtime_deployment.0,
                runtime_program: descriptor.identity.runtime_program.0,
                runtime_producer: descriptor.identity.runtime_producer.0,
                authority: configuration.binding,
            }))
        }
        ManagementRequest::InspectActors { .. } | ManagementRequest::InspectResources => None,
        ManagementRequest::Install(_)
        | ManagementRequest::UpgradeActor(_)
        | ManagementRequest::Suspend { .. }
        | ManagementRequest::Resume { .. }
        | ManagementRequest::RemoveLeaf { .. } => {
            reconstruction_lifecycle_row(configuration, state, call)?;
            if pending_runtime_transition_conflicts(state, call)
                || pending_actor_effect_conflicts(state, call)
            {
                return None;
            }
            projected_actor_effect(configuration, state, call)
        }
        ManagementRequest::ChangeReplicas { .. } => {
            let row = reconstruction_lifecycle_row(configuration, state, call)?;
            if row.profile == AgentProfile::Private as u8
                || pending_runtime_transition_conflicts(state, call)
            {
                return None;
            }
            Some(PendingManagementEffect::None)
        }
        ManagementRequest::UpgradeRuntime(upgrade) => {
            let row = reconstruction_lifecycle_row(configuration, state, call)?;
            if pending_runtime_transition_conflicts(state, call) {
                return None;
            }
            Some(PendingManagementEffect::UpgradeRuntime {
                agent: row.agent,
                from_deployment: row.runtime_deployment,
                to_deployment: upgrade.to_deployment.0,
                to_program: upgrade.to_program.0,
                producer: upgrade.producer.0,
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
            && state.nodes.iter().any(|node| node.owner == role.principal)
    })
}

fn admin_retry_shape_is_valid(
    configuration: &SystemAuthorityConfiguration,
    state: &AuthorityLinearState,
    record: &AdminRetryRecord,
) -> bool {
    if record.invocation == [0; 32]
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
    call.invocation.0 == record.invocation
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
}

fn admin_generations_are_unique(records: &[AdminRetryRecord]) -> bool {
    records.iter().enumerate().all(|(index, record)| {
        records.iter().enumerate().all(|(other_index, other)| {
            index == other_index || record.generation != other.generation
        })
    })
}

fn admin_history_reconstructs_identity(
    configuration: &SystemAuthorityConfiguration,
    state: &AuthorityLinearState,
) -> bool {
    let mut replay = AuthorityLinearState::bootstrap(*configuration);
    let mut history = state.admin_retries.iter().collect::<Vec<_>>();
    history.sort_unstable_by_key(|record| record.generation);
    for record in history {
        let Ok(call) = AuthorityAdminCall::decode(&record.call_bytes) else {
            return false;
        };
        if call.expected_generation.get() != replay.administration_generation
            || call
                .next_generation()
                .is_none_or(|generation| generation.get() != record.generation)
            || !authenticated_admin(&replay, &call)
            || !apply_admin_operation(&mut replay, &call.operation)
        {
            return false;
        }
        replay.administration_generation = record.generation;
        if !accessible_admin_exists(&replay) {
            return false;
        }
    }
    replay.administration_generation == state.administration_generation
        && replay.credentials == state.credentials
        && replay.nodes == state.nodes
        && replay.roles == state.roles
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

fn retired_operation_private_application_shape_is_valid(
    configuration: &SystemAuthorityConfiguration,
    record: &RetiredAuthorityOperationRow,
) -> bool {
    match (
        record.private_operation,
        record.private_application_invocation,
    ) {
        (None, None) => true,
        (Some(private), Some(application_invocation)) => {
            let Some(sequence) = NonZeroU64::new(record.authorization_sequence) else {
                return false;
            };
            retired_private_operation_is_valid(private)
                && PrivateControlApplicationAck::derive_application_invocation_from_issuance(
                    configured_authority_target(configuration),
                    InvocationId(record.invocation),
                    InvocationId(record.acknowledgement_invocation),
                    sequence,
                    Hash(record.issuance_ack),
                )
                .0 == application_invocation
        }
        _ => false,
    }
}

fn retry_finalization_shape_is_valid(record: &ExactRetryRecord) -> bool {
    match (
        record.finalized,
        record.acknowledgement,
        record.acknowledgement_bytes.as_deref(),
        record.reopened_state,
        record.applied_at,
    ) {
        (false, None, None, None, None) => true,
        (
            true,
            Some(acknowledgement),
            Some(acknowledgement_bytes),
            Some(reopened_state),
            Some(_),
        ) => {
            acknowledgement != [0; 32]
                && !acknowledgement_bytes.is_empty()
                && acknowledgement_bytes.len() <= MAX_INVOCATION_MESSAGE_BYTES
                && reopened_state != [0; 32]
        }
        _ => false,
    }
}

fn all_invocation_identifiers_are_unique(state: &AuthorityLinearState) -> bool {
    let mut identifiers = Vec::with_capacity(
        state
            .retries
            .len()
            .saturating_mul(2)
            .saturating_add(state.operation_retries.len().saturating_mul(2))
            .saturating_add(state.retired_authority_operations.len().saturating_mul(2))
            .saturating_add(state.operation_retries.len())
            .saturating_add(state.retired_authority_operations.len())
            .saturating_add(state.admin_retries.len()),
    );
    for record in &state.retries {
        identifiers.push(record.invocation);
        identifiers.push(record.acknowledgement_invocation);
    }
    for record in &state.operation_retries {
        identifiers.push(record.invocation);
        identifiers.push(record.acknowledgement_invocation);
        if let Some(application_invocation) = record.private_application_invocation {
            identifiers.push(application_invocation);
        }
    }
    for record in &state.retired_authority_operations {
        identifiers.push(record.invocation);
        identifiers.push(record.acknowledgement_invocation);
        if let Some(application_invocation) = record.private_application_invocation {
            identifiers.push(application_invocation);
        }
    }
    identifiers.extend(state.admin_retries.iter().map(|record| record.invocation));
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
    use alloc::boxed::Box;
    use alloc::vec;
    use ed25519_dalek::{Signer as _, SigningKey};
    use std::collections::BTreeMap;
    use vos::Message;
    use vos::abi::service::ServiceId;
    use vos::agent::StateLane;
    use vos::agent_sdk::authority::{
        AuthorityCredentialKind, AuthorityOperationKind, AuthorityReceipt,
        AuthorityReceiptSelector, ManagementApplicationAck, ManagementApproval,
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
    use vos::agent_sdk::{
        ActorEntry, AgentDescriptor, AgentIdentity, AgentReplica, BlobRef, InstallActor,
        InstallationData, InstallationId, InvocationOrigin, InvocationRoleClaims, LaneSet,
        MethodMode, NodeId, ProofSystemSet, ReplicaRole, RoleId, RuntimeCapabilities,
        RuntimeRequirements, UpgradeActor,
    };

    const ADMIN_PRINCIPAL: PrincipalId = PrincipalId([0x31; 32]);
    const ADMIN_NODE: NodeId = NodeId([0x41; 32]);
    const OBSERVED_SLOT: u64 = 100;

    fn signing(byte: u8) -> SigningKey {
        SigningKey::from_bytes(&[byte; 32])
    }

    fn configuration() -> SystemAuthorityConfiguration {
        let authority_key = signing(0x71).verifying_key().to_bytes();
        SystemAuthorityConfiguration {
            space: [0x11; 32],
            system_agent: [0x12; 32],
            system_runtime_deployment: [0x13; 32],
            system_runtime_program: [0x19; 32],
            system_runtime_producer: [0x1a; 32],
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
            bootstrap_principal: ADMIN_PRINCIPAL.0,
            bootstrap_credential_public_key: signing(0x21).verifying_key().to_bytes(),
            bootstrap_credential_kind: 0,
            bootstrap_node: ADMIN_NODE.0,
        }
    }

    fn actor() -> SystemAuthority {
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
            },
            creation_nonce,
            authority: config.binding.sdk(),
            runtime_package: BlobRef::of_bytes(&[nonce_byte]),
            runtime_contract: RuntimePackageContract::canonical(),
            capabilities: RuntimeCapabilities::standard(),
            replicas: vec![AgentReplica {
                node: NodeId([nonce_byte.wrapping_add(4); 32]),
                principal: owner,
                role: replica_role,
            }],
        }
    }

    fn target_for(descriptor: &AgentDescriptor) -> vos::agent_sdk::authority::ManagedAgentTarget {
        vos::agent_sdk::authority::ManagedAgentTarget {
            space: descriptor.identity.space,
            agent: descriptor.identity.agent,
            runtime_deployment: descriptor.identity.runtime_deployment,
        }
    }

    fn system_target(
        config: SystemAuthorityConfiguration,
    ) -> vos::agent_sdk::authority::ManagedAgentTarget {
        vos::agent_sdk::authority::ManagedAgentTarget {
            space: SpaceId(config.space),
            agent: AgentId(config.system_agent),
            runtime_deployment: DeploymentId(config.system_runtime_deployment),
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
        let mut call = AuthorityCredentialCall {
            invocation: InvocationId([invocation_byte; 32]),
            authority: authority_target(config),
            managed,
            principal,
            credential: CredentialId::of_public_key(&public_key),
            credential_public_key: public_key,
            authenticated_node: node,
            requested_valid_from: 1,
            requested_expires_at: 10_000,
            request,
            signature: [1; 64],
        };
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
            call.encode().expect("valid ACC1 fixture"),
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
        let mut call = AuthorityOperationCall {
            invocation: InvocationId([invocation_byte; 32]),
            authority: authority_target(config),
            principal,
            credential: CredentialId::of_public_key(&public_key),
            credential_public_key: public_key,
            authenticated_node: node,
            requested_valid_from: 1,
            requested_expires_at: 10_000,
            intent,
            signature: [1; 64],
        };
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
        call.signature = [1; 64];
        call.signature = key.sign(&call.signing_bytes()).to_bytes();
    }

    fn operation_context(call: &AuthorityOperationCall) -> InvocationContext {
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
            call.encode().expect("valid AOC1 fixture"),
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
        reopened_control_state: Hash,
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
            AuthorityOperationIntent::RecoverPrivateAgent {
                control,
                control_sequence,
                control_previous,
                epoch,
                ..
            } => (
                AuthorityOperationKind::RecoverPrivateAgent,
                *control,
                *control_sequence,
                *control_previous,
                *epoch,
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
            reopened_control_state,
            reopened_control_head: control,
            applied_at,
        }
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

    fn dispatch_private_application_bytes(
        actor: &mut SystemAuthority,
        bytes: Vec<u8>,
        invocation_context: Option<InvocationContext>,
    ) -> bool {
        let mut ctx = Context::new(ServiceId(0));
        if let Some(invocation_context) = invocation_context {
            ctx.__set_agent_invocation_context(invocation_context);
        }
        block_on(<SystemAuthority as Message<
            AcknowledgePrivateApplication,
        >>::handle(
            actor,
            AcknowledgePrivateApplication { ack: bytes },
            &mut ctx,
        ))
    }

    fn dispatch_private_application(
        actor: &mut SystemAuthority,
        ack: &PrivateControlApplicationAck,
    ) -> bool {
        dispatch_private_application_bytes(
            actor,
            ack.encode().expect("valid PCA1 fixture"),
            Some(private_application_context(ack)),
        )
    }

    fn receipt_for(
        config: SystemAuthorityConfiguration,
        approval: &ManagementApproval,
        decision_sequence: u64,
    ) -> AuthorityReceipt {
        let actor = approval.request.authority_actor();
        let mut receipt = AuthorityReceipt {
            selector: AuthorityReceiptSelector {
                policy: approval.authority.binding.policy,
                issuer: approval.authority.binding.issuer,
                space: approval.managed.space,
                agent: approval.managed.agent,
                operation: approval
                    .request
                    .authority_operation()
                    .expect("approval always carries a mutating request"),
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
                request: approval.request_commitment,
            },
            public_key: config.binding.public_key,
            signature: [1; 64],
        };
        receipt.signature = signing(0x71).sign(&receipt.signing_bytes()).to_bytes();
        receipt
    }

    fn application_ack(
        config: SystemAuthorityConfiguration,
        call: &AuthorityCredentialCall,
        approval: &ManagementApproval,
    ) -> ManagementApplicationAck {
        let mut ack = ManagementApplicationAck {
            authorization_invocation: call.invocation,
            acknowledgement_invocation: approval.acknowledgement_invocation,
            authority: call.authority,
            managed: call.managed,
            credential_call: call.commitment(),
            approval: approval.commitment(),
            authorization_sequence: approval.authorization_sequence,
            request: approval.request_commitment,
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
            invocation: InvocationId([invocation_byte; 32]),
            authority: authority_target(config),
            administrator,
            credential: CredentialId::of_public_key(&public_key),
            credential_public_key: public_key,
            authenticated_node,
            observed_slot: OBSERVED_SLOT,
            expected_generation: NonZeroU64::new(expected_generation).unwrap(),
            operation,
            signature: [1; 64],
        };
        resign_admin(&mut call, key);
        call
    }

    fn resign_admin(call: &mut AuthorityAdminCall, key: &SigningKey) {
        call.signature = [1; 64];
        call.signature = key.sign(&call.signing_bytes()).to_bytes();
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
            call.encode().expect("valid AAD1 fixture"),
            Some(admin_context(call)),
        )
    }

    fn dispatch_fixture_admin(
        actor: &mut SystemAuthority,
        invocation: InvocationId,
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
        call.invocation = invocation;
        resign_admin(&mut call, &key);
        assert!(!dispatch_admin(actor, &call).is_empty());
    }

    /// Build a canonical Admin history without revalidating its entire prefix
    /// after every fixture operation. Tests using this helper validate the
    /// completed state once, exercising the same replay invariant in linear
    /// rather than quadratic signature-verification time.
    fn record_fixture_admin(
        actor: &mut SystemAuthority,
        invocation: InvocationId,
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
        call.invocation = invocation;
        resign_admin(&mut call, &key);
        assert!(authenticated_admin(&actor.state, &call));
        let generation = call.next_generation().unwrap();
        assert!(apply_admin_operation(&mut actor.state, &call.operation));
        actor.state.administration_generation = generation.get();
        let result = AuthorityAdminResult::from_call(call.clone()).unwrap();
        let call_bytes = call.encode().unwrap();
        let result_bytes = result.encode().unwrap();
        let index = actor
            .state
            .admin_retries
            .binary_search_by(|record| record.invocation.cmp(&invocation.0))
            .expect_err("fixture Admin invocation must be unique");
        actor.state.admin_retries.insert(
            index,
            AdminRetryRecord {
                invocation: invocation.0,
                call_commitment: call.commitment().0,
                call_bytes,
                result_commitment: result.commitment().0,
                result_bytes,
                generation: generation.get(),
            },
        );
    }

    /// Append one canonical pending approval without replaying every existing
    /// history prefix. Capacity tests validate the completed history once.
    fn record_fixture_approval(
        actor: &mut SystemAuthority,
        call: &AuthorityCredentialCall,
    ) -> Vec<u8> {
        let state = &mut actor.state;
        let encoded_call = call.encode().unwrap();
        assert!(call.verify_with(&Ed25519CredentialVerifier).is_ok());
        let acknowledgement_invocation =
            ManagementApproval::derive_acknowledgement_invocation(call);
        assert!(invocation_pair_is_available(
            state,
            call.invocation,
            acknowledgement_invocation,
        ));
        let role = authenticated_role(state, call).unwrap();
        let effect = policy_effect(&actor.configuration, state, call, role).unwrap();
        let authorization_sequence = state.authorization_sequence.checked_add(1).unwrap();
        let sequence = NonZeroU64::new(authorization_sequence).unwrap();
        let (valid_from, expires_at) = narrowed_validity(call, OBSERVED_SLOT).unwrap();
        let approval = ManagementApproval::from_call(
            call,
            sequence,
            AuthorityEvidence {
                package: None,
                proof: None,
                commitment: Hash::digest(
                    EVIDENCE_DOMAIN,
                    &[
                        &actor.configuration.binding.policy,
                        call.commitment().as_bytes(),
                        &[role as u8],
                        &authorization_sequence.to_le_bytes(),
                        &OBSERVED_SLOT.to_le_bytes(),
                    ],
                ),
            },
            AuthorityLaneRoots::default(),
            state.epoch,
            valid_from,
            expires_at,
        )
        .unwrap();
        assert_eq!(
            approval.acknowledgement_invocation,
            acknowledgement_invocation
        );
        let approval_bytes = approval.encode().unwrap();
        let index = retry_record(state, call.invocation).unwrap_err();
        state.authorization_sequence = authorization_sequence;
        state.retries.insert(
            index,
            ExactRetryRecord {
                invocation: call.invocation.0,
                acknowledgement_invocation: acknowledgement_invocation.0,
                credential_call: call.commitment().0,
                credential_call_bytes: encoded_call,
                approval_commitment: approval.commitment().0,
                authorization_sequence,
                approval: approval_bytes.clone(),
                effect,
                finalized: false,
                acknowledgement: None,
                acknowledgement_bytes: None,
                reopened_state: None,
                applied_at: None,
            },
        );
        assert!(advance_operation_retirement_floor(state));
        approval_bytes
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
            ack.encode().expect("valid MAA1 fixture"),
            Some(acknowledgement_context(ack)),
        )
    }

    fn enroll(
        actor: &mut SystemAuthority,
        key: &SigningKey,
        principal: PrincipalId,
        node: NodeId,
        role: BuiltinPrincipalRole,
    ) {
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
            AuthorityAdminOperation::BindNodeOwner {
                node,
                owner: principal,
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
        call.invocation = InvocationId(
            Hash::digest(
                b"vos/test/system-authority/create-fixture/v1",
                &[descriptor.identity.agent.as_bytes()],
            )
            .0,
        );
        resign(&mut call, &signing(0x21));
        let approval = ManagementApproval::decode(&dispatch(actor, &call))
            .expect("fixture Create must be authorized");
        assert!(dispatch_ack(
            actor,
            &application_ack(config, &call, &approval)
        ));
    }

    fn install_catalog_projection(actor: &mut SystemAuthority) -> InstallActor {
        let config = actor.configuration;
        let install = catalog_install(config);
        let call = credential_call(
            config,
            &signing(0x21),
            ADMIN_PRINCIPAL,
            Some(ADMIN_NODE),
            0x23,
            system_target(config),
            ManagementRequest::Install(Box::new(install.clone())),
        );
        let approval = ManagementApproval::decode(&dispatch(actor, &call))
            .expect("root catalog install must be authorized");
        assert_eq!(approval.authorization_sequence.get(), 3);
        assert!(dispatch_ack(
            actor,
            &application_ack(config, &call, &approval),
        ));
        install
    }

    fn fill_pending_management_retries(actor: &mut SystemAuthority, count: usize) {
        let config = actor.configuration;
        for ordinal in 1..=count {
            let byte = u8::try_from(ordinal).expect("bounded retry fixture");
            let marker = byte.wrapping_add(0x40);
            let install = actor_install(
                AgentId(config.system_agent),
                &std::format!("pending-{ordinal}"),
                marker,
            );
            let call = credential_call(
                config,
                &signing(0x21),
                ADMIN_PRINCIPAL,
                Some(ADMIN_NODE),
                marker,
                system_target(config),
                ManagementRequest::Install(Box::new(install)),
            );
            assert!(!record_fixture_approval(actor, &call).is_empty());
        }
    }

    #[test]
    fn sac2_configuration_is_exact_and_clean_generation_bound() {
        let config = configuration();
        let encoded = config.encode();
        assert_eq!(encoded.len(), CONFIG_ENCODED_BYTES);
        assert_eq!(encoded.get(..4), Some(b"SAC2".as_slice()));
        assert_eq!(SystemAuthorityConfiguration::decode(&encoded), Some(config));
        assert_eq!(
            <SystemAuthority as vos::Actor>::STATE_SCHEMA_VERSION,
            7,
            "Private application projection is a clean Linear state generation",
        );

        let mut old_generation = encoded.clone();
        old_generation[..4].copy_from_slice(b"SAC1");
        assert_eq!(SystemAuthorityConfiguration::decode(&old_generation), None);
        let mut old_sac1_shape = vec![0; CONFIG_ENCODED_BYTES - 72];
        old_sac1_shape[..4].copy_from_slice(b"SAC1");
        assert_eq!(SystemAuthorityConfiguration::decode(&old_sac1_shape), None);
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
        invalid_kind[encoded.len() - 33] = 2;
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
        for altered_high_water in [0, 1, 3, u64::MAX] {
            let mut altered = config;
            altered.bootstrap_authorization_high_water = altered_high_water;
            assert!(!altered.is_valid());
            assert_eq!(
                SystemAuthorityConfiguration::decode(&altered.encode()),
                None
            );
        }

        let inert = SystemAuthority::new(&old_generation);
        assert!(!inert.state.initialized);
        assert!(inert.state.credentials.is_empty());
    }

    #[test]
    fn root_seed_starts_at_sequence_two_authorizes_catalog_install_as_three_and_restarts() {
        let config = configuration();
        let expected_seed = root_managed_agent(config);
        let mut actor = actor();
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

        let ack = application_ack(config, &call, &approval);
        let expected_actor = installed_actor_row(AgentId(config.system_agent), &install, true);
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
        .expect("seeded SAC2 authority state restarts");
        assert_eq!(restarted.state.authorization_sequence, 3);
        assert_eq!(restarted.state.managed_agents, vec![expected_seed]);
        assert_eq!(restarted.state.managed_actors, vec![expected_actor]);
        assert!(authority_state_is_valid(&config, &restarted.state));
        assert_eq!(dispatch(&mut restarted, &call), approval_bytes);
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
        let install_call = credential_call(
            config,
            &signing(0x21),
            ADMIN_PRINCIPAL,
            Some(ADMIN_NODE),
            0x51,
            managed,
            ManagementRequest::Install(Box::new(install.clone())),
        );
        let install_approval = ManagementApproval::decode(&dispatch(&mut actor, &install_call))
            .expect("valid Install is approved");
        assert_eq!(install_approval.authorization_sequence.get(), 4);
        assert!(actor.state.managed_actors.is_empty());

        let duplicate = credential_call(
            config,
            &signing(0x21),
            ADMIN_PRINCIPAL,
            Some(ADMIN_NODE),
            0x52,
            managed,
            ManagementRequest::Install(Box::new(install.clone())),
        );
        let pending = actor.state.clone();
        assert!(dispatch(&mut actor, &duplicate).is_empty());
        assert_eq!(actor.state, pending);

        let install_ack = application_ack(config, &install_call, &install_approval);
        let installed = installed_actor_row(managed.agent, &install, false);
        assert!(dispatch_ack(&mut actor, &install_ack));
        assert_eq!(actor.state.managed_actors, vec![installed.clone()]);
        assert_installed_projection(
            &actor.state.managed_actors[0],
            managed.agent,
            &install,
            false,
        );

        let mut stale_upgrade = actor_upgrade(&install, 0x53);
        stale_upgrade.from_deployment = DeploymentId([0x54; 32]);
        let stale_call = credential_call(
            config,
            &signing(0x21),
            ADMIN_PRINCIPAL,
            Some(ADMIN_NODE),
            0x55,
            managed,
            ManagementRequest::UpgradeActor(Box::new(stale_upgrade)),
        );
        let before_stale = actor.state.clone();
        assert!(dispatch(&mut actor, &stale_call).is_empty());
        assert_eq!(actor.state, before_stale);

        let upgrade = actor_upgrade(&install, 0x56);
        let upgrade_call = credential_call(
            config,
            &signing(0x21),
            ADMIN_PRINCIPAL,
            Some(ADMIN_NODE),
            0x57,
            managed,
            ManagementRequest::UpgradeActor(Box::new(upgrade.clone())),
        );
        let before_upgrade_ack = actor.state.managed_actors.clone();
        let upgrade_approval = ManagementApproval::decode(&dispatch(&mut actor, &upgrade_call))
            .expect("compatible UpgradeActor is approved");
        assert_eq!(upgrade_approval.authorization_sequence.get(), 5);
        assert_eq!(actor.state.managed_actors, before_upgrade_ack);
        let upgrade_ack = application_ack(config, &upgrade_call, &upgrade_approval);
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

        let stale_after_upgrade = credential_call(
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
        let before_stale = actor.state.clone();
        assert!(dispatch(&mut actor, &stale_after_upgrade).is_empty());
        assert_eq!(actor.state, before_stale);

        let suspend_call = credential_call(
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
        let suspend_approval = ManagementApproval::decode(&dispatch(&mut actor, &suspend_call))
            .expect("exact Suspend is approved");
        assert_eq!(suspend_approval.authorization_sequence.get(), 6);
        assert!(!actor.state.managed_actors[0].suspended);
        assert!(dispatch_ack(
            &mut actor,
            &application_ack(config, &suspend_call, &suspend_approval)
        ));
        assert!(actor.state.managed_actors[0].suspended);

        let resume_call = credential_call(
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
        let resume_approval = ManagementApproval::decode(&dispatch(&mut actor, &resume_call))
            .expect("exact Resume is approved");
        assert_eq!(resume_approval.authorization_sequence.get(), 7);
        assert!(actor.state.managed_actors[0].suspended);
        assert!(dispatch_ack(
            &mut actor,
            &application_ack(config, &resume_call, &resume_approval)
        ));
        assert!(!actor.state.managed_actors[0].suspended);

        let remove_call = credential_call(
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
        let remove_approval = ManagementApproval::decode(&dispatch(&mut actor, &remove_call))
            .expect("exact RemoveLeaf is approved");
        assert_eq!(remove_approval.authorization_sequence.get(), 8);
        assert_eq!(actor.state.managed_actors.len(), 1);
        assert!(dispatch_ack(
            &mut actor,
            &application_ack(config, &remove_call, &remove_approval)
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
        let reuse_call = credential_call(
            config,
            &signing(0x21),
            ADMIN_PRINCIPAL,
            Some(ADMIN_NODE),
            0x5e,
            managed,
            ManagementRequest::Install(Box::new(reuse)),
        );
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
    fn pending_parent_and_runtime_transitions_are_serialized() {
        let config = configuration();
        let descriptor = descriptor(config, ADMIN_PRINCIPAL, AgentProfile::Local, 0x7f);
        let managed = target_for(&descriptor);
        let mut actor = actor();
        insert_live(&mut actor, &descriptor);

        let parent = actor_install(managed.agent, "parent", 0x80);
        let parent_call = credential_call(
            config,
            &signing(0x21),
            ADMIN_PRINCIPAL,
            Some(ADMIN_NODE),
            0x81,
            managed,
            ManagementRequest::Install(Box::new(parent.clone())),
        );
        let parent_approval = ManagementApproval::decode(&dispatch(&mut actor, &parent_call))
            .expect("parent install approved");
        assert!(dispatch_ack(
            &mut actor,
            &application_ack(config, &parent_call, &parent_approval)
        ));

        let mut child = actor_install(managed.agent, "child", 0x82);
        child.entry.parent = Some(parent.entry.actor);
        child.entry.actor = ActorId::owned_child(parent.entry.actor, &child.entry.name);
        let child_call = credential_call(
            config,
            &signing(0x21),
            ADMIN_PRINCIPAL,
            Some(ADMIN_NODE),
            0x83,
            managed,
            ManagementRequest::Install(Box::new(child.clone())),
        );
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
            let call = credential_call(
                config,
                &signing(0x21),
                ADMIN_PRINCIPAL,
                Some(ADMIN_NODE),
                invocation,
                managed,
                request,
            );
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
        let blocked_runtime = credential_call(
            config,
            &signing(0x21),
            ADMIN_PRINCIPAL,
            Some(ADMIN_NODE),
            0x89,
            managed,
            runtime_request.clone(),
        );
        let before = actor.state.clone();
        assert!(dispatch(&mut actor, &blocked_runtime).is_empty());
        assert_eq!(actor.state, before);

        assert!(dispatch_ack(
            &mut actor,
            &application_ack(config, &child_call, &child_approval)
        ));
        let runtime_call = credential_call(
            config,
            &signing(0x21),
            ADMIN_PRINCIPAL,
            Some(ADMIN_NODE),
            0x8a,
            managed,
            runtime_request,
        );
        assert!(ManagementApproval::decode(&dispatch(&mut actor, &runtime_call)).is_ok());

        let child_suspend = credential_call(
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
        let install_call = credential_call(
            config,
            &signing(0x21),
            ADMIN_PRINCIPAL,
            Some(ADMIN_NODE),
            0x6a,
            managed,
            ManagementRequest::Install(Box::new(install.clone())),
        );
        let approval = ManagementApproval::decode(&dispatch(&mut actor, &install_call)).unwrap();
        assert!(dispatch_ack(
            &mut actor,
            &application_ack(config, &install_call, &approval)
        ));

        let cross_agent = credential_call(
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
        let before = actor.state.clone();
        assert!(dispatch(&mut actor, &cross_agent).is_empty());
        assert_eq!(actor.state, before);

        let wrong_agent_install = actor_install(managed.agent, "wrong-agent", 0x6c);
        let wrong_agent_call = credential_call(
            config,
            &signing(0x21),
            ADMIN_PRINCIPAL,
            Some(ADMIN_NODE),
            0x6d,
            system_target(config),
            ManagementRequest::Install(Box::new(wrong_agent_install)),
        );
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
        assert!(dispatch_ack(
            &mut actor,
            &application_ack(config, &call, &approval)
        ));
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

        let later_install = actor_install(AgentId(config.system_agent), "later-system", 0x72);
        let later_call = credential_call(
            config,
            &signing(0x21),
            ADMIN_PRINCIPAL,
            Some(ADMIN_NODE),
            0x73,
            system_target(config),
            ManagementRequest::Install(Box::new(later_install.clone())),
        );
        let later_approval =
            ManagementApproval::decode(&dispatch(&mut actor, &later_call)).unwrap();
        assert!(dispatch_ack(
            &mut actor,
            &application_ack(config, &later_call, &later_approval)
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
        assert!(dispatch_ack(
            &mut actor,
            &application_ack(config, &call, &approval)
        ));
        let system = &actor.state.managed_agents
            [managed_agent(&actor.state, AgentId(config.system_agent)).unwrap()];
        assert_eq!(system.runtime_deployment, [0x2c; 32]);
        assert_eq!(system.runtime_program, [0x2d; 32]);
        assert_eq!(system.runtime_producer, [0x2e; 32]);
        assert!(authority_state_is_valid(&config, &actor.state));

        let mut unbacked_drift = actor.state.clone();
        let index = managed_agent(&unbacked_drift, AgentId(config.system_agent)).unwrap();
        unbacked_drift.managed_agents[index].runtime_program[0] ^= 1;
        assert!(!authority_state_is_valid(&config, &unbacked_drift));
    }

    #[test]
    fn acc1_requires_exact_aic1_and_never_falls_back() {
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
        assert!(
            dispatch_bytes(
                &mut actor,
                b"legacy authority call".to_vec(),
                Some(context(&call))
            )
            .is_empty()
        );
        assert_eq!(actor.state, before);
        assert!(dispatch_bytes(&mut actor, call.encode().unwrap(), None).is_empty());
        assert_eq!(actor.state, before);

        let mut wrong_mode = context(&call);
        wrong_mode.mode = MethodMode::Merge;
        assert!(dispatch_bytes(&mut actor, call.encode().unwrap(), Some(wrong_mode)).is_empty());
        assert_eq!(actor.state, before);

        let mut claimed_role = context(&call);
        claimed_role.roles.space = Some(RoleId([0x99; 32]));
        assert!(dispatch_bytes(&mut actor, call.encode().unwrap(), Some(claimed_role)).is_empty());
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
        resign(&mut wrong_principal, &admin_key);
        cases.push(wrong_principal);

        let other_key = signing(0x22);
        let mut wrong_key = base.clone();
        wrong_key.credential_public_key = other_key.verifying_key().to_bytes();
        wrong_key.credential = CredentialId::of_public_key(&wrong_key.credential_public_key);
        resign(&mut wrong_key, &other_key);
        cases.push(wrong_key);

        let mut unknown_node = base.clone();
        unknown_node.authenticated_node = Some(NodeId([0x42; 32]));
        resign(&mut unknown_node, &admin_key);
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
    fn aoc1_none_node_exact_retry_restart_and_retirement_are_explicit() {
        let config = configuration();
        let mut actor = actor();
        let catalog = install_catalog_projection(&mut actor);
        assert_eq!(actor.state.operation_retirement_floor, 3);

        let call = invoke_operation_call(
            config,
            &signing(0x21),
            ADMIN_PRINCIPAL,
            None,
            0x81,
            0x82,
            system_target(config),
            &catalog,
        );
        let approval_bytes = dispatch_operation(&mut actor, &call);
        let approval = AuthorityOperationApproval::decode(&approval_bytes).unwrap();
        assert_eq!(approval.authorization_sequence.get(), 4);
        assert_eq!(approval.authenticated_node, None);
        assert!(approval.matches_call(&call));
        assert_eq!(dispatch_operation(&mut actor, &call), approval_bytes);
        assert_eq!(actor.state.operation_retries.len(), 1);
        assert_eq!(actor.state.operation_retirement_floor, 3);

        let mut unknown_node = call.clone();
        unknown_node.invocation = InvocationId([0x83; 32]);
        unknown_node.authenticated_node = Some(NodeId([0x84; 32]));
        let AuthorityOperationIntent::InvokeActor { origin, .. } = &mut unknown_node.intent else {
            unreachable!()
        };
        origin.transport_node = unknown_node.authenticated_node;
        resign_operation_call(&mut unknown_node, &signing(0x21));
        let before_unknown = actor.state.clone();
        assert!(dispatch_operation(&mut actor, &unknown_node).is_empty());
        assert_eq!(actor.state, before_unknown);

        let linear = <SystemAuthority as vos::Actor>::__save_agent_lane(&actor, StateLane::Linear);
        let mut restarted = <SystemAuthority as vos::Actor>::__load_agent_state(
            Some(&config.encode()),
            Some(&linear),
            None,
            None,
        )
        .expect("pending AOC1/AOP1 must restart");
        assert_eq!(dispatch_operation(&mut restarted, &call), approval_bytes);

        let ack = operation_issuance_ack(config, &call, &approval);
        assert!(dispatch_operation_ack(&mut restarted, &ack));
        assert!(restarted.state.operation_retries.is_empty());
        assert_eq!(restarted.state.operation_retirement_floor, 4);
        assert_eq!(restarted.state.retired_authority_operations.len(), 1);
        assert!(dispatch_operation_ack(&mut restarted, &ack));

        // Retirement deliberately ends AOC exact retry: the actor retains a
        // collision tombstone, not bytes from which it could invent AOP1.
        let retired_state = restarted.state.clone();
        assert!(dispatch_operation(&mut restarted, &call).is_empty());
        assert_eq!(restarted.state, retired_state);
        assert!(authority_state_is_valid(&config, &restarted.state));

        let mut corrupt_ack = restarted.state.clone();
        corrupt_ack.retired_authority_operations[0].issuance_ack[0] ^= 1;
        assert!(!authority_state_is_valid(&config, &corrupt_ack));
        let mut corrupt_floor = restarted.state.clone();
        corrupt_floor.operation_retirement_floor -= 1;
        assert!(!authority_state_is_valid(&config, &corrupt_floor));
        let mut corrupt_chain = restarted.state.clone();
        corrupt_chain.operation_retirement_commitment[0] ^= 1;
        assert!(!authority_state_is_valid(&config, &corrupt_chain));
    }

    #[test]
    fn out_of_order_aoi1_waits_for_gap_and_crosses_management_without_retiring_it() {
        let config = configuration();
        let mut actor = actor();
        let catalog = install_catalog_projection(&mut actor);
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
            &signing(0x21),
            ADMIN_PRINCIPAL,
            Some(ADMIN_NODE),
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
            &signing(0x21),
            ADMIN_PRINCIPAL,
            Some(ADMIN_NODE),
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
        assert_eq!(
            restarted
                .state
                .retired_authority_operations
                .iter()
                .map(|record| record.authorization_sequence)
                .collect::<Vec<_>>(),
            vec![4, 6]
        );
        // Sequence five was crossed but the separate management journal was
        // neither finalized nor compacted.
        assert_eq!(restarted.state.retries, management_journal);
        assert!(!restarted.state.retries.last().unwrap().finalized);
        assert!(dispatch_operation_ack(&mut restarted, &second_ack));
        assert!(authority_state_is_valid(&config, &restarted.state));
    }

    #[test]
    fn operation_domains_collisions_and_signed_substitutions_fail_closed() {
        let config = configuration();
        let mut actor = actor();
        let catalog = install_catalog_projection(&mut actor);
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
            actor.state.retries[0].invocation,
            actor.state.retries[0].acknowledgement_invocation,
        ] {
            let mut colliding = call.clone();
            colliding.invocation = InvocationId(collision);
            resign_operation_call(&mut colliding, &signing(0x21));
            assert!(dispatch_operation(&mut actor, &colliding).is_empty());
        }

        let admin = admin_call(
            config,
            &signing(0x21),
            ADMIN_PRINCIPAL,
            ADMIN_NODE,
            0x94,
            actor.state.administration_generation,
            AuthorityAdminOperation::EnrollPrincipal {
                principal: PrincipalId([0x95; 32]),
                credential: enrollment(&signing(0x96), AuthorityCredentialKind::Api),
            },
        );
        assert!(!dispatch_admin(&mut actor, &admin).is_empty());
        let mut admin_collision = call.clone();
        admin_collision.invocation = admin.invocation;
        resign_operation_call(&mut admin_collision, &signing(0x21));
        assert!(dispatch_operation(&mut actor, &admin_collision).is_empty());

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
            },
            actor: catalog_install.entry.actor,
            actor_deployment: catalog_install.entry.deployment,
            actor_program: catalog_install.entry.program,
            actor_package: catalog_install.package.clone(),
            content: BlobRef::of_bytes(b"published-system-catalog"),
        };
        let intent = AuthorityOperationIntent::catalog(
            InvocationId([0xa1; 32]),
            catalog,
            CatalogAlias {
                namespace: "system".into(),
                name: "catalog".into(),
            },
            CatalogMutationKind::Publish,
            publication.clone(),
            0,
        )
        .unwrap();
        let call = operation_call(config, &signing(0x21), ADMIN_PRINCIPAL, None, 0xa2, intent);
        let managed_before = actor.state.managed_agents.clone();
        let actors_before = actor.state.managed_actors.clone();
        let approval = AuthorityOperationApproval::decode(&dispatch_operation(&mut actor, &call))
            .expect("exact catalog route and publication must authorize");
        assert!(
            approval
                .intent
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
            InvocationId([0xa4; 32]),
            wrong_catalog,
            CatalogAlias {
                namespace: "system".into(),
                name: "wrong-route".into(),
            },
            CatalogMutationKind::Publish,
            publication,
            0,
        )
        .unwrap();
        let wrong_call = operation_call(
            config,
            &signing(0x21),
            ADMIN_PRINCIPAL,
            None,
            0xa5,
            wrong_intent,
        );
        let before = actor.state.clone();
        assert!(dispatch_operation(&mut actor, &wrong_call).is_empty());
        assert_eq!(actor.state, before);
    }

    #[test]
    fn private_controls_require_exact_owner_and_recovery_remains_unproved() {
        let config = configuration();
        let owner = PrincipalId([0xb1; 32]);
        let owner_node = NodeId([0xb2; 32]);
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
        let initial_member_set =
            private_member_set_commitment(descriptor.replicas.iter().map(|replica| replica.node))
                .unwrap();
        let invited_node = NodeId([0xf6; 32]);
        let invited_member_set =
            private_member_set_commitment([descriptor.replicas[0].node, invited_node].into_iter())
                .unwrap();
        let invite = AuthorityOperationIntent::InvitePrivateNode {
            managed,
            control: Hash([0xb5; 32]),
            control_sequence: 0,
            control_previous: None,
            epoch: 0,
            node: invited_node,
            node_identity: Hash([0xb7; 32]),
        };
        let revoke = AuthorityOperationIntent::RevokePrivateNode {
            managed,
            control: Hash([0xb8; 32]),
            control_sequence: 1,
            control_previous: Some(Hash([0xb5; 32])),
            epoch: 1,
            node: invited_node,
            member_set: initial_member_set,
        };
        for (offset, intent) in [invite.clone(), revoke.clone()].into_iter().enumerate() {
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

        let invite_call = operation_call(config, &owner_key, owner, None, 0xbc, invite);
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

        let revoke_call = operation_call(config, &owner_key, owner, None, 0xbd, revoke);
        assert!(
            AuthorityOperationApproval::decode(&dispatch_operation(&mut actor, &revoke_call))
                .is_ok()
        );

        let recover = AuthorityOperationIntent::RecoverPrivateAgent {
            managed,
            control: Hash([0xbe; 32]),
            control_sequence: 2,
            control_previous: Some(Hash([0xb8; 32])),
            epoch: 3,
            member_set: Hash([0xbf; 32]),
            recovery_evidence: Hash([0xc0; 32]),
        };
        for (byte, key, principal, node) in [
            (0xc1, &owner_key, owner, None),
            (0xc2, &admin_key, ADMIN_PRINCIPAL, Some(ADMIN_NODE)),
        ] {
            let call = operation_call(config, key, principal, node, byte, recover.clone());
            let before = actor.state.clone();
            assert!(dispatch_operation(&mut actor, &call).is_empty());
            assert_eq!(actor.state, before);
        }
    }

    #[test]
    fn tombstoned_pca1_advances_only_the_exact_private_projection_and_restarts() {
        let config = configuration();
        let owner = PrincipalId([0xc1; 32]);
        let owner_node = NodeId([0xc2; 32]);
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
            private_member_set_commitment(descriptor.replicas.iter().map(|replica| replica.node))
                .unwrap();
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

        let invited_node = NodeId([0xf0; 32]);
        let invited_member_set =
            private_member_set_commitment([descriptor.replicas[0].node, invited_node].into_iter())
                .unwrap();
        let invite_control = Hash([0xc5; 32]);
        let invite_call = operation_call(
            config,
            &owner_key,
            owner,
            None,
            0xc6,
            AuthorityOperationIntent::InvitePrivateNode {
                managed,
                control: invite_control,
                control_sequence: 0,
                control_previous: None,
                epoch: 0,
                node: invited_node,
                node_identity: Hash([0xc7; 32]),
            },
        );
        let private_before_issuance = actor.state.private_agents.clone();
        let (invite_approval, invite_issuance) =
            authorize_and_issue_operation(&mut actor, &invite_call);
        assert_eq!(actor.state.private_agents, private_before_issuance);
        assert!(actor.state.operation_retries.is_empty());
        assert_eq!(actor.state.retired_authority_operations.len(), 1);

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
        let management_projection = actor.state.managed_agents.clone();
        let actor_projection = actor.state.managed_actors.clone();
        let management_journal = actor.state.retries.clone();
        assert!(dispatch_private_application(&mut actor, &invite_pca));
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
        assert_eq!(
            projected.members,
            vec![descriptor.replicas[0].node.0, invited_node.0]
        );
        assert_eq!(projected.member_set, invited_member_set.0);
        assert_eq!(projected.reopened_control_state, Some([0xc8; 32]));
        assert_eq!(projected.applied_at, Some(OBSERVED_SLOT + 1));
        assert_eq!(
            projected.application_invocation,
            Some(invite_pca.application_invocation.0)
        );
        assert_eq!(projected.application_ack, Some(invite_pca.commitment().0));

        let after_invite = actor.state.clone();
        assert!(dispatch_private_application(&mut actor, &invite_pca));
        assert_eq!(actor.state, after_invite);
        let mut divergent_retry = invite_pca.clone();
        divergent_retry.application.reopened_control_state = Hash([0xc9; 32]);
        resign_private_application_ack(&mut divergent_retry);
        assert!(!dispatch_private_application(&mut actor, &divergent_retry));
        assert_eq!(actor.state, after_invite);

        let linear = <SystemAuthority as vos::Actor>::__save_agent_lane(&actor, StateLane::Linear);
        let mut restarted = <SystemAuthority as vos::Actor>::__load_agent_state(
            Some(&config.encode()),
            Some(&linear),
            None,
            None,
        )
        .expect("PCA1 projection restarts");
        assert_eq!(restarted.state, actor.state);
        assert!(dispatch_private_application(&mut restarted, &invite_pca));

        let revoke_control = Hash([0xca; 32]);
        let revoke_call = operation_call(
            config,
            &owner_key,
            owner,
            None,
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
    fn pending_pca1_source_remains_valid_when_aoi_floor_later_compacts_it() {
        let config = configuration();
        let owner = PrincipalId([0xd1; 32]);
        let owner_node = NodeId([0xd2; 32]);
        let owner_key = signing(0xd3);
        let mut actor = actor();
        enroll(
            &mut actor,
            &owner_key,
            owner,
            owner_node,
            BuiltinPrincipalRole::Member,
        );
        let gap_descriptor = descriptor(config, owner, AgentProfile::Private, 0xdc);
        let gap_managed = target_for(&gap_descriptor);
        insert_live(&mut actor, &gap_descriptor);
        let descriptor = descriptor(config, owner, AgentProfile::Private, 0xd4);
        let managed = target_for(&descriptor);
        insert_live(&mut actor, &descriptor);
        let invited_node = NodeId([0xf1; 32]);

        let gap_call = operation_call(
            config,
            &owner_key,
            owner,
            None,
            0xd5,
            AuthorityOperationIntent::InvitePrivateNode {
                managed: gap_managed,
                control: Hash([0xd6; 32]),
                control_sequence: 0,
                control_previous: None,
                epoch: 0,
                node: NodeId([0xf0; 32]),
                node_identity: Hash([0xd7; 32]),
            },
        );
        let gap_approval =
            AuthorityOperationApproval::decode(&dispatch_operation(&mut actor, &gap_call)).unwrap();
        let gap_issuance = operation_issuance_ack(config, &gap_call, &gap_approval);

        let target_call = operation_call(
            config,
            &owner_key,
            owner,
            None,
            0xd8,
            AuthorityOperationIntent::InvitePrivateNode {
                managed,
                control: Hash([0xd9; 32]),
                control_sequence: 0,
                control_previous: None,
                epoch: 0,
                node: invited_node,
                node_identity: Hash([0xda; 32]),
            },
        );
        let (target_approval, target_issuance) =
            authorize_and_issue_operation(&mut actor, &target_call);
        assert_eq!(actor.state.operation_retirement_floor, 4);
        assert_eq!(actor.state.operation_retries.len(), 2);
        assert!(actor.state.operation_retries.iter().any(|record| {
            record.invocation == target_call.invocation.0 && record.issuance_ack.is_some()
        }));
        let member_set =
            private_member_set_commitment([descriptor.replicas[0].node, invited_node].into_iter())
                .unwrap();
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
        assert!(actor.state.retired_authority_operations.is_empty());

        assert!(dispatch_operation_ack(&mut actor, &gap_issuance));
        assert!(actor.state.operation_retries.is_empty());
        assert_eq!(actor.state.retired_authority_operations.len(), 2);
        assert_eq!(actor.state.operation_retirement_floor, 6);
        let after_compaction = actor.state.clone();
        assert!(dispatch_private_application(&mut actor, &pca));
        assert_eq!(actor.state, after_compaction);
        assert!(authority_state_is_valid(&config, &actor.state));
    }

    #[test]
    fn delayed_old_runtime_pca1_is_authenticated_by_its_source_after_upgrade() {
        let config = configuration();
        let owner = PrincipalId([0xe1; 32]);
        let owner_node = NodeId([0xe2; 32]);
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
        let invited_node = NodeId([0xf2; 32]);
        let invite_call = operation_call(
            config,
            &owner_key,
            owner,
            None,
            0xe5,
            AuthorityOperationIntent::InvitePrivateNode {
                managed: old_managed,
                control: Hash([0xe6; 32]),
                control_sequence: 0,
                control_previous: None,
                epoch: 0,
                node: invited_node,
                node_identity: Hash([0xe7; 32]),
            },
        );
        let (invite_approval, invite_issuance) =
            authorize_and_issue_operation(&mut actor, &invite_call);
        let member_set =
            private_member_set_commitment([descriptor.replicas[0].node, invited_node].into_iter())
                .unwrap();
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
        let upgrade_call = credential_call(
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
        let upgrade_approval = ManagementApproval::decode(&dispatch(&mut actor, &upgrade_call))
            .expect("runtime upgrade authorized");
        let mut upgrade_ack = application_ack(config, &upgrade_call, &upgrade_approval);
        upgrade_ack.applied_at = OBSERVED_SLOT + 2;
        resign_ack(&mut upgrade_ack);
        assert!(dispatch_ack(&mut actor, &upgrade_ack));
        assert_eq!(
            actor.state.managed_agents[1].runtime_deployment,
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
    fn pca1_rejects_missing_issuance_substitution_and_cross_domain_collisions() {
        let config = configuration();
        let owner = PrincipalId([0xa1; 32]);
        let owner_node = NodeId([0xa2; 32]);
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
        let invited_node = NodeId([0xf3; 32]);
        let member_set =
            private_member_set_commitment([descriptor.replicas[0].node, invited_node].into_iter())
                .unwrap();
        let call = operation_call(
            config,
            &owner_key,
            owner,
            None,
            0xa5,
            AuthorityOperationIntent::InvitePrivateNode {
                managed,
                control: Hash([0xa6; 32]),
                control_sequence: 0,
                control_previous: None,
                epoch: 0,
                node: invited_node,
                node_identity: Hash([0xa7; 32]),
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

        let mut bad_signature = pca.clone();
        bad_signature.signature[0] ^= 1;
        assert!(!dispatch_private_application(&mut actor, &bad_signature));

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
        collision_admin.invocation = pca.application_invocation;
        resign_admin(&mut collision_admin, &signing(0x21));
        let collision_state = collision_actor.state.clone();
        assert!(dispatch_admin(&mut collision_actor, &collision_admin).is_empty());
        assert_eq!(collision_actor.state, collision_state);
        assert!(dispatch_private_application(&mut collision_actor, &pca));

        assert!(dispatch_private_application(&mut actor, &pca));
        let after_application = actor.state.clone();
        let mut colliding_operation = call.clone();
        colliding_operation.invocation = pca.application_invocation;
        resign_operation_call(&mut colliding_operation, &owner_key);
        assert!(dispatch_operation(&mut actor, &colliding_operation).is_empty());
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
        assert!(dispatch(&mut actor, &colliding_management).is_empty());
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
        assert!(dispatch_admin(&mut actor, &colliding_admin).is_empty());
        assert_eq!(actor.state, after_application);
    }

    #[test]
    fn private_projection_rejects_out_of_order_gaps_forks_epochs_and_slot_rollback() {
        let config = configuration();
        let owner = PrincipalId([0x61; 32]);
        let owner_node = NodeId([0x62; 32]);
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
            private_member_set_commitment(descriptor.replicas.iter().map(|replica| replica.node))
                .unwrap();
        let invited_node = NodeId([0xf4; 32]);
        let invited_member_set =
            private_member_set_commitment([descriptor.replicas[0].node, invited_node].into_iter())
                .unwrap();

        let first_control = Hash([0x65; 32]);
        let first_call = operation_call(
            config,
            &owner_key,
            owner,
            None,
            0x66,
            AuthorityOperationIntent::InvitePrivateNode {
                managed,
                control: first_control,
                control_sequence: 0,
                control_previous: None,
                epoch: 0,
                node: invited_node,
                node_identity: Hash([0x67; 32]),
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
        let second_call = operation_call(
            config,
            &owner_key,
            owner,
            None,
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
        let third_node = NodeId([0xf5; 32]);
        let third_member_set =
            private_member_set_commitment([descriptor.replicas[0].node, third_node].into_iter())
                .unwrap();
        let third_call = operation_call(
            config,
            &owner_key,
            owner,
            None,
            0x6e,
            AuthorityOperationIntent::InvitePrivateNode {
                managed,
                control: third_control,
                control_sequence: 2,
                control_previous: Some(second_control),
                epoch: 1,
                node: third_node,
                node_identity: Hash([0x6f; 32]),
            },
        );
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
            let call = operation_call(config, &owner_key, owner, None, invocation, intent);
            let before = actor.state.clone();
            assert!(dispatch_operation(&mut actor, &call).is_empty());
            assert_eq!(actor.state, before);
        }

        let fourth_node = NodeId([0xf9; 32]);
        let fourth_member_set = private_member_set_commitment(
            [descriptor.replicas[0].node, third_node, fourth_node].into_iter(),
        )
        .unwrap();
        let fourth_call = operation_call(
            config,
            &owner_key,
            owner,
            None,
            0x89,
            AuthorityOperationIntent::InvitePrivateNode {
                managed,
                control: Hash([0x8a; 32]),
                control_sequence: 3,
                control_previous: Some(third_control),
                epoch: 1,
                node: fourth_node,
                node_identity: Hash([0x8b; 32]),
            },
        );
        let (fourth_approval, fourth_issuance) =
            authorize_and_issue_operation(&mut actor, &fourth_call);

        let fork = operation_call(
            config,
            &owner_key,
            owner,
            None,
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
                OBSERVED_SLOT + 3,
            ),
        );
        assert!(!dispatch_private_application(&mut actor, &rollback));
        assert!(authority_state_is_valid(&config, &actor.state));
    }

    #[test]
    fn private_projection_reconstruction_rejects_corruption_and_explicit_overflow() {
        let config = configuration();
        let owner = PrincipalId([0x51; 32]);
        let owner_node = NodeId([0x52; 32]);
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
        let invited_node = NodeId([0xf6; 32]);
        let member_set =
            private_member_set_commitment([descriptor.replicas[0].node, invited_node].into_iter())
                .unwrap();
        let call = operation_call(
            config,
            &owner_key,
            owner,
            None,
            0x55,
            AuthorityOperationIntent::InvitePrivateNode {
                managed,
                control: Hash([0x56; 32]),
                control_sequence: 0,
                control_previous: None,
                epoch: 0,
                node: invited_node,
                node_identity: Hash([0x57; 32]),
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
            private_member_set_commitment(descriptor.replicas.iter().map(|replica| replica.node))
                .unwrap()
                .0;
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
        rewritten_source.retired_authority_operations[0].operation_call[0] ^= 1;
        rewritten_source.operation_retirement_commitment =
            initial_operation_retirement_commitment(config).0;
        for record in &rewritten_source.retired_authority_operations {
            rewritten_source.operation_retirement_commitment = operation_retirement_commitment(
                Hash(rewritten_source.operation_retirement_commitment),
                record,
            )
            .0;
        }
        assert!(!authority_state_is_valid(&config, &rewritten_source));

        let mut rewritten_reservation = actor.state.clone();
        rewritten_reservation.retired_authority_operations[0].private_application_invocation = None;
        rewritten_reservation.operation_retirement_commitment =
            initial_operation_retirement_commitment(config).0;
        for record in &rewritten_reservation.retired_authority_operations {
            rewritten_reservation.operation_retirement_commitment =
                operation_retirement_commitment(
                    Hash(rewritten_reservation.operation_retirement_commitment),
                    record,
                )
                .0;
        }
        assert!(!authority_state_is_valid(&config, &rewritten_reservation));

        let mut rewritten_target = actor.state.clone();
        rewritten_target.retired_authority_operations[0]
            .private_operation
            .as_mut()
            .unwrap()
            .node = Some([0xfe; 32]);
        rewritten_target.operation_retirement_commitment =
            initial_operation_retirement_commitment(config).0;
        for record in &rewritten_target.retired_authority_operations {
            rewritten_target.operation_retirement_commitment = operation_retirement_commitment(
                Hash(rewritten_target.operation_retirement_commitment),
                record,
            )
            .0;
        }
        assert!(!authority_state_is_valid(&config, &rewritten_target));

        let mut collision = actor.state.clone();
        collision.retired_authority_operations[0].private_application_invocation =
            Some(collision.retired_authority_operations[0].invocation);
        assert!(!all_invocation_identifiers_are_unique(&collision));
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
            vec![actor.state.private_applications[0]; MAX_PRIVATE_APPLICATION_RECORDS + 1];
        assert!(!authority_state_is_valid(&config, &overflow));
    }

    #[test]
    fn general_retry_and_retirement_bounds_fail_closed_without_sequence_drift() {
        let config = configuration();
        let mut actor = actor();
        let catalog = install_catalog_projection(&mut actor);
        let reserve = MAX_EXACT_RETRY_RECORDS - exact_retry_count(&actor.state) - 1;
        fill_pending_management_retries(&mut actor, reserve);
        assert_eq!(exact_retry_count(&actor.state), MAX_EXACT_RETRY_RECORDS - 1);
        let last = invoke_operation_call(
            config,
            &signing(0x21),
            ADMIN_PRINCIPAL,
            Some(ADMIN_NODE),
            0xd1,
            0xd2,
            system_target(config),
            &catalog,
        );
        assert!(AuthorityOperationApproval::decode(&dispatch_operation(&mut actor, &last)).is_ok());
        assert_eq!(exact_retry_count(&actor.state), MAX_EXACT_RETRY_RECORDS);
        let overflow = invoke_operation_call(
            config,
            &signing(0x21),
            ADMIN_PRINCIPAL,
            Some(ADMIN_NODE),
            0xd3,
            0xd4,
            system_target(config),
            &catalog,
        );
        let before = actor.state.clone();
        assert!(dispatch_operation(&mut actor, &overflow).is_empty());
        assert_eq!(actor.state, before);

        let mut retired = SystemAuthority::new(&config.encode());
        let catalog = install_catalog_projection(&mut retired);
        for ordinal in 0..MAX_RETIRED_AUTHORITY_OPERATIONS {
            let sequence = retired.state.authorization_sequence + 1;
            let ordinal = u64::try_from(ordinal).unwrap().to_le_bytes();
            let row = RetiredAuthorityOperationRow {
                invocation: Hash::digest(
                    b"vos/test/system-authority/retired-operation-auth/v1",
                    &[&ordinal],
                )
                .0,
                acknowledgement_invocation: Hash::digest(
                    b"vos/test/system-authority/retired-operation-ack/v1",
                    &[&ordinal],
                )
                .0,
                authorization_sequence: sequence,
                operation_call: Hash::digest(
                    b"vos/test/system-authority/retired-operation-call/v1",
                    &[&ordinal],
                )
                .0,
                approval: Hash::digest(
                    b"vos/test/system-authority/retired-operation-approval/v1",
                    &[&ordinal],
                )
                .0,
                issuance_ack: Hash::digest(
                    b"vos/test/system-authority/retired-operation-aoi/v1",
                    &[&ordinal],
                )
                .0,
                issued_at: OBSERVED_SLOT,
                private_application_invocation: None,
                private_operation: None,
            };
            retired.state.authorization_sequence = sequence;
            retired.state.operation_retirement_floor = sequence;
            retired.state.operation_retirement_commitment = operation_retirement_commitment(
                Hash(retired.state.operation_retirement_commitment),
                &row,
            )
            .0;
            retired.state.retired_authority_operations.push(row);
        }
        assert!(authority_state_is_valid(&config, &retired.state));
        let saturated = invoke_operation_call(
            config,
            &signing(0x21),
            ADMIN_PRINCIPAL,
            None,
            0xd5,
            0xd6,
            system_target(config),
            &catalog,
        );
        let before = retired.state.clone();
        assert!(dispatch_operation(&mut retired, &saturated).is_empty());
        assert_eq!(retired.state, before);

        let mut over_limit = retired.state.clone();
        let mut extra = *over_limit.retired_authority_operations.last().unwrap();
        extra.authorization_sequence += 1;
        extra.invocation[0] ^= 1;
        extra.acknowledgement_invocation[0] ^= 1;
        over_limit.retired_authority_operations.push(extra);
        assert_eq!(
            over_limit.retired_authority_operations.len(),
            MAX_RETIRED_AUTHORITY_OPERATIONS + 1
        );
        assert!(!authority_state_is_valid(&config, &over_limit));
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
            let node = NodeId([0x60 + ordinal as u8; 32]);
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
        let member_node = NodeId([0x85; 32]);
        let mut actor = actor();
        enroll(
            &mut actor,
            &signing(0x80),
            beneficiary,
            NodeId([0x80; 32]),
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
        let owner_node = NodeId([0x93; 32]);
        let outsider_key = signing(0x94);
        let outsider = PrincipalId([0x95; 32]);
        let outsider_node = NodeId([0x96; 32]);
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
        let install_call = credential_call(
            config,
            &signing(0x21),
            ADMIN_PRINCIPAL,
            Some(ADMIN_NODE),
            0x99,
            managed,
            ManagementRequest::Install(Box::new(install.clone())),
        );
        let install_approval = ManagementApproval::decode(&dispatch(&mut actor, &install_call))
            .expect("admin installs the owned actor");
        assert!(dispatch_ack(
            &mut actor,
            &application_ack(config, &install_call, &install_approval)
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
        assert!(dispatch_ack(
            &mut actor,
            &application_ack(config, &owner_call, &owner_approval)
        ));

        let admin_call = credential_call(
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
        let admin_approval = ManagementApproval::decode(&dispatch(&mut actor, &admin_call))
            .expect("admin may resume an exactly projected actor");
        assert!(dispatch_ack(
            &mut actor,
            &application_ack(config, &admin_call, &admin_approval)
        ));

        let mismatched_target = vos::agent_sdk::authority::ManagedAgentTarget {
            runtime_deployment: DeploymentId([0xaa; 32]),
            ..managed
        };
        let mismatch = credential_call(
            config,
            &signing(0x21),
            ADMIN_PRINCIPAL,
            Some(ADMIN_NODE),
            0xa3,
            mismatched_target,
            request,
        );
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
        let ManagementRequest::Create(descriptor) = &mut call.request else {
            unreachable!()
        };
        descriptor.authority = call.authority.binding;
        resign(&mut call, &key);
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
        resign(&mut conflict, &key);
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
        let mut left_node_bytes = [0xee; 32];
        left_node_bytes[31] = 1;
        let mut right_node_bytes = left_node_bytes;
        right_node_bytes[31] = 2;
        let left_node = NodeId(left_node_bytes);
        let right_node = NodeId(right_node_bytes);

        let config = configuration();
        let mut actor = actor();
        enroll(
            &mut actor,
            &left_key,
            left_principal,
            left_node,
            BuiltinPrincipalRole::Member,
        );
        enroll(
            &mut actor,
            &right_key,
            right_principal,
            right_node,
            BuiltinPrincipalRole::Member,
        );
        let left = create_call(
            config,
            &left_key,
            left_principal,
            Some(left_node),
            0xd1,
            AgentProfile::Private,
            0xd2,
        );
        let right = create_call(
            config,
            &right_key,
            right_principal,
            Some(right_node),
            0xd3,
            AgentProfile::Private,
            0xd4,
        );
        assert!(!dispatch(&mut actor, &left).is_empty());
        assert!(!dispatch(&mut actor, &right).is_empty());

        let mut confused = right;
        confused.authenticated_node = Some(left_node);
        resign(&mut confused, &right_key);
        confused.invocation = InvocationId([0xd5; 32]);
        resign(&mut confused, &right_key);
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
    fn retry_capacity_saturates_without_partial_sequence_mutation() {
        let config = configuration();
        let mut actor = actor();
        fill_pending_management_retries(&mut actor, MAX_EXACT_RETRY_RECORDS);
        assert!(authority_state_is_valid(&config, &actor.state));

        let call = create_call(
            config,
            &signing(0x21),
            ADMIN_PRINCIPAL,
            Some(ADMIN_NODE),
            0xf0,
            AgentProfile::Local,
            0xf1,
        );
        let before = actor.state.clone();
        assert!(dispatch(&mut actor, &call).is_empty());
        assert_eq!(actor.state, before);
    }

    #[test]
    fn admin_exact_retry_survives_combined_retry_capacity() {
        let config = configuration();
        let key = signing(0x21);
        let call = admin_call(
            config,
            &key,
            ADMIN_PRINCIPAL,
            ADMIN_NODE,
            0xf0,
            1,
            AuthorityAdminOperation::EnrollPrincipal {
                principal: PrincipalId([0xf1; 32]),
                credential: enrollment(&signing(0xf2), AuthorityCredentialKind::Api),
            },
        );
        let mut actor = actor();
        let result = dispatch_admin(&mut actor, &call);
        assert!(!result.is_empty());

        fill_pending_management_retries(&mut actor, MAX_EXACT_RETRY_RECORDS - 1);
        assert!(authority_state_is_valid(&config, &actor.state));

        let saturated = actor.state.clone();
        assert_eq!(dispatch_admin(&mut actor, &call), result);
        assert_eq!(actor.state, saturated);
        let fresh = admin_call(
            config,
            &key,
            ADMIN_PRINCIPAL,
            ADMIN_NODE,
            0xf3,
            2,
            AuthorityAdminOperation::BindNodeOwner {
                node: NodeId([0xf4; 32]),
                owner: PrincipalId([0xf1; 32]),
            },
        );
        assert!(dispatch_admin(&mut actor, &fresh).is_empty());
        assert_eq!(actor.state, saturated);
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
            approval.request.authority_operation(),
            Some(AuthorityOperationKind::CreateAgent)
        );
        assert_eq!(actor.state.managed_agents, vec![root_managed_agent(config)]);

        let ack = application_ack(config, &call, &approval);
        let ack_bytes = ack.encode().unwrap();
        assert_eq!(ack_bytes.get(..4), Some(b"MAA1".as_slice()));
        assert!(dispatch_ack(&mut actor, &ack));
        let live = &actor.state.managed_agents
            [managed_agent(&actor.state, call.managed.agent).expect("acknowledged Agent is live")];
        assert_eq!(live.agent, call.managed.agent.0);
        assert_eq!(live.authority, config.binding);
        assert!(actor.state.retries[0].finalized);

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
        let valid = application_ack(config, &call, &approval);

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
            };
            let before = actor.state.clone();
            assert!(!dispatch_ack(&mut actor, &ack));
            assert_eq!(actor.state, before);
            assert_eq!(actor.state.managed_agents, vec![root_managed_agent(config)]);
        }

        let mut actor = SystemAuthority {
            configuration: pending.configuration,
            state: pending.state.clone(),
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

        // First reserve the candidate's prospective MAA1 ID as another ACC1
        // ID. The candidate must be denied before consuming a sequence or
        // adding its pending Create effect.
        let mut blocker = create_call(
            config,
            &key,
            ADMIN_PRINCIPAL,
            Some(ADMIN_NODE),
            0x77,
            AgentProfile::Local,
            0x78,
        );
        blocker.invocation = candidate_ack;
        resign(&mut blocker, &key);
        let mut actor = actor();
        let blocker_approval = ManagementApproval::decode(&dispatch(&mut actor, &blocker)).unwrap();
        assert_eq!(actor.state.retries.len(), 1);

        let before = actor.state.clone();
        assert!(dispatch(&mut actor, &candidate).is_empty());
        assert_eq!(actor.state, before);

        // The reciprocal collision is also reserved immediately: a later
        // ACC1 cannot claim the blocker's prospective MAA1 ID while the
        // blocker is still pending finalization.
        let mut authorization_collision = create_call(
            config,
            &key,
            ADMIN_PRINCIPAL,
            Some(ADMIN_NODE),
            0x79,
            AgentProfile::Local,
            0x7a,
        );
        authorization_collision.invocation = blocker_approval.acknowledgement_invocation;
        resign(&mut authorization_collision, &key);
        assert!(dispatch(&mut actor, &authorization_collision).is_empty());
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
        let ack = application_ack(config, &call, &approval);
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
        other_call.invocation = ack.acknowledgement_invocation;
        resign(&mut other_call, &signing(0x21));
        let before = actor.state.clone();
        // The actor also rejects an ACC1 that reuses a finalized MAA1 runtime
        // invocation, even though the runtime should catch this first.
        assert!(dispatch(&mut actor, &other_call).is_empty());
        assert_eq!(actor.state, before);
    }

    #[test]
    fn admin_operations_are_canonical_exact_and_survive_restart() {
        let config = configuration();
        let admin_key = signing(0x21);
        let principal = PrincipalId([0x81; 32]);
        let first_key = signing(0x82);
        let second_key = signing(0x83);
        let first_node = NodeId([0x84; 32]);
        let second_node = NodeId([0x85; 32]);
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
        assert!(actor.state.nodes.iter().all(|row| row.owner != principal.0));

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
                AuthorityAdminOperation::BindNodeOwner {
                    node: first_node,
                    owner: principal,
                },
            ),
            (
                0x84,
                AuthorityAdminOperation::BindNodeOwner {
                    node: second_node,
                    owner: principal,
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
                .iter()
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
        assert_eq!(dispatch_admin(&mut reopened, &enroll_call), enrolled);
        assert_eq!(reopened.state, before_retry);
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
        resign_admin(&mut cross_space, &key);
        assert!(dispatch_admin(&mut actor, &cross_space).is_empty());

        let mut cross_target = call.clone();
        cross_target.authority.system_agent = AgentId([0xa2; 32]);
        resign_admin(&mut cross_target, &key);
        assert!(dispatch_admin(&mut actor, &cross_target).is_empty());

        let mut cross_node = call.clone();
        cross_node.authenticated_node = NodeId([0xa3; 32]);
        resign_admin(&mut cross_node, &key);
        assert!(dispatch_admin(&mut actor, &cross_node).is_empty());

        let mut cross_principal = call.clone();
        cross_principal.administrator = PrincipalId([0xa4; 32]);
        resign_admin(&mut cross_principal, &key);
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
        resign_admin(&mut weak_enrollment, &key);
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
            AuthorityAdminOperation::BindNodeOwner {
                node: NodeId([0xb3; 32]),
                owner: principal,
            },
        );
        assert!(dispatch_admin(&mut actor, &stale).is_empty());

        let mut conflict = call;
        conflict.operation = AuthorityAdminOperation::BindNodeOwner {
            node: NodeId([0xb4; 32]),
            owner: principal,
        };
        resign_admin(&mut conflict, &key);
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
        assert!(dispatch(&mut actor, &colliding_management).is_empty());
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
        let replacement_node = NodeId([0xc4; 32]);
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
                .iter()
                .all(|row| row.owner != inaccessible.0)
        );
        let no_node_admin = admin_call(
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
        let revoke_bootstrap = admin_call(
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
        assert!(!dispatch_admin(&mut actor, &revoke_bootstrap).is_empty());
        let revoke_last = admin_call(
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
        let before = actor.state.clone();
        assert!(dispatch_admin(&mut actor, &revoke_last).is_empty());
        assert_eq!(actor.state, before);

        let bind_replacement = admin_call(
            config,
            &replacement_key,
            ADMIN_PRINCIPAL,
            ADMIN_NODE,
            0xca,
            5,
            AuthorityAdminOperation::BindNodeOwner {
                node: replacement_node,
                owner: inaccessible,
            },
        );
        assert!(!dispatch_admin(&mut actor, &bind_replacement).is_empty());
        let demote_bootstrap = admin_call(
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
        assert!(!dispatch_admin(&mut actor, &demote_bootstrap).is_empty());
        let unbind_last_admin_node = admin_call(
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
            AuthorityAdminOperation::BindNodeOwner {
                node: NodeId([0xd3; 32]),
                owner: PrincipalId([0xd1; 32]),
            },
        );
        assert!(!dispatch_admin(&mut actor, &bind).is_empty());
        assert!(authority_state_is_valid(&config, &actor.state));

        let mut reordered = actor.state.clone();
        reordered.credentials.swap(0, 1);
        assert!(!authority_state_is_valid(&config, &reordered));
        let mut reordered_history = actor.state.clone();
        reordered_history.admin_retries.swap(0, 1);
        assert!(!authority_state_is_valid(&config, &reordered_history));
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
        let mut dangling_node = actor.state.clone();
        dangling_node
            .nodes
            .iter_mut()
            .find(|row| row.node == [0xd3; 32])
            .unwrap()
            .owner = [0xd4; 32];
        assert!(!authority_state_is_valid(&config, &dangling_node));

        let mut orphaned_agent = actor.state.clone();
        orphaned_agent.managed_agents.push(ManagedAgentRow {
            agent: [0xd5; 32],
            owner: [0xd6; 32],
            profile: AgentProfile::Private as u8,
            runtime_deployment: [0xd7; 32],
            runtime_program: [0xd8; 32],
            runtime_producer: [0xd9; 32],
            authority: config.binding,
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
            let mut node = [0xe3; 32];
            node[..8].copy_from_slice(&(ordinal as u64).to_le_bytes());
            let principal = PrincipalId(principal);
            let node = NodeId(node);
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
                AuthorityAdminOperation::BindNodeOwner {
                    node,
                    owner: principal,
                },
            );
        }
        assert_eq!(actor.state.roles.len(), MAX_AUTHORITY_PRINCIPALS);
        assert_eq!(actor.state.credentials.len(), MAX_AUTHORITY_CREDENTIALS);
        assert_eq!(actor.state.nodes.len(), MAX_AUTHORITY_NODES);
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
    fn read_only_management_has_no_acc1_actor_message() {
        let config = configuration();
        let descriptor = descriptor(config, ADMIN_PRINCIPAL, AgentProfile::Local, 0x61);
        let managed = target_for(&descriptor);
        let call = credential_call(
            config,
            &signing(0x21),
            ADMIN_PRINCIPAL,
            Some(ADMIN_NODE),
            0x62,
            managed,
            ManagementRequest::InspectResources,
        );
        assert!(call.encode().is_err());

        let mut actor = actor();
        let before = actor.state.clone();
        assert!(dispatch_bytes(&mut actor, call.signing_bytes(), Some(context(&call))).is_empty());
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
        resign(&mut call, &key);
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
        resign(&mut impossible, &key);
        let before = actor.state.clone();
        assert!(dispatch(&mut actor, &impossible).is_empty());
        assert_eq!(actor.state, before);
    }

    #[test]
    fn generated_agent_schema_marks_authority_methods_as_explicit_linear_public_preflight() {
        let method = SystemAuthorityMsg::AGENT_METHODS;
        assert_eq!(method.len(), 6);
        assert_eq!(method[0].name, "authorize");
        assert_eq!(method[0].mode, vos::agent_sdk::schema::MethodMode::Linear);
        assert!(method[0].explicit);
        assert_eq!(method[1].name, "finalize");
        assert_eq!(method[1].mode, vos::agent_sdk::schema::MethodMode::Linear);
        assert!(method[1].explicit);
        assert_eq!(method[2].name, "authorize_operation");
        assert_eq!(method[2].mode, vos::agent_sdk::schema::MethodMode::Linear);
        assert!(method[2].explicit);
        assert_eq!(method[3].name, "acknowledge_issuance");
        assert_eq!(method[3].mode, vos::agent_sdk::schema::MethodMode::Linear);
        assert!(method[3].explicit);
        assert_eq!(method[4].name, "acknowledge_private_application");
        assert_eq!(method[4].mode, vos::agent_sdk::schema::MethodMode::Linear);
        assert!(method[4].explicit);
        assert_eq!(method[5].name, "administer");
        assert_eq!(method[5].mode, vos::agent_sdk::schema::MethodMode::Linear);
        assert!(method[5].explicit);
        assert_eq!(SystemAuthorityMsg::AGENT_AUTHORIZATIONS.len(), 6);
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
