//! Clean, portable policy actor for standard Agent management.
//!
//! The actor accepts canonical `ACC1` management calls and self-authenticating
//! `AAD1` identity-admin calls delivered with an exact clean `AIC1` invocation
//! context. It performs policy, credential, and Admin-accessibility checks
//! inside the guest and retains exact results for replay. Agent and actor
//! lifecycle approvals remain pending until separately signed exact
//! durable-application acknowledgements are observed.

#![cfg_attr(target_arch = "riscv64", no_std)]

use core::cmp::{max, min};
use core::num::NonZeroU64;

use ed25519_dalek::{Signature, VerifyingKey};
use vos::agent_sdk::authority::{
    AgentAuthorityBinding, AuthorityActorTarget, AuthorityAdminCall, AuthorityAdminOperation,
    AuthorityAdminResult, AuthorityBuiltinRole, AuthorityCredentialCall,
    AuthorityCredentialEnrollment, AuthorityCredentialVerifier, AuthorityEvidence, AuthorityIssuer,
    AuthorityLaneRoots, AuthorityVerifier, ManagementApplicationAck, ManagementApproval,
};
use vos::agent_sdk::wire::CanonicalWire as _;
use vos::agent_sdk::{
    ActorId, AgentId, AgentProfile, CredentialId, DeploymentId, Hash, InvocationContext,
    InvocationId, MAX_INVOCATION_MESSAGE_BYTES, MAX_INVOCATION_REPLY_BYTES,
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
/// may only be retired by a future, explicitly ordered acknowledgement floor.
pub const MAX_EXACT_RETRY_RECORDS: usize = 128;
/// Worst-case canonical ACC1/AAD1 calls plus MAP1/AAR1 results and MAA1
/// acknowledgements retained by the bounded exact-retry tables. This leaves
/// over one MiB of the standard state ceiling for row metadata and actor
/// framing.
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
            admin_retries: Vec::new(),
        }
    }
}

/// Linear policy state for one Space's built-in system Agent.
#[actor(agent, state_version = 5)]
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
            if state
                .retries
                .len()
                .saturating_add(state.admin_retries.len())
                >= MAX_EXACT_RETRY_RECORDS
            {
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
            approval_bytes
        }
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
            if state
                .retries
                .len()
                .saturating_add(state.admin_retries.len())
                >= MAX_EXACT_RETRY_RECORDS
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
    apply_application_plan(state, plan);
    let record = &mut state.retries[record_index];
    record.finalized = true;
    record.acknowledgement = Some(ack_commitment.0);
    record.acknowledgement_bytes = Some(encoded_ack.to_vec());
    record.reopened_state = Some(ack.reopened_state.0);
    record.applied_at = Some(ack.applied_at);
    true
}

enum ApplicationPlan {
    None,
    Create {
        index: usize,
        row: ManagedAgentRow,
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
            Some(ApplicationPlan::Create {
                index,
                row: row.clone(),
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
            Some(ApplicationPlan::UpgradeRuntime {
                index,
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
        ApplicationPlan::Create { index, row } => state.managed_agents.insert(index, row),
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
            to_deployment,
            to_program,
            producer,
        } => {
            let row = &mut state.managed_agents[index];
            row.runtime_deployment = to_deployment;
            row.runtime_program = to_program;
            row.runtime_producer = producer;
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
        && state.admin_retries.iter().all(|record| {
            record.invocation != authorization.0 && record.invocation != acknowledgement.0
        })
}

fn authenticated_role(
    state: &AuthorityLinearState,
    call: &AuthorityCredentialCall,
) -> Option<BuiltinPrincipalRole> {
    let credential = state
        .credentials
        .binary_search_by(|row| row.credential.cmp(&call.credential.0))
        .ok()
        .map(|index| &state.credentials[index])?;
    if credential.principal != call.principal.0
        || credential.public_key != call.credential_public_key
        || credential.status != CredentialStatus::Active
    {
        return None;
    }
    let node = call.authenticated_node?;
    let node = state
        .nodes
        .binary_search_by(|row| row.node.cmp(&node.0))
        .ok()
        .map(|index| &state.nodes[index])?;
    if node.owner != call.principal.0 {
        return None;
    }
    state
        .roles
        .binary_search_by(|row| row.principal.cmp(&call.principal.0))
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
            lifecycle_owner(configuration, state, call, role)?;
            if pending_runtime_transition_conflicts(state, call) {
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
    let horizon = observed_slot.saturating_add(MAX_APPROVAL_VALIDITY_SLOTS);
    let valid_from = max(call.requested_valid_from, observed_slot);
    let expires_at = min(call.requested_expires_at, horizon);
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
        && state
            .retries
            .len()
            .saturating_add(state.admin_retries.len())
            <= MAX_EXACT_RETRY_RECORDS
        && sorted_unique_by(&state.credentials, |row| row.credential)
        && sorted_unique_by(&state.nodes, |row| row.node)
        && sorted_unique_by(&state.roles, |row| row.principal)
        && sorted_unique_by(&state.managed_agents, |row| row.agent)
        && sorted_unique_by(&state.retries, |row| row.invocation)
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
        && state
            .admin_retries
            .iter()
            .all(|row| admin_retry_shape_is_valid(configuration, state, row))
        && state.administration_generation
            == u64::try_from(state.admin_retries.len())
                .ok()
                .and_then(|count| count.checked_add(1))
                .unwrap_or(0)
        && retry_identifiers_are_unique(&state.retries)
        && admin_generations_are_unique(&state.admin_retries)
        && retry_families_are_disjoint(&state.retries, &state.admin_retries)
        && admin_history_reconstructs_identity(configuration, state)
        && management_history_reconstructs_policy(configuration, state)
}

fn management_history_reconstructs_policy(
    configuration: &SystemAuthorityConfiguration,
    state: &AuthorityLinearState,
) -> bool {
    let mut replay = AuthorityLinearState::bootstrap(*configuration);
    // Create effects require their owner to remain enrolled. Identity history
    // is reconstructed independently; use its already-validated final role
    // table while replaying the orthogonal management sequence.
    replay.roles.clone_from(&state.roles);
    let mut history = state.retries.iter().collect::<Vec<_>>();
    history.sort_unstable_by_key(|record| record.authorization_sequence);
    for record in history {
        let Some(expected_sequence) = replay.authorization_sequence.checked_add(1) else {
            return false;
        };
        if record.authorization_sequence != expected_sequence {
            return false;
        }
        let Ok(call) = AuthorityCredentialCall::decode(&record.credential_call_bytes) else {
            return false;
        };
        let Ok(approval) = ManagementApproval::decode(&record.approval) else {
            return false;
        };
        if call.invocation.0 != record.invocation
            || call.commitment().0 != record.credential_call
            || call.encode().ok().as_deref() != Some(record.credential_call_bytes.as_slice())
            || call.verify_with(&Ed25519CredentialVerifier).is_err()
            || !authority_target_matches(configuration, &call.authority)
            || approval.commitment().0 != record.approval_commitment
            || approval.encode().ok().as_deref() != Some(record.approval.as_slice())
            || approval.authorization_sequence.get() != record.authorization_sequence
            || approval.acknowledgement_invocation.0 != record.acknowledgement_invocation
            || !approval.matches_call(&call)
            || reconstruction_effect(configuration, &replay, &call).as_ref() != Some(&record.effect)
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
            let Some(plan) = application_plan(configuration, &replay, &record.effect, &call, &ack)
            else {
                return false;
            };
            apply_application_plan(&mut replay, plan);
        }
        replay.retries.push((*record).clone());
    }
    replay.authorization_sequence == state.authorization_sequence
        && replay.managed_agents == state.managed_agents
        && replay.managed_actors == state.managed_actors
        && replay.retired_actor_installations == state.retired_actor_installations
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
            reconstruction_lifecycle_row(configuration, state, call)?;
            if pending_runtime_transition_conflicts(state, call) {
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

fn retry_families_are_disjoint(
    retries: &[ExactRetryRecord],
    admin_retries: &[AdminRetryRecord],
) -> bool {
    retries.iter().all(|retry| {
        admin_retries.iter().all(|admin| {
            retry.invocation != admin.invocation
                && retry.acknowledgement_invocation != admin.invocation
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

fn retry_identifiers_are_unique(records: &[ExactRetryRecord]) -> bool {
    records.iter().enumerate().all(|(index, record)| {
        records.iter().enumerate().all(|(other_index, other)| {
            index == other_index
                || (record.authorization_sequence != other.authorization_sequence
                    && record.acknowledgement_invocation != other.invocation
                    && other.acknowledgement_invocation != record.invocation
                    && record.acknowledgement_invocation != other.acknowledgement_invocation)
        })
    })
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
        let call = credential_call(
            config,
            &signing(0x21),
            ADMIN_PRINCIPAL,
            Some(ADMIN_NODE),
            0x90,
            target_for(descriptor),
            ManagementRequest::Create(Box::new(descriptor.clone())),
        );
        let approval = ManagementApproval::decode(&dispatch(actor, &call))
            .expect("fixture Create must be authorized");
        assert!(dispatch_ack(
            actor,
            &application_ack(config, &call, &approval)
        ));
    }

    fn fill_pending_management_retries(actor: &mut SystemAuthority, count: usize) {
        let config = actor.configuration;
        for ordinal in 1..=count {
            let byte = u8::try_from(ordinal).expect("bounded retry fixture");
            let install = actor_install(
                AgentId(config.system_agent),
                &std::format!("pending-{ordinal}"),
                byte,
            );
            let call = credential_call(
                config,
                &signing(0x21),
                ADMIN_PRINCIPAL,
                Some(ADMIN_NODE),
                byte,
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
            5,
            "the actor projection is a clean Linear state generation",
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

        let mut no_ssh_node = base.clone();
        no_ssh_node.authenticated_node = None;
        resign(&mut no_ssh_node, &admin_key);
        cases.push(no_ssh_node);

        let mut bad_signature = base;
        bad_signature.signature[0] ^= 1;
        cases.push(bad_signature);

        for call in cases {
            let mut actor = actor();
            let before = actor.state.clone();
            assert!(dispatch(&mut actor, &call).is_empty());
            assert_eq!(actor.state, before, "a denial must not mutate state");
        }
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
        assert_eq!(method.len(), 3);
        assert_eq!(method[0].name, "authorize");
        assert_eq!(method[0].mode, vos::agent_sdk::schema::MethodMode::Linear);
        assert!(method[0].explicit);
        assert_eq!(method[1].name, "finalize");
        assert_eq!(method[1].mode, vos::agent_sdk::schema::MethodMode::Linear);
        assert!(method[1].explicit);
        assert_eq!(method[2].name, "administer");
        assert_eq!(method[2].mode, vos::agent_sdk::schema::MethodMode::Linear);
        assert!(method[2].explicit);
        assert_eq!(SystemAuthorityMsg::AGENT_AUTHORIZATIONS.len(), 3);
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
