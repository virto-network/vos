//! Clean, portable policy actor for standard Agent management.
//!
//! The actor accepts only canonical `ACC1` credential calls delivered with an
//! exact clean `AIC1` invocation context.  It performs policy and credential
//! verification inside the guest, emits deterministic `MAP1` approvals, and
//! retains exact results for replay.  A Create approval remains pending until
//! a separately signed durable-application acknowledgement is observed.

#![cfg_attr(target_arch = "riscv64", no_std)]

use core::cmp::{max, min};
use core::num::NonZeroU64;

use ed25519_dalek::{Signature, VerifyingKey};
use vos::agent_sdk::authority::{
    AgentAuthorityBinding, AuthorityActorTarget, AuthorityCredentialCall,
    AuthorityCredentialVerifier, AuthorityEvidence, AuthorityIssuer, AuthorityLaneRoots,
    AuthorityVerifier, ManagementApplicationAck, ManagementApproval,
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
pub const SYSTEM_AUTHORITY_CONFIGURATION_MAGIC: [u8; 4] = *b"SAC1";

/// Maximum durable rows in each caller table.
pub const MAX_AUTHORITY_CREDENTIALS: usize = 64;
pub const MAX_AUTHORITY_NODES: usize = 64;
pub const MAX_AUTHORITY_PRINCIPALS: usize = 64;
/// Maximum Agents for which this actor retains lifecycle policy state.
pub const MAX_MANAGED_AGENTS: usize = 256;
/// Exact approvals are deliberately bounded. Saturation fails closed; records
/// may only be retired by a future, explicitly ordered acknowledgement floor.
pub const MAX_EXACT_RETRY_RECORDS: usize = 128;
/// Worst-case canonical ACC1 + MAP1 + MAA1 preimages retained by the bounded
/// exact-retry table. This leaves over one MiB of the standard state ceiling
/// for row metadata and actor framing.
pub const MAX_RETAINED_EXACT_WIRE_BYTES: usize = MAX_EXACT_RETRY_RECORDS
    * (MAX_INVOCATION_MESSAGE_BYTES + MAX_INVOCATION_REPLY_BYTES + MAX_INVOCATION_MESSAGE_BYTES);
/// Policy will never authorize farther than this many logical slots after the
/// slot at which unseen work was accepted.
pub const MAX_APPROVAL_VALIDITY_SLOTS: u64 = 4_096;

const CONFIG_FIXED_FIELDS: usize = 13;
const CONFIG_ENCODED_BYTES: usize =
    SYSTEM_AUTHORITY_CONFIGURATION_MAGIC.len() + 32 + CONFIG_FIXED_FIELDS * 32 + 8;
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
    pub binding: AuthorityBindingState,
    pub bootstrap_principal: [u8; 32],
    pub bootstrap_credential_public_key: [u8; 32],
    pub bootstrap_node: [u8; 32],
}

impl SystemAuthorityConfiguration {
    pub fn is_valid(self) -> bool {
        self.space != [0; 32]
            && self.system_agent != [0; 32]
            && self.system_runtime_deployment != [0; 32]
            && self.bootstrap_principal != [0; 32]
            && self.bootstrap_credential_public_key != [0; 32]
            && CredentialId::of_public_key(&self.bootstrap_credential_public_key)
                != CredentialId::ZERO
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
        bytes.extend_from_slice(&self.binding.policy);
        bytes.extend_from_slice(&self.binding.issuer.principal);
        bytes.extend_from_slice(&self.binding.issuer.actor);
        bytes.extend_from_slice(&self.binding.issuer.deployment);
        bytes.extend_from_slice(&self.binding.issuer.program);
        bytes.extend_from_slice(&self.binding.issuer.producer);
        bytes.extend_from_slice(&self.binding.public_key);
        bytes.extend_from_slice(&self.binding.initial_epoch.to_le_bytes());
        bytes.extend_from_slice(&self.bootstrap_principal);
        bytes.extend_from_slice(&self.bootstrap_credential_public_key);
        bytes.extend_from_slice(&self.bootstrap_node);
        bytes
    }

    /// Decode SAC1 exactly. Prior clean generations, truncation, and trailing
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
        let bootstrap_principal = take_fixed(bytes, &mut cursor)?;
        let bootstrap_credential_public_key = take_fixed(bytes, &mut cursor)?;
        let bootstrap_node = take_fixed(bytes, &mut cursor)?;
        if cursor != bytes.len() {
            return None;
        }
        let value = Self {
            space,
            system_agent,
            system_runtime_deployment,
            binding: AuthorityBindingState {
                policy,
                issuer,
                public_key,
                initial_epoch,
            },
            bootstrap_principal,
            bootstrap_credential_public_key,
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
pub enum PendingManagementEffect {
    None,
    Create(ManagedAgentRow),
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
    pub credential_call: [u8; 32],
    pub credential_call_bytes: Vec<u8>,
    pub approval_commitment: [u8; 32],
    pub authorization_sequence: u64,
    pub approval: Vec<u8>,
    pub effect: PendingManagementEffect,
    pub finalized: bool,
    pub acknowledgement_invocation: Option<[u8; 32]>,
    pub acknowledgement: Option<[u8; 32]>,
    pub acknowledgement_bytes: Option<Vec<u8>>,
    pub reopened_state: Option<[u8; 32]>,
    pub applied_at: Option<u64>,
}

#[derive(
    vos::rkyv::Archive, vos::rkyv::Serialize, vos::rkyv::Deserialize, Clone, Debug, PartialEq, Eq,
)]
#[rkyv(crate = vos::rkyv)]
pub struct AuthorityLinearState {
    initialized: bool,
    epoch: u64,
    authorization_sequence: u64,
    credentials: Vec<CredentialRow>,
    nodes: Vec<NodeOwnerRow>,
    roles: Vec<PrincipalRoleRow>,
    managed_agents: Vec<ManagedAgentRow>,
    retries: Vec<ExactRetryRecord>,
}

impl AuthorityLinearState {
    fn inert() -> Self {
        Self {
            initialized: false,
            epoch: 0,
            authorization_sequence: 0,
            credentials: Vec::new(),
            nodes: Vec::new(),
            roles: Vec::new(),
            managed_agents: Vec::new(),
            retries: Vec::new(),
        }
    }

    fn bootstrap(config: SystemAuthorityConfiguration) -> Self {
        let credential = CredentialId::of_public_key(&config.bootstrap_credential_public_key);
        let mut credentials = Vec::with_capacity(1);
        credentials.push(CredentialRow {
            credential: credential.0,
            principal: config.bootstrap_principal,
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
        Self {
            initialized: true,
            epoch: config.binding.initial_epoch,
            authorization_sequence: 0,
            credentials,
            nodes,
            roles,
            managed_agents: Vec::new(),
            retries: Vec::new(),
        }
    }
}

/// Linear policy state for one Space's built-in system Agent.
#[actor(agent, state_version = 1)]
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
}

struct Ed25519CredentialVerifier;

impl AuthorityCredentialVerifier for Ed25519CredentialVerifier {
    fn verify(&self, public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
        let Ok(verifying_key) = VerifyingKey::from_bytes(public_key) else {
            return false;
        };
        verifying_key
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
    if state
        .retries
        .iter()
        .any(|record| record.acknowledgement_invocation == Some(call.invocation.0))
    {
        return Vec::new();
    }
    match retry_record(state, call.invocation) {
        Ok(index) => {
            let record = &state.retries[index];
            if record.credential_call != call_commitment.0
                || record.credential_call_bytes != encoded_call
            {
                return Vec::new();
            }
            let Ok(approval) = ManagementApproval::decode(&record.approval) else {
                return Vec::new();
            };
            if approval.matches_call(&call)
                && approval.commitment().0 == record.approval_commitment
                && approval.authorization_sequence.get() == record.authorization_sequence
                && authority_target_matches(configuration, &approval.authority)
            {
                return record.approval.clone();
            }
            return Vec::new();
        }
        Err(index) => {
            if state.retries.len() >= MAX_EXACT_RETRY_RECORDS {
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
            let Ok(approval_bytes) = approval.encode() else {
                return Vec::new();
            };
            if approval_bytes.len() > MAX_INVOCATION_REPLY_BYTES {
                return Vec::new();
            }

            let record = ExactRetryRecord {
                invocation: call.invocation.0,
                credential_call: call_commitment.0,
                credential_call_bytes: encoded_call.to_vec(),
                approval_commitment: approval.commitment().0,
                authorization_sequence,
                approval: approval_bytes.clone(),
                effect,
                finalized: false,
                acknowledgement_invocation: None,
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

    // Runtime invocation IDs are global exact-retry keys. An MAA1 must not
    // reuse any ACC1 ID, including one belonging to another pending record.
    if state
        .retries
        .iter()
        .any(|record| record.invocation == ack.acknowledgement_invocation.0)
    {
        return false;
    }
    if let Some(record) = state
        .retries
        .iter()
        .find(|record| record.acknowledgement_invocation == Some(ack.acknowledgement_invocation.0))
    {
        return record.invocation == ack.authorization_invocation.0
            && record.finalized
            && record.acknowledgement == Some(ack_commitment.0)
            && record.acknowledgement_bytes.as_deref() == Some(encoded_ack)
            && record.reopened_state == Some(ack.reopened_state.0)
            && record.applied_at == Some(ack.applied_at);
    }

    let Ok(record_index) = retry_record(state, ack.authorization_invocation) else {
        return false;
    };
    let record = &state.retries[record_index];
    if record.finalized
        || record.credential_call != ack.credential_call.0
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

    let Some(plan) = application_plan(configuration, state, &record.effect) else {
        return false;
    };
    apply_application_plan(state, plan);
    let record = &mut state.retries[record_index];
    record.finalized = true;
    record.acknowledgement_invocation = Some(ack.acknowledgement_invocation.0);
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
) -> Option<ApplicationPlan> {
    match effect {
        PendingManagementEffect::None => Some(ApplicationPlan::None),
        PendingManagementEffect::Create(row) => {
            if state.managed_agents.len() >= MAX_MANAGED_AGENTS
                || row.authority != configuration.binding
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
        | ManagementRequest::RemoveLeaf { .. }
        | ManagementRequest::ChangeReplicas { .. } => {
            lifecycle_owner(configuration, state, call, role)?;
            Some(PendingManagementEffect::None)
        }
        ManagementRequest::UpgradeRuntime(upgrade) => {
            let row = lifecycle_owner(configuration, state, call, role)?;
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
        && state.credentials.len() <= MAX_AUTHORITY_CREDENTIALS
        && state.nodes.len() <= MAX_AUTHORITY_NODES
        && state.roles.len() <= MAX_AUTHORITY_PRINCIPALS
        && state.managed_agents.len() <= MAX_MANAGED_AGENTS
        && state.retries.len() <= MAX_EXACT_RETRY_RECORDS
        && sorted_unique_by(&state.credentials, |row| row.credential)
        && sorted_unique_by(&state.nodes, |row| row.node)
        && sorted_unique_by(&state.roles, |row| row.principal)
        && sorted_unique_by(&state.managed_agents, |row| row.agent)
        && sorted_unique_by(&state.retries, |row| row.invocation)
        && state.credentials.iter().all(|row| {
            row.credential != [0; 32]
                && row.principal != [0; 32]
                && row.public_key != [0; 32]
                && CredentialId::of_public_key(&row.public_key).0 == row.credential
        })
        && state
            .nodes
            .iter()
            .all(|row| row.node != [0; 32] && row.owner != [0; 32])
        && state.roles.iter().all(|row| row.principal != [0; 32])
        && state.managed_agents.iter().all(|row| {
            row.agent != [0; 32]
                && row.owner != [0; 32]
                && matches!(row.profile, 0..=2)
                && row.runtime_deployment != [0; 32]
                && row.runtime_program != [0; 32]
                && row.runtime_producer != [0; 32]
                && row.authority == configuration.binding
        })
        && state.retries.iter().all(|row| {
            row.invocation != [0; 32]
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
        && retry_identifiers_are_unique(&state.retries)
}

fn retry_finalization_shape_is_valid(record: &ExactRetryRecord) -> bool {
    match (
        record.finalized,
        record.acknowledgement_invocation,
        record.acknowledgement,
        record.acknowledgement_bytes.as_deref(),
        record.reopened_state,
        record.applied_at,
    ) {
        (false, None, None, None, None, None) => true,
        (
            true,
            Some(invocation),
            Some(acknowledgement),
            Some(acknowledgement_bytes),
            Some(reopened_state),
            Some(_),
        ) => {
            invocation != [0; 32]
                && acknowledgement != [0; 32]
                && !acknowledgement_bytes.is_empty()
                && acknowledgement_bytes.len() <= MAX_INVOCATION_MESSAGE_BYTES
                && reopened_state != [0; 32]
                && invocation != record.invocation
        }
        _ => false,
    }
}

fn retry_identifiers_are_unique(records: &[ExactRetryRecord]) -> bool {
    records.iter().enumerate().all(|(index, record)| {
        records.iter().enumerate().all(|(other_index, other)| {
            index == other_index
                || (record.authorization_sequence != other.authorization_sequence
                    && record.acknowledgement_invocation != Some(other.invocation)
                    && other.acknowledgement_invocation != Some(record.invocation)
                    && (record.acknowledgement_invocation.is_none()
                        || record.acknowledgement_invocation != other.acknowledgement_invocation))
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
        AuthorityOperationKind, AuthorityReceipt, AuthorityReceiptSelector,
        ManagementApplicationAck, ManagementApproval,
    };
    use vos::agent_sdk::contract::RuntimePackageContract;
    use vos::agent_sdk::{
        AgentDescriptor, AgentIdentity, AgentReplica, BlobRef, InvocationOrigin,
        InvocationRoleClaims, MethodMode, NodeId, ReplicaRole, RoleId, RuntimeCapabilities,
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
            bootstrap_principal: ADMIN_PRINCIPAL.0,
            bootstrap_credential_public_key: signing(0x21).verifying_key().to_bytes(),
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
        acknowledgement_invocation: InvocationId,
    ) -> ManagementApplicationAck {
        let mut ack = ManagementApplicationAck {
            authorization_invocation: call.invocation,
            acknowledgement_invocation,
            authority: call.authority,
            managed: call.managed,
            credential_call: call.commitment(),
            approval: approval.commitment(),
            authorization_sequence: approval.authorization_sequence,
            request: approval.request_commitment,
            receipt: receipt_for(config, approval, 1),
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
        let public_key = key.verifying_key().to_bytes();
        let credential = CredentialId::of_public_key(&public_key).0;
        let credential_index = actor
            .state
            .credentials
            .binary_search_by(|row| row.credential.cmp(&credential))
            .unwrap_err();
        actor.state.credentials.insert(
            credential_index,
            CredentialRow {
                credential,
                principal: principal.0,
                public_key,
                status: CredentialStatus::Active,
            },
        );
        let node_index = actor
            .state
            .nodes
            .binary_search_by(|row| row.node.cmp(&node.0))
            .unwrap_err();
        actor.state.nodes.insert(
            node_index,
            NodeOwnerRow {
                node: node.0,
                owner: principal.0,
            },
        );
        let role_index = actor
            .state
            .roles
            .binary_search_by(|row| row.principal.cmp(&principal.0))
            .unwrap_err();
        actor.state.roles.insert(
            role_index,
            PrincipalRoleRow {
                principal: principal.0,
                role,
            },
        );
    }

    fn insert_live(actor: &mut SystemAuthority, descriptor: &AgentDescriptor) {
        let row = ManagedAgentRow {
            agent: descriptor.identity.agent.0,
            owner: descriptor.identity.owner.0,
            profile: descriptor.identity.profile as u8,
            runtime_deployment: descriptor.identity.runtime_deployment.0,
            runtime_program: descriptor.identity.runtime_program.0,
            runtime_producer: descriptor.identity.runtime_producer.0,
            authority: actor.configuration.binding,
        };
        let index = actor
            .state
            .managed_agents
            .binary_search_by(|existing| existing.agent.cmp(&row.agent))
            .unwrap_err();
        actor.state.managed_agents.insert(index, row);
    }

    #[test]
    fn sac1_configuration_is_exact_and_clean_generation_bound() {
        let config = configuration();
        let encoded = config.encode();
        assert_eq!(encoded.len(), CONFIG_ENCODED_BYTES);
        assert_eq!(encoded.get(..4), Some(b"SAC1".as_slice()));
        assert_eq!(SystemAuthorityConfiguration::decode(&encoded), Some(config));

        let mut old_generation = encoded.clone();
        old_generation[4] ^= 1;
        assert_eq!(SystemAuthorityConfiguration::decode(&old_generation), None);
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert_eq!(SystemAuthorityConfiguration::decode(&trailing), None);
        assert_eq!(SystemAuthorityConfiguration::decode(&encoded[..459]), None);

        let inert = SystemAuthority::new(&old_generation);
        assert!(!inert.state.initialized);
        assert!(inert.state.credentials.is_empty());
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
                assert!(actor.state.managed_agents.is_empty());
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
        let request = ManagementRequest::Suspend {
            actor: ActorId([0x98; 32]),
            expected_deployment: DeploymentId([0x99; 32]),
        };

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

        let owner_call = credential_call(
            config,
            &owner_key,
            owner,
            Some(owner_node),
            0xa0,
            managed,
            request.clone(),
        );
        assert!(!dispatch(&mut actor, &owner_call).is_empty());

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

        let admin_call = credential_call(
            config,
            &signing(0x21),
            ADMIN_PRINCIPAL,
            Some(ADMIN_NODE),
            0xa2,
            managed,
            request.clone(),
        );
        assert!(!dispatch(&mut actor, &admin_call).is_empty());

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
        actor.state.retries.clear();
        for ordinal in 1..=MAX_EXACT_RETRY_RECORDS {
            let byte = ordinal as u8;
            actor.state.retries.push(ExactRetryRecord {
                invocation: [byte; 32],
                credential_call: [byte; 32],
                credential_call_bytes: b"bounded retained call".to_vec(),
                approval_commitment: [byte.wrapping_add(1); 32],
                authorization_sequence: ordinal as u64,
                approval: b"bounded retained approval".to_vec(),
                effect: PendingManagementEffect::None,
                finalized: false,
                acknowledgement_invocation: None,
                acknowledgement: None,
                acknowledgement_bytes: None,
                reopened_state: None,
                applied_at: None,
            });
        }
        actor.state.authorization_sequence = MAX_EXACT_RETRY_RECORDS as u64;
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
        assert!(actor.state.managed_agents.is_empty());

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
        assert!(restarted.state.managed_agents.is_empty());
        assert_eq!(dispatch(&mut restarted, &call), approval);
        assert!(restarted.state.managed_agents.is_empty());
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
        assert!(actor.state.managed_agents.is_empty());

        let ack = application_ack(config, &call, &approval, InvocationId([0xe5; 32]));
        let ack_bytes = ack.encode().unwrap();
        assert_eq!(ack_bytes.get(..4), Some(b"MAA1".as_slice()));
        assert!(dispatch_ack(&mut actor, &ack));
        let live = &actor.state.managed_agents[0];
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
        let valid = application_ack(config, &call, &approval, InvocationId([0x69; 32]));

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
            assert!(actor.state.managed_agents.is_empty());
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
        let ack = application_ack(config, &call, &approval, InvocationId([0x6f; 32]));
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
    fn generated_agent_schema_marks_authorize_as_explicit_linear_public_preflight() {
        let method = SystemAuthorityMsg::AGENT_METHODS;
        assert_eq!(method.len(), 2);
        assert_eq!(method[0].name, "authorize");
        assert_eq!(method[0].mode, vos::agent_sdk::schema::MethodMode::Linear);
        assert!(method[0].explicit);
        assert_eq!(method[1].name, "finalize");
        assert_eq!(method[1].mode, vos::agent_sdk::schema::MethodMode::Linear);
        assert!(method[1].explicit);
        assert_eq!(SystemAuthorityMsg::AGENT_AUTHORIZATIONS.len(), 2);
    }
}
