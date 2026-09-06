//! A small, real custom AgentRuntime with deterministic Linear semantics.
//!
//! The example deliberately implements the portable SDK contract directly:
//! it authenticates Create/Install management, retains a canonical actor
//! directory, admits one public Linear counter actor, retains one exact result
//! until acknowledgement, and derives every output solely from `RuntimeWork`.
//! It does not load keys, read clocks, or rely on process-local state.

#![no_std]

extern crate alloc;

use alloc::boxed::Box;
use alloc::vec::Vec;

use ed25519_dalek::{Signature, VerifyingKey};
use vos_agent_sdk::authority::{AuthorityReceipt, AuthorityVerifier};
use vos_agent_sdk::protocol::wire::{DecodeError, Decoder, Encoder};
use vos_agent_sdk::wire::CanonicalWire as _;
use vos_agent_sdk::{
    ActorDirectoryPage, ActorDirectoryRecord, ActorId, AgentDescriptor, AgentProfile, AgentRuntime,
    Hash, InstallActor, InvocationAcknowledgement, InvocationAuthorization, InvocationError,
    InvocationReply, InvocationStatus, InvocationWork, LaneSet, ManagementError, ManagementReply,
    ManagementRequest, MethodMode, ProofSystemSet, RuntimeCapabilities, RuntimeOutcome,
    RuntimeResourceUsage, RuntimeState, RuntimeTransition, RuntimeWork, StateLane,
};

const CONTROL_MAGIC: [u8; 8] = *b"VCLCTL01";
const LINEAR_MAGIC: [u8; 8] = *b"VCLLIN01";
const MAX_STORED_WORK_BYTES: usize = vos_agent_sdk::MAX_RUNTIME_STATE_BYTES / 2;
const EXECUTION_GAS: u64 = 1;

/// This example intentionally supports one installed Linear actor and no
/// scheduling or proof backend.
pub const CUSTOM_LINEAR_CAPABILITIES: RuntimeCapabilities = RuntimeCapabilities {
    lanes: LaneSet::of(StateLane::Linear),
    scheduling: false,
    proof_systems: ProofSystemSet::EMPTY,
    max_actors: 1,
};

/// Process-stateless runtime implementation. Durable state always arrives in
/// the selected `RuntimeWork` and is returned in the transition.
#[derive(Default)]
pub struct CustomLinearRuntime;

impl AgentRuntime for CustomLinearRuntime {
    fn capabilities(&self) -> RuntimeCapabilities {
        CUSTOM_LINEAR_CAPABILITIES
    }

    fn apply(&mut self, work: RuntimeWork) -> RuntimeTransition {
        match work {
            RuntimeWork::Manage {
                space,
                agent,
                runtime_deployment,
                state,
                request,
                authority,
                observed_slot,
            } => apply_management(
                space,
                agent,
                runtime_deployment,
                state,
                *request,
                authority.map(|value| *value),
                observed_slot,
            ),
            RuntimeWork::Invoke {
                state,
                invocation,
                authorization,
                observed_slot,
            } => apply_invoke(state, *invocation, *authorization, observed_slot),
            RuntimeWork::Resume { state, .. } => transition(
                state,
                RuntimeOutcome::Completed(Err(InvocationError::NotReady)),
            ),
            RuntimeWork::Acknowledge {
                state,
                invocation,
                authorization,
            } => apply_acknowledge(state, *invocation, *authorization),
        }
    }
}

vos_agent_runtime_guest::export_agent_runtime!(crate::CustomLinearRuntime);

/// Incarnation selected by this runtime for its one installed actor.
pub fn actor_incarnation(install: &InstallActor) -> Hash {
    Hash::digest(
        b"vos/example/custom-linear/incarnation/v1",
        &[
            install.installation_id.as_bytes(),
            install.entry.actor.as_bytes(),
            install.entry.deployment.as_bytes(),
            install.state_layout.as_bytes(),
        ],
    )
}

struct Ed25519Verifier;

impl AuthorityVerifier for Ed25519Verifier {
    fn verify(&self, public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
        let Ok(key) = VerifyingKey::from_bytes(public_key) else {
            return false;
        };
        !key.is_weak()
            && key
                .verify_strict(message, &Signature::from_bytes(signature))
                .is_ok()
    }
}

#[derive(Clone)]
struct ControlState {
    decision_sequence: u64,
    create_work: Vec<u8>,
    install_work: Option<Vec<u8>>,
}

#[derive(Clone)]
struct LinearState {
    value: u64,
    revision: u64,
    retained_work: Option<Vec<u8>>,
}

#[derive(Clone)]
struct CustomState {
    control: ControlState,
    linear: LinearState,
}

impl CustomState {
    fn decode(state: &RuntimeState) -> Result<Self, DecodeError> {
        if !state.merge.is_empty() || !state.local.is_empty() {
            return Err(DecodeError::NonCanonical);
        }
        let mut control = Decoder::new(&state.control);
        if control.take(CONTROL_MAGIC.len())? != CONTROL_MAGIC {
            return Err(DecodeError::InvalidTag);
        }
        let decision_sequence = control.u64()?;
        let create_work = control.bytes_bounded(MAX_STORED_WORK_BYTES)?;
        let install_work =
            control.option(|decoder| decoder.bytes_bounded(MAX_STORED_WORK_BYTES))?;
        if !control.exhausted() || decision_sequence == 0 {
            return Err(DecodeError::NonCanonical);
        }
        validate_stored_create(&create_work)?;
        if let Some(work) = &install_work {
            validate_stored_install(work)?;
        }
        if decision_sequence != if install_work.is_some() { 2 } else { 1 } {
            return Err(DecodeError::NonCanonical);
        }

        let mut linear = Decoder::new(&state.linear);
        if linear.take(LINEAR_MAGIC.len())? != LINEAR_MAGIC {
            return Err(DecodeError::InvalidTag);
        }
        let value = linear.u64()?;
        let revision = linear.u64()?;
        let retained_work =
            linear.option(|decoder| decoder.bytes_bounded(MAX_STORED_WORK_BYTES))?;
        if !linear.exhausted() || revision == 0 && retained_work.is_some() {
            return Err(DecodeError::NonCanonical);
        }
        if let Some(work) = &retained_work {
            validate_stored_invoke(work)?;
        }
        let decoded = Self {
            control: ControlState {
                decision_sequence,
                create_work,
                install_work,
            },
            linear: LinearState {
                value,
                revision,
                retained_work,
            },
        };
        if decoded.encode().as_ref() != Some(state) {
            return Err(DecodeError::NonCanonical);
        }
        Ok(decoded)
    }

    fn encode(&self) -> Option<RuntimeState> {
        let mut control = Vec::new();
        control.extend_from_slice(&CONTROL_MAGIC);
        let mut encoder = Encoder(&mut control);
        encoder.u64(self.control.decision_sequence);
        encoder.bytes(&self.control.create_work);
        encoder.option(&self.control.install_work, |encoder, work| {
            encoder.bytes(work)
        });

        let mut linear = Vec::new();
        linear.extend_from_slice(&LINEAR_MAGIC);
        let mut encoder = Encoder(&mut linear);
        encoder.u64(self.linear.value);
        encoder.u64(self.linear.revision);
        encoder.option(&self.linear.retained_work, |encoder, work| {
            encoder.bytes(work)
        });

        let state = RuntimeState {
            control,
            linear,
            merge: Vec::new(),
            local: Vec::new(),
        };
        state.validate().then_some(state)
    }

    fn descriptor(&self) -> Option<AgentDescriptor> {
        let RuntimeWork::Manage { request, .. } =
            RuntimeWork::decode(&self.control.create_work).ok()?
        else {
            return None;
        };
        let ManagementRequest::Create(descriptor) = *request else {
            return None;
        };
        Some(*descriptor)
    }

    fn install(&self) -> Option<InstallActor> {
        let bytes = self.control.install_work.as_ref()?;
        let RuntimeWork::Manage { request, .. } = RuntimeWork::decode(bytes).ok()? else {
            return None;
        };
        let ManagementRequest::Install(install) = *request else {
            return None;
        };
        Some(*install)
    }
}

fn apply_management(
    space: vos_agent_sdk::SpaceId,
    agent: vos_agent_sdk::AgentId,
    runtime_deployment: vos_agent_sdk::DeploymentId,
    state: RuntimeState,
    request: ManagementRequest,
    authority: Option<AuthorityReceipt>,
    observed_slot: u64,
) -> RuntimeTransition {
    let prior = state.clone();
    if !request.is_valid() {
        return management_error(prior, ManagementError::InvalidRequest);
    }

    if let ManagementRequest::Create(descriptor) = &request {
        if state != RuntimeState::default() {
            if let Ok(existing) = CustomState::decode(&state)
                && existing.descriptor().as_ref() == Some(descriptor.as_ref())
                && stored_management_matches(
                    &existing.control.create_work,
                    space,
                    agent,
                    runtime_deployment,
                    &request,
                    authority.as_ref(),
                )
            {
                return transition(
                    state,
                    RuntimeOutcome::Management(Ok(ManagementReply::Created(
                        descriptor.identity.clone(),
                    ))),
                );
            }
            return management_error(prior, ManagementError::AlreadyCreated);
        }
        if !valid_create_target(descriptor, space, agent, runtime_deployment)
            || !verify_management_receipt(
                descriptor,
                &request,
                authority.as_ref(),
                observed_slot,
                1,
            )
        {
            return management_error(prior, ManagementError::InvalidRequest);
        }
        let created_identity = descriptor.identity.clone();
        let Some(create_work) = stored_management_work(
            space,
            agent,
            runtime_deployment,
            request,
            authority,
            observed_slot,
        ) else {
            return management_error(prior, ManagementError::ResourceLimit);
        };
        let model = CustomState {
            control: ControlState {
                decision_sequence: 1,
                create_work,
                install_work: None,
            },
            linear: LinearState {
                value: 0,
                revision: 0,
                retained_work: None,
            },
        };
        let Some(state) = model.encode() else {
            return management_error(prior, ManagementError::ResourceLimit);
        };
        return transition(
            state,
            RuntimeOutcome::Management(Ok(ManagementReply::Created(created_identity))),
        );
    }

    let Ok(mut model) = CustomState::decode(&state) else {
        return management_error(prior, ManagementError::NotCreated);
    };
    let Some(descriptor) = model.descriptor() else {
        return management_error(prior, ManagementError::InvalidRequest);
    };
    if descriptor.identity.space != space
        || descriptor.identity.agent != agent
        || descriptor.identity.runtime_deployment != runtime_deployment
    {
        return management_error(prior, ManagementError::InvalidRequest);
    }

    match request {
        ManagementRequest::InspectActors { after, limit } => {
            let mut entries = Vec::new();
            if let Some(install) = model.install()
                && after.is_none_or(|cursor| install.entry.actor > cursor)
                && limit != 0
            {
                entries.push(ActorDirectoryRecord {
                    entry: install.entry.clone(),
                    incarnation: actor_incarnation(&install),
                    installation_id: install.installation_id,
                    registry_reservation: install.registry_reservation,
                });
            }
            transition(
                state,
                RuntimeOutcome::Management(Ok(ManagementReply::Actors(ActorDirectoryPage {
                    entries,
                    next: None,
                }))),
            )
        }
        ManagementRequest::InspectResources => transition(
            state.clone(),
            RuntimeOutcome::Management(Ok(ManagementReply::Resources(RuntimeResourceUsage {
                actors: u32::from(model.control.install_work.is_some()),
                proof_artifacts: 0,
                schedules: 0,
                state_bytes: state_bytes(&state),
                ..RuntimeResourceUsage::default()
            }))),
        ),
        ManagementRequest::Install(install) => {
            if let Some(existing) = model.install() {
                if existing == *install
                    && model.control.install_work.as_ref().is_some_and(|stored| {
                        stored_management_matches(
                            stored,
                            space,
                            agent,
                            runtime_deployment,
                            &ManagementRequest::Install(install.clone()),
                            authority.as_ref(),
                        )
                    })
                {
                    return transition(
                        state,
                        RuntimeOutcome::Management(Ok(ManagementReply::Installed(
                            install.entry.clone(),
                        ))),
                    );
                }
                return management_error(prior, ManagementError::AlreadyExists);
            }
            let request = ManagementRequest::Install(install.clone());
            if install.entry.parent.is_some()
                || install.entry.suspended
                || install.entry.actor != ActorId::top_level(agent, &install.entry.name)
                || install
                    .validate_for_profile(descriptor.identity.profile)
                    .is_err()
                || !CUSTOM_LINEAR_CAPABILITIES.satisfies(install.requirements)
                || !descriptor.runtime_contract.supports(install.contract)
                || !verify_management_receipt(
                    &descriptor,
                    &request,
                    authority.as_ref(),
                    observed_slot,
                    model.control.decision_sequence.saturating_add(1),
                )
            {
                return management_error(prior, ManagementError::InvalidRequest);
            }
            let Some(stored) = stored_management_work(
                space,
                agent,
                runtime_deployment,
                request,
                authority,
                observed_slot,
            ) else {
                return management_error(prior, ManagementError::ResourceLimit);
            };
            model.control.decision_sequence += 1;
            model.control.install_work = Some(stored);
            let Some(state) = model.encode() else {
                return management_error(prior, ManagementError::ResourceLimit);
            };
            transition(
                state,
                RuntimeOutcome::Management(Ok(ManagementReply::Installed(install.entry.clone()))),
            )
        }
        _ => management_error(prior, ManagementError::UnsupportedRuntime),
    }
}

fn apply_invoke(
    state: RuntimeState,
    work: InvocationWork,
    authorization: InvocationAuthorization,
    observed_slot: u64,
) -> RuntimeTransition {
    let prior = state.clone();
    let Ok(mut model) = CustomState::decode(&state) else {
        return invocation_error(prior, InvocationError::NotCreated);
    };
    let Some(descriptor) = model.descriptor() else {
        return invocation_error(prior, InvocationError::NotCreated);
    };
    let Some(install) = model.install() else {
        return invocation_error(prior, InvocationError::NotFound);
    };

    if let Some(stored) = &model.linear.retained_work {
        if stored_invoke_matches(stored, &work, &authorization) {
            return completed_counter(state, &work, model.linear.value, model.linear.revision);
        }
        return invocation_error(prior, InvocationError::ResultCapacity);
    }
    if work.recovery_only {
        return invocation_error(prior, InvocationError::NotFound);
    }
    if !valid_invoke_target(&descriptor, &install, &work)
        || !public_authorization_matches(&work, &authorization, observed_slot)
    {
        return invocation_error(prior, InvocationError::InvalidAuthorization);
    }
    let Some(delta) = decode_delta(&work.message) else {
        return invocation_error(prior, InvocationError::InvalidInput);
    };
    let Some(value) = model.linear.value.checked_add(delta) else {
        return invocation_error(prior, InvocationError::InvalidInput);
    };
    let Some(revision) = model.linear.revision.checked_add(1) else {
        return invocation_error(prior, InvocationError::ResultCapacity);
    };
    let Some(stored_work) = stored_invoke_work(&work, &authorization, observed_slot) else {
        return invocation_error(prior, InvocationError::ResultCapacity);
    };
    model.linear.value = value;
    model.linear.revision = revision;
    model.linear.retained_work = Some(stored_work);
    let Some(state) = model.encode() else {
        return invocation_error(prior, InvocationError::ResultCapacity);
    };
    completed_counter(state, &work, value, revision)
}

fn apply_acknowledge(
    state: RuntimeState,
    work: InvocationWork,
    authorization: InvocationAuthorization,
) -> RuntimeTransition {
    let prior = state.clone();
    let Ok(mut model) = CustomState::decode(&state) else {
        return acknowledged_error(prior, InvocationError::NotCreated);
    };
    let Some(stored) = &model.linear.retained_work else {
        return acknowledged_error(prior, InvocationError::NotFound);
    };
    if !authorization.matches_acknowledgement(&work)
        || !stored_invoke_matches(stored, &work, &authorization)
    {
        return acknowledged_error(prior, InvocationError::DivergentInvocation);
    }
    model.linear.retained_work = None;
    let Some(state) = model.encode() else {
        return acknowledged_error(prior, InvocationError::ResultCapacity);
    };
    transition(
        state,
        RuntimeOutcome::Acknowledged(Ok(InvocationAcknowledgement {
            invocation: work.invocation,
            actor: work.actor,
            incarnation: work.incarnation,
            deployment: work.deployment,
            mode: work.mode,
            work: work.commitment(),
            authorization: authorization.commitment(),
        })),
    )
}

fn valid_create_target(
    descriptor: &AgentDescriptor,
    space: vos_agent_sdk::SpaceId,
    agent: vos_agent_sdk::AgentId,
    runtime_deployment: vos_agent_sdk::DeploymentId,
) -> bool {
    descriptor.validate().is_ok()
        && descriptor.identity.space == space
        && descriptor.identity.agent == agent
        && descriptor.identity.runtime_deployment == runtime_deployment
        && descriptor.capabilities == CUSTOM_LINEAR_CAPABILITIES
        && matches!(
            descriptor.identity.profile,
            AgentProfile::Local | AgentProfile::Shared
        )
}

fn verify_management_receipt(
    descriptor: &AgentDescriptor,
    request: &ManagementRequest,
    receipt: Option<&AuthorityReceipt>,
    observed_slot: u64,
    expected_sequence: u64,
) -> bool {
    let Some(receipt) = receipt else {
        return false;
    };
    descriptor.authority.accepts(receipt)
        && receipt.verify_at(observed_slot, &Ed25519Verifier).is_ok()
        && receipt.selector.space == descriptor.identity.space
        && receipt.selector.agent == descriptor.identity.agent
        && receipt.selector.runtime_deployment == descriptor.identity.runtime_deployment
        && Some(receipt.selector.operation) == request.authority_operation()
        && receipt.selector.request == request.commitment()
        && receipt.selector.decision_sequence == expected_sequence
        && receipt.selector.acknowledged_through < expected_sequence
        && match (
            request.authority_actor(),
            receipt.selector.actor,
            receipt.selector.actor_deployment,
        ) {
            (Some(expected), Some(actor), Some(deployment)) => expected == (actor, deployment),
            (None, None, None) => true,
            _ => false,
        }
}

fn valid_invoke_target(
    descriptor: &AgentDescriptor,
    install: &InstallActor,
    work: &InvocationWork,
) -> bool {
    work.validate()
        && work.space == descriptor.identity.space
        && work.agent == descriptor.identity.agent
        && work.runtime_deployment == descriptor.identity.runtime_deployment
        && work.actor == install.entry.actor
        && work.incarnation == actor_incarnation(install)
        && work.deployment == install.entry.deployment
        && work.program == install.entry.program
        && work.mode == MethodMode::Linear
        && !install.entry.suspended
        && work.installation_data == install.entry.installation_data
        && work.availability.is_empty()
        && work.origin == vos_agent_sdk::InvocationOrigin::anonymous()
        && work.roles == vos_agent_sdk::InvocationRoleClaims::none()
}

fn public_authorization_matches(
    work: &InvocationWork,
    authorization: &InvocationAuthorization,
    observed_slot: u64,
) -> bool {
    match authorization {
        InvocationAuthorization::PublicPreflight(preflight) => {
            preflight.matches(work, observed_slot)
        }
        InvocationAuthorization::AuthorityReceipt(_) => false,
    }
}

fn decode_delta(message: &[u8]) -> Option<u64> {
    let delta = u64::from_le_bytes(message.try_into().ok()?);
    (delta != 0).then_some(delta)
}

fn completed_counter(
    state: RuntimeState,
    work: &InvocationWork,
    value: u64,
    revision: u64,
) -> RuntimeTransition {
    transition(
        state,
        RuntimeOutcome::Completed(Ok(InvocationReply {
            invocation: work.invocation,
            actor: work.actor,
            incarnation: work.incarnation,
            deployment: work.deployment,
            mode: work.mode,
            lane: Some(StateLane::Linear),
            status: InvocationStatus::Done,
            reply: value.to_le_bytes().to_vec(),
            gas_remaining: work.gas.saturating_sub(EXECUTION_GAS),
            observation: vos_agent_sdk::InvocationObservation {
                linear_revision: Some(revision),
                ..vos_agent_sdk::InvocationObservation::default()
            },
        })),
    )
}

fn transition(state: RuntimeState, outcome: RuntimeOutcome) -> RuntimeTransition {
    RuntimeTransition { state, outcome }
}

fn management_error(state: RuntimeState, error: ManagementError) -> RuntimeTransition {
    transition(state, RuntimeOutcome::Management(Err(error)))
}

fn invocation_error(state: RuntimeState, error: InvocationError) -> RuntimeTransition {
    transition(state, RuntimeOutcome::Completed(Err(error)))
}

fn acknowledged_error(state: RuntimeState, error: InvocationError) -> RuntimeTransition {
    transition(state, RuntimeOutcome::Acknowledged(Err(error)))
}

fn state_bytes(state: &RuntimeState) -> u32 {
    state
        .control
        .len()
        .saturating_add(state.linear.len())
        .saturating_add(state.merge.len())
        .saturating_add(state.local.len())
        .try_into()
        .unwrap_or(u32::MAX)
}

fn stored_management_work(
    space: vos_agent_sdk::SpaceId,
    agent: vos_agent_sdk::AgentId,
    runtime_deployment: vos_agent_sdk::DeploymentId,
    request: ManagementRequest,
    authority: Option<AuthorityReceipt>,
    observed_slot: u64,
) -> Option<Vec<u8>> {
    let work = RuntimeWork::Manage {
        space,
        agent,
        runtime_deployment,
        state: RuntimeState::default(),
        request: Box::new(request),
        authority: authority.map(Box::new),
        observed_slot,
    };
    let bytes = work.encode().ok()?;
    (bytes.len() <= MAX_STORED_WORK_BYTES).then_some(bytes)
}

fn stored_invoke_work(
    invocation: &InvocationWork,
    authorization: &InvocationAuthorization,
    observed_slot: u64,
) -> Option<Vec<u8>> {
    let work = RuntimeWork::Invoke {
        state: RuntimeState::default(),
        invocation: Box::new(invocation.clone()),
        authorization: Box::new(authorization.clone()),
        observed_slot,
    };
    let bytes = work.encode().ok()?;
    (bytes.len() <= MAX_STORED_WORK_BYTES).then_some(bytes)
}

fn stored_management_matches(
    bytes: &[u8],
    space: vos_agent_sdk::SpaceId,
    agent: vos_agent_sdk::AgentId,
    runtime_deployment: vos_agent_sdk::DeploymentId,
    request: &ManagementRequest,
    authority: Option<&AuthorityReceipt>,
) -> bool {
    matches!(
        RuntimeWork::decode(bytes),
        Ok(RuntimeWork::Manage {
            space: stored_space,
            agent: stored_agent,
            runtime_deployment: stored_runtime,
            state,
            request: stored_request,
            authority: stored_authority,
            ..
        }) if state == RuntimeState::default()
            && stored_space == space
            && stored_agent == agent
            && stored_runtime == runtime_deployment
            && stored_request.as_ref() == request
            && stored_authority.as_deref() == authority
    )
}

fn stored_invoke_matches(
    bytes: &[u8],
    work: &InvocationWork,
    authorization: &InvocationAuthorization,
) -> bool {
    matches!(
        RuntimeWork::decode(bytes),
        Ok(RuntimeWork::Invoke {
            state,
            invocation,
            authorization: stored_authorization,
            ..
        }) if state == RuntimeState::default()
            && invocation.as_ref() == work
            && stored_authorization.as_ref() == authorization
    )
}

fn validate_stored_create(bytes: &[u8]) -> Result<(), DecodeError> {
    match RuntimeWork::decode(bytes).map_err(|_| DecodeError::NonCanonical)? {
        RuntimeWork::Manage {
            state,
            request,
            authority: Some(_),
            ..
        } if state == RuntimeState::default()
            && matches!(request.as_ref(), ManagementRequest::Create(_)) =>
        {
            Ok(())
        }
        _ => Err(DecodeError::NonCanonical),
    }
}

fn validate_stored_install(bytes: &[u8]) -> Result<(), DecodeError> {
    match RuntimeWork::decode(bytes).map_err(|_| DecodeError::NonCanonical)? {
        RuntimeWork::Manage {
            state,
            request,
            authority: Some(_),
            ..
        } if state == RuntimeState::default()
            && matches!(request.as_ref(), ManagementRequest::Install(_)) =>
        {
            Ok(())
        }
        _ => Err(DecodeError::NonCanonical),
    }
}

fn validate_stored_invoke(bytes: &[u8]) -> Result<(), DecodeError> {
    match RuntimeWork::decode(bytes).map_err(|_| DecodeError::NonCanonical)? {
        RuntimeWork::Invoke { state, .. } if state == RuntimeState::default() => Ok(()),
        _ => Err(DecodeError::NonCanonical),
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use alloc::boxed::Box;
    use alloc::string::ToString;
    use alloc::vec;
    use alloc::vec::Vec;

    use ed25519_dalek::{Signer as _, SigningKey};
    use vos_agent_sdk::authority::{
        AgentAuthorityBinding, AuthorityEvidence, AuthorityIssuer, AuthorityLaneRoots,
        AuthorityReceiptSelector,
    };
    use vos_agent_sdk::contract::{ActorPackageContract, RuntimePackageContract};
    use vos_agent_sdk::package::{
        AgentRuntimePackageManifest, PackageArtifact, PackageEnvelope, PackageManifest,
        PackageSigning,
    };
    use vos_agent_sdk::wire::CanonicalWire as _;
    use vos_agent_sdk::{
        ActorEntry, AgentId, AgentIdentity, AgentProfile, AgentReplica, BlobRef, DeploymentId,
        InstallationId, InvocationId, InvocationOrigin, InvocationRoleClaims, NodeId, PrincipalId,
        ProducerId, ProgramId, PublicPreflight, ReplicaRole, RuntimeRequirements, SpaceId,
    };
    use vos_pvm_compiler::assembler::{Assembler, Reg};

    use super::*;

    const AUTHORITY_SEED: [u8; 32] = [0x41; 32];

    struct Fixture {
        key: SigningKey,
        descriptor: AgentDescriptor,
    }

    impl Fixture {
        fn new() -> Self {
            let key = SigningKey::from_bytes(&AUTHORITY_SEED);
            let public_key = key.verifying_key().to_bytes();
            let space = SpaceId([0x11; 32]);
            let owner = PrincipalId([0x12; 32]);
            let creation_nonce = Hash([0x13; 32]);
            let agent = AgentId::derive(space, owner, creation_nonce.as_bytes());
            let issuer = AuthorityIssuer {
                principal: owner,
                actor: ActorId([0x14; 32]),
                deployment: DeploymentId([0x15; 32]),
                program: ProgramId([0x16; 32]),
                producer: ProducerId::of_public_key(&public_key),
            };
            let descriptor = AgentDescriptor {
                identity: AgentIdentity {
                    space,
                    agent,
                    owner,
                    profile: AgentProfile::Local,
                    runtime_deployment: DeploymentId([0x17; 32]),
                    runtime_program: ProgramId([0x18; 32]),
                    runtime_producer: ProducerId([0x19; 32]),
                },
                creation_nonce,
                authority: AgentAuthorityBinding {
                    policy: Hash([0x1a; 32]),
                    issuer,
                    public_key,
                    initial_epoch: 1,
                },
                runtime_package: blob(0x1b, 64),
                runtime_contract: RuntimePackageContract::canonical(),
                capabilities: CUSTOM_LINEAR_CAPABILITIES,
                replicas: vec![AgentReplica {
                    node: NodeId([0x1c; 32]),
                    principal: owner,
                    role: ReplicaRole::Voter,
                }],
            };
            descriptor.validate().unwrap();
            Self { key, descriptor }
        }

        fn receipt(
            &self,
            request: &ManagementRequest,
            sequence: u64,
            expires_at: u64,
        ) -> AuthorityReceipt {
            let (actor, actor_deployment) = request
                .authority_actor()
                .map_or((None, None), |(actor, deployment)| {
                    (Some(actor), Some(deployment))
                });
            let mut receipt = AuthorityReceipt {
                selector: AuthorityReceiptSelector {
                    policy: self.descriptor.authority.policy,
                    issuer: self.descriptor.authority.issuer,
                    space: self.descriptor.identity.space,
                    agent: self.descriptor.identity.agent,
                    operation: request.authority_operation().unwrap(),
                    runtime_deployment: self.descriptor.identity.runtime_deployment,
                    actor,
                    actor_deployment,
                    evidence: AuthorityEvidence {
                        package: None,
                        proof: None,
                        commitment: Hash([0x1d; 32]),
                    },
                    lane_roots: AuthorityLaneRoots::default(),
                    epoch: 1,
                    decision_sequence: sequence,
                    acknowledged_through: sequence.saturating_sub(1),
                    valid_from: 1,
                    expires_at,
                    request: request.commitment(),
                },
                public_key: self.descriptor.authority.public_key,
                signature: [0; 64],
            };
            receipt.signature = self.key.sign(&receipt.signing_bytes()).to_bytes();
            receipt
        }

        fn create(&self, state: RuntimeState, observed_slot: u64) -> RuntimeWork {
            let request = ManagementRequest::Create(Box::new(self.descriptor.clone()));
            RuntimeWork::Manage {
                space: self.descriptor.identity.space,
                agent: self.descriptor.identity.agent,
                runtime_deployment: self.descriptor.identity.runtime_deployment,
                state,
                authority: Some(Box::new(self.receipt(&request, 1, 10))),
                request: Box::new(request),
                observed_slot,
            }
        }

        fn install(&self) -> InstallActor {
            let package = blob(0x21, 64);
            let schema = blob(0x22, 64);
            let policy = blob(0x23, 64);
            let constructor_abi = Hash([0x24; 32]);
            let state_layout = Hash([0x25; 32]);
            let entry = ActorEntry {
                actor: ActorId::top_level(self.descriptor.identity.agent, "counter"),
                name: "counter".to_string(),
                parent: None,
                deployment: DeploymentId([0x26; 32]),
                program: ProgramId([0x27; 32]),
                package: package.clone(),
                agent_schema: schema.clone(),
                method_policy: policy.clone(),
                constructor_abi,
                installation_data: None,
                state_layout,
                lanes: LaneSet::of(StateLane::Linear),
                suspended: false,
            };
            InstallActor {
                installation_id: InstallationId([0x28; 32]),
                registry_reservation: Hash([0x29; 32]),
                entry,
                producer: ProducerId([0x2a; 32]),
                package,
                agent_schema: schema,
                method_policy: policy,
                constructor_abi,
                installation_data: None,
                state_layout,
                contract: ActorPackageContract::canonical(),
                requirements: RuntimeRequirements {
                    lanes: LaneSet::of(StateLane::Linear),
                    scheduling: false,
                    proof_systems: ProofSystemSet::EMPTY,
                },
            }
        }

        fn install_work(&self, state: RuntimeState, install: InstallActor) -> RuntimeWork {
            let request = ManagementRequest::Install(Box::new(install));
            RuntimeWork::Manage {
                space: self.descriptor.identity.space,
                agent: self.descriptor.identity.agent,
                runtime_deployment: self.descriptor.identity.runtime_deployment,
                state,
                authority: Some(Box::new(self.receipt(&request, 2, 20))),
                request: Box::new(request),
                observed_slot: 5,
            }
        }

        fn invocation(
            &self,
            install: &InstallActor,
            discriminator: u8,
            delta: u64,
        ) -> InvocationWork {
            InvocationWork {
                space: self.descriptor.identity.space,
                agent: self.descriptor.identity.agent,
                runtime_deployment: self.descriptor.identity.runtime_deployment,
                invocation: InvocationId([discriminator; 32]),
                actor: install.entry.actor,
                incarnation: actor_incarnation(install),
                deployment: install.entry.deployment,
                program: install.entry.program,
                mode: MethodMode::Linear,
                origin: InvocationOrigin::anonymous(),
                roles: InvocationRoleClaims::none(),
                message: delta.to_le_bytes().to_vec(),
                installation_data: None,
                availability: Vec::new(),
                gas: 10,
                recovery_only: false,
            }
        }
    }

    fn blob(byte: u8, len: usize) -> BlobRef {
        BlobRef::of_bytes(&vec![byte; len])
    }

    fn dispatch(work: RuntimeWork) -> RuntimeTransition {
        let input = work.encode().unwrap();
        let mut runtime = CustomLinearRuntime;
        let output = vos_agent_runtime_guest::dispatch(&mut runtime, &input).unwrap();
        let transition = RuntimeTransition::decode(&output).unwrap();
        assert_eq!(transition.encode().unwrap(), output);
        transition
    }

    fn created_and_installed(fixture: &Fixture) -> (InstallActor, RuntimeState) {
        let created = dispatch(fixture.create(RuntimeState::default(), 5));
        assert_eq!(
            created.outcome,
            RuntimeOutcome::Management(Ok(ManagementReply::Created(
                fixture.descriptor.identity.clone()
            )))
        );
        let install = fixture.install();
        let installed = dispatch(fixture.install_work(created.state, install.clone()));
        assert_eq!(
            installed.outcome,
            RuntimeOutcome::Management(Ok(ManagementReply::Installed(install.entry.clone())))
        );
        (install, installed.state)
    }

    fn completed_value(transition: &RuntimeTransition) -> u64 {
        let RuntimeOutcome::Completed(Ok(reply)) = &transition.outcome else {
            panic!("expected completed counter reply")
        };
        u64::from_le_bytes(reply.reply.as_slice().try_into().unwrap())
    }

    #[test]
    fn create_install_inspect_and_expired_exact_create_retry_are_deterministic() {
        let fixture = Fixture::new();
        let created = dispatch(fixture.create(RuntimeState::default(), 5));
        let retry = dispatch(fixture.create(created.state.clone(), 99));
        assert_eq!(retry.state, created.state);
        assert_eq!(retry.outcome, created.outcome);

        let install = fixture.install();
        let installed = dispatch(fixture.install_work(created.state, install.clone()));
        let inspected = dispatch(RuntimeWork::Manage {
            space: fixture.descriptor.identity.space,
            agent: fixture.descriptor.identity.agent,
            runtime_deployment: fixture.descriptor.identity.runtime_deployment,
            state: installed.state.clone(),
            request: Box::new(ManagementRequest::InspectActors {
                after: None,
                limit: 1,
            }),
            authority: None,
            observed_slot: 100,
        });
        let RuntimeOutcome::Management(Ok(ManagementReply::Actors(page))) = inspected.outcome
        else {
            panic!("expected actor page")
        };
        assert_eq!(page.entries.len(), 1);
        assert_eq!(page.entries[0].entry, install.entry);
        assert_eq!(page.entries[0].incarnation, actor_incarnation(&install));
        assert_eq!(inspected.state, installed.state);
    }

    #[test]
    fn custom_linear_result_survives_restart_retry_and_requires_acknowledgement() {
        let fixture = Fixture::new();
        let (install, initial) = created_and_installed(&fixture);
        let work = fixture.invocation(&install, 0x31, 5);
        let authorization =
            InvocationAuthorization::PublicPreflight(PublicPreflight::for_work(&work, 7));
        let applied = dispatch(RuntimeWork::Invoke {
            state: initial,
            invocation: Box::new(work.clone()),
            authorization: Box::new(authorization.clone()),
            observed_slot: 7,
        });
        assert_eq!(completed_value(&applied), 5);

        // `dispatch` constructs no process state. Supplying the returned
        // state to another invocation therefore models a fresh guest/restart.
        let retried = dispatch(RuntimeWork::Invoke {
            state: applied.state.clone(),
            invocation: Box::new(work.clone()),
            authorization: Box::new(authorization.clone()),
            observed_slot: 70,
        });
        assert_eq!(retried, applied);

        let second = fixture.invocation(&install, 0x32, 7);
        let second_authorization =
            InvocationAuthorization::PublicPreflight(PublicPreflight::for_work(&second, 8));
        let blocked = dispatch(RuntimeWork::Invoke {
            state: applied.state.clone(),
            invocation: Box::new(second.clone()),
            authorization: Box::new(second_authorization.clone()),
            observed_slot: 8,
        });
        assert_eq!(
            blocked.outcome,
            RuntimeOutcome::Completed(Err(InvocationError::ResultCapacity))
        );
        assert_eq!(blocked.state, applied.state);

        let acknowledged = dispatch(RuntimeWork::Acknowledge {
            state: applied.state,
            invocation: Box::new(work),
            authorization: Box::new(authorization),
        });
        assert!(matches!(
            acknowledged.outcome,
            RuntimeOutcome::Acknowledged(Ok(_))
        ));
        let next = dispatch(RuntimeWork::Invoke {
            state: acknowledged.state,
            invocation: Box::new(second),
            authorization: Box::new(second_authorization),
            observed_slot: 8,
        });
        assert_eq!(completed_value(&next), 12);
        let RuntimeOutcome::Completed(Ok(reply)) = next.outcome else {
            unreachable!()
        };
        assert_eq!(reply.observation.linear_revision, Some(2));
    }

    #[test]
    fn forged_management_and_invocation_contexts_fail_without_mutation() {
        let fixture = Fixture::new();
        let request = ManagementRequest::Create(Box::new(fixture.descriptor.clone()));
        let mut receipt = fixture.receipt(&request, 1, 10);
        receipt.signature[0] ^= 1;
        let rejected = dispatch(RuntimeWork::Manage {
            space: fixture.descriptor.identity.space,
            agent: fixture.descriptor.identity.agent,
            runtime_deployment: fixture.descriptor.identity.runtime_deployment,
            state: RuntimeState::default(),
            request: Box::new(request),
            authority: Some(Box::new(receipt)),
            observed_slot: 5,
        });
        assert_eq!(rejected.state, RuntimeState::default());
        assert_eq!(
            rejected.outcome,
            RuntimeOutcome::Management(Err(ManagementError::InvalidRequest))
        );

        let (install, state) = created_and_installed(&fixture);
        let mut work = fixture.invocation(&install, 0x33, 1);
        work.origin.transport_node = Some(NodeId([0x44; 32]));
        let authorization =
            InvocationAuthorization::PublicPreflight(PublicPreflight::for_work(&work, 9));
        let rejected = dispatch(RuntimeWork::Invoke {
            state: state.clone(),
            invocation: Box::new(work),
            authorization: Box::new(authorization),
            observed_slot: 9,
        });
        assert_eq!(rejected.state, state);
        assert_eq!(
            rejected.outcome,
            RuntimeOutcome::Completed(Err(InvocationError::InvalidAuthorization))
        );
    }

    #[test]
    fn weak_authority_keys_are_rejected() {
        let mut weak_public_key = [0_u8; 32];
        weak_public_key[0] = 1;
        let decoded = VerifyingKey::from_bytes(&weak_public_key)
            .expect("the identity point is structurally decodable");
        assert!(decoded.is_weak());
        assert!(!Ed25519Verifier.verify(
            &weak_public_key,
            b"forged authority message",
            &[0_u8; 64],
        ));
    }

    #[test]
    fn corrupt_custom_state_and_foreign_lane_state_fail_closed() {
        let fixture = Fixture::new();
        let (install, state) = created_and_installed(&fixture);
        let work = fixture.invocation(&install, 0x35, 1);
        let authorization =
            InvocationAuthorization::PublicPreflight(PublicPreflight::for_work(&work, 9));

        for mut hostile in [state.clone(), state] {
            if hostile.merge.is_empty() {
                hostile.merge.push(1);
            } else {
                hostile.control.push(1);
            }
            let rejected = dispatch(RuntimeWork::Invoke {
                state: hostile.clone(),
                invocation: Box::new(work.clone()),
                authorization: Box::new(authorization.clone()),
                observed_slot: 9,
            });
            assert_eq!(rejected.state, hostile);
            assert_eq!(
                rejected.outcome,
                RuntimeOutcome::Completed(Err(InvocationError::NotCreated))
            );
        }
    }

    #[test]
    fn signed_vos3_custom_runtime_envelope_passes_physical_admission() {
        let mut assembler = Assembler::new();
        let program = assembler.load_imm_64(Reg::A0, 1).trap().build_standard();
        let artifact = PackageArtifact {
            identity: BlobRef::of_bytes(&program),
            bytes: program.clone(),
        };
        let key = SigningKey::from_bytes(&[0x61; 32]);
        let public_key = key.verifying_key().to_bytes();
        let mut package = PackageEnvelope {
            manifest: PackageManifest::AgentRuntime(AgentRuntimePackageManifest {
                name: "custom-linear-test".to_string(),
                outer_program: artifact.identity.clone(),
                contract: RuntimePackageContract::canonical(),
                capabilities: CUSTOM_LINEAR_CAPABILITIES,
                signing: PackageSigning {
                    producer: ProducerId::of_public_key(&public_key),
                    public_key,
                    signature: [0; 64],
                },
            }),
            artifacts: vec![artifact],
        };
        package.manifest.signing_mut().signature =
            key.sign(&package.signing_bytes().unwrap()).to_bytes();
        let bytes = package.encode().unwrap();
        let admitted = vos::agent::package_admission::admit_runtime_package(&bytes).unwrap();
        assert_eq!(admitted.exact_bytes(), bytes);
        assert_eq!(admitted.program(), ProgramId::of_pvm(&program));
        assert_eq!(admitted.capabilities(), CUSTOM_LINEAR_CAPABILITIES);

        let mut trailing = bytes;
        trailing.push(0);
        assert!(vos::agent::package_admission::admit_runtime_package(&trailing).is_err());
    }
}
