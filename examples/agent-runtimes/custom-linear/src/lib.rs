//! A small, real custom AgentRuntime with deterministic Linear scheduling.
//!
//! The example deliberately implements the portable SDK contract directly:
//! it authenticates Create/Install management, retains a canonical actor
//! directory, admits one public Linear counter actor, persists deterministic
//! timers, retains one exact result until acknowledgement, and derives every
//! output solely from `RuntimeWork`. It does not load keys, read clocks, or
//! rely on process-local state.

#![no_std]

extern crate alloc;

use alloc::boxed::Box;
use alloc::vec::Vec;

use ed25519_dalek::{Signature, VerifyingKey};
use vos_agent_sdk::authority::{AuthorityReceipt, AuthorityVerifier};
use vos_agent_sdk::protocol::wire::{DecodeError, Decoder, Encoder};
use vos_agent_sdk::scheduling::{
    DeterministicScheduler, ScheduleCadence, ScheduleEntry, ScheduleObservation,
    ScheduleObservationSource, TimerScheduler,
};
use vos_agent_sdk::wire::CanonicalWire as _;
use vos_agent_sdk::{
    ActorDirectoryPage, ActorDirectoryRecord, ActorId, AgentDescriptor, AgentProfile, AgentRuntime,
    Hash, InstallActor, InvocationAcknowledgement, InvocationAuthorization, InvocationError,
    InvocationReply, InvocationStatus, InvocationWork, LaneSet, ManagementError, ManagementReply,
    ManagementRequest, MethodMode, ProofSystemSet, RuntimeCapabilities, RuntimeExecutionContext,
    RuntimeOutcome, RuntimeResourceUsage, RuntimeState, RuntimeTransition, RuntimeWork, ScheduleId,
    StateLane,
};

const CONTROL_MAGIC: [u8; 8] = *b"VCLCTL01";
const LINEAR_MAGIC: [u8; 8] = *b"VCLLIN01";
const MAX_STORED_WORK_BYTES: usize = vos_agent_sdk::MAX_RUNTIME_STATE_BYTES / 2;
const EXECUTION_GAS: u64 = 1;

/// This example intentionally supports one installed Linear actor, durable
/// deterministic scheduling, and no proof backend.
pub const CUSTOM_LINEAR_CAPABILITIES: RuntimeCapabilities = RuntimeCapabilities {
    lanes: LaneSet::of(StateLane::Linear),
    scheduling: true,
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
        if !work.execution_context().is_direct() {
            let state = match &work {
                RuntimeWork::Manage { state, .. }
                | RuntimeWork::Invoke { state, .. }
                | RuntimeWork::Resume { state, .. }
                | RuntimeWork::Acknowledge { state, .. } => state.clone(),
            };
            let outcome = match work {
                RuntimeWork::Manage { .. } => {
                    RuntimeOutcome::Management(Err(ManagementError::InvalidRequest))
                }
                RuntimeWork::Invoke { .. } | RuntimeWork::Resume { .. } => {
                    RuntimeOutcome::Completed(Err(InvocationError::InvalidAuthorization))
                }
                RuntimeWork::Acknowledge { .. } => {
                    RuntimeOutcome::Acknowledged(Err(InvocationError::InvalidAuthorization))
                }
            };
            return transition(state, outcome);
        }
        match work {
            RuntimeWork::Manage {
                space,
                agent,
                runtime_deployment,
                state,
                request,
                authority,
                observed_slot,
                ..
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
                ..
            } => apply_invoke(state, *invocation, *authorization, observed_slot),
            RuntimeWork::Resume { state, .. } => transition(
                state,
                RuntimeOutcome::Completed(Err(InvocationError::NotReady)),
            ),
            RuntimeWork::Acknowledge {
                state,
                invocation,
                authorization,
                ..
            } => apply_acknowledge(state, *invocation, *authorization),
        }
    }
}

#[cfg(not(feature = "scripted-fixture"))]
vos_agent_runtime_guest::export_agent_runtime!(crate::CustomLinearRuntime);

#[cfg(feature = "scripted-fixture")]
pub mod scripted_fixture;
#[cfg(feature = "scripted-fixture")]
vos_agent_runtime_guest::export_agent_runtime!(crate::scripted_fixture::ScriptedRuntime);

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

/// Encode the counter's ordinary Linear mutation.
pub fn add_message(delta: u64) -> Option<Vec<u8>> {
    (delta != 0).then(|| delta.to_le_bytes().to_vec())
}

/// Encode a one-shot durable callback. The callback adds `delta` when a later
/// work item carries a durable observation at or beyond `due_slot`.
pub fn schedule_once_message(
    schedule: ScheduleId,
    due_slot: u64,
    priority: u8,
    delta: u64,
) -> Option<Vec<u8>> {
    schedule_message(schedule, due_slot, priority, ScheduleCadence::Once, delta)
}

/// Encode a drift-free interval callback. Each next occurrence advances from
/// its previous due slot, not from a possibly late observation.
pub fn schedule_interval_message(
    schedule: ScheduleId,
    due_slot: u64,
    priority: u8,
    slots: u64,
    delta: u64,
) -> Option<Vec<u8>> {
    schedule_message(
        schedule,
        due_slot,
        priority,
        ScheduleCadence::Interval { slots },
        delta,
    )
}

/// Encode cancellation of one exact schedule identity.
pub fn cancel_schedule_message(schedule: ScheduleId) -> Option<Vec<u8>> {
    if schedule == ScheduleId::ZERO {
        return None;
    }
    let mut message = Vec::with_capacity(33);
    message.push(2);
    message.extend_from_slice(schedule.as_bytes());
    Some(message)
}

/// Encode an explicit tick. The host still supplies the durable observation;
/// this message never carries a clock value of its own.
pub fn tick_message() -> Vec<u8> {
    let mut message = Vec::with_capacity(1);
    message.push(3);
    message
}

fn schedule_message(
    schedule: ScheduleId,
    due_slot: u64,
    priority: u8,
    cadence: ScheduleCadence,
    delta: u64,
) -> Option<Vec<u8>> {
    if schedule == ScheduleId::ZERO || delta == 0 || !cadence.validate() {
        return None;
    }
    let capacity = match cadence {
        ScheduleCadence::Once => 51,
        ScheduleCadence::Interval { .. } => 59,
    };
    let mut message = Vec::with_capacity(capacity);
    message.push(1);
    message.extend_from_slice(schedule.as_bytes());
    message.extend_from_slice(&due_slot.to_le_bytes());
    message.push(priority);
    match cadence {
        ScheduleCadence::Once => message.push(0),
        ScheduleCadence::Interval { slots } => {
            message.push(1);
            message.extend_from_slice(&slots.to_le_bytes());
        }
    }
    message.extend_from_slice(&delta.to_le_bytes());
    (message.len() == capacity).then_some(message)
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
    scheduler: DeterministicScheduler,
}

#[derive(Clone)]
struct CustomState {
    control: ControlState,
    linear: LinearState,
}

impl CustomState {
    // Derive the public recovery projection from this runtime's own retained
    // signed work, not the standard runtime layout or a host-owned history.
    fn management_history_commitment(&self) -> Option<Hash> {
        use vos_agent_sdk::recovery::{ManagementHistoryEntry, management_history_commitment};
        let mut records = Vec::new();
        let mut acknowledged_through = 0;
        for bytes in
            core::iter::once(&self.control.create_work).chain(self.control.install_work.iter())
        {
            let RuntimeWork::Manage {
                request,
                authority: Some(receipt),
                observed_slot,
                ..
            } = RuntimeWork::decode(bytes).ok()?
            else {
                return None;
            };
            let reply = match request.as_ref() {
                ManagementRequest::Create(descriptor) => {
                    ManagementReply::Created(descriptor.identity.clone())
                }
                ManagementRequest::Install(install) => {
                    ManagementReply::Installed(install.entry.clone())
                }
                _ => return None,
            };
            acknowledged_through = receipt.selector.acknowledged_through;
            records.push((receipt, request, observed_slot, Ok(reply)));
        }
        management_history_commitment(
            acknowledged_through,
            records
                .iter()
                .filter(|(receipt, _, _, _)| {
                    receipt.selector.decision_sequence > acknowledged_through
                })
                .map(
                    |(receipt, request, observed_slot, result)| ManagementHistoryEntry {
                        authority: receipt.commitment(),
                        request: request.replay_commitment(),
                        epoch: receipt.selector.epoch,
                        sequence: receipt.selector.decision_sequence,
                        observed_slot: *observed_slot,
                        result,
                    },
                ),
        )
        .ok()
    }

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
        let scheduler = DeterministicScheduler::decode(
            linear.bytes_ref_bounded(vos_agent_sdk::scheduling::MAX_SCHEDULE_STATE_BYTES)?,
        )?;
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
                scheduler,
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
        let scheduler = self.linear.scheduler.encode().ok()?;
        encoder.bytes(&scheduler);

        let state = RuntimeState {
            control,
            linear,
            merge: Vec::new(),
            local: Vec::new(),
        };
        state.validate().then_some(state)
    }

    fn descriptor(&self) -> Option<AgentDescriptor> {
        let RuntimeWork::Manage {
            context: RuntimeExecutionContext::Direct,
            request,
            ..
        } = RuntimeWork::decode(&self.control.create_work).ok()?
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
        let RuntimeWork::Manage {
            context: RuntimeExecutionContext::Direct,
            request,
            ..
        } = RuntimeWork::decode(bytes).ok()?
        else {
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
                scheduler: DeterministicScheduler::default(),
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
        ManagementRequest::InspectManagementHistory => {
            if authority.is_some() {
                return management_error(prior, ManagementError::InvalidRequest);
            }
            match model.management_history_commitment() {
                Some(commitment) => transition(state, RuntimeOutcome::Management(Ok(ManagementReply::ManagementHistory(commitment)))),
                None => management_error(prior, ManagementError::InvalidRequest),
            }
        }
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
                    install_request: install.lineage_commitment(),
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
                schedules: model
                    .linear
                    .scheduler
                    .entries()
                    .len()
                    .try_into()
                    .unwrap_or(u32::MAX),
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
        ManagementRequest::PrivateControl { .. } => {
            management_error(prior, ManagementError::UnsupportedRuntime)
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
    let Some(command) = decode_command(&work.message) else {
        return invocation_error(prior, InvocationError::InvalidInput);
    };
    let Some(stored_work) = stored_invoke_work(&work, &authorization, observed_slot) else {
        return invocation_error(prior, InvocationError::ResultCapacity);
    };
    if observe_schedules(&mut model, &descriptor, &install, observed_slot).is_err()
        || apply_command(&mut model, &descriptor, &install, command).is_err()
    {
        return invocation_error(prior, InvocationError::InvalidInput);
    }
    model.linear.retained_work = Some(stored_work);
    let Some(state) = model.encode() else {
        return invocation_error(prior, InvocationError::ResultCapacity);
    };
    completed_counter(state, &work, model.linear.value, model.linear.revision)
}

fn apply_acknowledge(
    state: RuntimeState,
    work: vos_agent_sdk::InvocationRetirement,
    authorization: InvocationAuthorization,
) -> RuntimeTransition {
    let prior = state.clone();
    let Ok(mut model) = CustomState::decode(&state) else {
        return acknowledged_error(prior, InvocationError::NotCreated);
    };
    let Some(stored) = &model.linear.retained_work else {
        return acknowledged_error(prior, InvocationError::NotFound);
    };
    if !work.validate()
        || !authorization.matches_retirement(&work)
        || !stored_retirement_matches(stored, &work, &authorization)
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

enum CounterCommand {
    Add(u64),
    Schedule {
        schedule: ScheduleId,
        due_slot: u64,
        priority: u8,
        cadence: ScheduleCadence,
        delta: u64,
    },
    Cancel(ScheduleId),
    Tick,
}

fn decode_delta(message: &[u8]) -> Option<u64> {
    let delta = u64::from_le_bytes(message.try_into().ok()?);
    (delta != 0).then_some(delta)
}

fn decode_command(message: &[u8]) -> Option<CounterCommand> {
    if let Some(delta) = decode_delta(message) {
        return Some(CounterCommand::Add(delta));
    }
    match message {
        [1, rest @ ..] => {
            let schedule: [u8; 32] = rest.get(..32)?.try_into().ok()?;
            let due_slot = u64::from_le_bytes(schedule_bytes(rest, 32, 8)?);
            let priority = *message.get(41)?;
            let cadence_tag = *message.get(42)?;
            let (cadence, delta_offset, expected_len) = match cadence_tag {
                0 => (ScheduleCadence::Once, 43, 51),
                1 => (
                    ScheduleCadence::Interval {
                        slots: u64::from_le_bytes(schedule_bytes(message, 43, 8)?),
                    },
                    51,
                    59,
                ),
                _ => return None,
            };
            if message.len() != expected_len {
                return None;
            }
            let delta = u64::from_le_bytes(schedule_bytes(message, delta_offset, 8)?);
            let schedule = ScheduleId(schedule);
            (schedule != ScheduleId::ZERO && delta != 0 && cadence.validate()).then_some(
                CounterCommand::Schedule {
                    schedule,
                    due_slot,
                    priority,
                    cadence,
                    delta,
                },
            )
        }
        [2, rest @ ..] if rest.len() == 32 => {
            let schedule = ScheduleId(rest.try_into().ok()?);
            (schedule != ScheduleId::ZERO).then_some(CounterCommand::Cancel(schedule))
        }
        [3] => Some(CounterCommand::Tick),
        _ => None,
    }
}

fn schedule_bytes(message: &[u8], offset: usize, len: usize) -> Option<[u8; 8]> {
    if len != 8 {
        return None;
    }
    message
        .get(offset..offset.checked_add(len)?)?
        .try_into()
        .ok()
}

fn increment_revision(model: &mut CustomState) -> Result<(), ()> {
    model.linear.revision = model.linear.revision.checked_add(1).ok_or(())?;
    Ok(())
}

fn observe_schedules(
    model: &mut CustomState,
    descriptor: &AgentDescriptor,
    install: &InstallActor,
    observed_slot: u64,
) -> Result<(), ()> {
    let source = match descriptor.identity.profile {
        AgentProfile::Local => ScheduleObservationSource::DurableLocal,
        AgentProfile::Shared => ScheduleObservationSource::CommittedLeader,
        AgentProfile::Private => return Err(()),
    };
    let before = model.linear.scheduler.clone();
    let fires = model
        .linear
        .scheduler
        .observe(
            descriptor.identity.profile,
            ScheduleObservation {
                slot: observed_slot,
                source,
            },
            vos_agent_sdk::scheduling::MAX_SCHEDULE_FIRES_PER_SLICE,
        )
        .map_err(|_| ())?;
    if fires.is_empty() && model.linear.scheduler != before {
        increment_revision(model)?;
    }
    for fire in fires {
        if fire.actor != install.entry.actor
            || fire.incarnation != actor_incarnation(install)
            || fire.deployment != install.entry.deployment
            || fire.program != install.entry.program
            || fire.mode != MethodMode::Linear
        {
            return Err(());
        }
        let delta = decode_delta(&fire.message).ok_or(())?;
        model.linear.value = model.linear.value.checked_add(delta).ok_or(())?;
        increment_revision(model)?;
    }
    Ok(())
}

fn apply_command(
    model: &mut CustomState,
    descriptor: &AgentDescriptor,
    install: &InstallActor,
    command: CounterCommand,
) -> Result<(), ()> {
    match command {
        CounterCommand::Add(delta) => {
            model.linear.value = model.linear.value.checked_add(delta).ok_or(())?;
            increment_revision(model)
        }
        CounterCommand::Schedule {
            schedule,
            due_slot,
            priority,
            cadence,
            delta,
        } => {
            model
                .linear
                .scheduler
                .schedule(
                    descriptor.identity.profile,
                    ScheduleEntry {
                        schedule,
                        actor: install.entry.actor,
                        incarnation: actor_incarnation(install),
                        deployment: install.entry.deployment,
                        program: install.entry.program,
                        mode: MethodMode::Linear,
                        message: delta.to_le_bytes().to_vec(),
                        due_slot,
                        priority,
                        cadence,
                    },
                )
                .map_err(|_| ())?;
            increment_revision(model)
        }
        CounterCommand::Cancel(schedule) => {
            model
                .linear
                .scheduler
                .cancel(descriptor.identity.profile, schedule)
                .map_err(|_| ())?;
            increment_revision(model)
        }
        CounterCommand::Tick => Ok(()),
    }
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
        context: RuntimeExecutionContext::Direct,
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
        context: RuntimeExecutionContext::Direct,
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
            context: RuntimeExecutionContext::Direct,
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
            context: RuntimeExecutionContext::Direct,
            state,
            invocation,
            authorization: stored_authorization,
            ..
        }) if state == RuntimeState::default()
            && invocation.as_ref() == work
            && stored_authorization.as_ref() == authorization
    )
}

// The custom layout retains the original canonical invocation. Decode and
// validate those accepted bytes, then compare the complete metadata projection;
// retirement transport need not duplicate its authenticated artifact preimages.
fn stored_retirement_matches(
    bytes: &[u8],
    work: &vos_agent_sdk::InvocationRetirement,
    authorization: &InvocationAuthorization,
) -> bool {
    matches!(
        RuntimeWork::decode(bytes),
        Ok(RuntimeWork::Invoke {
            context: RuntimeExecutionContext::Direct,
            state,
            invocation,
            authorization: stored_authorization,
            ..
        }) if state == RuntimeState::default()
            && vos_agent_sdk::InvocationRetirement::from_work(&invocation) == *work
            && stored_authorization.as_ref() == authorization
    )
}

fn validate_stored_create(bytes: &[u8]) -> Result<(), DecodeError> {
    match RuntimeWork::decode(bytes).map_err(|_| DecodeError::NonCanonical)? {
        RuntimeWork::Manage {
            context: RuntimeExecutionContext::Direct,
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
            context: RuntimeExecutionContext::Direct,
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
        RuntimeWork::Invoke {
            context: RuntimeExecutionContext::Direct,
            state,
            ..
        } if state == RuntimeState::default() => Ok(()),
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
    use vos_pvm::ExitReason;
    use vos_pvm::refine_host::RefineContext;
    use vos_pvm_compiler::assembler::{Assembler, Reg};

    use super::*;

    const AUTHORITY_SEED: [u8; 32] = [0x41; 32];

    struct Fixture {
        key: SigningKey,
        descriptor: AgentDescriptor,
    }

    impl Fixture {
        fn new() -> Self {
            Self::for_profile(AgentProfile::Local)
        }

        fn for_profile(profile: AgentProfile) -> Self {
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
                    profile,
                    runtime_deployment: DeploymentId([0x17; 32]),
                    runtime_program: ProgramId([0x18; 32]),
                    runtime_producer: ProducerId([0x19; 32]),
                    transition_producer: ProducerId([0x1a; 32]),
                },
                creation_nonce,
                authority: AgentAuthorityBinding {
                    policy: Hash([0x1a; 32]),
                    issuer,
                    public_key,
                    initial_epoch: 1,
                },
                private_recovery: (profile == AgentProfile::Private).then_some(
                    vos::agent_sdk::PrivateRecoveryBinding {
                        signing_key_commitment: Hash([0x1d; 32]),
                        encryption_public_key: [0x1e; 32],
                    },
                ),
                runtime_package: blob(0x1b, 64),
                runtime_contract: RuntimePackageContract::canonical(),
                capabilities: CUSTOM_LINEAR_CAPABILITIES,
                replicas: vec![AgentReplica {
                    node: NodeId([0x1c; 32]),
                    principal: owner,
                    role: if profile == AgentProfile::Private {
                        ReplicaRole::Observer
                    } else {
                        ReplicaRole::Voter
                    },
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
            let operation = request.authority_operation().unwrap();
            let (actor, actor_deployment) = request.authority_actor_selector();
            let mut receipt = AuthorityReceipt {
                selector: AuthorityReceiptSelector {
                    policy: self.descriptor.authority.policy,
                    issuer: self.descriptor.authority.issuer,
                    space: self.descriptor.identity.space,
                    agent: self.descriptor.identity.agent,
                    operation,
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
                    decision_sequence: operation
                        .uses_management_decision_journal()
                        .then_some(sequence)
                        .unwrap_or(0),
                    acknowledged_through: operation
                        .uses_management_decision_journal()
                        .then_some(sequence.saturating_sub(1))
                        .unwrap_or(0),
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
                context: RuntimeExecutionContext::Direct,
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
                    scheduling: true,
                    proof_systems: ProofSystemSet::EMPTY,
                },
            }
        }

        fn install_work(&self, state: RuntimeState, install: InstallActor) -> RuntimeWork {
            let request = ManagementRequest::Install(Box::new(install));
            RuntimeWork::Manage {
                context: RuntimeExecutionContext::Direct,
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
            self.invocation_message(install, discriminator, delta.to_le_bytes().to_vec())
        }

        fn invocation_message(
            &self,
            install: &InstallActor,
            discriminator: u8,
            message: Vec<u8>,
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
                message,
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

    fn compiled_runtime_elf_path(
        manifest: &std::path::Path,
        target_dir: Option<&std::ffi::OsStr>,
    ) -> std::path::PathBuf {
        // The example recipes invoke Cargo from this package. Match their
        // target-dir override rather than silently reading an old local ELF.
        let target = target_dir
            .map(|target| manifest.join(target))
            .unwrap_or_else(|| manifest.join("target"));
        target.join("riscv64em-vos/release/custom_linear_agent_runtime.elf")
    }

    #[test]
    fn compiled_runtime_artifact_path_honors_target_override() {
        use std::path::Path;
        let manifest = Path::new("/example");
        let suffix = "riscv64em-vos/release/custom_linear_agent_runtime.elf";
        assert_eq!(
            compiled_runtime_elf_path(manifest, None),
            manifest.join("target").join(suffix)
        );
        assert_eq!(
            compiled_runtime_elf_path(manifest, Some(std::ffi::OsStr::new("/shared-target"))),
            Path::new("/shared-target").join(suffix)
        );
        assert_eq!(
            compiled_runtime_elf_path(manifest, Some(std::ffi::OsStr::new("custom-target"))),
            manifest.join("custom-target").join(suffix)
        );
    }

    fn compiled_runtime_pvm() -> Vec<u8> {
        let elf = compiled_runtime_elf_path(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")),
            std::env::var_os("CARGO_TARGET_DIR").as_deref(),
        );
        let elf = std::fs::read(&elf).unwrap_or_else(|error| {
            panic!(
                "read freshly built custom runtime ELF {}: {error}; run `cargo actor` first",
                elf.display()
            )
        });
        let pvm = vos_pvm_compiler::link_elf_spi(&elf)
            .expect("link custom runtime through the clean standard-program ABI");
        vos_pvm::spi::validate_refine_host_calls(&pvm)
            .expect("custom runtime uses only the clean outer Refine allowlist");
        pvm
    }

    fn dispatch_compiled(pvm: &[u8], work: RuntimeWork) -> RuntimeTransition {
        let input = work.encode().expect("encode physical RuntimeWork");
        let execution = RefineContext::load(pvm, &input, 2_000_000_000)
            .expect("load compiled custom runtime")
            .run();
        assert_eq!(
            execution.exit,
            ExitReason::Halt,
            "compiled custom runtime failed at pc {} with registers {:?}",
            execution.pc,
            execution.registers,
        );
        let output = execution
            .output_bounded(RuntimeTransition::MAX_ENCODED_BYTES)
            .expect("compiled custom runtime published an output window");
        let transition = RuntimeTransition::decode(&output)
            .expect("compiled custom runtime returned a canonical transition");
        assert_eq!(transition.encode().unwrap(), output);
        transition
    }

    fn acknowledge_work(
        state: RuntimeState,
        invocation: InvocationWork,
        authorization: InvocationAuthorization,
    ) -> RuntimeWork {
        RuntimeWork::Acknowledge {
            context: RuntimeExecutionContext::Direct,
            state,
            invocation: Box::new(vos_agent_sdk::InvocationRetirement::from_work(&invocation)),
            authorization: Box::new(authorization),
        }
    }

    fn invoke_work(
        state: RuntimeState,
        invocation: InvocationWork,
        authorization: InvocationAuthorization,
        observed_slot: u64,
    ) -> RuntimeWork {
        RuntimeWork::Invoke {
            context: RuntimeExecutionContext::Direct,
            state,
            invocation: Box::new(invocation),
            authorization: Box::new(authorization),
            observed_slot,
        }
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
    fn recovery_query_uses_custom_layout_and_rejects_foreign_scope_or_authority() {
        use vos_agent_sdk::recovery::{ManagementHistoryEntry, management_history_commitment};
        let fixture = Fixture::new();
        let create = fixture.create(RuntimeState::default(), 1);
        let created = dispatch(create.clone());
        let RuntimeWork::Manage {
            request,
            authority: Some(receipt),
            observed_slot,
            ..
        } = &create
        else {
            unreachable!()
        };
        let result = Ok(ManagementReply::Created(
            fixture.descriptor.identity.clone(),
        ));
        let expected = management_history_commitment(
            0,
            [ManagementHistoryEntry {
                authority: receipt.commitment(),
                request: request.replay_commitment(),
                epoch: receipt.selector.epoch,
                sequence: receipt.selector.decision_sequence,
                observed_slot: *observed_slot,
                result: &result,
            }],
        )
        .unwrap();
        let query = RuntimeWork::Manage {
            context: RuntimeExecutionContext::Direct,
            space: fixture.descriptor.identity.space,
            agent: fixture.descriptor.identity.agent,
            runtime_deployment: fixture.descriptor.identity.runtime_deployment,
            state: created.state.clone(),
            request: Box::new(ManagementRequest::InspectManagementHistory),
            authority: None,
            observed_slot: 0,
        };
        let inspected = dispatch(query.clone());
        assert_eq!(inspected.state, created.state);
        assert_eq!(
            inspected.outcome,
            RuntimeOutcome::Management(Ok(ManagementReply::ManagementHistory(expected)))
        );
        for mutation in 0..4 {
            let mut invalid = query.clone();
            if let RuntimeWork::Manage {
                space,
                agent,
                runtime_deployment,
                authority,
                ..
            } = &mut invalid
            {
                match mutation {
                    0 => space.0[0] ^= 1,
                    1 => agent.0[0] ^= 1,
                    2 => runtime_deployment.0[0] ^= 1,
                    _ => *authority = Some(receipt.clone()),
                }
            }
            // Exercise the runtime directly as well as the canonical codec's
            // admission rules: a caller cannot authorize this read-only query.
            let rejected = CustomLinearRuntime.apply(invalid);
            assert_eq!(rejected.state, created.state);
            assert!(matches!(
                rejected.outcome,
                RuntimeOutcome::Management(Err(_))
            ));
        }
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
            context: RuntimeExecutionContext::Direct,
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
        assert_eq!(
            page.entries[0].install_request,
            install.lineage_commitment()
        );
        assert_eq!(inspected.state, installed.state);
    }

    #[test]
    fn direct_custom_executor_fails_closed_on_attested_work_without_state_change() {
        let fixture = Fixture::new();
        let state = RuntimeState {
            control: vec![0xa1],
            linear: vec![0xa2],
            merge: Vec::new(),
            local: Vec::new(),
        };
        let mut work = fixture.create(state.clone(), 5);
        let RuntimeWork::Manage { context, .. } = &mut work else {
            unreachable!()
        };
        *context = RuntimeExecutionContext::Attested {
            proof_system: Hash([0xa3; 32]),
        };

        let mut runtime = CustomLinearRuntime;
        let rejected = runtime.apply(work);
        assert_eq!(rejected.state, state);
        assert_eq!(
            rejected.outcome,
            RuntimeOutcome::Management(Err(ManagementError::InvalidRequest))
        );
    }

    #[test]
    fn custom_linear_explicitly_rejects_private_runtime_control_without_state_change() {
        let fixture = Fixture::new();
        let created = dispatch(fixture.create(RuntimeState::default(), 5));
        let policy = vos_agent_sdk::contract::RuntimeResourcePolicy::standard();
        let policy_bytes = policy.encode().unwrap();
        let request = ManagementRequest::PrivateControl {
            control: Box::new(vos_agent_sdk::private::PrivateControlRecord {
                space: fixture.descriptor.identity.space,
                agent: fixture.descriptor.identity.agent,
                sequence: 0,
                previous: None,
                operation: vos_agent_sdk::private::PrivateControlOperation::SetResourcePolicy {
                    policy: BlobRef::of_bytes(&policy_bytes),
                },
                signer: vos_agent_sdk::private::PrivateControlSigner::Owner,
                signer_public_key: [0xa4; 32],
                signature: [0xa5; vos_agent_sdk::private::PRIVATE_SIGNATURE_BYTES],
            }),
            mutation: Box::new(vos_agent_sdk::PrivateRuntimeMutation::SetResourcePolicy(
                policy,
            )),
        };
        assert!(request.is_valid());
        let receipt = fixture.receipt(&request, 2, 20);
        let rejected = dispatch(RuntimeWork::Manage {
            context: RuntimeExecutionContext::Direct,
            space: fixture.descriptor.identity.space,
            agent: fixture.descriptor.identity.agent,
            runtime_deployment: fixture.descriptor.identity.runtime_deployment,
            state: created.state.clone(),
            request: Box::new(request),
            authority: Some(Box::new(receipt)),
            observed_slot: 6,
        });
        assert_eq!(rejected.state, created.state);
        assert_eq!(
            rejected.outcome,
            RuntimeOutcome::Management(Err(ManagementError::UnsupportedRuntime))
        );
    }

    #[test]
    fn custom_linear_result_survives_restart_retry_and_requires_acknowledgement() {
        let fixture = Fixture::new();
        let (install, initial) = created_and_installed(&fixture);
        let work = fixture.invocation(&install, 0x31, 5);
        let authorization =
            InvocationAuthorization::PublicPreflight(PublicPreflight::for_work(&work, 7));
        let applied = dispatch(RuntimeWork::Invoke {
            context: RuntimeExecutionContext::Direct,
            state: initial,
            invocation: Box::new(work.clone()),
            authorization: Box::new(authorization.clone()),
            observed_slot: 7,
        });
        assert_eq!(completed_value(&applied), 5);

        // `dispatch` constructs no process state. Supplying the returned
        // state to another invocation therefore models a fresh guest/restart.
        let retried = dispatch(RuntimeWork::Invoke {
            context: RuntimeExecutionContext::Direct,
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
            context: RuntimeExecutionContext::Direct,
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

        let compact = vos_agent_sdk::InvocationRetirement::from_work(&work);
        for mutation in 0..3 {
            let mut changed = compact.clone();
            match mutation {
                0 => changed.message.push(0xa7),
                1 => changed.gas += 1,
                2 => changed.incarnation = Hash([0xa7; 32]),
                _ => unreachable!(),
            }
            // Even a structurally valid binding for the substituted metadata
            // cannot retire the invocation accepted in the custom state layout.
            let changed_authorization = InvocationAuthorization::PublicPreflight(PublicPreflight {
                work: changed.commitment(), origin: changed.origin, observed_slot: 7,
            });
            let rejected = dispatch(RuntimeWork::Acknowledge {
                context: RuntimeExecutionContext::Direct,
                state: applied.state.clone(),
                invocation: Box::new(changed),
                authorization: Box::new(changed_authorization),
            });
            assert_eq!(rejected.state, applied.state);
            assert_eq!(rejected.outcome,
                RuntimeOutcome::Acknowledged(Err(InvocationError::DivergentInvocation)));
        }

        let acknowledged = dispatch(RuntimeWork::Acknowledge {
            context: RuntimeExecutionContext::Direct,
            state: applied.state,
            invocation: Box::new(vos_agent_sdk::InvocationRetirement::from_work(&work)),
            authorization: Box::new(authorization),
        });
        assert!(matches!(
            acknowledged.outcome,
            RuntimeOutcome::Acknowledged(Ok(_))
        ));
        let next = dispatch(RuntimeWork::Invoke {
            context: RuntimeExecutionContext::Direct,
            state: acknowledged.state,
            invocation: Box::new(second),
            authorization: Box::new(second_authorization),
            observed_slot: 8,
        });
        assert_eq!(completed_value(&next), 12);
        let RuntimeOutcome::Completed(Ok(reply)) = next.outcome else {
            unreachable!()
        };
        assert_eq!(reply.observation.linear_revision, Some(4));
    }

    #[test]
    fn forged_management_and_invocation_contexts_fail_without_mutation() {
        let fixture = Fixture::new();
        let request = ManagementRequest::Create(Box::new(fixture.descriptor.clone()));
        let mut receipt = fixture.receipt(&request, 1, 10);
        receipt.signature[0] ^= 1;
        let rejected = dispatch(RuntimeWork::Manage {
            context: RuntimeExecutionContext::Direct,
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
            context: RuntimeExecutionContext::Direct,
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
                context: RuntimeExecutionContext::Direct,
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

    fn scheduled_interval_survives_restart(profile: AgentProfile) {
        let fixture = Fixture::for_profile(profile);
        let (install, initial) = created_and_installed(&fixture);
        let schedule = ScheduleId([0x51; 32]);
        let schedule_work = fixture.invocation_message(
            &install,
            0x41,
            schedule_interval_message(schedule, 10, 2, 3, 2).unwrap(),
        );
        let schedule_authorization =
            InvocationAuthorization::PublicPreflight(PublicPreflight::for_work(&schedule_work, 5));
        let scheduled = dispatch(RuntimeWork::Invoke {
            context: RuntimeExecutionContext::Direct,
            state: initial,
            invocation: Box::new(schedule_work.clone()),
            authorization: Box::new(schedule_authorization.clone()),
            observed_slot: 5,
        });
        assert_eq!(completed_value(&scheduled), 0);
        let scheduled_model = CustomState::decode(&scheduled.state).unwrap();
        assert_eq!(scheduled_model.linear.scheduler.entries()[0].due_slot, 10);

        let acknowledged = dispatch(RuntimeWork::Acknowledge {
            context: RuntimeExecutionContext::Direct,
            state: scheduled.state,
            invocation: Box::new(vos_agent_sdk::InvocationRetirement::from_work(&schedule_work)),
            authorization: Box::new(schedule_authorization),
        });
        let tick = fixture.invocation_message(&install, 0x42, tick_message());
        let tick_authorization =
            InvocationAuthorization::PublicPreflight(PublicPreflight::for_work(&tick, 17));
        let fired = dispatch(RuntimeWork::Invoke {
            context: RuntimeExecutionContext::Direct,
            state: acknowledged.state,
            invocation: Box::new(tick.clone()),
            authorization: Box::new(tick_authorization.clone()),
            observed_slot: 17,
        });
        assert_eq!(completed_value(&fired), 6);
        let fired_model = CustomState::decode(&fired.state).unwrap();
        assert_eq!(fired_model.linear.scheduler.last_observation(), Some(17));
        assert_eq!(fired_model.linear.scheduler.entries()[0].due_slot, 19);

        // A fresh guest receives the same state and exact work. Even an
        // expired observation cannot duplicate the already retained fires.
        let retried = dispatch(RuntimeWork::Invoke {
            context: RuntimeExecutionContext::Direct,
            state: fired.state.clone(),
            invocation: Box::new(tick.clone()),
            authorization: Box::new(tick_authorization.clone()),
            observed_slot: 99,
        });
        assert_eq!(retried, fired);

        let acknowledged = dispatch(RuntimeWork::Acknowledge {
            context: RuntimeExecutionContext::Direct,
            state: fired.state,
            invocation: Box::new(vos_agent_sdk::InvocationRetirement::from_work(&tick)),
            authorization: Box::new(tick_authorization),
        });
        let regressed = fixture.invocation_message(&install, 0x43, tick_message());
        let regressed_authorization =
            InvocationAuthorization::PublicPreflight(PublicPreflight::for_work(&regressed, 16));
        let rejected = dispatch(RuntimeWork::Invoke {
            context: RuntimeExecutionContext::Direct,
            state: acknowledged.state.clone(),
            invocation: Box::new(regressed),
            authorization: Box::new(regressed_authorization),
            observed_slot: 16,
        });
        assert_eq!(rejected.state, acknowledged.state);
        assert_eq!(
            rejected.outcome,
            RuntimeOutcome::Completed(Err(InvocationError::InvalidInput))
        );
    }

    /// This is an explicit artifact gate rather than part of ordinary unit
    /// testing: `just test-custom-agent-runtime` first builds the deterministic
    /// riscv64 ELF and then selects this ignored test. Every transition is
    /// compared with the host-native model so the compiled outer ABI cannot
    /// silently implement different scheduling or retry semantics.
    #[test]
    #[ignore = "requires a freshly built riscv64 custom runtime artifact"]
    fn compiled_runtime_executes_scheduling_and_rejects_attested_context() {
        let pvm = compiled_runtime_pvm();
        assert_eq!(pvm, compiled_runtime_pvm(), "linking must be reproducible");
        assert_ne!(ProgramId::of_pvm(&pvm), ProgramId::ZERO);

        for profile in [AgentProfile::Local, AgentProfile::Shared] {
            let fixture = Fixture::for_profile(profile);
            let physical = |work: RuntimeWork| {
                let expected = dispatch(work.clone());
                let actual = dispatch_compiled(&pvm, work);
                assert_eq!(actual, expected, "compiled/native transition mismatch");
                actual
            };

            let created = physical(fixture.create(RuntimeState::default(), 5));
            let install = fixture.install();
            let installed = physical(fixture.install_work(created.state, install.clone()));

            // A fresh interpreter must expose original install lineage via
            // the public directory ABI, without access to private state.
            let inspected = physical(RuntimeWork::Manage {
                context: RuntimeExecutionContext::Direct,
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
                panic!("expected physical actor directory");
            };
            assert_eq!(page.entries.len(), 1);
            assert_eq!(
                page.entries[0].install_request,
                install.lineage_commitment()
            );
            assert_eq!(inspected.state, installed.state);

            let recovery = physical(RuntimeWork::Manage {
                context: RuntimeExecutionContext::Direct,
                space: fixture.descriptor.identity.space,
                agent: fixture.descriptor.identity.agent,
                runtime_deployment: fixture.descriptor.identity.runtime_deployment,
                state: installed.state.clone(),
                request: Box::new(ManagementRequest::InspectManagementHistory),
                authority: None,
                observed_slot: 0,
            });
            assert!(vos_agent_sdk::recovery::management_history_reply_matches(
                &installed.state,
                CustomState::decode(&installed.state).unwrap().management_history_commitment().unwrap(),
                &recovery,
            ));

            let interval = ScheduleId([0x71; 32]);
            let schedule = fixture.invocation_message(
                &install,
                0x72,
                schedule_interval_message(interval, 10, 2, 3, 2).unwrap(),
            );
            let schedule_authorization =
                InvocationAuthorization::PublicPreflight(PublicPreflight::for_work(&schedule, 5));
            let scheduled = physical(invoke_work(
                installed.state,
                schedule.clone(),
                schedule_authorization.clone(),
                5,
            ));
            assert_eq!(completed_value(&scheduled), 0);
            let acknowledged = physical(acknowledge_work(
                scheduled.state,
                schedule,
                schedule_authorization,
            ));

            // A second far-future timer is durably installed and then
            // cancelled. It must not be resurrected by restart/handoff.
            let cancelled_id = ScheduleId([0x73; 32]);
            let future = fixture.invocation_message(
                &install,
                0x74,
                schedule_once_message(cancelled_id, 100, 1, 99).unwrap(),
            );
            let future_authorization =
                InvocationAuthorization::PublicPreflight(PublicPreflight::for_work(&future, 6));
            let future_scheduled = physical(invoke_work(
                acknowledged.state,
                future.clone(),
                future_authorization.clone(),
                6,
            ));
            let future_acknowledged = physical(acknowledge_work(
                future_scheduled.state,
                future,
                future_authorization,
            ));
            let cancel = fixture.invocation_message(
                &install,
                0x75,
                cancel_schedule_message(cancelled_id).unwrap(),
            );
            let cancel_authorization =
                InvocationAuthorization::PublicPreflight(PublicPreflight::for_work(&cancel, 7));
            let cancelled = physical(invoke_work(
                future_acknowledged.state,
                cancel.clone(),
                cancel_authorization.clone(),
                7,
            ));
            let cancel_acknowledged = physical(acknowledge_work(
                cancelled.state,
                cancel,
                cancel_authorization,
            ));

            let tick = fixture.invocation_message(&install, 0x76, tick_message());
            let tick_authorization =
                InvocationAuthorization::PublicPreflight(PublicPreflight::for_work(&tick, 17));
            let fired = physical(invoke_work(
                cancel_acknowledged.state,
                tick.clone(),
                tick_authorization.clone(),
                17,
            ));
            assert_eq!(completed_value(&fired), 6);
            let model = CustomState::decode(&fired.state).unwrap();
            assert_eq!(model.linear.scheduler.last_observation(), Some(17));
            assert_eq!(model.linear.scheduler.entries().len(), 1);
            assert_eq!(model.linear.scheduler.entries()[0].schedule, interval);
            assert_eq!(model.linear.scheduler.entries()[0].due_slot, 19);

            // A new PVM instance receiving the serialized state models both a
            // process restart and a Shared-leader handoff. Exact retry at a
            // later observation recovers the retained transition unchanged.
            let recovered_state = RuntimeTransition::decode(&fired.encode().unwrap())
                .unwrap()
                .state;
            let retried = dispatch_compiled(
                &pvm,
                invoke_work(
                    recovered_state,
                    tick.clone(),
                    tick_authorization.clone(),
                    99,
                ),
            );
            assert_eq!(retried, fired);
            let tick_acknowledged =
                physical(acknowledge_work(fired.state, tick, tick_authorization));

            let next_tick = fixture.invocation_message(&install, 0x77, tick_message());
            let next_authorization =
                InvocationAuthorization::PublicPreflight(PublicPreflight::for_work(&next_tick, 20));
            let next = physical(invoke_work(
                tick_acknowledged.state,
                next_tick,
                next_authorization,
                20,
            ));
            assert_eq!(completed_value(&next), 8);
            let model = CustomState::decode(&next.state).unwrap();
            assert_eq!(model.linear.scheduler.entries().len(), 1);
            assert_eq!(model.linear.scheduler.entries()[0].due_slot, 22);
        }

        // This scheduling runtime is intentionally Local/Shared-only. Prove
        // that the compiled artifact rejects a Private descriptor before it
        // can create state (and therefore before it can retain a timer).
        let private = Fixture::for_profile(AgentProfile::Private);
        let private_work = private.create(RuntimeState::default(), 5);
        let expected = dispatch(private_work.clone());
        let rejected = dispatch_compiled(&pvm, private_work);
        assert_eq!(rejected, expected);
        assert_eq!(rejected.state, RuntimeState::default());
        assert_eq!(
            rejected.outcome,
            RuntimeOutcome::Management(Err(ManagementError::InvalidRequest))
        );

        let fixture = Fixture::new();
        let mut attested = fixture.create(RuntimeState::default(), 5);
        let RuntimeWork::Manage { context, .. } = &mut attested else {
            unreachable!()
        };
        *context = RuntimeExecutionContext::Attested {
            proof_system: Hash([0xa3; 32]),
        };
        let input = attested.encode().unwrap();
        let rejected = RefineContext::load(&pvm, &input, 2_000_000_000)
            .expect("load attested rejection probe")
            .run();
        assert_ne!(rejected.exit, ExitReason::Halt);
        assert!(
            rejected
                .output_bounded(RuntimeTransition::MAX_ENCODED_BYTES)
                .is_none()
        );
    }

    #[test]
    fn local_and_shared_timers_survive_restart_and_leader_handoff_without_drift() {
        scheduled_interval_survives_restart(AgentProfile::Local);
        scheduled_interval_survives_restart(AgentProfile::Shared);
    }

    #[test]
    fn scheduler_messages_are_canonical_and_reject_ambient_time() {
        let schedule = ScheduleId([0x61; 32]);
        let once = schedule_once_message(schedule, 7, 1, 3).unwrap();
        assert!(matches!(
            decode_command(&once),
            Some(CounterCommand::Schedule {
                due_slot: 7,
                priority: 1,
                cadence: ScheduleCadence::Once,
                delta: 3,
                ..
            })
        ));
        let interval = schedule_interval_message(schedule, 7, 1, 4, 3).unwrap();
        assert!(matches!(
            decode_command(&interval),
            Some(CounterCommand::Schedule {
                cadence: ScheduleCadence::Interval { slots: 4 },
                ..
            })
        ));
        let mut trailing = interval;
        trailing.push(0);
        assert!(decode_command(&trailing).is_none());
        assert!(schedule_interval_message(schedule, 7, 1, 0, 3).is_none());
        assert!(schedule_once_message(ScheduleId::ZERO, 7, 1, 3).is_none());
        assert!(matches!(
            decode_command(&tick_message()),
            Some(CounterCommand::Tick)
        ));
    }

    #[test]
    fn signed_vos3_scheduled_runtime_envelope_passes_physical_admission() {
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
                name: "custom-scheduled-linear-test".to_string(),
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
