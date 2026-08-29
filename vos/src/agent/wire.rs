//! Stable management ABI between a node and an agent-runtime PVM.

use alloc::vec::Vec;

use super::AgentRuntime;
use super::execution::{
    ActorExecutionError, ActorExecutionReply, ActorExecutionStatus, ActorInvocation, RuntimeBlob,
    RuntimeExecutionCall, RuntimeExecutionReturn,
};
use super::standard::{
    StandardActorState, StandardAgentRuntime, StandardLaneState, StandardRuntimeState,
};
use super::{
    ActorDirectoryPage, ActorEntry, ActorInitialState, ActorLifecycleDebt, AgentConfig,
    AgentIdentity, AgentProfile, AgentReplica, LaneSet, LifecycleError, LifecycleReply,
    LifecycleRequest, MethodMode, ReplicaRole, RuntimeCapabilities, RuntimeRequirements, StateLane,
};
use crate::service::wire::{DecodeError, Decoder, Encoder, ServiceWire};
use crate::service::{
    ActorId, AgentId, BlobRef, DeploymentId, Hash, NodeId, PrincipalId, ProducerId, ProgramId,
    SpaceId,
};

/// One management call. Runtime-owned state is opaque to the node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeCall {
    pub state: Vec<u8>,
    pub request: LifecycleRequest,
}

/// Deterministic result of one management call.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeReturn {
    pub state: Vec<u8>,
    pub result: Result<LifecycleReply, LifecycleError>,
}

impl ServiceWire for RuntimeCall {
    const MAGIC: [u8; 4] = *b"AGRT";

    fn encode_body(&self, output: &mut Vec<u8>) {
        let mut encoder = Encoder(output);
        encoder.fixed(&super::RUNTIME_ABI_ID.0);
        encoder.bytes(&self.state);
        encode_request(&mut encoder, &self.request);
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        if Hash(decoder.fixed()?) != super::RUNTIME_ABI_ID {
            return Err(DecodeError::InvalidPlatform);
        }
        Ok(Self {
            state: decoder.bytes()?,
            request: decode_request(decoder)?,
        })
    }
}

impl ServiceWire for AgentConfig {
    const MAGIC: [u8; 4] = *b"AGCF";

    fn encode_body(&self, output: &mut Vec<u8>) {
        let mut encoder = Encoder(output);
        encoder.fixed(&super::RUNTIME_ABI_ID.0);
        encode_config(&mut encoder, self);
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        if Hash(decoder.fixed()?) != super::RUNTIME_ABI_ID {
            return Err(DecodeError::InvalidPlatform);
        }
        decode_config(decoder)
    }
}

impl ServiceWire for RuntimeReturn {
    const MAGIC: [u8; 4] = *b"AGRR";

    fn encode_body(&self, output: &mut Vec<u8>) {
        let mut encoder = Encoder(output);
        encoder.fixed(&super::RUNTIME_ABI_ID.0);
        encoder.bytes(&self.state);
        match &self.result {
            Ok(reply) => {
                encoder.bool(true);
                encode_reply(&mut encoder, reply);
            }
            Err(error) => {
                encoder.bool(false);
                encode_error(&mut encoder, *error);
            }
        }
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        if Hash(decoder.fixed()?) != super::RUNTIME_ABI_ID {
            return Err(DecodeError::InvalidPlatform);
        }
        let state = decoder.bytes()?;
        let result = if decoder.bool()? {
            Ok(decode_reply(decoder)?)
        } else {
            Err(decode_error(decoder)?)
        };
        Ok(Self { state, result })
    }
}

impl ServiceWire for RuntimeExecutionCall {
    const MAGIC: [u8; 4] = *b"AGEX";

    fn encode_body(&self, output: &mut Vec<u8>) {
        let mut encoder = Encoder(output);
        encoder.fixed(&super::RUNTIME_ABI_ID.0);
        encoder.bytes(&self.state);
        encode_actor_invocation(&mut encoder, &self.invocation);
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        if Hash(decoder.fixed()?) != super::RUNTIME_ABI_ID {
            return Err(DecodeError::InvalidPlatform);
        }
        let call = Self {
            state: decoder.bytes()?,
            invocation: decode_actor_invocation(decoder)?,
        };
        call.invocation
            .validate()
            .map_err(|_| DecodeError::NonCanonical)?;
        Ok(call)
    }
}

impl ServiceWire for RuntimeExecutionReturn {
    const MAGIC: [u8; 4] = *b"AGER";

    fn encode_body(&self, output: &mut Vec<u8>) {
        let mut encoder = Encoder(output);
        encoder.fixed(&super::RUNTIME_ABI_ID.0);
        encoder.bytes(&self.state);
        match &self.result {
            Ok(reply) => {
                encoder.bool(true);
                encode_execution_reply(&mut encoder, reply);
            }
            Err(error) => {
                encoder.bool(false);
                encode_execution_error(&mut encoder, *error);
            }
        }
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        if Hash(decoder.fixed()?) != super::RUNTIME_ABI_ID {
            return Err(DecodeError::InvalidPlatform);
        }
        let state = decoder.bytes()?;
        let result = if decoder.bool()? {
            Ok(decode_execution_reply(decoder)?)
        } else {
            Err(decode_execution_error(decoder)?)
        };
        Ok(Self { state, result })
    }
}

impl ServiceWire for StandardRuntimeState {
    const MAGIC: [u8; 4] = *b"AGST";

    fn encode_body(&self, output: &mut Vec<u8>) {
        let mut encoder = Encoder(output);
        encoder.fixed(&super::RUNTIME_ABI_ID.0);
        encoder.option(&self.config, encode_config);
        encoder.list(&self.actors, |encoder, actor| {
            encode_entry(encoder, &actor.record.entry);
            encoder.fixed(&actor.record.producer.0);
            encode_blob(encoder, &actor.record.package);
            encode_initial_state(encoder, &actor.record.initial_state);
            encode_requirements(encoder, actor.record.requirements);
            encode_debt(encoder, actor.debt);
            encode_lane_state(encoder, &actor.lane_state);
        });
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        if Hash(decoder.fixed()?) != super::RUNTIME_ABI_ID {
            return Err(DecodeError::InvalidPlatform);
        }
        let state = StandardRuntimeState {
            config: decoder.option(decode_config)?,
            actors: decoder.list(|decoder| {
                Ok(StandardActorState {
                    record: super::ActorRecord {
                        entry: decode_entry(decoder)?,
                        producer: ProducerId(decoder.fixed()?),
                        package: decode_blob(decoder)?,
                        initial_state: decode_initial_state(decoder)?,
                        requirements: decode_requirements(decoder)?,
                    },
                    debt: decode_debt(decoder)?,
                    lane_state: decode_lane_state(decoder)?,
                })
            })?,
        };
        StandardAgentRuntime::restore(state.clone()).map_err(|_| DecodeError::NonCanonical)?;
        Ok(state)
    }
}

/// Apply one management call with the bundled deterministic runtime.
pub fn apply_standard(call: RuntimeCall) -> Result<RuntimeReturn, DecodeError> {
    let state = if call.state.is_empty() {
        StandardRuntimeState::default()
    } else {
        StandardRuntimeState::decode(&call.state)?
    };
    let mut runtime =
        StandardAgentRuntime::restore(state).map_err(|_| DecodeError::NonCanonical)?;
    let result = runtime.apply(call.request);
    Ok(RuntimeReturn {
        state: runtime.snapshot().encode(),
        result,
    })
}

/// Execute one actor call with the bundled runtime. Failed calls always return
/// the byte-identical prior runtime state.
#[cfg(feature = "pvm")]
pub fn apply_standard_execution(
    call: RuntimeExecutionCall,
) -> Result<RuntimeExecutionReturn, DecodeError> {
    let original_state = call.state;
    let state = StandardRuntimeState::decode(&original_state)?;
    let mut runtime =
        StandardAgentRuntime::restore(state).map_err(|_| DecodeError::NonCanonical)?;
    let result =
        runtime
            .prepare_execution_state(&call.invocation)
            .and_then(|(lane, actor_state)| {
                super::execution::run_inner_actor(&call.invocation, &actor_state).and_then(
                    |(reply, next_state)| {
                        if reply.status == ActorExecutionStatus::Done {
                            runtime.commit_execution_state(reply.actor, lane, next_state)?;
                        }
                        Ok(reply)
                    },
                )
            });
    let state = if result.is_ok() {
        runtime.snapshot().encode()
    } else {
        original_state
    };
    Ok(RuntimeExecutionReturn { state, result })
}

fn encode_actor_invocation(encoder: &mut Encoder<'_>, invocation: &ActorInvocation) {
    encoder.fixed(&invocation.invocation.0);
    encoder.fixed(&invocation.actor.0);
    encoder.fixed(&invocation.deployment.0);
    encoder.fixed(&invocation.program.0);
    encoder.u8(encode_method_mode(invocation.mode));
    encoder.bytes(&invocation.message);
    encoder.bytes(&invocation.actor_pvm);
    encoder.list(&invocation.availability, |encoder, blob| {
        encode_blob(encoder, &blob.reference);
        encoder.bytes(&blob.bytes);
    });
    encoder.u64(invocation.gas);
}

fn decode_actor_invocation(decoder: &mut Decoder<'_>) -> Result<ActorInvocation, DecodeError> {
    Ok(ActorInvocation {
        invocation: crate::service::InvocationId(decoder.fixed()?),
        actor: ActorId(decoder.fixed()?),
        deployment: DeploymentId(decoder.fixed()?),
        program: ProgramId(decoder.fixed()?),
        mode: decode_method_mode(decoder.u8()?)?,
        message: decoder.bytes()?,
        actor_pvm: decoder.bytes()?,
        availability: decoder.list(|decoder| {
            Ok(RuntimeBlob {
                reference: decode_blob(decoder)?,
                bytes: decoder.bytes()?,
            })
        })?,
        gas: decoder.u64()?,
    })
}

fn encode_execution_reply(encoder: &mut Encoder<'_>, reply: &ActorExecutionReply) {
    encoder.fixed(&reply.invocation.0);
    encoder.fixed(&reply.actor.0);
    encoder.fixed(&reply.deployment.0);
    encoder.u8(reply.lane as u8);
    encoder.u8(reply.status as u8);
    encoder.bytes(&reply.reply);
    encoder.u64(reply.gas_remaining);
}

fn decode_execution_reply(decoder: &mut Decoder<'_>) -> Result<ActorExecutionReply, DecodeError> {
    let reply = ActorExecutionReply {
        invocation: crate::service::InvocationId(decoder.fixed()?),
        actor: ActorId(decoder.fixed()?),
        deployment: DeploymentId(decoder.fixed()?),
        lane: decode_state_lane(decoder.u8()?)?,
        status: match decoder.u8()? {
            0 => ActorExecutionStatus::Done,
            1 => ActorExecutionStatus::Forbidden,
            2 => ActorExecutionStatus::Panicked,
            3 => ActorExecutionStatus::OutOfGas,
            _ => return Err(DecodeError::InvalidTag),
        },
        reply: decoder.bytes()?,
        gas_remaining: decoder.u64()?,
    };
    if reply.invocation == crate::service::InvocationId::ZERO
        || reply.actor == ActorId::ZERO
        || reply.deployment == DeploymentId::ZERO
        || reply.reply.len() > super::execution::MAX_EXECUTION_REPLY_BYTES
    {
        return Err(DecodeError::NonCanonical);
    }
    Ok(reply)
}

fn encode_execution_error(encoder: &mut Encoder<'_>, error: ActorExecutionError) {
    match error {
        ActorExecutionError::NotCreated => encoder.u8(0),
        ActorExecutionError::NotFound => encoder.u8(1),
        ActorExecutionError::Suspended => encoder.u8(2),
        ActorExecutionError::StaleDeployment => encoder.u8(3),
        ActorExecutionError::WrongProgram => encoder.u8(4),
        ActorExecutionError::UnsupportedMethod => encoder.u8(5),
        ActorExecutionError::MissingState => encoder.u8(6),
        ActorExecutionError::InvalidAvailability => encoder.u8(7),
        ActorExecutionError::InvalidInput => encoder.u8(8),
        ActorExecutionError::InvalidActorOutput => encoder.u8(9),
        ActorExecutionError::UnsupportedHostCall(id) => {
            encoder.u8(10);
            encoder.u32(id);
        }
    }
}

fn decode_execution_error(decoder: &mut Decoder<'_>) -> Result<ActorExecutionError, DecodeError> {
    Ok(match decoder.u8()? {
        0 => ActorExecutionError::NotCreated,
        1 => ActorExecutionError::NotFound,
        2 => ActorExecutionError::Suspended,
        3 => ActorExecutionError::StaleDeployment,
        4 => ActorExecutionError::WrongProgram,
        5 => ActorExecutionError::UnsupportedMethod,
        6 => ActorExecutionError::MissingState,
        7 => ActorExecutionError::InvalidAvailability,
        8 => ActorExecutionError::InvalidInput,
        9 => ActorExecutionError::InvalidActorOutput,
        10 => ActorExecutionError::UnsupportedHostCall(decoder.u32()?),
        _ => return Err(DecodeError::InvalidTag),
    })
}

const fn encode_method_mode(mode: MethodMode) -> u8 {
    match mode {
        MethodMode::Query => 0,
        MethodMode::LinearizableQuery => 1,
        MethodMode::Linear => 2,
        MethodMode::Merge => 3,
        MethodMode::Local => 4,
    }
}

fn decode_method_mode(value: u8) -> Result<MethodMode, DecodeError> {
    match value {
        0 => Ok(MethodMode::Query),
        1 => Ok(MethodMode::LinearizableQuery),
        2 => Ok(MethodMode::Linear),
        3 => Ok(MethodMode::Merge),
        4 => Ok(MethodMode::Local),
        _ => Err(DecodeError::InvalidTag),
    }
}

fn decode_state_lane(value: u8) -> Result<StateLane, DecodeError> {
    match value {
        0 => Ok(StateLane::Linear),
        1 => Ok(StateLane::Merge),
        2 => Ok(StateLane::Local),
        _ => Err(DecodeError::InvalidTag),
    }
}

fn encode_request(encoder: &mut Encoder<'_>, request: &LifecycleRequest) {
    match request {
        LifecycleRequest::Create(config) => {
            encoder.u8(0);
            encode_config(encoder, config);
        }
        LifecycleRequest::Inspect { after, limit } => {
            encoder.u8(1);
            encoder.option(after, |encoder, actor| encoder.fixed(&actor.0));
            encoder.u16(*limit);
        }
        LifecycleRequest::Install(install) => {
            encoder.u8(2);
            encode_entry(encoder, &install.entry);
            encoder.fixed(&install.producer.0);
            encode_blob(encoder, &install.package);
            encode_initial_state(encoder, &install.initial_state);
            encode_requirements(encoder, install.requirements);
        }
        LifecycleRequest::UpgradeActor(upgrade) => {
            encoder.u8(3);
            encoder.fixed(&upgrade.actor.0);
            encoder.fixed(&upgrade.from_deployment.0);
            encoder.fixed(&upgrade.to_deployment.0);
            encoder.fixed(&upgrade.to_program.0);
            encoder.fixed(&upgrade.producer.0);
            encode_blob(encoder, &upgrade.package);
            encode_requirements(encoder, upgrade.requirements);
        }
        LifecycleRequest::Suspend(actor) => {
            encoder.u8(4);
            encoder.fixed(&actor.0);
        }
        LifecycleRequest::Resume(actor) => {
            encoder.u8(5);
            encoder.fixed(&actor.0);
        }
        LifecycleRequest::RemoveLeaf {
            actor,
            expected_deployment,
        } => {
            encoder.u8(6);
            encoder.fixed(&actor.0);
            encoder.fixed(&expected_deployment.0);
        }
        LifecycleRequest::UpgradeRuntime {
            from_deployment,
            to_deployment,
            to_program,
            producer,
            package,
            abi,
            capabilities,
        } => {
            encoder.u8(7);
            encoder.fixed(&from_deployment.0);
            encoder.fixed(&to_deployment.0);
            encoder.fixed(&to_program.0);
            encoder.fixed(&producer.0);
            encode_blob(encoder, package);
            encoder.fixed(&abi.0);
            encode_capabilities(encoder, *capabilities);
        }
    }
}

fn decode_request(decoder: &mut Decoder<'_>) -> Result<LifecycleRequest, DecodeError> {
    match decoder.u8()? {
        0 => Ok(LifecycleRequest::Create(decode_config(decoder)?)),
        1 => Ok(LifecycleRequest::Inspect {
            after: decoder.option(|decoder| Ok(ActorId(decoder.fixed()?)))?,
            limit: decoder.u16()?,
        }),
        2 => Ok(LifecycleRequest::Install(super::InstallActor {
            entry: decode_entry(decoder)?,
            producer: ProducerId(decoder.fixed()?),
            package: decode_blob(decoder)?,
            initial_state: decode_initial_state(decoder)?,
            requirements: decode_requirements(decoder)?,
        })),
        3 => Ok(LifecycleRequest::UpgradeActor(super::UpgradeActor {
            actor: ActorId(decoder.fixed()?),
            from_deployment: DeploymentId(decoder.fixed()?),
            to_deployment: DeploymentId(decoder.fixed()?),
            to_program: ProgramId(decoder.fixed()?),
            producer: ProducerId(decoder.fixed()?),
            package: decode_blob(decoder)?,
            requirements: decode_requirements(decoder)?,
        })),
        4 => Ok(LifecycleRequest::Suspend(ActorId(decoder.fixed()?))),
        5 => Ok(LifecycleRequest::Resume(ActorId(decoder.fixed()?))),
        6 => Ok(LifecycleRequest::RemoveLeaf {
            actor: ActorId(decoder.fixed()?),
            expected_deployment: DeploymentId(decoder.fixed()?),
        }),
        7 => Ok(LifecycleRequest::UpgradeRuntime {
            from_deployment: DeploymentId(decoder.fixed()?),
            to_deployment: DeploymentId(decoder.fixed()?),
            to_program: ProgramId(decoder.fixed()?),
            producer: ProducerId(decoder.fixed()?),
            package: decode_blob(decoder)?,
            abi: Hash(decoder.fixed()?),
            capabilities: decode_capabilities(decoder)?,
        }),
        _ => Err(DecodeError::InvalidTag),
    }
}

fn encode_reply(encoder: &mut Encoder<'_>, reply: &LifecycleReply) {
    match reply {
        LifecycleReply::Created(identity) => {
            encoder.u8(0);
            encode_identity(encoder, identity);
        }
        LifecycleReply::Directory(page) => {
            encoder.u8(1);
            encode_directory_page(encoder, page);
        }
        LifecycleReply::Installed(entry) => {
            encoder.u8(2);
            encode_entry(encoder, entry);
        }
        LifecycleReply::Upgraded(entry) => {
            encoder.u8(3);
            encode_entry(encoder, entry);
        }
        LifecycleReply::Suspended(entry) => {
            encoder.u8(4);
            encode_entry(encoder, entry);
        }
        LifecycleReply::Resumed(entry) => {
            encoder.u8(5);
            encode_entry(encoder, entry);
        }
        LifecycleReply::Removed(actor) => {
            encoder.u8(6);
            encoder.fixed(&actor.0);
        }
        LifecycleReply::RuntimeUpgraded(identity) => {
            encoder.u8(7);
            encode_identity(encoder, identity);
        }
    }
}

fn decode_reply(decoder: &mut Decoder<'_>) -> Result<LifecycleReply, DecodeError> {
    match decoder.u8()? {
        0 => Ok(LifecycleReply::Created(decode_identity(decoder)?)),
        1 => Ok(LifecycleReply::Directory(decode_directory_page(decoder)?)),
        2 => Ok(LifecycleReply::Installed(decode_entry(decoder)?)),
        3 => Ok(LifecycleReply::Upgraded(decode_entry(decoder)?)),
        4 => Ok(LifecycleReply::Suspended(decode_entry(decoder)?)),
        5 => Ok(LifecycleReply::Resumed(decode_entry(decoder)?)),
        6 => Ok(LifecycleReply::Removed(ActorId(decoder.fixed()?))),
        7 => Ok(LifecycleReply::RuntimeUpgraded(decode_identity(decoder)?)),
        _ => Err(DecodeError::InvalidTag),
    }
}

fn encode_error(encoder: &mut Encoder<'_>, error: LifecycleError) {
    let tag = match error {
        LifecycleError::NotCreated => 0,
        LifecycleError::AlreadyCreated => 1,
        LifecycleError::NotFound => 2,
        LifecycleError::AlreadyExists => 3,
        LifecycleError::StaleDeployment => 4,
        LifecycleError::UnsupportedRuntime => 5,
        LifecycleError::UnsupportedLane => 6,
        LifecycleError::Busy(debt) => {
            encoder.u8(7);
            encode_debt(encoder, debt);
            return;
        }
        LifecycleError::DirectoryFull => 8,
        LifecycleError::InvalidRequest => 9,
    };
    encoder.u8(tag);
}

fn decode_error(decoder: &mut Decoder<'_>) -> Result<LifecycleError, DecodeError> {
    Ok(match decoder.u8()? {
        0 => LifecycleError::NotCreated,
        1 => LifecycleError::AlreadyCreated,
        2 => LifecycleError::NotFound,
        3 => LifecycleError::AlreadyExists,
        4 => LifecycleError::StaleDeployment,
        5 => LifecycleError::UnsupportedRuntime,
        6 => LifecycleError::UnsupportedLane,
        7 => LifecycleError::Busy(decode_debt(decoder)?),
        8 => LifecycleError::DirectoryFull,
        9 => LifecycleError::InvalidRequest,
        _ => return Err(DecodeError::InvalidTag),
    })
}

fn encode_config(encoder: &mut Encoder<'_>, config: &AgentConfig) {
    encode_identity(encoder, &config.identity);
    encode_blob(encoder, &config.runtime_package);
    encode_capabilities(encoder, config.capabilities);
    encoder.list(&config.replicas, |encoder, replica| {
        encoder.fixed(&replica.node.0);
        encoder.fixed(&replica.principal.0);
        encoder.u8(replica.role as u8);
    });
}

fn decode_config(decoder: &mut Decoder<'_>) -> Result<AgentConfig, DecodeError> {
    let config = AgentConfig {
        identity: decode_identity(decoder)?,
        runtime_package: decode_blob(decoder)?,
        capabilities: decode_capabilities(decoder)?,
        replicas: decoder.list(|decoder| {
            Ok(AgentReplica {
                node: NodeId(decoder.fixed()?),
                principal: PrincipalId(decoder.fixed()?),
                role: match decoder.u8()? {
                    0 => ReplicaRole::Voter,
                    1 => ReplicaRole::Observer,
                    _ => return Err(DecodeError::InvalidTag),
                },
            })
        })?,
    };
    config.validate().map_err(|_| DecodeError::NonCanonical)?;
    Ok(config)
}

fn encode_identity(encoder: &mut Encoder<'_>, identity: &AgentIdentity) {
    encoder.fixed(&identity.space.0);
    encoder.fixed(&identity.agent.0);
    encoder.fixed(&identity.owner.0);
    encoder.u8(identity.profile as u8);
    encoder.fixed(&identity.runtime_deployment.0);
    encoder.fixed(&identity.runtime_program.0);
    encoder.fixed(&identity.runtime_producer.0);
}

fn decode_identity(decoder: &mut Decoder<'_>) -> Result<AgentIdentity, DecodeError> {
    Ok(AgentIdentity {
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
        runtime_program: ProgramId(decoder.fixed()?),
        runtime_producer: ProducerId(decoder.fixed()?),
    })
}

fn encode_entry(encoder: &mut Encoder<'_>, entry: &ActorEntry) {
    encoder.fixed(&entry.actor.0);
    encoder.string(&entry.name);
    encoder.option(&entry.parent, |encoder, parent| encoder.fixed(&parent.0));
    encoder.fixed(&entry.deployment.0);
    encoder.fixed(&entry.program.0);
    encoder.u8(entry.lanes.bits());
    encoder.bool(entry.suspended);
}

fn decode_entry(decoder: &mut Decoder<'_>) -> Result<ActorEntry, DecodeError> {
    let entry = ActorEntry {
        actor: ActorId(decoder.fixed()?),
        name: decoder.string()?,
        parent: decoder.option(|decoder| Ok(ActorId(decoder.fixed()?)))?,
        deployment: DeploymentId(decoder.fixed()?),
        program: ProgramId(decoder.fixed()?),
        lanes: decode_lanes(decoder)?,
        suspended: decoder.bool()?,
    };
    if entry.name.is_empty() || entry.name.len() > crate::service::MAX_ACTOR_NAME_BYTES {
        return Err(DecodeError::NonCanonical);
    }
    Ok(entry)
}

fn encode_directory_page(encoder: &mut Encoder<'_>, page: &ActorDirectoryPage) {
    encoder.list(&page.entries, encode_entry);
    encoder.option(&page.next, |encoder, next| encoder.fixed(&next.0));
}

fn decode_directory_page(decoder: &mut Decoder<'_>) -> Result<ActorDirectoryPage, DecodeError> {
    let entries = decoder.list(decode_entry)?;
    if entries.len() > usize::from(super::standard::MAX_DIRECTORY_PAGE)
        || entries
            .windows(2)
            .any(|pair| pair[0].actor >= pair[1].actor)
    {
        return Err(DecodeError::NonCanonical);
    }
    let next = decoder.option(|decoder| Ok(ActorId(decoder.fixed()?)))?;
    if next.is_some() && next != entries.last().map(|entry| entry.actor) {
        return Err(DecodeError::NonCanonical);
    }
    Ok(ActorDirectoryPage { entries, next })
}

fn encode_initial_state(encoder: &mut Encoder<'_>, state: &ActorInitialState) {
    encoder.option(&state.linear, encode_blob);
    encoder.option(&state.merge, encode_blob);
    encoder.option(&state.local, encode_blob);
}

fn decode_initial_state(decoder: &mut Decoder<'_>) -> Result<ActorInitialState, DecodeError> {
    Ok(ActorInitialState {
        linear: decoder.option(decode_blob)?,
        merge: decoder.option(decode_blob)?,
        local: decoder.option(decode_blob)?,
    })
}

fn encode_lane_state(encoder: &mut Encoder<'_>, state: &StandardLaneState) {
    encoder.option(&state.linear, |encoder, bytes| encoder.bytes(bytes));
    encoder.option(&state.merge, |encoder, bytes| encoder.bytes(bytes));
    encoder.option(&state.local, |encoder, bytes| encoder.bytes(bytes));
}

fn decode_lane_state(decoder: &mut Decoder<'_>) -> Result<StandardLaneState, DecodeError> {
    let state = StandardLaneState {
        linear: decoder.option(Decoder::bytes)?,
        merge: decoder.option(Decoder::bytes)?,
        local: decoder.option(Decoder::bytes)?,
    };
    if [&state.linear, &state.merge, &state.local]
        .into_iter()
        .flatten()
        .any(|bytes| bytes.len() > super::execution::MAX_EXECUTION_STATE_BYTES)
    {
        return Err(DecodeError::NonCanonical);
    }
    Ok(state)
}

fn encode_blob(encoder: &mut Encoder<'_>, blob: &BlobRef) {
    encoder.fixed(&blob.hash.0);
    encoder.u64(blob.len);
}

fn decode_blob(decoder: &mut Decoder<'_>) -> Result<BlobRef, DecodeError> {
    Ok(BlobRef {
        hash: Hash(decoder.fixed()?),
        len: decoder.u64()?,
    })
}

fn encode_requirements(encoder: &mut Encoder<'_>, requirements: RuntimeRequirements) {
    encoder.u8(requirements.lanes.bits());
    encoder.bool(requirements.scheduling);
    encoder.bool(requirements.proofs);
}

fn decode_requirements(decoder: &mut Decoder<'_>) -> Result<RuntimeRequirements, DecodeError> {
    Ok(RuntimeRequirements {
        lanes: decode_lanes(decoder)?,
        scheduling: decoder.bool()?,
        proofs: decoder.bool()?,
    })
}

fn encode_capabilities(encoder: &mut Encoder<'_>, capabilities: RuntimeCapabilities) {
    encoder.u8(capabilities.lanes.bits());
    encoder.bool(capabilities.scheduling);
    encoder.bool(capabilities.proofs);
    encoder.u32(capabilities.max_actors);
}

fn decode_capabilities(decoder: &mut Decoder<'_>) -> Result<RuntimeCapabilities, DecodeError> {
    Ok(RuntimeCapabilities {
        lanes: decode_lanes(decoder)?,
        scheduling: decoder.bool()?,
        proofs: decoder.bool()?,
        max_actors: decoder.u32()?,
    })
}

fn decode_lanes(decoder: &mut Decoder<'_>) -> Result<LaneSet, DecodeError> {
    LaneSet::from_bits(decoder.u8()?).ok_or(DecodeError::NonCanonical)
}

fn encode_debt(encoder: &mut Encoder<'_>, debt: ActorLifecycleDebt) {
    encoder.u32(debt.children);
    encoder.u32(debt.continuations);
    encoder.u32(debt.inbox);
    encoder.u32(debt.outbox);
    encoder.u32(debt.schedules);
    encoder.u32(debt.proof_artifacts);
    encoder.u32(debt.lifecycle_operations);
}

fn decode_debt(decoder: &mut Decoder<'_>) -> Result<ActorLifecycleDebt, DecodeError> {
    Ok(ActorLifecycleDebt {
        children: decoder.u32()?,
        continuations: decoder.u32()?,
        inbox: decoder.u32()?,
        outbox: decoder.u32()?,
        schedules: decoder.u32()?,
        proof_artifacts: decoder.u32()?,
        lifecycle_operations: decoder.u32()?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn config() -> AgentConfig {
        let owner = PrincipalId([1; 32]);
        AgentConfig {
            identity: AgentIdentity {
                space: SpaceId([2; 32]),
                agent: AgentId([3; 32]),
                owner,
                profile: AgentProfile::Shared,
                runtime_deployment: DeploymentId([4; 32]),
                runtime_program: ProgramId([5; 32]),
                runtime_producer: ProducerId([6; 32]),
            },
            runtime_package: BlobRef {
                hash: Hash([7; 32]),
                len: 100,
            },
            capabilities: RuntimeCapabilities::standard(),
            replicas: vec![
                AgentReplica {
                    node: NodeId([8; 32]),
                    principal: owner,
                    role: ReplicaRole::Voter,
                },
                AgentReplica {
                    node: NodeId([9; 32]),
                    principal: PrincipalId([10; 32]),
                    role: ReplicaRole::Observer,
                },
            ],
        }
    }

    #[test]
    fn lifecycle_call_round_trips_with_opaque_runtime_state() {
        let call = RuntimeCall {
            state: vec![11, 12, 13],
            request: LifecycleRequest::Create(config()),
        };
        let encoded = call.encode();
        assert_eq!(RuntimeCall::decode(&encoded).unwrap(), call);
    }

    #[test]
    fn actor_execution_call_round_trips_with_content_addressed_inputs() {
        let actor_pvm = vec![0x21, 0x22, 0x23];
        let state = vec![0x31, 0x32];
        let call = RuntimeExecutionCall {
            state: vec![0x11, 0x12],
            invocation: ActorInvocation {
                invocation: crate::service::InvocationId([1; 32]),
                actor: ActorId([2; 32]),
                deployment: DeploymentId([3; 32]),
                program: ProgramId::of_pvm(&actor_pvm),
                mode: MethodMode::Linear,
                message: vec![0x41],
                actor_pvm,
                availability: vec![RuntimeBlob {
                    reference: BlobRef::of_bytes(&state),
                    bytes: state,
                }],
                gas: 1_000_000,
            },
        };
        assert_eq!(RuntimeExecutionCall::decode(&call.encode()).unwrap(), call);
    }

    #[test]
    fn busy_reply_preserves_every_removal_blocker() {
        let debt = ActorLifecycleDebt {
            children: 1,
            continuations: 2,
            inbox: 3,
            outbox: 4,
            schedules: 5,
            proof_artifacts: 6,
            lifecycle_operations: 7,
        };
        let output = RuntimeReturn {
            state: vec![8],
            result: Err(LifecycleError::Busy(debt)),
        };
        assert_eq!(RuntimeReturn::decode(&output.encode()).unwrap(), output);
    }

    #[test]
    fn unsorted_replica_configuration_is_noncanonical() {
        let mut call = RuntimeCall {
            state: Vec::new(),
            request: LifecycleRequest::Create(config()),
        };
        let LifecycleRequest::Create(config) = &mut call.request else {
            unreachable!()
        };
        config.replicas.swap(0, 1);
        assert_eq!(
            RuntimeCall::decode(&call.encode()),
            Err(DecodeError::NonCanonical)
        );
    }

    #[test]
    fn standard_runtime_state_survives_independent_calls() {
        let created = apply_standard(RuntimeCall {
            state: Vec::new(),
            request: LifecycleRequest::Create(config()),
        })
        .unwrap();
        assert!(matches!(created.result, Ok(LifecycleReply::Created(_))));
        let inspected = apply_standard(RuntimeCall {
            state: created.state,
            request: LifecycleRequest::Inspect {
                after: None,
                limit: 16,
            },
        })
        .unwrap();
        assert_eq!(
            inspected.result,
            Ok(LifecycleReply::Directory(ActorDirectoryPage {
                entries: Vec::new(),
                next: None,
            }))
        );
    }
}
