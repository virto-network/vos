//! Stable management ABI between a node and an agent-runtime PVM.

use alloc::vec::Vec;

use super::AgentRuntime;
use super::standard::{StandardActorState, StandardAgentRuntime, StandardRuntimeState};
use super::{
    ActorDirectoryPage, ActorEntry, ActorInitialState, ActorLifecycleDebt, AgentConfig,
    AgentIdentity, AgentProfile, AgentReplica, LaneSet, LifecycleError, LifecycleReply,
    LifecycleRequest, ReplicaRole, RuntimeCapabilities, RuntimeRequirements,
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
