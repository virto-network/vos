//! Stable management ABI between a node and an agent-runtime PVM.

use alloc::{boxed::Box, vec::Vec};

use super::AgentRuntime;
use super::execution::{
    ActorExecutionError, ActorExecutionReply, ActorExecutionStatus, ActorInvocation,
    ActorInvocationAuth, RuntimeBlob, RuntimeExecutionCall, RuntimeExecutionReturn,
};
use super::standard::{
    StandardActorState, StandardAgentRuntime, StandardAuthorityDisposition,
    StandardInvocationResult, StandardLaneState, StandardRuntimeState,
};
use super::{
    ActorDirectoryPage, ActorEntry, ActorLifecycleDebt, AgentConfig, AgentIdentity, AgentProfile,
    AgentReplica, LaneSet, LifecycleError, LifecycleReply, LifecycleRequest, MethodMode,
    ReplicaRole, RuntimeCapabilities, RuntimeRequirements, StateLane,
};
use crate::service::wire::{DecodeError, Decoder, Encoder, ServiceWire};
use crate::service::{
    ActorId, AgentId, BlobRef, CapabilityId, DeploymentId, Hash, NodeId, PrincipalId, ProducerId,
    ProgramId, SpaceId,
};

/// One management call. Runtime-owned state is opaque to the node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeCall {
    pub state: RuntimeState,
    pub request: LifecycleRequest,
}

/// Private runtime-to-actor dispatch control. Unlike the dynamic application
/// message, these bytes are constructed only after the runtime has validated
/// the signed method schema and authenticated invocation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ActorDispatchControl {
    pub invocation: crate::service::InvocationId,
    pub actor: ActorId,
    pub mode: MethodMode,
    pub auth: ActorInvocationAuth,
}

impl ServiceWire for ActorDispatchControl {
    const MAGIC: [u8; 4] = *b"AGDC";

    fn encode_body(&self, output: &mut Vec<u8>) {
        let mut encoder = Encoder(output);
        encoder.fixed(&super::RUNTIME_ABI_ID.0);
        encoder.fixed(&self.invocation.0);
        encoder.fixed(&self.actor.0);
        encoder.u8(encode_method_mode(self.mode));
        encode_invocation_auth(&mut encoder, &self.auth);
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        if Hash(decoder.fixed()?) != super::RUNTIME_ABI_ID {
            return Err(DecodeError::InvalidPlatform);
        }
        let value = Self {
            invocation: crate::service::InvocationId(decoder.fixed()?),
            actor: ActorId(decoder.fixed()?),
            mode: decode_method_mode(decoder.u8()?)?,
            auth: decode_invocation_auth(decoder)?,
        };
        if value.invocation == crate::service::InvocationId::ZERO
            || value.actor == ActorId::ZERO
            || !value.auth.validate()
        {
            return Err(DecodeError::NonCanonical);
        }
        Ok(value)
    }
}

/// Runtime-owned state split only at the replication boundary. The node does
/// not interpret any component, but can order and persist each component with
/// the consistency semantics promised by its lane.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RuntimeState {
    pub control: Vec<u8>,
    pub linear: Vec<u8>,
    pub merge: Vec<u8>,
    pub local: Vec<u8>,
}

/// Deterministic result of one management call.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeReturn {
    pub state: RuntimeState,
    pub result: Result<LifecycleReply, LifecycleError>,
}

impl ServiceWire for RuntimeCall {
    const MAGIC: [u8; 4] = *b"AGRT";

    fn encode_body(&self, output: &mut Vec<u8>) {
        let mut encoder = Encoder(output);
        encoder.fixed(&super::RUNTIME_ABI_ID.0);
        encode_runtime_state(&mut encoder, &self.state);
        encode_request(&mut encoder, &self.request);
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        if Hash(decoder.fixed()?) != super::RUNTIME_ABI_ID {
            return Err(DecodeError::InvalidPlatform);
        }
        Ok(Self {
            state: decode_runtime_state(decoder)?,
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
        encode_runtime_state(&mut encoder, &self.state);
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
        let state = decode_runtime_state(decoder)?;
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
        encode_runtime_state(&mut encoder, &self.state);
        encode_actor_invocation(&mut encoder, &self.invocation);
        encoder.bytes(&self.authority.encode());
        encoder.u64(self.observed_slot);
        encoder.bool(self.recovery_only);
        encoder.bytes(&self.actor_pvm);
        encode_blob(&mut encoder, &self.actor_schema.reference);
        encoder.bytes(&self.actor_schema.bytes);
        encode_blob(&mut encoder, &self.actor_policies.reference);
        encoder.bytes(&self.actor_policies.bytes);
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        if Hash(decoder.fixed()?) != super::RUNTIME_ABI_ID {
            return Err(DecodeError::InvalidPlatform);
        }
        let call = Self {
            state: decode_runtime_state(decoder)?,
            invocation: decode_actor_invocation(decoder)?,
            authority: super::authority::ActorInvocationReceipt::decode(&decoder.bytes()?)?,
            observed_slot: decoder.u64()?,
            recovery_only: decoder.bool()?,
            actor_pvm: {
                // Borrow first so the protocol limit remains at the allocation
                // boundary and oversized guest input is never copied.
                let bytes = decoder.bytes_ref()?;
                if bytes.len() > super::execution::MAX_EXECUTION_PROGRAM_BYTES {
                    return Err(DecodeError::LimitExceeded);
                }
                bytes.to_vec()
            },
            actor_schema: RuntimeBlob {
                reference: decode_blob(decoder)?,
                bytes: {
                    let bytes = decoder.bytes_ref()?;
                    if bytes.len() > super::schema::MAX_ENCODED_BYTES {
                        return Err(DecodeError::LimitExceeded);
                    }
                    bytes.to_vec()
                },
            },
            actor_policies: RuntimeBlob {
                reference: decode_blob(decoder)?,
                bytes: {
                    let bytes = decoder.bytes_ref()?;
                    if bytes.len() > super::execution::MAX_EXECUTION_POLICY_BYTES {
                        return Err(DecodeError::LimitExceeded);
                    }
                    bytes.to_vec()
                },
            },
        };
        call.invocation
            .validate()
            .map_err(|_| DecodeError::NonCanonical)?;
        let artifacts_absent = call.actor_pvm.is_empty()
            && call.actor_schema.reference.hash == Hash::ZERO
            && call.actor_schema.reference.len == 0
            && call.actor_schema.bytes.is_empty()
            && call.actor_policies.reference.hash == Hash::ZERO
            && call.actor_policies.reference.len == 0
            && call.actor_policies.bytes.is_empty();
        let artifacts_valid = !call.actor_pvm.is_empty()
            && call.actor_pvm.len() <= super::execution::MAX_EXECUTION_PROGRAM_BYTES
            && ProgramId::of_pvm(&call.actor_pvm) == call.invocation.program
            && call
                .actor_schema
                .reference
                .matches(&call.actor_schema.bytes)
            && super::schema::decode(&call.actor_schema.bytes).is_some()
            && call
                .actor_policies
                .reference
                .matches(&call.actor_policies.bytes)
            && crate::service::PackageRolePolicies::decode(&call.actor_policies.bytes).is_ok();
        if (call.recovery_only && !artifacts_absent) || (!call.recovery_only && !artifacts_valid) {
            return Err(DecodeError::NonCanonical);
        }
        Ok(call)
    }
}

impl ServiceWire for RuntimeExecutionReturn {
    const MAGIC: [u8; 4] = *b"AGER";

    fn encode_body(&self, output: &mut Vec<u8>) {
        let mut encoder = Encoder(output);
        encoder.fixed(&super::RUNTIME_ABI_ID.0);
        encode_runtime_state(&mut encoder, &self.state);
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
        let state = decode_runtime_state(decoder)?;
        let result = if decoder.bool()? {
            Ok(decode_execution_reply(decoder)?)
        } else {
            Err(decode_execution_error(decoder)?)
        };
        Ok(Self { state, result })
    }
}

impl RuntimeState {
    pub fn is_empty(&self) -> bool {
        self.control.is_empty()
            && self.linear.is_empty()
            && self.merge.is_empty()
            && self.local.is_empty()
    }

    pub fn component(&self, lane: StateLane) -> &[u8] {
        match lane {
            StateLane::Linear => &self.linear,
            StateLane::Merge => &self.merge,
            StateLane::Local => &self.local,
        }
    }

    /// Checked aggregate bytes owned by the opaque runtime image.
    pub fn encoded_len(&self) -> Option<usize> {
        self.control
            .len()
            .checked_add(self.linear.len())?
            .checked_add(self.merge.len())?
            .checked_add(self.local.len())
    }
}

/// Encode the standard runtime's policy state and three actor-state lanes as
/// independently durable opaque components.
pub fn encode_standard_runtime_state(state: &StandardRuntimeState) -> RuntimeState {
    let mut control = Vec::new();
    let mut encoder = Encoder(&mut control);
    encoder.fixed(&super::RUNTIME_ABI_ID.0);
    encoder.option(&state.config, encode_config);
    encoder.list(&state.actors, |encoder, actor| {
        encode_entry(encoder, &actor.record.entry);
        encoder.fixed(&actor.record.producer.0);
        encode_blob(encoder, &actor.record.package);
        encode_blob(encoder, &actor.record.agent_schema);
        encode_blob(encoder, &actor.record.role_policies);
        encoder.fixed(&actor.record.state_layout.0);
        super::contract::encode_actor_contract(encoder, actor.record.contract);
        encode_requirements(encoder, actor.record.requirements);
        encode_debt(encoder, actor.debt);
    });
    encoder.option(&state.authority_slot_high_water, |encoder, slot| {
        encoder.u64(*slot)
    });
    encoder.option(&state.authority_sequence_high_water, |encoder, sequence| {
        encoder.u64(*sequence)
    });
    encoder.list(&state.authority_dispositions, |encoder, disposition| {
        encoder.fixed(&disposition.credential.0);
        encoder.u64(disposition.sequence);
        encoder.fixed(&disposition.claim.0);
        encoder.fixed(&disposition.operation.0);
        match &disposition.result {
            Ok(reply) => {
                encoder.bool(true);
                encode_reply(encoder, reply);
            }
            Err(error) => {
                encoder.bool(false);
                encode_error(encoder, *error);
            }
        }
    });
    encoder.option(&state.control_authority_slot, |encoder, slot| {
        encoder.u64(*slot)
    });
    encoder.list(
        &state
            .invocation_results
            .iter()
            .filter(|result| result.storage == super::InvocationResultStorage::Control)
            .collect::<Vec<_>>(),
        |encoder, result| {
            encoder.fixed(&result.invocation.0);
            encoder.fixed(&result.request.0);
            encode_execution_reply(encoder, &result.reply);
        },
    );
    RuntimeState {
        control,
        linear: encode_standard_lane(state, StateLane::Linear),
        merge: encode_standard_lane(state, StateLane::Merge),
        local: encode_standard_lane(state, StateLane::Local),
    }
}

/// Decode all opaque standard-runtime components and enforce that their actor
/// keysets agree exactly with the control directory.
pub fn decode_standard_runtime_state(
    state: &RuntimeState,
) -> Result<StandardRuntimeState, DecodeError> {
    if state.is_empty() {
        return Ok(StandardRuntimeState::default());
    }
    if state.control.is_empty()
        || state.linear.is_empty()
        || state.merge.is_empty()
        || state.local.is_empty()
    {
        return Err(DecodeError::NonCanonical);
    }
    let mut decoder = Decoder::new(&state.control);
    if Hash(decoder.fixed()?) != super::RUNTIME_ABI_ID {
        return Err(DecodeError::InvalidPlatform);
    }
    let config = decoder.option(decode_config)?;
    let mut actors = decoder.list(|decoder| {
        Ok(StandardActorState {
            record: super::ActorRecord {
                entry: decode_entry(decoder)?,
                producer: ProducerId(decoder.fixed()?),
                package: decode_blob(decoder)?,
                agent_schema: decode_blob(decoder)?,
                role_policies: decode_blob(decoder)?,
                state_layout: Hash(decoder.fixed()?),
                contract: super::contract::decode_actor_contract(decoder)?,
                requirements: decode_requirements(decoder)?,
            },
            debt: decode_debt(decoder)?,
            lane_state: StandardLaneState::default(),
        })
    })?;
    let authority_slot_high_water = decoder.option(|decoder| decoder.u64())?;
    let authority_sequence_high_water = decoder.option(|decoder| decoder.u64())?;
    let authority_dispositions = decoder.list(|decoder| {
        Ok(StandardAuthorityDisposition {
            credential: crate::service::CredentialId(decoder.fixed()?),
            sequence: decoder.u64()?,
            claim: Hash(decoder.fixed()?),
            operation: Hash(decoder.fixed()?),
            result: if decoder.bool()? {
                Ok(decode_reply(decoder)?)
            } else {
                Err(decode_error(decoder)?)
            },
        })
    })?;
    let control_authority_slot = decoder.option(Decoder::u64)?;
    let mut invocation_results = decoder.list(|decoder| {
        let invocation = crate::service::InvocationId(decoder.fixed()?);
        let request = Hash(decoder.fixed()?);
        let reply = decode_execution_reply(decoder)?;
        if invocation == crate::service::InvocationId::ZERO
            || request == Hash::ZERO
            || reply.invocation != invocation
            || reply.mode.result_storage() != super::InvocationResultStorage::Control
        {
            return Err(DecodeError::NonCanonical);
        }
        Ok(StandardInvocationResult {
            invocation,
            request,
            reply,
            storage: super::InvocationResultStorage::Control,
        })
    })?;
    if invocation_results
        .windows(2)
        .any(|pair| pair[0].invocation >= pair[1].invocation)
    {
        return Err(DecodeError::NonCanonical);
    }
    if !decoder.exhausted() {
        return Err(DecodeError::TrailingBytes);
    }
    let mut lane_revisions = super::standard::StandardLaneRevisions::default();
    for (lane, bytes) in [
        (StateLane::Linear, state.linear.as_slice()),
        (StateLane::Merge, state.merge.as_slice()),
        (StateLane::Local, state.local.as_slice()),
    ] {
        let decoded = decode_standard_lane(bytes, lane)?;
        match lane {
            StateLane::Linear => {
                lane_revisions.linear = decoded.revision;
                lane_revisions.linear_authority_slot = decoded.authority_slot;
            }
            StateLane::Merge => {
                lane_revisions.merge = decoded.revision;
                lane_revisions.merge_authority_slot = decoded.authority_slot;
            }
            StateLane::Local => {
                lane_revisions.local = decoded.revision;
                lane_revisions.local_authority_slot = decoded.authority_slot;
            }
        }
        if decoded.values.len() != actors.len() {
            return Err(DecodeError::NonCanonical);
        }
        for (actor, (id, value)) in actors.iter_mut().zip(decoded.values) {
            if actor.record.entry.actor != id {
                return Err(DecodeError::NonCanonical);
            }
            match lane {
                StateLane::Linear => actor.lane_state.linear = value,
                StateLane::Merge => actor.lane_state.merge = value,
                StateLane::Local => actor.lane_state.local = value,
            }
        }
        invocation_results.extend(decoded.invocation_results);
    }
    invocation_results.sort_unstable_by_key(|result| result.invocation);
    if invocation_results
        .windows(2)
        .any(|pair| pair[0].invocation >= pair[1].invocation)
    {
        return Err(DecodeError::NonCanonical);
    }
    let state = StandardRuntimeState {
        config,
        actors,
        invocation_results,
        lane_revisions,
        control_authority_slot,
        authority_slot_high_water,
        authority_sequence_high_water,
        authority_dispositions,
    };
    StandardAgentRuntime::restore(state.clone()).map_err(|_| DecodeError::NonCanonical)?;
    Ok(state)
}

fn encode_standard_lane(state: &StandardRuntimeState, lane: StateLane) -> Vec<u8> {
    let mut output = Vec::new();
    let mut encoder = Encoder(&mut output);
    encoder.fixed(&super::RUNTIME_ABI_ID.0);
    encoder.u8(lane as u8);
    encoder.u64(match lane {
        StateLane::Linear => state.lane_revisions.linear,
        StateLane::Merge => state.lane_revisions.merge,
        StateLane::Local => state.lane_revisions.local,
    });
    encoder.option(
        &match lane {
            StateLane::Linear => state.lane_revisions.linear_authority_slot,
            StateLane::Merge => state.lane_revisions.merge_authority_slot,
            StateLane::Local => state.lane_revisions.local_authority_slot,
        },
        |encoder, slot| encoder.u64(*slot),
    );
    encoder.list(&state.actors, |encoder, actor| {
        encoder.fixed(&actor.record.entry.actor.0);
        let value = match lane {
            StateLane::Linear => &actor.lane_state.linear,
            StateLane::Merge => &actor.lane_state.merge,
            StateLane::Local => &actor.lane_state.local,
        };
        encoder.option(value, |encoder, bytes| encoder.bytes(bytes));
    });
    encoder.list(
        &state
            .invocation_results
            .iter()
            .filter(|result| result.storage == super::InvocationResultStorage::Lane(lane))
            .collect::<Vec<_>>(),
        |encoder, result| {
            encoder.fixed(&result.invocation.0);
            encoder.fixed(&result.request.0);
            encode_execution_reply(encoder, &result.reply);
        },
    );
    output
}

struct DecodedStandardLane {
    revision: u64,
    authority_slot: Option<u64>,
    values: Vec<(ActorId, Option<Vec<u8>>)>,
    invocation_results: Vec<StandardInvocationResult>,
}

fn decode_standard_lane(
    bytes: &[u8],
    expected_lane: StateLane,
) -> Result<DecodedStandardLane, DecodeError> {
    let mut decoder = Decoder::new(bytes);
    if Hash(decoder.fixed()?) != super::RUNTIME_ABI_ID
        || decode_state_lane(decoder.u8()?)? != expected_lane
    {
        return Err(DecodeError::InvalidPlatform);
    }
    let revision = decoder.u64()?;
    let authority_slot = decoder.option(Decoder::u64)?;
    let values = decoder.list(|decoder| {
        let actor = ActorId(decoder.fixed()?);
        let value = decoder.option(|decoder| {
            let bytes = decoder.bytes_ref()?;
            if bytes.len() > super::execution::MAX_EXECUTION_STATE_BYTES {
                return Err(DecodeError::LimitExceeded);
            }
            Ok(bytes.to_vec())
        })?;
        if actor == ActorId::ZERO
            || value
                .as_ref()
                .is_some_and(|bytes| bytes.len() > super::execution::MAX_EXECUTION_STATE_BYTES)
        {
            return Err(DecodeError::NonCanonical);
        }
        Ok((actor, value))
    })?;
    if values.windows(2).any(|pair| pair[0].0 >= pair[1].0) {
        return Err(DecodeError::NonCanonical);
    }
    let invocation_results = decoder.list(|decoder| {
        let invocation = crate::service::InvocationId(decoder.fixed()?);
        let request = Hash(decoder.fixed()?);
        let reply = decode_execution_reply(decoder)?;
        if invocation == crate::service::InvocationId::ZERO
            || request == Hash::ZERO
            || reply.invocation != invocation
            || reply.mode.result_storage() != super::InvocationResultStorage::Lane(expected_lane)
        {
            return Err(DecodeError::NonCanonical);
        }
        Ok(StandardInvocationResult {
            invocation,
            request,
            reply,
            storage: super::InvocationResultStorage::Lane(expected_lane),
        })
    })?;
    if invocation_results
        .windows(2)
        .any(|pair| pair[0].invocation >= pair[1].invocation)
        || !decoder.exhausted()
    {
        return Err(DecodeError::NonCanonical);
    }
    Ok(DecodedStandardLane {
        revision,
        authority_slot,
        values,
        invocation_results,
    })
}

/// Apply one management call with the bundled deterministic runtime.
pub fn apply_standard(call: RuntimeCall) -> Result<RuntimeReturn, DecodeError> {
    let state = decode_standard_runtime_state(&call.state)?;
    let mut runtime =
        StandardAgentRuntime::restore(state).map_err(|_| DecodeError::NonCanonical)?;
    let result = runtime.apply(call.request);
    Ok(RuntimeReturn {
        state: encode_standard_runtime_state(&runtime.snapshot()),
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
    let state = decode_standard_runtime_state(&original_state)?;
    let mut runtime =
        StandardAgentRuntime::restore(state).map_err(|_| DecodeError::NonCanonical)?;
    let authority = runtime.verify_invocation_authority(&call.invocation, &call.authority);
    let mut result = match authority {
        Err(error) => Err(error),
        Ok(()) => match runtime.recover_execution(&call.invocation, call.observed_slot) {
            Ok(Some(reply)) => Ok(reply),
            Err(error) => Err(error),
            Ok(None) if call.recovery_only => Err(ActorExecutionError::InvalidAvailability),
            Ok(None) => match runtime
                .validate_execution_schema(&call.invocation, &call.actor_schema)
                .and_then(|()| runtime.authorize_execution(&call.invocation, &call.actor_policies))
            {
                Err(error) => Err(error),
                Ok(false) => Ok(ActorExecutionReply {
                    invocation: call.invocation.invocation,
                    actor: call.invocation.actor,
                    deployment: call.invocation.deployment,
                    mode: call.invocation.mode,
                    lane: call.invocation.mode.write_lane(),
                    status: ActorExecutionStatus::Forbidden,
                    reply: Vec::new(),
                    gas_remaining: call.invocation.gas,
                    observation: super::execution::ActorObservation::default(),
                }),
                Ok(true) => runtime
                    .validate_unseen_invocation_slot(
                        &call.invocation,
                        &call.authority,
                        call.observed_slot,
                    )
                    .and_then(|()| runtime.prepare_execution_state(&call.invocation))
                    .and_then(|before| {
                        let actor_state = before.visible_for(call.invocation.mode);
                        super::execution::run_inner_actor(
                            &call.invocation,
                            &call.actor_pvm,
                            &actor_state,
                        )
                        .and_then(|(mut reply, next_state)| {
                            if reply.status == ActorExecutionStatus::Done {
                                runtime.commit_execution(
                                    &call.invocation,
                                    &mut reply,
                                    &before,
                                    next_state,
                                    call.observed_slot,
                                )?;
                            }
                            Ok(reply)
                        })
                    }),
            },
        },
    };
    let state = if result.is_ok() {
        let candidate = encode_standard_runtime_state(&runtime.snapshot());
        if candidate
            .encoded_len()
            .is_none_or(|len| len > super::execution::MAX_RUNTIME_STATE_BYTES)
        {
            result = Err(ActorExecutionError::ResultCapacity);
            original_state
        } else {
            candidate
        }
    } else {
        original_state
    };
    Ok(RuntimeExecutionReturn { state, result })
}

fn encode_runtime_state(encoder: &mut Encoder<'_>, state: &RuntimeState) {
    encoder.bytes(&state.control);
    encoder.bytes(&state.linear);
    encoder.bytes(&state.merge);
    encoder.bytes(&state.local);
}

fn decode_runtime_state(decoder: &mut Decoder<'_>) -> Result<RuntimeState, DecodeError> {
    let mut remaining = super::execution::MAX_RUNTIME_STATE_BYTES;
    let control = decoder.bytes_ref()?;
    if control.len() > remaining {
        return Err(DecodeError::LimitExceeded);
    }
    let control = control.to_vec();
    remaining -= control.len();
    let linear = decoder.bytes_ref()?;
    if linear.len() > remaining {
        return Err(DecodeError::LimitExceeded);
    }
    let linear = linear.to_vec();
    remaining -= linear.len();
    let merge = decoder.bytes_ref()?;
    if merge.len() > remaining {
        return Err(DecodeError::LimitExceeded);
    }
    let merge = merge.to_vec();
    remaining -= merge.len();
    let local = decoder.bytes_ref()?;
    if local.len() > remaining {
        return Err(DecodeError::LimitExceeded);
    }
    let local = local.to_vec();
    Ok(RuntimeState {
        control,
        linear,
        merge,
        local,
    })
}

fn encode_actor_invocation(encoder: &mut Encoder<'_>, invocation: &ActorInvocation) {
    encoder.fixed(&invocation.invocation.0);
    encoder.fixed(&invocation.actor.0);
    encoder.fixed(&invocation.deployment.0);
    encoder.fixed(&invocation.program.0);
    encoder.u8(encode_method_mode(invocation.mode));
    encode_invocation_auth(encoder, &invocation.auth);
    encoder.bytes(&invocation.message);
    encoder.list(&invocation.availability, |encoder, blob| {
        encode_blob(encoder, &blob.reference);
        encoder.bytes(&blob.bytes);
    });
    encoder.u64(invocation.gas);
}

fn decode_actor_invocation(decoder: &mut Decoder<'_>) -> Result<ActorInvocation, DecodeError> {
    let invocation = crate::service::InvocationId(decoder.fixed()?);
    let actor = ActorId(decoder.fixed()?);
    let deployment = DeploymentId(decoder.fixed()?);
    let program = ProgramId(decoder.fixed()?);
    let mode = decode_method_mode(decoder.u8()?)?;
    let auth = decode_invocation_auth(decoder)?;
    let message = {
        let bytes = decoder.bytes_ref()?;
        if bytes.len() > super::execution::MAX_EXECUTION_MESSAGE_BYTES {
            return Err(DecodeError::LimitExceeded);
        }
        bytes.to_vec()
    };
    let mut availability_remaining = super::execution::MAX_EXECUTION_AVAILABILITY_BYTES;
    let availability = decoder.list(|decoder| {
        let reference = decode_blob(decoder)?;
        let bytes = decoder.bytes_ref()?;
        if bytes.len() > availability_remaining {
            return Err(DecodeError::LimitExceeded);
        }
        availability_remaining -= bytes.len();
        Ok(RuntimeBlob {
            reference,
            bytes: bytes.to_vec(),
        })
    })?;
    Ok(ActorInvocation {
        invocation,
        actor,
        deployment,
        program,
        mode,
        auth,
        message,
        availability,
        gas: decoder.u64()?,
    })
}

fn encode_invocation_auth(encoder: &mut Encoder<'_>, auth: &ActorInvocationAuth) {
    crate::service::encode_origin(encoder, auth.origin);
    encoder.option(&auth.principal, |encoder, principal| {
        encoder.fixed(&principal.0)
    });
    encoder.option(&auth.origin_service, crate::service::encode_service);
    encoder.option(&auth.space_role, |encoder, role| encoder.u8(*role));
    encoder.option(&auth.actor_role, |encoder, role| encoder.u8(*role));
    encoder.option(&auth.capability, |encoder, capability| {
        encoder.fixed(&capability.0)
    });
}

fn decode_invocation_auth(decoder: &mut Decoder<'_>) -> Result<ActorInvocationAuth, DecodeError> {
    let auth = ActorInvocationAuth {
        origin: crate::service::decode_origin(decoder)?,
        principal: decoder.option(|decoder| Ok(crate::service::PrincipalId(decoder.fixed()?)))?,
        origin_service: decoder.option(crate::service::decode_service)?,
        space_role: decoder.option(Decoder::u8)?,
        actor_role: decoder.option(Decoder::u8)?,
        capability: decoder.option(|decoder| Ok(CapabilityId(decoder.fixed()?)))?,
    };
    auth.validate()
        .then_some(auth)
        .ok_or(DecodeError::NonCanonical)
}

fn encode_execution_reply(encoder: &mut Encoder<'_>, reply: &ActorExecutionReply) {
    encoder.fixed(&reply.invocation.0);
    encoder.fixed(&reply.actor.0);
    encoder.fixed(&reply.deployment.0);
    encoder.u8(encode_method_mode(reply.mode));
    encoder.option(&reply.lane, |encoder, lane| encoder.u8(*lane as u8));
    encoder.u8(reply.status as u8);
    encoder.bytes(&reply.reply);
    encoder.u64(reply.gas_remaining);
    encoder.option(&reply.observation.linear_revision, |encoder, revision| {
        encoder.u64(*revision)
    });
    encoder.option(&reply.observation.merge_frontier, |encoder, frontier| {
        encoder.fixed(&frontier.0)
    });
    encoder.option(&reply.observation.local_revision, |encoder, revision| {
        encoder.u64(*revision)
    });
}

fn decode_execution_reply(decoder: &mut Decoder<'_>) -> Result<ActorExecutionReply, DecodeError> {
    let reply = ActorExecutionReply {
        invocation: crate::service::InvocationId(decoder.fixed()?),
        actor: ActorId(decoder.fixed()?),
        deployment: DeploymentId(decoder.fixed()?),
        mode: decode_method_mode(decoder.u8()?)?,
        lane: decoder.option(|decoder| decode_state_lane(decoder.u8()?))?,
        status: match decoder.u8()? {
            0 => ActorExecutionStatus::Done,
            1 => ActorExecutionStatus::Forbidden,
            2 => ActorExecutionStatus::Panicked,
            3 => ActorExecutionStatus::OutOfGas,
            _ => return Err(DecodeError::InvalidTag),
        },
        reply: {
            let bytes = decoder.bytes_ref()?;
            if bytes.len() > super::execution::MAX_EXECUTION_REPLY_BYTES {
                return Err(DecodeError::LimitExceeded);
            }
            bytes.to_vec()
        },
        gas_remaining: decoder.u64()?,
        observation: super::execution::ActorObservation {
            linear_revision: decoder.option(Decoder::u64)?,
            merge_frontier: decoder.option(|decoder| Ok(Hash(decoder.fixed()?)))?,
            local_revision: decoder.option(Decoder::u64)?,
        },
    };
    if reply.invocation == crate::service::InvocationId::ZERO
        || reply.actor == ActorId::ZERO
        || reply.deployment == DeploymentId::ZERO
        || reply.lane != reply.mode.write_lane()
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
            encoder.u64(id);
        }
        ActorExecutionError::DivergentInvocation => encoder.u8(11),
        ActorExecutionError::ResultCapacity => encoder.u8(12),
        ActorExecutionError::InvalidAuthorization => encoder.u8(13),
        ActorExecutionError::AuthorityExpired => encoder.u8(14),
        ActorExecutionError::AuthoritySlotRegressed => encoder.u8(15),
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
        10 => ActorExecutionError::UnsupportedHostCall(decoder.u64()?),
        11 => ActorExecutionError::DivergentInvocation,
        12 => ActorExecutionError::ResultCapacity,
        13 => ActorExecutionError::InvalidAuthorization,
        14 => ActorExecutionError::AuthorityExpired,
        15 => ActorExecutionError::AuthoritySlotRegressed,
        _ => return Err(DecodeError::InvalidTag),
    })
}

const fn encode_method_mode(mode: MethodMode) -> u8 {
    match mode {
        MethodMode::Query => 0,
        MethodMode::LinearizableQuery => 1,
        MethodMode::LocalQuery => 2,
        MethodMode::Linear => 3,
        MethodMode::Merge => 4,
        MethodMode::Local => 5,
    }
}

fn decode_method_mode(value: u8) -> Result<MethodMode, DecodeError> {
    match value {
        0 => Ok(MethodMode::Query),
        1 => Ok(MethodMode::LinearizableQuery),
        2 => Ok(MethodMode::LocalQuery),
        3 => Ok(MethodMode::Linear),
        4 => Ok(MethodMode::Merge),
        5 => Ok(MethodMode::Local),
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
            encode_blob(encoder, &install.agent_schema);
            encode_blob(encoder, &install.role_policies);
            encoder.fixed(&install.state_layout.0);
            super::contract::encode_actor_contract(encoder, install.contract);
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
            encode_blob(encoder, &upgrade.agent_schema);
            encode_blob(encoder, &upgrade.role_policies);
            encoder.fixed(&upgrade.state_layout.0);
            super::contract::encode_actor_contract(encoder, upgrade.contract);
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
        LifecycleRequest::AcknowledgeInvocation {
            invocation,
            request,
            authority,
        } => {
            encoder.u8(8);
            encoder.fixed(&invocation.0);
            encoder.fixed(&request.0);
            encoder.bytes(&authority.encode());
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
            contract,
            capabilities,
        } => {
            encoder.u8(7);
            encoder.fixed(&from_deployment.0);
            encoder.fixed(&to_deployment.0);
            encoder.fixed(&to_program.0);
            encoder.fixed(&producer.0);
            encode_blob(encoder, package);
            super::contract::encode_runtime_contract(encoder, *contract);
            encode_capabilities(encoder, *capabilities);
        }
        LifecycleRequest::Authorized { admission, request } => {
            encoder.u8(9);
            encoder.bytes(&admission.receipt.encode());
            encoder.u64(admission.observed_slot);
            encode_request(encoder, request);
        }
    }
}

fn decode_request(decoder: &mut Decoder<'_>) -> Result<LifecycleRequest, DecodeError> {
    decode_request_at_depth(decoder, 0)
}

fn decode_request_at_depth(
    decoder: &mut Decoder<'_>,
    authorized_depth: u8,
) -> Result<LifecycleRequest, DecodeError> {
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
            agent_schema: decode_blob(decoder)?,
            role_policies: decode_blob(decoder)?,
            state_layout: Hash(decoder.fixed()?),
            contract: super::contract::decode_actor_contract(decoder)?,
            requirements: decode_requirements(decoder)?,
        })),
        3 => Ok(LifecycleRequest::UpgradeActor(super::UpgradeActor {
            actor: ActorId(decoder.fixed()?),
            from_deployment: DeploymentId(decoder.fixed()?),
            to_deployment: DeploymentId(decoder.fixed()?),
            to_program: ProgramId(decoder.fixed()?),
            producer: ProducerId(decoder.fixed()?),
            package: decode_blob(decoder)?,
            agent_schema: decode_blob(decoder)?,
            role_policies: decode_blob(decoder)?,
            state_layout: Hash(decoder.fixed()?),
            contract: super::contract::decode_actor_contract(decoder)?,
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
            contract: super::contract::decode_runtime_contract(decoder)?,
            capabilities: decode_capabilities(decoder)?,
        }),
        8 => Ok(LifecycleRequest::AcknowledgeInvocation {
            invocation: crate::service::InvocationId(decoder.fixed()?),
            request: Hash(decoder.fixed()?),
            authority: Box::new(super::authority::ActorInvocationReceipt::decode(
                &decoder.bytes()?,
            )?),
        }),
        9 => {
            if authorized_depth != 0 {
                return Err(DecodeError::NonCanonical);
            }
            let admission = super::LifecycleAuthorityAdmission {
                receipt: super::authority::AgentAuthorityReceipt::decode(&decoder.bytes()?)?,
                observed_slot: decoder.u64()?,
            };
            let request = decode_request_at_depth(decoder, 1)?;
            Ok(LifecycleRequest::Authorized {
                admission,
                request: alloc::boxed::Box::new(request),
            })
        }
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
        LifecycleReply::InvocationAcknowledged(invocation) => {
            encoder.u8(8);
            encoder.fixed(&invocation.0);
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
        8 => Ok(LifecycleReply::InvocationAcknowledged(
            crate::service::InvocationId(decoder.fixed()?),
        )),
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
        LifecycleError::AuthoritySequenceRegressed => 10,
        LifecycleError::AuthoritySequenceConflict => 11,
        LifecycleError::AuthoritySlotRegressed => 12,
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
        10 => LifecycleError::AuthoritySequenceRegressed,
        11 => LifecycleError::AuthoritySequenceConflict,
        12 => LifecycleError::AuthoritySlotRegressed,
        _ => return Err(DecodeError::InvalidTag),
    })
}

fn encode_config(encoder: &mut Encoder<'_>, config: &AgentConfig) {
    encode_identity(encoder, &config.identity);
    encoder.fixed(&config.creation_nonce.0);
    super::authority::encode_binding(encoder, &config.authority);
    encode_blob(encoder, &config.runtime_package);
    super::contract::encode_runtime_contract(encoder, config.runtime_contract);
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
        creation_nonce: Hash(decoder.fixed()?),
        authority: super::authority::decode_binding(decoder)?,
        runtime_package: decode_blob(decoder)?,
        runtime_contract: super::contract::decode_runtime_contract(decoder)?,
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
    encode_blob(encoder, &entry.package);
    encode_blob(encoder, &entry.agent_schema);
    encode_blob(encoder, &entry.role_policies);
    encoder.fixed(&entry.state_layout.0);
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
        package: decode_blob(decoder)?,
        agent_schema: decode_blob(decoder)?,
        role_policies: decode_blob(decoder)?,
        state_layout: Hash(decoder.fixed()?),
        lanes: decode_lanes(decoder)?,
        suspended: decoder.bool()?,
    };
    if entry.name.is_empty()
        || entry.name.len() > crate::service::MAX_ACTOR_NAME_BYTES
        || entry.package.hash == Hash::ZERO
        || entry.package.len == 0
        || entry.agent_schema.hash == Hash::ZERO
        || entry.agent_schema.len == 0
        || entry.agent_schema.len > super::schema::MAX_ENCODED_BYTES as u64
        || entry.role_policies.hash == Hash::ZERO
        || entry.role_policies.len == 0
        || entry.role_policies.len > super::execution::MAX_EXECUTION_POLICY_BYTES as u64
        || entry.state_layout == Hash::ZERO
    {
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
    use ed25519_dalek::{Signer as _, SigningKey};

    fn authority_key() -> SigningKey {
        SigningKey::from_bytes(&[0x41; 32])
    }

    fn authority_binding() -> crate::agent::authority::AgentAuthorityBinding {
        let public_key = crate::agent::authority::ed25519_public_key_wire(
            authority_key().verifying_key().to_bytes(),
        );
        crate::agent::authority::AgentAuthorityBinding {
            agent: AgentId([11; 32]),
            actor: ActorId([12; 32]),
            deployment: DeploymentId([13; 32]),
            program: ProgramId([14; 32]),
            producer: ProducerId::of_public_key(&public_key),
            public_key,
        }
    }

    fn config() -> AgentConfig {
        let owner = PrincipalId([1; 32]);
        let space = SpaceId([2; 32]);
        let creation_nonce = Hash([0x15; 32]);
        AgentConfig {
            identity: AgentIdentity {
                space,
                agent: AgentId::derive(space, owner, &creation_nonce.0),
                owner,
                profile: AgentProfile::Shared,
                runtime_deployment: DeploymentId([4; 32]),
                runtime_program: ProgramId([5; 32]),
                runtime_producer: ProducerId([6; 32]),
            },
            creation_nonce,
            authority: authority_binding(),
            runtime_package: BlobRef {
                hash: Hash([7; 32]),
                len: 100,
            },
            runtime_contract: crate::agent::contract::RuntimePackageContract::canonical(),
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
            state: RuntimeState {
                control: vec![11],
                linear: vec![12],
                merge: vec![13],
                local: vec![14],
            },
            request: LifecycleRequest::Create(config()),
        };
        let encoded = call.encode();
        assert_eq!(RuntimeCall::decode(&encoded).unwrap(), call);
    }

    #[test]
    fn lifecycle_wire_rejects_nested_authorized_envelopes() {
        let config = config();
        let request = LifecycleRequest::Suspend(ActorId([0x35; 32]));
        let admission = super::super::LifecycleAuthorityAdmission {
            receipt: crate::agent::authority::AgentAuthorityReceipt {
                claim: crate::agent::authority::AgentAuthorityClaim {
                    authority: config.authority,
                    space: config.identity.space,
                    agent: config.identity.agent,
                    principal: config.identity.owner,
                    credential: crate::service::CredentialId([0x32; 32]),
                    capability: CapabilityId::named("actor.lifecycle"),
                    operation: request.commitment(),
                    sequence: 1,
                    valid_from: 0,
                    valid_until: 20,
                },
                signature: vec![0; crate::agent::authority::ED25519_SIGNATURE_BYTES],
            },
            observed_slot: 10,
        };
        let call = RuntimeCall {
            state: RuntimeState::default(),
            request: LifecycleRequest::Authorized {
                admission: admission.clone(),
                request: alloc::boxed::Box::new(LifecycleRequest::Authorized {
                    admission,
                    request: alloc::boxed::Box::new(request),
                }),
            },
        };
        assert_eq!(
            RuntimeCall::decode(&call.encode()),
            Err(DecodeError::NonCanonical)
        );
    }

    #[test]
    fn directory_round_trip_preserves_schema_provenance() {
        let package = BlobRef {
            hash: Hash([0x26; 32]),
            len: 124,
        };
        let role_policies = BlobRef {
            hash: Hash([0x27; 32]),
            len: 125,
        };
        let entry = ActorEntry {
            actor: ActorId([0x21; 32]),
            name: "counter".into(),
            parent: None,
            deployment: DeploymentId([0x22; 32]),
            program: ProgramId([0x23; 32]),
            package,
            agent_schema: BlobRef {
                hash: Hash([0x24; 32]),
                len: 123,
            },
            role_policies,
            state_layout: Hash([0x25; 32]),
            lanes: LaneSet::of(StateLane::Linear),
            suspended: false,
        };
        let returned = RuntimeReturn {
            state: RuntimeState {
                control: vec![1],
                linear: vec![2],
                merge: vec![3],
                local: vec![4],
            },
            result: Ok(LifecycleReply::Directory(ActorDirectoryPage {
                entries: vec![entry.clone()],
                next: Some(entry.actor),
            })),
        };
        assert_eq!(RuntimeReturn::decode(&returned.encode()).unwrap(), returned);
    }

    #[test]
    fn actor_execution_call_round_trips_with_content_addressed_inputs() {
        let actor_pvm = vec![0x21, 0x22, 0x23];
        let state = vec![0x31, 0x32];
        let (schema, schema_len) =
            crate::agent::schema::encode::<512>(&crate::agent::schema::SchemaMeta {
                uses_storage: false,
                fields: &[],
                methods: &[crate::agent::schema::MethodMeta {
                    name: "call",
                    mode: MethodMode::Linear,
                    explicit: true,
                }],
            });
        let schema = schema[..schema_len].to_vec();
        let policies = crate::service::PackageRolePolicies {
            methods: vec![],
            task_dependencies: vec![],
        }
        .encode();
        let invocation = ActorInvocation {
            invocation: crate::service::InvocationId([1; 32]),
            actor: ActorId([2; 32]),
            deployment: DeploymentId([3; 32]),
            program: ProgramId::of_pvm(&actor_pvm),
            mode: MethodMode::Linear,
            auth: ActorInvocationAuth::anonymous(),
            message: vec![0x41],
            availability: vec![RuntimeBlob {
                reference: BlobRef::of_bytes(&state),
                bytes: state,
            }],
            gas: 1_000_000,
        };
        let call = RuntimeExecutionCall {
            state: RuntimeState {
                control: vec![0x11],
                linear: vec![0x12],
                merge: vec![0x13],
                local: vec![0x14],
            },
            recovery_only: false,
            authority: crate::agent::authority::ActorInvocationReceipt {
                claim: crate::agent::authority::ActorInvocationClaim {
                    authority: authority_binding(),
                    space: SpaceId([0x61; 32]),
                    agent: AgentId([0x62; 32]),
                    principal: None,
                    credential: None,
                    authorization: invocation.authorization_message(),
                    auth: invocation.auth.clone(),
                    valid_from: 0,
                    valid_until: 20,
                },
                signature: vec![0; crate::agent::authority::ED25519_SIGNATURE_BYTES],
            },
            observed_slot: 10,
            invocation,
            actor_pvm,
            actor_schema: RuntimeBlob {
                reference: BlobRef::of_bytes(&schema),
                bytes: schema,
            },
            actor_policies: RuntimeBlob {
                reference: BlobRef::of_bytes(&policies),
                bytes: policies,
            },
        };
        assert_eq!(RuntimeExecutionCall::decode(&call.encode()).unwrap(), call);
    }

    #[test]
    fn execution_error_preserves_a_wide_host_identifier() {
        let returned = RuntimeExecutionReturn {
            state: RuntimeState::default(),
            result: Err(ActorExecutionError::UnsupportedHostCall(u64::MAX)),
        };
        assert_eq!(
            RuntimeExecutionReturn::decode(&returned.encode()).unwrap(),
            returned
        );
    }

    #[test]
    fn private_dispatch_wire_rejects_anonymous_role_claims() {
        let control = ActorDispatchControl {
            invocation: crate::service::InvocationId([0x41; 32]),
            actor: ActorId([0x42; 32]),
            mode: MethodMode::Linear,
            auth: ActorInvocationAuth {
                origin: crate::service::Origin::Anonymous,
                principal: None,
                origin_service: None,
                space_role: None,
                actor_role: Some(1),
                capability: None,
            },
        };
        assert_eq!(
            ActorDispatchControl::decode(&control.encode()),
            Err(DecodeError::NonCanonical)
        );
    }

    #[test]
    fn runtime_state_wire_enforces_its_aggregate_guest_budget() {
        let exact = RuntimeCall {
            state: RuntimeState {
                control: vec![1; super::super::execution::MAX_RUNTIME_STATE_BYTES / 2],
                linear: vec![2; super::super::execution::MAX_RUNTIME_STATE_BYTES / 2],
                merge: Vec::new(),
                local: Vec::new(),
            },
            request: LifecycleRequest::Inspect {
                after: None,
                limit: 1,
            },
        };
        assert_eq!(RuntimeCall::decode(&exact.encode()).unwrap(), exact);

        let oversized = RuntimeCall {
            state: RuntimeState {
                local: vec![3],
                ..exact.state
            },
            request: exact.request,
        };
        assert_eq!(
            RuntimeCall::decode(&oversized.encode()),
            Err(DecodeError::LimitExceeded)
        );
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
            state: RuntimeState {
                control: vec![8],
                linear: vec![9],
                merge: vec![10],
                local: vec![11],
            },
            result: Err(LifecycleError::Busy(debt)),
        };
        assert_eq!(RuntimeReturn::decode(&output.encode()).unwrap(), output);
    }

    #[test]
    fn unsorted_replica_configuration_is_noncanonical() {
        let mut call = RuntimeCall {
            state: RuntimeState::default(),
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
        let config = config();
        let request = LifecycleRequest::Create(config.clone());
        let claim = crate::agent::authority::AgentAuthorityClaim {
            authority: config.authority.clone(),
            space: config.identity.space,
            agent: config.identity.agent,
            principal: config.identity.owner,
            credential: crate::service::CredentialId([0x72; 32]),
            capability: CapabilityId::named(
                crate::agent::authority::CAPABILITY_AGENT_CREATE_SHARED,
            ),
            operation: request.commitment(),
            sequence: 1,
            valid_from: 0,
            valid_until: 10,
        };
        let signature = authority_key()
            .sign(&claim.signing_message().0)
            .to_bytes()
            .to_vec();
        let created = apply_standard(RuntimeCall {
            state: RuntimeState::default(),
            request: LifecycleRequest::Authorized {
                admission: super::super::LifecycleAuthorityAdmission {
                    receipt: crate::agent::authority::AgentAuthorityReceipt { claim, signature },
                    observed_slot: 1,
                },
                request: Box::new(request),
            },
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
