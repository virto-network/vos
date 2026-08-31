//! Stable management ABI between a node and an agent-runtime PVM.

use alloc::{boxed::Box, vec::Vec};

use super::execution::{
    ActorExecutionError, ActorExecutionReply, ActorExecutionStatus, ActorInvocation,
    ActorInvocationAuth, RuntimeBlob, RuntimeExecutionCall, RuntimeExecutionReturn,
};
use super::standard::{
    StandardActorState, StandardAgentRuntime, StandardAuthorityDisposition,
    StandardInvocationResult, StandardLaneEntry, StandardLaneState, StandardRuntimeState,
};
use super::{
    ActorDirectoryPage, ActorDirectoryRecord, ActorEntry, ActorLifecycleDebt, AgentConfig,
    AgentIdentity, AgentProfile, AgentReplica, InvocationScope, LaneSet, LifecycleError,
    LifecycleReply, LifecycleRequest, MethodMode, ReplicaRole, RuntimeCapabilities,
    RuntimeRequirements, StateLane,
};
use crate::service::wire::{DecodeError, Decoder, Encoder, ServiceWire};
use crate::service::{
    ActorId, AgentId, BlobRef, CapabilityId, DeploymentId, Hash, NodeId, PrincipalId, ProducerId,
    ProgramId, SpaceId,
};

/// Replay-authenticated identity of the exact journal generation applying a
/// management input. These bytes are deterministic state-machine input, not a
/// capability: only replay may construct a scoped call which is eligible for
/// publication.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RuntimeJournalContext {
    genesis: super::journal::AgentJournalGenesisId,
    agent_admission: super::genesis::AgentGenesisAdmissionId,
}

impl RuntimeJournalContext {
    fn new(
        genesis: super::journal::AgentJournalGenesisId,
        agent_admission: super::genesis::AgentGenesisAdmissionId,
    ) -> Result<Self, super::system_authority::SystemAuthorityError> {
        if genesis == super::journal::AgentJournalGenesisId::ZERO
            || agent_admission == super::genesis::AgentGenesisAdmissionId::ZERO
        {
            return Err(super::system_authority::SystemAuthorityError::InvalidScope);
        }
        Ok(Self {
            genesis,
            agent_admission,
        })
    }

    /// Derive deterministic guest input from replay's opaque root identity.
    /// This value remains data only: decoding or copying it never mints the
    /// separate `SystemAuthorityJournalScope` capability.
    pub(crate) fn from_replayed_root(
        identity: &super::replay::ReplayedRootJournalIdentity,
    ) -> Result<Self, super::system_authority::SystemAuthorityError> {
        Self::new(identity.genesis(), identity.outer_admission())
    }

    pub(crate) const fn genesis(self) -> super::journal::AgentJournalGenesisId {
        self.genesis
    }

    pub(crate) const fn agent_admission(self) -> super::genesis::AgentGenesisAdmissionId {
        self.agent_admission
    }

    pub(crate) fn matches_system_authority_scope(
        self,
        scope: super::system_authority::SystemAuthorityJournalScope,
    ) -> bool {
        self.genesis == scope.system_genesis() && self.agent_admission == scope.agent_admission()
    }
}

/// One management call. Runtime-owned state is opaque to the node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeCall {
    pub state: RuntimeState,
    pub request: LifecycleRequest,
    journal_context: Option<RuntimeJournalContext>,
}

impl RuntimeCall {
    /// Construct an unscoped public call. Pre-genesis Create and logical
    /// operation commitments use this form. Direct live-authority commands
    /// deterministically reject it.
    pub const fn new(state: RuntimeState, request: LifecycleRequest) -> Self {
        Self {
            state,
            request,
            journal_context: None,
        }
    }

    /// Construct the exact replay input used by native and guest execution.
    pub(crate) const fn scoped_system_authority(
        state: RuntimeState,
        request: LifecycleRequest,
        trusted_scope: super::system_authority::SystemAuthorityJournalScope,
    ) -> Self {
        Self {
            state,
            request,
            journal_context: Some(RuntimeJournalContext {
                genesis: trusted_scope.system_genesis(),
                agent_admission: trusted_scope.agent_admission(),
            }),
        }
    }

    /// Construct a replay-selected guest call from data-only journal
    /// context. Only replay can obtain the context used by live authority
    /// execution; the guest still receives ordinary bytes, not a capability.
    pub(crate) const fn from_replay_context(
        state: RuntimeState,
        request: LifecycleRequest,
        journal_context: RuntimeJournalContext,
    ) -> Self {
        Self {
            state,
            request,
            journal_context: Some(journal_context),
        }
    }

    pub(crate) const fn journal_context(&self) -> Option<RuntimeJournalContext> {
        self.journal_context
    }
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
        encoder.option(&self.journal_context, |encoder, context| {
            encoder.fixed(&context.genesis.0);
            encoder.fixed(context.agent_admission.as_bytes());
        });
        encode_runtime_state(&mut encoder, &self.state);
        encode_request(&mut encoder, &self.request);
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        if Hash(decoder.fixed()?) != super::RUNTIME_ABI_ID {
            return Err(DecodeError::InvalidPlatform);
        }
        let journal_context = decoder.option(|decoder| {
            RuntimeJournalContext::new(
                super::journal::AgentJournalGenesisId(decoder.fixed()?),
                super::genesis::AgentGenesisAdmissionId::from_bytes(decoder.fixed()?),
            )
            .map_err(|_| DecodeError::NonCanonical)
        })?;
        Ok(Self {
            state: decode_runtime_state(decoder)?,
            request: decode_request(decoder)?,
            journal_context,
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
        encode_execution_result(&mut encoder, &self.result);
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        if Hash(decoder.fixed()?) != super::RUNTIME_ABI_ID {
            return Err(DecodeError::InvalidPlatform);
        }
        let state = decode_runtime_state(decoder)?;
        let result = decode_execution_result(decoder)?;
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

fn decode_bounded_list<T>(
    decoder: &mut Decoder<'_>,
    maximum: usize,
    mut decode: impl FnMut(&mut Decoder<'_>) -> Result<T, DecodeError>,
) -> Result<Vec<T>, DecodeError> {
    let len = decoder.u32()? as usize;
    if len > maximum {
        return Err(DecodeError::LimitExceeded);
    }
    // Validate the declared cardinality before allocating, then grow only
    // after a complete item consumed authenticated input.
    let mut values = Vec::new();
    for _ in 0..len {
        let before = decoder.remaining();
        let value = decode(decoder)?;
        if decoder.remaining() >= before {
            return Err(DecodeError::NonCanonical);
        }
        values
            .try_reserve(1)
            .map_err(|_| DecodeError::LimitExceeded)?;
        values.push(value);
    }
    Ok(values)
}

/// Encode the standard runtime's policy state and three actor-state lanes as
/// independently durable opaque components.
pub fn encode_standard_runtime_state(state: &StandardRuntimeState) -> RuntimeState {
    let mut control = Vec::new();
    let mut encoder = Encoder(&mut control);
    encoder.fixed(&super::RUNTIME_ABI_ID.0);
    encoder.option(&state.config, encode_config);
    encoder.option(&state.system_authority, |encoder, authority| {
        encoder.bytes(&authority.encode())
    });
    encoder.list(&state.actors, |encoder, actor| {
        encode_entry(encoder, &actor.record.entry);
        encoder.fixed(&actor.record.state_generation.0);
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
            encoder.u8(encode_invocation_scope(result.scope));
            encoder.fixed(&result.invocation.0);
            encoder.fixed(&result.incarnation.0);
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

/// Decode all opaque standard-runtime components. Lane maps are sparse and
/// independently keyed: matching active generations hydrate actor state,
/// missing matching entries mean fresh empty state, and nonmatching entries
/// remain historical until checkpoint compaction.
pub fn decode_standard_runtime_state(
    state: &RuntimeState,
) -> Result<StandardRuntimeState, DecodeError> {
    if state
        .encoded_len()
        .is_none_or(|bytes| bytes > super::execution::MAX_RUNTIME_STATE_BYTES)
    {
        return Err(DecodeError::LimitExceeded);
    }
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
    let system_authority = decoder.option(|decoder| {
        let bytes = decoder.bytes_ref()?;
        if bytes.len() > super::system_authority::MAX_SYSTEM_AUTHORITY_STATE_BYTES {
            return Err(DecodeError::LimitExceeded);
        }
        super::system_authority::SystemAuthorityState::decode(bytes)
    })?;
    let actors = decode_bounded_list(
        &mut decoder,
        super::contract::STANDARD_MAX_ACTORS as usize,
        |decoder| {
            Ok(StandardActorState {
                record: super::ActorRecord {
                    entry: decode_entry(decoder)?,
                    state_generation: Hash(decoder.fixed()?),
                    producer: ProducerId(decoder.fixed()?),
                    package: decode_blob(decoder)?,
                    agent_schema: decode_blob(decoder)?,
                    role_policies: decode_blob(decoder)?,
                    state_layout: Hash(decoder.fixed()?),
                    contract: super::contract::decode_actor_contract(decoder)?,
                    requirements: decode_requirements(decoder)?,
                },
                debt: decode_debt(decoder)?,
            })
        },
    )?;
    let authority_slot_high_water = decoder.option(|decoder| decoder.u64())?;
    let authority_sequence_high_water = decoder.option(|decoder| decoder.u64())?;
    let authority_dispositions = decode_bounded_list(
        &mut decoder,
        super::standard::MAX_AUTHORITY_DISPOSITIONS,
        |decoder| {
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
        },
    )?;
    let control_authority_slot = decoder.option(Decoder::u64)?;
    let mut invocation_results = decode_bounded_list(
        &mut decoder,
        super::standard::MAX_INVOCATION_RESULTS_PER_LANE,
        |decoder| {
            let scope = decode_invocation_scope(decoder.u8()?)?;
            let invocation = crate::service::InvocationId(decoder.fixed()?);
            let incarnation = Hash(decoder.fixed()?);
            let request = Hash(decoder.fixed()?);
            let reply = decode_execution_reply(decoder)?;
            if scope != InvocationScope::Ordered
                || invocation == crate::service::InvocationId::ZERO
                || incarnation == Hash::ZERO
                || request == Hash::ZERO
                || reply.invocation != invocation
                || reply.incarnation != incarnation
                || reply.mode.invocation_scope() != scope
                || reply.mode.result_storage() != super::InvocationResultStorage::Control
            {
                return Err(DecodeError::NonCanonical);
            }
            Ok(StandardInvocationResult {
                scope,
                invocation,
                incarnation,
                request,
                reply,
                storage: super::InvocationResultStorage::Control,
            })
        },
    )?;
    if invocation_results
        .windows(2)
        .any(|pair| (pair[0].scope, pair[0].invocation) >= (pair[1].scope, pair[1].invocation))
    {
        return Err(DecodeError::NonCanonical);
    }
    if !decoder.exhausted() {
        return Err(DecodeError::TrailingBytes);
    }
    let mut lane_revisions = super::standard::StandardLaneRevisions::default();
    let mut lane_state = StandardLaneState::default();
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
        match lane {
            StateLane::Linear => lane_state.linear = decoded.values,
            StateLane::Merge => lane_state.merge = decoded.values,
            StateLane::Local => lane_state.local = decoded.values,
        }
        invocation_results.extend(decoded.invocation_results);
    }
    invocation_results.sort_unstable_by_key(|result| (result.scope, result.invocation));
    if invocation_results
        .windows(2)
        .any(|pair| (pair[0].scope, pair[0].invocation) >= (pair[1].scope, pair[1].invocation))
    {
        return Err(DecodeError::NonCanonical);
    }
    let state = StandardRuntimeState {
        config,
        system_authority,
        actors,
        lane_state,
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
    let entries = match lane {
        StateLane::Linear => &state.lane_state.linear,
        StateLane::Merge => &state.lane_state.merge,
        StateLane::Local => &state.lane_state.local,
    };
    encoder.list(entries, |encoder, entry| {
        encoder.fixed(&entry.actor.0);
        encoder.fixed(&entry.state_generation.0);
        encoder.bytes(&entry.value);
    });
    encoder.list(
        &state
            .invocation_results
            .iter()
            .filter(|result| result.storage == super::InvocationResultStorage::Lane(lane))
            .collect::<Vec<_>>(),
        |encoder, result| {
            encoder.u8(encode_invocation_scope(result.scope));
            encoder.fixed(&result.invocation.0);
            encoder.fixed(&result.incarnation.0);
            encoder.fixed(&result.request.0);
            encode_execution_reply(encoder, &result.reply);
        },
    );
    output
}

struct DecodedStandardLane {
    revision: u64,
    authority_slot: Option<u64>,
    values: Vec<StandardLaneEntry>,
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
    let values = decode_bounded_list(
        &mut decoder,
        super::standard::MAX_LANE_STATE_ENTRIES,
        |decoder| {
            let actor = ActorId(decoder.fixed()?);
            let state_generation = Hash(decoder.fixed()?);
            let value = decoder.bytes_ref()?;
            if actor == ActorId::ZERO
                || state_generation == Hash::ZERO
                || value.is_empty()
                || value.len() > super::execution::MAX_EXECUTION_STATE_BYTES
            {
                return Err(DecodeError::NonCanonical);
            }
            Ok(StandardLaneEntry {
                actor,
                state_generation,
                value: value.to_vec(),
            })
        },
    )?;
    if values.windows(2).any(|pair| {
        (pair[0].actor, pair[0].state_generation) >= (pair[1].actor, pair[1].state_generation)
    }) {
        return Err(DecodeError::NonCanonical);
    }
    let invocation_results = decode_bounded_list(
        &mut decoder,
        super::standard::MAX_INVOCATION_RESULTS_PER_LANE,
        |decoder| {
            let scope = decode_invocation_scope(decoder.u8()?)?;
            let invocation = crate::service::InvocationId(decoder.fixed()?);
            let incarnation = Hash(decoder.fixed()?);
            let request = Hash(decoder.fixed()?);
            let reply = decode_execution_reply(decoder)?;
            if scope != invocation_scope_for_lane(expected_lane)
                || invocation == crate::service::InvocationId::ZERO
                || incarnation == Hash::ZERO
                || request == Hash::ZERO
                || reply.invocation != invocation
                || reply.incarnation != incarnation
                || reply.mode.invocation_scope() != scope
                || reply.mode.result_storage()
                    != super::InvocationResultStorage::Lane(expected_lane)
            {
                return Err(DecodeError::NonCanonical);
            }
            Ok(StandardInvocationResult {
                scope,
                invocation,
                incarnation,
                request,
                reply,
                storage: super::InvocationResultStorage::Lane(expected_lane),
            })
        },
    )?;
    if invocation_results
        .windows(2)
        .any(|pair| (pair[0].scope, pair[0].invocation) >= (pair[1].scope, pair[1].invocation))
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
    let result = runtime.apply_guest(call.journal_context(), call.request);
    Ok(RuntimeReturn {
        state: encode_standard_runtime_state(&runtime.snapshot()),
        result,
    })
}

/// Execute one actor call with the bundled runtime. Deterministic exact
/// outcomes advance only their owning result component's authority clock;
/// admission failures and unavailable execution keep byte-identical state.
#[cfg(feature = "pvm")]
pub fn apply_standard_execution(
    call: RuntimeExecutionCall,
) -> Result<RuntimeExecutionReturn, DecodeError> {
    let original_state = call.state;
    let state = decode_standard_runtime_state(&original_state)?;
    let hard_state_limit = super::execution::MAX_RUNTIME_STATE_BYTES;
    let signed_state_limit = state.config.as_ref().map_or(hard_state_limit, |config| {
        config.runtime_contract.resources.max_runtime_state_bytes as usize
    });
    let state_limit = hard_state_limit.min(signed_state_limit);
    let mut runtime =
        StandardAgentRuntime::restore(state).map_err(|_| DecodeError::NonCanonical)?;
    let (mut result, commit_candidate) = match call.invocation.validate() {
        Err(error) => (Err(error), false),
        Ok(()) => match runtime.verify_invocation_authority(&call.invocation, &call.authority) {
            Err(error) => (Err(error), false),
            Ok(()) => match runtime.validate_invocation_result_storage(&call.invocation) {
                Err(error) => (Err(error), false),
                Ok(()) => match runtime.recover_execution(&call.invocation, call.observed_slot) {
                    Ok(Some(reply)) => (Ok(reply), true),
                    Err(ActorExecutionError::DivergentInvocation) => {
                        (Err(ActorExecutionError::DivergentInvocation), false)
                    }
                    unseen => match runtime.validate_unseen_invocation_slot(
                        &call.invocation,
                        &call.authority,
                        call.observed_slot,
                    ) {
                        Err(error) => (Err(error), false),
                        Ok(()) => {
                            let pristine = runtime.clone();
                            let mut result = match unseen {
                                Err(error) => Err(error),
                                Ok(None) if call.recovery_only => {
                                    Err(ActorExecutionError::InvalidAvailability)
                                }
                                Ok(None) => match runtime
                                    .validate_execution_schema(&call.invocation, &call.actor_schema)
                                    .and_then(|()| {
                                        runtime.authorize_execution(
                                            &call.invocation,
                                            &call.actor_policies,
                                        )
                                    }) {
                                    Err(error) => Err(error),
                                    Ok(false) => Ok(ActorExecutionReply {
                                        invocation: call.invocation.invocation,
                                        actor: call.invocation.actor,
                                        incarnation: call.invocation.incarnation,
                                        deployment: call.invocation.deployment,
                                        mode: call.invocation.mode,
                                        lane: call.invocation.mode.write_lane(),
                                        status: ActorExecutionStatus::Forbidden,
                                        reply: Vec::new(),
                                        gas_remaining: call.invocation.gas,
                                        observation: super::execution::ActorObservation::default(),
                                    }),
                                    Ok(true) => {
                                        runtime.prepare_execution_state(&call.invocation).and_then(
                                            |before| {
                                                let actor_state =
                                                    before.visible_for(call.invocation.mode);
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
                                            },
                                        )
                                    }
                                },
                                Ok(Some(_)) => unreachable!("exact recovery returned above"),
                            };
                            let commit_candidate = finalize_unseen_standard_outcome(
                                &mut runtime,
                                pristine,
                                &call.invocation,
                                call.observed_slot,
                                &mut result,
                            );
                            (result, commit_candidate)
                        }
                    },
                },
            },
        },
    };
    let state = finish_standard_execution_candidate(
        original_state,
        &runtime,
        commit_candidate,
        state_limit,
        &mut result,
    );
    Ok(RuntimeExecutionReturn { state, result })
}

#[cfg(feature = "pvm")]
fn finish_standard_execution_candidate(
    original_state: RuntimeState,
    runtime: &StandardAgentRuntime,
    commit_candidate: bool,
    state_limit: usize,
    result: &mut Result<ActorExecutionReply, ActorExecutionError>,
) -> RuntimeState {
    if !commit_candidate {
        return original_state;
    }
    let candidate = encode_standard_runtime_state(&runtime.snapshot());
    if candidate.encoded_len().is_none_or(|len| len > state_limit) {
        *result = Err(ActorExecutionError::ResultCapacity);
        original_state
    } else {
        candidate
    }
}

/// Finish a fresh, authenticated execution result. `Done` has already passed
/// through `commit_execution`; every externally retained terminal/error result
/// is instead rebased on `pristine` and consumes only its owning clock.
#[cfg(feature = "pvm")]
fn finalize_unseen_standard_outcome(
    runtime: &mut StandardAgentRuntime,
    pristine: StandardAgentRuntime,
    invocation: &ActorInvocation,
    observed_slot: u64,
    result: &mut Result<ActorExecutionReply, ActorExecutionError>,
) -> bool {
    let external_exact = match result {
        Ok(reply) => reply.status != ActorExecutionStatus::Done,
        Err(error) => error.is_durable_exact_outcome(),
    };
    if external_exact {
        // A failed Done commit may have changed a candidate lane before
        // detecting a deterministic guest error. Discard every such candidate
        // before advancing the sole permitted result-component clock.
        *runtime = pristine;
        return match runtime.commit_exact_outcome_clock(invocation, observed_slot) {
            Ok(()) => true,
            Err(error) => {
                *result = Err(error);
                false
            }
        };
    }
    if result.is_ok() {
        true
    } else {
        *runtime = pristine;
        false
    }
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
    encoder.fixed(&invocation.incarnation.0);
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
    let incarnation = Hash(decoder.fixed()?);
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
        incarnation,
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

pub(crate) fn encode_execution_reply(encoder: &mut Encoder<'_>, reply: &ActorExecutionReply) {
    encoder.fixed(&reply.invocation.0);
    encoder.fixed(&reply.actor.0);
    encoder.fixed(&reply.incarnation.0);
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

pub(crate) fn decode_execution_reply(
    decoder: &mut Decoder<'_>,
) -> Result<ActorExecutionReply, DecodeError> {
    let reply = ActorExecutionReply {
        invocation: crate::service::InvocationId(decoder.fixed()?),
        actor: ActorId(decoder.fixed()?),
        incarnation: Hash(decoder.fixed()?),
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
    validate_execution_reply(&reply)?;
    Ok(reply)
}

pub(crate) fn validate_execution_reply(reply: &ActorExecutionReply) -> Result<(), DecodeError> {
    if reply.invocation == crate::service::InvocationId::ZERO
        || reply.actor == ActorId::ZERO
        || reply.incarnation == Hash::ZERO
        || reply.deployment == DeploymentId::ZERO
        || reply.lane != reply.mode.write_lane()
        || reply.reply.len() > super::execution::MAX_EXECUTION_REPLY_BYTES
    {
        return Err(DecodeError::NonCanonical);
    }
    Ok(())
}

pub(crate) fn encode_execution_error(encoder: &mut Encoder<'_>, error: ActorExecutionError) {
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
        ActorExecutionError::StaleIncarnation => encoder.u8(16),
        ActorExecutionError::UnsupportedResultStorage => encoder.u8(17),
    }
}

pub(crate) fn decode_execution_error(
    decoder: &mut Decoder<'_>,
) -> Result<ActorExecutionError, DecodeError> {
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
        16 => ActorExecutionError::StaleIncarnation,
        17 => ActorExecutionError::UnsupportedResultStorage,
        _ => return Err(DecodeError::InvalidTag),
    })
}

/// Canonical nested codec shared by the runtime-return ABI and durable
/// invocation outcomes. Keeping one implementation prevents exact-result
/// recovery from assigning different tags or validation rules to a result
/// which crossed the live runtime boundary first.
pub(crate) fn encode_execution_result(
    encoder: &mut Encoder<'_>,
    result: &Result<ActorExecutionReply, ActorExecutionError>,
) {
    match result {
        Ok(reply) => {
            encoder.bool(true);
            encode_execution_reply(encoder, reply);
        }
        Err(error) => {
            encoder.bool(false);
            encode_execution_error(encoder, *error);
        }
    }
}

pub(crate) fn decode_execution_result(
    decoder: &mut Decoder<'_>,
) -> Result<Result<ActorExecutionReply, ActorExecutionError>, DecodeError> {
    if decoder.bool()? {
        Ok(Ok(decode_execution_reply(decoder)?))
    } else {
        Ok(Err(decode_execution_error(decoder)?))
    }
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

const fn encode_invocation_scope(scope: InvocationScope) -> u8 {
    scope as u8
}

fn decode_invocation_scope(value: u8) -> Result<InvocationScope, DecodeError> {
    match value {
        0 => Ok(InvocationScope::Ordered),
        1 => Ok(InvocationScope::Merge),
        2 => Ok(InvocationScope::Local),
        _ => Err(DecodeError::InvalidTag),
    }
}

const fn invocation_scope_for_lane(lane: StateLane) -> InvocationScope {
    match lane {
        StateLane::Linear => InvocationScope::Ordered,
        StateLane::Merge => InvocationScope::Merge,
        StateLane::Local => InvocationScope::Local,
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
        LifecycleRequest::Suspend {
            actor,
            expected_deployment,
        } => {
            encoder.u8(4);
            encoder.fixed(&actor.0);
            encoder.fixed(&expected_deployment.0);
        }
        LifecycleRequest::Resume {
            actor,
            expected_deployment,
        } => {
            encoder.u8(5);
            encoder.fixed(&actor.0);
            encoder.fixed(&expected_deployment.0);
        }
        LifecycleRequest::AcknowledgeInvocation {
            scope,
            invocation,
            request,
            authority,
        } => {
            encoder.u8(8);
            encoder.u8(encode_invocation_scope(*scope));
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
        LifecycleRequest::FinalizeSystemAuthority(finalize) => {
            encoder.u8(10);
            encoder.bytes(&finalize.encode());
        }
        LifecycleRequest::RotateSystemAuthority(rotation) => {
            encoder.u8(11);
            encoder.bytes(&rotation.encode());
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
        4 => Ok(LifecycleRequest::Suspend {
            actor: ActorId(decoder.fixed()?),
            expected_deployment: DeploymentId(decoder.fixed()?),
        }),
        5 => Ok(LifecycleRequest::Resume {
            actor: ActorId(decoder.fixed()?),
            expected_deployment: DeploymentId(decoder.fixed()?),
        }),
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
            scope: decode_invocation_scope(decoder.u8()?)?,
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
        10 => {
            let bytes = decoder.bytes_ref()?;
            if bytes.len() > super::system_authority::MAX_SYSTEM_AUTHORITY_FINALIZE_BYTES {
                return Err(DecodeError::LimitExceeded);
            }
            Ok(LifecycleRequest::FinalizeSystemAuthority(
                super::system_authority::SystemAuthorityFinalize::decode(bytes)?,
            ))
        }
        11 => {
            let bytes = decoder.bytes_ref()?;
            if bytes.len() > super::system_authority::MAX_SYSTEM_AUTHORITY_ROTATION_BYTES {
                return Err(DecodeError::LimitExceeded);
            }
            Ok(LifecycleRequest::RotateSystemAuthority(
                super::system_authority::SystemAuthorityRotation::decode(bytes)?,
            ))
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
        LifecycleReply::InvocationAcknowledged { scope, invocation } => {
            encoder.u8(8);
            encoder.u8(encode_invocation_scope(*scope));
            encoder.fixed(&invocation.0);
        }
        LifecycleReply::SystemAuthorityFinalized(outcome) => {
            encoder.u8(9);
            match outcome {
                super::system_authority::SystemAuthorityFinalizeOutcome::Admitted(decision) => {
                    encoder.u8(0);
                    encoder.fixed(decision.as_bytes());
                }
                super::system_authority::SystemAuthorityFinalizeOutcome::ExactRetry(decision) => {
                    encoder.u8(1);
                    encoder.fixed(decision.as_bytes());
                }
                super::system_authority::SystemAuthorityFinalizeOutcome::TargetConflict(
                    decision,
                ) => {
                    encoder.u8(2);
                    encoder.fixed(decision.as_bytes());
                }
            }
        }
        LifecycleReply::SystemAuthorityRotated {
            rotation,
            epoch,
            exact_retry,
        } => {
            encoder.u8(10);
            encoder.fixed(rotation.as_bytes());
            encoder.u64(*epoch);
            encoder.bool(*exact_retry);
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
        8 => Ok(LifecycleReply::InvocationAcknowledged {
            scope: decode_invocation_scope(decoder.u8()?)?,
            invocation: crate::service::InvocationId(decoder.fixed()?),
        }),
        9 => {
            let outcome = decoder.u8()?;
            let decision = super::genesis::AgentGenesisDecisionId::from_bytes(decoder.fixed()?);
            if decision == super::genesis::AgentGenesisDecisionId::ZERO {
                return Err(DecodeError::NonCanonical);
            }
            Ok(LifecycleReply::SystemAuthorityFinalized(match outcome {
                0 => super::system_authority::SystemAuthorityFinalizeOutcome::Admitted(decision),
                1 => super::system_authority::SystemAuthorityFinalizeOutcome::ExactRetry(decision),
                2 => super::system_authority::SystemAuthorityFinalizeOutcome::TargetConflict(
                    decision,
                ),
                _ => return Err(DecodeError::InvalidTag),
            }))
        }
        10 => {
            let rotation =
                super::system_authority::SystemAuthorityRotationId::from_bytes(decoder.fixed()?);
            let epoch = decoder.u64()?;
            let exact_retry = decoder.bool()?;
            if rotation == super::system_authority::SystemAuthorityRotationId::ZERO || epoch == 0 {
                return Err(DecodeError::NonCanonical);
            }
            Ok(LifecycleReply::SystemAuthorityRotated {
                rotation,
                epoch,
                exact_retry,
            })
        }
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
        LifecycleError::ResourceLimit => 13,
        LifecycleError::SystemAuthority(error) => {
            encoder.u8(14);
            encode_system_authority_error(encoder, error);
            return;
        }
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
        13 => LifecycleError::ResourceLimit,
        14 => LifecycleError::SystemAuthority(decode_system_authority_error(decoder)?),
        _ => return Err(DecodeError::InvalidTag),
    })
}

fn encode_system_authority_error(
    encoder: &mut Encoder<'_>,
    error: super::system_authority::SystemAuthorityError,
) {
    use super::system_authority::SystemAuthorityError;
    let tag = match error {
        SystemAuthorityError::InvalidGenesis => 0,
        SystemAuthorityError::InvalidScope => 1,
        SystemAuthorityError::InvalidState => 2,
        SystemAuthorityError::InvalidDecisionFact => 3,
        SystemAuthorityError::InvalidDecisionNode => 4,
        SystemAuthorityError::InvalidDecisionProof => 5,
        SystemAuthorityError::InvalidRotationNode => 6,
        SystemAuthorityError::InvalidRotationProof => 7,
        SystemAuthorityError::InvalidFinalize => 8,
        SystemAuthorityError::InvalidProvision => 9,
        SystemAuthorityError::WrongSystemAgent => 10,
        SystemAuthorityError::StaleCommittee => 11,
        SystemAuthorityError::SequenceConflict => 12,
        SystemAuthorityError::RotationFirstSequencePending => 13,
        SystemAuthorityError::Capacity => 14,
        SystemAuthorityError::LimitExceeded => 15,
        SystemAuthorityError::Authority(error) => {
            encoder.u8(16);
            encode_authority_committee_error(encoder, error);
            return;
        }
        SystemAuthorityError::Genesis(error) => {
            encoder.u8(17);
            encode_agent_genesis_error(encoder, error);
            return;
        }
    };
    encoder.u8(tag);
}

fn decode_system_authority_error(
    decoder: &mut Decoder<'_>,
) -> Result<super::system_authority::SystemAuthorityError, DecodeError> {
    use super::system_authority::SystemAuthorityError;
    Ok(match decoder.u8()? {
        0 => SystemAuthorityError::InvalidGenesis,
        1 => SystemAuthorityError::InvalidScope,
        2 => SystemAuthorityError::InvalidState,
        3 => SystemAuthorityError::InvalidDecisionFact,
        4 => SystemAuthorityError::InvalidDecisionNode,
        5 => SystemAuthorityError::InvalidDecisionProof,
        6 => SystemAuthorityError::InvalidRotationNode,
        7 => SystemAuthorityError::InvalidRotationProof,
        8 => SystemAuthorityError::InvalidFinalize,
        9 => SystemAuthorityError::InvalidProvision,
        10 => SystemAuthorityError::WrongSystemAgent,
        11 => SystemAuthorityError::StaleCommittee,
        12 => SystemAuthorityError::SequenceConflict,
        13 => SystemAuthorityError::RotationFirstSequencePending,
        14 => SystemAuthorityError::Capacity,
        15 => SystemAuthorityError::LimitExceeded,
        16 => SystemAuthorityError::Authority(decode_authority_committee_error(decoder)?),
        17 => SystemAuthorityError::Genesis(decode_agent_genesis_error(decoder)?),
        _ => return Err(DecodeError::InvalidTag),
    })
}

fn encode_agent_genesis_error(encoder: &mut Encoder<'_>, error: super::genesis::AgentGenesisError) {
    use super::genesis::AgentGenesisError;
    let tag = match error {
        AgentGenesisError::InvalidLocator => 0,
        AgentGenesisError::InvalidExpectations => 1,
        AgentGenesisError::InvalidProposal => 2,
        AgentGenesisError::InvalidReplicaCommittee => 3,
        AgentGenesisError::InvalidClaim => 4,
        AgentGenesisError::InvalidEvidence => 5,
        AgentGenesisError::InvalidDecision => 6,
        AgentGenesisError::InvalidAdmission => 7,
        AgentGenesisError::InvalidProvision => 8,
        AgentGenesisError::InvalidCatalog => 9,
        AgentGenesisError::LimitExceeded => 10,
        AgentGenesisError::Authority(error) => {
            encoder.u8(11);
            encode_authority_committee_error(encoder, error);
            return;
        }
    };
    encoder.u8(tag);
}

fn decode_agent_genesis_error(
    decoder: &mut Decoder<'_>,
) -> Result<super::genesis::AgentGenesisError, DecodeError> {
    use super::genesis::AgentGenesisError;
    Ok(match decoder.u8()? {
        0 => AgentGenesisError::InvalidLocator,
        1 => AgentGenesisError::InvalidExpectations,
        2 => AgentGenesisError::InvalidProposal,
        3 => AgentGenesisError::InvalidReplicaCommittee,
        4 => AgentGenesisError::InvalidClaim,
        5 => AgentGenesisError::InvalidEvidence,
        6 => AgentGenesisError::InvalidDecision,
        7 => AgentGenesisError::InvalidAdmission,
        8 => AgentGenesisError::InvalidProvision,
        9 => AgentGenesisError::InvalidCatalog,
        10 => AgentGenesisError::LimitExceeded,
        11 => AgentGenesisError::Authority(decode_authority_committee_error(decoder)?),
        _ => return Err(DecodeError::InvalidTag),
    })
}

fn encode_authority_committee_error(
    encoder: &mut Encoder<'_>,
    error: super::committee::AuthorityCommitteeError,
) {
    use super::committee::AuthorityCommitteeError;
    let tag = match error {
        AuthorityCommitteeError::InvalidBinding => 0,
        AuthorityCommitteeError::InvalidMember => 1,
        AuthorityCommitteeError::InvalidSigner => 2,
        AuthorityCommitteeError::InvalidEpoch => 3,
        AuthorityCommitteeError::InvalidPreviousCommittee => 4,
        AuthorityCommitteeError::CommitteeTooLarge => 5,
        AuthorityCommitteeError::CertificateTooLarge => 6,
        AuthorityCommitteeError::NoVoters => 7,
        AuthorityCommitteeError::DuplicateNode => 8,
        AuthorityCommitteeError::NonCanonicalOrder => 9,
        AuthorityCommitteeError::InvalidClaim => 10,
        AuthorityCommitteeError::WrongAuthorityBinding => 11,
        AuthorityCommitteeError::WrongEpoch => 12,
        AuthorityCommitteeError::WrongCommittee => 13,
        AuthorityCommitteeError::WrongClaim => 14,
        AuthorityCommitteeError::UnknownSigner => 15,
        AuthorityCommitteeError::ObserverSignature => 16,
        AuthorityCommitteeError::InsufficientQuorum => 17,
        AuthorityCommitteeError::InvalidSignature => 18,
        AuthorityCommitteeError::InvalidRotationEpoch => 19,
        AuthorityCommitteeError::InvalidRotationLink => 20,
        AuthorityCommitteeError::InvalidRotationSequence => 21,
        AuthorityCommitteeError::InvalidRootAnchor => 22,
        AuthorityCommitteeError::RootAnchorTooLarge => 23,
        AuthorityCommitteeError::InvalidGenesisIntent => 24,
        AuthorityCommitteeError::InvalidGenesisExpectation => 25,
        AuthorityCommitteeError::InvalidGenesisClaim => 26,
        AuthorityCommitteeError::GenesisEvidenceTooLarge => 27,
        AuthorityCommitteeError::InvalidGenesisAdmission => 28,
        AuthorityCommitteeError::GenesisAdmissionTooLarge => 29,
        AuthorityCommitteeError::InvalidBootstrapAnchor => 30,
        AuthorityCommitteeError::WrongBootstrapAnchor => 31,
        AuthorityCommitteeError::WrongGenesisIntent => 32,
        AuthorityCommitteeError::WrongGenesisExpectation => 33,
    };
    encoder.u8(tag);
}

fn decode_authority_committee_error(
    decoder: &mut Decoder<'_>,
) -> Result<super::committee::AuthorityCommitteeError, DecodeError> {
    use super::committee::AuthorityCommitteeError;
    Ok(match decoder.u8()? {
        0 => AuthorityCommitteeError::InvalidBinding,
        1 => AuthorityCommitteeError::InvalidMember,
        2 => AuthorityCommitteeError::InvalidSigner,
        3 => AuthorityCommitteeError::InvalidEpoch,
        4 => AuthorityCommitteeError::InvalidPreviousCommittee,
        5 => AuthorityCommitteeError::CommitteeTooLarge,
        6 => AuthorityCommitteeError::CertificateTooLarge,
        7 => AuthorityCommitteeError::NoVoters,
        8 => AuthorityCommitteeError::DuplicateNode,
        9 => AuthorityCommitteeError::NonCanonicalOrder,
        10 => AuthorityCommitteeError::InvalidClaim,
        11 => AuthorityCommitteeError::WrongAuthorityBinding,
        12 => AuthorityCommitteeError::WrongEpoch,
        13 => AuthorityCommitteeError::WrongCommittee,
        14 => AuthorityCommitteeError::WrongClaim,
        15 => AuthorityCommitteeError::UnknownSigner,
        16 => AuthorityCommitteeError::ObserverSignature,
        17 => AuthorityCommitteeError::InsufficientQuorum,
        18 => AuthorityCommitteeError::InvalidSignature,
        19 => AuthorityCommitteeError::InvalidRotationEpoch,
        20 => AuthorityCommitteeError::InvalidRotationLink,
        21 => AuthorityCommitteeError::InvalidRotationSequence,
        22 => AuthorityCommitteeError::InvalidRootAnchor,
        23 => AuthorityCommitteeError::RootAnchorTooLarge,
        24 => AuthorityCommitteeError::InvalidGenesisIntent,
        25 => AuthorityCommitteeError::InvalidGenesisExpectation,
        26 => AuthorityCommitteeError::InvalidGenesisClaim,
        27 => AuthorityCommitteeError::GenesisEvidenceTooLarge,
        28 => AuthorityCommitteeError::InvalidGenesisAdmission,
        29 => AuthorityCommitteeError::GenesisAdmissionTooLarge,
        30 => AuthorityCommitteeError::InvalidBootstrapAnchor,
        31 => AuthorityCommitteeError::WrongBootstrapAnchor,
        32 => AuthorityCommitteeError::WrongGenesisIntent,
        33 => AuthorityCommitteeError::WrongGenesisExpectation,
        _ => return Err(DecodeError::InvalidTag),
    })
}

fn encode_config(encoder: &mut Encoder<'_>, config: &AgentConfig) {
    encode_identity(encoder, &config.identity);
    encoder.fixed(&config.creation_nonce.0);
    super::authority::encode_binding(encoder, &config.authority);
    encoder.option(&config.system_authority_genesis, |encoder, genesis| {
        encoder.bytes(&genesis.encode())
    });
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
    let identity = decode_identity(decoder)?;
    let creation_nonce = Hash(decoder.fixed()?);
    let authority = super::authority::decode_binding(decoder)?;
    let system_authority_genesis = decoder.option(|decoder| {
        let bytes = decoder.bytes_ref()?;
        if bytes.len() > super::system_authority::MAX_SYSTEM_AUTHORITY_GENESIS_BYTES {
            return Err(DecodeError::LimitExceeded);
        }
        super::system_authority::SystemAuthorityGenesis::decode(bytes)
    })?;
    let runtime_package = decode_blob(decoder)?;
    let runtime_contract = super::contract::decode_runtime_contract(decoder)?;
    let capabilities = decode_capabilities(decoder)?;
    let replica_count = decoder.u32()? as usize;
    if replica_count > super::MAX_AGENT_REPLICAS {
        return Err(DecodeError::LimitExceeded);
    }
    let mut replicas = Vec::new();
    replicas
        .try_reserve_exact(replica_count)
        .map_err(|_| DecodeError::LimitExceeded)?;
    for _ in 0..replica_count {
        replicas.push(AgentReplica {
            node: NodeId(decoder.fixed()?),
            principal: PrincipalId(decoder.fixed()?),
            role: match decoder.u8()? {
                0 => ReplicaRole::Voter,
                1 => ReplicaRole::Observer,
                _ => return Err(DecodeError::InvalidTag),
            },
        });
    }
    let config = AgentConfig {
        identity,
        creation_nonce,
        authority,
        system_authority_genesis,
        runtime_package,
        runtime_contract,
        capabilities,
        replicas,
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
    encoder.list(&page.entries, |encoder, record| {
        encode_entry(encoder, &record.entry);
        encoder.fixed(&record.incarnation.0);
    });
    encoder.option(&page.next, |encoder, next| encoder.fixed(&next.0));
}

fn decode_directory_page(decoder: &mut Decoder<'_>) -> Result<ActorDirectoryPage, DecodeError> {
    let entries = decode_bounded_list(
        decoder,
        usize::from(super::standard::MAX_DIRECTORY_PAGE),
        |decoder| {
            let entry = decode_entry(decoder)?;
            let incarnation = Hash(decoder.fixed()?);
            if incarnation == Hash::ZERO {
                return Err(DecodeError::NonCanonical);
            }
            Ok(ActorDirectoryRecord { entry, incarnation })
        },
    )?;
    if entries
        .windows(2)
        .any(|pair| pair[0].entry.actor >= pair[1].entry.actor)
    {
        return Err(DecodeError::NonCanonical);
    }
    let next = decoder.option(|decoder| Ok(ActorId(decoder.fixed()?)))?;
    if next.is_some() && next != entries.last().map(|record| record.entry.actor) {
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
            system_authority_genesis: None,
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

    fn sparse_standard_state() -> StandardRuntimeState {
        let config = config();
        let actor = ActorId::top_level(config.identity.agent, "sparse");
        let package = BlobRef {
            hash: Hash([0x81; 32]),
            len: 10,
        };
        let agent_schema = BlobRef {
            hash: Hash([0x82; 32]),
            len: 11,
        };
        let role_policies = BlobRef {
            hash: Hash([0x83; 32]),
            len: 12,
        };
        let generation = Hash([0x84; 32]);
        StandardRuntimeState {
            config: Some(config.clone()),
            system_authority: None,
            actors: vec![StandardActorState {
                record: super::super::ActorRecord {
                    entry: ActorEntry {
                        actor,
                        name: "sparse".into(),
                        parent: None,
                        deployment: DeploymentId([0x85; 32]),
                        program: ProgramId([0x86; 32]),
                        package: package.clone(),
                        agent_schema: agent_schema.clone(),
                        role_policies: role_policies.clone(),
                        state_layout: Hash([0x87; 32]),
                        lanes: LaneSet::ALL,
                        suspended: false,
                    },
                    state_generation: generation,
                    producer: ProducerId([0x88; 32]),
                    package,
                    agent_schema,
                    role_policies,
                    state_layout: Hash([0x87; 32]),
                    contract: super::super::contract::ActorPackageContract::canonical(),
                    requirements: RuntimeRequirements {
                        lanes: LaneSet::ALL,
                        scheduling: false,
                        proofs: false,
                    },
                },
                debt: ActorLifecycleDebt::default(),
            }],
            lane_state: StandardLaneState {
                linear: vec![StandardLaneEntry {
                    actor,
                    state_generation: generation,
                    value: vec![0x89],
                }],
                merge: Vec::new(),
                local: Vec::new(),
            },
            lane_revisions: super::super::standard::StandardLaneRevisions {
                linear: 1,
                ..Default::default()
            },
            authority_slot_high_water: Some(1),
            authority_sequence_high_water: Some(1),
            authority_dispositions: vec![StandardAuthorityDisposition {
                credential: crate::service::CredentialId([0x8a; 32]),
                sequence: 1,
                claim: Hash([0x8b; 32]),
                operation: Hash([0x8c; 32]),
                result: Ok(LifecycleReply::Created(config.identity)),
            }],
            ..Default::default()
        }
    }

    #[cfg(feature = "pvm")]
    fn sparse_invocation(mode: MethodMode, id: u8) -> ActorInvocation {
        let state = sparse_standard_state();
        let actor = &state.actors[0].record;
        ActorInvocation {
            invocation: crate::service::InvocationId([id; 32]),
            actor: actor.entry.actor,
            incarnation: actor.state_generation,
            deployment: actor.entry.deployment,
            program: actor.entry.program,
            mode,
            auth: ActorInvocationAuth::anonymous(),
            message: vec![1],
            availability: Vec::new(),
            gas: 100,
        }
    }

    #[cfg(feature = "pvm")]
    fn exact_reply(
        invocation: &ActorInvocation,
        status: ActorExecutionStatus,
    ) -> ActorExecutionReply {
        ActorExecutionReply {
            invocation: invocation.invocation,
            actor: invocation.actor,
            incarnation: invocation.incarnation,
            deployment: invocation.deployment,
            mode: invocation.mode,
            lane: invocation.mode.write_lane(),
            status,
            reply: vec![0xa5],
            gas_remaining: 50,
            observation: super::super::execution::ActorObservation::default(),
        }
    }

    #[cfg(feature = "pvm")]
    fn assert_only_result_component_changed(
        before: &RuntimeState,
        after: &RuntimeState,
        mode: MethodMode,
    ) {
        let changed = [
            before.control != after.control,
            before.linear != after.linear,
            before.merge != after.merge,
            before.local != after.local,
        ];
        let expected = match mode.result_storage() {
            super::super::InvocationResultStorage::Control => [true, false, false, false],
            super::super::InvocationResultStorage::Lane(StateLane::Linear) => {
                [false, true, false, false]
            }
            super::super::InvocationResultStorage::Lane(StateLane::Merge) => {
                [false, false, true, false]
            }
            super::super::InvocationResultStorage::Lane(StateLane::Local) => {
                [false, false, false, true]
            }
        };
        assert_eq!(changed, expected, "{mode:?}");
    }

    #[cfg(feature = "pvm")]
    fn exact_clock_successor(
        before: &StandardRuntimeState,
        mode: MethodMode,
        observed_slot: u64,
    ) -> StandardRuntimeState {
        let mut expected = before.clone();
        match mode.result_storage() {
            super::super::InvocationResultStorage::Control => {
                expected.control_authority_slot = Some(observed_slot);
            }
            super::super::InvocationResultStorage::Lane(StateLane::Linear) => {
                expected.lane_revisions.linear_authority_slot = Some(observed_slot);
            }
            super::super::InvocationResultStorage::Lane(StateLane::Merge) => {
                expected.lane_revisions.merge_authority_slot = Some(observed_slot);
            }
            super::super::InvocationResultStorage::Lane(StateLane::Local) => {
                expected.lane_revisions.local_authority_slot = Some(observed_slot);
            }
        }
        expected
    }

    #[cfg(feature = "pvm")]
    fn signed_invocation_receipt(
        config: &AgentConfig,
        invocation: &ActorInvocation,
        valid_from: u64,
        valid_until: u64,
    ) -> crate::agent::authority::ActorInvocationReceipt {
        let claim = crate::agent::authority::ActorInvocationClaim {
            authority: config.authority.clone(),
            space: config.identity.space,
            agent: config.identity.agent,
            principal: None,
            credential: None,
            authorization: invocation.authorization_message(),
            auth: invocation.auth.clone(),
            valid_from,
            valid_until,
        };
        crate::agent::authority::ActorInvocationReceipt {
            signature: authority_key()
                .sign(&claim.signing_message().0)
                .to_bytes()
                .to_vec(),
            claim,
        }
    }

    #[cfg(feature = "pvm")]
    fn forbidden_execution_call(observed_slot: u64, valid_until: u64) -> RuntimeExecutionCall {
        use crate::actors::codec::Encode as _;
        use crate::actors::value::{Msg, TAG_DYNAMIC};
        use crate::service::{MethodPolicy, method_authorization_policy_hash};

        let mut state = sparse_standard_state();
        let actor_pvm = vec![0x21, 0x22, 0x23];
        let program = ProgramId::of_pvm(&actor_pvm);
        let (schema, schema_len) =
            crate::agent::schema::encode::<512>(&crate::agent::schema::SchemaMeta {
                uses_storage: false,
                fields: &[],
                methods: &[crate::agent::schema::MethodMeta {
                    name: "private_call",
                    mode: MethodMode::Linear,
                    explicit: true,
                }],
            });
        let schema = schema[..schema_len].to_vec();
        let parsed = crate::agent::schema::decode(&schema).unwrap();
        let capability = CapabilityId::named("private.call");
        let policies = crate::service::PackageRolePolicies {
            methods: vec![MethodPolicy {
                method: "private_call".into(),
                schema: Hash([0x91; 32]),
                policy: method_authorization_policy_hash(Some(capability), None, None).unwrap(),
                public: false,
                attested: false,
                space_role: None,
                capability: Some(capability),
                actor_role: None,
            }],
            task_dependencies: Vec::new(),
        }
        .encode();
        let schema_blob = RuntimeBlob {
            reference: BlobRef::of_bytes(&schema),
            bytes: schema,
        };
        let policy_blob = RuntimeBlob {
            reference: BlobRef::of_bytes(&policies),
            bytes: policies,
        };
        let actor = &mut state.actors[0].record;
        actor.entry.program = program;
        actor.entry.agent_schema = schema_blob.reference.clone();
        actor.agent_schema = schema_blob.reference.clone();
        actor.entry.role_policies = policy_blob.reference.clone();
        actor.role_policies = policy_blob.reference.clone();
        actor.entry.state_layout = parsed.state_layout_hash();
        actor.state_layout = parsed.state_layout_hash();
        actor.entry.lanes = parsed.lanes();
        actor.requirements.lanes = parsed.lanes();
        let mut message = vec![TAG_DYNAMIC];
        message.extend_from_slice(&Msg::new("private_call").encode());
        let invocation = ActorInvocation {
            invocation: crate::service::InvocationId([0x92; 32]),
            actor: actor.entry.actor,
            incarnation: actor.state_generation,
            deployment: actor.entry.deployment,
            program,
            mode: MethodMode::Linear,
            auth: ActorInvocationAuth::anonymous(),
            message,
            availability: Vec::new(),
            gas: 100,
        };
        let authority =
            signed_invocation_receipt(state.config.as_ref().unwrap(), &invocation, 0, valid_until);
        RuntimeExecutionCall {
            state: encode_standard_runtime_state(&state),
            invocation,
            authority,
            observed_slot,
            recovery_only: false,
            actor_pvm,
            actor_schema: schema_blob,
            actor_policies: policy_blob,
        }
    }

    #[cfg(feature = "pvm")]
    fn unsupported_result_storage_call(observed_slot: u64) -> RuntimeExecutionCall {
        let mut call = forbidden_execution_call(observed_slot, observed_slot.saturating_add(10));
        let mut state = decode_standard_runtime_state(&call.state).unwrap();
        {
            let config = state.config.as_mut().unwrap();
            config.identity.profile = AgentProfile::Private;
            config.capabilities.lanes =
                LaneSet::of(StateLane::Merge).union(LaneSet::of(StateLane::Local));
            for replica in &mut config.replicas {
                replica.principal = config.identity.owner;
                replica.role = ReplicaRole::Observer;
            }
        }
        let actor = &mut state.actors[0].record;
        actor.entry.lanes = LaneSet::of(StateLane::Merge);
        actor.requirements.lanes = LaneSet::of(StateLane::Merge);
        state.lane_state.linear.clear();
        state.lane_revisions = Default::default();
        call.invocation.mode = MethodMode::LinearizableQuery;
        call.authority = signed_invocation_receipt(
            state.config.as_ref().unwrap(),
            &call.invocation,
            0,
            observed_slot.saturating_add(10),
        );
        call.state = encode_standard_runtime_state(&state);
        call
    }

    #[test]
    fn sparse_lane_state_round_trips_and_missing_is_the_only_empty_encoding() {
        let state = sparse_standard_state();
        let encoded = encode_standard_runtime_state(&state);
        assert_eq!(decode_standard_runtime_state(&encoded).unwrap(), state);

        let mut missing = state.clone();
        missing.lane_state.linear.clear();
        let encoded_missing = encode_standard_runtime_state(&missing);
        assert_eq!(
            decode_standard_runtime_state(&encoded_missing).unwrap(),
            missing,
            "a supported missing entry is canonical fresh-empty state"
        );

        let mut explicit_empty = state.clone();
        explicit_empty.lane_state.linear[0].value.clear();
        assert_eq!(
            decode_standard_runtime_state(&encode_standard_runtime_state(&explicit_empty)),
            Err(DecodeError::NonCanonical),
            "explicit empty and missing must never encode the same logical state"
        );
    }

    #[cfg(feature = "pvm")]
    #[test]
    fn exact_terminal_and_error_outcomes_commit_only_the_result_clock() {
        let base = sparse_standard_state();
        let before = encode_standard_runtime_state(&base);
        let modes = [
            MethodMode::Query,
            MethodMode::LinearizableQuery,
            MethodMode::Linear,
            MethodMode::Merge,
            MethodMode::LocalQuery,
            MethodMode::Local,
        ];

        for (index, status) in [
            ActorExecutionStatus::Forbidden,
            ActorExecutionStatus::Panicked,
            ActorExecutionStatus::OutOfGas,
        ]
        .into_iter()
        .enumerate()
        {
            let mode = modes[index * 2];
            let invocation = sparse_invocation(mode, 0xa0 + index as u8);
            let pristine = StandardAgentRuntime::restore(base.clone()).unwrap();
            let mut runtime = pristine.clone();
            runtime.commit_exact_outcome_clock(&invocation, 99).unwrap();
            let mut result = Ok(exact_reply(&invocation, status));
            assert!(finalize_unseen_standard_outcome(
                &mut runtime,
                pristine,
                &invocation,
                40,
                &mut result,
            ));
            let snapshot = runtime.snapshot();
            assert_eq!(snapshot, exact_clock_successor(&base, mode, 40));
            assert!(snapshot.invocation_results.is_empty());
            assert_eq!(snapshot.lane_state, base.lane_state);
            assert_eq!(
                (
                    snapshot.lane_revisions.linear,
                    snapshot.lane_revisions.merge,
                    snapshot.lane_revisions.local,
                ),
                (
                    base.lane_revisions.linear,
                    base.lane_revisions.merge,
                    base.lane_revisions.local,
                )
            );
            let after = encode_standard_runtime_state(&snapshot);
            assert_only_result_component_changed(&before, &after, mode);
            let reopened =
                StandardAgentRuntime::restore(decode_standard_runtime_state(&after).unwrap())
                    .unwrap();
            assert_eq!(reopened.snapshot(), snapshot);
        }

        let durable_errors = [
            ActorExecutionError::NotFound,
            ActorExecutionError::StaleIncarnation,
            ActorExecutionError::Suspended,
            ActorExecutionError::StaleDeployment,
            ActorExecutionError::WrongProgram,
            ActorExecutionError::UnsupportedMethod,
            ActorExecutionError::InvalidInput,
            ActorExecutionError::InvalidActorOutput,
            ActorExecutionError::UnsupportedHostCall(u64::MAX),
        ];
        for (index, error) in durable_errors.into_iter().enumerate() {
            let mode = modes[index % modes.len()];
            let invocation = sparse_invocation(mode, 0xb0 + index as u8);
            let pristine = StandardAgentRuntime::restore(base.clone()).unwrap();
            let mut runtime = pristine.clone();
            runtime.commit_exact_outcome_clock(&invocation, 99).unwrap();
            let mut result = Err(error);
            assert!(finalize_unseen_standard_outcome(
                &mut runtime,
                pristine,
                &invocation,
                41,
                &mut result,
            ));
            let snapshot = runtime.snapshot();
            assert_eq!(
                snapshot,
                exact_clock_successor(&base, mode, 41),
                "{error:?}"
            );
            assert!(snapshot.invocation_results.is_empty(), "{error:?}");
            assert_eq!(snapshot.lane_state, base.lane_state, "{error:?}");
            assert_only_result_component_changed(
                &before,
                &encode_standard_runtime_state(&snapshot),
                mode,
            );
        }
    }

    #[cfg(feature = "pvm")]
    #[test]
    fn done_keeps_its_guest_result_and_lane_commit() {
        let base = sparse_standard_state();
        let before_encoded = encode_standard_runtime_state(&base);
        let invocation = sparse_invocation(MethodMode::Linear, 0xaf);
        let mut runtime = StandardAgentRuntime::restore(base.clone()).unwrap();
        let before = runtime.prepare_execution_state(&invocation).unwrap();
        let mut after = before.visible_for(invocation.mode);
        after.linear = Some(vec![0xd0]);
        let mut reply = exact_reply(&invocation, ActorExecutionStatus::Done);
        runtime
            .commit_execution(&invocation, &mut reply, &before, after, 40)
            .unwrap();

        let snapshot = runtime.snapshot();
        assert_eq!(snapshot.invocation_results.len(), 1);
        assert_eq!(snapshot.invocation_results[0].reply, reply);
        assert_eq!(
            snapshot.lane_revisions.linear,
            base.lane_revisions.linear + 1
        );
        assert_eq!(snapshot.lane_revisions.linear_authority_slot, Some(40));
        assert_eq!(snapshot.lane_state.linear[0].value, vec![0xd0]);
        assert_only_result_component_changed(
            &before_encoded,
            &encode_standard_runtime_state(&snapshot),
            MethodMode::Linear,
        );
    }

    #[cfg(feature = "pvm")]
    #[test]
    fn actor_execution_refuses_a_candidate_past_the_signed_state_ceiling() {
        fn done_candidate(
            state: StandardRuntimeState,
        ) -> (
            RuntimeState,
            StandardAgentRuntime,
            Result<ActorExecutionReply, ActorExecutionError>,
        ) {
            let original = encode_standard_runtime_state(&state);
            let invocation = sparse_invocation(MethodMode::Linear, 0x90);
            let mut runtime = StandardAgentRuntime::restore(state).unwrap();
            let before = runtime.prepare_execution_state(&invocation).unwrap();
            let mut after = before.visible_for(invocation.mode);
            after.linear = Some(vec![0x2a]);
            let mut reply = exact_reply(&invocation, ActorExecutionStatus::Done);
            runtime
                .commit_execution(&invocation, &mut reply, &before, after, 50)
                .unwrap();
            (original, runtime, Ok(reply))
        }

        let hard_limit = super::super::execution::MAX_RUNTIME_STATE_BYTES;
        let base = sparse_standard_state();
        let (hard_before, hard_candidate, mut accepted_result) = done_candidate(base.clone());
        let hard_before_len = hard_before.encoded_len().unwrap();
        let accepted = finish_standard_execution_candidate(
            hard_before,
            &hard_candidate,
            true,
            hard_limit,
            &mut accepted_result,
        );
        assert!(matches!(
            accepted_result,
            Ok(ActorExecutionReply {
                status: ActorExecutionStatus::Done,
                ..
            })
        ));
        let candidate_len = accepted.encoded_len().unwrap();
        assert!(candidate_len > hard_before_len);
        assert!(candidate_len <= hard_limit);
        let accepted_state = decode_standard_runtime_state(&accepted).unwrap();
        assert_eq!(accepted_state.invocation_results.len(), 1);
        assert_eq!(accepted_state.lane_state.linear[0].value, vec![0x2a]);

        let signed_limit = u32::try_from(candidate_len - 1).unwrap();
        let mut constrained_state = base;
        constrained_state
            .config
            .as_mut()
            .unwrap()
            .runtime_contract
            .resources
            .max_runtime_state_bytes = signed_limit;
        let (before, constrained_candidate, mut constrained_result) =
            done_candidate(constrained_state);
        assert_eq!(before.encoded_len(), Some(hard_before_len));
        assert!(hard_before_len <= signed_limit as usize);
        let before_decoded = decode_standard_runtime_state(&before).unwrap();
        assert_eq!(
            before_decoded
                .config
                .as_ref()
                .unwrap()
                .runtime_contract
                .resources
                .max_runtime_state_bytes,
            signed_limit
        );

        let returned = finish_standard_execution_candidate(
            before.clone(),
            &constrained_candidate,
            true,
            signed_limit as usize,
            &mut constrained_result,
        );
        assert_eq!(constrained_result, Err(ActorExecutionError::ResultCapacity));
        assert_eq!(returned, before);
        assert_eq!(
            decode_standard_runtime_state(&returned).unwrap(),
            before_decoded
        );
        assert_eq!(before_decoded.lane_revisions.linear_authority_slot, None);
        assert!(before_decoded.invocation_results.is_empty());
        assert_eq!(before_decoded.lane_state.linear[0].value, vec![0x89]);
    }

    #[cfg(feature = "pvm")]
    #[test]
    fn unavailable_admission_and_inconsistent_errors_commit_nothing() {
        let base = sparse_standard_state();
        for (index, error) in [
            ActorExecutionError::NotCreated,
            ActorExecutionError::UnsupportedResultStorage,
            ActorExecutionError::MissingState,
            ActorExecutionError::InvalidAvailability,
            ActorExecutionError::DivergentInvocation,
            ActorExecutionError::ResultCapacity,
            ActorExecutionError::InvalidAuthorization,
            ActorExecutionError::AuthorityExpired,
            ActorExecutionError::AuthoritySlotRegressed,
        ]
        .into_iter()
        .enumerate()
        {
            let invocation = sparse_invocation(MethodMode::Linear, 0xc0 + index as u8);
            let pristine = StandardAgentRuntime::restore(base.clone()).unwrap();
            let mut runtime = pristine.clone();
            runtime.commit_exact_outcome_clock(&invocation, 99).unwrap();
            let mut result = Err(error);
            assert!(!finalize_unseen_standard_outcome(
                &mut runtime,
                pristine,
                &invocation,
                42,
                &mut result,
            ));
            assert_eq!(runtime.snapshot(), base, "{error:?}");
        }
    }

    #[cfg(feature = "pvm")]
    #[test]
    fn unsupported_result_storage_is_pre_admission_and_never_commits_a_clock() {
        let call = unsupported_result_storage_call(43);
        let before = call.state.clone();
        let returned = apply_standard_execution(call).unwrap();
        assert_eq!(
            returned.result,
            Err(ActorExecutionError::UnsupportedResultStorage)
        );
        assert_eq!(returned.state, before);
        let decoded = decode_standard_runtime_state(&returned.state).unwrap();
        assert_eq!(decoded.control_authority_slot, None);
        assert_eq!(decoded.lane_revisions.linear_authority_slot, None);
        assert_eq!(decoded.lane_revisions.merge_authority_slot, None);
        assert_eq!(decoded.lane_revisions.local_authority_slot, None);
        assert!(decoded.invocation_results.is_empty());
    }

    #[cfg(feature = "pvm")]
    #[test]
    fn forbidden_checks_freshness_then_persists_its_clock_across_restart() {
        let expired = forbidden_execution_call(31, 30);
        let original = expired.state.clone();
        let returned = apply_standard_execution(expired).unwrap();
        assert_eq!(returned.result, Err(ActorExecutionError::AuthorityExpired));
        assert_eq!(returned.state, original);

        let admitted = forbidden_execution_call(30, 100);
        let before = admitted.state.clone();
        let returned = apply_standard_execution(admitted.clone()).unwrap();
        assert!(matches!(
            returned.result,
            Ok(ActorExecutionReply {
                status: ActorExecutionStatus::Forbidden,
                ..
            })
        ));
        assert_only_result_component_changed(&before, &returned.state, MethodMode::Linear);
        let decoded = decode_standard_runtime_state(&returned.state).unwrap();
        assert_eq!(
            decoded,
            exact_clock_successor(
                &decode_standard_runtime_state(&before).unwrap(),
                MethodMode::Linear,
                30,
            )
        );
        assert_eq!(decoded.lane_revisions.linear_authority_slot, Some(30));
        assert!(decoded.invocation_results.is_empty());

        let reopened = encode_standard_runtime_state(
            &StandardAgentRuntime::restore(decoded).unwrap().snapshot(),
        );
        assert_eq!(reopened, returned.state);
        let mut regressed = admitted;
        regressed.state = reopened;
        regressed.observed_slot = 29;
        regressed.invocation.invocation = crate::service::InvocationId([0x93; 32]);
        regressed.authority = signed_invocation_receipt(
            sparse_standard_state().config.as_ref().unwrap(),
            &regressed.invocation,
            0,
            100,
        );
        let prior = regressed.state.clone();
        let returned = apply_standard_execution(regressed).unwrap();
        assert_eq!(
            returned.result,
            Err(ActorExecutionError::AuthoritySlotRegressed)
        );
        assert_eq!(returned.state, prior);
    }

    #[cfg(feature = "pvm")]
    #[test]
    fn durable_target_errors_commit_a_clock_but_unavailable_and_auth_failures_do_not() {
        let mut missing = forbidden_execution_call(20, 100);
        missing.invocation.actor = ActorId([0xe1; 32]);
        missing.authority = signed_invocation_receipt(
            sparse_standard_state().config.as_ref().unwrap(),
            &missing.invocation,
            0,
            100,
        );
        let before = missing.state.clone();
        let returned = apply_standard_execution(missing).unwrap();
        assert_eq!(returned.result, Err(ActorExecutionError::NotFound));
        assert_only_result_component_changed(&before, &returned.state, MethodMode::Linear);
        let decoded = decode_standard_runtime_state(&returned.state).unwrap();
        assert_eq!(
            decoded,
            exact_clock_successor(
                &decode_standard_runtime_state(&before).unwrap(),
                MethodMode::Linear,
                20,
            )
        );
        assert_eq!(decoded.lane_revisions.linear_authority_slot, Some(20));
        assert!(decoded.invocation_results.is_empty());

        let mut unavailable = forbidden_execution_call(21, 100);
        unavailable.recovery_only = true;
        unavailable.actor_pvm.clear();
        unavailable.actor_schema = RuntimeBlob {
            reference: BlobRef {
                hash: Hash::ZERO,
                len: 0,
            },
            bytes: Vec::new(),
        };
        unavailable.actor_policies = unavailable.actor_schema.clone();
        let before = unavailable.state.clone();
        let returned = apply_standard_execution(unavailable).unwrap();
        assert_eq!(
            returned.result,
            Err(ActorExecutionError::InvalidAvailability)
        );
        assert_eq!(returned.state, before);

        let mut forged = forbidden_execution_call(22, 100);
        forged.authority.signature[0] ^= 1;
        let before = forged.state.clone();
        let returned = apply_standard_execution(forged).unwrap();
        assert_eq!(
            returned.result,
            Err(ActorExecutionError::InvalidAuthorization)
        );
        assert_eq!(returned.state, before);
    }

    #[test]
    fn sparse_lane_state_rejects_duplicate_unsorted_and_oversized_cardinality() {
        let state = sparse_standard_state();
        let mut duplicate = state.clone();
        duplicate
            .lane_state
            .linear
            .push(duplicate.lane_state.linear[0].clone());
        assert_eq!(
            decode_standard_runtime_state(&encode_standard_runtime_state(&duplicate)),
            Err(DecodeError::NonCanonical)
        );

        let mut unsorted = state.clone();
        unsorted.lane_state.linear = vec![
            StandardLaneEntry {
                actor: ActorId([2; 32]),
                state_generation: Hash([1; 32]),
                value: vec![1],
            },
            StandardLaneEntry {
                actor: ActorId([1; 32]),
                state_generation: Hash([1; 32]),
                value: vec![2],
            },
        ];
        assert_eq!(
            decode_standard_runtime_state(&encode_standard_runtime_state(&unsorted)),
            Err(DecodeError::NonCanonical)
        );

        let mut zero_generation = state.clone();
        zero_generation.lane_state.linear[0].state_generation = Hash::ZERO;
        assert_eq!(
            decode_standard_runtime_state(&encode_standard_runtime_state(&zero_generation)),
            Err(DecodeError::NonCanonical)
        );

        let mut encoded = encode_standard_runtime_state(&state);
        const LANE_LIST_OFFSET: usize = 32 + 1 + 8 + 1;
        encoded.linear[LANE_LIST_OFFSET..LANE_LIST_OFFSET + 4].copy_from_slice(
            &u32::try_from(super::super::standard::MAX_LANE_STATE_ENTRIES + 1)
                .unwrap()
                .to_le_bytes(),
        );
        assert_eq!(
            decode_standard_runtime_state(&encoded),
            Err(DecodeError::LimitExceeded),
            "declared lane cardinality is rejected before entry allocation"
        );
    }

    #[test]
    fn lifecycle_call_round_trips_with_opaque_runtime_state() {
        let call = RuntimeCall::new(
            RuntimeState {
                control: vec![11],
                linear: vec![12],
                merge: vec![13],
                local: vec![14],
            },
            LifecycleRequest::Create(config()),
        );
        let encoded = call.encode();
        assert_eq!(RuntimeCall::decode(&encoded).unwrap(), call);
    }

    #[test]
    fn journal_context_round_trips_but_zero_ids_are_noncanonical() {
        let scope = super::super::system_authority::SystemAuthorityJournalScope::for_test(
            super::super::journal::AgentJournalGenesisId::new([0x31; 32]),
            super::super::genesis::AgentGenesisAdmissionId::from_bytes([0x32; 32]),
        )
        .unwrap();
        let call = RuntimeCall::scoped_system_authority(
            RuntimeState::default(),
            LifecycleRequest::Inspect {
                after: None,
                limit: 1,
            },
            scope,
        );
        let encoded = call.encode();
        let decoded = RuntimeCall::decode(&encoded).unwrap();
        assert_eq!(decoded, call);
        assert!(
            decoded
                .journal_context()
                .unwrap()
                .matches_system_authority_scope(scope)
        );

        // ServiceWire header (36) + runtime ABI (32) + Some tag (1).
        let mut zero_genesis = encoded.clone();
        zero_genesis[69..101].fill(0);
        assert_eq!(
            RuntimeCall::decode(&zero_genesis),
            Err(DecodeError::NonCanonical)
        );
        let mut zero_admission = encoded;
        zero_admission[101..133].fill(0);
        assert_eq!(
            RuntimeCall::decode(&zero_admission),
            Err(DecodeError::NonCanonical)
        );
    }

    #[test]
    fn direct_system_authority_payloads_are_bounded_before_nested_decode() {
        for (tag, maximum) in [
            (
                10,
                super::super::system_authority::MAX_SYSTEM_AUTHORITY_FINALIZE_BYTES,
            ),
            (
                11,
                super::super::system_authority::MAX_SYSTEM_AUTHORITY_ROTATION_BYTES,
            ),
        ] {
            let mut encoded = Vec::new();
            encoded.extend_from_slice(&RuntimeCall::MAGIC);
            encoded.extend_from_slice(&crate::service::PLATFORM_ID.0);
            {
                let mut encoder = Encoder(&mut encoded);
                encoder.fixed(&super::super::RUNTIME_ABI_ID.0);
                encoder.bool(false);
                encode_runtime_state(&mut encoder, &RuntimeState::default());
                encoder.u8(tag);
                encoder.u32(u32::try_from(maximum + 1).unwrap());
            }
            encoded.resize(encoded.len() + maximum + 1, 0);
            assert_eq!(
                RuntimeCall::decode(&encoded),
                Err(DecodeError::LimitExceeded)
            );
        }
    }

    #[test]
    fn system_authority_genesis_and_state_are_bounded_before_nested_decode() {
        let config = config();
        let genesis_maximum = super::super::system_authority::MAX_SYSTEM_AUTHORITY_GENESIS_BYTES;
        let mut encoded_config = Vec::new();
        encoded_config.extend_from_slice(&AgentConfig::MAGIC);
        encoded_config.extend_from_slice(&crate::service::PLATFORM_ID.0);
        {
            let mut encoder = Encoder(&mut encoded_config);
            encoder.fixed(&super::super::RUNTIME_ABI_ID.0);
            encode_identity(&mut encoder, &config.identity);
            encoder.fixed(&config.creation_nonce.0);
            super::super::authority::encode_binding(&mut encoder, &config.authority);
            encoder.bool(true);
            encoder.u32(u32::try_from(genesis_maximum + 1).unwrap());
        }
        encoded_config.resize(encoded_config.len() + genesis_maximum + 1, 0);
        assert_eq!(
            AgentConfig::decode(&encoded_config),
            Err(DecodeError::LimitExceeded),
            "an oversized nested genesis is rejected before its body is decoded"
        );

        let state_maximum = super::super::system_authority::MAX_SYSTEM_AUTHORITY_STATE_BYTES;
        let mut control = Vec::new();
        {
            let mut encoder = Encoder(&mut control);
            encoder.fixed(&super::super::RUNTIME_ABI_ID.0);
            encoder.bool(false);
            encoder.bool(true);
            encoder.u32(u32::try_from(state_maximum + 1).unwrap());
        }
        control.resize(control.len() + state_maximum + 1, 0);
        let state = RuntimeState {
            control,
            linear: vec![1],
            merge: vec![1],
            local: vec![1],
        };
        assert_eq!(
            decode_standard_runtime_state(&state),
            Err(DecodeError::LimitExceeded),
            "an oversized nested authority state is rejected before its body is decoded"
        );
    }

    #[test]
    fn suspend_and_resume_wire_bind_the_expected_deployment() {
        let state = RuntimeState {
            control: vec![11],
            linear: vec![12],
            merge: vec![13],
            local: vec![14],
        };
        let actor = ActorId([0x31; 32]);
        let expected_deployment = DeploymentId([0x32; 32]);
        for request in [
            LifecycleRequest::Suspend {
                actor,
                expected_deployment,
            },
            LifecycleRequest::Resume {
                actor,
                expected_deployment,
            },
        ] {
            let call = RuntimeCall::new(state.clone(), request);
            let encoded = call.encode();
            assert_eq!(RuntimeCall::decode(&encoded).unwrap(), call);
            assert_eq!(
                RuntimeCall::decode(&encoded[..encoded.len() - 32]),
                Err(DecodeError::Truncated),
                "the retired ActorId-only lifecycle wire is not accepted"
            );
        }
    }

    #[test]
    fn lifecycle_wire_rejects_nested_authorized_envelopes() {
        let config = config();
        let request = LifecycleRequest::Suspend {
            actor: ActorId([0x35; 32]),
            expected_deployment: DeploymentId([0x36; 32]),
        };
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
        let call = RuntimeCall::new(
            RuntimeState::default(),
            LifecycleRequest::Authorized {
                admission: admission.clone(),
                request: alloc::boxed::Box::new(LifecycleRequest::Authorized {
                    admission,
                    request: alloc::boxed::Box::new(request),
                }),
            },
        );
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
                entries: vec![ActorDirectoryRecord {
                    entry: entry.clone(),
                    incarnation: Hash([0x44; 32]),
                }],
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
            incarnation: Hash([0x45; 32]),
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
    fn execution_errors_round_trip_every_tag_and_a_wide_host_identifier() {
        for error in [
            ActorExecutionError::NotCreated,
            ActorExecutionError::NotFound,
            ActorExecutionError::StaleIncarnation,
            ActorExecutionError::Suspended,
            ActorExecutionError::StaleDeployment,
            ActorExecutionError::WrongProgram,
            ActorExecutionError::UnsupportedMethod,
            ActorExecutionError::UnsupportedResultStorage,
            ActorExecutionError::MissingState,
            ActorExecutionError::InvalidAvailability,
            ActorExecutionError::InvalidInput,
            ActorExecutionError::InvalidActorOutput,
            ActorExecutionError::DivergentInvocation,
            ActorExecutionError::ResultCapacity,
            ActorExecutionError::InvalidAuthorization,
            ActorExecutionError::AuthorityExpired,
            ActorExecutionError::AuthoritySlotRegressed,
            ActorExecutionError::UnsupportedHostCall(u64::MAX),
        ] {
            let returned = RuntimeExecutionReturn {
                state: RuntimeState::default(),
                result: Err(error),
            };
            assert_eq!(
                RuntimeExecutionReturn::decode(&returned.encode()).unwrap(),
                returned,
                "{error:?}"
            );
        }
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
        let exact = RuntimeCall::new(
            RuntimeState {
                control: vec![1; super::super::execution::MAX_RUNTIME_STATE_BYTES / 2],
                linear: vec![2; super::super::execution::MAX_RUNTIME_STATE_BYTES / 2],
                merge: Vec::new(),
                local: Vec::new(),
            },
            LifecycleRequest::Inspect {
                after: None,
                limit: 1,
            },
        );
        assert_eq!(RuntimeCall::decode(&exact.encode()).unwrap(), exact);

        let oversized = RuntimeCall::new(
            RuntimeState {
                local: vec![3],
                ..exact.state
            },
            exact.request,
        );
        assert_eq!(
            RuntimeCall::decode(&oversized.encode()),
            Err(DecodeError::LimitExceeded)
        );
    }

    #[test]
    fn standard_state_decoder_bounds_the_aggregate_before_component_decoding() {
        let oversized = RuntimeState {
            control: vec![0; super::super::execution::MAX_RUNTIME_STATE_BYTES],
            linear: vec![0],
            merge: vec![0],
            local: vec![0],
        };
        assert_eq!(
            decode_standard_runtime_state(&oversized),
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
    fn resource_limit_uses_new_canonical_error_tag_and_unknown_tags_fail_closed() {
        let mut bytes = Vec::new();
        encode_error(&mut Encoder(&mut bytes), LifecycleError::ResourceLimit);
        assert_eq!(bytes, vec![13]);
        let mut decoder = Decoder::new(&bytes);
        assert_eq!(
            decode_error(&mut decoder),
            Ok(LifecycleError::ResourceLimit)
        );
        assert!(decoder.exhausted());

        let mut decoder = Decoder::new(&[15]);
        assert_eq!(decode_error(&mut decoder), Err(DecodeError::InvalidTag));

        let output = RuntimeReturn {
            state: RuntimeState {
                control: vec![1],
                linear: vec![2],
                merge: vec![3],
                local: vec![4],
            },
            result: Err(LifecycleError::ResourceLimit),
        };
        assert_eq!(RuntimeReturn::decode(&output.encode()).unwrap(), output);

        use super::super::committee::AuthorityCommitteeError as CommitteeError;
        use super::super::genesis::AgentGenesisError as GenesisError;
        use super::super::system_authority::SystemAuthorityError as AuthorityError;

        let mut errors = vec![
            AuthorityError::InvalidGenesis,
            AuthorityError::InvalidScope,
            AuthorityError::InvalidState,
            AuthorityError::InvalidDecisionFact,
            AuthorityError::InvalidDecisionNode,
            AuthorityError::InvalidDecisionProof,
            AuthorityError::InvalidRotationNode,
            AuthorityError::InvalidRotationProof,
            AuthorityError::InvalidFinalize,
            AuthorityError::InvalidProvision,
            AuthorityError::WrongSystemAgent,
            AuthorityError::StaleCommittee,
            AuthorityError::SequenceConflict,
            AuthorityError::RotationFirstSequencePending,
            AuthorityError::Capacity,
            AuthorityError::LimitExceeded,
        ];
        errors.extend(
            [
                CommitteeError::InvalidBinding,
                CommitteeError::InvalidMember,
                CommitteeError::InvalidSigner,
                CommitteeError::InvalidEpoch,
                CommitteeError::InvalidPreviousCommittee,
                CommitteeError::CommitteeTooLarge,
                CommitteeError::CertificateTooLarge,
                CommitteeError::NoVoters,
                CommitteeError::DuplicateNode,
                CommitteeError::NonCanonicalOrder,
                CommitteeError::InvalidClaim,
                CommitteeError::WrongAuthorityBinding,
                CommitteeError::WrongEpoch,
                CommitteeError::WrongCommittee,
                CommitteeError::WrongClaim,
                CommitteeError::UnknownSigner,
                CommitteeError::ObserverSignature,
                CommitteeError::InsufficientQuorum,
                CommitteeError::InvalidSignature,
                CommitteeError::InvalidRotationEpoch,
                CommitteeError::InvalidRotationLink,
                CommitteeError::InvalidRotationSequence,
                CommitteeError::InvalidRootAnchor,
                CommitteeError::RootAnchorTooLarge,
                CommitteeError::InvalidGenesisIntent,
                CommitteeError::InvalidGenesisExpectation,
                CommitteeError::InvalidGenesisClaim,
                CommitteeError::GenesisEvidenceTooLarge,
                CommitteeError::InvalidGenesisAdmission,
                CommitteeError::GenesisAdmissionTooLarge,
                CommitteeError::InvalidBootstrapAnchor,
                CommitteeError::WrongBootstrapAnchor,
                CommitteeError::WrongGenesisIntent,
                CommitteeError::WrongGenesisExpectation,
            ]
            .map(AuthorityError::Authority),
        );
        errors.extend(
            [
                GenesisError::InvalidLocator,
                GenesisError::InvalidExpectations,
                GenesisError::InvalidProposal,
                GenesisError::InvalidReplicaCommittee,
                GenesisError::InvalidClaim,
                GenesisError::InvalidEvidence,
                GenesisError::InvalidDecision,
                GenesisError::InvalidAdmission,
                GenesisError::InvalidProvision,
                GenesisError::InvalidCatalog,
                GenesisError::LimitExceeded,
                GenesisError::Authority(CommitteeError::WrongCommittee),
            ]
            .map(AuthorityError::Genesis),
        );
        for authority_error in errors {
            let error = LifecycleError::SystemAuthority(authority_error);
            let mut bytes = Vec::new();
            encode_error(&mut Encoder(&mut bytes), error);
            let mut decoder = Decoder::new(&bytes);
            assert_eq!(decode_error(&mut decoder), Ok(error));
            assert!(decoder.exhausted());
        }
    }

    #[test]
    fn immediate_prior_runtime_abi_is_rejected_without_a_compatibility_decoder() {
        let mut bytes =
            RuntimeCall::new(RuntimeState::default(), LifecycleRequest::Create(config())).encode();
        bytes[36..68].copy_from_slice(b"vos-agent-runtime-abi-20260831r5");
        assert_eq!(
            RuntimeCall::decode(&bytes),
            Err(DecodeError::InvalidPlatform)
        );
    }

    #[test]
    fn unsorted_replica_configuration_is_noncanonical() {
        let mut call =
            RuntimeCall::new(RuntimeState::default(), LifecycleRequest::Create(config()));
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
    fn replica_count_is_bounded_before_list_allocation() {
        let mut config = config();
        config.replicas = (0..=super::super::MAX_AGENT_REPLICAS)
            .map(|index| {
                let mut node = [0u8; 32];
                node[..2].copy_from_slice(&(index as u16 + 1).to_le_bytes());
                AgentReplica {
                    node: NodeId(node),
                    principal: PrincipalId([0x61; 32]),
                    role: ReplicaRole::Voter,
                }
            })
            .collect();
        assert_eq!(
            AgentConfig::decode(&config.encode()),
            Err(DecodeError::LimitExceeded)
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
        let created = apply_standard(RuntimeCall::new(
            RuntimeState::default(),
            LifecycleRequest::Authorized {
                admission: super::super::LifecycleAuthorityAdmission {
                    receipt: crate::agent::authority::AgentAuthorityReceipt { claim, signature },
                    observed_slot: 1,
                },
                request: Box::new(request),
            },
        ))
        .unwrap();
        assert!(matches!(created.result, Ok(LifecycleReply::Created(_))));
        let inspected = apply_standard(RuntimeCall::new(
            created.state,
            LifecycleRequest::Inspect {
                after: None,
                limit: 16,
            },
        ))
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
