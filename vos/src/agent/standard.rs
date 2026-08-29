//! Deterministic policy core of the bundled agent runtime.
//!
//! Persistence and execution are supplied by the guest entry around this
//! type. The state machine itself is `no_std`, permits an empty actor forest,
//! and keeps lifecycle safety independent of the 63 live-machine limit.

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::ops::Bound::{Excluded, Unbounded};

use super::{
    ActorEntry, ActorLifecycleDebt, ActorRecord, AgentConfig, AgentConfigError, AgentRuntime,
    LaneSet, LifecycleError, LifecycleReply, LifecycleRequest, RUNTIME_ABI_ID, RuntimeRequirements,
    StateLane,
};
use crate::service::{
    ActorId, AgentId, CredentialId, DeploymentId, Hash, InvocationId, ProducerId, ProgramId,
};

pub const MAX_DIRECTORY_PAGE: u16 = 256;
pub const MAX_INVOCATION_RESULTS_PER_LANE: usize = 32;
pub const MAX_INVOCATION_RESULT_BYTES_PER_LANE: usize = 64 * 1024;
pub const MAX_AUTHORITY_DISPOSITIONS: usize = 256;

#[derive(Clone, Debug)]
struct ManagedActor {
    record: ActorRecord,
    /// Non-structural durable work. Child debt is derived from the directory.
    debt: ActorLifecycleDebt,
    lane_state: StandardLaneState,
}

#[derive(Clone, Debug, Default)]
pub struct StandardAgentRuntime {
    config: Option<AgentConfig>,
    actors: BTreeMap<ActorId, ManagedActor>,
    invocation_results: BTreeMap<InvocationId, StandardInvocationResult>,
    authority_slot_high_water: Option<u64>,
    /// Highest binding-global authority sequence durably consumed.
    authority_sequence_high_water: Option<u64>,
    authority_dispositions: Vec<StandardAuthorityDisposition>,
}

/// Canonical persisted state of the bundled runtime.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StandardRuntimeState {
    pub config: Option<AgentConfig>,
    pub actors: Vec<StandardActorState>,
    pub invocation_results: Vec<StandardInvocationResult>,
    pub authority_slot_high_water: Option<u64>,
    pub authority_sequence_high_water: Option<u64>,
    pub authority_dispositions: Vec<StandardAuthorityDisposition>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StandardAuthorityDisposition {
    pub credential: CredentialId,
    /// Globally unique within the immutable authority binding.
    pub sequence: u64,
    pub claim: Hash,
    pub operation: Hash,
    pub result: Result<LifecycleReply, LifecycleError>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StandardInvocationResult {
    pub invocation: InvocationId,
    pub request: Hash,
    pub reply: super::execution::ActorExecutionReply,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StandardActorState {
    pub record: ActorRecord,
    pub debt: ActorLifecycleDebt,
    pub lane_state: StandardLaneState,
}

/// Runtime-owned bytes for each durable actor lane. Every freshly installed
/// actor starts with the empty sentinel. The signed actor PVM expands that
/// sentinel into its constructor defaults on first execution.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StandardLaneState {
    pub linear: Option<Vec<u8>>,
    pub merge: Option<Vec<u8>>,
    pub local: Option<Vec<u8>>,
}

impl StandardAgentRuntime {
    pub const fn new() -> Self {
        Self {
            config: None,
            actors: BTreeMap::new(),
            invocation_results: BTreeMap::new(),
            authority_slot_high_water: None,
            authority_sequence_high_water: None,
            authority_dispositions: Vec::new(),
        }
    }

    pub fn config(&self) -> Option<&AgentConfig> {
        self.config.as_ref()
    }

    pub fn actor(&self, actor: ActorId) -> Option<&ActorEntry> {
        self.actors.get(&actor).map(|actor| &actor.record.entry)
    }

    pub fn actor_record(&self, actor: ActorId) -> Option<&ActorRecord> {
        self.actors.get(&actor).map(|actor| &actor.record)
    }

    pub fn len(&self) -> usize {
        self.actors.len()
    }

    pub fn is_empty(&self) -> bool {
        self.actors.is_empty()
    }

    pub fn snapshot(&self) -> StandardRuntimeState {
        StandardRuntimeState {
            config: self.config.clone(),
            actors: self
                .actors
                .values()
                .map(|actor| StandardActorState {
                    record: actor.record.clone(),
                    debt: actor.debt,
                    lane_state: actor.lane_state.clone(),
                })
                .collect(),
            invocation_results: self.invocation_results.values().cloned().collect(),
            authority_slot_high_water: self.authority_slot_high_water,
            authority_sequence_high_water: self.authority_sequence_high_water,
            authority_dispositions: self.authority_dispositions.clone(),
        }
    }

    pub fn restore(state: StandardRuntimeState) -> Result<Self, LifecycleError> {
        let Some(config) = state.config else {
            return if state.actors.is_empty()
                && state.invocation_results.is_empty()
                && state.authority_slot_high_water.is_none()
                && state.authority_sequence_high_water.is_none()
                && state.authority_dispositions.is_empty()
            {
                Ok(Self::new())
            } else {
                Err(LifecycleError::InvalidRequest)
            };
        };
        if state
            .actors
            .windows(2)
            .any(|pair| pair[0].record.entry.actor >= pair[1].record.entry.actor)
            || state.actors.iter().any(|actor| actor.debt.children != 0)
            || state
                .invocation_results
                .windows(2)
                .any(|pair| pair[0].invocation >= pair[1].invocation)
            || state.authority_dispositions.len() > MAX_AUTHORITY_DISPOSITIONS
            || state
                .authority_dispositions
                .windows(2)
                .any(|pair| pair[0].sequence >= pair[1].sequence)
        {
            return Err(LifecycleError::InvalidRequest);
        }

        let mut runtime = Self::new();
        runtime.apply(LifecycleRequest::Create(config))?;
        let mut pending = state.actors;
        let mut suspended = Vec::new();
        while !pending.is_empty() {
            let Some(index) = pending.iter().position(|actor| {
                actor.record.entry.parent.is_none()
                    || actor
                        .record
                        .entry
                        .parent
                        .is_some_and(|parent| runtime.actors.contains_key(&parent))
            }) else {
                return Err(LifecycleError::InvalidRequest);
            };
            let actor = pending.remove(index);
            let mut entry = actor.record.entry;
            if entry.suspended {
                suspended.push(entry.actor);
                entry.suspended = false;
            }
            let actor_id = entry.actor;
            runtime.install(super::InstallActor {
                entry,
                producer: actor.record.producer,
                package: actor.record.package,
                agent_schema: actor.record.agent_schema,
                role_policies: actor.record.role_policies,
                state_layout: actor.record.state_layout,
                requirements: actor.record.requirements,
            })?;
            runtime.set_lifecycle_debt(actor_id, actor.debt)?;
            runtime.validate_restored_lane_state(actor_id, &actor.lane_state)?;
            runtime
                .actors
                .get_mut(&actor_id)
                .expect("the actor was installed above")
                .lane_state = actor.lane_state;
        }
        for actor in suspended {
            runtime.set_suspended(actor, true)?;
        }
        for result in state.invocation_results {
            if result.invocation == InvocationId::ZERO
                || result.reply.invocation != result.invocation
                || result.request == Hash::ZERO
                || result.reply.status != super::execution::ActorExecutionStatus::Done
                || !runtime.actors.contains_key(&result.reply.actor)
            {
                return Err(LifecycleError::InvalidRequest);
            }
            runtime.invocation_results.insert(result.invocation, result);
        }
        for lane in [StateLane::Linear, StateLane::Merge, StateLane::Local] {
            if runtime.invocation_result_count(lane) > MAX_INVOCATION_RESULTS_PER_LANE
                || runtime.invocation_result_bytes(lane) > MAX_INVOCATION_RESULT_BYTES_PER_LANE
            {
                return Err(LifecycleError::InvalidRequest);
            }
        }
        runtime.authority_slot_high_water = state.authority_slot_high_water;
        runtime.authority_sequence_high_water = state.authority_sequence_high_water;
        for disposition in state.authority_dispositions {
            if disposition.credential == CredentialId::ZERO
                || disposition.sequence == 0
                || disposition.claim == Hash::ZERO
                || disposition.operation == Hash::ZERO
                || runtime
                    .authority_sequence_high_water
                    .is_none_or(|high_water| disposition.sequence > high_water)
            {
                return Err(LifecycleError::InvalidRequest);
            }
            runtime.authority_dispositions.push(disposition);
        }
        if runtime.authority_sequence_high_water.is_some()
            != runtime.authority_slot_high_water.is_some()
            || runtime.authority_sequence_high_water.is_some()
                == runtime.authority_dispositions.is_empty()
            || runtime
                .authority_dispositions
                .last()
                .map(|item| item.sequence)
                != runtime.authority_sequence_high_water
        {
            return Err(LifecycleError::InvalidRequest);
        }
        Ok(runtime)
    }

    /// Update non-structural lifecycle debt from durable runtime indexes.
    pub fn set_lifecycle_debt(
        &mut self,
        actor: ActorId,
        mut debt: ActorLifecycleDebt,
    ) -> Result<(), LifecycleError> {
        let managed = self
            .actors
            .get_mut(&actor)
            .ok_or(LifecycleError::NotFound)?;
        debt.children = 0;
        managed.debt = debt;
        Ok(())
    }

    fn created(&self) -> Result<&AgentConfig, LifecycleError> {
        self.config.as_ref().ok_or(LifecycleError::NotCreated)
    }

    fn expected_actor_id(agent: AgentId, entry: &ActorEntry) -> ActorId {
        match entry.parent {
            Some(parent) => ActorId::owned_child(parent, &entry.name),
            None => ActorId::top_level(agent, &entry.name),
        }
    }

    fn validate_requirements(
        &self,
        requirements: RuntimeRequirements,
    ) -> Result<(), LifecycleError> {
        let config = self.created()?;
        if !requirements.lanes.supported_by(config.identity.profile) {
            return Err(LifecycleError::UnsupportedLane);
        }
        if !config.capabilities.satisfies(requirements) {
            return Err(LifecycleError::UnsupportedRuntime);
        }
        Ok(())
    }

    fn directory_page(
        &self,
        after: Option<ActorId>,
        limit: u16,
    ) -> Result<LifecycleReply, LifecycleError> {
        self.created()?;
        if limit == 0 || limit > MAX_DIRECTORY_PAGE {
            return Err(LifecycleError::InvalidRequest);
        }
        let mut entries = Vec::with_capacity(usize::from(limit));
        let mut iterator: Box<dyn Iterator<Item = (&ActorId, &ManagedActor)> + '_> = match after {
            Some(after) => Box::new(self.actors.range((Excluded(after), Unbounded))),
            None => Box::new(self.actors.iter()),
        };
        for (_, actor) in iterator.by_ref().take(usize::from(limit)) {
            entries.push(actor.record.entry.clone());
        }
        let next = if entries.len() == usize::from(limit) && iterator.next().is_some() {
            entries.last().map(|entry| entry.actor)
        } else {
            None
        };
        Ok(LifecycleReply::Directory(super::ActorDirectoryPage {
            entries,
            next,
        }))
    }

    fn install(&mut self, install: super::InstallActor) -> Result<LifecycleReply, LifecycleError> {
        self.validate_requirements(install.requirements)?;
        let config = self.created()?;
        if self.actors.len() >= config.capabilities.max_actors as usize {
            return Err(LifecycleError::DirectoryFull);
        }
        if install.entry.name.is_empty()
            || install.entry.name.len() > crate::service::MAX_ACTOR_NAME_BYTES
            || install.entry.lanes != install.requirements.lanes
            || install.entry.deployment == DeploymentId::ZERO
            || install.entry.program == ProgramId::ZERO
            || install.entry.package != install.package
            || install.entry.agent_schema != install.agent_schema
            || install.entry.role_policies != install.role_policies
            || install.entry.state_layout != install.state_layout
            || install.entry.suspended
            || install.producer == ProducerId::ZERO
            || install.package.hash == Hash::ZERO
            || install.package.len == 0
            || install.agent_schema.hash == Hash::ZERO
            || install.agent_schema.len == 0
            || install.agent_schema.len > super::schema::MAX_ENCODED_BYTES as u64
            || install.role_policies.hash == Hash::ZERO
            || install.role_policies.len == 0
            || install.role_policies.len > super::execution::MAX_EXECUTION_POLICY_BYTES as u64
            || install.state_layout == Hash::ZERO
            || Self::expected_actor_id(config.identity.agent, &install.entry) != install.entry.actor
        {
            return Err(LifecycleError::InvalidRequest);
        }
        if self.actors.contains_key(&install.entry.actor) {
            return Err(LifecycleError::AlreadyExists);
        }
        if let Some(parent) = install.entry.parent {
            let parent = self.actors.get(&parent).ok_or(LifecycleError::NotFound)?;
            if parent.record.entry.suspended {
                return Err(LifecycleError::Busy(
                    self.lifecycle_debt(parent.record.entry.actor)?,
                ));
            }
        }
        let entry = install.entry.clone();
        let lane_state = StandardLaneState::fresh();
        self.actors.insert(
            entry.actor,
            ManagedActor {
                record: ActorRecord {
                    entry: install.entry,
                    producer: install.producer,
                    package: install.package,
                    agent_schema: install.agent_schema,
                    role_policies: install.role_policies,
                    state_layout: install.state_layout,
                    requirements: install.requirements,
                },
                debt: ActorLifecycleDebt::default(),
                lane_state,
            },
        );
        Ok(LifecycleReply::Installed(entry))
    }

    #[cfg(feature = "pvm")]
    pub(crate) fn recover_execution(
        &self,
        invocation: &super::execution::ActorInvocation,
    ) -> Result<Option<super::execution::ActorExecutionReply>, super::execution::ActorExecutionError>
    {
        use super::execution::ActorExecutionError;
        invocation.validate()?;
        let Some(result) = self.invocation_results.get(&invocation.invocation) else {
            return Ok(None);
        };
        if result.request != invocation.commitment() {
            return Err(ActorExecutionError::DivergentInvocation);
        }
        Ok(Some(result.reply.clone()))
    }

    #[cfg(feature = "pvm")]
    pub(crate) fn prepare_execution_state(
        &self,
        invocation: &super::execution::ActorInvocation,
    ) -> Result<super::execution::ActorStateLanes, super::execution::ActorExecutionError> {
        use super::execution::{ActorExecutionError, ActorStateLanes};

        invocation.validate()?;
        let config = self
            .config
            .as_ref()
            .ok_or(ActorExecutionError::NotCreated)?;
        let actor = self
            .actors
            .get(&invocation.actor)
            .ok_or(ActorExecutionError::NotFound)?;
        if actor.record.entry.suspended {
            return Err(ActorExecutionError::Suspended);
        }
        if actor.record.entry.deployment != invocation.deployment {
            return Err(ActorExecutionError::StaleDeployment);
        }
        if actor.record.entry.program != invocation.program {
            return Err(ActorExecutionError::WrongProgram);
        }
        if let Some(lane) = invocation.mode.write_lane() {
            if !config.identity.profile.supports(lane) || !actor.record.entry.lanes.contains(lane) {
                return Err(ActorExecutionError::UnsupportedMethod);
            }
            if self.invocation_result_count(lane) >= MAX_INVOCATION_RESULTS_PER_LANE
                || self.invocation_result_bytes(lane) >= MAX_INVOCATION_RESULT_BYTES_PER_LANE
            {
                return Err(ActorExecutionError::ResultCapacity);
            }
        }
        for lane in [StateLane::Linear, StateLane::Merge] {
            if actor.record.entry.lanes.contains(lane) && !invocation.mode.can_read(lane) {
                // A replicated handler must execute against one complete,
                // pinned shared-state view. Supplying only its write lane
                // would make cross-lane reads depend on constructor defaults.
                return Err(ActorExecutionError::UnsupportedMethod);
            }
        }
        let resolve = |lane| -> Result<Option<Vec<u8>>, ActorExecutionError> {
            if !actor.record.entry.lanes.contains(lane) || !invocation.mode.can_read(lane) {
                return Ok(None);
            }
            actor
                .lane_state
                .select(lane)
                .clone()
                .map(Some)
                .ok_or(ActorExecutionError::MissingState)
        };
        let state = ActorStateLanes {
            linear: resolve(StateLane::Linear)?,
            merge: resolve(StateLane::Merge)?,
            local: resolve(StateLane::Local)?,
        };
        if state
            .encoded_len()
            .is_none_or(|len| len > super::execution::MAX_EXECUTION_STATE_TOTAL_BYTES)
        {
            return Err(ActorExecutionError::InvalidAvailability);
        }
        Ok(state)
    }

    #[cfg(feature = "pvm")]
    pub(crate) fn validate_execution_schema(
        &self,
        invocation: &super::execution::ActorInvocation,
        schema_blob: &super::execution::RuntimeBlob,
    ) -> Result<(), super::execution::ActorExecutionError> {
        use super::execution::ActorExecutionError;
        use crate::actors::codec::Decode as _;
        use crate::actors::value::{Msg, TAG_DYNAMIC};

        let actor = self
            .actors
            .get(&invocation.actor)
            .ok_or(ActorExecutionError::NotFound)?;
        if schema_blob.reference != actor.record.agent_schema
            || !schema_blob.reference.matches(&schema_blob.bytes)
        {
            return Err(ActorExecutionError::InvalidAvailability);
        }
        let schema = super::schema::decode(&schema_blob.bytes)
            .ok_or(ActorExecutionError::InvalidAvailability)?;
        if schema.state_layout_hash() != actor.record.state_layout
            || schema.lanes() != actor.record.requirements.lanes
        {
            return Err(ActorExecutionError::InvalidAvailability);
        }
        let message = invocation
            .message
            .strip_prefix(&[TAG_DYNAMIC])
            .and_then(Msg::try_decode)
            .ok_or(ActorExecutionError::UnsupportedMethod)?;
        let method = schema
            .method(&message.name)
            .ok_or(ActorExecutionError::UnsupportedMethod)?;
        if method.mode != invocation.mode {
            return Err(ActorExecutionError::UnsupportedMethod);
        }
        Ok(())
    }

    /// Resolve the canonical signed method policy and enforce it against the
    /// host-authenticated invocation context before application code runs.
    /// Package signature verification and lifecycle authority bind the
    /// guest-owned reference; callers never select these policy bytes.
    #[cfg(feature = "pvm")]
    pub(crate) fn authorize_execution(
        &self,
        invocation: &super::execution::ActorInvocation,
        policy_blob: &super::execution::RuntimeBlob,
    ) -> Result<bool, super::execution::ActorExecutionError> {
        use super::execution::ActorExecutionError;
        use crate::actors::codec::Decode as _;
        use crate::actors::value::{Msg, TAG_DYNAMIC};
        use crate::service::PackageRolePolicies;
        use crate::service::wire::ServiceWire as _;

        let actor = self
            .actors
            .get(&invocation.actor)
            .ok_or(ActorExecutionError::NotFound)?;
        if policy_blob.reference != actor.record.role_policies
            || !policy_blob.reference.matches(&policy_blob.bytes)
        {
            return Err(ActorExecutionError::InvalidAvailability);
        }
        let policies = PackageRolePolicies::decode(&policy_blob.bytes)
            .map_err(|_| ActorExecutionError::InvalidAvailability)?;
        let message = invocation
            .message
            .strip_prefix(&[TAG_DYNAMIC])
            .and_then(Msg::try_decode)
            .ok_or(ActorExecutionError::UnsupportedMethod)?;
        let policy = policies
            .methods
            .binary_search_by(|policy| policy.method.as_str().cmp(message.name.as_str()))
            .ok()
            .and_then(|index| policies.methods.get(index))
            .ok_or(ActorExecutionError::UnsupportedMethod)?;
        if policy.schema == Hash::ZERO {
            return Err(ActorExecutionError::InvalidAvailability);
        }
        if policy.attested {
            // The bundled runtime advertises `proofs = false`; a valid
            // package requiring attestation is rejected at install. Keep the
            // execution boundary fail-closed even if an untrusted host tries
            // to construct lifecycle state without package verification.
            return Err(ActorExecutionError::UnsupportedMethod);
        }

        if policy.public {
            return Ok(true);
        }
        match invocation.auth.origin {
            crate::service::Origin::Anonymous => return Ok(false),
            // System has no grant-bearing principal. It may exercise only a
            // capability-only policy, and only with the exact capability
            // authenticated by the host boundary.
            crate::service::Origin::System => {
                return Ok(policy.space_role.is_none()
                    && policy.actor_role.is_none()
                    && policy
                        .capability
                        .is_some_and(|required| invocation.auth.capability == Some(required)));
            }
            crate::service::Origin::Member(_) | crate::service::Origin::Actor(_) => {}
        }
        Ok(policy.space_role.is_none_or(|required| {
            invocation
                .auth
                .space_role
                .is_some_and(|actual| actual >= required)
        }) && policy
            .capability
            .is_none_or(|required| invocation.auth.capability == Some(required))
            && policy.actor_role.is_none_or(|required| {
                invocation
                    .auth
                    .actor_role
                    .is_some_and(|actual| actual >= required)
            }))
    }

    #[cfg(feature = "pvm")]
    pub(crate) fn commit_execution(
        &mut self,
        invocation: &super::execution::ActorInvocation,
        reply: &super::execution::ActorExecutionReply,
        before: &super::execution::ActorStateLanes,
        mut after: super::execution::ActorStateLanes,
    ) -> Result<(), super::execution::ActorExecutionError> {
        use super::execution::{ActorExecutionError, MAX_EXECUTION_STATE_BYTES};
        if reply.invocation != invocation.invocation
            || reply.actor != invocation.actor
            || reply.deployment != invocation.deployment
            || reply.lane != invocation.mode.write_lane()
            || self.invocation_results.contains_key(&invocation.invocation)
        {
            return Err(ActorExecutionError::InvalidActorOutput);
        }
        let write_lane = invocation.mode.write_lane();
        for lane in [StateLane::Linear, StateLane::Merge, StateLane::Local] {
            let Some(previous) = before.get(lane) else {
                continue;
            };
            // Generated actors normalize every non-owned fresh lane back to
            // the runtime's empty sentinel after checking the reconstructed
            // canonical frame. Exact comparison is therefore sound from the
            // first invocation onward, including for hand-written PVMs.
            if Some(lane) != write_lane && after.get(lane) != Some(previous) {
                return Err(ActorExecutionError::InvalidActorOutput);
            }
        }
        let Some(lane) = write_lane else {
            return Ok(());
        };
        let state = after
            .take(lane)
            .ok_or(ActorExecutionError::InvalidActorOutput)?;
        if state.len() > MAX_EXECUTION_STATE_BYTES {
            return Err(ActorExecutionError::InvalidActorOutput);
        }
        if self.invocation_result_count(lane) >= MAX_INVOCATION_RESULTS_PER_LANE
            || self
                .invocation_result_bytes(lane)
                .saturating_add(reply.reply.len())
                > MAX_INVOCATION_RESULT_BYTES_PER_LANE
        {
            return Err(ActorExecutionError::ResultCapacity);
        }
        let actor = self
            .actors
            .get_mut(&reply.actor)
            .ok_or(ActorExecutionError::NotFound)?;
        *actor.lane_state.select_mut(lane) = Some(state);
        self.invocation_results.insert(
            invocation.invocation,
            StandardInvocationResult {
                invocation: invocation.invocation,
                request: invocation.commitment(),
                reply: reply.clone(),
            },
        );
        Ok(())
    }

    fn invocation_result_count(&self, lane: StateLane) -> usize {
        self.invocation_results
            .values()
            .filter(|result| result.reply.lane == Some(lane))
            .count()
    }

    fn invocation_result_bytes(&self, lane: StateLane) -> usize {
        self.invocation_results
            .values()
            .filter(|result| result.reply.lane == Some(lane))
            .fold(0usize, |total, result| {
                total.saturating_add(result.reply.reply.len())
            })
    }

    fn validate_restored_lane_state(
        &self,
        actor: crate::service::ActorId,
        state: &StandardLaneState,
    ) -> Result<(), LifecycleError> {
        let actor = self.actors.get(&actor).ok_or(LifecycleError::NotFound)?;
        let lanes = [
            (StateLane::Linear, &state.linear),
            (StateLane::Merge, &state.merge),
            (StateLane::Local, &state.local),
        ];
        for (lane, value) in lanes {
            if value
                .as_ref()
                .is_some_and(|bytes| bytes.len() > super::execution::MAX_EXECUTION_STATE_BYTES)
                || value.is_none()
                || (!actor.record.entry.lanes.contains(lane) && value.as_deref() != Some(&[][..]))
            {
                return Err(LifecycleError::InvalidRequest);
            }
        }
        if lanes
            .into_iter()
            .filter_map(|(_, value)| value.as_deref())
            .try_fold(0usize, |total, value| total.checked_add(value.len()))
            .is_none_or(|len| len > super::execution::MAX_EXECUTION_STATE_TOTAL_BYTES)
        {
            return Err(LifecycleError::InvalidRequest);
        }
        Ok(())
    }

    fn upgrade_actor(
        &mut self,
        upgrade: super::UpgradeActor,
    ) -> Result<LifecycleReply, LifecycleError> {
        self.validate_requirements(upgrade.requirements)?;
        let debt = self.lifecycle_debt(upgrade.actor)?;
        if !quiescent(debt) {
            return Err(LifecycleError::Busy(debt));
        }
        let actor = self
            .actors
            .get_mut(&upgrade.actor)
            .ok_or(LifecycleError::NotFound)?;
        if actor.record.entry.deployment != upgrade.from_deployment {
            return Err(LifecycleError::StaleDeployment);
        }
        if actor.record.requirements.lanes != upgrade.requirements.lanes {
            // Lane-shape migration needs an explicit runtime migration
            // payload. Reinterpreting existing bytes under a new lane set is
            // never a safe package-only upgrade.
            return Err(LifecycleError::UnsupportedLane);
        }
        if actor.record.requirements.lanes != LaneSet::NONE
            && actor.record.entry.program != upgrade.to_program
        {
            // Source-level layout metadata is not a semantic codec or state
            // migration proof. Until runtimes expose an explicit migration
            // ABI, only same-program repackaging is safe for stateful actors.
            return Err(LifecycleError::UnsupportedLane);
        }
        if upgrade.to_deployment == DeploymentId::ZERO || upgrade.to_program == ProgramId::ZERO {
            return Err(LifecycleError::InvalidRequest);
        }
        if upgrade.producer == ProducerId::ZERO
            || upgrade.package.hash == Hash::ZERO
            || upgrade.package.len == 0
            || upgrade.agent_schema.hash == Hash::ZERO
            || upgrade.agent_schema.len == 0
            || upgrade.agent_schema.len > super::schema::MAX_ENCODED_BYTES as u64
            || upgrade.role_policies.hash == Hash::ZERO
            || upgrade.role_policies.len == 0
            || upgrade.role_policies.len > super::execution::MAX_EXECUTION_POLICY_BYTES as u64
            || upgrade.state_layout == Hash::ZERO
        {
            return Err(LifecycleError::InvalidRequest);
        }
        if actor.record.state_layout != upgrade.state_layout {
            return Err(LifecycleError::UnsupportedLane);
        }
        actor.record.entry.deployment = upgrade.to_deployment;
        actor.record.entry.program = upgrade.to_program;
        actor.record.entry.package = upgrade.package.clone();
        actor.record.entry.agent_schema = upgrade.agent_schema.clone();
        actor.record.entry.role_policies = upgrade.role_policies.clone();
        actor.record.entry.state_layout = upgrade.state_layout;
        actor.record.entry.lanes = upgrade.requirements.lanes;
        actor.record.producer = upgrade.producer;
        actor.record.package = upgrade.package;
        actor.record.agent_schema = upgrade.agent_schema;
        actor.record.role_policies = upgrade.role_policies;
        actor.record.state_layout = upgrade.state_layout;
        actor.record.requirements = upgrade.requirements;
        Ok(LifecycleReply::Upgraded(actor.record.entry.clone()))
    }

    fn set_suspended(
        &mut self,
        actor: ActorId,
        suspended: bool,
    ) -> Result<LifecycleReply, LifecycleError> {
        let actor = self
            .actors
            .get_mut(&actor)
            .ok_or(LifecycleError::NotFound)?;
        if actor.record.entry.suspended == suspended {
            return Err(LifecycleError::InvalidRequest);
        }
        actor.record.entry.suspended = suspended;
        if suspended {
            Ok(LifecycleReply::Suspended(actor.record.entry.clone()))
        } else {
            Ok(LifecycleReply::Resumed(actor.record.entry.clone()))
        }
    }

    fn acknowledge_invocation(
        &mut self,
        invocation: InvocationId,
        request: Hash,
    ) -> Result<LifecycleReply, LifecycleError> {
        let result = self
            .invocation_results
            .get(&invocation)
            .ok_or(LifecycleError::NotFound)?;
        if result.request != request {
            return Err(LifecycleError::InvalidRequest);
        }
        self.invocation_results.remove(&invocation);
        Ok(LifecycleReply::InvocationAcknowledged(invocation))
    }

    fn remove_leaf(
        &mut self,
        actor: ActorId,
        expected_deployment: DeploymentId,
    ) -> Result<LifecycleReply, LifecycleError> {
        let managed = self.actors.get(&actor).ok_or(LifecycleError::NotFound)?;
        if managed.record.entry.deployment != expected_deployment {
            return Err(LifecycleError::StaleDeployment);
        }
        let debt = self.lifecycle_debt(actor)?;
        if !debt.is_clear() {
            return Err(LifecycleError::Busy(debt));
        }
        self.actors.remove(&actor);
        Ok(LifecycleReply::Removed(actor))
    }

    fn upgrade_runtime(
        &mut self,
        from_deployment: DeploymentId,
        to_deployment: DeploymentId,
        to_program: ProgramId,
        producer: crate::service::ProducerId,
        package: crate::service::BlobRef,
        abi: crate::service::Hash,
        capabilities: super::RuntimeCapabilities,
    ) -> Result<LifecycleReply, LifecycleError> {
        let config = self.created()?;
        if config.identity.runtime_deployment != from_deployment {
            return Err(LifecycleError::StaleDeployment);
        }
        if abi != RUNTIME_ABI_ID
            || to_deployment == DeploymentId::ZERO
            || to_program == ProgramId::ZERO
            || producer == ProducerId::ZERO
            || package.hash == Hash::ZERO
            || package.len == 0
            || capabilities.max_actors < self.actors.len() as u32
            || !capabilities.lanes.supported_by(config.identity.profile)
            || self
                .actors
                .values()
                .any(|actor| !capabilities.satisfies(actor.record.requirements))
        {
            return Err(LifecycleError::UnsupportedRuntime);
        }
        if let Some(debt) = self
            .actors
            .keys()
            .filter_map(|actor| self.lifecycle_debt(*actor).ok())
            .find(|debt| !quiescent(*debt))
        {
            return Err(LifecycleError::Busy(debt));
        }
        let config = self.config.as_mut().expect("created agent has config");
        config.identity.runtime_deployment = to_deployment;
        config.identity.runtime_program = to_program;
        config.identity.runtime_producer = producer;
        config.runtime_package = package;
        config.capabilities = capabilities;
        Ok(LifecycleReply::RuntimeUpgraded(config.identity.clone()))
    }

    fn apply_authorized(
        &mut self,
        admission: super::LifecycleAuthorityAdmission,
        request: LifecycleRequest,
    ) -> Result<LifecycleReply, LifecycleError> {
        let authority = match (&request, self.config.as_ref()) {
            (LifecycleRequest::Create(config), None) => &config.authority,
            (LifecycleRequest::Create(_), Some(config)) => &config.authority,
            (_, _) => &self.created()?.authority,
        };
        if admission.authority != authority.commitment()
            || admission.credential == CredentialId::ZERO
            || admission.sequence == 0
            || admission.claim == Hash::ZERO
            || admission.operation == Hash::ZERO
            || admission.operation != request.commitment()
            || matches!(
                request,
                LifecycleRequest::Inspect { .. }
                    | LifecycleRequest::AcknowledgeInvocation { .. }
                    | LifecycleRequest::Authorized { .. }
            )
        {
            return Err(LifecycleError::InvalidRequest);
        }

        if self
            .authority_slot_high_water
            .is_some_and(|high_water| admission.observed_slot < high_water)
        {
            return Err(LifecycleError::AuthoritySlotRegressed);
        }

        if let Some(disposition) = self
            .authority_dispositions
            .iter()
            .find(|disposition| disposition.sequence == admission.sequence)
        {
            if disposition.credential != admission.credential
                || disposition.claim != admission.claim
                || disposition.operation != admission.operation
            {
                return Err(LifecycleError::AuthoritySequenceConflict);
            }
            self.authority_slot_high_water = Some(admission.observed_slot);
            return disposition.result.clone();
        }

        if self
            .authority_sequence_high_water
            .is_some_and(|high_water| admission.sequence <= high_water)
        {
            return Err(LifecycleError::AuthoritySequenceRegressed);
        }

        // Lifecycle implementations promise atomic rejection. Preserve that
        // property defensively while still consuming the signed sequence and
        // recording its exact deterministic refusal.
        let before = self.clone();
        let result = self.apply(request);
        if result.is_err() {
            *self = before;
        }
        self.authority_sequence_high_water = Some(admission.sequence);
        self.authority_slot_high_water = Some(admission.observed_slot);
        if self.authority_dispositions.len() == MAX_AUTHORITY_DISPOSITIONS {
            // Globally monotone sequences make the oldest journal entry the
            // only canonical eviction candidate. Its sequence remains below
            // the durable high-water, so a later retry is rejected without
            // reapplying the lifecycle operation.
            self.authority_dispositions.remove(0);
        }
        self.authority_dispositions
            .push(StandardAuthorityDisposition {
                credential: admission.credential,
                sequence: admission.sequence,
                claim: admission.claim,
                operation: admission.operation,
                result: result.clone(),
            });
        result
    }
}

impl StandardLaneState {
    fn fresh() -> Self {
        Self {
            linear: Some(Vec::new()),
            merge: Some(Vec::new()),
            local: Some(Vec::new()),
        }
    }

    #[cfg(feature = "pvm")]
    fn select(&self, lane: StateLane) -> &Option<Vec<u8>> {
        match lane {
            StateLane::Linear => &self.linear,
            StateLane::Merge => &self.merge,
            StateLane::Local => &self.local,
        }
    }

    #[cfg(feature = "pvm")]
    fn select_mut(&mut self, lane: StateLane) -> &mut Option<Vec<u8>> {
        match lane {
            StateLane::Linear => &mut self.linear,
            StateLane::Merge => &mut self.merge,
            StateLane::Local => &mut self.local,
        }
    }
}

impl AgentRuntime for StandardAgentRuntime {
    fn capabilities(&self) -> super::RuntimeCapabilities {
        self.config
            .as_ref()
            .map(|config| config.capabilities)
            .unwrap_or_else(super::RuntimeCapabilities::standard)
    }

    fn apply(&mut self, request: LifecycleRequest) -> Result<LifecycleReply, LifecycleError> {
        match request {
            LifecycleRequest::Create(config) => {
                if self.config.is_some() {
                    return Err(LifecycleError::AlreadyCreated);
                }
                config.validate().map_err(|error| match error {
                    AgentConfigError::UnsupportedLane => LifecycleError::UnsupportedLane,
                    _ => LifecycleError::InvalidRequest,
                })?;
                let intrinsic = super::RuntimeCapabilities::standard();
                if config.capabilities.max_actors > intrinsic.max_actors
                    || config.capabilities.lanes.bits() & !intrinsic.lanes.bits() != 0
                    || (config.capabilities.scheduling && !intrinsic.scheduling)
                    || (config.capabilities.proofs && !intrinsic.proofs)
                {
                    // Creation may choose a smaller policy envelope, but it
                    // cannot make this runtime claim features the bundled
                    // implementation does not intrinsically provide.
                    return Err(LifecycleError::UnsupportedRuntime);
                }
                let identity = config.identity.clone();
                self.config = Some(config);
                Ok(LifecycleReply::Created(identity))
            }
            LifecycleRequest::Inspect { after, limit } => self.directory_page(after, limit),
            LifecycleRequest::Install(install) => self.install(install),
            LifecycleRequest::UpgradeActor(upgrade) => self.upgrade_actor(upgrade),
            LifecycleRequest::Suspend(actor) => self.set_suspended(actor, true),
            LifecycleRequest::Resume(actor) => self.set_suspended(actor, false),
            LifecycleRequest::AcknowledgeInvocation {
                invocation,
                request,
            } => self.acknowledge_invocation(invocation, request),
            LifecycleRequest::RemoveLeaf {
                actor,
                expected_deployment,
            } => self.remove_leaf(actor, expected_deployment),
            LifecycleRequest::UpgradeRuntime {
                from_deployment,
                to_deployment,
                to_program,
                producer,
                package,
                abi,
                capabilities,
            } => self.upgrade_runtime(
                from_deployment,
                to_deployment,
                to_program,
                producer,
                package,
                abi,
                capabilities,
            ),
            LifecycleRequest::Authorized { admission, request } => {
                self.apply_authorized(admission, *request)
            }
        }
    }

    fn lifecycle_debt(&self, actor: ActorId) -> Result<ActorLifecycleDebt, LifecycleError> {
        let managed = self.actors.get(&actor).ok_or(LifecycleError::NotFound)?;
        let mut debt = managed.debt;
        debt.children = u32::try_from(
            self.actors
                .values()
                .filter(|candidate| candidate.record.entry.parent == Some(actor))
                .count(),
        )
        .unwrap_or(u32::MAX);
        debt.lifecycle_operations = debt.lifecycle_operations.saturating_add(
            u32::try_from(
                self.invocation_results
                    .values()
                    .filter(|result| result.reply.actor == actor)
                    .count(),
            )
            .unwrap_or(u32::MAX),
        );
        Ok(debt)
    }
}

fn quiescent(mut debt: ActorLifecycleDebt) -> bool {
    debt.children = 0;
    debt.is_clear()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::{
        AgentIdentity, AgentProfile, AgentReplica, InstallActor, LaneSet, ReplicaRole,
        RuntimeCapabilities, StateLane, UpgradeActor,
    };
    use crate::service::{BlobRef, Hash, NodeId, PrincipalId, ProducerId, SpaceId};
    use alloc::vec;

    fn config(max_actors: u32) -> AgentConfig {
        let owner = PrincipalId([1; 32]);
        AgentConfig {
            identity: AgentIdentity {
                space: SpaceId([2; 32]),
                agent: AgentId([3; 32]),
                owner,
                profile: AgentProfile::Local,
                runtime_deployment: DeploymentId([4; 32]),
                runtime_program: ProgramId([5; 32]),
                runtime_producer: ProducerId([17; 32]),
            },
            authority: crate::agent::authority::AgentAuthorityBinding {
                agent: AgentId([18; 32]),
                actor: ActorId([19; 32]),
                deployment: DeploymentId([21; 32]),
                program: ProgramId([22; 32]),
                producer: ProducerId::of_public_key(b"authority-key"),
                public_key: b"authority-key".to_vec(),
            },
            capabilities: RuntimeCapabilities {
                max_actors,
                ..RuntimeCapabilities::standard()
            },
            runtime_package: BlobRef {
                hash: Hash([20; 32]),
                len: 100,
            },
            replicas: vec![AgentReplica {
                node: NodeId([6; 32]),
                principal: owner,
                role: ReplicaRole::Voter,
            }],
        }
    }

    fn install(agent: AgentId, parent: Option<ActorId>, name: &str) -> InstallActor {
        let actor = parent.map_or_else(
            || ActorId::top_level(agent, name),
            |parent| ActorId::owned_child(parent, name),
        );
        let requirements = RuntimeRequirements {
            lanes: LaneSet::of(StateLane::Linear),
            scheduling: false,
            proofs: false,
        };
        let package = BlobRef {
            hash: Hash([10; 32]),
            len: 100,
        };
        let agent_schema = BlobRef {
            hash: Hash([11; 32]),
            len: 100,
        };
        let role_policies = BlobRef {
            hash: Hash([13; 32]),
            len: 100,
        };
        InstallActor {
            entry: ActorEntry {
                actor,
                name: name.into(),
                parent,
                deployment: DeploymentId([7; 32]),
                program: ProgramId([8; 32]),
                package: package.clone(),
                agent_schema: agent_schema.clone(),
                role_policies: role_policies.clone(),
                state_layout: Hash([12; 32]),
                lanes: requirements.lanes,
                suspended: false,
            },
            producer: ProducerId([9; 32]),
            package,
            agent_schema,
            role_policies,
            state_layout: Hash([12; 32]),
            requirements,
        }
    }

    #[cfg(feature = "pvm")]
    #[test]
    fn merge_receives_complete_shared_state_and_cannot_replace_linear() {
        use crate::agent::execution::{
            ActorExecutionError, ActorExecutionReply, ActorExecutionStatus, ActorInvocation,
            ActorInvocationAuth, ActorStateLanes,
        };
        use crate::service::InvocationId;

        let config = config(4);
        let mut runtime = StandardAgentRuntime::new();
        runtime
            .apply(LifecycleRequest::Create(config.clone()))
            .unwrap();
        let mut install = install(config.identity.agent, None, "mixed");
        let shared = LaneSet::of(StateLane::Linear).union(LaneSet::of(StateLane::Merge));
        install.entry.lanes = shared;
        install.requirements.lanes = shared;
        let actor = install.entry.actor;
        let deployment = install.entry.deployment;
        let program = install.entry.program;
        runtime.apply(LifecycleRequest::Install(install)).unwrap();
        runtime.actors.get_mut(&actor).unwrap().lane_state.linear = Some(vec![7]);
        runtime.actors.get_mut(&actor).unwrap().lane_state.merge = Some(Vec::new());

        let invocation = ActorInvocation {
            invocation: InvocationId([31; 32]),
            actor,
            deployment,
            program,
            mode: crate::agent::MethodMode::Merge,
            auth: ActorInvocationAuth::anonymous(),
            message: vec![1],
            availability: Vec::new(),
            gas: 1,
        };
        let before = runtime.prepare_execution_state(&invocation).unwrap();
        assert_eq!(before.linear.as_deref(), Some(&[7][..]));
        assert_eq!(before.merge.as_deref(), Some(&[][..]));
        assert!(before.local.is_none());

        let reply = ActorExecutionReply {
            invocation: invocation.invocation,
            actor,
            deployment,
            lane: Some(StateLane::Merge),
            status: ActorExecutionStatus::Done,
            reply: Vec::new(),
            gas_remaining: 0,
        };
        let forged = ActorStateLanes {
            linear: Some(vec![8]),
            merge: Some(vec![1]),
            local: None,
        };
        let fresh = ActorStateLanes {
            linear: Some(Vec::new()),
            merge: Some(Vec::new()),
            local: None,
        };
        assert_eq!(
            runtime.commit_execution(&invocation, &reply, &fresh, forged.clone()),
            Err(ActorExecutionError::InvalidActorOutput),
            "the host enforces non-owned lanes even from the fresh sentinel"
        );
        assert_eq!(
            runtime.commit_execution(&invocation, &reply, &before, forged),
            Err(ActorExecutionError::InvalidActorOutput)
        );
    }

    fn authorized(
        config: &AgentConfig,
        credential: CredentialId,
        sequence: u64,
        claim_byte: u8,
        request: LifecycleRequest,
    ) -> LifecycleRequest {
        authorized_at(config, credential, sequence, 100, claim_byte, request)
    }

    fn authorized_at(
        config: &AgentConfig,
        credential: CredentialId,
        sequence: u64,
        observed_slot: u64,
        claim_byte: u8,
        request: LifecycleRequest,
    ) -> LifecycleRequest {
        let operation = request.commitment();
        LifecycleRequest::Authorized {
            admission: super::super::LifecycleAuthorityAdmission {
                authority: config.authority.commitment(),
                credential,
                sequence,
                observed_slot,
                claim: Hash([claim_byte; 32]),
                operation,
            },
            request: Box::new(request),
        }
    }

    #[test]
    fn created_agent_is_valid_and_usefully_empty() {
        let mut runtime = StandardAgentRuntime::new();
        let config = config(super::super::RuntimeCapabilities::STANDARD_MAX_ACTORS);
        // A later credential can advance the one global sequence without
        // consuming a permanent per-credential slot.
        assert!(matches!(
            runtime.apply(LifecycleRequest::Create(config)),
            Ok(LifecycleReply::Created(_))
        ));
        assert!(runtime.is_empty());
        assert_eq!(
            runtime.apply(LifecycleRequest::Inspect {
                after: None,
                limit: 16
            }),
            Ok(LifecycleReply::Directory(
                super::super::ActorDirectoryPage {
                    entries: vec![],
                    next: None,
                }
            ))
        );
    }

    #[test]
    fn authority_sequences_recover_exact_dispositions_without_reapplying_history() {
        let config = config(8);
        let agent = config.identity.agent;
        let credential = CredentialId([0x44; 32]);
        let install = install(agent, None, "counter");
        let actor = install.entry.actor;
        let deployment = install.entry.deployment;
        let mut runtime = StandardAgentRuntime::new();
        runtime
            .apply(LifecycleRequest::Create(config.clone()))
            .unwrap();

        let install_request = LifecycleRequest::Install(install.clone());
        let installed = runtime
            .apply(authorized(
                &config,
                credential,
                1,
                1,
                install_request.clone(),
            ))
            .unwrap();
        assert_eq!(installed, LifecycleReply::Installed(install.entry.clone()));

        let suspend_request = LifecycleRequest::Suspend(actor);
        let suspended = runtime
            .apply(authorized(
                &config,
                credential,
                2,
                2,
                suspend_request.clone(),
            ))
            .unwrap();
        assert!(matches!(
            &suspended,
            LifecycleReply::Suspended(entry) if entry.suspended
        ));
        runtime
            .apply(authorized(
                &config,
                credential,
                3,
                3,
                LifecycleRequest::Resume(actor),
            ))
            .unwrap();

        // A skipped lower sequence was never admitted and cannot become
        // valid merely because current actor state happens to permit it.
        runtime
            .apply(authorized(
                &config,
                credential,
                9,
                9,
                LifecycleRequest::Suspend(actor),
            ))
            .unwrap();
        assert_eq!(
            runtime.apply(authorized(
                &config,
                credential,
                8,
                8,
                LifecycleRequest::Resume(actor),
            )),
            Err(LifecycleError::AuthoritySequenceRegressed)
        );

        runtime
            .apply(authorized(
                &config,
                credential,
                10,
                10,
                LifecycleRequest::RemoveLeaf {
                    actor,
                    expected_deployment: deployment,
                },
            ))
            .unwrap();

        // Exercise the exact persisted encoding used across process restart.
        let encoded = super::super::wire::encode_standard_runtime_state(&runtime.snapshot());
        let decoded = super::super::wire::decode_standard_runtime_state(&encoded).unwrap();
        let mut reopened = StandardAgentRuntime::restore(decoded).unwrap();

        assert_eq!(
            reopened
                .apply(authorized(&config, credential, 2, 2, suspend_request,))
                .unwrap(),
            suspended,
            "Suspend(N) replay recovers its old result after Resume(N+1)"
        );
        assert_eq!(
            reopened
                .apply(authorized(&config, credential, 1, 1, install_request,))
                .unwrap(),
            installed,
            "an old Install retry recovers without reinstalling a removed actor"
        );
        assert!(reopened.is_empty());
        assert_eq!(
            reopened.apply(authorized(
                &config,
                credential,
                2,
                0xee,
                LifecycleRequest::Suspend(actor),
            )),
            Err(LifecycleError::AuthoritySequenceConflict)
        );
    }

    #[test]
    fn authority_slot_high_water_survives_restart_and_guards_exact_retries() {
        let config = config(8);
        let credential = CredentialId([0x54; 32]);
        let install = install(config.identity.agent, None, "counter");
        let actor = install.entry.actor;
        let install_request = LifecycleRequest::Install(install.clone());
        let mut runtime = StandardAgentRuntime::new();
        runtime
            .apply(LifecycleRequest::Create(config.clone()))
            .unwrap();
        let installed = runtime
            .apply(authorized_at(
                &config,
                credential,
                1,
                20,
                1,
                install_request.clone(),
            ))
            .unwrap();

        let encoded = super::super::wire::encode_standard_runtime_state(&runtime.snapshot());
        let decoded = super::super::wire::decode_standard_runtime_state(&encoded).unwrap();
        assert_eq!(decoded.authority_slot_high_water, Some(20));
        let mut reopened = StandardAgentRuntime::restore(decoded).unwrap();
        assert_eq!(
            reopened.apply(authorized_at(
                &config,
                credential,
                2,
                19,
                2,
                LifecycleRequest::Suspend(actor),
            )),
            Err(LifecycleError::AuthoritySlotRegressed)
        );
        assert_eq!(reopened.actor(actor), Some(&install.entry));

        assert_eq!(
            reopened
                .apply(authorized_at(
                    &config,
                    credential,
                    1,
                    25,
                    1,
                    install_request,
                ))
                .unwrap(),
            installed,
            "an exact retry is recovered at the provider's newer slot"
        );
        assert_eq!(reopened.snapshot().authority_slot_high_water, Some(25));
        assert_eq!(
            reopened.apply(authorized_at(
                &config,
                credential,
                2,
                24,
                2,
                LifecycleRequest::Suspend(actor),
            )),
            Err(LifecycleError::AuthoritySlotRegressed)
        );
    }

    #[test]
    fn authority_sequence_is_binding_global_and_journal_eviction_stays_fail_closed() {
        fn credential(sequence: u64) -> CredentialId {
            let mut bytes = [0u8; 32];
            bytes[..8].copy_from_slice(&sequence.to_le_bytes());
            CredentialId(bytes)
        }

        let config = config(8);
        let target_install = install(config.identity.agent, None, "sequence-target");
        let target = target_install.entry.actor;
        let request = LifecycleRequest::Suspend(target);
        let mut runtime = StandardAgentRuntime::new();
        runtime
            .apply(LifecycleRequest::Create(config.clone()))
            .unwrap();

        let last_sequence = MAX_AUTHORITY_DISPOSITIONS as u64 + 44;
        for sequence in 1..=last_sequence {
            assert_eq!(
                runtime.apply(authorized(
                    &config,
                    credential(sequence),
                    sequence,
                    (sequence % 251) as u8 + 1,
                    request.clone(),
                )),
                Err(LifecycleError::NotFound)
            );
        }

        let snapshot = runtime.snapshot();
        assert_eq!(snapshot.authority_sequence_high_water, Some(last_sequence));
        assert_eq!(
            snapshot.authority_dispositions.len(),
            MAX_AUTHORITY_DISPOSITIONS
        );
        assert_eq!(snapshot.authority_dispositions[0].sequence, 45);
        assert_eq!(
            snapshot
                .authority_dispositions
                .last()
                .map(|item| item.sequence),
            Some(last_sequence)
        );

        let encoded = super::super::wire::encode_standard_runtime_state(&snapshot);
        let decoded = super::super::wire::decode_standard_runtime_state(&encoded).unwrap();
        let mut reopened = StandardAgentRuntime::restore(decoded).unwrap();
        reopened
            .apply(LifecycleRequest::Install(target_install))
            .unwrap();
        assert_eq!(
            reopened.apply(authorized(&config, credential(1), 1, 2, request.clone())),
            Err(LifecycleError::AuthoritySequenceRegressed),
            "an evicted sequence remains consumed by the global high-water"
        );
        assert!(!reopened.actor(target).unwrap().suspended);
        assert_eq!(
            reopened.apply(authorized(
                &config,
                credential(45),
                45,
                (45 % 251) as u8 + 1,
                request.clone(),
            )),
            Err(LifecycleError::NotFound),
            "a retained exact refusal is still recoverable"
        );
        assert!(
            !reopened.actor(target).unwrap().suspended,
            "recovering a retained refusal must not reapply a now-valid request"
        );
        assert_eq!(
            reopened.apply(authorized(
                &config,
                credential(last_sequence + 1),
                last_sequence,
                (last_sequence % 251) as u8 + 1,
                request.clone(),
            )),
            Err(LifecycleError::AuthoritySequenceConflict),
            "a different credential cannot reuse a retained global sequence"
        );
        assert!(matches!(
            reopened.apply(authorized(
                &config,
                credential(last_sequence + 1),
                last_sequence + 1,
                7,
                request,
            )),
            Ok(LifecycleReply::Suspended(entry)) if entry.actor == target
        ));
    }

    #[test]
    fn restore_requires_the_journal_tail_to_match_the_global_high_water() {
        let config = config(8);
        let request = LifecycleRequest::Suspend(ActorId([0xb5; 32]));
        let mut runtime = StandardAgentRuntime::new();
        runtime
            .apply(LifecycleRequest::Create(config.clone()))
            .unwrap();
        assert_eq!(
            runtime.apply(authorized(&config, CredentialId([0xb6; 32]), 1, 1, request,)),
            Err(LifecycleError::NotFound)
        );

        let mut snapshot = runtime.snapshot();
        snapshot.authority_sequence_high_water = Some(2);
        assert!(matches!(
            StandardAgentRuntime::restore(snapshot),
            Err(LifecycleError::InvalidRequest)
        ));
    }

    #[test]
    fn authorized_create_is_durable_and_exactly_retryable() {
        let config = config(8);
        let credential = CredentialId([0x64; 32]);
        let request = LifecycleRequest::Create(config.clone());
        let mut runtime = StandardAgentRuntime::new();
        let created = runtime
            .apply(authorized_at(
                &config,
                credential,
                1,
                30,
                1,
                request.clone(),
            ))
            .unwrap();
        assert_eq!(created, LifecycleReply::Created(config.identity.clone()));

        let encoded = super::super::wire::encode_standard_runtime_state(&runtime.snapshot());
        let decoded = super::super::wire::decode_standard_runtime_state(&encoded).unwrap();
        let mut reopened = StandardAgentRuntime::restore(decoded).unwrap();
        assert_eq!(
            reopened
                .apply(authorized_at(&config, credential, 1, 31, 1, request,))
                .unwrap(),
            created
        );
        assert_eq!(reopened.snapshot().authority_slot_high_water, Some(31));
    }

    #[test]
    fn runtime_upgrade_retry_preserves_the_signed_from_deployment() {
        let config = config(8);
        let credential = CredentialId([0x74; 32]);
        let request = LifecycleRequest::UpgradeRuntime {
            from_deployment: config.identity.runtime_deployment,
            to_deployment: DeploymentId([0x75; 32]),
            to_program: ProgramId([0x76; 32]),
            producer: ProducerId([0x77; 32]),
            package: crate::service::BlobRef {
                hash: Hash([0x78; 32]),
                len: 10,
            },
            abi: RUNTIME_ABI_ID,
            capabilities: config.capabilities,
        };
        let mut runtime = StandardAgentRuntime::new();
        runtime
            .apply(LifecycleRequest::Create(config.clone()))
            .unwrap();
        let upgraded = runtime
            .apply(authorized(&config, credential, 1, 1, request.clone()))
            .unwrap();
        assert!(matches!(
            &upgraded,
            LifecycleReply::RuntimeUpgraded(identity)
                if identity.runtime_deployment == DeploymentId([0x75; 32])
        ));

        let encoded = super::super::wire::encode_standard_runtime_state(&runtime.snapshot());
        let decoded = super::super::wire::decode_standard_runtime_state(&encoded).unwrap();
        let mut reopened = StandardAgentRuntime::restore(decoded).unwrap();
        assert_eq!(
            reopened
                .apply(authorized(&config, credential, 1, 1, request))
                .unwrap(),
            upgraded,
            "retry uses the exact signed old-to-new request, not current-to-new"
        );
    }

    #[cfg(feature = "pvm")]
    #[test]
    fn signed_method_policy_is_authoritative_before_actor_dispatch() {
        use crate::actors::codec::Encode as _;
        use crate::actors::value::{Msg, TAG_DYNAMIC};
        use crate::service::wire::ServiceWire as _;
        use crate::service::{
            CapabilityId, MethodPolicy, Origin, PackageRolePolicies, SubjectId,
            method_authorization_policy_hash,
        };

        let config = config(4);
        let agent = config.identity.agent;
        let capability = CapabilityId::named("board.moderate");
        let policies = PackageRolePolicies {
            methods: vec![
                MethodPolicy {
                    method: "maintenance".into(),
                    schema: Hash([0x50; 32]),
                    policy: method_authorization_policy_hash(Some(capability), None, None).unwrap(),
                    public: false,
                    attested: false,
                    space_role: None,
                    capability: Some(capability),
                    actor_role: None,
                },
                MethodPolicy {
                    method: "set_title".into(),
                    schema: Hash([0x51; 32]),
                    policy: method_authorization_policy_hash(Some(capability), None, Some(7))
                        .unwrap(),
                    public: false,
                    attested: false,
                    space_role: None,
                    capability: Some(capability),
                    actor_role: Some(7),
                },
            ],
            task_dependencies: Vec::new(),
        }
        .encode();
        let policy_blob = super::super::execution::RuntimeBlob {
            reference: BlobRef::of_bytes(&policies),
            bytes: policies,
        };

        let mut runtime = StandardAgentRuntime::new();
        runtime.apply(LifecycleRequest::Create(config)).unwrap();
        let mut installed = install(agent, None, "board");
        installed.entry.role_policies = policy_blob.reference.clone();
        installed.role_policies = policy_blob.reference.clone();
        let actor = installed.entry.actor;
        let deployment = installed.entry.deployment;
        let program = installed.entry.program;
        runtime.apply(LifecycleRequest::Install(installed)).unwrap();

        let mut message = vec![TAG_DYNAMIC];
        message.extend_from_slice(&Msg::new("set_title").encode());
        let mut invocation = super::super::execution::ActorInvocation {
            invocation: InvocationId([0x52; 32]),
            actor,
            deployment,
            program,
            mode: super::super::MethodMode::Linear,
            auth: super::super::execution::ActorInvocationAuth {
                origin: Origin::Member(SubjectId([0x53; 32])),
                origin_service: None,
                space_role: None,
                actor_role: Some(7),
                capability: Some(capability),
            },
            message,
            availability: Vec::new(),
            gas: 1,
        };
        assert_eq!(
            runtime.authorize_execution(&invocation, &policy_blob),
            Ok(true)
        );

        invocation.auth.capability = Some(CapabilityId::named("board.read"));
        assert_eq!(
            runtime.authorize_execution(&invocation, &policy_blob),
            Ok(false)
        );

        // Public message bytes cannot forge the private caller context: even
        // role/capability fields paired with Anonymous remain unauthorized.
        invocation.auth.origin = Origin::Anonymous;
        invocation.auth.capability = Some(capability);
        assert_eq!(
            runtime.authorize_execution(&invocation, &policy_blob),
            Ok(false)
        );

        let mut system_message = vec![TAG_DYNAMIC];
        system_message.extend_from_slice(&Msg::new("maintenance").encode());
        invocation.message = system_message;
        invocation.auth = super::super::execution::ActorInvocationAuth {
            origin: Origin::System,
            origin_service: None,
            space_role: None,
            actor_role: None,
            capability: Some(capability),
        };
        assert_eq!(
            runtime.authorize_execution(&invocation, &policy_blob),
            Ok(true)
        );
        invocation.auth.capability = Some(CapabilityId::named("board.read"));
        assert_eq!(
            runtime.authorize_execution(&invocation, &policy_blob),
            Ok(false)
        );

        let corrupt = b"not-a-policy-set".to_vec();
        let corrupt_blob = super::super::execution::RuntimeBlob {
            reference: BlobRef::of_bytes(&corrupt),
            bytes: corrupt,
        };
        runtime.actors.get_mut(&actor).unwrap().record.role_policies =
            corrupt_blob.reference.clone();
        assert_eq!(
            runtime.authorize_execution(&invocation, &corrupt_blob),
            Err(super::super::execution::ActorExecutionError::InvalidAvailability)
        );
    }

    #[test]
    fn install_rejects_directory_provenance_mismatch() {
        let config = config(10);
        let agent = config.identity.agent;
        let mut runtime = StandardAgentRuntime::new();
        runtime.apply(LifecycleRequest::Create(config)).unwrap();

        let mut mismatched = install(agent, None, "counter");
        mismatched.entry.agent_schema.hash = Hash([0x44; 32]);
        assert_eq!(
            runtime.apply(LifecycleRequest::Install(mismatched)),
            Err(LifecycleError::InvalidRequest)
        );

        let mut mismatched = install(agent, None, "counter");
        mismatched.entry.state_layout = Hash([0x45; 32]);
        assert_eq!(
            runtime.apply(LifecycleRequest::Install(mismatched)),
            Err(LifecycleError::InvalidRequest)
        );

        let mut mismatched = install(agent, None, "counter");
        mismatched.entry.package.hash = Hash([0x46; 32]);
        assert_eq!(
            runtime.apply(LifecycleRequest::Install(mismatched)),
            Err(LifecycleError::InvalidRequest)
        );

        let mut mismatched = install(agent, None, "counter");
        mismatched.entry.role_policies.hash = Hash([0x47; 32]);
        assert_eq!(
            runtime.apply(LifecycleRequest::Install(mismatched)),
            Err(LifecycleError::InvalidRequest)
        );
        assert!(runtime.is_empty());
    }

    #[test]
    fn create_cannot_overstate_standard_runtime_capabilities() {
        let oversized = config(super::super::RuntimeCapabilities::STANDARD_MAX_ACTORS + 1);
        assert_eq!(
            StandardAgentRuntime::new().apply(LifecycleRequest::Create(oversized)),
            Err(LifecycleError::UnsupportedRuntime)
        );

        let mut proof_capable = config(1);
        proof_capable.capabilities.proofs = true;
        assert_eq!(
            StandardAgentRuntime::new().apply(LifecycleRequest::Create(proof_capable)),
            Err(LifecycleError::UnsupportedRuntime)
        );
    }

    #[test]
    fn install_rejects_proof_and_scheduler_requirements_before_state_changes() {
        let config = config(10);
        let agent = config.identity.agent;
        let mut runtime = StandardAgentRuntime::new();
        runtime.apply(LifecycleRequest::Create(config)).unwrap();

        let mut proof = install(agent, None, "attested");
        proof.requirements.proofs = true;
        assert_eq!(
            runtime.apply(LifecycleRequest::Install(proof)),
            Err(LifecycleError::UnsupportedRuntime)
        );

        let mut job = install(agent, None, "scheduled");
        job.requirements.scheduling = true;
        assert_eq!(
            runtime.apply(LifecycleRequest::Install(job)),
            Err(LifecycleError::UnsupportedRuntime)
        );
        assert!(runtime.is_empty());
    }

    #[test]
    fn actor_forest_has_no_privileged_root_actor() {
        let mut runtime = StandardAgentRuntime::new();
        let config = config(10);
        let agent = config.identity.agent;
        runtime.apply(LifecycleRequest::Create(config)).unwrap();
        let first = install(agent, None, "first");
        let second = install(agent, None, "second");
        let child = install(agent, Some(first.entry.actor), "child");
        runtime.apply(LifecycleRequest::Install(first)).unwrap();
        runtime.apply(LifecycleRequest::Install(second)).unwrap();
        runtime.apply(LifecycleRequest::Install(child)).unwrap();
        assert_eq!(runtime.len(), 3);
    }

    #[test]
    fn safe_removal_requires_a_leaf_with_no_durable_debt() {
        let mut runtime = StandardAgentRuntime::new();
        let config = config(10);
        let agent = config.identity.agent;
        runtime.apply(LifecycleRequest::Create(config)).unwrap();
        let parent = install(agent, None, "parent");
        let parent_id = parent.entry.actor;
        let deployment = parent.entry.deployment;
        let child = install(agent, Some(parent_id), "child");
        let child_id = child.entry.actor;
        runtime.apply(LifecycleRequest::Install(parent)).unwrap();
        runtime.apply(LifecycleRequest::Install(child)).unwrap();
        assert!(matches!(
            runtime.apply(LifecycleRequest::RemoveLeaf {
                actor: parent_id,
                expected_deployment: deployment,
            }),
            Err(LifecycleError::Busy(ActorLifecycleDebt { children: 1, .. }))
        ));
        runtime
            .set_lifecycle_debt(
                child_id,
                ActorLifecycleDebt {
                    outbox: 1,
                    ..ActorLifecycleDebt::default()
                },
            )
            .unwrap();
        assert!(matches!(
            runtime.apply(LifecycleRequest::RemoveLeaf {
                actor: child_id,
                expected_deployment: DeploymentId([7; 32]),
            }),
            Err(LifecycleError::Busy(ActorLifecycleDebt { outbox: 1, .. }))
        ));
    }

    #[test]
    fn runtime_upgrade_checks_every_installed_actor() {
        let mut runtime = StandardAgentRuntime::new();
        let config = config(10);
        let agent = config.identity.agent;
        runtime.apply(LifecycleRequest::Create(config)).unwrap();
        let actor = install(agent, None, "counter");
        runtime.apply(LifecycleRequest::Install(actor)).unwrap();
        let merge_only = RuntimeCapabilities {
            lanes: LaneSet::of(StateLane::Merge),
            scheduling: false,
            proofs: false,
            max_actors: 10,
        };
        assert_eq!(
            runtime.apply(LifecycleRequest::UpgradeRuntime {
                from_deployment: DeploymentId([4; 32]),
                to_deployment: DeploymentId([11; 32]),
                to_program: ProgramId([12; 32]),
                producer: ProducerId([18; 32]),
                package: BlobRef {
                    hash: Hash([13; 32]),
                    len: 100,
                },
                abi: RUNTIME_ABI_ID,
                capabilities: merge_only,
            }),
            Err(LifecycleError::UnsupportedRuntime)
        );
    }

    #[test]
    fn actor_program_changes_require_stateless_state() {
        let config = config(10);
        let agent = config.identity.agent;

        let mut stateful = StandardAgentRuntime::new();
        stateful
            .apply(LifecycleRequest::Create(config.clone()))
            .unwrap();
        let installed = install(agent, None, "stateful");
        let actor = installed.entry.actor;
        let requirements = installed.requirements;
        stateful
            .apply(LifecycleRequest::Install(installed))
            .unwrap();
        let replacement = UpgradeActor {
            actor,
            from_deployment: DeploymentId([7; 32]),
            to_deployment: DeploymentId([14; 32]),
            to_program: ProgramId([15; 32]),
            producer: ProducerId([19; 32]),
            package: BlobRef {
                hash: Hash([16; 32]),
                len: 100,
            },
            agent_schema: BlobRef {
                hash: Hash([17; 32]),
                len: 100,
            },
            role_policies: BlobRef {
                hash: Hash([18; 32]),
                len: 100,
            },
            state_layout: Hash([12; 32]),
            requirements,
        };
        assert_eq!(
            stateful.apply(LifecycleRequest::UpgradeActor(replacement.clone())),
            Err(LifecycleError::UnsupportedLane)
        );

        let mut stateless = StandardAgentRuntime::new();
        stateless.apply(LifecycleRequest::Create(config)).unwrap();
        let mut installed = install(agent, None, "stateless");
        installed.entry.lanes = LaneSet::NONE;
        installed.requirements.lanes = LaneSet::NONE;
        let actor = installed.entry.actor;
        stateless
            .apply(LifecycleRequest::Install(installed))
            .unwrap();
        let mut replacement = replacement;
        replacement.actor = actor;
        replacement.requirements.lanes = LaneSet::NONE;
        assert!(matches!(
            stateless.apply(LifecycleRequest::UpgradeActor(replacement)),
            Ok(LifecycleReply::Upgraded(entry))
                if entry.program == ProgramId([15; 32])
                    && entry.package.hash == Hash([16; 32])
                    && entry.role_policies.hash == Hash([18; 32])
        ));
    }

    #[test]
    fn upgrade_actor_is_blocked_by_pending_work() {
        let mut runtime = StandardAgentRuntime::new();
        let config = config(10);
        let agent = config.identity.agent;
        runtime.apply(LifecycleRequest::Create(config)).unwrap();
        let install = install(agent, None, "counter");
        let actor = install.entry.actor;
        runtime.apply(LifecycleRequest::Install(install)).unwrap();
        runtime
            .set_lifecycle_debt(
                actor,
                ActorLifecycleDebt {
                    continuations: 1,
                    ..ActorLifecycleDebt::default()
                },
            )
            .unwrap();
        let requirements = RuntimeRequirements {
            lanes: LaneSet::of(StateLane::Linear),
            scheduling: false,
            proofs: false,
        };
        assert!(matches!(
            runtime.apply(LifecycleRequest::UpgradeActor(UpgradeActor {
                actor,
                from_deployment: DeploymentId([7; 32]),
                to_deployment: DeploymentId([14; 32]),
                to_program: ProgramId([15; 32]),
                producer: ProducerId([19; 32]),
                package: BlobRef {
                    hash: Hash([16; 32]),
                    len: 100,
                },
                agent_schema: BlobRef {
                    hash: Hash([17; 32]),
                    len: 100,
                },
                role_policies: BlobRef {
                    hash: Hash([18; 32]),
                    len: 100,
                },
                state_layout: Hash([12; 32]),
                requirements,
            })),
            Err(LifecycleError::Busy(ActorLifecycleDebt {
                continuations: 1,
                ..
            }))
        ));
    }
}
