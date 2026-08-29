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
    LifecycleError, LifecycleReply, LifecycleRequest, RUNTIME_ABI_ID, RuntimeRequirements,
    StateLane,
};
use crate::service::{ActorId, AgentId, DeploymentId, Hash, InvocationId, ProducerId, ProgramId};

pub const MAX_DIRECTORY_PAGE: u16 = 256;
pub const MAX_INVOCATION_RESULTS_PER_LANE: usize = 256;
pub const MAX_INVOCATION_RESULT_BYTES_PER_LANE: usize = 8 * 1024 * 1024;

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
}

/// Canonical persisted state of the bundled runtime.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StandardRuntimeState {
    pub config: Option<AgentConfig>,
    pub actors: Vec<StandardActorState>,
    pub invocation_results: Vec<StandardInvocationResult>,
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

/// Runtime-owned bytes for each durable actor lane. `None` means the signed
/// initial content reference has not been hydrated yet; `Some([])` is a
/// canonical fresh lane.
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
        }
    }

    pub fn restore(state: StandardRuntimeState) -> Result<Self, LifecycleError> {
        let Some(config) = state.config else {
            return if state.actors.is_empty() && state.invocation_results.is_empty() {
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
                initial_state: actor.record.initial_state,
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
            || install.entry.suspended
            || install.producer == ProducerId::ZERO
            || install.package.hash == Hash::ZERO
            || install.package.len == 0
            || (install.initial_state.linear.is_some()
                && !install
                    .requirements
                    .lanes
                    .contains(super::StateLane::Linear))
            || (install.initial_state.merge.is_some()
                && !install.requirements.lanes.contains(super::StateLane::Merge))
            || (install.initial_state.local.is_some()
                && !install.requirements.lanes.contains(super::StateLane::Local))
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
        let lane_state = StandardLaneState::for_install(&install);
        self.actors.insert(
            entry.actor,
            ManagedActor {
                record: ActorRecord {
                    entry: install.entry,
                    producer: install.producer,
                    package: install.package,
                    initial_state: install.initial_state,
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
    ) -> Result<(StateLane, Vec<u8>), super::execution::ActorExecutionError> {
        use super::execution::ActorExecutionError;

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
        let lane = invocation
            .mode
            .write_lane()
            .ok_or(ActorExecutionError::UnsupportedMethod)?;
        if !config.identity.profile.supports(lane) || !actor.record.entry.lanes.contains(lane) {
            return Err(ActorExecutionError::UnsupportedMethod);
        }
        if self.invocation_result_count(lane) >= MAX_INVOCATION_RESULTS_PER_LANE
            || self.invocation_result_bytes(lane) >= MAX_INVOCATION_RESULT_BYTES_PER_LANE
        {
            return Err(ActorExecutionError::ResultCapacity);
        }
        let (value, initial) = actor.lane_state.select(lane, &actor.record.initial_state);
        match value {
            Some(bytes) => Ok((lane, bytes.clone())),
            None => initial
                .as_ref()
                .and_then(|reference| invocation.available(reference))
                .map(|bytes| (lane, bytes.to_vec()))
                .ok_or(ActorExecutionError::MissingState),
        }
    }

    #[cfg(feature = "pvm")]
    pub(crate) fn commit_execution(
        &mut self,
        invocation: &super::execution::ActorInvocation,
        reply: &super::execution::ActorExecutionReply,
        lane: StateLane,
        state: Vec<u8>,
    ) -> Result<(), super::execution::ActorExecutionError> {
        use super::execution::{ActorExecutionError, MAX_EXECUTION_STATE_BYTES};
        if state.len() > MAX_EXECUTION_STATE_BYTES {
            return Err(ActorExecutionError::InvalidActorOutput);
        }
        if reply.invocation != invocation.invocation
            || reply.actor != invocation.actor
            || reply.deployment != invocation.deployment
            || reply.lane != lane
            || self.invocation_results.contains_key(&invocation.invocation)
        {
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
            .filter(|result| result.reply.lane == lane)
            .count()
    }

    fn invocation_result_bytes(&self, lane: StateLane) -> usize {
        self.invocation_results
            .values()
            .filter(|result| result.reply.lane == lane)
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
        for (lane, value, initial) in [
            (
                StateLane::Linear,
                &state.linear,
                &actor.record.initial_state.linear,
            ),
            (
                StateLane::Merge,
                &state.merge,
                &actor.record.initial_state.merge,
            ),
            (
                StateLane::Local,
                &state.local,
                &actor.record.initial_state.local,
            ),
        ] {
            if value
                .as_ref()
                .is_some_and(|bytes| bytes.len() > super::execution::MAX_EXECUTION_STATE_BYTES)
                || (value.is_none() && initial.is_none())
                || (!actor.record.entry.lanes.contains(lane) && value.as_deref() != Some(&[][..]))
            {
                return Err(LifecycleError::InvalidRequest);
            }
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
        if upgrade.to_deployment == DeploymentId::ZERO || upgrade.to_program == ProgramId::ZERO {
            return Err(LifecycleError::InvalidRequest);
        }
        if upgrade.producer == ProducerId::ZERO
            || upgrade.package.hash == Hash::ZERO
            || upgrade.package.len == 0
        {
            return Err(LifecycleError::InvalidRequest);
        }
        actor.record.entry.deployment = upgrade.to_deployment;
        actor.record.entry.program = upgrade.to_program;
        actor.record.entry.lanes = upgrade.requirements.lanes;
        actor.record.producer = upgrade.producer;
        actor.record.package = upgrade.package;
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
}

impl StandardLaneState {
    fn for_install(install: &super::InstallActor) -> Self {
        fn pending_or_empty(
            declared: bool,
            initial: &Option<crate::service::BlobRef>,
        ) -> Option<Vec<u8>> {
            if declared && initial.is_some() {
                None
            } else {
                Some(Vec::new())
            }
        }
        Self {
            linear: pending_or_empty(
                install.requirements.lanes.contains(StateLane::Linear),
                &install.initial_state.linear,
            ),
            merge: pending_or_empty(
                install.requirements.lanes.contains(StateLane::Merge),
                &install.initial_state.merge,
            ),
            local: pending_or_empty(
                install.requirements.lanes.contains(StateLane::Local),
                &install.initial_state.local,
            ),
        }
    }

    #[cfg(feature = "pvm")]
    fn select<'a>(
        &'a self,
        lane: StateLane,
        initial: &'a super::ActorInitialState,
    ) -> (&'a Option<Vec<u8>>, &'a Option<crate::service::BlobRef>) {
        match lane {
            StateLane::Linear => (&self.linear, &initial.linear),
            StateLane::Merge => (&self.merge, &initial.merge),
            StateLane::Local => (&self.local, &initial.local),
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
        ActorInitialState, AgentIdentity, AgentProfile, AgentReplica, InstallActor, LaneSet,
        ReplicaRole, RuntimeCapabilities, StateLane, UpgradeActor,
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
        InstallActor {
            entry: ActorEntry {
                actor,
                name: name.into(),
                parent,
                deployment: DeploymentId([7; 32]),
                program: ProgramId([8; 32]),
                lanes: requirements.lanes,
                suspended: false,
            },
            producer: ProducerId([9; 32]),
            package: BlobRef {
                hash: Hash([10; 32]),
                len: 100,
            },
            initial_state: ActorInitialState {
                linear: None,
                merge: None,
                local: None,
            },
            requirements,
        }
    }

    #[test]
    fn created_agent_is_valid_and_usefully_empty() {
        let mut runtime = StandardAgentRuntime::new();
        let config = config(4096);
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
                requirements,
            })),
            Err(LifecycleError::Busy(ActorLifecycleDebt {
                continuations: 1,
                ..
            }))
        ));
    }
}
