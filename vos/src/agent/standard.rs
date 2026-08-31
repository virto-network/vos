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
    InvocationResultStorage, InvocationScope, LaneSet, LifecycleError, LifecycleReply,
    LifecycleRequest, RuntimeRequirements, StateLane,
};
use crate::service::{
    ActorId, AgentId, BlobRef, CredentialId, DeploymentId, Hash, InvocationId, ProducerId,
    ProgramId,
};

pub const MAX_DIRECTORY_PAGE: u16 = 256;
pub const MAX_INVOCATION_RESULTS_PER_LANE: usize = 32;
pub const MAX_INVOCATION_RESULT_BYTES_PER_LANE: usize = 64 * 1024;
pub const MAX_AUTHORITY_DISPOSITIONS: usize = 256;
/// Explicit cap below both the runtime-image byte limit and the generic wire
/// item limit. Historical entries are retained until checkpoint compaction.
pub const MAX_LANE_STATE_ENTRIES: usize = 16_384;

#[derive(Default)]
struct ArtifactResourceUsage {
    /// Catalog storage is hash-keyed. Retaining the one admitted length here
    /// both deduplicates exact references and rejects an unsatisfiable second
    /// length for the same content identity.
    lengths: BTreeMap<Hash, u64>,
    referenced_bytes: u64,
}

impl ArtifactResourceUsage {
    fn insert(
        &mut self,
        reference: &BlobRef,
        limits: super::contract::RuntimeResourceLimits,
    ) -> Result<(), LifecycleError> {
        if reference.hash == Hash::ZERO || reference.len == 0 {
            return Err(LifecycleError::InvalidRequest);
        }
        if let Some(encoded_len) = self.lengths.get(&reference.hash) {
            return if *encoded_len == reference.len {
                Ok(())
            } else {
                Err(LifecycleError::InvalidRequest)
            };
        }
        let references = self
            .lengths
            .len()
            .checked_add(1)
            .and_then(|count| u32::try_from(count).ok())
            .ok_or(LifecycleError::ResourceLimit)?;
        let referenced_bytes = self
            .referenced_bytes
            .checked_add(reference.len)
            .ok_or(LifecycleError::ResourceLimit)?;
        if reference.len > super::MAX_CATALOG_ARTIFACT_BYTES
            || references > limits.max_artifact_references
            || referenced_bytes > limits.max_artifact_referenced_bytes
        {
            return Err(LifecycleError::ResourceLimit);
        }
        self.lengths.insert(reference.hash, reference.len);
        self.referenced_bytes = referenced_bytes;
        Ok(())
    }
}

fn validate_artifact_resources<'a>(
    limits: super::contract::RuntimeResourceLimits,
    references: impl IntoIterator<Item = &'a BlobRef>,
) -> Result<(), LifecycleError> {
    if !limits.is_valid() {
        return Err(LifecycleError::InvalidRequest);
    }
    let mut usage = ArtifactResourceUsage::default();
    for reference in references {
        usage.insert(reference, limits)?;
    }
    Ok(())
}

fn actor_artifact_references(actor: &ManagedActor) -> [&BlobRef; 3] {
    [
        &actor.record.package,
        &actor.record.agent_schema,
        &actor.record.role_policies,
    ]
}

#[derive(Clone, Debug)]
struct ManagedActor {
    record: ActorRecord,
    /// Non-structural durable work. Child debt is derived from the directory.
    debt: ActorLifecycleDebt,
}

#[derive(Clone, Debug, Default)]
pub struct StandardAgentRuntime {
    config: Option<AgentConfig>,
    system_authority: Option<super::system_authority::SystemAuthorityState>,
    actors: BTreeMap<ActorId, ManagedActor>,
    lane_state: StandardLaneState,
    invocation_results: BTreeMap<(InvocationScope, InvocationId), StandardInvocationResult>,
    lane_revisions: StandardLaneRevisions,
    control_authority_slot: Option<u64>,
    authority_slot_high_water: Option<u64>,
    /// Highest binding-global authority sequence durably consumed.
    authority_sequence_high_water: Option<u64>,
    authority_dispositions: Vec<StandardAuthorityDisposition>,
}

/// Canonical persisted state of the bundled runtime.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StandardRuntimeState {
    pub config: Option<AgentConfig>,
    pub system_authority: Option<super::system_authority::SystemAuthorityState>,
    pub actors: Vec<StandardActorState>,
    pub lane_state: StandardLaneState,
    pub invocation_results: Vec<StandardInvocationResult>,
    pub lane_revisions: StandardLaneRevisions,
    pub control_authority_slot: Option<u64>,
    pub authority_slot_high_water: Option<u64>,
    pub authority_sequence_high_water: Option<u64>,
    pub authority_dispositions: Vec<StandardAuthorityDisposition>,
}

/// Replay-only durable objects selected by an authenticated native reapply.
/// Guest execution never exposes this metadata and raw journal-context bytes
/// cannot mint it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum StandardSystemAuthorityWrite {
    Finalize {
        admitted_fact: Option<super::system_authority::SystemAuthorityDecisionFact>,
        history: super::system_authority::SystemAuthorityDecisionWritePlan,
    },
    Rotation {
        record: super::system_authority::SystemAuthorityRotationRecord,
        history: super::system_authority::SystemAuthorityRotationWritePlan,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct StandardScopedApply {
    result: Result<LifecycleReply, LifecycleError>,
    system_authority_write: Option<StandardSystemAuthorityWrite>,
}

impl StandardScopedApply {
    pub(crate) const fn result(&self) -> &Result<LifecycleReply, LifecycleError> {
        &self.result
    }

    pub(crate) const fn system_authority_write(&self) -> Option<&StandardSystemAuthorityWrite> {
        self.system_authority_write.as_ref()
    }

    pub(crate) fn into_parts(
        self,
    ) -> (
        Result<LifecycleReply, LifecycleError>,
        Option<StandardSystemAuthorityWrite>,
    ) {
        (self.result, self.system_authority_write)
    }
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
    pub scope: InvocationScope,
    pub invocation: InvocationId,
    /// Install incarnation which owns this retained result.
    pub incarnation: Hash,
    pub request: Hash,
    pub reply: super::execution::ActorExecutionReply,
    /// Physical durable component retaining this exact result. Query replies
    /// have no logical write lane, so this cannot be inferred from `reply`.
    pub storage: InvocationResultStorage,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StandardLaneRevisions {
    pub linear: u64,
    pub merge: u64,
    pub local: u64,
    pub linear_authority_slot: Option<u64>,
    pub merge_authority_slot: Option<u64>,
    pub local_authority_slot: Option<u64>,
}

impl StandardLaneRevisions {
    fn authority_slot(self, lane: StateLane) -> Option<u64> {
        match lane {
            StateLane::Linear => self.linear_authority_slot,
            StateLane::Merge => self.merge_authority_slot,
            StateLane::Local => self.local_authority_slot,
        }
    }

    fn revision(self, lane: StateLane) -> u64 {
        match lane {
            StateLane::Linear => self.linear,
            StateLane::Merge => self.merge,
            StateLane::Local => self.local,
        }
    }

    fn set_authority_slot(&mut self, lane: StateLane, slot: u64) {
        *match lane {
            StateLane::Linear => &mut self.linear_authority_slot,
            StateLane::Merge => &mut self.merge_authority_slot,
            StateLane::Local => &mut self.local_authority_slot,
        } = Some(slot);
    }

    fn authority_slot_high_water(self) -> Option<u64> {
        [
            self.linear_authority_slot,
            self.merge_authority_slot,
            self.local_authority_slot,
        ]
        .into_iter()
        .flatten()
        .max()
    }

    #[cfg(feature = "pvm")]
    fn increment(&mut self, lane: StateLane) -> Result<(), super::execution::ActorExecutionError> {
        let revision = match lane {
            StateLane::Linear => &mut self.linear,
            StateLane::Merge => &mut self.merge,
            StateLane::Local => &mut self.local,
        };
        *revision = revision
            .checked_add(1)
            .ok_or(super::execution::ActorExecutionError::InvalidActorOutput)?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StandardActorState {
    pub record: ActorRecord,
    pub debt: ActorLifecycleDebt,
}

/// One independently keyed physical lane entry. Active entries are selected
/// by the directory's exact `(actor, state_generation)` pair. Nonmatching
/// entries are historical and remain authenticated until checkpoint-only
/// compaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StandardLaneEntry {
    pub actor: ActorId,
    pub state_generation: Hash,
    pub value: Vec<u8>,
}

/// Sparse physical state of all three independently persisted lanes. A
/// supported active actor with no matching entry hydrates as canonical empty
/// state; unsupported lanes hydrate as absent.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StandardLaneState {
    pub linear: Vec<StandardLaneEntry>,
    pub merge: Vec<StandardLaneEntry>,
    pub local: Vec<StandardLaneEntry>,
}

impl StandardAgentRuntime {
    pub const fn new() -> Self {
        Self {
            config: None,
            system_authority: None,
            actors: BTreeMap::new(),
            lane_state: StandardLaneState {
                linear: Vec::new(),
                merge: Vec::new(),
                local: Vec::new(),
            },
            invocation_results: BTreeMap::new(),
            lane_revisions: StandardLaneRevisions {
                linear: 0,
                merge: 0,
                local: 0,
                linear_authority_slot: None,
                merge_authority_slot: None,
                local_authority_slot: None,
            },
            control_authority_slot: None,
            authority_slot_high_water: None,
            authority_sequence_high_water: None,
            authority_dispositions: Vec::new(),
        }
    }

    pub fn config(&self) -> Option<&AgentConfig> {
        self.config.as_ref()
    }

    pub(crate) fn system_authority(
        &self,
    ) -> Option<&super::system_authority::SystemAuthorityState> {
        self.system_authority.as_ref()
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
            system_authority: self.system_authority.clone(),
            actors: self
                .actors
                .values()
                .map(|actor| StandardActorState {
                    record: actor.record.clone(),
                    debt: actor.debt,
                })
                .collect(),
            lane_state: self.lane_state.clone(),
            invocation_results: self.invocation_results.values().cloned().collect(),
            lane_revisions: self.lane_revisions,
            control_authority_slot: self.control_authority_slot,
            authority_slot_high_water: self.authority_slot_high_water,
            authority_sequence_high_water: self.authority_sequence_high_water,
            authority_dispositions: self.authority_dispositions.clone(),
        }
    }

    /// Drop only lane entries which do not belong to an active install.
    ///
    /// This is intentionally not part of ordinary lifecycle or actor
    /// execution. A checkpoint publisher may call it only while materializing
    /// a new authenticated checkpoint; journal history remains the authority
    /// for the compacted generations.
    #[allow(dead_code)]
    pub(crate) fn compact_historical_lane_entries_for_checkpoint(&mut self) {
        let actors = &self.actors;
        for lane in [StateLane::Linear, StateLane::Merge, StateLane::Local] {
            self.lane_state.select_mut(lane).retain(|entry| {
                actors.get(&entry.actor).is_some_and(|actor| {
                    actor.record.state_generation == entry.state_generation
                        && actor.record.entry.lanes.contains(lane)
                })
            });
        }
    }

    pub fn restore(state: StandardRuntimeState) -> Result<Self, LifecycleError> {
        let Some(config) = state.config else {
            return if state.actors.is_empty()
                && state.system_authority.is_none()
                && state.lane_state == StandardLaneState::default()
                && state.invocation_results.is_empty()
                && state.lane_revisions == StandardLaneRevisions::default()
                && state.control_authority_slot.is_none()
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
            || state.actors.iter().any(|actor| {
                actor.debt.children != 0 || actor.record.state_generation == Hash::ZERO
            })
            || state.invocation_results.windows(2).any(|pair| {
                (pair[0].scope, pair[0].invocation) >= (pair[1].scope, pair[1].invocation)
            })
            || !state.lane_state.is_canonical()
            || state.authority_dispositions.len() > MAX_AUTHORITY_DISPOSITIONS
            || state
                .authority_dispositions
                .windows(2)
                .any(|pair| pair[0].sequence >= pair[1].sequence)
        {
            return Err(LifecycleError::InvalidRequest);
        }

        let mut runtime = Self::new();
        runtime.apply_mutation(LifecycleRequest::Create(config))?;
        match (
            runtime
                .config
                .as_ref()
                .and_then(|config| config.system_authority_genesis.as_ref()),
            state.system_authority,
        ) {
            (Some(genesis), Some(system_authority)) => {
                system_authority
                    .validate_against_genesis(runtime.created()?.identity.agent, genesis)
                    .map_err(LifecycleError::SystemAuthority)?;
                runtime.system_authority = Some(system_authority);
            }
            (None, None) => {}
            _ => return Err(LifecycleError::InvalidRequest),
        }
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
                suspended.push((entry.actor, entry.deployment));
                entry.suspended = false;
            }
            let actor_id = entry.actor;
            let state_generation = actor.record.state_generation;
            runtime.install(
                super::InstallActor {
                    entry,
                    producer: actor.record.producer,
                    package: actor.record.package,
                    agent_schema: actor.record.agent_schema,
                    role_policies: actor.record.role_policies,
                    state_layout: actor.record.state_layout,
                    contract: actor.record.contract,
                    requirements: actor.record.requirements,
                },
                state_generation,
            )?;
            runtime.set_lifecycle_debt(actor_id, actor.debt)?;
        }
        for (actor, expected_deployment) in suspended {
            runtime.set_suspended(actor, expected_deployment, true)?;
        }
        runtime.lane_state = state.lane_state;
        runtime.lane_revisions = state.lane_revisions;
        runtime.validate_restored_lane_state()?;
        for result in state.invocation_results {
            let actor = runtime.actors.get(&result.reply.actor);
            if result.invocation == InvocationId::ZERO
                || result.incarnation == Hash::ZERO
                || result.reply.invocation != result.invocation
                || result.reply.incarnation != result.incarnation
                || result.request == Hash::ZERO
                || result.reply.status != super::execution::ActorExecutionStatus::Done
                || actor.is_none_or(|actor| {
                    actor.record.state_generation != result.incarnation
                        || actor.record.entry.deployment != result.reply.deployment
                })
                || result.scope != result.reply.mode.invocation_scope()
                || result.storage != result.reply.mode.result_storage()
                || !runtime.result_storage_supported(result.storage)
            {
                return Err(LifecycleError::InvalidRequest);
            }
            runtime
                .invocation_results
                .insert((result.scope, result.invocation), result);
        }
        runtime.control_authority_slot = state.control_authority_slot;
        for storage in [
            InvocationResultStorage::Control,
            InvocationResultStorage::Lane(StateLane::Linear),
            InvocationResultStorage::Lane(StateLane::Merge),
            InvocationResultStorage::Lane(StateLane::Local),
        ] {
            if runtime.invocation_result_count(storage) > MAX_INVOCATION_RESULTS_PER_LANE
                || runtime.invocation_result_bytes(storage) > MAX_INVOCATION_RESULT_BYTES_PER_LANE
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
        if runtime.authority_sequence_high_water.is_none()
            || runtime.authority_slot_high_water.is_none()
            || runtime.authority_dispositions.is_empty()
            || runtime
                .authority_dispositions
                .last()
                .map(|item| item.sequence)
                != runtime.authority_sequence_high_water
        {
            return Err(LifecycleError::InvalidRequest);
        }
        runtime.validate_signed_state_resource()?;
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

    fn validate_signed_state_resource(&self) -> Result<(), LifecycleError> {
        let limit = self
            .created()?
            .runtime_contract
            .resources
            .max_runtime_state_bytes as usize;
        let state = super::wire::encode_standard_runtime_state(&self.snapshot());
        if state.encoded_len().is_none_or(|bytes| bytes > limit) {
            Err(LifecycleError::ResourceLimit)
        } else {
            Ok(())
        }
    }

    fn record_authority_disposition(
        &mut self,
        credential: CredentialId,
        sequence: u64,
        claim: Hash,
        operation: Hash,
        observed_slot: u64,
        result: &Result<LifecycleReply, LifecycleError>,
    ) {
        self.authority_sequence_high_water = Some(sequence);
        self.authority_slot_high_water = Some(observed_slot);
        if self.authority_dispositions.len() == MAX_AUTHORITY_DISPOSITIONS {
            // Globally monotone sequences make the oldest journal entry the
            // only canonical eviction candidate. Its sequence remains below
            // the durable high-water, so a later retry is rejected without
            // reapplying the lifecycle operation.
            self.authority_dispositions.remove(0);
        }
        self.authority_dispositions
            .push(StandardAuthorityDisposition {
                credential,
                sequence,
                claim,
                operation,
                result: result.clone(),
            });
    }

    fn logical_slot_high_water(&self) -> Option<u64> {
        self.authority_slot_high_water
            .into_iter()
            .chain(self.control_authority_slot)
            .chain(self.lane_revisions.authority_slot_high_water())
            .max()
    }

    fn advance_result_authority_slot(
        &mut self,
        storage: InvocationResultStorage,
        observed_slot: u64,
    ) {
        match storage {
            InvocationResultStorage::Control => {
                self.control_authority_slot = Some(
                    self.control_authority_slot
                        .map_or(observed_slot, |current| current.max(observed_slot)),
                );
            }
            InvocationResultStorage::Lane(lane) => {
                let current = self.lane_revisions.authority_slot(lane);
                self.lane_revisions.set_authority_slot(
                    lane,
                    current.map_or(observed_slot, |v| v.max(observed_slot)),
                );
            }
        }
    }

    /// Commit only the monotone authority clock for one externally retained
    /// exact outcome. Terminal replies and deterministic execution errors do
    /// not enter the guest result table and cannot mutate actor state.
    pub(crate) fn commit_exact_outcome_clock(
        &mut self,
        invocation: &super::execution::ActorInvocation,
        observed_slot: u64,
    ) -> Result<(), super::execution::ActorExecutionError> {
        use super::execution::ActorExecutionError;

        let storage = invocation.mode.result_storage();
        if !self.result_storage_supported(storage) {
            return Err(ActorExecutionError::UnsupportedResultStorage);
        }
        self.advance_result_authority_slot(storage, observed_slot);
        Ok(())
    }

    /// Admit only invocation modes whose exact result has a durable owning
    /// component in this immutable profile/capability set.
    pub(crate) fn validate_invocation_result_storage(
        &self,
        invocation: &super::execution::ActorInvocation,
    ) -> Result<(), super::execution::ActorExecutionError> {
        if self.result_storage_supported(invocation.mode.result_storage()) {
            Ok(())
        } else {
            Err(super::execution::ActorExecutionError::UnsupportedResultStorage)
        }
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

    fn result_storage_supported(&self, storage: InvocationResultStorage) -> bool {
        let Some(config) = self.config.as_ref() else {
            return false;
        };
        match storage {
            InvocationResultStorage::Control => true,
            InvocationResultStorage::Lane(lane) => {
                config.identity.profile.supports(lane) && config.capabilities.lanes.contains(lane)
            }
        }
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
            entries.push(super::ActorDirectoryRecord {
                entry: actor.record.entry.clone(),
                incarnation: actor.record.state_generation,
            });
        }
        let next = if entries.len() == usize::from(limit) && iterator.next().is_some() {
            entries.last().map(|record| record.entry.actor)
        } else {
            None
        };
        Ok(LifecycleReply::Directory(super::ActorDirectoryPage {
            entries,
            next,
        }))
    }

    fn install(
        &mut self,
        install: super::InstallActor,
        state_generation: Hash,
    ) -> Result<LifecycleReply, LifecycleError> {
        self.validate_requirements(install.requirements)?;
        let config = self.created()?;
        if !config.runtime_contract.supports(install.contract) {
            return Err(LifecycleError::UnsupportedRuntime);
        }
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
            || state_generation == Hash::ZERO
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
        validate_artifact_resources(
            config.runtime_contract.resources,
            core::iter::once(&config.runtime_package)
                .chain(self.actors.values().flat_map(actor_artifact_references))
                .chain([
                    &install.package,
                    &install.agent_schema,
                    &install.role_policies,
                ]),
        )?;
        let entry = install.entry.clone();
        self.actors.insert(
            entry.actor,
            ManagedActor {
                record: ActorRecord {
                    entry: install.entry,
                    state_generation,
                    producer: install.producer,
                    package: install.package,
                    agent_schema: install.agent_schema,
                    role_policies: install.role_policies,
                    state_layout: install.state_layout,
                    contract: install.contract,
                    requirements: install.requirements,
                },
                debt: ActorLifecycleDebt::default(),
            },
        );
        Ok(LifecycleReply::Installed(entry))
    }

    #[cfg(feature = "pvm")]
    fn validate_invocation_target(
        &self,
        invocation: &super::execution::ActorInvocation,
    ) -> Result<&ManagedActor, super::execution::ActorExecutionError> {
        use super::execution::ActorExecutionError;

        invocation.validate()?;
        self.config
            .as_ref()
            .ok_or(ActorExecutionError::NotCreated)?;
        let actor = self
            .actors
            .get(&invocation.actor)
            .ok_or(ActorExecutionError::NotFound)?;
        if actor.record.state_generation != invocation.incarnation {
            return Err(ActorExecutionError::StaleIncarnation);
        }
        if actor.record.entry.deployment != invocation.deployment {
            return Err(ActorExecutionError::StaleDeployment);
        }
        if actor.record.entry.program != invocation.program {
            return Err(ActorExecutionError::WrongProgram);
        }
        Ok(actor)
    }

    #[cfg(feature = "pvm")]
    pub(crate) fn recover_execution(
        &mut self,
        invocation: &super::execution::ActorInvocation,
        observed_slot: u64,
    ) -> Result<Option<super::execution::ActorExecutionReply>, super::execution::ActorExecutionError>
    {
        use super::execution::ActorExecutionError;
        invocation.validate()?;
        let key = (invocation.mode.invocation_scope(), invocation.invocation);
        if let Some(result) = self.invocation_results.get(&key) {
            if result.request != invocation.commitment() {
                return Err(ActorExecutionError::DivergentInvocation);
            }
            let reply = result.reply.clone();
            let storage = result.storage;
            self.advance_result_authority_slot(storage, observed_slot);
            return Ok(Some(reply));
        }
        self.validate_invocation_target(invocation)?;
        Ok(None)
    }

    #[cfg(feature = "pvm")]
    pub(crate) fn verify_invocation_authority(
        &self,
        invocation: &super::execution::ActorInvocation,
        authority: &super::authority::ActorInvocationReceipt,
    ) -> Result<(), super::execution::ActorExecutionError> {
        use super::execution::ActorExecutionError;

        let config = self
            .config
            .as_ref()
            .ok_or(ActorExecutionError::NotCreated)?;
        authority
            .validate_for(
                &config.authority,
                config.identity.space,
                config.identity.agent,
                invocation,
            )
            .map_err(|_| ActorExecutionError::InvalidAuthorization)
    }

    #[cfg(feature = "pvm")]
    pub(crate) fn validate_unseen_invocation_slot(
        &self,
        _invocation: &super::execution::ActorInvocation,
        authority: &super::authority::ActorInvocationReceipt,
        observed_slot: u64,
    ) -> Result<(), super::execution::ActorExecutionError> {
        use super::execution::ActorExecutionError;

        if observed_slot < authority.claim.valid_from || observed_slot > authority.claim.valid_until
        {
            return Err(ActorExecutionError::AuthorityExpired);
        }
        let high_water = self.logical_slot_high_water();
        if high_water.is_some_and(|high_water| observed_slot < high_water) {
            return Err(ActorExecutionError::AuthoritySlotRegressed);
        }
        Ok(())
    }

    #[cfg(feature = "pvm")]
    pub(crate) fn prepare_execution_state(
        &self,
        invocation: &super::execution::ActorInvocation,
    ) -> Result<super::execution::ActorStateLanes, super::execution::ActorExecutionError> {
        use super::execution::{ActorExecutionError, ActorStateLanes};

        let config = self
            .config
            .as_ref()
            .ok_or(ActorExecutionError::NotCreated)?;
        let actor = self.validate_invocation_target(invocation)?;
        if actor.record.entry.suspended {
            return Err(ActorExecutionError::Suspended);
        }
        if let Some(lane) = invocation.mode.write_lane() {
            if !config.identity.profile.supports(lane) || !actor.record.entry.lanes.contains(lane) {
                return Err(ActorExecutionError::UnsupportedMethod);
            }
        }
        let result_storage = invocation.mode.result_storage();
        if !self.result_storage_supported(result_storage) {
            return Err(ActorExecutionError::UnsupportedResultStorage);
        }
        if self.invocation_result_count(result_storage) >= MAX_INVOCATION_RESULTS_PER_LANE
            || self.invocation_result_bytes(result_storage) >= MAX_INVOCATION_RESULT_BYTES_PER_LANE
        {
            return Err(ActorExecutionError::ResultCapacity);
        }
        let resolve = |lane| -> Result<Option<Vec<u8>>, ActorExecutionError> {
            if !actor.record.entry.lanes.contains(lane) {
                return Ok(None);
            }
            Ok(Some(
                self.lane_state
                    .lookup(
                        lane,
                        actor.record.entry.actor,
                        actor.record.state_generation,
                    )
                    .map_or_else(Vec::new, |entry| entry.value.clone()),
            ))
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
        reply: &mut super::execution::ActorExecutionReply,
        before: &super::execution::ActorStateLanes,
        mut after: super::execution::ActorStateLanes,
        observed_slot: u64,
    ) -> Result<(), super::execution::ActorExecutionError> {
        use super::execution::{ActorExecutionError, MAX_EXECUTION_STATE_BYTES};
        self.validate_invocation_target(invocation)?;
        if reply.invocation != invocation.invocation
            || reply.actor != invocation.actor
            || reply.incarnation != invocation.incarnation
            || reply.deployment != invocation.deployment
            || reply.mode != invocation.mode
            || reply.lane != invocation.mode.write_lane()
            || reply.observation != super::execution::ActorObservation::default()
            || self
                .invocation_results
                .contains_key(&(invocation.mode.invocation_scope(), invocation.invocation))
        {
            return Err(ActorExecutionError::InvalidActorOutput);
        }
        let write_lane = invocation.mode.write_lane();
        for lane in [StateLane::Linear, StateLane::Merge, StateLane::Local] {
            let previous = before.get(lane);
            // Generated actors normalize every non-owned fresh lane back to
            // the runtime's empty sentinel after checking the reconstructed
            // canonical frame. Exact comparison is therefore sound from the
            // first invocation onward, including for hand-written PVMs.
            if Some(lane) != write_lane && !invocation.mode.can_read(lane) {
                if after.get(lane).is_some_and(|bytes| !bytes.is_empty()) {
                    return Err(ActorExecutionError::InvalidActorOutput);
                }
            } else if Some(lane) != write_lane {
                match previous {
                    Some(previous) if after.get(lane) != Some(previous) => {
                        return Err(ActorExecutionError::InvalidActorOutput);
                    }
                    None if after.get(lane).is_some_and(|bytes| !bytes.is_empty()) => {
                        return Err(ActorExecutionError::InvalidActorOutput);
                    }
                    Some(_) | None => {}
                }
            }
        }
        let result_storage = invocation.mode.result_storage();
        if !self.result_storage_supported(result_storage) {
            return Err(ActorExecutionError::UnsupportedResultStorage);
        }
        if self.invocation_result_count(result_storage) >= MAX_INVOCATION_RESULTS_PER_LANE
            || self
                .invocation_result_bytes(result_storage)
                .saturating_add(reply.reply.len())
                > MAX_INVOCATION_RESULT_BYTES_PER_LANE
        {
            return Err(ActorExecutionError::ResultCapacity);
        }
        if let Some(lane) = write_lane {
            let state = after
                .take(lane)
                .ok_or(ActorExecutionError::InvalidActorOutput)?;
            if state.len() > MAX_EXECUTION_STATE_BYTES {
                return Err(ActorExecutionError::InvalidActorOutput);
            }
            let actor = self
                .actors
                .get(&reply.actor)
                .ok_or(ActorExecutionError::NotFound)?;
            if actor.record.state_generation != reply.incarnation {
                return Err(ActorExecutionError::StaleIncarnation);
            }
            self.lane_state.upsert(
                lane,
                actor.record.entry.actor,
                actor.record.state_generation,
                state,
            )?;
            self.lane_revisions.increment(lane)?;
        }
        reply.observation = self.observation(reply.actor, reply.mode)?;
        self.advance_result_authority_slot(result_storage, observed_slot);
        let scope = invocation.mode.invocation_scope();
        self.invocation_results.insert(
            (scope, invocation.invocation),
            StandardInvocationResult {
                scope,
                invocation: invocation.invocation,
                incarnation: invocation.incarnation,
                request: invocation.commitment(),
                reply: reply.clone(),
                storage: result_storage,
            },
        );
        Ok(())
    }

    fn invocation_result_count(&self, storage: InvocationResultStorage) -> usize {
        self.invocation_results
            .values()
            .filter(|result| result.storage == storage)
            .count()
    }

    fn invocation_result_bytes(&self, storage: InvocationResultStorage) -> usize {
        self.invocation_results
            .values()
            .filter(|result| result.storage == storage)
            .fold(0usize, |total, result| {
                total.saturating_add(result.reply.reply.len())
            })
    }

    #[cfg(feature = "pvm")]
    fn observation(
        &self,
        actor: ActorId,
        mode: super::MethodMode,
    ) -> Result<super::execution::ActorObservation, super::execution::ActorExecutionError> {
        use super::execution::{ActorExecutionError, ActorObservation};

        let actor = self
            .actors
            .get(&actor)
            .ok_or(ActorExecutionError::NotFound)?;
        Ok(ActorObservation {
            linear_revision: (actor.record.entry.lanes.contains(StateLane::Linear)
                && mode.can_read(StateLane::Linear))
            .then_some(self.lane_revisions.linear),
            merge_frontier: (actor.record.entry.lanes.contains(StateLane::Merge)
                && mode.can_read(StateLane::Merge))
            .then(|| {
                let merge = self
                    .lane_state
                    .lookup(
                        StateLane::Merge,
                        actor.record.entry.actor,
                        actor.record.state_generation,
                    )
                    .map_or(&[][..], |entry| entry.value.as_slice());
                Hash::digest(
                    b"vos/agent/merge-frontier",
                    &[&actor.record.entry.actor.0, merge],
                )
            }),
            local_revision: (actor.record.entry.lanes.contains(StateLane::Local)
                && mode.can_read(StateLane::Local))
            .then_some(self.lane_revisions.local),
        })
    }

    fn validate_restored_lane_state(&self) -> Result<(), LifecycleError> {
        if !self.lane_state.is_canonical() {
            return Err(LifecycleError::InvalidRequest);
        }
        let profile = self.created()?.identity.profile;
        for (lane, entries) in self.lane_state.lanes() {
            // Profile support is immutable. Unlike a Local/Shared runtime
            // capability downgrade, a Private agent could never have owned
            // Linear history, so any such bytes or cursor are corruption.
            if !profile.supports(lane)
                && (!entries.is_empty()
                    || self.lane_revisions.revision(lane) != 0
                    || self.lane_revisions.authority_slot(lane).is_some())
            {
                return Err(LifecycleError::InvalidRequest);
            }
            for entry in entries {
                if let Some(actor) = self.actors.get(&entry.actor)
                    && actor.record.state_generation == entry.state_generation
                    && !actor.record.entry.lanes.contains(lane)
                {
                    return Err(LifecycleError::InvalidRequest);
                }
            }
        }
        for actor in self.actors.values() {
            let total = [StateLane::Linear, StateLane::Merge, StateLane::Local]
                .into_iter()
                .filter(|lane| actor.record.entry.lanes.contains(*lane))
                .try_fold(0usize, |total, lane| {
                    total.checked_add(
                        self.lane_state
                            .lookup(
                                lane,
                                actor.record.entry.actor,
                                actor.record.state_generation,
                            )
                            .map_or(0, |entry| entry.value.len()),
                    )
                });
            if total.is_none_or(|len| len > super::execution::MAX_EXECUTION_STATE_TOTAL_BYTES) {
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
        if !self.created()?.runtime_contract.supports(upgrade.contract) {
            return Err(LifecycleError::UnsupportedRuntime);
        }
        let debt = self.lifecycle_debt(upgrade.actor)?;
        if !quiescent(debt) {
            return Err(LifecycleError::Busy(debt));
        }
        let actor = self
            .actors
            .get(&upgrade.actor)
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
        let config = self.created()?;
        validate_artifact_resources(
            config.runtime_contract.resources,
            core::iter::once(&config.runtime_package)
                .chain(
                    self.actors
                        .iter()
                        .filter(|(actor, _)| **actor != upgrade.actor)
                        .flat_map(|(_, actor)| actor_artifact_references(actor)),
                )
                .chain([
                    &upgrade.package,
                    &upgrade.agent_schema,
                    &upgrade.role_policies,
                ]),
        )?;
        let actor = self
            .actors
            .get_mut(&upgrade.actor)
            .expect("validated actor remains installed");
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
        actor.record.contract = upgrade.contract;
        actor.record.requirements = upgrade.requirements;
        Ok(LifecycleReply::Upgraded(actor.record.entry.clone()))
    }

    fn set_suspended(
        &mut self,
        actor: ActorId,
        expected_deployment: DeploymentId,
        suspended: bool,
    ) -> Result<LifecycleReply, LifecycleError> {
        let actor = self
            .actors
            .get_mut(&actor)
            .ok_or(LifecycleError::NotFound)?;
        if actor.record.entry.deployment != expected_deployment {
            return Err(LifecycleError::StaleDeployment);
        }
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
        scope: InvocationScope,
        invocation: InvocationId,
        request: Hash,
        authority: super::authority::ActorInvocationReceipt,
    ) -> Result<LifecycleReply, LifecycleError> {
        let result = self
            .invocation_results
            .get(&(scope, invocation))
            .ok_or(LifecycleError::NotFound)?;
        if result.request != request || result.scope != scope {
            return Err(LifecycleError::InvalidRequest);
        }
        let config = self.created()?;
        if authority.verify_guest_signature(&config.authority).is_err()
            || authority.claim.space != config.identity.space
            || authority.claim.agent != config.identity.agent
            || authority.claim.authorization
                != Hash::digest(b"vos/agent/invocation-authorization", &[&request.0])
        {
            return Err(LifecycleError::InvalidRequest);
        }
        self.invocation_results.remove(&(scope, invocation));
        Ok(LifecycleReply::InvocationAcknowledged { scope, invocation })
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
        contract: super::contract::RuntimePackageContract,
        capabilities: super::RuntimeCapabilities,
    ) -> Result<LifecycleReply, LifecycleError> {
        let config = self.created()?;
        let intrinsic = super::RuntimeCapabilities::standard();
        if config.identity.runtime_deployment != from_deployment {
            return Err(LifecycleError::StaleDeployment);
        }
        if !contract.is_valid()
            || to_deployment == DeploymentId::ZERO
            || to_program == ProgramId::ZERO
            || producer == ProducerId::ZERO
            || package.hash == Hash::ZERO
            || package.len == 0
            || capabilities.max_actors > intrinsic.max_actors
            || capabilities.lanes.bits() & !intrinsic.lanes.bits() != 0
            || (capabilities.scheduling && !intrinsic.scheduling)
            || (capabilities.proofs && !intrinsic.proofs)
            || capabilities.max_actors < self.actors.len() as u32
            || !capabilities.lanes.supported_by(config.identity.profile)
            || self.actors.values().any(|actor| {
                !capabilities.satisfies(actor.record.requirements)
                    || !contract.supports(actor.record.contract)
            })
            || self.invocation_results.values().any(|result| {
                matches!(
                    result.storage,
                    InvocationResultStorage::Lane(lane)
                        if !config.identity.profile.supports(lane)
                            || !capabilities.lanes.contains(lane)
                )
            })
        {
            return Err(LifecycleError::UnsupportedRuntime);
        }
        validate_artifact_resources(
            contract.resources,
            core::iter::once(&package)
                .chain(self.actors.values().flat_map(actor_artifact_references)),
        )?;
        if let Some(debt) = self
            .actors
            .keys()
            .filter_map(|actor| self.lifecycle_debt(*actor).ok())
            .find(|debt| !quiescent(*debt))
        {
            return Err(LifecycleError::Busy(debt));
        }
        let mut next = self.clone();
        let config = next.config.as_mut().expect("created agent has config");
        config.identity.runtime_deployment = to_deployment;
        config.identity.runtime_program = to_program;
        config.identity.runtime_producer = producer;
        config.runtime_package = package;
        config.runtime_contract = contract;
        config.capabilities = capabilities;
        let identity = config.identity.clone();
        next.validate_signed_state_resource()?;
        *self = next;
        Ok(LifecycleReply::RuntimeUpgraded(identity))
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
        let claim = &admission.receipt.claim;
        let required_capability = request
            .required_capability()
            .ok_or(LifecycleError::InvalidRequest)?;
        let (space, agent) = match (&request, self.config.as_ref()) {
            (LifecycleRequest::Create(config), _) => (config.identity.space, config.identity.agent),
            (_, Some(config)) => (config.identity.space, config.identity.agent),
            (_, None) => return Err(LifecycleError::NotCreated),
        };
        if admission.receipt.verify_guest_signature(authority).is_err()
            || claim.space != space
            || claim.agent != agent
            || matches!(
                &request,
                LifecycleRequest::Create(config)
                    if claim.principal != config.identity.owner
            )
            || claim.capability != crate::service::CapabilityId::named(required_capability)
            || claim.operation != request.commitment()
            || matches!(
                request,
                LifecycleRequest::Inspect { .. }
                    | LifecycleRequest::AcknowledgeInvocation { .. }
                    | LifecycleRequest::Authorized { .. }
            )
        {
            return Err(LifecycleError::InvalidRequest);
        }
        if matches!(
            &request,
            LifecycleRequest::Create(config)
                if config
                    .system_authority_genesis
                    .as_ref()
                    .is_some_and(|genesis| genesis.initial_sequence() != claim.sequence)
        ) {
            return Err(LifecycleError::SystemAuthority(
                super::system_authority::SystemAuthorityError::InvalidGenesis,
            ));
        }

        let claim_hash = claim.signing_message();

        if let Some(disposition) = self
            .authority_dispositions
            .iter()
            .find(|disposition| disposition.sequence == claim.sequence)
        {
            if disposition.credential != claim.credential
                || disposition.claim != claim_hash
                || disposition.operation != claim.operation
            {
                return Err(LifecycleError::AuthoritySequenceConflict);
            }
            self.authority_slot_high_water = Some(
                self.authority_slot_high_water
                    .map_or(admission.observed_slot, |current| {
                        current.max(admission.observed_slot)
                    }),
            );
            return disposition.result.clone();
        }

        if self
            .authority_sequence_high_water
            .is_some_and(|high_water| claim.sequence <= high_water)
        {
            return Err(LifecycleError::AuthoritySequenceRegressed);
        }
        if admission.observed_slot < claim.valid_from || admission.observed_slot > claim.valid_until
        {
            return Err(LifecycleError::InvalidRequest);
        }
        if self
            .logical_slot_high_water()
            .is_some_and(|high_water| admission.observed_slot < high_water)
        {
            return Err(LifecycleError::AuthoritySlotRegressed);
        }

        // Lifecycle implementations promise atomic rejection. Preserve that
        // property defensively while still consuming the signed sequence and
        // recording its exact deterministic refusal.
        let install_generation = match &request {
            LifecycleRequest::Install(install) => Some(derive_state_generation(
                claim_hash,
                claim.sequence,
                claim.operation,
                install.entry.actor,
            )),
            _ => None,
        };
        let before = self.clone();
        let result = match (request, install_generation) {
            (LifecycleRequest::Install(install), Some(generation)) => {
                self.install(install, generation)
            }
            (LifecycleRequest::Install(_), None) => Err(LifecycleError::InvalidRequest),
            (request, None) => self.apply_mutation(request),
            (_, Some(_)) => unreachable!("only install requests derive an actor generation"),
        };
        if result.is_err() {
            *self = before.clone();
        }

        // Before Create there is no canonical Agent state in which to retain
        // a disposition. Preserve the semantic refusal verbatim; only a
        // successful Create whose exact Created disposition exceeds its own
        // signed ceiling is translated to `ResourceLimit` below.
        if before.config.is_none() && result.is_err() {
            *self = before;
            return result;
        }

        // The signed state ceiling owns the exact final image for every
        // authorized outcome, including authority high-water and the retained
        // disposition itself. Successful Create/UpgradeRuntime naturally use
        // the newly installed contract here; every other transition uses the
        // current contract.
        let mut prospective = self.clone();
        prospective.record_authority_disposition(
            claim.credential,
            claim.sequence,
            claim_hash,
            claim.operation,
            admission.observed_slot,
            &result,
        );
        if prospective.validate_signed_state_resource().is_ok() {
            *self = prospective;
            return result;
        }

        // Roll back application semantics and retain a deterministic capacity
        // refusal under the pre-transition contract. An established Agent has
        // at least its Create disposition available as bounded eviction
        // headroom. `ResourceLimit` is smaller than every successful reply and
        // no larger than a fixed lifecycle error, so replacing the oldest
        // entry cannot grow a previously valid image.
        let limited = Err(LifecycleError::ResourceLimit);
        let mut fallback = before.clone();
        if fallback.config.is_none() {
            *self = before;
            return limited;
        }
        if !fallback.authority_dispositions.is_empty() {
            fallback.authority_dispositions.remove(0);
        }
        fallback.record_authority_disposition(
            claim.credential,
            claim.sequence,
            claim_hash,
            claim.operation,
            admission.observed_slot,
            &limited,
        );
        if fallback.validate_signed_state_resource().is_ok() {
            *self = fallback;
        } else {
            // A non-production state created without an authorized Create can
            // have no eviction headroom. Fail closed without making that
            // malformed baseline larger.
            *self = before;
        }
        limited
    }

    fn live_system_authority(
        &self,
    ) -> Result<&super::system_authority::SystemAuthorityState, LifecycleError> {
        let config = self.created()?;
        let genesis =
            config
                .system_authority_genesis
                .as_ref()
                .ok_or(LifecycleError::SystemAuthority(
                    super::system_authority::SystemAuthorityError::WrongSystemAgent,
                ))?;
        let state = self
            .system_authority
            .as_ref()
            .ok_or(LifecycleError::SystemAuthority(
                super::system_authority::SystemAuthorityError::InvalidState,
            ))?;
        state
            .validate_against_genesis(config.identity.agent, genesis)
            .map_err(LifecycleError::SystemAuthority)?;
        Ok(state)
    }

    /// Apply a management input whose raw journal context has independently
    /// been authenticated by replay. The opaque scope is the capability; the
    /// wire context is exact-compared to it before any transition or write
    /// plan can be produced.
    pub(crate) fn apply_scoped(
        &mut self,
        context: super::wire::RuntimeJournalContext,
        trusted_scope: super::system_authority::SystemAuthorityJournalScope,
        request: LifecycleRequest,
    ) -> StandardScopedApply {
        if !context.matches_system_authority_scope(trusted_scope) {
            return StandardScopedApply {
                result: Err(LifecycleError::SystemAuthority(
                    super::system_authority::SystemAuthorityError::InvalidScope,
                )),
                system_authority_write: None,
            };
        }
        match request {
            LifecycleRequest::FinalizeSystemAuthority(finalize) => {
                self.apply_system_authority_finalize(trusted_scope, finalize)
            }
            LifecycleRequest::RotateSystemAuthority(rotation) => {
                self.apply_system_authority_rotation(trusted_scope, rotation)
            }
            request => StandardScopedApply {
                result: self.apply(request),
                system_authority_write: None,
            },
        }
    }

    /// Guest/data-only application. Raw context bytes select deterministic
    /// state and reply bytes, but the primitive strips every admitted fact,
    /// committee record, and history plan from this path.
    pub(crate) fn apply_guest(
        &mut self,
        context: Option<super::wire::RuntimeJournalContext>,
        request: LifecycleRequest,
    ) -> Result<LifecycleReply, LifecycleError> {
        match request {
            LifecycleRequest::FinalizeSystemAuthority(finalize) => match context {
                Some(context) => self.simulate_system_authority_finalize(context, finalize),
                None => self.apply(LifecycleRequest::FinalizeSystemAuthority(finalize)),
            },
            LifecycleRequest::RotateSystemAuthority(rotation) => match context {
                Some(context) => self.simulate_system_authority_rotation(context, rotation),
                None => self.apply(LifecycleRequest::RotateSystemAuthority(rotation)),
            },
            request => self.apply(request),
        }
    }

    fn apply_system_authority_finalize(
        &mut self,
        trusted_scope: super::system_authority::SystemAuthorityJournalScope,
        finalize: super::system_authority::SystemAuthorityFinalize,
    ) -> StandardScopedApply {
        let transition = match self.live_system_authority().and_then(|state| {
            state
                .apply_finalize(trusted_scope, &finalize)
                .map_err(LifecycleError::SystemAuthority)
        }) {
            Ok(transition) => transition,
            Err(error) => {
                return StandardScopedApply {
                    result: Err(error),
                    system_authority_write: None,
                };
            }
        };
        let before = self.system_authority.clone();
        self.system_authority = Some(transition.state().clone());
        let result = Ok(LifecycleReply::SystemAuthorityFinalized(
            transition.outcome(),
        ));
        if self.validate_signed_state_resource().is_err() {
            self.system_authority = before;
            return StandardScopedApply {
                result: Err(LifecycleError::ResourceLimit),
                system_authority_write: None,
            };
        }
        StandardScopedApply {
            result,
            system_authority_write: Some(StandardSystemAuthorityWrite::Finalize {
                admitted_fact: transition.admitted_fact().cloned(),
                history: transition.history().clone(),
            }),
        }
    }

    fn apply_system_authority_rotation(
        &mut self,
        trusted_scope: super::system_authority::SystemAuthorityJournalScope,
        rotation: super::system_authority::SystemAuthorityRotation,
    ) -> StandardScopedApply {
        let transition = match self.live_system_authority().and_then(|state| {
            state
                .apply_rotation(trusted_scope, &rotation)
                .map_err(LifecycleError::SystemAuthority)
        }) {
            Ok(transition) => transition,
            Err(error) => {
                return StandardScopedApply {
                    result: Err(error),
                    system_authority_write: None,
                };
            }
        };
        let before = self.system_authority.clone();
        self.system_authority = Some(transition.state().clone());
        let result = Ok(LifecycleReply::SystemAuthorityRotated {
            rotation: transition.record().id(),
            epoch: transition.record().new_epoch(),
            exact_retry: transition.exact_retry(),
        });
        if self.validate_signed_state_resource().is_err() {
            self.system_authority = before;
            return StandardScopedApply {
                result: Err(LifecycleError::ResourceLimit),
                system_authority_write: None,
            };
        }
        StandardScopedApply {
            result,
            system_authority_write: Some(StandardSystemAuthorityWrite::Rotation {
                record: transition.record().clone(),
                history: transition.history().clone(),
            }),
        }
    }

    fn simulate_system_authority_finalize(
        &mut self,
        context: super::wire::RuntimeJournalContext,
        finalize: super::system_authority::SystemAuthorityFinalize,
    ) -> Result<LifecycleReply, LifecycleError> {
        let (state, outcome) = self
            .live_system_authority()?
            .simulate_finalize_untrusted(context.genesis(), context.agent_admission(), &finalize)
            .map_err(LifecycleError::SystemAuthority)?;
        let before = self.system_authority.replace(state);
        if self.validate_signed_state_resource().is_err() {
            self.system_authority = before;
            return Err(LifecycleError::ResourceLimit);
        }
        Ok(LifecycleReply::SystemAuthorityFinalized(outcome))
    }

    fn simulate_system_authority_rotation(
        &mut self,
        context: super::wire::RuntimeJournalContext,
        rotation: super::system_authority::SystemAuthorityRotation,
    ) -> Result<LifecycleReply, LifecycleError> {
        let (state, rotation, epoch, exact_retry) = self
            .live_system_authority()?
            .simulate_rotation_untrusted(context.genesis(), context.agent_admission(), &rotation)
            .map_err(LifecycleError::SystemAuthority)?;
        let before = self.system_authority.replace(state);
        if self.validate_signed_state_resource().is_err() {
            self.system_authority = before;
            return Err(LifecycleError::ResourceLimit);
        }
        Ok(LifecycleReply::SystemAuthorityRotated {
            rotation,
            epoch,
            exact_retry,
        })
    }

    fn apply_mutation(
        &mut self,
        request: LifecycleRequest,
    ) -> Result<LifecycleReply, LifecycleError> {
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
                    return Err(LifecycleError::UnsupportedRuntime);
                }
                validate_artifact_resources(
                    config.runtime_contract.resources,
                    core::iter::once(&config.runtime_package),
                )?;
                let identity = config.identity.clone();
                let system_authority = config
                    .system_authority_genesis
                    .as_ref()
                    .map(|genesis| {
                        super::system_authority::SystemAuthorityState::from_genesis(
                            config.identity.agent,
                            genesis,
                        )
                    })
                    .transpose()
                    .map_err(LifecycleError::SystemAuthority)?;
                self.config = Some(config);
                self.system_authority = system_authority;
                Ok(LifecycleReply::Created(identity))
            }
            LifecycleRequest::Install(_) => Err(LifecycleError::InvalidRequest),
            LifecycleRequest::UpgradeActor(upgrade) => self.upgrade_actor(upgrade),
            LifecycleRequest::Suspend {
                actor,
                expected_deployment,
            } => self.set_suspended(actor, expected_deployment, true),
            LifecycleRequest::Resume {
                actor,
                expected_deployment,
            } => self.set_suspended(actor, expected_deployment, false),
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
                contract,
                capabilities,
            } => self.upgrade_runtime(
                from_deployment,
                to_deployment,
                to_program,
                producer,
                package,
                contract,
                capabilities,
            ),
            LifecycleRequest::Inspect { .. }
            | LifecycleRequest::AcknowledgeInvocation { .. }
            | LifecycleRequest::FinalizeSystemAuthority(_)
            | LifecycleRequest::RotateSystemAuthority(_)
            | LifecycleRequest::Authorized { .. } => Err(LifecycleError::InvalidRequest),
        }
    }
}

impl StandardLaneState {
    fn select(&self, lane: StateLane) -> &[StandardLaneEntry] {
        match lane {
            StateLane::Linear => &self.linear,
            StateLane::Merge => &self.merge,
            StateLane::Local => &self.local,
        }
    }

    fn select_mut(&mut self, lane: StateLane) -> &mut Vec<StandardLaneEntry> {
        match lane {
            StateLane::Linear => &mut self.linear,
            StateLane::Merge => &mut self.merge,
            StateLane::Local => &mut self.local,
        }
    }

    fn lanes(&self) -> [(StateLane, &[StandardLaneEntry]); 3] {
        [
            (StateLane::Linear, &self.linear),
            (StateLane::Merge, &self.merge),
            (StateLane::Local, &self.local),
        ]
    }

    fn lookup(
        &self,
        lane: StateLane,
        actor: ActorId,
        state_generation: Hash,
    ) -> Option<&StandardLaneEntry> {
        self.select(lane)
            .binary_search_by_key(&(actor, state_generation), |entry| {
                (entry.actor, entry.state_generation)
            })
            .ok()
            .and_then(|index| self.select(lane).get(index))
    }

    #[cfg(feature = "pvm")]
    fn upsert(
        &mut self,
        lane: StateLane,
        actor: ActorId,
        state_generation: Hash,
        value: Vec<u8>,
    ) -> Result<(), super::execution::ActorExecutionError> {
        use super::execution::ActorExecutionError;

        let entries = self.select_mut(lane);
        match entries.binary_search_by_key(&(actor, state_generation), |entry| {
            (entry.actor, entry.state_generation)
        }) {
            Ok(index) if value.is_empty() => {
                entries.remove(index);
            }
            Ok(index) => entries[index].value = value,
            Err(_) if value.is_empty() => {}
            Err(index) => {
                if entries.len() >= MAX_LANE_STATE_ENTRIES {
                    return Err(ActorExecutionError::ResultCapacity);
                }
                entries.insert(
                    index,
                    StandardLaneEntry {
                        actor,
                        state_generation,
                        value,
                    },
                );
            }
        }
        Ok(())
    }

    fn is_canonical(&self) -> bool {
        self.lanes().into_iter().all(|(_, entries)| {
            entries.len() <= MAX_LANE_STATE_ENTRIES
                && entries.iter().all(|entry| {
                    entry.actor != ActorId::ZERO
                        && entry.state_generation != Hash::ZERO
                        && !entry.value.is_empty()
                        && entry.value.len() <= super::execution::MAX_EXECUTION_STATE_BYTES
                })
                && entries.windows(2).all(|pair| {
                    (pair[0].actor, pair[0].state_generation)
                        < (pair[1].actor, pair[1].state_generation)
                })
        })
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
            LifecycleRequest::Inspect { after, limit } => self.directory_page(after, limit),
            LifecycleRequest::AcknowledgeInvocation {
                scope,
                invocation,
                request,
                authority,
            } => self.acknowledge_invocation(scope, invocation, request, *authority),
            LifecycleRequest::Authorized { admission, request } => {
                self.apply_authorized(admission, *request)
            }
            LifecycleRequest::Create(_)
            | LifecycleRequest::Install(_)
            | LifecycleRequest::UpgradeActor(_)
            | LifecycleRequest::Suspend { .. }
            | LifecycleRequest::Resume { .. }
            | LifecycleRequest::RemoveLeaf { .. }
            | LifecycleRequest::UpgradeRuntime { .. } => Err(LifecycleError::InvalidRequest),
            LifecycleRequest::FinalizeSystemAuthority(_)
            | LifecycleRequest::RotateSystemAuthority(_) => Err(LifecycleError::SystemAuthority(
                super::system_authority::SystemAuthorityError::InvalidScope,
            )),
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

fn derive_state_generation(claim: Hash, sequence: u64, operation: Hash, actor: ActorId) -> Hash {
    let mut generation = Hash::digest(
        b"vos/agent/actor-state-generation/v1",
        &[&claim.0, &sequence.to_le_bytes(), &operation.0, &actor.0],
    );
    // State generation is an identity sentinel as well as a commitment. Make
    // nonzero structural rather than probabilistic while retaining all digest
    // bits except this dedicated marker bit.
    generation.0[0] |= 0x80;
    generation
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::authority::{
        AgentAuthorityClaim, AgentAuthorityReceipt, CAPABILITY_AGENT_CREATE_SHARED,
        ED25519_SIGNATURE_BYTES,
    };
    use crate::agent::committee::{
        AuthorityClaimCommitment, AuthorityCommittee, AuthorityCommitteeMember,
        AuthorityMemberRole, AuthorityQuorumCertificate, AuthoritySignature, AuthoritySignerId,
        RootAnchorConfigCommitment, RootAnchorId,
    };
    use crate::agent::genesis::{
        AgentGenesisClaim, AgentGenesisDecision, AgentGenesisEvidence, AgentGenesisExpectations,
        AgentGenesisLocator, AgentGenesisProposal, AgentReplicaCommittee, AgentReplicaMember,
        derive_replica_raft_slot,
    };
    use crate::agent::journal::{
        AgentJournalGenesisId, ReplayInput, ReplayOperation, RuntimeBinding,
        system_genesis_artifact_closure_commitment,
    };
    use crate::agent::system_authority::{
        SystemAuthorityDecisionProof, SystemAuthorityFinalize, SystemAuthorityGenesis,
        SystemAuthorityJournalScope, SystemAuthorityRotation, SystemAuthorityRotationCertificate,
        SystemAuthorityRotationClaim, SystemAuthorityRotationProof,
    };
    use crate::agent::{
        AgentIdentity, AgentProfile, AgentReplica, InstallActor, LaneSet,
        LifecycleAuthorityAdmission, ReplicaRole, RuntimeCapabilities, StateLane, UpgradeActor,
    };
    use crate::service::wire::ServiceWire;
    use crate::service::{
        BlobRef, CapabilityId, CredentialId, Hash, NodeId, PrincipalId, ProducerId, SpaceId,
    };
    use alloc::{collections::BTreeMap, vec, vec::Vec};
    use ed25519_dalek::{Signer as _, SigningKey};

    fn authority_key() -> SigningKey {
        SigningKey::from_bytes(&[0x42; 32])
    }

    fn config(max_actors: u32) -> AgentConfig {
        let owner = PrincipalId([1; 32]);
        let space = SpaceId([2; 32]);
        let creation_nonce = Hash([0x15; 32]);
        let agent = AgentId::derive(space, owner, &creation_nonce.0);
        let authority_public = crate::agent::authority::ed25519_public_key_wire(
            authority_key().verifying_key().to_bytes(),
        );
        AgentConfig {
            identity: AgentIdentity {
                space,
                agent,
                owner,
                profile: AgentProfile::Local,
                runtime_deployment: DeploymentId([4; 32]),
                runtime_program: ProgramId([5; 32]),
                runtime_producer: ProducerId([17; 32]),
            },
            creation_nonce,
            authority: crate::agent::authority::AgentAuthorityBinding {
                agent: AgentId([18; 32]),
                actor: ActorId([19; 32]),
                deployment: DeploymentId([21; 32]),
                program: ProgramId([22; 32]),
                producer: ProducerId::of_public_key(&authority_public),
                public_key: authority_public,
            },
            system_authority_genesis: None,
            capabilities: RuntimeCapabilities {
                max_actors,
                ..RuntimeCapabilities::standard()
            },
            runtime_package: BlobRef {
                hash: Hash([20; 32]),
                len: 100,
            },
            runtime_contract: crate::agent::contract::RuntimePackageContract::canonical(),
            replicas: vec![AgentReplica {
                node: NodeId([6; 32]),
                principal: owner,
                role: ReplicaRole::Voter,
            }],
        }
    }

    fn private_config(max_actors: u32) -> AgentConfig {
        let mut config = config(max_actors);
        config.identity.profile = AgentProfile::Private;
        config.capabilities.lanes =
            LaneSet::of(StateLane::Merge).union(LaneSet::of(StateLane::Local));
        config.replicas[0].role = ReplicaRole::Observer;
        config
    }

    const TEST_PEER_PREFIX: [u8; 6] = [0x00, 0x24, 0x08, 0x01, 0x12, 0x20];

    fn committee_key(byte: u8) -> SigningKey {
        SigningKey::from_bytes(&[byte; 32])
    }

    fn authority_committee(
        config: &AgentConfig,
        epoch: u64,
        previous: Option<Hash>,
        keys: &[SigningKey],
    ) -> AuthorityCommittee {
        let mut members = keys
            .iter()
            .enumerate()
            .map(|(index, key)| {
                AuthorityCommitteeMember::new(
                    NodeId([(0x80 + index as u8).wrapping_add(key.to_bytes()[0]); 32]),
                    key.verifying_key().to_bytes(),
                    AuthorityMemberRole::Voter,
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        members.sort_by_key(AuthorityCommitteeMember::signer);
        AuthorityCommittee::new(
            config.identity.space,
            config.authority.commitment(),
            epoch,
            previous,
            members,
        )
        .unwrap()
    }

    fn authority_certificate(
        committee: &AuthorityCommittee,
        claim: AuthorityClaimCommitment,
        keys: &[SigningKey],
    ) -> AuthorityQuorumCertificate {
        let message = AuthorityQuorumCertificate::signing_message(
            committee.authority_binding(),
            committee.epoch(),
            committee.commitment(),
            claim,
        );
        let mut signatures = keys
            .iter()
            .map(|key| {
                AuthoritySignature::new(
                    AuthoritySignerId::of_raw_ed25519(&key.verifying_key().to_bytes()),
                    key.sign(&message.0).to_bytes(),
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        signatures.sort_by_key(AuthoritySignature::signer);
        AuthorityQuorumCertificate::new(committee, claim, signatures).unwrap()
    }

    fn system_config() -> (AgentConfig, AuthorityCommittee, Vec<SigningKey>) {
        system_config_with_limits(
            64,
            crate::agent::contract::RuntimeResourceLimits::standard().max_runtime_state_bytes,
        )
    }

    fn system_config_with_limits(
        decision_limit: u32,
        max_runtime_state_bytes: u32,
    ) -> (AgentConfig, AuthorityCommittee, Vec<SigningKey>) {
        let mut config = config(64);
        config.authority.agent = config.identity.agent;
        config.runtime_contract.resources.max_runtime_state_bytes = max_runtime_state_bytes;
        let keys = vec![committee_key(0x51)];
        let committee = authority_committee(&config, 1, None, &keys);
        config.system_authority_genesis = Some(
            SystemAuthorityGenesis::new(
                RootAnchorId::from_bytes([0x71; 32]),
                1,
                RootAnchorConfigCommitment::from_bytes([0x72; 32]),
                committee.clone(),
                1,
                decision_limit,
                16,
            )
            .unwrap(),
        );
        config.validate().unwrap();
        (config, committee, keys)
    }

    fn journal_scope(byte: u8) -> SystemAuthorityJournalScope {
        SystemAuthorityJournalScope::for_test(
            AgentJournalGenesisId::new([byte; 32]),
            crate::agent::genesis::AgentGenesisAdmissionId::from_bytes([byte.wrapping_add(1); 32]),
        )
        .unwrap()
    }

    fn journal_context(
        scope: SystemAuthorityJournalScope,
    ) -> crate::agent::wire::RuntimeJournalContext {
        crate::agent::wire::RuntimeCall::scoped_system_authority(
            crate::agent::wire::RuntimeState::default(),
            LifecycleRequest::Inspect {
                after: None,
                limit: 1,
            },
            scope,
        )
        .journal_context()
        .unwrap()
    }

    fn replica_member(byte: u8) -> AgentReplicaMember {
        let raw = [byte; 32];
        let mut peer_id = Vec::from(TEST_PEER_PREFIX);
        peer_id.extend_from_slice(&raw);
        AgentReplicaMember::new(
            AgentReplica {
                node: NodeId::of_authenticated_peer(&peer_id),
                principal: PrincipalId::of_public_key(&raw),
                role: ReplicaRole::Voter,
            },
            peer_id.clone(),
            raw,
            Some(derive_replica_raft_slot(&peer_id)),
        )
        .unwrap()
    }

    fn finalize_command(
        system: &AgentConfig,
        committee: &AuthorityCommittee,
        keys: &[SigningKey],
        scope: SystemAuthorityJournalScope,
        sequence: u64,
    ) -> SystemAuthorityFinalize {
        let member = replica_member(0x31);
        let owner = PrincipalId([0x12; 32]);
        let nonce = Hash([0x10_u8.wrapping_add(sequence as u8); 32]);
        let agent = AgentId::derive(system.identity.space, owner, nonce.as_bytes());
        let target = AgentConfig {
            identity: AgentIdentity {
                space: system.identity.space,
                agent,
                owner,
                profile: AgentProfile::Shared,
                runtime_deployment: DeploymentId([0x21; 32]),
                runtime_program: ProgramId([0x22; 32]),
                runtime_producer: ProducerId([0x23; 32]),
            },
            creation_nonce: nonce,
            authority: system.authority.clone(),
            system_authority_genesis: None,
            runtime_package: BlobRef::of_bytes(b"ordinary-standard-runtime"),
            runtime_contract: crate::agent::contract::RuntimePackageContract::canonical(),
            capabilities: RuntimeCapabilities::standard(),
            replicas: vec![member.replica()],
        };
        target.validate().unwrap();
        let inner = LifecycleRequest::Create(target.clone());
        let create = ReplayInput {
            runtime: RuntimeBinding {
                space: target.identity.space,
                agent,
                deployment: target.identity.runtime_deployment,
                program: target.identity.runtime_program,
                producer: target.identity.runtime_producer,
                package: target.runtime_package.clone(),
                runtime_abi: super::super::RUNTIME_ABI_ID,
                execution_semantics: super::super::EXECUTION_SEMANTICS_ID,
            },
            operation: ReplayOperation::Management {
                request: LifecycleRequest::Authorized {
                    admission: LifecycleAuthorityAdmission {
                        receipt: AgentAuthorityReceipt {
                            claim: AgentAuthorityClaim {
                                authority: target.authority.clone(),
                                space: target.identity.space,
                                agent,
                                principal: owner,
                                credential: CredentialId([0x24; 32]),
                                capability: CapabilityId::named(CAPABILITY_AGENT_CREATE_SHARED),
                                operation: inner.commitment(),
                                sequence,
                                valid_from: 10,
                                valid_until: 40,
                            },
                            signature: vec![0x25; ED25519_SIGNATURE_BYTES],
                        },
                        observed_slot: 20,
                    },
                    request: Box::new(inner.clone()),
                },
            },
        };
        let catalog = vec![target.runtime_package.clone()];
        let expectations = AgentGenesisExpectations::new(
            create.runtime.commitment(),
            inner.commitment(),
            Hash([0x26; 32]),
            system_genesis_artifact_closure_commitment(&catalog).unwrap(),
            sequence,
        )
        .unwrap();
        let proposal = AgentGenesisProposal::new(
            AgentGenesisLocator {
                space: target.identity.space,
                agent,
            },
            create,
            expectations,
            catalog,
        )
        .unwrap();
        let replicas = AgentReplicaCommittee::new(
            target.identity.space,
            agent,
            AgentProfile::Shared,
            vec![member],
        )
        .unwrap();
        let claim = AgentGenesisClaim::new(
            system.identity.agent,
            scope.system_genesis(),
            scope.agent_admission(),
            &proposal,
            &replicas,
        )
        .unwrap();
        let evidence = AgentGenesisEvidence::new(
            claim.clone(),
            authority_certificate(committee, claim.authority_claim(), keys),
        )
        .unwrap();
        let decision = AgentGenesisDecision::new(&proposal, &replicas, &evidence).unwrap();
        SystemAuthorityFinalize::new(
            decision,
            evidence,
            SystemAuthorityDecisionProof::vacant(agent, vec![]).unwrap(),
        )
        .unwrap()
    }

    fn rotation_command(
        state: &crate::agent::system_authority::SystemAuthorityState,
        scope: SystemAuthorityJournalScope,
        old: &AuthorityCommittee,
        old_keys: &[SigningKey],
        new: &AuthorityCommittee,
        new_keys: &[SigningKey],
    ) -> SystemAuthorityRotation {
        let claim = SystemAuthorityRotationClaim::new(
            state.root_anchor(),
            state.root_anchor_config_version(),
            state.root_anchor_config(),
            scope.commitment(state.root_anchor()).unwrap(),
            old,
            new,
            3,
            4,
        )
        .unwrap();
        let authority_claim = claim.authority_claim();
        let certificate = SystemAuthorityRotationCertificate::new(
            claim,
            authority_certificate(old, authority_claim, old_keys),
            authority_certificate(new, authority_claim, new_keys),
        )
        .unwrap();
        SystemAuthorityRotation::new(
            new.clone(),
            certificate,
            SystemAuthorityRotationProof::vacant(2, vec![]).unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn system_authority_seed_is_exactly_bound_to_config_and_restore() {
        let (config, _, _) = system_config();

        let mut wrong_sequence = StandardAgentRuntime::new();
        assert_eq!(
            wrong_sequence.apply(authorized_at(
                &config,
                CredentialId([0x44; 32]),
                2,
                1,
                1,
                LifecycleRequest::Create(config.clone()),
            )),
            Err(LifecycleError::SystemAuthority(
                crate::agent::system_authority::SystemAuthorityError::InvalidGenesis
            ))
        );
        assert_eq!(wrong_sequence.snapshot(), StandardRuntimeState::default());

        let mut runtime = StandardAgentRuntime::new();
        assert!(matches!(
            create_authorized(&mut runtime, &config, 1),
            Ok(LifecycleReply::Created(_))
        ));
        let snapshot = runtime.snapshot();
        let seeded = snapshot.system_authority.as_ref().unwrap();
        seeded
            .validate_against_genesis(
                config.identity.agent,
                config.system_authority_genesis.as_ref().unwrap(),
            )
            .unwrap();
        let encoded = crate::agent::wire::encode_standard_runtime_state(&snapshot);
        let decoded = crate::agent::wire::decode_standard_runtime_state(&encoded).unwrap();
        assert_eq!(decoded, snapshot);
        assert_eq!(
            StandardAgentRuntime::restore(decoded).unwrap().snapshot(),
            snapshot
        );

        let mut missing_state = snapshot.clone();
        missing_state.system_authority = None;
        assert!(matches!(
            StandardAgentRuntime::restore(missing_state),
            Err(LifecycleError::InvalidRequest)
        ));

        let mut missing_marker = snapshot.clone();
        missing_marker
            .config
            .as_mut()
            .unwrap()
            .system_authority_genesis = None;
        assert!(matches!(
            StandardAgentRuntime::restore(missing_marker),
            Err(LifecycleError::InvalidRequest)
        ));

        let mut high_water_tamper = snapshot.clone();
        let authority = high_water_tamper.system_authority.as_ref().unwrap();
        let mut authority_bytes = authority.encode();
        let high_water_offset = 36
            + 2
            + 32
            + 8
            + 32
            + 32
            + 32
            + 32
            + 4
            + 4
            + 1
            + 4
            + authority.current_committee().encode().len();
        authority_bytes[high_water_offset..high_water_offset + 8]
            .copy_from_slice(&2_u64.to_le_bytes());
        high_water_tamper.system_authority = Some(
            crate::agent::system_authority::SystemAuthorityState::decode(&authority_bytes).unwrap(),
        );
        assert!(matches!(
            StandardAgentRuntime::restore(high_water_tamper),
            Err(LifecycleError::SystemAuthority(
                crate::agent::system_authority::SystemAuthorityError::InvalidState
            ))
        ));

        let mut changed_marker = snapshot;
        let genesis = config.system_authority_genesis.as_ref().unwrap();
        changed_marker
            .config
            .as_mut()
            .unwrap()
            .system_authority_genesis = Some(
            SystemAuthorityGenesis::new(
                genesis.root_anchor(),
                genesis.root_anchor_config_version(),
                genesis.root_anchor_config(),
                genesis.initial_committee().clone(),
                genesis.initial_sequence(),
                genesis.decision_limit() - 1,
                genesis.rotation_limit(),
            )
            .unwrap(),
        );
        assert!(matches!(
            StandardAgentRuntime::restore(changed_marker),
            Err(LifecycleError::SystemAuthority(
                crate::agent::system_authority::SystemAuthorityError::InvalidState
            ))
        ));
    }

    #[test]
    fn scoped_finalize_matches_guest_and_only_native_yields_write_metadata() {
        let (config, committee, keys) = system_config();
        let scope = journal_scope(0x61);
        let context = journal_context(scope);
        let mut runtime = StandardAgentRuntime::new();
        create_authorized(&mut runtime, &config, 1).unwrap();
        let command = finalize_command(&config, &committee, &keys, scope, 2);
        let request = LifecycleRequest::FinalizeSystemAuthority(command.clone());
        let before = crate::agent::wire::encode_standard_runtime_state(&runtime.snapshot());

        let mut public = runtime.clone();
        assert_eq!(
            public.apply(request.clone()),
            Err(LifecycleError::SystemAuthority(
                crate::agent::system_authority::SystemAuthorityError::InvalidScope
            ))
        );
        assert_eq!(
            crate::agent::wire::encode_standard_runtime_state(&public.snapshot()),
            before
        );
        let unscoped = crate::agent::wire::apply_standard(crate::agent::wire::RuntimeCall::new(
            before.clone(),
            request.clone(),
        ))
        .unwrap();
        assert_eq!(
            unscoped.result,
            Err(LifecycleError::SystemAuthority(
                crate::agent::system_authority::SystemAuthorityError::InvalidScope
            ))
        );
        assert_eq!(unscoped.state, before);

        let guest_call = crate::agent::wire::RuntimeCall::scoped_system_authority(
            before,
            request.clone(),
            scope,
        );
        let guest_call = crate::agent::wire::RuntimeCall::decode(&guest_call.encode()).unwrap();
        let guest = crate::agent::wire::apply_standard(guest_call).unwrap();
        assert_eq!(
            crate::agent::wire::RuntimeReturn::decode(
                &crate::agent::wire::RuntimeReturn {
                    state: guest.state.clone(),
                    result: guest.result.clone(),
                }
                .encode(),
            )
            .unwrap(),
            guest
        );
        let mut native = runtime;
        let native_apply = native.apply_scoped(context, scope, request.clone());
        assert_eq!(native_apply.result(), &guest.result);
        assert_eq!(
            crate::agent::wire::encode_standard_runtime_state(&native.snapshot()),
            guest.state
        );
        let StandardSystemAuthorityWrite::Finalize {
            admitted_fact,
            history,
        } = native_apply.system_authority_write().unwrap()
        else {
            panic!("finalize must return finalize metadata")
        };
        assert!(admitted_fact.is_some());
        assert!(history.inserted());

        let accepted = crate::agent::wire::encode_standard_runtime_state(&native.snapshot());
        let stale = native.apply_scoped(context, scope, request);
        assert_eq!(
            stale.result(),
            &Err(LifecycleError::SystemAuthority(
                crate::agent::system_authority::SystemAuthorityError::InvalidDecisionProof
            ))
        );
        assert!(stale.system_authority_write().is_none());
        assert_eq!(
            crate::agent::wire::encode_standard_runtime_state(&native.snapshot()),
            accepted,
            "a stale sparse proof must roll back byte-identically"
        );

        let nodes = history
            .nodes()
            .iter()
            .map(|node| (node.id(), node.encode()))
            .collect::<BTreeMap<_, _>>();
        let fact = command.fact().unwrap();
        let proof = crate::agent::system_authority::prove_decision(
            native.system_authority().unwrap().decisions_root(),
            fact.target_agent(),
            |id| Ok::<_, ()>(nodes.get(&id).cloned()),
        )
        .unwrap();
        let retry = SystemAuthorityFinalize::new(
            command.decision().clone(),
            command.evidence().clone(),
            proof,
        )
        .unwrap();
        let original_request = LifecycleRequest::FinalizeSystemAuthority(command);
        let retry_request = LifecycleRequest::FinalizeSystemAuthority(retry);
        assert_eq!(original_request.commitment(), retry_request.commitment());
        assert_ne!(
            crate::agent::wire::RuntimeCall::new(
                crate::agent::wire::RuntimeState::default(),
                original_request,
            )
            .encode(),
            crate::agent::wire::RuntimeCall::new(
                crate::agent::wire::RuntimeState::default(),
                retry_request.clone(),
            )
            .encode(),
        );
        let retry_apply = native.apply_scoped(context, scope, retry_request);
        assert!(matches!(
            retry_apply.result(),
            Ok(LifecycleReply::SystemAuthorityFinalized(
                crate::agent::system_authority::SystemAuthorityFinalizeOutcome::ExactRetry(_)
            ))
        ));
        let StandardSystemAuthorityWrite::Finalize { history, .. } =
            retry_apply.system_authority_write().unwrap()
        else {
            panic!("retry must retain finalize metadata")
        };
        assert!(!history.inserted());
    }

    #[test]
    fn scoped_rotation_matches_guest_and_refreshes_retry_proof_without_rekeying_operation() {
        let (config, old, old_keys) = system_config();
        let scope = journal_scope(0x71);
        let context = journal_context(scope);
        let mut runtime = StandardAgentRuntime::new();
        create_authorized(&mut runtime, &config, 1).unwrap();
        let finalize = finalize_command(&config, &old, &old_keys, scope, 2);
        let finalized = runtime.apply_scoped(
            context,
            scope,
            LifecycleRequest::FinalizeSystemAuthority(finalize),
        );
        assert!(finalized.result().is_ok());

        let new_keys = vec![committee_key(0x52)];
        let new = authority_committee(&config, 2, Some(old.commitment()), &new_keys);
        let rotation = rotation_command(
            runtime.system_authority().unwrap(),
            scope,
            &old,
            &old_keys,
            &new,
            &new_keys,
        );
        let request = LifecycleRequest::RotateSystemAuthority(rotation.clone());
        let before = crate::agent::wire::encode_standard_runtime_state(&runtime.snapshot());
        let guest_call = crate::agent::wire::RuntimeCall::scoped_system_authority(
            before,
            request.clone(),
            scope,
        );
        let guest_call = crate::agent::wire::RuntimeCall::decode(&guest_call.encode()).unwrap();
        let guest = crate::agent::wire::apply_standard(guest_call).unwrap();
        assert_eq!(
            crate::agent::wire::RuntimeReturn::decode(
                &crate::agent::wire::RuntimeReturn {
                    state: guest.state.clone(),
                    result: guest.result.clone(),
                }
                .encode(),
            )
            .unwrap(),
            guest
        );
        let applied = runtime.apply_scoped(context, scope, request);
        assert_eq!(applied.result(), &guest.result);
        assert_eq!(
            crate::agent::wire::encode_standard_runtime_state(&runtime.snapshot()),
            guest.state
        );
        let StandardSystemAuthorityWrite::Rotation { record, history } =
            applied.system_authority_write().unwrap()
        else {
            panic!("rotation must return rotation metadata")
        };
        assert_eq!(record.new_epoch(), 2);
        assert!(history.inserted());

        let nodes = history
            .nodes()
            .iter()
            .map(|node| (node.id(), node.encode()))
            .collect::<BTreeMap<_, _>>();
        let lookup = crate::agent::system_authority::prove_rotation(
            runtime.system_authority().unwrap().rotations_root(),
            2,
            |id| Ok::<_, ()>(nodes.get(&id).cloned()),
        )
        .unwrap();
        assert_eq!(lookup.occupied_record(), Some(record));
        let retry = SystemAuthorityRotation::new(
            rotation.new_committee().clone(),
            rotation.certificate().clone(),
            lookup.proof().clone(),
        )
        .unwrap();
        let original = LifecycleRequest::RotateSystemAuthority(rotation);
        let refreshed = LifecycleRequest::RotateSystemAuthority(retry);
        assert_eq!(original.commitment(), refreshed.commitment());
        assert_ne!(
            crate::agent::wire::RuntimeCall::new(
                crate::agent::wire::RuntimeState::default(),
                original,
            )
            .encode(),
            crate::agent::wire::RuntimeCall::new(
                crate::agent::wire::RuntimeState::default(),
                refreshed.clone(),
            )
            .encode(),
        );
        let retry = runtime.apply_scoped(context, scope, refreshed);
        assert!(matches!(
            retry.result(),
            Ok(LifecycleReply::SystemAuthorityRotated {
                epoch: 2,
                exact_retry: true,
                ..
            })
        ));
        let StandardSystemAuthorityWrite::Rotation { history, .. } =
            retry.system_authority_write().unwrap()
        else {
            panic!("rotation retry must retain rotation metadata")
        };
        assert!(!history.inserted());
    }

    #[test]
    fn scoped_authority_capacity_and_resource_refusals_roll_back_byte_identically() {
        let scope = journal_scope(0x75);
        let context = journal_context(scope);

        // The signed resource ceiling is part of Config but fixed-width on
        // wire, so the exact created-state length measured here remains the
        // exact created-state length after installing that value as its cap.
        let (probe_config, _, _) = system_config();
        let mut probe = StandardAgentRuntime::new();
        create_authorized(&mut probe, &probe_config, 1).unwrap();
        let exact_created_len =
            crate::agent::wire::encode_standard_runtime_state(&probe.snapshot())
                .encoded_len()
                .unwrap();
        let (capped_config, capped_committee, capped_keys) =
            system_config_with_limits(64, u32::try_from(exact_created_len).unwrap());
        let mut capped = StandardAgentRuntime::new();
        create_authorized(&mut capped, &capped_config, 1).unwrap();
        let capped_before = crate::agent::wire::encode_standard_runtime_state(&capped.snapshot());
        assert_eq!(capped_before.encoded_len(), Some(exact_created_len));
        let capped_request = LifecycleRequest::FinalizeSystemAuthority(finalize_command(
            &capped_config,
            &capped_committee,
            &capped_keys,
            scope,
            2,
        ));

        let guest = crate::agent::wire::apply_standard(
            crate::agent::wire::RuntimeCall::scoped_system_authority(
                capped_before.clone(),
                capped_request.clone(),
                scope,
            ),
        )
        .unwrap();
        assert_eq!(guest.result, Err(LifecycleError::ResourceLimit));
        assert_eq!(guest.state, capped_before);

        let native = capped.apply_scoped(context, scope, capped_request);
        assert_eq!(native.result(), &Err(LifecycleError::ResourceLimit));
        assert!(native.system_authority_write().is_none());
        assert_eq!(
            crate::agent::wire::encode_standard_runtime_state(&capped.snapshot()),
            capped_before
        );

        let (capacity_config, capacity_committee, capacity_keys) = system_config_with_limits(
            1,
            crate::agent::contract::RuntimeResourceLimits::standard().max_runtime_state_bytes,
        );
        let mut capacity = StandardAgentRuntime::new();
        create_authorized(&mut capacity, &capacity_config, 1).unwrap();
        let first = capacity.apply_scoped(
            context,
            scope,
            LifecycleRequest::FinalizeSystemAuthority(finalize_command(
                &capacity_config,
                &capacity_committee,
                &capacity_keys,
                scope,
                2,
            )),
        );
        assert!(first.result().is_ok());
        let StandardSystemAuthorityWrite::Finalize { history, .. } =
            first.system_authority_write().unwrap()
        else {
            panic!("the admitted decision must return finalize history")
        };
        let nodes = history
            .nodes()
            .iter()
            .map(|node| (node.id(), node.encode()))
            .collect::<BTreeMap<_, _>>();
        let capacity_before =
            crate::agent::wire::encode_standard_runtime_state(&capacity.snapshot());
        let full = finalize_command(
            &capacity_config,
            &capacity_committee,
            &capacity_keys,
            scope,
            3,
        );
        let target = full.fact().unwrap().target_agent();
        let proof = crate::agent::system_authority::prove_decision(
            capacity.system_authority().unwrap().decisions_root(),
            target,
            |id| Ok::<_, ()>(nodes.get(&id).cloned()),
        )
        .unwrap();
        assert!(proof.occupied_fact().is_none());
        let full_request = LifecycleRequest::FinalizeSystemAuthority(
            SystemAuthorityFinalize::new(full.decision().clone(), full.evidence().clone(), proof)
                .unwrap(),
        );
        let expected = Err(LifecycleError::SystemAuthority(
            crate::agent::system_authority::SystemAuthorityError::Capacity,
        ));

        let guest = crate::agent::wire::apply_standard(
            crate::agent::wire::RuntimeCall::scoped_system_authority(
                capacity_before.clone(),
                full_request.clone(),
                scope,
            ),
        )
        .unwrap();
        assert_eq!(guest.result, expected);
        assert_eq!(guest.state, capacity_before);

        let native = capacity.apply_scoped(context, scope, full_request);
        assert_eq!(native.result(), &expected);
        assert!(native.system_authority_write().is_none());
        assert_eq!(
            crate::agent::wire::encode_standard_runtime_state(&capacity.snapshot()),
            capacity_before
        );
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
            contract: crate::agent::contract::ActorPackageContract::canonical(),
            requirements,
        }
    }

    fn set_install_artifacts(
        install: &mut InstallActor,
        package: BlobRef,
        agent_schema: BlobRef,
        role_policies: BlobRef,
    ) {
        install.entry.package = package.clone();
        install.entry.agent_schema = agent_schema.clone();
        install.entry.role_policies = role_policies.clone();
        install.package = package;
        install.agent_schema = agent_schema;
        install.role_policies = role_policies;
    }

    fn suspend(actor: ActorId, expected_deployment: DeploymentId) -> LifecycleRequest {
        LifecycleRequest::Suspend {
            actor,
            expected_deployment,
        }
    }

    fn resume(actor: ActorId, expected_deployment: DeploymentId) -> LifecycleRequest {
        LifecycleRequest::Resume {
            actor,
            expected_deployment,
        }
    }

    #[cfg(feature = "pvm")]
    fn set_lane(runtime: &mut StandardAgentRuntime, actor: ActorId, lane: StateLane, value: &[u8]) {
        let generation = runtime.actors[&actor].record.state_generation;
        runtime
            .lane_state
            .upsert(lane, actor, generation, value.to_vec())
            .unwrap();
    }

    #[cfg(feature = "pvm")]
    #[test]
    fn merge_receives_only_merge_state_and_cannot_return_hidden_linear() {
        use crate::agent::execution::{
            ActorExecutionError, ActorExecutionReply, ActorExecutionStatus, ActorInvocation,
            ActorInvocationAuth, ActorStateLanes,
        };
        use crate::service::InvocationId;

        let config = config(4);
        let mut runtime = StandardAgentRuntime::new();
        apply_authorized(
            &mut runtime,
            &config,
            LifecycleRequest::Create(config.clone()),
        )
        .unwrap();
        let mut install = install(config.identity.agent, None, "mixed");
        let shared = LaneSet::of(StateLane::Linear).union(LaneSet::of(StateLane::Merge));
        install.entry.lanes = shared;
        install.requirements.lanes = shared;
        let actor = install.entry.actor;
        let deployment = install.entry.deployment;
        let program = install.entry.program;
        apply_authorized(&mut runtime, &config, LifecycleRequest::Install(install)).unwrap();
        let incarnation = runtime.actors[&actor].record.state_generation;
        set_lane(&mut runtime, actor, StateLane::Linear, &[7]);

        let invocation = ActorInvocation {
            invocation: InvocationId([31; 32]),
            actor,
            incarnation,
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
        let visible = before.visible_for(invocation.mode);
        assert!(visible.linear.is_none());
        assert_eq!(visible.merge.as_deref(), Some(&[][..]));
        assert!(visible.local.is_none());

        let mut reply = ActorExecutionReply {
            invocation: invocation.invocation,
            actor,
            incarnation,
            deployment,
            mode: invocation.mode,
            lane: Some(StateLane::Merge),
            status: ActorExecutionStatus::Done,
            reply: Vec::new(),
            gas_remaining: 0,
            observation: super::super::execution::ActorObservation::default(),
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
            runtime.commit_execution(&invocation, &mut reply, &fresh, forged.clone(), 1),
            Err(ActorExecutionError::InvalidActorOutput),
            "the host enforces non-owned lanes even from the fresh sentinel"
        );
        assert_eq!(
            runtime.commit_execution(&invocation, &mut reply, &before, forged, 1),
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
        let claim = crate::agent::authority::AgentAuthorityClaim {
            authority: config.authority.clone(),
            space: config.identity.space,
            agent: config.identity.agent,
            principal: PrincipalId([claim_byte.max(1); 32]),
            credential,
            capability: crate::service::CapabilityId::named(match &request {
                LifecycleRequest::Create(config) => match config.identity.profile {
                    AgentProfile::Local => crate::agent::authority::CAPABILITY_AGENT_CREATE_LOCAL,
                    AgentProfile::Private => {
                        crate::agent::authority::CAPABILITY_AGENT_CREATE_PRIVATE
                    }
                    AgentProfile::Shared => crate::agent::authority::CAPABILITY_AGENT_CREATE_SHARED,
                },
                LifecycleRequest::Install(_) => crate::agent::authority::CAPABILITY_ACTOR_INSTALL,
                LifecycleRequest::UpgradeActor(_) => {
                    crate::agent::authority::CAPABILITY_ACTOR_UPGRADE
                }
                LifecycleRequest::Suspend { .. }
                | LifecycleRequest::Resume { .. }
                | LifecycleRequest::RemoveLeaf { .. } => {
                    crate::agent::authority::CAPABILITY_ACTOR_LIFECYCLE
                }
                LifecycleRequest::UpgradeRuntime { .. } => {
                    crate::agent::authority::CAPABILITY_AGENT_RUNTIME_UPGRADE
                }
                _ => panic!("test helper accepts mutation requests only"),
            }),
            operation,
            sequence,
            valid_from: 0,
            valid_until: u64::MAX,
        };
        let signature = authority_key()
            .sign(&claim.signing_message().0)
            .to_bytes()
            .to_vec();
        LifecycleRequest::Authorized {
            admission: super::super::LifecycleAuthorityAdmission {
                receipt: crate::agent::authority::AgentAuthorityReceipt { claim, signature },
                observed_slot,
            },
            request: Box::new(request),
        }
    }

    fn apply_authorized(
        runtime: &mut StandardAgentRuntime,
        config: &AgentConfig,
        request: LifecycleRequest,
    ) -> Result<LifecycleReply, LifecycleError> {
        let sequence = runtime.authority_sequence_high_water.unwrap_or(0) + 1;
        runtime.apply(authorized(
            config,
            CredentialId([0x55; 32]),
            sequence,
            u8::try_from(sequence).unwrap_or(u8::MAX - 1),
            request,
        ))
    }

    fn create_authorized(
        runtime: &mut StandardAgentRuntime,
        config: &AgentConfig,
        observed_slot: u64,
    ) -> Result<LifecycleReply, LifecycleError> {
        runtime.apply(authorized_at(
            config,
            CredentialId([0x54; 32]),
            1,
            observed_slot,
            1,
            LifecycleRequest::Create(config.clone()),
        ))
    }

    #[cfg(feature = "pvm")]
    fn signed_invocation_receipt(
        config: &AgentConfig,
        invocation: &super::super::execution::ActorInvocation,
        valid_from: u64,
        valid_until: u64,
    ) -> super::super::authority::ActorInvocationReceipt {
        let claim = super::super::authority::ActorInvocationClaim {
            authority: config.authority.clone(),
            space: config.identity.space,
            agent: config.identity.agent,
            principal: invocation.auth.principal,
            credential: invocation.auth.principal.map(|_| CredentialId([0x66; 32])),
            authorization: invocation.authorization_message(),
            auth: invocation.auth.clone(),
            valid_from,
            valid_until,
        };
        super::super::authority::ActorInvocationReceipt {
            signature: authority_key()
                .sign(&claim.signing_message().0)
                .to_bytes()
                .to_vec(),
            claim,
        }
    }

    #[test]
    fn created_agent_is_valid_and_usefully_empty() {
        let mut runtime = StandardAgentRuntime::new();
        let config = config(super::super::RuntimeCapabilities::STANDARD_MAX_ACTORS);
        // A later credential can advance the one global sequence without
        // consuming a permanent per-credential slot.
        assert_eq!(
            runtime.apply(LifecycleRequest::Create(config.clone())),
            Err(LifecycleError::InvalidRequest),
            "raw lifecycle mutations are never an authority bypass"
        );
        assert!(matches!(
            apply_authorized(
                &mut runtime,
                &config,
                LifecycleRequest::Create(config.clone())
            ),
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
    fn standard_directory_physically_encodes_and_restores_its_signed_capacity() {
        let config = config(super::super::RuntimeCapabilities::STANDARD_MAX_ACTORS);
        let mut runtime = StandardAgentRuntime::new();
        create_authorized(&mut runtime, &config, 1).unwrap();
        for index in 0..config.capabilities.max_actors {
            runtime
                .install(
                    install(
                        config.identity.agent,
                        None,
                        &alloc::format!("actor-{index:04}"),
                    ),
                    Hash::digest(b"vos/test/state-generation", &[&index.to_le_bytes()]),
                )
                .unwrap();
        }
        assert_eq!(runtime.len(), 4_096);
        assert_eq!(
            runtime.install(
                install(config.identity.agent, None, "actor-overflow"),
                Hash([0x99; 32]),
            ),
            Err(LifecycleError::DirectoryFull)
        );

        let encoded = super::super::wire::encode_standard_runtime_state(&runtime.snapshot());
        assert!(
            encoded.encoded_len().unwrap()
                <= config.runtime_contract.resources.max_runtime_state_bytes as usize,
            "the signed standard runtime capacity must fit its own image ceiling"
        );
        let decoded = super::super::wire::decode_standard_runtime_state(&encoded).unwrap();
        let restored = StandardAgentRuntime::restore(decoded).unwrap();
        assert_eq!(restored.len(), 4_096);
    }

    #[test]
    fn management_directory_changes_leave_all_lane_components_byte_identical() {
        let config = config(8);
        let mut runtime = StandardAgentRuntime::new();
        create_authorized(&mut runtime, &config, 1).unwrap();
        let before_install = super::super::wire::encode_standard_runtime_state(&runtime.snapshot());

        let mut request = install(config.identity.agent, None, "sparse");
        request.entry.lanes = LaneSet::ALL;
        request.requirements.lanes = LaneSet::ALL;
        let actor = request.entry.actor;
        let initial_deployment = request.entry.deployment;
        apply_authorized(
            &mut runtime,
            &config,
            LifecycleRequest::Install(request.clone()),
        )
        .unwrap();
        let after_install = super::super::wire::encode_standard_runtime_state(&runtime.snapshot());
        assert_eq!(after_install.linear, before_install.linear);
        assert_eq!(after_install.merge, before_install.merge);
        assert_eq!(after_install.local, before_install.local);

        let generation = runtime.actors[&actor].record.state_generation;
        runtime.lane_state.linear.push(StandardLaneEntry {
            actor,
            state_generation: generation,
            value: vec![1],
        });
        runtime.lane_state.merge.push(StandardLaneEntry {
            actor,
            state_generation: generation,
            value: vec![2],
        });
        runtime.lane_state.local.push(StandardLaneEntry {
            actor,
            state_generation: generation,
            value: vec![3],
        });
        let baseline = super::super::wire::encode_standard_runtime_state(&runtime.snapshot());
        let assert_lanes = |runtime: &StandardAgentRuntime| {
            let state = super::super::wire::encode_standard_runtime_state(&runtime.snapshot());
            assert_eq!(state.linear, baseline.linear);
            assert_eq!(state.merge, baseline.merge);
            assert_eq!(state.local, baseline.local);
        };

        apply_authorized(&mut runtime, &config, suspend(actor, initial_deployment)).unwrap();
        assert_lanes(&runtime);
        apply_authorized(&mut runtime, &config, resume(actor, initial_deployment)).unwrap();
        assert_lanes(&runtime);

        let upgraded_deployment = DeploymentId([0x71; 32]);
        apply_authorized(
            &mut runtime,
            &config,
            LifecycleRequest::UpgradeActor(UpgradeActor {
                actor,
                from_deployment: initial_deployment,
                to_deployment: upgraded_deployment,
                to_program: request.entry.program,
                producer: request.producer,
                package: request.package.clone(),
                agent_schema: request.agent_schema.clone(),
                role_policies: request.role_policies.clone(),
                state_layout: request.state_layout,
                contract: request.contract,
                requirements: request.requirements,
            }),
        )
        .unwrap();
        assert_lanes(&runtime);
        assert_eq!(runtime.actors[&actor].record.state_generation, generation);

        apply_authorized(
            &mut runtime,
            &config,
            LifecycleRequest::UpgradeRuntime {
                from_deployment: config.identity.runtime_deployment,
                to_deployment: DeploymentId([0x72; 32]),
                to_program: ProgramId([0x73; 32]),
                producer: ProducerId([0x74; 32]),
                package: BlobRef {
                    hash: Hash([0x75; 32]),
                    len: 101,
                },
                contract: super::super::contract::RuntimePackageContract::canonical(),
                capabilities: RuntimeCapabilities::standard(),
            },
        )
        .unwrap();
        assert_lanes(&runtime);

        apply_authorized(
            &mut runtime,
            &config,
            LifecycleRequest::RemoveLeaf {
                actor,
                expected_deployment: upgraded_deployment,
            },
        )
        .unwrap();
        assert_lanes(&runtime);
    }

    #[cfg(feature = "pvm")]
    #[test]
    fn remove_and_reinstall_never_resurrect_historical_lane_state() {
        use crate::agent::execution::{ActorExecutionError, ActorInvocation, ActorInvocationAuth};
        use crate::service::InvocationId;

        let config = config(8);
        let mut runtime = StandardAgentRuntime::new();
        create_authorized(&mut runtime, &config, 1).unwrap();
        let request = install(config.identity.agent, None, "reused");
        let actor = request.entry.actor;
        apply_authorized(
            &mut runtime,
            &config,
            LifecycleRequest::Install(request.clone()),
        )
        .unwrap();
        let old_generation = runtime.actors[&actor].record.state_generation;
        let old_invocation = ActorInvocation {
            invocation: InvocationId([0x75; 32]),
            actor,
            incarnation: old_generation,
            deployment: request.entry.deployment,
            program: request.entry.program,
            mode: super::super::MethodMode::Linear,
            auth: ActorInvocationAuth::anonymous(),
            message: vec![1],
            availability: Vec::new(),
            gas: 1,
        };
        let old_receipt = signed_invocation_receipt(&config, &old_invocation, 0, 100);
        set_lane(&mut runtime, actor, StateLane::Linear, &[0xaa]);
        apply_authorized(
            &mut runtime,
            &config,
            LifecycleRequest::RemoveLeaf {
                actor,
                expected_deployment: request.entry.deployment,
            },
        )
        .unwrap();
        assert_eq!(runtime.lane_state.linear.len(), 1);

        apply_authorized(
            &mut runtime,
            &config,
            LifecycleRequest::Install(request.clone()),
        )
        .unwrap();
        let new_generation = runtime.actors[&actor].record.state_generation;
        assert_ne!(new_generation, old_generation);
        assert_ne!(new_generation, Hash::ZERO);
        runtime
            .verify_invocation_authority(&old_invocation, &old_receipt)
            .unwrap();
        assert_eq!(
            runtime.prepare_execution_state(&old_invocation),
            Err(ActorExecutionError::StaleIncarnation),
            "a valid receipt minted for a retired install cannot reach its replacement"
        );
        assert_eq!(
            runtime.recover_execution(&old_invocation, 1),
            Err(ActorExecutionError::StaleIncarnation)
        );

        let LifecycleReply::Directory(directory) = runtime
            .apply(LifecycleRequest::Inspect {
                after: None,
                limit: 1,
            })
            .unwrap()
        else {
            panic!("inspect must return a directory page")
        };
        let current = directory.entries.into_iter().next().unwrap();
        assert_eq!(current.entry.actor, actor);
        assert_eq!(current.incarnation, new_generation);
        let invocation = ActorInvocation {
            invocation: InvocationId([0x76; 32]),
            actor: current.entry.actor,
            incarnation: current.incarnation,
            deployment: current.entry.deployment,
            program: current.entry.program,
            mode: super::super::MethodMode::Linear,
            auth: ActorInvocationAuth::anonymous(),
            message: vec![1],
            availability: Vec::new(),
            gas: 1,
        };
        assert_eq!(
            runtime
                .prepare_execution_state(&invocation)
                .unwrap()
                .linear
                .as_deref(),
            Some(&[][..])
        );

        let encoded = super::super::wire::encode_standard_runtime_state(&runtime.snapshot());
        let decoded = super::super::wire::decode_standard_runtime_state(&encoded).unwrap();
        let mut reopened = StandardAgentRuntime::restore(decoded).unwrap();
        assert_eq!(
            reopened.lane_state.linear[0].state_generation,
            old_generation
        );
        assert_eq!(
            reopened
                .prepare_execution_state(&invocation)
                .unwrap()
                .linear
                .as_deref(),
            Some(&[][..])
        );

        set_lane(&mut reopened, actor, StateLane::Linear, &[0xbb]);
        reopened.compact_historical_lane_entries_for_checkpoint();
        assert_eq!(reopened.lane_state.linear.len(), 1);
        assert_eq!(
            reopened.lane_state.linear[0].state_generation,
            new_generation
        );
        assert_eq!(reopened.lane_state.linear[0].value, vec![0xbb]);
    }

    #[cfg(feature = "pvm")]
    #[test]
    fn private_profile_rejects_linearizable_queries_and_all_linear_history() {
        use crate::agent::execution::{
            ActorExecutionError, ActorExecutionReply, ActorExecutionStatus, ActorInvocation,
            ActorInvocationAuth,
        };
        use crate::service::InvocationId;

        let config = private_config(8);
        let mut runtime = StandardAgentRuntime::new();
        create_authorized(&mut runtime, &config, 1).unwrap();
        let mut install = install(config.identity.agent, None, "private");
        install.entry.lanes = LaneSet::of(StateLane::Merge);
        install.requirements.lanes = LaneSet::of(StateLane::Merge);
        let actor = install.entry.actor;
        let deployment = install.entry.deployment;
        let program = install.entry.program;
        apply_authorized(&mut runtime, &config, LifecycleRequest::Install(install)).unwrap();
        let incarnation = runtime.actors[&actor].record.state_generation;
        let invocation = ActorInvocation {
            invocation: InvocationId([0x78; 32]),
            actor,
            incarnation,
            deployment,
            program,
            mode: super::super::MethodMode::LinearizableQuery,
            auth: ActorInvocationAuth::anonymous(),
            message: vec![1],
            availability: Vec::new(),
            gas: 1,
        };
        let before = runtime.snapshot();
        assert_eq!(
            runtime.prepare_execution_state(&invocation),
            Err(ActorExecutionError::UnsupportedResultStorage)
        );
        assert_eq!(
            runtime.snapshot(),
            before,
            "rejection must not mutate state"
        );
        assert_eq!(
            runtime.commit_exact_outcome_clock(&invocation, 2),
            Err(ActorExecutionError::UnsupportedResultStorage),
            "an exact-outcome clock cannot synthesize unsupported result storage"
        );
        assert_eq!(runtime.snapshot(), before);

        let historical_entry = StandardLaneEntry {
            actor: ActorId([0x79; 32]),
            state_generation: Hash([0x7a; 32]),
            value: vec![1],
        };
        let mut with_entry = before.clone();
        with_entry.lane_state.linear.push(historical_entry);
        assert!(matches!(
            StandardAgentRuntime::restore(with_entry),
            Err(LifecycleError::InvalidRequest)
        ));

        let mut with_revision = before.clone();
        with_revision.lane_revisions.linear = 1;
        assert!(matches!(
            StandardAgentRuntime::restore(with_revision),
            Err(LifecycleError::InvalidRequest)
        ));

        let mut with_slot = before.clone();
        with_slot.lane_revisions.linear_authority_slot = Some(1);
        assert!(matches!(
            StandardAgentRuntime::restore(with_slot),
            Err(LifecycleError::InvalidRequest)
        ));

        let mut with_result = before;
        with_result
            .invocation_results
            .push(StandardInvocationResult {
                scope: InvocationScope::Ordered,
                invocation: invocation.invocation,
                incarnation,
                request: invocation.commitment(),
                reply: ActorExecutionReply {
                    invocation: invocation.invocation,
                    actor,
                    incarnation,
                    deployment,
                    mode: invocation.mode,
                    lane: None,
                    status: ActorExecutionStatus::Done,
                    reply: vec![1],
                    gas_remaining: 0,
                    observation: super::super::execution::ActorObservation::default(),
                },
                storage: InvocationResultStorage::Lane(StateLane::Linear),
            });
        assert!(matches!(
            StandardAgentRuntime::restore(with_result),
            Err(LifecycleError::InvalidRequest)
        ));
    }

    #[test]
    fn local_capability_downgrade_retains_unreachable_historical_lane_entries() {
        let config = config(8);
        let mut runtime = StandardAgentRuntime::new();
        create_authorized(&mut runtime, &config, 1).unwrap();
        runtime.lane_state.linear.push(StandardLaneEntry {
            actor: ActorId([0x7b; 32]),
            state_generation: Hash([0x7c; 32]),
            value: vec![1],
        });
        runtime.lane_revisions.linear = 1;
        let mut downgraded = config.capabilities;
        downgraded.lanes = LaneSet::of(StateLane::Merge).union(LaneSet::of(StateLane::Local));
        apply_authorized(
            &mut runtime,
            &config,
            LifecycleRequest::UpgradeRuntime {
                from_deployment: config.identity.runtime_deployment,
                to_deployment: DeploymentId([0x7d; 32]),
                to_program: ProgramId([0x7e; 32]),
                producer: ProducerId([0x7f; 32]),
                package: BlobRef {
                    hash: Hash([0x80; 32]),
                    len: 1,
                },
                contract: config.runtime_contract,
                capabilities: downgraded,
            },
        )
        .unwrap();

        let reopened = StandardAgentRuntime::restore(runtime.snapshot()).unwrap();
        assert_eq!(reopened.lane_state.linear.len(), 1);
        assert_eq!(reopened.lane_revisions.linear, 1);
    }

    #[cfg(feature = "pvm")]
    #[test]
    fn runtime_cannot_disable_a_lane_which_owns_a_retained_result() {
        use crate::agent::execution::{
            ActorExecutionReply, ActorExecutionStatus, ActorInvocation, ActorInvocationAuth,
        };
        use crate::service::InvocationId;

        let config = config(8);
        let mut runtime = StandardAgentRuntime::new();
        create_authorized(&mut runtime, &config, 1).unwrap();
        let mut install = install(config.identity.agent, None, "result-owner");
        install.entry.lanes = LaneSet::NONE;
        install.requirements.lanes = LaneSet::NONE;
        let actor = install.entry.actor;
        let deployment = install.entry.deployment;
        let program = install.entry.program;
        apply_authorized(&mut runtime, &config, LifecycleRequest::Install(install)).unwrap();
        let incarnation = runtime.actors[&actor].record.state_generation;
        let invocation = ActorInvocation {
            invocation: InvocationId([0x81; 32]),
            actor,
            incarnation,
            deployment,
            program,
            mode: super::super::MethodMode::LinearizableQuery,
            auth: ActorInvocationAuth::anonymous(),
            message: vec![1],
            availability: Vec::new(),
            gas: 1,
        };
        let before = runtime.prepare_execution_state(&invocation).unwrap();
        let mut reply = ActorExecutionReply {
            invocation: invocation.invocation,
            actor,
            incarnation,
            deployment,
            mode: invocation.mode,
            lane: None,
            status: ActorExecutionStatus::Done,
            reply: vec![1],
            gas_remaining: 0,
            observation: super::super::execution::ActorObservation::default(),
        };
        runtime
            .commit_execution(
                &invocation,
                &mut reply,
                &before,
                before.visible_for(invocation.mode),
                2,
            )
            .unwrap();

        let mut downgraded = config.capabilities;
        downgraded.lanes = LaneSet::of(StateLane::Merge).union(LaneSet::of(StateLane::Local));
        assert_eq!(
            apply_authorized(
                &mut runtime,
                &config,
                LifecycleRequest::UpgradeRuntime {
                    from_deployment: config.identity.runtime_deployment,
                    to_deployment: DeploymentId([0x82; 32]),
                    to_program: ProgramId([0x83; 32]),
                    producer: ProducerId([0x84; 32]),
                    package: BlobRef {
                        hash: Hash([0x85; 32]),
                        len: 1,
                    },
                    contract: config.runtime_contract,
                    capabilities: downgraded,
                },
            ),
            Err(LifecycleError::UnsupportedRuntime)
        );
        assert!(
            runtime
                .config()
                .unwrap()
                .capabilities
                .lanes
                .contains(StateLane::Linear)
        );
        assert_eq!(runtime.invocation_results.len(), 1);
    }

    #[cfg(feature = "pvm")]
    #[test]
    fn invocation_identity_is_scoped_and_acknowledgement_routes_exactly() {
        use crate::agent::execution::{
            ActorExecutionError, ActorExecutionReply, ActorExecutionStatus, ActorInvocation,
            ActorInvocationAuth,
        };
        use crate::service::InvocationId;

        let config = config(8);
        let mut runtime = StandardAgentRuntime::new();
        create_authorized(&mut runtime, &config, 1).unwrap();
        let mut request = install(config.identity.agent, None, "scoped");
        request.entry.lanes = LaneSet::ALL;
        request.requirements.lanes = LaneSet::ALL;
        let actor = request.entry.actor;
        let deployment = request.entry.deployment;
        let program = request.entry.program;
        apply_authorized(&mut runtime, &config, LifecycleRequest::Install(request)).unwrap();
        let incarnation = runtime.actors[&actor].record.state_generation;

        let raw_id = InvocationId([0x77; 32]);
        let invocation = |mode| ActorInvocation {
            invocation: raw_id,
            actor,
            incarnation,
            deployment,
            program,
            mode,
            auth: ActorInvocationAuth::anonymous(),
            message: vec![mode as u8 + 1],
            availability: Vec::new(),
            gas: 1,
        };
        let query = invocation(super::super::MethodMode::Query);
        let query_before = runtime.prepare_execution_state(&query).unwrap();
        let mut query_reply = ActorExecutionReply {
            invocation: raw_id,
            actor,
            incarnation,
            deployment,
            mode: query.mode,
            lane: None,
            status: ActorExecutionStatus::Done,
            reply: vec![0x11],
            gas_remaining: 0,
            observation: super::super::execution::ActorObservation::default(),
        };
        runtime
            .commit_execution(
                &query,
                &mut query_reply,
                &query_before,
                query_before.visible_for(query.mode),
                10,
            )
            .unwrap();

        let merge = invocation(super::super::MethodMode::Merge);
        let merge_before = runtime.prepare_execution_state(&merge).unwrap();
        let mut merge_reply = ActorExecutionReply {
            invocation: raw_id,
            actor,
            incarnation,
            deployment,
            mode: merge.mode,
            lane: Some(StateLane::Merge),
            status: ActorExecutionStatus::Done,
            reply: vec![0x22],
            gas_remaining: 0,
            observation: super::super::execution::ActorObservation::default(),
        };
        runtime
            .commit_execution(
                &merge,
                &mut merge_reply,
                &merge_before,
                merge_before.visible_for(merge.mode),
                11,
            )
            .unwrap();
        assert_eq!(runtime.invocation_results.len(), 2);
        assert_eq!(
            runtime.recover_execution(&query, 12).unwrap(),
            Some(query_reply.clone())
        );
        assert_eq!(
            runtime.recover_execution(&merge, 12).unwrap(),
            Some(merge_reply.clone())
        );

        let linear = invocation(super::super::MethodMode::Linear);
        assert_eq!(
            runtime.recover_execution(&linear, 12),
            Err(ActorExecutionError::DivergentInvocation),
            "Query and Linear share the Ordered exactly-once namespace"
        );

        let query_receipt = signed_invocation_receipt(&config, &query, 0, 100);
        assert_eq!(
            runtime.apply(LifecycleRequest::AcknowledgeInvocation {
                scope: super::super::InvocationScope::Merge,
                invocation: raw_id,
                request: query.commitment(),
                authority: Box::new(query_receipt.clone()),
            }),
            Err(LifecycleError::InvalidRequest),
            "an explicit but wrong scope cannot retire another result"
        );
        assert_eq!(
            runtime.apply(LifecycleRequest::AcknowledgeInvocation {
                scope: super::super::InvocationScope::Ordered,
                invocation: raw_id,
                request: query.commitment(),
                authority: Box::new(query_receipt),
            }),
            Ok(LifecycleReply::InvocationAcknowledged {
                scope: super::super::InvocationScope::Ordered,
                invocation: raw_id,
            })
        );
        assert_eq!(runtime.recover_execution(&query, 12).unwrap(), None);
        assert_eq!(
            runtime.recover_execution(&merge, 12).unwrap(),
            Some(merge_reply)
        );
        let merge_receipt = signed_invocation_receipt(&config, &merge, 0, 100);
        assert!(
            runtime
                .apply(LifecycleRequest::AcknowledgeInvocation {
                    scope: super::super::InvocationScope::Merge,
                    invocation: raw_id,
                    request: merge.commitment(),
                    authority: Box::new(merge_receipt),
                })
                .is_ok()
        );
        assert!(runtime.invocation_results.is_empty());
    }

    #[test]
    fn create_receipt_must_name_the_immutable_owner() {
        let config = config(8);
        let mut runtime = StandardAgentRuntime::new();
        assert_eq!(
            runtime.apply(authorized_at(
                &config,
                CredentialId([0x57; 32]),
                1,
                1,
                2,
                LifecycleRequest::Create(config.clone()),
            )),
            Err(LifecycleError::InvalidRequest)
        );
        assert!(runtime.config().is_none());
    }

    #[cfg(feature = "pvm")]
    #[test]
    fn query_results_recover_exactly_and_lanes_observe_only_visible_state() {
        use crate::agent::execution::{
            ActorExecutionError, ActorExecutionReply, ActorExecutionStatus, ActorInvocation,
            ActorInvocationAuth,
        };
        use crate::service::InvocationId;

        let config = config(8);
        let mut runtime = StandardAgentRuntime::new();
        create_authorized(&mut runtime, &config, 10).unwrap();
        let mut installed = install(config.identity.agent, None, "observed");
        installed.entry.lanes = LaneSet::ALL;
        installed.requirements.lanes = LaneSet::ALL;
        let actor = installed.entry.actor;
        let deployment = installed.entry.deployment;
        let program = installed.entry.program;
        apply_authorized(&mut runtime, &config, LifecycleRequest::Install(installed)).unwrap();
        let incarnation = runtime.actors[&actor].record.state_generation;
        set_lane(&mut runtime, actor, StateLane::Linear, &[1]);
        set_lane(&mut runtime, actor, StateLane::Merge, &[2]);
        set_lane(&mut runtime, actor, StateLane::Local, &[3]);
        runtime.lane_revisions.linear = 7;
        runtime.lane_revisions.merge = 8;
        runtime.lane_revisions.local = 9;

        let invocation = ActorInvocation {
            invocation: InvocationId([0x61; 32]),
            actor,
            incarnation,
            deployment,
            program,
            mode: super::super::MethodMode::Query,
            auth: ActorInvocationAuth::anonymous(),
            message: vec![1],
            availability: Vec::new(),
            gas: 1,
        };
        let receipt = signed_invocation_receipt(&config, &invocation, 0, 130);
        runtime
            .verify_invocation_authority(&invocation, &receipt)
            .unwrap();
        runtime
            .validate_unseen_invocation_slot(&invocation, &receipt, 120)
            .unwrap();
        let before = runtime.prepare_execution_state(&invocation).unwrap();
        let visible = before.visible_for(invocation.mode);
        assert_eq!(visible.linear.as_deref(), Some(&[1][..]));
        assert_eq!(visible.merge.as_deref(), Some(&[2][..]));
        assert!(visible.local.is_none());
        let mut reply = ActorExecutionReply {
            invocation: invocation.invocation,
            actor,
            incarnation,
            deployment,
            mode: invocation.mode,
            lane: None,
            status: ActorExecutionStatus::Done,
            reply: vec![0xaa],
            gas_remaining: 0,
            observation: super::super::execution::ActorObservation::default(),
        };
        runtime
            .commit_execution(&invocation, &mut reply, &before, visible, 120)
            .unwrap();
        assert_eq!(reply.observation.linear_revision, Some(7));
        assert!(reply.observation.merge_frontier.is_some());
        assert_eq!(reply.observation.local_revision, None);
        let merge_observation = runtime
            .observation(actor, super::super::MethodMode::Merge)
            .unwrap();
        assert_eq!(merge_observation.linear_revision, None);
        assert!(merge_observation.merge_frontier.is_some());
        assert_eq!(merge_observation.local_revision, None);
        let local_observation = runtime
            .observation(actor, super::super::MethodMode::LocalQuery)
            .unwrap();
        assert_eq!(local_observation.linear_revision, Some(7));
        assert!(local_observation.merge_frontier.is_some());
        assert_eq!(local_observation.local_revision, Some(9));

        // Mutation after the reply cannot change exact query recovery. The
        // result lives in the topology-neutral control component.
        set_lane(&mut runtime, actor, StateLane::Linear, &[9]);
        let encoded = super::super::wire::encode_standard_runtime_state(&runtime.snapshot());
        let decoded = super::super::wire::decode_standard_runtime_state(&encoded).unwrap();
        let mut reopened = StandardAgentRuntime::restore(decoded).unwrap();
        reopened
            .verify_invocation_authority(&invocation, &receipt)
            .unwrap();
        assert_eq!(
            reopened.recover_execution(&invocation, 140).unwrap(),
            Some(reply.clone()),
            "exact recovery remains valid after the receipt window closes"
        );

        let mut fresh = invocation.clone();
        fresh.invocation = InvocationId([0x62; 32]);
        let expired = signed_invocation_receipt(&config, &fresh, 0, 130);
        reopened
            .verify_invocation_authority(&fresh, &expired)
            .unwrap();
        assert_eq!(
            reopened.validate_unseen_invocation_slot(&fresh, &expired, 140),
            Err(ActorExecutionError::AuthorityExpired)
        );

        // Exact recovery at 140 advanced the global logical observation; a
        // new lifecycle receipt at an older slot cannot reopen history.
        assert_eq!(
            reopened.apply(authorized_at(
                &config,
                CredentialId([0x63; 32]),
                3,
                139,
                3,
                suspend(actor, deployment),
            )),
            Err(LifecycleError::AuthoritySlotRegressed)
        );
        reopened
            .apply(authorized_at(
                &config,
                CredentialId([0x63; 32]),
                3,
                150,
                3,
                suspend(actor, deployment),
            ))
            .unwrap();
        let mut regressed = invocation.clone();
        regressed.invocation = InvocationId([0x64; 32]);
        let regressed_receipt = signed_invocation_receipt(&config, &regressed, 0, 200);
        reopened
            .verify_invocation_authority(&regressed, &regressed_receipt)
            .unwrap();
        assert_eq!(
            reopened.validate_unseen_invocation_slot(&regressed, &regressed_receipt, 149),
            Err(ActorExecutionError::AuthoritySlotRegressed),
            "lifecycle and invocation receipts share one monotone clock"
        );
        assert_eq!(
            reopened.apply(LifecycleRequest::AcknowledgeInvocation {
                scope: invocation.mode.invocation_scope(),
                invocation: invocation.invocation,
                request: invocation.commitment(),
                authority: Box::new(receipt),
            }),
            Ok(LifecycleReply::InvocationAcknowledged {
                scope: invocation.mode.invocation_scope(),
                invocation: invocation.invocation,
            })
        );
        assert_eq!(reopened.recover_execution(&invocation, 151).unwrap(), None);
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
        create_authorized(&mut runtime, &config, 1).unwrap();

        let install_request = LifecycleRequest::Install(install.clone());
        let installed = runtime
            .apply(authorized(
                &config,
                credential,
                2,
                2,
                install_request.clone(),
            ))
            .unwrap();
        assert_eq!(installed, LifecycleReply::Installed(install.entry.clone()));

        let suspend_request = suspend(actor, deployment);
        let suspended = runtime
            .apply(authorized(
                &config,
                credential,
                3,
                3,
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
                4,
                4,
                resume(actor, deployment),
            ))
            .unwrap();

        // A skipped lower sequence was never admitted and cannot become
        // valid merely because current actor state happens to permit it.
        runtime
            .apply(authorized(
                &config,
                credential,
                10,
                10,
                suspend(actor, deployment),
            ))
            .unwrap();
        assert_eq!(
            runtime.apply(authorized(
                &config,
                credential,
                9,
                9,
                resume(actor, deployment),
            )),
            Err(LifecycleError::AuthoritySequenceRegressed)
        );

        runtime
            .apply(authorized(
                &config,
                credential,
                11,
                11,
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
                .apply(authorized(&config, credential, 3, 3, suspend_request,))
                .unwrap(),
            suspended,
            "Suspend(N) replay recovers its old result after Resume(N+1)"
        );
        assert_eq!(
            reopened
                .apply(authorized(&config, credential, 2, 2, install_request,))
                .unwrap(),
            installed,
            "an old Install retry recovers without reinstalling a removed actor"
        );
        assert!(reopened.is_empty());
        assert_eq!(
            reopened.apply(authorized(
                &config,
                credential,
                3,
                0xee,
                suspend(actor, deployment),
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
        let deployment = install.entry.deployment;
        let install_request = LifecycleRequest::Install(install.clone());
        let mut runtime = StandardAgentRuntime::new();
        create_authorized(&mut runtime, &config, 10).unwrap();
        let installed = runtime
            .apply(authorized_at(
                &config,
                credential,
                2,
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
                3,
                19,
                2,
                suspend(actor, deployment),
            )),
            Err(LifecycleError::AuthoritySlotRegressed)
        );
        assert_eq!(reopened.actor(actor), Some(&install.entry));

        assert_eq!(
            reopened
                .apply(authorized_at(
                    &config,
                    credential,
                    2,
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
                3,
                24,
                2,
                suspend(actor, deployment),
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
        let target_deployment = target_install.entry.deployment;
        let request = suspend(target, target_deployment);
        let mut runtime = StandardAgentRuntime::new();
        create_authorized(&mut runtime, &config, 1).unwrap();

        let last_sequence = MAX_AUTHORITY_DISPOSITIONS as u64 + 45;
        for sequence in 2..=last_sequence {
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
        assert_eq!(snapshot.authority_dispositions[0].sequence, 46);
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
        apply_authorized(
            &mut reopened,
            &config,
            LifecycleRequest::Install(target_install),
        )
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
                credential(47),
                47,
                (47 % 251) as u8 + 1,
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
                credential(last_sequence + 2),
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
                credential(last_sequence + 2),
                last_sequence + 2,
                7,
                request,
            )),
            Ok(LifecycleReply::Suspended(entry)) if entry.actor == target
        ));
    }

    #[test]
    fn restore_requires_the_journal_tail_to_match_the_global_high_water() {
        let config = config(8);
        let request = suspend(ActorId([0xb5; 32]), DeploymentId([0xb7; 32]));
        let mut runtime = StandardAgentRuntime::new();
        create_authorized(&mut runtime, &config, 1).unwrap();
        assert_eq!(
            runtime.apply(authorized(&config, CredentialId([0xb6; 32]), 2, 2, request,)),
            Err(LifecycleError::NotFound)
        );

        let mut snapshot = runtime.snapshot();
        snapshot.authority_sequence_high_water = Some(3);
        assert!(matches!(
            StandardAgentRuntime::restore(snapshot),
            Err(LifecycleError::InvalidRequest)
        ));

        let mut transient = StandardAgentRuntime::new();
        transient
            .apply_mutation(LifecycleRequest::Create(config))
            .unwrap();
        assert!(
            matches!(
                StandardAgentRuntime::restore(transient.snapshot()),
                Err(LifecycleError::InvalidRequest)
            ),
            "a durable created state must retain its authorized Create tail"
        );
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
            contract: config.runtime_contract,
            capabilities: config.capabilities,
        };
        let mut runtime = StandardAgentRuntime::new();
        create_authorized(&mut runtime, &config, 1).unwrap();
        let upgraded = runtime
            .apply(authorized(&config, credential, 2, 2, request.clone()))
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
                .apply(authorized(&config, credential, 2, 2, request))
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
        create_authorized(&mut runtime, &config, 1).unwrap();
        let mut installed = install(agent, None, "board");
        installed.entry.role_policies = policy_blob.reference.clone();
        installed.role_policies = policy_blob.reference.clone();
        let actor = installed.entry.actor;
        let deployment = installed.entry.deployment;
        let program = installed.entry.program;
        apply_authorized(&mut runtime, &config, LifecycleRequest::Install(installed)).unwrap();
        let incarnation = runtime.actors[&actor].record.state_generation;

        let mut message = vec![TAG_DYNAMIC];
        message.extend_from_slice(&Msg::new("set_title").encode());
        let mut invocation = super::super::execution::ActorInvocation {
            invocation: InvocationId([0x52; 32]),
            actor,
            incarnation,
            deployment,
            program,
            mode: super::super::MethodMode::Linear,
            auth: super::super::execution::ActorInvocationAuth {
                origin: Origin::Member(SubjectId([0x53; 32])),
                principal: Some(crate::service::PrincipalId([0x54; 32])),
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
            principal: None,
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
        create_authorized(&mut runtime, &config, 1).unwrap();

        let mut mismatched = install(agent, None, "counter");
        mismatched.entry.agent_schema.hash = Hash([0x44; 32]);
        assert_eq!(
            apply_authorized(&mut runtime, &config, LifecycleRequest::Install(mismatched)),
            Err(LifecycleError::InvalidRequest)
        );

        let mut mismatched = install(agent, None, "counter");
        mismatched.entry.state_layout = Hash([0x45; 32]);
        assert_eq!(
            apply_authorized(&mut runtime, &config, LifecycleRequest::Install(mismatched)),
            Err(LifecycleError::InvalidRequest)
        );

        let mut mismatched = install(agent, None, "counter");
        mismatched.entry.package.hash = Hash([0x46; 32]);
        assert_eq!(
            apply_authorized(&mut runtime, &config, LifecycleRequest::Install(mismatched)),
            Err(LifecycleError::InvalidRequest)
        );

        let mut mismatched = install(agent, None, "counter");
        mismatched.entry.role_policies.hash = Hash([0x47; 32]);
        assert_eq!(
            apply_authorized(&mut runtime, &config, LifecycleRequest::Install(mismatched)),
            Err(LifecycleError::InvalidRequest)
        );
        assert!(runtime.is_empty());
    }

    #[test]
    fn create_cannot_overstate_standard_runtime_capabilities() {
        let oversized = config(super::super::RuntimeCapabilities::STANDARD_MAX_ACTORS + 1);
        let mut runtime = StandardAgentRuntime::new();
        assert_eq!(
            create_authorized(&mut runtime, &oversized, 1),
            Err(LifecycleError::UnsupportedRuntime)
        );
        assert_eq!(runtime.snapshot(), StandardRuntimeState::default());

        let mut proof_capable = config(1);
        proof_capable.capabilities.proofs = true;
        let mut runtime = StandardAgentRuntime::new();
        assert_eq!(
            create_authorized(&mut runtime, &proof_capable, 1),
            Err(LifecycleError::UnsupportedRuntime)
        );
        assert_eq!(runtime.snapshot(), StandardRuntimeState::default());
    }

    #[test]
    fn create_enforces_signed_aggregate_and_global_per_reference_artifact_limits() {
        let mut aggregate = config(1);
        aggregate
            .runtime_contract
            .resources
            .max_artifact_referenced_bytes = aggregate.runtime_package.len - 1;
        let mut runtime = StandardAgentRuntime::new();
        assert_eq!(
            runtime.apply_mutation(LifecycleRequest::Create(aggregate)),
            Err(LifecycleError::ResourceLimit)
        );
        assert!(runtime.config().is_none());

        let mut per_reference = config(1);
        per_reference.runtime_package.len = super::super::MAX_CATALOG_ARTIFACT_BYTES + 1;
        let mut runtime = StandardAgentRuntime::new();
        assert_eq!(
            runtime.apply_mutation(LifecycleRequest::Create(per_reference)),
            Err(LifecycleError::ResourceLimit)
        );
        assert!(runtime.config().is_none());
    }

    #[test]
    fn install_counts_unique_exact_references_and_rejects_ambiguous_lengths() {
        let mut bounded = config(8);
        bounded.runtime_contract.resources.max_artifact_references = 4;
        bounded
            .runtime_contract
            .resources
            .max_artifact_referenced_bytes = 400;
        let mut runtime = StandardAgentRuntime::new();
        create_authorized(&mut runtime, &bounded, 1).unwrap();
        apply_authorized(
            &mut runtime,
            &bounded,
            LifecycleRequest::Install(install(bounded.identity.agent, None, "first")),
        )
        .unwrap();
        apply_authorized(
            &mut runtime,
            &bounded,
            LifecycleRequest::Install(install(bounded.identity.agent, None, "shared")),
        )
        .unwrap();
        assert_eq!(runtime.len(), 2, "exact cross-actor references deduplicate");

        let mut fifth = install(bounded.identity.agent, None, "fifth-ref");
        let package = BlobRef {
            hash: Hash([0x91; 32]),
            len: 100,
        };
        fifth.entry.package = package.clone();
        fifth.package = package;
        assert_eq!(
            apply_authorized(&mut runtime, &bounded, LifecycleRequest::Install(fifth)),
            Err(LifecycleError::ResourceLimit)
        );
        assert_eq!(runtime.len(), 2);

        let mut ambiguous_config = config(2);
        ambiguous_config
            .runtime_contract
            .resources
            .max_artifact_references = 4;
        ambiguous_config
            .runtime_contract
            .resources
            .max_artifact_referenced_bytes = 1_000;
        let mut ambiguous_runtime = StandardAgentRuntime::new();
        create_authorized(&mut ambiguous_runtime, &ambiguous_config, 1).unwrap();
        let mut ambiguous = install(ambiguous_config.identity.agent, None, "ambiguous");
        let package = BlobRef {
            hash: ambiguous_config.runtime_package.hash,
            len: ambiguous_config.runtime_package.len + 1,
        };
        ambiguous.entry.package = package.clone();
        ambiguous.package = package;
        assert_eq!(
            apply_authorized(
                &mut ambiguous_runtime,
                &ambiguous_config,
                LifecycleRequest::Install(ambiguous)
            ),
            Err(LifecycleError::InvalidRequest)
        );
        assert!(ambiguous_runtime.is_empty());
    }

    #[test]
    fn install_exact_duplicates_charge_once_at_the_one_reference_boundary() {
        let mut config = config(1);
        config.runtime_contract.resources.max_artifact_references = 1;
        config
            .runtime_contract
            .resources
            .max_artifact_referenced_bytes = config.runtime_package.len;
        let mut runtime = StandardAgentRuntime::new();
        create_authorized(&mut runtime, &config, 1).unwrap();
        let mut actor = install(config.identity.agent, None, "one-blob");
        set_install_artifacts(
            &mut actor,
            config.runtime_package.clone(),
            config.runtime_package.clone(),
            config.runtime_package.clone(),
        );
        assert!(apply_authorized(&mut runtime, &config, LifecycleRequest::Install(actor)).is_ok());
        assert_eq!(runtime.len(), 1);
    }

    #[test]
    fn actor_upgrade_keeps_globally_shared_old_references_charged() {
        let mut config = config(4);
        config.runtime_contract.resources.max_artifact_references = 6;
        config
            .runtime_contract
            .resources
            .max_artifact_referenced_bytes = 1_000;
        let mut runtime = StandardAgentRuntime::new();
        create_authorized(&mut runtime, &config, 1).unwrap();
        let first = install(config.identity.agent, None, "first-sharer");
        let first_entry = first.entry.clone();
        let second = install(config.identity.agent, None, "second-sharer");
        apply_authorized(&mut runtime, &config, LifecycleRequest::Install(first)).unwrap();
        apply_authorized(&mut runtime, &config, LifecycleRequest::Install(second)).unwrap();

        let upgrade = UpgradeActor {
            actor: first_entry.actor,
            from_deployment: first_entry.deployment,
            to_deployment: DeploymentId([0x92; 32]),
            to_program: first_entry.program,
            producer: ProducerId([0x93; 32]),
            package: BlobRef {
                hash: Hash([0x94; 32]),
                len: 100,
            },
            agent_schema: BlobRef {
                hash: Hash([0x95; 32]),
                len: 100,
            },
            role_policies: BlobRef {
                hash: Hash([0x96; 32]),
                len: 100,
            },
            state_layout: first_entry.state_layout,
            contract: crate::agent::contract::ActorPackageContract::canonical(),
            requirements: RuntimeRequirements {
                lanes: first_entry.lanes,
                scheduling: false,
                proofs: false,
            },
        };
        assert_eq!(
            apply_authorized(
                &mut runtime,
                &config,
                LifecycleRequest::UpgradeActor(upgrade)
            ),
            Err(LifecycleError::ResourceLimit)
        );
        assert_eq!(runtime.actor(first_entry.actor), Some(&first_entry));
        assert_eq!(runtime.len(), 2);
    }

    #[test]
    fn runtime_upgrade_uses_target_artifact_and_intrinsic_capacity_limits() {
        let mut config = config(8);
        config.runtime_contract.resources.max_artifact_references = 4;
        config
            .runtime_contract
            .resources
            .max_artifact_referenced_bytes = 400;
        let mut runtime = StandardAgentRuntime::new();
        create_authorized(&mut runtime, &config, 1).unwrap();
        apply_authorized(
            &mut runtime,
            &config,
            LifecycleRequest::Install(install(config.identity.agent, None, "resident")),
        )
        .unwrap();

        let mut lower = config.runtime_contract;
        lower.resources.max_artifact_referenced_bytes = 399;
        let lower_request = LifecycleRequest::UpgradeRuntime {
            from_deployment: config.identity.runtime_deployment,
            to_deployment: DeploymentId([0xa1; 32]),
            to_program: ProgramId([0xa2; 32]),
            producer: ProducerId([0xa3; 32]),
            package: BlobRef {
                hash: Hash([0xa4; 32]),
                len: 100,
            },
            contract: lower,
            capabilities: config.capabilities,
        };
        assert_eq!(
            apply_authorized(&mut runtime, &config, lower_request),
            Err(LifecycleError::ResourceLimit)
        );
        assert_eq!(
            runtime.config().unwrap().identity.runtime_deployment,
            config.identity.runtime_deployment
        );

        let mut excessive_capabilities = config.capabilities;
        excessive_capabilities.max_actors = RuntimeCapabilities::STANDARD_MAX_ACTORS + 1;
        assert_eq!(
            apply_authorized(
                &mut runtime,
                &config,
                LifecycleRequest::UpgradeRuntime {
                    from_deployment: config.identity.runtime_deployment,
                    to_deployment: DeploymentId([0xa5; 32]),
                    to_program: ProgramId([0xa6; 32]),
                    producer: ProducerId([0xa7; 32]),
                    package: BlobRef {
                        hash: Hash([0xa8; 32]),
                        len: 100,
                    },
                    contract: config.runtime_contract,
                    capabilities: excessive_capabilities,
                }
            ),
            Err(LifecycleError::UnsupportedRuntime)
        );

        let mut higher = config.runtime_contract;
        higher.resources.max_artifact_referenced_bytes = 500;
        let upgraded = apply_authorized(
            &mut runtime,
            &config,
            LifecycleRequest::UpgradeRuntime {
                from_deployment: config.identity.runtime_deployment,
                to_deployment: DeploymentId([0xa9; 32]),
                to_program: ProgramId([0xaa; 32]),
                producer: ProducerId([0xab; 32]),
                package: BlobRef {
                    hash: Hash([0xac; 32]),
                    len: 200,
                },
                contract: higher,
                capabilities: config.capabilities,
            },
        )
        .unwrap();
        assert!(matches!(
            upgraded,
            LifecycleReply::RuntimeUpgraded(identity)
                if identity.runtime_deployment == DeploymentId([0xa9; 32])
        ));
    }

    #[test]
    fn restore_recomputes_signed_artifact_closure_and_state_limits() {
        let config = config(2);
        let mut runtime = StandardAgentRuntime::new();
        create_authorized(&mut runtime, &config, 1).unwrap();
        runtime
            .install(
                install(config.identity.agent, None, "restored"),
                Hash([0xb1; 32]),
            )
            .unwrap();
        let snapshot = runtime.snapshot();

        let mut artifact_overflow = snapshot.clone();
        artifact_overflow
            .config
            .as_mut()
            .unwrap()
            .runtime_contract
            .resources
            .max_artifact_referenced_bytes = 399;
        assert!(matches!(
            StandardAgentRuntime::restore(artifact_overflow),
            Err(LifecycleError::ResourceLimit)
        ));

        let mut ambiguous = snapshot.clone();
        let runtime_reference = ambiguous.config.as_ref().unwrap().runtime_package.clone();
        let package = BlobRef {
            hash: runtime_reference.hash,
            len: runtime_reference.len + 1,
        };
        ambiguous.actors[0].record.entry.package = package.clone();
        ambiguous.actors[0].record.package = package;
        assert!(matches!(
            StandardAgentRuntime::restore(ambiguous),
            Err(LifecycleError::InvalidRequest)
        ));

        let mut state_overflow = snapshot;
        let encoded_len = super::super::wire::encode_standard_runtime_state(&state_overflow)
            .encoded_len()
            .unwrap();
        state_overflow
            .config
            .as_mut()
            .unwrap()
            .runtime_contract
            .resources
            .max_runtime_state_bytes = u32::try_from(encoded_len - 1).unwrap();
        assert!(matches!(
            StandardAgentRuntime::restore(state_overflow),
            Err(LifecycleError::ResourceLimit)
        ));
    }

    #[test]
    fn authorized_resource_refusal_is_atomic_consumed_and_exactly_retryable() {
        let mut config = config(2);
        config.runtime_contract.resources.max_artifact_references = 1;
        config
            .runtime_contract
            .resources
            .max_artifact_referenced_bytes = config.runtime_package.len;
        let mut runtime = StandardAgentRuntime::new();
        create_authorized(&mut runtime, &config, 1).unwrap();
        let before_config = runtime.config().unwrap().clone();
        let request =
            LifecycleRequest::Install(install(config.identity.agent, None, "over-signed-limit"));
        let signed = authorized(&config, CredentialId([0xb2; 32]), 2, 2, request);

        assert_eq!(
            runtime.apply(signed.clone()),
            Err(LifecycleError::ResourceLimit)
        );
        assert!(runtime.is_empty());
        assert_eq!(runtime.config(), Some(&before_config));
        assert_eq!(runtime.authority_sequence_high_water, Some(2));
        assert_eq!(runtime.authority_slot_high_water, Some(100));
        assert_eq!(
            runtime
                .authority_dispositions
                .last()
                .map(|item| &item.result),
            Some(&Err(LifecycleError::ResourceLimit))
        );
        let disposition_count = runtime.authority_dispositions.len();

        let encoded = super::super::wire::encode_standard_runtime_state(&runtime.snapshot());
        let decoded = super::super::wire::decode_standard_runtime_state(&encoded).unwrap();
        assert_eq!(
            decoded
                .authority_dispositions
                .last()
                .map(|item| &item.result),
            Some(&Err(LifecycleError::ResourceLimit))
        );
        let mut reopened = StandardAgentRuntime::restore(decoded).unwrap();
        assert_eq!(
            reopened.apply(signed),
            Err(LifecycleError::ResourceLimit),
            "an exact retry recovers the retained refusal without rechecking resources"
        );
        assert!(reopened.is_empty());
        assert_eq!(reopened.config(), Some(&before_config));
        assert_eq!(reopened.authority_sequence_high_water, Some(2));
        assert_eq!(reopened.authority_dispositions.len(), disposition_count);
    }

    #[test]
    fn every_authorized_outcome_reserves_its_exact_signed_state_bytes() {
        let config = config(2);
        let mut runtime = StandardAgentRuntime::new();
        create_authorized(&mut runtime, &config, 1).unwrap();
        let current_bytes = super::super::wire::encode_standard_runtime_state(&runtime.snapshot())
            .encoded_len()
            .unwrap();
        runtime
            .config
            .as_mut()
            .unwrap()
            .runtime_contract
            .resources
            .max_runtime_state_bytes = u32::try_from(current_bytes).unwrap();

        let request = LifecycleRequest::Install(install(
            config.identity.agent,
            None,
            "state-capacity-refusal",
        ));
        let signed = authorized(&config, CredentialId([0xb7; 32]), 2, 2, request);
        assert_eq!(
            runtime.apply(signed.clone()),
            Err(LifecycleError::ResourceLimit)
        );
        assert!(runtime.is_empty(), "the actor install must roll back");
        assert_eq!(runtime.authority_sequence_high_water, Some(2));
        assert_eq!(runtime.authority_slot_high_water, Some(100));
        assert_eq!(runtime.authority_dispositions.len(), 1);
        assert_eq!(runtime.authority_dispositions[0].sequence, 2);
        assert_eq!(
            runtime.authority_dispositions[0].result,
            Err(LifecycleError::ResourceLimit),
            "the oldest disposition supplies bounded headroom for the exact refusal"
        );
        assert!(
            super::super::wire::encode_standard_runtime_state(&runtime.snapshot())
                .encoded_len()
                .unwrap()
                <= current_bytes
        );

        let mut reopened = StandardAgentRuntime::restore(runtime.snapshot()).unwrap();
        assert_eq!(reopened.apply(signed), Err(LifecycleError::ResourceLimit));
        assert_eq!(reopened.authority_dispositions.len(), 1);

        let next = authorized(
            &config,
            CredentialId([0xb8; 32]),
            3,
            3,
            LifecycleRequest::Install(install(
                config.identity.agent,
                None,
                "second-state-capacity-refusal",
            )),
        );
        assert_eq!(reopened.apply(next), Err(LifecycleError::ResourceLimit));
        assert_eq!(reopened.authority_sequence_high_water, Some(3));
        assert_eq!(reopened.authority_dispositions.len(), 1);
        assert_eq!(reopened.authority_dispositions[0].sequence, 3);
        assert_eq!(
            reopened.apply(authorized(
                &config,
                CredentialId([0xb7; 32]),
                2,
                2,
                LifecycleRequest::Install(install(
                    config.identity.agent,
                    None,
                    "state-capacity-refusal",
                )),
            )),
            Err(LifecycleError::AuthoritySequenceRegressed),
            "evicted capacity refusals retain the global anti-replay high-water"
        );
    }

    #[test]
    fn undersized_create_refuses_without_publishing_a_partial_agent() {
        let mut config = config(1);
        config.runtime_contract.resources.max_runtime_state_bytes = 1;
        let mut runtime = StandardAgentRuntime::new();
        assert_eq!(
            create_authorized(&mut runtime, &config, 1),
            Err(LifecycleError::ResourceLimit)
        );
        assert_eq!(runtime.snapshot(), StandardRuntimeState::default());
    }

    #[test]
    fn runtime_upgrade_reserves_target_state_bytes_for_its_exact_disposition() {
        let config = config(1);
        let mut runtime = StandardAgentRuntime::new();
        create_authorized(&mut runtime, &config, 1).unwrap();

        let package = BlobRef {
            hash: Hash([0xb3; 32]),
            len: 100,
        };
        let mut direct = runtime.clone();
        direct
            .upgrade_runtime(
                config.identity.runtime_deployment,
                DeploymentId([0xb4; 32]),
                ProgramId([0xb5; 32]),
                ProducerId([0xb6; 32]),
                package.clone(),
                config.runtime_contract,
                config.capabilities,
            )
            .unwrap();
        let direct_bytes = super::super::wire::encode_standard_runtime_state(&direct.snapshot())
            .encoded_len()
            .unwrap();
        let mut target_contract = config.runtime_contract;
        target_contract.resources.max_runtime_state_bytes = u32::try_from(direct_bytes).unwrap();
        let request = LifecycleRequest::UpgradeRuntime {
            from_deployment: config.identity.runtime_deployment,
            to_deployment: DeploymentId([0xb4; 32]),
            to_program: ProgramId([0xb5; 32]),
            producer: ProducerId([0xb6; 32]),
            package,
            contract: target_contract,
            capabilities: config.capabilities,
        };
        assert_eq!(
            apply_authorized(&mut runtime, &config, request),
            Err(LifecycleError::ResourceLimit)
        );
        assert_eq!(
            runtime.config().unwrap().identity.runtime_deployment,
            config.identity.runtime_deployment,
            "the semantic upgrade rolls back while its exact refusal is retained"
        );
        assert_eq!(
            runtime
                .authority_dispositions
                .last()
                .map(|item| &item.result),
            Some(&Err(LifecycleError::ResourceLimit))
        );
    }

    #[test]
    fn install_rejects_proof_and_scheduler_requirements_before_state_changes() {
        let config = config(10);
        let agent = config.identity.agent;
        let mut runtime = StandardAgentRuntime::new();
        create_authorized(&mut runtime, &config, 1).unwrap();

        let mut proof = install(agent, None, "attested");
        proof.requirements.proofs = true;
        assert_eq!(
            apply_authorized(&mut runtime, &config, LifecycleRequest::Install(proof)),
            Err(LifecycleError::UnsupportedRuntime)
        );

        let mut job = install(agent, None, "scheduled");
        job.requirements.scheduling = true;
        assert_eq!(
            apply_authorized(&mut runtime, &config, LifecycleRequest::Install(job)),
            Err(LifecycleError::UnsupportedRuntime)
        );
        assert!(runtime.is_empty());
    }

    #[test]
    fn actor_forest_has_no_privileged_root_actor() {
        let mut runtime = StandardAgentRuntime::new();
        let config = config(10);
        let agent = config.identity.agent;
        create_authorized(&mut runtime, &config, 1).unwrap();
        let first = install(agent, None, "first");
        let second = install(agent, None, "second");
        let child = install(agent, Some(first.entry.actor), "child");
        apply_authorized(&mut runtime, &config, LifecycleRequest::Install(first)).unwrap();
        apply_authorized(&mut runtime, &config, LifecycleRequest::Install(second)).unwrap();
        apply_authorized(&mut runtime, &config, LifecycleRequest::Install(child)).unwrap();
        assert_eq!(runtime.len(), 3);
    }

    #[test]
    fn safe_removal_requires_a_leaf_with_no_durable_debt() {
        let mut runtime = StandardAgentRuntime::new();
        let config = config(10);
        let agent = config.identity.agent;
        create_authorized(&mut runtime, &config, 1).unwrap();
        let parent = install(agent, None, "parent");
        let parent_id = parent.entry.actor;
        let deployment = parent.entry.deployment;
        let child = install(agent, Some(parent_id), "child");
        let child_id = child.entry.actor;
        apply_authorized(&mut runtime, &config, LifecycleRequest::Install(parent)).unwrap();
        apply_authorized(&mut runtime, &config, LifecycleRequest::Install(child)).unwrap();
        assert!(matches!(
            apply_authorized(
                &mut runtime,
                &config,
                LifecycleRequest::RemoveLeaf {
                    actor: parent_id,
                    expected_deployment: deployment,
                }
            ),
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
            apply_authorized(
                &mut runtime,
                &config,
                LifecycleRequest::RemoveLeaf {
                    actor: child_id,
                    expected_deployment: DeploymentId([7; 32]),
                }
            ),
            Err(LifecycleError::Busy(ActorLifecycleDebt { outbox: 1, .. }))
        ));
    }

    #[test]
    fn runtime_upgrade_checks_every_installed_actor() {
        let mut runtime = StandardAgentRuntime::new();
        let config = config(10);
        let agent = config.identity.agent;
        create_authorized(&mut runtime, &config, 1).unwrap();
        let actor = install(agent, None, "counter");
        apply_authorized(&mut runtime, &config, LifecycleRequest::Install(actor)).unwrap();
        let merge_only = RuntimeCapabilities {
            lanes: LaneSet::of(StateLane::Merge),
            scheduling: false,
            proofs: false,
            max_actors: 10,
        };
        assert_eq!(
            apply_authorized(
                &mut runtime,
                &config,
                LifecycleRequest::UpgradeRuntime {
                    from_deployment: DeploymentId([4; 32]),
                    to_deployment: DeploymentId([11; 32]),
                    to_program: ProgramId([12; 32]),
                    producer: ProducerId([18; 32]),
                    package: BlobRef {
                        hash: Hash([13; 32]),
                        len: 100,
                    },
                    contract: config.runtime_contract,
                    capabilities: merge_only,
                }
            ),
            Err(LifecycleError::UnsupportedRuntime)
        );
    }

    #[test]
    fn actor_program_changes_require_stateless_state() {
        let config = config(10);
        let agent = config.identity.agent;

        let mut stateful = StandardAgentRuntime::new();
        create_authorized(&mut stateful, &config, 1).unwrap();
        let installed = install(agent, None, "stateful");
        let actor = installed.entry.actor;
        let requirements = installed.requirements;
        apply_authorized(&mut stateful, &config, LifecycleRequest::Install(installed)).unwrap();
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
            contract: crate::agent::contract::ActorPackageContract::canonical(),
            requirements,
        };
        assert_eq!(
            apply_authorized(
                &mut stateful,
                &config,
                LifecycleRequest::UpgradeActor(replacement.clone()),
            ),
            Err(LifecycleError::UnsupportedLane)
        );

        let mut stateless = StandardAgentRuntime::new();
        create_authorized(&mut stateless, &config, 1).unwrap();
        let mut installed = install(agent, None, "stateless");
        installed.entry.lanes = LaneSet::NONE;
        installed.requirements.lanes = LaneSet::NONE;
        let actor = installed.entry.actor;
        apply_authorized(
            &mut stateless,
            &config,
            LifecycleRequest::Install(installed),
        )
        .unwrap();
        let mut replacement = replacement;
        replacement.actor = actor;
        replacement.requirements.lanes = LaneSet::NONE;
        assert!(matches!(
            apply_authorized(
                &mut stateless,
                &config,
                LifecycleRequest::UpgradeActor(replacement),
            ),
            Ok(LifecycleReply::Upgraded(entry))
                if entry.program == ProgramId([15; 32])
                    && entry.package.hash == Hash([16; 32])
                    && entry.role_policies.hash == Hash([18; 32])
        ));
    }

    #[test]
    fn suspend_and_resume_bind_the_current_actor_deployment() {
        let config = config(10);
        let agent = config.identity.agent;
        let mut runtime = StandardAgentRuntime::new();
        create_authorized(&mut runtime, &config, 1).unwrap();
        let installed = install(agent, None, "deployment-bound");
        let actor = installed.entry.actor;
        let deployment_a = installed.entry.deployment;
        let deployment_b = DeploymentId([0x6e; 32]);
        let program = installed.entry.program;
        let requirements = installed.requirements;
        let state_layout = installed.state_layout;
        apply_authorized(&mut runtime, &config, LifecycleRequest::Install(installed)).unwrap();

        let stale_suspend = suspend(actor, deployment_a);
        let stale_resume = resume(actor, deployment_a);
        apply_authorized(
            &mut runtime,
            &config,
            LifecycleRequest::UpgradeActor(UpgradeActor {
                actor,
                from_deployment: deployment_a,
                to_deployment: deployment_b,
                to_program: program,
                producer: ProducerId([0x6f; 32]),
                package: BlobRef {
                    hash: Hash([0x70; 32]),
                    len: 100,
                },
                agent_schema: BlobRef {
                    hash: Hash([0x71; 32]),
                    len: 100,
                },
                role_policies: BlobRef {
                    hash: Hash([0x72; 32]),
                    len: 100,
                },
                state_layout,
                contract: crate::agent::contract::ActorPackageContract::canonical(),
                requirements,
            }),
        )
        .unwrap();

        assert_eq!(
            apply_authorized(&mut runtime, &config, stale_suspend),
            Err(LifecycleError::StaleDeployment)
        );
        assert_eq!(
            apply_authorized(&mut runtime, &config, stale_resume),
            Err(LifecycleError::StaleDeployment)
        );
        assert_eq!(
            runtime
                .actor(actor)
                .map(|entry| (entry.deployment, entry.suspended)),
            Some((deployment_b, false)),
            "stale lifecycle requests consume their authority sequence but do not mutate B"
        );

        assert!(matches!(
            apply_authorized(&mut runtime, &config, suspend(actor, deployment_b)),
            Ok(LifecycleReply::Suspended(entry))
                if entry.deployment == deployment_b && entry.suspended
        ));
        assert!(matches!(
            apply_authorized(&mut runtime, &config, resume(actor, deployment_b)),
            Ok(LifecycleReply::Resumed(entry))
                if entry.deployment == deployment_b && !entry.suspended
        ));
    }

    #[test]
    fn upgrade_actor_is_blocked_by_pending_work() {
        let mut runtime = StandardAgentRuntime::new();
        let config = config(10);
        let agent = config.identity.agent;
        create_authorized(&mut runtime, &config, 1).unwrap();
        let install = install(agent, None, "counter");
        let actor = install.entry.actor;
        apply_authorized(&mut runtime, &config, LifecycleRequest::Install(install)).unwrap();
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
            apply_authorized(
                &mut runtime,
                &config,
                LifecycleRequest::UpgradeActor(UpgradeActor {
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
                    contract: crate::agent::contract::ActorPackageContract::canonical(),
                    requirements,
                })
            ),
            Err(LifecycleError::Busy(ActorLifecycleDebt {
                continuations: 1,
                ..
            }))
        ));
    }
}
