//! Experimental adapter to the existing immutable journal blob store.
//!
//! Staging does not advance heads or mint a replay seal. Blocks remain
//! unpublished until replay and publication admit their external roots; staged
//! bytes alone must not be advertised as durable state. The publication owner
//! must serialize staging/publication against GC, exactly as for other journal
//! candidates. There is deliberately no second commit or filesystem engine.

use super::journal::{
    AgentJournalGenesis, CanonicalJournalRecord, LaneCursor, LaneStateManifest, LocalEntryId,
    MergeFrontier, MergeFrontierId, PersistedLane, ReplayInput, RuntimeBinding, encode_lane_cursor,
};
use super::journal_store::{AgentJournalStore, JournalBlobClass, JournalStoreError};
use crate::agent_sdk::{
    Hash,
    state_blocks::{BlockError, BlockRef, BlockScope, ReadBudget},
    state_change::StateChange,
    state_root::{RootContext, RootError, StateRootDescriptor},
    state_tree::{BlockReader, TreeError},
};

/// Initial context from an independently authenticated Create input, before
/// final genesis admission exists. Admission can commit post-Create state, so
/// neither the generation nor initial revision may hash the final genesis ID.
/// The Create intent and authority sequence provide the cycle-free seed.
/// Local scope additionally binds the node; replicas must not share private
/// blocks even when their public generation and lane are identical.
/// This validates canonical input shape, not authority or replica placement.
pub(crate) fn initial_root_context(
    create: &ReplayInput,
    lane: PersistedLane,
    node: Option<crate::service::NodeId>,
) -> Result<RootContext, RootError> {
    let invalid = |_| RootError::InvalidContext;
    create.validate().map_err(invalid)?;
    let runtime = &create.runtime;
    let sdk_lane = match lane {
        PersistedLane::Linear => crate::agent_sdk::StateLane::Linear,
        PersistedLane::Merge => crate::agent_sdk::StateLane::Merge,
        PersistedLane::Local => crate::agent_sdk::StateLane::Local,
        // Control metadata does not yet use this actor-state block contract.
        PersistedLane::Control => return Err(RootError::InvalidContext),
    };
    if (lane == PersistedLane::Local) != node.is_some()
        || node == Some(crate::service::NodeId::ZERO)
    {
        return Err(RootError::InvalidContext);
    }
    let intent = AgentJournalGenesis::create_intent(create).map_err(invalid)?;
    let sequence = AgentJournalGenesis::create_authority_sequence(create).map_err(invalid)?;
    let node_bytes = node.map_or([0; 32], |node| node.0);
    let generation = Hash::digest(
        b"vos/experimental/storage-generation/v1",
        &[intent.as_bytes(), &sequence.to_le_bytes(), &node_bytes],
    );
    let scope = BlockScope::new(
        crate::agent_sdk::SpaceId(runtime.space.0),
        crate::agent_sdk::AgentId(runtime.agent.0),
        generation,
        sdk_lane,
    )
    .map_err(|_| RootError::InvalidContext)?;
    let revision = Hash::digest(
        b"vos/experimental/state-initial-revision/v1",
        &[generation.as_bytes()],
    );
    RootContext::new(scope, Hash(runtime.commitment().0), revision)
}

/// Derive a descriptor binding from independently admitted journal metadata.
/// This checks shape and scope, NOT signatures, freshness, cursor existence,
/// or finality; the owner must use its validated replay/checkpoint snapshot.
/// Initial cursors normalize to the pre-admission Create context above.
pub(crate) fn journal_root_context(
    genesis: &AgentJournalGenesis,
    runtime: &RuntimeBinding,
    lane: PersistedLane,
    node: Option<crate::service::NodeId>,
    cursor: &LaneCursor,
) -> Result<RootContext, RootError> {
    let invalid = |_| RootError::InvalidContext;
    genesis.validate().map_err(invalid)?;
    runtime.validate().map_err(invalid)?;
    if runtime.space != genesis.runtime().space || runtime.agent != genesis.runtime().agent {
        return Err(RootError::InvalidContext);
    }
    let initial_context = initial_root_context(&genesis.create, lane, node)?;
    let initial = match (lane, cursor) {
        (PersistedLane::Linear, LaneCursor::Ordered { base }) => {
            base.validate().map_err(invalid)?;
            base.index == 0
        }
        (
            PersistedLane::Local,
            LaneCursor::Local {
                node: owner,
                revision,
                head,
            },
        ) if Some(*owner) == node => {
            if (*revision == 0) != head.is_none() || *head == Some(LocalEntryId::ZERO) {
                return Err(RootError::InvalidContext);
            }
            *revision == 0
        }
        (PersistedLane::Merge, LaneCursor::Merge { frontier }) => {
            if *frontier == MergeFrontierId::ZERO {
                return Err(RootError::InvalidContext);
            }
            *frontier
                == (MergeFrontier {
                    genesis: genesis.id(),
                    events: Vec::new(),
                })
                .id()
        }
        _ => return Err(RootError::InvalidContext),
    };
    if initial {
        if runtime != genesis.runtime() {
            return Err(RootError::InvalidContext);
        }
        return Ok(initial_context);
    }
    let revision = {
        let mut bytes = Vec::new();
        encode_lane_cursor(&mut crate::service::wire::Encoder(&mut bytes), cursor);
        Hash::digest(
            b"vos/experimental/state-journal-revision/v1",
            &[genesis.id().as_bytes(), &bytes],
        )
    };
    RootContext::new(
        initial_context.scope(),
        Hash(runtime.commitment().0),
        revision,
    )
}

use super::replay::ScopedBlockReader;

pub(crate) struct JournalBlockReader<'a, S: ?Sized> {
    pub store: &'a S,
    pub scope: BlockScope,
}

/// Derive all initial external data lanes from the exact admitted package and
/// canonical Create intent, before a post-Create genesis commitment exists.
/// This checks declared placement and package identity, not receipt authority or
/// finality. It neither executes Create nor permits genesis publication.
pub(crate) fn journal_create_state_work(
    runtime: &super::package_admission::AdmittedStateRuntimePackage,
    create: &ReplayInput,
    replica: crate::agent_sdk::AgentReplica,
) -> Result<crate::agent_sdk::state_execution::StateExecutionWork, JournalStoreError> {
    use crate::agent_sdk::{
        ManagementRequest, StateLane,
        state_execution::{ExternalLaneWork, StateExecutionWork},
    };
    create
        .validate()
        .map_err(|_| JournalStoreError::NonCanonical)?;
    let super::journal::ReplayOperation::CleanManage {
        request: ManagementRequest::Create(descriptor),
        ..
    } = &create.operation
    else {
        return Err(JournalStoreError::NonCanonical);
    };
    let expected = runtime
        .binding(create.runtime.space, create.runtime.agent)
        .map_err(|_| JournalStoreError::NonCanonical)?;
    if expected != create.runtime
        || descriptor.runtime_contract != runtime.manifest().contract
        || descriptor.capabilities != runtime.manifest().capabilities
        || !descriptor.replicas.contains(&replica)
    {
        return Err(JournalStoreError::ScopeMismatch);
    }
    let before = super::wire::RuntimeState::default();
    let work = super::replay::canonical_clean_runtime_work(create, &before)
        .ok_or(JournalStoreError::Unavailable)?;
    let mut lanes = Vec::new();
    for (lane, sdk_lane) in [
        (PersistedLane::Linear, StateLane::Linear),
        (PersistedLane::Merge, StateLane::Merge),
        (PersistedLane::Local, StateLane::Local),
    ] {
        if !runtime.manifest().capabilities.lanes.contains(sdk_lane) {
            continue;
        }
        let node = (lane == PersistedLane::Local).then_some(crate::service::NodeId(replica.node.0));
        let context = initial_root_context(create, lane, node)
            .map_err(|_| JournalStoreError::ScopeMismatch)?;
        lanes.push(ExternalLaneWork {
            base: StateRootDescriptor::new(context, None),
            next: context,
        });
    }
    StateExecutionWork::new(work, lanes, runtime.external_state_limits())
        .map_err(|_| JournalStoreError::NonCanonical)
}

/// Bind canonical journal work to explicitly declared external-state manifests
/// and independently selected successor cursors. No state-byte magic detection:
/// opaque r19 components remain opaque. The caller must obtain these manifests
/// and cursors from authenticated replay, not from an untrusted guest response.
/// This checks identity and canonical binding, not cursor ancestry, finality or
/// availability, and cannot mint a publication seal.
/// Bootstrap (no prior manifest) and runtime upgrade (conditional successor
/// binding) are not admitted by this adapter yet.
pub(crate) fn journal_state_work_with_limits(
    genesis: &AgentJournalGenesis,
    input: &ReplayInput,
    before: &super::wire::RuntimeState,
    lanes: &[(super::journal::LaneStateManifest, LaneCursor)],
    limits: crate::agent_sdk::contract::ExternalStateResourceLimits,
) -> Result<crate::agent_sdk::state_execution::StateExecutionWork, JournalStoreError> {
    use crate::agent_sdk::state_execution::{ExternalLaneWork, StateExecutionWork};
    if lanes.is_empty() || lanes.len() > 3 {
        return Err(JournalStoreError::LimitExceeded);
    }
    if matches!(
        &input.operation,
        super::journal::ReplayOperation::CleanManage {
            request: crate::agent_sdk::ManagementRequest::Create(_)
                | crate::agent_sdk::ManagementRequest::UpgradeRuntime(_),
            ..
        }
    ) {
        return Err(JournalStoreError::Unavailable);
    }
    input
        .validate()
        .map_err(|_| JournalStoreError::NonCanonical)?;
    let work = super::replay::canonical_clean_runtime_work(input, before)
        .ok_or(JournalStoreError::Unavailable)?;
    let mut external = Vec::with_capacity(lanes.len());
    for (manifest, next_cursor) in lanes {
        manifest
            .validate()
            .map_err(|_| JournalStoreError::NonCanonical)?;
        if manifest.genesis != genesis.id() || manifest.runtime != input.runtime {
            return Err(JournalStoreError::ScopeMismatch);
        }
        let base = manifest
            .external_root
            .as_ref()
            .ok_or(JournalStoreError::Unavailable)?;
        let node = match &manifest.cursor {
            LaneCursor::Local { node, .. } => Some(*node),
            _ => None,
        };
        let expected =
            journal_root_context(genesis, &base.runtime, manifest.lane, node, &base.cursor)
                .map_err(|_| JournalStoreError::ScopeMismatch)?;
        if base.descriptor.context() != expected {
            return Err(JournalStoreError::ScopeMismatch);
        }
        let next = journal_root_context(genesis, &input.runtime, manifest.lane, node, next_cursor)
            .map_err(|_| JournalStoreError::ScopeMismatch)?;
        external.push(ExternalLaneWork {
            base: base.descriptor,
            next,
        });
    }
    StateExecutionWork::new(work, external, limits).map_err(|_| JournalStoreError::NonCanonical)
}

/// Synthetic fixture policy only. Production must pass independently admitted limits.
#[cfg(test)]
pub(crate) fn journal_state_work(
    genesis: &AgentJournalGenesis,
    input: &ReplayInput,
    before: &super::wire::RuntimeState,
    lanes: &[(super::journal::LaneStateManifest, LaneCursor)],
) -> Result<crate::agent_sdk::state_execution::StateExecutionWork, JournalStoreError> {
    journal_state_work_with_limits(
        genesis,
        input,
        before,
        lanes,
        super::package_admission::tests::STATE_FIXTURE_LIMITS,
    )
}

/// Exclusive availability session, not a journal head or an execution permit.
/// The mutable store borrow prevents GC from invalidating the audited base
/// between verification and immutable staging. Audit once at recovery/import;
/// successful steps establish the next available root incrementally. The owner
/// must still publish through exact replay before executing against that root.
/// Dropping this session releases its availability guarantee; the descriptor
/// alone is not a GC pin. No production driver selects this prototype yet.
pub(crate) struct StateBlockStaging<'a, S> {
    store: &'a mut S,
    available: StateRootDescriptor,
}

impl<'a, S: AgentJournalStore> StateBlockStaging<'a, S> {
    /// Resume availability retained by the exclusive replay owner. Unlike an
    /// import/recovery audit this touches no tree blocks. The context is bound
    /// to the exact borrowed seal and store; a checkpoint audit cannot mint it.
    pub(crate) fn from_pinned_publication(
        store: &'a mut S,
        publication: &super::replay::ReplaySealedPublication,
        availability: &super::replay::ExternalCheckpointValidation<'_>,
    ) -> Result<Self, JournalStoreError> {
        if !availability.permits_pinned_base(store.instance_id(), publication)
            || store.heads()?.map(|heads| heads.id()) != Some(publication.expected())
        {
            return Err(JournalStoreError::Conflict);
        }
        let execution = publication
            .external_execution()
            .ok_or(JournalStoreError::NonCanonical)?;
        let lane = execution
            .owning_lane()
            .ok_or(JournalStoreError::Unavailable)?;
        Ok(Self {
            store,
            available: lane.base,
        })
    }

    /// Recovery/import availability audit of an exact journal declaration.
    /// The caller must independently authenticate this manifest's selection,
    /// origin ancestry and replica placement. Stored hashes and available
    /// blocks alone do not establish authority or freshness. Metadata reads
    /// are fixed-count; `budget` bounds the potentially large block traversal.
    /// The exclusive store borrow retains availability until this session ends.
    pub(crate) fn audit_manifest(
        store: &'a mut S,
        expected: &LaneStateManifest,
        budget: &mut ReadBudget,
    ) -> Result<Self, JournalStoreError> {
        expected
            .validate()
            .map_err(|_| JournalStoreError::NonCanonical)?;
        let root = expected
            .external_root
            .as_ref()
            .ok_or(JournalStoreError::NonCanonical)?;
        let genesis = store.genesis()?.ok_or(JournalStoreError::NotInitialized)?;
        if genesis.id() != expected.genesis {
            return Err(JournalStoreError::ScopeMismatch);
        }
        let stored: LaneStateManifest = store
            .get(expected.id())?
            .ok_or(JournalStoreError::MissingObject)?;
        if stored != *expected {
            return Err(JournalStoreError::Corrupt);
        }
        let node = match &root.cursor {
            LaneCursor::Local { node, .. } => Some(*node),
            _ => None,
        };
        let context =
            journal_root_context(&genesis, &root.runtime, expected.lane, node, &root.cursor)
                .map_err(|_| JournalStoreError::ScopeMismatch)?;
        if context != root.descriptor.context() {
            return Err(JournalStoreError::ScopeMismatch);
        }
        let encoded = root.descriptor.encode();
        let (bytes, _, _) = store.load_blob_with_work_limit(
            JournalBlobClass::LaneState,
            &expected.state,
            encoded.len() as u64,
            2,
        )?;
        if bytes.ok_or(JournalStoreError::MissingObject)? != encoded {
            return Err(JournalStoreError::Corrupt);
        }
        Self::audit_base(
            store,
            root.descriptor,
            context,
            root.descriptor.commitment(),
            budget,
        )
    }

    pub(crate) fn audit_base(
        store: &'a mut S,
        base: StateRootDescriptor,
        expected_context: RootContext,
        expected_commitment: Hash,
        budget: &mut ReadBudget,
    ) -> Result<Self, JournalStoreError> {
        let tree = base
            .bind(expected_context, expected_commitment)
            .map_err(|_| JournalStoreError::ScopeMismatch)?;
        tree.audit(
            &mut JournalBlockReader {
                store,
                scope: expected_context.scope(),
            },
            budget,
        )
        .map_err(map_availability_error)?;
        Ok(Self {
            store,
            available: base,
        })
    }

    /// Data availability only. This value must not replace the independently
    /// admitted journal cursor used for authorization or invocation ordering.
    pub(crate) fn available(&self) -> StateRootDescriptor {
        self.available
    }

    /// Stage only the candidate bound to the exact physical execution handoff.
    /// This retains the exclusive availability session across validation and
    /// immutable writes; it does not publish or mint a replay seal. Other lanes
    /// may be declared for reads, but atomic multi-lane writes are not supported.
    pub(crate) fn stage_execution(
        &mut self,
        execution: &super::replay::ReplayExternalExecution,
        budget: &mut ReadBudget,
    ) -> Result<usize, JournalStoreError> {
        let lane = execution
            .owning_lane()
            .ok_or(JournalStoreError::Unavailable)?;
        if lane.base != self.available {
            return Err(JournalStoreError::Conflict);
        }
        match execution.output().changes() {
            [] => {
                // No-op responses retain the base descriptor, even when the
                // work selected a newer potential successor revision.
                if execution
                    .output()
                    .transition()
                    .state
                    .component(lane.base.context().scope().lane())
                    != self.available.encode()
                {
                    return Err(JournalStoreError::ScopeMismatch);
                }
                Ok(0)
            }
            [change] => self.stage_next(change, lane.next, budget),
            _ => Err(JournalStoreError::Unavailable),
        }
    }

    pub(crate) fn stage_next(
        &mut self,
        change: &StateChange,
        expected_next: RootContext,
        budget: &mut ReadBudget,
    ) -> Result<usize, JournalStoreError> {
        if change.base() != self.available.commitment() {
            return Err(JournalStoreError::Conflict);
        }
        change
            .verify_reuse(self.available, expected_next, self, budget)
            .map_err(map_availability_error)?;
        let created = stage_change_blocks(
            self.store,
            change,
            self.available.commitment(),
            expected_next,
        )?;
        // Only fully persisted candidates advance data availability. Failed
        // staging may leave garbage, but retains the prior available base.
        self.available = change.next();
        Ok(created)
    }

    /// Recovery counterpart of staging: require every emitted block to already
    /// exist, then advance the availability cursor without writing anything.
    /// Guest output is not evidence that those bytes survived publication.
    /// A failure preserves the prior cursor; all reads share the caller's
    /// recovery budget. This still does not establish journal authority.
    pub(crate) fn verify_persisted_execution(
        &mut self,
        execution: &super::replay::ReplayExternalExecution,
        budget: &mut ReadBudget,
    ) -> Result<(), JournalStoreError> {
        self.available = verify_persisted_execution(self.available, execution, self, budget)?;
        Ok(())
    }
}

/// Read-only incremental recovery check. The caller must have audited `available`
/// and retained exclusive store ownership since that audit (including through
/// invocation-index borrows). No portable availability capability is returned.
pub(crate) fn verify_persisted_execution(
    available: StateRootDescriptor,
    execution: &super::replay::ReplayExternalExecution,
    reader: &mut impl BlockReader,
    budget: &mut ReadBudget,
) -> Result<StateRootDescriptor, JournalStoreError> {
    let lane = execution
        .owning_lane()
        .ok_or(JournalStoreError::Unavailable)?;
    if lane.base != available {
        return Err(JournalStoreError::Conflict);
    }
    let change = match execution.output().changes() {
        [] => {
            if execution
                .output()
                .transition()
                .state
                .component(lane.base.context().scope().lane())
                != available.encode()
            {
                return Err(JournalStoreError::ScopeMismatch);
            }
            return Ok(available);
        }
        [change] => change,
        _ => return Err(JournalStoreError::Unavailable),
    };
    change
        .verify_reuse(available, lane.next, reader, budget)
        .map_err(map_availability_error)?;
    for (reference, expected) in change.blocks() {
        // Charge before allocation and I/O, including failed reads. The
        // permit independently verifies the scoped persisted payload.
        let permit = budget
            .begin_fetch(lane.next.scope(), *reference)
            .map_err(|error| map_availability_error(error.into()))?;
        let mut bytes = vec![0; reference.byte_len() as usize];
        let present = reader
            .read(*reference, &mut bytes)
            .map_err(map_availability_error)?;
        let actual = permit
            .verify(present.then_some(bytes.as_slice()))
            .map_err(|error| map_availability_error(error.into()))?;
        if actual != expected {
            return Err(JournalStoreError::Corrupt);
        }
    }
    Ok(change.next())
}

impl<S: AgentJournalStore> BlockReader for StateBlockStaging<'_, S> {
    fn read(&mut self, reference: BlockRef, output: &mut [u8]) -> Result<bool, TreeError> {
        JournalBlockReader {
            store: self.store,
            scope: self.available.context().scope(),
        }
        .read(reference, output)
    }
}

fn map_availability_error(error: TreeError) -> JournalStoreError {
    match error {
        TreeError::Block(BlockError::BudgetExceeded) => JournalStoreError::LimitExceeded,
        TreeError::Block(BlockError::Unavailable) => JournalStoreError::MissingObject,
        TreeError::Storage => JournalStoreError::Unavailable,
        _ => JournalStoreError::NonCanonical,
    }
}

fn storage_reference(reference: BlockRef) -> crate::service::BlobRef {
    let reference = reference.storage_reference();
    crate::service::BlobRef {
        hash: crate::service::Hash(reference.hash.0),
        len: reference.len,
    }
}

impl<S: ScopedBlockReader + ?Sized> BlockReader for JournalBlockReader<'_, S> {
    fn read(&mut self, reference: BlockRef, output: &mut [u8]) -> Result<bool, TreeError> {
        self.store.read_scoped(self.scope, reference, output)
    }
}

impl<S: AgentJournalStore> ScopedBlockReader for S {
    fn read_scoped(
        &self,
        scope: BlockScope,
        reference: BlockRef,
        output: &mut [u8],
    ) -> Result<bool, TreeError> {
        if output.len() != reference.byte_len() as usize {
            return Err(BlockError::InvalidLength.into());
        }
        let storage = storage_reference(reference);
        // A crash-recovery alias can require checking both the canonical and
        // staged inode. Bound that physical work separately from one logical
        // SDK fetch. The SDK caller charges its budget before invoking us.
        let (envelope, _, _) = self
            .load_blob_with_work_limit(JournalBlobClass::StateBlock, &storage, storage.len * 2, 2)
            .map_err(|_| TreeError::Storage)?;
        let Some(envelope) = envelope else {
            return Ok(false);
        };
        let payload = scope.decode_block(reference, &envelope)?;
        output.copy_from_slice(payload);
        Ok(true)
    }
}

/// Persist the bounded candidate block set using the existing atomic immutable
/// writes. Repeating an exact stage is harmless. Failure can leave unreachable
/// blocks, but never publishes a partial root. Independent bindings prevent
/// accidentally staging a candidate for a different operation; authorization
/// and a complete availability check remain the replay coordinator's job.
/// This low-level writer is also used by corruption/codec fixtures; normal
/// external-state staging must use `StateBlockStaging` to check reachability.
pub(crate) fn stage_change_blocks(
    store: &mut impl AgentJournalStore,
    change: &StateChange,
    expected_base: Hash,
    expected_next: RootContext,
) -> Result<usize, JournalStoreError> {
    change
        .validate_context(expected_base, expected_next)
        .map_err(|_| JournalStoreError::ScopeMismatch)?;
    let mut created = 0;
    for (reference, bytes) in change.blocks() {
        let (actual, envelope) = expected_next
            .scope()
            .encode_block(bytes)
            .map_err(|_| JournalStoreError::NonCanonical)?;
        if actual != *reference {
            return Err(JournalStoreError::NonCanonical);
        }
        created += usize::from(store.put_blob(
            JournalBlobClass::StateBlock,
            &storage_reference(*reference),
            &envelope,
        )?);
    }
    Ok(created)
}
