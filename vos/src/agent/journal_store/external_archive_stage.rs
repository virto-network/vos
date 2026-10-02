//! Detached, unexposed disk quarantine for a streamed storage closure.
//!
//! A successful stage establishes rooted storage integrity only. It is not
//! foreign common-checkpoint authority, a destination binding, a serving pin,
//! or permission to publish any decoded source heads.

use super::*;
use std::io::Read;

const STAGE_DOMAIN: &[u8] = b"vos/agent/external-journal-archive-stage/v1";

/// Bind a fresh scratch lock to one independently admitted source genesis and
/// one selected source head. The fresh scratch stable lock durably binds this
/// selection; its caller-owned parent must be a private quarantine, never a
/// live Agent root.
pub(crate) fn external_archive_stage_intent(
    genesis: &super::super::replay::ReplaySealedExternalGenesis,
    expected_source_heads: JournalHeadsId,
) -> Result<Hash, JournalStoreError> {
    if !genesis.is_shared() || expected_source_heads == JournalHeadsId::ZERO {
        return Err(JournalStoreError::ScopeMismatch);
    }
    let initial = genesis
        .initial_heads()
        .map_err(|_| JournalStoreError::NonCanonical)?;
    Ok(Hash::digest(
        STAGE_DOMAIN,
        &[
            genesis.genesis().id().as_bytes(),
            initial.node.as_bytes(),
            expected_source_heads.as_bytes(),
        ],
    ))
}

pub(super) fn validate_fresh_stage_slot(
    slot: &FileLocalAgentJournalSlot,
    agent: AgentId,
    node: NodeId,
    intent: Hash,
) -> Result<(), JournalStoreError> {
    if slot.generation_exists() || slot.exposure_committed {
        return Err(JournalStoreError::Conflict);
    }
    if slot.intent() != intent || slot.agent() != agent || slot.node() != node {
        return Err(JournalStoreError::ScopeMismatch);
    }
    slot.verify_absent()
}

pub(super) fn validate_resume_stage_slot(
    slot: &FileLocalAgentJournalSlot,
    initial: &JournalHeads,
    intent: Hash,
) -> Result<(), JournalStoreError> {
    if !slot.generation_exists() || slot.exposure_committed {
        return Err(JournalStoreError::Conflict);
    }
    if slot.intent() != intent
        || slot.agent() != initial.runtime.agent
        || slot.node() != initial.node
    {
        return Err(JournalStoreError::ScopeMismatch);
    }
    slot.verify_lock()?;
    let name = slot
        .root_name
        .to_str()
        .map_err(|_| JournalStoreError::InvalidPath)?;
    let directory = open_directory_at(slot.journal_parent.get()?, name)?;
    validate_owned_directory(&directory)?;
    let bytes = read_pinned_bounded_regular_at(
        &directory,
        "heads",
        class_maximum(JournalStorageClass::Heads),
    )?
    .ok_or(JournalStoreError::Conflict)?;
    let current = decode_object::<JournalHeads>(&bytes, initial.id())?;
    if current != *initial
        || stat_at(&directory, &c_name("heads.next")?)
            .map_err(|_| JournalStoreError::Unavailable)?
            .is_some()
    {
        return Err(JournalStoreError::Conflict);
    }
    slot.verify_lock()
}

fn validate_genesis_catalog(
    genesis: &super::super::replay::ReplaySealedExternalGenesis,
    catalog: &[super::super::execution::RuntimeBlob],
) -> Result<(), JournalStoreError> {
    if catalog.len() != genesis.artifacts().artifacts.len()
        || catalog.len() > MAX_ARTIFACT_CLOSURE_ENTRIES
    {
        return Err(JournalStoreError::ScopeMismatch);
    }
    let mut seen = BTreeSet::new();
    for blob in catalog {
        validate_supplied_blob(
            JournalBlobClass::CatalogArtifact,
            &blob.reference,
            &blob.bytes,
        )?;
        if !genesis.artifacts().artifacts.contains(&blob.reference)
            || !seen.insert(blob.reference.hash)
        {
            return Err(JournalStoreError::ScopeMismatch);
        }
    }
    Ok(())
}

fn stage_archive_records<R: Read>(
    store: &mut FileAgentJournalStore,
    input: &mut R,
    expected_source_heads: JournalHeadsId,
    limits: ExternalArchiveLimits,
) -> Result<ExternalArchiveReport, JournalStoreError> {
    read_external_archive(
        input,
        expected_source_heads,
        limits,
        |record| match record {
            ExternalArchiveRecord::Object { class, id, bytes } => {
                if matches!(
                    class,
                    JournalStorageClass::Heads | JournalStorageClass::Genesis
                ) {
                    return Err(JournalStoreError::InvalidClass);
                }
                store.persist_portable_object_bytes(class, id, bytes)
            }
            ExternalArchiveRecord::Blob {
                class,
                reference,
                bytes,
            } => store.persist_blob(class, reference, bytes).map(|_| ()),
        },
    )
}

/// Owns a real descriptor-pinned scratch store. Neither that mutable store nor
/// its exposure/publication methods escape this type. Error paths can leave
/// immutable residue in this exact quarantine; cleanup is separately scoped.
pub(crate) struct StagedExternalArchive {
    store: FileAgentJournalStore,
    report: ExternalArchiveReport,
    genesis: AgentJournalGenesisId,
    initial: JournalHeadsId,
}

impl StagedExternalArchive {
    pub(crate) fn read<R: Read>(
        slot: FileLocalAgentJournalSlot,
        genesis: &super::super::replay::ReplaySealedExternalGenesis,
        catalog: &[super::super::execution::RuntimeBlob],
        expected_source_heads: JournalHeadsId,
        limits: ExternalArchiveLimits,
        budget: &mut crate::agent_sdk::state_blocks::ReadBudget,
        input: &mut R,
    ) -> Result<Self, JournalStoreError> {
        limits.validate()?;
        let intent = external_archive_stage_intent(genesis, expected_source_heads)?;
        let initial = genesis
            .initial_heads()
            .map_err(|_| JournalStoreError::NonCanonical)?;
        validate_fresh_stage_slot(
            &slot,
            genesis.genesis().runtime().agent,
            initial.node,
            intent,
        )?;
        // Seed only the seal's exact admitted genesis artifact closure. Later
        // archive catalog entries are inert content until the complete mark
        // and the caller's independent source authority both validate.
        validate_genesis_catalog(genesis, catalog)?;
        let mut store = slot.open_external_genesis(genesis, false, budget)?;
        for blob in catalog {
            store.put_blob(
                JournalBlobClass::CatalogArtifact,
                &blob.reference,
                &blob.bytes,
            )?;
        }
        store.initialize_external_local(genesis, budget)?;
        let report = stage_archive_records(&mut store, input, expected_source_heads, limits)?;
        if store.heads()?.as_ref() != Some(&initial) {
            return Err(JournalStoreError::Conflict);
        }
        let staged = Self {
            store,
            report,
            genesis: genesis.genesis().id(),
            initial: initial.id(),
        };
        staged.audit_closure(genesis, limits, budget)?;
        Ok(staged)
    }

    /// Reacquire only the same initialized, unexposed quarantine. Canonical
    /// input is replayed into immutable storage idempotently, and identity and
    /// complete closure are rechecked; no saved availability survives reopening.
    pub(crate) fn resume<R: Read>(
        slot: FileLocalAgentJournalSlot,
        genesis: &super::super::replay::ReplaySealedExternalGenesis,
        catalog: &[super::super::execution::RuntimeBlob],
        expected_source_heads: JournalHeadsId,
        expected_archive_identity: Hash,
        limits: ExternalArchiveLimits,
        budget: &mut crate::agent_sdk::state_blocks::ReadBudget,
        input: &mut R,
    ) -> Result<Self, JournalStoreError> {
        limits.validate()?;
        if expected_archive_identity == Hash::ZERO {
            return Err(JournalStoreError::ScopeMismatch);
        }
        let intent = external_archive_stage_intent(genesis, expected_source_heads)?;
        let initial = genesis
            .initial_heads()
            .map_err(|_| JournalStoreError::NonCanonical)?;
        validate_resume_stage_slot(&slot, &initial, intent)?;
        validate_genesis_catalog(genesis, catalog)?;
        let mut store = slot.open_external_genesis(genesis, false, budget)?;
        let report = stage_archive_records(&mut store, input, expected_source_heads, limits)?;
        if report.identity != expected_archive_identity {
            return Err(JournalStoreError::ScopeMismatch);
        }
        let staged = Self {
            store,
            report,
            genesis: genesis.genesis().id(),
            initial: initial.id(),
        };
        staged.audit_closure(genesis, limits, budget)?;
        Ok(staged)
    }

    fn audit_closure(
        &self,
        genesis: &super::super::replay::ReplaySealedExternalGenesis,
        limits: ExternalArchiveLimits,
        budget: &mut crate::agent_sdk::state_blocks::ReadBudget,
    ) -> Result<(), JournalStoreError> {
        self.with_audited_mark(genesis, limits, budget, |_, _| Ok(()))
    }

    fn with_audited_mark<T>(
        &self,
        genesis: &super::super::replay::ReplaySealedExternalGenesis,
        limits: ExternalArchiveLimits,
        budget: &mut crate::agent_sdk::state_blocks::ReadBudget,
        action: impl FnOnce(&mut ExternalArchiveSourceView<'_>, &GcMark) -> Result<T, JournalStoreError>,
    ) -> Result<T, JournalStoreError> {
        limits.validate()?;
        if self.report.objects > limits.max_objects as u64
            || self.report.blobs > limits.max_blobs as u64
            || self.report.history_nodes > limits.max_history_nodes as u64
            || self.report.wire_bytes > limits.max_wire_bytes
        {
            return Err(JournalStoreError::LimitExceeded);
        }
        if genesis.genesis().id() != self.genesis {
            return Err(JournalStoreError::ScopeMismatch);
        }
        let mut view = self.source_view()?;
        let heads = self.report.source_heads.clone();
        let result = super::super::replay::with_external_genesis_checkpoint_heads(
            &mut view,
            &heads,
            genesis,
            budget,
            |view, availability| {
                let (_, mut mark) = build_gc_mark_with_availability(
                    view,
                    heads.id(),
                    GcLimits {
                        max_index_nodes: limits.max_objects,
                        max_marked_objects: limits.max_objects,
                        max_marked_blobs: limits.max_blobs,
                        max_scanned_files: 1,
                        max_scanned_bytes: 1,
                        max_unlinks_per_run: 1,
                    },
                    availability,
                )?;
                mark_portable_history(view, &heads, &mut mark, limits.max_history_nodes)?;
                external_archive::validate_external_archive_mark(&self.report, &mark)?;
                action(view, &mark)
            },
        );
        drop(view);
        self.source_view()?;
        result
    }

    /// Re-audit the exact complete closure, then visit one immutable payload
    /// at a time. This remains content only; a live destination must require
    /// its separate opaque source-certificate/rebind capability before copying.
    pub(crate) fn visit_source_closure(
        &mut self,
        genesis: &super::super::replay::ReplaySealedExternalGenesis,
        limits: ExternalArchiveLimits,
        budget: &mut crate::agent_sdk::state_blocks::ReadBudget,
        mut visit: impl FnMut(ExternalArchiveRecord<'_>) -> Result<(), JournalStoreError>,
    ) -> Result<(), JournalStoreError> {
        self.with_audited_mark(genesis, limits, budget, |view, mark| {
            for (class, id) in &mark.objects {
                if matches!(
                    class,
                    JournalStorageClass::Heads | JournalStorageClass::Genesis
                ) {
                    continue;
                }
                let object = read_portable_object(view, *class, *id)?;
                visit(ExternalArchiveRecord::Object {
                    class: *class,
                    id: *id,
                    bytes: &object.bytes,
                })?;
            }
            for ((class, hash), len) in &mark.blobs {
                let reference = BlobRef {
                    hash: *hash,
                    len: *len,
                };
                validate_blob_reference(*class, &reference)?;
                let bytes = view
                    .load_blob(*class, &reference)?
                    .ok_or(JournalStoreError::MissingObject)?;
                validate_supplied_blob(*class, &reference, &bytes)?;
                visit(ExternalArchiveRecord::Blob {
                    class: *class,
                    reference: &reference,
                    bytes: &bytes,
                })?;
            }
            Ok(())
        })
    }

    /// Copy only the authenticated source closure admitted by an opaque rebind
    /// plan. Destination-private empty metadata is independently derived and
    /// staged by that plan, never replaced with foreign Local identifiers.
    #[cfg(feature = "storage")]
    pub(crate) fn promote_authenticated_source(
        &mut self,
        source_genesis: &super::super::replay::ReplaySealedExternalGenesis,
        destination_genesis: &super::super::replay::ReplaySealedExternalGenesis,
        rebound: &super::super::shared_journal_driver::ReboundExternalCommonCheckpoint,
        destination: &mut FileAgentJournalStore,
        limits: ExternalArchiveLimits,
        budget: &mut crate::agent_sdk::state_blocks::ReadBudget,
    ) -> Result<(), super::super::shared_journal_driver::SharedJournalDriverError> {
        rebound.require_current(self, destination, destination_genesis)?;
        if source_genesis.genesis().id() != self.genesis
            || source_genesis
                .initial_heads()
                .map_err(|_| JournalStoreError::NonCanonical)?
                .node
                != self.report.source_heads.node
            || rebound.source_heads() != &self.report.source_heads
        {
            return Err(JournalStoreError::ScopeMismatch.into());
        }
        let source_checkpoint_id = self
            .report
            .source_heads
            .checkpoint
            .ok_or(JournalStoreError::MissingObject)?;
        let source_checkpoint = self.with_source_view(|view| {
            view.get::<CheckpointManifest>(source_checkpoint_id)?
                .ok_or(JournalStoreError::MissingObject)
        })?;
        let source_local = source_checkpoint
            .lanes
            .iter()
            .find(|lane| lane.lane == PersistedLane::Local)
            .ok_or(JournalStoreError::MissingObject)?
            .state;
        let source_local_invocations = self.report.source_heads.local_invocations;
        self.visit_source_closure(source_genesis, limits, budget, |record| match record {
            ExternalArchiveRecord::Object { class, id, bytes } => {
                if (class == JournalStorageClass::Checkpoint && id == source_checkpoint.id().0)
                    || (class == JournalStorageClass::LaneState && id == source_local.0)
                    || (class == JournalStorageClass::InvocationIndex
                        && id == source_local_invocations.0)
                {
                    return Ok(());
                }
                destination.persist_portable_object_bytes(class, id, bytes)
            }
            ExternalArchiveRecord::Blob {
                class,
                reference,
                bytes,
            } => destination
                .persist_blob(class, reference, bytes)
                .map(|_| ()),
        })?;
        rebound.require_current(self, destination, destination_genesis)?;
        Ok(())
    }

    pub(crate) fn report(&self) -> &ExternalArchiveReport {
        &self.report
    }

    pub(crate) fn instance_id(&self) -> JournalStoreInstanceId {
        self.store.instance_id()
    }

    pub(crate) fn validation_epoch(&self) -> u64 {
        self.store.validation_epoch()
    }

    pub(crate) fn genesis_id(&self) -> AgentJournalGenesisId {
        self.genesis
    }

    pub(crate) fn catalog_blob_resolver(
        &self,
    ) -> Result<FileCatalogBlobResolver, JournalStoreError> {
        self.source_view()?;
        self.store.catalog_blob_resolver()
    }

    /// A caller may authenticate the original foreign QC against this view's
    /// selected source bytes, but may not substitute the scratch physical ID
    /// for the certificate's original source ID or mint serving availability.
    pub(crate) fn with_source_view<T>(
        &mut self,
        action: impl FnOnce(&mut ExternalArchiveSourceView<'_>) -> Result<T, JournalStoreError>,
    ) -> Result<T, JournalStoreError> {
        let mut view = self.source_view()?;
        let result = action(&mut view);
        drop(view);
        self.source_view()?;
        result
    }

    fn source_view(&self) -> Result<ExternalArchiveSourceView<'_>, JournalStoreError> {
        self.store.verify_lock()?;
        if self.store.genesis()?.as_ref().map(AgentJournalGenesis::id) != Some(self.genesis) {
            return Err(JournalStoreError::Corrupt);
        }
        if self.store.heads()?.as_ref().map(JournalHeads::id) != Some(self.initial)
            || self
                .store
                .read_fixed::<JournalHeads>("", "heads.next")?
                .is_some()
        {
            return Err(JournalStoreError::Conflict);
        }
        ExternalArchiveSourceView::from_store_report(&self.store, &self.report)
    }
}

/// Two bounded source envelopes over immutable quarantined disk content.
/// Physical identity remains the real scratch owner, and every mutator fails.
pub(crate) struct ExternalArchiveSourceView<'a> {
    store: &'a FileAgentJournalStore,
    report: &'a ExternalArchiveReport,
}

impl<'a> ExternalArchiveSourceView<'a> {
    pub(super) fn from_store_report(
        store: &'a FileAgentJournalStore,
        report: &'a ExternalArchiveReport,
    ) -> Result<Self, JournalStoreError> {
        store.verify_lock()?;
        let genesis = store.genesis()?.ok_or(JournalStoreError::NotInitialized)?;
        if genesis.id() != report.source_heads.genesis
            || genesis.admission != report.source_heads.admission
            || store.node != report.source_heads.node
        {
            return Err(JournalStoreError::ScopeMismatch);
        }
        Ok(Self { store, report })
    }
}

impl InvocationHistoryStore for ExternalArchiveSourceView<'_> {
    type Error = JournalStoreError;
    fn load_history_node(
        &self,
        id: InvocationHistoryNodeId,
    ) -> Result<Option<Vec<u8>>, Self::Error> {
        InvocationHistoryStore::load_history_node(self.store, id)
    }
}

impl AgentJournalStore for ExternalArchiveSourceView<'_> {
    fn instance_id(&self) -> JournalStoreInstanceId {
        self.store.instance_id()
    }
    fn validation_epoch(&self) -> u64 {
        self.store.validation_epoch()
    }
    fn initialize(&mut self, _: &ReplaySealedGenesis) -> Result<bool, JournalStoreError> {
        Err(JournalStoreError::Unavailable)
    }
    fn genesis(&self) -> Result<Option<AgentJournalGenesis>, JournalStoreError> {
        self.store.genesis()
    }
    fn heads(&self) -> Result<Option<JournalHeads>, JournalStoreError> {
        self.store.verify_lock()?;
        Ok(Some(self.report.source_heads.clone()))
    }
    fn historical_heads(
        &self,
        id: JournalHeadsId,
    ) -> Result<Option<JournalHeads>, JournalStoreError> {
        self.store.verify_lock()?;
        if let Some(previous) = &self.report.source_predecessor
            && previous.id() == id
        {
            return Ok(Some(previous.clone()));
        }
        self.store.historical_heads(id)
    }
    fn historical_heads_with_work_limit(
        &self,
        id: JournalHeadsId,
        max_bytes: u64,
        max_fetches: usize,
    ) -> Result<(Option<JournalHeads>, u64, usize), JournalStoreError> {
        if let Some(previous) = &self.report.source_predecessor
            && previous.id() == id
        {
            let bytes = previous.encode().len() as u64;
            if max_fetches == 0 || bytes > max_bytes {
                return Err(JournalStoreError::LimitExceeded);
            }
            self.store.verify_lock()?;
            return Ok((Some(previous.clone()), bytes, 1));
        }
        self.store
            .historical_heads_with_work_limit(id, max_bytes, max_fetches)
    }
    fn finish_reverified_open(&mut self) -> Result<(), JournalStoreError> {
        Err(JournalStoreError::Unavailable)
    }
    fn put<R: CanonicalJournalRecord>(&mut self, _: &R) -> Result<bool, JournalStoreError> {
        Err(JournalStoreError::Unavailable)
    }
    fn get<R: CanonicalJournalRecord>(&self, id: R::Id) -> Result<Option<R>, JournalStoreError> {
        self.store.get(id)
    }
    fn get_with_work_limit<R: CanonicalJournalRecord>(
        &self,
        id: R::Id,
        max_bytes: u64,
        max_fetches: usize,
    ) -> Result<(Option<R>, u64, usize), JournalStoreError> {
        self.store.get_with_work_limit(id, max_bytes, max_fetches)
    }
    fn put_blob(
        &mut self,
        _: JournalBlobClass,
        _: &BlobRef,
        _: &[u8],
    ) -> Result<bool, JournalStoreError> {
        Err(JournalStoreError::Unavailable)
    }
    fn load_blob(
        &self,
        class: JournalBlobClass,
        reference: &BlobRef,
    ) -> Result<Option<Vec<u8>>, JournalStoreError> {
        self.store.load_blob(class, reference)
    }
    fn load_blob_with_work_limit(
        &self,
        class: JournalBlobClass,
        reference: &BlobRef,
        max_bytes: u64,
        max_fetches: usize,
    ) -> Result<(Option<Vec<u8>>, u64, usize), JournalStoreError> {
        self.store
            .load_blob_with_work_limit(class, reference, max_bytes, max_fetches)
    }
    fn load_history_node_with_work_limit(
        &self,
        id: InvocationHistoryNodeId,
        max_bytes: u64,
        max_fetches: usize,
    ) -> Result<(Option<Vec<u8>>, u64, usize), JournalStoreError> {
        self.store
            .load_history_node_with_work_limit(id, max_bytes, max_fetches)
    }
    fn publish(
        &mut self,
        _: &ReplaySealedPublication,
    ) -> Result<JournalPublication, JournalStoreError> {
        Err(JournalStoreError::Unavailable)
    }
}
