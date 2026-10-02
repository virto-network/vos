//! Thin, explicitly selected external Shared catch-up. Preparation copies only
//! authenticated immutable content. ACX1 is retained only after both physical
//! endpoints are complete; restart therefore needs neither a foreign archive
//! locator nor a scratch-owner epoch.

use super::super::journal::JournalHeads;
use super::super::journal_store::{ExternalArchiveLimits, StagedExternalArchive};
use super::super::local_journal_driver::StandardLocalReplayExecutor;
use super::super::replay::{NoPrunedOrderedBases, ReplaySealedExternalGenesis};
use super::super::shared_recovery::SharedRecoveryManifest;
use super::*;

const MAX_EXTERNAL_COMMON_RESTORE_BYTES: usize =
    super::super::shared_commit::MAX_SHARED_AGENT_COMMON_SNAPSHOT_CERTIFICATE_BYTES
        + super::super::shared_commit::MAX_SHARED_AGENT_LOCAL_SNAPSHOT_BINDING_BYTES
        + super::super::shared_recovery::MAX_SHARED_RECOVERY_MANIFEST_BYTES
        + 2 * MAX_JOURNAL_RECORD_BYTES
        + 4096;

/// This is destination recovery authority, not a portable source image or an
/// ACL1 same-boundary compaction. Source authenticity has already been checked
/// before the immutable target closure and this separately signed binding are
/// retained. Every restart repeats destination QC/root/ledger validation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct ExternalCommonRestoreRecord {
    pub(super) intent: Hash,
    pub(super) certificate: SharedAgentCommonSnapshotCertificate,
    pub(super) binding: SharedAgentLocalSnapshotBinding,
    pub(super) predecessor: JournalHeads,
    pub(super) target: JournalHeads,
    recovery: Option<SharedRecoveryManifest>,
}

fn validate_recovery_baseline(
    certificate: &SharedAgentCommonSnapshotCertificate,
    recovery: Option<&SharedRecoveryManifest>,
) -> Result<(), SharedAgentHostError> {
    match (certificate.claim().recovery_manifest(), recovery) {
        (None, None) => Ok(()),
        (Some(expected), Some(manifest)) => {
            let ordered = certificate.claim().ordered();
            let generation = AgentGenerationRouteKey::new(
                ordered.space(),
                ordered.agent(),
                ordered.genesis(),
                ordered.admission(),
            )
            .map_err(|_| SharedAgentHostError::SnapshotCertificateInvalid)?;
            manifest
                .validate_at_raft_index(ordered.raft_index())
                .map_err(|_| SharedAgentHostError::SnapshotCertificateInvalid)?;
            if manifest.generation() != generation
                || manifest.committee() != certificate.claim().active_committee()
                || manifest.commitment() != expected
            {
                return Err(SharedAgentHostError::SnapshotCertificateInvalid);
            }
            Ok(())
        }
        // No uncertified retained management body is admitted.
        _ => Err(SharedAgentHostError::SnapshotCertificateInvalid),
    }
}

fn persisted_live_recovery(recovery: &SharedRecoveryManifest) -> Option<&SharedRecoveryManifest> {
    (!recovery.is_empty()).then_some(recovery)
}

fn corrupt_restore_at(phase: &'static str, error: impl std::fmt::Debug) -> SharedAgentHostError {
    tracing::debug!(phase, ?error, "External Shared checkpoint restore refused");
    #[cfg(test)]
    if std::env::var_os("VOS_TEST_BOOTSTRAP_DIAGNOSTICS").is_some() {
        eprintln!("external_shared_restore phase={phase} error={error:?}");
    }
    SharedAgentHostError::CorruptResidue
}

impl ExternalCommonRestoreRecord {
    fn validate(&self) -> Result<(), SharedAgentHostError> {
        self.predecessor
            .validate_successor(&self.target)
            .map_err(|_| SharedAgentHostError::CorruptResidue)?;
        let claim = self.binding.claim();
        if self.intent == Hash::ZERO
            || claim.journal_heads() != self.target.id()
            || claim.checkpoint_predecessor() != self.predecessor.id()
            || self.target.checkpoint != Some(claim.checkpoint())
            || self.target.node != claim.local_node()
            || self.target.genesis != claim.ordered().genesis()
            || self.target.admission != claim.ordered().admission()
            || self.target.ordered_index != claim.ordered().ordered().index
            || self.target.ordered_head != claim.ordered().ordered().head
            || self.predecessor.ordered_index > self.target.ordered_index
            || self.encode().len() > MAX_EXTERNAL_COMMON_RESTORE_BYTES
        {
            return Err(SharedAgentHostError::CorruptResidue);
        }
        self.binding
            .verify(&self.certificate, claim)
            .map_err(|_| SharedAgentHostError::SnapshotCertificateInvalid)?;
        validate_recovery_baseline(&self.certificate, self.recovery.as_ref())
    }

    fn recovery_manifest(&self) -> Result<SharedRecoveryManifest, SharedAgentHostError> {
        self.validate()?;
        if let Some(recovery) = &self.recovery {
            return Ok(recovery.clone());
        }
        let ordered = self.certificate.claim().ordered();
        let generation = AgentGenerationRouteKey::new(
            ordered.space(),
            ordered.agent(),
            ordered.genesis(),
            ordered.admission(),
        )
        .map_err(|_| SharedAgentHostError::SnapshotCertificateInvalid)?;
        SharedRecoveryManifest::new(
            generation,
            self.certificate.claim().active_committee().clone(),
        )
        .map_err(|_| SharedAgentHostError::SnapshotCertificateInvalid)
    }
}

impl ServiceWire for ExternalCommonRestoreRecord {
    const MAGIC: [u8; 4] = *b"ACX1";

    fn encode_body(&self, output: &mut Vec<u8>) {
        let mut encoder = Encoder(output);
        encoder.fixed(&self.intent.0);
        encoder.bytes(&self.certificate.encode());
        encoder.bytes(&self.binding.encode());
        encoder.bytes(&self.predecessor.encode());
        encoder.bytes(&self.target.encode());
        match &self.recovery {
            None => encoder.u8(0),
            Some(manifest) => {
                encoder.u8(1);
                encoder.bytes(&manifest.encode());
            }
        }
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        if decoder.remaining() > MAX_EXTERNAL_COMMON_RESTORE_BYTES {
            return Err(DecodeError::LimitExceeded);
        }
        let record = Self {
            intent: Hash(decoder.fixed()?),
            certificate: decode_common_field(
                decoder,
                super::super::shared_commit::MAX_SHARED_AGENT_COMMON_SNAPSHOT_CERTIFICATE_BYTES,
            )?,
            binding: decode_common_field(
                decoder,
                super::super::shared_commit::MAX_SHARED_AGENT_LOCAL_SNAPSHOT_BINDING_BYTES,
            )?,
            predecessor: decode_common_field(decoder, MAX_JOURNAL_RECORD_BYTES)?,
            target: decode_common_field(decoder, MAX_JOURNAL_RECORD_BYTES)?,
            recovery: match decoder.u8()? {
                0 => None,
                1 => Some(decode_common_field(
                    decoder,
                    super::super::shared_recovery::MAX_SHARED_RECOVERY_MANIFEST_BYTES,
                )?),
                _ => return Err(DecodeError::InvalidTag),
            },
        };
        record.validate().map_err(|_| DecodeError::NonCanonical)?;
        Ok(record)
    }
}

impl SharedAgentHost {
    /// Candidate-only catch-up of an existing, independently finalized and
    /// detached external Linear replica. Scratch remains caller-owned and
    /// unserved. The durable recovery record is installed only after immutable
    /// promotion and complete actual destination endpoint authentication.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn restore_external_common_checkpoint(
        &mut self,
        agent: AgentId,
        staged: &mut StagedExternalArchive,
        source_seal: &ReplaySealedExternalGenesis,
        certificate: &SharedAgentCommonSnapshotCertificate,
        source_binding: &SharedAgentLocalSnapshotBinding,
        recovery: Option<&SharedRecoveryManifest>,
        limits: ExternalArchiveLimits,
    ) -> Result<SharedAgentStatus, SharedAgentHostError> {
        self.require_external_restore_selection(agent)?;
        validate_recovery_baseline(certificate, recovery)?;
        let files = scan_generation_namespaces(&self.lease)?
            .remove(&agent)
            .ok_or(SharedAgentHostError::AgentNotFound)?;
        if let Some(record) = self.read_external_common_restore(agent, files)? {
            if &record.certificate != certificate || record.recovery.as_ref() != recovery {
                return Err(SharedAgentHostError::Conflict);
            }
            self.agents.remove(&agent);
            let finality = Arc::clone(&self.finality);
            let hosted =
                self.resume_external_common_restore(agent, files, &record, finality.as_ref())?;
            let status = status_for(&hosted, false)?;
            retire_host_record(&self.portable_restore_path(agent))?;
            self.agents.insert(agent, hosted);
            return Ok(status);
        }
        if files.intent_stage
            || files.exposed_stage
            || files.portable_restore
            || files.portable_restore_stage
            || !(files.journal
                && files.lock
                && files.intent
                && files.exposed
                && files.raft
                && files.artifacts)
        {
            return Err(SharedAgentHostError::Conflict);
        }
        let hosted = self
            .agents
            .get(&agent)
            .ok_or(SharedAgentHostError::AgentNotFound)?;
        if !hosted.driver.uses_external_state() {
            return Err(SharedAgentHostError::PortableBackupUnsupported);
        }
        let intent = hosted.intent.clone();
        let predecessor = hosted.driver.materialization().heads().clone();
        let (durable_intent, _) = self.read_intent(agent, files)?;
        if durable_intent != intent || !self.read_exposure(agent, intent.id(), files)? {
            return Err(SharedAgentHostError::CorruptResidue);
        }
        let sealed = self.verify_and_prepare(&intent)?;
        self.require_common_snapshot_genesis(&intent, &sealed)?;
        let PreparedSharedGenesis::ExternalAuthorityFinalized(external) = &sealed else {
            return Err(SharedAgentHostError::PortableBackupUnsupported);
        };
        source_seal
            .validate_seal()
            .map_err(|_| SharedAgentHostError::InvalidProvision)?;
        if !source_seal.is_shared()
            || source_seal.genesis().id() != external.genesis().id()
            || source_seal.admission_record().map(|record| record.id())
                != external.admission_record().map(|record| record.id())
            || source_seal.artifacts() != external.artifacts()
            || certificate.claim().active_committee() != intent.committee()
            || certificate.claim().authority_epoch() != intent.committee_authority.initial_epoch()
        {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        certificate
            .verify(intent.committee(), certificate.claim())
            .map_err(|_| SharedAgentHostError::SnapshotCertificateInvalid)?;
        source_binding
            .verify(certificate, source_binding.claim())
            .map_err(|_| SharedAgentHostError::SnapshotCertificateInvalid)?;
        self.common_snapshot_initial_state(agent)?;
        let hosted = self
            .agents
            .get(&agent)
            .ok_or(SharedAgentHostError::AgentNotFound)?;
        if let Some((installed, binding, baseline, _)) = hosted
            .driver
            .ledger()
            .common_snapshot_authority_with_recovery()
            .map_err(map_ledger_error)?
            && &installed == certificate
        {
            // Equality is harmless only at the exact physical installed
            // boundary; a matching QC never excuses a later local suffix.
            hosted
                .driver
                .ledger()
                .validate_bound_common_restore(certificate, &binding)
                .map_err(map_ledger_error)?;
            if binding.claim().journal_heads() != predecessor.id() || baseline.as_ref() != recovery
            {
                return Err(SharedAgentHostError::SnapshotCertificateInvalid);
            }
            return status_for(hosted, false);
        }

        // Stop the process-only serving owner before opening the actual locked
        // store. A failed preparation remains fail-closed; it cannot retain a
        // stale pin or keep advancing a partially copied predecessor.
        drop(
            self.agents
                .remove(&agent)
                .ok_or(SharedAgentHostError::AgentNotFound)?,
        );
        let (journal_parent, authority_parent) = self
            .lease
            .clone_generation_parents()
            .map_err(map_outer_lease_error)?;
        let slot = FileLocalAgentJournalSlot::acquire_with_pinned_parents(
            self.journal_path(agent),
            self.journal_lock_path(agent),
            self.scope().node,
            intent.id(),
            &journal_parent,
            &authority_parent,
        )
        .map_err(|error| corrupt_restore_at("prepare_slot", error))?;
        let ledger = self.open_generation_ledger(&intent, &sealed, slot.instance_id(), true)?;
        ledger
            .validate_common_restore(certificate)
            .map_err(map_ledger_error)?;
        let installed = ledger
            .common_snapshot_authority()
            .map_err(map_ledger_error)?;
        let (mut store, mut executor, _) = slot
            .open_external_shared_checkpoint_with_executor(
                external,
                |store| {
                    if store.instance_id() != ledger.journal_store() {
                        return Err(super::super::journal_store::JournalStoreError::ScopeMismatch);
                    }
                    Ok((
                        StandardLocalReplayExecutor::new_shared(
                            store.catalog_blob_resolver()?,
                            Arc::clone(&self.trust),
                            Arc::clone(&self.merge),
                            ledger.committee_history().map_err(|_| {
                                super::super::journal_store::JournalStoreError::Corrupt
                            })?,
                        ),
                        installed,
                    ))
                },
                &NoPrunedOrderedBases,
                &mut FileSharedDriver::external_recovery_budget(),
                None,
            )
            .map_err(|error| corrupt_restore_at("prepare_open", error))?;
        if store
            .heads()
            .map_err(|_| SharedAgentHostError::CorruptResidue)?
            .as_ref()
            != Some(&predecessor)
        {
            return Err(SharedAgentHostError::CorruptResidue);
        }
        let source_node = source_binding.claim().local_node();
        let mut source_executor = StandardLocalReplayExecutor::new_shared(
            staged
                .catalog_blob_resolver()
                .map_err(|_| SharedAgentHostError::CorruptResidue)?,
            Arc::clone(&self.trust),
            Arc::new(CommonSnapshotReadOnlyNode(source_node)),
            vec![intent.committee().clone()],
        );
        let report = staged.report().clone();
        let source = staged
            .with_source_view(|view| {
                super::super::replay::audit_external_archive_source(
                    view,
                    source_seal,
                    &report.source_heads,
                    report.source_predecessor.as_ref(),
                    &mut source_executor,
                    &NoPrunedOrderedBases,
                    certificate,
                    source_binding,
                    &mut FileSharedDriver::external_recovery_budget(),
                )
            })
            .map_err(|_| SharedAgentHostError::PortableBackupInvalid)?;
        let rebound = super::super::shared_journal_driver::preflight_external_common_rebind(
            source,
            staged,
            external,
            &store,
            &predecessor,
        )
        .map_err(map_driver_error)?;
        staged
            .promote_authenticated_source(
                source_seal,
                external,
                &rebound,
                &mut store,
                limits,
                &mut FileSharedDriver::external_recovery_budget(),
            )
            .map_err(map_driver_error)?;
        rebound
            .stage_metadata(staged, &mut store, external)
            .map_err(map_driver_error)?;
        super::super::replay::validate_external_checkpoint_heads(
            &mut store,
            rebound.heads(),
            &mut FileSharedDriver::external_recovery_budget(),
        )
        .map_err(|error| corrupt_restore_at("prepare_target_roots", error))?;
        let foundation = ledger
            .common_restore_foundation(certificate)
            .map_err(map_ledger_error)?;
        let claim = rebound
            .physical_claim(&foundation)
            .map_err(map_driver_error)?;
        let candidate = VerifiedSharedAgentLocalSnapshotCandidate::from_reconstructed(
            certificate.commitment(),
            claim,
        );
        let signature = self
            .merge
            .sign_local_snapshot_candidate(&candidate)
            .ok_or(SharedAgentHostError::SnapshotCertificateInvalid)?;
        let binding = SharedAgentLocalSnapshotBinding::new(
            certificate.commitment(),
            candidate.claim().clone(),
            signature,
        )
        .map_err(|_| SharedAgentHostError::SnapshotCertificateInvalid)?;
        let record = ExternalCommonRestoreRecord {
            intent: intent.id(),
            certificate: certificate.clone(),
            binding,
            predecessor,
            target: rebound.heads().clone(),
            recovery: recovery.cloned(),
        };
        record.validate().map_err(|error| {
            corrupt_restore_at("prepare_record", &error);
            error
        })?;
        ledger
            .validate_bound_common_restore(&record.certificate, &record.binding)
            .map_err(map_ledger_error)?;
        // Full actual predecessor+target replay precedes marker installation,
        // not merely the unsigned metadata plan or source content proof.
        drop(
            super::super::replay::audit_external_common_restore(
                &mut store,
                external,
                &record.predecessor,
                &record.target,
                &mut executor,
                &NoPrunedOrderedBases,
                &record.certificate,
                &record.binding,
                &mut FileSharedDriver::external_recovery_budget(),
            )
            .map_err(|error| corrupt_restore_at("prepare_endpoint_audit", error))?,
        );
        self.lease.validate_live().map_err(map_outer_lease_error)?;
        install_host_record(&self.portable_restore_path(agent), &record.encode())?;
        // The catalog resolver retains a clone of the stable lock descriptor.
        // Release the old replay owner as well as the store before reacquiring
        // this exact destination slot for marker-driven recovery.
        drop(executor);
        drop(store);
        drop(ledger);
        #[cfg(test)]
        self.common_checkpoint_crash_at(CommonCheckpointCrashStage::Marker)?;
        let files = scan_generation_namespaces(&self.lease)?
            .remove(&agent)
            .ok_or(SharedAgentHostError::CorruptResidue)?;
        let finality = Arc::clone(&self.finality);
        let hosted =
            self.resume_external_common_restore(agent, files, &record, finality.as_ref())?;
        let status = status_for(&hosted, false)?;
        retire_host_record(&self.portable_restore_path(agent))?;
        self.agents.insert(agent, hosted);
        Ok(status)
    }

    fn require_external_restore_selection(
        &mut self,
        agent: AgentId,
    ) -> Result<(), SharedAgentHostError> {
        self.lease.validate_live().map_err(map_outer_lease_error)?;
        if !matches!(
            self.execution_selection,
            SharedExecutionSelection::ExternalLinearCandidates
        ) {
            return Err(SharedAgentHostError::PortableBackupUnsupported);
        }
        if self.transport_leases.contains_key(&agent) {
            return Err(SharedAgentHostError::Conflict);
        }
        Ok(())
    }

    pub(super) fn read_external_common_restore(
        &mut self,
        agent: AgentId,
        files: GenerationFiles,
    ) -> Result<Option<ExternalCommonRestoreRecord>, SharedAgentHostError> {
        if !files.portable_restore && !files.portable_restore_stage {
            return Ok(None);
        }
        let bytes =
            read_host_record_pair(&self.portable_restore_path(agent), MAX_COMMON_RESTORE_BYTES)?
                .ok_or(SharedAgentHostError::CorruptResidue)?;
        if !bytes.starts_with(&ExternalCommonRestoreRecord::MAGIC) {
            return Ok(None);
        }
        self.require_external_restore_selection(agent)?;
        let record = ExternalCommonRestoreRecord::decode(&bytes)
            .map_err(|_| SharedAgentHostError::CorruptResidue)?;
        if record.encode() != bytes
            || record.target.runtime.agent != agent
            || record.target.node != self.scope().node
        {
            return Err(SharedAgentHostError::CorruptResidue);
        }
        Ok(Some(record))
    }

    pub(super) fn resume_external_common_restore(
        &mut self,
        agent: AgentId,
        files: GenerationFiles,
        record: &ExternalCommonRestoreRecord,
        finality: &dyn AgentGenesisFinalityVerifier,
    ) -> Result<HostedSharedAgent, SharedAgentHostError> {
        self.require_external_restore_selection(agent)?;
        record.validate()?;
        let recovery = record.recovery_manifest()?;
        let (intent, _) = self.read_intent(agent, files)?;
        if intent.id() != record.intent
            || intent.agent()? != agent
            || !self.read_exposure(agent, intent.id(), files)?
            || !(files.journal && files.lock && files.raft && files.artifacts)
        {
            return Err(SharedAgentHostError::CorruptResidue);
        }
        let sealed = self.verify_and_prepare_with_finality(&intent, finality)?;
        self.require_common_snapshot_genesis(&intent, &sealed)?;
        let PreparedSharedGenesis::ExternalAuthorityFinalized(external) = &sealed else {
            return Err(SharedAgentHostError::PortableBackupUnsupported);
        };
        let (journal_parent, authority_parent) = self
            .lease
            .clone_generation_parents()
            .map_err(map_outer_lease_error)?;
        let slot = FileLocalAgentJournalSlot::acquire_with_pinned_parents(
            self.journal_path(agent),
            self.journal_lock_path(agent),
            self.scope().node,
            intent.id(),
            &journal_parent,
            &authority_parent,
        )
        .map_err(|error| corrupt_restore_at("resume_slot", error))?;
        if &record.binding.claim().journal_store().0 != slot.instance_id().as_bytes() {
            return Err(SharedAgentHostError::SnapshotCertificateInvalid);
        }
        let ledger = self.open_generation_ledger(&intent, &sealed, slot.instance_id(), true)?;
        // Always check the freshly opened physical ledger, even for an exact
        // installed QC. No marker permits deleting a later local suffix.
        ledger
            .validate_bound_common_restore(&record.certificate, &record.binding)
            .map_err(map_ledger_error)?;
        // Recovery may have loaded a complete stage-only marker after a failed
        // sync. Make its exact inode and directory durable before the certified
        // opener can promote heads.next. Do not rename/retire it on a refusal.
        self.lease.validate_live().map_err(map_outer_lease_error)?;
        sync_host_record_pair(&self.portable_restore_path(agent), &record.encode())?;
        self.lease.validate_live().map_err(map_outer_lease_error)?;
        let installed = ledger
            .common_snapshot_authority()
            .map_err(map_ledger_error)?;
        let (mut store, mut executor, _) = slot
            .open_external_shared_checkpoint_with_executor(
                external,
                |store| {
                    if store.instance_id() != ledger.journal_store() {
                        return Err(super::super::journal_store::JournalStoreError::ScopeMismatch);
                    }
                    Ok((
                        StandardLocalReplayExecutor::new_shared(
                            store.catalog_blob_resolver()?,
                            Arc::clone(&self.trust),
                            Arc::clone(&self.merge),
                            ledger.committee_history().map_err(|_| {
                                super::super::journal_store::JournalStoreError::Corrupt
                            })?,
                        ),
                        installed,
                    ))
                },
                &NoPrunedOrderedBases,
                &mut FileSharedDriver::external_recovery_budget(),
                Some((
                    &record.certificate,
                    &record.binding,
                    &record.predecessor,
                    &record.target,
                )),
            )
            .map_err(|error| corrupt_restore_at("resume_open", error))?;
        super::super::replay::audit_external_common_restore(
            &mut store,
            external,
            &record.predecessor,
            &record.target,
            &mut executor,
            &NoPrunedOrderedBases,
            &record.certificate,
            &record.binding,
            &mut FileSharedDriver::external_recovery_budget(),
        )
        .map_err(|error| corrupt_restore_at("resume_endpoint_audit", error))?
        .publish()
        .map_err(|error| corrupt_restore_at("resume_publication", error))?;
        #[cfg(test)]
        self.common_checkpoint_crash_at(CommonCheckpointCrashStage::Journal)?;
        ledger
            .restore_common_snapshot(&record.certificate, &record.binding, &recovery)
            .map_err(map_ledger_error)?;
        #[cfg(test)]
        self.common_checkpoint_crash_at(CommonCheckpointCrashStage::Ledger)?;
        drop(executor);
        drop(store);
        drop(ledger);
        // A new owner and certified opener, not the pre-ledger replay result,
        // establish serving availability. The caller retires ACX1 only after
        // this succeeds and before inserting the generation into serving.
        let hosted = self
            .open_generation(intent, &sealed, true, files, None)
            .map_err(|error| {
                corrupt_restore_at("resume_certified_owner", &error);
                error
            })?;
        let authority = hosted
            .driver
            .ledger()
            .common_snapshot_authority_with_recovery()
            .map_err(map_ledger_error)?
            .ok_or(SharedAgentHostError::CorruptResidue)?;
        if authority.0 != record.certificate
            || authority.1 != record.binding
            || authority.2 != record.recovery
            // The ledger stores an empty management manifest as absence.
            // Compare that exact persisted
            // representation, not the synthesized restore input. Certified
            // baselines and every nonempty management manifest remain exact.
            || authority.3.as_ref() != persisted_live_recovery(&recovery)
            || hosted.driver.materialization().heads() != &record.target
        {
            #[cfg(test)]
            if std::env::var_os("VOS_TEST_BOOTSTRAP_DIAGNOSTICS").is_some() {
                eprintln!(
                    "external_shared_restore phase=resume_result certificate={} binding={} baseline={} live={} heads={}",
                    authority.0 == record.certificate,
                    authority.1 == record.binding,
                    authority.2 == record.recovery,
                    authority.3.as_ref() == persisted_live_recovery(&recovery),
                    hosted.driver.materialization().heads() == &record.target,
                );
            }
            return Err(SharedAgentHostError::CorruptResidue);
        }
        self.lease.validate_live().map_err(map_outer_lease_error)?;
        Ok(hosted)
    }
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer as _, SigningKey};

    use super::*;
    use crate::agent::journal::{CheckpointId, LaneStateId};

    fn record(certified_recovery: bool) -> ExternalCommonRestoreRecord {
        let mut common = crate::agent::shared_commit::common_snapshot_claim_for_test();
        let generation = AgentGenerationRouteKey::new(
            common.ordered().space(),
            common.ordered().agent(),
            common.ordered().genesis(),
            common.ordered().admission(),
        )
        .unwrap();
        let recovery = certified_recovery.then(|| {
            SharedRecoveryManifest::new(generation, common.active_committee().clone()).unwrap()
        });
        if let Some(manifest) = &recovery {
            common = common
                .with_recovery_manifest(manifest.commitment())
                .unwrap();
        }
        let message = SharedAgentCommonSnapshotCertificate::signing_message(
            common.active_committee().id(),
            common.commitment(),
        );
        let keys = [
            SigningKey::from_bytes(&[1; 32]),
            SigningKey::from_bytes(&[2; 32]),
        ];
        let node = |key: &SigningKey| {
            let mut peer = vec![0x00, 0x24, 0x08, 0x01, 0x12, 0x20];
            peer.extend_from_slice(&key.verifying_key().to_bytes());
            NodeId::of_authenticated_peer(&peer)
        };
        let mut signatures = keys
            .iter()
            .map(|key| {
                ReplicaCommitSignature::new(node(key), key.sign(&message.0).to_bytes()).unwrap()
            })
            .collect::<Vec<_>>();
        signatures.sort_by_key(ReplicaCommitSignature::signer);
        let certificate =
            SharedAgentCommonSnapshotCertificate::new(common.clone(), signatures).unwrap();
        let predecessor = JournalHeads::initial(
            common.ordered().genesis(),
            common.ordered().admission(),
            node(&keys[0]),
            common.ordered().merge_frontier(),
            common.ordered().runtime().clone(),
        );
        let mut target = predecessor.clone();
        target.publication_revision = 1;
        target.previous = Some(predecessor.id());
        target.ordered_index = common.ordered().ordered().index;
        target.ordered_head = common.ordered().ordered().head;
        target.ordered_invocations = common.ordered().ordered_invocations();
        target.merge_invocations = common.ordered().merge_invocations();
        target.checkpoint = Some(CheckpointId([0x71; 32]));
        let claim = SharedAgentSnapshotClaim::new(
            common.ordered().clone(),
            common.active_committee().clone(),
            common.authority_epoch(),
            Hash([0x72; 32]),
            Hash([0x73; 32]),
            target.id(),
            predecessor.id(),
            target.id(),
            target.checkpoint.unwrap(),
            target.node,
            LaneStateId([0x74; 32]),
            LaneStateId([0x75; 32]),
            LaneStateId([0x76; 32]),
            LaneStateId([0x77; 32]),
            target.ordered_invocations,
            target.merge_invocations,
            target.local_invocations,
            common.ordered().artifacts(),
            Hash([0x78; 32]),
            Hash([0x79; 32]),
            None,
        )
        .unwrap();
        let message = SharedAgentLocalSnapshotBinding::signing_message(
            certificate.commitment(),
            claim.commitment(),
            claim.local_node(),
        );
        let binding = SharedAgentLocalSnapshotBinding::new(
            certificate.commitment(),
            claim.clone(),
            ReplicaCommitSignature::new(claim.local_node(), keys[0].sign(&message.0).to_bytes())
                .unwrap(),
        )
        .unwrap();
        ExternalCommonRestoreRecord {
            intent: Hash([0x7a; 32]),
            certificate,
            binding,
            predecessor,
            target,
            recovery,
        }
    }

    #[test]
    fn external_restore_record_roundtrips_exact_endpoints_and_baseline() {
        for certified in [false, true] {
            let record = record(certified);
            record.validate().unwrap();
            let bytes = record.encode();
            assert_eq!(&bytes[..4], b"ACX1");
            assert_eq!(ExternalCommonRestoreRecord::decode(&bytes).unwrap(), record);
            let baseline = record.recovery_manifest().unwrap();
            assert!(baseline.is_empty());
            assert!(baseline.management_slots().is_empty());
            assert_eq!(CommonInstallRecord::decode(&bytes).is_err(), true);
            assert_eq!(CommonRestoreRecord::decode(&bytes).is_err(), true);
        }
    }

    #[test]
    fn external_restore_live_recovery_uses_only_management_scope_presence() {
        let empty = record(false).recovery_manifest().unwrap();
        assert_eq!(persisted_live_recovery(&empty), None);
        let retained =
            super::super::super::shared_recovery::completed_management_manifest_for_test();
        assert_eq!(persisted_live_recovery(&retained), Some(&retained));
        for retired in [*b"RMF1", *b"RMF2", *b"RMF3"] {
            let mut bytes = empty.encode();
            bytes[..4].copy_from_slice(&retired);
            assert!(SharedRecoveryManifest::decode(&bytes).is_err());
        }
    }

    #[test]
    fn external_restore_record_rejects_substituted_endpoints_and_ambiguous_bytes() {
        let original = record(false);
        let mut altered = original.clone();
        altered.target.ordered_head =
            Some(super::super::super::journal::OrderedEntryId([0x7b; 32]));
        assert!(altered.validate().is_err());
        assert!(ExternalCommonRestoreRecord::decode(&altered.encode()).is_err());
        let mut altered = original.clone();
        altered.predecessor.node = NodeId([0x7c; 32]);
        assert!(altered.validate().is_err());
        let mut bytes = original.encode();
        bytes.push(0);
        assert!(ExternalCommonRestoreRecord::decode(&bytes).is_err());
        let mut bytes = original.encode();
        bytes[..4].copy_from_slice(b"ACL1");
        assert!(ExternalCommonRestoreRecord::decode(&bytes).is_err());
    }

    #[test]
    fn external_restore_record_requires_the_exact_certified_manifest_body() {
        let mut uncertified = record(false);
        let empty = uncertified.recovery_manifest().unwrap();
        uncertified.recovery = Some(empty);
        assert!(uncertified.validate().is_err());
        let mut missing = record(true);
        missing.recovery = None;
        assert!(missing.validate().is_err());
        let mut substituted = record(true);
        let generation = substituted.recovery.as_ref().unwrap().generation();
        let foreign = AgentGenerationRouteKey::new(
            generation.space(),
            generation.agent(),
            super::super::super::journal::AgentJournalGenesisId([0x7d; 32]),
            generation.admission(),
        )
        .unwrap();
        substituted.recovery = Some(
            SharedRecoveryManifest::new(
                foreign,
                substituted.certificate.claim().active_committee().clone(),
            )
            .unwrap(),
        );
        assert!(substituted.validate().is_err());
    }
}
