//! Recover public member inputs only from an exact, never-opened host intent.
//!
//! This is not a finality verifier or an absent-namespace repair path. The
//! native owner must obtain fresh System evidence before publishing the OGAR.

use super::*;
use crate::agent::genesis::{AgentGenesisArchiveRecord, AgentGenesisLocator};

impl SharedAgentHost {
    /// Actual ordinary namespaces owned by this native lifecycle boundary.
    /// No archive-only ID or remote selector can expand the required set.
    pub(crate) fn recovery_member_agent_ids(
        &mut self,
    ) -> Result<Option<Vec<AgentId>>, SharedAgentHostError> {
        self.lease.validate_live().map_err(map_outer_lease_error)?;
        if !matches!(
            self.execution_selection,
            SharedExecutionSelection::ExternalLinearCandidates
        ) {
            return Ok(None);
        }
        let mut agents = self
            .deferred_generations
            .keys()
            .copied()
            .collect::<Vec<_>>();
        agents.extend(self.agents.iter().filter_map(|(agent, hosted)| {
            matches!(
                hosted.intent.authority,
                SharedGenesisAuthority::AuthorityFinalized(_)
            )
            .then_some(*agent)
        }));
        agents.sort_unstable();
        agents.dedup();
        Ok(Some(agents))
    }

    /// Bind independently leased OGAR inputs to an actual retained generation,
    /// without obtaining finality or opening a deferred namespace.
    pub(crate) fn validate_recovery_member_material(
        &mut self,
        record: &AgentGenesisArchiveRecord,
    ) -> Result<(), SharedAgentHostError> {
        self.lease.validate_live().map_err(map_outer_lease_error)?;
        let agent = record.provision().proposal().locator().agent;
        let descriptor = record
            .provision()
            .proposal()
            .clean_descriptor()
            .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
        let authority = CommitteeChangeAuthorityBinding::new(
            descriptor.authority.policy,
            descriptor.authority.issuer,
            descriptor.identity.runtime_deployment,
            descriptor.authority.public_key,
            descriptor.authority.initial_epoch,
        )
        .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
        let expected = SharedGenesisIntent::new(
            record.provision().clone(),
            record.catalog().to_vec(),
            authority,
        )?;
        if let Some(serving) = self.agents.get(&agent) {
            if serving.intent != expected {
                return Err(SharedAgentHostError::ScopeMismatch);
            }
            return self.lease.validate_live().map_err(map_outer_lease_error);
        }
        let files = self
            .deferred_generations
            .get(&agent)
            .copied()
            .ok_or(SharedAgentHostError::ScopeMismatch)?;
        // Restore-intent selection remains owned by the existing complete-set
        // opener. An ordinary retained intent must already bind exact inputs.
        if files.intent || files.intent_stage {
            if self.read_intent(agent, files)?.0 != expected {
                return Err(SharedAgentHostError::ScopeMismatch);
            }
        } else if self
            .read_portable_restore(agent, files)?
            .is_none_or(|restore| restore.bundle.intent != expected)
        {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        self.lease.validate_live().map_err(map_outer_lease_error)
    }

    /// Validate the retained live admission phase, never repair it. Published
    /// OGAR inputs require an actual namespace; an opened generation requires
    /// its complete serving files and exact durable intent/exposure binding.
    pub(crate) fn preflight_live_member_genesis(
        &mut self,
        record: &AgentGenesisArchiveRecord,
        archived: bool,
    ) -> Result<(), SharedAgentHostError> {
        self.lease.validate_live().map_err(map_outer_lease_error)?;
        let locator = record.provision().proposal().locator();
        if locator.validate().is_err()
            || locator.space != self.scope().space
            || !matches!(
                self.execution_selection,
                SharedExecutionSelection::ExternalLinearCandidates
            )
            || self.deferred_open
        {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        let current = scan_generation_namespaces(&self.lease)?;
        let files = current.get(&locator.agent).copied();
        let serving = self.agents.get(&locator.agent);
        let staged = self.deferred_generations.contains_key(&locator.agent);
        if self.transport_leases.contains_key(&locator.agent) && serving.is_none() {
            return Err(SharedAgentHostError::CorruptResidue);
        }
        validate_live_member_namespace_phase(files, serving.is_some(), staged, archived)?;
        if let Some(files) = files {
            let descriptor = record
                .provision()
                .proposal()
                .clean_descriptor()
                .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
            let authority = CommitteeChangeAuthorityBinding::new(
                descriptor.authority.policy,
                descriptor.authority.issuer,
                descriptor.identity.runtime_deployment,
                descriptor.authority.public_key,
                descriptor.authority.initial_epoch,
            )
            .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
            let expected = SharedGenesisIntent::new(
                record.provision().clone(),
                record.catalog().to_vec(),
                authority,
            )?;
            let (actual, _) = self.read_intent(locator.agent, files)?;
            if actual != expected {
                return Err(SharedAgentHostError::ScopeMismatch);
            }
            if let Some(serving) = serving {
                if serving.intent != actual
                    || !self.read_exposure(locator.agent, actual.id(), files)?
                {
                    return Err(SharedAgentHostError::CorruptResidue);
                }
            }
        }
        self.lease.validate_live().map_err(map_outer_lease_error)
    }

    /// Stage a live member using the existing physical lifecycle. Exact retries
    /// after promotion validate the entire retained intent, not merely an Agent
    /// ID or descriptor, and do not recreate or replace its namespace.
    pub(crate) fn stage_live_member_replay_verified(
        &mut self,
        provision: AgentGenesisProvision,
        catalog: Vec<RuntimeBlob>,
        committee_authority: CommitteeChangeAuthorityBinding,
        finality: &crate::agent::clean_bootstrap::ReplayVerifiedAgentGenesisFinality,
    ) -> Result<(), SharedAgentHostError> {
        self.lease.validate_live().map_err(map_outer_lease_error)?;
        if !matches!(
            self.execution_selection,
            SharedExecutionSelection::ExternalLinearCandidates
        ) || self.deferred_open
        {
            return Err(SharedAgentHostError::Conflict);
        }
        let intent = SharedGenesisIntent::new(provision, catalog, committee_authority)?;
        let agent = intent.agent()?;
        if let Some(existing) = self.agents.get(&agent) {
            if existing.intent != intent {
                return Err(SharedAgentHostError::ScopeMismatch);
            }
            let SharedGenesisAuthority::AuthorityFinalized(provision) = &intent.authority else {
                return Err(SharedAgentHostError::ScopeMismatch);
            };
            finality
                .verify_finalized(provision)
                .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
            self.lease.validate_live().map_err(map_outer_lease_error)?;
            return Ok(());
        }
        let SharedGenesisAuthority::AuthorityFinalized(provision) = intent.authority else {
            return Err(SharedAgentHostError::ScopeMismatch);
        };
        self.stage_live_replay_verified(
            provision,
            intent.catalog,
            intent.committee_authority,
            finality,
        )
    }

    /// Read the durable stage which precedes member OGAR publication. An
    /// interrupted preparation without a host intent supplies no inputs.
    /// Any physical, exposure, transport or restore residue refuses this seam:
    /// a missing archive after those phases must not repair a served Agent.
    pub(crate) fn staged_member_genesis_archive(
        &mut self,
        locator: AgentGenesisLocator,
    ) -> Result<Option<AgentGenesisArchiveRecord>, SharedAgentHostError> {
        self.lease.validate_live().map_err(map_outer_lease_error)?;
        if locator.validate().is_err()
            || locator.space != self.scope().space
            || !matches!(
                self.execution_selection,
                SharedExecutionSelection::ExternalLinearCandidates
            )
            || self.agents.contains_key(&locator.agent)
            || self.transport_leases.contains_key(&locator.agent)
        {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        let current = scan_generation_namespaces(&self.lease)?;
        let Some(files) = current.get(&locator.agent).copied() else {
            if self.deferred_generations.contains_key(&locator.agent) {
                return Err(SharedAgentHostError::CorruptResidue);
            }
            return Ok(None);
        };
        if !self.deferred_generations.contains_key(&locator.agent)
            || !staged_member_input_files(files)
        {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        // read_intent checks both recoverable files, the complete bound,
        // canonical re-encoding and the actual namespace Agent identity.
        let (intent, _) = self.read_intent(locator.agent, files)?;
        let SharedGenesisAuthority::AuthorityFinalized(provision) = &intent.authority else {
            return Err(SharedAgentHostError::ScopeMismatch);
        };
        let descriptor = provision
            .proposal()
            .clean_descriptor()
            .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
        if provision.proposal().locator() != locator
            || !super::super::replay::external_shared_descriptor_supported(descriptor)
            || provision
                .replicas()
                .validate_for_clean_descriptor(descriptor)
                .is_err()
            || provision
                .replicas()
                .member_by_node(self.scope().node)
                .is_none_or(|member| member.replica().role != ReplicaRole::Voter)
        {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        let authority = CommitteeChangeAuthorityBinding::new(
            descriptor.authority.policy,
            descriptor.authority.issuer,
            descriptor.identity.runtime_deployment,
            descriptor.authority.public_key,
            descriptor.authority.initial_epoch,
        )
        .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
        if intent.committee_authority != authority {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        let [blob] = intent.catalog.as_slice() else {
            return Err(SharedAgentHostError::ScopeMismatch);
        };
        let runtime = super::super::package_admission::admit_state_runtime_package(&blob.bytes)
            .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
        if descriptor.runtime_package != *runtime.package_ref()
            || descriptor.identity.runtime_deployment != runtime.deployment()
            || descriptor.identity.runtime_program != runtime.program()
            || descriptor.identity.runtime_producer != runtime.manifest().signing.producer
            || descriptor.runtime_contract != runtime.manifest().contract
            || descriptor.capabilities != runtime.manifest().capabilities
            || provision.proposal().create().runtime
                != runtime
                    .binding(locator.space, locator.agent)
                    .map_err(|_| SharedAgentHostError::ScopeMismatch)?
        {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        let record = AgentGenesisArchiveRecord::new(provision.clone(), intent.catalog)
            .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
        self.lease.validate_live().map_err(map_outer_lease_error)?;
        Ok(Some(record))
    }
}

fn validate_live_member_namespace_phase(
    files: Option<GenerationFiles>,
    serving: bool,
    staged: bool,
    archived: bool,
) -> Result<(), SharedAgentHostError> {
    let Some(files) = files else {
        return if serving || staged {
            Err(SharedAgentHostError::CorruptResidue)
        } else if archived {
            Err(SharedAgentHostError::ScopeMismatch)
        } else {
            Ok(())
        };
    };
    if serving == staged {
        return Err(SharedAgentHostError::CorruptResidue);
    }
    if !files.intent && !files.intent_stage {
        return Err(SharedAgentHostError::CorruptResidue);
    }
    if files.portable_restore || files.portable_restore_stage {
        return Err(SharedAgentHostError::Conflict);
    }
    if serving {
        if !archived {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        if !files.journal
            || !files.lock
            || !files.intent
            || !files.exposed
            || !files.raft
            || !files.artifacts
        {
            return Err(SharedAgentHostError::CorruptResidue);
        }
        if files.intent_stage || files.exposed_stage {
            return Err(SharedAgentHostError::Conflict);
        }
    } else if !archived && !staged_member_input_files(files) {
        // Publication precedes every physical opening/exposure write. Missing
        // OGAR cannot be repaired from a partially opened or served namespace.
        return Err(SharedAgentHostError::ScopeMismatch);
    }
    Ok(())
}

fn staged_member_input_files(files: GenerationFiles) -> bool {
    (files.intent || files.intent_stage)
        && !files.journal
        && !files.lock
        && !files.exposed
        && !files.exposed_stage
        && !files.portable_restore
        && !files.portable_restore_stage
        && !files.raft
        && !files.artifacts
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn live_member_namespace_phase_refuses_archive_only_or_lost_serving_material() {
        let intent = GenerationFiles {
            intent: true,
            ..GenerationFiles::default()
        };
        let serving_files = GenerationFiles {
            intent: true,
            journal: true,
            lock: true,
            exposed: true,
            raft: true,
            artifacts: true,
            ..GenerationFiles::default()
        };
        assert_eq!(
            validate_live_member_namespace_phase(None, false, false, false),
            Ok(())
        );
        assert_eq!(
            validate_live_member_namespace_phase(Some(intent), false, true, false),
            Ok(())
        );
        assert_eq!(
            validate_live_member_namespace_phase(Some(intent), false, true, true),
            Ok(())
        );
        assert_eq!(
            validate_live_member_namespace_phase(Some(serving_files), true, false, true),
            Ok(())
        );
        assert_eq!(
            validate_live_member_namespace_phase(None, false, false, true),
            Err(SharedAgentHostError::ScopeMismatch)
        );
        for (serving, staged) in [(true, false), (false, true), (true, true)] {
            assert_eq!(
                validate_live_member_namespace_phase(None, serving, staged, true),
                Err(SharedAgentHostError::CorruptResidue)
            );
        }
        assert_eq!(
            validate_live_member_namespace_phase(Some(intent), false, false, false),
            Err(SharedAgentHostError::CorruptResidue)
        );
        assert_eq!(
            validate_live_member_namespace_phase(
                Some(GenerationFiles::default()),
                false,
                true,
                true
            ),
            Err(SharedAgentHostError::CorruptResidue)
        );
        assert_eq!(
            validate_live_member_namespace_phase(Some(serving_files), true, false, false),
            Err(SharedAgentHostError::ScopeMismatch)
        );
        assert_eq!(
            validate_live_member_namespace_phase(Some(serving_files), false, true, false),
            Err(SharedAgentHostError::ScopeMismatch)
        );
        for missing in 0..6 {
            let mut files = serving_files;
            match missing {
                0 => files.intent = false,
                1 => files.journal = false,
                2 => files.lock = false,
                3 => files.exposed = false,
                4 => files.raft = false,
                _ => files.artifacts = false,
            }
            assert_eq!(
                validate_live_member_namespace_phase(Some(files), true, false, true),
                Err(SharedAgentHostError::CorruptResidue)
            );
        }
        for mutation in 0..4 {
            let mut files = serving_files;
            match mutation {
                0 => files.intent_stage = true,
                1 => files.exposed_stage = true,
                2 => files.portable_restore = true,
                _ => files.portable_restore_stage = true,
            }
            assert_eq!(
                validate_live_member_namespace_phase(Some(files), true, false, true),
                Err(SharedAgentHostError::Conflict)
            );
        }
        // The immutable archive is already durable during an interrupted open;
        // existing recovery, not missing-archive repair, owns that exact stage.
        assert_eq!(
            validate_live_member_namespace_phase(Some(serving_files), false, true, true),
            Ok(())
        );
    }

    #[test]
    fn missing_member_archive_inputs_allow_only_never_opened_intent() {
        assert!(!staged_member_input_files(GenerationFiles::default()));
        for (intent, intent_stage) in [(true, false), (false, true), (true, true)] {
            let files = GenerationFiles {
                intent,
                intent_stage,
                ..GenerationFiles::default()
            };
            assert!(staged_member_input_files(files));
            for residue in 0..8 {
                let mut changed = files;
                match residue {
                    0 => changed.journal = true,
                    1 => changed.lock = true,
                    2 => changed.exposed = true,
                    3 => changed.exposed_stage = true,
                    4 => changed.portable_restore = true,
                    5 => changed.portable_restore_stage = true,
                    6 => changed.raft = true,
                    _ => changed.artifacts = true,
                }
                assert!(!staged_member_input_files(changed));
            }
        }
    }
}
