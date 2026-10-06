//! Member admission from the installed Authority, never from an archive's QC.
//!
//! Publication is not application finality. A member must observe both the
//! exact permanent decision and the complete live Create descriptor before it
//! can obtain the existing owner-only replay attestation.

use super::*;
#[cfg(test)]
use crate::agent::sdk::authority::MAX_AUTHORITY_INVENTORY_PAGE_ENTRIES;
use crate::agent::sdk::authority::{
    AuthorityBuiltinRole, AuthorityCredentialKind, AuthorityCredentialStatus,
    AuthorityIngressAuthentication, AuthorityInventoryCursor, AuthorityInventoryEntry,
    AuthorityInventoryPosition, AuthorityInventoryProjectionPage,
};

/// Emit only a fixed diagnostic phase; this carries no admission authority.
pub(super) fn trace_member_admission_phase(phase: &'static str) {
    if std::env::var_os("VOS_TEST_BOOTSTRAP_DIAGNOSTICS").is_some() {
        tracing::debug!(phase, "VOS member admission phase");
    }
}

/// Four exact rows: descriptor followed by the fixed-three voter roster. The
/// existing inventory cursor is exclusive and need not name an existing row.
pub(crate) fn member_inventory_selector(
    agent: AgentId,
) -> Result<AuthorityProjectionSelector, SharedAgentHostError> {
    if agent == AgentId::ZERO {
        return Err(SharedAgentHostError::ScopeMismatch);
    }
    let mut predecessor = agent.0;
    for byte in predecessor.iter_mut().rev() {
        if *byte != 0 {
            *byte -= 1;
            break;
        }
        *byte = u8::MAX;
    }
    let after = (predecessor != [0; 32]).then_some(AuthorityInventoryCursor {
        agent: AgentId(predecessor),
        position: AuthorityInventoryPosition::Actor(super::super::sdk::ActorId([u8::MAX; 32])),
    });
    Ok(AuthorityProjectionSelector::Inventory {
        after,
        limit: 4,
        known_head: None,
    })
}

impl<P, R, I> CleanSystemAgentBootstrapOwner<P, R, I>
where
    P: CleanSystemAgentBootstrapStore,
    R: CleanSystemAgentBootstrapStore,
    I: CleanManagementIssuerStore,
{
    /// Validate complete independently leased member inputs against the actual
    /// deferred/opened namespaces. This creates no read permission, reservation
    /// or finality; each member still needs its own fresh Authority evidence.
    pub(crate) fn validate_recovery_member_set(
        &mut self,
        records: &[&super::super::genesis::AgentGenesisArchiveRecord],
    ) -> Result<(), SharedAgentHostError> {
        if self.pins.replicas.members().len() != 3 {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        self.validate_member_system_binding()?;
        let expected = {
            let mut host = self
                .host
                .lock()
                .map_err(|_| SharedAgentHostError::Unavailable)?;
            let Some(expected) = host.recovery_member_agent_ids()? else {
                return Ok(());
            };
            expected
        };
        if expected.is_empty() {
            return Ok(());
        }
        let mut actual = records
            .iter()
            .map(|record| record.provision().proposal().locator())
            .collect::<Vec<_>>();
        actual.sort_unstable_by_key(|locator| locator.agent);
        if actual.windows(2).any(|pair| pair[0].agent == pair[1].agent)
            || actual
                .iter()
                .any(|locator| locator.space.0 != self.pins.space.0)
        {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        validate_cold_member_namespace_coverage(&expected, &actual, &[])?;
        for record in records
            .iter()
            .filter(|record| expected.contains(&record.provision().proposal().locator().agent))
        {
            self.verify_member_shared_genesis_material(record)?;
            self.host
                .lock()
                .map_err(|_| SharedAgentHostError::Unavailable)?
                .validate_recovery_member_material(record)?;
        }
        // Recheck the same leased physical set after material validation.
        // Neither cached inputs nor a new namespace may replace that set.
        let current = self
            .host
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?
            .recovery_member_agent_ids()?;
        if current.as_deref() != Some(expected.as_slice()) {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        self.validate_member_system_binding()
    }
    /// Reject foreign material and occupied lifecycle lanes before preparing a
    /// member archive lease. This performs no signatures, read recovery,
    /// publication, transport refresh, or physical generation creation.
    pub(crate) fn preflight_live_member_shared_genesis(
        &mut self,
        record: &super::super::genesis::AgentGenesisArchiveRecord,
        public_key: [u8; 32],
    ) -> Result<(), SharedAgentHostError> {
        if public_key != self.pins.authority.public_key {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        self.verify_member_shared_genesis_material(record)?;
        validate_live_member_lane(
            self.record.phase == CleanSystemAgentBootstrapPhase::Complete,
            self.shared_lifecycle_recovery_pending,
            self.management_admission_held()?,
        )?;
        self.host
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?
            .preflight_live_genesis_capacity(record.provision().proposal().locator())
    }

    /// A durable archive is not permission to replace a disappeared physical
    /// generation. Validate the actual staged/serving phase before fresh work.
    pub(crate) fn preflight_live_member_namespace(
        &mut self,
        record: &super::super::genesis::AgentGenesisArchiveRecord,
        archived: bool,
    ) -> Result<(), SharedAgentHostError> {
        self.host
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?
            .preflight_live_member_genesis(record, archived)
    }

    /// Reauthenticate a fixed-three external generation on an actual local
    /// voter. This does not write its archive, provision it, attach transport,
    /// publish readiness, or stand in for the coordinator's application ACK.
    /// Retained Shared Install ownership remains independent of these immutable
    /// observations; no read custody or permission is added to that family.
    pub(crate) fn verify_member_shared_genesis<S: CleanManagementReceiptSigner>(
        &mut self,
        record: &super::super::genesis::AgentGenesisArchiveRecord,
        signer: &mut S,
    ) -> Result<ReplayVerifiedAgentGenesisFinality, SharedAgentHostError> {
        // Reject a substituted signer before observing. The configured Root
        // key remains the only signer for this lane.
        if signer.public_key() != self.pins.authority.public_key {
            trace_member_admission_phase("member_signer");
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        trace_member_admission_phase("member_static_material_start");
        self.verify_member_shared_genesis_material(record)?;
        trace_member_admission_phase("member_static_material_ok");
        let provision = record.provision();
        let agent = AgentId(provision.proposal().locator().agent.0);
        trace_member_admission_phase("member_decision_query_start");
        let nonce = self.member_genesis_query_nonce(record, 0)?;
        let query = self.signed_genesis_decision_query(agent, nonce, signer)?;
        trace_member_admission_phase("member_decision_query_ok");
        // The physical Authority guest revalidates the publication certificate
        // against its current committee. Do not decode its private state or
        // select a "trusted" committee from the untrusted archive.
        trace_member_admission_phase("member_decision_observation_start");
        let decision = self.invoke_authority_observation(query)?;
        trace_member_admission_phase("member_decision_observation_ok");
        if decision != provision.decision().encode() {
            trace_member_admission_phase(if decision.is_empty() {
                "member_decision_empty"
            } else {
                "member_decision_different"
            });
            return Err(SharedAgentHostError::ScopeMismatch);
        }

        let expected = provision
            .proposal()
            .clean_descriptor()
            .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
        trace_member_admission_phase("member_inventory_query_start");
        let query = self.sign_member_inventory_query(
            member_inventory_selector(agent)?,
            self.member_genesis_query_nonce(record, 1)?,
            signer,
        )?;
        trace_member_admission_phase("member_inventory_query_ok");
        trace_member_admission_phase("member_inventory_observation_start");
        let bytes = self.invoke_authority_observation(query.clone())?;
        trace_member_admission_phase("member_inventory_observation_ok");
        let page = AuthorityInventoryProjectionPage::decode(&bytes).map_err(|_| {
            trace_member_admission_phase("member_inventory_decode");
            SharedAgentHostError::ScopeMismatch
        })?;
        if page.encode().ok().as_deref() != Some(bytes.as_slice()) {
            trace_member_admission_phase("member_inventory_canonical");
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        if !member_inventory_page_matches(&page, &query, self.pins.authority.issuer.principal) {
            trace_member_admission_phase("member_inventory_page_credential");
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        if !member_inventory_descriptor_matches(&page, expected) {
            // A permanent decision alone can exist before Create finalization.
            // The live descriptor includes all three exact replica rows; no
            // missing, altered, or merely archived roster is sufficient.
            trace_member_admission_phase("member_inventory_descriptor");
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        // Recheck the exact sealed System generation after all executions.
        // This also rejects a committee transition or generation replacement
        // during the reads, before minting a process-only attestation.
        trace_member_admission_phase("member_final_material_start");
        self.verify_member_shared_genesis_material(record)?;
        trace_member_admission_phase("member_final_material_ok");
        Ok(ReplayVerifiedAgentGenesisFinality(provision.clone()))
    }

    /// Obtain fresh installed-System evidence, then durably stage the member's
    /// complete inputs before its archive is published. This does not open the
    /// physical generation or attach transport. The caller retains the archive
    /// lease and publishes the exact OGAR before calling the finishing phase.
    pub(crate) fn stage_live_member_shared_genesis<S: CleanManagementReceiptSigner>(
        &mut self,
        record: &super::super::genesis::AgentGenesisArchiveRecord,
        archived: bool,
        signer: &mut S,
    ) -> Result<ReplayVerifiedAgentGenesisFinality, SharedAgentHostError> {
        if signer.public_key() != self.pins.authority.public_key {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        self.host
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?
            .preflight_live_genesis_capacity(record.provision().proposal().locator())?;
        let proof = self.verify_member_shared_genesis(record, signer)?;
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
        let mut host = self
            .host
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        // Recheck after the fresh executions while holding the same physical
        // owner lock as staging. Cached serving intent cannot hide lost files.
        host.preflight_live_member_genesis(record, archived)?;
        host.stage_live_member_replay_verified(
            record.provision().clone(),
            record.catalog().to_vec(),
            authority,
            &proof,
        )?;
        Ok(proof)
    }

    /// Promote only after reloading the exact archive from its retained durable
    /// store. The existing opener publishes the physical genesis and exposure
    /// marker before returning; network attachment and route publication remain
    /// separate owner phases. An archive alone can never reach this method's
    /// opener without an existing staged namespace and owner-minted proof.
    pub(crate) fn finish_live_member_shared_genesis<A>(
        &mut self,
        record: &super::super::genesis::AgentGenesisArchiveRecord,
        proof: &ReplayVerifiedAgentGenesisFinality,
        archive: &A,
    ) -> Result<(), SharedAgentHostError>
    where
        A: super::super::genesis_archive::AgentGenesisArchiveStore,
    {
        if proof.0 != *record.provision() {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        self.verify_member_shared_genesis_material(record)?;
        self.validate_member_system_binding()?;
        let locator = record.provision().proposal().locator();
        let bytes = archive
            .load(locator)
            .map_err(|_| SharedAgentHostError::Unavailable)?
            .ok_or(SharedAgentHostError::Unavailable)?;
        if !member_archive_exact_bytes(&bytes, &record.encode()) {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        let finality = self.shared_genesis_finality.with_proof(proof.clone())?;
        let mut host = self
            .host
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        host.preflight_live_member_genesis(record, true)?;
        host.admit_live_replay_verified(locator.agent, proof, finality.clone())?;
        self.shared_genesis_finality = finality;
        Ok(())
    }

    /// Recover the gap between the durable unserved intent and OGAR insertion.
    /// Only the existing host stage supplies inputs: an absent or already-opened
    /// namespace is never synthesized from an empty archive preparation. Fresh
    /// member evidence still precedes publication, and complete-set cold recovery
    /// retains responsibility for physical opening and admission.
    pub(crate) fn recover_staged_member_shared_genesis_archive<A, S>(
        &mut self,
        locator: super::super::genesis::AgentGenesisLocator,
        archive: &A,
        signer: &mut S,
    ) -> Result<Option<super::super::genesis::AgentGenesisArchiveRecord>, SharedAgentHostError>
    where
        A: super::super::genesis_archive::AgentGenesisArchiveStore,
        S: CleanManagementReceiptSigner,
    {
        if signer.public_key() != self.pins.authority.public_key {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        let staged = self
            .host
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?
            .staged_member_genesis_archive(locator)?;
        let existing = archive
            .load(locator)
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        let Some(record) = staged else {
            // An immutable archive with no physical namespace is not an
            // unfinished first admission; the cold missing-member guard holds.
            return if existing.is_some() {
                Err(SharedAgentHostError::ScopeMismatch)
            } else {
                Ok(None)
            };
        };
        if existing
            .as_deref()
            .is_some_and(|bytes| !member_archive_exact_bytes(bytes, &record.encode()))
        {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        self.verify_member_shared_genesis(&record, signer)?;
        // Reuse the immutable publisher's success-and-reload protocol; a write
        // failure may have advanced the durable archive and remains exact retry.
        super::super::genesis_archive::ArchivedAgentGenesisProvider::new(locator.space, archive)
            .map_err(|_| SharedAgentHostError::ScopeMismatch)?
            .publish(&record)
            .map_err(|error| match error {
                super::super::genesis::AgentGenesisProviderError::Unavailable => {
                    SharedAgentHostError::Unavailable
                }
                _ => SharedAgentHostError::ScopeMismatch,
            })?;
        Ok(Some(record))
    }

    /// Validate the actual leased System owner and attachment, not a read clock
    /// or process-local permission. Freshness itself belongs to each ReadIndex
    /// observation; this guard binds the surrounding member lifecycle.
    fn validate_member_system_binding(&mut self) -> Result<(), SharedAgentHostError> {
        let agent = crate::service::AgentId(self.pins.agent.0);
        let manifest = self._network_host.management_recovery_manifest(agent)?;
        let mut host = self
            .host
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        host.validate_observation_owner(agent)?;
        let system = host
            .supervisor_attachment_status(agent)?
            .ok_or(SharedAgentHostError::AgentNotFound)?;
        if system.transport != super::super::shared_host::SharedAgentTransportState::Attached
            || system.committee_transition.is_some()
            || system.local_role != Some(crate::agent::ReplicaRole::Voter)
            || system.generation != manifest.generation()
            || manifest.generation().space().0 != self.pins.space.0
            || manifest.generation().agent().0 != self.pins.agent.0
            || system.route.committee() != self.pins.replicas.id()
            || manifest.committee() != &self.pins.replicas
            || self.snapshot_signer.node().0 != self.pins.node.0
            || self.pins.replicas.members().len() != 3
            || self
                .pins
                .replicas
                .members()
                .iter()
                .any(|member| member.replica().role != super::super::ReplicaRole::Voter)
        {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        host.validate_observation_owner(agent)
    }

    fn verify_member_shared_genesis_material(
        &mut self,
        record: &super::super::genesis::AgentGenesisArchiveRecord,
    ) -> Result<(), SharedAgentHostError> {
        self.validate_member_system_binding().map_err(|error| {
            trace_member_admission_phase("material_binding");
            error
        })?;
        let provision = record.provision();
        provision.validate().map_err(|_| {
            trace_member_admission_phase("material_provision");
            SharedAgentHostError::ScopeMismatch
        })?;
        super::super::genesis::validate_agent_genesis_catalog(
            provision.proposal(),
            record.catalog(),
        )
        .map_err(|_| {
            trace_member_admission_phase("material_catalog");
            SharedAgentHostError::ScopeMismatch
        })?;
        let proposal = provision.proposal();
        let descriptor = proposal.clean_descriptor().map_err(|_| {
            trace_member_admission_phase("material_descriptor");
            SharedAgentHostError::ScopeMismatch
        })?;
        let claim = provision.evidence().claim();
        let replicas = provision.replicas();
        if self.pins.replicas.members().len() != 3
            || self
                .pins
                .replicas
                .members()
                .iter()
                .any(|member| member.replica().role != super::super::ReplicaRole::Voter)
            || descriptor.identity.space != self.pins.space
            || descriptor.identity.agent == self.pins.agent
            || descriptor.authority != self.pins.authority
            || !super::super::replay::external_shared_descriptor_supported(descriptor)
            || replicas.validate_for_clean_descriptor(descriptor).is_err()
            || replicas
                .member_by_node(crate::service::NodeId(self.pins.node.0))
                .is_none_or(|member| member.replica().role != super::super::ReplicaRole::Voter)
            || claim.space().0 != self.pins.space.0
            || claim.system_agent().0 != self.pins.agent.0
        {
            trace_member_admission_phase("material_descriptor");
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        let super::super::journal::ReplayOperation::CleanManage {
            request,
            authority: receipt,
            observed_slot,
        } = &proposal.create().operation
        else {
            trace_member_admission_phase("material_receipt");
            return Err(SharedAgentHostError::ScopeMismatch);
        };
        if !self.pins.authority.accepts(receipt)
            || receipt
                .verify_at(*observed_slot, &RawCredentialVerifier)
                .is_err()
            || receipt.selector.operation != AuthorityOperationKind::CreateAgent
            || receipt.selector.space != descriptor.identity.space
            || receipt.selector.agent != descriptor.identity.agent
            || receipt.selector.runtime_deployment != descriptor.identity.runtime_deployment
            || receipt.selector.request != request.commitment()
        {
            trace_member_admission_phase("material_receipt");
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        let runtime = super::super::package_admission::admit_state_runtime_package(
            &record.catalog()[0].bytes,
        )
        .map_err(|_| {
            trace_member_admission_phase("material_runtime");
            SharedAgentHostError::ScopeMismatch
        })?;
        if descriptor.runtime_package != *runtime.package_ref()
            || descriptor.identity.runtime_deployment != runtime.deployment()
            || descriptor.identity.runtime_program != runtime.program()
            || descriptor.identity.runtime_producer != runtime.manifest().signing.producer
            || descriptor.runtime_contract != runtime.manifest().contract
            || descriptor.capabilities != runtime.manifest().capabilities
            || proposal.create().runtime
                != runtime
                    .binding(proposal.locator().space, proposal.locator().agent)
                    .map_err(|_| {
                        trace_member_admission_phase("material_runtime");
                        SharedAgentHostError::ScopeMismatch
                    })?
        {
            trace_member_admission_phase("material_runtime");
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        // Independently opened physical System lineage, not claim/archive
        // data. Fresh transport/committee admission is checked before each
        // signature; observations do not create a retained read obligation.
        let position = self
            .host
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?
            .journal_position(crate::service::AgentId(self.pins.agent.0))?;
        if claim.system_genesis() != position.genesis
            || claim.system_admission() != position.admission
        {
            trace_member_admission_phase("material_system_lineage");
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        self.validate_member_system_binding().map_err(|error| {
            trace_member_admission_phase("material_binding");
            error
        })
    }

    fn member_genesis_query_nonce(
        &self,
        record: &super::super::genesis::AgentGenesisArchiveRecord,
        sequence: u64,
    ) -> Result<Hash, SharedAgentHostError> {
        let position = self
            .host
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?
            .journal_position(crate::service::AgentId(self.pins.agent.0))?;
        Ok(Hash::digest(
            b"vos/shared-genesis/member-finality-read/v1",
            &[
                position.genesis.as_bytes(),
                position.admission.as_bytes(),
                &position.ordered_index.to_le_bytes(),
                position
                    .ordered_head
                    .map(|head| *head.as_bytes())
                    .unwrap_or([0; 32])
                    .as_slice(),
                record.provision().decision().id().as_bytes(),
                &sequence.to_le_bytes(),
            ],
        ))
    }

    fn sign_member_inventory_query<S: CleanManagementReceiptSigner>(
        &mut self,
        selector: AuthorityProjectionSelector,
        nonce: Hash,
        signer: &mut S,
    ) -> Result<AuthorityProjectionQuery, SharedAgentHostError> {
        let public_key = signer.public_key();
        if public_key != self.pins.authority.public_key {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        let authority = self.authority_target();
        let mut query = AuthorityProjectionQuery {
            authority,
            credential: super::super::sdk::CredentialId::of_public_key(&public_key),
            nonce,
            selector,
            authentication: AuthorityIngressAuthentication::ApiCredentialSignature {
                credential_public_key: public_key,
                // Shape-only placeholder; never dispatched or persisted.
                signature: [1; 64],
            },
            recovery: None,
        };
        query
            .validate_shape()
            .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
        query.authentication = AuthorityIngressAuthentication::ApiCredentialSignature {
            credential_public_key: public_key,
            signature: signer
                .sign_authority_projection(&query)
                .ok_or(SharedAgentHostError::Unavailable)?,
        };
        query
            .verify_api_with(&RawCredentialVerifier)
            .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
        Ok(query)
    }
}

fn member_archive_exact_bytes(stored: &[u8], expected: &[u8]) -> bool {
    stored.len() <= super::super::genesis::MAX_AGENT_GENESIS_ARCHIVE_RECORD_BYTES
        && stored == expected
}

fn validate_live_member_lane(
    complete: bool,
    recovering: bool,
    pending_management: bool,
) -> Result<(), SharedAgentHostError> {
    if !complete || recovering || pending_management {
        return Err(SharedAgentHostError::Conflict);
    }
    Ok(())
}

/// Archive identity cannot distinguish initial admission from loss of a
/// previously served namespace. Cold recovery therefore never creates an
/// absent member, and every existing namespace still needs one proof in the
/// complete issuer/member union. Initial live admission is a separate gate.
pub(super) fn validate_cold_member_namespace_coverage(
    expected: &[crate::service::AgentId],
    all: &[super::super::genesis::AgentGenesisLocator],
    members: &[super::super::genesis::AgentGenesisLocator],
) -> Result<(), SharedAgentHostError> {
    if members
        .iter()
        .any(|member| !expected.contains(&member.agent))
        || expected
            .iter()
            .any(|agent| !all.iter().any(|locator| locator.agent == *agent))
    {
        return Err(SharedAgentHostError::ScopeMismatch);
    }
    Ok(())
}

fn member_inventory_page_matches(
    page: &AuthorityInventoryProjectionPage,
    query: &AuthorityProjectionQuery,
    root_principal: super::super::sdk::PrincipalId,
) -> bool {
    page.validate_shape().is_ok()
        && page.credential.query == *query
        && !page.unchanged
        && (page.credential.principal == root_principal || {
            trace_member_admission_phase("inventory_page_principal");
            false
        })
        && page.credential.status == AuthorityCredentialStatus::Active
        && page.credential.kind == AuthorityCredentialKind::Api
        && page.credential.builtin_role == AuthorityBuiltinRole::Admin
}

fn member_inventory_descriptor_matches(
    page: &AuthorityInventoryProjectionPage,
    expected: &super::super::sdk::AgentDescriptor,
) -> bool {
    let [AuthorityInventoryEntry::Agent(row), rest @ ..] = page.entries.as_slice() else {
        return false;
    };
    if rest.len() != 3 || row.identity.agent != expected.identity.agent || row.replica_count != 3 {
        return false;
    }
    let replicas = rest
        .iter()
        .map(|entry| match entry {
            AuthorityInventoryEntry::Replica { agent, replica }
                if *agent == expected.identity.agent =>
            {
                Some(replica.clone())
            }
            _ => None,
        })
        .collect::<Option<Vec<_>>>();
    replicas.is_some_and(|replicas| row.reconstruct_descriptor(replicas).as_ref() == Ok(expected))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::sdk::{CredentialId, DeploymentId, PrincipalId, ProducerId, ProgramId};

    #[test]
    fn cold_member_targeted_cursor_is_exact_and_bounded_at_id_edges() {
        assert_eq!(
            member_inventory_selector(AgentId::ZERO),
            Err(SharedAgentHostError::ScopeMismatch)
        );
        let mut first = [0; 32];
        first[31] = 1;
        assert_eq!(
            member_inventory_selector(AgentId(first)),
            Ok(AuthorityProjectionSelector::Inventory {
                after: None,
                limit: 4,
                known_head: None,
            })
        );
        for agent in [AgentId([1; 32]), AgentId([255; 32])] {
            let AuthorityProjectionSelector::Inventory {
                after: Some(cursor),
                limit,
                known_head,
            } = member_inventory_selector(agent).unwrap()
            else {
                panic!("nonminimum cursor")
            };
            assert_eq!(limit, 4);
            assert_eq!(known_head, None);
            assert_eq!(
                cursor.position,
                AuthorityInventoryPosition::Actor(ActorId([255; 32]))
            );
            let mut successor = cursor.agent.0;
            for byte in successor.iter_mut().rev() {
                if *byte != 255 {
                    *byte += 1;
                    break;
                }
                *byte = 0;
            }
            assert_eq!(successor, agent.0);
        }
    }

    #[test]
    fn live_member_admission_refuses_recovery_or_management_lanes() {
        assert_eq!(validate_live_member_lane(true, false, false), Ok(()));
        for state in [
            (false, false, false),
            (true, true, false),
            (true, false, true),
        ] {
            assert_eq!(
                validate_live_member_lane(state.0, state.1, state.2),
                Err(SharedAgentHostError::Conflict),
            );
        }
    }

    // Shape-only fixture for pure negative guards. It cannot execute a query
    // or construct ReplayVerifiedAgentGenesisFinality.
    fn page_fixture() -> AuthorityInventoryProjectionPage {
        let public_key = [9; 32];
        let query = AuthorityProjectionQuery {
            authority: AuthorityActorTarget {
                space: SpaceId([1; 32]),
                system_agent: AgentId([2; 32]),
                system_runtime_deployment: DeploymentId([3; 32]),
                binding: AgentAuthorityBinding {
                    policy: Hash([4; 32]),
                    issuer: AuthorityIssuer {
                        principal: PrincipalId([5; 32]),
                        actor: ActorId([6; 32]),
                        deployment: DeploymentId([7; 32]),
                        program: ProgramId([8; 32]),
                        producer: ProducerId::of_public_key(&public_key),
                    },
                    public_key,
                    initial_epoch: 1,
                },
            },
            credential: CredentialId::of_public_key(&public_key),
            nonce: Hash([10; 32]),
            selector: AuthorityProjectionSelector::Inventory {
                after: None,
                limit: MAX_AUTHORITY_INVENTORY_PAGE_ENTRIES as u16,
                known_head: None,
            },
            authentication: AuthorityIngressAuthentication::ApiCredentialSignature {
                credential_public_key: public_key,
                signature: [11; 64],
            },
            recovery: None,
        };
        AuthorityInventoryProjectionPage::decode(
            &crate::agent::production_owner::inventory_page_fixture(
                query,
                crate::agent::sdk::authority::AuthorityProjectionHead {
                    state_revision: core::num::NonZeroU64::new(1).unwrap(),
                    epoch: core::num::NonZeroU64::new(1).unwrap(),
                    authorization_sequence: core::num::NonZeroU64::new(1).unwrap(),
                    administration_generation: core::num::NonZeroU64::new(1).unwrap(),
                    state_commitment: Hash([12; 32]),
                },
                PrincipalId([5; 32]),
                &[],
                &[],
                MAX_AUTHORITY_INVENTORY_PAGE_ENTRIES,
            )
            .unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn member_publication_requires_exact_complete_archive_bytes() {
        // This tests byte identity only, not a decodable archive or finality.
        let expected = b"exact canonical member inputs";
        assert!(member_archive_exact_bytes(expected, expected));
        assert!(!member_archive_exact_bytes(
            &expected[..expected.len() - 1],
            expected
        ));
        assert!(!member_archive_exact_bytes(
            b"substituted member inputs",
            expected
        ));
        let mut with_trailing = expected.to_vec();
        with_trailing.push(0);
        assert!(!member_archive_exact_bytes(&with_trailing, expected));
    }

    #[test]
    fn member_inventory_rejects_substituted_query_and_root_claims() {
        let page = page_fixture();
        let query = page.credential.query.clone();
        let root = query.authority.binding.issuer.principal;
        assert!(member_inventory_page_matches(&page, &query, root));
        let mut another_query = query.clone();
        another_query.nonce = Hash([13; 32]);
        assert!(!member_inventory_page_matches(&page, &another_query, root));
        for altered in 0..6 {
            let mut changed = page.clone();
            match altered {
                0 => changed.credential.principal = PrincipalId([13; 32]),
                1 => changed.credential.status = AuthorityCredentialStatus::Revoked,
                2 => changed.credential.kind = AuthorityCredentialKind::Ssh,
                3 => changed.credential.builtin_role = AuthorityBuiltinRole::Developer,
                4 => changed.unchanged = true,
                _ => changed.credential.head.state_commitment = Hash::ZERO,
            }
            assert!(!member_inventory_page_matches(&changed, &query, root));
        }
    }

    #[test]
    fn member_inventory_requires_exact_descriptor_and_complete_voter_roster() {
        use crate::agent::sdk::contract::RuntimePackageContract;
        use crate::agent::sdk::{
            AgentIdentity, AgentReplica, BlobRef, ReplicaRole, RuntimeCapabilities,
        };
        let template = page_fixture();
        let mut query = template.credential.query.clone();
        let owner = PrincipalId([0x66; 32]);
        let nonce = Hash([0x67; 32]);
        let agent = AgentId::derive(query.authority.space, owner, nonce.as_bytes());
        query.selector = member_inventory_selector(agent).unwrap();
        let expected = AgentDescriptor {
            identity: AgentIdentity {
                space: query.authority.space,
                agent,
                owner,
                profile: AgentProfile::Shared,
                runtime_deployment: DeploymentId([0x68; 32]),
                runtime_program: ProgramId([0x69; 32]),
                runtime_producer: ProducerId([0x6a; 32]),
                transition_producer: ProducerId([0x6b; 32]),
            },
            creation_nonce: nonce,
            authority: query.authority.binding,
            private_recovery: None,
            runtime_package: BlobRef::of_bytes(b"runtime"),
            runtime_contract: RuntimePackageContract::canonical(),
            capabilities: RuntimeCapabilities::standard(),
            replicas: [1, 2, 3]
                .into_iter()
                .map(|node| AgentReplica {
                    node: NodeId([node; 32]),
                    principal: owner,
                    role: ReplicaRole::Voter,
                })
                .collect(),
        };
        let page = AuthorityInventoryProjectionPage::decode(
            &crate::agent::production_owner::inventory_page_fixture(
                query.clone(),
                template.credential.head,
                query.authority.binding.issuer.principal,
                &[expected.clone()],
                &[],
                4,
            )
            .unwrap(),
        )
        .unwrap();
        assert!(member_inventory_page_matches(
            &page,
            &query,
            query.authority.binding.issuer.principal,
        ));
        assert!(member_inventory_descriptor_matches(&page, &expected));
        let mut missing = page.clone();
        missing.entries.pop();
        assert!(!member_inventory_descriptor_matches(&missing, &expected));
        let mut changed = page;
        let AuthorityInventoryEntry::Replica { replica, .. } = &mut changed.entries[1] else {
            unreachable!()
        };
        replica.principal = PrincipalId([0x7f; 32]);
        assert!(!member_inventory_descriptor_matches(&changed, &expected));
    }

    #[test]
    fn cold_member_archive_never_repairs_missing_namespace_and_requires_union_coverage() {
        use crate::agent::genesis::AgentGenesisLocator;
        use crate::service::{AgentId as HostAgentId, SpaceId as HostSpaceId};
        let issuer = AgentGenesisLocator {
            space: HostSpaceId([1; 32]),
            agent: HostAgentId([14; 32]),
        };
        let member = AgentGenesisLocator {
            agent: HostAgentId([15; 32]),
            ..issuer
        };
        let expected = [issuer.agent, member.agent];
        assert_eq!(
            validate_cold_member_namespace_coverage(&expected, &[issuer, member], &[member]),
            Ok(()),
        );
        assert_eq!(
            validate_cold_member_namespace_coverage(&[issuer.agent], &[issuer, member], &[member]),
            Err(SharedAgentHostError::ScopeMismatch),
        );
        assert_eq!(
            validate_cold_member_namespace_coverage(&expected, &[member], &[member]),
            Err(SharedAgentHostError::ScopeMismatch),
        );
        assert_eq!(
            validate_cold_member_namespace_coverage(&[], &[member], &[member]),
            Err(SharedAgentHostError::ScopeMismatch),
        );
    }
}
