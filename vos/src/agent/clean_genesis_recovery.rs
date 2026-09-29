//! Retained Shared Create recovery and continuing management ownership.

use super::genesis_issuance::RetainedCommitteeQuery;
use super::*;
use crate::agent::clean_authority_issuer::SignedManagementTerminal;
use crate::agent::clean_management_intent::{
    CleanManagementIntent, CleanManagementIntentSlot, ManagementJournalAnchor, SharedInstallHandoff,
};

fn recover_shared_install_handoff<I, J>(
    slot: &mut CleanManagementIntentSlot<I>,
    issuer: &DurableCleanManagementIssuer<J>,
    authority: AuthorityActorTarget,
    descriptor: &AgentDescriptor,
) -> Result<(), SharedAgentHostError>
where
    I: super::super::clean_authority_issuer::CleanSharedManagementIntentStore,
    J: CleanManagementIssuerStore,
{
    let Some(record) = slot
        .load_shared_install_handoff()
        .map_err(|_| SharedAgentHostError::Unavailable)?
    else {
        return Ok(());
    };
    let identity = &descriptor.identity;
    let managed = ManagedAgentTarget {
        space: identity.space,
        agent: identity.agent,
        owner: identity.owner,
        profile: identity.profile,
        runtime_deployment: identity.runtime_deployment,
        transition_producer: identity.transition_producer,
    };
    if record.next.call().authority != authority || record.next.call().managed != managed {
        return Err(SharedAgentHostError::ScopeMismatch);
    }
    validate_actor_install(descriptor, record.next.request(), &record.package)
        .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
    let current = slot
        .intent()
        .ok_or(SharedAgentHostError::ScopeMismatch)?
        .clone();
    let before = SharedInstallHandoff::matches(&current, &record.previous);
    let after = SharedInstallHandoff::matches(&current, &record.next);
    if !before && !after {
        return Err(SharedAgentHostError::ScopeMismatch);
    }
    if before
        || slot
            .authorization_work()
            .map_err(|_| SharedAgentHostError::Unavailable)?
            .is_none()
    {
        if issuer
            .recover_finalized_terminal(
                authority,
                record.previous.call().managed,
                record.previous.request(),
                record.previous.call(),
                &RawCredentialVerifier,
            )
            .map_err(|_| SharedAgentHostError::ScopeMismatch)?
            .is_none()
            || !issuer
                .can_resume_install(
                    authority,
                    record.next.call().managed,
                    record.next.request(),
                    record.next.call(),
                    &RawCredentialVerifier,
                )
                .map_err(|_| SharedAgentHostError::ScopeMismatch)?
        {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        if before {
            if !slot
                .retirement_complete()
                .map_err(|_| SharedAgentHostError::Unavailable)?
            {
                return Err(SharedAgentHostError::Conflict);
            }
            let old_package = slot
                .load_actor()
                .map_err(|_| SharedAgentHostError::Unavailable)?
                .ok_or(SharedAgentHostError::Unavailable)?;
            validate_actor_install(descriptor, current.request(), &old_package)
                .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
            slot.handoff_retired(&current, record.next.clone(), &RawCredentialVerifier)
                .map_err(|_| SharedAgentHostError::Unavailable)?;
        }
        slot.retain_actor(&record.package)
            .map_err(|_| SharedAgentHostError::Unavailable)?;
    } else {
        // Once authorization exists, missing or divergent package evidence is
        // corruption, not a pre-admission handoff that may repair its sidecar.
        let package = slot
            .load_actor()
            .map_err(|_| SharedAgentHostError::Unavailable)?
            .ok_or(SharedAgentHostError::Unavailable)?;
        if package.exact_bytes() != record.package.exact_bytes() {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
    }
    Ok(())
}

fn verify_shared_handoff_generation<B, C, D, J>(
    owner: &CleanSystemAgentBootstrapOwner<B, C, D>,
    record: &SharedInstallHandoff,
    issuer: &DurableCleanManagementIssuer<J>,
) -> Result<(), SharedAgentHostError>
where
    B: CleanSystemAgentBootstrapStore + Send + 'static,
    C: CleanSystemAgentBootstrapStore + Send + 'static,
    D: CleanManagementIssuerStore + Send + 'static,
    J: CleanManagementIssuerStore,
{
    let authority = owner.authority_target();
    let managed = record.next.call().managed;
    let mut host = owner
        .host
        .lock()
        .map_err(|_| SharedAgentHostError::Unavailable)?;
    if let Some(receipt) = issuer
        .recover_issued_application(
            authority,
            managed,
            record.next.request(),
            record.next.call(),
            &RawCredentialVerifier,
        )
        .map_err(|_| SharedAgentHostError::ScopeMismatch)?
    {
        // An interrupted successor may already be physically applied. Its
        // signed observation/finality is independently completed below.
        if let Ok(observation) = host.observe_durable_install(
            crate::service::AgentId(managed.agent.0),
            record.next.request(),
            &receipt,
        ) {
            if observation.managed() == managed {
                return Ok(());
            }
            return Err(SharedAgentHostError::ScopeMismatch);
        }
    }
    let (receipt, terminal) = issuer
        .recover_finalized_terminal(
            authority,
            managed,
            record.previous.request(),
            record.previous.call(),
            &RawCredentialVerifier,
        )
        .map_err(|_| SharedAgentHostError::ScopeMismatch)?
        .ok_or(SharedAgentHostError::ScopeMismatch)?;
    let observation = host.observe_durable_install(
        crate::service::AgentId(managed.agent.0),
        record.previous.request(),
        &receipt,
    )?;
    let matches = match terminal {
        SignedManagementTerminal::Applied(ack) => {
            observation.result() == &Ok(ack.application)
                && observation.reopened_state() == ack.reopened_state
                && observation.applied_at() == ack.applied_at
        }
        SignedManagementTerminal::Rejected(failure) => {
            observation.result() == &Err(failure.error)
                && observation.reopened_state() == failure.reopened_state
                && observation.applied_at() == failure.failed_at
        }
    };
    if matches && observation.managed() == managed {
        Ok(())
    } else {
        Err(SharedAgentHostError::ScopeMismatch)
    }
}

/// Owns the complete discovered reservation set and its archive leases through
/// recovery and serving. Construction validates ownership scope, not finality.
/// A signed Create before publication with bound runtime and replicas may lack
/// an archive; it stays retained and unroutable. Publication without its archive
/// fails closed.
pub struct NativeSharedGenesisController<I, J: CleanManagementIssuerStore, Q, R, W, P, A> {
    authority: AuthorityActorTarget,
    entries: Vec<(NativeSharedGenesisRecovery<I, J, Q, R, W, P>, Option<A>)>,
    recovered: bool,
    generations_recovered: bool,
}

impl<I, J, Q, R, W, P, A> NativeSharedGenesisController<I, J, Q, R, W, P, A>
where
    I: super::super::clean_authority_issuer::CleanManagementRuntimeStore,
    J: CleanManagementIssuerStore,
    Q: super::super::clean_authority_issuer::CleanSharedGenesisReplicaStore,
    R: CleanManagementIssuerStore,
    W: CleanManagementIssuerStore,
    P: CleanManagementIssuerStore,
    A: super::super::genesis_archive::AgentGenesisArchiveStore,
{
    pub fn new(
        authority: AuthorityActorTarget,
        mut entries: Vec<(NativeSharedGenesisRecovery<I, J, Q, R, W, P>, Option<A>)>,
    ) -> Result<Self, SharedAgentHostError> {
        if !authority.is_valid() {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        if entries.len() > super::super::shared_host::MAX_SHARED_HOST_AGENTS {
            return Err(SharedAgentHostError::CapacityExhausted);
        }
        if entries
            .iter()
            .any(|(recovery, _)| recovery.authority != authority || !recovery.admission_valid)
        {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        entries.sort_unstable_by_key(|(recovery, _)| recovery.locator.agent);
        if entries
            .windows(2)
            .any(|pair| pair[0].0.locator == pair[1].0.locator)
        {
            return Err(SharedAgentHostError::Conflict);
        }
        Ok(Self {
            authority,
            entries,
            recovered: false,
            generations_recovered: false,
        })
    }

    pub fn authority(&self) -> AuthorityActorTarget {
        self.authority
    }

    pub fn is_recovered(&self) -> bool {
        self.recovered
    }

    /// Retain a new signed, unissued Create after startup recovery. The factory
    /// may only reserve inputs and acquire leases: it must not execute Authority
    /// or provision a generation. Exact retries use the already-owned entry and
    /// never reopen its files. The returned locator is not an execution result.
    pub fn reserve_create_with<F>(
        &mut self,
        descriptor: &AgentDescriptor,
        call: &super::super::sdk::authority::AuthorityCredentialCall,
        runtime: &AdmittedRuntimePackage,
        replicas: &AgentReplicaCommittee,
        reserve: F,
    ) -> Result<super::super::genesis::AgentGenesisLocator, SharedAgentHostError>
    where
        F: FnOnce() -> Result<
            (NativeSharedGenesisRecovery<I, J, Q, R, W, P>, Option<A>),
            SharedAgentHostError,
        >,
    {
        if !self.recovered {
            return Err(SharedAgentHostError::Conflict);
        }
        let locator = super::super::genesis::AgentGenesisLocator {
            space: crate::service::SpaceId(self.authority.space.0),
            agent: crate::service::AgentId(descriptor.identity.agent.0),
        };
        let signed = NativeSharedGenesisRecovery::<I, J, Q, R, W, P>::validated_create_intent(
            self.authority,
            locator,
            descriptor,
            call,
            runtime,
            replicas,
        )?;
        let matches = |recovery: &mut NativeSharedGenesisRecovery<I, J, Q, R, W, P>| {
            Ok::<_, SharedAgentHostError>(
                recovery.authority == self.authority
                    && recovery.locator == locator
                    // Execution anchors/work grow after reservation. They are
                    // not caller inputs and cannot make an exact retry differ.
                    && recovery.intent.intent().is_some_and(|retained| {
                        retained.request() == signed.request() && retained.call() == signed.call()
                    })
                    && recovery
                        .runtime
                        .as_ref()
                        .map(AdmittedRuntimePackage::exact_bytes)
                        == Some(runtime.exact_bytes())
                    && recovery.retained_replicas()?.as_ref() == Some(replicas),
            )
        };
        let position = match self
            .entries
            .binary_search_by_key(&locator.agent, |(entry, _)| entry.locator.agent)
        {
            Ok(index) => {
                return if matches(&mut self.entries[index].0)? {
                    Ok(locator)
                } else {
                    Err(SharedAgentHostError::Conflict)
                };
            }
            Err(index) => index,
        };
        if self.entries.len() >= super::super::shared_host::MAX_SHARED_HOST_AGENTS {
            return Err(SharedAgentHostError::CapacityExhausted);
        }
        let (mut recovery, archive) = reserve()?;
        if !recovery.admission_valid
            || !matches(&mut recovery)?
            || recovery
                .intent
                .authorization_work()
                .map_err(|_| SharedAgentHostError::Unavailable)?
                .is_some()
            || !recovery.pending.is_empty()
            || recovery.issued.is_some()
            || recovery.retired
            || recovery.issuer.has_pending_application_observation()
            || recovery
                .intent
                .finalization_work()
                .map_err(|_| SharedAgentHostError::Unavailable)?
                .is_some()
            || archive
                .as_ref()
                .map(|archive| {
                    archive
                        .load(locator)
                        .map_err(|_| SharedAgentHostError::Unavailable)
                })
                .transpose()?
                .flatten()
                .is_some()
        {
            // Existing progressed entries must arrive through startup recovery,
            // not bypass its publication and physical-generation checks here.
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        self.entries.insert(position, (recovery, archive));
        Ok(locator)
    }

    #[cfg(test)]
    pub(super) fn into_entries_for_test(
        self,
    ) -> Vec<(NativeSharedGenesisRecovery<I, J, Q, R, W, P>, Option<A>)> {
        self.entries
    }

    /// Resume one signed, pre-archive Create through the retained lifecycle
    /// leases. The replica roster is re-admitted from its immutable sidecar;
    /// caller input cannot replace it after restart. The returned value binds
    /// the candidate to its independently queried committee for signing; it
    /// carries no signatures, publication, finality or route permission.
    pub fn prepare_pending_create<B, C, D, S>(
        &mut self,
        owner: &mut CleanSystemAgentBootstrapOwner<B, C, D>,
        locator: super::super::genesis::AgentGenesisLocator,
        receipt_signer: &mut S,
    ) -> Result<PreparedSharedGenesisEndorsement, SharedAgentHostError>
    where
        B: CleanSystemAgentBootstrapStore + Send + 'static,
        C: CleanSystemAgentBootstrapStore + Send + 'static,
        D: CleanManagementIssuerStore + Send + 'static,
        S: CleanManagementReceiptSigner,
    {
        if !self.recovered || owner.authority_target() != self.authority {
            return Err(SharedAgentHostError::Conflict);
        }
        let (recovery, archive) = self
            .entries
            .iter_mut()
            .find(|(recovery, _)| recovery.locator == locator)
            .ok_or(SharedAgentHostError::ScopeMismatch)?;
        if recovery.retired {
            return Err(SharedAgentHostError::Conflict);
        }
        if archive
            .as_ref()
            .map(|store| {
                store
                    .load(locator)
                    .map_err(|_| SharedAgentHostError::Unavailable)
            })
            .transpose()?
            .flatten()
            .is_some()
        {
            return Err(SharedAgentHostError::Conflict);
        }
        if owner.finish_denied_shared_genesis(recovery, receipt_signer)? {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        let replicas = recovery
            .retained_replicas()?
            .ok_or(SharedAgentHostError::ScopeMismatch)?;
        owner
            .host
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?
            .preflight_live_genesis_capacity(locator)?;
        let (candidate, committee) =
            match owner.resume_shared_genesis_preparation(recovery, &replicas, receipt_signer) {
                Ok(prepared) => prepared,
                Err(error) => {
                    owner.finish_denied_shared_genesis(recovery, receipt_signer)?;
                    return Err(error);
                }
            };
        Ok(PreparedSharedGenesisEndorsement {
            candidate,
            committee,
        })
    }

    pub(crate) fn endorse_pending_create<B, C, D, S, SignStore, K>(
        &mut self,
        owner: &mut CleanSystemAgentBootstrapOwner<B, C, D>,
        locator: super::super::genesis::AgentGenesisLocator,
        receipt_signer: &mut S,
        signature_store: &mut SignStore,
        genesis_signer: &mut K,
    ) -> Result<
        (
            AuthorizedSharedGenesisProposal,
            super::super::committee::AuthorityCommittee,
            super::super::committee::AuthoritySignature,
        ),
        SharedAgentHostError,
    >
    where
        B: CleanSystemAgentBootstrapStore + Send + 'static,
        C: CleanSystemAgentBootstrapStore + Send + 'static,
        D: CleanManagementIssuerStore + Send + 'static,
        S: CleanManagementReceiptSigner,
        SignStore: CleanManagementIssuerStore,
        K: super::genesis_issuance::GenesisClaimSigner,
    {
        let prepared = self.prepare_pending_create(owner, locator, receipt_signer)?;
        let signature = prepared.endorse(signature_store, genesis_signer)?;
        Ok((prepared.candidate, prepared.committee, signature))
    }

    /// Select and publish quorum evidence under the retained reservation and
    /// archive leases. The owner reauthenticates candidate/committee and checks
    /// the publication's positive ACK. Neither provisioning nor route exposure
    /// is part of this operation. Exact retry reuses the immutable archive.
    pub fn publish_pending_create<B, C, D, S>(
        &mut self,
        owner: &mut CleanSystemAgentBootstrapOwner<B, C, D>,
        locator: super::super::genesis::AgentGenesisLocator,
        signatures: Vec<super::super::committee::AuthoritySignature>,
        receipt_signer: &mut S,
    ) -> Result<super::super::genesis::AgentGenesisArchiveRecord, SharedAgentHostError>
    where
        B: CleanSystemAgentBootstrapStore + Send + 'static,
        C: CleanSystemAgentBootstrapStore + Send + 'static,
        D: CleanManagementIssuerStore + Send + 'static,
        S: CleanManagementReceiptSigner,
    {
        if !self.recovered || owner.authority_target() != self.authority {
            return Err(SharedAgentHostError::Conflict);
        }
        let (recovery, archive) = self
            .entries
            .iter_mut()
            .find(|(recovery, _)| recovery.locator == locator)
            .ok_or(SharedAgentHostError::ScopeMismatch)?;
        if recovery.retired {
            return Err(SharedAgentHostError::Conflict);
        }
        let archive = archive.as_ref().ok_or(SharedAgentHostError::Unavailable)?;
        if recovery
            .intent
            .denial_complete()
            .map_err(|_| SharedAgentHostError::Unavailable)?
        {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        let provider = super::super::genesis_archive::ArchivedAgentGenesisProvider::new(
            locator.space,
            archive,
        )
        .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
        let replicas = recovery
            .retained_replicas()?
            .ok_or(SharedAgentHostError::ScopeMismatch)?;
        // Endorsement collection can separate preparation from publication.
        // Recheck physical capacity before any publication-side Authority work.
        owner
            .host
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?
            .preflight_live_genesis_capacity(locator)?;
        owner.publish_recovered_shared_genesis(
            recovery,
            &replicas,
            receipt_signer,
            signatures,
            &provider,
        )
    }

    /// Complete physical application, signed finalization and retirement before
    /// admitting this generation. Exact terminal retries keep the original ACK
    /// and still require a fresh Authority check.
    pub fn complete_pending_create<B, C, D, S>(
        &mut self,
        owner: &mut CleanSystemAgentBootstrapOwner<B, C, D>,
        locator: super::super::genesis::AgentGenesisLocator,
        signer: &mut S,
    ) -> Result<ManagementApplicationAck, SharedAgentHostError>
    where
        B: CleanSystemAgentBootstrapStore + Send + 'static,
        C: CleanSystemAgentBootstrapStore + Send + 'static,
        D: CleanManagementIssuerStore + Send + 'static,
        S: CleanManagementReceiptSigner,
    {
        if !self.recovered || owner.authority_target() != self.authority {
            return Err(SharedAgentHostError::Conflict);
        }
        let predecessor = self.entries.iter().find_map(|(entry, _)| {
            (entry.locator != locator && !entry.retired && entry.admission_valid)
                .then(|| entry.pending.first().cloned())
                .flatten()
        });
        let (recovery, archive) = self
            .entries
            .iter_mut()
            .find(|(entry, _)| entry.locator == locator)
            .ok_or(SharedAgentHostError::ScopeMismatch)?;
        if recovery
            .intent
            .denial_complete()
            .map_err(|_| SharedAgentHostError::Unavailable)?
        {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        let archive = archive.as_ref().ok_or(SharedAgentHostError::Unavailable)?;
        let provider = super::super::genesis_archive::ArchivedAgentGenesisProvider::new(
            locator.space,
            archive,
        )
        .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
        let record = provider
            .load_record(locator)
            .map_err(|_| SharedAgentHostError::Unavailable)?
            .ok_or(SharedAgentHostError::Unavailable)?;
        owner.complete_live_shared_genesis(recovery, &record, signer, predecessor.as_ref())
    }

    /// Retain one continuing issuer only after authenticating the completed
    /// Create against the live generation and fresh Authority state. This does
    /// not execute or admit Install; the retained slot is still at Create.
    pub fn initialize_management<B, C, D, S>(
        &mut self,
        owner: &mut CleanSystemAgentBootstrapOwner<B, C, D>,
        locator: super::super::genesis::AgentGenesisLocator,
        signer: &mut S,
    ) -> Result<(), SharedAgentHostError>
    where
        B: CleanSystemAgentBootstrapStore + Send + 'static,
        C: CleanSystemAgentBootstrapStore + Send + 'static,
        D: CleanManagementIssuerStore + Send + 'static,
        J: super::super::clean_authority_issuer::CleanSharedManagementIssuerStore,
        I: super::super::clean_authority_issuer::CleanSharedManagementIntentStore,
        S: CleanManagementReceiptSigner,
    {
        if !self.recovered || owner.authority_target() != self.authority {
            return Err(SharedAgentHostError::Conflict);
        }
        if self
            .entries
            .iter()
            .any(|(entry, _)| entry.locator == locator && entry.management_issuer.is_some())
        {
            // The retained owner already authenticated genesis before opening
            // its continuation. Do not introduce a fresh read beside Install's
            // own protected reservation on an exact initialization retry.
            return Ok(());
        }
        self.complete_pending_create(owner, locator, signer)?;
        let (recovery, _) = self
            .entries
            .iter_mut()
            .find(|(entry, _)| entry.locator == locator)
            .ok_or(SharedAgentHostError::ScopeMismatch)?;
        recovery.initialize_management_issuer()
    }

    /// Retain validated Install inputs, without dispatching Authority or
    /// changing the physical generation. Execution and terminal recovery follow.
    pub fn prepare_install<B, C, D, S>(
        &mut self,
        owner: &mut CleanSystemAgentBootstrapOwner<B, C, D>,
        install: super::super::sdk::InstallActor,
        call: super::super::sdk::authority::AuthorityCredentialCall,
        package: &AdmittedActorPackage,
        signer: &mut S,
    ) -> Result<(), SharedAgentHostError>
    where
        B: CleanSystemAgentBootstrapStore + Send + 'static,
        C: CleanSystemAgentBootstrapStore + Send + 'static,
        D: CleanManagementIssuerStore + Send + 'static,
        I: super::super::clean_authority_issuer::CleanSharedManagementIntentStore,
        J: super::super::clean_authority_issuer::CleanSharedManagementIssuerStore,
        S: CleanManagementReceiptSigner,
    {
        let request = ManagementRequest::Install(Box::new(install));
        let index = self
            .entries
            .iter()
            .position(|(entry, _)| entry.locator.agent.0 == call.managed.agent.0)
            .ok_or(SharedAgentHostError::ScopeMismatch)?;
        let (recovery, _) = &self.entries[index];
        let original = recovery
            .intent
            .intent()
            .ok_or(SharedAgentHostError::ScopeMismatch)?;
        let ManagementRequest::Create(descriptor) = original.request() else {
            return Err(SharedAgentHostError::ScopeMismatch);
        };
        validate_actor_install(descriptor, &request, package)
            .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
        let descriptor = (**descriptor).clone();
        let intent = CleanManagementIntent::new(
            self.authority,
            original.call().managed,
            request,
            call,
            &RawCredentialVerifier,
        )
        .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
        if let Some(slot) = recovery.management_intent.as_ref() {
            if slot
                .intent()
                .is_some_and(|retained| !SharedInstallHandoff::matches(retained, &intent))
                && !slot
                    .retirement_complete()
                    .map_err(|_| SharedAgentHostError::Unavailable)?
            {
                return Err(SharedAgentHostError::Conflict);
            }
        }
        let locator = recovery.locator;
        self.initialize_management(owner, locator, signer)?;
        let recovery = &mut self.entries[index].0;
        let slot = recovery
            .management_intent
            .as_mut()
            .ok_or(SharedAgentHostError::Unavailable)?;
        if let Some(previous) = slot.intent().cloned() {
            if !SharedInstallHandoff::matches(&previous, &intent) {
                let record = SharedInstallHandoff::new(&previous, &intent, package)
                    .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
                let issuer = recovery
                    .management_issuer
                    .as_mut()
                    .ok_or(SharedAgentHostError::Unavailable)?;
                if issuer
                    .recover_finalized_terminal(
                        self.authority,
                        previous.call().managed,
                        previous.request(),
                        previous.call(),
                        &RawCredentialVerifier,
                    )
                    .map_err(|_| SharedAgentHostError::ScopeMismatch)?
                    .is_none()
                {
                    return Err(SharedAgentHostError::Conflict);
                }
                let previous_package = slot
                    .load_actor()
                    .map_err(|_| SharedAgentHostError::Unavailable)?
                    .ok_or(SharedAgentHostError::Unavailable)?;
                owner.complete_shared_install_from_management_intent(
                    slot,
                    &previous_package,
                    issuer,
                    signer,
                )?;
                slot.stage_shared_install_handoff(&record)
                    .map_err(|_| SharedAgentHostError::Unavailable)?;
                recover_shared_install_handoff(slot, issuer, self.authority, &descriptor)?;
            }
        }
        slot.pledge(intent)
            .map_err(|_| SharedAgentHostError::Conflict)?;
        slot.retain_actor(package)
            .map_err(|_| SharedAgentHostError::Unavailable)
    }

    /// Complete the already retained Install under this recovered controller.
    /// Exact retries use its existing issuer, package and reservation ownership.
    pub(crate) fn complete_install<B, C, D, S>(
        &mut self,
        owner: &mut CleanSystemAgentBootstrapOwner<B, C, D>,
        locator: super::super::genesis::AgentGenesisLocator,
        signer: &mut S,
    ) -> Result<SignedManagementTerminal, SharedAgentHostError>
    where
        B: CleanSystemAgentBootstrapStore + Send + 'static,
        C: CleanSystemAgentBootstrapStore + Send + 'static,
        D: CleanManagementIssuerStore + Send + 'static,
        I: super::super::clean_authority_issuer::CleanManagementActorStore,
        S: CleanManagementReceiptSigner,
    {
        if !self.recovered || owner.authority_target() != self.authority {
            return Err(SharedAgentHostError::Conflict);
        }
        let (recovery, _) = self
            .entries
            .iter_mut()
            .find(|(entry, _)| entry.locator == locator)
            .ok_or(SharedAgentHostError::ScopeMismatch)?;
        Self::complete_retained_install(owner, recovery, signer)
    }

    /// Borrow every store until bootstrap has admitted its retained work.
    pub fn startup_admission<'a>(
        &'a mut self,
        mut admission: NativeAuthorityOperationStartupAdmission<'a>,
    ) -> Result<NativeAuthorityOperationStartupAdmission<'a>, SharedAgentHostError> {
        if self.recovered {
            return Err(SharedAgentHostError::Conflict);
        }
        if admission.authority != self.authority {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        let empty = self.entries.is_empty();
        for (recovery, _) in &mut self.entries {
            admission = admission.include_shared_genesis(recovery)?;
        }
        Ok(if empty {
            admission
        } else {
            admission.with_deferred_shared_genesis()
        })
    }

    /// Re-read all leased archives before replaying any entry. A signed Create
    /// before publication stays an unroutable reservation, provided its runtime
    /// and independently selected replicas are durable and bound to that Create.
    /// Retained authorization/query work is reauthenticated through the owner;
    /// its reservations are not released. Every deferred generation requires
    /// a matching archive and independent live-history verification. An archive
    /// retained before provisioning can resume publication and stage its missing
    /// generation only if application has not been observed; archive signatures
    /// alone never grant finality. Errors retain all stores for an exact retry.
    pub fn recover<B, C, D, S>(
        &mut self,
        owner: &mut CleanSystemAgentBootstrapOwner<B, C, D>,
        signer: &mut S,
    ) -> Result<(), SharedAgentHostError>
    where
        B: CleanSystemAgentBootstrapStore + Send + 'static,
        C: CleanSystemAgentBootstrapStore + Send + 'static,
        D: CleanManagementIssuerStore + Send + 'static,
        I: super::super::clean_authority_issuer::CleanSharedManagementIntentStore,
        S: CleanManagementReceiptSigner,
    {
        if self.recovered {
            return Err(SharedAgentHostError::Conflict);
        }
        if owner.authority_target() != self.authority {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        if self.entries.is_empty() {
            owner.verify_empty_shared_genesis_startup()?;
            self.recovered = true;
            return Ok(());
        }
        owner.shared_lifecycle_recovery_pending = true;
        let records = self
            .entries
            .iter_mut()
            .map(|(recovery, archive)| {
                let bytes = archive
                    .as_ref()
                    .map(|archive| {
                        archive
                            .load(recovery.locator)
                            .map_err(|_| SharedAgentHostError::Unavailable)
                    })
                    .transpose()?
                    .flatten();
                let Some(bytes) = bytes else {
                    // Authorization and committee selection precede archive
                    // publication. Their presence is not evidence of a lost
                    // archive. Publication/finalization, however, require it.
                    if recovery.retired
                        || recovery.pending.len() > 2
                        || recovery.runtime.is_none()
                        || recovery.retained_replicas()?.is_none()
                    {
                        return Err(SharedAgentHostError::Unavailable);
                    }
                    return Ok(None);
                };
                if recovery.intent.denial_complete().map_err(|_| SharedAgentHostError::Unavailable)? {
                    return Err(SharedAgentHostError::ScopeMismatch);
                }
                if bytes.len() > super::super::genesis::MAX_AGENT_GENESIS_ARCHIVE_RECORD_BYTES {
                    return Err(SharedAgentHostError::ScopeMismatch);
                }
                let record = <super::super::genesis::AgentGenesisArchiveRecord as crate::service::ServiceWire>::decode(&bytes)
                    .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
                if record.provision().proposal().locator() != recovery.locator {
                    return Err(SharedAgentHostError::ScopeMismatch);
                }
                Ok(Some(record))
            })
            .collect::<Result<Vec<_>, _>>()?;
        // A crash may have retained the narrowly admitted verification read
        // beside its original Create. Drain only that child before replaying
        // lifecycle preparation, which continues to exclude ordinary reads.
        owner.recover_pending_authority_projection()?;
        // Replay retained system work before fresh reads can advance the clock
        // beyond its immutable preflight. Authorization only yields a receipt;
        // finalization only resumes an already signed application outcome.
        // Physical execution/evidence and fresh genesis authority remain gated
        // below, with route export closed throughout recovery.
        for (recovery, _) in &mut self.entries {
            if recovery.management_retirements.is_empty() && recovery.management_pending.is_empty()
            {
                continue;
            }
            let slot = recovery
                .management_intent
                .as_mut()
                .ok_or(SharedAgentHostError::ScopeMismatch)?;
            let issuer = recovery
                .management_issuer
                .as_mut()
                .ok_or(SharedAgentHostError::ScopeMismatch)?;
            let intent = slot.intent().ok_or(SharedAgentHostError::ScopeMismatch)?;
            let managed = intent.call().managed;
            let observed = issuer
                .recover_observed_terminal(
                    self.authority,
                    managed,
                    intent.request(),
                    intent.call(),
                    &RawCredentialVerifier,
                )
                .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
            if recovery.management_pending.len() == 1 {
                if observed.is_none() {
                    if let Err(error) = owner
                        .issue_management_intent_with_admission(slot, managed, issuer, signer, true)
                    {
                        if error != SharedAgentHostError::ScopeMismatch
                            || !owner.finish_denied_shared_install(slot, issuer, signer)?
                        {
                            return Err(error);
                        }
                        recovery.management_pending.clear();
                    }
                }
                // Approved work keeps its reservation until generation
                // verification and physical application prove a signed outcome.
                continue;
            }
            let (_, terminal) = observed.ok_or(SharedAgentHostError::ScopeMismatch)?;
            match terminal {
                SignedManagementTerminal::Applied(ack) => {
                    owner.finalize_management_intent_with_admission(
                        slot, managed, &ack, issuer, true,
                    )?;
                    owner.finish_live_management_intent(slot, managed, &ack, issuer)?
                }
                SignedManagementTerminal::Rejected(failure) => {
                    owner.finalize_failed_install_with_admission(
                        slot, managed, &failure, issuer, true,
                    )?;
                    owner.finish_live_failed_install(slot, managed, &failure, issuer)?
                }
            }
            recovery.management_pending.clear();
            recovery.management_retirements.clear();
        }
        for ((recovery, _), record) in self.entries.iter_mut().zip(&records) {
            if record.is_none() && owner.finish_denied_shared_genesis(recovery, signer)? {
                continue;
            }
            if record.is_none() && !recovery.pending.is_empty() {
                let replicas = recovery
                    .retained_replicas()?
                    .ok_or(SharedAgentHostError::ScopeMismatch)?;
                // Saved receipts and committee replies are not execution
                // authority. Replay their original journal intervals before
                // accepting the retained pre-publication phase. Do not endorse
                // genesis or mint an archive. Only a replay-proved denial may
                // discharge this unfinished Create instead of preparing it.
                if let Err(error) =
                    owner.resume_shared_genesis_preparation(recovery, &replicas, signer)
                {
                    if !owner.finish_denied_shared_genesis(recovery, signer)? {
                        return Err(error);
                    }
                }
            }
        }
        let predecessor = self
            .entries
            .iter()
            .zip(&records)
            .find_map(|((recovery, _), record)| {
                record
                    .is_none()
                    .then(|| recovery.pending.first().cloned())
                    .flatten()
            })
            .or_else(|| {
                self.entries
                    .iter()
                    .find_map(|(entry, _)| entry.management_pending.first().cloned())
            });
        let mut entries: Vec<_> = self
            .entries
            .iter_mut()
            .zip(&records)
            .filter_map(|((recovery, _), record)| record.as_ref().map(|record| (recovery, record)))
            .collect();
        if !self.generations_recovered {
            owner.recover_deferred_shared_generations_with_pending(
                &mut entries,
                signer,
                predecessor.as_ref(),
            )?;
            self.generations_recovered = true;
        }
        drop(entries);
        for (entry, _) in &mut self.entries {
            let Some(slot) = entry.management_intent.as_mut() else {
                continue;
            };
            if let Some(record) = slot
                .load_shared_install_handoff()
                .map_err(|_| SharedAgentHostError::Unavailable)?
            {
                verify_shared_handoff_generation(
                    owner,
                    &record,
                    entry
                        .management_issuer
                        .as_ref()
                        .ok_or(SharedAgentHostError::ScopeMismatch)?,
                )?;
            }
        }
        let mut installs = Vec::new();
        for (index, (entry, _)) in self.entries.iter().enumerate() {
            let Some(slot) = entry.management_intent.as_ref() else {
                continue;
            };
            if slot
                .denial_complete()
                .map_err(|_| SharedAgentHostError::Unavailable)?
            {
                continue;
            }
            let Some(anchor) = slot
                .authorization_anchor()
                .map_err(|_| SharedAgentHostError::Unavailable)?
            else {
                continue;
            };
            let intent = slot.intent().ok_or(SharedAgentHostError::ScopeMismatch)?;
            installs.push((
                anchor.ordered.index,
                intent.call().request_sequence.get(),
                entry.locator.agent,
                index,
            ));
        }
        installs.sort_unstable();
        for (_, _, _, index) in installs {
            Self::complete_retained_install(owner, &mut self.entries[index].0, signer)?;
        }
        owner.shared_lifecycle_recovery_pending = false;
        self.recovered = true;
        Ok(())
    }

    fn complete_retained_install<B, C, D, S>(
        owner: &mut CleanSystemAgentBootstrapOwner<B, C, D>,
        recovery: &mut NativeSharedGenesisRecovery<I, J, Q, R, W, P>,
        signer: &mut S,
    ) -> Result<SignedManagementTerminal, SharedAgentHostError>
    where
        B: CleanSystemAgentBootstrapStore + Send + 'static,
        C: CleanSystemAgentBootstrapStore + Send + 'static,
        D: CleanManagementIssuerStore + Send + 'static,
        I: super::super::clean_authority_issuer::CleanManagementActorStore,
        S: CleanManagementReceiptSigner,
    {
        let slot = recovery
            .management_intent
            .as_mut()
            .ok_or(SharedAgentHostError::ScopeMismatch)?;
        let issuer = recovery
            .management_issuer
            .as_mut()
            .ok_or(SharedAgentHostError::ScopeMismatch)?;
        if slot
            .denial_complete()
            .map_err(|_| SharedAgentHostError::Unavailable)?
        {
            owner.finish_denied_shared_install(slot, issuer, signer)?;
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        let package = slot
            .load_actor()
            .map_err(|_| SharedAgentHostError::Unavailable)?
            .ok_or(SharedAgentHostError::Unavailable)?;
        let terminal = match owner
            .complete_shared_install_from_management_intent(slot, &package, issuer, signer)
        {
            Ok(terminal) => terminal,
            Err(error) => {
                if error == SharedAgentHostError::ScopeMismatch
                    && owner.finish_denied_shared_install(slot, issuer, signer)?
                {
                    recovery.management_pending.clear();
                    recovery.management_retirements.clear();
                    return Err(SharedAgentHostError::ScopeMismatch);
                }
                return Err(error);
            }
        };
        recovery.management_pending.clear();
        recovery.management_retirements.clear();
        Ok(terminal)
    }
}

/// Owns the stores while bootstrap borrows their validated reservation data.
/// This authenticates the signed request, not execution, issuance or finality.
/// The owner must replay the authorization and reproduce its candidate before
/// executing any subsequent genesis phase.
pub struct NativeSharedGenesisRecovery<I, J: CleanManagementIssuerStore, Q, R, W, P> {
    locator: super::super::genesis::AgentGenesisLocator,
    pub(super) authority: AuthorityActorTarget,
    pub(super) pending: Vec<(ManagementJournalAnchor, RuntimeWork)>,
    pub(super) management_pending: Vec<(ManagementJournalAnchor, RuntimeWork)>,
    pub(super) management_retirements: Vec<[RuntimeWork; 2]>,
    pub(super) intent: CleanManagementIntentSlot<I>,
    pub(super) query: Q,
    pub(super) reply: R,
    pub(super) publication: W,
    pub(super) publication_reply: P,
    pub(super) runtime: Option<AdmittedRuntimePackage>,
    pub(super) issuer: DurableCleanManagementIssuer<J>,
    management_issuer: Option<DurableCleanManagementIssuer<J>>,
    management_intent: Option<CleanManagementIntentSlot<I>>,
    pub(super) issued: Option<AuthorityReceipt>,
    pub(super) admission_valid: bool,
    pub(super) retired: bool,
}

impl<
    I: super::super::clean_authority_issuer::CleanManagementRuntimeStore,
    J: CleanManagementIssuerStore,
    Q: CleanManagementIssuerStore,
    R: CleanManagementIssuerStore,
    W: CleanManagementIssuerStore,
    P: CleanManagementIssuerStore,
> NativeSharedGenesisRecovery<I, J, Q, R, W, P>
{
    /// File discovery retains an existing handoff under the original lease.
    /// Continuing work is classified separately from immutable Create evidence
    /// and must join startup admission before any system execution.
    /// The controller must still authenticate physical genesis before serving.
    fn reopen_management_handoff(&mut self) -> Result<(), SharedAgentHostError>
    where
        I: super::super::clean_authority_issuer::CleanSharedManagementIntentStore,
        J: super::super::clean_authority_issuer::CleanSharedManagementIssuerStore,
    {
        let mut candidate = self
            .intent
            .management_continuation_store()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        let inputs = candidate
            .load()
            .map_err(|_| SharedAgentHostError::Unavailable)?
            .is_some()
            || candidate
                .load_actor()
                .map_err(|_| SharedAgentHostError::Unavailable)?
                .is_some()
            || candidate
                .load_shared_install_handoff()
                .map_err(|_| SharedAgentHostError::Unavailable)?
                .is_some();
        if inputs
            && !self
                .issuer
                .creation_handoff_activated()
                .map_err(|_| SharedAgentHostError::Unavailable)?
        {
            return Err(SharedAgentHostError::Conflict);
        }
        if self
            .issuer
            .creation_continuation_retained()
            .map_err(|_| SharedAgentHostError::Unavailable)?
            || inputs
        {
            self.initialize_management_issuer()?;
        }
        Ok(())
    }

    fn initialize_management_issuer(&mut self) -> Result<(), SharedAgentHostError>
    where
        I: super::super::clean_authority_issuer::CleanSharedManagementIntentStore,
        J: super::super::clean_authority_issuer::CleanSharedManagementIssuerStore,
    {
        if !self.retired || !self.admission_valid || !self.pending.is_empty() {
            return Err(SharedAgentHostError::Conflict);
        }
        if self.management_issuer.is_some() {
            return Ok(());
        }
        let mut store = self
            .intent
            .management_continuation_store()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        let actor = store
            .load_actor()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        let mut slot = CleanManagementIntentSlot::open(store)
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        let continuation = self
            .issuer
            .open_creation_continuation()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        let original = self
            .intent
            .intent()
            .ok_or(SharedAgentHostError::ScopeMismatch)?;
        let ManagementRequest::Create(descriptor) = original.request() else {
            return Err(SharedAgentHostError::ScopeMismatch);
        };
        recover_shared_install_handoff(&mut slot, &continuation, self.authority, descriptor)?;
        if let Some(pending) = slot.intent().cloned() {
            if !self
                .issuer
                .creation_handoff_activated()
                .map_err(|_| SharedAgentHostError::Unavailable)?
                || !matches!(pending.request(), ManagementRequest::Install(_))
            {
                return Err(SharedAgentHostError::Conflict);
            }
            let original = self
                .intent
                .intent()
                .ok_or(SharedAgentHostError::ScopeMismatch)?;
            pending
                .verify(
                    self.authority,
                    original.call().managed,
                    &RawCredentialVerifier,
                )
                .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
            let ManagementRequest::Create(descriptor) = original.request() else {
                return Err(SharedAgentHostError::ScopeMismatch);
            };
            if let Some(package) = slot
                .load_actor()
                .map_err(|_| SharedAgentHostError::Unavailable)?
            {
                validate_actor_install(descriptor, pending.request(), &package)
                    .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
            } else if slot
                .authorization_work()
                .map_err(|_| SharedAgentHostError::Unavailable)?
                .is_some()
            {
                return Err(SharedAgentHostError::Unavailable);
            }
        } else if actor.is_some() {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        let mut pending_work = Vec::new();
        let mut retirements = Vec::new();
        if let Some(intent) = slot.intent() {
            let issued = continuation
                .recover_issued_application(
                    self.authority,
                    intent.call().managed,
                    intent.request(),
                    intent.call(),
                    &RawCredentialVerifier,
                )
                .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
            let observed = continuation
                .recover_observed_terminal(
                    self.authority,
                    intent.call().managed,
                    intent.request(),
                    intent.call(),
                    &RawCredentialVerifier,
                )
                .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
            let finalized = continuation
                .recover_finalized_terminal(
                    self.authority,
                    intent.call().managed,
                    intent.request(),
                    intent.call(),
                    &RawCredentialVerifier,
                )
                .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
            let retired = slot
                .retirement_complete()
                .map_err(|_| SharedAgentHostError::Unavailable)?;
            let denied = slot
                .denial_complete()
                .map_err(|_| SharedAgentHostError::Unavailable)?;
            let authorization = slot
                .authorization_work()
                .map_err(|_| SharedAgentHostError::Unavailable)?;
            let finalization = slot
                .finalization_work()
                .map_err(|_| SharedAgentHostError::Unavailable)?;
            if (denied
                && (retired
                    || issued.is_some()
                    || observed.is_some()
                    || finalized.is_some()
                    || authorization.is_none()
                    || finalization.is_some()
                    || continuation.has_pending_decision()
                    || continuation.has_pending_application_observation()))
                || (retired && finalized.is_none())
                || (finalized.is_some() && finalized != observed)
                || observed.as_ref().is_some_and(|(receipt, _)| {
                    issued.as_ref() != Some(receipt)
                        || continuation.has_pending_decision()
                        || continuation.retained_decisions() != 0
                        || continuation.sequence_high_water() != continuation.acknowledged_through()
                })
            {
                return Err(SharedAgentHostError::ScopeMismatch);
            }
            if issued.is_none()
                && !continuation
                    .can_resume_install(
                        self.authority,
                        intent.call().managed,
                        intent.request(),
                        intent.call(),
                        &RawCredentialVerifier,
                    )
                    .map_err(|_| SharedAgentHostError::ScopeMismatch)?
            {
                return Err(SharedAgentHostError::ScopeMismatch);
            }
            if let Some(work) = finalization {
                let (_, terminal) = observed
                    .as_ref()
                    .ok_or(SharedAgentHostError::ScopeMismatch)?;
                let Some(RuntimeWork::Invoke { observed_slot, .. }) = authorization else {
                    return Err(SharedAgentHostError::ScopeMismatch);
                };
                let RuntimeWork::Invoke { invocation, .. } = work else {
                    return Err(SharedAgentHostError::ScopeMismatch);
                };
                if terminal.applied_at() < *observed_slot
                    || invocation.message != terminal.finalization_message()
                {
                    return Err(SharedAgentHostError::ScopeMismatch);
                }
            }
            match (authorization, finalization) {
                (Some(_), None) if denied => {}
                (None, None)
                    if issued.is_none()
                        && !continuation.has_pending_decision()
                        && !continuation.has_pending_application_observation()
                        && observed.is_none() => {}
                (Some(first), Some(last)) if finalized.is_some() => {
                    if !retired {
                        retirements.push([first.clone(), last.clone()]);
                    }
                }
                (Some(first), last) if finalized.is_none() => {
                    pending_work.push((
                        slot.authorization_anchor()
                            .map_err(|_| SharedAgentHostError::Unavailable)?
                            .ok_or(SharedAgentHostError::ScopeMismatch)?
                            .clone(),
                        first.clone(),
                    ));
                    if let Some(last) = last {
                        pending_work.push((
                            slot.finalization_anchor()
                                .map_err(|_| SharedAgentHostError::Unavailable)?
                                .ok_or(SharedAgentHostError::ScopeMismatch)?
                                .clone(),
                            last.clone(),
                        ));
                    }
                }
                _ => return Err(SharedAgentHostError::ScopeMismatch),
            }
        } else if !self.issuer.matches_creation_checkpoint(&continuation) {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        self.management_pending = pending_work;
        self.management_retirements = retirements;
        self.management_issuer = Some(continuation);
        self.management_intent = Some(slot);
        Ok(())
    }

    /// Validate exact signed inputs before a file factory allocates per-Agent
    /// stores. This grants no Authority approval, reservation or route. The
    /// actual reservation repeats this validation before writing any inputs.
    pub fn validate_create_reservation(
        authority: AuthorityActorTarget,
        locator: super::super::genesis::AgentGenesisLocator,
        descriptor: &AgentDescriptor,
        call: &super::super::sdk::authority::AuthorityCredentialCall,
        runtime: &AdmittedRuntimePackage,
        replicas: &AgentReplicaCommittee,
    ) -> Result<(), SharedAgentHostError> {
        Self::validated_create_intent(authority, locator, descriptor, call, runtime, replicas)
            .map(|_| ())
    }

    fn validated_create_intent(
        authority: AuthorityActorTarget,
        locator: super::super::genesis::AgentGenesisLocator,
        descriptor: &AgentDescriptor,
        call: &super::super::sdk::authority::AuthorityCredentialCall,
        runtime: &AdmittedRuntimePackage,
        replicas: &AgentReplicaCommittee,
    ) -> Result<CleanManagementIntent, SharedAgentHostError> {
        locator
            .validate()
            .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
        if authority.space != descriptor.identity.space
            || locator.space.0 != descriptor.identity.space.0
            || locator.agent.0 != descriptor.identity.agent.0
            || replicas.validate_for_clean_descriptor(descriptor).is_err()
        {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        super::super::driver::verify_clean_runtime_package_binding(descriptor, runtime)
            .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
        CleanManagementIntent::new(
            authority,
            call.managed,
            ManagementRequest::Create(Box::new(descriptor.clone())),
            call.clone(),
            &RawCredentialVerifier,
        )
        .map_err(|_| SharedAgentHostError::ScopeMismatch)
    }

    /// First-release Shared reservation: durably stage the exact package and
    /// independently selected peer roster before pledging the signed Create.
    /// A crash before the pledge leaves an inert candidate; a crash after it
    /// leaves both inputs available for phase-aware recovery. No Authority
    /// work or route is admitted here.
    pub fn reserve_create_with_replicas(
        authority: AuthorityActorTarget,
        locator: super::super::genesis::AgentGenesisLocator,
        descriptor: AgentDescriptor,
        call: super::super::sdk::authority::AuthorityCredentialCall,
        runtime: AdmittedRuntimePackage,
        replicas: AgentReplicaCommittee,
        stores: (I, J, Q, R, W, P),
    ) -> Result<Self, SharedAgentHostError>
    where
        I: super::super::clean_authority_issuer::CleanManagementActorStore
            + super::super::clean_authority_issuer::CleanExternalLocalCreateArchiveStore,
        Q: super::super::clean_authority_issuer::CleanSharedGenesisReplicaStore,
    {
        let signed = Self::validated_create_intent(
            authority,
            locator,
            &descriptor,
            &call,
            &runtime,
            &replicas,
        )?;
        let (
            intent_store,
            mut issuer,
            mut query,
            mut reply,
            mut publication,
            mut publication_reply,
        ) = stores;
        let intent = CleanManagementIntentSlot::open(intent_store)
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        let selected = replicas.encode();
        if intent.intent().is_some() {
            let mut recovered = Self::open(
                authority,
                locator,
                intent.into_store(),
                issuer,
                query,
                reply,
                publication,
                publication_reply,
            )?;
            recovered
                .intent
                .pledge(signed)
                .map_err(|_| SharedAgentHostError::Conflict)?;
            if recovered
                .runtime
                .as_ref()
                .map(AdmittedRuntimePackage::exact_bytes)
                != Some(runtime.exact_bytes())
                || recovered.retained_replicas()? != Some(replicas)
            {
                return Err(SharedAgentHostError::Conflict);
            }
            return Ok(recovered);
        }
        let mut intent_store = intent.into_store();
        if issuer
            .load()
            .map_err(|_| SharedAgentHostError::Unavailable)?
            .is_some()
            || query
                .load()
                .map_err(|_| SharedAgentHostError::Unavailable)?
                .is_some()
            || reply
                .load()
                .map_err(|_| SharedAgentHostError::Unavailable)?
                .is_some()
            || publication
                .load()
                .map_err(|_| SharedAgentHostError::Unavailable)?
                .is_some()
            || publication_reply
                .load()
                .map_err(|_| SharedAgentHostError::Unavailable)?
                .is_some()
            || intent_store
                .load_actor()
                .map_err(|_| SharedAgentHostError::Unavailable)?
                .is_some()
            || intent_store
                .load_external_create_archive()
                .map_err(|_| SharedAgentHostError::Unavailable)?
                .is_some()
        {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        match query
            .load_replicas()
            .map_err(|_| SharedAgentHostError::Unavailable)?
        {
            Some(existing) if existing == selected => (),
            Some(_) => return Err(SharedAgentHostError::Conflict),
            None => query
                .commit_replicas(&selected)
                .map_err(|_| SharedAgentHostError::Unavailable)?,
        }
        match intent_store
            .load_runtime()
            .map_err(|_| SharedAgentHostError::Unavailable)?
        {
            Some(existing) if existing == runtime.exact_bytes() => (),
            Some(_) => return Err(SharedAgentHostError::Conflict),
            None => intent_store
                .commit_runtime(runtime.exact_bytes())
                .map_err(|_| SharedAgentHostError::Unavailable)?,
        }
        let mut intent = CleanManagementIntentSlot::open(intent_store)
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        intent
            .pledge(signed)
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        Self::open(
            authority,
            locator,
            intent.into_store(),
            issuer,
            query,
            reply,
            publication,
            publication_reply,
        )
    }

    /// Retain an exact signed Shared Create and its admitted runtime before any
    /// authorization execution. This reserves durable inputs only: it grants no
    /// authority receipt, finality or permission to publish a route.
    ///
    /// Existing reservations must pass full recovery before retry can fill a
    /// missing runtime. Orphan phase images are never repaired by a fresh call.
    pub fn reserve_create(
        authority: AuthorityActorTarget,
        locator: super::super::genesis::AgentGenesisLocator,
        descriptor: AgentDescriptor,
        call: super::super::sdk::authority::AuthorityCredentialCall,
        runtime: AdmittedRuntimePackage,
        stores: (I, J, Q, R, W, P),
    ) -> Result<Self, SharedAgentHostError>
    where
        Q: super::super::clean_authority_issuer::CleanSharedGenesisReplicaStore,
    {
        locator
            .validate()
            .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
        if descriptor.identity.profile != AgentProfile::Shared
            || descriptor.identity.space.0 != locator.space.0
            || descriptor.identity.agent.0 != locator.agent.0
            || authority.space != descriptor.identity.space
        {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        super::super::driver::verify_clean_runtime_package_binding(&descriptor, &runtime)
            .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
        let signed = crate::agent::clean_management_intent::CleanManagementIntent::new(
            authority,
            call.managed,
            ManagementRequest::Create(Box::new(descriptor)),
            call,
            &RawCredentialVerifier,
        )
        .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
        let (
            intent_store,
            mut issuer,
            mut query,
            mut reply,
            mut publication,
            mut publication_reply,
        ) = stores;
        let mut intent = CleanManagementIntentSlot::open(intent_store)
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        if intent.intent().is_some() {
            let mut recovered = Self::open(
                authority,
                locator,
                intent.into_store(),
                issuer,
                query,
                reply,
                publication,
                publication_reply,
            )?;
            recovered
                .intent
                .pledge(signed)
                .map_err(|_| SharedAgentHostError::Conflict)?;
            recovered
                .intent
                .retain_runtime(runtime.exact_bytes())
                .map_err(|_| SharedAgentHostError::Unavailable)?;
            let (intent, issuer, query, reply, publication, publication_reply) =
                recovered.into_stores();
            return Self::open(
                authority,
                locator,
                intent,
                issuer,
                query,
                reply,
                publication,
                publication_reply,
            );
        }
        if intent
            .load_runtime()
            .map_err(|_| SharedAgentHostError::Unavailable)?
            .is_some()
            || issuer
                .load()
                .map_err(|_| SharedAgentHostError::Unavailable)?
                .is_some()
            || query
                .load()
                .map_err(|_| SharedAgentHostError::Unavailable)?
                .is_some()
            || reply
                .load()
                .map_err(|_| SharedAgentHostError::Unavailable)?
                .is_some()
            || publication
                .load()
                .map_err(|_| SharedAgentHostError::Unavailable)?
                .is_some()
            || publication_reply
                .load()
                .map_err(|_| SharedAgentHostError::Unavailable)?
                .is_some()
        {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        intent
            .pledge(signed)
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        // A crash between these commits leaves a signed reservation with no
        // runtime; only an exact retry may complete it.
        intent
            .retain_runtime(runtime.exact_bytes())
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        Self::open(
            authority,
            locator,
            intent.into_store(),
            issuer,
            query,
            reply,
            publication,
            publication_reply,
        )
    }

    pub fn open(
        authority: AuthorityActorTarget,
        locator: super::super::genesis::AgentGenesisLocator,
        intent_store: I,
        issuer_store: J,
        query: Q,
        reply: R,
        publication: W,
        publication_reply: P,
    ) -> Result<Self, SharedAgentHostError>
    where
        Q: super::super::clean_authority_issuer::CleanSharedGenesisReplicaStore,
    {
        Self::open_inner(
            authority,
            locator,
            intent_store,
            issuer_store,
            query,
            reply,
            publication,
            publication_reply,
            false,
        )
    }

    /// Discover original Create and its continuing issuer together. Ordinary
    /// `open` refuses handed-off sources, so no caller can accidentally admit
    /// the Create while forgetting later management state.
    pub fn open_with_management_handoff(
        authority: AuthorityActorTarget,
        locator: super::super::genesis::AgentGenesisLocator,
        intent_store: I,
        issuer_store: J,
        query: Q,
        reply: R,
        publication: W,
        publication_reply: P,
    ) -> Result<Self, SharedAgentHostError>
    where
        I: super::super::clean_authority_issuer::CleanSharedManagementIntentStore,
        J: super::super::clean_authority_issuer::CleanSharedManagementIssuerStore,
        Q: super::super::clean_authority_issuer::CleanSharedGenesisReplicaStore,
    {
        let mut recovery = Self::open_inner(
            authority,
            locator,
            intent_store,
            issuer_store,
            query,
            reply,
            publication,
            publication_reply,
            true,
        )?;
        recovery.reopen_management_handoff()?;
        Ok(recovery)
    }

    fn open_inner(
        authority: AuthorityActorTarget,
        locator: super::super::genesis::AgentGenesisLocator,
        intent_store: I,
        mut issuer_store: J,
        mut query: Q,
        mut reply: R,
        mut publication: W,
        mut publication_reply: P,
        include_handoff: bool,
    ) -> Result<Self, SharedAgentHostError>
    where
        Q: super::super::clean_authority_issuer::CleanSharedGenesisReplicaStore,
    {
        if issuer_store
            .issuance_disabled()
            .map_err(|_| SharedAgentHostError::Unavailable)?
            && !include_handoff
        {
            return Err(SharedAgentHostError::Conflict);
        }
        locator
            .validate()
            .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
        let mut intent = CleanManagementIntentSlot::open(intent_store)
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        let request = intent.intent().ok_or(SharedAgentHostError::ScopeMismatch)?;
        request
            .verify(authority, request.call().managed, &RawCredentialVerifier)
            .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
        let ManagementRequest::Create(descriptor) = request.request() else {
            return Err(SharedAgentHostError::ScopeMismatch);
        };
        if descriptor.identity.profile != AgentProfile::Shared
            || descriptor.identity.space.0 != locator.space.0
            || descriptor.identity.agent.0 != locator.agent.0
        {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        let denied = intent
            .denial_complete()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        let retired = intent
            .retirement_complete()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        let descriptor = (**descriptor).clone();
        let issuer = DurableCleanManagementIssuer::open(
            issuer_store,
            descriptor.authority,
            descriptor.identity.space,
            descriptor.identity.agent,
        )
        .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
        let issued = issuer
            .recover_issued_application(
                authority,
                request.call().managed,
                request.request(),
                request.call(),
                &RawCredentialVerifier,
            )
            .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
        let observed = issuer
            .recover_observed_application(
                authority,
                request.call().managed,
                request.request(),
                request.call(),
                &RawCredentialVerifier,
            )
            .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
        if retired
            && issuer
                .recover_finalized_application(
                    authority,
                    request.call().managed,
                    request.request(),
                    request.call(),
                    &RawCredentialVerifier,
                )
                .map_err(|_| SharedAgentHostError::ScopeMismatch)?
                != observed
        {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        if observed.as_ref().is_some_and(|(receipt, _)| {
            issued.as_ref() != Some(receipt)
                || issuer.has_pending_decision()
                || issuer.retained_decisions() != 0
                || issuer.sequence_high_water() != issuer.acknowledged_through()
        }) || (issued.is_none()
            && !issuer
                .can_resume_initial_creation(
                    authority,
                    request.call().managed,
                    request.request(),
                    request.call(),
                    &RawCredentialVerifier,
                )
                .map_err(|_| SharedAgentHostError::ScopeMismatch)?)
        {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        let finalization = intent
            .finalization_work()
            .map_err(|_| SharedAgentHostError::Unavailable)?
            .cloned();
        if let Some(work) = &finalization {
            let (_, acknowledgement) = observed
                .as_ref()
                .ok_or(SharedAgentHostError::ScopeMismatch)?;
            let RuntimeWork::Invoke { invocation, .. } = work else {
                return Err(SharedAgentHostError::ScopeMismatch);
            };
            let Some(RuntimeWork::Invoke { observed_slot, .. }) = intent
                .authorization_work()
                .map_err(|_| SharedAgentHostError::Unavailable)?
            else {
                return Err(SharedAgentHostError::ScopeMismatch);
            };
            if acknowledgement.applied_at < *observed_slot
                || invocation.message
                    != CleanManagementIntent::finalization_message(acknowledgement)
            {
                return Err(SharedAgentHostError::ScopeMismatch);
            }
        }
        let runtime = intent
            .load_runtime()
            .map_err(|_| SharedAgentHostError::Unavailable)?
            .map(|bytes| {
                let package = super::super::package_admission::admit_runtime_package(&bytes)
                    .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
                super::super::driver::verify_clean_runtime_package_binding(&descriptor, &package)
                    .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
                Ok(package)
            })
            .transpose()?;
        let anchor = intent
            .authorization_anchor()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        let work = intent
            .authorization_work()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        let mut pending = Vec::new();
        match (anchor, work) {
            (Some(anchor), Some(work)) => {
                if runtime.is_none() {
                    return Err(SharedAgentHostError::ScopeMismatch);
                }
                pending.push((anchor.clone(), work.clone()));
                if let Some(saved) =
                    RetainedCommitteeQuery::load_for_recovery(&mut query, &authority, anchor, work)
                        .map_err(|_| SharedAgentHostError::ScopeMismatch)?
                {
                    if issued.is_none() {
                        return Err(SharedAgentHostError::ScopeMismatch);
                    }
                    let RuntimeWork::Invoke {
                        invocation,
                        authorization,
                        ..
                    } = &saved.work
                    else {
                        return Err(SharedAgentHostError::ScopeMismatch);
                    };
                    // Existing reply bytes must be canonical and belong to this
                    // exact query, but are never used as execution authority.
                    genesis_issuance::load_committee_reply(
                        &mut reply,
                        invocation,
                        authorization,
                        &authority,
                    )
                    .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
                    let published =
                        genesis_issuance::RetainedGenesisPublication::load_for_recovery(
                            &mut publication,
                            &authority,
                            &saved,
                        )
                        .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
                    pending.push((saved.anchor, saved.work));
                    if let Some(saved) = published {
                        genesis_issuance::load_publication_reply(&mut publication_reply, &saved)
                            .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
                        pending.push((saved.anchor, saved.work));
                    } else if publication_reply
                        .load()
                        .map_err(|_| SharedAgentHostError::Unavailable)?
                        .is_some()
                    {
                        return Err(SharedAgentHostError::ScopeMismatch);
                    }
                } else if reply
                    .load()
                    .map_err(|_| SharedAgentHostError::Unavailable)?
                    .is_some()
                    || publication
                        .load()
                        .map_err(|_| SharedAgentHostError::Unavailable)?
                        .is_some()
                    || publication_reply
                        .load()
                        .map_err(|_| SharedAgentHostError::Unavailable)?
                        .is_some()
                {
                    return Err(SharedAgentHostError::ScopeMismatch);
                }
            }
            (None, None) => {
                if issued.is_some()
                    || issuer.has_pending_decision()
                    || issuer.sequence_high_water() != 0
                    || query
                        .load()
                        .map_err(|_| SharedAgentHostError::Unavailable)?
                        .is_some()
                    || reply
                        .load()
                        .map_err(|_| SharedAgentHostError::Unavailable)?
                        .is_some()
                    || publication
                        .load()
                        .map_err(|_| SharedAgentHostError::Unavailable)?
                        .is_some()
                    || publication_reply
                        .load()
                        .map_err(|_| SharedAgentHostError::Unavailable)?
                        .is_some()
                {
                    return Err(SharedAgentHostError::ScopeMismatch);
                }
            }
            _ => return Err(SharedAgentHostError::ScopeMismatch),
        }
        if retired && (finalization.is_none() || observed.is_none()) {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        if let Some(work) = finalization {
            // Publication must precede application finalization. An incomplete
            // earlier phase cannot be hidden by a signed application ACK.
            if pending.len() != 3 {
                return Err(SharedAgentHostError::ScopeMismatch);
            }
            let anchor = intent
                .finalization_anchor()
                .map_err(|_| SharedAgentHostError::Unavailable)?
                .ok_or(SharedAgentHostError::ScopeMismatch)?;
            pending.push((anchor.clone(), work));
        }
        // A completed lifecycle no longer reserves old journal anchors. Its
        // archive is still untrusted: recovery must obtain a fresh decision
        // from the live pinned Authority before opening the generation.
        if denied {
            if retired
                || issued.is_some()
                || observed.is_some()
                || pending.len() != 1
                || issuer.sequence_high_water() != 0
                || issuer.has_pending_decision()
                || issuer.retained_decisions() != 0
            {
                return Err(SharedAgentHostError::ScopeMismatch);
            }
            pending.clear();
        } else if retired {
            pending.clear();
        }
        let mut recovered = Self {
            locator,
            authority,
            pending,
            management_pending: Vec::new(),
            management_retirements: Vec::new(),
            intent,
            query,
            reply,
            publication,
            publication_reply,
            runtime,
            issuer,
            management_issuer: None,
            management_intent: None,
            issued,
            admission_valid: true,
            retired,
        };
        // A roster sidecar is untrusted storage, even if its role envelope is
        // intact. Validate any present candidate before startup admission;
        // absence is still possible on the legacy/pre-staging test path.
        recovered.retained_replicas()?;
        Ok(recovered)
    }

    /// The exact locator checked against the signed Create during opening.
    /// This identifies the reservation; it is not proof of publication/finality.
    pub fn locator(&self) -> super::super::genesis::AgentGenesisLocator {
        self.locator
    }

    /// Admitted, descriptor-bound package retained before authorization.
    pub fn runtime(&self) -> Option<&AdmittedRuntimePackage> {
        self.runtime.as_ref()
    }

    pub fn issued_receipt(&self) -> Option<&AuthorityReceipt> {
        self.issued.as_ref()
    }

    /// Re-admit a retained replica roster under the same committee lease as
    /// the query. The file envelope is not authority: peer identities must be
    /// canonical and the roster must match the already verified signed Create.
    pub fn retained_replicas(
        &mut self,
    ) -> Result<Option<AgentReplicaCommittee>, SharedAgentHostError>
    where
        Q: super::super::clean_authority_issuer::CleanSharedGenesisReplicaStore,
    {
        let Some(bytes) = self
            .query
            .load_replicas()
            .map_err(|_| SharedAgentHostError::Unavailable)?
        else {
            return Ok(None);
        };
        if bytes.len() > MAX_AGENT_REPLICA_COMMITTEE_BYTES {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        let replicas = AgentReplicaCommittee::decode(&bytes)
            .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
        let Some(ManagementRequest::Create(descriptor)) =
            self.intent.intent().map(CleanManagementIntent::request)
        else {
            return Err(SharedAgentHostError::ScopeMismatch);
        };
        if replicas.encode() != bytes || replicas.validate_for_clean_descriptor(descriptor).is_err()
        {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        Ok(Some(replicas))
    }

    /// Return the still-leased stores for the owning lifecycle controller.
    pub fn into_stores(self) -> (I, J, Q, R, W, P) {
        (
            self.intent.into_store(),
            self.issuer.into_store(),
            self.query,
            self.reply,
            self.publication,
            self.publication_reply,
        )
    }
}
