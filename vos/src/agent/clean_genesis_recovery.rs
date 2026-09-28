//! Leased reservation recovery for ordinary Shared Create through publication.

use super::genesis_issuance::RetainedCommitteeQuery;
use super::*;
use crate::agent::clean_management_intent::{
    CleanManagementIntent, CleanManagementIntentSlot, ManagementJournalAnchor,
};

/// Owns the complete discovered reservation set and its archive leases through
/// recovery and serving. Construction validates ownership scope, not finality.
/// A signed Create before publication with bound runtime and replicas may lack
/// an archive; it stays retained and unroutable. Publication without its archive
/// fails closed.
pub struct NativeSharedGenesisController<I, J: CleanManagementIssuerStore, Q, R, W, P, A> {
    authority: AuthorityActorTarget,
    entries: Vec<(NativeSharedGenesisRecovery<I, J, Q, R, W, P>, Option<A>)>,
    recovered: bool,
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
                    && recovery.intent.intent() == Some(&signed)
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
        let replicas = recovery
            .retained_replicas()?
            .ok_or(SharedAgentHostError::ScopeMismatch)?;
        let (candidate, committee) =
            owner.resume_shared_genesis_preparation(recovery, &replicas, receipt_signer)?;
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
        let provider = super::super::genesis_archive::ArchivedAgentGenesisProvider::new(
            locator.space,
            archive,
        )
        .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
        let replicas = recovery
            .retained_replicas()?
            .ok_or(SharedAgentHostError::ScopeMismatch)?;
        owner.publish_recovered_shared_genesis(
            recovery,
            &replicas,
            receipt_signer,
            signatures,
            &provider,
        )
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
        for ((recovery, _), record) in self.entries.iter_mut().zip(&records) {
            if record.is_none() && !recovery.pending.is_empty() {
                let replicas = recovery
                    .retained_replicas()?
                    .ok_or(SharedAgentHostError::ScopeMismatch)?;
                // Saved receipts and committee replies are not execution
                // authority. Replay their original journal intervals before
                // accepting the retained pre-publication phase. Do not endorse
                // genesis, mint an archive or discharge the unfinished Create.
                owner.resume_shared_genesis_preparation(recovery, &replicas, signer)?;
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
            });
        let mut entries: Vec<_> = self
            .entries
            .iter_mut()
            .zip(&records)
            .filter_map(|((recovery, _), record)| record.as_ref().map(|record| (recovery, record)))
            .collect();
        owner.recover_deferred_shared_generations_with_pending(
            &mut entries,
            signer,
            predecessor.as_ref(),
        )?;
        self.recovered = true;
        Ok(())
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
    pub(super) intent: CleanManagementIntentSlot<I>,
    pub(super) query: Q,
    pub(super) reply: R,
    pub(super) publication: W,
    pub(super) publication_reply: P,
    pub(super) runtime: Option<AdmittedRuntimePackage>,
    pub(super) issuer: DurableCleanManagementIssuer<J>,
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
        mut query: Q,
        mut reply: R,
        mut publication: W,
        mut publication_reply: P,
    ) -> Result<Self, SharedAgentHostError>
    where
        Q: super::super::clean_authority_issuer::CleanSharedGenesisReplicaStore,
    {
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
            || intent
                .denial_complete()
                .map_err(|_| SharedAgentHostError::Unavailable)?
        {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
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
        if retired {
            pending.clear();
        }
        let mut recovered = Self {
            locator,
            authority,
            pending,
            intent,
            query,
            reply,
            publication,
            publication_reply,
            runtime,
            issuer,
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
