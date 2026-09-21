//! Leased reservation recovery for ordinary Shared Create through publication.

use super::genesis_issuance::RetainedCommitteeQuery;
use super::*;
use crate::agent::clean_management_intent::{
    CleanManagementIntent, CleanManagementIntentSlot, ManagementJournalAnchor,
};

/// Owns the complete discovered reservation set and its archive leases through
/// recovery and serving. Construction validates ownership scope, not finality.
/// Missing archives are retained as incomplete work, never silently filtered.
pub struct NativeSharedGenesisController<I, J: CleanManagementIssuerStore, Q, R, W, P, A> {
    authority: AuthorityActorTarget,
    entries: Vec<(NativeSharedGenesisRecovery<I, J, Q, R, W, P>, Option<A>)>,
    recovered: bool,
}

impl<I, J, Q, R, W, P, A> NativeSharedGenesisController<I, J, Q, R, W, P, A>
where
    I: super::super::clean_authority_issuer::CleanManagementRuntimeStore,
    J: CleanManagementIssuerStore,
    Q: CleanManagementIssuerStore,
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
        for (recovery, _) in &mut self.entries {
            admission = admission.include_shared_genesis(recovery)?;
        }
        Ok(admission.with_deferred_shared_genesis())
    }

    /// Re-read all leased archives before replaying any entry. Successful
    /// recovery requires the owner's exact complete deferred set and independent
    /// live-history verification; archive signatures alone never grant finality.
    /// Errors retain all stores for an exact retry or orderly shutdown.
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
        let records = self.entries.iter().map(|(recovery, archive)| {
            let archive = archive.as_ref().ok_or(SharedAgentHostError::Unavailable)?;
            let bytes = archive.load(recovery.locator)
                .map_err(|_| SharedAgentHostError::Unavailable)?
                .ok_or(SharedAgentHostError::Unavailable)?;
            if bytes.len() > super::super::genesis::MAX_AGENT_GENESIS_ARCHIVE_RECORD_BYTES {
                return Err(SharedAgentHostError::ScopeMismatch);
            }
            let record = <super::super::genesis::AgentGenesisArchiveRecord as crate::service::ServiceWire>::decode(&bytes)
                .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
            if record.provision().proposal().locator() != recovery.locator {
                return Err(SharedAgentHostError::ScopeMismatch);
            }
            Ok(record)
        }).collect::<Result<Vec<_>, _>>()?;
        let mut entries: Vec<_> = self
            .entries
            .iter_mut()
            .zip(&records)
            .map(|((recovery, _), record)| (recovery, record))
            .collect();
        owner.recover_deferred_shared_generations(&mut entries, signer)?;
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
    ) -> Result<Self, SharedAgentHostError> {
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
    ) -> Result<Self, SharedAgentHostError> {
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
        Ok(Self {
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
        })
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
