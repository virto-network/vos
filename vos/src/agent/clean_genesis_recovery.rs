//! Leased reservation recovery for ordinary Shared Create through publication.

use super::genesis_issuance::RetainedCommitteeQuery;
use super::*;
use crate::agent::clean_management_intent::{CleanManagementIntentSlot, ManagementJournalAnchor};

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
                .finalization_work()
                .map_err(|_| SharedAgentHostError::Unavailable)?
                .is_some()
            || intent
                .retirement_complete()
                .map_err(|_| SharedAgentHostError::Unavailable)?
            || intent
                .denial_complete()
                .map_err(|_| SharedAgentHostError::Unavailable)?
        {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
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
        if issuer
            .recover_observed_application(
                authority,
                request.call().managed,
                request.request(),
                request.call(),
                &RawCredentialVerifier,
            )
            .map_err(|_| SharedAgentHostError::ScopeMismatch)?
            .is_some()
            || (issued.is_none()
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
