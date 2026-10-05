//! Retained Shared Create recovery and continuing management ownership.

use super::*;
use crate::agent::clean_authority_issuer::SignedManagementTerminal;
use crate::agent::clean_management_intent::{
    CleanManagementIntent, CleanManagementIntentSlot, ManagementJournalAnchor, SharedInstallHandoff,
};
#[cfg(feature = "experimental-state-blocks")]
use alloc::boxed::Box;

/// The only pre-archive retained phase is the original Create authorization.
/// Publication (and its optional finalization successor) requires the selected
/// archive even when no ordinary generation has yet been physically opened.
fn shared_creation_requires_archive(retired: bool, retained_phases: usize) -> bool {
    retired || retained_phases > 1
}

#[cfg(test)]
mod archive_phase_tests {
    use super::shared_creation_requires_archive;

    #[test]
    fn missing_archive_accepts_only_prepublication_create_phases() {
        // No authorization yet, then the original authorization alone. The
        // caller still requires retained runtime and selected replica inputs.
        assert!(!shared_creation_requires_archive(false, 0));
        assert!(!shared_creation_requires_archive(false, 1));
        // Original authorization + publication is no longer an unarchived
        // preparation; adding finalization does not change that requirement.
        assert!(shared_creation_requires_archive(false, 2));
        assert!(shared_creation_requires_archive(false, 3));
        // Retirement clears reservations, not the archive's retention duty.
        assert!(shared_creation_requires_archive(true, 0));
    }
}

/// The exact admitted runtime selected by a signed ordinary Shared Create.
/// This is not an executor or finality capability. Retained VOS3 bytes are
/// re-admitted against the signed descriptor before this selection is restored.
#[derive(Clone, Debug)]
pub enum SharedGenesisRuntimePackage {
    Image(AdmittedRuntimePackage),
    #[cfg(feature = "experimental-state-blocks")]
    External(super::super::package_admission::AdmittedStateRuntimePackage),
}

impl SharedGenesisRuntimePackage {
    pub fn exact_bytes(&self) -> &[u8] {
        match self {
            Self::Image(runtime) => runtime.exact_bytes(),
            #[cfg(feature = "experimental-state-blocks")]
            Self::External(runtime) => runtime.exact_bytes(),
        }
    }

    fn validate_descriptor(
        &self,
        descriptor: &AgentDescriptor,
    ) -> Result<(), SharedAgentHostError> {
        if descriptor.identity.profile != AgentProfile::Shared {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        match self {
            Self::Image(runtime) => {
                super::super::driver::verify_clean_runtime_package_binding(descriptor, runtime)
                    .map_err(|_| SharedAgentHostError::ScopeMismatch)
            }
            #[cfg(feature = "experimental-state-blocks")]
            Self::External(runtime) => {
                if descriptor.runtime_package != *runtime.package_ref()
                    || descriptor.identity.runtime_deployment != runtime.deployment()
                    || descriptor.identity.runtime_program != runtime.program()
                    || descriptor.identity.runtime_producer != runtime.manifest().signing.producer
                    || descriptor.runtime_contract != runtime.manifest().contract
                    || descriptor.capabilities != runtime.manifest().capabilities
                    || !super::super::replay::external_shared_descriptor_supported(descriptor)
                {
                    return Err(SharedAgentHostError::ScopeMismatch);
                }
                Ok(())
            }
        }
    }

    fn from_retained(
        descriptor: &AgentDescriptor,
        bytes: &[u8],
    ) -> Result<Self, SharedAgentHostError> {
        // Select by the signed lifecycle ABI, never by a failed image decode
        // or by the presence of external storage files.
        let package =
            if descriptor.runtime_contract.lifecycle_abi == super::super::sdk::RUNTIME_ABI_ID {
                Self::Image(
                    super::super::package_admission::admit_runtime_package(bytes)
                        .map_err(|_| SharedAgentHostError::ScopeMismatch)?,
                )
            } else {
                #[cfg(feature = "experimental-state-blocks")]
                {
                    if descriptor.runtime_contract.lifecycle_abi
                        != super::super::sdk::state_execution::STATE_EXECUTION_ABI_ID
                    {
                        return Err(SharedAgentHostError::ScopeMismatch);
                    }
                    Self::External(
                        super::super::package_admission::admit_state_runtime_package(bytes)
                            .map_err(|_| SharedAgentHostError::ScopeMismatch)?,
                    )
                }
                #[cfg(not(feature = "experimental-state-blocks"))]
                return Err(SharedAgentHostError::ScopeMismatch);
            };
        package.validate_descriptor(descriptor)?;
        Ok(package)
    }
}

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
        let finalized = record.finalized_predecessor();
        if issuer
            .recover_finalized_terminal(
                authority,
                finalized.call().managed,
                finalized.request(),
                finalized.call(),
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
            let old_package = slot
                .load_actor()
                .map_err(|_| SharedAgentHostError::Unavailable)?
                .ok_or(SharedAgentHostError::Unavailable)?;
            validate_actor_install(descriptor, current.request(), &old_package)
                .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
            if let Some((certificate, _)) = &record.denial {
                slot.handoff_denied(
                    &current,
                    record.next.clone(),
                    certificate,
                    &RawCredentialVerifier,
                )
                .map_err(|_| SharedAgentHostError::Unavailable)?;
            } else {
                slot.handoff_retired(&current, record.next.clone(), &RawCredentialVerifier)
                    .map_err(|_| SharedAgentHostError::Unavailable)?;
            }
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
    let finalized = record.finalized_predecessor();
    let (receipt, terminal) = issuer
        .recover_finalized_terminal(
            authority,
            managed,
            finalized.request(),
            finalized.call(),
            &RawCredentialVerifier,
        )
        .map_err(|_| SharedAgentHostError::ScopeMismatch)?
        .ok_or(SharedAgentHostError::ScopeMismatch)?;
    if matches!(finalized.request(), ManagementRequest::Create(_)) {
        // The caller already recovered this generation against its immutable
        // Create archive and fresh Authority evidence. Denial adds no transition.
        return match terminal {
            SignedManagementTerminal::Applied(ack) if ack.managed == managed => Ok(()),
            _ => Err(SharedAgentHostError::ScopeMismatch),
        };
    }
    let observation = host.observe_durable_install(
        crate::service::AgentId(managed.agent.0),
        finalized.request(),
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
    // Members retain public archives, not another node's issuer or Create WAL.
    // The existing archive lease stays owned through recovery and serving.
    member_archives: Vec<(super::super::genesis::AgentGenesisLocator, A)>,
    #[cfg(feature = "experimental-state-blocks")]
    member_archive_factory: Option<
        Box<
            dyn FnMut(
                    &super::super::genesis::AgentGenesisArchiveRecord,
                ) -> Result<A, SharedAgentHostError>
                + Send,
        >,
    >,
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
            member_archives: Vec::new(),
            #[cfg(feature = "experimental-state-blocks")]
            member_archive_factory: None,
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

    /// Retain issuer-independent member archives before startup admission.
    /// Locators only select leased public data; decoding an archive cannot
    /// grant finality, provision a generation, or impersonate its coordinator.
    /// Cold recovery requires the member's physical namespace to exist;
    /// archive-only preparation cannot create or repair a missing generation.
    #[cfg(feature = "experimental-state-blocks")]
    pub fn with_member_archives(
        mut self,
        mut members: Vec<(super::super::genesis::AgentGenesisLocator, A)>,
    ) -> Result<Self, SharedAgentHostError> {
        if self.recovered || self.generations_recovered || !self.member_archives.is_empty() {
            return Err(SharedAgentHostError::Conflict);
        }
        validate_member_archive_locators(
            self.authority,
            &self
                .entries
                .iter()
                .map(|(entry, _)| entry.locator)
                .collect::<Vec<_>>(),
            &members
                .iter()
                .map(|(locator, _)| *locator)
                .collect::<Vec<_>>(),
        )?;
        members.sort_unstable_by_key(|(locator, _)| locator.agent);
        self.member_archives = members;
        Ok(self)
    }

    /// Retain the existing per-member archive owner for live admission. The
    /// factory acquires an empty or byte-identical lease only; it must not
    /// publish inputs, execute Authority, or create a physical generation.
    #[cfg(feature = "experimental-state-blocks")]
    pub fn with_member_archive_factory<F>(
        mut self,
        factory: F,
    ) -> Result<Self, SharedAgentHostError>
    where
        F: FnMut(
                &super::super::genesis::AgentGenesisArchiveRecord,
            ) -> Result<A, SharedAgentHostError>
            + Send
            + 'static,
    {
        if self.recovered || self.generations_recovered || self.member_archive_factory.is_some() {
            return Err(SharedAgentHostError::Conflict);
        }
        self.member_archive_factory = Some(Box::new(factory));
        Ok(self)
    }

    /// Admit this node's member of a finalized ordinary Shared Create. Public
    /// archive bytes never confer admission: the installed System must freshly
    /// confirm both the permanent decision and the complete live descriptor.
    /// This retains storage and physical ownership, not transport or readiness.
    #[cfg(feature = "experimental-state-blocks")]
    pub fn admit_member_archive<B, C, D, S>(
        &mut self,
        owner: &mut CleanSystemAgentBootstrapOwner<B, C, D>,
        record: &super::super::genesis::AgentGenesisArchiveRecord,
        signer: &mut S,
    ) -> Result<(), SharedAgentHostError>
    where
        B: CleanSystemAgentBootstrapStore + Send + 'static,
        C: CleanSystemAgentBootstrapStore + Send + 'static,
        D: CleanManagementIssuerStore + Send + 'static,
        S: CleanManagementReceiptSigner,
    {
        let locator = record.provision().proposal().locator();
        let existing = validate_live_member_archive_selection(
            self.authority,
            self.recovered,
            &self
                .entries
                .iter()
                .map(|(entry, _)| entry.locator)
                .collect::<Vec<_>>(),
            &self
                .member_archives
                .iter()
                .map(|(locator, _)| *locator)
                .collect::<Vec<_>>(),
            locator,
        )?;
        if owner.authority_target() != self.authority {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        // Static certified material, actual Root and exclusion checks precede
        // even the empty lease. No signing or projection WAL occurs here.
        owner.preflight_live_member_shared_genesis(record, signer.public_key())?;
        let index = match existing {
            Some(index) => index,
            None => {
                let archive =
                    self.member_archive_factory
                        .as_mut()
                        .ok_or(SharedAgentHostError::Unavailable)?(record)?;
                let index = self
                    .member_archives
                    .partition_point(|(member, _)| member.agent < locator.agent);
                // Retain the lease before fresh reads or host staging. Any
                // later ambiguous write is retried through this exact owner.
                self.member_archives.insert(index, (locator, archive));
                index
            }
        };
        let (_, archive) = &self.member_archives[index];
        let stored = archive
            .load(locator)
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        if stored.as_deref().is_some_and(|bytes| {
            bytes.len() > super::super::genesis::MAX_AGENT_GENESIS_ARCHIVE_RECORD_BYTES
                || bytes != record.encode().as_slice()
        }) {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        // Published inputs cannot repair an absent serving namespace. Empty
        // preparation permits only a genuine first admission or exact stage.
        owner.preflight_live_member_namespace(record, stored.is_some())?;
        let proof = owner.stage_live_member_shared_genesis(record, stored.is_some(), signer)?;
        super::super::genesis_archive::ArchivedAgentGenesisProvider::new(locator.space, archive)
            .map_err(|_| SharedAgentHostError::ScopeMismatch)?
            .publish(record)
            .map_err(|error| match error {
                super::super::genesis::AgentGenesisProviderError::Unavailable => {
                    SharedAgentHostError::Unavailable
                }
                _ => SharedAgentHostError::ScopeMismatch,
            })?;
        owner.finish_live_member_shared_genesis(record, &proof, archive)?;
        self.refresh_member_projection_scope(owner)
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
        self.reserve_create_with_runtime(
            descriptor,
            call,
            &SharedGenesisRuntimePackage::Image(runtime.clone()),
            replicas,
            reserve,
        )
    }

    /// The signed runtime contract is retained together with the original
    /// reservation; exact retries cannot replace its executor selection.
    pub fn reserve_create_with_runtime<F>(
        &mut self,
        descriptor: &AgentDescriptor,
        call: &super::super::sdk::authority::AuthorityCredentialCall,
        runtime: &SharedGenesisRuntimePackage,
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
        if self
            .member_archives
            .iter()
            .any(|(member, _)| member.agent == locator.agent)
        {
            // A member lease is not an issuer reservation or authority to
            // consume the coordinator's management sequence on this node.
            return Err(SharedAgentHostError::Conflict);
        }
        let matches = |recovery: &mut NativeSharedGenesisRecovery<I, J, Q, R, W, P>| {
            Self::create_reservation_matches(
                self.authority,
                locator,
                &signed,
                runtime,
                replicas,
                recovery,
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
        if self
            .entries
            .len()
            .saturating_add(self.member_archives.len())
            >= super::super::shared_host::MAX_SHARED_HOST_AGENTS
        {
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

    fn create_reservation_matches(
        authority: AuthorityActorTarget,
        locator: super::super::genesis::AgentGenesisLocator,
        signed: &CleanManagementIntent,
        runtime: &SharedGenesisRuntimePackage,
        replicas: &AgentReplicaCommittee,
        recovery: &mut NativeSharedGenesisRecovery<I, J, Q, R, W, P>,
    ) -> Result<bool, SharedAgentHostError> {
        Ok(recovery.authority == authority
            && recovery.locator == locator
            // Work grows after reservation. It is not caller input, and an
            // invalid admission cache must still permit exact native reload.
            && recovery.intent.intent().is_some_and(|retained| {
                retained.request() == signed.request() && retained.call() == signed.call()
            })
            && recovery.runtime.as_ref().map(SharedGenesisRuntimePackage::exact_bytes)
                == Some(runtime.exact_bytes())
            && recovery.retained_replicas()?.as_ref() == Some(replicas))
    }

    /// Lookup only: validate the complete signed caller material against an
    /// already-owned issuer reservation, without opening a lease, signing,
    /// persisting, or admitting a new Create while route publication is hidden.
    pub(crate) fn retained_create_locator(
        &mut self,
        descriptor: &AgentDescriptor,
        call: &AuthorityCredentialCall,
        runtime: &SharedGenesisRuntimePackage,
        replicas: &AgentReplicaCommittee,
    ) -> Result<Option<super::super::genesis::AgentGenesisLocator>, SharedAgentHostError> {
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
        if self
            .member_archives
            .iter()
            .any(|(member, _)| member.agent == locator.agent)
        {
            return Err(SharedAgentHostError::Conflict);
        }
        let Ok(index) = self
            .entries
            .binary_search_by_key(&locator.agent, |(entry, _)| entry.locator.agent)
        else {
            return Ok(None);
        };
        if Self::create_reservation_matches(
            self.authority,
            locator,
            &signed,
            runtime,
            replicas,
            &mut self.entries[index].0,
        )? {
            Ok(Some(locator))
        } else {
            Err(SharedAgentHostError::Conflict)
        }
    }

    /// Select only an already-owned exact continuing Install. This reads its
    /// current signed intent and admitted package without opening a lease,
    /// initializing management, pledging work, or granting route readiness.
    /// Package loading keeps the existing leased sidecar reconciliation.
    pub(crate) fn retained_install_locator(
        &mut self,
        install: &super::super::sdk::InstallActor,
        call: &AuthorityCredentialCall,
        package: &AdmittedActorPackage,
    ) -> Result<Option<super::super::genesis::AgentGenesisLocator>, SharedAgentHostError>
    where
        I: super::super::clean_authority_issuer::CleanManagementActorStore,
    {
        if !self.recovered {
            return Err(SharedAgentHostError::Conflict);
        }
        let locator = super::super::genesis::AgentGenesisLocator {
            space: crate::service::SpaceId(call.managed.space.0),
            agent: crate::service::AgentId(call.managed.agent.0),
        };
        if locator.validate().is_err()
            || call.managed.space != self.authority.space
            || call.managed.agent == self.authority.system_agent
            || call.managed.profile != AgentProfile::Shared
        {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        let signed = CleanManagementIntent::new(
            self.authority,
            call.managed,
            ManagementRequest::Install(Box::new(install.clone())),
            call.clone(),
            &RawCredentialVerifier,
        )
        .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
        if self
            .member_archives
            .iter()
            .any(|(member, _)| member.agent == locator.agent)
        {
            return Err(SharedAgentHostError::Conflict);
        }
        let Ok(index) = self
            .entries
            .binary_search_by_key(&locator.agent, |(entry, _)| entry.locator.agent)
        else {
            return Ok(None);
        };
        let recovery = &mut self.entries[index].0;
        if recovery.authority != self.authority || recovery.locator != locator {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        let original = recovery
            .intent
            .intent()
            .ok_or(SharedAgentHostError::ScopeMismatch)?;
        let ManagementRequest::Create(descriptor) = original.request() else {
            return Err(SharedAgentHostError::ScopeMismatch);
        };
        signed
            .verify(self.authority, original.call().managed, &RawCredentialVerifier)
            .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
        validate_actor_install(descriptor, signed.request(), package)
            .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
        let Some(slot) = recovery.management_intent.as_mut() else {
            return Ok(None);
        };
        let Some(retained) = slot.intent() else {
            return Ok(None);
        };
        retained
            .verify(self.authority, original.call().managed, &RawCredentialVerifier)
            .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
        if retained.request() != signed.request() || retained.call() != signed.call() {
            // A terminal current intent may still be retried. A predecessor
            // or prospective successor is not the current retained operation.
            return Err(SharedAgentHostError::Conflict);
        }
        let Some(retained_package) = slot
            .load_actor()
            .map_err(|_| SharedAgentHostError::Unavailable)?
        else {
            return Ok(None);
        };
        if retained_package.exact_bytes() != package.exact_bytes() {
            return Err(SharedAgentHostError::Conflict);
        }
        Ok(Some(locator))
    }

    #[cfg(test)]
    pub(super) fn into_entries_for_test(
        self,
    ) -> Vec<(NativeSharedGenesisRecovery<I, J, Q, R, W, P>, Option<A>)> {
        self.entries
    }

    /// Read the exact leased coordinator archive for a recovered reservation.
    /// This is untrusted publication data, not finality or route permission.
    /// A public exact retry may skip new endorsement when it already exists;
    /// completion must still perform the owner's normal live verification.
    pub(crate) fn create_archive(
        &self,
        locator: super::super::genesis::AgentGenesisLocator,
    ) -> Result<Option<super::super::genesis::AgentGenesisArchiveRecord>, SharedAgentHostError>
    {
        if !self.recovered {
            return Err(SharedAgentHostError::Conflict);
        }
        let (_, archive) = self
            .entries
            .iter()
            .find(|(entry, _)| entry.locator == locator)
            .ok_or(SharedAgentHostError::ScopeMismatch)?;
        let archive = archive.as_ref().ok_or(SharedAgentHostError::Unavailable)?;
        let provider = super::super::genesis_archive::ArchivedAgentGenesisProvider::new(
            locator.space,
            archive,
        )
        .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
        provider.load_record(locator).map_err(|error| match error {
            super::super::genesis::AgentGenesisProviderError::Unavailable => {
                SharedAgentHostError::Unavailable
            }
            _ => SharedAgentHostError::ScopeMismatch,
        })
    }

    /// Inspect the exact retained Create denial without executing or signing.
    /// A durable certificate alone does not prove retention release: callers
    /// must first finish the normal native denial continuation successfully.
    pub(crate) fn create_denial(
        &mut self,
        locator: super::super::genesis::AgentGenesisLocator,
        descriptor: &AgentDescriptor,
        call: &AuthorityCredentialCall,
    ) -> Result<Option<super::super::local_lifecycle::SharedCreateDenial>, SharedAgentHostError>
    {
        if !self.recovered || call.authority != self.authority {
            return Err(SharedAgentHostError::Conflict);
        }
        if locator.space.0 != self.authority.space.0
            || locator.space.0 != descriptor.identity.space.0
            || locator.agent.0 != descriptor.identity.agent.0
        {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        let Some((recovery, _)) = self
            .entries
            .iter_mut()
            .find(|(entry, _)| entry.locator == locator)
        else {
            return Ok(None);
        };
        let request = ManagementRequest::Create(Box::new(descriptor.clone()));
        if !recovery.intent.intent().is_some_and(|intent| {
            recovery.authority == self.authority
                && intent.request() == &request
                && intent.call() == call
        }) {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        if !recovery
            .intent
            .denial_complete()
            .map_err(|_| SharedAgentHostError::Unavailable)?
        {
            return Ok(None);
        }
        recovery
            .intent
            .load_denial_certificate()
            .map_err(|_| SharedAgentHostError::Unavailable)?
            .map(|bytes| {
                super::super::local_lifecycle::SharedCreateDenial::verify(descriptor, call, &bytes)
                    .map_err(|_| SharedAgentHostError::ScopeMismatch)
            })
            .transpose()
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
        let index = self
            .entries
            .iter()
            .position(|(recovery, _)| recovery.locator == locator)
            .ok_or(SharedAgentHostError::ScopeMismatch)?;
        let (recovery, archive) = &mut self.entries[index];
        if !recovery.admission_valid {
            recovery
                .readmit_creation_from_leased_stores()
                .map_err(|error| {
                    if std::env::var_os("VOS_TEST_BOOTSTRAP_DIAGNOSTICS").is_some() {
                        tracing::debug!(?error, "shared_create_prepare_phase_error: reload");
                    }
                    error
                })?;
        }
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
        if owner
            .finish_denied_shared_genesis(recovery, receipt_signer)
            .map_err(|error| {
                if std::env::var_os("VOS_TEST_BOOTSTRAP_DIAGNOSTICS").is_some() {
                    tracing::debug!(
                        node = ?owner.pins().node,
                        locator = ?locator,
                        phase = "create_denial_evidence",
                        admission_valid = recovery.admission_valid,
                        ?error,
                        "Retained Shared Create preparation refused"
                    );
                }
                error
            })?
        {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        let replicas = recovery
            .retained_replicas()?
            .ok_or(SharedAgentHostError::ScopeMismatch)?;
        owner
            .host
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?
            .preflight_live_genesis_capacity(locator)
            .map_err(|error| {
                if std::env::var_os("VOS_TEST_BOOTSTRAP_DIAGNOSTICS").is_some() {
                    tracing::debug!(
                        node = ?owner.pins().node,
                        locator = ?locator,
                        phase = "create_physical_preflight",
                        admission_valid = recovery.admission_valid,
                        ?error,
                        "Retained Shared Create preparation refused"
                    );
                }
                error
            })?;
        let (candidate, committee) =
            match owner.resume_shared_genesis_preparation(recovery, &replicas, receipt_signer) {
                Ok(prepared) => prepared,
                Err(error) => {
                    if std::env::var_os("VOS_TEST_BOOTSTRAP_DIAGNOSTICS").is_some() {
                        tracing::debug!(
                            node = ?owner.pins().node,
                            locator = ?locator,
                            phase = "create_resume",
                            admission_valid = recovery.admission_valid,
                            ?error,
                            "Retained Shared Create preparation refused"
                        );
                    }
                    owner
                        .finish_denied_shared_genesis(recovery, receipt_signer)
                        .map_err(|denial_error| {
                            if std::env::var_os("VOS_TEST_BOOTSTRAP_DIAGNOSTICS").is_some() {
                                tracing::debug!(
                                    node = ?owner.pins().node,
                                    locator = ?locator,
                                    phase = "create_denial_after_resume_error",
                                    admission_valid = recovery.admission_valid,
                                    resume_error = ?error,
                                    ?denial_error,
                                    "Retained Shared Create preparation refused"
                                );
                            }
                            denial_error
                        })?;
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
        if !recovery.admission_valid {
            // Publication can fail after selecting the immutable archive or
            // retaining its successor envelope. Re-admit the exact original
            // stores under their existing leases before resuming; an archive
            // alone is not authorization or proof that publication completed.
            recovery.readmit_creation_from_leased_stores()?;
        }
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
        let acknowledgement =
            owner.complete_live_shared_genesis(recovery, &record, signer, predecessor.as_ref())?;
        #[cfg(feature = "experimental-state-blocks")]
        self.refresh_member_projection_scope(owner)?;
        Ok(acknowledgement)
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
                && !slot
                    .denial_complete()
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
                let mut record = SharedInstallHandoff::new(&previous, &intent, package)
                    .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
                let issuer = recovery
                    .management_issuer
                    .as_mut()
                    .ok_or(SharedAgentHostError::Unavailable)?;
                if slot
                    .denial_complete()
                    .map_err(|_| SharedAgentHostError::Unavailable)?
                {
                    if !owner.finish_denied_shared_install(slot, issuer, signer)? {
                        return Err(SharedAgentHostError::Conflict);
                    }
                    let saved = slot
                        .load_shared_install_handoff()
                        .map_err(|_| SharedAgentHostError::Unavailable)?;
                    let finalized = match &saved {
                        Some(saved) => saved.finalized_predecessor(),
                        None => recovery
                            .intent
                            .intent()
                            .ok_or(SharedAgentHostError::ScopeMismatch)?,
                    };
                    let certificate = slot
                        .load_denial_certificate()
                        .map_err(|_| SharedAgentHostError::Unavailable)?
                        .ok_or(SharedAgentHostError::ScopeMismatch)?;
                    record = record
                        .with_denial(certificate, finalized)
                        .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
                }
                let finalized = record.finalized_predecessor();
                if issuer
                    .recover_finalized_terminal(
                        self.authority,
                        finalized.call().managed,
                        finalized.request(),
                        finalized.call(),
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
                if record.denial.is_none() {
                    owner.complete_shared_install_from_management_intent(
                        slot,
                        &previous_package,
                        issuer,
                        signer,
                    )?;
                } else {
                    verify_shared_handoff_generation(owner, &record, issuer)?;
                }
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

    pub(crate) fn install_denial(
        &mut self,
        locator: super::super::genesis::AgentGenesisLocator,
        install: &super::super::sdk::InstallActor,
        call: &AuthorityCredentialCall,
    ) -> Result<Option<super::super::local_lifecycle::SharedInstallDenial>, SharedAgentHostError>
    where
        I: super::super::clean_authority_issuer::CleanSharedManagementIntentStore,
    {
        if !self.recovered || call.authority != self.authority {
            return Err(SharedAgentHostError::Conflict);
        }
        let (recovery, _) = self
            .entries
            .iter_mut()
            .find(|(entry, _)| entry.locator == locator)
            .ok_or(SharedAgentHostError::ScopeMismatch)?;
        let original = recovery
            .intent
            .intent()
            .ok_or(SharedAgentHostError::ScopeMismatch)?;
        let request = ManagementRequest::Install(Box::new(install.clone()));
        CleanManagementIntent::new(
            self.authority,
            original.call().managed,
            request.clone(),
            call.clone(),
            &RawCredentialVerifier,
        )
        .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
        let Some(slot) = recovery.management_intent.as_mut() else {
            return Ok(None);
        };
        let bytes = if slot
            .intent()
            .is_some_and(|intent| intent.request() == &request && intent.call() == call)
        {
            slot.load_denial_certificate()
                .map_err(|_| SharedAgentHostError::Unavailable)?
        } else {
            slot.load_shared_install_handoff()
                .map_err(|_| SharedAgentHostError::Unavailable)?
                .filter(|record| {
                    record.previous.request() == &request && record.previous.call() == call
                })
                .and_then(|record| record.denial.map(|(certificate, _)| certificate))
        };
        bytes
            .map(|bytes| {
                super::super::local_lifecycle::SharedInstallDenial::verify(install, call, &bytes)
                    .map_err(|_| SharedAgentHostError::ScopeMismatch)
            })
            .transpose()
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
        let empty = self.entries.is_empty() && self.member_archives.is_empty();
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
        if !self.member_archives.is_empty()
            && signer.public_key() != self.authority.binding.public_key
        {
            // Refuse before recovering any read WAL or issuing retained work.
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        if self.entries.is_empty() && self.member_archives.is_empty() {
            owner.verify_empty_shared_genesis_startup()?;
            self.recovered = true;
            return Ok(());
        }
        owner.shared_lifecycle_recovery_pending = true;
        // Re-read every leased member archive before any replay or physical
        // staging. A previous in-memory record is not current storage evidence.
        #[cfg(feature = "experimental-state-blocks")]
        let mut staged_member_archives = Vec::new();
        let member_records = self.member_archives.iter().enumerate().filter_map(|(index, (locator, archive))| {
            let bytes = match archive.load(*locator) {
                Ok(Some(bytes)) => bytes,
                Err(_) => return Some(Err(SharedAgentHostError::Unavailable)),
                Ok(None) => {
                    // Empty preparation alone grants nothing. Only a present,
                    // never-opened exact host intent supplies missing inputs;
                    // publication still waits for fresh proof after issuer
                    // recovery has discharged its own dependencies below.
                    #[cfg(feature = "experimental-state-blocks")]
                    {
                        let staged = owner.host.lock()
                            .map_err(|_| SharedAgentHostError::Unavailable)
                            .and_then(|mut host| host.staged_member_genesis_archive(*locator));
                        match staged {
                            Ok(Some(record)) => {
                                staged_member_archives.push((index, record.clone()));
                                crate::service::ServiceWire::encode(&record)
                            }
                            Ok(None) => return None,
                            Err(error) => return Some(Err(error)),
                        }
                    }
                    #[cfg(not(feature = "experimental-state-blocks"))]
                    { return None; }
                }
            };
            if bytes.len() > super::super::genesis::MAX_AGENT_GENESIS_ARCHIVE_RECORD_BYTES {
                return Some(Err(SharedAgentHostError::ScopeMismatch));
            }
            let record = <super::super::genesis::AgentGenesisArchiveRecord as crate::service::ServiceWire>::decode(&bytes)
                .map_err(|_| SharedAgentHostError::ScopeMismatch);
            let record = match record {
                Ok(record) => record,
                Err(error) => return Some(Err(error)),
            };
            if record.provision().proposal().locator() != *locator
                || crate::service::ServiceWire::encode(&record) != bytes
            {
                return Some(Err(SharedAgentHostError::ScopeMismatch));
            }
            Some(Ok(record))
        }).collect::<Result<Vec<_>, _>>()?;
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
                    if shared_creation_requires_archive(recovery.retired, recovery.pending.len())
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
        #[cfg(feature = "experimental-state-blocks")]
        {
            let mut cold_records = records.iter().flatten().collect::<Vec<_>>();
            cold_records.extend(member_records.iter());
            owner.validate_recovery_member_set(&cold_records)?;
        }
        // Replay retained mutation work using its immutable preflight.
        // Non-retaining observations do not advance the guest's logical clock.
        // Authorization only yields a receipt;
        // finalization only resumes an already signed application outcome.
        // Physical execution/evidence and fresh genesis authority remain gated
        // below, with route export closed throughout recovery.
        for (recovery, _) in &mut self.entries {
            if let Some(slot) = recovery.management_intent.as_mut() {
                if slot
                    .denial_complete()
                    .map_err(|_| SharedAgentHostError::Unavailable)?
                {
                    let issuer = recovery
                        .management_issuer
                        .as_ref()
                        .ok_or(SharedAgentHostError::ScopeMismatch)?;
                    // A durable CND1 omits runtime admission, not the exact
                    // owner's quorum-release obligation. Retry its verified
                    // terminal before fresh genesis reads or the later skip.
                    if !owner.finish_denied_shared_install(slot, issuer, signer)? {
                        return Err(SharedAgentHostError::ScopeMismatch);
                    }
                    recovery.management_pending.clear();
                    recovery.management_retirements.clear();
                    continue;
                }
            }
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
            owner.recover_deferred_shared_generations_with_members(
                &mut entries,
                &member_records,
                signer,
                predecessor.as_ref(),
                |_member_owner, _member_signer| {
                    #[cfg(feature = "experimental-state-blocks")]
                    for (index, expected) in staged_member_archives {
                        let (locator, archive) = &self.member_archives[index];
                        let recovered = _member_owner
                            .recover_staged_member_shared_genesis_archive(
                                *locator,
                                archive,
                                _member_signer,
                            )?
                            .ok_or(SharedAgentHostError::ScopeMismatch)?;
                        if recovered != expected {
                            return Err(SharedAgentHostError::ScopeMismatch);
                        }
                    }
                    Ok(())
                },
            )?;
            self.generations_recovered = true;
        }
        drop(entries);
        // Every voter must attach its independently verified generations before
        // an original owner can recover an Install through their Raft quorum.
        // Keep completed physical recovery across a fallible attachment retry.
        owner._network_host.refresh()?;
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
        #[cfg(feature = "experimental-state-blocks")]
        self.refresh_member_projection_scope(owner)?;
        owner.shared_lifecycle_recovery_pending = false;
        self.recovered = true;
        Ok(())
    }

    /// Lifecycle-boundary material restriction for both warm and cold voters.
    /// Read every existing lease again; an unserved archive alone is excluded
    /// by the actual host namespace set. This does not sign or dispatch reads.
    #[cfg(feature = "experimental-state-blocks")]
    fn refresh_member_projection_scope<B, C, D>(
        &mut self,
        owner: &mut CleanSystemAgentBootstrapOwner<B, C, D>,
    ) -> Result<(), SharedAgentHostError>
    where
        B: CleanSystemAgentBootstrapStore,
        C: CleanSystemAgentBootstrapStore,
        D: CleanManagementIssuerStore,
    {
        if owner.authority_target() != self.authority {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        let leases = self
            .entries
            .iter()
            .filter_map(|(entry, archive)| archive.as_ref().map(|archive| (entry.locator, archive)))
            .chain(
                self.member_archives
                    .iter()
                    .map(|(locator, archive)| (*locator, archive)),
            );
        let mut records = Vec::new();
        for (locator, archive) in leases {
            let Some(bytes) = archive
                .load(locator)
                .map_err(|_| SharedAgentHostError::Unavailable)?
            else {
                continue;
            };
            if bytes.len() > super::super::genesis::MAX_AGENT_GENESIS_ARCHIVE_RECORD_BYTES {
                return Err(SharedAgentHostError::ScopeMismatch);
            }
            let record = <super::super::genesis::AgentGenesisArchiveRecord as crate::service::ServiceWire>::decode(&bytes)
                .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
            if record.provision().proposal().locator() != locator
                || crate::service::ServiceWire::encode(&record) != bytes
            {
                return Err(SharedAgentHostError::ScopeMismatch);
            }
            records.push(record);
        }
        owner.validate_recovery_member_set(&records.iter().collect::<Vec<_>>())
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

#[cfg(feature = "experimental-state-blocks")]
fn validate_live_member_archive_selection(
    authority: AuthorityActorTarget,
    recovered: bool,
    issuer: &[super::super::genesis::AgentGenesisLocator],
    members: &[super::super::genesis::AgentGenesisLocator],
    requested: super::super::genesis::AgentGenesisLocator,
) -> Result<Option<usize>, SharedAgentHostError> {
    if !recovered {
        return Err(SharedAgentHostError::Conflict);
    }
    validate_member_archive_locators(authority, issuer, members)?;
    if let Some(index) = members.iter().position(|member| *member == requested) {
        return Ok(Some(index));
    }
    let mut proposed = members.to_vec();
    proposed.push(requested);
    validate_member_archive_locators(authority, issuer, &proposed)?;
    Ok(None)
}

#[cfg(feature = "experimental-state-blocks")]
fn validate_member_archive_locators(
    authority: AuthorityActorTarget,
    issuer: &[super::super::genesis::AgentGenesisLocator],
    members: &[super::super::genesis::AgentGenesisLocator],
) -> Result<(), SharedAgentHostError> {
    if issuer.len().saturating_add(members.len())
        > super::super::shared_host::MAX_SHARED_HOST_AGENTS
    {
        return Err(SharedAgentHostError::CapacityExhausted);
    }
    let mut all: Vec<_> = issuer.iter().chain(members).copied().collect();
    if !authority.is_valid()
        || all.iter().any(|locator| {
            locator.validate().is_err()
                || locator.space.0 != authority.space.0
                || locator.agent.0 == authority.system_agent.0
        })
    {
        return Err(SharedAgentHostError::ScopeMismatch);
    }
    all.sort_unstable_by_key(|locator| locator.agent);
    if all.windows(2).any(|pair| pair[0].agent == pair[1].agent) {
        return Err(SharedAgentHostError::Conflict);
    }
    Ok(())
}

#[cfg(all(test, feature = "experimental-state-blocks"))]
mod retained_install_tests {
    use super::*;
    use crate::agent::clean_authority_issuer::{
        CleanExternalLocalCreateArchiveStore, CleanManagementActorStore,
        CleanManagementRuntimeStore, CleanSharedGenesisReplicaStore,
    };
    use crate::agent::sdk::{
        ActorEntry, AgentIdentity, CredentialId, DeploymentId, InstallActor, InstallationId,
        PrincipalId, ProducerId, ProgramId, ReplicaRole,
    };
    use core::num::NonZeroU64;
    use ed25519_dalek::{Signer as _, SigningKey};

    #[derive(Clone, Default, PartialEq, Eq)]
    struct Images {
        intent: Option<Vec<u8>>,
        runtime: Option<Vec<u8>>,
        actor: Option<Vec<u8>>,
        replicas: Option<Vec<u8>>,
        archive: Option<Vec<u8>>,
        commits: usize,
    }
    #[derive(Clone, Default)]
    struct Store(Arc<Mutex<Images>>);
    impl CleanManagementIssuerStore for Store {
        type Error = ();
        fn load(&mut self) -> Result<Option<Vec<u8>>, ()> {
            Ok(self.0.lock().unwrap().intent.clone())
        }
        fn commit(&mut self, bytes: &[u8]) -> Result<(), ()> {
            let mut image = self.0.lock().unwrap();
            image.intent = Some(bytes.to_vec());
            image.commits += 1;
            Ok(())
        }
    }
    macro_rules! sidecar {
        ($trait:ident, $load:ident, $commit:ident, $field:ident) => {
            impl $trait for Store {
                fn $load(&mut self) -> Result<Option<Vec<u8>>, ()> {
                    Ok(self.0.lock().unwrap().$field.clone())
                }
                fn $commit(&mut self, bytes: &[u8]) -> Result<(), ()> {
                    let mut image = self.0.lock().unwrap();
                    image.$field = Some(bytes.to_vec());
                    image.commits += 1;
                    Ok(())
                }
            }
        };
    }
    sidecar!(
        CleanManagementRuntimeStore,
        load_runtime,
        commit_runtime,
        runtime
    );
    sidecar!(CleanManagementActorStore, load_actor, commit_actor, actor);
    sidecar!(
        CleanSharedGenesisReplicaStore,
        load_replicas,
        commit_replicas,
        replicas
    );
    sidecar!(
        CleanExternalLocalCreateArchiveStore,
        load_external_create_archive,
        commit_external_create_archive,
        archive
    );
    impl super::super::super::genesis_archive::AgentGenesisArchiveStore for Store {
        type Error = ();
        fn load(
            &self,
            _: super::super::super::genesis::AgentGenesisLocator,
        ) -> Result<Option<Vec<u8>>, ()> {
            Ok(self.0.lock().unwrap().archive.clone())
        }
        fn insert_if_absent(
            &self,
            _: super::super::super::genesis::AgentGenesisLocator,
            _: &[u8],
        ) -> Result<(), ()> {
            Err(())
        }
    }
    type Controller =
        NativeSharedGenesisController<Store, Store, Store, Store, Store, Store, Store>;

    fn call(
        authority: AuthorityActorTarget,
        descriptor: &AgentDescriptor,
        request: &ManagementRequest,
        key: &SigningKey,
        sequence: u64,
    ) -> AuthorityCredentialCall {
        let public = key.verifying_key().to_bytes();
        let mut call = AuthorityCredentialCall {
            invocation: InvocationId::ZERO,
            authority,
            managed: ManagedAgentTarget {
                space: descriptor.identity.space,
                agent: descriptor.identity.agent,
                owner: descriptor.identity.owner,
                profile: descriptor.identity.profile,
                runtime_deployment: descriptor.identity.runtime_deployment,
                transition_producer: descriptor.identity.transition_producer,
            },
            principal: PrincipalId::of_public_key(&public),
            credential: CredentialId::of_public_key(&public),
            request_sequence: NonZeroU64::new(sequence).unwrap(),
            credential_public_key: public,
            authenticated_node: None,
            requested_valid_from: 10,
            requested_expires_at: 30,
            plan: request.authorization_plan().unwrap(),
            signature: [0; 64],
        };
        call.invocation = call.expected_invocation();
        call.signature = key.sign(&call.signing_bytes()).to_bytes();
        call.verify_with(&RawCredentialVerifier).unwrap();
        call
    }

    fn install(agent: AgentId, package: &AdmittedActorPackage, marker: u8) -> InstallActor {
        let schema = crate::agent::sdk::schema::decode(package.state_lane_schema_bytes()).unwrap();
        InstallActor {
            installation_id: InstallationId([marker; 32]),
            registry_reservation: Hash([marker + 1; 32]),
            entry: ActorEntry {
                actor: ActorId::top_level(agent, &package.manifest().name),
                name: package.manifest().name.clone(),
                parent: None,
                deployment: package.deployment(),
                program: package.program(),
                package: package.package_ref().clone(),
                agent_schema: package.manifest().state_lane_schema.clone(),
                method_policy: package.manifest().method_policy.clone(),
                constructor_abi: schema.constructor_abi().unwrap(),
                installation_data: None,
                state_layout: schema.state_layout_hash().unwrap(),
                lanes: package.requirements().lanes,
                suspended: false,
            },
            producer: package.producer(),
            package: package.package_ref().clone(),
            agent_schema: package.manifest().state_lane_schema.clone(),
            method_policy: package.manifest().method_policy.clone(),
            constructor_abi: schema.constructor_abi().unwrap(),
            installation_data: None,
            state_layout: schema.state_layout_hash().unwrap(),
            contract: package.manifest().contract,
            requirements: package.requirements(),
        }
    }

    #[test]
    fn retained_install_lookup_requires_signed_current_owner_intent_and_exact_package() {
        let key = SigningKey::from_bytes(&[31; 32]);
        let public = key.verifying_key().to_bytes();
        let authority = AuthorityActorTarget {
            space: SpaceId([1; 32]),
            system_agent: AgentId([2; 32]),
            system_runtime_deployment: DeploymentId([3; 32]),
            binding: AgentAuthorityBinding {
                policy: Hash([4; 32]),
                issuer: AuthorityIssuer {
                    principal: PrincipalId::of_public_key(&public),
                    actor: ActorId([6; 32]),
                    deployment: DeploymentId([7; 32]),
                    program: ProgramId([8; 32]),
                    producer: ProducerId::of_public_key(&public),
                },
                public_key: public,
                initial_epoch: 1,
            },
        };
        let runtime = crate::agent::package_admission::admitted_standard_runtime_for_test(
            "retained-lookup-runtime",
            32,
        );
        let nonce = Hash([33; 32]);
        let owner = PrincipalId::of_public_key(&public);
        let agent = AgentId::derive(authority.space, owner, nonce.as_bytes());
        let mut members = (34..37)
            .map(|seed| {
                let peer = libp2p::identity::Keypair::ed25519_from_bytes([seed; 32])
                    .unwrap()
                    .public()
                    .to_peer_id()
                    .to_bytes();
                let public = SigningKey::from_bytes(&[seed; 32])
                    .verifying_key()
                    .to_bytes();
                super::super::super::genesis::AgentReplicaMember::new(
                    super::super::super::AgentReplica {
                        node: crate::service::NodeId::of_authenticated_peer(&peer),
                        principal: crate::service::PrincipalId::of_public_key(&public),
                        role: super::super::super::ReplicaRole::Voter,
                    },
                    peer.clone(),
                    public,
                    Some(super::super::super::genesis::derive_replica_raft_slot(
                        &peer,
                    )),
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        members.sort_unstable_by_key(|member| member.replica().node);
        let descriptor = AgentDescriptor {
            identity: AgentIdentity {
                space: authority.space,
                agent,
                owner,
                profile: AgentProfile::Shared,
                runtime_deployment: runtime.deployment(),
                runtime_program: runtime.program(),
                runtime_producer: runtime.producer(),
                transition_producer: ProducerId([38; 32]),
            },
            creation_nonce: nonce,
            authority: authority.binding,
            private_recovery: None,
            runtime_package: runtime.package_ref().clone(),
            runtime_contract: runtime.manifest().contract,
            capabilities: runtime.capabilities(),
            replicas: members
                .iter()
                .map(|member| super::super::super::sdk::AgentReplica {
                    node: NodeId(member.replica().node.0),
                    principal: PrincipalId(member.replica().principal.0),
                    role: ReplicaRole::Voter,
                })
                .collect(),
        };
        let locator = super::super::super::genesis::AgentGenesisLocator {
            space: crate::service::SpaceId(authority.space.0),
            agent: crate::service::AgentId(agent.0),
        };
        let committee = AgentReplicaCommittee::new(
            locator.space,
            locator.agent,
            super::super::super::AgentProfile::Shared,
            members,
        )
        .unwrap();
        let create = ManagementRequest::Create(Box::new(descriptor.clone()));
        let recovery = NativeSharedGenesisRecovery::reserve_create_with_replicas(
            authority,
            locator,
            descriptor.clone(),
            call(authority, &descriptor, &create, &key, 1),
            runtime,
            committee,
            (
                Store::default(),
                Store::default(),
                Store::default(),
                Store::default(),
                Store::default(),
                Store::default(),
            ),
        )
        .unwrap();
        let package = crate::agent::package_admission::admitted_standard_actor_for_test(
            "retained-lookup-actor",
            vos_agent_sdk::StateLane::Linear,
            39,
        );
        let install = install(agent, &package, 40);
        let request = ManagementRequest::Install(Box::new(install.clone()));
        let signed_call = call(authority, &descriptor, &request, &key, 2);
        let signed = CleanManagementIntent::new(
            authority,
            signed_call.managed,
            request,
            signed_call.clone(),
            &RawCredentialVerifier,
        )
        .unwrap();
        let retained = Store::default();
        let mut slot = CleanManagementIntentSlot::open(retained.clone()).unwrap();
        slot.pledge(signed).unwrap();
        slot.retain_actor(&package).unwrap();
        let slot = CleanManagementIntentSlot::open(slot.into_store()).unwrap();
        let mut controller = Controller::new(authority, vec![(recovery, None)]).unwrap();
        controller.entries[0].0.management_intent = Some(slot);
        // This test isolates selection over real signed, reopened memory
        // stores. It does not claim physical recovery, finality or readiness.
        controller.recovered = true;
        let before = retained.0.lock().unwrap().clone();
        assert_eq!(
            controller.retained_install_locator(&install, &signed_call, &package),
            Ok(Some(locator))
        );
        let changed_call = call(
            authority,
            &descriptor,
            &ManagementRequest::Install(Box::new(install.clone())),
            &key,
            3,
        );
        assert_eq!(
            controller.retained_install_locator(&install, &changed_call, &package),
            Err(SharedAgentHostError::Conflict)
        );
        let mut changed = install.clone();
        changed.registry_reservation = Hash([44; 32]);
        let changed_call = call(
            authority,
            &descriptor,
            &ManagementRequest::Install(Box::new(changed.clone())),
            &key,
            2,
        );
        assert_eq!(
            controller.retained_install_locator(&changed, &changed_call, &package),
            Err(SharedAgentHostError::Conflict)
        );
        let mut forged = signed_call.clone();
        forged.signature[0] ^= 1;
        assert_eq!(
            controller.retained_install_locator(&install, &forged, &package),
            Err(SharedAgentHostError::ScopeMismatch)
        );
        let mut wrong_owner = descriptor.clone();
        wrong_owner.identity.owner = PrincipalId([45; 32]);
        let wrong_call = call(
            authority,
            &wrong_owner,
            &ManagementRequest::Install(Box::new(install.clone())),
            &key,
            2,
        );
        assert_eq!(
            controller.retained_install_locator(&install, &wrong_call, &package),
            Err(SharedAgentHostError::ScopeMismatch)
        );
        let other_package = crate::agent::package_admission::admitted_standard_actor_for_test(
            "retained-lookup-actor",
            vos_agent_sdk::StateLane::Linear,
            46,
        );
        assert_eq!(
            controller.retained_install_locator(&install, &signed_call, &other_package),
            Err(SharedAgentHostError::ScopeMismatch)
        );
        let successor_install = self::install(agent, &other_package, 47);
        let successor_call = call(
            authority,
            &descriptor,
            &ManagementRequest::Install(Box::new(successor_install.clone())),
            &key,
            4,
        );
        assert_eq!(
            controller.retained_install_locator(
                &successor_install,
                &successor_call,
                &other_package
            ),
            Err(SharedAgentHostError::Conflict)
        );
        assert!(retained.0.lock().unwrap().clone() == before);
        retained.0.lock().unwrap().actor = None;
        let before_missing = retained.0.lock().unwrap().clone();
        assert_eq!(
            controller.retained_install_locator(&install, &signed_call, &package),
            Ok(None)
        );
        assert!(retained.0.lock().unwrap().clone() == before_missing);
        let slot = controller.entries[0].0.management_intent.take();
        assert_eq!(
            controller.retained_install_locator(&install, &signed_call, &package),
            Ok(None)
        );
        controller.entries[0].0.management_intent = slot;
        controller.entries.clear();
        assert_eq!(
            controller.retained_install_locator(&install, &signed_call, &package),
            Ok(None)
        );
        controller.member_archives.push((locator, Store::default()));
        assert_eq!(
            controller.retained_install_locator(&install, &signed_call, &package),
            Err(SharedAgentHostError::Conflict)
        );
        assert!(retained.0.lock().unwrap().clone() == before_missing);
    }
}

#[cfg(all(test, feature = "experimental-state-blocks"))]
mod member_archive_tests {
    use super::*;
    use crate::agent::sdk::{DeploymentId, PrincipalId, ProducerId, ProgramId};

    // Construction-only stores: no execution or finality fixture is supplied.
    struct NoStore;
    impl CleanManagementIssuerStore for NoStore {
        type Error = ();
        fn load(&mut self) -> Result<Option<Vec<u8>>, ()> {
            Ok(None)
        }
        fn commit(&mut self, _: &[u8]) -> Result<(), ()> {
            Err(())
        }
    }
    impl super::super::super::clean_authority_issuer::CleanManagementRuntimeStore for NoStore {
        fn load_runtime(&mut self) -> Result<Option<Vec<u8>>, ()> {
            Ok(None)
        }
        fn commit_runtime(&mut self, _: &[u8]) -> Result<(), ()> {
            Err(())
        }
    }
    impl super::super::super::clean_authority_issuer::CleanSharedGenesisReplicaStore for NoStore {
        fn load_replicas(&mut self) -> Result<Option<Vec<u8>>, ()> {
            Ok(None)
        }
        fn commit_replicas(&mut self, _: &[u8]) -> Result<(), ()> {
            Err(())
        }
    }
    impl super::super::super::genesis_archive::AgentGenesisArchiveStore for NoStore {
        type Error = ();
        fn load(
            &self,
            _: super::super::super::genesis::AgentGenesisLocator,
        ) -> Result<Option<Vec<u8>>, ()> {
            Ok(None)
        }
        fn insert_if_absent(
            &self,
            _: super::super::super::genesis::AgentGenesisLocator,
            _: &[u8],
        ) -> Result<(), ()> {
            Err(())
        }
    }
    type EmptyController = NativeSharedGenesisController<
        NoStore,
        NoStore,
        NoStore,
        NoStore,
        NoStore,
        NoStore,
        NoStore,
    >;

    #[test]
    fn live_member_archive_factory_retains_its_owner_without_running_it() {
        use std::sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        };
        struct Owner(Arc<AtomicUsize>);
        impl Drop for Owner {
            fn drop(&mut self) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }
        let drops = Arc::new(AtomicUsize::new(0));
        let calls = Arc::new(AtomicUsize::new(0));
        let owner = Owner(drops.clone());
        let factory_calls = calls.clone();
        let controller = EmptyController::new(authority(), Vec::new())
            .unwrap()
            .with_member_archive_factory(move |_| {
                let _retained = &owner;
                factory_calls.fetch_add(1, Ordering::SeqCst);
                Err(SharedAgentHostError::Unavailable)
            })
            .unwrap();
        assert!(controller.member_archives.is_empty());
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(drops.load(Ordering::SeqCst), 0);
        drop(controller);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(drops.load(Ordering::SeqCst), 1);

        let controller = EmptyController::new(authority(), Vec::new())
            .unwrap()
            .with_member_archive_factory(|_| Err(SharedAgentHostError::Unavailable))
            .unwrap();
        assert!(matches!(
            controller.with_member_archive_factory(|_| Err(SharedAgentHostError::Unavailable)),
            Err(SharedAgentHostError::Conflict)
        ));
        let mut controller = EmptyController::new(authority(), Vec::new()).unwrap();
        controller.recovered = true; // Tests only builder ownership, not recovery.
        assert!(matches!(
            controller.with_member_archive_factory(|_| Err(SharedAgentHostError::Unavailable)),
            Err(SharedAgentHostError::Conflict)
        ));
    }

    fn authority() -> AuthorityActorTarget {
        let public_key = [9; 32];
        AuthorityActorTarget {
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
        }
    }

    #[test]
    fn member_archive_union_rejects_duplicate_and_wrong_scope_locators() {
        let authority = authority();
        let locator = super::super::super::genesis::AgentGenesisLocator {
            space: crate::service::SpaceId(authority.space.0),
            agent: crate::service::AgentId([14; 32]),
        };
        // This guard validates selections only; it mints no finality proof.
        assert_eq!(
            validate_member_archive_locators(authority, &[], &[]),
            Ok(())
        );
        for (issuer, members) in [
            (vec![locator], vec![locator]),
            (Vec::new(), vec![locator, locator]),
        ] {
            assert_eq!(
                validate_member_archive_locators(authority, &issuer, &members),
                Err(SharedAgentHostError::Conflict),
            );
        }
        for changed in [
            super::super::super::genesis::AgentGenesisLocator {
                space: crate::service::SpaceId([15; 32]),
                ..locator
            },
            super::super::super::genesis::AgentGenesisLocator {
                agent: crate::service::AgentId::ZERO,
                ..locator
            },
            super::super::super::genesis::AgentGenesisLocator {
                agent: crate::service::AgentId(authority.system_agent.0),
                ..locator
            },
        ] {
            assert_eq!(
                validate_member_archive_locators(authority, &[], &[changed]),
                Err(SharedAgentHostError::ScopeMismatch),
            );
        }
        assert_eq!(
            validate_member_archive_locators(
                authority,
                &[locator],
                &vec![locator; super::super::super::shared_host::MAX_SHARED_HOST_AGENTS]
            ),
            Err(SharedAgentHostError::CapacityExhausted),
        );
    }

    #[test]
    fn live_member_archive_selection_reuses_only_exact_member_ownership() {
        let authority = authority();
        let locator = super::super::super::genesis::AgentGenesisLocator {
            space: crate::service::SpaceId(authority.space.0),
            agent: crate::service::AgentId([14; 32]),
        };
        assert_eq!(
            validate_live_member_archive_selection(authority, false, &[], &[], locator),
            Err(SharedAgentHostError::Conflict)
        );
        assert_eq!(
            validate_live_member_archive_selection(authority, true, &[], &[], locator),
            Ok(None)
        );
        assert_eq!(
            validate_live_member_archive_selection(authority, true, &[], &[locator], locator),
            Ok(Some(0))
        );
        assert_eq!(
            validate_live_member_archive_selection(authority, true, &[locator], &[], locator),
            Err(SharedAgentHostError::Conflict)
        );
        for changed in [
            super::super::super::genesis::AgentGenesisLocator {
                space: crate::service::SpaceId([15; 32]),
                ..locator
            },
            super::super::super::genesis::AgentGenesisLocator {
                agent: crate::service::AgentId(authority.system_agent.0),
                ..locator
            },
        ] {
            assert_eq!(
                validate_live_member_archive_selection(authority, true, &[], &[locator], changed),
                Err(SharedAgentHostError::ScopeMismatch)
            );
        }
        let maximum = super::super::super::shared_host::MAX_SHARED_HOST_AGENTS;
        let mut members = Vec::new();
        for index in 0..maximum {
            let mut id = [16; 32];
            id[..8].copy_from_slice(&(index as u64 + 1).to_le_bytes());
            members.push(super::super::super::genesis::AgentGenesisLocator {
                agent: crate::service::AgentId(id),
                ..locator
            });
        }
        assert_eq!(
            validate_live_member_archive_selection(
                authority,
                true,
                &[],
                &members,
                members[maximum - 1]
            ),
            Ok(Some(maximum - 1))
        );
        assert_eq!(
            validate_live_member_archive_selection(authority, true, &[], &members, locator),
            Err(SharedAgentHostError::CapacityExhausted)
        );
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
    pub(super) runtime: Option<SharedGenesisRuntimePackage>,
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
        Self::validate_create_reservation_with_runtime(
            authority,
            locator,
            descriptor,
            call,
            &SharedGenesisRuntimePackage::Image(runtime.clone()),
            replicas,
        )
    }

    pub fn validate_create_reservation_with_runtime(
        authority: AuthorityActorTarget,
        locator: super::super::genesis::AgentGenesisLocator,
        descriptor: &AgentDescriptor,
        call: &super::super::sdk::authority::AuthorityCredentialCall,
        runtime: &SharedGenesisRuntimePackage,
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
        runtime: &SharedGenesisRuntimePackage,
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
        runtime.validate_descriptor(descriptor)?;
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
        Self::reserve_create_with_replicas_runtime(
            authority,
            locator,
            descriptor,
            call,
            SharedGenesisRuntimePackage::Image(runtime),
            replicas,
            stores,
        )
    }

    pub fn reserve_create_with_replicas_runtime(
        authority: AuthorityActorTarget,
        locator: super::super::genesis::AgentGenesisLocator,
        descriptor: AgentDescriptor,
        call: super::super::sdk::authority::AuthorityCredentialCall,
        runtime: SharedGenesisRuntimePackage,
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
                .map(SharedGenesisRuntimePackage::exact_bytes)
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
        // Fresh fixed-three startup has no durable committee read. Do not
        // reinterpret an older query/reply capsule as the selected-roster
        // sidecar: that separate Q-store object and its lease remain intact.
        if query
            .load()
            .map_err(|_| SharedAgentHostError::Unavailable)?
            .is_some()
            || reply
                .load()
                .map_err(|_| SharedAgentHostError::Unavailable)?
                .is_some()
        {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
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
            .map(|bytes| SharedGenesisRuntimePackage::from_retained(&descriptor, &bytes))
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
                if let Some(provision) =
                    genesis_issuance::RetainedGenesisPublication::load_candidate_for_recovery(
                        &mut publication,
                    )
                    .map_err(|_| SharedAgentHostError::ScopeMismatch)?
                {
                    let super::super::journal::ReplayOperation::CleanManage {
                        request: ManagementRequest::Create(saved_descriptor),
                        authority: receipt,
                        ..
                    } = &provision.proposal().create().operation
                    else {
                        return Err(SharedAgentHostError::ScopeMismatch);
                    };
                    let selected = query
                        .load_replicas()
                        .map_err(|_| SharedAgentHostError::Unavailable)?
                        .ok_or(SharedAgentHostError::ScopeMismatch)?;
                    if selected.len() > MAX_AGENT_REPLICA_COMMITTEE_BYTES {
                        return Err(SharedAgentHostError::ScopeMismatch);
                    }
                    let replicas = AgentReplicaCommittee::decode(&selected)
                        .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
                    if issued.as_ref() != Some(receipt)
                        || saved_descriptor.as_ref() != &descriptor
                        || replicas.encode() != selected
                        || replicas.validate_for_clean_descriptor(&descriptor).is_err()
                        || provision.replicas() != &replicas
                    {
                        return Err(SharedAgentHostError::ScopeMismatch);
                    }
                    let saved = genesis_issuance::RetainedGenesisPublication::load_for_recovery(
                        &mut publication,
                        &authority,
                        provision.evidence().claim().authority_claim().claim_hash(),
                        anchor,
                        work,
                    )
                    .map_err(|_| SharedAgentHostError::ScopeMismatch)?
                    .ok_or(SharedAgentHostError::ScopeMismatch)?;
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
            if pending.len() != 2 {
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

    /// Reconstruct a failed pre-archive preparation through the existing
    /// canonical open path, borrowing rather than moving the original leases.
    /// Reload grants no execution/finality: the owner still replays every phase.
    fn readmit_creation_from_leased_stores(&mut self) -> Result<(), SharedAgentHostError>
    where
        Q: super::super::clean_authority_issuer::CleanSharedGenesisReplicaStore,
    {
        self.admission_valid = false;
        if self.management_issuer.is_some()
            || self.management_intent.is_some()
            || !self.management_pending.is_empty()
            || !self.management_retirements.is_empty()
        {
            return Err(SharedAgentHostError::Conflict);
        }
        let original = self
            .intent
            .intent()
            .cloned()
            .ok_or(SharedAgentHostError::ScopeMismatch)?;
        let original_runtime = self
            .runtime
            .as_ref()
            .map(|runtime| runtime.exact_bytes().to_vec());
        let original_pending = self.pending.clone();
        let original_issued = self.issued.clone();
        let original_retired = self.retired;
        let (intent_cache, issuer_cache, runtime, pending, issued, retired) = {
            let recovered = NativeSharedGenesisRecovery::open(
                self.authority,
                self.locator,
                self.intent.leased_store_mut(),
                self.issuer.leased_store_mut(),
                &mut self.query,
                &mut self.reply,
                &mut self.publication,
                &mut self.publication_reply,
            )?;
            let request = recovered
                .intent
                .intent()
                .ok_or(SharedAgentHostError::ScopeMismatch)?;
            if request.request() != original.request()
                || request.call() != original.call()
                || original_runtime.as_ref().is_some_and(|bytes| {
                    recovered
                        .runtime
                        .as_ref()
                        .map(|runtime| runtime.exact_bytes())
                        != Some(bytes.as_slice())
                })
                || original_issued
                    .as_ref()
                    .is_some_and(|receipt| recovered.issued.as_ref() != Some(receipt))
                || (original_retired && !recovered.retired)
                || (!recovered.retired
                    && !recovered
                        .intent
                        .denial_complete()
                        .map_err(|_| SharedAgentHostError::Unavailable)?
                    && !recovered.pending.starts_with(&original_pending))
            {
                return Err(SharedAgentHostError::ScopeMismatch);
            }
            (
                recovered
                    .intent
                    .into_reload_cache()
                    .map_err(|_| SharedAgentHostError::ScopeMismatch)?,
                recovered
                    .issuer
                    .into_creation_reload_cache()
                    .map_err(|_| SharedAgentHostError::ScopeMismatch)?,
                recovered.runtime,
                recovered.pending,
                recovered.issued,
                recovered.retired,
            )
        };
        // No cache or admission field changes until the entire canonical set
        // and both monotonic, exact-original ownership guards have succeeded.
        if !self.intent.validates_reload_cache(&intent_cache)
            || !self.issuer.validates_creation_reload_cache(&issuer_cache)
        {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        self.intent.install_reload_cache(intent_cache);
        self.issuer.install_creation_reload_cache(issuer_cache);
        self.runtime = runtime;
        self.pending = pending;
        self.issued = issued;
        self.retired = retired;
        self.admission_valid = true;
        Ok(())
    }

    /// The exact locator checked against the signed Create during opening.
    /// This identifies the reservation; it is not proof of publication/finality.
    pub fn locator(&self) -> super::super::genesis::AgentGenesisLocator {
        self.locator
    }

    /// Admitted, descriptor-bound package retained before authorization.
    pub fn runtime(&self) -> Option<&SharedGenesisRuntimePackage> {
        self.runtime.as_ref()
    }

    pub fn issued_receipt(&self) -> Option<&AuthorityReceipt> {
        self.issued.as_ref()
    }

    /// Re-admit the independently retained replica selection under its original
    /// store lease. The file envelope is not authority: peer identities must be
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
