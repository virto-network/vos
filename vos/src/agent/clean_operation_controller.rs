//! Long-lived ownership of operation stores; parsed state is reopened for each
//! call so an ambiguous write cannot leave a stale in-memory issuer in use.

use super::*;
use crate::agent::authority_operation_coordinator::{
    AuthorityOperationCoordinatorError, AuthorityOperationCoordinatorStore,
    DurableAuthorityOperationCoordinator, MAX_AUTHORITY_OPERATION_COORDINATOR_RECORDS,
};
use crate::agent::authority_operation_issuer::{
    AuthorityOperationEvidenceSigner, AuthorityOperationIssuerError, AuthorityOperationIssuerStore,
    DurableAuthorityOperationIssuer, IssuedAuthorityOperation,
};
use crate::agent::sdk::InvocationContext;
use crate::agent::sdk::authority_operation::AuthorityOperationCall;

/// A leased, bounded completion index. Implementations must synchronize exact
/// retries and preserve existing certificates on failed or conflicting writes.
pub trait NativeAuthorityOperationCompletionStore {
    type Error;
    fn load(&mut self) -> Result<Vec<Vec<u8>>, Self::Error>;
    fn retain(&mut self, certificate: &[u8]) -> Result<(), Self::Error>;
    fn remove_retired(&mut self, _certificate: &[u8], _terminal: &[u8]) -> Result<(), Self::Error> {
        Ok(())
    }
}

// Legacy/test construction has no completion persistence. It must never
// manufacture a successful durability acknowledgement.
impl NativeAuthorityOperationCompletionStore for () {
    type Error = SharedAgentHostError;
    fn load(&mut self) -> Result<Vec<Vec<u8>>, SharedAgentHostError> {
        Ok(Vec::new())
    }
    fn retain(&mut self, _: &[u8]) -> Result<(), SharedAgentHostError> {
        Err(SharedAgentHostError::Unavailable)
    }
}

/// Retains all exclusive store handles across calls and failures.
/// Construction does not assert recovery or release admission: the caller must
/// restore startup admission before dispatch and keep the controller alive for
/// the lifetime of the corresponding system owner.
pub struct NativeAuthorityOperationController<C, B, J, K = (), T = (), D = ()> {
    authority: AuthorityActorTarget,
    coordinator: C,
    issuer: B,
    journal: J,
    completions: K,
    retirements: T,
    denials: D,
}

#[derive(Debug)]
pub enum NativeAuthorityOperationControllerError<C, B, S> {
    WrongAuthority,
    Completion(SharedAgentHostError),
    OpenIssuer(AuthorityOperationIssuerError<B>),
    OpenCoordinator(AuthorityOperationCoordinatorError<C, B>),
    Coordinate(AuthorityOperationCoordinatorError<C, B, SharedAgentHostError, S>),
}

/// A policy decision is distinct from transport, execution or persistence failure.
/// Issuance authorizes application; it does not prove application completed.
#[derive(Debug)]
pub enum NativeAuthorityOperationDecision {
    Issued(IssuedAuthorityOperation),
    /// Exact synchronized NDR1 and its committed NOD1 source.
    Denied {
        certificate: Vec<u8>,
        dispatch: Vec<u8>,
    },
}

impl<C, B, J> NativeAuthorityOperationController<C, B, J>
where
    C: AuthorityOperationCoordinatorStore,
    B: AuthorityOperationIssuerStore,
    J: NativeAuthorityOperationJournalStore,
{
    pub fn new(authority: AuthorityActorTarget, coordinator: C, issuer: B, journal: J) -> Self {
        Self {
            authority,
            coordinator,
            issuer,
            journal,
            completions: (),
            retirements: (),
            denials: (),
        }
    }

    pub fn with_completions<K: NativeAuthorityOperationCompletionStore>(
        self,
        completions: K,
    ) -> NativeAuthorityOperationController<C, B, J, K> {
        NativeAuthorityOperationController {
            authority: self.authority,
            coordinator: self.coordinator,
            issuer: self.issuer,
            journal: self.journal,
            completions,
            retirements: (),
            denials: (),
        }
    }

    pub fn into_parts(self) -> (C, B, J) {
        (self.coordinator, self.issuer, self.journal)
    }
}

impl<C, B, J, K> NativeAuthorityOperationController<C, B, J, K>
where
    C: AuthorityOperationCoordinatorStore,
    B: AuthorityOperationIssuerStore,
    J: NativeAuthorityOperationJournalStore,
    K: NativeAuthorityOperationCompletionStore,
{
    pub fn with_retirements<T: NativeAuthorityOperationRetirementStore>(
        self,
        retirements: T,
    ) -> NativeAuthorityOperationController<C, B, J, K, T> {
        NativeAuthorityOperationController {
            authority: self.authority,
            coordinator: self.coordinator,
            issuer: self.issuer,
            journal: self.journal,
            completions: self.completions,
            retirements,
            denials: (),
        }
    }

    pub fn into_parts_with_completions(self) -> (C, B, J, K) {
        (
            self.coordinator,
            self.issuer,
            self.journal,
            self.completions,
        )
    }
}

impl<C, B, J, K, T> NativeAuthorityOperationController<C, B, J, K, T> {
    pub fn with_denials<D: NativeAuthorityOperationDenialStore>(
        self,
        denials: D,
    ) -> NativeAuthorityOperationController<C, B, J, K, T, D> {
        NativeAuthorityOperationController {
            authority: self.authority,
            coordinator: self.coordinator,
            issuer: self.issuer,
            journal: self.journal,
            completions: self.completions,
            retirements: self.retirements,
            denials,
        }
    }

    pub fn into_all_parts(self) -> (C, B, J, K, T) {
        (
            self.coordinator,
            self.issuer,
            self.journal,
            self.completions,
            self.retirements,
        )
    }
}

impl<C, B, J, K, T, D> NativeAuthorityOperationController<C, B, J, K, T, D>
where
    C: AuthorityOperationCoordinatorStore,
    B: AuthorityOperationIssuerStore,
    J: NativeAuthorityOperationJournalStore,
    K: NativeAuthorityOperationCompletionStore,
    T: NativeAuthorityOperationRetirementStore,
    D: NativeAuthorityOperationDenialStore,
{
    pub fn startup_admission(
        &mut self,
        invocations: &[InvocationId],
    ) -> Result<NativeAuthorityOperationStartupAdmission<'_>, SharedAgentHostError> {
        let mut seen = std::collections::BTreeSet::new();
        if invocations.len() > 2 * MAX_AUTHORITY_OPERATION_COORDINATOR_RECORDS
            || invocations
                .iter()
                .any(|id| *id == InvocationId::ZERO || !seen.insert(*id))
        {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        self.validate()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        // Reconciliation may have removed only archive-proved hot records.
        // Re-read bounded discovery rather than treating the caller's earlier
        // pre-compaction snapshot as fresh pending work.
        let active = self
            .journal
            .active_invocations()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        let invocations = if let Some(active) = active.as_ref() {
            if active.iter().any(|id| !invocations.contains(id)) {
                return Err(SharedAgentHostError::ScopeMismatch);
            }
            for id in invocations.iter().filter(|id| !active.contains(id)) {
                self.retired_pair(*id)?
                    .ok_or(SharedAgentHostError::ScopeMismatch)?;
            }
            active.as_slice()
        } else {
            invocations
        };
        let certificates = self
            .completions
            .load()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        let retirements = self
            .retirements
            .load()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        let denials = self
            .denials
            .load()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        NativeAuthorityOperationStartupAdmission::load_with_denials(
            &mut self.journal,
            &mut self.issuer,
            self.authority,
            invocations,
            &certificates,
            &retirements,
            &denials,
        )
    }

    pub fn authority(&self) -> AuthorityActorTarget {
        self.authority
    }

    fn retired_pair(
        &mut self,
        invocation: InvocationId,
    ) -> Result<
        Option<(
            [Vec<u8>; 3],
            operation_dispatch::RetainedNativeOperationRetirement,
        )>,
        SharedAgentHostError,
    > {
        let Some(bytes) = self
            .journal
            .load_retired(invocation)
            .map_err(|_| SharedAgentHostError::Unavailable)?
        else {
            return Ok(None);
        };
        if !operation_dispatch::native_operation_retired_pair_matches(
            self.authority,
            invocation,
            &bytes[0],
            &bytes[1],
            &bytes[2],
        ) {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        let authorization =
            operation_dispatch::RetainedAuthorityOperationDispatch::decode(&bytes[0])
                .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
        let acknowledgement =
            operation_dispatch::RetainedAuthorityOperationDispatch::decode(&bytes[1])
                .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
        let terminal = operation_dispatch::restore_retired_operation_pair(
            self.authority,
            &authorization,
            &acknowledgement,
            &bytes[2],
        )?;
        Ok(Some((bytes, terminal)))
    }

    fn retired_for_call(
        &mut self,
        call: &AuthorityOperationCall,
        context: Option<&InvocationContext>,
        issued_at: Option<u64>,
    ) -> Result<Option<(InvocationContext, IssuedAuthorityOperation)>, SharedAgentHostError> {
        if let Some((bytes, terminal)) = self.retired_pair(call.invocation)? {
            let (authorization, _) = terminal.dispatches();
            let issued = terminal.issued()?;
            if authorization.request
                != call
                    .encode()
                    .map_err(|_| SharedAgentHostError::ScopeMismatch)?
                || context.is_some_and(|context| context != &authorization.context)
                || issued_at.is_some_and(|slot| slot != issued.issuance_ack.issued_at)
            {
                return Err(SharedAgentHostError::ScopeMismatch);
            }
            if !self
                .journal
                .retain_retired([&bytes[0], &bytes[1]], &bytes[2])
                .map_err(|_| SharedAgentHostError::Unavailable)?
            {
                return Err(SharedAgentHostError::Unavailable);
            }
            return Ok(Some((authorization.context.clone(), issued)));
        }
        let acknowledgement = crate::agent::sdk::authority_operation::AuthorityOperationApproval
            ::derive_acknowledgement_invocation(call);
        if self.retired_pair(acknowledgement)?.is_some() {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        Ok(None)
    }

    /// Reconcile one bounded hot set against targeted immutable terminal
    /// witnesses before opening the strict coordinator/issuer pair. This is
    /// restartable after either image or any hot-index publication fails.
    fn compact_retired(&mut self) -> Result<(), SharedAgentHostError> {
        if !self.journal.supports_retired_archive() {
            return Ok(());
        }
        let mut jobs = std::collections::BTreeMap::new();
        let mut covered = std::collections::BTreeSet::new();
        let certificates = self
            .retirements
            .load()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        if certificates.len() > MAX_AUTHORITY_OPERATION_COORDINATOR_RECORDS {
            return Err(SharedAgentHostError::CapacityExhausted);
        }
        for certificate in certificates {
            let completion = native_operation_retirement_completion(
                &self.authority.binding.public_key,
                &certificate,
            )
            .ok_or(SharedAgentHostError::ScopeMismatch)?;
            let ids = native_operation_completion_invocations(
                &self.authority.binding.public_key,
                &completion,
            )
            .ok_or(SharedAgentHostError::ScopeMismatch)?;
            let a = self
                .journal
                .load(ids[0])
                .map_err(|_| SharedAgentHostError::Unavailable)?
                .ok_or(SharedAgentHostError::ScopeMismatch)?;
            let b = self
                .journal
                .load(ids[1])
                .map_err(|_| SharedAgentHostError::Unavailable)?
                .ok_or(SharedAgentHostError::ScopeMismatch)?;
            let record = operation_dispatch::RetainedAuthorityOperationDispatch::decode(&a)
                .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
            let call = AuthorityOperationCall::decode(&record.request().request)
                .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
            if matches!(
                call.intent,
                crate::agent::sdk::authority_operation::AuthorityOperationIntent::InvokeActor { .. }
            ) && call.intent.managed().profile != crate::agent::sdk::AgentProfile::Private
            {
                if ids.iter().any(|id| covered.contains(id)) {
                    return Err(SharedAgentHostError::ScopeMismatch);
                }
                covered.extend(ids);
                if jobs.insert(ids[0], [a, b, certificate]).is_some() {
                    return Err(SharedAgentHostError::ScopeMismatch);
                }
            }
        }
        // A crash may already have removed the hot certificate while leaving
        // one NOD. Its archived exact proof, never absence, resumes cleanup.
        for id in self
            .journal
            .active_invocations()
            .map_err(|_| SharedAgentHostError::Unavailable)?
            .unwrap_or_default()
        {
            if covered.contains(&id) {
                continue;
            }
            if let Some((bytes, terminal)) = self.retired_pair(id)? {
                let ids = [
                    terminal.dispatches().0.context.invocation,
                    terminal.dispatches().1.context.invocation,
                ];
                if ids.iter().any(|id| covered.contains(id)) {
                    return Err(SharedAgentHostError::ScopeMismatch);
                }
                covered.extend(ids);
                if jobs.insert(ids[0], bytes).is_some() {
                    return Err(SharedAgentHostError::ScopeMismatch);
                }
            }
        }
        if jobs.len() > MAX_AUTHORITY_OPERATION_COORDINATOR_RECORDS {
            return Err(SharedAgentHostError::CapacityExhausted);
        }
        for (id, bytes) in jobs {
            if !operation_dispatch::native_operation_retired_pair_matches(
                self.authority,
                id,
                &bytes[0],
                &bytes[1],
                &bytes[2],
            ) {
                return Err(SharedAgentHostError::ScopeMismatch);
            }
            let a = operation_dispatch::RetainedAuthorityOperationDispatch::decode(&bytes[0])
                .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
            let b = operation_dispatch::RetainedAuthorityOperationDispatch::decode(&bytes[1])
                .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
            let terminal = operation_dispatch::restore_retired_operation_pair(
                self.authority,
                &a,
                &b,
                &bytes[2],
            )?;
            let coordinator =
                crate::agent::authority_operation_coordinator::compact_native_operation_terminal(
                    &mut self.coordinator,
                    self.authority,
                    &terminal,
                    false,
                )
                .map_err(|_| SharedAgentHostError::Unavailable)?;
            let issuer =
                crate::agent::authority_operation_issuer::compact_native_operation_terminal(
                    &mut self.issuer,
                    self.authority,
                    &terminal,
                    false,
                )
                .map_err(|_| SharedAgentHostError::Unavailable)?;
            if !coordinator || !issuer {
                continue;
            }
            if !self
                .journal
                .retain_retired([&bytes[0], &bytes[1]], &bytes[2])
                .map_err(|_| SharedAgentHostError::Unavailable)?
            {
                return Err(SharedAgentHostError::Unavailable);
            }
            if !crate::agent::authority_operation_coordinator::compact_native_operation_terminal(
                &mut self.coordinator,
                self.authority,
                &terminal,
                true,
            )
            .map_err(|_| SharedAgentHostError::Unavailable)?
            {
                return Err(SharedAgentHostError::ScopeMismatch);
            }
            if !crate::agent::authority_operation_issuer::compact_native_operation_terminal(
                &mut self.issuer,
                self.authority,
                &terminal,
                true,
            )
            .map_err(|_| SharedAgentHostError::Unavailable)?
            {
                return Err(SharedAgentHostError::ScopeMismatch);
            }
            let completion = native_operation_retirement_completion(
                &self.authority.binding.public_key,
                &bytes[2],
            )
            .ok_or(SharedAgentHostError::ScopeMismatch)?;
            self.completions
                .remove_retired(&completion, &bytes[2])
                .map_err(|_| SharedAgentHostError::Unavailable)?;
            self.retirements
                .remove_retired(&bytes[2])
                .map_err(|_| SharedAgentHostError::Unavailable)?;
            self.journal
                .remove_retired([&bytes[0], &bytes[1]], &bytes[2])
                .map_err(|_| SharedAgentHostError::Unavailable)?;
        }
        Ok(())
    }

    /// Prepare signed call ingress at the authoritative host clock and persist
    /// native work before returning its immutable authorization context. This
    /// performs no policy execution, receipt issuance or reservation release.
    pub fn prepare_call<P, R, I>(
        &mut self,
        owner: &mut CleanSystemAgentBootstrapOwner<P, R, I>,
        call: &AuthorityOperationCall,
    ) -> Result<InvocationContext, SharedAgentHostError>
    where
        P: CleanSystemAgentBootstrapStore,
        R: CleanSystemAgentBootstrapStore,
        I: CleanManagementIssuerStore,
    {
        let _timing = crate::agent::local_lifecycle::OperationTiming::start("controller_prepare");
        let diagnostic_request = std::env::var_os("VOS_TEST_BOOTSTRAP_DIAGNOSTICS")
            .map(|_| call.commitment());
        let diagnostic_node = owner.pins().node();
        let refused = |category: &'static str, error: &SharedAgentHostError| {
            if let Some(request) = diagnostic_request {
                tracing::debug!(target: "vos::agent::local_lifecycle",
                    invocation = ?call.invocation.0, request = ?request.0,
                    node = ?diagnostic_node.0, stage = "controller_prepare", category,
                    error_code = error.diagnostic_category(), "operation_refusal");
            }
        };
        if owner.authority_target() != self.authority {
            refused("owner_authority", &SharedAgentHostError::ScopeMismatch);
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        if call.authority != self.authority {
            refused("call_authority", &SharedAgentHostError::ScopeMismatch);
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        self.validate()
            .map_err(|error| {
                let category = match &error {
                    NativeAuthorityOperationControllerError::WrongAuthority => "wrong_authority",
                    NativeAuthorityOperationControllerError::Completion(_) => "completion",
                    NativeAuthorityOperationControllerError::OpenIssuer(_) => "issuer_open",
                    NativeAuthorityOperationControllerError::OpenCoordinator(_) => "coordinator_open",
                    NativeAuthorityOperationControllerError::Coordinate(_) => "coordinate",
                };
                // Preserve disposal of the masked store/controller error before
                // logging; never format its payload at this boundary.
                drop(error);
                refused(category, &SharedAgentHostError::Unavailable);
                tracing::warn!(invocation = ?call.invocation.0,
                    phase = "controller_validation", category,
                    "native operation preparation branch refused");
                SharedAgentHostError::Unavailable
            })?;
        if let Some((context, _)) = self.retired_for_call(call, None, None)
            .map_err(|error| {
                refused("retained_lookup", &error);
                error
            })?
        {
            return Ok(context);
        }
        operation_dispatch::NativeAuthorityOperationDispatcher::new(owner, &mut self.journal)
            .prepare_call(call)
            .map_err(|error| {
                refused("dispatch_prepare", &error);
                error
            })
    }

    /// Reconcile archive-certified older terminal rows, then cross-check both
    /// active images without executing or signing any operation.
    pub fn validate(
        &mut self,
    ) -> Result<
        (),
        NativeAuthorityOperationControllerError<C::Error, B::Error, core::convert::Infallible>,
    > {
        let _timing = crate::agent::local_lifecycle::OperationTiming::start("controller_validate");
        self.compact_retired()
            .map_err(NativeAuthorityOperationControllerError::Completion)?;
        let issuer =
            DurableAuthorityOperationIssuer::open(BorrowedIssuer(&mut self.issuer), self.authority)
                .map_err(NativeAuthorityOperationControllerError::OpenIssuer)?;
        let coordinator = DurableAuthorityOperationCoordinator::open(
            BorrowedCoordinator(&mut self.coordinator),
            self.authority,
            ValidationOnly,
            issuer,
        )
        .map_err(NativeAuthorityOperationControllerError::OpenCoordinator)?;
        let requests = coordinator
            .required_native_dispatches()
            .map_err(NativeAuthorityOperationControllerError::OpenCoordinator)?;
        drop(coordinator);
        for request in requests {
            let saved = self
                .journal
                .load(request.context.invocation)
                .map_err(|_| {
                    NativeAuthorityOperationControllerError::Coordinate(
                        AuthorityOperationCoordinatorError::Dispatch(
                            SharedAgentHostError::Unavailable,
                        ),
                    )
                })?
                .ok_or(NativeAuthorityOperationControllerError::Coordinate(
                    AuthorityOperationCoordinatorError::InvalidState,
                ))?;
            let record = operation_dispatch::RetainedAuthorityOperationDispatch::decode(&saved)
                .map_err(|_| {
                    NativeAuthorityOperationControllerError::Coordinate(
                        AuthorityOperationCoordinatorError::InvalidState,
                    )
                })?;
            if record.request() != &request
                || record.encode().ok().as_deref() != Some(saved.as_slice())
            {
                return Err(NativeAuthorityOperationControllerError::Coordinate(
                    AuthorityOperationCoordinatorError::InvalidState,
                ));
            }
        }
        let certificates = self.completions.load().map_err(|_| {
            NativeAuthorityOperationControllerError::Completion(SharedAgentHostError::Unavailable)
        })?;
        if certificates.len() > MAX_AUTHORITY_OPERATION_COORDINATOR_RECORDS {
            return Err(NativeAuthorityOperationControllerError::Completion(
                SharedAgentHostError::Unavailable,
            ));
        }
        let mut invocations = Vec::new();
        for certificate in &certificates {
            let ids = native_operation_completion_invocations(
                &self.authority.binding.public_key,
                certificate,
            )
            .ok_or(NativeAuthorityOperationControllerError::Completion(
                SharedAgentHostError::Unavailable,
            ))?;
            invocations.extend_from_slice(&ids);
        }
        let retirements = self.retirements.load().map_err(|_| {
            NativeAuthorityOperationControllerError::Completion(SharedAgentHostError::Unavailable)
        })?;
        let denials = self.denials.load().map_err(|_| {
            NativeAuthorityOperationControllerError::Completion(SharedAgentHostError::Unavailable)
        })?;
        if denials.len() > MAX_AUTHORITY_OPERATION_COORDINATOR_RECORDS {
            return Err(NativeAuthorityOperationControllerError::Completion(
                SharedAgentHostError::Unavailable,
            ));
        }
        for certificate in &denials {
            let id =
                native_operation_denial_invocation(&self.authority.binding.public_key, certificate)
                    .ok_or(NativeAuthorityOperationControllerError::Completion(
                        SharedAgentHostError::Unavailable,
                    ))?;
            if !invocations.contains(&id) {
                invocations.push(id);
            }
        }
        NativeAuthorityOperationStartupAdmission::load_with_denials(
            &mut self.journal,
            &mut self.issuer,
            self.authority,
            &invocations,
            &certificates,
            &retirements,
            &denials,
        )
        .map_err(NativeAuthorityOperationControllerError::Completion)?;
        Ok(())
    }

    /// Recovery routing only: require the exact retained call/context before
    /// invoking the normal coordinator, which still verifies all policy inputs.
    pub(crate) fn retains_call(
        &mut self,
        call: &AuthorityOperationCall,
        context: Option<&InvocationContext>,
    ) -> Result<bool, SharedAgentHostError> {
        let Some(bytes) = self
            .journal
            .load(call.invocation)
            .map_err(|_| SharedAgentHostError::Unavailable)?
        else {
            return Ok(false);
        };
        let record = operation_dispatch::RetainedAuthorityOperationDispatch::decode(&bytes)
            .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
        let request = record.request();
        Ok(request.target == self.authority
            && request.target == call.authority
            && request.method == crate::agent::authority_operation_coordinator::AuthorityOperationActorMethod::AuthorizeOperation
            && request.request == call.encode().map_err(|_| SharedAgentHostError::ScopeMismatch)?
            && context.is_none_or(|context| context == &request.context))
    }

    /// Only the native owner can supply policy results. Neither retained
    /// unsigned approval bytes nor a caller-provided dispatcher can reach the
    /// signer through this boundary. Exact contexts/slots remain caller inputs;
    /// retries must use their retained values, not a newly observed clock.
    pub fn coordinate<P, R, I, S>(
        &mut self,
        owner: &mut CleanSystemAgentBootstrapOwner<P, R, I>,
        call: &AuthorityOperationCall,
        context: InvocationContext,
        issued_at: u64,
        signer: &mut S,
    ) -> Result<
        IssuedAuthorityOperation,
        NativeAuthorityOperationControllerError<C::Error, B::Error, S::Error>,
    >
    where
        P: CleanSystemAgentBootstrapStore,
        R: CleanSystemAgentBootstrapStore,
        I: CleanManagementIssuerStore,
        S: AuthorityOperationEvidenceSigner,
    {
        let _timing = crate::agent::local_lifecycle::OperationTiming::start("controller_coordinate");
        if !self.authority.is_valid()
            || self.authority != owner.authority_target()
            || call.authority != self.authority
        {
            return Err(NativeAuthorityOperationControllerError::WrongAuthority);
        }
        if let Some((_, issued)) = self
            .retired_for_call(call, Some(&context), Some(issued_at))
            .map_err(NativeAuthorityOperationControllerError::Completion)?
        {
            return Ok(issued);
        }
        // Borrow rather than move the backing stores: even failed opens retain
        // the controller's leases. Every call rereads both canonical images.
        let issuer =
            DurableAuthorityOperationIssuer::open(BorrowedIssuer(&mut self.issuer), self.authority)
                .map_err(NativeAuthorityOperationControllerError::OpenIssuer)?;
        let dispatcher =
            operation_dispatch::NativeAuthorityOperationDispatcher::new(owner, &mut self.journal);
        let mut coordinator = DurableAuthorityOperationCoordinator::open(
            BorrowedCoordinator(&mut self.coordinator),
            self.authority,
            dispatcher,
            issuer,
        )
        .map_err(NativeAuthorityOperationControllerError::OpenCoordinator)?;
        coordinator
            .coordinate(call, context, issued_at, signer)
            .map_err(NativeAuthorityOperationControllerError::Coordinate)
    }

    /// Finish the native policy-result pair only after durably retaining its
    /// signed continuation. This does not release admission or apply the actor
    /// operation. Exact retries reuse retained certificates without re-signing.
    pub fn coordinate_and_acknowledge<P, R, I, S>(
        &mut self,
        owner: &mut CleanSystemAgentBootstrapOwner<P, R, I>,
        call: &AuthorityOperationCall,
        context: InvocationContext,
        issued_at: u64,
        signer: &mut S,
    ) -> Result<IssuedAuthorityOperation, SharedAgentHostError>
    where
        P: CleanSystemAgentBootstrapStore,
        R: CleanSystemAgentBootstrapStore,
        I: CleanManagementIssuerStore,
        S: AuthorityOperationEvidenceSigner + NativeAuthorityOperationCompletionSigner,
    {
        if owner.authority_target() != self.authority
            || call.authority != self.authority
            || NativeAuthorityOperationCompletionSigner::public_key(signer)
                != self.authority.binding.public_key
        {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        self.validate()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        if let Some((_, issued)) = self.retired_for_call(call, Some(&context), Some(issued_at))? {
            return Ok(issued);
        }
        let issued = self
            .coordinate(owner, call, context, issued_at, signer)
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        self.acknowledge_issued(owner, call.invocation, &issued, signer)?;
        Ok(issued)
    }

    /// Recover a synchronized terminal denial before considering policy dispatch.
    /// Only the coordinator's exact policy-denial result can create a new one.
    pub fn coordinate_and_decide<P, R, I, S>(
        &mut self,
        owner: &mut CleanSystemAgentBootstrapOwner<P, R, I>,
        call: &AuthorityOperationCall,
        context: InvocationContext,
        issued_at: u64,
        signer: &mut S,
    ) -> Result<NativeAuthorityOperationDecision, SharedAgentHostError>
    where
        P: CleanSystemAgentBootstrapStore,
        R: CleanSystemAgentBootstrapStore,
        I: CleanManagementIssuerStore,
        S: AuthorityOperationEvidenceSigner
            + NativeAuthorityOperationCompletionSigner
            + NativeAuthorityOperationRetirementSigner
            + NativeAuthorityOperationDenialSigner,
    {
        let diagnostics = std::env::var_os("VOS_TEST_BOOTSTRAP_DIAGNOSTICS").is_some();
        let diagnostic_request = diagnostics.then(|| call.commitment());
        let diagnostic_node = owner.pins().node();
        let refused = |category: &'static str, error: &SharedAgentHostError| {
            if let Some(request) = diagnostic_request {
                tracing::debug!(target: "vos::agent::local_lifecycle",
                    invocation = ?call.invocation.0, request = ?request.0,
                    node = ?diagnostic_node.0, stage = "controller_coordinate", category,
                    error_code = error.diagnostic_category(), "operation_refusal");
            }
        };
        let mismatch = |category: &'static str| {
            refused(category, &SharedAgentHostError::ScopeMismatch);
            true
        };
        let trace = |phase: &'static str, outcome: &'static str| {
            if diagnostics {
                tracing::debug!(phase, outcome, "native_operation_phase");
            }
        };
        trace("controller_checks", "start");
        if (owner.authority_target() != self.authority && mismatch("owner_authority"))
            || (call.authority != self.authority && mismatch("call_authority"))
            || (AuthorityOperationEvidenceSigner::public_key(signer)
                != self.authority.binding.public_key && mismatch("evidence_signer"))
            || (NativeAuthorityOperationCompletionSigner::public_key(signer)
                != self.authority.binding.public_key && mismatch("completion_signer"))
            || (NativeAuthorityOperationRetirementSigner::public_key(signer)
                != self.authority.binding.public_key && mismatch("retirement_signer"))
            || (NativeAuthorityOperationDenialSigner::public_key(signer)
                != self.authority.binding.public_key && mismatch("denial_signer"))
            || (!call.matches_invocation_context(&context) && mismatch("call_context"))
            || (issued_at < context.observed_slot && mismatch("issued_before_observation"))
            || (issued_at < call.requested_valid_from && mismatch("issued_before_validity"))
            || (issued_at > call.requested_expires_at && mismatch("issued_after_expiry"))
        {
            trace("controller_checks", "scope_mismatch");
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        self.validate()
            .map_err(|error| {
                let category = match &error {
                    NativeAuthorityOperationControllerError::WrongAuthority => "wrong_authority",
                    NativeAuthorityOperationControllerError::Completion(_) => "completion",
                    NativeAuthorityOperationControllerError::OpenIssuer(_) => "issuer_open",
                    NativeAuthorityOperationControllerError::OpenCoordinator(_) => "coordinator_open",
                    NativeAuthorityOperationControllerError::Coordinate(_) => "coordinate",
                };
                refused(category, &SharedAgentHostError::Unavailable);
                trace("controller_validate", "error");
                SharedAgentHostError::Unavailable
            })?;
        trace("controller_checks", "complete");
        if let Some((_, issued)) = self.retired_for_call(call, Some(&context), Some(issued_at))
            .map_err(|error| {
                refused("retained_lookup", &error);
                error
            })?
        {
            trace("retained_terminal", "issued");
            return Ok(NativeAuthorityOperationDecision::Issued(issued));
        }
        trace("denial_recovery", "start");
        for certificate in self
            .denials
            .load()
            .map_err(|_| SharedAgentHostError::Unavailable)?
        {
            let id = native_operation_denial_invocation(
                &self.authority.binding.public_key,
                &certificate,
            )
            .ok_or(SharedAgentHostError::ScopeMismatch)?;
            if id != call.invocation {
                continue;
            }
            let record = self.denial_source(call, &context)?;
            let mut issuer = DurableAuthorityOperationIssuer::open(
                BorrowedIssuer(&mut self.issuer),
                self.authority,
            )
            .map_err(|_| SharedAgentHostError::Unavailable)?;
            let retained =
                owner.restore_native_operation_denial(&record, &mut issuer, &certificate)?;
            self.denials
                .retain(&certificate)
                .map_err(|_| SharedAgentHostError::Unavailable)?;
            trace("denial_retained_release", "start");
            owner.release_native_operation_denial(&retained)?;
            trace("denial_retained_release", "complete");
            return Ok(NativeAuthorityOperationDecision::Denied {
                certificate,
                dispatch: record
                    .encode()
                    .map_err(|_| SharedAgentHostError::ScopeMismatch)?,
            });
        }
        // A failed certificate write follows durable removal of the unissued
        // coordinator pledge. Recover the native result without re-pledging an
        // already acknowledged invocation. A still-pledged call must go through
        // the coordinator so its journal transition is not bypassed.
        if self
            .journal
            .load(call.invocation)
            .map_err(|_| SharedAgentHostError::Unavailable)?
            .is_some()
            && self.denial_pledge_absent(call.invocation)?
        {
            let record = self.denial_source(call, &context)?;
            let mut issuer = DurableAuthorityOperationIssuer::open(
                BorrowedIssuer(&mut self.issuer),
                self.authority,
            )
            .map_err(|_| SharedAgentHostError::Unavailable)?;
            if issuer
                .recover_retained(call.invocation)
                .map_err(|_| SharedAgentHostError::Unavailable)?
                .is_none()
            {
                if let Some(proof) = owner.verify_native_operation_denial(&record, &mut issuer)? {
                    trace("denial_completion", "start");
                    owner.acknowledge_native_operation_denial(&proof)?;
                    let mut certificate = None;
                    owner.finish_native_operation_denial(&proof, signer, |bytes| {
                        self.denials
                            .retain(bytes)
                            .map_err(|_| SharedAgentHostError::Unavailable)?;
                        certificate = Some(bytes.to_vec());
                        Ok(())
                    })?;
                    trace("denial_completion", "complete");
                    return certificate
                        .map(|certificate| NativeAuthorityOperationDecision::Denied {
                            certificate,
                            dispatch: record.encode().expect("verified native denial source"),
                        })
                        .ok_or(SharedAgentHostError::Unavailable);
                }
            }
        }
        trace("coordinate", "start");
        match self.coordinate(owner, call, context.clone(), issued_at, signer) {
            Ok(issued) => {
                trace("coordinate", "complete");
                self.retire_issued(owner, call, issued, signer)
                    .map(NativeAuthorityOperationDecision::Issued)
                    .map_err(|error| {
                        refused("retire_issued", &error);
                        error
                    })
            },
            Err(NativeAuthorityOperationControllerError::Coordinate(
                AuthorityOperationCoordinatorError::Rejected(
                    crate::agent::authority_operation_coordinator::AuthorityOperationCoordinatorRejection::AuthorizationDenied,
                ),
            )) => {
                trace("coordinate", "denied");
                let record = self.denial_source(call, &context)?;
                let mut issuer = DurableAuthorityOperationIssuer::open(BorrowedIssuer(&mut self.issuer), self.authority)
                    .map_err(|_| SharedAgentHostError::Unavailable)?;
                let proof = owner.verify_native_operation_denial(&record, &mut issuer)?
                    .ok_or(SharedAgentHostError::Unavailable)?;
                owner.acknowledge_native_operation_denial(&proof)?;
                let mut certificate = None;
                owner.finish_native_operation_denial(&proof, signer, |bytes| {
                    self.denials.retain(bytes).map_err(|_| SharedAgentHostError::Unavailable)?;
                    certificate = Some(bytes.to_vec());
                    Ok(())
                })?;
                certificate.map(|certificate| NativeAuthorityOperationDecision::Denied { certificate,
                    dispatch: record.encode().expect("verified native denial source") })
                    .ok_or(SharedAgentHostError::Unavailable)
            }
            Err(error) => {
                let category = match &error {
                    NativeAuthorityOperationControllerError::WrongAuthority => "wrong_authority",
                    NativeAuthorityOperationControllerError::Completion(_) => "completion",
                    NativeAuthorityOperationControllerError::OpenIssuer(_) => "issuer_open",
                    NativeAuthorityOperationControllerError::OpenCoordinator(_) => "coordinator_open",
                    NativeAuthorityOperationControllerError::Coordinate(error) => match error {
                        AuthorityOperationCoordinatorError::Storage(_) => "coordinate_storage",
                        AuthorityOperationCoordinatorError::Issuer(_) => "coordinate_issuer",
                        AuthorityOperationCoordinatorError::Dispatch(error) => match error {
                            SharedAgentHostError::Unavailable => "dispatch_unavailable",
                            SharedAgentHostError::ScopeMismatch => "dispatch_scope_mismatch",
                            SharedAgentHostError::Conflict => "dispatch_conflict",
                            SharedAgentHostError::CapacityExhausted => "dispatch_capacity",
                            _ => "dispatch_other",
                        },
                        AuthorityOperationCoordinatorError::InvalidState => "coordinate_invalid_state",
                        AuthorityOperationCoordinatorError::Rejected(_) => "coordinate_rejected",
                    },
                };
                let host_error = match &error {
                    NativeAuthorityOperationControllerError::Coordinate(
                        AuthorityOperationCoordinatorError::Dispatch(error),
                    ) => *error,
                    _ => SharedAgentHostError::Unavailable,
                };
                trace(category, "error");
                refused(category, &host_error);
                Err(SharedAgentHostError::Unavailable)
            },
        }
    }

    fn denial_pledge_absent(
        &mut self,
        invocation: InvocationId,
    ) -> Result<bool, SharedAgentHostError> {
        let issuer =
            DurableAuthorityOperationIssuer::open(BorrowedIssuer(&mut self.issuer), self.authority)
                .map_err(|_| SharedAgentHostError::Unavailable)?;
        let coordinator = DurableAuthorityOperationCoordinator::open(
            BorrowedCoordinator(&mut self.coordinator),
            self.authority,
            ValidationOnly,
            issuer,
        )
        .map_err(|_| SharedAgentHostError::Unavailable)?;
        Ok(!coordinator
            .required_native_dispatches()
            .map_err(|_| SharedAgentHostError::Unavailable)?
            .iter()
            .any(|request| request.context.invocation == invocation))
    }

    fn denial_source(
        &mut self,
        call: &AuthorityOperationCall,
        context: &InvocationContext,
    ) -> Result<operation_dispatch::RetainedAuthorityOperationDispatch, SharedAgentHostError> {
        let bytes = self
            .journal
            .load(call.invocation)
            .map_err(|_| SharedAgentHostError::Unavailable)?
            .ok_or(SharedAgentHostError::Unavailable)?;
        let record = operation_dispatch::RetainedAuthorityOperationDispatch::decode(&bytes)
            .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
        if record.request().context != *context
            || record.request().request
                != call
                    .encode()
                    .map_err(|_| SharedAgentHostError::ScopeMismatch)?
        {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        Ok(record)
    }

    fn acknowledge_issued<P, R, I, S>(
        &mut self,
        owner: &mut CleanSystemAgentBootstrapOwner<P, R, I>,
        authorization: InvocationId,
        issued: &IssuedAuthorityOperation,
        signer: &mut S,
    ) -> Result<operation_dispatch::RetainedNativeOperationCompletion, SharedAgentHostError>
    where
        P: CleanSystemAgentBootstrapStore,
        R: CleanSystemAgentBootstrapStore,
        I: CleanManagementIssuerStore,
        S: NativeAuthorityOperationCompletionSigner,
    {
        let _timing = crate::agent::local_lifecycle::OperationTiming::start("controller_completion");
        let diagnostics = std::env::var_os("VOS_TEST_BOOTSTRAP_DIAGNOSTICS").is_some();
        let trace = |phase: &'static str, outcome: &'static str| {
            if diagnostics {
                tracing::debug!(phase, outcome, "native_operation_phase");
            }
        };
        trace("completion", "start");
        let ids = [
            authorization,
            issued.issuance_ack.acknowledgement_invocation,
        ];
        let mut records = Vec::new();
        for id in ids {
            let bytes = self
                .journal
                .load(id)
                .map_err(|_| SharedAgentHostError::Unavailable)?
                .ok_or(SharedAgentHostError::Unavailable)?;
            records.push(
                operation_dispatch::RetainedAuthorityOperationDispatch::decode(&bytes)
                    .map_err(|_| SharedAgentHostError::ScopeMismatch)?,
            );
        }
        let certificates = self
            .completions
            .load()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        let mut saved = None;
        for certificate in certificates {
            let certificate_ids = native_operation_completion_invocations(
                &self.authority.binding.public_key,
                &certificate,
            )
            .ok_or(SharedAgentHostError::ScopeMismatch)?;
            if certificate_ids == ids {
                if saved.replace(certificate).is_some() {
                    return Err(SharedAgentHostError::ScopeMismatch);
                }
            } else if certificate_ids.iter().any(|id| ids.contains(id)) {
                return Err(SharedAgentHostError::ScopeMismatch);
            }
        }
        let retained = if let Some(certificate) = saved {
            trace("completion_retained", "start");
            let retained = owner.restore_native_operation_completion(
                &records[0],
                &records[1],
                &certificate,
            )?;
            // A preceding write may have published before reporting failure.
            // Repeat exact retention to establish synchronization before Ack.
            self.completions
                .retain(&certificate)
                .map_err(|_| SharedAgentHostError::Unavailable)?;
            trace("completion_retained", "complete");
            retained
        } else {
            trace("completion_verify", "start");
            let verified =
                owner.verify_native_operation_completion(&records[0], &records[1], &issued)
                    .map_err(|error| {
                        trace("completion_verify", "error");
                        error
                    })?;
            trace("completion_verify", "complete");
            trace("completion_save", "start");
            owner.retain_native_operation_completion(&verified, signer, |certificate| {
                self.completions
                    .retain(certificate)
                    .map_err(|_| {
                        trace("completion_save", "error");
                        SharedAgentHostError::Unavailable
                    })
            })?
        };
        trace("completion", "complete");
        trace("actor_ack_pair", "start");
        owner.acknowledge_native_operation_completion(&retained)
            .map_err(|error| {
                trace("actor_ack_pair", "error");
                error
            })?;
        trace("actor_ack_pair", "complete");
        Ok(retained)
    }

    /// Production policy-result completion. Terminal retries recover the exact
    /// issuance and release from synchronized signed retirement without trying
    /// to re-acknowledge results whose admission has already been released.
    pub fn coordinate_and_retire<P, R, I, S>(
        &mut self,
        owner: &mut CleanSystemAgentBootstrapOwner<P, R, I>,
        call: &AuthorityOperationCall,
        context: InvocationContext,
        issued_at: u64,
        signer: &mut S,
    ) -> Result<IssuedAuthorityOperation, SharedAgentHostError>
    where
        P: CleanSystemAgentBootstrapStore,
        R: CleanSystemAgentBootstrapStore,
        I: CleanManagementIssuerStore,
        S: AuthorityOperationEvidenceSigner
            + NativeAuthorityOperationCompletionSigner
            + NativeAuthorityOperationRetirementSigner,
    {
        if owner.authority_target() != self.authority
            || call.authority != self.authority
            || NativeAuthorityOperationRetirementSigner::public_key(signer)
                != self.authority.binding.public_key
            || NativeAuthorityOperationCompletionSigner::public_key(signer)
                != self.authority.binding.public_key
        {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        self.validate()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        if let Some((_, issued)) = self.retired_for_call(call, Some(&context), Some(issued_at))? {
            return Ok(issued);
        }
        let issued = self
            .coordinate(owner, call, context, issued_at, signer)
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        self.retire_issued(owner, call, issued, signer)
    }

    fn retire_issued<P, R, I, S>(
        &mut self,
        owner: &mut CleanSystemAgentBootstrapOwner<P, R, I>,
        call: &AuthorityOperationCall,
        issued: IssuedAuthorityOperation,
        signer: &mut S,
    ) -> Result<IssuedAuthorityOperation, SharedAgentHostError>
    where
        P: CleanSystemAgentBootstrapStore,
        R: CleanSystemAgentBootstrapStore,
        I: CleanManagementIssuerStore,
        S: NativeAuthorityOperationCompletionSigner + NativeAuthorityOperationRetirementSigner,
    {
        let _timing = crate::agent::local_lifecycle::OperationTiming::start("controller_retirement");
        let diagnostics = std::env::var_os("VOS_TEST_BOOTSTRAP_DIAGNOSTICS").is_some();
        let trace = |phase: &'static str, outcome: &'static str| {
            if diagnostics {
                tracing::debug!(phase, outcome, "native_operation_phase");
            }
        };
        trace("retirement", "start");
        let ids = [
            call.invocation,
            issued.issuance_ack.acknowledgement_invocation,
        ];
        let mut load = |id| {
            let bytes = self
                .journal
                .load(id)
                .map_err(|_| SharedAgentHostError::Unavailable)?
                .ok_or(SharedAgentHostError::Unavailable)?;
            operation_dispatch::RetainedAuthorityOperationDispatch::decode(&bytes)
                .map_err(|_| SharedAgentHostError::ScopeMismatch)
        };
        let authorization = load(ids[0])?;
        let acknowledgement = load(ids[1])?;
        for certificate in self
            .retirements
            .load()
            .map_err(|_| SharedAgentHostError::Unavailable)?
        {
            let completion = native_operation_retirement_completion(
                &self.authority.binding.public_key,
                &certificate,
            )
            .ok_or(SharedAgentHostError::ScopeMismatch)?;
            let terminal_ids = native_operation_completion_invocations(
                &self.authority.binding.public_key,
                &completion,
            )
            .ok_or(SharedAgentHostError::ScopeMismatch)?;
            if terminal_ids == ids {
                trace("retirement_retained", "start");
                let retired = owner.restore_native_operation_retirement(
                    &authorization,
                    &acknowledgement,
                    &certificate,
                )?;
                self.retirements
                    .retain(&certificate)
                    .map_err(|_| SharedAgentHostError::Unavailable)?;
                trace("terminal_release", "start");
                owner.release_native_operation_retirement(&retired)
                    .map_err(|error| {
                        trace("terminal_release", "error");
                        error
                    })?;
                trace("terminal_release", "complete");
                return Ok(issued);
            }
            if terminal_ids.iter().any(|id| ids.contains(id)) {
                return Err(SharedAgentHostError::ScopeMismatch);
            }
        }
        let retained = self.acknowledge_issued(owner, call.invocation, &issued, signer)?;
        trace("retirement_finish", "start");
        owner.finish_native_operation_retirement(&retained, signer, |bytes| {
            trace("retirement_save", "start");
            self.retirements
                .retain(bytes)
                .map_err(|_| {
                    trace("retirement_save", "error");
                    SharedAgentHostError::Unavailable
                })?;
            trace("retirement_save", "complete");
            Ok(())
        }).map_err(|error| {
            trace("retirement_finish", "error");
            error
        })?;
        trace("retirement_finish", "complete");
        Ok(issued)
    }

    pub fn into_parts_with_denials(self) -> (C, B, J, K, T, D) {
        (
            self.coordinator,
            self.issuer,
            self.journal,
            self.completions,
            self.retirements,
            self.denials,
        )
    }
}

struct ValidationOnly;
impl crate::agent::authority_operation_coordinator::AuthorityOperationActorDispatcher
    for ValidationOnly
{
    type Error = SharedAgentHostError;
    fn dispatch(
        &mut self,
        _: &crate::agent::authority_operation_coordinator::AuthorityOperationActorDispatch,
    ) -> Result<
        crate::agent::authority_operation_coordinator::AuthorityOperationActorResult,
        Self::Error,
    > {
        Err(SharedAgentHostError::Unavailable)
    }
}

impl<P, R, I, C, B, J, K, T, D, S>
    crate::agent::local_lifecycle::NativeAuthorityOperationAccess<P, R, I>
    for (NativeAuthorityOperationController<C, B, J, K, T, D>, S)
where
    P: CleanSystemAgentBootstrapStore,
    R: CleanSystemAgentBootstrapStore,
    I: CleanManagementIssuerStore,
    C: AuthorityOperationCoordinatorStore + Send,
    B: AuthorityOperationIssuerStore + Send,
    J: NativeAuthorityOperationJournalStore + Send,
    K: NativeAuthorityOperationCompletionStore + Send,
    T: NativeAuthorityOperationRetirementStore + Send,
    D: NativeAuthorityOperationDenialStore + Send,
    S: AuthorityOperationEvidenceSigner
        + NativeAuthorityOperationCompletionSigner
        + NativeAuthorityOperationRetirementSigner
        + NativeAuthorityOperationDenialSigner
        + Send,
{
    fn retains_call(
        &mut self,
        call: &AuthorityOperationCall,
        context: Option<&InvocationContext>,
    ) -> Result<bool, SharedAgentHostError> {
        self.0.retains_call(call, context)
    }

    fn prepare(
        &mut self,
        owner: &mut CleanSystemAgentBootstrapOwner<P, R, I>,
        call: &AuthorityOperationCall,
    ) -> Result<InvocationContext, SharedAgentHostError> {
        self.0.prepare_call(owner, call)
    }

    fn coordinate(
        &mut self,
        owner: &mut CleanSystemAgentBootstrapOwner<P, R, I>,
        call: &AuthorityOperationCall,
        context: InvocationContext,
        issued_at: u64,
    ) -> Result<NativeAuthorityOperationDecision, SharedAgentHostError> {
        self.0
            .coordinate_and_decide(owner, call, context, issued_at, &mut self.1)
    }
}

struct BorrowedCoordinator<'a, C>(&'a mut C);
impl<C: AuthorityOperationCoordinatorStore> AuthorityOperationCoordinatorStore
    for BorrowedCoordinator<'_, C>
{
    type Error = C::Error;
    fn load(&mut self) -> Result<Option<Vec<u8>>, Self::Error> {
        self.0.load()
    }
    fn commit(&mut self, bytes: &[u8]) -> Result<(), Self::Error> {
        self.0.commit(bytes)
    }
}

pub(super) struct BorrowedIssuer<'a, B>(pub(super) &'a mut B);
impl<B: AuthorityOperationIssuerStore> AuthorityOperationIssuerStore for BorrowedIssuer<'_, B> {
    type Error = B::Error;
    fn load(&mut self) -> Result<Option<Vec<u8>>, Self::Error> {
        self.0.load()
    }
    fn commit(&mut self, bytes: &[u8]) -> Result<(), Self::Error> {
        self.0.commit(bytes)
    }
}
