//! Long-lived ownership of operation stores; parsed state is reopened for each
//! call so an ambiguous write cannot leave a stale in-memory issuer in use.

use super::*;
use crate::agent::authority_operation_coordinator::{
    AuthorityOperationCoordinatorError, AuthorityOperationCoordinatorStore,
    DurableAuthorityOperationCoordinator,
};
use crate::agent::authority_operation_issuer::{
    AuthorityOperationEvidenceSigner, AuthorityOperationIssuerError, AuthorityOperationIssuerStore,
    DurableAuthorityOperationIssuer, IssuedAuthorityOperation,
};
use crate::agent::sdk::InvocationContext;
use crate::agent::sdk::authority_operation::AuthorityOperationCall;

/// Retains all three exclusive store handles across calls and failures.
/// Construction does not assert recovery or release admission: the caller must
/// restore startup admission before dispatch and keep the controller alive for
/// the lifetime of the corresponding system owner.
pub struct NativeAuthorityOperationController<C, B, J> {
    authority: AuthorityActorTarget,
    coordinator: C,
    issuer: B,
    journal: J,
}

#[derive(Debug)]
pub enum NativeAuthorityOperationControllerError<C, B, S> {
    WrongAuthority,
    OpenIssuer(AuthorityOperationIssuerError<B>),
    OpenCoordinator(AuthorityOperationCoordinatorError<C, B>),
    Coordinate(AuthorityOperationCoordinatorError<C, B, SharedAgentHostError, S>),
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
        }
    }

    pub fn startup_admission(
        &mut self,
        invocations: &[InvocationId],
    ) -> Result<NativeAuthorityOperationStartupAdmission<'_>, SharedAgentHostError> {
        NativeAuthorityOperationStartupAdmission::load(
            &mut self.journal,
            self.authority,
            invocations,
        )
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
        if !self.authority.is_valid()
            || self.authority != owner.authority_target()
            || call.authority != self.authority
        {
            return Err(NativeAuthorityOperationControllerError::WrongAuthority);
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

    pub fn into_parts(self) -> (C, B, J) {
        (self.coordinator, self.issuer, self.journal)
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

struct BorrowedIssuer<'a, B>(&'a mut B);
impl<B: AuthorityOperationIssuerStore> AuthorityOperationIssuerStore for BorrowedIssuer<'_, B> {
    type Error = B::Error;
    fn load(&mut self) -> Result<Option<Vec<u8>>, Self::Error> {
        self.0.load()
    }
    fn commit(&mut self, bytes: &[u8]) -> Result<(), Self::Error> {
        self.0.commit(bytes)
    }
}
