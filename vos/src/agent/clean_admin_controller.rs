//! Exclusive ownership of admin dispatch and both terminal evidence phases.
use super::*;
use crate::agent::sdk::authority::{AuthorityAdminCall, AuthorityAdminResult};

/// Keep this controller alive for the system owner's lifetime. Restore its
/// complete discovery set into startup admission before accepting new work.
/// Every attempt rereads exact durable bytes; no completion cache is trusted.
pub struct NativeAuthorityAdminController<J, T> {
    authority: AuthorityActorTarget,
    journal: J,
    terminals: T,
}

impl<J: NativeAuthorityAdminJournalStore, T: NativeAuthorityAdminTerminalStore>
    NativeAuthorityAdminController<J, T>
{
    pub fn authority(&self) -> AuthorityActorTarget {
        self.authority
    }

    /// Resume only previously retained signed calls before ordinary routes
    /// are published. Missing/corrupt discovery members are never skipped.
    pub fn recover<P, R, I, S>(
        &mut self,
        owner: &mut CleanSystemAgentBootstrapOwner<P, R, I>,
        invocations: &[InvocationId],
        signer: &mut S,
    ) -> Result<(), SharedAgentHostError>
    where
        P: CleanSystemAgentBootstrapStore,
        R: CleanSystemAgentBootstrapStore,
        I: CleanManagementIssuerStore,
        S: NativeAuthorityAdminTerminalSigner,
    {
        let maximum = 2 * crate::agent::authority_operation_coordinator::MAX_AUTHORITY_OPERATION_COORDINATOR_RECORDS;
        if owner.authority_target() != self.authority
            || signer.public_key() != self.authority.binding.public_key
            || invocations.len() > maximum
            || invocations.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        for id in invocations {
            let bytes = self
                .journal
                .load(*id)
                .map_err(|_| SharedAgentHostError::Unavailable)?
                .ok_or(SharedAgentHostError::Unavailable)?;
            let record = admin_dispatch::RetainedAuthorityAdminDispatch::decode(&bytes)
                .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
            if record.call.invocation != *id {
                return Err(SharedAgentHostError::ScopeMismatch);
            }
            self.coordinate_and_retire(owner, &record.call, signer)?;
        }
        Ok(())
    }

    pub fn new(authority: AuthorityActorTarget, journal: J, terminals: T) -> Self {
        Self {
            authority,
            journal,
            terminals,
        }
    }

    pub fn startup_admission<'a>(
        &'a mut self,
        existing: NativeAuthorityOperationStartupAdmission<'a>,
        invocations: &[InvocationId],
    ) -> Result<NativeAuthorityOperationStartupAdmission<'a>, SharedAgentHostError> {
        if self.authority != existing.authority {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        existing.include_admin_with_terminals(&mut self.journal, &mut self.terminals, invocations)
    }

    /// None is a durably retired denial. Errors are never policy decisions.
    pub fn coordinate_and_retire<P, R, I, S>(
        &mut self,
        owner: &mut CleanSystemAgentBootstrapOwner<P, R, I>,
        call: &AuthorityAdminCall,
        signer: &mut S,
    ) -> Result<Option<AuthorityAdminResult>, SharedAgentHostError>
    where
        P: CleanSystemAgentBootstrapStore,
        R: CleanSystemAgentBootstrapStore,
        I: CleanManagementIssuerStore,
        S: NativeAuthorityAdminTerminalSigner,
    {
        if call.authority != self.authority
            || owner.authority_target() != self.authority
            || call.verify_with(&RawCredentialVerifier).is_err()
        {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        // A retired request no longer has pending admission. Load its original
        // dispatch without trying to reserve it again or rebase its clock.
        let record = if let Some(bytes) = self
            .journal
            .load(call.invocation)
            .map_err(|_| SharedAgentHostError::Unavailable)?
        {
            let record = admin_dispatch::RetainedAuthorityAdminDispatch::decode(&bytes)
                .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
            if record.call != *call {
                return Err(SharedAgentHostError::ScopeMismatch);
            }
            self.journal
                .retain(call.invocation, &bytes)
                .map_err(|_| SharedAgentHostError::Unavailable)?;
            record
        } else {
            owner.retain_authority_admin(call, &mut self.journal)?
        };
        owner.finish_authority_admin(&record, &mut self.terminals, signer)
    }
}
