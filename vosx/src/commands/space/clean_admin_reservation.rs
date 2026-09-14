//! Separate admin sequence ownership; only bound NAT2 can finish a claim.
use super::*;
use vos::agent::clean_bootstrap::NativeAuthorityAdminSubmission;
use vos::agent::sdk::{
    CredentialId, Hash, SpaceId, authority::AuthorityAdminCall, wire::CanonicalWire as _,
};

pub(crate) struct CleanAdminCredentialReservation(CleanCredentialReservation);

impl CleanAdminCredentialReservation {
    pub(crate) fn open_or_create(
        parent: &Path,
        space: SpaceId,
        credential: CredentialId,
    ) -> Result<Self, CleanFileStoreError> {
        CleanCredentialReservation::open_role(
            parent,
            space,
            credential,
            StoreRole::AdminCredentialReservation,
        )
        .map(Self)
    }
    pub(crate) fn current(
        &mut self,
    ) -> Result<Option<(Hash, CredentialReservationStatus)>, CleanFileStoreError> {
        self.0.current()
    }

    /// Hold this lease across discovery and signing. Reserve the exact signed
    /// zero-slot draft before sending preparation or submission requests.
    pub(crate) fn reserve(
        &mut self,
        draft: &AuthorityAdminCall,
    ) -> Result<CredentialReservationStatus, CleanFileStoreError> {
        if draft.observed_slot != 0
            || draft.authority.space != self.0.space
            || draft.credential != self.0.credential
            || draft
                .verify_with(&super::super::local_create::CredentialVerifier)
                .is_err()
        {
            return Err(CleanFileStoreError::Corrupt);
        }
        self.0.reserve(Hash(draft.invocation.0))
    }

    pub(crate) fn complete(
        &mut self,
        delivery: &mut CleanOperationClientFile,
    ) -> Result<CredentialReservationStatus, CleanFileStoreError> {
        let request = delivery
            .load_request()?
            .ok_or(CleanFileStoreError::RequestConflict)?;
        let response = delivery
            .load_response()?
            .ok_or(CleanFileStoreError::RequestConflict)?;
        let submission = NativeAuthorityAdminSubmission::decode(&request)
            .map_err(|_| CleanFileStoreError::Corrupt)?;
        let call = submission.call();
        if call.authority.space != self.0.space || call.credential != self.0.credential {
            return Err(CleanFileStoreError::Corrupt);
        }
        let completion = submission
            .verify_completion(&response)
            .map_err(|_| CleanFileStoreError::Corrupt)?;
        let mut draft = call.clone();
        draft.observed_slot = 0;
        let nonce = Hash(draft.expected_invocation().0);
        let current = self.0.load()?.ok_or(CleanFileStoreError::RequestConflict)?;
        if current[68..100] != nonce.0 {
            return Err(CleanFileStoreError::RequestConflict);
        }
        let mut finished = self.0.image(
            nonce,
            Some((
                Hash::digest(b"vos/admin-client/retained-request/v1", &[&request]),
                Hash::digest(b"vos/admin-client/retained-completion/v1", &[&response]),
            )),
        );
        if completion.result().is_none() {
            finished[100] = 2;
        }
        if current[100] != 0 && current != finished {
            return Err(CleanFileStoreError::RequestConflict);
        }
        self.0.store.commit(&finished)?;
        Ok(CredentialReservationStatus::from_tag(finished[100]))
    }
}
