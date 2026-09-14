//! Credential-local admin attempts, bound to exact NAS1 before dispatch.
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
    fn image(&self, nonce: Hash, phase: u8, first: Hash, second: Hash) -> Vec<u8> {
        let mut bytes = b"ACR2".to_vec();
        for value in [self.0.space.0, self.0.credential.0, nonce.0] {
            bytes.extend_from_slice(&value);
        }
        bytes.push(phase);
        bytes.extend_from_slice(&first.0);
        bytes.extend_from_slice(&second.0);
        bytes
    }
    fn load(&mut self) -> Result<Option<Vec<u8>>, CleanFileStoreError> {
        let bytes = self.0.store.load(165)?;
        if let Some(bytes) = &bytes {
            if bytes.len() != 165
                || &bytes[..4] != b"ACR2"
                || bytes[4..36] != self.0.space.0
                || bytes[36..68] != self.0.credential.0
                || bytes[68..100] == [0; 32]
                || bytes[101..133] == [0; 32]
                || !match bytes[100] {
                    0 => bytes[133..165] == [0; 32],
                    1..=3 => bytes[133..165] != [0; 32],
                    _ => false,
                }
            {
                return Err(CleanFileStoreError::Corrupt);
            }
            self.0.store.commit(bytes)?;
        }
        Ok(bytes)
    }
    fn status(phase: u8) -> CredentialReservationStatus {
        if phase == 3 {
            CredentialReservationStatus::Pending
        } else {
            CredentialReservationStatus::from_tag(phase)
        }
    }
    pub(crate) fn current(
        &mut self,
    ) -> Result<Option<(Hash, CredentialReservationStatus)>, CleanFileStoreError> {
        Ok(self.load()?.map(|bytes| {
            (
                Hash(bytes[68..100].try_into().expect("validated image")),
                Self::status(bytes[100]),
            )
        }))
    }
    fn validate_draft(&self, draft: &AuthorityAdminCall) -> Result<(), CleanFileStoreError> {
        if draft.observed_slot != 0
            || draft.authority.space != self.0.space
            || draft.credential != self.0.credential
            || draft
                .verify_with(&super::super::local_create::CredentialVerifier)
                .is_err()
        {
            return Err(CleanFileStoreError::Corrupt);
        }
        Ok(())
    }
    /// The draft must already be durable under this unique local attempt ID.
    pub(crate) fn reserve(
        &mut self,
        nonce: Hash,
        draft: &AuthorityAdminCall,
    ) -> Result<CredentialReservationStatus, CleanFileStoreError> {
        self.validate_draft(draft)?;
        if nonce == Hash::ZERO {
            return Err(CleanFileStoreError::Corrupt);
        }
        if let Some(current) = self.load()? {
            if current[68..100] == nonce.0 {
                if matches!(current[100], 0 | 3) && current[101..133] != draft.commitment().0 {
                    return Err(CleanFileStoreError::RequestConflict);
                }
                return Ok(Self::status(current[100]));
            }
            if matches!(current[100], 0 | 3) {
                return Err(CleanFileStoreError::RequestConflict);
            }
        }
        self.0
            .store
            .commit(&self.image(nonce, 0, draft.commitment(), Hash::ZERO))?;
        Ok(CredentialReservationStatus::Pending)
    }
    /// Bind after NAS1 retention, before dispatch. Old completion cannot finish
    /// a new attempt merely because both attempts use the same zero-slot draft.
    pub(crate) fn bind_submission(
        &mut self,
        nonce: Hash,
        draft: &AuthorityAdminCall,
        submission: &NativeAuthorityAdminSubmission,
    ) -> Result<(), CleanFileStoreError> {
        self.validate_draft(draft)?;
        let mut expected = submission
            .preparation()
            .call_to_sign(draft)
            .map_err(|_| CleanFileStoreError::Corrupt)?;
        expected.signature = submission.call().signature;
        if &expected != submission.call() {
            return Err(CleanFileStoreError::RequestConflict);
        }
        let request = submission
            .encode()
            .map_err(|_| CleanFileStoreError::Corrupt)?;
        let commitment = Self::request_commitment(&request);
        let current = self.load()?.ok_or(CleanFileStoreError::RequestConflict)?;
        if current[68..100] != nonce.0 {
            return Err(CleanFileStoreError::RequestConflict);
        }
        if matches!(current[100], 1 | 2) {
            return if current[101..133] == commitment.0 {
                Ok(())
            } else {
                Err(CleanFileStoreError::RequestConflict)
            };
        }
        if current[101..133] != draft.commitment().0
            || (current[100] == 3 && current[133..165] != commitment.0)
        {
            return Err(CleanFileStoreError::RequestConflict);
        }
        self.0
            .store
            .commit(&self.image(nonce, 3, draft.commitment(), commitment))
    }
    fn request_commitment(bytes: &[u8]) -> Hash {
        Hash::digest(b"vos/admin-client/retained-request/v1", &[bytes])
    }
    pub(crate) fn complete(
        &mut self,
        nonce: Hash,
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
        if submission.call().authority.space != self.0.space
            || submission.call().credential != self.0.credential
        {
            return Err(CleanFileStoreError::Corrupt);
        }
        let completion = submission
            .verify_completion(&response)
            .map_err(|_| CleanFileStoreError::Corrupt)?;
        let current = self.load()?.ok_or(CleanFileStoreError::RequestConflict)?;
        let commitment = Self::request_commitment(&request);
        if current[68..100] != nonce.0
            || current[100] == 0
            || (current[100] == 3 && current[133..165] != commitment.0)
        {
            return Err(CleanFileStoreError::RequestConflict);
        }
        let phase = if completion.result().is_none() { 2 } else { 1 };
        let finished = self.image(
            nonce,
            phase,
            commitment,
            Hash::digest(b"vos/admin-client/retained-completion/v1", &[&response]),
        );
        if current[100] != 3 && current != finished {
            return Err(CleanFileStoreError::RequestConflict);
        }
        self.0.store.commit(&finished)?;
        Ok(Self::status(phase))
    }
}
