//! Signed host-clock selection for admin calls. Preparation is not permission:
//! the Authority still checks the caller, sequence and generation at execution.
use super::*;
use crate::agent::sdk::authority::AuthorityAdminCall;

pub trait NativeAuthorityAdminPreparationSigner {
    type Error;
    fn public_key(&self) -> [u8; 32];
    fn sign_admin_preparation(&mut self, message: &[u8]) -> Result<[u8; 64], Self::Error>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeAuthorityAdminPreparation {
    intent: Hash,
    observed_slot: u64,
    incarnation: Hash,
    signature: [u8; 64],
}

fn intent(call: &AuthorityAdminCall) -> Hash {
    let mut draft = call.clone();
    draft.observed_slot = 0;
    draft.invocation_payload_commitment()
}

impl NativeAuthorityAdminPreparation {
    fn signing_bytes(&self) -> Vec<u8> {
        let mut bytes = b"vos/agent/native-admin-preparation/v1".to_vec();
        bytes.extend_from_slice(crate::agent_sdk::RUNTIME_ABI_ID.as_bytes());
        bytes.extend_from_slice(&self.intent.0);
        bytes.extend_from_slice(&self.observed_slot.to_le_bytes());
        bytes.extend_from_slice(&self.incarnation.0);
        bytes
    }

    pub const fn observed_slot(&self) -> u64 {
        self.observed_slot
    }
    pub(crate) const fn incarnation(&self) -> Hash {
        self.incarnation
    }

    pub fn matches_call(&self, call: &AuthorityAdminCall) -> bool {
        self.verify_intent(call)
            && call.observed_slot == self.observed_slot
            && call.verify_with(&RawCredentialVerifier).is_ok()
    }

    fn verify_intent(&self, call: &AuthorityAdminCall) -> bool {
        self.validate_wire()
            && self.intent == intent(call)
            && crate::agent::authority::verify_raw_ed25519(
                &call.authority.binding.public_key,
                &self.signing_bytes(),
                &self.signature,
            )
    }

    /// Verify the response against the client's signed zero-slot draft and
    /// return the exact call to sign. Its zero signature prevents execution
    /// until the client signs and durably retains this call and preparation.
    pub fn call_to_sign(
        &self,
        draft: &AuthorityAdminCall,
    ) -> Result<AuthorityAdminCall, SharedAgentHostError> {
        if draft.observed_slot != 0
            || draft.verify_with(&RawCredentialVerifier).is_err()
            || !self.verify_intent(draft)
        {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        let mut call = draft.clone();
        call.observed_slot = self.observed_slot;
        call.invocation = call.expected_invocation();
        call.signature = [0; 64];
        Ok(call)
    }
}

impl CanonicalWire for NativeAuthorityAdminPreparation {
    const MAGIC: [u8; 4] = *b"NAP1";
    const MAX_ENCODED_BYTES: usize = 256;
    fn validate_wire(&self) -> bool {
        self.intent != Hash::ZERO && self.incarnation != Hash::ZERO && self.signature != [0; 64]
    }
    fn encode_body(&self, encoder: &mut Encoder<'_>) {
        encoder.fixed(&self.intent.0);
        encoder.u64(self.observed_slot);
        encoder.fixed(&self.incarnation.0);
        encoder.bytes(&self.signature);
    }
    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            intent: Hash(decoder.fixed()?),
            observed_slot: decoder.u64()?,
            incarnation: Hash(decoder.fixed()?),
            signature: decoder
                .bytes_bounded(64)?
                .try_into()
                .map_err(|_| DecodeError::NonCanonical)?,
        })
    }
}

impl<P, R, I> CleanSystemAgentBootstrapOwner<P, R, I>
where
    P: CleanSystemAgentBootstrapStore,
    R: CleanSystemAgentBootstrapStore,
    I: CleanManagementIssuerStore,
{
    pub fn prepare_authority_admin<S: NativeAuthorityAdminPreparationSigner>(
        &self,
        draft: &AuthorityAdminCall,
        signer: &mut S,
    ) -> Result<NativeAuthorityAdminPreparation, SharedAgentHostError> {
        if draft.observed_slot != 0
            || draft.authority != self.authority_target()
            || draft.authenticated_node != self.pins.node
            || draft.verify_with(&RawCredentialVerifier).is_err()
            || signer.public_key() != self.authority_target().binding.public_key
            || self.record.pending_projection.is_some()
            || self.management_admission_held()?
        {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        let material = self.supervisor_invocation_material(
            self.pins.agent,
            draft.authority.binding.issuer.actor,
        )?;
        if material.actor.entry.deployment != draft.authority.binding.issuer.deployment
            || material.actor.entry.program != draft.authority.binding.issuer.program
            || material.producer != draft.authority.binding.issuer.producer
        {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        let mut prepared = NativeAuthorityAdminPreparation {
            intent: intent(draft),
            observed_slot: material.observed_slot,
            incarnation: material.actor.incarnation,
            signature: [0; 64],
        };
        prepared.signature = signer
            .sign_admin_preparation(&prepared.signing_bytes())
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        if !prepared.verify_intent(draft) {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        Ok(prepared)
    }
}
