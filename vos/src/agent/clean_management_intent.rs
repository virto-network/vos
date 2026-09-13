//! Durable exact input for native management coordination, before policy runs.
//! A signed credential call is not policy approval or genesis finality.

use super::clean_authority_issuer::CleanManagementIssuerStore;
use crate::agent_sdk::ManagementRequest;
use crate::agent_sdk::authority::{
    AuthorityActorTarget, AuthorityCredentialCall, AuthorityCredentialVerifier, ManagedAgentTarget,
};
use crate::agent_sdk::wire::CanonicalWire as _;
use crate::service::wire::{DecodeError, Decoder, Encoder, ServiceWire};

pub(crate) const MAX_INTENT_BYTES: usize = 64
    + crate::agent_sdk::wire::MAX_MANAGEMENT_REQUEST_WIRE_BYTES
    + crate::agent_sdk::wire::MAX_AUTHORITY_CREDENTIAL_CALL_WIRE_BYTES;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CleanManagementIntent {
    request: ManagementRequest,
    call: AuthorityCredentialCall,
}

impl CleanManagementIntent {
    pub(crate) fn new<V: AuthorityCredentialVerifier>(
        authority: AuthorityActorTarget,
        managed: ManagedAgentTarget,
        request: ManagementRequest,
        call: AuthorityCredentialCall,
        verifier: &V,
    ) -> Result<Self, DecodeError> {
        let intent = Self { request, call };
        intent.verify(authority, managed, verifier)?;
        Ok(intent)
    }

    /// Reverify on recovery against independently selected routes. Persisting
    /// the caller's own target does not make that target authoritative.
    pub(crate) fn verify<V: AuthorityCredentialVerifier>(
        &self,
        authority: AuthorityActorTarget,
        managed: ManagedAgentTarget,
        verifier: &V,
    ) -> Result<(), DecodeError> {
        self.validate()?;
        if self.call.authority != authority
            || self.call.managed != managed
            || self.call.verify_with(verifier).is_err()
        {
            return Err(DecodeError::NonCanonical);
        }
        Ok(())
    }

    pub(crate) fn request(&self) -> &ManagementRequest {
        &self.request
    }
    pub(crate) fn call(&self) -> &AuthorityCredentialCall {
        &self.call
    }

    fn validate(&self) -> Result<(), DecodeError> {
        if !self.request.is_valid()
            || self.call.encode().is_err()
            || !self.call.plan.matches_request(&self.request)
            || matches!(
                self.request,
                ManagementRequest::InspectActors { .. }
                    | ManagementRequest::InspectResources
                    | ManagementRequest::PrivateControl { .. }
            )
        {
            return Err(DecodeError::NonCanonical);
        }
        if let ManagementRequest::Create(descriptor) = &self.request {
            let target = self.call.managed;
            if descriptor.authority != self.call.authority.binding
                || descriptor.identity.space != target.space
                || descriptor.identity.agent != target.agent
                || descriptor.identity.owner != target.owner
                || descriptor.identity.profile != target.profile
                || descriptor.identity.runtime_deployment != target.runtime_deployment
                || descriptor.identity.transition_producer != target.transition_producer
            {
                return Err(DecodeError::NonCanonical);
            }
        }
        Ok(())
    }
}

impl ServiceWire for CleanManagementIntent {
    const MAGIC: [u8; 4] = *b"CMI1";
    fn encode_body(&self, output: &mut Vec<u8>) {
        let mut encoder = Encoder(output);
        encoder.bytes(&self.request.encode().unwrap_or_default());
        encoder.bytes(&self.call.encode().unwrap_or_default());
    }
    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let request_bytes = decoder.bytes_ref()?;
        if request_bytes.len() > crate::agent_sdk::wire::MAX_MANAGEMENT_REQUEST_WIRE_BYTES {
            return Err(DecodeError::LimitExceeded);
        }
        let call_bytes = decoder.bytes_ref()?;
        if call_bytes.len() > crate::agent_sdk::wire::MAX_AUTHORITY_CREDENTIAL_CALL_WIRE_BYTES {
            return Err(DecodeError::LimitExceeded);
        }
        let intent = Self {
            request: ManagementRequest::decode(request_bytes)
                .map_err(|_| DecodeError::NonCanonical)?,
            call: AuthorityCredentialCall::decode(call_bytes)
                .map_err(|_| DecodeError::NonCanonical)?,
        };
        intent.validate()?;
        Ok(intent)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum IntentSlotError<E> {
    Storage(E),
    Invalid,
    Conflict,
    Poisoned,
}

/// Dedicated single-writer intent store. It must not share its physical image
/// with the issuer even though both use the same atomic whole-image contract.
pub(crate) struct CleanManagementIntentSlot<B> {
    store: B,
    intent: Option<CleanManagementIntent>,
    poisoned: bool,
}

impl<B: CleanManagementIssuerStore> CleanManagementIntentSlot<B> {
    pub(crate) fn open(mut store: B) -> Result<Self, IntentSlotError<B::Error>> {
        let intent = store
            .load()
            .map_err(IntentSlotError::Storage)?
            .map(|bytes| {
                if bytes.len() > MAX_INTENT_BYTES {
                    return Err(IntentSlotError::Invalid);
                }
                CleanManagementIntent::decode(&bytes).map_err(|_| IntentSlotError::Invalid)
            })
            .transpose()?;
        Ok(Self {
            store,
            intent,
            poisoned: false,
        })
    }

    pub(crate) fn intent(&self) -> Option<&CleanManagementIntent> {
        self.intent.as_ref()
    }

    /// Commit before invoking authority policy or allocating any receipt.
    /// An ambiguous write poisons this instance; only a real reopen may retry.
    pub(crate) fn pledge(
        &mut self,
        intent: CleanManagementIntent,
    ) -> Result<bool, IntentSlotError<B::Error>> {
        if self.poisoned {
            return Err(IntentSlotError::Poisoned);
        }
        intent.validate().map_err(|_| IntentSlotError::Invalid)?;
        if let Some(existing) = &self.intent {
            return if *existing == intent {
                Ok(false)
            } else {
                Err(IntentSlotError::Conflict)
            };
        }
        let bytes = intent.encode();
        if bytes.len() > MAX_INTENT_BYTES {
            return Err(IntentSlotError::Invalid);
        }
        if let Err(error) = self.store.commit(&bytes) {
            self.poisoned = true;
            return Err(IntentSlotError::Storage(error));
        }
        self.intent = Some(intent);
        Ok(true)
    }
}
