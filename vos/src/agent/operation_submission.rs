//! Exact retry inputs for native operation authorization, not policy approval.

use super::super::authority_operation_coordinator::{
    AuthorityOperationActorDispatch, AuthorityOperationActorMethod,
};
use super::super::sdk::InvocationContext;
use super::super::sdk::authority_operation::AuthorityOperationCall;
use super::super::sdk::wire::{CanonicalWire, MAX_INVOCATION_CONTEXT_WIRE_BYTES};
use vos_protocol::wire::{DecodeError, Decoder, Encoder};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorityOperationSubmission {
    call: AuthorityOperationCall,
    context: InvocationContext,
    issued_at: u64,
}

impl AuthorityOperationSubmission {
    pub fn new(
        call: AuthorityOperationCall,
        context: InvocationContext,
        issued_at: u64,
    ) -> Result<Self, DecodeError> {
        let value = Self {
            call,
            context,
            issued_at,
        };
        if !value.validate_wire() {
            return Err(DecodeError::NonCanonical);
        }
        Ok(value)
    }

    pub fn call(&self) -> &AuthorityOperationCall {
        &self.call
    }
    pub fn context(&self) -> &InvocationContext {
        &self.context
    }
    pub fn issued_at(&self) -> u64 {
        self.issued_at
    }

    pub fn into_parts(self) -> (AuthorityOperationCall, InvocationContext, u64) {
        (self.call, self.context, self.issued_at)
    }
}

impl CanonicalWire for AuthorityOperationSubmission {
    const MAGIC: [u8; 4] = *b"AOQ1";
    const MAX_ENCODED_BYTES: usize =
        32 + AuthorityOperationCall::MAX_ENCODED_BYTES + MAX_INVOCATION_CONTEXT_WIRE_BYTES;

    fn validate_wire(&self) -> bool {
        let Ok(request) = self.call.encode() else {
            return false;
        };
        self.context.encode().is_ok()
            && self.issued_at >= self.context.observed_slot
            && self.issued_at >= self.call.requested_valid_from
            && self.issued_at <= self.call.requested_expires_at
            && AuthorityOperationActorDispatch {
                target: self.call.authority,
                method: AuthorityOperationActorMethod::AuthorizeOperation,
                context: self.context.clone(),
                request,
            }
            .has_valid_request()
    }

    fn encode_body(&self, encoder: &mut Encoder<'_>) {
        encoder.bytes(&self.call.encode().expect("validated operation call"));
        encoder.bytes(&self.context.encode().expect("validated operation context"));
        encoder.u64(self.issued_at);
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let call = AuthorityOperationCall::decode(
            &decoder.bytes_bounded(AuthorityOperationCall::MAX_ENCODED_BYTES)?,
        )
        .map_err(|_| DecodeError::NonCanonical)?;
        let context =
            InvocationContext::decode(&decoder.bytes_bounded(MAX_INVOCATION_CONTEXT_WIRE_BYTES)?)
                .map_err(|_| DecodeError::NonCanonical)?;
        Self::new(call, context, decoder.u64()?)
    }
}
