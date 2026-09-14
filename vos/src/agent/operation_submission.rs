//! Exact retry inputs for native operation authorization, not policy approval.

use super::super::authority_operation_coordinator::{
    AuthorityOperationActorDispatch, AuthorityOperationActorMethod,
};
use super::super::authority_operation_issuer::IssuedAuthorityOperation;
use super::super::clean_bootstrap::{
    NativeAuthorityOperationDecision, native_operation_denial_matches_request,
};
use super::super::sdk::InvocationContext;
use super::super::sdk::authority_operation::AuthorityOperationCall;
use super::super::sdk::authority_operation::{
    AuthorityOperationApproval, AuthorityOperationIssuanceAck,
};
use super::super::sdk::wire::{CanonicalWire, MAX_INVOCATION_CONTEXT_WIRE_BYTES};
use vos_protocol::wire::{DecodeError, Decoder, Encoder};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorityOperationSubmission {
    call: AuthorityOperationCall,
    context: InvocationContext,
    issued_at: u64,
}

impl AuthorityOperationSubmission {
    /// Maximum AOR1 response. Both outcomes are authenticated using this
    /// retained request, never a trust anchor supplied by the response.
    pub const MAX_RESPONSE_BYTES: usize = 16
        + AuthorityOperationIssuanceAck::MAX_ENCODED_BYTES
        + super::super::clean_bootstrap::MAX_NATIVE_OPERATION_DENIAL_BYTES
        + super::super::clean_bootstrap::MAX_NATIVE_AUTHORITY_OPERATION_DISPATCH_BYTES;

    fn verify_decision(
        &self,
        decision: &NativeAuthorityOperationDecision,
    ) -> Result<(), DecodeError> {
        if !self.validate_wire() {
            return Err(DecodeError::NonCanonical);
        }
        let valid = match decision {
            NativeAuthorityOperationDecision::Denied {
                certificate,
                dispatch,
            } => native_operation_denial_matches_request(
                &self.call,
                &self.context,
                dispatch,
                certificate,
            ),
            NativeAuthorityOperationDecision::Issued(issued) => {
                let ack = &issued.issuance_ack;
                let selector = &issued.receipt.selector;
                let approval = AuthorityOperationApproval::from_call(
                    &self.call,
                    ack.authorization_sequence,
                    selector.evidence.clone(),
                    selector.lane_roots.clone(),
                    selector.epoch,
                    selector.valid_from,
                    selector.expires_at,
                );
                ack.issued_at == self.issued_at
                    && ack.receipt == issued.receipt
                    && approval.is_ok_and(|approval| ack.matches_pending(&self.call, &approval))
                    && ack
                        .verify_with(
                            self.call.authority.binding,
                            &super::super::authority_operation_coordinator::RawEd25519Verifier,
                        )
                        .is_ok()
            }
        };
        if valid {
            Ok(())
        } else {
            Err(DecodeError::NonCanonical)
        }
    }

    /// Encode only evidence verified against these exact requested inputs.
    pub fn encode_response(
        &self,
        decision: &NativeAuthorityOperationDecision,
    ) -> Result<Vec<u8>, DecodeError> {
        self.verify_decision(decision)?;
        let (tag, payload) = match decision {
            NativeAuthorityOperationDecision::Issued(issued) => (
                0,
                issued
                    .issuance_ack
                    .encode()
                    .map_err(|_| DecodeError::NonCanonical)?,
            ),
            NativeAuthorityOperationDecision::Denied { certificate, .. } => {
                (1, certificate.clone())
            }
        };
        let mut bytes = b"AOR1".to_vec();
        let mut encoder = Encoder(&mut bytes);
        encoder.u8(tag);
        encoder.bytes(&payload);
        if let NativeAuthorityOperationDecision::Denied { dispatch, .. } = decision {
            encoder.bytes(dispatch);
        }
        Ok(bytes)
    }

    /// Verify the full signed response before returning a decision. This checks
    /// issuance at the retained issuance slot, not present-day receipt liveness;
    /// actual actor application must independently check liveness when applied.
    pub fn decode_response(
        &self,
        bytes: &[u8],
    ) -> Result<NativeAuthorityOperationDecision, DecodeError> {
        if bytes.len() > Self::MAX_RESPONSE_BYTES {
            return Err(DecodeError::LimitExceeded);
        }
        if bytes.get(..4) != Some(b"AOR1") {
            return Err(DecodeError::InvalidTag);
        }
        let mut decoder = Decoder::new(&bytes[4..]);
        let decision = match decoder.u8()? {
            0 => {
                let payload =
                    decoder.bytes_bounded(AuthorityOperationIssuanceAck::MAX_ENCODED_BYTES)?;
                let ack = AuthorityOperationIssuanceAck::decode(&payload)
                    .map_err(|_| DecodeError::NonCanonical)?;
                NativeAuthorityOperationDecision::Issued(IssuedAuthorityOperation {
                    receipt: ack.receipt.clone(),
                    issuance_ack: ack,
                })
            }
            1 => NativeAuthorityOperationDecision::Denied {
                certificate: decoder.bytes_bounded(
                    super::super::clean_bootstrap::MAX_NATIVE_OPERATION_DENIAL_BYTES,
                )?,
                dispatch: decoder.bytes_bounded(
                    super::super::clean_bootstrap::MAX_NATIVE_AUTHORITY_OPERATION_DISPATCH_BYTES,
                )?,
            },
            _ => return Err(DecodeError::InvalidTag),
        };
        if !decoder.exhausted() {
            return Err(DecodeError::TrailingBytes);
        }
        self.verify_decision(&decision)?;
        if self.encode_response(&decision)? != bytes {
            return Err(DecodeError::NonCanonical);
        }
        Ok(decision)
    }

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
