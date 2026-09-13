//! Signed continuation evidence, not an application receipt or finality proof.
use super::*;

/// A configured Authority signer; exact repeated messages must be idempotent.
pub trait NativeAuthorityOperationCompletionSigner {
    type Error;
    fn public_key(&self) -> [u8; 32];
    fn sign_native_operation_completion(&mut self, message: &[u8])
    -> Result<[u8; 64], Self::Error>;
}

pub(crate) struct RetainedNativeOperationCompletion {
    pub(super) completion: VerifiedNativeOperationCompletion,
}

#[derive(Clone)]
struct CompletionCertificate {
    authorization: InvocationId,
    acknowledgement: InvocationId,
    authorization_record: Hash,
    acknowledgement_record: Hash,
    signature: [u8; 64],
}

impl CompletionCertificate {
    fn signing_bytes(&self) -> Vec<u8> {
        let mut bytes = b"vos/agent/native-operation-completion/v1".to_vec();
        bytes.extend_from_slice(crate::agent_sdk::RUNTIME_ABI_ID.as_bytes());
        for value in [
            &self.authorization.0,
            &self.acknowledgement.0,
            &self.authorization_record.0,
            &self.acknowledgement_record.0,
        ] {
            bytes.extend_from_slice(value);
        }
        bytes
    }
}

impl CanonicalWire for CompletionCertificate {
    const MAGIC: [u8; 4] = *b"NOC1";
    const MAX_ENCODED_BYTES: usize = 512;
    fn validate_wire(&self) -> bool {
        self.authorization != InvocationId::ZERO
            && self.acknowledgement != InvocationId::ZERO
            && self.authorization != self.acknowledgement
            && self.authorization_record != Hash::ZERO
            && self.acknowledgement_record != Hash::ZERO
            && self.signature != [0; 64]
    }
    fn encode_body(&self, encoder: &mut Encoder<'_>) {
        encoder.fixed(&self.authorization.0);
        encoder.fixed(&self.acknowledgement.0);
        encoder.fixed(&self.authorization_record.0);
        encoder.fixed(&self.acknowledgement_record.0);
        encoder.bytes(&self.signature);
    }
    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            authorization: InvocationId(decoder.fixed()?),
            acknowledgement: InvocationId(decoder.fixed()?),
            authorization_record: Hash(decoder.fixed()?),
            acknowledgement_record: Hash(decoder.fixed()?),
            signature: decoder
                .bytes_bounded(64)?
                .try_into()
                .map_err(|_| DecodeError::NonCanonical)?,
        })
    }
}

fn commitment(record: &RetainedAuthorityOperationDispatch) -> Result<Hash, SharedAgentHostError> {
    let bytes = record
        .encode()
        .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
    Ok(Hash::digest(
        b"vos/agent/native-operation-dispatch/v1",
        &[&bytes],
    ))
}

impl<P, R, I> CleanSystemAgentBootstrapOwner<P, R, I>
where
    P: CleanSystemAgentBootstrapStore,
    R: CleanSystemAgentBootstrapStore,
    I: CleanManagementIssuerStore,
{
    /// Persist under the caller's exclusive journal lease before allowing Ack.
    /// A callback error preserves reservation and results; exact retry may sign
    /// the same preimage again, but must retain the same immutable bytes.
    pub(crate) fn retain_native_operation_completion<S, F>(
        &self,
        completion: &VerifiedNativeOperationCompletion,
        signer: &mut S,
        persist: F,
    ) -> Result<RetainedNativeOperationCompletion, SharedAgentHostError>
    where
        S: NativeAuthorityOperationCompletionSigner,
        F: FnOnce(&[u8]) -> Result<(), SharedAgentHostError>,
    {
        if completion.target != self.authority_target()
            || signer.public_key() != completion.target.binding.public_key
        {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        let mut certificate = CompletionCertificate {
            authorization: completion.authorization.request.context.invocation,
            acknowledgement: completion.acknowledgement.request.context.invocation,
            authorization_record: commitment(&completion.authorization)?,
            acknowledgement_record: commitment(&completion.acknowledgement)?,
            signature: [0; 64],
        };
        certificate.signature = signer
            .sign_native_operation_completion(&certificate.signing_bytes())
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        let bytes = certificate
            .encode()
            .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
        let retained = self.restore_native_operation_completion(
            &completion.authorization,
            &completion.acknowledgement,
            &bytes,
        )?;
        persist(&bytes)?;
        Ok(retained)
    }

    /// Recover only a signed continuation with exact source records. This does
    /// not establish that either result was acknowledged or release admission.
    pub(crate) fn restore_native_operation_completion(
        &self,
        authorization: &RetainedAuthorityOperationDispatch,
        acknowledgement: &RetainedAuthorityOperationDispatch,
        bytes: &[u8],
    ) -> Result<RetainedNativeOperationCompletion, SharedAgentHostError> {
        restore_completion(
            self.authority_target(),
            authorization,
            acknowledgement,
            bytes,
        )
    }
}

pub(super) fn completion_invocations(
    bytes: &[u8],
) -> Result<[InvocationId; 2], SharedAgentHostError> {
    let certificate =
        CompletionCertificate::decode(bytes).map_err(|_| SharedAgentHostError::ScopeMismatch)?;
    Ok([certificate.authorization, certificate.acknowledgement])
}

pub(super) fn restore_completion(
    target: AuthorityActorTarget,
    authorization: &RetainedAuthorityOperationDispatch,
    acknowledgement: &RetainedAuthorityOperationDispatch,
    bytes: &[u8],
) -> Result<RetainedNativeOperationCompletion, SharedAgentHostError> {
    let certificate =
        CompletionCertificate::decode(bytes).map_err(|_| SharedAgentHostError::ScopeMismatch)?;
    if authorization.request.target != target
        || acknowledgement.request.target != target
        || authorization.request.method != AuthorityOperationActorMethod::AuthorizeOperation
        || acknowledgement.request.method != AuthorityOperationActorMethod::AcknowledgeIssuance
        || !authorization.validate_wire()
        || !acknowledgement.validate_wire()
        || certificate.authorization != authorization.request.context.invocation
        || certificate.acknowledgement != acknowledgement.request.context.invocation
        || certificate.authorization_record != commitment(authorization)?
        || certificate.acknowledgement_record != commitment(acknowledgement)?
        || certificate.encode().ok().as_deref() != Some(bytes)
        || !crate::agent::authority::verify_raw_ed25519(
            &target.binding.public_key,
            &certificate.signing_bytes(),
            &certificate.signature,
        )
    {
        return Err(SharedAgentHostError::ScopeMismatch);
    }
    let call = AuthorityOperationCall::decode(&authorization.request.request)
        .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
    let ack = AuthorityOperationIssuanceAck::decode(&acknowledgement.request.request)
        .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
    if ack.authorization_invocation != call.invocation
        || ack.operation_call != call.commitment()
        || ack.issued_at < authorization.request.context.observed_slot
    {
        return Err(SharedAgentHostError::ScopeMismatch);
    }
    Ok(RetainedNativeOperationCompletion {
        completion: VerifiedNativeOperationCompletion {
            target,
            authorization: authorization.clone(),
            acknowledgement: acknowledgement.clone(),
        },
    })
}
