//! Terminal evidence for retiring the native policy-result pair. This is not
//! evidence that the authorized actor operation itself has been applied.
use super::*;

pub trait NativeAuthorityOperationRetirementSigner {
    type Error;
    fn public_key(&self) -> [u8; 32];
    fn sign_native_operation_retirement(&mut self, message: &[u8])
    -> Result<[u8; 64], Self::Error>;
}

pub(crate) struct RetainedNativeOperationRetirement {
    completion: RetainedNativeOperationCompletion,
}

struct RetirementCertificate {
    completion: Vec<u8>,
    signature: [u8; 64],
}

impl RetirementCertificate {
    fn signing_bytes(&self) -> Vec<u8> {
        let mut bytes = b"vos/agent/native-operation-retirement/v1".to_vec();
        bytes.extend_from_slice(crate::agent_sdk::RUNTIME_ABI_ID.as_bytes());
        bytes.extend_from_slice(
            &Hash::digest(
                b"vos/agent/native-operation-retired-completion/v1",
                &[&self.completion],
            )
            .0,
        );
        bytes
    }
}

impl CanonicalWire for RetirementCertificate {
    const MAGIC: [u8; 4] = *b"NRT1";
    const MAX_ENCODED_BYTES: usize = 1024;
    fn validate_wire(&self) -> bool {
        !self.completion.is_empty()
            && self.completion.len() <= MAX_NATIVE_OPERATION_COMPLETION_BYTES
            && self.signature != [0; 64]
    }
    fn encode_body(&self, encoder: &mut Encoder<'_>) {
        encoder.bytes(&self.completion);
        encoder.bytes(&self.signature);
    }
    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            completion: decoder
                .bytes_bounded(MAX_NATIVE_OPERATION_COMPLETION_BYTES)?
                .to_vec(),
            signature: decoder
                .bytes_bounded(64)?
                .try_into()
                .map_err(|_| DecodeError::NonCanonical)?,
        })
    }
}

fn restore_retirement(
    target: AuthorityActorTarget,
    authorization: &RetainedAuthorityOperationDispatch,
    acknowledgement: &RetainedAuthorityOperationDispatch,
    bytes: &[u8],
) -> Result<RetainedNativeOperationRetirement, SharedAgentHostError> {
    let certificate =
        RetirementCertificate::decode(bytes).map_err(|_| SharedAgentHostError::ScopeMismatch)?;
    if certificate.encode().ok().as_deref() != Some(bytes)
        || !crate::agent::authority::verify_raw_ed25519(
            &target.binding.public_key,
            &certificate.signing_bytes(),
            &certificate.signature,
        )
    {
        return Err(SharedAgentHostError::ScopeMismatch);
    }
    let completion = completion::restore_completion(
        target,
        authorization,
        acknowledgement,
        &certificate.completion,
    )?;
    Ok(RetainedNativeOperationRetirement { completion })
}

impl<P, R, I> CleanSystemAgentBootstrapOwner<P, R, I>
where
    P: CleanSystemAgentBootstrapStore,
    R: CleanSystemAgentBootstrapStore,
    I: CleanManagementIssuerStore,
{
    /// Sign and publish only under the network's retirement exclusion, after
    /// both independently verified positive acknowledgements. A failed callback
    /// retains exclusion even if it already published the exact certificate.
    pub(crate) fn finish_native_operation_retirement<S, F>(
        &mut self,
        retained: &RetainedNativeOperationCompletion,
        signer: &mut S,
        persist: F,
    ) -> Result<RetainedNativeOperationRetirement, SharedAgentHostError>
    where
        S: NativeAuthorityOperationRetirementSigner,
        F: FnOnce(&[u8]) -> Result<(), SharedAgentHostError>,
    {
        let target = self.authority_target();
        if retained.completion.target != target || signer.public_key() != target.binding.public_key
        {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        let mut result = None;
        self._network_host.complete_management_retirement(
            crate::service::AgentId(self.pins.agent.0),
            [
                retained.completion.authorization.envelope(),
                retained.completion.acknowledgement.envelope(),
            ],
            || {
                let mut certificate = RetirementCertificate {
                    completion: retained.certificate.clone(),
                    signature: [0; 64],
                };
                certificate.signature = signer
                    .sign_native_operation_retirement(&certificate.signing_bytes())
                    .map_err(|_| SharedAgentHostError::Unavailable)?;
                let bytes = certificate
                    .encode()
                    .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
                let verified = restore_retirement(
                    target,
                    &retained.completion.authorization,
                    &retained.completion.acknowledgement,
                    &bytes,
                )?;
                persist(&bytes)?;
                result = Some(verified);
                Ok(())
            },
        )?;
        result.ok_or(SharedAgentHostError::Unavailable)
    }

    pub(crate) fn restore_native_operation_retirement(
        &self,
        authorization: &RetainedAuthorityOperationDispatch,
        acknowledgement: &RetainedAuthorityOperationDispatch,
        bytes: &[u8],
    ) -> Result<RetainedNativeOperationRetirement, SharedAgentHostError> {
        restore_retirement(
            self.authority_target(),
            authorization,
            acknowledgement,
            bytes,
        )
    }

    /// The caller must hold the retirement store's exclusive lease and establish
    /// synchronization of the exact verified certificate before this call.
    pub(crate) fn release_native_operation_retirement(
        &mut self,
        retired: &RetainedNativeOperationRetirement,
    ) -> Result<(), SharedAgentHostError> {
        let completion = &retired.completion.completion;
        if completion.target != self.authority_target() {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        self._network_host.release_completed_management_retirement(
            crate::service::AgentId(self.pins.agent.0),
            [
                completion.authorization.envelope(),
                completion.acknowledgement.envelope(),
            ],
        )
    }
}
