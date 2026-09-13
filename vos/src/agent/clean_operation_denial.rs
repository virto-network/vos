//! Native unissued denial proof and separately signed terminal retirement.
use super::*;
use crate::agent::authority_operation_issuer::{
    AuthorityOperationIssuerStore, DurableAuthorityOperationIssuer,
};
use crate::agent::sdk::{InvocationStatus, RuntimeOutcome};

pub const MAX_NATIVE_OPERATION_DENIAL_BYTES: usize = 512;

/// Signature/framing validation only; native recovery also requires the exact
/// source record and independently verified absence of retained issuance.
pub fn native_operation_denial_invocation(
    public_key: &[u8; 32],
    bytes: &[u8],
) -> Option<InvocationId> {
    let certificate = DenialCertificate::decode(bytes).ok()?;
    if certificate.encode().ok().as_deref() != Some(bytes)
        || !crate::agent::authority::verify_raw_ed25519(
            public_key,
            &certificate.signing_bytes(),
            &certificate.signature,
        )
    {
        return None;
    }
    Some(certificate.invocation)
}

pub(crate) struct VerifiedNativeOperationDenial<'a> {
    proof: VerifiedManagementDenial,
    target: AuthorityActorTarget,
    record: RetainedAuthorityOperationDispatch,
    // Prevent issuance or replacement of the parsed issuer while this unissued
    // denial is being acknowledged. The caller must also retain its store lease.
    _issuer: core::marker::PhantomData<&'a mut ()>,
}

pub trait NativeAuthorityOperationDenialSigner {
    type Error;
    fn public_key(&self) -> [u8; 32];
    fn sign_native_operation_denial(&mut self, message: &[u8]) -> Result<[u8; 64], Self::Error>;
}

pub(crate) struct RetainedNativeOperationDenial<'a> {
    target: AuthorityActorTarget,
    record: RetainedAuthorityOperationDispatch,
    _issuer: core::marker::PhantomData<&'a mut ()>,
}

struct DenialCertificate {
    invocation: InvocationId,
    record: Hash,
    call: Hash,
    input: crate::agent::journal::ReplayInputId,
    signature: [u8; 64],
}

impl DenialCertificate {
    fn signing_bytes(&self) -> Vec<u8> {
        let mut bytes = b"vos/agent/native-operation-denial-retirement/v1".to_vec();
        bytes.extend_from_slice(crate::agent_sdk::RUNTIME_ABI_ID.as_bytes());
        for field in [
            &self.invocation.0,
            &self.record.0,
            &self.call.0,
            &self.input.0,
        ] {
            bytes.extend_from_slice(field);
        }
        bytes
    }
}

impl CanonicalWire for DenialCertificate {
    const MAGIC: [u8; 4] = *b"NDR1";
    const MAX_ENCODED_BYTES: usize = MAX_NATIVE_OPERATION_DENIAL_BYTES;
    fn validate_wire(&self) -> bool {
        self.invocation != InvocationId::ZERO
            && self.record != Hash::ZERO
            && self.call != Hash::ZERO
            && self.input != crate::agent::journal::ReplayInputId::ZERO
            && self.signature != [0; 64]
    }
    fn encode_body(&self, encoder: &mut Encoder<'_>) {
        encoder.fixed(&self.invocation.0);
        encoder.fixed(&self.record.0);
        encoder.fixed(&self.call.0);
        encoder.fixed(&self.input.0);
        encoder.bytes(&self.signature);
    }
    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            invocation: InvocationId(decoder.fixed()?),
            record: Hash(decoder.fixed()?),
            call: Hash(decoder.fixed()?),
            input: crate::agent::journal::ReplayInputId(decoder.fixed()?),
            signature: decoder
                .bytes_bounded(64)?
                .try_into()
                .map_err(|_| DecodeError::NonCanonical)?,
        })
    }
}

pub(super) fn restore_denial<'a>(
    target: AuthorityActorTarget,
    record: &RetainedAuthorityOperationDispatch,
    bytes: &[u8],
) -> Result<RetainedNativeOperationDenial<'a>, SharedAgentHostError> {
    let certificate =
        DenialCertificate::decode(bytes).map_err(|_| SharedAgentHostError::ScopeMismatch)?;
    if record.request.target != target
        || record.request.method != AuthorityOperationActorMethod::AuthorizeOperation
        || !record.validate_wire()
        || certificate.invocation != record.request.context.invocation
        || certificate.record != completion::commitment(record)?
        || certificate.encode().ok().as_deref() != Some(bytes)
        || !crate::agent::authority::verify_raw_ed25519(
            &target.binding.public_key,
            &certificate.signing_bytes(),
            &certificate.signature,
        )
    {
        return Err(SharedAgentHostError::ScopeMismatch);
    }
    let call = AuthorityOperationCall::decode(&record.request.request)
        .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
    if certificate.call != call.commitment() {
        return Err(SharedAgentHostError::ScopeMismatch);
    }
    Ok(RetainedNativeOperationDenial {
        target,
        record: record.clone(),
        _issuer: core::marker::PhantomData,
    })
}

impl<P, R, I> CleanSystemAgentBootstrapOwner<P, R, I>
where
    P: CleanSystemAgentBootstrapStore,
    R: CleanSystemAgentBootstrapStore,
    I: CleanManagementIssuerStore,
{
    /// Inspect only already-durable native policy execution. No fresh dispatch,
    /// signing, or release is permitted by this verification boundary.
    pub(crate) fn verify_native_operation_denial<'a, B: AuthorityOperationIssuerStore>(
        &mut self,
        record: &RetainedAuthorityOperationDispatch,
        issuer: &'a mut DurableAuthorityOperationIssuer<B>,
    ) -> Result<Option<VerifiedNativeOperationDenial<'a>>, SharedAgentHostError> {
        let target = self.authority_target();
        if record.request.target != target
            || record.request.method != AuthorityOperationActorMethod::AuthorizeOperation
            || !record.validate_wire()
            || issuer.authority() != target
            || issuer.is_poisoned()
            || issuer
                .recover_retained(record.request.context.invocation)
                .map_err(|_| SharedAgentHostError::Unavailable)?
                .is_some()
        {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        let call = AuthorityOperationCall::decode(&record.request.request)
            .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
        let RuntimeWork::Invoke {
            invocation,
            authorization,
            observed_slot,
            ..
        } = &record.envelope
        else {
            return Err(SharedAgentHostError::ScopeMismatch);
        };
        let agent = crate::service::AgentId(self.pins.agent.0);
        self._network_host.ensure_reattached(agent)?;
        self._network_host.ensure_management_pending_member(
            agent,
            &record.anchor,
            &record.envelope,
        )?;
        let mut material =
            self.supervisor_invocation_material(self.pins.agent, target.binding.issuer.actor)?;
        material.root_provenance = false;
        let identity = crate::agent::supervisor_adapters::physical_material_identity(&material)
            .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
        if !crate::agent::supervisor_adapters::physical_material_authorizes_reserved_work(
            &material,
            identity,
            RuntimeExecutionContext::Direct,
            invocation,
            authorization,
            *observed_slot,
        ) {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        let mut host = self
            .host
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        let Some(input) = host.management_denial_invocation_after_anchor(
            agent,
            &record.anchor,
            &record.envelope,
        )?
        else {
            return Ok(None);
        };
        let RuntimeOutcome::Completed(Ok(reply)) =
            host.replay_durable_management_denial(agent, &record.anchor, &record.envelope)?
        else {
            return Ok(None);
        };
        if reply.invocation != invocation.invocation
            || reply.actor != invocation.actor
            || reply.incarnation != invocation.incarnation
            || reply.deployment != invocation.deployment
            || reply.mode != invocation.mode
            || reply.status != InvocationStatus::Done
        {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        if reply.reply != crate::Encode::encode(&crate::value::Value::Bytes(Vec::new())) {
            return Ok(None);
        }
        Ok(Some(VerifiedNativeOperationDenial {
            record: record.clone(),
            proof: VerifiedManagementDenial {
                call: call.commitment(),
                anchor: record.anchor.clone(),
                work: record.envelope.clone(),
                input,
            },
            target,
            _issuer: core::marker::PhantomData,
        }))
    }

    /// Positively acknowledge only the exact verified unissued denial. Keep its
    /// reservation until separate durable terminal evidence authorizes release.
    pub(crate) fn acknowledge_native_operation_denial(
        &mut self,
        denial: &VerifiedNativeOperationDenial<'_>,
    ) -> Result<bool, SharedAgentHostError> {
        if denial.target != self.authority_target() {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        let (anchor, envelope) = denial.proof.envelope();
        let RuntimeWork::Invoke {
            invocation,
            authorization,
            ..
        } = envelope
        else {
            return Err(SharedAgentHostError::ScopeMismatch);
        };
        let agent = crate::service::AgentId(self.pins.agent.0);
        self._network_host.ensure_reattached(agent)?;
        self._network_host
            .ensure_management_pending_member(agent, anchor, envelope)?;
        if self
            .host
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?
            .retained_positive_clean_acknowledgement(agent, invocation, authorization)?
        {
            return Ok(false);
        }
        let mut material = self
            .supervisor_invocation_material(self.pins.agent, denial.target.binding.issuer.actor)?;
        material.root_provenance = false;
        let identity = crate::agent::supervisor_adapters::physical_material_identity(&material)
            .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
        let RuntimeOutcome::Acknowledged(Ok(ack)) = self
            ._network_host
            .supervisor_acknowledge_management_denial(identity, &denial.proof)?
        else {
            return Err(SharedAgentHostError::Unavailable);
        };
        if ack.invocation != invocation.invocation
            || ack.actor != invocation.actor
            || ack.incarnation != invocation.incarnation
            || ack.deployment != invocation.deployment
            || ack.mode != invocation.mode
            || ack.work != invocation.commitment()
            || ack.authorization != authorization.commitment()
            || !self
                .host
                .lock()
                .map_err(|_| SharedAgentHostError::Unavailable)?
                .retained_positive_clean_acknowledgement(agent, invocation, authorization)?
        {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        Ok(true)
    }

    /// Sign and persist under pending-admission exclusion after the host has
    /// independently confirmed positive acknowledgement. Failure keeps the
    /// reservation even if the callback already published the certificate.
    pub(crate) fn finish_native_operation_denial<'a, S, F>(
        &mut self,
        denial: &VerifiedNativeOperationDenial<'a>,
        signer: &mut S,
        persist: F,
    ) -> Result<RetainedNativeOperationDenial<'a>, SharedAgentHostError>
    where
        S: NativeAuthorityOperationDenialSigner,
        F: FnOnce(&[u8]) -> Result<(), SharedAgentHostError>,
    {
        let target = self.authority_target();
        if denial.target != target || signer.public_key() != target.binding.public_key {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        let mut result = None;
        self._network_host.finish_management_denial_record(
            crate::service::AgentId(self.pins.agent.0),
            denial.record.anchor(),
            denial.record.envelope(),
            false,
            || {
                let mut certificate = DenialCertificate {
                    invocation: denial.record.request.context.invocation,
                    record: completion::commitment(&denial.record)?,
                    call: denial.proof.call,
                    input: denial.proof.input,
                    signature: [0; 64],
                };
                certificate.signature = signer
                    .sign_native_operation_denial(&certificate.signing_bytes())
                    .map_err(|_| SharedAgentHostError::Unavailable)?;
                let bytes = certificate
                    .encode()
                    .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
                let retired = restore_denial(target, &denial.record, &bytes)?;
                persist(&bytes)?;
                result = Some(retired);
                Ok(())
            },
        )?;
        result.ok_or(SharedAgentHostError::Unavailable)
    }

    pub(crate) fn restore_native_operation_denial<'a, B: AuthorityOperationIssuerStore>(
        &self,
        record: &RetainedAuthorityOperationDispatch,
        issuer: &'a mut DurableAuthorityOperationIssuer<B>,
        bytes: &[u8],
    ) -> Result<RetainedNativeOperationDenial<'a>, SharedAgentHostError> {
        if issuer.authority() != self.authority_target()
            || issuer.is_poisoned()
            || issuer
                .recover_retained(record.request.context.invocation)
                .map_err(|_| SharedAgentHostError::Unavailable)?
                .is_some()
        {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        restore_denial(self.authority_target(), record, bytes)
    }

    /// Caller holds the denial store lease and has synchronized the exact
    /// verified bytes, including when recovering an ambiguous publication.
    pub(crate) fn release_native_operation_denial(
        &mut self,
        denied: &RetainedNativeOperationDenial<'_>,
    ) -> Result<(), SharedAgentHostError> {
        if denied.target != self.authority_target() {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        self._network_host.finish_management_denial_record(
            crate::service::AgentId(self.pins.agent.0),
            denied.record.anchor(),
            denied.record.envelope(),
            true,
            || Ok(()),
        )
    }
}
