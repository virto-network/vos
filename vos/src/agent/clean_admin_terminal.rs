//! Signed admin result retention before ACK, and terminal release after ACK.
use super::*;

pub(crate) trait NativeAuthorityAdminTerminalStore {
    type Error;
    /// Both phases are immutable and separately keyed. Bound reads before
    /// allocation; successful retention synchronizes file and parent directory.
    fn load(
        &mut self,
        invocation: InvocationId,
        retired: bool,
    ) -> Result<Option<Vec<u8>>, Self::Error>;
    fn retain(
        &mut self,
        invocation: InvocationId,
        retired: bool,
        bytes: &[u8],
    ) -> Result<(), Self::Error>;
}

pub(crate) trait NativeAuthorityAdminTerminalSigner {
    type Error;
    fn public_key(&self) -> [u8; 32];
    fn sign_admin_terminal(&mut self, message: &[u8]) -> Result<[u8; 64], Self::Error>;
}

struct Certificate {
    invocation: InvocationId,
    record: Hash,
    retired: bool,
    // Empty means the bundled Authority denied the call.
    result: Vec<u8>,
    signature: [u8; 64],
}

impl Certificate {
    fn signing_bytes(&self) -> Vec<u8> {
        let mut bytes = b"vos/agent/native-admin-terminal/v1".to_vec();
        bytes.extend_from_slice(crate::agent_sdk::RUNTIME_ABI_ID.as_bytes());
        bytes.extend_from_slice(&self.invocation.0);
        bytes.extend_from_slice(&self.record.0);
        bytes.push(u8::from(self.retired));
        bytes.extend_from_slice(
            &Hash::digest(b"vos/agent/native-admin-result/v1", &[&self.result]).0,
        );
        bytes
    }
}

impl CanonicalWire for Certificate {
    const MAGIC: [u8; 4] = *b"NAT1";
    const MAX_ENCODED_BYTES: usize = 256 + AuthorityAdminResult::MAX_ENCODED_BYTES;
    fn validate_wire(&self) -> bool {
        self.invocation != InvocationId::ZERO
            && self.record != Hash::ZERO
            && self.signature != [0; 64]
            && (self.result.is_empty() || AuthorityAdminResult::decode(&self.result).is_ok())
    }
    fn encode_body(&self, encoder: &mut Encoder<'_>) {
        encoder.fixed(&self.invocation.0);
        encoder.fixed(&self.record.0);
        encoder.u8(u8::from(self.retired));
        encoder.bytes(&self.result);
        encoder.bytes(&self.signature);
    }
    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            invocation: InvocationId(decoder.fixed()?),
            record: Hash(decoder.fixed()?),
            retired: match decoder.u8()? {
                0 => false,
                1 => true,
                _ => return Err(DecodeError::InvalidTag),
            },
            result: decoder.bytes_bounded(AuthorityAdminResult::MAX_ENCODED_BYTES)?,
            signature: decoder
                .bytes_bounded(64)?
                .try_into()
                .map_err(|_| DecodeError::NonCanonical)?,
        })
    }
}

fn commitment(record: &RetainedAuthorityAdminDispatch) -> Result<Hash, SharedAgentHostError> {
    Ok(Hash::digest(
        b"vos/agent/native-admin-dispatch/v1",
        &[&record
            .encode()
            .map_err(|_| SharedAgentHostError::ScopeMismatch)?],
    ))
}

pub(crate) fn verify_certificate(
    record: &RetainedAuthorityAdminDispatch,
    bytes: &[u8],
    retired: bool,
) -> Result<Option<AuthorityAdminResult>, SharedAgentHostError> {
    let certificate =
        Certificate::decode(bytes).map_err(|_| SharedAgentHostError::ScopeMismatch)?;
    if certificate.invocation != record.call.invocation
        || certificate.record != commitment(record)?
        || certificate.retired != retired
        || !crate::agent::authority::verify_raw_ed25519(
            &record.call.authority.binding.public_key,
            &certificate.signing_bytes(),
            &certificate.signature,
        )
    {
        return Err(SharedAgentHostError::ScopeMismatch);
    }
    if certificate.result.is_empty() {
        return Ok(None);
    }
    let result = AuthorityAdminResult::decode(&certificate.result)
        .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
    if result.call != record.call || result.verify_with(&RawCredentialVerifier).is_err() {
        return Err(SharedAgentHostError::ScopeMismatch);
    }
    Ok(Some(result))
}

/// Constructed only after a verified signed result is durably retained.
pub(crate) struct RetainedAdminResult {
    record: RetainedAuthorityAdminDispatch,
}
impl RetainedAdminResult {
    pub(crate) fn envelope(&self) -> (&ManagementJournalAnchor, &RuntimeWork) {
        (&self.record.anchor, &self.record.envelope)
    }
}

impl<P, R, I> CleanSystemAgentBootstrapOwner<P, R, I>
where
    P: CleanSystemAgentBootstrapStore,
    R: CleanSystemAgentBootstrapStore,
    I: CleanManagementIssuerStore,
{
    /// Return only after the exact result, positive ACK, and terminal release
    /// are durable. All ambiguous writes retain admission until exact retry.
    pub(crate) fn finish_authority_admin<T, S>(
        &mut self,
        record: &RetainedAuthorityAdminDispatch,
        store: &mut T,
        signer: &mut S,
    ) -> Result<Option<AuthorityAdminResult>, SharedAgentHostError>
    where
        T: NativeAuthorityAdminTerminalStore,
        S: NativeAuthorityAdminTerminalSigner,
    {
        if !record.validate_wire()
            || record.call.authority != self.authority_target()
            || record.call.authenticated_node != self.pins.node
            || signer.public_key() != self.authority_target().binding.public_key
            || self.record.pending_projection.is_some()
        {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        let invocation = record.call.invocation;
        let agent = crate::service::AgentId(self.pins.agent.0);
        if let Some(bytes) = store
            .load(invocation, true)
            .map_err(|_| SharedAgentHostError::Unavailable)?
        {
            let result = verify_certificate(record, &bytes, true)?;
            store
                .retain(invocation, true, &bytes)
                .map_err(|_| SharedAgentHostError::Unavailable)?;
            self._network_host.finish_pending_management_result(
                agent,
                &record.anchor,
                &record.envelope,
                true,
                || Ok(()),
            )?;
            return Ok(result);
        }
        self._network_host.ensure_management_pending_member(
            agent,
            &record.anchor,
            &record.envelope,
        )?;
        let (result, bytes) = if let Some(bytes) = store
            .load(invocation, false)
            .map_err(|_| SharedAgentHostError::Unavailable)?
        {
            (verify_certificate(record, &bytes, false)?, bytes)
        } else {
            let result = self.execute_authority_admin(record)?;
            let bytes = sign_certificate(record, &result, false, signer)?;
            (result, bytes)
        };
        store
            .retain(invocation, false, &bytes)
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        let proof = RetainedAdminResult {
            record: record.clone(),
        };
        let RuntimeWork::Invoke {
            invocation: work,
            authorization,
            ..
        } = &record.envelope
        else {
            return Err(SharedAgentHostError::ScopeMismatch);
        };
        if !self
            .host
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?
            .retained_positive_clean_acknowledgement(agent, work, authorization)?
        {
            let mut material = self.supervisor_invocation_material(self.pins.agent, work.actor)?;
            material.root_provenance = false;
            let identity = crate::agent::supervisor_adapters::physical_material_identity(&material)
                .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
            let crate::agent_sdk::RuntimeOutcome::Acknowledged(Ok(ack)) = self
                ._network_host
                .supervisor_acknowledge_admin_result(identity, &proof)?
            else {
                return Err(SharedAgentHostError::Unavailable);
            };
            if ack.invocation != work.invocation
                || ack.actor != work.actor
                || ack.incarnation != work.incarnation
                || ack.deployment != work.deployment
                || ack.mode != work.mode
                || ack.work != work.commitment()
                || ack.authorization != authorization.commitment()
            {
                return Err(SharedAgentHostError::ScopeMismatch);
            }
        }
        self._network_host.finish_pending_management_result(
            agent,
            &record.anchor,
            &record.envelope,
            false,
            || {
                let bytes = sign_certificate(record, &result, true, signer)?;
                store
                    .retain(invocation, true, &bytes)
                    .map_err(|_| SharedAgentHostError::Unavailable)
            },
        )?;
        Ok(result)
    }
}

fn sign_certificate<S: NativeAuthorityAdminTerminalSigner>(
    record: &RetainedAuthorityAdminDispatch,
    result: &Option<AuthorityAdminResult>,
    retired: bool,
    signer: &mut S,
) -> Result<Vec<u8>, SharedAgentHostError> {
    let mut certificate = Certificate {
        invocation: record.call.invocation,
        record: commitment(record)?,
        retired,
        result: result
            .as_ref()
            .map(|r| r.encode())
            .transpose()
            .map_err(|_| SharedAgentHostError::ScopeMismatch)?
            .unwrap_or_default(),
        signature: [0; 64],
    };
    certificate.signature = signer
        .sign_admin_terminal(&certificate.signing_bytes())
        .map_err(|_| SharedAgentHostError::Unavailable)?;
    let bytes = certificate
        .encode()
        .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
    verify_certificate(record, &bytes, retired)?;
    Ok(bytes)
}
