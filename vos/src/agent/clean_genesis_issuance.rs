//! Single-owner, per-candidate genesis signature retention. Not a QC or finality.

use super::AuthorizedSharedGenesisProposal;
use crate::agent::authority::verify_raw_ed25519;
use crate::agent::clean_authority_issuer::CleanManagementIssuerStore;
use crate::agent::committee::{
    AuthorityCommittee, AuthorityMemberRole, AuthorityQuorumCertificate, AuthoritySignature,
    AuthoritySignerId,
};

const PLEDGE_BYTES: usize = 4 + 32 + 32 + 32;
pub(crate) const MAX_GENESIS_SIGNATURE_IMAGE_BYTES: usize =
    crate::agent::clean_authority_issuer::MAX_CLEAN_GENESIS_SIGNATURE_IMAGE_BYTES;

/// The signer must be deterministic/idempotent for an exact message. Failure
/// after signing but before durable signature retention may repeat that message.
pub trait GenesisClaimSigner {
    type Error;
    fn public_key(&self) -> [u8; 32];
    fn sign_genesis_claim(&mut self, message: &[u8; 32]) -> Result<[u8; 64], Self::Error>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum GenesisIssuanceError {
    InvalidAuthority,
    Conflict,
    Corrupt,
    Unavailable,
    InvalidSignature,
}

pub(crate) fn committee_query_invocation(
    candidate: &AuthorizedSharedGenesisProposal,
) -> crate::agent_sdk::InvocationId {
    crate::agent_sdk::InvocationId(
        crate::service::Hash::digest(
            b"vos/ordinary-genesis/committee-query/v1",
            &[
                candidate.claim().authority_claim().claim_hash().as_bytes(),
                candidate.authorization().as_bytes(),
            ],
        )
        .0,
    )
}

/// Classify a freshly replayed publication result for reservation recovery.
/// This neither authenticates stored reply files nor grants finality.
pub(crate) fn is_publication_reply(work: &crate::agent_sdk::InvocationWork, reply: &[u8]) -> bool {
    use crate::actors::codec::Encode as _;
    use crate::service::ServiceWire as _;
    if reply.len() > crate::agent::genesis::MAX_AGENT_GENESIS_DECISION_BYTES + 5 {
        return false;
    }
    let Some(blob) = work
        .availability
        .iter()
        .find(|blob| publication_blob_matches(work, blob))
    else {
        return false;
    };
    let Ok(provision) = crate::agent::genesis::AgentGenesisProvision::decode(&blob.bytes) else {
        return false;
    };
    reply == crate::actors::value::Value::Bytes(provision.decision().encode()).encode()
}

/// Persist an authenticated publication result before allowing its ACK. Exact
/// decision equality binds the reply to the durably selected archive; this is
/// not independently rooted finality or permission to release reservations.
pub(crate) fn retain_publication_reply<S: CleanManagementIssuerStore>(
    store: &mut S,
    pending: &RetainedGenesisPublication,
    candidate: &AuthorizedSharedGenesisProposal,
    committee: &AuthorityCommittee,
    record: &crate::agent::genesis::AgentGenesisArchiveRecord,
    target: &crate::agent_sdk::authority::AuthorityActorTarget,
    reply: &crate::agent_sdk::InvocationReply,
) -> Result<crate::agent::genesis::AgentGenesisDecision, GenesisIssuanceError> {
    use crate::actors::codec::Encode as _;
    use crate::service::ServiceWire as _;
    use GenesisIssuanceError as Error;
    pending.validate(candidate, committee, record, target)?;
    let crate::agent_sdk::RuntimeWork::Invoke {
        invocation: work,
        authorization,
        ..
    } = &pending.work
    else {
        return Err(Error::InvalidAuthority);
    };
    let decision = record.provision().decision();
    let bytes = decision.encode();
    if reply.invocation != work.invocation
        || reply.actor != work.actor
        || reply.incarnation != work.incarnation
        || reply.deployment != work.deployment
        || reply.mode != work.mode
        || reply.status != crate::agent_sdk::InvocationStatus::Done
        || reply.reply != crate::actors::value::Value::Bytes(bytes.clone()).encode()
    {
        return Err(Error::InvalidAuthority);
    }
    let mut retained = Vec::with_capacity(68 + bytes.len());
    retained.extend_from_slice(b"GPR1");
    retained.extend_from_slice(work.commitment().as_bytes());
    retained.extend_from_slice(authorization.commitment().as_bytes());
    retained.extend_from_slice(&bytes);
    if retained.len()
        > crate::agent::clean_authority_issuer::MAX_CLEAN_GENESIS_PUBLICATION_REPLY_IMAGE_BYTES
    {
        return Err(Error::Corrupt);
    }
    if store
        .load()
        .map_err(|_| Error::Unavailable)?
        .is_some_and(|old| old != retained)
    {
        return Err(Error::Conflict);
    }
    store.commit(&retained).map_err(|_| Error::Unavailable)?;
    if store.load().map_err(|_| Error::Unavailable)?.as_deref() != Some(retained.as_slice()) {
        return Err(Error::Corrupt);
    }
    Ok(decision.clone())
}

/// Load publication reply data under the retained work's lease. This validates
/// exact bytes only; the owner must replay authenticated history before use.
pub(crate) fn load_publication_reply<S: CleanManagementIssuerStore>(
    store: &mut S,
    pending: &RetainedGenesisPublication,
) -> Result<Option<crate::agent::genesis::AgentGenesisDecision>, GenesisIssuanceError> {
    use crate::actors::codec::Encode as _;
    use crate::service::ServiceWire as _;
    use GenesisIssuanceError as Error;
    let Some(bytes) = store.load().map_err(|_| Error::Unavailable)? else {
        return Ok(None);
    };
    if bytes.len() < 68
        || bytes.len()
            > crate::agent::clean_authority_issuer::MAX_CLEAN_GENESIS_PUBLICATION_REPLY_IMAGE_BYTES
        || &bytes[..4] != b"GPR1"
    {
        return Err(Error::Corrupt);
    }
    let crate::agent_sdk::RuntimeWork::Invoke {
        invocation,
        authorization,
        ..
    } = &pending.work
    else {
        return Err(Error::InvalidAuthority);
    };
    if &bytes[4..36] != invocation.commitment().as_bytes()
        || &bytes[36..68] != authorization.commitment().as_bytes()
    {
        return Err(Error::Conflict);
    }
    let decision = crate::agent::genesis::AgentGenesisDecision::decode(&bytes[68..])
        .map_err(|_| Error::Corrupt)?;
    if !is_publication_reply(
        invocation,
        &crate::actors::value::Value::Bytes(bytes[68..].to_vec()).encode(),
    ) {
        return Err(Error::InvalidAuthority);
    }
    store.commit(&bytes).map_err(|_| Error::Unavailable)?;
    if store.load().map_err(|_| Error::Unavailable)?.as_deref() != Some(bytes.as_slice()) {
        return Err(Error::Corrupt);
    }
    Ok(Some(decision))
}

/// Assemble transport-order-independent signature replies against an
/// independently trusted committee. This returns archive data only: even a
/// valid quorum does not prove live Authority publication or genesis finality.
/// The coordinator must archive this exact result before publication and reuse
/// it on retry, not assemble a different valid subset into a replacement QC.
pub(crate) fn assemble(
    candidate: &AuthorizedSharedGenesisProposal,
    committee: &AuthorityCommittee,
    mut signatures: Vec<AuthoritySignature>,
) -> Result<crate::agent::genesis::AgentGenesisArchiveRecord, GenesisIssuanceError> {
    use crate::agent::genesis::{
        AgentGenesisArchiveRecord, AgentGenesisDecision, AgentGenesisEvidence,
        AgentGenesisProvision,
    };
    use GenesisIssuanceError as Error;
    if committee.validate().is_err()
        || committee.space() != candidate.claim().space()
        || committee.authority_binding() != candidate.claim().authority_binding()
    {
        return Err(Error::InvalidAuthority);
    }
    if signatures.len() > crate::agent::committee::MAX_AUTHORITY_QC_SIGNATURES {
        return Err(Error::InvalidSignature);
    }
    // Sort, but never deduplicate: repeated replies must not count as votes.
    signatures.sort_unstable_by_key(AuthoritySignature::signer);
    let certificate =
        AuthorityQuorumCertificate::new(committee, candidate.claim().authority_claim(), signatures)
            .map_err(|_| Error::InvalidSignature)?;
    let evidence = AgentGenesisEvidence::new(candidate.claim().clone(), certificate)
        .map_err(|_| Error::InvalidSignature)?;
    evidence
        .verify_certificate(committee)
        .map_err(|_| Error::InvalidSignature)?;
    let decision = AgentGenesisDecision::new(candidate.proposal(), candidate.replicas(), &evidence)
        .map_err(|_| Error::Corrupt)?;
    let provision = AgentGenesisProvision::new(
        candidate.proposal().clone(),
        candidate.replicas().clone(),
        evidence,
        decision,
    )
    .map_err(|_| Error::Corrupt)?;
    AgentGenesisArchiveRecord::new(provision, candidate.catalog().to_vec())
        .map_err(|_| Error::Corrupt)
}

/// Select exactly one QC archive before live publication. A retained valid
/// selection wins over a different incoming quorum subset on retry.
/// The supplied committee must be independently authenticated, not read from
/// the archive. The result is still not publication or finality evidence.
pub(crate) fn select_and_retain<S: crate::agent::genesis_archive::AgentGenesisArchiveStore>(
    candidate: &AuthorizedSharedGenesisProposal,
    committee: &AuthorityCommittee,
    signatures: Vec<AuthoritySignature>,
    archive: &crate::agent::genesis_archive::ArchivedAgentGenesisProvider<S>,
) -> Result<crate::agent::genesis::AgentGenesisArchiveRecord, GenesisIssuanceError> {
    let map_error = |error| match error {
        crate::agent::genesis::AgentGenesisProviderError::Unavailable => {
            GenesisIssuanceError::Unavailable
        }
        crate::agent::genesis::AgentGenesisProviderError::Conflict => {
            GenesisIssuanceError::Conflict
        }
        _ => GenesisIssuanceError::Corrupt,
    };
    let record = match archive
        .load_record(candidate.proposal().locator())
        .map_err(map_error)?
    {
        Some(record) => {
            let provision = record.provision();
            if provision.proposal() != candidate.proposal()
                || provision.replicas() != candidate.replicas()
                || provision.evidence().claim() != candidate.claim()
                || record.catalog() != candidate.catalog()
            {
                return Err(GenesisIssuanceError::Conflict);
            }
            provision
                .evidence()
                .verify_certificate(committee)
                .map_err(|_| GenesisIssuanceError::InvalidAuthority)?;
            record
        }
        None => assemble(candidate, committee, signatures)?,
    };
    // Exact insertion also completes durability after an ambiguous prior write.
    archive.publish(&record).map_err(map_error)?;
    Ok(record)
}

/// Complete immutable publication work, retained before dispatch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RetainedGenesisPublication {
    pub(crate) anchor: crate::agent::clean_management_intent::ManagementJournalAnchor,
    pub(crate) work: crate::agent_sdk::RuntimeWork,
}

impl RetainedGenesisPublication {
    const MAX_IMAGE_BYTES: usize =
        crate::agent::clean_authority_issuer::MAX_CLEAN_GENESIS_PUBLICATION_IMAGE_BYTES;

    /// Recover reservation data only. The caller must retain the store lease,
    /// reattach authenticated journal history, reproduce the candidate and
    /// validate against the independently authenticated committee before use.
    pub(crate) fn load_for_recovery<S: CleanManagementIssuerStore>(
        store: &mut S,
        target: &crate::agent_sdk::authority::AuthorityActorTarget,
        candidate_hash: crate::service::Hash,
        original_anchor: &crate::agent::clean_management_intent::ManagementJournalAnchor,
        original_work: &crate::agent_sdk::RuntimeWork,
    ) -> Result<Option<Self>, GenesisIssuanceError> {
        use crate::agent_sdk::{InvocationAuthorization, RuntimeExecutionContext, RuntimeWork};
        use crate::service::ServiceWire as _;
        let Some(bytes) = store
            .load()
            .map_err(|_| GenesisIssuanceError::Unavailable)?
        else {
            return Ok(None);
        };
        if bytes.len() > Self::MAX_IMAGE_BYTES {
            return Err(GenesisIssuanceError::Corrupt);
        }
        let saved = Self::decode(&bytes).map_err(|_| GenesisIssuanceError::Corrupt)?;
        let RuntimeWork::Invoke {
            context: original_context,
            state: original_state,
            invocation: previous,
            authorization: previous_auth,
            observed_slot: original_slot,
        } = original_work
        else {
            return Err(GenesisIssuanceError::InvalidAuthority);
        };
        let RuntimeWork::Invoke {
            context,
            state,
            invocation,
            authorization,
            observed_slot,
        } = &saved.work
        else {
            return Err(GenesisIssuanceError::InvalidAuthority);
        };
        let InvocationAuthorization::PublicPreflight(preflight) = authorization.as_ref() else {
            return Err(GenesisIssuanceError::InvalidAuthority);
        };
        let InvocationAuthorization::PublicPreflight(original_preflight) = previous_auth.as_ref()
        else {
            return Err(GenesisIssuanceError::InvalidAuthority);
        };
        if candidate_hash == crate::service::Hash::ZERO
            || *original_context != RuntimeExecutionContext::Direct
            || !original_state.is_empty()
            || *original_slot != original_preflight.observed_slot
            || !original_preflight.matches_work(previous)
            || saved.anchor.genesis != original_anchor.genesis
            || saved.anchor.admission != original_anchor.admission
            || saved.anchor.runtime != original_anchor.runtime
            || saved.anchor.runtime == crate::service::Hash::ZERO
            || original_anchor.genesis == crate::agent::journal::AgentJournalGenesisId::ZERO
            || original_anchor.admission == crate::agent::genesis::AgentGenesisAdmissionId::ZERO
            || original_anchor.ordered.validate().is_err()
            || saved.anchor.ordered.validate().is_err()
            || saved.anchor.ordered.index < original_anchor.ordered.index
            || (saved.anchor.ordered.index == original_anchor.ordered.index
                && saved.anchor.ordered.head != original_anchor.ordered.head)
            || *context != RuntimeExecutionContext::Direct
            || !state.is_empty()
            || !invocation.validate()
            || !preflight.matches_work(invocation)
            || *observed_slot != preflight.observed_slot
            || invocation.availability.len() != previous.availability.len() + 1
        {
            return Err(GenesisIssuanceError::InvalidAuthority);
        }
        let blob = invocation
            .availability
            .iter()
            .find(|blob| publication_blob_matches(invocation, blob))
            .ok_or(GenesisIssuanceError::InvalidAuthority)?;
        let provision = crate::agent::genesis::AgentGenesisProvision::decode(&blob.bytes)
            .map_err(|_| GenesisIssuanceError::Corrupt)?;
        let claim = provision.evidence().claim();
        if !authorized_create_matches(previous, target, &provision)
            || claim.authority_claim().claim_hash() != candidate_hash
            || claim.system_genesis() != saved.anchor.genesis
            || claim.system_admission() != saved.anchor.admission
            || claim.authority_binding().0 != target.binding.commitment().0
            || provision.publication_invocation(previous.invocation).ok()
                != Some(invocation.invocation)
        {
            return Err(GenesisIssuanceError::InvalidAuthority);
        }
        // Only the publication's ID/mode/message and one provision blob may
        // differ from the original signed Create. Committee observations have
        // no durable work or reply capsule and cannot be a predecessor.
        if !publication_preserves_create(invocation, previous, blob) {
            return Err(GenesisIssuanceError::InvalidAuthority);
        }
        store
            .commit(&bytes)
            .map_err(|_| GenesisIssuanceError::Unavailable)?;
        if store
            .load()
            .map_err(|_| GenesisIssuanceError::Unavailable)?
            .as_deref()
            != Some(bytes.as_slice())
        {
            return Err(GenesisIssuanceError::Corrupt);
        }
        Ok(Some(saved))
    }

    /// Decode retained candidate data without publishing, resyncing or granting
    /// authorization. Recovery must bind it to the issued Create, independently
    /// retained replica selection and original work before using the full loader.
    pub(crate) fn load_candidate_for_recovery<S: CleanManagementIssuerStore>(
        store: &mut S,
    ) -> Result<Option<crate::agent::genesis::AgentGenesisProvision>, GenesisIssuanceError> {
        use crate::service::ServiceWire as _;
        let Some(bytes) = store
            .load()
            .map_err(|_| GenesisIssuanceError::Unavailable)?
        else {
            return Ok(None);
        };
        if bytes.len() > Self::MAX_IMAGE_BYTES {
            return Err(GenesisIssuanceError::Corrupt);
        }
        let saved = Self::decode(&bytes).map_err(|_| GenesisIssuanceError::Corrupt)?;
        let crate::agent_sdk::RuntimeWork::Invoke { invocation, .. } = &saved.work else {
            return Err(GenesisIssuanceError::InvalidAuthority);
        };
        let mut blobs = invocation
            .availability
            .iter()
            .filter(|blob| publication_blob_matches(invocation, blob));
        let blob = blobs.next().ok_or(GenesisIssuanceError::InvalidAuthority)?;
        if blobs.next().is_some() {
            return Err(GenesisIssuanceError::InvalidAuthority);
        }
        crate::agent::genesis::AgentGenesisProvision::decode(&blob.bytes)
            .map(Some)
            .map_err(|_| GenesisIssuanceError::Corrupt)
    }
    pub(crate) fn validate(
        &self,
        candidate: &AuthorizedSharedGenesisProposal,
        committee: &AuthorityCommittee,
        record: &crate::agent::genesis::AgentGenesisArchiveRecord,
        target: &crate::agent_sdk::authority::AuthorityActorTarget,
    ) -> Result<(), GenesisIssuanceError> {
        use crate::agent_sdk::wire::CanonicalWire as _;
        use crate::agent_sdk::{InvocationAuthorization, RuntimeExecutionContext, RuntimeWork};
        let expected = publication_input(candidate, committee, record)?;
        let RuntimeWork::Invoke {
            context,
            state,
            invocation,
            authorization,
            observed_slot,
        } = &self.work
        else {
            return Err(GenesisIssuanceError::InvalidAuthority);
        };
        let InvocationAuthorization::PublicPreflight(preflight) = authorization.as_ref() else {
            return Err(GenesisIssuanceError::InvalidAuthority);
        };
        if !target.binding.is_valid()
            || target.binding.commitment().0 != candidate.claim().authority_binding().0
            || target.space.0 != candidate.claim().space().0
            || target.system_agent.0 != candidate.claim().system_agent().0
            || self.anchor.genesis != candidate.claim().system_genesis()
            || self.anchor.admission != candidate.claim().system_admission()
            || self.anchor.runtime == crate::service::Hash::ZERO
            || self.anchor.ordered.validate().is_err()
            || *context != RuntimeExecutionContext::Direct
            || !state.is_empty()
            || invocation.space != target.space
            || invocation.agent != target.system_agent
            || invocation.runtime_deployment != target.system_runtime_deployment
            || invocation.actor != target.binding.issuer.actor
            || invocation.deployment != target.binding.issuer.deployment
            || invocation.program != target.binding.issuer.program
            || invocation.invocation != expected.invocation
            || invocation.message != expected.message
            || !invocation.availability.contains(&expected.provision)
            || !publication_blob_matches(invocation, &expected.provision)
            || !invocation.validate()
            || !preflight.matches_work(invocation)
            || *observed_slot != preflight.observed_slot
            || self.work.encode().is_err()
        {
            return Err(GenesisIssuanceError::InvalidAuthority);
        }
        Ok(())
    }

    pub(crate) fn pledge<S: CleanManagementIssuerStore>(
        &self,
        store: &mut S,
        candidate: &AuthorizedSharedGenesisProposal,
        committee: &AuthorityCommittee,
        record: &crate::agent::genesis::AgentGenesisArchiveRecord,
        target: &crate::agent_sdk::authority::AuthorityActorTarget,
    ) -> Result<(), GenesisIssuanceError> {
        use crate::service::ServiceWire as _;
        self.validate(candidate, committee, record, target)?;
        let bytes = self.encode();
        if bytes.len() > Self::MAX_IMAGE_BYTES {
            return Err(GenesisIssuanceError::Corrupt);
        }
        if store
            .load()
            .map_err(|_| GenesisIssuanceError::Unavailable)?
            .is_some_and(|old| old != bytes)
        {
            return Err(GenesisIssuanceError::Conflict);
        }
        store
            .commit(&bytes)
            .map_err(|_| GenesisIssuanceError::Unavailable)?;
        if store
            .load()
            .map_err(|_| GenesisIssuanceError::Unavailable)?
            .as_deref()
            != Some(bytes.as_slice())
        {
            return Err(GenesisIssuanceError::Corrupt);
        }
        Ok(())
    }

    pub(crate) fn load<S: CleanManagementIssuerStore>(
        store: &mut S,
        candidate: &AuthorizedSharedGenesisProposal,
        committee: &AuthorityCommittee,
        record: &crate::agent::genesis::AgentGenesisArchiveRecord,
        target: &crate::agent_sdk::authority::AuthorityActorTarget,
    ) -> Result<Option<Self>, GenesisIssuanceError> {
        use crate::service::ServiceWire as _;
        let Some(bytes) = store
            .load()
            .map_err(|_| GenesisIssuanceError::Unavailable)?
        else {
            return Ok(None);
        };
        if bytes.len() > Self::MAX_IMAGE_BYTES {
            return Err(GenesisIssuanceError::Corrupt);
        }
        let pending = Self::decode(&bytes).map_err(|_| GenesisIssuanceError::Corrupt)?;
        pending.pledge(store, candidate, committee, record, target)?;
        Ok(Some(pending))
    }
}

impl crate::service::ServiceWire for RetainedGenesisPublication {
    const MAGIC: [u8; 4] = *b"GPW1";
    fn encode_body(&self, out: &mut Vec<u8>) {
        use crate::agent_sdk::wire::CanonicalWire as _;
        let mut encoder = crate::service::wire::Encoder(out);
        encoder.bytes(&self.anchor.encode());
        encoder.bytes(&self.work.encode().unwrap_or_default());
    }
    fn decode_body(
        decoder: &mut crate::service::wire::Decoder<'_>,
    ) -> Result<Self, crate::service::wire::DecodeError> {
        use crate::agent_sdk::wire::CanonicalWire as _;
        use crate::service::wire::DecodeError as Error;
        if decoder.remaining() > Self::MAX_IMAGE_BYTES - 36 {
            return Err(Error::LimitExceeded);
        }
        let anchor = decoder.bytes_ref()?;
        if anchor.len() > 256 {
            return Err(Error::LimitExceeded);
        }
        let anchor =
            crate::agent::clean_management_intent::ManagementJournalAnchor::decode(anchor)?;
        let work = decoder.bytes_ref()?;
        if work.len() > crate::agent_sdk::wire::MAX_RUNTIME_WORK_WIRE_BYTES {
            return Err(Error::LimitExceeded);
        }
        let work = crate::agent_sdk::RuntimeWork::decode(work).map_err(|_| Error::NonCanonical)?;
        Ok(Self { anchor, work })
    }
}

fn authorized_create_matches(
    work: &crate::agent_sdk::InvocationWork,
    target: &crate::agent_sdk::authority::AuthorityActorTarget,
    provision: &crate::agent::genesis::AgentGenesisProvision,
) -> bool {
    use crate::actors::codec::{Decode as _, Encode as _};
    use crate::agent_sdk::wire::CanonicalWire as _;
    use crate::agent_sdk::{InvocationRoleClaims, ManagementRequest, MethodMode};
    let crate::agent::journal::ReplayOperation::CleanManage { request, .. } =
        &provision.proposal().create().operation
    else {
        return false;
    };
    if !matches!(request, ManagementRequest::Create(_))
        || !target.binding.is_valid()
        || !work.validate()
        || work.mode != MethodMode::Linear
        || work.recovery_only
        || work.space != target.space
        || work.agent != target.system_agent
        || work.runtime_deployment != target.system_runtime_deployment
        || work.actor != target.binding.issuer.actor
        || work.deployment != target.binding.issuer.deployment
        || work.program != target.binding.issuer.program
        || work.message.first() != Some(&crate::actors::value::TAG_DYNAMIC)
    {
        return false;
    }
    let Some(message) = crate::actors::value::Msg::try_decode(&work.message[1..]) else {
        return false;
    };
    if message.encode() != work.message[1..] {
        return false;
    }
    let Some(bytes) = message.args.get_bytes("call") else {
        return false;
    };
    let Ok(call) = crate::agent_sdk::authority::AuthorityCredentialCall::decode(&bytes) else {
        return false;
    };
    let Ok(intent) = crate::agent::clean_management_intent::CleanManagementIntent::new(
        *target,
        call.managed,
        request.clone(),
        call,
        &super::RawCredentialVerifier,
    ) else {
        return false;
    };
    work.invocation == intent.call().invocation
        && work.origin == intent.authorization_origin()
        && work.roles == InvocationRoleClaims::none()
        && work.message == intent.authorization_message()
}

fn publication_preserves_create(
    publication: &crate::agent_sdk::InvocationWork,
    original: &crate::agent_sdk::InvocationWork,
    provision: &crate::agent_sdk::RuntimeBlob,
) -> bool {
    if publication.availability.len() != original.availability.len() + 1
        || original
            .availability
            .iter()
            .any(|entry| entry.reference == provision.reference)
        || publication
            .availability
            .iter()
            .filter(|entry| *entry == provision)
            .count()
            != 1
    {
        return false;
    }
    let mut base = publication.clone();
    base.mode = original.mode;
    base.invocation = original.invocation;
    base.message = original.message.clone();
    base.availability
        .retain(|entry| entry.reference != provision.reference);
    &base == original
}

/// Exact compact publication request derived from the selected archive. This
/// data still needs a persisted preflight, journal anchor and authenticated
/// dispatch; constructing it neither publishes a decision nor grants finality.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct GenesisPublicationInput {
    pub(crate) invocation: crate::agent_sdk::InvocationId,
    pub(crate) message: Vec<u8>,
    pub(crate) provision: crate::agent_sdk::RuntimeBlob,
}

pub(crate) fn publication_input(
    candidate: &AuthorizedSharedGenesisProposal,
    committee: &AuthorityCommittee,
    record: &crate::agent::genesis::AgentGenesisArchiveRecord,
) -> Result<GenesisPublicationInput, GenesisIssuanceError> {
    use crate::actors::codec::Encode as _;
    use crate::actors::value::{Msg, TAG_DYNAMIC, Value};
    use crate::service::ServiceWire as _;
    let provision = record.provision();
    if provision.proposal() != candidate.proposal()
        || provision.replicas() != candidate.replicas()
        || provision.evidence().claim() != candidate.claim()
        || record.catalog() != candidate.catalog()
    {
        return Err(GenesisIssuanceError::Conflict);
    }
    provision
        .evidence()
        .verify_certificate(committee)
        .map_err(|_| GenesisIssuanceError::InvalidAuthority)?;
    let bytes = provision.encode();
    if bytes.len() > crate::agent::genesis::MAX_CLEAN_CREATE_GENESIS_PROVISION_BYTES
        || bytes.len() > crate::agent::execution::MAX_EXECUTION_AVAILABILITY_BYTES
    {
        return Err(GenesisIssuanceError::Corrupt);
    }
    let reference = crate::agent_sdk::BlobRef::of_bytes(&bytes);
    let invocation = provision
        .publication_invocation(candidate.authorization())
        .map_err(|_| GenesisIssuanceError::Corrupt)?;
    let mut message = vec![TAG_DYNAMIC];
    message.extend(
        Msg::new("publish_genesis")
            .with(
                "authorization",
                Value::Bytes(candidate.authorization().0.to_vec()),
            )
            .with("provision_hash", Value::Bytes(reference.hash.0.to_vec()))
            .with("provision_len", Value::U64(reference.len))
            .encode(),
    );
    Ok(GenesisPublicationInput {
        invocation,
        message,
        provision: crate::agent_sdk::RuntimeBlob { reference, bytes },
    })
}

/// Validate the single extra caller blob permitted by genesis publication.
/// This binds transport data only; the Authority actor still checks the pending
/// authorization and QC, and the coordinator still authenticates its anchor.
pub(crate) fn publication_blob_matches(
    work: &crate::agent_sdk::InvocationWork,
    blob: &crate::agent_sdk::RuntimeBlob,
) -> bool {
    use crate::actors::codec::{Decode as _, Encode as _};
    use crate::actors::value::{Msg, TAG_DYNAMIC, Value};
    use crate::service::ServiceWire as _;
    if work.mode != crate::agent_sdk::MethodMode::Linear
        || work.recovery_only
        || work.message.first() != Some(&TAG_DYNAMIC)
        || !blob.validate()
        || blob.bytes.len() > crate::agent::genesis::MAX_CLEAN_CREATE_GENESIS_PROVISION_BYTES
        || blob.bytes.len() > crate::agent::execution::MAX_EXECUTION_AVAILABILITY_BYTES
    {
        return false;
    }
    let Some(message) = Msg::try_decode(&work.message[1..]) else {
        return false;
    };
    let Some(Value::Bytes(authorization)) = message.args.get("authorization") else {
        return false;
    };
    let Ok(authorization) = <[u8; 32]>::try_from(authorization.as_slice()) else {
        return false;
    };
    let authorization = crate::agent_sdk::InvocationId(authorization);
    let Ok(provision) = crate::agent::genesis::AgentGenesisProvision::decode(&blob.bytes) else {
        return false;
    };
    if provision.publication_invocation(authorization).ok() != Some(work.invocation)
        || provision.evidence().claim().space().0 != work.space.0
        || provision.evidence().claim().system_agent().0 != work.agent.0
    {
        return false;
    }
    let mut expected = vec![TAG_DYNAMIC];
    expected.extend(
        Msg::new("publish_genesis")
            .with("authorization", Value::Bytes(authorization.0.to_vec()))
            .with(
                "provision_hash",
                Value::Bytes(blob.reference.hash.0.to_vec()),
            )
            .with("provision_len", Value::U64(blob.reference.len))
            .encode(),
    );
    expected == work.message
}

/// `committee` must come from independently authenticated Authority history,
/// never from the proposed archive. `store` is an exclusively leased slot for
/// this genesis and signer, with atomic durable commits and bounded reads.
/// Every attempt reloads; no in-memory success survives an ambiguous commit.
/// A fresh replay-authorized candidate is required even when a signature exists.
pub(crate) fn issue<S: CleanManagementIssuerStore, K: GenesisClaimSigner>(
    candidate: &AuthorizedSharedGenesisProposal,
    committee: &AuthorityCommittee,
    store: &mut S,
    signer: &mut K,
) -> Result<AuthoritySignature, GenesisIssuanceError> {
    use GenesisIssuanceError as Error;
    let public = signer.public_key();
    let signer_id = AuthoritySignerId::of_raw_ed25519(&public);
    if committee.validate().is_err()
        || committee.space() != candidate.claim().space()
        || committee.authority_binding() != candidate.claim().authority_binding()
        || committee.member(signer_id).is_none_or(|member| {
            member.role() != AuthorityMemberRole::Voter || member.public_key() != &public
        })
    {
        return Err(Error::InvalidAuthority);
    }
    let message = AuthorityQuorumCertificate::signing_message(
        committee.authority_binding(),
        committee.epoch(),
        committee.commitment(),
        candidate.claim().authority_claim(),
    );
    // Fixed-size, domain-tagged pledge binds authorization, signer and complete
    // QC message (including committee epoch/commitment and genesis claim).
    let mut pledge = Vec::with_capacity(MAX_GENESIS_SIGNATURE_IMAGE_BYTES);
    pledge.extend_from_slice(b"GSI1");
    pledge.extend_from_slice(candidate.authorization().as_bytes());
    pledge.extend_from_slice(&public);
    pledge.extend_from_slice(&message.0);
    let retained = store.load().map_err(|_| Error::Unavailable)?;
    if let Some(bytes) = retained {
        if bytes.len() != PLEDGE_BYTES && bytes.len() != MAX_GENESIS_SIGNATURE_IMAGE_BYTES {
            return Err(Error::Corrupt);
        }
        if bytes[..PLEDGE_BYTES] != pledge {
            return Err(Error::Conflict);
        }
        if bytes.len() == MAX_GENESIS_SIGNATURE_IMAGE_BYTES {
            let signature: [u8; 64] = bytes[PLEDGE_BYTES..]
                .try_into()
                .map_err(|_| Error::Corrupt)?;
            if !verify_raw_ed25519(&public, &message.0, &signature) {
                return Err(Error::Corrupt);
            }
            // A previous commit may have failed after rename but before sync.
            // Reestablish durability before returning retained evidence.
            store.commit(&bytes).map_err(|_| Error::Unavailable)?;
            if store.load().map_err(|_| Error::Unavailable)?.as_deref() != Some(bytes.as_slice()) {
                return Err(Error::Corrupt);
            }
            return AuthoritySignature::new(signer_id, signature).map_err(|_| Error::Corrupt);
        }
    }
    // Also resync an existing pledge after an ambiguous prior write; mere
    // visibility is insufficient to authorize the external signing call.
    store.commit(&pledge).map_err(|_| Error::Unavailable)?;
    if store.load().map_err(|_| Error::Unavailable)?.as_deref() != Some(pledge.as_slice()) {
        return Err(Error::Corrupt);
    }
    let signature = signer
        .sign_genesis_claim(&message.0)
        .map_err(|_| Error::Unavailable)?;
    if !verify_raw_ed25519(&public, &message.0, &signature) {
        return Err(Error::InvalidSignature);
    }
    pledge.extend_from_slice(&signature);
    store.commit(&pledge).map_err(|_| Error::Unavailable)?;
    if store.load().map_err(|_| Error::Unavailable)?.as_deref() != Some(pledge.as_slice()) {
        return Err(Error::Corrupt);
    }
    AuthoritySignature::new(signer_id, signature).map_err(|_| Error::InvalidSignature)
}

#[cfg(test)]
mod publication_binding_tests {
    use super::publication_preserves_create;
    use crate::agent_sdk::{
        ActorId, AgentId, BlobRef, DeploymentId, Hash, InvocationId, InvocationOrigin,
        InvocationRoleClaims, InvocationWork, MethodMode, ProgramId, RuntimeBlob, SpaceId,
    };

    fn inputs() -> (InvocationWork, InvocationWork, RuntimeBlob) {
        let artifact = RuntimeBlob {
            reference: BlobRef::of_bytes(b"installed actor"),
            bytes: b"installed actor".to_vec(),
        };
        let arguments = RuntimeBlob {
            reference: BlobRef::of_bytes(b"constructor arguments"),
            bytes: b"constructor arguments".to_vec(),
        };
        let mut availability = vec![artifact, arguments.clone()];
        availability.sort_unstable_by(|a, b| a.reference.cmp(&b.reference));
        let original = InvocationWork {
            space: SpaceId([1; 32]),
            agent: AgentId([2; 32]),
            runtime_deployment: DeploymentId([3; 32]),
            invocation: InvocationId([4; 32]),
            actor: ActorId([5; 32]),
            incarnation: Hash([6; 32]),
            deployment: DeploymentId([7; 32]),
            program: ProgramId([8; 32]),
            mode: MethodMode::Linear,
            origin: InvocationOrigin::anonymous(),
            roles: InvocationRoleClaims::none(),
            message: b"original signed Create authorization".to_vec(),
            installation_data: Some(arguments.reference),
            availability,
            gas: 1_000_000_000,
            recovery_only: false,
        };
        let provision = RuntimeBlob {
            reference: BlobRef::of_bytes(b"exact provision"),
            bytes: b"exact provision".to_vec(),
        };
        let mut publication = original.clone();
        publication.invocation = InvocationId([9; 32]);
        publication.message = b"publication request bound separately to provision".to_vec();
        publication.availability.push(provision.clone());
        publication
            .availability
            .sort_unstable_by(|a, b| a.reference.cmp(&b.reference));
        assert!(original.validate());
        assert!(publication.validate());
        (original, publication, provision)
    }

    #[test]
    fn publication_binding_preserves_every_original_work_field() {
        let (original, publication, provision) = inputs();
        assert!(publication_preserves_create(
            &publication,
            &original,
            &provision
        ));
        let mutations: &[fn(&mut InvocationWork)] = &[
            |work| work.space = SpaceId([99; 32]),
            |work| work.agent = AgentId([99; 32]),
            |work| work.runtime_deployment = DeploymentId([99; 32]),
            |work| work.actor = ActorId([99; 32]),
            |work| work.incarnation = Hash([99; 32]),
            |work| work.deployment = DeploymentId([99; 32]),
            |work| work.program = ProgramId([99; 32]),
            |work| work.origin.principal = Some(crate::agent_sdk::PrincipalId([99; 32])),
            |work| work.origin.transport_node = Some(crate::agent_sdk::NodeId([99; 32])),
            |work| work.origin.credential = Some(crate::agent_sdk::CredentialId([99; 32])),
            |work| work.origin.actor = Some(ActorId([99; 32])),
            |work| work.origin.capability = Some(crate::agent_sdk::CapabilityId([99; 32])),
            |work| work.roles.actor = Some(crate::agent_sdk::RoleId([99; 32])),
            |work| work.installation_data = None,
            |work| work.gas = 1,
            |work| work.recovery_only = true,
        ];
        for (index, mutate) in mutations.iter().enumerate() {
            let mut changed = publication.clone();
            mutate(&mut changed);
            assert!(
                !publication_preserves_create(&changed, &original, &provision),
                "unauthorized field mutation {index}"
            );
        }
    }

    #[test]
    fn publication_binding_allows_only_one_new_exact_provision() {
        let (original, publication, provision) = inputs();
        let mut changed = publication.clone();
        changed.availability.push(provision.clone());
        assert!(!publication_preserves_create(
            &changed, &original, &provision
        ));
        let mut changed = publication.clone();
        changed
            .availability
            .iter_mut()
            .find(|blob| blob.reference == provision.reference)
            .unwrap()
            .bytes
            .push(0);
        assert!(!publication_preserves_create(
            &changed, &original, &provision
        ));
        let mut changed = publication.clone();
        changed
            .availability
            .iter_mut()
            .find(|blob| blob.reference == original.availability[0].reference)
            .unwrap()
            .bytes
            .push(0);
        assert!(!publication_preserves_create(
            &changed, &original, &provision
        ));
        let mut changed_original = original;
        changed_original.availability.push(provision.clone());
        assert!(!publication_preserves_create(
            &publication,
            &changed_original,
            &provision
        ));
    }
}
