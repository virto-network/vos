//! Single-owner, per-candidate genesis signature retention. Not a QC or finality.

use super::AuthorizedSharedGenesisProposal;
use crate::agent::authority::verify_raw_ed25519;
use crate::agent::clean_authority_issuer::CleanManagementIssuerStore;
use crate::agent::committee::{
    AuthorityCommittee, AuthorityMemberRole, AuthorityQuorumCertificate,
    AuthoritySignature, AuthoritySignerId,
};

const PLEDGE_BYTES: usize = 4 + 32 + 32 + 32;
pub(crate) const MAX_GENESIS_SIGNATURE_IMAGE_BYTES: usize =
    crate::agent::clean_authority_issuer::MAX_CLEAN_GENESIS_SIGNATURE_IMAGE_BYTES;

/// The signer must be deterministic/idempotent for an exact message. Failure
/// after signing but before durable signature retention may repeat that message.
pub(crate) trait GenesisClaimSigner {
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

/// Data retained before query dispatch, not evidence that dispatch or finality
/// occurred. Recovery must authenticate `anchor` against the live system store.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RetainedCommitteeQuery {
    candidate: crate::service::Hash,
    authorization: crate::agent_sdk::InvocationId,
    pub(crate) anchor: crate::agent::clean_management_intent::ManagementJournalAnchor,
    pub(crate) work: crate::agent_sdk::RuntimeWork,
}

const MAX_QUERY_BYTES: usize = crate::agent::clean_authority_issuer::MAX_CLEAN_GENESIS_QUERY_IMAGE_BYTES;

pub(crate) fn committee_query_invocation(candidate: &AuthorizedSharedGenesisProposal) -> crate::agent_sdk::InvocationId {
    crate::agent_sdk::InvocationId(crate::service::Hash::digest(
        b"vos/ordinary-genesis/committee-query/v1",
        &[candidate.claim().authority_claim().claim_hash().as_bytes(), candidate.authorization().as_bytes()],
    ).0)
}

impl RetainedCommitteeQuery {
    /// Read reservation data before the owner can reproduce an authorized
    /// candidate. This is NOT an authorization capability. Startup must retain
    /// the store lease, authenticate both anchors through journal reattachment,
    /// then reproduce the candidate and call `load` before query execution.
    pub(crate) fn load_for_recovery<S: CleanManagementIssuerStore>(
        store: &mut S,
        target: &crate::agent_sdk::authority::AuthorityActorTarget,
        predecessor: &crate::agent::clean_management_intent::ManagementJournalAnchor,
        original: &crate::agent_sdk::RuntimeWork,
    ) -> Result<Option<Self>, GenesisIssuanceError> {
        use crate::service::ServiceWire as _;
        use crate::agent_sdk::{RuntimeWork, RuntimeExecutionContext, InvocationAuthorization};
        let Some(bytes) = store.load().map_err(|_| GenesisIssuanceError::Unavailable)? else { return Ok(None); };
        if bytes.len() > MAX_QUERY_BYTES { return Err(GenesisIssuanceError::Corrupt); }
        let saved = Self::decode(&bytes).map_err(|_| GenesisIssuanceError::Corrupt)?;
        let RuntimeWork::Invoke { invocation: original, .. } = original else { return Err(GenesisIssuanceError::InvalidAuthority); };
        let RuntimeWork::Invoke { context, state, invocation, authorization, observed_slot } = &saved.work else {
            return Err(GenesisIssuanceError::InvalidAuthority);
        };
        let InvocationAuthorization::PublicPreflight(preflight) = authorization.as_ref() else {
            return Err(GenesisIssuanceError::InvalidAuthority);
        };
        let expected = crate::service::Hash::digest(b"vos/ordinary-genesis/committee-query/v1",
            &[saved.candidate.as_bytes(), saved.authorization.as_bytes()]);
        if saved.candidate == crate::service::Hash::ZERO
            || saved.authorization != original.invocation || !original.validate()
            || original.mode != crate::agent_sdk::MethodMode::Linear
            || original.space != target.space || original.agent != target.system_agent
            || original.runtime_deployment != target.system_runtime_deployment
            || original.actor != target.binding.issuer.actor || original.deployment != target.binding.issuer.deployment
            || original.program != target.binding.issuer.program
            || saved.anchor.genesis != predecessor.genesis || saved.anchor.admission != predecessor.admission
            || saved.anchor.runtime != predecessor.runtime || saved.anchor.runtime == crate::service::Hash::ZERO
            || predecessor.ordered.validate().is_err() || saved.anchor.ordered.validate().is_err()
            || saved.anchor.ordered.index < predecessor.ordered.index
            || *context != RuntimeExecutionContext::Direct || !state.is_empty()
            || invocation.invocation.0 != expected.0 || invocation.recovery_only
            || *observed_slot != preflight.observed_slot
            || !committee_query_matches(invocation, authorization, target)
        { return Err(GenesisIssuanceError::InvalidAuthority); }
        Ok(Some(saved))
    }

    pub(crate) fn new(
        candidate: &AuthorizedSharedGenesisProposal,
        target: &crate::agent_sdk::authority::AuthorityActorTarget,
        anchor: crate::agent::clean_management_intent::ManagementJournalAnchor,
        work: crate::agent_sdk::RuntimeWork,
    ) -> Result<Self, GenesisIssuanceError> {
        let record = Self {
            candidate: candidate.claim().authority_claim().claim_hash(),
            authorization: candidate.authorization(), anchor, work,
        };
        record.validate_for(candidate, target)?;
        Ok(record)
    }

    fn validate_for(&self, candidate: &AuthorizedSharedGenesisProposal,
        target: &crate::agent_sdk::authority::AuthorityActorTarget) -> Result<(), GenesisIssuanceError> {
        use crate::agent_sdk::wire::CanonicalWire as _;
        use crate::agent_sdk::{RuntimeWork, InvocationAuthorization, RuntimeExecutionContext};
        let RuntimeWork::Invoke { context, state, invocation, authorization, observed_slot } = &self.work else {
            return Err(GenesisIssuanceError::InvalidAuthority);
        };
        let InvocationAuthorization::PublicPreflight(preflight) = authorization.as_ref() else {
            return Err(GenesisIssuanceError::InvalidAuthority);
        };
        if self.candidate != candidate.claim().authority_claim().claim_hash()
            || self.authorization != candidate.authorization()
            || self.anchor.genesis != candidate.claim().system_genesis()
            || self.anchor.admission != candidate.claim().system_admission()
            || self.anchor.runtime == crate::service::Hash::ZERO
            || self.anchor.ordered.validate().is_err()
            || target.system_agent.0 != candidate.claim().system_agent().0
            || target.space.0 != candidate.claim().space().0
            || target.binding.commitment().0 != candidate.claim().authority_binding().0
            || *context != RuntimeExecutionContext::Direct || !state.is_empty()
            || *observed_slot != preflight.observed_slot
            || invocation.invocation != committee_query_invocation(candidate)
            || invocation.recovery_only
            || !committee_query_matches(invocation, authorization, target)
            || self.work.encode().is_err()
        { return Err(GenesisIssuanceError::InvalidAuthority); }
        Ok(())
    }

    pub(crate) fn pledge<S: CleanManagementIssuerStore>(&self, store: &mut S,
        candidate: &AuthorizedSharedGenesisProposal,
        target: &crate::agent_sdk::authority::AuthorityActorTarget) -> Result<(), GenesisIssuanceError> {
        use crate::service::ServiceWire as _;
        self.validate_for(candidate, target)?;
        let bytes = self.encode();
        if bytes.len() > MAX_QUERY_BYTES { return Err(GenesisIssuanceError::Corrupt); }
        if store.load().map_err(|_| GenesisIssuanceError::Unavailable)?.is_some_and(|old| old != bytes) {
            return Err(GenesisIssuanceError::Conflict);
        }
        store.commit(&bytes).map_err(|_| GenesisIssuanceError::Unavailable)?;
        if store.load().map_err(|_| GenesisIssuanceError::Unavailable)?.as_deref() != Some(bytes.as_slice()) {
            return Err(GenesisIssuanceError::Corrupt);
        }
        Ok(())
    }

    pub(crate) fn load<S: CleanManagementIssuerStore>(store: &mut S, candidate: &AuthorizedSharedGenesisProposal,
        target: &crate::agent_sdk::authority::AuthorityActorTarget) -> Result<Option<Self>, GenesisIssuanceError> {
        use crate::service::ServiceWire as _;
        let Some(bytes) = store.load().map_err(|_| GenesisIssuanceError::Unavailable)? else { return Ok(None); };
        if bytes.len() > MAX_QUERY_BYTES { return Err(GenesisIssuanceError::Corrupt); }
        let record = Self::decode(&bytes).map_err(|_| GenesisIssuanceError::Corrupt)?;
        record.validate_for(candidate, target)?;
        record.pledge(store, candidate, target)?;
        Ok(Some(record))
    }
}

impl crate::service::ServiceWire for RetainedCommitteeQuery {
    const MAGIC: [u8; 4] = *b"GCW1";
    fn encode_body(&self, out: &mut Vec<u8>) {
        use crate::agent_sdk::wire::CanonicalWire as _;
        let mut encoder = crate::service::wire::Encoder(out);
        encoder.fixed(&self.candidate.0);
        encoder.fixed(self.authorization.as_bytes());
        encoder.bytes(&self.anchor.encode());
        encoder.bytes(&self.work.encode().unwrap_or_default());
    }
    fn decode_body(decoder: &mut crate::service::wire::Decoder<'_>) -> Result<Self, crate::service::wire::DecodeError> {
        use crate::agent_sdk::wire::CanonicalWire as _;
        use crate::service::wire::DecodeError as Error;
        if decoder.remaining() > MAX_QUERY_BYTES - 36 { return Err(Error::LimitExceeded); }
        let candidate = crate::service::Hash(decoder.fixed()?);
        let authorization = crate::agent_sdk::InvocationId(decoder.fixed()?);
        let anchor = decoder.bytes_ref()?;
        if anchor.len() > 256 { return Err(Error::LimitExceeded); }
        let anchor = crate::agent::clean_management_intent::ManagementJournalAnchor::decode(anchor)?;
        let work = decoder.bytes_ref()?;
        if work.len() > crate::agent_sdk::wire::MAX_RUNTIME_WORK_WIRE_BYTES { return Err(Error::LimitExceeded); }
        let work = crate::agent_sdk::RuntimeWork::decode(work).map_err(|_| Error::NonCanonical)?;
        Ok(Self { candidate, authorization, anchor, work })
    }
}

fn committee_query_matches(work: &crate::agent_sdk::InvocationWork,
    authorization: &crate::agent_sdk::InvocationAuthorization,
    target: &crate::agent_sdk::authority::AuthorityActorTarget) -> bool {
    use crate::actors::codec::Encode as _;
    let mut message = vec![crate::actors::value::TAG_DYNAMIC];
    message.extend(crate::actors::value::Msg::new("genesis_signing_committee").encode());
    target.binding.is_valid() && work.validate() && authorization.matches_work(work)
        && matches!(authorization, crate::agent_sdk::InvocationAuthorization::PublicPreflight(_))
        && work.mode == crate::agent_sdk::MethodMode::Query
        && work.space == target.space && work.agent == target.system_agent
        && work.runtime_deployment == target.system_runtime_deployment
        && work.actor == target.binding.issuer.actor && work.deployment == target.binding.issuer.deployment
        && work.program == target.binding.issuer.program && work.message == message
}

/// Classify a freshly replayed journal result for pending-capacity recovery.
/// This is not committee authority or evidence of reply-file durability.
pub(crate) fn is_committee_query_reply(work: &crate::agent_sdk::InvocationWork, reply: &[u8]) -> bool {
    use crate::actors::codec::{Decode as _, Encode as _};
    use crate::service::ServiceWire as _;
    if work.mode != crate::agent_sdk::MethodMode::Query
        || reply.len() > crate::agent::committee::MAX_AUTHORITY_COMMITTEE_WIRE_BYTES + 5
    { return false; }
    let mut message = vec![crate::actors::value::TAG_DYNAMIC];
    message.extend(crate::actors::value::Msg::new("genesis_signing_committee").encode());
    if work.message != message { return false; }
    let Some(crate::actors::value::Value::Bytes(bytes)) = crate::actors::value::Value::try_decode(reply) else { return false; };
    AuthorityCommittee::decode(&bytes).is_ok_and(|committee| committee.space().0 == work.space.0)
}

/// Retain a validated committee reply before its invocation is acknowledged.
/// The caller must obtain `reply` from authenticated execution, not a network
/// payload. This persistence boundary does not itself confer committee trust.
/// The exact work and authorization commitments prevent cross-query reuse.
pub(crate) fn retain_committee_reply<S: CleanManagementIssuerStore>(
    store: &mut S,
    work: &crate::agent_sdk::InvocationWork,
    authorization: &crate::agent_sdk::InvocationAuthorization,
    reply: &crate::agent_sdk::InvocationReply,
    target: &crate::agent_sdk::authority::AuthorityActorTarget,
) -> Result<AuthorityCommittee, GenesisIssuanceError> {
    use crate::actors::codec::Decode as _;
    use crate::service::ServiceWire as _;
    use GenesisIssuanceError as Error;
    if !committee_query_matches(work, authorization, target)
        || reply.invocation != work.invocation || reply.actor != work.actor
        || reply.incarnation != work.incarnation || reply.deployment != work.deployment
        || reply.mode != work.mode || reply.status != crate::agent_sdk::InvocationStatus::Done
    { return Err(Error::InvalidAuthority); }
    if reply.reply.len() > crate::agent::committee::MAX_AUTHORITY_COMMITTEE_WIRE_BYTES + 5 {
        return Err(Error::Corrupt);
    }
    let Some(crate::actors::value::Value::Bytes(bytes)) = crate::actors::value::Value::try_decode(&reply.reply) else {
        return Err(Error::Corrupt);
    };
    if bytes.len() > crate::agent::committee::MAX_AUTHORITY_COMMITTEE_WIRE_BYTES {
        return Err(Error::Corrupt);
    }
    let committee = AuthorityCommittee::decode(&bytes).map_err(|_| Error::Corrupt)?;
    if committee.space().0 != target.space.0 || committee.authority_binding().0 != target.binding.commitment().0 {
        return Err(Error::InvalidAuthority);
    }
    let mut retained = Vec::with_capacity(68 + bytes.len());
    retained.extend_from_slice(b"GCR1");
    retained.extend_from_slice(work.commitment().as_bytes());
    retained.extend_from_slice(authorization.commitment().as_bytes());
    retained.extend_from_slice(&bytes);
    if store.load().map_err(|_| Error::Unavailable)?.is_some_and(|previous| previous != retained) {
        return Err(Error::Conflict);
    }
    // Exact recommit finishes an ambiguous earlier publication before ACK.
    store.commit(&retained).map_err(|_| Error::Unavailable)?;
    if store.load().map_err(|_| Error::Unavailable)?.as_deref() != Some(retained.as_slice()) {
        return Err(Error::Corrupt);
    }
    Ok(committee)
}

/// Recover exact reply data after ACK without redispatching a consumed query.
/// The caller must independently reauthenticate the retained query/anchor;
/// an integrity-valid local file is not itself committee authority.
pub(crate) fn load_committee_reply<S: CleanManagementIssuerStore>(
    store: &mut S,
    work: &crate::agent_sdk::InvocationWork,
    authorization: &crate::agent_sdk::InvocationAuthorization,
    target: &crate::agent_sdk::authority::AuthorityActorTarget,
) -> Result<Option<AuthorityCommittee>, GenesisIssuanceError> {
    use crate::actors::codec::Encode as _;
    use GenesisIssuanceError as Error;
    let Some(bytes) = store.load().map_err(|_| Error::Unavailable)? else { return Ok(None); };
    if bytes.len() < 68 || bytes.len() > crate::agent::clean_authority_issuer::MAX_CLEAN_GENESIS_REPLY_IMAGE_BYTES
        || &bytes[..4] != b"GCR1"
    { return Err(Error::Corrupt); }
    if &bytes[4..36] != work.commitment().as_bytes()
        || &bytes[36..68] != authorization.commitment().as_bytes()
    { return Err(Error::Conflict); }
    let reply = crate::agent_sdk::InvocationReply {
        invocation: work.invocation, actor: work.actor, incarnation: work.incarnation,
        deployment: work.deployment, mode: work.mode, lane: None,
        status: crate::agent_sdk::InvocationStatus::Done,
        reply: crate::actors::value::Value::Bytes(bytes[68..].to_vec()).encode(),
        gas_remaining: 0, observation: Default::default(),
    };
    // Reuse route/schema checks and reestablish the exact durability barrier.
    retain_committee_reply(store, work, authorization, &reply, target).map(Some)
}

/// Classify a freshly replayed publication result for reservation recovery.
/// This neither authenticates stored reply files nor grants finality.
pub(crate) fn is_publication_reply(work: &crate::agent_sdk::InvocationWork, reply: &[u8]) -> bool {
    use crate::service::ServiceWire as _;
    use crate::actors::codec::Encode as _;
    if reply.len() > crate::agent::genesis::MAX_AGENT_GENESIS_DECISION_BYTES + 5 { return false; }
    let Some(blob) = work.availability.iter().find(|blob| publication_blob_matches(work, blob)) else { return false; };
    let Ok(provision) = crate::agent::genesis::AgentGenesisProvision::decode(&blob.bytes) else { return false; };
    reply == crate::actors::value::Value::Bytes(provision.decision().encode()).encode()
}

/// Persist an authenticated publication result before allowing its ACK. Exact
/// decision equality binds the reply to the durably selected archive; this is
/// not independently rooted finality or permission to release reservations.
pub(crate) fn retain_publication_reply<S: CleanManagementIssuerStore>(
    store: &mut S, pending: &RetainedGenesisPublication,
    candidate: &AuthorizedSharedGenesisProposal, committee: &AuthorityCommittee,
    record: &crate::agent::genesis::AgentGenesisArchiveRecord,
    target: &crate::agent_sdk::authority::AuthorityActorTarget,
    reply: &crate::agent_sdk::InvocationReply,
) -> Result<crate::agent::genesis::AgentGenesisDecision, GenesisIssuanceError> {
    use crate::service::ServiceWire as _;
    use crate::actors::codec::Encode as _;
    use GenesisIssuanceError as Error;
    pending.validate(candidate, committee, record, target)?;
    let crate::agent_sdk::RuntimeWork::Invoke { invocation: work, authorization, .. } = &pending.work else {
        return Err(Error::InvalidAuthority);
    };
    let decision = record.provision().decision();
    let bytes = decision.encode();
    if reply.invocation != work.invocation || reply.actor != work.actor
        || reply.incarnation != work.incarnation || reply.deployment != work.deployment
        || reply.mode != work.mode || reply.status != crate::agent_sdk::InvocationStatus::Done
        || reply.reply != crate::actors::value::Value::Bytes(bytes.clone()).encode()
    { return Err(Error::InvalidAuthority); }
    let mut retained = Vec::with_capacity(68 + bytes.len());
    retained.extend_from_slice(b"GPR1");
    retained.extend_from_slice(work.commitment().as_bytes());
    retained.extend_from_slice(authorization.commitment().as_bytes());
    retained.extend_from_slice(&bytes);
    if retained.len() > crate::agent::clean_authority_issuer::MAX_CLEAN_GENESIS_PUBLICATION_REPLY_IMAGE_BYTES {
        return Err(Error::Corrupt);
    }
    if store.load().map_err(|_| Error::Unavailable)?.is_some_and(|old| old != retained) {
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
    store: &mut S, pending: &RetainedGenesisPublication,
) -> Result<Option<crate::agent::genesis::AgentGenesisDecision>, GenesisIssuanceError> {
    use crate::service::ServiceWire as _;
    use crate::actors::codec::Encode as _;
    use GenesisIssuanceError as Error;
    let Some(bytes) = store.load().map_err(|_| Error::Unavailable)? else { return Ok(None); };
    if bytes.len() < 68 || bytes.len() > crate::agent::clean_authority_issuer::MAX_CLEAN_GENESIS_PUBLICATION_REPLY_IMAGE_BYTES
        || &bytes[..4] != b"GPR1" { return Err(Error::Corrupt); }
    let crate::agent_sdk::RuntimeWork::Invoke { invocation, authorization, .. } = &pending.work else {
        return Err(Error::InvalidAuthority);
    };
    if &bytes[4..36] != invocation.commitment().as_bytes()
        || &bytes[36..68] != authorization.commitment().as_bytes()
    { return Err(Error::Conflict); }
    let decision = crate::agent::genesis::AgentGenesisDecision::decode(&bytes[68..]).map_err(|_| Error::Corrupt)?;
    if !is_publication_reply(invocation, &crate::actors::value::Value::Bytes(bytes[68..].to_vec()).encode()) {
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
    use crate::agent::genesis::{AgentGenesisArchiveRecord, AgentGenesisDecision, AgentGenesisEvidence, AgentGenesisProvision};
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
    let certificate = AuthorityQuorumCertificate::new(
        committee, candidate.claim().authority_claim(), signatures,
    ).map_err(|_| Error::InvalidSignature)?;
    let evidence = AgentGenesisEvidence::new(candidate.claim().clone(), certificate)
        .map_err(|_| Error::InvalidSignature)?;
    evidence.verify_certificate(committee).map_err(|_| Error::InvalidSignature)?;
    let decision = AgentGenesisDecision::new(candidate.proposal(), candidate.replicas(), &evidence)
        .map_err(|_| Error::Corrupt)?;
    let provision = AgentGenesisProvision::new(
        candidate.proposal().clone(), candidate.replicas().clone(), evidence, decision,
    ).map_err(|_| Error::Corrupt)?;
    AgentGenesisArchiveRecord::new(provision, candidate.catalog().to_vec()).map_err(|_| Error::Corrupt)
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
        crate::agent::genesis::AgentGenesisProviderError::Unavailable => GenesisIssuanceError::Unavailable,
        crate::agent::genesis::AgentGenesisProviderError::Conflict => GenesisIssuanceError::Conflict,
        _ => GenesisIssuanceError::Corrupt,
    };
    let record = match archive.load_record(candidate.proposal().locator()).map_err(map_error)? {
        Some(record) => {
            let provision = record.provision();
            if provision.proposal() != candidate.proposal() || provision.replicas() != candidate.replicas()
                || provision.evidence().claim() != candidate.claim() || record.catalog() != candidate.catalog()
            { return Err(GenesisIssuanceError::Conflict); }
            provision.evidence().verify_certificate(committee).map_err(|_| GenesisIssuanceError::InvalidAuthority)?;
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
    const MAX_IMAGE_BYTES: usize = crate::agent::clean_authority_issuer::MAX_CLEAN_GENESIS_PUBLICATION_IMAGE_BYTES;

    /// Recover reservation data only. The caller must retain the store lease,
    /// reattach authenticated journal history, reproduce the candidate and
    /// validate against the independently authenticated committee before use.
    pub(crate) fn load_for_recovery<S: CleanManagementIssuerStore>(
        store: &mut S,
        target: &crate::agent_sdk::authority::AuthorityActorTarget,
        query: &RetainedCommitteeQuery,
    ) -> Result<Option<Self>, GenesisIssuanceError> {
        use crate::service::ServiceWire as _;
        use crate::agent_sdk::{RuntimeWork, RuntimeExecutionContext, InvocationAuthorization};
        let Some(bytes) = store.load().map_err(|_| GenesisIssuanceError::Unavailable)? else { return Ok(None); };
        if bytes.len() > Self::MAX_IMAGE_BYTES { return Err(GenesisIssuanceError::Corrupt); }
        let saved = Self::decode(&bytes).map_err(|_| GenesisIssuanceError::Corrupt)?;
        let RuntimeWork::Invoke { invocation: previous, authorization: previous_auth, .. } = &query.work else {
            return Err(GenesisIssuanceError::InvalidAuthority);
        };
        let RuntimeWork::Invoke { context, state, invocation, authorization, observed_slot } = &saved.work else {
            return Err(GenesisIssuanceError::InvalidAuthority);
        };
        let InvocationAuthorization::PublicPreflight(preflight) = authorization.as_ref() else {
            return Err(GenesisIssuanceError::InvalidAuthority);
        };
        let expected_query = crate::service::Hash::digest(b"vos/ordinary-genesis/committee-query/v1",
            &[query.candidate.as_bytes(), query.authorization.as_bytes()]);
        if !committee_query_matches(previous, previous_auth, target)
            || query.candidate == crate::service::Hash::ZERO || previous.invocation.0 != expected_query.0
            || saved.anchor.genesis != query.anchor.genesis || saved.anchor.admission != query.anchor.admission
            || saved.anchor.runtime != query.anchor.runtime || saved.anchor.runtime == crate::service::Hash::ZERO
            || query.anchor.ordered.validate().is_err() || saved.anchor.ordered.validate().is_err()
            || saved.anchor.ordered.index < query.anchor.ordered.index
            || *context != RuntimeExecutionContext::Direct || !state.is_empty()
            || !invocation.validate() || !preflight.matches_work(invocation)
            || *observed_slot != preflight.observed_slot
            || invocation.availability.len() != previous.availability.len() + 1
        { return Err(GenesisIssuanceError::InvalidAuthority); }
        let blob = invocation.availability.iter().find(|blob| publication_blob_matches(invocation, blob))
            .ok_or(GenesisIssuanceError::InvalidAuthority)?;
        let provision = crate::agent::genesis::AgentGenesisProvision::decode(&blob.bytes)
            .map_err(|_| GenesisIssuanceError::Corrupt)?;
        let claim = provision.evidence().claim();
        if claim.authority_claim().claim_hash() != query.candidate
            || claim.system_genesis() != saved.anchor.genesis || claim.system_admission() != saved.anchor.admission
            || claim.authority_binding().0 != target.binding.commitment().0
            || provision.publication_invocation(query.authorization).ok() != Some(invocation.invocation)
        { return Err(GenesisIssuanceError::InvalidAuthority); }
        // No origin, installation, artifact or other work field may drift from
        // the query used to select this publication's committee.
        let mut base = (**invocation).clone();
        base.mode = previous.mode;
        base.invocation = previous.invocation;
        base.message = previous.message.clone();
        base.availability.retain(|entry| entry.reference != blob.reference);
        if &base != previous.as_ref() { return Err(GenesisIssuanceError::InvalidAuthority); }
        store.commit(&bytes).map_err(|_| GenesisIssuanceError::Unavailable)?;
        if store.load().map_err(|_| GenesisIssuanceError::Unavailable)?.as_deref() != Some(bytes.as_slice()) {
            return Err(GenesisIssuanceError::Corrupt);
        }
        Ok(Some(saved))
    }
    pub(crate) fn validate(&self, candidate: &AuthorizedSharedGenesisProposal, committee: &AuthorityCommittee,
        record: &crate::agent::genesis::AgentGenesisArchiveRecord,
        target: &crate::agent_sdk::authority::AuthorityActorTarget) -> Result<(), GenesisIssuanceError> {
        use crate::agent_sdk::wire::CanonicalWire as _;
        use crate::agent_sdk::{RuntimeWork, RuntimeExecutionContext, InvocationAuthorization};
        let expected = publication_input(candidate, committee, record)?;
        let RuntimeWork::Invoke { context, state, invocation, authorization, observed_slot } = &self.work else {
            return Err(GenesisIssuanceError::InvalidAuthority);
        };
        let InvocationAuthorization::PublicPreflight(preflight) = authorization.as_ref() else {
            return Err(GenesisIssuanceError::InvalidAuthority);
        };
        if !target.binding.is_valid() || target.binding.commitment().0 != candidate.claim().authority_binding().0
            || target.space.0 != candidate.claim().space().0 || target.system_agent.0 != candidate.claim().system_agent().0
            || self.anchor.genesis != candidate.claim().system_genesis() || self.anchor.admission != candidate.claim().system_admission()
            || self.anchor.runtime == crate::service::Hash::ZERO || self.anchor.ordered.validate().is_err()
            || *context != RuntimeExecutionContext::Direct || !state.is_empty()
            || invocation.space != target.space || invocation.agent != target.system_agent
            || invocation.runtime_deployment != target.system_runtime_deployment
            || invocation.actor != target.binding.issuer.actor || invocation.deployment != target.binding.issuer.deployment
            || invocation.program != target.binding.issuer.program
            || invocation.invocation != expected.invocation || invocation.message != expected.message
            || !invocation.availability.contains(&expected.provision)
            || !publication_blob_matches(invocation, &expected.provision)
            || !invocation.validate() || !preflight.matches_work(invocation) || *observed_slot != preflight.observed_slot
            || self.work.encode().is_err()
        { return Err(GenesisIssuanceError::InvalidAuthority); }
        Ok(())
    }

    pub(crate) fn pledge<S: CleanManagementIssuerStore>(&self, store: &mut S, candidate: &AuthorizedSharedGenesisProposal,
        committee: &AuthorityCommittee, record: &crate::agent::genesis::AgentGenesisArchiveRecord,
        target: &crate::agent_sdk::authority::AuthorityActorTarget) -> Result<(), GenesisIssuanceError> {
        use crate::service::ServiceWire as _;
        self.validate(candidate, committee, record, target)?;
        let bytes = self.encode();
        if bytes.len() > Self::MAX_IMAGE_BYTES { return Err(GenesisIssuanceError::Corrupt); }
        if store.load().map_err(|_| GenesisIssuanceError::Unavailable)?.is_some_and(|old| old != bytes) {
            return Err(GenesisIssuanceError::Conflict);
        }
        store.commit(&bytes).map_err(|_| GenesisIssuanceError::Unavailable)?;
        if store.load().map_err(|_| GenesisIssuanceError::Unavailable)?.as_deref() != Some(bytes.as_slice()) {
            return Err(GenesisIssuanceError::Corrupt);
        }
        Ok(())
    }

    pub(crate) fn load<S: CleanManagementIssuerStore>(store: &mut S, candidate: &AuthorizedSharedGenesisProposal,
        committee: &AuthorityCommittee, record: &crate::agent::genesis::AgentGenesisArchiveRecord,
        target: &crate::agent_sdk::authority::AuthorityActorTarget) -> Result<Option<Self>, GenesisIssuanceError> {
        use crate::service::ServiceWire as _;
        let Some(bytes) = store.load().map_err(|_| GenesisIssuanceError::Unavailable)? else { return Ok(None); };
        if bytes.len() > Self::MAX_IMAGE_BYTES { return Err(GenesisIssuanceError::Corrupt); }
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
    fn decode_body(decoder: &mut crate::service::wire::Decoder<'_>) -> Result<Self, crate::service::wire::DecodeError> {
        use crate::agent_sdk::wire::CanonicalWire as _;
        use crate::service::wire::DecodeError as Error;
        if decoder.remaining() > Self::MAX_IMAGE_BYTES - 36 { return Err(Error::LimitExceeded); }
        let anchor = decoder.bytes_ref()?;
        if anchor.len() > 256 { return Err(Error::LimitExceeded); }
        let anchor = crate::agent::clean_management_intent::ManagementJournalAnchor::decode(anchor)?;
        let work = decoder.bytes_ref()?;
        if work.len() > crate::agent_sdk::wire::MAX_RUNTIME_WORK_WIRE_BYTES { return Err(Error::LimitExceeded); }
        let work = crate::agent_sdk::RuntimeWork::decode(work).map_err(|_| Error::NonCanonical)?;
        Ok(Self { anchor, work })
    }
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
    use crate::actors::value::{Msg, Value, TAG_DYNAMIC};
    use crate::service::ServiceWire as _;
    let provision = record.provision();
    if provision.proposal() != candidate.proposal() || provision.replicas() != candidate.replicas()
        || provision.evidence().claim() != candidate.claim() || record.catalog() != candidate.catalog()
    { return Err(GenesisIssuanceError::Conflict); }
    provision.evidence().verify_certificate(committee).map_err(|_| GenesisIssuanceError::InvalidAuthority)?;
    let bytes = provision.encode();
    if bytes.len() > crate::agent::genesis::MAX_CLEAN_CREATE_GENESIS_PROVISION_BYTES
        || bytes.len() > crate::agent::execution::MAX_EXECUTION_AVAILABILITY_BYTES
    { return Err(GenesisIssuanceError::Corrupt); }
    let reference = crate::agent_sdk::BlobRef::of_bytes(&bytes);
    let invocation = provision.publication_invocation(candidate.authorization()).map_err(|_| GenesisIssuanceError::Corrupt)?;
    let mut message = vec![TAG_DYNAMIC];
    message.extend(Msg::new("publish_genesis")
        .with("authorization", Value::Bytes(candidate.authorization().0.to_vec()))
        .with("provision_hash", Value::Bytes(reference.hash.0.to_vec()))
        .with("provision_len", Value::U64(reference.len)).encode());
    Ok(GenesisPublicationInput { invocation, message,
        provision: crate::agent_sdk::RuntimeBlob { reference, bytes } })
}

/// Validate the single extra caller blob permitted by genesis publication.
/// This binds transport data only; the Authority actor still checks the pending
/// authorization and QC, and the coordinator still authenticates its anchor.
pub(crate) fn publication_blob_matches(work: &crate::agent_sdk::InvocationWork, blob: &crate::agent_sdk::RuntimeBlob) -> bool {
    use crate::actors::codec::{Decode as _, Encode as _};
    use crate::actors::value::{Msg, Value, TAG_DYNAMIC};
    use crate::service::ServiceWire as _;
    if work.mode != crate::agent_sdk::MethodMode::Linear || work.recovery_only
        || work.message.first() != Some(&TAG_DYNAMIC) || !blob.validate()
        || blob.bytes.len() > crate::agent::genesis::MAX_CLEAN_CREATE_GENESIS_PROVISION_BYTES
        || blob.bytes.len() > crate::agent::execution::MAX_EXECUTION_AVAILABILITY_BYTES
    { return false; }
    let Some(message) = Msg::try_decode(&work.message[1..]) else { return false; };
    let Some(Value::Bytes(authorization)) = message.args.get("authorization") else { return false; };
    let Ok(authorization) = <[u8; 32]>::try_from(authorization.as_slice()) else { return false; };
    let authorization = crate::agent_sdk::InvocationId(authorization);
    let Ok(provision) = crate::agent::genesis::AgentGenesisProvision::decode(&blob.bytes) else { return false; };
    if provision.publication_invocation(authorization).ok() != Some(work.invocation)
        || provision.evidence().claim().space().0 != work.space.0
        || provision.evidence().claim().system_agent().0 != work.agent.0
    { return false; }
    let mut expected = vec![TAG_DYNAMIC];
    expected.extend(Msg::new("publish_genesis")
        .with("authorization", Value::Bytes(authorization.0.to_vec()))
        .with("provision_hash", Value::Bytes(blob.reference.hash.0.to_vec()))
        .with("provision_len", Value::U64(blob.reference.len)).encode());
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
        committee.authority_binding(), committee.epoch(), committee.commitment(),
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
        if bytes[..PLEDGE_BYTES] != pledge { return Err(Error::Conflict); }
        if bytes.len() == MAX_GENESIS_SIGNATURE_IMAGE_BYTES {
            let signature: [u8; 64] = bytes[PLEDGE_BYTES..].try_into().map_err(|_| Error::Corrupt)?;
            if !verify_raw_ed25519(&public, &message.0, &signature) { return Err(Error::Corrupt); }
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
    let signature = signer.sign_genesis_claim(&message.0).map_err(|_| Error::Unavailable)?;
    if !verify_raw_ed25519(&public, &message.0, &signature) { return Err(Error::InvalidSignature); }
    pledge.extend_from_slice(&signature);
    store.commit(&pledge).map_err(|_| Error::Unavailable)?;
    if store.load().map_err(|_| Error::Unavailable)?.as_deref() != Some(pledge.as_slice()) {
        return Err(Error::Corrupt);
    }
    AuthoritySignature::new(signer_id, signature).map_err(|_| Error::InvalidSignature)
}
