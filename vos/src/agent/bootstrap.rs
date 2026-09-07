//! Independently provisioned bootstrap for the first system Agent.
//!
//! The provider boundary is deliberately an archive, not merely a signer.
//! A successful [`SystemAgentGenesisProvider::create`] must make the exact
//! proposal, evidence, and catalog bytes durable before returning. Restart
//! uses [`SystemAgentGenesisProvider::reproduce`], which is strictly read-only
//! and must never mint replacement evidence. This lets filesystem recovery
//! reproduce the complete sealed capability before `open_reverified` admits
//! an initialized journal. Pins nested in the archived provision are
//! reproducibility data, never a trust source: sealing separately requires the
//! operator-configured [`RootAnchorPins`] and exact-compares the archived copy.

use alloc::vec::Vec;
use core::fmt;

use super::committee::{
    AuthorityCommitteeError, MAX_ROOT_ANCHOR_PINS_BYTES, MAX_SYSTEM_GENESIS_EVIDENCE_BYTES,
    RootAnchorPins, SystemAgentGenesisClaim, SystemAgentGenesisEvidence,
    SystemAgentGenesisExpectations,
};
use super::execution::RuntimeBlob;
use super::journal::{
    CanonicalJournalRecord, MAX_ARTIFACT_CLOSURE_BYTES, MAX_REPLAY_INPUT_BYTES, ReplayInput,
    ReplayOperation, system_genesis_artifact_closure_commitment,
};
use super::replay::{ReplayPreparedGenesis, ReplaySealedGenesis};
use super::{AgentReplica, ReplicaRole};
use crate::service::wire::{DecodeError, Decoder, Encoder, ServiceWire};
use crate::service::{AgentId, BlobRef, Hash, NodeId, PrincipalId, SpaceId};

const SERVICE_WIRE_HEADER_BYTES: usize = 4 + 32;
const SYSTEM_GENESIS_CATALOG_REFERENCES: usize = 1;
const SYSTEM_AGENT_GENESIS_LOCATOR_BYTES: usize = SERVICE_WIRE_HEADER_BYTES + 3 * 32;
const SYSTEM_AGENT_GENESIS_REPLICA_BYTES: usize = 2 * 32 + 1;
const SYSTEM_AGENT_GENESIS_EXPECTATIONS_BYTES: usize = 4 * 32 + 8;
const BLOB_REFERENCE_BYTES: usize = 32 + 8;

/// Maximum canonical provider proposal. The exact Create input dominates;
/// the remaining fields are fixed-size expectations and one runtime package
/// reference.
pub const MAX_SYSTEM_AGENT_GENESIS_PROPOSAL_BYTES: usize = SERVICE_WIRE_HEADER_BYTES
    + 4
    + SYSTEM_AGENT_GENESIS_LOCATOR_BYTES
    + 4
    + MAX_REPLAY_INPUT_BYTES
    + SYSTEM_AGENT_GENESIS_REPLICA_BYTES
    + SYSTEM_AGENT_GENESIS_EXPECTATIONS_BYTES
    + 4
    + BLOB_REFERENCE_BYTES;
/// Maximum canonical archived provision. Raw catalog bytes are fetched by
/// content reference and are never nested in this envelope.
pub const MAX_SYSTEM_AGENT_GENESIS_PROVISION_BYTES: usize = SERVICE_WIRE_HEADER_BYTES
    + 4
    + MAX_SYSTEM_AGENT_GENESIS_PROPOSAL_BYTES
    + 4
    + MAX_ROOT_ANCHOR_PINS_BYTES
    + 4
    + MAX_SYSTEM_GENESIS_EVIDENCE_BYTES;

/// Stable out-of-band archive key for one clean system-Agent genesis. The
/// node is the exact physical replica selected by the one-voter Shared root.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SystemAgentGenesisLocator {
    pub space: SpaceId,
    pub agent: AgentId,
    pub node: NodeId,
}

impl SystemAgentGenesisLocator {
    pub fn validate(self) -> Result<(), SystemAgentGenesisBootstrapError> {
        if self.space == SpaceId::ZERO || self.agent == AgentId::ZERO || self.node == NodeId::ZERO {
            Err(SystemAgentGenesisBootstrapError::InvalidLocator)
        } else {
            Ok(())
        }
    }
}

impl ServiceWire for SystemAgentGenesisLocator {
    const MAGIC: [u8; 4] = *b"AGGL";

    fn encode_body(&self, output: &mut Vec<u8>) {
        let mut encoder = Encoder(output);
        encoder.fixed(&self.space.0);
        encoder.fixed(&self.agent.0);
        encoder.fixed(&self.node.0);
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let locator = Self {
            space: SpaceId(decoder.fixed()?),
            agent: AgentId(decoder.fixed()?),
            node: NodeId(decoder.fixed()?),
        };
        locator.validate().map_err(|_| DecodeError::NonCanonical)?;
        Ok(locator)
    }
}

/// Exact genesis-free Create result proposed to the durable authority
/// archive. Output commitments are replay-derived, never provider-selected.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SystemAgentGenesisProposal {
    locator: SystemAgentGenesisLocator,
    create: ReplayInput,
    replica: AgentReplica,
    expectations: SystemAgentGenesisExpectations,
    catalog: Vec<BlobRef>,
}

impl SystemAgentGenesisProposal {
    pub(crate) fn from_prepared(
        locator: SystemAgentGenesisLocator,
        prepared: &ReplayPreparedGenesis,
    ) -> Result<Self, SystemAgentGenesisBootstrapError> {
        let proposal = Self {
            locator,
            create: prepared.create().clone(),
            replica: prepared.replica(),
            expectations: prepared.expectations(),
            catalog: prepared.artifacts().to_vec(),
        };
        proposal.validate()?;
        Ok(proposal)
    }

    pub const fn locator(&self) -> SystemAgentGenesisLocator {
        self.locator
    }

    pub const fn create(&self) -> &ReplayInput {
        &self.create
    }

    pub const fn replica(&self) -> AgentReplica {
        self.replica
    }

    pub const fn expectations(&self) -> SystemAgentGenesisExpectations {
        self.expectations
    }

    pub fn catalog(&self) -> &[BlobRef] {
        &self.catalog
    }

    pub fn validate(&self) -> Result<(), SystemAgentGenesisBootstrapError> {
        self.locator.validate()?;
        self.create
            .validate()
            .map_err(|_| SystemAgentGenesisBootstrapError::InvalidProposal)?;
        let (descriptor, request, sequence) =
            system_create(&self.create).ok_or(SystemAgentGenesisBootstrapError::InvalidProposal)?;
        if self.create.runtime.space != self.locator.space
            || self.create.runtime.agent != self.locator.agent
            || self.replica.node != self.locator.node
            || !descriptor_matches_root_replica(descriptor, self.replica)
            || self.expectations.runtime_binding() != self.create.runtime.commitment()
            || self.expectations.inner_create_request() != Hash(request.commitment().0)
            || self.expectations.sequence() != sequence
            || self.catalog.as_slice() != [self.create.runtime.package.clone()]
            || system_genesis_artifact_closure_commitment(&self.catalog)
                .map_err(|_| SystemAgentGenesisBootstrapError::InvalidCatalog)?
                != self.expectations.artifact_closure()
        {
            return Err(SystemAgentGenesisBootstrapError::InvalidProposal);
        }
        if self.encode().len() > MAX_SYSTEM_AGENT_GENESIS_PROPOSAL_BYTES {
            return Err(SystemAgentGenesisBootstrapError::LimitExceeded);
        }
        Ok(())
    }
}

impl ServiceWire for SystemAgentGenesisProposal {
    const MAGIC: [u8; 4] = *b"AGGP";

    fn encode_body(&self, output: &mut Vec<u8>) {
        let mut encoder = Encoder(output);
        encoder.bytes(&self.locator.encode());
        encoder.bytes(&self.create.encode());
        encode_replica(&mut encoder, self.replica);
        encode_expectations(&mut encoder, self.expectations);
        encoder.list(&self.catalog, encode_blob_ref);
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        enforce_complete_bound(decoder, MAX_SYSTEM_AGENT_GENESIS_PROPOSAL_BYTES)?;
        let locator = decode_nested::<SystemAgentGenesisLocator>(
            decoder,
            SYSTEM_AGENT_GENESIS_LOCATOR_BYTES,
        )?;
        let create = decode_nested::<ReplayInput>(decoder, MAX_REPLAY_INPUT_BYTES)?;
        let proposal = Self {
            locator,
            create,
            replica: decode_replica(decoder)?,
            expectations: decode_expectations(decoder)?,
            catalog: {
                if decoder.u32()? as usize != SYSTEM_GENESIS_CATALOG_REFERENCES {
                    return Err(DecodeError::NonCanonical);
                }
                let mut catalog = Vec::new();
                catalog
                    .try_reserve_exact(SYSTEM_GENESIS_CATALOG_REFERENCES)
                    .map_err(|_| DecodeError::LimitExceeded)?;
                catalog.push(decode_blob_ref(decoder)?);
                catalog
            },
        };
        proposal.validate().map_err(map_decode_error)?;
        Ok(proposal)
    }
}

/// Complete bounded authority material returned by the durable provider.
/// Admission records and journal genesis IDs are intentionally absent: both
/// are derived only after exact replay and root/QC verification.
///
/// [`Self::validate`] proves that this envelope is internally consistent. It
/// does not trust the nested root; sealing independently supplies configured
/// [`RootAnchorPins`] and requires this archived copy to match exactly.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SystemAgentGenesisProvision {
    proposal: SystemAgentGenesisProposal,
    root: RootAnchorPins,
    evidence: SystemAgentGenesisEvidence,
}

impl SystemAgentGenesisProvision {
    pub fn new(
        proposal: SystemAgentGenesisProposal,
        root: RootAnchorPins,
        evidence: SystemAgentGenesisEvidence,
    ) -> Result<Self, SystemAgentGenesisBootstrapError> {
        let provision = Self {
            proposal,
            root,
            evidence,
        };
        provision.validate()?;
        Ok(provision)
    }

    pub const fn proposal(&self) -> &SystemAgentGenesisProposal {
        &self.proposal
    }

    pub const fn root(&self) -> &RootAnchorPins {
        &self.root
    }

    pub const fn evidence(&self) -> &SystemAgentGenesisEvidence {
        &self.evidence
    }

    pub fn validate(&self) -> Result<(), SystemAgentGenesisBootstrapError> {
        self.proposal.validate()?;
        self.root
            .validate()
            .map_err(SystemAgentGenesisBootstrapError::Authority)?;
        self.evidence
            .validate()
            .map_err(SystemAgentGenesisBootstrapError::Authority)?;
        let (descriptor, _, _) = system_create(&self.proposal.create)
            .ok_or(SystemAgentGenesisBootstrapError::InvalidProvision)?;
        let claim = SystemAgentGenesisClaim::new(self.root.record(), self.proposal.expectations)
            .map_err(SystemAgentGenesisBootstrapError::Authority)?;
        if self.root.record().space() != self.proposal.locator.space
            || self.root.record().system_agent() != self.proposal.locator.agent
            || self.root.record().authority_binding() != Hash(descriptor.authority.commitment().0)
            || self.root.genesis_claim() != claim.authority_claim()
            || self.evidence.claim() != &claim
            || self
                .evidence
                .certificate()
                .verify(
                    self.root.record().initial_committee(),
                    claim.authority_claim(),
                )
                .is_err()
        {
            return Err(SystemAgentGenesisBootstrapError::InvalidProvision);
        }
        if self.encode().len() > MAX_SYSTEM_AGENT_GENESIS_PROVISION_BYTES {
            return Err(SystemAgentGenesisBootstrapError::LimitExceeded);
        }
        Ok(())
    }
}

impl ServiceWire for SystemAgentGenesisProvision {
    const MAGIC: [u8; 4] = *b"AGGV";

    fn encode_body(&self, output: &mut Vec<u8>) {
        let mut encoder = Encoder(output);
        encoder.bytes(&self.proposal.encode());
        encoder.bytes(&self.root.encode());
        encoder.bytes(&self.evidence.encode());
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        enforce_complete_bound(decoder, MAX_SYSTEM_AGENT_GENESIS_PROVISION_BYTES)?;
        let provision = Self {
            proposal: decode_nested::<SystemAgentGenesisProposal>(
                decoder,
                MAX_SYSTEM_AGENT_GENESIS_PROPOSAL_BYTES,
            )?,
            root: decode_nested::<RootAnchorPins>(decoder, MAX_ROOT_ANCHOR_PINS_BYTES)?,
            evidence: decode_nested::<SystemAgentGenesisEvidence>(
                decoder,
                MAX_SYSTEM_GENESIS_EVIDENCE_BYTES,
            )?,
        };
        provision.validate().map_err(map_decode_error)?;
        Ok(provision)
    }
}

/// Bounded provider failures. Availability remains distinguishable from a
/// deterministic denial or an exact-create conflict.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SystemAgentGenesisProviderError {
    Unavailable,
    NotConfigured,
    Refused,
    Conflict,
    Corrupt,
}

impl fmt::Display for SystemAgentGenesisProviderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "system-Agent genesis provider: {self:?}")
    }
}

impl core::error::Error for SystemAgentGenesisProviderError {}

/// Durable external archive and authority boundary for first-system genesis.
pub trait SystemAgentGenesisProvider: Send + Sync {
    /// Certify and durably archive one exact proposal and its catalog. An
    /// exact retry returns the byte-identical provision; a divergent proposal
    /// for the same locator returns [`SystemAgentGenesisProviderError::Conflict`].
    fn create(
        &self,
        proposal: &SystemAgentGenesisProposal,
        catalog: &[RuntimeBlob],
    ) -> Result<SystemAgentGenesisProvision, SystemAgentGenesisProviderError>;

    /// Read the previously archived provision. This operation must never
    /// issue, replace, or re-sign authority evidence.
    fn reproduce(
        &self,
        locator: SystemAgentGenesisLocator,
    ) -> Result<SystemAgentGenesisProvision, SystemAgentGenesisProviderError>;

    /// Read one archived content-addressed catalog preimage.
    fn load_catalog(
        &self,
        locator: SystemAgentGenesisLocator,
        reference: &BlobRef,
    ) -> Result<Option<Vec<u8>>, SystemAgentGenesisProviderError>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SystemAgentGenesisBootstrapError {
    InvalidLocator,
    InvalidProposal,
    InvalidProvision,
    InvalidCatalog,
    InvalidPreparedSeal,
    LimitExceeded,
    Authority(AuthorityCommitteeError),
}

impl fmt::Display for SystemAgentGenesisBootstrapError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "system-Agent genesis bootstrap: {self:?}")
    }
}

impl core::error::Error for SystemAgentGenesisBootstrapError {}

/// Verify a provider response against independently configured root pins and
/// the exact replay-prepared token, then mint the otherwise unforgeable
/// journal bootstrap closure.
///
/// `configured_root` must originate outside the provider archive. The pins
/// nested in `provision` are retained for exact reproduction only and cannot
/// select the root or committee trusted by this operation.
pub(crate) fn seal_prepared_system_agent_genesis(
    prepared: ReplayPreparedGenesis,
    configured_root: &RootAnchorPins,
    provision: &SystemAgentGenesisProvision,
) -> Result<ReplaySealedGenesis, SystemAgentGenesisBootstrapError> {
    validate_prepared_system_agent_genesis_root(&prepared, configured_root)?;
    if &provision.root != configured_root {
        return Err(SystemAgentGenesisBootstrapError::InvalidProvision);
    }
    provision.validate()?;
    let expected =
        SystemAgentGenesisProposal::from_prepared(provision.proposal.locator, &prepared)?;
    if expected != provision.proposal {
        return Err(SystemAgentGenesisBootstrapError::InvalidProvision);
    }
    let claim = SystemAgentGenesisClaim::new(configured_root.record(), prepared.expectations())
        .map_err(SystemAgentGenesisBootstrapError::Authority)?;
    let trusted = configured_root
        .verify_claim(claim.authority_claim())
        .map_err(SystemAgentGenesisBootstrapError::Authority)?;
    let verified = provision
        .evidence
        .verify(&trusted, prepared.expectations())
        .map_err(SystemAgentGenesisBootstrapError::Authority)?;
    ReplaySealedGenesis::from_prepared_verified(&verified, provision.evidence.clone(), prepared)
        .map_err(|_| SystemAgentGenesisBootstrapError::InvalidPreparedSeal)
}

/// Exact root-marker preflight for the replay-prepared Create.
///
/// Provider-miss callers must invoke this after replay preparation and before
/// proposing or archiving anything. Sealing repeats it so alternate callers
/// cannot bypass the independently configured record, exact Create receipt
/// sequence, or root-system-Agent identity checks.
pub(crate) fn validate_prepared_system_agent_genesis_root(
    prepared: &ReplayPreparedGenesis,
    configured_root: &RootAnchorPins,
) -> Result<(), SystemAgentGenesisBootstrapError> {
    configured_root
        .validate()
        .map_err(SystemAgentGenesisBootstrapError::Authority)?;
    let (descriptor, _, _) = system_create(prepared.create())
        .ok_or(SystemAgentGenesisBootstrapError::InvalidPreparedSeal)?;
    if descriptor.identity.profile != crate::agent_sdk::AgentProfile::Shared
        || descriptor.replicas.len() != 1
        || !descriptor_matches_root_replica(descriptor, prepared.replica())
        || configured_root.record().space() != SpaceId(descriptor.identity.space.0)
        || configured_root.record().system_agent() != AgentId(descriptor.identity.agent.0)
        || configured_root.record().authority_binding() != Hash(descriptor.authority.commitment().0)
    {
        return Err(SystemAgentGenesisBootstrapError::InvalidPreparedSeal);
    }
    let claim = SystemAgentGenesisClaim::new(configured_root.record(), prepared.expectations())
        .map_err(SystemAgentGenesisBootstrapError::Authority)?;
    configured_root
        .verify_claim(claim.authority_claim())
        .map(|_| ())
        .map_err(SystemAgentGenesisBootstrapError::Authority)
}

/// Validate the raw bytes passed to provider `create` or returned through its
/// archive. System genesis has one exact runtime-package preimage.
pub fn validate_system_agent_genesis_catalog(
    proposal: &SystemAgentGenesisProposal,
    catalog: &[RuntimeBlob],
) -> Result<(), SystemAgentGenesisBootstrapError> {
    proposal.validate()?;
    if catalog.len() != SYSTEM_GENESIS_CATALOG_REFERENCES || catalog.len() != proposal.catalog.len()
    {
        return Err(SystemAgentGenesisBootstrapError::InvalidCatalog);
    }
    for (blob, expected) in catalog.iter().zip(&proposal.catalog) {
        if &blob.reference != expected
            || blob.bytes.len() > MAX_ARTIFACT_CLOSURE_BYTES
            || !blob.reference.matches(&blob.bytes)
        {
            return Err(SystemAgentGenesisBootstrapError::InvalidCatalog);
        }
    }
    Ok(())
}

fn system_create(
    create: &ReplayInput,
) -> Option<(
    &crate::agent_sdk::AgentDescriptor,
    &crate::agent_sdk::ManagementRequest,
    u64,
)> {
    let ReplayOperation::CleanManage {
        request, authority, ..
    } = &create.operation
    else {
        return None;
    };
    let crate::agent_sdk::ManagementRequest::Create(descriptor) = request else {
        return None;
    };
    Some((descriptor, request, authority.selector.decision_sequence))
}

fn descriptor_matches_root_replica(
    descriptor: &crate::agent_sdk::AgentDescriptor,
    replica: AgentReplica,
) -> bool {
    let [candidate] = descriptor.replicas.as_slice() else {
        return false;
    };
    descriptor.identity.profile == crate::agent_sdk::AgentProfile::Shared
        && candidate.node.0 == replica.node.0
        && candidate.principal.0 == replica.principal.0
        && matches!(
            (candidate.role, replica.role),
            (
                crate::agent_sdk::ReplicaRole::Voter,
                super::ReplicaRole::Voter
            )
        )
}

fn encode_replica(encoder: &mut Encoder<'_>, replica: AgentReplica) {
    encoder.fixed(&replica.node.0);
    encoder.fixed(&replica.principal.0);
    encoder.u8(replica.role as u8);
}

fn decode_replica(decoder: &mut Decoder<'_>) -> Result<AgentReplica, DecodeError> {
    Ok(AgentReplica {
        node: NodeId(decoder.fixed()?),
        principal: PrincipalId(decoder.fixed()?),
        role: match decoder.u8()? {
            0 => ReplicaRole::Voter,
            1 => ReplicaRole::Observer,
            _ => return Err(DecodeError::InvalidTag),
        },
    })
}

fn encode_expectations(encoder: &mut Encoder<'_>, expectations: SystemAgentGenesisExpectations) {
    encoder.fixed(&expectations.runtime_binding().0);
    encoder.fixed(&expectations.inner_create_request().0);
    encoder.fixed(&expectations.post_create_state().0);
    encoder.fixed(&expectations.artifact_closure().0);
    encoder.u64(expectations.sequence());
}

fn decode_expectations(
    decoder: &mut Decoder<'_>,
) -> Result<SystemAgentGenesisExpectations, DecodeError> {
    SystemAgentGenesisExpectations::new(
        crate::service::Hash(decoder.fixed()?),
        crate::service::Hash(decoder.fixed()?),
        crate::service::Hash(decoder.fixed()?),
        crate::service::Hash(decoder.fixed()?),
        decoder.u64()?,
    )
    .map_err(|_| DecodeError::NonCanonical)
}

fn encode_blob_ref(encoder: &mut Encoder<'_>, reference: &BlobRef) {
    encoder.fixed(&reference.hash.0);
    encoder.u64(reference.len);
}

fn decode_blob_ref(decoder: &mut Decoder<'_>) -> Result<BlobRef, DecodeError> {
    Ok(BlobRef {
        hash: crate::service::Hash(decoder.fixed()?),
        len: decoder.u64()?,
    })
}

fn decode_nested<T: ServiceWire>(
    decoder: &mut Decoder<'_>,
    maximum: usize,
) -> Result<T, DecodeError> {
    let bytes = decoder.bytes_ref()?;
    if bytes.len() > maximum {
        return Err(DecodeError::LimitExceeded);
    }
    T::decode(bytes)
}

fn enforce_complete_bound(decoder: &Decoder<'_>, maximum: usize) -> Result<(), DecodeError> {
    let body = maximum
        .checked_sub(SERVICE_WIRE_HEADER_BYTES)
        .ok_or(DecodeError::LimitExceeded)?;
    if decoder.remaining() > body {
        Err(DecodeError::LimitExceeded)
    } else {
        Ok(())
    }
}

fn map_decode_error(error: SystemAgentGenesisBootstrapError) -> DecodeError {
    match error {
        SystemAgentGenesisBootstrapError::LimitExceeded => DecodeError::LimitExceeded,
        _ => DecodeError::NonCanonical,
    }
}
