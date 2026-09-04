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
use super::{AgentReplica, LifecycleRequest, ReplicaRole};
use crate::service::wire::{DecodeError, Decoder, Encoder, ServiceWire};
use crate::service::{AgentId, BlobRef, NodeId, PrincipalId, SpaceId};

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

/// Stable out-of-band archive key for one Local system-Agent genesis.
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
        let config =
            create_config(&self.create).ok_or(SystemAgentGenesisBootstrapError::InvalidProposal)?;
        if self.create.runtime.space != self.locator.space
            || self.create.runtime.agent != self.locator.agent
            || self.replica.node != self.locator.node
            || config.identity.profile != super::AgentProfile::Local
            || config.replicas.as_slice() != [self.replica]
            || self.expectations.runtime_binding() != self.create.runtime.commitment()
            || self.expectations.inner_create_request()
                != match &self.create.operation {
                    ReplayOperation::Management {
                        request: LifecycleRequest::Authorized { request, .. },
                    } => request.commitment(),
                    _ => return Err(SystemAgentGenesisBootstrapError::InvalidProposal),
                }
            || self.expectations.sequence()
                != match &self.create.operation {
                    ReplayOperation::Management {
                        request: LifecycleRequest::Authorized { admission, .. },
                    } => admission.receipt.claim.sequence,
                    _ => return Err(SystemAgentGenesisBootstrapError::InvalidProposal),
                }
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
        let config = create_config(&self.proposal.create)
            .ok_or(SystemAgentGenesisBootstrapError::InvalidProvision)?;
        let claim = SystemAgentGenesisClaim::new(self.root.record(), self.proposal.expectations)
            .map_err(SystemAgentGenesisBootstrapError::Authority)?;
        if self.root.record().space() != self.proposal.locator.space
            || self.root.record().system_agent() != self.proposal.locator.agent
            || self.root.record().authority_binding() != config.authority.commitment()
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
    let config = create_config(prepared.create())
        .ok_or(SystemAgentGenesisBootstrapError::InvalidPreparedSeal)?;
    let genesis = config
        .system_authority_genesis
        .as_ref()
        .ok_or(SystemAgentGenesisBootstrapError::InvalidPreparedSeal)?;
    genesis
        .validate_root_config(
            configured_root.record(),
            config,
            prepared.expectations().sequence(),
        )
        .map_err(|_| SystemAgentGenesisBootstrapError::InvalidPreparedSeal)?;
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

fn create_config(create: &ReplayInput) -> Option<&super::AgentConfig> {
    let ReplayOperation::Management {
        request: LifecycleRequest::Authorized { request, .. },
    } = &create.operation
    else {
        return None;
    };
    let LifecycleRequest::Create(config) = request.as_ref() else {
        return None;
    };
    Some(config)
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

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::boxed::Box;
    use alloc::string::ToString;
    use alloc::sync::Arc;
    use alloc::vec;
    use core::convert::Infallible;
    use core::sync::atomic::{AtomicUsize, Ordering};
    use ed25519_dalek::{Signer as _, SigningKey};
    use std::sync::Mutex;

    use crate::agent::authority::{
        AgentAuthorityBinding, AgentAuthorityClaim, AgentAuthorityReceipt, ed25519_public_key_wire,
    };
    use crate::agent::committee::{
        AuthorityCommittee, AuthorityCommitteeMember, AuthorityMemberRole,
        AuthorityQuorumCertificate, AuthoritySignature, AuthoritySignerId, RootAnchorRecord,
    };
    use crate::agent::contract::RuntimePackageContract;
    use crate::agent::replay::{
        ReplayDisposition, ReplayExecutor, ReplayPosition, ReplayProducts, ReplayTransition,
    };
    use crate::agent::standard::StandardAgentRuntime;
    use crate::agent::system_authority::SystemAuthorityGenesis;
    use crate::agent::wire::{
        RuntimeState, decode_standard_runtime_state, encode_standard_runtime_state,
    };
    use crate::agent::{
        AgentConfig, AgentIdentity, AgentProfile, AgentRuntime, LaneSet,
        LifecycleAuthorityAdmission, RuntimeCapabilities,
    };
    use crate::service::{
        ActorId, CapabilityId, CredentialId, DeploymentId, Hash, ProducerId, ProgramId,
    };

    const RUNTIME_BYTES: &[u8] = b"system-agent-bootstrap-runtime";
    const ROOT_DISCRIMINATOR: u8 = 0x61;

    fn lifecycle_key() -> SigningKey {
        SigningKey::from_bytes(&[0x31; 32])
    }

    fn authority() -> AgentAuthorityBinding {
        let public_key = ed25519_public_key_wire(lifecycle_key().verifying_key().to_bytes());
        AgentAuthorityBinding {
            agent: fixture_agent(),
            actor: ActorId([0x33; 32]),
            deployment: DeploymentId([0x34; 32]),
            program: ProgramId([0x35; 32]),
            producer: ProducerId::of_public_key(&public_key),
            public_key,
        }
    }

    fn fixture_agent() -> AgentId {
        AgentId::derive(
            SpaceId([0x41; 32]),
            PrincipalId([0x42; 32]),
            Hash([0x43; 32]).as_bytes(),
        )
    }

    fn root_material(discriminator: u8) -> (RootAnchorRecord, [SigningKey; 3]) {
        let keys = [
            SigningKey::from_bytes(&[discriminator; 32]),
            SigningKey::from_bytes(&[discriminator.wrapping_add(1); 32]),
            SigningKey::from_bytes(&[discriminator.wrapping_add(2); 32]),
        ];
        let mut members = keys
            .iter()
            .enumerate()
            .map(|(index, key)| {
                AuthorityCommitteeMember::new(
                    NodeId([(index + 1) as u8; 32]),
                    key.verifying_key().to_bytes(),
                    AuthorityMemberRole::Voter,
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        members.sort_by_key(AuthorityCommitteeMember::signer);
        let binding = authority().commitment();
        let committee =
            AuthorityCommittee::new(SpaceId([0x41; 32]), binding, 1, None, members).unwrap();
        let root = RootAnchorRecord::new(
            u64::from(discriminator) + 1,
            SpaceId([0x41; 32]),
            fixture_agent(),
            binding,
            Hash([discriminator.wrapping_add(3); 32]),
            committee,
        )
        .unwrap();
        (root, keys)
    }

    fn config() -> AgentConfig {
        let space = SpaceId([0x41; 32]);
        let owner = PrincipalId([0x42; 32]);
        let nonce = Hash([0x43; 32]);
        let agent = AgentId::derive(space, owner, nonce.as_bytes());
        let (root, _) = root_material(ROOT_DISCRIMINATOR);
        let system_authority_genesis = SystemAuthorityGenesis::new(
            root.id(),
            root.config_version(),
            root.config_commitment(),
            root.initial_committee().clone(),
            1,
            Hash([0x75; 32]),
            Hash([0x76; 32]),
            8,
            8,
            8,
        )
        .unwrap();
        AgentConfig {
            identity: AgentIdentity {
                space,
                agent,
                owner,
                profile: AgentProfile::Local,
                runtime_deployment: DeploymentId([0x44; 32]),
                runtime_program: ProgramId([0x45; 32]),
                runtime_producer: ProducerId([0x46; 32]),
            },
            creation_nonce: nonce,
            authority: authority(),
            system_authority_genesis: Some(system_authority_genesis),
            runtime_package: BlobRef::of_bytes(RUNTIME_BYTES),
            runtime_contract: RuntimePackageContract::canonical(),
            capabilities: RuntimeCapabilities {
                lanes: LaneSet::ALL,
                scheduling: false,
                proofs: false,
                max_actors: 64,
            },
            replicas: vec![AgentReplica {
                node: NodeId([0x47; 32]),
                principal: owner,
                role: ReplicaRole::Voter,
            }],
        }
    }

    fn create_input(observed_slot: u64) -> ReplayInput {
        let config = config();
        let runtime = super::super::journal::RuntimeBinding {
            space: config.identity.space,
            agent: config.identity.agent,
            deployment: config.identity.runtime_deployment,
            program: config.identity.runtime_program,
            producer: config.identity.runtime_producer,
            package: config.runtime_package.clone(),
            runtime_abi: super::super::RUNTIME_ABI_ID,
            execution_semantics: super::super::EXECUTION_SEMANTICS_ID,
        };
        let inner = LifecycleRequest::Create(config.clone());
        let claim = AgentAuthorityClaim {
            authority: config.authority.clone(),
            space: config.identity.space,
            agent: config.identity.agent,
            principal: config.identity.owner,
            credential: CredentialId([0x48; 32]),
            capability: CapabilityId::named("agent.create.local"),
            operation: inner.commitment(),
            sequence: 1,
            valid_from: 10,
            valid_until: 30,
        };
        let signature = lifecycle_key()
            .sign(&claim.signing_message().0)
            .to_bytes()
            .to_vec();
        ReplayInput {
            runtime,
            operation: ReplayOperation::Management {
                request: LifecycleRequest::Authorized {
                    admission: LifecycleAuthorityAdmission {
                        receipt: AgentAuthorityReceipt { claim, signature },
                        observed_slot,
                    },
                    request: Box::new(inner),
                },
            },
        }
    }

    fn resign_create_input(input: &mut ReplayInput) {
        let ReplayOperation::Management {
            request: LifecycleRequest::Authorized { admission, request },
        } = &mut input.operation
        else {
            unreachable!("test input is an authorized Create");
        };
        admission.receipt.claim.operation = request.commitment();
        admission.receipt.claim.capability = CapabilityId::named(
            request
                .required_capability()
                .expect("Create always requires a capability"),
        );
        admission.receipt.signature = lifecycle_key()
            .sign(&admission.receipt.claim.signing_message().0)
            .to_bytes()
            .to_vec();
    }

    #[derive(Default)]
    struct ExactCreateExecutor {
        authentications: usize,
        executions: usize,
        mutate_state: bool,
        omit_system_authority: bool,
    }

    impl ReplayExecutor for ExactCreateExecutor {
        type Error = ();

        fn verify_merge_event(
            &mut self,
            _event: &super::super::journal::MergeEvent,
        ) -> Result<bool, Self::Error> {
            Ok(false)
        }

        fn authenticate(
            &mut self,
            input: &ReplayInput,
            _before: &RuntimeState,
            _position: ReplayPosition,
        ) -> Result<(), Self::Error> {
            self.authentications += 1;
            let ReplayOperation::Management {
                request: LifecycleRequest::Authorized { admission, request },
            } = &input.operation
            else {
                return Err(());
            };
            let LifecycleRequest::Create(config) = request.as_ref() else {
                return Err(());
            };
            admission
                .receipt
                .verify_guest_signature(&config.authority)
                .map_err(|_| ())
        }

        fn execute(
            &mut self,
            input: &ReplayInput,
            before: &RuntimeState,
            _position: ReplayPosition,
        ) -> Result<ReplayTransition, Self::Error> {
            self.executions += 1;
            let ReplayOperation::Management { request } = &input.operation else {
                return Err(());
            };
            let decoded = decode_standard_runtime_state(before).map_err(|_| ())?;
            let mut runtime = StandardAgentRuntime::restore(decoded).map_err(|_| ())?;
            let result = runtime.apply(request.clone());
            let mut snapshot = runtime.snapshot();
            if self.omit_system_authority {
                snapshot.system_authority = None;
            }
            let mut state = encode_standard_runtime_state(&snapshot);
            if self.mutate_state {
                state.linear.push(0xff);
            }
            Ok(ReplayTransition {
                state,
                disposition: if result.is_ok() {
                    ReplayDisposition::Applied
                } else {
                    ReplayDisposition::Rejected
                },
                result: None,
                next_runtime: input.runtime.clone(),
                products: ReplayProducts::default(),
            })
        }
    }

    fn prepare(input: ReplayInput) -> ReplayPreparedGenesis {
        let mut executor = ExactCreateExecutor::default();
        ReplayPreparedGenesis::prepare(input, config().replicas[0], &mut executor).unwrap()
    }

    fn authority_provision(
        proposal: SystemAgentGenesisProposal,
        discriminator: u8,
    ) -> SystemAgentGenesisProvision {
        let (root, keys) = root_material(discriminator);
        let committee = root.initial_committee().clone();
        let claim = SystemAgentGenesisClaim::new(&root, proposal.expectations).unwrap();
        let message = AuthorityQuorumCertificate::signing_message(
            committee.authority_binding(),
            committee.epoch(),
            committee.commitment(),
            claim.authority_claim(),
        );
        let mut signatures = keys[..2]
            .iter()
            .map(|key| {
                AuthoritySignature::new(
                    AuthoritySignerId::of_raw_ed25519(&key.verifying_key().to_bytes()),
                    key.sign(&message.0).to_bytes(),
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        signatures.sort_by_key(AuthoritySignature::signer);
        let evidence = SystemAgentGenesisEvidence::new(
            claim.clone(),
            AuthorityQuorumCertificate::new(&committee, claim.authority_claim(), signatures)
                .unwrap(),
        )
        .unwrap();
        let pins = RootAnchorPins::new(
            root.clone(),
            root.config_version(),
            root.id(),
            root.config_commitment(),
            claim.authority_claim(),
        )
        .unwrap();
        SystemAgentGenesisProvision::new(proposal, pins, evidence).unwrap()
    }

    fn catalog() -> Vec<RuntimeBlob> {
        vec![RuntimeBlob {
            reference: BlobRef::of_bytes(RUNTIME_BYTES),
            bytes: RUNTIME_BYTES.to_vec(),
        }]
    }

    struct MemoryProvider {
        configured: SystemAgentGenesisProvision,
        archive: Mutex<Option<(SystemAgentGenesisProvision, Vec<RuntimeBlob>)>>,
        creates: AtomicUsize,
        reproduces: AtomicUsize,
    }

    impl MemoryProvider {
        fn new(configured: SystemAgentGenesisProvision) -> Self {
            Self {
                configured,
                archive: Mutex::new(None),
                creates: AtomicUsize::new(0),
                reproduces: AtomicUsize::new(0),
            }
        }
    }

    impl SystemAgentGenesisProvider for MemoryProvider {
        fn create(
            &self,
            proposal: &SystemAgentGenesisProposal,
            catalog: &[RuntimeBlob],
        ) -> Result<SystemAgentGenesisProvision, SystemAgentGenesisProviderError> {
            self.creates.fetch_add(1, Ordering::Relaxed);
            validate_system_agent_genesis_catalog(proposal, catalog)
                .map_err(|_| SystemAgentGenesisProviderError::Corrupt)?;
            let mut archive = self.archive.lock().unwrap();
            if let Some((existing, bytes)) = archive.as_ref() {
                return if existing.proposal() == proposal && bytes == catalog {
                    Ok(existing.clone())
                } else {
                    Err(SystemAgentGenesisProviderError::Conflict)
                };
            }
            if self.configured.proposal() != proposal {
                return Err(SystemAgentGenesisProviderError::Refused);
            }
            *archive = Some((self.configured.clone(), catalog.to_vec()));
            Ok(self.configured.clone())
        }

        fn reproduce(
            &self,
            locator: SystemAgentGenesisLocator,
        ) -> Result<SystemAgentGenesisProvision, SystemAgentGenesisProviderError> {
            self.reproduces.fetch_add(1, Ordering::Relaxed);
            self.archive
                .lock()
                .unwrap()
                .as_ref()
                .filter(|(provision, _)| provision.proposal.locator == locator)
                .map(|(provision, _)| provision.clone())
                .ok_or(SystemAgentGenesisProviderError::NotConfigured)
        }

        fn load_catalog(
            &self,
            locator: SystemAgentGenesisLocator,
            reference: &BlobRef,
        ) -> Result<Option<Vec<u8>>, SystemAgentGenesisProviderError> {
            Ok(self
                .archive
                .lock()
                .unwrap()
                .as_ref()
                .filter(|(provision, _)| provision.proposal.locator == locator)
                .and_then(|(_, catalog)| {
                    catalog
                        .iter()
                        .find(|blob| &blob.reference == reference)
                        .map(|blob| blob.bytes.clone())
                }))
        }
    }

    #[test]
    fn preparation_is_deterministic_genesis_free_and_exactly_sealed() {
        let input = create_input(15);
        let mut first_executor = ExactCreateExecutor::default();
        let first = ReplayPreparedGenesis::prepare(
            input.clone(),
            config().replicas[0],
            &mut first_executor,
        )
        .unwrap();
        let mut second_executor = ExactCreateExecutor::default();
        let second =
            ReplayPreparedGenesis::prepare(input, config().replicas[0], &mut second_executor)
                .unwrap();
        assert_eq!(first, second);
        assert_eq!(
            (first_executor.authentications, first_executor.executions),
            (1, 1)
        );
        let locator = SystemAgentGenesisLocator {
            space: config().identity.space,
            agent: config().identity.agent,
            node: config().replicas[0].node,
        };
        let proposal = SystemAgentGenesisProposal::from_prepared(locator, &first).unwrap();
        let provision = authority_provision(proposal.clone(), ROOT_DISCRIMINATOR);
        assert_eq!(
            SystemAgentGenesisProposal::decode(&proposal.encode()).unwrap(),
            proposal
        );
        assert_eq!(
            SystemAgentGenesisProvision::decode(&provision.encode()).unwrap(),
            provision
        );
        let configured_root = provision.root().clone();
        let sealed =
            seal_prepared_system_agent_genesis(first, &configured_root, &provision).unwrap();
        let decoded = decode_standard_runtime_state(sealed.post_create()).unwrap();
        let expected_authority =
            super::super::system_authority::SystemAuthorityState::from_genesis(
                config().identity.agent,
                config().system_authority_genesis.as_ref().unwrap(),
            )
            .unwrap();
        assert_eq!(decoded.system_authority, Some(expected_authority));
        assert_ne!(
            sealed.genesis().admission,
            super::super::genesis::AgentGenesisAdmissionId::ZERO
        );
        assert_ne!(
            sealed.root_admission_id(),
            super::super::committee::SystemAgentGenesisAdmissionId::ZERO
        );
        assert_ne!(
            sealed.root_admission_id().as_bytes(),
            sealed.genesis().admission.as_bytes()
        );
        assert_ne!(
            sealed.genesis().id(),
            super::super::journal::AgentJournalGenesisId::ZERO
        );
        assert_eq!(
            sealed.root_admission_record().root_anchor(),
            configured_root.root_anchor()
        );
        assert_eq!(
            sealed.root_admission_record().root_anchor_config_version(),
            configured_root.config_version()
        );
        assert_eq!(
            sealed.root_admission_record().root_anchor_config(),
            configured_root.config_commitment()
        );
        assert!(matches!(
            sealed.admission_record(),
            super::super::genesis::AgentGenesisAdmissionRecord::RootBootstrap(record)
                if record == sealed.root_admission_record()
        ));
        assert_eq!(sealed.genesis().create, *provision.proposal().create());
        assert_eq!(sealed.artifacts().artifacts, proposal.catalog);
    }

    #[test]
    fn prepared_root_marker_preflight_blocks_provider_writes() {
        let prepared = prepare(create_input(15));
        let locator = SystemAgentGenesisLocator {
            space: config().identity.space,
            agent: config().identity.agent,
            node: config().replicas[0].node,
        };
        let proposal = SystemAgentGenesisProposal::from_prepared(locator, &prepared).unwrap();
        let provision = authority_provision(proposal, ROOT_DISCRIMINATOR);
        let configured_root = provision.root().clone();
        let provider = MemoryProvider::new(provision);
        assert_eq!(
            validate_prepared_system_agent_genesis_root(&prepared, &configured_root),
            Ok(())
        );

        let alternate_prepared = prepare(create_input(16));
        let alternate_claim = SystemAgentGenesisClaim::new(
            configured_root.record(),
            alternate_prepared.expectations(),
        )
        .unwrap();
        let divergent_claim_pins = RootAnchorPins::new(
            configured_root.record().clone(),
            configured_root.config_version(),
            configured_root.root_anchor(),
            configured_root.config_commitment(),
            alternate_claim.authority_claim(),
        )
        .unwrap();
        assert!(matches!(
            validate_prepared_system_agent_genesis_root(&prepared, &divergent_claim_pins),
            Err(SystemAgentGenesisBootstrapError::Authority(_))
        ));

        let mut missing = create_input(15);
        let ReplayOperation::Management {
            request: LifecycleRequest::Authorized { request, .. },
        } = &mut missing.operation
        else {
            unreachable!("test input is an authorized Create");
        };
        let LifecycleRequest::Create(missing_config) = request.as_mut() else {
            unreachable!("test input is an authorized Create");
        };
        missing_config.system_authority_genesis = None;
        resign_create_input(&mut missing);
        let missing = prepare(missing);
        assert_eq!(
            validate_prepared_system_agent_genesis_root(&missing, &configured_root),
            Err(SystemAgentGenesisBootstrapError::InvalidPreparedSeal)
        );

        let mut divergent = create_input(15);
        let ReplayOperation::Management {
            request: LifecycleRequest::Authorized { request, .. },
        } = &mut divergent.operation
        else {
            unreachable!("test input is an authorized Create");
        };
        let LifecycleRequest::Create(divergent_config) = request.as_mut() else {
            unreachable!("test input is an authorized Create");
        };
        let (foreign_root, _) = root_material(ROOT_DISCRIMINATOR.wrapping_add(1));
        divergent_config.system_authority_genesis = Some(
            SystemAuthorityGenesis::new(
                foreign_root.id(),
                foreign_root.config_version(),
                foreign_root.config_commitment(),
                foreign_root.initial_committee().clone(),
                1,
                Hash([0x75; 32]),
                Hash([0x76; 32]),
                8,
                8,
                8,
            )
            .unwrap(),
        );
        resign_create_input(&mut divergent);
        let divergent = prepare(divergent);
        assert_eq!(
            validate_prepared_system_agent_genesis_root(&divergent, &configured_root),
            Err(SystemAgentGenesisBootstrapError::InvalidPreparedSeal)
        );

        assert_eq!(provider.creates.load(Ordering::Relaxed), 0);
        assert!(provider.archive.lock().unwrap().is_none());
    }

    #[test]
    fn provider_create_is_exactly_idempotent_and_reproduce_is_read_only() {
        let prepared = prepare(create_input(15));
        let locator = SystemAgentGenesisLocator {
            space: config().identity.space,
            agent: config().identity.agent,
            node: config().replicas[0].node,
        };
        let proposal = SystemAgentGenesisProposal::from_prepared(locator, &prepared).unwrap();
        let expected = authority_provision(proposal.clone(), ROOT_DISCRIMINATOR);
        let provider = Arc::new(MemoryProvider::new(expected.clone()));
        assert_eq!(provider.create(&proposal, &catalog()).unwrap(), expected);
        assert_eq!(provider.create(&proposal, &catalog()).unwrap(), expected);

        let reproduced = provider.reproduce(locator).unwrap();
        assert_eq!(reproduced, expected);
        assert_eq!(provider.creates.load(Ordering::Relaxed), 2);
        assert_eq!(provider.reproduces.load(Ordering::Relaxed), 1);
        assert_eq!(
            provider
                .load_catalog(locator, &proposal.catalog[0])
                .unwrap(),
            Some(RUNTIME_BYTES.to_vec())
        );

        let divergent_prepared = prepare(create_input(16));
        let divergent =
            SystemAgentGenesisProposal::from_prepared(locator, &divergent_prepared).unwrap();
        assert_eq!(
            provider.create(&divergent, &catalog()),
            Err(SystemAgentGenesisProviderError::Conflict)
        );
        assert_eq!(provider.reproduces.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn preparation_and_sealing_reject_runtime_state_root_qc_and_catalog_mutations() {
        let locator = SystemAgentGenesisLocator {
            space: config().identity.space,
            agent: config().identity.agent,
            node: config().replicas[0].node,
        };

        let mut wrong_runtime = create_input(15);
        wrong_runtime.runtime.package = BlobRef::of_bytes(b"different runtime");
        let mut executor = ExactCreateExecutor::default();
        assert!(matches!(
            ReplayPreparedGenesis::prepare(wrong_runtime, config().replicas[0], &mut executor,),
            Err(super::super::replay::ReplayError::InvalidRecord)
        ));

        let mut wrong_input = create_input(15);
        let ReplayOperation::Management {
            request: LifecycleRequest::Authorized { admission, .. },
        } = &mut wrong_input.operation
        else {
            unreachable!("test input is an authorized Create");
        };
        admission.receipt.signature[0] ^= 1;
        let mut executor = ExactCreateExecutor::default();
        assert!(matches!(
            ReplayPreparedGenesis::prepare(wrong_input, config().replicas[0], &mut executor,),
            Err(super::super::replay::ReplayError::Executor(()))
        ));

        let mut shared_input = create_input(15);
        let ReplayOperation::Management {
            request: LifecycleRequest::Authorized { request, .. },
        } = &mut shared_input.operation
        else {
            unreachable!("test input is an authorized Create");
        };
        let LifecycleRequest::Create(shared_config) = request.as_mut() else {
            unreachable!("test input is an authorized Create");
        };
        shared_config.identity.profile = AgentProfile::Shared;
        shared_config.replicas.push(AgentReplica {
            node: NodeId([0x49; 32]),
            principal: shared_config.identity.owner,
            role: ReplicaRole::Voter,
        });
        resign_create_input(&mut shared_input);
        let mut executor = ExactCreateExecutor::default();
        assert!(matches!(
            ReplayPreparedGenesis::prepare(shared_input, config().replicas[0], &mut executor,),
            Err(super::super::replay::ReplayError::ScopeMismatch)
        ));

        let mut state_mutator = ExactCreateExecutor {
            mutate_state: true,
            ..ExactCreateExecutor::default()
        };
        assert!(matches!(
            ReplayPreparedGenesis::prepare(
                create_input(15),
                config().replicas[0],
                &mut state_mutator,
            ),
            Err(super::super::replay::ReplayError::InvalidManagementTransition)
        ));

        let mut authority_omitter = ExactCreateExecutor {
            omit_system_authority: true,
            ..ExactCreateExecutor::default()
        };
        assert!(matches!(
            ReplayPreparedGenesis::prepare(
                create_input(15),
                config().replicas[0],
                &mut authority_omitter,
            ),
            Err(super::super::replay::ReplayError::InvalidManagementTransition)
        ));

        let prepared = prepare(create_input(15));
        let proposal = SystemAgentGenesisProposal::from_prepared(locator, &prepared).unwrap();
        let provision = authority_provision(proposal.clone(), ROOT_DISCRIMINATOR);
        let configured_root = provision.root().clone();

        let mut bad_catalog = catalog();
        bad_catalog[0].bytes.push(0xff);
        assert_eq!(
            validate_system_agent_genesis_catalog(&proposal, &bad_catalog),
            Err(SystemAgentGenesisBootstrapError::InvalidCatalog)
        );
        let mut extra_catalog = catalog();
        extra_catalog.push(catalog()[0].clone());
        assert_eq!(
            validate_system_agent_genesis_catalog(&proposal, &extra_catalog),
            Err(SystemAgentGenesisBootstrapError::InvalidCatalog)
        );
        let mut bad_reference = proposal.clone();
        bad_reference.catalog[0].len += 1;
        assert!(bad_reference.validate().is_err());

        let mut tampered_qc = provision.evidence.encode();
        *tampered_qc.last_mut().unwrap() ^= 1;
        let tampered_evidence = SystemAgentGenesisEvidence::decode(&tampered_qc).unwrap();
        let mut invalid_qc = provision.clone();
        invalid_qc.evidence = tampered_evidence;
        assert_eq!(
            invalid_qc.validate(),
            Err(SystemAgentGenesisBootstrapError::InvalidProvision)
        );

        let alternate = authority_provision(proposal, 0x91);
        let mut invalid_root = provision.clone();
        invalid_root.root = alternate.root;
        assert_eq!(
            invalid_root.validate(),
            Err(SystemAgentGenesisBootstrapError::InvalidProvision)
        );
        assert!(matches!(
            seal_prepared_system_agent_genesis(prepared, &configured_root, &invalid_root),
            Err(SystemAgentGenesisBootstrapError::InvalidProvision)
        ));
    }

    #[test]
    fn self_consistent_provider_selected_root_and_qc_are_not_trusted() {
        let prepared = prepare(create_input(15));
        let locator = SystemAgentGenesisLocator {
            space: config().identity.space,
            agent: config().identity.agent,
            node: config().replicas[0].node,
        };
        let proposal = SystemAgentGenesisProposal::from_prepared(locator, &prepared).unwrap();
        let configured = authority_provision(proposal.clone(), ROOT_DISCRIMINATOR);
        let provider_selected = authority_provision(proposal, 0x93);

        assert!(configured.validate().is_ok());
        assert!(provider_selected.validate().is_ok());
        assert_ne!(configured.root(), provider_selected.root());
        assert!(matches!(
            seal_prepared_system_agent_genesis(prepared, configured.root(), &provider_selected),
            Err(SystemAgentGenesisBootstrapError::InvalidProvision)
        ));
    }

    #[test]
    fn provider_envelopes_reject_oversize_and_expectation_mutations() {
        let prepared = prepare(create_input(15));
        let locator = SystemAgentGenesisLocator {
            space: config().identity.space,
            agent: config().identity.agent,
            node: config().replicas[0].node,
        };
        let proposal = SystemAgentGenesisProposal::from_prepared(locator, &prepared).unwrap();
        let provision = authority_provision(proposal.clone(), ROOT_DISCRIMINATOR);
        let configured_root = provision.root().clone();

        let mut mutated = proposal.clone();
        mutated.expectations = SystemAgentGenesisExpectations::new(
            mutated.expectations.runtime_binding(),
            mutated.expectations.inner_create_request(),
            Hash([0xee; 32]),
            mutated.expectations.artifact_closure(),
            mutated.expectations.sequence(),
        )
        .unwrap();
        assert_ne!(mutated, proposal);
        assert!(matches!(
            seal_prepared_system_agent_genesis(
                prepared,
                &configured_root,
                &authority_provision(mutated, 0xa2),
            ),
            Err(SystemAgentGenesisBootstrapError::InvalidProvision)
        ));

        let mut oversized_proposal = proposal.encode();
        oversized_proposal.resize(MAX_SYSTEM_AGENT_GENESIS_PROPOSAL_BYTES + 1, 0);
        assert_eq!(
            SystemAgentGenesisProposal::decode(&oversized_proposal),
            Err(DecodeError::LimitExceeded)
        );
        let mut oversized_provision = provision.encode();
        oversized_provision.resize(MAX_SYSTEM_AGENT_GENESIS_PROVISION_BYTES + 1, 0);
        assert_eq!(
            SystemAgentGenesisProvision::decode(&oversized_provision),
            Err(DecodeError::LimitExceeded)
        );
    }

    #[test]
    fn provider_error_is_bounded_and_executor_error_type_stays_generic() {
        fn assert_generic_prepare(
            prepared: Result<
                ReplayPreparedGenesis,
                super::super::replay::ReplayError<Infallible, ()>,
            >,
        ) {
            assert!(prepared.is_ok());
        }
        let mut executor = ExactCreateExecutor::default();
        assert_generic_prepare(ReplayPreparedGenesis::prepare(
            create_input(15),
            config().replicas[0],
            &mut executor,
        ));
        assert_eq!(
            SystemAgentGenesisProviderError::Unavailable.to_string(),
            "system-Agent genesis provider: Unavailable"
        );
    }
}
