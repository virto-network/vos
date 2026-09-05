//! Canonical bounded codecs for the clean agent SDK generation.
//!
//! There is exactly one accepted ABI header. This module intentionally has no
//! compatibility tags or fallback decoder.

use alloc::vec::Vec;
use core::fmt;

use vos_protocol::wire::{DecodeError, Decoder, Encoder};

use crate::authority::{
    AUTHORITY_PUBLIC_KEY_BYTES, AUTHORITY_SIGNATURE_BYTES, AuthorityEvidence, AuthorityIssuer,
    AuthorityLaneRoots, AuthorityOperationKind, AuthorityReceipt, AuthorityReceiptSelector,
};
use crate::contract::{
    ActorAbiRange, ActorPackageContract, RuntimeMigrationPolicy, RuntimePackageContract,
    RuntimeResourceLimits,
};
use crate::*;

const HEADER_BYTES: usize = 4 + 32;
pub const MAX_ACTOR_ENTRY_WIRE_BYTES: usize = 1_024;
pub const MAX_DIRECTORY_PAGE_WIRE_BYTES: usize =
    HEADER_BYTES + 4 + MAX_DIRECTORY_PAGE_ENTRIES * (MAX_ACTOR_ENTRY_WIRE_BYTES + 128) + 33;
pub const MAX_AUTHORITY_RECEIPT_WIRE_BYTES: usize = 1_024;
pub const MAX_RUNTIME_WORK_WIRE_BYTES: usize =
    HEADER_BYTES + MAX_RUNTIME_STATE_BYTES + MAX_RUNTIME_AVAILABILITY_BYTES + 512 * 1024;
pub const MAX_RUNTIME_TRANSITION_WIRE_BYTES: usize =
    HEADER_BYTES + MAX_RUNTIME_STATE_BYTES + MAX_DIRECTORY_PAGE_WIRE_BYTES + 64 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WireError {
    Decode(DecodeError),
    InvalidValue,
    LimitExceeded,
}

impl fmt::Display for WireError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Decode(error) => error.fmt(formatter),
            Self::InvalidValue => formatter.write_str("invalid canonical agent value"),
            Self::LimitExceeded => formatter.write_str("canonical agent wire limit exceeded"),
        }
    }
}

impl core::error::Error for WireError {}

impl From<DecodeError> for WireError {
    fn from(value: DecodeError) -> Self {
        Self::Decode(value)
    }
}

/// One complete canonical SDK message. Implementations validate values before
/// encoding and after decoding; malformed values can never be normalized into
/// a second accepted representation.
pub trait CanonicalWire: Sized {
    const MAGIC: [u8; 4];
    const MAX_ENCODED_BYTES: usize;

    fn validate_wire(&self) -> bool;
    fn encode_body(&self, encoder: &mut Encoder<'_>);
    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError>;

    fn encode(&self) -> Result<Vec<u8>, WireError> {
        if !self.validate_wire() {
            return Err(WireError::InvalidValue);
        }
        let mut bytes = Vec::new();
        bytes
            .try_reserve(Self::MAX_ENCODED_BYTES.min(4096))
            .map_err(|_| WireError::LimitExceeded)?;
        bytes.extend_from_slice(&Self::MAGIC);
        bytes.extend_from_slice(RUNTIME_ABI_ID.as_bytes());
        Self::encode_body(self, &mut Encoder(&mut bytes));
        if bytes.len() > Self::MAX_ENCODED_BYTES {
            return Err(WireError::LimitExceeded);
        }
        Ok(bytes)
    }

    fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        if bytes.len() > Self::MAX_ENCODED_BYTES {
            return Err(WireError::LimitExceeded);
        }
        let mut decoder = Decoder::new(bytes);
        if decoder.take(4)? != Self::MAGIC {
            return Err(DecodeError::InvalidTag.into());
        }
        if Hash(decoder.fixed()?) != RUNTIME_ABI_ID {
            return Err(DecodeError::InvalidPlatform.into());
        }
        let value = Self::decode_body(&mut decoder)?;
        if !decoder.exhausted() {
            return Err(DecodeError::TrailingBytes.into());
        }
        if !value.validate_wire() {
            return Err(WireError::InvalidValue);
        }
        Ok(value)
    }
}

fn encode_blob(encoder: &mut Encoder<'_>, value: &BlobRef) {
    encoder.fixed(value.hash.as_bytes());
    encoder.u64(value.len);
}

fn decode_blob(decoder: &mut Decoder<'_>) -> Result<BlobRef, DecodeError> {
    Ok(BlobRef {
        hash: Hash(decoder.fixed()?),
        len: decoder.u64()?,
    })
}

fn encode_optional_blob(encoder: &mut Encoder<'_>, value: &Option<BlobRef>) {
    encoder.option(value, encode_blob);
}

fn decode_optional_blob(decoder: &mut Decoder<'_>) -> Result<Option<BlobRef>, DecodeError> {
    decoder.option(decode_blob)
}

fn encode_installation_data(encoder: &mut Encoder<'_>, value: &InstallationData) {
    encode_blob(encoder, &value.reference);
    encoder.bytes(&value.bytes);
}

fn decode_installation_data(decoder: &mut Decoder<'_>) -> Result<InstallationData, DecodeError> {
    let reference = decode_blob(decoder)?;
    // Bound the declared frame before allocating its owned representation.
    let bytes = decoder
        .bytes_ref_bounded(MAX_INSTALLATION_DATA_BYTES)?
        .to_vec();
    let value = InstallationData { reference, bytes };
    value
        .validate()
        .is_ok()
        .then_some(value)
        .ok_or(DecodeError::NonCanonical)
}

fn encode_optional_hash(encoder: &mut Encoder<'_>, value: &Option<Hash>) {
    encoder.option(value, |encoder, value| encoder.fixed(value.as_bytes()));
}

fn decode_optional_hash(decoder: &mut Decoder<'_>) -> Result<Option<Hash>, DecodeError> {
    decoder.option(|decoder| Ok(Hash(decoder.fixed()?)))
}

fn encode_lane(encoder: &mut Encoder<'_>, value: StateLane) {
    encoder.u8(value as u8);
}

fn decode_lane(decoder: &mut Decoder<'_>) -> Result<StateLane, DecodeError> {
    match decoder.u8()? {
        0 => Ok(StateLane::Linear),
        1 => Ok(StateLane::Merge),
        2 => Ok(StateLane::Local),
        _ => Err(DecodeError::InvalidTag),
    }
}

fn decode_method_mode(decoder: &mut Decoder<'_>) -> Result<MethodMode, DecodeError> {
    match decoder.u8()? {
        0 => Ok(MethodMode::Query),
        1 => Ok(MethodMode::LinearizableQuery),
        2 => Ok(MethodMode::LocalQuery),
        3 => Ok(MethodMode::Linear),
        4 => Ok(MethodMode::Merge),
        5 => Ok(MethodMode::Local),
        _ => Err(DecodeError::InvalidTag),
    }
}

fn encode_requirements(encoder: &mut Encoder<'_>, value: RuntimeRequirements) {
    encoder.u8(value.lanes.bits());
    encoder.bool(value.scheduling);
    value.proof_systems.encode_embedded(encoder);
}

fn decode_requirements(decoder: &mut Decoder<'_>) -> Result<RuntimeRequirements, DecodeError> {
    Ok(RuntimeRequirements {
        lanes: LaneSet::from_bits(decoder.u8()?).ok_or(DecodeError::NonCanonical)?,
        scheduling: decoder.bool()?,
        proof_systems: ProofSystemSet::decode_embedded(decoder)?,
    })
}

fn encode_capabilities(encoder: &mut Encoder<'_>, value: RuntimeCapabilities) {
    encoder.u8(value.lanes.bits());
    encoder.bool(value.scheduling);
    value.proof_systems.encode_embedded(encoder);
    encoder.u32(value.max_actors);
}

fn decode_capabilities(decoder: &mut Decoder<'_>) -> Result<RuntimeCapabilities, DecodeError> {
    let value = RuntimeCapabilities {
        lanes: LaneSet::from_bits(decoder.u8()?).ok_or(DecodeError::NonCanonical)?,
        scheduling: decoder.bool()?,
        proof_systems: ProofSystemSet::decode_embedded(decoder)?,
        max_actors: decoder.u32()?,
    };
    if value.max_actors == 0 || value.max_actors > STANDARD_MAX_ACTORS {
        return Err(DecodeError::NonCanonical);
    }
    Ok(value)
}

fn encode_actor_contract(encoder: &mut Encoder<'_>, value: ActorPackageContract) {
    encoder.u32(value.actor_abi);
}

fn decode_actor_contract(decoder: &mut Decoder<'_>) -> Result<ActorPackageContract, DecodeError> {
    let value = ActorPackageContract {
        actor_abi: decoder.u32()?,
    };
    value
        .is_valid()
        .then_some(value)
        .ok_or(DecodeError::NonCanonical)
}

fn encode_runtime_contract(encoder: &mut Encoder<'_>, value: RuntimePackageContract) {
    encoder.fixed(value.lifecycle_abi.as_bytes());
    encoder.u32(value.actor_abis.minimum);
    encoder.u32(value.actor_abis.maximum);
    encoder.fixed(value.control_schema.as_bytes());
    encoder.u32(value.resources.max_runtime_state_bytes);
    encoder.u32(value.resources.max_artifact_references);
    encoder.u64(value.resources.max_artifact_referenced_bytes);
    encoder.u8(value.migration as u8);
}

fn decode_runtime_contract(
    decoder: &mut Decoder<'_>,
) -> Result<RuntimePackageContract, DecodeError> {
    let value = RuntimePackageContract {
        lifecycle_abi: Hash(decoder.fixed()?),
        actor_abis: ActorAbiRange {
            minimum: decoder.u32()?,
            maximum: decoder.u32()?,
        },
        control_schema: Hash(decoder.fixed()?),
        resources: RuntimeResourceLimits {
            max_runtime_state_bytes: decoder.u32()?,
            max_artifact_references: decoder.u32()?,
            max_artifact_referenced_bytes: decoder.u64()?,
        },
        migration: match decoder.u8()? {
            0 => RuntimeMigrationPolicy::None,
            _ => return Err(DecodeError::InvalidTag),
        },
    };
    value
        .is_valid()
        .then_some(value)
        .ok_or(DecodeError::NonCanonical)
}

fn encode_package_kind(encoder: &mut Encoder<'_>, value: PackageKind) {
    match value {
        PackageKind::Actor {
            contract,
            requirements,
        } => {
            encoder.u8(0);
            encode_actor_contract(encoder, contract);
            encode_requirements(encoder, requirements);
        }
        PackageKind::AgentRuntime {
            contract,
            capabilities,
        } => {
            encoder.u8(1);
            encode_runtime_contract(encoder, contract);
            encode_capabilities(encoder, capabilities);
        }
    }
}

fn decode_package_kind(decoder: &mut Decoder<'_>) -> Result<PackageKind, DecodeError> {
    match decoder.u8()? {
        0 => Ok(PackageKind::Actor {
            contract: decode_actor_contract(decoder)?,
            requirements: decode_requirements(decoder)?,
        }),
        1 => Ok(PackageKind::AgentRuntime {
            contract: decode_runtime_contract(decoder)?,
            capabilities: decode_capabilities(decoder)?,
        }),
        _ => Err(DecodeError::InvalidTag),
    }
}

impl CanonicalWire for PackageKind {
    const MAGIC: [u8; 4] = *b"APKG";
    const MAX_ENCODED_BYTES: usize = 256;

    fn validate_wire(&self) -> bool {
        match *self {
            Self::Actor { contract, .. } => contract.is_valid(),
            Self::AgentRuntime {
                contract,
                capabilities,
            } => {
                contract.is_valid()
                    && capabilities.max_actors != 0
                    && capabilities.max_actors <= STANDARD_MAX_ACTORS
            }
        }
    }

    fn encode_body(&self, encoder: &mut Encoder<'_>) {
        encode_package_kind(encoder, *self);
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        decode_package_kind(decoder)
    }
}

fn encode_agent_identity(encoder: &mut Encoder<'_>, value: &AgentIdentity) {
    encoder.fixed(value.space.as_bytes());
    encoder.fixed(value.agent.as_bytes());
    encoder.fixed(value.owner.as_bytes());
    encoder.u8(value.profile as u8);
    encoder.fixed(value.runtime_deployment.as_bytes());
    encoder.fixed(value.runtime_program.as_bytes());
    encoder.fixed(value.runtime_producer.as_bytes());
}

fn decode_agent_identity(decoder: &mut Decoder<'_>) -> Result<AgentIdentity, DecodeError> {
    Ok(AgentIdentity {
        space: SpaceId(decoder.fixed()?),
        agent: AgentId(decoder.fixed()?),
        owner: PrincipalId(decoder.fixed()?),
        profile: match decoder.u8()? {
            0 => AgentProfile::Local,
            1 => AgentProfile::Shared,
            2 => AgentProfile::Private,
            _ => return Err(DecodeError::InvalidTag),
        },
        runtime_deployment: DeploymentId(decoder.fixed()?),
        runtime_program: ProgramId(decoder.fixed()?),
        runtime_producer: ProducerId(decoder.fixed()?),
    })
}

fn encode_replica(encoder: &mut Encoder<'_>, value: &AgentReplica) {
    encoder.fixed(value.node.as_bytes());
    encoder.fixed(value.principal.as_bytes());
    encoder.u8(value.role as u8);
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

fn encode_agent_descriptor(encoder: &mut Encoder<'_>, value: &AgentDescriptor) {
    encode_agent_identity(encoder, &value.identity);
    encoder.fixed(value.creation_nonce.as_bytes());
    encode_blob(encoder, &value.runtime_package);
    encode_runtime_contract(encoder, value.runtime_contract);
    encode_capabilities(encoder, value.capabilities);
    encoder.list(&value.replicas, encode_replica);
}

fn decode_agent_descriptor(decoder: &mut Decoder<'_>) -> Result<AgentDescriptor, DecodeError> {
    let value = AgentDescriptor {
        identity: decode_agent_identity(decoder)?,
        creation_nonce: Hash(decoder.fixed()?),
        runtime_package: decode_blob(decoder)?,
        runtime_contract: decode_runtime_contract(decoder)?,
        capabilities: decode_capabilities(decoder)?,
        replicas: decoder.list_bounded(MAX_AGENT_REPLICAS, decode_replica)?,
    };
    value
        .validate()
        .is_ok()
        .then_some(value)
        .ok_or(DecodeError::NonCanonical)
}

fn encode_actor_entry(encoder: &mut Encoder<'_>, value: &ActorEntry) {
    encoder.fixed(value.actor.as_bytes());
    encoder.string(&value.name);
    encoder.option(&value.parent, |encoder, value| {
        encoder.fixed(value.as_bytes())
    });
    encoder.fixed(value.deployment.as_bytes());
    encoder.fixed(value.program.as_bytes());
    encode_blob(encoder, &value.package);
    encode_blob(encoder, &value.agent_schema);
    encode_blob(encoder, &value.method_policy);
    encoder.fixed(value.constructor_abi.as_bytes());
    encode_optional_blob(encoder, &value.installation_data);
    encoder.fixed(value.state_layout.as_bytes());
    encoder.u8(value.lanes.bits());
    encoder.bool(value.suspended);
}

fn decode_actor_entry(decoder: &mut Decoder<'_>) -> Result<ActorEntry, DecodeError> {
    let value = ActorEntry {
        actor: ActorId(decoder.fixed()?),
        name: decoder.string_bounded(MAX_ACTOR_NAME_BYTES)?,
        parent: decoder.option(|decoder| Ok(ActorId(decoder.fixed()?)))?,
        deployment: DeploymentId(decoder.fixed()?),
        program: ProgramId(decoder.fixed()?),
        package: decode_blob(decoder)?,
        agent_schema: decode_blob(decoder)?,
        method_policy: decode_blob(decoder)?,
        constructor_abi: Hash(decoder.fixed()?),
        installation_data: decode_optional_blob(decoder)?,
        state_layout: Hash(decoder.fixed()?),
        lanes: LaneSet::from_bits(decoder.u8()?).ok_or(DecodeError::NonCanonical)?,
        suspended: decoder.bool()?,
    };
    value
        .validate()
        .is_ok()
        .then_some(value)
        .ok_or(DecodeError::NonCanonical)
}

impl CanonicalWire for ActorEntry {
    const MAGIC: [u8; 4] = *b"AACT";
    const MAX_ENCODED_BYTES: usize = MAX_ACTOR_ENTRY_WIRE_BYTES;

    fn validate_wire(&self) -> bool {
        self.validate().is_ok()
    }

    fn encode_body(&self, encoder: &mut Encoder<'_>) {
        encode_actor_entry(encoder, self);
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        decode_actor_entry(decoder)
    }
}

fn encode_directory_record(encoder: &mut Encoder<'_>, value: &ActorDirectoryRecord) {
    encode_actor_entry(encoder, &value.entry);
    encoder.fixed(value.incarnation.as_bytes());
    encoder.fixed(value.installation_id.as_bytes());
    encoder.fixed(value.registry_reservation.as_bytes());
}

fn decode_directory_record(decoder: &mut Decoder<'_>) -> Result<ActorDirectoryRecord, DecodeError> {
    let value = ActorDirectoryRecord {
        entry: decode_actor_entry(decoder)?,
        incarnation: Hash(decoder.fixed()?),
        installation_id: InstallationId(decoder.fixed()?),
        registry_reservation: Hash(decoder.fixed()?),
    };
    value
        .validate()
        .is_ok()
        .then_some(value)
        .ok_or(DecodeError::NonCanonical)
}

fn encode_directory_page(encoder: &mut Encoder<'_>, value: &ActorDirectoryPage) {
    encoder.list(&value.entries, encode_directory_record);
    encoder.option(&value.next, |encoder, value| {
        encoder.fixed(value.as_bytes())
    });
}

fn decode_directory_page(decoder: &mut Decoder<'_>) -> Result<ActorDirectoryPage, DecodeError> {
    let value = ActorDirectoryPage {
        entries: decoder.list_bounded(MAX_DIRECTORY_PAGE_ENTRIES, decode_directory_record)?,
        next: decoder.option(|decoder| Ok(ActorId(decoder.fixed()?)))?,
    };
    value
        .validate()
        .is_ok()
        .then_some(value)
        .ok_or(DecodeError::NonCanonical)
}

impl CanonicalWire for ActorDirectoryPage {
    const MAGIC: [u8; 4] = *b"AFST";
    const MAX_ENCODED_BYTES: usize = MAX_DIRECTORY_PAGE_WIRE_BYTES;

    fn validate_wire(&self) -> bool {
        self.validate().is_ok()
    }

    fn encode_body(&self, encoder: &mut Encoder<'_>) {
        encode_directory_page(encoder, self);
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        decode_directory_page(decoder)
    }
}

fn encode_storage_descriptor(encoder: &mut Encoder<'_>, value: &StorageFieldDescriptor) {
    encoder.fixed(value.field.as_bytes());
    encoder.u8(value.kind as u8);
    encoder.bytes(&value.prefix);
    encode_lane(encoder, value.lane);
    encoder.bool(value.committed);
    encoder.fixed(value.key_schema.as_bytes());
    encoder.fixed(value.value_schema.as_bytes());
    encoder.fixed(value.commitment_domain.as_bytes());
}

fn decode_storage_descriptor(
    decoder: &mut Decoder<'_>,
) -> Result<StorageFieldDescriptor, DecodeError> {
    let value = StorageFieldDescriptor {
        field: Hash(decoder.fixed()?),
        kind: match decoder.u8()? {
            0 => StorageKind::Value,
            1 => StorageKind::Map,
            2 => StorageKind::Set,
            3 => StorageKind::Vec,
            _ => return Err(DecodeError::InvalidTag),
        },
        prefix: decoder.bytes_bounded(MAX_STORAGE_PREFIX_BYTES)?,
        lane: decode_lane(decoder)?,
        committed: decoder.bool()?,
        key_schema: Hash(decoder.fixed()?),
        value_schema: Hash(decoder.fixed()?),
        commitment_domain: Hash(decoder.fixed()?),
    };
    value
        .validate()
        .is_ok()
        .then_some(value)
        .ok_or(DecodeError::NonCanonical)
}

impl CanonicalWire for StorageFieldDescriptor {
    const MAGIC: [u8; 4] = *b"ASFD";
    const MAX_ENCODED_BYTES: usize = 512;

    fn validate_wire(&self) -> bool {
        self.validate().is_ok()
    }

    fn encode_body(&self, encoder: &mut Encoder<'_>) {
        encode_storage_descriptor(encoder, self);
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        decode_storage_descriptor(decoder)
    }
}

fn encode_authority_operation(encoder: &mut Encoder<'_>, value: AuthorityOperationKind) {
    encoder.u8(value as u8);
}

fn decode_authority_operation(
    decoder: &mut Decoder<'_>,
) -> Result<AuthorityOperationKind, DecodeError> {
    match decoder.u8()? {
        0 => Ok(AuthorityOperationKind::CreateAgent),
        1 => Ok(AuthorityOperationKind::InstallActor),
        2 => Ok(AuthorityOperationKind::UpgradeActor),
        3 => Ok(AuthorityOperationKind::SuspendActor),
        4 => Ok(AuthorityOperationKind::ResumeActor),
        5 => Ok(AuthorityOperationKind::RemoveActor),
        6 => Ok(AuthorityOperationKind::UpgradeRuntime),
        7 => Ok(AuthorityOperationKind::InvokeActor),
        8 => Ok(AuthorityOperationKind::ChangeReplicaSet),
        9 => Ok(AuthorityOperationKind::InvitePrivateNode),
        10 => Ok(AuthorityOperationKind::RevokePrivateNode),
        11 => Ok(AuthorityOperationKind::RecoverPrivateAgent),
        12 => Ok(AuthorityOperationKind::PublishCatalog),
        _ => Err(DecodeError::InvalidTag),
    }
}

fn encode_authority_issuer(encoder: &mut Encoder<'_>, value: AuthorityIssuer) {
    encoder.fixed(value.principal.as_bytes());
    encoder.fixed(value.actor.as_bytes());
    encoder.fixed(value.deployment.as_bytes());
    encoder.fixed(value.program.as_bytes());
    encoder.fixed(value.producer.as_bytes());
}

fn decode_authority_issuer(decoder: &mut Decoder<'_>) -> Result<AuthorityIssuer, DecodeError> {
    Ok(AuthorityIssuer {
        principal: PrincipalId(decoder.fixed()?),
        actor: ActorId(decoder.fixed()?),
        deployment: DeploymentId(decoder.fixed()?),
        program: ProgramId(decoder.fixed()?),
        producer: ProducerId(decoder.fixed()?),
    })
}

fn encode_lane_roots(encoder: &mut Encoder<'_>, value: AuthorityLaneRoots) {
    encode_optional_hash(encoder, &value.control);
    encode_optional_hash(encoder, &value.linear);
    encode_optional_hash(encoder, &value.merge);
    encode_optional_hash(encoder, &value.local);
}

fn decode_lane_roots(decoder: &mut Decoder<'_>) -> Result<AuthorityLaneRoots, DecodeError> {
    Ok(AuthorityLaneRoots {
        control: decode_optional_hash(decoder)?,
        linear: decode_optional_hash(decoder)?,
        merge: decode_optional_hash(decoder)?,
        local: decode_optional_hash(decoder)?,
    })
}

fn encode_authority_selector(encoder: &mut Encoder<'_>, value: &AuthorityReceiptSelector) {
    encoder.fixed(value.policy.as_bytes());
    encode_authority_issuer(encoder, value.issuer);
    encoder.fixed(value.space.as_bytes());
    encoder.fixed(value.agent.as_bytes());
    encode_authority_operation(encoder, value.operation);
    encoder.fixed(value.runtime_deployment.as_bytes());
    encoder.option(&value.actor, |encoder, value| {
        encoder.fixed(value.as_bytes())
    });
    encoder.option(&value.actor_deployment, |encoder, value| {
        encoder.fixed(value.as_bytes())
    });
    encode_optional_blob(encoder, &value.evidence.package);
    encode_optional_blob(encoder, &value.evidence.proof);
    encoder.fixed(value.evidence.commitment.as_bytes());
    encode_lane_roots(encoder, value.lane_roots);
    encoder.u64(value.epoch);
    encoder.u64(value.valid_from);
    encoder.u64(value.expires_at);
    encoder.fixed(value.request.as_bytes());
}

fn decode_authority_selector(
    decoder: &mut Decoder<'_>,
) -> Result<AuthorityReceiptSelector, DecodeError> {
    let value = AuthorityReceiptSelector {
        policy: Hash(decoder.fixed()?),
        issuer: decode_authority_issuer(decoder)?,
        space: SpaceId(decoder.fixed()?),
        agent: AgentId(decoder.fixed()?),
        operation: decode_authority_operation(decoder)?,
        runtime_deployment: DeploymentId(decoder.fixed()?),
        actor: decoder.option(|decoder| Ok(ActorId(decoder.fixed()?)))?,
        actor_deployment: decoder.option(|decoder| Ok(DeploymentId(decoder.fixed()?)))?,
        evidence: AuthorityEvidence {
            package: decode_optional_blob(decoder)?,
            proof: decode_optional_blob(decoder)?,
            commitment: Hash(decoder.fixed()?),
        },
        lane_roots: decode_lane_roots(decoder)?,
        epoch: decoder.u64()?,
        valid_from: decoder.u64()?,
        expires_at: decoder.u64()?,
        request: Hash(decoder.fixed()?),
    };
    value
        .validate()
        .is_ok()
        .then_some(value)
        .ok_or(DecodeError::NonCanonical)
}

pub(crate) fn authority_signing_bytes(value: &AuthorityReceipt) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"AUSG");
    bytes.extend_from_slice(RUNTIME_ABI_ID.as_bytes());
    let mut encoder = Encoder(&mut bytes);
    encode_authority_selector(&mut encoder, &value.selector);
    encoder.0.extend_from_slice(&value.public_key);
    bytes
}

impl CanonicalWire for AuthorityReceipt {
    const MAGIC: [u8; 4] = *b"AURC";
    const MAX_ENCODED_BYTES: usize = MAX_AUTHORITY_RECEIPT_WIRE_BYTES;

    fn validate_wire(&self) -> bool {
        self.validate_shape().is_ok()
    }

    fn encode_body(&self, encoder: &mut Encoder<'_>) {
        encode_authority_selector(encoder, &self.selector);
        encoder.0.extend_from_slice(&self.public_key);
        encoder.0.extend_from_slice(&self.signature);
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let value = Self {
            selector: decode_authority_selector(decoder)?,
            public_key: decoder
                .take(AUTHORITY_PUBLIC_KEY_BYTES)?
                .try_into()
                .map_err(|_| DecodeError::Truncated)?,
            signature: decoder
                .take(AUTHORITY_SIGNATURE_BYTES)?
                .try_into()
                .map_err(|_| DecodeError::Truncated)?,
        };
        value
            .validate_shape()
            .is_ok()
            .then_some(value)
            .ok_or(DecodeError::NonCanonical)
    }
}

fn install_valid(value: &InstallActor) -> bool {
    value.installation_id != InstallationId::ZERO
        && value.registry_reservation != Hash::ZERO
        && value.entry.validate().is_ok()
        && value.producer != ProducerId::ZERO
        && value.package == value.entry.package
        && value.agent_schema == value.entry.agent_schema
        && value.method_policy == value.entry.method_policy
        && value.constructor_abi == value.entry.constructor_abi
        && value.constructor_abi != Hash::ZERO
        && value.installation_data.as_ref().map(|data| &data.reference)
            == value.entry.installation_data.as_ref()
        && value
            .installation_data
            .as_ref()
            .is_none_or(|data| data.validate().is_ok())
        && value.installation_data.as_ref().is_none_or(|data| {
            [&value.package, &value.agent_schema, &value.method_policy]
                .into_iter()
                .all(|artifact| artifact.hash != data.reference.hash)
        })
        && value.state_layout == value.entry.state_layout
        && value.contract.is_valid()
        && value.requirements.lanes.bits() == value.entry.lanes.bits()
}

fn encode_install(encoder: &mut Encoder<'_>, value: &InstallActor) {
    encoder.fixed(value.installation_id.as_bytes());
    encoder.fixed(value.registry_reservation.as_bytes());
    encode_actor_entry(encoder, &value.entry);
    encoder.fixed(value.producer.as_bytes());
    encode_blob(encoder, &value.package);
    encode_blob(encoder, &value.agent_schema);
    encode_blob(encoder, &value.method_policy);
    encoder.fixed(value.constructor_abi.as_bytes());
    encoder.option(&value.installation_data, encode_installation_data);
    encoder.fixed(value.state_layout.as_bytes());
    encode_actor_contract(encoder, value.contract);
    encode_requirements(encoder, value.requirements);
}

fn decode_install(decoder: &mut Decoder<'_>) -> Result<InstallActor, DecodeError> {
    let value = InstallActor {
        installation_id: InstallationId(decoder.fixed()?),
        registry_reservation: Hash(decoder.fixed()?),
        entry: decode_actor_entry(decoder)?,
        producer: ProducerId(decoder.fixed()?),
        package: decode_blob(decoder)?,
        agent_schema: decode_blob(decoder)?,
        method_policy: decode_blob(decoder)?,
        constructor_abi: Hash(decoder.fixed()?),
        installation_data: decoder.option(decode_installation_data)?,
        state_layout: Hash(decoder.fixed()?),
        contract: decode_actor_contract(decoder)?,
        requirements: decode_requirements(decoder)?,
    };
    install_valid(&value)
        .then_some(value)
        .ok_or(DecodeError::NonCanonical)
}

fn upgrade_actor_valid(value: &UpgradeActor) -> bool {
    value.actor != ActorId::ZERO
        && value.from_deployment != DeploymentId::ZERO
        && value.to_deployment != DeploymentId::ZERO
        && value.from_deployment != value.to_deployment
        && value.to_program != ProgramId::ZERO
        && value.producer != ProducerId::ZERO
        && crate::model::valid_blob(&value.package)
        && crate::model::valid_blob(&value.agent_schema)
        && crate::model::valid_blob(&value.method_policy)
        && value.constructor_abi != Hash::ZERO
        && value.state_layout != Hash::ZERO
        && value.contract.is_valid()
}

fn encode_upgrade_actor(encoder: &mut Encoder<'_>, value: &UpgradeActor) {
    encoder.fixed(value.actor.as_bytes());
    encoder.fixed(value.from_deployment.as_bytes());
    encoder.fixed(value.to_deployment.as_bytes());
    encoder.fixed(value.to_program.as_bytes());
    encoder.fixed(value.producer.as_bytes());
    encode_blob(encoder, &value.package);
    encode_blob(encoder, &value.agent_schema);
    encode_blob(encoder, &value.method_policy);
    encoder.fixed(value.constructor_abi.as_bytes());
    encoder.fixed(value.state_layout.as_bytes());
    encode_actor_contract(encoder, value.contract);
    encode_requirements(encoder, value.requirements);
}

fn decode_upgrade_actor(decoder: &mut Decoder<'_>) -> Result<UpgradeActor, DecodeError> {
    let value = UpgradeActor {
        actor: ActorId(decoder.fixed()?),
        from_deployment: DeploymentId(decoder.fixed()?),
        to_deployment: DeploymentId(decoder.fixed()?),
        to_program: ProgramId(decoder.fixed()?),
        producer: ProducerId(decoder.fixed()?),
        package: decode_blob(decoder)?,
        agent_schema: decode_blob(decoder)?,
        method_policy: decode_blob(decoder)?,
        constructor_abi: Hash(decoder.fixed()?),
        state_layout: Hash(decoder.fixed()?),
        contract: decode_actor_contract(decoder)?,
        requirements: decode_requirements(decoder)?,
    };
    upgrade_actor_valid(&value)
        .then_some(value)
        .ok_or(DecodeError::NonCanonical)
}

fn runtime_upgrade_valid(value: &RuntimeUpgrade) -> bool {
    value.from_deployment != DeploymentId::ZERO
        && value.to_deployment != DeploymentId::ZERO
        && value.from_deployment != value.to_deployment
        && value.to_program != ProgramId::ZERO
        && value.producer != ProducerId::ZERO
        && crate::model::valid_blob(&value.package)
        && value.contract.is_valid()
        && value.capabilities.max_actors != 0
        && value.capabilities.max_actors <= STANDARD_MAX_ACTORS
}

fn encode_runtime_upgrade(encoder: &mut Encoder<'_>, value: &RuntimeUpgrade) {
    encoder.fixed(value.from_deployment.as_bytes());
    encoder.fixed(value.to_deployment.as_bytes());
    encoder.fixed(value.to_program.as_bytes());
    encoder.fixed(value.producer.as_bytes());
    encode_blob(encoder, &value.package);
    encode_runtime_contract(encoder, value.contract);
    encode_capabilities(encoder, value.capabilities);
}

fn decode_runtime_upgrade(decoder: &mut Decoder<'_>) -> Result<RuntimeUpgrade, DecodeError> {
    let value = RuntimeUpgrade {
        from_deployment: DeploymentId(decoder.fixed()?),
        to_deployment: DeploymentId(decoder.fixed()?),
        to_program: ProgramId(decoder.fixed()?),
        producer: ProducerId(decoder.fixed()?),
        package: decode_blob(decoder)?,
        contract: decode_runtime_contract(decoder)?,
        capabilities: decode_capabilities(decoder)?,
    };
    runtime_upgrade_valid(&value)
        .then_some(value)
        .ok_or(DecodeError::NonCanonical)
}

fn replica_set_valid(replicas: &[AgentReplica]) -> bool {
    !replicas.is_empty()
        && replicas.len() <= MAX_AGENT_REPLICAS
        && replicas
            .iter()
            .all(|replica| replica.node != NodeId::ZERO && replica.principal != PrincipalId::ZERO)
        && replicas.windows(2).all(|pair| pair[0].node < pair[1].node)
}

fn management_request_valid(value: &ManagementRequest) -> bool {
    match value {
        ManagementRequest::Create(descriptor) => descriptor.validate().is_ok(),
        ManagementRequest::InspectActors { after, limit } => {
            *limit != 0
                && usize::from(*limit) <= MAX_DIRECTORY_PAGE_ENTRIES
                && *after != Some(ActorId::ZERO)
        }
        ManagementRequest::InspectResources => true,
        ManagementRequest::Install(value) => install_valid(value),
        ManagementRequest::UpgradeActor(value) => upgrade_actor_valid(value),
        ManagementRequest::Suspend {
            actor,
            expected_deployment,
        }
        | ManagementRequest::Resume {
            actor,
            expected_deployment,
        }
        | ManagementRequest::RemoveLeaf {
            actor,
            expected_deployment,
        } => *actor != ActorId::ZERO && *expected_deployment != DeploymentId::ZERO,
        ManagementRequest::UpgradeRuntime(value) => runtime_upgrade_valid(value),
        ManagementRequest::ChangeReplicas {
            expected_generation,
            replicas,
        } => *expected_generation != Hash::ZERO && replica_set_valid(replicas),
    }
}

fn encode_management_request(encoder: &mut Encoder<'_>, value: &ManagementRequest) {
    match value {
        ManagementRequest::Create(value) => {
            encoder.u8(0);
            encode_agent_descriptor(encoder, value);
        }
        ManagementRequest::InspectActors { after, limit } => {
            encoder.u8(1);
            encoder.option(after, |encoder, value| encoder.fixed(value.as_bytes()));
            encoder.u16(*limit);
        }
        ManagementRequest::InspectResources => encoder.u8(2),
        ManagementRequest::Install(value) => {
            encoder.u8(3);
            encode_install(encoder, value);
        }
        ManagementRequest::UpgradeActor(value) => {
            encoder.u8(4);
            encode_upgrade_actor(encoder, value);
        }
        ManagementRequest::Suspend {
            actor,
            expected_deployment,
        } => {
            encoder.u8(5);
            encoder.fixed(actor.as_bytes());
            encoder.fixed(expected_deployment.as_bytes());
        }
        ManagementRequest::Resume {
            actor,
            expected_deployment,
        } => {
            encoder.u8(6);
            encoder.fixed(actor.as_bytes());
            encoder.fixed(expected_deployment.as_bytes());
        }
        ManagementRequest::RemoveLeaf {
            actor,
            expected_deployment,
        } => {
            encoder.u8(7);
            encoder.fixed(actor.as_bytes());
            encoder.fixed(expected_deployment.as_bytes());
        }
        ManagementRequest::UpgradeRuntime(value) => {
            encoder.u8(8);
            encode_runtime_upgrade(encoder, value);
        }
        ManagementRequest::ChangeReplicas {
            expected_generation,
            replicas,
        } => {
            encoder.u8(9);
            encoder.fixed(expected_generation.as_bytes());
            encoder.list(replicas, encode_replica);
        }
    }
}

fn decode_management_request(decoder: &mut Decoder<'_>) -> Result<ManagementRequest, DecodeError> {
    let value = match decoder.u8()? {
        0 => ManagementRequest::Create(alloc::boxed::Box::new(decode_agent_descriptor(decoder)?)),
        1 => ManagementRequest::InspectActors {
            after: decoder.option(|decoder| Ok(ActorId(decoder.fixed()?)))?,
            limit: decoder.u16()?,
        },
        2 => ManagementRequest::InspectResources,
        3 => ManagementRequest::Install(alloc::boxed::Box::new(decode_install(decoder)?)),
        4 => {
            ManagementRequest::UpgradeActor(alloc::boxed::Box::new(decode_upgrade_actor(decoder)?))
        }
        5 => ManagementRequest::Suspend {
            actor: ActorId(decoder.fixed()?),
            expected_deployment: DeploymentId(decoder.fixed()?),
        },
        6 => ManagementRequest::Resume {
            actor: ActorId(decoder.fixed()?),
            expected_deployment: DeploymentId(decoder.fixed()?),
        },
        7 => ManagementRequest::RemoveLeaf {
            actor: ActorId(decoder.fixed()?),
            expected_deployment: DeploymentId(decoder.fixed()?),
        },
        8 => ManagementRequest::UpgradeRuntime(alloc::boxed::Box::new(decode_runtime_upgrade(
            decoder,
        )?)),
        9 => ManagementRequest::ChangeReplicas {
            expected_generation: Hash(decoder.fixed()?),
            replicas: decoder.list_bounded(MAX_AGENT_REPLICAS, decode_replica)?,
        },
        _ => return Err(DecodeError::InvalidTag),
    };
    management_request_valid(&value)
        .then_some(value)
        .ok_or(DecodeError::NonCanonical)
}

pub(crate) fn management_request_commitment(value: &ManagementRequest) -> Hash {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"AMRQ");
    bytes.extend_from_slice(RUNTIME_ABI_ID.as_bytes());
    encode_management_request(&mut Encoder(&mut bytes), value);
    Hash::digest(b"vos/agent/management-request", &[&bytes])
}

fn required_operation(value: &ManagementRequest) -> Option<AuthorityOperationKind> {
    match value {
        ManagementRequest::Create(_) => Some(AuthorityOperationKind::CreateAgent),
        ManagementRequest::InspectActors { .. } | ManagementRequest::InspectResources => None,
        ManagementRequest::Install(_) => Some(AuthorityOperationKind::InstallActor),
        ManagementRequest::UpgradeActor(_) => Some(AuthorityOperationKind::UpgradeActor),
        ManagementRequest::Suspend { .. } => Some(AuthorityOperationKind::SuspendActor),
        ManagementRequest::Resume { .. } => Some(AuthorityOperationKind::ResumeActor),
        ManagementRequest::RemoveLeaf { .. } => Some(AuthorityOperationKind::RemoveActor),
        ManagementRequest::UpgradeRuntime(_) => Some(AuthorityOperationKind::UpgradeRuntime),
        ManagementRequest::ChangeReplicas { .. } => Some(AuthorityOperationKind::ChangeReplicaSet),
    }
}

fn management_actor(value: &ManagementRequest) -> Option<(ActorId, DeploymentId)> {
    match value {
        ManagementRequest::Install(value) => Some((value.entry.actor, value.entry.deployment)),
        ManagementRequest::UpgradeActor(value) => Some((value.actor, value.to_deployment)),
        ManagementRequest::Suspend {
            actor,
            expected_deployment,
        }
        | ManagementRequest::Resume {
            actor,
            expected_deployment,
        }
        | ManagementRequest::RemoveLeaf {
            actor,
            expected_deployment,
        } => Some((*actor, *expected_deployment)),
        _ => None,
    }
}

fn authority_matches_management(
    receipt: &AuthorityReceipt,
    space: SpaceId,
    agent: AgentId,
    runtime_deployment: DeploymentId,
    request: &ManagementRequest,
    observed_slot: u64,
) -> bool {
    receipt.validate_shape().is_ok()
        && receipt.selector.space == space
        && receipt.selector.agent == agent
        && receipt.selector.runtime_deployment == runtime_deployment
        && Some(receipt.selector.operation) == required_operation(request)
        && receipt.selector.request == management_request_commitment(request)
        && receipt.selector.is_live_at(observed_slot)
        && match (
            management_actor(request),
            receipt.selector.actor,
            receipt.selector.actor_deployment,
        ) {
            (Some((actor, deployment)), Some(receipt_actor), Some(receipt_deployment)) => {
                actor == receipt_actor && deployment == receipt_deployment
            }
            (None, None, None) => true,
            _ => false,
        }
}

fn encode_runtime_state(encoder: &mut Encoder<'_>, value: &RuntimeState) {
    encoder.bytes(&value.control);
    encoder.bytes(&value.linear);
    encoder.bytes(&value.merge);
    encoder.bytes(&value.local);
}

fn decode_runtime_state(decoder: &mut Decoder<'_>) -> Result<RuntimeState, DecodeError> {
    let control = decoder.bytes_bounded(MAX_RUNTIME_STATE_BYTES)?;
    let mut remaining = MAX_RUNTIME_STATE_BYTES - control.len();
    let linear = decoder.bytes_bounded(remaining)?;
    remaining -= linear.len();
    let merge = decoder.bytes_bounded(remaining)?;
    remaining -= merge.len();
    let local = decoder.bytes_bounded(remaining)?;
    let value = RuntimeState {
        control,
        linear,
        merge,
        local,
    };
    value
        .validate()
        .then_some(value)
        .ok_or(DecodeError::LimitExceeded)
}

fn encode_origin(encoder: &mut Encoder<'_>, value: InvocationOrigin) {
    encoder.option(&value.principal, |encoder, value| {
        encoder.fixed(value.as_bytes())
    });
    encoder.option(&value.transport_node, |encoder, value| {
        encoder.fixed(value.as_bytes())
    });
    encoder.option(&value.credential, |encoder, value| {
        encoder.fixed(value.as_bytes())
    });
    encoder.option(&value.actor, |encoder, value| {
        encoder.fixed(value.as_bytes())
    });
    encoder.option(&value.capability, |encoder, value| {
        encoder.fixed(value.as_bytes())
    });
}

fn decode_origin(decoder: &mut Decoder<'_>) -> Result<InvocationOrigin, DecodeError> {
    let value = InvocationOrigin {
        principal: decoder.option(|decoder| Ok(PrincipalId(decoder.fixed()?)))?,
        transport_node: decoder.option(|decoder| Ok(NodeId(decoder.fixed()?)))?,
        credential: decoder.option(|decoder| Ok(CredentialId(decoder.fixed()?)))?,
        actor: decoder.option(|decoder| Ok(ActorId(decoder.fixed()?)))?,
        capability: decoder.option(|decoder| Ok(CapabilityId(decoder.fixed()?)))?,
    };
    value
        .validate()
        .then_some(value)
        .ok_or(DecodeError::NonCanonical)
}

fn encode_runtime_blob(encoder: &mut Encoder<'_>, value: &RuntimeBlob) {
    encode_blob(encoder, &value.reference);
    encoder.bytes(&value.bytes);
}

fn decode_runtime_availability(decoder: &mut Decoder<'_>) -> Result<Vec<RuntimeBlob>, DecodeError> {
    let mut remaining = MAX_RUNTIME_AVAILABILITY_BYTES;
    decoder.list_bounded(MAX_RUNTIME_AVAILABILITY_ITEMS, |decoder| {
        let reference = decode_blob(decoder)?;
        let bytes = decoder.bytes_bounded(remaining)?;
        remaining -= bytes.len();
        let value = RuntimeBlob { reference, bytes };
        value
            .validate()
            .then_some(value)
            .ok_or(DecodeError::NonCanonical)
    })
}

fn encode_required_refs(encoder: &mut Encoder<'_>, values: &[BlobRef]) {
    encoder.list(values, encode_blob);
}

fn decode_required_refs(
    decoder: &mut Decoder<'_>,
    installation_data: Option<&BlobRef>,
) -> Result<Vec<BlobRef>, DecodeError> {
    let values = decoder.list_bounded(MAX_RUNTIME_AVAILABILITY_ITEMS, decode_blob)?;
    let valid = values.iter().all(|reference| {
        reference.hash != Hash::ZERO
            && (reference.len != 0 || installation_data == Some(reference))
            && reference.len <= MAX_RUNTIME_AVAILABILITY_BYTES as u64
    }) && installation_data
        .is_none_or(|required| values.iter().any(|value| value == required))
        && values.windows(2).all(|pair| pair[0] < pair[1])
        && values
            .iter()
            .try_fold(0u64, |total, reference| total.checked_add(reference.len))
            .is_some_and(|total| total <= MAX_RUNTIME_AVAILABILITY_BYTES as u64);
    valid.then_some(values).ok_or(DecodeError::NonCanonical)
}

fn encode_invocation_work(encoder: &mut Encoder<'_>, value: &InvocationWork) {
    encoder.fixed(value.space.as_bytes());
    encoder.fixed(value.agent.as_bytes());
    encoder.fixed(value.runtime_deployment.as_bytes());
    encoder.fixed(value.invocation.as_bytes());
    encoder.fixed(value.actor.as_bytes());
    encoder.fixed(value.incarnation.as_bytes());
    encoder.fixed(value.deployment.as_bytes());
    encoder.fixed(value.program.as_bytes());
    encoder.u8(value.mode as u8);
    encode_origin(encoder, value.origin);
    encoder.bytes(&value.message);
    encode_optional_blob(encoder, &value.installation_data);
    encoder.list(&value.availability, encode_runtime_blob);
    encoder.u64(value.gas);
    encoder.bool(value.recovery_only);
}

fn decode_invocation_work(decoder: &mut Decoder<'_>) -> Result<InvocationWork, DecodeError> {
    let value = InvocationWork {
        space: SpaceId(decoder.fixed()?),
        agent: AgentId(decoder.fixed()?),
        runtime_deployment: DeploymentId(decoder.fixed()?),
        invocation: InvocationId(decoder.fixed()?),
        actor: ActorId(decoder.fixed()?),
        incarnation: Hash(decoder.fixed()?),
        deployment: DeploymentId(decoder.fixed()?),
        program: ProgramId(decoder.fixed()?),
        mode: decode_method_mode(decoder)?,
        origin: decode_origin(decoder)?,
        message: decoder.bytes_bounded(MAX_INVOCATION_MESSAGE_BYTES)?,
        installation_data: decode_optional_blob(decoder)?,
        availability: decode_runtime_availability(decoder)?,
        gas: decoder.u64()?,
        recovery_only: decoder.bool()?,
    };
    value
        .validate()
        .then_some(value)
        .ok_or(DecodeError::NonCanonical)
}

pub(crate) fn invocation_work_commitment(value: &InvocationWork) -> Hash {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"AINV");
    bytes.extend_from_slice(RUNTIME_ABI_ID.as_bytes());
    encode_invocation_work(&mut Encoder(&mut bytes), value);
    Hash::digest(b"vos/agent/invocation", &[&bytes])
}

fn authority_matches_invocation(
    receipt: &AuthorityReceipt,
    invocation: &InvocationWork,
    _observed_slot: u64,
) -> bool {
    receipt.validate_shape().is_ok()
        && receipt.selector.operation == AuthorityOperationKind::InvokeActor
        && receipt.selector.space == invocation.space
        && receipt.selector.agent == invocation.agent
        && receipt.selector.runtime_deployment == invocation.runtime_deployment
        && receipt.selector.actor == Some(invocation.actor)
        && receipt.selector.actor_deployment == Some(invocation.deployment)
        && receipt.selector.request == invocation_work_commitment(invocation)
}

fn encode_resume_input(encoder: &mut Encoder<'_>, value: &ResumeInput) {
    match value {
        ResumeInput::Ready(bytes) => {
            encoder.u8(0);
            encoder.bytes(bytes);
        }
        ResumeInput::Failed(code) => {
            encoder.u8(1);
            encoder.u32(*code);
        }
    }
}

fn decode_resume_input(decoder: &mut Decoder<'_>) -> Result<ResumeInput, DecodeError> {
    let value = match decoder.u8()? {
        0 => ResumeInput::Ready(decoder.bytes_bounded(MAX_RESUME_INPUT_BYTES)?),
        1 => ResumeInput::Failed(decoder.u32()?),
        _ => return Err(DecodeError::InvalidTag),
    };
    value
        .validate()
        .then_some(value)
        .ok_or(DecodeError::NonCanonical)
}

fn encode_resume_work(encoder: &mut Encoder<'_>, value: &ResumeWork) {
    encoder.fixed(value.invocation.as_bytes());
    encoder.fixed(value.actor.as_bytes());
    encoder.fixed(value.incarnation.as_bytes());
    encoder.fixed(value.deployment.as_bytes());
    encoder.fixed(value.program.as_bytes());
    encoder.u8(value.mode as u8);
    encode_blob(encoder, &value.continuation);
    encoder.u64(value.ready_sequence);
    encode_optional_blob(encoder, &value.installation_data);
    encoder.list(&value.availability, encode_runtime_blob);
    encoder.option(&value.input, encode_resume_input);
}

fn decode_resume_work(decoder: &mut Decoder<'_>) -> Result<ResumeWork, DecodeError> {
    let value = ResumeWork {
        invocation: InvocationId(decoder.fixed()?),
        actor: ActorId(decoder.fixed()?),
        incarnation: Hash(decoder.fixed()?),
        deployment: DeploymentId(decoder.fixed()?),
        program: ProgramId(decoder.fixed()?),
        mode: decode_method_mode(decoder)?,
        continuation: decode_blob(decoder)?,
        ready_sequence: decoder.u64()?,
        installation_data: decode_optional_blob(decoder)?,
        availability: decode_runtime_availability(decoder)?,
        input: decoder.option(decode_resume_input)?,
    };
    value
        .validate()
        .then_some(value)
        .ok_or(DecodeError::NonCanonical)
}

fn runtime_work_valid(value: &RuntimeWork) -> bool {
    match value {
        RuntimeWork::Manage {
            space,
            agent,
            runtime_deployment,
            state,
            request,
            authority,
            observed_slot,
        } => {
            if *space == SpaceId::ZERO
                || *agent == AgentId::ZERO
                || *runtime_deployment == DeploymentId::ZERO
                || !state.validate()
                || !management_request_valid(request)
            {
                return false;
            }
            if let ManagementRequest::Create(descriptor) = request.as_ref() {
                if !state.is_empty()
                    || descriptor.identity.space != *space
                    || descriptor.identity.agent != *agent
                    || descriptor.identity.runtime_deployment != *runtime_deployment
                {
                    return false;
                }
            }
            match (required_operation(request), authority) {
                (None, None) => true,
                (None, Some(_)) => false,
                (Some(_), Some(receipt)) => authority_matches_management(
                    receipt,
                    *space,
                    *agent,
                    *runtime_deployment,
                    request,
                    *observed_slot,
                ),
                (Some(_), None) => false,
            }
        }
        RuntimeWork::Invoke {
            state,
            invocation,
            authority,
            observed_slot,
        } => {
            state.validate()
                && invocation.validate()
                && authority_matches_invocation(authority, invocation, *observed_slot)
        }
        RuntimeWork::Resume { state, resume } => state.validate() && resume.validate(),
    }
}

impl CanonicalWire for RuntimeWork {
    const MAGIC: [u8; 4] = *b"AWRK";
    const MAX_ENCODED_BYTES: usize = MAX_RUNTIME_WORK_WIRE_BYTES;

    fn validate_wire(&self) -> bool {
        runtime_work_valid(self)
    }

    fn encode_body(&self, encoder: &mut Encoder<'_>) {
        match self {
            RuntimeWork::Manage {
                space,
                agent,
                runtime_deployment,
                state,
                request,
                authority,
                observed_slot,
            } => {
                encoder.u8(0);
                encoder.fixed(space.as_bytes());
                encoder.fixed(agent.as_bytes());
                encoder.fixed(runtime_deployment.as_bytes());
                encode_runtime_state(encoder, state);
                encode_management_request(encoder, request);
                encoder.option(authority, |encoder, value| {
                    <AuthorityReceipt as CanonicalWire>::encode_body(value, encoder)
                });
                encoder.u64(*observed_slot);
            }
            RuntimeWork::Invoke {
                state,
                invocation,
                authority,
                observed_slot,
            } => {
                encoder.u8(1);
                encode_runtime_state(encoder, state);
                encode_invocation_work(encoder, invocation);
                <AuthorityReceipt as CanonicalWire>::encode_body(authority, encoder);
                encoder.u64(*observed_slot);
            }
            RuntimeWork::Resume { state, resume } => {
                encoder.u8(2);
                encode_runtime_state(encoder, state);
                encode_resume_work(encoder, resume);
            }
        }
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let value = match decoder.u8()? {
            0 => RuntimeWork::Manage {
                space: SpaceId(decoder.fixed()?),
                agent: AgentId(decoder.fixed()?),
                runtime_deployment: DeploymentId(decoder.fixed()?),
                state: decode_runtime_state(decoder)?,
                request: alloc::boxed::Box::new(decode_management_request(decoder)?),
                authority: decoder
                    .option(<AuthorityReceipt as CanonicalWire>::decode_body)?
                    .map(alloc::boxed::Box::new),
                observed_slot: decoder.u64()?,
            },
            1 => RuntimeWork::Invoke {
                state: decode_runtime_state(decoder)?,
                invocation: alloc::boxed::Box::new(decode_invocation_work(decoder)?),
                authority: alloc::boxed::Box::new(
                    <AuthorityReceipt as CanonicalWire>::decode_body(decoder)?,
                ),
                observed_slot: decoder.u64()?,
            },
            2 => RuntimeWork::Resume {
                state: decode_runtime_state(decoder)?,
                resume: alloc::boxed::Box::new(decode_resume_work(decoder)?),
            },
            _ => return Err(DecodeError::InvalidTag),
        };
        runtime_work_valid(&value)
            .then_some(value)
            .ok_or(DecodeError::NonCanonical)
    }
}

fn encode_lifecycle_debt(encoder: &mut Encoder<'_>, value: ActorLifecycleDebt) {
    encoder.u32(value.children);
    encoder.u32(value.continuations);
    encoder.u32(value.inbox);
    encoder.u32(value.outbox);
    encoder.u32(value.schedules);
    encoder.u32(value.proof_artifacts);
    encoder.u32(value.lifecycle_operations);
}

fn decode_lifecycle_debt(decoder: &mut Decoder<'_>) -> Result<ActorLifecycleDebt, DecodeError> {
    Ok(ActorLifecycleDebt {
        children: decoder.u32()?,
        continuations: decoder.u32()?,
        inbox: decoder.u32()?,
        outbox: decoder.u32()?,
        schedules: decoder.u32()?,
        proof_artifacts: decoder.u32()?,
        lifecycle_operations: decoder.u32()?,
    })
}

fn encode_resource_usage(encoder: &mut Encoder<'_>, value: RuntimeResourceUsage) {
    encoder.u32(value.actors);
    encoder.u8(value.active_machines);
    encoder.u32(value.continuations);
    encoder.u32(value.inbox);
    encoder.u32(value.outbox);
    encoder.u32(value.schedules);
    encoder.u32(value.proof_artifacts);
    encoder.u32(value.state_bytes);
}

fn decode_resource_usage(decoder: &mut Decoder<'_>) -> Result<RuntimeResourceUsage, DecodeError> {
    let value = RuntimeResourceUsage {
        actors: decoder.u32()?,
        active_machines: decoder.u8()?,
        continuations: decoder.u32()?,
        inbox: decoder.u32()?,
        outbox: decoder.u32()?,
        schedules: decoder.u32()?,
        proof_artifacts: decoder.u32()?,
        state_bytes: decoder.u32()?,
    };
    if value.actors > STANDARD_MAX_ACTORS
        || value.active_machines > 63
        || value.state_bytes as usize > MAX_RUNTIME_STATE_BYTES
    {
        return Err(DecodeError::NonCanonical);
    }
    Ok(value)
}

fn identity_valid(value: &AgentIdentity) -> bool {
    value.space != SpaceId::ZERO
        && value.agent != AgentId::ZERO
        && value.owner != PrincipalId::ZERO
        && value.runtime_deployment != DeploymentId::ZERO
        && value.runtime_program != ProgramId::ZERO
        && value.runtime_producer != ProducerId::ZERO
}

fn management_reply_valid(value: &ManagementReply) -> bool {
    match value {
        ManagementReply::Created(identity) | ManagementReply::RuntimeUpgraded(identity) => {
            identity_valid(identity)
        }
        ManagementReply::Actors(page) => page.validate().is_ok(),
        ManagementReply::Resources(usage) => {
            usage.actors <= STANDARD_MAX_ACTORS
                && usage.active_machines <= 63
                && usage.state_bytes as usize <= MAX_RUNTIME_STATE_BYTES
        }
        ManagementReply::Installed(entry)
        | ManagementReply::Upgraded(entry)
        | ManagementReply::Suspended(entry)
        | ManagementReply::Resumed(entry) => entry.validate().is_ok(),
        ManagementReply::Removed(actor) => *actor != ActorId::ZERO,
        ManagementReply::ReplicasChanged { generation } => *generation != Hash::ZERO,
    }
}

fn encode_management_reply(encoder: &mut Encoder<'_>, value: &ManagementReply) {
    match value {
        ManagementReply::Created(value) => {
            encoder.u8(0);
            encode_agent_identity(encoder, value);
        }
        ManagementReply::Actors(value) => {
            encoder.u8(1);
            encode_directory_page(encoder, value);
        }
        ManagementReply::Resources(value) => {
            encoder.u8(2);
            encode_resource_usage(encoder, *value);
        }
        ManagementReply::Installed(value) => {
            encoder.u8(3);
            encode_actor_entry(encoder, value);
        }
        ManagementReply::Upgraded(value) => {
            encoder.u8(4);
            encode_actor_entry(encoder, value);
        }
        ManagementReply::Suspended(value) => {
            encoder.u8(5);
            encode_actor_entry(encoder, value);
        }
        ManagementReply::Resumed(value) => {
            encoder.u8(6);
            encode_actor_entry(encoder, value);
        }
        ManagementReply::Removed(value) => {
            encoder.u8(7);
            encoder.fixed(value.as_bytes());
        }
        ManagementReply::RuntimeUpgraded(value) => {
            encoder.u8(8);
            encode_agent_identity(encoder, value);
        }
        ManagementReply::ReplicasChanged { generation } => {
            encoder.u8(9);
            encoder.fixed(generation.as_bytes());
        }
    }
}

fn decode_management_reply(decoder: &mut Decoder<'_>) -> Result<ManagementReply, DecodeError> {
    let value = match decoder.u8()? {
        0 => ManagementReply::Created(decode_agent_identity(decoder)?),
        1 => ManagementReply::Actors(decode_directory_page(decoder)?),
        2 => ManagementReply::Resources(decode_resource_usage(decoder)?),
        3 => ManagementReply::Installed(decode_actor_entry(decoder)?),
        4 => ManagementReply::Upgraded(decode_actor_entry(decoder)?),
        5 => ManagementReply::Suspended(decode_actor_entry(decoder)?),
        6 => ManagementReply::Resumed(decode_actor_entry(decoder)?),
        7 => ManagementReply::Removed(ActorId(decoder.fixed()?)),
        8 => ManagementReply::RuntimeUpgraded(decode_agent_identity(decoder)?),
        9 => ManagementReply::ReplicasChanged {
            generation: Hash(decoder.fixed()?),
        },
        _ => return Err(DecodeError::InvalidTag),
    };
    management_reply_valid(&value)
        .then_some(value)
        .ok_or(DecodeError::NonCanonical)
}

fn encode_management_error(encoder: &mut Encoder<'_>, value: ManagementError) {
    match value {
        ManagementError::NotCreated => encoder.u8(0),
        ManagementError::AlreadyCreated => encoder.u8(1),
        ManagementError::NotFound => encoder.u8(2),
        ManagementError::AlreadyExists => encoder.u8(3),
        ManagementError::StaleDeployment => encoder.u8(4),
        ManagementError::UnsupportedRuntime => encoder.u8(5),
        ManagementError::UnsupportedLane => encoder.u8(6),
        ManagementError::Busy(debt) => {
            encoder.u8(7);
            encode_lifecycle_debt(encoder, debt);
        }
        ManagementError::DirectoryFull => encoder.u8(8),
        ManagementError::InvalidRequest => encoder.u8(9),
        ManagementError::AuthoritySequenceRegressed => encoder.u8(10),
        ManagementError::AuthoritySequenceConflict => encoder.u8(11),
        ManagementError::AuthoritySlotRegressed => encoder.u8(12),
        ManagementError::ResourceLimit => encoder.u8(13),
    }
}

fn decode_management_error(decoder: &mut Decoder<'_>) -> Result<ManagementError, DecodeError> {
    match decoder.u8()? {
        0 => Ok(ManagementError::NotCreated),
        1 => Ok(ManagementError::AlreadyCreated),
        2 => Ok(ManagementError::NotFound),
        3 => Ok(ManagementError::AlreadyExists),
        4 => Ok(ManagementError::StaleDeployment),
        5 => Ok(ManagementError::UnsupportedRuntime),
        6 => Ok(ManagementError::UnsupportedLane),
        7 => Ok(ManagementError::Busy(decode_lifecycle_debt(decoder)?)),
        8 => Ok(ManagementError::DirectoryFull),
        9 => Ok(ManagementError::InvalidRequest),
        10 => Ok(ManagementError::AuthoritySequenceRegressed),
        11 => Ok(ManagementError::AuthoritySequenceConflict),
        12 => Ok(ManagementError::AuthoritySlotRegressed),
        13 => Ok(ManagementError::ResourceLimit),
        _ => Err(DecodeError::InvalidTag),
    }
}

fn encode_observation(encoder: &mut Encoder<'_>, value: InvocationObservation) {
    encoder.option(&value.linear_revision, |encoder, value| encoder.u64(*value));
    encode_optional_hash(encoder, &value.merge_frontier);
    encoder.option(&value.local_revision, |encoder, value| encoder.u64(*value));
}

fn decode_observation(decoder: &mut Decoder<'_>) -> Result<InvocationObservation, DecodeError> {
    let value = InvocationObservation {
        linear_revision: decoder.option(|decoder| decoder.u64())?,
        merge_frontier: decode_optional_hash(decoder)?,
        local_revision: decoder.option(|decoder| decoder.u64())?,
    };
    if value.merge_frontier == Some(Hash::ZERO) {
        return Err(DecodeError::NonCanonical);
    }
    Ok(value)
}

fn invocation_reply_valid(value: &InvocationReply) -> bool {
    value.invocation != InvocationId::ZERO
        && value.actor != ActorId::ZERO
        && value.incarnation != Hash::ZERO
        && value.deployment != DeploymentId::ZERO
        && value.lane == value.mode.write_lane()
        && value.reply.len() <= MAX_INVOCATION_REPLY_BYTES
        && value.observation.merge_frontier != Some(Hash::ZERO)
}

fn encode_invocation_reply(encoder: &mut Encoder<'_>, value: &InvocationReply) {
    encoder.fixed(value.invocation.as_bytes());
    encoder.fixed(value.actor.as_bytes());
    encoder.fixed(value.incarnation.as_bytes());
    encoder.fixed(value.deployment.as_bytes());
    encoder.u8(value.mode as u8);
    encoder.option(&value.lane, |encoder, value| encode_lane(encoder, *value));
    encoder.u8(value.status as u8);
    encoder.bytes(&value.reply);
    encoder.u64(value.gas_remaining);
    encode_observation(encoder, value.observation);
}

fn decode_invocation_reply(decoder: &mut Decoder<'_>) -> Result<InvocationReply, DecodeError> {
    let value = InvocationReply {
        invocation: InvocationId(decoder.fixed()?),
        actor: ActorId(decoder.fixed()?),
        incarnation: Hash(decoder.fixed()?),
        deployment: DeploymentId(decoder.fixed()?),
        mode: decode_method_mode(decoder)?,
        lane: decoder.option(decode_lane)?,
        status: match decoder.u8()? {
            0 => InvocationStatus::Done,
            1 => InvocationStatus::Forbidden,
            2 => InvocationStatus::Panicked,
            3 => InvocationStatus::OutOfGas,
            _ => return Err(DecodeError::InvalidTag),
        },
        reply: decoder.bytes_bounded(MAX_INVOCATION_REPLY_BYTES)?,
        gas_remaining: decoder.u64()?,
        observation: decode_observation(decoder)?,
    };
    invocation_reply_valid(&value)
        .then_some(value)
        .ok_or(DecodeError::NonCanonical)
}

fn encode_invocation_error(encoder: &mut Encoder<'_>, value: InvocationError) {
    match value {
        InvocationError::NotCreated => encoder.u8(0),
        InvocationError::NotFound => encoder.u8(1),
        InvocationError::StaleIncarnation => encoder.u8(2),
        InvocationError::Suspended => encoder.u8(3),
        InvocationError::StaleDeployment => encoder.u8(4),
        InvocationError::WrongProgram => encoder.u8(5),
        InvocationError::UnsupportedMethod => encoder.u8(6),
        InvocationError::UnsupportedResultStorage => encoder.u8(7),
        InvocationError::MissingState => encoder.u8(8),
        InvocationError::InvalidAvailability => encoder.u8(9),
        InvocationError::InvalidInput => encoder.u8(10),
        InvocationError::InvalidActorOutput => encoder.u8(11),
        InvocationError::DivergentInvocation => encoder.u8(12),
        InvocationError::ResultCapacity => encoder.u8(13),
        InvocationError::InvalidAuthorization => encoder.u8(14),
        InvocationError::AuthorityExpired => encoder.u8(15),
        InvocationError::AuthoritySlotRegressed => encoder.u8(16),
        InvocationError::UnsupportedHostCall(call) => {
            encoder.u8(17);
            encoder.u64(call);
        }
        InvocationError::StaleContinuation => encoder.u8(18),
        InvocationError::NotReady => encoder.u8(19),
    }
}

fn decode_invocation_error(decoder: &mut Decoder<'_>) -> Result<InvocationError, DecodeError> {
    match decoder.u8()? {
        0 => Ok(InvocationError::NotCreated),
        1 => Ok(InvocationError::NotFound),
        2 => Ok(InvocationError::StaleIncarnation),
        3 => Ok(InvocationError::Suspended),
        4 => Ok(InvocationError::StaleDeployment),
        5 => Ok(InvocationError::WrongProgram),
        6 => Ok(InvocationError::UnsupportedMethod),
        7 => Ok(InvocationError::UnsupportedResultStorage),
        8 => Ok(InvocationError::MissingState),
        9 => Ok(InvocationError::InvalidAvailability),
        10 => Ok(InvocationError::InvalidInput),
        11 => Ok(InvocationError::InvalidActorOutput),
        12 => Ok(InvocationError::DivergentInvocation),
        13 => Ok(InvocationError::ResultCapacity),
        14 => Ok(InvocationError::InvalidAuthorization),
        15 => Ok(InvocationError::AuthorityExpired),
        16 => Ok(InvocationError::AuthoritySlotRegressed),
        17 => Ok(InvocationError::UnsupportedHostCall(decoder.u64()?)),
        18 => Ok(InvocationError::StaleContinuation),
        19 => Ok(InvocationError::NotReady),
        _ => Err(DecodeError::InvalidTag),
    }
}

fn encode_yield_reason(encoder: &mut Encoder<'_>, value: YieldReason) {
    match value {
        YieldReason::Cooperative => encoder.u8(0),
        YieldReason::Await { call } => {
            encoder.u8(1);
            encoder.fixed(call.as_bytes());
        }
    }
}

fn decode_yield_reason(decoder: &mut Decoder<'_>) -> Result<YieldReason, DecodeError> {
    match decoder.u8()? {
        0 => Ok(YieldReason::Cooperative),
        1 => {
            let call = CallId(decoder.fixed()?);
            if call == CallId::ZERO {
                return Err(DecodeError::NonCanonical);
            }
            Ok(YieldReason::Await { call })
        }
        _ => Err(DecodeError::InvalidTag),
    }
}

fn encode_yielded(encoder: &mut Encoder<'_>, value: &YieldedInvocation) {
    encoder.fixed(value.invocation.as_bytes());
    encoder.fixed(value.actor.as_bytes());
    encoder.fixed(value.incarnation.as_bytes());
    encoder.fixed(value.deployment.as_bytes());
    encoder.fixed(value.program.as_bytes());
    encoder.u8(value.mode as u8);
    encode_blob(encoder, &value.continuation);
    encoder.u64(value.ready_sequence);
    encode_optional_blob(encoder, &value.installation_data);
    encode_required_refs(encoder, &value.required);
    encode_yield_reason(encoder, value.reason);
}

fn decode_yielded(decoder: &mut Decoder<'_>) -> Result<YieldedInvocation, DecodeError> {
    let invocation = InvocationId(decoder.fixed()?);
    let actor = ActorId(decoder.fixed()?);
    let incarnation = Hash(decoder.fixed()?);
    let deployment = DeploymentId(decoder.fixed()?);
    let program = ProgramId(decoder.fixed()?);
    let mode = decode_method_mode(decoder)?;
    let continuation = decode_blob(decoder)?;
    let ready_sequence = decoder.u64()?;
    let installation_data = decode_optional_blob(decoder)?;
    let required = decode_required_refs(decoder, installation_data.as_ref())?;
    let value = YieldedInvocation {
        invocation,
        actor,
        incarnation,
        deployment,
        program,
        mode,
        continuation,
        ready_sequence,
        installation_data,
        required,
        reason: decode_yield_reason(decoder)?,
    };
    value
        .validate()
        .then_some(value)
        .ok_or(DecodeError::NonCanonical)
}

fn encode_runtime_outcome(encoder: &mut Encoder<'_>, value: &RuntimeOutcome) {
    match value {
        RuntimeOutcome::Management(result) => {
            encoder.u8(0);
            match result {
                Ok(reply) => {
                    encoder.bool(true);
                    encode_management_reply(encoder, reply);
                }
                Err(error) => {
                    encoder.bool(false);
                    encode_management_error(encoder, *error);
                }
            }
        }
        RuntimeOutcome::Completed(result) => {
            encoder.u8(1);
            match result {
                Ok(reply) => {
                    encoder.bool(true);
                    encode_invocation_reply(encoder, reply);
                }
                Err(error) => {
                    encoder.bool(false);
                    encode_invocation_error(encoder, *error);
                }
            }
        }
        RuntimeOutcome::Yielded(value) => {
            encoder.u8(2);
            encode_yielded(encoder, value);
        }
    }
}

fn decode_runtime_outcome(decoder: &mut Decoder<'_>) -> Result<RuntimeOutcome, DecodeError> {
    match decoder.u8()? {
        0 => Ok(RuntimeOutcome::Management(if decoder.bool()? {
            Ok(decode_management_reply(decoder)?)
        } else {
            Err(decode_management_error(decoder)?)
        })),
        1 => Ok(RuntimeOutcome::Completed(if decoder.bool()? {
            Ok(decode_invocation_reply(decoder)?)
        } else {
            Err(decode_invocation_error(decoder)?)
        })),
        2 => Ok(RuntimeOutcome::Yielded(decode_yielded(decoder)?)),
        _ => Err(DecodeError::InvalidTag),
    }
}

impl CanonicalWire for RuntimeTransition {
    const MAGIC: [u8; 4] = *b"ATRN";
    const MAX_ENCODED_BYTES: usize = MAX_RUNTIME_TRANSITION_WIRE_BYTES;

    fn validate_wire(&self) -> bool {
        self.validate()
    }

    fn encode_body(&self, encoder: &mut Encoder<'_>) {
        encode_runtime_state(encoder, &self.state);
        encode_runtime_outcome(encoder, &self.outcome);
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let value = Self {
            state: decode_runtime_state(decoder)?,
            outcome: decode_runtime_outcome(decoder)?,
        };
        value
            .validate()
            .then_some(value)
            .ok_or(DecodeError::NonCanonical)
    }
}

use crate::private::{
    EncryptedObjectKind, EncryptedPrivateObject, MAX_PRIVATE_CIPHERTEXT_BYTES, MAX_PRIVATE_NODES,
    MAX_SEALED_KEY_BYTES, MAX_TRANSPORT_IDENTITY_BYTES, PRIVATE_NONCE_BYTES,
    PRIVATE_SIGNATURE_BYTES, PrivateActorLifecycleKind, PrivateControlOperation,
    PrivateControlRecord, PrivateControlSigner, PrivateKeyEpoch, PrivateNodeIdentity,
    SealedPrivateKey,
};

pub const MAX_PRIVATE_NODE_IDENTITY_WIRE_BYTES: usize = 1_024;
pub const MAX_PRIVATE_KEY_EPOCH_WIRE_BYTES: usize =
    HEADER_BYTES + 160 + 2 * MAX_PRIVATE_NODES * (32 + 32 + 4 + MAX_SEALED_KEY_BYTES);
pub const MAX_PRIVATE_CONTROL_WIRE_BYTES: usize = HEADER_BYTES
    + MAX_PRIVATE_KEY_EPOCH_WIRE_BYTES
    + MAX_PRIVATE_NODES * (MAX_PRIVATE_NODE_IDENTITY_WIRE_BYTES + 32)
    + 512;
pub const MAX_PRIVATE_OBJECT_WIRE_BYTES: usize =
    HEADER_BYTES + 32 + 32 + 8 + 1 + 32 + PRIVATE_NONCE_BYTES + 4 + MAX_PRIVATE_CIPHERTEXT_BYTES;

fn encode_private_node(encoder: &mut Encoder<'_>, value: &PrivateNodeIdentity) {
    encoder.fixed(value.node.as_bytes());
    encoder.fixed(value.principal.as_bytes());
    encoder.bytes(&value.transport_identity);
    encoder.0.extend_from_slice(&value.encryption_public_key);
    encoder.fixed(value.authority_binding.as_bytes());
    encoder.0.extend_from_slice(&value.transport_signature);
}

fn decode_private_node(decoder: &mut Decoder<'_>) -> Result<PrivateNodeIdentity, DecodeError> {
    let value = PrivateNodeIdentity {
        node: NodeId(decoder.fixed()?),
        principal: PrincipalId(decoder.fixed()?),
        transport_identity: decoder.bytes_bounded(MAX_TRANSPORT_IDENTITY_BYTES)?,
        encryption_public_key: decoder
            .take(32)?
            .try_into()
            .map_err(|_| DecodeError::Truncated)?,
        authority_binding: Hash(decoder.fixed()?),
        transport_signature: decoder
            .take(PRIVATE_SIGNATURE_BYTES)?
            .try_into()
            .map_err(|_| DecodeError::Truncated)?,
    };
    value
        .validate()
        .then_some(value)
        .ok_or(DecodeError::NonCanonical)
}

impl CanonicalWire for PrivateNodeIdentity {
    const MAGIC: [u8; 4] = *b"PNID";
    const MAX_ENCODED_BYTES: usize = MAX_PRIVATE_NODE_IDENTITY_WIRE_BYTES;

    fn validate_wire(&self) -> bool {
        self.validate()
    }

    fn encode_body(&self, encoder: &mut Encoder<'_>) {
        encode_private_node(encoder, self);
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        decode_private_node(decoder)
    }
}

fn encode_sealed_key(encoder: &mut Encoder<'_>, value: &SealedPrivateKey) {
    encoder.fixed(value.node.as_bytes());
    encoder.0.extend_from_slice(&value.recipient_key);
    encoder.bytes(&value.sealed);
}

fn decode_sealed_key(decoder: &mut Decoder<'_>) -> Result<SealedPrivateKey, DecodeError> {
    let value = SealedPrivateKey {
        node: NodeId(decoder.fixed()?),
        recipient_key: decoder
            .take(32)?
            .try_into()
            .map_err(|_| DecodeError::Truncated)?,
        sealed: decoder.bytes_bounded(MAX_SEALED_KEY_BYTES)?,
    };
    value
        .validate()
        .then_some(value)
        .ok_or(DecodeError::NonCanonical)
}

fn encode_private_epoch(encoder: &mut Encoder<'_>, value: &PrivateKeyEpoch) {
    encoder.fixed(value.space.as_bytes());
    encoder.fixed(value.agent.as_bytes());
    encoder.u64(value.epoch);
    encoder.fixed(value.owner_key_commitment.as_bytes());
    encoder.fixed(value.data_key_commitment.as_bytes());
    encoder.fixed(value.recovery_key_commitment.as_bytes());
    encoder.list(&value.sealed_owner_keys, encode_sealed_key);
    encoder.list(&value.sealed_data_keys, encode_sealed_key);
}

fn decode_private_epoch(decoder: &mut Decoder<'_>) -> Result<PrivateKeyEpoch, DecodeError> {
    let value = PrivateKeyEpoch {
        space: SpaceId(decoder.fixed()?),
        agent: AgentId(decoder.fixed()?),
        epoch: decoder.u64()?,
        owner_key_commitment: Hash(decoder.fixed()?),
        data_key_commitment: Hash(decoder.fixed()?),
        recovery_key_commitment: Hash(decoder.fixed()?),
        sealed_owner_keys: decoder.list_bounded(MAX_PRIVATE_NODES, decode_sealed_key)?,
        sealed_data_keys: decoder.list_bounded(MAX_PRIVATE_NODES, decode_sealed_key)?,
    };
    value
        .validate()
        .then_some(value)
        .ok_or(DecodeError::NonCanonical)
}

impl CanonicalWire for PrivateKeyEpoch {
    const MAGIC: [u8; 4] = *b"PKEY";
    const MAX_ENCODED_BYTES: usize = MAX_PRIVATE_KEY_EPOCH_WIRE_BYTES;

    fn validate_wire(&self) -> bool {
        self.validate()
    }

    fn encode_body(&self, encoder: &mut Encoder<'_>) {
        encode_private_epoch(encoder, self);
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        decode_private_epoch(decoder)
    }
}

fn encode_encrypted_kind(encoder: &mut Encoder<'_>, value: EncryptedObjectKind) {
    encoder.u8(value as u8);
}

fn decode_encrypted_kind(decoder: &mut Decoder<'_>) -> Result<EncryptedObjectKind, DecodeError> {
    match decoder.u8()? {
        0 => Ok(EncryptedObjectKind::CrdtNode),
        1 => Ok(EncryptedObjectKind::Package),
        2 => Ok(EncryptedObjectKind::Blob),
        3 => Ok(EncryptedObjectKind::Index),
        4 => Ok(EncryptedObjectKind::Snapshot),
        5 => Ok(EncryptedObjectKind::Control),
        _ => Err(DecodeError::InvalidTag),
    }
}

impl CanonicalWire for EncryptedPrivateObject {
    const MAGIC: [u8; 4] = *b"POBJ";
    const MAX_ENCODED_BYTES: usize = MAX_PRIVATE_OBJECT_WIRE_BYTES;

    fn validate_wire(&self) -> bool {
        self.validate()
    }

    fn encode_body(&self, encoder: &mut Encoder<'_>) {
        encoder.fixed(self.space.as_bytes());
        encoder.fixed(self.agent.as_bytes());
        encoder.u64(self.epoch);
        encode_encrypted_kind(encoder, self.kind);
        encoder.fixed(self.content.as_bytes());
        encoder.0.extend_from_slice(&self.nonce);
        encoder.bytes(&self.ciphertext);
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let value = Self {
            space: SpaceId(decoder.fixed()?),
            agent: AgentId(decoder.fixed()?),
            epoch: decoder.u64()?,
            kind: decode_encrypted_kind(decoder)?,
            content: Hash(decoder.fixed()?),
            nonce: decoder
                .take(PRIVATE_NONCE_BYTES)?
                .try_into()
                .map_err(|_| DecodeError::Truncated)?,
            ciphertext: decoder.bytes_bounded(MAX_PRIVATE_CIPHERTEXT_BYTES)?,
        };
        value
            .validate()
            .then_some(value)
            .ok_or(DecodeError::NonCanonical)
    }
}

fn encode_private_lifecycle_kind(encoder: &mut Encoder<'_>, value: PrivateActorLifecycleKind) {
    encoder.u8(value as u8);
}

fn decode_private_lifecycle_kind(
    decoder: &mut Decoder<'_>,
) -> Result<PrivateActorLifecycleKind, DecodeError> {
    match decoder.u8()? {
        0 => Ok(PrivateActorLifecycleKind::Install),
        1 => Ok(PrivateActorLifecycleKind::Upgrade),
        2 => Ok(PrivateActorLifecycleKind::Suspend),
        3 => Ok(PrivateActorLifecycleKind::Resume),
        4 => Ok(PrivateActorLifecycleKind::Remove),
        _ => Err(DecodeError::InvalidTag),
    }
}

fn encode_private_operation(encoder: &mut Encoder<'_>, value: &PrivateControlOperation) {
    match value {
        PrivateControlOperation::Invite {
            node,
            epoch,
            sealed_owner_key,
            sealed_data_key,
        } => {
            encoder.u8(0);
            encode_private_node(encoder, node);
            encoder.u64(*epoch);
            encode_sealed_key(encoder, sealed_owner_key);
            encode_sealed_key(encoder, sealed_data_key);
        }
        PrivateControlOperation::Revoke { node, next_epoch } => {
            encoder.u8(1);
            encoder.fixed(node.as_bytes());
            encode_private_epoch(encoder, next_epoch);
        }
        PrivateControlOperation::RotateKeys { next_epoch } => {
            encoder.u8(2);
            encode_private_epoch(encoder, next_epoch);
        }
        PrivateControlOperation::SetResourcePolicy { policy } => {
            encoder.u8(3);
            encode_blob(encoder, policy);
        }
        PrivateControlOperation::ActorLifecycle {
            actor,
            operation,
            request,
        } => {
            encoder.u8(4);
            encoder.fixed(actor.as_bytes());
            encode_private_lifecycle_kind(encoder, *operation);
            encoder.fixed(request.as_bytes());
        }
        PrivateControlOperation::Recover {
            superseded_heads,
            next_epoch,
            replacement_nodes,
        } => {
            encoder.u8(5);
            encoder.list(superseded_heads, |encoder, value| {
                encoder.fixed(value.as_bytes())
            });
            encode_private_epoch(encoder, next_epoch);
            encoder.list(replacement_nodes, encode_private_node);
        }
    }
}

fn decode_private_operation(
    decoder: &mut Decoder<'_>,
) -> Result<PrivateControlOperation, DecodeError> {
    match decoder.u8()? {
        0 => Ok(PrivateControlOperation::Invite {
            node: decode_private_node(decoder)?,
            epoch: decoder.u64()?,
            sealed_owner_key: decode_sealed_key(decoder)?,
            sealed_data_key: decode_sealed_key(decoder)?,
        }),
        1 => Ok(PrivateControlOperation::Revoke {
            node: NodeId(decoder.fixed()?),
            next_epoch: decode_private_epoch(decoder)?,
        }),
        2 => Ok(PrivateControlOperation::RotateKeys {
            next_epoch: decode_private_epoch(decoder)?,
        }),
        3 => Ok(PrivateControlOperation::SetResourcePolicy {
            policy: decode_blob(decoder)?,
        }),
        4 => Ok(PrivateControlOperation::ActorLifecycle {
            actor: ActorId(decoder.fixed()?),
            operation: decode_private_lifecycle_kind(decoder)?,
            request: Hash(decoder.fixed()?),
        }),
        5 => Ok(PrivateControlOperation::Recover {
            superseded_heads: decoder
                .list_bounded(MAX_PRIVATE_NODES, |decoder| Ok(Hash(decoder.fixed()?)))?,
            next_epoch: decode_private_epoch(decoder)?,
            replacement_nodes: decoder.list_bounded(MAX_PRIVATE_NODES, decode_private_node)?,
        }),
        _ => Err(DecodeError::InvalidTag),
    }
}

fn encode_private_control_unsigned(encoder: &mut Encoder<'_>, value: &PrivateControlRecord) {
    encoder.fixed(value.space.as_bytes());
    encoder.fixed(value.agent.as_bytes());
    encoder.u64(value.sequence);
    encode_optional_hash(encoder, &value.previous);
    encode_private_operation(encoder, &value.operation);
    encoder.u8(value.signer as u8);
    encoder.0.extend_from_slice(&value.signer_public_key);
}

pub(crate) fn private_control_signing_bytes(value: &PrivateControlRecord) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"PCSG");
    bytes.extend_from_slice(RUNTIME_ABI_ID.as_bytes());
    encode_private_control_unsigned(&mut Encoder(&mut bytes), value);
    bytes
}

impl CanonicalWire for PrivateControlRecord {
    const MAGIC: [u8; 4] = *b"PCTL";
    const MAX_ENCODED_BYTES: usize = MAX_PRIVATE_CONTROL_WIRE_BYTES;

    fn validate_wire(&self) -> bool {
        self.validate_shape()
    }

    fn encode_body(&self, encoder: &mut Encoder<'_>) {
        encode_private_control_unsigned(encoder, self);
        encoder.0.extend_from_slice(&self.signature);
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let space = SpaceId(decoder.fixed()?);
        let agent = AgentId(decoder.fixed()?);
        let sequence = decoder.u64()?;
        let previous = decode_optional_hash(decoder)?;
        let operation = decode_private_operation(decoder)?;
        let signer = match decoder.u8()? {
            0 => PrivateControlSigner::Owner,
            1 => PrivateControlSigner::Recovery,
            _ => return Err(DecodeError::InvalidTag),
        };
        let signer_public_key = decoder
            .take(32)?
            .try_into()
            .map_err(|_| DecodeError::Truncated)?;
        let signature = decoder
            .take(PRIVATE_SIGNATURE_BYTES)?
            .try_into()
            .map_err(|_| DecodeError::Truncated)?;
        let value = Self {
            space,
            agent,
            sequence,
            previous,
            operation,
            signer,
            signer_public_key,
            signature,
        };
        value
            .validate_shape()
            .then_some(value)
            .ok_or(DecodeError::NonCanonical)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn blob(byte: u8) -> BlobRef {
        BlobRef {
            hash: Hash([byte; 32]),
            len: 1,
        }
    }

    fn actor(byte: u8) -> ActorEntry {
        ActorEntry {
            actor: ActorId([byte; 32]),
            name: alloc::format!("actor-{byte}"),
            parent: None,
            deployment: DeploymentId([byte.wrapping_add(1); 32]),
            program: ProgramId([byte.wrapping_add(2); 32]),
            package: blob(byte.wrapping_add(3)),
            agent_schema: blob(byte.wrapping_add(4)),
            method_policy: blob(byte.wrapping_add(5)),
            constructor_abi: Hash([byte.wrapping_add(6); 32]),
            installation_data: Some(blob(byte.wrapping_add(7))),
            state_layout: Hash([byte.wrapping_add(8); 32]),
            lanes: LaneSet::of(StateLane::Linear),
            suspended: false,
        }
    }

    #[test]
    fn actor_forest_round_trip_is_exact_and_bounded() {
        let page = ActorDirectoryPage {
            entries: alloc::vec![
                ActorDirectoryRecord {
                    entry: actor(1),
                    incarnation: Hash([20; 32]),
                    installation_id: InstallationId([21; 32]),
                    registry_reservation: Hash([22; 32]),
                },
                ActorDirectoryRecord {
                    entry: actor(2),
                    incarnation: Hash([23; 32]),
                    installation_id: InstallationId([24; 32]),
                    registry_reservation: Hash([25; 32]),
                },
            ],
            next: Some(ActorId([2; 32])),
        };
        let encoded = page.encode().unwrap();
        assert_eq!(ActorDirectoryPage::decode(&encoded), Ok(page));

        let mut oversized = actor(3);
        oversized.name = alloc::string::String::from_utf8(alloc::vec![b'x'; 129]).unwrap();
        assert_eq!(oversized.encode(), Err(WireError::InvalidValue));
    }

    #[test]
    fn installation_data_is_bounded_and_committed_by_install_request() {
        let mut entry = actor(3);
        let installation_bytes = alloc::vec![0x5a, 0xa5];
        entry.installation_data = Some(BlobRef::of_bytes(&installation_bytes));
        let install = InstallActor {
            installation_id: InstallationId([31; 32]),
            registry_reservation: Hash([32; 32]),
            producer: ProducerId([33; 32]),
            package: entry.package.clone(),
            agent_schema: entry.agent_schema.clone(),
            method_policy: entry.method_policy.clone(),
            constructor_abi: entry.constructor_abi,
            installation_data: Some(InstallationData {
                reference: entry.installation_data.clone().unwrap(),
                bytes: installation_bytes,
            }),
            state_layout: entry.state_layout,
            contract: ActorPackageContract::canonical(),
            requirements: RuntimeRequirements {
                lanes: entry.lanes,
                scheduling: false,
                proof_systems: ProofSystemSet::EMPTY,
            },
            entry,
        };
        let with_data = ManagementRequest::Install(alloc::boxed::Box::new(install.clone()));
        assert!(management_request_valid(&with_data));

        let mut without_data = install.clone();
        without_data.entry.installation_data = None;
        without_data.installation_data = None;
        let without_data = ManagementRequest::Install(alloc::boxed::Box::new(without_data));
        assert!(management_request_valid(&without_data));
        assert_ne!(with_data.commitment(), without_data.commitment());

        let mut present_empty = install.clone();
        let empty_reference = BlobRef::of_bytes(&[]);
        present_empty.entry.installation_data = Some(empty_reference.clone());
        present_empty.installation_data = Some(InstallationData {
            reference: empty_reference,
            bytes: alloc::vec![],
        });
        let present_empty_request =
            ManagementRequest::Install(alloc::boxed::Box::new(present_empty.clone()));
        assert!(management_request_valid(&present_empty_request));
        assert_ne!(
            present_empty_request.commitment(),
            without_data.commitment()
        );

        let mut encoded = alloc::vec![];
        encode_install(&mut Encoder(&mut encoded), &present_empty);
        let mut decoder = Decoder::new(&encoded);
        assert_eq!(decode_install(&mut decoder).unwrap(), present_empty);
        assert!(decoder.exhausted());

        let mut aliased = install.clone();
        let data_reference = aliased
            .installation_data
            .as_ref()
            .unwrap()
            .reference
            .clone();
        aliased.package = data_reference.clone();
        aliased.entry.package = data_reference;
        assert!(!management_request_valid(&ManagementRequest::Install(
            alloc::boxed::Box::new(aliased)
        )));

        let mut oversized = install;
        let bytes = alloc::vec![0; crate::MAX_INSTALLATION_DATA_BYTES + 1];
        let reference = BlobRef::of_bytes(&bytes);
        oversized.entry.installation_data = Some(reference.clone());
        oversized.installation_data = Some(InstallationData { reference, bytes });
        assert!(!management_request_valid(&ManagementRequest::Install(
            alloc::boxed::Box::new(oversized)
        )));
    }

    #[test]
    fn installation_data_decoder_rejects_declared_oversize_mismatch_truncation_and_trailing() {
        let empty = InstallationData {
            reference: BlobRef::of_bytes(&[]),
            bytes: alloc::vec![],
        };
        let mut canonical = alloc::vec![];
        encode_installation_data(&mut Encoder(&mut canonical), &empty);
        let mut decoder = Decoder::new(&canonical);
        assert_eq!(decode_installation_data(&mut decoder), Ok(empty));
        assert!(decoder.exhausted());

        let mut oversized_declaration = alloc::vec![];
        encode_blob(
            &mut Encoder(&mut oversized_declaration),
            &BlobRef {
                hash: Hash([1; 32]),
                len: (MAX_INSTALLATION_DATA_BYTES + 1) as u64,
            },
        );
        Encoder(&mut oversized_declaration).u32((MAX_INSTALLATION_DATA_BYTES + 1) as u32);
        assert_eq!(
            decode_installation_data(&mut Decoder::new(&oversized_declaration)),
            Err(DecodeError::LimitExceeded)
        );

        let mut truncated = alloc::vec![];
        encode_blob(&mut Encoder(&mut truncated), &BlobRef::of_bytes(&[0x51]));
        Encoder(&mut truncated).u32(1);
        assert_eq!(
            decode_installation_data(&mut Decoder::new(&truncated)),
            Err(DecodeError::Truncated)
        );

        let mut mismatch = alloc::vec![];
        encode_blob(&mut Encoder(&mut mismatch), &BlobRef::of_bytes(&[]));
        Encoder(&mut mismatch).bytes(&[0x51]);
        assert_eq!(
            decode_installation_data(&mut Decoder::new(&mismatch)),
            Err(DecodeError::NonCanonical)
        );

        canonical.push(0xff);
        let mut decoder = Decoder::new(&canonical);
        assert!(decode_installation_data(&mut decoder).is_ok());
        assert!(
            !decoder.exhausted(),
            "the enclosing canonical wire rejects trailing bytes"
        );
    }

    fn invocation() -> InvocationWork {
        InvocationWork {
            space: SpaceId([1; 32]),
            agent: AgentId([2; 32]),
            runtime_deployment: DeploymentId([3; 32]),
            invocation: InvocationId([4; 32]),
            actor: ActorId([5; 32]),
            incarnation: Hash([6; 32]),
            deployment: DeploymentId([7; 32]),
            program: ProgramId([8; 32]),
            mode: MethodMode::Linear,
            origin: InvocationOrigin {
                principal: Some(PrincipalId([9; 32])),
                transport_node: Some(NodeId([10; 32])),
                credential: Some(CredentialId([11; 32])),
                actor: None,
                capability: Some(CapabilityId([12; 32])),
            },
            message: alloc::vec![13, 14],
            installation_data: None,
            availability: alloc::vec![],
            gas: 1_000,
            recovery_only: false,
        }
    }

    fn receipt_for(invocation: &InvocationWork) -> AuthorityReceipt {
        let public_key = [31; 32];
        AuthorityReceipt {
            selector: AuthorityReceiptSelector {
                policy: Hash([15; 32]),
                issuer: AuthorityIssuer {
                    principal: PrincipalId([16; 32]),
                    actor: ActorId([17; 32]),
                    deployment: DeploymentId([18; 32]),
                    program: ProgramId([19; 32]),
                    producer: ProducerId::of_public_key(&public_key),
                },
                space: invocation.space,
                agent: invocation.agent,
                operation: AuthorityOperationKind::InvokeActor,
                runtime_deployment: invocation.runtime_deployment,
                actor: Some(invocation.actor),
                actor_deployment: Some(invocation.deployment),
                evidence: AuthorityEvidence {
                    package: Some(blob(20)),
                    proof: None,
                    commitment: Hash([21; 32]),
                },
                lane_roots: AuthorityLaneRoots {
                    linear: Some(Hash([22; 32])),
                    ..AuthorityLaneRoots::default()
                },
                epoch: 3,
                valid_from: 40,
                expires_at: 50,
                request: invocation.commitment(),
            },
            public_key,
            signature: [32; 64],
        }
    }

    #[test]
    fn invoke_work_round_trip_binds_receipt_to_exact_request() {
        let invocation = invocation();
        let work = RuntimeWork::Invoke {
            state: RuntimeState::default(),
            authority: alloc::boxed::Box::new(receipt_for(&invocation)),
            invocation: alloc::boxed::Box::new(invocation),
            observed_slot: 45,
        };
        let encoded = work.encode().unwrap();
        assert_eq!(RuntimeWork::decode(&encoded), Ok(work.clone()));
        let mut later_retry = work.clone();
        let RuntimeWork::Invoke { observed_slot, .. } = &mut later_retry else {
            unreachable!()
        };
        *observed_slot = 51;
        assert!(
            later_retry.encode().is_ok(),
            "the guest must distinguish an exact retry from unseen expired work before applying the signed slot window"
        );

        let RuntimeWork::Invoke {
            mut authority,
            state,
            invocation,
            observed_slot,
        } = work
        else {
            unreachable!()
        };
        authority.selector.request = Hash([99; 32]);
        let mismatched = RuntimeWork::Invoke {
            state,
            invocation,
            authority,
            observed_slot,
        };
        assert_eq!(mismatched.encode(), Err(WireError::InvalidValue));
    }

    #[test]
    fn read_only_management_has_one_authority_representation() {
        let invocation = invocation();
        let read = RuntimeWork::Manage {
            space: invocation.space,
            agent: invocation.agent,
            runtime_deployment: invocation.runtime_deployment,
            state: RuntimeState::default(),
            request: alloc::boxed::Box::new(ManagementRequest::InspectResources),
            authority: None,
            observed_slot: 45,
        };
        let encoded = read.encode().unwrap();
        assert_eq!(RuntimeWork::decode(&encoded), Ok(read));

        let with_receipt = RuntimeWork::Manage {
            space: invocation.space,
            agent: invocation.agent,
            runtime_deployment: invocation.runtime_deployment,
            state: RuntimeState::default(),
            request: alloc::boxed::Box::new(ManagementRequest::InspectResources),
            authority: Some(alloc::boxed::Box::new(receipt_for(&invocation))),
            observed_slot: 45,
        };
        assert_eq!(with_receipt.encode(), Err(WireError::InvalidValue));
    }

    #[test]
    fn create_rejects_predecessor_runtime_state() {
        let space = SpaceId([41; 32]);
        let owner = PrincipalId([42; 32]);
        let creation_nonce = Hash([43; 32]);
        let agent = AgentId::derive(space, owner, creation_nonce.as_bytes());
        let runtime_deployment = DeploymentId([44; 32]);
        let descriptor = AgentDescriptor {
            identity: AgentIdentity {
                space,
                agent,
                owner,
                profile: AgentProfile::Local,
                runtime_deployment,
                runtime_program: ProgramId([45; 32]),
                runtime_producer: ProducerId([46; 32]),
            },
            creation_nonce,
            runtime_package: blob(47),
            runtime_contract: RuntimePackageContract::canonical(),
            capabilities: RuntimeCapabilities::standard(),
            replicas: alloc::vec![AgentReplica {
                node: NodeId([48; 32]),
                principal: owner,
                role: ReplicaRole::Voter,
            }],
        };
        let request = ManagementRequest::Create(alloc::boxed::Box::new(descriptor));
        let mut authority = receipt_for(&invocation());
        authority.selector.space = space;
        authority.selector.agent = agent;
        authority.selector.operation = AuthorityOperationKind::CreateAgent;
        authority.selector.runtime_deployment = runtime_deployment;
        authority.selector.actor = None;
        authority.selector.actor_deployment = None;
        authority.selector.request = request.commitment();
        let work = RuntimeWork::Manage {
            space,
            agent,
            runtime_deployment,
            state: RuntimeState::default(),
            request: alloc::boxed::Box::new(request),
            authority: Some(alloc::boxed::Box::new(authority)),
            observed_slot: 45,
        };
        assert!(work.encode().is_ok());

        let mut with_predecessor = work;
        let RuntimeWork::Manage { state, .. } = &mut with_predecessor else {
            unreachable!()
        };
        state.control.push(1);
        assert_eq!(with_predecessor.encode(), Err(WireError::InvalidValue));
    }

    #[test]
    fn yielded_transition_round_trip_and_old_generation_rejection() {
        let installation_data = BlobRef::of_bytes(&[]);
        let mut required = alloc::vec![
            BlobRef::of_bytes(b"actor program"),
            installation_data.clone(),
        ];
        required.sort();
        let transition = RuntimeTransition {
            state: RuntimeState::default(),
            outcome: RuntimeOutcome::Yielded(YieldedInvocation {
                invocation: InvocationId([1; 32]),
                actor: ActorId([2; 32]),
                incarnation: Hash([3; 32]),
                deployment: DeploymentId([4; 32]),
                program: ProgramId([5; 32]),
                mode: MethodMode::Merge,
                continuation: BlobRef {
                    hash: Hash([6; 32]),
                    len: 512,
                },
                ready_sequence: 7,
                installation_data: Some(installation_data),
                required,
                reason: YieldReason::Await {
                    call: CallId([8; 32]),
                },
            }),
        };
        let encoded = transition.encode().unwrap();
        assert_eq!(RuntimeTransition::decode(&encoded), Ok(transition));

        let mut old_generation = encoded.clone();
        old_generation[4] ^= 0xff;
        assert_eq!(
            RuntimeTransition::decode(&old_generation),
            Err(WireError::Decode(DecodeError::InvalidPlatform))
        );

        let mut trailing = encoded;
        trailing.push(0);
        assert_eq!(
            RuntimeTransition::decode(&trailing),
            Err(WireError::Decode(DecodeError::TrailingBytes))
        );
    }

    fn private_node() -> PrivateNodeIdentity {
        let transport_identity = alloc::vec![3; 48];
        PrivateNodeIdentity {
            node: NodeId::of_authenticated_peer(&transport_identity),
            principal: PrincipalId([2; 32]),
            transport_identity,
            encryption_public_key: [4; 32],
            authority_binding: Hash([5; 32]),
            transport_signature: [6; 64],
        }
    }

    #[test]
    fn private_records_and_ciphertext_have_strict_canonical_wires() {
        let node = private_node();
        let sealed = |byte| SealedPrivateKey {
            node: node.node,
            recipient_key: node.encryption_public_key,
            sealed: alloc::vec![byte; 48],
        };
        let control = PrivateControlRecord {
            space: SpaceId([7; 32]),
            agent: AgentId([8; 32]),
            sequence: 0,
            previous: None,
            operation: PrivateControlOperation::Invite {
                node: node.clone(),
                epoch: 0,
                sealed_owner_key: sealed(9),
                sealed_data_key: sealed(10),
            },
            signer: PrivateControlSigner::Owner,
            signer_public_key: [11; 32],
            signature: [12; 64],
        };
        let encoded = control.encode().unwrap();
        assert_eq!(PrivateControlRecord::decode(&encoded), Ok(control));

        let object = EncryptedPrivateObject {
            space: SpaceId([7; 32]),
            agent: AgentId([8; 32]),
            epoch: 1,
            kind: EncryptedObjectKind::CrdtNode,
            content: Hash([13; 32]),
            nonce: [14; PRIVATE_NONCE_BYTES],
            ciphertext: alloc::vec![15; 128],
        };
        let encoded = object.encode().unwrap();
        assert_eq!(EncryptedPrivateObject::decode(&encoded), Ok(object));
    }

    #[test]
    fn runtime_state_aggregate_bound_is_enforced_while_decoding() {
        let mut bytes = Vec::new();
        let mut encoder = Encoder(&mut bytes);
        encoder.bytes(&alloc::vec![0; MAX_RUNTIME_STATE_BYTES]);
        encoder.bytes(&[1]);
        encoder.bytes(&[]);
        encoder.bytes(&[]);
        assert_eq!(
            decode_runtime_state(&mut Decoder::new(&bytes)),
            Err(DecodeError::LimitExceeded)
        );
    }
}
